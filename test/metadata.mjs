import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { query, decode, responseWire, nameWire } from './helpers/dns-wire.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const bundleWorker = entry => build({
  entryPoints: [path.join(root, entry)], bundle: true, write: false,
  external: ['cloudflare:sockets'], format: 'esm', platform: 'browser', outfile: path.join(root, 'test/doh-bundle.js'),
  plugins: [{ name: 'wasm-external', setup(build) {
    build.onResolve({ filter: /.wasm$/ }, args => ({
      path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
    }));
  } }],
});
const bundle = await bundleWorker('src/worker.js');
const logs = [];
class TestLog extends Log {
  constructor() { super(LogLevel.ERROR); }
  log(message) { logs.push(message); }
}
const calls = [];
let upstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
const options = bindings => ({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/doh-bundle.js`, script: bundle.outputFiles[0].text,
  cf: false, compatibilityDate: '2026-07-30', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public'], bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
  handleRuntimeStdio(stdout, stderr) {
    for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text));
  },
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
  outboundService: async request => {
    calls.push({ url: request.url, method: request.method, headers: Object.fromEntries(request.headers) });
    const response = await upstream(request);
    // Fix origin apparent age at zero unless this case supplies Date explicitly.
    if (!response.headers.has('date')) response.headers.set('date', new Date(Date.now() + 60_000).toUTCString());
    return response;
  },
});
const mf = new Miniflare(options({}));
after(() => mf.dispose());
const fixed = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const source = url => ({ default: { transport: 'https', url } });
const requestDefault = { type: 'queryUpstream', upstream: 'default' };
const group = actions => ({ order: 0, rules: [{ actions }] });
async function setup(bindings = {}, handler) {
  calls.length = 0; logs.length = 0;
  upstream = handler ?? (async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } }));
  await mf.setOptions(options(bindings));
}
const post = (url = 'https://doh.test/dns-query', wire = query(), headers = {}) => mf.dispatchFetch(url, {
  method: 'POST', headers: { 'Content-Type': 'application/dns-message', ...headers }, body: wire,
});
async function dns(response) {
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'application/dns-message');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  return decode(new Uint8Array(await response.arrayBuffer()));
}




// Miniflare merges a synthetic US fallback; explicitly null unavailable fields at this public seam.
const emptyCf = { asn: null, country: null, region: null, city: null, colo: null };
const incoming = (cf, headers = {}) => mf.dispatchFetch('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', ...headers }, body: query(), cf: { ...emptyCf, ...cf } });
const eq = (field, value) => ({ field, op: 'eq', value });
const exists = (field, value) => ({ field, op: 'exists', value });
const policy = when => ({ order: 0, rules: [{ actions: [fixed] }, { when, actions: [{ type: 'setTtl', ttl: 7 }] }] });
test('platform client ASN and region stay distinct from edge colo and client-supplied headers', async () => {
  await setup({ DNS_RULE_MAIN: policy({ all: [eq('query.name', 'example.com'), eq('query.type', 'A'), eq('client.asn', 64500), eq('client.country', 'US'), eq('client.region', 'California'), eq('client.city', 'San Jose'), eq('edge.colo', 'LAX'), exists('client.colo', false), exists('edge.country', false), exists('edge.city', false)] }) });
  const result = await dns(await incoming({ asn: 64500, country: 'US', region: 'California', city: 'San Jose', colo: 'LAX' }, { 'CF-IPCountry': 'GB', 'X-Client-ASN': '1', 'X-Client-Country': 'GB', 'X-Edge-Colo': 'HKG' }));
  assert.equal(result.records[0].ttl, 7, String(logs));
  assert.equal(calls.length, 0);
});

test('direct platform client IP supports IPv4, IPv6 and Pseudo IPv4 without forwarded-header fallbacks', async () => {
  for (const [headers, expected] of [
    [{ 'CF-Connecting-IP': '192.0.2.9', 'X-Forwarded-For': '203.0.113.9', 'X-Real-IP': '203.0.113.10' }, '192.0.2.0/24'],
    [{ 'CF-Connecting-IP': '2001:db8::9' }, '2001:db8::/32'],
    [{ 'CF-Connecting-IP': '240.0.0.1', 'CF-Connecting-IPv6': '2001:db8::9' }, '2001:db8::/32'],
  ]) {
    await setup({ DNS_RULE_MAIN: policy({ field: 'client.ip', op: 'cidr', value: expected }) });
    assert.equal((await dns(await incoming({ colo: 'SJC' }, headers))).records[0].ttl, 7);
  }
});

test('missing platform metadata never falls back to client-supplied network or geography headers', async () => {
  await setup({ DNS_RULE_MAIN: policy({ all: [exists('client.ip', false), exists('client.asn', false), exists('client.country', false), exists('client.region', false), exists('client.city', false), exists('edge.colo', false)] }) });
  for (const cf of [undefined, {}]) {
    const result = await dns(await incoming(cf, { 'CF-Connecting-IP': '192.0.2.1', 'CF-IPCountry': 'US', 'CF-Region': 'California', 'CF-City': 'San Jose', 'X-Forwarded-For': '192.0.2.2', 'X-Client-ASN': '64500', 'CF-Ray': 'abc-SJC' }));
    assert.equal(result.records[0].ttl, 7);
  }
  assert.equal(calls.length, 0);
});

test('unknown or malformed platform attributes stay absent rather than matching a real place', async () => {
  await setup({ DNS_RULE_MAIN: policy({ all: [exists('client.country', false), exists('client.asn', false), exists('client.region', false), exists('client.city', false), eq('edge.colo', 'LAX')] }) });
  for (const country of [null, 'XX', 'T1', '', 'invalid']) {
    assert.equal((await dns(await incoming({ colo: 'LAX', country, asn: 0, region: '', city: 'x'.repeat(129) }))).records[0].ttl, 7);
  }
  await setup({ DNS_RULE_MAIN: policy({ field: 'client.country', op: 'ne', value: 'US' }) });
  assert.equal((await dns(await incoming({ colo: 'LAX', country: 'XX' }))).records[0].ttl, 60);
});

test('Worker subrequests do not claim the original end-user identity or location', async () => {
  await setup({ DNS_RULE_MAIN: policy({ all: [exists('client.ip', false), exists('client.asn', false), exists('client.country', false), exists('client.city', false), eq('edge.colo', 'SJC')] }) });
  for (const headers of [{ 'CF-Worker': 'example.test', 'CF-Connecting-IP': '192.0.2.1' }, { 'CF-Connecting-IP': '2a06:98c0:3600:0:0:0:0:103' }, { 'CF-Connecting-IP': '240.0.0.1', 'CF-Connecting-IPv6': '2a06:98c0:3600::103' }]) {
    assert.equal((await dns(await incoming({ colo: 'SJC', asn: 64500, country: 'US', city: 'San Jose' }, headers))).records[0].ttl, 7);
  }
});

test('invalid, missing or synthetic addresses are absent; unrelated IPv6 and forwarding headers do not override a real IPv4', async () => {
  await setup({ DNS_RULE_MAIN: policy(exists('client.ip', false)) });
  for (const headers of [{}, { 'CF-Connecting-IP': 'bad' }, { 'CF-Connecting-IP': '192.0.2.1, 198.51.100.1' }, { 'CF-Connecting-IP': '240.0.0.1' }, { 'CF-Connecting-IP': '240.0.0.1', 'CF-Connecting-IPv6': 'bad' }]) {
    assert.equal((await dns(await incoming({ colo: 'SJC' }, headers))).records[0].ttl, 7);
  }
  await setup({ DNS_RULE_MAIN: policy(eq('client.ip', '192.0.2.1')) });
  assert.equal((await dns(await incoming({ colo: 'SJC' }, { 'CF-Connecting-IP': '192.0.2.1', 'CF-Connecting-IPv6': '2001:db8::1', 'X-Forwarded-For': '198.51.100.1' }))).records[0].ttl, 7);
});

test('same DNS query uses JSON source selection per client even when upstream caching is enabled', async () => {
  await setup({ DNS_CACHE: { read: true, write: true }, DNS_UPSTREAMS: { us: { transport: 'https', url: 'https://metadata.test/us' }, gb: { transport: 'https', url: 'https://metadata.test/gb' } }, DNS_RULE_MAIN: { order: 0, rules: [
    { when: { all: [eq('client.country', 'US'), eq('query.type', 'A'), eq('query.name', 'example.com')] }, actions: [{ type: 'queryUpstream', upstream: 'us' }] },
    { when: eq('client.country', 'GB'), actions: [{ type: 'queryUpstream', upstream: 'gb' }] },
  ] } }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [{ name: 'example.com', type: 1, ttl: 60, data: [192,0,2,request.url.endsWith('/us') ? 1 : 2] }] }), { headers: { 'Content-Type': 'application/dns-message' } }));
  for (const [country, last] of [['US',1], ['GB',2], ['US',1]]) {
    assert.deepEqual((await dns(await incoming({ colo: 'LAX', country }))).records[0].data, [192,0,2,last]);
  }
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map(call => call.url), ['https://metadata.test/us', 'https://metadata.test/gb']);
});

test('metadata is request-local for GET and POST and never appears in default error events', async () => {
  await setup({ DNS_RULE_MAIN: policy(eq('client.country', 'US')) });
  const get = await mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.from(query()).toString('base64url'), { cf: { colo: 'SJC', country: 'US' } });
  assert.equal((await dns(get)).records[0].ttl, 7);
  assert.equal((await dns(await incoming({ colo: 'SJC', country: 'GB' }))).records[0].ttl, 60);
  assert.equal((await dns(await incoming(undefined))).records[0].ttl, 60);
  await setup({ DNS_RULE_MAIN: group([{ type: 'setTtl', ttl: 7 }]) });
  assert.equal((await dns(await incoming({ colo: 'SJC', country: 'US', city: 'PrivateCity', region: 'PrivateRegion', asn: 64500 }, { 'CF-Connecting-IP': '192.0.2.193' }))).flags & 15, 2);
  assert.ok(String(logs).includes('NO_RESPONSE'));
  for (const secret of ['192.0.2.193', 'PrivateCity', 'PrivateRegion', '64500']) assert.ok(!String(logs).includes(secret));
});
