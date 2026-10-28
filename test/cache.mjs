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
  compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'], bindings, log: new TestLog(),
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


test('default upstream caching restores request identity but still executes each requests JSON rules', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/default'), DNS_RULE_UP: group([requestDefault, { type: 'setTtl', ttl: 9 }]) });
  const first = await dns(await post());
  assert.equal(first.records[0].ttl, 9);
  const wire = query(); wire[0] = 0x12; wire[1] = 0x34;
  const second = await dns(await post(undefined, wire));
  assert.equal(second.id, 0x1234);
  assert.equal(second.records[0].ttl, 9);
  assert.equal(calls.length, 1);
});

test('rules control reads and writes, single-request overrides do not leak', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/policy'), DNS_CACHE: { read: false, write: false }, DNS_RULE_UP: group([
    { type: 'setCache', read: true, write: true, maxTtl: 120 },
    { ...requestDefault, cache: { read: false, write: false } },
    requestDefault,
  ]) });
  await dns(await post());
  assert.equal(calls.length, 2);
  await dns(await post());
  assert.equal(calls.length, 3);
});

test('negative cache uses SOA minimum and ages without extending its original deadline', async () => {
  const soa = [...nameWire('ns.example.com'), ...nameWire('hostmaster.example.com'), ...[1, 60, 60, 60, 2].flatMap(n => [0, 0, 0, n])];
  await setup({ DNS_UPSTREAMS: source('https://cache.test/negative'), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), {
    rcode: 3, records: [{ name: 'example.com', type: 6, ttl: 60, section: 1, data: soa }],
  }), { headers: { 'Content-Type': 'application/dns-message' } }));
  const first = await dns(await post());
  assert.equal(first.flags & 15, 3);
  assert.equal(first.records[0].ttl, 2);
  await new Promise(resolve => setTimeout(resolve, 1100));
  const hit = await dns(await post());
  assert.equal(hit.records[0].ttl, 1);
  assert.equal(calls.length, 1);
  await new Promise(resolve => setTimeout(resolve, 1100));
  await dns(await post());
  assert.equal(calls.length, 2);
});

function ednsQuery({ flags = 0, code = 8, data = [0, 1, 24, 0, 192, 0, 2], options } = {}) {
  const wire = query(); wire[11] = 1;
  const encoded = (options ?? [{ code, data }]).flatMap(option => [option.code >>> 8, option.code & 255, option.data.length >>> 8, option.data.length & 255, ...option.data]);
  return Uint8Array.from([...wire, 0, 0, 41, 4, 208, 0, 0, flags >>> 8, flags & 255, encoded.length >>> 8, encoded.length & 255, ...encoded]);
}

test('connection-specific or malformed EDNS options never become reusable through policy overrides', async () => {
  for (const [code, data] of [[10, [1,2,3,4,5,6,7,8]], [65001, [1]]]) {
    await setup({ DNS_UPSTREAMS: source(`https://cache.test/unsafe-${code}-${data.length}`), DNS_RULE_UP: group([{ ...requestDefault, cache: { maxTtl: 86400 } }]) });
    const wire = ednsQuery({ code, data });
    await dns(await post(undefined, wire)); await dns(await post(undefined, wire));
    assert.equal(calls.length, 2);
  }
});

test('Padding queries cache without normalizing their exact identity', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/padding'), DNS_RULE_UP: group([requestDefault]) });
  for (const data of [[], Array(80).fill(0), [1, 255]]) {
    const wire = ednsQuery({ code: 12, data });
    const first = await dns(await post(undefined, wire));
    const next = wire.slice(); next[1] ^= 1;
    const second = await dns(await post(undefined, next));
    assert.equal(second.id, first.id ^ 1);
  }
  assert.equal(calls.length, 3);
});

test('ECS plus Padding supports both orders and retains subnet isolation', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/ecs-padding'), DNS_RULE_UP: group([requestDefault]) });
  const padding = { code: 12, data: Array(80).fill(0) };
  for (const network of [100, 101]) {
    const ecs = { code: 8, data: [0, 1, 24, 0, 198, 51, network] };
    for (const options of [[ecs, padding], [padding, ecs]]) {
      const wire = ednsQuery({ options });
      await dns(await post(undefined, wire)); await dns(await post(undefined, wire));
    }
  }
  assert.equal(calls.length, 4);
});

test('unknown options and duplicate Padding still bypass caching', async () => {
  const padding = { code: 12, data: [] };
  for (const options of [[padding, padding], [padding, { code: 65001, data: [7] }], [padding, { code: 10, data: [1,2,3,4,5,6,7,8] }]]) {
    await setup({ DNS_UPSTREAMS: source('https://cache.test/padding-bypass'), DNS_RULE_UP: group([requestDefault]) });
    const wire = ednsQuery({ options });
    await dns(await post(undefined, wire)); await dns(await post(undefined, wire));
    assert.equal(calls.length, 2);
  }
});

test('malformed ECS never reaches a source or cacheable DNS result', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/malformed-ecs'), DNS_RULE_UP: group([requestDefault]) });
  assert.equal((await post(undefined, ednsQuery({ data: [0,1,33,0,192,0,2] }))).status, 400);
  assert.equal(calls.length, 0);
});

test('HTTP Age reduces DNS TTL and HTTP freshness can only shorten reuse', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/http-age'), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), {
    headers: { 'Content-Type': 'application/dns-message', Age: '7', 'Cache-Control': 'public, max-age=60' },
  }));
  assert.equal((await dns(await post())).records[0].ttl, 53);
  assert.equal((await dns(await post())).records[0].ttl, 53);
  assert.equal(calls.length, 1);
  for (const directive of ['no-store', 'private', 'no-cache', 'max-age=0', 'max-age=4']) {
    await setup({ DNS_UPSTREAMS: source(`https://cache.test/http-${encodeURIComponent(directive)}`), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), {
      headers: { 'Content-Type': 'application/dns-message', Age: '7', 'Cache-Control': directive },
    }));
    await dns(await post()); await dns(await post());
    assert.equal(calls.length, 2, directive);
  }
});

test('cache identity separates named sources and changed endpoint secrets', async () => {
  await setup({ DNS_UPSTREAMS: { a: { transport: 'https', url: 'https://cache.test/same' }, b: { transport: 'https', url: 'https://cache.test/same' } }, DNS_RULE_UP: group([
    { type: 'queryUpstream', upstream: 'a' }, { type: 'queryUpstream', upstream: 'b' }, { type: 'queryUpstream', upstream: 'a' },
  ]) });
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.equal(calls.length, 2);
  const bindings = { DNS_UPSTREAMS: { default: { transport: 'https', urlSecret: 'ENDPOINT' } }, ENDPOINT: 'https://cache.test/secret?token=first', DNS_RULE_UP: group([requestDefault]) };
  await setup(bindings); await dns(await post()); await dns(await post());
  assert.equal(calls.length, 1);
  await setup({ ...bindings, ENDPOINT: 'https://cache.test/secret?token=second' });
  await dns(await post());
  assert.equal(calls.length, 1);
  assert.ok(!logs.join('\n').includes('token='));
});

test('query type, class, CD, DO, EDNS payload and exact ECS have separate identities', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/query-identity'), DNS_RULE_UP: group([requestDefault]) });
  const differentClass = query(); differentClass[differentClass.length - 1] = 3;
  const wires = [query(), query('example.com', 28), differentClass, query('example.com', 1, 0x0120), ednsQuery(), ednsQuery({ flags: 0x8000 }), ednsQuery({ data: [0,1,24,0,198,51,100] })];
  const udp = ednsQuery(); udp[query().length + 3] = 2; udp[query().length + 4] = 0; wires.push(udp);
  for (const wire of wires) {
    assert.equal((await dns(await post(undefined, wire))).flags & 15, 0);
    await dns(await post(undefined, wire));
  }
  assert.equal(calls.length, wires.length);
});

test('cache preserves original response across rule changes and request-local mutations', async () => {
  const bindings = { DNS_UPSTREAMS: source('https://cache.test/original'), DNS_RULE_UP: group([requestDefault, { type: 'setTtl', ttl: 999 }]) };
  await setup(bindings);
  assert.equal((await dns(await post())).records[0].ttl, 999);
  await setup({ ...bindings, DNS_RULE_UP: group([requestDefault]) });
  assert.equal((await dns(await post())).records[0].ttl, 60);
  assert.equal(calls.length, 0);
});

test('failures, truncation, zero TTL and unproven negative answers are never reused', async () => {
  for (const [name, reply] of [
    ['servfail', { rcode: 2 }], ['refused', { rcode: 5 }], ['nx-without-soa', { rcode: 3, records: [] }],
    ['nodata-without-soa', { records: [] }], ['truncated', { flags: 0x83b0 }],
    ['zero', { records: [{ name: 'example.com', type: 1, ttl: 0, data: [192,0,2,1] }] }],
  ]) {
    await setup({ DNS_UPSTREAMS: source(`https://cache.test/no-reuse-${name}`), DNS_RULE_UP: group([{ ...requestDefault, cache: { maxTtl: 86400 } }]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), reply), { headers: { 'Content-Type': 'application/dns-message' } }));
    await dns(await post()); await dns(await post());
    assert.equal(calls.length, 2, name);
  }
});

test('cache policy preflight validates all branches before any network access', async () => {
  for (const bad of [null, true, { read: 1 }, { write: 'yes' }, { maxTtl: -1 }, { maxTtl: 86401 }, { maxTtl: 1.1 }, { key: 'unsafe' }]) {
    for (const config of [
      { DNS_CACHE: bad },
      { DNS_RULE_BAD: { order: 1, rules: [{ when: { field: 'query.name', op: 'eq', value: 'never.test' }, actions: [{ ...requestDefault, cache: bad }] }] } },
    ]) {
      await setup({ DNS_UPSTREAMS: source('https://cache.test/bad'), DNS_RULE_UP: group([requestDefault]), ...config });
      assert.equal((await dns(await post())).flags & 15, 2);
      assert.equal(calls.length, 0);
      assert.ok(logs.join('\n').includes('INVALID_CONFIG'));
    }
  }
});

test('negative SOA must cover the question and non-standard high TTL is not reusable', async () => {
  const soa = [...nameWire('ns.unrelated.test'), ...nameWire('hostmaster.unrelated.test'), ...[1, 60, 60, 60, 30].flatMap(n => [0,0,0,n])];
  for (const [name, reply] of [
    ['unrelated-soa', { rcode: 3, records: [{ name: 'unrelated.test', type: 6, ttl: 60, section: 1, data: soa }] }],
    ['high-negative-ttl', { rcode: 3, records: [{ name: 'example.com', type: 6, ttl: 0x80000000, section: 1, data: soa }] }],
    ['high-ttl', { records: [{ name: 'example.com', type: 1, ttl: 0x80000000, data: [192,0,2,1] }] }],
  ]) {
    await setup({ DNS_UPSTREAMS: source(`https://cache.test/${name}`), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), reply), { headers: { 'Content-Type': 'application/dns-message' } }));
    await dns(await post()); await dns(await post());
    assert.equal(calls.length, 2, name);
  }
});

test('read bypass, disabled writes and zero cap have deterministic request-local behavior', async () => {
  for (const policy of [{ read: false }, { read: false, write: false }, { write: false }, { maxTtl: 0 }]) {
    await setup({ DNS_UPSTREAMS: source(`https://cache.test/disabled-${JSON.stringify(policy)}`), DNS_CACHE: policy, DNS_RULE_UP: group([requestDefault]) });
    assert.equal((await dns(await post())).flags & 15, 0);
    assert.equal((await dns(await post())).flags & 15, 0);
    assert.equal(calls.length, 2);
  }
});

test('unavailable cache storage is a deterministic miss rather than a stale fallback', async () => {
  const bindings = { DNS_UPSTREAMS: source('https://cache.test/disabled-storage'), DNS_RULE_UP: group([requestDefault]) };
  await setup(bindings);
  await mf.setOptions({ ...options(bindings), cache: false });
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.equal(calls.length, 2);
});

test('an ECS response for a different subnet is not reusable for the original client scope', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/ecs-mismatch'), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), {
    records: [{ name: 'example.com', type: 1, ttl: 60, data: [192,0,2,1] }, { name: '.', type: 41, class: 1232, ttl: 0, section: 2, data: [0,8,0,7,0,1,24,0,198,51,100] }],
  }), { headers: { 'Content-Type': 'application/dns-message' } }));
  await dns(await post(undefined, ednsQuery())); await dns(await post(undefined, ednsQuery()));
  assert.equal(calls.length, 2);
});

test('cache hits spend no upstream attempt and a smaller policy cap expires rather than refreshing old data', async () => {
  const bindings = { DNS_UPSTREAMS: source('https://cache.test/cap'), DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_RULE_UP: group([requestDefault, requestDefault]) };
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.equal(calls.length, 1);
  await new Promise(resolve => setTimeout(resolve, 1100));
  await setup({ ...bindings, DNS_CACHE: { maxTtl: 1 } });
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.equal(calls.length, 1);
});

test('cache-hit resource failures remain visible and optional rollback retains the previous answer', async () => {
  const records = Array.from({ length: 10 }, (_, index) => ({ name: 'example.com', type: 1, ttl: 60, data: [192,0,2,index] }));
  const bindings = { DNS_UPSTREAMS: source('https://cache.test/bounded'), DNS_RULE_UP: group([requestDefault]) };
  await setup(bindings, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records }), { headers: { 'Content-Type': 'application/dns-message' } }));
  assert.equal((await dns(await post())).records.length, 10);
  await setup({ ...bindings, DNS_LIMITS: { maxResponseBytes: 128 }, DNS_RULE_UP: { order: 0, rules: [
    { actions: [fixed, { ...requestDefault, onError: 'continue' }] },
    { when: { field: 'lastAction.code', op: 'eq', value: 'RESOURCE_LIMIT' }, actions: [{ type: 'setTtl', ttl: 7 }] },
  ] } });
  const result = await dns(await post());
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].ttl, 7);
  assert.equal(calls.length, 0);
  assert.ok(logs.join('\n').includes('rolled_back_continue'));
  assert.ok(!logs.join('\n').includes('cache.test'));
});

test('NODATA uses a covering SOA and only currently applicable RRSIG metadata can be cached', async () => {
  const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
  const soa = [...nameWire('ns.example.com'), ...nameWire('hostmaster.example.com'), ...[1,60,60,60,30].flatMap(u32)];
  await setup({ DNS_UPSTREAMS: source('https://cache.test/nodata'), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [{ name: 'example.com', type: 6, ttl: 60, section: 1, data: soa }] }), { headers: { 'Content-Type': 'application/dns-message' } }));
  assert.equal((await dns(await post(undefined, query('example.com', 28)))).records[0].ttl, 30);
  assert.equal((await dns(await post(undefined, query('example.com', 28)))).flags & 15, 0);
  assert.equal(calls.length, 1);
  const now = Math.floor(Date.now() / 1000);
  for (const [name, inception, expiration, expected] of [['valid', now - 60, now + 60, 1], ['expired', now - 120, now - 60, 2], ['future', now + 60, now + 120, 2]]) {
    const signature = [0,1,8,2, ...u32(60), ...u32(expiration), ...u32(inception), 0,1, ...nameWire('example.com'), 1];
    await setup({ DNS_UPSTREAMS: source(`https://cache.test/signed-${name}`), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [{ name: 'example.com', type: 1, ttl: 60, data: [192,0,2,1] }, { name: 'example.com', type: 46, ttl: 60, data: signature }] }), { headers: { 'Content-Type': 'application/dns-message' } }));
    await dns(await post()); const second = await dns(await post());
    assert.equal(second.records.filter(rr => rr.type === 46).length, 1);
    assert.equal(calls.length, expected, name);
  }
});

test('HTTP aging cannot turn an invalid high-bit TTL into a fresh cache entry', async () => {
  await setup({ DNS_UPSTREAMS: source('https://cache.test/high-ttl-aged'), DNS_RULE_UP: group([requestDefault]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), {
    records: [{ name: 'example.com', type: 1, ttl: 0x80000000, data: [192,0,2,1] }],
  }), { headers: { 'Content-Type': 'application/dns-message', Age: '1' } }));
  await dns(await post()); await dns(await post());
  assert.equal(calls.length, 2);
});
