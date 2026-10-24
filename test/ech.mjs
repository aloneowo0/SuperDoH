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
const trustedBundle = await bundleWorker('test/doh-options-worker.js');
const logs = [];
class TestLog extends Log {
  constructor() { super(LogLevel.ERROR); }
  log(message) { logs.push(message); }
}
const calls = [];
let upstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
const options = (bindings, trusted = false) => ({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/doh-bundle.js`, script: (trusted ? trustedBundle : bundle).outputFiles[0].text,
  compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'], bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
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
async function setup(bindings = {}, handler, trusted = false) {
  calls.length = 0; logs.length = 0;
  upstream = handler ?? (async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } }));
  await mf.setOptions(options(bindings, trusted));
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

const config = JSON.parse(await (await import('node:fs/promises')).readFile(new URL('../lib/ech-probe/test/fixtures/meta.json', import.meta.url), 'utf8')).base64;
const https = { type: 'answer', records: [{ name: 'example.com', type: 'HTTPS', ttl: 60, rdata: { Https: { priority: 1, target: '.', params: [{ key: 1, data: [2,104,50] }, { key: 3, data: [1,187] }] } } }] };
const load = { type: 'loadEch', config };
const apply = { type: 'applyEch' };
function params(record) {
  assert.equal(record.type, 65);
  assert.equal(record.data[2], 0, 'fixture target is root');
  const entries = new Map();
  for (let i = 3; i < record.data.length;) {
    const key = record.data[i] * 256 + record.data[i + 1], length = record.data[i + 2] * 256 + record.data[i + 3];
    entries.set(key, record.data.slice(i + 4, i + 4 + length)); i += 4 + length;
  }
  return entries;
}
test('direct ECH JSON acquisition and application preserve HTTPS service parameters without network work', async () => {
  await setup({ DNS_RULE_MAIN: group([https, load, apply]) });
  const result = await dns(await post(undefined, query('example.com', 65)));
  assert.equal(result.flags & 15, 0, String(logs));
  const values = params(result.records[0]);
  assert.deepEqual(values.get(1), [2,104,50]);
  assert.deepEqual(values.get(3), [1,187]);
  assert.deepEqual(values.get(5), [...Buffer.from(config, 'base64')]);
  assert.equal(calls.length, 0);
});

const u16 = value => [value >>> 8 & 255, value & 255];
const sourceData = (value = config) => [0,1,0,0,1,0,3,2,104,50,0,5,...u16(Buffer.from(value, 'base64').length),...Buffer.from(value, 'base64')];
const acquire = { type: 'queryEch', name: 'source.example', upstream: 'default' };
test('explicit HTTPS-source ECH acquisition remains isolated from the current DNS answer', async () => {
  await setup({ DNS_UPSTREAMS: source('https://ech.test/source'), DNS_RULE_MAIN: group([https, acquire, apply]) }, async request => {
    const input = new Uint8Array(await request.arrayBuffer());
    assert.deepEqual(decode(input).questions, [{ name: 'source.example', type: 65, class: 1 }]);
    return new Response(responseWire(input, { records: [{ name: 'source.example', type: 65, ttl: 30, data: sourceData() }] }), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  const result = await dns(await post(undefined, query('example.com',65)));
  assert.equal(result.flags & 15, 0, String(logs));
  assert.equal(result.questions[0].name, 'example.com');
  assert.equal(result.records[0].name, 'example.com');
  assert.deepEqual(params(result.records[0]).get(3), [1,187]);
  assert.deepEqual(params(result.records[0]).get(5), [...Buffer.from(config,'base64')]);
  assert.equal(calls.length, 1);
});

test('explicit ECH-source cache reuse shares the named-upstream safety policy and attempt budget', async () => {
  const cached = { ...acquire, cache: { read: true, write: true, maxTtl: 60 } };
  await setup({ DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_UPSTREAMS: source('https://ech.test/cached'), DNS_RULE_MAIN: group([https, cached, cached, apply]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), {
    records: [{ name: 'source.example', type: 65, ttl: 30, data: sourceData() }],
  }), { headers: { 'Content-Type': 'application/dns-message' } }));
  assert.equal((await dns(await post(undefined, query('example.com',65)))).flags & 15, 0, String(logs));
  assert.equal((await dns(await post(undefined, query('example.com',65)))).flags & 15, 0, String(logs));
  assert.equal(calls.length, 1);
});

test('ECH application rollback retains earlier records and exposes failure without leaking configuration', async () => {
  await setup({ DNS_LIMITS: { maxResponseBytes: 180 }, DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [https, load, { ...apply, onError: 'continue' }] },
    { when: { all: [{ field: 'lastAction.success', op: 'eq', value: false }, { field: 'lastAction.code', op: 'eq', value: 'RESOURCE_LIMIT' }] }, actions: [{ type: 'setTtl', ttl: 9 }] },
  ] } });
  const result = await dns(await post(undefined, query('example.com',65)));
  assert.equal(result.flags & 15, 0, String(logs));
  assert.equal(result.records[0].ttl, 9);
  assert.equal(params(result.records[0]).has(5), false);
  assert.ok(logs.join('').includes('rolled_back_continue'));
  assert.ok(!logs.join('').includes(config));
});

test('missing acquired data and missing selected HTTPS records obey required and optional failure policy', async () => {
  for (const [actions, code, rcode] of [
    [[https, apply], 'NO_ECH_CONFIG', 2],
    [[fixed, load, apply], 'NO_ECH_RECORD', 2],
    [[fixed, load, { ...apply, onError: 'continue' }], 'NO_ECH_RECORD', 0],
    [[load, apply], 'NO_RESPONSE', 2],
  ]) {
    await setup({ DNS_RULE_MAIN: group(actions) });
    assert.equal((await dns(await post())).flags & 15, rcode, String(logs));
    assert.ok(logs.join('').includes(code));
    assert.equal(calls.length, 0);
  }
});

test('DNS ECH source failures preserve previous successful acquisition, answer and failure event', async () => {
  for (const [handler, code] of [
    [async () => { throw new Error('private-ech-source-fault'); }, 'UPSTREAM_FAILED'],
    [async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { rcode: 5, records: [] }), { headers: { 'Content-Type': 'application/dns-message' } }), 'INVALID_ECH_SOURCE'],
    [async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [{ name: 'source.example', type: 65, ttl: 30, data: [0,1,0] }] }), { headers: { 'Content-Type': 'application/dns-message' } }), 'NO_ECH_CONFIG'],
  ]) {
    await setup({ DNS_UPSTREAMS: source('https://ech.test/private-source-token'), DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [https, load, { ...acquire, onError: 'continue' }] },
      { when: { field: 'lastAction.code', op: 'eq', value: code }, actions: [{ type: 'setTtl', ttl: 11 }, apply] },
    ] } }, handler);
    const result = await dns(await post(undefined, query('example.com',65)));
    assert.equal(result.flags & 15, 0, String(logs));
    assert.equal(result.records[0].ttl, 11);
    assert.deepEqual(params(result.records[0]).get(5), [...Buffer.from(config,'base64')]);
    assert.ok(logs.join('').includes(code));
    assert.ok(!/private-ech-source-fault|private-source-token/.test(logs.join('')));
    assert.equal(calls.length, 1);
  }
});

test('multiple HTTPS ECH candidates require identical bytes and never choose an arbitrary distinct configuration', async () => {
  const alternate = Buffer.from(config,'base64'); alternate[14] ^= 1;
  for (const identical of [true,false]) {
    await setup({ DNS_UPSTREAMS: source('https://ech.test/multiple'), DNS_RULE_MAIN: group([https, acquire, apply]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), {
      records: [config, identical ? config : alternate.toString('base64')].map(value => ({ name: 'source.example', type: 65, ttl: 30, data: sourceData(value) })),
    }), { headers: { 'Content-Type': 'application/dns-message' } }));
    assert.equal((await dns(await post(undefined, query('example.com',65)))).flags & 15, identical ? 0 : 2, String(logs));
    if (!identical) assert.ok(logs.join('').includes('AMBIGUOUS_ECH_CONFIG'));
  }
});

test('ECH edits preserve unrelated records and invalidate only the edited HTTPS RRset on all terminal paths', async () => {
  const signature = type => [0,type,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,...nameWire('example.com'),1];
  for (const end of [[],[{ type:'stop' }],[{ type:'return' }]]) {
    await setup({ DNS_UPSTREAMS: source('https://ech.test/signed'), DNS_RULE_MAIN: group([requestDefault, load, apply,...end]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [
      { name: 'example.com', type: 65, ttl: 60, data: [0,1,0,0,3,0,2,1,187] },
      { name: 'example.com', type: 46, ttl: 60, data: signature(65) },
      { name: 'example.com', type: 1, ttl: 60, data: [192,0,2,9] },
      { name: 'example.com', type: 46, ttl: 60, data: signature(1) },
    ] }), { headers: { 'Content-Type': 'application/dns-message' } }));
    const result = await dns(await post(undefined, query('example.com',65)));
    assert.equal(result.flags & 15, 0, String(logs));
    assert.equal(result.flags & 0x20, 0);
    assert.deepEqual(result.records.map(rr=>rr.type), [65,1,46]);
    assert.deepEqual(result.records[2].data, signature(1));
  }
});

test('invalid direct ECH and unreachable source references fail full preflight with no network work', async () => {
  for (const bad of ['', 'AAE=', config.slice(0,-1), 'not-base64']) {
    await setup({ DNS_RULE_MAIN: group([https,{ type:'return' }, { type:'loadEch',config:bad }]) });
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length,0);
  }
  await setup({ DNS_RULE_MAIN: group([https,{ type:'return' },acquire]) });
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length,0);
});
