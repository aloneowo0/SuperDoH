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



test('JSON adds native records without replacing unrelated response data', async () => {
  await setup({ DNS_RULE_MAIN: group([fixed, { type: 'addRecords', section: 'answer', records: [
    { name: 'alias.example.com', type: 'CNAME', ttl: 30, rdata: { Cname: { cname: 'example.com' } } },
  ] }]) });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0, String(logs));
  assert.deepEqual(result.records.map(rr => [rr.name, rr.type, rr.ttl]), [['example.com', 1, 60], ['alias.example.com', 5, 30]]);
  assert.equal(calls.length, 0);
});

test('removing AAAA yields NOERROR NODATA while retaining EDNS on every termination path', async () => {
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    await setup({ DNS_UPSTREAMS: source('https://records.test/aaaa'), DNS_RULE_MAIN: group([requestDefault, { type: 'removeRecords', where: { field: 'item.type', op: 'eq', value: 'AAAA' } }, ...end]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), {
      records: [{ name: 'example.com', type: 28, ttl: 60, data: [0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1] }, { name: '.', type: 41, class: 1232, ttl: 0, section: 2, data: [] }],
    }), { headers: { 'Content-Type': 'application/dns-message' } }));
    const result = await dns(await post(undefined, query('example.com', 28)));
    assert.equal(result.flags & 15, 0, String(logs));
    assert.deepEqual(result.records.map(rr => rr.type), [41]);
    assert.equal(result.flags & 0x20, 0);
  }
});

test('JSON selects addresses for replacement and later rules see the modified records', async () => {
  await setup({ DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [fixed, { type: 'replaceRecords', where: { field: 'item.ip', op: 'cidr', value: '192.0.2.0/24' }, records: [{ name: 'example.com', type: 'CNAME', ttl: 30, rdata: { Cname: { cname: 'target.example' } } }] }] },
    { when: { collection: 'response.records', quantifier: 'any', where: { field: 'item.target', op: 'eq', value: 'target.example' } }, actions: [{ type: 'setTtl', ttl: 7, where: { field: 'item.type', op: 'eq', value: 'CNAME' } }] },
  ] } });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0, String(logs));
  assert.deepEqual(result.records.map(rr => [rr.type, rr.ttl, rr.data]), [[5, 7, nameWire('target.example')]]);
});

const sig = [0,1,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,...nameWire('example.com'),1];
const signed = [
  { name: 'example.com', type: 1, ttl: 60, data: [192,0,2,9] },
  { name: 'example.com', type: 46, ttl: 60, data: sig },
  { name: 'other.example', type: 1, ttl: 12, data: [198,51,100,1] },
  { name: 'other.example', type: 46, ttl: 12, data: sig },
  { name: '.', type: 41, class: 1232, ttl: 0x1000000, section: 2, data: [] },
];
test('record edits invalidate only related signatures and preserve complete EDNS RCODE', async () => {
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    await setup({ DNS_UPSTREAMS: source('https://records.test/signed'), DNS_RULE_MAIN: group([requestDefault, { type: 'replaceRecords', where: { field: 'item.name', op: 'eq', value: 'example.com' }, records: [] }, ...end]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: signed }), { headers: { 'Content-Type': 'application/dns-message' } }));
    // Selecting RRSIG directly must fail instead of letting arbitrary JSON tamper with it.
    assert.equal((await dns(await post())).flags & 15, 2);
    await setup({ DNS_UPSTREAMS: source('https://records.test/signed'), DNS_RULE_MAIN: group([requestDefault, { type: 'replaceRecords', where: { all: [{ field: 'item.name', op: 'eq', value: 'example.com' }, { field: 'item.type', op: 'eq', value: 'A' }] }, records: [{ name: 'example.com', type: 'A', ttl: 30, rdata: { A: { addr: '203.0.113.1' } } }] }, ...end]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: signed }), { headers: { 'Content-Type': 'application/dns-message' } }));
    const result = await dns(await post());
    assert.equal(result.flags & 0x20, 0);
    assert.deepEqual(result.records.filter(rr => rr.type === 46).map(rr => rr.name), ['other.example']);
    assert.equal(result.records.find(rr => rr.type === 41).ttl, 0x1000000);
    assert.deepEqual(result.records.find(rr => rr.name === 'example.com').data, [203,0,113,1]);
  }
});

test('optional invalid record edits rollback while required errors terminate', async () => {
  const oversized = { type: 'addRecords', records: [{ name: 'example.com', type: 'TXT', ttl: 60, rdata: { Txt: ['x'.repeat(100)] } }] };
  for (const onError of ['continue', 'fail']) {
    await setup({ DNS_LIMITS: { maxResponseBytes: 80 }, DNS_RULE_MAIN: group([fixed, { ...oversized, onError }, { type: 'setTtl', ttl: 7 }]) });
    const result = await dns(await post());
    if (onError === 'continue') {
      assert.equal(result.records.length, 1);
      assert.equal(result.records[0].ttl, 7);
    } else assert.equal(result.flags & 15, 2);
    assert.ok(String(logs).includes('RESOURCE_LIMIT'));
  }
  await setup({ DNS_UPSTREAMS: source('https://records.test/protected'), DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [requestDefault, { type: 'removeRecords', where: { field: 'item.type', op: 'eq', value: 'OPT' }, onError: 'continue' }] },
    { when: { field: 'lastAction.code', op: 'eq', value: 'INVALID_STATE' }, actions: [{ type: 'setTtl', ttl: 7, where: { field: 'item.type', op: 'eq', value: 'A' } }] },
  ] } }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: signed }), { headers: { 'Content-Type': 'application/dns-message' } }));
  const retained = await dns(await post());
  assert.equal(retained.records.find(rr => rr.type === 41).ttl, 0x1000000);
  assert.equal(retained.records.find(rr => rr.type === 1).ttl, 7);
  assert.ok(String(logs).includes('rolled_back_continue'));
});

test('record mutation never poisons the cached original upstream response', async () => {
  const bindings = { DNS_CACHE: { read: true, write: true }, DNS_UPSTREAMS: source('https://records.test/cached'), DNS_RULE_MAIN: group([requestDefault, { type: 'replaceRecords', where: { field: 'item.type', op: 'eq', value: 'A' }, records: [{ name: 'example.com', type: 'A', ttl: 5, rdata: { A: { addr: '203.0.113.7' } } }] }]) };
  await setup(bindings);
  assert.deepEqual((await dns(await post())).records[0].data, [203,0,113,7]);
  assert.equal(calls.length, 1);
  await setup({ ...bindings, DNS_RULE_MAIN: group([requestDefault]) });
  const original = await dns(await post());
  assert.deepEqual(original.records[0].data, [192,0,2,9]);
  assert.equal(original.records[0].ttl, 60);
  assert.equal(calls.length, 0);
});

test('bad selectors, protected record insertion and native fields fail full preflight', async () => {
  for (const action of [
    { type: 'removeRecords' }, { type: 'replaceRecords', records: [] },
    { type: 'addRecords', section: 'invalid', records: [] },
    { type: 'addRecords', records: [{ name: '.', type: 'OPT', ttl: 0, rdata: { Opt: { options: [] } } }] },
    { type: 'addRecords', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: 'bad' } } }] },
    { type: 'removeRecords', where: { field: 'item.rdata', op: 'eq', value: 'code' } },
    { type: 'setTtl', ttl: 2, where: { collection: 'response.records', quantifier: 'any', where: { field: 'item.type', op: 'eq', value: 'A' } } },
  ]) {
    await setup({ DNS_UPSTREAMS: source('https://records.test/bad'), DNS_RULE_MAIN: group([requestDefault]), DNS_RULE_UNUSED: { order: 1, rules: [{ when: { field: 'query.name', op: 'eq', value: 'never.test' }, actions: [action] }] } });
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length, 0);
    assert.ok(String(logs).includes('INVALID_CONFIG'));
  }
});

test('no-match edits, empty additions and unchanged TTL preserve AD and unrelated signatures', async () => {
  await setup({ DNS_UPSTREAMS: source('https://records.test/no-op'), DNS_RULE_MAIN: group([
    requestDefault, { type: 'removeRecords', where: { field: 'item.name', op: 'eq', value: 'absent.test' } },
    { type: 'replaceRecords', where: { field: 'item.name', op: 'eq', value: 'absent.test' }, records: [] },
    { type: 'addRecords', records: [] },
    { type: 'setTtl', ttl: 60, where: { all: [{ field: 'item.name', op: 'eq', value: 'example.com' }, { field: 'item.type', op: 'eq', value: 'A' }] } },
  ]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: signed }), { headers: { 'Content-Type': 'application/dns-message' } }));
  const result = await dns(await post());
  assert.equal(result.flags & 0x20, 0x20);
  assert.equal(result.records.filter(rr => rr.type === 46).length, 2);
});

test('native and opaque records can be added in explicit sections without erasing original bytes', async () => {
  await setup({ DNS_RULE_MAIN: group([fixed,
    { type: 'addRecords', section: 'authority', records: [{ name: 'example.com', type: 'TXT', ttl: 30, rdata: { Txt: ['hello'] } }] },
    { type: 'addRecords', section: 'additional', records: [{ name: 'opaque.example', type: 65280, ttl: 20, rdata: { Raw: [1,2,3,255] } }] },
    { type: 'setTtl', ttl: 9, where: { field: 'item.section', op: 'eq', value: 'authority' } },
  ]) });
  const result = await dns(await post());
  assert.deepEqual(result.records.map(rr => [rr.type, rr.section, rr.ttl]), [[1,0,60], [16,1,9], [65280,2,20]]);
  assert.deepEqual(result.records[1].data, [5,104,101,108,108,111]);
  assert.deepEqual(result.records[2].data, [1,2,3,255]);
});

test('record selectors share compilation and runtime budgets instead of creating an unbounded loop', async () => {
  for (const limits of [{ maxConditionNodes: 1 }, { maxConditionSteps: 1 }]) {
    await setup({ DNS_LIMITS: limits, DNS_RULE_MAIN: group([fixed, { type: 'removeRecords', where: { all: [{ field: 'item.type', op: 'eq', value: 'A' }, { field: 'item.name', op: 'eq', value: 'example.com' }] } }]) });
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.ok(String(logs).includes('RESOURCE_LIMIT'));
  }
});

test('record actions require an existing response and optional failure remains observable', async () => {
  for (const action of [{ type: 'addRecords', records: [] }, { type: 'removeRecords', where: { field: 'item.type', op: 'eq', value: 'A' } }, { type: 'replaceRecords', where: { field: 'item.type', op: 'eq', value: 'A' }, records: [] }]) {
    await setup({ DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [{ ...action, onError: 'continue' }] },
      { when: { field: 'lastAction.code', op: 'eq', value: 'NO_RESPONSE' }, actions: [fixed] },
    ] } });
    assert.equal((await dns(await post())).records[0].ttl, 60);
    assert.ok(String(logs).includes('NO_RESPONSE'));
  }
});
