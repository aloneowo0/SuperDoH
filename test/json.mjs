import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { query, decode, responseWire } from './helpers/dns-wire.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const bundled = await build({
  entryPoints: [path.join(root, 'src/worker.js')], bundle: true, write: false,
  external: ['cloudflare:sockets'], format: 'esm', platform: 'browser', outfile: path.join(root, 'test/json-bundle.js'),
  plugins: [{ name: 'wasm-external', setup(build) {
    build.onResolve({ filter: /.wasm$/ }, args => ({
      path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
    }));
  } }],
});
const logs = [];
class TestLog extends Log { constructor() { super(LogLevel.ERROR); } log(message) { logs.push(message); } }
const calls = [];
let upstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
const mf = new Miniflare({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/json-bundle.js`, script: bundled.outputFiles[0].text,
  compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'],
  bindings: { DNS_CACHE: { read: false, write: false } }, log: new TestLog(),
  handleRuntimeStdio(stdout, stderr) { for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text)); },
  modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }, { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }],
  outboundService: async request => {
    calls.push(request);
    const response = await upstream(request);
    if (!response.headers.has('date')) response.headers.set('date', new Date(Date.now() + 60_000).toUTCString());
    return response;
  },
});
after(() => mf.dispose());
const source = url => ({ default: { transport: 'https', url } });
const group = actions => ({ order: 0, rules: [{ actions }] });
const fixed = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.8' } } }] };
async function setup(bindings = {}, handler) {
  calls.length = 0; logs.length = 0;
  upstream = handler ?? (async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } }));
  await mf.setOptions({
    modules: true, modulesRoot: root, scriptPath: `${root}/test/json-bundle.js`, script: bundled.outputFiles[0].text,
    compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'],
    bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
    handleRuntimeStdio(stdout, stderr) { for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text)); },
    modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }, { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }],
    outboundService: async request => {
      calls.push(request);
      const response = await upstream(request);
      if (!response.headers.has('date')) response.headers.set('date', new Date(Date.now() + 60_000).toUTCString());
      return response;
    },
  });
}
async function json(response) {
  assert.equal(response.headers.get('content-type'), 'application/dns-json');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return response.json();
}

test('opt-in JSON GET reuses the standard response pipeline and preserves response semantics', async () => {
  await setup({ DNS_JSON: true, DNS_RULE_FIXED: group([fixed]) });
  const params = new URLSearchParams({ name: 'example.com' });
  const result = await json(await mf.dispatchFetch(`https://doh.test/dns-query?${params}`));
  const wire = decode(responseWire(query('example.com', 1), { records: [{ name: 'example.com', type: 1, ttl: 60, data: [192, 0, 2, 8] }] }));
  assert.equal(result.Status, 0);
  assert.deepEqual(result.Question, [{ name: 'example.com', type: 1, class: 1 }]);
  assert.deepEqual(result.Answer.map(rr => [rr.name, rr.type, rr.TTL, rr.data]), [['example.com', 1, 60, '192.0.2.8']]);
  assert.deepEqual(wire.records.map(rr => [rr.name, rr.type, rr.ttl, rr.data]), [['example.com', 1, 60, [192, 0, 2, 8]]]);
  assert.equal(calls.length, 0);
});

test('JSON GET and method validation are unchanged at the /resolve alias', async () => {
  await setup({ DNS_JSON: true, DNS_PATH_KEY: 'json-key', DNS_RULE_FIXED: group([fixed]) });
  const result = await json(await mf.dispatchFetch('https://doh.test/json-key/resolve?name=example.com'));
  assert.equal(result.Status, 0);
  assert.deepEqual(result.Answer.map(rr => [rr.name, rr.type, rr.TTL, rr.data]), [['example.com', 1, 60, '192.0.2.8']]);
  const post = await mf.dispatchFetch('https://doh.test/json-key/resolve?name=example.com', {
    method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query(),
  });
  assert.equal(post.status, 405);
  assert.equal((await mf.dispatchFetch('https://doh.test/resolve?name=example.com')).status, 404);
});

test('JSON accepts numeric type and CD, and forwards one type-specific query through the named upstream', async () => {
  let sent;
  await setup({ DNS_JSON: 'true', DNS_UPSTREAMS: source('https://resolver.test/dns'), DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default' }]) }, async request => {
    const wire = new Uint8Array(await request.arrayBuffer());
    sent = decode(wire);
    return new Response(responseWire(wire), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  const result = await json(await mf.dispatchFetch('https://doh.test/dns-query?name=example.com&type=28&cd=true'));
  assert.equal(result.Status, 0);
  assert.equal(sent.questions[0].type, 28);
  assert.equal(sent.flags & 0x10, 0x10);
  assert.equal(calls.length, 1);
});

test('JSON query validation rejects duplicate, unknown, mixed, invalid and oversized parameters before network access', async () => {
  await setup({ DNS_JSON: true, DNS_UPSTREAMS: source('https://resolver.test/dns'), DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default' }]) });
  for (const path of [
    '/dns-query?name=example.com&name=example.net',
    '/dns-query?name=example.com&other=x',
    '/dns-query?name=example.com&dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE',
    '/dns-query?name=bad..example',
    '/dns-query?name=example.com&type=HTTPS&type=A',
    '/dns-query?name=example.com&cd=yes',
    '/dns-query?name=' + 'a'.repeat(255) + '.com',
  ]) {
    const response = await mf.dispatchFetch('https://doh.test' + path);
    assert.equal(response.status, 400, path);
    const body = await json(response);
    assert.equal(typeof body.error.code, 'string');
    assert.equal(typeof body.error.message, 'string');
  }
  const rejectedAccept = await mf.dispatchFetch('https://doh.test/dns-query', { headers: { Accept: 'application/dns-json;q=0' } });
  assert.equal(rejectedAccept.status, 406);
  assert.equal((await json(rejectedAccept)).error.code, 'NOT_ACCEPTABLE');
  const oversizedUrl = await mf.dispatchFetch('https://doh.test/dns-query?name=example.com&unused=' + 'x'.repeat(2100));
  assert.equal(oversizedUrl.status, 414);
  assert.equal((await json(oversizedUrl)).error.code, 'URI_TOO_LONG');
  assert.equal(calls.length, 0);
});

test('valid DNS failures use JSON DNS Status while authentication and disabled mode stay side-effect free', async () => {
  await setup({ DNS_JSON: true, DNS_PATH_KEY: 'json-key', DNS_RULE_BAD: '{broken', DNS_UPSTREAMS: source('https://resolver.test/private') });
  const denied = await mf.dispatchFetch('https://doh.test/dns-query?name=example.com');
  assert.equal(denied.status, 404);
  assert.ok(!(await denied.text()).includes('json-key'));
  assert.equal(calls.length, 0);

  await setup({ DNS_JSON: true, DNS_PATH_KEY: 'json-key', DNS_UPSTREAMS: source('https://resolver.test/dns'), DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default' }]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { rcode: 3, records: [] }), { headers: { 'Content-Type': 'application/dns-message' } }));
  const nx = await json(await mf.dispatchFetch('https://doh.test/json-key/dns-query?name=example.com'));
  assert.equal(nx.Status, 3);
  assert.deepEqual(nx.Answer, []);
  assert.equal(calls.length, 1);

  await setup({ DNS_JSON: false });
  const disabled = await mf.dispatchFetch('https://doh.test/dns-query?name=example.com');
  assert.equal(disabled.status, 404);
  assert.equal(calls.length, 0);
});

test('DNS_JSON accepts only boolean or exact true/false strings and execution errors become JSON SERVFAIL', async () => {
  await setup({ DNS_JSON: 'yes' });
  const malformedConfig = await mf.dispatchFetch('https://doh.test/dns-query?name=example.com');
  assert.equal(malformedConfig.status, 500);
  assert.equal((await json(malformedConfig)).error.code, 'INVALID_CONFIG');

  await setup({ DNS_JSON: true, DNS_RULE_STOP: group([{ type: 'stop' }]) });
  const failed = await json(await mf.dispatchFetch('https://doh.test/dns-query?name=example.com'));
  assert.equal(failed.Status, 2);
  assert.deepEqual(failed.Answer, []);
});

test('JSON output reflects finalized wire flags, RR edits, unknown records and complete EDNS RCODE', async () => {
  const signature = [0,1,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,7,101,120,97,109,112,108,101,3,99,111,109,0,1];
  const records = [
    { name: 'example.com', type: 1, ttl: 60, data: [192, 0, 2, 9] },
    { name: 'example.com', type: 46, ttl: 60, data: signature },
    { name: 'opaque.example', type: 65280, ttl: 33, data: [1, 2, 3] },
    { name: '.', type: 41, class: 1232, ttl: 0xab000000, section: 2, data: [] },
  ];
  await setup({ DNS_JSON: true, DNS_UPSTREAMS: source('https://resolver.test/dns'), DNS_RULE_MAIN: group([
    { type: 'queryUpstream', upstream: 'default' },
    { type: 'setTtl', ttl: 7, where: { all: [{ field: 'item.name', op: 'eq', value: 'example.com' }, { field: 'item.type', op: 'eq', value: 'A' }] } },
  ]) }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { rcode: 12, records, flags: 0x81b0 }), { headers: { 'Content-Type': 'application/dns-message' } }));
  const jsonResult = await json(await mf.dispatchFetch('https://doh.test/dns-query?name=example.com&type=A&cd=true'));
  const wireResult = decode(await (await mf.dispatchFetch('https://doh.test/dns-query', {
    method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query('example.com', 1),
  })).arrayBuffer());
  assert.equal(jsonResult.Status, 0xabc);
  assert.equal(jsonResult.AD, false);
  assert.equal(jsonResult.CD, true);
  assert.equal(wireResult.flags & 0x20, 0);
  assert.equal(wireResult.flags & 0x10, 0x10);
  assert.equal(wireResult.records.find(rr => rr.type === 41).ttl >>> 24, 0xab);
  assert.deepEqual(jsonResult.Answer.map(rr => [rr.name, rr.type, rr.class, rr.TTL]), wireResult.records.filter(rr => rr.section === 0).map(rr => [rr.name, rr.type, 1, rr.ttl]));
  assert.equal(jsonResult.Answer.find(rr => rr.type === 1).TTL, 7);
  assert.equal(jsonResult.Answer.find(rr => rr.type === 46), undefined);
  assert.deepEqual(wireResult.records.filter(rr => rr.type === 46), []);
  assert.equal(jsonResult.Answer.find(rr => rr.type === 65280).TTL, 33);
  assert.equal(jsonResult.Answer.find(rr => rr.type === 65280).data, '\\# 3 01 02 03');
});

test('JSON required and optional action failures use the same rollback contract', async () => {
  for (const onError of ['continue', 'fail']) {
    await setup({ DNS_JSON: true, DNS_UPSTREAMS: source('https://resolver.test/private-path?token=secret'), DNS_RULE_MAIN: group([
      fixed,
      { type: 'queryUpstream', upstream: 'default', onError },
      { type: 'setTtl', ttl: 19 },
    ]) }, async () => new Response('private-upstream-body', { status: 503 }));
    const result = await json(await mf.dispatchFetch('https://doh.test/dns-query?name=example.com'));
    assert.equal(result.Status, onError === 'continue' ? 0 : 2);
    assert.equal(result.Answer.length, onError === 'continue' ? 1 : 0);
    if (onError === 'continue') assert.equal(result.Answer[0].TTL, 19);
    assert.equal(calls.length, 1);
    await new Promise(resolve => setTimeout(resolve, 10));
    for (const secret of ['private-path', 'token=secret', 'private-upstream-body']) assert.ok(!logs.join('').includes(secret));
  }
});

test('JSON requests share the upstream response cache and still run response rules per request', async () => {
  let hit = 0;
  const common = { DNS_CACHE: { read: true, write: true }, DNS_UPSTREAMS: source('https://resolver.test/cached'), DNS_RULE_UP: group([
    { type: 'queryUpstream', upstream: 'default' },
    { type: 'setTtl', ttl: 8 },
  ]) };
  await setup({ DNS_JSON: true, ...common }, async request => {
    hit++;
    return new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [{ name: 'example.com', type: 1, ttl: 60, data: [192, 0, 2, 9] }] }), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  for (let i = 0; i < 2; i++) {
    const result = await json(await mf.dispatchFetch('https://doh.test/dns-query?name=example.com'));
    assert.equal(result.Answer[0].TTL, 8);
  }
  assert.equal(hit, 1);
});

test('enabling JSON leaves standard wire GET and POST behavior unchanged', async () => {
  await setup({ DNS_JSON: true, DNS_RULE_FIXED: group([fixed]) });
  const requests = [
    mf.dispatchFetch('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query() }),
    mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.from(query()).toString('base64url')),
  ];
  for (const response of await Promise.all(requests)) {
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Content-Type'), 'application/dns-message');
    const result = decode(new Uint8Array(await response.arrayBuffer()));
    assert.equal(result.records[0].ttl, 60);
    assert.deepEqual(result.records[0].data, [192, 0, 2, 8]);
  }
  assert.equal(calls.length, 0);
  const jsonPost = await mf.dispatchFetch('https://doh.test/dns-query?name=example.com', {
    method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query(),
  });
  assert.equal(jsonPost.status, 405);
  assert.equal((await json(jsonPost)).error.code, 'METHOD_NOT_ALLOWED');
  assert.equal(calls.length, 0);
});

test('JSON intent follows decoded parameter names and method errors advertise only GET', async () => {
  await setup({ DNS_JSON: true, DNS_RULE_FIXED: group([fixed]) });
  const response = await mf.dispatchFetch('https://doh.test/dns-query?%6eame=example.com&%74ype=A');
  assert.equal(response.status, 200);
  assert.equal((await json(response)).Status, 0);
  const post = await mf.dispatchFetch('https://doh.test/dns-query?name=example.com', { method: 'POST' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('Allow'), 'GET');
  assert.equal(calls.length, 0);
});
