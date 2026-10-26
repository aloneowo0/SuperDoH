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
const optionsBundle = await bundleWorker('test/doh-options-worker.js');
let activeBundle = bundle;
const logs = [];
class TestLog extends Log {
  constructor() { super(LogLevel.ERROR); }
  log(message) { logs.push(message); }
}
const calls = [];
let upstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
const options = bindings => ({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/doh-bundle.js`, script: activeBundle.outputFiles[0].text,
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
    // Keep these transport/record fixtures at zero HTTP age; cache tests cover aging separately.
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
async function setup(bindings = {}, handler, callerOptions = false) {
  activeBundle = callerOptions ? optionsBundle : bundle;
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

test('public DoH GET and POST return custom DNS answers without contacting an upstream', async () => {
  await setup({ DNS_RULE_FIXED: group([fixed]) });
  for (const response of [await post(), await mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.from(query()).toString('base64url'))]) {
    const result = await dns(response);
    assert.equal(result.id, 0x4242);
    assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
    assert.deepEqual(result.records[0].data, [192, 0, 2, 1]);
    assert.equal(result.flags & 0x20, 0);
    assert.equal(result.flags & 0x110, 0x110);
  }
  assert.equal(calls.length, 0);
});

test('an explicitly configured named upstream supplies one validated DNS response', async () => {
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/private-source?token=private-token'), DNS_RULE_UP: group([requestDefault]) });
  const result = await dns(await post());
  assert.deepEqual(result.records[0].data, [192, 0, 2, 9]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].headers['content-type'], 'application/dns-message');
});

test('optional Secret protects only the exact key path before invalid rules or upstream work', async () => {
  await setup({ DNS_PATH_KEY: 'private-key', DNS_RULE_BAD: '{broken', DNS_UPSTREAMS: source('not a URL'), DNS_LIMITS: { bad: 1 } });
  for (const path of ['/dns-query', '/wrong/dns-query', '/private-key/dns-query/', '/%70rivate-key/dns-query', '//private-key/dns-query']) {
    const response = await post('https://doh.test' + path);
    assert.equal(response.status, 404, path);
    assert.ok(!(await response.text()).includes('private-key'));
  }
  assert.equal(calls.length, 0);
  await setup({ DNS_PATH_KEY: 'private-key', DNS_RULE_FIXED: group([fixed]) });
  assert.equal((await dns(await post('https://doh.test/private-key/dns-query'))).records[0].ttl, 60);
  assert.equal((await post('https://doh.test/dns-query?key=private-key', query(), { Authorization: 'Bearer private-key' })).status, 404);
  await setup({ DNS_PATH_KEY: '', DNS_RULE_FIXED: group([fixed]) });
  assert.equal((await post()).status, 500);
});

test('HTTP and malformed DoH inputs return explicit HTTP errors without upstream queries', async () => {
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query') });
  const encoded = Buffer.from(query()).toString('base64url');
  const cases = [
    [() => mf.dispatchFetch('https://doh.test/dns-query', { method: 'PUT' }), 405],
    [() => post(undefined, query(), { Accept: 'application/dns-json' }), 406],
    [() => post(undefined, query(), { Accept: 'application/dns-message;q=0, */*;q=1' }), 406],
    [() => post(undefined, query(), { 'Content-Type': 'text/plain' }), 415],
    [() => post(undefined, new Uint8Array()), 400],
    [() => post(undefined, Uint8Array.of(1, 2, 3)), 400],
    [() => mf.dispatchFetch('https://doh.test/dns-query'), 400],
    [() => mf.dispatchFetch('https://doh.test/dns-query?dns=' + encoded + '&dns=' + encoded), 400],
    [() => mf.dispatchFetch('https://doh.test/dns-query?dns=' + encoded + '='), 400],
    [() => mf.dispatchFetch('https://doh.test/dns-query?dns=+///'), 400],
    [() => mf.dispatchFetch('https://doh.test/dns-query?dns=A'), 400],
    [() => post('https://doh.test/dns-query?key=secret'), 400],
  ];
  for (const [send, expected] of cases) {
    const response = await send();
    assert.equal(response.status, expected);
    assert.notEqual(response.headers.get('Content-Type'), 'application/dns-message');
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
  }
  assert.equal(calls.length, 0);
});

test('valid queries failing configuration or lacking an upstream get bounded correlated SERVFAIL', async () => {
  for (const bindings of [{}, { DNS_RULE_BAD: '{invalid' }, { DNS_LIMITS: { unknown: 1 } }, { DNS_UPSTREAMS: source('http://private.test/secret') },
    { DNS_LIMITS: { maxResponseBytes: 1 }, DNS_RULE_FIXED: group([fixed]) }]) {
    await setup(bindings);
    const result = await dns(await post());
    assert.equal(result.flags & 15, 2);
    assert.equal(result.flags & 0x20, 0);
    assert.equal(result.id, 0x4242);
    assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
    assert.deepEqual(result.records, []);
    assert.equal(calls.length, 0);
  }
});

test('explicit queries use current questions, replace prior answers and combine with later rules', async () => {
  const sent = [];
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_FLOW: { order: 0, rules: [
    { actions: [fixed, { type: 'rewriteQuery', name: 'alias.example', queryType: 'AAAA' }, { type: 'queryUpstream', upstream: 'default' }] },
    { when: { field: 'response.rcode', op: 'eq', value: 0 }, actions: [{ type: 'setTtl', ttl: 12 }, { type: 'return' }] },
  ] } }, async request => {
    const wire = new Uint8Array(await request.arrayBuffer()); sent.push(decode(wire));
    return new Response(responseWire(wire, { records: [{ name: 'alias.example', type: 28, ttl: 60, data: [32, 1, 13, 184, ...Array(11).fill(0), 1] }] }), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  const result = await dns(await post());
  assert.equal(calls.length, 1);
  assert.deepEqual(sent[0].questions, [{ name: 'alias.example', type: 28, class: 1 }]);
  assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].type, 28);
  assert.equal(result.records[0].ttl, 12);
  assert.equal(result.flags & 0x20, 0);
});

test('valid NXDOMAIN and NOERROR empty answers never trigger an extra default query', async () => {
  for (const rcode of [0, 3]) {
    await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default' }]) }, async request =>
      new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { rcode, records: [] }), { headers: { 'Content-Type': 'application/dns-message' } }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, rcode);
    assert.equal(result.records.length, 0);
    assert.equal(calls.length, 1);
  }
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_STOP: group([{ type: 'stop' }]) });
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 0);
});

test('optional upstream failures roll back the action, required failures return SERVFAIL with redacted events', async () => {
  for (const optional of [false, true]) {
    await setup({ DNS_PATH_KEY: 'private-key', DNS_UPSTREAMS: source('https://resolver.test/private-source?token=private-token'),
      DNS_RULE_UP: group([fixed, { type: 'queryUpstream', upstream: 'default', onError: optional ? 'continue' : 'fail' }, { type: 'setTtl', ttl: 19 }]),
    }, async () => new Response('private-response-secret', { status: 503 }));
    const result = await dns(await post('https://doh.test/private-key/dns-query'));
    assert.equal(result.flags & 15, optional ? 0 : 2);
    if (optional) {
      assert.deepEqual(result.records[0].data, [192, 0, 2, 1]);
      assert.equal(result.records[0].ttl, 19);
    }
    assert.equal(calls.length, 1);
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    assert.ok(output.includes('UPSTREAM_FAILED'), output);
    assert.ok(output.includes(optional ? 'rolled_back_continue' : 'terminated'), output);
    for (const secret of ['private-key', 'private-source', 'private-token', 'private-response-secret']) assert.ok(!output.includes(secret), output);
  }
});

test('upstream transport, media, DNS validity and correspondence failures never become answers', async () => {
  for (const mode of ['http', 'redirect', 'media', 'wire', 'id', 'question', 'query', 'edns']) {
    await setup({ DNS_UPSTREAMS: source('https://resolver.test/private-path'), DNS_RULE_UP: group([requestDefault]) }, async request => {
      const wire = new Uint8Array(await request.arrayBuffer());
      if (mode === 'http') return new Response('secret', { status: 500 });
      if (mode === 'redirect') return new Response(null, { status: 302, headers: { Location: 'https://other.test/leak' } });
      if (mode === 'media') return new Response(responseWire(wire), { headers: { 'Content-Type': 'text/plain' } });
      let bytes = responseWire(wire);
      if (mode === 'wire') bytes = Uint8Array.of(1, 2, 3);
      if (mode === 'id') bytes[0] ^= 1;
      if (mode === 'question') bytes[13] ^= 1;
      if (mode === 'query') bytes = wire;
      if (mode === 'servfail' || mode === 'refused') bytes = responseWire(wire, { rcode: mode === 'servfail' ? 2 : 5 });
      if (mode === 'edns') bytes = responseWire(wire, { records: [{ name: '.', type: 41, class: 1232, ttl: 0x10000, data: [], section: 2 }] });
      return new Response(bytes, { headers: { 'Content-Type': 'application/dns-message' } });
    });
    const result = await dns(await post());
    assert.equal(result.flags & 15, 2, mode);
    assert.deepEqual(result.records, [], mode);
    assert.equal(calls.length, 1, mode);
  }
});

test('network attempts are bounded across explicit actions without automatic retry', async () => {
  await setup({ DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([
    { type: 'queryUpstream', upstream: 'default' }, { type: 'queryUpstream', upstream: 'default', onError: 'continue' }, { type: 'setTtl', ttl: 18 },
  ]) });
  const first = await dns(await post());
  assert.equal(first.records[0].ttl, 18);
  assert.equal(calls.length, 1);
  let attempts = 0;
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default', onError: 'continue' }]) }, async request => {
    if (++attempts === 1) return new Response(null, { status: 503 });
    return new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 1);
  await setup({ DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default', onError: 'continue' }]) },
    async () => new Response(null, { status: 503 }));
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 1);
});

test('HTTP input and streaming upstream bodies reject excess bytes without waiting for EOF', async () => {
  await setup({ DNS_LIMITS: { maxQueryBytes: 32 }, DNS_RULE_FIXED: group([fixed]) });
  assert.equal((await post(undefined, new Uint8Array(33))).status, 413);
  assert.equal((await mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.alloc(33).toString('base64url'))).status, 414);
  await setup({ DNS_LIMITS: { maxResponseBytes: 64 }, DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([requestDefault]) }, async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(128)); },
  }), { headers: { 'Content-Type': 'application/dns-message' } }));
  assert.equal((await dns(await post())).flags & 15, 2);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('RESOURCE_LIMIT'), logs.join(''));
});

test('upstream header and body waits are bounded by per-call timeout and the shared execution deadline', async () => {
  for (const mode of ['headers', 'body', 'total']) {
    await setup({ DNS_LIMITS: { upstreamTimeoutMs: mode === 'total' ? 500 : 30, maxExecutionTimeMs: mode === 'total' ? 30 : 1000 },
      DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([requestDefault]),
    }, async request => {
      if (mode !== 'body') await new Promise(resolve => setTimeout(resolve, 100));
      if (mode === 'body') return new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/dns-message' } });
      return new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
    });
    const result = await dns(await post());
    assert.equal(result.flags & 15, 2, mode);
    assert.equal(calls.length, 1);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(logs.join('').includes(mode === 'total' ? 'EXECUTION_TIMEOUT' : 'UPSTREAM_TIMEOUT'), logs.join(''));
  }
});

test('optional upstream timeouts do not cancel later built-in actions or reset the shared deadline', async () => {
  await setup({ DNS_LIMITS: { upstreamTimeoutMs: 25, maxExecutionTimeMs: 1000 }, DNS_UPSTREAMS: source('https://resolver.test/dns-query'),
    DNS_RULE_UP: group([fixed, { type: 'queryUpstream', upstream: 'default', onError: 'continue' }, { type: 'setTtl', ttl: 11 }]),
  }, async () => { await new Promise(resolve => setTimeout(resolve, 100)); return new Response(null, { status: 503 }); });
  const result = await dns(await post());
  assert.equal(result.records[0].ttl, 11);
  assert.equal(calls.length, 1);
});


const signature = [0, 1, 8, 2, 0, 0, 0, 60, 119, 53, 148, 0, 59, 154, 202, 0, 0, 1, ...nameWire('example.com'), 1];
const signedRecords = [
  { name: 'example.com', type: 1, ttl: 60, data: [192, 0, 2, 9] },
  { name: 'example.com', type: 46, ttl: 60, data: signature },
  { name: 'other.example', type: 1, ttl: 12, data: [192, 0, 2, 8] },
  { name: 'other.example', type: 46, ttl: 12, data: signature },
  { name: '.', type: 41, class: 1232, ttl: 0, data: [], section: 2 },
];
const signedUpstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: signedRecords }), { headers: { 'Content-Type': 'application/dns-message' } });

test('unmodified upstream answers retain AD and signatures; TTL edits invalidate only changed RRsets on every termination path', async () => {
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([requestDefault]) }, signedUpstream);
  const untouched = await dns(await post());
  assert.equal(untouched.flags & 0x20, 0x20);
  assert.equal(untouched.records.filter(rr => rr.type === 46).length, 2);
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([
      { type: 'queryUpstream', upstream: 'default' }, { type: 'setTtl', ttl: 12 }, ...end,
    ]) }, signedUpstream);
    const edited = await dns(await post());
    assert.equal(edited.flags & 0x20, 0);
    assert.deepEqual(edited.records.filter(rr => rr.type === 46).map(rr => rr.name), ['other.example']);
    assert.equal(edited.records.find(rr => rr.type === 41).ttl, 0);
    assert.equal(calls.length, 1);
  }
});


test('request-body waiting is bounded before DNS parsing and does not contact upstreams', async () => {
  await setup({ DNS_LIMITS: { maxExecutionTimeMs: 30 }, DNS_UPSTREAMS: source('https://resolver.test/dns-query') });
  const response = await mf.dispatchFetch('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' },
    duplex: 'half', body: new ReadableStream({ start(controller) { controller.enqueue(query()); } }),
  });
  assert.equal(response.status, 408);
  assert.equal(calls.length, 0);
});

test('standard media negotiation allows optional whitespace but never serves DNS over plaintext HTTP', async () => {
  await setup({ DNS_RULE_FIXED: group([fixed]) });
  assert.equal((await post(undefined, query(), { Accept: 'application/dns-message ; q=1' })).status, 200);
  assert.equal((await post('http://doh.test/dns-query')).status, 400);
  assert.equal(calls.length, 0);
});

test('the delivered Worker configuration disables automatic URL-bearing invocation logs and traces', async () => {
  const { readFile } = await import('node:fs/promises');
  const text = await readFile(path.join(root, 'wrangler.jsonc'), 'utf8');
  const config = JSON.parse(text.replace(/^\s*\/\/.*$/gm, ''));
  assert.equal(config.observability.logs.invocation_logs, false);
  assert.equal(config.observability.traces.enabled, false);
});


const named = () => ({
  DNS_UPSTREAMS: { primary: { transport: 'https', url: 'https://primary.test/private?token=secret' }, backup: { transport: 'https', urlSecret: 'BACKUP_URL' }, unused: { transport: 'https', url: 'https://unused.test/dns-query' } },
  BACKUP_URL: 'https://backup.test/private-backup?token=backup-secret',
});
const upstreamReply = async (request, options) => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), options), { headers: { 'Content-Type': 'application/dns-message' } });
const failedRequest = { field: 'lastAction.success', op: 'eq', value: false };
const fallbackRules = (when = failedRequest) => ({ order: 0, rules: [
  { actions: [{ type: 'queryUpstream', upstream: 'primary', onError: 'continue' }] },
  { when, actions: [{ type: 'queryUpstream', upstream: 'backup' }] },
] });

test('JSON sequential fallback retains the failed action event after success', async () => {
  await setup({ ...named(), DNS_RULE_UP: fallbackRules() }, request => new URL(request.url).hostname === 'primary.test' ? new Response('private-error', { status: 503 }) : upstreamReply(request));
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['primary.test', 'backup.test']);
  const output = logs.join('');
  assert.ok(output.includes('action_failed') && output.includes('rolled_back_continue'), output);
  for (const secret of ['private?', 'token=', 'backup-secret', 'private-error', 'private-backup']) assert.ok(!output.includes(secret), output);
});

test('valid DNS RCODEs are successful requests and only JSON response conditions request a second source', async () => {
  for (const rcode of [0, 2, 3, 5]) {
    const when = { any: [failedRequest, { field: 'response.rcode', op: 'in', value: [2, 5] }] };
    await setup({ ...named(), DNS_RULE_UP: fallbackRules(when) }, request => upstreamReply(request, { rcode: new URL(request.url).hostname === 'primary.test' ? rcode : 0, records: [] }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, rcode === 2 || rcode === 5 ? 0 : rcode);
    assert.equal(result.records.length, 0);
    assert.equal(calls.length, rcode === 2 || rcode === 5 ? 2 : 1);
    assert.equal(logs.length, 0);
  }
});

test('record conditions express a JSON response policy without a hidden adoption step', async () => {
  const when = { not: { collection: 'response.records', quantifier: 'any', where: { all: [
    { field: 'item.section', op: 'eq', value: 'answer' }, { field: 'item.type', op: 'eq', value: 'A' },
  ] } } };
  await setup({ ...named(), DNS_RULE_UP: fallbackRules(when) }, request => upstreamReply(request, new URL(request.url).hostname === 'primary.test' ? { records: [] } : undefined));
  assert.equal((await dns(await post())).records.length, 1); assert.equal(calls.length, 2);
});

test('all named sources and unreachable references are validated before any action', async () => {
  const bad = [
    { DNS_UPSTREAMS: '{bad' },
    { DNS_UPSTREAMS: { invalid: { transport: 'https', url: 'http://private.test' } } },
    { DNS_UPSTREAMS: { invalid: { transport: 'https', urlSecret: 'MISSING' } } },
    { DNS_UPSTREAMS: { invalid: { transport: 'https', urlSecret: 'ABSENT_VALUE' } }, ABSENT_VALUE: null },
    { DNS_UPSTREAMS: { invalid: { transport: 'https', url: 'https://test/', urlSecret: 'BACKUP_URL' } } },
    { DNS_RULE_BADREF: { order: 99, rules: [{ when: { field: 'query.type', op: 'eq', value: 'AAAA' }, actions: [{ type: 'queryUpstream', upstream: 'missing' }] }] } },
    { DNS_RULE_BADREF: group([{ type: 'return' }, { type: 'queryUpstream', upstream: 'toString' }]) },
  ];
  for (const patch of bad) {
    await setup({ ...named(), DNS_RULE_FIXED: group([fixed, { type: 'return' }]), ...patch });
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(patch)); assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG'));
  }
});

test('named sources support JSON text and explicit reuse but never initiate requests themselves', async () => {
  const bindings = named(); bindings.DNS_UPSTREAMS = JSON.stringify(bindings.DNS_UPSTREAMS);
  bindings.DNS_RULE_REUSE = { order: 0, rules: [
    { actions: [{ type: 'queryUpstream', upstream: 'backup' }] },
    { when: { field: 'lastAction.success', op: 'eq', value: true }, actions: [{ type: 'queryUpstream', upstream: 'backup' }, { type: 'return' }] },
  ] };
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['backup.test', 'backup.test']);
  delete bindings.DNS_RULE_REUSE;
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 2); assert.equal(calls.length, 0);
});

test('stop never queries another source whether or not an answer exists', async () => {
  for (const hasAnswer of [false, true]) {
    await setup({ ...named(), DNS_RULE_UP: group([...(hasAnswer ? [{ type: 'queryUpstream', upstream: 'backup' }] : []), { type: 'stop' }]) });
    assert.equal((await dns(await post())).flags & 15, hasAnswer ? 0 : 2);
    assert.equal(calls.length, hasAnswer ? 1 : 0);
    if (hasAnswer) assert.equal(new URL(calls[0].url).hostname, 'backup.test');
  }
});

test('HTTP, transport, DNS and correspondence failures trigger only the explicitly configured fallback', async () => {
  for (const mode of ['http', 'redirect', 'network', 'media', 'wire', 'id', 'question', 'edns']) {
    await setup({ ...named(), DNS_RULE_UP: fallbackRules() }, async request => {
      if (new URL(request.url).hostname !== 'primary.test') return upstreamReply(request);
      if (mode === 'http') return new Response(null, { status: 503 });
      if (mode === 'redirect') return new Response(null, { status: 302, headers: { Location: 'https://unused.test/' } });
      if (mode === 'network') throw new Error('private-transport-error');
      if (mode === 'media') return new Response('not DNS');
      const wire = new Uint8Array(await request.arrayBuffer()); let bytes = responseWire(wire);
      if (mode === 'wire') bytes = Uint8Array.of(1);
      if (mode === 'id') bytes[0] ^= 1;
      if (mode === 'question') bytes[13] ^= 1;
      if (mode === 'edns') bytes = responseWire(wire, { records: [{ name: '.', type: 41, class: 1232, ttl: 0x10000, data: [], section: 2 }] });
      return new Response(bytes, { headers: { 'Content-Type': 'application/dns-message' } });
    });
    assert.equal((await dns(await post())).flags & 15, 0, mode);
    assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['primary.test', 'backup.test'], mode);
  }
});

test('valid REFUSED is preserved but invalid correspondence remains a request failure', async () => {
  for (const wrongId of [false, true]) {
    await setup({ ...named(), DNS_RULE_UP: fallbackRules() }, async request => {
      const bytes = responseWire(new Uint8Array(await request.arrayBuffer()), { rcode: 5, records: [] });
      if (wrongId && new URL(request.url).hostname === 'primary.test') bytes[0] ^= 1;
      return new Response(bytes, { headers: { 'Content-Type': 'application/dns-message' } });
    });
    assert.equal((await dns(await post())).flags & 15, 5); assert.equal(calls.length, wrongId ? 2 : 1);
    assert.equal(logs.join('').includes('UPSTREAM_INVALID'), wrongId);
  }
});

test('sequential request failures retain each action reason and respect required or optional rollback', async () => {
  for (const optional of [false, true]) {
    await setup({ ...named(), DNS_RULE_UP: group([fixed,
      { type: 'queryUpstream', upstream: 'primary', onError: optional ? 'continue' : 'fail' },
      { type: 'queryUpstream', upstream: 'backup', onError: 'continue' }, { type: 'setTtl', ttl: 17 },
    ]) }, async () => new Response(null, { status: 503 }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, optional ? 0 : 2);
    if (optional) { assert.equal(result.records[0].ttl, 17); assert.deepEqual(result.records[0].data, [192, 0, 2, 1]); }
    assert.equal(calls.length, optional ? 2 : 1);
    const events = logs.join('').split('\n').flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
    const failures = events.filter(e => e.event === 'action_failed');
    assert.equal(failures.length, optional ? 2 : 1, logs.join(''));
    assert.deepEqual(failures.map(e => e.location.action), optional ? [1, 2] : [1]);
    assert.ok(failures.every(e => e.code === 'UPSTREAM_FAILED' && e.location.group === 'DNS_RULE_UP' && e.location.rule === 0));
    assert.ok(failures.every(e => e.disposition === (optional ? 'rolled_back_continue' : 'terminated') && e.rolledBack === optional));
  }
});

test('per-request timeout permits JSON fallback while total deadline and cancellation prohibit more requests', async () => {
  for (const mode of ['headers', 'body', 'total', 'cancel']) {
    const bindings = { ...named(), DNS_RULE_UP: fallbackRules(), DNS_LIMITS: { upstreamTimeoutMs: mode === 'total' || mode === 'cancel' ? 1000 : 60, maxExecutionTimeMs: mode === 'total' ? 60 : 1500 } };
    await setup(bindings, async request => {
      if (new URL(request.url).hostname !== 'primary.test') return upstreamReply(request);
      if (mode === 'body') return new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/dns-message' } });
      await new Promise(resolve => setTimeout(resolve, 200)); return new Response(null, { status: 503 });
    }, mode === 'cancel');
    const result = await dns(await post(undefined, query(), mode === 'cancel' ? { 'x-test-cancel': 'true' } : {}));
    assert.equal(result.flags & 15, mode === 'total' || mode === 'cancel' ? 2 : 0, mode);
    assert.equal(calls.length, mode === 'total' || mode === 'cancel' ? 1 : 2, mode);
    assert.ok(logs.join('').includes(mode === 'total' ? 'EXECUTION_TIMEOUT' : mode === 'cancel' ? 'REQUEST_CANCELLED' : 'UPSTREAM_TIMEOUT'));
    assert.ok(!logs.join('').includes('private-cancel-reason'));
  }
});

test('named source and shared rule compilation limits are enforced before networking', async () => {
  for (const limits of [{ maxUpstreams: 1 }, { maxConfigBytes: 100 }, { maxConditionNodes: 1 }, { maxPatternInstructions: 1 }]) {
    await setup({ ...named(), DNS_LIMITS: limits, DNS_RULE_UP: { order: 0, rules: [
      { when: { all: [{ field: 'query.name', op: 'regex', value: 'example' }, { field: 'query.type', op: 'eq', value: 'A' }] }, actions: [{ type: 'queryUpstream', upstream: 'primary' }] },
    ] } });
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(limits)); assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('RESOURCE_LIMIT'));
  }
});

test('JSON response predicates inspect the complete EDNS extended response code', async () => {
  await setup({ ...named(), DNS_RULE_UP: { order: 0, rules: [
    { actions: [{ type: 'queryUpstream', upstream: 'primary' }] },
    { when: { field: 'response.rcode', op: 'ne', value: 16 }, actions: [{ type: 'queryUpstream', upstream: 'backup' }] },
  ] } }, request => upstreamReply(request, { records: [{ name: '.', type: 41, class: 1232, ttl: 0x01000000, data: [], section: 2 }] }));
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0); assert.equal(result.records[0].type, 41);
  assert.equal(result.records[0].ttl >>> 24, 1); assert.equal(calls.length, 1);
});

test('public GET preserves legal SERVFAIL without declaring a transport failure or contacting a backup', async () => {
  await setup({ ...named(), DNS_RULE_UP: fallbackRules() }, request => upstreamReply(request, { rcode: 2, records: [] }));
  const result = await dns(await mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.from(query()).toString('base64url')));
  assert.equal(result.flags & 15, 2); assert.equal(result.id, 0x4242); assert.equal(calls.length, 1); assert.equal(logs.length, 0);
});

test('sequential JSON requests share an absolute deadline instead of restarting it', async () => {
  await setup({ ...named(), DNS_RULE_UP: { order: 0, rules: [
    ...['primary', 'backup', 'unused'].map(upstream => ({ actions: [{ type: 'queryUpstream', upstream, onError: 'continue' }] })),
  ] }, DNS_LIMITS: { upstreamTimeoutMs: 250, maxExecutionTimeMs: 400, maxNetworkRequests: 3 } }, async () => {
    await new Promise(resolve => setTimeout(resolve, 600)); return new Response(null, { status: 503 });
  });
  assert.equal((await dns(await post())).flags & 15, 2); assert.equal(calls.length, 2);
  assert.ok(logs.join('').includes('UPSTREAM_TIMEOUT') && logs.join('').includes('EXECUTION_TIMEOUT'));
});

test('removed extension limits are rejected instead of silently accepted', async () => {
  for (const limits of [{ maxExtensionCalls: 1 }, { maxExtensionTimeMs: 100 }]) {
    await setup({ DNS_LIMITS: limits, DNS_RULE_FIXED: group([fixed]) });
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length, 0);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(logs.join('').includes('INVALID_CONFIG'), logs.join(''));
  }
});

test('asynchronous basic requests and trusted caller cancellation obey the overall deadline', async () => {
  for (const cancel of [false, true]) {
    await setup({ DNS_LIMITS: { maxExecutionTimeMs: cancel ? 1000 : 30, upstreamTimeoutMs: 1000 },
      DNS_UPSTREAMS: source('https://resolver.test/private?token=private-token'),
      DNS_RULE_UP: group([{ type: 'queryUpstream', upstream: 'default' }, fixed]),
    }, async () => { await new Promise(resolve => setTimeout(resolve, 150)); throw new Error('private-upstream-reason'); }, cancel);
    assert.equal((await dns(await post(undefined, query(), cancel ? { 'x-test-cancel': 'true' } : {}))).flags & 15, 2);
    await new Promise(resolve => setTimeout(resolve, 180));
    assert.equal(calls.length, 1);
    assert.ok(logs.join('').includes(cancel ? 'REQUEST_CANCELLED' : 'EXECUTION_TIMEOUT'), logs.join(''));
    assert.ok(!/private-cancel-reason|private-upstream-reason|private-token/.test(logs.join('')));
  }
});

test('basic no-op and TTL actions preserve OPT and invalidate only actual DNS changes', async () => {
  for (const ttl of [60, 21]) {
    const records = signedRecords.filter(rr => rr.name !== 'other.example');
    await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([
      { type: 'queryUpstream', upstream: 'default' }, { type: 'setTtl', ttl }, { type: 'return' },
    ]) }, request => upstreamReply(request, { records }));
    const result = await dns(await post());
    assert.equal(result.flags & 0x20, ttl === 60 ? 0x20 : 0);
    assert.equal(result.records.filter(rr => rr.type === 46).length, ttl === 60 ? 1 : 0);
    assert.equal(result.records[0].ttl, ttl);
    assert.equal(result.records.filter(rr => rr.type === 41).length, 1);
  }
});

test('basic query rewrites invalidate AD and signatures while preserving untouched client EDNS', async () => {
  let outgoing;
  await setup({ DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_UP: group([
    { type: 'rewriteQuery', name: 'alias.example' }, { type: 'queryUpstream', upstream: 'default' }, { type: 'return' },
  ]) }, async request => {
    const wire = new Uint8Array(await request.arrayBuffer()); outgoing = decode(wire);
    return new Response(responseWire(wire, { records: signedRecords }), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  const wire = query(); wire[11] = 1;
  const input = Uint8Array.from([...wire, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
  const result = await dns(await post(undefined, input));
  assert.equal(outgoing.questions[0].name, 'alias.example');
  assert.equal(outgoing.records.find(rr => rr.type === 41).ttl, 0x8000);
  assert.equal(result.questions[0].name, 'example.com');
  assert.equal(result.flags & 0x20, 0);
  assert.equal(result.records.filter(rr => rr.type === 46).length, 0);
  assert.equal(result.records.filter(rr => rr.type === 41).length, 1);
});

test('declarative response rules observe current and original query domains after explicit requests', async () => {
  const bindings = { ...named(), DNS_RULE_UP: { order: 0, rules: [
    { actions: [fixed, { type: 'rewriteQuery', name: 'alias.example' }, { type: 'queryUpstream', upstream: 'primary' }] },
    { when: { all: [
      { field: 'query.name', op: 'eq', value: 'alias.example' },
      { field: 'original.name', op: 'eq', value: 'example.com' },
      { not: { collection: 'response.records', quantifier: 'all', where: { field: 'item.ttl', op: 'gte', value: 50 } } },
    ] }, actions: [{ type: 'queryUpstream', upstream: 'backup' }, { type: 'return' }] },
  ] } };
  await setup(bindings, request => upstreamReply(request, { records: [{ name: 'alias.example', type: 1, ttl: new URL(request.url).hostname === 'primary.test' ? 10 : 60, data: [192, 0, 2, 7] }] }));
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0); assert.equal(calls.length, 2);
  assert.deepEqual(result.records[0].data, [192, 0, 2, 7]); assert.equal(result.records[0].ttl, 60);
  assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
});

test('removed custom adoption references fail before source access, including unused sources', async () => {
  for (const condition of [{ custom: { name: 'old', params: 'private-params' } }, { any: [
    { field: 'response.exists', op: 'eq', value: true }, { custom: { name: 'old' } },
  ] }]) {
    const bindings = named(); bindings.DNS_UPSTREAMS.unused.accept = condition;
    await setup(bindings);
    assert.equal((await dns(await post())).flags & 15, 2); assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG')); assert.ok(!logs.join('').includes('private-params'));
  }
});

test('network and condition budgets remain shared across sequential JSON actions and rules', async () => {
  for (const mode of ['required', 'optional', 'steps']) {
    const bindings = { ...named(), DNS_LIMITS: mode === 'steps' ? { maxConditionSteps: 1 } : { maxNetworkRequests: 1 }, DNS_RULE_UP: { order: 0, rules: [
      { actions: [{ type: 'queryUpstream', upstream: 'primary' }] },
      { when: { field: 'response.exists', op: 'eq', value: true }, actions: [{ type: 'queryUpstream', upstream: 'backup', onError: mode === 'optional' ? 'continue' : 'fail' }] },
      { when: { field: 'response.rcode', op: 'eq', value: 0 }, actions: [{ type: 'setTtl', ttl: 7 }] },
    ] } };
    await setup(bindings);
    const result = await dns(await post());
    assert.equal(result.flags & 15, mode === 'optional' ? 0 : 2, mode);
    assert.equal(calls.length, mode === 'steps' ? 2 : 1, mode);
    assert.ok(logs.join('').includes('RESOURCE_LIMIT'), logs.join(''));
  }
});

test('basic query rewrites preserve full upstream RCODE and original client correlation', async () => {
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    const bindings = named();
    bindings.DNS_RULE_UP = group([{ type: 'rewriteQuery', name: 'alias.example' }, { type: 'queryUpstream', upstream: 'primary' }, ...end]);
    await setup(bindings, request => upstreamReply(request, { rcode: 0, records: [
      { name: '.', type: 41, class: 1232, ttl: 0x01000000, data: [], section: 2 },
    ] }));
    const wire = query(); wire[11] = 1;
    const input = Uint8Array.from([...wire, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    const result = await dns(await post(undefined, input));
    assert.equal(result.id, 0x4242); assert.equal(result.questions[0].name, 'example.com');
    assert.equal(result.flags & 0x110, 0x110); assert.equal(result.flags & 0x20, 0);
    assert.equal(result.flags & 15, 0); assert.equal(calls.length, 1);
    assert.equal(result.records[0].ttl >>> 24, 1);
  }
});

test('public module exports and execution options no longer expose user registries', async () => {
  await setup({ DNS_RULE_FIXED: group([fixed]) }, undefined, true);
  const exports = await (await post(undefined, query(), { 'x-test-exports': '1' })).json();
  assert.deepEqual(exports.sort(), ['RuleError', 'executeQuery']);
  assert.equal((await post(undefined, query(), { 'x-test-registry': '1' })).status, 500);
  assert.equal(calls.length, 0);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('INVALID_OPTIONS'), logs.join(''));
});

test('unreachable custom actions and nested conditions are rejected before JSON actions or network', async () => {
  const old = { custom: { name: 'ttlIs', params: 'private-params' } };
  const yes = { field: 'query.type', op: 'eq', value: 'A' };
  const no = { field: 'query.type', op: 'eq', value: 'AAAA' };
  const conditions = [old, { any: [yes, old] }, { all: [no, old] }, { not: old },
    { collection: 'response.records', quantifier: 'any', where: old },
    { collection: 'response.addresses', quantifier: 'all', where: old }];
  const rules = [
    { when: no, actions: [{ type: 'custom', name: 'ttl', params: 'private-params', onError: 'continue' }] },
    ...conditions.map(when => ({ when, actions: [fixed] })),
  ];
  for (const bad of rules) {
    await setup({ DNS_UPSTREAMS: source('https://unused.test/private-source'), DNS_RULE_BAD: { order: 0, rules: [
      { actions: [fixed, { type: 'return' }] }, bad,
    ] } });
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length, 0);
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    assert.ok(output.includes('INVALID_CONFIG') && output.includes('"rule":1'), output);
    assert.ok(!/private-params|private-source/.test(output));
  }
});

test('pure JSON generates, matches, rewrites and returns without user code or source access', async () => {
  const bindings = { DNS_UPSTREAMS: source('https://unused.test/'), DNS_RULE_JSON: JSON.stringify({ order: 0, rules: [
    { actions: [fixed, { type: 'rewriteQuery', name: 'changed.example' }] },
    { when: { all: [
      { field: 'query.name', op: 'eq', value: 'changed.example' },
      { field: 'original.name', op: 'eq', value: 'example.com' },
      { collection: 'response.records', quantifier: 'all', where: { all: [
        { field: 'item.name', op: 'eq', value: 'example.com' },
        { field: 'item.ttl', op: 'eq', value: 60 },
      ] } },
    ] }, actions: [{ type: 'setTtl', ttl: 23 }, { type: 'return' }] },
    { actions: [{ type: 'queryUpstream', upstream: 'default' }] },
  ] }) };
  await setup(bindings);
  for (let i = 0; i < 2; i++) {
    const result = await dns(await post());
    assert.equal(result.id, 0x4242); assert.equal(result.questions[0].name, 'example.com');
    assert.equal(result.flags & 0x110, 0x110); assert.equal(result.flags & 0x20, 0);
    assert.equal(result.records[0].ttl, 23);
    assert.deepEqual(result.records[0].data, [192, 0, 2, 1]);
  }
  assert.equal(calls.length, 0);
  assert.equal(logs.length, 0);
});

test('failed basic answer candidates roll back only themselves or terminate before later actions', async () => {
  for (const optional of [false, true]) {
    await setup({ DNS_LIMITS: { maxResponseBytes: 70 }, DNS_RULE_STATE: group([
      fixed,
      { type: 'answer', records: [fixed.records[0], { ...fixed.records[0], rdata: { A: { addr: '192.0.2.8' } } }], onError: optional ? 'continue' : 'fail' },
      { type: 'setTtl', ttl: 17 }, { type: 'return' },
    ]) });
    const result = await dns(await post());
    assert.equal(result.flags & 15, optional ? 0 : 2);
    assert.equal(result.records.length, optional ? 1 : 0);
    if (optional) { assert.equal(result.records[0].ttl, 17); assert.deepEqual(result.records[0].data, [192, 0, 2, 1]); }
    assert.equal(calls.length, 0);
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    assert.ok(output.includes('RESOURCE_LIMIT') && output.includes('"action":1'), output);
    assert.ok(output.includes(optional ? 'rolled_back_continue' : 'terminated'), output);
  }
});

test('failed basic query rewrites preserve prior current query, original question and nested EDNS', async () => {
  let outgoing;
  await setup({ DNS_LIMITS: { maxQueryBytes: 60 }, DNS_UPSTREAMS: source('https://resolver.test/dns-query'), DNS_RULE_STATE: { order: 0, rules: [
    { actions: [{ type: 'rewriteQuery', name: 'good.example' },
      { type: 'rewriteQuery', name: 'a'.repeat(50) + '.example', onError: 'continue' }] },
    { when: { all: [{ field: 'query.name', op: 'eq', value: 'good.example' }, { field: 'original.name', op: 'eq', value: 'example.com' }] },
      actions: [{ type: 'queryUpstream', upstream: 'default' }, { type: 'return' }] },
  ] } }, async request => {
    const bytes = new Uint8Array(await request.arrayBuffer()); outgoing = decode(bytes);
    return upstreamReply(new Request(request, { body: bytes }));
  });
  const base = query(); base[11] = 1;
  const input = Uint8Array.from([...base, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 6, 253, 233, 0, 2, 1, 2]);
  const before = input.slice();
  const result = await dns(await post(undefined, input));
  assert.deepEqual(input, before);
  assert.equal(outgoing.questions[0].name, 'good.example');
  assert.deepEqual(outgoing.records[0].data, [253, 233, 0, 2, 1, 2]);
  assert.equal(result.questions[0].name, 'example.com');
  assert.equal(result.id, 0x4242); assert.equal(result.flags & 0x110, 0x110);
  assert.equal(calls.length, 1);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('rolled_back_continue'));
});

test('late upstream success or rejection cannot overwrite committed answers or another request', async () => {
  for (const reject of [false, true]) {
    let attempt = 0;
    await setup({ DNS_LIMITS: { upstreamTimeoutMs: 25, maxExecutionTimeMs: 1000 },
      DNS_UPSTREAMS: source('https://resolver.test/private?token=private-token'), DNS_RULE_STATE: group([
        fixed, { type: 'queryUpstream', upstream: 'default', onError: 'continue' }, { type: 'setTtl', ttl: 17 }, { type: 'return' },
      ]),
    }, async request => {
      if (++attempt === 1) {
        const bytes = new Uint8Array(await request.arrayBuffer());
        await new Promise(resolve => setTimeout(resolve, 120));
        if (reject) throw new Error('private-late-rejection');
        return new Response(responseWire(bytes, { records: [{ name: 'example.com', type: 1, ttl: 999, data: [192, 0, 2, 99] }] }), { headers: { 'Content-Type': 'application/dns-message' } });
      }
      return upstreamReply(request);
    });
    const firstResponse = await post();
    const second = await dns(await post());
    await new Promise(resolve => setTimeout(resolve, 150));
    const first = await dns(firstResponse);
    const third = await dns(await post());
    assert.deepEqual(first.records[0].data, [192, 0, 2, 1]);
    for (const result of [second, third]) assert.deepEqual(result.records[0].data, [192, 0, 2, 9]);
    for (const result of [first, second, third]) {
      assert.equal(result.records[0].ttl, 17); assert.equal(result.questions[0].name, 'example.com');
    }
    assert.equal(calls.length, 3);
    const output = logs.join('');
    assert.ok(output.includes('UPSTREAM_TIMEOUT') && output.includes('rolled_back_continue'), output);
    assert.ok(!/private-token|private-late-rejection/.test(output));
  }
});

test('response-finalization failure does not undo source access or the previously committed answer', async () => {
  for (const optional of [false, true]) {
    await setup({ DNS_LIMITS: { maxResponseBytes: 100 }, DNS_UPSTREAMS: source('https://resolver.test/private?token=secret'), DNS_RULE_STATE: group([
      fixed, { type: 'queryUpstream', upstream: 'default', onError: optional ? 'continue' : 'fail' }, { type: 'setTtl', ttl: 14 }, { type: 'return' },
    ]) }, request => upstreamReply(request, { records: Array.from({ length: 6 }, (_, i) => ({ name: 'example.com', type: 1, ttl: 999, data: [192, 0, 2, i] })) }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, optional ? 0 : 2); assert.equal(calls.length, 1);
    if (optional) { assert.equal(result.records[0].ttl, 14); assert.deepEqual(result.records[0].data, [192, 0, 2, 1]); }
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    assert.ok(output.includes('RESOURCE_LIMIT'), output);
    assert.ok(output.includes(optional ? 'rolled_back_continue' : 'terminated'), output);
    assert.ok(!/private|token=secret/.test(output));
  }
});

test('JSON answers cannot inject protected records, invalid native fields or executable properties', async () => {
  const records = [
    ...[41, 46, 24, 250].map(type => ({ name: '.', type, ttl: 0, rdata: { Raw: [] } })),
    { ...fixed.records[0], rdata: { A: { addr: '192.0.2.1', secret: 'private-field' } } },
  ];
  const actions = [
    ...records.map(record => ({ type: 'answer', records: [record], onError: 'continue' })),
    { type: 'setTtl', ttl: 1, run: 'private-function-body' },
    { type: 'rewriteQuery', name: 'alias.example', additional: [] },
  ];
  for (const action of actions) {
    await setup({ DNS_UPSTREAMS: source('https://unused.test/dns-query'), DNS_RULE_BAD: group([fixed, action]) });
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length, 0);
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    assert.ok(output.includes('INVALID_CONFIG'), output);
    assert.ok(!/private-field|private-function-body/.test(output));
  }
});

test('declarative short circuit avoids irrelevant runtime errors but not configuration validation', async () => {
  const target = { collection: 'response.records', quantifier: 'any', where: { field: 'item.target', op: 'suffix', value: 'example' } };
  const yes = { field: 'query.type', op: 'eq', value: 'A' };
  const no = { field: 'query.type', op: 'eq', value: 'AAAA' };
  for (const [when, fails] of [[target, true], [{ not: target }, true], [{ any: [yes, target] }, false], [{ not: { all: [no, target] } }, false]]) {
    await setup({ DNS_RULE_CONDITIONS: { order: 0, rules: [
      { actions: [{ type: 'answer', records: [{ name: 'example.com', type: 'CNAME', ttl: 60, rdata: { Cname: { cname: 'private!target.example' } } }] }] },
      { when, actions: [{ type: 'setTtl', ttl: 42 }] },
    ] } });
    const result = await dns(await post());
    assert.equal(result.flags & 15, fails ? 2 : 0);
    if (!fails) assert.equal(result.records[0].ttl, 42);
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    if (fails) assert.ok(output.includes('INVALID_STATE') && output.includes('execution_failed'), output);
    assert.ok(!output.includes('private!target'));
    assert.equal(calls.length, 0);
  }
});

test('trusted diagnostic observer failures cannot hide basic action rollback or termination', async () => {
  for (const mode of ['throw', 'reject']) for (const optional of [false, true]) {
    await setup({ DNS_RULE_LOG: group([
      { type: 'setTtl', ttl: 1, onError: optional ? 'continue' : 'fail' }, fixed, { type: 'return' },
    ]) }, undefined, true);
    const result = await dns(await post(undefined, query(), { 'x-test-observer': mode }));
    assert.equal(result.flags & 15, optional ? 0 : 2);
    if (optional) assert.equal(result.records[0].ttl, 60);
    await new Promise(resolve => setTimeout(resolve, 20));
    const output = logs.join('');
    assert.ok(output.includes('observer_failed') && output.includes('action_failed') && output.includes('NO_RESPONSE'), output);
    assert.ok(output.includes(optional ? 'rolled_back_continue' : 'terminated'), output);
    assert.ok(!output.includes('private-observer'));
    assert.equal(calls.length, 0);
  }
});

test('normal completion and stop without an answer report NO_RESPONSE without implicit source access', async () => {
  for (const actions of [undefined, [{ type: 'stop' }], [{ type: 'return' }]]) {
    await setup(actions ? { DNS_RULE_A: group(actions) } : {});
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('NO_RESPONSE'));
  }
});

test('an explicit named HTTPS action makes exactly one request and accepts valid failure RCODEs', async () => {
  for (const rcode of [0, 2, 3, 5]) {
    await setup({
      DNS_UPSTREAMS: JSON.stringify({ A: { transport: 'https', urlSecret: 'SOURCE_URL' } }),
      SOURCE_URL: 'https://resolver.test/private-source?token=private-token',
      DNS_RULE_A: group([{ type: 'queryUpstream', upstream: 'A' }]),
    }, async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { rcode, records: [] }), { headers: { 'Content-Type': 'application/dns-message' } }));
    assert.equal((await dns(await post())).flags & 15, rcode);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://resolver.test/private-source?token=private-token');
    assert.equal(logs.length, 0);
  }
});

test('removed upstream policies and unreachable old references fail before any source access', async () => {
  const sources = { A: { transport: 'https', url: 'https://resolver.test/private?token=secret-token' } };
  const invalid = [
    { DNS_UPSTREAM: 'https://resolver.test' }, { DNS_UPSTREAM: '' },
    { DNS_UPSTREAM_GROUPS: {} }, { DNS_DEFAULT_UPSTREAM_GROUP: 'A' },
    { DNS_LIMITS: { maxUpstreamGroups: 1 } }, { DNS_LIMITS: { maxUpstreamMembers: 1 } },
    { DNS_UPSTREAMS: { A: { url: 'https://resolver.test' } } },
    ...['tcp', 'tls', 'HTTPS'].map(transport => ({ DNS_UPSTREAMS: { A: { transport, url: 'https://resolver.test' } } })),
    { DNS_UPSTREAMS: { ...sources, unused: { transport: 'https', url: 'http://bad.test' } } },
    { DNS_UPSTREAMS: { A: { ...sources.A, urlSecret: 'SECRET' } }, SECRET: 'https://resolver.test' },
    { DNS_UPSTREAMS: { A: { transport: 'https', urlSecret: 'MISSING' } } },
    { DNS_UPSTREAMS: { A: { ...sources.A, members: ['A'] } } },
    { DNS_UPSTREAMS: { A: { ...sources.A, accept: { field: 'response.rcode', op: 'eq', value: 0 } } } },
    ...[{ type: 'queryUpstream' }, { type: 'queryUpstream', group: 'A' }, { type: 'queryUpstream', upstream: 'missing' }].map(action => ({ DNS_RULE_BAD: { order: 1, rules: [{ when: { field: 'query.type', op: 'eq', value: 'TXT' }, actions: [action] }] } })),
  ];
  for (const bad of invalid) {
    await setup({ DNS_UPSTREAMS: sources, DNS_RULE_A: group([fixed, { type: 'return' }]), ...bad });
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(bad));
    assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG'), logs.join(''));
    assert.ok(!logs.join('').includes('secret-token'));
  }
});

test('JSON recent action results distinguish an optional failed request from a retained old answer', async () => {
  const bindings = {
    DNS_UPSTREAMS: { A: { transport: 'https', url: 'https://a.test/private' }, B: { transport: 'https', url: 'https://b.test/' } },
    DNS_RULE_A: { order: 0, rules: [
      { actions: [fixed, { type: 'queryUpstream', upstream: 'A', onError: 'continue' }] },
      { when: { all: [
        { field: 'lastAction.success', op: 'eq', value: false },
        { field: 'lastAction.actionType', op: 'eq', value: 'queryUpstream' },
        { field: 'lastAction.code', op: 'eq', value: 'UPSTREAM_FAILED' },
        { field: 'lastAction.group', op: 'eq', value: 'DNS_RULE_A' },
        { field: 'lastAction.rule', op: 'eq', value: 0 },
        { field: 'lastAction.action', op: 'eq', value: 1 },
        { field: 'response.exists', op: 'eq', value: true },
      ] }, actions: [{ type: 'queryUpstream', upstream: 'B' }] },
      { when: { all: [{ field: 'lastAction.success', op: 'eq', value: true }, { field: 'lastAction.code', op: 'exists', value: false }] }, actions: [{ type: 'setTtl', ttl: 27 }] },
    ] },
  };
  await setup(bindings, async request => {
    if (new URL(request.url).hostname === 'a.test') throw new Error('private raw connection failure');
    return new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  const result = await dns(await post());
  assert.deepEqual(result.records[0].data, [192, 0, 2, 9]);
  assert.equal(result.records[0].ttl, 27);
  assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['a.test', 'b.test']);
  assert.ok(logs.join('').includes('UPSTREAM_FAILED'));
  assert.ok(logs.join('').includes('rolled_back_continue'));
  assert.ok(!logs.join('').includes('private raw'));
});

test('lastAction starts absent on every request and successful basic actions replace older errors', async () => {
  const has = (field, value) => ({ field, op: 'eq', value });
  await setup({ DNS_RULE_RESULTS: { order: 0, rules: [
    { when: { field: 'lastAction.success', op: 'exists', value: false }, actions: [{ type: 'return', onError: 'continue' }] },
    { when: { all: [failedRequest, has('lastAction.actionType', 'return'), has('lastAction.code', 'NO_RESPONSE')] }, actions: [fixed] },
    { when: { all: [has('lastAction.success', true), has('lastAction.actionType', 'answer'), { field: 'lastAction.code', op: 'exists', value: false }] }, actions: [{ type: 'rewriteQuery', name: 'changed.example' }] },
    { when: { all: [has('lastAction.success', true), has('lastAction.actionType', 'rewriteQuery'), has('lastAction.rule', 2), has('lastAction.action', 0)] }, actions: [{ type: 'setTtl', ttl: 29 }] },
    { when: { field: 'query.type', op: 'eq', value: 'TXT' }, actions: [fixed] },
    { when: { all: [has('lastAction.success', true), has('lastAction.actionType', 'setTtl'), has('lastAction.rule', 3)] }, actions: [{ type: 'return' }] },
    { actions: [{ type: 'setTtl', ttl: 99 }] },
  ] } });
  for (let i = 0; i < 3; i++) {
    const result = await dns(await post());
    assert.equal(result.records[0].ttl, 29);
    assert.equal(result.questions[0].name, 'example.com');
  }
  assert.equal(calls.length, 0);
  assert.equal(logs.join('').split('"code":"NO_RESPONSE"').length - 1, 3);
});

test('lastAction failure survives DNS rollback and subsequent validation success clears its code', async () => {
  for (const action of [
    { type: 'answer', records: [fixed.records[0], fixed.records[0]], onError: 'continue' },
    { type: 'rewriteQuery', name: 'a'.repeat(50) + '.example', onError: 'continue' },
  ]) {
    await setup({ DNS_LIMITS: { maxResponseBytes: 70, maxQueryBytes: 60 }, DNS_RULE_RESULTS: { order: 0, rules: [
      { actions: [fixed, action] },
      { when: { all: [failedRequest, { field: 'lastAction.code', op: 'eq', value: 'RESOURCE_LIMIT' }, { field: 'lastAction.action', op: 'eq', value: 1 },
        { field: 'query.name', op: 'eq', value: 'example.com' },
        { collection: 'response.records', quantifier: 'all', where: { field: 'item.ttl', op: 'eq', value: 60 } },
      ] }, actions: [{ type: 'setTtl', ttl: 31 }] },
      { when: { all: [{ field: 'lastAction.success', op: 'eq', value: true }, { field: 'lastAction.code', op: 'exists', value: false }] }, actions: [{ type: 'return' }] },
      { actions: [{ type: 'setTtl', ttl: 99 }] },
    ] } });
    const result = await dns(await post());
    assert.equal(result.records[0].ttl, 31); assert.equal(result.records.length, 1); assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('rolled_back_continue'));
  }
});

test('invalid lastAction predicates in unreachable branches are rejected before requests', async () => {
  for (const when of [
    { field: 'lastAction.success', op: 'eq', value: 'false' },
    { field: 'lastAction.rule', op: 'eq', value: -1 },
    { field: 'lastAction.code', op: 'lt', value: 1 },
    { field: 'lastAction.message', op: 'exists', value: true },
    { field: 'lastAction.location', op: 'eq', value: 'private' },
  ]) {
    await setup({ ...named(), DNS_RULE_INVALID: { order: 0, rules: [
      { actions: [{ type: 'queryUpstream', upstream: 'primary' }, { type: 'return' }] },
      { when, actions: [fixed] },
    ] } });
    assert.equal((await dns(await post())).flags & 15, 2); assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG'));
  }
});

test('an unused DoT definition rejects HTTPS configuration before any source access', async () => {
  await setup({
    DNS_UPSTREAMS: {
      default: { transport: 'https', url: 'https://resolver.test/private?token=secret-token' },
      unused: { transport: 'tls', address: 'private.example', serverName: 'private-identity.example' },
    },
    DNS_RULE_MAIN: group([requestDefault]),
  });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 2);
  assert.equal(result.records.length, 0);
  assert.equal(calls.length, 0);
  assert.ok(logs.join('').includes('INVALID_CONFIG'));
  assert.ok(!logs.join('').includes('private-identity.example'));
  assert.ok(!logs.join('').includes('secret-token'));
});
