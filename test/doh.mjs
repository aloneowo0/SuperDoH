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
  format: 'esm', platform: 'browser', outfile: path.join(root, 'test/doh-bundle.js'),
  plugins: [{ name: 'wasm-external', setup(build) {
    build.onResolve({ filter: /.wasm$/ }, args => ({
      path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
    }));
  } }],
});
const bundle = await bundleWorker('src/worker.js');
const extensionsBundle = await bundleWorker('test/doh-extensions-worker.js');
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
  compatibilityDate: '2026-07-30', compatibilityFlags: ['enable_request_signal'], bindings, log: new TestLog(),
  handleRuntimeStdio(stdout, stderr) {
    for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text));
  },
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
  outboundService: async request => {
    calls.push({ url: request.url, method: request.method, headers: Object.fromEntries(request.headers) });
    return upstream(request);
  },
});
const mf = new Miniflare(options({}));
after(() => mf.dispose());
const fixed = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const group = actions => ({ order: 0, rules: [{ actions }] });
async function setup(bindings = {}, handler, extensions = false) {
  activeBundle = extensions ? extensionsBundle : bundle;
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

test('a configured default upstream supplies one validated DNS response', async () => {
  await setup({ DNS_UPSTREAM: 'https://resolver.test/private-source?token=private-token' });
  const result = await dns(await post());
  assert.deepEqual(result.records[0].data, [192, 0, 2, 9]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].headers['content-type'], 'application/dns-message');
});

test('optional Secret protects only the exact key path before invalid rules or upstream work', async () => {
  await setup({ DNS_PATH_KEY: 'private-key', DNS_RULE_BAD: '{broken', DNS_UPSTREAM: 'not a URL', DNS_LIMITS: { bad: 1 } });
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
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query' });
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
  for (const bindings of [{}, { DNS_RULE_BAD: '{invalid' }, { DNS_LIMITS: { unknown: 1 } }, { DNS_UPSTREAM: 'http://private.test/secret' },
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
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_FLOW: { order: 0, rules: [
    { actions: [fixed, { type: 'rewriteQuery', name: 'alias.example', queryType: 'AAAA' }, { type: 'queryUpstream' }] },
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
    await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([{ type: 'queryUpstream' }]) }, async request =>
      new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { rcode, records: [] }), { headers: { 'Content-Type': 'application/dns-message' } }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, rcode);
    assert.equal(result.records.length, 0);
    assert.equal(calls.length, 1);
  }
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_STOP: group([{ type: 'stop' }]) });
  await dns(await post());
  assert.equal(calls.length, 1);
});

test('optional upstream failures roll back the action, required failures return SERVFAIL with redacted events', async () => {
  for (const optional of [false, true]) {
    await setup({ DNS_PATH_KEY: 'private-key', DNS_UPSTREAM: 'https://resolver.test/private-source?token=private-token',
      DNS_RULE_UP: group([fixed, { type: 'queryUpstream', onError: optional ? 'continue' : 'fail' }, { type: 'setTtl', ttl: 19 }]),
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
  for (const mode of ['http', 'redirect', 'media', 'wire', 'id', 'question', 'query', 'servfail', 'refused', 'edns']) {
    await setup({ DNS_UPSTREAM: 'https://resolver.test/private-path' }, async request => {
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

test('network attempts are bounded across explicit actions, optional failures and default fallback', async () => {
  await setup({ DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([
    { type: 'queryUpstream' }, { type: 'queryUpstream', onError: 'continue' }, { type: 'setTtl', ttl: 18 },
  ]) });
  const first = await dns(await post());
  assert.equal(first.records[0].ttl, 18);
  assert.equal(calls.length, 1);
  let attempts = 0;
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([{ type: 'queryUpstream', onError: 'continue' }]) }, async request => {
    if (++attempts === 1) return new Response(null, { status: 503 });
    return new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
  });
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.equal(calls.length, 2);
  await setup({ DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([{ type: 'queryUpstream', onError: 'continue' }]) },
    async () => new Response(null, { status: 503 }));
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 1);
});

test('HTTP input and streaming upstream bodies reject excess bytes without waiting for EOF', async () => {
  await setup({ DNS_LIMITS: { maxQueryBytes: 32 }, DNS_RULE_FIXED: group([fixed]) });
  assert.equal((await post(undefined, new Uint8Array(33))).status, 413);
  assert.equal((await mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.alloc(33).toString('base64url'))).status, 414);
  await setup({ DNS_LIMITS: { maxResponseBytes: 64 }, DNS_UPSTREAM: 'https://resolver.test/dns-query' }, async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(128)); },
  }), { headers: { 'Content-Type': 'application/dns-message' } }));
  assert.equal((await dns(await post())).flags & 15, 2);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('RESOURCE_LIMIT'), logs.join(''));
});

test('upstream header and body waits are bounded by per-call timeout and the shared execution deadline', async () => {
  for (const mode of ['headers', 'body', 'total']) {
    await setup({ DNS_LIMITS: { upstreamTimeoutMs: mode === 'total' ? 500 : 30, maxExecutionTimeMs: mode === 'total' ? 30 : 1000 },
      DNS_UPSTREAM: 'https://resolver.test/dns-query',
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
  await setup({ DNS_LIMITS: { upstreamTimeoutMs: 25, maxExecutionTimeMs: 1000 }, DNS_UPSTREAM: 'https://resolver.test/dns-query',
    DNS_RULE_UP: group([fixed, { type: 'queryUpstream', onError: 'continue' }, { type: 'setTtl', ttl: 11 }]),
  }, async () => { await new Promise(resolve => setTimeout(resolve, 100)); return new Response(null, { status: 503 }); });
  const result = await dns(await post());
  assert.equal(result.records[0].ttl, 11);
  assert.equal(calls.length, 1);
});

test('code-composed asynchronous extensions and caller cancellation obey the overall request deadline', async () => {
  await setup({ DNS_LIMITS: { maxExecutionTimeMs: 30, maxExtensionTimeMs: 1000 }, DNS_RULE_PAUSE: group([
    { type: 'custom', name: 'pause', params: 100 }, fixed,
  ]) }, undefined, true);
  assert.equal((await dns(await post())).flags & 15, 2);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('EXECUTION_TIMEOUT'), logs.join(''));
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query' }, async () => {
    await new Promise(resolve => setTimeout(resolve, 200)); return new Response(null, { status: 503 });
  }, true);
  assert.equal((await dns(await post(undefined, query(), { 'x-test-cancel': 'true' }))).flags & 15, 2);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('REQUEST_CANCELLED'), logs.join(''));
  assert.ok(!logs.join('').includes('private-cancel-reason'));
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
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query' }, signedUpstream);
  const untouched = await dns(await post());
  assert.equal(untouched.flags & 0x20, 0x20);
  assert.equal(untouched.records.filter(rr => rr.type === 46).length, 2);
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([
      { type: 'queryUpstream' }, { type: 'setTtl', ttl: 12 }, ...end,
    ]) }, signedUpstream);
    const edited = await dns(await post());
    assert.equal(edited.flags & 0x20, 0);
    assert.deepEqual(edited.records.filter(rr => rr.type === 46).map(rr => rr.name), ['other.example']);
    assert.equal(edited.records.find(rr => rr.type === 41).ttl, 0);
    assert.equal(calls.length, 1);
  }
});

test('custom actions inherit upstream signatures and OPT safely but cannot inject protected records', async () => {
  for (const action of [
    { type: 'custom', name: 'noop' },
    { type: 'custom', name: 'ttl', params: 21 },
    { type: 'custom', name: 'inject', onError: 'continue' },
  ]) {
    await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([{ type: 'queryUpstream' }, action]) }, signedUpstream, true);
    const result = await dns(await post());
    if (action.name === 'ttl') {
      assert.equal(result.flags & 0x20, 0);
      assert.equal(result.records.filter(rr => rr.type === 46).length, 0);
      assert.equal(result.records[0].ttl, 21);
    } else {
      assert.equal(result.flags & 0x20, 0x20);
      assert.equal(result.records.filter(rr => rr.type === 46).length, 2);
      assert.equal(result.records[0].ttl, 60);
    }
    assert.equal(result.records.filter(rr => rr.type === 41).length, 1);
  }
});

test('request-body waiting is bounded before DNS parsing and does not contact upstreams', async () => {
  await setup({ DNS_LIMITS: { maxExecutionTimeMs: 30 }, DNS_UPSTREAM: 'https://resolver.test/dns-query' });
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

test('extension changes to outgoing EDNS cannot preserve AD, signatures or changed-query OPT metadata', async () => {
  let outgoing;
  await setup({ DNS_UPSTREAM: 'https://resolver.test/dns-query', DNS_RULE_UP: group([
    { type: 'custom', name: 'edns' }, { type: 'queryUpstream' },
  ]) }, async request => {
    const wire = new Uint8Array(await request.arrayBuffer()); outgoing = decode(wire);
    return new Response(responseWire(wire, { records: signedRecords }), { headers: { 'Content-Type': 'application/dns-message' } });
  }, true);
  const result = await dns(await post());
  assert.equal(outgoing.records.find(rr => rr.type === 41).ttl, 0x8000);
  assert.equal(result.flags & 0x20, 0);
  assert.equal(result.records.filter(rr => rr.type === 46).length, 0);
  assert.equal(result.records.filter(rr => rr.type === 41).length, 0);
});

const named = (accept) => ({
  DNS_UPSTREAMS: { primary: { url: 'https://primary.test/private?token=secret' }, backup: { urlSecret: 'BACKUP_URL' }, unused: { url: 'https://unused.test/dns-query' } },
  BACKUP_URL: 'https://backup.test/private-backup?token=backup-secret',
  DNS_UPSTREAM_GROUPS: { standard: { members: ['primary', 'backup', 'unused'], ...(accept === undefined ? {} : { accept }) } },
  DNS_DEFAULT_UPSTREAM_GROUP: 'standard',
});
const upstreamReply = async (request, options) => new Response(responseWire(new Uint8Array(await request.arrayBuffer()), options), { headers: { 'Content-Type': 'application/dns-message' } });

test('named upstream groups fall back in order and preserve failed-member diagnostics after success', async () => {
  await setup(named(), request => new URL(request.url).hostname === 'primary.test' ? new Response('private-error', { status: 503 }) : upstreamReply(request));
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['primary.test', 'backup.test']);
  await new Promise(resolve => setTimeout(resolve, 20));
  const output = logs.join('');
  assert.ok(output.includes('upstream_failed') && output.includes('fallback'), output);
  for (const secret of ['private?', 'token=', 'backup-secret', 'private-error', 'private-backup']) assert.ok(!output.includes(secret), output);
});

test('named group adoption defaults accept empty NOERROR and NXDOMAIN without extra requests', async () => {
  for (const rcode of [0, 3]) {
    await setup(named(), request => upstreamReply(request, { rcode, records: [] }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, rcode); assert.equal(result.records.length, 0); assert.equal(calls.length, 1);
  }
});

test('declarative adoption examines the candidate and may require target records', async () => {
  await setup(named({ collection: 'response.records', quantifier: 'any', where: { all: [
    { field: 'item.section', op: 'eq', value: 'answer' }, { field: 'item.type', op: 'eq', value: 'A' },
  ] } }), request => upstreamReply(request, new URL(request.url).hostname === 'primary.test' ? { records: [] } : undefined));
  assert.equal((await dns(await post())).records.length, 1); assert.equal(calls.length, 2);
});

test('group references and unused definitions are fully validated before actions or network access', async () => {
  const bad = [
    { DNS_UPSTREAMS: '{bad' },
    { DNS_UPSTREAMS: { invalid: { url: 'http://private.test' } } },
    { DNS_UPSTREAMS: { invalid: { urlSecret: 'MISSING' } } },
    { DNS_UPSTREAMS: { invalid: { urlSecret: 'ABSENT_VALUE' } }, ABSENT_VALUE: null },
    { DNS_UPSTREAMS: { invalid: { url: 'https://test/', urlSecret: 'BACKUP_URL' } } },
    { DNS_UPSTREAM_GROUPS: { unused: { members: ['missing'] } } },
    { DNS_UPSTREAM_GROUPS: { unused: { members: [] } } },
    { DNS_UPSTREAM_GROUPS: { unused: { members: ['primary'], strategy: 'race' } } },
    { DNS_UPSTREAM_GROUPS: { unused: { members: ['primary'], accept: { custom: { name: 'missing' } } } } },
    { DNS_DEFAULT_UPSTREAM_GROUP: 'missing' },
    { DNS_UPSTREAM: 'https://old.test/dns-query' },
    { DNS_RULE_BADREF: { order: 99, rules: [{ when: { field: 'query.type', op: 'eq', value: 'AAAA' }, actions: [{ type: 'queryUpstream', group: 'missing' }] }] } },
    { DNS_RULE_BADREF: group([{ type: 'return' }, { type: 'queryUpstream', group: 'toString' }]) },
  ];
  for (const patch of bad) {
    await setup({ ...named(), DNS_RULE_FIXED: group([fixed, { type: 'return' }]), ...patch });
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(patch));
    assert.equal(calls.length, 0);
  }
});

test('named groups support single members, explicit reuse, JSON text and explicit-only configurations', async () => {
  const bindings = named(); delete bindings.DNS_DEFAULT_UPSTREAM_GROUP;
  bindings.DNS_UPSTREAMS = JSON.stringify(bindings.DNS_UPSTREAMS);
  bindings.DNS_UPSTREAM_GROUPS = JSON.stringify({ one: { members: ['backup'] } });
  bindings.DNS_RULE_REUSE = { order: 0, rules: [
    { actions: [{ type: 'queryUpstream', group: 'one' }] },
    { when: { field: 'response.exists', op: 'eq', value: true }, actions: [{ type: 'queryUpstream', group: 'one' }, { type: 'return' }] },
  ] };
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 0);
  assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['backup.test', 'backup.test']);
  delete bindings.DNS_RULE_REUSE;
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 2); assert.equal(calls.length, 0);
});

test('default group is used after stop and explicit group selection does not change the default', async () => {
  const bindings = { ...named(), DNS_RULE_UP: group([{ type: 'queryUpstream', group: 'single' }, { type: 'stop' }]) };
  bindings.DNS_UPSTREAM_GROUPS.single = { members: ['backup'] };
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 0); assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).hostname, 'backup.test');
  bindings.DNS_RULE_UP = group([{ type: 'stop' }]);
  await setup(bindings);
  await dns(await post()); assert.equal(new URL(calls[0].url).hostname, 'primary.test');
});

test('failed HTTP, transport, DNS, correspondence and default RCODE adoption all fall back', async () => {
  for (const mode of ['http', 'redirect', 'network', 'media', 'wire', 'id', 'question', 'edns', 'servfail', 'refused']) {
    await setup(named(), async request => {
      if (new URL(request.url).hostname !== 'primary.test') return upstreamReply(request);
      if (mode === 'http') return new Response(null, { status: 503 });
      if (mode === 'redirect') return new Response(null, { status: 302, headers: { Location: 'https://unused.test/' } });
      if (mode === 'network') throw new Error('private-transport-error');
      if (mode === 'media') return new Response('not DNS');
      const wire = new Uint8Array(await request.arrayBuffer());
      let bytes = responseWire(wire);
      if (mode === 'wire') bytes = Uint8Array.of(1);
      if (mode === 'id') bytes[0] ^= 1;
      if (mode === 'question') bytes[13] ^= 1;
      if (mode === 'edns') bytes = responseWire(wire, { records: [{ name: '.', type: 41, class: 1232, ttl: 0x10000, data: [], section: 2 }] });
      if (mode === 'servfail' || mode === 'refused') bytes = responseWire(wire, { rcode: mode === 'servfail' ? 2 : 5 });
      return new Response(bytes, { headers: { 'Content-Type': 'application/dns-message' } });
    });
    assert.equal((await dns(await post())).flags & 15, 0, mode);
    assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['primary.test', 'backup.test'], mode);
  }
});

test('explicit adoption overrides default RCODE policy but never protocol validity', async () => {
  for (const mode of ['valid', 'wrong-id']) {
    await setup(named({ any: [{ field: 'response.rcode', op: 'eq', value: 5 }, { not: { field: 'response.rcode', op: 'eq', value: 2 } }] }), async request => {
      const bytes = responseWire(new Uint8Array(await request.arrayBuffer()), { rcode: 5, records: [] });
      if (mode === 'wrong-id' && new URL(request.url).hostname === 'primary.test') bytes[0] ^= 1;
      return new Response(bytes, { headers: { 'Content-Type': 'application/dns-message' } });
    });
    assert.equal((await dns(await post())).flags & 15, 5);
    assert.equal(calls.length, mode === 'valid' ? 1 : 2);
  }
});

test('exhausted groups retain each reason and respect required or optional action rollback', async () => {
  for (const optional of [false, true]) {
    const bindings = named(); delete bindings.DNS_DEFAULT_UPSTREAM_GROUP;
    bindings.DNS_UPSTREAM_GROUPS.standard.members = ['primary', 'backup'];
    bindings.DNS_RULE_UP = group([fixed, { type: 'queryUpstream', group: 'standard', onError: optional ? 'continue' : 'fail' }, { type: 'setTtl', ttl: 17 }]);
    await setup(bindings, request => upstreamReply(request, { rcode: 2, records: [] }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, optional ? 0 : 2);
    if (optional) { assert.equal(result.records[0].ttl, 17); assert.deepEqual(result.records[0].data, [192, 0, 2, 1]); }
    assert.equal(calls.length, 2);
    await new Promise(resolve => setTimeout(resolve, 20));
    const events = logs.join('').split('\n').flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
    const failures = events.filter(e => e.event === 'upstream_failed');
    assert.equal(failures.length, 2, logs.join(''));
    assert.deepEqual(failures.map(e => e.upstream.memberIndex), [0, 1]);
    assert.deepEqual(failures.map(e => e.disposition), ['fallback', 'exhausted']);
    assert.ok(failures.every(e => e.location.group === 'DNS_RULE_UP' && e.location.rule === 0 && e.location.action === 1 && e.rolledBack === false));
    assert.ok(events.some(e => e.code === 'UPSTREAM_EXHAUSTED' && e.disposition === (optional ? 'rolled_back_continue' : 'terminated')));
  }
});

test('registered adoption conditions receive isolated candidate, current and original queries', async () => {
  const bindings = named({ custom: { name: 'candidate', params: 50 } });
  bindings.DNS_RULE_UP = group([fixed, { type: 'rewriteQuery', name: 'alias.example' }, { type: 'queryUpstream' }, { type: 'return' }]);
  await setup(bindings, request => upstreamReply(request, { records: [{ name: 'alias.example', type: 1, ttl: new URL(request.url).hostname === 'primary.test' ? 10 : 60, data: [192, 0, 2, 7] }] }), true);
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0); assert.equal(calls.length, 2);
  assert.deepEqual(result.records[0].data, [192, 0, 2, 7]); assert.equal(result.records[0].ttl, 60);
  assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
});

test('adoption extension errors are not false matches and parameter errors precede network access', async () => {
  for (const condition of [{ name: 'explode' }, { name: 'nonBoolean' }, { name: 'candidate', params: 'bad' }]) {
    await setup(named({ custom: condition }), undefined, true);
    assert.equal((await dns(await post())).flags & 15, 2);
    assert.equal(calls.length, condition.params === 'bad' ? 0 : 1);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(logs.join('').includes(condition.params === 'bad' ? 'INVALID_EXTENSION_PARAMS' : 'INVALID_STATE'));
    assert.ok(!logs.join('').includes('private-adoption-exception'));
    assert.ok(!logs.join('').includes('private-invalid-result'));
  }
});

test('member timeout falls back while total deadline and caller cancellation terminate without more queries', async () => {
  for (const mode of ['headers', 'body', 'total', 'cancel']) {
    const bindings = { ...named(), DNS_LIMITS: { upstreamTimeoutMs: mode === 'total' || mode === 'cancel' ? 1000 : 60, maxExecutionTimeMs: mode === 'total' ? 60 : 1500 } };
    await setup(bindings, async request => {
      if (new URL(request.url).hostname !== 'primary.test') return upstreamReply(request);
      if (mode === 'body') return new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/dns-message' } });
      await new Promise(resolve => setTimeout(resolve, 200));
      return new Response(null, { status: 503 });
    }, mode === 'cancel');
    const result = await dns(await post(undefined, query(), mode === 'cancel' ? { 'x-test-cancel': 'true' } : {}));
    assert.equal(result.flags & 15, mode === 'total' || mode === 'cancel' ? 2 : 0, mode);
    assert.equal(calls.length, mode === 'total' || mode === 'cancel' ? 1 : 2, mode);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(logs.join('').includes(mode === 'total' ? 'EXECUTION_TIMEOUT' : mode === 'cancel' ? 'REQUEST_CANCELLED' : 'UPSTREAM_TIMEOUT'), logs.join(''));
    assert.ok(!logs.join('').includes('private-cancel-reason'));
  }
});

test('network and extension budgets are shared across members, actions and default queries', async () => {
  for (const mode of ['network', 'actions', 'default', 'extension', 'extensionTime', 'steps']) {
    const bindings = named(mode === 'extension' ? { custom: { name: 'slow', params: 0 } } : mode === 'extensionTime' ? { custom: { name: 'slow', params: 200 } } : { field: 'response.rcode', op: 'eq', value: 3 });
    bindings.DNS_LIMITS = mode === 'extension' ? { maxExtensionCalls: 1 } : mode === 'extensionTime' ? { maxExtensionTimeMs: 50 } : mode === 'steps' ? { maxConditionSteps: 1 } : { maxNetworkRequests: 1 };
    if (mode === 'actions') bindings.DNS_RULE_UP = group([fixed, { type: 'queryUpstream', onError: 'continue' }, { type: 'queryUpstream', onError: 'continue' }]);
    if (mode === 'default') bindings.DNS_RULE_UP = group([{ type: 'queryUpstream', onError: 'continue' }]);
    await setup(bindings, undefined, true);
    const result = await dns(await post());
    assert.equal(result.flags & 15, mode === 'actions' ? 0 : 2, mode);
    assert.equal(calls.length, ['extension', 'steps'].includes(mode) ? 2 : 1, mode);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(logs.join('').includes(mode === 'extensionTime' ? 'EXTENSION_TIMEOUT' : 'RESOURCE_LIMIT'), logs.join(''));
  }
});

test('named source, group, member and shared configuration compilation limits are enforced before networking', async () => {
  for (const limits of [
    { maxUpstreams: 1 }, { maxUpstreamGroups: 1 }, { maxUpstreamMembers: 2 },
    { maxConfigBytes: 100 }, { maxConditionNodes: 1 }, { maxPatternInstructions: 1 },
  ]) {
    const bindings = named({ field: 'query.name', op: 'regex', value: 'example' });
    bindings.DNS_UPSTREAM_GROUPS.other = { members: ['primary'], accept: { field: 'query.type', op: 'eq', value: 'A' } };
    bindings.DNS_LIMITS = limits;
    await setup(bindings);
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(limits)); assert.equal(calls.length, 0);
  }
  const bindings = named({ field: 'query.type', op: 'eq', value: 'A' });
  bindings.DNS_LIMITS = { maxConditionNodes: 1 };
  bindings.DNS_RULE_CONDITION = { order: 0, rules: [{ when: { field: 'query.name', op: 'suffix', value: 'example.com' }, actions: [fixed] }] };
  await setup(bindings);
  assert.equal((await dns(await post())).flags & 15, 2); assert.equal(calls.length, 0);
});

test('adoption RCODE predicates inspect the complete EDNS extended response code', async () => {
  await setup(named({ field: 'response.rcode', op: 'eq', value: 16 }), request => upstreamReply(request, {
    rcode: 0, records: [{ name: '.', type: 41, class: 1232, ttl: 0x01000000, data: [], section: 2 }],
  }));
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0); assert.equal(result.records[0].type, 41);
  assert.equal(result.records[0].ttl >>> 24, 1); assert.equal(calls.length, 1);
});

test('public GET with a default group reports final exhaustion as correlated SERVFAIL', async () => {
  const bindings = named(); bindings.DNS_UPSTREAM_GROUPS.standard.members = ['primary', 'backup'];
  await setup(bindings, request => upstreamReply(request, { rcode: 2, records: [] }));
  const result = await dns(await mf.dispatchFetch('https://doh.test/dns-query?dns=' + Buffer.from(query()).toString('base64url')));
  assert.equal(result.flags & 15, 2); assert.equal(result.id, 0x4242); assert.equal(calls.length, 2);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(logs.join('').includes('UPSTREAM_EXHAUSTED'), logs.join(''));
});

test('sequential member waits share an absolute deadline instead of restarting it', async () => {
  await setup({ ...named(), DNS_LIMITS: { upstreamTimeoutMs: 250, maxExecutionTimeMs: 400, maxNetworkRequests: 3 } }, async () => {
    await new Promise(resolve => setTimeout(resolve, 600));
    return new Response(null, { status: 503 });
  });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 2); assert.equal(calls.length, 2);
  await new Promise(resolve => setTimeout(resolve, 20));
  const output = logs.join('');
  assert.ok(output.includes('UPSTREAM_TIMEOUT') && output.includes('EXECUTION_TIMEOUT'), output);
});

test('rewritten EDNS never loses an adopted extended RCODE during client finalization', async () => {
  for (const clientEdns of [false, true]) for (const explicit of [false, true]) {
    const bindings = named({ field: 'response.rcode', op: 'eq', value: 16 });
    bindings.DNS_RULE_UP = group([{ type: 'custom', name: 'edns' }, ...(explicit ? [{ type: 'queryUpstream' }] : [])]);
    await setup(bindings, request => upstreamReply(request, { rcode: 0, flags: 0x81b0, records: [
      { name: '.', type: 41, class: 4096, ttl: 0x01008000, data: [0, 12, 0, 1, 0], section: 2 },
    ] }), true);
    const wire = query();
    let input = wire;
    if (clientEdns) {
      wire[11] = 1;
      input = Uint8Array.from([...wire, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    }
    const result = await dns(await post(undefined, input));
    assert.equal(result.flags & 15, clientEdns ? 0 : 2);
    assert.equal(result.flags & 0x20, 0); assert.equal(calls.length, 1);
    if (clientEdns) {
      assert.equal(result.records.length, 1); assert.equal(result.records[0].type, 41);
      assert.equal(result.records[0].ttl, 0x01000000); assert.deepEqual(result.records[0].data, []);
    } else assert.equal(result.records.length, 0);
  }
});
