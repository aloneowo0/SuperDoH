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
const trustedBundle = await bundleWorker('test/domain-list-clock-worker.js');
const logs = [];
class TestLog extends Log {
  constructor() { super(LogLevel.ERROR); }
  log(message) { logs.push(message); }
}
const calls = [];
let upstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
const options = (bindings, trusted = false) => ({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/doh-bundle.js`, script: (trusted ? trustedBundle : bundle).outputFiles[0].text,
  compatibilityDate: '2026-07-30', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public'], bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
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

const lists = { selected: { domains: ['EXAMPLE.COM.'] } };
const inList = { field: 'query.name', op: 'inList', value: 'selected' };
const rules = { order: 0, rules: [
  { actions: [fixed] },
  { when: inList, actions: [{ type: 'setTtl', ttl: 7 }] },
] };
test('inline domain lists drive the public DoH pipeline without source access', async () => {
  await setup({ DNS_DOMAIN_LISTS: lists, DNS_RULE_MAIN: rules });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0, String(logs));
  assert.equal(result.records[0].ttl, 7);
  assert.equal(calls.length, 0);
});

test('maintained text and JSON sources atomically replace, invalidate on failure, and recover on configured clock boundaries', async () => {
  for (const format of ['text', 'json']) {
    let content = ['example.com'];
    let fault = false;
    await setup({ DNS_DOMAIN_LISTS: { selected: { url: `https://list.test/${format}`, format, refreshIntervalMs: 1000 } }, DNS_RULE_MAIN: rules }, () => {
      if (fault) return new Response(format === 'json' ? '["example.com",' : 'example.com\n0.0.0.0 blocked.example', { headers: { 'Content-Type': format === 'json' ? 'application/json' : 'text/plain' } });
      return new Response(format === 'json' ? JSON.stringify(content) : content.join('\r\n') + '\r\n', { headers: { 'Content-Type': format === 'json' ? 'application/json' : 'text/plain' } });
    }, true);
    const at = (time, name = 'example.com') => post(undefined, query(name), { 'x-test-time': String(time) }).then(dns);
    assert.equal((await at(10000)).records[0].ttl, 7);
    content = ['replacement.example'];
    assert.equal((await at(10999)).records[0].ttl, 7);
    assert.equal(calls.length, 1);
    assert.equal((await at(11000)).records[0].ttl, 60);
    assert.equal((await at(11001, 'replacement.example')).records[0].ttl, 7);
    assert.equal(calls.length, 2);
    fault = true;
    assert.equal((await at(12000, 'replacement.example')).flags & 15, 2, String(logs));
    assert.equal((await at(12001, 'replacement.example')).flags & 15, 2);
    assert.equal(calls.length, 3);
    assert.ok(logs.join('').includes('"source":"selected"'));
    assert.ok(logs.join('').includes('"rule":1'));
    fault = false; content = ['example.com'];
    assert.equal((await at(12999)).flags & 15, 2);
    assert.equal((await at(13000)).records[0].ttl, 7);
    assert.equal(calls.length, 4);
  }
});

test('list membership has exact and label-suffix semantics across current/original and record selectors', async () => {
  for (const [op, name, matched] of [
    ['inList','example.com',true], ['inList','a.example.com',false],
    ['inListSuffix','a.example.com',true], ['inListSuffix','notexample.com',false],
  ]) {
    await setup({ DNS_DOMAIN_LISTS: lists, DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [fixed] }, { when: { ...inList, op }, actions: [{ type: 'setTtl', ttl: 5 }] },
    ] } });
    assert.equal((await dns(await post(undefined, query(name)))).records[0].ttl, matched ? 5 : 60);
  }
  await setup({ DNS_DOMAIN_LISTS: lists, DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [fixed, { type: 'rewriteQuery', name: 'changed.example' }] },
    { when: inList, actions: [{ type: 'setTtl', ttl: 1 }] },
    { when: { ...inList, field: 'original.name' }, actions: [{ type: 'setTtl', ttl: 9, where: { ...inList, field: 'item.name' } }] },
  ] } });
  assert.equal((await dns(await post())).records[0].ttl, 9);
  assert.equal(calls.length, 0);
});

test('first-load and transport/data faults are errors, not empty-list nonmatches, and never expose source URLs', async () => {
  const faults = [
    () => new Response('', { status: 503 }),
    () => new Response('', { status: 302, headers: { Location: 'https://other.test/private' } }),
    () => { throw new Error('private-source-error'); },
    () => new Response('["example.com",false]'),
    () => new Response('["example.com", "bad domain"]'),
    () => new Response(new Uint8Array([0xff,0xff])),
  ];
  for (const handler of faults) {
    await setup({ LIST_SECRET: 'https://list.test/private-token', DNS_DOMAIN_LISTS: { selected: { urlSecret: 'LIST_SECRET', format: 'json', refreshIntervalMs: 1000 } }, DNS_RULE_MAIN: rules }, handler);
    const result = await dns(await post());
    assert.equal(result.flags & 15, 2, String(logs));
    assert.equal(calls.length, 1);
    assert.ok(/DOMAIN_LIST_(FAILED|INVALID)/.test(logs.join('')), String(logs));
    assert.ok(!/private-token|private-source-error|list\.test/.test(logs.join('')));
  }
});

test('list maintenance is bounded, shares network allowance and never starts before authorization', async () => {
  const external = { selected: { url: 'https://list.test/bounded', format: 'text', refreshIntervalMs: 1000 } };
  for (const [limits, handler, code] of [
    [{ maxDomainListBytes: 8 }, () => new Response('example.com'), 'RESOURCE_LIMIT'],
    [{ maxDomainListEntries: 1 }, () => new Response('example.com\nother.example'), 'RESOURCE_LIMIT'],
    [{ domainListTimeoutMs: 30 }, async () => { await new Promise(resolve => setTimeout(resolve, 100)); return new Response('example.com'); }, 'DOMAIN_LIST_TIMEOUT'],
  ]) {
    await setup({ DNS_LIMITS: limits, DNS_DOMAIN_LISTS: external, DNS_RULE_MAIN: rules }, handler);
    assert.equal((await dns(await post())).flags & 15, 2, String(logs));
    assert.equal(calls.length, 1);
    assert.ok(logs.join('').includes(code), String(logs));
  }
  await setup({ DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_DOMAIN_LISTS: external, DNS_UPSTREAMS: source('https://dns.test/query'), DNS_RULE_MAIN: { order: 0, rules: [
    { when: inList, actions: [requestDefault] },
  ] } }, () => new Response('example.com'));
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).hostname, 'list.test');
  await setup({ DNS_PATH_KEY: 'private', DNS_DOMAIN_LISTS: external, DNS_RULE_MAIN: rules }, () => new Response('example.com'));
  assert.equal((await post()).status, 404);
  assert.equal(calls.length, 0);
});

test('all list configuration and references are validated, even when rules cannot execute', async () => {
  const invalid = [
    { selected: { domains: ['bad domain'] } },
    { selected: { domains: ['example.com'], url: 'https://list.test' } },
    { selected: { url: 'http://list.test', format: 'text', refreshIntervalMs: 1000 } },
    { selected: { url: 'https://list.test', format: 'hosts', refreshIntervalMs: 1000 } },
    { selected: { url: 'https://list.test', format: 'text', refreshIntervalMs: 0 } },
    { selected: { url: 'https://list.test', urlSecret: 'SECRET', format: 'text', refreshIntervalMs: 1000 } },
  ];
  for (const definitions of invalid) {
    await setup({ DNS_DOMAIN_LISTS: definitions, DNS_RULE_MAIN: group([fixed, { type: 'return' }]) });
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(definitions));
    assert.equal(calls.length, 0);
  }
  await setup({ DNS_RULE_MAIN: { order: 0, rules: [{ actions: [fixed, { type: 'return' }] }, { when: inList, actions: [requestDefault] }] }, DNS_UPSTREAMS: source('https://dns.test/query') });
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 0);
});

test('concurrent refresh fails closed instead of sharing another requests pending I/O or old data', async () => {
  let block = false;
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let started;
  const ready = new Promise(resolve => { started = resolve; });
  await setup({ DNS_DOMAIN_LISTS: { selected: { url: 'https://list.test/concurrent', format: 'text', refreshIntervalMs: 1000 } }, DNS_RULE_MAIN: rules }, async () => {
    if (block) { started(); await gate; }
    return new Response('example.com');
  }, true);
  const at = time => post(undefined, query(), { 'x-test-time': String(time) }).then(dns);
  assert.equal((await at(10000)).records[0].ttl, 7);
  block = true;
  const refreshing = at(11000);
  await ready;
  try { assert.equal((await at(11001)).flags & 15, 2, String(logs)); }
  finally { release(); }
  assert.equal((await refreshing).records[0].ttl, 7);
  assert.equal((await at(11002)).records[0].ttl, 7);
  assert.equal(calls.length, 2);
});

test('configured domain-list state memory budget is enforced', async () => {
  await setup({ DNS_LIMITS: { maxDomainListStateBytes: 1 }, DNS_DOMAIN_LISTS: { selected: { url: 'https://list.test/memory', format: 'text', refreshIntervalMs: 1000 } }, DNS_RULE_MAIN: rules }, () => new Response('example.com'));
  assert.equal((await dns(await post())).flags & 15, 2, String(logs));
  assert.ok(logs.join('').includes('RESOURCE_LIMIT'));
  assert.equal(calls.length, 0);
});
