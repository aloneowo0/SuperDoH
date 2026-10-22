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

const geo = (extra = {}) => ({ geo: { url: 'https://geo.test/lookup', ipParam: 'ip', fields: { ip: ['ip'], asn: ['asn'], country: ['country'], region: ['region'], city: ['city'] }, ...extra } });
const enrich = { type: 'enrichAddresses', source: 'geo' };
const addressMatch = where => ({ collection: 'response.addresses', quantifier: 'any', where });
const asnCountry = { all: [{ field: 'item.asn', op: 'eq', value: 64512 }, { field: 'item.country', op: 'eq', value: 'DE' }] };
const json = (value, init) => Response.json(value, init);
const geoHandler = request => new URL(request.url).hostname === 'geo.test'
  ? json({ ip: new URL(request.url).searchParams.get('ip'), asn: 64512, country: 'DE' })
  : request.arrayBuffer().then(wire => new Response(responseWire(new Uint8Array(wire)), { headers: { 'Content-Type': 'application/dns-message' } }));

test('explicit attribution from JSON source drives later same-address matching through DoH', async () => {
  await setup({ DNS_UPSTREAMS: source('https://dns.test/query'), DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [requestDefault, enrich] },
    { when: addressMatch(asnCountry), actions: [{ type: 'setTtl', ttl: 7 }] },
  ] } }, geoHandler);
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0, String(logs));
  assert.equal(result.records[0].ttl, 7);
  assert.deepEqual(calls.map(call => new URL(call.url).hostname), ['dns.test', 'geo.test']);
  assert.equal(new URL(calls[1].url).searchParams.get('ip'), '192.0.2.9');
});

test('attribution conditions and denied or unselected actions do not perform lookups', async () => {
  for (const rules of [
    [{ actions: [fixed] }, { when: addressMatch(asnCountry), actions: [{ type: 'setTtl', ttl: 1 }] }],
    [{ actions: [fixed] }, { when: { field: 'query.type', op: 'eq', value: 'AAAA' }, actions: [enrich] }],
  ]) {
    await setup({ DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: { order: 0, rules } }, geoHandler);
    const result = await dns(await post());
    assert.equal(result.flags & 15, 0, String(logs));
    assert.equal(result.records[0].ttl, 60);
    assert.equal(calls.length, 0);
  }
  await setup({ DNS_PATH_KEY: 'private-key', DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: group([fixed, enrich]) }, geoHandler);
  assert.equal((await post()).status, 404);
  assert.equal(calls.length, 0);
});

test('canonical IPv4/IPv6 dedup spans sections and joint predicates never mix addresses', async () => {
  const v6 = [0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1];
  const records = [
    { name: 'example.com', type: 1, ttl: 60, data: [192,0,2,9] },
    { name: 'example.com', type: 28, ttl: 60, data: v6 },
    { name: 'extra.example', type: 28, ttl: 60, data: v6, section: 2 },
  ];
  await setup({ DNS_LIMITS: { maxNetworkRequests: 3 }, DNS_UPSTREAMS: source('https://dns.test/multi'), DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [requestDefault, enrich] },
    { when: addressMatch(asnCountry), actions: [{ type: 'setTtl', ttl: 1 }] },
    { when: addressMatch({ all: [{ field: 'item.ip', op: 'eq', value: '2001:DB8:0:0:0:0:0:1' }, { field: 'item.country', op: 'eq', value: 'DE' }] }), actions: [{ type: 'setTtl', ttl: 8, where: { field: 'item.type', op: 'eq', value: 'AAAA' } }] },
  ] } }, async request => {
    const url = new URL(request.url);
    if (url.hostname !== 'geo.test') return new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records }), { headers: { 'Content-Type': 'application/dns-message' } });
    const address = url.searchParams.get('ip');
    return json(address.includes(':') ? { ip: '2001:DB8:0:0:0:0:0:1', country: 'DE', asn: 64513 } : { ip: address, country: 'US', asn: 64512 });
  });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0, String(logs));
  assert.deepEqual(result.records.map(rr => rr.ttl), [60, 8, 8]);
  assert.equal(calls.filter(call => new URL(call.url).hostname === 'geo.test').length, 2);
});

test('partial optional enrichment rolls back attributes and leaves failure visible with prior DNS state', async () => {
  const two = { type: 'answer', records: [fixed.records[0], { ...fixed.records[0], rdata: { A: { addr: '192.0.2.2' } } }] };
  for (const previous of [false, true]) {
    const initial = geo().geo;
    await setup({ DNS_LIMITS: { maxNetworkRequests: 4 }, DNS_ADDRESS_SOURCES: { geo: initial, prior: { ...initial, url: 'https://geo.test/prior' } }, DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [two, ...(previous ? [{ ...enrich, source: 'prior' }] : []), { ...enrich, onError: 'continue' }] },
      { when: { all: [{ field: 'lastAction.success', op: 'eq', value: false }, { field: 'lastAction.actionType', op: 'eq', value: 'enrichAddresses' }, { field: 'lastAction.code', op: 'eq', value: 'ATTRIBUTION_FAILED' }] }, actions: [{ type: 'setTtl', ttl: 15 }] },
      { when: addressMatch(asnCountry), actions: [{ type: 'setTtl', ttl: 1 }] },
      ...(previous ? [{ when: addressMatch({ field: 'item.country', op: 'eq', value: 'US' }), actions: [{ type: 'setTtl', ttl: 9 }] }] : []),
    ] } }, request => {
      const url = new URL(request.url), address = url.searchParams.get('ip');
      if (url.pathname === '/prior') return json({ ip: address, country: 'US', asn: 64513 });
      if (address === '192.0.2.2') throw new Error('private-origin-secret');
      return json({ ip: address, country: 'DE', asn: 64512 });
    });
    const result = await dns(await post());
    assert.equal(result.flags & 15, 0, String(logs));
    assert.deepEqual(result.records.map(rr => rr.ttl), previous ? [9,9] : [15,15]);
    assert.ok(logs.join('').includes('rolled_back_continue'));
    assert.ok(logs.join('').includes('"source":"geo"'));
    assert.ok(!logs.join('').includes('private-origin-secret'));
    assert.equal(calls.length, previous ? 4 : 2);
  }
});

test('cached attribution is reused but origin Age cannot renew an expired entry', async () => {
  for (const age of ['0', '60']) {
    let lookups = 0;
    await setup({ DNS_ADDRESS_SOURCES: geo({ url: `https://geo.test/cache-age-${age}`, cacheTtl: 30 }), DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [fixed, enrich] }, { when: addressMatch(asnCountry), actions: [{ type: 'setTtl', ttl: 6 }] },
    ] } }, request => {
      lookups++;
      return json({ ip: new URL(request.url).searchParams.get('ip'), asn: 64512, country: 'DE' }, { headers: { Age: age } });
    });
    assert.equal((await dns(await post())).records[0].ttl, 6, String(logs));
    assert.equal((await dns(await post())).records[0].ttl, 6, String(logs));
    assert.equal(lookups, age === '0' ? 1 : 2, `Age=${age}`);
  }
});

test('source failures are required by default and protocol/mapping errors never become missing attributes', async () => {
  const faults = [
    ['ATTRIBUTION_FAILED', () => new Response('', { status: 503 })],
    ['ATTRIBUTION_FAILED', () => new Response('', { status: 302, headers: { Location: 'https://private.test/secret' } })],
    ['ATTRIBUTION_FAILED', () => { throw new Error('private-failure-secret'); }],
    ['ATTRIBUTION_INVALID', () => new Response('{"ip":"192.0.2.1"}', { headers: { 'Content-Type': 'text/plain' } })],
    ['ATTRIBUTION_INVALID', () => new Response('{bad-json', { headers: { 'Content-Type': 'application/json' } })],
    ['ATTRIBUTION_INVALID', () => json({ ip: '192.0.2.2', asn: 64512 })],
    ['ATTRIBUTION_INVALID', () => json({ ip: '192.0.2.1', asn: '64512' })],
    ['ATTRIBUTION_INVALID', () => json({ ip: '192.0.2.1', country: null })],
    ['ATTRIBUTION_INVALID', () => json({ ip: '192.0.2.1', country: 'DE' + String.fromCharCode(0) })],
  ];
  for (const [code, handler] of faults) {
    await setup({ GEO_URL: 'https://geo.test/private-secret?token=private-param', DNS_ADDRESS_SOURCES: JSON.stringify({ geo: { ...geo().geo, url: undefined, urlSecret: 'GEO_URL' } }), DNS_RULE_MAIN: group([fixed, enrich]) }, handler);
    assert.equal((await dns(await post())).flags & 15, 2, String(logs));
    assert.equal(calls.length, 1);
    const events = logs.join('');
    assert.ok(events.includes(code), events);
    assert.ok(events.includes('"source":"geo"'), events);
    assert.ok(!/private-secret|private-param|private-failure|geo\.test/.test(events), events);
  }
});

test('nested own-field mappings use configured query params and missing values replace old attributes', async () => {
  const definition = { ...geo().geo, params: { format: 'json' }, fields: { ip: ['query', 'address'], asn: ['network', 'asn'], country: ['location', 'country'], city: ['location', 'city'] } };
  await setup({ DNS_ADDRESS_SOURCES: geo(definition), DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [fixed, enrich, enrich] },
    { when: addressMatch({ all: [{ field: 'item.asn', op: 'eq', value: 64512 }, { field: 'item.country', op: 'exists', value: false }, { field: 'item.city', op: 'exists', value: false }] }), actions: [{ type: 'setTtl', ttl: 13 }] },
  ] } }, request => {
    const url = new URL(request.url);
    assert.equal(url.searchParams.get('format'), 'json');
    return json({ query: { address: url.searchParams.get('ip') }, network: { asn: 64512 }, ...(calls.length === 1 ? { location: { country: 'DE', city: 'Berlin' } } : {}) });
  });
  const result = await dns(await post());
  assert.equal(result.flags & 15, 0, String(logs));
  assert.equal(result.records[0].ttl, 13);
  assert.equal(calls.length, 2);
});

test('invalid sources and unreachable references fail preflight without any network work', async () => {
  const base = geo().geo;
  const invalid = [
    { geo: { ...base, url: 'http://geo.test/lookup' } },
    { geo: { ...base, url: 'https://user:pass@geo.test/lookup' } },
    { geo: { ...base, url: 'https://geo.test/lookup#fragment' } },
    { geo: { ...base, urlSecret: 'GEO_URL' } },
    { geo: { ...base, fields: { asn: ['asn'] } } },
    { geo: { ...base, fields: { ip: ['ip'] } } },
    { geo: { ...base, fields: { ip: ['ip'], asn: 'asn' } } },
    { geo: { ...base, fields: { ip: ['ip'], asn: [] } } },
    { geo: { ...base, fields: { ip: ['ip'], asn: ['a', ...Array(16).fill('b')] } } },
    { geo: { ...base, fields: { ip: ['ip'], unexpected: ['field'], asn: ['asn'] } } },
    { geo: { ...base, params: { ip: 'fixed' } } },
    { geo: { ...base, url: 'https://geo.test/?ip=fixed' } },
    { geo: { ...base, cacheTtl: 86401 } },
    { geo: { ...base, params: { token: 5 } } },
    { geo: { ...base, unexpected: true } },
  ];
  for (const definitions of invalid) {
    await setup({ DNS_ADDRESS_SOURCES: definitions, DNS_RULE_MAIN: group([fixed, { type: 'return' }]) }, geoHandler);
    assert.equal((await dns(await post())).flags & 15, 2, JSON.stringify(definitions));
    assert.equal(calls.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG'));
  }
  await setup({ DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [fixed, { type: 'return' }] }, { when: { field: 'query.type', op: 'eq', value: 'AAAA' }, actions: [{ ...enrich, source: 'missing' }] },
  ] } }, geoHandler);
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 0);
});

test('DNS and attribution share network quotas, including failed optional actions', async () => {
  for (const maxNetworkRequests of [1, 2]) {
    await setup({ DNS_LIMITS: { maxNetworkRequests }, DNS_UPSTREAMS: source('https://dns.test/query'), DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [requestDefault, { ...enrich, onError: 'continue' }, { ...enrich, onError: 'continue' }] },
      { when: { field: 'lastAction.code', op: 'eq', value: 'RESOURCE_LIMIT' }, actions: [{ type: 'setTtl', ttl: 11 }] },
    ] } }, async request => new URL(request.url).hostname === 'dns.test' ? geoHandler(request) : new Response('', { status: 500 }));
    const result = await dns(await post());
    assert.equal(result.flags & 15, 0, String(logs));
    assert.equal(result.records[0].ttl, 11);
    assert.equal(calls.length, maxNetworkRequests);
  }
});

test('address/source/body limits fail deterministically before unbounded work', async () => {
  const two = { type: 'answer', records: [fixed.records[0], { ...fixed.records[0], rdata: { A: { addr: '192.0.2.2' } } }] };
  const cases = [
    [{ maxAttributionAddresses: 1 }, geo(), two, geoHandler, 0],
    [{ maxAddressSources: 1 }, { ...geo(), extra: geo().geo }, fixed, geoHandler, 0],
    [{ maxAttributionBytes: 16 }, geo(), fixed, () => json({ ip: '192.0.2.1', country: 'DE' }), 1],
    [{ maxAttributionBytes: 16 }, geo(), fixed, () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '100' } }), 1],
  ];
  for (const [limits, definitions, answer, handler, expectedCalls] of cases) {
    await setup({ DNS_LIMITS: limits, DNS_ADDRESS_SOURCES: definitions, DNS_RULE_MAIN: group([answer, enrich]) }, handler);
    assert.equal((await dns(await post())).flags & 15, 2, String(logs));
    assert.equal(calls.length, expectedCalls);
    assert.ok(logs.join('').includes('RESOURCE_LIMIT'), String(logs));
  }
});

test('empty existing answers do not lookup and missing responses do not trigger implicit DNS work', async () => {
  await setup({ DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: group([{ type: 'answer', records: [], rcode: 3 }, enrich]) }, geoHandler);
  assert.equal((await dns(await post())).flags & 15, 3);
  assert.equal(calls.length, 0);
  await setup({ DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: group([enrich]) }, geoHandler);
  assert.equal((await dns(await post())).flags & 15, 2);
  assert.equal(calls.length, 0);
  assert.ok(logs.join('').includes('NO_RESPONSE'));
});

test('per-lookup timeout allows explicit JSON continuation but overall deadline cannot be reset', async () => {
  for (const mode of ['headers', 'body', 'total']) {
    await setup({ DNS_ADDRESS_SOURCES: geo(), DNS_LIMITS: { attributionTimeoutMs: mode === 'total' ? 1000 : 50, maxExecutionTimeMs: mode === 'total' ? 50 : 1500 }, DNS_RULE_MAIN: { order: 0, rules: [
      { actions: [fixed, { ...enrich, onError: 'continue' }] },
      { when: { field: 'lastAction.code', op: 'eq', value: 'ATTRIBUTION_TIMEOUT' }, actions: [{ type: 'setTtl', ttl: 12 }] },
    ] } }, async () => {
      if (mode === 'body') return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); } }), { headers: { 'Content-Type': 'application/json' } });
      await new Promise(resolve => setTimeout(resolve, 180));
      throw new Error('private-late-origin-failure');
    });
    const result = await dns(await post());
    assert.equal(result.flags & 15, mode === 'total' ? 2 : 0, String(logs));
    if (mode !== 'total') assert.equal(result.records[0].ttl, 12);
    assert.equal(calls.length, 1);
    assert.ok(logs.join('').includes(mode === 'total' ? 'EXECUTION_TIMEOUT' : 'ATTRIBUTION_TIMEOUT'));
    assert.ok(!logs.join('').includes('private-late-origin-failure'));
  }
});

test('attribution alone preserves signed DNS data on completed, stopped and returned paths', async () => {
  const signature = [0,1,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,...nameWire('example.com'),1];
  for (const end of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    await setup({ DNS_UPSTREAMS: source('https://dns.test/signed'), DNS_ADDRESS_SOURCES: geo(), DNS_RULE_MAIN: group([requestDefault, enrich, ...end]) }, async request => {
      if (new URL(request.url).hostname === 'geo.test') return geoHandler(request);
      return new Response(responseWire(new Uint8Array(await request.arrayBuffer()), { records: [
        { name: 'example.com', type: 1, ttl: 60, data: [192,0,2,9] },
        { name: 'example.com', type: 46, ttl: 60, data: signature },
      ] }), { headers: { 'Content-Type': 'application/dns-message' } });
    });
    const result = await dns(await post());
    assert.equal(result.flags & 15, 0, String(logs));
    assert.ok(result.flags & 0x20);
    assert.deepEqual(result.records.map(rr => rr.type), [1,46]);
    assert.deepEqual(result.records[1].data, signature);
  }
});

test('attribution cache never reuses expired, forbidden or failed source responses', async () => {
  for (const mode of ['expiry', 'no-store', 'private', 'no-cache', 'vary', 'cookie', 'failure', 'disabled']) {
    let lookups = 0;
    await setup({ DNS_ADDRESS_SOURCES: geo({ url: `https://geo.test/cache-${mode}`, cacheTtl: mode === 'disabled' ? 0 : mode === 'expiry' ? 1 : 60 }), DNS_RULE_MAIN: group([fixed, { ...enrich, onError: 'continue' }]) }, request => {
      lookups++;
      const headers = mode === 'vary' ? { Vary: 'Accept' } : mode === 'cookie' ? { 'Set-Cookie': 'private-cookie=1' } : ['no-store','private','no-cache'].includes(mode) ? { 'Cache-Control': mode } : {};
      if (mode === 'failure' && lookups === 1) return new Response('', { status: 500 });
      return json({ ip: new URL(request.url).searchParams.get('ip'), country: 'DE' }, { headers });
    });
    assert.equal((await dns(await post())).flags & 15, 0, String(logs));
    if (mode === 'expiry') await new Promise(resolve => setTimeout(resolve, 1150));
    assert.equal((await dns(await post())).flags & 15, 0, String(logs));
    assert.equal(lookups, 2, mode);
  }
});

test('cache identities include field mapping and requests never share committed attribution state', async () => {
  const first = { ...geo().geo, url: 'https://geo.test/isolation', cacheTtl: 60 };
  const second = { ...first, fields: { ip: ['ip'], country: ['otherCountry'] } };
  await setup({ DNS_ADDRESS_SOURCES: { geo: first, other: second }, DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [fixed] },
    { when: { field: 'query.name', op: 'eq', value: 'example.com' }, actions: [enrich] },
    { when: { field: 'query.name', op: 'eq', value: 'other.example' }, actions: [{ ...enrich, source: 'other' }] },
    { when: addressMatch({ field: 'item.country', op: 'eq', value: 'DE' }), actions: [{ type: 'setTtl', ttl: 5 }] },
    { when: addressMatch({ field: 'item.country', op: 'eq', value: 'US' }), actions: [{ type: 'setTtl', ttl: 9 }] },
  ] } }, request => json({ ip: new URL(request.url).searchParams.get('ip'), country: 'DE', otherCountry: 'US' }));
  assert.equal((await dns(await post())).records[0].ttl, 5);
  assert.equal((await dns(await post(undefined, query('other.example')))).records[0].ttl, 9);
  assert.equal((await dns(await post(undefined, query('unenriched.example')))).records[0].ttl, 60);
  assert.equal((await dns(await post())).records[0].ttl, 5);
  assert.equal(calls.length, 2);
});


test('trusted caller cancellation aborts attribution and optional failure cannot resume network work', async () => {
  await setup({ DNS_ADDRESS_SOURCES: geo(), DNS_LIMITS: { attributionTimeoutMs: 1000, maxExecutionTimeMs: 1500 }, DNS_RULE_MAIN: group([fixed, { ...enrich, onError: 'continue' }, enrich]) }, async () => {
    await new Promise(resolve => setTimeout(resolve, 120));
    throw new Error('private-late-attribution-error');
  }, true);
  const result = await dns(await post(undefined, query(), { 'x-test-cancel': 'true' }));
  assert.equal(result.flags & 15, 2, String(logs));
  assert.equal(calls.length, 1);
  assert.ok(logs.join('').includes('REQUEST_CANCELLED'));
  assert.ok(!/private-cancel-reason|private-late-attribution-error/.test(logs.join('')));
});
