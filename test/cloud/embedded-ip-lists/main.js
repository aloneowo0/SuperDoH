import padding from '../padding-cache/main.js';
import google from '../google-tcp/main.js';
import { authorized, check } from '../padding-cache/common.js';
import { runCases } from '../../../lib/ip-list/test/cases.mjs';
import { buildSnapshots, sourceDefinitions } from '../../../scripts/lib/build-ip-lists.js';
import { buildQuery, parseMessage, matchResponse, getRcode } from '../../../lib/dns-wasm/index.js';
import { readBody } from '../../../src/doh/body.js';
import { compileList } from '../../../lib/ip-list/index.js';
import { loadIpLists } from '../../../src/rules/ip-lists.js';
import { loadLimits } from '../../../src/rules/limits.js';
import { createConfigBudget } from '../../../src/rules/config-budget.js';
import { createBudget } from '../../../src/doh/budget.js';
import embeddedData from '../../../src/generated/ip-lists.js';

export default { async fetch(request, env) {
  if (request.method !== 'POST' || !await authorized(request, env)) return new Response('', { status: 404 });
  const url = new URL(request.url), path = url.pathname.split('/').slice(2).join('/');
  for (const [prefix, handler] of [['padding/', padding], ['google/', google]]) if (path.startsWith(prefix)) {
    url.pathname = `/${env.KEY}/${path.slice(prefix.length)}`;
    return handler.fetch(new Request(url, request), env);
  }
  if (['live/a', 'live/x', 'live/facebook'].includes(path)) {
    const domain = path === 'live/a' ? 'example.com' : path === 'live/x' ? 'x.com' : 'www.facebook.com';
    const type = path === 'live/facebook' ? 65 : 1, query = buildQuery(domain, type, 2345);
    const start = Date.now(); let stage = "fetch";
    try {
      const response = await fetch(env.LIVE_ENDPOINT, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' }, body: query, signal: AbortSignal.timeout(20000) });
      check(response.ok, 'production HTTP ' + response.status);
      stage = 'body';
      const wire = await readBody(response.body, 16384, new AbortController().signal);
      stage = 'match';
      matchResponse(wire, query);
      const packet = parseMessage(wire);
      check(getRcode(packet) === 0 && packet.answers.some(r => r.rtype === type), 'production DNS answer');
      return Response.json({ passed: true, results: [{ name: path, passed: true }], ms: Date.now() - start, answerTypes: packet.answers.map(r => r.rtype), colo: request.cf?.colo ?? null });
    } catch (e) { return Response.json({ passed: false, results: [{ name: path, passed: false, error: String(e.code ?? e.name), stage, detail: String(e.message).replaceAll(env.LIVE_ENDPOINT ?? '', '[endpoint]').slice(0, 160) }] }); }
  }
  if (path === 'library') return Response.json(await runCases());
  const results = [];
  const test = async (name, fn) => { try { await fn(); results.push({ name, passed: true }); } catch (e) { results.push({ name, passed: false, error: String(e.code ?? e.message).slice(0, 160) }); } };
  const reject = async fn => { let failed = false; try { await fn(); } catch { failed = true; } check(failed, 'invalid input accepted'); };
  if (path === 'builder') {
    const config = JSON.stringify({ list: { url: 'https://fixture.invalid/list', format: 'text' } });
    await test('valid-build', async () => {
      let calls = 0;
      const result = await buildSnapshots(config, async (url, opts) => { calls++; check(opts.redirect === 'manual' && opts.signal, 'missing safety controls'); return new Response('192.0.2.0/24\n2001:db8::/32', { headers: { 'content-type': 'text/plain' } }); });
      check(calls === 1 && result.list.snapshot.entries === 2 && /^[a-f0-9]{64}$/.test(result.list.sha256), 'build metadata');
    });
    for (const [name, response] of [
      ['redirect', () => new Response('', { status: 302 })],
      ['failed-origin', () => new Response('', { status: 503 })],
      ['html', () => new Response('192.0.2.1', { headers: { 'content-type': 'text/html' } })],
      ['declared-size', () => new Response('', { headers: { 'content-length': '262145' } })],
      ['stream-size', () => new Response(new Uint8Array(262145))],
      ['empty', () => new Response('')],
      ['utf8', () => new Response(new Uint8Array([255]))],
      ['bad-cidr', () => new Response('192.0.2.0/99')],
    ]) await test('reject-' + name, () => reject(() => buildSnapshots(config, async () => response())));
    for (const [name, value] of [['missing', undefined], ['empty', '{}'], ['http', '{"list":{"url":"http://example.com","format":"text"}}'], ['format', '{"list":{"url":"https://example.com","format":"csv"}}'], ['unknown', '{"list":{"url":"https://example.com","format":"text","extra":true}}']]) await test('reject-config-' + name, () => reject(() => sourceDefinitions(value)));
    await test('partial-build-not-returned', () => reject(() => buildSnapshots(JSON.stringify({ one: { url: 'https://fixture.invalid/one', format: 'text' }, two: { url: 'https://fixture.invalid/two', format: 'text' } }), async url => new Response(url.endsWith('/one') ? '192.0.2.0/24' : 'BAD'))));
  } else if (path === 'embedded') {
    const limits = loadLimits(undefined), budget = createBudget(10000);
    const originalFetch = globalThis.fetch, originalOpen = caches.open;
    let networkCalls = 0, cacheCalls = 0;
    globalThis.fetch = async () => { networkCalls++; throw Error('unexpected fetch'); };
    caches.open = async () => { cacheCalls++; throw Error('unexpected cache access'); };
    const prepare = async (definition, changes = {}) => {
      const cap = { ...limits, ...changes };
      return loadIpLists({ DNS_IP_LISTS: definition }, cap, createConfigBudget(cap)).prepare(new Set(Object.keys(definition)), budget, () => { networkCalls++; throw Error('unexpected network allowance'); });
    };
    try {
      await test('production-indexes-no-io', async () => {
        const values = await prepare({ cloudflare: { embedded: 'cloudflare' }, meta: { embedded: 'meta' } });
        check(values.get('cloudflare').index.contains('104.26.10.221'), 'CF identity');
        check(values.get('meta').index.contains('57.144.44.1'), 'Meta identity');
      });
      await test('repeat-reuses-same-index', async () => { const one = await prepare({ list: { embedded: 'cloudflare' } }), two = await prepare({ list: { embedded: 'cloudflare' } }); check(one.get('list').index === two.get('list').index, 'recompiled index'); });
      await test('unknown-embedded-fails', () => reject(() => prepare({ list: { embedded: 'missing' } })));
      await test('mixed-source-fails', () => reject(() => prepare({ list: { embedded: 'meta', url: 'https://example.com', format: 'text' } })));
      await test('entry-limit-fails', () => reject(() => prepare({ list: { embedded: 'meta' } }, { maxIpListEntries: 1 })));
      await test('byte-limit-fails', () => reject(() => prepare({ list: { embedded: 'meta' } }, { maxIpListBytes: 1 })));
      await test('state-limit-fails', () => reject(() => prepare({ list: { embedded: 'meta' } }, { maxIpListStateBytes: 1 })));
      await test('zero-network-and-cache-operations', () => check(networkCalls === 0 && cacheCalls === 0, 'embedded path performed I/O'));
    } finally { globalThis.fetch = originalFetch; caches.open = originalOpen; budget.dispose(); }
  } else if (path === 'equivalence/cloudflare' || path === 'equivalence/meta') {
    const name = path.split('/')[1];
    await test('all-source-boundaries-' + name, async () => {
      const parts = Number(env[name === 'cloudflare' ? 'CF_PARTS' : 'META_PARTS']);
      const encoded = Array.from({ length: parts }, (_, i) => env[(name === 'cloudflare' ? 'CF_' : 'META_') + i]).join('');
      const bytes = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
      const reference = compileList(bytes, 'text', 4096, 262144), snapshot = embeddedData[name].snapshot;
      const limits = loadLimits(undefined), budget = createBudget(10000);
      try {
        const index = (await loadIpLists({ DNS_IP_LISTS: { list: { embedded: name } } }, limits, createConfigBudget(limits)).prepare(new Set(['list']), budget, () => { throw Error('network'); })).get('list').index;
        check(reference.entries === index.entries, 'entry count');
        let checked = 0;
        for (const [i, ranges] of snapshot.ranges.entries()) for (const [start, end] of ranges) for (const bits of [BigInt('0x' + start) - 1n, BigInt('0x' + start), BigInt('0x' + end), BigInt('0x' + end) + 1n]) {
          const family = i ? 128 : 32; if (bits < 0n || bits >= 1n << BigInt(family)) continue;
          const key = family + ':' + bits.toString(16); check(reference.containsKey(key) === index.containsKey(key), 'membership mismatch'); checked++;
        }
        check(checked > 0, 'no boundaries checked');
      } finally { budget.dispose(); }
    });
  } else return new Response('', { status: 404 });
  return Response.json({ passed: results.length > 0 && results.every(r => r.passed), results });
} };
