import { createIpListStore, IpListError, restoreSnapshot } from '../../lib/ip-list/index.js';
import { RuleError } from './errors.js';
import { within } from './limits.js';
import { object, fields, upstreamName } from './values.js';
import { createBudget } from '../doh/budget.js';
import { readBody } from '../doh/body.js';

import embeddedData from '../generated/ip-lists.js';

// Only immutable, validated indexes are shared; no request-scoped I/O or promises.
const embedded = new Map(Object.entries(embeddedData).map(([name, value]) => {
  if (!/^[a-f0-9]{64}$/.test(value.sha256) || !Number.isFinite(Date.parse(value.fetchedAt))) throw new Error('Invalid embedded IP list metadata.');
  return [name, { index: restoreSnapshot(value.snapshot, 65536, 2097152, 16777216), sourceBytes: value.snapshot.sourceBytes }];
}));
const store = createIpListStore();
/** @typedef {{ name: string, url: string, format: 'text' | 'json', cacheTtl: number }} Definition */
/** @typedef {{ index: import('../../lib/ip-list/index.js').Index } | { error: RuleError }} IpListSnapshot */
const fatal = new Set(['RESOURCE_LIMIT', 'REQUEST_CANCELLED', 'EXECUTION_TIMEOUT', 'IP_LIST_TIMEOUT']);
/** @param {unknown} error */
function cacheError(error) { if (error instanceof RuleError && fatal.has(error.code)) throw error; }
/** @param {ReadableStream<Uint8Array> | null} body */
function cancel(body) { try { void body?.cancel().catch(() => {}); } catch { /* Best-effort cleanup. */ } }
/** @param {string} identity @param {ReturnType<typeof createBudget>} budget */
async function cacheKey(identity, budget) {
  const hash = await budget.run(() => crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity)));
  return 'https://superdoh-ip-list.invalid/v1/' + Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
/** @param {Definition} definition @param {import('./limits.js').Limits} limits @param {ReturnType<typeof createBudget>} budget @param {() => void} spendNetwork */
async function download(definition, limits, budget, spendNetwork) {
  /** @type {Response | undefined} */ let response;
  try {
    spendNetwork();
    const pending = fetch(definition.url, { method: 'GET', redirect: 'manual', cache: 'no-store', signal: budget.signal, headers: { Accept: definition.format === 'json' ? 'application/json' : 'text/plain' } });
    pending.then(value => { if (budget.signal.aborted) cancel(value.body); }, () => {});
    response = await budget.run(() => pending);
    if (!response.ok || response.redirected) throw new RuleError('IP_LIST_FAILED', 'The configured IP list source failed.');
    const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
    if (media && (definition.format === 'text' ? media !== 'text/plain' : media !== 'application/json' && !(media.startsWith('application/') && media.endsWith('+json')))) throw new RuleError('IP_LIST_INVALID', 'The configured IP list response has an invalid media type.');
    const length = response.headers.get('content-length');
    if (length !== null) {
      if (!/^\d+$/.test(length.trim())) throw new RuleError('IP_LIST_INVALID', 'The configured IP list response is invalid.');
      within(Number(length), limits.maxIpListBytes);
    }
    return await budget.run(() => readBody(/** @type {Response} */ (response).body, limits.maxIpListBytes, budget.signal));
  } finally { if (response && !response.bodyUsed) cancel(response.body); }
}
/** @param {Definition} definition @param {import('./limits.js').Limits} limits @param {ReturnType<typeof createBudget>} execution @param {() => void} spendNetwork */
async function prepare(definition, limits, execution, spendNetwork) {
  const budget = createBudget(limits.ipListTimeoutMs, execution.signal, 'IP_LIST_TIMEOUT');
  try {
    return await store.load({
      source: definition.url, format: definition.format, cacheTtl: definition.cacheTtl,
      maxEntries: limits.maxIpListEntries, maxBytes: limits.maxIpListBytes, maxStates: limits.maxIpLists, maxStateBytes: limits.maxIpListStateBytes,
      check: budget.check,
      load: () => download(definition, limits, budget, spendNetwork),
      cache: {
        onError: cacheError,
        async get(identity) {
          const key = await cacheKey(identity, budget);
          const cache = await budget.run(() => caches.open('superdoh-ip-list-v1'));
          const pending = cache.match(key);
          pending.then(response => { if (budget.signal.aborted && response) cancel(response.body); }, () => {});
          const response = await budget.run(() => pending);
          if (!response) return;
          const bytes = await budget.run(() => readBody(response.body, limits.maxIpListBytes * 6 + 512, budget.signal));
          return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
        },
        async put(identity, data, ttl) {
          const key = await cacheKey(identity, budget);
          const cache = await budget.run(() => caches.open('superdoh-ip-list-v1'));
          const remaining = Math.floor((data.storedAt + ttl * 1000 - Date.now()) / 1000);
          if (remaining <= 0) return;
          await budget.run(() => cache.put(key, new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=' + remaining } })));
        },
      },
    });
  } finally { budget.dispose(); }
}

/** @param {Record<string, unknown>} env @param {import('./limits.js').Limits} limits @param {ReturnType<typeof import('./config-budget.js').createConfigBudget>} configBudget */
export function loadIpLists(env, limits, configBudget) {
  try {
    const entries = Object.entries(env.DNS_IP_LISTS === undefined ? {} : object(configBudget.parse(env.DNS_IP_LISTS)));
    within(entries.length, limits.maxIpLists);
    /** @type {Map<string, Definition | { name: string, embedded: string, index: import('../../lib/ip-list/index.js').Index }>} */ const definitions = new Map();
    let embeddedBytes = 0;
    for (const [name, raw] of entries) {
      upstreamName(name);
      const value = fields(raw, ['url', 'urlSecret', 'format', 'cacheTtl', 'embedded']);
      if (value.embedded !== undefined) {
        fields(value, ['embedded']);
        const key = upstreamName(value.embedded), data = embedded.get(key);
        if (!data) throw new Error();
        within(data.index.entries, limits.maxIpListEntries);
        within(data.sourceBytes, limits.maxIpListBytes);
        within(embeddedBytes += data.index.bytes, limits.maxIpListStateBytes);
        definitions.set(name, { name, embedded: key, index: data.index });
        continue;
      }
      if ((value.url !== undefined) === (value.urlSecret !== undefined)) throw new Error();
      const rawUrl = value.urlSecret === undefined ? value.url : env[upstreamName(value.urlSecret)];
      if (typeof rawUrl !== 'string' || !rawUrl.length || rawUrl.length > 2048 || rawUrl.includes('#')) throw new Error();
      const url = new URL(rawUrl);
      if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error();
      if (value.format !== 'text' && value.format !== 'json') throw new Error();
      const ttl = value.cacheTtl === undefined ? 3600 : value.cacheTtl;
      if (typeof ttl !== 'number' || !Number.isSafeInteger(ttl) || ttl < 0 || ttl > 86400) throw new Error();
      definitions.set(name, { name, url: url.href, format: value.format, cacheTtl: ttl });
    }
    return {
      /** @param {string} name */
      resolve(name) {
        const definition = definitions.get(name);
        if (!definition) throw new RuleError('INVALID_CONFIG', 'Invalid IP list reference.');
        return definition;
      },
      /** @param {Set<string>} references @param {ReturnType<typeof createBudget>} execution @param {() => void} spendNetwork */
      async prepare(references, execution, spendNetwork) {
        /** @type {Map<string, IpListSnapshot>} */ const snapshots = new Map();
        for (const name of references) {
          const definition = this.resolve(name);
          execution.check();
          if ('embedded' in definition) { snapshots.set(name, { index: definition.index }); continue; }
          try { snapshots.set(name, { index: (await prepare(definition, limits, execution, spendNetwork)).index }); }
          catch (error) {
            const code = error instanceof RuleError ? error.code : error instanceof IpListError ? error.code : 'IP_LIST_FAILED';
            const failure = new RuleError(code, 'The configured IP list is unavailable.', { source: name });
            if (fatal.has(code)) throw failure;
            snapshots.set(name, { error: failure });
          }
        }
        return snapshots;
      },
    };
  } catch (error) {
    if (error instanceof RuleError && error.code === 'RESOURCE_LIMIT') throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid IP list configuration.');
  }
}
