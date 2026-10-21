import { RuleError } from './errors.js';
import { within } from './limits.js';
import { object, fields, domain, upstreamName } from './values.js';
import { createBudget } from '../doh/budget.js';
import { readBody } from '../doh/body.js';

const CONFIG_FIELDS = ['domains', 'url', 'urlSecret', 'format', 'refreshIntervalMs'];
const CACHE_LIMIT = 64;
const MAX_URL_LENGTH = 2048;
const DOMAIN_LIST_CACHE = new Map();
let generationSequence = 0;

/** @typedef {{ name: string, kind: 'inline', domains: ReadonlySet<string> } | { name: string, kind: 'external', url: string, format: 'text' | 'json', refreshIntervalMs: number }} DomainListDefinition */
/** @typedef {{ domains: ReadonlySet<string> } | { error: RuleError }} ListSnapshot */
/** @typedef {{ generation: number, refreshing: boolean, domains?: ReadonlySet<string>, error?: RuleError, nextRefreshAt: number, bytes: number }} DomainListState */

/** @param {unknown} value @returns {string} */
function normalizeDomain(value) {
  try { return domain(value); }
  catch { throw new RuleError('DOMAIN_LIST_INVALID', 'The domain list contains an invalid domain.'); }
}

/** @param {unknown} value @param {import('./limits.js').Limits & { maxDomainListEntries: number }} limits @returns {ReadonlySet<string>} */
function inlineDomains(value, limits) {
  if (!Array.isArray(value)) throw new Error();
  within(value.length, limits.maxDomainListEntries);
  const domains = new Set();
  for (const item of value) domains.add(normalizeDomain(item));
  return domains;
}

/** @param {unknown} raw @returns {string} */
function httpsUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URL_LENGTH || raw.includes('#')) throw new Error();
  const url = new URL(raw);
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '') throw new Error();
  return raw;
}

/** @param {unknown} value */
function sourceFailure(value) {
  if (value instanceof RuleError && [
    'DOMAIN_LIST_TIMEOUT', 'REQUEST_CANCELLED', 'EXECUTION_TIMEOUT', 'RESOURCE_LIMIT', 'DOMAIN_LIST_INVALID',
  ].includes(value.code)) return value;
  if (value instanceof RuleError && value.code === 'DOMAIN_LIST_FAILED') return value;
  return new RuleError('DOMAIN_LIST_FAILED', 'The configured domain list source failed.');
}

/** @param {string} name @param {string} code */
function unavailable(name, code = 'DOMAIN_LIST_FAILED') {
  const message = code === 'DOMAIN_LIST_INVALID'
    ? 'The configured domain list is invalid.'
    : code === 'DOMAIN_LIST_TIMEOUT'
      ? 'The configured domain list source timed out.'
      : code === 'RESOURCE_LIMIT'
        ? 'Configured resource limit exceeded.'
        : code === 'REQUEST_CANCELLED'
          ? 'DNS execution was cancelled.'
          : code === 'EXECUTION_TIMEOUT'
            ? 'DNS execution deadline exceeded.'
            : 'The configured domain list source is unavailable.';
  return new RuleError(code, message, { source: name });
}

/** @param {ReadableStream<Uint8Array> | null} body */
function cancelBody(body) {
  if (!body) return;
  try { void body.cancel().catch(() => {}); } catch { /* Best-effort cleanup. */ }
}

/** @param {Response} response @param {'text' | 'json'} format */
function validateMediaType(response, format) {
  const raw = response.headers.get('content-type');
  if (raw === null) return;
  const type = raw.split(';', 1)[0].trim().toLowerCase();
  if (format === 'json') {
    if (type !== 'application/json' && !(type.startsWith('application/') && type.endsWith('+json'))) {
      throw new RuleError('DOMAIN_LIST_INVALID', 'The configured domain list response has an invalid media type.');
    }
  } else if (type !== 'text/plain' && !type.startsWith('text/')) {
    throw new RuleError('DOMAIN_LIST_INVALID', 'The configured domain list response has an invalid media type.');
  }
}

/** @param {Uint8Array} bytes @param {'text' | 'json'} format @param {import('./limits.js').Limits & { maxDomainListEntries: number }} limits @returns {ReadonlySet<string>} */
function parseDomains(bytes, format, limits) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes); }
  catch { throw new RuleError('DOMAIN_LIST_INVALID', 'The configured domain list is not valid UTF-8.'); }
  /** @type {unknown[]} */
  let entries;
  if (format === 'json') {
    try {
      const parsed = JSON.parse(text);
      if (!Array.isArray(parsed)) throw new Error();
      entries = parsed;
    } catch { throw new RuleError('DOMAIN_LIST_INVALID', 'The configured JSON domain list is invalid.'); }
  } else {
    entries = text.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0);
  }
  within(entries.length, limits.maxDomainListEntries);
  const domains = new Set();
  for (const entry of entries) domains.add(normalizeDomain(entry));
  return domains;
}

/** @param {ReadonlySet<string>} domains */
function stateBytes(domains) {
  let bytes = 256;
  for (const value of domains) bytes += value.length * 2 + 32;
  return bytes;
}

/** @param {string} key @param {DomainListState} state @param {number} additionalBytes @param {import('./limits.js').Limits} limits */
function reserveState(key, state, additionalBytes, limits) {
  const targetBytes = state.bytes + additionalBytes;
  const maxStates = Math.min(CACHE_LIMIT, limits.maxDomainLists);
  while (true) {
    let total = 0;
    for (const value of DOMAIN_LIST_CACHE.values()) total += value.bytes;
    const isStored = DOMAIN_LIST_CACHE.get(key) === state;
    const countAfter = isStored ? DOMAIN_LIST_CACHE.size : DOMAIN_LIST_CACHE.size + 1;
    if (countAfter <= maxStates && total - (isStored ? state.bytes : 0) + targetBytes <= limits.maxDomainListStateBytes) {
      state.bytes = targetBytes;
      return true;
    }
    let evicted = false;
    for (const [otherKey, other] of DOMAIN_LIST_CACHE) {
      if (otherKey === key || other.refreshing) continue;
      DOMAIN_LIST_CACHE.delete(otherKey);
      evicted = true;
      break;
    }
    if (!evicted) return false;
  }
}

/** @param {DomainListDefinition} definition @param {ReturnType<typeof createBudget>} budget @param {import('./limits.js').Limits} limits */
async function identity(definition, budget, limits) {
  const material = JSON.stringify(definition.kind === 'external'
    ? [definition.name, definition.kind, definition.url, definition.format, definition.refreshIntervalMs,
      limits.maxDomainListEntries, limits.maxDomainListBytes, limits.maxDomainListStateBytes, limits.maxDomainLists]
    : [definition.name, definition.kind, [...definition.domains].sort()]);
  const digest = await budget.run(() => crypto.subtle.digest('SHA-256', new TextEncoder().encode(material)));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** @param {DomainListDefinition & { kind: 'external' }} definition @param {ReturnType<typeof createBudget>} budget @param {() => void} spendNetwork @param {import('./limits.js').Limits & { maxDomainListBytes: number, maxDomainListEntries: number, domainListTimeoutMs: number }} limits */
async function fetchDomains(definition, budget, spendNetwork, limits) {
  const child = createBudget(limits.domainListTimeoutMs, budget.signal, 'DOMAIN_LIST_TIMEOUT');
  /** @type {Response | undefined} */
  let response;
  let bodyConsumed = false;
  try {
    spendNetwork();
    const request = new Request(definition.url, {
      method: 'GET',
      headers: { Accept: definition.format === 'json' ? 'application/json' : 'text/plain' },
      redirect: 'manual', cache: 'no-store', signal: child.signal,
    });
    const pending = fetch(request);
    pending.then(value => { if (child.signal.aborted) cancelBody(value.body); }, () => {});
    try { response = await child.run(() => pending); }
    catch (error) { throw sourceFailure(error); }
    child.check();
    const received = response;
    if (!received) throw new RuleError('DOMAIN_LIST_FAILED', 'The configured domain list source failed.');
    if (!received.ok || received.redirected || (received.status >= 300 && received.status < 400)) {
      cancelBody(received.body);
      throw new RuleError('DOMAIN_LIST_FAILED', 'The configured domain list source failed.');
    }
    validateMediaType(received, definition.format);
    const contentLength = received.headers.get('content-length');
    if (contentLength !== null) {
      if (!/^\d+$/.test(contentLength.trim())) throw new RuleError('DOMAIN_LIST_INVALID', 'The configured domain list response is invalid.');
      if (Number(contentLength.trim()) > limits.maxDomainListBytes) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
    }
    const bytes = await child.run(() => readBody(received.body, limits.maxDomainListBytes, child.signal));
    bodyConsumed = true;
    child.check();
    return parseDomains(bytes, definition.format, limits);
  } catch (error) {
    if (error instanceof RuleError) throw sourceFailure(error);
    throw new RuleError('DOMAIN_LIST_FAILED', 'The configured domain list source failed.');
  } finally {
    if (response && !bodyConsumed) cancelBody(response.body);
    child.dispose();
  }
}

/** @param {string} name @param {unknown} raw @param {Record<string, unknown>} env @param {import('./limits.js').Limits & { maxDomainListEntries: number }} limits @returns {DomainListDefinition} */
function definition(name, raw, env, limits) {
  const value = fields(raw, CONFIG_FIELDS);
  if (value.domains !== undefined) {
    fields(value, ['domains']);
    try { return { name, kind: 'inline', domains: inlineDomains(value.domains, limits) }; }
    catch (error) {
      if (error instanceof RuleError && error.code === 'RESOURCE_LIMIT') throw error;
      throw new RuleError('INVALID_CONFIG', 'Invalid domain list configuration.');
    }
  }
  const hasUrl = value.url !== undefined;
  const hasSecret = value.urlSecret !== undefined;
  if (hasUrl === hasSecret || (value.format !== 'text' && value.format !== 'json')) throw new Error();
  if (typeof value.refreshIntervalMs !== 'number' || !Number.isSafeInteger(value.refreshIntervalMs) || value.refreshIntervalMs < 1) throw new Error();
  let rawUrl = value.url;
  if (hasSecret) {
    const binding = upstreamName(value.urlSecret);
    if (!Object.hasOwn(env, binding)) throw new Error();
    rawUrl = env[binding];
  }
  const url = httpsUrl(rawUrl);
  return { name, kind: 'external', url, format: value.format, refreshIntervalMs: value.refreshIntervalMs };
}

/**
 * Load and validate configured inline and external domain lists.
 * @param {Record<string, unknown>} env
 * @param {import('./limits.js').Limits & { maxDomainLists: number, maxDomainListEntries: number, maxDomainListBytes: number, domainListTimeoutMs: number }} limits
 * @param {ReturnType<typeof import('./config-budget.js').createConfigBudget>} configBudget
 */
export function loadDomainLists(env, limits, configBudget) {
  try {
    const input = env.DNS_DOMAIN_LISTS === undefined ? {} : object(configBudget.parse(env.DNS_DOMAIN_LISTS));
    const entries = Object.entries(input);
    within(entries.length, limits.maxDomainLists);
    /** @type {Map<string, DomainListDefinition>} */
    const definitions = new Map();
    for (const [name, raw] of entries) {
      upstreamName(name);
      definitions.set(name, definition(name, raw, env, limits));
    }
    return {
      /** @param {string} name */
      resolve(name) {
        const result = definitions.get(name);
        if (!result) throw new RuleError('INVALID_CONFIG', 'Invalid domain list reference.');
        return result;
      },
      /** @param {Set<string>} references @param {ReturnType<typeof createBudget>} budget @param {() => void} spendNetwork @returns {Promise<Map<string, ListSnapshot>>} */
      async prepare(references, budget, spendNetwork) {
        /** @type {Map<string, ListSnapshot>} */
        const snapshots = new Map();
        for (const name of references) {
          const list = this.resolve(name);
          if (list.kind === 'inline') {
            snapshots.set(name, { domains: list.domains });
            continue;
          }
          let key;
          try { key = await identity(list, budget, limits); }
          catch (error) {
            snapshots.set(name, { error: unavailable(name, sourceFailure(error).code) });
            continue;
          }
          let state = DOMAIN_LIST_CACHE.get(key);
          if (!state) {
            state = { generation: 0, refreshing: false, nextRefreshAt: 0, bytes: 256 };
            if (!reserveState(key, state, 0, limits)) {
              snapshots.set(name, { error: unavailable(name, 'RESOURCE_LIMIT') });
              continue;
            }
            DOMAIN_LIST_CACHE.set(key, state);
          } else {
            DOMAIN_LIST_CACHE.delete(key);
            DOMAIN_LIST_CACHE.set(key, state);
          }
          if (!state) {
            snapshots.set(name, { error: unavailable(name, 'RESOURCE_LIMIT') });
            continue;
          }
          const now = Date.now();
          if (now >= state.nextRefreshAt && !state.refreshing) {
            const generation = ++generationSequence;
            state.generation = generation;
            state.refreshing = true;
            state.domains = undefined;
            state.error = undefined;
            reserveState(key, state, 256 - state.bytes, limits);
            try {
              const domains = await fetchDomains(list, budget, spendNetwork, limits);
              if (state.generation === generation && DOMAIN_LIST_CACHE.get(key) === state) {
                const bytes = stateBytes(domains);
                if (!reserveState(key, state, bytes - state.bytes, limits)) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
                state.domains = domains;
                state.error = undefined;
                state.nextRefreshAt = Date.now() + list.refreshIntervalMs;
              }
            } catch (error) {
              if (state.generation === generation && DOMAIN_LIST_CACHE.get(key) === state) {
                state.domains = undefined;
                state.error = sourceFailure(error);
                state.nextRefreshAt = Date.now() + list.refreshIntervalMs;
                reserveState(key, state, 0, limits);
              }
            } finally {
              if (state.generation === generation && DOMAIN_LIST_CACHE.get(key) === state) state.refreshing = false;
            }
          }
          if (state.refreshing) {
            snapshots.set(name, { error: unavailable(name) });
          } else if (state.domains) {
            snapshots.set(name, { domains: state.domains });
          } else {
            const failure = state.error ?? new RuleError('DOMAIN_LIST_FAILED', 'The configured domain list source is unavailable.');
            snapshots.set(name, { error: unavailable(name, failure.code) });
          }
        }
        return snapshots;
      },
    };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid domain list configuration.');
  }
}
