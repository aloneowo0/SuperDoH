import { RuleError } from '../rules/errors.js';
import { ip } from '../rules/ip.js';
import { httpFreshness } from './cache.js';
import { createBudget } from './budget.js';
import { readBody } from './body.js';
import { within } from '../rules/limits.js';

const CACHE_NAME = 'superdoh-address-attribution-v1';
const CACHE_PREFIX = 'https://superdoh-address-attribution.invalid/v1/';
const CONTENT_TYPE = 'application/json';
const CACHE_STORED_HEADER = 'x-superdoh-attribution-stored';
const CACHE_TTL_HEADER = 'x-superdoh-attribution-lifetime';

/** @param {ReadableStream<Uint8Array> | null} body */
function cancelBody(body) {
  if (!body) return;
  try { void body.cancel().catch(() => {}); } catch { /* Best-effort cleanup. */ }
}

/** @param {unknown} error */
function isBudgetFailure(error) {
  return error instanceof RuleError && ['EXECUTION_TIMEOUT', 'ATTRIBUTION_TIMEOUT', 'REQUEST_CANCELLED', 'RESOURCE_LIMIT'].includes(error.code);
}

/** @param {bigint} bits @param {number} family @returns {string} */
function canonicalText(bits, family) {
  if (family === 32) return [24n, 16n, 8n, 0n].map(shift => Number((bits >> shift) & 255n)).join('.');
  const value = bits;
  const words = Array.from({ length: 8 }, (_, index) => Number((value >> BigInt((7 - index) * 16)) & 65535n).toString(16));
  let bestStart = -1, bestLength = 1;
  for (let index = 0; index < words.length;) {
    if (words[index] !== '0') { index++; continue; }
    let end = index + 1;
    while (end < words.length && words[end] === '0') end++;
    if (end - index > bestLength) { bestStart = index; bestLength = end - index; }
    index = end;
  }
  if (bestStart < 0) return words.join(':');
  return words.slice(0, bestStart).join(':') + '::' + words.slice(bestStart + bestLength).join(':');
}

/** @param {import('../rules/types.js').DeepReadonly<import('../../lib/dns-wasm/index.js').DnsMessage> | import('../../lib/dns-wasm/index.js').DnsMessage} response */
function responseAddresses(response) {
  /** @type {Map<string, { text: string, family: number, bits: bigint }>} */
  const addresses = new Map();
  for (const section of [response.answers, response.authority, response.additional]) {
    for (const record of section) {
      const address = record.rdata && 'A' in record.rdata ? record.rdata.A.addr
        : record.rdata && 'Aaaa' in record.rdata ? record.rdata.Aaaa.addr : undefined;
      if (address === undefined) continue;
      let parsed;
      try { parsed = ip(address); }
      catch { throw new RuleError('ATTRIBUTION_INVALID', 'Invalid DNS response address for attribution.'); }
      if (!addresses.has(parsed.key)) addresses.set(parsed.key, { text: canonicalText(parsed.bits, parsed.family), family: parsed.family, bits: parsed.bits });
    }
  }
  return addresses;
}

/** @param {unknown} value @param {string[]} path */
function ownPath(value, path) {
  let current = value;
  for (const segment of path) {
    if ((typeof current !== 'object' && typeof current !== 'function') || current === null || !Object.hasOwn(current, segment)) return { found: false, value: undefined };
    current = /** @type {Record<string, unknown>} */ (current)[segment];
  }
  return { found: true, value: current };
}

/** @param {unknown} value @param {string} requestedKey @param {import('../rules/address-sources.js').AddressSource} source */
function mappedResult(value, requestedKey, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.');
  const ipPath = source.fields.ip;
  if (!ipPath) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution mapping is invalid.');
  const mappedIp = ownPath(value, ipPath);
  if (!mappedIp.found || typeof mappedIp.value !== 'string') throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.');
  let mappedKey;
  try { mappedKey = ip(mappedIp.value).key; }
  catch { throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.'); }
  if (mappedKey !== requestedKey) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response does not match the requested address.');

  /** @type {{ asn?: number, country?: string, region?: string, city?: string }} */
  const attributes = {};
  for (const key of ['asn', 'country', 'region', 'city']) {
    const fieldPath = source.fields[key];
    if (!fieldPath) continue;
    const result = ownPath(value, fieldPath);
    if (!result.found) continue;
    if (key === 'asn') {
      if (typeof result.value !== 'number' || !Number.isInteger(result.value) || result.value < 0 || result.value > 0xffffffff) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.');
      attributes.asn = result.value;
    } else {
      if (typeof result.value !== 'string' || result.value.length === 0 || result.value.length > 128 || /[\x00-\x1f\x7f]/.test(result.value)) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.');
      attributes[/** @type {'country' | 'region' | 'city'} */ (key)] = result.value;
    }
  }
  return attributes;
}

/** @param {import('../rules/address-sources.js').AddressSource} source @param {string} sourceName @param {string} addressKey @param {ReturnType<typeof createBudget>} budget */
async function cacheKey(source, sourceName, addressKey, budget) {
  const identity = JSON.stringify([sourceName, source, addressKey]);
  const digest = await budget.run(() => crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity)));
  return new Request(CACHE_PREFIX + Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join(''));
}

/** @param {unknown} error */
function cacheError(error) {
  if (isBudgetFailure(error)) return error;
  return new RuleError('CACHE_FAILED', 'Address attribution cache operation failed.');
}

/** @param {import('../rules/address-sources.js').AddressSource} source @param {string} sourceName @param {string} addressKey @param {ReturnType<typeof createBudget>} budget @param {number} maximum */
async function readCached(source, sourceName, addressKey, budget, maximum) {
  /** @type {Response | undefined} */
  let response;
  try {
    const key = await cacheKey(source, sourceName, addressKey, budget);
    const cache = await budget.run(() => caches.open(CACHE_NAME));
    const pending = cache.match(key);
    pending.then(value => { if (budget.signal.aborted) cancelBody(value?.body ?? null); }, () => {});
    response = await budget.run(() => pending);
    if (!response) return undefined;
    const storedAt = Number(response.headers.get(CACHE_STORED_HEADER));
    const validFor = Number(response.headers.get(CACHE_TTL_HEADER));
    const now = Date.now();
    if (!Number.isSafeInteger(storedAt) || storedAt <= 0 || storedAt > now || !Number.isInteger(validFor) || validFor <= 0 || validFor > 86400) {
      cancelBody(response.body);
      throw new RuleError('CACHE_FAILED', 'Address attribution cache entry is invalid.');
    }
    const elapsed = Math.max(0, Math.floor((now - storedAt) / 1000));
    if (elapsed >= Math.min(validFor, source.cacheTtl)) { cancelBody(response.body); return undefined; }
    const bytes = await budget.run(() => readBody(response?.body ?? null, maximum, budget.signal));
    if (Math.max(0, Math.floor((Date.now() - storedAt) / 1000)) >= Math.min(validFor, source.cacheTtl)) return undefined;
    const payload = JSON.parse(new TextDecoder().decode(bytes));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || !Object.hasOwn(payload, 'ip') || !Object.hasOwn(payload, 'attributes')) {
      throw new RuleError('CACHE_FAILED', 'Address attribution cache entry is invalid.');
    }
    mappedResult({ ip: payload.ip }, addressKey, { ...source, fields: { ip: ['ip'] } });
    const cachedAttributes = payload.attributes;
    if (!cachedAttributes || typeof cachedAttributes !== 'object' || Array.isArray(cachedAttributes)) throw new RuleError('CACHE_FAILED', 'Address attribution cache entry is invalid.');
    const allowed = new Set(['asn', 'country', 'region', 'city']);
    if (Object.keys(cachedAttributes).some(key => !allowed.has(key))) throw new RuleError('CACHE_FAILED', 'Address attribution cache entry is invalid.');
    /** @type {{ asn?: number, country?: string, region?: string, city?: string }} */
    const checked = {};
    for (const key of ['asn', 'country', 'region', 'city']) {
      if (!Object.hasOwn(cachedAttributes, key)) continue;
      const value = cachedAttributes[key];
      if (key === 'asn') {
        if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RuleError('CACHE_FAILED', 'Address attribution cache entry is invalid.');
        checked.asn = value;
      } else {
        if (typeof value !== 'string' || value.length === 0 || value.length > 128 || /[\x00-\x1f\x7f]/.test(value)) throw new RuleError('CACHE_FAILED', 'Address attribution cache entry is invalid.');
        checked[/** @type {'country' | 'region' | 'city'} */ (key)] = value;
      }
    }
    budget.check();
    return checked;
  } catch (error) {
    throw cacheError(error);
  } finally {
    if (response?.body && !response.bodyUsed) cancelBody(response.body);
  }
}

/** @param {import('../rules/address-sources.js').AddressSource} source @param {string} sourceName @param {string} addressKey @param {string} addressText @param {Record<string, unknown>} attributes @param {Response} originResponse @param {number} receivedAt @param {ReturnType<typeof createBudget>} budget */
async function writeCached(source, sourceName, addressKey, addressText, attributes, originResponse, receivedAt, budget) {
  try {
    const freshness = httpFreshness(originResponse.headers);
    const lifetime = Math.min(source.cacheTtl - freshness.age, freshness.maxTtl);
    if (!Number.isFinite(lifetime) || lifetime <= 0) return;
    const storedAt = receivedAt;
    const payload = JSON.stringify({ ip: addressText, attributes });
    const key = await cacheKey(source, sourceName, addressKey, budget);
    const cache = await budget.run(() => caches.open(CACHE_NAME));
    const remaining = lifetime - Math.max(0, Math.floor((Date.now() - storedAt) / 1000));
    if (remaining <= 0) return;
    await budget.run(() => cache.put(key, new Response(payload, { headers: {
      'Content-Type': CONTENT_TYPE,
      'Cache-Control': `public, max-age=${remaining}`,
      [CACHE_STORED_HEADER]: String(storedAt),
      [CACHE_TTL_HEADER]: String(lifetime),
    } })));
  } catch (error) {
    throw cacheError(error);
  }
}

/** @param {import('../rules/address-sources.js').AddressSource} source @param {string} addressText @param {AbortSignal} signal */
function sourceRequest(source, addressText, signal) {
  const url = new URL(source.url);
  for (const [key, value] of Object.entries(source.params)) url.searchParams.set(key, value);
  url.searchParams.set(source.ipParam, addressText);
  return new Request(url, { method: 'GET', headers: { Accept: CONTENT_TYPE }, redirect: 'manual', cache: 'no-store', signal });
}

/** @param {Response} response */
function validateContentType(response) {
  const raw = response.headers.get('content-type');
  const type = raw?.split(';', 1)[0].trim().toLowerCase();
  if (type !== CONTENT_TYPE && !(type?.startsWith('application/') && type.endsWith('+json'))) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.');
}

/** @param {Response} response @param {number} maximum @param {AbortSignal} signal */
async function parseBody(response, maximum, signal) {
  const length = response.headers.get('content-length');
  if (length !== null) {
    if (!/^\d+$/.test(length.trim())) throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.');
    if (Number(length.trim()) > maximum) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
  }
  const bytes = await readBody(response.body, maximum, signal);
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new RuleError('ATTRIBUTION_INVALID', 'The address attribution response is invalid.'); }
}

/**
 * Create the request-scoped address-attribution operation.
 * @param {import('../rules/limits.js').Limits & { attributionTimeoutMs: number, maxAttributionBytes: number, maxAttributionAddresses: number, maxNetworkRequests: number }} limits
 * @param {ReturnType<typeof createBudget>} budget
 * @param {() => void} spendNetwork Shared request-scoped network quota callback.
 * @returns {(source: import('../rules/address-sources.js').AddressSource, response: import('../../lib/dns-wasm/index.js').DnsMessage | null, sourceName: string) => Promise<Map<string, { asn?: number, country?: string, region?: string, city?: string }>>}
 */
export function createAttribution(limits, budget, spendNetwork) {
  return async function attribute(source, response, sourceName) {
    if (!response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.');
    const addresses = responseAddresses(response);
    within(addresses.size, limits.maxAttributionAddresses);
    /** @type {Map<string, { asn?: number, country?: string, region?: string, city?: string }>} */
    const result = new Map();
    for (const [addressKey, address] of addresses) {
      budget.check();
      if (source.cacheTtl > 0) {
        const cached = await readCached(source, sourceName, addressKey, budget, limits.maxAttributionBytes);
        if (cached !== undefined) { result.set(addressKey, cached); continue; }
      }
      const child = createBudget(limits.attributionTimeoutMs, budget.signal, 'ATTRIBUTION_TIMEOUT');
      /** @type {Response | undefined} */
      let responseFromSource;
      let responseReceivedAt = 0;
      let bodyConsumed = false;
      try {
        const request = sourceRequest(source, address.text, child.signal);
        spendNetwork();
        const pending = fetch(request);
        pending.then(value => { if (child.signal.aborted) cancelBody(value.body); }, () => {});
        try {
          responseFromSource = await child.run(() => pending);
          responseReceivedAt = Date.now();
        }
        catch (error) {
          if (isBudgetFailure(error)) throw error;
          throw new RuleError('ATTRIBUTION_FAILED', 'The address attribution source request failed.');
        }
        child.check();
        const sourceResponse = responseFromSource;
        if (!sourceResponse) throw new RuleError('ATTRIBUTION_FAILED', 'The address attribution source request failed.');
        if (!sourceResponse.ok || sourceResponse.redirected || (sourceResponse.status >= 300 && sourceResponse.status < 400)) {
          cancelBody(sourceResponse.body);
          throw new RuleError('ATTRIBUTION_FAILED', 'The address attribution source request failed.');
        }
        validateContentType(sourceResponse);
        const payload = await child.run(() => parseBody(sourceResponse, limits.maxAttributionBytes, child.signal));
        bodyConsumed = true;
        child.check();
        const attributes = mappedResult(payload, addressKey, source);
        if (source.cacheTtl > 0) await writeCached(source, sourceName, addressKey, address.text, attributes, sourceResponse, responseReceivedAt, budget);
        result.set(addressKey, attributes);
      } catch (error) {
        if (error instanceof RuleError) throw error;
        throw new RuleError('ATTRIBUTION_FAILED', 'The address attribution source request failed.');
      } finally {
        if (responseFromSource && !bodyConsumed) cancelBody(responseFromSource.body);
        child.dispose();
      }
    }
    return result;
  };
}
