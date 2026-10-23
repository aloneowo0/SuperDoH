import { EchProbeError, parseEchConfigList, parseTrustAnchors, probeEch as libraryProbeEch } from '../../lib/ech-probe/index.js';
import { readBody } from './body.js';
import { RuleError } from '../rules/errors.js';

const PROBE_CACHE_NAME = 'superdoh-ech-probe-v1';
const PROBE_CACHE_PREFIX = 'https://superdoh-ech-probe.invalid/v1/';
const PROBE_CACHE_STORED = 'x-superdoh-ech-stored';
const PROBE_CACHE_TTL = 'x-superdoh-ech-lifetime';
const MAX_CACHE_TTL = 86400;
const MAX_TIMEOUT_MS = 60000;
const MAX_PROBE_BYTES = 1048576;
const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_BYTES = 65536;
const MAX_TRUST_ROOT_BYTES = 1048576;

/** @typedef {Omit<import('../../lib/ech-probe/index.js').CommonProbeOptions, 'hostname' | 'port' | 'serverName' | 'alpn' | 'timeoutMs' | 'maxBytes' | 'signal'> & { hostname: string, port: number, serverName: string, alpn: string[], timeoutMs: number, maxBytes: number, verifyCertificate: boolean, caCertificates?: (string | Uint8Array)[], cacheTtl: number }} ValidatedProbeOptions */

/** @param {unknown} value @returns {Record<string, unknown>} */
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {string} value @returns {string} */
function dnsName(value) {
  const name = value.endsWith('.') ? value.slice(0, -1).toLowerCase() : value.toLowerCase();
  const labels = name.split('.');
  if (!name.length || name.length > 253 || !labels.every(label => label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))
    || /^(?:[0-9]+|0x[0-9a-f]*)$/i.test(labels.at(-1) ?? '')) throw new Error();
  return name;
}

/** @param {string} value @returns {string} */
function hostname(value) {
  if (/^[0-9]+(?:\.[0-9]+){3}$/.test(value)) {
    if (!value.split('.').every(part => Number(part) <= 255 && String(Number(part)) === part)) throw new Error();
    return value;
  }
  if (value.includes(':') || value.includes('[') || value.includes(']')) {
    const literal = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
    if (!/^[0-9a-f:.]+$/i.test(literal)) throw new Error();
    try { return new URL(`http://[${literal}]/`).hostname.slice(1, -1); }
    catch { throw new Error(); }
  }
  return dnsName(value);
}

/** @param {unknown} value @returns {Uint8Array} */
function byteArray(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_TRUST_ROOT_BYTES
    || value.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error();
  return Uint8Array.from(value);
}

/**
 * Validate the JSON-serializable public options of lib/ech-probe. The socket signal
 * is supplied only at execution time and is never accepted from configuration.
 * @param {unknown} value
 * @returns {ValidatedProbeOptions}
 */
export function validateProbeOptions(value) {
  try {
    const input = object(value);
    const allowed = new Set(['hostname', 'port', 'serverName', 'alpn', 'timeoutMs', 'maxBytes', 'verifyCertificate', 'caCertificates', 'cacheTtl']);
    if (Object.keys(input).some(key => !allowed.has(key))) throw new Error();
    if (typeof input.hostname !== 'string' || input.hostname.length === 0 || input.hostname.length > 253) throw new Error();
    const target = hostname(input.hostname);
    const isIp = target.includes(':') || /^[0-9]+(?:\.[0-9]+){3}$/.test(target);
    const port = input.port === undefined ? 443 : input.port;
    if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error();
    const serverName = input.serverName === undefined
      ? (isIp ? undefined : target)
      : typeof input.serverName === 'string' ? dnsName(input.serverName) : undefined;
    if (!serverName) throw new Error();
    /** @type {string[]} */
    let alpn = [];
    if (input.alpn !== undefined) {
      if (!Array.isArray(input.alpn)) throw new Error();
      let encodedLength = 0;
      const seen = new Set();
      alpn = input.alpn.map(name => {
        if (typeof name !== 'string' || !/^[\x01-\x7f]{1,255}$/.test(name) || seen.has(name)) throw new Error();
        seen.add(name);
        encodedLength += name.length + 1;
        if (encodedLength > 12000) throw new Error();
        return name;
      });
    }
    const timeoutMs = input.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : input.timeoutMs;
    if (typeof timeoutMs !== 'number' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) throw new Error();
    const maxBytes = input.maxBytes === undefined ? DEFAULT_MAX_BYTES : input.maxBytes;
    if (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 1024 || maxBytes > MAX_PROBE_BYTES) throw new Error();
    const verifyCertificate = input.verifyCertificate === undefined ? false : input.verifyCertificate;
    if (typeof verifyCertificate !== 'boolean') throw new Error();
    /** @type {(string | Uint8Array)[] | undefined} */
    let caCertificates;
    if (input.caCertificates !== undefined) {
      if (!verifyCertificate || !Array.isArray(input.caCertificates) || input.caCertificates.length === 0
        || input.caCertificates.length > 64) throw new Error();
      let totalBytes = 0;
      caCertificates = input.caCertificates.map(certificate => {
        if (typeof certificate === 'string') {
          if (!certificate.length) throw new Error();
          totalBytes += new TextEncoder().encode(certificate).byteLength;
          if (totalBytes > MAX_TRUST_ROOT_BYTES) throw new Error();
          return certificate;
        }
        const bytes = byteArray(certificate);
        totalBytes += bytes.byteLength;
        if (totalBytes > MAX_TRUST_ROOT_BYTES) throw new Error();
        return bytes;
      });
    }
    const cacheTtl = input.cacheTtl === undefined ? 0 : input.cacheTtl;
    if (typeof cacheTtl !== 'number' || !Number.isSafeInteger(cacheTtl) || cacheTtl < 0 || cacheTtl > MAX_CACHE_TTL) throw new Error();
    if (caCertificates !== undefined) caCertificates = parseTrustAnchors(caCertificates);
    return {
      hostname: target, port, serverName, alpn, timeoutMs, maxBytes, verifyCertificate,
      ...(caCertificates === undefined ? {} : { caCertificates }), cacheTtl,
    };
  } catch {
    throw new RuleError('ECH_INVALID', 'Invalid ECH probe configuration.');
  }
}

/** @param {unknown} error */
function isBudgetError(error) {
  return error instanceof RuleError && ['EXECUTION_TIMEOUT', 'REQUEST_CANCELLED', 'RESOURCE_LIMIT'].includes(error.code);
}

/** @param {unknown} error */
function probeError(error) {
  if (isBudgetError(error)) return error;
  if (error instanceof EchProbeError && error.code === 'LIMIT') return new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
  if (error instanceof EchProbeError && error.code === 'TIMEOUT') {
    return new RuleError('ECH_PROBE_TIMEOUT', 'ECH probe exceeded its time limit.');
  }
  return new RuleError('ECH_PROBE_FAILED', 'ECH probe failed.');
}

/** @param {unknown} error */
function cacheError(error) {
  if (isBudgetError(error)) return error;
  return new RuleError('CACHE_FAILED', 'ECH probe cache operation failed.');
}

/** @param {ValidatedProbeOptions} options */
function identityOptions(options) {
  return {
    hostname: options.hostname,
    port: options.port ?? 443,
    serverName: options.serverName,
    alpn: options.alpn ?? [],
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxBytes: options.maxBytes ?? DEFAULT_MAX_BYTES,
    verifyCertificate: options.verifyCertificate ?? false,
    caCertificates: options.caCertificates?.map(certificate => typeof certificate === 'string'
      ? { pem: certificate }
      : { bytes: Array.from(certificate) }),
    cacheTtl: options.cacheTtl,
  };
}

/** @param {ValidatedProbeOptions} options @param {ReturnType<typeof import('./budget.js').createBudget>} budget */
async function cacheKey(options, budget) {
  try {
    const encoded = new TextEncoder().encode(JSON.stringify(identityOptions(options)));
    const digest = await budget.run(() => crypto.subtle.digest('SHA-256', encoded));
    const hex = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    return new Request(PROBE_CACHE_PREFIX + hex);
  } catch (error) {
    throw cacheError(error);
  }
}

/** @param {ReadableStream<Uint8Array> | null} body */
function cancelBody(body) {
  if (!body) return;
  try { void body.cancel().catch(() => {}); } catch { /* Best effort. */ }
}

/** @param {Request} key @param {number} maxBytes @param {ReturnType<typeof import('./budget.js').createBudget>} budget @param {(state: string) => void} notice */
async function readCached(key, maxBytes, budget, notice) {
  /** @type {Response | undefined} */
  let response;
  try {
    const cache = await budget.run(() => caches.open(PROBE_CACHE_NAME));
    const pending = cache.match(key);
    pending.then(value => { if (budget.signal.aborted) cancelBody(value?.body ?? null); }, () => {});
    response = await budget.run(() => pending);
    if (!response) { notice('miss'); return undefined; }
    const storedAt = Number(response.headers.get(PROBE_CACHE_STORED));
    const validFor = Number(response.headers.get(PROBE_CACHE_TTL));
    const now = Date.now();
    if (!Number.isSafeInteger(storedAt) || storedAt <= 0 || storedAt > now
      || !Number.isInteger(validFor) || validFor <= 0 || validFor > MAX_CACHE_TTL) {
      throw new Error();
    }
    if (Math.floor((now - storedAt) / 1000) >= validFor) { notice('expired'); return undefined; }
    const bytes = await budget.run(() => readBody(response?.body ?? null, maxBytes, budget.signal));
    if (Math.floor((Date.now() - storedAt) / 1000) >= validFor) { notice('expired'); return undefined; }
    try { parseEchConfigList(bytes); }
    catch { throw new Error(); }
    budget.check();
    notice('hit');
    return bytes;
  } catch (error) {
    throw cacheError(error);
  } finally {
    if (response?.body && !response.bodyUsed) cancelBody(response.body);
  }
}

/** @param {Request} key @param {Uint8Array} bytes @param {number} ttl @param {number} storedAt @param {ReturnType<typeof import('./budget.js').createBudget>} budget */
async function writeCached(key, bytes, ttl, storedAt, budget) {
  try {
    const remaining = ttl - Math.max(0, Math.floor((Date.now() - storedAt) / 1000));
    if (remaining <= 0) return;
    const cache = await budget.run(() => caches.open(PROBE_CACHE_NAME));
    const response = new Response(bytes.slice(), { headers: {
      'Content-Type': 'application/octet-stream',
      'Cache-Control': `public, max-age=${remaining}`,
      [PROBE_CACHE_STORED]: String(storedAt),
      [PROBE_CACHE_TTL]: String(ttl),
    } });
    await budget.run(() => cache.put(key, response));
  } catch (error) {
    throw cacheError(error);
  }
}

/**
 * Execute one library probe with the explicitly selected verification policy, consuming the caller's shared network
 * allowance only on a cache miss. The caller's budget signal bounds the whole action.
 * @param {unknown} rawOptions
 * @param {import('../rules/limits.js').Limits & { maxEchProbeTimeoutMs?: number, maxEchProbeBytes?: number }} limits
 * @param {ReturnType<typeof import('./budget.js').createBudget>} budget
 * @param {() => void} spendNetwork
 * @param {(state: string) => void} [notice]
 * @returns {Promise<Uint8Array>} Raw serialized ECHConfigList from the library.
 */
export async function probeEch(rawOptions, limits, budget, spendNetwork, notice = () => {}) {
  const options = validateProbeOptions(rawOptions);
  notice(options.verifyCertificate ? 'verification_enabled' : 'verification_disabled');
  if ((limits.maxEchProbeTimeoutMs !== undefined
      && (typeof limits.maxEchProbeTimeoutMs !== 'number' || !Number.isSafeInteger(limits.maxEchProbeTimeoutMs) || limits.maxEchProbeTimeoutMs < 1))
    || (limits.maxEchProbeBytes !== undefined
      && (typeof limits.maxEchProbeBytes !== 'number' || !Number.isSafeInteger(limits.maxEchProbeBytes) || limits.maxEchProbeBytes < 1024))) {
    throw new RuleError('INVALID_CONFIG', 'Invalid ECH probe resource limits.');
  }
  const overallCap = Number.isSafeInteger(limits?.maxExecutionTimeMs) && limits.maxExecutionTimeMs > 0
    ? limits.maxExecutionTimeMs : MAX_TIMEOUT_MS;
  const actionCap = typeof limits?.maxEchProbeTimeoutMs === 'number' && Number.isSafeInteger(limits.maxEchProbeTimeoutMs) && limits.maxEchProbeTimeoutMs > 0
    ? limits.maxEchProbeTimeoutMs : MAX_TIMEOUT_MS;
  const timeoutCap = Math.min(MAX_TIMEOUT_MS, overallCap, actionCap);
  const timeoutMs = Math.min(options.timeoutMs, timeoutCap);
  const byteCap = typeof limits?.maxEchProbeBytes === 'number' && Number.isSafeInteger(limits.maxEchProbeBytes) && limits.maxEchProbeBytes >= 1024
    ? Math.min(MAX_PROBE_BYTES, limits.maxEchProbeBytes) : MAX_PROBE_BYTES;
  const probeBytes = Math.min(options.maxBytes, byteCap);
  if (probeBytes < 1024) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
  const effectiveOptions = { ...options, timeoutMs, maxBytes: probeBytes };
  const cacheRequest = options.cacheTtl > 0 ? await cacheKey(effectiveOptions, budget) : undefined;
  if (cacheRequest) {
    const cached = await readCached(cacheRequest, probeBytes, budget, notice);
    if (cached) return cached;
  }

  budget.check();
  spendNetwork();
  let result;
  try {
    const common = {
      hostname: options.hostname,
      port: options.port,
      serverName: options.serverName,
      alpn: options.alpn,
      timeoutMs,
      maxBytes: probeBytes,
      signal: budget.signal,
    };
    result = options.verifyCertificate
      ? await libraryProbeEch({
        ...common,
        verifyCertificate: true,
        ...(options.caCertificates === undefined ? {} : { caCertificates: options.caCertificates }),
      })
      : await libraryProbeEch({ ...common, verifyCertificate: false });
    budget.check();
  } catch (error) {
    if (budget.signal.aborted) {
      try { budget.check(); } catch (budgetFailure) { throw budgetFailure; }
    }
    throw probeError(error);
  }

  const bytes = result.bytes;
  try { parseEchConfigList(bytes); }
  catch { throw new RuleError('ECH_INVALID', 'ECH probe returned an invalid ECHConfigList.'); }
  budget.check();
  const storedAt = Date.now();
  if (cacheRequest && options.cacheTtl > 0) await writeCached(cacheRequest, bytes, options.cacheTtl, storedAt, budget);
  notice('acquired');
  return bytes;
}
