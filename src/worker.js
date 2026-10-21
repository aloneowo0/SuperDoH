import { requestContext } from './doh/metadata.js';
import { executeQuery } from './index.js';
import { loadLimits } from './rules/limits.js';
import { RuleError, createReporter, normalizeFailure } from './rules/errors.js';
import { parseQuery, finalizeResponse } from './doh/protocol.js';
import { createBudget } from './doh/budget.js';
import { readBody } from './doh/body.js';
import { buildQuery, buildResponse, parseMessage, toDnsJson, typeCode, FLAGS } from '../lib/dns-wasm/index.js';

const mediaType = 'application/dns-message';
const jsonMediaType = 'application/dns-json';
class HttpError extends Error {
  /** @param {number} status @param {string} [code] @param {string} [message] */
  constructor(status, code = `HTTP_${status}`, message = 'Invalid JSON DNS query.') { super(message); this.status = status; this.code = code; }
}
/** @param {number} status @param {boolean} [json] @param {string} [code] @param {string} [message] */
function httpError(status, json = false, code = `HTTP_${status}`, message = 'Invalid DoH HTTP request.') {
  const headers = new Headers({ 'Cache-Control': 'no-store', ...(status === 405 ? { Allow: json ? 'GET' : 'GET, POST' } : {}) });
  if (json) {
    headers.set('Content-Type', jsonMediaType);
    return new Response(JSON.stringify({ error: { code, message } }), { status, headers });
  }
  headers.set('Content-Type', 'text/plain; charset=utf-8');
  return new Response(status === 404 ? 'Not found.' : 'Invalid DoH request.', { status, headers });
}
/** @param {unknown} value @returns {boolean} */
function jsonEnabled(value) {
  if (value === undefined || value === false || value === 'false') return false;
  if (value === true || value === 'true') return true;
  throw new RuleError('INVALID_CONFIG', 'Invalid DNS JSON configuration.');
}
/** @param {string | null} accept @param {string} expected */
function acceptsType(accept, expected) {
  if (accept === null) return true;
  let specificity = -1, quality = 0;
  for (const part of accept.split(',')) {
    const [raw, ...params] = part.trim().toLowerCase().split(';');
    const type = raw.trim();
    const rank = type === expected ? 2 : type === 'application/*' ? 1 : type === '*/*' ? 0 : -1;
    if (rank < 0) continue;
    const q = params.find(p => p.trim().startsWith('q='));
    const weight = q ? Number(q.trim().slice(2)) : 1;
    if (!Number.isFinite(weight) || weight < 0 || weight > 1) return false;
    if (rank > specificity || (rank === specificity && weight > quality)) { specificity = rank; quality = weight; }
  }
  return quality > 0;
}
/** @param {Request} request @param {URL} url */
function jsonIntent(request, url) {
  // Detect named parameters on any method so a POST cannot smuggle a JSON query into
  // the wire-format path; Accept-only detection is limited to GET to preserve POST.
  if (['name', 'type', 'cd'].some(name => url.searchParams.has(name))) return true;
  if (request.method !== 'GET') return false;
  const accept = request.headers.get('Accept');
  return !!accept && accept.split(',').some(part => part.split(';', 1)[0].trim().toLowerCase() === jsonMediaType) &&
    !url.searchParams.has('dns');
}
/** @param {URL} url @param {number} maximum @param {string | null} accept */
function jsonQueryWire(url, maximum, accept) {
  if (url.search.length > Math.min(2048, Math.ceil(maximum * 4 / 3) + 16)) throw new HttpError(414, 'URI_TOO_LONG', 'DNS JSON query parameters exceed the allowed size.');
  if (!acceptsType(accept, jsonMediaType)) throw new HttpError(406, 'NOT_ACCEPTABLE', 'The requested JSON response format is not acceptable.');
  const entries = [...url.searchParams];
  if (entries.some(([key]) => !['name', 'type', 'cd'].includes(key))) throw new HttpError(400, 'INVALID_PARAMETER', 'Unknown DNS JSON query parameter.');
  const values = new Map();
  for (const [key, value] of entries) {
    if (values.has(key)) throw new HttpError(400, 'DUPLICATE_PARAMETER', 'Duplicate DNS JSON query parameter.');
    values.set(key, value);
  }
  const name = values.get('name');
  if (typeof name !== 'string' || name.length === 0 || name.length > 254) throw new HttpError(400, 'INVALID_NAME', 'A valid DNS name is required.');
  let type = 1;
  if (values.has('type')) {
    const value = values.get('type');
    if (/^\d+$/.test(value)) {
      type = Number(value);
      if (!Number.isSafeInteger(type) || type > 65535) throw new HttpError(400, 'INVALID_TYPE', 'DNS type must be a valid decimal code or type name.');
    } else {
      try { type = typeCode(value); }
      catch { throw new HttpError(400, 'INVALID_TYPE', 'DNS type must be a valid decimal code or type name.'); }
    }
  }
  let cd = false;
  if (values.has('cd')) {
    const value = values.get('cd');
    if (value !== 'true' && value !== 'false') throw new HttpError(400, 'INVALID_PARAMETER', 'The cd parameter must be true or false.');
    cd = value === 'true';
  }
  try {
    const normalized = name.toLowerCase();
    const wire = buildQuery(normalized, type, 0, { flags: FLAGS.RD | (cd ? FLAGS.CD : 0) });
    if (wire.byteLength > maximum) throw new HttpError(414, 'URI_TOO_LONG', 'DNS JSON query exceeds the configured query size.');
    return wire;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, 'INVALID_NAME', 'DNS JSON query name or type is invalid.');
  }
}
/** @param {Uint8Array} wire */
function jsonDnsResponse(wire) {
  return new Response(JSON.stringify(toDnsJson(wire)), { headers: { 'Content-Type': jsonMediaType, 'Cache-Control': 'no-store' } });
}

/** @param {string} pathname @param {unknown} key */
async function authorize(pathname, key) {
  if (key === undefined) return pathname === '/dns-query';
  if (typeof key !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(key)) throw new RuleError('INVALID_CONFIG', 'Invalid access configuration.');
  if (pathname.length > 256) return false;
  const encoder = new TextEncoder();
  const [actual, expected] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(pathname)),
    crypto.subtle.digest('SHA-256', encoder.encode('/' + key + '/dns-query')),
  ]);
  return crypto.subtle.timingSafeEqual(actual, expected);
}
/** @param {string} value @param {number} maximum */
function decodeGet(value, maximum) {
  if (value.length > Math.ceil(maximum * 4 / 3)) throw new HttpError(414);
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new HttpError(400);
  let binary;
  try { binary = atob(value.replace(/-/g, '+').replace(/_/g, '/')); }
  catch { throw new HttpError(400); }
  if (btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') !== value) throw new HttpError(400);
  const result = Uint8Array.from(binary, c => c.charCodeAt(0));
  if (result.byteLength > maximum) throw new HttpError(414);
  return result;
}
/** @param {Request} request @param {URL} url @param {number} maximum @param {AbortSignal} signal */
async function inputWire(request, url, maximum, signal) {
  if (request.method !== 'GET' && request.method !== 'POST') throw new HttpError(405);
  if (!acceptsType(request.headers.get('Accept'), mediaType)) throw new HttpError(406);
  if (request.method === 'GET') {
    if (url.search.length > Math.ceil(maximum * 4 / 3) + 5) throw new HttpError(414);
    const values = [...url.searchParams];
    if (values.length !== 1 || values[0][0] !== 'dns') throw new HttpError(400);
    return decodeGet(values[0][1], maximum);
  }
  if (url.search) throw new HttpError(400);
  if (request.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase() !== mediaType) throw new HttpError(415);
  const length = request.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maximum)) throw new HttpError(413);
  try { return await readBody(request.body, maximum, signal); }
  catch (error) {
    if (error instanceof RuleError && error.code === 'RESOURCE_LIMIT') throw new HttpError(413);
    if (signal.aborted) throw new HttpError(408);
    throw new HttpError(400);
  }
}
/**
 * The standard DoH boundary. Options are supplied only by trusted application code.
 * @param {Request} request
 * @param {Record<string, unknown>} env
 * @param {import('./rules/types.js').ExecutionOptions} [options]
 */
export async function handleRequest(request, env, options = {}) {
  let report = createReporter({});
  /** @type {ReturnType<typeof createBudget> | undefined} */
  let budget;
  /** @type {Uint8Array | undefined} */
  let wire;
  /** @type {ReturnType<typeof parseQuery> | undefined} */
  let query;
  let executionStarted = false;
  let jsonRequest = false;
  try {
    const url = new URL(request.url);
    if (!await authorize(url.pathname, env.DNS_PATH_KEY)) {
      report(new RuleError('ACCESS_DENIED', 'The requested endpoint is not available.'));
      return httpError(404, jsonRequest, 'ACCESS_DENIED', 'The requested endpoint is not available.');
    }
    report = createReporter(options);
    jsonRequest = jsonIntent(request, url);
    const jsonIsEnabled = jsonEnabled(env.DNS_JSON);
    if (jsonRequest && !jsonIsEnabled) return httpError(404, true, 'JSON_DISABLED', 'DNS JSON queries are disabled.');
    if (url.protocol !== 'https:') throw new HttpError(400, 'INVALID_HTTP', 'HTTPS is required.');
    let limits, configFailure;
    try { limits = loadLimits(env.DNS_LIMITS); }
    catch (error) { configFailure = error; limits = loadLimits(undefined); }
    budget = createBudget(limits.maxExecutionTimeMs, options.signal ? AbortSignal.any([request.signal, options.signal]) : request.signal);
    const requestBudget = budget;
    wire = await budget.run(() => {
      if (jsonRequest) {
        if (request.method !== 'GET') throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'DNS JSON queries require GET.');
        return jsonQueryWire(url, limits.maxQueryBytes, request.headers.get('Accept'));
      }
      return inputWire(request, url, limits.maxQueryBytes, requestBudget.signal);
    });
    try { query = parseQuery(wire); }
    catch { throw new HttpError(400, 'INVALID_DNS_QUERY', 'The DNS query is invalid.'); }
    if (configFailure) throw configFailure;
    executionStarted = true;
    const result = await executeQuery(wire, env, { ...options, context: options.context === undefined ? requestContext(request) : options.context, signal: budget.signal });
    executionStarted = false;
    return jsonRequest
      ? jsonDnsResponse(result.response)
      : new Response(result.response, { headers: { 'Content-Type': mediaType, 'Cache-Control': 'no-store' } });
  } catch (error) {
    const failure = error instanceof HttpError
      ? new RuleError('INVALID_HTTP', 'Invalid DoH HTTP request.')
      : normalizeFailure(error);
    if (!executionStarted) report(failure);
    if (query && wire) {
      const response = parseMessage(buildResponse(query, { rcode: 2 }));
      const failWire = finalizeResponse(response, query, wire, 512);
      return jsonRequest
        ? jsonDnsResponse(failWire)
        : new Response(failWire, { headers: { 'Content-Type': mediaType, 'Cache-Control': 'no-store' } });
    }
    const status = error instanceof HttpError ? error.status : failure.code === 'EXECUTION_TIMEOUT' || failure.code === 'REQUEST_CANCELLED' ? 408 : 500;
    return httpError(status, jsonRequest, error instanceof HttpError ? error.code : failure.code,
      error instanceof HttpError ? error.message : failure.message);
  } finally { budget?.dispose(); }
}

export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  fetch(request, env) { return handleRequest(request, env); },
};
