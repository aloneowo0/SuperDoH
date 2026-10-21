import { requestContext } from './doh/metadata.js';
import { executeQuery } from './index.js';
import { loadLimits } from './rules/limits.js';
import { RuleError, createReporter, normalizeFailure } from './rules/errors.js';
import { parseQuery, finalizeResponse } from './doh/protocol.js';
import { createBudget } from './doh/budget.js';
import { readBody } from './doh/body.js';
import { buildResponse, parseMessage } from '../lib/dns-wasm/index.js';

const mediaType = 'application/dns-message';
class HttpError extends Error {
  /** @param {number} status */
  constructor(status) { super('Invalid DoH HTTP request.'); this.status = status; }
}
/** @param {number} status */
function httpError(status) {
  return new Response(status === 404 ? 'Not found.' : 'Invalid DoH request.', {
    status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...(status === 405 ? { Allow: 'GET, POST' } : {}) },
  });
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
/** @param {string | null} accept */
function acceptsDns(accept) {
  if (accept === null) return true;
  let specificity = -1, quality = 0;
  for (const part of accept.split(',')) {
    const [raw, ...params] = part.trim().toLowerCase().split(';');
    const type = raw.trim();
    const rank = type === mediaType ? 2 : type === 'application/*' ? 1 : type === '*/*' ? 0 : -1;
    if (rank < 0) continue;
    const q = params.find(p => p.trim().startsWith('q='));
    const weight = q ? Number(q.trim().slice(2)) : 1;
    if (!Number.isFinite(weight) || weight < 0 || weight > 1) return false;
    if (rank > specificity || (rank === specificity && weight > quality)) { specificity = rank; quality = weight; }
  }
  return quality > 0;
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
  if (!acceptsDns(request.headers.get('Accept'))) throw new HttpError(406);
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
  try {
    const url = new URL(request.url);
    if (!await authorize(url.pathname, env.DNS_PATH_KEY)) {
      report(new RuleError('ACCESS_DENIED', 'The requested endpoint is not available.'));
      return httpError(404);
    }
    report = createReporter(options);
    if (url.protocol !== 'https:') throw new HttpError(400);
    let limits, configFailure;
    try { limits = loadLimits(env.DNS_LIMITS); }
    catch (error) { configFailure = error; limits = loadLimits(undefined); }
    budget = createBudget(limits.maxExecutionTimeMs, options.signal ? AbortSignal.any([request.signal, options.signal]) : request.signal);
    const requestBudget = budget;
    wire = await budget.run(() => inputWire(request, url, limits.maxQueryBytes, requestBudget.signal));
    try { query = parseQuery(wire); }
    catch { throw new HttpError(400); }
    if (configFailure) throw configFailure;
    executionStarted = true;
    const result = await executeQuery(wire, env, { ...options, context: options.context === undefined ? requestContext(request) : options.context, signal: budget.signal });
    executionStarted = false;
    return new Response(result.response, { headers: { 'Content-Type': mediaType, 'Cache-Control': 'no-store' } });
  } catch (error) {
    const failure = error instanceof HttpError ? new RuleError('INVALID_HTTP', 'Invalid DoH HTTP request.') : normalizeFailure(error);
    if (!executionStarted) report(failure);
    if (query && wire) {
      const response = parseMessage(buildResponse(query, { rcode: 2 }));
      return new Response(finalizeResponse(response, query, wire, 512), { headers: { 'Content-Type': mediaType, 'Cache-Control': 'no-store' } });
    }
    return httpError(error instanceof HttpError ? error.status : failure.code === 'EXECUTION_TIMEOUT' || failure.code === 'REQUEST_CANCELLED' ? 408 : 500);
  } finally { budget?.dispose(); }
}

export default {
  /** @param {Request} request @param {Record<string, unknown>} env */
  fetch(request, env) { return handleRequest(request, env); },
};
