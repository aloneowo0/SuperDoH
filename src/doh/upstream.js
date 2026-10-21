import { encodeMessage, getEdns, matchResponse, parseMessage } from '../../lib/dns-wasm/index.js';
import { RuleError } from '../rules/errors.js';
import { createBudget } from './budget.js';
import { readBody } from './body.js';

/** @param {unknown} raw @returns {string | undefined} */
export function loadUpstream(raw) {
  if (raw === undefined) return undefined;
  try {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048 || raw.includes('#')) throw new Error();
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '' || parsed.hash !== '') throw new Error();
    return raw;
  } catch {
    throw new RuleError('INVALID_CONFIG', 'Invalid upstream configuration.');
  }
}

/** @param {unknown} error @returns {boolean} */
function isBudgetError(error) {
  return error instanceof RuleError && ['EXECUTION_TIMEOUT', 'UPSTREAM_TIMEOUT', 'REQUEST_CANCELLED'].includes(error.code);
}

/** @param {ReadableStream<Uint8Array> | null} body */
function cancelBody(body) {
  if (!body) return;
  try { void body.cancel().catch(() => {}); } catch { /* Best-effort cleanup. */ }
}

/**
 * @param {import('../rules/limits.js').Limits & { maxNetworkRequests: number, upstreamTimeoutMs: number }} limits
 * @param {ReturnType<typeof createBudget>} budget
 * @returns {(url: string | undefined, query: import('../../lib/dns-wasm/index.js').DnsMessage) => Promise<import('../../lib/dns-wasm/index.js').DnsMessage>}
 */
export function createUpstream(limits, budget) {
  let attempts = 0;
  return async function upstream(url, query) {
    budget.check();
    if (!url) throw new RuleError('NO_UPSTREAM', 'No DNS upstream is configured.');

    let queryWire;
    try {
      queryWire = encodeMessage(query);
      if (queryWire.byteLength > limits.maxQueryBytes) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
    } catch (error) {
      if (error instanceof RuleError) throw error;
      throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream query is invalid.');
    }

    const child = createBudget(limits.upstreamTimeoutMs, budget.signal, 'UPSTREAM_TIMEOUT');
    /** @type {Response | undefined} */
    let response;
    let bodyConsumed = false;
    try {
      const request = new Request(url, {
        method: 'POST',
        headers: { Accept: 'application/dns-message', 'Content-Type': 'application/dns-message' },
        body: queryWire,
        redirect: 'manual',
        signal: child.signal,
      });
      if (attempts >= limits.maxNetworkRequests) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
      attempts += 1;
      const responsePromise = fetch(request);
      // If fetch resolves after the budget has already won its race, promptly drain/cancel it.
      responsePromise.then(value => {
        if (child.signal.aborted) cancelBody(value.body);
      }, () => {});
      try {
        response = await child.run(() => responsePromise);
      } catch (error) {
        if (isBudgetError(error)) throw error;
        throw new RuleError('UPSTREAM_FAILED', 'The DNS upstream request failed.');
      }

      child.check();
      if (!response.ok || response.redirected || (response.status >= 300 && response.status < 400)) {
        cancelBody(response.body);
        throw new RuleError('UPSTREAM_FAILED', 'The DNS upstream request failed.');
      }
      const contentType = response.headers.get('content-type');
      if (typeof contentType !== 'string' || contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/dns-message') {
        cancelBody(response.body);
        throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
      }
      const contentLength = response.headers.get('content-length');
      if (contentLength !== null && /^[0-9]+$/.test(contentLength.trim())) {
        const declaredLength = Number(contentLength.trim());
        if (declaredLength > limits.maxResponseBytes) {
          cancelBody(response.body);
          throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
        }
      }

      let responseWire;
      try {
        responseWire = await child.run(() => readBody(response?.body ?? null, limits.maxResponseBytes, child.signal));
        bodyConsumed = true;
      } catch (error) {
        if (error instanceof RuleError && (error.code === 'RESOURCE_LIMIT' || isBudgetError(error))) throw error;
        throw new RuleError('UPSTREAM_FAILED', 'The DNS upstream request failed.');
      }
      child.check();

      let parsed;
      try {
        matchResponse(responseWire, queryWire);
        parsed = parseMessage(responseWire);
        const edns = getEdns(parsed);
        if (edns && edns.version !== 0) throw new Error();
      } catch {
        throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
      }
      const recordCount = parsed.answers.length + parsed.authority.length + parsed.additional.length;
      if (recordCount > limits.maxRecords) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');

      try {
        return parseMessage(encodeMessage(parsed, { strip_message_authentication: true }));
      } catch {
        throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
      }
    } catch (error) {
      if (error instanceof RuleError) throw error;
      throw new RuleError('UPSTREAM_FAILED', 'The DNS upstream request failed.');
    } finally {
      if (response && !bodyConsumed) cancelBody(response.body);
      child.dispose();
    }
  };
}
