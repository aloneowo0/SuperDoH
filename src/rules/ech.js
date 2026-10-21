import {
  buildQuery, encodeMessage, getRcode, getSvcParam, parseMessage, setSvcParam,
  TYPES,
} from '../../lib/dns-wasm/index.js';
import { parseEchConfigList } from '../../lib/ech-probe/config.js';
import { invalidateResponse } from '../doh/protocol.js';
import { cachePolicy } from './cache-policy.js';
import { recordItem } from './conditions.js';
import { RuleError } from './errors.js';
import { within } from './limits.js';
import { domain, fields, upstreamName } from './values.js';

const ECH_PARAM = 5;
const DNS_CLASS_IN = 1;

/** @typedef {import('../../lib/dns-wasm/index.js').DnsMessage} DnsMessage */
/** @typedef {import('../../lib/dns-wasm/index.js').DnsRecord} DnsRecord */
/** @typedef {import('./errors.js').Location} Location */
/** @typedef {{ bytes: Uint8Array, base64: string, source: 'direct' | 'https' | 'probe' }} EchCandidate */
/** @typedef {{ type: 'loadEch', config: string, onError?: 'fail' | 'continue' }} LoadEchAction */
/** @typedef {{ type: 'applyEch', where?: import('./types.js').RecordCondition, selector?: import('./conditions.js').Predicate, onError?: 'fail' | 'continue' }} ApplyEchAction */
/** @typedef {{ type: 'queryEch', name: string, upstream: string, cache?: Partial<import('./types.js').CachePolicy>, onError?: 'fail' | 'continue' }} QueryEchAction */

/** @param {unknown} value */
function invalidConfig(value) {
  try {
    return fields(value, ['type', 'config', 'where', 'name', 'upstream', 'cache', 'onError']);
  } catch {
    throw new RuleError('INVALID_CONFIG', 'Invalid or unsupported ECH action configuration.');
  }
}

/**
 * Validate and normalize ECH-specific action JSON. A caller-supplied selectorCompiler
 * should be the existing rule-condition compiler for `where` on applyEch actions.
 * @param {unknown} value
 * @param {(where: unknown) => import('./conditions.js').Predicate} [selectorCompiler]
 * @returns {LoadEchAction | ApplyEchAction | QueryEchAction}
 */
export function validateEchAction(value, selectorCompiler) {
  const v = invalidConfig(value);
  try {
    if (v.onError !== undefined && v.onError !== 'fail' && v.onError !== 'continue') throw new Error();
    const onError = /** @type {'fail' | 'continue' | undefined} */ (v.onError);
    if (v.type === 'loadEch') {
      fields(v, ['type', 'config', 'onError']);
      if (typeof v.config !== 'string') throw new Error();
      // Validate the bytes now, not later during a partially executed ruleset.
      const candidate = directEch(v.config);
      return { type: 'loadEch', config: candidate.base64, ...(onError ? { onError } : {}) };
    }
    if (v.type === 'applyEch') {
      fields(v, ['type', 'where', 'onError']);
      if (v.where === undefined) return { type: 'applyEch', ...(onError ? { onError } : {}) };
      if (!selectorCompiler) throw new Error();
      const action = /** @type {ApplyEchAction} */ ({ type: 'applyEch', where: v.where, selector: selectorCompiler(v.where), ...(onError ? { onError } : {}) });
      return action;
    }
    if (v.type === 'queryEch') {
      fields(v, ['type', 'name', 'upstream', 'cache', 'onError']);
      const name = domain(v.name);
      const upstream = upstreamName(v.upstream);
      const cache = v.cache === undefined ? undefined : cachePolicy(v.cache);
      return { type: 'queryEch', name, upstream, ...(cache ? { cache } : {}), ...(onError ? { onError } : {}) };
    }
    throw new Error();
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid or unsupported ECH action configuration.');
  }
}

/** @param {string} value @returns {Uint8Array} */
function decodeBase64(value) {
  // Require canonical, padded RFC 4648 Base64; atob alone accepts non-canonical input.
  if (value.length === 0 || value.length > 87384 || value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new RuleError('INVALID_ECH_CONFIG', 'ECHConfigList must be valid standard Base64.');
  }
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
    if (bytes.length > 65537) throw new Error();
    return bytes;
  } catch {
    throw new RuleError('INVALID_ECH_CONFIG', 'ECHConfigList must be valid standard Base64.');
  }
}

/**
 * Validate a directly configured ECHConfigList. Parsing is structural only and does
 * not authenticate the source or imply server acceptance.
 * @param {string} config
 * @returns {EchCandidate}
 */
export function directEch(config) {
  if (typeof config !== 'string') throw new RuleError('INVALID_ECH_CONFIG', 'ECHConfigList must be valid standard Base64.');
  const bytes = decodeBase64(config);
  try {
    const parsed = parseEchConfigList(bytes);
    if (parsed.base64 !== config) throw new Error();
    return { bytes: parsed.bytes.slice(), base64: parsed.base64, source: 'direct' };
  } catch {
    throw new RuleError('INVALID_ECH_CONFIG', 'ECHConfigList is structurally invalid.');
  }
}

/** @param {string} name */
function normalizedName(name) {
  return domain(name === '' ? '.' : name);
}

/**
 * Extract one unambiguous ECHConfigList from an independently obtained HTTPS answer.
 * Only a successful, complete type-65 answer for `sourceName` is eligible.
 * @param {DnsMessage | Uint8Array | ArrayBuffer} response
 * @param {string} sourceName
 * @returns {EchCandidate}
 */
export function extractEch(response, sourceName) {
  let message;
  try {
    message = response instanceof Uint8Array || response instanceof ArrayBuffer ? parseMessage(response) : response;
    const source = domain(sourceName);
    if (!message || !Array.isArray(message.questions) || !Array.isArray(message.answers) ||
        !(message.flags & 0x8000) || (message.flags & 0x0200) !== 0 || getRcode(message) !== 0 ||
        message.questions.length !== 1 || message.questions[0].rtype !== TYPES.HTTPS ||
        message.questions[0].class !== DNS_CLASS_IN || normalizedName(message.questions[0].name) !== source) {
      throw new Error();
    }
    /** @type {Map<string, EchCandidate>} */
    const candidates = new Map();
    for (const rr of message.answers) {
      if (rr.rtype !== TYPES.HTTPS || rr.class !== DNS_CLASS_IN || normalizedName(rr.name) !== source ||
          !rr.rdata || !('Https' in rr.rdata) || rr.rdata.Https.priority === 0) continue;
      const encoded = getSvcParam(rr, ECH_PARAM);
      if (encoded === undefined) continue;
      if (typeof encoded !== 'string') throw new Error();
      const candidate = directEch(encoded);
      candidates.set(candidate.base64, { ...candidate, source: 'https' });
    }
    if (candidates.size === 0) throw new RuleError('NO_ECH_CONFIG', 'No qualifying HTTPS ServiceMode record contains ECH.');
    if (candidates.size > 1) throw new RuleError('AMBIGUOUS_ECH_CONFIG', 'HTTPS ServiceMode records contain distinct ECH configurations.');
    return /** @type {EchCandidate} */ (candidates.values().next().value);
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_ECH_SOURCE', 'HTTPS response is not a valid ECH source answer.');
  }
}

/**
 * Execute an explicit DNS HTTPS lookup through the caller's existing named-upstream
 * transport. The callback signature mirrors the upstream transport query/policy/source
 * arguments; the caller resolves `action.upstream` to its configured transport target.
 * @param {QueryEchAction} action
 * @param {(upstreamName: string, query: DnsMessage, policy: import('./types.js').CachePolicy, sourceName: string) => Promise<DnsMessage>} transport
 * @param {import('./types.js').CachePolicy} [basePolicy]
 * @returns {Promise<EchCandidate>}
 */
export async function queryEch(action, transport, basePolicy = { read: true, write: true, maxTtl: 300 }) {
  const checked = /** @type {QueryEchAction} */ (validateEchAction(action));
  const query = parseMessage(buildQuery(checked.name, TYPES.HTTPS));
  const policy = { ...basePolicy, ...checked.cache };
  const response = await transport(checked.upstream, query, policy, checked.upstream);
  return extractEch(response, checked.name);
}

/** @param {DnsRecord} record */
function isServiceModeHttps(record) {
  return record.rtype === TYPES.HTTPS && !!record.rdata && 'Https' in record.rdata && record.rdata.Https.priority !== 0;
}

/** @param {DnsMessage} message */
function recordCount(message) {
  return message.answers.length + message.authority.length + message.additional.length;
}

/**
 * Apply an acquired ECHConfigList to selected existing answer-section HTTPS
 * ServiceMode records. This helper returns an isolated DNS candidate and never edits
 * the caller's response or source bytes.
 * @param {ApplyEchAction} action
 * @param {import('./conditions.js').MatchContext} context
 * @param {Uint8Array | ArrayBuffer | readonly number[] | EchCandidate} bytes
 * @param {import('./limits.js').Limits} limits
 * @param {Location} [location]
 * @returns {Promise<DnsMessage>}
 */
export async function applyEch(action, context, bytes, limits, location = {}) {
  if (!context.response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
  const candidate = typeof bytes === 'object' && bytes !== null && 'bytes' in bytes
    ? directEch(/** @type {EchCandidate} */ (bytes).base64)
    : directEch(encodeBase64(bytes));
  const response = structuredClone(context.response);
  /** @type {import('../../lib/dns-wasm/index.js').DnsQuestion[]} */
  const changed = [];
  let selected = 0;
  for (const rr of response.answers) {
    context.spend();
    if (!isServiceModeHttps(rr)) continue;
    if (action.selector && !await action.selector({ ...context, response, item: recordItem(rr, 'answer') })) continue;
    selected++;
    const old = getSvcParam(rr, ECH_PARAM);
    if (old === candidate.base64) continue;
    setSvcParam(rr, ECH_PARAM, candidate.base64);
    changed.push({ name: rr.name, rtype: rr.rtype, class: rr.class });
  }
  if (!selected) throw new RuleError('NO_ECH_RECORD', 'No selected HTTPS ServiceMode answer record exists.', location);
  if (changed.length) {
    within(recordCount(response), limits.maxRecords, location);
    const invalidated = invalidateResponse(response, changed);
    const wire = encodeMessage(invalidated);
    within(wire.byteLength, limits.maxResponseBytes, location);
    return invalidated;
  }
  within(recordCount(response), limits.maxRecords, location);
  within(encodeMessage(response).byteLength, limits.maxResponseBytes, location);
  return response;
}

/** @param {Uint8Array | ArrayBuffer | readonly number[] | EchCandidate} input @returns {string} */
function encodeBase64(input) {
  if (typeof input === 'object' && input !== null && 'bytes' in input) return /** @type {EchCandidate} */ (input).base64;
  let data;
  if (input instanceof ArrayBuffer) data = new Uint8Array(input);
  else if (ArrayBuffer.isView(input)) data = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  else if (Array.isArray(input) && input.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) data = Uint8Array.from(input);
  else throw new RuleError('INVALID_ECH_CONFIG', 'ECHConfigList bytes are invalid.');
  let binary = '';
  for (let offset = 0; offset < data.length; offset += 0x8000) {
    binary += String.fromCharCode(...data.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}
