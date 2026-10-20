import { loadLimits, within } from './rules/limits.js';
import { RuleError, createReporter, normalizeFailure } from './rules/errors.js';
export { RuleError } from './rules/errors.js';
import { loadGroups, recordType, domain } from './rules/config.js';
import { matches } from './rules/conditions.js';
import { buildResponse, parseMessage, encodeMessage, matchResponse, TYPES, FLAGS, getEdns } from '../lib/dns-wasm/index.js';

/** @template T @param {T} value @returns {T} */
function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/**
 * Validate a response without changing live action state.
 * @param {import('../lib/dns-wasm/index.js').DnsMessage} response
 * @param {import('../lib/dns-wasm/index.js').ParsedMessage} original
 * @param {Uint8Array} originalWire
 * @param {number} maximum
 * @param {import('./rules/errors.js').Location} location
 */
function responseWire(response, original, originalWire, maximum, location) {
  const output = structuredClone(response);
  output.id = original.id;
  output.questions = original.questions.map(q => ({ ...q }));
  output.flags = (output.flags & ~(FLAGS.AD | FLAGS.RD | FLAGS.CD)) | (original.flags & (FLAGS.RD | FLAGS.CD));
  const wire = encodeMessage(output);
  within(wire.byteLength, maximum, location);
  matchResponse(wire, originalWire);
  return wire;
}
/** @param {unknown} error @param {import('./rules/errors.js').Location} location */
function failureAt(error, location) {
  return normalizeFailure(error, location);
}
/**
 * Execute environment rules without network access.
 * @param {Uint8Array} queryWire
 * @param {Record<string, unknown>} env
 * @param {import('./rules/types.js').ExecutionOptions} [options]
 * @returns {import('./rules/types.js').ExecutionResult}
 */
export function executeQuery(queryWire, env, options = {}) {
  const report = createReporter(options);
  /** @type {import('./rules/types.js').Action['type'] | undefined} */
  let actionType;
  /** @type {import('./rules/errors.js').Location} */
  const location = {};
  try {
    const limits = loadLimits(env.DNS_LIMITS);
    within(queryWire.byteLength, limits.maxQueryBytes);
    const originalWire = queryWire.slice();
    let parsed;
    try {
      parsed = parseMessage(originalWire);
      const edns = getEdns(parsed);
      if (edns && (edns.version !== 0 || edns.extended_rcode !== 0)) throw new Error();
      if (parsed.is_response || parsed.opcode !== 0 || parsed.truncated || parsed.rcode !== 0 || parsed.questions.length !== 1 || parsed.answers.length || parsed.authority.length || parsed.additional.some(rr => rr.rtype !== TYPES.OPT)) throw new Error();
      domain(parsed.questions[0].name);
    } catch {
      throw new RuleError('INVALID_QUERY', 'Invalid or unsupported DNS query.');
    }
    const originalQuery = freeze(parsed);
    /** @type {{ query: import('../lib/dns-wasm/index.js').DnsMessage, response: import('../lib/dns-wasm/index.js').DnsMessage | null }} */
    let state = { query: structuredClone(originalQuery), response: null };
    const groups = loadGroups(env, limits);
    /** @type {'completed' | 'stopped' | 'returned'} */
    let termination = 'completed';
    pipeline: for (const group of groups) {
      location.group = group.name;
      for (const [ruleIndex, rule] of group.rules.entries()) {
        location.rule = ruleIndex;
        delete location.action;
        actionType = undefined;
        if (!matches(rule.when, state.query.questions[0], originalQuery.questions[0], state.response)) continue;
        for (const [actionIndex, action] of rule.actions.entries()) {
          location.action = actionIndex;
          actionType = action.type;
          try {
            if (action.type === 'stop' || action.type === 'return') {
              if (action.type === 'return' && !state.response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
              termination = action.type === 'stop' ? 'stopped' : 'returned';
              break pipeline;
            }
            const candidate = structuredClone(state);
            if (action.type === 'answer') {
              candidate.response = parseMessage(buildResponse(candidate.query, { rcode: action.rcode ?? 0, answers: action.records.map(({ type, ...rr }) => ({ ...rr, class: rr.class ?? 1, rtype: recordType(type) })) }));
            } else if (action.type === 'setTtl') {
              if (!candidate.response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
              for (const records of [candidate.response.answers, candidate.response.authority, candidate.response.additional]) {
                for (const rr of records) if (rr.rtype !== TYPES.OPT) rr.ttl = action.ttl;
              }
            } else if (action.type === 'rewriteQuery') {
              if (action.name !== undefined) candidate.query.questions[0].name = action.name;
              if (action.queryType !== undefined) candidate.query.questions[0].rtype = recordType(action.queryType);
              within(encodeMessage(candidate.query).byteLength, limits.maxQueryBytes, location);
            }
            if (action.type !== 'rewriteQuery' && candidate.response) {
              responseWire(candidate.response, originalQuery, originalWire, limits.maxResponseBytes, location);
            }
            state = candidate;
          } catch (error) {
            const failure = failureAt(error, location);
            if (action.onError !== 'continue') throw failure;
            // Discard candidate state; earlier successful actions remain committed.
            report(failure, action.type, true);
          }
        }
      }
    }
    const wire = state.response ? responseWire(state.response, originalQuery, originalWire, limits.maxResponseBytes, location) : null;
    return { termination, response: wire, originalQuery, query: state.query };
  } catch (error) {
    const failure = failureAt(error, location);
    report(failure, actionType);
    throw failure;
  }
}
