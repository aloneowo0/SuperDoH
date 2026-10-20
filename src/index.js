import { loadLimits, within } from './rules/limits.js';
import { RuleError } from './rules/errors.js';
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
 * Execute environment rules without network access.
 * @param {Uint8Array} queryWire
 * @param {Record<string, unknown>} env
 * @returns {import('./rules/types.js').ExecutionResult}
 */
export function executeQuery(queryWire, env) {
  const limits = loadLimits(env.DNS_LIMITS);
  within(queryWire.byteLength, limits.maxQueryBytes);
  let parsed;
  try {
    parsed = parseMessage(queryWire);
    const edns = getEdns(parsed);
    if (edns && (edns.version !== 0 || edns.extended_rcode !== 0)) throw new Error();
    if (parsed.is_response || parsed.opcode !== 0 || parsed.truncated || parsed.rcode !== 0 || parsed.questions.length !== 1 || parsed.answers.length || parsed.authority.length || parsed.additional.some(rr => rr.rtype !== TYPES.OPT)) throw new Error();
    domain(parsed.questions[0].name);
  } catch {
    throw new RuleError('INVALID_QUERY', 'Invalid or unsupported DNS query.');
  }
  const originalQuery = freeze(parsed);
  const query = structuredClone(originalQuery);
  /** @type {import('../lib/dns-wasm/index.js').DnsMessage | null} */
  let response = null;
  const groups = loadGroups(env, limits);
  /** @type {'completed' | 'stopped' | 'returned'} */
  let termination = 'completed';
  /** @type {import('./rules/errors.js').Location} */
  const location = {};
  pipeline: for (const group of groups) {
    location.group = group.name;
    for (const [ruleIndex, rule] of group.rules.entries()) {
      location.rule = ruleIndex;
      if (!matches(rule.when, query.questions[0], originalQuery.questions[0], response)) continue;
      for (const [actionIndex, action] of rule.actions.entries()) {
        location.action = actionIndex;
        if (action.type === 'stop' || action.type === 'return') {
          if (action.type === 'return' && !response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
          termination = action.type === 'stop' ? 'stopped' : 'returned';
          break pipeline;
        }
        if (action.type === 'answer') {
          response = parseMessage(buildResponse(query, { rcode: action.rcode ?? 0, answers: action.records.map(({ type, ...rr }) => ({ ...rr, class: rr.class ?? 1, rtype: recordType(type) })) }));
        } else if (action.type === 'setTtl') {
          if (!response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
          for (const records of [response.answers, response.authority, response.additional]) {
            for (const rr of records) if (rr.rtype !== TYPES.OPT) rr.ttl = action.ttl;
          }
        } else if (action.type === 'rewriteQuery') {
          if (action.name !== undefined) query.questions[0].name = action.name;
          if (action.queryType !== undefined) query.questions[0].rtype = recordType(action.queryType);
        }
      }
    }
  }
  let wire = null;
  if (response) {
    response.id = originalQuery.id;
    response.questions = originalQuery.questions.map(q => ({ ...q }));
    response.flags = (response.flags & ~(FLAGS.AD | FLAGS.RD | FLAGS.CD)) | (originalQuery.flags & (FLAGS.RD | FLAGS.CD));
    wire = encodeMessage(response);
    within(wire.byteLength, limits.maxResponseBytes);
    matchResponse(wire, queryWire);
  }
  return { termination, response: wire, originalQuery, query };
}
