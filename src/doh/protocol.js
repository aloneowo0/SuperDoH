import { parseMessage, encodeResponse, normalizeMessage, TYPES, FLAGS, getEdns } from '../../lib/dns-wasm/index.js';
import { domain } from '../rules/values.js';
import { RuleError } from '../rules/errors.js';

/** @param {Uint8Array} wire */
export function parseQuery(wire) {
  const parsed = parseMessage(wire);
  const edns = getEdns(parsed);
  if (edns && (edns.version !== 0 || edns.extended_rcode !== 0)) throw new Error();
  if (parsed.is_response || parsed.opcode !== 0 || parsed.truncated || parsed.rcode !== 0 || parsed.questions.length !== 1 || parsed.answers.length || parsed.authority.length || parsed.additional.some(rr => rr.rtype !== TYPES.OPT)) throw new Error();
  domain(parsed.questions[0].name);
  return parsed;
}
/**
 * @param {import('../../lib/dns-wasm/index.js').DnsMessage} response
 * @param {import('../../lib/dns-wasm/index.js').DnsMessage} original
 * @param {Uint8Array} originalWire
 * @param {number} maximum
 * @param {import('../rules/errors.js').Location} [location]
 */
export function finalizeResponse(response, original, originalWire, maximum, location = {}) {
  // Encoding only reads records; isolate the envelope fields that are rewritten.
  const output = { ...response };
  output.id = original.id;
  output.questions = original.questions.map(q => ({ ...q }));
  output.flags = (output.flags & ~(FLAGS.RD | FLAGS.CD)) | (original.flags & (FLAGS.RD | FLAGS.CD));
  const wire = encodeResponse(output, originalWire, maximum);
  if (wire === null) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.', location);
  return wire;
}
/**
 * @param {import('../../lib/dns-wasm/index.js').DnsMessage} response
 * @param {import('../../lib/dns-wasm/index.js').DnsQuestion[]} [rrsets]
 */
export function invalidateResponse(response, rrsets) {
  const output = { ...response, answers: [...response.answers], authority: [...response.authority], additional: [...response.additional] };
  output.flags &= ~FLAGS.AD;
  for (const records of [output.answers, output.authority, output.additional]) {
    for (let i = records.length - 1; i >= 0; i--) {
      if ((!rrsets && records[i].rtype === TYPES.RRSIG) || records[i].rtype === 24 || records[i].rtype === TYPES.TSIG) records.splice(i, 1);
    }
  }
  return normalizeMessage(output, { strip_message_authentication: true, ...(rrsets ? { invalidate_rrsets: rrsets } : {}) });
}
