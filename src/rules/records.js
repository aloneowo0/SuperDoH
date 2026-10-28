import { TYPES } from '../../lib/dns-wasm/index.js';
import { invalidateResponse } from '../doh/protocol.js';
import { RuleError } from './errors.js';
import { within } from './limits.js';
import { recordType, resolveName } from './values.js';
import { recordItem } from './conditions.js';

/** @typedef {Extract<import('./types.js').CompiledAction, { type: 'addRecords' | 'removeRecords' | 'replaceRecords' | 'setTtl' | 'setRecordName' }>} RecordAction */
/** @param {import('../../lib/dns-wasm/index.js').DnsRecord[]} records */
function identities(records) {
  return records.map(({ name, rtype, class: rrclass }) => ({ name, rtype, class: rrclass }));
}
/** @param {import('./types.js').RecordConfig[]} records @param {{ current: { name: string }, original: { name: string } }} context */
export function materializeRecords(records, context) {
  return records.map(({ type, ...rr }) => ({ ...structuredClone(rr), name: resolveName(rr.name, context), class: rr.class ?? 1, rtype: recordType(type) }));
}
/** @param {import('./types.js').RecordSection | undefined} section @returns {'answers' | 'authority' | 'additional'} */
function sectionKey(section) {
  return section === 'additional' ? 'additional' : section === 'authority' ? 'authority' : 'answers';
}
/** @param {import('../../lib/dns-wasm/index.js').DnsMessage} response */
function sections(response) {
  return /** @type {const} */ ([['answer', response.answers], ['authority', response.authority], ['additional', response.additional]]);
}
/** @param {import('../../lib/dns-wasm/index.js').DnsMessage} response @param {import('./limits.js').Limits} limits @param {import('./errors.js').Location} location */
function countRecords(response, limits, location) {
  within(response.answers.length + response.authority.length + response.additional.length, limits.maxRecords, location);
}
/** Edits only the caller's candidate; the executor owns validation and commit/rollback.
 * @param {RecordAction} action
 * @param {import('./conditions.js').MatchContext} context
 * @param {import('./limits.js').Limits} limits
 * @param {import('./errors.js').Location} location
 */
export async function editRecords(action, context, limits, location) {
  const response = context.response;
  if (!response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
  if (action.type === 'removeRecords' || action.type === 'replaceRecords') {
    /** @type {Set<import('../../lib/dns-wasm/index.js').DnsRecord>} */
    const removed = new Set();
    for (const [section, records] of sections(response)) {
      for (const rr of records) {
        context.spend();
        if (action.selector && await action.selector({ ...context, item: recordItem(rr, section) })) {
          if ([TYPES.OPT, TYPES.RRSIG, TYPES.TSIG, 24].includes(rr.rtype)) throw new RuleError('INVALID_STATE', 'Protected DNS records cannot be edited.', location);
          removed.add(rr);
        }
      }
    }
    for (const [, records] of sections(response)) {
      for (let i = records.length - 1; i >= 0; i--) if (removed.has(records[i])) records.splice(i, 1);
    }
    const changed = identities(Array.from(removed));
    if (removed.size && action.type === 'replaceRecords') {
      const added = materializeRecords(action.records, context);
      response[sectionKey(action.section)].push(...added);
      changed.push(...identities(added));
      countRecords(response, limits, location);
    }
    return changed.length ? invalidateResponse(response, changed) : response;
  }
  if (action.type === 'addRecords') {
    const added = materializeRecords(action.records, context);
    response[sectionKey(action.section)].push(...added);
    countRecords(response, limits, location);
    return added.length ? invalidateResponse(response, identities(added)) : response;
  }
  /** @type {import('../../lib/dns-wasm/index.js').DnsQuestion[]} */
  const changed = [];
  if (action.type === 'setRecordName') {
    const name = resolveName(action.name, context);
    for (const [section, records] of sections(response)) {
      for (const rr of records) {
        context.spend();
        if (!action.selector || !await action.selector({ ...context, item: recordItem(rr, section) })) continue;
        if ([TYPES.OPT, TYPES.RRSIG, TYPES.TSIG, 24].includes(rr.rtype)) throw new RuleError('INVALID_STATE', 'Protected DNS records cannot be edited.', location);
        if (rr.name === name) continue;
        changed.push({ name: rr.name, rtype: rr.rtype, class: rr.class }, { name, rtype: rr.rtype, class: rr.class });
        rr.name = name;
      }
    }
    return changed.length ? invalidateResponse(response, changed) : response;
  }
  for (const [section, records] of sections(response)) {
    for (const rr of records) {
      if (action.selector) context.spend();
      if ([TYPES.OPT, TYPES.RRSIG, TYPES.TSIG, 24].includes(rr.rtype) || rr.ttl === action.ttl) continue;
      if (action.selector && !await action.selector({ ...context, item: recordItem(rr, section) })) continue;
      changed.push({ name: rr.name, rtype: rr.rtype, class: rr.class });
      rr.ttl = action.ttl;
    }
  }
  return changed.length ? invalidateResponse(response, changed) : response;
}
