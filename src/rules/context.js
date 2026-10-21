import { within } from './limits.js';
import { fields, integer, object } from './values.js';
import { ip } from './ip.js';
import { RuleError } from './errors.js';

/** @param {unknown} value @returns {import('./types.js').NetworkAttributes} */
function attributes(value) {
  const source = fields(value, ['ip', 'asn', 'country', 'region', 'city', 'colo']);
  /** @type {import('./types.js').NetworkAttributes} */
  const result = {};
  if (source.ip !== undefined) { ip(source.ip); result.ip = /** @type {string} */ (source.ip); }
  if (source.asn !== undefined) result.asn = integer(source.asn, 0xffffffff);
  for (const key of /** @type {const} */ (['country', 'region', 'city', 'colo'])) {
    if (source[key] === undefined) continue;
    const text = source[key];
    if (typeof text !== 'string' || !text.length || text.length > 128 || /[\x00-\x1f\x7f]/.test(text)) throw new Error();
    result[key] = text;
  }
  return result;
}
/** @param {unknown} raw @param {import('./limits.js').Limits} limits */
export function loadContext(raw, limits) {
  try {
    const value = raw === undefined ? {} : fields(raw, ['client', 'edge', 'addresses']);
    /** @type {Map<string, import('./types.js').NetworkAttributes>} */
    const addresses = new Map();
    /** @type {NonNullable<import('./types.js').MatchingContext['addresses']>} */
    const snapshotAddresses = {};
    if (value.addresses !== undefined) {
      const entries = Object.entries(object(value.addresses));
      within(entries.length, limits.maxContextAddresses);
      for (const [address, rawAttributes] of entries) {
        const key = ip(address).key;
        if (addresses.has(key)) throw new Error();
        fields(rawAttributes, ['asn', 'country', 'region', 'city']);
        const attrs = attributes(rawAttributes);
        addresses.set(key, attrs);
        snapshotAddresses[address] = attrs;
      }
    }
    const client = value.client === undefined ? {} : attributes(value.client);
    const edge = value.edge === undefined ? {} : attributes(value.edge);
    return { addresses, client, edge, snapshot: { client, edge, addresses: snapshotAddresses } };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONTEXT', 'Invalid matching context.');
  }
}
