import { domain, recordType } from './config.js';

/**
 * @param {import('./types.js').Condition | undefined} condition
 * @param {import('../../lib/dns-wasm/index.js').DnsQuestion} current
 * @param {Readonly<import('../../lib/dns-wasm/index.js').DnsQuestion>} original
 * @param {import('../../lib/dns-wasm/index.js').DnsMessage | null} response
 * @returns {boolean}
 */
export function matches(condition, current, original, response) {
  if (!condition) return true;
  if ('all' in condition) return condition.all.every(c => matches(c, current, original, response));
  if ('any' in condition) return condition.any.some(c => matches(c, current, original, response));
  if ('not' in condition) return !matches(condition.not, current, original, response);
  if (condition.field === 'response.exists') return (response !== null) === condition.value;
  if (condition.field === 'response.rcode') return response !== null && (response.flags & 15) === condition.value;
  const question = condition.field.startsWith('original.') ? original : current;
  if (condition.field.endsWith('.type')) return question.rtype === recordType(condition.value);
  const name = domain(question.name);
  const value = domain(condition.value);
  const subdomain = value === '.' ? name !== '.' : name.endsWith(`.${value}`);
  return condition.op === 'exact' ? name === value : condition.op === 'suffix' ? name === value || subdomain : subdomain;
}
