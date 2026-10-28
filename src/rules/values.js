import { typeCode } from '../../lib/dns-wasm/index.js';

/** @param {unknown} value @returns {Record<string, unknown>} */
export function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  return /** @type {Record<string, unknown>} */ (value);
}
/** @param {unknown} value @param {string[]} allowed @returns {Record<string, unknown>} */
export function fields(value, allowed) {
  const result = object(value);
  if (Object.keys(result).some(key => !allowed.includes(key))) throw new Error();
  return result;
}
/** @param {unknown} value @param {number} max @returns {number} */
export function integer(value, max) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > max) throw new Error();
  return value;
}
/** @param {unknown} value @returns {number} */
export function recordType(value) {
  return integer(typeof value === 'string' ? typeCode(value) : value, 65535);
}
/** @param {unknown} value @returns {string} */
export function domain(value) {
  if (typeof value !== 'string' || value.length > 254) throw new Error();
  const normalized = value.replace(/\.$/, '').toLowerCase();
  if (value === '.') return '.';
  if (!normalized || normalized.length > 253 || normalized.split('.').some(label => !/^[a-z0-9_-]{1,63}$/.test(label))) throw new Error();
  return normalized;
}

/** @param {unknown} value @returns {import('./types.js').NameValue} */
export function nameValue(value) {
  if (typeof value === 'string') return domain(value);
  const ref = fields(value, ['from']);
  if (ref.from !== 'original.name' && ref.from !== 'query.name') throw new Error();
  return { from: ref.from };
}
/** @param {import('./types.js').NameValue} value @param {{ current: { name: string }, original: { name: string } }} context */
export function resolveName(value, context) {
  return typeof value === 'string' ? value : domain(value.from === 'original.name' ? context.original.name : context.current.name);
}

/** @param {unknown} value @returns {string} */
export function upstreamName(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value)) throw new Error();
  return value;
}
