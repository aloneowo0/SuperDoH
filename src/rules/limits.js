import { RuleError } from './errors.js';

const defaults = Object.freeze({
  maxQueryBytes: 4096, maxResponseBytes: 16384, maxGroupBytes: 5120, maxConfigBytes: 65536,
  maxGroups: 32, maxRules: 256, maxActions: 1024, maxRecords: 256, maxConditionNodes: 1024,
});
const ceilings = Object.freeze({
  maxQueryBytes: 65535, maxResponseBytes: 65535, maxGroupBytes: 65536, maxConfigBytes: 262144,
  maxGroups: 64, maxRules: 8192, maxActions: 32768, maxRecords: 4096, maxConditionNodes: 8192,
});
/** @typedef {{ -readonly [K in keyof typeof defaults]: number }} Limits */
/** @param {unknown} raw @returns {Limits} */
export function loadLimits(raw) {
  if (raw === undefined) return { ...defaults };
  try {
    if (typeof raw === 'string' && raw.length > 4096) throw new Error();
    const value = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    /** @type {Limits} */
    const limits = { ...defaults };
    for (const [key, item] of Object.entries(value)) {
      if (!Object.hasOwn(defaults, key)) throw new Error();
      const name = /** @type {keyof Limits} */ (key);
      if (!Number.isSafeInteger(item) || item < 1 || item > ceilings[name]) throw new Error();
      limits[name] = item;
    }
    return limits;
  } catch {
    throw new RuleError('INVALID_CONFIG', 'Invalid resource limit configuration.');
  }
}
/** @param {number} actual @param {number} maximum @param {import('./errors.js').Location} [location] */
export function within(actual, maximum, location) {
  if (actual > maximum) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.', location);
}
