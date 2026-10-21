import { fields, integer } from './values.js';
import { RuleError } from './errors.js';

/** @param {unknown} raw @returns {Partial<import('./types.js').CachePolicy>} */
export function cachePolicy(raw) {
  const value = fields(raw, ['read', 'write', 'maxTtl']);
  /** @type {Partial<import('./types.js').CachePolicy>} */
  const policy = {};
  for (const key of /** @type {const} */ (['read', 'write'])) {
    if (value[key] !== undefined) {
      if (typeof value[key] !== 'boolean') throw new Error();
      policy[key] = value[key];
    }
  }
  if (value.maxTtl !== undefined) policy.maxTtl = integer(value.maxTtl, 86400);
  return policy;
}

/** @param {unknown} raw @param {ReturnType<typeof import('./config-budget.js').createConfigBudget>} configBudget @returns {import('./types.js').CachePolicy} */
export function loadCachePolicy(raw, configBudget) {
  try {
    return { read: true, write: true, maxTtl: 300, ...(raw === undefined ? {} : cachePolicy(configBudget.parse(raw))) };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid DNS cache policy.');
  }
}
