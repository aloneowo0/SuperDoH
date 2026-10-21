import { RuleError } from '../rules/errors.js';
import { fields, object, upstreamName } from '../rules/values.js';
import { within } from '../rules/limits.js';
import { loadUpstream } from './upstream.js';

/**
 * @param {Record<string, unknown>} env
 * @param {import('../rules/limits.js').Limits} limits
 * @param {ReturnType<typeof import('../rules/config-budget.js').createConfigBudget>} configBudget
 */
export function loadUpstreams(env, limits, configBudget) {
  try {
    for (const key of ['DNS_UPSTREAM', 'DNS_UPSTREAM_GROUPS', 'DNS_DEFAULT_UPSTREAM_GROUP']) {
      if (Object.hasOwn(env, key)) throw new Error();
    }
    const definitions = env.DNS_UPSTREAMS === undefined ? {} : object(configBudget.parse(env.DNS_UPSTREAMS));
    within(Object.keys(definitions).length, limits.maxUpstreams);
    /** @type {Map<string, string>} */
    const upstreams = new Map();
    for (const [name, raw] of Object.entries(definitions)) {
      upstreamName(name);
      const value = fields(raw, ['transport', 'url', 'urlSecret']);
      if (value.transport !== 'https' || (value.url === undefined) === (value.urlSecret === undefined)) throw new Error();
      let rawUrl = value.url;
      if (value.urlSecret !== undefined) {
        const binding = upstreamName(value.urlSecret);
        if (!Object.hasOwn(env, binding)) throw new Error();
        rawUrl = env[binding];
      }
      const url = loadUpstream(rawUrl);
      if (url === undefined) throw new Error();
      upstreams.set(name, url);
    }
    return {
      /** @param {string} name */
      resolve(name) {
        const url = upstreams.get(name);
        if (!url) throw new RuleError('INVALID_CONFIG', 'Invalid upstream reference.');
        return url;
      },
    };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid upstream configuration.');
  }
}
