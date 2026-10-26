import { RuleError } from '../rules/errors.js';
import { fields, object, upstreamName } from '../rules/values.js';
import { within } from '../rules/limits.js';
import { loadUpstream } from './upstream.js';
import { ip } from '../rules/ip.js';

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
    /** @type {Map<string, import('../rules/types.js').ResolvedUpstream>} */
    const upstreams = new Map();
    for (const [name, raw] of Object.entries(definitions)) {
      upstreamName(name);
      const value = fields(raw, ['transport', 'url', 'urlSecret', 'address', 'port']);
      if (value.transport === 'tcp') {
        if (value.url !== undefined || value.urlSecret !== undefined) throw new Error();
        const address = value.address;
        if (typeof address !== 'string' || address.length === 0 || address.length > 253) throw new Error();
        if (address.includes(':') || /^[0-9.]+$/.test(address)) ip(address);
        else if (address.replace(/\.$/, '').split('.').some(label => !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))) throw new Error();
        const port = value.port === undefined ? 53 : value.port;
        if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error();
        upstreams.set(name, { transport: 'tcp', address, port });
        continue;
      }
      if (value.address !== undefined || value.port !== undefined) throw new Error();
      if (value.transport !== 'https' || (value.url === undefined) === (value.urlSecret === undefined)) throw new Error();
      let rawUrl = value.url;
      if (value.urlSecret !== undefined) {
        const binding = upstreamName(value.urlSecret);
        if (!Object.hasOwn(env, binding)) throw new Error();
        rawUrl = env[binding];
      }
      const url = loadUpstream(rawUrl);
      if (url === undefined) throw new Error();
      upstreams.set(name, { transport: 'https', url });
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
