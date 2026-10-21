import { getRcode } from '../../lib/dns-wasm/index.js';
import { RuleError, normalizeFailure } from '../rules/errors.js';
import { fields, object } from '../rules/values.js';
import { within } from '../rules/limits.js';
import { compileCondition } from '../rules/conditions.js';
import { loadUpstream } from './upstream.js';

/** @typedef {{ index: number, urls: string[], accept?: import('../rules/conditions.js').Predicate }} CompiledUpstreamGroup */

/** @param {unknown} value @returns {string} */
function upstreamName(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value)) throw new Error();
  return value;
}
/**
 * @param {Record<string, unknown>} env
 * @param {import('../rules/limits.js').Limits} limits
 * @param {ReturnType<typeof import('../rules/config-budget.js').createConfigBudget>} configBudget
 */
export function loadUpstreamGroups(env, limits, configBudget) {
  try {
    const legacy = loadUpstream(env.DNS_UPSTREAM);
    const upstreams = new Map();
    const definitions = env.DNS_UPSTREAMS === undefined ? {} : object(configBudget.parse(env.DNS_UPSTREAMS));
    within(Object.keys(definitions).length, limits.maxUpstreams);
    for (const [key, raw] of Object.entries(definitions)) {
      upstreamName(key);
      const v = fields(raw, ['url', 'urlSecret']);
      if ((v.url === undefined) === (v.urlSecret === undefined)) throw new Error();
      let rawUrl = v.url;
      if (v.urlSecret !== undefined) {
        const binding = upstreamName(v.urlSecret);
        if (!Object.hasOwn(env, binding)) throw new Error();
        rawUrl = env[binding];
      }
      const url = loadUpstream(rawUrl);
      if (url === undefined) throw new Error();
      upstreams.set(key, url);
    }
    /** @type {Map<string, CompiledUpstreamGroup>} */
    const groups = new Map();
    const rawGroups = env.DNS_UPSTREAM_GROUPS === undefined ? {} : object(configBudget.parse(env.DNS_UPSTREAM_GROUPS));
    within(Object.keys(rawGroups).length, limits.maxUpstreamGroups);
    let members = 0;
    for (const [key, raw] of Object.entries(rawGroups)) {
      upstreamName(key);
      const v = fields(raw, ['members', 'accept']);
      if (!Array.isArray(v.members) || !v.members.length) throw new Error();
      within(members += v.members.length, limits.maxUpstreamMembers);
      const urls = v.members.map(value => {
        const url = upstreams.get(upstreamName(value));
        if (!url) throw new Error();
        return url;
      });
      const accept = v.accept === undefined ? undefined : compileCondition(v.accept, configBudget.node, limits, configBudget.pattern);
      groups.set(key, { index: groups.size, urls, accept });
    }
    const defaultGroup = env.DNS_DEFAULT_UPSTREAM_GROUP === undefined ? undefined : upstreamName(env.DNS_DEFAULT_UPSTREAM_GROUP);
    if (defaultGroup !== undefined && (!groups.has(defaultGroup) || legacy !== undefined)) throw new Error();
    return {
      hasDefault: legacy !== undefined || defaultGroup !== undefined,
      /** @param {string | undefined} group */
      resolve(group) {
        const selected = group ?? defaultGroup;
        if (selected === undefined) return legacy === undefined ? undefined : { index: -1, urls: [legacy], accept: undefined };
        const result = groups.get(selected);
        if (!result) throw new RuleError('INVALID_CONFIG', 'Invalid upstream group reference.');
        return result;
      },
    };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid upstream group configuration.');
  }
}

/**
 * @param {CompiledUpstreamGroup | undefined} group
 * @param {import('../../lib/dns-wasm/index.js').DnsMessage} query
 * @param {ReturnType<typeof import('./upstream.js').createUpstream>} transport
 * @param {(condition: import('../rules/conditions.js').Predicate, response: import('../../lib/dns-wasm/index.js').DnsMessage) => Promise<boolean>} accepts
 * @param {(error: RuleError, memberIndex: number, disposition: 'fallback' | 'exhausted' | 'terminated') => void} failed
 * @param {() => void} check
 */
export async function queryGroup(group, query, transport, accepts, failed, check) {
  if (!group) throw new RuleError('NO_UPSTREAM', 'No DNS upstream is configured.');
  let last = new RuleError('UPSTREAM_FAILED', 'DNS upstream request failed.');
  for (const [index, url] of group.urls.entries()) {
    check();
    let response;
    try { response = await transport(url, query); }
    catch (error) {
      const safe = normalizeFailure(error);
      last = safe;
      const terminal = !['UPSTREAM_TIMEOUT', 'UPSTREAM_FAILED', 'UPSTREAM_INVALID'].includes(safe.code);
      failed(safe, index, terminal ? 'terminated' : index + 1 < group.urls.length ? 'fallback' : 'exhausted');
      if (terminal) throw safe;
      continue;
    }
    let accepted;
    try {
      accepted = group.accept ? await accepts(group.accept, response) : [0, 3].includes(getRcode(response));
      check();
    } catch (error) {
      const safe = normalizeFailure(error);
      failed(safe, index, 'terminated');
      throw safe;
    }
    if (accepted) return response;
    failed(new RuleError('UPSTREAM_REJECTED', 'DNS upstream response did not meet the adoption condition.'), index, index + 1 < group.urls.length ? 'fallback' : 'exhausted');
  }
  // Keep the legacy single-upstream failure contract for callers without a named group.
  if (group.index === -1) throw last;
  throw new RuleError('UPSTREAM_EXHAUSTED', 'No member of the DNS upstream group produced an acceptable response.');
}
