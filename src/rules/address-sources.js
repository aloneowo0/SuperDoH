import { RuleError } from './errors.js';
import { within } from './limits.js';
import { fields, object, integer, upstreamName } from './values.js';

const sourceFields = ['url', 'urlSecret', 'ipParam', 'params', 'fields', 'cacheTtl'];
const mappedFields = ['ip', 'asn', 'country', 'region', 'city'];
const MAX_PATH_DEPTH = 16;
const MAX_PATH_SEGMENT_LENGTH = 128;
const MAX_PARAMS = 64;
const MAX_PARAM_NAME_LENGTH = 128;
const MAX_PARAM_VALUE_LENGTH = 2048;

/** @param {unknown} raw @returns {string[]} */
function path(raw) {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_PATH_DEPTH) throw new Error();
  return raw.map(segment => {
    if (typeof segment !== 'string' || segment.length === 0 || segment.length > MAX_PATH_SEGMENT_LENGTH || /[\x00-\x1f\x7f]/.test(segment)) throw new Error();
    return segment;
  });
}

/** @param {unknown} raw @returns {Record<string, string>} */
function params(raw) {
  if (raw === undefined) return {};
  const input = object(raw);
  const entries = Object.entries(input);
  if (entries.length > MAX_PARAMS) throw new Error();
  /** @type {Record<string, string>} */
  const result = Object.create(null);
  for (const [name, value] of entries) {
    if (!name || name.length > MAX_PARAM_NAME_LENGTH || /[\x00-\x1f\x7f]/.test(name)
      || typeof value !== 'string' || value.length > MAX_PARAM_VALUE_LENGTH || /[\x00-\x1f\x7f]/.test(value)) throw new Error();
    result[name] = value;
  }
  return result;
}

/** @param {unknown} raw @returns {Record<string, string[] | undefined>} */
function fieldPaths(raw) {
  const input = fields(raw, mappedFields);
  if (input.ip === undefined) throw new Error();
  const result = /** @type {Record<string, string[] | undefined>} */ ({});
  for (const key of mappedFields) if (input[key] !== undefined) result[key] = path(input[key]);
  if (!['asn', 'country', 'region', 'city'].some(key => result[key] !== undefined)) throw new Error();
  return result;
}

/** @param {unknown} raw @returns {string} */
function httpsUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048 || raw.includes('#')) throw new Error();
  const parsed = new URL(raw);
  if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '' || parsed.hash !== '') throw new Error();
  return raw;
}

/**
 * Load and validate named HTTPS address-attribution sources from trusted bindings.
 * @param {Record<string, unknown>} env
 * @param {import('./limits.js').Limits} limits
 * @param {ReturnType<typeof import('./config-budget.js').createConfigBudget>} configBudget
 * @returns {{ resolve(name: string): AddressSource }}
 */
export function loadAddressSources(env, limits, configBudget) {
  try {
    const definitions = env.DNS_ADDRESS_SOURCES === undefined ? {} : object(configBudget.parse(env.DNS_ADDRESS_SOURCES));
    const entries = Object.entries(definitions);
    within(entries.length, limits.maxAddressSources);
    /** @type {Map<string, AddressSource>} */
    const sources = new Map();
    for (const [name, raw] of entries) {
      upstreamName(name);
      const value = fields(raw, sourceFields);
      const hasUrl = value.url !== undefined;
      const hasSecret = value.urlSecret !== undefined;
      if (hasUrl === hasSecret) throw new Error();
      let rawUrl = value.url;
      if (hasSecret) {
        const binding = upstreamName(value.urlSecret);
        if (!Object.hasOwn(env, binding)) throw new Error();
        rawUrl = env[binding];
      }
      const url = httpsUrl(rawUrl);
      if (typeof value.ipParam !== 'string' || value.ipParam.length === 0 || value.ipParam.length > MAX_PARAM_NAME_LENGTH || /[\x00-\x1f\x7f]/.test(value.ipParam)) throw new Error();
      const query = new URL(url).searchParams;
      if (query.has(value.ipParam)) throw new Error();
      const staticParams = params(value.params);
      if (Object.hasOwn(staticParams, value.ipParam)) throw new Error();
      const fieldsConfig = fieldPaths(value.fields);
      const cacheTtl = value.cacheTtl === undefined ? 0 : integer(value.cacheTtl, 86400);
      sources.set(name, { name, url, ipParam: value.ipParam, params: staticParams, fields: fieldsConfig, cacheTtl });
    }
    return {
      /** @param {string} name */
      resolve(name) {
        const source = sources.get(name);
        if (!source) throw new RuleError('INVALID_CONFIG', 'Invalid address source reference.');
        return source;
      },
    };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid address source configuration.');
  }
}

/** @typedef {{ name: string, url: string, ipParam: string, params: Record<string, string>, fields: Record<string, string[] | undefined>, cacheTtl: number }} AddressSource */
