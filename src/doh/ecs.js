import { cidr, ip } from '../rules/ip.js';
import { fields } from '../rules/values.js';
import { RuleError } from '../rules/errors.js';
import { decodeEcs, encodeEcs, getEdns, getEcs, setEcs, setEdns, TYPES } from '../../lib/dns-wasm/index.js';

/** @typedef {import('../../lib/dns-wasm/index.js').DnsMessage} Message */

/** Parse, fully validate and resolve the opt-in ECS policy.
 * @param {unknown} raw @param {Record<string, unknown>} env
 * @param {import('../rules/limits.js').Limits} limits
 * @param {ReturnType<typeof import('../rules/config-budget.js').createConfigBudget>} configBudget
 * @param {(name: string) => import('../rules/types.js').ResolvedUpstream | undefined} resolveUpstream
 * @returns {{ mode: 'client'; upstreams: Set<string>; ipv4Prefix: number; ipv6Prefix: number } | { mode: 'fixed'; upstreams: Set<string>; ecs: import('../../lib/dns-wasm/index.js').Ecs } | null}
 */
export function loadEcs(raw, env, limits, configBudget, resolveUpstream) {
  if (raw === undefined || raw === false || raw === 'false') return null;
  try {
    const value = fields(configBudget.parse(raw), ['mode', 'upstreams', 'ipv4Prefix', 'ipv6Prefix', 'subnet']);
    const mode = /** @type {string} */ (value.mode);
    if (!['client', 'fixed'].includes(mode) || !Array.isArray(value.upstreams) || !value.upstreams.length || value.upstreams.length > limits.maxUpstreams) throw new Error();
    /** @type {Set<string>} */
    const upstreams = new Set();
    for (const name of value.upstreams) {
      if (typeof name !== 'string' || upstreams.has(name)) throw new Error();
      if (!resolveUpstream(name)) throw new Error();
      upstreams.add(name);
    }
    if (value.mode === 'client') {
      fields(value, ['mode', 'upstreams', 'ipv4Prefix', 'ipv6Prefix']);
      const rawIpv4Prefix = value.ipv4Prefix === undefined ? 24 : value.ipv4Prefix;
      const rawIpv6Prefix = value.ipv6Prefix === undefined ? 56 : value.ipv6Prefix;
      if (typeof rawIpv4Prefix !== 'number' || !Number.isInteger(rawIpv4Prefix) || rawIpv4Prefix < 0 || rawIpv4Prefix > 24 || typeof rawIpv6Prefix !== 'number' || !Number.isInteger(rawIpv6Prefix) || rawIpv6Prefix < 0 || rawIpv6Prefix > 56) throw new Error();
      return { mode: 'client', upstreams, ipv4Prefix: rawIpv4Prefix, ipv6Prefix: rawIpv6Prefix };
    }
    fields(value, ['mode', 'upstreams', 'subnet']);
    const network = cidr(value.subnet);
    if (network.shift < BigInt(network.family === 32 ? 8 : 72)) throw new Error();
    const width = network.family;
    const prefix = width - Number(network.shift);
    const hostBits = network.network << network.shift;
    const normalizedAddress = network.family === 32
      ? [24n, 16n, 8n, 0n].map(n => Number(hostBits >> n & 255n)).join('.')
      : Array.from({ length: 8 }, (_, i) => Number(hostBits >> BigInt(112 - i * 16) & 65535n).toString(16)).join(':');
    return { mode: 'fixed', upstreams, ecs: { address: normalizedAddress, source_prefix: prefix } };
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('INVALID_CONFIG', 'Invalid ECS configuration.');
  }
}

/** @param {import('../../lib/dns-wasm/index.js').Ecs} decoded @param {number[] | Uint8Array} original */
function canonicalEcs(decoded, original) {
  const encoded = encodeEcs(decoded);
  return encoded.length === original.length && encoded.every((byte, index) => byte === original[index]);
}

/** Reject malformed/duplicate/nonzero-scope request ECS and return its validated identity.
 * @param {Message} query
 */
export function validateIncomingEcs(query) {
  const opt = query.additional.filter(rr => rr.rtype === TYPES.OPT);
  if (opt.length > 1 || opt.some(rr => !('Opt' in rr.rdata))) throw new RuleError('INVALID_QUERY', 'Invalid or unsupported DNS query.');
  const optRdata = opt[0]?.rdata;
  const options = optRdata && 'Opt' in optRdata ? optRdata.Opt.options : [];
  const ecs = options.filter(item => item.code === 8);
  if (ecs.length > 1) throw new RuleError('INVALID_QUERY', 'Invalid or unsupported DNS query.');
  if (!ecs.length) return null;
  try {
    const raw = ecs[0].data;
    const decoded = decodeEcs(raw);
    if (!canonicalEcs(decoded, raw)) throw new Error();
    const address = ip(decoded.address);
    if (decoded.scope_prefix !== 0 || decoded.source_prefix > address.family || decoded.source_prefix % 1) throw new Error();
    return { ...decoded, family: address.family };
  } catch { throw new RuleError('INVALID_QUERY', 'Invalid or unsupported DNS query.'); }
}

/** @param {string} address @param {number} prefix */
function truncate(address, prefix) {
  const parsed = ip(address), shift = BigInt(parsed.family - prefix);
  const bits = (parsed.bits >> shift) << shift;
  const text = parsed.family === 32
    ? [24n, 16n, 8n, 0n].map(n => Number(bits >> n & 255n)).join('.')
    : Array.from({ length: 8 }, (_, i) => Number(bits >> BigInt(112 - i * 16) & 65535n).toString(16)).join(':');
  return { address: text, source_prefix: prefix };
}

/** @param {Message} message */
function ensureEcsOpt(message) {
  if (!message.additional.some(rr => rr.rtype === TYPES.OPT)) setEdns(message, { udp_payload_size: 1232 });
}

/** Apply policy only to a private copy; never widen an incoming ECS disclosure.
 * @param {{ mode: 'client'; upstreams: Set<string>; ipv4Prefix: number; ipv6Prefix: number } | { mode: 'fixed'; upstreams: Set<string>; ecs: import('../../lib/dns-wasm/index.js').Ecs }} policy
 * @param {Message} query
 * @param {(import('../../lib/dns-wasm/index.js').Ecs & { family: number }) | null} incoming
 * @param {string | undefined} clientIp
 * @param {import('../rules/limits.js').Limits} limits
 */
export function outgoingEcs(policy, query, incoming, clientIp, limits) {
  if (!policy) return query;
  const copy = structuredClone(query);
  if (incoming) {
    // An explicit source /0 requests no client identity and is never replaced.
    if (incoming.source_prefix === 0) return copy;
    const maximum = incoming.family === 32 ? (policy.mode === 'client' ? policy.ipv4Prefix : 24) : (policy.mode === 'client' ? policy.ipv6Prefix : 56);
    const prefix = Math.min(incoming.source_prefix, maximum);
    const value = truncate(incoming.address, prefix);
    ensureEcsOpt(copy);
    setEcs(copy, value);
    return copy;
  }
  let selected;
  if (policy.mode === 'fixed') selected = policy.ecs;
  else if (clientIp) {
    const parsed = ip(clientIp), prefix = parsed.family === 32 ? policy.ipv4Prefix : policy.ipv6Prefix;
    if (prefix === 0) return copy;
    selected = truncate(clientIp, prefix);
  }
  if (selected) {
    ensureEcsOpt(copy);
    setEcs(copy, selected);
    if (encodeEcs({ ...selected, scope_prefix: 0 }).byteLength + 11 > limits.maxQueryBytes) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
  }
  return copy;
}

/** Validate upstream ECS identity and remove internal client ECS before client finalization. */
/** @param {Message} response @param {Message} query */
export function checkEcsResponse(response, query) {
  const actualOptions = response.additional.filter(rr => rr.rtype === TYPES.OPT);
  if (actualOptions.length > 1 || actualOptions.some(rr => !('Opt' in rr.rdata))) throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
  const responseOpt = actualOptions[0]?.rdata;
  const options = responseOpt && 'Opt' in responseOpt ? responseOpt.Opt.options : [];
  const ecsOptions = options.filter(option => option.code === 8);
  if (ecsOptions.length > 1) throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
  let actual = null;
  try {
    if (ecsOptions.length) {
      const raw = ecsOptions[0].data;
      actual = decodeEcs(raw);
      if (!canonicalEcs(actual, raw)) throw new Error();
    }
  } catch { throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.'); }
  const expected = getEcs(query);
  if (actual) {
    if (!expected) throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
    const a = ip(actual.address), e = ip(expected.address);
    // RFC 7871 permits scope > source for this client; cache reuse rejects it separately.
    if (a.family !== e.family || actual.source_prefix !== expected.source_prefix || actual.scope_prefix > a.family) throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
    const mask = BigInt(a.family - actual.source_prefix);
    if ((a.bits >> mask) !== (e.bits >> mask)) throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response is invalid.');
  }
  return response;
}

/** @param {Message} response @param {(import('../../lib/dns-wasm/index.js').Ecs & { family: number }) | null} [clientEcs] */
export function stripResponseEcs(response, clientEcs = null) {
  const copy = structuredClone(response);
  const edns = getEdns(copy);
  if (!edns) return copy;
  const opt = copy.additional.find(rr => rr.rtype === TYPES.OPT);
  if (opt && 'Opt' in opt.rdata) {
    const ecsOption = opt.rdata.Opt.options.find(option => option.code === 8);
    opt.rdata.Opt.options = opt.rdata.Opt.options.filter(option => option.code !== 8);
    // Restore the client's exact query identity while retaining only the server's real scope.
    if (clientEcs && ecsOption) {
      const actual = decodeEcs(ecsOption.data);
      setEcs(copy, { address: clientEcs.address, source_prefix: clientEcs.source_prefix, scope_prefix: actual.scope_prefix });
    }
  }
  return copy;
}
