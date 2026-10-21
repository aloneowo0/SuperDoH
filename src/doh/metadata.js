import { ip } from '../rules/ip.js';
/** @param {unknown} value @returns {string | undefined} */
function text(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 128 && !/[\x00-\x1f\x7f]/.test(value) ? value : undefined;
}

/** @param {string | null} value */
function address(value) {
  if (value === null) return undefined;
  try { return { value, ...ip(value) }; } catch { return undefined; }
}

/** Only Cloudflare-provided cf metadata, never location/ASN headers.
 * @param {Request} request
 * @returns {import('../rules/types.js').MatchingContext}
 */
export function requestContext(request) {
  const cf = request.cf;
  if (!cf || typeof cf !== 'object') return {};
  /** @type {import('../rules/types.js').NetworkAttributes} */
  const client = {};
  /** @type {import('../rules/types.js').NetworkAttributes} */
  const edge = {};
  if (typeof cf.colo === 'string' && /^[A-Z]{3}$/.test(cf.colo)) edge.colo = cf.colo;
  let source = address(request.headers.get('CF-Connecting-IP'));
  if (request.headers.has('CF-Worker')) return { edge };
  // Overwrite-Headers Pseudo IPv4 preserves the real IPv6 separately. Never use a synthetic Class E identity.
  if (source?.family === 32 && source.bits >= 0xf0000000n) {
    const original = address(request.headers.get('CF-Connecting-IPv6'));
    source = original?.family === 128 ? original : undefined;
  }
  if (source?.key === ip('2a06:98c0:3600::103').key) return { edge };
  if (edge.colo && source) client.ip = source.value;
  if (typeof cf.asn === 'number' && Number.isInteger(cf.asn) && cf.asn > 0 && cf.asn <= 0xffffffff) client.asn = cf.asn;
  if (typeof cf.country === 'string' && /^[A-Z]{2}$/.test(cf.country) && cf.country !== 'XX') client.country = cf.country;
  for (const key of /** @type {const} */ (['region', 'city'])) {
    const value = text(cf[key]);
    if (value !== undefined) client[key] = value;
  }
  return { client, edge };
}
