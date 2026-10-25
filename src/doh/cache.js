import { encodeMessage, encodeResponse, parseMessage, getRcode, TYPES } from '../../lib/dns-wasm/index.js';
import { RuleError } from '../rules/errors.js';
import { readBody } from './body.js';

/** @typedef {import('../../lib/dns-wasm/index.js').DnsMessage} Message */

/** Only stateless EDNS or validated ECS is reusable; exact query bytes remain in the key. @param {Message} message @param {boolean} [isQuery] */
export function reusable(message, isQuery = false) {
  if (isQuery && [41, 249, 250, 251, 252, 253, 254, 255].includes(message.questions[0].rtype)) return false;
  for (const rr of [...message.answers, ...message.authority, ...message.additional]) {
    if (rr.rtype === TYPES.TSIG || rr.rtype === 24) return false;
    if (rr.rtype !== TYPES.OPT) continue;
    if (!('Opt' in rr.rdata)) return false;
    if (rr.rdata.Opt.options.length > 1) return false;
    for (const option of rr.rdata.Opt.options) {
      if (option.code !== 8) return false;
      const bytes = Uint8Array.from(option.data);
      if (bytes.length < 4) return false;
      const family = bytes[0] * 256 + bytes[1], source = bytes[2], scope = bytes[3];
      if (![1, 2].includes(family) || source > (family === 1 ? 32 : 128) || scope > source || (isQuery && scope !== 0) || bytes.length !== 4 + Math.ceil(source / 8)) return false;
      if (source % 8 && (bytes[bytes.length - 1] & ((1 << (8 - source % 8)) - 1))) return false;
    }
  }
  return true;
}

/** @param {Message} message */
function ecs(message) {
  const opt = message.additional.find(rr => rr.rtype === TYPES.OPT);
  return opt && 'Opt' in opt.rdata ? opt.rdata.Opt.options.find(option => option.code === 8)?.data : undefined;
}

/** @param {Message} query @param {Message} response */
export function reusableResponse(query, response) {
  if (!reusable(response)) return false;
  const actual = ecs(response), expected = ecs(query);
  if (!actual) return true;
  if (!expected || expected.length !== actual.length) return false;
  return Array.from(actual).every((byte, index) => index === 3 || byte === expected[index]);
}

/** @param {Message} message */
function records(message) {
  return [...message.answers, ...message.authority, ...message.additional].filter(rr => rr.rtype !== TYPES.OPT);
}

/** @param {Message} message */
export function normalizeNegative(message) {
  if (getRcode(message) === 3 || (getRcode(message) === 0 && !message.answers.length)) {
    for (const rr of message.authority) if (rr.rtype === TYPES.SOA && 'Soa' in rr.rdata) rr.ttl = rr.ttl > 0x7fffffff ? 0 : Math.min(rr.ttl, rr.rdata.Soa.minimum);
  }
  return message;
}

/** @param {Message} message @param {number} seconds */
export function ageMessage(message, seconds) {
  for (const rr of records(message)) rr.ttl = rr.ttl > 0x7fffffff ? 0 : Math.max(0, rr.ttl - seconds);
  return message;
}

/** Safe whole-message lifetime; never retain only part of a response. @param {Message} message */
function lifetime(message) {
  if (!reusable(message) || message.flags & 0x0200 || ![0, 3].includes(getRcode(message))) return 0;
  const all = records(message);
  if (!all.length || all.some(rr => rr.ttl > 0x7fffffff)) return 0;
  let ttl = Math.min(...all.map(rr => rr.ttl));
  if (getRcode(message) === 3 || !message.answers.length) {
    const soa = message.authority.find(rr => rr.rtype === TYPES.SOA && rr.class === message.questions[0].class && 'Soa' in rr.rdata);
    if (!soa || !('Soa' in soa.rdata)) return 0;
    const name = message.questions[0].name.replace(/[.]$/, '').toLowerCase();
    const zone = soa.name.replace(/[.]$/, '').toLowerCase();
    if (zone && name !== zone && !name.endsWith('.' + zone)) return 0;
    ttl = Math.min(ttl, soa.rdata.Soa.minimum);
  }
  const now = Math.floor(Date.now() / 1000);
  for (const rr of all) {
    if (rr.rtype === TYPES.TSIG || rr.rtype === 24) return 0;
    if (rr.rtype === TYPES.RRSIG) {
      if (!('Rrsig' in rr.rdata)) return 0;
      const sig = rr.rdata.Rrsig;
      if (sig.inception > now || sig.expiration <= now) return 0;
      ttl = Math.min(ttl, sig.original_ttl, sig.expiration - now);
    }
  }
  return ttl;
}

/** @param {import('../rules/types.js').ResolvedUpstream} target @param {Message} query @param {string} sourceName */
export async function cacheKey(target, query, sourceName) {
  const wire = encodeMessage(query);
  wire[0] = 0; wire[1] = 0;
  const identity = new TextEncoder().encode(JSON.stringify([sourceName, target]));
  const bytes = new Uint8Array(identity.length + 1 + wire.length);
  bytes.set(identity); bytes.set(wire, identity.length + 1);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return new Request('https://superdoh-cache.invalid/v1/' + Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join(''));
}

/** @param {Request} key @param {Message} query @param {number} maxTtl @param {import('../rules/limits.js').Limits} limits @param {ReturnType<typeof import('./budget.js').createBudget>} budget */
export async function readCache(key, query, maxTtl, limits, budget) {
  try {
    const cache = await budget.run(() => caches.open('superdoh-original-v1'));
    const pending = cache.match(key);
    pending.then(value => {
      if (budget.signal.aborted) { try { void value?.body?.cancel().catch(() => {}); } catch { /* Best effort. */ } }
    }, () => {});
    const response = await budget.run(() => pending);
    if (!response) return undefined;
    const stored = Number(response.headers.get('x-dns-stored'));
    const validFor = Number(response.headers.get('x-dns-lifetime'));
    let elapsed = Math.max(0, Math.floor((Date.now() - stored) / 1000));
    if (!Number.isFinite(stored) || stored > Date.now() || !Number.isInteger(validFor) || validFor <= 0 || elapsed >= Math.min(validFor, maxTtl)) {
      try { void response.body?.cancel().catch(() => {}); } catch { /* Best effort. */ }
      return undefined;
    }
    const wire = await readBody(response.body, limits.maxResponseBytes, budget.signal);
    elapsed = Math.max(0, Math.floor((Date.now() - stored) / 1000));
    if (stored > Date.now() || elapsed >= Math.min(validFor, maxTtl)) return undefined;
    budget.check();
    const message = parseMessage(wire);
    message.id = query.id;
    const checkedWire = encodeResponse(message, encodeMessage(query), 65535, {});
    if (checkedWire === null) throw new Error('cached response exceeds maximum DNS message size');
    message.questions = structuredClone(query.questions);
    if (message.answers.length + message.authority.length + message.additional.length > limits.maxRecords) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
    ageMessage(message, elapsed);
    return lifetime(message) > 0 ? message : undefined;
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('CACHE_FAILED', 'DNS cache operation failed.');
  }
}

/** @param {Request} key @param {Message} message @param {number} maxTtl @param {number} receivedAt @param {ReturnType<typeof import('./budget.js').createBudget>} budget */
export async function writeCache(key, message, maxTtl, receivedAt, budget) {
  const ttl = Math.min(maxTtl, lifetime(message));
  if (ttl <= 0) return;
  try {
    const cache = await budget.run(() => caches.open('superdoh-original-v1'));
    const remaining = ttl - Math.max(0, Math.floor((Date.now() - receivedAt) / 1000));
    if (remaining <= 0) return;
    const response = new Response(encodeMessage(message), { headers: {
      'Content-Type': 'application/dns-message', 'Cache-Control': `public, max-age=${remaining}`,
      'x-dns-stored': String(receivedAt), 'x-dns-lifetime': String(ttl),
    } });
    await budget.run(() => cache.put(key, response));
  } catch (error) {
    if (error instanceof RuleError) throw error;
    throw new RuleError('CACHE_FAILED', 'DNS cache operation failed.');
  }
}

/** @param {Headers} headers */
export function httpFreshness(headers) {
  const rawAge = headers.get('age');
  const age = rawAge === null ? 0 : /^[0-9]+$/.test(rawAge.trim()) ? Number(rawAge.trim()) : Infinity;
  let cap = Infinity;
  if (headers.has('set-cookie') || headers.has('vary')) cap = 0;
  for (const raw of (headers.get('cache-control') ?? '').split(',')) {
    const directive = raw.trim().toLowerCase();
    if (/^(no-store|no-cache|private)(?:$|\s*=)/.test(directive)) cap = 0;
    if (/^(s-maxage|max-age)\s*=/.test(directive)) {
      const match = /^(?:s-maxage|max-age)\s*=\s*"?([0-9]+)"?$/.exec(directive);
      cap = Math.min(cap, match ? Number(match[1]) : 0);
    }
  }
  const date = Date.parse(headers.get('date') ?? '');
  const elapsed = Number.isFinite(date) ? Math.max(0, Math.floor((Date.now() - date) / 1000)) : 0;
  const effectiveAge = Math.max(age, elapsed);
  const expires = Date.parse(headers.get('expires') ?? '');
  if (Number.isFinite(expires)) cap = Math.min(cap, Math.max(0, Math.floor((expires - (Number.isFinite(date) ? date : Date.now())) / 1000)));
  return { age: effectiveAge, maxTtl: Number.isSafeInteger(effectiveAge) ? Math.max(0, cap - effectiveAge) : 0 };
}
