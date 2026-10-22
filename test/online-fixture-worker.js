import { FLAGS, TYPES, encodeMessage, parseMessage } from '../lib/dns-wasm/index.js';
import { readBody } from '../src/doh/body.js';
import { RuleError } from '../src/rules/errors.js';

const MAX_DNS_BYTES = 4096;
const ECH_BASE64 = 'AD7+DQA6AQAgACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAEAAEAAQALZXhhbXBsZS5jb20AAA==';
const ECH_BYTES = Uint8Array.from(atob(ECH_BASE64), char => char.charCodeAt(0));
const FIXTURE_IPS = new Set(['192.0.2.8', '192.0.2.9', '2001:db8::8']);
/** @typedef {import('../lib/dns-wasm/index.js').DnsRecord} DnsRecord */
/** @param {string} body @param {number} status @param {Record<string, string>} [headers] @returns {Response} */
const text = (body, status, headers = {}) => new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...headers } });

/** @param {Request} request @param {boolean} noStore @returns {Promise<Response>} */
async function dnsResponse(request, noStore) {
  const length = request.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_DNS_BYTES)) {
    return text('Request body too large', 413);
  }
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(1000)]);
  let input;
  try { input = await readBody(request.body, MAX_DNS_BYTES, signal); }
  catch (error) {
    if (error instanceof RuleError && error.code === 'RESOURCE_LIMIT') return text('Request body too large', 413);
    if (signal.aborted) return text('Request timed out', 408);
    return text('Invalid DNS message', 400);
  }
  let query;
  try {
    query = parseMessage(input);
    if (query.is_response || query.opcode !== 0 || query.questions.length !== 1 || query.questions[0].class !== 1) {
      throw new Error('invalid query');
    }
  } catch {
    return text('Invalid DNS message', 400);
  }
  const question = query.questions[0];
  /** @type {DnsRecord[]} */
  let answers = [];
  if (question.rtype === TYPES.A) {
    answers = [{ name: question.name, rtype: TYPES.A, class: question.class, ttl: 60, rdata: { A: { addr: '192.0.2.8' } } }];
  } else if (question.rtype === TYPES.AAAA) {
    answers = [{ name: question.name, rtype: TYPES.AAAA, class: question.class, ttl: 60, rdata: { Aaaa: { addr: '2001:db8::8' } } }];
  } else if (question.rtype === TYPES.HTTPS) {
    answers = [{ name: question.name, rtype: TYPES.HTTPS, class: question.class, ttl: 60,
      rdata: { Https: { priority: 1, target: '.', params: [{ key: 5, data: Array.from(ECH_BYTES) }] } } }];
  }
  try {
    const packet = encodeMessage({
      id: query.id, flags: FLAGS.QR | FLAGS.RA | (query.flags & (FLAGS.RD | FLAGS.CD)),
      questions: [question], answers, authority: [], additional: [],
    });
    return new Response(packet, { headers: {
      'Content-Type': 'application/dns-message',
      ...(noStore ? { 'Cache-Control': 'no-store' } : {}),
    } });
  } catch {
    return text('Invalid DNS message', 400);
  }
}

export default {
  /** @param {Request} request @param {{ EXPIRES_AT?: unknown, LIST_STATE?: unknown }} env @returns {Promise<Response>} */
  async fetch(request, env) {
    if (typeof env.EXPIRES_AT !== 'number' || !Number.isFinite(env.EXPIRES_AT) || env.EXPIRES_AT <= Date.now()) {
      return text('Fixture unavailable', 503);
    }
    const url = new URL(request.url);
    if (url.pathname === '/fail') return text('Fixture failure', 503);
    if (url.pathname === '/dns' || url.pathname === '/dns-no-store') {
      if (request.method !== 'POST') return text('Method not allowed', 405);
      return dnsResponse(request, url.pathname === '/dns-no-store');
    }
    const listMatch = /^\/list-(100|1000|4096)$/.exec(url.pathname);
    if (listMatch) {
      if (request.method !== 'GET') return text('Method not allowed', 405);
      if (env.LIST_STATE === 'bad') return text('Fixture unavailable', 503);
      const count = Number(listMatch[1]);
      const names = Array.from({ length: count }, (_, index) => index === 0
        ? env.LIST_STATE === 'recovered' ? 'changed.example' : 'example.com'
        : `item${index + 1}.example`);
      return new Response(`${names.join('\n')}\n`, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }
    if (url.pathname === '/geo') {
      if (request.method !== 'GET') return text('Method not allowed', 405);
      const ip = url.searchParams.get('ip');
      if (typeof ip !== 'string' || !FIXTURE_IPS.has(ip)) return text('Invalid fixture IP', 400);
      return Response.json({ ip, network: { asn: 64512 }, location: { country: 'DE', region: 'fixture', city: 'fixture' } }, {
        headers: { 'Cache-Control': 'max-age=60' },
      });
    }
    return text('Not found', 404);
  },
};
