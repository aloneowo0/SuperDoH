import { buildResponse, parseMessage, encodeMessage, getEdns, setEdns, setSvcParam, TYPES } from '../../../lib/dns-wasm/index.js';
import { CF_ECH } from '../main-parity/data.js';
import parity from '../main-parity/fixture.js';
import { authorized, boundedBody, pad, cookie, unknown } from './common.js';

const modes = ['echo', 'add-padding', 'drop-padding', 'wrong-ecs', 'cookie', 'unknown', 'duplicate-padding', 'zero-ttl', 'negative', 'unproven-negative', 'truncated', 'ech-clean'];
export default { async fetch(request, env) {
  if (!await authorized(request, env)) return new Response('', { status: 404 });
  const url = new URL(request.url), parts = url.pathname.split('/');
  if (parts[2] === 'parity') {
    url.pathname = url.pathname.replace('/parity', '');
    return parity.fetch(new Request(url, request), env);
  }
  if (request.method !== 'POST' || request.headers.get('content-type') !== 'application/dns-message' || !modes.includes(parts[2]) || parts.length !== 3) return new Response('', { status: 404 });
  let q;
  try { q = parseMessage(await boundedBody(request)); } catch { return new Response('', { status: 400 }); }
  if (q.questions.length !== 1 || !/^[0-9a-f-]{36}\.[a-z0-9-]+\.example$/.test(q.questions[0].name) || ![1, 28, 65].includes(q.questions[0].rtype)) return new Response('', { status: 400 });
  const mode = parts[2], name = q.questions[0].name, ttl = mode === 'zero-ttl' ? 0 : 60;
  // A fresh receipt for every invocation avoids isolate-local statistics as hit evidence.
  const receipt = crypto.randomUUID() + ':' + (request.cf?.colo ?? 'unknown');
  const proof = { name, rtype: TYPES.TXT, class: 1, ttl, rdata: { Txt: [receipt] } };
  const answers = mode.includes('negative') ? [] : q.questions[0].rtype === 65
    ? [{ name, rtype: 65, class: 1, ttl, rdata: { Https: { priority: 1, target: '.', params: [] } } }]
    : [{ name, rtype: 1, class: 1, ttl, rdata: { A: { addr: '192.0.2.1' } } }];
  const authority = mode === 'negative' ? [{ name: 'example', rtype: TYPES.SOA, class: 1, ttl: 60, rdata: { Soa: { mname: 'ns.example', rname: 'hostmaster.example', serial: 1, refresh: 60, retry: 60, expire: 3600, minimum: 15 } } }] : [];
  const response = parseMessage(buildResponse(q, { rcode: mode.includes('negative') ? 3 : 0, answers, authority, additional: [proof] }));
  const edns = getEdns(q);
  if (mode === 'ech-clean' && (edns?.options.length ?? 0) > 0) return new Response('', { status: 400 });
  if (mode === 'ech-clean') setSvcParam(response.answers[0], 5, CF_ECH);
  if (edns) {
    const options = structuredClone(edns.options).filter(o => mode !== 'drop-padding' || o.code !== 12);
    if (mode === 'add-padding' && !options.some(o => o.code === 12)) options.push(pad([23]));
    if (mode === 'wrong-ecs') for (const option of options) if (option.code === 8) option.data[4] = 192;
    if (mode === 'cookie') options.push(cookie());
    if (mode === 'unknown') options.push(unknown());
    if (mode === 'duplicate-padding') options.push(pad());
    setEdns(response, { ...edns, options });
  }
  if (mode === 'truncated') response.flags |= 0x0200;
  return new Response(encodeMessage(response), { headers: {
    'content-type': 'application/dns-message', 'cache-control': 'public, max-age=60', date: new Date().toUTCString(),
  } });
} };
