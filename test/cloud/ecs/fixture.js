import { parseMessage, encodeMessage, setEcs, getEcs, getEdns, setEdns, setRcode, TYPES, FLAGS, buildResponse } from '../../../lib/dns-wasm/index.js';

let isolateId;
let requests = 0;
const seen = [];
const allowedScenarios = new Set([
  'client24', 'client56', 'fixed', 'no-trust', 'prefix-zero', 'inbound-zero', 'bad-ecs',
  'cache-scope', 'response-sanitized', 'unselected', 'disabled', 'edns-preserve',
  'rollback', 'ech-isolation', 'ech-source', 'extended-no-client-opt',
]);
const requestShape = name => {
  const match = /^([0-9a-f-]{36})\.([a-z0-9-]+)\.example$/.exec(name.toLowerCase());
  return match && allowedScenarios.has(match[2]) ? { run: match[1], name: match[2] } : null;
};
const answerA = (scenario, ecs) => {
  if (scenario === 'fixed') return ecs?.address === '203.0.113.0' && ecs.source_prefix === 24 ? '192.0.2.24' : '192.0.2.254';
  if (scenario === 'client24' || scenario === 'response-sanitized' || scenario === 'edns-preserve') {
    return ecs?.address === '198.51.100.0' && ecs.source_prefix === 24 ? '192.0.2.24' : '192.0.2.254';
  }
  if (scenario === 'client56') return '192.0.2.254';
  if (scenario === 'inbound-zero') return ecs?.source_prefix === 0 ? '192.0.2.0' : '192.0.2.254';
  if (scenario === 'no-trust' || scenario === 'prefix-zero' || scenario === 'unselected' || scenario === 'disabled') return ecs === null ? '192.0.2.44' : '192.0.2.254';
  if (scenario === 'cache-scope') return '192.0.2.24';
  return '192.0.2.44';
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!env.ECS_FIXTURE_KEY || url.pathname !== `/${env.ECS_FIXTURE_KEY}/dns-query`) return new Response('not found', { status: 404 });
    const expires = Number(env.ECS_FIXTURE_EXPIRES);
    if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + 3600000) return new Response('', { status: 410 });
    isolateId ??= crypto.randomUUID();
    const colo = typeof request.cf?.colo === 'string' ? request.cf.colo : null;
    if (request.method === 'GET' && url.searchParams.get('stats') === '1') {
      const run = url.searchParams.get('run') ?? '';
      if (!/^[0-9a-f-]{36}$/.test(run)) return new Response('', { status: 400 });
      return Response.json({ run, colo, isolate: isolateId, requests, seen: seen.filter(item => item.run === run) });
    }
    if (request.method !== 'POST' || request.headers.get('content-type')?.split(';')[0] !== 'application/dns-message') return new Response('', { status: 415 });
    let query;
    try { query = parseMessage(new Uint8Array(await request.arrayBuffer())); }
    catch { return new Response('', { status: 400 }); }
    const question = query.questions[0];
    const shape = question && requestShape(question.name);
    if (query.questions.length !== 1 || !shape) return new Response('', { status: 400 });
    const ecs = getEcs(query);
    requests++;
    seen.push({ ...shape, type: question.rtype, ecs: ecs ? { address: ecs.address, source: ecs.source_prefix } : null, colo, isolate: isolateId });
    if (seen.length > 128) seen.shift();

    // ECS on queryEch changes this controlled HTTPS response to SERVFAIL;
    // the expected no-ECS query returns NOERROR with no ECH data.
    const rcode = shape.name === 'ech-source' && ecs ? 2 : ['edns-preserve', 'extended-no-client-opt'].includes(shape.name) ? 16 : 0;
    let answers = [];
    if (rcode === 0 && question.rtype === TYPES.HTTPS) {
      answers = [{ name: question.name, rtype: TYPES.HTTPS, class: 1, ttl: 30, rdata: { Https: { priority: 1, target: '.', params: [] } } }];
    } else if (rcode === 0 && question.rtype === TYPES.A) {
      answers = [{ name: question.name, rtype: TYPES.A, class: 1, ttl: 30, rdata: { A: { addr: answerA(shape.name, ecs) } } }];
    } else if (rcode === 0 && question.rtype === TYPES.AAAA) {
      const validV6 = shape.name === 'client56' && ecs?.source_prefix === 56 && ecs.address.startsWith('2001:db8:abcd:1200:');
      answers = [{ name: question.name, rtype: TYPES.AAAA, class: 1, ttl: 30, rdata: { Aaaa: { addr: validV6 ? '2001:db8:56::44' : '2001:db8::ffff' } } }];
    }
    const response = parseMessage(buildResponse(query, { rcode: ['edns-preserve', 'extended-no-client-opt'].includes(shape.name) ? 0 : rcode, answers }));
    const requestOpt = query.additional.find(rr => rr.rtype === TYPES.OPT);
    if (requestOpt) response.additional.push(structuredClone(requestOpt));
    if (ecs) {
      const responseIdentity = shape.name === 'bad-ecs' || shape.name === 'rollback'
        ? { address: '192.0.2.0', source_prefix: ecs.source_prefix, scope_prefix: 0 }
        : { ...ecs, scope_prefix: 0 };
      setEcs(response, responseIdentity);
    }
    const edns = getEdns(response);
    if (edns) setEdns(response, { flags: edns.flags | 0x8000 });
    if (['edns-preserve', 'extended-no-client-opt'].includes(shape.name)) setRcode(response, 16);
    if (shape.name === 'edns-preserve') response.flags |= FLAGS.AD;
    return new Response(encodeMessage(response), { headers: { 'content-type': 'application/dns-message', 'cache-control': 'public, max-age=60' } });
  },
};
