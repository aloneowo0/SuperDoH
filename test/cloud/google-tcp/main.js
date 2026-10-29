import { executeQuery } from '../../../src/index.js';
import { createUpstream } from '../../../src/doh/upstream.js';
import { createBudget } from '../../../src/doh/budget.js';
import { loadLimits } from '../../../src/rules/limits.js';
import { queryEch } from '../../../src/rules/ech.js';
import { buildQuery, parseMessage, encodeMessage, setEdns, getRcode, matchResponse } from '../../../lib/dns-wasm/index.js';
import { authorized, check, pad } from '../padding-cache/common.js';

export const cases = ['a', 'aaaa', 'https', 'padding', 'ecs', 'echPrimary', 'echSecondary', 'production-a', 'production-facebook', 'production-instagram', 'production-x'];
const target = { transport: 'tcp', address: '8.8.8.8', port: 53 };
export default { async fetch(request, env) {
  if (request.method !== 'POST' || !await authorized(request, env)) return new Response('', { status: 404 });
  const name = new URL(request.url).pathname.split('/')[2];
  if (!cases.includes(name)) return new Response('', { status: 404 });
  const start = Date.now(), stages = [];
  let budget;
  try {
    const production = JSON.parse(Array.from({ length: Number(env.PRODUCTION_PARTS) }, (_, i) => env["PRODUCTION_" + i]).join(""));
    const limits = loadLimits(production.DNS_LIMITS);
    budget = createBudget(limits.maxExecutionTimeMs);
    const transport = createUpstream(limits, budget);
    const upstream = async (source, query, policy) => {
      const began = Date.now();
      try { return await transport(target, query, policy, source); }
      finally { stages.push({ source, queryType: query.questions[0].rtype, ms: Date.now() - began }); }
    };
    let answerTypes = [], rcode, echBytes;
    if (name === 'echPrimary' || name === 'echSecondary') {
      const candidate = await queryEch({ type: 'queryEch', upstream: name, name: 'cloudflare-ech.com' }, upstream, { read: false, write: false, maxTtl: 0 });
      check(candidate.bytes.length > 0, 'missing ECH config');
      echBytes = candidate.bytes.length;
    } else {
      const domain = name === 'production-facebook' ? 'www.facebook.com' : name === 'production-instagram' ? 'www.instagram.com' : name === 'production-x' ? 'x.com' : name === 'https' ? 'cloudflare-ech.com' : 'example.com';
      const type = name === 'aaaa' ? 28 : name === 'https' || ['production-facebook', 'production-instagram', 'production-x'].includes(name) ? 65 : 1;
      let query = parseMessage(buildQuery(domain, type, 1234));
      if (name === 'padding' || name === 'ecs' || name.startsWith('production-')) query = setEdns(query, { udp_payload_size: 1232, options: [pad(), ...(name === 'ecs' ? [{ code: 8, data: [0, 1, 24, 0, 1, 1, 1] }] : [])] });
      let response;
      if (name.startsWith('production-') || name === 'ecs') {
        const config = name === 'ecs' ? { DNS_UPSTREAMS: { resolver: target }, DNS_LIMITS: production.DNS_LIMITS, DNS_CACHE: { read: false, write: false, maxTtl: 0 }, DNS_ECS: { mode: 'client', upstreams: ['resolver'] }, DNS_RULE_CHECK: { order: 0, rules: [{ actions: [{ type: 'queryUpstream', upstream: 'resolver' }, { type: 'return' }] }] } } : production;
        const began = Date.now();
        const result = await executeQuery(encodeMessage(query), config, { context: { client: { ip: '1.1.1.1' } }, onEvent() {} });
        stages.push({ source: 'full-pipeline', ms: Date.now() - began });
        matchResponse(result.response, encodeMessage(query));
        response = parseMessage(result.response);
      } else response = await upstream('resolver', query, { read: false, write: false, maxTtl: 0 });
      rcode = getRcode(response);
      check(rcode === 0, 'nonzero DNS rcode: ' + rcode);
      check(response.id === query.id, 'query ID mismatch');
      check(response.answers.some(rr => rr.rtype === type), 'missing requested answer type');
      answerTypes = response.answers.map(rr => rr.rtype);
      if (['production-facebook', 'production-instagram', 'production-x'].includes(name)) check(response.answers.some(rr => rr.rtype === 65 && rr.rdata.Https.params.some(p => p.key === 5)), 'missing rewritten ECH');
    }
    return Response.json({ name, passed: true, ms: Date.now() - start, stages, rcode, answerTypes, echBytes, colo: request.cf?.colo ?? null });
  } catch (error) {
    return Response.json({ name, passed: false, ms: Date.now() - start, stages, error: String(error.code ?? error.message).replace(/https?:\/\/[^\s]+/g, '[url]').slice(0, 180), colo: request.cf?.colo ?? null });
  } finally { budget?.dispose(); }
} };
