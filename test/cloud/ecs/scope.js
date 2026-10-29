import { executeQuery } from '../../../src/index.js';
import { checkEcsResponse, stripResponseEcs, validateIncomingEcs } from '../../../src/doh/ecs.js';
import { reusable, reusableResponse } from '../../../src/doh/cache.js';
import { buildQuery, buildResponse, parseMessage, encodeMessage, setEdns, setEcs, getEcs, getRcode } from '../../../lib/dns-wasm/index.js';
import { check, pad } from '../padding-cache/common.js';

export async function scope(test) {
  const message = (address, source, scope = 0) => setEcs(setEdns(parseMessage(buildQuery('ecs-scope.example')), { udp_payload_size: 1232, options: [pad()] }), { address, source_prefix: source, scope_prefix: scope });
  for (const [family, address, source, scopes] of [
    ['ipv4', '198.51.100.0', 24, [0, 24, 25, 32]],
    ['ipv6', '2001:db8:abcd:1200::', 56, [0, 56, 64, 128]],
    ['nonbyte', '198.51.128.0', 17, [24]],
  ]) for (const value of scopes) await test(`${family}-source${source}-scope${value}`, () => {
    const query = message(address, source), response = message(address, source, value);
    check(checkEcsResponse(response, query) === response, 'valid response rejected');
    check(reusable(response) === (value <= source), 'cache scope boundary');
    check(reusableResponse(query, response) === (value <= source), 'response cache boundary');
    check(!getEcs(stripResponseEcs(response)), 'internal ECS leaked');
    const restored = getEcs(stripResponseEcs(response, validateIncomingEcs(query)));
    check(restored.source_prefix === source && restored.scope_prefix === value, 'client scope changed');
  });
  for (const [name, response] of [
    ['family', message('198.51.100.0', 24, 32)],
    ['source', message('2001:db8:abcd:1200::', 48, 64)],
    ['subnet', message('2001:db8:abcd:1300::', 56, 64)],
  ]) await test(`reject-wrong-${name}`, () => {
    try { checkEcsResponse(response, message('2001:db8:abcd:1200::', 56)); }
    catch (error) { check(error.code === 'UPSTREAM_INVALID', 'wrong rejection'); return; }
    throw Error('wrong identity accepted');
  });
  await test('reject-scope-outside-family', () => {
    const query = message('2001:db8:abcd:1200::', 56), response = structuredClone(query);
    response.additional[0].rdata.Opt.options.find(option => option.code === 8).data[3] = 129;
    try { checkEcsResponse(response, query); }
    catch (error) { check(error.code === 'UPSTREAM_INVALID', 'wrong rejection'); return; }
    throw Error('invalid scope accepted');
  });
  for (const value of [56, 64]) await test(`pipeline-scope${value}-cache-and-sanitization`, async () => {
    const originalFetch = globalThis.fetch, originalOpen = caches.open, stored = new Map();
    let calls = 0, writes = 0;
    const target = 'https://ecs-scope-fixture.invalid/dns-query';
    globalThis.fetch = async request => {
      check(request instanceof Request && request.url === target, 'unexpected network request');
      const query = parseMessage(new Uint8Array(await request.arrayBuffer())), ecs = getEcs(query);
      check(ecs?.source_prefix === 56, 'client prefix changed');
      const response = parseMessage(buildResponse(query, { answers: [{ name: query.questions[0].name, rtype: 1, class: 1, ttl: 60, rdata: { A: { addr: `192.0.2.${++calls}` } } }] }));
      response.additional = structuredClone(query.additional);
      setEcs(response, { ...ecs, scope_prefix: value });
      return new Response(encodeMessage(response), { headers: { 'Content-Type': 'application/dns-message' } });
    };
    caches.open = async () => ({
      match: async key => stored.get(key.url)?.clone(),
      put: async (key, response) => { writes++; stored.set(key.url, response.clone()); },
    });
    try {
      const query = setEdns(parseMessage(buildQuery(`${crypto.randomUUID()}.scope.example`)), { udp_payload_size: 1232, options: [pad()] });
      const answers = [];
      for (const address of ['2001:db8:abcd:1200::1', '2001:db8:abcd:12ff::2', '2001:db8:abcd:1200::1']) {
        const result = await executeQuery(encodeMessage(query), {
          DNS_UPSTREAMS: { resolver: { transport: 'https', url: target } },
          DNS_ECS: { mode: 'client', upstreams: ['resolver'] },
          DNS_CACHE: { read: true, write: true, maxTtl: 300 },
          DNS_RULE_TEST: { order: 0, rules: [{ actions: [{ type: 'queryUpstream', upstream: 'resolver' }] }] },
        }, { context: { client: { ip: address } }, onEvent() {} });
        const packet = parseMessage(result.response);
        check(result.lastAction.success && getRcode(packet) === 0 && packet.answers.length === 1, 'pipeline resolution failed');
        check(!getEcs(packet), 'internal ECS leaked');
        answers.push(packet.answers[0].rdata.A.addr);
      }
      check(calls === (value === 64 ? 3 : 1), 'unsafe cache reuse or safe cache miss');
      check(writes === (value === 64 ? 0 : 1), 'cache write boundary');
      check(answers.join(',') === (value === 64 ? '192.0.2.1,192.0.2.2,192.0.2.3' : '192.0.2.1,192.0.2.1,192.0.2.1'), 'wrong client answer');
    } finally { globalThis.fetch = originalFetch; caches.open = originalOpen; }
  });
}
