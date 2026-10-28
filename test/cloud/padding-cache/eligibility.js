import { reusable, reusableResponse, cacheKey, ageMessage, normalizeNegative } from '../../../src/doh/cache.js';
import { buildQuery, parseMessage, buildResponse, setEdns, TYPES } from '../../../lib/dns-wasm/index.js';
import { check, pad, ecs, cookie, unknown } from './common.js';

export async function eligibility(test) {
  const message = options => setEdns(parseMessage(buildQuery('eligibility.example')), { udp_payload_size: 1232, options });
  for (const [name, options] of [['padding-empty', [pad([])]], ['padding-nonzero', [pad([255, 42])]], ['padding-chrome80', [pad()]], ['ecs-padding', [ecs(), pad()]], ['padding-ecs', [pad(), ecs()]]]) {
    await test(name, () => check(reusable(message(options), true), 'not eligible'));
  }
  for (const [name, options] of [['duplicate-padding', [pad(), pad()]], ['duplicate-ecs', [ecs(), ecs()]], ['cookie-padding', [cookie(), pad()]], ['unknown-padding', [unknown(), pad()]], ['invalid-ecs-padding', [{ code: 8, data: [0, 1, 17, 0, 198, 51, 129] }, pad()]]]) {
    await test(name, () => check(!reusable(message(options), true), 'unsafe eligible'));
  }
  await test('invalid-data-bytes', () => {
    for (const data of [[256], [-1], [0.5], ['0'], null, {}]) {
      const q = message([pad()]); q.additional[0].rdata.Opt.options[0].data = data;
      check(!reusable(q, true), 'invalid bytes eligible');
    }
  });
  await test('duplicate-opt-global', () => {
    const q = message([pad()]); q.additional.push(structuredClone(q.additional[0]));
    check(!reusable(q, true) && !reusable(q), 'duplicate OPT eligible');
    q.additional.pop(); q.answers.push(structuredClone(q.additional[0]));
    check(!reusable(q), 'OPT count only additional');
  });
  await test('message-authentication', () => {
    for (const rtype of [24, TYPES.TSIG]) {
      const q = message([pad()]); q.additional.push({ name: 'key.example', rtype, class: 255, ttl: 0, rdata: { Raw: [] } });
      check(!reusable(q, true) && !reusable(q), 'signed message eligible');
    }
  });
  await test('query-type-exclusions', () => {
    for (const type of [41, 249, 250, 251, 252, 253, 254, 255]) { const q = message([pad()]); q.questions[0].rtype = type; check(!reusable(q, true), 'special type eligible'); }
  });
  await test('response-padding-asymmetry', () => {
    check(reusableResponse(message([pad()]), message([])), 'removed padding');
    check(reusableResponse(message([]), message([pad([23])])), 'added padding');
    check(reusableResponse(message([ecs(), pad()]), message([pad([23]), ecs()])), 'reordered response');
  });
  await test('response-ecs-identity', () => {
    check(!reusableResponse(message([ecs(), pad()]), message([ecs(101), pad()])), 'wrong subnet reused');
    check(!reusableResponse(message([pad()]), message([ecs(), pad()])), 'unexpected ECS reused');
    const scoped = ecs(); scoped.data[3] = 16;
    check(reusableResponse(message([ecs(), pad()]), message([scoped, pad()])), 'valid scope rejected');
  });
  await test('exact-key-and-id', async () => {
    const q = message([pad()]), target = { transport: 'https', url: 'https://fixture.example/dns-query' };
    const first = (await cacheKey(target, q, 'resolver')).url;
    q.id = 99; check((await cacheKey(target, q, 'resolver')).url === first, 'ID in key');
    q.additional[0].rdata.Opt.options[0].data[0] = 23;
    check((await cacheKey(target, q, 'resolver')).url !== first, 'padding not in key');
  });
  await test('negative-ttl-and-opt-flags', () => {
    const q = message([pad()]);
    const packet = parseMessage(buildResponse(q, { rcode: 3, authority: [{ name: 'example', rtype: 6, class: 1, ttl: 60, rdata: { Soa: { mname: 'ns.example', rname: 'hostmaster.example', serial: 1, refresh: 60, retry: 60, expire: 3600, minimum: 15 } } }] }));
    setEdns(packet, { udp_payload_size: 1232, flags: 0x8000, options: [pad()] });
    ageMessage(normalizeNegative(packet), 2);
    check(packet.authority[0].ttl === 13 && packet.additional[0].ttl === 0x8000, 'TTL or OPT flags changed');
  });
}
