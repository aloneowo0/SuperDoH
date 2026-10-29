import { executeQuery } from '../../../src/index.js';
import { createUpstream } from '../../../src/doh/upstream.js';
import { createBudget } from '../../../src/doh/budget.js';
import { loadLimits } from '../../../src/rules/limits.js';
import { buildQuery, parseMessage, encodeMessage, setEdns, getEcs, getEdns, TYPES, FLAGS } from '../../../lib/dns-wasm/index.js';
import parity, { suiteNames as paritySuites } from '../main-parity/main.js';
import { scope } from '../ecs/scope.js';
import { eligibility } from './eligibility.js';
import { authorized, check, pad, ecs, cookie, unknown } from './common.js';

const policy = { read: true, write: true, maxTtl: 300 };
export default { async fetch(request, env) {
  if (!await authorized(request, env) || request.method !== 'POST' || request.headers.get('authorization') !== `Bearer ${env.KEY}`) return new Response('', { status: 404 });
  const url = new URL(request.url), parts = url.pathname.split('/'), suite = parts[2];
  if (suite === 'parity' && paritySuites.includes(parts[3])) {
    url.pathname = `/${env.KEY}/${parts[3]}`;
    return parity.fetch(new Request(url, request), { ...env, FIXTURE: env.FIXTURE + '/parity' });
  }
  if (!['eligibility', 'hits', 'isolation', 'sources', 'bypass', 'pipeline', 'ecs', 'ecs-scope'].includes(suite)) return new Response('', { status: 404 });
  const results = [], proofs = [];
  const test = async (name, fn) => {
    try { await fn(); results.push({ name, passed: true }); }
    catch (error) { results.push({ name, passed: false, error: String(error.code ?? error.message).replace(/https?:\/\/[^\s]+/g, '[url]').slice(0, 180) }); }
  };
  const run = crypto.randomUUID();
  const query = (label, options = [pad()], flags = FLAGS.RD) => setEdns(parseMessage(buildQuery(`${run}.${label}.example`, 1, 100, { flags })), { udp_payload_size: 1232, options });
  const receipt = packet => packet.additional.find(r => r.rtype === TYPES.TXT)?.rdata?.Txt?.[0];
  const limits = loadLimits(undefined);
  const transportTest = async (name, options, expected, mode = 'echo', mutate) => {
    let calls = 0;
    const budget = createBudget(15000);
    try {
      // This request-local callback is the actual upstream network-attempt counter.
      const upstream = createUpstream(limits, budget, () => { calls++; });
      const q = query(name, options), target = { transport: 'https', url: env.FIXTURE + '/' + mode };
      const first = await upstream(target, q, policy, 'resolver');
      const secondQuery = structuredClone(q); secondQuery.id = 101;
      if (mutate) mutate(secondQuery);
      const second = await upstream(target, secondQuery, policy, 'resolver');
      check(calls === expected, `upstream calls ${calls}, expected ${expected}`);
      check(first.id === 100 && second.id === 101 && second.questions[0].name === q.questions[0].name, 'identity');
      check(receipt(first) && receipt(second), 'missing fixture receipt');
      check((receipt(first) === receipt(second)) === (expected === 1), 'receipt contradicts invocation count');
      check(second.answers.every(r => r.ttl <= 60), 'TTL extended');
      proofs.push({ name, calls, expected, sameReceipt: receipt(first) === receipt(second), colo: request.cf?.colo ?? null });
    } finally { budget.dispose(); }
  };
  if (suite === 'ecs-scope') await scope(test);
  if (suite === 'eligibility') await eligibility(test);
  if (suite === 'hits') {
    for (const [name, options] of [['chrome80', [pad()]], ['empty', [pad([])]], ['nonzero', [pad([42, 255])]], ['ecs-first', [ecs(), pad()]], ['padding-first', [pad(), ecs()]]]) await test(name, () => transportTest(name, options, 1));
    await test('response-add-padding', () => transportTest('response-add-padding', [], 1, 'add-padding'));
    await test('response-drop-padding', () => transportTest('response-drop-padding', [pad()], 1, 'drop-padding'));
    await test('negative-soa', () => transportTest('negative-soa', [pad()], 1, 'negative'));
  }
  if (suite === 'isolation') {
    for (const [name, options, mutate] of [
      ['padding-content', [pad()], q => { q.additional[0].rdata.Opt.options[0].data[0] = 23; }],
      ['padding-length', [pad()], q => { q.additional[0].rdata.Opt.options[0].data.pop(); }],
      ['ecs-subnet', [ecs(), pad()], q => { q.additional[0].rdata.Opt.options[0].data[6]++; }],
      ['option-order', [ecs(), pad()], q => { q.additional[0].rdata.Opt.options.reverse(); }],
      ['do', [pad()], q => { q.additional[0].ttl |= 0x8000; }],
      ['cd', [pad()], q => { q.flags |= FLAGS.CD; }],
      ['udp-payload', [pad()], q => { q.additional[0].class = 4096; }],
    ]) await test(name, () => transportTest(name, options, 2, 'echo', mutate));
  }
  if (suite === 'sources') {
    await test('upstream-name-and-target', async () => {
      let calls = 0; const budget = createBudget(15000);
      try {
        const upstream = createUpstream(limits, budget, () => { calls++; }), q = query('sources');
        for (const [mode, name] of [['echo', 'resolver'], ['echo', 'other'], ['drop-padding', 'resolver']]) {
          const target = { transport: 'https', url: env.FIXTURE + '/' + mode };
          await upstream(target, q, policy, name); await upstream(target, q, policy, name);
        }
        check(calls === 3, 'source identities not isolated');
      } finally { budget.dispose(); }
    });
  }
  if (suite === 'bypass') {
    for (const [name, options] of [['cookie', [cookie(), pad()]], ['unknown', [unknown(), pad()]], ['duplicate-padding', [pad(), pad()]]]) await test(name, () => transportTest(name, options, 2));
    for (const mode of ['cookie', 'unknown', 'duplicate-padding', 'zero-ttl', 'unproven-negative', 'truncated']) await test('response-' + mode, () => transportTest('response-' + mode, [pad()], 2, mode));
    await test('wrong-response-ecs', () => transportTest('wrong-response-ecs', [ecs(), pad()], 2, 'wrong-ecs'));
  }
  const execute = async (q, extra = {}, actions = [{ type: 'queryUpstream', upstream: 'resolver' }], context = {}) => {
    const result = await executeQuery(q instanceof Uint8Array ? q : encodeMessage(q), { DNS_UPSTREAMS: { resolver: { transport: 'https', url: env.FIXTURE + '/echo' } }, DNS_CACHE: policy, DNS_RULE_TEST: { order: 0, rules: [{ actions }] }, ...extra }, { context, onEvent() {} });
    return parseMessage(result.response);
  };
  if (suite === 'pipeline') {
    await test('rules-run-on-hit', async () => {
      const q = query('pipeline'), first = await execute(q);
      q.id = 102;
      const second = await execute(q, {}, [{ type: 'queryUpstream', upstream: 'resolver' }, { type: 'setTtl', ttl: 7 }]);
      check(receipt(first) === receipt(second) && second.id === 102 && second.answers[0].ttl === 7, 'cached rules or identity');
    });
    for (const name of ['duplicate-ecs', 'duplicate-opt', 'bad-ecs']) await test(name, async () => {
      const options = [ecs(), pad()];
      if (name === 'duplicate-ecs') options.push(ecs());
      if (name === 'bad-ecs') options[0].data[2] = 33;
      // Construct invalid bytes independently: encodeMessage validates some of these itself.
      const base = buildQuery(`${run}.${name}.example`);
      const bytes = options.flatMap(o => [o.code >>> 8, o.code & 255, o.data.length >>> 8, o.data.length & 255, ...o.data]);
      const opt = [0, 0, 41, 4, 208, 0, 0, 0, 0, bytes.length >>> 8, bytes.length & 255, ...bytes];
      base[11] = name === 'duplicate-opt' ? 2 : 1;
      const wire = Uint8Array.from([...base, ...opt, ...(name === 'duplicate-opt' ? opt : [])]);
      const extra = { DNS_ECS: { mode: 'client', upstreams: ['resolver'] } };
      try { await execute(wire, extra); } catch (error) { check(error.code === 'INVALID_QUERY', 'wrong rejection code: ' + error.code); return; }
      throw Error('invalid query accepted');
    });
    await test('malformed-wire', async () => {
      const wire = encodeMessage(query('malformed'));
      try { await executeQuery(wire.slice(0, wire.length - 1), {}, { onEvent() {} }); }
      catch (error) { check(error.code === 'INVALID_QUERY', 'wrong malformed code'); return; }
      throw Error('malformed accepted');
    });
  }
  if (suite === 'ecs') {
    const config = { DNS_ECS: { mode: 'client', upstreams: ['resolver'], ipv4Prefix: 24, ipv6Prefix: 56 } };
    await test('client-subnet-hit-and-isolation', async () => {
      const q = query('client'), first = await execute(q, config, undefined, { client: { ip: '198.51.100.1' } });
      q.id++;
      const second = await execute(q, config, undefined, { client: { ip: '198.51.100.2' } });
      const third = await execute(q, config, undefined, { client: { ip: '198.51.101.1' } });
      check(receipt(first) === receipt(second) && receipt(first) !== receipt(third), 'client subnet cache');
      check(!getEcs(second) && getEdns(second)?.options.some(o => o.code === 12), 'ECS leaked or Padding lost');
    });
    await test('ipv6-subnet-hit-and-isolation', async () => {
      const q = query('client6'), a = await execute(q, config, undefined, { client: { ip: '2001:db8:abcd:1200::1' } });
      const b = await execute(q, config, undefined, { client: { ip: '2001:db8:abcd:12ff::2' } });
      const c = await execute(q, config, undefined, { client: { ip: '2001:db8:abcd:1300::1' } });
      check(receipt(a) === receipt(b) && receipt(a) !== receipt(c) && !getEcs(b), 'IPv6 ECS identity');
    });
    await test('query-ech-clean-padding-and-ecs', async () => {
      const q = query('ech', [ecs(), pad()]);
      const extra = { ...config, DNS_UPSTREAMS: { resolver: { transport: 'https', url: env.FIXTURE + '/ech-clean' } } };
      await executeQuery(encodeMessage(q), { ...extra, DNS_RULE_TEST: { order: 0, rules: [{ actions: [{ type: 'queryEch', name: `${run}.ech-source.example`, upstream: 'resolver', cache: policy }, { type: 'answer', records: [] }] }] } }, { onEvent() {} });
      check(q.additional[0].rdata.Opt.options.length === 2, 'input mutated');
    });
  }
  return Response.json({ suite: 'padding-cache-v1/' + suite, passed: results.length > 0 && results.every(r => r.passed), results, proofs, colo: request.cf?.colo ?? null });
} };
