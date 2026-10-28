import { executeQuery } from '../../../src/index.js';
import { requestContext } from '../../../src/doh/metadata.js';
import { loadEcs, outgoingEcs, validateIncomingEcs, checkEcsResponse, stripResponseEcs } from '../../../src/doh/ecs.js';
import { createConfigBudget } from '../../../src/rules/config-budget.js';
import { loadLimits } from '../../../src/rules/limits.js';
import { buildQuery, parseMessage, encodeMessage, setEcs, setEdns, getEdns, getEcs, getRcode, TYPES, FLAGS } from '../../../lib/dns-wasm/index.js';

const fixedContext = { client: { ip: '198.51.100.129' } };
const noOpEvent = () => {};
const codeFrom = fn => { try { fn(); return null; } catch (error) { return error?.code ?? 'THREW'; } };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const safeErrorSummary = (error, secrets = []) => {
  let message = String(error?.message ?? 'No error message');
  message = message.replace(/https?:\/\/[^\s)]+/gi, '[redacted-url]');
  for (const secret of secrets) if (typeof secret === 'string' && secret) message = message.split(secret).join('[redacted]');
  const name = /^[A-Za-z0-9_]{1,48}$/.test(String(error?.name ?? '')) ? String(error.name) : 'Error';
  const rawCode = String(error?.code ?? 'UNKNOWN');
  const code = /^[A-Za-z0-9_-]{1,48}$/.test(rawCode) ? rawCode : 'UNKNOWN';
  return { name, code, message: message.slice(0, 200) };
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!env.ECS_CHECK_KEY || url.pathname !== `/${env.ECS_CHECK_KEY}/suite`) return new Response('', { status: 404 });
    const expires = Number(env.ECS_CHECK_EXPIRES);
    if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + 3600000) return Response.json({ error: 'expired' }, { status: 410 });
    if (request.method !== 'POST') return new Response('', { status: 405 });
    if (request.headers.get('authorization') !== `Bearer ${env.ECS_CHECK_KEY}`) return new Response('', { status: 404 });
    if (!env.ECS_FIXTURE_URL) return Response.json({ error: 'fixture-not-configured' }, { status: 503 });

    const fixture = new URL(env.ECS_FIXTURE_URL);
    if (fixture.protocol !== 'https:' || fixture.username || fixture.password || fixture.search || fixture.hash) return Response.json({ error: 'invalid-fixture-url' }, { status: 503 });
    const runId = crypto.randomUUID();
    const checks = {};
    const limits = loadLimits(undefined);
    const localPolicy = (raw, resolve = name => name === 'resolver' || name === 'other' ? { transport: 'https', url: 'https://resolver.example/dns-query' } : undefined) =>
      loadEcs(raw, {}, limits, createConfigBudget(limits), resolve);
    const directQuery = (label = 'local') => parseMessage(buildQuery(`${runId}.${label}.example`, TYPES.A));
    const wireQuery = (label, type = TYPES.A) => parseMessage(buildQuery(`${runId}.${label}.example`, type));
    const hasCode = (fn, code) => codeFrom(fn) === code;

    // Pure policy regressions, executed in the deployed Worker without node:test.
    checks.disabledDefaults = localPolicy(undefined) === null && localPolicy(false) === null && localPolicy('false') === null;
    checks.fullUpstreamPreflight = hasCode(() => localPolicy({ mode: 'client', upstreams: ['missing'] }), 'INVALID_CONFIG') &&
      hasCode(() => loadEcs({ mode: 'client', upstreams: ['resolver'] }, {}, limits, createConfigBudget(limits), () => undefined), 'INVALID_CONFIG') &&
      hasCode(() => localPolicy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 25 }), 'INVALID_CONFIG');

    const original = directQuery();
    const originalWire = encodeMessage(original);
    const optQuery = setEdns(directQuery('opt'), { udp_payload_size: 4096, flags: 0x8000, options: [{ code: 65001, data: [7] }] });
    const defaultClientPolicy = localPolicy({ mode: 'client', upstreams: ['resolver'] });
    const decorated = outgoingEcs(defaultClientPolicy, optQuery, null, '198.51.100.129', limits);
    const decoratedEdns = getEdns(decorated);
    checks.clientPrefixesAndOptPreservation = getEcs(decorated)?.address === '198.51.100.0' && getEcs(decorated)?.source_prefix === 24 &&
      decoratedEdns?.udp_payload_size === 4096 && decoratedEdns.flags === 0x8000 &&
      same(decoratedEdns.options, [{ code: 65001, data: [7] }, { code: 8, data: [0, 1, 24, 0, 198, 51, 100] }]) &&
      encodeMessage(original).every((byte, index) => byte === originalWire[index]) && encodeMessage(original).length === originalWire.length;
    const v6 = outgoingEcs(defaultClientPolicy, original, null, '2001:db8:abcd:1234::9', limits);
    checks.ipv6Truncation = getEcs(v6)?.source_prefix === 56 && getEcs(v6)?.address.startsWith('2001:db8:abcd:1200:');
    const nonBytePolicy = localPolicy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 17 });
    const nonByte = outgoingEcs(nonBytePolicy, original, null, '198.51.200.129', limits);
    checks.nonBytePrefix = getEcs(nonByte)?.source_prefix === 17 && getEcs(nonByte)?.address === '198.51.128.0';
    const fixedPolicy = localPolicy({ mode: 'fixed', upstreams: ['resolver'], subnet: '203.0.113.129/24' });
    checks.fixedNormalization = fixedPolicy.ecs.address === '203.0.113.0' && fixedPolicy.ecs.source_prefix === 24;

    const inboundZero = setEcs(setEdns(directQuery('zero'), { udp_payload_size: 1232 }), { address: '0.0.0.0', source_prefix: 0 });
    const inboundZeroIdentity = validateIncomingEcs(inboundZero);
    const preservedZero = outgoingEcs(fixedPolicy, inboundZero, inboundZeroIdentity, '198.51.100.129', limits);
    const incoming = setEcs(setEdns(directQuery('incoming'), { udp_payload_size: 1232 }), { address: '198.51.100.129', source_prefix: 24 });
    const incomingIdentity = validateIncomingEcs(incoming);
    const capped = outgoingEcs(localPolicy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 16 }), incoming, incomingIdentity, undefined, limits);
    const noIdentity = outgoingEcs(localPolicy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 0 }), incoming, incomingIdentity, undefined, limits);
    checks.incomingZeroAndPrefixCaps = inboundZeroIdentity?.source_prefix === 0 && getEcs(preservedZero)?.source_prefix === 0 &&
      getEcs(capped)?.source_prefix === 16 && getEcs(capped)?.address === '198.51.0.0' && getEcs(noIdentity)?.source_prefix === 0;

    const malformedQuery = setEdns(directQuery('malformed'), { udp_payload_size: 1232, options: [{ code: 8, data: [0, 1, 17, 0, 198, 51] }] });
    const duplicateQuery = setEcs(setEdns(directQuery('duplicate'), { udp_payload_size: 1232 }), { address: '198.51.100.0', source_prefix: 24 });
    const duplicateOpt = duplicateQuery.additional.find(rr => rr.rtype === TYPES.OPT);
    duplicateOpt.rdata.Opt.options.push(structuredClone(duplicateOpt.rdata.Opt.options[0]));
    const scopedQuery = setEcs(setEdns(directQuery('scope'), { udp_payload_size: 1232 }), { address: '198.51.100.0', source_prefix: 24, scope_prefix: 8 });
    checks.invalidIncomingEcsRejected = hasCode(() => validateIncomingEcs(malformedQuery), 'INVALID_QUERY') &&
      hasCode(() => validateIncomingEcs(duplicateQuery), 'INVALID_QUERY') && hasCode(() => validateIncomingEcs(scopedQuery), 'INVALID_QUERY');

    const expectedQuery = outgoingEcs(defaultClientPolicy, directQuery('expected'), null, '198.51.100.129', limits);
    const wrongResponse = setEcs(setEdns(directQuery('wrong'), { udp_payload_size: 1232 }), { address: '192.0.2.0', source_prefix: 24 });
    const duplicateResponse = setEcs(setEdns(directQuery('duplicate-response'), { udp_payload_size: 1232 }), { address: '198.51.100.0', source_prefix: 24 });
    const duplicateResponseOpt = duplicateResponse.additional.find(rr => rr.rtype === TYPES.OPT);
    duplicateResponseOpt.rdata.Opt.options.push(structuredClone(duplicateResponseOpt.rdata.Opt.options[0]));
    const malformedResponse = setEdns(directQuery('malformed-response'), { udp_payload_size: 1232, options: [{ code: 8, data: [0, 1, 17, 0, 198, 51] }] });
    checks.badResponsesRejected = hasCode(() => checkEcsResponse(wrongResponse, expectedQuery), 'UPSTREAM_INVALID') &&
      hasCode(() => checkEcsResponse(duplicateResponse, expectedQuery), 'UPSTREAM_INVALID') &&
      hasCode(() => checkEcsResponse(malformedResponse, expectedQuery), 'UPSTREAM_INVALID');
    const nonBytePadding = [0, 1, 17, 0, 198, 51, 129];
    const nonCanonicalQuery = setEdns(directQuery('noncanonical-query'), { udp_payload_size: 1232, options: [{ code: 8, data: nonBytePadding }] });
    const expected17 = outgoingEcs(localPolicy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 17 }), directQuery('expected17'), null, '198.51.200.129', limits);
    const nonCanonicalResponse = setEdns(directQuery('noncanonical-response'), { udp_payload_size: 1232, options: [{ code: 8, data: nonBytePadding }] });
    checks.nonBytePaddingRejected = hasCode(() => validateIncomingEcs(nonCanonicalQuery), 'INVALID_QUERY') &&
      hasCode(() => checkEcsResponse(nonCanonicalResponse, expected17), 'UPSTREAM_INVALID');

    const source32 = setEcs(setEdns(directQuery('source32'), { udp_payload_size: 1232 }), { address: '198.51.100.129', source_prefix: 32 });
    const source32Identity = validateIncomingEcs(source32);
    const sent24 = outgoingEcs(defaultClientPolicy, source32, source32Identity, undefined, limits);
    const responseForRestore = setEcs(setEdns(directQuery('restore'), { udp_payload_size: 1232 }), { address: '198.51.100.0', source_prefix: 24, scope_prefix: 16 });
    checkEcsResponse(responseForRestore, sent24);
    const restored = getEcs(stripResponseEcs(responseForRestore, source32Identity));
    checks.responseIdentityRestore = restored?.address === '198.51.100.129' && restored.source_prefix === 32 && restored.scope_prefix === 16;

    checks.untrustedRequestHeadersIgnored = !requestContext(new Request('https://doh.test/', { headers: {
      'CF-Connecting-IP': '198.51.100.129', 'X-Forwarded-For': '198.51.100.129', 'CF-IPCountry': 'US',
    } })).client?.ip;

    const actionsFor = upstream => [{ type: 'queryUpstream', upstream }];
    const run = async ({ policy, context = {}, label, type = TYPES.A, actions, upstreams, dnsLimits, signal, wire, cache = false } = {}) => {
      const targetUrl = fixture.toString();
      const envConfig = {
        DNS_UPSTREAMS: upstreams ?? { resolver: { transport: 'https', url: targetUrl }, other: { transport: 'https', url: targetUrl } },
        DNS_RULE_MAIN: { order: 0, rules: [{ actions: actions ?? actionsFor('resolver') }] },
        DNS_LIMITS: { maxNetworkRequests: 1, ...(dnsLimits ?? {}) },
        DNS_CACHE: { read: cache, write: cache, maxTtl: cache ? 300 : 0 },
        ...(policy === undefined ? {} : { DNS_ECS: policy }),
      };
      return executeQuery(encodeMessage(wire ?? wireQuery(label, type)), envConfig, { context, signal, onEvent: noOpEvent });
    };
    const answerOf = result => parseMessage(result.response);
    const addressA = result => answerOf(result).answers[0]?.rdata?.A?.addr;
    const addressAaaa = result => answerOf(result).answers[0]?.rdata?.Aaaa?.addr;
    const goodResult = (result, type, expectedAddress) => {
      const response = answerOf(result);
      return result.lastAction?.success === true && getRcode(response) === 0 && response.answers.length === 1 &&
        response.answers[0].rtype === type && (type === TYPES.A ? addressA(result) : addressAaaa(result)) === expectedAddress;
    };
    const inspect = async (name, options) => {
      try { checks[name] = goodResult(await run(options), options.type ?? TYPES.A, options.expectedAddress); }
      catch { checks[name] = false; }
    };

    const clientPolicy = { mode: 'client', upstreams: ['resolver'] };
    await inspect('cloudClientIpv4', { policy: clientPolicy, context: fixedContext, label: 'client24', expectedAddress: '192.0.2.24' });
    await inspect('cloudClientIpv6', { policy: clientPolicy, context: { client: { ip: '2001:db8:abcd:1234::9' } }, label: 'client56', type: TYPES.AAAA, expectedAddress: '2001:db8:56::44' });
    await inspect('cloudFixedSubnet', { policy: { mode: 'fixed', upstreams: ['resolver'], subnet: '203.0.113.129/24' }, label: 'fixed', expectedAddress: '192.0.2.24' });
    await inspect('cloudMissingTrustedIp', { policy: clientPolicy, context: {}, label: 'no-trust', expectedAddress: '192.0.2.44' });
    await inspect('cloudConfiguredPrefixZero', { policy: { ...clientPolicy, ipv4Prefix: 0 }, context: fixedContext, label: 'prefix-zero', expectedAddress: '192.0.2.44' });
    try {
      const result = await run({ policy: { mode: 'fixed', upstreams: ['resolver'], subnet: '203.0.113.0/24' }, context: fixedContext, label: 'inbound-zero', wire: setEcs(setEdns(wireQuery('inbound-zero'), { udp_payload_size: 1232 }), { address: '0.0.0.0', source_prefix: 0 }) });
      checks.cloudInboundZero = goodResult(result, TYPES.A, '192.0.2.0') && getEcs(answerOf(result))?.source_prefix === 0;
    } catch { checks.cloudInboundZero = false; }

    try {
      const result = await run({ policy: clientPolicy, context: fixedContext, label: 'response-sanitized' });
      checks.responseSanitized = goodResult(result, TYPES.A, '192.0.2.24') && getEcs(answerOf(result)) === null;
    } catch { checks.responseSanitized = false; }

    try {
      const result = await run({ policy: { mode: 'client', upstreams: ['other'] }, context: fixedContext, label: 'unselected' });
      checks.notSelectedUpstreamUnaffected = goodResult(result, TYPES.A, '192.0.2.44');
    } catch { checks.notSelectedUpstreamUnaffected = false; }
    try {
      const result = await run({ context: fixedContext, label: 'disabled' });
      checks.cloudDefaultDisabled = goodResult(result, TYPES.A, '192.0.2.44') && getEcs(result.originalQuery) === null;
    } catch { checks.cloudDefaultDisabled = false; }

    try {
      const query = setEdns(wireQuery('edns-preserve'), { udp_payload_size: 4096, flags: 0x8000, options: [{ code: 65001, data: [7] }] });
      const result = await run({ policy: clientPolicy, context: fixedContext, label: 'edns-preserve', wire: query });
      const response = answerOf(result), edns = getEdns(response);
      checks.doAdOtherOptAndExtendedRcode = result.lastAction?.success === true && getRcode(response) === 16 && !!(response.flags & FLAGS.AD) &&
        edns?.udp_payload_size === 4096 && edns.flags === 0x8000 && same(edns.options, [{ code: 65001, data: [7] }]);
    } catch { checks.doAdOtherOptAndExtendedRcode = false; }

    try {
      await run({ policy: clientPolicy, context: fixedContext, label: 'extended-no-client-opt' });
      checks.extendedRcodeWithoutClientOptRejected = false;
    } catch (error) { checks.extendedRcodeWithoutClientOptRejected = error?.code === 'UPSTREAM_INVALID'; }

    try {
      const result = await run({ policy: clientPolicy, context: fixedContext, label: 'rollback', actions: [
        { type: 'queryUpstream', upstream: 'resolver', onError: 'continue' },
        { type: 'answer', records: [{ name: `${runId}.rollback.example`, type: 'A', ttl: 30, rdata: { A: { addr: '203.0.113.77' } } }] },
      ] });
      checks.optionalRollback = goodResult(result, TYPES.A, '203.0.113.77');
    } catch { checks.optionalRollback = false; }

    try {
      const echActions = [
        { type: 'queryEch', name: `${runId}.ech-source.example`, upstream: 'resolver', onError: 'continue' },
      ];
      const rules = [
        { actions: echActions },
        {
          when: { field: 'lastAction.code', op: 'eq', value: 'NO_ECH_CONFIG' },
          actions: [{ type: 'answer', records: [{
            name: `${runId}.ech-isolation.example`, type: 'A', ttl: 30,
            rdata: { A: { addr: '192.0.2.44' } },
          }] }],
        },
      ];
      const result = await executeQuery(encodeMessage(wireQuery('ech-isolation')), {
        DNS_UPSTREAMS: { resolver: { transport: 'https', url: fixture.toString() } },
        DNS_RULE_MAIN: { order: 0, rules }, DNS_LIMITS: { maxNetworkRequests: 1 },
        DNS_CACHE: { read: false, write: false, maxTtl: 0 }, DNS_ECS: clientPolicy,
      }, { context: fixedContext, onEvent: noOpEvent });
      checks.queryEchIsolated = goodResult(result, TYPES.A, '192.0.2.44');
    } catch { checks.queryEchIsolated = false; }

    const controller = new AbortController();
    controller.abort();
    try {
      await run({ policy: clientPolicy, context: fixedContext, label: 'disabled', signal: controller.signal });
      checks.cancelledBeforeNetwork = false;
    } catch (error) { checks.cancelledBeforeNetwork = error?.code === 'REQUEST_CANCELLED'; }

    try {
      const result = await run({ policy: clientPolicy, context: fixedContext, label: 'bad-ecs' });
      checks.responseIdentityMismatchRejected = false;
    } catch (error) { checks.responseIdentityMismatchRejected = error?.code === 'UPSTREAM_INVALID'; }

    try {
      const cacheQuery = wireQuery('cache-scope');
      const first = await run({ policy: clientPolicy, context: fixedContext, label: 'cache-scope', wire: cacheQuery, cache: true });
      const second = await run({ policy: clientPolicy, context: fixedContext, label: 'cache-scope', wire: cacheQuery, cache: true });
      const otherSubnet = await run({ policy: clientPolicy, context: { client: { ip: '203.0.113.7' } }, label: 'cache-scope', wire: cacheQuery, cache: true });
      checks.cacheResultsSuccessful = goodResult(first, TYPES.A, '192.0.2.24') && goodResult(second, TYPES.A, '192.0.2.24') && goodResult(otherSubnet, TYPES.A, '192.0.2.24');
    } catch { checks.cacheResultsSuccessful = false; }

    let fixtureStats;
    let cacheStats = { events: [], error: null };
    try {
      const statsUrl = new URL(fixture);
      statsUrl.searchParams.set('stats', '1');
      statsUrl.searchParams.set('run', runId);
      const statsResponse = await fetch(statsUrl, { headers: { accept: 'application/json' }, redirect: 'manual' });
      if (statsResponse.redirected || (statsResponse.status >= 300 && statsResponse.status < 400)) throw Object.assign(new Error('Fixture stats endpoint redirected.'), { code: 'FIXTURE_STATS_REDIRECT' });
      if (!statsResponse.ok) throw Object.assign(new Error(`Fixture stats returned HTTP ${statsResponse.status}.`), { code: 'FIXTURE_STATS_HTTP' });
      fixtureStats = await statsResponse.json();
      const cacheEvents = fixtureStats.seen.filter(item => item.name === 'cache-scope');
      const sameColo = cacheEvents.length > 0 && cacheEvents.every(item => item.colo === fixtureStats.colo && item.colo !== null);
      const sameIsolate = cacheEvents.length > 0 && cacheEvents.every(item => item.isolate === fixtureStats.isolate);
      const sameSubnet = cacheEvents.filter(item => item.ecs?.address === '198.51.100.0' && item.ecs.source === 24).length;
      const otherNetwork = cacheEvents.filter(item => item.ecs?.address === '203.0.113.0' && item.ecs.source === 24).length;
      const events = cacheEvents.map(item => {
        const address = item.ecs?.address;
        const safeAddress = typeof address === 'string' && (address.startsWith('198.51.100.') || address.startsWith('203.0.113.') || address.startsWith('2001:db8:')) ? address : null;
        return { scenario: item.name, type: item.type, ecs: safeAddress ? { address: safeAddress, source: item.ecs.source } : null, colo: item.colo, isolate: item.isolate };
      });
      cacheStats = { events, colo: fixtureStats.colo, isolate: fixtureStats.isolate, error: null };
      checks.cacheStatsSameColo = sameColo;
      checks.cacheStatsSameIsolate = sameIsolate;
      checks.cacheSameSubnetHitAndCrossSubnetMiss = sameColo && sameIsolate && cacheEvents.length === 2 && sameSubnet === 1 && otherNetwork === 1;
      if (!sameColo || !sameIsolate) cacheStats.error = { name: 'CacheStatsMismatch', code: 'CACHE_STATS_SCOPE_MISMATCH', message: 'Cache observations and stats read did not share the same colo and isolate.' };
    } catch (error) {
      cacheStats = { events: [], error: safeErrorSummary(error, [env.ECS_FIXTURE_KEY, env.ECS_CHECK_KEY]) };
      checks.cacheStatsSameColo = false;
      checks.cacheStatsSameIsolate = false;
      checks.cacheSameSubnetHitAndCrossSubnetMiss = false;
    }

    // Exactly one fixed, reserved documentation subnet probe to the approved Google resolver.
    let googleResolverError = null;
    let googleResolverDiagnostics = null;
    try {
      const response = await executeQuery(encodeMessage(parseMessage(buildQuery('example.com', TYPES.A))), {
        DNS_UPSTREAMS: { resolver: { transport: 'https', url: 'https://dns.google/dns-query' } },
        DNS_RULE_MAIN: { order: 0, rules: [{ actions: [{ type: 'queryUpstream', upstream: 'resolver' }] }] },
        DNS_LIMITS: { maxNetworkRequests: 1 },
        DNS_CACHE: { read: false, write: false, maxTtl: 0 },
        DNS_ECS: { mode: 'fixed', upstreams: ['resolver'], subnet: '203.0.113.0/24' },
      }, { context: {}, onEvent: noOpEvent });
      const answer = parseMessage(response.response);
      googleResolverDiagnostics = {
        rcode: getRcode(answer),
        lastActionSuccess: response.lastAction?.success === true,
        answerTypes: answer.answers.map(record => record.rtype),
        ecsNull: getEcs(answer) === null,
      };
      checks.fixedResolverBoundary = googleResolverDiagnostics.lastActionSuccess && googleResolverDiagnostics.rcode === 0 &&
        googleResolverDiagnostics.answerTypes.includes(TYPES.A) && googleResolverDiagnostics.ecsNull;
      if (!checks.fixedResolverBoundary) googleResolverError = { name: 'AssertionError', code: 'RESOLVER_ASSERTION_FAILED', message: 'Resolver did not return successful A data with internal ECS stripped.' };
    } catch (error) {
      checks.fixedResolverBoundary = false;
      googleResolverError = safeErrorSummary(error);
    }

    const required = [
      'disabledDefaults', 'fullUpstreamPreflight', 'clientPrefixesAndOptPreservation', 'ipv6Truncation', 'nonBytePrefix', 'fixedNormalization',
      'incomingZeroAndPrefixCaps', 'invalidIncomingEcsRejected', 'badResponsesRejected', 'nonBytePaddingRejected', 'responseIdentityRestore', 'untrustedRequestHeadersIgnored',
      'cloudClientIpv4', 'cloudClientIpv6', 'cloudFixedSubnet', 'cloudMissingTrustedIp', 'cloudConfiguredPrefixZero', 'cloudInboundZero',
      'responseSanitized', 'notSelectedUpstreamUnaffected', 'cloudDefaultDisabled', 'doAdOtherOptAndExtendedRcode', 'extendedRcodeWithoutClientOptRejected', 'optionalRollback',
      'queryEchIsolated', 'cancelledBeforeNetwork', 'responseIdentityMismatchRejected', 'cacheResultsSuccessful', 'cacheStatsSameColo',
      'cacheStatsSameIsolate', 'cacheSameSubnetHitAndCrossSubnetMiss', 'fixedResolverBoundary',
    ];
    const missing = required.filter(name => checks[name] !== true);
    return Response.json({
      suite: 'ecs-fixed-fixtures-v2', runId, checks,
      cacheStats,
      googleResolverError,
      googleResolverDiagnostics,
      limitation: 'Fixture counters are isolate-local. Cache evidence is accepted only when the fixture query events and stats read share both colo and isolate; restarts or routing across isolates make the cache assertion fail rather than aggregate. The single Google boundary probe checks DNS success and ECS stripping only, not location steering; 203.0.113.0/24 is reserved documentation space and may be rejected.',
      missing,
    });
  },
};
