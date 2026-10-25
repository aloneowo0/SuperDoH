import { probeEch } from './doh/ech-probe.js';
import { parseEchConfigList } from '../lib/ech-probe/config.js';
import { directEch, queryEch, applyEch } from './rules/ech.js';
import { loadDomainLists } from './rules/domain-lists.js';
import { loadAddressSources } from './rules/address-sources.js';
import { createAttribution } from './doh/attribution.js';
import { editRecords } from './rules/records.js';
import { loadCachePolicy } from './rules/cache-policy.js';
import { createConfigBudget } from './rules/config-budget.js';
import { loadUpstreams } from './doh/upstreams.js';
import { createBudget, createNetworkAllowance } from './doh/budget.js';
import { createUpstream } from './doh/upstream.js';
import { parseQuery, finalizeResponse, invalidateResponse } from './doh/protocol.js';
import { loadLimits, within } from './rules/limits.js';
import { RuleError, createReporter, normalizeFailure } from './rules/errors.js';
export { RuleError } from './rules/errors.js';
import { loadGroups, recordType, domain } from './rules/config.js';
import { matches } from './rules/conditions.js';
import { loadContext } from './rules/context.js';
import { buildResponse, parseMessage, encodeMessage, getRcode, TYPES } from '../lib/dns-wasm/index.js';

/** @template T @param {T} value @returns {T} */
function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/** @param {unknown} error @param {import('./rules/errors.js').Location} location */
function failureAt(error, location) {
  return normalizeFailure(error, location);
}
/** @param {import('../lib/dns-wasm/index.js').DnsMessage} a @param {import('../lib/dns-wasm/index.js').DnsMessage} b */
function sameQuery(a, b) {
  const first = a.questions[0], second = b.questions[0];
  return domain(first.name) === domain(second.name) && first.rtype === second.rtype && first.class === second.class && a.flags === b.flags && JSON.stringify(a.additional) === JSON.stringify(b.additional);
}
/** @param {import('../lib/dns-wasm/index.js').DnsMessage} response @param {import('../lib/dns-wasm/index.js').DnsMessage} current @param {import('../lib/dns-wasm/index.js').DnsMessage} original */
function upstreamForClient(response, current, original) {
  if (sameQuery(current, original)) return response;
  const result = invalidateResponse(response);
  // Do not pass through EDNS metadata produced for different client options.
  if (JSON.stringify(current.additional) !== JSON.stringify(original.additional)) {
    const rcode = getRcode(result);
    result.additional = result.additional.filter(rr => rr.rtype !== TYPES.OPT);
    if (rcode > 15) {
      const clientOpt = original.additional.find(rr => rr.rtype === TYPES.OPT);
      if (!clientOpt) throw new RuleError('UPSTREAM_INVALID', 'The DNS upstream response cannot be represented for this query.');
      // Preserve the response code, never options or flags from the rewritten query.
      result.additional.push({ name: '.', rtype: TYPES.OPT, class: clientOpt.class, ttl: (rcode >>> 4) * 0x1000000, rdata: { Opt: { options: [] } } });
    }
  }
  return result;
}
/**
 * Execute JSON rules sequentially; network actions share the request budget.
 * @param {Uint8Array} queryWire
 * @param {Record<string, unknown>} env
 * @param {import('./rules/types.js').ExecutionOptions} [options]
 * @returns {Promise<import('./rules/types.js').ExecutionResult>}
 */
export async function executeQuery(queryWire, env, options = {}) {
  const report = createReporter(options);
  /** @type {import('./rules/types.js').Action['type'] | undefined} */
  let actionType;
  /** @type {import('./rules/errors.js').Location} */
  const location = {};
  /** @type {ReturnType<typeof createBudget> | undefined} */
  let budget;
  try {
    const limits = loadLimits(env.DNS_LIMITS);
    budget = createBudget(limits.maxExecutionTimeMs, options.signal);
    const execution = budget;
    execution.check();
    const context = loadContext(options.context, limits);
    within(queryWire.byteLength, limits.maxQueryBytes);
    const originalWire = queryWire.slice();
    let parsed;
    try {
      parsed = parseQuery(originalWire);
    } catch {
      throw new RuleError('INVALID_QUERY', 'Invalid or unsupported DNS query.');
    }
    const originalQuery = freeze(parsed);
    /** @type {{ query: import('../lib/dns-wasm/index.js').DnsMessage, response: import('../lib/dns-wasm/index.js').DnsMessage | null }} */
    let state = { query: structuredClone(originalQuery), response: null };
    /** @type {Uint8Array | undefined} */
    let responseWire;
    const configBudget = createConfigBudget(limits);
    const upstreams = loadUpstreams(env, limits, configBudget);
    let cache = loadCachePolicy(env.DNS_CACHE, configBudget);
    const spendNetwork = createNetworkAllowance(limits.maxNetworkRequests, execution);
    const transport = createUpstream(limits, execution, spendNetwork);
    const sources = loadAddressSources(env, limits, configBudget);
    const enrich = createAttribution(limits, execution, spendNetwork);
    let properties = context;
    const domainLists = loadDomainLists(env, limits, configBudget);
    const groups = loadGroups(env, limits, configBudget);
    for (const group of groups) {
      for (const [ruleIndex, rule] of group.rules.entries()) {
        for (const [actionIndex, action] of rule.actions.entries()) {
          if (action.type === 'enrichAddresses') {
            try { sources.resolve(action.source); }
            catch (error) { throw failureAt(error, { group: group.name, rule: ruleIndex, action: actionIndex, source: action.source }); }
          }
          if (action.type !== 'queryUpstream' && action.type !== 'queryEch') continue;
          try { upstreams.resolve(action.upstream); }
          catch (error) { throw failureAt(error, { group: group.name, rule: ruleIndex, action: actionIndex }); }
        }
      }
    }
    for (const name of configBudget.listReferences) domainLists.resolve(name);
    properties = { ...properties, lists: await domainLists.prepare(configBudget.listReferences, execution, spendNetwork) };
    /** @type {import('./rules/types.js').ActionResult | undefined} */
    let lastAction;
    /** @type {import('./rules/ech.js').EchCandidate | undefined} */
    let ech;
    let conditionSteps = 0;
    const spend = () => { execution.check(); within(++conditionSteps, limits.maxConditionSteps, location); };
    /** @type {'completed' | 'stopped' | 'returned'} */
    let termination = 'completed';
    pipeline: for (const group of groups) {
      location.group = group.name;
      for (const [ruleIndex, rule] of group.rules.entries()) {
        execution.check();
        location.rule = ruleIndex;
        delete location.action;
        delete location.source;
        actionType = undefined;
        if (!await matches(rule.when, state.query.questions[0], originalQuery.questions[0], state.response, properties, spend, lastAction)) continue;
        for (const [actionIndex, action] of rule.actions.entries()) {
          execution.check();
          location.action = actionIndex;
          actionType = action.type;
          delete location.source;
          if (action.type === 'enrichAddresses') location.source = action.source;
          if (action.type === 'queryEch') location.source = action.upstream;
          if (action.type === 'probeEch') location.source = 'probe';
          try {
            if (action.type === 'stop' || action.type === 'return') {
              if (action.type === 'return' && !state.response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.', location);
              lastAction = freeze({ success: true, actionType: action.type, location: { group: group.name, rule: ruleIndex, action: actionIndex } });
              termination = action.type === 'stop' ? 'stopped' : 'returned';
              break pipeline;
            }
            // Only in-place writers need private data; all other actions read committed state.
            const editsRecords = ['removeRecords', 'replaceRecords', 'addRecords', 'setTtl'].includes(action.type);
            const candidate = {
              query: action.type === 'rewriteQuery' ? structuredClone(state.query) : state.query,
              response: editsRecords && state.response ? structuredClone(state.response) : state.response,
            };
            let nextWire = responseWire;
            let nextCache = cache;
            let nextProperties = properties;
            let nextEch = ech;
            if (action.type === 'queryUpstream') {
              candidate.response = upstreamForClient(await transport(upstreams.resolve(action.upstream), candidate.query, { ...cache, ...action.cache }, action.upstream), candidate.query, originalQuery);
            } else if (action.type === 'loadEch') {
              nextEch = directEch(action.config);
            } else if (action.type === 'queryEch') {
              nextEch = await queryEch(action, (name, query, policy, sourceName) => transport(upstreams.resolve(name), query, policy, sourceName), cache);
            } else if (action.type === 'probeEch') {
              const bytes = await probeEch(action.options, limits, execution, spendNetwork, state => {
                try { console.info(JSON.stringify({ event: 'ech_source_state', level: 'info', requestId: report.requestId, location: { ...location }, state })); }
                catch { /* Diagnostics must not change DNS execution. */ }
              });
              nextEch = { ...directEch(parseEchConfigList(bytes).base64), source: 'probe' };
            } else if (action.type === 'applyEch') {
              if (!ech) throw new RuleError('NO_ECH_CONFIG', 'No ECH configuration has been acquired.');
              candidate.response = await applyEch(action, { current: candidate.query.questions[0], original: originalQuery.questions[0], response: candidate.response, properties, spend, lastAction }, ech, limits, location);
            } else if (action.type === 'enrichAddresses') {
              if (!candidate.response) throw new RuleError('NO_RESPONSE', 'This action requires an existing DNS response.');
              const enriched = await enrich(sources.resolve(action.source), candidate.response, action.source);
              const addresses = new Map(properties.addresses);
              for (const [key, attributes] of enriched) addresses.set(key, attributes);
              within(addresses.size, limits.maxContextAddresses, location);
              nextProperties = { ...properties, addresses };
            } else if (action.type === 'setCache') {
              const { type, onError, ...policy } = action;
              nextCache = { ...cache, ...policy };
            } else if (action.type === 'answer') {
              candidate.response = parseMessage(buildResponse(candidate.query, { rcode: action.rcode ?? 0, answers: action.records.map(({ type, ...rr }) => ({ ...rr, class: rr.class ?? 1, rtype: recordType(type) })) }));
            } else if (action.type === 'removeRecords' || action.type === 'replaceRecords' || action.type === 'addRecords' || action.type === 'setTtl') {
              candidate.response = await editRecords(action, { current: candidate.query.questions[0], original: originalQuery.questions[0], response: candidate.response, properties, spend, lastAction }, limits, location);
            } else if (action.type === 'rewriteQuery') {
              if (action.name !== undefined) candidate.query.questions[0].name = action.name;
              if (action.queryType !== undefined) candidate.query.questions[0].rtype = recordType(action.queryType);
              within(encodeMessage(candidate.query).byteLength, limits.maxQueryBytes, location);
            }
            if (candidate.response && candidate.response !== state.response) {
              nextWire = finalizeResponse(candidate.response, originalQuery, originalWire, limits.maxResponseBytes, location);
            }
            state = candidate;
            responseWire = nextWire;
            cache = nextCache;
            properties = nextProperties;
            ech = nextEch;
            lastAction = freeze({ success: true, actionType: action.type, location: { group: group.name, rule: ruleIndex, action: actionIndex } });
          } catch (error) {
            const failure = failureAt(error, location);
            lastAction = freeze({ success: false, actionType: action.type, location: { group: group.name, rule: ruleIndex, action: actionIndex }, code: failure.code });
            if (action.onError !== 'continue') throw failure;
            // Discard candidate state; earlier successful actions remain committed.
            report(failure, action.type, true);
          }
        }
      }
    }
    execution.check();
    if (state.response === null) throw new RuleError('NO_RESPONSE', 'No DNS response was produced.');
    const wire = responseWire ?? finalizeResponse(state.response, originalQuery, originalWire, limits.maxResponseBytes, location);
    return { termination, response: wire, originalQuery, query: state.query, lastAction };
  } catch (error) {
    const failure = failureAt(error, location);
    report(failure, actionType);
    throw failure;
  } finally { budget?.dispose(); }
}
