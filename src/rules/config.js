import { cachePolicy } from './cache-policy.js';
import { createConfigBudget } from './config-budget.js';
import { within } from './limits.js';
import { decodeRdata, encodeRdata, TYPES } from '../../lib/dns-wasm/index.js';
import { RuleError, normalizeFailure } from './errors.js';
import { object, fields, integer, domain, recordType, upstreamName } from './values.js';
import { compileCondition } from './conditions.js';
export { domain, recordType } from './values.js';

/** @param {unknown} value @param {unknown} canonical */
function knownFields(value, canonical) {
  if (Array.isArray(value)) {
    if (!Array.isArray(canonical)) throw new Error();
    value.forEach((item, index) => knownFields(item, canonical[index]));
  } else if (value && typeof value === 'object') {
    const schema = object(canonical);
    for (const [key, child] of Object.entries(value)) {
      if (!Object.hasOwn(schema, key)) throw new Error();
      knownFields(child, schema[key]);
    }
  }
}
/** @param {unknown} value @returns {import('./types.js').RecordConfig} */
function validateRecord(value) {
  const rr = fields(value, ['name', 'type', 'class', 'ttl', 'rdata']);
  const rtype = recordType(rr.type);
  if (rtype === TYPES.OPT || rtype === TYPES.TSIG || rtype === TYPES.RRSIG || rtype === 24) throw new Error();
  const data = object(rr.rdata);
  if (Object.keys(data).length !== 1) throw new Error();
  // The library validates the type/RDATA pairing, IPs and native record fields.
  const bytes = encodeRdata(rtype, /** @type {import('../../lib/dns-wasm/index.js').Rdata} */ (data));
  if (!Object.hasOwn(data, 'Raw')) knownFields(data, decodeRdata(rtype, bytes));
  return { name: domain(rr.name), type: rtype, class: rr.class === undefined ? 1 : integer(rr.class, 65535), ttl: integer(rr.ttl, 0xffffffff), rdata: /** @type {import('../../lib/dns-wasm/index.js').Rdata} */ (data) };
}
/** @param {unknown} value @param {() => void} countRecord @param {(value: unknown) => import('./conditions.js').Predicate} compileSelector @returns {import('./types.js').CompiledAction} */
function action(value, countRecord, compileSelector) {
  const { onError, ...body } = object(value);
  if (onError !== undefined && onError !== 'fail' && onError !== 'continue') throw new Error();
  const parsed = actionValue(body, countRecord);
  return { ...parsed, onError: onError ?? 'fail', ...('where' in parsed && parsed.where !== undefined ? { selector: compileSelector(parsed.where) } : {}) };
}
/** @param {unknown} value @param {() => void} countRecord @returns {import('./types.js').Action} */
function actionValue(value, countRecord) {
  const v = object(value);
  switch (v.type) {
    case 'answer': {
      fields(v, ['type', 'records', 'rcode']);
      if (!Array.isArray(v.records)) throw new Error();
      return { type: 'answer', records: v.records.map(rr => { countRecord(); return validateRecord(rr); }), rcode: v.rcode === undefined ? 0 : integer(v.rcode, 15) };
    }
    case 'removeRecords':
      fields(v, ['type', 'where']);
      if (v.where === undefined) throw new Error();
      return { type: 'removeRecords', where: /** @type {import('./types.js').RecordCondition} */ (v.where) };
    case 'addRecords':
    case 'replaceRecords': {
      fields(v, v.type === 'replaceRecords' ? ['type', 'section', 'records', 'where'] : ['type', 'section', 'records']);
      if (v.type === 'replaceRecords' && v.where === undefined) throw new Error();
      if (v.section !== undefined && !['answer', 'authority', 'additional'].includes(/** @type {string} */ (v.section))) throw new Error();
      if (!Array.isArray(v.records)) throw new Error();
      const common = { section: /** @type {import('./types.js').RecordSection} */ (v.section ?? 'answer'), records: v.records.map(rr => { countRecord(); return validateRecord(rr); }) };
      return v.type === 'replaceRecords' ? { ...common, type: 'replaceRecords', where: /** @type {import('./types.js').RecordCondition} */ (v.where) } : { ...common, type: 'addRecords' };
    }
    case 'setTtl':
      fields(v, ['type', 'ttl', 'where']);
      return { type: 'setTtl', ttl: integer(v.ttl, 0xffffffff), where: /** @type {import('./types.js').RecordCondition | undefined} */ (v.where) };
    case 'rewriteQuery':
      fields(v, ['type', 'name', 'queryType']);
      if (v.name === undefined && v.queryType === undefined) throw new Error();
      return { type: 'rewriteQuery', name: v.name === undefined ? undefined : domain(v.name), queryType: v.queryType === undefined ? undefined : recordType(v.queryType) };
    case 'enrichAddresses':
      fields(v, ['type', 'source']);
      return { type: 'enrichAddresses', source: upstreamName(v.source) };
    case 'queryUpstream':
      fields(v, ['type', 'upstream', 'cache']);
      return { type: 'queryUpstream', upstream: upstreamName(v.upstream), cache: v.cache === undefined ? undefined : cachePolicy(v.cache) };
    case 'setCache': {
      const { type, ...policy } = v;
      return { type: 'setCache', ...cachePolicy(policy) };
    }
    case 'stop':
    case 'return':
      fields(v, ['type']);
      return { type: v.type };
    default: throw new Error();
  }
}
/** @param {Record<string, unknown>} env @param {import('./limits.js').Limits} limits @param {ReturnType<typeof createConfigBudget>} [configBudget] @returns {import('./types.js').Group[]} */
export function loadGroups(env, limits, configBudget = createConfigBudget(limits)) {
  const entries = Object.entries(env).filter(([name]) => name.startsWith('DNS_RULE_'));
  within(entries.length, limits.maxGroups);
  let rules = 0, actions = 0, records = 0;
  return entries.map(([name, raw]) => {
    /** @type {import('./errors.js').Location} */
    const location = { group: /^[A-Za-z0-9_]{1,128}$/.test(name) ? name : '<invalid>' };
    try {
      if (location.group === '<invalid>') throw new Error();
      const v = fields(configBudget.parse(raw), ['order', 'rules']);
      if (!Number.isSafeInteger(v.order) || !Array.isArray(v.rules)) throw new Error();
      rules += v.rules.length;
      within(rules, limits.maxRules, location);
      return { name, order: /** @type {number} */ (v.order), rules: v.rules.map((rawRule, ruleIndex) => {
        location.rule = ruleIndex;
        delete location.action;
        const r = fields(rawRule, ['when', 'actions']);
        const when = r.when === undefined ? undefined : compileCondition(r.when, configBudget.node, limits, configBudget.pattern);
        if (!Array.isArray(r.actions) || r.actions.length === 0) throw new Error();
        actions += r.actions.length;
        within(actions, limits.maxActions, location);
        return { when, actions: r.actions.map((rawAction, actionIndex) => {
          location.action = actionIndex;
          return action(rawAction, () => within(++records, limits.maxRecords, location), value => compileCondition(value, configBudget.node, limits, configBudget.pattern, 0, 'records'));
        }) };
      }) };
    } catch (error) {
      if (error instanceof RuleError) throw normalizeFailure(error, location);
      throw new RuleError('INVALID_CONFIG', 'Invalid or unsupported rule configuration.', location);
    }
  }).sort((a, b) => a.order - b.order || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}
