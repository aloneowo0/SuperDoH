import { createConfigBudget } from './config-budget.js';
import { bindExtension } from './extensions.js';
import { within } from './limits.js';
import { decodeRdata, encodeRdata, TYPES } from '../../lib/dns-wasm/index.js';
import { RuleError, normalizeFailure } from './errors.js';
import { object, fields, integer, domain, recordType } from './values.js';
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
export function validateRecord(value) {
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
/** @param {unknown} value @param {() => void} countRecord @param {import('./types.js').ExtensionRegistry} extensions @returns {import('./types.js').Action & { run?: import('./types.js').ActionHandler }} */
function action(value, countRecord, extensions) {
  const { onError, ...body } = object(value);
  if (onError !== undefined && onError !== 'fail' && onError !== 'continue') throw new Error();
  return { ...actionValue(body, countRecord, extensions), onError: onError ?? 'fail' };
}
/** @param {unknown} value @param {() => void} countRecord @param {import('./types.js').ExtensionRegistry} extensions @returns {import('./types.js').Action & { run?: import('./types.js').ActionHandler }} */
function actionValue(value, countRecord, extensions) {
  const v = object(value);
  switch (v.type) {
    case 'custom': {
      fields(v, ['type', 'name', 'params']);
      const { type, ...reference } = v;
      return { type: 'custom', name: /** @type {string} */ (v.name), params: v.params, run: bindExtension(reference, extensions.actions) };
    }
    case 'answer': {
      fields(v, ['type', 'records', 'rcode']);
      if (!Array.isArray(v.records)) throw new Error();
      return { type: 'answer', records: v.records.map(rr => { countRecord(); return validateRecord(rr); }), rcode: v.rcode === undefined ? 0 : integer(v.rcode, 15) };
    }
    case 'setTtl':
      fields(v, ['type', 'ttl']);
      return { type: 'setTtl', ttl: integer(v.ttl, 0xffffffff) };
    case 'rewriteQuery':
      fields(v, ['type', 'name', 'queryType']);
      if (v.name === undefined && v.queryType === undefined) throw new Error();
      return { type: 'rewriteQuery', name: v.name === undefined ? undefined : domain(v.name), queryType: v.queryType === undefined ? undefined : recordType(v.queryType) };
    case 'queryUpstream':
      fields(v, ['type', 'group']);
      if (v.group !== undefined && (typeof v.group !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(v.group))) throw new Error();
      return { type: 'queryUpstream', group: /** @type {string | undefined} */ (v.group) };
    case 'stop':
    case 'return':
      fields(v, ['type']);
      return { type: v.type };
    default: throw new Error();
  }
}
/** @param {Record<string, unknown>} env @param {import('./limits.js').Limits} limits @param {import('./types.js').ExtensionRegistry} [extensions] @param {ReturnType<typeof createConfigBudget>} [configBudget] @returns {import('./types.js').Group[]} */
export function loadGroups(env, limits, extensions = {}, configBudget = createConfigBudget(limits)) {
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
        const when = r.when === undefined ? undefined : compileCondition(r.when, configBudget.node, limits, configBudget.pattern, 0, undefined, extensions);
        if (!Array.isArray(r.actions) || r.actions.length === 0) throw new Error();
        actions += r.actions.length;
        within(actions, limits.maxActions, location);
        return { when, actions: r.actions.map((rawAction, actionIndex) => {
          location.action = actionIndex;
          return action(rawAction, () => within(++records, limits.maxRecords, location), extensions);
        }) };
      }) };
    } catch (error) {
      if (error instanceof RuleError) throw normalizeFailure(error, location);
      throw new RuleError('INVALID_CONFIG', 'Invalid or unsupported rule configuration.', location);
    }
  }).sort((a, b) => a.order - b.order || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}
