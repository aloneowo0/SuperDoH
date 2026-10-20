import { within } from './limits.js';
import { decodeRdata, encodeRdata, typeCode, TYPES } from '../../lib/dns-wasm/index.js';
import { RuleError } from './errors.js';

/** @param {unknown} value @returns {Record<string, unknown>} */
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  return /** @type {Record<string, unknown>} */ (value);
}
/** @param {unknown} value @param {string[]} allowed @returns {Record<string, unknown>} */
function fields(value, allowed) {
  const result = object(value);
  if (Object.keys(result).some(key => !allowed.includes(key))) throw new Error();
  return result;
}
/** @param {unknown} value @param {number} max @returns {number} */
function integer(value, max) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > max) throw new Error();
  return value;
}
/** @param {unknown} value @returns {number} */
export function recordType(value) {
  return integer(typeof value === 'string' ? typeCode(value) : value, 65535);
}
/** @param {unknown} value @returns {string} */
export function domain(value) {
  if (typeof value !== 'string' || value.length > 254) throw new Error();
  const normalized = value.replace(/\.$/, '').toLowerCase();
  if (value === '.') return '.';
  if (!normalized || normalized.length > 253 || normalized.split('.').some(label => !/^[a-z0-9_-]{1,63}$/.test(label))) throw new Error();
  return normalized;
}
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
function record(value) {
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
/** @param {unknown} value @param {() => void} countRecord @returns {import('./types.js').Action} */
function action(value, countRecord) {
  const { onError, ...body } = object(value);
  if (onError !== undefined && onError !== 'fail' && onError !== 'continue') throw new Error();
  return { ...actionValue(body, countRecord), onError: onError ?? 'fail' };
}
/** @param {unknown} value @param {() => void} countRecord @returns {import('./types.js').Action} */
function actionValue(value, countRecord) {
  const v = object(value);
  switch (v.type) {
    case 'answer': {
      fields(v, ['type', 'records', 'rcode']);
      if (!Array.isArray(v.records)) throw new Error();
      return { type: 'answer', records: v.records.map(rr => { countRecord(); return record(rr); }), rcode: v.rcode === undefined ? 0 : integer(v.rcode, 15) };
    }
    case 'setTtl':
      fields(v, ['type', 'ttl']);
      return { type: 'setTtl', ttl: integer(v.ttl, 0xffffffff) };
    case 'rewriteQuery':
      fields(v, ['type', 'name', 'queryType']);
      if (v.name === undefined && v.queryType === undefined) throw new Error();
      return { type: 'rewriteQuery', name: v.name === undefined ? undefined : domain(v.name), queryType: v.queryType === undefined ? undefined : recordType(v.queryType) };
    case 'stop':
    case 'return':
      fields(v, ['type']);
      return { type: v.type };
    default: throw new Error();
  }
}
/** @param {unknown} value @param {() => void} countNode @param {number} [depth] @returns {import('./types.js').Condition} */
function condition(value, countNode, depth = 0) {
  countNode();
  if (depth > 16) throw new Error();
  const v = object(value);
  for (const key of ['all', 'any']) {
    if (key in v) {
      fields(v, [key]);
      const children = v[key];
      if (!Array.isArray(children) || children.length === 0) throw new Error();
      const parsed = children.map(child => condition(child, countNode, depth + 1));
      return key === 'all' ? { all: parsed } : { any: parsed };
    }
  }
  if ('not' in v) {
    fields(v, ['not']);
    return { not: condition(v.not, countNode, depth + 1) };
  }
  fields(v, ['field', 'op', 'value']);
  if ((v.field === 'query.name' || v.field === 'original.name') && (v.op === 'exact' || v.op === 'suffix' || v.op === 'subdomain')) {
    return { field: v.field, op: v.op, value: domain(v.value) };
  }
  if ((v.field === 'query.type' || v.field === 'original.type') && v.op === 'eq') {
    return { field: v.field, op: 'eq', value: recordType(v.value) };
  }
  if (v.field === 'response.exists' && v.op === 'eq' && typeof v.value === 'boolean') {
    return { field: v.field, op: 'eq', value: v.value };
  }
  if (v.field === 'response.rcode' && v.op === 'eq') {
    return { field: v.field, op: 'eq', value: integer(v.value, 15) };
  }
  throw new Error();
}
/** @param {Record<string, unknown>} env @param {import('./limits.js').Limits} limits @returns {import('./types.js').Group[]} */
export function loadGroups(env, limits) {
  const entries = Object.entries(env).filter(([name]) => name.startsWith('DNS_RULE_'));
  within(entries.length, limits.maxGroups);
  let totalBytes = 0, rules = 0, actions = 0, records = 0, nodes = 0;
  return entries.map(([name, raw]) => {
    /** @type {import('./errors.js').Location} */
    const location = { group: /^[A-Za-z0-9_]{1,128}$/.test(name) ? name : '<invalid>' };
    try {
      if (location.group === '<invalid>') throw new Error();
      const text = typeof raw === 'string' ? raw : JSON.stringify(raw);
      if (typeof text !== 'string') throw new Error();
      within(text.length, limits.maxGroupBytes, location);
      const size = new TextEncoder().encode(text).byteLength;
      within(size, limits.maxGroupBytes, location);
      totalBytes += size;
      within(totalBytes, limits.maxConfigBytes, location);
      const v = fields(JSON.parse(text), ['order', 'rules']);
      if (!Number.isSafeInteger(v.order) || !Array.isArray(v.rules)) throw new Error();
      rules += v.rules.length;
      within(rules, limits.maxRules, location);
      return { name, order: /** @type {number} */ (v.order), rules: v.rules.map((rawRule, ruleIndex) => {
        location.rule = ruleIndex;
        delete location.action;
        const r = fields(rawRule, ['when', 'actions']);
        const when = r.when === undefined ? undefined : condition(r.when, () => within(++nodes, limits.maxConditionNodes, location));
        if (!Array.isArray(r.actions) || r.actions.length === 0) throw new Error();
        actions += r.actions.length;
        within(actions, limits.maxActions, location);
        return { when, actions: r.actions.map((rawAction, actionIndex) => {
          location.action = actionIndex;
          return action(rawAction, () => within(++records, limits.maxRecords, location));
        }) };
      }) };
    } catch (error) {
      if (error instanceof RuleError) throw error;
      throw new RuleError('INVALID_CONFIG', 'Invalid or unsupported rule configuration.', location);
    }
  }).sort((a, b) => a.order - b.order || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}
