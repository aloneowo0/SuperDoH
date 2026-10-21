import { getRcode } from '../../lib/dns-wasm/index.js';
import { within } from './limits.js';
import { ip, cidr } from './ip.js';
import { RE2JS } from 're2js';
import { fields, domain, recordType, integer } from './values.js';

/** @typedef {{ current: import('../../lib/dns-wasm/index.js').DnsQuestion, original: Readonly<import('../../lib/dns-wasm/index.js').DnsQuestion>, response: import('../../lib/dns-wasm/index.js').DnsMessage | null, spend: () => void, lastAction?: import('./types.js').ActionResult, item?: Record<string, string | number | boolean>, properties: ReturnType<typeof import('./context.js').loadContext> }} MatchContext */
/** @typedef {(context: MatchContext) => boolean | Promise<boolean>} Predicate */
const kinds = /** @type {Record<string, string>} */ ({
  'query.name': 'name', 'original.name': 'name', 'query.type': 'type', 'original.type': 'type',
  'response.exists': 'boolean', 'response.rcode': 'rcode',
  'lastAction.success': 'boolean', 'lastAction.actionType': 'text', 'lastAction.code': 'text',
  'lastAction.group': 'text', 'lastAction.rule': 'number', 'lastAction.action': 'number',
  ...Object.fromEntries(['client', 'edge'].flatMap(prefix => [
    [prefix + '.ip', 'ip'], [prefix + '.asn', 'number'],
    ...['country', 'region', 'city', 'colo'].map(field => [prefix + '.' + field, 'text']),
  ])),
});
/** @param {string} kind @param {unknown} value @returns {string | number | boolean} */
function scalar(kind, value) {
  if (kind === 'ip') return ip(value).key;
  if (kind === 'number') return integer(value, 0xffffffff);
  if (kind === 'section' && (value === 'answer' || value === 'authority' || value === 'additional')) return value;
  if (kind === 'text' && typeof value === 'string' && value.length > 0 && value.length <= 128) return value;
  if (kind === 'name') return domain(value);
  if (kind === 'type') return recordType(value);
  if (kind === 'rcode') return integer(value, 4095);
  if (kind === 'boolean' && typeof value === 'boolean') return value;
  throw new Error();
}
/** @param {MatchContext} context @param {string} field @returns {string | number | boolean | undefined} */
function read(context, field) {
  if (field.startsWith('lastAction.')) {
    const result = context.lastAction;
    if (field === 'lastAction.success') return result?.success;
    if (field === 'lastAction.actionType') return result?.actionType;
    if (field === 'lastAction.code') return result?.code;
    if (field === 'lastAction.group') return result?.location.group;
    if (field === 'lastAction.rule') return result?.location.rule;
    return result?.location.action;
  }
  if (field.startsWith('item.')) return context.item?.[field.slice(5)];
  if (field.startsWith('client.') || field.startsWith('edge.')) {
    const [prefix, key] = field.split('.');
    const attrs = prefix === 'client' ? context.properties.client : context.properties.edge;
    const actual = attrs[/** @type {keyof typeof attrs} */ (key)];
    return key === 'ip' && typeof actual === 'string' ? ip(actual).key : actual;
  }
  if (field === 'response.exists') return context.response !== null;
  if (field === 'response.rcode') return context.response ? getRcode(context.response) : undefined;
  const question = field.startsWith('original.') ? context.original : context.current;
  return field.endsWith('.type') ? question.rtype : domain(question.name);
}
/** @param {unknown} value @param {() => void} countNode @param {import('./limits.js').Limits} limits @param {(size: number) => void} countPattern @param {number} [depth] @param {string} [scope] @returns {Predicate} */
export function compileCondition(value, countNode, limits, countPattern, depth = 0, scope) {
  const predicate = compile(value, countNode, limits, countPattern, depth, scope);
  return async context => { context.spend(); return predicate(context); };
}
/** @param {unknown} value @param {() => void} countNode @param {import('./limits.js').Limits} limits @param {(size: number) => void} countPattern @param {number} depth @param {string | undefined} scope @returns {Predicate} */
function compile(value, countNode, limits, countPattern, depth, scope) {
  countNode();
  within(depth, limits.maxConditionDepth);
  const v = fields(value, ['all', 'any', 'not', 'field', 'op', 'value', 'collection', 'quantifier', 'where']);
  for (const key of ['all', 'any']) {
    if (key in v) {
      fields(v, [key]);
      const children = v[key];
      if (!Array.isArray(children) || !children.length) throw new Error();
      const parsed = children.map(child => compileCondition(child, countNode, limits, countPattern, depth + 1, scope));
      return async context => {
        for (const child of parsed) {
          const hit = await child(context);
          if (key === 'all' && !hit) return false;
          if (key === 'any' && hit) return true;
        }
        return key === 'all';
      };
    }
  }
  if ('not' in v) {
    fields(v, ['not']);
    const child = compileCondition(v.not, countNode, limits, countPattern, depth + 1, scope);
    return async context => !await child(context);
  }
  if ('collection' in v) {
    fields(v, ['collection', 'quantifier', 'where']);
    if (scope || (v.collection !== 'response.addresses' && v.collection !== 'response.records') || (v.quantifier !== 'any' && v.quantifier !== 'all')) throw new Error();
    const collection = v.collection;
    const child = compileCondition(v.where, countNode, limits, countPattern, depth + 1, collection === 'response.records' ? 'records' : 'addresses');
    return async context => {
      let seen = false;
      if (!context.response) return false;
      for (const [section, records] of /** @type {const} */ ([['answer', context.response.answers], ['authority', context.response.authority], ['additional', context.response.additional]])) {
        for (const record of records) {
          context.spend();
          const address = 'A' in record.rdata ? record.rdata.A.addr : 'Aaaa' in record.rdata ? record.rdata.Aaaa.addr : undefined;
          if (collection === 'response.addresses' && !address) continue;
          seen = true;
          /** @type {Record<string, string | number | boolean>} */
          const item = { name: domain(record.name), type: record.rtype, ttl: record.ttl, section };
          if (collection === 'response.addresses' && address) {
            const key = ip(address).key;
            Object.assign(item, context.properties.addresses.get(key), { ip: key });
          } else {
            const target = recordTarget(record.rdata);
            if (target !== undefined) item.target = domain(target);
          }
          const hit = await child({ ...context, item });
          if (v.quantifier === 'any' && hit) return true;
          if (v.quantifier === 'all' && !hit) return false;
        }
      }
      return seen && v.quantifier === 'all';
    };
  }
  fields(v, ['field', 'op', 'value']);
  /** @type {Record<string, string>} */
  const itemKinds = scope === 'addresses' ? { 'item.ip': 'ip', 'item.asn': 'number', 'item.country': 'text', 'item.region': 'text', 'item.city': 'text', 'item.name': 'name', 'item.type': 'type', 'item.ttl': 'number', 'item.section': 'section' } : scope === 'records' ? { 'item.name': 'name', 'item.type': 'type', 'item.target': 'name', 'item.ttl': 'number', 'item.section': 'section' } : {};
  /** @type {Record<string, string>} */
  const available = { ...kinds, ...itemKinds };
  if (typeof v.field !== 'string' || !Object.hasOwn(available, v.field)) throw new Error();
  const field = v.field, kind = available[field], op = v.op;
  if (op === 'exists') {
    if (typeof v.value !== 'boolean') throw new Error();
    return context => (read(context, field) !== undefined) === v.value;
  }
  if (op === 'in') {
    if (!Array.isArray(v.value) || !v.value.length) throw new Error();
    within(v.value.length, limits.maxConditionValues);
    const values = new Set(v.value.map(item => scalar(kind, item)));
    return context => { const actual = read(context, field); return actual !== undefined && values.has(actual); };
  }
  if (kind === 'name' && (op === 'wildcard' || op === 'regex')) {
    if (typeof v.value !== 'string' || !v.value.length) throw new Error();
    within(v.value.length, limits.maxPatternLength);
    let pattern = v.value;
    if (op === 'wildcard') {
      const labels = pattern === '.' ? [] : pattern.replace(/\.$/, '').toLowerCase().split('.');
      if (labels.some(label => label !== '*' && label !== '**' && domain(label) !== label)) throw new Error();
      pattern = '^' + labels.map(label => label === '**' ? '(?:[^.]+[.])*' : label === '*' ? '[^.]+[.]' : label + '[.]').join('') + '$';
    }
    const regex = RE2JS.compile(pattern, RE2JS.CASE_INSENSITIVE);
    countPattern(regex.programSize());
    return context => {
      const actual = read(context, field);
      return typeof actual === 'string' && regex.matcher(op === 'wildcard' ? (actual === '.' ? '' : actual + '.') : actual).find();
    };
  }
  if (kind === 'ip' && op === 'cidr') {
    const network = cidr(v.value);
    return context => {
      const key = read(context, field);
      if (typeof key !== 'string') return false;
      const [family, hex] = key.split(':');
      return Number(family) === network.family && (BigInt('0x' + hex) >> network.shift) === network.network;
    };
  }
  const expected = scalar(kind, v.value);
  if (op === 'eq' || op === 'ne') return context => {
    const actual = read(context, field);
    return actual !== undefined && (op === 'eq' ? actual === expected : actual !== expected);
  };
  if ((kind === 'rcode' || kind === 'number') && typeof expected === 'number' && ['lt', 'lte', 'gt', 'gte'].includes(String(op))) return context => {
    const actual = read(context, field);
    if (typeof actual !== 'number') return false;
    return op === 'lt' ? actual < expected : op === 'lte' ? actual <= expected : op === 'gt' ? actual > expected : actual >= expected;
  };
  if (kind === 'name' && typeof expected === 'string' && ['exact', 'suffix', 'subdomain'].includes(String(op))) return context => {
    const actual = read(context, field);
    if (typeof actual !== 'string') return false;
    const subdomain = expected === '.' ? actual !== '.' : actual.endsWith(`.${expected}`);
    return op === 'exact' ? actual === expected : op === 'suffix' ? actual === expected || subdomain : subdomain;
  };
  throw new Error();
}
/** @param {import('../../lib/dns-wasm/index.js').Rdata} data */
function recordTarget(data) {
  if ('Cname' in data) return data.Cname.cname;
  if ('Dname' in data) return data.Dname.dname;
  if ('Ns' in data) return data.Ns.nsdname;
  if ('Ptr' in data) return data.Ptr.ptrdname;
  if ('Mx' in data) return data.Mx.exchange;
  if ('Srv' in data) return data.Srv.target;
  if ('Svcb' in data) return data.Svcb.target;
  if ('Https' in data) return data.Https.target;
  return undefined;
}
/** @param {Predicate | undefined} condition @param {MatchContext['current']} current @param {MatchContext['original']} original @param {MatchContext['response']} response @param {MatchContext['properties']} properties @param {() => void} spend @param {MatchContext['lastAction']} [lastAction] */
export function matches(condition, current, original, response, properties, spend, lastAction) {
  return condition ? condition({ current, original, response, properties, spend, lastAction }) : true;
}
