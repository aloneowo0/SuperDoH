import fs from 'node:fs/promises';
const dir = new URL('../examples/meta-cf-ech-env-only/', import.meta.url);
const env = JSON.parse(await fs.readFile(new URL('bindings.json', dir), 'utf8'));
const routes = JSON.parse(await fs.readFile(new URL('meta-routes.json', dir), 'utf8'));
const metaEch = env.DNS_RULE_ENV_META_QUERY.rules.flatMap(r => r.actions).find(a => a.type === 'loadEch')?.config ?? env.DNS_RULE_ENV_META_IP.rules[1].actions.find(a => a.type === 'loadEch').config;
const field = (name, op, value) => ({ field: name, op, value });
const all = (...conditions) => ({ all: conditions });
const type = value => field('original.type', 'eq', value);
const list = value => field('original.name', 'inListSuffix', value);
const success = all(field('lastAction.success', 'eq', true), field('lastAction.actionType', 'eq', 'queryEch'));
const query = { type: 'queryUpstream', upstream: 'resolver' };
const done = { type: 'return' };
const owner = { from: 'original.name' };
const https = { type: 'answer', records: [{ name: owner, type: 'HTTPS', ttl: 300, rdata: { Https: { priority: 1, target: '.', params: [{ key: 1, data: [2,104,50,2,104,51] }] } } }] };
const cfAddress = all(field('item.section','eq','answer'),field('item.type','eq','A'),field('item.ip','inList','cloudflare'));
const hasCf = { collection: 'response.records', quantifier: 'any', where: cfAddress };
const remapA = all(type('A'), list('cfRemap'));
const remapHttps = all(type('HTTPS'), list('cfRemap'));
const preferred = 'cf.090227.xyz';
for (const key of Object.keys(env)) if (/^DNS_RULE_ENV_META_A_\d+$/.test(key) || /^DNS_RULE_ENV_META_FIXED_\d+$/.test(key)) delete env[key];
env.DNS_DOMAIN_LISTS.meta.domains = [...new Set([...env.DNS_DOMAIN_LISTS.meta.domains, ...routes.exact.map(([name]) => name), ...routes.suffix.map(([name]) => name)])];
env.DNS_RULE_ENV_NO_IPV6 = { order: -30, rules: [{ when: all(type('AAAA'), { any: [list('meta'), list('cfRemap')] }), actions: [{ type: 'answer', records: [], rcode: 0 }, done] }] };
const routeRule = ([name, address], op) => ({ when: all(type('A'), field('original.name', op, name)), actions: [{ type: 'answer', records: [{ name: owner, type: 'A', ttl: 300, rdata: { A: { addr: address } } }] }, done] });
let chunk = [], chunkIndex = 0;
for (const entry of routes.exact) {
  const rule = routeRule(entry, 'eq');
  if (Buffer.byteLength(JSON.stringify({ order: -20, rules: [...chunk, rule] })) > 4800) { env[`DNS_RULE_ENV_META_A_${chunkIndex++}`] = { order: -20, rules: chunk }; chunk = []; }
  chunk.push(rule);
}
if (chunk.length) env[`DNS_RULE_ENV_META_A_${chunkIndex}`] = { order: -20, rules: chunk };
env.DNS_RULE_ENV_META_A_SUFFIX = { order: -19, rules: routes.suffix.map(entry => routeRule(entry, 'suffix')) };
env.DNS_RULE_ENV_CF_ADDRESS = { order: -10, rules: [
  { when: remapA, actions: [query] },
  { when: all(remapA, field('response.rcode', 'ne', 0)), actions: [done] },
  { when: remapA, actions: [{ type: 'rewriteQuery', name: preferred, queryType: 'A' }, { ...query, onError: 'continue' }] },
  { when: all(remapA, field('lastAction.success','eq',true), field('response.rcode','eq',0), hasCf), actions: [
    { type: 'removeRecords', where: all(field('item.section','eq','answer'), { any: [field('item.type','eq','CNAME'), all(field('item.type','eq','A'), { not: field('item.ip','inList','cloudflare') })] }) },
    { type: 'setRecordName', name: owner, where: cfAddress },
    { type: 'setTtl', ttl: 60, where: cfAddress }, done,
  ] },
  { when: remapA, actions: [{ type: 'rewriteQuery', name: owner, queryType: 'A' }, query, done] },
] };
env.DNS_RULE_ENV_META_QUERY = { order: 1, rules: [{ when: type('HTTPS'), actions: [query] }] };
env.DNS_RULE_ENV_META_SUFFIX = { order: 2, rules: [
  { when: all(type('HTTPS'),list('meta'),field('response.rcode','eq',0)), actions: [{ type: 'loadEch', config: metaEch }, https, { type: 'applyEch' }, done] },
  { when: all(type('HTTPS'),list('meta')), actions: [done] },
] };
env.DNS_RULE_ENV_CF_REMAP = { order: 3, rules: [
  { when: all(remapHttps,field('response.rcode','eq',0)), actions: [{ type: 'queryEch', name: 'cloudflare-ech.com', upstream: 'echPrimary', cache: { read:true,write:true,maxTtl:600 }, onError:'continue' }] },
  { when: all(remapHttps,field('lastAction.group','eq','DNS_RULE_ENV_CF_REMAP'),field('lastAction.actionType','eq','queryEch'),field('lastAction.success','eq',false)), actions: [{ type:'queryEch', name:'cloudflare-ech.com', upstream:'echSecondary', cache:{read:true,write:true,maxTtl:600},onError:'continue' }] },
  { when: all(remapHttps,field('lastAction.group','eq','DNS_RULE_ENV_CF_REMAP'),success), actions:[https,{type:'applyEch'},done] },
  { when: remapHttps, actions:[done] },
] };
// IP-classified non-Meta names use the same fresh answer owner rather than assuming an existing HTTPS record.
const ipMeta = env.DNS_RULE_ENV_META_IP.rules[1].actions;
if (!ipMeta.some(a => a.type === 'answer')) ipMeta.splice(ipMeta.findIndex(a => a.type === 'applyEch'),0,https);
const ordered = Object.fromEntries(Object.entries(env).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
const variableSizes = Object.fromEntries(Object.entries(ordered).map(([name,value])=>[name,Buffer.byteLength(JSON.stringify(value))]));
if (Math.max(...Object.values(variableSizes)) > 5000 || Buffer.byteLength(JSON.stringify(ordered)) > 65536) throw Error('Generated configuration exceeds deployment budget');
const report = { sourceCommit: routes.commit, preferred, exactRoutes: routes.exact.length, suffixRoutes: routes.suffix.length, variables: Object.keys(env).length, variableSizes, totalBytes: Buffer.byteLength(JSON.stringify(ordered)) };
await fs.writeFile(new URL('bindings.json',dir),JSON.stringify(ordered)+'\n');
await fs.writeFile(new URL('dashboard.txt',dir),Object.entries(ordered).map(([k,v])=>k+'\n'+JSON.stringify(v)).join('\n\n')+'\n');
await fs.writeFile(new URL('main-parity-report.json',dir),JSON.stringify(report,null,2)+'\n');
const previous = JSON.parse(await fs.readFile(new URL('report.json',dir),'utf8'));
await fs.writeFile(new URL('report.json',dir),JSON.stringify({ ...previous, variables: report.variables, groups: Object.keys(ordered).filter(k=>k.startsWith('DNS_RULE_')).length, maximumVariableBytes: Math.max(...Object.values(variableSizes)), variableSizes, mainParity: routes.commit },null,2)+String.fromCharCode(10));
console.log(JSON.stringify(report,null,2));
