import fs from 'node:fs/promises';
const dir = new URL('../examples/meta-cf-ech-env-only/', import.meta.url);
const original = JSON.parse(await fs.readFile(new URL('bindings.literal.json', dir), 'utf8'));
const env = structuredClone(original);
const keys = Object.keys(env).filter(key => /^DNS_RULE_ENV_(CF|META_IP)_\d+$/.test(key));
for (const key of keys) delete env[key];
env.DNS_IP_LISTS = Object.fromEntries([['cloudflare','cloudflare'],['meta','facebook']].map(([name,file]) => [name, { url: `https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/${file}.txt`, format: 'text', cacheTtl: 3600 }]));
env.DNS_LIMITS.maxNetworkRequests = 6;
for (const [kind, name] of [['CF','cloudflare'],['META_IP','meta']]) {
  const oldKey = `DNS_RULE_ENV_${kind}_00`, key = `DNS_RULE_ENV_${kind}`;
  const group = JSON.parse(JSON.stringify(original[oldKey]).split(oldKey).join(key));
  group.rules[0].when.all[3].where.all[2] = { field: 'item.ip', op: 'inList', value: name };
  env[key] = group;
}
const sizes = Object.fromEntries(Object.entries(env).map(([key,value]) => [key, Buffer.byteLength(JSON.stringify(value))]));
if (Math.max(...Object.values(sizes)) > 5000) throw Error('Variable exceeds 5KB');
const groups = Object.keys(env).filter(key => key.startsWith('DNS_RULE_'));
const report = { status: 'candidate-not-deployed', requires: 'Remote IP list library and thin runtime adapter; not compatible with unchanged production code', previousVariables: Object.keys(original).length, variables: Object.keys(env).length, groups: groups.length, cacheTtl: 3600, removedCidrShards: keys.length, maximumVariableBytes: Math.max(...Object.values(sizes)), variableSizes: sizes };
await fs.writeFile(new URL('bindings.json', dir), JSON.stringify(env) + '\n');
await fs.writeFile(new URL('dashboard.txt', dir), Object.entries(env).map(([key,value])=>key+'\n'+JSON.stringify(value)).join('\n\n')+'\n');
await fs.writeFile(new URL('report.json', dir), JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report));
