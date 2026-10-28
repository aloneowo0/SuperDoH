import { handleRequest } from '../src/worker.js';
import { loadIpLists } from '../src/rules/ip-lists.js';
import { loadLimits } from '../src/rules/limits.js';
import { createConfigBudget } from '../src/rules/config-budget.js';
import { createBudget, createNetworkAllowance } from '../src/doh/budget.js';
import { runCases } from '../lib/ip-list/test/cases.mjs';
import { compileList, cidr } from '../lib/ip-list/index.js';
import { createIpListStore } from '../lib/ip-list/index.js';
import { readBody } from '../src/doh/body.js';
import config from '../examples/meta-cf-ech-env-only/bindings.json';
import cf from '../examples/meta-cf-ech/cloudflare.txt';
import meta from '../examples/meta-cf-ech/facebook.txt';
const fixture='https://superdoh-iplist-fixture-20261028.aloneowo0.workers.dev';
const labels=['text','text2','json','fail','redirect','html','utf8','bad','large','slow','timeout','budget','cancel','entries','state','nullttl'];
export default {async fetch(request,bindings){
  if(Date.now()>Number(bindings.EXPIRES))return new Response('Expired',{status:410});
  const url=new URL(request.url),[kind,label]=url.pathname.slice(1).split('/');
  if(kind==='suite')return Response.json(await runCases());
  if(kind==='persistent'){
    const cache=await caches.open('superdoh-ip-list-test-l2-v1');
    const source='https://ip-list-fixture.invalid/snapshot?expires='+String(bindings.EXPIRES);
    const bytes=new TextEncoder().encode('192.0.2.0/24\n');let calls=0;
    const keyFor=async identity=>{
      const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(identity));
      return 'https://superdoh-ip-list-test.invalid/l2/'+Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('');
    };
    const cacheIO={
      async get(identity){
        const response=await cache.match(await keyFor(identity));if(!response)return undefined;
        const body=await readBody(response.body,8192,new AbortController().signal);
        return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));
      },
      async put(identity,data,ttl){
        await cache.put(await keyFor(identity),new Response(JSON.stringify(data),{headers:{'Content-Type':'application/json','Cache-Control':'public, max-age='+ttl}}));
      },
    };
    const options={source,format:'text',cacheTtl:3600,maxBytes:1024,maxEntries:8,maxStates:4,maxStateBytes:4096,cache:cacheIO,load:async()=>{calls++;return bytes;}};
    const first=await createIpListStore().load(options);
    const second=await createIpListStore().load(options);
    return Response.json({first:first.via,second:second.via,calls,firstStoredAt:first.storedAt,secondStoredAt:second.storedAt,match:second.index.contains('192.0.2.1')});
  }
  if(kind==='prepare'&&labels.includes(label)){
    const limits=loadLimits({maxNetworkRequests:4,maxExecutionTimeMs:5000,...(label==='large'?{maxIpListBytes:8}:{}),...(label==='entries'?{maxIpListEntries:1}:{}),...(label==='state'?{maxIpListStateBytes:1}:{}),...(['slow','timeout'].includes(label)?{ipListTimeoutMs:40}:{}),...(label==='timeout'?{maxExecutionTimeMs:10}:{})});
    const controller=new AbortController();if(label==='cancel')controller.abort();
    const budget=createBudget(limits.maxExecutionTimeMs,controller.signal);let calls=0;
    const allowance=createNetworkAllowance(label==='budget'?1:limits.maxNetworkRequests,budget);
    if(label==='budget')allowance();
    const env={DNS_IP_LISTS:{list:{url:fixture+'/'+(label==='timeout'?'slow':['budget','cancel','entries','state'].includes(label)?'text':label),format:label==='json'?'json':'text',cacheTtl:label==='text2'?3600:label==='nullttl'?null:0}}};
    try {
      const lists=loadIpLists(env,limits,createConfigBudget(limits));
      const snapshots=await lists.prepare(new Set(['list']),budget,()=>{calls++;allowance();});
      const value=snapshots.get('list');
      return Response.json({calls,code:'error'in value?value.error.code:'ok',entries:'index'in value?value.index.entries:null,match:'index'in value?value.index.contains('192.0.2.1'):false});
    }catch(error){return Response.json({calls,code:error instanceof Error&&'code'in error?error.code:'FAILED'});}
    finally{budget.dispose();}
  }
  if(kind==='equivalence'&&['cf','meta'].includes(label)){
    const key=label==='cf'?'cloudflare':'meta',snapshot=label==='cf'?cf:meta;
    const limits=loadLimits({maxExecutionTimeMs:10000,ipListTimeoutMs:5000});const budget=createBudget(10000);let calls=0;
    try{
      const list=loadIpLists({DNS_IP_LISTS:{[key]:config.DNS_IP_LISTS[key]}},limits,createConfigBudget(limits));
      const value=(await list.prepare(new Set([key]),budget,()=>calls++)).get(key);
      if('error'in value)return Response.json({passed:false,code:value.error.code});
      const reference=compileList(new TextEncoder().encode(snapshot),'text',4096,262144),ranges=snapshot.trim().split(/\r?\n/).map(cidr);let checked=0;
      for(const [i,r]of ranges.entries()){
        const start=r.network<<r.shift,end=start+(1n<<r.shift)-1n;
        for(const bits of [start,end,...(i%20===0?[start-1n,end+1n]:[])]){
          if(bits<0n||bits>=(1n<<BigInt(r.family)))continue;
          const canonical=r.family+':'+bits.toString(16);const actual=value.index.containsKey(canonical);
          if(actual!==reference.containsKey(canonical))throw Error('snapshot mismatch');
          if(i%20===0&&actual!==ranges.some(n=>n.family===r.family&&(bits>>n.shift)===n.network))throw Error('literal mismatch');
          checked++;
        }
      }
      return Response.json({passed:value.index.entries===ranges.length,entries:value.index.entries,checked,calls});
    }finally{budget.dispose();}
  }
  if(kind!=='dns'||!['cf','meta','meta-ip','non','negative','meta-domain','nov6','v4','v6','missing','unused','selector'].includes(label))return new Response('Not found',{status:404});
  const env=structuredClone(config);env.DNS_CACHE={read:false,write:false};
  env.DNS_UPSTREAMS.resolver.url=fixture+'/dns-'+(['cf','meta','meta-ip','non','negative'].includes(label)?(label==='meta-ip'?'meta':label):'non');
  env.DNS_UPSTREAMS.echPrimary.url=fixture+'/ech';env.DNS_UPSTREAMS.echSecondary.url=fixture+'/ech';
  if(['missing','unused','selector'].includes(label)){
    env.DNS_IP_LISTS={list:{url:fixture+'/text',format:'text',cacheTtl:0}};
    for(const key of Object.keys(env))if(key.startsWith('DNS_RULE_'))delete env[key];
    env.DNS_RULE_TEST={order:0,rules:[{actions:[{type:'answer',records:[]},{type:'return'}]},{when:{field:'client.ip',op:'inList',value:label==='missing'?'missing':'list'},actions:[{type:'return'}]}]};
    if(label==='unused')env.DNS_IP_LISTS.list.format='invalid';
    if(label==='selector')env.DNS_RULE_TEST.rules[1]={actions:[{type:'removeRecords',where:{field:'item.ip',op:'inList',value:'missing'}}]};
  }
  const destination=new URL(request.url);destination.pathname='/dns-query';const codes=[];
  const response=await handleRequest(new Request(destination,request),env,{onEvent:event=>codes.push(event.code)});
  const headers=new Headers(response.headers);headers.set('X-Ip-List-Codes',codes.join(','));
  return new Response(response.body,{status:response.status,headers});
}};
