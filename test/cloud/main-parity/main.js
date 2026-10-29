import { executeQuery } from '../../../src/index.js';
import { buildQuery, parseMessage, getRcode, getSvcParam, TYPES } from '../../../lib/dns-wasm/index.js';
import config from '../../../examples/meta-cf-ech-env-only/bindings.json';
import routes from '../../../examples/meta-cf-ech-env-only/meta-routes.json';
import { CF_ECH, META_ECH, scenarios } from './data.js';
import { runCore } from './core.js';
const assert=(value,label)=>{if(!value)throw Error(label);};
export const suiteNames=['core',...Array.from({length:6},(_,i)=>'map'+i),'ipv6','https0','https1','https2','https3','fallback','addresses','controls'];
export default {async fetch(request,env){
  const url=new URL(request.url),parts=url.pathname.split('/');
  if(!env.KEY || parts[1]!==env.KEY || request.headers.get('authorization')!==`Bearer ${env.KEY}` || request.method!=='POST')return new Response('',{status:404});
  const expiry=Number(env.EXPIRES);if(!Number.isFinite(expiry)||Date.now()>expiry||expiry>Date.now()+3600000)return new Response('',{status:410});
  const suite=parts[2];if(!suiteNames.includes(suite))return new Response('',{status:404});
  if(suite==='core')return Response.json(await runCore());
  const results=[];
  const test=async(name,fn)=>{try{await fn();results.push({name,passed:true});}catch(error){results.push({name,passed:false,error:String(error.code??error.message).slice(0,160)});}};
  const execute=async(name,type,scenario='empty')=>{
    assert(scenarios.includes(scenario),'unlisted fixture');
    const values=structuredClone(config),base=env.FIXTURE;
    values.DNS_UPSTREAMS={resolver:{transport:'https',url:base+'/'+scenario+'/resolver'},echPrimary:{transport:'https',url:base+'/'+scenario+'/primary'},echSecondary:{transport:'https',url:base+'/'+scenario+'/secondary'}};
    values.DNS_IP_LISTS=env.CHECK_IP_LISTS ? JSON.parse(env.CHECK_IP_LISTS) : {cloudflare:{url:base+'/cf-list',format:'text',cacheTtl:3600},meta:{url:base+'/meta-list',format:'text',cacheTtl:3600}};
    values.DNS_CACHE={read:false,write:false};
    values.DNS_ECS={mode:'client',upstreams:['resolver'],ipv4Prefix:24,ipv6Prefix:56};
    const result=await executeQuery(buildQuery(name,type),values,{context:{client:{ip:'203.0.113.9'}},onEvent(){}});
    const response=parseMessage(result.response);
    assert(response.questions[0].name===name&&response.questions[0].rtype===type,'client question changed');
    return response;
  };
  const https=async(name,scenario,expected)=>{
    const packet=await execute(name,65,scenario);
    assert(getRcode(packet)===0,'not NOERROR');
    assert(packet.answers.length===1&&packet.answers[0].rtype===65,'not a fresh HTTPS answer');
    const rr=packet.answers[0];assert(rr.name===name&&rr.rdata.Https.priority===1&&rr.rdata.Https.target==='.', 'owner or ServiceMode');
    assert(getSvcParam(rr,5)===expected,'ECH bytes mismatch');
    assert(!(packet.flags&0x20),'rewritten AD retained');
  };
  if(suite.startsWith('map')){
    const entries=[...routes.exact.map(([name,ip])=>[name,ip]),...routes.suffix.map(([name,ip])=>['asset.'+name,ip])];
    for(const[name,ip]of entries.slice(Number(suite.slice(3))*5,Number(suite.slice(3))*5+5))await test('route:'+name,async()=>{
      const p=await execute(name,1);assert(getRcode(p)===0&&p.answers.length===1&&p.answers[0].name===name&&p.answers[0].rdata.A?.addr===ip,'main route mismatch');
    });
  }else if(suite==='ipv6'){
    for(const name of ['www.facebook.com','www.instagram.com','asset.fbcdn.net','x.com','pbs.twimg.com'])await test('no-v6:'+name,async()=>{const p=await execute(name,28);assert(getRcode(p)===0&&!p.answers.length,'AAAA not empty');});
  }else if(suite.startsWith('https')){
    const scenario=['empty','cname','alias','existing'][Number(suite.slice(5))];
    for(const name of ['x.com','asset.cdninstagram.com','asset.facebook.com'])await test('https:'+scenario+':'+name,()=>https(name,scenario,name.endsWith('x.com')?CF_ECH:META_ECH));
  }else if(suite==='fallback'){
    await test('secondary-source-no-client-ECS',()=>https('www.x.com','secondary',CF_ECH));
    await test('both-ECH-sources-fail-preserve-CNAME',async()=>{const p=await execute('x.com',65,'echfail');assert(p.answers.length===1&&p.answers[0].rtype===5,'original lost');});
    for(const scenario of ['negative','refused'])for(const name of ['x.com','www.facebook.com'])await test('negative:'+scenario+':'+name,async()=>{const p=await execute(name,65,scenario);assert(getRcode(p)===(scenario==='negative'?3:5)&&!p.answers.length,'negative fabricated');});
  }else if(suite==='addresses'){
    for(const scenario of ['preferred','prefempty','prefbad','prefnx','preferr'])await test('CF-address:'+scenario,async()=>{
      const p=await execute('x.com',1,scenario),ip=scenario==='preferred'?'192.0.2.10':'192.0.2.99';
      assert(getRcode(p)===0&&p.answers.length===1&&p.answers[0].rtype===1&&p.answers[0].name==='x.com'&&p.answers[0].rdata.A.addr===ip,'preferred/fallback mismatch');
      if(scenario==='preferred')assert(p.answers[0].ttl===60,'preferred TTL');
    });
    await test('negative-original-A-not-overridden',async()=>{const p=await execute('x.com',1,'negative');assert(getRcode(p)===3&&!p.answers.length,'NXDOMAIN fabricated');});
  }else if(suite==='controls'){
    await test('unrelated-A-not-remapped',async()=>{const p=await execute('notfacebook.example',1);assert(p.answers[0].rdata.A.addr==='203.0.113.22','unrelated affected');});
    await test('unrelated-AAAA-retained',async()=>{const p=await execute('example.net',28);assert(p.answers[0].rtype===28,'non-target blocked');});
    await test('unrelated-HTTPS-not-synthesized',async()=>{const p=await execute('example.net',65,'non-target');assert(!p.answers.length,'non-target ECH injected');});
    await test('IP-classified-Meta-HTTPS-synthesized',()=>https('ip-meta.example','meta-ip',META_ECH));
    await test('native-CF-ECH-still-applied',()=>https('native-cf.example','native-cf',CF_ECH));
  }
  return Response.json({suite,passed:results.length>0&&results.every(r=>r.passed),results});
}};
