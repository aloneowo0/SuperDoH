import { buildResponse, parseMessage, encodeMessage, getEcs, setEcs, setSvcParam, TYPES } from '../../../lib/dns-wasm/index.js';
import { CF_ECH, scenarios } from './data.js';
export default { async fetch(request,env) {
  const url=new URL(request.url),parts=url.pathname.split('/');
  if(!env.KEY || parts[1]!==env.KEY)return new Response('',{status:404});
  const expires=Number(env.EXPIRES);if(!Number.isFinite(expires)||Date.now()>expires||expires>Date.now()+3600000)return new Response('',{status:410});
  if(parts[2]==='cf-list')return new Response('192.0.2.0/24\n',{headers:{'content-type':'text/plain'}});
  if(parts[2]==='meta-list')return new Response('198.51.100.0/24\n',{headers:{'content-type':'text/plain'}});
  const scenario=parts[2],role=parts[3];
  if(!scenarios.includes(scenario)||!['resolver','primary','secondary'].includes(role)||request.method!=='POST')return new Response('',{status:404});
  const body=await request.arrayBuffer();if(body.byteLength>4096)return new Response('',{status:413});
  const q=parseMessage(new Uint8Array(body)),question=q.questions[0];if(q.questions.length!==1||![1,28,65].includes(question.rtype))return new Response('',{status:400});
  const ecs=getEcs(q);if(role!=='resolver'&&ecs)return new Response('Unexpected client ECS',{status:400});
  if((scenario==='echfail'&&role!=='resolver')||(scenario==='secondary'&&role==='primary'))return new Response('',{status:503});
  const preferred=question.name==='cf.090227.xyz';
  if(preferred&&scenario==='preferr')return new Response('',{status:503});
  const rcode=scenario==='negative'||(preferred&&scenario==='prefnx')?3:scenario==='refused'?5:0;
  const cname={name:question.name,rtype:5,class:1,ttl:30,rdata:{Cname:{cname:'alias.example'}}};
  const https={name:question.name,rtype:65,class:1,ttl:30,rdata:{Https:{priority:1,target:'.',params:[{key:1,data:[2,104,50]}]}}};
  let answers=[];
  if(!rcode) {
    if(role!=='resolver'){setSvcParam(https,5,CF_ECH);answers=[https];}
    else if(question.rtype===1){
      const ip=preferred?(scenario==='prefbad'?'203.0.113.2':'192.0.2.10'):scenario==='meta-ip'?'198.51.100.2':scenario==='native-cf'?'192.0.2.20':question.name==='x.com'?'192.0.2.99':'203.0.113.22';
      if(!(preferred&&scenario==='prefempty'))answers=[{name:question.name,rtype:1,class:1,ttl:30,rdata:{A:{addr:ip}}}];
      if(preferred&&scenario==='preferred')answers=[cname,{name:'alias.example',rtype:1,class:1,ttl:30,rdata:{A:{addr:ip}}},{name:'alias.example',rtype:1,class:1,ttl:30,rdata:{A:{addr:'203.0.113.2'}}}];
    } else if(question.rtype===28) answers=[{name:question.name,rtype:28,class:1,ttl:30,rdata:{Aaaa:{addr:'2001:db8::1'}}}];
    else if(scenario==='cname'||scenario==='echfail')answers=[cname];
    else if(scenario==='alias')answers=[{...https,rdata:{Https:{priority:0,target:'alias.example',params:[]}}}];
    else if(scenario==='existing'||scenario==='native-cf')answers=[https];
  }
  const response=parseMessage(buildResponse(q,{rcode,answers}));
  const opt=q.additional.find(r=>r.rtype===TYPES.OPT);if(opt)response.additional.push(structuredClone(opt));if(ecs)setEcs(response,{...ecs,scope_prefix:0});
  return new Response(encodeMessage(response),{headers:{'content-type':'application/dns-message'}});
}};
