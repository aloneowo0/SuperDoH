import fs from'node:fs';import path from'node:path';import net from'node:net';import{fileURLToPath}from'node:url';import{build}from'esbuild';import{Miniflare,Log,LogLevel}from'miniflare';import{query,decode,responseWire}from'./helpers/dns-wire.mjs';
import assert from'node:assert/strict';

// Opt-in local diagnostic only; no deployment, credentials or public upstreams.
if(process.argv.length!==2)throw Error('This diagnostic accepts no endpoint or mode arguments');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const outputRoot=path.join(root,'.acceptance');fs.mkdirSync(outputRoot,{recursive:true});
const dir=fs.mkdtempSync(path.join(outputRoot,'local-profiles-'));
console.log(JSON.stringify({outputDirectory:path.relative(root,dir)}));
const bundled=await build({entryPoints:[path.join(root,'src/worker.js')],bundle:true,write:false,external:['cloudflare:sockets'],format:'esm',platform:'browser',plugins:[{name:'external-wasm',setup(api){api.onResolve({filter:/[.]wasm$/},args=>({path:'../'+path.relative(root,path.resolve(args.resolveDir,args.path)).split(path.sep).join('/'),external:true}));}}]});
const sockets=new Set();let connections=0;
const server=net.createServer(socket=>{connections++;sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.once('data',()=>socket.end(Buffer.from([21,3,3,0,2,2,40])));});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const fixed={type:'answer',records:[{name:'example.com',type:'A',ttl:60,rdata:{A:{addr:'192.0.2.8'}}}]};
async function profileCase(label,bindings,count){
 const events=[];let sourceCalls=0;
 const mf=new Miniflare({name:'local-cpu-profile',inspectorPort:0,inspectorHost:'127.0.0.1',modules:true,modulesRoot:root,scriptPath:path.join(root,'test/local-profile-bundle.js'),script:bundled.outputFiles[0].text,compatibilityDate:'2026-07-30',compatibilityFlags:['enable_request_signal','global_fetch_strictly_public'],bindings,log:new Log(LogLevel.NONE),handleRuntimeStdio(stdout,stderr){for(const stream of[stdout,stderr])stream.setEncoding('utf8').on('data',text=>events.push(text));},modulesRules:[{type:'ESModule',include:['**/*.js'],fallthrough:true},{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],outboundService:async request=>{const host=new URL(request.url).hostname;if(host!=='lists.test'&&host!=='delay.test')throw Error('Unexpected nonlocal source');sourceCalls++;if(host==='delay.test'){if(label==='wait-1000')await new Promise(resolve=>setTimeout(resolve,1000));return new Response(responseWire(new Uint8Array(await request.arrayBuffer())),{headers:{'Content-Type':'application/dns-message'}});}return new Response(Array.from({length:1000},(_,i)=>i===0?'example.com':'item'+i+'.example').join(String.fromCharCode(10)));}});
 let ws;const pending=new Map();let commandId=0;
 try{
  const inspector=await mf.getInspectorURL();const targets=await(await fetch(new URL('/json',inspector.href.replace('ws:','http:')))).json();
  if(!Array.isArray(targets)||!targets.length)throw Error('No local inspector target');
  ws=new WebSocket(targets.find(t=>t.id.includes('local-cpu-profile'))?.webSocketDebuggerUrl??targets[0].webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Local inspector connection timed out')),10000);ws.addEventListener('open',()=>{clearTimeout(timer);resolve();},{once:true});ws.addEventListener('error',()=>{clearTimeout(timer);reject(Error('Local inspector connection failed'));},{once:true});});
  ws.addEventListener('message',event=>{const data=JSON.parse(String(event.data));const p=pending.get(data.id);if(p){pending.delete(data.id);clearTimeout(p.timer);data.error?p.reject(Error(JSON.stringify(data.error))):p.resolve(data.result);}});
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++commandId;const timer=setTimeout(()=>{pending.delete(id);reject(Error('Local inspector command timed out:'+method));},10000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));});
  await send('Profiler.enable');await send('Profiler.setSamplingInterval',{interval:100});
  for(let i=0;i<count;i++){
   await send('Profiler.start');
   const response=await mf.dispatchFetch('https://local.test/dns-query',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:query()});
   const parsed=decode(new Uint8Array(await response.arrayBuffer()));
   assert.equal(response.status,200);assert.equal(parsed.id,0x4242);assert.equal(parsed.questions[0].name,'example.com');
   assert.equal(parsed.flags&15,label.includes('auth-alert')?2:0);
   if(label.startsWith('list-'))assert.equal(parsed.records[0].ttl,30);
   const result=await send('Profiler.stop');
   fs.writeFileSync(path.join(dir,label+'-'+i+'.cpuprofile'),JSON.stringify(result.profile));
   console.log(JSON.stringify({label,index:i,httpStatus:response.status,rcode:parsed.flags&15,ttl:parsed.records[0]?.ttl??null,samples:result.profile.samples?.length,profileWindowMs:(result.profile.endTime-result.profile.startTime)/1000,sourceCalls,connections}));
  }
 }finally{for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('Disposed'));}ws?.close();await mf.dispose();}
}
try{
 const group=actions=>({order:0,rules:[{actions}]});
 await profileCase('fixed',{DNS_RULE_MAIN:group([fixed])},2);
 const probe={type:'probeEch',options:{hostname:'127.0.0.1',port:server.address().port,serverName:'example.test',timeoutMs:1500,maxBytes:65536}};
 await profileCase('default-auth-alert',{DNS_RULE_MAIN:group([fixed,probe])},3);
 const ca=JSON.parse(fs.readFileSync(path.join(root,'lib/ech-probe/test/fixtures/certificates.json'))).rootPem;
 await profileCase('custom-auth-alert',{DNS_RULE_MAIN:group([fixed,{...probe,options:{...probe.options,caCertificates:[ca]}}])},3);
 for(const refresh of[1,60000])await profileCase('list-'+refresh,{DNS_DOMAIN_LISTS:{selected:{url:'https://lists.test/list',format:'text',refreshIntervalMs:refresh}},DNS_RULE_MAIN:{order:0,rules:[{actions:[fixed]},{when:{field:'query.name',op:'inListSuffix',value:'selected'},actions:[{type:'setTtl',ttl:30}]}]}},3);
 for(const ms of[0,1000])await profileCase('wait-'+ms,{DNS_CACHE:{read:false,write:false},DNS_UPSTREAMS:{selected:{transport:'https',url:'https://delay.test/dns-query'}},DNS_RULE_MAIN:group([{type:'queryUpstream',upstream:'selected'}])},3);
}finally{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}

// Sample intervals can span suspended I/O. Count stack observations; do not turn gaps into CPU.
const summaries=[];
for(const file of fs.readdirSync(dir).filter(name=>name.endsWith('.cpuprofile')).sort()){
 const profile=JSON.parse(fs.readFileSync(path.join(dir,file),'utf8'));
 const nodes=new Map(profile.nodes.map(node=>[node.id,node])),parents=new Map(),inclusive=new Map();
 for(const node of profile.nodes)for(const child of node.children??[])parents.set(child,node.id);
 let idleSamples=0,programSamples=0,gcSamples=0;
 for(let i=0;i<(profile.samples?.length??0);i++){
  const node=nodes.get(profile.samples[i]),us=profile.timeDeltas[i]??0,name=node.callFrame.functionName;
  if(name==='(idle)')idleSamples++;if(name==='(program)')programSamples++;if(name==='(garbage collector)')gcSamples++;
  const seen=new Set();
  for(let current=node;current;current=nodes.get(parents.get(current.id))){const frame=current.callFrame.functionName;if(!seen.has(frame)){inclusive.set(frame,(inclusive.get(frame)??0)+1);seen.add(frame);}}
 }
 summaries.push({file,sampleCount:profile.samples?.length??0,profileWindowMs:(profile.endTime-profile.startTime)/1000,idleSamples,unattributedProgramSamples:programSamples,gcSamples,maxSampleGapMs:Math.max(0,...(profile.timeDeltas??[]))/1000,sampleGapsOver10ms:(profile.timeDeltas??[]).filter(us=>us>10000).length,inclusiveStackSamples:Object.fromEntries(['prepareTrustAnchors','decodePem','parseDer','fromBER','createClientHello','loadGroups','validateProbeOptions','fetchDomains','parseDomains','prepare'].map(name=>[name,inclusive.get(name)??0]))});
}
fs.writeFileSync(path.join(dir,'summary.json'),JSON.stringify({evidenceKind:'Local stack observations only; sample time gaps include waits and are NOT CPU',requestedSamplingIntervalUs:100,inclusiveStackCountsOverlap:true,sampleIntervalsMustNotBeSummedAsCpu:true,results:summaries},null,2));
console.log(JSON.stringify({localProfiles:summaries.length,onlineRequests:0,quotaConclusion:'not-measured'}));
