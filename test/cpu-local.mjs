import fs from'node:fs';import path from'node:path';import net from'node:net';import{fileURLToPath}from'node:url';import{build}from'esbuild';import{Miniflare,Log,LogLevel}from'miniflare';import{query,decode,responseWire}from'./helpers/dns-wire.mjs';
import assert from'node:assert/strict';import{execFileSync}from'node:child_process';import{performance}from'node:perf_hooks';
const ps=code=>execFileSync('pwsh',['-NoLogo','-NoProfile','-NonInteractive','-Command',code],{encoding:'utf8',timeout:30000}).trim();
const cpu=pid=>{const text=ps('(Get-Process -Id '+pid+').TotalProcessorTime.TotalMilliseconds'),value=Number(text);assert.ok(text.length>0&&Number.isFinite(value)&&value>=0,'invalid process CPU counter');return value;};

// Opt-in Windows process-CPU diagnostic; no deployment, credentials or public upstreams.
if(process.platform!=='win32')throw Error('This diagnostic requires Windows process CPU counters and pwsh');
if(process.argv.length!==2)throw Error('This diagnostic accepts no endpoint or mode arguments');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
console.log(JSON.stringify({evidenceKind:'Windows workerd whole-process CPU, not platform quota CPU or function CPU',processCpuIncludesAllThreads:true,counterPrecision:'coarse OS counter',zeroDoesNotMeanNoCpu:true,onlineRequests:0}));
const bundled=await build({entryPoints:[path.join(root,'src/worker.js')],bundle:true,write:false,external:['cloudflare:sockets'],format:'esm',platform:'browser',plugins:[{name:'external-wasm',setup(api){api.onResolve({filter:/[.]wasm$/},args=>({path:'../'+path.relative(root,path.resolve(args.resolveDir,args.path)).split(path.sep).join('/'),external:true}));}}]});
const sockets=new Set();let connections=0;
const server=net.createServer(socket=>{connections++;sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.once('data',()=>socket.end(Buffer.from([21,3,3,0,2,2,40])));});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const fixed={type:'answer',records:[{name:'example.com',type:'A',ttl:60,rdata:{A:{addr:'192.0.2.8'}}}]};
async function profileCase(label,bindings,count){
 const events=[];let sourceCalls=0;
 const mf=new Miniflare({name:'local-cpu-profile',inspectorPort:0,inspectorHost:'127.0.0.1',modules:true,modulesRoot:root,scriptPath:path.join(root,'test/local-profile-bundle.js'),script:bundled.outputFiles[0].text,compatibilityDate: '2026-10-19',compatibilityFlags: ['enable_request_signal','global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'],bindings,log:new Log(LogLevel.NONE),handleRuntimeStdio(stdout,stderr){for(const stream of[stdout,stderr])stream.setEncoding('utf8').on('data',text=>events.push(text));},modulesRules:[{type:'ESModule',include:['**/*.js'],fallthrough:true},{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],outboundService:async request=>{const host=new URL(request.url).hostname;if(host!=='lists.test'&&host!=='delay.test')throw Error('Unexpected nonlocal source');sourceCalls++;if(host==='delay.test'){if(label==='wait-1000')await new Promise(resolve=>setTimeout(resolve,1000));return new Response(responseWire(new Uint8Array(await request.arrayBuffer())),{headers:{'Content-Type':'application/dns-message'}});}return new Response(Array.from({length:1000},(_,i)=>i===0?'example.com':'item'+i+'.example').join(String.fromCharCode(10)));}});
 try{
  await mf.ready;
  const pids=JSON.parse(ps('ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_Process -Filter "ParentProcessId = '+process.pid+' AND Name = '+String.fromCharCode(39)+'workerd.exe'+String.fromCharCode(39)+'" | Select-Object -ExpandProperty ProcessId)'));
  assert.equal(pids.length,1,'exactly one workerd child of this harness');const pid=pids[0];
  for(let i=0;i<count;i++){
   const before=cpu(pid),start=performance.now();
   const response=await mf.dispatchFetch('https://local.test/dns-query',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:query()});
   const parsed=decode(new Uint8Array(await response.arrayBuffer()));const wallMs=performance.now()-start;const cpuMs=cpu(pid)-before;
   assert.equal(response.status,200);assert.equal(parsed.flags&15,label.endsWith('-alert')?2:0);assert.equal(parsed.id,0x4242);
   if(label.startsWith('list-'))assert.equal(parsed.records[0].ttl,30);
   console.log(JSON.stringify({label,index:i,processCpuMs:cpuMs,wallMs,sourceCalls,connections,rcode:parsed.flags&15}));
  }
 }finally{await mf.dispose();}
}
try{
 const group=actions=>({order:0,rules:[{actions}]});
 await profileCase('fixed',{DNS_RULE_MAIN:group([fixed])},2);
 const probe={type:'probeEch',options:{cacheTtl:0,verifyCertificate:true,hostname:'127.0.0.1',port:server.address().port,serverName:'example.test',timeoutMs:1500,maxBytes:65536}};
 await profileCase('default-unverified-alert',{DNS_RULE_MAIN:group([fixed,{...probe,options:Object.fromEntries(Object.entries(probe.options).filter(([key])=>key!=='verifyCertificate'))}])},3);
 await profileCase('default-auth-alert',{DNS_RULE_MAIN:group([fixed,probe])},3);
 const ca=JSON.parse(fs.readFileSync(path.join(root,'lib/ech-probe/test/fixtures/certificates.json'))).rootPem;
 await profileCase('custom-auth-alert',{DNS_RULE_MAIN:group([fixed,{...probe,options:{...probe.options,caCertificates:[ca]}}])},3);
 for(const refresh of[1,60000])await profileCase('list-'+refresh,{DNS_DOMAIN_LISTS:{selected:{url:'https://lists.test/list',format:'text',refreshIntervalMs:refresh}},DNS_RULE_MAIN:{order:0,rules:[{actions:[fixed]},{when:{field:'query.name',op:'inListSuffix',value:'selected'},actions:[{type:'setTtl',ttl:30}]}]}},3);
 for(const ms of[0,1000])await profileCase('wait-'+ms,{DNS_CACHE:{read:false,write:false},DNS_UPSTREAMS:{selected:{transport:'https',url:'https://delay.test/dns-query'}},DNS_RULE_MAIN:group([{type:'queryUpstream',upstream:'selected'}])},3);
}finally{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}
