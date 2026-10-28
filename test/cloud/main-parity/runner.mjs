import fs from 'node:fs/promises';import path from 'node:path';import {fileURLToPath}from'node:url';import{setTimeout}from'node:timers/promises';import{setGlobalProxyFromEnv}from'node:http';
setGlobalProxyFromEnv();
const suites=['core',...Array.from({length:6},(_,i)=>'map'+i),'ipv6','https0','https1','https2','https3','fallback','addresses','controls'];
const counts={core:9,map0:5,map1:5,map2:5,map3:5,map4:5,map5:4,ipv6:5,https0:3,https1:3,https2:3,https3:3,fallback:6,addresses:6,controls:5};
const dir=fileURLToPath(new URL('../../../.acceptance/main-parity-20261028/',import.meta.url));
const access=JSON.parse(await fs.readFile(path.join(dir,'access.json'),'utf8'));
const attempt=Number(process.env.PARITY_ATTEMPT??'1');if(![1,2].includes(attempt))throw Error('Only two reviewed attempts permitted');
const selected=process.env.PARITY_SUITES?JSON.parse(process.env.PARITY_SUITES):suites;
if(!Array.isArray(selected)||!selected.length||new Set(selected).size!==selected.length||selected.some(s=>!suites.includes(s)))throw Error('Unapproved suite selection');
const file=path.join(dir,`ledger-v${attempt}.json`);
const previous=attempt===2?JSON.parse(await fs.readFile(path.join(dir,'ledger-v1.json'),'utf8')):{used:1,requests:[]};
const state={budget:40,used:previous.used,preflightRequests:1,requests:[...previous.requests],attempt};
if(state.used+selected.length>31)throw Error('Reserve nine of forty total requests for production verification');
await fs.writeFile(file,JSON.stringify(state,null,2),{flag:'wx'});
const failed=[];
for(const suite of selected){
  const prior=state.requests.at(-1);if(prior)await setTimeout(Math.max(0,1050-(Date.now()-Date.parse(prior.startedAt))));
  const row={suite,startedAt:new Date().toISOString(),status:'attempted'};state.requests.push(row);state.used++;await fs.writeFile(file,JSON.stringify(state,null,2));
  try{const response=await fetch(`https://superdoh-main-parity-check-20261028.aloneowo0.workers.dev/${access.check}/${suite}`,{method:'POST',headers:{authorization:`Bearer ${access.check}`},redirect:'error',signal:AbortSignal.timeout(20000)});
    row.http=response.status;row.body=await response.json();
    row.status=response.status===200&&row.body.passed===true&&row.body.results?.length===counts[suite]&&row.body.results.every(r=>r.passed===true)?'passed':'failed';
  }catch(e){row.status='failed';row.error=e.name??'REQUEST_FAILED';}
  if(row.status!=='passed')failed.push(suite);await fs.writeFile(file,JSON.stringify(state,null,2));console.log(JSON.stringify(row));
}
if(failed.length)throw Error('Failed cloud suites: '+failed.join(','));
console.log(JSON.stringify({passed:true,used:state.used,requests:selected.length}));
