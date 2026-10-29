import { readFile, writeFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import { setGlobalProxyFromEnv } from 'node:http';
setGlobalProxyFromEnv();
const counts = { 'live/a':1, 'live/x':1, 'live/facebook':1, library: 28, builder: 15, embedded: 8, 'equivalence/cloudflare': 1, 'equivalence/meta': 1,
  ...Object.fromEntries(Object.entries({ eligibility:18,hits:8,isolation:7,sources:1,bypass:10,pipeline:5,ecs:3 }).map(([k,v])=>['padding/'+k,v])),
  'padding/parity/core':9,...Object.fromEntries(Array.from({length:6},(_,i)=>['padding/parity/map'+i,i===5?4:5])),
  'padding/parity/ipv6':5,'padding/parity/https0':3,'padding/parity/https1':3,'padding/parity/https2':3,'padding/parity/https3':3,'padding/parity/fallback':6,'padding/parity/addresses':6,'padding/parity/controls':5,
  'google/production-a':1,'google/production-facebook':1,'google/production-instagram':1,'google/production-x':1 };
const dir = new URL('../../../.acceptance/embedded-ip-lists-20261029/', import.meta.url), file = new URL('ledger.json', dir);
const access = JSON.parse(await readFile(new URL('access.json', dir), 'utf8')), ledger = JSON.parse(await readFile(file, 'utf8'));
const selected = process.argv.slice(2);
if (!selected.length || new Set(selected).size !== selected.length || selected.some(s=>!(s in counts)) || ledger.budget!==40 || ledger.used!==ledger.requests.length || ledger.used+selected.length>ledger.budget || Date.now()>=access.expires) throw Error('Invalid suites/budget/expiry');
let failed = false;
for (const suite of selected) {
  const prior=ledger.requests.at(-1);if(prior)await setTimeout(Math.max(0,1050-(Date.now()-Date.parse(prior.startedAt))));
  const row={number:++ledger.used,suite,startedAt:new Date().toISOString(),status:'attempted'};ledger.requests.push(row);await writeFile(file,JSON.stringify(ledger,null,2));
  try {
    const response=await fetch(`${access.endpoint}/${access.key}/${suite}`,{method:'POST',headers:{authorization:`Bearer ${access.key}`},redirect:'error',signal:AbortSignal.timeout(60000)});
    row.http=response.status;const chunks=[];let size=0;for await(const p of response.body){if((size+=p.length)>65536)throw Error('Response too large');chunks.push(p);}
    row.body=JSON.parse(Buffer.concat(chunks).toString());
    const google=suite.startsWith('google/');
    row.status=response.ok&&row.body.passed===true&&(google?row.body.name===suite.slice(7):row.body.results?.length===counts[suite]&&row.body.results.every(r=>r.passed===true))?'passed':'failed';
  }catch(error){row.status='failed';row.error=error.name;row.cause=error.cause?.code;}
  if(row.status!=='passed')failed=true;await writeFile(file,JSON.stringify(ledger,null,2));
  console.log(JSON.stringify({number:row.number,suite,status:row.status,http:row.http,count:row.body?.results?.length,failures:row.body?.results?.filter(r=>!r.passed),error:row.error,ms:row.body?.ms}));
}
if(failed)process.exitCode=1;
