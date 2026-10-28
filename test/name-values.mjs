import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Miniflare } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
test('bounded question references and DNSSEC-safe owner changes',async()=>{
  const result=await build({entryPoints:[root+'test/cloud/main-parity/core-worker.js'],bundle:true,write:false,format:'esm',platform:'browser',outfile:root+'test/name-values-bundle.js',external:['cloudflare:sockets'],plugins:[{name:'external-wasm',setup(b){b.onResolve({filter:/dns_bindgen_bg\.wasm$/},()=>({path:'../lib/dns-wasm/dns_bindgen_bg.wasm',external:true}));}}]});
  const worker=new Miniflare({modules:true,modulesRoot:root,scriptPath:root+'test/name-values-bundle.js',script:result.outputFiles[0].text,compatibilityDate:'2026-10-19',compatibilityFlags:['enable_request_signal','global_fetch_strictly_public','no_nodejs_compat','no_nodejs_compat_v2'],modulesRules:[{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}]});
  try{const response=await worker.dispatchFetch('https://local.test/core');assert.equal(response.status,200);const body=await response.json();assert.equal(body.results.length,9);assert.equal(body.passed,true,JSON.stringify(body));}finally{await worker.dispose();}
});
