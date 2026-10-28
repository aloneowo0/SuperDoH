import { compileList, createIpListStore, ip } from '../index.js';
const encode = text => new TextEncoder().encode(text);
const assert = (yes, message='Assertion failed') => { if (!yes) throw Error(message); };
export async function runCases() {
  const results = [];
  const test = async (name, fn) => { try { await fn(); results.push({name,passed:true}); } catch(error) { results.push({name,passed:false,error:error.code ?? error.message}); } };
  const compile = (text, format='text', entries=4096, bytes=262144) => compileList(encode(text),format,entries,bytes);
  const invalid = fn => { try { fn(); } catch(error) { assert(['IP_LIST_INVALID','RESOURCE_LIMIT'].includes(error.code)); return; } throw Error('Accepted invalid data'); };
  await test('IPv4 boundaries and exact IP',()=>{const x=compile('192.0.2.0/24\n198.51.100.8'); for(const a of ['192.0.2.0','192.0.2.255','198.51.100.8']) assert(x.contains(a)); for(const a of ['192.0.1.255','192.0.3.0','198.51.100.9','::ffff:192.0.2.1']) assert(!x.contains(a));});
  await test('IPv6 boundaries and family isolation',()=>{const x=compile('2001:db8::/127\n::ffff:192.0.2.1/128');assert(x.contains('2001:db8::')&&x.contains('2001:db8::1')&&!x.contains('2001:db8::2')&&x.contains('::ffff:c000:201')&&!x.contains('192.0.2.1'));});
  await test('zero prefixes, maximum prefixes, host-bit normalization',()=>{assert(compile('0.0.0.0/0').contains('255.255.255.255'));assert(compile('::/0').contains('ffff::1'));assert(!compile('::/0').contains('1.1.1.1'));assert(compile('192.0.2.7/24').contains('192.0.2.255'));});
  await test('overlap duplicate adjacency union',()=>{const x=compile('192.0.2.0/25\n192.0.2.128/25\n192.0.2.1/32\n192.0.2.0/25');assert(x.entries===4&&x.contains('192.0.2.255')&&!x.contains('192.0.3.0'));});
  await test('comments, CRLF, BOM, JSON',()=>{assert(compile('﻿# comment\r\n\r\n192.0.2.1\r\n').contains('192.0.2.1'));assert(compile('["2001:db8::/32"]','json').contains('2001:db8::f'));});
  for (const text of ['', '# only comment', '01.2.3.4/8', '1.2.3.4/33', '::/129', 'fe80::1%eth0/64', 'https://example.com', '<html>192.0.2.1</html>', '192.0.2.1\nBAD', '192.0.2.1 # inline', '1.2.3.4:53']) await test('reject '+JSON.stringify(text),()=>invalid(()=>compile(text)));
  await test('reject wrong JSON shape and non-string',()=>{invalid(()=>compile('{}','json'));invalid(()=>compile('[1]','json'));invalid(()=>compile('[]','json'));});
  await test('reject UTF8, entry and byte ceilings',()=>{invalid(()=>compileList(new Uint8Array([255]),'text',10,100));invalid(()=>compile('192.0.2.1\n192.0.2.2','text',1));invalid(()=>compile('192.0.2.1','text',10,1));});
  await test('immutable index and charged bounded search',()=>{const x=compile('192.0.2.1\n192.0.2.3\n192.0.2.5');let steps=0; assert(Object.isFrozen(x)&&x.containsKey(ip('192.0.2.5').key,()=>steps++)&&steps<=2);assert(!x.containsKey('32:fffffffff'));});
  const defaults={source:'https://example.com/list',format:'text',maxBytes:1024,maxEntries:16,maxStates:4,maxStateBytes:16384};
  await test('default 1h TTL, persistent age, expiry and no stale',async()=>{
    let time=10000, calls=0, fail=false; const data=new Map();
    const cache={get:async key=>data.get(key),put:async(key,value)=>{data.set(key,value);}};
    const o={...defaults,now:()=>time,cache,load:async()=>{calls++;if(fail)throw Error('Source failed');return encode('192.0.2.1');}};
    const store=createIpListStore();assert((await store.load(o)).via==='origin');time+=3599999;
    assert((await store.load(o)).via==='memory'&&calls===1);
    const next=createIpListStore();assert((await next.load(o)).via==='cache'&&calls===1);
    time++;fail=true;let rejected=false;try{await next.load(o);}catch{rejected=true;}assert(rejected&&calls===2);
    fail=false;assert((await next.load(o)).via==='origin'&&calls===3);
  });
  await test('TTL zero, identity and bounded eviction',async()=>{let calls=0;const store=createIpListStore();const o={...defaults,maxStates:1,load:async()=>{calls++;return encode('192.0.2.1');}};await store.load(o);await store.load(o);assert(calls===1);await store.load({...o,cacheTtl:0});await store.load({...o,cacheTtl:0});assert(calls===3);await store.load({...o,source:o.source+'?next'});await store.load(o);assert(calls===5);await store.load({...o,maxEntries:15});assert(calls===6);await store.load({...o,cacheTtl:3601});assert(calls===7);});
  await test('corrupt unavailable cache and no negative caching',async()=>{let calls=0;const o={...defaults,cache:{get:async()=>({storedAt:Date.now(),text:'BAD'}),put:async()=>{throw Error('cache unavailable');}},load:async()=>{calls++;return encode(calls===1?'BAD':'192.0.2.1');}};const store=createIpListStore();let failed=false;try{await store.load(o);}catch{failed=true;}assert(failed);assert((await store.load(o)).index.contains('192.0.2.1')&&calls===2);});
  await test('cancellation cannot be hidden by cache fallback',async()=>{let cancelled=false,calls=0;const o={...defaults,check:()=>{if(cancelled)throw Error('cancelled');},cache:{get:async()=>{cancelled=true;throw Error('cache');},put:async()=>{}},load:async()=>{calls++;return encode('192.0.2.1');}};let failed=false;try{await createIpListStore().load(o);}catch{failed=true;}assert(failed&&calls===0);});
  await test('concurrent callers never share promises or signals',async()=>{const store=createIpListStore();let calls=0;const load=async()=>{calls++;await Promise.resolve();return encode('192.0.2.1');};const pair=await Promise.all([store.load({...defaults,load}),store.load({...defaults,load})]);assert(calls===2&&pair.every(x=>x.index.contains('192.0.2.1')));});
  await test('explicit null cache TTL is invalid',async()=>{let failed=false;try{await createIpListStore().load({...defaults,cacheTtl:null,load:async()=>encode('192.0.2.1')});}catch(error){failed=error.code==='IP_LIST_INVALID';}assert(failed);});
  await test('state ceiling is explicit',async()=>{let failed=false;try{await createIpListStore().load({...defaults,maxStateBytes:1,load:async()=>encode('192.0.2.1')});}catch(error){failed=error.code==='RESOURCE_LIMIT';}assert(failed);});
  return {passed:results.every(x=>x.passed), results};
}
