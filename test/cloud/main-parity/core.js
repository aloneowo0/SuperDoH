import { executeQuery } from '../../../src/index.js';
import { nameValue, resolveName } from '../../../src/rules/values.js';
import { editRecords } from '../../../src/rules/records.js';
import { loadContext } from '../../../src/rules/context.js';
import { loadLimits } from '../../../src/rules/limits.js';
import { buildQuery, buildResponse, encodeMessage, parseMessage, getEdns, setEdns, FLAGS } from '../../../lib/dns-wasm/index.js';
const check = (condition, label) => { if (!condition) throw Error(label); };
const fails = async (fn, code) => { try { await fn(); } catch (e) { check(!code || e.code === code, 'unexpected error '+e.code); return; } throw Error('accepted invalid input'); };
const ref = { from: 'original.name' };
const record = name => ({ name, type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } });
const answer = records => ({ type: 'answer', records });
const env = actions => ({ DNS_RULE_TEST: { order: 0, rules: [{ actions }] } });
const execute = (actions, limits) => executeQuery(buildQuery('source.example'), { ...env(actions), ...(limits ? { DNS_LIMITS: limits } : {}) }, { onEvent() {} });
export async function runCore() {
  const results = [];
  const test = async (name, fn) => { try { await fn(); results.push({ name, passed: true }); } catch(e) { results.push({ name, passed: false, error: String(e.code ?? e.message).slice(0,128) }); } };
  await test('bounded-name-values', async () => {
    check(nameValue('Example.COM.') === 'example.com', 'literal normalization');
    check(resolveName(nameValue(ref), { current: { name:'current.example' }, original: { name:'source.example' } }) === 'source.example', 'original ref');
    for (const v of [null, {}, { from:'client.ip' }, { from:'original.name', extra:true }, [], '$original.name']) await fails(() => nameValue(v));
  });
  await test('answer-and-query-references', async () => {
    const result = await execute([{ type:'rewriteQuery', name:'current.example' },answer([record(ref),record({from:'query.name'})])]);
    const packet = parseMessage(result.response);
    check(packet.questions[0].name === 'source.example' && packet.answers[0].name === 'source.example' && packet.answers[1].name === 'current.example', 'question and owners');
    check(result.originalQuery.questions[0].name === 'source.example', 'original mutated');
  });
  await test('add-replace-materialization', async () => {
    const result = await execute([answer([record('old.example')]),{type:'replaceRecords',where:{field:'item.type',op:'eq',value:'A'},records:[record(ref)]},{type:'addRecords',records:[record({from:'query.name'})]}]);
    check(parseMessage(result.response).answers.every(r=>r.name==='source.example'), 'record materialization');
  });
  await test('rename-and-original-query-restore', async () => {
    const result = await execute([answer([record('old.example')]),{type:'rewriteQuery',name:'preferred.example'},{type:'setRecordName',name:ref,where:{field:'item.type',op:'eq',value:'A'}},{type:'rewriteQuery',name:ref}]);
    check(result.query.questions[0].name==='source.example' && parseMessage(result.response).answers[0].name==='source.example','rename');
  });
  await test('unreachable-invalid-reference-preflight', async () => {
    await fails(()=>executeQuery(buildQuery('source.example'),{DNS_RULE_TEST:{order:0,rules:[{actions:[answer([record(ref)]),{type:'return'}]},{actions:[answer([record({from:'response.name'})])]}]}},{onEvent(){}}),'INVALID_CONFIG');
    await fails(()=>execute([{type:'setRecordName',name:ref}]),'INVALID_CONFIG');
  });
  await test('optional-size-rollback', async () => {
    const result=await execute([answer([record(ref)]),{type:'addRecords',onError:'continue',records:[{name:ref,type:'TXT',ttl:60,rdata:{Txt:['x'.repeat(200)]}}]}],{maxResponseBytes:100});
    check(parseMessage(result.response).answers.length===1 && result.lastAction.success===false,'rollback');
  });
  await test('response-size-and-config-immutability', async () => {
    const config=env([answer([record(ref)])]);const before=JSON.stringify(config);
    const longName=['a'.repeat(63),'b'.repeat(63),'c'.repeat(63),'d'.repeat(50)].join('.');
    await fails(()=>executeQuery(buildQuery(longName),{...config,DNS_LIMITS:{maxResponseBytes:100}},{onEvent(){}}),'RESOURCE_LIMIT');
    await executeQuery(buildQuery('source.example'),config,{onEvent(){}});
    check(JSON.stringify(config)===before,'config mutation');
  });
  const limits=loadLimits(undefined);
  const current={name:'current.example',rtype:1,class:1}, original={name:'source.example',rtype:1,class:1};
  const context=response=>({current,original,response,properties:loadContext({},limits),spend(){}});
  await test('rename-invalidates-old-and-new-signatures', async () => {
    const signer=[7,101,120,97,109,112,108,101,3,99,111,109,0];
    const sig={Raw:[0,1,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,...signer,1]};
    const packet=parseMessage(buildResponse(parseMessage(buildQuery('source.example')),{flags:FLAGS.QR|FLAGS.AD|FLAGS.RD,answers:[
      {name:'old.example',rtype:1,class:1,ttl:60,rdata:{A:{addr:'192.0.2.1'}}},
      ...['old.example','source.example','unrelated.example'].map(name=>({name,rtype:46,class:1,ttl:60,rdata:sig})),
    ]}));
    setEdns(packet,{udp_payload_size:1232,extended_rcode:1,flags:0x8000,options:[{code:65001,data:[9]}]});
    const result=await editRecords({type:'setRecordName',name:ref,where:{field:'item.type',op:'eq',value:'A'},selector:ctx=>ctx.item.type===1},context(packet),limits,{});
    check(!(result.flags&FLAGS.AD),'AD not cleared');
    check(result.answers.filter(r=>r.rtype===46).map(r=>r.name).join(',')==='unrelated.example','signatures');
    check(getEdns(result).extended_rcode===1 && getEdns(result).flags===0x8000,'EDNS changed');
  });
  await test('protected-records-and-noop',async()=>{
    const packet=parseMessage(buildResponse(parseMessage(buildQuery('source.example')),{flags:FLAGS.QR|FLAGS.AD}));setEdns(packet,{udp_payload_size:1232});
    await fails(()=>editRecords({type:'setRecordName',name:ref,where:{field:'item.type',op:'eq',value:'OPT'},selector:()=>true},context(structuredClone(packet)),limits,{}),'INVALID_STATE');
    const unchanged=await editRecords({type:'setRecordName',name:ref,where:{field:'item.type',op:'eq',value:'A'},selector:()=>false},context(packet),limits,{});
    check(unchanged.flags&FLAGS.AD,'noop cleared AD');
  });
  return {passed:results.every(r=>r.passed),results};
}
