import net from 'node:net';
import ts from 'typescript';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { query, decode, responseWire, nameWire } from './helpers/dns-wire.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const bundleWorker = entry => build({
  entryPoints: [path.join(root, entry)], bundle: true, write: false,
  external: ['cloudflare:sockets'], format: 'esm', platform: 'browser', outfile: path.join(root, 'test/doh-bundle.js'),
  plugins: [{ name: 'wasm-external', setup(build) {
    build.onResolve({ filter: /.wasm$/ }, args => ({
      path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
    }));
  } }],
});
const bundle = await bundleWorker('src/worker.js');
const trustedBundle = await bundleWorker('test/doh-options-worker.js');
const logs = [];
class TestLog extends Log {
  constructor() { super(LogLevel.ERROR); }
  log(message) { logs.push(message); }
}
const calls = [];
let upstream = async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } });
const options = (bindings, trusted = false) => ({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/doh-bundle.js`, script: (trusted ? trustedBundle : bundle).outputFiles[0].text,
  compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'], bindings, log: new TestLog(),
  handleRuntimeStdio(stdout, stderr) {
    for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text));
  },
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
  outboundService: async request => {
    calls.push({ url: request.url, method: request.method, headers: Object.fromEntries(request.headers) });
    const response = await upstream(request);
    // Fix origin apparent age at zero unless this case supplies Date explicitly.
    if (!response.headers.has('date')) response.headers.set('date', new Date(Date.now() + 60_000).toUTCString());
    return response;
  },
});
const mf = new Miniflare(options({}));
after(() => mf.dispose());
const fixed = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const source = url => ({ default: { transport: 'https', url } });
const requestDefault = { type: 'queryUpstream', upstream: 'default' };
const group = actions => ({ order: 0, rules: [{ actions }] });
async function setup(bindings = {}, handler, trusted = false) {
  calls.length = 0; logs.length = 0;
  upstream = handler ?? (async request => new Response(responseWire(new Uint8Array(await request.arrayBuffer())), { headers: { 'Content-Type': 'application/dns-message' } }));
  await mf.setOptions(options(bindings, trusted));
}
const post = (url = 'https://doh.test/dns-query', wire = query(), headers = {}) => mf.dispatchFetch(url, {
  method: 'POST', headers: { 'Content-Type': 'application/dns-message', ...headers }, body: wire,
});
async function dns(response) {
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'application/dns-message');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  return decode(new Uint8Array(await response.arrayBuffer()));
}

const example = async name => JSON.parse(await fs.readFile(new URL('../examples/' + name + '.json', import.meta.url),'utf8'));
const direct = await example('ech-direct');
const sampleConfig = direct.DNS_RULE_ECH_DIRECT.rules[0].actions.find(action => action.type === 'loadEch').config;
const u16=value=>[value>>>8&255,value&255];
const httpsData=()=>[0,1,0,0,3,0,2,1,187,0,5,...u16(Buffer.from(sampleConfig,'base64').length),...Buffer.from(sampleConfig,'base64')];
const handler=async request=>{
  const url=new URL(request.url);
  if(url.hostname==='lists.example') return new Response('example.com' + String.fromCharCode(10));
  if(url.hostname==='geo.example') return Response.json({ip:url.searchParams.get('ip'),network:{asn:64512},location:{country:'DE'}});
  const input=new Uint8Array(await request.arrayBuffer()); const q=decode(input).questions[0];
  const records=q.type===65 ? [{name:q.name,type:65,ttl:60,data:httpsData()}] : [{name:q.name,type:1,ttl:60,data:[192,0,2,9]}];
  return new Response(responseWire(input,{records,rcode:url.hostname==='primary.example'?2:0}),{headers:{'Content-Type':'application/dns-message'}});
};

test('checked-in fallback example handles action failures and legal failure RCODEs explicitly',async()=>{
  for(const fault of [false,true]) {
    await setup(await example('fallback'),async request=>{
      if(fault && new URL(request.url).hostname==='primary.example') throw Error('private-primary-fault');
      return handler(request);
    });
    const result=await dns(await post(undefined, query(fault ? 'failure.example' : 'example.com')));
    assert.equal(result.flags&15,0,String(logs));
    assert.deepEqual(calls.map(call=>new URL(call.url).hostname),['primary.example','backup.example']);
    if(fault)assert.ok(logs.join('').includes('rolled_back_continue'));
  }
});

test('checked-in client, attribution and maintained-list examples run through the production HTTP entry',async()=>{
  for(const [name,ttl] of [['client-selection',60],['attribution',30],['domain-list',30]]) {
    await setup(await example(name),handler);
    const response=await mf.dispatchFetch('https://doh.test/dns-query',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:query(),cf:{country:'DE',asn:64512,colo:'FRA'}});
    const result=await dns(response);
    assert.equal(result.flags&15,0,name+String(logs));
    assert.equal(result.records[0].ttl,ttl,name);
    if(name==='client-selection')assert.equal(new URL(calls[0].url).hostname,'eu-resolver.example');
  }
});

test('checked-in direct and DNS ECH examples use JSON data without a vendor policy',async()=>{
  for(const name of ['ech-direct','ech-query']) {
    await setup(await example(name),handler);
    const result=await dns(await post(undefined,query(name==='ech-query'?'www.example.com':'example.com',65)));
    assert.equal(result.flags&15,0,name+String(logs));
    assert.equal(result.records[0].type,65);
    const data=Buffer.from(result.records[0].data);
    assert.ok(data.includes(Buffer.from(sampleConfig,'base64')));
    assert.equal(calls.length,name==='ech-direct'?0:1);
  }
});

test('maintained lists, original caching, attribution, ECH and JSON compose without hiding optional failures',async()=>{
  const geo=(await example('attribution')).DNS_ADDRESS_SOURCES.geo;
  const signature=[0,65,8,2,0,0,0,60,119,53,148,0,59,154,202,0,0,1,...nameWire('example.com'),1];
  await setup({
    DNS_JSON:true,DNS_LIMITS:{maxNetworkRequests:5},
    DNS_UPSTREAMS:{default:{transport:'https',url:'https://combo-resolver.example/query'},broken:{transport:'https',url:'https://combo-failure.example/query'}},
    DNS_DOMAIN_LISTS:{selected:{url:'https://lists.example/combo',format:'text',refreshIntervalMs:60000}},
    DNS_ADDRESS_SOURCES:{geo:{...geo,url:'https://geo.example/lookup?combo=1'}},
    DNS_RULE_COMBO:{order:0,rules:[
      {when:{field:'query.name',op:'inList',value:'selected'},actions:[requestDefault,{type:'enrichAddresses',source:'geo'}]},
      {when:{collection:'response.addresses',quantifier:'any',where:{all:[{field:'item.asn',op:'eq',value:64512},{field:'item.country',op:'eq',value:'DE'}]}},actions:[{type:'queryEch',name:'ech.example',upstream:'default'},{type:'applyEch'}]},
      {actions:[{type:'queryEch',name:'missing.example',upstream:'broken',onError:'continue'}]},
      {when:{field:'lastAction.code',op:'eq',value:'UPSTREAM_FAILED'},actions:[{type:'setTtl',ttl:17,where:{field:'item.type',op:'eq',value:'HTTPS'}}]},
    ]},
  },async request=>{
    const url=new URL(request.url);
    if(url.hostname==='combo-failure.example')return new Response('private-combo-failure',{status:503});
    if(url.hostname!=='combo-resolver.example')return handler(request);
    const input=new Uint8Array(await request.arrayBuffer()),q=decode(input).questions[0];
    const records=q.name==='ech.example'?[{name:q.name,type:65,ttl:60,data:httpsData()}]:[
      {name:q.name,type:65,ttl:60,data:[0,1,0,0,3,0,2,1,187]},
      {name:q.name,type:46,ttl:60,data:signature},
      {name:q.name,type:1,ttl:60,section:2,data:[192,0,2,9]},
    ];
    return new Response(responseWire(input,{records}),{headers:{'Content-Type':'application/dns-message'}});
  });
  const wire=await dns(await post(undefined,query('example.com',65,0x0100)));
  assert.equal(wire.flags&15,0,String(logs));
  assert.equal(wire.flags&0x20,0);
  assert.equal(wire.records.find(rr=>rr.type===65).ttl,17);
  assert.ok(!wire.records.some(rr=>rr.type===46));
  assert.ok(Buffer.from(wire.records[0].data).includes(Buffer.from(sampleConfig,'base64')));
  assert.equal(calls.length,5,String(calls));
  const response=await mf.dispatchFetch('https://doh.test/dns-query?name=example.com&type=HTTPS');
  assert.equal(response.status,200);
  const json=await response.json();
  assert.equal(json.Status,0);
  assert.equal(json.AD,false);
  assert.equal(json.Answer[0].TTL,17);
  assert.ok(json.Answer[0].data.includes(sampleConfig));
  assert.equal(calls.length,6,'only the explicit failing action repeats; cached originals still run rules');
  assert.equal(calls.filter(call=>new URL(call.url).hostname==='lists.example').length,1);
  assert.ok(logs.join('').includes('UPSTREAM_FAILED'));
  assert.ok(!logs.join('').includes('private-combo-failure'));
});


test('checked-in probe example fails closed against a controlled unsupported TLS source', { timeout:5000 }, async()=>{
  const sockets=new Set();let connections=0;
  const server=net.createServer(socket=>{connections++;sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.once('data',()=>socket.end(Buffer.from([21,3,3,0,2,2,40])));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const bindings=await example('ech-probe');
    const options=bindings.DNS_RULE_ECH_PROBE.rules[0].actions.find(action=>action.type==='probeEch').options;
    options.hostname='127.0.0.1';options.port=server.address().port;options.timeoutMs=500;
    await setup(bindings);
    const result=await dns(await post(undefined,query('www.example.com',65)));
    assert.equal(result.flags&15,2,String(logs));
    assert.equal(connections,1);
    assert.ok(logs.join('').includes('ECH_PROBE_FAILED'));
  } finally {
    for(const socket of sockets)socket.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('deployment configuration retains Dashboard variables and keeps the no-nodejs-compat runtime boundary',async()=>{
  const text=await fs.readFile(new URL('../wrangler.jsonc',import.meta.url),'utf8');
  const parsed=ts.parseConfigFileTextToJson('wrangler.jsonc',text);
  assert.equal(parsed.error,undefined);
  assert.equal(parsed.config.keep_vars,true);
  assert.equal(parsed.config.main,'src/worker.js');
  assert.ok(!parsed.config.compatibility_flags.includes('nodejs_compat'));
  assert.ok(parsed.config.compatibility_flags.includes('global_fetch_strictly_public'));
});
