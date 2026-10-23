import { readFileSync } from 'node:fs';
import net from 'node:net';
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
  compatibilityDate: '2026-07-30', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public'], bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
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

const probe = options => ({ type: 'probeEch', options });
test('real TCP probe timeout is observable, cleans its connection, and optional failure keeps the DNS answer', { timeout: 5000 }, async () => {
  const sockets = new Set();
  let connections = 0;
  const server = net.createServer(socket => {
    connections++; sockets.add(socket);
    socket.on('error',()=>{}); socket.on('close',()=>sockets.delete(socket)); socket.on('data',()=>{});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    await setup({ DNS_RULE_MAIN: { order:0,rules:[
      {actions:[fixed,{...probe({hostname:'127.0.0.1',port:server.address().port,serverName:'example.test',timeoutMs:50}),onError:'continue'}]},
      {when:{field:'lastAction.code',op:'eq',value:'ECH_PROBE_TIMEOUT'},actions:[{type:'setTtl',ttl:12}]},
    ] } });
    const result=await dns(await post());
    assert.equal(result.flags&15,0,String(logs));
    assert.equal(result.records[0].ttl,12,String(logs));
    assert.ok(logs.join('').includes('verification_disabled'));
    assert.equal(connections,1);
    await new Promise(resolve=>setTimeout(resolve,30));
    assert.equal(sockets.size,0,'probe must close the actual TCP connection');
    assert.equal(calls.length,0,'raw TLS probe does not make HTTPS fetches');
  } finally {
    for(const socket of sockets) socket.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('TLS byte-limit failures preserve the shared resource error contract', { timeout: 5000 }, async () => {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('error',()=>{}); socket.on('close',()=>sockets.delete(socket));
    socket.once('data',()=>socket.write(Buffer.concat([Buffer.from([22,3,3,4,1]), Buffer.alloc(1025)])));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    await setup({ DNS_RULE_MAIN: { order:0,rules:[
      {actions:[fixed,{...probe({hostname:'127.0.0.1',port:server.address().port,serverName:'example.test',maxBytes:1024}),onError:'continue'}]},
      {when:{field:'lastAction.code',op:'eq',value:'RESOURCE_LIMIT'},actions:[{type:'setTtl',ttl:14}]},
    ] } });
    const result=await dns(await post());
    assert.equal(result.flags&15,0,String(logs));
    assert.equal(result.records[0].ttl,14,String(logs));
  } finally {
    for(const socket of sockets) socket.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('probe attempts share the request quota and cancellation cannot restart later probes', { timeout: 10000 }, async () => {
  const sockets=new Set(); let connections=0;
  const server=net.createServer(socket=>{ connections++; sockets.add(socket); socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.on('data',()=>{}); });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const action={...probe({hostname:'127.0.0.1',port:server.address().port,serverName:'example.test',timeoutMs:30}),onError:'continue'};
    await setup({ DNS_LIMITS:{maxNetworkRequests:1},DNS_RULE_MAIN:{order:0,rules:[
      {actions:[fixed,action,action]},
      {when:{field:'lastAction.code',op:'eq',value:'RESOURCE_LIMIT'},actions:[{type:'setTtl',ttl:16}]},
    ]} });
    assert.equal((await dns(await post())).records[0].ttl,16,String(logs));
    assert.equal(connections,1);
    connections=0;
    await setup({DNS_RULE_MAIN:group([fixed,{...action,options:{...action.options,timeoutMs:1000}},action])},undefined,true);
    assert.equal((await dns(await post(undefined,query(),{'x-test-cancel':'true'}))).flags&15,2);
    assert.equal(connections,1);
    assert.ok(logs.join('').includes('REQUEST_CANCELLED'));
    assert.ok(!logs.join('').includes('private-cancel-reason'));
  } finally {
    for(const socket of sockets) socket.destroy();
    await new Promise(resolve=>server.close(resolve));
  }
});

test('probe options are strict JSON and are validated before unreachable actions can dial', async () => {
  for(const options of [
    {hostname:'127.0.0.1'},
    {hostname:'example.com',port:0},
    {hostname:'example.com',alpn:['h2','h2']},
    {hostname:'example.com',maxBytes:10},
    {hostname:'example.com',verifyCertificate:false,caCertificates:['invalid']},
    {hostname:'example.com',caCertificates:['invalid']},
    {hostname:'example.com',caCertificates:[[1,2,3]]},
    {hostname:'example.com',signal:'not-a-runtime-signal'},
  ]) {
    await setup({DNS_RULE_MAIN:group([fixed,{type:'return'},probe(options)])});
    assert.equal((await dns(await post())).flags&15,2,String(logs));
    assert.equal(calls.length,0);
    assert.ok(logs.join('').includes('ECH_INVALID'));
  }
});

test('custom CA requires explicit verification even in an unreachable probe action', async () => {
  const fixture = JSON.parse(readFileSync(path.join(root, 'lib/ech-probe/test/fixtures/certificates.json'), 'utf8'));
  await setup({ DNS_RULE_MAIN: group([fixed, { type: 'return' }, probe({ hostname: 'example.com', caCertificates: [fixture.rootPem] })]) });
  assert.equal((await dns(await post())).flags & 15, 2, String(logs));
  assert.ok(logs.join('').includes('ECH_INVALID'));
  assert.equal(calls.length, 0);
});
