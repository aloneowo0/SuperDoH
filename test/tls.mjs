import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import tls from 'node:tls';
import fs from 'node:fs/promises';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { once } from 'node:events';

import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { query, decode, responseWire } from './helpers/dns-wire.mjs';

const fixtures = JSON.parse(await fs.readFile(new URL('../lib/ech-probe/test/fixtures/certificates.json', import.meta.url), 'utf8'));
const key = '-----BEGIN PRIVATE KEY-----\n' + fixtures.leafPrivateKeyPkcs8Base64.match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----\n';
const root = fileURLToPath(new URL('../', import.meta.url));
const bundleWorker = entry => build({
  entryPoints: [path.join(root, entry)], bundle: true, write: false,
  format: 'esm', platform: 'browser', external: ['cloudflare:sockets'],
  plugins: [{ name: 'wasm', setup(build) {
    build.onResolve({ filter: /\.wasm$/ }, args => ({ path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true }));
  } }],
});
const bundle = await bundleWorker('src/worker.js');
const optionsBundle = await bundleWorker('test/doh-options-worker.js');
let activeBundle = bundle;
let trustRoot = true;
const logs = [];
class TestLog extends Log { constructor() { super(LogLevel.ERROR); } log(text) { logs.push(text); } }
const options = bindings => ({
  modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/tcp-bundle.js'), script: activeBundle.outputFiles[0].text,
  outboundService: { network: { allow: ['private'], tlsOptions: { trustBrowserCas: false, trustedCertificates: trustRoot ? [fixtures.rootPem] : [] } } },
  compatibilityDate: '2026-07-30', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public'], bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
  handleRuntimeStdio(stdout, stderr) {
    for (const stream of [stdout, stderr]) stream.setEncoding('utf8').on('data', text => logs.push(text));
  },
  modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }, { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }],
});
const mf = new Miniflare(options({}));
after(() => mf.dispose());
const fixed = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const request = { type: 'queryUpstream', upstream: 'primary' };
const group = actions => ({ order: 0, rules: [{ actions }] });
const frame = data => { const b = Buffer.alloc(data.length + 2); b.writeUInt16BE(data.length); b.set(data, 2); return b; };
async function serverTest(handler, run) {
  const sockets = new Set(), requests = [];
  const server = tls.createServer({ key, cert: fixtures.leafPem + fixtures.intermediatePem }, socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let input = Buffer.alloc(0), handled = false;
    socket.on('data', chunk => {
      input = Buffer.concat([input, chunk]);
      if (!handled && input.length >= 2 && input.length >= 2 + input.readUInt16BE(0)) {
        handled = true; const wire = input.subarray(2, 2 + input.readUInt16BE(0)); requests.push(wire);
        Promise.resolve(handler(socket, wire)).catch(() => socket.destroy());
      }
    });
  });
  server.on('tlsClientError', () => {});
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try { await run({ port: server.address().port, requests, sockets }); }
  finally { for (const s of sockets) s.destroy(); server.close(); await once(server, 'close'); }
}
async function setup(port, extra = {}, callerOptions = false, trusted = true) {
  trustRoot = trusted;
  activeBundle = callerOptions ? optionsBundle : bundle;
  logs.length = 0;
  await mf.setOptions(options({ DNS_UPSTREAMS: { primary: { transport: 'tls', address: '127.0.0.1', port, serverName: 'example.test' } }, DNS_RULE_MAIN: group([request]), ...extra }));
}
async function post(wire = query(), headers = {}) {
  const response = await mf.dispatchFetch('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', ...headers }, body: wire });
  assert.equal(response.status, 200); return decode(new Uint8Array(await response.arrayBuffer()));
}

test('public DoH queries a real authenticated TLS DNS source with explicit server identity', async () => {
  await serverTest((socket, wire) => socket.write(frame(responseWire(wire))), async ({ port, requests }) => {
    await setup(port, { DNS_RULE_MAIN: group([request, { type: 'setTtl', ttl: 17 }]) });
    const result = await post();
    assert.equal(result.flags & 15, 0);
    assert.equal(result.id, 0x4242);
    assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
    assert.deepEqual(result.records[0].data, [192, 0, 2, 9]);
    assert.equal(result.records[0].ttl, 17);
    assert.equal(requests.length, 1);
  });
});


test('TLS length prefixes and messages may be fragmented and do not require peer EOF', async () => {
  await serverTest(async (socket, wire) => {
    const b = frame(responseWire(wire));
    for (const part of [b.subarray(0, 1), b.subarray(1, 7), b.subarray(7)]) {
      socket.write(part); await new Promise(resolve => setTimeout(resolve, 5));
    }
    // Keep the connection open: a DNS frame, not EOF, terminates the response.
  }, async ({ port, requests }) => {
    await setup(port);
    assert.deepEqual((await post()).records[0].data, [192, 0, 2, 9]);
    assert.equal(requests.length, 1);
  });
});

test('valid failure RCODEs and EDNS extended codes survive the TLS path', async () => {
  for (const rcode of [2, 3, 5, 16]) {
    await serverTest((socket, wire) => socket.end(frame(responseWire(wire, {
      rcode: rcode & 15,
      records: rcode >= 16 ? [{ name: '.', type: 41, class: 1232, ttl: 0x01000000, data: [], section: 2 }] : [],
    }))), async ({ port, requests }) => {
      await setup(port);
      let q = query();
      if (rcode >= 16) { q = Uint8Array.from([...q, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]); q[11] = 1; }
      const result = await post(q);
      assert.equal(result.flags & 15, rcode & 15);
      if (rcode >= 16) assert.equal(result.records.find(r => r.type === 41).ttl >>> 24, 1);
      assert.equal(requests.length, 1);
    });
  }
});


test('an optional TLS timeout preserves a prior answer and exposes failure to JSON', async () => {
  await serverTest(() => {}, async ({ port, requests }) => {
    await setup(port, {
      DNS_LIMITS: { upstreamTimeoutMs: 40 },
      DNS_RULE_MAIN: { order: 0, rules: [
        { actions: [fixed, { ...request, onError: 'continue' }] },
        { when: { field: 'lastAction.code', op: 'eq', value: 'UPSTREAM_TIMEOUT' }, actions: [{ type: 'setTtl', ttl: 7 }] },
      ] },
    });
    const result = await post();
    assert.deepEqual(result.records[0].data, [192, 0, 2, 1]);
    assert.equal(result.records[0].ttl, 7);
    assert.equal(requests.length, 1);
    assert.ok(logs.join('\n').includes('rolled_back_continue'));
    assert.ok(!logs.join('\n').includes('127.0.0.1'));
  });
});


test('TLS success, timeout and trusted caller cancellation release the server connection', async () => {
  for (const mode of ['success', 'timeout', 'cancel']) {
    await serverTest((socket, wire) => {
      if (mode === 'success') socket.write(frame(responseWire(wire)));
    }, async ({ port, sockets }) => {
      await setup(port, { DNS_LIMITS: { upstreamTimeoutMs: mode === 'timeout' ? 40 : 1500 } }, mode === 'cancel');
      const result = await post(query(), mode === 'cancel' ? { 'x-test-cancel': '1' } : {});
      assert.equal(result.flags & 15, mode === 'success' ? 0 : 2);
      for (let i = 0; i < 40 && sockets.size; i++) await new Promise(resolve => setTimeout(resolve, 5));
      assert.equal(sockets.size, 0, mode);
      if (mode === 'cancel') assert.ok(logs.join('\n').includes('REQUEST_CANCELLED'));
      assert.ok(!logs.join('\n').includes('private-cancel-reason'));
    });
  }
});


test('TLS rejects a wrong server identity or untrusted chain without sending DNS or falling back', async () => {
  for (const mode of ['identity', 'trust']) await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, requests }) => {
    await setup(port, { DNS_UPSTREAMS: { primary: { transport: 'tls', address: '127.0.0.1', port, serverName: mode === 'identity' ? 'wrong.invalid' : 'example.test' } } }, false, mode !== 'trust');
    assert.equal((await post()).flags & 15, 2);
    assert.equal(requests.length, 0);
    assert.ok(logs.join('\n').includes('UPSTREAM_FAILED'));
    // Only fixed application events are emitted, not the raw TLS exception.
    const events = logs.filter(line => line.includes('"event":')).join('\n');
    assert.ok(!events.includes('wrong.invalid'));
    assert.ok(!events.includes('127.0.0.1'));
    assert.ok(!events.includes('CERTIFICATE_VERIFY_FAILED'));
  });
});

test('TLS configuration fails closed for invalid identities and insecure overrides', async () => {
  await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, requests }) => {
    for (const bad of [
      { serverName: '' }, { serverName: null }, { serverName: '*.example.test' },
      { serverName: '127.0.0.1' }, { serverName: 'example.test/path' },
      { verifyCertificate: false }, { secureTransport: 'off' }, { caCertificates: [] },
    ]) {
      await setup(port, { DNS_UPSTREAMS: { primary: { transport: 'tls', address: '127.0.0.1', port, serverName: 'example.test', ...bad } } });
      assert.equal((await post()).flags & 15, 2);
      assert.equal(requests.length, 0);
      assert.ok(logs.join('\n').includes('INVALID_CONFIG'));
    }
  });
});

test('a stalled TLS handshake is bounded and never retries as plaintext', async () => {
  const { default: net } = await import('node:net');
  const sockets = new Set(), chunks = [];
  let connections = 0;
  const server = net.createServer(socket => {
    connections++; sockets.add(socket);
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    await setup(server.address().port, { DNS_LIMITS: { upstreamTimeoutMs: 80 } });
    assert.equal((await post()).flags & 15, 2);
    assert.equal(connections, 1);
    assert.ok(chunks.length > 0);
    assert.equal(chunks[0][0], 22); // TLS handshake record, never a plaintext DNS frame.
    assert.ok(logs.join('\n').includes('UPSTREAM_TIMEOUT'));
    for (let i = 0; i < 40 && sockets.size; i++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(sockets.size, 0);
  } finally { for (const socket of sockets) socket.destroy(); server.close(); await once(server, 'close'); }
});

test('native transport caches only original DNS and still executes rules on a hit', async () => {
  await serverTest((socket, wire) => socket.write(frame(responseWire(wire))), async ({ port, requests }) => {
    await setup(port, { DNS_CACHE: { read: true, write: true }, DNS_RULE_MAIN: group([request, { type: 'setTtl', ttl: 17 }]) });
    assert.equal((await post()).records[0].ttl, 17);
    const wire = query(); wire[0] = 1; wire[1] = 2;
    const hit = await post(wire);
    assert.equal(hit.id, 258);
    assert.equal(hit.records[0].ttl, 17);
    assert.equal(requests.length, 1);
  });
});

test('a cached TLS answer never bypasses a changed authentication identity', async () => {
  await serverTest((socket, wire) => socket.write(frame(responseWire(wire))), async ({ port, requests }) => {
    await setup(port, { DNS_CACHE: { read: true, write: true } });
    assert.equal((await post()).flags & 15, 0);
    await setup(port, { DNS_CACHE: { read: true, write: true }, DNS_UPSTREAMS: { primary: { transport: 'tls', address: '127.0.0.1', port, serverName: 'wrong.invalid' } } });
    assert.equal((await post()).flags & 15, 2);
    assert.equal(requests.length, 1);
  });
});
