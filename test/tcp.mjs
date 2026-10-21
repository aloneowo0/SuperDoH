import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import net from 'node:net';
import { once } from 'node:events';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { query, decode, responseWire } from './helpers/dns-wire.mjs';

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
const logs = [];
class TestLog extends Log { constructor() { super(LogLevel.ERROR); } log(text) { logs.push(text); } }
const options = bindings => ({
  modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/tcp-bundle.js'), script: activeBundle.outputFiles[0].text,
  compatibilityDate: '2026-07-30', compatibilityFlags: ['enable_request_signal'], bindings, log: new TestLog(),
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
  const server = net.createServer(socket => {
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
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try { await run({ port: server.address().port, requests, sockets }); }
  finally { for (const s of sockets) s.destroy(); server.close(); await once(server, 'close'); }
}
async function setup(port, extra = {}, callerOptions = false) {
  activeBundle = callerOptions ? optionsBundle : bundle;
  logs.length = 0;
  await mf.setOptions(options({ DNS_UPSTREAMS: { primary: { transport: 'tcp', address: '127.0.0.1', port } }, DNS_RULE_MAIN: group([request]), ...extra }));
}
async function post(wire = query(), headers = {}) {
  const response = await mf.dispatchFetch('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', ...headers }, body: wire });
  assert.equal(response.status, 200); return decode(new Uint8Array(await response.arrayBuffer()));
}

test('public DoH explicitly queries a real TCP DNS source once and runs later JSON actions', async () => {
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

test('unused malformed TCP definitions fail preflight before a valid source is contacted', async () => {
  await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, requests }) => {
    for (const bad of [
      { address: '', port }, { address: '127.0.0.999', port }, { address: 'resolver.test/path', port },
      { address: 'resolver.test?', port }, { address: '[::1]', port }, { address: 'host:53', port },
      { address: 'resolver.test', port: 0 }, { address: 'resolver.test', port: 65536 },
      { address: 'resolver.test', port: '53' }, { address: 'resolver.test', port: null },
      { address: 'resolver.test', port, url: 'https://secret.test/' },
    ]) {
      await setup(port, { DNS_UPSTREAMS: {
        primary: { transport: 'tcp', address: '127.0.0.1', port },
        unused: { transport: 'tcp', ...bad },
      } });
      assert.equal((await post()).flags & 15, 2, JSON.stringify(bad));
      assert.equal(requests.length, 0);
    }
  });
});

test('TCP length prefixes and messages may be fragmented and do not require peer EOF', async () => {
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

test('valid failure RCODEs and EDNS extended codes survive the TCP path', async () => {
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

test('TCP truncation, invalid length, surplus bytes and mismatched answers fail without retry', async () => {
  const handlers = [
    socket => socket.end(Uint8Array.of(0)),
    socket => socket.end(Uint8Array.of(0, 11)),
    socket => socket.end(Uint8Array.of(0, 40, 1, 2, 3)),
    (socket, wire) => { const b = frame(responseWire(wire)); socket.end(Buffer.concat([b, Buffer.from([1])])); },
    (socket, wire) => { const b = responseWire(wire); b[0] ^= 1; socket.end(frame(b)); },
    socket => socket.destroy(),
  ];
  for (const handler of handlers) await serverTest(handler, async ({ port, requests }) => {
    await setup(port);
    const result = await post();
    assert.equal(result.flags & 15, 2);
    assert.equal(result.id, 0x4242);
    assert.equal(requests.length, 1);
  });
});

test('oversized TCP frame declarations fail immediately even when the peer stays open', async () => {
  await serverTest(socket => socket.write(Buffer.from([0xff, 0xff])), async ({ port, requests }) => {
    await setup(port, { DNS_LIMITS: { maxResponseBytes: 512, upstreamTimeoutMs: 1000 } });
    assert.equal((await post()).flags & 15, 2);
    assert.ok(logs.join('\n').includes('RESOURCE_LIMIT'));
    assert.ok(!logs.join('\n').includes('UPSTREAM_TIMEOUT'));
    assert.equal(requests.length, 1);
  });
});

test('an optional TCP timeout preserves a prior answer and exposes failure to JSON', async () => {
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

test('TCP actions share network and absolute execution budgets', async () => {
  await serverTest((socket, wire) => socket.write(frame(responseWire(wire))), async ({ port, requests }) => {
    await setup(port, { DNS_LIMITS: { maxNetworkRequests: 1 }, DNS_RULE_MAIN: group([request, request]) });
    assert.equal((await post()).flags & 15, 2);
    assert.equal(requests.length, 1);
    assert.ok(logs.join('\n').includes('RESOURCE_LIMIT'));
  });
  await serverTest(() => {}, async ({ port, requests }) => {
    await setup(port, { DNS_LIMITS: { maxExecutionTimeMs: 40, upstreamTimeoutMs: 1000 }, DNS_RULE_MAIN: group([{ ...request, onError: 'continue' }, fixed]) });
    assert.equal((await post()).flags & 15, 2);
    assert.equal(requests.length, 1);
    assert.ok(logs.join('\n').includes('EXECUTION_TIMEOUT'));
  });
});

test('TCP success, timeout and trusted caller cancellation release the server connection', async () => {
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

test('an unavailable TCP listener is an observable optional action failure, not a missing or successful response', async () => {
  const probe = net.createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
  const port = probe.address().port; probe.close(); await once(probe, 'close');
  await setup(port, { DNS_LIMITS: { upstreamTimeoutMs: 80 }, DNS_RULE_MAIN: { order: 0, rules: [
    { actions: [{ ...request, onError: 'continue' }] },
    { when: { field: 'lastAction.success', op: 'eq', value: false }, actions: [fixed] },
  ] } });
  const result = await post();
  assert.equal(result.flags & 15, 0, logs.join('\n'));
  assert.deepEqual(result.records[0].data, [192, 0, 2, 1]);
  assert.ok(logs.join('\n').includes('rolled_back_continue'));
});
