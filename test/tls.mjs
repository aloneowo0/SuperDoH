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
const logs = [];
class TestLog extends Log { constructor() { super(LogLevel.ERROR); } log(text) { logs.push(text); } }
const options = bindings => ({
  modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/tcp-bundle.js'), script: bundle.outputFiles[0].text,
  compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'global_fetch_strictly_public', 'no_nodejs_compat', 'no_nodejs_compat_v2'], bindings: { DNS_CACHE: { read: false, write: false }, ...bindings }, log: new TestLog(),
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
  const sockets = new Set(), requests = [], connections = [];
  const server = net.createServer(socket => {
    connections.push(socket); sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
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
  try { await run({ port: server.address().port, requests, sockets, connections }); }
  finally { for (const s of sockets) s.destroy(); server.close(); await once(server, 'close'); }
}
async function setup(port, extra = {}) {
  logs.length = 0;
  await mf.setOptions(options({ DNS_UPSTREAMS: { primary: { transport: 'tcp', address: '127.0.0.1', port } }, DNS_RULE_MAIN: group([request]), ...extra }));
}
async function post(wire = query(), headers = {}) {
  const response = await mf.dispatchFetch('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', ...headers }, body: wire });
  assert.equal(response.status, 200); return decode(new Uint8Array(await response.arrayBuffer()));
}

test('unsupported DoT definitions fail preflight even when unused after an answer', async () => {
  await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, connections, requests }) => {
    await setup(port, {
      DNS_UPSTREAMS: {
        primary: { transport: 'tcp', address: '127.0.0.1', port },
        unused: { transport: 'tls', address: '127.0.0.1', port, serverName: 'example.test' },
      },
      DNS_RULE_MAIN: group([fixed, { type: 'return' }]),
    });
    const result = await post();
    assert.equal(result.flags & 15, 2);
    assert.equal(result.id, 0x4242);
    assert.deepEqual(result.questions, [{ name: 'example.com', type: 1, class: 1 }]);
    assert.equal(result.records.length, 0);
    assert.equal(connections.length, 0);
    assert.equal(requests.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG'));
  });
});

test('referenced DoT cannot be downgraded or hidden by an optional action', async () => {
  await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, connections, requests }) => {
    for (const onError of [undefined, 'continue']) {
      await setup(port, {
        DNS_UPSTREAMS: { primary: { transport: 'tls', address: '127.0.0.1', port, serverName: 'private.example' } },
        DNS_RULE_MAIN: group([fixed, { ...request, ...(onError ? { onError } : {}) }]),
      });
      const result = await post();
      assert.equal(result.flags & 15, 2);
      assert.equal(result.records.length, 0);
      assert.equal(connections.length, 0);
      assert.equal(requests.length, 0);
      assert.ok(logs.join('').includes('INVALID_CONFIG'));
      assert.ok(!logs.join('').includes('private.example'));
    }
  });
});

test('a DoT definition in an unreachable rule still invalidates the configuration', async () => {
  await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, connections }) => {
    await setup(port, {
      DNS_UPSTREAMS: { primary: { transport: 'tls', address: 'resolver.example', port } },
      DNS_RULE_MAIN: { order: 0, rules: [
        { when: { field: 'query.type', op: 'eq', value: 'AAAA' }, actions: [request] },
        { actions: [fixed] },
      ] },
    });
    assert.equal((await post()).flags & 15, 2);
    assert.equal(connections.length, 0);
    assert.ok(logs.join('').includes('INVALID_CONFIG'));
  });
});

test('a cached TCP answer cannot bypass an unused unsupported DoT definition', async () => {
  await serverTest((socket, wire) => socket.write(frame(responseWire(wire))), async ({ port, connections, requests }) => {
    await setup(port, { DNS_CACHE: { read: true, write: true } });
    for (let i = 0; i < 2; i++) assert.equal((await post()).flags & 15, 0);
    assert.equal(requests.length, 1);
    assert.equal(connections.length, 1);
    await setup(port, {
      DNS_CACHE: { read: true, write: true },
      DNS_UPSTREAMS: {
        primary: { transport: 'tcp', address: '127.0.0.1', port },
        unused: { transport: 'tls', address: 'resolver.example' },
      },
    });
    const result = await post();
    assert.equal(result.flags & 15, 2);
    assert.equal(result.records.length, 0);
    assert.equal(requests.length, 1);
    assert.equal(connections.length, 1);
    assert.ok(logs.join('').includes('INVALID_CONFIG'));
  });
});

test('removing the unsupported definition restores explicit TCP without changing transport', async () => {
  await serverTest((socket, wire) => socket.end(frame(responseWire(wire))), async ({ port, connections, requests }) => {
    await setup(port, { DNS_UPSTREAMS: { primary: { transport: 'tls', address: '127.0.0.1', port, serverName: 'example.test' } } });
    assert.equal((await post()).flags & 15, 2);
    assert.equal(connections.length, 0);
    await setup(port);
    const result = await post();
    assert.equal(result.flags & 15, 0);
    assert.deepEqual(result.records[0].data, [192, 0, 2, 9]);
    assert.equal(connections.length, 1);
    assert.equal(requests.length, 1);
  });
});
