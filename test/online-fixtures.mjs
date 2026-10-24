import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Log, LogLevel, Miniflare } from 'miniflare';
import { decode, query } from './helpers/dns-wire.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const buildFixture = async () => build({
  entryPoints: [path.join(root, 'test/online-fixture-worker.js')], bundle: true, write: false,
  external: ['cloudflare:sockets'], format: 'esm', platform: 'browser',
  plugins: [{ name: 'wasm-external', setup(api) {
    api.onResolve({ filter: /\.wasm$/ }, args => ({
      path: '../' + path.relative(root, path.resolve(args.resolveDir, args.path)).split(path.sep).join('/'), external: true,
    }));
  } }],
});
const bundled = await buildFixture();
const runtimeOptions = {
  modules: true, modulesRoot: root, scriptPath: path.join(root, 'test/online-fixture-worker.js'),
  script: bundled.outputFiles[0].text, compatibilityDate: '2026-10-19', compatibilityFlags: ['enable_request_signal', 'no_nodejs_compat', 'no_nodejs_compat_v2'], log: new Log(LogLevel.NONE),
  bindings: { EXPIRES_AT: Date.now() + 60 * 60 * 1000 },
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
  outboundService: { network: { allow: [] } },
};
const mf = new Miniflare(runtimeOptions);
after(() => mf.dispose());
const postDns = (endpoint, packet) => mf.dispatchFetch(`https://fixture.test${endpoint}`, {
  method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: packet,
});

test('A and AAAA fixture replies preserve one question and only return documentation addresses', async () => {
  for (const [type, address] of [[1, [192, 0, 2, 8]], [28, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]]]) {
    const input = query('sample.example', type, 0x0110);
    const response = await postDns('/dns', input);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Content-Type'), 'application/dns-message');
    const message = decode(new Uint8Array(await response.arrayBuffer()));
    assert.equal(message.id, 0x4242);
    assert.equal(message.flags & 0x808f, 0x8080);
    assert.equal(message.flags & 0x0110, 0x0110);
    assert.deepEqual(message.questions, [{ name: 'sample.example', type, class: 1 }]);
    assert.equal(message.records.length, 1);
    assert.equal(message.records[0].section, 0);
    assert.equal(message.records[0].name, 'sample.example');
    assert.equal(message.records[0].type, type);
    assert.equal(message.records[0].ttl, 60);
    assert.deepEqual(message.records[0].data, address);
  }
});

test('unknown DNS types succeed without fabricating records', async () => {
  const response = await postDns('/dns', query('unknown.example', 65280));
  assert.equal(response.status, 200);
  const message = decode(new Uint8Array(await response.arrayBuffer()));
  assert.equal(message.flags & 15, 0);
  assert.deepEqual(message.records, []);
});

test('HTTPS reply carries the synthetic ECH ServiceParam and no-store variant is explicit', async () => {
  const packet = query('example.com', 65);
  const regular = await postDns('/dns', packet);
  assert.equal(regular.status, 200);
  const response = decode(new Uint8Array(await regular.arrayBuffer()));
  assert.equal(response.flags & 15, 0);
  assert.equal(response.records.length, 1);
  const rr = response.records[0];
  assert.equal(rr.type, 65);
  assert.equal(rr.ttl, 60);
  const bytes = rr.data;
  assert.deepEqual(bytes.slice(0, 3), [0, 1, 0]);
  let offset = 3;
  const params = new Map();
  while (offset < bytes.length) {
    const key = bytes[offset] * 256 + bytes[offset + 1];
    const length = bytes[offset + 2] * 256 + bytes[offset + 3];
    offset += 4;
    params.set(key, bytes.slice(offset, offset + length));
    offset += length;
  }
  const echExample = JSON.parse(await readFile(path.join(root, 'examples/ech-direct.json'), 'utf8'));
  const echBase64 = echExample.DNS_RULE_ECH_DIRECT.rules[0].actions.find(action => action.type === 'loadEch').config;
  assert.deepEqual(params.get(5), [...Buffer.from(echBase64, 'base64')]);
  const noStore = await postDns('/dns-no-store', packet);
  assert.equal(noStore.status, 200);
  assert.equal(noStore.headers.get('Cache-Control'), 'no-store');
  assert.deepEqual(decode(new Uint8Array(await noStore.arrayBuffer())).records, response.records);
});

test('fixture rejects malformed, multi-question, and over-limit DNS bodies safely', async () => {
  const malformed = await postDns('/dns', new Uint8Array([1, 2, 3]));
  assert.equal(malformed.status, 400);
  assert.equal(await malformed.text(), 'Invalid DNS message');
  const multiple = query('one.example');
  multiple[5] = 2;
  const multiResponse = await postDns('/dns', multiple);
  assert.equal(multiResponse.status, 400);
  assert.equal(await multiResponse.text(), 'Invalid DNS message');
  const tooLarge = await postDns('/dns', new Uint8Array(4097));
  assert.equal(tooLarge.status, 413);
  assert.equal(await tooLarge.text(), 'Request body too large');
});

test('fixture rejects unsupported DNS opcode and non-IN question class', async () => {
  const opcode = query('sample.example');
  opcode[2] |= 0x08;
  const opcodeResponse = await postDns('/dns', opcode);
  assert.equal(opcodeResponse.status, 400);
  assert.equal(await opcodeResponse.text(), 'Invalid DNS message');
  const nonInternet = query('sample.example');
  nonInternet[nonInternet.length - 1] = 3;
  const classResponse = await postDns('/dns', nonInternet);
  assert.equal(classResponse.status, 400);
  assert.equal(await classResponse.text(), 'Invalid DNS message');
});

test('fixture times out a stalled DNS request body without hanging', async () => {
  const body = new ReadableStream({
    start(controller) { controller.enqueue(query()); },
    pull() {},
  });
  const started = Date.now();
  const response = await mf.dispatchFetch('https://fixture.test/dns', {
    method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, duplex: 'half', body,
  });
  assert.equal(response.status, 408);
  assert.equal(await response.text(), 'Request timed out');
  assert.ok(Date.now() - started < 2000, 'stalled body must not hang the fixture request');
});

test('list fixtures have exact valid-domain counts and switch state atomically', async () => {
  for (const count of [100, 1000, 4096]) {
    const response = await mf.dispatchFetch(`https://fixture.test/list-${count}`);
    assert.equal(response.status, 200);
    const lines = (await response.text()).trimEnd().split('\n');
    assert.equal(lines.length, count);
    assert.equal(lines[0], 'example.com');
    assert.ok(lines.slice(1).every((name, index) => name === `item${index + 2}.example`));
  }
  await mf.setOptions({ ...runtimeOptions, bindings: { EXPIRES_AT: Date.now() + 60_000, LIST_STATE: 'bad' } });
  const failed = await mf.dispatchFetch('https://fixture.test/list-100');
  assert.equal(failed.status, 503);
  assert.equal(await failed.text(), 'Fixture unavailable');
  await mf.setOptions({ ...runtimeOptions, bindings: { EXPIRES_AT: Date.now() + 60_000, LIST_STATE: 'recovered' } });
  const recovered = await mf.dispatchFetch('https://fixture.test/list-100');
  const recoveredLines = (await recovered.text()).trimEnd().split('\n');
  assert.equal(recovered.status, 200);
  assert.equal(recoveredLines.length, 100);
  assert.equal(recoveredLines[0], 'changed.example');
});

test('fixture has safe failure and reserved-address-only geo routes', async () => {
  const failed = await mf.dispatchFetch('https://fixture.test/fail');
  assert.equal(failed.status, 503);
  assert.equal(await failed.text(), 'Fixture failure');
  for (const ip of ['192.0.2.8', '192.0.2.9', '2001:db8::8']) {
    const response = await mf.dispatchFetch(`https://fixture.test/geo?ip=${encodeURIComponent(ip)}`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Cache-Control'), 'max-age=60');
    assert.deepEqual(await response.json(), { ip, network: { asn: 64512 }, location: { country: 'DE', region: 'fixture', city: 'fixture' } });
  }
  const rejected = await mf.dispatchFetch('https://fixture.test/geo?ip=8.8.8.8');
  assert.equal(rejected.status, 400);
  assert.equal(await rejected.text(), 'Invalid fixture IP');
});

test('fixture fails closed when expiry is missing, invalid, or elapsed', async () => {
  for (const value of [undefined, 'not-a-time', Date.now() - 1]) {
    await mf.setOptions({ ...runtimeOptions, bindings: value === undefined ? {} : { EXPIRES_AT: value } });
    const response = await mf.dispatchFetch('https://fixture.test/fail');
    assert.equal(response.status, 503);
    assert.equal(await response.text(), 'Fixture unavailable');
  }
});
