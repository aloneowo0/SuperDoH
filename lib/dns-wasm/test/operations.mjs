import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { wire, record, name, u16, u32 } from './wire.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(process.env.DNS_WASM_TEST_TOOLS ? path.resolve(process.env.DNS_WASM_TEST_TOOLS, 'package.json') : import.meta.url);
const { Miniflare } = require('miniflare');
const mf = new Miniflare({ modules: true, scriptPath: path.join(root, 'test/worker.js'), modulesRoot: root, compatibilityDate: '2025-05-27', modulesRules: [{ type: 'ESModule', include: ['**/*.js'], fallthrough: true }, { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true }] });
let passed = 0;
async function op(op, ...args) {
  const res = await mf.dispatchFetch('https://dns.test/op', { method: 'POST', body: JSON.stringify({ op, args }) });
  const value = await res.json();
  assert.equal(res.status, 200, `${op}: ${JSON.stringify(value)}`);
  return value;
}
async function rejects(op, ...args) {
  const res = await mf.dispatchFetch('https://dns.test/op', { method: 'POST', body: JSON.stringify({ op, args }) });
  assert.equal(res.status, 400, `${op} should reject`);
}
async function test(label, fn) {
  try { await fn(); passed++; } catch (error) { error.message = `${label}: ${error.message}`; throw error; }
}
const rr = (rtype, rdata, owner = 'example.com') => ({ name: owner, rtype, class: 1, ttl: 60, rdata });
const message = overrides => ({ id: 0x4242, flags: 0x8180, questions: [{ name: 'example.com', rtype: 1, class: 1 }], answers: [], authority: [], additional: [], ...overrides });
const rows = JSON.parse(fs.readFileSync(path.join(root, 'test/fixtures/records.json'), 'utf8'));
const schemas = {};
try {
  for (const row of rows) await test(`native ${row.label}`, async () => {
    const data = await op('decodeRdata', row.rtype, row.bytes);
    schemas[row.label] = data;
    assert.deepEqual(await op('encodeRdata', row.rtype, data), row.bytes);
    const input = wire({ qtype: row.rtype, answers: [record(row.rtype, row.bytes)] });
    const p = await op('parseMessage', input);
    p.answers[0].name = 'longer-owner.example'; p.answers[0].ttl = 123;
    const encoded = await op('encodeMessage', p);
    const parsed = await op('parseMessage', encoded);
    assert.equal(parsed.answers[0].ttl, 123); assert.equal(parsed.answers[0].name, 'longer-owner.example');
    assert.deepEqual(parsed.answers[0].rdata, data);
    // The output writer is uncompressed: independently assert the final RDATA bytes.
    assert.deepEqual(encoded.slice(-row.bytes.length), row.bytes);
  });
  await test('all flags, multiple questions and non-IN class', async () => {
    const p = message({ flags: 0xffff }); p.questions.push({ name: '_sip._tcp.example', rtype: 33, class: 3 });
    const out = await op('parseMessage', await op('encodeMessage', p));
    assert.equal(out.flags, 0xffff); assert.deepEqual(out.questions, p.questions);
  });
  await test('root query and root-valued native names', async () => {
    const q = await op('parseMessage', await op('buildQuery', '.', 2, 0));
    assert.equal(q.questions[0].name, '.');
    const d = await op('decodeRdata', 2, [0]); assert.deepEqual(await op('encodeRdata', 2, d), [0]);
  });
  await test('compressed RDATA survives insertion and moving sections', async () => {
    const ptr = [0xc0, 12];
    const input = wire({ answers: [record(5, ptr), record(15, [...u16(10), ...ptr])], authority: [record(6, [...ptr, ...ptr, ...[1, 2, 3, 4, 5].flatMap(u32)])], additional: [record(33, [...u16(1), ...u16(2), ...u16(443), ...ptr])] });
    const p = await op('parseMessage', input);
    const before = [...p.answers, ...p.authority, ...p.additional].map(r => r.data);
    p.answers.unshift(rr(1, { A: { addr: '8.8.8.8' } }, 'added.example'));
    p.additional.push(p.authority.pop());
    const out = await op('parseMessage', await op('encodeMessage', p));
    assert.deepEqual([out.answers[1].data, out.answers[2].data, out.additional[1].data, out.additional[0].data], before);
  });
  await test('A/AAAA editing and generic JSON', async () => {
    const p = message({ answers: [rr(1, { A: { addr: '8.8.8.8' } }), rr(28, { Aaaa: { addr: '2001:db8::1' } })] });
    const w = await op('encodeMessage', p); const ips = await op('extractIPs', w);
    assert.equal(ips[0].address, '8.8.8.8'); assert.equal(ips[1].bytes.length, 16);
    const j = await op('toDnsJson', w); assert.equal(j.Answer.length, 2);
  });
  await test('EDNS explicit creation and metadata preservation', async () => {
    await rejects('setEdns', message(), { flags: 0x8000 });
    let p = await op('setEdns', message(), { udp_payload_size: 1232, version: 7, extended_rcode: 171, flags: 0x8001, options: [{ code: 65001, data: [0, 255] }] });
    p = await op('setEdnsOption', p, 12, [0, 0]);
    p = await op('parseMessage', await op('encodeMessage', p));
    const edns = await op('getEdns', p);
    assert.equal(edns.udp_payload_size, 1232); assert.equal(edns.version, 7); assert.equal(edns.extended_rcode, 171); assert.equal(edns.flags, 0x8001);
    assert.equal(edns.options.length, 2);
    p = await op('removeEdnsOption', p, 12); assert.equal((await op('getEdns', p)).options.length, 1);
    p = await op('removeEdns', p); assert.equal(await op('getEdns', p), null);
  });
  for (const [address, width] of [['192.168.1.255', 32], ['2001:db8::abcd', 128]]) {
    for (const prefix of [0, 1, 7, width - 1, width]) await test(`ECS ${address}/${prefix}`, async () => {
      const data = await op('encodeEcs', { address, source_prefix: prefix });
      assert.equal(data.length, 4 + Math.ceil(prefix / 8));
      const value = await op('decodeEcs', data);
      assert.equal(value.source_prefix, prefix);
      assert.deepEqual(await op('encodeEcs', value), data);
    });
  }
  await test('ECS model add/replace/remove does not alter unrelated options', async () => {
    let p = await op('setEdns', message(), { udp_payload_size: 1400, options: [{ code: 65001, data: [255] }] });
    p = await op('setEcs', p, { address: '10.1.2.255', source_prefix: 25 });
    assert.equal((await op('getEcs', p)).address, '10.1.2.128');
    p = await op('setEcs', p, { address: '8.8.8.8', source_prefix: 24 });
    assert.equal((await op('getEdns', p)).options.length, 2);
    p = await op('removeEdnsOption', p, 8); assert.equal(await op('getEcs', p), null);
    assert.deepEqual((await op('getEdns', p)).options[0], { code: 65001, data: [255] });
  });
  await test('malformed ECS and EDE', async () => {
    await rejects('encodeEcs', { address: '1.2.3.4', source_prefix: 33 });
    await rejects('encodeEcs', { address: '::1', source_prefix: 129 });
    await rejects('decodeEcs', [0, 1, 25, 0, 1, 2, 3, 255]);
    await rejects('decodeEcs', [0, 1, 0, 33]);
    await rejects('decodeEde', [0]);
    const ede = { code: 22, text: '测试 EDE' };
    assert.deepEqual(await op('decodeEde', await op('encodeEde', ede)), ede);
    // Invalid UTF8 can still round-trip as an unknown/raw EDNS option.
    const p = message({ additional: [{ name: '.', rtype: 41, class: 1232, ttl: 0, rdata: { Opt: { options: [{ code: 15, data: [0, 22, 255] }] } } }] });
    assert.equal((await op('parseMessage', await op('encodeMessage', p))).additional[0].rdata.Opt.options[0].data[2], 255);
  });
  await test('extended RCODE is not confused with OPT TTL flags', async () => {
    let p = await op('setRcode', message(), 0xabc, 1232);
    p = await op('parseMessage', await op('encodeMessage', p));
    assert.equal(await op('getRcode', p), 0xabc);
    assert.equal((await op('toDnsJson', await op('encodeMessage', p))).Status, 0xabc);
    await rejects('setRcode', message(), 16);
  });
  for (const [key, value] of [[0, [3, 1]], [1, ['h2', 'h3']], [2, null], [3, 443], [4, ['1.2.3.4']], [6, ['2001:db8::1']], [65001, [0, 255]]]) await test(`SvcParam ${key} codec`, async () => {
    const bytes = await op('encodeSvcParam', key, value);
    const decoded = await op('decodeSvcParam', key, bytes);
    assert.deepEqual(await op('encodeSvcParam', key, decoded), bytes);
  });
  await test('SVCB/HTTPS arbitrary parameter editing and unknown preservation', async () => {
    let r = rr(65, { Https: { priority: 1, target: '.', params: [{ key: 65001, data: [0, 255] }] } });
    r = await op('setSvcParam', r, 1, ['h2', 'h3']);
    r = await op('setSvcParam', r, 3, 443);
    r = await op('setSvcParam', r, 0, [3, 1]);
    const data = await op('decodeRdata', 65, await op('encodeRdata', 65, r.rdata));
    assert.deepEqual(data.Https.params.map(p => p.key), [0, 1, 3, 65001]);
    assert.equal(await op('getSvcParam', r, 3), 443);
    r = await op('removeSvcParam', r, 3); await rejects('encodeRdata', 65, r.rdata);
    r = await op('removeSvcParam', r, 0); await op('encodeRdata', 65, r.rdata);
  });
  await test('ECH configs can be edited without any CDN policy', async () => {
    const live = JSON.parse(fs.readFileSync(path.join(root, 'test/fixtures/real-dns.json'), 'utf8'));
    const p = await op('parseMessage', Array.from(Buffer.from(live['cloudflare-ech.com:65'], 'base64')));
    const sample = p.answers.find(r => r.rtype === 65);
    const config = await op('getSvcParam', sample, 5);
    let r = rr(65, { Https: { priority: 1, target: '.', params: [] } }, 'arbitrary.example');
    r = await op('setSvcParam', r, 5, config);
    const out = await op('parseMessage', await op('encodeMessage', message({ answers: [r] })));
    assert.equal(await op('getSvcParam', out.answers[0], 5), config);
    r = await op('removeSvcParam', r, 5); assert.equal(r.rdata.Https.params.length, 0);
    await rejects('encodeSvcParam', 5, 'AAE=');
  });
  await test('reject malformed SVCB params and AliasMode', async () => {
    for (const params of [[{ key: 1, data: [] }], [{ key: 3, data: [1] }], [{ key: 4, data: [1] }], [{ key: 6, data: [] }], [{ key: 1, data: [1, 104] }, { key: 1, data: [1, 104] }], [{ key: 0, data: [0, 3] }], [{ key: 2, data: [] }]]) {
      await rejects('encodeRdata', 65, { Https: { priority: 1, target: '.', params } });
    }
    const alias = { Https: { priority: 0, target: 'alias.example', params: [{ key: 3, data: [1, 187] }] } };
    assert.deepEqual(await op('decodeRdata', 65, await op('encodeRdata', 65, alias)), alias);
  });
  await test('raw input cannot bypass known record validation', async () => {
    await rejects('encodeRdata', 1, { Raw: [1, 2] });
    await rejects('decodeRdata', 5, [192, 0]);
    await rejects('encodeRdata', 28, { A: { addr: '1.2.3.4' } });
    await rejects('encodeMessage', message({ answers: [{ ...rr(1, { A: { addr: '1.2.3.4' } }), ttl: -1 }] }));
  });
  await test('message authentication is parsed but cannot be silently re-encoded', async () => {
    const tsig = [...name('hmac-sha256'), 0, 0, 0, 0, 0, 1, ...u16(300), ...u16(32), ...Array(32).fill(0x42), ...u16(0x4242), 0, 0, 0, 0];
    const input = wire({ additional: [record(250, tsig, name('key.example'), 255, 0)] });
    const p = await op('parseMessage', input);
    assert.equal(p.additional[0].rtype, 250);
    await rejects('encodeMessage', p);
    const out = await op('parseMessage', await op('encodeMessage', p, { strip_message_authentication: true }));
    assert.equal(out.additional.length, 0);
    const sig0 = [...u16(0), 15, 0, ...u32(0), ...u32(1900000000), ...u32(1700000000), ...u16(1234), ...name('example'), ...Array(64).fill(0x42)];
    const s = await op('parseMessage', wire({ additional: [record(24, sig0)] }));
    await rejects('encodeMessage', s);
    assert.equal((await op('parseMessage', await op('encodeMessage', s, { strip_message_authentication: true }))).additional.length, 0);
  });
  await test('explicit RRset invalidation only removes matching RRSIG', async () => {
    const sig = rows.find(r => r.rtype === 46).bytes;
    const input = wire({ flags: 0x81a0, answers: [record(1, [1, 2, 3, 4]), record(46, sig), record(46, sig, name('other.example'))] });
    const p = await op('parseMessage', input);
    assert.equal((await op('parseMessage', await op('encodeMessage', p))).flags & 0x20, 0x20);
    p.answers[0].rdata.A.addr = '8.8.8.8';
    const result = await op('parseMessage', await op('encodeMessage', p, { invalidate_rrsets: [{ name: 'EXAMPLE.COM.', rtype: 1, class: 1 }] }));
    assert.equal(result.flags & 0x20, 0); assert.equal(result.answers.filter(r => r.rtype === 46).length, 1);
    assert.equal(result.answers.find(r => r.rtype === 46).name, 'other.example');
  });
  await test('OPT placement, duplicate records and trailing garbage', async () => {
    const opt = { name: '.', rtype: 41, class: 1232, ttl: 0, rdata: { Opt: { options: [] } } };
    await rejects('encodeMessage', message({ additional: [opt, opt] }));
    await rejects('encodeMessage', message({ answers: [opt] }));
    await rejects('encodeMessage', message({ additional: [{ ...opt, name: 'bad.example' }] }));
    await rejects('parseMessage', wire().concat(0));
  });
  await test('generic request response matching is optional', async () => {
    const query = await op('buildQuery', 'example.com', 16, 0x4242, { class: 3, flags: 0 });
    const response = await op('buildResponse', query, { rcode: 3 });
    assert.equal((await op('matchResponse', response, query)).rcode, 3);
    const p = await op('parseMessage', response); p.id++;
    await rejects('matchResponse', await op('encodeMessage', p), query);
    p.id--; p.questions[0].class = 1;
    await rejects('matchResponse', await op('encodeMessage', p), query);
    assert.equal((await op('validateMessage', query)).is_response, false);
  });
  await test('new error responses preserve requested flags without inventing RA', async () => {
    const query = await op('buildQuery', 'example.com', 1, 12, { flags: 0x0110 });
    const p = await op('parseMessage', await op('buildResponse', query, { rcode: 2 }));
    assert.equal(p.id, 12); assert.equal(p.flags, 0x8112); assert.equal(p.additional.length, 0);
    const ext = await op('parseMessage', await op('buildResponse', query, { rcode: 16, udp_payload_size: 1232 }));
    assert.equal(await op('getRcode', ext), 16);
  });
  await test('type mapping supports native and unknown types', async () => {
    assert.equal(await op('typeCode', 'https'), 65); assert.equal(await op('typeName', 65), 'HTTPS');
    assert.equal(await op('typeCode', 'TYPE65280'), 65280);
    await rejects('typeName', 65536); await rejects('decodeRdata', -1, []);
  });
  await test('byteOffset views and typed array model fields', async () => {
    const res = await mf.dispatchFetch('https://dns.test/views');
    const value = await res.json();
    assert.equal(res.status, 200, JSON.stringify(value));
    assert.equal(value.id, 0x4242); assert.deepEqual(value.raw, [0, 255, 192, 12]);
  });
  for (const row of rows) await test(`combined operations preserve native ${row.label}`, async () => {
    const p = message({ answers: [rr(row.rtype, schemas[row.label])] });
    const encoded = await op('encodeMessage', p, { strip_message_authentication: true });
    assert.deepEqual(await op('normalizeMessage', p), await op('parseMessage', encoded));
    const q = await op('buildQuery', 'example.com', 1, 0x4242);
    assert.deepEqual(await op('encodeResponse', p, q, encoded.length), encoded);
    assert.equal(await op('encodeResponse', p, q, encoded.length - 1), null);
  });
  await test('checked response encoding preserves its default authentication stripping contract', async () => {
    const q = await op('buildQuery', 'example.com', 1, 0x4242);
    const tsig = [...name('hmac-sha256'), 0, 0, 0, 0, 0, 1, ...u16(300), ...u16(32), ...Array(32).fill(0x42), ...u16(0x4242), 0, 0, 0, 0];
    const sig0 = [...u16(0), 15, 0, ...u32(0), ...u32(1900000000), ...u32(1700000000), ...u16(1234), ...name('example'), ...Array(64).fill(0x42)];
    for (const [rtype, data, owner, cls] of [[250, tsig, name('key.example'), 255], [24, sig0, name('example.com'), 1]]) {
      const p = await op('parseMessage', wire({ additional: [record(rtype, data, owner, cls, 0)] }));
      const expected = await op('encodeMessage', p, { strip_message_authentication: true });
      assert.deepEqual(await op('encodeResponse', p, q, 65535), expected);
      await rejects('encodeResponse', p, q, 65535, {});
      assert.deepEqual(await op('encodeResponse', p, q, 65535, { strip_message_authentication: true }), expected);
    }
  });
  await test('checked response encoding rejects cache entries with mismatched identity', async () => {
    const q = await op('buildQuery', 'example.com', 1, 0x4242);
    const wrongQuestion = message({ questions: [{ name: 'other.example', rtype: 1, class: 1 }] });
    await rejects('encodeResponse', wrongQuestion, q, 65535, {});
  });
  await test('checked encoding keeps correspondence checks and size error precedence', async () => {
    const q = await op('buildQuery', 'example.com', 1, 0x4242);
    for (const p of [message({ id: 7 }), message({ flags: 0x0180 }), message({ flags: 0x8980 }),
      message({ questions: [{ name: 'other.example', rtype: 1, class: 1 }] }),
      message({ questions: [{ name: 'example.com', rtype: 28, class: 1 }] }),
      message({ questions: [{ name: 'example.com', rtype: 1, class: 3 }] })]) {
      await rejects('encodeResponse', p, q, 65535);
      assert.equal(await op('encodeResponse', p, q, 0), null);
    }
    await rejects('encodeResponse', message(), [], 65535);
    assert.equal(await op('encodeResponse', message(), [], 0), null);
    await rejects('normalizeMessage', message({ answers: [rr(1, { A: { addr: 'invalid' } })] }));
    await rejects('encodeResponse', message({ answers: [rr(1, { A: { addr: 'invalid' } })] }), q, 0);
    await rejects('encodeResponse', message(), q, -1);
  });
  const captures = JSON.parse(fs.readFileSync(path.join(root, 'test/fixtures/real-dns.json'), 'utf8'));
  for (const [label, b64] of Object.entries(captures)) await test(`captured roundtrip ${label}`, async () => {
    const p = await op('parseMessage', Array.from(Buffer.from(b64, 'base64')));
    const out = await op('parseMessage', await op('encodeMessage', p));
    assert.deepEqual(out, p);
  });
  if (process.env.DNS_WASM_SCHEMA_OUT) fs.writeFileSync(process.env.DNS_WASM_SCHEMA_OUT, JSON.stringify(schemas, null, 2));
  console.log(`Workers/workerd generic DNS operations: ${passed} passed (including ${rows.length} RR types)`);
} finally { await mf.dispose(); }
