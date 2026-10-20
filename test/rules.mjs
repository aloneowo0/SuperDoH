import assert from 'node:assert/strict';
import { test, after } from 'node:test';
import { Miniflare } from 'miniflare';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const options = bindings => ({
  modules: true, modulesRoot: root, scriptPath: `${root}/test/worker.js`,
  compatibilityDate: '2026-07-30', bindings,
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
  outboundService: () => { throw new Error('Rule execution must not access the network'); },
});
const mf = new Miniflare(options({}));
after(() => mf.dispose());

function query(name = 'example.com', type = 1, flags = 0x0130) {
  const labels = name === '.' ? [0] : [...name.replace(/\.$/, '').split('.').flatMap(v => [v.length, ...Buffer.from(v)]), 0];
  return Uint8Array.from([0x42, 0x42, flags >> 8, flags & 255, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, type >> 8, type & 255, 0, 1]);
}

// Independent DNS wire reader, including compression; never derives expectations via dns-wasm.
function decode(wire) {
  const b = Buffer.from(wire); let offset = 12;
  function name(at) {
    const labels = []; let end;
    for (let steps = 0; steps < b.length; steps++) {
      const size = b[at++];
      if (size === 0) return { value: labels.join('.') || '.', end: end ?? at };
      if ((size & 0xc0) === 0xc0) { end ??= at + 1; at = ((size & 63) << 8) | b[at]; continue; }
      labels.push(b.subarray(at, at + size).toString()); at += size;
    }
    throw new Error('DNS compression loop');
  }
  const questions = [], records = [];
  for (let i = 0; i < b.readUInt16BE(4); i++) {
    const n = name(offset); offset = n.end;
    questions.push({ name: n.value, type: b.readUInt16BE(offset), class: b.readUInt16BE(offset + 2) }); offset += 4;
  }
  for (let section = 0; section < 3; section++) {
    for (let i = 0; i < b.readUInt16BE(6 + section * 2); i++) {
      const n = name(offset); offset = n.end;
      const type = b.readUInt16BE(offset), ttl = b.readUInt32BE(offset + 4), length = b.readUInt16BE(offset + 8);
      records.push({ name: n.value, type, ttl, section, data: [...b.subarray(offset + 10, offset + 10 + length)] }); offset += 10 + length;
    }
  }
  assert.equal(offset, b.length);
  return { id: b.readUInt16BE(0), flags: b.readUInt16BE(2), questions, records };
}
const record = (address = '192.0.2.1', ttl = 60) => ({ name: 'example.com', type: 'A', ttl, rdata: { A: { addr: address } } });
const answer = (address = '192.0.2.1', ttl = 60) => ({ type: 'answer', records: [record(address, ttl)] });
const group = (actions, order = 0, when) => ({ order, rules: [{ ...(when && { when }), actions }] });
async function execute(bindings = {}, wire = query(), headers = {}) {
  await mf.setOptions(options(bindings));
  const response = await mf.dispatchFetch('https://rules.test/', { method: 'POST', body: wire, headers });
  return { status: response.status, ...await response.json() };
}

test('environment JSON rule group generates a correlated custom DNS answer', async () => {
  const result = await execute({ DNS_RULE_FIXED: group([answer()]) });
  assert.equal(result.status, 200);
  assert.equal(result.termination, 'completed');
  const packet = decode(result.response);
  assert.equal(packet.id, 0x4242);
  assert.ok(packet.flags & 0x8000);
  assert.equal(packet.flags & 0x20, 0);
  assert.ok(packet.flags & 0x100);
  assert.ok(packet.flags & 0x10);
  assert.deepEqual(packet.questions, [{ name: 'example.com', type: 1, class: 1 }]);
  assert.deepEqual(packet.records, [{ name: 'example.com', type: 1, ttl: 60, section: 0, data: [192, 0, 2, 1] }]);
});

test('groups sort by integer order then variable name; rule and action arrays stay ordered', async () => {
  const result = await execute({
    DNS_RULE_Z: group([answer('192.0.2.9'), { type: 'setTtl', ttl: 9 }], 1),
    DNS_RULE_A: JSON.stringify({ order: 1, rules: [{ actions: [answer('192.0.2.2')] }, { actions: [{ type: 'setTtl', ttl: 2 }] }] }),
    DNS_RULE_FIRST: group([answer('192.0.2.3')], -1),
  });
  assert.equal(result.status, 200);
  assert.deepEqual(decode(result.response).records[0].data, [192, 0, 2, 9]);
  assert.equal(decode(result.response).records[0].ttl, 9);
});

test('invalid and unsupported configuration is rejected before any rule executes, without leaking values', async () => {
  const secret = 'https://user:secret@private.test/path-key';
  const invalid = [
    null, [], {}, { order: 1.5, rules: [] }, { order: '1', rules: [] },
    { order: 0, rules: [], upstream: secret },
    group([{ type: 'missing', source: secret }]),
    group([{ ...answer(), optional: true }]),
    group([{ type: 'setTtl', ttl: -1 }]),
    group([{ type: 'setTtl', ttl: 4294967296 }]),
    group([{ type: 'answer', records: [record('not-an-ip')] }]),
    group([{ type: 'answer', records: [{ ...record(), type: 'AAAA' }] }]),
    group([{ type: 'answer', records: [{ ...record(), extra: secret }] }]),
  ];
  for (const value of [...invalid, `{"order": ${secret}`]) {
    const result = await execute({ DNS_RULE_A: group([{ type: 'return' }]), DNS_RULE_BAD: value });
    assert.equal(result.status, 400, JSON.stringify(value));
    assert.equal(result.code, 'INVALID_CONFIG', JSON.stringify(result));
    assert.equal(result.location.group, 'DNS_RULE_BAD');
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.ok(!JSON.stringify(result).includes('not-an-ip'));
  }
});

test('conditions compose domain label boundaries and query types without unmatched action side effects', async () => {
  const bindings = { DNS_RULE_MATCH: { order: 0, rules: [
    { when: { field: 'query.name', op: 'subdomain', value: 'example.com' }, actions: [answer('192.0.2.3')] },
    { when: { all: [
      { field: 'query.name', op: 'suffix', value: 'EXAMPLE.COM.' },
      { any: [{ field: 'query.type', op: 'eq', value: 'A' }, { field: 'query.type', op: 'eq', value: 28 }] },
      { not: { field: 'query.name', op: 'exact', value: 'excluded.example.com' } },
    ] }, actions: [answer('192.0.2.4'), { type: 'setTtl', ttl: 44 }] },
    { when: { field: 'query.type', op: 'eq', value: 'TXT' }, actions: [{ type: 'return' }] },
  ] } };
  for (const name of ['example.com', 'EXAMPLE.COM.', 'a.example.com']) {
    const result = await execute(bindings, query(name));
    assert.equal(result.status, 200, JSON.stringify(result));
    assert.deepEqual(decode(result.response).records[0].data, [192, 0, 2, 4]);
    assert.equal(decode(result.response).records[0].ttl, 44);
  }
  for (const name of ['notexample.com', 'example.com.evil']) {
    assert.equal((await execute(bindings, query(name))).response, null);
  }
  assert.deepEqual(decode((await execute(bindings, query('excluded.example.com'))).response).records[0].data, [192, 0, 2, 3]);
  assert.equal((await execute({ DNS_RULE_A: group([answer()], 0, { field: 'query.name', op: 'subdomain', value: 'example.com' }) })).response, null);
});

test('a rule matches once; later rules see current state while original query and caller input stay intact', async () => {
  const wire = query();
  const result = await execute({ DNS_RULE_STATE: { order: 0, rules: [
    { when: { field: 'query.name', op: 'exact', value: 'example.com' }, actions: [
      { type: 'rewriteQuery', name: 'changed.example', queryType: 'AAAA' },
      { type: 'answer', records: [], rcode: 3 },
    ] },
    { when: { all: [
      { field: 'original.name', op: 'exact', value: 'example.com' },
      { field: 'original.type', op: 'eq', value: 'A' },
      { field: 'query.name', op: 'exact', value: 'changed.example' },
      { field: 'query.type', op: 'eq', value: 'AAAA' },
      { field: 'response.rcode', op: 'eq', value: 3 },
    ] }, actions: [answer('192.0.2.8')] },
    { when: { field: 'response.exists', op: 'eq', value: true }, actions: [{ type: 'setTtl', ttl: 88 }] },
  ] } }, wire);
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.deepEqual(wire, query());
  assert.deepEqual(result.originalQuery.questions, [{ name: 'example.com', rtype: 1, class: 1 }]);
  assert.deepEqual(result.query.questions, [{ name: 'changed.example', rtype: 28, class: 1 }]);
  const packet = decode(result.response);
  assert.deepEqual(packet.questions, [{ name: 'example.com', type: 1, class: 1 }]);
  assert.equal(packet.flags & 15, 0);
  assert.deepEqual(packet.records[0].data, [192, 0, 2, 8]);
  assert.equal(packet.records[0].ttl, 88);
});

test('completion and stop preserve no-response state; return requires even an empty explicit response', async () => {
  assert.equal((await execute()).response, null);
  assert.equal((await execute()).termination, 'completed');
  const stopped = await execute({ DNS_RULE_A: group([{ type: 'stop' }, answer()]), DNS_RULE_B: group([answer()]) });
  assert.equal(stopped.status, 200, JSON.stringify(stopped));
  assert.equal(stopped.termination, 'stopped');
  assert.equal(stopped.response, null);
  const missing = await execute({ DNS_RULE_A: group([{ type: 'return' }, answer()]) });
  assert.equal(missing.code, 'NO_RESPONSE');
  assert.deepEqual(missing.location, { group: 'DNS_RULE_A', rule: 0, action: 0 });
  for (const rcode of [0, 3]) {
    for (const terminal of ['stop', 'return']) {
      const result = await execute({ DNS_RULE_A: group([{ type: 'answer', records: [], rcode }, { type: terminal }, answer()]), DNS_RULE_B: group([answer()]) });
      assert.equal(result.status, 200, JSON.stringify(result));
      assert.equal(result.termination, terminal === 'stop' ? 'stopped' : 'returned');
      const packet = decode(result.response);
      assert.equal(packet.flags & 15, rcode);
      assert.deepEqual(packet.records, []);
    }
  }
  const ttl = await execute({ DNS_RULE_A: group([{ type: 'setTtl', ttl: 5 }]) });
  assert.equal(ttl.code, 'NO_RESPONSE');
});

test('malformed and unsupported DNS inputs fail with stable redacted input errors', async () => {
  const responsePacket = query(); responsePacket[2] |= 0x80;
  const noQuestion = Uint8Array.from([0x42, 0x42, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const opcode = query(); opcode[2] |= 0x08;
  const malformed = [new Uint8Array(), new Uint8Array(11), query().slice(0, -1), responsePacket, noQuestion, opcode];
  for (const wire of malformed) {
    const result = await execute({}, wire);
    assert.equal(result.status, 400);
    assert.equal(result.code, 'INVALID_QUERY', JSON.stringify(result));
  }
});

test('resource limits are environment-configurable, bounded, and enforced before execution', async () => {
  for (const [limits, rule] of [
    [{ maxQueryBytes: 20 }, group([answer()])],
    [{ maxGroupBytes: 20 }, group([answer()])],
    [{ maxConfigBytes: 20 }, group([answer()])],
    [{ maxRules: 1 }, { order: 0, rules: [{ actions: [answer()] }, { actions: [answer()] }] }],
    [{ maxActions: 1 }, group([answer(), answer()])],
    [{ maxRecords: 1 }, group([{ type: 'answer', records: [record(), record()] }])],
    [{ maxConditionNodes: 1 }, group([answer()], 0, { not: { field: 'query.type', op: 'eq', value: 1 } })],
  ]) {
    const result = await execute({ DNS_LIMITS: JSON.stringify(limits), DNS_RULE_A: rule });
    assert.equal(result.code, 'RESOURCE_LIMIT', JSON.stringify(result));
  }
  assert.equal((await execute({ DNS_LIMITS: { maxGroups: 1 }, DNS_RULE_A: group([answer()]), DNS_RULE_B: group([answer()]) })).code, 'RESOURCE_LIMIT');
  for (const limits of [null, { maxActions: 0 }, { maxQueryBytes: 65536 }, { maxActions: '2' }, { unknown: 1 }]) {
    assert.equal((await execute({ DNS_LIMITS: limits })).code, 'INVALID_CONFIG');
  }
});

test('unknown condition fields, references and errors in unreachable branches are not silently skipped', async () => {
  const invalid = [
    { field: 'query.name', op: 'regex', value: '[' },
    { field: 'query.name', op: 'exact', value: 'a..example' },
    { field: 'query.type', op: 'eq', value: 'NOT_A_TYPE' },
    { field: 'client.asn', op: 'eq', value: 123 },
    { ref: 'missing-extension' },
    { list: 'missing-list' },
    { all: [] }, { any: [] }, { not: null },
    { all: [{ field: 'query.type', op: 'eq', value: 'TXT' }, { ref: 'missing' }] },
    { field: 'query.type', op: 'eq', value: 1, extra: 'secret' },
  ];
  for (const when of invalid) {
    const result = await execute({ DNS_RULE_BAD: group([answer()], 0, when) });
    assert.equal(result.code, 'INVALID_CONFIG', JSON.stringify(when));
    assert.deepEqual(result.location, { group: 'DNS_RULE_BAD', rule: 0 });
  }
  const result = await execute({ DNS_RULE_BAD: group([{ type: 'upstream', ref: 'missing' }], 0, { field: 'query.type', op: 'eq', value: 'TXT' }) });
  assert.equal(result.code, 'INVALID_CONFIG');
});

test('numeric group order overrides name order and each successful answer replaces previous records', async () => {
  const result = await execute({ DNS_RULE_A: { order: 9, rules: [
    { actions: [answer('192.0.2.2')] },
    { actions: [{ type: 'setTtl', ttl: 22 }] },
  ] }, DNS_RULE_Z: group([answer('192.0.2.1')], -9) });
  assert.deepEqual(decode(result.response).records, [{ name: 'example.com', type: 1, ttl: 22, section: 0, data: [192, 0, 2, 2] }]);
});

test('custom AAAA and CNAME answers decode independently, including immediate return', async () => {
  const result = await execute({ DNS_RULE_A: group([{ type: 'answer', records: [
    { name: 'example.com', type: 'CNAME', ttl: 0, rdata: { Cname: { cname: 'target.example' } } },
    { name: 'target.example', type: 'AAAA', ttl: 4294967295, rdata: { Aaaa: { addr: '2001:db8::1' } } },
  ] }, { type: 'return' }]) }, query('example.com', 28));
  assert.equal(result.status, 200, JSON.stringify(result));
  const packet = decode(result.response);
  assert.equal(packet.questions[0].type, 28);
  assert.equal(packet.records[0].type, 5);
  assert.equal(packet.records[0].ttl, 0);
  assert.deepEqual(packet.records[0].data, [6, ...Buffer.from('target'), 7, ...Buffer.from('example'), 0]);
  assert.equal(packet.records[1].ttl, 4294967295);
  assert.deepEqual(packet.records[1].data, [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
});

test('unknown native RDATA fields and invalid raw bytes are rejected rather than erased', async () => {
  for (const rr of [
    { ...record(), rdata: { A: { addr: '192.0.2.1', secret: 'should-not-be-ignored' } } },
    { ...record(), type: 'TYPE65280', rdata: { Raw: [256] } },
    { ...record(), type: 'RRSIG', rdata: { Raw: [] } },
  ]) {
    const result = await execute({ DNS_RULE_BAD: group([{ type: 'answer', records: [rr] }]) });
    assert.equal(result.code, 'INVALID_CONFIG', JSON.stringify(result));
  }
});

test('malformed native raw RDATA is rejected even in an unmatched rule', async () => {
  const result = await execute({ DNS_RULE_BAD: group([{ type: 'answer', records: [{ ...record(), rdata: { Raw: [1] } }] }], 0, { field: 'query.type', op: 'eq', value: 'TXT' }) });
  assert.equal(result.code, 'INVALID_CONFIG');
});

test('response size limits apply to early return and stop as well as normal completion', async () => {
  for (const terminal of [[], [{ type: 'stop' }], [{ type: 'return' }]]) {
    const result = await execute({ DNS_LIMITS: { maxResponseBytes: 30 }, DNS_RULE_A: group([answer(), ...terminal]) });
    assert.equal(result.code, 'RESOURCE_LIMIT');
  }
});

test('unsupported query names and EDNS versions report input errors, not raw parser or matcher errors', async () => {
  const badName = query(); badName[13] = 0x21;
  const edns = query(); edns[11] = 1;
  const versionOne = Uint8Array.from([...edns, 0, 0, 41, 4, 208, 0, 1, 0, 0, 0, 0]);
  for (const wire of [badName, versionOne]) {
    const result = await execute({ DNS_RULE_A: group([answer()], 0, { field: 'query.name', op: 'exact', value: 'example.com' }) }, wire);
    assert.equal(result.code, 'INVALID_QUERY', JSON.stringify(result));
  }
});

test('public original snapshot cannot be mutated through returned references', async () => {
  await mf.setOptions(options({ DNS_RULE_A: group([{ type: 'rewriteQuery', name: 'changed.example' }]) }));
  const response = await mf.dispatchFetch('https://rules.test/', { method: 'POST', body: query(), headers: { 'x-test-mutate-result': '1' } });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.originalQuery.questions[0].name, 'example.com');
  assert.equal(result.query.questions[0].name, 'mutable.example');
});


test('required action failure emits a correlated termination event before throwing', async () => {
  const result = await execute({ DNS_RULE_FAIL: group([{ type: 'setTtl', ttl: 30 }]) });
  assert.equal(result.code, 'NO_RESPONSE');
  assert.equal(result.events.length, 1);
  const event = result.events[0];
  assert.equal(event.event, 'action_failed');
  assert.equal(event.requestId, 'test-request');
  assert.equal(event.code, 'NO_RESPONSE');
  assert.equal(event.actionType, 'setTtl');
  assert.equal(event.disposition, 'terminated');
  assert.deepEqual(event.location, { group: 'DNS_RULE_FAIL', rule: 0, action: 0 });
  assert.equal(typeof event.message, 'string');
});

test('an optional answer that mutates then exceeds the state budget rolls back only itself', async () => {
  const result = await execute({
    DNS_LIMITS: { maxResponseBytes: 70 },
    DNS_RULE_TRANSACTION: group([
      answer('192.0.2.1', 10),
      { type: 'answer', onError: 'continue', records: [record('192.0.2.2'), record('192.0.2.3')] },
      { type: 'setTtl', ttl: 99 },
      { type: 'return' },
    ]),
  });
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal(result.termination, 'returned');
  const packet = decode(result.response);
  assert.equal(packet.records.length, 1);
  assert.deepEqual(packet.records[0].data, [192, 0, 2, 1]);
  assert.equal(packet.records[0].ttl, 99);
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].code, 'RESOURCE_LIMIT');
  assert.equal(result.events[0].disposition, 'rolled_back_continue');
  assert.equal(result.events[0].rolledBack, true);
  assert.deepEqual(result.events[0].location, { group: 'DNS_RULE_TRANSACTION', rule: 0, action: 1 });
});

test('a throwing observer cannot hide an optional rollback or the original required failure', async () => {
  for (const onError of ['continue', 'fail']) {
    const result = await execute({ DNS_RULE_LOG: group([
      { type: 'setTtl', ttl: 20, onError }, answer(), { type: 'return' },
    ]) }, query(), { 'x-test-observer': 'throw' });
    assert.equal(result.status, onError === 'continue' ? 200 : 400, JSON.stringify(result));
    if (onError === 'fail') assert.equal(result.code, 'NO_RESPONSE');
    else assert.equal(decode(result.response).records.length, 1);
    const logs = result.logs.map(args => JSON.parse(args[0]));
    assert.ok(logs.some(event => event.event === 'observer_failed'));
    assert.ok(logs.some(event => event.event === 'action_failed' && event.code === 'NO_RESPONSE'));
    const output = JSON.stringify(result);
    for (const secret of ['observer-secret', 'password', 'private.test', 'path-key']) assert.ok(!output.includes(secret));
  }
});

test('optional missing-response actions continue without prematurely terminating the pipeline', async () => {
  const result = await execute({ DNS_RULE_OPTIONAL: group([
    { type: 'return', onError: 'continue' },
    { type: 'setTtl', ttl: 20, onError: 'continue' },
    answer('192.0.2.4'), { type: 'return' },
  ]) });
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal(result.termination, 'returned');
  assert.deepEqual(decode(result.response).records[0].data, [192, 0, 2, 4]);
  assert.equal(result.events.length, 2);
  assert.deepEqual(result.events.map(e => e.actionType), ['return', 'setTtl']);
  assert.ok(result.events.every(e => e.requestId === 'test-request' && e.disposition === 'rolled_back_continue'));
});

test('required oversized intermediate answers fail before a later small answer can hide the failure', async () => {
  for (const onError of [undefined, 'fail']) {
    const result = await execute({ DNS_LIMITS: { maxResponseBytes: 70 }, DNS_RULE_REQUIRED: group([
      answer(), { type: 'answer', ...(onError && { onError }), records: [record(), record('192.0.2.2')] },
      answer('192.0.2.9'),
    ]) });
    assert.equal(result.code, 'RESOURCE_LIMIT');
    assert.equal(result.response, undefined);
    assert.equal(result.events.length, 1);
    assert.equal(result.events[0].disposition, 'terminated');
    assert.equal(result.events[0].location.action, 1);
  }
});

test('a failed query rewrite restores current query and nested EDNS data without input aliases', async () => {
  const base = query(); base[11] = 1;
  const wire = Uint8Array.from([...base, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 6, 253, 233, 0, 2, 1, 2]);
  const storage = new Uint8Array(wire.length + 9); storage.set(wire, 4);
  const view = storage.subarray(4, 4 + wire.length), before = storage.slice();
  const result = await execute({ DNS_LIMITS: { maxQueryBytes: 60 }, DNS_RULE_QUERY: { order: 0, rules: [
    { actions: [
      { type: 'rewriteQuery', name: 'good.example' },
      { type: 'rewriteQuery', name: `${'a'.repeat(50)}.example`, onError: 'continue' },
    ] },
    { when: { field: 'query.name', op: 'exact', value: 'good.example' }, actions: [answer('192.0.2.7')] },
  ] } }, view, { 'x-test-mutate-edns': '1' });
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal(result.query.questions[0].name, 'good.example');
  assert.equal(result.originalQuery.questions[0].name, 'example.com');
  assert.deepEqual(result.originalQuery.additional[0].rdata.Opt.options[0].data, [1, 2]);
  assert.deepEqual(result.query.additional[0].rdata.Opt.options[0].data, [99, 2]);
  assert.deepEqual(storage, before);
  assert.deepEqual(decode(result.response).records[0].data, [192, 0, 2, 7]);
  assert.equal(result.events[0].code, 'RESOURCE_LIMIT');
});

test('default diagnostics and unexpected async observers never silence the original action failure', async () => {
  for (const mode of ['default', 'reject', 'mutate']) {
    const result = await execute({ DNS_RULE_REPORT: group([
      { type: 'return', onError: 'continue' }, answer(),
    ]) }, query(), { 'x-test-observer': mode });
    assert.equal(result.status, 200, JSON.stringify(result));
    assert.equal(result.logs.filter(args => JSON.parse(args[0]).event === 'action_failed').length, 1);
    const original = result.logs.map(args => JSON.parse(args[0])).find(e => e.event === 'action_failed');
    assert.equal(original.location.group, 'DNS_RULE_REPORT');
    assert.equal(original.code, 'NO_RESPONSE');
    assert.equal(original.disposition, 'rolled_back_continue');
    if (mode !== 'default') assert.ok(result.logs.some(args => JSON.parse(args[0]).event === 'observer_failed'));
    assert.ok(!JSON.stringify(result).includes('observer-secret'));
  }
  const success = await execute({ DNS_RULE_OK: group([answer()]) }, query(), { 'x-test-observer': 'throw' });
  assert.equal(success.status, 200);
  assert.deepEqual(success.events, []);
  assert.deepEqual(success.logs, []);
});

test('observer side effects cannot mutate the private original wire or change request correlation', async () => {
  const result = await execute({ DNS_RULE_INPUT: group([
    { type: 'return', onError: 'continue' }, answer(),
  ]) }, query(), { 'x-test-observer': 'input' });
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal(decode(result.response).id, 0x4242);
  assert.deepEqual(decode(result.response).questions, [{ name: 'example.com', type: 1, class: 1 }]);
});

test('configuration failures cannot be downgraded by optionality and diagnostic metadata is validated', async () => {
  for (const onError of [true, null, '', 'ignore']) {
    const result = await execute({ DNS_RULE_CONFIG: group([{ ...answer(), onError }]) });
    assert.equal(result.code, 'INVALID_CONFIG');
    assert.equal(result.events[0].event, 'execution_failed');
    assert.equal(result.events[0].disposition, 'terminated');
  }
  const secret = 'https://user:password@private.test/path-key?token=do-not-log';
  const result = await execute({ DNS_RULE_CONFIG: group([
    { ...answer(), onError: 'continue', records: [{ ...record(), rdata: { A: { addr: secret } } }] },
    answer(),
  ]) });
  assert.equal(result.code, 'INVALID_CONFIG');
  assert.equal(result.events.length, 1);
  assert.equal(result.response, undefined);
  for (const marker of ['password', 'private.test', 'path-key', 'do-not-log']) assert.ok(!JSON.stringify(result).includes(marker));
  const badId = await execute({}, query(), { 'x-test-request-id': secret });
  assert.equal(badId.code, 'INVALID_OPTIONS');
  assert.equal(badId.logs.length, 1);
  assert.ok(!JSON.stringify(badId).includes('private.test'));
});
