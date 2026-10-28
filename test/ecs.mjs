import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildQuery, parseMessage, encodeMessage, setEdns, getEdns, setEcs, getEcs, TYPES } from '../lib/dns-wasm/index.js';
import { loadEcs, outgoingEcs, validateIncomingEcs, checkEcsResponse, stripResponseEcs } from '../src/doh/ecs.js';
import { loadLimits } from '../src/rules/limits.js';
import { createConfigBudget } from '../src/rules/config-budget.js';

const limits = loadLimits(undefined);
function policy(raw) {
  return loadEcs(raw, {}, limits, createConfigBudget(limits), name => {
    if (name !== 'resolver') throw new Error('unreachable');
    return { transport: 'https', url: 'https://resolver.example/dns-query' };
  });
}
const query = () => parseMessage(buildQuery('ecs.example', TYPES.A));

test('ECS absent and false are disabled and explicit policies validate all upstream refs', () => {
  assert.equal(policy(undefined), null);
  assert.equal(policy(false), null);
  assert.equal(policy('false'), null);
  assert.throws(() => policy({ mode: 'client', upstreams: ['missing'] }));
  assert.throws(() => loadEcs({ mode: 'client', upstreams: ['resolver'] }, {}, limits, createConfigBudget(limits), () => undefined));
  assert.throws(() => policy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 25 }));
});

test('client prefixes mask private IPv4 and IPv6 without mutating the query', () => {
  const original = query();
  const before = encodeMessage(original);
  const withOpt = setEdns(query(), { udp_payload_size: 4096, flags: 0x8000, options: [{ code: 65001, data: [7] }] });
  const preserved = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'] }), withOpt, null, '198.51.100.129', limits);
  assert.deepEqual(getEdns(preserved), { udp_payload_size: 4096, extended_rcode: 0, version: 0, flags: 0x8000, options: [{ code: 65001, data: [7] }, { code: 8, data: [0, 1, 24, 0, 198, 51, 100] }] });
  const v4 = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'] }), original, null, '198.51.100.129', limits);
  assert.deepEqual(getEcs(v4), { address: '198.51.100.0', source_prefix: 24, scope_prefix: 0 });
  const v6 = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'] }), original, null, '2001:db8:abcd:1234::9', limits);
  assert.equal(getEcs(v6).source_prefix, 56);
  assert.deepEqual(encodeMessage(original), before);
});

test('fixed subnet normalizes host bits and query ECS /0 is not replaced', () => {
  const fixed = policy({ mode: 'fixed', upstreams: ['resolver'], subnet: '203.0.113.129/24' });
  assert.deepEqual(fixed.ecs, { address: '203.0.113.0', source_prefix: 24 });
  const inbound = setEcs(setEdns(query(), { udp_payload_size: 1232 }), { address: '0.0.0.0', source_prefix: 0 });
  assert.equal(validateIncomingEcs(inbound).source_prefix, 0);
  assert.equal(getEcs(outgoingEcs(fixed, inbound, validateIncomingEcs(inbound), '198.51.100.1', limits)).source_prefix, 0);
});

test('client-configured prefix also caps more-specific incoming ECS, and /0 is explicit', () => {
  const incoming = setEcs(setEdns(query(), { udp_payload_size: 1232 }), { address: '198.51.100.129', source_prefix: 24 });
  const identity = validateIncomingEcs(incoming);
  const capped = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 16 }), incoming, identity, undefined, limits);
  assert.deepEqual(getEcs(capped), { address: '198.51.0.0', source_prefix: 16, scope_prefix: 0 });
  const noIdentity = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 0 }), incoming, identity, undefined, limits);
  assert.deepEqual(getEcs(noIdentity), { address: '0.0.0.0', source_prefix: 0, scope_prefix: 0 });
});

test('response ECS restores original client identity with real upstream scope', () => {
  const incoming = setEcs(setEdns(query(), { udp_payload_size: 1232 }), { address: '198.51.100.129', source_prefix: 32 });
  const identity = validateIncomingEcs(incoming);
  const sent = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'] }), incoming, identity, undefined, limits);
  const upstream = setEcs(setEdns(query(), { udp_payload_size: 1232 }), { address: '198.51.100.0', source_prefix: 24, scope_prefix: 16 });
  checkEcsResponse(upstream, sent);
  assert.deepEqual(getEcs(stripResponseEcs(upstream, identity)), { address: '198.51.100.129', source_prefix: 32, scope_prefix: 16 });
});

test('non-byte ECS prefixes reject nonzero trailing padding bits', () => {
  const padding = [0, 1, 17, 0, 198, 51, 129];
  const malformedQuery = setEdns(query(), { udp_payload_size: 1232, options: [{ code: 8, data: padding }] });
  assert.throws(() => validateIncomingEcs(malformedQuery), { code: 'INVALID_QUERY' });
  const expected = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'], ipv4Prefix: 17 }), query(), null, '198.51.200.129', limits);
  const malformedResponse = setEdns(query(), { udp_payload_size: 1232, options: [{ code: 8, data: padding }] });
  assert.throws(() => checkEcsResponse(malformedResponse, expected), { code: 'UPSTREAM_INVALID' });
});

test('response ECS identity mismatch is a hard failure, not a successful cache bypass', () => {
  const request = outgoingEcs(policy({ mode: 'client', upstreams: ['resolver'] }), query(), null, '198.51.100.129', limits);
  const wrong = setEcs(setEdns(query(), { udp_payload_size: 1232 }), { address: '192.0.2.0', source_prefix: 24, scope_prefix: 0 });
  assert.throws(() => checkEcsResponse(wrong, request), { code: 'UPSTREAM_INVALID' });
});
