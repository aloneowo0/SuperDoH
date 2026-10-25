import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertLoggingDisabled, assertCleanBindings } from '../scripts/lib/acceptance-safety.mjs';

test('secret-path tests require every URL logging channel explicitly disabled', () => {
  const safe = { enabled: false, logs: { enabled: false, invocation_logs: false }, traces: { enabled: false } };
  assert.doesNotThrow(() => assertLoggingDisabled(safe));
  for (const value of [undefined, {}, { ...safe, enabled: true }, { ...safe, logs: { enabled: false, invocation_logs: true } }, { ...safe, logs: { enabled: true, invocation_logs: false } }, { ...safe, traces: { enabled: true } }, { ...safe, traces: null }, { ...safe, logs: {} }]) {
    assert.throws(() => assertLoggingDisabled(value), /UNSAFE_LOGGING/);
  }
});

test('acceptance starts only when active and latest bindings are both empty', () => {
  assert.doesNotThrow(() => assertCleanBindings([], []));
  for (const [active, latest] of [[[], undefined], [undefined, []], [[], [{ name: 'stale' }]], [[{ name: 'active' }], []]]) {
    assert.throws(() => assertCleanBindings(active, latest), /DIRTY_BINDINGS/);
  }
});
