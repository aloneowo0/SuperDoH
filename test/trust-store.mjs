import assert from 'node:assert/strict';
import fs from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { test } from 'node:test';
import * as store from '../lib/ech-probe/internal/trust-store.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare, Log, LogLevel } from 'miniflare';
import { Certificate, fromBER } from '../lib/ech-probe/vendor/pki-core.js';
import { spawnSync } from 'node:child_process';

test('generated default trust index preserves every pinned CA as exact DER', () => {
  const pem = fs.readFileSync(new URL('../lib/ech-probe/vendor/cacert.pem', import.meta.url), 'utf8');
  const roots = [...pem.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)];
  assert.ok(Array.isArray(store.DEFAULT_CA_INDEX), 'missing generated subject/DER index');
  assert.equal(store.DEFAULT_CA_INDEX.length, roots.length);
  for (let i = 0; i < roots.length; i++) {
    const entry = store.DEFAULT_CA_INDEX[i];
    assert.deepEqual(Buffer.from(entry.certificate, 'base64'), new X509Certificate(roots[i][0]).raw);
    const parsed = new Certificate({ schema: fromBER(Buffer.from(entry.certificate, 'base64')).result });
    assert.deepEqual(Buffer.from(entry.subject, 'base64'), Buffer.from(parsed.subject.valueBeforeDecode));
    assert.ok(Object.isFrozen(entry));
  }
  assert.ok(Object.isFrozen(store.DEFAULT_CA_INDEX));
});

// Build-time substitution exercises real TLS with fixture CAs, never production roots.

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const lib = path.join(root, 'lib/ech-probe');
const fixture = {
  certificates: JSON.parse(fs.readFileSync(path.join(lib, 'test/fixtures/certificates.json'), 'utf8')),
  meta: JSON.parse(fs.readFileSync(path.join(lib, 'test/fixtures/meta.json'), 'utf8')),
};
const fromPem = pem => new Certificate({ schema: fromBER(new X509Certificate(pem).raw).result });
const entry = cert => ({ subject: Buffer.from(cert.subject.toSchema().toBER(false)).toString('base64'), certificate: Buffer.from(cert.toSchema(true).toBER(false)).toString('base64') });
const valid = fromPem(fixture.certificates.rootPem);
// Same public key, but different string encoding, casing and spacing.
const alternateName = Buffer.from('  SUPERDOH   Test ROOT  ');
valid.subject.typesAndValues[0].value = fromBER(Buffer.concat([Buffer.from([0x13, alternateName.length]), alternateName])).result;
valid.subject.valueBeforeDecode = new ArrayBuffer(0);
const wrongKey = fromPem(fixture.certificates.nameConstraintCases.rootPem);
wrongKey.subject = fromPem(fixture.certificates.rootPem).subject;
// Assert the serialized fixture, not just the mutable PKI object, changed.
const encodedValid = new Certificate({ schema: fromBER(Buffer.from(entry(valid).certificate, 'base64')).result });
const encodedWrong = new Certificate({ schema: fromBER(Buffer.from(entry(wrongKey).certificate, 'base64')).result });
assert.notEqual(entry(valid).subject, entry(fromPem(fixture.certificates.rootPem)).subject);
assert.ok(encodedValid.subject.isEqual(encodedWrong.subject));
assert.equal(encodedValid.subject.typesAndValues[0].value.constructor.blockName(), 'PrintableString');
assert.notEqual(Buffer.from(encodedValid.subjectPublicKeyInfo.toSchema().toBER(false)).toString('base64'), Buffer.from(encodedWrong.subjectPublicKeyInfo.toSchema().toBER(false)).toString('base64'));

async function bundle(trusted) {
  const index = [entry(wrongKey), ...(trusted ? [entry(valid)] : []), ...store.DEFAULT_CA_INDEX];
  const snapshot = `export const DEFAULT_CA_INDEX = Object.freeze(${JSON.stringify(index)}.map(Object.freeze));`;
  const result = await build({
    entryPoints: [path.join(lib, 'test/lazy-trust-entry.js')], bundle: true, write: false, format: 'esm', platform: 'browser',
    plugins: [{ name: 'controlled-trust-and-parse-counter', setup(api) {
      api.onLoad({ filter: /trust-store[.]js$/ }, () => ({ contents: snapshot, loader: 'js' }));
      api.onLoad({ filter: /certificate[.]js$/ }, args => {
        const original = fs.readFileSync(args.path, 'utf8');
        assert.ok(original.includes('function parseDer(der) {'), 'instrumentation seam changed');
        return { contents: original.replace('function parseDer(der) {', 'function parseDer(der) { globalThis.__lazyTrustParses++;'), loader: 'js', resolveDir: path.dirname(args.path) };
      });
    } }],
  });
  return ['globalThis.__lazyTrustParses = 0;', result.outputFiles[0].text, '//# sourceURL=lazy-trust-controlled.js'].join(String.fromCharCode(10));
}

test('pinned trust index is reproducible without fetching or changing the snapshot', () => {
  const result = spawnSync(process.execPath, [path.join(lib, 'scripts/build-trust-store.mjs'), '--check'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

for (const runtime of ['Node', 'workerd']) {
  test(`${runtime}: lazy roots preserve authenticated TLS, backtracking and fail-closed checks`, async () => {
    for (const trusted of [true, false]) {
      const script = await bundle(trusted);
      if (runtime === 'Node') {
        const module = await import('data:text/javascript;base64,' + Buffer.from(script).toString('base64'));
        const rows = await module.runLazyTrustTests(fixture, trusted);
        assert.ok(rows.length >= (trusted ? 9 : 1));
      } else {
        const mf = new Miniflare({ modules: true, script, compatibilityDate: '2026-07-30', log: new Log(LogLevel.NONE) });
        try {
          const response = await mf.dispatchFetch('https://lazy-trust.test/', { method: 'POST', body: JSON.stringify({ fixture, trusted }) });
          const rows = await response.json();
          assert.equal(response.status, 200, JSON.stringify(rows));
          assert.ok(rows.length >= (trusted ? 9 : 1));
        } finally { await mf.dispose(); }
      }
    }
  });
}
