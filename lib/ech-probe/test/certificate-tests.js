import { prepareTrustAnchors, validateCertificateChain, verifyCertificateVerify } from '../internal/certificate.js';
const check = (condition, message) => { if (!condition) throw new Error(message); };
const rejects = async (fn, code) => {
  try { await fn(); throw new Error(`Expected rejection (${code})`); }
  catch (error) { if (error.message.startsWith('Expected rejection')) throw error; if (code && error.code !== code) throw new Error(`Expected ${code}, got ${error.code ?? error.name}: ${error.message}`); }
};
const decode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
function rawToDer(raw, width = raw.length / 2) {
  const lengthBytes = n => n < 128 ? [n] : [0x81, n];
  const integer = bytes => { let start = 0; while (start < bytes.length - 1 && bytes[start] === 0) start++; const body = bytes.subarray(start), pad = body[0] & 0x80 ? new Uint8Array([0]) : new Uint8Array(), value = new Uint8Array(pad.length + body.length); value.set(pad); value.set(body, pad.length); return new Uint8Array([2, ...lengthBytes(value.length), ...value]); };
  const r = integer(raw.subarray(0, width)), s = integer(raw.subarray(width, width * 2)), body = new Uint8Array([...r, ...s]); return new Uint8Array([0x30, ...lengthBytes(body.length), ...body]);
}
export async function runCertificateTests(fixture) {
  let passed = 0;
  const test = async (name, fn) => { try { await fn(); passed++; } catch (error) { throw new Error(`${name}: ${error.message}`, { cause: error }); } };
  const leaf = decode(fixture.leafDerBase64), chain = fixture.chainDerBase64.map(decode);
  await test('valid custom trust chain', async () => {
    const anchors = prepareTrustAnchors([fixture.rootPem]); check(anchors.length === 1, 'expected one root');
    await validateCertificateChain(chain, 'example.test', anchors);
    await validateCertificateChain(chain, 'service.example', anchors);
    await validateCertificateChain(chain, 'a.example.test', anchors);
  });
  await test('trust anchor preparation copies input and exposes static defaults', async () => {
    const source = decode(fixture.rootPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), anchors = prepareTrustAnchors([source]);
    check(anchors.length === 1 && anchors[0] !== source, 'DER anchor was not copied'); source.fill(0);
    await validateCertificateChain(chain, 'example.com', anchors);
    const defaults = prepareTrustAnchors(); check(defaults.length > 50 && defaults.every(v => v instanceof Uint8Array && v.length), 'default static roots missing');
  });
  await test('empty and malformed anchors throw synchronously', async () => {
    for (const value of [[], ['not PEM'], [new Uint8Array()], ['-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----']]) {
      try { prepareTrustAnchors(value); throw new Error('Expected invalid trust anchors'); }
      catch (error) { check(error instanceof TypeError || error instanceof RangeError, `unexpected error ${error}`); }
    }
  });
  await test('SAN matching and wildcard depth', async () => {
    const anchors = prepareTrustAnchors([fixture.rootPem]); await validateCertificateChain(chain, 'a.example.test', anchors);
    for (const host of ['bad.example', 'deep.a.example.test', 'example.test.evil', '192.0.2.1', 'not-used.example']) await rejects(() => validateCertificateChain(chain, host, anchors), 'HOSTNAME');
  });
  await test('missing intermediate and untrusted root fail closed', async () => {
    await rejects(() => validateCertificateChain(chain, 'example.test', prepareTrustAnchors()), 'CERTIFICATE');
    await rejects(() => validateCertificateChain([leaf], 'example.test', prepareTrustAnchors([fixture.rootPem])), 'CERTIFICATE');
  });
  await test('rejects invalid CA EKU, pathLen, nameConstraints, critical extensions, weak RSA and SHA-1', async () => {
    const anchors = prepareTrustAnchors([fixture.rootPem]);
    const failures = fixture.negativeChains;
    for (const [name, value] of Object.entries(failures)) {
      const badChain = value.chainDerBase64.map(decode);
      await rejects(() => validateCertificateChain(badChain, 'example.test', anchors), 'CERTIFICATE');
    }
  });
  await test('leading-dot nameConstraints exclude the apex, allow matching subdomains, and reject leaf NC', async () => {
    const cases = fixture.nameConstraintCases, anchors = prepareTrustAnchors([cases.rootPem]);
    await validateCertificateChain(cases.subdomainChainDerBase64.map(decode), 'a.example.test', anchors);
    await rejects(() => validateCertificateChain(cases.apexChainDerBase64.map(decode), 'example.test', anchors), 'CERTIFICATE');
    await rejects(() => validateCertificateChain(cases.leafConstraintChainDerBase64.map(decode), 'example.test', anchors), 'CERTIFICATE');
    await rejects(() => validateCertificateChain(cases.invalidDnsConstraintChainDerBase64.map(decode), 'a.example.test', anchors), 'CERTIFICATE');
  });
  await test('rejects oversized trust-anchor arrays and oversized PEM before parsing', async () => {
    const rootDer = decode(fixture.chainDerBase64[1]);
    try { prepareTrustAnchors(Array.from({ length: 513 }, () => rootDer)); throw new Error('Expected anchor count limit'); }
    catch (error) { check(error instanceof RangeError, 'anchor count limit did not throw RangeError'); }
    try { prepareTrustAnchors(['x'.repeat(2 * 1024 * 1024 + 1)]); throw new Error('Expected PEM input limit'); }
    catch (error) { check(error instanceof RangeError, 'PEM budget did not throw RangeError'); }
  });
  await test('malformed and trailing DER are rejected', async () => {
    const roots = prepareTrustAnchors([fixture.rootPem]);
    await rejects(() => validateCertificateChain([new Uint8Array([0x30, 0]), chain[1]], 'example.test', roots));
    const trailing = new Uint8Array(leaf.length + 1); trailing.set(leaf);
    await rejects(() => validateCertificateChain([trailing, chain[1]], 'example.test', roots));
  });
  await test('CertificateVerify checks real ECDSA signature, tampering and scheme mismatch', async () => {
    const pkcs8 = decode(fixture.leafPrivateKeyPkcs8Base64), data = new TextEncoder().encode('TLS 1.3, server CertificateVerify test');
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const der = rawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data)));
    check(await verifyCertificateVerify(leaf, 0x0403, der, data), 'valid signature rejected');
    const changed = data.slice(); changed[0] ^= 1;
    await rejects(() => verifyCertificateVerify(leaf, 0x0403, der, changed), 'CERTIFICATE_VERIFY');
    await rejects(() => verifyCertificateVerify(leaf, 0x0503, der, data), 'CERTIFICATE_VERIFY');
    await rejects(() => verifyCertificateVerify(leaf, 0x9999, der, data), 'CERTIFICATE_VERIFY');
  });
  await test('CertificateVerify tests P-384, P-521, RSA-PSS SHA-2 and Ed25519', async () => {
    const data = new TextEncoder().encode('TLS 1.3 CertificateVerify variant test');
    for (const item of fixture.signatureVariants) {
      const leafVariant = decode(item.leafDerBase64), pkcs8 = decode(item.privateKeyPkcs8Base64);
      if (item.name === 'p384' || item.name === 'p521') {
        const curve = item.name === 'p384' ? 'P-384' : 'P-521', hash = item.name === 'p384' ? 'SHA-384' : 'SHA-512', width = item.name === 'p384' ? 48 : 66;
        const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: curve }, false, ['sign']);
        const signature = rawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash }, privateKey, data)), width);
        check(await verifyCertificateVerify(leafVariant, item.scheme, signature, data), `${item.name} CV rejected`);
        const altered = data.slice(); altered[0] ^= 1;
        await rejects(() => verifyCertificateVerify(leafVariant, item.scheme, signature, altered), 'CERTIFICATE_VERIFY');
      } else if (item.name === 'rsa') {
        for (const [scheme, hash, saltLength] of [[0x0804, 'SHA-256', 32], [0x0805, 'SHA-384', 48], [0x0806, 'SHA-512', 64]]) {
          const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-PSS', hash }, false, ['sign']);
          const signature = new Uint8Array(await crypto.subtle.sign({ name: 'RSA-PSS', saltLength }, privateKey, data));
          check(await verifyCertificateVerify(leafVariant, scheme, signature, data), `RSA-PSS ${hash} CV rejected`);
          const altered = data.slice(); altered[0] ^= 1;
          await rejects(() => verifyCertificateVerify(leafVariant, scheme, signature, altered), 'CERTIFICATE_VERIFY');
        }
      } else if (item.name === 'ed25519') {
        const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
        const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, data));
        check(await verifyCertificateVerify(leafVariant, item.scheme, signature, data), 'Ed25519 CV rejected');
        const altered = data.slice(); altered[0] ^= 1;
        await rejects(() => verifyCertificateVerify(leafVariant, item.scheme, signature, altered), 'CERTIFICATE_VERIFY');
      }
    }
  });
  return { passed, failed: 0, total: passed };
}
