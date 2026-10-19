import { AlgorithmIdentifier, Certificate, CryptoEngine, fromBER, RSASSAPSSParams } from '../vendor/pki-core.js';
import { EchProbeError, bytes } from './bytes.js';
import { DEFAULT_CA_PEM } from './trust-store.js';

const O = { bc: '2.5.29.19', ku: '2.5.29.15', eku: '2.5.29.37', san: '2.5.29.17', nc: '2.5.29.30', rsa: '1.2.840.113549.1.1.1', ec: '1.2.840.10045.2.1', ed: '1.3.101.112' };
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const KNOWN_CRITICAL = new Set([O.bc, O.ku, O.eku, O.san, O.nc]);
const engine = () => new CryptoEngine({ name: 'SuperDoH WebCrypto', crypto: globalThis.crypto });
const failCert = (message, cause) => { throw new EchProbeError('CERTIFICATE', message, cause ? { cause } : undefined); };
const failHost = message => { throw new EchProbeError('HOSTNAME', message); };
const MAX_CERT_BYTES = 65536;
const MAX_ANCHORS = 512;
const MAX_TRUST_BYTES = 2 * 1024 * 1024;
const MAX_CHAIN_CERTS = 16;
const preparedAnchorCache = new WeakMap();
let defaultAnchorRecords;
function parseDer(der) {
  if (!(der instanceof Uint8Array)) throw new TypeError('Certificate DER must be a Uint8Array');
  if (!der.length) throw new RangeError('Certificate DER is empty');
  if (der.length > MAX_CERT_BYTES) throw new RangeError('Certificate DER exceeds 64 KiB');
  const copy = der.slice(), parsed = fromBER(copy);
  if (parsed.offset !== copy.length || parsed.offset < 0 || parsed.result?.idBlock?.tagClass !== 1 || parsed.result.idBlock.tagNumber !== 16) throw new RangeError('Invalid certificate DER');
  try {
    const cert = new Certificate({ schema: parsed.result });
    const canonical = new Uint8Array(cert.toSchema().toBER(false));
    if (canonical.length !== copy.length || !canonical.every((byte, i) => byte === copy[i])) throw new RangeError('Certificate is not canonical DER');
    if (!cert.signature || !cert.signatureAlgorithm || cert.signature.algorithmId !== cert.signatureAlgorithm.algorithmId) throw new RangeError('Certificate signature algorithm identifiers differ');
    const a = new Uint8Array(cert.signature.toSchema().toBER(false)), b = new Uint8Array(cert.signatureAlgorithm.toSchema().toBER(false));
    if (a.length !== b.length || !a.every((byte, i) => byte === b[i])) throw new RangeError('Certificate signature algorithm parameters differ');
    return { der: copy, cert };
  } catch (cause) { if (cause instanceof RangeError) throw cause; throw new TypeError('Invalid X.509 certificate DER', { cause }); }
}
function decodePem(pem) {
  if (typeof pem !== 'string') throw new TypeError('PEM certificate must be a string');
  if (pem.length > MAX_TRUST_BYTES) throw new RangeError('Trust PEM exceeds 2 MiB');
  const matches = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)];
  const remainder = pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').replace(/^##[^\r\n]*$/gm, '').trim();
  if (!matches.length || remainder) throw new TypeError('Invalid certificate PEM');
  return matches.map(match => {
    const base64 = match[1].replace(/\s/g, '');
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64) || !base64) throw new TypeError('Invalid certificate PEM base64');
    return parseDer(Uint8Array.from(atob(base64), c => c.charCodeAt(0))).der;
  });
}
export function prepareTrustAnchors(caCertificates) {
  if (caCertificates === undefined && defaultAnchorRecords) {
    const cachedCopies = defaultAnchorRecords.map(record => record.der.slice());
    preparedAnchorCache.set(cachedCopies, defaultAnchorRecords);
    return cachedCopies;
  }
  const input = caCertificates === undefined ? [DEFAULT_CA_PEM] : caCertificates;
  if (!Array.isArray(input)) throw new TypeError('caCertificates must be an array');
  if (!input.length) throw new RangeError('caCertificates must not be empty');
  if (input.length > MAX_ANCHORS) throw new RangeError('Too many trust anchor inputs');
  let inputBytes = 0, totalDerBytes = 0;
  const result = [];
  for (const item of input) {
    if (typeof item === 'string') {
      inputBytes += item.length;
      if (inputBytes > MAX_TRUST_BYTES) throw new RangeError('Trust PEM input exceeds 2 MiB');
      const certs = decodePem(item); result.push(...certs);
      totalDerBytes += certs.reduce((sum, der) => sum + der.length, 0);
    }
    else {
      const inputDer = item instanceof ArrayBuffer ? new Uint8Array(item) : ArrayBuffer.isView(item) ? new Uint8Array(item.buffer, item.byteOffset, item.byteLength) : Array.isArray(item) ? bytes(item) : null;
      if (!inputDer) throw new TypeError('Trust anchors must be PEM strings or DER byte views');
      const parsed = parseDer(inputDer).der; result.push(parsed); totalDerBytes += parsed.length;
    }
    if (result.length > MAX_ANCHORS || totalDerBytes > MAX_TRUST_BYTES) throw new RangeError('Trust anchors exceed certificate count or byte budget');
  }
  if (!result.length) throw new RangeError('No trust anchors were supplied');
  let records;
  if (caCertificates === undefined && defaultAnchorRecords) records = defaultAnchorRecords;
  else {
    records = result.map(parseDer);
    if (caCertificates === undefined) defaultAnchorRecords = records;
  }
  const copied = result.map(der => der.slice());
  preparedAnchorCache.set(copied, records);
  return copied;
}
function extMap(cert) {
  const map = new Map();
  if (cert.extensions !== undefined && !Array.isArray(cert.extensions)) failCert('Malformed certificate extension list');
  for (const ext of cert.extensions ?? []) {
    if (!ext || typeof ext.extnID !== 'string' || typeof ext.critical !== 'boolean') failCert('Malformed certificate extension');
    if (map.has(ext.extnID)) failCert(`Duplicate certificate extension ${ext.extnID}`);
    map.set(ext.extnID, ext);
    if (ext.critical && (!KNOWN_CRITICAL.has(ext.extnID) || !ext.parsedValue)) failCert(`Unsupported critical certificate extension ${ext.extnID}`);
  }
  return map;
}
function usage(exts) {
  const ext = exts.get(O.ku);
  if (!ext) return null;
  const block = ext.parsedValue?.valueBlock;
  if (!block || !(block.valueHex instanceof ArrayBuffer)) failCert('Malformed keyUsage extension');
  const bytes = new Uint8Array(block.valueHex);
  if (!bytes.length || block.unusedBits < 0 || block.unusedBits > 7) failCert('Malformed keyUsage bit string');
  const has = n => n < bytes.length * 8 && Boolean(bytes[n >> 3] & (0x80 >> (n & 7)));
  return { digitalSignature: has(0), keyCertSign: has(5) };
}
function constraints(exts) {
  const ext = exts.get(O.bc);
  if (!ext) return { ca: false, pathLen: null };
  const v = ext.parsedValue;
  if (!v || typeof v.cA !== 'boolean' || (v.pathLenConstraint !== undefined && (!Number.isInteger(v.pathLenConstraint) || v.pathLenConstraint < 0)) || (v.pathLenConstraint !== undefined && !v.cA)) failCert('Malformed basicConstraints extension');
  return { ca: v.cA, pathLen: v.pathLenConstraint ?? null };
}
function extendedUsage(exts) {
  const ext = exts.get(O.eku);
  if (!ext) return null;
  const purposes = ext.parsedValue?.keyPurposes;
  if (!Array.isArray(purposes) || !purposes.length || purposes.some(p => typeof p !== 'string')) failCert('Malformed extendedKeyUsage extension');
  return purposes;
}
const SHA2_OIDS = new Map([['2.16.840.1.101.3.4.2.1', 32], ['2.16.840.1.101.3.4.2.2', 48], ['2.16.840.1.101.3.4.2.3', 64]]);
function checkSignatureAlgorithm(cert, isTrustAnchor) {
  if (isTrustAnchor) return; // Trust anchors are local policy objects; their self-signature is not validated.
  const oid = cert.signatureAlgorithm.algorithmId;
  if (['1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4', '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13', '1.3.101.112'].includes(oid)) return;
  if (oid !== '1.2.840.113549.1.1.10') failCert('Weak or unsupported certificate signature algorithm');
  try {
    if (!cert.signatureAlgorithm.algorithmParams) failCert('RSA-PSS signature parameters are missing');
    const pss = new RSASSAPSSParams({ schema: cert.signatureAlgorithm.algorithmParams });
    const digestBytes = SHA2_OIDS.get(pss.hashAlgorithm.algorithmId);
    if (!digestBytes || pss.maskGenAlgorithm.algorithmId !== '1.2.840.113549.1.1.8' || !pss.maskGenAlgorithm.algorithmParams) failCert('RSA-PSS requires SHA-2 and MGF1');
    const mgfHash = new AlgorithmIdentifier({ schema: pss.maskGenAlgorithm.algorithmParams });
    if (mgfHash.algorithmId !== pss.hashAlgorithm.algorithmId || !Number.isInteger(pss.saltLength) || pss.saltLength < digestBytes || pss.trailerField !== 1) failCert('Weak or inconsistent RSA-PSS parameters');
  } catch (cause) { if (cause instanceof EchProbeError) throw cause; failCert('Malformed RSA-PSS certificate parameters', cause); }
}
function validity(cert, now, isTrustAnchor = false) {
  const start = cert.notBefore.value?.getTime(), end = cert.notAfter.value?.getTime(), timestamp = now.getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isFinite(timestamp) || timestamp < start || timestamp > end) failCert('Certificate is outside its validity period');
  checkSignatureAlgorithm(cert, isTrustAnchor);
  if (cert.subjectPublicKeyInfo.algorithm.algorithmId === O.rsa && getRsaBits(cert) < 2048) failCert('RSA public key is weaker than 2048 bits');
}
function sanDns(cert, exts) {
  const names = exts.get(O.san)?.parsedValue?.altNames;
  if (!Array.isArray(names)) failCert('Leaf certificate has no usable subjectAltName');
  const dns = names.filter(n => n.type === 2 && typeof n.value === 'string').map(n => n.value.toLowerCase());
  if (!dns.length) failCert('Leaf certificate has no DNS subjectAltName');
  return dns;
}
function normalizeHost(value) {
  if (typeof value !== 'string' || !value || value.length > 253 || /[\x00- \x7f/\\:@]/.test(value)) throw new TypeError('serverName must be a DNS hostname');
  const host = value.toLowerCase().replace(/\.$/, '');
  if (!host || host.split('.').some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) throw new TypeError('serverName must be a valid DNS hostname');
  return host;
}
function matchDns(pattern, host) {
  if (pattern === host) return true;
  if (!pattern.startsWith('*.')) return false;
  const suffix = pattern.slice(2), prefix = host.slice(0, -(suffix.length + 1));
  return host.endsWith(`.${suffix}`) && prefix.length > 0 && !prefix.includes('.');
}
function validDnsConstraint(value) {
  const domain = value.startsWith('.') ? value.slice(1) : value;
  return domain.length <= 253 && !domain.endsWith('.') && domain.split('.').every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}
function checkNameConstraints(path, host) {
  for (let issuerIndex = 1; issuerIndex < path.length; issuerIndex++) {
    const ext = extMap(path[issuerIndex].cert).get(O.nc);
    if (!ext) continue;
    const nc = ext.parsedValue;
    if (!nc || !Array.isArray(nc.permittedSubtrees ?? []) || !Array.isArray(nc.excludedSubtrees ?? [])) failCert('Malformed nameConstraints extension');
    const permitted = nc.permittedSubtrees ?? [], excluded = nc.excludedSubtrees ?? [];
    if (!permitted.length && !excluded.length) failCert('Empty nameConstraints extension');
    for (const subtree of [...permitted, ...excluded]) {
      const value = subtree?.base?.value;
      if (subtree?.base?.type !== 2 || typeof value !== 'string' || !validDnsConstraint(value) ||
          (subtree.minimum !== undefined && subtree.minimum !== 0) || subtree.maximum !== undefined) failCert('Unsupported nameConstraints subtree');
    }
    const p = permitted.map(s => s.base.value.toLowerCase()), e = excluded.map(s => s.base.value.toLowerCase());
    const within = (name, base) => base.startsWith('.') ? name.endsWith(base) : name === base || name.endsWith(`.${base}`);
    const wildcardWithin = (pattern, base) => { const suffix = pattern.slice(2), b = base.startsWith('.') ? base.slice(1) : base; return suffix === b || suffix.endsWith(`.${b}`); };
    const wildcardMayIntersect = (pattern, base) => {
      const suffix = pattern.slice(2), b = base.startsWith('.') ? base.slice(1) : base;
      if (base.startsWith('.')) return suffix === b || suffix.endsWith(`.${b}`);
      return suffix === b || suffix.endsWith(`.${b}`) || b.endsWith(`.${suffix}`);
    };
    const dnsNames = [];
    for (const subordinate of path.slice(0, issuerIndex)) {
      const sans = extMap(subordinate.cert).get(O.san);
      if (!sans) continue;
      const alternatives = sans.parsedValue?.altNames;
      if (!Array.isArray(alternatives)) failCert('Malformed subjectAltName under nameConstraints');
      for (const name of alternatives) {
        if (name.type !== 2 || typeof name.value !== 'string') failCert('Unsupported subjectAltName under nameConstraints');
        dnsNames.push(name.value.toLowerCase());
      }
    }
    dnsNames.push(host);
    for (const name of dnsNames) {
      const wildcard = name.startsWith('*.');
      if (e.some(base => wildcard ? wildcardMayIntersect(name, base) : within(name, base))) failCert('DNS name is excluded by nameConstraints');
      if (p.length && !p.some(base => wildcard ? wildcardWithin(name, base) : within(name, base))) failCert('DNS name is outside permitted nameConstraints');
    }
  }
}
function sameDer(a, b) { return a.length === b.length && a.every((byte, i) => byte === b[i]); }
export async function validateCertificateChain(certificates, serverName, trustAnchors) {
  if (!Array.isArray(certificates) || !certificates.length || certificates.length > MAX_CHAIN_CERTS || certificates.some(c => !(c instanceof Uint8Array))) throw new TypeError('certificates must be a non-empty bounded Uint8Array array');
  if (!Array.isArray(trustAnchors) || !trustAnchors.length || trustAnchors.length > MAX_ANCHORS || trustAnchors.some(c => !(c instanceof Uint8Array))) throw new TypeError('trustAnchors must be a bounded non-empty DER byte array');
  if (certificates.reduce((sum, c) => sum + c.length, 0) > MAX_TRUST_BYTES || trustAnchors.reduce((sum, c) => sum + c.length, 0) > MAX_TRUST_BYTES) throw new RangeError('Certificate chain or trust anchors exceed 2 MiB');
  const host = normalizeHost(serverName), decode = der => { try { return parseDer(der); } catch (cause) { failCert('Invalid certificate DER', cause); } };
  const supplied = certificates.map(decode), cachedAnchors = preparedAnchorCache.get(trustAnchors);
  const anchors = cachedAnchors && cachedAnchors.length === trustAnchors.length && cachedAnchors.every((record, i) => sameDer(record.der, trustAnchors[i])) ? cachedAnchors : trustAnchors.map(decode);
  const pool = [...supplied.slice(1), ...anchors], now = new Date(), cryptoEngine = engine();
  let attempts = 0;
  const buildPath = async path => {
    const current = path[path.length - 1], isAnchor = anchors.some(anchor => sameDer(anchor.der, current.der));
    validity(current.cert, now, isAnchor);
    const currentExts = extMap(current.cert);
    if (isAnchor) {
      if (!constraints(currentExts).ca || (usage(currentExts) && !usage(currentExts).keyCertSign)) return null;
      return path;
    }
    if (path.length >= 12) return null;
    for (const candidate of pool) {
      if (path.includes(candidate) || !current.cert.issuer.isEqual(candidate.cert.subject)) continue;
      if (++attempts > 64) failCert('Certificate path search limit exceeded');
      try {
        const issuerExts = extMap(candidate.cert), issuerBc = constraints(issuerExts), issuerKu = usage(issuerExts);
        if (!issuerBc.ca || (issuerKu && !issuerKu.keyCertSign)) continue;
        if (!await current.cert.verify(candidate.cert, cryptoEngine)) continue;
        const built = await buildPath([...path, candidate]);
        if (built) return built;
      } catch (error) { if (error instanceof EchProbeError && error.code !== 'CERTIFICATE') throw error; }
    }
    return null;
  };
  const path = await buildPath([supplied[0]]);
  if (!path) failCert('Unable to build certificate path to a configured local trust anchor');
  for (let i = 0; i < path.length; i++) {
    const item = path[i], exts = extMap(item.cert), anchor = anchors.some(a => sameDer(a.der, item.der));
    validity(item.cert, now, anchor);
    if (i > 0) {
      const bc = constraints(exts), ku = usage(exts), eku = extendedUsage(exts);
      if (!bc.ca) failCert('Issuer certificate is not a CA');
      if (ku && !ku.keyCertSign) failCert('Issuer certificate keyUsage lacks keyCertSign');
      if (eku && !eku.includes(SERVER_AUTH) && !eku.includes('2.5.29.37.0')) failCert('CA EKU does not permit serverAuth');
      if (bc.pathLen !== null && path.slice(1, i).filter(p => constraints(extMap(p.cert)).ca && !p.cert.subject.isEqual(p.cert.issuer)).length > bc.pathLen) failCert('Certificate pathLenConstraint exceeded');
    }
  }
  const leafExts = extMap(path[0].cert), leafBc = constraints(leafExts), ku = usage(leafExts), eku = extendedUsage(leafExts);
  if (leafExts.has(O.nc)) failCert('Leaf certificate must not assert nameConstraints');
  if (leafBc.ca) failCert('Leaf certificate is marked as a CA');
  if (ku && !ku.digitalSignature) failCert('Leaf keyUsage lacks digitalSignature');
  if (eku && !eku.includes(SERVER_AUTH) && !eku.includes('2.5.29.37.0')) failCert('Leaf EKU does not permit serverAuth');
  if (!sanDns(path[0].cert, leafExts).some(name => matchDns(name, host))) failHost('Leaf certificate DNS SAN does not match serverName');
  checkNameConstraints(path, host);
}

function ecdsaSignatureToRaw(signature, width) {
  const decoded = fromBER(signature), sequence = decoded.result;
  if (decoded.offset !== signature.length || decoded.offset < 0 || sequence?.idBlock?.tagClass !== 1 || sequence.idBlock.tagNumber !== 16 || !sequence.idBlock.isConstructed) failCert('Malformed ECDSA signature sequence');
  const canonical = new Uint8Array(sequence.toBER(false));
  if (canonical.length !== signature.length || !canonical.every((byte, i) => byte === signature[i])) failCert('ECDSA signature is not canonical DER');
  const integers = sequence.valueBlock.value;
  if (integers.length !== 2) failCert('ECDSA signature must contain two integers');
  const out = new Uint8Array(width * 2);
  for (let i = 0; i < 2; i++) {
    const item = integers[i];
    if (item.idBlock?.tagClass !== 1 || item.idBlock.tagNumber !== 2 || item.idBlock.isConstructed) failCert('ECDSA signature components must be INTEGERs');
    let part = item.valueBlock.valueHexView;
    if (!part.length || (part[0] & 0x80) || (part.length > 1 && part[0] === 0 && !(part[1] & 0x80)) || part.every(byte => byte === 0)) failCert('ECDSA signature INTEGER must be a canonical positive value');
    while (part.length > width && part[0] === 0) part = part.subarray(1);
    if (part.length > width) failCert('Oversized ECDSA signature integer');
    out.set(part, i * width + width - part.length);
  }
  return out;
}
function getRsaBits(cert) {
  const spki = new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)), root = fromBER(spki).result;
  const bits = root.valueBlock.value[1].valueBlock.valueHexView, parsed = fromBER(bits);
  if (parsed.offset !== bits.length || parsed.offset < 0 || parsed.result.valueBlock.value.length < 2) return 0;
  const modulus = parsed.result.valueBlock.value[0].valueBlock.valueHexView;
  let zeros = 0; while (zeros < 8 && !(modulus[0] & (0x80 >> zeros))) zeros++;
  return modulus.length * 8 - zeros;
}
export async function verifyCertificateVerify(leafDer, scheme, signature, signedData) {
  if (!(leafDer instanceof Uint8Array) || !(signature instanceof Uint8Array) || !(signedData instanceof Uint8Array)) throw new TypeError('CertificateVerify inputs must be Uint8Array');
  try {
    const cert = parseDer(leafDer).cert, spki = new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)), keyOid = cert.subjectPublicKeyInfo.algorithm.algorithmId;
    let importAlgorithm, verifyAlgorithm, sig = signature;
    if ([0x0403, 0x0503, 0x0603].includes(scheme)) {
      if (keyOid !== O.ec) failCert('CertificateVerify ECDSA scheme does not match public key');
      const cfg = { 0x0403: ['P-256', 'SHA-256', 32, '1.2.840.10045.3.1.7'], 0x0503: ['P-384', 'SHA-384', 48, '1.3.132.0.34'], 0x0603: ['P-521', 'SHA-512', 66, '1.3.132.0.35'] }[scheme];
      const params = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
      const actualCurve = params?.valueBlock?.toString?.();
      if (actualCurve && actualCurve !== cfg[3]) failCert('CertificateVerify ECDSA curve does not match scheme');
      sig = ecdsaSignatureToRaw(signature, cfg[2]);
      importAlgorithm = { name: 'ECDSA', namedCurve: cfg[0] }; verifyAlgorithm = { name: 'ECDSA', hash: cfg[1] };
    } else if ([0x0804, 0x0805, 0x0806].includes(scheme)) {
      if (keyOid !== O.rsa) failCert('TLS rsa_pss_rsae scheme requires rsaEncryption SPKI');
      if (getRsaBits(cert) < 2048) failCert('RSA public key is weaker than 2048 bits');
      const cfg = { 0x0804: ['SHA-256', 32], 0x0805: ['SHA-384', 48], 0x0806: ['SHA-512', 64] }[scheme];
      importAlgorithm = { name: 'RSA-PSS', hash: cfg[0] }; verifyAlgorithm = { name: 'RSA-PSS', saltLength: cfg[1] };
    } else if (scheme === 0x0807) {
      if (keyOid !== O.ed) failCert('Ed25519 scheme does not match public key');
      importAlgorithm = { name: 'Ed25519' }; verifyAlgorithm = { name: 'Ed25519' };
    } else failCert(`Unsupported TLS signature scheme 0x${Number(scheme).toString(16)}`);
    const key = await crypto.subtle.importKey('spki', spki, importAlgorithm, false, ['verify']);
    if (!await crypto.subtle.verify(verifyAlgorithm, key, sig, signedData)) throw new EchProbeError('CERTIFICATE_VERIFY', 'CertificateVerify signature is invalid');
    return true;
  } catch (cause) {
    if (cause instanceof EchProbeError) {
      if (cause.code === 'CERTIFICATE') throw new EchProbeError('CERTIFICATE_VERIFY', cause.message, { cause });
      throw cause;
    }
    throw new EchProbeError('CERTIFICATE_VERIFY', 'CertificateVerify signature verification failed', { cause });
  }
}
