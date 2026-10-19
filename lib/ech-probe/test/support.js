import { concat, Cursor, extension, extensions, handshake, random, record, u16, vector } from '../internal/bytes.js';

export function check(value, message = 'Assertion failed') { if (!value) throw new Error(message); }
export function same(a, b, message = 'Values differ') { check(JSON.stringify(a) === JSON.stringify(b), message); }
export async function rejects(fn, code) {
  try { await fn(); } catch (error) { check(error.code === code, `Expected ${code}, got ${error.code}: ${error.message}`); return; }
  throw new Error(`Expected rejection ${code}`);
}
export function hex(data) { return Array.from(data, n => n.toString(16).padStart(2, '0')).join(''); }
export function unhex(text) {
  check(typeof text === 'string' && text.length % 2 === 0 && /^[0-9a-f]*$/i.test(text), 'Invalid hexadecimal fixture');
  return Uint8Array.from(text.match(/../g) ?? [], s => parseInt(s, 16));
}
export function decode(text) { return Uint8Array.from(atob(text), ch => ch.charCodeAt(0)); }
export function pemDer(pem) { return decode(pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\\s/g, '')); }

export function readClientHello(wire) {
  const message = wire.slice(5), c = new Cursor(message.slice(4));
  check(c.uint16() === 0x0303); c.take(32);
  const sessionId = c.vec8(); check(hex(c.vec16()) === '1301'); check(hex(c.vec8()) === '00');
  const exts = extensions(c.vec16()); c.end();
  const shares = new Cursor(exts.get(51)), share = new Cursor(shares.vec16()); shares.end();
  const group = share.uint16(), publicKey = share.vec16(); share.end();
  const names = new Cursor(exts.get(0)), nameList = new Cursor(names.vec16()); names.end();
  check(nameList.uint8() === 0);
  const serverName = new TextDecoder().decode(nameList.vec16()); nameList.end();
  const alpn = [];
  if (exts.has(16)) {
    const outer = new Cursor(exts.get(16)), list = new Cursor(outer.vec16()); outer.end();
    while (list.remaining) alpn.push(new TextDecoder().decode(list.vec8()));
  }
  return { sessionId, message, group, publicKey, serverName, alpn };
}

const INFO = (label, ctx, size) => {
  const name = new TextEncoder().encode('tls13 ' + label);
  return concat(u16(size), new Uint8Array([name.length]), name, new Uint8Array([ctx.length]), ctx);
};
const EMPTY_HASH = new Uint8Array([0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55]);
const DERIVED_SECRET = unhex('6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba');
async function digest(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); }
async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}
async function hkdfExtract(salt, input) { return hmac(salt, input); }
async function hkdfExpand(secret, info, length) {
  let prior = new Uint8Array(), output = new Uint8Array();
  for (let i = 1; output.length < length; i++) {
    prior = await hmac(secret, concat(prior, info, new Uint8Array([i])));
    output = concat(output, prior);
  }
  return output.slice(0, length);
}
async function expandLabel(secret, label, context, length) { return hkdfExpand(secret, INFO(label, context, length), length); }
async function deriveSecret(secret, label, transcript) { return expandLabel(secret, label, await digest(transcript), 32); }
async function trafficKey(secret) {
  return { key: await crypto.subtle.importKey('raw', await expandLabel(secret, 'key', new Uint8Array(), 16), 'AES-GCM', false, ['encrypt', 'decrypt']),
    iv: await expandLabel(secret, 'iv', new Uint8Array(), 12) };
}
function u24(n) { return new Uint8Array([n >>> 16, n >>> 8, n]); }
function vector24(data) { return concat(u24(data.length), data); }
function derInteger(raw) {
  let start = 0;
  while (start < raw.length - 1 && raw[start] === 0) start++;
  let value = raw.slice(start);
  if (value[0] & 0x80) value = concat(new Uint8Array([0]), value);
  return concat(new Uint8Array([2, value.length]), value);
}
function p1363ToDer(signature) {
  const size = signature.length / 2;
  const body = concat(derInteger(signature.slice(0, size)), derInteger(signature.slice(size)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

// Test-side TLS server key schedule. It intentionally uses native HKDF and never
// calls the client implementation's handshakeKeys() to create a server flight.
export async function makeFlight(hello, configs, options = {}) {
  const algorithm = hello.group === 29 ? 'X25519' : { name: 'ECDH', namedCurve: 'P-256' };
  const server = await crypto.subtle.generateKey(algorithm, false, ['deriveBits']);
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', server.publicKey));
  const peer = await crypto.subtle.importKey('raw', hello.publicKey, algorithm, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: hello.group === 29 ? 'X25519' : 'ECDH', public: peer }, server.privateKey, 256));
  const serverRandom = options.serverRandom ?? random(32);
  const sh = handshake(2, concat(new Uint8Array([3,3]), serverRandom,
    new Uint8Array([32]), options.sessionId ?? hello.sessionId, u16(options.cipher ?? 0x1301), new Uint8Array([0]),
    vector(concat(extension(43, new Uint8Array([3,4])), extension(51, concat(u16(hello.group), vector(pub)))))));
  const earlySecret = await hkdfExtract(new Uint8Array(32), new Uint8Array(32));
  const derived = await expandLabel(earlySecret, 'derived', EMPTY_HASH, 32);
  const handshakeSecret = await hkdfExtract(derived, shared);
  const chShTranscript = concat(hello.message, sh);
  const hsTraffic = await deriveSecret(handshakeSecret, 's hs traffic', chShTranscript);
  const clientHsTraffic = await deriveSecret(handshakeSecret, 'c hs traffic', chShTranscript);
  const serverKeys = await trafficKey(hsTraffic);
  const key = serverKeys.key;
  const iv = serverKeys.iv;
  const encrypted = [];
  let sequence = 0n;
  const encrypt = async (payload, type = 22, padding = 0) => {
    const plain = concat(payload, new Uint8Array([type]), new Uint8Array(padding));
    const head = new Uint8Array([23,3,3,...u16(plain.length + 16)]), nonce = iv.slice();
    let seq = sequence++;
    for (let i = 11; i >= 4; i--) { nonce[i] ^= Number(seq & 255n); seq >>= 8n; }
    return concat(head, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: head }, key, plain)));
  };
  const encryptHandshake = async (payload, fragment = false, padding = 0) => {
    if (!fragment) return [await encrypt(payload, 22, padding)];
    const cuts = [1, Math.max(2, Math.floor(payload.length / 2)), payload.length].filter((n, i, all) => n > (i ? all[i - 1] : 0));
    const parts = []; let start = 0;
    for (const end of cuts) { parts.push(await encrypt(payload.slice(start, end), 22, padding)); start = end; }
    return parts;
  };
  const ee = handshake(options.handshakeType ?? 8, vector(options.eeExtensions ??
    (configs ? extension(0xfe0d, configs) : new Uint8Array())));
  const certs = options.certificates;
  let certificate = null, cv = null, serverFinishedTranscript = null, clientAppTraffic = null;
  if (certs) {
    const chain = options.chain ?? certs.chainDerBase64.map(decode);
    const entries = chain.map((der, i) => concat(vector24(der), vector(options.certificateEntryExtensions?.[i] ?? new Uint8Array())));
    const certBody = concat(new Uint8Array([0]), vector24(concat(...entries)));
    certificate = handshake(11, certBody);
    const request = options.certificateRequest ? handshake(13, concat(new Uint8Array([0]), vector(options.certificateRequest))) : null;
    const signedTranscript = concat(hello.message, sh, ee, ...(request ? [request] : []), certificate);
    const transcript = await digest(signedTranscript);
    const context = concat(new Uint8Array(64).fill(0x20), new TextEncoder().encode('TLS 1.3, server CertificateVerify'), new Uint8Array([0]), transcript);
    let signature;
    if (options.signature) signature = options.signature;
    else {
      const privateKey = await crypto.subtle.importKey('pkcs8', decode(certs.leafPrivateKeyPkcs8Base64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      signature = p1363ToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, context)));
    }
    cv = handshake(15, concat(u16(options.signatureScheme ?? 0x0403), vector(signature)));
    const beforeFinished = await digest(concat(signedTranscript, cv));
    const finishedKey = await expandLabel(hsTraffic, 'finished', new Uint8Array(), 32);
    const verify = await hmac(finishedKey, beforeFinished);
    const finished = handshake(20, options.finished ?? verify);
    serverFinishedTranscript = concat(signedTranscript, cv, finished);
    const masterDerived = await expandLabel(handshakeSecret, 'derived', EMPTY_HASH, 32);
    const masterSecret = await hkdfExtract(masterDerived, new Uint8Array(32));
    clientAppTraffic = await deriveSecret(masterSecret, 'c ap traffic', serverFinishedTranscript);
    encrypted.push(...await encryptHandshake(ee, options.fragmentHandshake, options.padding ?? 0));
    if (request) encrypted.push(...await encryptHandshake(request, false));
    if (options.omitCertificate !== true) encrypted.push(...await encryptHandshake(certificate, options.fragmentCertificate));
    if (options.omitCertificate !== true) encrypted.push(...await encryptHandshake(cv, false));
    if (options.omitFinished !== true) encrypted.push(...await encryptHandshake(finished, false));
  } else {
    encrypted.push(await encrypt(ee, 22, options.padding ?? 0));
    if (options.includeFinished) encrypted.push(await encrypt(handshake(20, new Uint8Array(32)), 22));
  }
  const shRecords = options.fragmentServerHello ? [record(22, sh.slice(0, 3)), record(22, sh.slice(3))] : [record(22, sh)];
  const wire = concat(...shRecords, record(20, new Uint8Array([1])), ...encrypted);
  return { sh, ee, certificate, certificateRequest: options.certificateRequest ? handshake(13, concat(new Uint8Array([0]), vector(options.certificateRequest))) : null,
    cv, encrypted, wire, hsTraffic, clientHsTraffic, clientAppTraffic,
    serverFinishedTranscript: certs ? serverFinishedTranscript : null, sequence: sequence.toString() };
}

// Independently checks emitted client handshake and application records.
export async function verifyClientFinish(hello, flight, records, expectedAlert = new Uint8Array([2, 121])) {
  check(flight.clientHsTraffic && flight.clientAppTraffic && flight.serverFinishedTranscript, 'Full authenticated server flight is required');
  check(records.length >= 2, 'client Finished and encrypted application alert were not emitted');
  const transcript = flight.certificateRequest
    ? concat(flight.serverFinishedTranscript, handshake(11, concat(new Uint8Array([0]), u24(0))))
    : flight.serverFinishedTranscript;
  const clientFinishedHash = await digest(transcript);
  const finishedKey = await expandLabel(flight.clientHsTraffic, 'finished', new Uint8Array(), 32);
  const verifyData = await hmac(finishedKey, clientFinishedHash);
  const clientKeys = await trafficKey(flight.clientHsTraffic);
  const appKeys = await trafficKey(flight.clientAppTraffic);
  const decrypt = async (wire, keys, seq) => {
    check(wire.length >= 5 && wire[0] === 23, 'expected encrypted client TLS record');
    const header = wire.slice(0, 5), nonce = keys.iv.slice(); let n = BigInt(seq);
    for (let i = 11; i >= 4; i--) { nonce[i] ^= Number(n & 255n); n >>= 8n; }
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: header }, keys.key, wire.slice(5)));
  };
  const firstClientHandshakeSequence = flight.certificateRequest ? 1 : 0;
  if (flight.certificateRequest) {
    const certPlain = await decrypt(records[0], clientKeys, 0);
    check(certPlain[certPlain.length - 1] === 22 && hex(certPlain.slice(0, -1)) === '0b00000400000000', 'empty client Certificate response differs');
  }
  const finishedIndex = flight.certificateRequest ? 1 : 0;
  const finishedPlain = await decrypt(records[finishedIndex], clientKeys, firstClientHandshakeSequence);
  let end = finishedPlain.length - 1; while (end >= 0 && finishedPlain[end] === 0) end--;
  check(end >= 0 && finishedPlain[end] === 22, 'first client record is not handshake content');
  const finishedMessage = finishedPlain.slice(0, end);
  check(finishedMessage.length === 36 && finishedMessage[0] === 20, 'client Finished message is malformed');
  check(hex(finishedMessage.slice(4)) === hex(verifyData), 'client Finished verify_data differs');
  const alertPlain = await decrypt(records[finishedIndex + 1], appKeys, 0);
  end = alertPlain.length - 1; while (end >= 0 && alertPlain[end] === 0) end--;
  check(end >= 0 && alertPlain[end] === 21, 'second client record is not an encrypted alert');
  check(hex(alertPlain.slice(0, end)) === hex(expectedAlert), 'client application alert differs');
  return true;
}
