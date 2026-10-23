import { Cursor, bytes, concat, equal, extension, extensions, fail, handshake, random, record, u16, u24, vector, EchProbeError } from './bytes.js';
import { applicationKeys, finishedVerifyData, handshakeKeys, hash, nonce, verifyFinished } from './crypto.js';
import { parseEchConfigList } from '../config.js';
import { DEFAULT_TRUST_ANCHORS, validateCertificateChain, verifyCertificateVerify } from './certificate.js';

const HRR = new Uint8Array([0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c]);
const CV_SCHEMES = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807];
const CERT_SCHEMES = [...CV_SCHEMES, 0x0401, 0x0501, 0x0601];
const SIGALGS = 13, SIGALGS_CERT = 50;
const u16list = values => concat(...values.map(u16));

export async function createClientHello(hostname, protocols = []) {
  let key, group;
  try { key = await crypto.subtle.generateKey('X25519', false, ['deriveBits']); group = 29; }
  catch (error) {
    if (error.name !== 'NotSupportedError') throw error;
    key = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']); group = 23;
  }
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
  const host = new TextEncoder().encode(hostname), sessionId = random(32);
  const alpn = protocols.map(name => new TextEncoder().encode(name));
  const exts = concat(
    extension(0, vector(concat(new Uint8Array([0]), vector(host)))),
    extension(10, vector(u16(group))),
    extension(SIGALGS, vector(u16list(CV_SCHEMES))),
    // TLS 1.3 permits certificate-chain signature schemes here that cannot be
    // used for CertificateVerify (notably RSA PKCS#1 v1.5).
    extension(SIGALGS_CERT, vector(u16list(CERT_SCHEMES))),
    extension(43, new Uint8Array([2,3,4])),
    extension(51, vector(concat(u16(group), vector(publicKey)))),
    ...(alpn.length ? [extension(16, vector(concat(...alpn.map(name => concat(new Uint8Array([name.length]), name)))))] : []),
    // Intentionally invalid ECH outer: solicits retry configs, not ECH acceptance.
    extension(0xfe0d, concat(new Uint8Array([0]), u16(1), u16(1), random(1), vector(random(32)), vector(random(128)))),
  );
  const body = concat(new Uint8Array([3,3]), random(32), new Uint8Array([32]), sessionId,
    vector(u16(0x1301)), new Uint8Array([1,0]), vector(exts));
  const message = handshake(1, body);
  return { key, group, publicKey, sessionId, message, alpn, serverName: hostname, wire: record(22, message) };
}

export class TlsProbe {
  constructor(hello, maxBytes, { verifyCertificate = true, serverName, trustAnchors } = {}) {
    this.hello = hello;
    this.alpn = hello.alpn;
    this.maxBytes = maxBytes;
    this.verifyCertificate = verifyCertificate;
    this.serverName = serverName ?? hello.serverName;
    this.trustAnchors = verifyCertificate ? (trustAnchors ?? []) : [];
    if (this.trustAnchors !== DEFAULT_TRUST_ANCHORS && !Array.isArray(this.trustAnchors)) throw new TypeError('trustAnchors must be an array of DER certificates');
    this.total = 0;
    this.records = new Uint8Array();
    this.messages = new Uint8Array();
    this.serverSequence = 0n;
    this.clientSequence = 0n;
    this.appClientSequence = 0n;
    this.keys = null;
    this.application = null;
    this.transcript = hello.message.slice();
    this.state = 'server-hello';
    this.requestClientCertificate = false;
    this.certificateRequestSchemes = null;
    this.leafDer = null;
    this.result = null;
    this.ready = false;
    this.disposed = false;
    this.finished = false;
  }
  async push(input) {
    if (this.disposed) fail('MALFORMED', 'TLS parser has been disposed');
    if (this.ready) return this.readiness();
    const chunk = bytes(input);
    this.total += chunk.length;
    if (this.total > this.maxBytes) fail('LIMIT', 'TLS receive budget exceeded');
    this.records = concat(this.records, chunk);
    while (!this.ready && this.records.length >= 5) {
      const c = new Cursor(this.records), type = c.uint8(), version = c.uint16(), length = c.uint16();
      if (version !== 0x0303) fail('UNSUPPORTED', 'Expected TLS record legacy version 0x0303');
      if (!length || length > (type === 23 ? 16640 : 16384)) fail('MALFORMED', 'Invalid TLS record length');
      if (this.records.length < 5 + length) break;
      const header = this.records.slice(0, 5), data = c.take(length);
      this.records = this.records.slice(5 + length);
      if (type === 20) {
        if (!equal(data, new Uint8Array([1]))) fail('MALFORMED', 'Invalid ChangeCipherSpec');
      } else if (type === 21) {
        if (this.keys) fail('MALFORMED', 'Unprotected alert after ServerHello');
        this.alert(data);
      } else if (type === 22 && !this.keys) {
        await this.consume(data);
      } else if (type === 23 && this.keys) {
        let plain;
        try {
          plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce(this.keys.server.iv, this.serverSequence++),
            additionalData: header, tagLength: 128 }, this.keys.server.key, data));
        } catch (cause) { throw new EchProbeError('DECRYPT', 'TLS record authentication failed', { cause }); }
        let end = plain.length - 1;
        while (end >= 0 && plain[end] === 0) end--;
        if (end < 0 || end > 16384) fail('MALFORMED', 'Invalid TLSInnerPlaintext');
        if (plain[end] === 21) this.alert(plain.slice(0, end));
        if (plain[end] !== 22) fail('MALFORMED', 'Expected encrypted handshake data');
        await this.consume(plain.slice(0, end));
      } else fail('MALFORMED', 'Unexpected TLS record');
      // The connection's server handshake ends at Finished. Do not try to
      // decrypt tickets or application data under handshake traffic keys.
      if (this.ready) break;
    }
    return this.ready ? this.readiness() : null;
  }
  readiness() { return { ready: true, result: this.result, authenticated: this.verifyCertificate }; }
  alert(data) {
    if (data.length !== 2 || ![1,2].includes(data[0])) fail('MALFORMED', 'Invalid TLS alert');
    fail('TLS_ALERT', `TLS alert ${data[1]} (level ${data[0]})`);
  }
  async consume(data) {
    this.messages = concat(this.messages, data);
    while (!this.ready && this.messages.length >= 4) {
      const m = this.messages, length = (m[1] << 16) | (m[2] << 8) | m[3];
      if (length > this.maxBytes) fail('LIMIT', 'TLS handshake message exceeds receive budget');
      if (m.length < length + 4) break;
      const message = m.slice(0, length + 4);
      this.messages = m.slice(length + 4);
      if (this.state === 'server-hello') {
        if (message[0] !== 2 || this.messages.length) fail('MALFORMED', 'Expected a standalone ServerHello');
        await this.serverHello(message);
      } else {
        await this.handshakeMessage(message);
      }
    }
  }
  async serverHello(message) {
    const c = new Cursor(message.slice(4));
    if (c.uint16() !== 0x0303) fail('MALFORMED', 'Invalid ServerHello legacy version');
    if (equal(c.take(32), HRR)) fail('UNSUPPORTED', 'HelloRetryRequest is not implemented');
    if (!equal(c.vec8(), this.hello.sessionId)) fail('MALFORMED', 'ServerHello session ID mismatch');
    if (c.uint16() !== 0x1301) fail('UNSUPPORTED', 'Only TLS_AES_128_GCM_SHA256 is supported');
    if (c.uint8() !== 0) fail('MALFORMED', 'Unexpected TLS compression');
    const exts = extensions(c.vec16()); c.end();
    if (exts.size !== 2 || !exts.has(43) || !exts.has(51)) fail('MALFORMED', 'Unexpected ServerHello extensions');
    if (!equal(exts.get(43), new Uint8Array([3,4]))) fail('UNSUPPORTED', 'Only TLS 1.3 is supported');
    const share = new Cursor(exts.get(51)), group = share.uint16(), peer = share.vec16(); share.end();
    if (group !== this.hello.group) fail('UNSUPPORTED', 'Server selected an unoffered key share');
    if (peer.length !== (group === 29 ? 32 : 65)) fail('MALFORMED', 'Invalid server key share length');
    try {
      const algorithm = group === 29 ? 'X25519' : { name: 'ECDH', namedCurve: 'P-256' };
      const publicKey = await crypto.subtle.importKey('raw', peer, algorithm, false, []);
      const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: group === 29 ? 'X25519' : 'ECDH', public: publicKey }, this.hello.key.privateKey, 256));
      this.transcript = concat(this.transcript, message);
      this.keys = await handshakeKeys(shared, this.transcript);
      shared.fill(0);
      this.hello = null;
      this.state = 'encrypted-extensions';
    } catch (cause) { throw new EchProbeError('CRYPTO', 'TLS key exchange failed', { cause }); }
  }
  async handshakeMessage(message) {
    const type = message[0], body = message.slice(4);
    if (this.state === 'encrypted-extensions') {
      if (type !== 8) fail('MALFORMED', 'Expected EncryptedExtensions');
      this.encryptedExtensions(body); this.transcript = concat(this.transcript, message); this.state = 'certificate-or-request'; return;
    }
    if (this.state === 'certificate-or-request' && type === 13) {
      this.certificateRequest(body); this.transcript = concat(this.transcript, message); this.state = 'certificate'; return;
    }
    if (this.state === 'certificate-or-request' || this.state === 'certificate') {
      if (type !== 11) fail('MALFORMED', 'Expected server Certificate');
      await this.certificate(body); this.transcript = concat(this.transcript, message); this.state = 'certificate-verify'; return;
    }
    if (this.state === 'certificate-verify') {
      if (type !== 15) fail('MALFORMED', 'Expected server CertificateVerify');
      await this.certificateVerify(body); this.transcript = concat(this.transcript, message); this.state = 'server-finished'; return;
    }
    if (this.state === 'server-finished') {
      if (type !== 20) fail('MALFORMED', 'Expected server Finished');
      await this.serverFinished(body); return;
    }
    fail('MALFORMED', 'Unexpected TLS handshake message');
  }
  encryptedExtensions(body) {
    const c = new Cursor(body), exts = extensions(c.vec16()); c.end();
    for (const type of exts.keys()) if (![0,10,16,0xfe0d].includes(type)) fail('MALFORMED', 'Unsolicited EncryptedExtensions extension');
    if (exts.has(0) && exts.get(0).length) fail('MALFORMED', 'Nonempty server_name acknowledgement');
    if (exts.has(10)) {
      const groups = new Cursor(exts.get(10)), list = groups.vec16(); groups.end();
      if (!list.length || list.length % 2) fail('MALFORMED', 'Invalid supported_groups');
    }
    if (exts.has(16)) {
      const alpn = new Cursor(exts.get(16)), list = new Cursor(alpn.vec16()); alpn.end();
      const selected = list.vec8();
      if (!this.alpn.some(protocol => equal(selected, protocol))) fail('MALFORMED', 'Unsolicited ALPN selection');
      list.end();
    }
    if (exts.has(0xfe0d)) {
      this.result = parseEchConfigList(exts.get(0xfe0d));
      if (!this.result.configs.some(config => config.known)) fail('UNSUPPORTED', 'No supported ECHConfig version');
    }
  }
  certificateRequest(body) {
    const c = new Cursor(body);
    if (c.vec8().length !== 0) fail('MALFORMED', 'Unsupported post-handshake CertificateRequest context');
    const exts = extensions(c.vec16()); c.end();
    for (const type of exts.keys()) if (![SIGALGS, SIGALGS_CERT, 47].includes(type)) fail('UNSUPPORTED', 'Unsupported CertificateRequest extension');
    if (!exts.has(SIGALGS)) fail('MALFORMED', 'CertificateRequest lacks signature_algorithms');
    this.certificateRequestSchemes = readSchemes(exts.get(SIGALGS));
    if (exts.has(SIGALGS_CERT)) readSchemes(exts.get(SIGALGS_CERT));
    if (exts.has(47)) {
      const authorities = new Cursor(exts.get(47)), names = new Cursor(authorities.vec16());
      authorities.end();
      while (names.remaining) names.vec16();
    }
    this.requestClientCertificate = true;
  }
  async certificate(body) {
    const c = new Cursor(body);
    if (c.vec8().length !== 0) fail('MALFORMED', 'Unsupported Certificate context');
    const list = new Cursor(c.take(c.uint24())); c.end();
    const certificates = [];
    while (list.remaining) {
      if (certificates.length >= 16) fail('LIMIT', 'Certificate chain contains too many entries');
      const der = list.take(list.uint24()), entryExtensions = extensions(list.vec16());
      // Parse all extensions and reject duplicates/truncation; unknown certificate
      // entry extensions are structurally valid and do not affect this probe.
      void entryExtensions;
      if (!der.length) fail('MALFORMED', 'Empty certificate entry');
      certificates.push(der);
    }
    if (!certificates.length) fail('CERTIFICATE', 'Server sent an empty certificate chain');
    this.leafDer = certificates[0].slice();
    if (this.verifyCertificate) {
      try { await validateCertificateChain(certificates, this.serverName, this.trustAnchors); }
      catch (cause) { if (cause?.code) throw cause; throw new EchProbeError('CERTIFICATE', 'Server certificate validation failed', { cause }); }
    }
  }
  async certificateVerify(body) {
    const c = new Cursor(body), scheme = c.uint16(), signature = c.vec16(); c.end();
    if (!CV_SCHEMES.includes(scheme)) fail('CERTIFICATE_VERIFY', 'Unsupported CertificateVerify signature scheme');
    const signedData = concat(new Uint8Array(64).fill(0x20), new TextEncoder().encode('TLS 1.3, server CertificateVerify'), new Uint8Array([0]), await hash(this.transcript));
    try { await verifyCertificateVerify(this.leafDer, scheme, signature, signedData); }
    catch (cause) { if (cause?.code) throw cause; throw new EchProbeError('CERTIFICATE_VERIFY', 'CertificateVerify signature failed', { cause }); }
  }
  async serverFinished(body) {
    if (this.messages.length) fail('MALFORMED', 'Unexpected handshake bytes after server Finished in the same record');
    if (body.length !== 32) fail('FINISHED', 'Invalid server Finished length');
    if (!await verifyFinished(this.keys.serverHandshakeSecret, await hash(this.transcript), body)) fail('FINISHED', 'Server Finished verification failed');
    this.transcript = concat(this.transcript, new Uint8Array([20,0,0,body.length]), body);
    const app = await applicationKeys(this.keys.masterSecret, await hash(this.transcript));
    this.application = app;
    this.ready = true;
    this.state = 'complete';
    this.keys.serverSequence = this.serverSequence;
  }
  async finishHandshake() {
    if (!this.ready || this.finished) fail('FINISHED', 'Server Finished has not been verified or handshake already finished');
    const records = [];
    if (this.requestClientCertificate) {
      // No client identity is configured: answer the request with an empty chain.
      records.push(await this.encryptClientHandshake(handshake(11, concat(new Uint8Array([0]), u24(0)))));
      this.transcript = concat(this.transcript, handshake(11, concat(new Uint8Array([0]), u24(0))));
    }
    const verify = await finishedVerifyData(this.keys.clientHandshakeSecret, await hash(this.transcript));
    const finished = handshake(20, verify);
    this.transcript = concat(this.transcript, finished);
    records.push(await this.encryptClientHandshake(finished));
    // ECH retry probing terminates the connection with ech_required; no appdata.
    const payload = concat(new Uint8Array([2,121]), new Uint8Array([21]));
    records.push(await this.encryptClientApplication(payload));
    this.finished = true;
    return { records, result: this.result, authenticated: this.verifyCertificate };
  }
  async encryptClientHandshake(message) {
    const plain = concat(message, new Uint8Array([22]));
    return encryptRecord(this.keys.client.key, this.keys.client.iv, this.clientSequence++, plain);
  }
  async encryptClientApplication(plain) {
    return encryptRecord(this.application.client.key, this.application.client.iv, this.appClientSequence++, plain);
  }
  finish() { fail('TRUNCATED', 'Connection ended before authenticated server Finished'); }
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.transcript.fill(0); this.messages.fill(0); this.records.fill(0);
    for (const value of [this.keys?.earlySecret, this.keys?.handshakeSecret, this.keys?.serverHandshakeSecret,
      this.keys?.clientHandshakeSecret, this.keys?.masterSecret, this.keys?.server?.secret, this.keys?.client?.secret,
      this.application?.server?.secret, this.application?.client?.secret]) value?.fill?.(0);
    this.keys = null; this.application = null; this.hello = null; this.leafDer = null; this.trustAnchors = [];
  }
}

function readSchemes(data) {
  const c = new Cursor(data), schemes = new Cursor(c.vec16()); c.end();
  if (!schemes.remaining || schemes.remaining % 2) fail('MALFORMED', 'Invalid signature_algorithms list');
  const out = [];
  while (schemes.remaining) out.push(schemes.uint16());
  return out;
}

async function encryptRecord(key, iv, sequence, plain) {
  const header = new Uint8Array([23,3,3,...u16(plain.length + 16)]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce(iv, sequence), additionalData: header, tagLength: 128 }, key, plain));
  return concat(header, ciphertext);
}
