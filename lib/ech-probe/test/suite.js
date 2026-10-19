import { parseEchConfigList } from '../config.js';
import { concat, extension, record, u16, vector } from '../internal/bytes.js';
import { expandLabel, hmac } from '../internal/crypto.js';
import { probeWithConnect as runProbe } from '../internal/probe.js';

import { TlsProbe, createClientHello } from '../internal/tls.js';
import { runCertificateTests } from './certificate-tests.js';
import { check, decode, hex, readClientHello, rejects, unhex, makeFlight, pemDer, verifyClientFinish } from './support.js';

const EMPTY_HASH = unhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
const EARLY_SECRET = '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a';
const DERIVED_SECRET = '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba';

export async function runSuite(fixture) {
  const meta = fixture.meta ?? fixture;
  const certificates = fixture.certificates;
  if (!certificates?.rootPem) throw new Error('Missing TLS certificate fixture');
  const testRoot = certificates.rootPem;
  const withTrust = options => options?.verifyCertificate === false
    ? options
    : ({ verifyCertificate: true, caCertificates: [testRoot], ...options });
  const fullFlight = (hello, config, options = {}) => makeFlight(hello, config, { certificates, ...options });
  const completed = async (parser, wire) => {
    const ready = await parser.push(wire);
    check(ready?.ready === true, 'complete server flight did not reach authenticated readiness');
    return parser.finishHandshake();
  };
  const probeWithConnect = (connect, options = {}) => runProbe(connect,
    options && typeof options === 'object' && !Array.isArray(options) ? { hostname: 'example.test', ...withTrust(options) } : options);
  let passed = 0;
  const test = async (name, fn) => {
    try { await fn(); passed++; }
    catch (error) { throw new Error(`${name}: ${error?.message ?? String(error)}`, { cause: error }); }
  };
  const raw = decode(meta.base64);
  const parsed = parseEchConfigList(raw);
  const known = parsed.configs.filter(config => config.known);
  const unknown = parsed.configs.filter(config => !config.known);

  await test('fixture integrity and metadata', async () => {
    check(raw.length === 707, `expected 707 fixture bytes, got ${raw.length}`);
    check(parsed.configs.length === 10, `expected 10 configs, got ${parsed.configs.length}`);
    check(known.length > 0 && unknown.length === 0, 'fixture config version mix changed');
    check(hex(new Uint8Array(await crypto.subtle.digest('SHA-256', raw))) === meta.sha256, 'fixture meta SHA-256 mismatch');
    check(parsed.base64 === meta.base64, 'base64 round trip differs');
  });
  await test('config parser accepts views with nonzero byteOffset', async () => {
    const backing = new Uint8Array(raw.length + 12); backing.set(raw, 7);
    const view = new DataView(backing.buffer, 7, raw.length);
    const result = parseEchConfigList(view);
    check(result.bytes.length === raw.length && hex(result.bytes) === hex(raw), 'DataView slice was not honored');
  });
  await test('config parser preserves unknown versions', async () => {
    const input = vector(concat(u16(0x1234), vector(new Uint8Array([9, 8, 7]))));
    const result = parseEchConfigList(input);
    check(result.configs.length === 1 && result.configs[0].known === false, 'unknown version not preserved');
    check(result.configs[0].version === 0x1234 && hex(result.configs[0].contents) === '090807', 'unknown config fields differ');
  });
  await test('config parser rejects malformed and oversized inputs', async () => {
    for (const value of [new Uint8Array(), new Uint8Array([0]), new Uint8Array([0, 1, 0]), new Uint8Array([0, 2, 0, 1]), new Uint8Array([0, 0])])
      await rejects(() => parseEchConfigList(value), 'MALFORMED');
    await rejects(() => parseEchConfigList(new Uint8Array(65538)), 'LIMIT');
    try { parseEchConfigList('not bytes'); throw new Error('Expected byte input validation'); }
    catch (error) { check(error instanceof TypeError, 'invalid input did not throw TypeError'); }
    try { parseEchConfigList(new Array(2)); throw new Error('Expected sparse array validation'); }
    catch (error) { check(error instanceof TypeError, 'sparse byte array did not throw TypeError'); }
    const invalidConfig = name => {
      const encodedName = new TextEncoder().encode(name);
      const contents = concat(new Uint8Array([1]), u16(0x20), vector(new Uint8Array(32)),
        vector(concat(u16(1), u16(1))), new Uint8Array([0, encodedName.length]), encodedName, vector(new Uint8Array()));
      return vector(concat(u16(0xfe0d), vector(contents)));
    };
    for (const name of ['example.com', 'example.0xg']) {
      const result = parseEchConfigList(invalidConfig(name));
      check(result.configs[0].publicName === name, 'valid public_name was rejected');
    }
    for (const name of ['example.123', 'example.0x', 'example.0x12', '0x123'])
      await rejects(() => parseEchConfigList(invalidConfig(name)), 'MALFORMED');
  });
  await test('RFC 4231 HMAC-SHA256 vectors', async () => {
    const cases = [
      ['0b'.repeat(20), 'Hi There', 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
      ['4a656665', 'what do ya want for nothing?', '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'],
    ];
    for (const [key, data, expected] of cases) check(hex(await hmac(unhex(key), new TextEncoder().encode(data))) === expected, `RFC 4231 mismatch for ${data}`);
  });
  await test('TLS no-PSK early and derived secrets', async () => {
    const zeros = new Uint8Array(32);
    const early = await hmac(zeros, zeros);
    check(hex(early) === EARLY_SECRET, 'early_secret differs from RFC 8448');
    const derived = await expandLabel(early, 'derived', EMPTY_HASH, 32);
    check(hex(derived) === DERIVED_SECRET, 'derived_secret differs from RFC 8448');
  });

  const makeParser = async options => {
    const hello = await createClientHello('example.test');
    const flight = await fullFlight(readClientHello(hello.wire), raw, options);
    return { hello, parser: new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'example.test', trustAnchors: [pemDer(testRoot)] }), flight };
  };
  await test('complete verified server flight emits independently valid client Finished and alert', async () => {
    const hello = await createClientHello('example.test');
    const flight = await fullFlight(readClientHello(hello.wire), raw);
    const parser = new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'example.test', trustAnchors: [pemDer(testRoot)] });
    const result = await completed(parser, flight.wire);
    check(result.authenticated && result.result.configs.length === 10, 'default verification did not authenticate complete flight');
    await verifyClientFinish(hello, flight, result.records);
  });
  await test('default verification rejects unknown CA and hostname without retry', async () => {
    const hello = await createClientHello('example.test');
    const flight = await fullFlight(readClientHello(hello.wire), raw);
    await rejects(() => new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'example.test', trustAnchors: [] }).push(flight.wire), 'CERTIFICATE');
    await rejects(() => new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'not-used.example', trustAnchors: [pemDer(testRoot)] }).push(flight.wire), 'HOSTNAME');
  });
  await test('CertificateRequest is answered with empty client Certificate before Finished', async () => {
    const hello = await createClientHello('example.test');
    const requestExtensions = extension(13, vector(u16(0x0403)));
    const flight = await fullFlight(readClientHello(hello.wire), raw, { certificateRequest: requestExtensions });
    const parser = new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'example.test', trustAnchors: [pemDer(testRoot)] });
    const result = await completed(parser, flight.wire);
    check(result.authenticated, 'CertificateRequest flight was not authenticated');
    check(result.records.length === 3, 'empty certificate response / Finished / alert records missing');
    await verifyClientFinish(hello, flight, result.records);
  });
  await test('Certificate handshake survives encrypted-record fragmentation and sequence increments', async () => {
    const hello = await createClientHello('example.test');
    const flight = await fullFlight(readClientHello(hello.wire), raw, { fragmentCertificate: true });
    const parser = new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'example.test', trustAnchors: [pemDer(testRoot)] });
    const result = await completed(parser, flight.wire);
    check(result.authenticated && result.result.configs.length === 10, 'fragmented Certificate flight failed');
    await verifyClientFinish(hello, flight, result.records);
  });
  await test('authentication-disabled path still verifies CertificateVerify and Finished', async () => {
    const hello = await createClientHello('example.test');
    const flight = await fullFlight(readClientHello(hello.wire), raw);
    const parser = new TlsProbe(hello, 65536, { verifyCertificate: false, serverName: 'not-used.example' });
    const result = await completed(parser, flight.wire);
    check(result.authenticated === false && result.result.configs.length === 10, 'disabled chain validation result differs');
    await verifyClientFinish(hello, flight, result.records);
    const badCv = await fullFlight(readClientHello(hello.wire), raw, { signature: new Uint8Array([0x30, 0]) });
    await rejects(() => new TlsProbe(hello, 65536, { verifyCertificate: false, serverName: 'example.test' }).push(badCv.wire), 'CERTIFICATE_VERIFY');
    const badFinished = await fullFlight(readClientHello(hello.wire), raw, { finished: new Uint8Array(32) });
    await rejects(() => new TlsProbe(hello, 65536, { verifyCertificate: false, serverName: 'example.test' }).push(badFinished.wire), 'FINISHED');
    const eeOnly = await makeFlight(readClientHello(hello.wire), raw);
    const waiting = new TlsProbe(hello, 65536, { verifyCertificate: false, serverName: 'example.test' });
    check(await waiting.push(eeOnly.wire) === null, 'EE-only server response unexpectedly completed');
    await rejects(() => waiting.finish(), 'TRUNCATED');
    const truncated = await fullFlight(readClientHello(hello.wire), raw, { omitCertificate: true });
    await rejects(() => new TlsProbe(hello, 65536, { verifyCertificate: false, serverName: 'example.test' }).push(truncated.wire), 'MALFORMED');
  });
  await test('P-256 fallback uses the same TLS extraction path', async () => {
    const original = crypto.subtle.generateKey;
    let hello;
    try {
      crypto.subtle.generateKey = function(algorithm, ...args) {
        if (algorithm === 'X25519') return Promise.reject(new DOMException('test fallback', 'NotSupportedError'));
        return original.call(this, algorithm, ...args);
      };
      hello = await createClientHello('example.test');
    } finally { crypto.subtle.generateKey = original; }
    check(hello.group === 23 && hello.key.privateKey.extractable === false, 'P-256 fallback did not select a private ephemeral key');
    const flight = await fullFlight(readClientHello(hello.wire), raw, { fragmentHandshake: true });
    const result = await completed(new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'example.test', trustAnchors: [pemDer(testRoot)] }), flight.wire);
    check(result.result.configs.length === 10 && result.authenticated === true, 'P-256 extraction/authentication failed');
  });
  await test('TLS rejects reordered encrypted records and duplicate extensions', async () => {
    const reordered = await makeParser({ fragmentHandshake: true });
    await rejects(() => reordered.parser.push(concat(record(22, reordered.flight.sh),
      reordered.flight.encrypted[1], reordered.flight.encrypted[0])), 'DECRYPT');
    const duplicate = await makeParser({ eeExtensions: concat(extension(0xfe0d, raw), extension(0xfe0d, raw)) });
    await rejects(() => duplicate.parser.push(duplicate.flight.wire), 'MALFORMED');
  });
  await test('TLS reassembles split handshake and ServerHello records', async () => {
    const { parser, flight } = await makeParser({ fragmentHandshake: true, fragmentServerHello: true, padding: 7 });
    let result;
    for (let i = 0; i < flight.wire.length; i += 3) {
      const value = await parser.push(flight.wire.subarray(i, i + 3));
      if (value?.ready) result = await parser.finishHandshake();
    }
    check(result?.result.configs.length === 10 && result.authenticated, 'fragmented TLS flight did not complete');
  });
  await test('TLS permits dummy CCS before SH, between fragments, and multiple times', async () => {
    const ccs = record(20, new Uint8Array([1]));
    const first = await makeParser({ fragmentHandshake: true, fragmentServerHello: true });
    const result = await completed(first.parser, concat(ccs, ccs, first.flight.wire));
    check(result.result.configs.length === 10, 'CCS before ServerHello changed extraction');
    const second = await makeParser({ fragmentHandshake: true });
    const firstEncrypted = second.flight.encrypted[0], restEncrypted = concat(...second.flight.encrypted.slice(1));
    const interleaved = concat(record(22, second.flight.sh), ccs, record(20, new Uint8Array([1])), firstEncrypted, ccs, restEncrypted);
    const between = await completed(second.parser, interleaved);
    check(between.result.configs.length === 10, 'CCS between encrypted handshake fragments consumed sequence number');
  });
  await test('TLS rejects altered ciphertext authentication', async () => {
    const { parser, flight } = await makeParser();
    const modified = flight.wire.slice(); modified[modified.length - 1] ^= 1;
    await rejects(() => parser.push(modified), 'DECRYPT');
  });
  await test('TLS rejects missing ECH extension and unsupported handshake', async () => {
    const missing = await makeParser({ eeExtensions: new Uint8Array() });
    const missingResult = await completed(missing.parser, missing.flight.wire);
    check(missingResult.result === null, 'missing ECH config was not deferred until the complete handshake');
    const other = await makeParser({ handshakeType: 11 });
    await rejects(() => other.parser.push(other.flight.wire), 'MALFORMED');
  });
  await test('TLS rejects alert, unsupported cipher, HRR, and session mismatch', async () => {
    const badCipher = await makeParser({ cipher: 0x1302 });
    await rejects(() => badCipher.parser.push(record(22, badCipher.flight.sh)), 'UNSUPPORTED');
    const badSession = await makeParser({ sessionId: new Uint8Array(32) });
    await rejects(() => badSession.parser.push(record(22, badSession.flight.sh)), 'MALFORMED');
    const hello = await createClientHello('example.test');
    const hrr = concat(new Uint8Array([2, 0, 0, 72, 3, 3]), unhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'),
      new Uint8Array([32]), hello.sessionId, new Uint8Array([0x13, 1, 0, 0, 0]));
    await rejects(() => new TlsProbe(hello, 65536).push(record(22, hrr)), 'UNSUPPORTED');
    await rejects(() => new TlsProbe(hello, 65536).push(record(21, new Uint8Array([2, 40]))), 'TLS_ALERT');
  });
  await test('TLS enforces receive budget', async () => {
    const parser = new TlsProbe(await createClientHello('example.test'), 1024);
    await rejects(() => parser.push(new Uint8Array(1025)), 'LIMIT');
    const badRecord = new TlsProbe(await createClientHello('example.test'), 65536);
    await rejects(() => badRecord.push(new Uint8Array([22, 3, 3, 0x40, 1])), 'MALFORMED');
    const badCcs = new TlsProbe(await createClientHello('example.test'), 65536);
    await rejects(() => badCcs.push(record(20, new Uint8Array([2]))), 'MALFORMED');
  });

  const successfulSocket = async (mode, config = raw) => {
    let closed = 0, written, flight, readableController;
    const writes = [];
    const readable = new ReadableStream({
      start(controller) { readableController = controller; if (mode?.readFail) controller.error(new Error('read failed')); },
    });
    const writable = new WritableStream({
      async write(chunk) {
        writes.push(chunk);
        if (mode?.writeFail) throw new Error('write failed');
        if (mode?.readFail || written) return;
        written = chunk;
        flight = await fullFlight(readClientHello(chunk), config);
        readableController.enqueue(flight.wire);
        readableController.close();
      },
    });
    const opened = mode?.openFail ? Promise.reject(new Error('open failed')) : Promise.resolve();
    void opened.catch(() => {});
    const socket = { opened, closed: Promise.resolve(), readable, writable,
      close() { closed++; return Promise.resolve(); } };
    return { socket, get closedCount() { return closed; }, get written() { return written; }, get writes() { return writes; }, get flight() { return flight; } };
  };
  await test('transport succeeds and closes resources with supported connect options', async () => {
    const fake = await successfulSocket(); let params, options;
    const result = await probeWithConnect((p, o) => { params = p; options = o; return fake.socket; });
    check(result.configs.length === 10 && result.authenticated === true && result.handshakeComplete === true, 'transport result differs');
    check(params.hostname === 'example.test' && params.port === 443, 'wrong configured endpoint');
    check(options.secureTransport === 'off' && options.allowHalfOpen === false, 'socket options differ');
    check(fake.closedCount === 1 && fake.written instanceof Uint8Array, 'socket was not written/closed');
    check(!fake.socket.readable.locked && !fake.socket.writable.locked, 'stream locks were not released');
    await verifyClientFinish(readClientHello(fake.written), fake.flight, fake.writes.slice(1));
  });
  await test('unauthenticated transport skips only chain and hostname checks', async () => {
    const fake = await successfulSocket();
    const result = await probeWithConnect(() => fake.socket, { verifyCertificate: false, serverName: 'not-used.example' });
    check(result.authenticated === false && result.handshakeComplete === true, 'explicitly unauthenticated result differs');
    await verifyClientFinish(readClientHello(fake.written), fake.flight, fake.writes.slice(1));
  });
  await test('hostname validation failure closes once without client handshake writes', async () => {
    const fake = await successfulSocket(); let connects = 0;
    await rejects(() => probeWithConnect(() => { connects++; return fake.socket; }, { serverName: 'not-used.example' }), 'HOSTNAME');
    check(connects === 1 && fake.closedCount === 1, 'hostname failure retried or leaked transport');
    check(fake.writes.length === 1, 'client sent Finished after hostname validation failed');
  });
  await test('unknown CA validation failure does not reconnect', async () => {
    const badRoot = pemDer(testRoot), needle = new TextEncoder().encode('SuperDoH Test Root');
    let found = -1;
    outer: for (let i = 0; i <= badRoot.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) if (badRoot[i + j] !== needle[j]) continue outer;
      found = i;
    }
    check(found >= 0, 'test root subject was not found');
    badRoot[found + needle.length - 1] ^= 1;
    const base64 = btoa(String.fromCharCode(...badRoot));
    const wrongRoot = `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`;
    const fake = await successfulSocket(); let connects = 0;
    await rejects(() => probeWithConnect(() => { connects++; return fake.socket; }, { caCertificates: [wrongRoot] }), 'CERTIFICATE');
    check(connects === 1 && fake.closedCount === 1, 'unknown CA failure retried or leaked transport');
    check(fake.writes.length === 1, 'client sent Finished after unknown CA failure');
  });
  await test('no retry config is reported only after writing a complete authenticated handshake', async () => {
    const fake = await successfulSocket(undefined, null);
    await rejects(() => probeWithConnect(() => fake.socket), 'NO_RETRY_CONFIG');
    check(fake.writes.length >= 3, 'no-config path omitted client Finished or alert records');
    await verifyClientFinish(readClientHello(fake.written), fake.flight, fake.writes.slice(1));
  });
  for (const mode of ['openFail', 'writeFail', 'readFail']) await test(`transport wraps ${mode} and cleans up`, async () => {
    const fake = await successfulSocket({ [mode]: true });
    await rejects(() => probeWithConnect(() => fake.socket), 'IO');
    check(fake.closedCount === 1, 'socket not closed after failure');
  });
  await test('transport reports EOF as truncated and closes', async () => {
    let closed = 0;
    const socket = { opened: Promise.resolve(), closed: Promise.resolve(), readable: new ReadableStream({ start(c) { c.close(); } }),
      writable: new WritableStream(), close() { closed++; return Promise.resolve(); } };
    await rejects(() => probeWithConnect(() => socket), 'TRUNCATED'); check(closed === 1, 'EOF socket not closed');
  });
  await test('transport timeout closes a stalled socket', async () => {
    let closed = 0;
    const socket = { opened: new Promise(() => {}), closed: Promise.resolve(), readable: new ReadableStream(), writable: new WritableStream(), close() { closed++; return Promise.resolve(); } };
    await rejects(() => probeWithConnect(() => socket, { timeoutMs: 250 }), 'TIMEOUT'); check(closed === 1, 'timed out socket not closed');
  });
  await test('transport honors AbortSignal and pre-aborted signals without connecting', async () => {
    const pre = new AbortController(); pre.abort(); let connects = 0;
    await rejects(() => probeWithConnect(() => { connects++; throw new Error('connected'); }, { signal: pre.signal }), 'ABORTED');
    check(connects === 0, 'pre-aborted signal connected');
    const controller = new AbortController(); let closed = 0;
    const socket = { opened: Promise.resolve(), closed: Promise.resolve(), readable: new ReadableStream(), writable: new WritableStream(), close() { closed++; return Promise.resolve(); } };
    const result = probeWithConnect(() => { queueMicrotask(() => controller.abort()); return socket; }, { signal: controller.signal, timeoutMs: 1000 });
    await rejects(() => result, 'ABORTED'); check(closed === 1, 'aborted socket not closed');
  });
  await test('transport rejects unknown options and invalid values', async () => {
    const connect = () => { throw new Error('must not connect'); };
    for (const options of [{ nope: true }, null, [], { timeoutMs: 0 }, { timeoutMs: null }, { maxBytes: 5 }, { maxBytes: null }, { signal: {} }, { verifyCertificate: 'yes' }, { verifyCertificate: false, caCertificates: [testRoot] }]) {
      try { await probeWithConnect(connect, options); throw new Error('Expected invalid options to throw'); }
      catch (error) { check(error instanceof TypeError || error instanceof RangeError, `unexpected error ${error}`); }
    }
  });
  for (const stage of ['write', 'read']) await test(`transport deadline covers stalled ${stage}`, async () => {
    let closed = 0, writeStarted = false;
    const socket = { opened: Promise.resolve(), closed: Promise.resolve(), readable: new ReadableStream(),
      writable: new WritableStream({ write() { writeStarted = true; if (stage === 'write') return new Promise(() => {}); } }),
      close() { closed++; return Promise.resolve(); } };
    await rejects(() => probeWithConnect(() => socket, { timeoutMs: 250 }), 'TIMEOUT');
    check(writeStarted && closed === 1, 'deadline did not reach intended transport stage');
    check(!socket.readable.locked && !socket.writable.locked, 'timed out streams remained locked');
  });
  await test('transport wraps synchronous connect errors', async () => {
    await rejects(() => probeWithConnect(() => { throw new Error('connect failed'); }), 'IO');
  });
  for (const behavior of ['reject', 'throw', 'stall']) await test(`transport cleanup handles close ${behavior}`, async () => {
    const fake = await successfulSocket(); let invoked = 0;
    fake.socket.close = () => {
      invoked++;
      if (behavior === 'throw') throw new Error('close failed');
      if (behavior === 'reject') return Promise.reject(new Error('close failed'));
      return new Promise(() => {});
    };
    const result = await probeWithConnect(() => fake.socket, { timeoutMs: 1000 });
    check(result.authenticated === true && invoked === 1, 'cleanup changed successful result');
    check(!fake.socket.readable.locked && !fake.socket.writable.locked, 'cleanup retained stream locks');
  });
  await test('transport consumes rejection of socket.closed', async () => {
    const fake = await successfulSocket();
    Object.defineProperty(fake.socket, 'closed', { get() { return Promise.reject(new Error('closed failed')); } });
    const result = await probeWithConnect(() => fake.socket);
    check(result.configs.length === 10 && fake.closedCount === 1, 'closed rejection interrupted extraction');
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  await test('generic destinations separate connection address, port and SNI', async () => {
    const cases = [
      [{ hostname: 'Example.COM.' }, 'example.com', 443, 'example.com'],
      [{ hostname: 'edge.example', port: 8443, serverName: 'Outer.Example.', alpn: ['h2', 'http/1.1'] }, 'edge.example', 8443, 'outer.example'],
      [{ hostname: '192.0.2.7', serverName: 'public.example' }, '192.0.2.7', 443, 'public.example'],
      [{ hostname: '2001:0DB8::1', port: 9443, serverName: 'public.example' }, '2001:db8::1', 9443, 'public.example'],
      [{ hostname: '[2001:db8::2]', serverName: 'public.example' }, '2001:db8::2', 443, 'public.example'],
    ];
    for (const [options, hostname, port, sni] of cases) {
      const fake = await successfulSocket(); let address;
      const result = await runProbe(value => { address = value; return fake.socket; }, withTrust(options));
      const hello = readClientHello(fake.written);
      check(address.hostname === hostname && address.port === port, 'wrong configured socket address');
      check(hello.serverName === sni && result.serverName === sni, 'SNI was not encoded independently');
      check(result.target === hostname && result.port === port, 'result destination metadata differs');
      check(JSON.stringify(hello.alpn) === JSON.stringify(options.alpn ?? []), 'ClientHello ALPN differs');
      check(result.configs.length === 10 && fake.closedCount === 1, 'generic extraction failed');
    }
  });
  await test('generic destinations reject invalid inputs before connecting', async () => {
    let connections = 0;
    const connect = () => { connections++; throw new Error('must not connect'); };
    const invalid = [undefined, {}, { hostname: '' }, { hostname: 123 },
      { hostname: 'https://example.com' }, { hostname: 'example.com:443' },
      { hostname: '192.0.2.7' }, { hostname: '::1' },
      { hostname: '999.0.0.1', serverName: 'example.com' }, { hostname: '127.0.0.01', serverName: 'example.com' },
      { hostname: '[::1]:443', serverName: 'example.com' },
      ...[0, -1, 65536, 1.5, '443', null].map(port => ({ hostname: 'example.com', port })),
      ...['192.0.2.1', '::1', '', 'https://example.com', '*.example.com'].map(serverName => ({ hostname: 'example.com', serverName })),
      ...[null, 'h2', [''], ['h2', 'h2'], ['x'.repeat(256)], ['\x00'], ['é'], new Array(1),
        Array.from({ length: 50 }, (_, i) => String(i).padEnd(255, 'x'))].map(alpn => ({ hostname: 'example.com', alpn })),
    ];
    for (const options of invalid) {
      try { await runProbe(connect, options); throw new Error('Expected invalid target to throw'); }
      catch (error) { check(error instanceof TypeError || error instanceof RangeError, `Unexpected target error: ${error}`); }
    }
    check(connections === 0, 'invalid input reached socket creation');
  });
  await test('ALPN selection must match an explicitly offered protocol', async () => {
    const selected = extension(16, vector(concat(new Uint8Array([8]), new TextEncoder().encode('http/1.1'))));
    const hello = await createClientHello('service.example', ['h2', 'http/1.1']);
    const flight = await fullFlight(readClientHello(hello.wire), raw, { eeExtensions: concat(selected, extension(0xfe0d, raw)) });
    const parser = new TlsProbe(hello, 65536, { verifyCertificate: true, serverName: 'service.example', trustAnchors: [pemDer(testRoot)] });
    check((await completed(parser, flight.wire)).result.configs.length === 10, 'offered ALPN was rejected');
    for (const protocols of [[], ['h2']]) {
      const client = await createClientHello('service.example', protocols);
      const other = await fullFlight(readClientHello(client.wire), raw, { eeExtensions: concat(selected, extension(0xfe0d, raw)) });
      await rejects(() => new TlsProbe(client, 65536, { verifyCertificate: true, serverName: 'service.example', trustAnchors: [pemDer(testRoot)] }).push(other.wire), 'MALFORMED');
    }
  });
  const certificateResults = await runCertificateTests(certificates);
  passed += certificateResults.passed;
  return { passed, failed: 0, total: passed };
}
