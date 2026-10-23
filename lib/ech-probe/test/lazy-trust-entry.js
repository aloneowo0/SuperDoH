// Test-only bundle entry. The build substitutes a controlled trust snapshot and
// instruments parseDer; neither fixture CAs nor counters enter production code.
import { probeWithConnect } from '../internal/probe.js';
import { check, decode, makeFlight, readClientHello, rejects, verifyClientFinish } from './support.js';

export async function runLazyTrustTests(fixture, trusted) {
  const { certificates, meta } = fixture, rows = [];
  const options = { hostname: 'example.test', verifyCertificate: true };
  const measured = async (name, parses, fn) => {
    const before = globalThis.__lazyTrustParses;
    await fn();
    const actual = globalThis.__lazyTrustParses - before;
    check(actual === parses, `${name}: expected ${parses} full DER parses, got ${actual}`);
    rows.push({ name, parses: actual });
  };
  const socketFor = (flightOptions = {}, alert = false) => {
    let controller, flight, closed = 0;
    const writes = [];
    const socket = {
      opened: Promise.resolve(), closed: Promise.resolve(),
      readable: new ReadableStream({ start(c) { controller = c; } }),
      writable: new WritableStream({ async write(wire) {
        writes.push(wire);
        if (writes.length !== 1) return;
        if (alert) controller.enqueue(new Uint8Array([21, 3, 3, 0, 2, 2, 40]));
        else {
          flight = await makeFlight(readClientHello(wire), decode(meta.base64), { certificates, ...flightOptions });
          controller.enqueue(flight.wire);
        }
        controller.close();
      } }),
      close() { closed++; return Promise.resolve(); },
    };
    return { socket, writes, get flight() { return flight; }, get closed() { return closed; } };
  };
  const run = async (fake, extra = {}) => {
    try { return await probeWithConnect(() => fake.socket, { ...options, ...extra }); }
    finally { check(fake.closed === 1 && !fake.socket.readable.locked && !fake.socket.writable.locked, 'transport cleanup failed'); }
  };
  if (!trusted) {
    await measured('server-supplied same-subject root cannot create trust', 4, async () => {
      const root = decode(certificates.rootPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''));
      await rejects(() => run(socketFor({ chain: [...certificates.chainDerBase64.map(decode), root] })), 'CERTIFICATE');
    });
    return rows;
  }
  await measured('connect failure does not parse default roots', 0, () => rejects(() => probeWithConnect(() => { throw new Error('controlled connect failure'); }, options), 'IO'));
  await measured('early TLS alert does not parse default roots', 0, () => rejects(() => run(socketFor({}, true)), 'TLS_ALERT'));
  await measured('custom malformed CA still fails before connect', 1, async () => {
    let connects = 0;
    try {
      await probeWithConnect(() => { connects++; throw new Error('must not connect'); }, { ...options, caCertificates: [new Uint8Array([0x30, 0])] });
      throw new Error('malformed custom root was accepted');
    } catch (error) { check(error instanceof TypeError || error instanceof RangeError, 'unexpected preflight error: ' + error.message); check(error.message.includes('X.509'), 'wrong preflight rejection: ' + error.message); }
    check(connects === 0, 'invalid custom root reached connect');
  });
  await measured('matching roots backtrack and accept equivalent encoded names', 5, async () => {
    const fake = socketFor(), result = await run(fake);
    check(result.authenticated === true && result.handshakeComplete === true && result.configs.length === 10, 'verified result differs');
    await verifyClientFinish(readClientHello(fake.writes[0]), fake.flight, fake.writes.slice(1));
  });
  await measured('subsequent handshake reuses only private matching root records', 3, async () => {
    check((await run(socketFor())).authenticated === true, 'cached root did not authenticate');
  });
  await measured('hostname verification remains required', 2, () => rejects(() => run(socketFor(), { serverName: 'wrong.example' }), 'HOSTNAME'));
  await measured('CertificateVerify tampering still fails closed', 3, () => rejects(() => run(socketFor({ signature: new Uint8Array([0x30, 0]) })), 'CERTIFICATE_VERIFY'));
  await measured('Finished tampering still fails closed', 3, () => rejects(() => run(socketFor({ finished: new Uint8Array(32) })), 'FINISHED'));
  await measured('missing intermediate cannot be filled by unrelated roots', 1, () => rejects(() => run(socketFor({ chain: [decode(certificates.leafDerBase64)] })), 'CERTIFICATE'));
  for (const [name, chain] of Object.entries(certificates.negativeChains)) {
    await rejects(() => run(socketFor({ chain: chain.chainDerBase64.map(decode) })), 'CERTIFICATE');
    rows.push({ name: `negative chain ${name}`, rejected: true });
  }
  return rows;
}
export default {
  async fetch(request) {
    const { fixture, trusted } = await request.json();
    try { return Response.json(await runLazyTrustTests(fixture, trusted)); }
    catch (error) { return Response.json({ error: error.message, stack: error.stack }, { status: 500 }); }
  },
};
