import { EchProbeError } from './bytes.js';
import { createClientHello, TlsProbe } from './tls.js';
import { prepareTrustAnchors } from './certificate.js';

import { target } from './target.js';

function integer(value, name, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) throw new RangeError(`${name} must be an integer in ${min}..${max}`);
  return value;
}

// Separate transport injection is internal and used by the offline test suite only.
export async function probeWithConnect(connect, options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Expected an options object');
  for (const key of Object.keys(options)) if (!['hostname', 'port', 'serverName', 'alpn', 'timeoutMs', 'maxBytes', 'signal', 'verifyCertificate', 'caCertificates'].includes(key)) throw new TypeError(`Unknown probe option: ${key}`);
  const destination = target(options);
  const verifyCertificate = options.verifyCertificate === undefined ? false : options.verifyCertificate;
  if (typeof verifyCertificate !== 'boolean') throw new TypeError('verifyCertificate must be a boolean');
  if (!verifyCertificate && options.caCertificates !== undefined) throw new TypeError('caCertificates cannot be used when verifyCertificate is false');
  if (options.caCertificates !== undefined && (!Array.isArray(options.caCertificates) || !options.caCertificates.length)) {
    throw new TypeError('caCertificates must be a nonempty array of PEM/DER certificates');
  }
  const timeoutMs = integer(options.timeoutMs === undefined ? 8000 : options.timeoutMs, 'timeoutMs', 1, 60000);
  const maxBytes = integer(options.maxBytes === undefined ? 65536 : options.maxBytes, 'maxBytes', 1024, 1048576);
  const signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('signal must be an AbortSignal');
  if (signal?.aborted) throw new EchProbeError('ABORTED', 'ECH probe aborted');
  const started = Date.now();
  let socket, reader, writer, parser, rejectStop;
  const stopped = new Promise((_, reject) => { rejectStop = reject; });
  const abort = () => rejectStop(new EchProbeError('ABORTED', 'ECH probe aborted'));
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => rejectStop(new EchProbeError('TIMEOUT', 'ECH probe timed out')), timeoutMs);
  const wait = operation => Promise.race([operation, stopped]);
  try {
    const trustAnchors = verifyCertificate ? await wait(Promise.resolve().then(() => prepareTrustAnchors(options.caCertificates))) : [];
    const hello = await wait(createClientHello(destination.serverName, destination.alpn).catch(cause => {
      throw new EchProbeError('CRYPTO', 'Failed to create TLS ClientHello', { cause });
    }));
    socket = connect({ hostname: destination.hostname, port: destination.port }, { secureTransport: 'off', allowHalfOpen: false });
    // Observe both promises; Workers may reject closed as well as opened/read/write.
    void socket.closed.catch(() => {});
    await wait(socket.opened);
    writer = socket.writable.getWriter();
    await wait(writer.write(hello.wire));
    reader = socket.readable.getReader();
    parser = new TlsProbe(hello, maxBytes, { verifyCertificate, serverName: destination.serverName, trustAnchors });
    while (true) {
      const part = await wait(reader.read());
      if (part.done) parser.finish();
      const state = await wait(parser.push(part.value));
      if (state?.ready) {
        const completed = await wait(parser.finishHandshake());
        for (const record of completed.records) await wait(writer.write(record));
        if (!completed.result) throw new EchProbeError('NO_RETRY_CONFIG', 'Server did not supply supported ECH retry configs');
        return { ...completed.result, authenticated: completed.authenticated, handshakeComplete: true,
          target: destination.hostname, port: destination.port, serverName: destination.serverName,
          elapsedMs: Date.now() - started, bytesReceived: parser.total };
      }
    }
  } catch (cause) {
    if (cause instanceof EchProbeError || cause instanceof TypeError || cause instanceof RangeError) throw cause;
    throw new EchProbeError('IO', 'ECH probe failed', { cause });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    if (socket) {
      // Start forced closure immediately; do not let a stalled close extend the deadline.
      try { void socket.close().catch(() => {}); } catch {}
    }
    try { reader?.releaseLock(); } catch {}
    try { writer?.releaseLock(); } catch {}
    parser?.dispose();
  }
}
