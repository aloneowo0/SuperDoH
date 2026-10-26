import { connect } from 'cloudflare:sockets';
import { RuleError } from '../rules/errors.js';

/**
 * One connection, one framed query and one response; never wait for peer EOF.
 * @param {Extract<import('../rules/types.js').ResolvedUpstream, { transport: 'tcp' }>} target
 * @param {Uint8Array} query
 * @param {number} maximum
 * @param {ReturnType<typeof import('./budget.js').createBudget>} budget
 */
export async function queryStream(target, query, maximum, budget) {
  budget.check();
  const socket = connect({ hostname: target.address, port: target.port }, { secureTransport: 'off', allowHalfOpen: false });
  socket.closed.catch(() => {});
  socket.opened.catch(() => {});
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    try { void socket.close().catch(() => {}); } catch { /* Best-effort cleanup. */ }
  };
  budget.signal.addEventListener('abort', close, { once: true });
  /** @type {WritableStreamDefaultWriter<Uint8Array> | undefined} */
  let writer;
  /** @type {ReadableStreamDefaultReader<Uint8Array> | undefined} */
  let reader;
  try {
    const outputWriter = writer = socket.writable.getWriter();
    const inputReader = reader = socket.readable.getReader();
    await budget.run(() => socket.opened);
    const request = new Uint8Array(query.byteLength + 2);
    request[0] = query.byteLength >>> 8;
    request[1] = query.byteLength & 255;
    request.set(query, 2);
    await budget.run(() => outputWriter.write(request));
    const prefix = new Uint8Array(2);
    let prefixBytes = 0, received = 0;
    /** @type {Uint8Array | undefined} */
    let output;
    while (true) {
      const { value, done } = await budget.run(() => inputReader.read());
      if (done) throw new RuleError('UPSTREAM_INVALID', 'Incomplete DNS TCP response.');
      let offset = 0;
      while (prefixBytes < 2 && offset < value.byteLength) prefix[prefixBytes++] = value[offset++];
      if (prefixBytes < 2) continue;
      if (!output) {
        const length = prefix[0] * 256 + prefix[1];
        if (length < 12) throw new RuleError('UPSTREAM_INVALID', 'Invalid DNS TCP frame length.');
        if (length > maximum) throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
        output = new Uint8Array(length);
      }
      const count = value.byteLength - offset;
      if (count > output.byteLength - received) throw new RuleError('UPSTREAM_INVALID', 'Unexpected DNS TCP data.');
      output.set(value.subarray(offset), received);
      received += count;
      if (received === output.byteLength) { budget.check(); return output; }
    }
  } finally {
    budget.signal.removeEventListener('abort', close);
    close();
    try { reader?.releaseLock(); } catch { /* A cancelled read may still be settling. */ }
    try { writer?.releaseLock(); } catch { /* A cancelled write may still be settling. */ }
  }
}
