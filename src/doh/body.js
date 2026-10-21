import { RuleError } from '../rules/errors.js';

/** @param {ReadableStreamDefaultReader<Uint8Array>} reader */
function cancelReader(reader) {
  try {
    // Do not wait for cancellation: an underlying source may never settle cancel().
    void reader.cancel().catch(() => {});
  } catch { /* Cancellation is best-effort. */ }
}

/** @param {unknown} reason */
function abortError(reason) {
  return reason instanceof Error ? reason : new RuleError('REQUEST_CANCELLED', 'The request was cancelled.');
}

/**
 * Reads a stream into bounded memory while remaining promptly cancellable.
 * @param {ReadableStream<Uint8Array> | null} body
 * @param {number} maximum
 * @param {AbortSignal} signal
 * @returns {Promise<Uint8Array>}
 */
export async function readBody(body, maximum, signal) {
  if (body === null) return new Uint8Array();
  const reader = body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let total = 0;
  /** @type {Promise<ReadableStreamReadResult<Uint8Array>> | undefined} */
  let pendingRead;
  let lockReleased = false;
  const releaseLock = () => {
    if (lockReleased) return;
    lockReleased = true;
    try { reader.releaseLock(); } catch { /* Cancellation may still be resolving the read. */ }
  };
  try {
    while (true) {
      if (signal.aborted) throw abortError(signal.reason);
      /** @type {(() => void) | undefined} */
      let onAbort;
      const cancelled = new Promise((_, reject) => {
        onAbort = () => reject(abortError(signal.reason));
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) onAbort();
      });
      let result;
      try {
        pendingRead = reader.read();
        result = await Promise.race([pendingRead, cancelled]);
      } finally {
        if (onAbort) signal.removeEventListener('abort', onAbort);
      }
      pendingRead = undefined;
      if (signal.aborted) throw abortError(signal.reason);
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maximum) {
        cancelReader(reader);
        throw new RuleError('RESOURCE_LIMIT', 'Configured resource limit exceeded.');
      }
      chunks.push(result.value);
    }
    const output = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return output;
  } catch (error) {
    if (signal.aborted) {
      cancelReader(reader);
      if (pendingRead) {
        const read = pendingRead;
        void read.then(releaseLock, releaseLock);
      }
    }
    throw error;
  } finally {
    if (!pendingRead) releaseLock();
  }
}
