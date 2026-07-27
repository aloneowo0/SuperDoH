export const MAX_DNS_RESPONSE_SIZE = 65535;

export function cancelDnsResponseBody(response) {
  if (!response || !response.body) return;
  void response.body.cancel().catch(function() { return undefined; });
}

export async function readDnsResponseBody(response) {
  const contentLength = response.headers.get('Content-Length');
  if (contentLength && /^\d+$/.test(contentLength.trim()) && Number(contentLength) > MAX_DNS_RESPONSE_SIZE) {
    cancelDnsResponseBody(response);
    throw new RangeError('DNS response exceeds 65535 bytes');
  }

  if (!response.body) return new ArrayBuffer(0);

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = next.value;
      if (total + chunk.byteLength > MAX_DNS_RESPONSE_SIZE) {
        void reader.cancel().catch(function() { return undefined; });
        throw new RangeError('DNS response exceeds 65535 bytes');
      }
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < chunks.length; i++) {
    body.set(chunks[i], offset);
    offset += chunks[i].byteLength;
  }
  return body.buffer;
}
