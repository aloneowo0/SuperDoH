import { describe, expect, it } from 'vitest';
import { readDnsResponseBody } from '../src/dns-response.js';

describe('capped upstream DNS response reader', () => {
  it('accepts a response exactly at the DNS message limit', async () => {
    const body = new Uint8Array(65535);
    await expect(readDnsResponseBody(new Response(body))).resolves.toHaveProperty('byteLength', 65535);
  });

  it('rejects declared oversized bodies without reading their stream', async () => {
    let getReaderCalled = false;
    let cancelled = false;
    const response = {
      headers: new Headers({ 'Content-Length': '65536' }),
      body: {
        cancel() {
          cancelled = true;
          return Promise.resolve();
        },
        getReader() {
          getReaderCalled = true;
          throw new Error('body should not be read');
        },
      },
    };
    await expect(readDnsResponseBody(response)).rejects.toThrow('DNS response exceeds 65535 bytes');
    expect(getReaderCalled).toBe(false);
    expect(cancelled).toBe(true);
  });

  it('reports the size error even when body cancellation rejects', async () => {
    const response = {
      headers: new Headers({ 'Content-Length': '65536' }),
      body: {
        cancel() { return Promise.reject(new Error('cancel failed')); },
      },
    };
    await expect(readDnsResponseBody(response)).rejects.toThrow('DNS response exceeds 65535 bytes');
  });

  it('does not wait for a stalled body cancellation', async () => {
    const response = {
      headers: new Headers({ 'Content-Length': '65536' }),
      body: {
        cancel() { return new Promise(function() {}); },
      },
    };
    await expect(Promise.race([
      readDnsResponseBody(response),
      new Promise(function(_resolve, reject) { setTimeout(function() { reject(new Error('cancel stalled')); }, 50); }),
    ])).rejects.toThrow('DNS response exceeds 65535 bytes');
  });

  it('cancels chunked bodies that exceed the cap while streaming', async () => {
    let cancelled = false;
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(65535));
        controller.enqueue(new Uint8Array([0]));
      },
      cancel() {
        cancelled = true;
      },
    });
    await expect(readDnsResponseBody(new Response(stream))).rejects.toThrow('DNS response exceeds 65535 bytes');
    expect(cancelled).toBe(true);
  });
});
