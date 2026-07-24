import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../_worker.js';
import { buildDNS } from '../src/dns-lib.js';
import { query } from './dns-fixtures.js';

afterEach(() => vi.unstubAllGlobals());

describe('worker DoH boundary integration', () => {
  it('returns HTTP client errors with a request ID and never calls an upstream', async () => {
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    const response = await worker.fetch(new Request('https://doh.test/dns-query', { method: 'PUT' }));
    expect(response.status).toBe(405);
    expect(response.headers.get('Allow')).toBe('GET, POST');
    expect(response.headers.get('X-DoH-Request-ID')).toMatch(/^[0-9a-f]{8}$/);
    expect(upstream).not.toHaveBeenCalled();
  });

  it.each([
    ['wrong media type', new Request('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x' }), 415],
    ['short wire body', new Request('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: new Uint8Array([1, 2]) }), 400],
    ['ambiguous GET', new Request('https://doh.test/dns-query?name=example.com&dns=AA'), 400],
  ])('does not forward %s client errors', async (_name, request, status) => {
    const upstream = vi.fn();
    vi.stubGlobal('fetch', upstream);
    const response = await worker.fetch(request);
    expect(response.status).toBe(status);
    expect(response.headers.get('X-DoH-Request-ID')).toMatch(/^[0-9a-f]{8}$/);
    expect(upstream).not.toHaveBeenCalled();
  });

  it('serves compatibility GET DNS JSON through a mocked upstream', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
      const id = new DataView(options.body).getUint16(0);
      return new Response(buildDNS(id, 'example.com', 1, [new Uint8Array([1, 1, 1, 1])], 60));
    }));
    const response = await worker.fetch(new Request('https://doh.test/google/dns-query?name=example.com&type=A', { headers: { Accept: 'application/dns-json' } }));
    expect(response.status).toBe(200);
    expect((await response.json()).Question).toEqual([{ name: 'example.com', type: 1 }]);
  });

  it('filters a single-upstream response whose question does not match the client query', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
      const id = new DataView(options.body).getUint16(0);
      return new Response(buildDNS(id, 'wrong.example', 1, [new Uint8Array([8, 8, 8, 8])], 60));
    }));
    const response = await worker.fetch(new Request('https://doh.test/google/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message' },
      body: query('example.com', 1, 0x4242),
    }));
    const packet = new DataView(await response.arrayBuffer());
    expect(response.status).toBe(200);
    expect(packet.getUint16(0)).toBe(0x4242);
    expect(packet.getUint16(2) & 0x000F).toBe(2);
  });

  it('rejects a wrong QTYPE from a single upstream', async () => {
    const upstream = vi.fn(async (_url, options) => new Response(buildDNS(new DataView(options.body).getUint16(0), 'example.com', 28, [], 60)));
    vi.stubGlobal('fetch', upstream);
    const response = await worker.fetch(new Request('https://doh.test/google/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query() }));
    expect(new DataView(await response.arrayBuffer()).getUint16(2) & 15).toBe(2);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('rejects a bad HTTPS answer before CN ECH processing can fetch a second upstream', async () => {
    const upstream = vi.fn(async (_url, options) => new Response(buildDNS(new DataView(options.body).getUint16(0), 'wrong.example', 65, [], 60)));
    vi.stubGlobal('fetch', upstream);
    const request = new Request('https://doh.test/google/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query('x.com', 65) });
    Object.defineProperty(request, 'cf', { value: { country: 'CN' } });
    const response = await worker.fetch(request);
    expect(new DataView(await response.arrayBuffer()).getUint16(2) & 15).toBe(2);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it.each([['NXDOMAIN', 0x8183], ['NODATA', 0x8180]])('preserves valid %s single-upstream responses', async (_name, flags) => {
    vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
      const body = buildDNS(new DataView(options.body).getUint16(0), 'example.com', 1, [], 60);
      new DataView(body).setUint16(2, flags);
      return new Response(body);
    }));
    const response = await worker.fetch(new Request('https://doh.test/google/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query() }));
    expect(new DataView(await response.arrayBuffer()).getUint16(2) & 15).toBe(flags & 15);
  });
});
