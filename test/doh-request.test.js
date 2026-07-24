import { describe, expect, it } from 'vitest';
import { parseDohRequest } from '../doh-request.js';
import { query, toBase64Url } from './dns-fixtures.js';

describe('DoH request boundary', () => {
  it('preserves documented name/type GET support with a cryptographic ID', async () => {
    const parsed = await parseDohRequest(new Request('https://doh.test/dns-query?name=Example.COM.&type=AAAA', { headers: { Accept: 'application/dns-json' } }));
    expect(parsed.error).toBeUndefined();
    expect(parsed.queryMeta).toMatchObject({ name: 'example.com', type: 28 });
    expect(parsed.queryMeta.id).toBeGreaterThanOrEqual(0);
    expect(parsed.wantsJson).toBe(true);
  });

  it('rejects ambiguous, malformed, and invalid wire GET requests before forwarding', async () => {
    const valid = toBase64Url(query());
    const ambiguous = await parseDohRequest(new Request('https://doh.test/dns-query?dns=' + valid + '&name=example.com'));
    const malformed = await parseDohRequest(new Request('https://doh.test/dns-query?dns=not+base64'));
    const short = await parseDohRequest(new Request('https://doh.test/dns-query?dns=' + toBase64Url(new Uint8Array([1, 2]).buffer)));
    expect(ambiguous.error.status).toBe(400);
    expect(malformed.error.status).toBe(400);
    expect(short.error.status).toBe(400);
  });

  it('enforces POST media type and structural DNS validation', async () => {
    const badMedia = await parseDohRequest(new Request('https://doh.test/dns-query', { method: 'POST', body: query() }));
    const validPost = await parseDohRequest(new Request('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'Application/DNS-Message; charset=binary' }, body: query('example.com', 1, 0) }));
    const qr = new Uint8Array(query());
    qr[2] = 0x80;
    const invalidQuery = await parseDohRequest(new Request('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: qr }));
    expect(badMedia.error.status).toBe(415);
    expect(validPost.queryMeta.id).toBe(0);
    expect(invalidQuery.error.status).toBe(400);
  });

  it('returns Allow for unsupported DoH methods', async () => {
    const parsed = await parseDohRequest(new Request('https://doh.test/dns-query', { method: 'PUT' }));
    expect(parsed.error).toMatchObject({ status: 405, headers: { Allow: 'GET, POST' } });
  });

  it('rejects oversized POST and decoded GET messages', async () => {
    const oversized = new Uint8Array(65536);
    const post = await parseDohRequest(new Request('https://doh.test/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: oversized }));
    const get = await parseDohRequest(new Request('https://doh.test/dns-query?dns=' + toBase64Url(oversized.buffer)));
    expect(post.error.status).toBe(413);
    expect(get.error.status).toBe(413);
  });
});
