import { afterEach, describe, expect, it, vi } from 'vitest';
import { __resetCFEchCacheForTests, fetchCFEch, injectECH } from '../src/ech.js';
import { buildDNS, parseDns } from '../src/dns-lib.js';

afterEach(() => {
  __resetCFEchCacheForTests();
  vi.unstubAllGlobals();
});

describe('ECH upstream selection and response flags', () => {
  it('tries configured upstreams sequentially and accepts only a validated HTTPS response', async () => {
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, options) => {
      calls.push(url);
      const request = options.body;
      const id = new DataView(request).getUint16(0);
      if (calls.length === 1) return new Response(buildDNS(id + 1, 'cloudflare-ech.com', 65, [new Uint8Array([0, 1, 0, 0, 0])], 60));
      const rdata = new Uint8Array([0, 1, 0, 0, 5, 0, 3, 1, 2, 3]);
      return new Response(buildDNS(id, 'cloudflare-ech.com', 65, [rdata], 60));
    }));
    const result = await fetchCFEch(null, null);
    expect(calls).toHaveLength(2);
    expect(result.params.some((param) => param.key === 'ech')).toBe(true);
  });

  it('clears TC but preserves AD when rebuilding HTTPS responses', async () => {
    const original = buildDNS(0x1234, 'example.com', 65, [new Uint8Array([0, 1, 0])], 60);
    new DataView(original).setUint16(2, 0x82A0);
    const result = await injectECH(original, 'example.com', 'CF', { params: [{ key: 'ech', val: 'AQID' }] });
    const flags = parseDns(await result.body.arrayBuffer()).header.flags;
    expect(flags & 0x0200).toBe(0);
    expect(flags & 0x0020).toBe(0x0020);
  });
});
