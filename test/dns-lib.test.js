import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildDNS, buildQueryWireId, encodeDnsName, resolveDNSWire, resolveDNSWireAll, resolveDNSWireForeign, setRuntimeUpstreams, validateDnsQuery, validateDnsResponse } from '../src/dns-lib.js';
import { query } from './dns-fixtures.js';

function mockCtx(overrides = {}) {
  return { requestId: 'test0000', qname: null, qtype: null, fallbacks: [], ...overrides };
}

afterEach(() => {
  setRuntimeUpstreams(null, null);
  vi.unstubAllGlobals();
});

describe('DNS wire helpers', () => {
  it('rejects invalid textual names and qtypes without truncating labels', () => {
    expect(() => encodeDnsName('a..example')).toThrow();
    expect(() => encodeDnsName('a'.repeat(64) + '.example')).toThrow();
    expect(() => buildQueryWireId('example.com', 0, 1)).toThrow();
    expect(() => buildQueryWireId('example.com', 1, 0x10000)).toThrow();
    expect(() => buildDNS(1, 'example.com', 70000, [], 60)).toThrow();
  });

  it('supports service labels while enforcing DNS wire limits', () => {
    expect(encodeDnsName('_service._tcp.example.com')).toBeInstanceOf(Uint8Array);
    expect(encodeDnsName('a'.repeat(63) + '.example')).toBeInstanceOf(Uint8Array);
    expect(() => encodeDnsName('a'.repeat(64) + '.example')).toThrow();
    expect(() => encodeDnsName('a..example')).toThrow();
    expect(() => encodeDnsName(Array(128).fill('a').join('.'))).toThrow();
    expect(new DataView(buildQueryWireId('example.com', 1, 0xBEEF)).getUint16(0)).toBe(0xBEEF);
  });

  it('accepts a legal EDNS additional record while rejecting trailing data', () => {
    const base = new Uint8Array(query());
    const withOpt = new Uint8Array(base.length + 11);
    withOpt.set(base);
    new DataView(withOpt.buffer).setUint16(10, 1);
    withOpt[base.length] = 0;
    new DataView(withOpt.buffer).setUint16(base.length + 1, 41);
    new DataView(withOpt.buffer).setUint16(base.length + 3, 1232);
    expect(validateDnsQuery(withOpt.buffer)).toMatchObject({ name: 'example.com', type: 1 });
    const trailing = new Uint8Array(withOpt.length + 1);
    trailing.set(withOpt);
    expect(() => validateDnsQuery(trailing.buffer)).toThrow();
  });

  it('rejects query packets carrying answer or authority sections', () => {
    const base = new Uint8Array(query());
    const withAnswer = new Uint8Array(base.length + 16);
    withAnswer.set(base);
    const view = new DataView(withAnswer.buffer);
    view.setUint16(6, 1);
    let offset = base.length;
    view.setUint16(offset, 0xC00C); offset += 2;
    view.setUint16(offset, 1); offset += 2;
    view.setUint16(offset, 1); offset += 2;
    view.setUint32(offset, 60); offset += 4;
    view.setUint16(offset, 4); offset += 2;
    withAnswer.set([1, 2, 3, 4], offset);
    expect(() => validateDnsQuery(withAnswer.buffer)).toThrow();

    const withAuthority = withAnswer.slice();
    const authorityView = new DataView(withAuthority.buffer);
    authorityView.setUint16(6, 0);
    authorityView.setUint16(8, 1);
    expect(() => validateDnsQuery(withAuthority.buffer)).toThrow();
  });

  it.each([
    ['missing QR flag', function(body) { new DataView(body).setUint16(2, 0x0180); }],
    ['non-standard opcode', function(body) { new DataView(body).setUint16(2, 0x8980); }],
    ['multiple questions', function(body) { new DataView(body).setUint16(4, 2); }],
    ['non-IN question class', function(body) {
      const bytes = new Uint8Array(body);
      let offset = 12;
      while (bytes[offset] !== 0) offset += bytes[offset] + 1;
      new DataView(body).setUint16(offset + 3, 3);
    }],
  ])('rejects responses with %s', (_name, mutate) => {
    const response = buildDNS(0x1234, 'example.com', 1, [new Uint8Array([1, 1, 1, 1])], 60);
    mutate(response);
    expect(validateDnsResponse(response, 0x1234, 'example.com', 1).classification).toBe('invalid');
  });

  it('rejects mismatched query identity in internal resolver paths', async () => {
    setRuntimeUpstreams({ test: { url: 'https://resolver.test', ecs: false } }, ['test']);
    vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
      const id = new DataView(options.body).getUint16(0);
      return new Response(buildDNS(id, 'wrong.example', 1, [new Uint8Array([1, 1, 1, 1])], 60));
    }));

    const ctx = mockCtx();
    expect(await resolveDNSWire('example.com', 1, ctx)).toBeNull();
    expect(await resolveDNSWireForeign(query('example.com', 1, 0x1234), undefined, ctx)).toBeNull();
    expect(await resolveDNSWireAll('example.com', 1, ctx)).toEqual([]);
  });

  it('binds root queries to the root response question', () => {
    const response = buildDNS(0x1234, 'wrong.example', 1, [new Uint8Array([1, 1, 1, 1])], 60);
    expect(validateDnsResponse(response, 0x1234, '', 1).classification).toBe('invalid');
  });
});
