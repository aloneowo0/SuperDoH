import { describe, expect, it } from 'vitest';
import { buildDNS, buildQueryWireId, encodeDnsName, validateDnsQuery } from '../src/dns-lib.js';
import { query } from './dns-fixtures.js';

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
});
