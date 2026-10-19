export class EchProbeError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'EchProbeError';
    this.code = code;
  }
}

export function fail(code, message) {
  throw new EchProbeError(code, message);
}

export function bytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (!Number.isInteger(value[i]) || value[i] < 0 || value[i] > 255) throw new TypeError('Invalid byte array');
    }
    return Uint8Array.from(value);
  }
  throw new TypeError('Expected ArrayBuffer, byte view, or array of bytes');
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

export function u16(n) { return new Uint8Array([n >>> 8, n & 255]); }
export function u24(n) { return new Uint8Array([n >>> 16, (n >>> 8) & 255, n & 255]); }
export function vector(data) { return concat(u16(data.length), data); }
export function extension(type, data) { return concat(u16(type), vector(data)); }
export function handshake(type, data) {
  return concat(new Uint8Array([type, data.length >>> 16, (data.length >>> 8) & 255, data.length & 255]), data);
}
export function record(type, data) { return concat(new Uint8Array([type, 3, 3]), vector(data)); }
export function random(n) { return crypto.getRandomValues(new Uint8Array(n)); }
export function equal(a, b) { return a.length === b.length && a.every((v, i) => v === b[i]); }

export class Cursor {
  constructor(data) { this.data = data; this.offset = 0; }
  get remaining() { return this.data.length - this.offset; }
  take(n) {
    if (!Number.isInteger(n) || n < 0 || n > this.remaining) fail('MALFORMED', 'Truncated protocol field');
    const out = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
  uint8() { return this.take(1)[0]; }
  uint16() { const b = this.take(2); return (b[0] << 8) | b[1]; }
  uint24() { const b = this.take(3); return (b[0] << 16) | (b[1] << 8) | b[2]; }
  vec8() { return this.take(this.uint8()); }
  vec16() { return this.take(this.uint16()); }
  end() { if (this.remaining !== 0) fail('MALFORMED', 'Unexpected trailing protocol bytes'); }
}

export function extensions(data) {
  const c = new Cursor(data), out = new Map();
  while (c.remaining) {
    const type = c.uint16(), value = c.vec16();
    if (out.has(type)) fail('MALFORMED', 'Duplicate extension');
    out.set(type, value);
  }
  return out;
}
