/** Strict IP parsing: no ports, zones, octal IPv4, or inferred attributes. @param {unknown} value */
export function ip(value) {
  if (typeof value !== 'string' || value.length > 45) throw new Error();
  let text = value;
  if (text.includes(':') && text.includes('.')) {
    const at = text.lastIndexOf(':');
    const v4 = ip(text.slice(at + 1));
    if (v4.family !== 32) throw new Error();
    text = text.slice(0, at + 1) + (v4.bits >> 16n).toString(16) + ':' + (v4.bits & 65535n).toString(16);
  }
  if (!text.includes(':')) {
    const parts = text.split('.');
    if (parts.length !== 4 || parts.some(v => !/^(0|[1-9][0-9]{0,2})$/.test(v) || Number(v) > 255)) throw new Error();
    const bits = parts.reduce((n, v) => (n << 8n) | BigInt(v), 0n);
    return { family: 32, bits, key: '32:' + bits.toString(16) };
  }
  const halves = text.split('::');
  if (halves.length > 2) throw new Error();
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const count = left.length + right.length;
  if (halves.length === 1 ? count !== 8 : count >= 8) throw new Error();
  if ([...left, ...right].some(v => !/^[0-9a-fA-F]{1,4}$/.test(v))) throw new Error();
  const parts = [...left, ...Array(8 - count).fill('0'), ...right];
  const bits = parts.reduce((n, v) => (n << 16n) | BigInt('0x' + v), 0n);
  return { family: 128, bits, key: '128:' + bits.toString(16) };
}
/** @param {unknown} value */
export function cidr(value) {
  if (typeof value !== 'string') throw new Error();
  const parts = value.split('/');
  if (parts.length !== 2 || !/^(0|[1-9][0-9]{0,2})$/.test(parts[1])) throw new Error();
  const address = ip(parts[0]), prefix = Number(parts[1]);
  if (prefix > address.family) throw new Error();
  const shift = BigInt(address.family - prefix);
  return { ...address, shift, network: address.bits >> shift };
}
