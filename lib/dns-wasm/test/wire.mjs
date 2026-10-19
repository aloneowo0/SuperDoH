// Independent, test-only fixture writer. Production wire handling is Rust/domain.
export const u16 = n => [n >>> 8, n & 255];
export const u32 = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
export const name = s => s === '.' ? [0] : s.split('.').flatMap(s => [s.length, ...Buffer.from(s)]).concat(0);
export function record(rtype, data, owner = [0xc0, 12], cls = 1, ttl = 60) {
  return [...owner, ...u16(rtype), ...u16(cls), ...u32(ttl), ...u16(data.length), ...data];
}
export function wire({ flags = 0x8180, id = 0x4242, qname = 'example.com', qtype = 1, answers = [], authority = [], additional = [] } = {}) {
  return [...u16(id), ...u16(flags), 0, 1, ...u16(answers.length), ...u16(authority.length), ...u16(additional.length), ...name(qname), ...u16(qtype), 0, 1, ...answers.flat(), ...authority.flat(), ...additional.flat()];
}
