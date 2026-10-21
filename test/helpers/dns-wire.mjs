import assert from 'node:assert/strict';
export function query(name = 'example.com', type = 1, flags = 0x0130) {
  const labels = name === '.' ? [0] : [...name.replace(/\.$/, '').split('.').flatMap(v => [v.length, ...Buffer.from(v)]), 0];
  return Uint8Array.from([0x42, 0x42, flags >> 8, flags & 255, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, type >> 8, type & 255, 0, 1]);
}

// Independent DNS wire reader, including compression; never derives expectations via dns-wasm.
export function decode(wire) {
  const b = Buffer.from(wire); let offset = 12;
  function name(at) {
    const labels = []; let end;
    for (let steps = 0; steps < b.length; steps++) {
      const size = b[at++];
      if (size === 0) return { value: labels.join('.') || '.', end: end ?? at };
      if ((size & 0xc0) === 0xc0) { end ??= at + 1; at = ((size & 63) << 8) | b[at]; continue; }
      labels.push(b.subarray(at, at + size).toString()); at += size;
    }
    throw new Error('DNS compression loop');
  }
  const questions = [], records = [];
  for (let i = 0; i < b.readUInt16BE(4); i++) {
    const n = name(offset); offset = n.end;
    questions.push({ name: n.value, type: b.readUInt16BE(offset), class: b.readUInt16BE(offset + 2) }); offset += 4;
  }
  for (let section = 0; section < 3; section++) {
    for (let i = 0; i < b.readUInt16BE(6 + section * 2); i++) {
      const n = name(offset); offset = n.end;
      const type = b.readUInt16BE(offset), ttl = b.readUInt32BE(offset + 4), length = b.readUInt16BE(offset + 8);
      records.push({ name: n.value, type, ttl, section, data: [...b.subarray(offset + 10, offset + 10 + length)] }); offset += 10 + length;
    }
  }
  assert.equal(offset, b.length);
  return { id: b.readUInt16BE(0), flags: b.readUInt16BE(2), questions, records };
}

export function nameWire(name) {
  return name === '.' ? [0] : [...name.split('.').flatMap(v => [v.length, ...Buffer.from(v)]), 0];
}
const u16 = n => [n >>> 8 & 255, n & 255];
const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
export function responseWire(wire, { rcode = 0, flags = 0x81b0, records = [{ name: 'example.com', type: 1, ttl: 60, data: [192, 0, 2, 9] }] } = {}) {
  const q = decode(wire);
  const sections = [0, 1, 2].map(section => records.filter(rr => (rr.section ?? 0) === section));
  return Uint8Array.from([
    ...u16(q.id), ...u16(flags & ~15 | rcode), ...u16(q.questions.length), ...sections.flatMap(rows => u16(rows.length)),
    ...q.questions.flatMap(v => [...nameWire(v.name), ...u16(v.type), ...u16(v.class)]),
    ...sections.flatMap(rows => rows.flatMap(v => [...nameWire(v.name), ...u16(v.type), ...u16(v.class ?? 1), ...u32(v.ttl), ...u16(v.data.length), ...v.data])),
  ]);
}
