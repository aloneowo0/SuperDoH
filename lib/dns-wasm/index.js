import wasmModule from './dns_bindgen_bg.wasm';
import * as wasm from './dns_bindgen.js';

wasm.initSync({ module: wasmModule });

export const FLAGS = Object.freeze({ QR: 0x8000, AA: 0x0400, TC: 0x0200, RD: 0x0100, RA: 0x0080, AD: 0x0020, CD: 0x0010 });
export const TYPES = Object.freeze({ A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DNAME: 39, OPT: 41, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52, SVCB: 64, HTTPS: 65, TSIG: 250, ANY: 255, CAA: 257 });

function integer(value, max, label) {
  if (!Number.isInteger(value) || value < 0 || value > max) throw new RangeError(`${label} must be an integer in 0..${max}`);
  return value;
}
function u16(value, label) { return integer(value, 65535, label); }
function bytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) { value.forEach(v => integer(v, 255, 'byte')); return Uint8Array.from(value); }
  throw new TypeError('expected an ArrayBuffer, byte view or byte array');
}
function json(value) {
  return JSON.stringify(value, (_key, v) => v instanceof ArrayBuffer || ArrayBuffer.isView(v) ? Array.from(bytes(v)) : v);
}
function invoke(fn, ...args) {
  try { return fn(...args); } catch (error) { throw error instanceof Error ? error : new Error(String(error)); }
}
function read(fn, ...args) { return JSON.parse(invoke(fn, ...args)); }

export function createMessage(options = {}) {
  return { id: 0, flags: 0, questions: [], answers: [], authority: [], additional: [], ...options };
}
function withHeaderFields(message) {
  return { ...message, is_response: !!(message.flags & FLAGS.QR), opcode: (message.flags >>> 11) & 15, rcode: message.flags & 15, truncated: !!(message.flags & FLAGS.TC) };
}
export function parseMessage(packet) {
  return withHeaderFields(read(wasm.parseMessageJson, bytes(packet)));
}
export function normalizeMessage(message, options = {}) {
  return withHeaderFields(read(wasm.normalizeMessageJson, json(message), json(options)));
}
export function encodeResponse(message, query, maximum, options = { strip_message_authentication: true }) {
  integer(maximum, 0xffffffff, 'maximum response bytes');
  const input = json(message), original = bytes(query), encodedOptions = json(options);
  try { return wasm.encodeResponseJson(input, original, maximum, encodedOptions); }
  catch (error) {
    if (error === null) return null;
    throw error instanceof Error ? error : new Error(String(error));
  }
}
export function encodeMessage(message, options = {}) {
  return invoke(wasm.encodeMessageJson, json(message), json(options));
}
export function buildQuery(name, rtype = 1, id = 0, options) {
  if (typeof name !== 'string') throw new TypeError('name must be a string');
  u16(rtype, 'rtype'); u16(id, 'id');
  if (options === undefined) return invoke(wasm.buildQuery, name, rtype, id);
  return encodeMessage(createMessage({ id, flags: options.flags ?? FLAGS.RD, questions: [{ name, rtype, class: options.class ?? 1 }] }));
}
export function buildResponse(query, options = {}) {
  const q = query && Array.isArray(query.questions) ? query : parseMessage(query);
  const message = createMessage({ id: q.id, flags: (q.flags & 0x7910) | FLAGS.QR, questions: q.questions.map(v => ({ ...v })), ...options });
  delete message.rcode;
  if (options.rcode !== undefined) setRcode(message, options.rcode, options.udp_payload_size);
  delete message.udp_payload_size;
  return encodeMessage(message);
}
export function decodeRdata(rtype, packet) { return read(wasm.decodeRdataJson, u16(rtype, 'rtype'), bytes(packet)); }
export function encodeRdata(rtype, value) { return invoke(wasm.encodeRdataJson, u16(rtype, 'rtype'), json(value)); }
export function encodeEcs(value) { return invoke(wasm.encodeEcsJson, json(value)); }
export function decodeEcs(value) { return read(wasm.decodeEcsJson, bytes(value)); }
export function encodeEde(value) { return invoke(wasm.encodeEdeJson, json(value)); }
export function decodeEde(value) { return read(wasm.decodeEdeJson, bytes(value)); }
export function encodeSvcParam(key, value) { return invoke(wasm.encodeSvcParamJson, u16(key, 'key'), json(value)); }
export function decodeSvcParam(key, value) { return read(wasm.decodeSvcParamJson, u16(key, 'key'), bytes(value)); }
export function validateMessage(packet) { return read(wasm.validateMessageJson, bytes(packet)); }
export function matchResponse(response, query) { return read(wasm.matchResponseJson, bytes(response), bytes(query)); }
export function extractIPs(packet) { return read(wasm.extractIpsJson, bytes(packet)); }
export function toDnsJson(packet) { return read(wasm.toDnsJson, bytes(packet)); }
export function typeCode(name) {
  if (typeof name !== 'string') throw new TypeError('type name must be a string');
  return invoke(wasm.typeCode, name.toUpperCase());
}
export function typeName(code) { return invoke(wasm.typeName, u16(code, 'rtype')); }

function optRecord(message) {
  const records = message.additional.filter(r => r.rtype === TYPES.OPT);
  if (records.length > 1) throw new Error('multiple OPT records');
  if (records[0] && !records[0].rdata?.Opt) throw new Error('expected parsed Opt RDATA; decode raw RDATA first');
  return records[0];
}
export function getEdns(message) {
  const rr = optRecord(message);
  return rr ? { udp_payload_size: rr.class, extended_rcode: rr.ttl >>> 24, version: (rr.ttl >>> 16) & 255, flags: rr.ttl & 65535, options: rr.rdata.Opt.options } : null;
}
export function setEdns(message, value) {
  const old = optRecord(message);
  if (!old && value.udp_payload_size === undefined) throw new Error('udp_payload_size is required when creating OPT');
  const current = getEdns(message) ?? { extended_rcode: 0, version: 0, flags: 0, options: [] };
  const payload = u16(value.udp_payload_size ?? old?.class, 'udp_payload_size');
  const ext = integer(value.extended_rcode ?? current.extended_rcode, 255, 'extended_rcode');
  const version = integer(value.version ?? current.version, 255, 'version');
  const flags = u16(value.flags ?? current.flags, 'EDNS flags');
  const options = value.options === undefined ? current.options : value.options.map(v => ({ code: u16(v.code, 'option code'), data: Array.from(bytes(v.data)) }));
  const rr = { name: '.', rtype: TYPES.OPT, class: payload, ttl: ((ext << 24) | (version << 16) | flags) >>> 0, rdata: { Opt: { options } } };
  if (old) message.additional[message.additional.indexOf(old)] = rr;
  else message.additional.push(rr);
  return message;
}
export function removeEdns(message) { message.additional = message.additional.filter(r => r.rtype !== TYPES.OPT); return message; }
export function setEdnsOption(message, code, data) {
  const rr = optRecord(message);
  if (!rr) throw new Error('create OPT explicitly with setEdns first');
  u16(code, 'option code');
  const option = { code, data: Array.from(bytes(data)) };
  rr.rdata.Opt.options = [...rr.rdata.Opt.options.filter(v => v.code !== code), option];
  return message;
}
export function removeEdnsOption(message, code) {
  u16(code, 'option code');
  const rr = optRecord(message);
  if (rr) rr.rdata.Opt.options = rr.rdata.Opt.options.filter(v => v.code !== code);
  return message;
}
export function setEcs(message, value) { return setEdnsOption(message, 8, encodeEcs(value)); }
export function getEcs(message) { const item = getEdns(message)?.options.find(v => v.code === 8); return item ? decodeEcs(item.data) : null; }
export function getRcode(message) { return (message.flags & 15) | ((getEdns(message)?.extended_rcode ?? 0) << 4); }
export function setRcode(message, rcode, udpPayloadSize) {
  integer(rcode, 4095, 'rcode');
  u16(message.flags, 'flags');
  if (rcode > 15 || optRecord(message)) setEdns(message, { extended_rcode: rcode >>> 4, ...(udpPayloadSize !== undefined ? { udp_payload_size: udpPayloadSize } : {}) });
  message.flags = (message.flags & ~15) | (rcode & 15);
  return message;
}

function serviceBinding(record) {
  const value = record.rtype === TYPES.SVCB ? record.rdata.Svcb : record.rtype === TYPES.HTTPS ? record.rdata.Https : null;
  if (!value) throw new TypeError('expected structured SVCB or HTTPS RDATA');
  return value;
}
export function getSvcParam(record, key) {
  u16(key, 'key');
  const p = serviceBinding(record).params.find(v => v.key === key);
  return p ? decodeSvcParam(key, p.data) : undefined;
}
export function setSvcParam(record, key, value) {
  const data = Array.from(encodeSvcParam(key, value));
  const svc = serviceBinding(record);
  svc.params = svc.params.filter(v => v.key !== key);
  svc.params.push({ key, data }); svc.params.sort((a, b) => a.key - b.key);
  return record;
}
export function removeSvcParam(record, key) {
  u16(key, 'key');
  const svc = serviceBinding(record);
  svc.params = svc.params.filter(v => v.key !== key);
  return record;
}
