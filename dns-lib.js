/** DNS utility library — wire format, response building, internal resolution */

import { UPSTREAMS, FOREIGN_UPSTREAMS, HARD_TIMEOUT_MS, PREFERRED_TIMEOUT_MS } from './config.js';
import { logEvent } from './logger.js';

export const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };
const DNS_HEADER_LEN = 12;
const TYPE_OPT = 41;
const MAX_NAME_JUMPS = 128;

// ── Low-level byte helpers ──────────────────────────────────────────

export function toBytes(body) {
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  throw new Error('body must be ArrayBuffer');
}

export function requireBytes(view, offset, len) {
  if (offset < 0 || len < 0 || offset + len > view.byteLength) throw new Error('DNS packet out of bounds');
}

// ── DNS name encoding/decoding ──────────────────────────────────────

export function encodeDnsName(domain) {
  const parts = domain.split('.');
  const buf = new Uint8Array(domain.length + 2);
  let offset = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    buf[offset++] = part.length;
    for (let j = 0; j < part.length; j++) buf[offset++] = part.charCodeAt(j);
  }
  buf[offset++] = 0;
  return buf.slice(0, offset);
}

// ── DNS packet parsing (canonical: edns.js version with cycle detection) ──

export function skipName(view, start) {
  let offset = start;
  let end = start;
  let jumped = false;
  let jumps = 0;
  const seen = [];

  for (;;) {
    requireBytes(view, offset, 1);
    const len = view.getUint8(offset);

    if ((len & 0xC0) === 0xC0) {
      requireBytes(view, offset, 2);
      const pointer = ((len & 0x3F) << 8) | view.getUint8(offset + 1);
      if (pointer >= view.byteLength || seen[pointer]) throw new Error('bad DNS compression pointer');
      if (!jumped) end = offset + 2;
      seen[pointer] = true;
      offset = pointer;
      jumped = true;
      if (++jumps > MAX_NAME_JUMPS) throw new Error('DNS compression loop');
      continue;
    }

    if ((len & 0xC0) !== 0) throw new Error('unsupported DNS label type');
    if (len === 0) return jumped ? end : offset + 1;

    offset += 1;
    requireBytes(view, offset, len);
    if (!jumped) end = offset + len;
    offset += len;
  }
}

export function readRecord(view, offset) {
  const headerOffset = skipName(view, offset);
  requireBytes(view, headerOffset, 10);

  const type = view.getUint16(headerOffset);
  const cls = view.getUint16(headerOffset + 2);
  const ttl = view.getUint32(headerOffset + 4);
  const rdlength = view.getUint16(headerOffset + 8);
  const rdataOffset = headerOffset + 10;
  const end = rdataOffset + rdlength;
  requireBytes(view, rdataOffset, rdlength);

  return { offset, headerOffset, type, cls, ttl, rdlength, rdataOffset, end };
}

export function parseDns(body) {
  const bytes = toBytes(body);
  if (bytes.length < DNS_HEADER_LEN) throw new Error('short DNS packet');

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const header = {
    id: view.getUint16(0),
    flags: view.getUint16(2),
    qdcount: view.getUint16(4),
    ancount: view.getUint16(6),
    nscount: view.getUint16(8),
    arcount: view.getUint16(10),
  };

  let offset = DNS_HEADER_LEN;
  for (let i = 0; i < header.qdcount; i++) {
    offset = skipName(view, offset);
    requireBytes(view, offset, 4);
    offset += 4;
  }

  const answers = [];
  for (let i = 0; i < header.ancount; i++) {
    const record = readRecord(view, offset);
    answers.push(record);
    offset = record.end;
  }

  for (let i = 0; i < header.nscount; i++) {
    offset = readRecord(view, offset).end;
  }

  const additionals = [];
  let opt = null;
  for (let i = 0; i < header.arcount; i++) {
    const record = readRecord(view, offset);
    additionals.push(record);
    if (record.type === TYPE_OPT && !opt) opt = record;
    offset = record.end;
  }

  if (offset !== bytes.length) throw new Error('trailing DNS data');
  return { bytes, view, header, answers, additionals, opt };
}

// ── Question section helpers ────────────────────────────────────────

export function skipQuestion(body) {
  if (!body || body.byteLength < 12) return 12;
  let off = 12;
  const bytes = new Uint8Array(body);
  while (off < bytes.length) {
    const len = bytes[off];
    if (len === 0) return off + 1 + 4;
    if (len & 0xC0) return off + 2 + 4;
    off += 1 + len;
  }
  return 12;
}

export function parseAnswers(buf, expectedType) {
  const bytes = buf instanceof ArrayBuffer
    ? new Uint8Array(buf)
    : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (bytes.length < 12) return [];

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    offset = skipNameRaw(bytes, offset);
    offset += 4;
  }

  const answers = [];
  for (let i = 0; i < ancount; i++) {
    if (offset + 10 > bytes.length) break;
    const nameEnd = skipNameRaw(bytes, offset);
    const type = view.getUint16(nameEnd);
    const ttl = view.getUint32(nameEnd + 4);
    const rdlength = view.getUint16(nameEnd + 8);
    const rdataOffset = nameEnd + 10;

    if (rdataOffset + rdlength > bytes.length) break;

    if (type === expectedType) {
      answers.push({
        type: type,
        rdata: bytes.slice(rdataOffset, rdataOffset + rdlength),
        ttl: ttl,
      });
    }
    offset = rdataOffset + rdlength;
  }

  return answers;
}

function skipNameRaw(bytes, start) {
  let offset = start;
  let end = start;
  let jumped = false;
  let jumps = 0;

  while (jumps < 128) {
    if (offset >= bytes.length) return end || offset;
    const len = bytes[offset];

    if ((len & 0xC0) === 0xC0) {
      if (offset + 1 >= bytes.length) break;
      const pointer = ((len & 0x3F) << 8) | bytes[offset + 1];
      if (pointer >= bytes.length) break;
      if (!jumped) end = offset + 2;
      offset = pointer;
      jumped = true;
      jumps++;
      continue;
    }

    if ((len & 0xC0) !== 0) break;
    if (len === 0) return jumped ? end : offset + 1;

    offset += 1 + len;
    if (!jumped) end = offset;
  }

  return end || offset;
}

// ── Wire-format query builders ──────────────────────────────────────

export function buildWireQuery(domain, type) {
  const id = Math.floor(Math.random() * 65536);
  const labels = domain.replace(/\.+$/, '').split('.');

  let nameLen = 0;
  for (const label of labels) nameLen += label.length + 1;
  nameLen += 1;

  const total = 12 + nameLen + 4;
  const buf = new ArrayBuffer(total);
  const v = new DataView(buf);
  const bytes = new Uint8Array(buf);

  v.setUint16(0, id);
  v.setUint16(2, 0x0100);
  v.setUint16(4, 1);
  v.setUint16(6, 0);
  v.setUint16(8, 0);
  v.setUint16(10, 0);

  let offset = 12;
  for (const label of labels) {
    bytes[offset++] = label.length;
    for (let i = 0; i < label.length; i++) bytes[offset++] = label.charCodeAt(i);
  }
  bytes[offset++] = 0;

  v.setUint16(offset, type); offset += 2;
  v.setUint16(offset, 1);

  return buf;
}

export function buildQueryWireId(qname, qtype, id) {
  const labels = qname.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) break;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);
  const total = 12 + nameBytes.length + 4;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint16(0, id);
  view.setUint16(2, 0x0100);
  view.setUint16(4, 1);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);
  let off = 12;
  out.set(nameBytes, off); off += nameBytes.length;
  view.setUint16(off, qtype); off += 2;
  view.setUint16(off, 1);
  return out.buffer;
}

export function buildQueryFromURL(url) {
  const dnsParam = url.searchParams.get('dns');
  if (dnsParam) {
    try {
      const b64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
      const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      return bin.buffer;
    } catch (err) {
      logEvent('error', 'dns_error', { stage: 'buildQueryFromURL', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    }
  }

  const name = url.searchParams.get('name');
  if (!name) return null;
  const typeStr = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12, HTTPS: 65, SVCB: 64 };
  const qtype = typeMap[typeStr] || parseInt(typeStr, 10) || 1;

  return buildQueryWireId(name, qtype, Math.floor(Math.random() * 65536));
}

// ── Query metadata parsers ──────────────────────────────────────────

export function parseQueryMetaFromURL(url) {
  const typeStr = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12, HTTPS: 65, SVCB: 64 };
  const qtype = typeMap[typeStr] || parseInt(typeStr, 10) || 1;

  const name = url.searchParams.get('name');
  if (name) {
    return { id: Math.floor(Math.random() * 65536), name: name.toLowerCase().replace(/\.+$/, ''), type: qtype };
  }

  const dnsParam = url.searchParams.get('dns');
  if (dnsParam) {
    try {
      const b64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
      const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      if (bin.length < 12) return null;
      const view = new DataView(bin.buffer);
      const id = view.getUint16(0);
      let off = 12;
      const labels = [];
      for (let jumps = 0; jumps < 128; jumps++) {
        if (off >= bin.length) return null;
        const len = bin[off];
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        if (len === 0) { off++; break; }
        off++;
        labels.push(new TextDecoder().decode(bin.subarray(off, off + len)));
        off += len;
      }
      const qType = view.getUint16(off);
      return { id, name: labels.join('.').toLowerCase(), type: qType };
    } catch (err) {
      logEvent('error', 'dns_error', { stage: 'parseQueryMetaFromURL', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    }
  }

  return null;
}

export function parseQueryMeta(body) {
  try {
    const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (bytes.length < 12) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const id = view.getUint16(0);
    let offset = 12;
    const labels = [];
    for (let jumps = 0; jumps < 128; jumps++) {
      if (offset >= bytes.length) return null;
      const len = bytes[offset];
      if ((len & 0xC0) === 0xC0) { offset += 2; break; }
      if (len === 0) { offset++; break; }
      offset++;
      labels.push(new TextDecoder().decode(bytes.subarray(offset, offset + len)));
      offset += len;
    }
    const qType = view.getUint16(offset);
    return { id, name: labels.join('.').toLowerCase(), type: qType };
  } catch (err) {
    logEvent('error', 'dns_error', { stage: 'parseQueryMeta', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return null;
  }
}

// ── DNS response builders ───────────────────────────────────────────

export function dnsResponse(body, upstreamTime) {
  const headers = upstreamTime != null
    ? { ...DNS_HEADERS, 'X-Upstream-Time': String(upstreamTime) }
    : DNS_HEADERS;
  return new Response(body, { status: 200, headers });
}

export function buildDNS(id, qName, qType, rdataList, ttl) {
  const labels = qName.replace(/\.+$/, '').split('.');
  const nameBytes = [];
  for (const label of labels) {
    if (label.length > 63) break;
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) nameBytes.push(label.charCodeAt(i));
  }
  nameBytes.push(0);

  let totalLen = 12 + nameBytes.length + 4;
  for (const rd of rdataList) totalLen += 12 + rd.length;

  const buf = new ArrayBuffer(totalLen);
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf);
  view.setUint16(0, id);
  view.setUint16(2, 0x8180);
  view.setUint16(4, 1);
  view.setUint16(6, rdataList.length);
  view.setUint16(8, 0);
  view.setUint16(10, 0);

  let offset = 12;
  bytes.set(nameBytes, offset); offset += nameBytes.length;
  view.setUint16(offset, qType); offset += 2;
  view.setUint16(offset, 1); offset += 2;

  for (const rd of rdataList) {
    view.setUint16(offset, 0xC00C); offset += 2;
    view.setUint16(offset, qType); offset += 2;
    view.setUint16(offset, 1); offset += 2;
    view.setUint32(offset, ttl); offset += 4;
    view.setUint16(offset, rd.length); offset += 2;
    bytes.set(rd, offset); offset += rd.length;
  }
  return buf;
}

export function servfail(originalBody, edeCode = 0, edeText = '') {
  const id = originalBody && originalBody.byteLength >= 2 ? new DataView(originalBody).getUint16(0) : 0;
  const textBytes = new TextEncoder().encode(edeText);
  const edeOptionLen = edeCode ? (6 + textBytes.length) : 0;

  const headerLen = 12;
  const qdEnd = skipQuestion(originalBody);
  const qdBytes = qdEnd > headerLen ? new Uint8Array(originalBody.slice(headerLen, qdEnd)) : new Uint8Array(0);

  const arcount = edeCode ? 1 : 0;
  const optLen = edeCode ? (11 + edeOptionLen) : 0;
  const total = headerLen + qdBytes.length + optLen;
  const buf = new ArrayBuffer(total);
  const out = new DataView(buf);
  const bytes = new Uint8Array(buf);

  const qdcount = qdBytes.length > 0 ? 1 : 0;
  out.setUint16(0, id);
  out.setUint16(2, 0x8182);
  out.setUint16(4, qdcount);
  out.setUint16(6, 0);
  out.setUint16(8, 0);
  out.setUint16(10, arcount);
  bytes.set(qdBytes, headerLen);

  if (edeCode) {
    const off = headerLen + qdBytes.length;
    bytes[off] = 0;
    out.setUint16(off + 1, 41);
    out.setUint16(off + 3, 4096);
    out.setUint32(off + 5, 0);
    out.setUint16(off + 9, edeOptionLen);
    out.setUint16(off + 11, 15);
    out.setUint16(off + 13, 2 + textBytes.length);
    out.setUint16(off + 15, edeCode);
    if (textBytes.length) bytes.set(textBytes, off + 17);
  }

  return buf;
}

// ── Internal DNS resolution ─────────────────────────────────────────

export async function resolveDNSWire(domain, type) {
  const query = buildWireQuery(domain, type);
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;

  const entries = Object.entries(UPSTREAMS);
  if (entries.length === 0) return null;

  const controllers = [];

  function abortAll() {
    for (const c of controllers) {
      try { c.abort(); } catch (_) {}
    }
  }

  const promises = entries.map(function ([_name, cfg]) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    return fetch(cfg.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: query,
      signal: ctrl.signal,
    }).then(async function (res) {
      if (res.status !== 200) return null;
      const buf = await res.arrayBuffer();
      if (buf.byteLength < 12) return null;
      if (new DataView(buf).getUint16(6) === 0) return null;
      return buf;
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return null;
      logEvent('error', 'dns_error', { stage: 'resolveDNSWire', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return null;
    });
  });

  const timeout = new Promise(function (resolve) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(null); return; }
    setTimeout(function () { resolve(null); }, remaining);
  });

  // Only valid (non-null) results compete; failures are ignored until timeout
  const validPromises = promises.map(function (p) {
    return p.then(function (r) { if (!r) throw new Error('invalid'); return r; });
  });
  const firstValid = Promise.any(validPromises).catch(function (err) {
    logEvent('error', 'dns_error', { stage: 'resolveDNSWire_any', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return null;
  });
  const result = await Promise.race([firstValid, timeout]);

  // Clean up: abort any still-pending fetches
  abortAll();

  return result;
}

export async function resolveDNSWireForeign(body, timeoutMs) {
  var t = typeof timeoutMs === 'number' && timeoutMs > 0 ? timeoutMs : 50;
  var started = Date.now();
  var deadline = started + t;

  var foreignUrls = FOREIGN_UPSTREAMS.map(function(n) { return UPSTREAMS[n].url; });
  if (foreignUrls.length === 0) return null;

  var controllers = [];
  var result = null;
  var done = false;

  function abortAll() {
    done = true;
    for (var i = 0; i < controllers.length; i++) {
      try { controllers[i].abort(); } catch (_) {}
    }
  }

  var promises = foreignUrls.map(function (url) {
    var ctrl = new AbortController();
    controllers.push(ctrl);
    return fetch(url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: body,
      signal: ctrl.signal,
    }).then(async function (res) {
      if (done) return null;
      if (res.status !== 200) return null;
      var buf = await res.arrayBuffer();
      if (done) return null;
      if (buf.byteLength < 12) return null;
      if (new DataView(buf).getUint16(6) === 0) return null;
      result = buf;
      abortAll();
      return buf;
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return null;
      logEvent('error', 'dns_error', { stage: 'resolveDNSWireForeign', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return null;
    });
  });

  var timeoutPromise = new Promise(function (resolve) {
    var remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(); return; }
    setTimeout(function () { if (!done) abortAll(); resolve(); }, remaining);
  });

  await Promise.race([Promise.all(promises), timeoutPromise]);

  return result;
}

export function extractIPBytes(buf, type) {
  try {
    const answers = parseAnswers(buf, type);
    return answers.filter(function (a) {
      return a.type === type && (a.rdata.length === 4 || a.rdata.length === 16);
    }).map(function (a) { return a.rdata; });
  } catch (err) {
    logEvent('error', 'dns_error', { stage: 'extractIPBytes', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return [];
  }
}

export function extractIPStrings(buf, type) {
  try {
    const answers = parseAnswers(buf, type);
    if (type === 1) {
      return answers.filter(function (a) {
        return a.type === 1 && a.rdata.length === 4;
      }).map(function (a) {
        return a.rdata[0] + '.' + a.rdata[1] + '.' + a.rdata[2] + '.' + a.rdata[3];
      });
    }
    if (type === 28) {
      return answers.filter(function (a) {
        return a.type === 28 && a.rdata.length === 16;
      }).map(function (a) {
        const p = [];
        for (let i = 0; i < 16; i += 2) {
          p.push(((a.rdata[i] << 8) | a.rdata[i + 1]).toString(16));
        }
        return p.join(':');
      });
    }
    return [];
  } catch (err) {
    logEvent('error', 'dns_error', { stage: 'extractIPStrings', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return [];
  }
}

export async function resolveDNSWireAll(domain, type) {
  const query = buildWireQuery(domain, type);
  const started = Date.now();
  const deadline = started + HARD_TIMEOUT_MS;

  const entries = Object.entries(UPSTREAMS);
  if (entries.length === 0) return [];

  const controllers = [];
  const promises = entries.map(function ([_name, cfg]) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    return fetch(cfg.url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: query,
      signal: ctrl.signal,
    }).then(async function (res) {
      if (res.status !== 200) return null;
      return await res.arrayBuffer();
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return null;
      logEvent('error', 'dns_error', { stage: 'resolveDNSWireAll', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return null;
    });
  });

  const timeout = new Promise(function (resolve) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(); return; }
    setTimeout(function () { resolve(); }, remaining);
  });

  await Promise.race([Promise.allSettled(promises), timeout]);

  for (const c of controllers) {
    try { c.abort(); } catch (_) {}
  }

  const results = await Promise.allSettled(promises);
  const ipSet = new Set();
  const allIps = [];

  for (const r of results) {
    if (r.status !== 'fulfilled' || !r.value || r.value.byteLength < 12) continue;
    try {
      const answers = parseAnswers(r.value, type);
      for (const a of answers) {
        if (a.rdata.length === 4 || a.rdata.length === 16) {
          const key = String.fromCharCode.apply(null, a.rdata);
          if (!ipSet.has(key)) {
            ipSet.add(key);
            allIps.push(a.rdata);
          }
        }
      }
    } catch (err) {
      logEvent('error', 'dns_error', { stage: 'resolveDNSWireAll_parse', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    }
  }

  return allIps;
}

export async function resolvePreferredIPs(domain, type, expectedOwner, ctx) {
  var query = buildWireQuery(domain, type);
  var started = Date.now();
  var deadline = started + PREFERRED_TIMEOUT_MS;
  var requestId = ctx && ctx.requestId;

  var foreignUrls = FOREIGN_UPSTREAMS.map(function(n) { return UPSTREAMS[n].url; });
  if (foreignUrls.length === 0) return [];

  var controllers = [];
  var collected = [];

  function abortAll() {
    for (var i = 0; i < controllers.length; i++) {
      try { controllers[i].abort(); } catch (_) {}
    }
  }

  var promises = foreignUrls.map(function (url) {
    var ctrl = new AbortController();
    controllers.push(ctrl);
    return fetch(url, {
      method: 'POST',
      headers: DNS_HEADERS,
      body: query,
      signal: ctrl.signal,
    }).then(async function (res) {
      if (res.status !== 200) return null;
      var buf = await res.arrayBuffer();
      if (buf.byteLength < 12) return null;
      if (new DataView(buf).getUint16(6) === 0) return null;
      return buf;
    }).then(function (buf) {
      if (!buf) return null;
      try {
        var ips = extractIPBytes(buf, type);
        for (var i = 0; i < ips.length; i++) {
          collected.push(ips[i]);
        }
      } catch (err) {
        logEvent('error', 'dns_error', { requestId: requestId, stage: 'resolvePreferredIPs_extract', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      }
      return null;
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return null;
      logEvent('error', 'dns_error', { requestId: requestId, stage: 'resolvePreferredIPs_fetch', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return null;
    });
  });

  var timeout = new Promise(function (resolve) {
    var remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(); return; }
    setTimeout(function () { abortAll(); resolve(); }, remaining);
  });

  await Promise.race([Promise.all(promises), timeout]);
  abortAll();

  var ipSet = new Set();
  var allIps = [];
  for (var i = 0; i < collected.length; i++) {
    var key = Array.from(collected[i]).join(',');
    if (!ipSet.has(key)) {
      ipSet.add(key);
      allIps.push(collected[i]);
    }
  }

  // Validate IPs belong to expected CDN owner
  if (expectedOwner) {
    try {
      var { detectOwner } = await import('./cdn.js');
      var ownerFiltered = [];
      for (var oi = 0; oi < allIps.length; oi++) {
        var ipBytes = allIps[oi];
        var ipStr;
        if (ipBytes.length === 4) {
          ipStr = ipBytes[0] + '.' + ipBytes[1] + '.' + ipBytes[2] + '.' + ipBytes[3];
        } else if (ipBytes.length === 16) {
          var parts = [];
          for (var pi = 0; pi < 16; pi += 2) {
            parts.push(((ipBytes[pi] << 8) | ipBytes[pi + 1]).toString(16));
          }
          ipStr = parts.join(':');
        }
        if (ipStr && detectOwner(ipStr) === expectedOwner) ownerFiltered.push(ipBytes);
      }
      return ownerFiltered;
    } catch (err) {
      logEvent('error', 'dns_error', { requestId: requestId, stage: 'resolvePreferredIPs_owner_filter', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
      return [];
    }
  }
  return allIps;
}
