#!/usr/bin/env node
/* Build a self-contained Cloudflare Snippets-compatible DoH proxy. */
var fs = require('fs');
var path = require('path');
var https = require('https');
var http = require('http');

var GEOIP_BASE_URL = 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/';
var CEALING_HOST_URL = 'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json';

function fetchText(url) {
  return new Promise(function(resolve, reject) {
    var fetcher = url.indexOf('https:') === 0 ? https : http;
    var req = fetcher.get(url, { headers: { 'User-Agent': 'superdoh-snippets-build/1.0' } }, function(res) {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        fetchText(new URL(res.headers.location, url).toString()).then(resolve, reject);
        return;
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error('HTTP ' + res.statusCode + ' for ' + url));
        return;
      }
      var data = '';
      res.setEncoding('utf8');
      res.on('data', function(chunk) { data += chunk; });
      res.on('end', function() { resolve(data); });
    });
    req.setTimeout(30000, function() { req.destroy(new Error('Timeout fetching ' + url)); });
    req.on('error', reject);
  });
}

async function fetchGeoipCidrs(category) {
  var body = await fetchText(GEOIP_BASE_URL + category + '.txt');
  return body.split(/\r?\n/).map(function(line) { return line.trim(); }).filter(function(line) {
    return line && line.charAt(0) !== '#';
  });
}

function ipToLong(ip) {
  var parts = ip.split('.');
  if (parts.length !== 4) throw new Error('bad IPv4');
  var result = 0;
  for (var i = 0; i < 4; i++) {
    var n = parseInt(parts[i], 10);
    if (isNaN(n) || n < 0 || n > 255) throw new Error('bad IPv4 octet');
    result = (result * 256) + n;
  }
  return result >>> 0;
}

function ipv6ToBigInt(ip) {
  var groups = ip.split(':');
  if (ip.indexOf('::') >= 0) {
    var doubleColon = ip.indexOf('::');
    var left = ip.substring(0, doubleColon);
    var right = ip.substring(doubleColon + 2);
    var leftParts = left ? left.split(':') : [];
    var rightParts = right ? right.split(':') : [];
    var fill = 8 - leftParts.length - rightParts.length;
    if (fill < 0) throw new Error('bad IPv6');
    groups = [];
    for (var i = 0; i < leftParts.length; i++) groups.push(leftParts[i]);
    for (var j = 0; j < fill; j++) groups.push('0');
    for (var k = 0; k < rightParts.length; k++) groups.push(rightParts[k]);
  }
  if (groups.length !== 8) throw new Error('bad IPv6 group count');
  var result = 0n;
  for (var g = 0; g < 8; g++) {
    var val = parseInt(groups[g] || '0', 16);
    if (isNaN(val) || val > 0xFFFF || val < 0) throw new Error('bad IPv6 group');
    result = (result << 16n) + BigInt(val);
  }
  return result;
}

function mergeRanges(ranges, big) {
  ranges.sort(function(a, b) {
    if (a.start < b.start) return -1;
    if (a.start > b.start) return 1;
    return 0;
  });
  var out = [];
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    if (!out.length) { out.push({ start: r.start, end: r.end }); continue; }
    var last = out[out.length - 1];
    var adjacent = big ? (r.start <= last.end + 1n) : (r.start <= last.end + 1);
    if (adjacent) {
      if (r.end > last.end) last.end = r.end;
    } else {
      out.push({ start: r.start, end: r.end });
    }
  }
  return out;
}

function compileCidrs(cidrList) {
  var v4 = [];
  var v6 = [];
  for (var i = 0; i < cidrList.length; i++) {
    try {
      var cidr = cidrList[i];
      var parts = cidr.split('/');
      if (parts.length !== 2) continue;
      var ip = parts[0];
      var bits = parseInt(parts[1], 10);
      if (isNaN(bits)) continue;
      if (ip.indexOf(':') >= 0) {
        if (bits < 0 || bits > 128) continue;
        var hostBits = 128n - BigInt(bits);
        var mask = hostBits === 128n ? 0n : (((1n << 128n) - 1n) ^ ((1n << hostBits) - 1n));
        var ipBn = ipv6ToBigInt(ip);
        var start6 = ipBn & mask;
        var end6 = start6 | ((1n << hostBits) - 1n);
        v6.push({ start: start6, end: end6 });
      } else {
        if (bits < 0 || bits > 32) continue;
        var ipNum = ipToLong(ip);
        var host = 32 - bits;
        var size = Math.pow(2, host);
        var start4 = Math.floor(ipNum / size) * size;
        var end4 = start4 + size - 1;
        v4.push({ start: start4 >>> 0, end: end4 >>> 0 });
      }
    } catch (_) {}
  }
  return { v4: mergeRanges(v4, false), v6: mergeRanges(v6, true) };
}

function jsCompiled(obj) {
  return '{v4:[' + obj.v4.map(function(r) { return '{start:' + r.start + ',end:' + r.end + '}'; }).join(',') + '],v6:[' +
    obj.v6.map(function(r) { return '{start:' + r.start.toString() + 'n,end:' + r.end.toString() + 'n}'; }).join(',') + ']}';
}

function validIPv4(ip) {
  try {
    var p = ip.split('.');
    if (p.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i])) return false;
      var n = Number(p[i]);
      if (n < 0 || n > 255) return false;
    }
    return true;
  } catch (_) { return false; }
}

async function fetchGoogleProxy() {
  var cealingData = JSON.parse(await fetchText(CEALING_HOST_URL));
  var googleEntries = [];
  var googleKeys = ['google', 'youtube', 'gstatic', 'youtu.be', 'ggpht', 'blogger', 'blogspot', 'googleapis', 'googlevideo', 'android.com', 'googleadservices', 'gemini'];
  if (!Array.isArray(cealingData)) return [];
  for (var i = 0; i < cealingData.length; i++) {
    var r = cealingData[i];
    var domains = r && r[0];
    if (!Array.isArray(domains)) continue;
    var sni = (r[1] || '').trim();
    var ip = (r[2] || '').trim();
    if (!ip || ip.charAt(0) === '[' || !validIPv4(ip)) continue;
    var isGoogle = false;
    for (var j = 0; j < domains.length; j++) {
      var d = String(domains[j]).replace(/[#$^*]/g, '').toLowerCase();
      for (var k = 0; k < googleKeys.length; k++) {
        if (d.indexOf(googleKeys[k]) >= 0) { isGoogle = true; break; }
      }
      if (isGoogle) break;
    }
    if (!isGoogle) continue;
    var matchPatterns = [];
    for (var m = 0; m < domains.length; m++) {
      var raw = String(domains[m]);
      if (raw.charAt(0) === '^') continue;
      var clean = raw.replace(/[#$]/g, '').replace(/\*/g, '').trim();
      if (clean) matchPatterns.push(clean);
    }
    if (matchPatterns.length > 0) googleEntries.push({ ips: [ip], sni: sni || null, match: matchPatterns });
  }
  var merged = [];
  var seenMap = {};
  for (var x = 0; x < googleEntries.length; x++) {
    var e = googleEntries[x];
    var key = JSON.stringify(e.ips) + '|' + (e.sni || '');
    if (seenMap[key] !== undefined) {
      merged[seenMap[key]].match = merged[seenMap[key]].match.concat(e.match);
    } else {
      seenMap[key] = merged.length;
      merged.push(e);
    }
  }
  var youtubeSupplements = ['googlevideo.com', 'yt3.ggpht.com', 'ytimg.com', 'gvt1.com', 'gvt2.com', 'gvt3.com', 'video.google.com'];
  var googleSupplements = ['doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'google.com.hk', 'google.cn', 'google.co.jp', 'googleusercontent.com', 'gmail.com'];
  for (var y = 0; y < merged.length; y++) {
    if (merged[y].sni === 'g.cn') {
      merged[y].match = merged[y].match.concat(youtubeSupplements, googleSupplements);
      break;
    }
  }
  return merged;
}

function snippetSource(cf, meta, googleProxy) {
  return `// Generated by build.js. Self-contained Cloudflare Snippets DoH proxy.\n` +
`var UPSTREAM = 'https://dns.google/dns-query';\n` +
`var TYPE_A = 1, TYPE_AAAA = 28, TYPE_OPT = 41, TYPE_HTTPS = 65, OPT_ECS = 8, UDP_PAYLOAD_SIZE = 4096, DO_BIT = 0x8000;\n` +
`var SVC_KEY_ALPN = 1, SVC_KEY_ECH = 5, CACHE_TTL_MS = 600000, STALE_TTL_MS = 3600000, CF_ECH_DOMAIN = 'cloudflare-ech.com';\n` +
`var ECS_PREFIX4 = 24, ECS_PREFIX6 = 56;\n` +
`var META_ECH_B64 = 'AsH+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAD+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAD+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAD+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA/g0ASwYAIAAgti54XaD8VhwGEmxjGpaxUkuAz3VmpQSMOFSRgSPchR0ABAABAAEyHHNjb250ZW50LWxheDMtMi54eC5mYmNkbi5uZXQAAP4NAEgEACAAINQS+ceVTWrz9nffBM163+nvpZ9k5F5WK51t4DAGG3ReAAQAAQABZBl2aWRlby1sYXgzLTIueHguZmJjZG4ubmV0AAD+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAD+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=';\n` +
`var COMPILED_CF = ${jsCompiled(cf)};\n` +
`var COMPILED_META = ${jsCompiled(meta)};\n` +
`var GOOGLE_PROXY = ${JSON.stringify(googleProxy)};\n` + runtimeSource();
}

function runtimeSource() {
  return String.raw`
var echCache = new Map();
function toBytes(body) { if (body instanceof ArrayBuffer) return new Uint8Array(body); if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength); throw new Error('body must be ArrayBuffer'); }
function requireBytes(view, offset, len) { if (offset < 0 || len < 0 || offset + len > view.byteLength) throw new Error('DNS packet out of bounds'); }
function joinBytes() { var len = 0; for (var i = 0; i < arguments.length; i++) len += arguments[i].length; var out = new Uint8Array(len); var o = 0; for (var j = 0; j < arguments.length; j++) { out.set(arguments[j], o); o += arguments[j].length; } return out; }
function encodeDnsName(domain) { if (!domain || domain === '.') return new Uint8Array([0]); var parts = domain.replace(/\.+$/, '').split('.'); var buf = new Uint8Array(domain.length + 2); var offset = 0; for (var i = 0; i < parts.length; i++) { var part = parts[i]; buf[offset++] = part.length; for (var j = 0; j < part.length; j++) buf[offset++] = part.charCodeAt(j); } buf[offset++] = 0; return buf.slice(0, offset); }
function decodeName(view, start) { var offset = start, end = start, jumped = false, jumps = 0, seen = {}, labels = []; var decoder = new TextDecoder(); for (;;) { requireBytes(view, offset, 1); var len = view.getUint8(offset); if ((len & 0xC0) === 0xC0) { requireBytes(view, offset, 2); var pointer = ((len & 0x3F) << 8) | view.getUint8(offset + 1); if (pointer >= view.byteLength || seen[pointer]) throw new Error('bad DNS compression pointer'); if (!jumped) end = offset + 2; seen[pointer] = true; offset = pointer; jumped = true; if (++jumps > 128) throw new Error('DNS compression loop'); continue; } if ((len & 0xC0) !== 0) throw new Error('unsupported DNS label type'); if (len === 0) return { name: labels.join('.'), end: jumped ? end : offset + 1 }; offset++; requireBytes(view, offset, len); labels.push(decoder.decode(new Uint8Array(view.buffer, view.byteOffset + offset, len))); if (!jumped) end = offset + len; offset += len; } }
function skipName(view, start) { return decodeName(view, start).end; }
function readRecord(view, offset) { var headerOffset = skipName(view, offset); requireBytes(view, headerOffset, 10); var type = view.getUint16(headerOffset); var cls = view.getUint16(headerOffset + 2); var ttl = view.getUint32(headerOffset + 4); var rdlength = view.getUint16(headerOffset + 8); var rdataOffset = headerOffset + 10; var end = rdataOffset + rdlength; requireBytes(view, rdataOffset, rdlength); return { offset: offset, headerOffset: headerOffset, type: type, cls: cls, ttl: ttl, rdlength: rdlength, rdataOffset: rdataOffset, end: end }; }
function parseDns(body) { var bytes = toBytes(body); if (bytes.length < 12) throw new Error('short DNS packet'); var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); var header = { id: view.getUint16(0), flags: view.getUint16(2), qdcount: view.getUint16(4), ancount: view.getUint16(6), nscount: view.getUint16(8), arcount: view.getUint16(10) }; var offset = 12; for (var i = 0; i < header.qdcount; i++) { offset = skipName(view, offset); requireBytes(view, offset, 4); offset += 4; } var answers = []; for (var a = 0; a < header.ancount; a++) { var record = readRecord(view, offset); answers.push(record); offset = record.end; } for (var n = 0; n < header.nscount; n++) offset = readRecord(view, offset).end; var additionals = [], opt = null; for (var r = 0; r < header.arcount; r++) { var ar = readRecord(view, offset); additionals.push(ar); if (ar.type === TYPE_OPT && !opt) opt = ar; offset = ar.end; } if (offset !== bytes.length) throw new Error('trailing DNS data'); return { bytes: bytes, view: view, header: header, answers: answers, additionals: additionals, opt: opt }; }
function buildWireQuery(domain, type) { var id = Math.floor(Math.random() * 65536); var nameBytes = encodeDnsName(domain); var total = 12 + nameBytes.length + 4; var buf = new ArrayBuffer(total); var v = new DataView(buf); var bytes = new Uint8Array(buf); v.setUint16(0, id); v.setUint16(2, 0x0100); v.setUint16(4, 1); bytes.set(nameBytes, 12); var off = 12 + nameBytes.length; v.setUint16(off, type); v.setUint16(off + 2, 1); return buf; }
function parseQueryMeta(body) { try { var bytes = toBytes(body); if (bytes.length < 12) return null; var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); var qname = decodeName(view, 12); if (!qname || qname.end + 4 > bytes.length) return null; return { id: view.getUint16(0), name: qname.name.toLowerCase(), type: view.getUint16(qname.end) }; } catch (_) { return null; } }
function b64UrlToBytes(value) { var b64 = value.replace(/-/g, '+').replace(/_/g, '/'); while (b64.length % 4) b64 += '='; var bin = atob(b64); var out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
function buildQueryFromURL(url) { var dnsParam = url.searchParams.get('dns'); if (dnsParam) return b64UrlToBytes(dnsParam).buffer; var name = url.searchParams.get('name'); if (!name) return null; var typeStr = (url.searchParams.get('type') || 'A').toUpperCase(); var typeMap = { A: 1, AAAA: 28, TXT: 16, MX: 15, CNAME: 5, NS: 2, SOA: 6, PTR: 12, HTTPS: 65, SVCB: 64 }; var qtype = typeMap[typeStr] || parseInt(typeStr, 10) || 1; return buildWireQuery(name, qtype); }
function skipQuestionBytes(bytes) { try { var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); var off = 12; for (var i = 0; i < view.getUint16(4); i++) { off = skipName(view, off); off += 4; } return off; } catch (_) { return 12; } }
function servfail(originalBody) { var originalBytes = null; try { originalBytes = originalBody ? toBytes(originalBody) : null; } catch (_) {} var id = 0; var qdBytes = new Uint8Array(0); if (originalBytes && originalBytes.length >= 2) { var ov = new DataView(originalBytes.buffer, originalBytes.byteOffset, originalBytes.byteLength); id = ov.getUint16(0); var qdEnd = skipQuestionBytes(originalBytes); if (qdEnd > 12 && qdEnd <= originalBytes.length) qdBytes = originalBytes.slice(12, qdEnd); } var buf = new ArrayBuffer(12 + qdBytes.length); var out = new DataView(buf); var bytes = new Uint8Array(buf); out.setUint16(0, id); out.setUint16(2, 0x8182); out.setUint16(4, qdBytes.length ? 1 : 0); bytes.set(qdBytes, 12); return buf; }
function dnsResponse(body) { return new Response(body, { status: 200, headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' } }); }
function buildDNS(id, qName, qType, rdataList, ttl) { var nameBytes = encodeDnsName(qName); var totalLen = 12 + nameBytes.length + 4; for (var i = 0; i < rdataList.length; i++) totalLen += 12 + rdataList[i].length; var buf = new ArrayBuffer(totalLen); var bytes = new Uint8Array(buf); var view = new DataView(buf); view.setUint16(0, id); view.setUint16(2, 0x8180); view.setUint16(4, 1); view.setUint16(6, rdataList.length); bytes.set(nameBytes, 12); var offset = 12 + nameBytes.length; view.setUint16(offset, qType); offset += 2; view.setUint16(offset, 1); offset += 2; for (var r = 0; r < rdataList.length; r++) { var rd = rdataList[r]; view.setUint16(offset, 0xC00C); offset += 2; view.setUint16(offset, qType); offset += 2; view.setUint16(offset, 1); offset += 2; view.setUint32(offset, ttl); offset += 4; view.setUint16(offset, rd.length); offset += 2; bytes.set(rd, offset); offset += rd.length; } return buf; }
function parseAnswers(buf, expectedType) { var bytes = toBytes(buf); if (bytes.length < 12) return []; var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); var qdcount = view.getUint16(4); var ancount = view.getUint16(6); var offset = 12; for (var i = 0; i < qdcount; i++) { offset = skipName(view, offset); offset += 4; } var answers = []; for (var a = 0; a < ancount; a++) { if (offset + 10 > bytes.length) break; var nameEnd = skipName(view, offset); var type = view.getUint16(nameEnd); var ttl = view.getUint32(nameEnd + 4); var rdlength = view.getUint16(nameEnd + 8); var rdataOffset = nameEnd + 10; if (rdataOffset + rdlength > bytes.length) break; if (type === expectedType) answers.push({ type: type, rdata: bytes.slice(rdataOffset, rdataOffset + rdlength), ttl: ttl }); offset = rdataOffset + rdlength; } return answers; }
function extractIPBytes(buf, type) { try { var answers = parseAnswers(buf, type); var out = []; for (var i = 0; i < answers.length; i++) if (answers[i].rdata.length === 4 || answers[i].rdata.length === 16) out.push(answers[i].rdata); return out; } catch (_) { return []; } }
function extractIps(buffer) { var ips = []; try { var bytes = toBytes(buffer); var packet = parseDns(bytes); for (var i = 0; i < packet.answers.length; i++) { var a = packet.answers[i]; if (a.type === 1 && a.rdlength === 4) ips.push(packet.bytes[a.rdataOffset] + '.' + packet.bytes[a.rdataOffset + 1] + '.' + packet.bytes[a.rdataOffset + 2] + '.' + packet.bytes[a.rdataOffset + 3]); else if (a.type === 28 && a.rdlength === 16) { var p = []; for (var j = 0; j < 16; j += 2) p.push(((packet.bytes[a.rdataOffset + j] << 8) | packet.bytes[a.rdataOffset + j + 1]).toString(16)); ips.push(p.join(':')); } } } catch (_) {} return ips; }
function ipToLong(ip) { var parts = ip.split('.'); if (parts.length !== 4) throw new Error('bad IPv4'); var result = 0; for (var i = 0; i < 4; i++) { var n = parseInt(parts[i], 10); if (isNaN(n) || n < 0 || n > 255) throw new Error('bad IPv4 octet'); result = (result * 256) + n; } return result >>> 0; }
function ipv6ToBigInt(ip) { var groups = ip.split(':'); if (ip.indexOf('::') >= 0) { var dc = ip.indexOf('::'); var left = ip.substring(0, dc); var right = ip.substring(dc + 2); var lp = left ? left.split(':') : []; var rp = right ? right.split(':') : []; var fill = 8 - lp.length - rp.length; if (fill < 0) throw new Error('bad IPv6'); groups = []; for (var i = 0; i < lp.length; i++) groups.push(lp[i]); for (var f = 0; f < fill; f++) groups.push('0'); for (var r = 0; r < rp.length; r++) groups.push(rp[r]); } if (groups.length !== 8) throw new Error('bad IPv6 group count'); var result = 0n; for (var g = 0; g < 8; g++) { var val = parseInt(groups[g] || '0', 16); if (isNaN(val) || val > 0xFFFF || val < 0) throw new Error('bad IPv6 group'); result = (result << 16n) + BigInt(val); } return result; }
function isIpInCompiled(ip, compiled) { if (!ip || !compiled) return false; if (ip.indexOf(':') >= 0) { try { var ipBn = ipv6ToBigInt(ip); for (var i = 0; i < compiled.v6.length; i++) if (ipBn >= compiled.v6[i].start && ipBn <= compiled.v6[i].end) return true; } catch (_) {} } else { try { var ipNum = ipToLong(ip); for (var j = 0; j < compiled.v4.length; j++) if (ipNum >= compiled.v4[j].start && ipNum <= compiled.v4[j].end) return true; } catch (_) {} } return false; }
function detectOwner(ip) { if (isIpInCompiled(ip, COMPILED_CF)) return 'CF'; if (isIpInCompiled(ip, COMPILED_META)) return 'META'; return null; }
function classifyResponse(responseBuf) { var ips = extractIps(responseBuf); for (var i = 0; i < ips.length; i++) { var owner = detectOwner(ips[i]); if (owner) return owner; } return null; }
function ipToBytes(ip) { if (!ip || ip.indexOf(':') >= 0) return null; var parts = ip.split('.'); if (parts.length !== 4) return null; var out = new Uint8Array(4); for (var i = 0; i < 4; i++) { var n = parseInt(parts[i], 10); if (isNaN(n) || n < 0 || n > 255) return null; out[i] = n; } return out; }
function matchGoogleProxy(name, googleConf) { if (!name || !googleConf || !googleConf.length) return null; var n = name.toLowerCase().replace(/\.+$/, ''); for (var i = 0; i < googleConf.length; i++) { var entry = googleConf[i]; var patterns = entry.match || []; for (var j = 0; j < patterns.length; j++) { var rd = String(patterns[j]).toLowerCase().replace(/\.+$/, ''); var suffix = rd.charAt(0) === '.' ? rd : '.' + rd; if (n === rd || n.endsWith(suffix)) return entry; } } return null; }
function readOptions(view, opt) { var offset = opt.rdataOffset; var end = opt.end; var result = { hasEcs: false }; while (offset < end) { requireBytes(view, offset, 4); var code = view.getUint16(offset); var len = view.getUint16(offset + 2); var dataOffset = offset + 4; if (dataOffset + len > end) throw new Error('bad EDNS option length'); if (code === OPT_ECS) result.hasEcs = true; offset = dataOffset + len; } return result; }
function appendOption(packet, opt, option) { if (opt.rdlength + option.length > 0xFFFF) throw new Error('OPT RDLEN overflow'); var out = new Uint8Array(packet.bytes.length + option.length); out.set(packet.bytes.subarray(0, opt.end)); out.set(option, opt.end); out.set(packet.bytes.subarray(opt.end), opt.end + option.length); var view = new DataView(out.buffer); view.setUint16(opt.headerOffset + 8, opt.rdlength + option.length); return out; }
function appendOpt(packet, options, ttl) { if (packet.header.arcount === 0xFFFF) throw new Error('ARCOUNT overflow'); var record = new Uint8Array(11 + options.length); var rv = new DataView(record.buffer); record[0] = 0; rv.setUint16(1, TYPE_OPT); rv.setUint16(3, UDP_PAYLOAD_SIZE); rv.setUint32(5, ttl); rv.setUint16(9, options.length); record.set(options, 11); var out = joinBytes(packet.bytes, record); new DataView(out.buffer).setUint16(10, packet.header.arcount + 1); return out; }
function extractClientIP(value) { return typeof value === 'string' ? value.trim() : ''; }
function parsePublicIPv4(value) { var ip = extractClientIP(value); if (!ip || ip.indexOf(':') >= 0) return null; var parts = ip.split('.'); if (parts.length !== 4) return null; var addr = new Uint8Array(4); for (var i = 0; i < 4; i++) { if (!/^\d{1,3}$/.test(parts[i])) return null; var n = Number(parts[i]); if (n < 0 || n > 255) return null; addr[i] = n; } var a = addr[0], b = addr[1], c = addr[2]; if (a === 0 || a === 10 || a === 127 || a >= 224) return null; if (a === 100 && b >= 64 && b <= 127) return null; if (a === 169 && b === 254) return null; if (a === 172 && b >= 16 && b <= 31) return null; if (a === 192 && b === 168) return null; if (a === 192 && b === 0 && (c === 0 || c === 2)) return null; if (a === 192 && b === 88 && c === 99) return null; if (a === 198 && (b === 18 || b === 19)) return null; if (a === 198 && b === 51 && c === 100) return null; if (a === 203 && b === 0 && c === 113) return null; return addr; }
function parsePublicIPv6(value) { var ip = extractClientIP(value); if (!ip || ip.indexOf(':') < 0) return null; var parts = ip.split('::'); if (parts.length > 2) return null; var left = parts[0] ? parts[0].split(':').filter(function(g) { return g !== ''; }) : []; var right = parts[1] ? parts[1].split(':').filter(function(g) { return g !== ''; }) : []; var fill = 8 - left.length - right.length; if (fill < 0) return null; var groups = left.concat(Array(fill).fill('0')).concat(right); var addr = new Uint8Array(16); for (var i = 0; i < 8; i++) { var group = groups[i] || '0'; if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null; var val = parseInt(group, 16); if (isNaN(val) || val > 0xFFFF) return null; addr[i * 2] = (val >> 8) & 0xFF; addr[i * 2 + 1] = val & 0xFF; } if (addr[0] === 0xFE && (addr[1] & 0xC0) === 0x80) return null; var allZero = true; for (var z = 0; z < 16; z++) if (addr[z] !== 0) allZero = false; if (allZero) return null; if (addr[15] === 1) { var loop = true; for (var l = 0; l < 15; l++) if (addr[l] !== 0) loop = false; if (loop) return null; } if (addr[0] === 0xFD || addr[0] === 0xFC) return null; return addr; }
function makeEcsOption4(ip) { var addr = parsePublicIPv4(ip); if (!addr) return null; var prefix = ECS_PREFIX4; var addrLen = Math.ceil(prefix / 8); var optionLen = 4 + addrLen; var option = new Uint8Array(4 + optionLen); var view = new DataView(option.buffer); view.setUint16(0, OPT_ECS); view.setUint16(2, optionLen); view.setUint16(4, 1); option[6] = prefix; option[7] = 0; option.set(addr.subarray(0, addrLen), 8); if (prefix % 8 !== 0 && addrLen > 0) option[7 + addrLen] &= (0xFF << (8 - (prefix % 8))) & 0xFF; return option; }
function makeEcsOption6(ip) { var addr = parsePublicIPv6(ip); if (!addr) return null; var prefix = ECS_PREFIX6; var addrLen = Math.ceil(prefix / 8); var optionLen = 4 + addrLen; var option = new Uint8Array(4 + optionLen); var view = new DataView(option.buffer); view.setUint16(0, OPT_ECS); view.setUint16(2, optionLen); view.setUint16(4, 2); option[6] = prefix; option[7] = 0; option.set(addr.subarray(0, addrLen), 8); if (prefix % 8 !== 0 && addrLen > 0) option[7 + addrLen] &= (0xFF << (8 - (prefix % 8))) & 0xFF; return option; }
function makeEcsOption(clientIP) { var ip = extractClientIP(clientIP); if (!ip) return null; return ip.indexOf(':') >= 0 ? makeEcsOption6(ip) : makeEcsOption4(ip); }
function prepareQuery(body, clientIP) { try { var ecs = makeEcsOption(clientIP); var packet = parseDns(body); var prepared = body; if (ecs) { if (packet.opt) { if (!readOptions(packet.view, packet.opt).hasEcs) prepared = appendOption(packet, packet.opt, ecs).buffer; } else { prepared = appendOpt(packet, ecs, 0).buffer; } packet = parseDns(prepared); } if (!packet.opt) return appendOpt(packet, new Uint8Array(0), DO_BIT).buffer; var ttl = packet.view.getUint32(packet.opt.headerOffset + 4); if (packet.opt.cls !== UDP_PAYLOAD_SIZE || (ttl & DO_BIT) === 0) { var bytes = new Uint8Array(packet.bytes); var view = new DataView(bytes.buffer); view.setUint16(packet.opt.headerOffset + 2, UDP_PAYLOAD_SIZE); view.setUint32(packet.opt.headerOffset + 4, ttl | DO_BIT); return bytes.buffer; } return prepared; } catch (_) { return body; } }
async function queryGoogle(query) { var res = await fetch(UPSTREAM, { method: 'POST', headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' }, body: query }); if (!res || res.status !== 200) throw new Error('upstream HTTP ' + (res && res.status)); var buf = await res.arrayBuffer(); if (!buf || buf.byteLength < 12) throw new Error('short upstream response'); return buf; }
function copyRdata(view, rdataOffset, rdlength) { return new Uint8Array(view.buffer.slice(view.byteOffset + rdataOffset, view.byteOffset + rdataOffset + rdlength)); }
function expandRdataNames(view, rdataOffset, rdlength, rrType) { if (rrType !== 5 && rrType !== 2 && rrType !== 12 && rrType !== 15 && rrType !== 33 && rrType !== 6) return copyRdata(view, rdataOffset, rdlength); if (rrType === 5 || rrType === 2 || rrType === 12) return encodeDnsName(decodeName(view, rdataOffset).name); if (rrType === 15) { requireBytes(view, rdataOffset, 2); var pref = view.getUint16(rdataOffset); var mxName = decodeName(view, rdataOffset + 2); var encodedMx = encodeDnsName(mxName.name); var mxResult = new Uint8Array(2 + encodedMx.length); new DataView(mxResult.buffer).setUint16(0, pref); mxResult.set(encodedMx, 2); return mxResult; } if (rrType === 33) { requireBytes(view, rdataOffset, 6); var srvName = decodeName(view, rdataOffset + 6); var encodedSrv = encodeDnsName(srvName.name); var srvResult = new Uint8Array(6 + encodedSrv.length); srvResult.set(copyRdata(view, rdataOffset, 6), 0); srvResult.set(encodedSrv, 6); return srvResult; } if (rrType === 6) { var mname = decodeName(view, rdataOffset); var rname = decodeName(view, mname.end); var encodedMname = encodeDnsName(mname.name); var encodedRname = encodeDnsName(rname.name); var fixedOffset = rname.end; requireBytes(view, fixedOffset, 20); var soaResult = new Uint8Array(encodedMname.length + encodedRname.length + 20); var soaOffset = 0; soaResult.set(encodedMname, soaOffset); soaOffset += encodedMname.length; soaResult.set(encodedRname, soaOffset); soaOffset += encodedRname.length; soaResult.set(copyRdata(view, fixedOffset, 20), soaOffset); return soaResult; } return copyRdata(view, rdataOffset, rdlength); }
function parseHttpsRdata(view, rdataOffset, rdlength) { try { var end = rdataOffset + rdlength; var offset = rdataOffset; requireBytes(view, offset, 2); var priority = view.getUint16(offset); offset += 2; var decoded = decodeName(view, offset); var target = decoded.name || '.'; offset = decoded.end; var paramBytes = []; while (offset < end) { requireBytes(view, offset, 4); var valLen = view.getUint16(offset + 2); var paramLen = 4 + valLen; requireBytes(view, offset, paramLen); var raw = new Uint8Array(view.buffer, view.byteOffset + offset, paramLen); paramBytes.push(raw.slice()); offset += paramLen; } return { priority: priority, target: target, paramBytes: paramBytes }; } catch (_) { return null; } }
function decodeAlpn(bytes) { var ids = []; var o = 0; while (o < bytes.length) { var len = bytes[o++]; var s = ''; for (var j = 0; j < len; j++) s += String.fromCharCode(bytes[o + j]); ids.push(s); o += len; } return ids.join(','); }
function encodeBase64Url(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function encodeSvcParam(key, value) { var id = key === 'alpn' ? SVC_KEY_ALPN : key === 'ech' ? SVC_KEY_ECH : 0; if (!id) return null; var valBuf; if (key === 'alpn') { var parts = value.split(','); var total = 0; for (var i = 0; i < parts.length; i++) total += parts[i].length + 1; valBuf = new Uint8Array(total); var o = 0; for (var j = 0; j < parts.length; j++) { var p = parts[j]; valBuf[o++] = p.length; for (var k = 0; k < p.length; k++) valBuf[o++] = p.charCodeAt(k); } } else { var b64 = value.replace(/-/g, '+').replace(/_/g, '/'); while (b64.length % 4) b64 += '='; var bin = atob(b64); valBuf = new Uint8Array(bin.length); for (var x = 0; x < bin.length; x++) valBuf[x] = bin.charCodeAt(x); } var res = new Uint8Array(4 + valBuf.length); var v = new DataView(res.buffer); v.setUint16(0, id); v.setUint16(2, valBuf.length); res.set(valBuf, 4); return res; }
function packHttpsParams(priority, target, params) { var targetBuf = target === '.' ? new Uint8Array([0]) : encodeDnsName(target); var paramBufs = []; for (var i = 0; i < params.length; i++) { var encoded = params[i] instanceof Uint8Array ? params[i] : encodeSvcParam(params[i].key, params[i].val); if (encoded) paramBufs.push(encoded); } paramBufs.sort(function(a, b) { return new DataView(a.buffer, a.byteOffset, 2).getUint16(0) - new DataView(b.buffer, b.byteOffset, 2).getUint16(0); }); var totalLen = 2 + targetBuf.length; for (var j = 0; j < paramBufs.length; j++) totalLen += paramBufs[j].length; var res = new Uint8Array(totalLen); new DataView(res.buffer).setUint16(0, priority); res.set(targetBuf, 2); var offset = 2 + targetBuf.length; for (var k = 0; k < paramBufs.length; k++) { res.set(paramBufs[k], offset); offset += paramBufs[k].length; } return res; }
function buildHttpsRdata(priority, target, paramBytes) { return packHttpsParams(priority, target, paramBytes); }
function createDNSResponseEx(id, qName, records, flags) { var encName = encodeDnsName(qName); var totalLen = 12 + encName.length + 4; for (var i = 0; i < records.length; i++) { var rec = records[i]; var ownerLen = rec.name && rec.name !== qName ? encodeDnsName(rec.name).length : 2; totalLen += ownerLen + 10 + rec.rdata.length; } var buf = new Uint8Array(totalLen); var v = new DataView(buf.buffer); var newFlags = (flags || 0x8180) & ~0x0020; newFlags = (newFlags & ~0x000F) | 0x8000; v.setUint16(0, id); v.setUint16(2, newFlags); v.setUint16(4, 1); v.setUint16(6, records.length); var offset = 12; buf.set(encName, offset); offset += encName.length; v.setUint16(offset, TYPE_HTTPS); offset += 2; v.setUint16(offset, 1); offset += 2; for (var r = 0; r < records.length; r++) { var rd = records[r].rdata; if (records[r].name && records[r].name !== qName) { var encOwner = encodeDnsName(records[r].name); buf.set(encOwner, offset); offset += encOwner.length; } else { v.setUint16(offset, 0xC00C); offset += 2; } v.setUint16(offset, records[r].type); offset += 2; v.setUint16(offset, 1); offset += 2; v.setUint32(offset, records[r].ttl); offset += 4; v.setUint16(offset, rd.length); offset += 2; buf.set(rd, offset); offset += rd.length; } return buf.buffer; }
async function fetchCFEch() { var cached = echCache.get(CF_ECH_DOMAIN); if (cached && Date.now() - cached.ts < CACHE_TTL_MS) return cached.data; try { var buf = await queryGoogle(buildWireQuery(CF_ECH_DOMAIN, TYPE_HTTPS)); var packet = parseDns(buf); var ans = null; for (var i = 0; i < packet.answers.length; i++) if (packet.answers[i].type === TYPE_HTTPS) { ans = packet.answers[i]; break; } if (!ans) throw new Error('no HTTPS answer'); var httpsRdata = parseHttpsRdata(packet.view, ans.rdataOffset, ans.rdlength); if (!httpsRdata) throw new Error('bad HTTPS rdata'); var params = []; for (var j = 0; j < httpsRdata.paramBytes.length; j++) { var pb = httpsRdata.paramBytes[j]; if (pb.length < 4) continue; var pbView = new DataView(pb.buffer, pb.byteOffset, pb.byteLength); var keyId = pbView.getUint16(0); var valLen = pbView.getUint16(2); if (keyId !== SVC_KEY_ALPN && keyId !== SVC_KEY_ECH) continue; var valBytes = pb.subarray(4, 4 + valLen); params.push({ key: keyId === SVC_KEY_ALPN ? 'alpn' : 'ech', val: keyId === SVC_KEY_ALPN ? decodeAlpn(valBytes) : encodeBase64Url(valBytes) }); } var hasEch = false; for (var p = 0; p < params.length; p++) if (params[p].key === 'ech' && params[p].val) hasEch = true; if (!hasEch) throw new Error('no ECH param'); var result = { rdata: packHttpsParams(httpsRdata.priority, httpsRdata.target, params), params: params }; echCache.set(CF_ECH_DOMAIN, { ts: Date.now(), data: result }); return result; } catch (_) { if (cached && cached.data && Date.now() - cached.ts < STALE_TTL_MS) return cached.data; return null; } }
async function injectECH(originalBuf, queryName, ownerType, echConfig) { var echValue = null, echAlpn = null; if (ownerType === 'CF' && echConfig && echConfig.params) { for (var i = 0; i < echConfig.params.length; i++) { if (echConfig.params[i].key === 'ech') echValue = echConfig.params[i].val; if (echConfig.params[i].key === 'alpn') echAlpn = echConfig.params[i].val; } } else if (ownerType === 'META') { echValue = META_ECH_B64; echAlpn = 'h2,h3'; try { var id = new DataView(originalBuf).getUint16(0); var params = []; if (echAlpn) params.push({ key: 'alpn', val: echAlpn }); params.push({ key: 'ech', val: echValue }); return buildDNS(id, queryName, TYPE_HTTPS, [packHttpsParams(1, '.', params)], 300); } catch (_) { return originalBuf; } } if (!echValue) return originalBuf; try { var packet = parseDns(originalBuf); if (packet.header.ancount === 0) { var bparams = []; if (echAlpn) bparams.push({ key: 'alpn', val: echAlpn }); bparams.push({ key: 'ech', val: echValue }); return buildDNS(packet.header.id, queryName, TYPE_HTTPS, [packHttpsParams(1, '.', bparams)], 300); } var newRecords = [], httpsWritten = false; for (var a = 0; a < packet.answers.length; a++) { var answer = packet.answers[a]; var ownerName = decodeName(packet.view, answer.offset).name; if (answer.type !== TYPE_HTTPS) { newRecords.push({ name: ownerName, type: answer.type, rdata: expandRdataNames(packet.view, answer.rdataOffset, answer.rdlength, answer.type), ttl: answer.ttl }); continue; } var parsed = parseHttpsRdata(packet.view, answer.rdataOffset, answer.rdlength); if (!parsed) { newRecords.push({ name: ownerName, type: answer.type, rdata: copyRdata(packet.view, answer.rdataOffset, answer.rdlength), ttl: answer.ttl }); continue; } var kept = []; for (var j = 0; j < parsed.paramBytes.length; j++) { var key = new DataView(parsed.paramBytes[j].buffer, parsed.paramBytes[j].byteOffset, 2).getUint16(0); if (key !== SVC_KEY_ECH && key !== SVC_KEY_ALPN) kept.push(parsed.paramBytes[j]); } var echParam = encodeSvcParam('ech', echValue); if (echParam) kept.push(echParam); if (echAlpn) { var alpnParam = encodeSvcParam('alpn', echAlpn); if (alpnParam) kept.push(alpnParam); } newRecords.push({ name: ownerName, type: TYPE_HTTPS, rdata: buildHttpsRdata(parsed.priority, parsed.target, kept), ttl: answer.ttl }); httpsWritten = true; } if (!httpsWritten) { var params = []; if (echAlpn) params.push({ key: 'alpn', val: echAlpn }); params.push({ key: 'ech', val: echValue }); return buildDNS(packet.header.id, queryName, TYPE_HTTPS, [packHttpsParams(1, '.', params)], 300); } return createDNSResponseEx(packet.header.id, queryName, newRecords, packet.header.flags); } catch (_) { return originalBuf; } }
async function classifyHttpsName(name, clientIP) { try { var q = prepareQuery(buildWireQuery(name, TYPE_A), clientIP); var buf = await queryGoogle(q); return classifyResponse(buf); } catch (_) { return null; } }
async function handleDns(request) { var query = null; if (request.method === 'GET') query = buildQueryFromURL(new URL(request.url)); else if (request.method === 'POST') query = await request.arrayBuffer(); else return new Response('method not allowed', { status: 405 }); if (!query) return new Response('bad dns query', { status: 400 }); var meta = parseQueryMeta(query); if (!meta) return dnsResponse(servfail(query)); var clientIP = request.headers.get('CF-Connecting-IP') || ''; var prepared = prepareQuery(query, clientIP); try { var responseBuf = await queryGoogle(prepared); var owner = classifyResponse(responseBuf); var googleMatch = matchGoogleProxy(meta.name, GOOGLE_PROXY); if (meta.type === TYPE_A && googleMatch && googleMatch.ips) { var proxyBytes = googleMatch.ips.map(ipToBytes).filter(function(b) { return b; }); if (proxyBytes.length > 0) { var existingIps = extractIPBytes(responseBuf, TYPE_A); var seen = {}, combined = []; for (var pi = 0; pi < proxyBytes.length; pi++) { var pk = Array.prototype.join.call(proxyBytes[pi], '.'); if (!seen[pk]) { seen[pk] = true; combined.push(proxyBytes[pi]); } } for (var ei = 0; ei < existingIps.length; ei++) { var ek = Array.prototype.join.call(existingIps[ei], '.'); if (!seen[ek]) { seen[ek] = true; combined.push(existingIps[ei]); } } responseBuf = buildDNS(meta.id, meta.name, TYPE_A, combined, 300); owner = 'GOOGLE'; } } if (meta.type === TYPE_HTTPS) { if (!owner) owner = await classifyHttpsName(meta.name, clientIP); if (owner === 'CF') responseBuf = await injectECH(responseBuf, meta.name, 'CF', await fetchCFEch()); else if (owner === 'META') responseBuf = await injectECH(responseBuf, meta.name, 'META', null); } return dnsResponse(responseBuf); } catch (_) { return dnsResponse(servfail(query)); } }
export default { async fetch(request) { try { if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept' } }); return await handleDns(request); } catch (_) { return dnsResponse(servfail(null)); } } };
`;
}

(async function main() {
  console.log('Fetching Cloudflare CIDRs...');
  var cfCidrs = await fetchGeoipCidrs('cloudflare');
  console.log('Fetching Meta CIDRs...');
  var metaCidrs = await fetchGeoipCidrs('facebook');
  console.log('Fetching Cealing-Host Google proxy entries...');
  var googleProxy = await fetchGoogleProxy();
  console.log('Compiling CIDRs...');
  var cf = compileCidrs(cfCidrs);
  var meta = compileCidrs(metaCidrs);
  var out = snippetSource(cf, meta, googleProxy);
  var outPath = path.join(__dirname, 'doh-snippet.js');
  fs.writeFileSync(outPath, out, 'utf8');
  console.log('Generated ' + outPath);
  console.log('CF ranges: v4=' + cf.v4.length + ' v6=' + cf.v6.length + '; META ranges: v4=' + meta.v4.length + ' v6=' + meta.v6.length + '; Google proxy entries=' + googleProxy.length);
})().catch(function(err) {
  console.error(err && err.stack || err);
  process.exit(1);
});
