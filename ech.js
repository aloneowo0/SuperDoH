/** ECH injection module — fetches CF ECH, injects into HTTPS RR */
import { buildWireQuery, requireBytes, parseDns, encodeDnsName, buildDNS, decodeName } from './dns-lib.js';
import { HARD_TIMEOUT_MS, UPSTREAMS } from './config.js';
import { logEvent } from './logger.js';
import { validateResponse } from './edns.js';

const DNS_HEADER_LEN = 12;
const TYPE_HTTPS = 65;
const SVC_KEY_ALPN = 1;
const SVC_KEY_ECH = 5;
const CACHE_TTL_MS = 600000;
const STALE_TTL_MS = 3600000;
const CF_ECH_DOMAIN = 'cloudflare-ech.com';

export const META_ECH_B64 = 'AsH+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAD+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAD+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAD+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA/g0ASwYAIAAgti54XaD8VhwGEmxjGpaxUkuAz3VmpQSMOFSRgSPchR0ABAABAAEyHHNjb250ZW50LWxheDMtMi54eC5mYmNkbi5uZXQAAP4NAEgEACAAINQS+ceVTWrz9nffBM163+nvpZ9k5F5WK51t4DAGG3ReAAQAAQABZBl2aWRlby1sYXgzLTIueHguZmJjZG4ubmV0AAD+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAD+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=';
var META_ECH_DATE = '2026-05-30';
console.log('[ECH] Meta ECH config date: ' + META_ECH_DATE);

const echCache = new Map();

export async function fetchCFEch(_env, _ctx) {
    try {
        const cached = echCache.get(CF_ECH_DOMAIN);
        if (cached && (Date.now() - cached.ts) < CACHE_TTL_MS) {
            return cached.data;
        }

        var query = buildWireQuery(CF_ECH_DOMAIN, TYPE_HTTPS);
        var queryId = new DataView(query).getUint16(0);
        var entries = Object.entries(UPSTREAMS).slice(0, 3);
        var buf = null;
        var controller = new AbortController();
        var timer = setTimeout(function() { controller.abort(); }, HARD_TIMEOUT_MS);
        var deadline = Date.now() + HARD_TIMEOUT_MS;
        try {
        for (var i = 0; i < entries.length && !buf && Date.now() < deadline; i++) {
          try {
            var res = await fetch(entries[i][1].url, { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query, signal: controller.signal });
            if (res.status !== 200) continue;
            var ab = await res.arrayBuffer();
            var validation = validateResponse(ab, queryId, CF_ECH_DOMAIN, TYPE_HTTPS);
            if (validation.classification === 'positive') buf = ab;
          } catch (_) {}
        }
        } finally { clearTimeout(timer); }
        if (!buf) return getStaleCFEch(cached);

        const packet = parseDns(buf);
        if (!packet || packet.header.ancount === 0) return getStaleCFEch(cached);

        const ans = findHttpsAnswer(packet);
        if (!ans) return getStaleCFEch(cached);

        const httpsRdata = parseHttpsRdata(packet.view, ans.rdataOffset, ans.rdlength);
        if (!httpsRdata) return getStaleCFEch(cached);

        const params = [];
        for (let i = 0; i < httpsRdata.paramBytes.length; i++) {
            const pb = httpsRdata.paramBytes[i];
            if (pb.length < 4) continue;
            const pbView = new DataView(pb.buffer, pb.byteOffset, pb.byteLength);
            const keyId = pbView.getUint16(0);
            const valLen = pbView.getUint16(2);
            if (keyId !== SVC_KEY_ALPN && keyId !== SVC_KEY_ECH) continue;
            const valBytes = pb.subarray(4, 4 + valLen);
            const key = keyId === SVC_KEY_ALPN ? 'alpn' : 'ech';
            const val = key === 'alpn' ? decodeAlpn(valBytes) : encodeBase64Url(valBytes);
            params.push({ key: key, val: val });
        }

        var hasEch = params.some(function(p) { return p.key === 'ech' && p.val; });
        if (!hasEch) return getStaleCFEch(cached);

        const rdata = packHttpsParams(httpsRdata.priority, httpsRdata.target, params);

        const result = { rdata: rdata, params: params };
        echCache.set(CF_ECH_DOMAIN, { ts: Date.now(), data: result });
        return result;
    } catch (err) {
        logEvent('error', 'ech_error', { stage: 'fetchCFEch', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
        return getStaleCFEch(echCache.get(CF_ECH_DOMAIN));
    }
}

export function __resetCFEchCacheForTests() {
    echCache.clear();
}

function getStaleCFEch(cached) {
    if (!cached || !cached.data || (Date.now() - cached.ts) >= STALE_TTL_MS) return null;
    logEvent('warn', 'ech_result', { owner: 'CF', status: 'stale', reason: 'using_last_known_good' });
    return Object.assign({}, cached.data, { stale: true });
}

function findHttpsAnswer(packet) {
    for (let i = 0; i < packet.answers.length; i++) {
        if (packet.answers[i].type === TYPE_HTTPS) return packet.answers[i];
    }
    return null;
}

function decodeAlpn(bytes) {
    const ids = [];
    let o = 0;
    while (o < bytes.length) {
        const len = bytes[o]; o++;
        let s = '';
        for (let j = 0; j < len; j++) s += String.fromCharCode(bytes[o + j]);
        ids.push(s);
        o += len;
    }
    return ids.join(',');
}

function encodeBase64Url(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function rebuildTail(packet, startOffset) {
  var parts = [];
  var end = packet.view.byteLength;

  function adjoin() {
    var total = 0;
    for (var i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total);
    var pos = 0;
    for (var i = 0; i < parts.length; i++) {
      out.set(parts[i], pos);
      pos += parts[i].length;
    }
    return out;
  }

  // Use the ORIGINAL packet view for name decoding — compression pointers
  // reference absolute offsets in the full packet, not the tail slice.
  var fullView = packet.view;
  var offset = startOffset;
  while (offset < end) {
    var nameResult = decodeName(fullView, offset);
    requireBytes(fullView, nameResult.end, 10);
    var type = fullView.getUint16(nameResult.end);
    var ttl = fullView.getUint32(nameResult.end + 4);
    var rdlength = fullView.getUint16(nameResult.end + 8);
    var rdataOffset = nameResult.end + 10;
    requireBytes(fullView, rdataOffset, rdlength);

    var expandedRdata = expandRdataNames(fullView, rdataOffset, rdlength, type);
    var ownerBytes = encodeDnsName(nameResult.name);

    var rr = new Uint8Array(ownerBytes.length + 10 + expandedRdata.length);
    rr.set(ownerBytes, 0);
    var dv = new DataView(rr.buffer);
    dv.setUint16(ownerBytes.length, type);
    dv.setUint16(ownerBytes.length + 2, fullView.getUint16(nameResult.end + 2));
    dv.setUint32(ownerBytes.length + 4, ttl);
    dv.setUint16(ownerBytes.length + 8, expandedRdata.length);
    rr.set(expandedRdata, ownerBytes.length + 10);

    parts.push(rr);
    offset = rdataOffset + rdlength;
  }

  return adjoin();
}

export async function injectECH(originalResponse, queryName, ownerType, echConfig, ctx) {
    try {
        let echValue = null;
        let echAlpn = null;

        if (ownerType === 'CF' && echConfig && echConfig.params) {
            for (let i = 0; i < echConfig.params.length; i++) {
                const p = echConfig.params[i];
                if (p.key === 'ech') echValue = p.val;
                if (p.key === 'alpn') echAlpn = p.val;
            }
        } else if (ownerType === 'META') {
            echValue = META_ECH_B64;
            echAlpn = 'h2,h3';

            // Build fresh HTTPS RR from scratch — discarding CNAME chain
            // avoids DNS CNAME conflict that causes Chromium to discard ECH
            const body = await readBody(originalResponse);
            if (!body || body.byteLength < 2) return { body: originalResponse, changed: false, status: 'failed' };
            var id = new DataView(body).getUint16(0);
            const params = [];
            if (echAlpn) params.push({ key: 'alpn', val: echAlpn });
            params.push({ key: 'ech', val: echValue });
            const echRdata = packHttpsParams(1, '.', params);
            const newBody = buildDNS(id, queryName, TYPE_HTTPS, [echRdata], 300);
            return {
                body: new Response(newBody, {
                    headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' }
                }),
                changed: true,
                status: 'built'
            };
        }

        if (!echValue) return { body: originalResponse, changed: false, status: 'unchanged' };

        const body = await readBody(originalResponse);
        if (!body) return { body: originalResponse, changed: false, status: 'unchanged' };

        const packet = parseDns(body);
        if (!packet) return { body: originalResponse, changed: false, status: 'failed' };
        if (packet.header.ancount === 0) {
          const params = [];
          if (echAlpn) params.push({ key: 'alpn', val: echAlpn });
          params.push({ key: 'ech', val: echValue });
          const echRdata = packHttpsParams(1, '.', params);
          const newBody = buildDNS(packet.header.id, queryName, TYPE_HTTPS, [echRdata], 300);
          return {
            body: new Response(newBody, {
              headers: {
                'Content-Type': 'application/dns-message',
                'Access-Control-Allow-Origin': '*'
              }
            }),
            changed: true,
            status: 'built'
          };
        }

        const newRecords = [];
        var httpsWritten = false;
        let ttl = 3600;

        for (let i = 0; i < packet.answers.length; i++) {
            const answer = packet.answers[i];
            const ownerName = decodeName(packet.view, answer.offset).name;
            if (answer.type !== TYPE_HTTPS) {
                newRecords.push({ name: ownerName, type: answer.type, rdata: expandRdataNames(packet.view, answer.rdataOffset, answer.rdlength, answer.type), ttl: answer.ttl });
                continue;
            }

            ttl = answer.ttl;

            const httpsRdata = parseHttpsRdata(packet.view, answer.rdataOffset, answer.rdlength);
            if (!httpsRdata) {
                const raw = packet.bytes.slice(answer.rdataOffset, answer.end);
                newRecords.push({ name: ownerName, type: answer.type, rdata: new Uint8Array(raw), ttl: answer.ttl });
                continue;
            }

            const keptParams = [];
            for (let j = 0; j < httpsRdata.paramBytes.length; j++) {
                const pb = httpsRdata.paramBytes[j];
                const key = new DataView(pb.buffer, pb.byteOffset, 2).getUint16(0);
                if (key !== SVC_KEY_ECH && key !== SVC_KEY_ALPN) {
                    keptParams.push(pb);
                }
            }

            const echParam = encodeSvcParam('ech', echValue);
            if (echParam) keptParams.push(echParam);

            if (echAlpn) {
                const alpnParam = encodeSvcParam('alpn', echAlpn);
                if (alpnParam) keptParams.push(alpnParam);
            }

            keptParams.sort(function (a, b) {
                const ka = new DataView(a.buffer, a.byteOffset, 2).getUint16(0);
                const kb = new DataView(b.buffer, b.byteOffset, 2).getUint16(0);
                return ka - kb;
            });

            const newRdata = buildHttpsRdata(httpsRdata.priority, httpsRdata.target, keptParams);
            newRecords.push({ name: ownerName, type: TYPE_HTTPS, rdata: newRdata, ttl: ttl });
            httpsWritten = true;
        }

        if (!httpsWritten) {
          // Build new HTTPS RR from scratch when no valid one to inject into
          const params = [];
          if (echAlpn) params.push({ key: 'alpn', val: echAlpn });
          params.push({ key: 'ech', val: echValue });
          const echRdata = packHttpsParams(1, '.', params);
          const newBody = buildDNS(packet.header.id, queryName, TYPE_HTTPS, [echRdata], 300);
          return {
            body: new Response(newBody, {
              headers: {
                'Content-Type': 'application/dns-message',
                'Access-Control-Allow-Origin': '*'
              }
            }),
            changed: true,
            status: 'built'
          };
        }

        var lastAnswerEnd = packet.answers.length > 0 ? packet.answers[packet.answers.length - 1].end : 0;
        var rebuiltTail = lastAnswerEnd > 0 && packet.view.byteLength > lastAnswerEnd
          ? rebuildTail(packet, lastAnswerEnd)
          : new Uint8Array(0);
        var tailNsCount = rebuiltTail.length > 0 ? (packet.header.nscount || 0) : 0;
        var tailArCount = rebuiltTail.length > 0 ? (packet.header.arcount || 0) : 0;
        const newBody = createDNSResponseEx(
            packet.header.id,
            queryName,
            newRecords,
            rebuiltTail,
            packet.header.flags,
            tailNsCount,
            tailArCount
        );

        return {
          body: new Response(newBody, {
            headers: {
              'Content-Type': 'application/dns-message',
              'Access-Control-Allow-Origin': '*'
            }
          }),
          changed: true,
          status: 'injected'
        };
    } catch (err) {
        logEvent('error', 'ech_error', { requestId: ctx && ctx.requestId, stage: 'injectECH', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err), fallbackAction: 'return_original_response' });
        return { body: originalResponse, changed: false, status: 'failed' };
    }
}

function encodeSvcParam(key, value) {
    const ids = { 'alpn': SVC_KEY_ALPN, 'ech': SVC_KEY_ECH };
    const id = ids[key];
    if (!id) return null;

    let valBuf;

    if (key === 'alpn') {
        const parts = value.split(',');
        let total = 0;
        for (let i = 0; i < parts.length; i++) total += parts[i].length + 1;
        valBuf = new Uint8Array(total);
        let o = 0;
        for (let i = 0; i < parts.length; i++) {
            const p = parts[i];
            valBuf[o] = p.length;
            o++;
            for (let j = 0; j < p.length; j++) {
                valBuf[o] = p.charCodeAt(j);
                o++;
            }
        }
    } else {
        const s = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
        valBuf = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) {
            valBuf[i] = s.charCodeAt(i);
        }
    }

    const res = new Uint8Array(4 + valBuf.length);
    const v = new DataView(res.buffer);
    v.setUint16(0, id);
    v.setUint16(2, valBuf.length);
    res.set(valBuf, 4);
    return res;
}

function packHttpsParams(priority, target, params) {
    const targetBuf = target === '.' ? new Uint8Array([0]) : encodeDnsName(target);
    const paramBufs = [];
    for (let i = 0; i < params.length; i++) {
        const p = params[i];
        if (p instanceof Uint8Array) {
            paramBufs.push(p);
        } else {
            const encoded = encodeSvcParam(p.key, p.val);
            if (encoded) paramBufs.push(encoded);
        }
    }
    paramBufs.sort(function (a, b) {
        return new DataView(a.buffer, a.byteOffset, 2).getUint16(0) -
               new DataView(b.buffer, b.byteOffset, 2).getUint16(0);
    });

    let totalLen = 2 + targetBuf.length;
    for (let i = 0; i < paramBufs.length; i++) totalLen += paramBufs[i].length;

    const res = new Uint8Array(totalLen);
    const v = new DataView(res.buffer);
    v.setUint16(0, priority);
    res.set(targetBuf, 2);
    let offset = 2 + targetBuf.length;
    for (let i = 0; i < paramBufs.length; i++) {
        res.set(paramBufs[i], offset);
        offset += paramBufs[i].length;
    }
    return res;
}

function buildHttpsRdata(priority, target, paramBytes) {
    const targetBuf = target === '.' ? new Uint8Array([0]) : encodeDnsName(target);

    let totalLen = 2 + targetBuf.length;
    for (let i = 0; i < paramBytes.length; i++) totalLen += paramBytes[i].length;

    const res = new Uint8Array(totalLen);
    const v = new DataView(res.buffer);
    v.setUint16(0, priority);
    res.set(targetBuf, 2);
    let offset = 2 + targetBuf.length;
    for (let i = 0; i < paramBytes.length; i++) {
        res.set(paramBytes[i], offset);
        offset += paramBytes[i].length;
    }
    return res;
}

function createDNSResponseEx(id, qName, records, nsArBytes, flags, nsCount, arCount) {
    const encName = encodeDnsName(qName);
    const tailBytes = nsArBytes || new Uint8Array(0);

    let totalLen = DNS_HEADER_LEN + encName.length + 4 + tailBytes.length;
    for (let i = 0; i < records.length; i++) {
        const rec = records[i];
        const rd = rec.rdata;
        const ownerLen = rec.name && rec.name !== qName ? encodeDnsName(rec.name).length : 2;
        totalLen += ownerLen + 2 + 2 + 4 + 2 + (rd.byteLength || rd.length);
    }

    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);
    var newFlags = (flags || 0x8180) & ~0x0200;
    newFlags = newFlags & ~0x000F;
    newFlags |= 0x8000;
    const tailNsCount = tailBytes.length ? (nsCount || 0) : 0;
    const tailArCount = tailBytes.length ? (arCount || 0) : 0;

    v.setUint16(0, id);
    v.setUint16(2, newFlags);
    v.setUint16(4, 1);
    v.setUint16(6, records.length);
    v.setUint16(8, tailNsCount);
    v.setUint16(10, tailArCount);

    let offset = DNS_HEADER_LEN;

    buf.set(encName, offset); offset += encName.length;
    v.setUint16(offset, TYPE_HTTPS); offset += 2;
    v.setUint16(offset, 1); offset += 2;

    for (let i = 0; i < records.length; i++) {
        const rec = records[i];
        const rd = rec.rdata;
        const rdLen = rd.byteLength || rd.length;

        if (rec.name && rec.name !== qName) {
            var encOwner = encodeDnsName(rec.name);
            buf.set(encOwner, offset); offset += encOwner.length;
        } else {
            v.setUint16(offset, 0xC00C); offset += 2;
        }
        v.setUint16(offset, rec.type); offset += 2;
        v.setUint16(offset, 1); offset += 2;
        v.setUint32(offset, rec.ttl); offset += 4;
        v.setUint16(offset, rdLen); offset += 2;
        buf.set(rd, offset); offset += rdLen;
    }
    buf.set(tailBytes, offset);
    return buf.buffer;
}

function copyRdata(view, rdataOffset, rdlength) {
    return new Uint8Array(view.buffer.slice(view.byteOffset + rdataOffset, view.byteOffset + rdataOffset + rdlength));
}

function expandRdataNames(view, rdataOffset, rdlength, rrType) {
    if (rrType !== 5 && rrType !== 2 && rrType !== 12 && rrType !== 15 && rrType !== 33 && rrType !== 6) {
        return copyRdata(view, rdataOffset, rdlength);
    }

    if (rrType === 5 || rrType === 2 || rrType === 12) {
        var name = decodeName(view, rdataOffset);
        return encodeDnsName(name.name);
    }

    if (rrType === 15) {
        requireBytes(view, rdataOffset, 2);
        var pref = view.getUint16(rdataOffset);
        var mxName = decodeName(view, rdataOffset + 2);
        var encodedMx = encodeDnsName(mxName.name);
        var mxResult = new Uint8Array(2 + encodedMx.length);
        new DataView(mxResult.buffer).setUint16(0, pref);
        mxResult.set(encodedMx, 2);
        return mxResult;
    }

    if (rrType === 33) {
        requireBytes(view, rdataOffset, 6);
        var srvName = decodeName(view, rdataOffset + 6);
        var encodedSrv = encodeDnsName(srvName.name);
        var srvResult = new Uint8Array(6 + encodedSrv.length);
        srvResult.set(copyRdata(view, rdataOffset, 6), 0);
        srvResult.set(encodedSrv, 6);
        return srvResult;
    }

    if (rrType === 6) {
        var mname = decodeName(view, rdataOffset);
        var rname = decodeName(view, mname.end);
        var encodedMname = encodeDnsName(mname.name);
        var encodedRname = encodeDnsName(rname.name);
        var fixedOffset = rname.end;
        requireBytes(view, fixedOffset, 20);
        var soaResult = new Uint8Array(encodedMname.length + encodedRname.length + 20);
        var soaOffset = 0;
        soaResult.set(encodedMname, soaOffset); soaOffset += encodedMname.length;
        soaResult.set(encodedRname, soaOffset); soaOffset += encodedRname.length;
        soaResult.set(copyRdata(view, fixedOffset, 20), soaOffset);
        return soaResult;
    }

    return copyRdata(view, rdataOffset, rdlength);
}

function parseHttpsRdata(view, rdataOffset, rdlength) {
    try {
        const end = rdataOffset + rdlength;
        let offset = rdataOffset;

        requireBytes(view, offset, 2);
        const priority = view.getUint16(offset);
        offset += 2;

        const decoded = decodeName(view, offset);
        const target = decoded.name || '.';
        offset = decoded.end;

        const paramBytes = [];
        while (offset < end) {
            requireBytes(view, offset, 4);
            const valLen = view.getUint16(offset + 2);
            const paramLen = 4 + valLen;
            requireBytes(view, offset, paramLen);

            const raw = new Uint8Array(view.buffer, view.byteOffset + offset, paramLen);
            paramBytes.push(raw.slice());
            offset += paramLen;
        }

        return { priority: priority, target: target, paramBytes: paramBytes };
    } catch (err) {
        logEvent('error', 'ech_error', { stage: 'parseHttpsRdata', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
        return null;
    }
}

function readBody(input) {
    try {
        if (input instanceof Response) return input.clone().arrayBuffer();
        if (input instanceof ArrayBuffer) return input;
        if (ArrayBuffer.isView(input)) return input.buffer;
        return null;
    } catch (err) {
        logEvent('error', 'ech_error', { stage: 'readBody', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
        return null;
    }
}
