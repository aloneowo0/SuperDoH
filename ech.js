/** ECH injection module — fetches CF ECH, injects into HTTPS RR */
import { resolveDNSWire, requireBytes, parseDns, encodeDnsName, buildDNS } from './dns-lib.js';

const DNS_HEADER_LEN = 12;
const TYPE_HTTPS = 65;
const MAX_NAME_JUMPS = 128;
const SVC_KEY_ALPN = 1;
const SVC_KEY_ECH = 5;
const CACHE_TTL_MS = 600000;
const CF_ECH_DOMAIN = 'cloudflare-ech.com';

export const META_ECH_B64 = 'AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=';

const echCache = new Map();

export async function fetchCFEch(_env, _ctx) {
    try {
        const cached = echCache.get(CF_ECH_DOMAIN);
        if (cached && (Date.now() - cached.ts) < CACHE_TTL_MS) {
            return cached.data;
        }

        const buf = await resolveDNSWire(CF_ECH_DOMAIN, TYPE_HTTPS);
        if (!buf) return null;

        const packet = parseDns(buf);
        if (!packet || packet.header.ancount === 0) return null;

        const ans = findHttpsAnswer(packet);
        if (!ans) return null;

        const httpsRdata = parseHttpsRdata(packet.view, ans.rdataOffset, ans.rdlength);
        if (!httpsRdata) return null;

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

        if (params.length === 0) return null;

        const rdata = packHttpsParams(httpsRdata.priority, httpsRdata.target, params);

        const result = { rdata: rdata, params: params };
        echCache.set(CF_ECH_DOMAIN, { ts: Date.now(), data: result });
        return result;
    } catch (_) {
        return null;
    }
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

export async function injectECH(originalResponse, queryName, ownerType, echConfig) {
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
        }

        if (!echValue) return originalResponse;

        const body = await readBody(originalResponse);
        if (!body) return originalResponse;

        const packet = parseDns(body);
        if (!packet) return originalResponse;
        if (packet.header.ancount === 0) {
          const params = [];
          if (echAlpn) params.push({ key: 'alpn', val: echAlpn });
          params.push({ key: 'ech', val: echValue });
          const echRdata = packHttpsParams(1, '.', params);
          const newBody = buildDNS(packet.header.id, queryName, TYPE_HTTPS, [echRdata], 300);
          return new Response(newBody, {
            headers: {
              'Content-Type': 'application/dns-message',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }

        const newRecords = [];
        let ttl = 3600;

        for (let i = 0; i < packet.answers.length; i++) {
            const answer = packet.answers[i];
            if (answer.type !== TYPE_HTTPS) {
                const raw = packet.bytes.slice(answer.rdataOffset, answer.end);
                newRecords.push({ type: answer.type, rdata: new Uint8Array(raw), ttl: answer.ttl });
                continue;
            }

            ttl = answer.ttl;

            const httpsRdata = parseHttpsRdata(packet.view, answer.rdataOffset, answer.rdlength);
            if (!httpsRdata) {
                const raw = packet.bytes.slice(answer.rdataOffset, answer.end);
                newRecords.push({ type: answer.type, rdata: new Uint8Array(raw), ttl: answer.ttl });
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
            newRecords.push({ type: TYPE_HTTPS, rdata: newRdata, ttl: ttl });
        }

        if (newRecords.length === 0) return originalResponse;

        const newBody = createDNSResponseEx(packet.header.id, queryName, newRecords);

        return new Response(newBody, {
            headers: {
                'Content-Type': 'application/dns-message',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (_) {
        return originalResponse;
    }
}

function decodeDnsName(view, offset) {
    const parts = [];
    let jumped = false;
    let end = offset;
    let jumps = 0;

    while (true) {
        requireBytes(view, offset, 1);
        const len = view.getUint8(offset);

        if ((len & 0xC0) === 0xC0) {
            requireBytes(view, offset, 2);
            const pointer = ((len & 0x3F) << 8) | view.getUint8(offset + 1);
            if (pointer >= view.byteLength) throw new Error('bad compression pointer');
            if (!jumped) end = offset + 2;
            offset = pointer;
            jumped = true;
            jumps++;
            if (jumps > MAX_NAME_JUMPS) throw new Error('compression loop');
            continue;
        }

        if ((len & 0xC0) !== 0) {
            throw new Error('unsupported label type');
        }

        if (len === 0) {
            if (!jumped) end = offset + 1;
            offset++;
            break;
        }

        offset++;
        requireBytes(view, offset, len);
        let label = '';
        for (let i = 0; i < len; i++) {
            label += String.fromCharCode(view.getUint8(offset + i));
        }
        parts.push(label);

        if (!jumped) end = offset + len;
        offset += len;
    }

    return { name: parts.join('.'), end: end };
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

function createDNSResponseEx(id, qName, records) {
    const encName = encodeDnsName(qName);

    let totalLen = DNS_HEADER_LEN + encName.length + 4;
    for (let i = 0; i < records.length; i++) {
        const rd = records[i].rdata;
        totalLen += 2 + 2 + 2 + 4 + 2 + (rd.byteLength || rd.length);
    }

    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);

    v.setUint16(0, id);
    v.setUint16(2, 0x8180);
    v.setUint16(4, 1);
    v.setUint16(6, records.length);
    v.setUint16(8, 0);
    v.setUint16(10, 0);

    let offset = DNS_HEADER_LEN;

    buf.set(encName, offset); offset += encName.length;
    v.setUint16(offset, records[0].type); offset += 2;
    v.setUint16(offset, 1); offset += 2;

    for (let i = 0; i < records.length; i++) {
        const rec = records[i];
        const rd = rec.rdata;
        const rdLen = rd.byteLength || rd.length;

        v.setUint16(offset, 0xC00C); offset += 2;
        v.setUint16(offset, rec.type); offset += 2;
        v.setUint16(offset, 1); offset += 2;
        v.setUint32(offset, rec.ttl); offset += 4;
        v.setUint16(offset, rdLen); offset += 2;
        buf.set(rd, offset); offset += rdLen;
    }
    return buf.buffer;
}

function parseHttpsRdata(view, rdataOffset, rdlength) {
    try {
        const end = rdataOffset + rdlength;
        let offset = rdataOffset;

        requireBytes(view, offset, 2);
        const priority = view.getUint16(offset);
        offset += 2;

        const decoded = decodeDnsName(view, offset);
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
    } catch (_) {
        return null;
    }
}

function readBody(input) {
    try {
        if (input instanceof Response) return input.clone().arrayBuffer();
        if (input instanceof ArrayBuffer) return input;
        if (ArrayBuffer.isView(input)) return input.buffer;
        return null;
    } catch (_) {
        return null;
    }
}


