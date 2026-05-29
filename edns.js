import { BLOCKED_RANGES, ECS_PREFIX4, ECS_PREFIX6 } from './config.js';

const DNS_HEADER_LEN = 12;
const TYPE_A = 1;
const TYPE_OPT = 41;
const TYPE_AAAA = 28;
const OPT_ECS = 8;
const UDP_PAYLOAD_SIZE = 4096;
const DO_BIT = 0x8000;
const MAX_NAME_JUMPS = 128;

function autoMode(body, clientIP) {
    try {
        const ecs = makeEcsOption(clientIP);
        if (!ecs) return body;

        const packet = parseDns(body);
        if (packet.opt) {
            if (readOptions(packet.view, packet.opt).hasEcs) return body;
            return appendOption(packet, packet.opt, ecs).buffer;
        }

        return appendOpt(packet, ecs, 0).buffer;
    } catch (_) {
        return body;
    }
}

export function prepareQuery(body, clientIP) {
    try {
        const prepared = autoMode(body, clientIP);
        let packet = parseDns(prepared);

        if (!packet.opt) return appendOpt(packet, new Uint8Array(0), DO_BIT).buffer;

        const ttl = packet.view.getUint32(packet.opt.headerOffset + 4);
        if (packet.opt.cls !== UDP_PAYLOAD_SIZE || (ttl & DO_BIT) === 0) {
            const bytes = new Uint8Array(packet.bytes);
            const view = new DataView(bytes.buffer);
            view.setUint16(packet.opt.headerOffset + 2, UDP_PAYLOAD_SIZE);
            view.setUint32(packet.opt.headerOffset + 4, ttl | DO_BIT);
            return bytes.buffer;
        }

        return prepared;
    } catch (_) {
        return body;
    }
}

export function filterAnswers(response) {
    try {
        const packet = parseDns(response);
        for (const answer of packet.answers) {
            if (answer.type === TYPE_A && answer.rdlength === 4) {
                const addr = packet.bytes.subarray(answer.rdataOffset, answer.end);
                if (matchesBlockedRange(4, addr)) return { passed: false, reason: 'blocked_ip' };
            }
            if (answer.type === TYPE_AAAA && answer.rdlength === 16) {
                const addr = packet.bytes.subarray(answer.rdataOffset, answer.end);
                if (matchesBlockedRange(6, addr)) return { passed: false, reason: 'blocked_ip' };
            }
        }
    } catch (_) {
        return { passed: false, reason: 'parse_error' };
    }

    return { passed: true, reason: null };
}

function parseDns(body) {
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

function readRecord(view, offset) {
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

function skipName(view, start) {
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

function readOptions(view, opt) {
    let offset = opt.rdataOffset;
    const end = opt.end;
    const result = { hasEcs: false };

    while (offset < end) {
        requireBytes(view, offset, 4);
        const code = view.getUint16(offset);
        const len = view.getUint16(offset + 2);
        const dataOffset = offset + 4;
        if (dataOffset + len > end) throw new Error('bad EDNS option length');
        if (code === OPT_ECS) result.hasEcs = true;
        offset = dataOffset + len;
    }

    return result;
}

function appendOption(packet, opt, option) {
    if (opt.rdlength + option.length > 0xFFFF) throw new Error('OPT RDLEN overflow');

    const out = new Uint8Array(packet.bytes.length + option.length);
    out.set(packet.bytes.subarray(0, opt.end));
    out.set(option, opt.end);
    out.set(packet.bytes.subarray(opt.end), opt.end + option.length);

    const view = new DataView(out.buffer);
    view.setUint16(opt.headerOffset + 8, opt.rdlength + option.length);
    return out;
}

function appendOpt(packet, options, ttl) {
    if (packet.header.arcount === 0xFFFF) throw new Error('ARCOUNT overflow');

    const record = new Uint8Array(11 + options.length);
    const recordView = new DataView(record.buffer);
    record[0] = 0;
    recordView.setUint16(1, TYPE_OPT);
    recordView.setUint16(3, UDP_PAYLOAD_SIZE);
    recordView.setUint32(5, ttl);
    recordView.setUint16(9, options.length);
    record.set(options, 11);

    const out = joinBytes(packet.bytes, record);
    const outView = new DataView(out.buffer);
    outView.setUint16(10, packet.header.arcount + 1);
    return out;
}

function makeEcsOption(clientIP) {
    const ip = extractClientIP(clientIP);
    if (!ip) return null;

    if (ip.includes(':')) return makeEcsOption6(ip);
    return makeEcsOption4(ip);
}

function makeEcsOption4(ip) {
    const addr = parsePublicIPv4(ip);
    if (!addr) return null;

    const prefix = ECS_PREFIX4;
    const addrLen = Math.ceil(prefix / 8);
    const optionLen = 4 + addrLen;
    const option = new Uint8Array(4 + optionLen);
    const view = new DataView(option.buffer);

    view.setUint16(0, OPT_ECS);
    view.setUint16(2, optionLen);
    view.setUint16(4, 1);
    option[6] = prefix;
    option[7] = 0;
    option.set(addr.subarray(0, addrLen), 8);

    if (prefix % 8 !== 0 && addrLen > 0) {
        option[7 + addrLen] &= (0xFF << (8 - (prefix % 8))) & 0xFF;
    }

    return option;
}

function makeEcsOption6(ip) {
    const addr = parsePublicIPv6(ip);
    if (!addr) return null;

    const prefix = ECS_PREFIX6;
    const addrLen = Math.ceil(prefix / 8);
    const optionLen = 4 + addrLen;
    const option = new Uint8Array(4 + optionLen);
    const view = new DataView(option.buffer);

    view.setUint16(0, OPT_ECS);
    view.setUint16(2, optionLen);
    view.setUint16(4, 2);
    option[6] = prefix;
    option[7] = 0;
    option.set(addr.subarray(0, addrLen), 8);

    if (prefix % 8 !== 0 && addrLen > 0) {
        option[7 + addrLen] &= (0xFF << (8 - (prefix % 8))) & 0xFF;
    }

    return option;
}

function parsePublicIPv4(value) {
    const ip = extractClientIP(value);
    if (!ip || ip.includes(':')) return null;

    const parts = ip.split('.');
    if (parts.length !== 4) return null;

    const addr = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        if (!/^\d{1,3}$/.test(parts[i])) return null;
        const n = Number(parts[i]);
        if (n < 0 || n > 255) return null;
        addr[i] = n;
    }

    const [a, b, c] = addr;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return null;
    if (a === 100 && b >= 64 && b <= 127) return null;
    if (a === 169 && b === 254) return null;
    if (a === 172 && b >= 16 && b <= 31) return null;
    if (a === 192 && b === 168) return null;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return null;
    if (a === 192 && b === 88 && c === 99) return null;
    if (a === 198 && (b === 18 || b === 19)) return null;
    if (a === 198 && b === 51 && c === 100) return null;
    if (a === 203 && b === 0 && c === 113) return null;

    return addr;
}

function parsePublicIPv6(value) {
    const ip = extractClientIP(value);
    if (!ip || !ip.includes(':')) return null;

    const parts = ip.split('::');
    if (parts.length > 2) return null;
    const left = parts[0] ? parts[0].split(':').filter(g => g !== '') : [];
    const right = parts[1] ? parts[1].split(':').filter(g => g !== '') : [];
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;

    const groups = [...left, ...Array(fill).fill('0'), ...right];
    const addr = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
        const val = parseInt(groups[i] || '0', 16);
        if (isNaN(val)) return null;
        addr[i * 2] = (val >> 8) & 0xFF;
        addr[i * 2 + 1] = val & 0xFF;
    }

    if (addr[0] === 0xFE && (addr[1] & 0xC0) === 0x80) return null;
    if (addr.every(b => b === 0)) return null;
    if (addr[0] === 0 && addr[1] === 0 && addr[2] === 0 && addr[3] === 0 &&
        addr[4] === 0 && addr[5] === 0 && addr[6] === 0 && addr[7] === 0 &&
        addr[8] === 0 && addr[9] === 0 && addr[10] === 0 && addr[11] === 0 &&
        addr[12] === 0 && addr[13] === 0 && addr[14] === 0 && addr[15] === 1) return null;
    if (addr[0] === 0xFD) return null;
    if (addr[0] === 0xFC) return null;

    return addr;
}

function extractClientIP(value) {
    if (typeof value === 'string') return value.trim();
    return '';
}

function matchesBlockedRange(family, addr) {
    for (const range of BLOCKED_RANGES) {
        if (range.family === family && matchesRange(addr, range.addr, range.mask)) return true;
    }
    return false;
}

function matchesRange(addr, target = [], mask) {
    let bits = mask;
    for (let i = 0; i < addr.length && bits > 0; i++) {
        const take = Math.min(bits, 8);
        const byteMask = (0xFF << (8 - take)) & 0xFF;
        if ((addr[i] & byteMask) !== ((target[i] || 0) & byteMask)) return false;
        bits -= take;
    }
    return bits <= 0;
}

function joinBytes(...chunks) {
    let len = 0;
    for (const chunk of chunks) len += chunk.length;

    const out = new Uint8Array(len);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function toBytes(body) {
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    throw new Error('body must be ArrayBuffer');
}

function requireBytes(view, offset, len) {
    if (offset < 0 || len < 0 || offset + len > view.byteLength) throw new Error('DNS packet out of bounds');
}
