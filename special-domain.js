/** Special domain handling — remap, CDN owner detection, CIDR matching */

import { UPSTREAMS, HARD_TIMEOUT_MS } from './config.js';

const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_HTTPS = 65;
const CACHE_TTL = 300_000;
const PROBE_CACHE_TTL = 3600 * 1000;

const RAW_META_CIDRS = [
    '31.13.24.0/21', '31.13.64.0/18', '45.64.40.0/22',
    '57.141.0.0/24', '57.141.2.0/23', '57.141.4.0/22',
    '57.141.8.0/21', '57.141.16.0/23', '57.144.0.0/14',
    '66.220.144.0/20', '69.63.176.0/20', '69.171.224.0/19',
    '74.119.76.0/22', '102.132.96.0/20', '102.132.112.0/24',
    '102.132.114.0/23', '102.132.116.0/23', '102.132.119.0/24',
    '102.132.120.0/23', '102.132.123.0/24', '102.132.125.0/24',
    '102.132.126.0/23', '102.221.188.0/22', '103.4.96.0/22',
    '129.134.0.0/17', '129.134.130.0/24', '129.134.135.0/24',
    '129.134.136.0/22', '129.134.140.0/24', '129.134.143.0/24',
    '129.134.144.0/24', '129.134.147.0/24', '129.134.148.0/23',
    '129.134.154.0/23', '129.134.156.0/22', '129.134.160.0/22',
    '129.134.164.0/23', '129.134.168.0/21', '129.134.176.0/20',
    '129.134.194.0/24', '157.240.0.0/17', '157.240.128.0/23',
    '157.240.131.0/24', '157.240.132.0/24', '157.240.134.0/24',
    '157.240.136.0/23', '157.240.139.0/24', '157.240.156.0/23',
    '157.240.159.0/24', '157.240.169.0/24', '157.240.175.0/24',
    '157.240.177.0/24', '157.240.179.0/24', '157.240.181.0/24',
    '157.240.182.0/23', '157.240.184.0/21', '157.240.192.0/18',
    '163.70.128.0/17', '163.77.132.0/23', '163.77.136.0/23',
    '163.114.128.0/20', '173.252.64.0/18', '179.60.192.0/22',
    '185.60.216.0/22', '185.89.216.0/22', '199.201.64.0/22',
    '204.15.20.0/22',
    '2620:0:1c00::/40', '2620:10d:c090::/44',
    '2a03:2880::/32', '2a03:2887:ff00::/48',
    '2a03:2887:ff02::/48', '2a03:2887:ff04::/46',
    '2a03:2887:ff09::/48', '2a03:2887:ff0a::/48',
    '2a03:2887:ff1b::/48', '2a03:2887:ff1c::/48',
    '2a03:2887:ff1e::/48', '2a03:2887:ff20::/48',
    '2a03:2887:ff22::/47', '2a03:2887:ff27::/48',
    '2a03:2887:ff28::/46', '2a03:2887:ff2f::/48',
    '2a03:2887:ff30::/48', '2a03:2887:ff33::/48',
    '2a03:2887:ff37::/48', '2a03:2887:ff38::/46',
    '2a03:2887:ff3f::/48', '2a03:2887:ff40::/46',
    '2a03:2887:ff44::/47', '2a03:2887:ff48::/46',
    '2a03:2887:ff4d::/48', '2a03:2887:ff4e::/47',
    '2a03:2887:ff50::/45', '2a03:2887:ff58::/47',
    '2a03:2887:ff5a::/48', '2a03:2887:ff5f::/48',
    '2a03:2887:ff60::/48', '2a03:2887:ff62::/47',
    '2a03:2887:ff64::/46', '2a03:2887:ff68::/47',
    '2a03:2887:ff6a::/48', '2a03:2887:ff70::/47',
    '2c0f:ef78:3::/48', '2c0f:ef78:5::/48',
    '2c0f:ef78:9::/48', '2c0f:ef78:c::/47',
    '2c0f:ef78:e::/48', '2c0f:ef78:10::/47',
];

const RAW_CF_CIDRS = [
    '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13',
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
    '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
    '2c0f:f248::/32',
];

const ipCache = new Map();
const probeCache = new Map();

const COMPILED_META = compileCidrs(RAW_META_CIDRS);
const COMPILED_CF = compileCidrs(RAW_CF_CIDRS);

export async function remapResponse(originalBody, queryName, queryType, preferredDomain, echRdata) {
    try {
        const id = parseQueryId(originalBody);

        if (queryType === TYPE_AAAA) {
            return createDNSResponse(id, queryName, TYPE_AAAA, [], 3600);
        }

        if (queryType === TYPE_HTTPS) {
            if (echRdata && echRdata.length > 0) {
                return createDNSResponse(id, queryName, TYPE_HTTPS, [echRdata], 3600);
            }
            return createDNSResponse(id, queryName, TYPE_HTTPS, [], 60);
        }

        if (queryType === TYPE_A) {
            if (!preferredDomain) return null;
            const ips = await resolvePreferredIPs(preferredDomain, TYPE_A);
            if (!ips || ips.length === 0) return null;
            return createDNSResponse(id, queryName, TYPE_A, ips, 60);
        }

        return null;
    } catch (_) {
        return null;
    }
}

/**
 * Resolve a domain's A (type=1) or AAAA (type=28) records via Google DoH JSON API.
 * Returns an array of IP bytes (Uint8Array[]) or null on failure.
 * Results are cached for 300 seconds.
 */
export async function resolvePreferredIPs(domain, type) {
    try {
        const cacheKey = `${domain}|${type}`;
        const cached = ipCache.get(cacheKey);
        if (cached && Date.now() < cached.expires) {
            return cached.ips;
        }

        const buf = await resolveDNSWire(domain, type);
        if (!buf) return null;

        const ips = extractIPBytes(buf, type);
        if (ips.length > 0) {
            ipCache.set(cacheKey, { ips, expires: Date.now() + CACHE_TTL });
            return ips;
        }

        return null;
    } catch (_) {
        return null;
    }
}

/**
 * Synchronously detect the CDN owner of an IP address.
 * @param {string} ip - IPv4 or IPv6 address
 * @returns {'CF'|'META'|null}
 */
export function detectOwner(ip) {
    try {
        if (!ip || typeof ip !== 'string') return null;
        const trimmed = ip.trim();
        if (!trimmed) return null;

        if (isIpInCompiled(trimmed, COMPILED_CF)) return 'CF';
        if (isIpInCompiled(trimmed, COMPILED_META)) return 'META';
        return null;
    } catch (_) {
        return null;
    }
}

/**
 * Asynchronously probe a domain's A records to determine its CDN owner.
 * Caches results in a module-level Map with 1-hour TTL.
 * @param {string} domain - Domain name to probe
 * @returns {Promise<{owner: 'CF'|'META'|null, ips: string[]}>}
 */
export async function probeOwner(domain) {
    try {
        if (!domain || typeof domain !== 'string') {
            return { owner: null, ips: [] };
        }

        const key = domain.trim().toLowerCase();
        if (!key) return { owner: null, ips: [] };

        const cached = probeCache.get(key);
        if (cached && cached.expire > Date.now()) {
            return { owner: cached.owner, ips: cached.ips };
        }

        const ips = await resolveA(key);
        let owner = null;
        for (const ip of ips) {
            if (isIpInCompiled(ip, COMPILED_CF)) { owner = 'CF'; break; }
            if (isIpInCompiled(ip, COMPILED_META)) { owner = 'META'; break; }
        }

        probeCache.set(key, { owner, ips, expire: Date.now() + PROBE_CACHE_TTL });
        return { owner, ips };
    } catch (_) {
        return { owner: null, ips: [] };
    }
}

export function extractIps(buffer) {
  const ips = [];
  try {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    if (bytes.length < 12) return ips;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ancount = view.getUint16(6);
    let offset = 12;
    for (let i = 0; i < view.getUint16(4); i++) {
      while (offset < bytes.length) {
        const b = bytes[offset];
        if (b === 0) { offset++; break; }
        if ((b & 0xC0) === 0xC0) { offset += 2; break; }
        offset += b + 1;
      }
      offset += 4;
    }
    for (let i = 0; i < ancount; i++) {
      if (offset + 12 > bytes.length) break;
      let b = bytes[offset];
      if ((b & 0xC0) === 0xC0) { offset += 2; }
      else {
        while (b !== 0) {
          if ((b & 0xC0) === 0xC0) { offset += 1; break; }
          offset += b + 1;
          b = bytes[offset];
        }
        offset++;
      }
      const type = view.getUint16(offset); offset += 8;
      const rdlen = view.getUint16(offset); offset += 2;
      if (type === 1 && rdlen === 4) {
        ips.push(bytes[offset] + '.' + bytes[offset+1] + '.' + bytes[offset+2] + '.' + bytes[offset+3]);
      } else if (type === 28 && rdlen === 16) {
        const p = [];
        for (let j = 0; j < 16; j += 2) p.push(((bytes[offset+j] << 8) | bytes[offset+j+1]).toString(16));
        ips.push(p.join(':'));
      }
      offset += rdlen;
    }
  } catch (_) {}
  return ips;
}

export function isMetaDomain(name) {
  const domains = ['facebook.com','fbcdn.net','instagram.com','cdninstagram.com','messenger.com','whatsapp.com','whatsapp.net','threads.net','meta.com','oculus.com','fbsbx.com','thefacebook.com','connect.facebook.net'];
  try {
    return domains.some(function (d) { return name === d || name.endsWith('.' + d); });
  } catch (_) { return false; }
}

async function resolveA(domain) {
    try {
        const buf = await resolveDNSWire(domain, 1);
        if (!buf) return [];
        return extractIPStrings(buf, 1);
    } catch (_) {
        return [];
    }
}

function createDNSResponse(id, qName, qType, rdataList, ttl) {
    const encodedName = encodeDnsName(qName);

    let totalLen = 12 + encodedName.length + 4;
    for (let i = 0; i < rdataList.length; i++) {
        totalLen += 12 + rdataList[i].length;
    }

    const buf = new Uint8Array(totalLen);
    const v = new DataView(buf.buffer);

    v.setUint16(0, id);                        // Transaction ID
    v.setUint16(2, 0x8180);                    // Flags: QR=1, RD=1, RA=1
    v.setUint16(4, 1);                         // QDCOUNT
    v.setUint16(6, rdataList.length);          // ANCOUNT
    v.setUint16(8, 0);                         // NSCOUNT
    v.setUint16(10, 0);                        // ARCOUNT

    let offset = 12;
    buf.set(encodedName, offset);
    offset += encodedName.length;
    v.setUint16(offset, qType);
    offset += 2;
    v.setUint16(offset, 1);                    // Class IN
    offset += 2;

    for (let i = 0; i < rdataList.length; i++) {
        const r = rdataList[i];
        v.setUint16(offset, 0xC00C);           // Name pointer to question (offset 12)
        offset += 2;
        v.setUint16(offset, qType);
        offset += 2;
        v.setUint16(offset, 1);                // Class IN
        offset += 2;
        v.setUint32(offset, ttl || 3600);
        offset += 4;
        v.setUint16(offset, r.length);         // RDLENGTH
        offset += 2;
        buf.set(r, offset);
        offset += r.length;
    }

    return buf.buffer;
}

function encodeDnsName(domain) {
    const parts = domain.split('.');
    const buf = new Uint8Array(domain.length + 2);
    let offset = 0;
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        buf[offset++] = part.length;
        for (let j = 0; j < part.length; j++) {
            buf[offset++] = part.charCodeAt(j);
        }
    }
    buf[offset++] = 0;
    return buf.slice(0, offset);
}

function parseQueryId(body) {
    try {
        const bytes = toBytes(body);
        if (bytes.length < 2) return 0;
        return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0);
    } catch (_) {
        return 0;
    }
}

function toBytes(body) {
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    throw new Error('body must be ArrayBuffer or ArrayBufferView');
}

function compileCidrs(cidrList) {
    const v4 = [];
    const v6 = [];
    for (let i = 0; i < cidrList.length; i++) {
        try {
            const cidr = cidrList[i];
            const parts = cidr.split('/');
            if (parts.length !== 2) continue;
            const ip = parts[0];
            const bits = parseInt(parts[1], 10);
            if (isNaN(bits)) continue;

            if (ip.includes(':')) {
                const mask = ~((1n << (128n - BigInt(bits))) - 1n);
                const ipBn = ipv6ToBigInt(ip);
                const start = ipBn & mask;
                const end = start | ((1n << (128n - BigInt(bits))) - 1n);
                v6.push({ start: start, end: end });
            } else {
                const mask = ~((1 << (32 - bits)) - 1);
                const ipNum = ipToLong(ip);
                const start = (ipNum & mask) >>> 0;
                const end = (start | ((1 << (32 - bits)) - 1)) >>> 0;
                v4.push({ start: start, end: end });
            }
        } catch (_) {}
    }
    return { v4: v4, v6: v6 };
}

function isIpInCompiled(ip, compiled) {
    if (ip.includes(':')) {
        try {
            const ipBn = ipv6ToBigInt(ip);
            const ranges = compiled.v6;
            for (let i = 0; i < ranges.length; i++) {
                if (ipBn >= ranges[i].start && ipBn <= ranges[i].end) return true;
            }
        } catch (_) {}
    } else {
        try {
            const ipNum = ipToLong(ip);
            const ranges = compiled.v4;
            for (let i = 0; i < ranges.length; i++) {
                if (ipNum >= ranges[i].start && ipNum <= ranges[i].end) return true;
            }
        } catch (_) {}
    }
    return false;
}

function ipToLong(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) throw new Error('bad IPv4');
    let result = 0;
    for (let i = 0; i < 4; i++) {
        const n = parseInt(parts[i], 10);
        if (isNaN(n) || n < 0 || n > 255) throw new Error('bad IPv4 octet');
        result = (result << 8) + n;
    }
    return result >>> 0;
}

function ipv6ToBigInt(ip) {
    let groups = ip.split(':');
    if (ip.includes('::')) {
        const doubleColon = ip.indexOf('::');
        const left = ip.substring(0, doubleColon);
        const right = ip.substring(doubleColon + 2);
        const leftParts = left ? left.split(':') : [];
        const rightParts = right ? right.split(':') : [];
        const fill = 8 - leftParts.length - rightParts.length;
        if (fill < 0) throw new Error('bad IPv6');
        groups = [];
        for (let i = 0; i < leftParts.length; i++) groups.push(leftParts[i]);
        for (let i = 0; i < fill; i++) groups.push('0');
        for (let i = 0; i < rightParts.length; i++) groups.push(rightParts[i]);
    }
    if (groups.length !== 8) throw new Error('bad IPv6 group count');

    let result = 0n;
    for (let i = 0; i < 8; i++) {
        const val = parseInt(groups[i] || '0', 16);
        if (isNaN(val) || val > 0xFFFF || val < 0) throw new Error('bad IPv6 group');
        result = (result << 16n) + BigInt(val);
    }
    return result;
}

// ── Inlined from resolver.js ────────────────────────────────────────────────

const DNS_HEADERS = { 'Content-Type': 'application/dns-message' };

function buildWireQuery(domain, type) {
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
  v.setUint16(offset, 1);    offset += 2;

  return buf;
}

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
      const ancount = new DataView(buf).getUint16(6);
      if (ancount === 0) return null;
      return buf;
    }).catch(function (_) {
      return null;
    });
  });

  const timeoutPromise = new Promise(function (resolve) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { resolve(null); return; }
    setTimeout(function () { resolve(null); }, remaining);
  });

  const racers = [...promises, timeoutPromise];

  while (racers.length > 1) {
    const winner = await Promise.race(racers);
    if (winner !== null) {
      abortAll();
      return winner;
    }
    // Either an upstream or timeout resolved null
    if (Date.now() >= deadline) break;
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    // Replace timeout with a new shorter one for retry
    const newTimeout = new Promise(function (resolve) {
      setTimeout(function () { resolve(null); }, Math.min(remaining, 50));
    });
    const idx = racers.indexOf(timeoutPromise);
    if (idx >= 0) racers[idx] = newTimeout;
    timeoutPromise = newTimeout;
  }

  abortAll();
  return null;
}

export function extractIPBytes(buf, type) {
  try {
    const answers = parseAnswers(buf, type);
    return answers.filter(function (a) {
      return a.type === type && (a.rdata.length === 4 || a.rdata.length === 16);
    }).map(function (a) { return a.rdata; });
  } catch (_) {
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
  } catch (_) {
    return [];
  }
}

function parseAnswers(buf, expectedType) {
  const bytes = buf instanceof ArrayBuffer
    ? new Uint8Array(buf)
    : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (bytes.length < 12) return [];

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    offset = skipName(bytes, offset);
    offset += 4;
  }

  const answers = [];
  for (let i = 0; i < ancount; i++) {
    if (offset + 10 > bytes.length) break;
    const nameEnd = skipName(bytes, offset);
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

function skipName(bytes, start) {
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
