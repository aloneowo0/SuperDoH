import { toBytes, resolveDNSWire, extractIPStrings } from './dns-lib.js';
import { logEvent } from './logger.js';
import { USE_GEOIP, GEOIP_CF, GEOIP_CFT, GEOIP_META, GEOIP_FASTLY, GEOIP_NETFLIX, GEOIP_TELEGRAM, GEOIP_TWITTER, GEOIP_TOR } from './config.js';

const PROBE_CACHE_TTL = 3600 * 1000;
const MAX_PROBE_CACHE = 256;

export function isMetaDomain(name) {
    var domains = ['facebook.com','fbcdn.net','instagram.com','cdninstagram.com','messenger.com','whatsapp.com','whatsapp.net','threads.net','meta.com','oculus.com','fbsbx.com','thefacebook.com','connect.facebook.net'];
    try {
        var n = name.toLowerCase().replace(/\.+$/, '');
        for (var i = 0; i < domains.length; i++) {
            if (n === domains[i] || n.endsWith('.' + domains[i])) return true;
        }
        return false;
    } catch (err) {
    logEvent('error', 'cdn_error', { stage: 'isMetaDomain', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return false;
  }
}

const RAW_VERCEL_CIDRS = [
    '143.13.0.0/16',
    '155.121.0.0/16',
    '198.169.1.0/24',
    '198.169.2.0/24',
    '216.150.1.0/24',
    '216.150.16.0/24',
    '216.198.79.0/24',
    '216.230.84.0/24',
    '216.230.86.0/24',
    '64.239.109.0/24',
    '64.239.123.0/24',
    '64.29.17.0/24',
    '66.33.60.0/24',
    '76.76.21.0/24',
];

const probeCache = new Map();

const COMPILED_META = compileCidrs(USE_GEOIP ? GEOIP_META : []);
const COMPILED_CF = compileCidrs(USE_GEOIP ? GEOIP_CF : []);
const COMPILED_CFT = compileCidrs(USE_GEOIP ? GEOIP_CFT : []);
const COMPILED_VRC = compileCidrs(RAW_VERCEL_CIDRS);
const COMPILED_FASTLY = compileCidrs(USE_GEOIP ? GEOIP_FASTLY : []);
const COMPILED_NETFLIX = compileCidrs(USE_GEOIP ? GEOIP_NETFLIX : []);
const COMPILED_TELEGRAM = compileCidrs(USE_GEOIP ? GEOIP_TELEGRAM : []);
const COMPILED_TWITTER = compileCidrs(USE_GEOIP ? GEOIP_TWITTER : []);
const COMPILED_TOR = compileCidrs(USE_GEOIP ? GEOIP_TOR : []);

// META reachability — LPM over status file, most-specific-first
const META_REACHABILITY_RULES = [
  { ip: 520962048, bits: 24, reachable: true },
  { ip: 520962560, bits: 24, reachable: false },
  { ip: 520963328, bits: 24, reachable: true },
  { ip: 520963584, bits: 24, reachable: true },
  { ip: 520963840, bits: 24, reachable: true },
  { ip: 520964096, bits: 24, reachable: false },
  { ip: 520964352, bits: 24, reachable: false },
  { ip: 520966144, bits: 24, reachable: false },
  { ip: 520966656, bits: 24, reachable: true },
  { ip: 520966912, bits: 24, reachable: false },
  { ip: 520967168, bits: 24, reachable: false },
  { ip: 520967680, bits: 24, reachable: false },
  { ip: 520967936, bits: 24, reachable: true },
  { ip: 520968448, bits: 24, reachable: true },
  { ip: 520968960, bits: 24, reachable: true },
  { ip: 520969472, bits: 24, reachable: true },
  { ip: 520969728, bits: 24, reachable: true },
  { ip: 520969984, bits: 24, reachable: true },
  { ip: 1719952128, bits: 24, reachable: true },
  { ip: 1719953408, bits: 24, reachable: true },
  { ip: 2649751552, bits: 24, reachable: true },
  { ip: 2649752320, bits: 24, reachable: true },
  { ip: 2649752832, bits: 24, reachable: true },
  { ip: 2649753600, bits: 24, reachable: true },
  { ip: 2649753856, bits: 24, reachable: true },
  { ip: 2649754368, bits: 24, reachable: true },
  { ip: 2649754624, bits: 24, reachable: true },
  { ip: 2649754880, bits: 24, reachable: true },
  { ip: 2649755136, bits: 24, reachable: true },
  { ip: 2649755392, bits: 24, reachable: true },
  { ip: 2649755904, bits: 24, reachable: true },
  { ip: 2649757184, bits: 24, reachable: true },
  { ip: 2649757696, bits: 24, reachable: true },
  { ip: 2649757952, bits: 24, reachable: true },
  { ip: 2649758208, bits: 24, reachable: true },
  { ip: 2649758464, bits: 24, reachable: true },
  { ip: 2649758976, bits: 24, reachable: true },
  { ip: 2649759232, bits: 24, reachable: true },
  { ip: 2649759488, bits: 24, reachable: true },
  { ip: 2649801728, bits: 24, reachable: true },
  { ip: 2649801984, bits: 24, reachable: true },
  { ip: 2649802752, bits: 24, reachable: true },
  { ip: 2649803264, bits: 24, reachable: true },
  { ip: 2649803520, bits: 24, reachable: true },
  { ip: 2649804032, bits: 24, reachable: true },
  { ip: 2649804800, bits: 24, reachable: true },
  { ip: 2649805056, bits: 24, reachable: true },
  { ip: 2649805312, bits: 24, reachable: true },
  { ip: 2649805568, bits: 24, reachable: true },
  { ip: 2649805824, bits: 24, reachable: true },
  { ip: 2649806336, bits: 24, reachable: true },
  { ip: 2649808640, bits: 24, reachable: true },
  { ip: 2649808896, bits: 24, reachable: true },
  { ip: 2649809152, bits: 24, reachable: true },
  { ip: 2649809408, bits: 24, reachable: true },
  { ip: 2649809664, bits: 24, reachable: true },
  { ip: 2649810688, bits: 24, reachable: true },
  { ip: 2649811200, bits: 24, reachable: true },
  { ip: 2649811456, bits: 24, reachable: true },
  { ip: 2649812480, bits: 24, reachable: true },
  { ip: 2649813248, bits: 24, reachable: true },
  { ip: 2649813760, bits: 24, reachable: true },
  { ip: 2649814016, bits: 24, reachable: true },
  { ip: 2649816320, bits: 24, reachable: true },
  { ip: 2649816576, bits: 24, reachable: true },
  { ip: 2739306496, bits: 24, reachable: true },
  { ip: 2739307008, bits: 24, reachable: false },
  { ip: 2739307264, bits: 24, reachable: true },
  { ip: 2739310592, bits: 24, reachable: true },
  { ip: 2739312384, bits: 24, reachable: true },
  { ip: 2739314432, bits: 24, reachable: true },
  { ip: 2739766272, bits: 24, reachable: true },
  { ip: 2739766528, bits: 24, reachable: true },
  { ip: 2739767296, bits: 24, reachable: true },
  { ip: 2739767552, bits: 24, reachable: true },
  { ip: 3107772672, bits: 24, reachable: true },
  { ip: 3107772928, bits: 24, reachable: true },
  { ip: 3107773184, bits: 24, reachable: true },
  { ip: 965547008, bits: 23, reachable: false },
  { ip: 965742080, bits: 23, reachable: true },
  { ip: 965744128, bits: 23, reachable: true },
  { ip: 965748224, bits: 23, reachable: true },
  { ip: 965749248, bits: 23, reachable: true },
  { ip: 965749760, bits: 23, reachable: true },
  { ip: 965751296, bits: 23, reachable: true },
  { ip: 965752320, bits: 23, reachable: true },
  { ip: 965752832, bits: 23, reachable: true },
  { ip: 965754880, bits: 23, reachable: true },
  { ip: 965755392, bits: 23, reachable: true },
  { ip: 965755904, bits: 23, reachable: true },
  { ip: 965756416, bits: 23, reachable: true },
  { ip: 965756928, bits: 23, reachable: true },
  { ip: 965757440, bits: 23, reachable: true },
  { ip: 965757952, bits: 23, reachable: true },
  { ip: 965758464, bits: 23, reachable: true },
  { ip: 965758976, bits: 23, reachable: true },
  { ip: 965760000, bits: 23, reachable: true },
  { ip: 965760512, bits: 23, reachable: true },
  { ip: 965764096, bits: 23, reachable: true },
  { ip: 965765120, bits: 23, reachable: true },
  { ip: 965766144, bits: 23, reachable: true },
  { ip: 965766656, bits: 23, reachable: true },
  { ip: 965767168, bits: 23, reachable: true },
  { ip: 965767680, bits: 23, reachable: true },
  { ip: 965768192, bits: 23, reachable: true },
  { ip: 965769216, bits: 23, reachable: true },
  { ip: 965770240, bits: 23, reachable: true },
  { ip: 965770752, bits: 23, reachable: true },
  { ip: 965771264, bits: 23, reachable: true },
  { ip: 965772288, bits: 23, reachable: true },
  { ip: 965772800, bits: 23, reachable: true },
  { ip: 965773312, bits: 23, reachable: true },
  { ip: 965773824, bits: 23, reachable: true },
  { ip: 965774336, bits: 23, reachable: true },
  { ip: 965774848, bits: 23, reachable: true },
  { ip: 965775360, bits: 23, reachable: true },
  { ip: 965776384, bits: 23, reachable: true },
  { ip: 965776896, bits: 23, reachable: true },
  { ip: 965777408, bits: 23, reachable: true },
  { ip: 965779456, bits: 23, reachable: true },
  { ip: 965779968, bits: 23, reachable: true },
  { ip: 965780480, bits: 23, reachable: true },
  { ip: 965782528, bits: 23, reachable: true },
  { ip: 965783040, bits: 23, reachable: true },
  { ip: 965783552, bits: 23, reachable: true },
  { ip: 965784064, bits: 23, reachable: true },
  { ip: 965784576, bits: 23, reachable: true },
  { ip: 965785088, bits: 23, reachable: true },
  { ip: 965785600, bits: 23, reachable: true },
  { ip: 965786112, bits: 23, reachable: true },
  { ip: 965786624, bits: 23, reachable: true },
  { ip: 965787648, bits: 23, reachable: true },
  { ip: 965788160, bits: 23, reachable: true },
  { ip: 965788672, bits: 23, reachable: true },
  { ip: 965789184, bits: 23, reachable: true },
  { ip: 965789696, bits: 23, reachable: true },
  { ip: 965790208, bits: 23, reachable: true },
  { ip: 965790720, bits: 23, reachable: true },
  { ip: 965791232, bits: 23, reachable: true },
  { ip: 965791744, bits: 23, reachable: true },
  { ip: 965792256, bits: 23, reachable: true },
  { ip: 965792768, bits: 23, reachable: true },
  { ip: 965793792, bits: 23, reachable: true },
  { ip: 965794304, bits: 23, reachable: true },
  { ip: 965794816, bits: 23, reachable: true },
  { ip: 965795328, bits: 23, reachable: true },
  { ip: 965796864, bits: 23, reachable: true },
  { ip: 965797888, bits: 23, reachable: true },
  { ip: 965798400, bits: 23, reachable: false },
  { ip: 965798912, bits: 23, reachable: true },
  { ip: 965799424, bits: 23, reachable: true },
  { ip: 965799936, bits: 23, reachable: true },
  { ip: 965800448, bits: 23, reachable: true },
  { ip: 965800960, bits: 23, reachable: true },
  { ip: 965801472, bits: 23, reachable: true },
  { ip: 965801984, bits: 23, reachable: true },
  { ip: 965802496, bits: 23, reachable: true },
  { ip: 965803008, bits: 23, reachable: true },
  { ip: 965803520, bits: 23, reachable: true },
  { ip: 965804032, bits: 23, reachable: true },
  { ip: 965804544, bits: 23, reachable: true },
  { ip: 965805056, bits: 23, reachable: true },
  { ip: 965805568, bits: 23, reachable: true },
  { ip: 965806080, bits: 23, reachable: true },
  { ip: 965807104, bits: 23, reachable: true },
  { ip: 2739766272, bits: 23, reachable: true },
  { ip: 2739767296, bits: 23, reachable: true },
  { ip: 759179264, bits: 22, reachable: false },
  { ip: 965545984, bits: 22, reachable: false },
  { ip: 1249332224, bits: 22, reachable: false },
  { ip: 1728339968, bits: 22, reachable: false },
  { ip: 3007102976, bits: 22, reachable: false },
  { ip: 3107772416, bits: 22, reachable: false },
  { ip: 3109672960, bits: 22, reachable: false },
  { ip: 3423540224, bits: 22, reachable: false },
  { ip: 520951808, bits: 21, reachable: false },
  { ip: 965541888, bits: 20, reachable: false },
  { ip: 1121751040, bits: 20, reachable: false },
  { ip: 1161801728, bits: 20, reachable: false },
  { ip: 1719951360, bits: 20, reachable: false },
  { ip: 520970240, bits: 19, reachable: false },
  { ip: 1168891904, bits: 19, reachable: false },
  { ip: 520962048, bits: 18, reachable: true },
  { ip: 2649800704, bits: 18, reachable: false },
  { ip: 2918989824, bits: 18, reachable: false },
  { ip: 2173042688, bits: 17, reachable: false },
  { ip: 2649751552, bits: 17, reachable: true },
  { ip: 2739306496, bits: 17, reachable: true },
  { ip: 965738496, bits: 14, reachable: false },
];

/**
 * Synchronously detect the CDN owner of an IP address.
 * @param {string} ip - IPv4 or IPv6 address
 * @returns {'CF'|'META'|'CFT'|'VRC'|'FASTLY'|'NETFLIX'|'TELEGRAM'|'TWITTER'|'TOR'|null}
 */
export function detectOwner(ip) {
    try {
        if (!ip || typeof ip !== 'string') return null;
        const trimmed = ip.trim();
        if (!trimmed) return null;

        if (isIpInCompiled(trimmed, COMPILED_CF)) return 'CF';
        if (isIpInCompiled(trimmed, COMPILED_META)) return 'META';
        if (isIpInCompiled(trimmed, COMPILED_CFT)) return 'CFT';
        if (isIpInCompiled(trimmed, COMPILED_VRC)) return 'VRC';
        if (isIpInCompiled(trimmed, COMPILED_FASTLY)) return 'FASTLY';
        if (isIpInCompiled(trimmed, COMPILED_NETFLIX)) return 'NETFLIX';
        if (isIpInCompiled(trimmed, COMPILED_TELEGRAM)) return 'TELEGRAM';
        if (isIpInCompiled(trimmed, COMPILED_TWITTER)) return 'TWITTER';
        if (isIpInCompiled(trimmed, COMPILED_TOR)) return 'TOR';
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
            // Refresh LRU: delete and re-insert to move to end
            probeCache.delete(key);
            probeCache.set(key, cached);
            return { owner: cached.owner, ips: cached.ips };
        }

        const ips = await resolveA(key);
        let owner = null;
        for (const ip of ips) {
            if (isIpInCompiled(ip, COMPILED_CF)) { owner = 'CF'; break; }
            if (isIpInCompiled(ip, COMPILED_META)) { owner = 'META'; break; }
        }

        if (probeCache.size >= MAX_PROBE_CACHE) {
          var firstKey = probeCache.keys().next().value;
          if (firstKey !== undefined) probeCache.delete(firstKey);
        }
        var ttl = owner ? PROBE_CACHE_TTL : 15000;
        probeCache.set(key, { owner, ips, expire: Date.now() + ttl });
        return { owner, ips };
    } catch (err) {
        logEvent('error', 'cdn_error', { stage: 'probeOwner', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err), fallbackAction: 'return_null_owner' });
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
  } catch (err) {
    logEvent('error', 'cdn_error', { stage: 'extractIps', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
  }
  return ips;
}

async function resolveA(domain) {
    try {
        const buf = await resolveDNSWire(domain, 1);
        if (!buf) return [];
        return extractIPStrings(buf, 1);
    } catch (err) {
        logEvent('error', 'cdn_error', { stage: 'resolveA', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
        return [];
    }
}



export function parseQueryId(body) {
    try {
        const bytes = toBytes(body);
        if (bytes.length < 2) return 0;
        return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0);
    } catch (_) {
        return 0;
    }
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

/**
 * Filter Meta IP bytes to only return those from known-reachable CIDR ranges.
 * GFW blocks specific Meta subnets at TCP level; ECH hides SNI but can't fix IP drops.
 * 57.144.0.0/14 (Meta HK edge) is consistently reachable from China.
 * @param {Uint8Array[]} ipBytesArr - IP rdata bytes from extractIPBytes()
 * @param {number} maxCount - Maximum IPs to return (default 2)
 * @returns {Uint8Array[]} reachable IP bytes, sorted best-first
 */
export function filterReachableMeta(ipBytesArr, maxCount) {
  if (!ipBytesArr || !ipBytesArr.length) return [];
  const limit = typeof maxCount === 'number' && maxCount > 0 ? maxCount : 4;
  const reachable = [];
  for (let i = 0; i < ipBytesArr.length; i++) {
    if (isReachableMetaIP(ipBytesArr[i])) {
      reachable.push(ipBytesArr[i]);
      if (reachable.length >= limit) break;
    }
  }
  return reachable;
}

/** Check if a 4-byte Meta IP falls in a known-reachable CIDR range */
function isReachableMetaIP(ipBytes) {
  if (!ipBytes || ipBytes.length !== 4) return false;
  var ip = ((ipBytes[0] << 24) | (ipBytes[1] << 16) | (ipBytes[2] << 8) | ipBytes[3]) >>> 0;
  // LPM: first match (most-specific) wins
  for (var i = 0; i < META_REACHABILITY_RULES.length; i++) {
    var rule = META_REACHABILITY_RULES[i];
    var mask = ~((1 << (32 - rule.bits)) - 1);
    if ((ip & mask) === (rule.ip & mask)) return rule.reachable;
  }
  return false;
}

/**
 * Classify a DNS response buffer by detecting the CDN owner of resolved IPs.
 * Returns 'META', 'CF', 'CFT', 'VRC', 'FASTLY', 'NETFLIX', 'TELEGRAM', 'TWITTER', 'TOR', or null.
 */
export function classifyResponse(responseBuf, queryType) {
  try {
    if (queryType !== 1 && queryType !== 28) return null;
    const ips = extractIps(responseBuf);
    for (var i = 0; i < ips.length; i++) {
      const owner = detectOwner(ips[i]);
      if (owner) return owner;
    }
    return null;
  } catch (err) {
    logEvent('error', 'cdn_error', { stage: 'classifyResponse', errorName: err && err.name || 'Error', errorMessage: err && err.message || String(err) });
    return null;
  }
}
