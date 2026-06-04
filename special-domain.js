/** Special domain handling — remap, CDN owner detection, CIDR matching */

import { toBytes, buildDNS, resolveDNSWire, extractIPBytes, extractIPStrings } from './dns-lib.js';

const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_HTTPS = 65;
const CACHE_TTL = 300_000;
const PROBE_CACHE_TTL = 3600 * 1000;

// AS32934 scanned 2026-05-31 — only REACHABLE IPv4 + IPv6
const RAW_META_CIDRS = [
    '31.13.64.0/18',
    '31.13.64.0/24',
    '31.13.69.0/24',
    '31.13.70.0/24',
    '31.13.71.0/24',
    '31.13.82.0/24',
    '31.13.87.0/24',
    '31.13.89.0/24',
    '31.13.91.0/24',
    '31.13.93.0/24',
    '31.13.94.0/24',
    '31.13.95.0/24',
    '57.144.14.0/23',
    '57.144.22.0/23',
    '57.144.38.0/23',
    '57.144.42.0/23',
    '57.144.44.0/23',
    '57.144.50.0/23',
    '57.144.54.0/23',
    '57.144.56.0/23',
    '57.144.64.0/23',
    '57.144.66.0/23',
    '57.144.68.0/23',
    '57.144.70.0/23',
    '57.144.72.0/23',
    '57.144.74.0/23',
    '57.144.76.0/23',
    '57.144.78.0/23',
    '57.144.80.0/23',
    '57.144.84.0/23',
    '57.144.86.0/23',
    '57.144.100.0/23',
    '57.144.104.0/23',
    '57.144.108.0/23',
    '57.144.110.0/23',
    '57.144.112.0/23',
    '57.144.114.0/23',
    '57.144.120.0/23',
    '57.144.124.0/23',
    '57.144.126.0/23',
    '57.144.128.0/23',
    '57.144.132.0/23',
    '57.144.134.0/23',
    '57.144.136.0/23',
    '57.144.138.0/23',
    '57.144.140.0/23',
    '57.144.142.0/23',
    '57.144.144.0/23',
    '57.144.148.0/23',
    '57.144.150.0/23',
    '57.144.152.0/23',
    '57.144.160.0/23',
    '57.144.162.0/23',
    '57.144.164.0/23',
    '57.144.172.0/23',
    '57.144.174.0/23',
    '57.144.176.0/23',
    '57.144.178.0/23',
    '57.144.180.0/23',
    '57.144.182.0/23',
    '57.144.184.0/23',
    '57.144.186.0/23',
    '57.144.188.0/23',
    '57.144.192.0/23',
    '57.144.194.0/23',
    '57.144.196.0/23',
    '57.144.198.0/23',
    '57.144.200.0/23',
    '57.144.202.0/23',
    '57.144.204.0/23',
    '57.144.206.0/23',
    '57.144.208.0/23',
    '57.144.210.0/23',
    '57.144.212.0/23',
    '57.144.216.0/23',
    '57.144.218.0/23',
    '57.144.220.0/23',
    '57.144.222.0/23',
    '57.144.228.0/23',
    '57.144.232.0/23',
    '57.144.234.0/23',
    '57.144.236.0/23',
    '57.144.238.0/23',
    '57.144.240.0/23',
    '57.144.242.0/23',
    '57.144.244.0/23',
    '57.144.246.0/23',
    '57.144.248.0/23',
    '57.144.250.0/23',
    '57.144.252.0/23',
    '57.144.254.0/23',
    '57.145.0.0/23',
    '57.145.2.0/23',
    '57.145.4.0/23',
    '57.145.6.0/23',
    '57.145.8.0/23',
    '57.145.12.0/23',
    '102.132.99.0/24',
    '102.132.104.0/24',
    '157.240.0.0/17',
    '157.240.0.0/24',
    '157.240.3.0/24',
    '157.240.5.0/24',
    '157.240.8.0/24',
    '157.240.9.0/24',
    '157.240.11.0/24',
    '157.240.12.0/24',
    '157.240.13.0/24',
    '157.240.14.0/24',
    '157.240.15.0/24',
    '157.240.17.0/24',
    '157.240.22.0/24',
    '157.240.24.0/24',
    '157.240.25.0/24',
    '157.240.26.0/24',
    '157.240.27.0/24',
    '157.240.29.0/24',
    '157.240.30.0/24',
    '157.240.31.0/24',
    '157.240.196.0/24',
    '157.240.197.0/24',
    '157.240.200.0/24',
    '157.240.202.0/24',
    '157.240.203.0/24',
    '157.240.205.0/24',
    '157.240.208.0/24',
    '157.240.209.0/24',
    '157.240.210.0/24',
    '157.240.211.0/24',
    '157.240.212.0/24',
    '157.240.214.0/24',
    '157.240.223.0/24',
    '157.240.224.0/24',
    '157.240.225.0/24',
    '157.240.226.0/24',
    '157.240.227.0/24',
    '157.240.231.0/24',
    '157.240.233.0/24',
    '157.240.234.0/24',
    '157.240.238.0/24',
    '157.240.241.0/24',
    '157.240.243.0/24',
    '157.240.244.0/24',
    '157.240.253.0/24',
    '157.240.254.0/24',
    '163.70.128.0/17',
    '163.70.128.0/24',
    '163.70.131.0/24',
    '163.70.144.0/24',
    '163.70.151.0/24',
    '163.70.159.0/24',
    '163.77.132.0/23',
    '163.77.132.0/24',
    '163.77.133.0/24',
    '163.77.136.0/23',
    '163.77.136.0/24',
    '163.77.137.0/24',
    '185.60.217.0/24',
    '185.60.218.0/24',
    '185.60.219.0/24',
    '2620:0:1c00::/40',
    '2620:10d:c090::/44',
    '2a03:2880::/32',
    '2a03:2887:ff00::/48',
    '2a03:2887:ff02::/48',
    '2a03:2887:ff04::/46',
    '2a03:2887:ff09::/48',
    '2a03:2887:ff0a::/48',
    '2a03:2887:ff1b::/48',
    '2a03:2887:ff1c::/48',
    '2a03:2887:ff1e::/48',
    '2a03:2887:ff20::/48',
    '2a03:2887:ff22::/47',
    '2a03:2887:ff27::/48',
    '2a03:2887:ff28::/46',
    '2a03:2887:ff2f::/48',
    '2a03:2887:ff30::/48',
    '2a03:2887:ff33::/48',
    '2a03:2887:ff37::/48',
    '2a03:2887:ff38::/46',
    '2a03:2887:ff3f::/48',
    '2a03:2887:ff40::/46',
    '2a03:2887:ff44::/47',
    '2a03:2887:ff48::/46',
    '2a03:2887:ff4d::/48',
    '2a03:2887:ff4e::/47',
    '2a03:2887:ff50::/45',
    '2a03:2887:ff58::/47',
    '2a03:2887:ff5a::/48',
    '2a03:2887:ff5f::/48',
    '2a03:2887:ff60::/48',
    '2a03:2887:ff62::/47',
    '2a03:2887:ff64::/46',
    '2a03:2887:ff68::/47',
    '2a03:2887:ff6a::/48',
    '2a03:2887:ff70::/47',
    '2c0f:ef78:3::/48',
    '2c0f:ef78:5::/48',
    '2c0f:ef78:9::/48',
    '2c0f:ef78:c::/47',
    '2c0f:ef78:e::/48',
    '2c0f:ef78:10::/47',
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

const RAW_CLOUDFRONT_CIDRS = [
    '3.10.17.128/25',
    '3.11.53.0/24',
    '3.29.40.64/26',
    '3.29.40.128/25',
    '3.29.57.0/26',
    '3.35.130.128/25',
    '3.101.158.0/23',
    '3.107.43.128/25',
    '3.107.44.0/24',
    '3.128.93.0/24',
    '3.134.215.0/24',
    '3.146.232.0/22',
    '3.147.164.0/22',
    '3.147.244.0/22',
    '3.160.0.0/13',
    '3.168.0.0/14',
    '3.172.0.0/17',
    '3.173.0.0/16',
    '3.174.0.0/15',
    '3.231.2.0/25',
    '3.234.232.224/27',
    '3.236.48.0/23',
    '3.236.169.192/26',
    '13.32.0.0/15',
    '13.35.0.0/16',
    '13.54.63.128/26',
    '13.59.250.0/26',
    '13.113.196.64/26',
    '13.113.203.0/24',
    '13.124.199.0/24',
    '13.134.24.0/23',
    '13.134.94.0/23',
    '13.203.133.0/26',
    '13.210.67.128/26',
    '13.224.0.0/14',
    '13.228.69.0/24',
    '13.233.177.192/26',
    '13.249.0.0/16',
    '15.158.0.0/16',
    '15.188.184.0/24',
    '15.207.13.128/25',
    '15.207.213.128/25',
    '18.64.0.0/14',
    '18.68.0.0/16',
    '18.154.0.0/15',
    '18.160.0.0/15',
    '18.164.0.0/15',
    '18.172.0.0/15',
    '18.175.65.0/24',
    '18.175.66.0/23',
    '18.192.142.0/23',
    '18.199.68.0/22',
    '18.199.72.0/21',
    '18.200.212.0/23',
    '18.216.170.128/25',
    '18.229.220.192/26',
    '18.230.229.0/24',
    '18.230.230.0/25',
    '18.238.0.0/15',
    '18.244.0.0/15',
    '23.91.0.0/19',
    '23.228.212.0/23',
    '23.228.214.0/24',
    '23.228.220.0/22',
    '23.228.244.0/24',
    '23.234.192.0/18',
    '24.110.32.0/19',
    '34.195.252.0/24',
    '34.216.51.0/25',
    '34.223.12.224/27',
    '34.223.80.192/26',
    '34.226.14.0/24',
    '35.93.168.0/22',
    '35.93.172.0/23',
    '35.158.136.0/24',
    '35.162.63.192/26',
    '35.167.191.128/26',
    '36.103.232.0/25',
    '36.103.232.128/26',
    '43.218.56.64/26',
    '43.218.56.128/25',
    '43.218.71.0/26',
    '44.220.194.0/23',
    '44.220.196.0/22',
    '44.220.200.0/22',
    '44.222.66.0/24',
    '44.227.178.0/24',
    '44.234.90.252/30',
    '44.234.108.128/25',
    '47.129.82.0/23',
    '47.129.84.0/24',
    '51.44.234.0/23',
    '51.44.236.0/22',
    '51.74.192.0/18',
    '52.15.127.128/26',
    '52.46.0.0/18',
    '52.47.139.0/24',
    '52.52.191.128/26',
    '52.56.127.0/25',
    '52.57.254.0/24',
    '52.66.194.128/26',
    '52.78.247.128/26',
    '52.82.128.0/19',
    '52.84.0.0/15',
    '52.124.128.0/17',
    '52.199.127.192/26',
    '52.212.248.0/26',
    '52.220.191.0/26',
    '52.222.128.0/17',
    '54.182.0.0/16',
    '54.192.0.0/16',
    '54.230.0.0/17',
    '54.230.128.0/18',
    '54.230.200.0/21',
    '54.230.208.0/20',
    '54.230.224.0/19',
    '54.233.255.128/26',
    '54.239.128.0/18',
    '54.239.192.0/19',
    '54.240.128.0/18',
    '56.125.46.0/24',
    '56.125.47.0/32',
    '56.125.48.0/24',
    '57.182.253.0/24',
    '57.183.42.0/25',
    '58.254.138.0/25',
    '58.254.138.128/26',
    '64.252.64.0/18',
    '64.252.128.0/18',
    '65.8.0.0/16',
    '65.9.0.0/17',
    '65.9.128.0/18',
    '70.132.0.0/18',
    '71.152.0.0/17',
    '99.79.169.0/24',
    '99.84.0.0/16',
    '99.86.0.0/16',
    '108.138.0.0/15',
    '108.156.0.0/14',
    '111.13.171.128/25',
    '111.13.185.32/27',
    '111.13.185.64/27',
    '116.129.226.0/25',
    '116.129.226.128/26',
    '118.193.97.64/26',
    '118.193.97.128/25',
    '119.147.182.0/25',
    '119.147.182.128/26',
    '120.52.12.64/26',
    '120.52.22.96/27',
    '120.52.39.128/27',
    '120.52.153.192/26',
    '120.232.236.0/25',
    '120.232.236.128/26',
    '120.253.240.192/26',
    '120.253.241.160/27',
    '120.253.245.128/26',
    '120.253.245.192/27',
    '130.176.0.0/17',
    '130.176.128.0/18',
    '130.176.192.0/19',
    '130.176.224.0/20',
    '143.204.0.0/16',
    '144.220.0.0/16',
    '180.163.57.0/25',
    '180.163.57.128/26',
    '204.246.164.0/22',
    '204.246.168.0/21',
    '204.246.176.0/20',
    '205.251.202.0/23',
    '205.251.204.0/22',
    '205.251.208.0/20',
    '205.251.249.0/24',
    '205.251.250.0/23',
    '205.251.252.0/23',
    '205.251.254.0/24',
    '216.137.32.0/19',
];

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

const ipCache = new Map();
const probeCache = new Map();

const COMPILED_META = compileCidrs(RAW_META_CIDRS);
const COMPILED_CF = compileCidrs(RAW_CF_CIDRS);
const COMPILED_CFT = compileCidrs(RAW_CLOUDFRONT_CIDRS);
const COMPILED_VRC = compileCidrs(RAW_VERCEL_CIDRS);

export async function remapResponse(originalBody, queryName, queryType, preferredDomain, echRdata) {
    try {
        const id = parseQueryId(originalBody);

        if (queryType === TYPE_AAAA) {
            return buildDNS(id, queryName, TYPE_AAAA, [], 3600);
        }

        if (queryType === TYPE_HTTPS) {
            if (echRdata && echRdata.length > 0) {
                return buildDNS(id, queryName, TYPE_HTTPS, [echRdata], 3600);
            }
            return buildDNS(id, queryName, TYPE_HTTPS, [], 60);
        }

        if (queryType === TYPE_A) {
            if (!preferredDomain) return null;
            const ips = await resolvePreferredIPs(preferredDomain, TYPE_A);
            if (!ips || ips.length === 0) return null;
            return buildDNS(id, queryName, TYPE_A, ips, 60);
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
 * @returns {'CF'|'META'|'CFT'|'VRC'|null}
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
  const limit = typeof maxCount === 'number' && maxCount > 0 ? maxCount : 2;
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
  var a = ipBytes[0], b = ipBytes[1], c = ipBytes[2];
  // 57.144.0.0/14 — Meta HK edge, consistently reachable
  if (a === 57 && b >= 144 && b <= 147) return true;
  // 157.240.0.0/17 — Facebook CDN (low-numbered /24s, verified reachable)
  if (a === 157 && b === 240 && c < 128) return true;
  return false;
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



function parseQueryId(body) {
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
