#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { isIP } = require('net');
const { spawnSync } = require('child_process');

const PRESETS = {
  google: { url: 'https://dns.google/dns-query', ecs: true },
  cloudflare_Public: { url: 'https://cloudflare-dns.com/dns-query', ecs: false },
  quad9: { url: 'https://dns11.quad9.net/dns-query', ecs: true },
  adguard: { url: 'https://dns.adguard-dns.com/dns-query', ecs: true },
  opendns: { url: 'https://dns.opendns.com/dns-query', ecs: true },
  yandex: { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false },
  dnspod: { url: 'https://sm2.doh.pub/dns-query', ecs: true },
  alidns: { url: 'https://dns.alidns.com/dns-query', ecs: true },
  360: { url: 'https://doh.360.cn/dns-query', ecs: true },
  nextdns: { url: 'https://dns.nextdns.io', ecs: true },
};

const DEFAULT_UPSTREAM_KEYS = ['google', 'cloudflare_Public'];

const GEOIP_CATEGORIES = {
  CF: 'cloudflare',
  CFT: 'cloudfront',
  META: 'facebook',
  FASTLY: 'fastly',
  NETFLIX: 'netflix',
  TELEGRAM: 'telegram',
  TWITTER: 'twitter',
  TOR: 'tor',
};

const DEFAULT_GEOIP_URL = 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/';
const DEFAULT_CEALING_HOST_URL =
  'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json';
const DEFAULT_BLOCKED_CIDRS = '127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128';
const DEFAULT_META_ECH_CONFIG =
  'AsH+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAD+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAD+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAD+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA/g0ASwYAIAAgti54XaD8VhwGEmxjGpaxUkuAz3VmpQSMOFSRgSPchR0ABAABAAEyHHNjb250ZW50LWxheDMtMi54eC5mYmNkbi5uZXQAAP4NAEgEACAAINQS+ceVTWrz9nffBM163+nvpZ9k5F5WK51t4DAGG3ReAAQAAQABZBl2aWRlby1sYXgzLTIueHguZmJjZG4ubmV0AAD+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAD+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=';
const DEFAULT_META_ECH_MAP = {
  'scontent.xx.fbcdn.net': DEFAULT_META_ECH_CONFIG,
};
const MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fetchText(url, redirects = 0) {
  let target;
  try {
    target = new URL(url);
  } catch {
    return Promise.reject(new Error(`Invalid download URL: ${url}`));
  }
  if (target.protocol !== 'https:') {
    return Promise.reject(new Error(`Only HTTPS download URLs are allowed: ${url}`));
  }
  return new Promise((resolve, reject) => {
    const request = https.get(target, (response) => {
      const status = response.statusCode || 0;
      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume();
        if (redirects >= 5) {
          reject(new Error(`Too many redirects for ${url}`));
          return;
        }
        let redirectUrl;
        try {
          redirectUrl = new URL(response.headers.location, target);
        } catch {
          reject(new Error(`Invalid redirect URL from ${url}`));
          return;
        }
        if (redirectUrl.protocol !== 'https:') {
          reject(new Error(`Refusing non-HTTPS redirect from ${url}`));
          return;
        }
        fetchText(redirectUrl.toString(), redirects + 1).then(resolve, reject);
        return;
      }
      if (status < 200 || status >= 300) {
        response.resume();
        reject(new Error(`HTTP ${status} for ${url}`));
        return;
      }
      const contentLength = Number.parseInt(response.headers['content-length'], 10);
      if (Number.isSafeInteger(contentLength) && contentLength > MAX_DOWNLOAD_BYTES) {
        response.destroy();
        reject(new Error(`Download exceeds ${MAX_DOWNLOAD_BYTES} byte limit for ${url}`));
        return;
      }
      let received = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_DOWNLOAD_BYTES) {
          response.destroy(new Error(`Download exceeds ${MAX_DOWNLOAD_BYTES} byte limit for ${url}`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      response.on('error', reject);
    });
    request.setTimeout(15000, () => request.destroy(new Error(`Timeout fetching ${url}`)));
    request.on('error', reject);
  });
}

function parseEnv(filepath) {
  if (!fs.existsSync(filepath)) return {};
  const env = {};
  for (const line of fs.readFileSync(filepath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator < 0) continue;
    env[trimmed.slice(0, separator).trim()] = trimmed.slice(separator + 1).trim();
  }
  return env;
}

function num(value, fallback, min = 0, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

function parseBlockedCidrs(value) {
  if (typeof value !== 'string') return [];
  const entries = [];
  for (const cidr of value.split(/\s+/)) {
    if (!cidr) continue;
    const slash = cidr.lastIndexOf('/');
    if (slash <= 0 || slash === cidr.length - 1) continue;
    const address = cidr.slice(0, slash);
    const prefix = Number.parseInt(cidr.slice(slash + 1), 10);
    const family = isIP(address);
    if (family === 6) {
      if (
        !Number.isInteger(prefix) ||
        prefix < 0 ||
        prefix > 128
      ) {
        continue;
      }
      entries.push({ family: 6, address, prefix });
      continue;
    }
    const octets = address.split('.');
    if (
      !Number.isInteger(prefix) ||
      prefix < 0 ||
      prefix > 32 ||
      family !== 4 ||
      octets.length !== 4
    ) {
      continue;
    }
    entries.push({ family: 4, address, prefix });
  }
  return entries;
}

function validMetaEchPattern(value) {
  const pattern = value.startsWith('*.') ? value.slice(2) : value;
  return pattern.length > 0 && pattern.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function resolveMetaEchMap(value) {
  const mappings = { ...DEFAULT_META_ECH_MAP };
  if (!isRecord(value)) return mappings;
  for (const [pattern, encoded] of Object.entries(value)) {
    const normalized = pattern.trim().toLowerCase().replace(/\.+$/, '');
    if (!validMetaEchPattern(normalized)) {
      console.warn(`Skip invalid Meta ECH domain pattern: ${pattern}`);
      continue;
    }
    if (encoded === null) {
      delete mappings[normalized];
    } else if (typeof encoded === 'string' && encoded.length > 0) {
      mappings[normalized] = encoded;
    } else {
      console.warn(`Skip invalid Meta ECH config for ${pattern}`);
    }
  }
  return mappings;
}

function buildUpstreams(userConfig, env) {
  const upstreams = {};
  const userUpstreams = isRecord(userConfig.upstreams) ? userConfig.upstreams : {};

  for (const [name, value] of Object.entries(userUpstreams)) {
    if (value === true) {
      if (PRESETS[name]) {
        upstreams[name] = { ...PRESETS[name] };
      } else {
        console.warn(`Unknown preset upstream: ${name} (skipped)`);
      }
    } else if (typeof value === 'string' && value.length > 0) {
      if (!/^[a-z][a-z0-9_]*$/.test(name)) {
        console.warn(`Skip invalid custom upstream name: ${name}`);
        continue;
      }
      upstreams[name] = { url: value, ecs: true };
    }
  }

  for (const [name, preset] of Object.entries(PRESETS)) {
    const key = name.toUpperCase();
    if (env[key] === 'true' && !upstreams[name]) upstreams[name] = { ...preset };
    if (env[key] === 'false') delete upstreams[name];
  }

  for (const [key, url] of Object.entries(env)) {
    if (!key.startsWith('CUSTOM_') || key === 'CUSTOM_' || upstreams[key.slice(7).toLowerCase()]) {
      continue;
    }
    const name = key.slice(7).toLowerCase();
    if (!/^[a-z][a-z0-9_]*$/.test(name)) {
      console.warn(`Skip invalid custom upstream name from .env: ${key} → ${name}`);
      continue;
    }
    upstreams[name] = { url, ecs: true };
  }

  return upstreams;
}

function joinUrl(base, filename) {
  return `${base.endsWith('/') ? base : `${base}/`}${filename}`;
}

async function fetchGeoipCidrs(geoipBase) {
  const cidrs = Object.fromEntries(Object.keys(GEOIP_CATEGORIES).map((key) => [key, []]));
  const keys = Object.keys(GEOIP_CATEGORIES);
  console.log(`Fetching GeoIP CIDR lists from ${geoipBase} ...`);
  const results = await Promise.allSettled(
    keys.map(async (key) => {
      const text = await fetchText(joinUrl(geoipBase, `${GEOIP_CATEGORIES[key]}.txt`));
      return {
        key,
        cidrs: text
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line && !line.startsWith('#'))
          .filter((line) => parseBlockedCidrs(line).length === 1),
      };
    }),
  );

  for (let index = 0; index < results.length; index += 1) {
    const result = results[index];
    if (result.status === 'fulfilled') {
      cidrs[result.value.key] = result.value.cidrs;
      console.log(`Fetched ${result.value.cidrs.length} ${GEOIP_CATEGORIES[result.value.key]} CIDRs`);
    } else {
      console.warn(`Failed to fetch ${keys[index]}: ${result.reason.message}`);
    }
  }
  return cidrs;
}

async function fetchGoogleProxy(cealingUrl) {
  try {
    console.log(`Fetching Cealing-Host from ${cealingUrl} ...`);
    const cealingData = JSON.parse(await fetchText(cealingUrl));
    if (!Array.isArray(cealingData)) {
      console.warn('Failed to fetch Cealing-Host for Google proxy: response is not an array');
      return null;
    }

    const googleKeys = [
      'google',
      'youtube',
      'gstatic',
      'youtu.be',
      'ggpht',
      'blogger',
      'blogspot',
      'googleapis',
      'googlevideo',
      'android.com',
      'googleadservices',
      'gemini',
    ];
    const entries = [];

    for (const row of cealingData) {
      if (!Array.isArray(row) || !Array.isArray(row[0])) continue;
      const domains = row[0].filter((domain) => typeof domain === 'string');
      const sni = typeof row[1] === 'string' ? row[1].trim() : '';
      const ip = typeof row[2] === 'string' ? row[2].trim() : '';
      if (!ip || ip.startsWith('[')) continue;

      const isGoogle = domains.some((domain) => {
        const normalized = domain.replace(/[#$^*]/g, '').toLowerCase();
        return googleKeys.some((key) => normalized.includes(key));
      });
      if (!isGoogle) continue;

      const matchPatterns = domains
        .filter((domain) => !domain.startsWith('^'))
        .map((domain) => domain.replace(/[#$]/g, '').replace(/\*/g, '').trim())
        .filter(Boolean);
      if (matchPatterns.length > 0) entries.push({ ips: [ip], sni: sni || null, match: matchPatterns });
    }

    const merged = [];
    const indexes = new Map();
    for (const entry of entries) {
      const key = `${entry.ips.join(',')}|${entry.sni || ''}`;
      const existing = indexes.get(key);
      if (existing === undefined) {
        indexes.set(key, merged.length);
        merged.push(entry);
      } else {
        merged[existing].match.push(...entry.match);
      }
    }

    const youtubeSupplements = [
      'googlevideo.com',
      'yt3.ggpht.com',
      'ytimg.com',
      'gvt1.com',
      'gvt2.com',
      'gvt3.com',
      'video.google.com',
    ];
    const googleSupplements = [
      'doubleclick.net',
      'googleadservices.com',
      'googlesyndication.com',
      'google.com.hk',
      'google.cn',
      'google.co.jp',
      'googleusercontent.com',
      'gmail.com',
    ];
    const supplementTarget = merged.find((entry) => entry.sni === 'g.cn');
    if (supplementTarget) supplementTarget.match.push(...youtubeSupplements, ...googleSupplements);

    console.log(`Extracted ${merged.length} Google proxy entries from Cealing-Host`);
    return merged;
  } catch (error) {
    console.warn(`Failed to fetch Cealing-Host for Google proxy: ${error.message}`);
    return null;
  }
}

function resolveConfig(userConfig, env) {
  const configured = userConfig.configured === 1 ? 1 : 0;
  if (configured === 0) {
    return {
      configured,
      upstreams: Object.fromEntries(DEFAULT_UPSTREAM_KEYS.map((key) => [key, { ...PRESETS[key] }])),
      metaEchMap: resolveMetaEchMap(userConfig.metaEchMap),
      ecsPrefix4: 24,
      ecsPrefix6: 56,
      blockedCidrs: DEFAULT_BLOCKED_CIDRS,
      autoConcurrency: 6,
      ecsProtectMs: 20,
      hardTimeoutMs: 800,
      metaHardTimeoutMs: 800,
      metaCollectWindowMs: 50,
      metaMaxIps: 4,
      preferredTimeoutMs: 300,
      fastTimeoutMs: 200,
      mixTimeoutMs: 200,
      mixTtl: 300,
      preferredTtl: 60,
      servfailEdeCode: 22,
      cfEchCacheTtlMs: 600000,
      cfEchStaleTtlMs: 3600000,
      logLevel: 'info',
      regions: {},
      geoipUrl: DEFAULT_GEOIP_URL,
      cealingHostUrl: DEFAULT_CEALING_HOST_URL,
      fetchGoogleProxy: true,
    };
  }

  const configNumber = (envName, configName, fallback, min, max) =>
    num(env[envName], num(userConfig[configName], fallback, min, max), min, max);
  return {
    configured,
    upstreams: buildUpstreams(userConfig, env),
    metaEchMap: resolveMetaEchMap(userConfig.metaEchMap),
    ecsPrefix4: configNumber('ECS_PREFIX4', 'ecsPrefix4', 24, 0, 32),
    ecsPrefix6: configNumber('ECS_PREFIX6', 'ecsPrefix6', 56, 0, 128),
    blockedCidrs: env.BLOCKED_CIDRS || userConfig.blockedCidrs || DEFAULT_BLOCKED_CIDRS,
    autoConcurrency: num(
      env.AUTO_CONCURRENCY || env.MIX_CONCURRENCY,
      num(userConfig.autoConcurrency, 6),
    ),
    ecsProtectMs: configNumber('ECS_PROTECT_MS', 'ecsProtectMs', 20),
    hardTimeoutMs: configNumber('HARD_TIMEOUT_MS', 'hardTimeoutMs', 800),
    metaHardTimeoutMs: configNumber('META_HARD_TIMEOUT_MS', 'metaHardTimeoutMs', 800),
    metaCollectWindowMs: configNumber('META_COLLECT_WINDOW_MS', 'metaCollectWindowMs', 50),
    metaMaxIps: configNumber('META_MAX_IPS', 'metaMaxIps', 4),
    preferredTimeoutMs: configNumber('PREFERRED_TIMEOUT_MS', 'preferredTimeoutMs', 300),
    fastTimeoutMs: configNumber('FAST_TIMEOUT_MS', 'fastTimeoutMs', 200),
    mixTimeoutMs: configNumber('MIX_TIMEOUT_MS', 'mixTimeoutMs', 200),
    mixTtl: configNumber('MIX_TTL', 'mixTtl', 300),
    preferredTtl: configNumber('PREFERRED_TTL', 'preferredTtl', 60),
    servfailEdeCode: configNumber('SERVFAIL_EDE_CODE', 'servfailEdeCode', 22, 0, 65535),
    cfEchCacheTtlMs: configNumber('CF_ECH_CACHE_TTL_MS', 'cfEchCacheTtlMs', 600000),
    cfEchStaleTtlMs: configNumber('CF_ECH_STALE_TTL_MS', 'cfEchStaleTtlMs', 3600000),
    logLevel: env.LOG_LEVEL || userConfig.logLevel || 'info',
    regions: isRecord(userConfig.regions) ? userConfig.regions : {},
    geoipUrl: userConfig.geoipUrl || DEFAULT_GEOIP_URL,
    cealingHostUrl: userConfig.cealingHostUrl || DEFAULT_CEALING_HOST_URL,
    fetchGoogleProxy: userConfig.fetchGoogleProxy !== false,
  };
}

function rustString(value) {
  const escaped = [...String(value)]
    .map((character) => {
      if (character === '\\') return '\\\\';
      if (character === '"') return '\\"';
      if (character === '\n') return '\\n';
      if (character === '\r') return '\\r';
      if (character === '\t') return '\\t';
      const codePoint = character.codePointAt(0);
      return codePoint < 0x20 || codePoint === 0x7f ? `\\u{${codePoint.toString(16)}}` : character;
    })
    .join('');
  return `"${escaped}"`;
}

function rustInteger(value) {
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`Expected a safe integer, received ${value}`);
  }
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, '_');
}

function rustStringSlice(values, indent) {
  if (values.length === 0) return '&[]';
  const itemIndent = `${indent}    `;
  return `&[\n${values.map((value) => `${itemIndent}${rustString(value)},`).join('\n')}\n${indent}]`;
}

function remapValues(value) {
  if (typeof value === 'string') return value.split(/[\s,]+/).filter(Boolean);
  if (!Array.isArray(value)) return [];
  return value.filter((domain) => typeof domain === 'string' && domain.length > 0);
}

function generateConfigRs(config, geoipCidrs, fetchedGoogleProxy) {
  const regionNames = Object.keys(config.regions).sort();
  const regions = regionNames.map((name) => {
    const value = isRecord(config.regions[name]) ? config.regions[name] : {};
    return {
      name,
      preferredCf: typeof value.preferredCf === 'string' ? value.preferredCf : '',
      preferredCft: typeof value.preferredCft === 'string' ? value.preferredCft : '',
      preferredVrc: typeof value.preferredVrc === 'string' ? value.preferredVrc : '',
      remap: remapValues(value.remap),
      ech: value.ech === true,
      googleEnabled: value.google === true,
    };
  });
  const upstreams = Object.entries(config.upstreams);
  const metaEchEntries = Object.entries(config.metaEchMap).sort(([left], [right]) => left.localeCompare(right));
  const foreignUpstreams = upstreams
    .map(([name]) => name)
    .filter((name) => name !== 'dnspod' && name !== 'alidns');
  const blocked = parseBlockedCidrs(config.blockedCidrs);

  const regionStatics = regions.flatMap((region, index) => {
    const prefix = `REGION_${index}`;
    const values = [`static ${prefix}_REMAP: &[&str] = ${rustStringSlice(region.remap, '')};`];
    if (region.googleEnabled && fetchedGoogleProxy !== null) {
      const entries = fetchedGoogleProxy.map((entry) => [
        '    GoogleProxy {',
        `        match_patterns: ${rustStringSlice(entry.match, '        ')},`,
        `        ips: ${rustStringSlice(entry.ips, '        ')},`,
        `        sni: ${entry.sni === null ? 'None' : `Some(${rustString(entry.sni)})`},`,
        '    },',
      ].join('\n'));
      values.push(`static ${prefix}_GOOGLE: &[GoogleProxy] = &[\n${entries.join('\n')}\n];`);
    }
    return values;
  });

  const geoipStatics = Object.keys(GEOIP_CATEGORIES)
    .map((key) => `pub static GEOIP_${key}: &[&str] = ${rustStringSlice(geoipCidrs[key] || [], '')};`)
    .join('\n\n');
  const upstreamEntries = upstreams
    .map(
      ([name, upstream]) =>
        `    Upstream {\n        name: ${rustString(name)},\n        url: ${rustString(upstream.url)},\n        ecs: ${upstream.ecs},\n    },`,
    )
    .join('\n');
  const metaEchMapEntries = metaEchEntries
    .map(
      ([domainPattern, configB64]) =>
        `    MetaEchConfig { domain_pattern: ${rustString(domainPattern)}, config_b64: ${rustString(configB64)} },`,
    )
    .join('\n');
  const blockedEntries = blocked
    .map(
      (entry) =>
        `    Cidr { family: ${rustInteger(entry.family)}, address: ${rustString(entry.address)}, prefix: ${rustInteger(entry.prefix)} },`,
    )
    .join('\n');
  const regionEntries = regions
    .map((region, index) => {
      const google = region.googleEnabled && fetchedGoogleProxy !== null ? `Some(REGION_${index}_GOOGLE)` : 'None';
      return [
        '    RegionConfig {',
        `        name: ${rustString(region.name)},`,
        `        preferred_cf: ${rustString(region.preferredCf)},`,
        `        preferred_cft: ${rustString(region.preferredCft)},`,
        `        preferred_vrc: ${rustString(region.preferredVrc)},`,
        `        remap: REGION_${index}_REMAP,`,
        `        ech: ${region.ech},`,
        `        google_enabled: ${region.googleEnabled},`,
        `        google_proxies: ${google},`,
        '    },',
      ].join('\n');
    })
    .join('\n');

  return `#[derive(Debug, Clone, Copy)]
pub struct Upstream {
    pub name: &'static str,
    pub url: &'static str,
    pub ecs: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct MetaEchConfig {
    pub domain_pattern: &'static str,
    pub config_b64: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    pub family: u8,
    pub address: &'static str,
    pub prefix: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct GoogleProxy {
    pub match_patterns: &'static [&'static str],
    pub ips: &'static [&'static str],
    pub sni: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct RegionConfig {
    pub name: &'static str,
    pub preferred_cf: &'static str,
    pub preferred_cft: &'static str,
    pub preferred_vrc: &'static str,
    pub remap: &'static [&'static str],
    pub ech: bool,
    pub google_enabled: bool,
    pub google_proxies: Option<&'static [GoogleProxy]>,
}

pub const CONFIGURED: u8 = ${rustInteger(config.configured)};
pub const AUTO_CONCURRENCY: usize = ${rustInteger(config.autoConcurrency)};
pub const FAST_TIMEOUT_MS: u32 = ${rustInteger(config.fastTimeoutMs)};
pub const MIX_TIMEOUT_MS: u32 = ${rustInteger(config.mixTimeoutMs)};
pub const MIX_TTL: u32 = ${rustInteger(config.mixTtl)};
pub const PREFERRED_TTL: u32 = ${rustInteger(config.preferredTtl)};
pub const ECS_PREFIX4: u8 = ${rustInteger(config.ecsPrefix4)};
pub const ECS_PREFIX6: u8 = ${rustInteger(config.ecsPrefix6)};
pub const SERVFAIL_EDE_CODE: u16 = ${rustInteger(config.servfailEdeCode)};
pub const CF_ECH_CACHE_TTL_MS: u32 = ${rustInteger(config.cfEchCacheTtlMs)};
pub const CF_ECH_STALE_TTL_MS: u32 = ${rustInteger(config.cfEchStaleTtlMs)};

pub const ECS_PROTECT_MS: u32 = ${rustInteger(config.ecsProtectMs)};
pub const HARD_TIMEOUT_MS: u32 = ${rustInteger(config.hardTimeoutMs)};
pub const META_HARD_TIMEOUT_MS: u32 = ${rustInteger(config.metaHardTimeoutMs)};
pub const META_COLLECT_WINDOW_MS: u32 = ${rustInteger(config.metaCollectWindowMs)};
pub const META_MAX_IPS: usize = ${rustInteger(config.metaMaxIps)};
pub const PREFERRED_TIMEOUT_MS: u32 = ${rustInteger(config.preferredTimeoutMs)};
pub const AUTO_PROVIDER: &str = "auto";
pub const LOG_LEVEL: &str = ${rustString(config.logLevel)};
pub const REGION: &str = ${rustString(regionNames.join(','))};

pub static UPSTREAMS: &[Upstream] = &[
${upstreamEntries}
];

pub static META_ECH_MAP: &[MetaEchConfig] = &[
${metaEchMapEntries}
];

pub static FOREIGN_UPSTREAMS: &[&str] = ${rustStringSlice(foreignUpstreams, '')};

pub static BLOCKED_RANGES: &[Cidr] = &[
${blockedEntries}
];

${geoipStatics}

${regionStatics.join('\n\n')}${regionStatics.length > 0 ? '\n\n' : ''}pub static REGION_NAMES: &[&str] = ${rustStringSlice(regionNames, '')};

pub static REGION_CONFIG: &[RegionConfig] = &[
${regionEntries}
];
`;
}

function formatRust(filepath) {
  const result = spawnSync('rustfmt', [filepath], { stdio: 'inherit' });
  if (result.error?.code === 'ENOENT') {
    console.warn('rustfmt is unavailable; skipping generated config formatting');
    return;
  }
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`rustfmt failed for ${filepath}`);
  }
}

async function main() {
  const rootDir = path.resolve(__dirname, '..');
  const configJsPath = path.join(rootDir, 'superdoh.config.js');
  const envPath = path.join(rootDir, '.env');
  const configRsPath = path.join(rootDir, 'src', 'config.rs');

  console.log(`Reading ${configJsPath} ...`);
  if (!fs.existsSync(configJsPath)) {
    throw new Error('superdoh.config.js not found at repo root. Copy from superdoh.config.example.js.');
  }

  const userConfigModule = await import(`file://${configJsPath}`);
  const userConfig = isRecord(userConfigModule.default) ? userConfigModule.default : {};
  console.log(`configured = ${userConfig.configured === 1 ? 1 : 0}`);

  const env = parseEnv(envPath);
  if (Object.keys(env).length > 0) {
    console.log(`.env found (${Object.keys(env).length} keys) — used as optional override`);
  }

  const config = resolveConfig(userConfig, env);
  if (Object.keys(config.upstreams).length === 0) {
    throw new Error('No upstreams enabled! Check superdoh.config.js upstreams section.');
  }

  const geoipCidrs = await fetchGeoipCidrs(config.geoipUrl);
  const needsGoogleProxy =
    config.fetchGoogleProxy && Object.values(config.regions).some((region) => isRecord(region) && region.google === true);
  const fetchedGoogleProxy = needsGoogleProxy
    ? await fetchGoogleProxy(config.cealingHostUrl)
    : (console.log('No region has google=true — skipping Cealing-Host fetch.'), null);

  console.log(`Generating ${configRsPath} ...`);
  fs.writeFileSync(configRsPath, generateConfigRs(config, geoipCidrs, fetchedGoogleProxy));
  formatRust(configRsPath);
  console.log(`Done — ${Object.keys(config.upstreams).length} upstreams configured, CONFIGURED=${config.configured}.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
