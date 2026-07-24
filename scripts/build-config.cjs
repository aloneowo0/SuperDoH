#!/usr/bin/env node
// build-config.js — 从 .env 生成 config.js，或在 USE_CONFIG_JS=true 时直接使用现有 config.js

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// ── 预设上游的 URL 和 EDNS 能力 ──────────────────────────────────
const PRESETS = {
    google:     { url: 'https://dns.google/dns-query',         ecs: true  },
    cloudflare_Public: { url: 'https://cloudflare-dns.com/dns-query', ecs: false },
    quad9:      { url: 'https://dns11.quad9.net/dns-query',   ecs: true  },
    adguard:    { url: 'https://dns.adguard-dns.com/dns-query', ecs: true  },
    opendns:    { url: 'https://dns.opendns.com/dns-query',   ecs: true  },
    yandex:     { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false },
    dnspod:     { url: 'https://sm2.doh.pub/dns-query',       ecs: true  },
    alidns:     { url: 'https://dns.alidns.com/dns-query',    ecs: true  },
    360:        { url: 'https://doh.360.cn/dns-query',        ecs: true  },
    nextdns:    { url: 'https://dns.nextdns.io',              ecs: true  },
};

const GEOIP_BASE_URL = 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/';
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

async function fetchGeoipCidrs(category) {
    const url = GEOIP_BASE_URL + category + '.txt';
    const fetcher = url.startsWith('https') ? https : http;
    const body = await new Promise(function(resolve, reject) {
        const req = fetcher.get(url, function(res) {
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
        req.setTimeout(15000, function() {
            req.destroy(new Error('Timeout fetching ' + url));
        });
        req.on('error', reject);
    });
    return body.split(/\r?\n/).map(function(line) { return line.trim(); }).filter(function(line) {
        return line && !line.startsWith('#');
    });
}

// ── 解析 .env ─────────────────────────────────────────────────────
function parseEnv(filepath) {
    if (!fs.existsSync(filepath)) {
        console.error(`.env not found: ${filepath}`);
        process.exit(1);
    }
    const env = {};
    const lines = fs.readFileSync(filepath, 'utf-8').split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq < 0) continue;
        const key = trimmed.slice(0, eq).trim();
        const val = trimmed.slice(eq + 1).trim();
        env[key] = val;
    }
    return env;
}

// ── 构建 UPSTREAMS ─────────────────────────────────────────────────
function buildUpstreams(env) {
    const upstreams = {};

    // 预设上游
    for (const [name, cfg] of Object.entries(PRESETS)) {
        const key = name.toUpperCase();
        if (env[key] === 'true') {
            upstreams[name] = { ...cfg };
        }
    }

    // 自定义上游 (CUSTOM_<NAME>=URL)
    for (const [key, url] of Object.entries(env)) {
        if (!key.startsWith('CUSTOM_') || key === 'CUSTOM_') continue;
        const name = key.slice(7).toLowerCase();
        if (!/^[a-z][a-z0-9_]*$/.test(name)) {
            console.warn(`Skip invalid custom upstream name: ${key} → ${name}`);
            continue;
        }
        upstreams[name] = { url, ecs: true };
    }

    return upstreams;
}

// ── 解析 CIDR 黑名单 ───────────────────────────────────────────────
function parseBlockedCidrs(cidrsStr) {
    const entries = [];
    if (!cidrsStr) return entries;
    for (const cidr of cidrsStr.split(/\s+/)) {
        if (!cidr) continue;
        try {
            if (cidr.includes(':')) {
                const [ip, pfxStr] = cidr.split('/');
                const mask = Number(pfxStr);
                if (isNaN(mask) || mask < 0 || mask > 128) continue;
                const addr = parseIPv6(ip);
                if (!addr) continue;
                if (addr.every(b => b === 0)) {
                    entries.push({ family: 6, mask });
                } else {
                    entries.push({ family: 6, addr, mask });
                }
            } else {
                const [ip, pfx] = cidr.split('/');
                const parts = ip.split('.').map(Number);
                if (parts.length !== 4) continue;
                if (parts.some(p => isNaN(p) || p < 0 || p > 255)) continue;
                const mask = Number(pfx);
                if (isNaN(mask) || mask < 0 || mask > 32) continue;
                entries.push({ family: 4, addr: parts, mask });
            }
        } catch (_) { /* skip malformed */ }
    }
    return entries;
}

function parseIPv6(ip) {
    // Expand :: to full 8 groups
    const parts = ip.split('::');
    if (parts.length > 2) return null;
    const left = parts[0] ? parts[0].split(':').filter(g => g !== '') : [];
    const right = parts[1] ? parts[1].split(':').filter(g => g !== '') : [];
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    const groups = [...left, ...Array(fill).fill('0'), ...right];
    const addr = new Array(16).fill(0);
    for (let i = 0; i < 8; i++) {
        const val = parseInt(groups[i] || '0', 16);
        addr[i * 2] = (val >> 8) & 0xFF;
        addr[i * 2 + 1] = val & 0xFF;
    }
    return addr;
}

// ── 生成 config.js ─────────────────────────────────────────────────
function geoipExportLines(geoipCidrs) {
    return Object.keys(GEOIP_CATEGORIES).map(function(key) {
        return 'export const GEOIP_' + key + ' = ' + JSON.stringify(geoipCidrs[key] || []) + ';';
    }).join('\n');
}

function generateConfig(env, upstreams, fetchedGoogleProxy, geoipCidrs) {
    const entries = Object.entries(upstreams)
        .map(([name, cfg]) => {
            return `    ${name}: { url: ${JSON.stringify(cfg.url)}, ecs: ${cfg.ecs} },`;
        })
        .join('\n');

    const blocked = parseBlockedCidrs(env.BLOCKED_CIDRS || '');
    const blockedLines = blocked.map((e, i) => {
        let line = `    { family: ${e.family}, `;
        if (e.addr) line += `addr: [${e.addr.join(', ')}], `;
        line += `mask: ${e.mask} }`;
        if (i < blocked.length - 1) line += ',';
        return line;
    });
    const blockedStr = blockedLines.length > 0
        ? '[\n' + blockedLines.join('\n') + '\n]'
        : '[]';

    const ecsProtectMs = 20;
    const hardTimeoutMs = 800;
    const ecsPrefix4 = parseInt(env.ECS_PREFIX4, 10);
    const ecsPrefix6 = parseInt(env.ECS_PREFIX6, 10);
    const metaHardTimeoutMs = 800;
    const metaCollectWindowMs = 50;
    const metaMaxIps = 4;
    const preferredTimeoutMs = 300;
    // AUTO 竞速并发上游数。0 = 全部上游（默认）。
    // Cloudflare Workers Free 计划只有 6 个同时出站连接，设为 4 可避免挤占其他子请求的槽位。
    var autoConcurrency = parseInt(env.AUTO_CONCURRENCY || env.MIX_CONCURRENCY, 10);
    if (isNaN(autoConcurrency) || autoConcurrency < 0) autoConcurrency = 0;

    // 地区优化解析（从 REGION_XX_* 块自动发现地区）
    const regionSet = new Set();
    for (const key of Object.keys(env)) {
        const m = key.match(/^REGION_([A-Z]{2})_/);
        if (m) regionSet.add(m[1]);
    }
    const regions = [...regionSet].sort();
    const region = regions.join(',');

    // 全局默认值
    const defaultPreferredCfDomain = env.PREFERRED_CF_DOMAIN || '';
    const defaultRemap = (env.FORCE_REMAP_DOMAINS || '')
        .split(/[\s,]+/).filter(d => d.length > 0);

    const regionConfig = {};
    for (const r of regions) {
        regionConfig[r] = {
            preferredCf: env['REGION_' + r + '_PREFERRED_CF'] || defaultPreferredCfDomain,
            preferredCft: env['REGION_' + r + '_PREFERRED_CFT'] || '',
            preferredVrc: env['REGION_' + r + '_PREFERRED_VRC'] || '',
            remap: env['REGION_' + r + '_REMAP']
                ? env['REGION_' + r + '_REMAP'].split(/[\s,]+/).filter(d => d.length > 0)
                : defaultRemap,
            ech: env['REGION_' + r + '_ECH'] === 'true',
            google: env['REGION_' + r + '_GOOGLE'] === 'true' ? (fetchedGoogleProxy || []) : undefined,
        };
    }
    const regionConfigStr = JSON.stringify(regionConfig, null, 2)
        .replace(/^/gm, '  ')
        .replace(/^\s{2}/, '');

    return `/**
 * SuperDoH — 配置文件（由 scripts/build-config.cjs 自动生成）
 * USE_CONFIG_JS=true 时 scripts/build-config.cjs 不会重写本文件，
 * Worker 会直接读取现有 config.js。
 */

export const UPSTREAMS = {
${entries}
};

export const FOREIGN_UPSTREAMS = Object.keys(UPSTREAMS).filter(function(n) { return n !== 'dnspod' && n !== 'alidns'; });

export const ECS_PROTECT_MS = ${ecsProtectMs};
export const HARD_TIMEOUT_MS = ${hardTimeoutMs};
export const META_HARD_TIMEOUT_MS = ${metaHardTimeoutMs};
export const META_COLLECT_WINDOW_MS = ${metaCollectWindowMs};
export const META_MAX_IPS = ${metaMaxIps};
export const PREFERRED_TIMEOUT_MS = ${preferredTimeoutMs};
export const AUTO_CONCURRENCY = ${autoConcurrency};
export const ECS_PREFIX4 = ${isNaN(ecsPrefix4) ? 24 : ecsPrefix4};
export const ECS_PREFIX6 = ${isNaN(ecsPrefix6) ? 56 : ecsPrefix6};

export const BLOCKED_RANGES = ${blockedStr};

${geoipExportLines(geoipCidrs)}

export const AUTO_PROVIDER = 'auto';

// ── 日志级别 ────────────────────────────────────────
export const LOG_LEVEL = ${JSON.stringify(env.LOG_LEVEL || 'info')};

// ── 地区优化解析 ─────────────────────────────────────
export const REGION = ${JSON.stringify(region)};
export const REGION_CONFIG = ${regionConfigStr};
`;
}

// ── Main ───────────────────────────────────────────────────────────
const rootDir = path.resolve(__dirname, '..');
const envPath = path.join(rootDir, '.env');
const configPath = path.join(rootDir, 'src', 'config.js');

async function main() {
  console.log(`Reading ${envPath} ...`);
  const env = parseEnv(envPath);

  if (env.USE_CONFIG_JS === 'true') {
    if (!fs.existsSync(configPath)) {
      console.error('USE_CONFIG_JS=true but src/config.js does not exist. Copy src/config.example.js to src/config.js first.');
      process.exit(1);
    }
    console.log(`USE_CONFIG_JS=true — using existing ${configPath}; no config generated.`);
    return;
  }

  console.log('Building upstreams ...');
  const upstreams = buildUpstreams(env);

  if (Object.keys(upstreams).length === 0) {
    console.error('No upstreams enabled! Set at least one to true in .env');
    process.exit(1);
  }

  var geoipCidrs = {};
  for (var geoipKey of Object.keys(GEOIP_CATEGORIES)) geoipCidrs[geoipKey] = [];
  console.log('Fetching GeoIP CIDR lists ...');
  var geoipResults = await Promise.allSettled(Object.keys(GEOIP_CATEGORIES).map(async function(key) {
    var category = GEOIP_CATEGORIES[key];
    return { key: key, cidrs: await fetchGeoipCidrs(category) };
  }));
  for (var ri = 0; ri < geoipResults.length; ri++) {
    if (geoipResults[ri].status === 'fulfilled') {
      var rr = geoipResults[ri].value;
      geoipCidrs[rr.key] = rr.cidrs;
      console.log(`Fetched ${rr.cidrs.length} ${GEOIP_CATEGORIES[rr.key]} CIDRs`);
    } else {
      console.warn('Failed to fetch ' + Object.keys(GEOIP_CATEGORIES)[ri] + ': ' + geoipResults[ri].reason.message);
    }
  }

  // 从 Cealing-Host 拉取 Google 代理配置
  let fetchedGoogleProxy = null;
  if (env.FETCH_GOOGLE_PROXY !== 'false') {
    try {
      const url = env.CEALING_HOST_URL || 'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json';
      console.log(`Fetching Cealing-Host from ${url} ...`);
      const https = require('https');
      const http = require('http');
      const fetcher = url.startsWith('https') ? https : http;
      const cealingData = await new Promise(function(resolve, reject) {
        const req = fetcher.get(url, function(res) {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            res.resume();
            reject(new Error('HTTP ' + res.statusCode + ' for ' + url));
            return;
          }
          var body = '';
          res.setEncoding('utf8');
          res.on('data', function(chunk) { body += chunk; });
          res.on('end', function() {
            try { resolve(JSON.parse(body)); }
            catch(e) { reject(e); }
          });
        });
        req.setTimeout(15000, function() {
          req.destroy(new Error('Timeout fetching Cealing-Host'));
        });
        req.on('error', reject);
      });

      if (cealingData && Array.isArray(cealingData)) {
        var googleEntries = [];
        var googleKeys = ['google', 'youtube', 'gstatic', 'youtu.be', 'ggpht',
                          'blogger', 'blogspot', 'googleapis', 'googlevideo',
                          'android.com', 'googleadservices', 'gemini'];
        
        for (var i = 0; i < cealingData.length; i++) {
          var r = cealingData[i];
          var domains = r[0];
          var sni = (r[1] || '').trim();
          var ip = (r[2] || '').trim();
          if (!ip || ip.startsWith('[')) continue;

          var isGoogle = false;
          for (var j = 0; j < domains.length; j++) {
            var d = domains[j].replace(/[#$^*]/g, '').toLowerCase();
            for (var k = 0; k < googleKeys.length; k++) {
              if (d.indexOf(googleKeys[k]) >= 0) { isGoogle = true; break; }
            }
            if (isGoogle) break;
          }
          if (!isGoogle) continue;

          var matchPatterns = [];
          for (var j = 0; j < domains.length; j++) {
            var d = domains[j];
            if (d.startsWith('^')) continue;
            var clean = d.replace(/[#$]/g, '').replace(/\*/g, '').trim();
            if (!clean) continue;
            matchPatterns.push(clean);
          }

          if (matchPatterns.length > 0) {
            googleEntries.push({ ips: [ip], sni: sni || null, match: matchPatterns });
          }
        }

        if (googleEntries.length > 0) {
          var merged = [];
          var seenMap = {};
          for (var k = 0; k < googleEntries.length; k++) {
            var e = googleEntries[k];
            var key = JSON.stringify(e.ips) + '|' + (e.sni || '');
            if (seenMap[key] !== undefined) {
              merged[seenMap[key]].match = merged[seenMap[key]].match.concat(e.match);
            } else {
              seenMap[key] = merged.length;
              merged.push(e);
            }
          }
          fetchedGoogleProxy = merged;
          console.log(`Extracted ${fetchedGoogleProxy.length} Google proxy entries from Cealing-Host`);

          // 补充 YouTube CDN 域名
          var youtubeSupplements = [
            'googlevideo.com', 'yt3.ggpht.com', 'ytimg.com',
            'gvt1.com', 'gvt2.com', 'gvt3.com', 'video.google.com',
          ];
          // 补充 Google 广告 / 区域域名（Cealing-Host 规则未覆盖）
          var googleSupplements = [
            'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
            'google.com.hk', 'google.cn', 'google.co.jp',
            'googleusercontent.com', 'gmail.com',
          ];
          // 补充更多代理 IP

          for (var k = 0; k < fetchedGoogleProxy.length; k++) {
            if (fetchedGoogleProxy[k].sni === 'g.cn') {
              fetchedGoogleProxy[k].match = fetchedGoogleProxy[k].match.concat(youtubeSupplements, googleSupplements);
              break;
            }
          }
        }
      }
    } catch (e) {
      console.warn('Failed to fetch Cealing-Host for Google proxy:', e.message);
    }
  }

  console.log(`Generating ${configPath} ...`);
  fs.writeFileSync(configPath, generateConfig(env, upstreams, fetchedGoogleProxy, geoipCidrs));

  console.log(`Done — ${Object.keys(upstreams).length} upstreams configured.`);
}

main().catch(function(err) { console.error(err); process.exit(1); });
