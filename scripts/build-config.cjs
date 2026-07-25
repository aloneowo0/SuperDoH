#!/usr/bin/env node
// build-config.cjs — 读 superdoh.config.js → 生成 src/config.js + src/templates.js
//
// 配置源优先级：superdoh.config.js（人类源，tracked）> .env（可选覆盖，legacy）
// superdoh.config.js 的 configured:0 → 生成内置默认配置（CF+Google+AUTO，无地区优化）
// superdoh.config.js 的 configured:1 → 用用户填写的配置生成

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// ── 预设上游 ─────────────────────────────────────────────────────
const PRESETS = {
  google:            { url: 'https://dns.google/dns-query',                ecs: true  },
  cloudflare_Public: { url: 'https://cloudflare-dns.com/dns-query',         ecs: false },
  quad9:             { url: 'https://dns11.quad9.net/dns-query',            ecs: true  },
  adguard:           { url: 'https://dns.adguard-dns.com/dns-query',        ecs: true  },
  opendns:           { url: 'https://dns.opendns.com/dns-query',            ecs: true  },
  yandex:            { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false },
  dnspod:            { url: 'https://sm2.doh.pub/dns-query',                ecs: true  },
  alidns:            { url: 'https://dns.alidns.com/dns-query',             ecs: true  },
  '360':             { url: 'https://doh.360.cn/dns-query',                 ecs: true  },
  nextdns:           { url: 'https://dns.nextdns.io',                      ecs: true  },
};

// configured:0 时使用的内置默认上游
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
const DEFAULT_CEALING_HOST_URL = 'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json';

// ── HTTP fetch helper ────────────────────────────────────────────
function fetchText(url) {
  const fetcher = url.startsWith('https') ? https : http;
  return new Promise((resolve, reject) => {
    const req = fetcher.get(url, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        reject(new Error('HTTP ' + res.statusCode + ' for ' + url));
        return;
      }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.setTimeout(15000, () => req.destroy(new Error('Timeout fetching ' + url)));
    req.on('error', reject);
  });
}

// ── 解析 .env（legacy，可选）─────────────────────────────────────
function parseEnv(filepath) {
  if (!fs.existsSync(filepath)) return {};
  const env = {};
  const lines = fs.readFileSync(filepath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    env[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return env;
}

// ── CIDR 解析 ─────────────────────────────────────────────────────
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
        if (addr.every((b) => b === 0)) {
          entries.push({ family: 6, mask });
        } else {
          entries.push({ family: 6, addr, mask });
        }
      } else {
        const [ip, pfx] = cidr.split('/');
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) continue;
        if (parts.some((p) => isNaN(p) || p < 0 || p > 255)) continue;
        const mask = Number(pfx);
        if (isNaN(mask) || mask < 0 || mask > 32) continue;
        entries.push({ family: 4, addr: parts, mask });
      }
    } catch (_) { /* skip malformed */ }
  }
  return entries;
}

function parseIPv6(ip) {
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(':').filter((g) => g !== '') : [];
  const right = parts[1] ? parts[1].split(':').filter((g) => g !== '') : [];
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

// ── 从 superdoh.config.js + .env 构建 UPSTREAMS ──────────────────
function buildUpstreams(userCfg, env) {
  const upstreams = {};

  const userUpstreams = userCfg.upstreams || {};

  for (const [name, val] of Object.entries(userUpstreams)) {
    if (val === true) {
      if (PRESETS[name]) {
        upstreams[name] = { ...PRESETS[name] };
      } else {
        console.warn(`Unknown preset upstream: ${name} (skipped)`);
      }
    } else if (typeof val === 'string' && val.length > 0) {
      if (!/^[a-z][a-z0-9_]*$/.test(name)) {
        console.warn(`Skip invalid custom upstream name: ${name}`);
        continue;
      }
      upstreams[name] = { url: val, ecs: true };
    } else if (val === false) {
      // 显式禁用，跳过
    }
  }

  // .env legacy 覆盖（USE_CONFIG_JS=false 时 .env 仍可叠加）
  for (const [name, cfg] of Object.entries(PRESETS)) {
    const key = name.toUpperCase();
    if (env[key] === 'true' && !upstreams[name]) {
      upstreams[name] = { ...cfg };
    }
    if (env[key] === 'false') {
      delete upstreams[name];
    }
  }
  for (const [key, url] of Object.entries(env)) {
    if (!key.startsWith('CUSTOM_') || key === 'CUSTOM_') continue;
    const name = key.slice(7).toLowerCase();
    if (upstreams[name]) continue;
    if (!/^[a-z][a-z0-9_]*$/.test(name)) {
      console.warn(`Skip invalid custom upstream name from .env: ${key} → ${name}`);
      continue;
    }
    upstreams[name] = { url, ecs: true };
  }

  return upstreams;
}

// ── GeoIP 抓取 ───────────────────────────────────────────────────
async function fetchGeoipCidrs(geoipBase) {
  const cidrs = {};
  for (const key of Object.keys(GEOIP_CATEGORIES)) cidrs[key] = [];
  console.log('Fetching GeoIP CIDR lists from ' + geoipBase + ' ...');
  const results = await Promise.allSettled(
    Object.keys(GEOIP_CATEGORIES).map(async (key) => {
      const category = GEOIP_CATEGORIES[key];
      const url = geoipBase + category + '.txt';
      const text = await fetchText(url);
      return {
        key,
        cidrs: text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')),
      };
    })
  );
  for (let i = 0; i < results.length; i++) {
    if (results[i].status === 'fulfilled') {
      cidrs[results[i].value.key] = results[i].value.cidrs;
      console.log(`Fetched ${results[i].value.cidrs.length} ${GEOIP_CATEGORIES[results[i].value.key]} CIDRs`);
    } else {
      console.warn('Failed to fetch ' + Object.keys(GEOIP_CATEGORIES)[i] + ': ' + results[i].reason.message);
    }
  }
  return cidrs;
}

// ── Cealing-Host Google 代理抓取 ─────────────────────────────────
async function fetchGoogleProxy(cealingUrl) {
  let fetched = null;
  try {
    console.log('Fetching Cealing-Host from ' + cealingUrl + ' ...');
    const data = await fetchText(cealingUrl);
    const cealingData = JSON.parse(data);
    if (!cealingData || !Array.isArray(cealingData)) return null;

    const googleKeys = ['google', 'youtube', 'gstatic', 'youtu.be', 'ggpht',
      'blogger', 'blogspot', 'googleapis', 'googlevideo',
      'android.com', 'googleadservices', 'gemini'];

    const googleEntries = [];
    for (let i = 0; i < cealingData.length; i++) {
      const r = cealingData[i];
      const domains = r[0];
      const sni = (r[1] || '').trim();
      const ip = (r[2] || '').trim();
      if (!ip || ip.startsWith('[')) continue;

      let isGoogle = false;
      for (let j = 0; j < domains.length; j++) {
        const d = domains[j].replace(/[#$^*]/g, '').toLowerCase();
        for (let k = 0; k < googleKeys.length; k++) {
          if (d.indexOf(googleKeys[k]) >= 0) { isGoogle = true; break; }
        }
        if (isGoogle) break;
      }
      if (!isGoogle) continue;

      const matchPatterns = [];
      for (let j = 0; j < domains.length; j++) {
        const d = domains[j];
        if (d.startsWith('^')) continue;
        const clean = d.replace(/[#$]/g, '').replace(/\*/g, '').trim();
        if (!clean) continue;
        matchPatterns.push(clean);
      }
      if (matchPatterns.length > 0) {
        googleEntries.push({ ips: [ip], sni: sni || null, match: matchPatterns });
      }
    }

    if (googleEntries.length > 0) {
      const merged = [];
      const seenMap = {};
      for (const e of googleEntries) {
        const key = JSON.stringify(e.ips) + '|' + (e.sni || '');
        if (seenMap[key] !== undefined) {
          merged[seenMap[key]].match = merged[seenMap[key]].match.concat(e.match);
        } else {
          seenMap[key] = merged.length;
          merged.push(e);
        }
      }
      fetched = merged;
      console.log(`Extracted ${fetched.length} Google proxy entries from Cealing-Host`);

      const youtubeSupplements = ['googlevideo.com', 'yt3.ggpht.com', 'ytimg.com',
        'gvt1.com', 'gvt2.com', 'gvt3.com', 'video.google.com'];
      const googleSupplements = ['doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
        'google.com.hk', 'google.cn', 'google.co.jp', 'googleusercontent.com', 'gmail.com'];
      for (const entry of fetched) {
        if (entry.sni === 'g.cn') {
          entry.match = entry.match.concat(youtubeSupplements, googleSupplements);
          break;
        }
      }
    }
  } catch (e) {
    console.warn('Failed to fetch Cealing-Host for Google proxy: ' + e.message);
  }
  return fetched;
}

// ── 数字解析 helper ───────────────────────────────────────────────
function num(val, def) {
  const n = parseInt(val, 10);
  return isNaN(n) ? def : n;
}

// ── 从 userCfg + env 组装最终配置值 ──────────────────────────────
function resolveConfig(userCfg, env) {
  const configured = userCfg.configured === 1 ? 1 : 0;

  if (configured === 0) {
    // 首次配置模式：内置默认 CF + Google + AUTO，无地区优化
    const upstreams = {};
    for (const k of DEFAULT_UPSTREAM_KEYS) {
      upstreams[k] = { ...PRESETS[k] };
    }
    return {
      configured: 0,
      upstreams,
      ecsPrefix4: 24,
      ecsPrefix6: 56,
      blockedCidrs: '127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128',
      autoConcurrency: 6,
      ecsProtectMs: 20,
      hardTimeoutMs: 800,
      metaHardTimeoutMs: 800,
      metaCollectWindowMs: 50,
      metaMaxIps: 4,
      preferredTimeoutMs: 300,
      logLevel: 'info',
      regions: {},
      geoipUrl: DEFAULT_GEOIP_URL,
      cealingHostUrl: DEFAULT_CEALING_HOST_URL,
      fetchGoogleProxy: true,
    };
  }

  // configured:1 — 用用户配置，.env 可选覆盖个别字段
  const upstreams = buildUpstreams(userCfg, env);
  return {
    configured: 1,
    upstreams,
    ecsPrefix4: num(env.ECS_PREFIX4, num(userCfg.ecsPrefix4, 24)),
    ecsPrefix6: num(env.ECS_PREFIX6, num(userCfg.ecsPrefix6, 56)),
    blockedCidrs: env.BLOCKED_CIDRS || userCfg.blockedCidrs || '127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128',
    autoConcurrency: num(env.AUTO_CONCURRENCY || env.MIX_CONCURRENCY, num(userCfg.autoConcurrency, 6)),
    ecsProtectMs: num(env.ECS_PROTECT_MS, num(userCfg.ecsProtectMs, 20)),
    hardTimeoutMs: num(env.HARD_TIMEOUT_MS, num(userCfg.hardTimeoutMs, 800)),
    metaHardTimeoutMs: num(env.META_HARD_TIMEOUT_MS, num(userCfg.metaHardTimeoutMs, 800)),
    metaCollectWindowMs: num(env.META_COLLECT_WINDOW_MS, num(userCfg.metaCollectWindowMs, 50)),
    metaMaxIps: num(env.META_MAX_IPS, num(userCfg.metaMaxIps, 4)),
    preferredTimeoutMs: num(env.PREFERRED_TIMEOUT_MS, num(userCfg.preferredTimeoutMs, 300)),
    logLevel: env.LOG_LEVEL || userCfg.logLevel || 'info',
    regions: userCfg.regions || {},
    geoipUrl: userCfg.geoipUrl || DEFAULT_GEOIP_URL,
    cealingHostUrl: userCfg.cealingHostUrl || DEFAULT_CEALING_HOST_URL,
    fetchGoogleProxy: userCfg.fetchGoogleProxy !== false,
  };
}

// ── 生成 src/config.js ────────────────────────────────────────────
function generateConfigJs(cfg, geoipCidrs, fetchedGoogleProxy) {
  const upstreamEntries = Object.entries(cfg.upstreams)
    .map(([name, c]) => `    ${name}: { url: ${JSON.stringify(c.url)}, ecs: ${c.ecs} },`)
    .join('\n');

  const foreignUpstreams = Object.keys(cfg.upstreams)
    .filter((n) => n !== 'dnspod' && n !== 'alidns');

  const blocked = parseBlockedCidrs(cfg.blockedCidrs);
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

  // 地区配置
  const regionNames = Object.keys(cfg.regions).sort();
  const regionConfig = {};
  for (const r of regionNames) {
    const rc = cfg.regions[r];
    regionConfig[r] = {
      preferredCf: rc.preferredCf || '',
      preferredCft: rc.preferredCft || '',
      preferredVrc: rc.preferredVrc || '',
      remap: typeof rc.remap === 'string'
        ? rc.remap.split(/[\s,]+/).filter((d) => d.length > 0)
        : (Array.isArray(rc.remap) ? rc.remap : []),
      ech: rc.ech === true,
      google: rc.google === true ? (fetchedGoogleProxy || []) : undefined,
    };
  }
  const regionConfigStr = JSON.stringify(regionConfig, null, 2)
    .replace(/^/gm, '  ')
    .replace(/^\s{2}/, '');

  const geoipExportLines = Object.keys(GEOIP_CATEGORIES)
    .map((key) => `export const GEOIP_${key} = ${JSON.stringify(geoipCidrs[key] || [])};`)
    .join('\n');

  return `/**
 * SuperDoH — src/config.js（由 scripts/build-config.cjs 自动生成，请勿手动修改）
 * 源文件：仓库根目录 superdoh.config.js
 */
export const CONFIGURED = ${cfg.configured};

export const UPSTREAMS = {
${upstreamEntries}
};

export const FOREIGN_UPSTREAMS = ${JSON.stringify(foreignUpstreams)};

export const ECS_PROTECT_MS = ${cfg.ecsProtectMs};
export const HARD_TIMEOUT_MS = ${cfg.hardTimeoutMs};
export const META_HARD_TIMEOUT_MS = ${cfg.metaHardTimeoutMs};
export const META_COLLECT_WINDOW_MS = ${cfg.metaCollectWindowMs};
export const META_MAX_IPS = ${cfg.metaMaxIps};
export const PREFERRED_TIMEOUT_MS = ${cfg.preferredTimeoutMs};
export const AUTO_CONCURRENCY = ${cfg.autoConcurrency};
export const ECS_PREFIX4 = ${cfg.ecsPrefix4};
export const ECS_PREFIX6 = ${cfg.ecsPrefix6};

export const BLOCKED_RANGES = ${blockedStr};

${geoipExportLines}

export const AUTO_PROVIDER = 'auto';

export const LOG_LEVEL = ${JSON.stringify(cfg.logLevel)};

export const REGION = ${JSON.stringify(regionNames.join(','))};
export const REGION_CONFIG = ${regionConfigStr};
`;
}

// ── 生成 src/templates.js ────────────────────────────────────────
function generateTemplatesJs(rootDir) {
  const frontendDir = path.join(rootDir, 'frontend');
  const htmlCn = fs.readFileSync(path.join(frontendDir, 'index.html'), 'utf8');
  const htmlEn = fs.readFileSync(path.join(frontendDir, 'en.html'), 'utf8');
  const cssContent = fs.readFileSync(path.join(frontendDir, 'css', 'style.css'), 'utf8');
  const jsContent = fs.readFileSync(path.join(frontendDir, 'js', 'resolver.js'), 'utf8');
  const wizardJsPath = path.join(frontendDir, 'js', 'config-wizard.js');
  const wizardContent = fs.existsSync(wizardJsPath) ? fs.readFileSync(wizardJsPath, 'utf8') : '';
  return `// Auto-generated by scripts/build-config.cjs from frontend/*
// Do not edit manually — edit frontend/ files instead
export const HTML_CN = ${JSON.stringify(htmlCn)};
export const HTML_EN = ${JSON.stringify(htmlEn)};
export const CSS = ${JSON.stringify(cssContent)};
export const JS = ${JSON.stringify(jsContent)};
export const WIZARD_JS = ${JSON.stringify(wizardContent)};
`;
}

// ── Main ─────────────────────────────────────────────────────────
async function main() {
  const rootDir = path.resolve(__dirname, '..');
  const configJsPath = path.join(rootDir, 'superdoh.config.js');
  const envPath = path.join(rootDir, '.env');
  const configPath = path.join(rootDir, 'src', 'config.js');
  const templatesPath = path.join(rootDir, 'src', 'templates.js');

  console.log(`Reading ${configJsPath} ...`);
  if (!fs.existsSync(configJsPath)) {
    console.error('superdoh.config.js not found at repo root. Copy from superdoh.config.example.js.');
    process.exit(1);
  }

  const userCfgMod = await import('file://' + configJsPath);
  const userCfg = userCfgMod.default || {};

  console.log(`configured = ${userCfg.configured === 1 ? 1 : 0}`);
  const env = parseEnv(envPath);
  if (Object.keys(env).length > 0) {
    console.log(`.env found (${Object.keys(env).length} keys) — used as optional override`);
  }

  const cfg = resolveConfig(userCfg, env);

  if (Object.keys(cfg.upstreams).length === 0) {
    console.error('No upstreams enabled! Check superdoh.config.js upstreams section.');
    process.exit(1);
  }

  // GeoIP 总是抓取（configured:0 也抓，保证 cdn.js 不爆）
  const geoipBase = cfg.geoipUrl;
  const geoipCidrs = await fetchGeoipCidrs(geoipBase);

  // Cealing-Host：仅当任意 region.google=true 时抓取
  const needsGoogleProxy = cfg.fetchGoogleProxy &&
    Object.values(cfg.regions).some((r) => r.google === true);
  let fetchedGoogleProxy = null;
  if (needsGoogleProxy) {
    fetchedGoogleProxy = await fetchGoogleProxy(cfg.cealingHostUrl);
  } else {
    console.log('No region has google=true — skipping Cealing-Host fetch.');
  }

  console.log(`Generating ${configPath} ...`);
  fs.writeFileSync(configPath, generateConfigJs(cfg, geoipCidrs, fetchedGoogleProxy));

  console.log('Generating templates from frontend/*.html ...');
  fs.writeFileSync(templatesPath, generateTemplatesJs(rootDir));

  console.log(`Done — ${Object.keys(cfg.upstreams).length} upstreams configured, CONFIGURED=${cfg.configured}.`);
}

main().catch((err) => { console.error(err); process.exit(1); });