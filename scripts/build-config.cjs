#!/usr/bin/env node
// build-config.js — 从 .env 生成 config.js

const fs = require('fs');
const path = require('path');

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
function generateConfig(env, upstreams) {
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
        ? '[\n' + blockedLines.join('\n') + '\n];'
        : '[]';

    const ecsProtectMs = parseInt(env.ECS_PROTECT_MS, 10);
    const hardTimeoutMs = parseInt(env.HARD_TIMEOUT_MS, 10);
    const ecsPrefix4 = parseInt(env.ECS_PREFIX4, 10);
    const ecsPrefix6 = parseInt(env.ECS_PREFIX6, 10);
    const metaHardTimeoutMs = parseInt(env.META_HARD_TIMEOUT_MS, 10);
    const metaCollectWindowMs = parseInt(env.META_COLLECT_WINDOW_MS, 10);
    const metaMaxIps = parseInt(env.META_MAX_IPS, 10);
    const preferredTimeoutMs = parseInt(env.PREFERRED_TIMEOUT_MS, 10);

    // 地区优化解析（从 REGION_XX_* 块自动发现地区）
    const regionSet = new Set();
    for (const key of Object.keys(env)) {
        const m = key.match(/^REGION_([A-Z]{2})_/);
        if (m) regionSet.add(m[1]);
    }
    const regions = [...regionSet].sort();
    const region = regions.join(',');

    // 全局默认值
    const defaultPrefDomain = env.PREFERRED_DOMAIN || '';
    const defaultRemap = (env.FORCE_REMAP_DOMAINS || '')
        .split(/[\s,]+/).filter(d => d.length > 0);

    // 按地区块解析 REGION_<XX>_PREFERRED / REGION_<XX>_REMAP / REGION_<XX>_ECH
    const regionConfig = {};
    for (const r of regions) {
        regionConfig[r] = {
            preferred: env['REGION_' + r + '_PREFERRED'] || defaultPrefDomain,
            preferredCft: env['REGION_' + r + '_PREFERRED_CFT'] || '',
            preferredVrc: env['REGION_' + r + '_PREFERRED_VRC'] || '',
            remap: env['REGION_' + r + '_REMAP']
                ? env['REGION_' + r + '_REMAP'].split(/[\s,]+/).filter(d => d.length > 0)
                : defaultRemap,
            ech: env['REGION_' + r + '_ECH'] === 'true',
        };
    }
    const regionConfigStr = JSON.stringify(regionConfig);

    return `/**
 * Workers-DoH — 配置文件（由 scripts/build-config.cjs 自动生成）
 * 不要手动编辑此文件，修改 .env 后重新运行构建脚本。
 */

export const UPSTREAMS = {
${entries}
};

export const ECS_PROTECT_MS = ${isNaN(ecsProtectMs) ? 20 : ecsProtectMs};
export const HARD_TIMEOUT_MS = ${isNaN(hardTimeoutMs) ? 800 : hardTimeoutMs};
export const META_HARD_TIMEOUT_MS = ${isNaN(metaHardTimeoutMs) ? 800 : metaHardTimeoutMs};
export const META_COLLECT_WINDOW_MS = ${isNaN(metaCollectWindowMs) ? 50 : metaCollectWindowMs};
export const META_MAX_IPS = ${isNaN(metaMaxIps) ? 4 : metaMaxIps};
export const PREFERRED_TIMEOUT_MS = ${isNaN(preferredTimeoutMs) ? 300 : preferredTimeoutMs};
export const ECS_PREFIX4 = ${isNaN(ecsPrefix4) ? 24 : ecsPrefix4};
export const ECS_PREFIX6 = ${isNaN(ecsPrefix6) ? 56 : ecsPrefix6};

export const BLOCKED_RANGES = ${blockedStr};

export const MIX_PROVIDER = 'mix';

// ── 地区优化解析 ─────────────────────────────────────
export const REGION = ${JSON.stringify(region)};
export const REGION_CONFIG = ${regionConfigStr};
`;
}

// ── Main ───────────────────────────────────────────────────────────
const rootDir = path.resolve(__dirname, '..');
const envPath = path.join(rootDir, '.env');
const configPath = path.join(rootDir, 'config.js');

console.log(`Reading ${envPath} ...`);
const env = parseEnv(envPath);

console.log('Building upstreams ...');
const upstreams = buildUpstreams(env);

if (Object.keys(upstreams).length === 0) {
    console.error('No upstreams enabled! Set at least one to true in .env');
    process.exit(1);
}

console.log(`Generating ${configPath} ...`);
fs.writeFileSync(configPath, generateConfig(env, upstreams));

console.log(`Done — ${Object.keys(upstreams).length} upstreams configured.`);
