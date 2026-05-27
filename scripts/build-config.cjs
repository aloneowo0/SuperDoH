#!/usr/bin/env node
// build-config.js — 从 .env 生成 config.js

const fs = require('fs');
const path = require('path');
const dns = require('dns');
const { execSync } = require('child_process');

// ── 预设上游的 URL 和 EDNS 能力 ──────────────────────────────────
const PRESETS = {
    google:     { url: 'https://dns.google/dns-query',         ecs: true,  plus: true  },
    cloudflare: { url: 'https://cloudflare-dns.com/dns-query', ecs: true,  plus: true  },
    quad9:      { url: 'https://dns11.quad9.net/dns-query',   ecs: true,  plus: true  },
    adguard:    { url: 'https://dns.adguard-dns.com/dns-query', ecs: true,  plus: true  },
    opendns:    { url: 'https://dns.opendns.com/dns-query',   ecs: true,  plus: true  },
    yandex:     { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false, plus: false },
    dnspod:     { url: 'https://sm2.doh.pub/dns-query',       ecs: true,  plus: true  },
    alidns:     { url: 'https://dns.alidns.com/dns-query',    ecs: true,  plus: true  },
    360:        { url: 'https://doh.360.cn/dns-query',        ecs: true,  plus: true  },
    nextdns:    { url: 'https://dns.nextdns.io',              ecs: true,  plus: true  },
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
        // 自动探测 EDNS 支持
        console.log(`Probing ${name}: ${url} ...`);
        const caps = probeEDNS(url);
        upstreams[name] = { url, ...caps };
        console.log(`  ecs=${caps.ecs} plus=${caps.plus}`);
    }

    return upstreams;
}

// ── 探测 EDNS 能力 ────────────────────────────────────────────────
function probeEDNS(url) {
    // 默认值（探测失败时使用）
    const result = { ecs: true, plus: true };

    try {
        // 用 curl 发 basic DNS 查询测试连通性
        const query = 'AAABAAABAAAAAAAAA2RucwZnb29nbGUDY29tAAABAAE=';
        execSync(
            `curl -sS --connect-timeout 5 -m 10 -o /dev/null -w '%{http_code}' ` +
            `-X POST -H 'Accept: application/dns-message' ` +
            `-H 'Content-Type: application/dns-message' ` +
            `--data-binary '${query}' '${url}'`,
            { encoding: 'utf-8', timeout: 15000 }
        );
    } catch (_) {
        console.warn(`  Warning: probe failed for ${url}, using defaults`);
    }

    return result;
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
                const mask = parseInt(pfxStr) || 128;
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
                entries.push({ family: 4, addr: parts, mask: parseInt(pfx) || 32 });
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
            const ecs = String(cfg.ecs);
            const plus = String(cfg.plus);
            return `    ${name}: { url: '${cfg.url}', ecs: ${ecs}, plus: ${plus} },`;
        })
        .join('\n');

    const blockedEntries = parseBlockedCidrs(env.BLOCKED_CIDRS || '');
    const blockedStr = blockedEntries.length > 0
        ? JSON.stringify(blockedEntries, null, 4)
            .replace(/"([^"]+)":/g, '$1:')
        : '[]';

    return `/**
 * DoH Proxy v2 — 配置文件（由 scripts/build-config.js 自动生成）
 * 不要手动编辑此文件，修改 .env 后重新运行构建脚本。
 */

export const UPSTREAMS = {
${entries}
};

export const ECS_PROTECT_MS = ${env.ECS_PROTECT_MS || 20};
export const HARD_TIMEOUT_MS = ${env.HARD_TIMEOUT_MS || 800};
export const ECS_PREFIX4 = ${env.ECS_PREFIX4 || 24};
export const ECS_PREFIX6 = ${env.ECS_PREFIX6 || 56};

export const BLOCKED_RANGES = ${blockedStr};

export const EDNS_MODES = ['keep', 'auto', 'plus'];
export const DEFAULT_MODE = 'auto';
export const MIX_PROVIDER = 'mix';
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
