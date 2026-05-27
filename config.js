/**
 * DoH Proxy v2 — 配置文件（由 scripts/build-config.js 自动生成）
 * 不要手动编辑此文件，修改 .env 后重新运行构建脚本。
 */

export const UPSTREAMS = {
    360: { url: 'https://doh.360.cn/dns-query', ecs: true, plus: true },
    google: { url: 'https://dns.google/dns-query', ecs: true, plus: true },
    cloudflare: { url: 'https://cloudflare-dns.com/dns-query', ecs: true, plus: true },
    quad9: { url: 'https://dns11.quad9.net/dns-query', ecs: true, plus: true },
    adguard: { url: 'https://dns.adguard-dns.com/dns-query', ecs: true, plus: true },
    opendns: { url: 'https://dns.opendns.com/dns-query', ecs: true, plus: true },
    yandex: { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false, plus: false },
    dnspod: { url: 'https://sm2.doh.pub/dns-query', ecs: true, plus: true },
    alidns: { url: 'https://dns.alidns.com/dns-query', ecs: true, plus: true },
    nextdns: { url: 'https://dns.nextdns.io', ecs: true, plus: true },
};

export const ECS_PROTECT_MS = 20;
export const HARD_TIMEOUT_MS = 800;
export const ECS_PREFIX4 = 24;
export const ECS_PREFIX6 = 56;

export const BLOCKED_RANGES = [
    { family: 4, addr: [127, 0, 0, 0], mask: 8 },
    { family: 4, addr: [0, 0, 0, 0], mask: 32 },
    { family: 6, mask: 128 },
    { family: 6, addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], mask: 128 }
];;

export const EDNS_MODES = ['keep', 'auto', 'plus'];
export const DEFAULT_MODE = 'auto';
export const MIX_PROVIDER = 'mix';
