/**
 * Workers-DoH — 配置文件（由 scripts/build-config.cjs 自动生成）
 * 不要手动编辑此文件，修改 .env 后重新运行构建脚本。
 */

export const UPSTREAMS = {
    google: { url: "https://dns.google/dns-query", ecs: true },
    cloudflare_Public: { url: "https://cloudflare-dns.com/dns-query", ecs: false },
    quad9: { url: "https://dns11.quad9.net/dns-query", ecs: true },
    adguard: { url: "https://dns.adguard-dns.com/dns-query", ecs: true },
    opendns: { url: "https://dns.opendns.com/dns-query", ecs: true },
    dnspod: { url: "https://sm2.doh.pub/dns-query", ecs: true },
    alidns: { url: "https://dns.alidns.com/dns-query", ecs: true },
    nextdns: { url: "https://dns.nextdns.io", ecs: true },
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

export const MIX_PROVIDER = 'mix';

// ── 地区优化解析（REGION 非空时 ECH 自动启用） ──────────
export const REGION = "CN";
export const ENABLE_ECH = true;
export const ECH_FETCH_DOMAIN = "cloudflare-ech.com";
export const REGION_CONFIG = {"CN":{"preferred":"cf.090227.xyz","remap":["twimg.com","twitter.com","x.com","t.co"],"ech":true}};
