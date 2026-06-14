/**
 * SuperDoH — 配置文件（由 scripts/build-config.cjs 自动生成）
 * 如果 USE_CONFIG_JS=true 则可以手写 REGION_CONFIG 域规则，
 * UPSTREAMS / 超时 / LOG_LEVEL 始终从 .env 构建。
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

export const FOREIGN_UPSTREAMS = Object.keys(UPSTREAMS).filter(function(n) { return n !== 'dnspod' && n !== 'alidns'; });

export const ECS_PROTECT_MS = 20;
export const HARD_TIMEOUT_MS = 800;
export const META_HARD_TIMEOUT_MS = 800;
export const META_COLLECT_WINDOW_MS = 50;
export const META_MAX_IPS = 4;
export const PREFERRED_TIMEOUT_MS = 300;
export const ECS_PREFIX4 = 24;
export const ECS_PREFIX6 = 56;

export const BLOCKED_RANGES = [
    { family: 4, addr: [127, 0, 0, 0], mask: 8 },
    { family: 4, addr: [0, 0, 0, 0], mask: 32 },
    { family: 6, mask: 128 },
    { family: 6, addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], mask: 128 }
];;

export const MIX_PROVIDER = 'mix';

// ── 日志级别 ────────────────────────────────────────
export const LOG_LEVEL = "warn";

// ── 地区优化解析 ─────────────────────────────────────
export const REGION = "CN";
export const REGION_CONFIG = {
    "CN": {
      "preferred": "cf.090227.xyz",
      "preferredCft": "worker.cloudfront.182682.xyz",
      "preferredVrc": "worker.vercel.182682.xyz",
      "remap": [
        "twimg.com",
        "twitter.com",
        "x.com",
        "t.co",
        "pixiv.net",
        "www.pixiv.net",
        "imp.pixiv.net"
      ],
      "ech": true,
      "front": true,
      "google": [
        {
          "ips": [
            "47.102.115.14"
          ],
          "sni": null,
          "match": [
            "gemini.google.com"
          ]
        },
        {
          "ips": [
            "183.56.143.147",
            "120.25.173.150",
            "120.25.173.160"
          ],
          "sni": "g.cn",
          "match": [
            "google",
            "google.com",
            "gstatic.com",
            "youtube.com",
            "youtu.be",
            ".ggpht.com",
            "i.ytimg.com",
            "youtube-nocookie.com",
            "blogger.com",
            "android.com",
            "googlevideo.com",
            "yt3.ggpht.com",
            "ytimg.com",
            "gvt1.com",
            "gvt2.com",
            "gvt3.com",
            "video.google.com",
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "google.com.hk",
            "google.cn",
            "google.co.jp",
            "googleusercontent.com",
            "gmail.com"
          ]
        }
      ]
    }
  };
