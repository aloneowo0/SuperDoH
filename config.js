/** Active DNS upstream endpoints with EDNS capability flags. */
export const UPSTREAMS = {
    google:     { url: 'https://dns.google/dns-query',         ecs: true,  plus: true  },
    cloudflare: { url: 'https://cloudflare-dns.com/dns-query', ecs: true,  plus: true  },
    quad9:      { url: 'https://dns11.quad9.net/dns-query',   ecs: true,  plus: true  },
    adguard:    { url: 'https://dns.adguard-dns.com/dns-query', ecs: true,  plus: true  },
    opendns:    { url: 'https://dns.opendns.com/dns-query',   ecs: true,  plus: true  },
    yandex:     { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false, plus: false },
    dnspod:     { url: 'https://sm2.doh.pub/dns-query',       ecs: true,  plus: true  },
    alidns:     { url: 'https://dns.alidns.com/dns-query',    ecs: true,  plus: true  },
    360:        { url: 'https://doh.360.cn/dns-query',        ecs: true,  plus: true  },
};

/** Concurrency: grace window after first valid response arrives (ms). */
export const GRACE_WINDOW_MS = 80;

/** Concurrency: hard cap on total wait (ms). */
export const HARD_TIMEOUT_MS = 800;

/** Mix priority when ECS is present (original or injected). */
export const ECS_PRIORITY = ['google', 'quad9', 'adguard', 'opendns', 'cloudflare', 'dnspod', 'alidns', '360', 'yandex'];

/** Mix priority when no ECS. */
export const NO_ECS_PRIORITY = ['cloudflare', 'google', 'quad9', 'adguard', 'opendns', 'dnspod', 'alidns', '360', 'yandex'];

/** EDNS client-subnet IPv4 prefix length. */
export const ECS_PREFIX4 = 24;

/** EDNS client-subnet IPv6 prefix length. */
export const ECS_PREFIX6 = 56;

/** A/AAAA answers matching these ranges are blocked. */
export const BLOCKED_RANGES = [
    { family: 4, addr: [127, 0, 0, 0], mask: 8 },            // loopback
    { family: 4, addr: [0, 0, 0, 0], mask: 32 },              // null
    { family: 6, mask: 128 },                                  // :: (unspecified)
    { family: 6, addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], mask: 128 }, // ::1
];

/** Recognized EDNS modes. */
export const EDNS_MODES = ['keep', 'auto', 'plus'];

/** Default EDNS mode when none is specified. */
export const DEFAULT_MODE = 'auto';

/** Upstream key that triggers concurrent-fetch behaviour. */
export const MIX_PROVIDER = 'mix';
