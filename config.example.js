/**
 * SuperDoH config.js 完整手写模板
 *
 * 使用方式：
 *   1. 复制本文件为 config.js
 *   2. 在 .env 中设置 USE_CONFIG_JS=true
 *   3. 执行 npm run build / npm run deploy
 *
 * USE_CONFIG_JS=true 时，scripts/build-config.cjs 只检查 config.js 是否存在，
 * 不会生成、合并或覆盖 config.js；Worker 会直接读取本文件的所有导出。
 * 因此下面每个 export 都是运行时配置，不是装饰性示例。
 *
 * 必需导出：
 *   UPSTREAMS, FOREIGN_UPSTREAMS, ECS_PROTECT_MS, HARD_TIMEOUT_MS,
 *   META_HARD_TIMEOUT_MS, META_COLLECT_WINDOW_MS, META_MAX_IPS,
 *   PREFERRED_TIMEOUT_MS, ECS_PREFIX4, ECS_PREFIX6, BLOCKED_RANGES,
 *   MIX_PROVIDER, LOG_LEVEL, REGION, REGION_CONFIG
 */

// ── 上游配置 ─────────────────────────────────────────
// key 会成为访问路径：/<key>/dns-query。
// 例如 google 可通过 /google/dns-query 访问；MIX_PROVIDER 则走默认混合竞速。
// url 必须是 DoH endpoint；ecs 表示发送到该上游前是否保留/注入 ECS。
export const UPSTREAMS = {
  google: { url: 'https://dns.google/dns-query', ecs: true },
  cloudflare_Public: { url: 'https://cloudflare-dns.com/dns-query', ecs: false },
  quad9: { url: 'https://dns11.quad9.net/dns-query', ecs: true },
  adguard: { url: 'https://dns.adguard-dns.com/dns-query', ecs: true },
  opendns: { url: 'https://dns.opendns.com/dns-query', ecs: true },
  dnspod: { url: 'https://sm2.doh.pub/dns-query', ecs: true },
  alidns: { url: 'https://dns.alidns.com/dns-query', ecs: true },
  nextdns: { url: 'https://dns.nextdns.io', ecs: true },

  // 可选预设示例：需要时取消注释。
  // yandex: { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false },
  // '360': { url: 'https://doh.360.cn/dns-query', ecs: true },

  // 自定义上游示例：key 建议使用小写字母、数字、下划线。
  // mydoh: { url: 'https://my-doh.example.com/dns-query', ecs: true },
};

// 用于 preferred/foreign 解析的上游集合。
// 默认排除中国大陆上游 dnspod / alidns，避免优选域名解析时仍拿到本地化结果。
export const FOREIGN_UPSTREAMS = Object.keys(UPSTREAMS).filter(function(name) {
  return name !== 'dnspod' && name !== 'alidns';
});

// ── 竞速/超时参数 ───────────────────────────────────
// 单位都是毫秒。
// HARD_TIMEOUT_MS：普通上游/混合竞速总超时。
// ECS_PROTECT_MS：竞速开始后短时间保护 ECS 上游，避免非 ECS 上游过早胜出。
// META_*：Meta 域名专用静态路由/可达性收集窗口。
// PREFERRED_TIMEOUT_MS：preferred / CloudFront / Vercel 优选域名解析超时。
export const ECS_PROTECT_MS = 20;
export const HARD_TIMEOUT_MS = 800;
export const META_HARD_TIMEOUT_MS = 800;
export const META_COLLECT_WINDOW_MS = 50;
export const META_MAX_IPS = 4;
export const PREFERRED_TIMEOUT_MS = 300;

// ── ECS 与响应过滤 ───────────────────────────────────
// ECS_PREFIX4 / ECS_PREFIX6 控制注入 EDNS Client Subnet 时暴露的前缀长度。
// 数值越大定位越精确，数值越小隐私性越高。
export const ECS_PREFIX4 = 24;
export const ECS_PREFIX6 = 56;

// BLOCKED_RANGES 用于过滤上游返回的不可用/保留/不希望暴露的地址。
// family: 4 使用 4 字节 addr；family: 6 使用 16 字节 addr。
// addr 省略时按全 0 地址处理，适合 ::/128 这类规则。
export const BLOCKED_RANGES = [
  { family: 4, addr: [127, 0, 0, 0], mask: 8 },
  { family: 4, addr: [0, 0, 0, 0], mask: 32 },
  { family: 6, mask: 128 },
  { family: 6, addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], mask: 128 },
];

// ── 路由与日志 ───────────────────────────────────────
// /dns-query 默认使用 MIX_PROVIDER。
// MIX_PROVIDER 必须和 UPSTREAMS 的 key 不冲突。
export const MIX_PROVIDER = 'mix';

// 支持：debug / info / warn / error / none。
export const LOG_LEVEL = 'warn';

// ── 地区优化解析 ─────────────────────────────────────
// REGION 只用于 /health 展示，不参与实际匹配；可写空字符串。
// 实际地区来自 Cloudflare request.cf.country，并按 REGION_CONFIG[国家码] 精确查找。
// 当前没有 default / fallback 区域，未命中国家码时不启用地区优化。
export const REGION = 'CN,RU,US';

export const REGION_CONFIG = {
  CN: {
    // Cloudflare 优选域名。
    // 触发条件：remap 命中，或 MIX1 响应 IP 被识别为 Cloudflare。
    // 禁用写法：preferredCf: ''。
    preferredCf: 'cf-preferred.example.com',

    // CloudFront / Vercel 优选域名。
    // 只有 MIX1 响应 IP 分别被识别为 CFT / VRC 时才使用。
    // 禁用写法：preferredCft: '' / preferredVrc: ''。
    preferredCft: 'cloudfront-preferred.example.com',
    preferredVrc: 'vercel-preferred.example.com',

    // 强制按 Cloudflare 处理的域名后缀。
    // 'x.com' 会匹配 x.com 和任意子域，例如 api.x.com。
    // 禁用写法：remap: []。
    remap: [
      'twimg.com',
      'twitter.com',
      'x.com',
      't.co',
      'pixiv.net',
      'www.pixiv.net',
      'imp.pixiv.net',
    ],

    // 是否对 HTTPS/SVCB(type=65) 查询结果注入 ECH。
    // CF 使用动态 ECH；Meta 使用内置静态 ECH；CFT/VRC 当前不注入 ECH。
    ech: true,

    // Google 静态 DNS 注入规则。
    // 命中 match 后，会把 ips 合并进原始 A 记录回答。
    // 注意：
    //   - ips 当前只支持 IPv4；IPv6 会被忽略。
    //   - match 支持字符串后缀匹配，也支持 RegExp。
    //   - sni 当前不被 Worker 运行时代码使用，仅保留规则来源信息。
    //   - USE_CONFIG_JS=true 时不会自动从 Cealing-Host 注入，请手写。
    // 禁用写法：google: []。
    google: [
      {
        ips: ['47.102.115.14'],
        sni: null,
        match: ['gemini.google.com'],
      },
      {
        ips: ['183.56.143.147'],
        sni: 'g.cn',
        match: [
          'google',
          'google.com',
          'gstatic.com',
          'youtube.com',
          'youtu.be',
          '.ggpht.com',
          'i.ytimg.com',
          'youtube-nocookie.com',
          'blogger.com',
          'android.com',
          'googlevideo.com',
          'yt3.ggpht.com',
          'ytimg.com',
          'gvt1.com',
          'gvt2.com',
          'gvt3.com',
          'video.google.com',
          'doubleclick.net',
          'googleadservices.com',
          'googlesyndication.com',
          'google.com.hk',
          'google.cn',
          'google.co.jp',
          'googleusercontent.com',
          'gmail.com',
          /(^|\.)googleapis\.com$/i,
        ],
      },
    ],
  },

  // 示例：只启用 Cloudflare 优选和 ECH。
  RU: {
    preferredCf: 'cf-preferred-ru.example.com',
    preferredCft: '',
    preferredVrc: '',
    remap: ['twimg.com', 'twitter.com', 'x.com', 't.co'],
    ech: true,
    google: [],
  },

  // 示例：保留完整字段，但关闭全部地区优化。
  US: {
    preferredCf: '',
    preferredCft: '',
    preferredVrc: '',
    remap: [],
    ech: false,
    google: [],
  },
};
