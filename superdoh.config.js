/**
 * SuperDoH 用户配置文件
 *
 * 这是 SuperDoH 唯一的人类可编辑配置源。
 * scripts/build-config.cjs 读取本文件 → 生成 src/config.rs（机器产物）→ 打包进 Worker。
 * 改完本文件后必须重新部署（Workers Builds 会自动触发）才生效。
 *
 * configured: 1 = 正式运行模式。Worker 使用下面你填写的配置。
 *   0 = 首次配置模式（Worker 用内置默认跑，首页「配置」tab 显示向导）。
 *
 * 格式说明：
 *   - upstreams: 每个预设使用 { enabled, transport }；transport 为 "doh" 或 "tcp"
 *     自定义上游仍通过 Workers 环境变量注入（CUSTOM_<NAME>=https://...），仅支持 DoH
 *   - regions: 空对象 = 不启用地区优化；每地区一块，键为 ISO 国家码或 * (全球通配)；实际匹配由 request.cf.country 决定
 *   - geoipUrl / cealingHostUrl: 构建时自动抓取大列表的源，普通用户无需改
 */
export default {
  configured: 1,

  // ── 上游 ──────────────────────────────────────────
  upstreams: {
    google: { enabled: true, transport: "tcp" },
    cloudflare_Public: { enabled: true, transport: "doh" },
    quad9: { enabled: true, transport: "tcp" },
    adguard: { enabled: false, transport: "tcp" },
    opendns: { enabled: false, transport: "tcp" },
    // yandex: { enabled: false, transport: "tcp" },
    // dnspod: { enabled: false, transport: "tcp" },
    // alidns: { enabled: false, transport: "tcp" },
    // '360': { enabled: false, transport: "tcp" },
    nextdns: { enabled: false, transport: "doh" },
  },

  // ── ECS / DNS 调优 ────────────────────────────────
  ecsPrefix4: 24,
  ecsPrefix6: 56,
  // 应答 IP 黑名单（CIDR，空格分隔）
  blockedCidrs: "127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128",
  // fast / mix 共用的滑动并发窗口（0 = 最多 6；全部启用上游仍作为候选）
  upstreamConcurrency: 2,

  // ── 新版 Rust 解析参数 ────────────────────────────
  // fast：主解析 / HTTPS owner 探测 / CF ECH 获取等竞速阶段的硬超时
  fastTimeoutMs: 300,
  // mix：Meta A/AAAA 二次收集阶段的硬超时
  mixTimeoutMs: 200,
  // mix 合并结果与优选替换的 TTL（秒）
  mixTtl: 300,
  preferredTtl: 60,
  // 所有上游均失败时返回 SERVFAIL 所带的 EDE code
  servfailEdeCode: 22,
  // Cloudflare 动态 ECHConfig：正常缓存 / stale 兜底时间（毫秒）
  cfEchCacheTtlMs: 600000,
  cfEchStaleTtlMs: 3600000,
  // 日志级别：debug / info / warn / error / none
  logLevel: "info",

  // ── 地区优化 ──────────────────────────────────────
  regions: {
    CN: {
      preferredCf: 'cf.090227.xyz',
      preferredCft: 'worker.cloudfront.182682.xyz',
      preferredVrc: 'worker.vercel.182682.xyz',
      remap: 'twimg.com twitter.com x.com t.co pixiv.net www.pixiv.net imp.pixiv.net',
      ech: true,
      google: true,
    },
  },

  // ── 构建时远程抓取 ────────────────────────────────
  // GeoIP CIDR 列表源（8 个分类，构建时自动抓取并编译进 config.rs）
  geoipUrl: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/",
  // Cealing-Host Google 代理列表源（regions.*.google=true 时抓取）
  cealingHostUrl: "https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json",
  // 设为 false 可跳过 Cealing-Host 抓取
  fetchGoogleProxy: true,
};