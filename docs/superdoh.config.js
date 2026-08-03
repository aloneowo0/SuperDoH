/**
 * SuperDoH 用户配置文件
 *
 * 这是 SuperDoH 唯一的人类可编辑配置源。
 * scripts/build-config.cjs 读取本文件 → 生成 src/config.js（机器产物）→ 打包进 Worker。
 * 改完本文件后必须重新部署（Workers Builds 会自动触发）才生效。
 *
 * configured: 1 = 正式运行模式。Worker 使用下面你填写的配置。
 *   0 = 首次配置模式（Worker 用内置默认跑，首页「配置」tab 显示向导）。
 *
 * 格式说明：
 *   - upstreams: 预设名设 true 启用；自定义上游通过 Workers 环境变量注入（CUSTOM_<NAME>=https://...）
 *   - regions: 空对象 = 不启用地区优化；每地区一块，键为 ISO 国家码或 * (全球通配)；实际匹配由 request.cf.country 决定
 *   - geoipUrl / cealingHostUrl: 构建时自动抓取大列表的源，普通用户无需改
 */
export default {
  configured: 1,

  // ── 上游 ──────────────────────────────────────────
  upstreams: {
    google: true,
    cloudflare_Public: true,
    quad9: true,
    adguard: true,
    opendns: true,
    // yandex: false,
    // dnspod: false,
    // alidns: false,
    // '360': false,
    nextdns: true,
  },

  // ── ECS / DNS 调优 ────────────────────────────────
  ecsPrefix4: 24,
  ecsPrefix6: 56,
  // 应答 IP 黑名单（CIDR，空格分隔）
  blockedCidrs: "127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128",
  // AUTO 竞速并发上游数（0 = 全部上游；Free 计划建议 4-6）
  autoConcurrency: 6,
  // 以下均为毫秒，通常无需改动
  ecsProtectMs: 20,
  hardTimeoutMs: 800,
  metaHardTimeoutMs: 800,
  metaCollectWindowMs: 50,
  metaMaxIps: 4,
  preferredTimeoutMs: 300,
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
  // GeoIP CIDR 列表源（8 个分类，构建时自动抓取并编译进 config.js）
  geoipUrl: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/",
  // Cealing-Host Google 代理列表源（regions.*.google=true 时抓取）
  cealingHostUrl: "https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json",
  // 设为 false 可跳过 Cealing-Host 抓取
  fetchGoogleProxy: true,
};