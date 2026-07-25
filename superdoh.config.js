/**
 * SuperDoH 用户配置文件
 *
 * 这是 SuperDoH 唯一的人类可编辑配置源。
 * scripts/build-config.cjs 读取本文件 → 生成 src/config.js（机器产物）→ 打包进 Worker。
 * 改完本文件后必须重新部署（Workers Builds 会自动触发）才生效。
 *
 * configured:
 *   0 = 首次配置模式。Worker 用内置默认（CF + Google + AUTO，无地区优化）跑，
 *       首页「配置」tab 显示图形化向导，引导你生成完整配置并覆盖本文件。
 *   1 = 正式运行模式。Worker 使用下面你填写的配置。
 *
 * 格式说明：
 *   - upstreams: 预设名设 true 启用；自定义上游写 DoH URL（强制 ecs:true）
 *   - regions: 空对象 = 不启用地区优化；每地区一块，实际匹配由 request.cf.country 决定
 *   - geoipUrl / cealingHostUrl: 构建时自动抓取大列表的源，普通用户无需改
 */
export default {
  configured: 0,

  // ── 上游 ──────────────────────────────────────────
  upstreams: {
    google: true,
    cloudflare_Public: true,
    // quad9: false,
    // adguard: false,
    // opendns: false,
    // nextdns: false,
    // yandex: false,
    // dnspod: false,
    // alidns: false,
    // '360': false,
    // 示例自定义上游：键名须小写字母/数字/下划线
    // mycustom: 'https://my-doh.example.com/dns-query',
  },

  // ── ECS / DNS 调优 ────────────────────────────────
  ecsPrefix4: 24,
  ecsPrefix6: 56,
  // 应答 IP 黑名单（CIDR，空格分隔）
  blockedCidrs: '127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128',
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
  logLevel: 'info',

  // ── 地区优化 ──────────────────────────────────────
  // 空对象 = 不启用地区优化。
  // 每地区一块，键为 ISO 国家码（实际匹配由 request.cf.country 决定）。
  regions: {
    // CN: {
    //   preferredCf: 'cf.090227.xyz',
    //   preferredCft: 'worker.cloudfront.182682.xyz',
    //   preferredVrc: 'worker.vercel.182682.xyz',
    //   remap: 'twimg.com twitter.com x.com t.co pixiv.net',
    //   ech: true,
    //   google: true,
    // },
    // RU: {
    //   preferredCf: 'cf.example.com',
    //   preferredCft: '',
    //   preferredVrc: '',
    //   remap: 'twimg.com twitter.com x.com t.co',
    //   ech: true,
    //   google: false,
    // },
  },

  // ── 构建时远程抓取 ────────────────────────────────
  // GeoIP CIDR 列表源（8 个分类，构建时自动抓取并编译进 config.js）
  geoipUrl: 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/',
  // Cealing-Host Google 代理列表源（regions.*.google=true 时抓取）
  cealingHostUrl: 'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json',
  // 设为 false 可跳过 Cealing-Host 抓取
  fetchGoogleProxy: true,
};