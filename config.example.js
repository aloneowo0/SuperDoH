/**
 * SuperDoH — 完整配置模板（高级用户参考）
 *
 * 使用方式:
 *   USE_CONFIG_JS=true 后，手写 REGION_CONFIG，只修改需要的字段。
 *   UPSTREAMS / 超时等基础参数始终从 .env 构建。
 *
 * 竞速参数默认值（置入 config.js 后覆盖 .env 行为，build 不会读取 .env 对应字段）:
 *   HARD_TIMEOUT_MS=800       总超时 ms
 *   ECS_PROTECT_MS=20         ECS 保护窗口 ms
 *   META_HARD_TIMEOUT_MS=800  Meta 总超时
 *   META_COLLECT_WINDOW_MS=50 Meta 收集窗口
 *   META_MAX_IPS=4            Meta 最大 IP
 *   PREFERRED_TIMEOUT_MS=300  优选域名超时
 */

export const REGION_CONFIG = {
  CN: {
    // ── 优选域名（CF 分流时解析此域名替代原域名）────
    preferred: 'cf.090227.xyz',
    preferredCft: 'worker.cloudfront.182682.xyz',   // CloudFront
    preferredVrc: 'worker.vercel.182682.xyz',       // Vercel

    // ── 域名重映射（强制 CF 分流 + ECH，适用于非 CF 解析但需走 CF 的域）
    //     等价于 isCFDomain 强制匹配
    remap: [
      'twimg.com', 'twitter.com', 'x.com', 't.co',
      'pixiv.net', 'www.pixiv.net', 'imp.pixiv.net',
    ],

    // ── 功能开关 ─────────────────────────────────
    ech: true,    // ECH 注入（仅 TLS 1.3）
    front: true,  // SNI 前置（实验性，证书覆盖的域才有效）

    // ── Google 静态代理（从 Cealing-Host 自动拉取）
    //     REGION_CN_GOOGLE=true 时生效
    google: [
      {
        ips: ['183.56.143.147'],
        sni: 'g.cn',
        match: [
          'google.com', 'youtube.com', 'gstatic.com',
          'youtu.be', 'ggpht.com', 'i.ytimg.com',
          'googlevideo.com', 'blogger.com', 'android.com',
        ],
      },
      { ips: ['47.102.115.14'], match: ['gemini.google.com'] },
    ],
  },

  // 其他地区示例
  // RU: {
  //   preferred: 'cf.877774.xyz',
  //   remap: ['twimg.com', 'twitter.com'],
  //   ech: true,
  // },
};
