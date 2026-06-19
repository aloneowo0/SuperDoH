/**
 * SuperDoH 完整配置模板
 *
 * USE_CONFIG_JS=true 后，build 保留此文件的 REGION_CONFIG 不动，
 * 仅从 .env 刷新 UPSTREAMS / LOG_LEVEL / BLOCKED_RANGES。竞速参数硬编码如下：
 *   HARD_TIMEOUT_MS=800  ECS_PROTECT_MS=20  META_HARD_TIMEOUT_MS=800
 *   META_COLLECT_WINDOW_MS=50  META_MAX_IPS=4  PREFERRED_TIMEOUT_MS=300
 *
 * Google 代理在 USE_CONFIG_JS=false 时也会生效（从 Cealing-Host 自动拉取，无需手写）。
 */

export const REGION_CONFIG = {

  CN: {

    preferred: 'cf.090227.xyz',
    preferredCft: 'worker.cloudfront.182682.xyz',
    preferredVrc: 'worker.vercel.182682.xyz',

    remap: [
      'twimg.com', 'twitter.com', 'x.com', 't.co',
      'pixiv.net', 'www.pixiv.net', 'imp.pixiv.net',
    ],

    ech: true,

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
          'google', 'google.com', 'gstatic.com', 'youtube.com',
          'youtu.be', '.ggpht.com', 'i.ytimg.com', 'youtube-nocookie.com',
          'blogger.com', 'android.com',
          'googlevideo.com', 'yt3.ggpht.com', 'ytimg.com',
          'gvt1.com', 'gvt2.com', 'gvt3.com', 'video.google.com',
          'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
          'google.com.hk', 'google.cn', 'google.co.jp',
          'googleusercontent.com', 'gmail.com',
        ],
      },
    ],
  },

  // RU: {
  //   preferred: 'cf.877774.xyz',
  //   remap: ['twimg.com', 'twitter.com', 'x.com', 't.co'],
  //   ech: true,
  // },
};
