# SuperDoH 文档

> 简述功能、部署方式、已知问题、致谢见 [README.md](README.md)。本文档涵盖架构、API、配置细节、分流策略。

## 架构

```
DNS 请求
  │
  ├─ AAAA + remap 域名 → NODATA（跳过 v6）
  │
  ▼
AUTO 1 — 多上游并发查询原始域名，分类 CDN 归属
  │
  ├─ 未命中地区分流 → 直接返回 AUTO 1 结果
  └─ 命中地区分流 → classifyOwner
       │
       ├─ CF/CFT/VRC → AUTO 2 解析各自优选域名，替换 IP
       ├─ META       → 800ms 硬超时 + 50ms 收集窗口 + 静态路由
       ├─ GOOGLE     → 代理 IP 优先注入 + 真实 IP 兜底
       └─ UNKNOWN    → 返回 AUTO 1 结果

非 A/AAAA（type=65 HTTPS 等）:
  → 并发竞速 + ECH 注入（post-process）
```

### 模块职责

| 模块 | 职责 |
|------|------|
| `_worker.js` | 入口、路由调度、两阶段 AUTO、AAAA 阻塞、CDN 分类、运行时环境变量注入 |
| `doh-request.js` | DoH HTTP 方法/媒体类型校验、GET 参数与 wire 查询解析 |
| `auto.js` | 多上游竞速引擎、ECS 保护期、ECH 后处理 |
| `edns.js` | DNS 包解析、ECS 注入、IP 黑名单过滤、响应有效性校验 |
| `ech.js` | CF ECH 动态拉取、Meta ECH 静态构建、HTTPS RR 注入与重建 |
| `dns-lib.js` | DNS 线格式编码/解码、响应构建、内部解析 |
| `cdn.js` | CDN CIDR 归属检测（9 家）、域名探测、IP 分类 |
| `meta-route.js` | Meta 类匹配静态 IP 路由表（19 精确 + 8 泛域名） |
| `logger.js` | 结构化 JSON 日志，支持级别过滤 |
| `homepage.js` | 中英文双首页，模板注入 + CONFIGURED 透传 |
| `config.js` | 运行时配置（自动生成，gitignored） |

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 中文首页（主页 tab + 配置 tab） |
| `/en` | GET | 英文首页 |
| `/health` | GET | JSON 健康检查（上游列表、超时配置、地区信息、configured 状态） |
| `/config.json` | GET | JSON 当前生效配置（供配置向导 / 只读视图读取） |
| `/dns-query` | GET/POST | 多上游并发竞速（AUTO 模式） |
| `/:provider/dns-query` | GET/POST | 单上游查询（provider 见配置中启用的上游名） |

### 响应头

| 响应头 | 说明 |
|--------|------|
| `Content-Type` | `application/dns-message` 或 `application/dns-json` |
| `X-DoH-Request-ID` | 请求追踪 ID（8 位 hex），所有日志共享 |
| `X-Upstream-Time` | 上游处理耗时（毫秒） |
| `Cache-Control` | `no-store`；响应会按 ECS 和地区配置转换，不允许共享缓存 |
| `Vary` | `Accept`；区分 wire-format 与 DNS JSON 响应 |

> [!NOTE]
> DoH 端点只接受 `GET` 和 `POST`；其他方法返回 `405`。`POST` 必须使用 `Content-Type: application/dns-message`，否则返回 `415`。DNS wire 消息超过 65535 字节返回 `413`。所有 HTTP 级别错误均含 `X-DoH-Request-ID`。

### 使用示例

```bash
# GET 查询（与 Google DNS JSON API 兼容）
curl "https://你的worker域名/dns-query?name=example.com&type=A"

# POST wire-format（RFC 8484）
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin "https://你的worker域名/dns-query"

# JSON 格式响应
curl -H "Accept: application/dns-json" \
  "https://你的worker域名/dns-query?name=example.com&type=A"

# 健康检查
curl "https://你的worker域名/health"

# 指定单上游查询
curl "https://你的worker域名/google/dns-query?name=example.com&type=A"
```

## 分流策略

| CDN 归属 | 触发方式 | AUTO 2 行为 |
|----------|----------|-------------|
| **CF** (Cloudflare) | 域名匹配 `remap` 列表 或 IP 归属到 `GEOIP_CF` | 并发解析 `preferredCf` 优选域名，替换原始 IP |
| **CFT** (CloudFront) | IP 归属到 `GEOIP_CFT` | 并发解析 `preferredCft` 优选域名 |
| **VRC** (Vercel) | IP 归属到 `GEOIP_FASTLY` | 并发解析 `preferredVrc` 优选域名 |
| **META** (Meta/Facebook) | 域名匹配 `isMetaDomain` 或 IP 归属到 `GEOIP_META` | 800ms 硬超时 + 首响应后 50ms 收集 + 静态 IP 路由表 |
| **GOOGLE** | `matchGoogleProxy` 域名匹配（仅 A 记录） | 代理 IP 优先注入，真实 IP 兜底 |
| **UNKNOWN** | 无匹配 | 直接返回 AUTO 1 结果 |

### Remap 域名 AAAA 屏蔽

地区 `remap` 列表中的域名（如 `twitter.com`、`x.com`、`pixiv.net` 等），AAAA（type=28）查询直接返回 NODATA。部分网站主动屏蔽 v6 连接，返回 NODATA 后浏览器只走 v4，避免 Happy Eyeballs 被 v6 超时拖慢。不影响 A（type=1）和 HTTPS（type=65）查询。

### Chrome DoH Canary

自动拦截 `use-application-dns.net` 的 A/AAAA 查询，返回 NXDOMAIN，关闭 Chrome 原生 DoH 回退，确保流量经由本代理。

## ECH 策略

| CDN | ECH 来源 | 降级策略 |
|-----|----------|----------|
| **CF** | `fetchCFEch()` 从 `cloudflare-ech.com` 动态获取 HTTPS RR（10 分钟缓存，1 小时 stale 兜底） | fresh → stale（末次有效）→ degraded（原响应不注入） |
| **META** | `META_ECH_B64` 硬编码 TLS retry-config（静态） | 内置 ECH → 主动构建 HTTPS RR |
| **CFT/VRC** | 无 ECH 注入 | 不处理 |

CF 的 ECH 通过 `cloudflare-ech.com` 的 HTTPS RR 动态获取公钥，注入到 remap 域名的 type=65 响应中。浏览器使用 ECH 后，外层 SNI 为 `cloudflare-ech.com`（GFW 不拦截），内层真实 SNI 被加密，绕过 SNI DPI 阻断。

## 配置

配置源为仓库根目录的 **`superdoh.config.js`**（JS 格式，`export default`）。`scripts/build-config.cjs` 读取该文件 → 生成 `src/config.js`（机器产物，gitignored）→ 打包进 Worker。

两种模式由 `configured` 字段控制：

| `configured` | 行为 | 首页「配置」tab |
|:---:|------|----------------|
| `0` | 首次配置模式。Worker 用内置默认（Cloudflare + Google + AUTO，无地区优化）运行 | 显示图形化配置向导 |
| `1` | 正式运行模式。Worker 使用 `superdoh.config.js` 中的配置 | 只读展示当前生效配置 + 「重新配置」按钮 |

改完 `superdoh.config.js` 后必须重新部署（Workers Builds 会自动触发）才生效。

### 图形化配置

首页「配置」tab 内置向导（`frontend/js/config-wizard.js`）：

- `configured: 0` — 可编辑表单（上游勾选、地区添加、调优参数），内联校验，生成 `superdoh.config.js` 文本，支持下载 / 复制
- `configured: 1` — 只读展示当前生效配置 + 「重新配置」按钮切换到可编辑模式（预填当前值）

### `superdoh.config.js` 字段

```js
export default {
  configured: 1,            // 0=首次配置模式 / 1=正式运行
  upstreams: {              // 预设名: true 启用
    google: true,
    cloudflare_Public: true,
  },
  ecsPrefix4: 24,           // ECS IPv4 前缀长度
  ecsPrefix6: 56,           // ECS IPv6 前缀长度
  blockedCidrs: '127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128',  // 应答 IP 黑名单
  autoConcurrency: 6,       // AUTO 竞速并发数（0=全部）
  ecsProtectMs: 20,        // ECS 保护窗（毫秒）
  hardTimeoutMs: 800,       // 上游硬超时（毫秒）
  metaHardTimeoutMs: 800,
  metaCollectWindowMs: 50,
  metaMaxIps: 4,
  preferredTimeoutMs: 300,
  logLevel: 'info',         // debug/info/warn/error/none
  regions: {               // 空对象=不启用地区优化；键为 ISO 国家码或 *（全球通配）
    CN: {
      preferredCf: 'cf.090227.xyz',        // Cloudflare 优选域名
      preferredCft: 'worker.cloudfront.182682.xyz',  // CloudFront 优选域名
      preferredVrc: 'worker.vercel.182682.xyz',       // Vercel 优选域名
      remap: 'twimg.com twitter.com x.com t.co',      // 强制走 CF 的域名（空格分隔）
      ech: true,           // 尽力 ECH 支持
      google: true,         // Google 加速（规则来源 Cealing-Host，仅对 CN 地区有效）
    },
  },
  geoipUrl: 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/',
  cealingHostUrl: 'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json',
  fetchGoogleProxy: true,
};
```

### 预设上游

| 名称 | URL | ECS |
|------|-----|:---:|
| `google` | `https://dns.google/dns-query` | ✓ |
| `cloudflare_Public` | `https://cloudflare-dns.com/dns-query` | ✗ |
| `quad9` | `https://dns11.quad9.net/dns-query` | ✓ |
| `adguard` | `https://dns.adguard-dns.com/dns-query` | ✓ |
| `opendns` | `https://dns.opendns.com/dns-query` | ✓ |
| `nextdns` | `https://dns.nextdns.io` | ✓ |
| `yandex` | `https://common.dot.dns.yandex.net/dns-query` | ✗ |
| `dnspod` | `https://sm2.doh.pub/dns-query` | ✓ |
| `alidns` | `https://dns.alidns.com/dns-query` | ✓ |
| `360` | `https://doh.360.cn/dns-query` | ✓ |

### 自定义上游（运行时环境变量）

自定义上游不进 `superdoh.config.js`，通过 Workers 环境变量注入，即时生效无需重新部署。在 **Cloudflare Dashboard → Worker → Settings → Variables** 添加：

| 变量名 | 值 | 规则 |
|--------|----|------|
| `CUSTOM_<NAME>` | `https://example.com/dns-query` | 键名须 `^[a-z][a-z0-9_]*$`，URL 须 `https://`，强制 ECS 启用 |

注入的自定义上游与预设上游合并，可在 `/health` 和 `/config.json` 中看到。

### 地区通配 `*`

`regions` 中键为 `*` 时表示全球通配——未命中具体国家码的请求回退到此配置。可与具体国家码同时使用，具体国家码优先匹配。

## 项目结构

```
superdoh/
├── _worker.js                  # 入口 + 路由 + 两阶段 AUTO + 环境变量注入
├── superdoh.config.js          # 用户配置（JS，唯一人类配置源）
├── frontend/                   # 前端静态资源
│   ├── index.html              # 中文首页（主页 + 配置 tab）
│   ├── en.html                 # 英文首页
│   ├── css/style.css           # 共享样式
│   └── js/
│       ├── resolver.js         # tab 切换
│       └── config-wizard.js    # 配置向导（图形化配置 + 生成器）
├── scripts/
│   └── build-config.cjs        # 构建脚本：superdoh.config.js → config.js + templates.js + GeoIP + Cealing-Host
├── src/
│   ├── config.js               # 运行时配置（自动生成，gitignored）
│   ├── templates.js            # HTML/CSS/JS 模板（自动生成，gitignored）
│   ├── doh-request.js          # DoH HTTP 请求边界校验
│   ├── auto.js                 # 多上游竞速引擎
│   ├── edns.js                 # DNS 包解析 + ECS 注入 + 响应验证
│   ├── ech.js                  # CF/Meta ECH 获取 + HTTPS RR 注入
│   ├── dns-lib.js              # DNS 线格式编解码库
│   ├── cdn.js                  # CDN CIDR 归属 + 域名探测
│   ├── meta-route.js           # Meta 静态 IP 路由表
│   ├── logger.js               # 结构化 JSON 日志
│   └── homepage.js             # 模板加载 + 动态注入
├── test/                       # 测试用例（vitest）
│   ├── dns-lib.test.js
│   ├── doh-request.test.js
│   ├── ech.test.js
│   ├── worker-boundary.test.js
│   └── dns-fixtures.js
├── wrangler.jsonc              # Cloudflare Workers 配置
├── package.json
├── README.md
└── DOCUMENTATION.md
```
