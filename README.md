# SuperDoH — 多上游并发竞速 DNS-over-HTTPS 代理

基于 Cloudflare Workers 的智能 DoH 代理。多上游并发竞速、CDN 归属分流、优选域名替换、ECH 外置 SNI 注入、Meta 静态 IP 路由，一套方案解决 DNS 解析加速与绕过的问题。

## 功能特性

- **多上游并发竞速** — Google、Cloudflare、Quad9、AdGuard、OpenDNS、NextDNS 等预设上游并行查询，最快响应优先返回
- **两阶段 AUTO 流程** — AUTO 1 多上游分类查询，识别 CDN 归属；AUTO 2 按归属对优选的域名进行二次最优解析
- **CDN 感知路由** — 识别 Cloudflare、CloudFront、Vercel、Meta 等 CDN 响应，替换为地区可达的优选 IP
- **ECH 外置 SNI 注入** — CF 动态获取 ECH 公钥 + Meta 静态 ECH 配置，在 HTTPS RR 响应中注入加密 SNI，绕过 GFW SNI DPI
- **AAAA 阻塞** — 对 remap 域名直接返回 AAAA NODATA，避免 Happy Eyeballs 被 v6 超时拖慢
- **ECS 注入** — EDNS Client Subnet 携带客户端 IP 前缀，获取就近解析结果；隐私保护前缀可配
- **Chrome DoH Canary 拦截** — `use-application-dns.net` 返回 NXDOMAIN，关闭 Chrome 原生 DoH
- **结构化 JSON 日志** — 全链路 requestId 追踪，支持 debug/info/warn/error 分级
- **双响应格式** — 同时支持 RFC 8484 wire-format（`application/dns-message`）和 JSON（`application/dns-json`）

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
       ├─ CF/CFT/VRC → AUTO 2 解析各自的优选域名，替换 IP
       ├─ META       → 800ms 硬超时 + 50ms 收集窗口 + 静态路由
       ├─ GOOGLE     → 代理 IP 优先注入 + 真实 IP 兜底
       └─ UNKNOWN    → 返回 AUTO 1 结果

非 A/AAAA（type=65 HTTPS 等）:
  → 并发竞速 + ECH 注入（post-process）
```

### 模块职责

| 模块 | 职责 |
|------|------|
| `_worker.js` | 入口、路由调度、两阶段 AUTO、AAAA 阻塞、CDN 分类 |
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

## 快速开始

### 前置要求

- Cloudflare 账号
- GitHub 账号（用于 Workers Builds 自动部署）

### 部署

1. Fork 本仓库
2. 在 Cloudflare Dashboard 连接 GitHub 仓库到 Workers（Workers Builds）
3. 第一次部署 — `superdoh.config.js` 默认 `configured: 0`，Worker 用内置默认（CF + Google + AUTO，无地区优化）跑，首页「配置」tab 显示图形化配置向导
4. 在向导中选择上游、地区、ECH、超时等 → 生成 `superdoh.config.js` → 下载 → 覆盖仓库根目录的 `superdoh.config.js` → 提交
5. Workers Builds 自动触发第二次部署 — `configured: 1`，Worker 进入正式运行模式

```
用户 Fork → 连接 GitHub → 第一次部署(configured:0)
  → 首页「配置」tab 图形向导 → 生成配置 → 覆盖 superdoh.config.js → push
  → 自动第二次部署(configured:1) → 正式运行
```

> 也可本地部署：`npm run build && npm run deploy`（需 [wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) 已登录）

### 使用示例

```bash
# GET 查询（与 Google DNS JSON API 兼容）
curl "https://你的worker域名/dns-query?name=example.com&type=A"

# POST wire-format（RFC 8484）
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin "https://你的worker域名/dns-query"

# Firefox DoH 兼容
curl "https://你的worker域名/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

# JSON 格式响应
curl -H "Accept: application/dns-json" \
  "https://你的worker域名/dns-query?name=example.com&type=A"

# 健康检查
curl "https://你的worker域名/health"

# 指定上游
curl "https://你的worker域名/google/dns-query?name=example.com&type=A"
```

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 中文首页（主页 tab + 配置 tab） |
| `/en` | GET | 英文首页 |
| `/health` | GET | JSON 健康检查（上游列表、超时配置、地区信息、configured 状态） |
| `/config.json` | GET | JSON 当前生效配置（供配置向导/只读视图读取） |
| `/dns-query` | GET/POST | 多上游并发竞速（AUTO 模式） |
| `/:provider/dns-query` | GET/POST | 单上游查询（provider 见配置中启用的上游名） |

### 响应头

| 响应头 | 说明 |
|--------|------|
| `Content-Type` | `application/dns-message` 或 `application/dns-json` |
| `X-DoH-Request-ID` | 请求追踪 ID（8 位 hex），所有日志共享 |
| `X-Upstream-Time` | 上游处理耗时（毫秒） |

> [!NOTE]
> DoH 端点只接受 `GET` 和 `POST`；其他方法返回 `405`。`POST` 必须使用 `Content-Type: application/dns-message`，否则返回 `415`。DNS wire 消息超过 65535 字节返回 `413`。所有 HTTP 级别错误均含 `X-DoH-Request-ID`。

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

CN 地区 `REGION_CN_REMAP` 中的域名（如 `twitter.com`、`x.com`、`pixiv.net` 等），AAAA（type=28）查询直接返回 NODATA。部分网站主动屏蔽 v6 连接，返回 NODATA 后浏览器只走 v4，避免 Happy Eyeballs 被 v6 超时拖慢。不影响 A（type=1）和 HTTPS（type=65）查询。

### Chrome DoH Canary

自动拦截 `use-application-dns.net` 的 A/AAAA 查询，返回 NXDOMAIN，关闭 Chrome 原生 DoH 回退，确保流量经由本代理。

## ECH 策略

| CDN | ECH 来源 | 降级策略 |
|-----|----------|----------|
| **CF** | `fetchCFEch()` 从 `cloudflare-ech.com` 动态获取 HTTPS RR（10 分钟缓存，1 小时 stale 兜底） | fresh → stale（末次有效）→ degraded（原响应不注入） |
| **META** | `META_ECH_B64` 硬编码 TLS retry-config（静态） | 内置 ECH → 主动构建 HTTPS RR |
| **CFT/VRC** | 无 ECH 注入 | 不处理 |

CF 的 ECH 通过 `cloudflare-ech.com` 的 HTTPS RR 动态获取公钥，注入到 remap 域名的 type=65 响应中。浏览器使用 ECH 后，外层 SNI 为 `cloudflare-ech.com`（GFW 不拦截），内层真实 SNI 被加密，绕过 SNI DPI 阻断。外置 SNI 域名可通过 `ech.js` 中的 `CF_ECH_DOMAIN` 更换。

## 配置

配置源为仓库根目录的 `superdoh.config.js`（JS 格式，`export default`）。`scripts/build-config.cjs` 读取该文件 → 生成 `src/config.js`（机器产物，gitignored）→ 打包进 Worker。

两种模式由 `configured` 字段控制：

| `configured` | 行为 | 首页「配置」tab |
|:---:|------|----------------|
| `0` | 首次配置模式。Worker 用内置默认（CF + Google + AUTO，无地区优化）跑 | 显示图形化配置向导 |
| `1` | 正式运行模式。Worker 使用 `superdoh.config.js` 中的配置 | 只读展示当前生效配置 |

改完 `superdoh.config.js` 后必须重新部署（Workers Builds 会自动触发）才生效。

### 图形化配置

首页「配置」tab 内置向导（`frontend/js/config-wizard.js`）：

- `configured: 0` — 可编辑表单（上游勾选、地区添加、调优参数），内联校验，生成 `superdoh.config.js` 文本，支持下载/复制
- `configured: 1` — 只读展示当前生效配置 + 「重新配置」按钮切换到可编辑模式（预填当前值）

### superdoh.config.js 字段

```js
export default {
  configured: 0,            // 0=首次配置模式 / 1=正式运行
  upstreams: {              // 预设名: true 启用；自定义: name: 'https://...'
    google: true,
    cloudflare_Public: true,
  },
  ecsPrefix4: 24,           // ECS IPv4 前缀长度
  ecsPrefix6: 56,           // ECS IPv6 前缀长度
  blockedCidrs: '...',      // 应答 IP 黑名单（CIDR 空格分隔）
  autoConcurrency: 6,      // AUTO 竞速并发数（0=全部）
  ecsProtectMs: 20,        // ECS 保护窗（毫秒）
  hardTimeoutMs: 800,       // 上游硬超时
  metaHardTimeoutMs: 800,
  metaCollectWindowMs: 50,
  metaMaxIps: 4,
  preferredTimeoutMs: 300,
  logLevel: 'info',         // debug/info/warn/error/none
  regions: {               // 空对象=不启用地区优化
    CN: {
      preferredCf: 'cf.example.com',
      preferredCft: 'cloudfront.example.com',
      preferredVrc: 'vercel.example.com',
      remap: 'twimg.com twitter.com x.com',
      ech: true,
      google: true,         // 启用 Cealing-Host Google 代理注入
    },
  },
  geoipUrl: 'https://...',           // GeoIP CIDR 列表源（构建时抓取）
  cealingHostUrl: 'https://...',     // Cealing-Host Google 代理源
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

自定义上游：通过 Workers 运行时环境变量注入（不进 `superdoh.config.js`）。在 Cloudflare Dashboard → Worker → Settings → Variables 添加：

| 变量名 | 值 | 规则 |
|--------|----|------|
| `CUSTOM_<NAME>` | `https://your-doh.example.com/dns-query` | 键名须 `^[a-z][a-z0-9_]*$`，URL 须 `https://`，强制 ECS 启用 |

注入的自定义上游与预设上游合并，可在 `/health` 和 `/config.json` 中看到。环境变量改完即时生效，无需重新部署。

> [!NOTE]
> `.env` 文件仍可作为可选覆盖保留（legacy），优先级低于 `superdoh.config.js`。后续版本将移除。

## 项目结构

```
superdoh/
├── _worker.js                  # 入口 + 路由 + 两阶段 AUTO 调度
├── superdoh.config.js          # 用户配置（JS，唯一人类配置源，tracked）
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
├── wrangler.jsonc              # Cloudflare Workers 配置
├── package.json                # v2.0.0
└── README.md
```

## 已知限制

> [!WARNING]
> - **Meta ECH 是静态的** — `META_ECH_B64` 硬编码于 `ech.js`，不随 Meta 服务器轮换自动更新。ECH 公钥过期后需手动更新。
> - **ECH 注入会丢弃部分 DNS 记录** — HTTPS RR 重建时仅保留问题段和回答段，不保留原响应的 NS/AR/OPT/DNSSEC 信息。对普通浏览器 DoH 无影响，但依赖 DNSSEC 的客户端可能拿到不完整响应。
> - **Workers Free 计划 6 连接限制** — Free 计划仅有 6 个同时出站 TCP 连接。超过 6 个上游会导致排队等待，拖慢 DNS 响应。建议启用上游数不超过 6，并为 AUTO 2 优选解析预留槽位（`AUTO_CONCURRENCY` 设为 4）。
> - **地区优化依赖 `request.cf.country`** — `wrangler dev` 或非 Cloudflare 环境下该字段为空，地区优化路径不会触发。需通过线上 Worker 验证地区优化行为。

## 致谢

特别感谢以下项目提供的思路、数据和参考实现：

- [Total-ECH](https://github.com/RememberOurPromise/Total-ECH) — ECH 配置获取与 HTTPS RR 注入方案的核心参考
- [Sheas Cealer](https://github.com/SpaceTimee/Sheas-Cealer) — 域前置实践与 Cealing-Host 规则维护，本项目 Google 代理配置的自动拉取来源
