# SuperDoH — Cloudflare Workers DNS-over-HTTPS 代理

基于 Cloudflare Workers 的 DoH 代理，支持两次 MIX 竞速、CDN 归属分流、优选域名解析、ECH 外置 SNI 注入、Meta 静态 IP 路由、remap 域名 AAAA 屏蔽、结构化日志。

## 架构

```
DNS 请求
  │
  ├─ AAAA + remap 域名 → 直接返回 NODATA (部分网站屏蔽 v6, 避免 Happy Eyeballs 超时)
  │
  ▼
MIX 1 — 8 上游并发查询原始域名
  │
  ├─ 未命中地区分流 → 直接返回
  └─ 命中地区分流 → classifyOwner
       │
       ├─ CF/CFT/VRC → MIX 2 解析各自优选域名
       ├─ META → MIX 2 (800ms+50ms 收集 + 静态路由)
       ├─ GOOGLE → 代理 IP 注入
       └─ UNKNOWN → 返回 MIX 1 结果

非 A/AAAA 查询 (type=65 HTTPS 等):
  → MIX 竞速 + postProcessBody ECH 注入
```

## 模块

| 模块 | 职责 |
|------|------|
| `_worker.js` | 入口、路由、两次 MIX 调度、remap AAAA 屏蔽、CF/Meta/Pixiv/Google 分流 |
| `mix.js` | 多上游竞速引擎（ECS 保护窗 + postProcessBody ECH 注入） |
| `edns.js` | DNS 包解析、ECS 注入、IP 黑名单过滤 |
| `ech.js` | CF ECH 动态获取 + Meta ECH 静态构建 + HTTPS RR 注入 |
| `dns-lib.js` | DNS 线格式、响应构建、内部解析、IP 聚合 |
| `cdn.js` | CDN CIDR 归属检测、Meta LPM 可达性过滤 |
| `meta-route.js` | Meta 类匹配静态 IP 路由表 |
| `logger.js` | 结构化 JSON 日志（requestId 追踪） |
| `homepage.js` | 中英文首页 |
| `config.js` | 运行时配置（由 `.env` 构建生成） |

## 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 中文首页 |
| `/en` | GET | 英文首页 |
| `/health` | GET | JSON 健康检查 |
| `/dns-query` | GET/POST | 多上游并发竞速（mix） |
| `/:provider/dns-query` | GET/POST | 单上游查询 |

### 响应头

| 头 | 说明 |
|----|------|
| `Content-Type` | `application/dns-message` |
| `X-DoH-Request-ID` | 请求追踪 ID（8 位 hex） |
| `X-Upstream-Time` | 上游处理耗时（ms） |

```bash
# GET
curl "https://example.com/dns-query?name=x.com&type=A"

# POST wire format
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin "https://example.com/dns-query"

# Firefox DoH
curl "https://example.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

# 健康检查
curl "https://example.com/health"
```

## 分流策略

| CDN | 触发方式 | MIX 2 行为 |
|-----|---------|-----------|
| **CF** (Cloudflare) | `isCFDomain` 域名匹配 或 IP 归属 | 并发解析 `preferredCf`，替换原域名 IP |
| **CFT** (CloudFront) | IP 归属 | 并发解析 `preferredCft` |
| **VRC** (Vercel) | IP 归属 | 并发解析 `preferredVrc` |
| **META** | `isMetaDomain` 域名匹配 或 IP 归属 | 800ms 硬超时 + 首个有效响应后 50ms 收集窗口 + 静态 IP 路由 |
| **GOOGLE** | `matchGoogleProxy` 域名匹配 (仅 A) | 代理 IP 优先注入，后附真实 IP 兜底 |
| **UNKNOWN** | 无匹配 | 直接返回 MIX 1 结果 |

### Remap 域名 AAAA 屏蔽

CN 地区 `REGION_CN_REMAP` 中的域名，AAAA (type=28) 查询直接返回 NODATA。部分网站（如 Pixiv）会主动屏蔽 v6 连接，返回 NODATA 后浏览器只走 v4，避免 Happy Eyeballs 被 v6 超时拖慢。

不影响 A (type=1)、HTTPS (type=65) 及其他类型。

### ECH 策略

| CDN | ECH 来源 | 降级策略 |
|-----|---------|---------|
| CF | `fetchCFEch()` 动态获取 (10min 缓存) | fresh → stale(last-known-good) → degraded(原响应) |
| META | `META_ECH_B64` 静态硬编码 (TLS retry-config) | 内置 → 主动构建 HTTPS RR |
| CFT/VRC | 无独立 ECH | 不注入 |

CF 的 ECH 通过 `cloudflare-ech.com` 的 HTTPS RR 动态获取公钥，注入到 remap 域名的 type=65 响应中。浏览器使用 ECH 后，外层 SNI 为 `cloudflare-ech.com`（GFW 不拦截），内层真实 SNI（如 `x.com`）被加密，绕过 GFW 的 SNI DPI 阻断。

外置 SNI 域名可通过 `ech.js` 中的 `CF_ECH_DOMAIN` 更换。

**已知限制**：ECH 注入时重建 HTTPS RR 响应，仅保留问题段和回答段，不保留原响应的 NS/AR/OPT/DNSSEC 等信息。对普通浏览器 DoH 无影响，依赖 DNSSEC 的客户端可能拿到不完整响应。

## 配置

默认模式下编辑 `.env`，执行 `npm run build` 生成 `config.js`。
如果设置 `USE_CONFIG_JS=true`，构建脚本不会生成或覆盖 `config.js`，Worker 会直接读取现有 `config.js`。

```env
# 上游
GOOGLE=true
CLOUDFLARE_PUBLIC=true
QUAD9=true
ADGUARD=true
OPENDNS=true
DNSPOD=true
ALIDNS=true
NEXTDNS=true

# 竞速
HARD_TIMEOUT_MS=800
ECS_PROTECT_MS=20
META_HARD_TIMEOUT_MS=800
META_COLLECT_WINDOW_MS=50
META_MAX_IPS=4
PREFERRED_TIMEOUT_MS=300

# ECS
ECS_PREFIX4=24
ECS_PREFIX6=56

# 黑名单
BLOCKED_CIDRS=127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128

# 区域优化
REGION=CN
PREFERRED_CF_DOMAIN=cf.example.com
REGION_CN_PREFERRED_CF=cf.090227.xyz
REGION_CN_PREFERRED_CFT=worker.cloudfront.182682.xyz
REGION_CN_PREFERRED_VRC=worker.vercel.182682.xyz
REGION_CN_REMAP=twimg.com twitter.com x.com t.co pixiv.net www.pixiv.net imp.pixiv.net
REGION_CN_ECH=true
```

## 部署

```bash
cd superdoh
npm run build    # USE_CONFIG_JS=false: .env → config.js；USE_CONFIG_JS=true: 直接使用现有 config.js
npm run deploy   # → Cloudflare Workers
```

**本地开发注意**：`wrangler dev` 或非 Cloudflare 环境下，`request.cf.country` 可能为空，地区优化路径不会触发。稳定前须通过 staging/线上 Worker 验证地区优化行为。

## 致谢

特别感谢以下项目提供的思路、数据和参考实现：

- **[Total-ECH](https://github.com/Total-ECH)** — ECH 配置获取与 HTTPS RR 注入方案的核心参考
- **[Sheas Cealer](https://github.com/SpaceTimee/Sheas-Cealer)** — 域前置实践与 Cealing-Host 规则维护，本项目 Google 代理配置的自动拉取来源

## 项目结构

```
superdoh/
├── .env                     # 用户配置
├── scripts/build-config.cjs # .env → config.js，或 USE_CONFIG_JS=true 时跳过生成
├── config.js                # 运行时配置（自动生成或手写）
├── _worker.js               # 入口、路由、两次 MIX
├── mix.js                   # 竞速引擎
├── edns.js                  # ECS/EDNS
├── ech.js                   # ECH 注入
├── dns-lib.js               # DNS 线格式库
├── cdn.js                   # CDN CIDR + Meta LPM
├── meta-route.js            # Meta 静态 IP 路由
├── logger.js                # 结构化日志
├── homepage.js              # 首页
├── wrangler.jsonc           # CF Workers 配置
└── README.md
```
