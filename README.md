# Workers-DoH

基于 Cloudflare Workers 的轻量级 DNS over HTTPS 代理，支持多上游并发竞速和 EDNS Client-Subnet 注入。

## 快速开始

1. Fork 本仓库
2. 编辑 `.env`：启用需要的上游，调整参数
3. 运行 `npm run build`（调用 `scripts/build-config.cjs`）生成 `config.js`
4. 部署到 Cloudflare Workers（连接仓库自动部署，或 `npx wrangler deploy`）

之后修改 `.env` 重新构建推送即可自动更新。

## 端点参考

所有端点支持 `POST application/dns-message`（wire format）和 `GET ?name=&type=`。设置 `Accept: application/dns-json` 时走 RFC 8484 JSON 透传。

| 端点 | 说明 |
|------|------|
| `/` `/index.html` | 首页（中文） |
| `/en` | 首页（英文） |
| `/query-dns` | v1 兼容，等同 `/mix/query-dns` |
| `/mix/query-dns` | 全部已启用上游并发竞速 |
| `/<provider>/query-dns` | 单上游查询 |

provider 可选值：`google` `cloudflare` `quad9` `adguard` `opendns` `dnspod` `alidns` `360` `nextdns` `yandex`。

支持 DNS 类型：A（默认）、AAAA、TXT、MX、CNAME、NS、SOA、PTR。

```bash
# GET 查询
curl "https://your-worker.dev/mix/query-dns?name=example.com&type=AAAA"

# POST wire-format
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin \
  "https://your-worker.dev/google/query-dns?mode=plus"
```

### 查询参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `name` / `dns` | string | 查询域名 |
| `type` | string | DNS 记录类型（默认 A） |
| `mode` | string | EDNS 模式：keep / auto（默认）/ plus |

## EDNS 模式

通过 `?mode=` 参数选择 EDNS 处理方式：

| 模式 | 行为 |
|------|------|
| `keep` | 透传原始请求体，不做 EDNS 修改。mix 下等效纯竞速 |
| `auto` | 请求无 ECS 则注入客户端 /24，已有则跳过（默认） |
| `plus` | 强制补全：UDP 4096 + DO 位 + ECS + Padding 完整 EDNS 扩展 |

不支持对应能力（ecs / plus）的上游自动降级为 keep 透传。

## 竞速算法

mix 端点的核心逻辑在 `concurrentAll()` 中实现：

```
ECS 启用时（mode=auto/plus 或请求自带 ECS）：

t=0      并发发送所有上游
         ├── 保护期 (ECS_PROTECT_MS) ───────────┤
t=10     [ECS 上游] 到 → 有效 → 立即返回
t=15     [非 ECS 上游] 到 → 丢弃，继续等
t=20     保护期结束，后续任意有效响应均可返回

ECS 未启用时（mode=keep 且无 ECS）：

t=0      并发发送所有上游
t=5      [最快上游] 到 → 有效 → 立即返回（纯竞速）
```

- **ECS_PROTECT_MS**（默认 20ms）：保护窗口。窗口内只接受支持 ECS 的上游的响应，防止非 ECS 上游先返回导致地域不准确。
- **HARD_TIMEOUT_MS**（默认 800ms）：总超时。超时后停止等待，有结果返回最快有效响应，全部无效返回 SERVFAIL。

## 配置

编辑 `.env`，运行 `npm run build` 生成 `config.js`。

```env
# 预设上游开关
GOOGLE=true
CLOUDFLARE=true
QUAD9=true
ADGUARD=true
OPENDNS=true
YANDEX=false
DNSPOD=true
ALIDNS=true
360=false
NEXTDNS=true

# 自定义上游（格式：CUSTOM_<名称>=<DoH URL>）
# CUSTOM_MY=https://my-doh.example.com/dns-query

# 竞速参数（毫秒）
HARD_TIMEOUT_MS=800
ECS_PROTECT_MS=20

# ECS 子网前缀
ECS_PREFIX4=24
ECS_PREFIX6=56

# 应答 IP 黑名单（CIDR 空格分隔）
BLOCKED_CIDRS=127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128
```

`CUSTOM_` 上游默认标记 `ecs: true, plus: true`，名称仅限字母数字和下划线。

## 上游 EDNS 兼容性

各上游的 `ecs`（EDNS Client-Subnet）和 `plus`（UDP 4096 + DO + ECS + Padding）能力由 `scripts/build-config.cjs` 定义：

| 上游 | ECS | Plus |
|------|-----|------|
| Google | ✅ | ✅ |
| Cloudflare | ✅ | ✅ |
| Quad9 | ✅ | ✅ |
| AdGuard | ✅ | ✅ |
| OpenDNS | ✅ | ✅ |
| DNSPod | ✅ | ✅ |
| AliDNS | ✅ | ✅ |
| 360 | ✅ | ✅ |
| NextDNS | ✅ | ✅ |
| Yandex | ✖ | ✖ |

## 应答过滤

`BLOCKED_CIDRS` 定义 IPv4/IPv6 黑名单 CIDR。上游返回的 A/AAAA 记录命中任意范围时整包丢弃，返回 SERVFAIL。默认拦截：127.0.0.0/8、0.0.0.0/32、::/128、::1/128。

## 首页

访问 `/`（中文）或 `/en`（英文）可查看内置管理页，包含：
- 所有可用端点的路径列表
- 各上游 ECS/Plus 支持情况表
- 在线延迟检测工具（选择端点 → 开始测试，显示总延迟和上游处理时间）

## 项目结构

```
Workers-DoH/
├── .env                      # 用户配置：上游开关、超时、前缀等
├── scripts/build-config.cjs  # 构建脚本：解析 .env 生成 config.js
├── config.js                 # 运行时配置（自动生成）
├── _worker.js                # Worker 入口：路由分发、并发竞速
├── router.js                 # URL 路由解析
├── edns.js                   # DNS 包解析、EDNS 注入/过滤
├── homepage.js               # 中英文首页（EDNS 表、延迟检测）
├── wrangler.jsonc            # Cloudflare 部署配置
└── package.json
```

## 注意事项

- **CF 并发上限**：Workers 免费计划约 6 个并发 subrequest，标准付费约 8-10 个。mix 模式超配额的上游会内部排队，建议启用不超过 8 个上游。
- **CF-Connecting-IP**：ECS 注入依赖此请求头，仅在 Cloudflare 代理环境下可用。非 CF 环境需自行传入客户端 IP。
- **自定义上游默认值**：`CUSTOM_*` 默认 `ecs/plus` 均为 `true`。若上游不支持，需在 `build-config.cjs` 的预设表或构建逻辑中调整。
- **Yandex** 延迟较高（200-900ms），默认关闭。
