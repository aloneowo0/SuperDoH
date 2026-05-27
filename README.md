# DoH Proxy v2

基于 Cloudflare Workers 的轻量级 DNS over HTTPS 代理，支持多上游并发竞速和 EDNS Client-Subnet 注入。

## 功能

- **多上游并发** — mix 端点同时查询全部上游，先到有效先返回
- **EDNS 控制** — keep（透传）/ auto（智能补 ECS）/ plus（强制 EDNS 扩展）
- **竞速策略** — ECS 启用时支持 ECS 的上游有保护期先跑，之后所有上游平等竞速
- **应答过滤** — 自动拦截回环地址、空地址等，返回 SERVFAIL
- **10 个预设上游** — Google / Cloudflare / Quad9 / AdGuard / OpenDNS / Yandex / DNSPod / AliDNS / 360 / NextDNS
- **自定义上游** — 通过 .env 添加任意 DoH 端点
- **Homepage** — 内置中英文管理页，展示 EDNS 能力表 + 延迟检测
- **跨平台** — Cloudflare Workers 基准实现，Vercel / EdgeOne Pages 适配计划中

## 快速开始

```bash
# 1. Fork 本仓库，Clone 到本地
git clone https://github.com/YOUR_USER/cloudflare-doh-v2 && cd cloudflare-doh-v2

# 2. 编辑配置
# 直接编辑 .env
# 按需开关上游、调整超时 ...

# 3. 生成运行配置并推送
npm run build && git add config.js && git commit -m "update config" && git push
```

> Cloudflare Workers 检测到 main 分支更新后自动部署。
> 也可在 Cloudflare 控制台将 Build command 设为 `npm run build`，之后每次改 `.env` 直接在线编辑即可，无需本地构建。

## 配置

编辑 `.env` 文件，然后运行 `npm run build` 生成 `config.js`（或由 CI 自动完成）。

```env
# 预设上游开关（true=启用 false=关闭）
GOOGLE=true
CLOUDFLARE=true
QUAD9=true
ADGUARD=true
OPENDNS=true
YANDEX=true
DNSPOD=true
ALIDNS=true
360=true
NEXTDNS=true

# 自定义上游（格式：CUSTOM_<名称>=<URL>）
# CUSTOM_MY=https://my-doh.example.com/dns-query

# 超时（毫秒）
HARD_TIMEOUT_MS=800    # mix 总超时
ECS_PROTECT_MS=20      # ECS 保护窗口

# ECS 子网前缀
ECS_PREFIX4=24
ECS_PREFIX6=56

# 应答黑名单（CIDR，空格分隔）
BLOCKED_CIDRS=127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128
```

## API

所有端点支持 POST `application/dns-message`（DNS wire format）。

| 端点 | 说明 |
|------|------|
| `/google/query-dns?mode=keep` | 单上游查询，指定 EDNS 模式 |
| `/mix/query-dns?mode=auto` | 并发竞速，默认 auto |
| `/query-dns` | v1 兼容，等同于 /mix |

**EDNS 模式：**

| 模式 | 说明 |
|------|------|
| `keep` | 保留客户端原始 EDNS |
| `auto` | 有 ECS 则跳过，没有则注入客户端 /24 |
| `plus` | 强制补全：UDP 4096 + DO + ECS + Padding |

## 竞速算法

### ECS 启用时（mode=auto/plus 或客户端自带 ECS）

```
t=0   并发 fire 全部上游
       ├── 保护期 20ms ───┐
t=10  [google] ECS ✅ 到了 → 有效 → 立即返回
t=15  [cf]    非 ECS 到了 → 丢弃，继续等
t=20  保护期结束，所有新到的响应均可立即返回
       接着等 → 谁先到有效用谁
```

### ECS 未启用时（mode=keep 且无 ECS）

```
t=0   并发 fire 全部上游
t=5   [cf] 到了 → 有效 → 立即返回（纯竞速）
```

## 上游 EDNS 兼容性

| 上游 | ECS | Plus | 说明 |
|------|-----|------|------|
| Google | ✅ | ✅ | |
| Cloudflare | ✅ | ✅ | |
| Quad9 | ✅ | ✅ | |
| AdGuard | ✅ | ✅ | |
| OpenDNS | ✅ | ✅ | |
| DNSPod | ✅ | ✅ | |
| AliDNS | ✅ | ✅ | |
| 360 | ✅ | ✅ | |
| NextDNS | ✅ | ✅ | |
| Yandex | ✖ | ✖ | auto/plus 自动降级 basic |

## 使用示例

所有查询使用 `POST application/dns-message`（DNS wire format 二进制）。

```bash
# 并发查询（默认 auto）
echo -n -e '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02qq\x03com\x00\x00\x01\x00\x01' \
  | curl -sS -X POST -H "Content-Type: application/dns-message" \
  --data-binary @- \
  "https://your-worker.dev/mix/query-dns"

# 单上游 + plus 模式
echo -n -e '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02qq\x03com\x00\x00\x01\x00\x01' \
  | curl -sS -X POST -H "Content-Type: application/dns-message" \
  --data-binary @- \
  "https://your-worker.dev/google/query-dns?mode=plus"
```

## 注意事项

- **Cloudflare Workers 并发连接上限**：免费 ~6 个，标准 ~8-10 个。mix 10 个上游不会全部真正并发，超出限额的会内部排队。建议启用不超过 8 个上游，或将最快的排前面。
- **生产环境**建议使用 Workers 标准付费计划，获得更好的并发和 SLA。
- **yandex 延迟较高**（200-900ms），建议按需启用。

## 项目结构

```
cloudflare-doh-v2/
├── .env                      # 用户配置（上游开关、超时等）
├── scripts/build-config.cjs  # 构建脚本：.env → config.js
├── config.js                 # 运行时配置（自动生成）
├── _worker.js                # Worker 入口，路由分发、并发逻辑
├── router.js                 # URL 解析
├── edns.js                   # DNS 包解析、EDNS 注入/过滤
├── homepage.js               # 中英文管理页
├── wrangler.jsonc            # Cloudflare 部署配置
├── .gitignore
└── package.json
```

## 后续计划

- **GET 查询支持** — 解析 `?name=example.com&type=A` 参数，自动构建 DNS wire-format 请求
- **JSON 查询支持** — 接受 `application/dns-json` 格式（RFC 8484），兼容更多客户端
- **IPv6 ECS 注入** — 当前仅支持 IPv4 客户端子网，需增加 IPv6 前缀处理
- **EDNS 自动探测** — 自定义上游添加时真正探测 ECS/Plus 能力，而非使用默认值
- **保护期窗口缓存** — ECS 保护期间接收的非 ECS 响应暂存，窗口结束后直接取用而非丢弃
- **跨平台适配器** — Vercel Serverless Functions 和 EdgeOne Pages 的部署配置与构建适配

MIT
