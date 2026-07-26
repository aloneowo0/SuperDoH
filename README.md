# SuperDoH

> 轻量级 DNS-over-HTTPS 代理，部署在 Cloudflare Workers。

多上游并发竞速、CDN 归属分流、优选域名替换、ECH 外置 SNI 注入、Meta 静态 IP 路由——一套方案解决 DNS 解析加速与绕过。

## 功能特性

- **多上游并发竞速** — Google、Cloudflare、Quad9、AdGuard、OpenDNS、NextDNS 等预设上游并行查询，最快响应优先返回
- **两阶段 AUTO 流程** — AUTO 1 多上游分类查询，识别 CDN 归属；AUTO 2 按归属对优选域名进行二次最优解析
- **CDN 感知路由** — 识别 Cloudflare、CloudFront、Vercel、Meta 等 CDN 响应，替换为地区可达的优选 IP
- **ECH 外置 SNI 注入** — CF 动态获取 ECH 公钥 + Meta 静态 ECH 配置，在 HTTPS RR 响应中注入加密 SNI，绕过 GFW SNI DPI
- **AAAA 阻塞** — 对 remap 域名直接返回 AAAA NODATA，避免 Happy Eyeballs 被 v6 超时拖慢
- **ECS 注入** — EDNS Client Subnet 携带客户端 IP 前缀，获取就近解析结果；隐私保护前缀可配
- **Chrome DoH Canary 拦截** — `use-application-dns.net` 返回 NXDOMAIN，关闭 Chrome 原生 DoH
- **结构化 JSON 日志** — 全链路 requestId 追踪，支持 debug/info/warn/error 分级
- **双响应格式** — 同时支持 RFC 8484 wire-format（`application/dns-message`）和 JSON（`application/dns-json`）
- **图形化配置向导** — 首页内置配置 UI，浏览器内完成全部配置，无需手写配置文件

## 部署

```
Fork 仓库 → 在 Cloudflare 连接 GitHub（Workers Builds）
  → 第一次部署（configured:0，内置默认跑）
  → 首页「配置」tab 图形向导 → 选上游/地区/ECH → 生成配置
  → 覆盖 superdoh.config.js → push
  → 自动第二次部署（configured:1）→ 正式运行
```

1. **Fork** 本仓库
2. 在 **Cloudflare Dashboard** → Workers Builds 连接你的 GitHub fork
3. **第一次部署** — `superdoh.config.js` 默认 `configured: 0`，Worker 用内置默认（Cloudflare + Google + AUTO，无地区优化）运行
4. 打开首页 **「配置」tab** → 图形向导选择上游、地区、ECH 等 → **生成 `superdoh.config.js`** → 下载 → 覆盖仓库根目录文件 → 提交
5. **第二次部署自动触发** — `configured: 1`，Worker 进入正式运行模式

> 也可本地部署：`npm install && npm run build && npm run deploy`（需 [wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) 已登录）

详细配置说明、API 端点、分流策略、架构等见 [DOCUMENTATION.md](DOCUMENTATION.md)。

## 已知限制

> [!WARNING]
> - **Meta ECH 是静态的** — `META_ECH_B64` 硬编码于 `ech.js`，不随 Meta 服务器轮换自动更新。ECH 公钥过期后需手动更新。
> - **ECH 注入会丢弃部分 DNS 记录** — HTTPS RR 重建时仅保留问题段和回答段，不保留原响应的 NS/AR/OPT/DNSSEC 信息。对普通浏览器 DoH 无影响，但依赖 DNSSEC 的客户端可能拿到不完整响应。
> - **Workers Free 计划 6 连接限制** — Free 计划仅有 6 个同时出站 TCP 连接。超过 6 个上游会导致排队等待，拖慢 DNS 响应。建议启用上游数不超过 6，并为 AUTO 2 优选解析预留槽位（`autoConcurrency` 设为 4）。
> - **地区优化依赖 `request.cf.country`** — `wrangler dev` 或非 Cloudflare 环境下该字段为空，地区优化路径不会触发。需通过线上 Worker 验证地区优化行为。

## 致谢

- [Total-ECH](https://github.com/RememberOurPromise/Total-ECH) — ECH 配置获取与 HTTPS RR 注入方案的核心参考
- [Sheas Cealer](https://github.com/SpaceTimee/Sheas-Cealer) — 域前置实践与 Cealing-Host 规则维护，本项目 Google 代理配置的自动拉取来源
- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) — GeoIP CIDR 数据源
