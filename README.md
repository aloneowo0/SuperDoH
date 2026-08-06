# SuperDoH

> 轻量级 DNS-over-HTTPS 代理，部署在 Cloudflare Workers。

多上游并发竞速、CDN 归属分流、优选域名替换、ECH 外置 SNI 注入、Meta 静态 IP 路由——一套方案解决 DNS 解析加速与绕过。

## 功能特性

- **多传输上游竞速** — 预设上游可分别选择 DoH 或 DNS-over-TCP；全部启用上游作为候选，按滑动并发窗口竞速
- **两阶段 AUTO 流程** — AUTO 1 多上游分类查询，识别 CDN 归属；AUTO 2 按归属对优选域名进行二次最优解析
- **CDN 感知路由** — 识别 Cloudflare、CloudFront、Vercel、Meta 等 CDN 响应，替换为地区可达的优选 IP
- **ECH 外置 SNI 注入** — CF 动态获取 ECH 公钥 + Meta 静态 ECH 配置，在 HTTPS RR 响应中注入加密 SNI，绕过 GFW SNI DPI
- **AAAA 阻塞** — 对 remap 域名直接返回 AAAA NODATA，避免 Happy Eyeballs 被 v6 超时拖慢
- **ECS 注入** — EDNS Client Subnet 携带客户端 IP 前缀，获取就近解析结果；隐私保护前缀可配
- **Chrome DoH Canary 拦截** — `use-application-dns.net` 返回 NXDOMAIN，关闭 Chrome 原生 DoH
- **结构化 JSON 日志** — 全链路 requestId 追踪，支持 debug/info/warn/error 分级
- **双响应格式** — 同时支持 RFC 8484 wire-format（`application/dns-message`）和 JSON（`application/dns-json`）
- **图形化配置向导** — 首页内置配置 UI，浏览器内完成全部配置，无需手写配置文件
- **伪装入口** — 设置 `ENTRANCE` + `PROXY` 环境变量后，非秘密路径反向代理到指定网站，仅秘密路径显示主页
- **自定义上游** — 通过 Workers 环境变量 `CUSTOM_<NAME>` 运行时注入自定义 DoH 上游，即时生效无需重新部署

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

Workers Builds 的 **Build command** 使用 `npm run build`，**Deploy command** 使用 `npx wrangler versions upload`。构建脚本会在缺少工具链时自动安装固定版本的 Rust 1.88.0、rustfmt、`wasm32-unknown-unknown` 和 `worker-build` 0.8.5，然后生成配置并编译 Worker；部署阶段只上传已生成的产物。

> 也可本地部署：`npm install && npm run build && npm run deploy`（需 [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) 已登录；Windows 请先自行安装 rustup）

详细配置说明、API 端点、分流策略、架构等见 [DOCUMENTATION.md](DOCUMENTATION.md)。

## 已知限制

> [!WARNING]
> - **Meta ECH 映射是静态策略数据** — 构建器把 `metaEchMap` 编译进 Worker，不随 Meta 服务器轮换自动更新；映射失效时需更新配置/构建数据。
> - **ECH 注入会修改 DNS 响应** — HTTPS RR 重建时清除 AD 位并删除覆盖 type 65 的 RRSIG，不保留原响应的 DNSSEC 签名。对普通浏览器 DoH 无影响，但 DNSSEC 验证客户端会丢弃修改后的响应。
> - **Workers 出站连接限制** — 单次 fast/mix 的同时在飞数量由 `upstreamConcurrency` 控制，默认 2；过高窗口会放大页面级 socket 压力。Cloudflare 与 NextDNS 预设保持 DoH-only。
> - **地区优化依赖 `request.cf.country`** — `wrangler dev` 或非 Cloudflare 环境下该字段为空，地区优化路径不会触发。需通过线上 Worker 验证地区优化行为。

## 致谢

- [Total-ECH](https://github.com/RememberOurPromise/Total-ECH) — ECH 配置获取与 HTTPS RR 注入方案的核心参考
- [Sheas Cealer](https://github.com/SpaceTimee/Sheas-Cealer) — 域前置实践与 Cealing-Host 规则维护，本项目 Google 代理配置的自动拉取来源
- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) — GeoIP CIDR 数据源
