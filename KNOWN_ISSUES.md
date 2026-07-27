# SuperDoH 已知问题

## DoH 响应显式禁止共享缓存

客户端 DNS 响应设置 `Cache-Control: no-store` 和 `Vary: Accept`。请求会按 ECS 与地区配置转换，上游或 CDN 的共享缓存无法安全复用这些响应；这是 RFC 8484 §5.1 下的有意策略。

## GeoIP 部分失败静默降级

`build-config.cjs` 用 `Promise.allSettled` 抓取 8 个 GeoIP CIDR 列表，失败时只 `console.warn` 不终止构建。构建产物中对应分类为空数组，CDN 分类静默失效。构建日志可见 warning。

## ECS 发给所有上游

`prepareQuery` 注入一次 ECS，同一请求体发给所有上游（含 `ecs:false` 的）。`ecs` 字段控制竞速优先级，不控制是否注入。这是特性，非 bug。

## 自定义上游不进 AUTO 竞速

`slice(0, AUTO_CONCURRENCY)` 按插入顺序截断，`CUSTOM_*` 环境变量注入的上游在末尾被排除。自定义上游只能通过 `/<provider>/dns-query` 单独访问。这是特性，非 bug。

## Token 仅支持 query 参数

`?token=secret` 是 DoH 的标准做法。不支持 `Authorization: Bearer` header，因为部分 DoH 客户端不支持自定义 header。token 可能出现在浏览器历史、代理日志中。

## /config.json 无鉴权

`/config.json` 在 token 校验之前返回，暴露上游名称、URL、地区配置、Google 代理 IP 等信息。主页和静态资源也无鉴权。

## 默认记录完整查询域名

`logLevel: info` 下 `request_start` 事件记录完整 `qname`。Cloudflare observability 默认 100% 采样。日志只有部署者可见。

## DO bit 强制设置

`prepareQuery` 对所有查询注入 EDNS OPT 并强制设置 DO bit，即使客户端没请求 DNSSEC。这是 ECH 流程需要看到 RRSIG 的设计。

## DNS JSON 仅支持 A/AAAA

`rdataToJsonData` 只格式化 A（IPv4 点分）和 AAAA（IPv6 冒号）。CNAME、MX、TXT、HTTPS 等类型返回 base64 原始 RDATA。

## 构建依赖远程可变数据

构建时从 GitHub（GeoIP）和 GitLab（Cealing-Host）抓取数据，使用浮动分支 URL，无 SHA 校验。相同代码多次构建结果可能不同。

## 配置数值缺范围校验

`build-config.cjs` 的 `parseInt` 不验证 `ecsPrefix4`（应 0-32）、`ecsPrefix6`（应 0-128）等范围。前端向导有校验但构建脚本没有。

## 测试未用 Workers 运行时

`vitest.config.js` 用 `environment: 'node'` 而非 `@cloudflare/vitest-pool-workers`。测试无法覆盖 `env` 绑定、`request.cf`、子请求限制等 Workers 特性。

## clean checkout 无法直接 test

`src/config.js` 和 `src/templates.js` 是 gitignore 的生成产物。`npm test` 前需先 `npm run build`，否则 import 失败。
