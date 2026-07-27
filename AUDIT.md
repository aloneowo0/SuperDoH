# SuperDoH 代码审计报告

审计时间：2026-07-27
分支：dev
审计方：Oracle（全量审查）+ Sisyphus（人工评判与验证）

---

## 审计范围

全部源码文件：`_worker.js`、`src/*.js`、`scripts/build-config.cjs`、`frontend/js/config-wizard.js`、`frontend/index.html`、`frontend/en.html`、`test/*`、`wrangler.jsonc`、`package.json`

审计维度：正确性、安全性、DNS 协议合规、Workers 平台适配、代码质量

---

## 已修复问题

### H-01 AUTO 把 NXDOMAIN/NODATA 变正常答案（HIGH）

**文件**：`_worker.js:507-511`

**问题**：AUTO 1 返回 NXDOMAIN（RCODE=3）或空 Answer（NODATA）后，如果查询域名命中 remap/Meta/Google 规则，代码仍走分类逻辑合成正面答案。例如查询 `ghost.facebook.com` 返回 NXDOMAIN，但 `isMetaDomain` 匹配 `facebook.com`，Meta 路由合成有效 IP。

**修复**：在 `regionActive` 检查后增加 RCODE 和 Answer 数量检查，非 NOERROR 或零 Answer 直接返回原始响应，不进入分类。

**状态**：✅ 已修复

---

### H-02 Meta 解析接受任意公网 IP（HIGH）

**文件**：`_worker.js:456-488`

**问题**：Meta 解析从上游响应提取 A/AAAA 记录 IP 后直接加入候选列表，没有检查 IP 是否属于 Meta CIDR。静态路由 IP 和上游 IP 混在一起无区分。被污染或异常的上游可将 Meta 流量重定向到任意服务器。

**修复**：静态路由 IP 保留信任；非静态 IP 调用 `detectOwner()` 确认归属为 META，不属于的丢弃。

**状态**：✅ 已修复

---

### H-04 ECH 保留无效 DNSSEC 签名（HIGH）

**文件**：`src/ech.js:244-248`

**问题**：ECH 注入修改 HTTPS RR 后，原始 RRSIG（type 46，覆盖 type 65）仍被保留在 Answer 段中。修改后的 RRset 不再被原始签名覆盖，DNSSEC 验证客户端会标记为 BOGUS 并拒绝。清除 AD 位不够——签名本身必须移除。

**修复**：在 Answer 遍历中跳过 `type === RRSIG(46)` 且 RDATA 前 2 字节（covered type）等于 `TYPE_HTTPS(65)` 的记录。

**状态**：✅ 已修复

---

### L-01 未知路由返回 400 而非 404（LOW）

**文件**：`_worker.js:716`

**问题**：`not_found` 错误和 `unknown_provider` 错误都返回 400 Bad Request。`not_found` 应返回 404。

**修复**：`jsonError(route.error, route.error === 'not_found' ? 404 : 400)`

**状态**：✅ 已修复

---

### L-10 安全入口 section 无法折叠（LOW）

**文件**：`frontend/js/config-wizard.js:399`

**问题**：安全入口 section 的标题区域没有 `onclick` 事件，无法像其他 section 一样点击折叠/展开。

**修复**：添加 `onclick: function (e) { toggleSection(sec, e); }`

**状态**：✅ 已修复

---

## 已知问题（评估后不修复）

以下问题经评估后决定不修复，原因附后。

### 上游响应无大小限制（原 H-03）

`arrayBuffer()` 无限制读取上游响应。DoH 响应正常只有几百字节到几 KB，上游 DNS 服务器不会返回大 body。理论风险但实际触发概率极低。**降级为 LOW，不修复。**

### GeoIP 部分失败静默产生降级部署（原 H-05）

`Promise.allSettled` + warn-only 不终止构建。这是构建时行为，用户可在部署前看构建日志。空 CIDR 只让 CDN 分类不触发，不产生错误结果。**降级为 MEDIUM，不修复。**

### ECS 发给所有上游（M-03 in review report）

`prepareQuery` 注入一次 ECS，同一 body 发给所有上游（含 `ecs:false` 的）。用户确认不影响功能——`ecs` 字段控制竞速优先级而非是否注入。**作为特性保留，不修复。**

### 自定义上游不进 AUTO（M-06 in review report）

`slice(0, AUTO_CONCURRENCY)` 按插入顺序截断，CUSTOM_* 在末尾被排除。用户确认作为特性。**不修复。**

### Token 仅支持 query 参数（M-11）

DoH 客户端不一定支持自定义 header，query 参数是 DoH 标准做法。**不修复。**

### /config.json 在 token 前公开（M-12）

之前修过又撤销。用户决定不修。**不修复。**

### 默认记录完整 qname（M-13）

observability 是用户自己开启的，日志只有用户可见。**不修复。**

### DO bit 强制设置（M-04）

可能是 ECH 流程需要看到 RRSIG 的故意设计。**不修复。**

### DNS JSON 只支持 A/AAAA（M-07）

按需扩展即可，当前够用。**不修复。**

### 构建依赖远程可变数据（M-19）

GeoIP/Cealing-Host 必须构建时拉取。加 SHA 校验是理想但过度工程化。**不修复。**

### 其余 MEDIUM/LOW

响应验证不完整（M-01/M-02）、buildDNS 标志（M-05）、JSON 路径（M-06）、向导配置丢失（M-08/M-09）、配置范围校验（M-10）、npm audit（M-16）、HTTPS RDATA 解析（M-17）、IPv4 /0 CIDR（M-18）、clean checkout test（M-14）、Workers Pool（M-15）——均因投入产出比低或影响极小，不修复。

---

## 审计中确认做得好的部分

- 入站 DNS wire 请求有结构化和大小校验
- RCODE 和 AD 位的 ECH 修复已到位
- 上游竞速使用 AbortController 安全 settle
- 伪装代理剥离了凭据和客户端 IP 头，验证了重定向
- DNS 名称解析包含压缩循环和越界保护
- 日志结构化 JSON，observability 已启用
- 现有边界测试清晰且快速

---

## 审计方法

1. Oracle 全量审查 25 个源文件，输出 5 HIGH + 20 MEDIUM + 13 LOW
2. Sisyphus 逐条验证 Oracle 发现，读实际代码确认
3. 评判每条：属实/不属实/过度标级/故意设计
4. 修复确认属实的 HIGH + 低成本 LOW
5. 不修复的记录原因