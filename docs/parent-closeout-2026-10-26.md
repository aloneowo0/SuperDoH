# #7 父规格交付核对

## 当前结论

截至 2026-10-26，GitHub 开放票据只有 [#7](https://github.com/aloneowo0/SuperDoH/issues/7)。#8–#29 共 22 个子项均关闭：21 个 `COMPLETED`，#14 竞速为 `NOT_PLANNED`。没有下一张待实现、可直接领取的子票。

本次推进的是父规格的交付核对，不是重新验收 #25。核对基线为已发布的 `faae1d67982e133e2060ef40dbc0b154f22c34c9`；检查规格、子项状态、当前实现入口、已有测试定义及已提交证据的对应关系。**未发现需要立即新建实现票的已确认功能缺口**；这不是全仓无缺陷证明，也不因子票关闭就自动认定父规格通过。

[最终验收](final-acceptance-2026-10-26.md)支持已确认使用政策下的有限交付。父规格收尾仍需明确同步其陈旧状态与接受边界；本文件不发布 GitHub 评论、不修改正文、不关闭 #7、不推送或部署。

## 73 个用户故事与测试要求映射

编号取自 #7 的 User Stories；T1–T13 对应其 Testing Decisions / 外部行为覆盖。表中测试文件是覆盖定义，不表示本轮重新运行通过；实际执行记录以所链的已提交验收资料为准。

| 用户故事 | 交付与当前实现 | 测试要求及依据 |
| --- | --- | --- |
| 1、60–62 | 免费环境测量、资源错误与用户取舍；不是无条件 Free 保证 | T13；[#25](https://github.com/aloneowo0/SuperDoH/issues/25)、[最终验收](final-acceptance-2026-10-26.md) |
| 2–10、73 | 单部署运行时 JSON、组排序、全量预检、移除用户函数；`src/rules/config.js`、`src/index.js`、`docs/migration.md` | T1/T12；#8/#26/#27；`test/rules.mjs`、`test/runtime-config.mjs` |
| 11–22 | 条件组合、域名/原始与当前数据、客户端/边缘区分、同地址归属；`src/rules/conditions.js`、`src/doh/metadata.js`、`src/doh/attribution.js` | T2；#10/#17/#18；`test/rules.mjs`、`test/metadata.mjs`、`test/attribution.mjs` |
| 23–29、71 | 列表文本/JSON、刷新前失效、成功原子替换、失败不可用与恢复；`src/rules/domain-lists.js` | T9；#19；`test/domain-lists.mjs`；[历史当前版本来源测量](online-results-2026-10-25.md) |
| 30–31、34–42、46–49、65–67 | 显式命名请求、合法 RCODE、候选提交与可选回滚、最近结果不回滚、无隐式补查；`src/index.js`、`src/doh/upstream.js` | T3/T5/T6/T7；#9/#27；`test/rules.mjs`、`test/doh.mjs`；当前组合云端证据 |
| 32–33、58 | 自定义记录、记录/TTL/AAAA/HTTPS 改写、统一协议和 AD/RRSIG 收尾；`src/rules/records.js`、`src/doh/protocol.js` | T11；#8/#16；`test/records.mjs`；当前云端签名收尾 4/4 |
| 43–45 | 请求/动作定位、稳定错误码、继续/终止处置及默认脱敏；`src/rules/errors.js` | T6/T10；#9/#12/#27；`test/rules.mjs`、`test/doh.mjs`；[密钥与脱敏证据](practical-free-closeout-2026-10-26.md) |
| 50–51、68–70 | 原始上游缓存、身份/TTL/负缓存、命中继续规则、动作覆盖策略；`src/doh/cache.js`、`src/rules/cache-policy.js` | T8；#15；`test/cache.mjs`；[当前隔离检查](cache-isolation-2026-10-26.md) 14/14 |
| 52–54 | GET/POST、可选 JSON 同核、Secret 路径认证先于配置/来源工作；`src/worker.js` | T10；#12/#23；`test/doh.mjs`、`test/json.mjs`；当前公开入口与历史密钥轮换证据 |
| 55–57、59、72 | 直接/DNS/主动 ECH 薄适配、独立通用库、默认未认证与显式认证分离；`src/rules/ech.js`、`src/doh/ech-probe.js`、`lib/ech-probe` | T11/T12；#20/#21/#22；`test/ech.mjs`、`test/ech-probe.mjs`；[独立互操作与历史回归](acceptance.md#current-build-task-closeout-2026-10-23) |
| 63–64 | HTTPS/明文 TCP；任何 tls 定义预检失败，包括未使用、不可达与缓存命中场景；`src/doh/upstreams.js`、`src/doh/dns-stream.js` | T4/T7；#28、后续范围修订；`test/tcp.mjs`、`test/tls.mjs`；[当前源码冒烟](current-source-smoke-2026-10-26.md)、[HTTPS 认证负例](results/2026-10-26/https-auth.json) |

T12 的类型检查、无 `nodejs_compat` 运行配置与既有 DNS/ECH 库回归的执行来源，见[验收索引](acceptance.md)及最终验收报告。当前公共执行器先做完整配置/引用预检，再维护列表、匹配规则和执行动作；任何收尾路径不自动补查。此处是实现核对，不新增网络调用次数或取消行为的实测证明。

## 不能由 CLOSED 状态推出的结论

1. **#11/#13 是旧规格交付，不是当前仍支持的能力。** 用户函数、上游组自动回退已由 #26/#27 迁移移除；当前迁移文档明确拒绝旧配置。#14 已取消，不是待补实现，也不能换名加回竞速。
2. **#29 不代表当前 DoT 认证通过。** 该票保留历史实现，2026-10-25 后续评论明确撤出范围。当前 [ADR 0001](adr/0001-exclude-dot-from-current-scope.md) 与代码要求整体拒绝 tls；独立 ECH TLS 探测不受影响。
3. **#25 完成不等于所有请求 Free 安全。** 用户已确认“大部分请求满足 Free、允许成功超额”；代表性 32 次测量中 26 次 ≤10 ms，40 个含初始请求中 31 次 ≤10 ms。主动未缓存 ECH 有重复高成本，旧资源错误和 TCP 一次失败仍保留，不能承诺任意配置或每次完整握手均合适。
4. **测试存在、历史通过和本轮重跑是不同事实。** 本次没有运行本地行为/全量 npm/Rust 测试、独立握手或新增云端测量。#25 的当前云端结果与相同输入的历史库回归有明确来源，不把它们升级成全仓当前版本全套重新通过。
5. **源码发布不等于部署。** dev 已发布，main 未合并；隔离 Worker 恢复原测试代码，不是候选生产部署。交付不代表业务流量已迁移。

## 剩余的实际收尾项

- #7 正文“实施快照”仍停在 `37fd8ae`，2026-10-23 评论仍称 #25 开放。这些是历史记录，不删除；需要追加当前状态，而不是继续按旧快照领取已经完成的迁移工作。
- 当前关闭依据必须引用最终验收、HTTPS/TCP-only ADR、明确的 ECH 认证默认与性能限制。不得只写“全部子票关闭，所以完整版本无条件通过”。父规格原文的 Free 目标应结合后续已批准取舍解释，不把有界结果改写成更强承诺。
- 当前未发现需要新增功能票的已确认缺口；可推进的是**发布父规格对账与明确范围的关闭说明**。若后续选择 DoT、逐请求未缓存 ECH 的 Free 保证或生产部署，分别作为新范围处理，不擅自恢复或扩张。
- 工作区另有既存未提交的诊断/工具改动；本次不纳入提交、不删除、不替其宣称审查通过。

## 拟发布的 #7 收尾说明

> 当前 JSON-only、显式 HTTPS/普通 TCP、原始响应缓存、来源维护、记录改写、JSON 入口及独立 ECH 薄适配已按子项交付。#25 已完成并关闭，当前源码代表用例、DNSSEC 收尾和 HTTPS 证书拒绝证据已发布。
>
> 本规格按后续批准的 HTTPS/TCP-only 范围及多数请求满足 Free 的实际使用政策收尾。不是任意配置或逐请求未缓存主动 ECH 的 CPU 保证；ECH 默认未认证、显式 true 才验证身份的契约及所有模式的 CertificateVerify/Finished 校验保持不变。DoT 历史结果、性能超额/错误和所有既有记录保留，#14 不实施，#29 不作为当前云端认证通过依据。
>
> 详情见父规格核对、最终验收报告与 ADR 0001。仅收尾规格交付，不表示合并 main、部署、清理无关工作区或开始新范围。

**发布边界：** 以上是本地拟稿，不是已发布评论。此前授权只关闭 #25 且明确不修改 #7；发布此新文件、修改或关闭 #7 必须另行确认，不沿用上一次授权。
