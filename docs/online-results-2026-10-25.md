# 2026-10-25 线上测量记录与验收边界

## 摘要

本次矩阵请求分两段：首段保留 15 个请求后中断并完成恢复；接续段再记录 175 个请求，共 **190 次矩阵尝试**。另有两次独立收尾验证请求，故总预算实际使用 **192/300**，剩余 108；收尾验证不纳入矩阵统计。矩阵有 4 项断言失败，分别是 3 项 HTTPS fixture 的 TTL 期望值和 1 项原本期望成功、但 TLS 上游返回 SERVFAIL 的场景。native invocation 数据只有 **189/190** 条；缺少的唯一记录属于 `ech-auth-cache` 的 subsequent 样本，没有 CPU/Wall/outcome/requestId 数据，未补零，也未用同版本的孤立 app 事件替代关联。

两个 composed workload 各有 16 次 warmup 和 32 次 measured；它们使用 fixture DNS ECH 来源，不代表每个 DNS 请求都执行一次主动 TLS 握手。round1 measured CPU median 为 6 ms；round2 为 10 ms，未达到严格 `<10 ms` 目标。两轮源码 SHA-256 相同，tracing 均为 false；但两轮使用不同 config version、发生在不同时间，缓存状态也可能不同，故不是稳定的因果 A/B。round2 的 `median=10 ms` 按严格小于条件判为未通过。

**结论：`fullAcceptance=false`。** 本记录只陈述有限的线上样本，不宣称完整 Free 套餐验收、keyed HTTP 验收或完整主动 ECH 握手覆盖。

## 样本和关联

| 项目 | 数量 / 结果 |
|---|---:|
| 首段中断前尝试 | 15 |
| 接续段尝试 | 175 |
| 矩阵尝试（首段 + 接续段） | 190 |
| 正确矩阵响应 | 186 |
| 矩阵断言失败 | 4 |
| 收尾验证请求（独立于矩阵） | 2 |
| 实际预算用量 / 上限 | 192 / 300 |
| 剩余预算 | 108 |
| native rows / 匹配矩阵样本 | 189 / 190（首段 15 + 接续段 174） |
| native outcome 为 `ok` | 189 / 189 |
| native CPU 严格 >10 ms | 54 / 189 |
| 缺失 native 样本 | 1，`ech-auth-cache` subsequent |
| 有 native requestId + version 关联的 app 事件 | 127 |
| 未与本轮 native requestId + version 关联的 app 事件，排除 | 29 |

JSON 为每个客户端样本保留 sample UUID、config version，并在 native 关联存在时保留 requestId、CPU、Wall、outcome；关联的 app 事件也带回对应样本 ID。所有 app 事件均要求同时匹配 native requestId 和 version。没有关联到样本的事件（包括其他 access 类事件）不纳入结果。缺失 native 的 ECH 样本没有 native metrics 字段，也不从同 version 的孤立 app 记录推断它是 cache hit。

两轮测量记录的 commit 相同（`0582d8600480e96bd4a4df30641af14dd8bf85e9`）。Runner source SHA-256 为 `413911583ee363a72cbc951e5449213fcd5478f9317ce23de61acbc4a4838c4c`；这是测量 runner 脚本哈希，不是线上 Worker 源码哈希。两个 before 快照中下载并核验的 Worker JS 为 1,209,790 bytes、SHA-256 `3b32bd2b2bbee8242da529f0b8f504c7ac84911d34b71a85a6c6c340a52be007`；WASM 为 854,948 bytes、SHA-256 `b19b09a573512b21f50c943c72ec6553078328623f442a511ddf33cd0b1f3a73`。composed-round1 config version 为 `f55cf11b-76dd-45d2-9b51-2549dd69a55d`，round2 为 `b544cc30-7c02-4576-80ac-6bdd15df12aa`，配置时间分别为 `2026-10-25T03:38:37.961Z` 和 `2026-10-25T03:39:55.736Z`。config version、时间、缓存状态均不同；这是影响解读的混杂条件。

## CPU、Wall 与客户端耗时

以下 summary 按 phase 汇总：首个观测样本、随后请求，以及 composed 两轮 warmup / measured。`over10` 仅计 **CPU 严格大于 10 ms**；Wall 和客户端延迟不是 CPU 阈值。每组 p95 都留空（JSON 为 `null`），不从小样本声称尾部分布。

| 样本组 | Attempts | Native 匹配 n | CPU min / median / max ms | CPU >10 ms | Wall min / median / max ms | 客户端延迟 min / median / max ms |
|---|---:|---:|---:|---:|---:|---:|
| first-observed | 24 | 24 | 11 / 17.5 / 110 | 24 | 12 / 52 / 129 | 1057.6 / 1116.3 / 1240.6 |
| subsequent | 70 | 69 | 0 / 2 / 36 | 5 | 0 / 4 / 197 | 159.9 / 182.0 / 1234.4 |
| composed warmup（两轮合计） | 32 | 32 | 6 / 11 / 57 | 17 | 21 / 31.5 / 167 | 189.1 / 204.9 / 1243.1 |
| composed measured（两轮合计） | 64 | 64 | 5 / 8 / 16 | 8 | 19 / 26 / 40 | 187.1 / 189.8 / 351.2 |

| Composed round | Phase | n | CPU min / median / max ms | CPU >10 ms | Wall min / median / max ms | 客户端延迟 min / median / max ms | 严格 `<10 ms` |
|---|---|---:|---:|---:|---:|---:|---|
| round1 | warmup | 16 | 6 / 7 / 36 | 2 | 21 / 23 / 155 | 189.1 / 203.1 / 1243.1 | 不作验收 |
| round1 | measured | 32 | 5 / 6 / 8 | 0 | 19 / 21 / 24 | 187.1 / 189.7 / 204.2 | 通过该轮中位数目标 |
| round2 | warmup | 16 | 9 / 13 / 57 | 15 | 31 / 34 / 167 | 190.8 / 205.3 / 1193.0 | 不作验收 |
| round2 | measured | 32 | 8 / 10 / 16 | 8 | 28 / 31 / 40 | 187.3 / 190.0 / 351.2 | **未通过** |

这里的客户端延迟是请求端耗时，不是 CPU；wall 也不是 CPU。首样本与 warmup 不混入 composed measured 的中位数。n=32 的 p95 不足以支撑可靠尾部保证。其余首观测/随后样本来自不同情景，不能把其混合 min/median/max 当作单一 workload 的性能承诺。

## 断言失败与 ECH 证据

1. `https-fixture-bypass`、`https-cache-disabled-policy`、`https-no-store` 三个 fixture 场景的预期 TTL 为 60，实际记录 TTL 为 59。该精确 TTL 断言不适合经过时间递减的 TTL，属于 fixture 期望不合理，不应归类为生产 bug。
2. `tls-public` 返回 HTTP 200，但 DNS RCODE 为 SERVFAIL（2）。与该 native requestId + version 关联的 app 事件为 `RESOURCE_LIMIT`；对应 native outcome 是 `ok`。这表示 invocation 平台记录本身正常结束，不表示 DNS 处理成功。具体 raw exception 未保存，因此不猜测更具体的异常原因。
3. 本轮最多执行 10 次 ECH probeAttempt，不等于发生 10 次真实 TLS 握手；composed 两轮使用 fixture DNS ECH 来源，也不是每请求一次主动 TLS。四个 uncached ECH 请求按顺序的 native CPU 为 default 57/21 ms、auth 110/35 ms，均有 requestId + version 匹配的 app `acquired` 事件。缓存模式的已关联样本为 default：66 ms `acquired`/`miss`、8 ms `hit`、7 ms `hit`；auth：69 ms `acquired`/`miss`、5 ms `hit`。最后一个 `ech-auth-cache` subsequent 样本缺 native 关联；不把同 version 的孤立 app 事件关联到该 sample UUID，也不推断它的命中状态。

接续段 ledger 在 keyed HTTP 阶段前以 `RUN_STOPPED` 安全门停止；没有 keyed HTTP 样本，因此不宣称 key 已完成验收。Sonnet 发现 fail-closed 安全门缺陷后，主线程在 keyed 阶段前中断，保留 15 个样本并执行恢复。更早的 proxy/OAuth 启动失败没有产生客户端请求；OAuth 后续自动刷新。完整 key / 身份行为仍待另行安全授权和验收。

## 收尾请求（不计入矩阵）

矩阵之后实际执行了两次收尾验证，不采集 telemetry，也不计入 190 条矩阵样本：producer 空配置请求返回 HTTP 200、DNS SERVFAIL 且无 records，符合预期；fixture/list-100 收尾请求返回 HTTP 503，也符合预期。两次计入总预算，实际使用量为 192/300，剩余 108。

## 当前资源恢复状态

清理记录中的恢复、active/latest bindings 恢复、fixture 恢复和 observability 恢复均为 true，错误数为 0。主线程另行检查的当前 Worker version 为 `eac6ba38-421c-4e84-a178-f90482c946d8`，active/latest bindings 均为空；fixture 状态为过期时间 0、列表状态 good。当前 logs 与 traces 均为 true。这里的恢复快照代表最终状态，不是 composed 测量期间的 tracing 设置；测量期间 tracing 为 false。未记录凭据、密钥绑定值、完整敏感 URL 或个人账户信息；结构化证据保留已脱敏的非 Secret 配置。历史 runner 归档保留的是实际源字节，不是可直接执行工具；旧归档引用了原私有 scratch 中的 composed config，因此本报告不要求读者访问该目录，而在结构化 JSON 中保存脱敏后的本轮 scenario vars 和完整 composed 规则/资源配置。若要重新执行，必须取得新的授权、建立新的 scratch 目录，并从本报告配置重建；不得导入旧脚本或 OAuth 状态，也不得覆盖历史证据。fixture latest 没有单独的 pretest 快照；当前恢复状态已由主线程另行双查。

## 历史编排归档的已知缺陷

两个 `runner-*.mjs.txt` 是保留实际执行字节的证据，不是可运行或推荐复用的工具。首段归档只按 `fatal` 设置失败退出码，未计入 `ledger.failures`，因此其退出码不能用作正确性结论；接续段已把样本失败纳入非零退出码。两段还不能仅凭退出码保证 cleanup 成功，必须独立读取清理记录和控制面状态。本报告按样本逐条统计、保留中断和所有断言失败，并独立核验恢复，不按退出码推断验收。重新实施时应先修复这些编排边界，不能直接运行归档；也不能为修复历史缺陷而改写已执行源码字节。

## 实现与测试状态

本轮安全门代码改动限于 `scripts/lib/acceptance-safety.mjs` 与对应测试；`package.json` 注册了 `test:measurement`，没有修改生产实现。新增的两个安全断言经历 red/green；`npm run test:measurement` 19 项通过，主线程实际运行的 `npm test` 共 540 项通过。Rust 本轮没有重新运行 cargo。总预算 192/300 已包含 190 次矩阵尝试和两次不采 telemetry 的收尾验证，剩余 108；按安全边界停止，不自动追加测试、不绕过 fail-closed，也不通过隐藏失败来制造验收结论。

## #25 验收条件逐项对账

| #25 验收主题 | 当前证据 | 剩余缺口 / 状态 |
|---|---|---|
| 1. 单独授权的 Free 环境、资源及恢复边界 | 受控样本可关联；中断恢复与接续清理均记录成功，当前 active/latest bindings 为空 | 本轮依已批准计划执行，不公开授权对话或凭据；套餐未通过账单 API 核验；keyed HTTP 未启动 |
| 2. 冷/热、缓存、规则规模、列表、归属、主动 ECH | 有 fixed/rules-16/rules-128、HTTPS cache 场景、list-100/1000/4096/refresh、attribution-0/60、composed、ECH 场景样本 | 规模覆盖是有限样本；4 个断言失败；10 probeAttempt 不是 10 次握手；一条 ECH native 缺失；不足以证明全部冷/热和完整主动探测覆盖 |
| 3. CPU、Wall、延迟、资源错误与限制 | 190 客户端样本、189 native 关联；分组给出 min/median/max 与 CPU >10；TLS 对应 `RESOURCE_LIMIT` | 1 native 丢失；p95 未报告；第二 composed 轮 median 10 ms 未通过严格 `<10`；不能承诺尾部或任意负载 |
| 4. Free 默认 / 内置配置及重型来源错误 | 有若干配置情景；TLS 上游失败能关联到 `RESOURCE_LIMIT` 事件 | 不能替代完整默认 / 内置配置矩阵；key 阶段无 HTTP 样本；失败范围不等于全部来源行为 |
| 5. 本地互操作、公开入口、缓存隔离、脱敏、DNSSEC | 有协议 JSON、HTTPS/TCP/TLS、ECH 和缓存状态相关样本 | 本轮证据不完整证明独立互操作、所有上游协议校验、缓存隔离、密钥脱敏与 DNSSEC 改写语义 |
| 6. 可复现说明、边界与结论 | 样本 UUID/version/native requestId、source SHA-256 和恢复状态均保留；明确 `fullAcceptance=false` | 当前结果只覆盖本报告列出的特定配置、时间和暖/缓存状态，不是完整免费套餐保证 |
| 7. 未通过时给出取舍并等待决定 | 断言失败、未通过轮次和停止边界均如实记录；只改安全门测试代码 | 完整验收仍未通过，不自动完成父规格或其他任务；后续范围需按授权与用户决定推进 |
| 8. 类型、workerd、DNS/ECH 回归 | 本轮 `test:measurement` 19 项及 `npm test` 540 项通过 | Rust 未重跑 cargo；这些结果不替代线上 Free CPU 验收 |
| 9. HTTPS/TCP/TLS、JSON 顺序处理与缓存覆盖 | 有 HTTPS、TCP、TLS、protocol-json、缓存策略情景记录 | TLS 为 SERVFAIL / `RESOURCE_LIMIT`；keyed HTTP 没有样本；当前结果不足以宣称相关验收全部通过 |
| 10. 真实传输与身份错误 | TLS 失败有 matched `RESOURCE_LIMIT` 证据；proxy/OAuth 初始失败未产生客户端请求 | 没有 keyed 请求；raw 异常未保存；不得推断具体异常或宣称认证行为已完整验收 |

**验收结论：当前证据不满足 #25 完整验收，`fullAcceptance` 保持 false。** 本轮计划已批准；Free 套餐条件沿用人工确认，未通过账单 API 独立核验。本报告不修改先前保留的五个文件，也不构成额外后续操作授权。
