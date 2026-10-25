# 2026-10-25 优化测量结果

## 结论

本轮 `.acceptance/optimization-20261025` 白名单证据包含 576 次客户端尝试，全部得到正确响应；其中 192 次预热、384 次测量。每条样本均以 ledger 的 `sampleId` 关联 native invocation 的 CPU、Wall、outcome、requestId 和运行版本。结果可复核，但这是顺序部署、暖路径的有限测量，不构成稳定 A/B，也不是完整 Free 套餐验收。

最新源码的最后两个 composed 测量阶段（residual、confirm）CPU 中位数均为 6 ms；此前 phase2b 同一代码的 composed 中位数为 11 ms。phase2b 与后续阶段的 tracing 设置不同，部署、隔离实例和时间条件也不同，不能据此认定是代码产生了 5 ms 改善。residual 中移除 list 与移除 geo 的结果仅是单独的探索性对照，不足以归因 list 或 geo 的 CPU 成本。

## 计数、样本和口径

| 阶段 | 总请求 | 预热 | 测量 | 工作负载 | 正确响应 | CPU 中位数（测量样本） |
|---|---:|---:|---:|---|---:|---|
| baseline | 96 | 32 | 64 | cache32、composed，各 16 预热 + 32 测量 | 96/96 | cache32 3 ms；composed 11 ms |
| phase1 | 96 | 32 | 64 | cache32、composed，各 16 + 32 | 96/96 | cache32 2 ms；composed 11 ms |
| phase2 | 96 | 32 | 64 | cache32、composed，各 16 + 32 | 96/96 | cache32 1 ms；composed 10 ms |
| phase2b | 96 | 32 | 64 | cache32、composed，各 16 + 32 | 96/96 | cache32 1 ms；composed 11 ms |
| residual | 144 | 48 | 96 | composed、without-list、without-geo，各 16 + 32 | 144/144 | 6 ms；6 ms；8 ms |
| confirm | 48 | 16 | 32 | composed，16 + 32 | 48/48 | composed 6 ms |
| **总计** | **576** | **192** | **384** |  | **576/576** |  |

CPU 为 Cloudflare invocation CPU，不是客户端延迟；Wall 是 native invocation Wall 时间，不可与 CPU 混为一谈。各条 CPU、Wall、outcome 与样本的对应关系见随附 JSON。六阶段 ledger 共 576 个样本，native rows 也各自按 `sampleId` 与版本一一匹配，共 576/576；没有未匹配样本。native 证据的 `count` 字段在 phase1 为 192，但其可核对的 rows 只有 96 条。故本报告按唯一 `sampleId` + version 关联的 96 条计入 phase1，而不是把这个 count 字段当作额外请求；六阶段总数按 ledger/client attempts 计算。

对照测量包括预热样本；所列每项 CPU 分布只统计对应 workload 的 32 个 measured、成功且匹配的样本。各 workload 的测量 n=32：baseline composed p95/max 14/14 ms；phase1 14/15 ms；phase2 12/14 ms；phase2b 16/17 ms；residual composed 8/8 ms、without-list 8/8 ms、without-geo 10/10 ms；confirm composed 8/8 ms。n=32 的 p95 仅是历史探索性描述，尾部样本太少，不是可靠的尾部保证。median、p95 及 max 都不能保证未来请求符合 Free CPU 限制。

native invocation 结果状态为 `ok`，各阶段成功测量的 CPU/Wall 是独立字段；不把传输时延算入 CPU。汇总中没有失败或缺失指标。唯一标识是合成测试关联标识，不是凭据；随附 JSON 保留 sample UUID、部署 version 与 native requestId，以便审计关联。

## 阶段设置差异与可比性

- baseline、phase1、phase2、phase2b 各含 cache32 和 composed 两类 workload，均按每类 16 次预热、32 次测量；residual 增加 composed / without-list / without-geo 三组；confirm 只复测 composed。
- `comparison` 中的 `observabilityBefore` 是每轮测量前的恢复快照，并不表示实际测量期间的 invocation logging 设置。运行器在各轮测量时都将 `invocation_logs` 设为 true，并在轮次后恢复该快照；因此 invocation logging 不是各阶段的测量差异。tracing 未被同一运行脚本切换：baseline 至 phase2b 的测量前快照为 `traces.enabled=false`，residual 与 confirm 为 `true`，这项差异在测量期间保留。日志和 traces 的 head sampling 均为 1、持久化启用；这些观测设置与部署/实例/时间变化仍有混杂，不能单独解释 CPU 差异。
- comparison 将六阶段标为顺序部署，不是 isolate-controlled 的因果比较。缓存按既有策略可能已预热；这些结果是暖路径，不代表冷路径。
- residual 的 without-list / without-geo 是 workload 标签下的探索性差分，不是随机化、重复、单因素控制实验；不可据此断言 list 或 geo 是耗时来源。

## 与独立 interleaved 实验区分

`.acceptance/repeated-interleaved-20261024/summary.json` 是另一项独立实验，不计入上面的 576 次。其记录为 306 attempts、192 次预热、304 个正确响应、32 轮计划中的 17 个完整配对轮次。两次 HTTP 503 中，一次有平台 `exceededCpu` 证据（CPU 14 ms、Wall 17 ms、平台错误 1102）；该 14 ms 是 CPU 限额触发后的截断记录，不是该请求完整执行成本。另一次 503 没有可归因的 `exceededCpu` 证据。该实验 retained 112 requests、109 native-matched；存在被替换测量及未匹配项，因此不能与本轮数据拼接或作为额外重复样本。

## #25 验收条件对账

本次证据只能支持有限的性能样本和正确响应计数，不能宣称 #25 完整验收：

- 这不是完整覆盖冷/热、缓存命中/未命中、多规则规模、列表加载/更新、归属补全、完整主动 ECH 探测等要求的测试矩阵；现有 workload 标签不证明这些维度已全面覆盖。
- 没有在本轮证明 Free 默认及内置配置行为、真实上游传输/认证错误、外部可公开入口与独立互操作结果、缓存隔离、密钥脱敏、DNSSEC 改写语义的完整验收覆盖。
- 结果是 Cloudflare 实际 invocation CPU 与 Wall 的特定暖路径样本，不等于无限制配置、冷路径或所有免费套餐请求都能满足 CPU 限制。后台/Cron 也不改变这个结论。
- 任意规模配置和不受限外部列表均不作无条件 CPU 承诺；尚未完成的验收范围应继续标为未验收，不以本报告替代缺项或自动关闭相关任务。

本会话已审查的三个提交 `25a82bb`、`d80e62e`、`0582d86` 未发现阻塞；npm 538 项通过。Rust 本轮未重新运行 cargo，因此不表述为本轮 Rust 测试通过。此前尚未提交的 README、acceptance、online-acceptance、online-results20261024、evidence 五项保持原样。

## 恢复状态

最终恢复证据表明：active/latest bindings 均为空，fixture 已恢复但已过期；当前 observability 恢复状态为 `invocation_logs=true`、`traces=true`，并非关闭。恢复检查通过，确认版本为 `a6648644-3bbe-42b2-9e62-2eff11421921`。此处记录的是实际恢复后的状态，不把它误写成 false。

## 可复核材料

随附 `docs/results/2026-10-25/optimization.json` 是脱敏后的结构化提取：包括六阶段摘要、观测设置、恢复状态，以及 576 条 ledger/native 一一关联的样本记录。未纳入私有日志、完整敏感 URL、凭据或未列入白名单的原始记录。
