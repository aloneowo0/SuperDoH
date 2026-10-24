# 无效 ECH 占位 A/B 与默认 Cache API（2026-10-24）

## 结果

无效 ECH 扩展本身约 0.002992 ms，固定模板复制约 0.000481 ms，差值约 2.511 微秒；原图约 0.4–0.5 ms 的阶段观测不是它的净耗时。固定模板能在本地 OpenSSL 夹具取得 retry_configs 并完成握手，但完整探测批次区间重叠，认证路径在一个固定模板 session 还比两个随机版 session 更慢。没有证明稳定的完整调用收益，保留生产随机占位实现，不引入固定可识别的 ECH 值。重叠范围是描述性统计，不是置信区间，也不能证明绝对没有收益。

应用 probeEch 动作现已默认使用 Workers Cache API 缓存成功的 ECHConfigList **60 秒**。显式 cacheTtl:0 关闭，1..86400 自定义。独立库仍不依赖 Cache API；queryEch 保持原 DNS TTL 缓存策略。

## A/B 数据

单位 ms / 操作，批次 CPU 由 Linux 进程 CPU 时钟读取，无阶段 RPC、无采样 profiler，计入 workerd 各线程及 GC。按 random / fixed / fixed / random 启动四个隔离 runtime；各 session 六个正反序批次。每种实现有 120,000 次扩展构造、6,000 次 ClientHello、每认证模式 480 次计时握手。另有预热，总计 2,080 次诊断握手成功；服务端收到 2,083 条客户端 Finished，额外 3 条来自既有互操作成功用例。

| 操作 | 随机版均值 | 固定版均值 | 随机版批次均值范围 | 固定版批次均值范围 |
| --- | ---: | ---: | --- | --- |
| 空循环对照 | 0.000165 | 0.000147 | 0.000056–0.000480 | 0.000064–0.000479 |
| 无效 ECH 扩展构造 | 0.002992 | 0.000481 | 0.002309–0.003640 | 0.000297–0.000941 |
| 完整 ClientHello | 0.041316 | 0.037737 | 0.036397–0.045580 | 0.031575–0.043459 |
| 完整库探测，关闭链认证 | 1.627094 | 1.531268 | 1.392844–1.861689 | 1.325127–1.720730 |
| 完整库探测，自定义 CA 认证 | 3.811210 | 3.766978 | 3.223077–4.793009 | 3.307547–4.591461 |

固定模板为预编码、格式合法但不可解密的测试扩展，不是 ECHConfig，也不是有效 ECH 加密；不抓取第三方密文。两种实现均验证每次 TLS 私钥 / 公钥、ClientHello random、Session ID 保持新鲜。固定模板只在隔离 bundle 插件中替换，不修改 lib/ech-probe/internal/tls.js。兼容性仅证明此固定 OpenSSL 成功夹具，不代表任意公网服务端。

本轮一次 Worker HTTP 请求包含多次操作，包装开销被摊销；之前完整调用基线是每握手一次独立请求。两轮数字不能直接作性能改善比较。阶段、函数和完整探测不是可加分区；没有机械扣除空循环。

## Cache API 落实与验证

复用现有 superdoh-ech-probe-v1 命名缓存，唯一业务逻辑改动是省略 cacheTtl 时的默认值由 0 变为 60。现有键继续隔离目标地址 / 端口、SNI、ALPN、认证策略、完整信任根、实际预算与 TTL。只写入完整成功的配置，读回重新验证；过期只重新获取，不用旧值掩盖失败。缓存可被平台清理，只在数据中心本地生效，不保证全球命中。

公开 DoH + 本地 ECH OpenSSL 回归已验证：默认命中不新增服务端 Finished；错误 SNI / 信任根不借用认证缓存；关闭认证策略隔离；显式 0 连续两次真实握手；目标端口隔离；短 TTL 命中、到期更新；停止服务端后的到期更新失败返回 SERVFAIL，重复请求仍走 miss / expired 而非缓存失败或返回旧值。

新默认缓存回归在改代码前确实失败（omitted cacheTtl must enable the Cache API hit path），改后通过。普通探测回归也增加默认 Cache API miss 断言；CPU / profile 诊断显式 cacheTtl:0，避免缓存隐藏真实探测成本。

## 最终验证

- 隔离 WSL 当前工作树 npm test：类型检查与 488 项回归通过，0 失败 / 0 skip。
- 独立库 OpenSSL：4 项通过，3 条客户端 Finished；包含身份 / 信任根负例。
- 扩展公开 DoH 缓存互操作：1 项通过，覆盖上述全部缓存子场景。
- Windows 探测回归：5 项通过，包含最后新增的普通套件默认缓存断言；该断言晚于 WSL 全量快照，未混称已经包含在该快照中。
- 首轮诊断曾有重复 dispose / 已退出子进程清理问题，修正后以上最终运行退出 0；不把失败运行标成成功。
- 未部署、未提交 / 推送、无新公网 ECH 请求，不能宣称线上 Free 冷请求 CPU 已达标。

## 证据与复现

- [完整 A/B 批次](results/2026-10-24/ech-placeholder-ab.json)
- [A/B 汇总](results/2026-10-24/ech-placeholder-summary.json)
- [缓存变更与回归记录](results/2026-10-24/ech-cache-default.json)
- 本地 A/B 生成器：.acceptance/ech-cpu-20261024/placeholder-body.txt、make-profile.mjs、linux-clock.mjs；执行临时目录 superdoh-closeout/run-ech-placeholder-ab.sh。依赖本机此前构建的 ECH OpenSSL 和锁文件匹配 Linux 依赖，不是新增的 clean-checkout 测试入口。
- 缓存回归可复用仓库入口：ECH_PROBE_OPENSSL=<支持 ECH 的 OpenSSL> npm run test:ech-interop；标准回归 npm test。
- Cache API 语义参考：https://developers.cloudflare.com/workers/runtime-apis/cache/ 、https://developers.cloudflare.com/workers/reference/how-the-cache-works/ 。
