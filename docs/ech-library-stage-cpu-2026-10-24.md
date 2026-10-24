# ECH 库全阶段 CPU 补测（2026-10-24）

本次补齐先前流程图中尚未单测的成功路径阶段。**没有改生产实现、没有部署、没有新公网请求。** 这不是所有协议分支 / 算法 / 公网矩阵的测试。

## 无埋点完整调用

| 模式 | 进程 CPU 均值 ms / 次 | 样本数 |
| --- | ---: | ---: |
| 关闭认证 | 2.887 | 80 |
| 自定义 CA | 5.240 | 80 |
| 测试默认库 | 4.856 | 80 |

使用 Linux clock_getcpuclockid(workerd PID) / clock_gettime_ns，独立 Python 辅助进程读取。包含所有 workerd 线程、runtime / GC 和外层 HTTP 包装；不把纯 I/O 等待当 CPU，不等于线上平台配额 CPU。时钟报告分辨率 1 ns，不代表纳秒准确度。测试默认库是完整固定根索引加本地夹具根的隔离 bundle，没有修改生产根库。

## 观测开销验证

先同时打开所有阶段埋点：318 次诊断握手全部成功，321 条客户端 Finished。每模式 80 次无埋点计时、20 次全埋点计时，两套 runtime 各预热 9 次。全埋点完整调用均值为 19.598 / 24.845 / 25.143 ms，而该轮无埋点基线为 2.762 / 5.518 / 4.911 ms。空埋点平均 0.271 ms。所有 exclusive 纳秒严格分割同次 total-probe inclusive，但这只证明埋点账目一致，不证明自然成本。

因此增加单阶段轮：每次只启用一个阶段，其余阶段不发 marker RPC；每个模式 / 阶段各测 10 次，正反序各 5 次。共 790 次阶段计时握手、240 次无埋点计时握手、18 次预热 = **1,048 次诊断握手全部成功**；服务端收到 **1,051 条客户端 Finished**（另 3 条来自原互操作成功用例）。每次断言只出现一个选中阶段、握手与 ECH 配置成功、认证状态符合策略；workerd PID 稳定、时钟 helper 无错误。

单阶段轮空埋点平均 0.284 ms，40 次范围 0.190–0.675 ms。单阶段轮全调用平均为 3.824 / 5.647 / 5.245 ms（各选中阶段混合，仅用于观察开销诊断）。

**单阶段模式仍不能给出无扰动精确拆分。** 低成本步骤与 marker 开销同量级；独立样本的 JIT / GC / 调度不同，父项甚至可小于子项。解密 / 加密等重复步骤含多份 marker。不能统一减去空埋点后宣称精确，不能相加或相减各行。下表是带埋点 inclusive 原始均值，不是业务净成本。

## 全阶段结果

单位 ms，10 次均值 / 阶段 / 模式；父项含子步骤，不能重复累加。

| 阶段（含埋点成本） | 关闭认证 | 自定义 CA | 测试默认库 |
| --- | ---: | ---: | ---: |
| 完整 probe 范围（不含外层 HTTP 包装） | 2.561 | 4.656 | 5.068 |
| 配置、限额与超时设置 | 0.340 | 0.335 | 0.313 |
| CA 准备（仅认证模式） | 结构性跳过 | 0.713 | 0.334 |
| 生成 ClientHello 与临时密钥 | 0.433 | 0.425 | 0.394 |
| 打开 TCP 连接 | 0.554 | 0.476 | 0.490 |
| 写出 ClientHello | 0.334 | 0.403 | 0.313 |
| 初始化 TLS 解析器 | 0.302 | 0.260 | 0.365 |
| 读取网络数据 | 0.354 | 0.294 | 0.311 |
| 处理服务端记录（含 TLS 子步骤） | 1.606 | 3.217 | 2.653 |
| 处理 ServerHello（含密钥派生） | 0.658 | 0.842 | 0.444 |
| 握手密钥派生 | 0.435 | 0.440 | 0.679 |
| 服务端记录解密（每握手 5 次合计） | 1.683 | 1.778 | 1.429 |
| 解析 EncryptedExtensions / ECH 配置 | 0.491 | 0.284 | 0.284 |
| 解析 CertificateRequest | 0.416 | 0.243 | 0.510 |
| 处理 Certificate（含可选链校验） | 0.290 | 1.859 | 1.604 |
| 证书链、有效期、主机名校验 | 结构性跳过 | 2.032 | 1.858 |
| 处理 CertificateVerify（含验签函数） | 1.238 | 1.052 | 1.046 |
| verifyCertificateVerify 函数 | 1.061 | 1.278 | 1.164 |
| 处理服务端 Finished（含应用密钥派生） | 0.592 | 0.858 | 0.966 |
| 验证服务端 Finished 证明 | 0.351 | 0.368 | 0.489 |
| 派生应用流量密钥 | 0.428 | 0.934 | 0.566 |
| 生成客户端记录（空证书 / Finished / 告警） | 0.400 | 0.386 | 0.586 |
| 生成空客户端证书（含记录加密） | 0.570 | 0.473 | 0.427 |
| 计算客户端 Finished 证明 | 0.598 | 0.368 | 0.522 |
| 客户端记录加密（每握手 3 次合计） | 1.302 | 1.119 | 1.373 |
| 写出客户端加密记录 | 0.642 | 0.420 | 0.687 |
| 关闭连接、清除状态与密钥 | 0.470 | 0.551 | 0.616 |

## 证书内部：无阶段 RPC 的函数批量微基准

每项 4 × 500 = 2,000 次操作，正反顺序交替；548 B ECDSA P-256 测试证书。X.509 构建、canonical、算法一致性、SPKI / 签名格式的输入图在计时区间外准备，但准备造成的 GC 仍可能延后进入计时。空循环对照不做机械扣减。

| 操作 | CPU 均值 ms / 操作 | 4 个批次均值范围 ms |
| --- | ---: | ---: |
| 空循环 / 请求摊销对照 | 0.002 | 0.002–0.003 |
| 复制输入 + ASN.1 fromBER | 0.099 | 0.085–0.123 |
| X.509 对象构建 | 0.147 | 0.118–0.209 |
| 规范 DER 重编码与逐字节比较 | 0.196 | 0.163–0.231 |
| 签名算法标识 / 参数一致性 | 0.014 | 0.011–0.017 |
| SPKI 提取 / 曲线检查 / 签名转换 | 0.026 | 0.017–0.039 |
| 完整 parseDer | 0.354 | 0.336–0.379 |
| 私有跳过 canonical 的诊断变体¹ | 0.197 | 0.191–0.206 |
| 完整 verifyCertificateVerify | 0.450 | 0.404–0.576 |
| 导入 ECDSA 公钥 | 0.015 | 0.007–0.037 |
| ECDSA 验签（已导入公钥） | 0.039 | 0.037–0.040 |

独立微基准不能相加成完整 parseDer 或 CertificateVerify：准备方式、JIT、GC 和分配生命周期不同。canonical 直接微基准 0.196 ms，与完整解析减去私有跳过检查变体的差值 0.157 ms，是不同口径，不能互相替换。¹ 跳过 canonical 的变体仅成本隔离，未用于握手或生产，不是建议删除校验。

## 定位结论

- 完整证书解析 0.354 ms；CertificateVerify 整体 0.450 ms；已导入公钥后的纯 ECDSA 验签 0.039 ms。结合此前 JS 栈采样，ASN.1 / X.509 对象构建和 DER 重编码仍是优先调查方向，不能把全部成本归因于 ECDSA 运算。
- 认证路径 validateCertificateChain 和 verifyCertificateVerify 会重复解析叶证书，见 lib/ech-probe/internal/certificate.js:233、:317；canonical guard 在 :51–52。复用值得调查，但此前隔离原型收益不稳定，本次不合入任何性能改动。
- 成功夹具覆盖 CertificateRequest / 空客户端证书及 ech_required 告警；verifyCertificate=false 仍验证 CertificateVerify 和 Finished。结构性不走的 CA / 链校验显示跳过，不虚报零。
- 无扰动精确阶段拆分、线上 profiling、Free 配额重新验收及完整公网矩阵仍未完成。本轮没有重新运行全仓 488 测试；此前运行时升级回归不能充作本轮阶段测试。

## 证据与复现材料

- [汇总数据](results/2026-10-24/ech-library-stage-summary.json)
- [全埋点原始行](results/2026-10-24/ech-library-all-phase-cpu.json)
- [单阶段原始行](results/2026-10-24/ech-library-single-phase-cpu.json)
- [微基准原始批次](results/2026-10-24/ech-library-certificate-micro-cpu.json)
- 新离线图：.acceptance/ech-cpu-20261024/ech-cpu-stages.html、.svg、.png。历史图和证据没有覆盖。
- 生成器在忽略目录 .acceptance/ech-cpu-20261024/：phase-instrument.mjs、phase-body.txt、make-single-phase.mjs、make-full-micro.mjs、make-profile.mjs、summarize-stages.mjs、render-stages.mjs；未进入生产实现、未提交。
- 实际执行：node make-single-phase.mjs；经 WSL bash 运行本机临时目录 superdoh-closeout/run-ech-library-single-phase.sh，在新建 /tmp 隔离副本中运行生成的 lib/ech-probe/test/cpu-profile-local.mjs，ECH_PROBE_OPENSSL 指向此前编译的 ECH OpenSSL。micro-full 使用 run-ech-library-micro-full.sh。依赖本机夹具和安装目录，**不是 clean checkout 即可执行的新测试入口**。
- 日志在本机临时目录 superdoh-closeout/：ech-library-single-phase-20261024.log、ech-library-phases-20261024-final.log、ech-library-micro-full-20261024.log；三次最终运行均退出 0。
