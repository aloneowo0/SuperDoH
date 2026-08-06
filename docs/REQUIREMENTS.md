# SuperDoH-RS 需求文档(正式版)

> 版本:v0.1(2026-08-03,由需求草稿整理,全部决策已闭环)
> 前置资料:`docs/README.md`、`docs/DOCUMENTATION.md`、`docs/KNOWN_ISSUES.md`、`docs/META_ECH_HANDOFF.md`(原版资料副本)
> 决策记录:`docs/01-requirements.md`(含 Q1-Q28 逐条裁决历史)

---

## 1. 项目概述与技术栈

将原版 JS 版 SuperDoH(Cloudflare Workers DNS-over-HTTPS 代理)重写为 **Rust 为主** 的 SuperDoH-RS:

| 层 | 语言 | 说明 |
|---|---|---|
| Worker 本体(核心逻辑) | **Rust**(workers-rs / worker crate) | 严格按代码规范(`docs/00-coding-standards.md`) |
| 构建脚本 / 配置生成 | JS(Node) | 允许,宽松规范 |
| 前端 / 测试 | JS | 前端像素级复刻,零修改 |

## 2. 设计分层原则

1. **算法层**:`fast` / `mix` 是算法,不承载 CDN、Meta、ECH、过滤等业务策略
2. **策略层**:Domain/IP 归属、优选、IP 加入、ECH、remap AAAA 属于策略
3. **协议/实现层**:DNSSEC、EDNS、RCODE、wire format、TTL 边界、连接取消属协议/实现
4. 不因原版 JS 存在某个策略就默认新版必须继承
5. 协议正确性和 Rust 实现细节自行采用正确实现,不再逐项确认
6. 只有改变实际产品行为或已确认优化策略时,才提出需求问题

## 3. 全局原则:模仿正常 DNS 分发服务

本项目涉及对 DNS 结果的修改操作(替换 IP / 注入 ECH / 移除 AAAA 等),整个服务必须表现得像一个**正常的、标准的 DNS 分发服务**——协议行为、响应格式、错误语义均符合标准 DNS/DoH 规范,不暴露代理/优化痕迹:

- DNS wire format 正确性(RFC 8484),响应结构规范
- 标准状态码与 RCODE 语义(NODATA / NXDOMAIN / SERVFAIL + EDE)
- **生产 DoH 响应不通过公开响应头暴露内部优化路径**(request id、耗时、上游等诊断信息只进结构化日志;正常响应保持统一外部行为)
- TTL 合理性、EDNS/DO 位处理符合正常解析器行为

---

## 4. 统一编排流程

### 4.1 流程图

```mermaid
flowchart TD
    A[请求] --> B[校验 / fast 竞速]
    B --> C{Domain 归属}

    C -->|命中| D{Domain 类型}
    D -->|Google| E[代理 IP + 真实 IP 合并]
    D -->|CF / X / Pixiv| F[CF 优选<br/>标记: 来自 Domain 命中]
    D -->|Meta| I[mix 二次解析 → IP 加入]

    C -->|未命中| G{IP 归属}

    G -->|CF| H[CF 优选]
    G -->|Meta| I
    G -->|CFT| J[CFT 优选]
    G -->|Vercel| K[Vercel 优选]

    F --> H
    H --> L[增强 / 合成 HTTPS<br/>尝试注入 ECH]
    I --> L

    L --> N{带有 Domain 命中标记?}
    N -->|是| O[remap AAAA 屏蔽]
    N -->|否| Q[构建包]
    O --> Q

    E --> Q
    J --> Q
    K --> Q

    Q --> R[输出]
```

### 4.2 统一编排语义(Q11 裁决)

"所有 QTYPE 一样的流程"指**统一编排流程**,不代表把同一种 RDATA 修改方式硬套给所有类型。按 QTYPE 正确处理 wire format:

- **A**:处理 A 记录
- **AAAA**:处理 AAAA 记录
- **HTTPS(65)**:处理 HTTPS RR 内可修改的字段(hints / ECH)
- **其他 QTYPE**:仍经过统一流程,没有适用优化动作时自然 **no-op**

不要因类型不同拆成完全独立的业务流程。

### 4.3 流程要点

1. **Domain 归属优先于 IP 归属**:域名命中规则(remap 列表 / Google 代理规则 / Meta 域名规则)时不再做 IP 分类
2. **Domain 命中的 CF/X/Pixiv**(remap)→ CF 优选 + 打"来自 Domain 命中"标记
3. **Domain 未命中** → 按响应 IP 归属分类:CF → CF 优选;Meta → mix 二次解析后 IP 加入;CFT → 优选;Vercel → Vercel 优选
4. **HTTPS 增强 / 合成 + ECH**:已有兼容 ServiceMode HTTPS(65) RR 时安全修改并注入;没有兼容 ServiceMode RR(含 HTTPS NODATA)时,若 owner 可被明确证明且有可靠 ECH 来源,允许合成完整合法的 ServiceMode HTTPS RR;NXDOMAIN、owner 不明确或 ECH 不可用时保持原结果(Q2/Q15/Q19/Q21)
5. **remap AAAA 屏蔽**:带有"来自 Domain 命中"标记的 AAAA,最终语义必须 NODATA(Q14)
6. Google → 代理 IP + 真实 IP 合并,不经过 ECH
7. 所有路径汇聚 → 构建包 → 输出

### 4.4 无地区配置路径(Q9)

configured:0 / regions 为空 / 非 CN 地区:fast 竞速后**直接返回**,不做归属/优选/ECH 优化。

---

## 5. 算法层

### 5.1 fast(竞速)

- **语义**:并发查询多个上游,**先回有效者胜**(原 AUTO 1 竞速重新设计)
- **硬超时**:200ms(可配置;Q5)
- **三态验证**(Q12):区分 `positive / negative / invalid`
  - 首个语义完整 **positive** 立即胜出
  - 标准 **negative** 可暂存,最终无 positive 时返回最早有效 negative
  - 这是通用响应有效性处理,不是 ECS 保护窗
- **通用验收回调**(Q16):fast 提供 `accept/validator` 回调接口——算法层不硬编码 CF/Meta/ECH 等业务知识,具体验收条件由调用方(策略层)提供
- **调用点**:
  - 主查询(第 4 节流程入口)
  - 优选域名解析(CF/CFT/Vercel 优选节点)
  - CF ECH 获取(cloudflare-ech.com HTTPS RR 查询)
- **ECS/EDNS**:不区分优先级;仅 `ecs:true` 上游携带 ECS(Q23 按 RFC 正确实现)

### 5.2 mix(收集)

- **语义**:向多个 DNS 厂商(上游)发送请求,收集所有返回结果并**合并去重**,获取尽可能多的 IP
- **纯算法边界**(Q18):mix 只做 **并发查询 → 收集 → 合并 → 去重**;不知道 Meta、CF、blockedCidrs,不知道调用前后流程。family、blockedCidrs、owner 等业务检查由**调用 mix 的策略层负责,绝不能写进 mix 算法本身**
- **硬超时**:200ms(与 fast 一致,可配置)
- **无固定 IP 数量上限**(Q25):算法内部不设上限;最终 DNS 构包保证合法 wire size(65535),消息大小边界内安全裁剪属构包实现问题
- **调用点**:Meta IP 归属确认后的二次解析(策略层,见 6.4)
- **查询类型**:跟随原请求类型(A 查 A、AAAA 查 AAAA;A/AAAA 对等支持,Q20)

### 5.3 连接管理(实现要求,Q24)

winner/deadline 后及时取消 loser(显式 AbortSignal),遵守 Worker 并发连接限制。

---

## 6. 策略层

### 6.1 Domain 归属

| 规则 | 对应原版 | 命中后 |
|---|---|---|
| remap 列表(CF/X/Pixiv 等) | `isCFDomain` | CF 优选 + 打"来自 Domain 命中"标记 |
| Google 代理规则(Cealing-Host) | `matchGoogleProxy` | 代理 IP + 真实 IP 合并 |
| Meta 域名列表 | `isMetaDomain` | Meta 策略(进 6.4) |

Domain 分类补齐 Meta(Q21):Domain 命中 Meta 时进入 Meta 策略,不应因为 HTTPS 没有普通 A/AAAA Answer 就无法识别 Meta。

### 6.2 IP 归属(GeoIP)

按响应 IP 归属分类(CF / Meta / CFT / Vercel / 其他)。**混合 owner 或无法明确 owner 时,默认不做基于 IP owner 的整体替换**(Q17);Domain 明确命中的强制规则不受此限制。

HTTPS(65) 响应没有普通 A/AAAA Answer 时,优先使用其 ServiceMode `ipv4hint` / `ipv6hint` 作为响应内 IP 归属依据(Q11/Q19)。若没有兼容 ServiceMode/hints 且 Domain 规则也无法直接确定 owner,为 HTTPS 合成允许策略层执行**专用 side A/AAAA owner probe**:仅用于证明 owner / 获取地址事实,不得递归触发 HTTPS 合成;只有 A/AAAA 证据得到单一明确 owner 时才继续,混合/未知/失败则不合成(Q21 修订)。

### 6.3 优选替换(CF / CFT / Vercel)

- 用 **fast** 解析优选域名(`preferredCf` / `preferredCft` / `preferredVrc`)
- **替换语义**:优选解析得到的 IP **替换**原先解析结果中的 IP(不是追加/合并);TTL 60(Q27)
- 验收条件(expectedOwner 等)由调用方通过 fast 的 accept 回调提供(Q16)

### 6.4 Meta(mix 二次解析)

- 流程:IP 归属判定为 Meta(或 Domain 命中 Meta)→ **mix 二次解析** → IP 加入
- mix 结果与 **Meta 静态路由表**(meta-route.js)合并(Q8;合并顺序/去重为实现细节)
- **Meta AAAA 正常增强**(Q20):A → mix A 收集 IPv4;AAAA → mix AAAA 收集 IPv6;不沿用原版"Meta AAAA NODATA"限制
- TTL:300(Q27)
- 业务过滤(如 owner / blockedCidrs 检查)由策略层在 IP 加入前执行(Q18)

### 6.5 Google(代理 + fallback)

- **合并 + Happy Eyeballs**:Cealing-Host 代理 IP 优先 + 真实 IP 兜底合并(Q4)
- 代理 IP 排前只作为 **best-effort**,不承诺客户端一定按 RR wire 顺序连接(Q26)

### 6.6 HTTPS 增强 / 合成与 ECH

| 来源 | 说明 |
|---|---|
| CF 动态 | `cloudflare-ech.com` HTTPS RR 查询(用 fast);缓存 10min + 1h stale 兜底(Q10 #9),失效策略可配置(Q22) |
| Meta 静态 | 独立策略配置;ECHConfig 与域名的映射做成**可配置/可维护数据,不写死进通用算法**(Q22) |

- **已有 ServiceMode**:按 DNS/SVCB/HTTPS 规范正确处理 AliasMode、ServiceMode、mandatory、hints、ECH;保留兼容参数并安全加入/替换 ECH;无法安全修改时 no-op / 保留原数据(Q19)
- 当地区 A/AAAA 地址策略会改变实际连接目标时,HTTPS ServiceMode 中对应的 `ipv4hint` / `ipv6hint` 必须同步重写或移除,避免客户端绕过优选或 remap AAAA 屏蔽。已有 ServiceMode 的 hints 维护本身**不额外增加 side A/AAAA lookup**;HTTPS 合成所需的专用 owner probe 是 Q21 修订定义的独立步骤(Q19/Q21/Q24)
- **无兼容 ServiceMode / HTTPS NODATA**:不再直接跳过。仅在 `region.ech=true`、owner 明确且存在可靠 ECH 来源时允许合成 HTTPS ServiceMode(Q2 修订)。
- **负响应边界**:NXDOMAIN 永不合成;一般 NODATA 不复活。仅 HTTPS(65) NODATA 可在上述严格条件下转为正 HTTPS RR。若原响应含 SOA/NSEC/NSEC3/RRSIG 等否定证明,合成后删除与新 RRset 矛盾的否定证明/失效签名并清 AD,按客户端 OPT/DO/CD 重建(Q15 修订)。
- **合成 RR 基线**(Q19 修订):`SvcPriority=1`,`TargetName=.`;若存在 CNAME/Alias 链,在最终协议允许的 owner 上合成,不得与 CNAME 同 owner 冲突。
- **SvcParams 最小可信原则**:必须包含经 owner 策略验证的 `ech`;没有可信来源时不伪造 `alpn`、`port`、`no-default-alpn` 或未知参数。无 `alpn` 时使用 HTTPS/SVCB 标准默认 ALPN 语义。`mandatory` 只在实际需要时生成并保持自洽。
- **合成 RR 默认不写 IP hints**:`ipv4hint` / `ipv6hint` 由 A/AAAA 地区优化路径替代,避免绕过 preferred/remap AAAA 策略。未来若写 hints,必须来自同一轮已确认的优化地址并符合地址族策略。
- **fail-open**:owner 不明确、ECH 获取/映射失败、ServiceMode 无法自洽构造时不合成,返回原始 DNS 结果。

### 6.7 remap AAAA 屏蔽(Q14)

remap Domain 命中的 AAAA **最终语义必须 NODATA**。如果"构建前删除 AAAA"会因 CNAME 链产生绕过,实现允许改为更早短路。保持产品语义,不强制代码执行位置。

### 6.8 Chrome DoH canary

`use-application-dns.net` A/AAAA 查询返回 NXDOMAIN(Q8 保留)。

---

## 7. 协议层要求

### 7.1 DNSSEC(Q13)

- **DNSSEC 必须协议兼容**,不能因客户端请求 DNSSEC 就直接绕过整个优化流程
- 正确支持 DO/CD/AD/OPT、DNSKEY、DS、RRSIG、NSEC/NSEC3 等 DNSSEC 数据和状态语义
- SuperDoH 是 **DNSSEC-aware / DNSSEC-preserving proxy**,不是递归 DNSSEC 验证器;密码学验证由可信递归上游负责
- 未修改的数据正常保留上游 DNSSEC 数据及 AD 状态
- 被修改/替换/合成的 RRset:删除对应无效 RRSIG,清除不能再成立的 AD 状态,**不伪造 Secure**
- 不要求也不允许在没有目标 Zone 私钥的情况下为修改后的第三方 RRset 重新签名

### 7.2 EDNS / ECS(Q23)

按 RFC 正确实现:避免重复 ECS、不扩大客户端主动提供的前缀、正确处理 /0。请求自带 ECS 时不重复注入。

### 7.3 RCODE 与负响应(Q12 / Q15)

- fast 区分 positive / negative / invalid;负响应可暂存兜底
- **NXDOMAIN 永不被优化策略复活**。
- A/AAAA/其他 QTYPE 的 NODATA 保持 NODATA。
- **唯一例外是 HTTPS(65) NODATA 合成**:名称存在、owner 有明确证据、地区 ECH 策略启用且对应 ECH 来源可用时,可按 6.6 合成正 HTTPS ServiceMode RR;否则保持原负响应。
- HTTPS NODATA 转正后不得保留与新 HTTPS RRset 冲突的 SOA/NSEC/NSEC3/RRSIG 否定证明;清 AD 并按客户端 EDNS/DNSSEC 状态重建。

### 7.4 TTL(Q27)

已确认地址策略 TTL:**mix 300,preferred 60**(不因 review 改变)。实现层可在不改变策略上限的前提下,规范处理明显超出源数据有效期的异常缓存行为。

HTTPS 合成新增 TTL 规则:

- CF 合成 HTTPS RR 的 TTL 上限为 **60s**,并且不得超过当前所用动态 ECHConfig 的剩余有效期;使用 stale ECH 时也不得超过 stale 截止时间。
- Meta 合成 HTTPS RR 的 TTL 上限为 **300s**,同时受对应静态 ECH 映射自身的维护/失效策略约束。
- 若无法得到可信的 ECH 有效期边界,使用更短 TTL 而不是延长缓存;不得让合成 HTTPS RR 比其关键 ECH/地址依据活得更久。

### 7.5 响应构建(Q25 / Q28)

- 最终 DNS 构包保证合法 wire size(65535);超限按完整 RR 边界裁剪并设 TC 或回退
- 生产响应不暴露内部优化路径(响应头统一外部行为)

---

## 8. 配置与构建

### 8.1 配置源(R2)

- 仓库根目录 `superdoh.config.js`(JS 格式 `export default`,唯一人类可编辑源)
- 构建流程:`npm run build`→ 必要时准备固定 Rust 1.88.0/rustfmt/wasm32/worker-build 0.8.5 → 读取配置并生成 **Rust 版 config**(对应原版 `src/config.js` → `src/config.rs`)→ 编译 `build/worker/*`;Deploy command 只上传产物,不重复构建
- 构建时远程抓取:GeoIP CIDR(8 类)、Cealing-Host Google 代理列表
- `configured: 0/1` 双模式语义保留(0=首次配置模式,1=正式运行)

### 8.2 参数表(Q10 裁决)

| # | 参数 | 结论 |
|---|---|---|
| 1 | fast 并发上游数 | **与 #2 合并**为 `upstreamConcurrency`,滑动窗口默认 2 |
| 2 | mix 并发上游数 | 同上,fast/mix 共用;全部启用上游仍为候选,完成一个后补充下一个 |
| 3 | mix IP 上限 | **无限制**(去重全保留;metaMaxIps 废弃) |
| 4 | mix 结果 TTL | 300 |
| 5 | 优选替换 TTL | 60 |
| 6 | IP 黑名单 blockedCidrs | 保留 |
| 7 | ECS 前缀 | 24 / 56 |
| 8 | 超时后返回 | SERVFAIL + EDE 22 |
| 9 | CF ECH 缓存 | 10min + 1h stale |
| 10 | 日志 | logLevel 结构化 JSON |
| 11 | configured:0 默认上游 | google + cloudflare_Public |
| 12 | mix 查询类型 | 跟随原请求类型 |

**全局原则:所有参数均可配置(可调),不硬编码。**

### 8.3 新版配置契约(Q1,2026-08-05 修订)

- **不兼容旧 JS 配置字段**,不保留无实际作用的死参数。
- 删除:`autoConcurrency`、`ecsProtectMs`、`hardTimeoutMs`、`metaHardTimeoutMs`、`metaCollectWindowMs`、`metaMaxIps`、`preferredTimeoutMs`。
- 新版算法字段:`upstreamConcurrency`、`fastTimeoutMs`、`mixTimeoutMs`、`mixTtl`、`preferredTtl`、`servfailEdeCode`、`cfEchCacheTtlMs`、`cfEchStaleTtlMs`。
- `/config.json` 与配置向导只暴露新版实际生效字段;构建器不接受上述旧字段的别名或旧环境变量。

### 8.4 上游 transport(2026-08-05 新增)

- 预设上游配置格式:`provider: { enabled: true|false, transport: "doh"|"tcp" }`。
- 前端每个支持 TCP 的厂商块同时提供“启用”和“TCP”复选框;TCP 未选中时使用 DoH。
- Cloudflare 与 NextDNS 显示为 DoH-only,不提供 TCP 开关。
- 构建器把每个启用上游编译为统一结构:`name + transport + doh_url + tcp_host + tcp_port + ecs`。
- fast / mix 不区分 DoH/TCP;transport 层完成请求 framing、读取、取消和资源释放。
- TCP DNS 使用 2 字节大端长度前缀,拒绝 0 长度和超过 65535 字节的响应。
- TCP 地址由预设提供,普通用户不需要输入 IP;当前内置主地址见 `docs/01-requirements.md` R4.1。
- `upstreamConcurrency` 是 fast/mix 的**最大同时在飞数**,不得在 transport 构建阶段用 `.take()` 截断候选。默认 2;算法按配置顺序补充后续候选。
- 初始候选顺序与启用集:`google(tcp)`、`cloudflare_Public(doh)`、`quad9(tcp)`;其余预设默认关闭但可在向导中启用。

---

## 9. 前端(R1)

- 原项目 `frontend/` 的页面与样式可复用,但 `config-wizard.js` 按新版 Rust 配置契约维护,**不要求兼容旧字段**
- 构建时打包进 Worker(替代 JS 版 `src/templates.js` 内嵌机制)
- 首页动态注入逻辑保留(`__HOST__`、`__UPSTREAM_LIST__`、`__CONFIGURED_VALUE__` 等占位符替换),在 Rust 侧实现
- 配置向导(config-wizard.js)为纯浏览器端逻辑,输出新版 `superdoh.config.js`

## 10. 端点(Q8)

| 端点 | 保留 | 说明 |
|---|---|---|
| `/dns-query` | ✅ | 唯一 DoH 端点(fast 模式;单上游端点已删除) |
| `/:provider/dns-query` | ❌ | **删除** |
| `/health` | ✅ | 健康检查 |
| `/config.json` | ✅ | 当前生效配置(前端向导契约) |
| 伪装入口(ENTRANCE+PROXY) | ✅ | 反向代理伪装 |
| Chrome canary | ✅ | use-application-dns.net → NXDOMAIN |

---

## 11. 与原版实现对应关系

| 新版组件 | 原版实现 |
|---|---|
| fast 竞速 | `concurrentAll`(去 ECS 保护窗,300ms) |
| mix 收集 | `metaResolve` 收集窗 + `resolvePreferred` 收集语义 |
| Domain 归属 | `isCFDomain`(remap)/ `isMetaDomain` / `matchGoogleProxy` |
| IP 归属 | `classifyResponse` / `detectOwner`(GeoIP CIDR) |
| CF/CFT/Vercel 优选 | `preferredAnswer`(解析优选域名,替换,T TL 60) |
| Meta IP 加入 | `metaResolve`(静态路由 + 收集)→ 新版 mix 二次解析 + 静态路由合并 |
| ECH 注入 | `injectECH`(CF 动态 / Meta 静态) |
| remap AAAA 屏蔽 | 原版入口拦截 NODATA(语义保留,位置自由) |
| canary | 原版 NXDOMAIN |

---

## 12. 待办(实现层,不在需求裁决范围)

- 构建脚本 `build-config`(superdoh.config.js → src/config.rs)实现
- fast/mix 算法实现与 accept 回调接口设计
- DNSSEC / EDNS / ECS / wire format 协议正确性(Rust 实现细节,自行采用正确实现)
- 连接管理(winner abort losers、6 连接限制、subrequest 上限)
- 构包:65535 wire-size 硬限制、TTL 规范化、负响应 SOA 附注
- ECHConfig 与域名映射的可配置数据结构(Meta 静态 ECH)
- 测试:纯逻辑宿主 `#[test]` + wasm 测试 + miniflare E2E

---

*文档状态:正式版 v0.1,需求决策全部闭环。后续变更走"需求问题"流程(仅当改变实际产品行为或已确认优化策略时)。*
