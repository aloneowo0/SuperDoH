# SuperDoH-RS 文件地图

> 逐文件职责说明(26 个源文件,约 9600 行)。配套:需求 `REQUIREMENTS.md`、裁决记录 `01-requirements.md`、代码规范 `00-coding-standards.md`。

## 依赖关系总览

```
lib.rs → http/* → policy::process_query → policy/* → algo/* + dns/*
                                              ↓              ↓
                                    worker fetch 实现    纯 Rust 协议库(无 worker)
```

**核心不变量**:
- `dns/` 和 `algo/` 不依赖 worker 运行时(宿主 `cargo test` 直接跑)
- `policy/` 和 `http/` 是 worker 侧
- 业务词(CF/Meta/ECH/黑名单)只出现在 `policy/`,不进 `algo/`

---

## 入口与配置

| 文件 | 行数 | 职责 |
|---|---|---|
| `src/lib.rs` | ~60 | **Worker 入口**。`#[event(fetch)]` + Router:注册 `/`、`/en`、`/health`、`/config.json`、静态资源、`/dns-query`、兜底路由(伪装 fallback)。ENTRANCE 前缀剥离也在这 |
| `src/config.rs` | ~700 | **构建生成物**(gitignored)。全部运行时常量:UPSTREAMS、FAST_TIMEOUT_MS=200、MIX_TIMEOUT_MS=200、TTL、ECS 前缀、GEOIP_* 八类 CIDR、REGION_CONFIG(remap/优选域名/ECH)、META_ECH_MAP、前端死参 |
| `scripts/build-config.cjs` | ~660 | **构建脚本**(Node)。读 superdoh.config.js → 抓 GeoIP 8 类 + Cealing-Host → 生成 config.rs。configured 0/1 双模式,下载带 HTTPS/大小校验 |
| `scripts/build-worker.cjs` | ~190 | **统一 Worker 构建入口**。缺失时引导安装 Rust 1.88.0、rustfmt、wasm32 target、worker-build 0.8.5，再生成 config.rs 并编译 `build/worker/*`；部署阶段不重复构建 |

## dns/ — 协议层(纯 Rust,无 worker 依赖)

通用协议结构优先复用成熟 crate:`hickory-proto` 负责标准 DNS typed RDATA / HTTPS/SVCB/ECH / ECS 编解码,`ipnet` 负责 CIDR;本项目只保留 SuperDoH 特有的响应分类、修改安全边界和策略语义,避免重复实现通用协议。

| 文件 | 行数 | 职责 |
|---|---|---|
| `dns/proto.rs` | ~50 | **Hickory typed DNS 适配层**。通用 Message/RData 解码、A/AAAA 提取、HTTPS ECHConfigList 提取;不承载业务策略 |
| `dns/wire.rs` | ~800 | **响应安全边界/兼容层**。保留需要精确控制的报文边界、压缩名展开、构包和修改保真逻辑;通用 typed RDATA 逐步交给 Hickory |
| `dns/edns.rs` | ~500 | **EDNS/ECS 策略层**。OPT 状态保持、是否注入/移除 ECS;ECS 网络/前缀与 wire 编解码交给 `ipnet` + Hickory `ClientSubnet` |
| `dns/classify.rs` | ~150 | **响应三态分类**。positive(需目标 QTYPE RRset 或完整 CNAME 链)/ NXDOMAIN / NODATA / referral / invalid;CIDR 黑名单过滤 |
| `dns/svcb.rs` | ~100 | **Hickory SVCB/HTTPS 薄适配层**。AliasMode/ServiceMode、ECHConfigList、参数排序和 wire 序列化交给 Hickory |
| `dns/mod.rs` | ~30 | 模块导出 |

## algo/ — 算法层(纯逻辑,零业务知识)

| 文件 | 行数 | 职责 |
|---|---|---|
| `algo/fast.rs` | ~130 | **fast 竞速**。并发查上游,首个语义完整 positive 胜出;negative 暂存兜底;accept 回调(业务验收由调用方传);deadline 取消 |
| `algo/mix.rs` | ~100 | **mix 收集**。并发查询→收集正答案 IP→合并去重→全量返回(无上限)。不知道 Meta/CF/黑名单 |
| `algo/mod.rs` | ~20 | trait 定义(Upstream 可取消抽象)+ 导出 |

## policy/ — 策略层(编排 + 业务决策,worker 侧)

| 文件 | 行数 | 职责 |
|---|---|---|
| `policy/mod.rs` | ~300 | **编排核心**。`process_query` 入口:canary → fast 主查询 → 三态门控(Q15 不复活)→ Domain/IP 归属 → 分派 → ECH → 构包;日志/上游追踪汇总 |
| `policy/classify.rs` | ~230 | **归属判定**。Domain 规则(remap 列表/Google 代理模式/Meta 后缀)+ IP 归属(GeoIP CIDR,混合 owner 返回 None)+ 黑名单 |
| `policy/upstream.rs` | ~330 | **worker 侧上游实现**。实现 algo 的 trait:Fetch POST、按 ecs:true 注入 ECS、AbortOnDrop 取消、流式 65535 限长、6 连接并发调度 |
| `policy/prefer.rs` | ~120 | **优选替换**(CF/CFT/Vercel)。fast 解析优选域名 + expectedOwner 验收 → 替换原始 IP(TTL 60) |
| `policy/meta.rs` | ~180 | **Meta 增强**。mix 二次解析 + 静态路由表(EXACT 21 条 + WILDCARD 8 条)+ 去重 + owner/黑名单过滤 → IP 加入(TTL 300);无候选 → SERVFAIL 不伪造 |
| `policy/google.rs` | ~80 | **Google 合并**。Cealing-Host 代理 IP 优先 + 真实 IP 兜底(去重,Happy Eyeballs best-effort) |
| `policy/ech.rs` | ~250 | **ECH 注入**。CF 动态(cloudflare-ech.com 用 fast 获取 + 10min 缓存 + 1h stale)、Meta 按 META_ECH_MAP 查表;调用 dns::svcb 安全修改(仅 ServiceMode、不生成非法 RR) |
| `policy/remap.rs` | ~30 | **remap AAAA 屏蔽**。命中 remap 的 AAAA 语义必须 NODATA(更早短路) |
| `policy/response.rs` | ~200 | **响应构建**。IP 替换(精确删被改 RRset 的 RRSIG + 清 AD)、合成响应按客户端 OPT/DO/CD 重建、65535 完整 RR 边界裁剪 + TC |
| `policy/logger.rs` | ~130 | **结构化 JSON 日志**。requestId、事件、分级;qname 默认脱敏(debug 才完整);失败类型/上游记录 |

## http/ — 端点层(HTTP 边界,worker 侧)

| 文件 | 行数 | 职责 |
|---|---|---|
| `http/mod.rs` | ~560 | **路由辅助 + 伪装 + 运行时配置**。ENTRANCE 前缀隔离、PROXY 反代(剥敏感头/hop-by-hop/Location 重写/URL 校验)、CUSTOM_* 环境变量合并运行时上游 |
| `http/doh.rs` | ~300 | **/dns-query**。GET(dns= base64url 或 name&type)/ POST 解析、405/415/413/400、流式 65535 限长、canary NXDOMAIN、调用 policy::process_query、dns-json 转换、统一响应头(不暴露内部) |
| `http/health.rs` | ~40 | **/health**。configured/上游/超时/地区 JSON |
| `http/config_json.rs` | ~130 | **/config.json**。前端向导契约 16 字段(含死参),URL 脱敏 |
| `http/home.rs` | ~110 | **首页**。include_str! 内嵌 frontend/ 五件套,占位符注入(`__HOST__` 等) |

## 一次请求的完整路径

```
HTTP 请求 → http/doh.rs(校验 + canary)
  → policy::process_query(编排)
    → fast 竞速(200ms,三态验证)→ 无地区配置直接返回
    → Domain 归属(remap/Google/Meta)→ 未命中 → IP 归属(GeoIP)
    → 分派:CF/CFT/Vercel 优选替换(TTL 60)| Meta mix+静态路由(TTL 300)| Google 合并
    → 尝试注入 ECH(CF 动态 / Meta 映射)
    → 构建包(remap 标记 → AAAA NODATA;65535 裁剪)
  → http/doh.rs(统一响应头,dns-json 转换)
```
