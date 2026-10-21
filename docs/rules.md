# 环境变量规则执行器（JSON-only / #26）

当前实现提供异步 `executeQuery` 和标准 DoH GET/POST。#26 已移除旧 #11 用户条件/动作代码扩展，DNS 行为仅由环境变量 JSON 的声明式条件和基础动作组成；异步网络、原始数据隔离、回滚及脱敏诊断继续保留。`test/worker.js` 只是旧规则测试适配器，生产入口为 `src/worker.js`。

**分阶段迁移**：修订 #7 是目标规格，不是全部已实现声明。旧 #12/#13 的单上游默认补查、上游策略组及采用条件目前仍在；#27 负责移除这些政策、改为显式命名单上游并提供最近动作结果。本票没有新增自动回退、重试、补查或并发。不新增依赖这些旧政策的推荐配置；下文旧上游章节仅说明当前兼容行为。TCP/TLS、缓存、外部来源与 ECH 动作仍待后续票交付。未部署、未做线上免费 CPU 验收，README 的历史版本说明不作为本实现功能清单。

## 公共入口

```js
import { executeQuery, RuleError } from './src/index.js';

try {
  const result = await executeQuery(queryWire, env);
  // result.termination: 'completed' | 'stopped' | 'returned'
  // result.response: Uint8Array | null
  // result.originalQuery: 深度只读原始查询，与输入和当前状态没有可变共享引用
  // result.query: 当前查询快照，包含 rewriteQuery 的成功修改
} catch (error) {
  if (!(error instanceof RuleError)) throw error;
  // error.code, error.message, error.location
}
```

入口返回 `Promise<ExecutionResult>`，调用者必须 `await` 并处理拒绝（T4 将原同步入口迁移为异步）。上游查询动作和配置上游后的无响应收尾可以执行网络 I/O；移除用户函数不改变网络异步契约。输入为 `Uint8Array` DNS 报文和 Workers 环境绑定对象；不读取文件、`process.env` 或请求中的配置。支持标准单问题 QUERY、根域或 ASCII 标签（字母、数字、连字符、下划线）；IDN 使用 punycode。拒绝响应报文、其他 opcode、截断查询、已有 Answer/Authority、非 OPT 的 Additional 和非零 EDNS 版本/扩展 RCODE。合法的 EDNS 0 查询可以处理，但此切片的自定义响应不回显请求的 OPT/ECS。

规则正常结束是 `completed`；`stop` 是 `stopped`；`return` 是 `returned`。三者均经过统一输出收尾。

- `response === null` 唯一表示尚未取得响应；配置 DNS_UPSTREAM 后，规则结束仍无响应会调用一次默认上游。未配置上游时直接 executeQuery 仍可返回 null；正式 HTTP 入口将这类处理失败映射为 SERVFAIL。
- NOERROR 空答案、NXDOMAIN 均是已取得的响应，仍有 wire bytes，不是 `null`。
- `stop` 不要求已有响应；`return` 和 `setTtl` 在无响应时抛 `NO_RESPONSE`。
- 任何必需处理错误直接抛出，不返回部分成功结果；正式 DoH 层负责将执行失败映射成 DNS SERVFAIL，输入错误另行处理。

## 环境配置

每个 `DNS_RULE_*` 变量是独立规则组，接受平台 JSON 对象或 JSON 文本，两者采用同一校验路径。变量名须为 ASCII 字母、数字、下划线，长度不超过 128。变量名用作诊断标识，不要把密钥或 URL 放进变量名。

```json
{
  "order": 10,
  "rules": [
    {
      "when": {
        "all": [
          { "field": "query.name", "op": "suffix", "value": "example.com" },
          { "field": "query.type", "op": "eq", "value": "A" }
        ]
      },
      "actions": [
        {
          "type": "answer",
          "records": [
            { "name": "example.com", "type": "A", "ttl": 60, "rdata": { "A": { "addr": "192.0.2.1" } } }
          ]
        },
        { "type": "setTtl", "ttl": 120 },
        { "type": "return" }
      ]
    }
  ]
}
```

- `order` 必填且为安全整数，允许负数；升序执行。同序号按变量名 ASCII 字典序稳定排序（不依赖枚举顺序或本机 locale）。
- 规则及动作保持数组顺序。`rules` 可以为空；每条规则的 `actions` 必须非空。省略 `when` 表示始终匹配。
- 每条规则进入时只判断一次。后续动作读取当前状态；后续规则重新判断自己的条件。不隐式重跑规则。
- 所有组、规则、动作及条件分支在执行前完整校验，即使在未命中或终止动作之后也不跳过错误配置。
- 未知字段、动作、条件操作符和引用明确报错，不回退文件。无 `DNS_RULE_*` 变量是合法空流水线，返回 `completed` 和 `null`。
- 其他无关环境绑定不作规则解析；配置入口包括 `DNS_RULE_*`、`DNS_LIMITS`、`DNS_UPSTREAM`，HTTP 入口还读取可选 Secret `DNS_PATH_KEY`。在其他名称的变量中放置规则不会启用规则。

### 条件

条件以字段、操作符、值表达，结构全量预检并编译；每次规则进入时只求值一次。`all` / `any` 数组非空，分别 AND / OR；`not` 是布尔取反。执行可短路，校验不短路：未执行分支的未知字段、错误正则或错误参数仍使整个配置失败。内置条件没有网络、文件、DNS 查询、域名列表下载或归属补全等隐式副作用。不接受用户函数；异步联网仅由明确支持的网络动作承担。

```json
{ "all": [
  { "field": "query.name", "op": "suffix", "value": "example.com" },
  { "field": "query.type", "op": "in", "value": ["A", "AAAA"] },
  { "field": "client.asn", "op": "eq", "value": 64512 }
] }
```

#### 字段和标量操作符

| field | 类型 / 含义 |
| --- | --- |
| `query.name` / `original.name` | 域名；当前 / 只读原始查询名 |
| `query.type` / `original.type` | DNS 类型；名称或 0..65535 整数，由库解析 A、AAAA、TYPE65280 等 |
| `response.exists` | 布尔值；无响应 false，已有空答案或 NXDOMAIN 也为 true |
| `response.rcode` | 0..4095 完整 RCODE 整数（含 EDNS 扩展位）；无响应时缺失，不伪造 NOERROR |
| `client.ip` / `edge.ip` | IPv4 / IPv6；客户端与边缘属性互不替代 |
| `client.asn` / `edge.asn` | 0..4294967295 整数 |
| `client.country/region/city/colo`、`edge.country/region/city/colo` | 对应对象的文本属性，长度 1..128；区分大小写，无自动地区代码转换 |

斜线仅为表格缩写，实际字段如 `client.country`、`edge.colo`，不能写成带斜线的字段。

- `eq` / `ne`：严格类型相等 / 不等。域名和 IP 先规范化；不将字符串 ASN 转换成数字。
- `in`：非空数组中的集合成员匹配，各成员均须符合字段类型，受 `maxConditionValues` 限制。配置重复成员不改变结果，但仍计入成员数预算。适用于所有标量字段，包括布尔值。
- `lt` / `lte` / `gt` / `gte`：仅用于 ASN、rcode、TTL 等数值字段，不对 DNS 类型代码或文本作排序比较。
- `exists`：`value` 必须是布尔值，判断该属性是否存在。所有普通比较（包括 `ne`）对缺失属性均为 false；显式 `not` 则取反，因此 `not(eq missing)` 为 true，若不希望这样应先组合 `exists: true`。
- `response.exists` 本身始终是存在的布尔属性：其 `exists: true` 总为 true；检查是否已有响应请用 `eq: true`。
- 任意未知字段、非法作用域、参数或操作符均为 `INVALID_CONFIG`，不是缺失属性，也不是普通未命中。

#### 域名边界

域名操作支持查询名，以及下述集合中的 `item.name` / `item.target`。输入域名规范化为小写，并去掉单个末尾点；根域保留 `.`，IDN 使用 punycode。域名标签沿用入口的 ASCII 范围，不以字符串包含冒充标签后缀。

| op | 语义 |
| --- | --- |
| `exact`（或 `eq`） | 精确匹配 |
| `suffix` | 含自身的标签后缀：example.com 匹配自身及 a.example.com，不匹配 notexample.com |
| `subdomain` | 仅子域：example.com 不匹配自身，匹配 a.example.com 和 a.b.example.com |
| `wildcard` | 全名匹配；`*` 恰好一个完整非空标签，`**` 零个或多个完整标签；不可写 `w*` 等部分标签通配符 |
| `regex` | RE2JS 2.8.8 的 RE2 语法，在规范化域名上搜索；完整匹配须显式 `^` / `$`，默认启用大小写不敏感标志（RE2 内联标志可覆盖） |

`*.example.com` 仅匹配 a.example.com，不匹配自身或 a.b.example.com；`**.example.com` 同时匹配自身和多级子域；`a.**.example.com` 包含 a.example.com。`.` 通配符模式只匹配根域；`*` 不匹配根，`**` 匹配根及所有支持的域名。根域的 suffix 匹配所有支持的域名，subdomain 排除根自身。

正则中的点、转义和大小写标志属于正则语法，不作为域名配置去掉或改写。例：JSON 中 `"^www[0-9]+\.example\.com$"`。不接受反向引用、前后查找等 RE2 不支持的语法；无效表达式报错，不回退原生 JS 回溯引擎。模式长度和所有组的编译指令总数受限，仍不能据此承诺任意规则满足线上免费 CPU 配额。

#### 受控匹配上下文与 IP/CIDR

第三参数的 `context` 是调用者已取得的可信属性，不是请求自行声明的配置或归属来源：

```js
await executeQuery(queryWire, env, { context: {
  client: { ip: '2001:db8::1', asn: 64512, country: 'DE' },
  edge: { country: 'GB', colo: 'LHR' },
  addresses: {
    '192.0.2.1': { asn: 64512, country: 'DE' },
    '2001:db8::1': { region: 'example-region' },
  },
} });
```

省略 context/client/edge/某个属性表示不可用；显式 null、未知键、无效 IP/ASN/文本报 `INVALID_CONTEXT`。非可信请求头不能直接作为生产归属数据。`test/worker.js` 的 `x-test-context` 仅用于本地受控构造，不是生产 API。context 在执行前校验并复制；诊断接收器之后修改调用者对象不会改变后续匹配。它不会补造客户端/响应地址归属，也不会使用边缘位置填充缺失的国家。普通文本大小写敏感；文本控制字符被拒绝。

`client` / `edge` 接受 `ip/asn/country/region/city/colo`。`addresses` 仅接受 IP 键对应的 `asn/country/region/city`，最多 `maxContextAddresses` 项，不接受额外 `ip` 或 `colo`；只会为当前响应中真实存在的 A/AAAA 地址附加属性，不凭该映射生成地址。等价 IPv6 键重复配置报错，不用枚举顺序决定覆盖。

IP 的 eq/ne/in 按地址值而非拼写比较，压缩 IPv6、大小写及嵌入 IPv4 的等价 IPv6 可匹配；IPv4 与 IPv4-mapped IPv6 保持不同地址族。`cidr` 接受带十进制前缀的字符串，如 `192.0.2.0/24`、`2001:db8::/32`，主机位忽略；支持 IPv4 /0..32 和 IPv6 /0..128。拒绝带端口、zone ID、IPv4 前导零、IPv4 缩写和非法前缀，不让 URL 解析器宽松转换地址。

#### 响应集合与同项绑定

```json
{ "collection": "response.addresses", "quantifier": "any", "where": {
  "all": [
    { "field": "item.ip", "op": "cidr", "value": "192.0.2.0/24" },
    { "field": "item.asn", "op": "eq", "value": 64512 },
    { "field": "item.country", "op": "eq", "value": "DE" }
  ]
} }
```

- `response.records` 遍历当前响应的 Answer、Authority、Additional；`response.addresses` 只选择其中的 A/AAAA 记录。同一地址在多个记录出现则按记录分别访问，附加属性按规范化 IP 共享。
- `any` 为至少一个项命中，`all` 为非空且每个项都命中。**无响应或空集合的 any/all 均为 false**，不是逻辑真空真值。空答案仍可用 `response.exists` 区分。
- `where` 中的 all/any/not 始终绑定同一个 `item`；上例不能由第一个地址提供 ASN、第二个地址提供国家凑成命中。需要地址的多个属性共同满足时放进同一个 where，不要拆成几个独立集合条件。
- `where` 可引用全局 query/original/client/edge/response 字段，但不能再嵌套集合。`item.*` 不能出现在顶层或其他集合的作用域；类型检查和配置校验均约束作用域。

| item 字段 | records | addresses |
| --- | --- | --- |
| `item.name` | 记录 owner 域名，不是查询名或目标名 | 同左 |
| `item.type` | DNS 类型；eq/ne/in/exists | 同左（A/AAAA） |
| `item.ttl` | 数值，0..4294967295 | 同左 |
| `item.section` | `answer` / `authority` / `additional`；eq/ne/in/exists | 同左 |
| `item.target` | CNAME、DNAME、NS、PTR、MX、SRV、SVCB、HTTPS 的实际目标域名；其他类型缺失 | 不允许 |
| `item.ip` | 不允许 | 实际 A/AAAA 地址；eq/ne/in/cidr/exists |
| `item.asn/country/region/city` | 不允许 | 仅来自同 IP 的显式 context.addresses；无补全时缺失 |

SVCB/HTTPS 目标 `.` 保持字面根值，不隐式替换为 owner；SOA 等多域名字段不随意挑一个作为 target。匹配对象出现不支持的域名表示等执行异常会终止处理并记录脱敏 `INVALID_STATE`，不当成未命中；求值预算错误为 `RESOURCE_LIMIT`。条件错误不受动作 `onError: continue` 影响。

### 动作

| type | 字段 | 行为 |
| --- | --- | --- |
| `queryUpstream` | 无 | 查询配置的单个 DoH 上游，以新响应替换当前响应；不合并、不隐式终止 |
| `answer` | `records`，可选 `rcode`（默认 0） | 以自定义响应替换当前响应；不隐式返回，不追加到旧答案。`records: []` 是合法空答案 |
| `setTtl` | `ttl` | 修改当前响应各普通记录 TTL；无响应报错 |
| `rewriteQuery` | `name` 和/或 `queryType` | 修改当前问题，仅影响后续动作及匹配，不修改原始查询，不自动重命名已有答案 |
| `stop` | 无 | 立即停止剩余动作及所有后续规则，保留当前响应/无响应状态 |
| `return` | 无 | 立即直接返回已有响应，无响应报错 |

记录包含 `name`、`type`、`ttl`、`rdata`，可选 `class`（默认 1）。TTL 为 0..4294967295 整数。RDATA 沿用 [`lib/dns-wasm/index.d.ts`](../lib/dns-wasm/index.d.ts) 的 native/Raw 模型，如 `Aaaa`、`Cname`、`Txt`、`Https`，不是 DNS 展示字符串。已使用的字段和类型/RDATA 对应关系必须通过库校验；未知 native 字段不能静默忽略。禁止自定义 OPT、TSIG、SIG、RRSIG 记录，本切片不支持携带认证声明或签名生成。

所有正常输出恢复原始请求 ID、Question、RD/CD，并经过统一编码与 matchResponse 校验。未改写上游保留适用 AD/RRSIG；自定义答案和响应改写不能携带失效认证声明。setTtl 仅修改普通 RR，保留 OPT 的 EDNS TTL 位字段，并移除覆盖实际改动 RRset 的 RRSIG。rewriteQuery 影响的上游答案按改写答案收尾，不能继承其 AD/签名；不自动重命名记录 owner。通用 DNS 库不包含业务策略。

上游组、缓存、命名列表、来源补全、ECH 等属于后续切片，不声明已完成父规格全部功能。

## 错误

`RuleError` 提供固定消息、稳定 `code` 和 `location`（可含 group、从 0 开始的 rule/action 索引）。

- `INVALID_CONFIG`：无效或尚不支持的配置。
- `INVALID_QUERY`：不支持或损坏的 DNS 输入。
- `NO_RESPONSE`：动作需要已有响应。
- `RESOURCE_LIMIT`：超出配置预算。
- `INVALID_STATE`：动作产生无效工作状态或底层操作异常，原因仅保留安全分类。
- `INVALID_OPTIONS`：执行选项不符合公开契约。
- `NO_UPSTREAM`：处理需要上游但未配置。
- `UPSTREAM_FAILED` / `UPSTREAM_INVALID` / `UPSTREAM_TIMEOUT`：上游失败、无效响应或单次超时。
- `EXECUTION_TIMEOUT` / `REQUEST_CANCELLED`：整体处理超时或取消。
- `ACCESS_DENIED` / `INVALID_HTTP`：安全的 HTTP 边界诊断。
- `INVALID_CONTEXT`：匹配上下文的结构、属性或地址键无效。

不附加原始 JSON/库异常文本、配置值、凭据、路径密钥或完整报文。`RuleError.reason` 在适用时只提供固定的安全错误分类和说明，不附带任意原始 cause 或 stack。执行器记录结构化失败事件；调用者仍不得把 `env` 或完整 DNS 输入写入日志。默认日志使用 Worker 日志通道；不在应用中自动配置其他日志接收服务。

## 动作失败与回滚

所有动作都可以设置 `onError`：省略或 `"fail"` 表示必需动作，失败立即抛出原有稳定错误；`"continue"` 表示可选动作。未知值（包括 null/布尔值）拒绝，不支持第二套 `optional` 开关。

```json
{ "type": "setTtl", "ttl": 60, "onError": "continue" }
```

可选动作在自己的候选状态上执行，成功且状态校验通过后才提交；失败时丢弃该动作的候选状态，保留此前成功动作，并继续剩余动作和规则。原始查询及嵌套 EDNS 数据保持独立，调用者的输入字节也不作为后续校验的共享可变引用。网络请求与已经写出的日志等外部行为不能撤销。

`return` 在没有响应时也可以按可选失败继续，不会误认为流水线已经终止。配置错误仍在执行前完整预检，不能用 `onError` 把非法配置或无效引用降为可选失败。

**T2 明确收紧中间状态语义**：动作生成或修改响应后立即校验，超限响应不能先提交给后面的动作，即使后面本来会再生成一个较小答案。必需动作立即失败，可选动作恢复旧状态。只改查询的动作不重新编码已有响应；所有最终返回仍经过统一校验。逐动作复制和校验会增加 CPU，不能据此宣称已满足线上免费额度。

## 资源边界

`DNS_LIMITS` 接受 JSON 值/文本，只能包含下表字段。所有值必须为正整数，不能高于硬上限。计数作用于一次调用的所有规则组（包括未命中分支），不是只计执行过的动作。字节数按 UTF-8 计算。

| 字段 | 默认 | 硬上限 |
| --- | ---: | ---: |
| maxNetworkRequests | 2 | 16 |
| maxExecutionTimeMs | 3000 | 30000 |
| upstreamTimeoutMs | 1500 | 10000 |
| maxQueryBytes | 4096 | 65535 |
| maxResponseBytes | 16384 | 65535 |
| maxGroupBytes | 5120 | 65536 |
| maxConfigBytes | 65536 | 262144 |
| maxGroups | 32 | 64 |
| maxRules | 256 | 8192 |
| maxActions | 1024 | 32768 |
| maxRecords | 256 | 4096 |
| maxConditionNodes | 1024 | 8192 |
| maxConditionDepth | 16 | 32 |
| maxConditionSteps | 8192 | 131072 |
| maxConditionValues | 128 | 1024 |
| maxPatternLength | 256 | 1024 |
| maxPatternInstructions | 4096 | 32768 |
| maxContextAddresses | 256 | 4096 |

`maxRecords` 计所有 answer 配置中的记录总数，同时限制上游响应记录总数（包括 Answer/Authority/Additional）；maxConfigBytes 计所有规则组及 DNS_UPSTREAMS/DNS_UPSTREAM_GROUPS 命名表，不计无关绑定；maxResponseBytes 在每个生成/修改响应动作提交前及统一收尾应用，stop/return 也不能绕过；rewriteQuery 提交前检查编码后的查询大小。规则组大小先检查再解析/编译，条件深度与总节点数均受限；平台 JSON 对象仍需序列化才能计数，因此可信部署配置本身不应包含异常巨大的对象。应用边界不能放宽 Cloudflare 平台变量大小/数量限制，也不证明任意规则规模满足免费套餐 CPU。

条件深度根节点为 0，逻辑子项与集合 where 各增加一层。maxConditionValues 限制每个 in 的原始成员数，maxPatternLength 限制单个正则/通配符模式的 UTF-16 长度，maxPatternInstructions 限制全部组中 RE2 编译后指令数的总和（包括通配符）。这些检查在求值前覆盖所有分支。

maxConditionSteps 为每次 executeQuery 累计预算，不按组或规则重置：每访问一个条件节点计一步，每检查一个响应记录额外计一步，即使该记录不是地址、被 addresses 过滤也计入。短路之后未访问的项不计；省略 when 不访问条件节点。一个标量 in 已预编译成集合，计一次节点访问；正则使用线性时间引擎且模式规模另受上述限制。该计数不是毫秒/CPU 时间，也不是免费额度证明。maxContextAddresses 限制传入映射的项数，不只是匹配到的地址数；各属性长度另有限制。调用者必须提供合理规模的受信任对象，属性 getter 抛错会失败，不能保证任意自定义 getter 或超大输入对象的 CPU/内存开销。

## 本地验证

```sh
npm ci
npm run typecheck
npm run test:rules
npm run test:doh
npm test
```

规则测试通过 esbuild 0.28.2 将应用和 RE2JS 打包为 ESM（WASM 保留真实模块导入），没有替换正则或 DNS 库。本地协议验收通过 Miniflare 4.20260730.0 / workerd 1.20260730.1，兼容日期为 2026-07-30，不启用 nodejs_compat（使用本地二进制支持的日期而非未来日期）。规则回归通过真实环境绑定调用公共执行入口；T5 则通过 src/worker.js 正式 HTTP 入口，独立 DNS wire 解码器检查响应。DoH 测试仅在外部网络边界使用受控上游，不向公共解析器发请求。根类型检查还包含既有 DNS/ECH 类型用例，完整测试包含两个库现有回归。

当前 registry 的最新 Miniflare 版本仍有 `sharp` / `undici` 传递开发依赖告警（`npm audit` 为 3 项 high，2026-10-20 检查）。它们只用于本地测试，不导入应用模块；尚未修复这些工具依赖告警，不把测试通过说成依赖安全审计通过。没有执行真实公网/公共上游或线上 CPU/免费配额验收，也没有推送或部署。

## 失败事件与诊断参数

旧的两参数形式继续有效，但现在必须 await 返回的 Promise。第三参数可为调用提供请求标识与同步事件接收器：

```js
const result = await executeQuery(queryWire, env, {
  requestId: 'request-123',
  onEvent(event) {
    console.error(JSON.stringify(event));
  },
});
```

- `requestId` 省略时每次调用生成独立 UUID；显式值必须为 1–128 位 ASCII 字母、数字及 `_ . : -`。不要把凭据当请求标识，完整 URL 或密钥路径不能作为标识。
- `onEvent` 只处理失败，不在普通成功路径调用。省略时默认通过 `console.error` 写出 JSON 事件，而不是静默处理；Host 的 error 通道抛错时尝试 warn 通道。
- 配置、输入、上下文及条件求值错误产生 `execution_failed`；动作或动作状态校验失败产生 `action_failed`。事件含 `level`、`requestId`、`location`、`actionType`（适用时）、`code`、`message`、可选安全 `reason`、`disposition` 和 `rolledBack`。
- 必需失败的 `disposition` 为 `terminated`，不返回部分结果；可选失败为 `rolled_back_continue`，`rolledBack: true`。此处回滚仅指 DNS 工作状态，不代表撤销外部副作用。
- 事件及嵌套位置/原因均只读，与活跃 DNS 状态无可变共享引用。多个失败保留同一请求标识及各自动作位置，不会因后续执行而改变此前事件。
- 接收器必须同步。它抛错、尝试修改只读事件或意外返回 Promise 时，不替换原动作结果；安全默认通道记录 `observer_failed` 及原失败事件。意外 Promise 的拒绝被消费，不等待它完成，也不输出它的原始异常内容。
- 接收器属于受信任代码，必须实际记录或处理传入事件；执行器不能检查一个正常返回的回调是否将事件保存到了外部。Host 的所有诊断通道都不可用时无法保证日志投递，但不会让诊断故障覆盖原 DNS 错误。
- 不记录原始配置、DNS 报文、异常 stack 或任意 cause 文本。错误信息使用稳定安全消息，底层原因在适用时只提供 Error/TypeError/RangeError 等固定分类，不直接转储可能含凭据或 URL 的原异常。

T2 回归通过同一公开 `executeQuery` 接口观察事件和 DNS 输出；“部分修改后失败”使用可选 answer 产生超限候选响应来验证，而不是添加测试专用动作。旧 T4 用户扩展已由 #26 移除；正式 HTTP 回归通过基础动作、受控网络与运行时脱敏日志维持安全覆盖。

## JSON-only 迁移（#26）

旧 #11 按旧规格完成的历史保留；本版本不再提供用户函数注册或执行：

| 旧入口 | 当前行为 / 迁移方式 |
| --- | --- |
| defineCondition / defineAction 导出 | 已删除；不要导入或注册函数 |
| ExecutionOptions.extensions 及 ExtensionRegistry / ExtensionDefinition / ActionContext / ConditionContext / ConditionHandler / ActionHandler 类型 | 已删除；旧选项即使为空也报 INVALID_OPTIONS |
| custom 条件及 CustomCondition 类型 | INVALID_CONFIG；使用字段比较、all/any/not、记录/地址集合量词 |
| type: custom 动作 | INVALID_CONFIG；使用 answer、setTtl、rewriteQuery、queryUpstream、stop、return |
| maxExtensionCalls / maxExtensionTimeMs | INVALID_CONFIG；从 DNS_LIMITS 删除，不再有扩展执行预算或扩展专属错误码 |
| 任意网络、EDNS 注入、代码参数解析器、通用异步任务 | 不提供替代函数或字符串执行入口；未有基础动作支持的能力不能伪装已交付 |

旧引用在全量配置编译时失败：包括 return 后的规则、不匹配分支、逻辑短路后的条件、集合 where 以及未使用上游组的 accept。onError: continue 不能掩盖配置错误；未知 run、函数体和未知字段也不作为可执行配置。只接受明确支持的 JSON 结构，不 eval、不调用任意函数、不循环或竞速。

例如将“生成答案 → 自定义 TTL 判断/改写 → 返回”改为单个 DNS_RULE_JSON 环境变量的 JSON 值：

```json
{
  "order": 0,
  "rules": [
    { "actions": [
      { "type": "answer", "records": [
        { "name": "example.com", "type": "A", "ttl": 60, "rdata": { "A": { "addr": "192.0.2.1" } } }
      ] },
      { "type": "rewriteQuery", "name": "changed.example" }
    ] },
    { "when": { "all": [
      { "field": "query.name", "op": "eq", "value": "changed.example" },
      { "field": "original.name", "op": "eq", "value": "example.com" },
      { "collection": "response.records", "quantifier": "all", "where": {
        "field": "item.ttl", "op": "gte", "value": 60
      } }
    ] }, "actions": [
      { "type": "setTtl", "ttl": 23 },
      { "type": "return" }
    ] }
  ]
}
```

对 example.com 的请求生成一条 TTL 23 的 A 答案；当前查询改写后可匹配，客户端 ID/Question/RD/CD 仍按原始请求收尾，无需上游或用户函数。匹配不隐式联网；queryUpstream 仍异步执行。每个基础动作使用独立候选 DNS 状态，失败不污染此前答案；网络已经发出和脱敏失败事件不会因回滚消失。迟到网络成功/拒绝不能提交到后续状态或其他请求。

executeQuery 继续返回 Promise；保留 signal、context、requestId 和 onEvent 作为可信宿主集成/诊断选项，onEvent 不是 DNS 条件/动作注册表，普通部署者无需编写回调。最近动作结果是 #27 待交付功能，本票不以旧响应冒充其结果，也不新增该接口。

回归映射：旧任意函数状态修改改用真实 answer 超限与 rewriteQuery 超限验证原子回滚；旧延迟函数改用受控上游的迟到成功/拒绝、取消及总 deadline；旧自定义匹配改用当前/原始字段和记录量词；旧签名/OPT 注入改用禁止配置及基础 TTL/查询改写的 DNSSEC 收尾。代码参数解析与恶意闭包专有测试随被删除能力撤除，不承诺不存在的用户代码沙箱。通用 DNS/ECH 库及其测试不变。

## 标准 DoH 网络入口（T5 / #12）

正式入口是 `src/worker.js` 的默认 fetch 导出；代码组合可导入 `handleRequest(request, env, options?)`，把可信取消、上下文及诊断选项传入同一执行器（不含用户注册表）。`package.json` 也导出 `superdoh/worker`。Worker 不接受请求携带规则、函数或上游 URL，不读文件配置。只支持 HTTPS wire-format DoH，不提供历史 README 中的 JSON DNS、UI、竞速或文件配置功能。

### 环境绑定与路径

| 绑定 | 含义 |
| --- | --- |
| `DNS_RULE_*` | 既有环境变量规则组 |
| `DNS_LIMITS` | 可选资源边界 JSON/JSON 文本 |
| `DNS_UPSTREAM` | 可选单个 HTTPS DoH URL 字符串；不预置厂商，长度至多 2048，不接受 userinfo 或 fragment，可有受信任的路径/查询参数 |
| `DNS_PATH_KEY` | 可选 Workers Secret；未设置时公开，设置后启用路径密钥 |

未配置密钥时路径为 `/dns-query`。配置密钥后仅接受 `/<key>/dns-query`，旧的公开路径也关闭。key 格式为 1–128 个 ASCII 字母、数字、下划线、连字符，使用高熵值；空串、null、其他类型或非法字符是配置错误，不当作“未配置”。根据 URL pathname 精确匹配，不接受尾斜杠或 percent-encoded 密钥拼写；平台/代理可能先做 URL 规范化，不能把路径规范化当作额外认证手段。密钥比较使用 SHA-256 摘要及固定长度 timingSafeEqual，不用普通字符串比较秘密。

认证先于规则/limits/上游预检与请求体读取；错误路径返回固定 404，非法 Secret 配置返回固定 500。仅支持路径密钥，不接受 Authorization/Bearer 或查询参数密钥。路径密钥可能进入客户端历史、代理或平台访问日志；应用不记录路径，不等于整个链路不会保存 URL。不要把真实密钥写进源码、wrangler.jsonc、测试、命令参数或报告。

`wrangler.jsonc` 指向正式入口，并启用 `enable_request_signal`。其兼容日期与本仓库已验证的 workerd 版本保持为 2026-07-30，不启用 nodejs_compat；更新日期/运行时时应再跑协议回归。配置中未放入 Secret 或默认上游，并关闭会自动携带 URL 的 invocation logs 和 traces，仅保留应用的固定脱敏事件；这不代表客户端、代理或平台其他日志已全链路脱敏。Wrangler 为本地开发依赖；本次仅使用本地类型生成，没有部署。`worker-configuration.d.ts` 由 `wrangler types --include-runtime=false` 生成；规则/可选 Secret 仍需环境绑定并在运行时严格校验，不由客户端自行声明。

### HTTP 与 DNS 错误语义

- GET：一个且仅一个 `dns` 参数，内容为 canonical、无 padding 的 base64url DNS wire；不接受重复参数或额外查询字段。
- POST：`Content-Type: application/dns-message`，body 为 DNS wire；不接受 URL 查询参数。请求体按流限量读取，Content-Length 仅作提前拒绝优化，不作为唯一限制。
- Accept 省略或允许 application/dns-message 时可用，支持媒体范围和 q 值；明确拒绝 dns-message 时 406。无效 DoH/DNS 输入 400，不支持的方法 405（含 Allow），POST 超限 413、GET 超限 414、媒体类型错误 415。读取未完成便超时/取消返回 408。
- 有效查询的执行、配置或上游失败：HTTP 200，`Content-Type: application/dns-message`，相关 DNS SERVFAIL；不返回此前部分成功答案。不把合法 NXDOMAIN/NODATA 当失败。
- 正常与错误响应均 `Cache-Control: no-store`；T5 未提供 HTTP/DNS 缓存。所有 DNS 响应经过同一 finalize 编码、大小和 matchResponse 校验。正常响应受 maxResponseBytes 限制，SERVFAIL 单独使用固定 **512 字节**协议错误预算，不带 OPT/EDNS，避免极小或无效响应限额令合法查询无法取得相关错误报文。

### 显式动作与默认上游

```json
{
  "order": 0,
  "rules": [
    { "actions": [
      { "type": "queryUpstream" },
      { "type": "setTtl", "ttl": 60 },
      { "type": "return" }
    ] }
  ]
}
```

`queryUpstream` 使用当前查询，发送一次 POST wire 查询；新响应替换当前响应，不合并记录、不自动返回。不隐式重试，redirect 设为 manual 并拒绝 3xx。配置 URL 固定且受信任，不依据请求转发客户端凭据。上游 HTTP 状态、媒体类型、流大小、DNS 协议、EDNS 版本及与实际发送查询的 ID/Question 对应关系全部通过后才能提交。默认采用 NOERROR/NXDOMAIN，包括 NODATA；SERVFAIL/REFUSED 及其他 RCODE 作为失败，不伪装成可用答案。

规则结束（包括 stop）仍无响应时，配置了 DNS_UPSTREAM 才执行一次默认查询；已有自定义答案、合法空答案或 NXDOMAIN 均不触发它。没有上游的直接 executeQuery 仍能返回 null，正式 HTTP 入口则返回相关 SERVFAIL。上游配置错误即使在自定义答案路径也失败，避免静默忽略坏配置。

可选上游动作的失败产生 action_failed/rolled_back_continue，保留动作开始前状态；必需失败终止为 SERVFAIL。若可选查询失败且仍无响应，最后的默认查询也是一次独立、有预算的网络请求，不是隐式无限重试。网络次数在一次执行中累计，超时/失败也计入，状态回滚不重置次数。

### 预算、清理和 DNSSEC

maxExecutionTimeMs 覆盖认证之后的输入读取、执行器和网络响应读取；maxNetworkRequests 累计显式/默认上游尝试；upstreamTimeoutMs 限制一次上游的 headers 和 body 等待，并受共享总 deadline 约束。客户端 Request.signal 与可信调用方 options.signal 统一传播；可选单次上游超时不取消整个请求，但整体 deadline 耗尽不能被可选动作放宽。

结束、失败或取消时清理计时器和监听器，取消未消费 body/reader，消费迟到的 Promise 拒绝；取消本身不作为必须无限等待的工作。AbortSignal 是合作式取消，不能保证远端服务器立即停止，也不能抢占同步死循环。测试通过真实 workerd 验证 bounded wait、超限流无需等待 EOF 和取消结果；Node callback-service 对远端流 cancel 回调传播的可观测性有限，不用它声称远端所有资源已释放。

上游响应先对应**当前出站查询**校验，再恢复**原始客户端问题**收尾。查询比较包含完整 flags 及 OPT/EDNS 参数；收尾保留对出站 EDNS 差异的防御检查；当前基础 rewriteQuery 不改 EDNS。若未来动作改变出站 EDNS，则不将为不同参数生成的响应 OPT 透传给原客户端；T6 显式采用扩展 RCODE 时的最小 OPT 重建例外见下文。未经业务改写的上游保留适用 AD/RRSIG；这只是保留可信上游的声明，本服务不执行 DNSSEC 密码学校验。TSIG/SIG0 消息认证不能在重新编码后沿用，统一移除。TTL 修改清 AD，并只移除覆盖真正被修改 RRset 的 RRSIG；保留未改动 RRset 的适用签名。answer 不能注入 OPT/RRSIG/TSIG/SIG；queryUpstream 可保留适用上游记录，rewriteQuery 后的上游响应按保守策略清 AD、移除全部 RRSIG。提前 stop/return、可选回滚及 SERVFAIL 都不能绕过统一协议收尾。

本地测试的默认网络边界为受控上游，不发真实公共解析请求；没有部署、没有公网或线上免费套餐 CPU/连接数验收。开发依赖的 npm audit 仍有 3 项 high 告警，本票未自动强制升级或以功能回归代替依赖安全验收。

## 命名上游组与顺序回退（T6 / #13）

本节扩展 T5 的单 URL 契约；不提供并发竞速、缓存、隐式厂商或公网验收声明。所有配置仍来自部署环境，不接受请求中的上游或规则。

### 配置与引用

以下分别是两个独立 JSON 环境绑定（也接受 JSON 文本）：

`DNS_UPSTREAMS`：

```json
{
  "primary": { "url": "https://primary.example/dns-query" },
  "backup": { "urlSecret": "BACKUP_DOH_URL" }
}
```

`DNS_UPSTREAM_GROUPS`：

```json
{
  "standard": { "members": ["primary", "backup"] },
  "requireAddress": {
    "members": ["primary", "backup"],
    "accept": {
      "collection": "response.records",
      "quantifier": "any",
      "where": { "all": [
        { "field": "item.section", "op": "eq", "value": "answer" },
        { "field": "item.type", "op": "eq", "value": "A" }
      ] }
    }
  }
}
```

`BACKUP_DOH_URL` 是由部署者另行配置的 Secret，值为完整 HTTPS DoH URL。每个上游只能指定 `url` 或 `urlSecret` 之一；含令牌/敏感路径的 URL 应使用 Secret 引用，不写在普通 JSON、源码或报告中。URL 校验与 T5 相同；Secret 绑定名、上游名、组名均为 `[A-Za-z][A-Za-z0-9_]{0,63}`，引用区分大小写，不从对象原型查找。

组的 `members` 是非空、有序的命名上游引用。单成员即单上游策略；多成员严格顺序等待，不并发、不自动重试同一成员。数组显式重复成员意味着显式再次尝试，仍消耗网络预算。不接受未知字段或 `strategy: "race"`。两个命名表的所有条目及声明式条件都预检，包括未使用组；规则中不可达的错误组引用同样报错，不在错误配置时返回自定义答案掩盖问题。

规则动作使用 `{ "type": "queryUpstream", "group": "standard" }`，不同规则可复用同一组。`DNS_DEFAULT_UPSTREAM_GROUP` 是可选组名字符串：无 group 的动作及流水线结束/stop 后的无响应查询使用该组；不自动选择命名表第一项。没有默认配置时，显式组动作仍可使用，直接执行器仍可返回 null，HTTP 入口映射 SERVFAIL。

兼容 T5：未指定默认组时，原有 `DNS_UPSTREAM` 继续作为无 group 动作和无响应时的单 URL 来源；也可与仅显式引用的命名组并存。**同时配置 DNS_UPSTREAM 与 DNS_DEFAULT_UPSTREAM_GROUP 是歧义错误**，不猜测优先级。选中组的响应替换当前响应，不合并；合法空答案也不会触发另一轮默认查询。可选动作耗尽且仍无响应时，最后默认查询仍是一轮独立调用，但共享同一预算。

### 上游成功条件

底层传输先验证 HTTP 成功/媒体、DNS 报文、EDNS 版本、记录数量和实际出站查询 ID/Question 对应性；任何 `accept` 都不能绕过这些检查。T5 的重定向禁止、流量边界、消息认证清理、客户端关联恢复及 DNSSEC 收尾继续适用。

不设置 `accept` 时仅采用有效 NOERROR/NXDOMAIN（完整 RCODE 0/3），包括 NODATA 与空答案；默认拒绝 SERVFAIL/REFUSED 和其他 RCODE。`accept` **替换**默认策略，而不是额外 AND：部署者可显式采用其他协议有效 RCODE。仅写“存在 A”不会同时约束 RCODE，如需同时要求 NOERROR，请用 `all` 明确组合。`response.rcode` 读取含 EDNS 扩展位的完整 0–4095 RCODE，不只读头部低四位。若查询的 EDNS 被改写而收尾需要清除不适用的上游 OPT，扩展 RCODE 不能随之丢失：原客户端带 OPT 时重建仅携带扩展 RCODE、原客户端 payload size 且无 DO/其他 flags/options 的最小 OPT；原客户端没有 OPT 时该结果不能安全表达，按 UPSTREAM_INVALID 让动作失败（默认路径为 SERVFAIL），绝不把 RCODE 16 等错误降为 NOERROR。

`accept` 仅支持声明式 Condition：all/any/not、字段和集合条件，不再接受 custom 引用。query/original 字段分别读取实际出站查询和原始客户端查询；response 字段和集合读取刚通过协议验证的候选响应，不是此前提交的旧响应；客户端/边缘/地址属性来自已验证上下文，不隐式联网。量词逐项绑定，匹配不修改候选。条件 false 表示旧政策的拒绝；条件求值异常或资源耗尽则让查询动作失败，不伪装未命中。

### 顺序回退、诊断与预算

网络失败、HTTP/DNS 无效、单成员超时或采用条件 false 会依数组顺序尝试下一成员；一旦合格便停止，不发多余查询。整体执行超时、取消、共享资源耗尽或条件执行错误立即终止本轮组查询。大小/记录资源限制也是硬边界，不因换成员而放宽。

每个失败的命名组成员产生 `upstream_failed` 固定脱敏事件，包含既有 requestId/location/actionType，以及 `upstream: { groupIndex, memberIndex }`：分别为 `DNS_UPSTREAM_GROUPS` 对象条目顺序与成员数组的 **0 起始索引**。这允许定位配置而不记录可能敏感的自定义组名、URL、Secret 绑定名/值或原始错误。未发送成员不声称已有网络失败。

- `fallback`：该成员失败，继续尝试下一成员。
- `exhausted`：最后成员未能提供合格响应。
- `terminated`：取消、整体/资源限制或条件执行错误阻止继续。
- `rolledBack` 对成员事件为 false：尚未提交候选，不冒充整个动作回滚。

采用条件拒绝为 `UPSTREAM_REJECTED`；普通传输/协议/超时沿用固定错误码。全部成员失败后抛 `UPSTREAM_EXHAUSTED`，再产生动作/执行最终事件：必需动作 terminated/SERVFAIL；可选动作 rolled_back_continue，保留此前响应及后续动作。成功回退保留之前全部失败事件，不只记录最终成功。旧单 URL 保持原有错误码和事件契约，不额外输出命名成员事件。同步 observer 及日志写入兜底机制保持不变。

| 新边界 | 默认 | 硬上限 | 累计范围 |
| --- | ---: | ---: | --- |
| maxUpstreams | 16 | 64 | 命名上游数 |
| maxUpstreamGroups | 16 | 64 | 命名组数 |
| maxUpstreamMembers | 64 | 256 | 所有组的成员引用总数 |

两个命名 JSON 表各受 maxGroupBytes（默认 5120），并与所有规则组**共同**累计 maxConfigBytes；采用条件与规则条件共同累计节点及正则程序预算，执行时共同累计步骤。Secret URL 另受单 URL 2048 字符及上游数量边界。maxNetworkRequests（默认 2）在全部成员、显式动作和默认查询间共享，失败也计数；若配置更长回退链，必须在硬上限内显式配置足够次数，不偷偷提升预算。maxExecutionTimeMs 不因成员/组/动作重置；upstreamTimeoutMs 覆盖单成员 headers/body。

未采用响应已完成有界读取；失败/迟到响应仍按 T5 取消未消费 body、释放计时器/监听器并消费迟到拒绝。合作式取消及本地受控上游测试不证明远端立即停止或线上免费 CPU/连接配额合格。本票没有部署或访问公共解析服务。
