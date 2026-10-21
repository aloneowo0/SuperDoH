# 环境变量规则执行器（JSON-only / #15–#24、#26–#29）

当前实现提供异步 `executeQuery` 和标准 DoH GET/POST。#26 已移除旧 #11 用户条件/动作代码扩展，DNS 行为仅由环境变量 JSON 的声明式条件和基础动作组成；异步网络、原始数据隔离、回滚及脱敏诊断继续保留。`test/worker.js` 只是旧规则测试适配器，生产入口为 `src/worker.js`。

**分阶段迁移**：#26 已移除用户代码扩展；#27 已移除旧默认补查、策略组和采用条件，改为显式命名单 HTTPS 上游与只读最近动作结果。核心不自动回退、重试、补查或竞速。普通 TCP 和认证 TLS 上游已在 #28/#29 交付；默认上游原始响应缓存及 JSON 策略已在 #15 交付，通用记录改写已在 #16 交付，真实请求元数据适配已在 #17 交付；响应地址归属补全已在 #18 交付；域名列表已在 #19 交付，ECH 直接配置与 DNS HTTPS 来源已在 #20/#21 交付，#22 主动库探测适配及 #23 JSON 接口已接入；独立 ECH OpenSSL 成功互操作仍受本地程序缺失阻塞，不能声明完整版本已验收。修订 #7 是目标规格，不是全部已实现声明；未部署、未做线上免费 CPU 验收，README 历史版本说明不是当前功能清单。

## 公共入口

```js
import { executeQuery, RuleError } from './src/index.js';

try {
  const result = await executeQuery(queryWire, env);
  // result.termination: 'completed' | 'stopped' | 'returned'
  // result.response: Uint8Array；无响应时抛出 NO_RESPONSE
  // result.originalQuery: 深度只读原始查询，与输入和当前状态没有可变共享引用
  // result.query: 当前查询快照，包含 rewriteQuery 的成功修改
  // result.lastAction: 深只读最近动作结果，与 DNS 状态及回滚分离
} catch (error) {
  if (!(error instanceof RuleError)) throw error;
  // error.code, error.message, error.location
}
```

入口返回 `Promise<ExecutionResult>`，调用者必须 `await` 并处理拒绝（T4 将原同步入口迁移为异步）。联网由显式上游、归属和 ECH 动作以及流水线前的已配置列表维护执行；条件本身不联网；移除用户函数不改变网络异步契约。输入为 `Uint8Array` DNS 报文和 Workers 环境绑定对象；不读取文件、`process.env` 或请求中的配置。支持标准单问题 QUERY、根域或 ASCII 标签（字母、数字、连字符、下划线）；IDN 使用 punycode。拒绝响应报文、其他 opcode、截断查询、已有 Answer/Authority、非 OPT 的 Additional 和非零 EDNS 版本/扩展 RCODE。合法的 EDNS 0 查询可以处理，但此切片的自定义响应不回显请求的 OPT/ECS。

规则正常结束是 `completed`；`stop` 是 `stopped`；`return` 是 `returned`。三者均经过统一输出收尾。

- 内部尚未取得响应与合法空答案不同；正常结束或 stop 后仍无响应，executeQuery 抛出 NO_RESPONSE，HTTP 入口返回相关 SERVFAIL，不隐式联网。成功的 ExecutionResult.response 始终是 wire bytes。
- 所有协议有效且可表示的 RCODE（包括 SERVFAIL/REFUSED）、NOERROR 空答案及 NXDOMAIN 均是已取得的响应，仍有 wire bytes，不是 `null`。
- `stop` 动作本身不要求响应，但停止后统一收尾仍要求已有响应；`return` 和 `setTtl` 在无响应时立即抛 `NO_RESPONSE`。
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
- 未知字段、动作、条件操作符和引用明确报错，不回退文件。无 `DNS_RULE_*` 变量可通过配置校验，但空流水线无响应，执行时以 NO_RESPONSE 失败。
- 其他无关环境绑定不作规则解析；配置入口包括 `DNS_RULE_*`、`DNS_LIMITS`、`DNS_UPSTREAMS`、`DNS_CACHE`、`DNS_ADDRESS_SOURCES`、`DNS_DOMAIN_LISTS`、`DNS_JSON`，HTTP 入口还读取可选 Secret `DNS_PATH_KEY`。在其他名称的变量中放置规则不会启用规则。

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

executeQuery 第三参数的 `context` 是调用者已取得的可信属性，不是请求自行声明的配置或归属来源；标准 HTTP 入口未显式覆盖时使用 #17 平台适配，见后文：

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
- `where` 可引用全局 query/original/client/edge/response/lastAction 字段，但不能再嵌套集合。`item.*` 不能出现在顶层或其他集合的作用域；类型检查和配置校验均约束作用域。

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
| `queryUpstream` | 必填 `upstream` 上游名 | 查询指定命名 HTTPS DoH 上游一次，以新响应替换当前响应；不合并、不隐式终止 |
| `answer` | `records`，可选 `rcode`（默认 0） | 以自定义响应替换当前响应；不隐式返回，不追加到旧答案。`records: []` 是合法空答案 |
| `setTtl` | `ttl` | 修改当前响应各普通记录 TTL；无响应报错 |
| `rewriteQuery` | `name` 和/或 `queryType` | 修改当前问题，仅影响后续动作及匹配，不修改原始查询，不自动重命名已有答案 |
| `stop` | 无 | 立即停止剩余动作及所有后续规则，保留当前响应并统一收尾，无响应则 NO_RESPONSE |
| `return` | 无 | 立即直接返回已有响应，无响应报错 |

记录包含 `name`、`type`、`ttl`、`rdata`，可选 `class`（默认 1）。TTL 为 0..4294967295 整数。RDATA 沿用 [`lib/dns-wasm/index.d.ts`](../lib/dns-wasm/index.d.ts) 的 native/Raw 模型，如 `Aaaa`、`Cname`、`Txt`、`Https`，不是 DNS 展示字符串。已使用的字段和类型/RDATA 对应关系必须通过库校验；未知 native 字段不能静默忽略。禁止自定义 OPT、TSIG、SIG、RRSIG 记录，本切片不支持携带认证声明或签名生成。

所有正常输出恢复原始请求 ID、Question、RD/CD，并经过统一编码与 matchResponse 校验。未改写上游保留适用 AD/RRSIG；自定义答案和响应改写不能携带失效认证声明。setTtl 仅修改普通 RR，保留 OPT 的 EDNS TTL 位字段，并移除覆盖实际改动 RRset 的 RRSIG。rewriteQuery 影响的上游答案按改写答案收尾，不能继承其 AD/签名；不自动重命名记录 owner。通用 DNS 库不包含业务策略。

缓存、TCP/TLS、命名列表、来源补全、ECH 等属于后续切片；不提供上游策略组，不声明已完成父规格全部功能。

## 错误

`RuleError` 提供固定消息、稳定 `code` 和 `location`（可含 group、从 0 开始的 rule/action 索引）。

- `INVALID_CONFIG`：无效或尚不支持的配置。
- `INVALID_QUERY`：不支持或损坏的 DNS 输入。
- `NO_RESPONSE`：动作需要已有响应，或流水线结束/stop 仍无响应。
- `RESOURCE_LIMIT`：超出配置预算。
- `INVALID_STATE`：动作产生无效工作状态或底层操作异常，原因仅保留安全分类。
- `INVALID_OPTIONS`：执行选项不符合公开契约。
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
| maxUpstreams | 16 | 64 |
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

`maxRecords` 计所有 answer 配置中的记录总数，同时限制上游响应记录总数（包括 Answer/Authority/Additional）；maxConfigBytes 计所有规则组及 DNS_UPSTREAMS 命名表，不计无关绑定；maxResponseBytes 在每个生成/修改响应动作提交前及统一收尾应用，stop/return 也不能绕过；rewriteQuery 提交前检查编码后的查询大小。规则组大小先检查再解析/编译，条件深度与总节点数均受限；平台 JSON 对象仍需序列化才能计数，因此可信部署配置本身不应包含异常巨大的对象。应用边界不能放宽 Cloudflare 平台变量大小/数量限制，也不证明任意规则规模满足免费套餐 CPU。

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

2026-10-20 检查时使用的 Miniflare 版本存在 `sharp` / `undici` 传递开发依赖告警（`npm audit` 为 3 项 high，2026-10-20 检查）。它们只用于本地测试，不导入应用模块；尚未修复这些工具依赖告警，不把测试通过说成依赖安全审计通过。没有执行真实公网/公共上游或线上 CPU/免费配额验收，也没有推送或部署。

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
| type: custom 动作 | INVALID_CONFIG；使用 answer、setTtl、addRecords、removeRecords、replaceRecords、setCache、rewriteQuery、queryUpstream、stop、return |
| maxExtensionCalls / maxExtensionTimeMs | INVALID_CONFIG；从 DNS_LIMITS 删除，不再有扩展执行预算或扩展专属错误码 |
| 任意网络、EDNS 注入、代码参数解析器、通用异步任务 | 不提供替代函数或字符串执行入口；未有基础动作支持的能力不能伪装已交付 |

旧引用在全量配置编译时失败：包括 return 后的规则、不匹配分支、逻辑短路后的条件、集合 where 以及未引用上游里的旧 accept 字段。onError: continue 不能掩盖配置错误；未知 run、函数体和未知字段也不作为可执行配置。只接受明确支持的 JSON 结构，不 eval、不调用任意函数、不循环或竞速。

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

executeQuery 继续返回 Promise；保留 signal、context、requestId 和 onEvent 作为可信宿主集成/诊断选项，onEvent 不是 DNS 条件/动作注册表，普通部署者无需编写回调。最近动作结果由 #27 提供，见后文；旧响应不冒充本次请求结果。

回归映射：旧任意函数状态修改改用真实 answer 超限与 rewriteQuery 超限验证原子回滚；旧延迟函数改用受控上游的迟到成功/拒绝、取消及总 deadline；旧自定义匹配改用当前/原始字段和记录量词；旧签名/OPT 注入改用禁止配置及基础 TTL/查询改写的 DNSSEC 收尾。代码参数解析与恶意闭包专有测试随被删除能力撤除，不承诺不存在的用户代码沙箱。通用 DNS/ECH 库及其测试不变。

## 标准 DoH 网络入口（T5 / #12）

正式入口是 `src/worker.js` 的默认 fetch 导出；代码组合可导入 `handleRequest(request, env, options?)`，把可信取消、上下文及诊断选项传入同一执行器（不含用户注册表）。`package.json` 也导出 `superdoh/worker`。Worker 不接受请求携带规则、函数或上游 URL，不读文件配置。只支持 HTTPS wire-format DoH，不提供历史 README 中的 JSON DNS、UI、竞速或文件配置功能。

### 环境绑定与路径

| 绑定 | 含义 |
| --- | --- |
| `DNS_RULE_*` | 既有环境变量规则组 |
| `DNS_LIMITS` | 可选资源边界 JSON/JSON 文本 |
| `DNS_UPSTREAMS` | 可选命名 HTTPS/TCP/TLS 上游 JSON/JSON 文本，不能自行触发网络 |
| `DNS_CACHE` | 可选默认缓存策略 JSON/JSON 文本，字段 read、write、maxTtl；不触发上游请求 |
| `DNS_PATH_KEY` | 可选 Workers Secret；未设置时公开，设置后启用路径密钥 |

未配置密钥时路径为 `/dns-query`。配置密钥后仅接受 `/<key>/dns-query`，旧的公开路径也关闭。key 格式为 1–128 个 ASCII 字母、数字、下划线、连字符，使用高熵值；空串、null、其他类型或非法字符是配置错误，不当作“未配置”。根据 URL pathname 精确匹配，不接受尾斜杠或 percent-encoded 密钥拼写；平台/代理可能先做 URL 规范化，不能把路径规范化当作额外认证手段。密钥比较使用 SHA-256 摘要及固定长度 timingSafeEqual，不用普通字符串比较秘密。

认证先于规则/limits/上游预检与请求体读取；错误路径返回固定 404，非法 Secret 配置返回固定 500。仅支持路径密钥，不接受 Authorization/Bearer 或查询参数密钥。路径密钥可能进入客户端历史、代理或平台访问日志；应用不记录路径，不等于整个链路不会保存 URL。不要把真实密钥写进源码、wrangler.jsonc、测试、命令参数或报告。

`wrangler.jsonc` 指向正式入口，并启用 `enable_request_signal`。其兼容日期与本仓库已验证的 workerd 版本保持为 2026-07-30，不启用 nodejs_compat；更新日期/运行时时应再跑协议回归。配置中未放入 Secret 或默认上游，并关闭会自动携带 URL 的 invocation logs 和 traces，仅保留应用的固定脱敏事件；这不代表客户端、代理或平台其他日志已全链路脱敏。Wrangler 为本地开发依赖；本次仅使用本地类型生成，没有部署。`worker-configuration.d.ts` 由 `wrangler types --include-runtime=false` 生成；规则/可选 Secret 仍需环境绑定并在运行时严格校验，不由客户端自行声明。

### HTTP 与 DNS 错误语义

- GET：一个且仅一个 `dns` 参数，内容为 canonical、无 padding 的 base64url DNS wire；不接受重复参数或额外查询字段。
- POST：`Content-Type: application/dns-message`，body 为 DNS wire；不接受 URL 查询参数。请求体按流限量读取，Content-Length 仅作提前拒绝优化，不作为唯一限制。
- Accept 省略或允许 application/dns-message 时可用，支持媒体范围和 q 值；明确拒绝 dns-message 时 406。无效 DoH/DNS 输入 400，不支持的方法 405（含 Allow），POST 超限 413、GET 超限 414、媒体类型错误 415。读取未完成便超时/取消返回 408。
- 有效查询的执行、配置或上游失败：HTTP 200，`Content-Type: application/dns-message`，相关 DNS SERVFAIL；不返回此前部分成功答案。不把合法 NXDOMAIN/NODATA 当失败。
- 正常与错误响应均 `Cache-Control: no-store`；HTTP 入口不缓存最终答案；#15 仅在显式上游动作内缓存原始响应。所有 DNS 响应经过同一 finalize 编码、大小和 matchResponse 校验。正常响应受 maxResponseBytes 限制，SERVFAIL 单独使用固定 **512 字节**协议错误预算，不带 OPT/EDNS，避免极小或无效响应限额令合法查询无法取得相关错误报文。

### 显式命名 HTTPS 上游（#27）

`DNS_UPSTREAMS` 是独立 JSON 环境变量（也可为 JSON 文本），只保存连接信息。名称为 1–64 位 ASCII，首位字母，其余字母、数字或下划线；区分大小写。不预置厂商，不自动选择第一项。HTTPS 项必须有 `transport: "https"`，且 `url` / `urlSecret` 恰好一个；普通 TCP 项见下节：

```json
{
  "A": { "transport": "https", "url": "https://resolver-a.example/dns-query" },
  "B": { "transport": "https", "urlSecret": "BACKUP_URL" }
}
```

`BACKUP_URL` 是 Workers Secret 的绑定名，值是完整 HTTPS URL。URL 最多 2048 字符，拒绝 userinfo、fragment 和非 HTTPS 协议；敏感路径/查询参数使用 Secret，不放源码或普通配置。TCP/TLS 使用独立 address/port 字段；TLS 还支持显式 serverName，详见后文。未知字段、未引用的无效上游、缺失 Secret 和不可达动作中的坏引用都在任何动作/网络执行前失败。

显式请求动作：

```json
{
  "order": 0,
  "rules": [{ "actions": [
    { "type": "queryUpstream", "upstream": "A" },
    { "type": "setTtl", "ttl": 60 },
    { "type": "return" }
  ] }]
}
```

一次 HTTPS 动作未命中可用缓存时只向指定上游发一次 POST wire 查询，不重试、切换上游或跟随重定向。目标只来自部署配置，客户端不能指定地址或上传配置。先校验 HTTP、媒体、消息大小、DNS/EDNS 版本及实际出站 ID/Question 对应性，再以新响应替换当前响应。所有协议有效且可表示的完整 RCODE 均算请求成功，包括 SERVFAIL、REFUSED、NXDOMAIN、NODATA；业务是否满意由下一条规则判断。HTTP 200 本身不等于 DNS 有效。

仅定义上游不联网；正常结束/stop 没有响应时报 NO_RESPONSE 并返回相关 SERVFAIL，绝不补查。return 没响应仍按动作失败处理，可选时可继续。没有显式请求动作时，即使配置了上游也不会访问它。

### 最近动作结果与 JSON 顺序回退

结果是只读 `lastAction`，与 DNS 状态分开：

```js
// ExecutionResult.lastAction（仅示例形状，非用户函数接口）
{ success: false, actionType: 'queryUpstream',
  location: { group: 'DNS_RULE_MAIN', rule: 0, action: 0 },
  code: 'UPSTREAM_FAILED' }
```

每次请求初始没有 lastAction。每个实际执行动作在成功提交后更新成功结果（无 code）；失败时更新失败结果及稳定脱敏 code，DNS 回滚不会撤销它。stop/return 成功也更新，未命中规则、未执行动作及条件求值不更新。每条规则只判断一次，读取前一动作结果应写在**下一条规则**，不是同一规则中每个动作前重新判断。结果与嵌套 location 深只读且每请求独立，不含原始异常、URL 或 Secret；也不能通过 ExecutionOptions 注入。

| 条件字段 | 类型 / 含义 |
| --- | --- |
| `lastAction.success` | 布尔；初始缺失，false 不等于当前无响应 |
| `lastAction.actionType` | 动作 type 文本 |
| `lastAction.code` | 失败的稳定脱敏码；初始和成功后缺失 |
| `lastAction.group` | `location.group` 文本 |
| `lastAction.rule` / `lastAction.action` | `location` 的 0 起始索引，0..4294967295 |

文本条件支持 eq/ne/in/exists，布尔支持 eq/ne/in/exists，索引支持数值比较；缺失属性普通比较（含 ne）为 false，需明确使用 exists/not。集合 where 也可读取这些全局条件。

**例 1：A 连接失败允许继续，再显式请求 B**（DNS_RULE_MAIN）：

```json
{
  "order": 0,
  "rules": [
    { "actions": [{ "type": "queryUpstream", "upstream": "A", "onError": "continue" }] },
    { "when": { "field": "lastAction.success", "op": "eq", "value": false },
      "actions": [{ "type": "queryUpstream", "upstream": "B" }] }
  ]
}
```

即使 A 之前已有自定义答案且 A 失败后保留，lastAction.success 仍为 false，旧答案不能冒充本次请求成功。若 A 合格则第二条不命中，只请求 A。A 返回合法 SERVFAIL 也属于请求成功，上例不会请求 B。

**例 2：A 失败或返回 SERVFAIL/REFUSED 时请求 B**：沿用例 1，把第二条 when 改为：

```json
{ "any": [
  { "field": "lastAction.success", "op": "eq", "value": false },
  { "all": [
    { "field": "lastAction.success", "op": "eq", "value": true },
    { "field": "response.rcode", "op": "in", "value": [2, 5] }
  ] }
] }
```

**例 3：仅超时允许换上游**：沿用例 1，把第二条 when 改为：

```json
{ "all": [
  { "field": "lastAction.success", "op": "eq", "value": false },
  { "field": "lastAction.code", "op": "eq", "value": "UPSTREAM_TIMEOUT" }
] }
```

只会因符合 JSON 条件而执行下一次请求；整体 deadline/取消或预算耗尽仍不能通过可选动作绕过。多个动作成功/失败都会替换最近结果，跨越其他动作后不能把较早请求结果当“最近请求”；需要观察 A 的条件应紧接 A 所在规则。

### 旧上游政策迁移

旧 #12/#13 按旧规格交付的历史不改写；以下入口现在明确拒绝，不静默兼容：

| 旧配置/接口 | 当前处理 / 迁移 |
| --- | --- |
| DNS_UPSTREAM | INVALID_CONFIG；移入 DNS_UPSTREAMS 名称项，并增加显式 queryUpstream 动作 |
| DNS_UPSTREAM_GROUPS、DNS_DEFAULT_UPSTREAM_GROUP | INVALID_CONFIG（即使空对象/空值）；删除策略组，按名称写顺序规则 |
| queryUpstream 缺少上游名或包含旧 group 字段 | INVALID_CONFIG；改为必填 upstream 名称 |
| 上游项缺少 transport，或包含 members、accept 等旧字段 | INVALID_CONFIG；按传输使用 transport 和 url/urlSecret 或 address/port；采用判断移到后续规则 |
| maxUpstreamGroups、maxUpstreamMembers | INVALID_CONFIG；删除，使用 maxUpstreams 和共享资源预算 |
| UpstreamGroupConfig、upstream_failed、组成员索引、fallback/exhausted 处置、UPSTREAM_REJECTED/UPSTREAM_EXHAUSTED | 已移除；每次显式动作失败用 action_failed 及动作位置，后续成功不抹除既有事件 |

### 预算、清理和 DNSSEC

maxUpstreams 默认 16、硬上限 64；命名上游表及所有规则组各受 maxGroupBytes，并共同累计 maxConfigBytes。所有规则条件共同累计节点、正则指令和执行步骤。Secret URL 另受单 URL 2048 字符边界。

maxExecutionTimeMs 覆盖认证后的输入读取、执行器和网络响应读取；maxNetworkRequests（默认 2）在所有显式动作之间累计实际上游请求，缓存命中不计数，出站失败也计数，DNS 回滚不重置；upstreamTimeoutMs 覆盖单次 headers/body 等待并受总 deadline 约束。更长顺序回退必须在硬上限内显式配置预算，不偷偷增加次数。客户端 Request.signal 与可信 options.signal 合并传播。

结束、失败或取消时清理计时器/监听器，取消未消费 body/reader，消费迟到 Promise 拒绝；合作式取消不保证远端立即停止。迟到完成不能提交回滚候选或污染其他请求。Node callback-service 对远端流 cancel 回调传播的可观测性有限，不据此声称远端所有资源释放或线上配额合格。

响应先对应当前出站查询校验，再恢复原始客户端 ID/Question/RD/CD。未经改写数据保留适用 AD/RRSIG（不代表本服务执行 DNSSEC 密码学校验）；TTL 修改清 AD 并仅移除被改 RRset 的失效签名；rewriteQuery 后的上游响应保守清 AD/全部 RRSIG；TSIG/SIG0 消息认证重新编码后不能沿用。当前基础动作不改 EDNS，保留对未来出站 EDNS 差异的防御：必要时清除不适用 OPT，扩展 RCODE 只能用原客户端 OPT 重建最小无 flags/options OPT，无法安全表示则 UPSTREAM_INVALID，绝不降为 NOERROR。提前返回、可选回滚与 SERVFAIL 都经过统一协议收尾。

本地测试仅使用受控上游，不发真实公共解析请求。未部署、未做线上免费 CPU/连接数或公网互操作验收。原始响应缓存见后文；外部列表与 ECH 动作为后续票据，不能因 #27 完成声称新版 #7 全部完成。

### 普通 TCP 命名上游（#28）

```json
{
  "primary": { "transport": "tcp", "address": "resolver.example", "port": 53 }
}
```

`address` 是独立的 ASCII DNS 主机名、严格 IPv4 或不带括号的 IPv6，不接受 URL、端口后缀、IPv6 zone 或路径；国际域名需先转 ASCII。`port` 省略时为 53，显式值必须为 1–65535 的整数，null 和数字字符串不接受。TCP 项不接受 url/urlSecret，HTTPS 项不接受 address/port；未使用的坏定义也在执行前失败。目标仅来自部署者配置，不从客户端请求拼接。

这是**明文 DNS over TCP**，不是 DoT。每个未命中缓存的显式请求动作创建一个连接，发送带两字节长度前缀的 DNS 报文，只取得一份对应响应后关闭连接；不池化、不管线化、不重试、不切其他传输或上游。与 HTTPS 共用完整 RCODE、报文/实际查询对应性、EDNS、记录预算及统一客户端收尾；请求、失败结果及 JSON lastAction 分支语义相同。

前缀和正文可以分段到达；收到完整帧即完成，不等待服务器 EOF。前缀声明不足 DNS 头、超过响应预算、截断、同一读块中超出首帧的数据或不对应响应均拒绝。完整首帧之后不继续等候额外消息，关闭连接后到达的数据不参与当前请求。maxResponseBytes 限制 DNS 正文，不含两个分帧字节。

单次连接建立、写入及读取共同受 upstreamTimeoutMs 和请求总 deadline 约束；maxNetworkRequests 跨 HTTPS/TCP 动作累计，失败也计数。取消、超时、成功和失败均关闭本地 socket，处理 opened/closed 和迟到操作拒绝；不承诺已经发送的网络数据可回滚或远端应用立即停止。平台/操作系统对不可用端口可能先报连接失败，也可能直到预算超时，JSON 应按所需的成功状态或稳定错误码组合处理。

本地验证通过正式 DoH 入口，workerd 直接连接受控 Node TCP DNS 服务，无 nodejs_compat，不用模拟 connect 替代真实连接。覆盖分段帧、保持连接不发 EOF、失败及扩展 RCODE、畸形帧、限额、超时、取消、连接释放及回滚。esbuild 浏览器目标需将平台模块 cloudflare:sockets 保留为 external。

Workers 出站 TCP 对 Cloudflare IP 范围等目标存在平台限制，生产环境本地地址的可达性也不同于 Miniflare；本地受控服务成功不证明任意公共解析器或所有端口可达。本票未进行公网解析、部署或线上 CPU/连接配额验证。平台说明：https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/ 。

### 认证 TLS 命名上游（#29）

```json
{
  "secure": { "transport": "tls", "address": "resolver.example", "port": 853 },
  "secureIp": { "transport": "tls", "address": "192.0.2.53", "port": 853, "serverName": "resolver.example" }
}
```

TLS 是标准 DNS over TLS，默认端口 **853**，不等同明文 TCP。address/port 校验与 TCP 相同；serverName 为证书身份和 SNI 使用的 ASCII DNS 主机名，默认取地址中的主机名，连接 IP 时必须显式提供 DNS serverName。此接口不提供仅 IP SAN 身份认证、私有 CA 注入、关闭证书校验或明文降级开关；未知字段在预检阶段失败。TCP/HTTPS 项不接受 serverName。

使用平台原生 socket.startTls 的 expectedServerHostname，在任何 DNS 应用数据发送前立即启用 TLS；没有 STARTTLS DNS 命令，也不会先发明文 DNS。信任链及服务端身份由平台验证。认证失败是明确的动作失败，不重连明文、不换来源、不请求默认上游。普通 DoT 不调用或复刻 ECH 探测库。

握手、写入和读取共同使用单次 upstreamTimeoutMs，并受整体执行 deadline 和跨传输请求次数约束；握手失败、超时和取消均关闭连接。分帧、完整 RCODE、协议对应性、最近动作结果、回滚和最终 DNSSEC/EDNS 收尾与 TCP/HTTPS 共用。

TLS 回归在真实 workerd 正式 DoH 入口连接受控 Node TLS DNS 服务。测试网络单独配置既有证书夹具的根信任，未向生产配置添加测试 CA，未关闭校验。覆盖正确身份、错误身份、不信任根、拆分响应、失败/扩展 RCODE、可选回滚、取消清理，以及原始 TCP 对端不完成 TLS 握手时的有界失败与不降级。通过这些测试不等于公网目标可达或线上 CPU/连接配额合格；平台底层诊断与外部代理日志仍需部署者另行审查。


## 原始上游响应缓存（#15）

默认开启读取和写入，缓存上限 **300 秒**。可配置 DNS_CACHE（JSON 对象或 JSON 文本）：

```json
{ "read": true, "write": true, "maxTtl": 300 }
```

read/write 必须为布尔值；maxTtl 必须为 **0–86400 的整数秒**。缺省字段继承默认值；0 禁止本次策略下的读取和写入。未知字段、非法数值和不可达分支中的非法策略均在联网前失败，不接受任意缓存键、延长 DNS 安全 TTL、过期容忍或后台刷新配置。策略上限限制的是本地复用期限，不是 setTtl，不会把答案 TTL 改成配置的上限。

### JSON 优先级与隔离

```json
{
  "order": 0,
  "rules": [{
    "actions": [
      { "type": "setCache", "read": true, "write": true, "maxTtl": 120 },
      { "type": "queryUpstream", "upstream": "primary", "cache": { "read": false } },
      { "type": "queryUpstream", "upstream": "primary" }
    ]
  }]
}
```

优先级为**本次 queryUpstream.cache > 之前成功执行的 setCache > DNS_CACHE > 默认值**，逐字段覆盖。setCache 只影响当前执行中之后的请求，受匹配条件和顺序控制；动作局部覆盖不改变规则策略，也不会泄漏到下一次 HTTP 请求。上例第一次动作强制向上游请求并按继承策略写入，第二次可以命中原始响应。read:false 仅绕过读取，write:false 仅禁止新写入，不删除此前缓存；要完全禁用设置二者均为 false，或 maxTtl:0。

只保存校验后的上游 DNS 原始语义，必要的 HTTP Age 和负缓存 SOA TTL 规范化在用户动作之前完成；不保存 setTtl、answer、rewriteQuery 收尾或将来的 ECH 改写后的最终答案。缓存命中是成功的 queryUpstream，照常更新 lastAction，并继续执行后续规则。每次读取解析为独立对象，恢复本次 ID/Question，最后仍经过统一协议/DNSSEC 收尾。直接 answer 不读写上游缓存。

### 安全复用与期限

- 使用独立 Workers Cache API 命名空间 superdoh-original-v1，而非入口前缓存；每个 HTTP 请求都会执行规则。最终 HTTP 答案继续 no-store。
- 键为命名上游名称、完整解析后连接身份（含 HTTPS Secret 实际地址、TCP 端口、TLS serverName）和出站查询 wire（仅清零 ID）的 SHA-256。类型、类、名称大小写、RD/CD、EDNS 大小、DO 和完整 ECS 均隔离；Secret 轮换自然换键。缓存键只含固定版本路径及摘要，不含明文 DNS 名称或敏感 URL。
- 按整份消息最短的普通记录 TTL、策略上限、适用 SOA 最小值、RRSIG 元数据时间窗及 HTTPS 新鲜度取保守交集。OPT 的 ttl 是协议位，不作为 DNS TTL 递减。命中按原始接收时刻递减普通记录 TTL，不刷新插入时间；存储耗时不能延长期限。RRSIG 适用性检查不代表执行 DNSSEC 密码学校验。
- NXDOMAIN/NODATA 必须具有覆盖原始出站问题域名、同类的 SOA，按 min(SOA.ttl, SOA.minimum) 负缓存并规范化 SOA TTL；无证明、跨区别名的复杂负答案保守绕过，不猜测安全期限。
- SERVFAIL/REFUSED 等故障 RCODE、TC 截断、零 TTL、高位异常 TTL、消息认证、ANY/区传送/密钥协商类查询不缓存。普通无状态 EDNS 和合法 ECS 可复用；COOKIE、未知/有连接状态的 EDNS 选项、多个选项或 ECS 返回身份不对应时保守绕过。ECS 仅复用完全相同查询，不跨网段扩大命中范围。
- HTTPS fetch 显式 cache:no-store，不依赖隐式 HTTP 缓存。响应 Age/Date 对 DNS TTL 减龄；HTTP max-age/s-maxage/Expires 只能进一步缩短期限。no-store/private/no-cache、Set-Cookie、任何 Vary 或不可判定 Age 禁止新缓存，不用 DNS TTL 绕过来源限制。

### 缺失、错误与资源边界

未命中、过期、被平台清理或禁用存储而返回 miss 时，执行**同一显式动作**的一次真实上游请求，不查询其他来源、不重试、不取旧数据顶替。Cache API 本身可以静默不保留对象，不承诺写入后必命中。实际 API 拒绝/数据解码失败产生脱敏 CACHE_FAILED；尺寸/记录上限及超时保留 RESOURCE_LIMIT、EXECUTION_TIMEOUT、REQUEST_CANCELLED。必需动作终止，可选动作记录 action_failed 并仅回滚自身 DNS 候选；最近动作结果可供下一条 JSON 规则处理，绝不悄悄切换成网络重试。普通 miss/保守绕过不是错误，不输出含查询或键的逐次命中日志。

Cache API 读写、摘要及读取 body 共用执行总 deadline；实际出站才消耗 maxNetworkRequests，单次网络等待仍受 upstreamTimeoutMs 约束。缓存写入作为外部副作用不能因后续动作验证失败或取消而保证撤销；迟到缓存结果不提交 DNS 状态。缓存仅为数据中心本地、可随时清理的加速层，不是数据库，不保证跨地区或全球一致，不合并并发请求。

测试使用真实 workerd 的公开 DoH HTTP 入口、出站次数、受控 HTTP Age 和有界实际等待验证 TTL/过期；另有真实本地 TCP/TLS 命中及 TLS 身份变化测试。协议预算回归显式关闭缓存，避免把命中误认为真实网络覆盖。未添加测试专用生产时钟/缓存注入 API；这些本地测试不是线上免费 CPU、生产 Cache API 可达性或公网证书互操作验收。

参考：[Workers Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/)、[本地缓存边界](https://developers.cloudflare.com/workers/reference/how-the-cache-works/)。


## JSON 通用记录改写（#16）

所有记录编辑要求已有当前响应；从头生成答案继续使用 answer。动作失败统一进入 NO_RESPONSE / INVALID_STATE / RESOURCE_LIMIT 等脱敏失败契约；onError:continue 仅丢弃本次编辑候选，不污染此前答案、原始查询或原始上游缓存。

| 动作 | 参数 | 行为 |
| --- | --- | --- |
| addRecords | records，section? | 向指定节追加一次原生记录列表，默认 answer；空列表不改数据 |
| removeRecords | where | 删除全部命中记录；必须显式选择，不存在隐式全删 |
| replaceRecords | where，records，section? | 有命中时删除所有命中记录，并向指定节追加列表**一次**；无命中不插入；空列表等同删除 |
| setTtl | ttl，where? | 未指定 where 时沿用全普通记录 TTL 编辑；指定时仅调整命中普通记录 |

section 为 answer / authority / additional。records 使用与 answer 相同的原生记录模型、未知类型 Raw 表达和严格原生字段校验。列表中的名称必须明确填写，不插值、不调用函数、不额外解析目标。移动或替换不自动推导其他记录、补全 CNAME 链、合成 SOA 或查询另一个来源。

### 选择器与后续条件

where 使用同一有界 all/any/not、比较、域名、RE2 正则与 IP CIDR 条件语法，作用于每条记录：

- item.name：记录所有者；item.target：明确的 CNAME/DNAME/NS/PTR/MX/SRV/SVCB/HTTPS 目标，与查询域名分离。
- item.type / item.ttl / item.section：记录类型、TTL、所在节。
- item.ip：仅 A/AAAA 有值，不隐式查询 ASN 或地理信息；也可用于 response.records 的 where。
- query.* / original.* / response.rcode 等全局字段仍读取当前执行上下文；不支持在记录选择器内再嵌套集合量化。

每次编辑先选择，再修改其候选记录；后续规则读取改写后的当前响应。所有动作选择器在完整配置预检中编译，共享条件节点、正则与运行步骤预算，不绕过 maxRecords/maxResponseBytes/执行 deadline。没有选择器的旧 setTtl 不新增条件求值费用。

```json
{
  "order": 0,
  "rules": [{
    "actions": [
      { "type": "queryUpstream", "upstream": "primary" },
      { "type": "removeRecords", "where": { "field": "item.type", "op": "eq", "value": "AAAA" } },
      {
        "type": "replaceRecords",
        "where": { "field": "item.ip", "op": "cidr", "value": "192.0.2.0/24" },
        "records": [{ "name": "example.com", "type": "A", "ttl": 30, "rdata": { "A": { "addr": "203.0.113.7" } } }]
      },
      { "type": "setTtl", "ttl": 10, "where": { "field": "item.section", "op": "eq", "value": "answer" } }
    ]
  }]
}
```

删除 NOERROR 响应的全部 AAAA 后保留 NOERROR/NODATA，而不谎报 NXDOMAIN，也不自动联网；已有 authority/additional/适用 OPT 保留。要动态决定新记录名称或地址，必须等待有明确基础动作支持，不能把示例静态记录当变量模板。

### DNSSEC、保护记录与输出

实际添加、删除、替换及 TTL 改动清除 AD，并按被删除/加入/修改的 name/type/class RRset 删除相关 RRSIG；未涉及的记录、签名及 EDNS 信息继续保留。replaceRecords 对命中 RRset 按显式替换处理，保守使其相关签名失效，不声称验证新内容的密码学等价性。无命中编辑、空添加、相同 TTL 不使原签名无故失效。

不能直接添加/替换 OPT、RRSIG、TSIG、SIG 保护记录；removeRecords/replaceRecords 选中它们属于动作失败，不悄悄删除。setTtl 一贯跳过它们，OPT 的 ttl 不是记录存活时间。这里只提供普通记录编辑，**未提供 EDNS 写入动作**；已有完整扩展 RCODE 在记录编辑后仍保留。

编辑在独立候选响应中进行，动作后的记录/大小校验、正常结束、return、stop 均走同一协议收尾。超限的可选添加/替换不会留下部分新增或删除，必需失败终止。上游缓存仍保存改写前数据，不因一次调用的编辑被污染。

公开 DoH/workerd 回归覆盖原生 CNAME、地址选择、TXT/不透明记录和三个节、AAAA NODATA、后续条件可见、RRSIG/AD/扩展 RCODE、可选回滚、不可达配置预检、预算及真实原始缓存隔离；不增加用户函数、循环、隐式请求或部署。


## 平台客户端与边缘上下文（#17）

标准 DoH GET/POST 默认从入站 Request.cf 和 Cloudflare 管理的连接头适配规则上下文，使用既有 client.* / edge.* 条件，不需要新环境变量，也不隐式请求 GeoIP/ASN 服务。相同 DNS 查询可以按来源组合域名、类型、ASN 或地区条件选择显式上游；缓存命中不跳过这些规则。

| 条件字段 | HTTP 入口来源 |
| --- | --- |
| client.ip | 具有有效平台 colo 元数据时的 CF-Connecting-IP；严格解析单个 IPv4/IPv6，不取客户端转发链 |
| client.asn | Request.cf.asn，合法 1–2^32−1 整数 |
| client.country | Request.cf.country，两字母值；XX、T1、null/缺失不当真实国家 |
| client.region / client.city | Request.cf.region / city 的实际名称，可缺失；不将 regionCode 猜成地区名称 |
| edge.colo | Request.cf.colo，实际处理数据中心的三字母代码 |
| client.colo、edge.ip/asn/country/region/city | 平台接口未给出相应可靠数据，默认不填、不根据 colo 推断地理位置 |

地理字段只是平台基于连接来源的粗粒度信息，不保证设备精确位置、VPN 之后的真实住址或行政区精度。不用 DNS 上游地址推断查询者属性，不把客户端城市复制成边缘城市。文本限长并排除控制字符；非法、未知、空或不可用字段保持缺失。既定 exists、比较和 not 语义不变：缺失值不会因为 ne:US 自动等同“美国以外”。需要安全限制的规则必须显式处理缺失情况，地理条件本身不是身份认证。

### 连接头和 Worker 子请求边界

- ASN/地理位置只信 Request.cf，不信任 CF-IPCountry、CF-Region、CF-City、X-Client-ASN、X-Edge-Colo 等客户端可提交头。X-Forwarded-For、X-Real-IP、True-Client-IP 和 CF-Ray 也不作为源 IP 或边缘信息回退。
- 源 IP 路径假设**直接部署在 Cloudflare Workers 的网络入口**：Cloudflare 在普通访问中提供 CF-Connecting-IP。存在 request.cf/colo 不是通用的远端认证协议；自行构造 Request、在非 Cloudflare 网关转发、Service Binding/RPC 转发或开放本地测试服务的宿主必须另行建立可信入口，不能仅凭同名 HTTP 头声称已验证来源。
- 同区 Worker 子请求的 CF-Connecting-IP 可受其 X-Real-IP 修改；跨区 Worker 子请求可能是固定 2a06:98c0:3600::103。遇到 CF-Worker 头或该固定地址，本适配器保守保留 edge.colo，但**不填整组 client 属性**，不冒充原始最终用户。CF-Worker 仅作为撤销不可靠属性的提示，不用于认证/放行，也不根据其区名授予权限。需要区级限制可在 Cloudflare WAF/Transform Rules 使用 cf.worker.upstream_zone。
- Pseudo IPv4 的 Overwrite Headers 模式可能给出 240.0.0.0/4 合成地址，仅此情况下从合法 CF-Connecting-IPv6 恢复真实 IPv6；缺少合法 IPv6 时 IP 缺失，不将合成 IPv4 当真实位置/身份。其他情况下 CF-Connecting-IPv6 不能覆盖有效 CF-Connecting-IP。
- Managed Transform 移除 IP、预览不提供 cf、字段不可用或地域未知时不补查、不伪造。仅有效平台 colo 才启用连接头到 IP 的适配；其他 cf 字段按实际可用值独立采用。

可信应用调用 handleRequest 的显式 options.context 仍可完全覆盖默认平台适配（与 executeQuery 的宿主上下文能力一致）；这是可信代码集成，不是新增客户端头、环境变量脚本或 DNS 用户扩展入口。默认入口不读取客户端上传的上下文。每请求重新构造并由执行器私有化上下文，不跨请求复用，不默认记录客户端地址/地区。

公开 workerd/DoH 回归通过标准 Miniflare cf 注入提供受控平台元数据，覆盖属性分离、同名伪装头、IPv4/IPv6/Pseudo IPv4、Worker 子请求、未知/缺失字段、GET/POST、逐来源 JSON 上游选择与缓存命中及脱敏错误。Miniflare 会合并合成默认 cf 数据，测试显式将不可用字段置 null，避免把本地默认美国元数据误认为来自被测请求；未为私有模块增加测试 API。这些是本地信任边界/规则验收，不是生产网络地理精度或线上免费 CPU 验收。

参考：[Workers Request.cf](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties)、[CF-Connecting-IP 与 Worker 子请求](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip)、[Pseudo IPv4](https://developers.cloudflare.com/network/pseudo-ipv4/)、[Worker 子请求 WAF 字段](https://developers.cloudflare.com/waf/custom-rules/use-cases/block-worker-subrequests/)。


## 显式响应地址归属补全（#18）

在已取得当前响应后，用 enrichAddresses 动作从明确配置的 HTTPS JSON 来源取得其中 A/AAAA 地址的 ASN、国家/地区、省级行政区或城市。它不修改 DNS 报文，不根据客户端或边缘属性猜测答案地址的归属；单独使用 item.asn / item.country 等条件绝不触发联网。没有默认厂商、全球归属库或用户函数适配。

### 配置与示例

DNS_ADDRESS_SOURCES 是命名来源对象，可为环境 JSON 或 JSON 文本；与规则共用配置字节预算。敏感来源地址放入 Secret，通过 urlSecret 引用，不写入仓库。以下来源使用保留示例域名，部署时替换成自己提供此契约的真实服务，并按服务实际 JSON 修改字段路径。

~~~json
{
  "geo": {
    "url": "https://geo.example/lookup",
    "ipParam": "ip",
    "params": { "format": "json" },
    "fields": {
      "ip": ["ip"],
      "asn": ["network", "asn"],
      "country": ["location", "country"],
      "region": ["location", "region"],
      "city": ["location", "city"]
    },
    "cacheTtl": 60
  }
}
~~~

例如查询 ?format=json&ip=192.0.2.9 时，来源返回：

~~~json
{ "ip": "192.0.2.9", "network": { "asn": 64512 }, "location": { "country": "DE" } }
~~~

以下 DNS_RULE_MAIN 使用已有命名上游 primary：

~~~json
{
  "order": 0,
  "rules": [
    { "actions": [
      { "type": "queryUpstream", "upstream": "primary" },
      { "type": "enrichAddresses", "source": "geo" }
    ] },
    {
      "when": { "collection": "response.addresses", "quantifier": "any", "where": { "all": [
        { "field": "item.asn", "op": "eq", "value": 64512 },
        { "field": "item.country", "op": "eq", "value": "DE" }
      ] } },
      "actions": [{ "type": "setTtl", "ttl": 30 }]
    }
  ]
}
~~~

来源 url 与 urlSecret 必须且只能选一个；只允许 HTTPS、无用户信息/片段，不跟随重定向。静态 params 仅接受受限字符串键值；ipParam 每次写入实际目标地址。fields.ip 必填，并至少指定一个归属字段；映射是有界字符串路径数组，不是点表达式、模板或可执行选择器。只读取 JSON 对象自身属性，不执行原型链访问。所有来源和动作引用在执行前全量校验，未命中分支中的错误也拒绝。

返回 IP 必须与被查地址等价；ASN 必须为 0..4294967295 的整数，不接受 AS64512 或数字字符串。地区/城市等必须为 1..128 字符的无控制字符文本。缺失的可选字段保持缺失，非法值（包括 null）产生 ATTRIBUTION_INVALID，不伪造默认 ASN/国家，也不隐式把省份名称转换成代码。字段含义、地区编码、精度、IPv6 覆盖与数据更新程度取决于配置来源；本适配不保证物理位置或认证准确性。

### 当前状态、失败与资源

遍历当前响应 Answer/Authority/Additional 的 A/AAAA，按规范化 IPv4/IPv6 去重后顺序查询。空响应不联网且成功；尚无响应则 NO_RESPONSE。属性始终绑定实际 IP，不允许第一个地址的 ASN 与另一个地址的国家拼成一次 where 命中。后续记录改写产生新地址时，不会为该新地址自动补全。

全部地址成功后才提交本动作的属性；对于此次补全的地址，新属性替换旧属性，不能把旧国家与新 ASN 混合。必需失败终止并返回相关 SERVFAIL；onError:continue 丢弃本次全部部分结果，保留此前成功 DNS/归属状态，生成脱敏失败事件并保留失败 lastAction 供后续规则分支。已完成的来源请求与缓存写入是外部副作用，不声称回滚。日志通过 location.source 标识来源，错误区分 ATTRIBUTION_FAILED、ATTRIBUTION_INVALID、ATTRIBUTION_TIMEOUT、CACHE_FAILED 和共享资源/取消错误；不打印完整 URL、参数、Secret 或原始异常。

默认 maxAddressSources=16、maxAttributionAddresses=16、maxAttributionBytes=16384、attributionTimeoutMs=1500，可通过 DNS_LIMITS 调整，硬上限分别为 64、256、262144、10000。地址数在来源请求前检查。归属与 DNS 上游请求共享 maxNetworkRequests（默认 2）及 maxExecutionTimeMs 总预算；实际出站才消耗额度，缓存命中不消耗网络次数。多地址补全需显式提高额度，不能通过可选失败或新动作重置。每次请求涵盖响应头和有界流读取，超时/取消后清理资源，不自动重试、回退或竞速。

### 归属缓存

cacheTtl 默认为 0（不跨请求缓存），可显式设置秒数上限，最大 86400。归属缓存独立于原始 DNS 缓存和 DNS TTL；配置读取的是来源提供的附加数据，不是认证证明。缓存身份涵盖完整来源身份、字段映射及规范化 IP 的摘要；Secret 地址变化自然隔离，不把敏感 URL 明文写入缓存键。

只复用完整校验成功的属性，期限受显式 cacheTtl 和适用 HTTP 新鲜度共同限制，不缓存失败或把过期数据顶替新结果；缓存读回重新校验数据。来源返回 no-store/private/no-cache、Vary、Set-Cookie 等不安全共享缓存条件时不写入。Cache API 为本地、可清理的加速层，不保证全球一致或每次写入必命中；实际缓存错误明确报 CACHE_FAILED，不静默切换政策。可选失败后的部分已写缓存可能保留，但不进入本次处理状态。

普通回归使用真实 workerd 公共 DoH 入口、受控 DNS/归属服务、独立 wire 解码及出站/日志观察，覆盖动作、后续匹配、状态回滚与缓存；不依赖公网归属服务，不将本地结果视为线上免费 CPU 或数据精度验收。

## 配置维护的域名列表（#19）

`DNS_DOMAIN_LISTS` 保存命名数据源。小列表可直接写 `{ "selected": { "domains": ["example.com"] } }`；外部来源用 `{ "selected": { "urlSecret": "LIST_URL", "format": "text", "refreshIntervalMs": 60000 } }`，也可用非敏感 `url` 替代 `urlSecret`。外部地址仅允许无用户信息和片段的 HTTPS，不跟随重定向。来源仅为数据，不接受远程动作、hosts/Adblock/Clash 语法或字符串代码。

- `text`：UTF-8，一行一个域名，支持 LF/CRLF，忽略空行及行首尾空白。
- `json`：UTF-8 JSON 域名字符串数组，可为空；不支持对象、混合类型或域名到动作映射。
- 所有条目使用现有域名校验和规范化（小写、去单个末尾点、IDN 使用 punycode）；非法条目使整个版本失败，不跳过坏条目或暴露部分数据。重复条目去重，但输入条目仍计入数量限制。

名称字段的 `inList` 为精确成员判断，`inListSuffix` 为包含自身的标签后缀判断。例如 `{ "field": "query.name", "op": "inListSuffix", "value": "selected" }`；可用于 query.name、original.name、item.name 和适用的 item.target，也可在记录选择器中使用。后缀不会把 notexample.com 当成 example.com 的子域；根域列表项 `.` 的后缀涵盖所有支持域名。非域名字段不接受列表操作符。全量配置预检检查所有引用，包括短路分支或 return 后的规则。

### 加载与刷新边界

认证及有效 DNS 输入、全部配置校验完成后，进入规则流水线前统一维护被配置条件/选择器引用的来源。首次使用或已达到刷新期限时，由当前请求顺序下载一次，不要求用户插入加载动作。随后匹配只读取此次维护取得的快照，条件本身不联网。同一个未到期来源在请求间复用已解析数据，不会因每个条件或每条记录重复下载。

`refreshIntervalMs` 是成功或失败维护完成后到下次允许尝试的间隔，不是 DNS TTL，也不被来源 HTTP Age 重置成 DNS TTL。仅在下一个有效、已授权请求的维护阶段检查是否到期；没有后台 Cron、定时刷新或无请求时的更新保证。失败不会在同一请求自动重试；下一次到期维护可恢复。所有请求仍共享自己的总 deadline 和网络额度，维护本身也占用 maxNetworkRequests。

成功版本只有完整下载、解析和所有条目校验完成后才原子发布。开始刷新即撤销旧版本：刷新失败后，即使历史数据曾存在也不得用于匹配。首次失败、HTTP/协议/解析失败、超限与超时均保持来源不可用；依赖它的条件抛出带 location.source 及规则定位的脱敏错误，而不是返回 false、空集或静默跳过。普通条件错误按既有必需执行失败处理，onError:continue 是动作政策，不能用来把条件来源故障变成未命中。显式逻辑短路仍按既有条件语义执行，但全量引用校验和维护不因短路而省略。

### 隔离、并发与资源

外部列表仅在**同一个 isolate** 内保存有界的解析后数据与不可用状态，不跨请求共享 Response、stream、socket 或未决 Promise，不增加 KV/D1 等基础设施。配置身份（包括 Secret 实际地址、格式、刷新参数及相关资源上限）隔离；部署、isolate 回收或有界缓存淘汰后重新加载。不是全球缓存，也不保证其他 isolate 同时失效。并发请求遇到正在刷新的来源直接视为不可用，不借用旧版本，不跨请求等待别人的 I/O。

默认 maxDomainLists=16、maxDomainListEntries=4096、maxDomainListBytes=262144、domainListTimeoutMs=1500、maxDomainListStateBytes=4194304；对应硬上限为 64、65536、2097152、10000、16777216。限制输入条目（包括重复项）、完整下载字节、单次维护耗时及保留状态的估算内存，状态内存不是 JS 引擎实际堆使用量承诺。后缀查找逐标签消费现有条件步骤预算。来源列表超过单变量预算时，环境变量仅保存来源描述，实际数据不需要塞入变量。

workerd 回归以公开 HTTP/DNS 入口观察两种格式、原子替换、失败即失效、按期限恢复及额度；时钟通过仅测试用的宿主包装控制，不新增生产时钟或私有状态测试 API。本地结果不代表全球失效时效、外网可达性或线上免费 CPU 验收。

## ECH 数据取得与 HTTPS 应用分离（#20、#21）

ECH 配置不默认来自任何厂商；必须先用 JSON 动作取得数据，再用 applyEch 写入已有目标响应。结构解析成功不证明 TLS 身份认证、ECH 接受或连接可达性。

- `{ "type": "loadEch", "config": "<标准带填充 Base64 ECHConfigList>" }`：直接从受信任环境 JSON 取得数据，完整预检损坏或不支持的配置；不联网。
- `{ "type": "queryEch", "name": "source.example", "upstream": "primary", "cache": { "read": true, "write": true, "maxTtl": 60 } }`：通过已有命名 HTTPS/TCP/TLS 上游发出一次独立 IN/HTTPS 查询，不改当前查询或当前答案，不执行 CNAME/别名自动追踪、回退或重试。
- `{ "type": "applyEch", "where": { "field": "item.name", "op": "eq", "value": "example.com" } }`：将当前已取得的 ECH 数据设置到当前响应 Answer 中命中的 HTTPS ServiceMode（priority 非零）记录。where 可省略以选择全部合格记录；选择器复用现有有界记录条件。仅改参数 key 5，保留优先级、目标、TTL、ALPN、端口和其他适用参数。

要创建 HTTPS 记录，先显式 answer/addRecords；applyEch 不隐式创建、选择厂商或修复 AliasMode。无当前响应报 NO_RESPONSE，无已取得数据报 NO_ECH_CONFIG，无合格目标报 NO_ECH_RECORD。修改后清 AD 并移除被修改 HTTPS RRset 的相关签名，未涉及的记录与签名不无故丢失；写入完全相同 ECH 数据时不无故使原签名失效。

queryEch 仅接受与来源问题对应、RCODE=NOERROR 且完整的响应，从 Answer 中 owner 等于来源名的 IN/HTTPS ServiceMode 记录提取 ECH 参数。没有合格配置报 NO_ECH_CONFIG；每个候选均完整校验，多个候选必须具有相同 ECHConfigList 字节，否则报 AMBIGUOUS_ECH_CONFIG，不任意选第一条。不把其他记录、额外节、错误 RCODE 或 AliasMode 当作配置，也不声称 DNS 数据经过主动 TLS 认证。

queryEch 的 cache 覆盖当前规则缓存策略，否则沿用既有默认安全上游原始响应缓存。DNS TTL、HTTP 新鲜度、来源/查询身份、存储作用域、超时/取消及共享网络额度与其他上游动作完全一致；不建立厂商常量或过期 ECH 回退。来源响应缓存与目标答案隔离，命中仍执行后续 applyEch 和其他规则。

取得和应用均为独立原子动作。取得失败的可选动作不会删除此前成功取得的 ECH 或替换当前 DNS 答案；应用失败不提交任何部分改动。lastAction 暴露本动作成功/失败及安全错误码，既有失败事件不因后来成功消失。原始查询、原始上游缓存及其他请求不受候选修改污染。所有终止方式继续统一协议收尾。

## 主动 TLS retry-config 探测（#22）

`{ "type": "probeEch", "options": { "hostname": "example.com", "port": 443, "serverName": "example.com", "alpn": ["h2"], "timeoutMs": 1500, "maxBytes": 65536, "cacheTtl": 60 } }` 仅调用通用 `lib/ech-probe` 的真实公开 probeEch API，取得的 ECH 数据仍需后续 applyEch 应用；不另造 TLS 客户端或把探测响应当 DNS 答案。

参数均为受校验的环境 JSON：hostname/port 为连接目标，serverName 为 TLS 身份/SNI（DNS 主机默认自身，IP 目标必须另填），alpn 为唯一 ASCII 协议名数组。verifyCertificate 默认 true；可显式 false 沿用库的未认证语义，但应用绝不因证书、网络或资源失败自动关闭验证、切来源或取静态厂商值。caCertificates 接受 PEM 字符串或 DER 字节数组列表，仅适用于开启认证；省略时用库默认信任根，错误证书/身份不会被缓存或伪装成成功。JSON 不接收 signal，运行时绑定当前请求取消信号。

一次未命中的动作只执行一次真实库探测，消耗与列表/归属/DNS 上游相同的网络额度。库负责 TLS 字节预算、完整握手、证书校验和 socket 清理；调用层限制总 deadline、单探测 timeoutMs/maxBytes 及取消。默认 maxEchProbeTimeoutMs=1500、maxEchProbeBytes=65536，硬上限分别 10000 和 1048576，字节上限最小 1024。动作参数只能缩短这些上限及总执行期限，不能通过 onError:continue 重置预算。超时、字节超限及其他失败分别保留 ECH_PROBE_TIMEOUT、RESOURCE_LIMIT、ECH_PROBE_FAILED 等脱敏结果。

cacheTtl 默认 0，显式设置 1..86400 秒才复用探测结果。缓存身份覆盖目标、身份、ALPN、认证政策、完整信任根、有效预算及期限的摘要，不向键写入明文配置。只缓存完整有效成功结果，读回重新校验，期限内仍可能被平台清理；过期不采用旧结果，而在当前显式动作内重新探测一次。更新失败按动作失败处理，不自动退回旧缓存。已成功取得的数据与 DNS 候选按动作隔离，后续可选失败保留前序成功状态，但不会把失败动作标成成功。

探测缓存 miss/hit、检测到的 expired 及新 acquired 状态产生带 requestId/动作定位的 ech_source_state 结构化信息日志；平台直接清理过期对象时只能观察 miss，不能臆造到期原因。失败仍走已有脱敏失败事件与 lastAction，不输出主机、完整 URL、证书或原始异常。缓存仅为数据中心本地加速层，不是全球新鲜性或目标认证的永久数据库。

### 验收边界与当前阻塞

普通回归通过真实 workerd 公共 DoH 入口连接受控本地 TCP 服务，验证单次连接、TLS 收包上限、超时、取消、清理和原答案保留；另保留通用 ECH Node/workerd 离线握手回归。`npm run test:ech-interop` 是独立本地 ECH-capable OpenSSL 的真实成功/证书失败/缓存路径验收，要求设置 ECH_PROBE_OPENSSL。它不放入默认测试后假装通过，不在缺少程序时以 skip 伪装成功。

当前 Windows 环境的 OpenSSL 3.5.5 不提供 ech 命令或 s_server -ech_key，历史 Linux ECH OpenSSL 路径也不存在，因此独立 OpenSSL 成功互操作尚未执行，#22 的该项验收仍阻塞；提供了可运行脚本，但不能宣称这等同成功互操作。主动探测的证书验证与完整握手是重型路径，elapsedMs/网络等待/后台执行均不能证明线上免费 CPU 合格；#25 仍需另行授权部署与实测。

## 可选 DNS JSON 查询接口（#23）

DNS_JSON 默认为关闭；仅接受布尔 true/false 或精确字符串 "true"/"false"，其他值为 INVALID_CONFIG。开启后，在与标准 DoH 相同的路径（含相同可选路径 Secret）使用 GET ?name=example.com&type=A&cd=false。name 必填；type 可省略为 A，也可为 DNS 类型名称或 0..65535 十进制代码；cd 可省略为 false，仅接受 true/false。名称及类型继续受标准 DNS 查询校验和大小约束，重复参数、未知参数或混入 dns= 均拒绝；参数名按 URL 解码后判断。

输出媒体类型 application/dns-json，使用通用 DNS 库 toDnsJson 对**最终 wire 响应**格式化：Status 为完整扩展 RCODE，TC/RD/RA/AD/CD 为布尔标志；Question 包含 name/type/class；Answer/Authority/Additional 记录包含 name/type/class/TTL/data（DNS 展示文本，包括未知类型的 RFC 3597 形式）。不声称不同供应商的 JSON 额外字段天然兼容。Accept 缺省或允许该类型时可用；显式 q=0 不被忽略。

这是输入/输出适配，不是第二套解析器：JSON 输入先生成受限 wire query，随后复用同一配置、规则顺序、上游/缓存、平台元数据、动作状态、失败回滚、协议及 DNSSEC 收尾。没有隐式默认上游。合法 NXDOMAIN 保持 HTTP 200 / Status 3；合法 DNS 查询在规则执行中失败或无答案保持 HTTP 200 / Status 2，不伪造成功记录。非法参数/HTTP 使用对应 400/405/406/414 等状态和 {error:{code,message}} 脱敏 JSON；配置不合法且尚未取得有效查询时为 HTTP 500。所有响应 no-store。

JSON 风格请求在功能关闭时为 404；JSON 查询只允许 GET（405 的 Allow 为 GET），不新增 POST JSON body 接口。标准 wire GET/POST 不变，且 JSON 开启不改变 wire 的 Accept 语义。路径认证在 JSON 参数解析、配置和网络工作前执行；未授权统一返回不含密钥的 404，不使用客户端上传的配置或认证请求头。应用日志不输出密钥路径或原始查询参数。
