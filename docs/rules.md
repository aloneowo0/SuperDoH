# 环境变量规则执行器（JSON-only / #26–#27）

当前实现提供异步 `executeQuery` 和标准 DoH GET/POST。#26 已移除旧 #11 用户条件/动作代码扩展，DNS 行为仅由环境变量 JSON 的声明式条件和基础动作组成；异步网络、原始数据隔离、回滚及脱敏诊断继续保留。`test/worker.js` 只是旧规则测试适配器，生产入口为 `src/worker.js`。

**分阶段迁移**：#26 已移除用户代码扩展；#27 已移除旧默认补查、策略组和采用条件，改为显式命名单 HTTPS 上游与只读最近动作结果。核心不自动回退、重试、补查或竞速。TCP/TLS、缓存、外部来源与 ECH 动作待后续票交付。修订 #7 是目标规格，不是全部已实现声明；未部署、未做线上免费 CPU 验收，README 历史版本说明不是当前功能清单。

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

入口返回 `Promise<ExecutionResult>`，调用者必须 `await` 并处理拒绝（T4 将原同步入口迁移为异步）。仅显式上游查询动作执行网络 I/O；移除用户函数不改变网络异步契约。输入为 `Uint8Array` DNS 报文和 Workers 环境绑定对象；不读取文件、`process.env` 或请求中的配置。支持标准单问题 QUERY、根域或 ASCII 标签（字母、数字、连字符、下划线）；IDN 使用 punycode。拒绝响应报文、其他 opcode、截断查询、已有 Answer/Authority、非 OPT 的 Additional 和非零 EDNS 版本/扩展 RCODE。合法的 EDNS 0 查询可以处理，但此切片的自定义响应不回显请求的 OPT/ECS。

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
- 其他无关环境绑定不作规则解析；配置入口包括 `DNS_RULE_*`、`DNS_LIMITS`、`DNS_UPSTREAMS`，HTTP 入口还读取可选 Secret `DNS_PATH_KEY`。在其他名称的变量中放置规则不会启用规则。

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
| type: custom 动作 | INVALID_CONFIG；使用 answer、setTtl、rewriteQuery、queryUpstream、stop、return |
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
| `DNS_UPSTREAMS` | 可选命名 HTTPS 上游 JSON/JSON 文本，不能自行触发网络 |
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

### 显式命名 HTTPS 上游（#27）

`DNS_UPSTREAMS` 是独立 JSON 环境变量（也可为 JSON 文本），只保存连接信息。名称为 1–64 位 ASCII，首位字母，其余字母、数字或下划线；区分大小写。不预置厂商，不自动选择第一项。每项必须有 `transport: "https"`，且 `url` / `urlSecret` 恰好一个：

```json
{
  "A": { "transport": "https", "url": "https://resolver-a.example/dns-query" },
  "B": { "transport": "https", "urlSecret": "BACKUP_URL" }
}
```

`BACKUP_URL` 是 Workers Secret 的绑定名，值是完整 HTTPS URL。URL 最多 2048 字符，拒绝 userinfo、fragment 和非 HTTPS 协议；敏感路径/查询参数使用 Secret，不放源码或普通配置。TCP/TLS 尚未交付，`transport: "tcp"` / `"tls"` 会明确报 INVALID_CONFIG，不能写上后假装可用。未知字段、未引用的无效上游、缺失 Secret 和不可达动作中的坏引用都在任何动作/网络执行前失败。

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

一次动作只向指定上游发一次 POST wire 查询，不重试、切换上游或跟随重定向。目标只来自部署配置，客户端不能指定地址或上传配置。先校验 HTTP、媒体、消息大小、DNS/EDNS 版本及实际出站 ID/Question 对应性，再以新响应替换当前响应。所有协议有效且可表示的完整 RCODE 均算请求成功，包括 SERVFAIL、REFUSED、NXDOMAIN、NODATA；业务是否满意由下一条规则判断。HTTP 200 本身不等于 DNS 有效。

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
| 上游项缺少 transport，或包含 members、accept 等旧字段 | INVALID_CONFIG；每项仅 transport 和 url/urlSecret；采用判断移到后续规则 |
| maxUpstreamGroups、maxUpstreamMembers | INVALID_CONFIG；删除，使用 maxUpstreams 和共享资源预算 |
| UpstreamGroupConfig、upstream_failed、组成员索引、fallback/exhausted 处置、UPSTREAM_REJECTED/UPSTREAM_EXHAUSTED | 已移除；每次显式动作失败用 action_failed 及动作位置，后续成功不抹除既有事件 |

### 预算、清理和 DNSSEC

maxUpstreams 默认 16、硬上限 64；命名上游表及所有规则组各受 maxGroupBytes，并共同累计 maxConfigBytes。所有规则条件共同累计节点、正则指令和执行步骤。Secret URL 另受单 URL 2048 字符边界。

maxExecutionTimeMs 覆盖认证后的输入读取、执行器和网络响应读取；maxNetworkRequests（默认 2）在所有显式动作之间累计，失败也计数，DNS 回滚不重置；upstreamTimeoutMs 覆盖单次 headers/body 等待并受总 deadline 约束。更长顺序回退必须在硬上限内显式配置预算，不偷偷增加次数。客户端 Request.signal 与可信 options.signal 合并传播。

结束、失败或取消时清理计时器/监听器，取消未消费 body/reader，消费迟到 Promise 拒绝；合作式取消不保证远端立即停止。迟到完成不能提交回滚候选或污染其他请求。Node callback-service 对远端流 cancel 回调传播的可观测性有限，不据此声称远端所有资源释放或线上配额合格。

响应先对应当前出站查询校验，再恢复原始客户端 ID/Question/RD/CD。未经改写数据保留适用 AD/RRSIG（不代表本服务执行 DNSSEC 密码学校验）；TTL 修改清 AD 并仅移除被改 RRset 的失效签名；rewriteQuery 后的上游响应保守清 AD/全部 RRSIG；TSIG/SIG0 消息认证重新编码后不能沿用。当前基础动作不改 EDNS，保留对未来出站 EDNS 差异的防御：必要时清除不适用 OPT，扩展 RCODE 只能用原客户端 OPT 重建最小无 flags/options OPT，无法安全表示则 UPSTREAM_INVALID，绝不降为 NOERROR。提前返回、可选回滚与 SERVFAIL 都经过统一协议收尾。

本地测试仅使用受控上游，不发真实公共解析请求。未部署、未做线上免费 CPU/连接数或公网互操作验收。TCP/TLS、安全原始响应缓存、外部列表与 ECH 动作为后续票据，不能因 #27 完成声称新版 #7 全部完成。
