# 环境变量规则执行器（T1 / #8、T2 / #9、T3 / #10）

本切片提供 `src/index.js` 的公共 `executeQuery(queryWire, env, options?)`，在 workerd 中组合现有 DNS WASM 库。**尚不是公网 DoH 服务**：没有正式 HTTP 入口、认证、上游、缓存、ECH 动作或线上免费套餐 CPU 验收。`test/worker.js` 只是测试适配器，不能作为生产入口部署。README 描述的是历史版本，不是此切片的可用功能清单。

## 公共入口

```js
import { executeQuery, RuleError } from './src/index.js';

try {
  const result = executeQuery(queryWire, env);
  // result.termination: 'completed' | 'stopped' | 'returned'
  // result.response: Uint8Array | null
  // result.originalQuery: 深度只读原始查询，与输入和当前状态没有可变共享引用
  // result.query: 当前查询快照，包含 rewriteQuery 的成功修改
} catch (error) {
  if (!(error instanceof RuleError)) throw error;
  // error.code, error.message, error.location
}
```

入口是同步、无网络 I/O 的函数。输入为 `Uint8Array` DNS 报文和 Workers 环境绑定对象；不读取文件、`process.env` 或请求中的配置。支持标准单问题 QUERY、根域或 ASCII 标签（字母、数字、连字符、下划线）；IDN 使用 punycode。拒绝响应报文、其他 opcode、截断查询、已有 Answer/Authority、非 OPT 的 Additional 和非零 EDNS 版本/扩展 RCODE。合法的 EDNS 0 查询可以处理，但此切片的自定义响应不回显请求的 OPT/ECS。

规则正常结束是 `completed`；`stop` 是 `stopped`；`return` 是 `returned`。三者均经过统一输出收尾。

- `response === null` 唯一表示尚未取得响应；后续应用层可据此调用默认上游。本切片不执行该调用，也不自动生成 SERVFAIL。
- NOERROR 空答案、NXDOMAIN 均是已取得的响应，仍有 wire bytes，不是 `null`。
- `stop` 不要求已有响应；`return` 和 `setTtl` 在无响应时抛 `NO_RESPONSE`。
- 任何必需处理错误直接抛出，不返回部分成功结果；未来正式 DoH 层负责将执行失败映射成 DNS SERVFAIL，输入错误另行处理。

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
- 其他无关环境绑定不作规则解析；只有 `DNS_RULE_*` 和 `DNS_LIMITS` 是本切片的配置入口。在其他名称的变量中放置规则不会启用规则。

### 条件

条件以字段、操作符、值表达，结构全量预检并编译；每次规则进入时只求值一次。`all` / `any` 数组非空，分别 AND / OR；`not` 是布尔取反。执行可短路，校验不短路：未执行分支的未知字段、错误正则或错误参数仍使整个配置失败。条件没有网络、文件、DNS 查询、域名列表下载或归属补全等隐式副作用。

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
| `response.rcode` | 0..15 整数；无响应时缺失，不伪造 NOERROR |
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
executeQuery(queryWire, env, { context: {
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
| `answer` | `records`，可选 `rcode`（默认 0） | 以自定义响应替换当前响应；不隐式返回，不追加到旧答案。`records: []` 是合法空答案 |
| `setTtl` | `ttl` | 修改当前响应各普通记录 TTL；无响应报错 |
| `rewriteQuery` | `name` 和/或 `queryType` | 修改当前问题，仅影响后续动作及匹配，不修改原始查询，不自动重命名已有答案 |
| `stop` | 无 | 立即停止剩余动作及所有后续规则，保留当前响应/无响应状态 |
| `return` | 无 | 立即直接返回已有响应，无响应报错 |

记录包含 `name`、`type`、`ttl`、`rdata`，可选 `class`（默认 1）。TTL 为 0..4294967295 整数。RDATA 沿用 [`lib/dns-wasm/index.d.ts`](../lib/dns-wasm/index.d.ts) 的 native/Raw 模型，如 `Aaaa`、`Cname`、`Txt`、`Https`，不是 DNS 展示字符串。已使用的字段和类型/RDATA 对应关系必须通过库校验；未知 native 字段不能静默忽略。禁止自定义 OPT、TSIG、SIG、RRSIG 记录，本切片不支持携带认证声明或签名生成。

所有输出恢复原始请求 ID、Question、RD/CD，设置响应标识并清除 AD，经重新编码与 `matchResponse` 校验。显式 rewriteQuery 不自动改写记录 owner，记录名必须在 answer 中明确填写。答案全部来自自定义记录，不复制原始查询的签名或认证数据；没有上游响应，因而也没有可被 TTL 修改遗留的上游 RRSIG。后续接入上游时须对实际修改的 RRset 执行签名失效处理。

扩展函数、命名上游/列表引用、来源补全、ECH 等属于后续切片。把这些字段放在规则中会得到 `INVALID_CONFIG`，不会宣称已经完成父规格的全部功能。

## 错误

`RuleError` 提供固定消息、稳定 `code` 和 `location`（可含 group、从 0 开始的 rule/action 索引）。

- `INVALID_CONFIG`：无效或尚不支持的配置。
- `INVALID_QUERY`：不支持或损坏的 DNS 输入。
- `NO_RESPONSE`：动作需要已有响应。
- `RESOURCE_LIMIT`：超出配置预算。
- `INVALID_STATE`：动作产生无效工作状态或底层操作异常，原因仅保留安全分类。
- `INVALID_OPTIONS`：执行选项不符合公开契约。
- `INVALID_CONTEXT`：匹配上下文的结构、属性或地址键无效。

不附加原始 JSON/库异常文本、配置值、凭据、路径密钥或完整报文。`RuleError.reason` 在适用时只提供固定的安全错误分类和说明，不附带任意原始 cause 或 stack。执行器记录结构化失败事件；调用者仍不得把 `env` 或完整 DNS 输入写入日志。本切片没有线上访问路径，也不自动发送日志到外部服务。

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

`maxRecords` 计所有 answer 配置中的记录总数；maxConfigBytes 计所有规则组，不计无关绑定；maxResponseBytes 在每个生成/修改响应动作提交前及统一收尾应用，stop/return 也不能绕过；rewriteQuery 提交前检查编码后的查询大小。规则组大小先检查再解析/编译，条件深度与总节点数均受限；平台 JSON 对象仍需序列化才能计数，因此可信部署配置本身不应包含异常巨大的对象。应用边界不能放宽 Cloudflare 平台变量大小/数量限制，也不证明任意规则规模满足免费套餐 CPU。

条件深度根节点为 0，逻辑子项与集合 where 各增加一层。maxConditionValues 限制每个 in 的原始成员数，maxPatternLength 限制单个正则/通配符模式的 UTF-16 长度，maxPatternInstructions 限制全部组中 RE2 编译后指令数的总和（包括通配符）。这些检查在求值前覆盖所有分支。

maxConditionSteps 为每次 executeQuery 累计预算，不按组或规则重置：每访问一个条件节点计一步，每检查一个响应记录额外计一步，即使该记录不是地址、被 addresses 过滤也计入。短路之后未访问的项不计；省略 when 不访问条件节点。一个标量 in 已预编译成集合，计一次节点访问；正则使用线性时间引擎且模式规模另受上述限制。该计数不是毫秒/CPU 时间，也不是免费额度证明。maxContextAddresses 限制传入映射的项数，不只是匹配到的地址数；各属性长度另有限制。调用者必须提供合理规模的受信任对象，属性 getter 抛错会失败，不能保证任意自定义 getter 或超大输入对象的 CPU/内存开销。

## 本地验证

```sh
npm ci
npm run typecheck
npm run test:rules
npm test
```

规则测试通过 esbuild 0.28.2 将应用和 RE2JS 打包为 ESM（WASM 保留真实模块导入），没有替换正则或 DNS 库。应用验收通过 Miniflare 4.20260730.0 / workerd 1.20260730.1，兼容日期为 2026-07-30，不启用 nodejs_compat（使用本地二进制支持的日期而非未来日期）。测试通过真实环境绑定与 wire 输入调用公共入口，独立 DNS wire 解码器检查响应；出站请求被测试边界禁止。根类型检查还包含既有 DNS/ECH 类型用例，完整测试包含两个库现有回归。

当前 registry 的最新 Miniflare 版本仍有 `sharp` / `undici` 传递开发依赖告警（`npm audit` 为 3 项 high，2026-10-20 检查）。它们只用于本地测试，不导入应用模块；尚未修复这些工具依赖告警，不把测试通过说成依赖安全审计通过。没有执行公网 DoH、真实上游或线上 CPU/免费配额验收，也没有推送或部署。

## 失败事件与诊断参数

旧的两参数调用继续有效。第三参数可为调用提供请求标识与同步事件接收器：

```js
const result = executeQuery(queryWire, env, {
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

T2 回归通过同一公开 `executeQuery` 接口观察事件和 DNS 输出；“部分修改后失败”使用可选 answer 产生超限候选响应来验证，而不是添加测试专用动作。尚未提供自定义动作注册、上游、生产 HTTP 入口或自动线上日志服务。
