# 环境变量规则执行器（T1 / #8）

本切片提供 `src/index.js` 的公共 `executeQuery(queryWire, env)`，在 workerd 中组合现有 DNS WASM 库。**尚不是公网 DoH 服务**：没有正式 HTTP 入口、认证、上游、缓存、ECH 动作或线上免费套餐 CPU 验收。`test/worker.js` 只是测试适配器，不能作为生产入口部署。README 描述的是历史版本，不是此切片的可用功能清单。

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

组合：`{"all":[...]}`、`{"any":[...]}`、`{"not":{...}}`。all/any 数组不能为空，嵌套深度最多 16（根节点为 0）。匹配组合逻辑可短路，但配置校验不短路。条件不隐式联网。

| field | op | value / 语义 |
| --- | --- | --- |
| `query.name` / `original.name` | `exact` | 当前/原始查询名精确匹配 |
| 同上 | `suffix` | 包含自身及子域，按标签边界；example.com 不匹配 notexample.com |
| 同上 | `subdomain` | 仅子域，不含自身 |
| `query.type` / `original.type` | `eq` | 类型名称或 0..65535 整数；名称由 DNS 库解析，如 A、AAAA、TYPE65280 |
| `response.exists` | `eq` | 布尔值；空答案也为 true |
| `response.rcode` | `eq` | 0..15 整数；尚无响应时为 false |

域名比较忽略 ASCII 大小写和单个末尾点；根域 `.` 的 suffix 匹配所有支持的域名，subdomain 排除根自身。不接受正则、通配符或外部域名列表引用，避免把未支持的语义当作普通未命中。

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

扩展函数、命名上游/列表引用、可选动作与回滚、来源补全、ECH 等属于后续切片。把这些字段放在规则中会得到 `INVALID_CONFIG`，不会宣称已经完成父规格的全部功能。

## 错误

`RuleError` 提供固定消息、稳定 `code` 和 `location`（可含 group、从 0 开始的 rule/action 索引）。

- `INVALID_CONFIG`：无效或尚不支持的配置。
- `INVALID_QUERY`：不支持或损坏的 DNS 输入。
- `NO_RESPONSE`：动作需要已有响应。
- `RESOURCE_LIMIT`：超出配置预算。

不附加原始 JSON/库异常文本、配置值、凭据、路径密钥或完整报文。由调用者为错误补充请求关联和日志处置，不应把 `env` 或完整 DNS 输入直接写日志。本切片没有线上访问路径，也不自动发送日志到外部服务。

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

`maxRecords` 计所有 answer 配置中的记录总数；maxConfigBytes 计所有规则组，不计无关绑定；maxResponseBytes 在统一收尾应用，stop/return 也不能绕过。规则组大小先检查再解析/编译，条件深度与总节点数均受限；平台 JSON 对象仍需序列化才能计数，因此可信部署配置本身不应包含异常巨大的对象。应用边界不能放宽 Cloudflare 平台变量大小/数量限制，也不证明任意规则规模满足免费套餐 CPU。

## 本地验证

```sh
npm ci
npm run typecheck
npm run test:rules
npm test
```

应用验收通过 Miniflare 4.20260730.0 / workerd 1.20260730.1，兼容日期为 2026-07-30，不启用 nodejs_compat（使用本地二进制支持的日期而非未来日期）。测试通过真实环境绑定与 wire 输入调用公共入口，独立 DNS wire 解码器检查响应；出站请求被测试边界禁止。根类型检查还包含既有 DNS/ECH 类型用例，完整测试包含两个库现有回归。

当前 registry 的最新 Miniflare 版本仍有 `sharp` / `undici` 传递开发依赖告警（`npm audit` 为 3 项 high，2026-10-20 检查）。它们只用于本地测试，不导入应用模块；尚未修复这些工具依赖告警，不把测试通过说成依赖安全审计通过。没有执行公网 DoH、真实上游或线上 CPU/免费配额验收，也没有推送或部署。
