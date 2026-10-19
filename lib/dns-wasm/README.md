# DNS WASM

通用 Rust/WASM DNS 报文操作库，供 JS/TS 在 Cloudflare Workers 中使用。核心基于 **NLnet Labs `domain 0.12.3`**，通过原生记录类型、Serde 数据模型及 MessageBuilder 实现拆解、编辑、重建，不是旧 Worker 业务逻辑的 Rust 翻译。

- 无网络请求、CDN/地区规则、上游竞速或固定 ECH 公钥。
- 不自动添加 ECS、不强制 DO、不设置默认 OPT payload、不筛选 IP。
- 支持完整报文模型、记录级编解码和通用 EDNS/SVCB 辅助操作。
- WASM 在模块加载时通过 Workers 静态导入初始化，无需 `nodejs_compat`。

## 拆解 → 修改 → 重建

假定 Worker 入口在仓库根目录：

```ts
import { parseMessage, encodeMessage, TYPES } from './lib/dns-wasm/index.js';

function replaceAddresses(original: Uint8Array): Uint8Array {
  const message = parseMessage(original);
  const changed = [];
  for (const rr of message.answers) {
    if ('A' in rr.rdata) {
      rr.rdata.A.addr = '8.8.8.8';
      rr.ttl = 60;
      changed.push({ name: rr.name, rtype: TYPES.A, class: rr.class });
    }
  }
  // Explicitly invalidate DNSSEC metadata for changed RRsets; no re-signing.
  return encodeMessage(message, { invalidate_rrsets: changed });
}
```

`questions`、`answers`、`authority`、`additional` 都是可编辑数组，可增删、替换、移动记录；owner、type、class、TTL、RDATA 可修改。修改 rtype 时也需要提供对应 RDATA。

```ts
import { createMessage, buildQuery, buildResponse, encodeMessage, TYPES } from './lib/dns-wasm/index.js';

const query = buildQuery('example.com', TYPES.A, 0x4242);
const reply = buildResponse(query, {
  flags: 0x8180,
  answers: [{
    name: 'example.com', rtype: TYPES.A, class: 1, ttl: 300,
    rdata: { A: { addr: '1.2.3.4' } },
  }],
});
// An empty NOERROR response, NXDOMAIN, SERVFAIL, or another RCODE is caller-selected.
const nxdomain = buildResponse(query, { rcode: 3 });
const custom = encodeMessage(createMessage({
  id: 1, flags: 0,
  questions: [{ name: 'version.bind', rtype: TYPES.TXT, class: 3 }],
}));
```

`buildQuery` 默认 RD=1、class=IN、ID=0，可以传第四参数 `{ flags, class }` 覆盖；不会添加 EDNS。`buildResponse` 默认仅复制查询的 opcode/RD/CD，设置 QR，不自动设置 RA、复制 OPT 或填充应答。

## 数据模型

- `id`：u16；`flags`：完整 u16，**这是唯一参与编码的标志来源**。
- `parseMessage` 额外提供 `is_response/opcode/rcode/truncated` 只读快照；修改 flags 后快照不会自动更新。扩展 RCODE 使用 `getRcode`。
- Question：`{ name, rtype, class }`。
- RR：`{ name, rtype, class, ttl, rdata, data? }`。`data` 是展示字符串，编码忽略它；**编辑 `rdata` 而非 `data`**。
- 编码器重新计算 counts/RDLENGTH。输出采用无压缩名称；可解析输入的合法压缩，重建不会沿用旧指针。语义保持，不保证字节布局相同。
- owner/问题的根域输出 `.`。原生记录内部名称遵循上游表示，根域也可能为 `""`，适配层可往返两者。
- 字节输入支持 ArrayBuffer、带 byteOffset 的视图、number[]；模型里的字节数组也可以用 Uint8Array。

### 原生记录类型

结构化编解码直接使用 domain 的 ZoneRecordData 模型，涵盖：

```text
A AAAA NS CNAME PTR DNAME MX SOA SRV TXT HINFO CAA
NAPTR RP MB MD MF MG MR MINFO
DS DNSKEY RRSIG NSEC NSEC3 NSEC3PARAM CDS CDNSKEY
SSHFP TLSA IPSECKEY OPENPGPKEY ZONEMD
```

SVCB/HTTPS 和 OPT 在库原生解析基础上提供额外的参数/选项数组视图。NULL、TSIG、未被上游实现的 CERT 及其他未知记录使用 `{ Raw: number[] }`；已知类型的 Raw 输入仍需通过原生解析检查，不绕过长度校验。

常用模型示例：

```ts
({ A: { addr: '1.2.3.4' } });
({ Aaaa: { addr: '2001:db8::1' } });
({ Cname: { cname: 'target.example' } });
({ Mx: { preference: 10, exchange: 'mail.example' } });
({ Txt: ['hello', 'second string'] });
({ Raw: [0, 255, 192, 12] });
```

完整字段类型见 `native-rdata.d.ts`，38 类记录的实际往返样例见 `test/fixtures/native-models.json`。上游的二进制约定保持不变：例如 DS digest 是十六进制，DNSKEY/RRSIG/CDS 的对应字段使用 Base64，SSHFP/TLSA 等使用字节数组。TXT/character-string 使用 DNS 转义字符串，不能当作任意 UTF-8 或简单拼接字符。

独立操作 RDATA：`decodeRdata(rtype, bytes)` / `encodeRdata(rtype, value)`。这里的 bytes 必须是独立、未压缩的 RDATA；消息内压缩记录请通过 `parseMessage` 拆解。

## EDNS / ECS / EDE

```ts
import {
  parseMessage, buildQuery, setEdns, setEcs, encodeMessage,
  setEdnsOption, encodeEde, getEdns, getEcs,
} from './lib/dns-wasm/index.js';

const message = parseMessage(buildQuery('example.com', 1, 123));
// Payload and DO are explicit caller choices, not library policy.
setEdns(message, { udp_payload_size: 1232, flags: 0x8000 });
setEcs(message, { address: '2001:db8::1234', source_prefix: 56 });
setEdnsOption(message, 15, encodeEde({ code: 22, text: 'Caller-provided reason' }));
const output = encodeMessage(message);
```

- `getEdns` / `setEdns` / `removeEdns`：payload、扩展 RCODE、version、flags、所有选项。
- `setEdnsOption` / `removeEdnsOption`：按 code 编辑，替换时移除原来同 code 项；不影响其他 code。
- `encodeEcs` / `decodeEcs`、`setEcs` / `getEcs`：IPv4/IPv6、source/scope prefix、非整字节掩码。允许私网地址，合法性/隐私策略交给应用。
- `encodeEde` / `decodeEde`：错误码和 UTF-8 文本；非 UTF-8 EDE 仍可作为原始选项保留，但文本解码会报错。
- 创建 OPT 时必须提供 `udp_payload_size`；`setEcs` 不会隐式创建 OPT。
- `getEdns` 返回元数据快照。修改元数据用 `setEdns`，不能只改快照。
- `getRcode` / `setRcode`：0–4095；需要创建 OPT 时仍要求显式提供 payload。
- OPT 的 class 是 payload，TTL 保存扩展 RCODE/version/flags，**不能作为普通 DNS TTL 修改**。可用 `setEdns` 避免混淆。

## SVCB / HTTPS / ECH

```ts
import { TYPES, setSvcParam, encodeRdata } from './lib/dns-wasm/index.js';

const record = {
  name: 'service.example', rtype: TYPES.HTTPS, class: 1, ttl: 300,
  rdata: { Https: { priority: 1, target: '.', params: [] } },
};
setSvcParam(record, 1, ['h2', 'h3']);
setSvcParam(record, 3, 443);
// setSvcParam(record, 5, echConfigBase64); // supplied by the application
const rdataBytes = encodeRdata(TYPES.HTTPS, record.rdata);
```

| key | `encodeSvcParam` / `setSvcParam` 的值 | `decodeSvcParam` / `getSvcParam` 的值 |
|---|---|---|
| 0 mandatory | number[] | number[] |
| 1 ALPN | string[] 或 number[][] | number[][]，ALPN ID 是不透明字节 |
| 2 no-default-alpn | null | null |
| 3 port | number | number |
| 4 ipv4hint | string[] | string[] |
| 5 ECH | Base64/Base64URL 字符串 | 标准 Base64 字符串 |
| 6 ipv6hint | string[] | string[] |
| 其他 key | number[] | number[] |

`getSvcParam` / `setSvcParam` / `removeSvcParam` 编辑一个 RR；底层模型为 `params: [{ key, data }]`，可直接编辑所有键。编码使用原生 SvcParamsBuilder 排序并拒绝重复，保留未知键。

校验长度、mandatory 依赖、ALPN、hints、ECHConfigList 向量边界等；**不验证 ECH 公钥是否仍被服务器接受或实际握手是否成功**。AliasMode 的参数按 RFC 9460 保留；客户端应忽略它们，不能当成 ServiceMode 使用。

## 校验、展示与签名边界

- `validateMessage(wire)`：完整语法/结构检查，不强制单问题或 IN class。
- `matchResponse(response, query)`：额外匹配 QR、opcode、ID 和全部 question（QNAME 不区分大小写）。不验证上游网络来源，不验证 DNSSEC。
- `extractIPs(wire)`：提取 answer 中的 A/AAAA，返回地址、原始字节和 owner，不执行 CIDR 黑名单或 CNAME 信任判断。
- `typeCode` / `typeName`：原生类型名和 `TYPE65280` 等未知类型转换。
- `toDnsJson(wire)`：头标志、扩展 RCODE、Question/Answer/Authority/Additional 的展示表示。不是用于重建的无损模型。

普通 `encodeMessage` 不自动清 AD、TC、RCODE 或删除 RRSIG。修改已签名 RRset 后，可显式传入：

```ts
encodeMessage(message, {
  invalidate_rrsets: [{ name: 'example.com', rtype: 1, class: 1 }],
});
```

这会清 AD，并移除所有分区中覆盖指定 owner/type/class 的 RRSIG；不删除其他 RRset 的签名，也不重新签名。直接编辑模型后不使用此选项，维护正确签名语义是调用者的责任。

TSIG/SIG(0) 可以解析，但重新编码默认拒绝。显式传 `{ strip_message_authentication: true }` 才移除这些消息级认证记录。库不持有密钥、不提供认证能力。

## 范围与限制

- 这是 DNS **报文协议库**，不是递归 resolver、DNS server 或 Workers 网络栈。
- 不提供 DNSSEC/TSIG 加密验证或签名、DNS 缓存、zonefile 管理、AXFR/IXFR 会话、动态更新策略、IDNA 转换和 HTTP DoH 路由。
- 动态 UPDATE 等特殊上下文中的空 RDATA 已知类型，不属于本版已覆盖的记录模型；不能仅凭 opcode 字段可编辑就认定支持全部 UPDATE 语义。
- EDNS 选项提供通用原始数据接口；除 ECS 和 EDE 基本结构外，不保证所有已登记选项的完整语义校验。
- 未知类型按 RFC 3597 保留 opaque bytes；不解释未知私有格式里可能嵌入的旧报文指针。
- 输出无压缩，可能比输入大；超过 65535 字节返回错误，不自动截断或丢记录。
- 自带入口面向 Workers 静态 WASM 导入。Node/browser 若直接调用底层生成绑定，需要自行初始化 WASM，不是本版统一入口支持的运行方式。

## 构建和测试

源码在 `rust/`，发布使用 `index.js`、`index.d.ts`、`native-rdata.d.ts` 及 `dns_bindgen*` 文件。不要手改自动生成的绑定。

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
sh build.sh
cargo test --manifest-path rust/Cargo.toml --locked
```

本次验证 Rust 1.99.0、wasm-bindgen 0.2.129。构建建议使用本次验证的 Rust 版本；不要仅升级 CLI 而不匹配 Rust 端 wasm-bindgen 版本。Windows 使用原生 MSVC Build Tools 和 Git Bash，无需 WSL。

Workers 测试（在本目录）：

```sh
npm install
npm test
# Optional: tsc --noEmit --strict --module nodenext --moduleResolution nodenext --target es2022 test/typecheck.ts
```

Miniflare 仅为测试依赖。测试使用本地 workerd、38 类离线 RR 样本、21 个 DNS 真实响应快照、独立测试报文构造器，不要求运行时联网。真实快照为历史样本，不证明域名当前配置。Rust 测试另包含 4000 次确定性畸形输入扰动。

构建依赖下载可用 `HTTPS_PROXY` / `HTTP_PROXY`；不应把本地代理配置写入 Worker。

## 许可

封装代码沿用仓库许可；domain 为 BSD-3-Clause，见 `LICENSE.domain`。依赖许可见 `THIRD_PARTY_LICENSES.txt`。
