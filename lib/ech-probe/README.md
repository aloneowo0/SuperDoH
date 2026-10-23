# ECH Probe

供 **Cloudflare Workers** 使用的通用 TLS 1.3 ECH retry-config 探测库。连接目标、端口、SNI、ALPN 由调用方指定，没有默认业务域名。

运行时使用 `cloudflare:sockets`、Web Crypto 和静态 JS 模块；不需要 WASM、`nodejs_compat`、系统证书库或本地文件。PKI.js 等第三方实现以 vendored ESM 随库附带，调用方不必另装运行时 npm 依赖；来源、版本、许可和可重建脚本保留在库中。

**证书信任链和主机名验证默认关闭（`verifyCertificate: false`）。** 默认结果为 `authenticated: false`，不能确认目标身份；需要认证时必须显式设为 `true`，此时证书链和 SNI 身份必须通过验证。所有模式都必须验证 CertificateVerify、server Finished，并成功写出 client Finished 后才返回配置。证书验证失败不会自动降级为关闭验证。实现仍是有限范围的 TLS/ECH 探测器，不是经过独立安全审计的通用 TLS 栈。

## 使用

Worker 入口位于仓库根目录时：

```ts
import { probeEch } from './lib/ech-probe/index.js';

const result = await probeEch({
  hostname: 'your-server.example',
  port: 443,
  alpn: ['h2', 'http/1.1'],
  verifyCertificate: true, // 显式开启目标身份认证，不可省略
  timeoutMs: 8000,
});

console.log(result.authenticated);     // 上述显式 true 模式成功时为 true
console.log(result.handshakeComplete); // true，不代表 ECH 被接受
console.log(result.base64);
```

在请求或 scheduled 处理函数内调用，不要在模块顶层发起 socket 或密码操作。

### 默认未认证模式

```ts
const diagnostic = await probeEch({
  hostname: 'your-test-server.example',
  verifyCertificate: false,
});
// diagnostic.authenticated 的类型为 false。
```

`false` 只跳过 CA 信任链和 SNI 主机名检查，**不会跳过 CertificateVerify、Finished、记录 AEAD 或完整握手检查**。因此它不能确认对方身份，不能作为可信自动刷新来源；但也不会退回“解密出 EE 就成功”的旧行为。关闭验证时同时传入 `caCertificates` 会被拒绝，包括省略 `verifyCertificate` 却配置自定义 CA 的情况；不能把未认证结果标为已认证。

### 自定义 CA

```ts
const result = await probeEch({
  hostname: '192.0.2.10',
  serverName: 'ech.example.com',
  verifyCertificate: true,
  caCertificates: [myRootPem], // 替换默认信任根，不是追加
});
```

`caCertificates` 接受非空的 PEM/DER 证书数组。没有指定时采用库附带的 Mozilla/curl CA 快照；不访问宿主系统证书库，不把服务端附带的根证书当作可信锚，不自动在线下载中间证书或 CA。默认根快照的来源、日期、哈希和许可随构建产物保存；更新根集合需要重新构建和部署。

### 预检自定义信任根

`parseTrustAnchors(caCertificates)` 复用库内同一 PEM/DER 解析器，同步校验证书结构并返回隔离的 DER 副本；不联网，不建立信任链，不验证远端主机。调用者可在完整配置预检中拒绝损坏的信任根，而不是等到发起探测动作才发现。它不替代 probeEch 在显式开启认证时的运行时认证。

## API

### `probeEch(options)`

`hostname` 必填，DNS 名默认用作 SNI；连接 IP 时必须显式提供 DNS `serverName`。DNS 名规范化为小写并移除单个末尾点；IP 保持规范形式，IPv6 可输入括号形式，返回时不带括号。证书名称检查始终针对实际发送的 **serverName**，不是连接 IP 或另一个 hostname。

| 选项 | 默认值 | 约束 |
|---|---|---|
| `hostname` | 必填 | ASCII DNS 名、规范四段 IPv4 或 IPv6；不是 URL |
| `port` | 443 | 整数，1–65535 |
| `serverName` | DNS hostname | DNS SNI；连接 IP 时必填 |
| `alpn` | `[]` | 唯一 ASCII 0x01..0x7f 名称，每项 1–255 字节，总编码最多 12000 字节 |
| `verifyCertificate` | `false` | 严格 boolean；失败不自动降级 |
| `caCertificates` | 随库 CA 快照 | 非空 PEM/DER 数组，替换默认根集合；false 模式不可传 |
| `timeoutMs` | 8000 | 整数，1–60000；覆盖验证与客户端握手写入 |
| `maxBytes` | 65536 | 整数，1024–1048576；累计接收 TLS 字节，包括记录头 |
| `signal` | 无 | `AbortSignal` |

未知选项拒绝。所有路径启动 socket 关闭并释放读写锁；关闭拒绝会被消费，关闭停滞不会无限阻止返回。完整握手完成前的 ECH 配置不会以部分成功结果交给调用方；未认证模式不会被标记为已认证。

返回结构：

```ts
{
  authenticated: boolean; // 显式 true 模式成功为 true，默认/false 模式为 false
  handshakeComplete: true;
  target: string;
  port: number;
  serverName: string;
  elapsedMs: number;
  bytesReceived: number;
  bytes: Uint8Array;       // 完整 ECHConfigList，包含前置 uint16 长度
  base64: string;
  configs: (KnownEchConfig | UnknownEchConfig)[];
}
```

类型重载区分开启/关闭模式；动态 boolean 返回判别联合。`handshakeComplete` 表示本地已验证服务端握手并成功写出 client Finished，不表示服务器已确认接受 client Finished，更不表示 ECH 已被接受。

`elapsedMs` 是 Worker 内粗粒度经过时间，**不是 CPU 时间**，不包括调用者到 Worker 的 HTTP 往返。不能用它保证免费套餐的 CPU 限额。

### `parseEchConfigList(input)`

纯结构解析器，可从 `./config.js` 导入，不加载 socket 或 CA 验证代码，也可用于 Node 等提供 `btoa` 的环境。

```ts
import { parseEchConfigList } from './lib/ech-probe/config.js';
const parsed = parseEchConfigList(configBytes);
```

支持 ArrayBuffer、尊重 byteOffset/byteLength 的视图和合法字节数组；输出字节为副本。解析 0xfe0d 配置的 config ID、KEM、公钥、KDF/AEAD、最大名称长度、public_name 与扩展；校验边界、重复扩展、已知 X25519 公钥长度和主机名语法。未知版本保留 opaque contents。

`known: true` **只代表识别结构版本**，不代表配置可信、算法可用、未过期或被服务端接受。独立解析器不进行 TLS 认证；不要把解析成功当作 `authenticated: true`。

## TLS 与证书范围

- TLS 1.3，TLS_AES_128_GCM_SHA256；X25519，运行时明确不支持时回退 P-256。
- 发送故意无效的 ECH outer 扩展以获取拒绝后的 retry-config；不建立真实 ECH inner 连接，不保证任意服务器都会返回配置。
- 完整处理服务端 EE、可选初始 CertificateRequest、Certificate、CertificateVerify、Finished。需要时发送空客户端 Certificate，再发送 client Finished 和加密 ech_required 结束 alert；不发送应用数据。
- 两种开关模式均验证当前连接 transcript、CV 和 Finished，不通过另一条连接来替代本连接的证书证明。
- 默认身份验证采用 SAN DNS 匹配（不回退 CN）、证书路径、有效期、CA/用途/路径长度/名称约束检查；不支持的关键扩展或算法拒绝，不静默通过。
- 不提供在线 OCSP/CRL、CT 或浏览器额外根策略，不能宣称与浏览器全部证书策略等价。CA 快照不是永远有效的系统信任库。
- 不提供 TLS 1.2、HelloRetryRequest、PSK/恢复、STARTTLS、客户端私钥认证、通用应用数据会话或 ECH 接受确认。
- 支持 TCP/握手分片、多个消息共用记录、记录序列号、padding 和兼容性 CCS。
- 不内置配置缓存、静态旧配置回退、DNS 注入、KV 或 Cron；`test/fixtures/meta.json` 只是历史测试数据。

## Workers 兼容性

- 应使用 Workers 构建工具处理 ES module 导入。运行时没有 Node TLS、文件 I/O、操作系统 CA 查询或动态下载代码。
- `cloudflare:sockets` 的平台限制不因本库而消失，例如目的 IP 被平台禁止时仍会失败。不能保证所有 Cloudflare 托管域名都能从 Worker 原始 TCP 直连。
- 验证完整链比只提取 EE 消耗更多 CPU。官方 HTTP CPU 限额为 Free 10 ms、Paid 默认 30 秒；本地 workerd 兼容测试**不等于**线上免费套餐的 CPU 配额证明。正式部署应查看 Workers CPU/Wall time 指标，优先后台刷新、缓存结果，而不是每条 DNS 请求重新握手。
- `examples/worker.js` 只展示由服务端代码配置目标；不要无保护地将请求参数变成任意 socket 目标。示例不自动部署。

## 错误

参数错误为 TypeError/RangeError；运行时失败使用 EchProbeError.code：

| code | 含义 |
|---|---|
| `CERTIFICATE` | 证书、信任链、用途、约束或有效期验证失败 |
| `HOSTNAME` | 叶证书与 serverName 不匹配 |
| `CERTIFICATE_VERIFY` | CV 算法/公钥不符或签名错误 |
| `FINISHED` | Finished 验证或握手完成状态错误 |
| `TIMEOUT` / `ABORTED` | 总超时 / 取消 |
| `IO` | 连接、读写失败；保留 cause |
| `TRUNCATED` | 尚未完成所需服务端握手便 EOF |
| `LIMIT` | 接收/协议/证书预算超限 |
| `MALFORMED` / `UNSUPPORTED` | 非法结构/消息或未支持协商 |
| `TLS_ALERT` | 服务端 alert |
| `DECRYPT` / `CRYPTO` | 记录校验或密码操作失败 |
| `NO_RETRY_CONFIG` | 完成所需握手后没有可用 retry-config |

## 测试和重建

```sh
ECH_PROBE_TEST_TOOLS=/path/to/tools npm --prefix lib/ech-probe test

tsc --noEmit --strict --module nodenext --moduleResolution nodenext \
  --target es2022 lib/ech-probe/test/typecheck.ts
```

测试/构建工具要求 Node.js 22 或更新版本；部署运行时不要求 Node 兼容模式。测试配置日期取自安装的 workerd 版本，避免使用比二进制更新的兼容日期。离线套件在 Node 和不启用 nodejs_compat 的 workerd 中验证完整 flight、开关、证书与协议负例、资源清理；测试 CA 和私钥只在 test 下，不进入默认根集合。独立 OpenSSL 互操作测试另行运行，不要求普通离线测试访问公网或使用 Cloudflare token：

```sh
ECH_PROBE_OPENSSL=/path/to/ech-capable/openssl node lib/ech-probe/test/interop.mjs
```

该测试启动本地 OpenSSL ECH 服务端，从 workerd 的公开 API 通过真实 TCP 连接，验证默认/关闭模式、错误 SNI/CA，以及空客户端证书回复。OpenSSL 仅用于本地测试，不进入运行时依赖。

依赖重建使用 package-lock.json 锁定版本，构建脚本为 `npm run build:vendor` 与 `npm run build:trust-store`。更新信任根时应核对来源和记录新哈希，不能悄悄替换既有快照。

本库与 `../dns-wasm` 独立，不修改 DNS 报文库的接口或默认行为。

参考：[TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) · [Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/) · [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) · [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) · [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849) · [PKI.js](https://pkijs.org/)
