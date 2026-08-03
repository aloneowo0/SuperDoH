# Meta CDN ECH 交接报告

最后重写时间：2026-05-30，Asia/Shanghai  
项目目录：`/home/aloneowo/DoH/superdoh`  
支持 ECH 的 OpenSSL 源码树：`/tmp/opencode/openssl-ech`  
支持 ECH 的 OpenSSL 可执行文件：`/tmp/opencode/openssl-ech/apps/openssl`

## 1. 结论

已成功获取并验证 Meta CDN 的 ECH 配置。

关键结论：本次测试过的 Meta CDN 域名没有通过公共 DNS HTTPS/SVCB 记录发布 `ech=`。可用的 ECHConfigList 是通过 Meta TLS ECH retry-config 路径获取的。

使用给定的 ECH-capable OpenSSL 构建验证成功，关键输出如下：

```text
Verify return code: 0 (ok)
ECH: success: 1
ECH: inner: scontent.xx.fbcdn.net
ECH: outer: scontent.xx.fbcdn.net
```

本次操作没有使用 sudo，也没有安装额外软件包。

## 2. 关键环境信息

`/tmp/opencode/openssl-ech/apps/openssl` 依赖同一构建目录中的动态库。运行时必须带上 `LD_LIBRARY_PATH`：

```bash
LD_LIBRARY_PATH=/tmp/opencode/openssl-ech \
/tmp/opencode/openssl-ech/apps/openssl version -a
```

实测版本：

```text
OpenSSL 4.0.0-dev  (Library: OpenSSL 4.0.0-dev )
platform: linux-x86_64
```

如果不设置 `LD_LIBRARY_PATH`，会失败并报错：

```text
error while loading shared libraries: libssl.so.4: cannot open shared object file
```

该构建的 `s_client` 支持以下 ECH 参数：

```text
-ech_config_list val       Set ECHConfigList, value is base64-encoded ECHConfigList
-ech_outer_alpn val        Specify outer ALPN value, when using ECH
-ech_outer_sni val         The name to put in the outer ClientHello
-ech_no_outer_sni          Do not send SNI in the outer ClientHello
-ech_select int            Select one ECHConfig from the supplied list
-ech_grease                Send GREASE values when not really using ECH
-ech_ignore_cid            Ignore the server-chosen ECH config ID
```

## 3. 公共 DNS HTTPS/SVCB 查询结论

通过 Google DoH 查询了 Meta 和 Meta CDN 域名的 HTTPS RR，类型为 65。

测试过的域名包括：

```text
www.facebook.com
facebook.com
m.facebook.com
graph.facebook.com
gateway.facebook.com
edge-mqtt.facebook.com
mqtt-mini.facebook.com
www.instagram.com
instagram.com
cdninstagram.com
static.xx.fbcdn.net
scontent.xx.fbcdn.net
video.xx.fbcdn.net
fbcdn.net
```

代表性结果如下：

```text
www.facebook.com.          CNAME star-mini.c10r.facebook.com.
star-mini.c10r.facebook.com. 65 1 . alpn=h2,h3
star-mini.c10r.facebook.com. 65 2 star-mini.fallback.c10r.facebook.com. alpn=h2,h3

facebook.com.              65 1 . alpn=h2,h3
facebook.com.              65 2 star-mini.fallback.c10r.facebook.com. alpn=h2,h3

scontent.xx.fbcdn.net.     65 1 . alpn=h2,h3
scontent.xx.fbcdn.net.     65 2 scontent.fallback.xx.fbcdn.net. alpn=h2,h3

video.xx.fbcdn.net.        65 1 . alpn=h2,h3
video.xx.fbcdn.net.        65 2 video.fallback.xx.fbcdn.net. alpn=h2,h3
```

所有测试到的公共 DNS 回答都没有包含 `ech=`。

也抽样查询了多个区域 CDN 域名，仍未发现 `ech=`。抽样域名包括：

```text
scontent-hkg4-1.xx.fbcdn.net
scontent-sin6-1.xx.fbcdn.net
scontent-nrt1-1.xx.fbcdn.net
scontent-lax3-1.xx.fbcdn.net
scontent-sjc3-1.xx.fbcdn.net
scontent-iad3-1.xx.fbcdn.net
scontent-lhr8-1.xx.fbcdn.net
scontent-fra5-1.xx.fbcdn.net
scontent-cdg4-1.xx.fbcdn.net
scontent-hkg4-1.cdninstagram.com
scontent-sin6-1.cdninstagram.com
scontent-nrt1-1.cdninstagram.com
scontent-lax3-1.cdninstagram.com
```

给下一个 agent 的结论：不要假设 Meta 公共 DNS 会返回 `ech=`。当前可用路径是 TLS retry-config 提取，或者将配置通过项目逻辑进行 out-of-band 注入。

## 4. Meta retry-config 获取过程

获取方法是：向 Meta CDN 提供一个故意无效的 ECHConfigList，让服务端返回 retry-configs。

### 4.1 生成用于探测的假 ECHConfig

```bash
LD_LIBRARY_PATH=/tmp/opencode/openssl-ech \
/tmp/opencode/openssl-ech/apps/openssl ech \
  -public_name scontent.xx.fbcdn.net \
  -out /tmp/opencode/meta-ech-probe.pem \
  -text
```

生成出的探测用 ECHConfigList 为：

```text
AEj+DQBEkwAgACCvBbx6kw66Lx8/4fjdSdljvBrucBqVD6USVtLF1FWVJAAEAAEAAQAVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA=
```

### 4.2 将无效探测配置发送给 Meta CDN

```bash
PROBE_ECH='AEj+DQBEkwAgACCvBbx6kw66Lx8/4fjdSdljvBrucBqVD6USVtLF1FWVJAAEAAEAAQAVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA='

LD_LIBRARY_PATH=/tmp/opencode/openssl-ech \
timeout 20 /tmp/opencode/openssl-ech/apps/openssl s_client \
  -connect scontent.xx.fbcdn.net:443 \
  -servername scontent.xx.fbcdn.net \
  -tls1_3 \
  -ech_config_list "$PROBE_ECH" \
  -no_ign_eof < /dev/null
```

关键输出：

```text
Connecting to 157.240.11.22
ECH: failed+retry-configs: -106
ECH: Got 10 retry-configs
```

测试时观察到的 IP 是 `157.240.11.22`。不要硬编码这个 IP，除非后续任务明确需要固定 IP。

### 4.3 将 OpenSSL 摘要输出还原为 ECHConfigList Base64

OpenSSL 会以人类可读摘要格式打印 retry-config，例如：

```text
ECH: 	[fe0d,08,scontent.xx.fbcdn.net,[0020,0001,0001],686a00a25e73001d3a6cb36519f9f5bf37fc117e545dc2706c89c6ba6ee9fc36,32,00]
```

这行内容不能直接作为 `ech=` 使用。必须先还原为二进制 ECHConfigList 格式，再进行 Base64 编码。还原脚本见第 8 节。

## 5. 已获取的 Meta ECHConfigList

下面是从 Meta retry-config 响应中还原出来的完整 10-entry ECHConfigList。使用时保持为单行。

```text
AsH+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAD+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAD+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAD+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA/g0ASwYAIAAgti54XaD8VhwGEmxjGpaxUkuAz3VmpQSMOFSRgSPchR0ABAABAAEyHHNjb250ZW50LWxheDMtMi54eC5mYmNkbi5uZXQAAP4NAEgEACAAINQS+ceVTWrz9nffBM163+nvpZ9k5F5WK51t4DAGG3ReAAQAAQABZBl2aWRlby1sYXgzLTIueHguZmJjZG4ubmV0AAD+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAD+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=
```

最适合 CDN 内容测试的单条配置如下：

```text
AEj+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA=
```

## 6. 条目清单

下面每一项都是单 entry 的 ECHConfigList。

```text
0  id=0x08  public_name=scontent.xx.fbcdn.net         max_name_len=50
   AEj+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA=

1  id=0x05  public_name=graph.facebook.com            max_name_len=50
   AEX+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAA=

2  id=0x09  public_name=video.xx.fbcdn.net            max_name_len=50
   AEX+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAA=

3  id=0x01  public_name=ech-public.atmeta.com         max_name_len=100
   AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=

4  id=0x03  public_name=video.xx.fbcdn.net            max_name_len=100
   AEX+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAA=

5  id=0x07  public_name=video-lax3-2.xx.fbcdn.net     max_name_len=50
   AEz+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA

6  id=0x06  public_name=scontent-lax3-2.xx.fbcdn.net  max_name_len=50
   AE/+DQBLBgAgACC2LnhdoPxWHAYSbGMalrFSS4DPdWalBIw4VJGBI9yFHQAEAAEAATIcc2NvbnRlbnQtbGF4My0yLnh4LmZiY2RuLm5ldAAA

7  id=0x04  public_name=video-lax3-2.xx.fbcdn.net     max_name_len=100
   AEz+DQBIBAAgACDUEvnHlU1q8/Z33wTNet/p76WfZOReViudbeAwBht0XgAEAAEAAWQZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA

8  id=0x00  public_name=facebook.com                  max_name_len=100
   AD/+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAA=

9  id=0x02  public_name=fbcdn.net                     max_name_len=100
   ADz+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=
```

## 7. 验证命令

### 7.1 验证单条 `scontent.xx.fbcdn.net` 配置

```bash
ECH='AEj+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA='

LD_LIBRARY_PATH=/tmp/opencode/openssl-ech \
/tmp/opencode/openssl-ech/apps/openssl s_client \
  -connect scontent.xx.fbcdn.net:443 \
  -servername scontent.xx.fbcdn.net \
  -tls1_3 \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  -ech_config_list "$ECH" \
  -no_ign_eof < /dev/null
```

实测成功输出：

```text
Verify return code: 0 (ok)
ECH: success: 1
ECH: inner: scontent.xx.fbcdn.net
ECH: outer: scontent.xx.fbcdn.net
```

### 7.2 验证完整 10-entry 列表

```bash
META_ECH='AsH+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAD+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAD+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAD+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA/g0ASwYAIAAgti54XaD8VhwGEmxjGpaxUkuAz3VmpQSMOFSRgSPchR0ABAABAAEyHHNjb250ZW50LWxheDMtMi54eC5mYmNkbi5uZXQAAP4NAEgEACAAINQS+ceVTWrz9nffBM163+nvpZ9k5F5WK51t4DAGG3ReAAQAAQABZBl2aWRlby1sYXgzLTIueHguZmJjZG4ubmV0AAD+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAD+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA='

LD_LIBRARY_PATH=/tmp/opencode/openssl-ech \
/tmp/opencode/openssl-ech/apps/openssl s_client \
  -connect scontent.xx.fbcdn.net:443 \
  -servername scontent.xx.fbcdn.net \
  -tls1_3 \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  -ech_config_list "$META_ECH" \
  -no_ign_eof < /dev/null
```

实测成功输出：

```text
Verify return code: 0 (ok)
ECH: success: 1
ECH: inner: scontent.xx.fbcdn.net
ECH: outer: scontent.xx.fbcdn.net
```

### 7.3 为什么需要 `-CAfile`

不加 `-CAfile /etc/ssl/certs/ca-certificates.crt` 时，有一次输出为：

```text
Verification error: unable to get local issuer certificate
ECH: BAD NAME: -102
```

在这个 OpenSSL 分支里，`SSL_ECH_STATUS_BAD_NAME` 可能表示 ECH 已经成功，但证书校验没有返回 `X509_V_OK`。它不一定表示 ECH 解密失败。加上 CA 文件后得到 `ECH: success: 1`。

## 8. 还原脚本

这个脚本会重新执行无效探测，解析 OpenSSL 打印的 retry-config 摘要行，还原二进制 ECHConfigList 格式，然后输出完整列表和每个单 entry 的 Base64。

```python
import base64
import os
import re
import subprocess
import sys

openssl = '/tmp/opencode/openssl-ech/apps/openssl'
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = '/tmp/opencode/openssl-ech'

probe = 'AEj+DQBEkwAgACCvBbx6kw66Lx8/4fjdSdljvBrucBqVD6USVtLF1FWVJAAEAAEAAQAVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA='

cmd = [
    openssl,
    's_client',
    '-connect', 'scontent.xx.fbcdn.net:443',
    '-servername', 'scontent.xx.fbcdn.net',
    '-tls1_3',
    '-ech_config_list', probe,
    '-no_ign_eof',
]

p = subprocess.run(
    cmd,
    input=b'',
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    env=env,
    timeout=25,
)
text = p.stdout.decode('utf-8', 'replace')

print('s_client_exit', p.returncode)
for line in text.splitlines():
    if line.startswith('ECH:'):
        print(line)

pat = re.compile(
    r'^ECH:\s+\[(?P<ver>[0-9a-fA-F]{4}),(?P<cid>[0-9a-fA-F]{2}),(?P<pn>[^,]+),'
    r'\[(?P<suites>[0-9a-fA-F,]+)\],(?P<pub>[0-9a-fA-F]+),(?P<max>[0-9a-fA-F]{2}),(?P<extcnt>[0-9a-fA-F]{2})\]$'
)


def enc_entry(ver, cid, pn, suites, pub, maxn, extcnt):
    if int(extcnt, 16) != 0:
        raise ValueError('cannot reconstruct non-empty extensions from printed summary')

    suite_parts = suites.split(',')
    if len(suite_parts) % 3:
        raise ValueError('unexpected suite triple list')

    content = bytearray()
    content.append(int(cid, 16))

    # OpenSSL 摘要会在每组 suite 中重复 KEM。
    # ECHConfig 中只存一个 KEM ID，然后存 KDF/AEAD pair 列表。
    kem = suite_parts[0]
    content += bytes.fromhex(kem)

    pub_b = bytes.fromhex(pub)
    content += len(pub_b).to_bytes(2, 'big') + pub_b

    pairs = bytearray()
    for i in range(0, len(suite_parts), 3):
        if suite_parts[i].lower() != kem.lower():
            raise ValueError('mixed KEM IDs are not representable in one ECHConfig')
        pairs += bytes.fromhex(suite_parts[i + 1]) + bytes.fromhex(suite_parts[i + 2])

    content += len(pairs).to_bytes(2, 'big') + pairs
    content.append(int(maxn, 16))

    pn_b = pn.encode('ascii')
    content.append(len(pn_b))
    content += pn_b

    # extensions length。本次观察到的 retry-config 都是 extcnt=0。
    content += (0).to_bytes(2, 'big')

    return bytes.fromhex(ver) + len(content).to_bytes(2, 'big') + bytes(content)


entries = []
for line in text.splitlines():
    m = pat.match(line.strip())
    if not m:
        continue
    d = m.groupdict()
    cfg = enc_entry(d['ver'], d['cid'], d['pn'], d['suites'], d['pub'], d['max'], d['extcnt'])
    entries.append((d, cfg))

if not entries:
    print('NO_RETRY_CONFIGS_PARSED')
    sys.exit(2)

full = b''.join(cfg for _, cfg in entries)
print('META_RETRY_CONFIG_LIST_BASE64=' + base64.b64encode(len(full).to_bytes(2, 'big') + full).decode())

for i, (d, cfg) in enumerate(entries):
    single = len(cfg).to_bytes(2, 'big') + cfg
    print(
        f"ENTRY {i} id=0x{d['cid']} public_name={d['pn']} "
        f"max_name_len={int(d['max'], 16)} base64={base64.b64encode(single).decode()}"
    )
```

## 9. 对本项目的集成建议

该仓库看起来是一个 Cloudflare Worker DoH 项目。如果下一个 agent 要把 Meta ECH 支持集成进来，建议方向如下：

1. 在处理 HTTPS/SVCB 响应时识别 Meta 自有域名或 Meta CDN 域名。
2. 保留已有 HTTPS/SVCB 参数，例如 `alpn=h2,h3`。
3. 使用上面的完整 Meta ECHConfigList 注入或合成 `ech=<base64>`；如果目标非常明确，也可以使用更窄的单 entry 配置。
4. ECHConfigList Base64 必须保持为一个精确字符串。除 DNS presentation format 必需的处理外，不要换行、转义或改写。
5. 增加一个验证路由或脚本，向 Worker 查询 HTTPS type 65，并确认响应中包含 `ech=`。

除非后续实时检查证明 Meta 会轮换这些 retry-configs，否则不要先实现轮换逻辑。本次观察到的 retry-config 集合来自 TLS retry-config，不来自 DNS，因此没有 DNS TTL 语义。

## 10. 已知注意事项

- 测试时公共 DNS 没有提供 Meta ECH。未来 Meta 部署策略可能变化。
- retry-config 集合是从 `scontent.xx.fbcdn.net` 获取的。不要在未测试前假设每个 entry 都适用于所有 Meta origin。
- 这个 OpenSSL 分支里的 `ECH: BAD NAME` 可能由证书验证失败导致，不一定是 ECH 失败。验证时使用 `-CAfile /etc/ssl/certs/ca-certificates.crt`。
- 不要把用户提供的 sudo 密码写入报告或代码。本次没有用到 sudo。
- 后续如果还要测试 ECH，请保留 `/tmp/opencode/openssl-ech`，除非系统 OpenSSL 已经具备等价的 ECH 支持。
