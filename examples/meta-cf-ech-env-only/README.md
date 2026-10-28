# Meta / CF ECH 运行时配置

当前示例补齐 main 的 Meta 静态 IPv4 路由、Meta/重映射域名空 AAAA、任意匹配子域 HTTPS 重建，以及 X/重映射域名的 CF 优选地址与 ECH 合成。

- `bindings.json`、`dashboard.txt`：20 项示例变量，规则按显式 order 执行；不要和旧 CIDR 分片或旧 Meta 枚举规则一起追加使用。
- `meta-routes.json`：main 提交的 21 条精确映射和 8 条子域映射，包含来源 commit。
- `main-parity-report.json`：当前大小与来源；每变量小于5KB、整套约20KB。
- `report.json`：当前配置计数及历史验收记录；其中 `production` 是最初17变量 IP-list 切换的历史记录，不代表最新部署。
- `bindings.literal.json`、`report.literal.json`：更早的31变量历史快照，不是当前配置。

生成方式：

```sh
node scripts/generate-ip-list-ech.mjs
node scripts/generate-main-parity.mjs
```

示例 `DNS_PATHS` 仍是模板入口。应用到现有部署时，必须保留实际 `DNS_PATHS`、已按用户选择启用的 `DNS_ECS`、命名上游和其他无关绑定；不要用整套示例替换生产的访问配置。

`DNS_IP_LISTS` 从指定 HTTPS 来源取得 CF/Meta CIDR，成功数据缓存3600秒；规则使用 IP `inList` 匹配。缓存可被淘汰，不保证跨地区命中；过期更新失败不会伪装成成功。规则中的 CF 优选域名为 `cf.090227.xyz`，地址必须通过CF归属过滤，否则显式回退原解析。

首轮云端72项检查通过，覆盖静态映射、动态owner、IPv6策略、HTTPS合成、负响应保护、ECH来源回退、优选地址回退和DNSSEC失效处理。这不是用户本地浏览器的ECH接受或网络可达性测试。

[当前策略与验证说明](../../docs/main-parity-2026-10-28.md) · [当前云端证据](../../docs/results/2026-10-28/main-parity.json) · [历史IP-list发布记录](../../docs/ip-lists-production-2026-10-28.md)。
