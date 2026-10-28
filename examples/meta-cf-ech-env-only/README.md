# Meta / CF ECH 环境变量配置候选

本目录同时保留已部署配置和未部署的新代码候选，二者不可混用。

- `bindings.literal.json` 是当前正式 Worker 配置快照：31 项变量，运行于生产基线 `be69de28`，配置版本 `321b9034-bbf8-448e-b52a-f812a6d5c950`。它使用 CIDR 分片，不依赖本次新增 IP 列表代码。
- `bindings.json`、`dashboard.txt`、`report.json` 是基于 IP 列表能力生成的**候选**，状态仍为 `candidate-not-deployed`。共 17 项变量、11 个规则组；已通过 2026-10-28 临时、生产基线派生候选的云端验收，但没有部署到正式 Worker，也不能将候选变量直接写入当前正式配置。
- `report.literal.json` 是生成候选前的配置报告备份。

候选以 `DNS_IP_LISTS` 定义 HTTPS 文本来源，规则只通过 `item.ip` 的 `inList` 引用。列表缓存 TTL 为 3600 秒，与 DNS 答案 TTL 无关。Workers Cache API 是数据中心本地、可淘汰的 best-effort 缓存，不保证全球或跨 isolate 命中；来源失败不会返回旧快照作为成功结果。

2026-10-28 云端验收在临时 Worker 上覆盖了列表来源/缓存/预算、780 条 Cloudflare 与 118 条 Meta CIDR 集合等价性、CF/Meta ECH DNS 及 Pixiv/Twimg 空 AAAA 策略（X 的原有配置策略亦保留）；两个临时 Worker 已删除，正式 Worker 的配置版本和 31 项 bindings 未变。验收详情见 [云端证据摘要](../../docs/ip-lists-2026-10-28.md) 与 [机器可读结果](../../docs/results/2026-10-28/ip-lists.json)。这不是浏览器 ECH 接受测试，不改变 Meta 仅部分域名已知接受的既有结论。
