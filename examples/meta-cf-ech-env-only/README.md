# Meta / CF ECH 运行时配置

**截至 2026-10-28 的正式 Worker 是 17 变量，已通过生产 DoH 检查。** 对应代码提交为 `578934a`，未包含先前未发布的 ECH 执行器扩展。当前示例在这17项运行时变量之外新增 `DNS_PATHS`（`["/resolve", "/dns-query"]`），因此示例总计18项；这项代码/配置变更尚不代表已部署，`report.json` 中 `production` 字段保留原17变量发布记录。

- `bindings.json`、`dashboard.txt`：18项当前示例运行时变量，包含11个规则组；应整套配置，不能追加到仍启用的旧CIDR分片后面。
- `report.json`：当前示例配置大小、云端验收及历史生产切换记录。
- `bindings.literal.json`、`report.literal.json`：切换前31变量方案的历史快照，不是当前配置。

`DNS_IP_LISTS` 从明确配置的 HTTPS 链接取得 CF/Meta CIDR，缓存 TTL 为3600秒；规则使用 `item.ip` 的 `inList` 匹配。此期限与DNS答案TTL无关。内存索引与 Workers Cache API 复用成功数据，缓存可被淘汰且不保证跨地区命中；到期更新失败不返回过期数据作为成功结果。

保留既有Meta固定域名/HTTPS改写、CF来源回退及X/Pixiv/Twimg等域名的空AAAA政策，其他A/AAAA不全局禁用。生产8项DoH检查通过；这不是浏览器ECH接受测试，不改变先前Meta仅部分域名已知接受的结论。

[生产发布记录](../../docs/ip-lists-production-2026-10-28.md) · [生产结果](../../docs/results/2026-10-28/ip-lists-production.json) · [发布前34请求云验](../../docs/ip-lists-2026-10-28.md)。
