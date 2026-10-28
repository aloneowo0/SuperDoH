# IP 列表生产发布：2026-10-28

用户明确授权更新 Worker 环境变量、提交并 push。本次从现网基线 `be69de28` 在独立发布副本应用已验证的 IP-list 补丁，未发布本地 `13f6695` 的 lookupDns/ECH 合成/复用扩展，也未提交其他 CPU/TLS 工作区改动。

## 代码与变量

- 代码提交 `578934a34f7686cb6bae5c2e61f4f24448cba4f6` 已推送 `dev`；Cloudflare 自动构建 `86f84430-5be4-4a4a-8b05-db0048e7c47b` 成功，先发布代码并保留旧变量。
- 随后备份 settings、deployments、原始 multipart 模块及 Secret 名称/类型清单，才更新环境。备份位于本地忽略目录 `.acceptance/ip-list-20261028/production-apply-v3/`，不含 OAuth 凭据。两个预检失败均在写入前停止，失败备份也保留。
- 运行时变量从31项减为17项，规则组11个，旧17个CIDR分片均已移除。`DNS_IP_LISTS.cloudflare` 与 `.meta` 使用配置中的 GitHub HTTPS 文本来源，`cacheTtl` 均为3600秒。
- 变量切换前代码版本 `ee8858c4-dc75-4550-b7ab-7007023049be`；切换后版本 `55b4b80f-8240-4568-98bd-f6a069272580`，核验时100%流量。后续文档提交触发的同代码部署可能产生新版本，不代表变量回退。
- 主模块 SHA-256 为 `d94d78a55b595003315661776a91458fec50bb23575e91116b6cc2da372667fd`。兼容日期与四个flags均保持原值；无浏览器登录、Secret值写入、访问路径或套餐变更。
- Cloudflare MCP 独立 GET settings/deployments 确认17项变量、11组规则、无旧分片、TTL3600及空AAAA策略保留。

## 正式 DoH 检查：8/8

| 查询 | 结果 |
| --- | --- |
| www.cloudflare.com HTTPS | HTTP200 / NOERROR，ECH71字节 |
| www.facebook.com HTTPS | HTTP200 / NOERROR，历史Meta ECH707字节 |
| www.instagram.com HTTPS | 同上 |
| x.com / www.pixiv.net / pbs.twimg.com AAAA | 均为空NOERROR |
| example.net A / AAAA | 均返回对应地址记录，未全局禁用IPv6 |

请求串行、间隔至少1.05秒，无自动重试。本轮只验证正式DNS行为，不是浏览器ECH接受测试；不改变之前Meta仅部分目标实际接受的结论。列表的一小时到期边界在发布前云端受控时钟测试中验证，没有等待真实一小时。

[生产结果 JSON](results/2026-10-28/ip-lists-production.json) · [完整变量与使用说明](../examples/meta-cf-ech-env-only/README.md) · [发布前云端验收](ip-lists-2026-10-28.md)。
