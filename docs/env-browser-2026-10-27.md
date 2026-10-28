# 环境变量上线与浏览器 ECH 实测

## 已完成的生产变更

用户授权将纯环境变量方案写入superdoh并测试浏览器，随后补充main中的X/Pixiv IPv6策略。本次只更新31个运行时变量，没有上传任何Worker代码、push或运行代码部署。已备份原设置（当时bindings为空）、原部署及完整原模块，备份保存在忽略目录 `.acceptance/env-browser-20261027/`，不包含OAuth凭据。

- 变更前版本：9b2a5c1f-cc4f-47f5-b146-31106c15b05d。
- 变量更新后版本：321b9034-bbf8-448e-b52a-f812a6d5c950，100%流量；设置变更本身会产生版本，并非代码发布。
- 原模块与变更后独立下载模块SHA-256均为 `209ab06c48b59319efee096bcba1482f7dedea800b4c22ecf4484b6dfe124b56`。兼容日期/标志未变。
- remap列表：twimg.com、twitter.com、x.com、t.co、pixiv.net，含子域。最前面的规则对这些域名的AAAA直接返回空NOERROR，A正常解析，不声称这些网站天生没有IPv6。
- 配置源：[bindings.literal.json](../examples/meta-cf-ech-env-only/bindings.literal.json)、[说明](../examples/meta-cf-ech-env-only/README.md)（2026-10-27 的31变量历史快照；新17变量方案另列）。实际值与正式Worker绑定逐项比对一致。

Cloudflare MCP用于读取、独立核验生产状态。大量本地JSON通过无交互已授权API写入；第一次旧访问令牌返回401、尚未写入。Wrangler只读whoami自动续期成功后再执行，不曾打开登录浏览器。没有改Secrets、DNS路由、套餐或新增云端测试Worker。

## 正式DoH检查：10/10断言通过

向正式 `/dns-query` POST，串行且间隔至少1秒：

| 查询 | 实际结果 |
| --- | --- |
| www.facebook.com HTTPS | NOERROR，原名HTTPS，Meta ECH707字节、TTL300 |
| www.instagram.com HTTPS | 同上 |
| www.cloudflare.com HTTPS | NOERROR，包含CF ECH71字节 |
| crypto.cloudflare.com HTTPS | 同上 |
| x.com / www.pixiv.net / pbs.twimg.com AAAA | 各自NOERROR、空Answer |
| x.com / www.pixiv.net A | 各自仍有A记录 |
| www.cloudflare.com AAAA | 仍有IPv6记录，非全局关闭IPv6 |

这只能证明DNS配置下发和规则行为，不代表网站TLS握手接受。

## 浏览器实际握手

使用独立Firefox153.5.1临时配置，正常页面导航（headless/eager），证书验证保持开启，未登录网站。DoH设为本Worker、TRR-only；使用机器既有本地SOCKS5作为传输，并关闭SOCKS5远程DNS，保留浏览器自己的DoH/HTTPS记录查询。没有修改用户日常浏览器、系统DNS、注册表或代理设置。

浏览器响应通道读取原生 `nsITransportSecurityInfo.isAcceptedEch` 和 `usedPrivateDNS`，不是根据网页能打开推断。Cloudflare另有服务端trace交叉证据。所有有效导航均为TLS1.3、usedPrivateDNS=true。

| 页面/主机 | HTTP主文档 | ECH接受 | 说明 |
| --- | --- | --- | --- |
| www.cloudflare.com/cdn-cgi/trace | 200，两轮 | true，两轮 | 服务端同时返回sni=encrypted |
| www.facebook.com | 200 | false | 标题Facebook，Worker HTTPS查询完成，但不能认定ECH启用 |
| www.instagram.com | 200 | false | 标题Instagram，同上 |
| graph.facebook.com | 400 | false | 应用错误响应，ECH未接受 |
| facebook.com | 404 | true | 根域TLS握手确认接受ECH，但网页不是正常200；不能宣称整站访问成功 |

**结论：CF已验证实际浏览器ECH成功；Meta仅部分目标验证成功，不能宣称所有Meta网站正常启用。** 不能仅根据www/Graph失败断言整份历史配置已失效，因为根域有实际接受记录；也尚未确证具体差异源自CNAME路径、所选配置、服务端入口或其他兼容性。需要进一步定位才能作因果结论，未擅自修改IP或扩大Worker代码。

## 失败/对照与限制

- Chromium155独立配置的netlog确认安全DNS模板指向本Worker，但本机无代理直连导航18秒超时，没有主文档TLS结果，未作为ECH成功证据。
- Firefox初次使用旧的socks_remote_dns选项，当前版本实际SOCKS5仍远程解析：页面可能打开，但usedPrivateDNS=false、ECH=false。这一轮是无效Worker DNS路径/负对照，未算成功。
- 根据当前Firefox源码补上 `network.proxy.socks5_remote_dns=false` 后，原生日志确认Meta/CF HTTPS查询通过TRR完成；CF接受ECH且服务端交叉验证。复测使用全新配置，不混用前一轮缓存。
- 本次没有测试所有浏览器/网络/页面资源，也没有Free CPU profile；真实浏览器访问运行的是云端正式Worker，不是本地Miniflare行为套件。代理连接环境不同于用户所有日常网络；HTTP代理/远程DNS可能绕开浏览器ECH流程。
- 所有本次启动的独立浏览器进程均已退出。只清理本次临时浏览器数据，不动用户配置；原始网络日志/设置备份不作为公开材料，归档只留脱敏结果。

完整脱敏结果：[env-browser.json](results/2026-10-27/env-browser.json)。

依据：[Firefox原生握手状态接口](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/manager/ssl/nsITransportSecurityInfo.idl)、[Firefox SOCKS5 DNS开关实现](https://raw.githubusercontent.com/mozilla-firefox/firefox/main/netwerk/base/nsProtocolProxyService.cpp)、[Chromium DoH配置来源](https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/net/default_dns_over_https_config_source.cc)。判定以本次实测为准，不用文档或历史握手代替实际浏览器证据。
