# `@superdoh/ip-list`

通用 IPv4/IPv6 地址与 CIDR 列表解析、索引和缓存；不内置厂商策略、来源 URL 或 Workers API。

```js
import { createIpListStore } from './index.js';
const store = createIpListStore();
const snapshot = await store.load({
  source: 'https://example.net/ranges.txt', format: 'text', cacheTtl: 3600,
  maxBytes: 262144, maxEntries: 4096, maxStates: 16, maxStateBytes: 4194304,
  load: async () => new TextEncoder().encode('192.0.2.0/24\n'),
  cache: { get: async key => undefined, put: async (key, data, ttl) => {} },
});
snapshot.index.contains('192.0.2.1');
```

示例里的 `load` 仅注入有效测试字节；生产实现应以调用方的受控 HTTPS 下载器和流式字节上限提供完整 `Uint8Array`，不要使用无界 `response.text()`。

格式仅支持严格 UTF-8 文本（逐行 CIDR/IP，允许空行和整行 `#` 注释）或 JSON 字符串数组。整份来源必须有效；非法条目、空列表、异常 UTF-8、超出条目/字节/状态限制均失败，不跳过坏行或截断。索引规范化同族重叠/相邻区间并二分查找。

`cacheTtl` 秒，默认 3600，0 关闭复用，上限 86400。内存 LRU 仅保存成功的已编译索引和时间/大小标量；注入的持久缓存只保存通过验证的原始文本与 `storedAt`，读取时重新编译。身份包括 URL/格式/TTL/限制/版本。过期即重新加载；来源失败不返回 stale 数据、不缓存失败。缓存 I/O 可由调用方视为 miss（`onError` 可传播取消、截止时间及资源限制）。

Workers 适配器使用 Workers Cache API。它是数据中心本地、可淘汰的 best-effort 缓存，不是全局或持久存储保证；3600 秒是最大复用期限，不是 DNS TTL。该库不保存跨请求 Promise、Response、reader 或 AbortSignal，也不合并并发加载。

## 预编译快照

`exportSnapshot(index, sourceBytes)` 导出有版本的区间快照，`restoreSnapshot(snapshot, maxEntries, maxBytes, maxStateBytes)` 验证并恢复不可变索引，复用同一个二分查找实现。恢复不再解析 CIDR、排序或合并；仍拒绝非法家族/位宽、倒置/重叠/相邻/未排序区间、空索引、未知版本和超限快照。原始文本条目数和字节数用于运行限制检查，快照对象变更不会改变恢复后的索引。

生产可使用 `DNS_IP_LISTS={"cloudflare":{"embedded":"cloudflare"},"meta":{"embedded":"meta"}}` 引用部署时内置索引。embedded 定义与 URL、format、cacheTtl 互斥，引用缺失或损坏必须失败，不回退到远程来源。适配器在 isolate 初始化时恢复成功索引，后续查询无列表 fetch、Cache API 或重新编译；DNS 响应本身的缓存仍按原策略工作。

部署说明见 `docs/embedded-ip-lists.md`。既有显式 URL 模式继续可用，但不是生产内置列表的备用通道。
