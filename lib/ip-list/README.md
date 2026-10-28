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
