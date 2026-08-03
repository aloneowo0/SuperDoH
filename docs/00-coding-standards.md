# SuperDoH-RS 代码规范基线(草案)

> 技术栈:**以 Rust 为主**;允许使用 JavaScript(构建脚本、胶水代码、测试),JS 部分遵循最新 JS 规范但**不强制严格**(宽松处理)。
> 本文档是代码编写的最低约束,不是完整指南。来源见文末。

---

## 1. 技术栈总则

| 层 | 语言 | 严格度 |
|---|---|---|
| Worker 本体(核心逻辑) | **Rust**(workers-rs / worker crate) | 严格,按第 2 节 |
| 构建脚本 / 配置生成 | JS(Node,允许) | 宽松,按第 3 节 |
| 前端 / 测试(如需要) | JS | 宽松 |

---

## 2. Rust 规范基线(严格)

### 2.1 工具链与 Edition

- **Edition 2024**(Rust 1.85.0 起稳定);`Cargo.toml` 写 `edition = "2024"`
- **工具链锁定 stable 1.88.0**(workers-rs 官方 rust-toolchain.toml 同款)
- panic 策略:默认 `panic=abort`;如需 unwind 恢复,`worker-build --panic-unwind`(需 **nightly + `-Z build-std=std,panic_unwind`**,按需启用,基线不默认)
- 2024 edition 注意点:async handler 的 RPIT 生命周期捕获(通常无碍);依赖含 `gen` 标识符的旧 crate(如 rand ≤0.8)需升级

### 2.2 rustfmt(全稳定选项)

```toml
# rustfmt.toml
edition = "2024"
style_edition = "2024"   # 必须显式写:直接跑 rustfmt 默认 2015,会导致编辑器/CI 输出不一致
max_width = 100          # 默认值,可省略
```

- ⚠️ `imports_granularity` / `group_imports` **2026 年仍未稳定**(需 nightly),稳定基线不用

### 2.3 Cargo.toml 体积优化配方(生态共识)

```toml
[lib]
crate-type = ["cdylib"]

[profile.release]
opt-level = "z"
debug = false
lto = true
strip = true
debug-assertions = false
codegen-units = 1

[package.metadata.wasm-pack.profile.release]
wasm-opt = ["-Oz", "--enable-bulk-memory", "--all-features"]
```

- ⚠️ worker-build 默认 wasm-opt 是 `-O` 不是 `-Oz`,**必须显式覆盖**
- worker 依赖建议 `default-features = false` + 按需 `features = ["http"]`

### 2.4 Clippy(cherry-pick,不用整组)

```toml
[workspace.lints.clippy]
pedantic = "warn"
unwrap_used = "deny"
expect_used = "deny"
cast_possible_truncation = "deny"   # 协议字节/长度转换密集,必开
cast_lossless = "deny"
```

- 现代惯例:`#[expect(...)]` 取代 `#[allow(...)]`(过期 allow 会被 `unfulfilled_lint_expectations` 抓住)
- **wasm 目标坑**:`--target` 必须放 `--` 前(`cargo clippy --target wasm32-unknown-unknown`);`cast_*` 按目标指针宽度判定(wasm32 usize 是 32 位)
- CI:`cargo fmt --check` + `cargo clippy --target wasm32-unknown-unknown -- -D warnings` + `cargo test`

### 2.5 错误处理(workers-rs 生态实况)

**直接用 `worker::Error`,不用 anyhow/thiserror**(tul、doh-edge 两个真实项目一致):

```rust
return Err(Error::RustError("Empty domain name".into()));
// 或带 context(生态无 anyhow 式 .context,手动拼):
.map_err(|e| Error::RustError(format!("bad base64url: {e}")))?
```

- `From<&str>` / `From<String>` 自动映射 `RustError`,`?` 直接可用
- handler 加 **`#[event(fetch, respond_with_errors)]`**:错误自动转 500 并回显信息
- `worker::Error` 的 `Display` 内置 `Caused by:` 链式输出

### 2.6 测试

```sh
# 纯逻辑(DNS 编解码/解析,不碰 wasm API)→ 普通 #[test],宿主跑
cargo test

# wasm API 相关 → #[wasm_bindgen_test] + runner
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --target wasm32-unknown-unknown

# E2E → miniflare + vitest(JS/TS 写,官方推荐)
# scriptPath: "./build/worker/shim.mjs" + modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }]
```

- `[lib] crate-type = ["cdylib"]` 时宿主 `cargo test` 只跑纯逻辑;要 wasm 集成测试加 `"rlib"`
- DNS 报文编解码是项目核心 → **优先用普通 `#[test]` 宿主测试**(快)

### 2.7 模块组织

- **单 crate**:`src/lib.rs` 入口(`#[event(fetch)]`)+ 模块拆分(`src/dns/`、`src/rewrite/`、`src/config/`、`src/error.rs` 等)
- **new style 模块文件**(`module.rs` + `module/` 子目录,不用旧 `mod.rs` 风格)
- 入口签名固定:`async fn main(req: Request, env: Env, ctx: Context) -> Result<Response>`

---

## 3. JS 规范基线(宽松)

> JS 只承担构建脚本/胶水/测试,规范从宽。底线 + 可用特性如下。

### 3.1 底线(必须遵守)

- **禁止**:`eval()`、`new Function`、`WebAssembly.compile*` / `instantiate(buffer)`(Workers 平台安全限制)
- 不用 `var`(用 `let`/`const`)
- 不用 `Math.random()` 生成 DNS 交易 ID(用 `crypto.getRandomValues`——防投毒)

### 3.2 规范基准

- **目标规范:ES2025(定稿)+ ES2026(2026-06-30 定稿)**
- **运行时基准:Workers V8 15.0**(2026-06-04,比 Node 26 的 14.6 还新;所有 Chrome stable 标准内置对象默认可用,零 flag)
- 构建脚本(Node):ES2025 全覆盖需 **Node ≥ 24**

### 3.3 可放心使用的新特性(零配置)

`Promise.try`、Iterator helpers、Set methods(union/intersection/difference)、`Array.fromAsync`、`Object.groupBy`/`Map.groupBy`、`Error.isError`、`Map.getOrInsert`、`Uint8Array` ↔ base64/hex(`toBase64`/`toHex`/`setFromBase64`/`setFromHex`)、`structuredClone`、`using`/`await using`

### 3.4 建议风格(不强制,写了就算达标)

- 可选链 `?.` / 空值合并 `??`(替代 `err && err.name || 'Error'` 等防御式)
- 模板字符串(替代 `'a' + b + 'c'` 拼接)
- async/await(替代 `.then()` 链)
- `Object.hasOwn`(替代 `hasOwnProperty.call`)

---

## 4. 参考来源

### Rust
- Edition 2024:https://doc.rust-lang.org/edition-guide/rust-2024/index.html
- Style Guide / style editions:https://doc.rust-lang.org/style-guide/、https://doc.rust-lang.org/style-guide/editions.html
- rustfmt(style_edition 稳定化):https://github.com/rust-lang/rustfmt/issues/5720
- Clippy changelog:https://github.com/rust-lang/rust-clippy/blob/HEAD/CHANGELOG.md
- workers-rs 仓库(模板/Cargo.toml/worker-build 源码):https://github.com/cloudflare/workers-rs
- Cloudflare Rust 文档:https://developers.cloudflare.com/workers/languages/rust/
- 生态参考实现:tul(https://github.com/yylt/tul)、doh-edge(https://github.com/vasie1337/doh-edge)

### JS
- ECMA-262 17th(ES2026):https://262.ecma-international.org/17.0/
- Workers Web standards(Chrome stable 承诺 + 禁止项):https://developers.cloudflare.com/workers/runtime-apis/web-standards/
- Workers Changelog(V8 版本轨迹):https://developers.cloudflare.com/workers/platform/changelog/

---

*草案状态:待评审。规范基线内容已由 2026-08 调查核实,版本号随上游更新。*
