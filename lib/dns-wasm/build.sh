#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
# Install the tool matching Cargo.lock: cargo install wasm-bindgen-cli --version 0.2.129 --locked
version=$(wasm-bindgen --version)
if [ "$version" != 'wasm-bindgen 0.2.129' ]; then
  echo 'Expected wasm-bindgen 0.2.129 (matching rust/Cargo.lock)' >&2
  exit 1
fi
cargo build --manifest-path rust/Cargo.toml --target wasm32-unknown-unknown --release --locked
# cargo metadata handles CARGO_TARGET_DIR and absolute Windows paths.
target=$(cargo metadata --manifest-path rust/Cargo.toml --no-deps --format-version 1 | node -e 'let s="";process.stdin.on("data",c=>s+=c);process.stdin.on("end",()=>process.stdout.write(JSON.parse(s).target_directory))')
wasm-bindgen "$target/wasm32-unknown-unknown/release/superdoh_dns.wasm" --target web --out-dir . --out-name dns_bindgen
