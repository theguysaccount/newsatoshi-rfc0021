#!/bin/sh
# Reproducible build of the browser verifier.
#
# Cargo hashes the absolute path of a path dependency into symbol names, and the verifier
# depends on ../node by path, so a build depends on where the source sits. This script
# therefore copies the sources to one fixed path, builds there, and remaps every other
# machine-specific path. With rustc 1.97.0 (target wasm32-unknown-unknown) and this
# Cargo.lock, the SHA-256 printed at the end matches the verifier the site runs (§14).
set -e
SRC=$(cd "$(dirname "$0")/.." && pwd)
B=/tmp/newsatoshi-wasm-build
rm -rf "$B"
mkdir -p "$B"
(cd "$SRC" && tar --exclude=./node/target --exclude=./wasm/target -cf - ./node ./wasm) | (cd "$B" && tar -xf -)
REG=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/ | head -1)
RS=$(rustc --print sysroot)
cd "$B/wasm"
RUSTFLAGS="--remap-path-prefix=$B=/newsatoshi --remap-path-prefix=${REG%/}=/cargo --remap-path-prefix=$RS=/rust" \
  cargo build --release --locked --target wasm32-unknown-unknown
OUT="$SRC/wasm/target/wasm32-unknown-unknown/release"
mkdir -p "$OUT"
cp target/wasm32-unknown-unknown/release/ns_verify.wasm "$OUT/ns_verify.wasm"
cd "$OUT"
rm -rf "$B"
sha256sum ns_verify.wasm 2>/dev/null || shasum -a 256 ns_verify.wasm
