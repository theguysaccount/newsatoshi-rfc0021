#!/bin/sh
# Reproducible build of the browser wallet (keys, nullifiers, note scanning, and spend proofs).
#
# Cargo hashes the absolute path of a path dependency into symbol names, and the wallet
# depends on ../node by path, so a build depends on where the source sits. This script
# copies the sources to one fixed path, builds there with --locked, and remaps every
# machine-specific path so any builder using the same rustc + Cargo.lock reproduces the
# exact byte-for-byte SHA-256 of ns_wallet.wasm.
set -e
SRC=$(cd "$(dirname "$0")/.." && pwd)
B=/tmp/newsatoshi-walletwasm-build
rm -rf "$B"
mkdir -p "$B"
(cd "$SRC" && tar --exclude=./node/target --exclude=./walletwasm/target -cf - ./node ./walletwasm) | (cd "$B" && tar -xf -)
REG=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/ | head -1)
RS=$(rustc --print sysroot)
cd "$B/walletwasm"
RUSTFLAGS="--remap-path-prefix=$B=/newsatoshi --remap-path-prefix=${REG%/}=/cargo --remap-path-prefix=$RS=/rust" \
  cargo build --release --locked --target wasm32-unknown-unknown
OUT="$SRC/walletwasm/target/wasm32-unknown-unknown/release"
mkdir -p "$OUT"
cp target/wasm32-unknown-unknown/release/ns_wallet.wasm "$OUT/ns_wallet.wasm"
cd "$OUT"
rm -rf "$B"
sha256sum ns_wallet.wasm 2>/dev/null || shasum -a 256 ns_wallet.wasm
