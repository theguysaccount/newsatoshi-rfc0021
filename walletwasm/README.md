# Reproducible Browser Wallet Build (`ns_wallet.wasm`)

Builds the full Newsatoshi shielded post-quantum browser wallet (keys, `nsd1…` delivery scanning, light-client header & Merkle/channel root verification, nullifier non-inclusion checks, and client-side STARK spend proofs) into a deterministic `wasm32-unknown-unknown` binary.

```sh
rustup target add wasm32-unknown-unknown
./walletwasm/build.sh
```

`build.sh` copies `./node` and `./walletwasm` to the fixed directory `/tmp/newsatoshi-walletwasm-build`, remaps all host/registry/sysroot paths via `--remap-path-prefix`, and builds with `cargo build --release --locked --target wasm32-unknown-unknown`.

Verified byte-for-byte reproducible across clean builds on `rustc 1.100.0` (`v0.3.0-v2-prep`):
- Output: `walletwasm/target/wasm32-unknown-unknown/release/ns_wallet.wasm`
- SHA-256: `8e4cae979343a1dd829f807aadc3c2c3908aa4b8f6fdd2acc16263f5e6554c85`
