# Reproducible Browser Wallet Build (`ns_wallet.wasm`)

Builds the full Newsatoshi shielded post-quantum browser wallet (keys, `nsd1…` delivery scanning, light-client header & Merkle/channel root verification, nullifier non-inclusion checks, and client-side STARK spend proofs) into a deterministic `wasm32-unknown-unknown` binary.

```sh
rustup target add wasm32-unknown-unknown
./walletwasm/build.sh
```

`build.sh` copies `./node` and `./walletwasm` to the fixed directory `/tmp/newsatoshi-walletwasm-build`, remaps all host/registry/sysroot paths via `--remap-path-prefix`, and builds with `cargo build --release --locked --target wasm32-unknown-unknown`.

Verified byte-for-byte reproducible across clean builds on `rustc 1.100.0` (`v0.4.0-substrate`):
- Output: `walletwasm/target/wasm32-unknown-unknown/release/ns_wallet.wasm`
- Exports include `viewing_key` (`nsvk1…` selective auditability) and `light_root` (`channels`, `bonds`, `rollups` Merkle root verification)
- SHA-256: `9c494b8726f32c46b149f6ab0c702c729aac5b2b076a42e850094aba92ee6690`
