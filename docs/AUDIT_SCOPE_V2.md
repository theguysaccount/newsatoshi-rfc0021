# Newsatoshi Mainnet v2 External Security Audit Scope & Cutover Packet (`v0.9.0-frontier`)

This document is the authoritative, zero-hype engineering scope packet for **two independent external security audits** required before activating **Newsatoshi Mainnet v2** (`RFC-0021` through `RFC-0027`). For direct auditor engagement & RFP terms, see [`docs/EXTERNAL_AUDIT_RFP.md`](./EXTERNAL_AUDIT_RFP.md).

> **Honest Pre-Cutover Status:** As of `v0.9.0-frontier`, **0 of 2** external security audits have been completed and **0 of 3** independent real-difficulty Bitcoin AuxPoW merge-mining pools are live on Mainnet. All v2 consensus upgrades remain height-gated (`None`) on `v0.1.0` Mainnet/Testnet until both external audit reports and ≥ 3 independent pools are verified. Live cutover gate: `GET https://commons.newsatoshi.org/api/v2/cutover-readiness`.

---

## 1. Cryptographic & Consensus Scope Inventory (Exact SHA-256 Fingerprints)

| Component | File Path | SHA-256 Fingerprint (`shasum -a 256`) | Key Security Invariants to Audit |
| :--- | :--- | :--- | :--- |
| **Winterfell 0.13.1 Patch** | `node/vendor/winter-*` (`18` marked `NEWSATOSHI patch` sites across 6 vendored crates) | Verify via `grep -rn "NEWSATOSHI patch" node/vendor/` | Haböck–Al Kindi (ePrint 2024/1037) constraint composition segment masking; hostile-proof allocation DoS bounds; UB-free raw-pointer concurrent FFT `permute` & Merkle `build_merkle_nodes` (eliminates upstream Winterfell 0.13.1 aliasing `&mut` slices under modern `rustc`/LLVM `noalias`) |
| **Shielded Spend STARK** | `node/src/spend.rs` | `67df47d6a7cee8d2651f916177c9726e0ec4a01f93e91f8fccc2a08e1a03e83a` | `249` Goldilocks AIR constraints, Constraint #247 balance conservation, Constraint #248 `< 2^60` note range check, no mod-`P` wrap-around, end-to-end 384-bit SHA-384 FRI (`192` proven classical bits / `128`-bit QROM) automatic dispatch in `MAIN_V2` + `PROOF_BYTES_CAP = 700_000` wire decoding |
| **Universal Trust Bonds (`RFC-0024`)** | `node/src/bond.rs` | `03702b996093f5ec292bacce2b9d0d292913462cbe95216a70a5b2019932485e` | Anti-wash-trading `counterparty_vk != owner_vk`, exact slash conservation (`victim + burn + fee == slash`), ascending distinct arbiter quorum, unbond cooldown |
| **Sovereign L2 Rollup Vaults (`RFC-0023`)** | `node/src/rollup.rs` | `7224c1730b7051485289bc98d0c65f8a3cc7ad4062fdc2ec13d3bcb181abfe31` | 192-bit classical / 128-bit QROM pure-SHA-384 STARK (`RollupBatchAir`) AND permissionless on-chain L1 `apply_zkvm_batch` verifying `1..=4` contiguous `ZkVmExecutionAir` STARKs pinned to `vault.post.vk_hash` + canonical `MerkleMap` exit & nullifier lock |
| **Turing-Complete LogUp zkVM (`RFC-0023`)** | `node/src/zkvm.rs` | `2036242272fa6ed0f9fdee684e724b88b488a66ea9338454b48111b068a27ebe9` | `81`-col main + `3`-col Haböck LogUp RAP aux trace (`256`-bit extension-field challenges), `6` verifier-constructed periodic ROM columns pinned to `program_hash == vault.post.vk_hash`, `13` opcodes incl. Turing-complete `JMP`/`JZ`/`JNZ`/`LT`, `32` base-4 (`d(d-1)(d-2)(d-3)=0`) exact 64-bit overflow/underflow range limbs in `f128`, lossless 3-limb 256-bit hash binding, `192`-bit SHA-384 FRI (`128`-bit QROM) |
| **Mission Launchpads (`RFC-0027`)** | `node/src/mission.rs` | `e9a415d66556ff7417b909c6b16ec742d7c5cd57cce27ca84fa9f639f8715502` | Dual zero-rugpull treasury (`bounty_pool` never founder-withdrawable), exact `isqrt_u128` bonding curve, 100% trade fee → `bounty_pool`, exact contributor/public-goods split, `RFC-0024` anti-Sybil bond check |
| **PayWord Channels (`RFC-0022`)** | `node/src/channel.rs` | `b2b43c3d23046b922ce6c5567b563acf744c09caf3a07bf6d418614a51db6b6a` | Seller-authorized unilateral partial claim (`seller + refund + fee == deposit`), exact timeout refund, replay & over-claim rejection |
| **ASERT Launch Ramp & Fair-Launch Params** | `node/src/pow.rs`, `node/src/params.rs` | `398c48c7020f84f0e0dd00658c3e495f232ce049fc3482101fd3ba06249851f9` / `e51c0013d0396063264836bd98c0f1639b3748c9b132cc76ae774f208abfbfe6` | Continuous two-stage `aserti3-launch` (1 h half-life for first 2,016 blocks → 48 h steady-state), isolated Mainnet v2 `nsM2` magic (`port 8445`, `MAIN_V2_DEFAULT_FEE = 800_000`, `MAIN_V2_MAX_TX_BYTES = 1_400_000`), `mmr_from = Some(0)`, `pq_transport = true`, Bitcoin-block-anchored `genesis-v2 --out` + `--genesis-v2` CLI boot |
| **BIP-9 AuxPoW-Safe Signaling (`RFC-0026`)** | `node/src/signal.rs` | `d290cbe1e1021754c4645ce12fa75c33e251cc7bca9524c6d85a798e32ecb85d` | Header version bits `1..=7` (`0xfe`) non-collision with `VERSION_AUXPOW` (`0x100`) and `CHAIN_ID = 20051` (`0x4e53 << 16`) |
| **Selective Audit Viewing Keys** | `node/src/deliver.rs` | `f55d8bdfc909fa190d421ef601c02e005a7fe33f018b5b697a9ff132ce5f018a` | ML-KEM-768 `nsvk1…` read-only viewing keys decrypt memos without exposing spending key `sk` |
| **Post-Quantum P2P Transport (`NSPQ1`)** | `node/src/pq_transport.rs` | `933297c8d97f6b295bdacebc3b6def83f7200cf7a8b395977e369c69e318ad5e` | Ephemeral NIST FIPS 203 `ML-KEM-768` + directional SHA-256-CTR + Encrypt-then-MAC keyed SHA-256 with monotonic 64-bit sequence counters, full-duplex `PqSender`/`PqReceiver` wired mandatorily into Mainnet v2 `node.rs` (zero plaintext downgrade) |
| **Eclipse Defense, Compact Blocks & Parallel Verify** | `node/src/peers.rs`, `node/src/node.rs` | `cb09cb9d9e6618edee3a50469aea868ee958d939080628a9d8c1a40d2a0160bb` / `3cbd2ca74ea02871ec4272271ee961c611f8223fb5a258967c52fac6e0a174ce` | `/16` IPv4 & `/32` IPv6 netgroup caps (`32` book, `8` inbound, 1 outbound per non-loopback netgroup), persistent `anchors.txt`, BIP-152-style `CompactBlock` (`>95%` STARK relay reduction), mandatory Mainnet v2 `NSPQ1` P2P encryption, multi-core parallel block STARK verification |
| **FlyClient MMR & Unified Light Client** | `node/src/light.rs` | `ff9fb5c694a8ca229b7c85a868fd191bfd0b73b43a8620d20d63bb9706ea96b3` | Consensus-committed $O(\log N)$ Merkle Mountain Range (`DigestParts::header_mmr` from Genesis #0 on Mainnet v2, Zcash ZIP-221 style) + Fiat–Shamir difficulty-weighted PoW proofs + unified `NoteTree`/`NfTree`/`MerkleMap` light verification + `GET /api/flyclient` |
| **Consensus State & Snapshots** | `node/src/state.rs`, `node/src/snapshot.rs` | `1d801f66664d777151b2da1f0bd613acc8b39cb63f5baa48250c5b2b35c09a95` / `70d654639cacca28d277da51508b3816f9df2f480600a5741cecc6f54c8f9090` | Global solvency invariant `pool + locked + burned == issued`, canonical `DigestParts` roots incl. Genesis-#0 `header_mmr`, `nsSNAP04` fast-boot snapshot persistence |
| **Utreexo 1 KB Compact Frontier** | `node/src/utreexo.rs` | `2be67b6e95728683bf1ed79512a9b43a45e3245f502767f87ec75d9ce4482585` | Constant `<= 1,024 B` RAM 32-peak accumulator bit-for-bit identical to `NoteTree` + $O(1)$ `TrackedNoteProof` updater feeding directly into `spend::prove` |
| **Disk-Backed Pruned KV Store** | `node/src/pruned_store.rs` | `971155b93502f07378e7c0ff1e576757b64fd05727fe76efb9aee59133211433` | Crash-safe WAL + sorted on-disk binary-searched SSTable `DiskKvStore` + Bitcoin-Core `-prune`-style `prune_chain_to_disk` / `load_pruned_checkpoint` |
| **SHA-384 STARK Recursion Primitives** | `node/src/recursion.rs` | `81efa1b60fb6c165428ed54a81e9bb524a0f7fdb9f7c8f451aa1fdc8255c2857` | Bit-exact FIPS 180-4 SHA-256d 80-byte PoW header-chain STARK (`HeaderChainAir`, 236 cols × 1,024 rows, 12 compressions/segment + segment folding) and algebraic FRI-folding verifier STARK (`FriFoldVerifyAir`), both pure SHA-384 (`>= 146`/`158` Goldilocks-cubic LDR bits, `128`-bit QROM) |
| **Independent Second Verifier Client** | `verifier-ts/newsatoshi_verifier.mjs` | `021fa4e61c28bbabf464878588cd2e55c4c05a23f0543c410c6ce99bc1ae6545` | Zero-dependency Node.js/OpenSSL/BigInt second consensus implementation (shares zero code with Rust `node/src/`) verified differentially against live Rust chains in CI |
| **Differential & Mutation Fuzz Harness** | `node/tests/differential_fuzz.rs`, `node/fuzz/` | `node/fuzz/fuzz_targets/{fuzz_wire_decode,fuzz_stark_and_zkvm,fuzz_p2p_and_flyclient}.rs` | Continuous Rust ↔ JS/OpenSSL differential cross-check + 10,000-iteration hostile wire/STARK/zkVM/P2P/FlyClient mutation fuzzer + `cargo-fuzz` / libFuzzer targets |
| **Lean 4.36.0 Formal Proof** | `node/proof/SpendBalance.lean` | `a8b1b4a3a45a43c8e67e4412eb82f89e155bc3d5fc0a353489de4a0c6a868316` | `14` machine-checked theorems (incl. zkVM base-4 range/ALU soundness, FlyClient MMR work conservation, & Theorem 14 `utreexo_frontier_and_fri_fold_uniqueness`), `0 sorry`, zero warnings, zero Mathlib, standard core axioms only |

---

## 2. Reproducible Auditor Verification Commands

Every claim in this repository can be independently reproduced offline from source:

```bash
# 1. Full L1 unit suite (46 tests) + differential JS/OpenSSL verifier + 10k mutation fuzzer + E2E + 8-test red-team suite
cd node
cargo test --release --lib
cargo test --release --test differential_fuzz --test clearinghouse_substrate --test audit_redteam --test light --test mainnet_params
node ../verifier-ts/newsatoshi_verifier.mjs --self-test

# 2. Live Turing-complete LogUp zkVM -> 2x 192-bit SHA-384 STARK shards -> 1x 192-bit RFC-0023 L1 RollupBatch STARK demo (~70 ms total)
cargo run --release --example zkvm_l2_dapp

# 3. Fair-launch Mainnet v2 Bitcoin-block-anchored genesis ceremony dry-run
cargo run --release --bin newsatoshi -- genesis-v2 \
  --btc-block-hash <FUTURE_64HEX_BTC_BLOCK_HASH> --btc-height <BTC_HEIGHT>

# 4. Symbolic Z3 spend-circuit verification (249 constraints, 2,950 terms + 5 planted-bug self-tests)
cargo run --release --example extract_constraints -- /tmp/constraints.json
python3 proof/check.py /tmp/constraints.json

# 5. Rust-extracted Lean 4.36.0 formal verification (14 theorems, 0 sorry, 0 warnings)
cargo run --release --example extract_lean_spend -- proof/SpendBalance.lean
lean proof/SpendBalance.lean

# 6. Reproducible WASM light-client verifier build
cd ../walletwasm && ./build.sh
```

---

## 3. Mainnet v2 Cutover Requirements (Hard Non-Negotiable Gates)

| Gate | Requirement | Current Live Status |
| :--- | :--- | :--- |
| **Gate 1 — Audit #1** | Independent cryptography & consensus audit report published with all Critical/High findings remediated | **PENDING (`0/2`)** — RFP ready in [`EXTERNAL_AUDIT_RFP.md`](./EXTERNAL_AUDIT_RFP.md) |
| **Gate 2 — Audit #2** | Second independent security audit of Winterfell patch, `spend.rs`, `bond.rs`, `rollup.rs`, `zkvm.rs`, `mission.rs`, `pq_transport.rs`, `light.rs`, `utreexo.rs`, `pruned_store.rs`, `recursion.rs` | **PENDING (`0/2`)** |
| **Gate 3 — Independent AuxPoW Pools** | ≥ 3 independent Bitcoin SHA-256 mining pools merge-mining `chainid = 20051` at real Bitcoin-grade difficulty | **PENDING (`0/3`)** — see `newsatoshi-commons/auxpow-stratum/POOL_OPERATOR_OUTREACH.md` & `verify-auxpow-pool.sh` |
| **Gate 4 — Formal, Multi-Client & Red-Team Suite** | 14 Lean 4 theorems (`0 sorry`), Z3 `249/249`, 192-bit SHA-384 FRI (`128`-bit QROM) full stack, LogUp ROM-bound Turing-complete zkVM, Utreexo 1 KB frontier + disk KV pruner, SHA-256d header-chain & FRI-fold STARKs, independent Node.js/OpenSSL verifier + 10k mutation fuzzer, ML-KEM-768 P2P + eclipse defense + Compact Blocks + FlyClient MMR, 8 adversarial red-team tests, reproducible WASM | **PASSING** |
