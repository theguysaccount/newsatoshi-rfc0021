# Newsatoshi Mainnet v2 External Security Audit Scope & Cutover Packet (`v0.6.0-zkvm`)

This document is the authoritative, zero-hype engineering scope packet for **two independent external security audits** required before activating **Newsatoshi Mainnet v2** (`RFC-0021` through `RFC-0027`).

> **Honest Pre-Cutover Status:** As of `v0.6.0-zkvm`, **0 of 2** external security audits have been completed and **0 of 3** independent real-difficulty Bitcoin AuxPoW merge-mining pools are live on Mainnet. All v2 consensus upgrades remain height-gated (`None`) on `v0.1.0` Mainnet/Testnet until both external audit reports and ≥ 3 independent pools are verified. Live cutover gate: `GET https://commons.newsatoshi.org/api/v2/cutover-readiness`.

---

## 1. Cryptographic & Consensus Scope Inventory (Exact SHA-256 Fingerprints)

| Component | File Path | SHA-256 Fingerprint (`shasum -a 256`) | Key Security Invariants to Audit |
| :--- | :--- | :--- | :--- |
| **Winterfell 0.13.1 Patch** | `node/vendor/winter-*` (`15` marked `NEWSATOSHI patch` sites) | Verify via `grep -rn "NEWSATOSHI patch" node/vendor/` | Haböck–Al Kindi (ePrint 2024/1037) constraint composition segment masking (ZK soundness & zero-knowledge); hostile-proof allocation DoS bounds |
| **Shielded Spend STARK** | `node/src/spend.rs` | `c550dd3f6cb836e3c91842986ab9382bb24d3ce53859dc5a0cc68ae93adb8528` | `249` Goldilocks AIR constraints, Constraint #247 balance conservation, Constraint #248 `< 2^60` note range check, no mod-`P` wrap-around, 384-bit FRI in `MAIN_V2` |
| **Universal Trust Bonds (`RFC-0024`)** | `node/src/bond.rs` | `03702b996093f5ec292bacce2b9d0d292913462cbe95216a70a5b2019932485e` | Anti-wash-trading `counterparty_vk != owner_vk`, exact slash conservation (`victim + burn + fee == slash`), ascending distinct arbiter quorum, unbond cooldown |
| **Sovereign L2 Rollup Vaults (`RFC-0023`)** | `node/src/rollup.rs` | `edfbff8515ec636ec5219e8ff5dda9b9d45929ad359b85166fd6a5726342ecae` | 128-bit list-decoding pure-SHA-2 STARK (`RollupBatchAir`), 63-bit bit-decomposition range proofs, exact TVL conservation, canonical `MerkleMap` exit + nullifier replay lock |
| **General-Purpose L2 zkVM (`RFC-0023`)** | `node/src/zkvm.rs` | `36469f288faf96f69eccea16347eaab55d19e724c1ae919cc03f7779dcca2393` | 40-column × 64-row register VM AIR (`ZkVmExecutionAir`, 52 constraints, 19 assertions, ≥ 128 proven bits), contiguous multi-shard state chaining into `RollupBatch` |
| **Mission Launchpads (`RFC-0027`)** | `node/src/mission.rs` | `e9a415d66556ff7417b909c6b16ec742d7c5cd57cce27ca84fa9f639f8715502` | Dual zero-rugpull treasury (`bounty_pool` never founder-withdrawable), exact `isqrt_u128` bonding curve, 100% trade fee → `bounty_pool`, exact contributor/public-goods split, `RFC-0024` anti-Sybil bond check |
| **PayWord Channels (`RFC-0022`)** | `node/src/channel.rs` | `b2b43c3d23046b922ce6c5567b563acf744c09caf3a07bf6d418614a51db6b6a` | Seller-authorized unilateral partial claim (`seller + refund + fee == deposit`), exact timeout refund, replay & over-claim rejection |
| **ASERT Launch Ramp & PoW** | `node/src/pow.rs` | `398c48c7020f84f0e0dd00658c3e495f232ce049fc3482101fd3ba06249851f9` | Continuous two-stage `aserti3-launch` (1 h half-life for first 2,016 blocks → 48 h steady-state), Day-1 anti-instamine convergence, timestamp clamping |
| **BIP-9 AuxPoW-Safe Signaling (`RFC-0026`)** | `node/src/signal.rs` | `d290cbe1e1021754c4645ce12fa75c33e251cc7bca9524c6d85a798e32ecb85d` | Header version bits `1..=7` (`0xfe`) non-collision with `VERSION_AUXPOW` (`0x100`) and `CHAIN_ID = 20051` (`0x4e53 << 16`) |
| **Selective Audit Viewing Keys** | `node/src/deliver.rs` | `f55d8bdfc909fa190d421ef601c02e005a7fe33f018b5b697a9ff132ce5f018a` | ML-KEM-768 `nsvk1…` read-only viewing keys decrypt memos without exposing spending key `sk` |
| **Consensus State & Snapshots** | `node/src/state.rs`, `node/src/snapshot.rs` | `a0e58936e759eb12d2d4cd158af698f96c43873232224e6c5750ead4a8008c7d` / `c408e3ad6db40c095fd6e7a43e0bf8333024278cfe6420a073e45e0320ed76dd` | Global solvency invariant `pool + locked + burned == issued`, canonical `DigestParts` roots, `nsSNAP03` snapshot persistence |
| **Lean 4.36.0 Formal Proof** | `node/proof/SpendBalance.lean` | `90c9d8b34e9f0c991e123a746f4b22e1dd0c4325b059d9585aaee4afa4786047` | 10 machine-checked theorems, `0 sorry`, zero Mathlib, standard core axioms only |

---

## 2. Reproducible Auditor Verification Commands

Every claim in this repository can be independently reproduced offline from source:

```bash
# 1. Full L1 unit suite (40 tests) + E2E clearinghouse/launchpad + adversarial red-team suite
cd node
cargo test --release --lib
cargo test --release --test clearinghouse_substrate --test audit_redteam --test light

# 2. Live L2 zkVM compiler -> 2x 128-bit STARK shards -> 1x RFC-0023 L1 RollupBatch STARK demo
cargo run --release --example zkvm_l2_dapp

# 3. Symbolic Z3 spend-circuit verification (249 constraints, 2,950 terms + 5 planted-bug self-tests)
cargo run --release --example extract_constraints > /tmp/constraints.json
python3 verify/check.py /tmp/constraints.json

# 4. Rust-extracted Lean 4.36.0 formal verification (10 theorems, 0 sorry)
cargo run --release --example extract_lean_spend -- proof/SpendBalance.lean
lean proof/SpendBalance.lean

# 5. Reproducible WASM light-client verifier build
cd ../walletwasm && ./build.sh
```

---

## 3. Mainnet v2 Cutover Requirements (Hard Non-Negotiable Gates)

| Gate | Requirement | Current Live Status |
| :--- | :--- | :--- |
| **Gate 1 — Audit #1** | Independent cryptography & consensus audit report published with all Critical/High findings remediated | **PENDING (`0/2`)** |
| **Gate 2 — Audit #2** | Second independent security audit of Winterfell patch, `spend.rs`, `bond.rs`, `rollup.rs`, `zkvm.rs`, `mission.rs` | **PENDING (`0/2`)** |
| **Gate 3 — Independent AuxPoW Pools** | ≥ 3 independent Bitcoin SHA-256 mining pools merge-mining `chainid = 20051` at real Bitcoin-grade difficulty | **PENDING (`0/3`)** — see `newsatoshi-commons/auxpow-stratum/MULTI_POOL_ONBOARDING.md` |
| **Gate 4 — Formal & Red-Team Suite** | 10 Lean 4 theorems (`0 sorry`), Z3 `249/249`, 128-bit STARKs, adversarial red-team tests, reproducible WASM | **PASSING** |
