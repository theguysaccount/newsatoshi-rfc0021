# Newsatoshi (`LOVE`) — Mainnet v2 (`nsM2` · `v1.2.1`)

[![Mainnet v2](https://img.shields.io/badge/Mainnet%20v2-LIVE%20%C2%B7%20BTC%20%23977%2C738-10b981)](https://newsatoshi.org/)
[![Zero Premine](https://img.shields.io/badge/Fair%20Launch-0%20LOVE%20Premine-f59e0b)](node/genesis-v2.json)
[![Consensus Crypto](https://img.shields.io/badge/L1%20Coins-FIPS%20SHA--2%2F384%20STARKs%20%2B%20SLH--DSA-38bdf8)](docs/newsatoshi-v2.2.pdf)
[![Lean 4](https://img.shields.io/badge/Lean%204.36-249%20AIR%20Identities%20%2B%2010%20Theorems-a855f7)](node/proof/SpendCircuitFull.lean)
[![Bug Bounty](https://img.shields.io/badge/Security%20Bounty-Paid%20in%20Mined%20LOVE-ef4444)](docs/BUG_BOUNTY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-zinc)](LICENSE)

**Private, post-quantum electronic cash secured by Bitcoin merge-mining (`AuxPoW`, `chainid = 20051`) — where all coin security and consensus proofs rest strictly on FIPS 180-4 SHA-2 (`SHA-256` / `SHA-384`) and FIPS 205 `SLH-DSA`, with zero elliptic curves, zero trusted setup, and zero novel algebraic ZK-hashes.**

- **Whitepaper (Satoshi-Format 8-Page PDF):** [newsatoshi.org/newsatoshi-v2.2.pdf](https://newsatoshi.org/newsatoshi-v2.2.pdf) · [Markdown Edition](docs/WHITEPAPER_V2_2.md)
- **Live Browser WASM STARK Verifier & Mainnet Status:** [newsatoshi.org](https://newsatoshi.org/) · [Live Seed JSON](https://newsatoshi-seed-v2.fly.dev/status)
- **Public Security Bug Bounty (Paid in Fair-Mined `LOVE`):** [newsatoshi.org/bounty/](https://newsatoshi.org/bounty/) · [docs/BUG_BOUNTY.md](docs/BUG_BOUNTY.md) · [Audit Scope & SHA-256s](docs/AUDIT_SCOPE_V2.md)
- **Layer-2 Agent Commerce & `nsUSD` Gateway (`newsatoshi-commons`):** [commons.newsatoshi.org](https://commons.newsatoshi.org/) · [RFC-0028 `nsUSD` Spec](docs/RFC-0028-NSUSD-SHIELDED-DOLLAR.md) · [Hyperscale Roadmap](docs/HYPERSCALE_ARCHITECTURE.md)

---

## Cryptographic Design & Exact Trust Boundaries

Newsatoshi targets a specific, extreme point on the cryptographic design frontier: **minimal-assumption, mandatory-shielded PoW money**.

- **Coin Security & Consensus Proofs (`100%` Hash-Based):** Every balance, nullifier, commitment, spend proof, and signature protecting funds rests solely on **FIPS 180-4 `SHA-256` / `SHA-384`** and **FIPS 205 `SLH-DSA-SHA2-128s`** — zero elliptic curves, zero pairings, zero lattices protecting coins, zero trusted setup, and zero novel algebraic ZK-hashes (`Poseidon`, `Rescue`, `Tip5`).
- **P2P Transport Encryption (`NSPQ2`):** Uses **NIST FIPS 203 `ML-KEM-768`** (lattice KEM) authenticated by **FIPS 205 `SLH-DSA-SHA2-128s`** peer-identity pinning (`node/src/pq_transport.rs`). A hypothetical break in `ML-KEM-768` affects transport confidentiality only — never coin ownership, supply soundness, or shielded note commitments.
- **Zero-Knowledge Spend STARK (`node/src/spend.rs`, `MAIN_V2`):** Mandatory 2-in/2-out shielded spends (`8,192 × 247`, `249` Goldilocks AIR constraints) using **Quartic Goldilocks ($\mathbb{F}_{p^4} = \mathbb{F}_p[x]/(x^4 - 7)$)**, **`SHA-384`** Merkle/Fiat–Shamir, `blowup = 8`, `queries = 152`, `grinding = 20`, and **Haböck–Al Kindi (ePrint 2024/1037)** masked quotient segments in a vendored, patched Winterfell 0.13.1 (fixing upstream `f64::BaseElement::double()` and `mul_small()` canonicalization bugs).
- **Soundness Formula (Reproducible in `node/src/spend.rs`):** Classical proven LDR = `192` bits (`min(384/2, unclipped_ldr)` where `unclipped_ldr = 208.4 / 204.4 / 202.4 / 200.4` for `K = 1 / 4 / 8 / 16`). Conservative CMS19 QROM quantum FRI soundness = `min(384/3, unclipped_ldr/2)` = **`104 / 102 / 101 / 100` bits** alongside `128`-bit BHT `SHA-384` collision resistance.
- **Bitcoin Merge-Mining (`AuxPoW`, `chainid = 20051`):** Existing Bitcoin SHA-256 ASICs can merge-mine Newsatoshi with zero extra electricity, paired with a continuous two-stage `aserti3-launch` difficulty ramp (1h half-life for blocks `1..2,016` → 48h steady-state ASERT). *Security note: actual PoW security equals the real Bitcoin hashrate that opts into merge-mining Mainnet v2.*

---

## Live Mainnet v2 (`nsM2` · `v1.2.1`) — Join in 60 Seconds

- **Canonical Genesis Hash:** `00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8`
- **Bitcoin Anchor:** Block `#977,738` (`0000000000000000000163900064a4cc4807dbd8bcaf35e322e694e6c387a780`) — [genesis-v2.json](node/genesis-v2.json)
- **Fair Launch:** `0 LOVE` premine, `50 LOVE/block` halving to a perpetual `0.1953125 LOVE/block` tail floor + permanent **50% base-fee burn**.
- **Zero-Fee Bitaxe / ASIC AuxPoW Solo Pool:**
  ```text
  Stratum URL: stratum+tcp://pool.newsatoshi.org:3333
  Worker:      <YOUR_MAINNET_V2_ns1_ADDRESS>.rig1
  Password:    x
  ```
- **Run a Full Mainnet v2 Node + Multi-Threaded Miner (`NSPQ2` Authenticated P2P):**
  ```bash
  git clone https://github.com/theguysaccount/newsatoshi-rfc0021.git
  cd newsatoshi-rfc0021/node
  cargo build --release --bin newsatoshi

  ./target/release/newsatoshi --net mainnet-v2 address
  ./target/release/newsatoshi --net mainnet-v2 node \
    --peer newsatoshi-seed-v2.fly.dev:8445@b024aaeafa0e4ca384b99483c28c3bedde45a5461a560063b283766414dfbbcc \
    --peer pool.newsatoshi.org:8445@78187a9436dd2d8cc7ed7afff2396b72b56687099d45d93da676b0a90ed8c6b6
  ```

---

## Head-to-Head L1 Comparison (Honest Trade-Offs)

| Property | Bitcoin | Zcash (Orchard) | Monero | Neptune Cash | **Newsatoshi L1 (`LOVE` `v1.2.1`)** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Default Privacy** | Transparent | Opt-in Shielded | RingCT (decoys) | Default Shielded | **Mandatory Shielded (Full Note Tree)** |
| **Post-Quantum Coins** | No (`secp256k1`) | No (Pasta curves) | No (Ed25519) | Yes (Tip5 STARKs) | **Yes (FIPS SHA-2/384 STARKs + SLH-DSA)** |
| **Hash Conservatism** | FIPS SHA-256 | Sinsemilla / Blake2 | Keccak / Ed25519 | Novel Algebraic (`Tip5`) | **100% FIPS SHA-2 (`SHA-256`/`SHA-384`)** |
| **Single Spend Proof Size** | ~250 B (public) | **~5 KB** (Halo 2, audited) | ~1.5 KB (BP+) | **~30 KB** (Triton VM) | `~603 KB` single · **`~93 KB/spend` (`K=8`)** · `~49 KB` (`K=16`) |
| **Chain Recursion (Live)** | None | None | None | **Live (CPU IVC)** | **FlyClient MMR live** *(pure-SHA-2 IVC in `recursion.rs` is R&D prototype)* |
| **Bitcoin Merge-Mining** | Native | No | No | No | **Yes (`AuxPoW chainid = 20051`)** |
| **Native BTC/LN Atomic Swaps** | Native | Complex | Adaptor sigs | No native SHA-256 | **Native `SHA-256` HTLCs + `O(1)` PayWords** |

**Where Newsatoshi L1 wins:** Strictest hash-only cryptographic conservatism (`FIPS SHA-2` only, zero elliptic curves, zero novel algebraic hashes) + Bitcoin AuxPoW merge-mining + native SHA-256 HTLC/PayWord compatibility + symbolic Rust-to-Lean-4 AIR checking.  
**Where peers beat Newsatoshi L1 today:** Zcash Orchard (`~5 KB` audited proofs, non-PQ) and Neptune Cash (`~30 KB` Tip5 proofs + shipping chain recursion) have substantially smaller proofs and longer external audit/review history; delegated multi-user `BatchSpend` reveals spend witnesses to the batch prover (self-batching has zero privacy loss).

---

## Measured Mainnet v2 Production Benchmarks (`node/src/spend.rs` & `batch_spend.rs`)

Measured on Apple Silicon CPU (`cargo test`, `opt-level = 2`, deps `opt-level = 3`):

| Live Mainnet v2 Operation (`MAIN_V2`, Quartic $\mathbb{F}_{p^4}$, SHA-384) | Proof Size | Per-Spend Size | Prove Time | Verify Time | Conservative QROM (CMS19) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Single Shielded Spend (`K = 1`) | `~603 KB` | `~603 KB` | **`~0.30 s`** | `~25 ms` | **`104` bits** (`192` classical) |
| `BatchSpend` (`K = 4`, wired in consensus) | `~695 KB` | `~174 KB` | **`~0.68 s`** | `~26 ms` | **`102` bits** (`3.47×` comp) |
| `BatchSpend` (`K = 8`, wired in consensus) | `~741 KB` | `~93 KB` | **`~1.28 s`** | `~38 ms` | **`101` bits** (`6.51×` comp, ~80 spends / 8 MB) |
| `BatchSpend` (`K = 16`, wired in consensus) | `~790 KB` | `~49 KB` | `~3.0 s` | `~70 ms` | **`100` bits** (`12.2×` comp) |

**Experimental R&D Prototype (Not Wired Into Mainnet v2 Consensus):**
- `node/src/recursion.rs` (`StarkInStarkVerifierAir`, `254 × 16,384`, `404` constraints) is an executable pure-SHA-2 STARK-in-STARK folding prototype (`newsatoshi ivc-prove`, `~671 KB` proof, `~36–114 ms` verify) that executes `204` bit-exact SHA-256 compressions + all `10` Quartic FRI folds in-circuit. **Explicit limitation (`recursion.rs:32–38`):** the CPU-sized inner AIR authenticates Merkle paths for **1 of 152** outer queries and omits full out-of-domain constraint evaluation, so it is a working recursion gadget — **not** yet a full-soundness recursive chain verifier. Live Mainnet v2 light clients verify headers via **work-proportional FlyClient MMR** (`node/src/light.rs`) and `1 KB` Utreexo frontiers (`node/src/utreexo.rs`).

---

## Exact Formal Verification & Audit Scope (Zero Ambiguity)

1. **`node/proof/SpendCircuitFull.lean` (Lean 4.36.0 pure kernel, `0 sorry`, `0 native_decide`, `0 Mathlib`):**
   - `extract_lean_circuit` symbolically executes live compiling Rust `spend::eval_constraints` (spot-checked at 20 random Goldilocks points) and emits all **249 transition constraint polynomials (`#0..#248`, `2,950` monomials)**.
   - Proved theorems: independent NIST FIPS 180-4 `SHA-256` vector match (`""`, `"abc"`), multilinear bit-polynomial identities (`XOR2`, `XOR3`, `Ch`, `Maj`, `< 2^32`), **`all_249_constraints_match_fips180_4_spec`** (`rustCon i = fipsCon i := by decide`), all **7 Goldilocks no-wrap / unreduced-word lemmas** (`a_64`, `e_64`, `W_0`), 64-round compression & 32-level Merkle inductions, and exact 128-block layout counts.
2. **`node/proof/SpendBalance.lean` (Lean 4.36.0, 10 theorems, `0 sorry`, `0 Mathlib`):**
   - Proves value conservation (`#247`/`#248`), `< 2^60` note range, PayWord channel accounting, 50% fee-burn solvency, `PriorLock` 50/50 bounty/burn conservation, incentive-compatible `BatchSpend` `prover_fee` miner dominance (`sub + miner_fee >= sub`), and FlyClient work-interval uniqueness.
3. **Cell-Freedom Under-Constraint Scan (`node/src/audit.rs`):** Linear-algebra nullspace scan over the live spend constraint Jacobian verifying planted constraint holes are caught.
4. **Explicit Formal Boundaries (What Is NOT Yet Mechanized):** These proofs do **not** yet constitute an end-to-end semantic soundness proof (`accepted STARK trace + boundary assertions => ownership + Merkle membership + nullifier uniqueness`) and do **not** formally verify the vendored Winterfell Rust prover/verifier or Haböck–Al Kindi masking patch. Those exact targets sit at the top of our [Public Security Bug Bounty (`LOVE`)](docs/BUG_BOUNTY.md) and [Audit Scope (`docs/AUDIT_SCOPE_V2.md`)](docs/AUDIT_SCOPE_V2.md).

---

## Layer-2 Live Rails vs. Future Roadmap (`nsUSD` & Soft-Forks)

Strict separation between what is **live in L1 code today**, what is **live at Layer 2 (`newsatoshi-commons`)**, and what is **future roadmap**:
- **Live on Layer 1 Today (`newsatoshi-rfc0021` `v1.2.1`):** Shielded `LOVE`, `BatchSpend` (`K=2..=16`), Bitcoin AuxPoW (`20051`), `aserti3-launch`, SHA-256 HTLCs, unilateral partial-claim `PayWord` channels, `PriorLock`, FlyClient MMR, `1 KB` Utreexo, `NSPQ2` (`ML-KEM-768` + `SLH-DSA`) P2P, and zero-Rust JS verifier (`verifier-ts/`).
- **Live at Layer 2 Today (`newsatoshi-commons`):** 30 zero-auth MCP tools, **USD-denominated JIT `x402` + `O(1)` PayWords** (`GET https://commons.newsatoshi.org/api/v2/nsusd/quote?usd=0.01`), and zero-custody Bitcoin/Lightning/Solana/4-chain EVM SHA-256 HTLC compilers.
- **Specified Roadmap (NOT Yet Live in L1 `node/src/` — Pre-Reserved BIP-9 Soft-Fork Bits, Zero Genesis Restart):**
  - `BIT_FUTURE_COMPACT_PROOF = 5`: Pure-hash WHIR / Binius compact spend proofs (`2–4×` smaller proofs)
  - `BIT_FUTURE_RECURSIVE_AGG = 6`: Full-query GPU STARK-in-STARK spend & chain aggregation
  - `BIT_MULTI_ASSET_NOTES = 7`: Tier-2 Sovereign BTC-collateralized `nsUSD` multi-asset shielded notes (`docs/RFC-0028-NSUSD-SHIELDED-DOLLAR.md`)

---

## Reproduce Full Verification Suite Offline (200+ Tests, Fuzzers & Lean 4)

```bash
cd node

# 1. Zero-Rust independent JavaScript/OpenSSL consensus verifier self-test
node ../verifier-ts/newsatoshi_verifier.mjs --self-test

# 2. Core unit test suite (46 unit tests)
cargo test --lib

# 3. Full 15-suite integration, differential JS<->Rust, 10k-mutation fuzz, crypto KAT & red-team suites
cargo test --release --test priorism_fep_core --test mainnet_v2_readiness --test audit_redteam \
  --test differential_fuzz --test payword_channel --test attacks --test discovery \
  --test crypto_kats --test conds --test auxpow --test locks --test light --test mainnet_params --test chain

# 4. Re-extract and kernel-verify BOTH Lean 4.36.0 proofs (0 sorry, 0 native_decide, 0 Mathlib)
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean && diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean && lean proof/SpendBalance.lean
cargo run --release --example extract_lean_circuit -- /tmp/SpendCircuitFull.lean && diff -u proof/SpendCircuitFull.lean /tmp/SpendCircuitFull.lean && lean proof/SpendCircuitFull.lean
```

---

## Public Security Bug Bounty (Paid in Fair-Mined `LOVE`)

- **Rules, Tiers & Disclosure:** [docs/BUG_BOUNTY.md](docs/BUG_BOUNTY.md) · [docs/AUDIT_SCOPE_V2.md](docs/AUDIT_SCOPE_V2.md)
- **Public Mainnet v2 Bounty Wallet:** `ns1af734b0e0b0c1c6a54e206ba7a23f586daee77ede5e7c51b6ec6b133c51f572a99d8cb66`
