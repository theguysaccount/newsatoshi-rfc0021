# Newsatoshi `v1.0.0-core` External Security Audit Scope & Cutover Packet

This document is the authoritative, zero-hype engineering scope packet for the **two independent external security audits** required before running the single canonical Bitcoin-block-anchored Mainnet genesis (`newsatoshi genesis-v2`). For direct auditor engagement terms, see [`docs/EXTERNAL_AUDIT_RFP.md`](./EXTERNAL_AUDIT_RFP.md).

> **Honest Pre-Cutover Status (`v1.0.0-core`):**
> - **External Security Audits:** **`0 / 2` completed** (PENDING — hard launch blocker).
> - **Independent Bitcoin AuxPoW Pools (`chainid = 20051`):** **`0 / 3` at real difficulty** (PENDING — hard launch blocker).
> - **One Canonical Genesis Policy:** The Nov 10 `v0.1.0` chain is retired as a pre-launch rehearsal/canary network. All stripped alt-L1 prototypes (`rollup.rs`, `zkvm.rs`, `mission.rs`, `bond.rs`, `covenant_stark.rs`) have been permanently removed from L1 consensus.
> - Live machine-readable cutover gate: `GET https://commons.newsatoshi.org/api/v2/cutover-readiness`.

---

## 1. Minimalist Consensus Scope Inventory (Exact SHA-256 Fingerprints)

| Component | File Path | SHA-256 Fingerprint (`shasum -a 256`) | Key Security Invariants to Audit |
| :--- | :--- | :--- | :--- |
| **Winterfell 0.13.1 Patch** | `node/vendor/winter-*` (`18` marked `NEWSATOSHI patch` sites across 6 crates) | Verify via `grep -rn "NEWSATOSHI patch" node/vendor/` | Haböck–Al Kindi (ePrint 2024/1037) segment masking; hostile-proof allocation bounds; UB-free raw-pointer concurrent FFT & Merkle tree writes |
| **Shielded Spend STARK** | `node/src/spend.rs` | `4e140f04854053f7236e467d0320821542d6e22e42fd26974f5f2f8855883d22` | `249` Goldilocks AIR constraints, `#247` balance conservation, `#248` `< 2^60` range check, no mod-`P` wrap-around, `MAIN_V2` SHA-384 FRI (`>= 140` classical LDR bits; 128-bit BHT QROM hash bound; ~67–80 bit conservative quantum FRI bound) |
| **Multi-Spend `BatchSpend` STARK** | `node/src/batch_spend.rs` | `f8c243a7aa511c31638aa9d251bd29cec72dc07541b32c40df1071e990bce028` | Vertical tiling of `K ∈ 2..=16` spends reusing `spend::eval_constraints` verbatim, inter-spend `P_ACT` isolation via `Kind::Rand` separators, Fiat–Shamir binding of `prover_a_pk`, `>= 2,304` random ZK rows at all `K` |
| **Priorism-FEP `PriorLock`** | `node/src/prior.rs` | `f266812c3e107583ea855970eb37b0ae831fe3bc8a1b0cec82f9684a66d8899b` | SCGS Invariant I-3 (`arbiter_vk != owner_vk`, distinct arbiters), objective preimage & equivocation disconfirmation, independent `M-of-N` SLH-DSA quorum, 10% fee cap, exact 50/50 bounty+burn conservation (`bounty + burned + fee == stake`), bounded `O(open)` active map |
| **PayWord Channels (`RFC-0022`)** | `node/src/channel.rs` | `b2b43c3d23046b922ce6c5567b563acf744c09caf3a07bf6d418614a51db6b6a` | Seller-authorized unilateral partial claim (`seller + refund + fee == deposit`), exact timeout refund, replay & over-claim rejection |
| **ASERT Ramp & Homeostatic Burn** | `node/src/pow.rs`, `node/src/params.rs` | `398c48c7020f84f0e0dd00658c3e495f232ce049fc3482101fd3ba06249851f9` / `6f96b13b62d1365c5f02ae413d67b344458230cbfdb8a14e6845128919e19def` | Continuous two-stage `aserti3-launch` (1 h for 2,016 blocks -> 48 h steady), `BASE_FEE_BURN_BPS = 5_000` (50% burn), `PROVER_SUBSIDY_MAX_BPS = 3_000` (30% cap), `MIN_BATCH_SPEND_FEE = 10_000`, `nsM2` fair-launch genesis CLI |
| **Work-Proportional FlyClient MMR** | `node/src/light.rs` | `6dc69f60e25a9f8d3dc69e24d4e521c8f837855df179a9b23e56998c631d1e2c` | Integer `U512` work-offset sampling over `[0, ancestor_work)` (blocks sibling-work inflation), `tip_header.commit` -> `DigestParts::header_mmr` binding, rightmost ancestor leaf tail binding |
| **Consensus State & Snapshots** | `node/src/state.rs`, `node/src/snapshot.rs` | `372b36ee8a0cad0cbf05383f1bdb6b47714d4da3bdf0357fcf3f6209687ec958` / `cd08f926b186e37bf83043880b9aaa704ad75e155d4fc8bbdeba4aa81fd135c7` | Global solvency (`pool + locked + burned == issued`), atomic intra-batch double-spend rejection, split-coinbase prover payout validation, `DigestParts` (`priors` + `header_mmr`), `nsSNAP05` fast-boot snapshot |
| **Opportunistic PQ P2P (`NSPQ1`)** | `node/src/pq_transport.rs` | `d7f2d22320995be22685fda38a357b05fcb68e649f4696e0c2419c0d96cb41f8` | Ephemeral FIPS 203 `ML-KEM-768` + directional SHA-256-CTR + Encrypt-then-MAC keyed SHA-256 (passive HNDL & in-session tamper/replay protection; unauthenticated handshake — does not prevent active MITM without key pinning) |
| **Eclipse Defense, Compact Blocks & Parallel Verify** | `node/src/peers.rs`, `node/src/node.rs` | `cb09cb9d9e6618edee3a50469aea868ee958d939080628a9d8c1a40d2a0160bb` / `f20e59bb6c3707bdb372bfd8d3bd97f1e0f17c2f44fb896eaba20d4c0f10229f` | `/16` IPv4 & `/32` IPv6 netgroup caps, `CompactBlock` reconstruction, multi-core parallel `Tx::Spend` + `Tx::BatchSpend` verification, `NSPQ1` wiring |
| **Selective Audit Viewing Keys** | `node/src/deliver.rs` | `f55d8bdfc909fa190d421ef601c02e005a7fe33f018b5b697a9ff132ce5f018a` | ML-KEM-768 `nsvk1…` read-only viewing keys decrypt memos without exposing `sk` |
| **BIP-9 AuxPoW Signaling** | `node/src/signal.rs` | `eb0354c974e1f5f45513e55d6a3dd9e202df562e775680e6892497a5a0ce21f9` | Version bits `1..=7` non-collision with `VERSION_AUXPOW` (`0x100`) and `CHAIN_ID = 20051` |
| **Utreexo Frontier, Disk KV & Recursion R&D** | `node/src/utreexo.rs`, `pruned_store.rs`, `recursion.rs` | `2be67b6e…` / `971155b9…` / `81efa1b6…` | `<= 1,024 B` RAM frontier equivalence, WAL/SSTable crash recovery, `HeaderChainAir` & `FriFoldVerifyAir` R&D primitives |
| **Independent Second Verifier** | `verifier-ts/newsatoshi_verifier.mjs` | `2c160377e7a5d9c8972e6ae70c8f3de49e8b6191524078f81e1ffe08b032705d` | Zero-dependency Node.js/OpenSSL/BigInt second consensus implementation verified differentially against Rust L1 |
| **Lean 4.36.0 Proof** | `node/proof/SpendBalance.lean` | `c2b4485342d218aa3dc81843acc5c22b0f1230a846584d5b77502f197536a0c3` | 10 machine-checked balance/solvency/conservation theorems (`0 sorry`, zero Mathlib); **explicitly does NOT mechanize SHA-256 constraints `#0..#246`** (checked via Z3 in `audit.rs` / `proof/check.py`) |

---

## 2. Mainnet Launch Requirements (Hard Non-Negotiable Gates)

| Gate | Requirement | Current Status |
| :--- | :--- | :--- |
| **Gate 1 — External Audit #1** | Independent cryptography & consensus audit report published; all Critical/High findings fixed | **PENDING (`0 / 2`)** |
| **Gate 2 — External Audit #2** | Second independent audit of Winterfell patch, `spend.rs`, `batch_spend.rs`, `prior.rs`, `light.rs`, `state.rs`, `pq_transport.rs` | **PENDING (`0 / 2`)** |
| **Gate 3 — Independent AuxPoW Pools** | >= 3 independent Bitcoin SHA-256 pools merge-mining `chainid = 20051` at real Bitcoin-grade difficulty | **PENDING (`0 / 3`)** |
| **Gate 4 — Internal CI & Self-Checks** | Unit suite, integration/red-team/differential tests, 10 Lean 4 accounting theorems (`0 sorry`), Z3 249-constraint check | **CI GREEN (not a substitute for Gates 1–3)** |
