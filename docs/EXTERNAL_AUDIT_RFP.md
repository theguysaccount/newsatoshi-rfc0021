# External Security Audit RFP — Newsatoshi `v1.0.0-core`

> **Purpose:** Ready-to-send engagement brief for **two independent external security audit firms** required to clear Gates 1 & 2 prior to running the single canonical Bitcoin-block-anchored Mainnet genesis (`GET https://commons.newsatoshi.org/api/v2/cutover-readiness`).

---

## 1. Executive Summary

**Newsatoshi (`LOVE`) `v1.0.0-core`** is a minimalist, fair-launch, Bitcoin merge-mined (`AuxPoW`, `chainid = 20051`) Layer-1 cryptocurrency with **zero elliptic curves in consensus**:
- **Default Shielded Spend STARK (`spend.rs`) & Multi-Spend `BatchSpend` Compression (`batch_spend.rs`):** 249 Goldilocks AIR constraints over pure SHA-256, Haböck–Al Kindi (ePrint 2024/1037) masked quotient segments, SHA-384 FRI commitments on Mainnet v2 (`>= 140` classical LDR bits; 128-bit BHT QROM hash collision bound; ~67–80 bit conservative quantum FRI bound), and `K = 2..=16` multi-spend compression (`6.49×` at `K=8`) with consensus split-coinbase payout to the Fiat–Shamir-bound `prover_a_pk`.
- **Priorism-FEP Consensus Primitives (`prior.rs`, `params.rs`, `state.rs`):** Homeostatic 50% shielded base-fee burn + ONE unified falsifiable `PriorLock` primitive (SCGS I-3 `arbiter_vk != owner_vk`, objective preimage/equivocation OR independent `M-of-N` SLH-DSA disconfirmation with exact 50% surprise bounty + 50% permanent burn) + unilateral PayWord channels (`channel.rs`).
- **Work-Proportional FlyClient MMR (`light.rs`) & Opportunistic `NSPQ1` ML-KEM-768 P2P (`pq_transport.rs`):** Work-offset FlyClient proofs bound to `DigestParts::header_mmr` (Genesis #0 on Mainnet v2), `/16` & `/32` eclipse defense, Compact Blocks, Utreexo 1 KB frontier, and disk-backed KV pruning.

**Target Audit Tag:** `theguysaccount/newsatoshi-rfc0021` tag **`v1.0.0-core`**  
**Exact File Inventory & SHA-256 Fingerprints:** `docs/AUDIT_SCOPE_V2.md`

---

## 2. Requested Scope (Two Independent Parallel Engagements)

### Engagement A — Cryptography, STARK AIR Soundness & Winterfell Patch
1. **Vendored Winterfell 0.13.1 Patch (`node/vendor/winter-*`, 18 `NEWSATOSHI patch` sites):**
   - Audit Haböck–Al Kindi constraint composition segment masking zero-knowledge and soundness.
   - Audit UB-free concurrent FFT / Merkle raw-pointer writes and hostile-proof deserialization memory caps.
2. **Shielded Spend & `BatchSpend` Circuits (`node/src/spend.rs`, `node/src/batch_spend.rs`):**
   - Verify zero underconstrained cells, zero Goldilocks wrap-around, exact inter-spend `P_ACT` isolation in `BatchSpendAir`, `prover_a_pk` transcript binding, and `MAIN_V2` SHA-384 domain separation.
   - Evaluate roadmap to full Lean 4 mechanization of SHA-256 constraints `#0..#246` (currently checked via Z3 in `proof/check.py`, while `proof/SpendBalance.lean` mechanizes `#247`/`#248` and ledger conservation).
3. **Post-Quantum Primitives (`node/src/pq_transport.rs`, `node/src/deliver.rs`, `node/src/job.rs`):**
   - Audit NIST FIPS 203 `ML-KEM-768` (`NSPQ1` transcript binding, nonce/sequence non-reuse, constant-time MAC verification) and NIST FIPS 205 `SLH-DSA-SHA2-128s`.

### Engagement B — Consensus State Machine, Economic Invariants, FlyClient & P2P
1. **Consensus & Monetary Rules (`node/src/state.rs`, `node/src/params.rs`, `node/src/pow.rs`, `node/src/auxpow.rs`, `node/src/signal.rs`):**
   - Verify global solvency (`pool + locked + burned == issued`), Homeostatic 50% fee burn, `BatchSpend` split-coinbase enforcement & anti-spam `MIN_BATCH_SPEND_FEE`, `aserti3-launch` continuity, and AuxPoW + BIP-9 non-collision.
2. **FEP & Settlement Primitives (`node/src/prior.rs`, `node/src/channel.rs`, `node/src/job.rs`, `node/src/lock.rs`, `node/src/cond.rs`):**
   - Audit SCGS I-3 enforcement, exact 50/50 disconfirmation bounty+burn, fee-cap anti-siphon check, replay protection, and PayWord channel hash-chain conservation.
3. **FlyClient, P2P & Storage (`node/src/light.rs`, `node/src/node.rs`, `node/src/peers.rs`, `node/src/utreexo.rs`, `node/src/pruned_store.rs`):**
   - Audit work-proportional FlyClient MMR sampling against sibling-work inflation and tail spoofing, P2P DoS/eclipse defense, Compact Block reconstruction, and snapshot/pruned-store recovery.

---

## 3. One-Command Pre-Audit Reproduction

```bash
git clone --branch v1.0.0-core https://github.com/theguysaccount/newsatoshi-rfc0021.git
cd newsatoshi-rfc0021/node
cargo test --lib
cargo test --release --test priorism_fep_core --test audit_redteam --test differential_fuzz \
  --test payword_channel --test attacks --test discovery --test crypto_kats --test mainnet_params
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean && diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean
lean proof/SpendBalance.lean
node ../verifier-ts/newsatoshi_verifier.mjs --self-test
```

---

## 4. Deliverables & Launch Sign-Off Criteria

- Publicly publishable PDF audit reports pinned to `v1.0.0-core` (or remediation commit).
- **Zero unresolved Critical or High findings** before running the single canonical Bitcoin-block-anchored `newsatoshi genesis-v2` launch ceremony.
