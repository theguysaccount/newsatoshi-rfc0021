# External Security Audit RFP — Newsatoshi `v1.2.0-mainnet-rc1`

> **Purpose:** Ready-to-send engagement brief for **two independent external security audit firms** required to clear Gates 1 & 2 prior to running the single canonical Bitcoin-block-anchored Mainnet genesis (`GET https://commons.newsatoshi.org/api/v2/cutover-readiness`).

---

## 1. Executive Summary

**Newsatoshi (`LOVE`) `v1.2.0-mainnet-rc1`** is a minimalist, fair-launch, Bitcoin merge-mined (`AuxPoW`, `chainid = 20051`) Layer-1 cryptocurrency with **zero elliptic curves in consensus**:
- **Default Shielded Spend STARK (`spend.rs`) & Multi-Spend `BatchSpend` Compression (`batch_spend.rs`):** 249 Goldilocks AIR constraints over pure SHA-256 (all 249 constraints + 7 no-wrap lemmas kernel-verified in Lean 4 `proof/SpendCircuitFull.lean`, `0 sorry`), Haböck–Al Kindi (ePrint 2024/1037) masked quotient segments, 256-bit Quartic Goldilocks $\mathbb{F}_{p^4} = \mathbb{F}_p[x]/(x^4 - 7)$ + SHA-384 FRI on Mainnet v2 (`B=8, q=152, g=20`: `192` classical LDR bits, `128`-bit BHT QROM SHA-384, **`100–104` conservative CMS19 QROM bits**), and `K = 2..=16` multi-spend compression (`6.5×` at `K=8`) with incentive-compatible STARK-bound `prover_fee` (AuxPoW miners always keep 100% of block subsidy + `miner_fee`).
- **Priorism-FEP Consensus Primitives (`prior.rs`, `params.rs`, `state.rs`):** Homeostatic 50% shielded base-fee burn + ONE unified falsifiable `PriorLock` primitive (SCGS I-3 `arbiter_vk != owner_vk`, objective preimage/equivocation OR independent `M-of-N` SLH-DSA disconfirmation with exact 50% surprise bounty + 50% permanent burn) + unilateral PayWord channels (`channel.rs`), with strictly $O(\log N)$ Merkleized `locks` & `conds` and legacy matrix jobs disabled on `nsM2`.
- **Work-Proportional FlyClient MMR (`light.rs`) & PQ P2P (`pq_transport.rs`):** Work-offset FlyClient proofs bound to `DigestParts::header_mmr` (Genesis #0 on Mainnet v2), Day-14 ASERT steady-anchor continuity (`2,016 → 2,017`), opportunistic `NSPQ1` + SLH-DSA peer-pinned `NSPQ2` ML-KEM-768 P2P with 64 KB chunked anti-slowloris reads, `/16` & `/32` eclipse defense, Compact Blocks, Utreexo 1 KB frontier, and disk-backed KV pruning.

**Target Audit Tag:** `theguysaccount/newsatoshi-rfc0021` tag **`v1.2.0-mainnet-rc1`**  
**Exact File Inventory & SHA-256 Fingerprints:** `docs/AUDIT_SCOPE_V2.md`

---

## 2. Requested Scope (Two Independent Parallel Engagements)

### Engagement A — Cryptography, STARK AIR Soundness & Winterfell Patch
1. **Vendored Winterfell 0.13.1 Patch (`node/vendor/winter-*`, 31 `NEWSATOSHI patch` sites):**
   - Audit 256-bit Quartic Goldilocks extension $\mathbb{F}_{p^4} = \mathbb{F}_p[x]/(x^4 - 7)$ (`QuartExtension`, diagonal Frobenius, inversion) and our canonicalization fixes to upstream `f64::BaseElement::double()` and `mul_small()`.
   - Audit `ProvenSecurity::qrom_ldr_bits()`, Haböck–Al Kindi constraint composition segment masking zero-knowledge and soundness, UB-free concurrent FFT/Merkle raw-pointer writes, and hostile-proof deserialization memory caps.
2. **Shielded Spend, `BatchSpend`, & IVC Recursion Circuits (`node/src/spend.rs`, `node/src/batch_spend.rs`, `node/src/recursion.rs`, `node/proof/SpendCircuitFull.lean`):**
   - Verify zero underconstrained cells, zero Goldilocks wrap-around, exact inter-spend `P_ACT` isolation in `BatchSpendAir`, Fiat–Shamir binding of `prover_a_pk` and `prover_fee`, `MAIN_V2` SHA-384 domain separation, and `HeaderChainAir` + `StarkInStarkVerifierAir` constraints.
   - Review the Lean 4.36.0 pure-kernel mechanization (`proof/SpendCircuitFull.lean` + `proof/SpendBalance.lean`).
3. **Post-Quantum Primitives (`node/src/pq_transport.rs`, `node/src/deliver.rs`):**
   - Audit NIST FIPS 203 `ML-KEM-768` (`NSPQ1` & `NSPQ2` transcript binding, nonce/sequence non-reuse, constant-time MAC verification, 64 KB chunked slowloris defense) and NIST FIPS 205 `SLH-DSA-SHA2-128s` peer-identity pinning.

### Engagement B — Consensus State Machine, Economic Invariants, FlyClient & P2P
1. **Consensus & Monetary Rules (`node/src/state.rs`, `node/src/params.rs`, `node/src/pow.rs`, `node/src/chain.rs`, `node/src/auxpow.rs`, `node/src/signal.rs`):**
   - Verify global solvency (`pool + locked + burned == issued`), Homeostatic 50% fee burn, incentive-compatible `BatchSpend` `prover_fee` validation (`burned + prover_fee + miner_fee == total_fee`), panic-free Day-14 `aserti3-launch` transition (`2,016 → 2,017`), `O(log N)` Merkleized `locks`/`conds`, legacy job disabling on `nsM2`, and AuxPoW + BIP-9 non-collision.
2. **FEP & Settlement Primitives (`node/src/prior.rs`, `node/src/channel.rs`, `node/src/lock.rs`, `node/src/cond.rs`):**
   - Audit SCGS I-3 enforcement, exact 50/50 disconfirmation bounty+burn, fee-cap anti-siphon check, replay protection, and PayWord channel hash-chain conservation.
3. **FlyClient, P2P & Storage (`node/src/light.rs`, `node/src/node.rs`, `node/src/peers.rs`, `node/src/utreexo.rs`, `node/src/pruned_store.rs`, `node/src/snapshot.rs`):**
   - Audit work-proportional FlyClient MMR sampling against sibling-work inflation and tail spoofing, P2P DoS/eclipse defense, Compact Block reconstruction, and `nsSNAP06` snapshot / pruned-store recovery.

---

## 3. One-Command Pre-Audit Reproduction

```bash
git clone --branch v1.2.0-mainnet-rc1 https://github.com/theguysaccount/newsatoshi-rfc0021.git
cd newsatoshi-rfc0021/node
cargo test --lib
cargo test --release --test priorism_fep_core --test mainnet_v2_readiness --test audit_redteam \
  --test differential_fuzz --test payword_channel --test attacks --test discovery \
  --test crypto_kats --test conds --test auxpow --test locks --test light --test mainnet_params --test chain
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean && diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean
lean proof/SpendBalance.lean
cargo run --release --example extract_lean_circuit -- /tmp/SpendCircuitFull.lean && diff -u proof/SpendCircuitFull.lean /tmp/SpendCircuitFull.lean
lean proof/SpendCircuitFull.lean
node ../verifier-ts/newsatoshi_verifier.mjs --self-test
```

---

## 4. Deliverables & Launch Sign-Off Criteria

- Publicly publishable PDF audit reports pinned to `v1.2.0-mainnet-rc1` (or remediation commit).
- **Zero unresolved Critical or High findings** before running the single canonical Bitcoin-block-anchored `newsatoshi genesis-v2` launch ceremony.
