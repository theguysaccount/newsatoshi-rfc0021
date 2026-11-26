# External Security Audit RFP — Newsatoshi Mainnet v2 (`v0.9.0-frontier`)

> **Purpose:** Ready-to-send engagement brief for **two independent external security audit firms** (e.g., Trail of Bits, Least Authority, Veridise, Quarkslab, Zellic, OtterSec) required to clear Gates 1 & 2 of Newsatoshi Mainnet v2 cutover (`GET https://commons.newsatoshi.org/api/v2/cutover-readiness`).

---

## 1. Executive Summary

**Newsatoshi (`LOVE`)** is a fair-launch, Bitcoin merge-mined (`AuxPoW`, `chainid = 20051`) Layer-1 cryptocurrency built with **zero elliptic curves**:
- **192-bit classical / 128-bit QROM pure SHA-384 STARKs** (Winterfell 0.13.1 + Haböck–Al Kindi ePrint 2024/1037 segment masking + UB-free concurrent FFT/Merkle patch).
- **Shielded 2-in/2-out default privacy** (`spend.rs`, 249 Goldilocks AIR constraints) + **ML-KEM-768 `nsvk1…` selective viewing keys** (`deliver.rs`).
- **Turing-complete Haböck LogUp ROM-bound L2 zkVM** (`zkvm.rs`, 81 main + 3 aux cols, 6 verifier periodic ROM cols pinned to `vault.post.vk_hash`, 32 base-4 exact 64-bit range limbs, 192-bit SHA-384 FRI) verified directly in L1 consensus (`Action::RollupZkVmBatch`).
- **Native L1 Clearinghouse Rails:** PayWord unilateral channels (`RFC-0022`), Universal Trust Bonds with 3-tier slashing (`RFC-0024`), Sovereign L2 Rollups (`RFC-0023`), Mission Launchpads (`RFC-0027`), and BIP-9 AuxPoW-safe signaling (`RFC-0026`).
- **Post-Quantum Networking & Succinct Light Sync:** Mandatory Mainnet v2 `NSPQ1` (`ML-KEM-768` + SHA-256-CTR + Encrypt-then-MAC), `/16` IPv4 / `/32` IPv6 eclipse defense, Compact Blocks, Genesis-#0 consensus-committed FlyClient Header MMR, Utreexo 1 KB compact note frontier, disk-backed KV + block pruning, bit-exact SHA-256d `HeaderChainAir` & algebraic `FriFoldVerifyAir`, and a second independent Node.js/OpenSSL verifier (`verifier-ts/newsatoshi_verifier.mjs`).

**Target Audit Commit / Tag:** `theguysaccount/newsatoshi-rfc0021` tag **`v0.9.0-frontier`**  
**Exact File Inventory & SHA-256 Fingerprints:** `docs/AUDIT_SCOPE_V2.md`

---

## 2. Requested Scope (Two Independent Parallel Engagements)

### Engagement A — Cryptography, STARK AIR Soundness & Winterfell Patch
1. **Vendored Winterfell 0.13.1 Patch (`node/vendor/winter-*`, 18 `NEWSATOSHI patch` sites):**
   - Verify Haböck–Al Kindi constraint composition segment masking zero-knowledge property & soundness.
   - Verify UB-free raw-pointer disjoint writes in `winter-math/src/fft/concurrent.rs`, `winter-prover/src/matrix/segments.rs`, and `winter-crypto/src/merkle/concurrent.rs`.
   - Audit hostile-proof deserialization allocation ceilings against OOM / DoS.
2. **Shielded Spend STARK (`node/src/spend.rs`, `node/proof/SpendBalance.lean`, `node/proof/check.py`):**
   - Verify zero underconstrained cells, zero Goldilocks wrap-around, exact `< 2^60` note range enforcement, and `MAIN_V2` SHA-384 FRI domain separation.
3. **Turing-Complete LogUp zkVM & Rollup STARK (`node/src/zkvm.rs`, `node/src/rollup.rs`, `node/src/recursion.rs`):**
   - Audit Haböck LogUp RAP ROM binding (`program_hash == vault.post.vk_hash`), `256`-bit extension-field challenge sampling, 32 base-4 exact 64-bit range limbs in `f128`, jump/loop soundness, `HeaderChainAir`, and `FriFoldVerifyAir`.
4. **Post-Quantum Primitives (`node/src/pq_transport.rs`, `node/src/deliver.rs`, `node/src/job.rs`):**
   - Audit NIST FIPS 203 `ML-KEM-768` (`NSPQ1` handshake transcript binding, sequence counter non-reuse, MAC verification) and NIST FIPS 205 `SLH-DSA-SHA2-128s`.

### Engagement B — Consensus State Machine, Economic Invariants, P2P & Storage
1. **Consensus & Monetary Invariants (`node/src/state.rs`, `node/src/params.rs`, `node/src/pow.rs`, `node/src/auxpow.rs`, `node/src/signal.rs`):**
   - Verify global solvency (`pool + locked + burned == issued`), `aserti3-launch` continuity & overflow safety, AuxPoW `CHAIN_ID = 20051` + BIP-9 bits `1..=7` non-collision, and Genesis-#0 `DigestParts::header_mmr` binding.
2. **Clearinghouse Primitives (`node/src/channel.rs`, `node/src/bond.rs`, `node/src/mission.rs`):**
   - Verify anti-wash-trading, exact slash/claim/curve conservation, integer `isqrt_u128` rounding safety, and zero founder rugpull path on `bounty_pool`.
3. **P2P, Eclipse Defense, Pruning & Light Verification (`node/src/node.rs`, `node/src/peers.rs`, `node/src/light.rs`, `node/src/utreexo.rs`, `node/src/pruned_store.rs`):**
   - Audit DoS/memory bounds, `/16` & `/32` eclipse resistance, Compact Block reconstruction, FlyClient MMR sampling, Utreexo frontier equivalence, and disk-backed KV crash recovery.

---

## 3. One-Command Pre-Audit Reproduction

```bash
git clone --branch v0.9.0-frontier https://github.com/theguysaccount/newsatoshi-rfc0021.git
cd newsatoshi-rfc0021/node
cargo test --lib
cargo test --release --test audit_redteam --test differential_fuzz --test clearinghouse_substrate --test soundness --test attacks --test discovery --test mainnet_params --test payword_channel
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean && diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean
lean proof/SpendBalance.lean
node ../verifier-ts/newsatoshi_verifier.mjs --self-test
```

---

## 4. Deliverables & Cutover Sign-Off Criteria

- Publicly publishable PDF audit report pinned to exact commit SHA (`v0.9.0-frontier` or remediation commit).
- **Zero unresolved Critical or High findings** prior to `newsatoshi genesis-v2` Bitcoin-block-anchored Mainnet v2 launch ceremony.
- Remediation verification pass confirming all fixes are covered by regression tests in `node/tests/audit_redteam.rs`.
