# newsatoshi (`v1.0.0-core`)

Minimalist reference node for **Newsatoshi (`LOVE`)**: a Bitcoin-shaped, Bitcoin merge-mined (`AuxPoW`, `chainid = 20051`) Layer-1 cryptocurrency where every balance is shielded by default, every payment is verified by pure SHA-2 STARKs (zero elliptic curves, zero trusted setup, zero novel hashes), and **Priorism-FEP** (`PriorLock` + Homeostatic Fee Burn + `BatchSpend` Negentropy Prover split coinbase) encodes falsifiable truth-seeking and deflationary burn directly into L1 consensus.

> **Brutally Honest Pre-Launch Status (`v1.0.0-core`):**
> - **External Security Audits:** **`0 / 2` completed** (hard blocker before mainnet genesis; scope packet in [`docs/AUDIT_SCOPE_V2.md`](docs/AUDIT_SCOPE_V2.md)).
> - **Independent Bitcoin AuxPoW Pools (`chainid = 20051`):** **`0 / 3` at Bitcoin-grade difficulty** (hard blocker before mainnet genesis).
> - **One Canonical Genesis:** The Nov 10 `v0.1.0` chain is explicitly retired as a pre-launch rehearsal/canary network. Production Mainnet will launch **once** via a single fresh Bitcoin-block-anchored `newsatoshi genesis-v2` ceremony (zero premine, Day-1 ASERT anti-instamine ramp) only after both external audits and >= 3 independent pools are verified. Live status: `GET https://commons.newsatoshi.org/api/v2/cutover-readiness`.

---

## Core Architecture (Minimalist Consensus Surface)

Everything in L1 consensus rests on **FIPS 180-4 SHA-2 (`SHA-256` / `SHA-384`)** and **FIPS 205 (`SLH-DSA-SHA2-128s`)**. No elliptic curves, no pairings, no bonding-curve launchpads, no unconstrained rollup vaults, and no toy VMs in L1 consensus.

1. **Ordering (Bitcoin-Compatible AuxPoW + Day-1 ASERT):**
   - 80-byte SHA-256d headers in Bitcoin's layout + Namecoin-compatible AuxPoW (`chainid = 20051 = 0x4e53`), borrowing Bitcoin's SHA-256 hardware security budget.
   - Continuous two-stage `aserti3-launch` (`node/src/pow.rs`): 1-hour half-life for the first 2,016 blocks (prevents Day-1 instamine under 1,000,000x hashrate spikes), transitioning continuously to 48-hour steady-state ASERT.
2. **Default Shielded Privacy & `BatchSpend` Compression (`spend.rs`, `batch_spend.rs`):**
   - Single 2-in/2-out shielded spend: `8,192` rows x `247` columns, `249` Goldilocks AIR constraints, Haböck–Al Kindi (ePrint 2024/1037) masked quotient segments, SHA-384 FRI commitments on Mainnet v2 (`MAIN_V2`).
   - **Multi-Spend `BatchSpend` STARK Compression (`K ∈ 2..=16`):** Tiles `K` independent 2-in/2-out spends vertically in ONE Winterfell STARK reusing `spend::eval_constraints` verbatim (zero new circuit constraints). Because FRI proof size scales logarithmically (`O(log ROWS)`), `K = 8` compresses 8 shielded spends into **641 KB total (~80 KB/spend = 6.49× compression)** — lifting 8 MB block capacity from ~15 to **~96–170+ shielded payments per 10-minute block** on CPU in ~3.3 s!
   - **Split Coinbase (AuxPoW Orderer + Negentropy Prover):** When a block includes valid `Tx::BatchSpend` proofs compressing `K >= 2` spends (each paying `>= MIN_BATCH_SPEND_FEE`, 50% burned so self-spamming costs real LOVE), the block's coinbase MUST pay `min(30%, 5% * K)` of the block subsidy to the prover's Fiat–Shamir-bound `prover_a_pk` address, while the Bitcoin AuxPoW miner receives the remaining `70%–100%` + unburned fees. When no `BatchSpend` is present, AuxPoW miners receive 100% (zero liveness stall risk).
   - **Honest privacy boundary:** Self-batching (exchanges, wallets, treasuries, agent swarms) has zero privacy loss; delegated multi-user batching shares spend witnesses with the batch prover until future STARK-in-STARK aggregation removes witness visibility.
3. **Priorism-FEP Monetary & Truth Mechanism (`prior.rs`, `params.rs`, `state.rs`):**
   - **Homeostatic Supply Thermostat:** Bitcoin's halving schedule down to a perpetual `0.1953125 LOVE/block` security floor, paired with consensus burn: **50% of every shielded spend / batch-spend fee is permanently burned into `state.burned`** (`50%` to block producers), directly offsetting tail issuance under real economic usage without demurrage or Ponzi yield.
   - **ONE Unified FEP Consensus Primitive (`PriorLock`):** Any human or AI agent locks `stake >= 0.01 LOVE` behind a falsifiable `spec_hash`, `deadline`, `challenge_window`, optional objective SHA-256 `falsifier_hash`, and optional `M-of-N` independent `SLH-DSA` arbiters (enforcing SCGS Invariant I-3: every arbiter key is distinct and strictly `arbiter_vk != owner_vk`).
     - On valid disconfirmation (objective SHA-256 preimage, owner signed equivocation, OR independent `M-of-N` arbiter quorum): `miner_fee <= 10%`, and the remaining collateral splits **50% → Disconfirmer (Surprise Bounty)** and **50% → Permanently Burned** (`bounty + burned + miner_fee == stake`).
     - On zero disconfirmation past `deadline + challenge_window`: collateral unlocks cleanly back to `owner_addr`.
     - Bounded `O(open)` L1 state committed via `MerkleMap` in `DigestParts::priors`.
4. **Native-LOVE Agent Micropayments (`channel.rs`):**
   - Unilateral partial-claim PayWord hash-chain channels (pure SHA-256 + FIPS-205 `SLH-DSA`), enabling sub-millisecond off-chain agent billing that settles directly in native `LOVE`.
5. **Work-Proportional FlyClient, Utreexo 1 KB Frontier, Disk KV & Opportunistic PQ P2P (`light.rs`, `utreexo.rs`, `pruned_store.rs`, `pq_transport.rs`):**
   - **Work-Proportional FlyClient (`light.rs`):** Deterministic integer `U512` work-offset sampling over `[0, ancestor_work)` (catching sibling-work inflation with overwhelming probability), bound directly to the tip's 80-byte PoW header via `DigestParts::header_mmr` (Genesis #0 on Mainnet v2) and rightmost ancestor leaf proof.
   - **Opportunistic `NSPQ1` ML-KEM-768 P2P (`pq_transport.rs`, wired live into `node.rs`):** Protects against passive Harvest-Now-Decrypt-Later (HNDL) traffic capture and in-session frame tampering/replay. Like Bitcoin BIP-324, the ephemeral handshake is unauthenticated and does not by itself stop active MITM without out-of-band peer identity pinning.
   - **Utreexo 1 KB Note Frontier & Disk KV Pruner:** Constant `<= 1,024 B` RAM accumulator (`utreexo.rs`) + WAL/SSTable disk KV store & chain pruner (`pruned_store.rs`).

---

## Measured Benchmarks & Honest Security Parameters

Measured locally on Apple Silicon CPU (default `cargo test`, `opt-level = 2`, deps `opt-level = 3`):

| Operation / Profile | Measured Proof Size | Per-Spend Size | Prove Time | Verify Time | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `TEST` Single Spend (`K=1`, SHA-256, 64 queries) | ~249 KB | ~249 KB | ~0.5 s | ~10 ms | Testnet / Regtest |
| `TEST` `BatchSpend` (`K=4`, SHA-256, 64 queries) | `279,935 B` | `69,983 B` | `2.13 s` | `34 ms` | `3.56×` compression |
| `MAIN_V2` Single Spend (`K=1`, SHA-384, 128 queries) | `520,078 B` | `520,078 B` | `0.57 s` | ~45 ms | ~15 spends / 8 MB block |
| `MAIN_V2` `BatchSpend` (`K=4`, SHA-384, 128 queries) | `602,025 B` | `150,506 B` | `1.57 s` | `44 ms` | `3.46×` compression (~52 spends / block) |
| `MAIN_V2` `BatchSpend` (`K=8`, SHA-384, 128 queries) | `641,180 B` | `80,147 B` | `3.27 s` | `52 ms` | **`6.49×` compression (~96 spends / 8 MB block)** |

### Honest Security & Formal Verification Boundaries

- **STARK Soundness:**
  - Winterfell `proven_security().ldr_bits()` reports `128` proven classical bits on `TEST`/`MAIN` (capped by SHA-256's 128-bit collision resistance) and `>= 140` proven classical bits on `MAIN_V2` (SHA-384 gives 192-bit classical / 128-bit BHT QROM hash collision resistance).
  - **Quantum FRI caveat (honest bound):** Under current Goldilocks cubic-extension (`192`-bit field) and conservative Johnson-bound QROM reductions (Chiesa–Manohar–Spooner, TCC 2019), overall quantum soundness is roughly **67–80 bits** depending on query/grinding assumptions — **NOT** "192-bit quantum".
- **Formal Verification Scope (`node/proof/SpendBalance.lean` & `node/proof/check.py`):**
  - `extract_constraints` + `proof/check.py` (Z3): checks all `249` spend-circuit constraints (`2,950` polynomial terms) against a FIPS 180-4 spec + 5 planted-bug self-tests.
  - `extract_lean_spend` + `proof/SpendBalance.lean` (Lean 4.36.0, **10 theorems**, `0 sorry`, zero Mathlib): proves extracted Constraints `#247` & `#248`, `< 2^60` note range, exact integer spend conservation, PayWord conservation, Homeostatic Burn block solvency, `PriorLock` 50/50 bounty/burn conservation, `BatchSpend` split-coinbase bounds, FlyClient work-interval uniqueness, and Utreexo/FRI-fold uniqueness.
  - **What is NOT yet mechanized in Lean:** Full Lean mechanization of SHA-256 constraints `#0..#246` (comparable to Zcash Ironwood's 2,700+ theorem Lean proof) has **not** been done yet.
- **Recursive Chain Proof Status:** `node/src/recursion.rs` implements building-block STARKs (`HeaderChainAir` + `FriFoldVerifyAir`), while full recursive STARK-in-STARK chain compression (proving a complete SHA-384 STARK verifier inside a STARK) remains future R&D. `BatchSpend` (`K = 2..=16`) provides practical `3.5×–11×` blockspace compression today.

---

## Build, Verify & Reproduce Offline

```bash
cd node

# 1. Independent Node.js/OpenSSL second verifier self-test
node ../verifier-ts/newsatoshi_verifier.mjs --self-test

# 2. All unit tests (incl. PriorLock, BatchSpend K=4, work-proportional FlyClient regression)
cargo test --lib

# 3. Full integration, differential JS<->Rust, 10k mutation fuzz, and red-team suites
cargo test --release --test priorism_fep_core --test audit_redteam --test differential_fuzz \
  --test payword_channel --test attacks --test discovery --test crypto_kats \
  --test conds --test auxpow --test locks --test light --test mainnet_params --test chain

# 4. Re-extract and verify Lean 4.36.0 formal proof (10 theorems, 0 sorry)
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean
diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean
lean proof/SpendBalance.lean

# 5. Fair-launch Mainnet v2 Bitcoin-block-anchored genesis ceremony dry-run
cargo run --release --bin newsatoshi -- genesis-v2 \
  --btc-block-hash <FUTURE_64HEX_BTC_BLOCK_HASH> --btc-height <BTC_HEIGHT>
```

---

## Minimalist L1 Module Layout

```text
node/src/
  hash.rs          SHA-256 / SHA-384 compression & Winterfell hashers
  note.rs          addresses, commitments, nullifiers, depth-32 note tree
  spend.rs         2-in/2-out shielded spend STARK (249 constraints, Haböck–Al Kindi masking)
  batch_spend.rs   multi-spend K=2..=16 STARK compression (reuses spend::eval_constraints)
  prior.rs         Priorism-FEP PriorLock (SCGS I-3, objective/quorum disconfirm, 50/50 bounty+burn)
  channel.rs       unilateral partial-claim PayWord channels (pure SHA-256 + SLH-DSA)
  params.rs        issuance floor, Homeostatic 50% fee burn, split-coinbase prover share, Mainnet v2
  state.rs         ledger state, DigestParts, global solvency, split-coinbase validation
  light.rs         HeaderTip SPV + work-proportional FlyClient MMR light client
  pq_transport.rs  opportunistic NSPQ1 ML-KEM-768 P2P encryption (passive HNDL protection)
  utreexo.rs       1 KB compact note-tree frontier + tracked proofs
  pruned_store.rs  WAL/SSTable disk KV store & historical block pruner
  recursion.rs     SHA-256d HeaderChainAir + algebraic FriFoldVerifyAir R&D primitives
  audit.rs         spend-circuit cell-freedom soundness scan
  job.rs           verified matrix-product escrow (Freivalds + fraud proofs + SLH-DSA)
  lock.rs          SHA-256 hash- and time-locked atomic swaps
  cond.rs / script.rs  bounded Bitcoin-style post-quantum script conditions
  pow.rs / auxpow.rs / signal.rs  ASERT launch ramp, Bitcoin AuxPoW (20051), BIP-9 signaling
  chain.rs / node.rs / peers.rs / rpc.rs / snapshot.rs / tx.rs / wallet.rs / deliver.rs / swap.rs
verifier-ts/       zero-dependency independent Node.js/OpenSSL consensus verifier
node/proof/        Lean 4.36.0 proofs + Z3 249-constraint checker
```
