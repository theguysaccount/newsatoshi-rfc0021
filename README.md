# newsatoshi (`v1.0.0-core`)

**Private, quantum-proof electronic cash secured by Bitcoin merge-mining — built strictly on SHA-2.**

Newsatoshi (`LOVE`) is designed as an **unfreezable, private settlement floor** for humans and autonomous AI agents. Stablecoins like USDC are freezable and 100% public (leaking every agent's suppliers, margins, and treasury on-chain); Bitcoin is unfreezable and credibly neutral, but transparent and not post-quantum. Newsatoshi combines **default shielded privacy**, **pure SHA-2 cryptography** (zero elliptic curves, zero trusted setup, zero novel ZK-hashes), and **Bitcoin SHA-256 merge-mining (`AuxPoW`, `chainid = 20051`)**.

> **Honest Pre-Launch Status (`v1.0.0-core`):**
> - **External Security Audits:** **`0 / 2` completed** (hard blocker before mainnet genesis; scope packet in [`docs/AUDIT_SCOPE_V2.md`](docs/AUDIT_SCOPE_V2.md)).
> - **Independent Bitcoin AuxPoW Pools (`chainid = 20051`):** **`0 / 3` at Bitcoin-grade difficulty** (hard blocker before mainnet genesis).
> - **One Canonical Genesis:** The Nov 10 `v0.1.0` chain is retired as a pre-launch rehearsal/canary network. Production Mainnet will launch **once** via a single fresh Bitcoin-block-anchored `newsatoshi genesis-v2` ceremony (zero premine, Day-1 ASERT anti-instamine ramp) only after both external audits and >= 3 independent pools are verified. Live status: `GET https://commons.newsatoshi.org/api/v2/cutover-readiness`.

---

## The Hourglass Architecture (Strict Layer Separation)

Base layers become Schelling points by staying **radically small, neutral, and ossified** — like IP or Bitcoin — while richer protocols innovate freely on top.

| Layer | Repository / Ecosystem | What Lives Here | Explicitly Excluded |
| :--- | :--- | :--- | :--- |
| **Layer 2 & Applications** *(Above the Waist)* | [`newsatoshi-commons`](https://github.com/theguysaccount/newsatoshi-commons), `x402`, `ERC-8004`, agent escrow protocols (e.g. Psilo), liquidity bridges | 30-tool MCP gateway, Web4 charters, mission launchpads, zkTLS P2P market-maker desks, multi-chain BTC/Lightning/Solana/Base HTLC bridges, `x402` USDC on-ramps, opt-in agent arbitration/juries | Never requires L1 hard forks to iterate |
| **Layer 1 Settlement Floor** *(The Narrow Waist — This Repo)* | [`newsatoshi-rfc0021`](https://github.com/theguysaccount/newsatoshi-rfc0021) (`v1.0.0-core`) | Default shielded transfers (`BatchSpend` compression), pure SHA-2 STARKs + SLH-DSA, Bitcoin AuxPoW (`chainid = 20051`) + ASERT ramp, FlyClient MMR light proofs, 50% fee burn, SHA-256 HTLCs, PayWord channels, and one minimal `PriorLock` collateral primitive | **No** L1 bonding-curve launchpads, **no** L1 subjective juries, **no** L1 rollup vaults or toy VMs |

---

## What Is Inside the Narrow Waist (`v1.0.0-core`)

Everything in L1 consensus rests solely on **FIPS 180-4 SHA-2 (`SHA-256` / `SHA-384`)** and **FIPS 205 (`SLH-DSA-SHA2-128s`)**.

1. **Bitcoin-Compatible Ordering (`pow.rs`, `auxpow.rs`):**
   - 80-byte SHA-256d headers in Bitcoin's format + Namecoin-compatible AuxPoW (`chainid = 20051 = 0x4e53`), allowing existing Bitcoin SHA-256 mining hardware to secure the chain with zero extra electricity.
   - Continuous two-stage `aserti3-launch` difficulty ramp (1-hour half-life for the first 2,016 blocks -> 48-hour steady-state ASERT) to prevent Day-1 instamine under large hashrate spikes.
2. **Default Shielded Privacy & `BatchSpend` Compression (`spend.rs`, `batch_spend.rs`):**
   - Single 2-in/2-out shielded spend: `8,192` rows x `247` columns, `249` Goldilocks AIR constraints, Haböck–Al Kindi (ePrint 2024/1037) masked quotient segments, SHA-384 FRI commitments on Mainnet v2 (`MAIN_V2`).
   - **Multi-Spend `BatchSpend` STARK Compression (`K ∈ 2..=16`):** Tiles `K` independent shielded spends vertically into ONE Winterfell STARK reusing `spend::eval_constraints` verbatim (`0` new circuit constraints). Because FRI proof size scales logarithmically, `K = 8` compresses 8 shielded spends into **641 KB total (~80 KB/spend = `6.49×` compression)** — lifting 8 MB block capacity from ~15 to **~96–170+ shielded payments per 10-minute block** on CPU in ~3.3 s.
   - **Proof-Compression Split Coinbase:** When a block includes valid `Tx::BatchSpend` proofs (`K >= 2`, each paying `>= MIN_BATCH_SPEND_FEE` with 50% burned), consensus pays `min(30%, 5% * K)` of the block subsidy to the proof builder's Fiat–Shamir-bound `prover_a_pk` address and `70%–100%` + unburned fees to the Bitcoin AuxPoW miner. If no batch is present, miners receive 100% (zero liveness risk).
   - **Honest privacy boundary:** Self-batching (exchanges, wallets, agent fleets) has zero privacy loss; delegated multi-user batching reveals spend witnesses to the batch prover until future STARK-in-STARK aggregation removes witness visibility.
3. **50% Base-Fee Burn & Minimal Conditional Locks (`params.rs`, `prior.rs`, `channel.rs`, `lock.rs`):**
   - **Monetary Policy & 50% Fee Burn:** Bitcoin's halving schedule down to a perpetual `0.1953125 LOVE/block` miner security floor, paired with permanent burning of **50% of every shielded spend / batch-spend fee** into `state.burned` (offsetting tail issuance under real transaction volume).
   - **SHA-256 HTLCs & PayWord Channels (`lock.rs`, `channel.rs`):** Native `SHA-256` hash-time locks for zero-custody atomic swaps with Bitcoin, Lightning, Solana, and EVM chains, plus unilateral partial-claim PayWord channels for sub-millisecond agent micropayments.
   - **Falsifiable Collateral Lock (`PriorLock`, `prior.rs`):** One minimal, opt-in collateral primitive (`stake >= 0.01 LOVE`) for objective slashable commitments (hash preimage, double-sign equivocation, or user-chosen independent `M-of-N` SLH-DSA arbiters enforcing `arbiter_vk != owner_vk`). Valid disconfirmation splits net collateral **50% bounty / 50% burn**; clean expiration unlocks back to the owner. *(Subjective arbitration and rich escrow workflows remain opt-in at Layer 2; L1 has no global jury or oracle.)*
4. **Work-Proportional FlyClient Light Proofs, Utreexo 1 KB Frontier & Opportunistic PQ P2P (`light.rs`, `utreexo.rs`, `pruned_store.rs`, `pq_transport.rs`):**
   - **Work-Proportional FlyClient (`light.rs`):** Integer-only `U512` work-offset sampling over `[0, ancestor_work)` (blocks sibling-work inflation), bound to the tip header via `DigestParts::header_mmr` and rightmost-leaf tail proofs.
   - **Opportunistic `NSPQ1` ML-KEM-768 P2P (`pq_transport.rs`, wired into `node.rs`):** Protects against passive Harvest-Now-Decrypt-Later (HNDL) traffic capture and in-session tampering/replay. Like Bitcoin BIP-324, the unauthenticated handshake does not by itself stop active MITM without peer key pinning.
   - **Utreexo 1 KB Note Frontier & Disk KV Pruner:** Constant `<= 1,024 B` RAM accumulator (`utreexo.rs`) + WAL/SSTable disk KV store & block pruner (`pruned_store.rs`).

<details>
<summary>Theoretical Background Note (Priorism / Free-Energy Principle motivation)</summary>

The 50% fee burn and `PriorLock` 50/50 disconfirmation bounty+burn were informed by a Priorism / Free-Energy Principle (FEP) framing: treating credible commitments as falsifiable priors where surprise triggers collateral burn and accurate prediction preserves capital, while keeping the consensus code itself strictly minimal, objective, and free of any global L1 oracle or subjective referee.

</details>

---

## Honest Positioning vs. Related Systems

- **Neptune Cash (NPT):** Already runs a live PoW L1 with default privacy (Mutator Sets), hash-only post-quantum STARKs (Tip5 + Triton VM), split Composer/Guesser mining, and recursive chain proofs. Newsatoshi makes a narrower cryptographic bet: **SHA-2 only** (25 years of cryptanalysis + native Bitcoin/Lightning `OP_SHA256` swaps, at the cost of much heavier recursion) + **Bitcoin AuxPoW merge-mining** + **native AI-agent rails (`newsatoshi-commons`)**.
- **Miden:** Mature STARK VM and client-side privacy, settling as an Ethereum L2 rather than sovereign PoW base money.
- **Recursive Chain Proof Status:** `node/src/recursion.rs` contains R&D building blocks (`HeaderChainAir` + `FriFoldVerifyAir`), **not** a complete recursive SHA-384 STARK-in-STARK chain proof yet. Today, light clients verify headers logarithmically via **work-proportional FlyClient MMR** and blocks compress spends via **`BatchSpend` (`K = 2..=16`)**.

---

## Measured Benchmarks & Honest Security Parameters

Measured locally on Apple Silicon CPU (`cargo test`, `opt-level = 2`, deps `opt-level = 3`):

| Operation / Profile | Measured Proof Size | Per-Spend Size | Prove Time | Verify Time | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `TEST` Single Spend (`K=1`, SHA-256, 64 queries) | ~249 KB | ~249 KB | ~0.5 s | ~10 ms | Testnet / Regtest |
| `TEST` `BatchSpend` (`K=4`, SHA-256, 64 queries) | `279,935 B` | `69,983 B` | `2.13 s` | `34 ms` | `3.56×` compression |
| `MAIN_V2` Single Spend (`K=1`, SHA-384, 128 queries) | `520,078 B` | `520,078 B` | `0.57 s` | ~45 ms | ~15 spends / 8 MB block |
| `MAIN_V2` `BatchSpend` (`K=4`, SHA-384, 128 queries) | `602,025 B` | `150,506 B` | `1.57 s` | `44 ms` | `3.46×` compression (~52 spends / block) |
| `MAIN_V2` `BatchSpend` (`K=8`, SHA-384, 128 queries) | `641,180 B` | `80,147 B` | `3.27 s` | `52 ms` | **`6.49×` compression (~96 spends / 8 MB block)** |

### Honest Security & Formal Verification Boundaries

- **STARK Soundness:**
  - Winterfell `proven_security().ldr_bits()` reports `128` proven classical bits on `TEST`/`MAIN` (SHA-256) and `>= 140` proven classical bits on `MAIN_V2` (SHA-384 gives 192-bit classical / 128-bit BHT QROM hash collision resistance).
  - **Quantum FRI bound (honest estimate):** Under current Goldilocks cubic-extension (`192`-bit field) and conservative Johnson-bound QROM reductions (Chiesa–Manohar–Spooner, TCC 2019), overall quantum soundness is roughly **67–80 bits** depending on query/grinding assumptions — **not** "192-bit quantum".
- **Formal Verification Scope (`node/proof/SpendBalance.lean` & `node/proof/check.py`):**
  - `extract_constraints` + `proof/check.py` (Z3): checks all `249` spend-circuit constraints (`2,950` polynomial terms) against a FIPS 180-4 spec + 5 planted-bug self-tests.
  - `extract_lean_spend` + `proof/SpendBalance.lean` (Lean 4.36.0, **10 theorems**, `0 sorry`, zero Mathlib): proves extracted Constraints `#247` & `#248`, `< 2^60` note range, exact integer spend conservation, PayWord conservation, fee-burn block solvency, `PriorLock` 50/50 bounty/burn conservation, `BatchSpend` split-coinbase bounds, FlyClient work-interval uniqueness, and Utreexo/FRI-fold uniqueness.
  - **Not yet mechanized in Lean:** Full Lean mechanization of SHA-256 constraints `#0..#246` (comparable to Zcash Ironwood's 2,700+ theorem Lean proof) has **not** been done yet.

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
  prior.rs         minimal opt-in PriorLock collateral (objective/quorum disconfirm, 50/50 bounty+burn)
  channel.rs       unilateral partial-claim PayWord channels (pure SHA-256 + SLH-DSA)
  params.rs        issuance floor, 50% base-fee burn, split-coinbase prover share, Mainnet v2
  state.rs         ledger state, DigestParts, global solvency, split-coinbase validation
  light.rs         HeaderTip SPV + work-proportional FlyClient MMR light client
  pq_transport.rs  opportunistic NSPQ1 ML-KEM-768 P2P encryption (passive HNDL protection)
  utreexo.rs       1 KB compact note-tree frontier + tracked proofs
  pruned_store.rs  WAL/SSTable disk KV store & historical block pruner
  recursion.rs     SHA-256d HeaderChainAir + algebraic FriFoldVerifyAir R&D building blocks
  audit.rs         spend-circuit cell-freedom soundness scan
  job.rs           verified matrix-product escrow (Freivalds + fraud proofs + SLH-DSA)
  lock.rs          SHA-256 hash- and time-locked atomic swaps
  cond.rs / script.rs  bounded Bitcoin-style post-quantum script conditions
  pow.rs / auxpow.rs / signal.rs  ASERT launch ramp, Bitcoin AuxPoW (20051), BIP-9 signaling
  chain.rs / node.rs / peers.rs / rpc.rs / snapshot.rs / tx.rs / wallet.rs / deliver.rs / swap.rs
verifier-ts/       zero-dependency independent Node.js/OpenSSL consensus verifier
node/proof/        Lean 4.36.0 proofs + Z3 249-constraint checker
```
