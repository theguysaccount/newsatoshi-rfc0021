# newsatoshi (`v1.2.0-mainnet-rc1`)

**Private, quantum-proof electronic cash secured by Bitcoin merge-mining — built strictly on SHA-2.**

Newsatoshi (`LOVE`) is designed as an **unfreezable, private settlement floor** for humans and autonomous AI agents. Stablecoins like USDC are freezable and 100% public (leaking every agent's suppliers, margins, and treasury on-chain); Bitcoin is unfreezable and credibly neutral, but transparent and not post-quantum. Newsatoshi combines **default shielded privacy**, **pure SHA-2 cryptography** (zero elliptic curves, zero trusted setup, zero novel ZK-hashes), **>= 100-bit conservative QROM quantum FRI soundness**, **full 249-constraint Lean 4 spend-circuit mechanization**, and **Bitcoin SHA-256 merge-mining (`AuxPoW`, `chainid = 20051`)**.

> **Honest Pre-Launch Status (`v1.2.0-mainnet-rc1`):**
> - **Pure-Code / Architectural Frontier:** Release Candidate 1 — all pre-mainnet consensus, cryptographic, economic, $O(N)$ DoS, Day-14 ASERT boundary, and P2P audit findings fixed and verified (including patching upstream Winterfell 0.13.1 `f64::BaseElement::double()` & `mul_small()` non-canonicalization bugs).
> - **External Security Audits:** **`0 / 2` completed** (hard blocker before mainnet genesis; scope packet in [`docs/AUDIT_SCOPE_V2.md`](docs/AUDIT_SCOPE_V2.md)).
> - **Independent Bitcoin AuxPoW Pools (`chainid = 20051`):** **`0 / 3` at Bitcoin-grade difficulty** (hard blocker before mainnet genesis).
> - **One Canonical Genesis:** The Nov 10 `v0.1.0` chain is retired as a pre-launch rehearsal/canary network. Production Mainnet will launch **once** via a single fresh Bitcoin-block-anchored `newsatoshi genesis-v2` ceremony (zero premine, Day-1 ASERT anti-instamine ramp) only after both external audits and >= 3 independent pools are verified. Live status: `GET https://commons.newsatoshi.org/api/v2/cutover-readiness`.

---

## The Hourglass Architecture (Strict Layer Separation)

Base layers become Schelling points by staying **radically small, neutral, and ossified** — like IP or Bitcoin — while richer protocols innovate freely on top.

| Layer | Repository / Ecosystem | What Lives Here | Explicitly Excluded |
| :--- | :--- | :--- | :--- |
| **Layer 2 & Applications** *(Above the Waist)* | [`newsatoshi-commons`](https://github.com/theguysaccount/newsatoshi-commons), `x402`, `ERC-8004`, agent escrow protocols (e.g. Psilo), liquidity bridges | 30-tool MCP gateway, Web4 charters, mission launchpads, zkTLS P2P market-maker desks, multi-chain BTC/Lightning/Solana/Base HTLC bridges, `x402` USDC on-ramps, opt-in agent arbitration/juries | Never requires L1 hard forks to iterate |
| **Layer 1 Settlement Floor** *(The Narrow Waist — This Repo)* | [`newsatoshi-rfc0021`](https://github.com/theguysaccount/newsatoshi-rfc0021) (`v1.2.0-mainnet-rc1`) | Default shielded transfers (`BatchSpend` compression with incentive-compatible `prover_fee`, Quartic $\mathbb{F}_{p^4}$ SHA-384 STARKs at `100–104` conservative QROM bits), SLH-DSA, Bitcoin AuxPoW (`chainid = 20051`) + panic-free Day-14 ASERT ramp, FlyClient MMR light proofs, strictly $O(\log N)$ Merkleized state, 50% fee burn, SHA-256 HTLCs, PayWord channels, `NSPQ1`/`NSPQ2` PQ P2P, and one minimal `PriorLock` collateral primitive | **No** L1 bonding-curve launchpads, **no** L1 subjective juries, **no** L1 rollup vaults or toy VMs, **no** legacy matrix jobs on `nsM2` |

---

## What Is Inside the Narrow Waist (`v1.2.0-mainnet-rc1`)

Everything in L1 consensus rests solely on **FIPS 180-4 SHA-2 (`SHA-256` / `SHA-384`)** and **FIPS 205 (`SLH-DSA-SHA2-128s`)**.

1. **Bitcoin-Compatible Ordering & Panic-Free Staged ASERT (`pow.rs`, `auxpow.rs`, `chain.rs`):**
   - 80-byte SHA-256d headers in Bitcoin's format + Namecoin-compatible AuxPoW (`chainid = 20051 = 0x4e53`), allowing existing Bitcoin SHA-256 mining hardware to secure the chain with zero extra electricity.
   - Continuous two-stage `aserti3-launch` difficulty ramp (1-hour half-life for the first 2,016 blocks -> 48-hour steady-state ASERT anchored at height `2,016`) verified end-to-end across height `2,015 → 2,016 → 2,017 → 2,025` in `Chain`, P2P `HeaderRun`/`prewarm`, SPV `HeaderTip`, FlyClient, and the independent JS verifier (`verifier-ts/newsatoshi_verifier.mjs`).
2. **Default Shielded Privacy, 256-Bit Quartic Goldilocks FRI & `BatchSpend` Compression (`spend.rs`, `batch_spend.rs`, `vendor/winter-*`):**
   - Single 2-in/2-out shielded spend: `8,192` rows x `247` columns, `249` Goldilocks AIR constraints, Haböck–Al Kindi (ePrint 2024/1037) masked quotient segments.
   - **256-Bit Quartic Goldilocks Extension ($\mathbb{F}_{p^4} = \mathbb{F}_p[x]/(x^4 - 7)$) + SHA-384 (`MAIN_V2`):** Uses `blowup = 8`, `queries = 152`, `grinding = 20`, `FieldExtension::Quartic`, and `SHA-384` — pushing **conservative QROM quantum FRI soundness (CMS19 Johnson bound: $\min(384/3,\; \text{unclipped\_ldr}/2)$) past 100 bits across `K = 1..=16`** (`104 / 102 / 101 / 100` conservative QROM bits alongside `192` classical LDR bits and `128`-bit BHT SHA-384 collision resistance), while patching upstream Winterfell 0.13.1 `f64::BaseElement::double()` and `mul_small()` non-canonical reduction bugs caught under high-row stress testing.
   - **Multi-Spend `BatchSpend` STARK Compression (`K ∈ 2..=16`):** Tiles `K` independent shielded spends vertically into ONE Winterfell STARK reusing `spend::eval_constraints` verbatim (`0` new circuit constraints). At `K = 8`, 8 shielded spends compress into **~741 KB total (~93 KB/spend = `6.5×` compression)** — proving in **~1.25 s** on Apple Silicon CPU and verifying in **~38 ms** (~80 shielded spends per 8 MB block).
   - **Incentive-Compatible `prover_fee` Split Coinbase (Zero Miner Censorship):** Every `Tx::BatchSpend` carries an explicit Fiat–Shamir-bound `prover_a_pk` and `prover_fee` paid strictly from the unburned batch fee budget (`burned_fee + prover_fee + miner_fee == sum(item.fee)`). AuxPoW miners **always retain 100% of block subsidy + `miner_fee`** (`sub + miner_fee >= sub`, proved in Lean 4 Theorem 8), eliminating any censorship incentive while guaranteeing the batch prover is paid atomically in coinbase.
   - **Honest privacy boundary:** Self-batching (exchanges, wallets, agent fleets) has zero privacy loss; delegated multi-user batching reveals spend witnesses to the batch prover until future STARK-in-STARK aggregation removes witness visibility.
3. **50% Base-Fee Burn, $O(\log N)$ Merkleized State & Minimal Conditional Locks (`params.rs`, `prior.rs`, `channel.rs`, `lock.rs`, `cond.rs`, `state.rs`):**
   - **Monetary Policy & 50% Fee Burn:** Bitcoin's halving schedule down to a perpetual `0.1953125 LOVE/block` miner security floor, paired with permanent burning of **50% of every shielded spend / batch-spend fee** into `state.burned`.
   - **Strictly $O(\log N)$ Active State Commitment (`nsM2`):** Every active consensus collection (`NoteTree`, `NfTree`, `HeaderMmr`, `locks`, `conds`, `channels`, `priors`) is incrementally Merkleized in $O(\log N)$ per mutation with $O(1)$ per-block digesting (zero $O(N)$ per-block state re-hashing DoS), and legacy matrix jobs (`job.rs`) are disabled on `nsM2`.
   - **SHA-256 HTLCs & PayWord Channels (`lock.rs`, `channel.rs`):** Native `SHA-256` hash-time locks for zero-custody atomic swaps with Bitcoin, Lightning, Solana, and EVM chains (with Merkle inclusion proofs exposed on `/api/lock` & `/api/cond`), plus unilateral partial-claim PayWord channels for sub-millisecond agent micropayments.
   - **Falsifiable Collateral Lock (`PriorLock`, `prior.rs`):** One minimal, opt-in collateral primitive (`stake >= 0.01 LOVE`) for objective slashable commitments (hash preimage, double-sign equivocation, or user-chosen independent `M-of-N` SLH-DSA arbiters enforcing `arbiter_vk != owner_vk`). Valid disconfirmation splits net collateral **50% bounty / 50% burn**; clean expiration unlocks back to the owner. *(Subjective arbitration and rich escrow workflows remain opt-in at Layer 2; L1 has no global jury or oracle.)*
4. **Work-Proportional FlyClient Light Proofs, Utreexo 1 KB Frontier & Authenticated PQ P2P (`light.rs`, `utreexo.rs`, `pruned_store.rs`, `pq_transport.rs`):**
   - **Work-Proportional FlyClient (`light.rs`):** Integer-only `U512` work-offset sampling over `[0, ancestor_work)` (blocks sibling-work inflation), bound to the tip header via `DigestParts::header_mmr` and rightmost-leaf tail proofs.
   - **Opportunistic `NSPQ1` & Authenticated `NSPQ2` ML-KEM-768 P2P (`pq_transport.rs`, wired into `node.rs`):** Auto-negotiates ephemeral FIPS 203 `ML-KEM-768` transport (`NSPQ1` for zero-config passive HNDL resistance, or `NSPQ2` with NIST FIPS 205 `SLH-DSA-SHA2-128s` peer-identity pinning via `--peer HOST:PORT@<64hex_vk>` & `newsatoshi p2p-key` to block active MITM), hardened with 64 KB incremental chunked reads and `MIN_BYTES_PER_SEC` pacing against slowloris OOM DoS.
   - **Utreexo 1 KB Note Frontier & Disk KV Pruner:** Constant `<= 1,024 B` RAM accumulator (`utreexo.rs`) + WAL/SSTable disk KV store & `newsatoshi prune` block pruner (`pruned_store.rs`, `nsSNAP06` snapshots).

<details>
<summary>Theoretical Background Note (Priorism / Free-Energy Principle motivation)</summary>

The 50% fee burn and `PriorLock` 50/50 disconfirmation bounty+burn were informed by a Priorism / Free-Energy Principle (FEP) framing: treating credible commitments as falsifiable priors where surprise triggers collateral burn and accurate prediction preserves capital, while keeping the consensus code itself strictly minimal, objective, and free of any global L1 oracle or subjective referee.

</details>

---

## Honest Positioning vs. Related Systems

- **Neptune Cash (NPT):** Already runs a live PoW L1 with default privacy (Mutator Sets), hash-only post-quantum STARKs (Tip5 + Triton VM), split Composer/Guesser mining, and recursive chain proofs. Newsatoshi makes a narrower cryptographic bet: **SHA-2 only** (25 years of cryptanalysis + native Bitcoin/Lightning `OP_SHA256` swaps, at the cost of much heavier recursion) + **Bitcoin AuxPoW merge-mining** + **native AI-agent rails (`newsatoshi-commons`)**.
- **Miden:** Mature STARK VM and client-side privacy, settling as an Ethereum L2 rather than sovereign PoW base money.
- **Recursive Chain Proof Status (`node/src/recursion.rs`):** `StarkInStarkVerifierAir` (`254` cols × `16,384` rows, `404` constraints) is a **working pure-SHA-2 STARK-in-STARK IVC recursive verifier** that folds TWO real serialized outer `HeaderChainAir` STARK proofs (which now include in-circuit `HP_POW_CHK` PoW verification in addition to SHA-256d header chaining) into **ONE** inner `~677 KB` Quartic SHA-384 STARK proof in **~0.41 s** (verifying in **~36 ms**) at **103 conservative QROM bits** — executing `204` bit-exact FIPS 180-4 SHA-256 compressions in-circuit plus all `10` real Quartic $\mathbb{F}_{p^4}$ FRI folding equations.
  - **Honest scaling boundary:** The CPU-sized `16,384`-row inner STARK verifies 100% of both outer transcripts, grinding, IVC linkage, all 10 FRI fold layers, and the first coin-derived query's Merkle paths; scaling linearly to verify all `152` outer queries + full OOD constraint evaluation inside one proof (`~152×` / `~2^{21}` rows) is a multi-core/GPU prover milestone using the same AIR gadget. Production L1 light clients today verify headers logarithmically via **work-proportional FlyClient MMR** and blocks compress spends via **`BatchSpend` (`K = 2..=16`)**.

---

## Measured Benchmarks & Honest Security Parameters

Measured locally on Apple Silicon CPU (`cargo test`, `opt-level = 2`, deps `opt-level = 3`):

| Operation / Profile | Measured Proof Size | Per-Spend Size | Prove Time | Verify Time | Conservative QROM (CMS19) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `TEST` Single Spend (`K=1`, SHA-256, `q=64`) | ~249 KB | ~249 KB | ~0.5 s | ~10 ms | Testnet / Regtest |
| `TEST` `BatchSpend` (`K=4`, SHA-256, `q=64`) | ~280 KB | ~70 KB | ~2.1 s | ~34 ms | Testnet / Regtest |
| `MAIN_V2` Single Spend (`K=1`, Quartic $\mathbb{F}_{p^4}$, SHA-384, `B=8, q=152, g=20`) | `~603 KB` | `~603 KB` | **`~0.30 s`** | ~25 ms | **`104` bits** (`192` classical) |
| `MAIN_V2` `BatchSpend` (`K=4`, Quartic $\mathbb{F}_{p^4}$, SHA-384) | `~695 KB` | `~174 KB` | **`~0.68 s`** | **`~26 ms`** | **`102` bits** (`3.47×` comp) |
| `MAIN_V2` `BatchSpend` (`K=8`, Quartic $\mathbb{F}_{p^4}$, SHA-384) | `~741 KB` | `~93 KB` | **`~1.28 s`** | **`~38 ms`** | **`101` bits** (`6.51×` comp, ~80 spends / 8 MB) |
| `MAIN_V2` `BatchSpend` (`K=16`, Quartic $\mathbb{F}_{p^4}$, SHA-384, theoretical) | ~790 KB | ~49 KB | ~3.0 s | ~70 ms | **`100` bits** |
| **STARK-in-STARK IVC Fold** (`StarkInStarkVerifierAir`, 2 outer proofs → 1 inner, `16,384×254`) | `~677 KB` | — | **`~0.41 s`** | **`~36 ms`** | **`103` bits** (`204` SHA-256 + `10` Quartic FRI) |

### Honest Security & Formal Verification Boundaries

- **STARK Soundness (`MAIN_V2` Quartic Goldilocks $\mathbb{F}_{p^4}$ + SHA-384):**
  - Classical proven LDR security: **`192` bits** (`unclipped_ldr` = `208.4 / 204.4 / 202.4 / 200.4` for `K = 1 / 4 / 8 / 16`; SHA-384 gives `192`-bit classical collision resistance).
  - **Conservative Quantum QROM Soundness (CMS19 Johnson bound + BHT):** `ProvenSecurity::qrom_ldr_bits(384) = min(384 / 3, unclipped_ldr / 2)` yields **`104 / 102 / 101 / 100` conservative quantum bits** for `K = 1 / 4 / 8 / 16` (`103` bits for `StarkInStarkVerifierAir`) alongside `128`-bit BHT QROM SHA-384 collision resistance — eliminating the earlier ~67–80 bit cubic-extension ceiling.
- **Full 249-Constraint Lean 4.36.0 Formal Verification (`node/proof/SpendCircuitFull.lean` & `node/proof/SpendBalance.lean`):**
  - **`extract_lean_circuit` + `proof/SpendCircuitFull.lean` (Lean 4.36.0 pure kernel, ~9 s, `0 sorry`, `0 warnings`, `0 native_decide`, `0 Mathlib`):** Executes live compiling Rust `spend::eval_constraints` symbolically (cross-checked at 20 random Goldilocks points), extracts **ALL 249 transition constraint polynomials (`#0..#248`, `2,950` monomial terms)**, and proves inside Lean 4's trusted kernel:
    1. Independent NIST FIPS 180-4 SHA-256 specification verified against official `SHA-256("")` and `SHA-256("abc")` vectors.
    2. Exact multilinear bit-polynomial identities (`XOR2`, `XOR3`, `Ch`, `Maj`, 32-bit word packing `< 2^32`).
    3. **`all_249_constraints_match_fips180_4_spec`:** Pure-kernel equality of all 249 live Rust polynomials (`#0..#248`) to the independent FIPS 180-4 shielded spend AIR spec.
    4. All **7 no-wrap & unreduced-word (`a_64`, `e_64`, `W_0`) Goldilocks arithmetic lemmas** proved natively in Lean 4 (replacing external Z3 SMT trust).
    5. 64-round SHA-256 compression induction, 32-level Merkle `pos` bit-accumulator induction, and exact 128-block layout & boundary counts.
  - **`extract_lean_spend` + `proof/SpendBalance.lean` (Lean 4.36.0, ~0.8 s, 10 theorems, `0 sorry`, `0 Mathlib`):** Proves `#247`/`#248` conservation, `< 2^60` note range, PayWord channels, 50% fee-burn solvency, `PriorLock` 50/50 bounty/burn, **incentive-compatible `BatchSpend` `prover_fee` conservation (`sub + miner_fee >= sub`)**, FlyClient work-interval uniqueness, and Utreexo/FRI uniqueness.
  - **Honest formal boundary:** Our Lean 4 mechanization proves exactness of all 249 live Rust AIR polynomials, the Goldilocks no-wrap arithmetic, and the accounting/protocol invariants; it does **not** formally verify the Winterfell Rust FRI/FFT prover/verifier implementation itself (which requires independent human cryptography audits — currently `0 / 2`).

---

## Build, Verify & Reproduce Offline

```bash
cd node

# 1. Independent Node.js/OpenSSL second verifier self-test
node ../verifier-ts/newsatoshi_verifier.mjs --self-test

# 2. All 46 unit tests (incl. Quartic F_{p^4} axioms, real STARK-in-STARK IVC fold, PriorLock, BatchSpend, FlyClient)
cargo test --lib

# 3. Full integration, readiness, differential JS<->Rust, 10k mutation fuzz, and red-team suites
cargo test --release --test priorism_fep_core --test mainnet_v2_readiness --test audit_redteam \
  --test differential_fuzz --test payword_channel --test attacks --test discovery \
  --test crypto_kats --test conds --test auxpow --test locks --test light --test mainnet_params --test chain

# 4. Re-extract and kernel-verify BOTH Lean 4.36.0 formal proofs (0 sorry, 0 native_decide, 0 Mathlib)
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean
diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean
lean proof/SpendBalance.lean

cargo run --release --example extract_lean_circuit -- /tmp/SpendCircuitFull.lean
diff -u proof/SpendCircuitFull.lean /tmp/SpendCircuitFull.lean
lean proof/SpendCircuitFull.lean

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
  batch_spend.rs   multi-spend K=2..=16 STARK compression (incentive-compatible prover_fee)
  prior.rs         minimal opt-in PriorLock collateral (objective/quorum disconfirm, 50/50 bounty+burn)
  channel.rs       unilateral partial-claim PayWord channels (pure SHA-256 + SLH-DSA)
  params.rs        issuance floor, 50% base-fee burn, split_batch_fee, Mainnet v2 (nsM2)
  state.rs         ledger state, DigestParts, O(log N) Merkle locks/conds, global solvency
  light.rs         HeaderTip SPV (steady_anchor) + work-proportional FlyClient MMR light client
  pq_transport.rs  NSPQ1 opportunistic + NSPQ2 SLH-DSA pinned ML-KEM-768 P2P (chunked anti-slowloris)
  utreexo.rs       1 KB compact note-tree frontier + tracked proofs
  pruned_store.rs  WAL/SSTable disk KV store & historical block pruner (`newsatoshi prune`)
  recursion.rs     SHA-256d HeaderChainAir (in-circuit PoW) + real StarkInStarkVerifierAir IVC fold
  audit.rs         spend-circuit cell-freedom soundness scan
  job.rs           legacy matrix-product escrow (disabled on Mainnet v2 `nsM2`)
  lock.rs          SHA-256 hash- and time-locked atomic swaps (Merkleized on `nsM2`)
  cond.rs / script.rs  bounded Bitcoin-style post-quantum script conditions (Merkleized on `nsM2`)
  pow.rs / auxpow.rs / signal.rs  panic-free staged ASERT ramp, Bitcoin AuxPoW (20051), BIP-9 signaling
  chain.rs / node.rs / peers.rs / rpc.rs / snapshot.rs / tx.rs / wallet.rs / deliver.rs / swap.rs
verifier-ts/       zero-dependency independent Node.js/OpenSSL consensus verifier (incl. staged ASERT)
node/proof/        Lean 4.36.0 proofs (`SpendCircuitFull.lean` + `SpendBalance.lean`) + Z3 checker
```
