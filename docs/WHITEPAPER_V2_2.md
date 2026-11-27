# NEWSATOSHI/2.2: Pure SHA-2 Shielded Machine Cash

**Mainnet v2 (`nsM2`, `v1.2.1`) — Post-Quantum Privacy, Bitcoin Merged Mining, Lean 4 Mechanized Validity, and Priorism–FEP Settlement**

*Newsatoshi Contributors · November 27, 2026 · Canonical Genesis anchored to Bitcoin Block `#977,738`*  
*Live Terminal: https://newsatoshi.org/ · Commons & Telemetry: https://commons.newsatoshi.org/ · Reference L1: https://github.com/theguysaccount/newsatoshi-rfc0021*

---

## Abstract

The emerging economy of autonomous AI agents—software entities negotiating compute, data, APIs, and multi-step contracts at machine speed—exposes a structural void in existing payment rails. Traditional banks cannot onboard software; corporate stablecoins (such as USDC) are permissioned, freezable, and publicly transparent; and Bitcoin, while credibly neutral and unfreezable, exposes every balance and counterparty graph, relies on elliptic-curve signatures vulnerable to future quantum computers, lacks native streaming micropayments, and faces a declining block-subsidy security budget.

**Newsatoshi (`LOVE`) Mainnet v2 (`nsM2`)** is a minimalist, zero-premine Layer-1 monetary protocol designed as an unfreezable, private, post-quantum settlement floor for both humans and autonomous machines. Every shielded balance is protected exclusively by standard **FIPS 180-4 SHA-2 / SHA-384** hash functions inside transparent **Quartic Goldilocks ($\mathbb{F}_{p^4}$) Winterfell STARKs** (`192`-bit classical / `100–104`-bit conservative CMS19 QROM soundness, zero elliptic curves, zero trusted setup, zero novel algebraic ZK-hashes). Blocks are ordered by Bitcoin-compatible SHA-256d Proof of Work merge-mined directly by existing Bitcoin ASICs (`AuxPoW chainid = 20051`) under a Day-1 anti-instamine staged ASERT ramp (`1`-hour launch half-life transitioning smoothly at block `2,016` to `2`-day steady-state ASERT).

All `249` active constraints of the live Rust shielded-spend AIR and `10` core conservation/solvency theorems are mechanized in zero-dependency **Lean 4** (`0 sorry`, `0 Mathlib`, `0 native_decide`). Above the narrow L1 monetary floor, `nsM2` provides four native primitives for machine commerce and epistemic alignment: (1) `BatchSpend` proof compression (`K = 2..=16`, `6.5×` byte reduction at `K = 8` with incentive-compatible miner subsidy), (2) seller-signed `RFC-0022` `O(1)` SHA-256 PayWord streaming channels, (3) `PriorLock`—a minimal **Priorism / Free Energy Principle (FEP)** commitment primitive that rewards accurate verifiable forecasts and burns `50%` of disconfirmed stake, and (4) **Homeostatic Fee Burn** (`50%` base-fee burn counterbalancing the perpetual `0.1953125 LOVE/block` tail emission).

This paper documents the exact architecture live on Mainnet v2 (`v1.2.1`), its independent cross-client verification (`verifier-ts` + `<= 1 KB` Utreexo frontier + FlyClient MMR + pure-SHA-2 STARK-in-STARK IVC), its reserved BIP-9 soft-fork upgrade path, and an unvarnished disclosure of its remaining non-code ecosystem gates (`0/2` external human security audits and `0/3` independent real-difficulty Bitcoin pools at publication).

---

## 1. The Thesis: Why Autonomous Agents Need a New Monetary Floor

Autonomous AI agents are transitioning from passive chat assistants to active economic actors that hire other agents, purchase GPU inference, pay per-query APIs, post collateral for verifiable outputs, and settle contracts across jurisdictions without human intervention.

Every incumbent payment rail fails this regime along at least one fatal axis:

| Payment Rail | Unfreezable (No Issuer Kill-Switch) | Default Private Balances & Graph | Quantum-Proof Custody (Zero ECC) | Native Sub-Cent Machine Streaming | Bitcoin-Grade PoW Security Budget |
|---|---|---|---|---|---|
| **Banks / Cards / Stripe** | No (KYC/custodial) | No | N/A (custodial) | No (high fixed fees) | No |
| **Corporate Stablecoins (USDC/USDT)** | **No** (issuer blacklist & freeze keys) | **No** (100% public ledger) | No (ECC L1/L2s) | Partial (L2 gas) | No |
| **Bitcoin (L1 + Lightning)** | **Yes** | No (public UTXO graph) | No (`secp256k1` ECC) | Lightning (channel/ECC) | **Yes** (declining subsidy) |
| **Algebraic-Hash PQ Chains (e.g. Neptune)** | **Yes** | **Yes** | Relies on novel algebraic hash (Tip5) | No native PayWords | Standalone PoW (no BTC AuxPoW) |
| **Newsatoshi Mainnet v2 (`LOVE`, `nsM2`)** | **Yes** (zero issuer, zero premine) | **Yes** (100% shielded by default) | **Yes** (pure FIPS SHA-2 / SHA-384 + FIPS 205 SLH-DSA) | **Yes** (`RFC-0022` `O(1)` SHA-256 PayWords) | **Yes** (Bitcoin AuxPoW `20051` + perpetual tail floor) |

Two properties make corporate stablecoins structurally unfit as the base layer of an adversarial agent-to-agent market:
1. **Permissioned Freeze Risk:** An autonomous agent treasury held in USDC can be frozen globally by a single issuer blacklist transaction.
2. **Total Commercial Surveillance:** On transparent ledgers, every competitor immediately observes an agent swarm's suppliers, unit costs, margins, compute spend, and treasury runway in real time.

Newsatoshi follows the **Hourglass Principle** (TCP/IP and Bitcoin): keep Layer 1 radically small, cryptographically conservative, and engineered to ossify, while moving bridges, application SDKs, MCP tooling, and marketplaces above the narrow waist (`commons.newsatoshi.org`).

---

## 2. Canonical Mainnet v2 (`nsM2`) Genesis & Fair-Launch Ceremony

Newsatoshi's earlier November 10, 2026 `v0.1.0` chain is formally retired as a pre-audit canary (preserved read-only at `https://newsatoshi.org/v01/status`). Mainnet v2 (`nsM2`, `v1.2.0` / `v1.2.1`) launched as a single canonical, zero-premine genesis anchored directly to a live Bitcoin block hash cross-verified across independent Bitcoin explorers (`mempool.space` and `blockstream.info`):

- **Network ID / Magic / P2P Port:** `mainnet-v2` · `nsM2` · TCP `:8445` · AuxPoW `chainid = 20051` (`0x4e53`)
- **Bitcoin Anchor:** Block `#977,738` (`0000000000000000000163900064a4cc4807dbd8bcaf35e322e694e6c387a780`)
- **Genesis Message:** `NEWSATOSHI-V2 BTC#977738 0000000000000000000163900064a4cc4807dbd8bcaf35e322e694e6c387a780`
- **Genesis Timestamp / Compact Bits / Nonce:** `1795742750` (2026-11-27 01:25:50 UTC) · `0x1d00ffff` (real Bitcoin difficulty `1.0`) · `2649823154`
- **Canonical Genesis Hash:** `00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8`
- **Premine / Foundation / Project Self-Mining:** **`0 LOVE`** (Genesis pays no one; project seed nodes do not mine)
- **Pinned `NSPQ2` (`SLH-DSA-SHA2-128s`) Seeds:**
  - `newsatoshi-seed-v2.fly.dev:8445@b024aaeafa0e4ca384b99483c28c3bedde45a5461a560063b283766414dfbbcc`
  - `pool.newsatoshi.org:8445@78187a9436dd2d8cc7ed7afff2396b72b56687099d45d93da676b0a90ed8c6b6`

---

## 3. Pure SHA-2 / SHA-384 Shielded Note Protocol & Cryptographic Hardening

### 3.1 Hash-Only Shielded Notes
Every coin is an opaque note `(a_pk, v, rho)` with `v < 2^60` base units (`1 LOVE = 10^8` units), domain-separated purely with raw FIPS 180-4 `SHA256Compress`:

```text
a_pk = C("nsAD", sk, 0)
cm   = C("nsCM", a_pk, v_hi, v_lo, rho)
nf   = C("nsNF", sk, pos, rho, 0)
node = C(left, right)   // depth-32 append-only note Merkle tree
```

No elliptic curve key, pairing, discrete logarithm, or lattice assumption ever guards spend authority. Encrypted on-chain note delivery envelopes (`nsd1...`) use NIST FIPS 203 `ML-KEM-768` strictly for **recipient discovery confidentiality**; even a complete break of `ML-KEM-768` could never forge or steal a single base unit of `LOVE`.

### 3.2 `MAIN_V2` Quartic Goldilocks ($\mathbb{F}_{p^4}$) Pure SHA-384 STARKs
Spending notes proves knowledge of `(sk, rho, pos, path)` and exact integer balance conservation inside a zero-knowledge Winterfell 0.13.1 STARK (`247` trace columns × `8,192` rows, Haböck–Al Kindi randomized quotient segments):

- **Extension Field:** Quartic Goldilocks $\mathbb{F}_{p^4} = \mathbb{F}_p[u]/(u^4 - 7)$ ($256$-bit algebraic challenge space, $p = 2^{64} - 2^{32} + 1$).
- **Commitment & Fiat–Shamir Hash:** Pure **FIPS 180-4 SHA-384** (`192`-bit classical collision bound / `128`-bit BHT QROM collision bound).
- **FRI Parameters (`MAIN_V2`):** Blowup `B = 8`, Queries `q = 152`, PoW Grinding `g = 20` bits, Folding Factor `F = 8`.
- **Proven Security Across `BatchSpend` `K = 1..=16`:**
  - **Classical Proven Security:** `192` bits (Johnson-bound LDR, capped only by SHA-384 collision bound).
  - **Conservative Post-Quantum Soundness (CMS19 QROM):** **`104` bits (`K=1`), `102` bits (`K=4`), `101` bits (`K=8`), `100` bits (`K=16`)**.
  - **Pareto Optimality:** Verified analytically against Winterfell's Johnson-bound LDR formula (`vendor/winter-air/src/proof/security.rs`) that `B=8, q=152, g=20, F=8` is the exact Pareto optimum for `>= 100` QROM bits across all `K=1..=16`.
- **Measured Performance (`v1.2.1`):** Single `MAIN_V2` spend proof = `603,686` bytes, proved in `272 ms` native, verified in `16 ms` native and **`24.8 ms` in browser WebAssembly** (live at `https://newsatoshi.org/`).
- **Pre-Genesis Upstream Winterfell Patch:** During pre-genesis red-team stress testing, two upstream canonicalization bugs in `winter-math 0.13.1` (`f64::BaseElement::double()` and `mul_small()` returning unreduced values `>= M` with probability $2^{-33}$ and $2^{-32}$, causing intermittent `~5–8%` Quartic OOD failures) were isolated, patched in `node/vendor/winter-math/src/field/f64/mod.rs`, and stress-tested across `25/25` consecutive `MAIN_V2` Quartic batches (`75` full proofs, `0` failures).

### 3.3 `BatchSpend` Compression (`K = 2..=16`) & Incentive-Compatible Fees
Any user (self-batching with zero privacy loss) or delegated batch prover can fold `K ∈ [2, 16]` 2-in-2-out shielded spends into a single `MAIN_V2` Quartic SHA-384 STARK (`batch_spend.rs`), compressing `K = 8` spends from `4.83 MB` down to **`741,672` bytes (`6.51×` compression; `~92.7 KB/spend`, and `~49 KB/spend` at `K = 16`)**. `BatchSpend` commits to a dedicated `prover_fee` whose miner subsidy is incentive-compatible (`100%` of batch prover fee routed cleanly without breaking the base-fee burn invariant).

---

## 4. Mechanized Formal Verification (Lean 4 & Z3)

Following the June 2026 Zcash Orchard balance vulnerability, shielded monetary circuits must carry machine-checked soundness proofs rather than informal audits alone. Newsatoshi verifies its live Rust spend circuit (`node/src/spend.rs`) with two independent formal backends:

1. **Automated Z3 SMT Extraction (`node/proof/check.py`):** Extracts all `249` polynomial transition constraints (`2,950` terms) directly from the live Rust AIR and checks zero unintended cell freedom across all `1,138,176` active cells.
2. **Zero-Dependency Lean 4 Kernel (`0 sorry`, `0 Mathlib`, `0 native_decide`):**
   - **`node/proof/SpendCircuitFull.lean`:** Mechanizes all **`249`** live Rust spend AIR constraints and `7` no-wrap lemmas directly inside Lean 4's pure kernel.
   - **`node/proof/SpendBalance.lean`:** Proves **`10`** core monetary theorems: exact Constraint `#247/#248` spend balance conservation over `< 2^60` notes across all `4,607` active rows, `BatchSpend` conservation, `RFC-0022` PayWord channel deposit conservation, `PriorLock` 50/50 surprise bounty/burn conservation, Homeostatic 50/50 fee burn conservation, and global L1 solvency (`shielded_pool + locked + burned == issued`).

---

## 5. Monetary Policy, Priorism–FEP `PriorLock`, and Machine Commerce Primitives

### 5.1 Bitcoin Issuance Schedule + Perpetual Tail Floor + Homeostatic Fee Burn
- **Block Subsidy:** `50 LOVE/block`, halving every `210,000` blocks for `8` halvings (`20,917,968.75 LOVE`), followed by a perpetual tail floor of **`0.1953125 LOVE/block`** (`19,531,250` base units; `0.049%` initial annual tail dilution, strictly declining asymptotically toward `0%`) so miner incentives never collapse into fee-only instability.
- **Homeostatic Base-Fee Burn (`50%`):** On Mainnet v2 from block `0`, `50%` of every transaction's base fee (`5,000` bps) is provably burned (`state.burned`), while `50%` pays the block producer. Under high machine-commerce velocity, burned fees directly counterbalance tail issuance, aligning holders and miners without introducing discretionary monetary committees.

### 5.2 Day-1 Anti-Instamine Staged ASERT (`pow::asert_bits_staged`)
To prevent early GPU/ASIC instamines without centralized checkpoints:
- **Blocks `1..=2,016` (first ~14 days):** `1`-hour (`3,600 s`) ASERT launch half-life (`target_spacing = 600 s`, starting from real Bitcoin difficulty `1.0`, `0x1d00ffff`). Difficulty doubles every `6` fast blocks, rapidly absorbing sudden hashrate surges (verified under `1,000,000×` surge simulation).
- **Block `2,016+` (steady state):** Panic-free handoff anchored deterministically to Block `#2,016`'s `(bits, time)` into standard `2`-day (`172,800 s`) ASERT.

### 5.3 Priorism / Free Energy Principle (`PriorLock`)
Newsatoshi encodes a minimal epistemic commitment primitive (`node/src/prior.rs`, active from genesis on `nsM2`) grounded in **Priorism** and the **Free Energy Principle (FEP)**:
- An agent or human posts a shielded stake into a `PriorLock` committing to a verifiable prediction or service prior (`claim_hash`), challenge window, and `m`-of-`n` FIPS 205 `SLH-DSA` arbiter quorum (enforcing SCGS-I3 anti-self-arbitration: the poster cannot arbitrate their own prior).
- **Confirmed Prior (Low Surprise):** Stake returns intact to the honest agent.
- **Disconfirmed Prior (High Surprise / Prediction Error):** After capped miner fee (`<= 10%`), the slashable stake splits **exactly `50%` bounty to the challenger who proved the error and `50%` permanently burned**, coupling epistemic accuracy directly to monetary conservation.

### 5.4 Seller-Signed `RFC-0022` PayWord Channels
Hash-chain micropayments (Rivest–Shamir 1996) allow autonomous agents to stream millions of sub-cent API calls at **`O(1)` verification cost (`~0.01 ms`, zero per-call L1 gas)** backed by a single L1 channel lock (`node/src/channel.rs`). Seller `SLH-DSA` co-signing on `ChannelClaim` prevents adversarial-buyer early-close theft, while `O(log N)` Merkleized state maps keep consensus overhead logarithmic.

---

## 6. Post-Quantum Networking, Light Clients, Utreexo & Independent Verification

1. **Authenticated Post-Quantum P2P (`NSPQ1` + `NSPQ2`, `pq_transport.rs`):** Every Mainnet v2 node automatically negotiates `ML-KEM-768` + `SHA-256` AEAD (`NSPQ1`, blocking passive Harvest-Now-Decrypt-Later wiretapping) and supports FIPS 205 `SLH-DSA-SHA2-128s` peer-key pinning (`--peer HOST:PORT@<64hex_vk>`, `NSPQ2`, blocking active MITM) with `64 KB` chunked slowloris defense.
2. **Work-Proportional `O(log N)` FlyClient MMR (`light.rs`):** Every Mainnet v2 header commits to `header_mmr` inside `nsSTATE` (`DigestParts`, tag `F`) from block `0`, binding exact cumulative work into every MMR internal node (`nsMMRND1`) so sibling work inflation is cryptographically impossible.
3. **`<= 1 KB` Utreexo Shielded Note Accumulator (`utreexo.rs`, `pruned_store.rs`):** `CompactNoteTree` maintains bit-for-bit identical depth-32 note roots in **at most `1,024` bytes of RAM** regardless of whether the network holds `10` notes or `4.29` billion notes, exposed live at `GET /api/utreexo` and `newsatoshi utreexo-frontier`, alongside disk-backed pruned KV checkpoints (`newsatoshi prune`).
4. **Real Pure-SHA-2 STARK-in-STARK IVC Verifier (`recursion.rs`, `newsatoshi ivc-prove`):** Folds TWO actual serialized outer SHA-256 `HeaderChainAir` STARK proofs (`8` PoW headers) into ONE inner `>= 103`-bit QROM Quartic SHA-384 STARK proof (`254 × 16,384` rows, `204` bit-exact in-circuit SHA-256 compressions, `20`-bit PoW grinding, `10` Quartic FRI folds, `423 ms` prove / `40 ms` verify on laptop CPU). *Honest scaling boundary:* on single-machine CPU this verifies 100% of both outer transcripts, PoW grinding, IVC linkage, all 10 FRI folds, and the first coin-derived query's Merkle paths; proving all `152` outer queries (`~2^{21}` rows) linearly targets multi-core/GPU provers.
5. **Independent Second Verifier Client (`verifier-ts/newsatoshi_verifier.mjs`):** Zero shared Rust code—pure Node.js / OpenSSL / `BigInt` implementation verifying live Mainnet v2 Genesis, every Bitcoin AuxPoW merge-mined block, Day-1 staged ASERT difficulty, FlyClient MMR root, and `nsSTATE`/`header_commit("nsBLOCK")` live via `node verifier-ts/newsatoshi_verifier.mjs --live https://newsatoshi.org/mainnet`.

---

## 7. Honest Trade-Offs, Soft-Fork Roadmap & Open Non-Code Gates

Credible monetary protocols distinguish clearly between **solved engineering**, **future soft-fork improvements**, and **non-code adoption realities**:

### 7.1 Two Honest Architectural Trade-Offs & The Hyperscale Roadmap (Zero Genesis Restart)
Just like Bitcoin (2009), Zcash (2016), and Monero (2014), Mainnet v2 (`nsM2`, `BTC #977,738`) is a single permanent Genesis that never needs to restart to reach planetary scale (full architectural specification in `docs/HYPERSCALE_ARCHITECTURE.md`). **Zero-consensus hyperscale primitives** are already live today—`100,000+` TPS/core `RFC-0022` PayWord channels, BIP-152-style Compact Block Relay (`>95%` bandwidth savings in `node.rs`), `<= 1 KB` Utreexo frontiers, disk-pruned checkpoints, read-only `ViewingKey` (`nsvk1...`) scanning, and `8 MB` / `100,000`-tx block limits.

Two deliberate proof-layer trade-offs were kept conservative at Genesis #0 to minimize audit surface and prevent unaudited shielded inflation bugs, and are scheduled via **height-gated BIP-9 Coordinated Network Upgrades** (zero Genesis restart, zero coin migration—identical to Zcash Sapling→Orchard and Monero Bulletproofs+):
1. **Proof Size (`~603 KB` single / `~93 KB` per spend at `K=8` / `~49 KB` at `K=16`):** Pure FIPS SHA-2/SHA-384 prioritizes 25-year cryptanalytic conservatism and full Lean 4 mechanization over unaudited novel proof systems. BIP-9 **`BIT_FUTURE_COMPACT_PROOF = 5`** is reserved in `node/src/signal.rs` so audited pure-hash **WHIR / Binius** compact spend proofs (`2–4×` smaller) can activate cleanly at an agreed future height.
2. **Delegated `BatchSpend` Witness Visibility & L1 Onboarding Ceiling (`~0.27` TPS today → `~10` TPS post-recursion):** Self-batching leaks zero witness data; multi-user delegated batching shares witnesses with the batch prover until GPU-scaled zero-witness recursive block proofs land under BIP-9 **`BIT_FUTURE_RECURSIVE_AGG = 6`** (extending `StarkInStarkVerifierAir` to fold 1,000+ spends into one block proof, lifting L1 to `~5,800` txs / 8 MB block ≈ `~10` TPS / `~864,000` L1 channel settlements/day alongside L2 Channel Factories), followed by permanent monetary ossification via **`BIT_OSSIFY_MONETARY_BASE = 7`**.

### 7.2 Open Non-Code Ecosystem Gates (Tracked Live at `commons.newsatoshi.org/api/v2/cutover-readiness`)
Code alone cannot manufacture a monetary Schelling point. Mainnet v2 (`nsM2`) is live, open, and zero-premine, and transparently tracks two open external gates:
1. **External Independent Security Audits (`0/2` completed):** Requires two independent human cryptographic & consensus audits covering patched Winterfell segment masking & `f64` canonicalization, `spend.rs`, `batch_spend.rs`, `prior.rs`, `light.rs`, and `pq_transport.rs` (`docs/AUDIT_SCOPE_V2.md`, `docs/EXTERNAL_AUDIT_RFP.md`). Until completed, hold only what you can afford to lose.
2. **Independent Real-Difficulty Bitcoin AuxPoW Pools (`0/3` observed at `>= 10,000` difficulty):** `stratum+tcp://pool.newsatoshi.org:3333` operates at `0%` fee with direct solo coinbase payouts; sustained participation from three or more independent Bitcoin pools (`auxpow-stratum/MULTI_POOL_ONBOARDING.md`) remains the key external security-budget milestone.
