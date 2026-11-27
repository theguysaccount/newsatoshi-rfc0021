# Newsatoshi (`LOVE`) — Mainnet v2 (`nsM2` · `v1.2.1`)

[![Mainnet v2](https://img.shields.io/badge/Mainnet%20v2-LIVE%20%C2%B7%20BTC%20%23977%2C738-10b981)](https://newsatoshi.org/)
[![Zero Premine](https://img.shields.io/badge/Fair%20Launch-0%20LOVE%20Premine-f59e0b)](node/genesis-v2.json)
[![Cryptography](https://img.shields.io/badge/ZK%20Proofs-100%25%20FIPS%20SHA--2%20%2F%20SHA--384%20STARKs-38bdf8)](docs/newsatoshi-v2.2.pdf)
[![Formal Verification](https://img.shields.io/badge/Lean%204.36-249%2F249%20Spend%20Constraints%20(0%20sorry)-a855f7)](node/proof/SpendCircuitFull.lean)
[![Bug Bounty](https://img.shields.io/badge/Security%20Bounty-Paid%20in%20Mined%20LOVE-ef4444)](docs/BUG_BOUNTY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-zinc)](LICENSE)

**Private, quantum-proof Bitcoin — shielded purely by FIPS SHA-2/SHA-384 STARKs, formally verified across all 249 spend constraints in Lean 4, and merge-mined directly by Bitcoin ASICs.**

- **Whitepaper (Satoshi-Format 8-Page PDF):** [newsatoshi.org/newsatoshi-v2.2.pdf](https://newsatoshi.org/newsatoshi-v2.2.pdf) · [Markdown Edition](docs/WHITEPAPER_V2_2.md)
- **Live Browser STARK Verifier & Mainnet Status:** [newsatoshi.org](https://newsatoshi.org/) · [Live Seed JSON](https://newsatoshi-seed-v2.fly.dev/status)
- **Public Security Bug Bounty (Paid in Fair-Mined `LOVE`):** [newsatoshi.org/bounty/](https://newsatoshi.org/bounty/) · [docs/BUG_BOUNTY.md](docs/BUG_BOUNTY.md)
- **Manifesto & Hyperscale Architecture:** [The Manifesto](docs/MANIFESTO.md) · [Hyperscale L1+L2 Roadmap](docs/HYPERSCALE_ARCHITECTURE.md) · [RFC-0028 `nsUSD` Private Dollar](docs/RFC-0028-NSUSD-SHIELDED-DOLLAR.md)
- **Layer-2 Agent Commerce & `nsUSD` Gateway:** [commons.newsatoshi.org](https://commons.newsatoshi.org/) ([`newsatoshi-commons`](https://github.com/theguysaccount/newsatoshi-commons))

---

## Why Newsatoshi Exists

Banks and card networks cannot onboard autonomous AI agents. Corporate stablecoins like USDC carry a central freeze switch and broadcast every supplier, margin, and treasury publicly. Bitcoin is unfreezable and backed by global physical work, but transparent on-chain and reliant on elliptic curves vulnerable to future quantum computers.

**Newsatoshi (`LOVE`) is the sovereign, neutral settlement floor for humans and autonomous machines:**
1. **Default Shielded Privacy — Pure SHA-2 Only:** Every balance and transfer is shielded by transparent **Quartic Goldilocks ($\mathbb{F}_{p^4}$) + FIPS SHA-384 Winterfell STARKs** (`192`-bit classical / `100–104`-bit conservative CMS19 QROM quantum soundness). **Zero elliptic curves, zero pairings, zero trusted setup, zero novel ZK-hashes.**
2. **Bitcoin Merge-Mining (`AuxPoW`, `chainid = 20051`):** Existing Bitcoin SHA-256 ASICs secure Newsatoshi simultaneously with **zero extra electricity**. Fair launch with **0 LOVE premine**, zero ICO, zero VC allocation, anchored openly to Bitcoin Block `#977,738`.
3. **Formally Verified in Lean 4.36.0 (`0 sorry`):** Live Rust `spend::eval_constraints` is symbolically extracted and machine-checked across **all 249 spend AIR constraints (`2,950` monomials)** inside Lean 4's pure kernel (`SpendCircuitFull.lean` + `SpendBalance.lean`).
4. **Built for Machine Velocity & Hyperscale:** Native `O(1)` SHA-256 `PayWords` streaming (`< 1 ms`, zero per-call gas), native SHA-256 atomic swaps with Bitcoin/Lightning/EVM/Solana, `BatchSpend` (`6.5×` STARK compression), `1 KB` Utreexo frontier, FlyClient MMR light proofs, and **`nsUSD`** private dollar settlement (`RFC-0028`).
5. **Credible Commitments (`PriorLock`) + 50% Fee Burn:** Half of every shielded transaction fee is permanently burned; opt-in `PriorLock` collateral enables falsifiable economic commitments (`50%` verifier bounty / `50%` burn on disconfirmation).

---

## Live Mainnet v2 (`nsM2` · `v1.2.1`) — Join in 60 Seconds

- **Canonical Genesis Hash:** `00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8`
- **Bitcoin Anchor:** Block `#977,738` (`0000000000000000000163900064a4cc4807dbd8bcaf35e322e694e6c387a780`) — [genesis-v2.json](node/genesis-v2.json)
- **Zero-Fee Bitaxe / ASIC AuxPoW Solo Pool:**
  ```text
  Stratum URL: stratum+tcp://pool.newsatoshi.org:3333
  Worker:      <YOUR_MAINNET_V2_ns1_ADDRESS>.rig1
  Password:    x
  ```
- **Run a Full Mainnet v2 Node + Multi-Threaded Miner (`NSPQ2` Authenticated Post-Quantum P2P):**
  ```bash
  git clone https://github.com/theguysaccount/newsatoshi-rfc0021.git
  cd newsatoshi-rfc0021/node
  cargo build --release --bin newsatoshi

  # Sync Mainnet v2 over SLH-DSA-pinned ML-KEM-768 P2P (add --mine --threads 8 to mine)
  ./target/release/newsatoshi --net mainnet-v2 node \
    --peer newsatoshi-seed-v2.fly.dev:8445@b024aaeafa0e4ca384b99483c28c3bedde45a5461a560063b283766414dfbbcc \
    --peer pool.newsatoshi.org:8445@78187a9436dd2d8cc7ed7afff2396b72b56687099d45d93da676b0a90ed8c6b6
  ```
- **Inspect your shielded address or read-only audit viewing key:**
  ```bash
  ./target/release/newsatoshi --net mainnet-v2 address
  ./target/release/newsatoshi --net mainnet-v2 viewing-key
  ```

---

## Architecture Comparison

| Property | Bitcoin | USDC (EVM/Sol) | Zcash (Orchard) | **Newsatoshi (`LOVE` + `nsUSD`)** |
| :--- | :---: | :---: | :---: | :---: |
| **Default Privacy** | No | No | Opt-in | **Yes (Mandatory Shielded)** |
| **Post-Quantum Safe** | No (`secp256k1`) | No (`secp256k1`) | No (Pasta curves) | **Yes (100% FIPS SHA-2/384 + SLH-DSA)** |
| **Zero Freeze Switch** | Yes | **No (Issuer Freeze)** | Yes | **Yes (`LOVE` & Sovereign `nsUSD`)** |
| **Zero Premine / Founder Tax** | Yes | Corporate | 20% Dev Fund | **Yes (`0 LOVE` Premine)** |
| **Bitcoin Merge-Mined** | Native | No | No | **Yes (`AuxPoW chainid = 20051`)** |
| **Formal Proof Coverage** | Partial | None | Halo 2 specs | **249/249 Live Rust AIR in Lean 4** |
| **Sub-Cent AI Streaming** | Lightning | Gas-limited | No | **Native `O(1)` SHA-256 PayWords** |

---

## Measured Mainnet v2 Cryptographic Benchmarks

Measured on Apple Silicon CPU (`opt-level = 2`, deps `opt-level = 3`):

| Operation (`MAIN_V2` Quartic $\mathbb{F}_{p^4}$ + SHA-384) | Proof Size | Per-Spend Size | Prove Time | Verify Time | Conservative QROM (CMS19) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Single Shielded Spend (`K = 1`) | `~603 KB` | `~603 KB` | **`~0.30 s`** | `~25 ms` | **`104` bits** (`192` classical) |
| `BatchSpend` (`K = 4`) | `~695 KB` | `~174 KB` | **`~0.68 s`** | `~26 ms` | **`102` bits** (`3.47×` comp) |
| `BatchSpend` (`K = 8`) | `~741 KB` | `~93 KB` | **`~1.28 s`** | `~38 ms` | **`101` bits** (`6.51×` comp) |
| `BatchSpend` (`K = 16`) | `~790 KB` | `~49 KB` | `~3.0 s` | `~70 ms` | **`100` bits** (`12.2×` comp) |
| **STARK-in-STARK IVC Fold** (`2` outer proofs → `1` inner) | `~677 KB` | — | **`~0.41 s`** | `~36 ms` | **`103` bits** (`204` SHA-256 + `10` FRI) |

---

## Verify Everything Independently (Zero Trust Required)

```bash
cd node

# 1. Zero-Rust independent JavaScript/OpenSSL consensus verifier self-test
node ../verifier-ts/newsatoshi_verifier.mjs --self-test

# 2. All 46 core unit tests (Quartic F_{p^4}, STARK-in-STARK IVC, BatchSpend, PriorLock, FlyClient, Utreexo, NSPQ2)
cargo test --lib

# 3. Full integration, differential fuzz, and red-team suites
cargo test --release --test priorism_fep_core --test mainnet_v2_readiness --test audit_redteam \
  --test differential_fuzz --test payword_channel --test attacks --test discovery \
  --test crypto_kats --test conds --test auxpow --test locks --test light --test mainnet_params --test chain

# 4. Re-extract and kernel-verify BOTH Lean 4.36.0 proofs (0 sorry, 0 native_decide, 0 Mathlib)
cargo run --release --example extract_lean_spend -- /tmp/SpendBalance.lean && diff -u proof/SpendBalance.lean /tmp/SpendBalance.lean && lean proof/SpendBalance.lean
cargo run --release --example extract_lean_circuit -- /tmp/SpendCircuitFull.lean && diff -u proof/SpendCircuitFull.lean /tmp/SpendCircuitFull.lean && lean proof/SpendCircuitFull.lean
```

---

## Public Security Bug Bounty (Paid in Fair-Mined `LOVE`)

We follow Satoshi's open cryptographic verification standard: don't trust claims — **break the math and claim real Mainnet v2 `LOVE`**.

- **Program Rules, Scope & Reward Tiers:** [docs/BUG_BOUNTY.md](docs/BUG_BOUNTY.md) · [docs/AUDIT_SCOPE_V2.md](docs/AUDIT_SCOPE_V2.md)
- **Public Mainnet v2 Bounty Wallet:** `ns1af734b0e0b0c1c6a54e206ba7a23f586daee77ede5e7c51b6ec6b133c51f572a99d8cb66`

---

## Clean Future Soft-Fork Path (Never Restart Genesis)

AuxPoW-safe BIP-9 signaling bits are pre-reserved in [`node/src/signal.rs`](node/src/signal.rs) so major future upgrades activate cleanly without touching Genesis `#0`:
- `BIT_FUTURE_COMPACT_PROOF = 5`: Pure-hash WHIR / Binius compact spend proofs (`2–4×` smaller proofs)
- `BIT_FUTURE_RECURSIVE_AGG = 6`: Zero-witness-visibility GPU STARK-in-STARK spend aggregation
- `BIT_MULTI_ASSET_NOTES = 7`: Native L1 multi-asset shielded notes (`LOVE` + Sovereign `nsUSD`, [`RFC-0028`](docs/RFC-0028-NSUSD-SHIELDED-DOLLAR.md))

---

## Minimalist L1 Module Map

```text
node/src/
  hash.rs          FIPS SHA-256 / SHA-384 compression & Winterfell hashers
  note.rs          shielded addresses, commitments, nullifiers, depth-32 note tree
  spend.rs         2-in/2-out shielded spend STARK (249 constraints, Haböck–Al Kindi masking)
  batch_spend.rs   K=2..=16 vertical STARK compression (incentive-compatible prover_fee)
  prior.rs         minimal opt-in PriorLock collateral (50% challenger bounty / 50% burn)
  channel.rs       unilateral partial-claim PayWord channels (O(1) SHA-256 + SLH-DSA)
  params.rs        Mainnet v2 (nsM2), 50% base-fee burn, perpetual 0.1953125 LOVE tail floor
  state.rs         strictly O(log N) Merkleized active state & global solvency invariant
  light.rs         work-proportional FlyClient MMR light client & HeaderTip SPV
  pq_transport.rs  NSPQ1 opportunistic & NSPQ2 SLH-DSA pinned ML-KEM-768 P2P transport
  utreexo.rs       1 KB compact note-tree accumulator frontier
  pruned_store.rs  WAL/SSTable disk KV store & historical block pruner (`newsatoshi prune`)
  recursion.rs     SHA-256d HeaderChainAir + real StarkInStarkVerifierAir IVC fold
  lock.rs / cond.rs / script.rs  native SHA-256 HTLCs & bounded post-quantum script conditions
  pow.rs / auxpow.rs / signal.rs staged ASERT ramp, Bitcoin AuxPoW (20051), BIP-9 signaling
verifier-ts/       zero-dependency independent Node.js/OpenSSL consensus verifier
node/proof/        Lean 4.36.0 pure-kernel proofs (SpendCircuitFull.lean + SpendBalance.lean)
docs/              Whitepaper v2.2 PDF & MD, Manifesto, Hyperscale Architecture, RFC-0028 nsUSD, Bug Bounty
```
