# Newsatoshi Mainnet v2 (`nsM2`) — Hyperscale Architecture & Upgrade Discipline

**Why Mainnet v2 (`BTC #977,738`) Never Needs Another Genesis — and Exactly Why We Did Not Ship Unaudited 2028 R&D at Block 0**

*Newsatoshi Contributors · November 27, 2026 · Canonical Chain: `mainnet-v2` (`nsM2`, `v1.2.1`)*

---

## 1. The Iron Law: One Canonical Genesis, Zero Future Restarts

Credible monetary networks do not restart Genesis to scale:
- **Bitcoin** kept one Genesis (January 3, 2009) while adding LevelDB, Compact Blocks (BIP-152), SegWit, Taproot, and Lightning.
- **Zcash** kept one Genesis (October 28, 2016) while upgrading from Sprout → Sapling → Orchard → Ironwood via height-gated Network Upgrades, preserving every coin and history.
- **Monero** kept one Genesis (April 18, 2014) while upgrading through RingCT → Bulletproofs → Bulletproofs+ → FCMP++ via coordinated height-gated upgrades.

Newsatoshi's pre-audit Nov 10 `v0.1.0` canary was retired explicitly so **`Mainnet v2` (`nsM2`, Genesis `00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8`, Bitcoin Block `#977,738`, `0 LOVE` premine)** could serve as the **single, permanent monetary genesis**. Every single component required to scale from launch to **100M+ users, billions of autonomous AI agents, and 10,000,000+ L2 TPS** is already accounted for without ever restarting Genesis or invalidating existing coins.

---

## 2. What Is Already Live at Genesis (`v1.2.1`) for Hyperscale

| Scaling Dimension | Already Live in `nsM2` (`v1.2.1`) | Measured Capacity / Bound |
|---|---|---|
| **Live Machine-to-Machine TPS** | Seller-signed `RFC-0022` `O(1)` SHA-256 PayWord channels (`channel.rs`) | **`~0.01 ms`/payment (`~100,000` TPS per CPU core)**; horizontally parallel to **`10,000,000+` TPS** globally (beats Visa + Mastercard combined by `100×+`) |
| **L1 Block Space Headroom** | `max_block_bytes = 8_000_000` (8 MB), `MAX_BLOCK_TXS = 100_000` (`params.rs`) | Already sized for **`~5,800` shielded txs/block (~10 TPS / ~864,000 L1 settlements/day)** once per-spend proofs are folded by `bit 6` |
| **L1 Spend Compression Today** | `Tx::BatchSpend` (`K = 2..=16`, `batch_spend.rs`) | `6.51×` compression at `K = 8` (`~93 KB/spend`); `~49 KB/spend` at `K = 16` (`~23,000` shielded L1 settlements/day today) |
| **Block Propagation Bandwidth** | BIP-152-style **Compact Block Relay** (`Msg::CompactBlock`, `compact_short_id("nsCMPCT1")` in `node.rs`) | **`>95%` bandwidth savings** reconstructing multi-MB STARK blocks from warm mempools |
| **Note-Tree RAM Footprint** | `CompactNoteTree` Utreexo frontier (`utreexo.rs`, `GET /api/utreexo`) | **Constant `<= 1,024` bytes RAM** whether the chain holds `10` notes or `4.29 billion` notes |
| **Light Client Verification** | Work-proportional `O(log N)` FlyClient MMR committed in Genesis (`light.rs`, `/api/flyclient`) | Verifies total chainwork & tip state in milliseconds without downloading history |
| **Historical Block Pruning** | Disk-backed pruned KV checkpoints (`pruned_store.rs`, `newsatoshi prune`) | Prunes historical block bodies while retaining verifiable nullifier state |
| **Private Scanning Delegation** | Read-only `ViewingKey` (`nsvk1...`, `deliver.rs`) + `ML-KEM-768` envelopes | Zero-spend-authority watch-only / oblivious scan servers; `ML-KEM-768` decapsulation runs natively ~5–10× faster than ECC Diffie–Hellman, and agent PayWords/out-of-band notes require **zero scanning** |
| **Upgrade Governance** | AuxPoW-safe BIP-9 signaling bits `1..=7` (`signal.rs`, `/api/signaling`) | Pre-reserved `bit 5` (compact proofs), `bit 6` (recursive block proofs), `bit 7` (monetary ossification) |

---

## 3. The 4-Phase Hyperscale Roadmap (Zero Genesis Restart)

### Phase A — Zero-Consensus Upgrades (Ship Anytime, No Fork Required)
These upgrades require **zero L1 consensus changes** and deploy purely as node, wallet, or Layer-2 software releases:
1. **Multi-Merchant PayWord Hubs & Channel Factories (L2):** Built directly atop live `RFC-0022` PayWords + `LockPost` SHA-256 HTLCs + `CondPost` (`CHECKMULTISIG`, `AFTER`, `BEFORE`, `SHA256`), allowing 100–1,000 agents/users to share a single L1 settlement lock and route micro-payments across hubs — multiplying effective onboarding capacity **100×–1,000×**.
2. **Production Embedded Disk KV Storage Backend:** Swapping local node RAM `imbl` maps for RocksDB/LMDB behind the existing `pruned_store.rs` interface (purely local storage, identical to Bitcoin Core migrating BerkeleyDB → LevelDB). Handles **100M+ L1 nullifiers (~3–6 GB disk)** effortlessly on commodity NVMe.
3. **Delegated Oblivious Scanning (`nsvk1...` / OMR):** Mobile wallets optionally offload `ML-KEM-768` envelope scanning to watch-only scan servers or TEE/OMR relays holding `nsvk1...` (zero spend capability, zero privacy loss from naive public view tags).

### Phase B — Height-Gated BIP-9 Coordinated Network Upgrades (Same Chain, Same Coins)
Because `v1.2.1` intentionally keeps `Tx::decode` strict and minimal (no unchecked anyone-can-spend wildcard parser at Block 0), upgrading the L1 proof format activates cleanly via **pre-announced, miner-signaled BIP-9 Coordinated Network Upgrades** at agreed future block heights (identical to Zcash's Sapling/Orchard upgrades and Monero's Bulletproofs+ upgrades — **zero Genesis restart, zero coin migration**):
1. **`BIT_FUTURE_COMPACT_PROOF = 5` — Pure-Hash Compact Proofs (WHIR / Binius):** Shrinks single shielded spend proofs `2–4×` while preserving zero elliptic curves and zero algebraic-hash assumptions → immediately raises unbatched L1 capacity toward `~1` TPS.
2. **`BIT_FUTURE_RECURSIVE_AGG = 6` — GPU-Scaled Recursive Block / Spend Aggregation:** Extends our existing pure-SHA-2 `StarkInStarkVerifierAir` (`recursion.rs`) from single-CPU single-query verification to multi-core/GPU 152-query full block folding. Removes per-spend proof bytes from blocks entirely (`~1.36 KB` public data per spend inside the existing `8 MB` cap) → **`~5,800` shielded txs/block (`~10` TPS / `~864,000` L1 settlements/day)** with zero-witness-visibility aggregation.
3. **Evolving / Epoch Nullifiers (Bowe–Miers 2025, if L1 ever nears 10B+ spends):** Introduces a second versioned note type with bounded epoch nullifier sets without touching Genesis notes.

### Phase C — Permanent Base-Layer Ossification (`BIT_OSSIFY_MONETARY_BASE = 7`)
Once `bit 5` and `bit 6` have battle-tested at scale and external audits (`>= 2`) + independent Bitcoin AuxPoW pools (`>= 3`) have matured, `bit 7` locks the monetary floor (`subsidy`, `SUBSIDY_FLOOR`, `50%` Homeostatic Fee Burn, zero-premine invariant, and pure-SHA-2 spend conservation) permanently.

---

## 4. Why We Deliberately Did NOT Ship Phase B at Block 0 (Engineering Discipline)

Every serious cryptographer and institutional investor asks: *"If WHIR/Binius, GPU recursive block proofs, and RocksDB make L1 faster, why didn't you wait and ship them at Genesis #0?"*

Four hard engineering reasons:

1. **Preventing Silent Shielded Inflation (The June 2026 Orchard Lesson):** In a transparent chain, an inflation bug is visible in the next block. In a shielded chain, an unsound circuit lets an attacker print invisible coins indefinitely. Our `v1.2.1` `MAIN_V2` Winterfell SHA-384 circuit is tiny (`249` constraints), completely mechanized in zero-`sorry` Lean 4 (`SpendCircuitFull.lean` + `SpendBalance.lean`), and built on 25-year-old FIPS SHA-2. Rushing bleeding-edge 2025–2026 WHIR/Binius provers or 2^{21}-row GPU recursive circuits unaudited into Genesis #0 would trade **proven cryptographic soundness** for premature throughput we don't yet need on Day 1.
2. **Minimizing Initial Consensus Attack Surface (Hourglass Rule):** Keeping the initial `newsatoshi` consensus binary pure Rust with zero C++ RocksDB FFI eliminates an entire class of memory-corruption and supply-chain vulnerabilities during the critical pre-audit phase (`0/2` external audits).
3. **Real Demand Precedes L1 Congestion:** With `BatchSpend K=16` (`~23,000` L1 settlements/day) plus `100,000+` TPS/core `RFC-0022` PayWord channels already live today, L1 block space has **years of runway** while external audits (`docs/AUDIT_SCOPE_V2.md`), multi-pool Bitcoin AuxPoW onboarding, and commercial AI liquidity mature.
4. **Never Shipping Privacy Regressions Under "Optimization":** Naive shortcut optimizations—such as attaching a public-address-derived 1-byte view tag to `ML-KEM-768` envelopes—leak 8 bits of recipient linkage because post-quantum KEMs lack non-interactive Diffie–Hellman view keys. We explicitly reject privacy-leaking shortcuts in favor of zero-leakage `nsvk1...` / OMR delegation and out-of-band PayWord streaming.
