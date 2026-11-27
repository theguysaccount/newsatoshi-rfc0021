# RFC-0028: `nsUSD` — Private, Post-Quantum Dollar Settlement on Newsatoshi

**Status:** Canonical Specification (Tier 1 Live on L2 Commons · Tier 2 BIP-9 Soft-Fork Ready)  
**Network:** Newsatoshi Mainnet v2 (`nsM2`, `v1.2.1`, Bitcoin Anchor `#977,738`)  
**Genesis Restart Required:** **NO** (Zero changes to Genesis `#0`; L1 multi-asset notes activate cleanly via future BIP-9 soft fork)

---

## 1. Motivation: Solving Early-Volatility Adoption Without a Corporate Kill Switch

Layer-1 `LOVE` is sovereign, fairly mined, hard-capped-tail Proof-of-Work money secured by Bitcoin's global ASIC fleet. Like early Bitcoin (2009–2013), native PoW money experiences natural price volatility while liquidity, mining participation, and price discovery mature.

Real businesses, SaaS APIs, and autonomous AI agents paying `$0.0002` per inference call face an acute dilemma:
- **Corporate stablecoins (`USDC`, `USDT`)** provide USD stability, but carry a **central issuer freeze switch** and broadcast every supplier, treasury balance, and margin publicly on transparent ledgers.
- **Native `LOVE` (and Bitcoin)** cannot be frozen by any issuer, but volatile working capital makes USD-denominated invoicing difficult in early adoption.

`RFC-0028` defines **`nsUSD`**: a disciplined, two-tier private USD settlement architecture built natively on Newsatoshi's pure SHA-2/SHA-384 STARKs, `PayWords` streaming, atomic SHA-256 HTLCs, and `PriorLock` bonded collateral — **explicitly forbidding algorithmic undercollateralized pegs**.

---

## 2. Hard Invariants (What `nsUSD` Will Never Do)

1. **No Algorithmic / Undercollateralized `LOVE` Mint-Burn Pegs:** Minting USD against thin early `LOVE` liquidity risks an irreversible death spiral. Sovereign `nsUSD` MUST remain strictly over-collateralized by deep, liquid, verifiable collateral (`BTC` first, `LOVE` second at higher collateral ratios once liquid).
2. **Strict Separation of Risk Tiers (`asset_id` Isolation):** Any 1:1 bridged ERC-20 dollar (`nsUSD-B`) MUST carry a distinct asset identifier and explicit risk disclosure from sovereign unfreezable BTC-backed `nsUSD`. The protocol never conflates custodial bridge reserves with unfreezable sovereign collateral.
3. **Zero L1 Bloat:** Vault accounting, oracle aggregation, liquidation auctions, and merchant invoicing execute cleanly above the waist (Layer 2 / Commons / Rollup), while Layer 1 only ever needs one tiny future soft-fork (`BIT_MULTI_ASSET_NOTES`) to tag shielded notes with a 32-bit `asset_id`.

---

## 3. Tier 1 — Live Day-1 USD Stability (Zero L1 Fork)

### 3.1 Just-In-Time (JIT) USD-Denominated `x402` + `PayWords` Settlement (Live Today)
- APIs and AI agents quote prices strictly in **USD** (e.g., `$0.0005 / call`, `GET /api/v2/nsusd/quote?usd=0.0005`).
- High-frequency micro-calls stream off-chain in microseconds via `O(1)` SHA-256 `PayWords` (`0` per-call gas).
- Net channel balances settle atomically via zero-custody SHA-256 HTLCs (`Bitcoin BIP-199`, `Lightning BOLT-11`, `Base/Arbitrum/Optimism/Polygon`, or native Mainnet v2 `LOVE`), eliminating multi-day volatility exposure for both payer and merchant.

### 3.2 `nsUSD-B` — 1:1 Bridged Shielded Dollar (L2 Beta)
- Extends the immutable, ownerless `NewsatoshiBackingVault.sol` architecture (`0x37Ed94525DBE408fA72cDd156409875666679265`) with 1:1 verifiable deposit/redemption escrows for `USDC` / `USDS` / `DAI`.
- Deposits issue shielded `nsUSD-B` notes inside Newsatoshi's L2 private settlement pool so every downstream AI payment and supplier invoice is hidden by pure SHA-384 STARK proofs.
- **Explicit Trust Boundary:** `nsUSD-B` gives immediate privacy and micro-payment velocity while honestly inheriting underlying stablecoin issuer/bridge risk at redemption exits.

---

## 4. Tier 2 — Sovereign Unfreezable `nsUSD` (Zero Corporate Freeze Key)

Sovereign `nsUSD` is an unfreezable, post-quantum shielded dollar backed by over-collateralized sovereign crypto collateral:

| Component | Specification | Security Guarantee |
| :--- | :--- | :--- |
| **Primary Collateral** | **Native Bitcoin (`BTC`) at `>= 150%` Collateral Ratio** (`120%` liquidation threshold) | Deep `$1.5T+` global liquidity, zero issuer freeze key, native SHA-256 HTLC compatibility with Newsatoshi. |
| **Secondary Collateral** | **Native Mainnet v2 `LOVE` at `>= 250%` CR** *(activated only after deep liquid spot markets exist)* | Adds native `LOVE` collateral demand without ever exposing `nsUSD` to thin-market reflexive depegs. |
| **Price Oracle** | **`PriorLock` Bonded Median Oracle (RFC-0021)** | Oracle reporters stake `LOVE` inside L1 `PriorLock` commitments behind signed BTC/USD median quotes. Falsifiable manipulation triggers automatic `50%` challenger bounty + `50%` permanent `LOVE` burn. |
| **Hard Peg Floor** | **Liquity-Style Direct Collateral Redemption** | Any holder of `1 nsUSD` can always redeem it for `$1.00` worth of BTC collateral (minus a dynamic base redemption fee), enforcing `nsUSD ≈ $1.00` via permissionless arbitrage. |
| **Liquidation Engine** | **Stability Pool + Permissionless Keepers** | Vaults dropping below `120%` CR are absorbed atomically by Stability Pool depositors who receive discounted BTC collateral. |
| **L1 Shielded Notes** | **Future BIP-9 Soft-Fork (`BIT_MULTI_ASSET_NOTES = 7`)** | Extends the 249-constraint Winterfell SHA-384 Spend AIR commitment with a 32-bit `asset_id` (`0 = LOVE`, `1 = nsUSD`) and per-asset value conservation — letting `LOVE` and `nsUSD` share the **exact same shielded anonymity set** on Layer 1 with zero Genesis restart. |

---

## 5. Economic Alignment With Native `LOVE`

`nsUSD` strengthens `LOVE` directly:
1. **Fee Burn Flywheel:** Every L1 settlement, rollup state anchor, and vault checkpoint pays native `LOVE` transaction fees, permanently burning **50%** of every base fee (`state.burned`).
2. **Oracle Staking Demand:** `PriorLock` price reporters lock real `LOVE` collateral to earn oracle fees — misbehavior permanently burns `LOVE`.
3. **Real Commerce Funnel:** AI agents, privacy apps, and global businesses onboard via stable `nsUSD` and automatically hold shielded wallets capable of saving, bonding, and settling in sovereign `LOVE`.
