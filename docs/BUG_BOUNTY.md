# Newsatoshi (`LOVE`) Public Security Bug Bounty Program

**Verify the math. Break the code. Collect `LOVE`.**

*Canonical Mainnet v2 (`nsM2`) · Genesis `00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8` (Bitcoin Block `#977,738`)*

---

## 1. Philosophy

Newsatoshi's security model is simple: every consensus rule, every STARK constraint, and every Lean 4 proof is open source for anyone on Earth to inspect, attack, and verify. Rather than asking anyone to trust credentials or closed reviews, we reward real cryptographic and consensus findings directly in native **`LOVE`** mined on Mainnet v2 (`nsM2`).

---

## 2. Public Bug Bounty Treasury (Mainnet v2)

All bounty payouts come from real, fair-mined `LOVE` accumulated in the public Bug Bounty wallet (zero premine — funded purely by live Proof-of-Work mining and voluntary community contributions):

- **Mainnet v2 Shielded Mining / Bounty Address (`ns1...`):**  
  `ns1af734b0e0b0c1c6a54e206ba7a23f586daee77ede5e7c51b6ec6b133c51f572a99d8cb66`
- **Mine Directly to Support the Bounty Treasury (0% Fee Solo Pool):**  
  `stratum+tcp://pool.newsatoshi.org:3333`  
  Worker username: `ns1af734b0e0b0c1c6a54e206ba7a23f586daee77ede5e7c51b6ec6b133c51f572a99d8cb66.bounty`
- **Live On-Chain Status & Balance:** Funded directly by live Mainnet v2 blocks mined to the address above; payout awards scale up to the verified available treasury balance and are disbursed transparently via shielded Mainnet v2 transactions (with optional public payment proof).

---

## 3. Target Scope & Reward Tiers (Denominated in `LOVE`)

Full cryptographic scope and exact SHA-256 module hashes live in [`docs/AUDIT_SCOPE_V2.md`](https://github.com/theguysaccount/newsatoshi-rfc0021/blob/main/docs/AUDIT_SCOPE_V2.md).

| Severity | Scope & Impact | Target Reward (in `LOVE`) |
|---|---|---|
| **Critical** | Shielded spend soundness / counterfeit `LOVE` creation, double-spend bypass, Winterfell segment-masking / `f64` field exploit, `SpendCircuitFull.lean` / `SpendBalance.lean` proof-to-Rust mismatch, consensus chain split, or AuxPoW forgery | **Up to 50% of Bounty Treasury** (target **1,000–10,000+ LOVE** as mined pool grows) |
| **High** | Remote node crash / consensus DoS, `BatchSpend` fee/prover-fee conservation break, `PriorLock` SCGS-I3 bypass, `RFC-0022` PayWord channel theft, FlyClient MMR work forgery, or `NSPQ2` `SLH-DSA` authentication bypass | **Up to 25% of Bounty Treasury** (target **250–1,000 LOVE**) |
| **Medium** | P2P resource exhaustion / slowloris bypass, mempool griefing, `wallet.wasm` key/proof bug, or independent JS verifier divergence (`verifier-ts`) | **50–250 LOVE** |
| **Low / Hardening** | Non-consensus bugs, edge-case RPC issues, or verifiable cryptographic hardening improvements | **10–50 LOVE** |

---

## 4. How to Verify & Report Responsibly

1. **Test Locally First:** Never exploit live mainnet users. Reproduce any finding against `--net regtest` or a local `mainnet-v2` node.
2. **Independent Tools Ready Today:**
   - Live browser 192-bit classical / 104-bit QROM STARK verifier: https://newsatoshi.org/
   - Zero-Rust-code live JS/OpenSSL verifier: `node verifier-ts/newsatoshi_verifier.mjs --live https://newsatoshi.org/mainnet`
   - Lean 4 mechanized proofs (`0 sorry`): `node/proof/SpendCircuitFull.lean` & `node/proof/SpendBalance.lean`
3. **Submit a Responsible Disclosure:** Open a private GitHub Security Advisory at https://github.com/theguysaccount/newsatoshi-rfc0021/security/advisories or email `contributors@newsatoshi.org` with a minimal proof-of-concept test and your `ns1...` or `nsd1...` Mainnet v2 payout address.
