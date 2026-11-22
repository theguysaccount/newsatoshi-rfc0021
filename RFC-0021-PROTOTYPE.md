# Newsatoshi L1 v0.1.0 + RFC-0021 (`OP_VERIFY_COVENANT_STARK`, `0xb4`) Soft-Fork Prototype

> **Base Upstream Archive:** `https://newsatoshi.org/newsatoshi-0.1.0-src.zip` (`SHA-256: 3d022302f4120a446dc2cc505dcf51036d832e1d68d3855c0afc38aacb396134`)
>
> **Status:** Experimental **Testnet / Regtest Soft-Fork Prototype** implementing `RFC-0021` (`OP_VERIFY_COVENANT_STARK`, opcode `0xb4`) natively inside Newsatoshi's condition script VM (`node/src/script.rs`). Requires a 90-day testnet soak + external cryptography audit prior to any Mainnet signaling.

---

## What Changed vs Upstream `newsatoshi` v0.1.0

1. **`node/src/covenant_stark.rs`** (Zero new dependencies — uses Newsatoshi's existing vendored Winterfell 0.13.1 & pure-SHA-256 `crate::hash::Sha2_256` hasher):
   - 15-column × 64-row `CovenantTransitionAir` over `f128::BaseElement` with `Sha2_256` Merkle commitments & Fiat–Shamir (99+ bits conjectured security).
   - Canonical 175-byte `CovenantPublicInputs` wire format enforcing:
     - Recursive covenant continuity (`covenant_rule_hash == change_covenant_rule_hash == expected_rule_hash`)
     - Exact value conservation (`input_amount == payout_amount + change_amount`)
     - 63-bit bit-decomposition range proofs on payout, change, bounty cap slack (`max_bounty_payout - payout_amount >= 0`), ecological floor slack (`soil_health_score - min_soil_health_score >= 0`), and PayWord streaming `reinvest_bps` floor-division bounds.
2. **`node/src/script.rs` & `node/src/job.rs`:**
   - Added `op::VERIFY_COVENANT_STARK = 0xb4` (the exact next slot after `op::PAYOUT = 0xb3`) and assembler keyword `VERIFY_COVENANT_STARK`.
   - Stack semantics: pops `<expected_rule_hash_32>`, `<public_inputs_175B>`, `<stark_proof_bytes>`, verifies the pure-SHA-256 Winterfell STARK & recursive rule continuity, pushes boolean `1`/`0`.
   - Enforces strict anti-DoS caps: `MAX_STARK_CHECKS = 2` per script, `MAX_ITEM = 32_768` bytes, `MAX_WITNESS_BYTES = 65_536` bytes total.
3. **`node/tests/covenant_stark_softfork.rs`:**
   - End-to-end mined L1 blockchain consensus tests verifying legitimate `PAYOUT 0 NUMEQUALVERIFY 0x<rule_hash> VERIFY_COVENANT_STARK` settlement AND verifying L1 block rejection of tampered proof bytes, covenant-stripping/rule-substitution, tampered payouts, degraded soil scores, wrong payout indices, condition replays, and STARK DoS floods.

## Quick Verification

```bash
cd node
cargo test --test covenant_stark_softfork --test conds --test auxpow --test locks --test mainnet_params
cargo run --bin newsatoshi -- program \
  "PAYOUT 0 NUMEQUALVERIFY 0x272a6205610a85485ed6114f9017cdc006329621fb245e6c32742738290ff237 VERIFY_COVENANT_STARK"
```

## Companion Stack
- **Phase 1 CSV Engine, Live Dual-Chain Mirror & Legal Airlock:** https://github.com/theguysaccount/newsatoshi-commons (`https://commons.newsatoshi.org`)
