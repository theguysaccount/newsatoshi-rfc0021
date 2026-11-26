# RFC-0022: Unilateral Partial-Claim PayWord Channels & 64× Batched Funding

> **Status:** Executable Testnet / Regtest L1 Consensus Prototype (`node/src/channel.rs`, `node/tests/payword_channel.rs`) built alongside `RFC-0021` (`OP_VERIFY_COVENANT_STARK`, `0xb4`, 128 proven bits) on top of `newsatoshi` v0.1.0.
>
> **Upgrade Path:** Height-gated consensus upgrade (**hard fork**, controlled by `Params::rfc0021_from` and `Params::rfc0022_from`, defaulting to `None` on v0.1.0 Mainnet/Testnet and `Some(0)` on Regtest/Rehearsal; `DigestParts::channels` is omitted whenever `state.channels.is_empty()` so historical hashes are untouched) — or active from genesis in an audited Mainnet v2 relaunch.

---

## 1. Problem Statement

On Newsatoshi L1 v0.1.0:
1. **No consensus-enforced partial split:** Both `Lock` (`node/src/lock.rs`) and `Cond` (`node/src/cond.rs`) release 100% of `amount` to one single payout address. A merchant who accepts 237 off-chain PayWord vouchers out of a 1,000-unit deposit has no unilateral L1 mechanism to collect 237 and return 763 if the buyer and gateway servers go offline.
2. **Channel-opening bottleneck:** `Spend` allows at most one `Deposit` per ~461 KB mainnet STARK spend proof (~17 channel opens per 8 MB 10-minute block ≈ 2,450 relationships/day).
3. **Zero-fee action censorship risk:** `Tx::Act` (`Unlock` / `Expire` / `Fulfil`) previously returned `Ok(0)` miner fee, giving rational miners zero incentive to include time-sensitive settlement claims under fee congestion.

---

## 2. Consensus Primitives (`node/src/channel.rs`, `job.rs`, `state.rs`)

### New `Deposit` Variants
- **`Deposit::Channel(ChannelPost)` (tag `5`)**: Locks `max_ticks * unit_price + claim_fee` (checked overflow, `<= MAX_NOTE_VALUE`) under a Rivest–Shamir (1996) SHA-256 PayWord commitment:
  - `tip: [u8; 32]` (`SHA256^{max_ticks}(seed)`)
  - `max_ticks: u32` (`1..=1_000_000`)
  - `unit_price: u64` (`>= 1`)
  - `claim_fee: u64` (pre-funded miner fee paid to the block producer on claim or expire)
  - `timeout: u32` (`height < timeout <= height + MAX_LOCK_BLOCKS`)
  - `seller_addr: Word8`, `seller_vk: [u8; 32]` (seller's NIST FIPS 205 `SLH-DSA-SHA2-128s` verifying key), `refund_addr: Word8`
- **`Deposit::ChannelBatch(Vec<ChannelPost>)` (tag `6`)**: Opens **`1..=64` distinct buyer–seller channels atomically inside ONE single shielded `Spend` proof** (~152 bytes per channel ≈ +9.7 KB for 64 channels = **64× channel-opening throughput lift**, ~1,088 channel opens per 8 MB Mainnet block ≈ ~156,672/day even before recursive proof compression).

### New `Action` Variants
- **`Action::ChannelClaim { channel, ticks, token, sig }` (tag `11`, `7,930` bytes with FIPS 205 `SLH-DSA-SHA2-128s` signature)**:
  - Requires a valid `SLH-DSA-SHA2-128s` signature by `ch.post.seller_vk` over `SHA256("nsCHANCLAIM" || channel_id || ticks_u32_le || token)` — **blocking adversarial buyers** who hold every earlier voucher (`token_1..token_{k-1}`) from front-running or closing early at `ticks = 1` to steal unpaid calls, and preventing unauthenticated hash-loop DoS (signature is checked before hashing).
  - Seller unilaterally submits `(ticks, token, sig)` to **any independent L1 node** at `height <= ch.post.timeout` with zero buyer cooperation.
  - Consensus checks `1 <= ticks <= ch.post.max_ticks`, enforces the per-block anti-DoS hash budget (`MAX_BLOCK_CHANNEL_HASHES = 2_000_000` SHA-256 iterations across all claims in a block, `< 80 ms` total CPU), and verifies `SHA256^{ticks}(token) == ch.post.tip` (so even a malicious seller with their own valid signature can never over-claim `ticks + 1`).
  - Atomically creates:
    - `seller_paid = ticks * unit_price` → new note for `seller_addr`
    - `buyer_refunded = (max_ticks - ticks) * unit_price` → new note for `refund_addr` (omitted if `0`)
    - `miner_fee = claim_fee` → routed directly into block `fees` (coinbase)
  - Deletes `channel` from `state.channels` so the deposit can **never** pay out more than `max_ticks * unit_price + claim_fee` or be claimed/expired twice.
- **`Action::ChannelExpire { channel }` (tag `12`, 34 bytes encoded)**:
  - At `height > ch.post.timeout`, refunds `max_ticks * unit_price` to `refund_addr`, routes `claim_fee` to the block miner, and deletes `channel`.

---

## 3. Honest Privacy Boundary

Consistent with `node/src/lock.rs` and `node/src/cond.rs`, RFC-0022 channels currently live beside the shielded pool:
- **Public at open/close:** Funding amount, `max_ticks`, `unit_price`, `timeout`, `seller_addr`, `refund_addr`, and final settled `(ticks, seller_paid, buyer_refunded)`.
- **Private before open & after close:** The coins funding the channel come from a shielded STARK spend, and both the seller's settled payout note (`237`) and the buyer's refund note (`763`) enter the shielded note tree and are spent privately via zero-knowledge STARK proofs afterward. Hiding channel terms themselves inside shielded notes waits on the recursive chain proof (`CHAIN-PROOF.md`).

---

## 4. Phase 1 Production Hardening (`v0.2.1-rfc0022`)

1. **O(log N) Canonical `MerkleMap` State Commitments (`node/src/merkmap.rs`):**
   - Replaces linear O(N) per-block hashing of open channels with a persistent, insertion-order-independent SHA-256 binary Merkle trie (`nsMKL` / `nsMKB`).
   - Measured benchmark: 10,000 inserts in `61.18 ms` (`0.0061 ms/op`), 1,000 removes in `6.17 ms` (`0.0062 ms/op`), average inclusion proof depth `14.53` siblings (~465 bytes), O(1) root lookup at block finalization.
2. **Live Public HTTP RPC (`GET /api/channel?id=<64hex>` & `?tip=<64hex>` in `node/src/rpc.rs`):**
   - Exposes open, claimed, and expired channel terms, settlement payouts, confirmations, and canonical SHA-256 `merkle_proof` objects verifiable by light clients and SDKs against `GET /api/state` (`parts.channels`).
3. **Mempool Fee Ordering, Block Hash Anti-DoS Cap & Miner Coinbase Payouts (`node/src/node.rs`):**
   - `Node::admit`, `Node::select_with_fees`, and `Node::block_template` extract real `claim_fee` values for `ChannelClaim` and `ChannelExpire`, prioritize fee-bearing claims by fee rate, enforce `MAX_BLOCK_CHANNEL_HASHES` (`2,000,000`) during template assembly, and credit pre-funded `claim_fee`s directly into the miner coinbase.
4. **Verified Fast-Boot Disk Snapshots (`node/src/snapshot.rs`, `node/src/chain.rs`):**
   - Atomic `state.snap` (`tmp` → `fsync` → `rename`) with trailing SHA-256 checksum, genesis binding, tip-block verification against `blocks.dat`, and recomputed `state.digest()` check — automatically catching up trailing blocks or falling back cleanly to `blocks.dat` replay on any mismatch/corruption.
5. **NIST FIPS 203 & FIPS 205 Determinism / KAT Regression Suite (`node/tests/crypto_kats.rs`):**
   - Locks byte lengths, determinism, and 1-bit tamper rejection for `SLH-DSA-SHA2-128s` and `ML-KEM-768` plus snapshot integrity.

---

## 5. Verification Commands

```bash
cd node
cargo test --release --lib -- --nocapture
cargo test --release --test payword_channel --test crypto_kats --test locks --test conds --test light --test covenant_stark_softfork --test mainnet_params --test chain --test auxpow -- --nocapture
```
