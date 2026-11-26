# RFC-0022: Unilateral Partial-Claim PayWord Channels & 64× Batched Funding

> **Status:** Executable Testnet / Regtest L1 Consensus Prototype (`node/src/channel.rs`, `node/tests/payword_channel.rs`) built alongside `RFC-0021` (`OP_VERIFY_COVENANT_STARK`, `0xb4`) on top of `newsatoshi` v0.1.0.
>
> **Upgrade Path:** Activatable on existing Mainnet via a height-gated consensus upgrade (`v0.2.0`, zero genesis reset required; state digest tag `b"P"` is omitted whenever `state.channels.is_empty()`, preserving 100% of historical block hashes) — or included from genesis in a clean audited Mainnet v2.

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
  - `seller_addr: Word8`, `refund_addr: Word8`
- **`Deposit::ChannelBatch(Vec<ChannelPost>)` (tag `6`)**: Opens **`1..=64` distinct buyer–seller channels atomically inside ONE single shielded `Spend` proof** (~120 bytes per channel ≈ +7.7 KB for 64 channels = **64× channel-opening throughput lift**, ~1,088 channel opens per 8 MB Mainnet block ≈ ~156,672/day even before recursive proof compression).

### New `Action` Variants
- **`Action::ChannelClaim { channel, ticks, token }` (tag `11`, 70 bytes encoded)**:
  - Anyone (typically the seller) submits the highest received voucher `(ticks, token)` to **any independent L1 node** at `height <= ch.post.timeout`.
  - Consensus checks `1 <= ticks <= ch.post.max_ticks`, enforces the per-block anti-DoS hash budget (`MAX_BLOCK_CHANNEL_HASHES = 2_000_000` SHA-256 iterations across all claims in a block, `< 80 ms` total CPU), and verifies `SHA256^{ticks}(token) == ch.post.tip`.
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

## 4. Verification Command

```bash
cd node
cargo test --release --lib channel --test payword_channel --test locks --test conds --test light --test covenant_stark_softfork -- --nocapture
```
