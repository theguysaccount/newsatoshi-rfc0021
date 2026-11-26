//! RFC-0022: Seller-Authorized Unilateral Partial-Claim PayWord Payment Channels & 64× Batched Opens.
//!
//! Solves three consensus-level requirements for autonomous machine payments on Newsatoshi L1:
//! 1. **Exact unilateral partial settlement (`1,000 → 237 / 763`) resistant to adversarial buyers:**
//!    A buyer locks `max_ticks * unit_price + claim_fee` under a Rivest–Shamir (1996) SHA-256
//!    PayWord chain commitment (`tip = SHA256^{max_ticks}(seed)`) together with the seller's
//!    NIST FIPS 205 `SLH-DSA-SHA2-128s` verifying key (`seller_vk`, 32 bytes, deterministically
//!    derived from the seller's wallet spending key). Off-chain, the buyer reveals sequential
//!    vouchers `token_k = SHA256^{max_ticks - k}(seed)` verified in O(1) (1 hash).
//!    Even if the buyer turns adversarial (holding every earlier `token_1..token_{k-1}`) or
//!    vanishes completely along with all gateway servers:
//!    - An adversarial buyer **cannot** front-run or close the channel early at `ticks = 1`
//!      because `Action::ChannelClaim` requires a valid `SLH-DSA-SHA2-128s` signature by
//!      `seller_vk` over `SHA256("nsCHANCLAIM" || channel_id || ticks_le || token)`!
//!    - An adversarial seller **cannot** over-claim `ticks > k` because producing `token_{k+1}`
//!      requires inverting SHA-256!
//!    - Consensus verifies the seller's SLH-DSA signature **before** running the `ticks` SHA-256
//!      iterations (eliminating unauthenticated hashing DoS), verifies `SHA256^{ticks}(token_k) == tip`,
//!      and atomically creates:
//!      - `seller_payout = ticks * unit_price` to `seller_addr`,
//!      - `buyer_refund  = (max_ticks - ticks) * unit_price` to `refund_addr` (when > 0),
//!      - `claim_fee` paid directly to the block miner (preventing zero-fee censorship).
//!    The channel is immediately deleted from state, guaranteeing total payout can never
//!    exceed the locked deposit. If unclaimed after `timeout`, unsigned `Action::ChannelExpire`
//!    (34 bytes) returns `max_ticks * unit_price` to `refund_addr` and pays `claim_fee` to the miner.
//! 2. **Batched multi-channel funding (`Deposit::ChannelBatch`):** A single shielded `Spend`
//!    proof can open up to `MAX_BATCH_CHANNELS` (64) distinct buyer–seller channels atomically,
//!    lifting channel-opening capacity 64× per block without changing the spend STARK circuit.

use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, Word8};
use crate::job::{payout_rho, Payout};
use crate::lock::MAX_LOCK_BLOCKS;
use crate::note::MAX_NOTE_VALUE;

/// Maximum cumulative PayWord ticks per channel (matches JS/Python SDKs).
pub const MAX_CHANNEL_TICKS: u32 = 1_000_000;
/// Maximum distinct buyer–seller channels opened inside a single shielded `Spend` proof.
pub const MAX_BATCH_CHANNELS: usize = 64;
/// Anti-DoS cap on total SHA-256 hash iterations across all `ChannelClaim` txs in one block.
/// 2,000,000 single-block SHA-256 iterations takes < 80 ms on a single modern CPU core.
pub const MAX_BLOCK_CHANNEL_HASHES: u64 = 2_000_000;

const TAG_SELLER: u8 = 21;
const TAG_REFUND: u8 = 22;
const TAG_EXPIRE: u8 = 23;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelPost {
    /// PayWord chain tip: `SHA256^{max_ticks}(seed)`.
    pub tip: [u8; 32],
    /// Maximum billable vouchers in this channel (`1..=MAX_CHANNEL_TICKS`).
    pub max_ticks: u32,
    /// Base units paid to `seller_addr` per revealed voucher tick (`>= 1`).
    pub unit_price: u64,
    /// Pre-funded miner fee paid to the block producer on `ChannelClaim` or `ChannelExpire`.
    pub claim_fee: u64,
    /// Last block height at which the seller may unilaterally claim; after it, `ChannelExpire`
    /// refunds the full channel budget to `refund_addr`.
    pub timeout: u32,
    pub seller_addr: Word8,
    /// Seller's NIST FIPS 205 `SLH-DSA-SHA2-128s` verifying key (32 bytes). Required to sign
    /// `Action::ChannelClaim`, preventing an adversarial buyer from closing early with a lower voucher.
    pub seller_vk: [u8; 32],
    pub refund_addr: Word8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    pub id: [u8; 32],
    pub post: ChannelPost,
    /// Block height at which the channel was funded.
    pub at: u32,
}

/// How a closed PayWord channel settled (derived data for wallets; excluded from state digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelEnd {
    pub channel: Channel,
    pub height: u32,
    /// `Some((ticks, token))` if claimed by the seller; `None` if expired & refunded to buyer.
    pub claimed: Option<(u32, [u8; 32])>,
    pub seller_paid: u64,
    pub buyer_refunded: u64,
    pub miner_fee: u64,
}

/// Consensus-enforced atomic split produced by `claim()` or `expire()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSettlement {
    pub payouts: Vec<Payout>,
    pub seller_paid: u64,
    pub buyer_refunded: u64,
    pub miner_fee: u64,
}

impl ChannelPost {
    /// Total spendable voucher budget (`max_ticks * unit_price`), checked against overflow.
    pub fn budget(&self) -> Res<u64> {
        (self.max_ticks as u64)
            .checked_mul(self.unit_price)
            .ok_or_else(|| "channel budget overflow".into())
    }

    /// Total base units locked on-chain (`max_ticks * unit_price + claim_fee`).
    pub fn total_deposit(&self) -> Res<u64> {
        let total = self
            .budget()?
            .checked_add(self.claim_fee)
            .ok_or_else(|| "channel deposit overflow".to_string())?;
        if total == 0 || total > MAX_NOTE_VALUE {
            return Err("channel deposit out of range".into());
        }
        Ok(total)
    }

    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.tip)
            .u32(self.max_ticks)
            .u64(self.unit_price)
            .u64(self.claim_fee)
            .u32(self.timeout)
            .word8(&self.seller_addr)
            .raw(&self.seller_vk)
            .word8(&self.refund_addr);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(ChannelPost {
            tip: r.arr()?,
            max_ticks: r.u32()?,
            unit_price: r.u64()?,
            claim_fee: r.u64()?,
            timeout: r.u32()?,
            seller_addr: r.word8()?,
            seller_vk: r.arr()?,
            refund_addr: r.word8()?,
        })
    }
}

impl Channel {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.at);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(Channel {
            id: r.arr()?,
            post: ChannelPost::decode(r)?,
            at: r.u32()?,
        })
    }

    /// Domain-separated value hash stored as the leaf payload in `State::channels_merkle`.
    pub fn value_hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsCHV");
        self.encode(&mut w);
        sha256(&w.0)
    }
}

/// Deterministic channel identity binding terms, funding spend's first nullifier, and batch slot.
pub fn channel_id(post: &ChannelPost, first_nf: &Word8, batch_index: u32) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsCHAN");
    post.encode(&mut w);
    w.word8(first_nf);
    w.u32(batch_index);
    sha256(&w.0)
}

/// Validate a single channel funding post at block `height`.
pub fn check_post(p: &ChannelPost, height: u32) -> Res<u64> {
    if p.max_ticks == 0 || p.max_ticks > MAX_CHANNEL_TICKS {
        return Err("channel max_ticks out of range".into());
    }
    if p.unit_price == 0 {
        return Err("channel unit_price must be positive".into());
    }
    if p.timeout <= height {
        return Err("channel timeout must be in the future".into());
    }
    if p.timeout - height > MAX_LOCK_BLOCKS {
        return Err("channel timeout too far ahead".into());
    }
    p.total_deposit()
}

/// Validate a batched multi-channel open (`1..=MAX_BATCH_CHANNELS`) and return its exact sum.
pub fn check_batch(posts: &[ChannelPost], height: u32) -> Res<u64> {
    if posts.is_empty() || posts.len() > MAX_BATCH_CHANNELS {
        return Err("channel batch size out of range".into());
    }
    let mut total: u64 = 0;
    for p in posts {
        let dep = check_post(p, height)?;
        total = total.checked_add(dep).ok_or("channel batch deposit overflow")?;
        if total > MAX_NOTE_VALUE {
            return Err("channel batch total exceeds max note value".into());
        }
    }
    Ok(total)
}

/// Domain-separated message the seller signs with `SLH-DSA-SHA2-128s` to authorize
/// unilateral settlement of `(channel_id, ticks, token)`.
pub fn claim_message(channel_id: &[u8; 32], ticks: u32, token: &[u8; 32]) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsCHANCLAIM").raw(channel_id).u32(ticks).raw(token);
    sha256(&w.0)
}

/// Seller-authorized unilateral claim of `ticks` earned vouchers against an open channel at `height`.
///
/// Requires a valid `SLH-DSA-SHA2-128s` signature by `ch.post.seller_vk` over
/// `claim_message(&ch.id, ticks, token)` so an adversarial buyer cannot close the channel early
/// with a lower voucher (`ticks = 1`) to steal unpaid calls.
///
/// Atomically splits the locked deposit into:
/// - `seller_paid = ticks * unit_price` → `seller_addr`
/// - `buyer_refunded = (max_ticks - ticks) * unit_price` → `refund_addr` (omitted if 0)
/// - `miner_fee = claim_fee` → block coinbase miner
pub fn claim(
    ch: &Channel,
    ticks: u32,
    token: &[u8; 32],
    sig: &[u8],
    height: u32,
) -> Res<ChannelSettlement> {
    if height > ch.post.timeout {
        return Err("channel has expired".into());
    }
    if ticks == 0 || ticks > ch.post.max_ticks {
        return Err("channel ticks out of range".into());
    }
    let msg = claim_message(&ch.id, ticks, token);
    if !crate::job::verify_sig(&ch.post.seller_vk, &msg, sig) {
        return Err("invalid seller SLH-DSA signature on channel claim".into());
    }
    let mut cur = *token;
    for _ in 0..ticks {
        cur = sha256(&cur);
    }
    if cur != ch.post.tip {
        return Err("invalid payword token: SHA256^ticks(token) != tip".into());
    }
    let seller_paid = (ticks as u64)
        .checked_mul(ch.post.unit_price)
        .ok_or("seller payout overflow")?;
    let remaining_ticks = ch.post.max_ticks - ticks;
    let buyer_refunded = (remaining_ticks as u64)
        .checked_mul(ch.post.unit_price)
        .ok_or("buyer refund overflow")?;

    let mut payouts = Vec::with_capacity(2);
    payouts.push(Payout {
        a_pk: ch.post.seller_addr,
        v: seller_paid,
        rho: payout_rho(&ch.id, TAG_SELLER),
    });
    if buyer_refunded > 0 {
        payouts.push(Payout {
            a_pk: ch.post.refund_addr,
            v: buyer_refunded,
            rho: payout_rho(&ch.id, TAG_REFUND),
        });
    }
    Ok(ChannelSettlement {
        payouts,
        seller_paid,
        buyer_refunded,
        miner_fee: ch.post.claim_fee,
    })
}

/// Refund an unclaimed channel after `timeout` (`height > ch.post.timeout`).
pub fn expire(ch: &Channel, height: u32) -> Res<ChannelSettlement> {
    if height <= ch.post.timeout {
        return Err("channel has not expired".into());
    }
    let buyer_refunded = ch.post.budget()?;
    Ok(ChannelSettlement {
        payouts: vec![Payout {
            a_pk: ch.post.refund_addr,
            v: buyer_refunded,
            rho: payout_rho(&ch.id, TAG_EXPIRE),
        }],
        seller_paid: 0,
        buyer_refunded,
        miner_fee: ch.post.claim_fee,
    })
}

/// Helper: builds a PayWord SHA-256 hash chain (`chain[0] = seed`, `chain[n] = tip`).
pub fn build_payword_chain(seed: [u8; 32], max_ticks: u32) -> Vec<[u8; 32]> {
    let mut chain = Vec::with_capacity(max_ticks as usize + 1);
    let mut cur = seed;
    chain.push(cur);
    for _ in 0..max_ticks {
        cur = sha256(&cur);
        chain.push(cur);
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;

    #[test]
    fn unilateral_partial_claim_splits_exact_237_and_763_with_fee_and_blocks_adversarial_buyer() {
        let seller_key = JobKey::derive(b"unit-test-seller-key");
        let buyer_key = JobKey::derive(b"unit-test-adversarial-buyer-key");
        let seller_vk: [u8; 32] = seller_key.vk().try_into().unwrap();
        let chain = build_payword_chain(sha256(b"buyer-seed-237"), 1_000);
        let tip = *chain.last().unwrap();
        let post = ChannelPost {
            tip,
            max_ticks: 1_000,
            unit_price: 1,
            claim_fee: 10,
            timeout: 100,
            seller_addr: [1; 8],
            seller_vk,
            refund_addr: [2; 8],
        };
        assert_eq!(check_post(&post, 50).unwrap(), 1_010);
        let ch = Channel { id: channel_id(&post, &[7; 8], 0), post, at: 50 };

        let token_1 = chain[1_000 - 1];
        let token_237 = chain[1_000 - 237];
        let sig_237 = seller_key.sign(&claim_message(&ch.id, 237, &token_237));

        // Adversarial buyer holding token_1 CANNOT close early (unsigned or signed with wrong key)
        assert!(claim(&ch, 1, &token_1, &[], 60).is_err());
        let buyer_forged_sig = buyer_key.sign(&claim_message(&ch.id, 1, &token_1));
        assert!(claim(&ch, 1, &token_1, &buyer_forged_sig, 60).is_err());
        // Adversarial buyer watching mempool CANNOT replay seller's sig_237 on (ticks=1, token_1)!
        assert!(claim(&ch, 1, &token_1, &sig_237, 60).is_err());

        // Legitimate seller claim splits exact 237 / 763 + 10 fee
        let s = claim(&ch, 237, &token_237, &sig_237, 60).unwrap();
        assert_eq!(s.seller_paid, 237);
        assert_eq!(s.buyer_refunded, 763);
        assert_eq!(s.miner_fee, 10);
        assert_eq!(s.payouts.len(), 2);
        assert_eq!((s.payouts[0].a_pk, s.payouts[0].v), ([1; 8], 237));
        assert_eq!((s.payouts[1].a_pk, s.payouts[1].v), ([2; 8], 763));
        assert_ne!(s.payouts[0].rho, s.payouts[1].rho);

        // Overclaiming tick 238 even with seller's valid signature MUST fail
        let sig_238 = seller_key.sign(&claim_message(&ch.id, 238, &token_237));
        assert!(claim(&ch, 238, &token_237, &sig_238, 60).is_err());
        // Claiming after timeout MUST fail
        assert!(claim(&ch, 237, &token_237, &sig_237, 101).is_err());
        // Full 1,000-tick claim creates only seller payout (no zero-value refund note)
        let sig_1000 = seller_key.sign(&claim_message(&ch.id, 1_000, &chain[0]));
        let full = claim(&ch, 1_000, &chain[0], &sig_1000, 60).unwrap();
        assert_eq!(full.seller_paid, 1_000);
        assert_eq!(full.buyer_refunded, 0);
        assert_eq!(full.payouts.len(), 1);
        // Expire before timeout fails; after timeout unsigned expire refunds 1,000 + fee 10
        assert!(expire(&ch, 100).is_err());
        let exp = expire(&ch, 101).unwrap();
        assert_eq!(exp.buyer_refunded, 1_000);
        assert_eq!(exp.miner_fee, 10);
    }
}
