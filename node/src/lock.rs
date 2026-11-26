//! Hash- and time-locked payments: the lock every Lightning payment uses, on this chain.
//!
//! A spend deposits `amount` into a lock that names a SHA-256 payment hash, a timeout height
//! and two addresses. Up to and including the timeout height, whoever publishes the 32-byte
//! preimage of the hash releases the coins to the claim address; after it, anyone may
//! release them to the refund address. Both payouts are fixed when the lock is made, so
//! publishing the preimage early, or racing someone else's release, moves nothing anywhere
//! else. Nothing is signed: the preimage is the claim and the height is the refund.
//!
//! The hash is Lightning's payment hash, SHA-256 of a 32-byte preimage, so a Lightning
//! payment and a payment here can be made to stand or fall together: the preimage that
//! settles one releases the other. That is a swap with no custodian and no bridge, and it
//! works with any Lightning wallet, because to Lightning it is an ordinary payment.
//!
//! What a lock shows: its amount, hash, timeout and the two addresses. The coins that fund
//! it are spent privately, and the payouts are notes like any other, spent privately later.

use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, Word8};
use crate::job::{payout_rho, Payout};
use crate::note::MAX_NOTE_VALUE;

/// Longest a lock may run, in blocks: two weeks of one-minute test blocks.
pub const MAX_LOCK_BLOCKS: u32 = 20_160;

const TAG_CLAIM: u8 = 3;
const TAG_REFUND: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockPost {
    /// SHA-256 of the 32-byte preimage that releases the lock to `claim_addr`.
    pub hash: [u8; 32],
    /// Last height at which the preimage releases the lock; after it, the refund does.
    pub timeout: u32,
    pub claim_addr: Word8,
    pub refund_addr: Word8,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock {
    pub id: [u8; 32],
    pub post: LockPost,
    /// Height of the block that made the lock.
    pub at: u32,
}

/// How a lock ended, kept for wallets and swap servers (not part of the state digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockEnd {
    pub lock: Lock,
    pub height: u32,
    /// The preimage, if the lock was claimed; `None` if it was refunded.
    pub preimage: Option<[u8; 32]>,
}

impl LockPost {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.hash)
            .u32(self.timeout)
            .word8(&self.claim_addr)
            .word8(&self.refund_addr)
            .u64(self.amount);
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(LockPost {
            hash: r.arr()?,
            timeout: r.u32()?,
            claim_addr: r.word8()?,
            refund_addr: r.word8()?,
            amount: r.u64()?,
        })
    }
}

impl Lock {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.at);
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(Lock { id: r.arr()?, post: LockPost::decode(r)?, at: r.u32()? })
    }
}

/// A lock's identity: its terms and the first nullifier of the spend that funds it, which
/// no other spend can share.
pub fn lock_id(post: &LockPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsLOCK");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

/// Validate a new lock at `height`.
pub fn check_post(p: &LockPost, height: u32) -> Res<()> {
    if p.amount == 0 || p.amount > MAX_NOTE_VALUE {
        return Err("lock amount out of range".into());
    }
    if p.timeout <= height {
        return Err("lock timeout must be in the future".into());
    }
    if p.timeout - height > MAX_LOCK_BLOCKS {
        return Err("lock timeout too far ahead".into());
    }
    Ok(())
}

/// The note a claim creates. Anyone can compute it from public data; only the holder of
/// the key behind `claim_addr` can spend it.
pub fn claim_payout(l: &Lock) -> Payout {
    Payout {
        a_pk: l.post.claim_addr,
        v: l.post.amount,
        rho: payout_rho(&l.id, TAG_CLAIM),
    }
}

pub fn refund_payout(l: &Lock) -> Payout {
    Payout {
        a_pk: l.post.refund_addr,
        v: l.post.amount,
        rho: payout_rho(&l.id, TAG_REFUND),
    }
}

/// Release to the claim address with the preimage, at a height no later than the timeout.
pub fn unlock(l: &Lock, preimage: &[u8; 32], height: u32) -> Res<Payout> {
    if height > l.post.timeout {
        return Err("lock has expired".into());
    }
    if sha256(preimage) != l.post.hash {
        return Err("wrong preimage".into());
    }
    Ok(claim_payout(l))
}

/// Release to the refund address, at any height after the timeout.
pub fn expire(l: &Lock, height: u32) -> Res<Payout> {
    if height <= l.post.timeout {
        return Err("lock has not expired".into());
    }
    Ok(refund_payout(l))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post() -> LockPost {
        LockPost {
            hash: sha256(&[9u8; 32]),
            timeout: 100,
            claim_addr: [1; 8],
            refund_addr: [2; 8],
            amount: 5,
        }
    }

    #[test]
    fn the_preimage_claims_until_the_timeout_and_the_refund_after() {
        let l = Lock {
            id: lock_id(&post(), &[7; 8]),
            post: post(),
            at: 10,
        };
        assert_eq!(unlock(&l, &[9u8; 32], 100).unwrap().a_pk, [1; 8]);
        assert!(unlock(&l, &[9u8; 32], 101).is_err());
        assert!(unlock(&l, &[8u8; 32], 50).is_err());
        assert!(expire(&l, 100).is_err());
        assert_eq!(expire(&l, 101).unwrap().a_pk, [2; 8]);
        assert_ne!(claim_payout(&l).rho, refund_payout(&l).rho);
    }

    #[test]
    fn terms_are_checked() {
        assert!(check_post(&post(), 99).is_ok());
        assert!(check_post(&post(), 100).is_err());
        assert!(check_post(
            &LockPost {
                amount: 0,
                ..post()
            },
            10
        )
        .is_err());
        assert!(check_post(
            &LockPost {
                timeout: 10 + MAX_LOCK_BLOCKS + 1,
                ..post()
            },
            10
        )
        .is_err());
        assert!(check_post(
            &LockPost {
                timeout: 10 + MAX_LOCK_BLOCKS,
                ..post()
            },
            10
        )
        .is_ok());
    }

    #[test]
    fn ids_bind_terms_and_funding() {
        let a = lock_id(&post(), &[7; 8]);
        assert_ne!(a, lock_id(&post(), &[8; 8]));
        assert_ne!(
            a,
            lock_id(
                &LockPost {
                    timeout: 101,
                    ..post()
                },
                &[7; 8]
            )
        );
    }
}
