//! Coins locked to a condition: a program (`crate::script`) that releases them when it is
//! run with a witness that satisfies it. Two of three keys for an escrow, a hash and a
//! timeout, a key that may spend only after a date, or any mix: whatever the language can
//! express.
//!
//! A spend deposits `amount` under a condition that names up to four payout addresses, a
//! timeout height and a refund address, and commits to its program by a hash with a salt,
//! so the program stays private until it is used. Up to the timeout, anyone who reveals
//! the salt, the program and a witness that satisfies it releases the coins to the payout
//! the program accepts; signatures sign the condition and that payout, so nobody can turn a
//! signed release into another. After the timeout, anyone may return the coins to the
//! refund address.
//!
//! What a condition shows: its amount, its addresses and timeout, and, when it is used, its
//! program and witness, as a script does on Bitcoin. Inside shielded notes, with the chain
//! learning only that some condition was met (white paper §7), it needs the chain proof's
//! recursion; until then conditions live beside the shielded pool, as locks do.

use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, Word8};
use crate::job::{payout_rho, Payout};
use crate::lock::MAX_LOCK_BLOCKS;
use crate::note::MAX_NOTE_VALUE;
use crate::script;

pub const MAX_PAYOUTS: usize = 4;
const TAG_REFUND: u8 = 15;
const TAG_PAYOUT: u8 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondPost {
    /// SHA-256 of a salt and the program (`commitment`).
    pub commitment: [u8; 32],
    /// Where the program may send the coins: it runs knowing which one is being chosen.
    pub payouts: Vec<Word8>,
    /// Last height at which the program can release the coins; after it, the refund can.
    pub timeout: u32,
    pub refund_addr: Word8,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cond {
    pub id: [u8; 32],
    pub post: CondPost,
    /// Height of the block that made it.
    pub at: u32,
}

/// How a condition ended, kept for wallets (not part of the state digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondEnd {
    pub cond: Cond,
    pub height: u32,
    /// The payout chosen and the program that chose it; `None` if refunded.
    pub fulfilled: Option<(u8, Vec<u8>)>,
}

impl CondPost {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.commitment).u8(self.payouts.len() as u8);
        for p in &self.payouts {
            w.word8(p);
        }
        w.u32(self.timeout).word8(&self.refund_addr).u64(self.amount);
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        let commitment = r.arr()?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_PAYOUTS {
            return Err("a condition has one to four payouts".into());
        }
        let payouts = (0..n).map(|_| r.word8()).collect::<Res<Vec<_>>>()?;
        Ok(CondPost { commitment, payouts, timeout: r.u32()?, refund_addr: r.word8()?, amount: r.u64()? })
    }
}

impl Cond {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.at);
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(Cond { id: r.arr()?, post: CondPost::decode(r)?, at: r.u32()? })
    }
}

/// The commitment to a program: SHA-256 of a domain tag, a 32-byte salt and the program.
pub fn commitment(salt: &[u8; 32], program: &[u8]) -> [u8; 32] {
    sha256(&[b"nsPROG".as_slice(), salt, program].concat())
}

/// A condition's identity: its terms and the first nullifier of the spend that funds it.
pub fn cond_id(post: &CondPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsCOND");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

/// What signatures in a program sign: the condition and the payout being chosen.
pub fn sign_message(id: &[u8; 32], payout: u8) -> [u8; 32] {
    sha256(&[b"nsCONDSIG".as_slice(), id, &[payout]].concat())
}

pub fn check_post(p: &CondPost, height: u32) -> Res<()> {
    if p.amount == 0 || p.amount > MAX_NOTE_VALUE {
        return Err("condition amount out of range".into());
    }
    if p.payouts.is_empty() || p.payouts.len() > MAX_PAYOUTS {
        return Err("a condition has one to four payouts".into());
    }
    if p.timeout <= height {
        return Err("condition timeout must be in the future".into());
    }
    if p.timeout - height > MAX_LOCK_BLOCKS {
        return Err("condition timeout too far ahead".into());
    }
    Ok(())
}

pub fn payout(c: &Cond, index: u8) -> Payout {
    Payout { a_pk: c.post.payouts[index as usize], v: c.post.amount, rho: payout_rho(&c.id, TAG_PAYOUT + index) }
}

pub fn refund_payout(c: &Cond) -> Payout {
    Payout { a_pk: c.post.refund_addr, v: c.post.amount, rho: payout_rho(&c.id, TAG_REFUND) }
}

/// Release the coins to payout `index` by running the committed program with `witness`, in
/// a block at `height` no later than the timeout (`rfc0021_active = true`).
pub fn fulfil(c: &Cond, index: u8, salt: &[u8; 32], program: &[u8], witness: &[Vec<u8>], height: u32) -> Res<Payout> {
    fulfil_at(c, index, salt, program, witness, height, true)
}

/// Height-gated release enforcing `rfc0021_active` for `OP_VERIFY_COVENANT_STARK` (0xb4).
pub fn fulfil_at(
    c: &Cond,
    index: u8,
    salt: &[u8; 32],
    program: &[u8],
    witness: &[Vec<u8>],
    height: u32,
    rfc0021_active: bool,
) -> Res<Payout> {
    if height > c.post.timeout {
        return Err("condition has expired".into());
    }
    if index as usize >= c.post.payouts.len() {
        return Err("no such payout".into());
    }
    if commitment(salt, program) != c.post.commitment {
        return Err("that is not the committed program".into());
    }
    let msg = sign_message(&c.id, index);
    script::run_with_rfc0021(
        program,
        witness,
        &script::Ctx { height, payout: index, msg: &msg },
        rfc0021_active,
    )
    .map_err(|e| format!("condition not met: {e}"))?;
    Ok(payout(c, index))
}

/// Return the coins to the refund address, at any height after the timeout.
pub fn expire(c: &Cond, height: u32) -> Res<Payout> {
    if height <= c.post.timeout {
        return Err("condition has not expired".into());
    }
    Ok(refund_payout(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;

    #[test]
    fn a_two_of_three_escrow_pays_where_two_keys_agree() {
        let keys: Vec<JobKey> = (0..3).map(|_| JobKey::generate()).collect();
        let program = script::assemble(&format!(
            "2 0x{} 0x{} 0x{} 3 CHECKMULTISIG",
            hex::encode(keys[0].vk()),
            hex::encode(keys[1].vk()),
            hex::encode(keys[2].vk())
        ))
        .unwrap();
        let salt = [3u8; 32];
        let post = CondPost { commitment: commitment(&salt, &program), payouts: vec![[1; 8], [2; 8]], timeout: 100, refund_addr: [9; 8], amount: 5 };
        assert!(check_post(&post, 50).is_ok());
        let c = Cond { id: cond_id(&post, &[4; 8]), post, at: 50 };
        let sign = |k: usize, payout: u8| keys[k].sign(&sign_message(&c.id, payout));
        // buyer and arbiter agree the seller is paid (payout 1)
        let p = fulfil(&c, 1, &salt, &program, &[sign(0, 1), sign(2, 1)], 60).unwrap();
        assert_eq!((p.a_pk, p.v), ([2; 8], 5));
        // signatures for payout 1 cannot choose payout 0
        assert!(fulfil(&c, 0, &salt, &program, &[sign(0, 1), sign(2, 1)], 60).is_err());
        assert!(fulfil(&c, 1, &[4u8; 32], &program, &[sign(0, 1), sign(2, 1)], 60).is_err(), "wrong salt");
        assert!(fulfil(&c, 1, &salt, &program, &[sign(0, 1), sign(2, 1)], 101).is_err(), "expired");
        assert!(fulfil(&c, 2, &salt, &program, &[], 60).is_err(), "no such payout");
        assert!(expire(&c, 100).is_err());
        assert_eq!(expire(&c, 101).unwrap().a_pk, [9; 8]);
        assert_ne!(payout(&c, 0).rho, payout(&c, 1).rho);
        assert_ne!(payout(&c, 0).rho, refund_payout(&c).rho);
    }

    #[test]
    fn terms_are_checked() {
        let post = CondPost { commitment: [0; 32], payouts: vec![[1; 8]], timeout: 100, refund_addr: [2; 8], amount: 5 };
        assert!(check_post(&post, 99).is_ok());
        assert!(check_post(&post, 100).is_err());
        assert!(check_post(&CondPost { payouts: vec![], ..post.clone() }, 10).is_err());
        assert!(check_post(&CondPost { payouts: vec![[1; 8]; 5], ..post.clone() }, 10).is_err());
        assert!(check_post(&CondPost { amount: 0, ..post.clone() }, 10).is_err());
        let mut w = Writer::new();
        post.encode(&mut w);
        assert_eq!(CondPost::decode(&mut Reader::new(&w.0)).unwrap(), post);
    }
}
