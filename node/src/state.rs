//! Ledger state and the block validity rules.

use crate::channel::{self, Channel, ChannelEnd, MAX_BLOCK_CHANNEL_HASHES};
use crate::codec::Writer;
use crate::hash::{sha256, Word8};
use crate::job::{self, Action, Deposit, Job, Payout, Phase};
use crate::cond::{self, Cond, CondEnd};
use crate::lock::{self, Lock, LockEnd};
use crate::merkmap::MerkleMap;
use crate::nftree::NfTree;
use crate::note::{self, NoteTree, MAX_NOTE_VALUE};
use crate::params::{subsidy, Params, MAX_COINBASE_EXTRA, MAX_MEMO};
use crate::spend;
use crate::tx::{header_commit, Block, Coinbase, PlainOut, Tx};
use std::collections::{BTreeMap, VecDeque};
// The state is kept in persistent collections: a copy shares everything it has in common
// with the state it was copied from. A node keeps the state after each of its last blocks,
// to step back to on a reorganisation, and copies the state to apply each new block; with
// these, each kept state costs what its block changed, not the whole state again.
use imbl::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct State {
    /// Height of the last applied block (genesis = 0).
    pub height: u32,
    pub tree: NoteTree,
    /// Every position at which a commitment sits (for wallets).
    pub cm_pos: HashMap<Word8, Vec<u32>>,
    pub nullifiers: HashSet<Word8>,
    /// The same nullifiers, sorted in a Merkle tree (`crate::nftree`).
    pub nf_tree: NfTree,
    /// Whether this state's digest includes the nullifier tree's root (from
    /// `Params::nf_tree_from`).
    pub nf_committed: bool,
    /// Note-tree roots at the end of every block: the anchors a spend may prove against.
    pub roots: HashSet<Word8>,
    pub nf_acc: [u8; 32],
    pub jobs: BTreeMap<[u8; 32], Job>,
    /// Open hash- and time-locked payments. A lock leaves this map when it is claimed or
    /// refunded.
    pub locks: BTreeMap<[u8; 32], Lock>,
    /// Coinbase outputs wait here until they mature, then join the note tree. Delaying the
    /// insertion enforces maturity without linking the later, private spend to the reward.
    pub pending_coinbase: VecDeque<(u32, Vec<PlainOut>)>,
    pub issued: u128,
    pub burned: u128,
    pub locked: u128,
    /// Openings that are public by construction (coinbase rewards, job payouts), by address.
    /// Derived data for wallets; not part of the state digest.
    pub public_notes: HashMap<Word8, Vec<(u64, crate::note::Rho)>>,
    /// How each closed lock ended, and the locks made for each payment hash. Derived data
    /// for wallets and swap servers; not part of the state digest.
    pub lock_ends: HashMap<[u8; 32], LockEnd>,
    /// Coins under conditions (`crate::cond`), and how the finished ones ended.
    pub conds: BTreeMap<[u8; 32], Cond>,
    pub cond_ends: HashMap<[u8; 32], CondEnd>,
    pub locks_by_hash: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// RFC-0022: Open unilateral partial-claim PayWord payment channels (`crate::channel`).
    pub channels: imbl::OrdMap<[u8; 32], Channel>,
    /// O(log N) incremental canonical SHA-256 Merkle map committing to open channels.
    pub channels_merkle: MerkleMap,
    pub channel_ends: HashMap<[u8; 32], ChannelEnd>,
    pub channels_by_tip: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

#[derive(Clone, Copy)]
pub struct Checks {
    pub verify_proofs: bool,
    pub check_commit: bool,
}

pub const FULL: Checks = Checks { verify_proofs: true, check_commit: true };
/// For building templates and screening the mempool, where proofs were checked on entry.
pub const NO_PROOFS: Checks = Checks { verify_proofs: false, check_commit: false };

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        let tree = NoteTree::new();
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        State {
            height: 0,
            tree,
            cm_pos: HashMap::new(),
            nullifiers: HashSet::new(),
            nf_tree: NfTree::new(),
            nf_committed: false,
            roots,
            nf_acc: [0u8; 32],
            jobs: BTreeMap::new(),
            locks: BTreeMap::new(),
            pending_coinbase: VecDeque::new(),
            issued: 0,
            burned: 0,
            locked: 0,
            public_notes: HashMap::new(),
            lock_ends: HashMap::new(),
            conds: BTreeMap::new(),
            cond_ends: HashMap::new(),
            locks_by_hash: HashMap::new(),
            channels: imbl::OrdMap::new(),
            channels_merkle: MerkleMap::new(),
            channel_ends: HashMap::new(),
            channels_by_tip: HashMap::new(),
        }
    }

    /// Add a note commitment to the tree (and the index wallets look it up by).
    pub fn append(&mut self, cm: Word8) {
        let pos = self.tree.append(cm);
        self.cm_pos.entry(cm).or_default().push(pos);
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest_parts().digest()
    }

    /// What the digest is made of, so a light client can check that a block commits to a
    /// note-tree root without holding the state (`crate::light`).
    pub fn digest_parts(&self) -> DigestParts {
        let mut jw = Writer::new();
        for j in self.jobs.values() {
            j.encode(&mut jw);
        }
        let mut pw = Writer::new();
        for (h, outs) in &self.pending_coinbase {
            pw.u32(*h);
            for o in outs {
                pw.word8(&o.cm());
            }
        }
        // Open locks enter the digest while there are any, so the commitments of blocks
        // made before locks existed are unchanged.
        let locks = (!self.locks.is_empty()).then(|| {
            let mut lw = Writer::new();
            lw.raw(b"nsLOCKS");
            for l in self.locks.values() {
                l.encode(&mut lw);
            }
            sha256(&lw.0)
        });
        // conditions likewise, while any are open
        let conds = (!self.conds.is_empty()).then(|| {
            let mut cw = Writer::new();
            cw.raw(b"nsCONDS");
            for c in self.conds.values() {
                c.encode(&mut cw);
            }
            sha256(&cw.0)
        });
        // RFC-0022 PayWord channels: O(1) incremental Merkle root while any are open
        let channels = (!self.channels.is_empty()).then(|| self.channels_merkle.root());
        DigestParts {
            height: self.height,
            tree_root: self.tree.root(),
            nf_acc: self.nf_acc,
            jobs: sha256(&jw.0),
            pending: sha256(&pw.0),
            issued: self.issued,
            burned: self.burned,
            locked: self.locked,
            locks,
            conds,
            nf_root: self.nf_committed.then(|| crate::hash::words_to_bytes(&self.nf_tree.root())),
            channels,
        }
    }

    /// Pay out of escrow: the value leaves `locked`, and the note joins the tree with its
    /// opening public. Checked before anything changes.
    fn pay_out(&mut self, payouts: &[Payout], burned: u64) -> Result<(), String> {
        self.pay_out_with_fee(payouts, burned, 0)
    }

    /// Pay out of escrow while also routing an explicit pre-funded `miner_fee` into the
    /// block's fee pool (`locked` decreases by `payouts + burned + miner_fee`).
    fn pay_out_with_fee(&mut self, payouts: &[Payout], burned: u64, miner_fee: u64) -> Result<(), String> {
        let out: u128 = payouts.iter().map(|p| p.v as u128).sum::<u128>()
            + burned as u128
            + miner_fee as u128;
        let locked = self.locked.checked_sub(out).ok_or("escrow accounting underflow")?;
        let cms = payouts.iter().map(|p| note::try_commit(&p.a_pk, p.v, &p.rho)).collect::<Result<Vec<_>, _>>()?;
        self.locked = locked;
        self.burned += burned as u128;
        for (p, cm) in payouts.iter().zip(cms) {
            self.append(cm);
            self.public_notes.entry(p.a_pk).or_default().push((p.v, p.rho));
        }
        Ok(())
    }

    /// Issued − burned − locked: what the shielded pool holds *if every rule held*, counting
    /// coinbase outputs still maturing. It is a public counter identity, not an audit of the
    /// pool, which is private: a flaw in the circuit or the verifier could inflate the pool
    /// without moving this number.
    pub fn shielded_supply(&self) -> u128 {
        self.issued - self.burned - self.locked
    }

    /// First step of a block at height `h`: matured coinbase outputs join the note tree.
    pub fn begin_block(&mut self, h: u32, params: &Params) {
        while let Some((ch, _)) = self.pending_coinbase.front() {
            if *ch + params.coinbase_maturity <= h {
                let (_, outs) = self.pending_coinbase.pop_front().unwrap();
                for o in outs {
                    self.append(o.cm());
                    self.public_notes.entry(o.a_pk).or_default().push((o.v, o.rho));
                }
            } else {
                break;
            }
        }
    }

    /// Check one non-coinbase transaction against this state and apply it; returns its fee.
    /// Every check runs before anything changes, so on error the state is exactly as it was
    /// and a block builder or the mempool can try transactions one at a time.
    pub fn apply_tx(&mut self, tx: &Tx, h: u32, params: &Params, checks: Checks) -> Result<u64, String> {
        let size = tx.to_bytes().len();
        if size > params.max_tx_bytes {
            return Err(format!("transaction of {size} bytes exceeds {}", params.max_tx_bytes));
        }
        self.apply_tx_sized(tx, h, params, checks)
    }

    fn apply_tx_sized(&mut self, tx: &Tx, h: u32, params: &Params, checks: Checks) -> Result<u64, String> {
        match tx {
            Tx::Coinbase(_) => Err("a coinbase may only come first".into()),
            Tx::Spend(sp) => {
                // `roots` changes only at the end of a block, so this is the set of anchors
                // as of the previous block
                if !self.roots.contains(&sp.anchor) {
                    return Err("unknown anchor".into());
                }
                if sp.dummy[0] && sp.dummy[1] {
                    return Err("a spend needs at least one real input".into());
                }
                for k in 0..2 {
                    if !sp.dummy[k] && self.nullifiers.contains(&sp.nf[k]) {
                        return Err("double spend".into());
                    }
                }
                if !sp.dummy[0] && !sp.dummy[1] && sp.nf[0] == sp.nf[1] {
                    return Err("double spend".into());
                }
                if sp.memo.len() > MAX_MEMO {
                    return Err("memo too long".into());
                }
                if sp.proof.len() > params.proof.max_proof_bytes {
                    return Err("proof too large".into());
                }
                let pi = sp.public()?;
                // job deposits: validate before paying for proof verification
                let job_after = match &sp.deposit {
                    Some(Deposit::Post(p)) => {
                        job::check_post(p, h)?;
                        let first_nf = if sp.dummy[0] { sp.nf[1] } else { sp.nf[0] };
                        let id = job::job_id(p, &first_nf);
                        if self.jobs.contains_key(&id) {
                            return Err("duplicate job".into());
                        }
                        Some(Job { id, post: p.clone(), posted_at: h, phase: Phase::Open })
                    }
                    Some(Deposit::Claim(c)) => {
                        let mut j = self.jobs.get(&c.job).ok_or("unknown job")?.clone();
                        job::apply_claim(&mut j, c, h)?;
                        Some(j)
                    }
                    Some(Deposit::Lock(_))
                    | Some(Deposit::Cond(_))
                    | Some(Deposit::Channel(_))
                    | Some(Deposit::ChannelBatch(_))
                    | None => None,
                };
                let cond_after = match &sp.deposit {
                    Some(Deposit::Cond(p)) => {
                        cond::check_post(p, h)?;
                        let first_nf = if sp.dummy[0] { sp.nf[1] } else { sp.nf[0] };
                        let id = cond::cond_id(p, &first_nf);
                        if self.conds.contains_key(&id) {
                            return Err("duplicate condition".into());
                        }
                        Some(Cond { id, post: p.clone(), at: h })
                    }
                    _ => None,
                };
                let lock_after = match &sp.deposit {
                    Some(Deposit::Lock(p)) => {
                        lock::check_post(p, h)?;
                        let first_nf = if sp.dummy[0] { sp.nf[1] } else { sp.nf[0] };
                        let id = lock::lock_id(p, &first_nf);
                        // the funding nullifier is new, so the id is too; checked anyway
                        if self.locks.contains_key(&id) {
                            return Err("duplicate lock".into());
                        }
                        Some(Lock { id, post: p.clone(), at: h })
                    }
                    _ => None,
                };
                let channels_after = match &sp.deposit {
                    Some(Deposit::Channel(p)) => {
                        if !params.rfc0022_from.is_some_and(|f| h >= f) {
                            return Err("RFC-0022 PayWord channels are not active at this height".into());
                        }
                        channel::check_post(p, h)?;
                        let first_nf = if sp.dummy[0] { sp.nf[1] } else { sp.nf[0] };
                        let id = channel::channel_id(p, &first_nf, 0);
                        if self.channels.contains_key(&id) {
                            return Err("duplicate channel".into());
                        }
                        vec![Channel { id, post: p.clone(), at: h }]
                    }
                    Some(Deposit::ChannelBatch(list)) => {
                        if !params.rfc0022_from.is_some_and(|f| h >= f) {
                            return Err("RFC-0022 PayWord channels are not active at this height".into());
                        }
                        channel::check_batch(list, h)?;
                        let first_nf = if sp.dummy[0] { sp.nf[1] } else { sp.nf[0] };
                        let mut out = Vec::with_capacity(list.len());
                        for (idx, p) in list.iter().enumerate() {
                            let id = channel::channel_id(p, &first_nf, idx as u32);
                            if self.channels.contains_key(&id) {
                                return Err("duplicate channel".into());
                            }
                            out.push(Channel { id, post: p.clone(), at: h });
                        }
                        out
                    }
                    _ => vec![],
                };
                if checks.verify_proofs {
                    spend::verify_bytes_cached(&params.proof, &pi, &sp.proof).map_err(|e| format!("proof rejected: {e}"))?;
                }
                // every check passed: apply
                for k in 0..2 {
                    if !sp.dummy[k] {
                        self.nullifiers.insert(sp.nf[k]);
                        self.nf_tree.insert(sp.nf[k]);
                        self.nf_acc = sha256(&[self.nf_acc.as_slice(), &crate::hash::words_to_bytes(&sp.nf[k])].concat());
                    }
                }
                self.append(sp.cm_out[0]);
                self.append(sp.cm_out[1]);
                if let Some(j) = job_after {
                    self.jobs.insert(j.id, j);
                }
                if let Some(l) = lock_after {
                    self.locks_by_hash.entry(l.post.hash).or_default().push(l.id);
                    self.locks.insert(l.id, l);
                }
                if let Some(c) = cond_after {
                    self.conds.insert(c.id, c);
                }
                for ch in channels_after {
                    self.channels_by_tip.entry(ch.post.tip).or_default().push(ch.id);
                    self.channels_merkle.insert(ch.id, ch.value_hash());
                    self.channels.insert(ch.id, ch);
                }
                let dep_amt = match &sp.deposit {
                    Some(d) => d.checked_amount()? as u128,
                    None => 0,
                };
                self.locked += dep_amt;
                Ok(sp.fee)
            }
            Tx::Act(Action::Unlock { lock: id, preimage }) => {
                let l = self.locks.get(id).ok_or("unknown lock")?;
                let p = lock::unlock(l, preimage, h)?;
                self.pay_out(&[p], 0)?;
                let l = self.locks.remove(id).expect("checked above");
                self.lock_ends.insert(*id, LockEnd { lock: l, height: h, preimage: Some(*preimage) });
                Ok(0)
            }
            Tx::Act(Action::Expire { lock: id }) if self.conds.contains_key(id) => {
                let p = cond::expire(&self.conds[id], h)?;
                self.pay_out(&[p], 0)?;
                let c = self.conds.remove(id).expect("checked above");
                self.cond_ends.insert(*id, CondEnd { cond: c, height: h, fulfilled: None });
                Ok(0)
            }
            Tx::Act(Action::Fulfil { cond: id, payout, salt, program, witness }) => {
                let c = self.conds.get(id).ok_or("unknown condition")?;
                let rfc0021_active = params.rfc0021_from.is_some_and(|f| h >= f);
                let p = cond::fulfil_at(c, *payout, salt, program, witness, h, rfc0021_active)?;
                self.pay_out(&[p], 0)?;
                let c = self.conds.remove(id).expect("checked above");
                self.cond_ends.insert(*id, CondEnd { cond: c, height: h, fulfilled: Some((*payout, program.clone())) });
                Ok(0)
            }
            Tx::Act(Action::Expire { lock: id }) => {
                let l = self.locks.get(id).ok_or("unknown lock")?;
                let p = lock::expire(l, h)?;
                self.pay_out(&[p], 0)?;
                let l = self.locks.remove(id).expect("checked above");
                self.lock_ends.insert(*id, LockEnd { lock: l, height: h, preimage: None });
                Ok(0)
            }
            Tx::Act(Action::ChannelClaim { channel: id, ticks, token, sig }) => {
                if !params.rfc0022_from.is_some_and(|f| h >= f) {
                    return Err("RFC-0022 PayWord channels are not active at this height".into());
                }
                let ch = self.channels.get(id).ok_or("unknown channel")?;
                let res = channel::claim(ch, *ticks, token, sig, h)?;
                self.pay_out_with_fee(&res.payouts, 0, res.miner_fee)?;
                let ch = self.channels.remove(id).expect("checked above");
                self.channels_merkle.remove(id);
                self.channel_ends.insert(
                    *id,
                    ChannelEnd {
                        channel: ch,
                        height: h,
                        claimed: Some((*ticks, *token)),
                        seller_paid: res.seller_paid,
                        buyer_refunded: res.buyer_refunded,
                        miner_fee: res.miner_fee,
                    },
                );
                Ok(res.miner_fee)
            }
            Tx::Act(Action::ChannelExpire { channel: id }) => {
                if !params.rfc0022_from.is_some_and(|f| h >= f) {
                    return Err("RFC-0022 PayWord channels are not active at this height".into());
                }
                let ch = self.channels.get(id).ok_or("unknown channel")?;
                let res = channel::expire(ch, h)?;
                self.pay_out_with_fee(&res.payouts, 0, res.miner_fee)?;
                let ch = self.channels.remove(id).expect("checked above");
                self.channels_merkle.remove(id);
                self.channel_ends.insert(
                    *id,
                    ChannelEnd {
                        channel: ch,
                        height: h,
                        claimed: None,
                        seller_paid: 0,
                        buyer_refunded: res.buyer_refunded,
                        miner_fee: res.miner_fee,
                    },
                );
                Ok(res.miner_fee)
            }
            Tx::Act(a) => {
                let mut j = self.jobs.get(a.job()).ok_or("unknown job")?.clone();
                let fx = job::apply_action(&mut j, a, h)?;
                self.pay_out(&fx.payouts, fx.burned)?;
                self.jobs.insert(j.id, j);
                Ok(0)
            }
        }
    }

    /// Last step: the coinbase claim, issuance, the maturity queue and the new anchor.
    fn finish_block(&mut self, cb: &Coinbase, fees: u128, h: u32, genesis: bool) -> Result<(), String> {
        let claimed: u128 = cb.outs.iter().map(|o| o.v as u128).sum();
        let allowed = if genesis { 0 } else { subsidy(h) as u128 + fees };
        if claimed > allowed {
            return Err(format!("coinbase claims {claimed}, allowed {allowed}"));
        }
        // fees left the shielded pool when paid and return through the coinbase; fees not
        // claimed are burned, and the subsidy portion is issuance
        if claimed >= fees {
            self.issued += claimed - fees;
        } else {
            self.burned += fees - claimed;
        }
        if !cb.outs.is_empty() {
            self.pending_coinbase.push_back((h, cb.outs.clone()));
        }
        self.roots.insert(self.tree.root());
        self.height = h;
        Ok(())
    }

    /// Apply a block on top of this state and return the new state. Genesis blocks are
    /// applied to `State::new()` at height 0.
    pub fn apply(&self, block: &Block, params: &Params, checks: Checks) -> Result<State, String> {
        let genesis = block.header.prev == [0u8; 32];
        let h = if genesis { 0 } else { self.height + 1 };
        if genesis && (self.height != 0 || !self.tree.is_empty()) {
            return Err("genesis applied to a non-empty state".into());
        }
        // every limit `Block::decode` enforces is enforced here too, so a block this node
        // accepts is a block every node can decode
        block.check_limits(params.max_block_bytes, params.max_tx_bytes)?;

        let mut s = self.clone();
        s.nf_committed = params.nf_tree_from.is_some_and(|f| h >= f);
        s.begin_block(h, params);

        let Some(Tx::Coinbase(cb)) = block.txs.first() else {
            return Err("first transaction must be the coinbase".into());
        };
        if cb.height != h {
            return Err("coinbase height mismatch".into());
        }
        if cb.extra.len() > MAX_COINBASE_EXTRA || cb.outs.len() > 64 {
            return Err("coinbase too large".into());
        }
        if cb.outs.iter().any(|o| o.v > MAX_NOTE_VALUE) {
            return Err("coinbase output out of range".into());
        }
        if genesis && !cb.outs.is_empty() {
            return Err("the genesis block pays no one".into());
        }

        let mut fees: u128 = 0;
        let mut channel_hashes: u64 = 0;
        for (i, tx) in block.txs.iter().enumerate().skip(1) {
            if let Tx::Act(Action::ChannelClaim { ticks, .. }) = tx {
                channel_hashes = channel_hashes
                    .checked_add(*ticks as u64)
                    .ok_or_else(|| format!("tx {i}: block channel hash budget overflow"))?;
                if channel_hashes > MAX_BLOCK_CHANNEL_HASHES {
                    return Err(format!(
                        "tx {i}: block channel SHA-256 budget ({channel_hashes}) exceeds {MAX_BLOCK_CHANNEL_HASHES}"
                    ));
                }
            }
            fees += s.apply_tx_sized(tx, h, params, checks).map_err(|e| format!("tx {i}: {e}"))? as u128;
        }
        s.finish_block(cb, fees, h, genesis)?;
        if checks.check_commit {
            let digest = s.digest();
            if block.digest != digest || block.header.commit != header_commit(&block.tx_root(), &digest) {
                return Err("header commitment does not match the block".into());
            }
        }
        Ok(s)
    }
}

/// The parts of the state digest a block header commits to: the height, the note-tree root,
/// the nullifier accumulator, hashes of the jobs, the maturing coinbases and the open locks,
/// and the supply counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestParts {
    pub height: u32,
    pub tree_root: Word8,
    pub nf_acc: [u8; 32],
    pub jobs: [u8; 32],
    pub pending: [u8; 32],
    pub issued: u128,
    pub burned: u128,
    pub locked: u128,
    pub locks: Option<[u8; 32]>,
    pub conds: Option<[u8; 32]>,
    /// The nullifier tree's root, from `Params::nf_tree_from`.
    pub nf_root: Option<[u8; 32]>,
    /// RFC-0022: Open PayWord channels digest (present only while any channels are open).
    pub channels: Option<[u8; 32]>,
}

impl DigestParts {
    pub fn digest(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsSTATE").u32(self.height).word8(&self.tree_root).raw(&self.nf_acc);
        w.raw(&self.jobs).raw(&self.pending);
        w.raw(&self.issued.to_le_bytes()).raw(&self.burned.to_le_bytes()).raw(&self.locked.to_le_bytes());
        if let Some(l) = &self.locks {
            w.raw(l);
        }
        // marked, so that open conditions and open locks can never hash alike
        if let Some(c) = &self.conds {
            w.raw(b"C").raw(c);
        }
        if let Some(n) = &self.nf_root {
            w.raw(b"N").raw(n);
        }
        if let Some(ch) = &self.channels {
            w.raw(b"P").raw(ch);
        }
        sha256(&w.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest before locks existed: blocks made then must keep their commitments.
    fn digest_without_locks(s: &State) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsSTATE").u32(s.height).word8(&s.tree.root()).raw(&s.nf_acc);
        let mut jw = Writer::new();
        for j in s.jobs.values() {
            j.encode(&mut jw);
        }
        w.raw(&sha256(&jw.0));
        let mut pw = Writer::new();
        for (h, outs) in &s.pending_coinbase {
            pw.u32(*h);
            for o in outs {
                pw.word8(&o.cm());
            }
        }
        w.raw(&sha256(&pw.0));
        w.raw(&s.issued.to_le_bytes()).raw(&s.burned.to_le_bytes()).raw(&s.locked.to_le_bytes());
        sha256(&w.0)
    }

    #[test]
    fn with_no_open_locks_the_digest_is_the_one_blocks_already_commit_to() {
        let mut s = State::new();
        s.height = 7;
        s.issued = 123;
        s.locked = 5;
        s.append([1; 8]);
        s.pending_coinbase.push_back((7, vec![PlainOut { a_pk: [2; 8], v: 9, rho: [3; 5] }]));
        assert_eq!(s.digest(), digest_without_locks(&s));
        let post = lock::LockPost { hash: [4; 32], timeout: 20, claim_addr: [5; 8], refund_addr: [6; 8], amount: 5 };
        s.locks.insert([8; 32], Lock { id: [8; 32], post, at: 7 });
        assert_ne!(s.digest(), digest_without_locks(&s), "an open lock is committed to");
        s.locks.clear();
        assert_eq!(s.digest(), digest_without_locks(&s));
    }
}
