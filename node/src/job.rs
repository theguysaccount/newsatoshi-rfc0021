//! Proof of negentropy, as settlement: escrow for a verified matrix product.
//!
//! A poster locks `pay` and commits to A (n×k, by rows) and B (k×m, by columns) over the
//! Goldilocks field p = 2^64 − 2^32 + 1. A worker claims the job with a bond ≥ pay,
//! computes C = A·B off-chain, commits to C by rows and hands C over off-chain.
//! The poster checks it with Freivalds (1977): pick r at random, compare A(Br) with Cr,
//! O(n²) work for an O(n³) product, wrong answers survive with probability ≤ 1/p.
//! If C is wrong, one wrong entry convicts: anyone posts row i of A, column j of B and
//! row i of C with their Merkle paths, every node computes one dot product, the bond is
//! burned and the poster refunded. If the poster accepts, or the window closes with no
//! fraud proof, the worker is paid pay + bond. Withholding C is answered by a challenge
//! naming rows, which the worker must publish on chain or forfeit the bond.
//! Authorisations (commit, accept, challenge) are SLH-DSA-SHA2-128s signatures, FIPS 205,
//! which rest on SHA-256 alone.

use crate::bond::{BondPost, MAX_ARBITERS};
use crate::channel::{ChannelPost, MAX_BATCH_CHANNELS};
use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, Word8};
use crate::cond::CondPost;
use crate::lock::LockPost;
use crate::merkmap::MerkleProof;
use crate::mission::{MissionPost, MAX_VERIFIERS};
use crate::note::Rho;
use crate::rollup::{RollupPost, MAX_ROLLUP_PROOF_BYTES};
use rand::Rng;
use slh_dsa::{Sha2_128s, Signature, SigningKey, VerifyingKey};
use winterfell::math::{fields::f64::BaseElement as Felt, FieldElement, StarkField};

pub const MAX_DIM: u32 = 4096;
pub const MAX_CHALLENGE_ROWS: usize = 16;
pub const SIG_CONTEXT: &[u8] = b"newsatoshi/v0";
pub const VK_LEN: usize = 32;

// ---- matrix commitments -----------------------------------------------------------------

pub fn leaf(values: &[u64]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(6 + 8 * values.len());
    buf.extend_from_slice(b"nsLEAF");
    for v in values {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    sha256(&buf)
}

pub fn mnode(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 70];
    buf[..6].copy_from_slice(b"nsNODE");
    buf[6..38].copy_from_slice(l);
    buf[38..].copy_from_slice(r);
    sha256(&buf)
}

fn depth_for(count: usize) -> usize {
    count.next_power_of_two().trailing_zeros() as usize
}

/// Root and all levels of a padded binary tree over leaf hashes.
pub fn tree_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let d = depth_for(leaves.len().max(1));
    let mut lvl: Vec<[u8; 32]> = leaves.to_vec();
    lvl.resize(1 << d, [0u8; 32]);
    let mut out = vec![lvl.clone()];
    while lvl.len() > 1 {
        lvl = lvl.chunks(2).map(|c| mnode(&c[0], &c[1])).collect();
        out.push(lvl.clone());
    }
    out
}

pub fn root_of(rows: &[Vec<u64>]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = rows.iter().map(|r| leaf(r)).collect();
    *tree_levels(&leaves).last().unwrap().first().unwrap()
}

pub fn path_of(levels: &[Vec<[u8; 32]>], mut i: usize) -> Vec<[u8; 32]> {
    let mut p = vec![];
    for l in &levels[..levels.len() - 1] {
        p.push(l[i ^ 1]);
        i /= 2;
    }
    p
}

pub fn check_path(root: &[u8; 32], count: u32, i: u32, values: &[u64], path: &[[u8; 32]]) -> bool {
    if i >= count || path.len() != depth_for(count as usize) {
        return false;
    }
    let mut h = leaf(values);
    let mut idx = i;
    for s in path {
        h = if idx & 1 == 0 { mnode(&h, s) } else { mnode(s, &h) };
        idx >>= 1;
    }
    &h == root
}

// ---- field arithmetic for the product ----------------------------------------------------

pub fn reduce(x: u64) -> u64 {
    Felt::new(x).as_int()
}

pub fn dot(a: &[u64], b: &[u64]) -> u64 {
    let mut s = Felt::ZERO;
    for (x, y) in a.iter().zip(b) {
        s += Felt::new(*x) * Felt::new(*y);
    }
    s.as_int()
}

/// C = A·B with A given by rows (n×k) and B by columns (m columns of length k).
pub fn matmul(a_rows: &[Vec<u64>], b_cols: &[Vec<u64>]) -> Vec<Vec<u64>> {
    a_rows.iter().map(|r| b_cols.iter().map(|c| dot(r, c)).collect()).collect()
}

/// Freivalds with private randomness. Returns the first wrong entry found, if any.
pub fn freivalds(a_rows: &[Vec<u64>], b_cols: &[Vec<u64>], c_rows: &[Vec<u64>], rounds: usize) -> Option<(u32, u32)> {
    let mut rng = rand::thread_rng();
    let m = b_cols.len();
    for _ in 0..rounds {
        let r: Vec<u64> = (0..m).map(|_| rng.gen_range(0..Felt::MODULUS)).collect();
        // B·r as a k-vector: sum over columns j of r_j * col_j
        let k = a_rows.first().map(|x| x.len()).unwrap_or(0);
        let mut br = vec![Felt::ZERO; k];
        for (j, col) in b_cols.iter().enumerate() {
            let rj = Felt::new(r[j]);
            for (t, x) in col.iter().enumerate() {
                br[t] += Felt::new(*x) * rj;
            }
        }
        let br: Vec<u64> = br.iter().map(|x| x.as_int()).collect();
        for (i, row) in a_rows.iter().enumerate() {
            if dot(row, &br) != dot(&c_rows[i], &r) {
                // locate the column by recomputing this one row of the product
                for (j, col) in b_cols.iter().enumerate() {
                    if dot(row, col) != reduce(c_rows[i][j]) {
                        return Some((i as u32, j as u32));
                    }
                }
            }
        }
    }
    None
}

// ---- keys --------------------------------------------------------------------------------

pub struct JobKey(SigningKey<Sha2_128s>);

impl JobKey {
    pub fn generate() -> Self {
        JobKey(SigningKey::<Sha2_128s>::new(&mut rand::thread_rng()))
    }
    /// The job key that belongs to a wallet's spending key, so that the spending key alone
    /// restores a wallet (FIPS 205's key generation from seeds).
    pub fn derive(seed: &[u8]) -> Self {
        let a = sha256(&[b"nsJK1".as_slice(), seed].concat());
        let b = sha256(&[b"nsJK2".as_slice(), seed].concat());
        JobKey(SigningKey::<Sha2_128s>::slh_keygen_internal(&a[..16], &a[16..], &b[..16]))
    }
    pub fn from_bytes(b: &[u8]) -> Res<Self> {
        SigningKey::<Sha2_128s>::try_from(b).map(JobKey).map_err(|_| "bad signing key".into())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    pub fn vk(&self) -> Vec<u8> {
        let vk: &VerifyingKey<Sha2_128s> = self.0.as_ref();
        vk.to_vec()
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.try_sign_with_context(msg, SIG_CONTEXT, None).expect("sign").to_vec()
    }
}

pub fn verify_sig(vk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::<Sha2_128s>::try_from(vk) else { return false };
    let Ok(sig) = Signature::<Sha2_128s>::try_from(sig) else { return false };
    vk.try_verify_with_context(msg, SIG_CONTEXT, &sig).is_ok()
}

pub fn msg_commit(job: &[u8; 32], c_root: &[u8; 32]) -> Vec<u8> {
    [b"nsCOMMIT".as_slice(), job, c_root].concat()
}
pub fn msg_accept(job: &[u8; 32]) -> Vec<u8> {
    [b"nsACCEPT".as_slice(), job].concat()
}
pub fn msg_challenge(job: &[u8; 32], rows: &[u32]) -> Vec<u8> {
    let mut v = [b"nsCHALLENGE".as_slice(), job].concat();
    for r in rows {
        v.extend_from_slice(&r.to_le_bytes());
    }
    v
}

// ---- consensus objects -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobPost {
    pub poster_vk: Vec<u8>,
    pub poster_addr: Word8,
    pub n: u32,
    pub k: u32,
    pub m: u32,
    pub a_root: [u8; 32],
    pub b_root: [u8; 32],
    pub pay: u64,
    pub bond_min: u64,
    pub claim_by: u32,
    pub deliver_blocks: u32,
    pub window_blocks: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobClaim {
    pub job: [u8; 32],
    pub worker_vk: Vec<u8>,
    pub worker_addr: Word8,
    pub bond: u64,
}

/// What the public value of a spend pays for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deposit {
    Post(JobPost),
    Claim(JobClaim),
    /// A hash- and time-locked payment (`crate::lock`).
    Lock(LockPost),
    /// Coins locked to a condition, a program that releases them (`crate::cond`).
    Cond(CondPost),
    /// RFC-0022: Unilateral partial-claim PayWord payment channel (`crate::channel`).
    Channel(ChannelPost),
    /// RFC-0022: Batched open of up to 64 distinct PayWord payment channels in one spend.
    ChannelBatch(Vec<ChannelPost>),
    /// RFC-0024: Create a persistent Universal Trust Bond (`crate::bond`).
    Bond(BondPost),
    /// RFC-0024: Top up an existing Universal Trust Bond's active collateral.
    BondTopUp { bond: [u8; 32], amount: u64 },
    /// RFC-0023: Permissionlessly deploy a Sovereign L2 Rollup Vault (`crate::rollup`).
    RollupRegister(RollupPost),
    /// RFC-0023: Shielded L1 → L2 bridge deposit into an active Rollup Vault.
    RollupDeposit { rollup: [u8; 32], l2_recipient: [u8; 32], amount: u64 },
    /// RFC-0027: Launch a decentralized agent-coordination Mission Pool & Launchpad.
    MissionLaunch(MissionPost),
    /// RFC-0027: Fund a Mission Pool (either direct patron bounty or bonding-curve share buy).
    MissionFund { mission: [u8; 32], holder_vk: [u8; 32], amount: u64, direct_to_bounty: bool },
}

impl Deposit {
    pub fn amount(&self) -> u64 {
        self.checked_amount().unwrap_or(u64::MAX)
    }

    pub fn checked_amount(&self) -> Res<u64> {
        match self {
            Deposit::Post(p) => Ok(p.pay),
            Deposit::Claim(c) => Ok(c.bond),
            Deposit::Lock(l) => Ok(l.amount),
            Deposit::Cond(c) => Ok(c.amount),
            Deposit::Channel(ch) => ch.total_deposit(),
            Deposit::ChannelBatch(list) => {
                let mut sum: u64 = 0;
                for ch in list {
                    sum = sum
                        .checked_add(ch.total_deposit()?)
                        .ok_or("channel batch deposit overflow")?;
                }
                Ok(sum)
            }
            Deposit::Bond(b) => Ok(b.stake),
            Deposit::BondTopUp { amount, .. } => Ok(*amount),
            Deposit::RollupRegister(r) => Ok(r.initial_tvl),
            Deposit::RollupDeposit { amount, .. } => Ok(*amount),
            Deposit::MissionLaunch(m) => Ok(m.initial_funding),
            Deposit::MissionFund { amount, .. } => Ok(*amount),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowOpening {
    pub i: u32,
    pub values: Vec<u64>,
    pub path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Commit { job: [u8; 32], c_root: [u8; 32], sig: Vec<u8> },
    Accept { job: [u8; 32], sig: Vec<u8> },
    Challenge { job: [u8; 32], rows: Vec<u32>, sig: Vec<u8> },
    Respond { job: [u8; 32], rows: Vec<RowOpening> },
    Fraud { job: [u8; 32], a: RowOpening, b: RowOpening, c: RowOpening, j: u32 },
    Finalize { job: [u8; 32] },
    Refund { job: [u8; 32] },
    /// Release a lock to its claim address by publishing the preimage of its hash.
    Unlock { lock: [u8; 32], preimage: [u8; 32] },
    /// Release a lock, or coins under a condition, to the refund address once the timeout
    /// has passed.
    Expire { lock: [u8; 32] },
    /// Release coins under a condition to one of its payouts by running its program
    /// (`crate::cond`): the salt and program its commitment names, and a witness.
    Fulfil { cond: [u8; 32], payout: u8, salt: [u8; 32], program: Vec<u8>, witness: Vec<Vec<u8>> },
    /// RFC-0022: Seller-authorized unilateral claim of `ticks` vouchers from a PayWord channel,
    /// signed with the seller's `SLH-DSA-SHA2-128s` key (`seller_vk`), atomically splitting
    /// `ticks * unit_price` to seller, remainder to buyer, and fee to miner.
    ChannelClaim { channel: [u8; 32], ticks: u32, token: [u8; 32], sig: Vec<u8> },
    /// RFC-0022: Expire an unclaimed PayWord channel after timeout, refunding buyer and paying miner fee.
    ChannelExpire { channel: [u8; 32] },
    /// RFC-0024: Dual-signed honest settlement attestation compounding portable reputation.
    BondAttest {
        bond: [u8; 32],
        receipt_hash: [u8; 32],
        settled_amount: u64,
        fee: u64,
        owner_sig: Vec<u8>,
        counterparty_vk: [u8; 32],
        counterparty_sig: Vec<u8>,
    },
    /// RFC-0024: Permissionless Tier-1/Tier-2 equivocation slash paying victim + burning penalty.
    BondSlashEquivocation {
        bond: [u8; 32],
        context_nonce: u64,
        payload_a: [u8; 32],
        sig_a: Vec<u8>,
        payload_b: [u8; 32],
        sig_b: Vec<u8>,
        victim_addr: Word8,
        slash_amount: u64,
        miner_fee: u64,
    },
    /// RFC-0024: Tier-3 M-of-N arbiter quorum adjudication slash paying victim + burning penalty.
    BondSlashQuorum {
        bond: [u8; 32],
        dispute_hash: [u8; 32],
        victim_addr: Word8,
        slash_amount: u64,
        miner_fee: u64,
        sigs: Vec<(u8, Vec<u8>)>,
    },
    /// RFC-0024: Initiate timelocked bond withdrawal (collateral remains slashable during delay).
    BondUnbondRequest { bond: [u8; 32], amount: u64, sig: Vec<u8> },
    /// RFC-0024: Complete timelocked bond withdrawal once cooldown has elapsed.
    BondUnbondComplete { bond: [u8; 32], miner_fee: u64 },
    /// RFC-0023: Settle a hyperscale L2 batch via a 128-bit pure-SHA-2 Winterfell STARK proof.
    RollupBatch {
        rollup: [u8; 32],
        new_state_root: [u8; 32],
        withdraw_root: [u8; 32],
        batch_tx_count: u64,
        batch_withdrawals: u64,
        batch_fee: u64,
        sequencer_sig: Vec<u8>,
        proof: Vec<u8>,
    },
    /// RFC-0023: Trustless L2 → L1 shielded exit via canonical Merkle proof against `withdraw_root`.
    RollupWithdraw {
        rollup: [u8; 32],
        batch_seq: u64,
        withdrawal_id: [u8; 32],
        recipient_addr: Word8,
        amount: u64,
        miner_fee: u64,
        proof: MerkleProof,
    },
    /// RFC-0027: Post a verifiable lemma/subtask backed by the Mission Pool's bounty_pool.
    MissionPostTask {
        mission: [u8; 32],
        task_id: u32,
        spec_hash: [u8; 32],
        reward: u64,
        sig: Vec<u8>,
    },
    /// RFC-0027: Claim a verified Mission task with atomic contributor/public-goods split.
    MissionClaimTask {
        mission: [u8; 32],
        task_id: u32,
        proof_hash: [u8; 32],
        contributor_addr: Word8,
        contributor_bond_id: Option<[u8; 32]>,
        miner_fee: u64,
        verifier_sigs: Vec<(u8, Vec<u8>)>,
    },
    /// RFC-0027: Redeem bonding-curve shares back to shielded LOVE (routing fee to bounty_pool).
    MissionCurveRedeem {
        mission: [u8; 32],
        holder_vk: [u8; 32],
        shares: u64,
        recipient_addr: Word8,
        miner_fee: u64,
        sig: Vec<u8>,
    },
    /// RFC-0023: Permissionless on-chain L1 settlement directly verifying 1..=4 contiguous
    /// 128-bit pure-SHA-2 L2 `ZkVmExecutionAir` STARK shards pinned to `vault.post.vk_hash`.
    RollupZkVmBatch {
        rollup: [u8; 32],
        withdraw_root: [u8; 32],
        batch_fee: u64,
        sequencer_sig: Vec<u8>,
        shards: Vec<crate::zkvm::ZkVmShard>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Open,
    Claimed { worker_vk: Vec<u8>, worker_addr: Word8, bond: u64, at: u32 },
    Committed { worker_vk: Vec<u8>, worker_addr: Word8, bond: u64, c_root: [u8; 32], at: u32, challenged: bool },
    Challenged { worker_vk: Vec<u8>, worker_addr: Word8, bond: u64, c_root: [u8; 32], rows: Vec<u32>, at: u32 },
    Closed { paid_worker: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: [u8; 32],
    pub post: JobPost,
    pub posted_at: u32,
    pub phase: Phase,
}

/// A note the chain creates: the recipient learns (v, rho) from public data and spends it
/// with the key behind `a_pk`, like any other note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub a_pk: Word8,
    pub v: u64,
    pub rho: Rho,
}

pub fn payout_rho(job: &[u8; 32], tag: u8) -> Rho {
    let h = sha256(&[b"nsPAY".as_slice(), job, &[tag]].concat());
    core::array::from_fn(|i| u32::from_be_bytes(h[4 * i..4 * i + 4].try_into().unwrap()))
}

pub fn job_id(post: &JobPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsJOB");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

impl JobPost {
    pub fn encode(&self, w: &mut Writer) {
        w.bytes(&self.poster_vk).word8(&self.poster_addr).u32(self.n).u32(self.k).u32(self.m);
        w.raw(&self.a_root).raw(&self.b_root).u64(self.pay).u64(self.bond_min);
        w.u32(self.claim_by).u32(self.deliver_blocks).u32(self.window_blocks);
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(JobPost {
            poster_vk: r.bytes(VK_LEN)?,
            poster_addr: r.word8()?,
            n: r.u32()?,
            k: r.u32()?,
            m: r.u32()?,
            a_root: r.arr()?,
            b_root: r.arr()?,
            pay: r.u64()?,
            bond_min: r.u64()?,
            claim_by: r.u32()?,
            deliver_blocks: r.u32()?,
            window_blocks: r.u32()?,
        })
    }
}

impl Deposit {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Deposit::Post(p) => {
                w.u8(1);
                p.encode(w);
            }
            Deposit::Claim(c) => {
                w.u8(2).raw(&c.job).bytes(&c.worker_vk).word8(&c.worker_addr).u64(c.bond);
            }
            Deposit::Lock(l) => {
                w.u8(3);
                l.encode(w);
            }
            Deposit::Cond(c) => {
                w.u8(4);
                c.encode(w);
            }
            Deposit::Channel(ch) => {
                w.u8(5);
                ch.encode(w);
            }
            Deposit::ChannelBatch(list) => {
                w.u8(6).u8(list.len() as u8);
                for ch in list {
                    ch.encode(w);
                }
            }
            Deposit::Bond(b) => {
                w.u8(7);
                b.encode(w);
            }
            Deposit::BondTopUp { bond, amount } => {
                w.u8(8).raw(bond).u64(*amount);
            }
            Deposit::RollupRegister(r) => {
                w.u8(9);
                r.encode(w);
            }
            Deposit::RollupDeposit { rollup, l2_recipient, amount } => {
                w.u8(10).raw(rollup).raw(l2_recipient).u64(*amount);
            }
            Deposit::MissionLaunch(m) => {
                w.u8(11);
                m.encode(w);
            }
            Deposit::MissionFund { mission, holder_vk, amount, direct_to_bounty } => {
                w.u8(12).raw(mission).raw(holder_vk).u64(*amount).bool(*direct_to_bounty);
            }
        }
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        let tag = r.u8()?;
        Self::decode_body(tag, r)
    }
    pub fn decode_body(tag: u8, r: &mut Reader) -> Res<Self> {
        match tag {
            1 => Ok(Deposit::Post(JobPost::decode(r)?)),
            2 => Ok(Deposit::Claim(JobClaim { job: r.arr()?, worker_vk: r.bytes(VK_LEN)?, worker_addr: r.word8()?, bond: r.u64()? })),
            3 => Ok(Deposit::Lock(LockPost::decode(r)?)),
            4 => Ok(Deposit::Cond(CondPost::decode(r)?)),
            5 => Ok(Deposit::Channel(ChannelPost::decode(r)?)),
            6 => {
                let n = r.u8()? as usize;
                if n == 0 || n > MAX_BATCH_CHANNELS {
                    return Err("channel batch size out of range".into());
                }
                let list = (0..n).map(|_| ChannelPost::decode(r)).collect::<Res<Vec<_>>>()?;
                Ok(Deposit::ChannelBatch(list))
            }
            7 => Ok(Deposit::Bond(BondPost::decode(r)?)),
            8 => Ok(Deposit::BondTopUp { bond: r.arr()?, amount: r.u64()? }),
            9 => Ok(Deposit::RollupRegister(RollupPost::decode(r)?)),
            10 => Ok(Deposit::RollupDeposit { rollup: r.arr()?, l2_recipient: r.arr()?, amount: r.u64()? }),
            11 => Ok(Deposit::MissionLaunch(MissionPost::decode(r)?)),
            12 => Ok(Deposit::MissionFund {
                mission: r.arr()?,
                holder_vk: r.arr()?,
                amount: r.u64()?,
                direct_to_bounty: r.bool()?,
            }),
            _ => Err("bad deposit tag".into()),
        }
    }
}

const MAX_SIG: usize = 7856;

impl RowOpening {
    fn encode(&self, w: &mut Writer) {
        w.u32(self.i).u64s(&self.values);
        w.u32(self.path.len() as u32);
        for p in &self.path {
            w.raw(p);
        }
    }
    fn decode(r: &mut Reader) -> Res<Self> {
        let i = r.u32()?;
        let values = r.u64s(MAX_DIM as usize)?;
        let n = r.u32()? as usize;
        if n > 32 {
            return Err("path too long".into());
        }
        let path = (0..n).map(|_| r.arr()).collect::<Res<Vec<_>>>()?;
        Ok(RowOpening { i, values, path })
    }
}

impl Action {
    /// The job, or for `Unlock` and `Expire` the lock, that this action acts on.
    pub fn job(&self) -> &[u8; 32] {
        match self {
            Action::Commit { job, .. }
            | Action::Accept { job, .. }
            | Action::Challenge { job, .. }
            | Action::Respond { job, .. }
            | Action::Fraud { job, .. }
            | Action::Finalize { job }
            | Action::Refund { job } => job,
            Action::Unlock { lock, .. } | Action::Expire { lock } => lock,
            Action::Fulfil { cond, .. } => cond,
            Action::ChannelClaim { channel, .. } | Action::ChannelExpire { channel } => channel,
            Action::BondAttest { bond, .. }
            | Action::BondSlashEquivocation { bond, .. }
            | Action::BondSlashQuorum { bond, .. }
            | Action::BondUnbondRequest { bond, .. }
            | Action::BondUnbondComplete { bond, .. } => bond,
            Action::RollupBatch { rollup, .. }
            | Action::RollupWithdraw { rollup, .. }
            | Action::RollupZkVmBatch { rollup, .. } => rollup,
            Action::MissionPostTask { mission, .. }
            | Action::MissionClaimTask { mission, .. }
            | Action::MissionCurveRedeem { mission, .. } => mission,
        }
    }
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Action::Commit { job, c_root, sig } => {
                w.u8(1).raw(job).raw(c_root).bytes(sig);
            }
            Action::Accept { job, sig } => {
                w.u8(2).raw(job).bytes(sig);
            }
            Action::Challenge { job, rows, sig } => {
                w.u8(3).raw(job).u32(rows.len() as u32);
                rows.iter().for_each(|x| {
                    w.u32(*x);
                });
                w.bytes(sig);
            }
            Action::Respond { job, rows } => {
                w.u8(4).raw(job).u32(rows.len() as u32);
                rows.iter().for_each(|o| o.encode(w));
            }
            Action::Fraud { job, a, b, c, j } => {
                w.u8(5).raw(job);
                a.encode(w);
                b.encode(w);
                c.encode(w);
                w.u32(*j);
            }
            Action::Finalize { job } => {
                w.u8(6).raw(job);
            }
            Action::Refund { job } => {
                w.u8(7).raw(job);
            }
            Action::Unlock { lock, preimage } => {
                w.u8(8).raw(lock).raw(preimage);
            }
            Action::Expire { lock } => {
                w.u8(9).raw(lock);
            }
            Action::Fulfil { cond, payout, salt, program, witness } => {
                w.u8(10).raw(cond).u8(*payout).raw(salt).bytes(program).u32(witness.len() as u32);
                for x in witness {
                    w.bytes(x);
                }
            }
            Action::ChannelClaim { channel, ticks, token, sig } => {
                w.u8(11).raw(channel).u32(*ticks).raw(token).bytes(sig);
            }
            Action::ChannelExpire { channel } => {
                w.u8(12).raw(channel);
            }
            Action::BondAttest {
                bond,
                receipt_hash,
                settled_amount,
                fee,
                owner_sig,
                counterparty_vk,
                counterparty_sig,
            } => {
                w.u8(13)
                    .raw(bond)
                    .raw(receipt_hash)
                    .u64(*settled_amount)
                    .u64(*fee)
                    .bytes(owner_sig)
                    .raw(counterparty_vk)
                    .bytes(counterparty_sig);
            }
            Action::BondSlashEquivocation {
                bond,
                context_nonce,
                payload_a,
                sig_a,
                payload_b,
                sig_b,
                victim_addr,
                slash_amount,
                miner_fee,
            } => {
                w.u8(14)
                    .raw(bond)
                    .u64(*context_nonce)
                    .raw(payload_a)
                    .bytes(sig_a)
                    .raw(payload_b)
                    .bytes(sig_b)
                    .word8(victim_addr)
                    .u64(*slash_amount)
                    .u64(*miner_fee);
            }
            Action::BondSlashQuorum { bond, dispute_hash, victim_addr, slash_amount, miner_fee, sigs } => {
                w.u8(15)
                    .raw(bond)
                    .raw(dispute_hash)
                    .word8(victim_addr)
                    .u64(*slash_amount)
                    .u64(*miner_fee)
                    .u8(sigs.len() as u8);
                for (idx, sig) in sigs {
                    w.u8(*idx).bytes(sig);
                }
            }
            Action::BondUnbondRequest { bond, amount, sig } => {
                w.u8(16).raw(bond).u64(*amount).bytes(sig);
            }
            Action::BondUnbondComplete { bond, miner_fee } => {
                w.u8(17).raw(bond).u64(*miner_fee);
            }
            Action::RollupBatch {
                rollup,
                new_state_root,
                withdraw_root,
                batch_tx_count,
                batch_withdrawals,
                batch_fee,
                sequencer_sig,
                proof,
            } => {
                w.u8(18)
                    .raw(rollup)
                    .raw(new_state_root)
                    .raw(withdraw_root)
                    .u64(*batch_tx_count)
                    .u64(*batch_withdrawals)
                    .u64(*batch_fee)
                    .bytes(sequencer_sig)
                    .bytes(proof);
            }
            Action::RollupWithdraw {
                rollup,
                batch_seq,
                withdrawal_id,
                recipient_addr,
                amount,
                miner_fee,
                proof,
            } => {
                w.u8(19)
                    .raw(rollup)
                    .u64(*batch_seq)
                    .raw(withdrawal_id)
                    .word8(recipient_addr)
                    .u64(*amount)
                    .u64(*miner_fee)
                    .raw(&proof.key)
                    .raw(&proof.value_hash)
                    .u16(proof.siblings.len() as u16);
                for s in &proof.siblings {
                    w.raw(s);
                }
            }
            Action::MissionPostTask { mission, task_id, spec_hash, reward, sig } => {
                w.u8(20).raw(mission).u32(*task_id).raw(spec_hash).u64(*reward).bytes(sig);
            }
            Action::MissionClaimTask {
                mission,
                task_id,
                proof_hash,
                contributor_addr,
                contributor_bond_id,
                miner_fee,
                verifier_sigs,
            } => {
                w.u8(21).raw(mission).u32(*task_id).raw(proof_hash).word8(contributor_addr);
                match contributor_bond_id {
                    Some(bid) => {
                        w.bool(true).raw(bid);
                    }
                    None => {
                        w.bool(false);
                    }
                }
                w.u64(*miner_fee).u8(verifier_sigs.len() as u8);
                for (idx, sig) in verifier_sigs {
                    w.u8(*idx).bytes(sig);
                }
            }
            Action::MissionCurveRedeem { mission, holder_vk, shares, recipient_addr, miner_fee, sig } => {
                w.u8(22)
                    .raw(mission)
                    .raw(holder_vk)
                    .u64(*shares)
                    .word8(recipient_addr)
                    .u64(*miner_fee)
                    .bytes(sig);
            }
            Action::RollupZkVmBatch { rollup, withdraw_root, batch_fee, sequencer_sig, shards } => {
                w.u8(23)
                    .raw(rollup)
                    .raw(withdraw_root)
                    .u64(*batch_fee)
                    .bytes(sequencer_sig)
                    .u8(shards.len() as u8);
                for s in shards {
                    s.encode(w);
                }
            }
        }
    }
    pub fn decode(r: &mut Reader) -> Res<Self> {
        Ok(match r.u8()? {
            1 => Action::Commit { job: r.arr()?, c_root: r.arr()?, sig: r.bytes(MAX_SIG)? },
            2 => Action::Accept { job: r.arr()?, sig: r.bytes(MAX_SIG)? },
            3 => {
                let job = r.arr()?;
                let n = r.u32()? as usize;
                if n > MAX_CHALLENGE_ROWS {
                    return Err("too many rows".into());
                }
                let rows = (0..n).map(|_| r.u32()).collect::<Res<Vec<_>>>()?;
                Action::Challenge { job, rows, sig: r.bytes(MAX_SIG)? }
            }
            4 => {
                let job = r.arr()?;
                let n = r.u32()? as usize;
                if n > MAX_CHALLENGE_ROWS {
                    return Err("too many rows".into());
                }
                Action::Respond { job, rows: (0..n).map(|_| RowOpening::decode(r)).collect::<Res<Vec<_>>>()? }
            }
            5 => Action::Fraud {
                job: r.arr()?,
                a: RowOpening::decode(r)?,
                b: RowOpening::decode(r)?,
                c: RowOpening::decode(r)?,
                j: r.u32()?,
            },
            6 => Action::Finalize { job: r.arr()? },
            7 => Action::Refund { job: r.arr()? },
            8 => Action::Unlock { lock: r.arr()?, preimage: r.arr()? },
            9 => Action::Expire { lock: r.arr()? },
            10 => {
                let (cond, payout, salt) = (r.arr()?, r.u8()?, r.arr()?);
                let program = r.bytes(crate::script::MAX_PROGRAM)?;
                let n = r.u32()? as usize;
                if n > crate::script::MAX_WITNESS {
                    return Err("witness too long".into());
                }
                let witness = (0..n).map(|_| r.bytes(crate::script::MAX_ITEM)).collect::<Res<Vec<_>>>()?;
                if witness.iter().map(Vec::len).sum::<usize>() > crate::script::MAX_WITNESS_BYTES {
                    return Err("witness bytes exceed limit".into());
                }
                Action::Fulfil { cond, payout, salt, program, witness }
            }
            11 => Action::ChannelClaim {
                channel: r.arr()?,
                ticks: r.u32()?,
                token: r.arr()?,
                sig: r.bytes(MAX_SIG)?,
            },
            12 => Action::ChannelExpire { channel: r.arr()? },
            13 => Action::BondAttest {
                bond: r.arr()?,
                receipt_hash: r.arr()?,
                settled_amount: r.u64()?,
                fee: r.u64()?,
                owner_sig: r.bytes(MAX_SIG)?,
                counterparty_vk: r.arr()?,
                counterparty_sig: r.bytes(MAX_SIG)?,
            },
            14 => Action::BondSlashEquivocation {
                bond: r.arr()?,
                context_nonce: r.u64()?,
                payload_a: r.arr()?,
                sig_a: r.bytes(MAX_SIG)?,
                payload_b: r.arr()?,
                sig_b: r.bytes(MAX_SIG)?,
                victim_addr: r.word8()?,
                slash_amount: r.u64()?,
                miner_fee: r.u64()?,
            },
            15 => {
                let bond = r.arr()?;
                let dispute_hash = r.arr()?;
                let victim_addr = r.word8()?;
                let slash_amount = r.u64()?;
                let miner_fee = r.u64()?;
                let n = r.u8()? as usize;
                if n == 0 || n > MAX_ARBITERS {
                    return Err("quorum sig count out of range".into());
                }
                let mut sigs = Vec::with_capacity(n);
                for _ in 0..n {
                    sigs.push((r.u8()?, r.bytes(MAX_SIG)?));
                }
                Action::BondSlashQuorum { bond, dispute_hash, victim_addr, slash_amount, miner_fee, sigs }
            }
            16 => Action::BondUnbondRequest {
                bond: r.arr()?,
                amount: r.u64()?,
                sig: r.bytes(MAX_SIG)?,
            },
            17 => Action::BondUnbondComplete { bond: r.arr()?, miner_fee: r.u64()? },
            18 => Action::RollupBatch {
                rollup: r.arr()?,
                new_state_root: r.arr()?,
                withdraw_root: r.arr()?,
                batch_tx_count: r.u64()?,
                batch_withdrawals: r.u64()?,
                batch_fee: r.u64()?,
                sequencer_sig: r.bytes(MAX_SIG)?,
                proof: r.bytes(MAX_ROLLUP_PROOF_BYTES)?,
            },
            19 => {
                let rollup = r.arr()?;
                let batch_seq = r.u64()?;
                let withdrawal_id = r.arr()?;
                let recipient_addr = r.word8()?;
                let amount = r.u64()?;
                let miner_fee = r.u64()?;
                let key = r.arr()?;
                let value_hash = r.arr()?;
                let ns = r.u16()? as usize;
                if ns > 256 {
                    return Err("rollup withdrawal Merkle proof too deep".into());
                }
                let siblings = (0..ns).map(|_| r.arr()).collect::<Res<Vec<_>>>()?;
                Action::RollupWithdraw {
                    rollup,
                    batch_seq,
                    withdrawal_id,
                    recipient_addr,
                    amount,
                    miner_fee,
                    proof: MerkleProof { key, value_hash, siblings },
                }
            }
            20 => Action::MissionPostTask {
                mission: r.arr()?,
                task_id: r.u32()?,
                spec_hash: r.arr()?,
                reward: r.u64()?,
                sig: r.bytes(MAX_SIG)?,
            },
            21 => {
                let mission = r.arr()?;
                let task_id = r.u32()?;
                let proof_hash = r.arr()?;
                let contributor_addr = r.word8()?;
                let contributor_bond_id = if r.bool()? { Some(r.arr()?) } else { None };
                let miner_fee = r.u64()?;
                let n = r.u8()? as usize;
                if n == 0 || n > MAX_VERIFIERS {
                    return Err("mission verifier sig count out of range".into());
                }
                let mut verifier_sigs = Vec::with_capacity(n);
                for _ in 0..n {
                    verifier_sigs.push((r.u8()?, r.bytes(MAX_SIG)?));
                }
                Action::MissionClaimTask {
                    mission,
                    task_id,
                    proof_hash,
                    contributor_addr,
                    contributor_bond_id,
                    miner_fee,
                    verifier_sigs,
                }
            }
            22 => Action::MissionCurveRedeem {
                mission: r.arr()?,
                holder_vk: r.arr()?,
                shares: r.u64()?,
                recipient_addr: r.word8()?,
                miner_fee: r.u64()?,
                sig: r.bytes(MAX_SIG)?,
            },
            23 => {
                let rollup = r.arr()?;
                let withdraw_root = r.arr()?;
                let batch_fee = r.u64()?;
                let sequencer_sig = r.bytes(MAX_SIG)?;
                let n = r.u8()? as usize;
                if n == 0 || n > crate::zkvm::MAX_ONCHAIN_ZKVM_SHARDS {
                    return Err("zkVM shard count out of range".into());
                }
                let mut shards = Vec::with_capacity(n);
                for _ in 0..n {
                    shards.push(crate::zkvm::ZkVmShard::decode(r)?);
                }
                Action::RollupZkVmBatch { rollup, withdraw_root, batch_fee, sequencer_sig, shards }
            }
            _ => return Err("bad action tag".into()),
        })
    }
}

impl Job {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.posted_at);
        match &self.phase {
            Phase::Open => {
                w.u8(0);
            }
            Phase::Claimed { worker_vk, worker_addr, bond, at } => {
                w.u8(1).bytes(worker_vk).word8(worker_addr).u64(*bond).u32(*at);
            }
            Phase::Committed { worker_vk, worker_addr, bond, c_root, at, challenged } => {
                w.u8(2).bytes(worker_vk).word8(worker_addr).u64(*bond).raw(c_root).u32(*at).bool(*challenged);
            }
            Phase::Challenged { worker_vk, worker_addr, bond, c_root, rows, at } => {
                w.u8(3).bytes(worker_vk).word8(worker_addr).u64(*bond).raw(c_root).u32(*at);
                w.u32(rows.len() as u32);
                rows.iter().for_each(|x| {
                    w.u32(*x);
                });
            }
            Phase::Closed { paid_worker } => {
                w.u8(4).bool(*paid_worker);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let id = r.arr()?;
        let post = JobPost::decode(r)?;
        let posted_at = r.u32()?;
        let phase = match r.u8()? {
            0 => Phase::Open,
            1 => Phase::Claimed {
                worker_vk: r.bytes(VK_LEN)?,
                worker_addr: r.word8()?,
                bond: r.u64()?,
                at: r.u32()?,
            },
            2 => Phase::Committed {
                worker_vk: r.bytes(VK_LEN)?,
                worker_addr: r.word8()?,
                bond: r.u64()?,
                c_root: r.arr()?,
                at: r.u32()?,
                challenged: r.bool()?,
            },
            3 => {
                let worker_vk = r.bytes(VK_LEN)?;
                let worker_addr = r.word8()?;
                let bond = r.u64()?;
                let c_root = r.arr()?;
                let at = r.u32()?;
                let n = r.u32()? as usize;
                if n > MAX_CHALLENGE_ROWS {
                    return Err("too many challenged rows".into());
                }
                let rows = (0..n).map(|_| r.u32()).collect::<Res<Vec<_>>>()?;
                Phase::Challenged { worker_vk, worker_addr, bond, c_root, rows, at }
            }
            4 => Phase::Closed { paid_worker: r.bool()? },
            _ => return Err("bad job phase tag".into()),
        };
        Ok(Job { id, post, posted_at, phase })
    }
}

/// Bytes of the transaction that answers a challenge of `MAX_CHALLENGE_ROWS` rows of an
/// n-row result with m columns: 230 + 128·m + 512·⌈log2 n⌉.
pub fn max_respond_bytes(n: u32, m: u32) -> usize {
    let row = 4 + (4 + 8 * m as usize) + (4 + 32 * depth_for(n as usize));
    1 + 1 + 32 + 4 + MAX_CHALLENGE_ROWS * row
}

/// Validate a post against the chain height; returns the error if it may not be accepted.
pub fn check_post(p: &JobPost, height: u32) -> Res<()> {
    if p.poster_vk.len() != VK_LEN {
        return Err("poster key must be 32 bytes".into());
    }
    for d in [p.n, p.k, p.m] {
        if d == 0 || d > MAX_DIM {
            return Err("matrix dimension out of range".into());
        }
    }
    // A worker must always be able to answer a full challenge in one transaction; otherwise
    // a poster could challenge, see no valid answer is possible, and take the bond.
    if max_respond_bytes(p.n, p.m) > crate::params::MAX_TX_BYTES {
        return Err("a full challenge response would not fit in one transaction; lower m".into());
    }
    if p.pay == 0 || p.bond_min < p.pay {
        return Err("pay must be positive and the bond at least the pay".into());
    }
    // pay + bond becomes one note when the worker is paid
    if p.bond_min > crate::note::MAX_NOTE_VALUE - p.pay.min(crate::note::MAX_NOTE_VALUE) {
        return Err("pay plus bond exceeds the largest note".into());
    }
    if p.claim_by <= height {
        return Err("claim deadline already passed".into());
    }
    if !(1..=10_000).contains(&p.deliver_blocks) || !(1..=10_000).contains(&p.window_blocks) {
        return Err("deadlines out of range".into());
    }
    Ok(())
}

/// Effects of applying an action: payouts to create and value burned.
#[derive(Default, Debug)]
pub struct Effects {
    pub payouts: Vec<Payout>,
    pub burned: u64,
}

fn pay_worker(job: &Job, worker_addr: &Word8, bond: u64) -> Effects {
    Effects { payouts: vec![Payout { a_pk: *worker_addr, v: job.post.pay + bond, rho: payout_rho(&job.id, 1) }], burned: 0 }
}

fn refund(job: &Job, burned: u64) -> Effects {
    Effects { payouts: vec![Payout { a_pk: job.post.poster_addr, v: job.post.pay, rho: payout_rho(&job.id, 2) }], burned }
}

/// Apply a claim deposit.
pub fn apply_claim(job: &mut Job, c: &JobClaim, height: u32) -> Res<()> {
    if job.phase != Phase::Open {
        return Err("job is not open".into());
    }
    if height > job.post.claim_by {
        return Err("claim deadline passed".into());
    }
    if c.bond < job.post.bond_min {
        return Err("bond below the minimum".into());
    }
    if job.post.pay.checked_add(c.bond).map_or(true, |v| v > crate::note::MAX_NOTE_VALUE) {
        return Err("pay plus bond exceeds the largest note".into());
    }
    if c.worker_vk.len() != VK_LEN {
        return Err("worker key must be 32 bytes".into());
    }
    job.phase = Phase::Claimed { worker_vk: c.worker_vk.clone(), worker_addr: c.worker_addr, bond: c.bond, at: height };
    Ok(())
}

/// Apply a standalone action at `height`.
pub fn apply_action(job: &mut Job, a: &Action, height: u32) -> Res<Effects> {
    let post = job.post.clone();
    match (a, job.phase.clone()) {
        (Action::Commit { c_root, sig, .. }, Phase::Claimed { worker_vk, worker_addr, bond, at }) => {
            if height > at + post.deliver_blocks {
                return Err("delivery deadline passed".into());
            }
            if !verify_sig(&worker_vk, &msg_commit(&job.id, c_root), sig) {
                return Err("bad worker signature".into());
            }
            job.phase = Phase::Committed { worker_vk, worker_addr, bond, c_root: *c_root, at: height, challenged: false };
            Ok(Effects::default())
        }
        (Action::Accept { sig, .. }, Phase::Committed { worker_addr, bond, .. })
        | (Action::Accept { sig, .. }, Phase::Challenged { worker_addr, bond, .. }) => {
            if !verify_sig(&post.poster_vk, &msg_accept(&job.id), sig) {
                return Err("bad poster signature".into());
            }
            let fx = pay_worker(job, &worker_addr, bond);
            job.phase = Phase::Closed { paid_worker: true };
            Ok(fx)
        }
        (Action::Challenge { rows, sig, .. }, Phase::Committed { worker_vk, worker_addr, bond, c_root, at, challenged }) => {
            if challenged {
                return Err("a job may be challenged once".into());
            }
            if height > at + post.window_blocks {
                return Err("challenge window closed".into());
            }
            if rows.is_empty() || rows.len() > MAX_CHALLENGE_ROWS || rows.iter().any(|r| *r >= post.n) {
                return Err("bad challenge rows".into());
            }
            if !verify_sig(&post.poster_vk, &msg_challenge(&job.id, rows), sig) {
                return Err("bad poster signature".into());
            }
            job.phase = Phase::Challenged { worker_vk, worker_addr, bond, c_root, rows: rows.clone(), at: height };
            Ok(Effects::default())
        }
        (Action::Respond { rows: opened, .. }, Phase::Challenged { worker_vk, worker_addr, bond, c_root, rows, at }) => {
            if height > at + post.window_blocks {
                return Err("response window closed".into());
            }
            for want in &rows {
                let Some(o) = opened.iter().find(|o| o.i == *want) else {
                    return Err(format!("row {want} not published"));
                };
                if o.values.len() != post.m as usize || !check_path(&c_root, post.n, o.i, &o.values, &o.path) {
                    return Err("row opening does not match the committed result".into());
                }
            }
            job.phase = Phase::Committed { worker_vk, worker_addr, bond, c_root, at: height, challenged: true };
            Ok(Effects::default())
        }
        (Action::Fraud { a, b, c, j, .. }, Phase::Committed { bond, c_root, at, .. })
        | (Action::Fraud { a, b, c, j, .. }, Phase::Challenged { bond, c_root, at, .. }) => {
            if height > at + post.window_blocks {
                return Err("fraud window closed".into());
            }
            if a.i != c.i || b.i != *j || *j >= post.m {
                return Err("fraud proof indices disagree".into());
            }
            if a.values.len() != post.k as usize || b.values.len() != post.k as usize || c.values.len() != post.m as usize {
                return Err("fraud proof vectors have the wrong length".into());
            }
            if !check_path(&post.a_root, post.n, a.i, &a.values, &a.path)
                || !check_path(&post.b_root, post.m, b.i, &b.values, &b.path)
                || !check_path(&c_root, post.n, c.i, &c.values, &c.path)
            {
                return Err("fraud proof openings do not match the commitments".into());
            }
            if dot(&a.values, &b.values) == reduce(c.values[*j as usize]) {
                return Err("the entry is correct".into());
            }
            let fx = refund(job, bond);
            job.phase = Phase::Closed { paid_worker: false };
            Ok(fx)
        }
        (Action::Finalize { .. }, Phase::Committed { worker_addr, bond, at, .. }) => {
            if height <= at + post.window_blocks {
                return Err("window still open".into());
            }
            let fx = pay_worker(job, &worker_addr, bond);
            job.phase = Phase::Closed { paid_worker: true };
            Ok(fx)
        }
        (Action::Refund { .. }, Phase::Open) => {
            if height <= post.claim_by {
                return Err("job can still be claimed".into());
            }
            let fx = refund(job, 0);
            job.phase = Phase::Closed { paid_worker: false };
            Ok(fx)
        }
        (Action::Refund { .. }, Phase::Claimed { bond, at, .. }) => {
            if height <= at + post.deliver_blocks {
                return Err("worker can still deliver".into());
            }
            let fx = refund(job, bond);
            job.phase = Phase::Closed { paid_worker: false };
            Ok(fx)
        }
        (Action::Refund { .. }, Phase::Challenged { bond, at, .. }) => {
            if height <= at + post.window_blocks {
                return Err("worker can still respond".into());
            }
            let fx = refund(job, bond);
            job.phase = Phase::Closed { paid_worker: false };
            Ok(fx)
        }
        _ => Err("action not allowed in this phase".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_matrix(rows: usize, cols: usize) -> Vec<Vec<u64>> {
        let mut rng = rand::thread_rng();
        (0..rows).map(|_| (0..cols).map(|_| rng.gen_range(0..Felt::MODULUS)).collect()).collect()
    }

    #[test]
    fn freivalds_catches_one_wrong_entry_and_locates_it() {
        let a = rand_matrix(48, 40);
        let b = rand_matrix(36, 40); // 36 columns of length 40
        let mut c = matmul(&a, &b);
        assert_eq!(freivalds(&a, &b, &c, 2), None);
        c[17][29] = (c[17][29] + 1) % Felt::MODULUS;
        assert_eq!(freivalds(&a, &b, &c, 1), Some((17, 29)));
    }

    #[test]
    fn openings_verify_and_forged_ones_do_not() {
        let a = rand_matrix(13, 7);
        let leaves: Vec<_> = a.iter().map(|r| leaf(r)).collect();
        let lv = tree_levels(&leaves);
        let root = root_of(&a);
        for i in 0..13 {
            assert!(check_path(&root, 13, i as u32, &a[i], &path_of(&lv, i)));
        }
        let mut bad = a[5].clone();
        bad[0] ^= 1;
        assert!(!check_path(&root, 13, 5, &bad, &path_of(&lv, 5)));
        assert!(!check_path(&root, 13, 6, &a[5], &path_of(&lv, 5)));
    }

    #[test]
    fn slh_dsa_signs_and_verifies() {
        let k = JobKey::generate();
        let job = [7u8; 32];
        let sig = k.sign(&msg_accept(&job));
        assert_eq!(sig.len(), 7856);
        assert_eq!(k.vk().len(), 32);
        assert!(verify_sig(&k.vk(), &msg_accept(&job), &sig));
        assert!(!verify_sig(&k.vk(), &msg_accept(&[8u8; 32]), &sig));
    }
}
