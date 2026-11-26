//! Priorism-FEP Consensus Primitive: Falsifiable `PriorLock` with Surprise Bounty & Burn.
//!
//! Encodes the Free Energy Principle (variational surprise minimization) directly into
//! L1 settlement rules using pure SHA-256 + NIST FIPS 205 (`SLH-DSA-SHA2-128s`) signatures:
//!
//! 1. **Commit (`Deposit::Prior`):** An actor or AI agent locks `stake >= MIN_PRIOR_STAKE`
//!    bound to a falsifiable `spec_hash`, `deadline`, `challenge_window`, an optional
//!    objective `falsifier_hash`, and optional `M-of-N` independent `SLH-DSA` arbiters
//!    (enforcing SCGS Invariant I-3: every arbiter key is distinct AND strictly
//!    `arbiter_vk != owner_vk` — self-approval is cryptographically impossible).
//! 2. **Optional Outcome Claim (`Action::PriorCommit`):** Before `deadline`, the committer
//!    signs an `outcome_hash` so verifiers know the exact claimed outcome to audit.
//! 3. **Disconfirmation / Surprise Event (before `deadline + challenge_window`):**
//!    - **Objective (`Action::PriorDisconfirmObjective`):** Permissionless cryptographic
//!      falsification requiring zero arbiters — either revealing a preimage whose SHA-256
//!      equals `falsifier_hash` (kind 0), OR submitting two distinct payloads signed by
//!      `owner_vk` under the same `(prior_id, context_nonce)` (signed equivocation, kind 1).
//!    - **Independent Arbiter Quorum (`Action::PriorDisconfirmQuorum`):** `M-of-N` distinct
//!      independent arbiters sign the disconfirmation evidence.
//!    On any valid disconfirmation, `miner_fee <= stake / 10` is paid to the block producer,
//!    and the remaining `slashable = stake - miner_fee` splits deterministically:
//!      * `bounty = slashable / 2` -> shielded note paid to `disconfirmer_addr` (Surprise Bounty)
//!      * `burned = slashable - bounty` (>= 50%) -> permanently burned into `state.burned`!
//!    Exact conservation: `bounty + burned + miner_fee == stake`.
//! 4. **Zero-Surprise Unlock (`Action::PriorRelease`):** After `height > deadline + challenge_window`
//!    with zero disconfirmation, collateral unlocks cleanly back to `owner_addr`.
//!
//! Active L1 consensus state holds ONLY open `PriorLock`s (`O(open)` bounded state committed
//! via `MerkleMap` in `DigestParts::priors`). Closed priors are removed from the active map.

use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, Word8};
use crate::job::{payout_rho, verify_sig, Payout};
use crate::note::MAX_NOTE_VALUE;

/// Minimum collateral to open a `PriorLock` (`0.01 LOVE` = 1,000,000 base units).
pub const MIN_PRIOR_STAKE: u64 = 1_000_000;
/// Maximum distinct independent arbiters per `PriorLock`.
pub const MAX_PRIOR_ARBITERS: usize = 7;
/// Maximum deadline horizon ahead of opening height (~1 year at 10-minute blocks).
pub const MAX_PRIOR_HORIZON: u32 = 52_560;
/// Maximum challenge window duration in blocks.
pub const MAX_CHALLENGE_WINDOW: u32 = 10_000;
/// Maximum fraction of stake allowed as miner fee on disconfirmation/release (10% = 1,000 bps).
pub const MAX_PRIOR_FEE_BPS: u64 = 1_000;

const TAG_DISCONFIRM_BOUNTY: u8 = 41;
const TAG_RELEASE_OWNER: u8 = 42;

/// Immutable terms committed when opening a `PriorLock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorPost {
    /// Committer's 32-byte `SLH-DSA-SHA2-128s` verifying key (FIPS 205).
    pub owner_vk: [u8; 32],
    /// Shielded address that receives the unlocked stake on zero-surprise completion.
    pub owner_addr: Word8,
    /// SHA-256 commitment to the falsifiable specification / service promise.
    pub spec_hash: [u8; 32],
    /// Optional objective SHA-256 falsifier target (`[0u8; 32]` disables preimage falsification;
    /// signed equivocation under `owner_vk` is ALWAYS objectively disconfirmable!).
    pub falsifier_hash: [u8; 32],
    /// Independent `SLH-DSA-SHA2-128s` arbiter verifying keys (every key != `owner_vk`).
    pub arbiter_vks: Vec<[u8; 32]>,
    /// Quorum threshold `M` (`0` = objective-only mode; otherwise `1..=arbiter_vks.len()`).
    pub quorum_m: u8,
    /// Height by which the prior matures (challenge window begins after `deadline`).
    pub deadline: u32,
    /// Blocks after `deadline` during which disconfirmation remains open (`1..=10_000`).
    pub challenge_window: u32,
    /// Locked `LOVE` collateral (`>= MIN_PRIOR_STAKE`).
    pub stake: u64,
}

/// Active on-chain `PriorLock` entry (removed from consensus map upon disconfirmation or release).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorLock {
    pub id: [u8; 32],
    pub post: PriorPost,
    pub created_at: u32,
    pub outcome_hash: Option<[u8; 32]>,
    pub committed_at: Option<u32>,
}

/// Derived historical record of how a `PriorLock` closed (for RPC/wallets; NOT in state digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorEnd {
    pub prior: PriorLock,
    pub height: u32,
    /// `Some((evidence_hash, disconfirmer_addr, bounty, burned))` if disconfirmed; `None` if released.
    pub disconfirmed: Option<([u8; 32], Word8, u64, u64)>,
    pub miner_fee: u64,
}

/// Exact state-transition effects returned to `state.rs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PriorEffects {
    pub payouts: Vec<Payout>,
    pub burned: u64,
    pub miner_fee: u64,
    pub disconfirmed: Option<([u8; 32], Word8, u64, u64)>,
}

impl PriorPost {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.owner_vk)
            .word8(&self.owner_addr)
            .raw(&self.spec_hash)
            .raw(&self.falsifier_hash)
            .u8(self.arbiter_vks.len() as u8);
        for vk in &self.arbiter_vks {
            w.raw(vk);
        }
        w.u8(self.quorum_m)
            .u32(self.deadline)
            .u32(self.challenge_window)
            .u64(self.stake);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let owner_vk = r.arr()?;
        let owner_addr = r.word8()?;
        let spec_hash = r.arr()?;
        let falsifier_hash = r.arr()?;
        let n = r.u8()? as usize;
        if n > MAX_PRIOR_ARBITERS {
            return Err("too many prior arbiters".into());
        }
        let mut arbiter_vks = Vec::with_capacity(n);
        for _ in 0..n {
            arbiter_vks.push(r.arr()?);
        }
        Ok(PriorPost {
            owner_vk,
            owner_addr,
            spec_hash,
            falsifier_hash,
            arbiter_vks,
            quorum_m: r.u8()?,
            deadline: r.u32()?,
            challenge_window: r.u32()?,
            stake: r.u64()?,
        })
    }
}

impl PriorLock {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.created_at);
        match (self.outcome_hash, self.committed_at) {
            (Some(oh), Some(h)) => {
                w.bool(true).raw(&oh).u32(h);
            }
            _ => {
                w.bool(false);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let id = r.arr()?;
        let post = PriorPost::decode(r)?;
        let created_at = r.u32()?;
        let (outcome_hash, committed_at) = if r.bool()? {
            (Some(r.arr()?), Some(r.u32()?))
        } else {
            (None, None)
        };
        Ok(PriorLock { id, post, created_at, outcome_hash, committed_at })
    }

    /// Canonical SHA-256 leaf digest for `State::priors_merkle` (`DigestParts::priors`).
    pub fn value_hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsPRIORV1");
        self.encode(&mut w);
        sha256(&w.0)
    }

    /// Height through which disconfirmation is accepted; strictly after this height, release opens.
    pub fn unlock_after(&self) -> u32 {
        self.post.deadline.saturating_add(self.post.challenge_window)
    }
}

/// Deterministic `PriorLock` identifier: `sha256("nsPRIOR1" || post || first_nf)`.
pub fn prior_id(post: &PriorPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsPRIOR1");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

/// Message signed by `owner_vk` to commit an outcome claim before `deadline`.
pub fn commit_message(prior: &[u8; 32], outcome_hash: &[u8; 32]) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsPRIOR-COMMIT").raw(prior).raw(outcome_hash);
    sha256(&w.0)
}

/// Message signed by `owner_vk` for contextual commitments (two conflicting payloads under
/// the same `(prior, context_nonce)` constitute an objective equivocation proof!).
pub fn statement_message(prior: &[u8; 32], context_nonce: u64, payload_hash: &[u8; 32]) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsPRIOR-STMT").raw(prior).u64(context_nonce).raw(payload_hash);
    sha256(&w.0)
}

/// Message signed by `M-of-N` independent arbiters to disconfirm a falsified prior.
pub fn quorum_disconfirm_message(
    prior: &[u8; 32],
    evidence_hash: &[u8; 32],
    disconfirmer_addr: &Word8,
    miner_fee: u64,
) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsPRIOR-DISCONFIRM")
        .raw(prior)
        .raw(evidence_hash)
        .word8(disconfirmer_addr)
        .u64(miner_fee);
    sha256(&w.0)
}

/// Message signed by `owner_vk` when releasing with a non-zero `miner_fee`.
pub fn release_message(prior: &[u8; 32], miner_fee: u64) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsPRIOR-RELEASE").raw(prior).u64(miner_fee);
    sha256(&w.0)
}

/// Validate `PriorPost` creation rules, including SCGS Invariant I-3 (`arbiter != owner`).
pub fn check_post(p: &PriorPost, height: u32) -> Res<()> {
    if p.stake < MIN_PRIOR_STAKE || p.stake > MAX_NOTE_VALUE {
        return Err(format!("prior stake must be between {MIN_PRIOR_STAKE} and {MAX_NOTE_VALUE}"));
    }
    if p.spec_hash == [0u8; 32] {
        return Err("prior spec_hash must be non-zero".into());
    }
    if p.deadline <= height {
        return Err("prior deadline must be in the future".into());
    }
    if p.deadline - height > MAX_PRIOR_HORIZON {
        return Err("prior deadline exceeds max horizon".into());
    }
    if p.challenge_window == 0 || p.challenge_window > MAX_CHALLENGE_WINDOW {
        return Err("prior challenge_window out of range".into());
    }
    if p.arbiter_vks.len() > MAX_PRIOR_ARBITERS {
        return Err("too many prior arbiters".into());
    }
    if p.quorum_m as usize > p.arbiter_vks.len() {
        return Err("prior quorum_m exceeds arbiter count".into());
    }
    if p.quorum_m == 0 && !p.arbiter_vks.is_empty() {
        return Err("prior arbiter_vks provided with quorum_m == 0".into());
    }
    // SCGS Invariant I-3: independent verification requires distinct arbiters AND arbiter != owner.
    for (i, vk) in p.arbiter_vks.iter().enumerate() {
        if vk == &p.owner_vk {
            return Err("SCGS I-3 violation: owner cannot be an arbiter of their own prior".into());
        }
        if p.arbiter_vks[i + 1..].iter().any(|other| other == vk) {
            return Err("duplicate arbiter verifying key in prior".into());
        }
    }
    Ok(())
}

/// Record the committer's signed outcome hash before `deadline`.
pub fn apply_commit(p: &mut PriorLock, outcome_hash: [u8; 32], sig: &[u8], height: u32) -> Res<()> {
    if height > p.post.deadline {
        return Err("prior commit deadline passed".into());
    }
    if p.outcome_hash.is_some() {
        return Err("prior outcome already committed".into());
    }
    if outcome_hash == [0u8; 32] {
        return Err("outcome_hash must be non-zero".into());
    }
    let msg = commit_message(&p.id, &outcome_hash);
    if !verify_sig(&p.post.owner_vk, &msg, sig) {
        return Err("invalid owner SLH-DSA signature on prior commit".into());
    }
    p.outcome_hash = Some(outcome_hash);
    p.committed_at = Some(height);
    Ok(())
}

fn compute_disconfirm_split(
    prior_id: &[u8; 32],
    stake: u64,
    disconfirmer_addr: Word8,
    miner_fee: u64,
    evidence_hash: [u8; 32],
) -> Res<PriorEffects> {
    let max_fee = (stake as u128 * MAX_PRIOR_FEE_BPS as u128 / 10_000) as u64;
    if miner_fee > max_fee {
        return Err(format!("miner_fee {miner_fee} exceeds 10% cap ({max_fee})"));
    }
    let slashable = stake - miner_fee;
    let bounty = slashable / 2;
    let burned = slashable - bounty;
    debug_assert_eq!(bounty + burned + miner_fee, stake);
    let payouts = if bounty > 0 {
        vec![Payout {
            a_pk: disconfirmer_addr,
            v: bounty,
            rho: payout_rho(prior_id, TAG_DISCONFIRM_BOUNTY),
        }]
    } else {
        vec![]
    };
    Ok(PriorEffects {
        payouts,
        burned,
        miner_fee,
        disconfirmed: Some((evidence_hash, disconfirmer_addr, bounty, burned)),
    })
}

/// Objective cryptographic disconfirmation (zero arbiters needed):
/// - `evidence_kind == 0`: SHA-256 preimage `payload_a` satisfies `sha256(payload_a) == falsifier_hash`
/// - `evidence_kind == 1`: signed equivocation (`payload_a != payload_b`, both signed by `owner_vk`
///   at the same `(prior.id, context_nonce)`).
#[allow(clippy::too_many_arguments)]
pub fn apply_disconfirm_objective(
    p: &PriorLock,
    evidence_kind: u8,
    context_nonce: u64,
    payload_a: &[u8; 32],
    sig_a: &[u8],
    payload_b: &[u8; 32],
    sig_b: &[u8],
    disconfirmer_addr: Word8,
    miner_fee: u64,
    height: u32,
) -> Res<PriorEffects> {
    if height > p.unlock_after() {
        return Err("prior challenge window has closed".into());
    }
    let evidence_hash = match evidence_kind {
        0 => {
            if p.post.falsifier_hash == [0u8; 32] {
                return Err("prior has no objective falsifier_hash".into());
            }
            if sha256(payload_a) != p.post.falsifier_hash {
                return Err("preimage does not match prior falsifier_hash".into());
            }
            sha256(&[b"nsPRIOR-PREIMG".as_slice(), payload_a].concat())
        }
        1 => {
            if payload_a == payload_b {
                return Err("equivocation requires two distinct payloads".into());
            }
            let msg_a = statement_message(&p.id, context_nonce, payload_a);
            let msg_b = statement_message(&p.id, context_nonce, payload_b);
            if !verify_sig(&p.post.owner_vk, &msg_a, sig_a) || !verify_sig(&p.post.owner_vk, &msg_b, sig_b) {
                return Err("invalid owner equivocation SLH-DSA signature".into());
            }
            sha256(&[b"nsPRIOR-EQUIV".as_slice(), &context_nonce.to_le_bytes(), payload_a, payload_b].concat())
        }
        _ => return Err("unknown objective disconfirmation kind".into()),
    };
    compute_disconfirm_split(&p.id, p.post.stake, disconfirmer_addr, miner_fee, evidence_hash)
}

/// Independent `M-of-N` SLH-DSA arbiter quorum disconfirmation before `deadline + challenge_window`.
pub fn apply_disconfirm_quorum(
    p: &PriorLock,
    evidence_hash: &[u8; 32],
    disconfirmer_addr: Word8,
    miner_fee: u64,
    sigs: &[(u8, Vec<u8>)],
    height: u32,
) -> Res<PriorEffects> {
    if height > p.unlock_after() {
        return Err("prior challenge window has closed".into());
    }
    if p.post.quorum_m == 0 || p.post.arbiter_vks.is_empty() {
        return Err("prior does not enable arbiter quorum disconfirmation".into());
    }
    if sigs.len() < p.post.quorum_m as usize {
        return Err("insufficient arbiter signatures for prior disconfirmation".into());
    }
    let msg = quorum_disconfirm_message(&p.id, evidence_hash, &disconfirmer_addr, miner_fee);
    let mut seen = vec![false; p.post.arbiter_vks.len()];
    let mut valid = 0usize;
    for (idx, sig) in sigs {
        let i = *idx as usize;
        if i >= p.post.arbiter_vks.len() {
            return Err("arbiter index out of range".into());
        }
        if seen[i] {
            return Err("duplicate arbiter signature".into());
        }
        if !verify_sig(&p.post.arbiter_vks[i], &msg, sig) {
            return Err("invalid arbiter SLH-DSA signature".into());
        }
        seen[i] = true;
        valid += 1;
    }
    if valid < p.post.quorum_m as usize {
        return Err("insufficient valid arbiter signatures".into());
    }
    compute_disconfirm_split(&p.id, p.post.stake, disconfirmer_addr, miner_fee, *evidence_hash)
}

/// Zero-surprise collateral release after `height > deadline + challenge_window`.
/// Permissionless with `miner_fee == 0`; non-zero `miner_fee <= 10%` requires `owner_vk` signature.
pub fn apply_release(p: &PriorLock, miner_fee: u64, owner_sig: &[u8], height: u32) -> Res<PriorEffects> {
    if height <= p.unlock_after() {
        return Err("prior challenge window is still open".into());
    }
    let max_fee = (p.post.stake as u128 * MAX_PRIOR_FEE_BPS as u128 / 10_000) as u64;
    if miner_fee > max_fee {
        return Err(format!("miner_fee {miner_fee} exceeds 10% cap ({max_fee})"));
    }
    if miner_fee > 0 {
        let msg = release_message(&p.id, miner_fee);
        if !verify_sig(&p.post.owner_vk, &msg, owner_sig) {
            return Err("non-zero release miner_fee requires owner SLH-DSA signature".into());
        }
    }
    let owner_payout = p.post.stake - miner_fee;
    Ok(PriorEffects {
        payouts: vec![Payout {
            a_pk: p.post.owner_addr,
            v: owner_payout,
            rho: payout_rho(&p.id, TAG_RELEASE_OWNER),
        }],
        burned: 0,
        miner_fee,
        disconfirmed: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;

    #[test]
    fn scgs_i3_blocks_self_arbitration_and_enforces_exact_50_50_surprise_burn() {
        let owner = JobKey::derive(&[11u8; 32]);
        let arb0 = JobKey::derive(&[12u8; 32]);
        let arb1 = JobKey::derive(&[13u8; 32]);
        let owner_vk: [u8; 32] = owner.vk().try_into().unwrap();
        let arb0_vk: [u8; 32] = arb0.vk().try_into().unwrap();
        let arb1_vk: [u8; 32] = arb1.vk().try_into().unwrap();

        // SCGS I-3: owner listed as arbiter MUST be rejected!
        let self_arb = PriorPost {
            owner_vk,
            owner_addr: [1; 8],
            spec_hash: sha256(b"uptime-sla-99.9"),
            falsifier_hash: [0u8; 32],
            arbiter_vks: vec![owner_vk, arb0_vk],
            quorum_m: 1,
            deadline: 100,
            challenge_window: 20,
            stake: 10_000_000,
        };
        assert!(check_post(&self_arb, 10).is_err());

        // Valid objective + 2-of-2 arbiter prior
        let secret_fail = [0x99u8; 32];
        let post = PriorPost {
            falsifier_hash: sha256(&secret_fail),
            arbiter_vks: vec![arb0_vk, arb1_vk],
            quorum_m: 2,
            ..self_arb
        };
        check_post(&post, 10).unwrap();
        let id = prior_id(&post, &[7; 8]);
        let mut pl = PriorLock { id, post, created_at: 10, outcome_hash: None, committed_at: None };

        // Owner commits outcome before deadline
        let oh = sha256(b"claimed-honest-output");
        apply_commit(&mut pl, oh, &owner.sign(&commit_message(&id, &oh)), 50).unwrap();
        assert_eq!(pl.outcome_hash, Some(oh));

        // Premature release before deadline + challenge_window (120) fails
        assert!(apply_release(&pl, 0, &[], 120).is_err());
        // Release at 121 succeeds with full stake returned
        let rel = apply_release(&pl, 0, &[], 121).unwrap();
        assert_eq!(rel.payouts[0].v, 10_000_000);
        assert_eq!(rel.burned, 0);

        // Objective preimage disconfirmation at height 115 -> 50% bounty, 50% permanently burned!
        let eff = apply_disconfirm_objective(
            &pl, 0, 0, &secret_fail, &[], &[0; 32], &[], [9; 8], 100_000, 115,
        )
        .unwrap();
        assert_eq!(eff.miner_fee, 100_000);
        assert_eq!(eff.payouts[0].v, 4_950_000);
        assert_eq!(eff.burned, 4_950_000);
        assert_eq!(eff.payouts[0].v + eff.burned + eff.miner_fee, 10_000_000);

        // Signed equivocation disconfirmation also works with zero arbiters!
        let pa = sha256(b"quote-A");
        let pb = sha256(b"quote-B");
        let sa = owner.sign(&statement_message(&id, 42, &pa));
        let sb = owner.sign(&statement_message(&id, 42, &pb));
        let eff_eq = apply_disconfirm_objective(
            &pl, 1, 42, &pa, &sa, &pb, &sb, [9; 8], 100_001, 115,
        )
        .unwrap();
        // Odd slashable (9_899_999): bounty = 4_949_999, burned = 4_950_000 (1-sat remainder burned!)
        assert_eq!(eff_eq.payouts[0].v, 4_949_999);
        assert_eq!(eff_eq.burned, 4_950_000);
        assert_eq!(eff_eq.payouts[0].v + eff_eq.burned + eff_eq.miner_fee, 10_000_000);
        assert!(eff_eq.burned >= eff_eq.payouts[0].v);

        // 2-of-2 independent arbiter quorum disconfirmation
        let ev = sha256(b"audit-failure");
        let qm = quorum_disconfirm_message(&id, &ev, &[8; 8], 50_000);
        let eff_q = apply_disconfirm_quorum(
            &pl, &ev, [8; 8], 50_000, &[(0, arb0.sign(&qm)), (1, arb1.sign(&qm))], 118,
        )
        .unwrap();
        assert_eq!(eff_q.payouts[0].v + eff_q.burned + eff_q.miner_fee, 10_000_000);
        assert_eq!(eff_q.burned, 4_975_000);
    }
}
