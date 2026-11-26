//! RFC-0027: Native L1 Mission Launchpads & Decentralized AI Agent Swarm Coordination Pools.
//!
//! Makes Newsatoshi L1 the easiest, most secure substrate for launching decentralized
//! agent-coordination swarms & verified-work launchpads (e.g., open-science Lean 4 proof
//! swarms, red-team bounty fleets, autonomous research DAOs) in **one shielded transaction**:
//!
//! - **Zero-Rugpull Dual Treasury (`bounty_pool` + `curve_reserve`):**
//!   - `bounty_pool` can ONLY pay out to verified proof/task claims (`Action::MissionClaimTask`)
//!     and can NEVER be withdrawn by the creator.
//!   - `curve_reserve` backs deterministic bonding-curve shares (`Deposit::MissionFund` /
//!     `Action::MissionCurveRedeem`), automatically routing `curve_fee_bps` on EVERY buy AND
//!     sell directly into `bounty_pool` so market activity continuously funds verified work.
//! - **Automatic Verifiable Split (e.g., 80% Outside Contributor / 20% Public Goods):**
//!   - When an agent's proof/lemma passes the `verifier_quorum_m`-of-`N` FIPS 205 checker desk,
//!     L1 atomically mints shielded `LOVE` notes for both the winning contributor AND the
//!     designated `public_goods_addr` (e.g., Lean FRO / protocol backing vault) with exact
//!     conservation: `contributor_payout + public_goods_payout + miner_fee == reward`.
//! - **Native Anti-Sybil Trust Bond Gate:** Optional `min_worker_bond` enforces that claiming
//!   agents hold an active, unslashed `RFC-0024` Trust Bond on L1.

use crate::bond::TrustBond;
use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, words_to_bytes, Word8};
use crate::job::{verify_sig, Payout, VK_LEN};
use crate::note::{Rho, MAX_NOTE_VALUE};
use std::collections::BTreeMap;

pub const MAX_VERIFIERS: usize = 7;
pub const MAX_MISSION_TASKS: usize = 10_000;
pub const MAX_CURVE_FEE_BPS: u16 = 1_000; // max 10% trade fee into bounty pool
pub const INITIAL_SHARE_SCALE: u64 = 1_000; // initial shares per 1,000 base units on empty curve

/// Creation terms for a permissionless L1 Mission Launchpad & Agent Swarm Pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionPost {
    /// Optional orchestrator FIPS 205 VK (`[0; 32]` = permissionless task posting).
    pub orchestrator_vk: [u8; 32],
    /// Checker-desk / formal-verifier FIPS 205 verifying keys (`1..=7` distinct keys).
    pub verifier_vks: Vec<[u8; 32]>,
    /// Required distinct verifier signatures to approve a task proof (`1..=verifier_vks.len()`).
    pub verifier_quorum_m: u8,
    /// Shielded address receiving `public_goods_bps` of every completed bounty (e.g. Lean FRO).
    pub public_goods_addr: Word8,
    /// Share of each completed net bounty routed to `public_goods_addr` (`0..=10_000`, e.g. 2000 = 20%).
    pub public_goods_bps: u16,
    /// Fee on every bonding-curve buy/sell routed automatically into `bounty_pool` (`0..=1000` bps).
    pub curve_fee_bps: u16,
    /// Initial shielded `LOVE` seeded straight into `bounty_pool` (must be >= 1).
    pub initial_funding: u64,
    /// Minimum active, unslashed `RFC-0024` Trust Bond stake required to claim tasks (`0` = open).
    pub min_worker_bond: u64,
    /// Canonical SHA-256 digest of mission charter / theorem statement / benchmark spec.
    pub mission_hash: [u8; 32],
}

impl MissionPost {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.orchestrator_vk)
            .u8(self.verifier_vks.len() as u8);
        for vk in &self.verifier_vks {
            w.raw(vk);
        }
        w.u8(self.verifier_quorum_m)
            .word8(&self.public_goods_addr)
            .u16(self.public_goods_bps)
            .u16(self.curve_fee_bps)
            .u64(self.initial_funding)
            .u64(self.min_worker_bond)
            .raw(&self.mission_hash);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let orchestrator_vk = r.arr()?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_VERIFIERS {
            return Err("mission verifier count out of range".into());
        }
        let verifier_vks = (0..n).map(|_| r.arr()).collect::<Res<Vec<_>>>()?;
        Ok(MissionPost {
            orchestrator_vk,
            verifier_vks,
            verifier_quorum_m: r.u8()?,
            public_goods_addr: r.word8()?,
            public_goods_bps: r.u16()?,
            curve_fee_bps: r.u16()?,
            initial_funding: r.u64()?,
            min_worker_bond: r.u64()?,
            mission_hash: r.arr()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    Open,
    Completed {
        contributor_addr: Word8,
        proof_hash: [u8; 32],
        height: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionTask {
    pub task_id: u32,
    pub spec_hash: [u8; 32],
    pub reward: u64,
    pub status: TaskStatus,
}

impl MissionTask {
    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.task_id).raw(&self.spec_hash).u64(self.reward);
        match &self.status {
            TaskStatus::Open => {
                w.u8(0);
            }
            TaskStatus::Completed { contributor_addr, proof_hash, height } => {
                w.u8(1).word8(contributor_addr).raw(proof_hash).u32(*height);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let task_id = r.u32()?;
        let spec_hash = r.arr()?;
        let reward = r.u64()?;
        let status = match r.u8()? {
            0 => TaskStatus::Open,
            1 => TaskStatus::Completed {
                contributor_addr: r.word8()?,
                proof_hash: r.arr()?,
                height: r.u32()?,
            },
            _ => return Err("bad mission task status".into()),
        };
        Ok(MissionTask { task_id, spec_hash, reward, status })
    }
}

/// Live canonical Mission Launchpad & Agent Swarm state in `State::missions` & `missions_merkle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionPool {
    pub id: [u8; 32],
    pub post: MissionPost,
    pub created_at: u32,
    /// Locked `LOVE` reserved exclusively for verified task bounties (never founder-withdrawable).
    pub bounty_pool: u64,
    /// Locked `LOVE` backing launchpad bonding-curve shares.
    pub curve_reserve: u64,
    /// Total outstanding bonding-curve shares.
    pub total_shares: u64,
    /// Quantum-safe share balances keyed by holder's 32-byte FIPS 205 `SLH-DSA` verifying key.
    pub shares_by_holder: BTreeMap<[u8; 32], u64>,
    pub tasks: BTreeMap<u32, MissionTask>,
    pub completed_tasks: u64,
    pub total_bounties_paid: u128,
    pub action_nonce: u64,
}

impl MissionPool {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.created_at)
            .u64(self.bounty_pool)
            .u64(self.curve_reserve)
            .u64(self.total_shares)
            .u32(self.shares_by_holder.len() as u32);
        for (vk, sh) in &self.shares_by_holder {
            w.raw(vk).u64(*sh);
        }
        w.u32(self.tasks.len() as u32);
        for t in self.tasks.values() {
            t.encode(w);
        }
        w.u64(self.completed_tasks)
            .raw(&self.total_bounties_paid.to_le_bytes())
            .u64(self.action_nonce);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let id = r.arr()?;
        let post = MissionPost::decode(r)?;
        let created_at = r.u32()?;
        let bounty_pool = r.u64()?;
        let curve_reserve = r.u64()?;
        let total_shares = r.u64()?;
        let nh = r.u32()? as usize;
        if nh > 1_000_000 {
            return Err("too many mission share holders".into());
        }
        let mut shares_by_holder = BTreeMap::new();
        for _ in 0..nh {
            shares_by_holder.insert(r.arr()?, r.u64()?);
        }
        let nt = r.u32()? as usize;
        if nt > MAX_MISSION_TASKS {
            return Err("too many mission tasks".into());
        }
        let mut tasks = BTreeMap::new();
        for _ in 0..nt {
            let t = MissionTask::decode(r)?;
            tasks.insert(t.task_id, t);
        }
        let completed_tasks = r.u64()?;
        let total_bounties_paid = u128::from_le_bytes(r.arr()?);
        let action_nonce = r.u64()?;
        Ok(MissionPool {
            id,
            post,
            created_at,
            bounty_pool,
            curve_reserve,
            total_shares,
            shares_by_holder,
            tasks,
            completed_tasks,
            total_bounties_paid,
            action_nonce,
        })
    }

    /// Canonical SHA-256 leaf hash for `State::missions_merkle`.
    pub fn value_hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsMISSV");
        self.encode(&mut w);
        sha256(&w.0)
    }

    /// Total shielded `LOVE` locked by this mission (`bounty_pool + curve_reserve`).
    pub fn total_locked(&self) -> u128 {
        self.bounty_pool as u128 + self.curve_reserve as u128
    }

    /// Total reward already earmarked for currently open tasks.
    pub fn earmarked_bounties(&self) -> u128 {
        self.tasks
            .values()
            .filter(|t| matches!(t.status, TaskStatus::Open))
            .map(|t| t.reward as u128)
            .sum()
    }
}

pub fn mission_id(post: &MissionPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsMISS");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

pub fn check_post(post: &MissionPost) -> Result<(), String> {
    if post.initial_funding == 0 || post.initial_funding > MAX_NOTE_VALUE {
        return Err("mission initial_funding out of range".into());
    }
    if post.verifier_vks.is_empty() || post.verifier_vks.len() > MAX_VERIFIERS {
        return Err("mission verifier count out of range".into());
    }
    for (i, vk) in post.verifier_vks.iter().enumerate() {
        if *vk == [0u8; 32] {
            return Err("mission verifier key must be non-zero".into());
        }
        if post.verifier_vks[..i].contains(vk) {
            return Err("duplicate mission verifier key".into());
        }
    }
    if post.verifier_quorum_m == 0 || post.verifier_quorum_m as usize > post.verifier_vks.len() {
        return Err("mission verifier quorum out of range".into());
    }
    if post.public_goods_bps > 10_000 {
        return Err("mission public_goods_bps exceeds 10000".into());
    }
    if post.curve_fee_bps > MAX_CURVE_FEE_BPS {
        return Err("mission curve_fee_bps exceeds 1000 (10%)".into());
    }
    Ok(())
}

/// Deterministic integer square-root bonding-curve shares minted for `net_deposit` into `curve_reserve`:
/// Uses quadratic reserve invariant `R = k * S^2` -> `S_new = floor(sqrt(R_new * SCALE))`
/// (monotonic rising marginal price, exact integer arithmetic, zero float non-determinism!).
fn isqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// Quote deterministic shares minted for a bonding-curve deposit `amount`.
pub fn quote_curve_buy(
    curve_reserve: u64,
    total_shares: u64,
    curve_fee_bps: u16,
    amount: u64,
) -> Result<(u64, u64, u64), String> {
    if amount == 0 || amount > MAX_NOTE_VALUE {
        return Err("mission fund amount out of range".into());
    }
    let fee_to_bounty = ((amount as u128) * (curve_fee_bps as u128) / 10_000u128) as u64;
    let net_to_curve = amount - fee_to_bounty;
    if net_to_curve == 0 {
        return Err("net bonding-curve deposit must be > 0".into());
    }
    let new_reserve = curve_reserve
        .checked_add(net_to_curve)
        .ok_or("curve reserve overflow")?;
    if new_reserve > MAX_NOTE_VALUE {
        return Err("curve reserve exceeds MAX_NOTE_VALUE".into());
    }
    let target_shares = isqrt_u128((new_reserve as u128) * (INITIAL_SHARE_SCALE as u128)) as u64;
    let minted = target_shares.saturating_sub(total_shares).max(1);
    Ok((fee_to_bounty, net_to_curve, minted))
}

/// Apply `Deposit::MissionFund` (either direct patron bounty funding OR bonding-curve buy).
pub fn apply_fund(
    mission: &mut MissionPool,
    holder_vk: [u8; 32],
    amount: u64,
    direct_to_bounty: bool,
) -> Result<(), String> {
    if amount == 0 || amount > MAX_NOTE_VALUE {
        return Err("mission fund amount out of range".into());
    }
    if direct_to_bounty {
        let next = mission
            .bounty_pool
            .checked_add(amount)
            .ok_or("bounty pool overflow")?;
        if next > MAX_NOTE_VALUE {
            return Err("bounty pool exceeds MAX_NOTE_VALUE".into());
        }
        mission.bounty_pool = next;
        return Ok(());
    }
    if holder_vk == [0u8; 32] {
        return Err("bonding-curve holder_vk must be non-zero".into());
    }
    let (fee_to_bounty, net_to_curve, minted) = quote_curve_buy(
        mission.curve_reserve,
        mission.total_shares,
        mission.post.curve_fee_bps,
        amount,
    )?;
    let next_bounty = mission
        .bounty_pool
        .checked_add(fee_to_bounty)
        .ok_or("bounty pool overflow")?;
    let next_reserve = mission
        .curve_reserve
        .checked_add(net_to_curve)
        .ok_or("curve reserve overflow")?;
    let next_shares = mission
        .total_shares
        .checked_add(minted)
        .ok_or("total shares overflow")?;
    if next_bounty > MAX_NOTE_VALUE || next_reserve > MAX_NOTE_VALUE {
        return Err("mission pool exceeds MAX_NOTE_VALUE".into());
    }
    mission.bounty_pool = next_bounty;
    mission.curve_reserve = next_reserve;
    mission.total_shares = next_shares;
    *mission.shares_by_holder.entry(holder_vk).or_insert(0) += minted;
    Ok(())
}

pub fn post_task_message(mission: &[u8; 32], task_id: u32, spec_hash: &[u8; 32], reward: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(10 + 32 + 4 + 32 + 8);
    buf.extend_from_slice(b"nsMISSTASK");
    buf.extend_from_slice(mission);
    buf.extend_from_slice(&task_id.to_le_bytes());
    buf.extend_from_slice(spec_hash);
    buf.extend_from_slice(&reward.to_le_bytes());
    sha256(&buf)
}

pub fn claim_task_message(
    mission: &[u8; 32],
    task_id: u32,
    spec_hash: &[u8; 32],
    proof_hash: &[u8; 32],
    contributor_addr: &Word8,
    miner_fee: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(11 + 32 + 4 + 32 + 32 + 32 + 8);
    buf.extend_from_slice(b"nsMISSCLAIM");
    buf.extend_from_slice(mission);
    buf.extend_from_slice(&task_id.to_le_bytes());
    buf.extend_from_slice(spec_hash);
    buf.extend_from_slice(proof_hash);
    buf.extend_from_slice(&words_to_bytes(contributor_addr));
    buf.extend_from_slice(&miner_fee.to_le_bytes());
    sha256(&buf)
}

pub fn redeem_message(
    mission: &[u8; 32],
    nonce: u64,
    shares: u64,
    recipient_addr: &Word8,
    miner_fee: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(10 + 32 + 8 + 8 + 32 + 8);
    buf.extend_from_slice(b"nsMISSREDM");
    buf.extend_from_slice(mission);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&shares.to_le_bytes());
    buf.extend_from_slice(&words_to_bytes(recipient_addr));
    buf.extend_from_slice(&miner_fee.to_le_bytes());
    sha256(&buf)
}

fn mission_payout_rho(mission: &[u8; 32], nonce: u64, tag: u8) -> Rho {
    let mut buf = Vec::with_capacity(8 + 32 + 8 + 1);
    buf.extend_from_slice(b"nsMSNPAY");
    buf.extend_from_slice(mission);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.push(tag);
    let h = sha256(&buf);
    core::array::from_fn(|i| u32::from_be_bytes(h[4 * i..4 * i + 4].try_into().unwrap()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionEffect {
    pub payouts: Vec<Payout>,
    pub miner_fee: u64,
}

/// Register a new verifiable task/lemma backed by `mission.bounty_pool`.
pub fn apply_post_task(
    mission: &mut MissionPool,
    task_id: u32,
    spec_hash: [u8; 32],
    reward: u64,
    sig: &[u8],
) -> Result<(), String> {
    if reward == 0 || reward > MAX_NOTE_VALUE {
        return Err("mission task reward out of range".into());
    }
    if mission.tasks.len() >= MAX_MISSION_TASKS {
        return Err("mission task limit reached".into());
    }
    if mission.tasks.contains_key(&task_id) {
        return Err("duplicate mission task_id".into());
    }
    if mission.earmarked_bounties() + reward as u128 > mission.bounty_pool as u128 {
        return Err("mission bounty_pool insufficient to back new task".into());
    }
    if mission.post.orchestrator_vk != [0u8; 32] {
        let msg = post_task_message(&mission.id, task_id, &spec_hash, reward);
        if !verify_sig(&mission.post.orchestrator_vk, &msg, sig) {
            return Err("invalid mission orchestrator signature".into());
        }
    }
    mission.tasks.insert(
        task_id,
        MissionTask { task_id, spec_hash, reward, status: TaskStatus::Open },
    );
    Ok(())
}

/// Claim a completed task/lemma once verified by `verifier_quorum_m` distinct FIPS 205 checkers.
#[allow(clippy::too_many_arguments)]
pub fn apply_claim_task(
    mission: &mut MissionPool,
    task_id: u32,
    proof_hash: [u8; 32],
    contributor_addr: Word8,
    contributor_bond: Option<&TrustBond>,
    miner_fee: u64,
    verifier_sigs: &[(u8, Vec<u8>)],
    height: u32,
) -> Result<MissionEffect, String> {
    let task = mission.tasks.get(&task_id).ok_or("unknown mission task")?;
    if !matches!(task.status, TaskStatus::Open) {
        return Err("mission task already completed".into());
    }
    let reward = task.reward;
    let spec_hash = task.spec_hash;
    if miner_fee > reward {
        return Err("claim miner fee exceeds task reward".into());
    }
    if reward > mission.bounty_pool {
        return Err("mission bounty_pool underflow".into());
    }
    // Optional anti-Sybil RFC-0024 Trust Bond gate!
    if mission.post.min_worker_bond > 0 {
        let b = contributor_bond.ok_or("mission requires an active RFC-0024 Trust Bond")?;
        if b.post.stake < mission.post.min_worker_bond {
            return Err("contributor Trust Bond stake below mission min_worker_bond".into());
        }
        if b.slash_count > 0 {
            return Err("slashed Trust Bond cannot claim mission bounties".into());
        }
    }
    if verifier_sigs.len() != mission.post.verifier_quorum_m as usize {
        return Err("wrong number of verifier quorum signatures".into());
    }
    let msg = claim_task_message(
        &mission.id,
        task_id,
        &spec_hash,
        &proof_hash,
        &contributor_addr,
        miner_fee,
    );
    let mut prev_idx: Option<u8> = None;
    for (idx, sig) in verifier_sigs {
        if let Some(p) = prev_idx {
            if *idx <= p {
                return Err("verifier indices must be strictly ascending and distinct".into());
            }
        }
        let vk = mission
            .post
            .verifier_vks
            .get(*idx as usize)
            .ok_or("verifier index out of range")?;
        if vk.len() != VK_LEN || !verify_sig(vk, &msg, sig) {
            return Err("invalid mission verifier quorum signature".into());
        }
        prev_idx = Some(*idx);
    }

    // Exact conservation split: contributor_payout + public_goods_payout + miner_fee == reward!
    let net = reward - miner_fee;
    let public_goods_payout =
        ((net as u128) * (mission.post.public_goods_bps as u128) / 10_000u128) as u64;
    let contributor_payout = net - public_goods_payout;
    debug_assert_eq!(contributor_payout + public_goods_payout + miner_fee, reward);

    let nonce = mission.action_nonce;
    mission.bounty_pool -= reward;
    mission.completed_tasks = mission.completed_tasks.saturating_add(1);
    mission.total_bounties_paid = mission.total_bounties_paid.saturating_add(reward as u128);
    mission.action_nonce = mission.action_nonce.checked_add(1).ok_or("mission nonce overflow")?;
    if let Some(t) = mission.tasks.get_mut(&task_id) {
        t.status = TaskStatus::Completed { contributor_addr, proof_hash, height };
    }

    let mut payouts = Vec::new();
    if contributor_payout > 0 {
        payouts.push(Payout {
            a_pk: contributor_addr,
            v: contributor_payout,
            rho: mission_payout_rho(&mission.id, nonce, 0x01),
        });
    }
    if public_goods_payout > 0 {
        payouts.push(Payout {
            a_pk: mission.post.public_goods_addr,
            v: public_goods_payout,
            rho: mission_payout_rho(&mission.id, nonce, 0x02),
        });
    }
    Ok(MissionEffect { payouts, miner_fee })
}

/// Redeem launchpad bonding-curve shares back to shielded `LOVE`, automatically routing
/// `curve_fee_bps` of the redemption directly into `bounty_pool` to fund the swarm!
pub fn apply_curve_redeem(
    mission: &mut MissionPool,
    holder_vk: [u8; 32],
    shares: u64,
    recipient_addr: Word8,
    miner_fee: u64,
    sig: &[u8],
) -> Result<MissionEffect, String> {
    if shares == 0 || mission.total_shares == 0 {
        return Err("redeem shares must be > 0".into());
    }
    let bal = mission.shares_by_holder.get(&holder_vk).copied().unwrap_or(0);
    if shares > bal || shares > mission.total_shares {
        return Err("insufficient bonding-curve share balance".into());
    }
    let msg = redeem_message(&mission.id, mission.action_nonce, shares, &recipient_addr, miner_fee);
    if !verify_sig(&holder_vk, &msg, sig) {
        return Err("invalid share holder signature".into());
    }
    // Proportional deterministic reserve exit; fee flows strictly into `bounty_pool`!
    let gross = ((mission.curve_reserve as u128) * (shares as u128) / (mission.total_shares as u128)) as u64;
    let fee_to_bounty = ((gross as u128) * (mission.post.curve_fee_bps as u128) / 10_000u128) as u64;
    let after_bounty_fee = gross - fee_to_bounty;
    if miner_fee > after_bounty_fee {
        return Err("redeem miner fee exceeds payout".into());
    }
    let user_payout = after_bounty_fee - miner_fee;
    debug_assert_eq!(fee_to_bounty + user_payout + miner_fee, gross);

    let nonce = mission.action_nonce;
    mission.curve_reserve -= gross;
    mission.bounty_pool = mission
        .bounty_pool
        .checked_add(fee_to_bounty)
        .ok_or("bounty pool overflow on redeem")?;
    mission.total_shares -= shares;
    let rem = bal - shares;
    if rem == 0 {
        mission.shares_by_holder.remove(&holder_vk);
    } else {
        mission.shares_by_holder.insert(holder_vk, rem);
    }
    mission.action_nonce = mission.action_nonce.checked_add(1).ok_or("mission nonce overflow")?;

    let mut payouts = Vec::new();
    if user_payout > 0 {
        payouts.push(Payout {
            a_pk: recipient_addr,
            v: user_payout,
            rho: mission_payout_rho(&mission.id, nonce, 0x03),
        });
    }
    Ok(MissionEffect { payouts, miner_fee })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;

    #[test]
    fn pequalnp_style_mission_launchpad_routes_curve_fees_to_verified_80_20_bounties() {
        let orch = JobKey::derive(&[1u8; 32]);
        let v0 = JobKey::derive(&[2u8; 32]);
        let v1 = JobKey::derive(&[3u8; 32]);
        let trader = JobKey::derive(&[4u8; 32]);
        let pub_goods_addr: Word8 = [55u32; 8]; // e.g., Lean FRO
        let agent_addr: Word8 = [88u32; 8];

        let post = MissionPost {
            orchestrator_vk: orch.vk().try_into().unwrap(),
            verifier_vks: vec![v0.vk().try_into().unwrap(), v1.vk().try_into().unwrap()],
            verifier_quorum_m: 2,
            public_goods_addr: pub_goods_addr,
            public_goods_bps: 2_000, // 20% Lean FRO / 80% outside contributor
            curve_fee_bps: 500,      // 5% of every launchpad buy/sell funds the AI swarm!
            initial_funding: 1_000_000,
            min_worker_bond: 0,
            mission_hash: sha256(b"pequalnp-lean4-swarm-charter"),
        };
        check_post(&post).unwrap();
        let mid = mission_id(&post, &[9u32; 8]);
        let mut pool = MissionPool {
            id: mid,
            post,
            created_at: 1,
            bounty_pool: 1_000_000,
            curve_reserve: 0,
            total_shares: 0,
            shares_by_holder: BTreeMap::new(),
            tasks: BTreeMap::new(),
            completed_tasks: 0,
            total_bounties_paid: 0,
            action_nonce: 0,
        };

        // 1. Trader buys 10,000,000 into bonding curve -> 500,000 fee flows straight into bounty_pool!
        let trader_vk: [u8; 32] = trader.vk().try_into().unwrap();
        apply_fund(&mut pool, trader_vk, 10_000_000, false).unwrap();
        assert_eq!(pool.bounty_pool, 1_500_000);
        assert_eq!(pool.curve_reserve, 9_500_000);
        let sh = pool.shares_by_holder[&trader_vk];
        assert!(sh > 0);

        // 2. Orchestrator posts Lemma #1 for 1,010,000 reward
        let spec = sha256(b"lemma-01-natural-proof-barrier.lean");
        let tmsg = post_task_message(&mid, 1, &spec, 1_010_000);
        apply_post_task(&mut pool, 1, spec, 1_010_000, &orch.sign(&tmsg)).unwrap();

        // 3. External agent solves Lemma #1; 2-of-2 Lean checker desk signs -> 80/20 atomic shielded split!
        let proof = sha256(b"lean4-zero-sorry-build-digest-001");
        let cmsg = claim_task_message(&mid, 1, &spec, &proof, &agent_addr, 10_000);
        let eff = apply_claim_task(
            &mut pool,
            1,
            proof,
            agent_addr,
            None,
            10_000,
            &[(0, v0.sign(&cmsg)), (1, v1.sign(&cmsg))],
            10,
        )
        .unwrap();
        assert_eq!(eff.miner_fee, 10_000);
        assert_eq!(eff.payouts[0].a_pk, agent_addr);
        assert_eq!(eff.payouts[0].v, 800_000); // 80% outside contributor
        assert_eq!(eff.payouts[1].a_pk, pub_goods_addr);
        assert_eq!(eff.payouts[1].v, 200_000); // 20% Lean FRO / public goods
        assert_eq!(pool.bounty_pool, 490_000);

        // 4. Trader redeems half their shares -> 5% exit fee AGAIN flows straight into bounty_pool!
        let half = sh / 2;
        let rmsg = redeem_message(&mid, pool.action_nonce, half, &agent_addr, 5_000);
        let reff = apply_curve_redeem(&mut pool, trader_vk, half, agent_addr, 5_000, &trader.sign(&rmsg)).unwrap();
        assert!(pool.bounty_pool > 490_000, "sell fee must grow verified-work bounty pool");
        assert!(reff.payouts[0].v > 0);
    }
}
