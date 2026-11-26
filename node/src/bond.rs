//! RFC-0024: Native L1 Universal Trust Bonds & Slashing-Backed Portable Reputation.
//!
//! Turns economic trust into a credibly neutral, pure-SHA-2 post-quantum L1 primitive:
//! - Any human, API, compute cluster, zkTLS market maker, or AI agent locks native shielded
//!   `LOVE` into a persistent, Merkle-provable `TrustBond` keyed by its FIPS 205
//!   `SLH-DSA-SHA2-128s` verifying key (`owner_vk`).
//! - **Anti-wash-trading standing:** `BondAttest` requires dual FIPS 205 signatures from the
//!   bonded provider AND an independent counterparty (`counterparty_vk != owner_vk`) over a
//!   settlement receipt digest (zkTLS receipt, PayWord close, or compute hash) and deducts a
//!   real non-refundable protocol fee from stake.
//! - **Tier-1 / Tier-2 Zero-Arbiter Cryptographic Slash (`BondSlashEquivocation`):** Anyone
//!   submitting two conflicting `SLH-DSA` commitments signed by `owner_vk` for the same
//!   `(bond, context_nonce)` instantly slashes `slash_amount`, mints a spendable shielded
//!   `LOVE` note to the victim, burns `slash_burn_bps` forever, and pays `miner_fee`.
//! - **Tier-3 Reputation-Staked Blind Jury Adjudication (`BondSlashQuorum`):** `quorum_m`-of-`N`
//!   distinct `arbiter_vks` resolve subjective disputes with instant victim payout + burn.
//! - **Timelocked Unbonding:** `BondUnbondRequest` starts an `unbond_delay` cooldown while the
//!   full collateral stays slashable; `BondUnbondComplete` releases remaining unslashed stake
//!   only after `height >= requested_at + unbond_delay`.
//! - **Exact Conservation:** Every slash satisfies `victim_payout + burn_amount + miner_fee ==
//!   slash_amount`, preserving the Lean 4 `SolvencyInvariant` (`pool + locked + burned = issued`).

use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, words_to_bytes, Word8};
use crate::job::{verify_sig, Payout, VK_LEN};
use crate::note::{Rho, MAX_NOTE_VALUE};

pub const MAX_ARBITERS: usize = 7;
pub const MIN_UNBOND_DELAY: u32 = 1;
pub const MAX_UNBOND_DELAY: u32 = 52_560;
pub const MIN_ATTEST_FEE: u64 = 1_000;

/// Creation parameters of a persistent L1 Trust Bond (funded by a shielded spend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondPost {
    /// Bonded entity's FIPS 205 `SLH-DSA-SHA2-128s` verifying key (32 bytes).
    pub owner_vk: [u8; 32],
    /// Shielded address receiving unbonded collateral after cooldown.
    pub owner_addr: Word8,
    /// Optional Tier-3 adjudication quorum verifying keys (0..=7 distinct 32-byte SLH-DSA VKs).
    pub arbiter_vks: Vec<[u8; 32]>,
    /// Required distinct arbiter signatures for `BondSlashQuorum` (0 disables quorum slash).
    pub quorum_m: u8,
    /// Cooldown in blocks between `BondUnbondRequest` and `BondUnbondComplete`.
    pub unbond_delay: u32,
    /// Fraction of net slashed collateral burned forever in basis points (`0..=10_000`);
    /// remainder (`10_000 - slash_burn_bps`) is paid directly to the victim as a shielded note.
    pub slash_burn_bps: u16,
    /// Active staked collateral in base units (initially locked on creation, mutable on top-up/slash/unbond).
    pub stake: u64,
    /// Domain / service descriptor hash (e.g., zkTLS ramp ID, API endpoint hash, compute pool ID).
    pub service_tag: [u8; 32],
}

impl BondPost {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.owner_vk)
            .word8(&self.owner_addr)
            .u8(self.arbiter_vks.len() as u8);
        for vk in &self.arbiter_vks {
            w.raw(vk);
        }
        w.u8(self.quorum_m)
            .u32(self.unbond_delay)
            .u16(self.slash_burn_bps)
            .u64(self.stake)
            .raw(&self.service_tag);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let owner_vk = r.arr()?;
        let owner_addr = r.word8()?;
        let n = r.u8()? as usize;
        if n > MAX_ARBITERS {
            return Err("too many bond arbiters".into());
        }
        let arbiter_vks = (0..n).map(|_| r.arr()).collect::<Res<Vec<_>>>()?;
        Ok(BondPost {
            owner_vk,
            owner_addr,
            arbiter_vks,
            quorum_m: r.u8()?,
            unbond_delay: r.u32()?,
            slash_burn_bps: r.u16()?,
            stake: r.u64()?,
            service_tag: r.arr()?,
        })
    }
}

/// Live canonical Trust Bond state stored in `State::bonds` and committed to `State::bonds_merkle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustBond {
    pub id: [u8; 32],
    pub post: BondPost,
    pub created_at: u32,
    pub settled_count: u64,
    pub settled_volume: u128,
    pub slash_count: u32,
    pub slashed_total: u128,
    pub unbond_requested_at: Option<u32>,
    pub unbond_amount: u64,
    pub action_nonce: u64,
}

impl TrustBond {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.created_at)
            .u64(self.settled_count)
            .raw(&self.settled_volume.to_le_bytes())
            .u32(self.slash_count)
            .raw(&self.slashed_total.to_le_bytes());
        match self.unbond_requested_at {
            Some(h) => {
                w.bool(true).u32(h);
            }
            None => {
                w.bool(false);
            }
        }
        w.u64(self.unbond_amount).u64(self.action_nonce);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let id = r.arr()?;
        let post = BondPost::decode(r)?;
        let created_at = r.u32()?;
        let settled_count = r.u64()?;
        let settled_volume = u128::from_le_bytes(r.arr()?);
        let slash_count = r.u32()?;
        let slashed_total = u128::from_le_bytes(r.arr()?);
        let unbond_requested_at = if r.bool()? { Some(r.u32()?) } else { None };
        let unbond_amount = r.u64()?;
        let action_nonce = r.u64()?;
        Ok(TrustBond {
            id,
            post,
            created_at,
            settled_count,
            settled_volume,
            slash_count,
            slashed_total,
            unbond_requested_at,
            unbond_amount,
            action_nonce,
        })
    }

    /// Canonical SHA-256 leaf value hash for `State::bonds_merkle` (`MerkleMap`).
    pub fn value_hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsBONDV");
        self.encode(&mut w);
        sha256(&w.0)
    }
}

/// Deterministic unique Trust Bond ID bound to terms and the funding spend's nullifier.
pub fn bond_id(post: &BondPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsBOND");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

/// Validate Trust Bond creation parameters before verifying the spend STARK proof.
pub fn check_post(post: &BondPost) -> Result<(), String> {
    if post.stake == 0 || post.stake > MAX_NOTE_VALUE {
        return Err("bond stake out of range".into());
    }
    if post.owner_vk == [0u8; 32] {
        return Err("bond owner_vk must be non-zero".into());
    }
    if post.arbiter_vks.len() > MAX_ARBITERS {
        return Err("too many bond arbiters".into());
    }
    for (i, vk) in post.arbiter_vks.iter().enumerate() {
        if *vk == [0u8; 32] || *vk == post.owner_vk {
            return Err("invalid arbiter key".into());
        }
        if post.arbiter_vks[..i].contains(vk) {
            return Err("duplicate arbiter key".into());
        }
    }
    if post.quorum_m as usize > post.arbiter_vks.len() {
        return Err("bond quorum exceeds arbiter count".into());
    }
    if post.unbond_delay < MIN_UNBOND_DELAY || post.unbond_delay > MAX_UNBOND_DELAY {
        return Err("bond unbond_delay out of range".into());
    }
    if post.slash_burn_bps > 10_000 {
        return Err("bond slash_burn_bps exceeds 10000".into());
    }
    Ok(())
}

/// Apply a shielded `BondTopUp` deposit to an existing bond.
pub fn apply_topup(bond: &mut TrustBond, amount: u64) -> Result<(), String> {
    if amount == 0 || amount > MAX_NOTE_VALUE {
        return Err("bond top-up amount out of range".into());
    }
    let next = bond.post.stake.checked_add(amount).ok_or("bond stake overflow")?;
    if next > MAX_NOTE_VALUE {
        return Err("bond stake exceeds MAX_NOTE_VALUE".into());
    }
    bond.post.stake = next;
    Ok(())
}

/// Domain-separated message for dual-signed honest settlement attestation (`BondAttest`).
pub fn attest_message(
    bond: &[u8; 32],
    nonce: u64,
    receipt_hash: &[u8; 32],
    settled_amount: u64,
    fee: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(12 + 32 + 8 + 32 + 8 + 8);
    buf.extend_from_slice(b"nsBONDATTEST");
    buf.extend_from_slice(bond);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(receipt_hash);
    buf.extend_from_slice(&settled_amount.to_le_bytes());
    buf.extend_from_slice(&fee.to_le_bytes());
    sha256(&buf)
}

/// Domain-separated commitment signed by a bonded service (`owner_vk`); signing two distinct
/// payloads for the same `(bond, context_nonce)` enables permissionless Tier-1/Tier-2 slashing.
pub fn commit_message(bond: &[u8; 32], context_nonce: u64, payload_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(12 + 32 + 8 + 32);
    buf.extend_from_slice(b"nsBONDCOMMIT");
    buf.extend_from_slice(bond);
    buf.extend_from_slice(&context_nonce.to_le_bytes());
    buf.extend_from_slice(payload_hash);
    sha256(&buf)
}

/// Domain-separated verdict signed by `quorum_m` distinct Tier-3 arbiters (`BondSlashQuorum`).
pub fn quorum_slash_message(
    bond: &[u8; 32],
    nonce: u64,
    dispute_hash: &[u8; 32],
    victim_addr: &Word8,
    slash_amount: u64,
    miner_fee: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(12 + 32 + 8 + 32 + 32 + 8 + 8);
    buf.extend_from_slice(b"nsBONDSLASHQ");
    buf.extend_from_slice(bond);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(dispute_hash);
    buf.extend_from_slice(&words_to_bytes(victim_addr));
    buf.extend_from_slice(&slash_amount.to_le_bytes());
    buf.extend_from_slice(&miner_fee.to_le_bytes());
    sha256(&buf)
}

/// Domain-separated message signed by `owner_vk` to initiate timelocked unbonding.
pub fn unbond_request_message(bond: &[u8; 32], nonce: u64, amount: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(12 + 32 + 8 + 8);
    buf.extend_from_slice(b"nsBONDUNBOND");
    buf.extend_from_slice(bond);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&amount.to_le_bytes());
    sha256(&buf)
}

fn bond_payout_rho(bond: &[u8; 32], nonce: u64, tag: u8) -> Rho {
    let mut buf = Vec::with_capacity(8 + 32 + 8 + 1);
    buf.extend_from_slice(b"nsBNDPAY");
    buf.extend_from_slice(bond);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.push(tag);
    let h = sha256(&buf);
    core::array::from_fn(|i| u32::from_be_bytes(h[4 * i..4 * i + 4].try_into().unwrap()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondEffect {
    pub payouts: Vec<Payout>,
    pub burned: u64,
    pub miner_fee: u64,
}

fn execute_slash(
    bond: &mut TrustBond,
    victim_addr: Word8,
    slash_amount: u64,
    miner_fee: u64,
    rho_tag: u8,
) -> Result<BondEffect, String> {
    if slash_amount == 0 || slash_amount > bond.post.stake {
        return Err("slash amount out of range".into());
    }
    if miner_fee > slash_amount {
        return Err("slash miner fee exceeds slash amount".into());
    }
    let net = slash_amount - miner_fee;
    let burn_amount = ((net as u128) * (bond.post.slash_burn_bps as u128) / 10_000u128) as u64;
    let victim_payout = net - burn_amount;
    debug_assert_eq!(victim_payout + burn_amount + miner_fee, slash_amount);

    let nonce = bond.action_nonce;
    bond.post.stake -= slash_amount;
    if bond.unbond_amount > bond.post.stake {
        bond.unbond_amount = bond.post.stake;
        if bond.unbond_amount == 0 {
            bond.unbond_requested_at = None;
        }
    }
    bond.slash_count = bond.slash_count.saturating_add(1);
    bond.slashed_total = bond.slashed_total.saturating_add(slash_amount as u128);
    bond.action_nonce = bond.action_nonce.checked_add(1).ok_or("bond nonce overflow")?;

    let mut payouts = Vec::new();
    if victim_payout > 0 {
        payouts.push(Payout {
            a_pk: victim_addr,
            v: victim_payout,
            rho: bond_payout_rho(&bond.id, nonce, rho_tag),
        });
    }
    Ok(BondEffect { payouts, burned: burn_amount, miner_fee })
}

/// Record a dual-signed completed settlement, deducting a non-refundable anti-wash-trading `fee`.
pub fn attest(
    bond: &mut TrustBond,
    receipt_hash: &[u8; 32],
    settled_amount: u64,
    fee: u64,
    owner_sig: &[u8],
    counterparty_vk: &[u8; 32],
    counterparty_sig: &[u8],
) -> Result<BondEffect, String> {
    if settled_amount == 0 {
        return Err("attested settlement amount must be > 0".into());
    }
    if fee < MIN_ATTEST_FEE || fee > bond.post.stake {
        return Err("attestation fee out of range".into());
    }
    if *counterparty_vk == [0u8; 32] || *counterparty_vk == bond.post.owner_vk {
        return Err("counterparty must be distinct from bond owner".into());
    }
    let msg = attest_message(&bond.id, bond.action_nonce, receipt_hash, settled_amount, fee);
    if !verify_sig(&bond.post.owner_vk, &msg, owner_sig) {
        return Err("invalid bond owner attestation signature".into());
    }
    if !verify_sig(counterparty_vk, &msg, counterparty_sig) {
        return Err("invalid counterparty attestation signature".into());
    }
    bond.post.stake -= fee;
    if bond.unbond_amount > bond.post.stake {
        bond.unbond_amount = bond.post.stake;
        if bond.unbond_amount == 0 {
            bond.unbond_requested_at = None;
        }
    }
    bond.settled_count = bond.settled_count.saturating_add(1);
    bond.settled_volume = bond.settled_volume.saturating_add(settled_amount as u128);
    bond.action_nonce = bond.action_nonce.checked_add(1).ok_or("bond nonce overflow")?;
    Ok(BondEffect { payouts: vec![], burned: 0, miner_fee: fee })
}

/// Tier-1 / Tier-2 permissionless cryptographic equivocation slash: proves `owner_vk` signed
/// two conflicting payload digests for the same `context_nonce`.
#[allow(clippy::too_many_arguments)]
pub fn slash_equivocation(
    bond: &mut TrustBond,
    context_nonce: u64,
    payload_a: &[u8; 32],
    sig_a: &[u8],
    payload_b: &[u8; 32],
    sig_b: &[u8],
    victim_addr: Word8,
    slash_amount: u64,
    miner_fee: u64,
) -> Result<BondEffect, String> {
    if payload_a == payload_b {
        return Err("equivocation payloads must differ".into());
    }
    let msg_a = commit_message(&bond.id, context_nonce, payload_a);
    let msg_b = commit_message(&bond.id, context_nonce, payload_b);
    if !verify_sig(&bond.post.owner_vk, &msg_a, sig_a)
        || !verify_sig(&bond.post.owner_vk, &msg_b, sig_b)
    {
        return Err("invalid equivocation proof signature".into());
    }
    execute_slash(bond, victim_addr, slash_amount, miner_fee, 0xE1)
}

/// Tier-3 blind reputation-staked jury adjudication slash (`quorum_m`-of-`N` distinct arbiters).
pub fn slash_quorum(
    bond: &mut TrustBond,
    dispute_hash: &[u8; 32],
    victim_addr: Word8,
    slash_amount: u64,
    miner_fee: u64,
    sigs: &[(u8, Vec<u8>)],
) -> Result<BondEffect, String> {
    if bond.post.quorum_m == 0 {
        return Err("quorum slashing disabled on this bond".into());
    }
    if sigs.len() != bond.post.quorum_m as usize {
        return Err("wrong number of quorum arbiter signatures".into());
    }
    let msg = quorum_slash_message(
        &bond.id,
        bond.action_nonce,
        dispute_hash,
        &victim_addr,
        slash_amount,
        miner_fee,
    );
    let mut prev_idx: Option<u8> = None;
    for (idx, sig) in sigs {
        if let Some(p) = prev_idx {
            if *idx <= p {
                return Err("arbiter indices must be strictly ascending and distinct".into());
            }
        }
        let vk = bond
            .post
            .arbiter_vks
            .get(*idx as usize)
            .ok_or("arbiter index out of range")?;
        if vk.len() != VK_LEN || !verify_sig(vk, &msg, sig) {
            return Err("invalid arbiter quorum signature".into());
        }
        prev_idx = Some(*idx);
    }
    execute_slash(bond, victim_addr, slash_amount, miner_fee, 0xE2)
}

/// Request timelocked unbonding (collateral remains fully slashable during `unbond_delay`).
pub fn request_unbond(
    bond: &mut TrustBond,
    amount: u64,
    sig: &[u8],
    height: u32,
) -> Result<(), String> {
    if amount == 0 || amount > bond.post.stake {
        return Err("unbond amount out of range".into());
    }
    if bond.unbond_requested_at.is_some() {
        return Err("unbond request already pending".into());
    }
    let msg = unbond_request_message(&bond.id, bond.action_nonce, amount);
    if !verify_sig(&bond.post.owner_vk, &msg, sig) {
        return Err("invalid bond owner unbond signature".into());
    }
    bond.unbond_requested_at = Some(height);
    bond.unbond_amount = amount;
    bond.action_nonce = bond.action_nonce.checked_add(1).ok_or("bond nonce overflow")?;
    Ok(())
}

/// Complete unbonding once `height >= requested_at + unbond_delay`.
pub fn complete_unbond(
    bond: &mut TrustBond,
    miner_fee: u64,
    height: u32,
) -> Result<BondEffect, String> {
    let req_h = bond.unbond_requested_at.ok_or("no pending unbond request")?;
    let ready_at = req_h.saturating_add(bond.post.unbond_delay);
    if height < ready_at {
        return Err("unbond delay has not elapsed".into());
    }
    let actual = bond.unbond_amount.min(bond.post.stake);
    if actual == 0 || miner_fee > actual {
        return Err("nothing left to unbond or miner fee exceeds amount".into());
    }
    let owner_payout = actual - miner_fee;
    let nonce = bond.action_nonce;
    bond.post.stake -= actual;
    bond.unbond_requested_at = None;
    bond.unbond_amount = 0;
    bond.action_nonce = bond.action_nonce.checked_add(1).ok_or("bond nonce overflow")?;

    let mut payouts = Vec::new();
    if owner_payout > 0 {
        payouts.push(Payout {
            a_pk: bond.post.owner_addr,
            v: owner_payout,
            rho: bond_payout_rho(&bond.id, nonce, 0x01),
        });
    }
    Ok(BondEffect { payouts, burned: 0, miner_fee })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;

    #[test]
    fn trust_bond_attest_equivocation_quorum_and_timelocked_unbond() {
        let owner_key = JobKey::derive(&[1u8; 32]);
        let client_key = JobKey::derive(&[2u8; 32]);
        let arb0 = JobKey::derive(&[3u8; 32]);
        let arb1 = JobKey::derive(&[4u8; 32]);
        let arb2 = JobKey::derive(&[5u8; 32]);

        let owner_vk: [u8; 32] = owner_key.vk().try_into().unwrap();
        let client_vk: [u8; 32] = client_key.vk().try_into().unwrap();
        let a0_vk: [u8; 32] = arb0.vk().try_into().unwrap();
        let a1_vk: [u8; 32] = arb1.vk().try_into().unwrap();
        let a2_vk: [u8; 32] = arb2.vk().try_into().unwrap();

        let post = BondPost {
            owner_vk,
            owner_addr: [10u32; 8],
            arbiter_vks: vec![a0_vk, a1_vk, a2_vk],
            quorum_m: 2,
            unbond_delay: 10,
            slash_burn_bps: 2_000, // 20% burned, 80% paid to victim
            stake: 10_000_000,
            service_tag: sha256(b"zktls-wise-ramp-v1"),
        };
        check_post(&post).unwrap();
        let id = bond_id(&post, &[99u32; 8]);
        let mut bond = TrustBond {
            id,
            post,
            created_at: 1,
            settled_count: 0,
            settled_volume: 0,
            slash_count: 0,
            slashed_total: 0,
            unbond_requested_at: None,
            unbond_amount: 0,
            action_nonce: 0,
        };

        // 1. Honest dual-signed attestation (anti-wash-trading fee deducted)
        let receipt = sha256(b"zktls-receipt-001");
        let amsg = attest_message(&id, 0, &receipt, 5_000_000, 10_000);
        let eff_a = attest(
            &mut bond,
            &receipt,
            5_000_000,
            10_000,
            &owner_key.sign(&amsg),
            &client_vk,
            &client_key.sign(&amsg),
        )
        .unwrap();
        assert_eq!(eff_a.miner_fee, 10_000);
        assert_eq!(bond.settled_count, 1);
        assert_eq!(bond.settled_volume, 5_000_000);
        assert_eq!(bond.post.stake, 9_990_000);

        // 2. Owner requests unbond of 5,000,000 at height 5 (unlocks at height 15)
        let umsg = unbond_request_message(&id, bond.action_nonce, 5_000_000);
        request_unbond(&mut bond, 5_000_000, &owner_key.sign(&umsg), 5).unwrap();
        assert!(complete_unbond(&mut bond, 1_000, 14).is_err(), "cannot exit before cooldown");

        // 3. During cooldown, owner equivocates on nonce 7 -> permissionless math slash!
        let pa = sha256(b"compute-result-honest");
        let pb = sha256(b"compute-result-forged");
        let sa = owner_key.sign(&commit_message(&id, 7, &pa));
        let sb = owner_key.sign(&commit_message(&id, 7, &pb));
        let victim: Word8 = [77u32; 8];
        let eff_eq =
            slash_equivocation(&mut bond, 7, &pa, &sa, &pb, &sb, victim, 2_010_000, 10_000).unwrap();
        assert_eq!(eff_eq.miner_fee, 10_000);
        assert_eq!(eff_eq.burned, 400_000); // 20% of 2,000,000
        assert_eq!(eff_eq.payouts[0].v, 1_600_000); // 80% of 2,000,000
        assert_eq!(bond.slash_count, 1);
        assert_eq!(bond.post.stake, 7_980_000);

        // 4. Tier-3 2-of-3 quorum slash
        let dispute = sha256(b"design-dispute-42");
        let qmsg = quorum_slash_message(&id, bond.action_nonce, &dispute, &victim, 1_010_000, 10_000);
        let eff_q = slash_quorum(
            &mut bond,
            &dispute,
            victim,
            1_010_000,
            10_000,
            &[(0, arb0.sign(&qmsg)), (2, arb2.sign(&qmsg))],
        )
        .unwrap();
        assert_eq!(eff_q.burned, 200_000);
        assert_eq!(eff_q.payouts[0].v, 800_000);
        assert_eq!(bond.slash_count, 2);
        assert_eq!(bond.post.stake, 6_970_000);

        // 5. After cooldown (height 15), unbond completes cleanly
        let eff_u = complete_unbond(&mut bond, 5_000, 15).unwrap();
        assert_eq!(eff_u.payouts[0].v, 4_995_000);
        assert_eq!(eff_u.miner_fee, 5_000);
        assert_eq!(bond.post.stake, 1_970_000);
    }
}
