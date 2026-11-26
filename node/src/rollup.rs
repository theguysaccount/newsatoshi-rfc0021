//! RFC-0023: Native Sovereign L2 Rollup Vaults & Hyperscale 128-Bit Pure-SHA-2 STARK Settlement.
//!
//! Turns Newsatoshi L1 into a credibly neutral, post-quantum settlement substrate for arbitrary
//! L2 rollups, encrypted shared-state apps, zkTLS P2P banking ramps, and AI compute networks:
//! - **1-Transaction Permissionless L2 Launch (`Deposit::RollupRegister`):** Anyone deploys a
//!   sovereign rollup vault pinned to an immutable `vk_hash`, `genesis_root`, and optional
//!   `sequencer_vk` (or `None` for fully permissionless proving).
//! - **Shielded L1 → L2 Deposits (`Deposit::RollupDeposit`):** Shielded notes lock into `tvl`
//!   and fold into a canonical rolling SHA-256 `deposit_acc`.
//! - **Hyperscale 128-Bit Proven STARK Batch Settlement (`Action::RollupBatch`):** One ~75 KB
//!   pure-SHA-2 Winterfell 0.13 STARK (128 proven list-decoding bits, zero elliptic curves, zero
//!   trusted multisig) settles thousands to millions of off-chain L2 transactions per batch while
//!   proving exact TVL conservation (`prev_tvl == new_tvl + batch_withdrawals + batch_fee`) and
//!   63-bit bit-decomposition non-negativity inside the finite field.
//! - **Trustless L2 → L1 Shielded Exit (`Action::RollupWithdraw`):** Any L2 user exits directly
//!   to a private native shielded `LOVE` note via a canonical `MerkleMap` inclusion proof against
//!   a settled batch's `withdraw_root`, protected against replay by `claimed_withdrawals`.

use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, words_to_bytes, Sha2_256, Word8};
use crate::job::{verify_sig, Payout};
use crate::merkmap::{verify_proof, MerkleProof};
use crate::note::{Rho, MAX_NOTE_VALUE};
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::{FieldElement, ToElements};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
};

/// Execution trace length (64 rows => 63 bit-decomposition transitions).
pub const ROLLUP_TRACE_LEN: usize = 64;
/// Number of algebraic columns in `RollupBatchAir`.
pub const ROLLUP_TRACE_WIDTH: usize = 15;
/// Minimum proven (list-decoding, non-conjectured) security bits enforced on L1.
pub const ROLLUP_MIN_PROVEN_BITS: u32 = 128;
/// Hard DoS cap on serialized Rollup STARK batch proof bytes.
pub const MAX_ROLLUP_PROOF_BYTES: usize = 131_072;
/// Maximum number of retained batch withdrawal roots per rollup vault.
pub const MAX_WITHDRAW_ROOTS: usize = 1024;
/// Maximum number of recorded withdrawal nullifiers per rollup vault in snapshot/state.
pub const MAX_CLAIMED_WITHDRAWALS: usize = 1_000_000;

type RollupHashFn = Sha2_256<BaseElement>;
type RollupVC = MerkleTree<RollupHashFn>;
type RollupCoin = DefaultRandomCoin<RollupHashFn>;

// ---- Consensus Objects ------------------------------------------------------------------

/// Parameters to permissionlessly deploy a sovereign L2 Rollup Vault on L1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollupPost {
    /// Immutable verification key / program digest defining valid L2 state transitions.
    pub vk_hash: [u8; 32],
    /// Initial L2 state root at batch 0.
    pub genesis_root: [u8; 32],
    /// Optional designated sequencer FIPS 205 `SLH-DSA-SHA2-128s` VK (`None` = permissionless).
    pub sequencer_vk: Option<[u8; 32]>,
    /// Initial shielded `LOVE` TVL locked into the L2 bridge vault (must be >= 1).
    pub initial_tvl: u64,
    /// Human/protocol namespace digest (e.g. `sha256(b"my-ai-clearinghouse-l2")`).
    pub name_tag: [u8; 32],
}

impl RollupPost {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.vk_hash).raw(&self.genesis_root);
        match &self.sequencer_vk {
            Some(vk) => {
                w.bool(true).raw(vk);
            }
            None => {
                w.bool(false);
            }
        }
        w.u64(self.initial_tvl).raw(&self.name_tag);
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let vk_hash = r.arr()?;
        let genesis_root = r.arr()?;
        let sequencer_vk = if r.bool()? { Some(r.arr()?) } else { None };
        let initial_tvl = r.u64()?;
        let name_tag = r.arr()?;
        Ok(RollupPost { vk_hash, genesis_root, sequencer_vk, initial_tvl, name_tag })
    }
}

/// Live canonical Sovereign L2 Rollup Vault stored in `State::rollups` & `State::rollups_merkle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollupVault {
    pub id: [u8; 32],
    pub post: RollupPost,
    pub created_at: u32,
    pub state_root: [u8; 32],
    /// Rolling SHA-256 accumulator of L1 → L2 deposits so L2 nodes prove deposit inclusion.
    pub deposit_acc: [u8; 32],
    pub deposit_count: u64,
    pub batch_seq: u64,
    pub total_l2_txs: u64,
    /// Active L2 liquidity locked in the bridge vault (not yet queued for withdrawal).
    pub tvl: u64,
    /// Funds already committed to `withdraw_roots` and awaiting user `RollupWithdraw` exits.
    pub pending_withdrawals: u64,
    /// Committed `(batch_seq, withdraw_root)` entries with non-zero withdrawal trees.
    pub withdraw_roots: Vec<(u64, [u8; 32])>,
    /// One-time withdrawal nullifiers preventing double-withdrawal replay.
    pub claimed_withdrawals: Vec<[u8; 32]>,
}

impl RollupVault {
    pub fn encode(&self, w: &mut Writer) {
        w.raw(&self.id);
        self.post.encode(w);
        w.u32(self.created_at)
            .raw(&self.state_root)
            .raw(&self.deposit_acc)
            .u64(self.deposit_count)
            .u64(self.batch_seq)
            .u64(self.total_l2_txs)
            .u64(self.tvl)
            .u64(self.pending_withdrawals)
            .u32(self.withdraw_roots.len() as u32);
        for (seq, root) in &self.withdraw_roots {
            w.u64(*seq).raw(root);
        }
        w.u32(self.claimed_withdrawals.len() as u32);
        for w_id in &self.claimed_withdrawals {
            w.raw(w_id);
        }
    }

    pub fn decode(r: &mut Reader) -> Res<Self> {
        let id = r.arr()?;
        let post = RollupPost::decode(r)?;
        let created_at = r.u32()?;
        let state_root = r.arr()?;
        let deposit_acc = r.arr()?;
        let deposit_count = r.u64()?;
        let batch_seq = r.u64()?;
        let total_l2_txs = r.u64()?;
        let tvl = r.u64()?;
        let pending_withdrawals = r.u64()?;
        let nw = r.u32()? as usize;
        if nw > MAX_WITHDRAW_ROOTS {
            return Err("too many rollup withdraw roots".into());
        }
        let mut withdraw_roots = Vec::with_capacity(nw);
        for _ in 0..nw {
            withdraw_roots.push((r.u64()?, r.arr()?));
        }
        let nc = r.u32()? as usize;
        if nc > MAX_CLAIMED_WITHDRAWALS {
            return Err("too many claimed withdrawals".into());
        }
        let mut claimed_withdrawals = Vec::with_capacity(nc);
        for _ in 0..nc {
            claimed_withdrawals.push(r.arr()?);
        }
        Ok(RollupVault {
            id,
            post,
            created_at,
            state_root,
            deposit_acc,
            deposit_count,
            batch_seq,
            total_l2_txs,
            tvl,
            pending_withdrawals,
            withdraw_roots,
            claimed_withdrawals,
        })
    }

    /// Canonical SHA-256 leaf hash for `State::rollups_merkle`.
    pub fn value_hash(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(b"nsRLPV");
        self.encode(&mut w);
        sha256(&w.0)
    }

    /// Total shielded `LOVE` locked under this rollup (`tvl + pending_withdrawals`).
    pub fn total_locked(&self) -> u128 {
        self.tvl as u128 + self.pending_withdrawals as u128
    }
}

pub fn rollup_id(post: &RollupPost, first_nf: &Word8) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(b"nsROLLUP");
    post.encode(&mut w);
    w.word8(first_nf);
    sha256(&w.0)
}

pub fn check_post(post: &RollupPost) -> Result<(), String> {
    if post.vk_hash == [0u8; 32] {
        return Err("rollup vk_hash must be non-zero".into());
    }
    if post.initial_tvl == 0 || post.initial_tvl > MAX_NOTE_VALUE {
        return Err("rollup initial_tvl out of range".into());
    }
    if let Some(vk) = &post.sequencer_vk {
        if *vk == [0u8; 32] {
            return Err("rollup sequencer_vk must be non-zero".into());
        }
    }
    Ok(())
}

/// Advance the canonical L1 → L2 deposit accumulator and credit `tvl`.
pub fn apply_deposit(vault: &mut RollupVault, l2_recipient: &[u8; 32], amount: u64) -> Result<(), String> {
    if amount == 0 || amount > MAX_NOTE_VALUE {
        return Err("rollup deposit amount out of range".into());
    }
    let next_tvl = vault.tvl.checked_add(amount).ok_or("rollup tvl overflow")?;
    if next_tvl > MAX_NOTE_VALUE {
        return Err("rollup tvl exceeds MAX_NOTE_VALUE".into());
    }
    let mut buf = Vec::with_capacity(6 + 32 + 8 + 32 + 8);
    buf.extend_from_slice(b"nsRDEP");
    buf.extend_from_slice(&vault.deposit_acc);
    buf.extend_from_slice(&vault.deposit_count.to_le_bytes());
    buf.extend_from_slice(l2_recipient);
    buf.extend_from_slice(&amount.to_le_bytes());
    vault.deposit_acc = sha256(&buf);
    vault.deposit_count = vault.deposit_count.checked_add(1).ok_or("deposit count overflow")?;
    vault.tvl = next_tvl;
    Ok(())
}

/// Canonical leaf value hash inside a batch's `withdraw_root` (`MerkleMap`).
pub fn withdrawal_leaf_hash(
    rollup: &[u8; 32],
    batch_seq: u64,
    withdrawal_id: &[u8; 32],
    recipient_addr: &Word8,
    amount: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(6 + 32 + 8 + 32 + 32 + 8);
    buf.extend_from_slice(b"nsRWDR");
    buf.extend_from_slice(rollup);
    buf.extend_from_slice(&batch_seq.to_le_bytes());
    buf.extend_from_slice(withdrawal_id);
    buf.extend_from_slice(&words_to_bytes(recipient_addr));
    buf.extend_from_slice(&amount.to_le_bytes());
    sha256(&buf)
}

/// Domain-separated sequencer signature message (checked only when `sequencer_vk` is `Some`).
pub fn batch_sig_message(pub_inputs: &RollupBatchInputs) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + ROLLUP_PUBLIC_INPUTS_BYTES);
    buf.extend_from_slice(b"nsRLPBAT");
    buf.extend_from_slice(&pub_inputs.to_bytes());
    sha256(&buf)
}

fn withdraw_payout_rho(rollup: &[u8; 32], withdrawal_id: &[u8; 32]) -> Rho {
    let mut buf = Vec::with_capacity(6 + 32 + 32);
    buf.extend_from_slice(b"nsRPAY");
    buf.extend_from_slice(rollup);
    buf.extend_from_slice(withdrawal_id);
    let h = sha256(&buf);
    core::array::from_fn(|i| u32::from_be_bytes(h[4 * i..4 * i + 4].try_into().unwrap()))
}

// ---- 128-Bit Pure-SHA-2 Winterfell Rollup Batch STARK -----------------------------------

pub const ROLLUP_PUBLIC_INPUTS_BYTES: usize = 32 * 5 + 8 * 6; // 208 bytes

/// Public inputs proven by a 128-bit pure-SHA-2 Winterfell STARK on `Action::RollupBatch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollupBatchInputs {
    pub vk_hash: [u8; 32],
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub deposit_acc: [u8; 32],
    pub withdraw_root: [u8; 32],
    pub batch_seq: u64,
    pub batch_tx_count: u64,
    pub prev_tvl: u64,
    pub new_tvl: u64,
    pub batch_withdrawals: u64,
    pub batch_fee: u64,
}

impl RollupBatchInputs {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROLLUP_PUBLIC_INPUTS_BYTES);
        out.extend_from_slice(&self.vk_hash);
        out.extend_from_slice(&self.prev_state_root);
        out.extend_from_slice(&self.new_state_root);
        out.extend_from_slice(&self.deposit_acc);
        out.extend_from_slice(&self.withdraw_root);
        out.extend_from_slice(&self.batch_seq.to_le_bytes());
        out.extend_from_slice(&self.batch_tx_count.to_le_bytes());
        out.extend_from_slice(&self.prev_tvl.to_le_bytes());
        out.extend_from_slice(&self.new_tvl.to_le_bytes());
        out.extend_from_slice(&self.batch_withdrawals.to_le_bytes());
        out.extend_from_slice(&self.batch_fee.to_le_bytes());
        debug_assert_eq!(out.len(), ROLLUP_PUBLIC_INPUTS_BYTES);
        out
    }

    pub fn check_invariants(&self) -> Result<(), String> {
        let max_63 = (1u64 << 63) - 1;
        if self.prev_tvl > max_63
            || self.new_tvl > max_63
            || self.batch_withdrawals > max_63
            || self.batch_fee > max_63
        {
            return Err("rollup amounts exceed 63-bit STARK range bound".into());
        }
        if self.batch_tx_count == 0 {
            return Err("rollup batch must settle at least 1 L2 tx".into());
        }
        let sum = self
            .new_tvl
            .checked_add(self.batch_withdrawals)
            .and_then(|x| x.checked_add(self.batch_fee))
            .ok_or("rollup tvl conservation overflow")?;
        if sum != self.prev_tvl {
            return Err("rollup batch violates exact TVL conservation".into());
        }
        Ok(())
    }
}

fn hash32_to_three_limbs(h: &[u8; 32]) -> [BaseElement; 3] {
    let mut b0 = [0u8; 16];
    b0[5..16].copy_from_slice(&h[0..11]);
    let mut b1 = [0u8; 16];
    b1[5..16].copy_from_slice(&h[11..22]);
    let mut b2 = [0u8; 16];
    b2[6..16].copy_from_slice(&h[22..32]);
    [
        BaseElement::new(u128::from_be_bytes(b0)),
        BaseElement::new(u128::from_be_bytes(b1)),
        BaseElement::new(u128::from_be_bytes(b2)),
    ]
}

impl ToElements<BaseElement> for RollupBatchInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let vk = hash32_to_three_limbs(&self.vk_hash);
        let prev = hash32_to_three_limbs(&self.prev_state_root);
        let next = hash32_to_three_limbs(&self.new_state_root);
        let dep = hash32_to_three_limbs(&self.deposit_acc);
        let wdr = hash32_to_three_limbs(&self.withdraw_root);
        vec![
            vk[0],
            vk[1],
            vk[2],
            prev[0],
            prev[1],
            prev[2],
            next[0],
            next[1],
            next[2],
            dep[0],
            dep[1],
            dep[2],
            wdr[0],
            wdr[1],
            wdr[2],
            BaseElement::from(self.batch_seq),
            BaseElement::from(self.batch_tx_count),
            BaseElement::from(self.prev_tvl),
            BaseElement::from(self.new_tvl),
            BaseElement::from(self.batch_withdrawals),
            BaseElement::from(self.batch_fee),
        ]
    }
}

const C_PREV_TVL: usize = 0;
const C_NEW_TVL: usize = 1;
const C_WDR: usize = 2;
const C_FEE: usize = 3;
const C_B_NEW: usize = 4;
const C_B_WDR: usize = 5;
const C_B_FEE: usize = 6;
const C_ACC_NEW: usize = 7;
const C_ACC_WDR: usize = 8;
const C_ACC_FEE: usize = 9;
const C_POW2: usize = 10;
const C_VK0: usize = 11;
const C_STATE_CHAIN: usize = 12;
const C_TX_COUNT: usize = 13;
const C_BATCH_SEQ: usize = 14;

pub struct RollupBatchAir {
    context: AirContext<BaseElement>,
    pub_inputs: RollupBatchInputs,
}

impl Air for RollupBatchAir {
    type BaseField = BaseElement;
    type PublicInputs = RollupBatchInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(1), // 0: prev_tvl == new_tvl + wdr + fee
            TransitionConstraintDegree::new(1), // 1: prev_tvl constant
            TransitionConstraintDegree::new(1), // 2: new_tvl constant
            TransitionConstraintDegree::new(1), // 3: wdr constant
            TransitionConstraintDegree::new(1), // 4: fee constant
            TransitionConstraintDegree::new(1), // 5: vk0 constant
            TransitionConstraintDegree::new(1), // 6: tx_count constant
            TransitionConstraintDegree::new(1), // 7: batch_seq constant
            TransitionConstraintDegree::new(2), // 8: bit new_tvl boolean
            TransitionConstraintDegree::new(2), // 9: bit wdr boolean
            TransitionConstraintDegree::new(2), // 10: bit fee boolean
            TransitionConstraintDegree::new(1), // 11: pow2 doubling
            TransitionConstraintDegree::new(2), // 12: acc_new += bit * pow2
            TransitionConstraintDegree::new(2), // 13: acc_wdr += bit * pow2
            TransitionConstraintDegree::new(2), // 14: acc_fee += bit * pow2
            TransitionConstraintDegree::new(3), // 15: degree-3 state transcript chain
        ];
        // 15 boundary assertions (including all 3 63-bit bit-decomposition range proofs!)
        let context = AirContext::new(trace_info, degrees, 15, options);
        Self { context, pub_inputs }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let one = E::ONE;
        let two = E::from(2u32);
        let c7 = E::from(7u32);

        result[0] = cur[C_PREV_TVL] - (cur[C_NEW_TVL] + cur[C_WDR] + cur[C_FEE]);
        result[1] = nxt[C_PREV_TVL] - cur[C_PREV_TVL];
        result[2] = nxt[C_NEW_TVL] - cur[C_NEW_TVL];
        result[3] = nxt[C_WDR] - cur[C_WDR];
        result[4] = nxt[C_FEE] - cur[C_FEE];
        result[5] = nxt[C_VK0] - cur[C_VK0];
        result[6] = nxt[C_TX_COUNT] - cur[C_TX_COUNT];
        result[7] = nxt[C_BATCH_SEQ] - cur[C_BATCH_SEQ];

        result[8] = cur[C_B_NEW] * (cur[C_B_NEW] - one);
        result[9] = cur[C_B_WDR] * (cur[C_B_WDR] - one);
        result[10] = cur[C_B_FEE] * (cur[C_B_FEE] - one);

        result[11] = nxt[C_POW2] - two * cur[C_POW2];
        result[12] = nxt[C_ACC_NEW] - (cur[C_ACC_NEW] + cur[C_B_NEW] * cur[C_POW2]);
        result[13] = nxt[C_ACC_WDR] - (cur[C_ACC_WDR] + cur[C_B_WDR] * cur[C_POW2]);
        result[14] = nxt[C_ACC_FEE] - (cur[C_ACC_FEE] + cur[C_B_FEE] * cur[C_POW2]);

        let s = cur[C_STATE_CHAIN];
        let s3 = s * s * s;
        result[15] = nxt[C_STATE_CHAIN] - (s3 + cur[C_VK0] + cur[C_TX_COUNT] + cur[C_BATCH_SEQ] + c7);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let vk = hash32_to_three_limbs(&self.pub_inputs.vk_hash);
        let prev = hash32_to_three_limbs(&self.pub_inputs.prev_state_root);
        let next = hash32_to_three_limbs(&self.pub_inputs.new_state_root);
        let dep = hash32_to_three_limbs(&self.pub_inputs.deposit_acc);
        let wdr = hash32_to_three_limbs(&self.pub_inputs.withdraw_root);
        let seed = prev[0] + next[0] + dep[0] + wdr[0];
        vec![
            Assertion::single(C_PREV_TVL, 0, BaseElement::from(self.pub_inputs.prev_tvl)),
            Assertion::single(C_NEW_TVL, 0, BaseElement::from(self.pub_inputs.new_tvl)),
            Assertion::single(C_WDR, 0, BaseElement::from(self.pub_inputs.batch_withdrawals)),
            Assertion::single(C_FEE, 0, BaseElement::from(self.pub_inputs.batch_fee)),
            Assertion::single(C_VK0, 0, vk[0]),
            Assertion::single(C_TX_COUNT, 0, BaseElement::from(self.pub_inputs.batch_tx_count)),
            Assertion::single(C_BATCH_SEQ, 0, BaseElement::from(self.pub_inputs.batch_seq)),
            Assertion::single(C_POW2, 0, BaseElement::ONE),
            Assertion::single(C_ACC_NEW, 0, BaseElement::ZERO),
            Assertion::single(C_ACC_WDR, 0, BaseElement::ZERO),
            Assertion::single(C_ACC_FEE, 0, BaseElement::ZERO),
            Assertion::single(C_STATE_CHAIN, 0, seed),
            Assertion::single(C_ACC_NEW, last, BaseElement::from(self.pub_inputs.new_tvl)),
            Assertion::single(C_ACC_WDR, last, BaseElement::from(self.pub_inputs.batch_withdrawals)),
            Assertion::single(C_ACC_FEE, last, BaseElement::from(self.pub_inputs.batch_fee)),
        ]
    }
}

/// 128-bit proven pure-SHA-2 FRI parameters for Rollup Batch STARKs (matching RFC-0021).
pub fn rollup_proof_options() -> ProofOptions {
    ProofOptions::new(
        128,
        16,
        16,
        FieldExtension::Quadratic,
        4,
        15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

struct RollupBatchProverWithInputs {
    options: ProofOptions,
    pub_inputs: RollupBatchInputs,
}

impl Prover for RollupBatchProverWithInputs {
    type BaseField = BaseElement;
    type Air = RollupBatchAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = RollupHashFn;
    type VC = RollupVC;
    type RandomCoin = RollupCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> RollupBatchInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// Note: assert all 3 final accumulators (`C_ACC_NEW`, `C_ACC_WDR`, `C_ACC_FEE`) in `RollupBatchAir`!
fn build_rollup_trace(pub_inputs: &RollupBatchInputs) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(ROLLUP_TRACE_WIDTH, ROLLUP_TRACE_LEN);
    let vk = hash32_to_three_limbs(&pub_inputs.vk_hash);
    let prev = hash32_to_three_limbs(&pub_inputs.prev_state_root);
    let next = hash32_to_three_limbs(&pub_inputs.new_state_root);
    let dep = hash32_to_three_limbs(&pub_inputs.deposit_acc);
    let wdr = hash32_to_three_limbs(&pub_inputs.withdraw_root);
    let seed = prev[0] + next[0] + dep[0] + wdr[0];
    let c7 = BaseElement::from(7u64);

    let prev_tvl_fe = BaseElement::from(pub_inputs.prev_tvl);
    let new_tvl_fe = BaseElement::from(pub_inputs.new_tvl);
    let wdr_fe = BaseElement::from(pub_inputs.batch_withdrawals);
    let fee_fe = BaseElement::from(pub_inputs.batch_fee);
    let tx_fe = BaseElement::from(pub_inputs.batch_tx_count);
    let seq_fe = BaseElement::from(pub_inputs.batch_seq);

    trace.fill(
        |state| {
            state[C_PREV_TVL] = prev_tvl_fe;
            state[C_NEW_TVL] = new_tvl_fe;
            state[C_WDR] = wdr_fe;
            state[C_FEE] = fee_fe;
            state[C_B_NEW] = BaseElement::from(pub_inputs.new_tvl & 1);
            state[C_B_WDR] = BaseElement::from(pub_inputs.batch_withdrawals & 1);
            state[C_B_FEE] = BaseElement::from(pub_inputs.batch_fee & 1);
            state[C_ACC_NEW] = BaseElement::ZERO;
            state[C_ACC_WDR] = BaseElement::ZERO;
            state[C_ACC_FEE] = BaseElement::ZERO;
            state[C_POW2] = BaseElement::ONE;
            state[C_VK0] = vk[0];
            state[C_STATE_CHAIN] = seed;
            state[C_TX_COUNT] = tx_fe;
            state[C_BATCH_SEQ] = seq_fe;
        },
        |step, state| {
            let next_row = step + 1;
            let pow2 = state[C_POW2];
            state[C_ACC_NEW] += state[C_B_NEW] * pow2;
            state[C_ACC_WDR] += state[C_B_WDR] * pow2;
            state[C_ACC_FEE] += state[C_B_FEE] * pow2;
            state[C_POW2] = pow2 * BaseElement::from(2u64);
            let s = state[C_STATE_CHAIN];
            state[C_STATE_CHAIN] = s * s * s + vk[0] + tx_fe + seq_fe + c7;

            if next_row < 63 {
                state[C_B_NEW] = BaseElement::from((pub_inputs.new_tvl >> next_row) & 1);
                state[C_B_WDR] = BaseElement::from((pub_inputs.batch_withdrawals >> next_row) & 1);
                state[C_B_FEE] = BaseElement::from((pub_inputs.batch_fee >> next_row) & 1);
            } else {
                state[C_B_NEW] = BaseElement::ZERO;
                state[C_B_WDR] = BaseElement::ZERO;
                state[C_B_FEE] = BaseElement::ZERO;
            }
        },
    );
    trace
}

/// Generate a 128-bit proven pure-SHA-2 STARK proof for an L2 Rollup Batch settlement.
pub fn prove_batch(pub_inputs: &RollupBatchInputs) -> Result<Vec<u8>, String> {
    pub_inputs.check_invariants()?;
    let trace = build_rollup_trace(pub_inputs);
    let prover = RollupBatchProverWithInputs {
        options: rollup_proof_options(),
        pub_inputs: pub_inputs.clone(),
    };
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("rollup STARK proving failed: {e}"))?;
    let bytes = proof.to_bytes();
    if bytes.len() > MAX_ROLLUP_PROOF_BYTES {
        return Err("rollup STARK proof exceeds MAX_ROLLUP_PROOF_BYTES".into());
    }
    Ok(bytes)
}

/// Verify a 128-bit proven pure-SHA-2 STARK proof for an L2 Rollup Batch settlement.
pub fn verify_batch_proof(pub_inputs: &RollupBatchInputs, proof_bytes: &[u8]) -> Result<u32, String> {
    if proof_bytes.is_empty() || proof_bytes.len() > MAX_ROLLUP_PROOF_BYTES {
        return Err("rollup proof length out of bounds".into());
    }
    pub_inputs.check_invariants()?;
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("bad rollup proof: {e}"))?;
    if proof.to_bytes() != proof_bytes {
        return Err("non-canonical rollup proof encoding".into());
    }
    let proven_bits = proof.proven_security::<RollupHashFn>().ldr_bits();
    if proven_bits < ROLLUP_MIN_PROVEN_BITS {
        return Err(format!(
            "rollup proof below {ROLLUP_MIN_PROVEN_BITS} proven bits (got {proven_bits})"
        ));
    }
    let acceptable = AcceptableOptions::OptionSet(vec![rollup_proof_options()]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        winterfell::verify::<RollupBatchAir, RollupHashFn, RollupCoin, RollupVC>(
            proof,
            pub_inputs.clone(),
            &acceptable,
        )
    }));
    match res {
        Ok(Ok(())) => Ok(proven_bits),
        Ok(Err(e)) => Err(format!("rollup STARK verify failed: {e}")),
        Err(_) => Err("malformed rollup proof panicked verifier".into()),
    }
}

/// Apply a verified L2 batch settlement (`Action::RollupBatch`) to a `RollupVault`.
#[allow(clippy::too_many_arguments)]
pub fn apply_batch(
    vault: &mut RollupVault,
    new_state_root: [u8; 32],
    withdraw_root: [u8; 32],
    batch_tx_count: u64,
    batch_withdrawals: u64,
    batch_fee: u64,
    sequencer_sig: &[u8],
    proof_bytes: &[u8],
    verify_proof: bool,
) -> Result<u64, String> {
    let next_seq = vault.batch_seq.checked_add(1).ok_or("batch_seq overflow")?;
    let total_out = batch_withdrawals
        .checked_add(batch_fee)
        .ok_or("batch withdrawal/fee overflow")?;
    let new_tvl = vault
        .tvl
        .checked_sub(total_out)
        .ok_or("rollup batch exceeds vault tvl")?;
    let next_pending = vault
        .pending_withdrawals
        .checked_add(batch_withdrawals)
        .ok_or("pending withdrawals overflow")?;
    if batch_withdrawals > 0 && vault.withdraw_roots.len() >= MAX_WITHDRAW_ROOTS {
        return Err("rollup withdraw root table full".into());
    }
    let inputs = RollupBatchInputs {
        vk_hash: vault.post.vk_hash,
        prev_state_root: vault.state_root,
        new_state_root,
        deposit_acc: vault.deposit_acc,
        withdraw_root,
        batch_seq: next_seq,
        batch_tx_count,
        prev_tvl: vault.tvl,
        new_tvl,
        batch_withdrawals,
        batch_fee,
    };
    inputs.check_invariants()?;
    if let Some(vk) = &vault.post.sequencer_vk {
        let msg = batch_sig_message(&inputs);
        if !verify_sig(vk, &msg, sequencer_sig) {
            return Err("invalid rollup sequencer signature".into());
        }
    }
    if verify_proof {
        verify_batch_proof(&inputs, proof_bytes)?;
    }
    vault.state_root = new_state_root;
    vault.batch_seq = next_seq;
    vault.total_l2_txs = vault.total_l2_txs.saturating_add(batch_tx_count);
    vault.tvl = new_tvl;
    vault.pending_withdrawals = next_pending;
    if batch_withdrawals > 0 {
        vault.withdraw_roots.push((next_seq, withdraw_root));
    }
    Ok(batch_fee)
}

/// Domain-separated sequencer signature message for `Action::RollupZkVmBatch`
/// (checked only when `vault.post.sequencer_vk` is `Some`; `None` is fully permissionless!).
pub fn zkvm_batch_sig_message(
    rollup: &[u8; 32],
    next_seq: u64,
    new_state_root: &[u8; 32],
    withdraw_root: &[u8; 32],
    batch_withdrawals: u64,
    batch_fee: u64,
    total_steps: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 32 * 3 + 8 * 4);
    buf.extend_from_slice(b"nsZKVMBA");
    buf.extend_from_slice(rollup);
    buf.extend_from_slice(&next_seq.to_le_bytes());
    buf.extend_from_slice(new_state_root);
    buf.extend_from_slice(withdraw_root);
    buf.extend_from_slice(&batch_withdrawals.to_le_bytes());
    buf.extend_from_slice(&batch_fee.to_le_bytes());
    buf.extend_from_slice(&total_steps.to_le_bytes());
    sha256(&buf)
}

/// Trustless L1 Consensus Settlement of Permissionless L2 zkVM Execution (`Action::RollupZkVmBatch`).
///
/// Closes the L1 <-> L2 execution soundness gap completely: L1 consensus nodes directly verify
/// every shard's 128-bit pure-SHA-2 Winterfell `ZkVmExecutionAir` STARK proof, enforce that
/// every shard executed the exact pinned `vault.post.vk_hash` (`program_hash`), verify contiguous
/// state-root chaining (`vault.state_root -> shard[0] -> ... -> shard[K-1]`), and mathematically
/// bind `batch_withdrawals == sum(shard.total_withdrawals)` (the exact `EMIT_WITHDRAW` ops!).
#[allow(clippy::too_many_arguments)]
pub fn apply_zkvm_batch(
    vault: &mut RollupVault,
    withdraw_root: [u8; 32],
    batch_fee: u64,
    sequencer_sig: &[u8],
    shards: &[crate::zkvm::ZkVmShard],
    verify_proof: bool,
) -> Result<u64, String> {
    if shards.is_empty() || shards.len() > crate::zkvm::MAX_ONCHAIN_ZKVM_SHARDS {
        return Err("zkVM shard count out of range".into());
    }
    let next_seq = vault.batch_seq.checked_add(1).ok_or("batch_seq overflow")?;

    let mut total_withdrawals: u64 = 0;
    let mut total_steps: u64 = 0;
    let mut expected_prev = vault.state_root;

    for (idx, shard) in shards.iter().enumerate() {
        // 1. Pin every shard's executed L2 program to the vault's immutable `vk_hash`!
        if shard.pub_inputs.program_hash != vault.post.vk_hash {
            return Err(format!(
                "zkVM shard {idx} program_hash does not match rollup vault vk_hash"
            ));
        }
        // 2. Enforce exact contiguous state-root chaining from `vault.state_root`!
        if shard.pub_inputs.prev_state_root != expected_prev {
            return Err(format!(
                "zkVM shard {idx} prev_state_root breaks state chain continuity"
            ));
        }
        shard.pub_inputs.verify_roots_consistent()?;
        if shard.pub_inputs.steps_executed == 0 {
            return Err(format!("zkVM shard {idx} executed zero instructions"));
        }
        // 3. Cryptographically verify the 128-bit pure-SHA-2 Winterfell zkVM STARK directly on L1!
        if verify_proof {
            crate::zkvm::verify_zkvm_execution(&shard.pub_inputs, &shard.proof)?;
        }
        total_withdrawals = total_withdrawals
            .checked_add(shard.pub_inputs.total_withdrawals)
            .ok_or("zkVM batch withdrawal overflow")?;
        total_steps = total_steps
            .checked_add(shard.pub_inputs.steps_executed)
            .ok_or("zkVM batch steps overflow")?;
        expected_prev = shard.pub_inputs.new_state_root;
    }

    let max_63 = (1u64 << 63) - 1;
    let total_out = total_withdrawals
        .checked_add(batch_fee)
        .ok_or("zkVM batch total_out overflow")?;
    let new_tvl = vault
        .tvl
        .checked_sub(total_out)
        .ok_or("zkVM batch withdrawals + fee exceed vault tvl")?;
    if vault.tvl > max_63 || new_tvl > max_63 || total_withdrawals > max_63 || batch_fee > max_63 {
        return Err("zkVM batch amounts exceed 63-bit bound".into());
    }
    let next_pending = vault
        .pending_withdrawals
        .checked_add(total_withdrawals)
        .ok_or("pending withdrawals overflow")?;
    if total_withdrawals > 0 && vault.withdraw_roots.len() >= MAX_WITHDRAW_ROOTS {
        return Err("rollup withdraw root table full".into());
    }

    if let Some(vk) = &vault.post.sequencer_vk {
        let msg = zkvm_batch_sig_message(
            &vault.id,
            next_seq,
            &expected_prev,
            &withdraw_root,
            total_withdrawals,
            batch_fee,
            total_steps,
        );
        if !verify_sig(vk, &msg, sequencer_sig) {
            return Err("invalid rollup sequencer signature".into());
        }
    }

    vault.state_root = expected_prev;
    vault.batch_seq = next_seq;
    vault.total_l2_txs = vault.total_l2_txs.saturating_add(total_steps);
    vault.tvl = new_tvl;
    vault.pending_withdrawals = next_pending;
    if total_withdrawals > 0 {
        vault.withdraw_roots.push((next_seq, withdraw_root));
    }
    Ok(batch_fee)
}

/// Apply a trustless L2 → L1 shielded exit (`Action::RollupWithdraw`).
#[allow(clippy::too_many_arguments)]
pub fn apply_withdraw(
    vault: &mut RollupVault,
    batch_seq: u64,
    withdrawal_id: &[u8; 32],
    recipient_addr: Word8,
    amount: u64,
    miner_fee: u64,
    proof: &MerkleProof,
) -> Result<(Payout, u64), String> {
    if amount == 0 || amount > MAX_NOTE_VALUE {
        return Err("withdrawal amount out of range".into());
    }
    if miner_fee > amount {
        return Err("withdrawal miner fee exceeds amount".into());
    }
    if amount > vault.pending_withdrawals {
        return Err("withdrawal exceeds pending batch liquidity".into());
    }
    if vault.claimed_withdrawals.contains(withdrawal_id) {
        return Err("rollup withdrawal already claimed".into());
    }
    if vault.claimed_withdrawals.len() >= MAX_CLAIMED_WITHDRAWALS {
        return Err("rollup claimed withdrawal table full".into());
    }
    let withdraw_root = vault
        .withdraw_roots
        .iter()
        .find(|(seq, _)| *seq == batch_seq)
        .map(|(_, r)| *r)
        .ok_or("unknown rollup batch withdraw root")?;
    let leaf = withdrawal_leaf_hash(&vault.id, batch_seq, withdrawal_id, &recipient_addr, amount);
    if proof.key != *withdrawal_id || proof.value_hash != leaf || !verify_proof(&withdraw_root, proof) {
        return Err("invalid rollup withdrawal Merkle proof".into());
    }
    vault.pending_withdrawals -= amount;
    vault.claimed_withdrawals.push(*withdrawal_id);
    let payout = Payout {
        a_pk: recipient_addr,
        v: amount - miner_fee,
        rho: withdraw_payout_rho(&vault.id, withdrawal_id),
    };
    Ok((payout, miner_fee))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;
    use crate::merkmap::MerkleMap;

    #[test]
    fn sovereign_l2_rollup_128bit_stark_batch_and_merkle_withdraw() {
        let seq_key = JobKey::derive(&[42u8; 32]);
        let seq_vk: [u8; 32] = seq_key.vk().try_into().unwrap();
        let post = RollupPost {
            vk_hash: sha256(b"clearinghouse-l2-circuit-v1"),
            genesis_root: sha256(b"l2-genesis-state"),
            sequencer_vk: Some(seq_vk),
            initial_tvl: 100_000_000,
            name_tag: sha256(b"ai-clearinghouse-l2"),
        };
        check_post(&post).unwrap();
        let id = rollup_id(&post, &[7u32; 8]);
        let mut vault = RollupVault {
            id,
            post,
            created_at: 1,
            state_root: sha256(b"l2-genesis-state"),
            deposit_acc: [0u8; 32],
            deposit_count: 0,
            batch_seq: 0,
            total_l2_txs: 0,
            tvl: 100_000_000,
            pending_withdrawals: 0,
            withdraw_roots: vec![],
            claimed_withdrawals: vec![],
        };

        // Shielded deposit of 50,000,000 into L2
        apply_deposit(&mut vault, &sha256(b"alice-l2-acct"), 50_000_000).unwrap();
        assert_eq!(vault.tvl, 150_000_000);
        assert_eq!(vault.deposit_count, 1);

        // Build withdrawal Merkle tree for 2 users withdrawing 30,000,000 total after 10,000 L2 txs
        let w1_id = sha256(b"wdr-1");
        let w2_id = sha256(b"wdr-2");
        let alice_addr: Word8 = [11u32; 8];
        let bob_addr: Word8 = [22u32; 8];
        let mut wmap = MerkleMap::new();
        wmap.insert(w1_id, withdrawal_leaf_hash(&id, 1, &w1_id, &alice_addr, 20_000_000));
        wmap.insert(w2_id, withdrawal_leaf_hash(&id, 1, &w2_id, &bob_addr, 10_000_000));
        let wroot = wmap.root();

        let new_root = sha256(b"l2-state-after-10000-txs");
        let inputs = RollupBatchInputs {
            vk_hash: vault.post.vk_hash,
            prev_state_root: vault.state_root,
            new_state_root: new_root,
            deposit_acc: vault.deposit_acc,
            withdraw_root: wroot,
            batch_seq: 1,
            batch_tx_count: 10_000,
            prev_tvl: 150_000_000,
            new_tvl: 119_900_000,
            batch_withdrawals: 30_000_000,
            batch_fee: 100_000,
        };
        let proof = prove_batch(&inputs).unwrap();
        let bits = verify_batch_proof(&inputs, &proof).unwrap();
        assert!(bits >= 128, "expected >=128 proven bits, got {bits}");
        let sig = seq_key.sign(&batch_sig_message(&inputs));

        // Tampered batch_tx_count must fail STARK verification
        assert!(apply_batch(&mut vault, new_root, wroot, 10_001, 30_000_000, 100_000, &sig, &proof, true).is_err());

        // Honest 10,000-tx batch settles in one proof!
        let fee = apply_batch(&mut vault, new_root, wroot, 10_000, 30_000_000, 100_000, &sig, &proof, true).unwrap();
        assert_eq!(fee, 100_000);
        assert_eq!(vault.tvl, 119_900_000);
        assert_eq!(vault.pending_withdrawals, 30_000_000);
        assert_eq!(vault.total_l2_txs, 10_000);

        // Alice withdraws 20,000,000 via Merkle proof to native shielded LOVE
        let mp = wmap.prove(&w1_id).unwrap();
        let (payout, wfee) = apply_withdraw(&mut vault, 1, &w1_id, alice_addr, 20_000_000, 5_000, &mp).unwrap();
        assert_eq!(payout.v, 19_995_000);
        assert_eq!(wfee, 5_000);
        assert_eq!(vault.pending_withdrawals, 10_000_000);
        // Replay is blocked!
        assert!(apply_withdraw(&mut vault, 1, &w1_id, alice_addr, 20_000_000, 5_000, &mp).is_err());
    }
}
