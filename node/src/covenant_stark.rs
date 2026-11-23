//! RFC-0021 `OP_VERIFY_COVENANT_STARK` (0xb4) — Native SHA-256 Winterfell 0.13 Covenant STARK
//!
//! Pure SHA-256 post-quantum STARK verifier & prover embedded directly into the Newsatoshi L1
//! condition script VM (`crate::script::op::VERIFY_COVENANT_STARK`, opcode `0xb4`).
//!
//! Uses Newsatoshi's native `crate::hash::Sha2_256` Winterfell hasher (100% SHA-256 — zero
//! auxiliary hash primitives or elliptic curves) over `f128::BaseElement` to prove & verify:
//!   1. Recursive covenant rule continuity (`covenant_rule_hash == change_covenant_rule_hash == expected_rule_hash`)
//!   2. Exact value conservation (`input_amount == payout_amount + change_amount`)
//!   3. 63-bit bit-decomposition non-negativity range proofs on payout, change, bounty cap slack
//!      (`max_bounty_payout - payout_amount >= 0`) and ecological floor slack
//!      (`soil_health_score - min_soil_health_score >= 0`), or exact `reinvest_bps` floor division
//!      bounds for PayWord streaming settlements.
//!   4. Degree-3 algebraic state-chain step bound to `prev_state_root` and absorbed into Fiat–Shamir.

use crate::hash::Sha2_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::{FieldElement, StarkField, ToElements};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
};

/// Power-of-2 execution trace length (64 rows => 63 bit-decomposition transitions).
pub const TRACE_LENGTH: usize = 64;
/// Number of algebraic columns in `CovenantTransitionAir`.
pub const TRACE_WIDTH: usize = 15;
/// Minimum conjectured post-quantum security bits required by L1 script verification.
pub const MIN_SECURITY_BITS: u32 = 95;
/// Exact canonical byte length of encoded `CovenantPublicInputs`.
pub const PUBLIC_INPUTS_BYTES: usize = 1 + 8 + 32 * 4 + 8 * 4 + 2 * 3; // 175 bytes
/// Hard DoS cap on a serialized Covenant STARK proof inside an L1 script witness.
pub const MAX_COVENANT_STARK_BYTES: usize = 32_768;

type StarkHashFn = Sha2_256<BaseElement>;
type StarkVC = MerkleTree<StarkHashFn>;
type StarkCoin = DefaultRandomCoin<StarkHashFn>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CovenantTxKind {
    LandDeed = 0,
    TelemetryBounty = 1,
    StreamingSettlement = 2,
}

impl CovenantTxKind {
    pub fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(Self::LandDeed),
            1 => Ok(Self::TelemetryBounty),
            2 => Ok(Self::StreamingSettlement),
            _ => Err(format!("invalid covenant tx kind tag {v}")),
        }
    }
}

/// Canonical L1 public inputs for `OP_VERIFY_COVENANT_STARK` (`0xb4`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CovenantPublicInputs {
    pub tx_kind: CovenantTxKind,
    pub tx_nonce: u64,
    pub covenant_rule_hash: [u8; 32],
    pub change_covenant_rule_hash: [u8; 32],
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub input_amount: u64,
    pub payout_amount: u64,
    pub change_amount: u64,
    pub max_bounty_payout: u64,
    pub reinvest_bps: u16,
    pub min_soil_health_score: u16,
    pub soil_health_score: u16,
}

impl CovenantPublicInputs {
    /// Deterministic 175-byte canonical wire encoding (little-endian integers).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_INPUTS_BYTES);
        out.push(self.tx_kind as u8);
        out.extend_from_slice(&self.tx_nonce.to_le_bytes());
        out.extend_from_slice(&self.covenant_rule_hash);
        out.extend_from_slice(&self.change_covenant_rule_hash);
        out.extend_from_slice(&self.prev_state_root);
        out.extend_from_slice(&self.new_state_root);
        out.extend_from_slice(&self.input_amount.to_le_bytes());
        out.extend_from_slice(&self.payout_amount.to_le_bytes());
        out.extend_from_slice(&self.change_amount.to_le_bytes());
        out.extend_from_slice(&self.max_bounty_payout.to_le_bytes());
        out.extend_from_slice(&self.reinvest_bps.to_le_bytes());
        out.extend_from_slice(&self.min_soil_health_score.to_le_bytes());
        out.extend_from_slice(&self.soil_health_score.to_le_bytes());
        debug_assert_eq!(out.len(), PUBLIC_INPUTS_BYTES);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != PUBLIC_INPUTS_BYTES {
            return Err(format!(
                "covenant public inputs must be exactly {PUBLIC_INPUTS_BYTES} bytes, got {}",
                b.len()
            ));
        }
        let tx_kind = CovenantTxKind::from_u8(b[0])?;
        let tx_nonce = u64::from_le_bytes(b[1..9].try_into().unwrap());
        let covenant_rule_hash: [u8; 32] = b[9..41].try_into().unwrap();
        let change_covenant_rule_hash: [u8; 32] = b[41..73].try_into().unwrap();
        let prev_state_root: [u8; 32] = b[73..105].try_into().unwrap();
        let new_state_root: [u8; 32] = b[105..137].try_into().unwrap();
        let input_amount = u64::from_le_bytes(b[137..145].try_into().unwrap());
        let payout_amount = u64::from_le_bytes(b[145..153].try_into().unwrap());
        let change_amount = u64::from_le_bytes(b[153..161].try_into().unwrap());
        let max_bounty_payout = u64::from_le_bytes(b[161..169].try_into().unwrap());
        let reinvest_bps = u16::from_le_bytes(b[169..171].try_into().unwrap());
        let min_soil_health_score = u16::from_le_bytes(b[171..173].try_into().unwrap());
        let soil_health_score = u16::from_le_bytes(b[173..175].try_into().unwrap());
        Ok(Self {
            tx_kind,
            tx_nonce,
            covenant_rule_hash,
            change_covenant_rule_hash,
            prev_state_root,
            new_state_root,
            input_amount,
            payout_amount,
            change_amount,
            max_bounty_payout,
            reinvest_bps,
            min_soil_health_score,
            soil_health_score,
        })
    }

    fn expected_bounty_slack_fe(&self) -> BaseElement {
        match self.tx_kind {
            CovenantTxKind::TelemetryBounty => {
                BaseElement::from(self.max_bounty_payout) - BaseElement::from(self.payout_amount)
            }
            CovenantTxKind::LandDeed => {
                BaseElement::from(self.input_amount) - BaseElement::from(self.payout_amount)
            }
            CovenantTxKind::StreamingSettlement => {
                BaseElement::from(self.input_amount) * BaseElement::from(self.reinvest_bps as u64)
                    - BaseElement::from(self.change_amount) * BaseElement::from(10_000u64)
            }
        }
    }

    fn expected_soil_slack_fe(&self) -> BaseElement {
        match self.tx_kind {
            CovenantTxKind::TelemetryBounty => {
                BaseElement::from(self.soil_health_score as u64)
                    - BaseElement::from(self.min_soil_health_score as u64)
            }
            CovenantTxKind::LandDeed => BaseElement::from(self.change_amount),
            CovenantTxKind::StreamingSettlement => {
                let rem = self.expected_bounty_slack_fe();
                BaseElement::from(9_999u64) - rem
            }
        }
    }

    fn compute_checked_slacks(&self) -> Result<(u64, u64), String> {
        let max_63 = (1u64 << 63) - 1;
        if self.input_amount > max_63 || self.payout_amount > max_63 || self.change_amount > max_63
        {
            return Err("amounts exceed 63-bit STARK range bound".into());
        }
        if self.payout_amount.checked_add(self.change_amount) != Some(self.input_amount) {
            return Err("value conservation violated".into());
        }
        if self.covenant_rule_hash != self.change_covenant_rule_hash {
            return Err("recursive covenant rule continuity violated".into());
        }
        if self.reinvest_bps > 10_000 {
            return Err("reinvest_bps exceeds 10000".into());
        }
        match self.tx_kind {
            CovenantTxKind::TelemetryBounty => {
                let bounty_slack = self
                    .max_bounty_payout
                    .checked_sub(self.payout_amount)
                    .ok_or("bounty cap violated")?;
                let soil_slack = self
                    .soil_health_score
                    .checked_sub(self.min_soil_health_score)
                    .ok_or("ecological soil floor violated")?;
                Ok((bounty_slack, u64::from(soil_slack)))
            }
            CovenantTxKind::LandDeed => {
                let slack = self
                    .input_amount
                    .checked_sub(self.payout_amount)
                    .ok_or("deed payout exceeds input")?;
                Ok((slack, self.change_amount))
            }
            CovenantTxKind::StreamingSettlement => {
                let lhs = (self.input_amount as u128) * (self.reinvest_bps as u128);
                let rhs = (self.change_amount as u128) * 10_000u128;
                let rem = lhs.checked_sub(rhs).ok_or("reinvest exceeds floor bound")?;
                if rem > 9_999 {
                    return Err("streaming settlement under-reinvested".into());
                }
                let rem_u64 = rem as u64;
                Ok((rem_u64, 9_999 - rem_u64))
            }
        }
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

impl ToElements<BaseElement> for CovenantPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let rule_in = hash32_to_three_limbs(&self.covenant_rule_hash);
        let rule_out = hash32_to_three_limbs(&self.change_covenant_rule_hash);
        let prev_root = hash32_to_three_limbs(&self.prev_state_root);
        let new_root = hash32_to_three_limbs(&self.new_state_root);

        vec![
            BaseElement::from(self.tx_kind as u64),
            BaseElement::from(self.tx_nonce),
            rule_in[0],
            rule_in[1],
            rule_in[2],
            rule_out[0],
            rule_out[1],
            rule_out[2],
            prev_root[0],
            prev_root[1],
            prev_root[2],
            new_root[0],
            new_root[1],
            new_root[2],
            BaseElement::from(self.input_amount),
            BaseElement::from(self.payout_amount),
            BaseElement::from(self.change_amount),
            BaseElement::from(self.max_bounty_payout),
            BaseElement::from(self.reinvest_bps as u64),
            BaseElement::from(self.min_soil_health_score as u64),
            BaseElement::from(self.soil_health_score as u64),
        ]
    }
}

pub struct CovenantTransitionAir {
    context: AirContext<BaseElement>,
    pub_inputs: CovenantPublicInputs,
}

impl Air for CovenantTransitionAir {
    type BaseField = BaseElement;
    type PublicInputs = CovenantPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(3),
        ];
        Self {
            context: AirContext::new(trace_info, degrees, 18, options),
            pub_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let curr = frame.current();
        let next = frame.next();

        result[0] = next[0] - curr[0];
        result[1] = next[1] - curr[1];
        result[2] = next[2] - curr[2];

        result[3] = next[3] - curr[3];
        result[4] = next[4] - curr[4];
        result[5] = next[5] - curr[5];

        result[6] = curr[3] - curr[4] - curr[5];

        result[7] = curr[6] * (curr[6] - E::ONE);
        result[8] = next[7] - (curr[7] + curr[7] + curr[6]);

        result[9] = curr[8] * (curr[8] - E::ONE);
        result[10] = next[9] - (curr[9] + curr[9] + curr[8]);

        result[11] = curr[10] * (curr[10] - E::ONE);
        result[12] = next[11] - (curr[11] + curr[11] + curr[10]);

        result[13] = curr[12] * (curr[12] - E::ONE);
        result[14] = next[13] - (curr[13] + curr[13] + curr[12]);

        let state_cubed = curr[14] * curr[14] * curr[14];
        result[15] = next[14] - (state_cubed + curr[0] + curr[4] + E::ONE);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let in_rule = hash32_to_three_limbs(&self.pub_inputs.covenant_rule_hash);
        let out_rule = hash32_to_three_limbs(&self.pub_inputs.change_covenant_rule_hash);
        let prev_root = hash32_to_three_limbs(&self.pub_inputs.prev_state_root);

        vec![
            Assertion::single(0, 0, in_rule[0]),
            Assertion::single(1, 0, in_rule[1]),
            Assertion::single(2, 0, in_rule[2]),
            Assertion::single(0, last, out_rule[0]),
            Assertion::single(1, last, out_rule[1]),
            Assertion::single(2, last, out_rule[2]),
            Assertion::single(3, 0, BaseElement::from(self.pub_inputs.input_amount)),
            Assertion::single(4, 0, BaseElement::from(self.pub_inputs.payout_amount)),
            Assertion::single(5, 0, BaseElement::from(self.pub_inputs.change_amount)),
            Assertion::single(7, 0, BaseElement::ZERO),
            Assertion::single(7, last, self.pub_inputs.expected_bounty_slack_fe()),
            Assertion::single(9, 0, BaseElement::ZERO),
            Assertion::single(9, last, self.pub_inputs.expected_soil_slack_fe()),
            Assertion::single(11, 0, BaseElement::ZERO),
            Assertion::single(11, last, BaseElement::from(self.pub_inputs.change_amount)),
            Assertion::single(13, 0, BaseElement::ZERO),
            Assertion::single(13, last, BaseElement::from(self.pub_inputs.payout_amount)),
            Assertion::single(14, 0, prev_root[0]),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct CovenantProver {
    options: ProofOptions,
    pub_inputs: CovenantPublicInputs,
}

impl CovenantProver {
    fn default_options() -> ProofOptions {
        ProofOptions::new(
            32,
            8,
            4,
            FieldExtension::None,
            4,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        )
    }

    fn build_trace(pub_inputs: &CovenantPublicInputs) -> Result<TraceTable<BaseElement>, String> {
        let (bounty_slack, soil_slack) = pub_inputs.compute_checked_slacks()?;
        let rule_limbs = hash32_to_three_limbs(&pub_inputs.covenant_rule_hash);
        let prev_root_limbs = hash32_to_three_limbs(&pub_inputs.prev_state_root);

        let input_fe = BaseElement::from(pub_inputs.input_amount);
        let payout_fe = BaseElement::from(pub_inputs.payout_amount);
        let change_fe = BaseElement::from(pub_inputs.change_amount);

        let g = BaseElement::get_root_of_unity(6);
        let final_bit_for_full_degree = |val: u64| -> BaseElement {
            let mut sum = BaseElement::ZERO;
            let mut g_pow = BaseElement::ONE;
            for step in 0..63 {
                if ((val >> (62 - step)) & 1) == 1 {
                    sum += g_pow;
                }
                g_pow *= g;
            }
            if sum == BaseElement::ZERO {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            }
        };

        let bounty_last_bit = final_bit_for_full_degree(bounty_slack);
        let soil_last_bit = final_bit_for_full_degree(soil_slack);
        let change_last_bit = final_bit_for_full_degree(pub_inputs.change_amount);
        let payout_last_bit = final_bit_for_full_degree(pub_inputs.payout_amount);

        let bit_at = |val: u64, last_bit: BaseElement, step: usize| -> BaseElement {
            if step < 63 {
                BaseElement::from((val >> (62 - step)) & 1)
            } else {
                last_bit
            }
        };

        let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
        trace.fill(
            |state| {
                state[0] = rule_limbs[0];
                state[1] = rule_limbs[1];
                state[2] = rule_limbs[2];
                state[3] = input_fe;
                state[4] = payout_fe;
                state[5] = change_fe;
                state[6] = bit_at(bounty_slack, bounty_last_bit, 0);
                state[7] = BaseElement::ZERO;
                state[8] = bit_at(soil_slack, soil_last_bit, 0);
                state[9] = BaseElement::ZERO;
                state[10] = bit_at(pub_inputs.change_amount, change_last_bit, 0);
                state[11] = BaseElement::ZERO;
                state[12] = bit_at(pub_inputs.payout_amount, payout_last_bit, 0);
                state[13] = BaseElement::ZERO;
                state[14] = prev_root_limbs[0];
            },
            |step, state| {
                let next_step = step + 1;
                state[7] = state[7] + state[7] + state[6];
                state[6] = bit_at(bounty_slack, bounty_last_bit, next_step);

                state[9] = state[9] + state[9] + state[8];
                state[8] = bit_at(soil_slack, soil_last_bit, next_step);

                state[11] = state[11] + state[11] + state[10];
                state[10] = bit_at(pub_inputs.change_amount, change_last_bit, next_step);

                state[13] = state[13] + state[13] + state[12];
                state[12] = bit_at(pub_inputs.payout_amount, payout_last_bit, next_step);

                let cubed = state[14] * state[14] * state[14];
                state[14] = cubed + state[0] + state[4] + BaseElement::ONE;
            },
        );
        Ok(trace)
    }
}

impl Prover for CovenantProver {
    type BaseField = BaseElement;
    type Air = CovenantTransitionAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = StarkHashFn;
    type VC = StarkVC;
    type RandomCoin = StarkCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> CovenantPublicInputs {
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

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Generates a real pure-SHA-256 Winterfell 0.13 STARK proof for `OP_VERIFY_COVENANT_STARK`.
pub fn prove_covenant_stark(inputs: &CovenantPublicInputs) -> Result<Vec<u8>, String> {
    let trace = CovenantProver::build_trace(inputs)?;
    let prover = CovenantProver {
        options: CovenantProver::default_options(),
        pub_inputs: inputs.clone(),
    };
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("covenant STARK prove failed: {e}"))?;
    let bytes = proof.to_bytes();
    if bytes.len() > MAX_COVENANT_STARK_BYTES {
        return Err(format!(
            "covenant STARK proof ({} bytes) exceeds limit {MAX_COVENANT_STARK_BYTES}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Consensus verifier executed by `script::op::VERIFY_COVENANT_STARK` (`0xb4`).
pub fn verify_covenant_stark_bytes(
    expected_rule_hash: &[u8; 32],
    pub_inputs_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<(), String> {
    if proof_bytes.is_empty() || proof_bytes.len() > MAX_COVENANT_STARK_BYTES {
        return Err("covenant STARK proof size out of bounds".into());
    }
    let inputs = CovenantPublicInputs::from_bytes(pub_inputs_bytes)?;
    if &inputs.covenant_rule_hash != expected_rule_hash {
        return Err("covenant_rule_hash mismatch".into());
    }
    if &inputs.change_covenant_rule_hash != expected_rule_hash {
        return Err("recursive covenant continuity violated".into());
    }
    // Pre-verify integer domain bounds before invoking Winterfell FRI verification (DoS + soundness guard).
    let max_63 = (1u64 << 63) - 1;
    if inputs.input_amount > max_63 || inputs.payout_amount > max_63 || inputs.change_amount > max_63 {
        return Err("covenant amounts exceed 63-bit range bound".into());
    }
    if inputs.reinvest_bps > 10_000 {
        return Err("covenant reinvest_bps exceeds 10000".into());
    }
    if inputs.min_soil_health_score > 100 || inputs.soil_health_score > 100 {
        return Err("covenant soil_health_score exceeds 100".into());
    }
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|e| format!("bad covenant STARK proof: {e}"))?;
    let acceptable = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<CovenantTransitionAir, StarkHashFn, StarkCoin, StarkVC>(
        proof,
        inputs,
        &acceptable,
    )
    .map_err(|e| format!("covenant STARK verify failed: {e}"))
}
