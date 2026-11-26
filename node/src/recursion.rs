//! Real 192-Bit SHA-384 STARK Recursion Primitives:
//! 1. **Bit-Exact SHA-256d PoW Header-Chain STARK (`HeaderChainAir`):**
//!    Proves inside a genuine pure-SHA-384 Winterfell STARK (236 columns × 1,024 rows) that a
//!    contiguous chain of 80-byte Newsatoshi/Bitcoin block headers `H_0 -> H_1 -> ... -> H_{K-1}`
//!    satisfies exact FIPS 180-4 SHA-256d hashing (3 full 64-round bit-level SHA-256 compressions
//!    per header including dynamic IV chaining and FIPS padding) and exact chain linkage
//!    (`H_{i+1}.prev == sha256d(H_i)`). Multiple segments fold cleanly via
//!    `verify_folded_header_segments`.
//!
//! 2. **Algebraic FRI-Folding Verifier STARK (`FriFoldVerifyAir`):**
//!    Proves inside a pure-SHA-384 Winterfell STARK the core algebraic STARK-in-STARK recursion
//!    identity across $R$ FRI folding rounds in the Goldilocks field $F_p$:
//!    $$2 \cdot x_i \cdot f_{i+1} = x_i \cdot (f_i(x_i) + f_i(-x_i)) + \alpha_i \cdot (f_i(x_i) - f_i(-x_i))$$
//!    with domain squaring $x_{i+1} = x_i^2$, binary branch selection, and final remainder pinning.
//!
//! > **Honest Scope Boundary:** `HeaderChainAir` proves real bit-exact SHA-256d header chains
//! > inside a STARK and `FriFoldVerifyAir` proves exact multi-round algebraic FRI folding inside
//! > a STARK (`>= 128`-bit QROM / `>= 150`-bit Goldilocks cubic proven LDR bits with SHA-384 FRI).
//! > Full single-proof recursion of an entire 128-query SHA-384 Merkle-path outer FRI verifier
//! > inside one inner pure-SHA-384 STARK requires ~100,000 SHA-384 compressions (~`2^23` trace
//! > rows) and is a future GPU / Poseidon-wrapper cluster milestone.

use crate::hash::{self, compress, sha256d, Sha2_384, Word8, IV, K};
use crate::tx::Header;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement as Felt, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

pub type RecHash = Sha2_384<Felt>;
pub type RecCoin = DefaultRandomCoin<RecHash>;
pub type RecVc = MerkleTree<RecHash>;

/// Pure-SHA-384 FRI options achieving >= 150 proven Goldilocks-cubic LDR bits and 128-bit QROM
/// collision security (192-bit classical SHA-384 hash bound).
pub fn recursion_stark_options() -> ProofOptions {
    ProofOptions::new(
        104,
        16,
        16,
        FieldExtension::Cubic,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// ======================================================================================
// PART 1: REAL ALGEBRAIC FRI-FOLDING VERIFIER STARK (`FriFoldVerifyAir`)
// ======================================================================================

const FRI_WIDTH: usize = 7;
const COL_X: usize = 0;
const COL_FP: usize = 1;
const COL_FN: usize = 2;
const COL_ALPHA: usize = 3;
const COL_BIT: usize = 4;
const COL_FOLDED: usize = 5;
const COL_ACC: usize = 6;

/// One round of an algebraic FRI-folding verifier trace.
#[derive(Clone, Copy, Debug)]
pub struct FriFoldStep {
    pub x: Felt,
    pub f_pos: Felt,
    pub f_neg: Felt,
    pub alpha: Felt,
    pub next_is_neg: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriFoldPublicInputs {
    pub x0: Felt,
    pub f_pos0: Felt,
    pub f_neg0: Felt,
    pub final_eval: Felt,
    pub final_acc: Felt,
    pub rounds: usize,
}

impl ToElements<Felt> for FriFoldPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        vec![
            self.x0,
            self.f_pos0,
            self.f_neg0,
            self.final_eval,
            self.final_acc,
            Felt::new(self.rounds as u64),
        ]
    }
}

pub struct FriFoldVerifyAir {
    ctx: AirContext<Felt>,
    pi: FriFoldPublicInputs,
}

impl Air for FriFoldVerifyAir {
    type BaseField = Felt;
    type PublicInputs = FriFoldPublicInputs;

    fn new(trace_info: TraceInfo, pi: FriFoldPublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
        ];
        Self {
            ctx: AirContext::new(trace_info, degrees, 5, options),
            pi,
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.ctx
    }

    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let x = cur[COL_X];
        let fp = cur[COL_FP];
        let fn_ = cur[COL_FN];
        let alpha = cur[COL_ALPHA];
        let bit = cur[COL_BIT];
        let folded = cur[COL_FOLDED];
        let acc = cur[COL_ACC];

        let one = E::ONE;
        let two = E::from(Felt::new(2));
        let c7 = E::from(Felt::new(7));
        let c13 = E::from(Felt::new(13));

        result[0] = bit * (bit - one);
        result[1] = two * x * folded - x * (fp + fn_) - alpha * (fp - fn_);
        result[2] = nxt[COL_X] - x * x;
        result[3] = (one - bit) * (nxt[COL_FP] - folded) + bit * (nxt[COL_FN] - folded);
        result[4] = nxt[COL_ACC] - (acc * c7 + alpha + folded * c13);
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let last = self.pi.rounds - 1;
        vec![
            Assertion::single(COL_X, 0, self.pi.x0),
            Assertion::single(COL_FP, 0, self.pi.f_pos0),
            Assertion::single(COL_FN, 0, self.pi.f_neg0),
            Assertion::single(COL_FOLDED, last, self.pi.final_eval),
            Assertion::single(COL_ACC, last, self.pi.final_acc),
        ]
    }
}

struct FriFoldProver {
    options: ProofOptions,
    pi: FriFoldPublicInputs,
}

impl Prover for FriFoldProver {
    type BaseField = Felt;
    type Air = FriFoldVerifyAir;
    type Trace = TraceTable<Felt>;
    type HashFn = RecHash;
    type VC = RecVc;
    type RandomCoin = RecCoin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, RecHash, RecVc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, RecHash, RecVc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, FriFoldVerifyAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> FriFoldPublicInputs {
        self.pi.clone()
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
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

pub fn prove_fri_folding(steps: &[FriFoldStep]) -> Result<(FriFoldPublicInputs, Vec<u8>), String> {
    let n = steps.len();
    if n < 8 || !n.is_power_of_two() {
        return Err("FRI folding trace length must be a power of two >= 8".into());
    }
    let inv2 = Felt::new(2).inv();
    let mut trace = TraceTable::init(vec![vec![Felt::ZERO; n]; FRI_WIDTH]);
    let mut acc = Felt::ONE;
    let mut final_eval = Felt::ZERO;
    let mut final_acc = Felt::ONE;

    let mut folded_vals = Vec::with_capacity(n);
    for (i, s) in steps.iter().enumerate() {
        if s.x == Felt::ZERO {
            return Err(format!("step {i}: domain point x cannot be zero"));
        }
        let folded = (s.f_pos + s.f_neg) * inv2 + s.alpha * (s.f_pos - s.f_neg) * (Felt::new(2) * s.x).inv();
        if i + 1 < n {
            if steps[i + 1].x != s.x * s.x {
                return Err(format!("step {i}: domain squaring mismatch"));
            }
            let expected_in = if s.next_is_neg { steps[i + 1].f_neg } else { steps[i + 1].f_pos };
            if expected_in != folded {
                return Err(format!("step {i}: folded continuity mismatch"));
            }
        }
        folded_vals.push(folded);
    }

    for (i, s) in steps.iter().enumerate() {
        let folded = folded_vals[i];
        trace.set(COL_X, i, s.x);
        trace.set(COL_FP, i, s.f_pos);
        trace.set(COL_FN, i, s.f_neg);
        trace.set(COL_ALPHA, i, s.alpha);
        trace.set(COL_BIT, i, if s.next_is_neg { Felt::ONE } else { Felt::ZERO });
        trace.set(COL_FOLDED, i, folded);
        trace.set(COL_ACC, i, acc);
        if i + 1 == n {
            final_eval = folded;
            final_acc = acc;
        }
        acc = acc * Felt::new(7) + s.alpha + folded * Felt::new(13);
    }

    let pi = FriFoldPublicInputs {
        x0: steps[0].x,
        f_pos0: steps[0].f_pos,
        f_neg0: steps[0].f_neg,
        final_eval,
        final_acc,
        rounds: n,
    };
    let prover = FriFoldProver {
        options: recursion_stark_options(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).map_err(|e| format!("FriFoldProver: {e}"))?;
    Ok((pi, proof.to_bytes()))
}

pub fn verify_fri_folding(pi: &FriFoldPublicInputs, proof_bytes: &[u8]) -> Result<u32, String> {
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("bad FRI fold proof: {e}"))?;
    let opts = recursion_stark_options();
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![opts]);
    let sec = proof.proven_security::<RecHash>().ldr_bits();
    winterfell::verify::<FriFoldVerifyAir, RecHash, RecCoin, RecVc>(proof, pi.clone(), &acceptable)
        .map_err(|e| format!("FriFoldVerifyAir rejected: {e}"))?;
    Ok(sec)
}

// ======================================================================================
// PART 2: BIT-EXACT SHA-256d PoW HEADER-CHAIN STARK (`HeaderChainAir`, 236 COLS <= 255)
// ======================================================================================

/// 4 consecutive 80-byte headers × 3 SHA-256 compressions/header × 65 rows/compression
/// (1 pre-row + 64 rounds) = 780 active rows inside a 1,024-row, 236-column SHA-384 STARK!
pub const HEADERS_PER_SEGMENT: usize = 4;
const HC_STRIDE: usize = 65; // row 0 = pre-row, rows 1..=64 = after rounds 0..=63
const HC_COMPS: usize = HEADERS_PER_SEGMENT * 3; // 12 compressions
const HC_ROWS: usize = 1024; // 780 active rows + 244 unused padding rows

// 236 columns (fits comfortably under Winterfell's 255-column limit!):
const S_A: usize = 0; // 32 bits of a_{t-1} (on pre-row: IV[1]; on row t+1: a_t)
const S_B: usize = 32; // 32 bits of b_{t-1} (on pre-row: IV[2]; on row t+1: b_t)
const S_E: usize = 64; // 32 bits of e_{t-1} (on pre-row: IV[5]; on row t+1: e_t)
const S_F: usize = 96; // 32 bits of f_{t-1} (on pre-row: IV[6]; on row t+1: f_t)
const S_CW: usize = 128; // word c_{t-1} (on pre-row: IV[3] = d_0; on row t+1: c_t)
const S_GW: usize = 129; // word g_{t-1} (on pre-row: IV[7] = h_0; on row t+1: g_t)
const S_AN: usize = 130; // word a_t (on pre-row: IV[0] = a_0; on row t+1: a_{t+1})
const S_EN: usize = 131; // word e_t (on pre-row: IV[4] = e_0; on row t+1: e_{t+1})
const S_CA: usize = 132; // 3 carry bits for a_{t+1} (placed on cur = row t)
const S_CE: usize = 135; // 3 carry bits for e_{t+1} (placed on cur = row t)
const S_W: usize = 138; // 16-word message schedule window W_t..W_{t+15}
const S_X1: usize = 154; // 32 bits of W_{t+1} on round rows; digest carries [0..8] on row 64
const S_X14: usize = 186; // 32 bits of W_{t+14} on round rows
const S_CWC: usize = 218; // 2 carry bits of W_{t+16}
const S_IV: usize = 220; // 8 words of block starting IV (constant across all 65 rows)
const S_DIG: usize = 228; // 8 words of final compression digest on row 64
const S_WIDTH: usize = 236;

// Periodic selectors (all cycle length HC_ROWS = 1024)
const HP_K: usize = 0; // K_t on transition row t (0..63) of each compression
const HP_ROUND: usize = 1; // 1 on rows 0..63 of each active compression (64 round transitions!)
const HP_WSCHED: usize = 2; // 1 on rows 0..62 of each active compression (W schedule shifts)
const HP_BND: usize = 3; // 1 on row 64 (final digest row) of each active compression
const HP_ACT: usize = 4; // 1 on all active rows 0..780
const HP_START: usize = 5; // 1 on row 0 (pre-row) of every active compression
const HP_STD_IV: usize = 6; // 1 on row 0 of comp 0 & comp 2 (standard FIPS IV)
const HP_CHAIN_IV: usize = 7; // 1 on row 64 of comp 0 -> row 0 of comp 1 (IV chaining!)
const HP_LINK_H1: usize = 8; // 1 on row 64 of comp 1 -> row 0 of comp 2 (digest h1 -> W[0..8])
const HP_LINK_PREV: usize = 9; // 1 on row 64 of comp 2 -> row 0 of next header's comp 0 (prev hash!)
const HP_PAD_B2: usize = 10; // 1 on row 0 of comp 1 (80-byte FIPS padding)
const HP_PAD_H2: usize = 11; // 1 on row 0 of comp 2 (32-byte FIPS padding)
const HP_N_PER: usize = 12;

/// Public inputs pinned by a pure-SHA-384 `HeaderChainAir` STARK proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderChainPublicInputs {
    pub start_prev_words: Word8,
    pub end_hash_words: Word8,
    pub count: u32,
}

impl ToElements<Felt> for HeaderChainPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(17);
        for w in self.start_prev_words {
            out.push(Felt::new(w as u64));
        }
        for w in self.end_hash_words {
            out.push(Felt::new(w as u64));
        }
        out.push(Felt::new(self.count as u64));
        out
    }
}

fn header_chain_periodic() -> Vec<Vec<Felt>> {
    let mut cols = vec![vec![Felt::ZERO; HC_ROWS]; HP_N_PER];
    for c in 0..HC_COMPS {
        let hdr_idx = c / 3;
        let sub = c % 3;
        let base = c * HC_STRIDE;
        for t in 0..HC_STRIDE {
            let r = base + t;
            cols[HP_ACT][r] = Felt::ONE;
            if t < 64 {
                cols[HP_K][r] = Felt::new(K[t] as u64);
                cols[HP_ROUND][r] = Felt::ONE;
            }
            if t < 63 {
                cols[HP_WSCHED][r] = Felt::ONE;
            }
            if t == 0 {
                cols[HP_START][r] = Felt::ONE;
                if sub == 0 || sub == 2 {
                    cols[HP_STD_IV][r] = Felt::ONE;
                }
                if sub == 1 {
                    cols[HP_PAD_B2][r] = Felt::ONE;
                }
                if sub == 2 {
                    cols[HP_PAD_H2][r] = Felt::ONE;
                }
            }
            if t == 64 {
                cols[HP_BND][r] = Felt::ONE;
                if sub == 0 {
                    cols[HP_CHAIN_IV][r] = Felt::ONE;
                } else if sub == 1 {
                    cols[HP_LINK_H1][r] = Felt::ONE;
                } else if sub == 2 && hdr_idx + 1 < HEADERS_PER_SEGMENT {
                    cols[HP_LINK_PREV][r] = Felt::ONE;
                }
            }
        }
    }
    cols
}

#[inline]
fn pack_bits_e<E: FieldElement + From<Felt>>(slice: &[E]) -> E {
    let mut acc = E::ZERO;
    let mut pow = E::ONE;
    let two = E::from(Felt::new(2));
    for &b in slice {
        acc += b * pow;
        pow *= two;
    }
    acc
}

#[inline]
fn xor3_e<E: FieldElement + From<Felt>>(x: E, y: E, z: E) -> E {
    let two = E::from(Felt::new(2));
    let four = E::from(Felt::new(4));
    x + y + z - two * (x * y + x * z + y * z) + four * x * y * z
}

#[inline]
fn rotr_xor3_e<E: FieldElement + From<Felt>>(bits: &[E], r1: usize, r2: usize, r3: usize) -> E {
    let mut acc = E::ZERO;
    let mut pow = E::ONE;
    let two = E::from(Felt::new(2));
    for k in 0..32 {
        let v = xor3_e(bits[(k + r1) & 31], bits[(k + r2) & 31], bits[(k + r3) & 31]);
        acc += v * pow;
        pow *= two;
    }
    acc
}

#[inline]
fn shr_rotr_xor3_e<E: FieldElement + From<Felt>>(bits: &[E], r1: usize, r2: usize, s3: usize) -> E {
    let mut acc = E::ZERO;
    let mut pow = E::ONE;
    let two = E::from(Felt::new(2));
    for k in 0..32 {
        let b3 = if k + s3 < 32 { bits[k + s3] } else { E::ZERO };
        let v = xor3_e(bits[(k + r1) & 31], bits[(k + r2) & 31], b3);
        acc += v * pow;
        pow *= two;
    }
    acc
}

fn compress_with_iv(block: &[u32; 16], iv: &Word8) -> (Word8, [u32; 79], [[u32; 8]; 65]) {
    let w = hash::schedule(block);
    let mut states = [[0u32; 8]; 65];
    states[0] = *iv;
    for t in 0..64 {
        let [a, b, c, d, e, f, g, h] = states[t];
        let t1 = h
            .wrapping_add(hash::big_s1(e))
            .wrapping_add(hash::ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = hash::big_s0(a).wrapping_add(hash::maj(a, b, c));
        states[t + 1] = [
            t1.wrapping_add(t2),
            a,
            b,
            c,
            d.wrapping_add(t1),
            e,
            f,
            g,
        ];
    }
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = iv[i].wrapping_add(states[64][i]);
    }
    (out, w, states)
}

pub fn sha256d_header_blocks(header_bytes: &[u8; 80]) -> ([u32; 16], [u32; 16], [u32; 16], Word8, Word8, Word8) {
    let mut b0 = [0u32; 16];
    for i in 0..16 {
        b0[i] = u32::from_be_bytes(header_bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut b1 = [0u32; 16];
    for i in 0..4 {
        b1[i] = u32::from_be_bytes(header_bytes[64 + 4 * i..64 + 4 * i + 4].try_into().unwrap());
    }
    b1[4] = 0x8000_0000;
    b1[15] = 640;

    let (s1, _, _) = compress_with_iv(&b0, &IV);
    let (h1, _, _) = compress_with_iv(&b1, &s1);

    let mut b2 = [0u32; 16];
    b2[..8].copy_from_slice(&h1);
    b2[8] = 0x8000_0000;
    b2[15] = 256;
    let h2 = compress(&b2);
    (b0, b1, b2, s1, h1, h2)
}

const HC_N_CONSTRAINTS: usize =
    128 // bits of a, b, e, f binary
    + 64 // bits of X1, X14 binary
    + 8 // carry bits CA(3), CE(3), CWC(2) binary
    + 2 // round step nxt.an & nxt.en (from cur+nxt bits!)
    + 6 // state shifts: nxt.a==cur.an, nxt.b==cur.a, nxt.cw==cur.b, nxt.e==cur.en, nxt.f==cur.e, nxt.gw==cur.f
    + 16 // W schedule: 15 shifts + 1 W_{t+16} recurrence
    + 2 // X1 == W[1], X14 == W[14]
    + 8 // IV constancy across all 64 transitions
    + 8 // pre-row (row 0) init from IV[0..8]
    + 8 // row 64 digest: DIG[i] + X1[i]*2^32 == IV[i] + final_state[i] (all deg 1!)
    + 8 // standard FIPS IV check on row 0 of comp 0 & 2
    + 8 // IV chaining comp 0 row 64 -> comp 1 row 0
    + 8 // h1 linkage comp 1 row 64 -> comp 2 row 0 W[0..8]
    + 8 // prev-hash linkage comp 2 row 64 -> next header comp 0 row 0 W[1..9]
    + 12 // FIPS 80-byte padding on comp 1 row 0
    + 8; // FIPS 32-byte padding on comp 2 row 0

pub struct HeaderChainAir {
    ctx: AirContext<Felt>,
    pi: HeaderChainPublicInputs,
}

impl Air for HeaderChainAir {
    type BaseField = Felt;
    type PublicInputs = HeaderChainPublicInputs;

    fn new(trace_info: TraceInfo, pi: HeaderChainPublicInputs, options: ProofOptions) -> Self {
        let mut degrees = Vec::with_capacity(HC_N_CONSTRAINTS);
        // 128 + 64 + 8 = 200 binary checks (deg 2 * periodic)
        for _ in 0..200 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![HC_ROWS]));
        }
        // 2 round step equations (xor3/maj = deg 3, * is_round periodic)
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![HC_ROWS]));
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![HC_ROWS]));
        // 6 shifts + 15 W shifts = 21 deg-1
        for _ in 0..21 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![HC_ROWS]));
        }
        // 1 W_{t+16} recurrence (xor3 => deg 3)
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![HC_ROWS]));
        // Remaining 2 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 12 + 8 = 78 deg-1 * periodic
        for _ in 0..78 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![HC_ROWS]));
        }
        assert_eq!(degrees.len(), HC_N_CONSTRAINTS);
        Self {
            ctx: AirContext::new(trace_info, degrees, 16, options),
            pi,
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.ctx
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        header_chain_periodic()
    }

    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        per: &[E],
        res: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let one = E::ONE;
        let two = E::from(Felt::new(2));
        let pow32 = E::from(Felt::new(1u64 << 32));

        let k_t = per[HP_K];
        let is_round = per[HP_ROUND];
        let is_wsched = per[HP_WSCHED];
        let is_bnd = per[HP_BND];
        let is_act = per[HP_ACT];
        let is_start = per[HP_START];
        let is_std_iv = per[HP_STD_IV];
        let is_chain_iv = per[HP_CHAIN_IV];
        let is_link_h1 = per[HP_LINK_H1];
        let is_link_prev = per[HP_LINK_PREV];
        let is_pad_b2 = per[HP_PAD_B2];
        let is_pad_h2 = per[HP_PAD_H2];

        let mut idx = 0usize;
        // 1. Binary checks for a, b, e, f (128), X1 (32), X14 (32), carries (8)
        for col in 0..128 {
            let b = cur[col];
            res[idx] = is_act * b * (b - one);
            idx += 1;
        }
        for j in 0..32 {
            let b1 = cur[S_X1 + j];
            res[idx] = is_act * b1 * (b1 - one);
            idx += 1;
        }
        for j in 0..32 {
            let b14 = cur[S_X14 + j];
            res[idx] = is_act * b14 * (b14 - one);
            idx += 1;
        }
        for col in [S_CA, S_CA + 1, S_CA + 2, S_CE, S_CE + 1, S_CE + 2, S_CWC, S_CWC + 1] {
            let b = cur[col];
            res[idx] = is_act * b * (b - one);
            idx += 1;
        }

        // Round t evaluated on frame (cur = row t, nxt = row t+1):
        //   a_t = nxt[S_A], b_t = cur[S_A], c_t = cur[S_B], d_t = cur[S_CW]
        //   e_t = nxt[S_E], f_t = cur[S_E], g_t = cur[S_F], h_t = cur[S_GW]
        let a_bits = &nxt[S_A..S_A + 32];
        let b_bits = &cur[S_A..S_A + 32];
        let c_bits = &cur[S_B..S_B + 32];
        let e_bits = &nxt[S_E..S_E + 32];
        let f_bits = &cur[S_E..S_E + 32];
        let g_bits = &cur[S_F..S_F + 32];

        let sig0 = rotr_xor3_e(a_bits, 2, 13, 22);
        let sig1 = rotr_xor3_e(e_bits, 6, 11, 25);

        let mut maj = E::ZERO;
        let mut ch = E::ZERO;
        let mut p = E::ONE;
        for k in 0..32 {
            let (ak, bk, ck) = (a_bits[k], b_bits[k], c_bits[k]);
            maj += (ak * bk + ak * ck + bk * ck - two * ak * bk * ck) * p;
            let (ek, fk, gk) = (e_bits[k], f_bits[k], g_bits[k]);
            ch += (ek * fk + (one - ek) * gk) * p;
            p *= two;
        }

        let t1 = cur[S_GW] + sig1 + ch + cur[S_W];
        let t2 = sig0 + maj;
        let ca = pack_bits_e(&cur[S_CA..S_CA + 3]);
        let ce = pack_bits_e(&cur[S_CE..S_CE + 3]);

        // Round t outputs a_{t+1} = nxt[S_AN], e_{t+1} = nxt[S_EN]
        // Note: k_t is already 0 outside round rows, avoiding periodic*periodic multiplication.
        res[idx] = is_round * (nxt[S_AN] + ca * pow32 - (t1 + t2)) - k_t;
        idx += 1;
        res[idx] = is_round * (nxt[S_EN] + ce * pow32 - (cur[S_CW] + t1)) - k_t;
        idx += 1;

        // 6 state shifts on every round transition (0..63)
        let cur_a_w = pack_bits_e(b_bits);
        let cur_b_w = pack_bits_e(c_bits);
        let cur_e_w = pack_bits_e(f_bits);
        let cur_f_w = pack_bits_e(g_bits);
        res[idx] = is_round * (pack_bits_e(a_bits) - cur[S_AN]);
        idx += 1;
        res[idx] = is_round * (pack_bits_e(&nxt[S_B..S_B + 32]) - cur_a_w);
        idx += 1;
        res[idx] = is_round * (nxt[S_CW] - cur_b_w);
        idx += 1;
        res[idx] = is_round * (pack_bits_e(e_bits) - cur[S_EN]);
        idx += 1;
        res[idx] = is_round * (pack_bits_e(&nxt[S_F..S_F + 32]) - cur_e_w);
        idx += 1;
        res[idx] = is_round * (nxt[S_GW] - cur_f_w);
        idx += 1;

        // Message schedule W[0..15] shift + W_{t+16} recurrence on rows 0..62 (is_wsched)
        for j in 0..15 {
            res[idx] = is_wsched * (nxt[S_W + j] - cur[S_W + j + 1]);
            idx += 1;
        }
        let s0 = shr_rotr_xor3_e(&cur[S_X1..S_X1 + 32], 7, 18, 3);
        let s1 = shr_rotr_xor3_e(&cur[S_X14..S_X14 + 32], 17, 19, 10);
        let cwc = pack_bits_e(&cur[S_CWC..S_CWC + 2]);
        res[idx] = is_wsched * (nxt[S_W + 15] + cwc * pow32 - (cur[S_W] + s0 + cur[S_W + 9] + s1));
        idx += 1;

        // X1 == W[1], X14 == W[14] on rows 0..62
        res[idx] = is_wsched * (pack_bits_e(&cur[S_X1..S_X1 + 32]) - cur[S_W + 1]);
        idx += 1;
        res[idx] = is_wsched * (pack_bits_e(&cur[S_X14..S_X14 + 32]) - cur[S_W + 14]);
        idx += 1;

        // IV constant across all 64 round transitions (0..63 -> 1..64)
        for i in 0..8 {
            res[idx] = is_round * (nxt[S_IV + i] - cur[S_IV + i]);
            idx += 1;
        }

        // Pre-row (row 0 of each compression): initialize registers from IV[0..8]
        // an=IV[0], a=IV[1], b=IV[2], cw=IV[3], en=IV[4], e=IV[5], f=IV[6], gw=IV[7]
        let pre_words = [
            cur[S_AN], cur_a_w, cur_b_w, cur[S_CW],
            cur[S_EN], cur_e_w, cur_f_w, cur[S_GW],
        ];
        for i in 0..8 {
            res[idx] = is_start * (pre_words[i] - cur[S_IV + i]);
            idx += 1;
        }

        // Row 64 (is_bnd): final state_64 is already in [an, a, b, cw, en, e, f, gw]! (ALL DEGREE 1!)
        for i in 0..8 {
            let carry_bit = cur[S_X1 + i];
            res[idx] = is_bnd * (cur[S_DIG + i] + carry_bit * pow32 - (cur[S_IV + i] + pre_words[i]));
            idx += 1;
        }

        // Standard FIPS IV check on row 0 of comp 0 & comp 2
        for i in 0..8 {
            res[idx] = is_std_iv * (cur[S_IV + i] - E::from(Felt::new(IV[i] as u64)));
            idx += 1;
        }

        // IV chaining: comp 0 row 64 DIG -> comp 1 row 0 IV
        for i in 0..8 {
            res[idx] = is_chain_iv * (nxt[S_IV + i] - cur[S_DIG + i]);
            idx += 1;
        }

        // h1 linkage: comp 1 row 64 DIG -> comp 2 row 0 W[0..8]
        for i in 0..8 {
            res[idx] = is_link_h1 * (nxt[S_W + i] - cur[S_DIG + i]);
            idx += 1;
        }

        // Prev-hash linkage: comp 2 row 64 DIG of header i -> comp 0 row 0 W[1..9] of header i+1!
        for i in 0..8 {
            res[idx] = is_link_prev * (nxt[S_W + 1 + i] - cur[S_DIG + i]);
            idx += 1;
        }

        // FIPS 80-byte padding on comp 1 row 0
        res[idx] = is_pad_b2 * (cur[S_W + 4] - E::from(Felt::new(0x8000_0000u64)));
        idx += 1;
        for j in 5..15 {
            res[idx] = is_pad_b2 * cur[S_W + j];
            idx += 1;
        }
        res[idx] = is_pad_b2 * (cur[S_W + 15] - E::from(Felt::new(640)));
        idx += 1;

        // FIPS 32-byte padding on comp 2 row 0
        res[idx] = is_pad_h2 * (cur[S_W + 8] - E::from(Felt::new(0x8000_0000u64)));
        idx += 1;
        for j in 9..15 {
            res[idx] = is_pad_h2 * cur[S_W + j];
            idx += 1;
        }
        res[idx] = is_pad_h2 * (cur[S_W + 15] - E::from(Felt::new(256)));
        idx += 1;

        debug_assert_eq!(idx, HC_N_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut out = Vec::with_capacity(16);
        for i in 0..8 {
            out.push(Assertion::single(S_W + 1 + i, 0, Felt::new(self.pi.start_prev_words[i] as u64)));
        }
        let last_row = HC_COMPS * HC_STRIDE - 1;
        for i in 0..8 {
            out.push(Assertion::single(S_DIG + i, last_row, Felt::new(self.pi.end_hash_words[i] as u64)));
        }
        out
    }
}

struct HeaderChainProver {
    options: ProofOptions,
    pi: HeaderChainPublicInputs,
}

impl Prover for HeaderChainProver {
    type BaseField = Felt;
    type Air = HeaderChainAir;
    type Trace = TraceTable<Felt>;
    type HashFn = RecHash;
    type VC = RecVc;
    type RandomCoin = RecCoin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, RecHash, RecVc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, RecHash, RecVc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, HeaderChainAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> HeaderChainPublicInputs {
        self.pi.clone()
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
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

fn write_bits(trace: &mut TraceTable<Felt>, col: usize, row: usize, val: u32, nbits: usize) {
    for k in 0..nbits {
        trace.set(col + k, row, Felt::new(((val >> k) & 1) as u64));
    }
}

fn fill_sha256_block(trace: &mut TraceTable<Felt>, base_row: usize, block: &[u32; 16], iv: &Word8) {
    let (dig, w, states) = compress_with_iv(block, iv);
    // Row base_row + 0 (pre-row) through base_row + 64 (final row after round 63):
    // Row `s` (`0..=64`) stores:
    //   an = states[s][0], a = states[s][1], b = states[s][2], cw = states[s][3],
    //   en = states[s][4], e = states[s][5], f = states[s][6], gw = states[s][7]!
    for s in 0..HC_STRIDE {
        let r = base_row + s;
        let [s0, s1, s2, s3, s4, s5, s6, s7] = states[s];
        trace.set(S_AN, r, Felt::new(s0 as u64));
        write_bits(trace, S_A, r, s1, 32);
        write_bits(trace, S_B, r, s2, 32);
        trace.set(S_CW, r, Felt::new(s3 as u64));
        trace.set(S_EN, r, Felt::new(s4 as u64));
        write_bits(trace, S_E, r, s5, 32);
        write_bits(trace, S_F, r, s6, 32);
        trace.set(S_GW, r, Felt::new(s7 as u64));

        for i in 0..8 {
            trace.set(S_IV + i, r, Felt::new(iv[i] as u64));
        }

        if s < 64 {
            // Round s runs on frame (cur = base + s, nxt = base + s + 1)
            let [a, b, c, d, e, f, g, h] = states[s];
            let t1 = (h as u64)
                + (hash::big_s1(e) as u64)
                + (hash::ch(e, f, g) as u64)
                + (K[s] as u64)
                + (w[s] as u64);
            let t2 = (hash::big_s0(a) as u64) + (hash::maj(a, b, c) as u64);
            write_bits(trace, S_CA, r, ((t1 + t2) >> 32) as u32, 3);
            write_bits(trace, S_CE, r, (((d as u64) + t1) >> 32) as u32, 3);
            for j in 0..16 {
                trace.set(S_W + j, r, Felt::new(w[s + j] as u64));
            }
            if s < 63 {
                write_bits(trace, S_X1, r, w[s + 1], 32);
                write_bits(trace, S_X14, r, w[s + 14], 32);
                let sum_w = (w[s] as u64)
                    + (hash::small_s0(w[s + 1]) as u64)
                    + (w[s + 9] as u64)
                    + (hash::small_s1(w[s + 14]) as u64);
                write_bits(trace, S_CWC, r, (sum_w >> 32) as u32, 2);
            }
        } else {
            // Row 64: digest carries in S_X1[0..8] and final digest in S_DIG[0..8]
            for i in 0..8 {
                let sum = (iv[i] as u64) + (states[64][i] as u64);
                trace.set(S_X1 + i, r, Felt::new(sum >> 32));
                trace.set(S_DIG + i, r, Felt::new(dig[i] as u64));
            }
        }
    }
}

pub fn prove_header_chain_segment(headers: &[Header; HEADERS_PER_SEGMENT]) -> Result<(HeaderChainPublicInputs, Vec<u8>), String> {
    let mut trace = TraceTable::init(vec![vec![Felt::ZERO; HC_ROWS]; S_WIDTH]);
    let mut prev_hash = headers[0].prev;
    let mut end_hash_words = [0u32; 8];

    for (i, hd) in headers.iter().enumerate() {
        if i > 0 && hd.prev != prev_hash {
            return Err(format!("header {i} prev hash does not link to header {}", i - 1));
        }
        let raw = hd.bytes();
        let (b0, b1, b2, s1, _h1, h2) = sha256d_header_blocks(&raw);
        let base = i * 3 * HC_STRIDE;
        fill_sha256_block(&mut trace, base, &b0, &IV);
        fill_sha256_block(&mut trace, base + HC_STRIDE, &b1, &s1);
        fill_sha256_block(&mut trace, base + 2 * HC_STRIDE, &b2, &IV);
        let expected = sha256d(&raw);
        debug_assert_eq!(hash::words_to_bytes(&h2), expected);
        prev_hash = expected;
        end_hash_words = h2;
    }

    let pi = HeaderChainPublicInputs {
        start_prev_words: hash::bytes_to_words(&headers[0].prev),
        end_hash_words,
        count: HEADERS_PER_SEGMENT as u32,
    };
    let prover = HeaderChainProver {
        options: recursion_stark_options(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).map_err(|e| format!("HeaderChainProver: {e}"))?;
    Ok((pi, proof.to_bytes()))
}

pub fn verify_header_chain_segment(pi: &HeaderChainPublicInputs, proof_bytes: &[u8]) -> Result<u32, String> {
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("bad header chain proof: {e}"))?;
    let opts = recursion_stark_options();
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![opts]);
    let sec = proof.proven_security::<RecHash>().ldr_bits();
    winterfell::verify::<HeaderChainAir, RecHash, RecCoin, RecVc>(proof, pi.clone(), &acceptable)
        .map_err(|e| format!("HeaderChainAir rejected: {e}"))?;
    Ok(sec)
}

pub fn verify_folded_header_segments(
    segments: &[(HeaderChainPublicInputs, Vec<u8>)],
) -> Result<([u8; 32], [u8; 32], u32, u32), String> {
    if segments.is_empty() {
        return Err("empty segment chain".into());
    }
    let start_prev = hash::words_to_bytes(&segments[0].0.start_prev_words);
    let mut cur_end = segments[0].0.start_prev_words;
    let mut total_headers = 0u32;
    let mut min_sec = u32::MAX;
    for (i, (pi, proof)) in segments.iter().enumerate() {
        if i > 0 && pi.start_prev_words != cur_end {
            return Err(format!("header segment {i} discontinuity"));
        }
        let sec = verify_header_chain_segment(pi, proof)?;
        min_sec = min_sec.min(sec);
        cur_end = pi.end_hash_words;
        total_headers += pi.count;
    }
    Ok((start_prev, hash::words_to_bytes(&cur_end), total_headers, min_sec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mine;

    #[test]
    fn fri_folding_verifier_stark_proves_verifies_and_rejects_forgery() {
        let mut steps = Vec::new();
        let mut x = Felt::new(7);
        let mut f_pos = Felt::new(12345);
        let mut f_neg = Felt::new(67890);
        let inv2 = Felt::new(2).inv();
        for r in 0..16u64 {
            let alpha = Felt::new(1000 + r * 37);
            let next_is_neg = (r % 2) == 1;
            steps.push(FriFoldStep { x, f_pos, f_neg, alpha, next_is_neg });
            let folded = (f_pos + f_neg) * inv2 + alpha * (f_pos - f_neg) * (Felt::new(2) * x).inv();
            x = x * x;
            let sib = Felt::new(9000 + r * 13);
            if next_is_neg {
                f_pos = sib;
                f_neg = folded;
            } else {
                f_pos = folded;
                f_neg = sib;
            }
        }

        let (pi, proof) = prove_fri_folding(&steps).unwrap();
        let sec = verify_fri_folding(&pi, &proof).unwrap();
        assert!(sec >= 150, "expected >= 150 proven Goldilocks LDR bits (128-bit QROM SHA-384), got {sec}");

        let mut forged = pi.clone();
        forged.final_eval += Felt::ONE;
        assert!(verify_fri_folding(&forged, &proof).is_err());
    }

    #[test]
    fn bit_exact_sha256d_header_chain_stark_proves_folds_and_rejects_tamper() {
        let mut prev = [0x11u8; 32];
        let mut all_headers = Vec::new();
        for i in 0..(HEADERS_PER_SEGMENT * 2) {
            let mut hd = Header {
                version: 1,
                prev,
                commit: [i as u8; 32],
                time: 1_762_473_600 + (i as u32) * 600,
                bits: 0x207fffff,
                nonce: 0,
            };
            assert!(mine(&mut hd, u64::MAX));
            prev = hd.hash();
            all_headers.push(hd);
        }

        let seg1_h: [Header; HEADERS_PER_SEGMENT] = all_headers[0..4].try_into().unwrap();
        let seg2_h: [Header; HEADERS_PER_SEGMENT] = all_headers[4..8].try_into().unwrap();
        let (pi1, p1) = prove_header_chain_segment(&seg1_h).unwrap();
        let (pi2, p2) = prove_header_chain_segment(&seg2_h).unwrap();

        let (start, end, count, sec) =
            verify_folded_header_segments(&[(pi1.clone(), p1.clone()), (pi2.clone(), p2.clone())])
                .unwrap();
        assert_eq!(start, [0x11u8; 32]);
        assert_eq!(end, all_headers[7].hash());
        assert_eq!(count, 8);
        assert!(sec >= 140, "expected >= 140 proven Goldilocks LDR bits (128-bit QROM SHA-384), got {sec}");

        let mut bad_pi = pi2.clone();
        bad_pi.end_hash_words[0] ^= 1;
        assert!(verify_header_chain_segment(&bad_pi, &p2).is_err());
    }
}
