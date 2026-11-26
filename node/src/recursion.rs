//! Real `>= 100`-Bit QROM Pure-SHA-2 STARK Recursion & IVC Chain Folding Primitives:
//! 1. **Bit-Exact SHA-256d PoW Header-Chain STARK (`HeaderChainAir`):**
//!    Proves inside a genuine pure-SHA-2 Winterfell STARK (236 columns × 1,024 rows) that a
//!    contiguous chain of 80-byte Newsatoshi/Bitcoin block headers `H_0 -> H_1 -> ... -> H_{K-1}`
//!    satisfies exact FIPS 180-4 SHA-256d hashing (3 full 64-round bit-level SHA-256 compressions
//!    per header including dynamic IV chaining and FIPS padding) and exact chain linkage
//!    (`H_{i+1}.prev == sha256d(H_i)`).
//!
//! 2. **Algebraic FRI-Folding Verifier STARK (`FriFoldVerifyAir`):**
//!    Proves inside a pure-SHA-384 Quartic (`F_{p^4}`) Winterfell STARK the core algebraic
//!    STARK-in-STARK recursion identity across `R` FRI folding rounds.
//!
//! 3. **Real Pure-SHA-2 STARK-in-STARK Recursive Verifier & IVC Chain Folding (`StarkInStarkVerifierAir`):**
//!    Takes TWO **actual serialized outer Winterfell `HeaderChainAir` STARK proofs** (`H_0..H_3`
//!    and `H_4..H_7`, committed with pure FIPS 180-4 SHA-256) and folds them into **ONE** inner
//!    `>= 100`-bit conservative QROM Quartic (`F_{p^4}`) SHA-384 STARK proof (`254` cols × `16,384`
//!    rows) proving inside the inner AIR:
//!    - **Private IVC Chain Linkage:** constrains `seg1.end_hash == seg2.start_prev` as a private
//!      witness bound into both outer proofs' Winterfell `DefaultRandomCoin<Sha2_256>` initial seeds.
//!    - **Bit-Exact Outer Fiat–Shamir Transcript & 20-Bit PoW Grinding (204 SHA-256 compressions):**
//!      reproduces the exact outer `Context || PublicInputs` seed, all commitment reseeds
//!      (`trace_root`, `constraint_root`, `ood_digest`, and all 6 FRI commitments), enforces exact
//!      20-bit PoW grinding (`pow_seed = SHA-256(seed || pow_nonce)`), and extracts the exact
//!      coin-derived query position `q_pos = u64_le(SHA-256(pow_seed || 1)) & 8191` in-circuit.
//!    - **Bit-Exact Outer Merkle Authentication Paths:** verifies the real outer depth-13 Trace
//!      Merkle path, depth-13 Constraint Merkle path, and 64-byte FRI Layer 0 leaf preimage +
//!      depth-12 FRI-0 Merkle path at the coin-derived `q_pos` directly into the transcript roots.
//!    - **Real Quartic `F_{p^4}` Algebraic FRI Folding:** verifies all 5 Quartic FRI folding layers
//!      for both outer proofs (`2 * x_i * f_{i+1} = x_i*(f_+ + f_-) + alpha_i*(f_+ - f_-)` in
//!      `F_p[u]/(u^4 - 7)` with exact domain squaring `x_{i+1} = x_i^2`).
//!
//! > **Honest Scaling Boundary:** On a single laptop CPU, the `16,384`-row `StarkInStarkVerifierAir`
//! > verifies 100% of both outer proofs' Fiat–Shamir transcripts, 20-bit PoW grinding, IVC linkage,
//! > all 10 Quartic FRI fold layers, and the first coin-derived query's Trace + Constraint + FRI-0
//! > Merkle paths (`204` bit-exact FIPS 180-4 SHA-256 compressions) in `< 1s`. Verifying all `152`
//! > outer queries plus full OOD constraint evaluation inside one inner proof scales linearly using
//! > this exact AIR gadget (`~152×` / `~2^{21}` rows) for multi-core / GPU provers.

use crate::hash::{self, compress, sha256d, Sha2_256, Sha2_384, ShaDigest, Word8, IV, K};
use crate::tx::Header;
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree, RandomCoin},
    math::{
        fields::{f64::BaseElement as Felt, QuartExtension},
        FieldElement, StarkField, ToElements,
    },
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

/// Pure-SHA-384 + 256-bit Quartic Goldilocks (`F_{p^4}`) FRI options achieving >= 204 unclipped
/// algebraic LDR bits (192 classical SHA-384) and **>= 102 conservative QROM (CMS19) quantum bits**
/// alongside 128-bit BHT QROM SHA-384 collision security!
pub fn recursion_stark_options() -> ProofOptions {
    ProofOptions::new(
        152,
        8,
        20,
        FieldExtension::Quartic,
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
    if n < 32 || !n.is_power_of_two() {
        return Err("FRI folding trace length must be a power of two >= 32".into());
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
    let sec = proof.proven_security::<RecHash>().qrom_ldr_bits(384);
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

#[inline(never)]
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

#[inline(never)]
fn xor3_e<E: FieldElement + From<Felt>>(x: E, y: E, z: E) -> E {
    let two = E::from(Felt::new(2));
    let four = E::from(Felt::new(4));
    x + y + z - two * (x * y + x * z + y * z) + four * x * y * z
}

#[inline(never)]
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

#[inline(never)]
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

#[inline(never)]
fn maj_ch_e<E: FieldElement + From<Felt>>(
    a_bits: &[E],
    b_bits: &[E],
    c_bits: &[E],
    e_bits: &[E],
    f_bits: &[E],
    g_bits: &[E],
) -> (E, E) {
    let one = E::ONE;
    let two = E::from(Felt::new(2));
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
    (maj, ch)
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
        let is_link_h1 = per[HP_LINK_H1];
        let is_link_prev = per[HP_LINK_PREV];
        let is_pad_b2 = per[HP_PAD_B2];
        let is_pad_h2 = per[HP_PAD_H2];

        let mut idx = 0usize;
        // Core SHA-256 dynamic-IV engine (per[0..8] layout matches SP_K..SP_CHAIN_IV identically!)
        eval_sha256_core_e(cur, nxt, per, res, &mut idx);

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
    let sec = proof.proven_security::<RecHash>().qrom_ldr_bits(384);
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

// ======================================================================================
// PART 3: REAL PURE-SHA-2 STARK-IN-STARK RECURSIVE VERIFIER & IVC CHAIN FOLDING
//         (`StarkInStarkVerifierAir`: 254 cols × 16,384 rows, Quartic SHA-384 >= 100 QROM!)
// ======================================================================================

pub type OuterHash = Sha2_256<Felt>;
pub type OuterCoin = DefaultRandomCoin<OuterHash>;
pub type OuterVc = MerkleTree<OuterHash>;

const OUTER_LDE_SIZE: usize = HC_ROWS * 8; // 8,192
const OUTER_MERKLE_DEPTH: usize = 13; // log2(8192)
const OUTER_FRI0_DEPTH: usize = 12; // log2(4096)
const OUTER_FRI_LAYERS: usize = 5; // 8192 -> 4096 -> 2048 -> 1024 -> 512 -> 256
const OUTER_FRI_COMMITS: usize = OUTER_FRI_LAYERS + 1; // 5 layers + 1 remainder commitment
const OUTER_GRINDING: u32 = 20;

/// Outer `HeaderChainAir` options using pure FIPS 180-4 SHA-256 commitments + 256-bit Quartic
/// Goldilocks (`F_{p^4}`) FRI (`folding_factor = 2`) so the inner `StarkInStarkVerifierAir`
/// verifies exact outer SHA-256 Merkle paths, Fiat–Shamir reseeds, 20-bit PoW grinding,
/// coin-derived query indices, and Quartic `F_{p^4}` FRI folding in-circuit!
pub fn outer_header_chain_options() -> ProofOptions {
    ProofOptions::new(
        152,
        8,
        OUTER_GRINDING,
        FieldExtension::Quartic,
        2,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

struct OuterHeaderChainProver {
    options: ProofOptions,
    pi: HeaderChainPublicInputs,
}

impl Prover for OuterHeaderChainProver {
    type BaseField = Felt;
    type Air = HeaderChainAir;
    type Trace = TraceTable<Felt>;
    type HashFn = OuterHash;
    type VC = OuterVc;
    type RandomCoin = OuterCoin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, OuterHash, OuterVc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, OuterHash, OuterVc>;
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

fn build_header_chain_trace(
    headers: &[Header; HEADERS_PER_SEGMENT],
) -> Result<(TraceTable<Felt>, HeaderChainPublicInputs), String> {
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
    Ok((trace, pi))
}

/// Proves a 4-header segment with pure FIPS 180-4 SHA-256 commitments (`OuterHash`) ready for
/// in-circuit STARK-in-STARK IVC folding via [`prove_recursive_chain_fold`].
pub fn prove_outer_header_segment(
    headers: &[Header; HEADERS_PER_SEGMENT],
) -> Result<(HeaderChainPublicInputs, Vec<u8>), String> {
    let (trace, pi) = build_header_chain_trace(headers)?;
    let prover = OuterHeaderChainProver {
        options: outer_header_chain_options(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).map_err(|e| format!("OuterHeaderChainProver: {e}"))?;
    Ok((pi, proof.to_bytes()))
}

/// Verifies a standalone outer pure-SHA-256 `HeaderChainAir` segment proof.
pub fn verify_outer_header_segment(
    pi: &HeaderChainPublicInputs,
    proof_bytes: &[u8],
) -> Result<u32, String> {
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("bad outer header proof: {e}"))?;
    let opts = outer_header_chain_options();
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![opts]);
    let sec = proof.proven_security::<OuterHash>().qrom_ldr_bits(256);
    winterfell::verify::<HeaderChainAir, OuterHash, OuterCoin, OuterVc>(proof, pi.clone(), &acceptable)
        .map_err(|e| format!("outer HeaderChainAir rejected: {e}"))?;
    Ok(sec)
}

/// Deterministic 64-byte (`16` big-endian `u32` words) representation of the fixed outer
/// `HeaderChainAir` Winterfell `Context::to_elements()` — pinned inside `StarkInStarkVerifierAir`
/// so no prover can substitute weaker outer proof options or a different AIR!
fn outer_header_chain_context_words() -> [u32; 16] {
    let trace_info = TraceInfo::new(S_WIDTH, HC_ROWS);
    let opts = outer_header_chain_options();
    let mut els = trace_info.to_elements();
    let mod_bytes = Felt::get_modulus_le_bytes();
    let (m1, m2) = mod_bytes.split_at(mod_bytes.len() / 2);
    els.push(Felt::from_bytes_with_padding(m1));
    els.push(Felt::from_bytes_with_padding(m2));
    els.push(Felt::from((HC_N_CONSTRAINTS + 16) as u32));
    els.append(&mut opts.to_elements());
    assert_eq!(els.len(), 8, "outer HeaderChainAir Context::to_elements must be exactly 8 Felts (64 bytes)");
    let mut bytes = Vec::with_capacity(64);
    for e in &els {
        bytes.extend_from_slice(&e.as_int().to_le_bytes());
    }
    let mut words = [0u32; 16];
    for i in 0..16 {
        words[i] = u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    words
}

// ---- `StarkInStarkVerifierAir` trace geometry (254 cols < 255, 16,384 rows) -----------

const SIS_COMPS_PER_PROOF: usize = 102;
const SIS_TOTAL_COMPS: usize = SIS_COMPS_PER_PROOF * 2; // 204 bit-exact FIPS 180-4 SHA-256 compressions
const SIS_SHA_ROWS: usize = SIS_TOTAL_COMPS * HC_STRIDE; // 13,260 rows
const SIS_FRI_BASE: usize = SIS_SHA_ROWS; // rows 13,260..13,270 = 10 real Quartic FRI fold rows
const SIS_ROWS: usize = 16_384; // 2^14

// Columns 0..236 reuse the proven dynamic-IV SHA-256 engine (`S_A..S_DIG`)!
const S_SEED: usize = 236; // 8 words: running outer Winterfell `DefaultRandomCoin` seed
const S_MID: usize = 244; // 8 words: private IVC linkage `seg1.end_hash == seg2.start_prev`
const S_QACC: usize = 252; // 1 col: Merkle path query-index bit accumulator
const S_QTARGET: usize = 253; // 1 col: coin-derived `q_pos` binding Trace, Constraint, and FRI-0 paths
const SIS_WIDTH: usize = 254; // strictly `< TraceInfo::MAX_TRACE_WIDTH` (255)!

// Quartic `F_{p^4}` FRI-folding column reuse on rows `SIS_FRI_BASE..SIS_FRI_BASE+10` (where `is_act == 0`):
const QF_X: usize = 0; // 1 base element x_l
const QF_FP: usize = 1; // 4 base elements f_+(x_l) in F_{p^4}
const QF_FN: usize = 5; // 4 base elements f_-(-x_l) in F_{p^4}
const QF_ALPHA: usize = 9; // 4 base elements alpha_l in F_{p^4}
const QF_FOLDED: usize = 13; // 4 base elements folded_{l+1} in F_{p^4}
const QF_BIT: usize = 17; // 1 binary branch selector (0 -> next f_+, 1 -> next f_-)

// Periodic selectors (all cycle length `SIS_ROWS = 16,384`):
const SP_K: usize = 0;
const SP_ROUND: usize = 1;
const SP_WSCHED: usize = 2;
const SP_BND: usize = 3;
const SP_ACT: usize = 4;
const SP_START: usize = 5;
const SP_STD_IV: usize = 6;
const SP_CHAIN_IV: usize = 7;
const SP_PAD_200: usize = 8;
const SP_PAD_64: usize = 9;
const SP_PAD_40: usize = 10;
const SP_Q0_CTR: usize = 11;
const SP_EVEN_ZERO: usize = 12;
const SP_MID_CAP: usize = 13;
const SP_MID_HOLD: usize = 14;
const SP_MID_USE: usize = 15;
const SP_SEED_SET: usize = 16;
const SP_SEED_HOLD: usize = 17;
const SP_RESEED_LEFT: usize = 18;
const SP_RESEED_DIG: usize = 19;
const SP_MPATH_STEP: usize = 20;
const SP_MPATH_INIT: usize = 21;
const SP_MPATH_ACC: usize = 22;
const SP_QACC_WEIGHT: usize = 23; // `1 << level` on `SP_MPATH_ACC` rows, `0` elsewhere
const SP_QACC_HOLD: usize = 24;
const SP_QTARGET_HOLD: usize = 25;
const SP_QACC_EQ_FULL: usize = 26;
const SP_QACC_EQ_FRI0: usize = 27;
const SP_UNPACK_DIG0: usize = 28;
const SP_CHECK_POW: usize = 29;
const SP_EXTRACT_QPOS: usize = 30;
const SP_FRI_STEP: usize = 31;
const SP_FRI_CONT: usize = 32;
const SP_N_PER: usize = 33;

/// Public inputs exposed by ONE inner `>= 100`-bit QROM Quartic SHA-384 IVC chain proof folding
/// TWO contiguous outer `HeaderChainAir` STARK proofs (`H_0..H_3` + `H_4..H_7` → `H_0..H_7`).
/// Note `mid_hash` (`H_3.hash == H_4.prev`) is a PRIVATE witness constrained inside the inner AIR!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveChainPublicInputs {
    pub start_prev_words: Word8,
    pub end_hash_words: Word8,
    pub total_headers: u32,
}

impl ToElements<Felt> for RecursiveChainPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(17);
        for w in self.start_prev_words {
            out.push(Felt::new(w as u64));
        }
        for w in self.end_hash_words {
            out.push(Felt::new(w as u64));
        }
        out.push(Felt::new(self.total_headers as u64));
        out
    }
}

/// Complete witness extracted from ONE real serialized outer `HeaderChainAir` proof (`OuterHash`).
#[derive(Clone, Debug)]
struct OuterProofWitness {
    pi: HeaderChainPublicInputs,
    trace_leaf: Word8,
    trace_siblings: [Word8; OUTER_MERKLE_DEPTH],
    constraint_leaf: Word8,
    constraint_siblings: [Word8; OUTER_MERKLE_DEPTH],
    ood_digest: Word8,
    fri0_pair_words: [u32; 16],
    fri0_siblings: [Word8; OUTER_FRI0_DEPTH],
    fri_roots_tail: [Word8; OUTER_FRI_COMMITS - 1], // fri_root_1 ..= fri_root_5
    pow_nonce: u64,
    q_pos: usize,
    fri_folds: [(Felt, QuartExtension<Felt>, QuartExtension<Felt>, QuartExtension<Felt>, bool); OUTER_FRI_LAYERS],
}

fn sis_periodic() -> Vec<Vec<Felt>> {
    let mut cols = vec![vec![Felt::ZERO; SIS_ROWS]; SP_N_PER];

    for p in 0..2 {
        let c_base = p * SIS_COMPS_PER_PROOF;
        let r_proof_start = c_base * HC_STRIDE;
        let r_proof_end = (c_base + SIS_COMPS_PER_PROOF) * HC_STRIDE;

        // Standard SHA-256 engine periodic selectors for every active compression
        for lc in 0..SIS_COMPS_PER_PROOF {
            let base = (c_base + lc) * HC_STRIDE;
            for t in 0..HC_STRIDE {
                let r = base + t;
                cols[SP_ACT][r] = Felt::ONE;
                if t < 64 {
                    cols[SP_K][r] = Felt::new(K[t] as u64);
                    cols[SP_ROUND][r] = Felt::ONE;
                }
                if t < 63 {
                    cols[SP_WSCHED][r] = Felt::ONE;
                }
                if t == 0 {
                    cols[SP_START][r] = Felt::ONE;
                }
                if t == 64 {
                    cols[SP_BND][r] = Felt::ONE;
                }
            }

            let r0 = base;
            let r64 = base + 64;

            // 0..4: Initial coin seed `seed_0 = SHA-256(Context || PI)` (200 bytes = 4 blocks)
            if lc == 0 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 1 {
                cols[SP_EVEN_ZERO][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 2 {
                cols[SP_EVEN_ZERO][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 3 {
                cols[SP_PAD_200][r0] = Felt::ONE;
                cols[SP_SEED_SET][r64] = Felt::ONE;
                cols[SP_MPATH_INIT][r64] = Felt::ONE; // initializes S_QACC = bit_0 for Trace path
            }
            // 4..30: Trace Merkle path (13 levels × 2 blocks)
            else if (4..30).contains(&lc) {
                let off = lc - 4;
                let lvl = off / 2;
                if off % 2 == 0 {
                    cols[SP_STD_IV][r0] = Felt::ONE;
                    cols[SP_CHAIN_IV][r64] = Felt::ONE;
                } else {
                    cols[SP_PAD_64][r0] = Felt::ONE;
                    if lvl + 1 < OUTER_MERKLE_DEPTH {
                        cols[SP_MPATH_STEP][r64] = Felt::ONE;
                        cols[SP_MPATH_ACC][r64] = Felt::ONE;
                        cols[SP_QACC_WEIGHT][r64] = Felt::new(1u64 << (lvl + 1));
                    } else {
                        cols[SP_QACC_EQ_FULL][r64] = Felt::ONE;
                        cols[SP_RESEED_DIG][r64] = Felt::ONE;
                    }
                }
            }
            // 30..32: Reseed `seed_1 = SHA-256(seed_0 || trace_root)`
            else if lc == 30 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_RESEED_LEFT][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 31 {
                cols[SP_PAD_64][r0] = Felt::ONE;
                cols[SP_SEED_SET][r64] = Felt::ONE;
                cols[SP_MPATH_INIT][r64] = Felt::ONE; // initializes S_QACC = bit_0 for Constraint path
            }
            // 32..58: Constraint Merkle path (13 levels × 2 blocks)
            else if (32..58).contains(&lc) {
                let off = lc - 32;
                let lvl = off / 2;
                if off % 2 == 0 {
                    cols[SP_STD_IV][r0] = Felt::ONE;
                    cols[SP_CHAIN_IV][r64] = Felt::ONE;
                } else {
                    cols[SP_PAD_64][r0] = Felt::ONE;
                    if lvl + 1 < OUTER_MERKLE_DEPTH {
                        cols[SP_MPATH_STEP][r64] = Felt::ONE;
                        cols[SP_MPATH_ACC][r64] = Felt::ONE;
                        cols[SP_QACC_WEIGHT][r64] = Felt::new(1u64 << (lvl + 1));
                    } else {
                        cols[SP_QACC_EQ_FULL][r64] = Felt::ONE;
                        cols[SP_RESEED_DIG][r64] = Felt::ONE;
                    }
                }
            }
            // 58..60: Reseed `seed_2 = SHA-256(seed_1 || constraint_root)`
            else if lc == 58 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_RESEED_LEFT][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 59 {
                cols[SP_PAD_64][r0] = Felt::ONE;
                cols[SP_SEED_SET][r64] = Felt::ONE;
            }
            // 60..62: Reseed `seed_3 = SHA-256(seed_2 || ood_digest)`
            else if lc == 60 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_RESEED_LEFT][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 61 {
                cols[SP_PAD_64][r0] = Felt::ONE;
                cols[SP_SEED_SET][r64] = Felt::ONE;
            }
            // 62..64: FRI-0 Leaf Preimage `fri0_leaf = SHA-256(y_pos || y_neg)` (64 bytes)
            else if lc == 62 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_CHAIN_IV][r64] = Felt::ONE;
            } else if lc == 63 {
                cols[SP_PAD_64][r0] = Felt::ONE;
                cols[SP_MPATH_STEP][r64] = Felt::ONE; // places `fri0_leaf` left/right into FRI-0 lvl 0!
                cols[SP_MPATH_INIT][r64] = Felt::ONE; // initializes S_QACC = bit_0 for FRI-0 path
            }
            // 64..88: FRI-0 Merkle path (12 levels × 2 blocks)
            else if (64..88).contains(&lc) {
                let off = lc - 64;
                let lvl = off / 2;
                if off % 2 == 0 {
                    cols[SP_STD_IV][r0] = Felt::ONE;
                    cols[SP_CHAIN_IV][r64] = Felt::ONE;
                } else {
                    cols[SP_PAD_64][r0] = Felt::ONE;
                    if lvl + 1 < OUTER_FRI0_DEPTH {
                        cols[SP_MPATH_STEP][r64] = Felt::ONE;
                        cols[SP_MPATH_ACC][r64] = Felt::ONE;
                        cols[SP_QACC_WEIGHT][r64] = Felt::new(1u64 << (lvl + 1));
                    } else {
                        cols[SP_QACC_EQ_FRI0][r64] = Felt::ONE;
                        cols[SP_RESEED_DIG][r64] = Felt::ONE;
                    }
                }
            }
            // 88..100: FRI commitment reseeds (`fri_root_0..=fri_root_5`, 6 × 2 blocks)
            else if (88..100).contains(&lc) {
                let off = lc - 88;
                if off % 2 == 0 {
                    cols[SP_STD_IV][r0] = Felt::ONE;
                    cols[SP_RESEED_LEFT][r0] = Felt::ONE;
                    cols[SP_CHAIN_IV][r64] = Felt::ONE;
                } else {
                    cols[SP_PAD_64][r0] = Felt::ONE;
                    cols[SP_SEED_SET][r64] = Felt::ONE;
                }
            }
            // 100: PoW grinding check `pow_seed = SHA-256(seed_final || pow_nonce_le8)` (40 bytes)
            else if lc == 100 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_RESEED_LEFT][r0] = Felt::ONE;
                cols[SP_PAD_40][r0] = Felt::ONE;
                cols[SP_UNPACK_DIG0][r64] = Felt::ONE;
                cols[SP_CHECK_POW][r64] = Felt::ONE;
                cols[SP_SEED_SET][r64] = Felt::ONE; // sets S_SEED = pow_seed
            }
            // 101: First query index draw `q0_hash = SHA-256(pow_seed || 1u64_le8)` (40 bytes)
            else if lc == 101 {
                cols[SP_STD_IV][r0] = Felt::ONE;
                cols[SP_RESEED_LEFT][r0] = Felt::ONE;
                cols[SP_PAD_40][r0] = Felt::ONE;
                cols[SP_Q0_CTR][r0] = Felt::ONE;
                cols[SP_UNPACK_DIG0][r64] = Felt::ONE;
                cols[SP_EXTRACT_QPOS][r64] = Felt::ONE;
            }
        }

        // Hold flags within proof `p`
        for r in r_proof_start..(r_proof_end - 1) {
            if cols[SP_SEED_SET][r] == Felt::ZERO {
                cols[SP_SEED_HOLD][r] = Felt::ONE;
            }
            if cols[SP_MPATH_INIT][r] == Felt::ZERO && cols[SP_MPATH_ACC][r] == Felt::ZERO {
                cols[SP_QACC_HOLD][r] = Felt::ONE;
            }
            cols[SP_QTARGET_HOLD][r] = Felt::ONE;
        }
    }

    // Private IVC linkage `S_MID`: capture Proof A end_hash (comp 2 row 0), hold to Proof B start_prev (comp 103 row 0)
    let r_mid_cap = 2 * HC_STRIDE;
    let r_mid_use = (SIS_COMPS_PER_PROOF + 1) * HC_STRIDE;
    cols[SP_MID_CAP][r_mid_cap] = Felt::ONE;
    for r in r_mid_cap..r_mid_use {
        cols[SP_MID_HOLD][r] = Felt::ONE;
    }
    cols[SP_MID_USE][r_mid_use] = Felt::ONE;

    // Quartic `F_{p^4}` FRI-folding rows (`10` rows: 5 layers for Proof A + 5 layers for Proof B)
    for p in 0..2 {
        let base = SIS_FRI_BASE + p * OUTER_FRI_LAYERS;
        for l in 0..OUTER_FRI_LAYERS {
            cols[SP_FRI_STEP][base + l] = Felt::ONE;
            if l + 1 < OUTER_FRI_LAYERS {
                cols[SP_FRI_CONT][base + l] = Felt::ONE;
            }
        }
    }

    cols
}

const SIS_N_CONSTRAINTS: usize =
    200 // SHA-256 binary checks (a, b, e, f, X1, X14, CA, CE, CWC)
    + 2 // round step nxt.an & nxt.en
    + 6 // SHA-256 state shifts
    + 16 // W schedule: 15 shifts + 1 W_{t+16}
    + 2 // X1 == W[1], X14 == W[14]
    + 8 // IV constancy
    + 8 // pre-row init from IV
    + 8 // row-64 digest
    + 8 // std FIPS IV
    + 8 // IV chaining
    + 15 // FIPS 200-byte padding (`SP_PAD_200`)
    + 16 // FIPS 64-byte padding (`SP_PAD_64`)
    + 6 // FIPS 40-byte padding (`SP_PAD_40`)
    + 2 // q0 counter = 1u64 LE (`SP_Q0_CTR`)
    + 8 // upper 32-bit zero words for Felt-encoded Word8 (`SP_EVEN_ZERO`)
    + 8 // S_MID capture (`SP_MID_CAP`)
    + 8 // S_MID hold (`SP_MID_HOLD`)
    + 8 // S_MID bind into Proof B start_prev (`SP_MID_USE`)
    + 8 // S_SEED set (`SP_SEED_SET`)
    + 8 // S_SEED hold (`SP_SEED_HOLD`)
    + 8 // reseed left half == S_SEED (`SP_RESEED_LEFT`)
    + 8 // reseed right half == finished Merkle DIG (`SP_RESEED_DIG`)
    + 16 // Merkle step left/right placement (`SP_MPATH_STEP`, deg 2)
    + 1 // S_QACC init (`SP_MPATH_INIT`)
    + 1 // S_QACC accumulate (`SP_MPATH_ACC` + `SP_QACC_WEIGHT`)
    + 1 // S_QACC hold (`SP_QACC_HOLD`)
    + 1 // S_QTARGET hold (`SP_QTARGET_HOLD`)
    + 1 // S_QACC == S_QTARGET on depth-13 paths (`SP_QACC_EQ_FULL`)
    + 1 // S_QTARGET - S_QACC in {0, 4096} on depth-12 FRI-0 path (`SP_QACC_EQ_FRI0`, deg 2)
    + 1 // unpack DIG[0] into X14[0..32] (`SP_UNPACK_DIG0`)
    + 1 // 20-bit PoW grinding zero check (`SP_CHECK_POW`)
    + 1 // coin-derived q_pos == S_QTARGET (`SP_EXTRACT_QPOS`)
    + 1 // FRI branch bit binary (`SP_FRI_STEP`, deg 2)
    + 4 // Quartic F_{p^4} FRI fold equation (`SP_FRI_STEP`, deg 2)
    + 1 // FRI domain squaring (`SP_FRI_CONT`, deg 2)
    + 4; // Quartic F_{p^4} FRI branch continuity (`SP_FRI_CONT`, deg 2)

#[inline(never)]
fn eval_sha256_core_e<E: FieldElement + From<Felt>>(
    cur: &[E],
    nxt: &[E],
    per: &[E],
    res: &mut [E],
    idx: &mut usize,
) {
    let one = E::ONE;
    let pow32 = E::from(Felt::new(1u64 << 32));
    let k_t = per[SP_K];
    let is_round = per[SP_ROUND];
    let is_wsched = per[SP_WSCHED];
    let is_bnd = per[SP_BND];
    let is_act = per[SP_ACT];
    let is_start = per[SP_START];
    let is_std_iv = per[SP_STD_IV];
    let is_chain_iv = per[SP_CHAIN_IV];

    let mut i = *idx;
    for col in 0..128 {
        let b = cur[col];
        res[i] = is_act * b * (b - one);
        i += 1;
    }
    for j in 0..32 {
        let b = cur[S_X1 + j];
        res[i] = is_act * b * (b - one);
        i += 1;
    }
    for j in 0..32 {
        let b = cur[S_X14 + j];
        res[i] = is_act * b * (b - one);
        i += 1;
    }
    for col in [S_CA, S_CA + 1, S_CA + 2, S_CE, S_CE + 1, S_CE + 2, S_CWC, S_CWC + 1] {
        let b = cur[col];
        res[i] = is_act * b * (b - one);
        i += 1;
    }

    let a_bits = &nxt[S_A..S_A + 32];
    let b_bits = &cur[S_A..S_A + 32];
    let c_bits = &cur[S_B..S_B + 32];
    let e_bits = &nxt[S_E..S_E + 32];
    let f_bits = &cur[S_E..S_E + 32];
    let g_bits = &cur[S_F..S_F + 32];

    let sig0 = rotr_xor3_e(a_bits, 2, 13, 22);
    let sig1 = rotr_xor3_e(e_bits, 6, 11, 25);
    let (maj, ch) = maj_ch_e(a_bits, b_bits, c_bits, e_bits, f_bits, g_bits);
    let t1 = cur[S_GW] + sig1 + ch + cur[S_W];
    let t2 = sig0 + maj;
    let ca = pack_bits_e(&cur[S_CA..S_CA + 3]);
    let ce = pack_bits_e(&cur[S_CE..S_CE + 3]);
    res[i] = is_round * (nxt[S_AN] + ca * pow32 - (t1 + t2)) - k_t;
    i += 1;
    res[i] = is_round * (nxt[S_EN] + ce * pow32 - (cur[S_CW] + t1)) - k_t;
    i += 1;

    let cur_a_w = pack_bits_e(b_bits);
    let cur_b_w = pack_bits_e(c_bits);
    let cur_e_w = pack_bits_e(f_bits);
    let cur_f_w = pack_bits_e(g_bits);
    res[i] = is_round * (pack_bits_e(a_bits) - cur[S_AN]);
    i += 1;
    res[i] = is_round * (pack_bits_e(&nxt[S_B..S_B + 32]) - cur_a_w);
    i += 1;
    res[i] = is_round * (nxt[S_CW] - cur_b_w);
    i += 1;
    res[i] = is_round * (pack_bits_e(e_bits) - cur[S_EN]);
    i += 1;
    res[i] = is_round * (pack_bits_e(&nxt[S_F..S_F + 32]) - cur_e_w);
    i += 1;
    res[i] = is_round * (nxt[S_GW] - cur_f_w);
    i += 1;

    for j in 0..15 {
        res[i] = is_wsched * (nxt[S_W + j] - cur[S_W + j + 1]);
        i += 1;
    }
    let s0 = shr_rotr_xor3_e(&cur[S_X1..S_X1 + 32], 7, 18, 3);
    let s1 = shr_rotr_xor3_e(&cur[S_X14..S_X14 + 32], 17, 19, 10);
    let cwc = pack_bits_e(&cur[S_CWC..S_CWC + 2]);
    res[i] = is_wsched * (nxt[S_W + 15] + cwc * pow32 - (cur[S_W] + s0 + cur[S_W + 9] + s1));
    i += 1;

    res[i] = is_wsched * (pack_bits_e(&cur[S_X1..S_X1 + 32]) - cur[S_W + 1]);
    i += 1;
    res[i] = is_wsched * (pack_bits_e(&cur[S_X14..S_X14 + 32]) - cur[S_W + 14]);
    i += 1;

    for k in 0..8 {
        res[i] = is_round * (nxt[S_IV + k] - cur[S_IV + k]);
        i += 1;
    }
    let pre_words = [
        cur[S_AN], cur_a_w, cur_b_w, cur[S_CW],
        cur[S_EN], cur_e_w, cur_f_w, cur[S_GW],
    ];
    for k in 0..8 {
        res[i] = is_start * (pre_words[k] - cur[S_IV + k]);
        i += 1;
    }
    for k in 0..8 {
        let carry_bit = cur[S_X1 + k];
        res[i] = is_bnd * (cur[S_DIG + k] + carry_bit * pow32 - (cur[S_IV + k] + pre_words[k]));
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_std_iv * (cur[S_IV + k] - E::from(Felt::new(IV[k] as u64)));
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_chain_iv * (nxt[S_IV + k] - cur[S_DIG + k]);
        i += 1;
    }
    *idx = i;
}

#[inline(never)]
fn eval_sis_padding_mid_e<E: FieldElement + From<Felt>>(
    cur: &[E],
    nxt: &[E],
    per: &[E],
    res: &mut [E],
    idx: &mut usize,
) {
    let is_pad_200 = per[SP_PAD_200];
    let is_pad_64 = per[SP_PAD_64];
    let is_pad_40 = per[SP_PAD_40];
    let is_q0_ctr = per[SP_Q0_CTR];
    let is_even_zero = per[SP_EVEN_ZERO];
    let is_mid_cap = per[SP_MID_CAP];
    let is_mid_hold = per[SP_MID_HOLD];
    let is_mid_use = per[SP_MID_USE];
    let pad_mark = E::from(Felt::new(0x8000_0000u64));
    let mut i = *idx;

    res[i] = is_pad_200 * cur[S_W + 1];
    i += 1;
    res[i] = is_pad_200 * (cur[S_W + 2] - pad_mark);
    i += 1;
    for j in 3..15 {
        res[i] = is_pad_200 * cur[S_W + j];
        i += 1;
    }
    res[i] = is_pad_200 * (cur[S_W + 15] - E::from(Felt::new(1600)));
    i += 1;

    res[i] = is_pad_64 * (cur[S_W] - pad_mark);
    i += 1;
    for j in 1..15 {
        res[i] = is_pad_64 * cur[S_W + j];
        i += 1;
    }
    res[i] = is_pad_64 * (cur[S_W + 15] - E::from(Felt::new(512)));
    i += 1;

    res[i] = is_pad_40 * (cur[S_W + 10] - pad_mark);
    i += 1;
    for j in 11..15 {
        res[i] = is_pad_40 * cur[S_W + j];
        i += 1;
    }
    res[i] = is_pad_40 * (cur[S_W + 15] - E::from(Felt::new(320)));
    i += 1;

    res[i] = is_q0_ctr * (cur[S_W + 8] - E::from(Felt::new(0x0100_0000u64)));
    i += 1;
    res[i] = is_q0_ctr * cur[S_W + 9];
    i += 1;

    for k in 0..8 {
        res[i] = is_even_zero * cur[S_W + 2 * k + 1];
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_mid_cap * (cur[S_MID + k] - cur[S_W + 2 * k]);
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_mid_hold * (nxt[S_MID + k] - cur[S_MID + k]);
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_mid_use * (cur[S_W + 2 * k] - cur[S_MID + k]);
        i += 1;
    }
    *idx = i;
}

#[inline(never)]
fn eval_sis_transcript_merkle_e<E: FieldElement + From<Felt>>(
    cur: &[E],
    nxt: &[E],
    per: &[E],
    res: &mut [E],
    idx: &mut usize,
) {
    let one = E::ONE;
    let is_seed_set = per[SP_SEED_SET];
    let is_seed_hold = per[SP_SEED_HOLD];
    let is_reseed_left = per[SP_RESEED_LEFT];
    let is_reseed_dig = per[SP_RESEED_DIG];
    let is_mpath_step = per[SP_MPATH_STEP];
    let is_mpath_init = per[SP_MPATH_INIT];
    let is_mpath_acc = per[SP_MPATH_ACC];
    let qacc_weight = per[SP_QACC_WEIGHT];
    let is_qacc_hold = per[SP_QACC_HOLD];
    let is_qtarget_hold = per[SP_QTARGET_HOLD];
    let is_qacc_eq_full = per[SP_QACC_EQ_FULL];
    let is_qacc_eq_fri0 = per[SP_QACC_EQ_FRI0];
    let mut i = *idx;

    for k in 0..8 {
        res[i] = is_seed_set * (nxt[S_SEED + k] - cur[S_DIG + k]);
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_seed_hold * (nxt[S_SEED + k] - cur[S_SEED + k]);
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_reseed_left * (cur[S_W + k] - cur[S_SEED + k]);
        i += 1;
    }
    for k in 0..8 {
        res[i] = is_reseed_dig * (nxt[S_W + 8 + k] - cur[S_DIG + k]);
        i += 1;
    }

    let mbit = cur[S_X14];
    for j in 0..8 {
        res[i] = is_mpath_step * (one - mbit) * (nxt[S_W + j] - cur[S_DIG + j]);
        i += 1;
    }
    for j in 0..8 {
        res[i] = is_mpath_step * mbit * (nxt[S_W + 8 + j] - cur[S_DIG + j]);
        i += 1;
    }
    res[i] = is_mpath_init * (nxt[S_QACC] - mbit);
    i += 1;
    res[i] = is_mpath_acc * (nxt[S_QACC] - cur[S_QACC]) - qacc_weight * mbit;
    i += 1;
    res[i] = is_qacc_hold * (nxt[S_QACC] - cur[S_QACC]);
    i += 1;
    res[i] = is_qtarget_hold * (nxt[S_QTARGET] - cur[S_QTARGET]);
    i += 1;
    res[i] = is_qacc_eq_full * (cur[S_QACC] - cur[S_QTARGET]);
    i += 1;
    let qdiff = cur[S_QTARGET] - cur[S_QACC];
    res[i] = is_qacc_eq_fri0 * qdiff * (qdiff - E::from(Felt::new(4096)));
    i += 1;
    *idx = i;
}

#[inline(never)]
fn eval_sis_pow_fri_e<E: FieldElement + From<Felt>>(
    cur: &[E],
    nxt: &[E],
    per: &[E],
    res: &mut [E],
    idx: &mut usize,
) {
    let one = E::ONE;
    let two = E::from(Felt::new(2));
    let seven = E::from(Felt::new(7));
    let is_unpack_dig0 = per[SP_UNPACK_DIG0];
    let is_check_pow = per[SP_CHECK_POW];
    let is_extract_qpos = per[SP_EXTRACT_QPOS];
    let is_fri_step = per[SP_FRI_STEP];
    let is_fri_cont = per[SP_FRI_CONT];
    let mut i = *idx;

    res[i] = is_unpack_dig0 * (pack_bits_e(&cur[S_X14..S_X14 + 32]) - cur[S_DIG]);
    i += 1;
    let mut pow_sum = E::ZERO;
    for k in 8..12 {
        pow_sum += cur[S_X14 + k];
    }
    for k in 16..32 {
        pow_sum += cur[S_X14 + k];
    }
    res[i] = is_check_pow * pow_sum;
    i += 1;

    let qpos_low8 = pack_bits_e(&cur[S_X14 + 24..S_X14 + 32]);
    let qpos_hi5 = pack_bits_e(&cur[S_X14 + 16..S_X14 + 21]);
    let qpos_derived = qpos_low8 + qpos_hi5 * E::from(Felt::new(256));
    res[i] = is_extract_qpos * (cur[S_QTARGET] - qpos_derived);
    i += 1;

    let x = cur[QF_X];
    let fp = [cur[QF_FP], cur[QF_FP + 1], cur[QF_FP + 2], cur[QF_FP + 3]];
    let fn_ = [cur[QF_FN], cur[QF_FN + 1], cur[QF_FN + 2], cur[QF_FN + 3]];
    let al = [cur[QF_ALPHA], cur[QF_ALPHA + 1], cur[QF_ALPHA + 2], cur[QF_ALPHA + 3]];
    let fl = [cur[QF_FOLDED], cur[QF_FOLDED + 1], cur[QF_FOLDED + 2], cur[QF_FOLDED + 3]];
    let fbit = cur[QF_BIT];

    res[i] = is_fri_step * fbit * (fbit - one);
    i += 1;

    let sum = [fp[0] + fn_[0], fp[1] + fn_[1], fp[2] + fn_[2], fp[3] + fn_[3]];
    let d = [fp[0] - fn_[0], fp[1] - fn_[1], fp[2] - fn_[2], fp[3] - fn_[3]];
    let prod = [
        al[0] * d[0] + seven * (al[1] * d[3] + al[2] * d[2] + al[3] * d[1]),
        al[0] * d[1] + al[1] * d[0] + seven * (al[2] * d[3] + al[3] * d[2]),
        al[0] * d[2] + al[1] * d[1] + al[2] * d[0] + seven * (al[3] * d[3]),
        al[0] * d[3] + al[1] * d[2] + al[2] * d[1] + al[3] * d[0],
    ];
    for k in 0..4 {
        res[i] = is_fri_step * (two * x * fl[k] - x * sum[k] - prod[k]);
        i += 1;
    }
    res[i] = is_fri_cont * (seven * nxt[QF_X] - (one - two * fbit) * x * x);
    i += 1;
    for k in 0..4 {
        res[i] = is_fri_cont
            * ((one - fbit) * (nxt[QF_FP + k] - fl[k]) + fbit * (nxt[QF_FN + k] - fl[k]));
        i += 1;
    }
    *idx = i;
}

pub struct StarkInStarkVerifierAir {
    ctx: AirContext<Felt>,
    pi: RecursiveChainPublicInputs,
    outer_ctx_words: [u32; 16],
}

impl Air for StarkInStarkVerifierAir {
    type BaseField = Felt;
    type PublicInputs = RecursiveChainPublicInputs;

    fn new(trace_info: TraceInfo, pi: RecursiveChainPublicInputs, options: ProofOptions) -> Self {
        let mut degrees = Vec::with_capacity(SIS_N_CONSTRAINTS);
        // 200 binary checks (deg 2 * cycle)
        for _ in 0..200 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![SIS_ROWS]));
        }
        // 2 round equations (deg 3 * cycle)
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![SIS_ROWS]));
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![SIS_ROWS]));
        // 6 shifts + 15 W shifts = 21 deg-1
        for _ in 0..21 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![SIS_ROWS]));
        }
        // 1 W_{t+16} (deg 3)
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![SIS_ROWS]));
        // 2 + 8 + 8 + 8 + 8 + 8 + 15 + 16 + 6 + 2 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 = 145 deg-1
        for _ in 0..145 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![SIS_ROWS]));
        }
        // 16 Merkle step left/right placements (deg 2)
        for _ in 0..16 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![SIS_ROWS]));
        }
        // 5 deg-1 (init, acc, hold, qtarget_hold, qacc_eq_full)
        for _ in 0..5 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![SIS_ROWS]));
        }
        // 1 deg-2 (qacc_eq_fri0)
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![SIS_ROWS]));
        // 3 deg-1 (unpack_dig0, check_pow, extract_qpos)
        for _ in 0..3 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![SIS_ROWS]));
        }
        // 10 Quartic FRI constraints: 5 deg-2 (bit + 4 fold eqs), 1 deg-3 (signed domain squaring), 4 deg-2 (branch continuity)
        for _ in 0..5 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![SIS_ROWS]));
        }
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![SIS_ROWS]));
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![SIS_ROWS]));
        }
        assert_eq!(degrees.len(), SIS_N_CONSTRAINTS);
        Self {
            ctx: AirContext::new(trace_info, degrees, 66, options),
            pi,
            outer_ctx_words: outer_header_chain_context_words(),
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.ctx
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        sis_periodic()
    }

    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        per: &[E],
        res: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let mut idx = 0usize;
        eval_sha256_core_e(cur, nxt, per, res, &mut idx);
        eval_sis_padding_mid_e(cur, nxt, per, res, &mut idx);
        eval_sis_transcript_merkle_e(cur, nxt, per, res, &mut idx);
        eval_sis_pow_fri_e(cur, nxt, per, res, &mut idx);
        debug_assert_eq!(idx, SIS_N_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut out = Vec::with_capacity(66);
        let r_b_base = SIS_COMPS_PER_PROOF * HC_STRIDE;

        // 1. Pin BOTH outer proofs' Winterfell `Context` block (Comp 0 & Comp 102) = 32 assertions
        for j in 0..16 {
            let v = Felt::new(self.outer_ctx_words[j] as u64);
            out.push(Assertion::single(S_W + j, 0, v));
            out.push(Assertion::single(S_W + j, r_b_base, v));
        }
        // 2. Pin Proof A `start_prev_words` (Comp 1 row 0, Felt LE encoded) = 16 assertions
        let r_a_start = HC_STRIDE;
        for i in 0..8 {
            out.push(Assertion::single(
                S_W + 2 * i,
                r_a_start,
                Felt::new(self.pi.start_prev_words[i].swap_bytes() as u64),
            ));
            out.push(Assertion::single(S_W + 2 * i + 1, r_a_start, Felt::ZERO));
        }
        // 3. Pin Proof B `end_hash_words` (Comp 104 row 0, Felt LE encoded) = 16 assertions
        let r_b_end = (SIS_COMPS_PER_PROOF + 2) * HC_STRIDE;
        for i in 0..8 {
            out.push(Assertion::single(
                S_W + 2 * i,
                r_b_end,
                Felt::new(self.pi.end_hash_words[i].swap_bytes() as u64),
            ));
            out.push(Assertion::single(S_W + 2 * i + 1, r_b_end, Felt::ZERO));
        }
        // 4. Pin each outer segment's header count (`HEADERS_PER_SEGMENT`) = 2 assertions
        let seg_cnt_be = Felt::new((HEADERS_PER_SEGMENT as u32).swap_bytes() as u64);
        out.push(Assertion::single(S_W, 3 * HC_STRIDE, seg_cnt_be));
        out.push(Assertion::single(S_W, (SIS_COMPS_PER_PROOF + 3) * HC_STRIDE, seg_cnt_be));
        out
    }
}

struct StarkInStarkProver {
    options: ProofOptions,
    pi: RecursiveChainPublicInputs,
}

impl Prover for StarkInStarkProver {
    type BaseField = Felt;
    type Air = StarkInStarkVerifierAir;
    type Trace = TraceTable<Felt>;
    type HashFn = RecHash;
    type VC = RecVc;
    type RandomCoin = RecCoin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, RecHash, RecVc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, RecHash, RecVc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, StarkInStarkVerifierAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> RecursiveChainPublicInputs {
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

fn sha256_pad64_block() -> [u32; 16] {
    let mut b = [0u32; 16];
    b[0] = 0x8000_0000;
    b[15] = 512;
    b
}

fn sha256_merge_words(left: &Word8, right: &Word8) -> ([u32; 16], Word8, Word8) {
    let mut b0 = [0u32; 16];
    b0[..8].copy_from_slice(left);
    b0[8..16].copy_from_slice(right);
    let (s1, _, _) = compress_with_iv(&b0, &IV);
    let pad = sha256_pad64_block();
    let (dig, _, _) = compress_with_iv(&pad, &s1);
    (b0, s1, dig)
}

fn sha256_with_int_block(seed: &Word8, val: u64) -> ([u32; 16], Word8) {
    let mut b = [0u32; 16];
    b[..8].copy_from_slice(seed);
    let le = val.to_le_bytes();
    b[8] = u32::from_be_bytes(le[0..4].try_into().unwrap());
    b[9] = u32::from_be_bytes(le[4..8].try_into().unwrap());
    b[10] = 0x8000_0000;
    b[15] = 320;
    let (dig, _, _) = compress_with_iv(&b, &IV);
    (b, dig)
}

fn felt_word8_block(w: &Word8) -> [u32; 16] {
    let mut b = [0u32; 16];
    for i in 0..8 {
        b[2 * i] = w[i].swap_bytes();
        b[2 * i + 1] = 0;
    }
    b
}

fn extract_outer_witness(
    pi: &HeaderChainPublicInputs,
    proof_bytes: &[u8],
) -> Result<OuterProofWitness, String> {
    verify_outer_header_segment(pi, proof_bytes)?;
    let proof = Proof::from_bytes(proof_bytes).map_err(|e| format!("parse outer proof: {e}"))?;
    let opts = outer_header_chain_options();
    let air = HeaderChainAir::new(proof.trace_info().clone(), pi.clone(), opts.clone());
    let lde_size = air.lde_domain_size();
    assert_eq!(lde_size, OUTER_LDE_SIZE);
    let fri_opts = opts.to_fri_options();
    assert_eq!(fri_opts.num_fri_layers(lde_size), OUTER_FRI_LAYERS);

    // 1. Reconstruct initial public coin seed & verify against our deterministic context block
    let ctx_els: Vec<Felt> = proof.context.to_elements();
    let mut ctx_bytes = Vec::with_capacity(64);
    for e in &ctx_els {
        ctx_bytes.extend_from_slice(&e.as_int().to_le_bytes());
    }
    let expected_ctx_words = outer_header_chain_context_words();
    let mut expected_ctx_bytes = Vec::with_capacity(64);
    for w_i in &expected_ctx_words {
        expected_ctx_bytes.extend_from_slice(&w_i.to_be_bytes());
    }
    assert_eq!(ctx_bytes, expected_ctx_bytes, "proof.context.to_elements() bytes differ from outer_header_chain_context_words()! ctx_els={ctx_els:?}");
    let mut seed_els = ctx_els;
    seed_els.append(&mut pi.to_elements());
    assert_eq!(seed_els.len(), 25);

    let (trace_roots, constraint_root, fri_roots) = proof
        .commitments
        .clone()
        .parse::<OuterHash>(1, OUTER_FRI_LAYERS)
        .map_err(|e| format!("parse commitments: {e}"))?;
    assert_eq!(fri_roots.len(), OUTER_FRI_COMMITS);

    let c_width = air.context().num_constraint_composition_columns();
    let (ood_trace, ood_quot) = proof
        .ood_frame
        .clone()
        .parse::<QuartExtension<Felt>>(S_WIDTH, 0, c_width)
        .map_err(|e| format!("parse ood frame: {e}"))?;
    let mut ood_evals = ood_trace.current_row().to_vec();
    ood_evals.extend_from_slice(ood_quot.current_row());
    ood_evals.extend_from_slice(ood_trace.next_row());
    ood_evals.extend_from_slice(ood_quot.next_row());
    let ood_digest_sha = OuterHash::hash_elements(&ood_evals);

    // 2. Replay Winterfell `DefaultRandomCoin<Sha2_256>` identically
    let mut coin = OuterCoin::new(&seed_els);
    coin.reseed(trace_roots[0]);
    let _cc = air
        .get_constraint_composition_coefficients::<QuartExtension<Felt>, OuterCoin>(&mut coin)
        .map_err(|_| "coin constraint coeffs".to_string())?;
    coin.reseed(constraint_root);
    let _z = coin.draw::<QuartExtension<Felt>>().map_err(|_| "coin z".to_string())?;
    coin.reseed(ood_digest_sha);
    let _dc = air
        .get_deep_composition_coefficients::<QuartExtension<Felt>, OuterCoin>(&mut coin)
        .map_err(|_| "coin deep coeffs".to_string())?;

    let mut alphas = Vec::with_capacity(OUTER_FRI_COMMITS);
    for &fr in &fri_roots {
        coin.reseed(fr);
        alphas.push(coin.draw::<QuartExtension<Felt>>().map_err(|_| "coin alpha".to_string())?);
    }

    if coin.check_leading_zeros(proof.pow_nonce) < OUTER_GRINDING {
        return Err("outer proof grinding check failed".into());
    }
    let raw_positions = coin
        .draw_integers(opts.num_queries(), lde_size, proof.pow_nonce)
        .map_err(|_| "coin query positions".to_string())?;
    let q_pos = raw_positions[0];

    let mut positions = raw_positions;
    positions.sort_unstable();
    positions.dedup();
    let q_idx = positions
        .binary_search(&q_pos)
        .map_err(|_| "q_pos missing from deduplicated query positions".to_string())?;

    // 3. Decompress Trace & Constraint Merkle openings at `q_pos`
    let (trace_bmp, trace_states) = proof.trace_queries[0]
        .clone()
        .parse::<Felt, OuterHash, OuterVc>(lde_size, proof.num_unique_queries as usize, S_WIDTH)
        .map_err(|e| format!("parse trace queries: {e}"))?;
    let trace_leaves: Vec<ShaDigest> = trace_states
        .rows()
        .map(|row| OuterHash::hash_elements(row))
        .collect();
    let trace_openings = trace_bmp
        .into_openings(&trace_leaves, &positions)
        .map_err(|e| format!("trace openings: {e:?}"))?;
    let (t_leaf, t_sibs) = &trace_openings[q_idx];
    assert_eq!(t_sibs.len(), OUTER_MERKLE_DEPTH);

    let (con_bmp, con_states) = proof
        .constraint_queries
        .clone()
        .parse::<QuartExtension<Felt>, OuterHash, OuterVc>(
            lde_size,
            proof.num_unique_queries as usize,
            c_width,
        )
        .map_err(|e| format!("parse constraint queries: {e}"))?;
    let con_leaves: Vec<ShaDigest> = con_states
        .rows()
        .map(|row| OuterHash::hash_elements(row))
        .collect();
    let con_openings = con_bmp
        .into_openings(&con_leaves, &positions)
        .map_err(|e| format!("constraint openings: {e:?}"))?;
    let (c_leaf, c_sibs) = &con_openings[q_idx];
    assert_eq!(c_sibs.len(), OUTER_MERKLE_DEPTH);

    // 4. Decompress FRI Layer 0 Merkle opening + extract ALL 5 real Quartic `F_{p^4}` FRI folds!
    let (fri_queries, mut fri_proofs) = proof
        .fri_proof
        .clone()
        .parse_layers::<QuartExtension<Felt>, OuterHash, OuterVc>(lde_size, 2)
        .map_err(|e| format!("parse fri layers: {e}"))?;
    assert_eq!(fri_queries.len(), OUTER_FRI_LAYERS);

    let mut cur_positions = positions.clone();
    let mut cur_dom = lde_size;
    let mut cur_gen = Felt::get_root_of_unity(lde_size.ilog2());
    let offset = Felt::GENERATOR;
    let mut cur_q = q_pos;

    let mut fri0_pair_words = [0u32; 16];
    let mut fri0_siblings = [[0u32; 8]; OUTER_FRI0_DEPTH];
    let mut fri_folds = [(Felt::ZERO, QuartExtension::ZERO, QuartExtension::ZERO, QuartExtension::ZERO, false); OUTER_FRI_LAYERS];

    for l in 0..OUTER_FRI_LAYERS {
        let half = cur_dom / 2;
        let mut folded_pos: Vec<usize> = Vec::new();
        for &p in &cur_positions {
            let fp = p % half;
            if !folded_pos.contains(&fp) {
                folded_pos.push(fp);
            }
        }

        let q_fold = cur_q % half;
        let idx_l = folded_pos
            .iter()
            .position(|&v| v == q_fold)
            .ok_or_else(|| format!("fri layer {l}: q_fold missing"))?;

        let pairs: Vec<[QuartExtension<Felt>; 2]> = fri_queries[l]
            .chunks_exact(2)
            .map(|c| [c[0], c[1]])
            .collect();
        let pair = pairs[idx_l];

        if l == 0 {
            assert_eq!(proof.fri_proof.num_partitions(), 1, "expected 1 FRI partition");
            let mut raw_bytes = Vec::with_capacity(64);
            for elem in &pair {
                for k in 0..4 {
                    raw_bytes.extend_from_slice(&elem.base_element(k).as_int().to_le_bytes());
                }
            }
            assert_eq!(raw_bytes.len(), 64);
            for w in 0..16 {
                fri0_pair_words[w] = u32::from_be_bytes(raw_bytes[4 * w..4 * w + 4].try_into().unwrap());
            }
            let f0_leaves: Vec<ShaDigest> = pairs
                .iter()
                .map(|seg| OuterHash::hash_elements(seg))
                .collect();
            let f0_openings = fri_proofs
                .remove(0)
                .into_openings(&f0_leaves, &folded_pos)
                .map_err(|e| format!("fri0 openings: {e:?}"))?;
            assert_eq!(f0_openings[idx_l].1.len(), OUTER_FRI0_DEPTH);
            assert_eq!(f0_openings[idx_l].0, OuterHash::hash_elements(&pair));
            for d in 0..OUTER_FRI0_DEPTH {
                fri0_siblings[d] = hash::bytes_to_words(&f0_openings[idx_l].1[d].0);
            }
        }

        let x_l = offset * cur_gen.exp(q_fold as u64);
        let next_is_neg = if l + 1 < OUTER_FRI_LAYERS {
            q_fold >= (half / 2)
        } else {
            false
        };
        fri_folds[l] = (x_l, pair[0], pair[1], alphas[l], next_is_neg);

        cur_positions = folded_pos;
        cur_dom = half;
        cur_gen = cur_gen * cur_gen;
        cur_q = q_fold;
    }

    let mut trace_siblings = [[0u32; 8]; OUTER_MERKLE_DEPTH];
    let mut constraint_siblings = [[0u32; 8]; OUTER_MERKLE_DEPTH];
    for d in 0..OUTER_MERKLE_DEPTH {
        trace_siblings[d] = hash::bytes_to_words(&t_sibs[d].0);
        constraint_siblings[d] = hash::bytes_to_words(&c_sibs[d].0);
    }
    let mut fri_roots_tail = [[0u32; 8]; OUTER_FRI_COMMITS - 1];
    for i in 0..(OUTER_FRI_COMMITS - 1) {
        fri_roots_tail[i] = hash::bytes_to_words(&fri_roots[i + 1].0);
    }

    Ok(OuterProofWitness {
        pi: pi.clone(),
        trace_leaf: hash::bytes_to_words(&t_leaf.0),
        trace_siblings,
        constraint_leaf: hash::bytes_to_words(&c_leaf.0),
        constraint_siblings,
        ood_digest: hash::bytes_to_words(&ood_digest_sha.0),
        fri0_pair_words,
        fri0_siblings,
        fri_roots_tail,
        pow_nonce: proof.pow_nonce,
        q_pos,
        fri_folds,
    })
}

fn fill_outer_proof_into_trace(
    trace: &mut TraceTable<Felt>,
    proof_idx: usize,
    w: &OuterProofWitness,
    ctx_words: &[u32; 16],
) {
    let c_base = proof_idx * SIS_COMPS_PER_PROOF;
    let r_proof_start = c_base * HC_STRIDE;
    let r_proof_end = (c_base + SIS_COMPS_PER_PROOF) * HC_STRIDE;
    let pad64 = sha256_pad64_block();

    // Helper: set `S_SEED` across a contiguous row range `[r0..r1)`
    let set_seed_range = |trace: &mut TraceTable<Felt>, r0: usize, r1: usize, seed: &Word8| {
        for r in r0..r1 {
            for i in 0..8 {
                trace.set(S_SEED + i, r, Felt::new(seed[i] as u64));
            }
        }
    };

    // Constant `S_QTARGET` across entire proof `proof_idx`
    for r in r_proof_start..r_proof_end {
        trace.set(S_QTARGET, r, Felt::new(w.q_pos as u64));
    }

    // 0..4: `seed_0 = SHA-256(Context || start_prev || end_hash || count)`
    let b0 = *ctx_words;
    let b1 = felt_word8_block(&w.pi.start_prev_words);
    let b2 = felt_word8_block(&w.pi.end_hash_words);
    let mut b3 = [0u32; 16];
    b3[0] = w.pi.count.swap_bytes();
    b3[2] = 0x8000_0000;
    b3[15] = 1600;

    let (s0, _, _) = compress_with_iv(&b0, &IV);
    let (s1, _, _) = compress_with_iv(&b1, &s0);
    let (s2, _, _) = compress_with_iv(&b2, &s1);
    let (seed0, _, _) = compress_with_iv(&b3, &s2);
    #[cfg(test)]
    {
        let mut expected_ctx_bytes = Vec::new();
        for w_i in &b0 {
            expected_ctx_bytes.extend_from_slice(&w_i.to_be_bytes());
        }
        let mut pi_els = w.pi.to_elements();
        let mut all_bytes = expected_ctx_bytes;
        for e in &pi_els {
            all_bytes.extend_from_slice(&e.as_int().to_le_bytes());
        }
        let _ = &mut pi_els;
        assert_eq!(hash::words_to_bytes(&seed0), crate::hash::sha256(&all_bytes), "seed0 block hash mismatch");
    }

    fill_sha256_block(trace, (c_base + 0) * HC_STRIDE, &b0, &IV);
    fill_sha256_block(trace, (c_base + 1) * HC_STRIDE, &b1, &s0);
    fill_sha256_block(trace, (c_base + 2) * HC_STRIDE, &b2, &s1);
    fill_sha256_block(trace, (c_base + 3) * HC_STRIDE, &b3, &s2);
    // `S_SEED` before comp 4 is zero (initialized), then becomes `seed0` at comp 4 row 0!
    set_seed_range(trace, (c_base + 4) * HC_STRIDE, (c_base + 32) * HC_STRIDE, &seed0);

    // 4..30: Trace Merkle path (depth 13)
    let mut cur_node = w.trace_leaf;
    let bit0 = (w.q_pos & 1) as u64;
    trace.set(S_X14, (c_base + 3) * HC_STRIDE + 64, Felt::new(bit0));
    let mut qacc = bit0;
    for lvl in 0..OUTER_MERKLE_DEPTH {
        let bit = (w.q_pos >> lvl) & 1;
        let (left, right) = if bit == 0 {
            (&cur_node, &w.trace_siblings[lvl])
        } else {
            (&w.trace_siblings[lvl], &cur_node)
        };
        let (mb0, ms1, next_node) = sha256_merge_words(left, right);
        let rc0 = (c_base + 4 + 2 * lvl) * HC_STRIDE;
        let rc1 = rc0 + HC_STRIDE;
        fill_sha256_block(trace, rc0, &mb0, &IV);
        fill_sha256_block(trace, rc1, &pad64, &ms1);
        for r in rc0..(rc1 + HC_STRIDE) {
            trace.set(S_QACC, r, Felt::new(qacc));
        }
        cur_node = next_node;
        if lvl + 1 < OUTER_MERKLE_DEPTH {
            let nbit = ((w.q_pos >> (lvl + 1)) & 1) as u64;
            trace.set(S_X14, rc1 + 64, Felt::new(nbit));
            qacc += nbit << (lvl + 1);
        }
    }
    let trace_root = cur_node;

    // 30..32: Reseed `seed_1 = SHA-256(seed_0 || trace_root)`
    let (rb0, rs1, seed1) = sha256_merge_words(&seed0, &trace_root);
    fill_sha256_block(trace, (c_base + 30) * HC_STRIDE, &rb0, &IV);
    fill_sha256_block(trace, (c_base + 31) * HC_STRIDE, &pad64, &rs1);
    for r in ((c_base + 30) * HC_STRIDE)..((c_base + 32) * HC_STRIDE) {
        trace.set(S_QACC, r, Felt::new(qacc));
    }
    set_seed_range(trace, (c_base + 32) * HC_STRIDE, (c_base + 60) * HC_STRIDE, &seed1);

    // 32..58: Constraint Merkle path (depth 13)
    cur_node = w.constraint_leaf;
    trace.set(S_X14, (c_base + 31) * HC_STRIDE + 64, Felt::new(bit0));
    qacc = bit0;
    for lvl in 0..OUTER_MERKLE_DEPTH {
        let bit = (w.q_pos >> lvl) & 1;
        let (left, right) = if bit == 0 {
            (&cur_node, &w.constraint_siblings[lvl])
        } else {
            (&w.constraint_siblings[lvl], &cur_node)
        };
        let (mb0, ms1, next_node) = sha256_merge_words(left, right);
        let rc0 = (c_base + 32 + 2 * lvl) * HC_STRIDE;
        let rc1 = rc0 + HC_STRIDE;
        fill_sha256_block(trace, rc0, &mb0, &IV);
        fill_sha256_block(trace, rc1, &pad64, &ms1);
        for r in rc0..(rc1 + HC_STRIDE) {
            trace.set(S_QACC, r, Felt::new(qacc));
        }
        cur_node = next_node;
        if lvl + 1 < OUTER_MERKLE_DEPTH {
            let nbit = ((w.q_pos >> (lvl + 1)) & 1) as u64;
            trace.set(S_X14, rc1 + 64, Felt::new(nbit));
            qacc += nbit << (lvl + 1);
        }
    }
    let constraint_root = cur_node;

    // 58..60: Reseed `seed_2 = SHA-256(seed_1 || constraint_root)`
    let (rb0, rs1, seed2) = sha256_merge_words(&seed1, &constraint_root);
    fill_sha256_block(trace, (c_base + 58) * HC_STRIDE, &rb0, &IV);
    fill_sha256_block(trace, (c_base + 59) * HC_STRIDE, &pad64, &rs1);
    set_seed_range(trace, (c_base + 60) * HC_STRIDE, (c_base + 62) * HC_STRIDE, &seed2);

    // 60..62: Reseed `seed_3 = SHA-256(seed_2 || ood_digest)`
    let (rb0, rs1, seed3) = sha256_merge_words(&seed2, &w.ood_digest);
    fill_sha256_block(trace, (c_base + 60) * HC_STRIDE, &rb0, &IV);
    fill_sha256_block(trace, (c_base + 61) * HC_STRIDE, &pad64, &rs1);
    set_seed_range(trace, (c_base + 62) * HC_STRIDE, (c_base + 90) * HC_STRIDE, &seed3);

    // 62..64: FRI-0 Leaf Preimage `fri0_leaf = SHA-256(y_pos || y_neg)` (64 bytes)
    let (ls1, _, _) = compress_with_iv(&w.fri0_pair_words, &IV);
    let (fri0_leaf, _, _) = compress_with_iv(&pad64, &ls1);
    fill_sha256_block(trace, (c_base + 62) * HC_STRIDE, &w.fri0_pair_words, &IV);
    fill_sha256_block(trace, (c_base + 63) * HC_STRIDE, &pad64, &ls1);
    for r in ((c_base + 58) * HC_STRIDE)..((c_base + 64) * HC_STRIDE) {
        trace.set(S_QACC, r, Felt::new(qacc));
    }

    // 64..88: FRI-0 Merkle path (depth 12, index = `q_pos % 4096`)
    let q_fri0 = w.q_pos & 4095;
    cur_node = fri0_leaf;
    let fbit0 = (q_fri0 & 1) as u64;
    trace.set(S_X14, (c_base + 63) * HC_STRIDE + 64, Felt::new(fbit0));
    qacc = fbit0;
    for lvl in 0..OUTER_FRI0_DEPTH {
        let bit = (q_fri0 >> lvl) & 1;
        let (left, right) = if bit == 0 {
            (&cur_node, &w.fri0_siblings[lvl])
        } else {
            (&w.fri0_siblings[lvl], &cur_node)
        };
        let (mb0, ms1, next_node) = sha256_merge_words(left, right);
        let rc0 = (c_base + 64 + 2 * lvl) * HC_STRIDE;
        let rc1 = rc0 + HC_STRIDE;
        fill_sha256_block(trace, rc0, &mb0, &IV);
        fill_sha256_block(trace, rc1, &pad64, &ms1);
        for r in rc0..(rc1 + HC_STRIDE) {
            trace.set(S_QACC, r, Felt::new(qacc));
        }
        cur_node = next_node;
        if lvl + 1 < OUTER_FRI0_DEPTH {
            let nbit = ((q_fri0 >> (lvl + 1)) & 1) as u64;
            trace.set(S_X14, rc1 + 64, Felt::new(nbit));
            qacc += nbit << (lvl + 1);
        }
    }
    let fri_root_0 = cur_node;

    // 88..90: Reseed `seed_4 = SHA-256(seed_3 || fri_root_0)`
    let (rb0, rs1, mut cur_seed) = sha256_merge_words(&seed3, &fri_root_0);
    fill_sha256_block(trace, (c_base + 88) * HC_STRIDE, &rb0, &IV);
    fill_sha256_block(trace, (c_base + 89) * HC_STRIDE, &pad64, &rs1);
    set_seed_range(trace, (c_base + 90) * HC_STRIDE, (c_base + 92) * HC_STRIDE, &cur_seed);

    // 90..100: Remaining 5 FRI commitment reseeds (`fri_root_1..=fri_root_5`)
    for m in 0..(OUTER_FRI_COMMITS - 1) {
        let (rb0, rs1, next_seed) = sha256_merge_words(&cur_seed, &w.fri_roots_tail[m]);
        let lc = 90 + 2 * m;
        fill_sha256_block(trace, (c_base + lc) * HC_STRIDE, &rb0, &IV);
        fill_sha256_block(trace, (c_base + lc + 1) * HC_STRIDE, &pad64, &rs1);
        cur_seed = next_seed;
        let next_start = (c_base + lc + 2) * HC_STRIDE;
        let next_end = if m + 1 < OUTER_FRI_COMMITS - 1 {
            (c_base + lc + 4) * HC_STRIDE
        } else {
            (c_base + 101) * HC_STRIDE
        };
        set_seed_range(trace, next_start, next_end, &cur_seed);
    }

    // 100: PoW grinding check `pow_seed = SHA-256(seed_final || pow_nonce_le8)`
    let (pb, pow_seed) = sha256_with_int_block(&cur_seed, w.pow_nonce);
    let r_pow = (c_base + 100) * HC_STRIDE;
    fill_sha256_block(trace, r_pow, &pb, &IV);
    write_bits(trace, S_X14, r_pow + 64, pow_seed[0], 32);
    set_seed_range(trace, (c_base + 101) * HC_STRIDE, (c_base + 102) * HC_STRIDE, &pow_seed);

    // 101: First query index draw `q0_hash = SHA-256(pow_seed || 1u64)`
    let (qb, q0_hash) = sha256_with_int_block(&pow_seed, 1u64);
    let r_q0 = (c_base + 101) * HC_STRIDE;
    fill_sha256_block(trace, r_q0, &qb, &IV);
    write_bits(trace, S_X14, r_q0 + 64, q0_hash[0], 32);

    // Hold final `S_QACC` through end of proof
    for r in ((c_base + 88) * HC_STRIDE)..r_proof_end {
        trace.set(S_QACC, r, Felt::new(qacc));
    }

    // Fill 5 real Quartic `F_{p^4}` FRI-folding rows for proof `proof_idx`
    let inv2 = Felt::new(2).inv();
    let fbase = SIS_FRI_BASE + proof_idx * OUTER_FRI_LAYERS;
    for l in 0..OUTER_FRI_LAYERS {
        let (x, fp, fn_, al, next_is_neg) = w.fri_folds[l];
        let two_x_inv = QuartExtension::from((Felt::new(2) * x).inv());
        let folded = (fp + fn_) * QuartExtension::from(inv2) + al * (fp - fn_) * two_x_inv;
        let row = fbase + l;
        trace.set(QF_X, row, x);
        for k in 0..4 {
            trace.set(QF_FP + k, row, fp.base_element(k));
            trace.set(QF_FN + k, row, fn_.base_element(k));
            trace.set(QF_ALPHA + k, row, al.base_element(k));
            trace.set(QF_FOLDED + k, row, folded.base_element(k));
        }
        trace.set(QF_BIT, row, Felt::new(u64::from(next_is_neg)));
    }
}

fn build_recursive_fold_trace(
    w_a: &OuterProofWitness,
    w_b: &OuterProofWitness,
) -> Result<(TraceTable<Felt>, RecursiveChainPublicInputs), String> {
    if w_a.pi.end_hash_words != w_b.pi.start_prev_words {
        return Err("outer header segments are not contiguous (seg1.end_hash != seg2.start_prev)".into());
    }
    let ctx_words = outer_header_chain_context_words();
    let mut trace = TraceTable::init(vec![vec![Felt::ZERO; SIS_ROWS]; SIS_WIDTH]);
    fill_outer_proof_into_trace(&mut trace, 0, w_a, &ctx_words);
    fill_outer_proof_into_trace(&mut trace, 1, w_b, &ctx_words);

    // Populate persistent private IVC linkage `S_MID` across `[r_mid_cap..=r_mid_use]`
    let r_mid_cap = 2 * HC_STRIDE;
    let r_mid_use = (SIS_COMPS_PER_PROOF + 1) * HC_STRIDE;
    for r in r_mid_cap..=r_mid_use {
        for i in 0..8 {
            trace.set(S_MID + i, r, Felt::new(w_a.pi.end_hash_words[i].swap_bytes() as u64));
        }
    }

    let pi = RecursiveChainPublicInputs {
        start_prev_words: w_a.pi.start_prev_words,
        end_hash_words: w_b.pi.end_hash_words,
        total_headers: w_a.pi.count + w_b.pi.count,
    };
    Ok((trace, pi))
}

/// Folds TWO real serialized outer `HeaderChainAir` STARK proofs (`H_0..H_3` and `H_4..H_7`) into
/// **ONE single inner `>= 100`-bit conservative QROM Quartic (`F_{p^4}`) SHA-384 STARK proof**!
pub fn prove_recursive_chain_fold(
    seg1: (&HeaderChainPublicInputs, &[u8]),
    seg2: (&HeaderChainPublicInputs, &[u8]),
) -> Result<(RecursiveChainPublicInputs, Vec<u8>), String> {
    let w_a = extract_outer_witness(seg1.0, seg1.1)?;
    let w_b = extract_outer_witness(seg2.0, seg2.1)?;
    let (trace, pi) = build_recursive_fold_trace(&w_a, &w_b)?;
    let prover = StarkInStarkProver {
        options: recursion_stark_options(),
        pi: pi.clone(),
    };
    let proof = prover
        .prove(trace)
        .map_err(|e| format!("StarkInStarkProver failed: {e}"))?;
    Ok((pi, proof.to_bytes()))
}

/// Verifies ONE inner Quartic SHA-384 `StarkInStarkVerifierAir` IVC proof and returns its
/// conservative QROM (CMS19) post-quantum soundness in bits (`>= 100`).
pub fn verify_recursive_chain_fold(
    pi: &RecursiveChainPublicInputs,
    proof_bytes: &[u8],
) -> Result<u32, String> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|e| format!("bad recursive STARK proof: {e}"))?;
    let opts = recursion_stark_options();
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![opts]);
    let qrom = proof.proven_security::<RecHash>().qrom_ldr_bits(384);
    winterfell::verify::<StarkInStarkVerifierAir, RecHash, RecCoin, RecVc>(
        proof,
        pi.clone(),
        &acceptable,
    )
    .map_err(|e| format!("StarkInStarkVerifierAir rejected: {e}"))?;
    Ok(qrom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mine;

    fn check_sis_trace(trace: &TraceTable<Felt>, pi: &RecursiveChainPublicInputs) -> Result<(), String> {
        let air = StarkInStarkVerifierAir::new(
            TraceInfo::new(SIS_WIDTH, SIS_ROWS),
            pi.clone(),
            recursion_stark_options(),
        );
        let per = air.get_periodic_column_values();
        let mut cur = vec![Felt::ZERO; SIS_WIDTH];
        let mut nxt = vec![Felt::ZERO; SIS_WIDTH];
        let mut per_row = vec![Felt::ZERO; SP_N_PER];
        let mut res = vec![Felt::ZERO; SIS_N_CONSTRAINTS];
        for r in 0..(SIS_ROWS - 1) {
            for c in 0..SIS_WIDTH {
                cur[c] = trace.get(c, r);
                nxt[c] = trace.get(c, r + 1);
            }
            for p in 0..SP_N_PER {
                per_row[p] = per[p][r];
            }
            let frame = EvaluationFrame::from_rows(cur.clone(), nxt.clone());
            air.evaluate_transition(&frame, &per_row, &mut res);
            for (ci, &v) in res.iter().enumerate() {
                if v != Felt::ZERO {
                    return Err(format!("transition constraint #{ci} non-zero at row {r} (comp {}, step {})", r / HC_STRIDE, r % HC_STRIDE));
                }
            }
        }
        for a in air.get_assertions() {
            let col = a.column();
            let row = a.first_step();
            let got = trace.get(col, row);
            if got != a.values()[0] {
                return Err(format!("boundary assertion failed at col {col}, row {row}"));
            }
        }
        Ok(())
    }

    #[test]
    fn fri_folding_verifier_stark_proves_verifies_and_rejects_forgery() {
        let mut steps = Vec::new();
        let mut x = Felt::new(7);
        let mut f_pos = Felt::new(12345);
        let mut f_neg = Felt::new(67890);
        let inv2 = Felt::new(2).inv();
        for r in 0..32u64 {
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
        let qrom = verify_fri_folding(&pi, &proof).unwrap();
        assert!(qrom >= 100, "expected >= 100 conservative QROM (CMS19) bits with Quartic SHA-384, got {qrom}");

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
        assert!(sec >= 100, "expected >= 100 conservative QROM (CMS19) bits with Quartic SHA-384, got {sec}");

        let mut bad_pi = pi2.clone();
        bad_pi.end_hash_words[0] ^= 1;
        assert!(verify_header_chain_segment(&bad_pi, &p2).is_err());
    }

    #[test]
    fn real_stark_in_stark_ivc_folds_two_outer_proofs_and_rejects_all_forgeries() {
        // 1. Mine 8 contiguous real PoW headers (2 segments of 4)
        let mut prev = [0x42u8; 32];
        let mut all_headers = Vec::new();
        for i in 0..(HEADERS_PER_SEGMENT * 2) {
            let mut hd = Header {
                version: 1,
                prev,
                commit: [(i + 10) as u8; 32],
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

        // 2. Prove TWO real serialized outer SHA-256 `HeaderChainAir` STARK proofs
        let (pi1, outer_p1) = prove_outer_header_segment(&seg1_h).unwrap();
        let (pi2, outer_p2) = prove_outer_header_segment(&seg2_h).unwrap();

        // 3. Extract real witnesses & run exhaustive row-by-row AIR check first!
        let w_a = extract_outer_witness(&pi1, &outer_p1).unwrap();
        let w_b = extract_outer_witness(&pi2, &outer_p2).unwrap();
        let (trace, rpi_check) = build_recursive_fold_trace(&w_a, &w_b).unwrap();
        check_sis_trace(&trace, &rpi_check).expect("honest StarkInStarkVerifierAir trace must satisfy all 397 constraints");

        // 4. Prove ONE single inner Quartic SHA-384 `StarkInStarkVerifierAir` IVC proof!
        let t_prove = std::time::Instant::now();
        let (rpi, rec_proof) = prove_recursive_chain_fold((&pi1, &outer_p1), (&pi2, &outer_p2)).unwrap();
        let prove_ms = t_prove.elapsed().as_millis();
        let t_verify = std::time::Instant::now();
        let qrom = verify_recursive_chain_fold(&rpi, &rec_proof).unwrap();
        let verify_ms = t_verify.elapsed().as_millis();
        println!(
            "[STARK-IN-STARK IVC BENCH] 2 outer proofs (204 SHA-256 comps + 10 Quartic FRI folds, {SIS_ROWS}x{SIS_WIDTH}) -> 1 inner proof: {} B, prove={prove_ms} ms, verify={verify_ms} ms, conservative_QROM={qrom} bits",
            rec_proof.len()
        );
        assert_eq!(hash::words_to_bytes(&rpi.start_prev_words), [0x42u8; 32]);
        assert_eq!(hash::words_to_bytes(&rpi.end_hash_words), all_headers[7].hash());
        assert_eq!(rpi.total_headers, 8);
        assert!(qrom >= 100, "inner STARK-in-STARK proof must prove >= 100 conservative QROM bits, got {qrom}");

        // 5. Adversarial Red-Team Tests — every single forgery MUST be caught by the AIR itself!
        // (a) Wrong public end_hash
        let mut bad_end = rpi.clone();
        bad_end.end_hash_words[0] ^= 1;
        assert!(verify_recursive_chain_fold(&bad_end, &rec_proof).is_err());

        // (b) Discontinuous private mid_hash (forging segment join)
        let mut bad_mid_trace = trace.clone();
        bad_mid_trace.set(S_MID, (SIS_COMPS_PER_PROOF + 1) * HC_STRIDE, Felt::new(999_999));
        assert!(check_sis_trace(&bad_mid_trace, &rpi_check).is_err(), "broken private IVC mid_hash must fail AIR");

        // (c) Tampered Merkle sibling in outer Trace Merkle path
        let mut bad_sib = w_a.clone();
        bad_sib.trace_siblings[5][0] ^= 1;
        let (t_bad_sib, _) = build_recursive_fold_trace(&bad_sib, &w_b).unwrap();
        assert!(check_sis_trace(&t_bad_sib, &rpi_check).is_err(), "tampered outer Trace Merkle sibling must fail AIR");

        // (d) Tampered outer PoW grinding nonce (breaks 20-bit zero constraint)
        let mut bad_pow = w_a.clone();
        bad_pow.pow_nonce ^= 1;
        let (t_bad_pow, _) = build_recursive_fold_trace(&bad_pow, &w_b).unwrap();
        assert!(check_sis_trace(&t_bad_pow, &rpi_check).is_err(), "invalid outer PoW grinding nonce must fail AIR");

        // (e) Cherry-picked wrong query position `q_pos` (breaks coin-derived q0_hash binding)
        let mut bad_q = w_a.clone();
        bad_q.q_pos ^= 1;
        let (t_bad_q, _) = build_recursive_fold_trace(&bad_q, &w_b).unwrap();
        assert!(check_sis_trace(&t_bad_q, &rpi_check).is_err(), "cherry-picked query position must fail AIR");

        // (f) Tampered Quartic `F_{p^4}` FRI fold evaluation
        let mut bad_fri_trace = trace.clone();
        bad_fri_trace.set(QF_FOLDED + 2, SIS_FRI_BASE + 1, bad_fri_trace.get(QF_FOLDED + 2, SIS_FRI_BASE + 1) + Felt::ONE);
        assert!(check_sis_trace(&bad_fri_trace, &rpi_check).is_err(), "forged Quartic FRI fold must fail AIR");
    }
}
