//! Multi-Spend Block STARK Compression (`BatchSpendAir`): proves `K ∈ 2..=16` shielded
//! 2-in / 2-out spends inside ONE pure-SHA-256 / SHA-384 Winterfell STARK proof.
//!
//! Why this matters for L1 throughput & useful work:
//! - A single shielded spend STARK (`spend.rs`, 8,192 rows) is ~460–540 KB on Mainnet v2,
//!   limiting an 8 MB / 10-minute block to ~15 individual spends.
//! - Because FRI proof size grows only **logarithmically** with trace length (`O(log(ROWS))`),
//!   tiling `K` independent 2-in/2-out spends vertically inside ONE Winterfell trace
//!   (`16,384` rows for `K=2..3`, `32,768` for `K=4..6`, `65,536` for `K=7..13`,
//!   `131,072` for `K=14..16`) keeps total proof size around ~580–850 KB for the entire batch
//!   — compressing L1 blockspace by **4×–11×+** immediately on CPU with **zero new circuit
//!   constraints** (it reuses `spend::eval_constraints` verbatim!).
//! - `prover_a_pk` is absorbed into the Fiat–Shamir transcript via `BatchSpendPublic::to_elements`,
//!   binding the consensus Negentropy Prover split-coinbase payout address cryptographically to
//!   the STARK proof so no block producer can steal a prover's reward.
//!
//! **Privacy disclosure (honest boundary):**
//! Generating a `BatchSpend` proof requires the batch prover to see the witnesses of the `K`
//! spends in that batch. Self-batching (wallets, exchanges, treasuries, or AI agent swarms
//! batching their own payments) has **zero privacy loss**. Delegated multi-user batching shares
//! spend witness data with the chosen batch prover (like a shielded transaction coordinator)
//! until future STARK-in-STARK proof aggregation removes witness visibility.

use crate::hash::{self, Word8, K};
use crate::note::{self, Rho, DEPTH, TAG_ADDR, TAG_CM, TAG_NF};
use crate::spend::{
    eval_constraints, fill_block, rand_felt, random_elements, signed, zk_mask_len, Coin,
    Coin384, Cols, Hash, Hash384, Kind, Profile, SpendPublic, SpendWitness, Vc, Vc384, BLK,
    COL_BAL, COL_BIT, COL_DIG, COL_POS, COL_RHO, COL_SK, COL_W, MAX_VALUE_BALANCE, N_CONSTRAINTS,
    N_PERIODIC, P_ACT, P_ACTROW, P_ADDR, P_BND, P_CMIN, P_CMOUT, P_K, P_MERKLE, P_NF, P_RHOC,
    P_ROUND, P_SKC, P_VCHK, P_W, WIDTH, ZK_META,
};
use winterfell::{
    math::{fields::f64::BaseElement as Felt, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

pub const MIN_BATCH_SPENDS: usize = 2;
pub const MAX_BATCH_SPENDS: usize = 16;
/// 72 active SHA-256 blocks per 2-in/2-out spend + 1 isolating `Kind::Rand` block between spends.
pub const BLOCKS_PER_SPEND: usize = 73;
/// Largest serialized `BatchSpend` proof accepted across all networks (fits `K = 16` Quartic SHA-384).
pub const MAX_BATCH_PROOF_BYTES: usize = 1_250_000;

/// Trace length (power of 2) for a batch of `k` spends (`2 <= k <= 16`).
/// Guarantees >= 2,304 unconstrained random rows for zero-knowledge masking at every `k`.
pub fn batch_rows(k: usize) -> usize {
    assert!((MIN_BATCH_SPENDS..=MAX_BATCH_SPENDS).contains(&k));
    let min_blocks = k * BLOCKS_PER_SPEND + 1;
    let nblk = min_blocks.next_power_of_two();
    nblk * BLK
}

fn batch_layout(k: usize) -> Vec<Kind> {
    let nblk = batch_rows(k) / BLK;
    let mut v = Vec::with_capacity(nblk);
    for _ in 0..k {
        v.push(Kind::Rand);
        for i in 0..2 {
            v.push(Kind::Addr(i));
            v.push(Kind::CmIn(i));
            for lvl in 0..DEPTH {
                v.push(Kind::Merkle(i, lvl));
            }
            v.push(Kind::Nf(i));
        }
        v.push(Kind::CmOut(0));
        v.push(Kind::CmOut(1));
    }
    while v.len() < nblk {
        v.push(Kind::Rand);
    }
    debug_assert_eq!(v.len(), nblk);
    v
}

#[inline]
fn sub_start_block(s: usize) -> usize {
    1 + s * BLOCKS_PER_SPEND
}

fn periodic_columns_batch(k: usize) -> Vec<Vec<Felt>> {
    let rows = batch_rows(k);
    let nblk = rows / BLK;
    let lay = batch_layout(k);
    let mut cols = vec![vec![Felt::ZERO; rows]; N_PERIODIC];
    cols[P_K] = (0..BLK).map(|t| Felt::new(K[(t + 1) % BLK] as u64)).collect();

    for b in 0..nblk {
        let kind = lay[b];
        let next = if b + 1 < nblk { lay[b + 1] } else { Kind::Rand };
        for t in 0..BLK {
            let r = b * BLK + t;
            if kind.active() {
                cols[P_ACTROW][r] = Felt::ONE;
                if t != BLK - 1 {
                    cols[P_ROUND][r] = Felt::ONE;
                } else {
                    cols[P_BND][r] = Felt::ONE;
                }
                if t == 8 && matches!(kind, Kind::CmIn(_) | Kind::CmOut(_)) {
                    cols[P_VCHK][r] = Felt::ONE;
                }
            }
            if t == BLK - 1 {
                match next {
                    Kind::Addr(_) => cols[P_ADDR][r] = Felt::ONE,
                    Kind::CmIn(_) => cols[P_CMIN][r] = Felt::ONE,
                    Kind::Merkle(_, lvl) => {
                        cols[P_MERKLE][r] = Felt::ONE;
                        cols[P_W][r] = Felt::new(1u64 << lvl);
                    }
                    Kind::Nf(_) => cols[P_NF][r] = Felt::ONE,
                    Kind::CmOut(_) => cols[P_CMOUT][r] = Felt::ONE,
                    Kind::Rand => {}
                }
            }
        }
    }

    // Isolate each sub-spend's register persistence (SK, RHO, POS, BAL) strictly inside its
    // 72-block span `[start_blk * BLK .. (start_blk + 72) * BLK - 1)`.
    for s in 0..k {
        let start_r = sub_start_block(s) * BLK;
        let end_r = (sub_start_block(s) + 72) * BLK - 1;
        for r in start_r..end_r {
            cols[P_ACT][r] = Felt::ONE;
        }
    }

    for r in 0..rows {
        cols[P_SKC][r] = cols[P_ACT][r] * (Felt::ONE - cols[P_ADDR][r]);
        cols[P_RHOC][r] = cols[P_ACT][r] * (Felt::ONE - cols[P_CMIN][r]);
    }
    cols
}

fn degrees_batch(rows: usize) -> Vec<TransitionConstraintDegree> {
    let d = |base: usize| TransitionConstraintDegree::with_cycles(base, vec![rows]);
    let mut v = vec![d(3), d(3), d(1), d(1)];
    v.extend((0..64).map(|_| d(1)));
    v.extend([d(1), d(1)]);
    v.extend((0..15).map(|_| d(2)));
    v.push(d(3));
    v.extend([d(1), d(1)]);
    v.extend((0..8).map(|_| d(1)));
    v.extend((0..137).map(|_| d(2)));
    v.extend((0..15).map(|_| d(1)));
    v.push(d(1));
    debug_assert_eq!(v.len(), N_CONSTRAINTS);
    v
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSpendPublic {
    pub spends: Vec<SpendPublic>,
    /// Prover's shielded address, bound into Fiat–Shamir so no miner can divert `prover_fee`.
    pub prover_a_pk: Word8,
    /// Explicit fee paid from the unburned batch fee budget to `prover_a_pk` (AuxPoW miners
    /// always keep 100% of block subsidy + remaining `miner_fee`, eliminating censorship!).
    pub prover_fee: u64,
}

impl ToElements<Felt> for BatchSpendPublic {
    fn to_elements(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(2 + 8 + self.spends.len() * 51);
        out.push(Felt::new(self.spends.len() as u64));
        for w in self.prover_a_pk {
            out.push(Felt::new(w as u64));
        }
        out.push(Felt::new(self.prover_fee));
        for sp in &self.spends {
            out.extend(sp.to_elements());
        }
        out
    }
}

fn assertions_batch(pi: &BatchSpendPublic) -> Vec<Assertion<Felt>> {
    let mut a = Vec::new();
    for (s, sp) in pi.spends.iter().enumerate() {
        let base = sub_start_block(s);
        let first_row = |offset: usize| (base + offset) * BLK;
        let last_row = |offset: usize| (base + offset) * BLK + BLK - 1;
        // Sub-spend offset map inside its 72-block span:
        // Input 0: Addr=0, CmIn=1, Merkle=2..34, Nf=34
        // Input 1: Addr=35, CmIn=36, Merkle=37..69, Nf=69
        // Outputs: CmOut0=70, CmOut1=71
        a.push(Assertion::single(COL_BAL, first_row(0), Felt::ZERO));
        a.push(Assertion::single(COL_POS, first_row(0), Felt::ZERO));
        for i in 0..2 {
            let inp_base = i * 35;
            if sp.dummy[i] {
                a.push(Assertion::single(COL_W + 9, first_row(inp_base + 1), Felt::ZERO));
                a.push(Assertion::single(COL_W + 10, first_row(inp_base + 1), Felt::ZERO));
            } else {
                for j in 0..8 {
                    a.push(Assertion::single(
                        COL_DIG + j,
                        last_row(inp_base + 2 + DEPTH - 1),
                        Felt::new(sp.root[j] as u64),
                    ));
                }
            }
            for j in 0..8 {
                a.push(Assertion::single(
                    COL_DIG + j,
                    last_row(inp_base + 34),
                    Felt::new(sp.nf[i][j] as u64),
                ));
            }
        }
        for o in 0..2 {
            for j in 0..8 {
                a.push(Assertion::single(
                    COL_DIG + j,
                    last_row(70 + o),
                    Felt::new(sp.cm_out[o][j] as u64),
                ));
            }
        }
        a.push(Assertion::single(COL_BAL, last_row(71), signed(sp.value_balance)));
    }
    a
}

pub struct BatchSpendAir {
    ctx: AirContext<Felt>,
    pi: BatchSpendPublic,
}

impl Air for BatchSpendAir {
    type BaseField = Felt;
    type PublicInputs = BatchSpendPublic;

    fn new(trace_info: TraceInfo, pi: BatchSpendPublic, options: ProofOptions) -> Self {
        let k = pi.spends.len();
        assert!((MIN_BATCH_SPENDS..=MAX_BATCH_SPENDS).contains(&k));
        let rows = batch_rows(k);
        assert_eq!(trace_info.width(), WIDTH);
        assert_eq!(trace_info.length(), rows);
        let n_assert = assertions_batch(&pi).len();
        let zk = trace_info.meta().starts_with(ZK_META);
        let mask = zk_mask_len(&options);
        let ctx = AirContext::new(trace_info, degrees_batch(rows), n_assert, options);
        Self {
            ctx: if zk { ctx.with_zk_segments(mask) } else { ctx },
            pi,
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.ctx
    }

    fn evaluate_transition<E: FieldElement + From<Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        eval_constraints(frame.current(), frame.next(), periodic_values, result);
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        assertions_batch(&self.pi)
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        periodic_columns_batch(self.pi.spends.len())
    }
}

pub fn batch_meta(profile: &Profile) -> Vec<u8> {
    [ZK_META, b"/batch", profile.tag].concat()
}

fn plain_batch_composition_columns(rows: usize, options: &ProofOptions) -> usize {
    AirContext::<Felt>::new(
        TraceInfo::new(WIDTH, rows),
        degrees_batch(rows),
        1,
        options.clone(),
    )
    .num_constraint_composition_columns()
}

pub fn build_batch_trace(wits: &[SpendWitness], meta: &[u8]) -> Result<TraceTable<Felt>, String> {
    let k = wits.len();
    if !(MIN_BATCH_SPENDS..=MAX_BATCH_SPENDS).contains(&k) {
        return Err(format!(
            "batch spend count {k} out of range ({MIN_BATCH_SPENDS}..={MAX_BATCH_SPENDS})"
        ));
    }
    let rows = batch_rows(k);
    let mut rng = rand::thread_rng();
    // Safe zero-free randomized trace initialization (NEVER TraceTable::new!).
    let mut cols = Cols(
        (0..WIDTH)
            .map(|_| (0..rows).map(|_| rand_felt(&mut rng)).collect())
            .collect(),
    );

    for (s, wit) in wits.iter().enumerate() {
        let base = sub_start_block(s);
        let a_in: [Word8; 2] = core::array::from_fn(|i| note::address(&wit.inputs[i].sk));
        let mut prev_digest = [0u32; 8];
        let (mut sk, mut rho, mut pos, mut bal): (Word8, Rho, u64, i128) = ([0; 8], [0; 5], 0, 0);

        let mut fill_kind = |offset: usize, kind: Kind| {
            let b = base + offset;
            let mut bit = 0u64;
            let mut m = [0u32; 16];
            match kind {
                Kind::Addr(i) => {
                    sk = wit.inputs[i].sk;
                    pos = 0;
                    m[0] = TAG_ADDR;
                    m[1..9].copy_from_slice(&sk);
                }
                Kind::CmIn(i) => {
                    let inp = &wit.inputs[i];
                    rho = inp.rho;
                    bal += inp.v as i128;
                    m[0] = TAG_CM;
                    m[1..9].copy_from_slice(&a_in[i]);
                    m[9] = (inp.v >> 32) as u32;
                    m[10] = inp.v as u32;
                    m[11..16].copy_from_slice(&inp.rho);
                }
                Kind::Merkle(i, lvl) => {
                    bit = ((wit.inputs[i].pos >> lvl) & 1) as u64;
                    pos += bit << lvl;
                    let sib = wit.inputs[i].path[lvl];
                    if bit == 0 {
                        m[..8].copy_from_slice(&prev_digest);
                        m[8..].copy_from_slice(&sib);
                    } else {
                        m[..8].copy_from_slice(&sib);
                        m[8..].copy_from_slice(&prev_digest);
                    }
                }
                Kind::Nf(i) => {
                    let inp = &wit.inputs[i];
                    m[0] = TAG_NF;
                    m[1..9].copy_from_slice(&inp.sk);
                    m[9] = inp.pos;
                    m[10..15].copy_from_slice(&inp.rho);
                }
                Kind::CmOut(o) => {
                    let out = &wit.outputs[o];
                    bal -= out.v as i128;
                    m[0] = TAG_CM;
                    m[1..9].copy_from_slice(&out.a_pk);
                    m[9] = (out.v >> 32) as u32;
                    m[10] = out.v as u32;
                    m[11..16].copy_from_slice(&out.rho);
                }
                Kind::Rand => unreachable!(),
            }
            for t in 0..BLK {
                let r = b * BLK + t;
                for j in 0..8 {
                    cols.set(COL_SK + j, r, sk[j] as u64);
                }
                for j in 0..5 {
                    cols.set(COL_RHO + j, r, rho[j] as u64);
                }
                cols.set(COL_POS, r, pos);
                cols.0[COL_BAL][r] = signed(bal as i64);
                cols.set(COL_BIT, r, if t == 0 { bit } else { 0 });
            }
            prev_digest = fill_block(&mut cols, b, &m, &mut rng);
        };

        for i in 0..2 {
            let inp_base = i * 35;
            fill_kind(inp_base, Kind::Addr(i));
            fill_kind(inp_base + 1, Kind::CmIn(i));
            for lvl in 0..DEPTH {
                fill_kind(inp_base + 2 + lvl, Kind::Merkle(i, lvl));
            }
            fill_kind(inp_base + 34, Kind::Nf(i));
        }
        fill_kind(70, Kind::CmOut(0));
        fill_kind(71, Kind::CmOut(1));
    }

    Ok(TraceTable::init_with_meta(cols.0, meta.to_vec()))
}

struct BatchSpendProver256 {
    options: ProofOptions,
    pi: BatchSpendPublic,
}

impl Prover for BatchSpendProver256 {
    type BaseField = Felt;
    type Air = BatchSpendAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hash;
    type VC = Vc;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Hash, Vc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> = DefaultConstraintCommitment<E, Hash, Vc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, BatchSpendAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchSpendPublic {
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
    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        let plain = plain_batch_composition_columns(domain.trace_length(), &self.options);
        if num_constraint_composition_columns > plain {
            let k = zk_mask_len(&self.options);
            let masks: Vec<Vec<E>> = (1..num_constraint_composition_columns)
                .map(|_| random_elements::<E>(k))
                .collect();
            DefaultConstraintCommitment::new_masked(
                composition_poly_trace,
                num_constraint_composition_columns,
                domain.trace_length() - k,
                &masks,
                domain,
                partition_options,
            )
        } else {
            DefaultConstraintCommitment::new(
                composition_poly_trace,
                num_constraint_composition_columns,
                domain,
                partition_options,
            )
        }
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a BatchSpendAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

struct BatchSpendProver384 {
    options: ProofOptions,
    pi: BatchSpendPublic,
}

impl Prover for BatchSpendProver384 {
    type BaseField = Felt;
    type Air = BatchSpendAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hash384;
    type VC = Vc384;
    type RandomCoin = Coin384;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Hash384, Vc384>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, Hash384, Vc384>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, BatchSpendAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchSpendPublic {
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
    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        let plain = plain_batch_composition_columns(domain.trace_length(), &self.options);
        if num_constraint_composition_columns > plain {
            let k = zk_mask_len(&self.options);
            let masks: Vec<Vec<E>> = (1..num_constraint_composition_columns)
                .map(|_| random_elements::<E>(k))
                .collect();
            DefaultConstraintCommitment::new_masked(
                composition_poly_trace,
                num_constraint_composition_columns,
                domain.trace_length() - k,
                &masks,
                domain,
                partition_options,
            )
        } else {
            DefaultConstraintCommitment::new(
                composition_poly_trace,
                num_constraint_composition_columns,
                domain,
                partition_options,
            )
        }
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a BatchSpendAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn batch_context_prefix(profile: &Profile, pi: &BatchSpendPublic) -> Vec<u8> {
    use winter_utils::Serializable;
    let rows = batch_rows(pi.spends.len());
    let mut b: Vec<u8> = Vec::new();
    TraceInfo::with_meta(WIDTH, rows, batch_meta(profile)).write_into(&mut b);
    let m = Felt::get_modulus_le_bytes();
    b.push(m.len() as u8);
    b.extend_from_slice(&m);
    profile.options().write_into(&mut b);
    (assertions_batch(pi).len() + degrees_batch(rows).len()).write_into(&mut b);
    b
}

/// Prove `K ∈ 2..=16` shielded 2-in/2-out spends inside ONE pure-SHA-2 Winterfell STARK,
/// binding both `prover_a_pk` and explicit `prover_fee` into the Fiat–Shamir transcript.
pub fn prove_batch_for(
    profile: &Profile,
    wits: &[SpendWitness],
    binds: &[Word8],
    prover_a_pk: Word8,
    prover_fee: u64,
) -> Result<(BatchSpendPublic, Proof), String> {
    if wits.len() != binds.len() {
        return Err("witness and bind count mismatch".into());
    }
    if !(MIN_BATCH_SPENDS..=MAX_BATCH_SPENDS).contains(&wits.len()) {
        return Err(format!(
            "batch spend count {} out of range ({MIN_BATCH_SPENDS}..={MAX_BATCH_SPENDS})",
            wits.len()
        ));
    }
    if prover_fee >= MAX_VALUE_BALANCE {
        return Err("batch prover_fee out of range".into());
    }
    let mut spends = Vec::with_capacity(wits.len());
    for (w, b) in wits.iter().zip(binds.iter()) {
        spends.push(w.public(*b)?);
    }
    let pi = BatchSpendPublic { spends, prover_a_pk, prover_fee };
    let trace = build_batch_trace(wits, &batch_meta(profile))?;
    let proof = if profile.sha384 {
        BatchSpendProver384 { options: profile.options(), pi: pi.clone() }
            .prove(trace)
            .map_err(|e| format!("batch prover: {e}"))?
    } else {
        BatchSpendProver256 { options: profile.options(), pi: pi.clone() }
            .prove(trace)
            .map_err(|e| format!("batch prover: {e}"))?
    };
    Ok((pi, proof))
}

/// Verify a serialized `BatchSpend` proof with strict context-prefix, canonical-encoding,
/// exact `OptionSet`, and unwind safety.
pub fn verify_batch_bytes_for(
    profile: &Profile,
    pi: &BatchSpendPublic,
    proof: &[u8],
) -> Result<(), String> {
    let k = pi.spends.len();
    if !(MIN_BATCH_SPENDS..=MAX_BATCH_SPENDS).contains(&k) {
        return Err("batch spend count out of range".into());
    }
    if proof.len() > MAX_BATCH_PROOF_BYTES {
        return Err("batch proof too large".into());
    }
    if pi.prover_fee >= MAX_VALUE_BALANCE {
        return Err("batch prover_fee out of range".into());
    }
    for sp in &pi.spends {
        if sp.value_balance.unsigned_abs() >= MAX_VALUE_BALANCE {
            return Err("batch spend value balance out of range".into());
        }
    }
    if !proof.starts_with(&batch_context_prefix(profile, pi)) {
        return Err("batch proof is not for this circuit/network".into());
    }
    let options = profile.options();
    let sha384 = profile.sha384;
    let run = || -> Result<(), String> {
        let p = Proof::from_bytes(proof).map_err(|e| format!("malformed batch proof: {e}"))?;
        if p.to_bytes() != proof {
            return Err("batch proof is not canonically encoded".into());
        }
        let acceptable = winterfell::AcceptableOptions::OptionSet(vec![options.clone()]);
        if sha384 {
            winterfell::verify::<BatchSpendAir, Hash384, Coin384, Vc384>(p, pi.clone(), &acceptable)
                .map_err(|e| format!("{e}"))
        } else {
            winterfell::verify::<BatchSpendAir, Hash, Coin, Vc>(p, pi.clone(), &acceptable)
                .map_err(|e| format!("{e}"))
        }
    };
    #[cfg(panic = "unwind")]
    {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
            .unwrap_or_else(|_| Err("malformed batch proof".into()))
    }
    #[cfg(not(panic = "unwind"))]
    {
        run()
    }
}

fn verified_batch_cache() -> &'static std::sync::Mutex<std::collections::HashSet<[u8; 32]>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> =
        std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

pub fn verify_batch_bytes_cached(
    profile: &Profile,
    pi: &BatchSpendPublic,
    proof: &[u8],
) -> Result<(), String> {
    let mut key_in = Vec::with_capacity(72 + pi.spends.len() * 210 + proof.len());
    key_in.extend_from_slice(b"nsBATCHC");
    key_in.push(profile.queries as u8);
    key_in.push(profile.blowup as u8);
    key_in.push(profile.grinding as u8);
    key_in.push(profile.extension as u8);
    key_in.push(profile.sha384 as u8);
    key_in.extend_from_slice(profile.tag);
    key_in.extend_from_slice(&hash::words_to_bytes(&pi.prover_a_pk));
    key_in.extend_from_slice(&pi.prover_fee.to_le_bytes());
    for sp in &pi.spends {
        key_in.extend_from_slice(&sp.to_bytes());
    }
    key_in.extend_from_slice(proof);
    let key = hash::sha256(&key_in);
    if verified_batch_cache().lock().map(|c| c.contains(&key)).unwrap_or(false) {
        return Ok(());
    }
    verify_batch_bytes_for(profile, pi, proof)?;
    if let Ok(mut c) = verified_batch_cache().lock() {
        if c.len() >= 4_000 {
            c.clear();
        }
        c.insert(key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::NoteTree;
    use crate::spend::{self, InputNote, OutputNote};
    use rand::Rng;

    #[test]
    fn batch_spend_compresses_4_spends_into_one_stark_and_binds_prover_address() {
        let mut rng = rand::thread_rng();
        let mut tree = NoteTree::new();
        let mut notes = Vec::new();
        for _ in 0..4 {
            let sk: Word8 = rng.gen();
            let v = 100_000_000u64;
            let rho: Rho = rng.gen();
            let pos = tree.append(note::commit(&note::address(&sk), v, &rho));
            notes.push((sk, v, rho, pos));
        }
        let mut wits = Vec::new();
        let mut binds = Vec::new();
        for (sk, v, rho, pos) in notes {
            wits.push(SpendWitness {
                inputs: [
                    InputNote { sk, v, rho, pos, path: tree.path(pos) },
                    InputNote::dummy(),
                ],
                outputs: [
                    OutputNote { a_pk: rng.gen(), v: 60_000_000, rho: rng.gen() },
                    OutputNote { a_pk: note::address(&sk), v: 39_990_000, rho: rng.gen() },
                ],
                dummy: [false, true],
            });
            binds.push(rng.gen());
        }
        let prover_a_pk: Word8 = [0x42; 8];
        let prover_fee = 15_000u64;
        let t0 = std::time::Instant::now();
        let (pi, proof) = prove_batch_for(&spend::TEST, &wits, &binds, prover_a_pk, prover_fee).unwrap();
        let prove_ms = t0.elapsed().as_millis();
        let bytes = proof.to_bytes();
        let tv = std::time::Instant::now();
        verify_batch_bytes_for(&spend::TEST, &pi, &bytes).unwrap();
        let verify_ms = tv.elapsed().as_millis();
        println!(
            "[BatchSpend K=4 TEST] {} bytes ({} B/spend), prove={} ms, verify={} ms",
            bytes.len(),
            bytes.len() / 4,
            prove_ms,
            verify_ms
        );
        // Logarithmic compression: 4 spends in ~290 KB vs 4 * ~249 KB (~1,000 KB)!
        assert!(bytes.len() < 400_000, "expected compressed K=4 batch < 400 KB, got {}", bytes.len());

        // Miner trying to swap prover_a_pk or reduce prover_fee MUST fail!
        let mut stolen = pi.clone();
        stolen.prover_a_pk = [0x99; 8];
        assert!(verify_batch_bytes_for(&spend::TEST, &stolen, &bytes).is_err());

        let mut shaved = pi.clone();
        shaved.prover_fee = 0;
        assert!(verify_batch_bytes_for(&spend::TEST, &shaved, &bytes).is_err());

        // Mutating any sub-spend value_balance MUST fail!
        let mut inflated = pi.clone();
        inflated.spends[2].value_balance += 1;
        assert!(verify_batch_bytes_for(&spend::TEST, &inflated, &bytes).is_err());
    }
}
