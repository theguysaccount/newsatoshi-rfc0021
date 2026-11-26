//! The shielded spend: one STARK proves a whole 2-in / 2-out transaction.
//!
//! Statement (public: root, nf[2], cm_out[2], value_balance, dummy[2], bind):
//!   for each input i that is not a dummy, the prover knows sk_i, v_i, rho_i, pos_i and a
//!   depth-32 path such that
//!       a_pk_i = address(sk_i),  cm_i = commit(a_pk_i, v_i, rho_i),
//!       cm_i sits at position pos_i under `root`,  nf_i = nullifier(sk_i, pos_i, rho_i);
//!   each output o has cm_out_o = commit(a_pk_o, v_o, rho_o) for some a_pk_o, rho_o;
//!   every value is below 2^60, a dummy input has value 0, and
//!       v_in_0 + v_in_1 − v_out_0 − v_out_1 = value_balance.
//!   `bind` is absorbed into Fiat–Shamir and binds the proof to the rest of the transaction.
//!
//! Arithmetisation. One SHA-256 round per row, 64 rows per compression, 72 compressions
//! (two inputs × (address, commitment, 32 tree levels, nullifier) + two outputs).
//! Row t of a compression holds a_t, b_t, e_t, f_t as bits, c_t and g_t as words, the
//! round's results a_{t+1} and e_{t+1} as words, and the window W_t..W_{t+15}. Round t+1
//! is checked on the row pair (t, t+1): c_{t+1} = b_t and g_{t+1} = f_t are read as bits
//! from row t, d_{t+1} = c_t and h_{t+1} = g_t as words. Round 0 starts from the IV, so it
//! is checked against constants. The digest is written on row 63 of its own block.
//! Every word that feeds a sum is below 2^35, so nothing wraps the 64-bit field; the
//! only window word never range-checked is W_0, and it is only ever used modulo 2^32.
//!
//! Zero knowledge. Winterfell 0.13 does not randomise proofs, so the circuit randomises
//! itself, and a patched Winterfell masks what the circuit cannot reach:
//!   * every row outside the 72 compressions (3,584 of 8,192) is fresh randomness and no
//!     constraint touches it. A column's polynomial is then uniformly random at any set of
//!     points outside the trace domain no larger than the number of random rows (the
//!     Lagrange matrix restricted to those rows is a scaled Cauchy matrix, so full rank).
//!     A proof exposes each column at 2q + 9 = 137 base-field coordinates (the q queries,
//!     their next-row shifts, and z, zg, zg², each three coordinates of the cubic
//!     extension), far fewer than 3,584;
//!   * three extra columns are uniformly random and unconstrained. They enter the DEEP
//!     composition with independent coefficients and mask what the low-degree test reveals.
//!   * the quotient's segments are opened on their own, and a segment's value at a point is
//!     not a function of the trace there, so the argument above does not reach them. They
//!     are masked as Haböck and Al Kindi set out (ePrint 2024/1037): four segments with
//!     stride n − k instead of three, neighbours sharing random polynomials of k =
//!     `zk_mask_len` coefficients that cancel in the verifier's sum (`vendor/`, marked
//!     `NEWSATOSHI patch`). Proofs made before carry no `ZK_META` and still verify on the
//!     test network, whose history holds them.

use crate::hash::{self, compress, Sha2_256, Sha2_384, Word8, IV, K};
use crate::note::{self, Rho, DEPTH, MAX_NOTE_VALUE, TAG_ADDR, TAG_CM, TAG_NF};
use rand::Rng;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement as Felt, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

pub type Hash = Sha2_256<Felt>;
pub type Coin = DefaultRandomCoin<Hash>;
pub type Vc = MerkleTree<Hash>;

/// Mainnet v2 384-bit SHA-2 STARK commitment stack (192-bit classical / 128-bit QROM collision).
pub type Hash384 = Sha2_384<Felt>;
pub type Coin384 = DefaultRandomCoin<Hash384>;
pub type Vc384 = MerkleTree<Hash384>;

pub const ROWS: usize = 8192;
pub const BLK: usize = 64;
pub const NBLK: usize = ROWS / BLK;

// ---- columns -------------------------------------------------------------------------
pub const COL_A: usize = 0; // bits of a_t
pub const COL_AP: usize = 32; // bits of b_t = a_{t-1}
pub const COL_E: usize = 64; // bits of e_t
pub const COL_EP: usize = 96; // bits of f_t = e_{t-1}
pub const COL_CWORD: usize = 128; // c_t = a_{t-2}
pub const COL_GWORD: usize = 129; // g_t = e_{t-2}
pub const COL_AN: usize = 130; // a_{t+1}
pub const COL_EN: usize = 131; // e_{t+1}
pub const COL_CA: usize = 132; // 3 carry bits of a_{t+1}
pub const COL_CE: usize = 135; // 3 carry bits of e_{t+1}
pub const COL_W: usize = 138; // window W_t..W_{t+15}
pub const COL_X1: usize = 154; // bits of W_{t+1}; on row 63, bits 0..8 are digest carries
pub const COL_X14: usize = 186; // bits of W_{t+14}
pub const COL_CWC: usize = 218; // 2 carry bits of W_{t+16}
pub const COL_DIG: usize = 220; // 8 digest words, on row 63
pub const COL_SK: usize = 228; // 8
pub const COL_RHO: usize = 236; // 5
pub const COL_BIT: usize = 241; // tree path bit, on row 0 of a tree block
pub const COL_POS: usize = 242;
pub const COL_BAL: usize = 243;
pub const COL_RND: usize = 244; // 3 masking columns
pub const WIDTH: usize = 247;

// ---- periodic columns ----------------------------------------------------------------
const P_K: usize = 0; // K_{t+1} on row t, cycle 64
const P_ROUND: usize = 1;
const P_BND: usize = 2;
const P_ADDR: usize = 3;
const P_CMIN: usize = 4;
const P_MERKLE: usize = 5;
const P_NF: usize = 6;
const P_CMOUT: usize = 7;
const P_W: usize = 8;
const P_VCHK: usize = 9;
const P_ACTROW: usize = 10;
const P_ACT: usize = 11;
const P_SKC: usize = 12;
const P_RHOC: usize = 13;
const N_PERIODIC: usize = 14;

pub const N_CONSTRAINTS: usize = 2 + 2 + 64 + 2 + 16 + 2 + 8 + 137 + 15 + 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Rand,
    Addr(usize),
    CmIn(usize),
    Merkle(usize, usize),
    Nf(usize),
    CmOut(usize),
}

impl Kind {
    pub fn active(&self) -> bool {
        !matches!(self, Kind::Rand)
    }
}

/// Block layout: one random block, two inputs (address, commitment, 32 tree levels,
/// nullifier), two outputs, then random blocks to the end of the trace.
pub fn layout() -> Vec<Kind> {
    let mut v = vec![Kind::Rand];
    for i in 0..2 {
        v.push(Kind::Addr(i));
        v.push(Kind::CmIn(i));
        for k in 0..DEPTH {
            v.push(Kind::Merkle(i, k));
        }
        v.push(Kind::Nf(i));
    }
    v.push(Kind::CmOut(0));
    v.push(Kind::CmOut(1));
    while v.len() < NBLK {
        v.push(Kind::Rand);
    }
    v
}

fn block_of(lay: &[Kind], k: Kind) -> usize {
    lay.iter().position(|x| *x == k).expect("kind in layout")
}

/// Rows of pure randomness that hide each column.
pub fn random_rows() -> usize {
    layout().iter().filter(|k| !k.active()).count() * BLK
}

/// The selector values on every row, `[row][selector]`, for tools that evaluate the
/// constraints directly (`crate::audit`).
pub fn periodic_table() -> Vec<Vec<Felt>> {
    let per = periodic_columns();
    (0..ROWS).map(|r| per.iter().map(|p| p[r % p.len()]).collect()).collect()
}

/// The boundary assertions as cells: (column, row, value).
pub fn assertion_cells(pi: &SpendPublic) -> Vec<(usize, usize, Felt)> {
    let mut out = vec![];
    for a in assertions(pi) {
        a.apply(ROWS, |row, value| out.push((a.column(), row, value)));
    }
    out
}

fn periodic_columns() -> Vec<Vec<Felt>> {
    let lay = layout();
    let last = block_of(&lay, Kind::CmOut(1));
    let mut cols = vec![vec![Felt::ZERO; ROWS]; N_PERIODIC];
    cols[P_K] = (0..BLK).map(|t| Felt::new(K[(t + 1) % BLK] as u64)).collect();
    for b in 0..NBLK {
        let kind = lay[b];
        let next = if b + 1 < NBLK { lay[b + 1] } else { Kind::Rand };
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
                    Kind::Merkle(_, k) => {
                        cols[P_MERKLE][r] = Felt::ONE;
                        cols[P_W][r] = Felt::new(1u64 << k);
                    }
                    Kind::Nf(_) => cols[P_NF][r] = Felt::ONE,
                    Kind::CmOut(_) => cols[P_CMOUT][r] = Felt::ONE,
                    Kind::Rand => {}
                }
            }
            // register transitions that stay inside the active region
            if r >= BLK && r + 1 < (last + 1) * BLK {
                cols[P_ACT][r] = Felt::ONE;
            }
        }
    }
    for r in 0..ROWS {
        cols[P_SKC][r] = cols[P_ACT][r] * (Felt::ONE - cols[P_ADDR][r]);
        cols[P_RHOC][r] = cols[P_ACT][r] * (Felt::ONE - cols[P_CMIN][r]);
    }
    cols
}

// ---- public inputs -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPublic {
    pub root: Word8,
    pub nf: [Word8; 2],
    pub cm_out: [Word8; 2],
    pub value_balance: i64,
    pub dummy: [bool; 2],
    pub bind: Word8,
}

fn signed(v: i64) -> Felt {
    if v >= 0 {
        Felt::new(v as u64)
    } else {
        Felt::ZERO - Felt::new(v.unsigned_abs())
    }
}

impl ToElements<Felt> for SpendPublic {
    fn to_elements(&self) -> Vec<Felt> {
        let mut v = Vec::with_capacity(8 * 6 + 3);
        let w = |x: &Word8, v: &mut Vec<Felt>| v.extend(x.iter().map(|y| Felt::new(*y as u64)));
        w(&self.root, &mut v);
        w(&self.nf[0], &mut v);
        w(&self.nf[1], &mut v);
        w(&self.cm_out[0], &mut v);
        w(&self.cm_out[1], &mut v);
        v.push(signed(self.value_balance));
        v.push(Felt::new(self.dummy[0] as u64));
        v.push(Felt::new(self.dummy[1] as u64));
        w(&self.bind, &mut v);
        v
    }
}

impl SpendPublic {
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 32 * 6 + 10 {
            return Err("public inputs have the wrong length".into());
        }
        let w = |i: usize| hash::bytes_to_words(&b[32 * i..32 * i + 32].try_into().unwrap());
        let d = |x: u8| match x {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("bad flag".to_string()),
        };
        Ok(SpendPublic {
            root: w(0),
            nf: [w(1), w(2)],
            cm_out: [w(3), w(4)],
            bind: w(5),
            value_balance: i64::from_le_bytes(b[192..200].try_into().unwrap()),
            dummy: [d(b[200])?, d(b[201])?],
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 6 + 10);
        for w in [&self.root, &self.nf[0], &self.nf[1], &self.cm_out[0], &self.cm_out[1], &self.bind] {
            out.extend_from_slice(&hash::words_to_bytes(w));
        }
        out.extend_from_slice(&self.value_balance.to_le_bytes());
        out.push(self.dummy[0] as u8);
        out.push(self.dummy[1] as u8);
        out
    }
}

// ---- constraint helpers --------------------------------------------------------------

#[inline]
fn xor2<E: FieldElement>(x: E, y: E) -> E {
    x + y - (x * y).double()
}
#[inline]
fn xor3<E: FieldElement>(x: E, y: E, z: E) -> E {
    let xy = x * y;
    x + y + z - (xy + x * z + y * z).double() + (xy * z).double().double()
}
#[inline]
fn word<E: FieldElement>(bits: &[E], p2: &[E; 32]) -> E {
    let mut s = E::ZERO;
    for i in 0..32 {
        s += bits[i] * p2[i];
    }
    s
}
fn bsig0<E: FieldElement>(a: &[E], p2: &[E; 32]) -> E {
    (0..32).fold(E::ZERO, |s, i| s + p2[i] * xor3(a[(i + 2) % 32], a[(i + 13) % 32], a[(i + 22) % 32]))
}
fn bsig1<E: FieldElement>(e: &[E], p2: &[E; 32]) -> E {
    (0..32).fold(E::ZERO, |s, i| s + p2[i] * xor3(e[(i + 6) % 32], e[(i + 11) % 32], e[(i + 25) % 32]))
}
fn ssig0<E: FieldElement>(x: &[E], p2: &[E; 32]) -> E {
    (0..32).fold(E::ZERO, |s, i| {
        let v = if i + 3 < 32 {
            xor3(x[(i + 7) % 32], x[(i + 18) % 32], x[i + 3])
        } else {
            xor2(x[(i + 7) % 32], x[(i + 18) % 32])
        };
        s + p2[i] * v
    })
}
fn ssig1<E: FieldElement>(x: &[E], p2: &[E; 32]) -> E {
    (0..32).fold(E::ZERO, |s, i| {
        let v = if i + 10 < 32 {
            xor3(x[(i + 17) % 32], x[(i + 19) % 32], x[i + 10])
        } else {
            xor2(x[(i + 17) % 32], x[(i + 19) % 32])
        };
        s + p2[i] * v
    })
}
fn chf<E: FieldElement>(e: &[E], f: &[E], g: &[E], p2: &[E; 32]) -> E {
    (0..32).fold(E::ZERO, |s, i| s + p2[i] * (g[i] + e[i] * (f[i] - g[i])))
}
fn majf<E: FieldElement>(a: &[E], b: &[E], c: &[E], p2: &[E; 32]) -> E {
    (0..32).fold(E::ZERO, |s, i| {
        let ab = a[i] * b[i];
        s + p2[i] * (ab + a[i] * c[i] + b[i] * c[i] - (ab * c[i]).double())
    })
}

fn felt<E: FieldElement + From<Felt>>(x: u64) -> E {
    E::from(Felt::new(x))
}

/// Round 0 starts from the IV, so everything but W_0 is a constant.
fn round0_consts() -> (u64, u64) {
    let [a, b, c, d, e, f, g, h] = IV;
    let t1 = h as u64 + hash::big_s1(e) as u64 + hash::ch(e, f, g) as u64 + K[0] as u64;
    let s_a = t1 + hash::big_s0(a) as u64 + hash::maj(a, b, c) as u64;
    (s_a, d as u64 + t1)
}

/// Evaluate every transition constraint on one row pair. Shared by the AIR and by
/// `check_trace`, so the constraints that are tested are the constraints that are proved.
pub fn eval_constraints<E: FieldElement + From<Felt>>(cur: &[E], nxt: &[E], pv: &[E], res: &mut [E]) {
    let p2: [E; 32] = core::array::from_fn(|i| felt::<E>(1u64 << i));
    let two32: E = felt(1u64 << 32);
    let four: E = felt(4);
    let (pk, p_round, p_bnd) = (pv[P_K], pv[P_ROUND], pv[P_BND]);
    let (p_addr, p_cmin, p_merkle, p_nf, p_cmout) =
        (pv[P_ADDR], pv[P_CMIN], pv[P_MERKLE], pv[P_NF], pv[P_CMOUT]);
    let (p_w, p_vchk, p_actrow, p_act, p_skc, p_rhoc) =
        (pv[P_W], pv[P_VCHK], pv[P_ACTROW], pv[P_ACT], pv[P_SKC], pv[P_RHOC]);
    let p_iv = p_addr + p_cmin + p_merkle + p_nf + p_cmout;
    let iv = |i: usize| felt::<E>(IV[i] as u64);
    let ivbit = |i: usize, j: usize| felt::<E>(((IV[i] >> j) & 1) as u64);
    let (k0a, k0e) = round0_consts();

    // state of round t+1 on the pair (t, t+1)
    let na = &nxt[COL_A..COL_A + 32];
    let nap = &nxt[COL_AP..COL_AP + 32];
    let cap = &cur[COL_AP..COL_AP + 32];
    let ne = &nxt[COL_E..COL_E + 32];
    let nep = &nxt[COL_EP..COL_EP + 32];
    let cep = &cur[COL_EP..COL_EP + 32];
    let w = &cur[COL_W..COL_W + 16];
    let nw = &nxt[COL_W..COL_W + 16];
    let x1 = &cur[COL_X1..COL_X1 + 32];
    let x14 = &cur[COL_X14..COL_X14 + 32];
    let carry3 = |row: &[E], col: usize| row[col] + row[col + 1].double() + four * row[col + 2];

    let t1 = cur[COL_GWORD] + bsig1(ne, &p2) + chf(ne, nep, cep, &p2) + pk + nw[0];
    let s_a = t1 + bsig0(na, &p2) + majf(na, nap, cap, &p2);
    let s_e = cur[COL_CWORD] + t1;
    let an = nxt[COL_AN] + two32 * carry3(nxt, COL_CA);
    let en = nxt[COL_EN] + two32 * carry3(nxt, COL_CE);

    let mut k = 0;
    let mut put = |res: &mut [E], v: E| {
        res[k] = v;
        k += 1;
    };
    // round results (round 0 against the IV constants)
    put(res, p_round * (an - s_a) + p_iv * (an - felt::<E>(k0a) - nw[0]));
    put(res, p_round * (en - s_e) + p_iv * (en - felt::<E>(k0e) - nw[0]));
    // the next row's a and e are the bits of this row's results (or the IV)
    put(res, p_round * (word(na, &p2) - cur[COL_AN]) + p_iv * (word(na, &p2) - iv(0)));
    put(res, p_round * (word(ne, &p2) - cur[COL_EN]) + p_iv * (word(ne, &p2) - iv(4)));
    // b <- a, f <- e
    for j in 0..32 {
        put(res, p_round * (nap[j] - cur[COL_A + j]) + p_iv * (nap[j] - ivbit(1, j)));
    }
    for j in 0..32 {
        put(res, p_round * (nep[j] - cur[COL_E + j]) + p_iv * (nep[j] - ivbit(5, j)));
    }
    // c <- b, g <- f
    put(res, p_round * (nxt[COL_CWORD] - word(cap, &p2)) + p_iv * (nxt[COL_CWORD] - iv(2)));
    put(res, p_round * (nxt[COL_GWORD] - word(cep, &p2)) + p_iv * (nxt[COL_GWORD] - iv(6)));

    // message window: shift and extend inside a block, load at a block start
    let (nsk, nrho, nbit, npos) =
        (&nxt[COL_SK..COL_SK + 8], &nxt[COL_RHO..COL_RHO + 5], nxt[COL_BIT], nxt[COL_POS]);
    let dig = &cur[COL_DIG..COL_DIG + 8];
    let tag = |t: u32| felt::<E>(t as u64);
    for j in 0..16 {
        let mut r = if j < 15 {
            p_round * (nw[j] - w[j + 1])
        } else {
            let cw = cur[COL_CWC] + cur[COL_CWC + 1].double();
            p_round * (nw[15] + two32 * cw - (ssig1(x14, &p2) + w[9] + ssig0(x1, &p2) + w[0]))
        };
        // address block: [TAG, sk, 0 ...]
        let t_addr = match j {
            0 => tag(TAG_ADDR),
            1..=8 => nsk[j - 1],
            _ => E::ZERO,
        };
        r += p_addr * (nw[j] - t_addr);
        // input commitment: [TAG, a_pk = previous digest, v_hi, v_lo, rho]
        match j {
            0 => r += p_cmin * (nw[0] - tag(TAG_CM)),
            1..=8 => r += p_cmin * (nw[j] - dig[j - 1]),
            9 | 10 => {}
            _ => r += p_cmin * (nw[j] - nrho[j - 11]),
        }
        // tree level: the running node sits left when the bit is 0, right when it is 1;
        // the other half is the sibling, a free witness
        if j < 8 {
            r += p_merkle * (E::ONE - nbit) * (nw[j] - dig[j]);
        } else {
            r += p_merkle * nbit * (nw[j] - dig[j - 8]);
        }
        // nullifier: [TAG, sk, pos, rho, 0]
        let t_nf = match j {
            0 => tag(TAG_NF),
            1..=8 => nsk[j - 1],
            9 => npos,
            10..=14 => nrho[j - 10],
            _ => E::ZERO,
        };
        r += p_nf * (nw[j] - t_nf);
        // output commitment: only the tag is fixed
        if j == 0 {
            r += p_cmout * (nw[0] - tag(TAG_CM));
        }
        put(res, r);
    }
    // the schedule reads W_{t+1} and W_{t+14} bitwise (rows 0..62)
    put(res, p_round * (w[1] - word(x1, &p2)));
    put(res, p_round * (w[14] - word(x14, &p2)));
    // digest on row 63: IV + state after round 63, carries in X1[0..8]
    let out = [
        cur[COL_AN],
        word(&cur[COL_A..COL_A + 32], &p2),
        word(cap, &p2),
        cur[COL_CWORD],
        cur[COL_EN],
        word(&cur[COL_E..COL_E + 32], &p2),
        word(cep, &p2),
        cur[COL_GWORD],
    ];
    for j in 0..8 {
        put(res, p_bnd * (cur[COL_DIG + j] + two32 * x1[j] - iv(j) - out[j]));
    }
    // booleanity
    let boolean = |x: E| x * (x - E::ONE);
    for base in [COL_A, COL_E, COL_X1, COL_X14] {
        for j in 0..32 {
            put(res, p_actrow * boolean(cur[base + j]));
        }
    }
    for col in (COL_CA..COL_CA + 6).chain([COL_CWC, COL_CWC + 1, COL_BIT]) {
        put(res, p_actrow * boolean(cur[col]));
    }
    // registers carried across blocks
    for j in 0..8 {
        put(res, p_skc * (nxt[COL_SK + j] - cur[COL_SK + j]));
    }
    for j in 0..5 {
        put(res, p_rhoc * (nxt[COL_RHO + j] - cur[COL_RHO + j]));
    }
    put(res, p_act * npos - p_skc * cur[COL_POS] - p_w * nbit);
    let nv = two32 * nw[9] + nw[10];
    put(res, p_act * (nxt[COL_BAL] - cur[COL_BAL]) - p_cmin * nv + p_cmout * nv);
    // a note's high value word is below 2^28
    put(res, p_vchk * (x1[28] + x1[29] + x1[30] + x1[31]));
    debug_assert_eq!(k, N_CONSTRAINTS);
}

fn degrees() -> Vec<TransitionConstraintDegree> {
    let d = |base: usize| TransitionConstraintDegree::with_cycles(base, vec![ROWS]);
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
    assert_eq!(v.len(), N_CONSTRAINTS);
    v
}

fn assertions(pi: &SpendPublic) -> Vec<Assertion<Felt>> {
    let lay = layout();
    let last_row = |k: Kind| block_of(&lay, k) * BLK + BLK - 1;
    let first_row = |k: Kind| block_of(&lay, k) * BLK;
    let mut a = vec![Assertion::single(COL_BAL, BLK, Felt::ZERO), Assertion::single(COL_POS, BLK, Felt::ZERO)];
    for i in 0..2 {
        if pi.dummy[i] {
            a.push(Assertion::single(COL_W + 9, first_row(Kind::CmIn(i)), Felt::ZERO));
            a.push(Assertion::single(COL_W + 10, first_row(Kind::CmIn(i)), Felt::ZERO));
        } else {
            for j in 0..8 {
                a.push(Assertion::single(COL_DIG + j, last_row(Kind::Merkle(i, DEPTH - 1)), Felt::new(pi.root[j] as u64)));
            }
        }
        for j in 0..8 {
            a.push(Assertion::single(COL_DIG + j, last_row(Kind::Nf(i)), Felt::new(pi.nf[i][j] as u64)));
        }
    }
    for o in 0..2 {
        for j in 0..8 {
            a.push(Assertion::single(COL_DIG + j, last_row(Kind::CmOut(o)), Felt::new(pi.cm_out[o][j] as u64)));
        }
    }
    a.push(Assertion::single(COL_BAL, last_row(Kind::CmOut(1)), signed(pi.value_balance)));
    a
}

// ---- AIR -----------------------------------------------------------------------------

pub struct SpendAir {
    ctx: AirContext<Felt>,
    pi: SpendPublic,
}

impl Air for SpendAir {
    type BaseField = Felt;
    type PublicInputs = SpendPublic;

    fn new(trace_info: TraceInfo, pi: SpendPublic, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), WIDTH);
        assert_eq!(trace_info.length(), ROWS);
        let n_assert = assertions(&pi).len();
        let zk = trace_info.meta().starts_with(ZK_META);
        let mask = zk_mask_len(&options);
        let ctx = AirContext::new(trace_info, degrees(), n_assert, options);
        Self { ctx: if zk { ctx.with_zk_segments(mask) } else { ctx }, pi }
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
        assertions(&self.pi)
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        periodic_columns()
    }
}

// ---- witness and trace -----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct InputNote {
    pub sk: Word8,
    pub v: u64,
    pub rho: Rho,
    pub pos: u32,
    pub path: [Word8; DEPTH],
}

#[derive(Clone, Debug)]
pub struct OutputNote {
    pub a_pk: Word8,
    pub v: u64,
    pub rho: Rho,
}

#[derive(Clone, Debug)]
pub struct SpendWitness {
    pub inputs: [InputNote; 2],
    pub outputs: [OutputNote; 2],
    pub dummy: [bool; 2],
}

impl InputNote {
    /// A zero-value input with fresh random secrets; its path is never checked.
    pub fn dummy() -> Self {
        let mut rng = rand::thread_rng();
        InputNote { sk: rng.gen(), v: 0, rho: rng.gen(), pos: 0, path: [[0u32; 8]; DEPTH] }
    }
    pub fn cm(&self) -> Word8 {
        note::commit(&note::address(&self.sk), self.v, &self.rho)
    }
    pub fn nf(&self) -> Word8 {
        note::nullifier(&self.sk, self.pos, &self.rho)
    }
    pub fn root(&self) -> Word8 {
        note::root_from_path(&self.cm(), self.pos, &self.path)
    }
}

impl OutputNote {
    pub fn cm(&self) -> Word8 {
        note::commit(&self.a_pk, self.v, &self.rho)
    }
}

impl SpendWitness {
    pub fn public(&self, bind: Word8) -> Result<SpendPublic, String> {
        if self.inputs.iter().any(|i| i.v > MAX_NOTE_VALUE) || self.outputs.iter().any(|o| o.v > MAX_NOTE_VALUE) {
            return Err("value out of range".into());
        }
        for i in 0..2 {
            if self.dummy[i] && self.inputs[i].v != 0 {
                return Err("dummy input must have value 0".into());
            }
        }
        let real: Vec<usize> = (0..2).filter(|i| !self.dummy[*i]).collect();
        let root = real.first().map(|i| self.inputs[*i].root()).unwrap_or([0u32; 8]);
        if real.iter().any(|i| self.inputs[*i].root() != root) {
            return Err("inputs prove membership under different roots".into());
        }
        let vin: i128 = self.inputs.iter().map(|i| i.v as i128).sum();
        let vout: i128 = self.outputs.iter().map(|o| o.v as i128).sum();
        Ok(SpendPublic {
            root,
            nf: [self.inputs[0].nf(), self.inputs[1].nf()],
            cm_out: [self.outputs[0].cm(), self.outputs[1].cm()],
            value_balance: (vin - vout) as i64,
            dummy: self.dummy,
            bind,
        })
    }
}

fn rand_felt<R: Rng>(rng: &mut R) -> Felt {
    Felt::new(rng.gen_range(0..Felt::MODULUS))
}

struct Cols(Vec<Vec<Felt>>);
impl Cols {
    fn set(&mut self, col: usize, row: usize, v: u64) {
        self.0[col][row] = Felt::new(v);
    }
    fn bits(&mut self, col: usize, row: usize, x: u32) {
        for j in 0..32 {
            self.0[col + j][row] = Felt::new(((x >> j) & 1) as u64);
        }
    }
}

/// Fill one compression's 64 rows and return its digest.
fn fill_block<R: Rng>(cols: &mut Cols, b: usize, m: &[u32; 16], rng: &mut R) -> Word8 {
    let w = hash::schedule(m);
    let [mut a, mut bb, mut c, mut d, mut e, mut f, mut g, mut h] = IV;
    let mut digest = [0u32; 8];
    for t in 0..BLK {
        let r = b * BLK + t;
        cols.bits(COL_A, r, a);
        cols.bits(COL_AP, r, bb);
        cols.bits(COL_E, r, e);
        cols.bits(COL_EP, r, f);
        cols.set(COL_CWORD, r, c as u64);
        cols.set(COL_GWORD, r, g as u64);
        for j in 0..16 {
            cols.set(COL_W + j, r, w[t + j] as u64);
        }
        let t1 = h as u64 + hash::big_s1(e) as u64 + hash::ch(e, f, g) as u64 + K[t] as u64 + w[t] as u64;
        let s_a = t1 + hash::big_s0(a) as u64 + hash::maj(a, bb, c) as u64;
        let s_e = d as u64 + t1;
        cols.set(COL_AN, r, s_a & 0xffff_ffff);
        cols.set(COL_EN, r, s_e & 0xffff_ffff);
        for j in 0..3 {
            cols.set(COL_CA + j, r, (s_a >> (32 + j)) & 1);
            cols.set(COL_CE + j, r, (s_e >> (32 + j)) & 1);
        }
        if t < BLK - 1 {
            cols.bits(COL_X1, r, w[t + 1]);
            cols.bits(COL_X14, r, w[t + 14]);
            let sw = hash::small_s1(w[t + 14]) as u64 + w[t + 9] as u64 + hash::small_s0(w[t + 1]) as u64 + w[t] as u64;
            debug_assert_eq!(sw as u32, w[t + 16]);
            cols.set(COL_CWC, r, (sw >> 32) & 1);
            cols.set(COL_CWC + 1, r, (sw >> 33) & 1);
        } else {
            let outs = [s_a & 0xffff_ffff, a as u64, bb as u64, c as u64, s_e & 0xffff_ffff, e as u64, f as u64, g as u64];
            for j in 0..8 {
                let full = IV[j] as u64 + outs[j];
                digest[j] = full as u32;
                cols.set(COL_DIG + j, r, full & 0xffff_ffff);
                cols.set(COL_X1 + j, r, full >> 32);
            }
            for j in 8..32 {
                cols.set(COL_X1 + j, r, rng.gen_range(0..2));
            }
            for j in 0..32 {
                cols.set(COL_X14 + j, r, rng.gen_range(0..2));
            }
            for j in 0..2 {
                cols.set(COL_CWC + j, r, rng.gen_range(0..2));
            }
        }
        h = g;
        g = f;
        f = e;
        e = s_e as u32;
        d = c;
        c = bb;
        bb = a;
        a = s_a as u32;
    }
    debug_assert_eq!(digest, compress(m));
    digest
}

/// Marks a proof whose constraint composition segments are masked for zero knowledge
/// (Haböck and Al Kindi, ePrint 2024/1037): the first bytes of the trace's metadata, which
/// every proof states in its first bytes and binds into its transcript. Every proof made
/// now carries it, followed by its network's name (`Profile::tag`; nothing on the test
/// network). The test network also accepts proofs without it, which its history holds;
/// the main network accepts only proofs with it.
pub const ZK_META: &[u8] = b"zk";

/// Coefficients in each mask of a segment. A segment is opened at the two out-of-domain
/// points and at each queried position, and its commitment shows the hash of the row beside
/// each queried one. Masks larger than all of these together leave every value a proof
/// reveals or hashes of a segment uniformly random, apart from the one relation the verifier
/// checks, so the commitment needs no salt.
pub fn zk_mask_len(options: &ProofOptions) -> usize {
    2 * options.num_queries() + 3
}

/// Build the execution trace for a witness. Every row outside the compressions is random.
pub fn build_trace(wit: &SpendWitness) -> TraceTable<Felt> {
    build_trace_with(wit, ZK_META)
}

/// How a network makes and checks payment proofs (white paper §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Queries per proof.
    pub queries: usize,
    /// The network's name inside its proofs: bytes that follow `ZK_META` in the trace's
    /// metadata, which every proof states in its first bytes and binds into its
    /// transcript. A proof made for one network is then no proof on any other, whatever
    /// else the two have in common.
    pub tag: &'static [u8],
    /// Also take proofs without masked segments (the test network's early history).
    pub unmasked: bool,
    /// Largest proof taken.
    pub max_proof_bytes: usize,
    /// Use 384-bit SHA-384 FRI/Merkle commitments (192-bit classical / 128-bit QROM soundness).
    pub sha384: bool,
}

/// The test network's proofs (and regtest's): 64 queries, about 249 KB.
pub const TEST: Profile = Profile { queries: 64, tag: b"", unmasked: true, max_proof_bytes: MAX_PROOF_BYTES, sha384: false };

/// The main network's proofs: `MAIN_QUERIES` queries, about 460 KB, masked only.
pub const MAIN: Profile = Profile { queries: MAIN_QUERIES, tag: b"/main", unmasked: false, max_proof_bytes: MAIN_MAX_PROOF_BYTES, sha384: false };

/// The rehearsal network's proofs: the main network's in everything but the name.
pub const DRY: Profile = Profile { queries: MAIN_QUERIES, tag: b"/dry", unmasked: false, max_proof_bytes: MAIN_MAX_PROOF_BYTES, sha384: false };

impl Profile {
    /// Blowup 16, 16 bits of grinding, the cubic extension, FRI folding by 8 (`options`),
    /// with this network's number of queries.
    pub fn options(&self) -> ProofOptions {
        ProofOptions::new(self.queries, 16, 16, FieldExtension::Cubic, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
    }

    /// The trace metadata of this network's proofs.
    pub fn meta(&self) -> Vec<u8> {
        [ZK_META, self.tag].concat()
    }
}

/// The trace of a proof without masked segments, as the test network made them before.
pub fn build_trace_legacy(wit: &SpendWitness) -> TraceTable<Felt> {
    build_trace_with(wit, &[])
}

fn build_trace_with(wit: &SpendWitness, meta: &[u8]) -> TraceTable<Felt> {
    let mut rng = rand::thread_rng();
    let lay = layout();
    let mut cols = Cols((0..WIDTH).map(|_| (0..ROWS).map(|_| rand_felt(&mut rng)).collect()).collect());

    let a_in: [Word8; 2] = core::array::from_fn(|i| note::address(&wit.inputs[i].sk));
    let mut prev_digest = [0u32; 8];
    let (mut sk, mut rho, mut pos, mut bal): (Word8, Rho, u64, i128) = ([0; 8], [0; 5], 0, 0);

    for (b, kind) in lay.iter().enumerate() {
        if !kind.active() {
            continue;
        }
        let mut bit = 0u64;
        let mut m = [0u32; 16];
        match *kind {
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
            Kind::Merkle(i, k) => {
                bit = ((wit.inputs[i].pos >> k) & 1) as u64;
                pos += bit << k;
                let s = wit.inputs[i].path[k];
                if bit == 0 {
                    m[..8].copy_from_slice(&prev_digest);
                    m[8..].copy_from_slice(&s);
                } else {
                    m[..8].copy_from_slice(&s);
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
    }
    TraceTable::init_with_meta(cols.0, meta.to_vec())
}

/// Check every transition constraint and assertion directly on a trace.
pub fn check_trace(trace: &TraceTable<Felt>, pi: &SpendPublic) -> Result<(), String> {
    let per = periodic_columns();
    let mut res = vec![Felt::ZERO; N_CONSTRAINTS];
    let mut cur = vec![Felt::ZERO; WIDTH];
    let mut nxt = vec![Felt::ZERO; WIDTH];
    for r in 0..ROWS - 1 {
        for c in 0..WIDTH {
            cur[c] = trace.get(c, r);
            nxt[c] = trace.get(c, r + 1);
        }
        let pv: Vec<Felt> = per.iter().map(|p| p[r % p.len()]).collect();
        eval_constraints(&cur, &nxt, &pv, &mut res);
        if let Some(i) = res.iter().position(|x| *x != Felt::ZERO) {
            return Err(format!("constraint {i} fails at row {r} (block {}, round {})", r / BLK, r % BLK));
        }
    }
    for a in assertions(pi) {
        let mut bad = None;
        a.apply(ROWS, |row, value| {
            if trace.get(a.column(), row) != value {
                bad = Some(row);
            }
        });
        if let Some(row) = bad {
            return Err(format!("assertion on column {} fails at row {row}", a.column()));
        }
    }
    Ok(())
}

// ---- prover and verifier ---------------------------------------------------------------

pub struct SpendProver {
    options: ProofOptions,
    pi: SpendPublic,
}

/// `k` field elements drawn uniformly at random.
fn random_elements<E: FieldElement>(k: usize) -> Vec<E> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; E::ELEMENT_BYTES];
    let mut out = Vec::with_capacity(k);
    while out.len() < k {
        rng.fill_bytes(&mut buf);
        if let Some(e) = E::from_random_bytes(&buf) {
            out.push(e);
        }
    }
    out
}

impl Prover for SpendProver {
    type BaseField = Felt;
    type Air = SpendAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hash;
    type VC = Vc;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Hash, Vc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> = DefaultConstraintCommitment<E, Hash, Vc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> = DefaultConstraintEvaluator<'a, SpendAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SpendPublic {
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
        // the AIR asks for one segment more than the composition polynomial needs exactly when
        // the trace is marked for zero knowledge; the segments are then masked
        if num_constraint_composition_columns > plain_composition_columns() {
            let k = zk_mask_len(&self.options);
            let masks: Vec<Vec<E>> = (1..num_constraint_composition_columns).map(|_| random_elements::<E>(k)).collect();
            DefaultConstraintCommitment::new_masked(composition_poly_trace, num_constraint_composition_columns, domain.trace_length() - k, &masks, domain, partition_options)
        } else {
            DefaultConstraintCommitment::new(composition_poly_trace, num_constraint_composition_columns, domain, partition_options)
        }
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a SpendAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Proof parameters: blowup 16, 64 queries, 16 bits of grinding, the cubic extension of the
/// 64-bit Goldilocks field, FRI folding by 8. Winterfell's estimator gives 135 bits of
/// *proven* soundness in the list-decoding regime (Johnson bound), reported as 128 because
/// no claim may exceed SHA-256's 128-bit collision resistance; 128 conjectured. Cheaper
/// settings reach 128 only conjecturally (36 queries at blowup 8 prove 69 bits with this
/// grinding), and a final currency should not rest on a conjecture where a theorem is
/// affordable. Against a quantum attacker the proof that applies (Chiesa, Manohar and
/// Spooner, TCC 2019) loses a square: these parameters prove about 67 bits there.
pub fn options() -> ProofOptions {
    ProofOptions::new(64, 16, 16, FieldExtension::Cubic, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
}

pub const PROVEN_BITS: u32 = 128;

/// Largest proof the test network accepts. Proofs at its parameters are about 249 KB.
pub const MAX_PROOF_BYTES: usize = 300_000;

/// Largest proof any network accepts: what a decoder will read. Each network's own limit
/// (`Profile::max_proof_bytes`) is enforced when a payment is checked.
pub const PROOF_BYTES_CAP: usize = MAIN_V2_MAX_PROOF_BYTES;

/// |value_balance| must stay below this. Inputs are below 2^61 in total, so nothing larger
/// can balance, and the bound keeps the signed encoding into the field one-to-one.
pub const MAX_VALUE_BALANCE: u64 = 1 << 62;

pub fn prove(wit: &SpendWitness, bind: Word8) -> Result<(SpendPublic, Proof), String> {
    let pi = wit.public(bind)?;
    let trace = build_trace(wit);
    let prover = SpendProver { options: options(), pi: pi.clone() };
    let proof = prover.prove(trace).map_err(|e| format!("prover: {e}"))?;
    Ok((pi, proof))
}

pub fn verify(pi: &SpendPublic, proof: &Proof) -> Result<(), String> {
    if pi.value_balance.unsigned_abs() >= MAX_VALUE_BALANCE {
        return Err("value balance out of range".into());
    }
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![options()]);
    winterfell::verify::<SpendAir, Hash, Coin, Vc>(proof.clone(), pi.clone(), &acceptable).map_err(|e| format!("{e}"))
}

/// Composition segments the circuit needs without masking.
fn plain_composition_columns() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| AirContext::<Felt>::new(TraceInfo::new(WIDTH, ROWS), degrees(), 1, options()).num_constraint_composition_columns())
}

/// The exact bytes every proof of this circuit begins with: trace shape and metadata, field
/// modulus, proof options and constraint count, in Winterfell's own encoding. Winterfell's
/// decoders and `SpendAir::new` assert (panic) on some malformed contexts, so a proof whose
/// prefix differs is refused before anything parses it. This is the prefix of the proofs
/// made now, with masked segments; `context_prefix_legacy` is the earlier kind's.
pub fn context_prefix(pi: &SpendPublic) -> Vec<u8> {
    prefix_with(pi, ZK_META)
}

pub fn context_prefix_legacy(pi: &SpendPublic) -> Vec<u8> {
    prefix_with(pi, &[])
}

/// `context_prefix` for a network: its name in the metadata, its number of queries.
pub fn context_prefix_for(profile: &Profile, pi: &SpendPublic) -> Vec<u8> {
    prefix_of(pi, &profile.meta(), &profile.options())
}

fn prefix_with(pi: &SpendPublic, meta: &[u8]) -> Vec<u8> {
    prefix_of(pi, meta, &options())
}

fn prefix_of(pi: &SpendPublic, meta: &[u8], options: &ProofOptions) -> Vec<u8> {
    use winter_utils::Serializable;
    let mut b: Vec<u8> = Vec::new();
    TraceInfo::with_meta(WIDTH, ROWS, meta.to_vec()).write_into(&mut b);
    let m = Felt::get_modulus_le_bytes();
    b.push(m.len() as u8);
    b.extend_from_slice(&m);
    options.write_into(&mut b);
    (assertions(pi).len() + degrees().len()).write_into(&mut b);
    b
}

/// Make a payment proof for a network (automatically dispatches 384-bit SHA-384 FRI for `MAIN_V2`).
pub fn prove_for(profile: &Profile, wit: &SpendWitness, bind: Word8) -> Result<(SpendPublic, Proof), String> {
    let pi = wit.public(bind)?;
    let trace = build_trace_with(wit, &profile.meta());
    let proof = if profile.sha384 {
        SpendProver384 { options: profile.options(), pi: pi.clone() }
            .prove(trace)
            .map_err(|e| format!("prover: {e}"))?
    } else {
        SpendProver { options: profile.options(), pi: pi.clone() }
            .prove(trace)
            .map_err(|e| format!("prover: {e}"))?
    };
    Ok((pi, proof))
}

/// Verify a serialised proof on the test network (`verify_bytes_for` with `TEST`).
pub fn verify_bytes(pi: &SpendPublic, proof: &[u8]) -> Result<(), String> {
    verify_bytes_for(&TEST, pi, proof)
}

/// Verify a serialised proof for a network. Refuses, before parsing, anything over the
/// network's limit or not starting with the exact bytes its proofs start with (the
/// network's name and parameters among them); refuses any encoding but the canonical one,
/// so a valid proof cannot be padded or re-encoded into a second valid transaction.
/// Automatically dispatches 384-bit SHA-384 FRI verification when `profile.sha384` is true.
/// Natively a panic anywhere inside the library becomes an error rather than a dead node.
pub fn verify_bytes_for(profile: &Profile, pi: &SpendPublic, proof: &[u8]) -> Result<(), String> {
    if proof.len() > profile.max_proof_bytes {
        return Err("proof too large".into());
    }
    if pi.value_balance.unsigned_abs() >= MAX_VALUE_BALANCE {
        return Err("value balance out of range".into());
    }
    let options = profile.options();
    if !proof.starts_with(&context_prefix_for(profile, pi)) && !(profile.unmasked && proof.starts_with(&prefix_of(pi, &[], &options))) {
        return Err("proof is not for this circuit".into());
    }
    let sha384 = profile.sha384;
    let run = || -> Result<(), String> {
        let p = Proof::from_bytes(proof).map_err(|e| format!("malformed proof: {e}"))?;
        if p.to_bytes() != proof {
            return Err("proof is not canonically encoded".into());
        }
        let acceptable = winterfell::AcceptableOptions::OptionSet(vec![options.clone()]);
        if sha384 {
            winterfell::verify::<SpendAir, Hash384, Coin384, Vc384>(p, pi.clone(), &acceptable).map_err(|e| format!("{e}"))
        } else {
            winterfell::verify::<SpendAir, Hash, Coin, Vc>(p, pi.clone(), &acceptable).map_err(|e| format!("{e}"))
        }
    };
    #[cfg(panic = "unwind")]
    {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| Err("malformed proof".into()))
    }
    #[cfg(not(panic = "unwind"))]
    {
        run()
    }
}

/// Proofs already verified, keyed by SHA-256 of (public inputs, proof). A transaction
/// checked when it entered the mempool is not checked again inside a block, and a block's
/// proofs can be checked before the node takes its lock. Bounded; cleared when full.
fn verified_cache() -> &'static std::sync::Mutex<std::collections::HashSet<[u8; 32]>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

fn cache_key(profile: &Profile, pi: &SpendPublic, proof: &[u8]) -> [u8; 32] {
    let rules = [profile.queries as u8, profile.unmasked as u8, profile.sha384 as u8, profile.tag.len() as u8];
    hash::sha256(&[rules.as_slice(), profile.tag, &(profile.max_proof_bytes as u64).to_le_bytes(), pi.to_bytes().as_slice(), proof].concat())
}

/// `verify_bytes_for` with the cache.
pub fn verify_bytes_cached(profile: &Profile, pi: &SpendPublic, proof: &[u8]) -> Result<(), String> {
    let key = cache_key(profile, pi, proof);
    let hit = verified_cache().lock().map(|c| c.contains(&key)).unwrap_or(false);
    if hit {
        return Ok(());
    }
    verify_bytes_for(profile, pi, proof)?;
    if let Ok(mut c) = verified_cache().lock() {
        if c.len() >= 20_000 {
            c.clear();
        }
        c.insert(key);
    }
    Ok(())
}

/// A prover with explicit options, for parameter studies.
pub fn test_prover(options: ProofOptions, pi: SpendPublic) -> SpendProver {
    SpendProver { options, pi }
}

// ---- the main network's proof parameters (white paper §9) ---------------------------------

/// Queries per proof on the main network: twice the test network's 64. That halves the
/// query error again, so the proven bound is set by the 256-bit hash (about 85 bits against
/// a quantum attacker in the quantum random-oracle model) rather than by the queries.
pub const MAIN_QUERIES: usize = 128;

/// The main network's proof options: the test network's, with `MAIN_QUERIES` queries.
pub fn main_options() -> ProofOptions {
    ProofOptions::new(MAIN_QUERIES, 16, 16, FieldExtension::Cubic, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
}

/// Largest proof the main network accepts. Proofs at its parameters measure about 460 KB.
pub const MAIN_MAX_PROOF_BYTES: usize = 520_000;

/// Largest Mainnet v2 SHA-384 proof (384-bit FRI commitments + 128 queries + ZK masking).
pub const MAIN_V2_MAX_PROOF_BYTES: usize = 700_000;

/// Mainnet v2 spend profile: 128 queries, 384-bit SHA-384 FRI/Merkle commitments (128-bit
/// QROM post-quantum collision resistance, 192-bit classical), Haböck–Al Kindi ZK masking.
pub const MAIN_V2: Profile = Profile {
    queries: MAIN_QUERIES,
    tag: b"/main-v2-sha384",
    unmasked: false,
    max_proof_bytes: MAIN_V2_MAX_PROOF_BYTES,
    sha384: true,
};

pub struct SpendProver384 {
    options: ProofOptions,
    pi: SpendPublic,
}

impl Prover for SpendProver384 {
    type BaseField = Felt;
    type Air = SpendAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hash384;
    type VC = Vc384;
    type RandomCoin = Coin384;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, Hash384, Vc384>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> = DefaultConstraintCommitment<E, Hash384, Vc384>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> = DefaultConstraintEvaluator<'a, SpendAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SpendPublic {
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
        if num_constraint_composition_columns > plain_composition_columns() {
            let k = zk_mask_len(&self.options);
            let masks: Vec<Vec<E>> = (1..num_constraint_composition_columns).map(|_| random_elements::<E>(k)).collect();
            DefaultConstraintCommitment::new_masked(composition_poly_trace, num_constraint_composition_columns, domain.trace_length() - k, &masks, domain, partition_options)
        } else {
            DefaultConstraintCommitment::new(composition_poly_trace, num_constraint_composition_columns, domain, partition_options)
        }
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a SpendAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Prove a Mainnet v2 spend with 384-bit SHA-384 FRI commitments (>= 128-bit QROM soundness).
pub fn prove_v2_sha384(wit: &SpendWitness, bind: Word8) -> Result<(SpendPublic, Proof), String> {
    let pi = wit.public(bind)?;
    let trace = build_trace_with(wit, &MAIN_V2.meta());
    let proof = SpendProver384 { options: MAIN_V2.options(), pi: pi.clone() }
        .prove(trace)
        .map_err(|e| format!("prover: {e}"))?;
    Ok((pi, proof))
}

/// Verify a serialized Mainnet v2 SHA-384 spend proof (canonical encoding + exact OptionSet + catch_unwind).
pub fn verify_v2_sha384_bytes(pi: &SpendPublic, proof: &[u8]) -> Result<(), String> {
    if proof.len() > MAIN_V2.max_proof_bytes {
        return Err("proof too large".into());
    }
    if pi.value_balance.unsigned_abs() >= MAX_VALUE_BALANCE {
        return Err("value balance out of range".into());
    }
    let options = MAIN_V2.options();
    if !proof.starts_with(&context_prefix_for(&MAIN_V2, pi)) {
        return Err("proof is not for Mainnet v2 SHA-384 circuit".into());
    }
    let run = || -> Result<(), String> {
        let p = Proof::from_bytes(proof).map_err(|e| format!("malformed proof: {e}"))?;
        if p.to_bytes() != proof {
            return Err("proof is not canonically encoded".into());
        }
        let acceptable = winterfell::AcceptableOptions::OptionSet(vec![options.clone()]);
        winterfell::verify::<SpendAir, Hash384, Coin384, Vc384>(p, pi.clone(), &acceptable).map_err(|e| format!("{e}"))
    };
    #[cfg(panic = "unwind")]
    {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| Err("malformed proof".into()))
    }
    #[cfg(not(panic = "unwind"))]
    {
        run()
    }
}

/// Prove with the given options: `options()` for the test network, `main_options()` for
/// the main network.
pub fn prove_with(wit: &SpendWitness, bind: Word8, options: ProofOptions) -> Result<(SpendPublic, Proof), String> {
    let pi = wit.public(bind)?;
    let trace = build_trace(wit);
    let proof = SpendProver { options, pi: pi.clone() }.prove(trace).map_err(|e| format!("prover: {e}"))?;
    Ok((pi, proof))
}

/// Verify against exactly the given options; a proof made with any other options fails.
/// The main network takes only proofs with masked segments.
pub fn verify_with(pi: &SpendPublic, proof: &Proof, options: ProofOptions) -> Result<(), String> {
    if pi.value_balance.unsigned_abs() >= MAX_VALUE_BALANCE {
        return Err("value balance out of range".into());
    }
    if options != self::options() && proof.trace_info().meta() != ZK_META {
        return Err("the main network takes only zero-knowledge proofs".into());
    }
    let acceptable = winterfell::AcceptableOptions::OptionSet(vec![options]);
    winterfell::verify::<SpendAir, Hash, Coin, Vc>(proof.clone(), pi.clone(), &acceptable).map_err(|e| format!("{e}"))
}
