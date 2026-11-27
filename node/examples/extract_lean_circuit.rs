//! Extract ALL 249 transition constraint polynomials (`#0..#248`, ~2,950 terms), the exact
//! 128-block / 8,192-row selector layout, and all real/dummy boundary assertion cells directly
//! from the compiling Rust `newsatoshi::spend::{eval_constraints, periodic_table, layout, assertion_cells}`,
//! cross-check every polynomial at 20 random Goldilocks points, and emit a self-contained,
//! zero-`sorry`, zero-Mathlib, kernel-checked Lean 4.36.0 formal mechanization of the ENTIRE
//! SHA-256 shielded spend circuit at `proof/SpendCircuitFull.lean`.
//!
//! Usage:
//!     cargo run --release --example extract_lean_circuit -- proof/SpendCircuitFull.lean
//!     lean proof/SpendCircuitFull.lean

use newsatoshi::{hash, note, spend::{self, BLK, N_CONSTRAINTS, ROWS, WIDTH}};
use rand::Rng;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::*;
use std::sync::{Mutex, OnceLock};
use winter_utils::{
    AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError, Randomizable,
    Serializable,
};
use winterfell::math::{fields::f64::BaseElement as Felt, ExtensionOf, FieldElement, StarkField};

type Poly = BTreeMap<Vec<u16>, Felt>;

fn arena() -> &'static Mutex<Vec<Poly>> {
    static A: OnceLock<Mutex<Vec<Poly>>> = OnceLock::new();
    A.get_or_init(|| Mutex::new(vec![Poly::new(), Poly::from([(vec![], Felt::ONE)])]))
}

fn get(s: Sym) -> Poly {
    arena().lock().unwrap()[s.0 as usize].clone()
}

fn put(p: Poly) -> Sym {
    let p: Poly = p.into_iter().filter(|(_, c)| *c != Felt::ZERO).collect();
    let mut a = arena().lock().unwrap();
    a.push(p);
    Sym((a.len() - 1) as u32)
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Sym(u32);

impl Sym {
    fn var(id: u16) -> Sym {
        put(Poly::from([(vec![id], Felt::ONE)]))
    }
    fn constant(c: Felt) -> Sym {
        put(Poly::from([(vec![], c)]))
    }
}

impl fmt::Debug for Sym {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", get(*self))
    }
}
impl fmt::Display for Sym {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", get(*self))
    }
}
impl Add for Sym {
    type Output = Sym;
    fn add(self, o: Sym) -> Sym {
        let mut p = get(self);
        for (m, c) in get(o) {
            *p.entry(m).or_insert(Felt::ZERO) += c;
        }
        put(p)
    }
}
impl Neg for Sym {
    type Output = Sym;
    fn neg(self) -> Sym {
        put(get(self).into_iter().map(|(m, c)| (m, -c)).collect())
    }
}
impl Sub for Sym {
    type Output = Sym;
    fn sub(self, o: Sym) -> Sym {
        self + (-o)
    }
}
impl Mul for Sym {
    type Output = Sym;
    fn mul(self, o: Sym) -> Sym {
        let (a, b) = (get(self), get(o));
        let mut p = Poly::new();
        for (ma, ca) in &a {
            for (mb, cb) in &b {
                let mut m = [ma.as_slice(), mb.as_slice()].concat();
                m.sort_unstable();
                *p.entry(m).or_insert(Felt::ZERO) += *ca * *cb;
            }
        }
        put(p)
    }
}
impl Div for Sym {
    type Output = Sym;
    fn div(self, _: Sym) -> Sym {
        panic!("constraints never divide")
    }
}
impl AddAssign for Sym {
    fn add_assign(&mut self, o: Sym) {
        *self = *self + o;
    }
}
impl SubAssign for Sym {
    fn sub_assign(&mut self, o: Sym) {
        *self = *self - o;
    }
}
impl MulAssign for Sym {
    fn mul_assign(&mut self, o: Sym) {
        *self = *self * o;
    }
}
impl DivAssign for Sym {
    fn div_assign(&mut self, o: Sym) {
        *self = *self / o;
    }
}
impl From<Felt> for Sym {
    fn from(c: Felt) -> Sym {
        Sym::constant(c)
    }
}
impl From<u32> for Sym {
    fn from(c: u32) -> Sym {
        Sym::constant(Felt::from(c))
    }
}
impl From<u16> for Sym {
    fn from(c: u16) -> Sym {
        Sym::constant(Felt::from(c))
    }
}
impl From<u8> for Sym {
    fn from(c: u8) -> Sym {
        Sym::constant(Felt::from(c))
    }
}
impl TryFrom<u64> for Sym {
    type Error = String;
    fn try_from(c: u64) -> Result<Sym, String> {
        Ok(Sym::constant(Felt::new(c)))
    }
}
impl TryFrom<u128> for Sym {
    type Error = String;
    fn try_from(_: u128) -> Result<Sym, String> {
        Err("unused".into())
    }
}
impl TryFrom<&[u8]> for Sym {
    type Error = String;
    fn try_from(_: &[u8]) -> Result<Sym, String> {
        Err("unused".into())
    }
}
impl ExtensionOf<Felt> for Sym {
    fn mul_base(self, other: Felt) -> Sym {
        self * Sym::constant(other)
    }
}
impl AsBytes for Sym {
    fn as_bytes(&self) -> &[u8] {
        &[]
    }
}
impl Randomizable for Sym {
    const VALUE_SIZE: usize = 8;
    fn from_random_bytes(_: &[u8]) -> Option<Sym> {
        None
    }
}
impl Serializable for Sym {
    fn write_into<W: ByteWriter>(&self, _: &mut W) {
        panic!("unused")
    }
}
impl Deserializable for Sym {
    fn read_from<R: ByteReader>(_: &mut R) -> Result<Sym, DeserializationError> {
        Err(DeserializationError::InvalidValue("unused".into()))
    }
}
impl FieldElement for Sym {
    type PositiveInteger = u64;
    type BaseField = Felt;
    const EXTENSION_DEGREE: usize = 1;
    const ELEMENT_BYTES: usize = 8;
    const IS_CANONICAL: bool = false;
    const ZERO: Sym = Sym(0);
    const ONE: Sym = Sym(1);
    fn inv(self) -> Sym {
        panic!("constraints never invert")
    }
    fn conjugate(&self) -> Sym {
        *self
    }
    fn base_element(&self, _: usize) -> Felt {
        panic!("unused")
    }
    fn slice_as_base_elements(_: &[Sym]) -> &[Felt] {
        panic!("unused")
    }
    fn slice_from_base_elements(_: &[Felt]) -> &[Sym] {
        panic!("unused")
    }
    fn elements_as_bytes(_: &[Sym]) -> &[u8] {
        panic!("unused")
    }
    unsafe fn bytes_as_elements(_: &[u8]) -> Result<&[Sym], DeserializationError> {
        Err(DeserializationError::InvalidValue("unused".into()))
    }
}

fn format_lean_poly(p: &Poly) -> String {
    let mut entries: Vec<(&Vec<u16>, &Felt)> = p.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let items: Vec<String> = entries
        .into_iter()
        .map(|(m, c)| {
            let vars = m.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");
            format!("([{vars}],{})", c.as_int())
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proof/SpendCircuitFull.lean".into());

    let periodic = spend::periodic_table();
    let np = periodic[0].len();
    assert_eq!(periodic.len(), ROWS);

    // 1. Symbolically evaluate the live compiling `spend::eval_constraints` on ALL 249 constraints!
    let cur: Vec<Sym> = (0..WIDTH).map(|i| Sym::var(i as u16)).collect();
    let nxt: Vec<Sym> = (0..WIDTH).map(|i| Sym::var((WIDTH + i) as u16)).collect();
    let pv: Vec<Sym> = (0..np).map(|i| Sym::var((2 * WIDTH + i) as u16)).collect();
    let mut res = vec![Sym::ZERO; N_CONSTRAINTS];
    spend::eval_constraints(&cur, &nxt, &pv, &mut res);

    // 2. Cross-check all 249 symbolic polynomials against numeric `spend::eval_constraints` on 20 random points.
    let mut rng = rand::thread_rng();
    for _ in 0..20 {
        let vals: Vec<Felt> = (0..2 * WIDTH + np)
            .map(|_| Felt::new(rng.gen::<u64>() % Felt::MODULUS))
            .collect();
        let mut direct = vec![Felt::ZERO; N_CONSTRAINTS];
        spend::eval_constraints(
            &vals[..WIDTH],
            &vals[WIDTH..2 * WIDTH],
            &vals[2 * WIDTH..],
            &mut direct,
        );
        for (c, r) in res.iter().enumerate() {
            let v = get(*r).iter().fold(Felt::ZERO, |s, (m, k)| {
                s + *k * m.iter().fold(Felt::ONE, |p, &x| p * vals[x as usize])
            });
            assert_eq!(v, direct[c], "extracted constraint {c} disagreed at random point");
        }
    }

    // 3. Emit each extracted constraint as its own canonical Lean Poly definition + O(1)-depth dispatch
    let mut total_terms = 0usize;
    let mut extracted_defs = String::new();
    for (i, r) in res.iter().enumerate() {
        let p = get(*r);
        total_terms += p.len();
        extracted_defs.push_str(&format!("def rustCon{i} : Poly := {}\n", format_lean_poly(&p)));
    }
    let mut rust_dispatch = String::new();
    for b in 0..16 {
        rust_dispatch.push_str(&format!("def rustConBucket{b} : Nat → Poly\n"));
        for rem in 0..16 {
            let idx = b * 16 + rem;
            if idx < N_CONSTRAINTS {
                rust_dispatch.push_str(&format!("  | {rem} => rustCon{idx}\n"));
            }
        }
        rust_dispatch.push_str("  | _ => []\n");
    }
    rust_dispatch.push_str("def rustCon (i : Nat) : Poly :=\n  match i / 16 with\n");
    for b in 0..16 {
        rust_dispatch.push_str(&format!("  | {b} => rustConBucket{b} (i % 16)\n"));
    }
    rust_dispatch.push_str("  | _ => []\n");

    // 4. Verify all 8,192 periodic rows & encode compact per-block layout + assertions
    let layout = spend::layout();
    assert_eq!(layout.len(), ROWS / BLK);
    let layout_codes: Vec<String> = layout
        .iter()
        .map(|k| match *k {
            spend::Kind::Rand => "0".to_string(),
            spend::Kind::Addr(i) => format!("{}", 1 + i),
            spend::Kind::CmIn(i) => format!("{}", 3 + i),
            spend::Kind::Merkle(i, d) => format!("{}", 10 + i * 32 + d),
            spend::Kind::Nf(i) => format!("{}", 5 + i),
            spend::Kind::CmOut(o) => format!("{}", 7 + o),
        })
        .collect();

    // Check periodic_table row-by-row matches the formula we will independently prove in Lean!
    for r in 0..ROWS {
        let b = r / BLK;
        let t = r % BLK;
        let kind = layout[b];
        let next = if b + 1 < layout.len() { layout[b + 1] } else { spend::Kind::Rand };
        let act = kind.active();
        assert_eq!(periodic[r][0].as_int(), newsatoshi::hash::K[(t + 1) % 64] as u64);
        assert_eq!(periodic[r][1].as_int(), u64::from(act && t < 63));
        assert_eq!(periodic[r][2].as_int(), u64::from(act && t == 63));
        assert_eq!(periodic[r][3].as_int(), u64::from(t == 63 && matches!(next, spend::Kind::Addr(_))));
        assert_eq!(periodic[r][4].as_int(), u64::from(t == 63 && matches!(next, spend::Kind::CmIn(_))));
        assert_eq!(periodic[r][5].as_int(), u64::from(t == 63 && matches!(next, spend::Kind::Merkle(_, _))));
        assert_eq!(periodic[r][6].as_int(), u64::from(t == 63 && matches!(next, spend::Kind::Nf(_))));
        assert_eq!(periodic[r][7].as_int(), u64::from(t == 63 && matches!(next, spend::Kind::CmOut(_))));
        let exp_w = match next {
            spend::Kind::Merkle(_, k) if t == 63 => 1u64 << k,
            _ => 0,
        };
        assert_eq!(periodic[r][8].as_int(), exp_w);
        assert_eq!(periodic[r][9].as_int(), u64::from(act && t == 8 && matches!(kind, spend::Kind::CmIn(_) | spend::Kind::CmOut(_))));
        assert_eq!(periodic[r][10].as_int(), u64::from(act));
        let last_block = layout.iter().position(|k| *k == spend::Kind::CmOut(1)).unwrap();
        let exp_act = u64::from(r >= BLK && r + 1 < (last_block + 1) * BLK);
        assert_eq!(periodic[r][11].as_int(), exp_act);
        assert_eq!(periodic[r][12].as_int(), exp_act * (1 - periodic[r][3].as_int()));
        assert_eq!(periodic[r][13].as_int(), exp_act * (1 - periodic[r][4].as_int()));
    }

    // 4b. Cross-check the EXACT closed-form `periodicVal(r, s)` definition emitted into Lean 4
    // across ALL 8,192 rows × 14 selectors = 114,688 cells against live Rust `spend::periodic_table()`!
    for r in 0..ROWS {
        let b = r / 64;
        let t = r % 64;
        let lean_per = |s: usize| -> u64 {
            match s {
                0  => hash::K[(t + 1) % 64] as u64,
                1  => u64::from(1 <= b && b <= 72 && t < 63),
                2  => u64::from(1 <= b && b <= 72 && t == 63),
                3  => u64::from(t == 63 && (b == 0 || b == 35)),
                4  => u64::from(t == 63 && (b == 1 || b == 36)),
                5  => u64::from(t == 63 && ((2 <= b && b <= 33) || (37 <= b && b <= 68))),
                6  => u64::from(t == 63 && (b == 34 || b == 69)),
                7  => u64::from(t == 63 && (b == 70 || b == 71)),
                8  => if t == 63 && 2 <= b && b <= 33 { 1u64 << (b - 2) }
                      else if t == 63 && 37 <= b && b <= 68 { 1u64 << (b - 37) }
                      else { 0 },
                9  => u64::from(t == 8 && (b == 2 || b == 37 || b == 71 || b == 72)),
                10 => u64::from(1 <= b && b <= 72),
                11 => u64::from(64 <= r && r < 4671),
                12 => u64::from(64 <= r && r < 4671) * (1 - u64::from(t == 63 && (b == 0 || b == 35))),
                13 => u64::from(64 <= r && r < 4671) * (1 - u64::from(t == 63 && (b == 1 || b == 36))),
                _  => 0,
            }
        };
        for s in 0..np {
            assert_eq!(
                periodic[r][s].as_int(),
                lean_per(s),
                "Lean closed-form periodicVal({r}, {s}) disagreed with live Rust periodic_table()"
            );
        }
    }

    // 4c. Construct a REAL non-dummy 2-in/2-out shielded spend witness sharing a 32-level Merkle root,
    // verify it LIVE against `spend::build_trace` + `spend::check_trace`, and emit it as a Lean 4
    // non-vacuity certificate (`concretePi`, `concreteWitness`, `raw_rust_air_non_vacuous`).
    let sk0: [u32; 8] = [0x0123_4567, 0x89ab_cdef, 0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888, 0x9999_aaaa, 0xbbbb_cccc];
    let sk1: [u32; 8] = [0xfedc_ba98, 0x7654_3210, 0x1357_9bdf, 0x2468_ace0, 0x0f1e_2d3c, 0x4b5a_6978, 0xa1b2_c3d4, 0xe5f6_0718];
    let rho0: [u32; 5] = [0x1000_0001, 0x2000_0002, 0x3000_0003, 0x4000_0004, 0x5000_0005];
    let rho1: [u32; 5] = [0x6000_0006, 0x7000_0007, 0x8000_0008, 0x9000_0009, 0xa000_000a];
    let v_in0: u64 = 5_000_000_000;
    let v_in1: u64 = 3_000_000_000;
    let pos0: u32 = 0x5a3c_1020; // even (bit 0 = 0)
    let pos1: u32 = 0x5a3c_1021; // odd sibling (bit 0 = 1) -> shares levels 1..31 & exact 32-level root!
    let apk0 = note::address(&sk0);
    let apk1 = note::address(&sk1);
    let cm_in0 = note::commit(&apk0, v_in0, &rho0);
    let cm_in1 = note::commit(&apk1, v_in1, &rho1);
    let mut path0 = [[0u32; 8]; note::DEPTH];
    let mut path1 = [[0u32; 8]; note::DEPTH];
    path0[0] = cm_in1;
    path1[0] = cm_in0;
    for k in 1..note::DEPTH {
        let sib = [
            0x1000_0000u32 + k as u32,
            0x2000_0000u32 + k as u32,
            0x3000_0000u32 + k as u32,
            0x4000_0000u32 + k as u32,
            0x5000_0000u32 + k as u32,
            0x6000_0000u32 + k as u32,
            0x7000_0000u32 + k as u32,
            0x8000_0000u32 + k as u32,
        ];
        path0[k] = sib;
        path1[k] = sib;
    }
    let apk_out0: [u32; 8] = [0xaaaa_0001, 0xaaaa_0002, 0xaaaa_0003, 0xaaaa_0004, 0xaaaa_0005, 0xaaaa_0006, 0xaaaa_0007, 0xaaaa_0008];
    let apk_out1: [u32; 8] = [0xbbbb_0001, 0xbbbb_0002, 0xbbbb_0003, 0xbbbb_0004, 0xbbbb_0005, 0xbbbb_0006, 0xbbbb_0007, 0xbbbb_0008];
    let rho_out0: [u32; 5] = [0xb000_0001, 0xb000_0002, 0xb000_0003, 0xb000_0004, 0xb000_0005];
    let rho_out1: [u32; 5] = [0xc000_0001, 0xc000_0002, 0xc000_0003, 0xc000_0004, 0xc000_0005];
    let v_out0: u64 = 6_500_000_000;
    let v_out1: u64 = 1_499_990_000;
    let concrete_wit = spend::SpendWitness {
        inputs: [
            spend::InputNote { sk: sk0, v: v_in0, rho: rho0, pos: pos0, path: path0 },
            spend::InputNote { sk: sk1, v: v_in1, rho: rho1, pos: pos1, path: path1 },
        ],
        outputs: [
            spend::OutputNote { a_pk: apk_out0, v: v_out0, rho: rho_out0 },
            spend::OutputNote { a_pk: apk_out1, v: v_out1, rho: rho_out1 },
        ],
        dummy: [false, false],
    };
    let concrete_pi = concrete_wit
        .public([0u32; 8])
        .expect("concrete 2-in/2-out witness must produce valid SpendPublic");
    let concrete_trace = spend::build_trace(&concrete_wit);
    spend::check_trace(&concrete_trace, &concrete_pi)
        .expect("concrete 2-in/2-out witness must pass live Rust spend::check_trace");

    let merkle_chain = |leaf: [u32; 8], pos: u32, path: &[[u32; 8]; note::DEPTH]| -> Vec<[u32; 8]> {
        let mut nodes = Vec::with_capacity(note::DEPTH + 1);
        let mut cur = leaf;
        nodes.push(cur);
        for k in 0..note::DEPTH {
            let bit = (pos >> k) & 1;
            cur = if bit == 0 { hash::node(&cur, &path[k]) } else { hash::node(&path[k], &cur) };
            nodes.push(cur);
        }
        nodes
    };
    let nodes0 = merkle_chain(cm_in0, pos0, &path0);
    let nodes1 = merkle_chain(cm_in1, pos1, &path1);
    assert_eq!(nodes0[note::DEPTH], concrete_pi.root);
    assert_eq!(nodes1[note::DEPTH], concrete_pi.root);

    let fmt_u32_arr = |xs: &[u32]| -> String {
        let parts: Vec<String> = xs.iter().map(|x| format!("0x{x:08x}")).collect();
        format!("#[{}]", parts.join(", "))
    };
    let fmt_u32_arr_list = |arrs: &[[u32; 8]]| -> String {
        let parts: Vec<String> = arrs.iter().map(|a| format!("  {}", fmt_u32_arr(a))).collect();
        format!("#[\n{}\n]", parts.join(",\n"))
    };

    let pi_real = spend::SpendPublic {
        root: [0; 8],
        nf: [[0; 8]; 2],
        cm_out: [[0; 8]; 2],
        value_balance: 0,
        dummy: [false, false],
        bind: [0; 8],
    };
    let pi_dummy = spend::SpendPublic { dummy: [true, true], ..pi_real };
    let fmt_cells = |cells: Vec<(usize, usize, Felt)>| -> String {
        let mut pairs: Vec<(usize, usize)> = cells.into_iter().map(|(c, r, _)| (c, r)).collect();
        pairs.sort_unstable();
        pairs.into_iter().map(|(c, r)| format!("({c},{r})")).collect::<Vec<_>>().join(",")
    };
    let assert_real_str = fmt_cells(spend::assertion_cells(&pi_real));
    let assert_dummy_str = fmt_cells(spend::assertion_cells(&pi_dummy));

    // Also emit per-constraint equality proofs grouped cleanly so Lean's pure kernel checks
    // EVERY SINGLE ONE of the 249 constraints (`#0..#248`) with ZERO `native_decide` and ZERO `sorry`!
    let mut con_proofs = String::new();
    // Group into fast kernel-checked chunks:
    //   - Constraints 0, 1 (round a & e equations — largest degree-3 polynomials) individually
    //   - Constraints 2..69 (state bit & word shifts)
    //   - Constraints 70..84 (window shifts + loads)
    //   - Constraint 85 (W_{t+16} recurrence — degree-3 ssig0/ssig1 polynomial) individually
    //   - Constraints 86..95 (W1/W14 range checks + 8 digest equations)
    //   - Constraints 96..232 (137 booleanity constraints)
    //   - Constraints 233..248 (sk/rho/pos/bal/vchk constraints)
    con_proofs.push_str(
r#"theorem con_0_round_a_matches_fips180_4 : rustCon 0 = fipsCon 0 := by decide
theorem con_1_round_e_matches_fips180_4 : rustCon 1 = fipsCon 1 := by decide
theorem con_2_to_69_state_shifts_match_fips180_4 :
    (List.range 68).all (fun k => rustCon (k + 2) == fipsCon (k + 2)) = true := by decide
theorem con_70_to_84_window_and_loads_match_fips180_4 :
    (List.range 15).all (fun k => rustCon (k + 70) == fipsCon (k + 70)) = true := by decide
theorem con_85_w16_schedule_matches_fips180_4 : rustCon 85 = fipsCon 85 := by decide
theorem con_86_to_95_range_and_digest_match_fips180_4 :
    (List.range 10).all (fun k => rustCon (k + 86) == fipsCon (k + 86)) = true := by decide
theorem con_96_to_232_booleanity_137_match_fips180_4 :
    (List.range 137).all (fun k => rustCon (k + 96) == fipsCon (k + 96)) = true := by decide
theorem con_233_to_248_registers_and_balance_match_fips180_4 :
    (List.range 16).all (fun k => rustCon (k + 233) == fipsCon (k + 233)) = true := by decide
"#
    );

    let mut lean_src = format!(
r#"/-!
# Newsatoshi Full 249-Constraint SHA-256 Spend Circuit — Machine-Checked Lean 4 Proof
# AUTO-GENERATED FROM LIVE RUST `spend::eval_constraints` (`examples/extract_lean_circuit.rs`)

Zero `sorry`, zero Mathlib, zero `native_decide`, zero external SMT/Z3 trust.
Every single one of the **249 transition constraint polynomials** (`#0..#248`, `{total_terms}`
monomial terms total), the 128-block layout, and all real/dummy boundary cells were extracted
directly by executing the live compiling Rust `newsatoshi::spend::eval_constraints` (cross-checked
at 20 random Goldilocks points before emission), and are proven **identically equal** inside Lean 4's
trusted kernel to an independent NIST FIPS 180-4 SHA-256 + Merkle + Nullifier + Balance AIR spec.

## What This File Proves Inside Lean 4's Trusted Kernel
1. **Independent NIST FIPS 180-4 SHA-256 Spec (`fips180_4_sha256_empty_exact`, `fips180_4_sha256_abc_exact`):**
   Pure-Lean `UInt32` SHA-256 compression verified against official NIST FIPS 180-4 test vectors.
2. **Exact Bit-Polynomial Algebra (`xor2_poly_exact`, `xor3_poly_exact`, `ch_poly_exact`, `maj_poly_exact`, `word32_lt_two32`):**
   Proves the multilinear polynomials used in the AIR compute exact bitwise `XOR2`, `XOR3`, `Ch`, `Maj`,
   and 32-bit unsigned word packing on all boolean inputs `{{0, 1}}`.
3. **ALL 249 Extracted Rust Polynomials == Independent FIPS 180-4 AIR Spec (`all_249_constraints_match_fips180_4_spec`):**
   Kernel-checked (`by decide`, zero `native_decide`!) formal equality across `#0..#248` over Goldilocks `P = 2^64 - 2^32 + 1`.
4. **All 7 No-Wrap & Unreduced-Word (`a_64`, `e_64`, `W_0`) Arithmetic Lemmas Proved Natively in Lean 4:**
   Completely replaces `proof/check.py`'s Z3 SMT queries inside Lean 4's own kernel (`round_a_mod32_sound`,
   `round_e_mod32_sound`, `w16_mod32_sound`, `digest_word_mod32_even_unreduced`, `w0_unreduced_round0_a_harmless`,
   `w0_unreduced_round0_e_harmless`, `w0_unreduced_w16_harmless`).
5. **Inductive 64-Round SHA-256 Compression, 32-Level Merkle Path, Layout/Assertions & Semantic Spend Soundness:**
   Proves 64-round compression induction, 32-level Merkle path + `pos` bit-accumulation induction,
   exact 128-block layout & boundary cells, and exact integer spend conservation `< 2^60` with zero Goldilocks wrap.
6. **Goldilocks Pocklington Primality & Bitwise Polynomial Algebra (`goldilocks_is_prime`, `goldilocks_boolean_sound`):**
   Self-contained zero-Mathlib Pocklington proof that `P = 2^64 - 2^32 + 1` is prime (so `GF(P)` is an integral domain
   and `x * (x - 1) ≡ 0 (mod P)` forces `x ∈ {{0, 1}}`), plus exact sparse `Poly` evaluation homomorphisms.
7. **Full Raw `8,192 × 247` Goldilocks AIR → `ValidSpendWitness` Soundness Refinement (`raw_rust_air_soundness`):**
   Mechanizes the complete bridge from ANY raw `8,192 × 247` Goldilocks field trace satisfying all 249 live Rust
   extracted polynomials (`rustCon 0..248`) and all boundary assertions (`spend::assertion_cells(&pi)`) to a semantic
   `ValidSpendWitness pi` (ownership, commitments, 32-level Merkle paths, nullifiers, `< 2^60` ranges, conservation).
8. **Completeness, Bidirectional Equivalence & Live Rust-Verified Concrete Non-Vacuity Witness:**
   Constructs `canonicalRawTrace`, proves `valid_witness_satisfies_raw_air` (completeness) and the bidirectional
   `raw_rust_air_iff_valid_spend_witness`, and certifies a real non-dummy 2-in/2-out witness (`raw_rust_air_non_vacuous`,
   independently verified by live Rust `spend::check_trace(&spend::build_trace(&wit), &pi)`).
-/

namespace NewsatoshiFullCircuit

set_option maxRecDepth 16384
set_option maxHeartbeats 8000000

def P_NAT : Nat := {modulus}
def P : Int := {modulus}
def TWO32_NAT : Nat := 4294967296
def TWO32 : Int := 4294967296
def MAX_NOTE_BOUND : Int := 1152921504606846976
def MAX_VB_BOUND : Int := 4611686018427387904

-- ============================================================================
-- SECTION 1: INDEPENDENT NIST FIPS 180-4 SHA-256 SPECIFICATION & TEST VECTORS
-- ============================================================================

def IV : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def K : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def TAG_ADDR : Nat := 0x6e734144 -- "nsAD"
def TAG_CM   : Nat := 0x6e73434d -- "nsCM"
def TAG_NF   : Nat := 0x6e734e46 -- "nsNF"

def rotr32 (x : UInt32) (r : UInt32) : UInt32 := (x >>> r) ||| (x <<< (32 - r))
def bigS0 (a : UInt32) : UInt32 := rotr32 a 2 ^^^ rotr32 a 13 ^^^ rotr32 a 22
def bigS1 (e : UInt32) : UInt32 := rotr32 e 6 ^^^ rotr32 e 11 ^^^ rotr32 e 25
def smallS0 (x : UInt32) : UInt32 := rotr32 x 7 ^^^ rotr32 x 18 ^^^ (x >>> 3)
def smallS1 (x : UInt32) : UInt32 := rotr32 x 17 ^^^ rotr32 x 19 ^^^ (x >>> 10)
def ch32 (e f g : UInt32) : UInt32 := (e &&& f) ^^^ ((~~~e) &&& g)
def maj32 (a b c : UInt32) : UInt32 := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)

structure ShaState where
  a : UInt32
  b : UInt32
  c : UInt32
  d : UInt32
  e : UInt32
  f : UInt32
  g : UInt32
  h : UInt32
  deriving DecidableEq, Repr

def sha256ScheduleStep (w : Array UInt32) : Nat → Array UInt32
  | 0 => w
  | n + 1 =>
    let i := w.size
    let wi := smallS1 w[i - 2]! + w[i - 7]! + smallS0 w[i - 15]! + w[i - 16]!
    sha256ScheduleStep (w.push wi) n

def sha256Schedule (blk : Array UInt32) : Array UInt32 :=
  sha256ScheduleStep blk 48

def sha256Round (st : ShaState) (kt wt : UInt32) : ShaState :=
  let t1 := st.h + bigS1 st.e + ch32 st.e st.f st.g + kt + wt
  let t2 := bigS0 st.a + maj32 st.a st.b st.c
  {{ a := t1 + t2, b := st.a, c := st.b, d := st.c,
     e := st.d + t1, f := st.e, g := st.f, h := st.g }}

def sha256RunRounds (w : Array UInt32) : Nat → ShaState → ShaState
  | 0, st => st
  | t + 1, st => sha256Round (sha256RunRounds w t st) K[t]! w[t]!

def sha256Init : ShaState :=
  {{ a := IV[0]!, b := IV[1]!, c := IV[2]!, d := IV[3]!,
     e := IV[4]!, f := IV[5]!, g := IV[6]!, h := IV[7]! }}

def sha256Compress (blk : Array UInt32) : Array UInt32 :=
  let w := sha256Schedule blk
  let s := sha256RunRounds w 64 sha256Init
  #[IV[0]! + s.a, IV[1]! + s.b, IV[2]! + s.c, IV[3]! + s.d,
    IV[4]! + s.e, IV[5]! + s.f, IV[6]! + s.g, IV[7]! + s.h]

-- Official NIST FIPS 180-4 SHA-256("") & SHA-256("abc") kernel checks
theorem fips180_4_sha256_empty_exact :
    sha256Compress #[0x80000000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] =
    #[0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
      0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855] := by decide

theorem fips180_4_sha256_abc_exact :
    sha256Compress #[0x61626380,0,0,0,0,0,0,0,0,0,0,0,0,0,0,24] =
    #[0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
      0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad] := by decide

-- ============================================================================
-- SECTION 2: MACHINE-CHECKED BIT-POLYNOMIAL & WORD-PACKING IDENTITIES
-- ============================================================================

def bitXor2 (x y : Int) : Int := if x == y then 0 else 1
def bitXor3 (x y z : Int) : Int := bitXor2 (bitXor2 x y) z
def bitCh (e f g : Int) : Int := if e == 1 then f else g
def bitMaj (a b c : Int) : Int := if a + b + c ≥ 2 then 1 else 0

theorem xor2_poly_exact (x y : Int) (hx : x = 0 ∨ x = 1) (hy : y = 0 ∨ y = 1) :
    x + y - 2 * x * y = bitXor2 x y := by
  rcases hx with rfl | rfl <;> rcases hy with rfl | rfl <;> decide

theorem xor3_poly_exact (x y z : Int)
    (hx : x = 0 ∨ x = 1) (hy : y = 0 ∨ y = 1) (hz : z = 0 ∨ z = 1) :
    x + y + z - 2 * (x * y + x * z + y * z) + 4 * x * y * z = bitXor3 x y z := by
  rcases hx with rfl | rfl <;> rcases hy with rfl | rfl <;> rcases hz with rfl | rfl <;> decide

theorem ch_poly_exact (e f g : Int)
    (he : e = 0 ∨ e = 1) (hf : f = 0 ∨ f = 1) (hg : g = 0 ∨ g = 1) :
    g + e * (f - g) = bitCh e f g := by
  rcases he with rfl | rfl <;> rcases hf with rfl | rfl <;> rcases hg with rfl | rfl <;> decide

theorem maj_poly_exact (a b c : Int)
    (ha : a = 0 ∨ a = 1) (hb : b = 0 ∨ b = 1) (hc : c = 0 ∨ c = 1) :
    a * b + a * c + b * c - 2 * a * b * c = bitMaj a b c := by
  rcases ha with rfl | rfl <;> rcases hb with rfl | rfl <;> rcases hc with rfl | rfl <;> decide

/-- Packing `n` boolean bits `b_0..b_{{n-1}}` yields an integer strictly in `[0, 2^n)`. -/
def packBits (b : Nat → Int) : Nat → Int
  | 0 => 0
  | n + 1 => packBits b n + b n * (2 ^ n : Nat)

theorem packBits_bounds (b : Nat → Int) (n : Nat)
    (hbits : ∀ i, i < n → b i = 0 ∨ b i = 1) :
    0 ≤ packBits b n ∧ packBits b n < (2 ^ n : Nat) := by
  induction n with
  | zero => simp [packBits]
  | succ k ih =>
    have hprev := ih (fun i hi => hbits i (by omega))
    have hk := hbits k (by omega)
    rw [packBits]
    have hpow : (2 ^ (k + 1) : Nat) = 2 * (2 ^ k : Nat) := by
      rw [Nat.pow_succ]; omega
    rcases hk with h0 | h1
    · rw [h0]; omega
    · rw [h1]; omega

theorem word32_pack_bounds (b : Nat → Int) (hbits : ∀ i, i < 32 → b i = 0 ∨ b i = 1) :
    0 ≤ packBits b 32 ∧ packBits b 32 < TWO32 := by
  have h := packBits_bounds b 32 hbits
  simpa [TWO32] using h

-- ============================================================================
-- SECTION 3: CANONICAL SPARSE POLYNOMIAL ALGEBRA OVER GF(P) & FIPS 180-4 AIR SPEC
-- ============================================================================

abbrev Poly := List (List Nat × Nat)

def evalMonomial (env : Nat → Int) : List Nat → Int
  | [] => 1
  | v :: vs => env v * evalMonomial env vs

def evalPoly (env : Nat → Int) : Poly → Int
  | [] => 0
  | (m, c) :: rest => (c : Int) * evalMonomial env m + evalPoly env rest

theorem poly_eq_eval_mod_P (p q : Poly) (h : p = q) (env : Nat → Int) :
    evalPoly env p % P = evalPoly env q % P := by
  rw [h]

def monCmp : List Nat → List Nat → Ordering
  | [], [] => .eq
  | [], _ :: _ => .lt
  | _ :: _, [] => .gt
  | a :: as, b :: bs =>
    if a < b then .lt
    else if a > b then .gt
    else monCmp as bs

-- Pure structural recursion (zero WellFounded.fix) so Lean 4's kernel reduces `decide` directly!
def monMergeGo (x : Nat) (xs : List Nat) (recMerge : List Nat → List Nat) : List Nat → List Nat
  | [] => x :: xs
  | y :: ys =>
    if x ≤ y then x :: recMerge (y :: ys)
    else y :: monMergeGo x xs recMerge ys

def monMerge : List Nat → List Nat → List Nat
  | [], ys => ys
  | x :: xs, ys => monMergeGo x xs (monMerge xs) ys

def pAddGo (m1 : List Nat) (c1 : Nat) (ps : Poly) (recAdd : Poly → Poly) : Poly → Poly
  | [] => (m1, c1) :: ps
  | (m2, c2) :: qs =>
    match monCmp m1 m2 with
    | .lt => (m1, c1) :: recAdd ((m2, c2) :: qs)
    | .gt => (m2, c2) :: pAddGo m1 c1 ps recAdd qs
    | .eq =>
      let s := (c1 + c2) % P_NAT
      if s == 0 then recAdd qs else (m1, s) :: recAdd qs

def pAdd : Poly → Poly → Poly
  | [], q => q
  | (m1, c1) :: ps, q => pAddGo m1 c1 ps (pAdd ps) q

def pScaleAux (km : Nat) : Poly → Poly
  | [] => []
  | (m, c) :: rest =>
    let v := (c * km) % P_NAT
    if v == 0 then pScaleAux km rest else (m, v) :: pScaleAux km rest

def pScale (k : Nat) (p : Poly) : Poly :=
  let km := k % P_NAT
  if km == 0 then [] else pScaleAux km p

def pNeg : Poly → Poly
  | [] => []
  | (m, c) :: rest =>
    let cm := c % P_NAT
    if cm == 0 then pNeg rest else (m, P_NAT - cm) :: pNeg rest

def pSub (p q : Poly) : Poly := pAdd p (pNeg q)

def pPairMerge : List Poly → List Poly
  | [] => []
  | [p] => [p]
  | p :: q :: rest => pAdd p q :: pPairMerge rest

def pSumListFuel : Nat → List Poly → Poly
  | _, [] => []
  | _, [p] => p
  | 0, p :: ps => ps.foldl pAdd p
  | fuel + 1, ps => pSumListFuel fuel (pPairMerge ps)

def pSumList (ps : List Poly) : Poly := pSumListFuel 16 ps

def pMulTermList (m : List Nat) (c : Nat) : Poly → List Poly
  | [] => []
  | (m2, c2) :: rest =>
    let v := (c * c2) % P_NAT
    if v == 0 then pMulTermList m c rest
    else [(monMerge m m2, v)] :: pMulTermList m c rest

def pMulTerm (m : List Nat) (c : Nat) (q : Poly) : Poly :=
  pSumList (pMulTermList m c q)

def pMulList (q : Poly) : Poly → List Poly
  | [] => []
  | (m, c) :: rest => pMulTerm m c q :: pMulList q rest

def pMul (p q : Poly) : Poly :=
  pSumList (pMulList q p)

def pSumPow2 : Nat → Nat → (Nat → Poly) → Poly
  | 0, lo, f => f lo
  | d + 1, lo, f => pAdd (pSumPow2 d lo f) (pSumPow2 d (lo + 2 ^ d) f)

def pConst (c : Nat) : Poly :=
  let cm := c % P_NAT
  if cm == 0 then [] else [([], cm)]

def pVar (v : Nat) : Poly := [([v], 1)]

-- Trace column & periodic selector indices matching spend.rs statement
def W_COLS : Nat := {width}
def COL_A : Nat := 0
def COL_AP : Nat := 32
def COL_E : Nat := 64
def COL_EP : Nat := 96
def COL_CWORD : Nat := 128
def COL_GWORD : Nat := 129
def COL_AN : Nat := 130
def COL_EN : Nat := 131
def COL_CA : Nat := 132
def COL_CE : Nat := 135
def COL_W : Nat := 138
def COL_X1 : Nat := 154
def COL_X14 : Nat := 186
def COL_CWC : Nat := 218
def COL_DIG : Nat := 220
def COL_SK : Nat := 228
def COL_RHO : Nat := 236
def COL_BIT : Nat := 241
def COL_POS : Nat := 242
def COL_BAL : Nat := 243

def vCur (c : Nat) : Poly := pVar c
def vNxt (c : Nat) : Poly := pVar (W_COLS + c)
def vPer (i : Nat) : Poly := pVar (2 * W_COLS + i)

def pXor2 (x y : Poly) : Poly := pSub (pAdd x y) (pScale 2 (pMul x y))
def pXor3 (x y z : Poly) : Poly :=
  let xy := pMul x y
  pAdd (pSub (pAdd (pAdd x y) z) (pScale 2 (pAdd (pAdd xy (pMul x z)) (pMul y z))))
       (pScale 4 (pMul xy z))

def pWordBits (getBit : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i => pScale (2 ^ i) (getBit i)

def pBigS0 (getBit : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i =>
    pScale (2 ^ i) (pXor3 (getBit ((i + 2) % 32)) (getBit ((i + 13) % 32)) (getBit ((i + 22) % 32)))

def pBigS1 (getBit : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i =>
    pScale (2 ^ i) (pXor3 (getBit ((i + 6) % 32)) (getBit ((i + 11) % 32)) (getBit ((i + 25) % 32)))

def pSmallS0 (getBit : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i =>
    let v := if i + 3 < 32
      then pXor3 (getBit ((i + 7) % 32)) (getBit ((i + 18) % 32)) (getBit (i + 3))
      else pXor2 (getBit ((i + 7) % 32)) (getBit ((i + 18) % 32))
    pScale (2 ^ i) v

def pSmallS1 (getBit : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i =>
    let v := if i + 10 < 32
      then pXor3 (getBit ((i + 17) % 32)) (getBit ((i + 19) % 32)) (getBit (i + 10))
      else pXor2 (getBit ((i + 17) % 32)) (getBit ((i + 19) % 32))
    pScale (2 ^ i) v

def pChWord (e f g : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i =>
    pScale (2 ^ i) (pAdd (g i) (pMul (e i) (pSub (f i) (g i))))

def pMajWord (a b c : Nat → Poly) : Poly :=
  pSumPow2 5 0 fun i =>
    let ab := pMul (a i) (b i)
    pScale (2 ^ i) (pSub (pAdd (pAdd ab (pMul (a i) (c i))) (pMul (b i) (c i)))
                         (pScale 2 (pMul ab (c i))))

def ivNat : Nat → Nat
  | 0 => 0x6a09e667
  | 1 => 0xbb67ae85
  | 2 => 0x3c6ef372
  | 3 => 0xa54ff53a
  | 4 => 0x510e527f
  | 5 => 0x9b05688c
  | 6 => 0x1f83d9ab
  | _ => 0x5be0cd19

def k0aConst : Nat :=
  let t1 : Nat := (ivNat 7) + (bigS1 IV[4]!).toNat + (ch32 IV[4]! IV[5]! IV[6]!).toNat + K[0]!.toNat
  t1 + (bigS0 IV[0]!).toNat + (maj32 IV[0]! IV[1]! IV[2]!).toNat

def k0eConst : Nat :=
  let t1 : Nat := (ivNat 7) + (bigS1 IV[4]!).toNat + (ch32 IV[4]! IV[5]! IV[6]!).toNat + K[0]!.toNat
  (ivNat 3) + t1

/-- Independent NIST FIPS 180-4 + Shielded Spend AIR specification for constraint `idx ∈ 0..248`.
    Pure structural definition (zero `Id.run`, zero `Array.get!`) so Lean 4's kernel reduces
    every single constraint directly with `by decide`. -/
def fipsCon (idx : Nat) : Poly :=
  let pk      := vPer 0
  let p_round := vPer 1
  let p_bnd   := vPer 2
  let p_addr  := vPer 3
  let p_cmin  := vPer 4
  let p_merkle:= vPer 5
  let p_nf    := vPer 6
  let p_cmout := vPer 7
  let p_w     := vPer 8
  let p_vchk  := vPer 9
  let p_actrow:= vPer 10
  let p_act   := vPer 11
  let p_skc   := vPer 12
  let p_rhoc  := vPer 13
  let p_iv    := pAdd (pAdd (pAdd (pAdd p_addr p_cmin) p_merkle) p_nf) p_cmout

  let na  (j : Nat) := vNxt (COL_A + j)
  let nap (j : Nat) := vNxt (COL_AP + j)
  let cap (j : Nat) := vCur (COL_AP + j)
  let ne  (j : Nat) := vNxt (COL_E + j)
  let nep (j : Nat) := vNxt (COL_EP + j)
  let cep (j : Nat) := vCur (COL_EP + j)
  let x1  (j : Nat) := vCur (COL_X1 + j)
  let x14 (j : Nat) := vCur (COL_X14 + j)
  let carry3 (col : Nat) := pAdd (pAdd (vNxt col) (pScale 2 (vNxt (col + 1)))) (pScale 4 (vNxt (col + 2)))

  if idx == 0 then
    let t1 := pAdd (pAdd (pAdd (pAdd (vCur COL_GWORD) (pBigS1 ne)) (pChWord ne nep cep)) pk) (vNxt COL_W)
    let s_a := pAdd (pAdd t1 (pBigS0 na)) (pMajWord na nap cap)
    let an  := pAdd (vNxt COL_AN) (pScale TWO32_NAT (carry3 COL_CA))
    pAdd (pMul p_round (pSub an s_a)) (pMul p_iv (pSub (pSub an (pConst k0aConst)) (vNxt COL_W)))
  else if idx == 1 then
    let t1 := pAdd (pAdd (pAdd (pAdd (vCur COL_GWORD) (pBigS1 ne)) (pChWord ne nep cep)) pk) (vNxt COL_W)
    let s_e := pAdd (vCur COL_CWORD) t1
    let en  := pAdd (vNxt COL_EN) (pScale TWO32_NAT (carry3 COL_CE))
    pAdd (pMul p_round (pSub en s_e)) (pMul p_iv (pSub (pSub en (pConst k0eConst)) (vNxt COL_W)))
  else if idx == 2 then
    pAdd (pMul p_round (pSub (pWordBits na) (vCur COL_AN))) (pMul p_iv (pSub (pWordBits na) (pConst (ivNat 0))))
  else if idx == 3 then
    pAdd (pMul p_round (pSub (pWordBits ne) (vCur COL_EN))) (pMul p_iv (pSub (pWordBits ne) (pConst (ivNat 4))))
  else if idx < 36 then
    let j := idx - 4
    let ivb := ((ivNat 1) >>> j) &&& 1
    pAdd (pMul p_round (pSub (nap j) (vCur (COL_A + j)))) (pMul p_iv (pSub (nap j) (pConst ivb)))
  else if idx < 68 then
    let j := idx - 36
    let ivb := ((ivNat 5) >>> j) &&& 1
    pAdd (pMul p_round (pSub (nep j) (vCur (COL_E + j)))) (pMul p_iv (pSub (nep j) (pConst ivb)))
  else if idx == 68 then
    pAdd (pMul p_round (pSub (vNxt COL_CWORD) (pWordBits cap))) (pMul p_iv (pSub (vNxt COL_CWORD) (pConst (ivNat 2))))
  else if idx == 69 then
    pAdd (pMul p_round (pSub (vNxt COL_GWORD) (pWordBits cep))) (pMul p_iv (pSub (vNxt COL_GWORD) (pConst (ivNat 6))))
  else if idx < 86 then
    let j := idx - 70
    let nbit := vNxt COL_BIT
    let r0 :=
      if j < 15 then
        pMul p_round (pSub (vNxt (COL_W + j)) (vCur (COL_W + j + 1)))
      else
        let cw := pAdd (vCur COL_CWC) (pScale 2 (vCur (COL_CWC + 1)))
        let rhs := pAdd (pAdd (pAdd (pSmallS1 x14) (vCur (COL_W + 9))) (pSmallS0 x1)) (vCur COL_W)
        pMul p_round (pSub (pAdd (vNxt (COL_W + 15)) (pScale TWO32_NAT cw)) rhs)
    let t_addr :=
      if j == 0 then pConst TAG_ADDR
      else if j ≤ 8 then vNxt (COL_SK + j - 1)
      else []
    let r1 := pAdd r0 (pMul p_addr (pSub (vNxt (COL_W + j)) t_addr))
    let r2 :=
      if j == 0 then pAdd r1 (pMul p_cmin (pSub (vNxt COL_W) (pConst TAG_CM)))
      else if j ≤ 8 then pAdd r1 (pMul p_cmin (pSub (vNxt (COL_W + j)) (vCur (COL_DIG + j - 1))))
      else if j ≥ 11 then pAdd r1 (pMul p_cmin (pSub (vNxt (COL_W + j)) (vNxt (COL_RHO + j - 11))))
      else r1
    let r3 :=
      if j < 8 then
        pAdd r2 (pMul (pMul p_merkle (pSub (pConst 1) nbit)) (pSub (vNxt (COL_W + j)) (vCur (COL_DIG + j))))
      else
        pAdd r2 (pMul (pMul p_merkle nbit) (pSub (vNxt (COL_W + j)) (vCur (COL_DIG + j - 8))))
    let t_nf :=
      if j == 0 then pConst TAG_NF
      else if j ≤ 8 then vNxt (COL_SK + j - 1)
      else if j == 9 then vNxt COL_POS
      else if j ≤ 14 then vNxt (COL_RHO + j - 10)
      else []
    let r4 := pAdd r3 (pMul p_nf (pSub (vNxt (COL_W + j)) t_nf))
    if j == 0 then pAdd r4 (pMul p_cmout (pSub (vNxt COL_W) (pConst TAG_CM))) else r4
  else if idx == 86 then
    pMul p_round (pSub (vCur (COL_W + 1)) (pWordBits x1))
  else if idx == 87 then
    pMul p_round (pSub (vCur (COL_W + 14)) (pWordBits x14))
  else if idx < 96 then
    let j := idx - 88
    let sw :=
      match j with
      | 0 => vCur COL_AN
      | 1 => pWordBits (fun k => vCur (COL_A + k))
      | 2 => pWordBits cap
      | 3 => vCur COL_CWORD
      | 4 => vCur COL_EN
      | 5 => pWordBits (fun k => vCur (COL_E + k))
      | 6 => pWordBits cep
      | _ => vCur COL_GWORD
    pMul p_bnd (pSub (pSub (pAdd (vCur (COL_DIG + j)) (pScale TWO32_NAT (x1 j))) (pConst (ivNat j))) sw)
  else if idx < 224 then
    let k := idx - 96
    let base := if k < 32 then COL_A else if k < 64 then COL_E else if k < 96 then COL_X1 else COL_X14
    let x := vCur (base + (k % 32))
    pMul p_actrow (pMul x (pSub x (pConst 1)))
  else if idx < 233 then
    let col :=
      match idx - 224 with
      | 0 => COL_CA
      | 1 => COL_CA + 1
      | 2 => COL_CA + 2
      | 3 => COL_CE
      | 4 => COL_CE + 1
      | 5 => COL_CE + 2
      | 6 => COL_CWC
      | 7 => COL_CWC + 1
      | _ => COL_BIT
    let x := vCur col
    pMul p_actrow (pMul x (pSub x (pConst 1)))
  else if idx < 241 then
    let j := idx - 233
    pMul p_skc (pSub (vNxt (COL_SK + j)) (vCur (COL_SK + j)))
  else if idx < 246 then
    let j := idx - 241
    pMul p_rhoc (pSub (vNxt (COL_RHO + j)) (vCur (COL_RHO + j)))
  else if idx == 246 then
    pSub (pSub (pMul p_act (vNxt COL_POS)) (pMul p_skc (vCur COL_POS))) (pMul p_w (vNxt COL_BIT))
  else if idx == 247 then
    let nv := pAdd (pScale TWO32_NAT (vNxt (COL_W + 9))) (vNxt (COL_W + 10))
    pAdd (pSub (pMul p_act (pSub (vNxt COL_BAL) (vCur COL_BAL))) (pMul p_cmin nv)) (pMul p_cmout nv)
  else
    pMul p_vchk (pAdd (pAdd (pAdd (x1 28) (x1 29)) (x1 30)) (x1 31))

-- ============================================================================
-- SECTION 4: ALL 249 EXTRACTED POLYNOMIALS FROM LIVE RUST `spend::eval_constraints`
-- ============================================================================

{extracted_defs}
{rust_dispatch}
theorem extracted_count_is_249 : (List.range 249).length = 249 := by decide

{con_proofs}

/-- Master Exactness Theorem: ALL 249 live Rust spend-circuit constraints (`#0..#248`, `{total_terms}`
    terms total) are formally identical in `GF(P)[cur, nxt, per]` to the independent NIST FIPS 180-4
    shielded spend AIR specification, verified inside Lean 4's trusted kernel with zero `sorry`. -/
theorem all_249_constraints_match_fips180_4_spec :
    ∀ i, i < 249 → rustCon i = fipsCon i := by
  intro i hi
  by_cases h0 : i = 0
  · subst h0; exact con_0_round_a_matches_fips180_4
  · by_cases h1 : i = 1
    · subst h1; exact con_1_round_e_matches_fips180_4
    · by_cases h2 : i < 70
      · have h := List.all_eq_true.mp con_2_to_69_state_shifts_match_fips180_4 (i - 2) (List.mem_range.mpr (by omega))
        have hrew : i - 2 + 2 = i := by omega
        rw [hrew] at h; exact beq_iff_eq.mp h
      · by_cases h3 : i < 85
        · have h := List.all_eq_true.mp con_70_to_84_window_and_loads_match_fips180_4 (i - 70) (List.mem_range.mpr (by omega))
          have hrew : i - 70 + 70 = i := by omega
          rw [hrew] at h; exact beq_iff_eq.mp h
        · by_cases h4 : i = 85
          · subst h4; exact con_85_w16_schedule_matches_fips180_4
          · by_cases h5 : i < 96
            · have h := List.all_eq_true.mp con_86_to_95_range_and_digest_match_fips180_4 (i - 86) (List.mem_range.mpr (by omega))
              have hrew : i - 86 + 86 = i := by omega
              rw [hrew] at h; exact beq_iff_eq.mp h
            · by_cases h6 : i < 233
              · have h := List.all_eq_true.mp con_96_to_232_booleanity_137_match_fips180_4 (i - 96) (List.mem_range.mpr (by omega))
                have hrew : i - 96 + 96 = i := by omega
                rw [hrew] at h; exact beq_iff_eq.mp h
              · have h := List.all_eq_true.mp con_233_to_248_registers_and_balance_match_fips180_4 (i - 233) (List.mem_range.mpr (by omega))
                have hrew : i - 233 + 233 = i := by omega
                rw [hrew] at h; exact beq_iff_eq.mp h

-- ============================================================================
-- SECTION 5: ALL 7 NO-WRAP & UNREDUCED-WORD ARITHMETIC LEMMAS (REPLACING Z3!)
-- ============================================================================

/-- Lemma A (No-wrap round word): any word `< 2^32` plus `2^32 * carry` (`carry < 8`) matching
    a sum `S < 7 * 2^32` modulo Goldilocks `P` equals `S % 2^32` identically. -/
theorem round_word_mod32_sound (an c S : Int)
    (han : 0 ≤ an ∧ an < TWO32)
    (hc : 0 ≤ c ∧ c < 8)
    (hS : 0 ≤ S ∧ S < 7 * TWO32)
    (hmod : (an + TWO32 * c - S) % P = 0) :
    an = S % TWO32 := by
  have hdiv : P ∣ (an + TWO32 * c - S) := Int.dvd_of_emod_eq_zero hmod
  rcases hdiv with ⟨q, hq⟩
  have hq0 : q = 0 := by
    simp only [P, TWO32] at *
    omega
  have heq : an + TWO32 * c = S := by
    rw [hq0] at hq; omega
  rw [← heq]
  simp only [TWO32] at *
  omega

/-- Lemma B (Schedule `W_{{t+16}}` no-wrap): 4-word sum `< 4 * 2^32`, 2-bit carry `< 4`. -/
theorem w16_word_mod32_sound (w16 cw S : Int)
    (hw : 0 ≤ w16 ∧ w16 < TWO32)
    (hc : 0 ≤ cw ∧ cw < 4)
    (hS : 0 ≤ S ∧ S < 4 * TWO32)
    (hmod : (w16 + TWO32 * cw - S) % P = 0) :
    w16 = S % TWO32 := by
  have hdiv : P ∣ (w16 + TWO32 * cw - S) := Int.dvd_of_emod_eq_zero hmod
  rcases hdiv with ⟨q, hq⟩
  have hq0 : q = 0 := by simp only [P, TWO32] at *; omega
  have heq : w16 + TWO32 * cw = S := by rw [hq0] at hq; omega
  rw [← heq]; simp only [TWO32] at *; omega

/-- Lemma C (Digest word soundness even when `out` is unreduced `a_64` or `e_64`, replacing Z3):
    Even though `a_64` and `e_64` are not bit-decomposed on row 63, they satisfy
    `out + 2^32 * cc ≡ S_ [ZMOD P]` with `S_ < 7 * 2^32`, `cc < 8`. Any `dig < 2^32` satisfying
    `dig + 2^32 * x ≡ ivj + out [ZMOD P]` (`x ∈ {{0, 1}}`) MUST equal `(ivj + S_) % 2^32`! -/
theorem digest_word_mod32_even_unreduced
    (dig x ivj out S_ cc : Int)
    (hdig : 0 ≤ dig ∧ dig < TWO32)
    (hx : x = 0 ∨ x = 1)
    (hiv : 0 ≤ ivj ∧ ivj < TWO32)
    (_hout : 0 ≤ out ∧ out < P)
    (hS : 0 ≤ S_ ∧ S_ < 7 * TWO32)
    (hcc : 0 ≤ cc ∧ cc < 8)
    (h1 : (out + TWO32 * cc - S_) % P = 0)
    (h2 : (dig + TWO32 * x - ivj - out) % P = 0) :
    dig = (ivj + S_) % TWO32 := by
  have hd1 := Int.dvd_of_emod_eq_zero h1
  have hd2 := Int.dvd_of_emod_eq_zero h2
  rcases hd1 with ⟨q1, hq1⟩
  rcases hd2 with ⟨q2, hq2⟩
  -- Eliminate `out`: `(dig + 2^32*(x + cc) - (ivj + S_)) = P*(q1 + q2)`
  have hcomb : dig + TWO32 * (x + cc) - (ivj + S_) = P * (q1 + q2) := by
    have : (out + TWO32 * cc - S_) + (dig + TWO32 * x - ivj - out) = P * q1 + P * q2 := by
      rw [hq1, hq2]
    rw [Int.mul_add TWO32 x cc, Int.mul_add P q1 q2]
    omega
  have hqsum : q1 + q2 = 0 := by
    simp only [P, TWO32] at *
    rcases hx with rfl | rfl <;> omega
  have heq : dig + TWO32 * (x + cc) = ivj + S_ := by
    rw [hqsum] at hcomb; omega
  rw [← heq]
  simp only [TWO32] at *
  rcases hx with rfl | rfl <;> omega

/-- Lemma D (Unreduced `W_0` harmlessness for round 0 `a`, round 0 `e`, and schedule `W_16`, replacing Z3):
    Even when `dig` (copied into `W_0` of the next block) is NOT range-checked below `2^32`,
    any `an < 2^32` with carry `c < 8` satisfying `an + 2^32 * c ≡ k + dig [ZMOD P]` (for
    `k < 7 * 2^32`) MUST equal `(k + (ivj + S_) % 2^32) % 2^32`! -/
theorem w0_unreduced_harmless_mod32
    (dig x ivj out S_ cc k an c : Int)
    (_hdig : 0 ≤ dig ∧ dig < P)
    (hx : x = 0 ∨ x = 1)
    (hiv : 0 ≤ ivj ∧ ivj < TWO32)
    (_hout : 0 ≤ out ∧ out < P)
    (hS : 0 ≤ S_ ∧ S_ < 7 * TWO32)
    (hcc : 0 ≤ cc ∧ cc < 8)
    (hk : 0 ≤ k ∧ k < 7 * TWO32)
    (han : 0 ≤ an ∧ an < TWO32)
    (hc : 0 ≤ c ∧ c < 8)
    (h1 : (out + TWO32 * cc - S_) % P = 0)
    (h2 : (dig + TWO32 * x - ivj - out) % P = 0)
    (h3 : (an + TWO32 * c - k - dig) % P = 0) :
    an = (k + (ivj + S_) % TWO32) % TWO32 := by
  have hd1 := Int.dvd_of_emod_eq_zero h1
  have hd2 := Int.dvd_of_emod_eq_zero h2
  have hd3 := Int.dvd_of_emod_eq_zero h3
  rcases hd1 with ⟨q1, hq1⟩
  rcases hd2 with ⟨q2, hq2⟩
  rcases hd3 with ⟨q3, hq3⟩
  have hcomb : an + TWO32 * (c + x + cc) - (k + ivj + S_) = P * (q1 + q2 + q3) := by
    have : (out + TWO32 * cc - S_) + (dig + TWO32 * x - ivj - out) + (an + TWO32 * c - k - dig) =
        P * q1 + P * q2 + P * q3 := by rw [hq1, hq2, hq3]
    rw [Int.mul_add TWO32 (c + x) cc, Int.mul_add TWO32 c x,
        Int.mul_add P (q1 + q2) q3, Int.mul_add P q1 q2]
    omega
  have hqsum : q1 + q2 + q3 = 0 := by
    simp only [P, TWO32] at *
    rcases hx with rfl | rfl <;> omega
  have heq : an + TWO32 * (c + x + cc) = k + ivj + S_ := by
    rw [hqsum] at hcomb; omega
  have hmod32 : (k + ivj + S_) % TWO32 = (k + (ivj + S_) % TWO32) % TWO32 := by
    rw [Int.add_assoc, Int.add_emod, Int.add_emod k ((ivj + S_) % TWO32), Int.emod_emod]
  rw [← hmod32, ← heq]
  simp only [TWO32] at *
  rcases hx with rfl | rfl <;> omega

-- ============================================================================
-- SECTION 6: 64-ROUND COMPRESSION, 32-LEVEL MERKLE & LAYOUT SOUNDNESS
-- ============================================================================

/-- 64-round SHA-256 induction: if a 64-row block starts at `IV` and each step `t < 64`
    matches `sha256Round` with schedule `w[t]` and constant `K[t]`, then row 64 equals
    exact FIPS 180-4 `sha256RunRounds w 64 sha256Init`. -/
theorem sha256_64_rounds_induction
    (w : Array UInt32) (trace : Nat → ShaState)
    (h0 : trace 0 = sha256Init)
    (hstep : ∀ t, t < 64 → trace (t + 1) = sha256Round (trace t) K[t]! w[t]!) :
    ∀ t, t ≤ 64 → trace t = sha256RunRounds w t sha256Init := by
  intro t ht
  induction t with
  | zero => exact h0
  | succ k ih =>
    rw [hstep k (by omega), sha256RunRounds, ih (by omega)]

/-- 32-level Merkle position accumulator induction (Constraint #246): starting from `pos 0 = 0`,
    adding `bit k * 2^k` at each level `k < 32` produces the exact 32-bit leaf index `< 2^32`. -/
def posAcc (bit : Nat → Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => posAcc bit k + bit k * 2 ^ k

theorem merkle_pos_32_levels_sound
    (bit pos : Nat → Nat)
    (hbit : ∀ k, k < 32 → bit k = 0 ∨ bit k = 1)
    (h0 : pos 0 = 0)
    (hstep : ∀ k, k < 32 → pos (k + 1) = pos k + bit k * 2 ^ k) :
    ∀ k, k ≤ 32 → pos k = posAcc bit k ∧ pos k < 2 ^ k := by
  intro k hk
  induction k with
  | zero => simp [posAcc, h0]
  | succ m ih =>
    have hp := ih (by omega)
    have hb := hbit m (by omega)
    have hs := hstep m (by omega)
    have hpow : 2 ^ (m + 1) = 2 * 2 ^ m := by rw [Nat.pow_succ]; omega
    constructor
    · rw [hs, posAcc, hp.1]
    · rcases hb with h0' | h1'
      · rw [hs, h0']; omega
      · rw [hs, h1']; omega

/-- Extracted 128-block layout & boundary cells match the spend statement identically. -/
def extractedLayout : List Nat := [{layout_str}]
def expectedLayout : List Nat :=
  [0] ++
  ([1, 3] ++ (List.range 32).map (fun d => 10 + d) ++ [5]) ++
  ([2, 4] ++ (List.range 32).map (fun d => 42 + d) ++ [6]) ++
  [7, 8] ++
  List.replicate 55 0

theorem layout_128_blocks_exact : extractedLayout = expectedLayout := by decide

def extractedAssertReal : List (Nat × Nat) := [{assert_real_str}]
def extractedAssertDummy : List (Nat × Nat) := [{assert_dummy_str}]

theorem boundary_assertions_counts_exact :
    extractedAssertReal.length = 51 ∧ extractedAssertDummy.length = 39 := by decide

-- ============================================================================
-- SECTION 7: END-TO-END SEMANTIC SPEND SOUNDNESS (OWNERSHIP, MERKLE
-- MEMBERSHIP, NULLIFIER UNIQUENESS & INTEGER CONSERVATION UNDER ASSERTIONS)
-- ============================================================================

abbrev Word8 := Fin 8 → UInt32
abbrev Rho5  := Fin 5 → UInt32

def arr8ToWord8 (a : Array UInt32) : Word8 := fun i => a[i.val]!

def noteAddress (sk : Word8) : Word8 :=
  arr8ToWord8 (sha256Compress #[
    UInt32.ofNat TAG_ADDR,
    sk 0, sk 1, sk 2, sk 3, sk 4, sk 5, sk 6, sk 7,
    0, 0, 0, 0, 0, 0, 0
  ])

def noteCommit (apk : Word8) (vHi vLo : UInt32) (rho : Rho5) : Word8 :=
  arr8ToWord8 (sha256Compress #[
    UInt32.ofNat TAG_CM,
    apk 0, apk 1, apk 2, apk 3, apk 4, apk 5, apk 6, apk 7,
    vHi, vLo,
    rho 0, rho 1, rho 2, rho 3, rho 4
  ])

def noteNullifier (sk : Word8) (pos : UInt32) (rho : Rho5) : Word8 :=
  arr8ToWord8 (sha256Compress #[
    UInt32.ofNat TAG_NF,
    sk 0, sk 1, sk 2, sk 3, sk 4, sk 5, sk 6, sk 7,
    pos,
    rho 0, rho 1, rho 2, rho 3, rho 4,
    0
  ])

def merkleMsg (cur sib : Word8) (bit : Nat) : Array UInt32 :=
  if bit = 0 then
    #[cur 0, cur 1, cur 2, cur 3, cur 4, cur 5, cur 6, cur 7,
      sib 0, sib 1, sib 2, sib 3, sib 4, sib 5, sib 6, sib 7]
  else
    #[sib 0, sib 1, sib 2, sib 3, sib 4, sib 5, sib 6, sib 7,
      cur 0, cur 1, cur 2, cur 3, cur 4, cur 5, cur 6, cur 7]

def merkleStep (cur sib : Word8) (bit : Nat) : Word8 :=
  arr8ToWord8 (sha256Compress (merkleMsg cur sib bit))

def merkleRoot (leaf : Word8) (bits : Nat → Nat) (sibs : Nat → Word8) : Nat → Word8
  | 0 => leaf
  | k + 1 => merkleStep (merkleRoot leaf bits sibs k) (sibs k) (bits k)

def noteValue (vHi vLo : UInt32) : Int :=
  TWO32 * (vHi.toNat : Int) + (vLo.toNat : Int)

def signedField (vb : Int) : Int :=
  if vb ≥ 0 then vb % P else (P - ((-vb) % P)) % P

/-- Public statement verified by `SpendAir` (`spend.rs:SpendPublic`). -/
structure SpendPublicStmt where
  root         : Word8
  nf0          : Word8
  nf1          : Word8
  cmOut0       : Word8
  cmOut1       : Word8
  valueBalance : Int
  dummy0       : Bool
  dummy1       : Bool
  hvb          : -MAX_VB_BOUND < valueBalance ∧ valueBalance < MAX_VB_BOUND

/-- Complete semantic shielded-spend witness relation: spend authorization (ownership),
    input note commitment binding, 32-level Merkle membership (all non-dummy inputs),
    deterministic nullifier binding, output commitment binding, `< 2^60` note range bounds,
    dummy zero-value enforcement, and exact integer value conservation. -/
structure ValidSpendWitness (pi : SpendPublicStmt) where
  sk0     : Word8
  sk1     : Word8
  apk0    : Word8
  apk1    : Word8
  vHiIn0  : UInt32
  vLoIn0  : UInt32
  vHiIn1  : UInt32
  vLoIn1  : UInt32
  rho0    : Rho5
  rho1    : Rho5
  cmIn0   : Word8
  cmIn1   : Word8
  bits0   : Nat → Nat
  bits1   : Nat → Nat
  sibs0   : Nat → Word8
  sibs1   : Nat → Word8
  pos0    : UInt32
  pos1    : UInt32
  apkOut0 : Word8
  apkOut1 : Word8
  vHiOut0 : UInt32
  vLoOut0 : UInt32
  vHiOut1 : UInt32
  vLoOut1 : UInt32
  rhoOut0 : Rho5
  rhoOut1 : Rho5
  -- 1. Spend authorization / ownership (`a_pk = H_addr(sk)`)
  hOwner0           : apk0 = noteAddress sk0
  hOwner1           : apk1 = noteAddress sk1
  -- 2. Input note commitment binding (`cm_in = H_cm(a_pk, v, rho)`)
  hCmIn0            : cmIn0 = noteCommit apk0 vHiIn0 vLoIn0 rho0
  hCmIn1            : cmIn1 = noteCommit apk1 vHiIn1 vLoIn1 rho1
  -- 3. 32-level Merkle inclusion + exact bit-accumulated leaf index for non-dummy inputs
  hBits0            : ∀ k, k < 32 → bits0 k = 0 ∨ bits0 k = 1
  hBits1            : ∀ k, k < 32 → bits1 k = 0 ∨ bits1 k = 1
  hPos0             : pos0.toNat = posAcc bits0 32
  hPos1             : pos1.toNat = posAcc bits1 32
  hMerkle0          : pi.dummy0 = false → merkleRoot cmIn0 bits0 sibs0 32 = pi.root
  hMerkle1          : pi.dummy1 = false → merkleRoot cmIn1 bits1 sibs1 32 = pi.root
  -- 4. Deterministic nullifier binding (`nf = H_nf(sk, pos, rho)`)
  hNf0              : pi.nf0 = noteNullifier sk0 pos0 rho0
  hNf1              : pi.nf1 = noteNullifier sk1 pos1 rho1
  -- 5. Output commitment binding
  hCmOut0           : pi.cmOut0 = noteCommit apkOut0 vHiOut0 vLoOut0 rhoOut0
  hCmOut1           : pi.cmOut1 = noteCommit apkOut1 vHiOut1 vLoOut1 rhoOut1
  -- 6. Strict `< 2^60` note range bounds + dummy zero-value enforcement
  hRangeIn0         : 0 ≤ noteValue vHiIn0 vLoIn0 ∧ noteValue vHiIn0 vLoIn0 < MAX_NOTE_BOUND
  hRangeIn1         : 0 ≤ noteValue vHiIn1 vLoIn1 ∧ noteValue vHiIn1 vLoIn1 < MAX_NOTE_BOUND
  hRangeOut0        : 0 ≤ noteValue vHiOut0 vLoOut0 ∧ noteValue vHiOut0 vLoOut0 < MAX_NOTE_BOUND
  hRangeOut1        : 0 ≤ noteValue vHiOut1 vLoOut1 ∧ noteValue vHiOut1 vLoOut1 < MAX_NOTE_BOUND
  hDummy0           : pi.dummy0 = true → noteValue vHiIn0 vLoIn0 = 0
  hDummy1           : pi.dummy1 = true → noteValue vHiIn1 vLoIn1 = 0
  -- 7. Exact integer value conservation (zero Goldilocks modular wraparound)
  hConservation     : noteValue vHiIn0 vLoIn0 + noteValue vHiIn1 vLoIn1
                        - (noteValue vHiOut0 vLoOut0 + noteValue vHiOut1 vLoOut1) = pi.valueBalance

/-- Block-level trace satisfying the exact 128-block layout (`layout_128_blocks_exact`),
    all 249 transition constraints (`all_249_constraints_match_fips180_4_spec` + Section 5/6
    no-wrap/compression soundness), and all boundary assertions (`spend.rs:521-546`). -/
structure AcceptedSpendTrace (pi : SpendPublicStmt) where
  blkMsg    : Nat → Array UInt32
  blkDig    : Nat → Word8
  skReg     : Nat → Word8
  rhoReg    : Nat → Rho5
  posReg    : Nat → Nat
  bitReg    : Nat → Nat
  sibReg    : Nat → Word8
  balReg  : Nat → Int
  vHiIn0  : UInt32
  vLoIn0  : UInt32
  vHiIn1  : UInt32
  vLoIn1  : UInt32
  apkOut0 : Word8
  apkOut1 : Word8
  vHiOut0 : UInt32
  vLoOut0 : UInt32
  vHiOut1 : UInt32
  vLoOut1 : UInt32
  rhoOut0 : Rho5
  rhoOut1 : Rho5
  -- Per-block SHA-256 compression soundness (blocks 1..72, grounded in Constraints #0..#232)
  hCompress : ∀ b, 1 ≤ b → b ≤ 72 → blkDig b = arr8ToWord8 (sha256Compress (blkMsg b))
  -- Inter-block message wiring (Constraints #70..#85, spend.rs:427-461):
  -- Input 0: Block 1 (Addr), Block 2 (CmIn), Blocks 3..34 (Merkle 0..31), Block 35 (Nf)
  hMsgAddr0 : blkMsg 1 = #[UInt32.ofNat TAG_ADDR,
                skReg 1 0, skReg 1 1, skReg 1 2, skReg 1 3, skReg 1 4, skReg 1 5, skReg 1 6, skReg 1 7,
                0, 0, 0, 0, 0, 0, 0]
  hMsgCmIn0 : blkMsg 2 = #[UInt32.ofNat TAG_CM,
                blkDig 1 0, blkDig 1 1, blkDig 1 2, blkDig 1 3, blkDig 1 4, blkDig 1 5, blkDig 1 6, blkDig 1 7,
                vHiIn0, vLoIn0,
                rhoReg 2 0, rhoReg 2 1, rhoReg 2 2, rhoReg 2 3, rhoReg 2 4]
  hMsgMrk0  : ∀ k, k < 32 → blkMsg (3 + k) = merkleMsg (blkDig (2 + k)) (sibReg (3 + k)) (bitReg (3 + k))
  hMsgNf0   : blkMsg 35 = #[UInt32.ofNat TAG_NF,
                skReg 35 0, skReg 35 1, skReg 35 2, skReg 35 3, skReg 35 4, skReg 35 5, skReg 35 6, skReg 35 7,
                UInt32.ofNat (posReg 35),
                rhoReg 35 0, rhoReg 35 1, rhoReg 35 2, rhoReg 35 3, rhoReg 35 4, 0]
  -- Input 1: Block 36 (Addr), Block 37 (CmIn), Blocks 38..69 (Merkle 0..31), Block 70 (Nf)
  hMsgAddr1 : blkMsg 36 = #[UInt32.ofNat TAG_ADDR,
                skReg 36 0, skReg 36 1, skReg 36 2, skReg 36 3, skReg 36 4, skReg 36 5, skReg 36 6, skReg 36 7,
                0, 0, 0, 0, 0, 0, 0]
  hMsgCmIn1 : blkMsg 37 = #[UInt32.ofNat TAG_CM,
                blkDig 36 0, blkDig 36 1, blkDig 36 2, blkDig 36 3, blkDig 36 4, blkDig 36 5, blkDig 36 6, blkDig 36 7,
                vHiIn1, vLoIn1,
                rhoReg 37 0, rhoReg 37 1, rhoReg 37 2, rhoReg 37 3, rhoReg 37 4]
  hMsgMrk1  : ∀ k, k < 32 → blkMsg (38 + k) = merkleMsg (blkDig (37 + k)) (sibReg (38 + k)) (bitReg (38 + k))
  hMsgNf1   : blkMsg 70 = #[UInt32.ofNat TAG_NF,
                skReg 70 0, skReg 70 1, skReg 70 2, skReg 70 3, skReg 70 4, skReg 70 5, skReg 70 6, skReg 70 7,
                UInt32.ofNat (posReg 70),
                rhoReg 70 0, rhoReg 70 1, rhoReg 70 2, rhoReg 70 3, rhoReg 70 4, 0]
  -- Output 0 & 1: Block 71 (CmOut 0), Block 72 (CmOut 1)
  hMsgOut0  : blkMsg 71 = #[UInt32.ofNat TAG_CM,
                apkOut0 0, apkOut0 1, apkOut0 2, apkOut0 3, apkOut0 4, apkOut0 5, apkOut0 6, apkOut0 7,
                vHiOut0, vLoOut0,
                rhoOut0 0, rhoOut0 1, rhoOut0 2, rhoOut0 3, rhoOut0 4]
  hMsgOut1  : blkMsg 72 = #[UInt32.ofNat TAG_CM,
                apkOut1 0, apkOut1 1, apkOut1 2, apkOut1 3, apkOut1 4, apkOut1 5, apkOut1 6, apkOut1 7,
                vHiOut1, vLoOut1,
                rhoOut1 0, rhoOut1 1, rhoOut1 2, rhoOut1 3, rhoOut1 4]
  -- Register persistence & bit booleanity (Constraints #232..#246, spend.rs:487-497)
  hBitBool  : ∀ b, 1 ≤ b → b ≤ 72 → bitReg b = 0 ∨ bitReg b = 1
  hSkConst0 : ∀ b, 1 ≤ b → b < 35 → skReg (b + 1) = skReg b
  hSkConst1 : ∀ b, 36 ≤ b → b < 70 → skReg (b + 1) = skReg b
  hRhoCst0  : ∀ b, 2 ≤ b → b < 35 → rhoReg (b + 1) = rhoReg b
  hRhoCst1  : ∀ b, 37 ≤ b → b < 70 → rhoReg (b + 1) = rhoReg b
  hPos0Init : posReg 2 = 0
  hPos0Step : ∀ k, k < 32 → posReg (3 + k) = posReg (2 + k) + bitReg (3 + k) * 2 ^ k
  hPos0Hold : posReg 35 = posReg 34
  hPos1Init : posReg 37 = 0
  hPos1Step : ∀ k, k < 32 → posReg (38 + k) = posReg (37 + k) + bitReg (38 + k) * 2 ^ k
  hPos1Hold : posReg 70 = posReg 69
  -- Value range constraints (Constraint #248: top 4 bits of high value word are 0 => vHi < 2^28)
  hVHiIn0   : vHiIn0.toNat < 268435456
  hVHiIn1   : vHiIn1.toNat < 268435456
  hVHiOut0  : vHiOut0.toNat < 268435456
  hVHiOut1  : vHiOut1.toNat < 268435456
  -- Balance accumulator constraint (Constraint #247, spend.rs:498-499)
  hBalStep  : ∀ b, 1 ≤ b → b ≤ 72 →
    (balReg (b + 1) - balReg b -
      (if b = 2 then noteValue vHiIn0 vLoIn0
       else if b = 37 then noteValue vHiIn1 vLoIn1
       else if b = 71 then -(noteValue vHiOut0 vLoOut0)
       else if b = 72 then -(noteValue vHiOut1 vLoOut1)
       else 0)) % P = 0
  -- Boundary assertions (spend.rs:521-546):
  hAssertBal0   : balReg 1 = 0
  hAssertBalEnd : (balReg 73 - signedField pi.valueBalance) % P = 0
  hAssertDummy0 : pi.dummy0 = true → vHiIn0 = 0 ∧ vLoIn0 = 0
  hAssertDummy1 : pi.dummy1 = true → vHiIn1 = 0 ∧ vLoIn1 = 0
  hAssertRoot0  : pi.dummy0 = false → blkDig 34 = pi.root
  hAssertRoot1  : pi.dummy1 = false → blkDig 69 = pi.root
  hAssertNf0    : blkDig 35 = pi.nf0
  hAssertNf1    : blkDig 70 = pi.nf1
  hAssertOut0   : blkDig 71 = pi.cmOut0
  hAssertOut1   : blkDig 72 = pi.cmOut1

theorem reg_const_range {{α : Type}} (reg : Nat → α) (a : Nat)
    (hstep : ∀ b, a ≤ b → b < a + n → reg (b + 1) = reg b) :
    ∀ k, k ≤ n → reg (a + k) = reg a := by
  intro k hk
  induction k with
  | zero => simp
  | succ m ih =>
    have hm : a + (m + 1) = (a + m) + 1 := by omega
    rw [hm, hstep (a + m) (by omega) (by omega), ih (by omega)]

theorem merkle_chain_32_sound
    (blkDig : Nat → Word8) (blkMsg : Nat → Array UInt32)
    (bitReg : Nat → Nat) (sibReg : Nat → Word8) (base : Nat)
    (hComp : ∀ k, k < 32 → blkDig (base + 1 + k) = arr8ToWord8 (sha256Compress (blkMsg (base + 1 + k))))
    (hMsg  : ∀ k, k < 32 → blkMsg (base + 1 + k) = merkleMsg (blkDig (base + k)) (sibReg (base + 1 + k)) (bitReg (base + 1 + k))) :
    ∀ k, k ≤ 32 → blkDig (base + k) = merkleRoot (blkDig base) (fun j => bitReg (base + 1 + j)) (fun j => sibReg (base + 1 + j)) k := by
  intro k hk
  induction k with
  | zero => simp [merkleRoot]
  | succ m ih =>
    have hidx : base + (m + 1) = base + 1 + m := by omega
    rw [hidx, hComp m (by omega), hMsg m (by omega)]
    simp only [merkleRoot, merkleStep]
    rw [ih (by omega)]

theorem noteValue_lt_max_bound (vHi vLo : UInt32) (hHi : vHi.toNat < 268435456) :
    0 ≤ noteValue vHi vLo ∧ noteValue vHi vLo < MAX_NOTE_BOUND := by
  have hLo : vLo.toNat < 4294967296 := vLo.toBitVec.isLt
  simp only [noteValue, TWO32, MAX_NOTE_BOUND]
  omega

theorem bal_mod_step_const (bal : Nat → Int) (a : Nat)
    (hstep : ∀ b, a ≤ b → b < a + n → (bal (b + 1) - bal b) % P = 0) :
    ∀ k, k ≤ n → (bal (a + k) - bal a) % P = 0 := by
  intro k hk
  induction k with
  | zero => simp
  | succ m ih =>
    have h1 := hstep (a + m) (by omega) (by omega)
    have h2 := ih (by omega)
    have hd1 := Int.dvd_of_emod_eq_zero h1
    have hd2 := Int.dvd_of_emod_eq_zero h2
    rcases hd1 with ⟨q1, hq1⟩
    rcases hd2 with ⟨q2, hq2⟩
    have hm : a + (m + 1) = (a + m) + 1 := by omega
    rw [hm]
    have hsum : bal ((a + m) + 1) - bal a = P * (q1 + q2) := by
      rw [Int.mul_add]; omega
    rw [hsum]; exact Int.mul_emod_right P (q1 + q2)

theorem goldilocks_balance_no_wrap (v0 v1 v2 v3 vb : Int)
    (h0 : 0 ≤ v0 ∧ v0 < MAX_NOTE_BOUND)
    (h1 : 0 ≤ v1 ∧ v1 < MAX_NOTE_BOUND)
    (h2 : 0 ≤ v2 ∧ v2 < MAX_NOTE_BOUND)
    (h3 : 0 ≤ v3 ∧ v3 < MAX_NOTE_BOUND)
    (hvb : -MAX_VB_BOUND < vb ∧ vb < MAX_VB_BOUND)
    (hmod : ((v0 + v1 - v2 - v3) - signedField vb) % P = 0) :
    v0 + v1 - (v2 + v3) = vb := by
  have hsf : (signedField vb - vb) % P = 0 := by
    have hvb' : -4611686018427387904 < vb ∧ vb < 4611686018427387904 := hvb
    by_cases hpos : vb ≥ 0
    · have h1' : signedField vb = vb := by
        simp only [signedField, hpos, ↓reduceIte, P]
        exact Int.emod_eq_of_lt (by omega) (by omega)
      rw [h1']; simp
    · have h1' : signedField vb = P + vb := by
        simp only [signedField, hpos, ↓reduceIte, P]
        have hm1 : (-vb) % 18446744069414584321 = -vb := Int.emod_eq_of_lt (by omega) (by omega)
        rw [hm1]
        have hm2 : (18446744069414584321 - -vb) = 18446744069414584321 + vb := by omega
        rw [hm2]
        exact Int.emod_eq_of_lt (by omega) (by omega)
      rw [h1']
      have h2' : P + vb - vb = P := by omega
      rw [h2']; exact Int.emod_self
  have hd1 := Int.dvd_of_emod_eq_zero hmod
  have hd2 := Int.dvd_of_emod_eq_zero hsf
  rcases hd1 with ⟨q1, hq1⟩
  rcases hd2 with ⟨q2, hq2⟩
  have hdiff : (v0 + v1 - (v2 + v3)) - vb = P * (q1 + q2) := by
    rw [Int.mul_add]; omega
  have hq0 : q1 + q2 = 0 := by
    simp only [P, MAX_NOTE_BOUND, MAX_VB_BOUND] at *
    omega
  rw [hq0] at hdiff
  omega

/-- Standalone Nullifier Uniqueness Theorem: any two spends referencing the same `(sk, pos, rho)`
    produce identically equal public nullifiers (deterministic binding). -/
theorem nullifier_deterministic_unique (sk : Word8) (pos : UInt32) (rho : Rho5) (nfA nfB : Word8)
    (hA : nfA = noteNullifier sk pos rho) (hB : nfB = noteNullifier sk pos rho) :
    nfA = nfB := by
  rw [hA, hB]

/-- Master End-to-End Semantic Soundness Theorem:
    ANY trace accepted by the 128-block Spend AIR + boundary assertions (`AcceptedSpendTrace pi`)
    witnesses a complete `ValidSpendWitness pi` establishing:
    (1) Spend authorization (`a_pk = H_addr(sk)`),
    (2) Input note commitment binding (`cm_in = H_cm(a_pk, v, rho)`),
    (3) 32-level FIPS SHA-256 Merkle membership against `pi.root` for every non-dummy input,
    (4) Deterministic nullifier binding (`pi.nf = H_nf(sk, pos, rho)`),
    (5) Output commitment binding & `< 2^60` range bounds + dummy zero-value enforcement, and
    (6) Exact integer value conservation (`v_in0 + v_in1 - (v_out0 + v_out1) = pi.valueBalance`)
    with zero Goldilocks modular wraparound. Pure Lean 4 kernel, 0 `sorry`, 0 `native_decide`. -/
theorem accepted_spend_trace_implies_spend_relation (pi : SpendPublicStmt)
    (tr : AcceptedSpendTrace pi) : Nonempty (ValidSpendWitness pi) := by
  -- 1. Register constancy across both 35-block input halves
  have hSk0 : tr.skReg 35 = tr.skReg 1 := by
    have h := reg_const_range tr.skReg 1 (n := 34) (fun b ha hb => tr.hSkConst0 b ha (by omega)) 34 (by omega)
    simpa using h
  have hSk1 : tr.skReg 70 = tr.skReg 36 := by
    have h := reg_const_range tr.skReg 36 (n := 34) (fun b ha hb => tr.hSkConst1 b ha (by omega)) 34 (by omega)
    simpa using h
  have hRho0 : tr.rhoReg 35 = tr.rhoReg 2 := by
    have h := reg_const_range tr.rhoReg 2 (n := 33) (fun b ha hb => tr.hRhoCst0 b ha (by omega)) 33 (by omega)
    simpa using h
  have hRho1 : tr.rhoReg 70 = tr.rhoReg 37 := by
    have h := reg_const_range tr.rhoReg 37 (n := 33) (fun b ha hb => tr.hRhoCst1 b ha (by omega)) 33 (by omega)
    simpa using h
  -- 2. Ownership & input commitment binding
  have hApk0 : tr.blkDig 1 = noteAddress (tr.skReg 1) := by
    rw [tr.hCompress 1 (by omega) (by omega), tr.hMsgAddr0]; rfl
  have hApk1 : tr.blkDig 36 = noteAddress (tr.skReg 36) := by
    rw [tr.hCompress 36 (by omega) (by omega), tr.hMsgAddr1]; rfl
  have hCmIn0 : tr.blkDig 2 = noteCommit (tr.blkDig 1) tr.vHiIn0 tr.vLoIn0 (tr.rhoReg 2) := by
    rw [tr.hCompress 2 (by omega) (by omega), tr.hMsgCmIn0]; rfl
  have hCmIn1 : tr.blkDig 37 = noteCommit (tr.blkDig 36) tr.vHiIn1 tr.vLoIn1 (tr.rhoReg 37) := by
    rw [tr.hCompress 37 (by omega) (by omega), tr.hMsgCmIn1]; rfl
  -- 3. 32-level Merkle membership & exact 32-bit pos accumulator
  have hBits0 : ∀ k, k < 32 → tr.bitReg (3 + k) = 0 ∨ tr.bitReg (3 + k) = 1 :=
    fun k hk => tr.hBitBool (3 + k) (by omega) (by omega)
  have hBits1 : ∀ k, k < 32 → tr.bitReg (38 + k) = 0 ∨ tr.bitReg (38 + k) = 1 :=
    fun k hk => tr.hBitBool (38 + k) (by omega) (by omega)
  have hPosAcc0 := merkle_pos_32_levels_sound
    (fun k => tr.bitReg (3 + k)) (fun k => tr.posReg (2 + k))
    hBits0 tr.hPos0Init (fun k hk => by
      have hm : 2 + (k + 1) = 3 + k := by omega
      rw [hm]; exact tr.hPos0Step k hk) 32 (by omega)
  have hPosAcc1 := merkle_pos_32_levels_sound
    (fun k => tr.bitReg (38 + k)) (fun k => tr.posReg (37 + k))
    hBits1 tr.hPos1Init (fun k hk => by
      have hm : 37 + (k + 1) = 38 + k := by omega
      rw [hm]; exact tr.hPos1Step k hk) 32 (by omega)
  have hPos35 : tr.posReg 35 = posAcc (fun k => tr.bitReg (3 + k)) 32 ∧ tr.posReg 35 < 2 ^ 32 := by
    rw [tr.hPos0Hold]; simpa using hPosAcc0
  have hPos70 : tr.posReg 70 = posAcc (fun k => tr.bitReg (38 + k)) 32 ∧ tr.posReg 70 < 2 ^ 32 := by
    rw [tr.hPos1Hold]; simpa using hPosAcc1
  have hPos0U32 : (UInt32.ofNat (tr.posReg 35)).toNat = posAcc (fun k => tr.bitReg (3 + k)) 32 := by
    have hmod : (UInt32.ofNat (tr.posReg 35)).toNat = tr.posReg 35 % 2 ^ 32 := by
      simp [UInt32.toNat_ofNat']
    rw [hmod, Nat.mod_eq_of_lt hPos35.2, hPos35.1]
  have hPos1U32 : (UInt32.ofNat (tr.posReg 70)).toNat = posAcc (fun k => tr.bitReg (38 + k)) 32 := by
    have hmod : (UInt32.ofNat (tr.posReg 70)).toNat = tr.posReg 70 % 2 ^ 32 := by
      simp [UInt32.toNat_ofNat']
    rw [hmod, Nat.mod_eq_of_lt hPos70.2, hPos70.1]
  have hMrk0 : tr.blkDig 34 = merkleRoot (tr.blkDig 2) (fun j => tr.bitReg (3 + j)) (fun j => tr.sibReg (3 + j)) 32 := by
    have h := merkle_chain_32_sound tr.blkDig tr.blkMsg tr.bitReg tr.sibReg 2
      (fun k hk => tr.hCompress (3 + k) (by omega) (by omega))
      (fun k hk => tr.hMsgMrk0 k hk) 32 (by omega)
    simpa using h
  have hMrk1 : tr.blkDig 69 = merkleRoot (tr.blkDig 37) (fun j => tr.bitReg (38 + j)) (fun j => tr.sibReg (38 + j)) 32 := by
    have h := merkle_chain_32_sound tr.blkDig tr.blkMsg tr.bitReg tr.sibReg 37
      (fun k hk => tr.hCompress (38 + k) (by omega) (by omega))
      (fun k hk => tr.hMsgMrk1 k hk) 32 (by omega)
    simpa using h
  -- 4. Nullifier binding using sk & rho constancy
  have hNf0 : pi.nf0 = noteNullifier (tr.skReg 1) (UInt32.ofNat (tr.posReg 35)) (tr.rhoReg 2) := by
    rw [← tr.hAssertNf0, tr.hCompress 35 (by omega) (by omega), tr.hMsgNf0, hSk0, hRho0]; rfl
  have hNf1 : pi.nf1 = noteNullifier (tr.skReg 36) (UInt32.ofNat (tr.posReg 70)) (tr.rhoReg 37) := by
    rw [← tr.hAssertNf1, tr.hCompress 70 (by omega) (by omega), tr.hMsgNf1, hSk1, hRho1]; rfl
  -- 5. Output commitment binding
  have hOut0 : pi.cmOut0 = noteCommit tr.apkOut0 tr.vHiOut0 tr.vLoOut0 tr.rhoOut0 := by
    rw [← tr.hAssertOut0, tr.hCompress 71 (by omega) (by omega), tr.hMsgOut0]; rfl
  have hOut1 : pi.cmOut1 = noteCommit tr.apkOut1 tr.vHiOut1 tr.vLoOut1 tr.rhoOut1 := by
    rw [← tr.hAssertOut1, tr.hCompress 72 (by omega) (by omega), tr.hMsgOut1]; rfl
  -- 6. Balance telescoping across all 72 blocks + Goldilocks no-wrap conservation
  have hb1 : (tr.balReg 2 - tr.balReg 1) % P = 0 := by simpa using tr.hBalStep 1 (by omega) (by omega)
  have hb2 : (tr.balReg 3 - tr.balReg 2 - noteValue tr.vHiIn0 tr.vLoIn0) % P = 0 := by
    simpa using tr.hBalStep 2 (by omega) (by omega)
  have hb3_37 : (tr.balReg 37 - tr.balReg 3) % P = 0 := by
    have h := bal_mod_step_const tr.balReg 3 (n := 34) (fun b ha hb => by
      have hs := tr.hBalStep b (by omega) (by omega)
      have hne2 : b ≠ 2 := by omega
      have hne37 : b ≠ 37 := by omega
      have hne71 : b ≠ 71 := by omega
      have hne72 : b ≠ 72 := by omega
      simp [hne2, hne37, hne71, hne72] at hs
      exact hs) 34 (by omega)
    simpa using h
  have hb37 : (tr.balReg 38 - tr.balReg 37 - noteValue tr.vHiIn1 tr.vLoIn1) % P = 0 := by
    simpa using tr.hBalStep 37 (by omega) (by omega)
  have hb38_71 : (tr.balReg 71 - tr.balReg 38) % P = 0 := by
    have h := bal_mod_step_const tr.balReg 38 (n := 33) (fun b ha hb => by
      have hs := tr.hBalStep b (by omega) (by omega)
      have hne2 : b ≠ 2 := by omega
      have hne37 : b ≠ 37 := by omega
      have hne71 : b ≠ 71 := by omega
      have hne72 : b ≠ 72 := by omega
      simp [hne2, hne37, hne71, hne72] at hs
      exact hs) 33 (by omega)
    simpa using h
  have hb71 : (tr.balReg 72 - tr.balReg 71 + noteValue tr.vHiOut0 tr.vLoOut0) % P = 0 := by
    have hs := tr.hBalStep 71 (by omega) (by omega)
    have heq : tr.balReg 72 - tr.balReg 71 + noteValue tr.vHiOut0 tr.vLoOut0 =
        tr.balReg 72 - tr.balReg 71 - -noteValue tr.vHiOut0 tr.vLoOut0 := by omega
    rw [heq]; simpa using hs
  have hb72 : (tr.balReg 73 - tr.balReg 72 + noteValue tr.vHiOut1 tr.vLoOut1) % P = 0 := by
    have hs := tr.hBalStep 72 (by omega) (by omega)
    have heq : tr.balReg 73 - tr.balReg 72 + noteValue tr.vHiOut1 tr.vLoOut1 =
        tr.balReg 73 - tr.balReg 72 - -noteValue tr.vHiOut1 tr.vLoOut1 := by omega
    rw [heq]; simpa using hs
  have hBalMod : ((noteValue tr.vHiIn0 tr.vLoIn0 + noteValue tr.vHiIn1 tr.vLoIn1
      - noteValue tr.vHiOut0 tr.vLoOut0 - noteValue tr.vHiOut1 tr.vLoOut1) - signedField pi.valueBalance) % P = 0 := by
    rcases Int.dvd_of_emod_eq_zero hb1 with ⟨q1, hq1⟩
    rcases Int.dvd_of_emod_eq_zero hb2 with ⟨q2, hq2⟩
    rcases Int.dvd_of_emod_eq_zero hb3_37 with ⟨q3, hq3⟩
    rcases Int.dvd_of_emod_eq_zero hb37 with ⟨q4, hq4⟩
    rcases Int.dvd_of_emod_eq_zero hb38_71 with ⟨q5, hq5⟩
    rcases Int.dvd_of_emod_eq_zero hb71 with ⟨q6, hq6⟩
    rcases Int.dvd_of_emod_eq_zero hb72 with ⟨q7, hq7⟩
    rcases Int.dvd_of_emod_eq_zero tr.hAssertBalEnd with ⟨q8, hq8⟩
    have h0 := tr.hAssertBal0
    have hcomb : (noteValue tr.vHiIn0 tr.vLoIn0 + noteValue tr.vHiIn1 tr.vLoIn1
        - noteValue tr.vHiOut0 tr.vLoOut0 - noteValue tr.vHiOut1 tr.vLoOut1) - signedField pi.valueBalance
        = P * (q8 - q1 - q2 - q3 - q4 - q5 - q6 - q7) := by
      have : P * (q8 - q1 - q2 - q3 - q4 - q5 - q6 - q7) =
          P * q8 - P * q1 - P * q2 - P * q3 - P * q4 - P * q5 - P * q6 - P * q7 := by
        repeat rw [Int.mul_sub]
      rw [this]; omega
    rw [hcomb]; exact Int.mul_emod_right P _
  have hR0 := noteValue_lt_max_bound tr.vHiIn0 tr.vLoIn0 tr.hVHiIn0
  have hR1 := noteValue_lt_max_bound tr.vHiIn1 tr.vLoIn1 tr.hVHiIn1
  have hR2 := noteValue_lt_max_bound tr.vHiOut0 tr.vLoOut0 tr.hVHiOut0
  have hR3 := noteValue_lt_max_bound tr.vHiOut1 tr.vLoOut1 tr.hVHiOut1
  have hCons := goldilocks_balance_no_wrap
    (noteValue tr.vHiIn0 tr.vLoIn0) (noteValue tr.vHiIn1 tr.vLoIn1)
    (noteValue tr.vHiOut0 tr.vLoOut0) (noteValue tr.vHiOut1 tr.vLoOut1)
    pi.valueBalance hR0 hR1 hR2 hR3 pi.hvb hBalMod
  exact ⟨{{
    sk0 := tr.skReg 1
    sk1 := tr.skReg 36
    apk0 := tr.blkDig 1
    apk1 := tr.blkDig 36
    vHiIn0 := tr.vHiIn0, vLoIn0 := tr.vLoIn0
    vHiIn1 := tr.vHiIn1, vLoIn1 := tr.vLoIn1
    rho0 := tr.rhoReg 2, rho1 := tr.rhoReg 37
    cmIn0 := tr.blkDig 2, cmIn1 := tr.blkDig 37
    bits0 := fun j => tr.bitReg (3 + j)
    bits1 := fun j => tr.bitReg (38 + j)
    sibs0 := fun j => tr.sibReg (3 + j)
    sibs1 := fun j => tr.sibReg (38 + j)
    pos0 := UInt32.ofNat (tr.posReg 35)
    pos1 := UInt32.ofNat (tr.posReg 70)
    apkOut0 := tr.apkOut0, apkOut1 := tr.apkOut1
    vHiOut0 := tr.vHiOut0, vLoOut0 := tr.vLoOut0
    vHiOut1 := tr.vHiOut1, vLoOut1 := tr.vLoOut1
    rhoOut0 := tr.rhoOut0, rhoOut1 := tr.rhoOut1
    hOwner0 := hApk0
    hOwner1 := hApk1
    hCmIn0 := hCmIn0
    hCmIn1 := hCmIn1
    hBits0 := hBits0
    hBits1 := hBits1
    hPos0 := hPos0U32
    hPos1 := hPos1U32
    hMerkle0 := fun h => by rw [← hMrk0, tr.hAssertRoot0 h]
    hMerkle1 := fun h => by rw [← hMrk1, tr.hAssertRoot1 h]
    hNf0 := hNf0
    hNf1 := hNf1
    hCmOut0 := hOut0
    hCmOut1 := hOut1
    hRangeIn0 := hR0
    hRangeIn1 := hR1
    hRangeOut0 := hR2
    hRangeOut1 := hR3
    hDummy0 := fun h => by rcases tr.hAssertDummy0 h with ⟨h1', h2'⟩; simp [noteValue, h1', h2']
    hDummy1 := fun h => by rcases tr.hAssertDummy1 h with ⟨h1', h2'⟩; simp [noteValue, h1', h2']
    hConservation := hCons
  }}⟩


"#,
        modulus = Felt::MODULUS,
        width = WIDTH,
        total_terms = total_terms,
        extracted_defs = extracted_defs,
        rust_dispatch = rust_dispatch,
        con_proofs = con_proofs,
        layout_str = layout_codes.join(","),
        assert_real_str = assert_real_str,
        assert_dummy_str = assert_dummy_str,
    );

    lean_src.push_str(r####"
-- ============================================================================
-- SECTION 7B: GOLDILOCKS POCKLINGTON PRIMALITY, SPARSE POLY EVALUATION
--             HOMOMORPHISMS, BITWISE LEMMAS & FREE W_0 CANONICALIZATION
-- ============================================================================

-- VERIFIED PRIMITIVES
def modPowAux (base m : Nat) : Nat → Nat → Nat → Nat
  | 0, _, acc => acc % m
  | fuel + 1, exp, acc =>
    if exp = 0 then acc % m
    else
      let acc' := if exp % 2 = 1 then (acc * base) % m else acc
      modPowAux ((base * base) % m) m fuel (exp / 2) acc'

def modPow (base exp m : Nat) : Nat :=
  modPowAux (base % m) m 65 exp 1

theorem modPowAux_eq (m : Nat) (fuel : Nat) :
    ∀ base exp acc, exp < 2 ^ fuel →
      modPowAux base m fuel exp acc = (acc * base ^ exp) % m := by
  induction fuel with
  | zero =>
    intro base exp acc hexp
    have he0 : exp = 0 := by omega
    subst he0
    simp [modPowAux]
  | succ k ih =>
    intro base exp acc hexp
    simp only [modPowAux]
    by_cases h0 : exp = 0
    · simp [h0]
    · simp only [h0, ↓reduceIte]
      have hdiv : exp / 2 < 2 ^ k := by
        rw [Nat.pow_succ] at hexp
        omega
      rw [ih ((base * base) % m) (exp / 2) _ hdiv]
      have hpow_mod : ((base * base) % m) ^ (exp / 2) % m = (base * base) ^ (exp / 2) % m := by
        induction (exp / 2) with
        | zero => simp
        | succ n ihn =>
          rw [Nat.pow_succ, Nat.pow_succ, Nat.mul_mod, ihn, ← Nat.mul_mod]
          rw [Nat.mul_mod ((base * base) ^ n), Nat.mod_mod, ← Nat.mul_mod]
      have hsq : (base * base) ^ (exp / 2) = base ^ (2 * (exp / 2)) := by
        rw [← Nat.pow_two, ← Nat.pow_mul]
      by_cases hodd : exp % 2 = 1
      · simp only [hodd, ↓reduceIte]
        rw [Nat.mul_mod, Nat.mod_mod, hpow_mod, hsq, ← Nat.mul_mod]
        have he : exp = 2 * (exp / 2) + 1 := by omega
        have hpow : base ^ exp = base ^ (2 * (exp / 2)) * base := by
          rw [← Nat.pow_succ]; exact congrArg (base ^ ·) he
        rw [hpow, Nat.mul_assoc, Nat.mul_comm base (base ^ (2 * (exp / 2)))]
      · simp only [hodd, ↓reduceIte]
        rw [Nat.mul_mod, hpow_mod, hsq, ← Nat.mul_mod]
        have he : exp = 2 * (exp / 2) := by omega
        have hpow : base ^ exp = base ^ (2 * (exp / 2)) := congrArg (base ^ ·) he
        rw [hpow]

theorem modPow_eq (base exp m : Nat) (hexp : exp < 2 ^ 65) :
    modPow base exp m = (base ^ exp) % m := by
  unfold modPow
  rw [modPowAux_eq m 65 (base % m) exp 1 hexp, Nat.one_mul]
  clear hexp
  induction exp with
  | zero => simp
  | succ n ih =>
    rw [Nat.pow_succ, Nat.pow_succ, Nat.mul_mod, ih, Nat.mod_mod, ← Nat.mul_mod]

theorem pock_full : modPow 7 (P_NAT - 1) P_NAT = 1 := by decide
theorem pock_val2_pos : 1 ≤ modPow 7 ((P_NAT - 1) / 2) P_NAT := by decide
theorem pock_gcd2 : Nat.gcd (modPow 7 ((P_NAT - 1) / 2) P_NAT - 1) P_NAT = 1 := by decide
theorem pock_val3_pos : 1 ≤ modPow 7 ((P_NAT - 1) / 3) P_NAT := by decide
theorem pock_gcd3 : Nat.gcd (modPow 7 ((P_NAT - 1) / 3) P_NAT - 1) P_NAT = 1 := by decide

def isPrime (p : Nat) : Prop :=
  1 < p ∧ ∀ d, d ∣ p → d = 1 ∨ d = p

theorem dvd_prime_mul {p a b : Nat} (hp : isPrime p) (h : p ∣ a * b) : p ∣ a ∨ p ∣ b := by
  by_cases ha : p ∣ a
  · exact Or.inl ha
  · right
    have hg : Nat.gcd p a = 1 := by
      rcases hp.2 (Nat.gcd p a) (Nat.gcd_dvd_left p a) with h1 | hp'
      · exact h1
      · exfalso; apply ha; rw [← hp']; exact Nat.gcd_dvd_right p a
    exact Nat.Coprime.dvd_of_dvd_mul_left hg h

def fact : Nat → Nat
  | 0 => 1
  | n + 1 => (n + 1) * fact n

def binom : Nat → Nat → Nat
  | _, 0 => 1
  | 0, _ + 1 => 0
  | n + 1, k + 1 => binom n k + binom n (k + 1)

theorem binom_self (n : Nat) : binom n n = 1 := by
  induction n with
  | zero => rfl
  | succ k ih =>
    have hgt : ∀ m r, m < r → binom m r = 0 := by
      intro m
      induction m with
      | zero => intro r hr; cases r with | zero => omega | succ _ => rfl
      | succ m ihm =>
        intro r hr
        cases r with
        | zero => omega
        | succ r => simp [binom, ihm r (by omega), ihm (r + 1) (by omega)]
    simp [binom, ih, hgt k (k + 1) (by omega)]

theorem binom_mul_fact (n k : Nat) (hk : k ≤ n) :
    binom n k * (fact k * fact (n - k)) = fact n := by
  induction n generalizing k with
  | zero =>
    have hk0 : k = 0 := by omega
    subst hk0; simp [binom, fact]
  | succ m ih =>
    cases k with
    | zero => simp [binom, fact]
    | succ j =>
      by_cases hjm : j = m
      · subst hjm; simp [binom_self, fact]
      · have h1 := ih j (by omega)
        have h2 := ih (j + 1) (by omega)
        simp only [binom]
        have hsub1 : m - j = (m - (j + 1)) + 1 := by omega
        have hsub2 : m + 1 - (j + 1) = m - j := by omega
        rw [hsub2]
        have hf1 : fact (j + 1) = (j + 1) * fact j := rfl
        have hf2 : fact (m - j) = (m - j) * fact (m - (j + 1)) := by rw [hsub1]; rfl
        have hfm : fact (m + 1) = (m + 1) * fact m := rfl
        have lhs1 : binom m j * (fact (j + 1) * fact (m - j)) = (j + 1) * fact m := by
          rw [hf1, ← h1, Nat.mul_assoc (j + 1), Nat.mul_left_comm (binom m j)]
        have lhs2 : binom m (j + 1) * (fact (j + 1) * fact (m - j)) = (m - j) * fact m := by
          rw [hf2, ← h2, Nat.mul_left_comm (fact (j + 1)), Nat.mul_left_comm (binom m (j + 1))]
        rw [Nat.add_mul, lhs1, lhs2, ← Nat.add_mul, hfm]
        have hjm' : j + 1 + (m - j) = m + 1 := by omega
        rw [hjm']

theorem prime_not_dvd_fact {p n : Nat} (hp : isPrime p) (hn : n < p) : ¬ (p ∣ fact n) := by
  induction n with
  | zero =>
    simp only [fact]
    intro h; have := Nat.le_of_dvd (by decide) h; have := hp.1; omega
  | succ k ih =>
    intro h
    have hmul : fact (k + 1) = (k + 1) * fact k := rfl
    rw [hmul] at h
    rcases dvd_prime_mul hp h with h1 | h2
    · have := Nat.le_of_dvd (by omega) h1; omega
    · exact ih (by omega) h2

theorem prime_dvd_binom {p k : Nat} (hp : isPrime p) (hk0 : 0 < k) (hkp : k < p) :
    p ∣ binom p k := by
  have heq := binom_mul_fact p k (by omega)
  have hdvd : p ∣ fact p := by
    cases p with
    | zero => have := hp.1; omega
    | succ m => exact Nat.dvd_mul_right (m + 1) (fact m)
  rw [← heq] at hdvd
  rcases dvd_prime_mul hp hdvd with h1 | h2
  · exact h1
  · exfalso
    rcases dvd_prime_mul hp h2 with h3 | h4
    · exact prime_not_dvd_fact hp hkp h3
    · exact prime_not_dvd_fact hp (by omega) h4

def binomSum (x n : Nat) : Nat → Nat
  | 0 => binom n 0 * x ^ 0
  | k + 1 => binomSum x n k + binom n (k + 1) * x ^ (k + 1)

theorem binomSum_succ (x n : Nat) :
    ∀ k, k ≤ n →
      binomSum x (n + 1) k = binomSum x n k + (if k = 0 then 0 else binomSum x n (k - 1) * x) := by
  intro k hk
  induction k with
  | zero => simp [binomSum, binom]
  | succ j ih =>
    simp only [binomSum, Nat.succ_ne_zero, ↓reduceIte, Nat.add_sub_cancel]
    rw [ih (by omega)]
    by_cases hj : j = 0
    · subst hj
      simp only [↓reduceIte, Nat.add_zero, binomSum, binom, Nat.pow_zero, Nat.pow_succ, Nat.mul_one, Nat.one_mul]
      rw [Nat.add_mul]
      omega
    · simp only [hj, ↓reduceIte]
      have hj1 : j = (j - 1) + 1 := by omega
      have hsplit : binomSum x n j = binomSum x n (j - 1) + binom n j * x ^ j := by
        rw [hj1, binomSum, ← hj1]
      rw [hsplit, Nat.add_mul]
      simp only [binom, Nat.add_mul, Nat.pow_succ]
      have hterm : binom n j * (x ^ j * x) = binom n j * x ^ j * x := by rw [Nat.mul_assoc]
      rw [hterm]
      omega

theorem add_one_pow_eq_binomSum (x n : Nat) : (x + 1) ^ n = binomSum x n n := by
  induction n with
  | zero => simp [binomSum, binom]
  | succ m ih =>
    rw [Nat.pow_succ, ih, Nat.mul_add, Nat.mul_one]
    have h1 := binomSum_succ x m m (by omega)
    simp only [binomSum]
    rw [h1]
    by_cases hm : m = 0
    · subst hm; simp [binomSum, binom]; omega
    · simp only [hm, ↓reduceIte]
      have hm1 : m = (m - 1) + 1 := by omega
      have hlast : binomSum x m m = binomSum x m (m - 1) + binom m m * x ^ m := by
        rw [hm1, binomSum, ← hm1]
      rw [hlast, Nat.add_mul, binom_self, binom_self, Nat.one_mul, Nat.one_mul, Nat.pow_succ]
      omega

theorem prime_dvd_mid_binomSum {p : Nat} (hp : isPrime p) (x : Nat) :
    ∀ k, k < p → (binomSum x p k) % p = 1 % p := by
  intro k hk
  induction k with
  | zero => simp [binomSum, binom]
  | succ j ih =>
    simp only [binomSum]
    have hd : p ∣ binom p (j + 1) := prime_dvd_binom hp (by omega) hk
    rcases hd with ⟨q, hq⟩
    rw [Nat.add_mod, ih (by omega), hq, Nat.mul_assoc, Nat.mul_mod_right, Nat.add_zero, Nat.mod_mod]

theorem freshman_dream {p : Nat} (hp : isPrime p) (x : Nat) :
    (x + 1) ^ p % p = (x ^ p + 1) % p := by
  rw [add_one_pow_eq_binomSum]
  have hp0 : p = (p - 1) + 1 := by have := hp.1; omega
  have hsplit : binomSum x p p = binomSum x p (p - 1) + binom p p * x ^ p := by
    rw [hp0, binomSum, ← hp0]
  rw [hsplit, Nat.add_mod, prime_dvd_mid_binomSum hp x (p - 1) (by have := hp.1; omega), binom_self, Nat.one_mul]
  rw [Nat.add_comm, ← Nat.add_mod]

theorem fermat_little_pow {p : Nat} (hp : isPrime p) (a : Nat) : a ^ p % p = a % p := by
  induction a with
  | zero =>
    have hp0 : p > 0 := by have := hp.1; omega
    rw [Nat.zero_pow hp0]
  | succ x ih =>
    rw [freshman_dream hp x, Nat.add_mod, ih, ← Nat.add_mod]

theorem fermat_little {p a : Nat} (hp : isPrime p) (ha : ¬ (p ∣ a)) :
    a ^ (p - 1) % p = 1 := by
  have h1 := fermat_little_pow hp a
  have hp1 : p = (p - 1) + 1 := by have := hp.1; omega
  have hpow : a ^ p = a ^ (p - 1) * a := by
    rw [← Nat.pow_succ]; exact congrArg (a ^ ·) hp1
  rw [hpow] at h1
  have ha0 : a ≥ 1 := by
    cases a with
    | zero => exfalso; exact ha (Nat.dvd_zero p)
    | succ _ => omega
  have hge : a ^ (p - 1) ≥ 1 := Nat.one_le_pow (p - 1) a ha0
  have hdvd : p ∣ (a ^ (p - 1) - 1) * a := by
    rw [Nat.sub_mul, Nat.one_mul]
    exact Nat.dvd_of_mod_eq_zero (Nat.sub_mod_eq_zero_of_mod_eq h1)
  rcases dvd_prime_mul hp hdvd with hpow' | ha'
  · rcases hpow' with ⟨q, hq⟩
    have hp_gt : 1 < p := hp.1
    have : a ^ (p - 1) = p * q + 1 := by omega
    rw [this, Nat.mul_add_mod, Nat.mod_eq_of_lt hp_gt]
  · exact absurd ha' ha

theorem exists_prime_dvd (n : Nat) (hn : 1 < n) : ∃ p, isPrime p ∧ p ∣ n := by
  induction n using Nat.strongRecOn with
  | ind m ih =>
    by_cases hprim : ∀ d, d ∣ m → d = 1 ∨ d = m
    · exact ⟨m, ⟨hn, hprim⟩, Nat.dvd_refl m⟩
    · have hex : ∃ d, d ∣ m ∧ d ≠ 1 ∧ d ≠ m :=
        Classical.byContradiction fun hno => hprim fun d hd =>
          Classical.byContradiction fun hne => hno ⟨d, hd, fun h1 => hne (Or.inl h1), fun hm => hne (Or.inr hm)⟩
      rcases hex with ⟨d, hd, hd1, hdm⟩
      have hd_pos : 0 < d := Nat.pos_of_dvd_of_pos hd (by omega)
      have hd_lt : d < m := Nat.lt_of_le_of_ne (Nat.le_of_dvd (by omega) hd) hdm
      rcases ih d hd_lt (by omega) with ⟨p, hp, hpd⟩
      exact ⟨p, hp, Nat.dvd_trans hpd hd⟩

theorem pow_mod_eq_one_sub {a m e f : Nat} (hfe : f ≤ e)
    (he : a ^ e % m = 1) (hf : a ^ f % m = 1) :
    a ^ (e - f) % m = 1 := by
  have heq : a ^ e = a ^ f * a ^ (e - f) := by
    rw [← Nat.pow_add, Nat.add_sub_cancel' hfe]
  rw [heq] at he
  have h1 : (a ^ f % m * (a ^ (e - f) % m)) % m = 1 := by
    rw [← Nat.mul_mod]; exact he
  rw [hf, Nat.one_mul, Nat.mod_mod] at h1
  exact h1

theorem pow_mod_eq_one_mul {a m e k : Nat} (hm : 1 < m) (he : a ^ e % m = 1) :
    a ^ (e * k) % m = 1 := by
  induction k with
  | zero => simp [Nat.mod_eq_of_lt hm]
  | succ n ih =>
    rw [Nat.mul_succ, Nat.pow_add, Nat.mul_mod, ih, he, Nat.one_mul, Nat.mod_eq_of_lt hm]

theorem pow_mod_eq_one_gcd {a m : Nat} (hm : 1 < m) :
    ∀ e f, a ^ e % m = 1 → a ^ f % m = 1 → a ^ (Nat.gcd e f) % m = 1 := by
  intro e
  induction e using Nat.strongRecOn with
  | ind e ih =>
    intro f he hf
    by_cases he0 : e = 0
    · subst he0; simpa using hf
    · rw [Nat.gcd_rec]
      have hmod : a ^ (f % e) % m = 1 := by
        have hdiv : f = e * (f / e) + f % e := (Nat.div_add_mod f e).symm
        have hpow_mul : a ^ (e * (f / e)) % m = 1 := pow_mod_eq_one_mul hm he
        have hle : e * (f / e) ≤ f := by omega
        have hsub : f - e * (f / e) = f % e := by omega
        rw [← hsub]
        exact pow_mod_eq_one_sub hle hf hpow_mul
      exact ih (f % e) (Nat.mod_lt f (by omega)) e hmod he

theorem mod_of_dvd_mod {x p M : Nat} (hpM : p ∣ M) : (x % M) % p = x % p := by
  rcases hpM with ⟨k, hk⟩
  have h1 : x = M * (x / M) + x % M := (Nat.div_add_mod x M).symm
  have h2 : x % p = (p * (k * (x / M)) + x % M) % p := by
    have : p * (k * (x / M)) + x % M = x := by rw [← Nat.mul_assoc, ← hk, ← h1]
    rw [this]
  rw [h2, Nat.mul_add_mod]

theorem prime_pow_coprime_dvd {p k g q : Nat} (hp : isPrime p) (hnd : ¬ (p ∣ q))
    (h : p ^ k ∣ g * q) : p ^ k ∣ g := by
  induction k generalizing g with
  | zero => simp
  | succ m ih =>
    rw [Nat.pow_succ] at h
    have hp_dvd_gq : p ∣ g * q := Nat.dvd_trans (Nat.dvd_mul_left p (p ^ m)) h
    rcases dvd_prime_mul hp hp_dvd_gq with hpg | hpq
    · rcases hpg with ⟨g', hg'⟩
      have hp0 : 0 < p := by have := hp.1; omega
      have h' : p ^ m ∣ g' * q := by
        rcases h with ⟨t, ht⟩
        refine ⟨t, ?_⟩
        have hmul : (g' * q) * p = (p ^ m * t) * p := by
          have h1 : g' * q * p = g * q := by
            rw [hg', Nat.mul_assoc, Nat.mul_comm q p, ← Nat.mul_assoc, Nat.mul_comm g' p]
          rw [h1, ht, Nat.mul_right_comm]
        exact Nat.eq_of_mul_eq_mul_right hp0 hmul
      rcases ih h' with ⟨s, hs⟩
      refine ⟨s, ?_⟩
      rw [hg', hs, Nat.pow_succ, Nat.mul_left_comm, ← Nat.mul_assoc]
    · exact absurd hpq hnd

theorem isPrime_2 : isPrime 2 := ⟨by decide, fun d hd => by
  have hle := Nat.le_of_dvd (by decide) hd
  have hpos := Nat.pos_of_dvd_of_pos hd (by decide)
  omega⟩

theorem isPrime_3 : isPrime 3 := ⟨by decide, fun d hd => by
  have hle := Nat.le_of_dvd (by decide) hd
  have hpos := Nat.pos_of_dvd_of_pos hd (by decide)
  have hmod := Nat.mod_eq_zero_of_dvd hd
  have hcases : d = 1 ∨ d = 2 ∨ d = 3 := by omega
  rcases hcases with rfl | rfl | rfl
  · exact Or.inl rfl
  · simp at hmod
  · exact Or.inr rfl⟩

theorem goldilocks_is_prime : isPrime P_NAT := by
  refine ⟨by decide, fun d hd => ?_⟩
  by_cases hd1 : d = 1
  · exact Or.inl hd1
  · by_cases hdp : d = P_NAT
    · exact Or.inr hdp
    · exfalso
      rcases hd with ⟨q, hq⟩
      have hd_pos : 0 < d := by
        cases d with | zero => simp [P_NAT] at hq | succ _ => omega
      have hq_gt : 1 < q := by
        cases q with
        | zero => simp [P_NAT] at hq
        | succ q' =>
          cases q' with
          | zero => simp at hq; omega
          | succ _ => omega
      have hm_ex : ∃ m, 1 < m ∧ m ∣ P_NAT ∧ m * m ≤ P_NAT := by
        by_cases hle : d ≤ q
        · exact ⟨d, by omega, ⟨q, hq⟩, by rw [hq]; exact Nat.mul_le_mul_left d hle⟩
        · exact ⟨q, hq_gt, ⟨d, by rw [Nat.mul_comm]; exact hq⟩, by rw [hq]; exact Nat.mul_le_mul_right q (by omega)⟩
      rcases hm_ex with ⟨m, hm1, hmP, hmm⟩
      rcases exists_prime_dvd m hm1 with ⟨p, hp, hpm⟩
      have hpP : p ∣ P_NAT := Nat.dvd_trans hpm hmP
      have hp_le_m : p ≤ m := Nat.le_of_dvd (by omega) hpm
      have hpp : p * p ≤ P_NAT := Nat.le_trans (Nat.mul_le_mul hp_le_m hp_le_m) hmm
      have h7_ndvd : ¬ (p ∣ 7) := by
        intro h7
        have hle := Nat.le_of_dvd (by decide) h7
        have hp_eq : p = 7 := by
          have : ∀ x, x ≤ 7 → 1 < x → 7 % x = 0 → x = 7 := by decide
          exact this p hle hp.1 (Nat.mod_eq_zero_of_dvd h7)
        subst hp_eq
        exact absurd hpP (by decide)
      have hflt : 7 ^ (p - 1) % p = 1 := fermat_little hp h7_ndvd
      have hfullP : 7 ^ (P_NAT - 1) % P_NAT = 1 := by
        have h := pock_full
        rw [modPow_eq 7 (P_NAT - 1) P_NAT (by decide)] at h
        exact h
      have hfullp : 7 ^ (P_NAT - 1) % p = 1 := by
        rw [← mod_of_dvd_mod hpP, hfullP, Nat.mod_eq_of_lt hp.1]
      have hnot_half : ∀ f, f = 2 ∨ f = 3 → 7 ^ ((P_NAT - 1) / f) % p ≠ 1 := by
        intro f hf h1
        have hgcd : Nat.gcd (7 ^ ((P_NAT - 1) / f) % P_NAT - 1) P_NAT = 1 := by
          rcases hf with rfl | rfl
          · have h := pock_gcd2; rwa [modPow_eq 7 ((P_NAT - 1) / 2) P_NAT (by decide)] at h
          · have h := pock_gcd3; rwa [modPow_eq 7 ((P_NAT - 1) / 3) P_NAT (by decide)] at h
        have hmodp : (7 ^ ((P_NAT - 1) / f) % P_NAT) % p = 1 := by
          rw [mod_of_dvd_mod hpP]; exact h1
        have hpdvd : p ∣ (7 ^ ((P_NAT - 1) / f) % P_NAT - 1) := by
          have heq1 : (7 ^ ((P_NAT - 1) / f) % P_NAT) % p = 1 % p := by
            rw [hmodp, Nat.mod_eq_of_lt hp.1]
          exact Nat.dvd_of_mod_eq_zero (Nat.sub_mod_eq_zero_of_mod_eq heq1)
        have hpg : p ∣ Nat.gcd (7 ^ ((P_NAT - 1) / f) % P_NAT - 1) P_NAT := Nat.dvd_gcd hpdvd hpP
        rw [hgcd] at hpg
        have := Nat.le_of_dvd (by decide) hpg
        have := hp.1
        omega
      let g := Nat.gcd (p - 1) (P_NAT - 1)
      have h7g : 7 ^ g % p = 1 := pow_mod_eq_one_gcd hp.1 (p - 1) (P_NAT - 1) hflt hfullp
      rcases Nat.gcd_dvd_right (p - 1) (P_NAT - 1) with ⟨r, hr⟩
      have hnd2 : ¬ (2 ∣ r) := by
        intro h2r
        rcases h2r with ⟨t, ht⟩
        have heq : (P_NAT - 1) / 2 = g * t := by
          have hmul : 2 * ((P_NAT - 1) / 2) = 2 * (g * t) := by
            have hdiv2 : 2 * ((P_NAT - 1) / 2) = P_NAT - 1 := by decide
            rw [hdiv2, hr, ht, Nat.mul_left_comm]
          exact Nat.eq_of_mul_eq_mul_left (by decide) hmul
        exact hnot_half 2 (Or.inl rfl) (by rw [heq]; exact pow_mod_eq_one_mul hp.1 h7g)
      have hnd3 : ¬ (3 ∣ r) := by
        intro h3r
        rcases h3r with ⟨t, ht⟩
        have heq : (P_NAT - 1) / 3 = g * t := by
          have hmul : 3 * ((P_NAT - 1) / 3) = 3 * (g * t) := by
            have hdiv3 : 3 * ((P_NAT - 1) / 3) = P_NAT - 1 := by decide
            rw [hdiv3, hr, ht, Nat.mul_left_comm]
          exact Nat.eq_of_mul_eq_mul_left (by decide) hmul
        exact hnot_half 3 (Or.inr rfl) (by rw [heq]; exact pow_mod_eq_one_mul hp.1 h7g)
      have h232_dvd : 2 ^ 32 ∣ g := by
        have hdiv : 2 ^ 32 ∣ g * r := by rw [← hr]; decide
        exact prime_pow_coprime_dvd isPrime_2 hnd2 hdiv
      have h3_dvd : 3 ∣ g := by
        have hdiv : 3 ^ 1 ∣ g * r := by rw [← hr]; decide
        simpa using prime_pow_coprime_dvd isPrime_3 hnd3 hdiv
      have hF_dvd : 2 ^ 32 * 3 ∣ g := by
        have hcop : Nat.Coprime (2 ^ 32) 3 := by decide
        exact hcop.mul_dvd_of_dvd_of_dvd h232_dvd h3_dvd
      have hF_dvd_pm1 : 2 ^ 32 * 3 ∣ p - 1 := Nat.dvd_trans hF_dvd (Nat.gcd_dvd_left (p - 1) (P_NAT - 1))
      have hp_ge : 2 ^ 32 * 3 + 1 ≤ p := by
        have hpm1_pos : 0 < p - 1 := by have := hp.1; omega
        have hle := Nat.le_of_dvd hpm1_pos hF_dvd_pm1
        omega
      have hsq_gt : P_NAT < (2 ^ 32 * 3 + 1) * (2 ^ 32 * 3 + 1) := by decide
      have hsq_le : (2 ^ 32 * 3 + 1) * (2 ^ 32 * 3 + 1) ≤ p * p := Nat.mul_le_mul hp_ge hp_ge
      omega

theorem goldilocks_mul_eq_zero_mod_P {a b : Int}
    (h : (a * b) % P = 0) : a % P = 0 ∨ b % P = 0 := by
  have h1 : ((a % P) * (b % P)) % P = 0 := by
    rw [← Int.mul_emod]; exact h
  have ha0 : 0 ≤ a % P := Int.emod_nonneg a (by decide)
  have hb0 : 0 ≤ b % P := Int.emod_nonneg b (by decide)
  have hPnat : (P_NAT : Int) = P := rfl
  have hdvdNat : P_NAT ∣ (a % P).toNat * (b % P).toNat := by
    have hmul_eq : (((a % P).toNat * (b % P).toNat : Nat) : Int) = (a % P) * (b % P) := by
      rw [Int.natCast_mul, Int.toNat_of_nonneg ha0, Int.toNat_of_nonneg hb0]
    have hmod_nat : ((((a % P).toNat * (b % P).toNat) % P_NAT : Nat) : Int) = 0 := by
      rw [Int.natCast_emod, hmul_eq, hPnat]; exact h1
    have : ((a % P).toNat * (b % P).toNat) % P_NAT = 0 := Int.ofNat.inj hmod_nat
    exact Nat.dvd_of_mod_eq_zero this
  rcases dvd_prime_mul goldilocks_is_prime hdvdNat with ha | hb
  · left
    have hmod0 : (a % P).toNat % P_NAT = 0 := Nat.mod_eq_zero_of_dvd ha
    have hlt : (a % P).toNat < P_NAT := by
      have := Int.emod_lt_of_pos a (by decide : (0 : Int) < P)
      simp only [P, P_NAT] at *; omega
    rw [Nat.mod_eq_of_lt hlt] at hmod0
    omega
  · right
    have hmod0 : (b % P).toNat % P_NAT = 0 := Nat.mod_eq_zero_of_dvd hb
    have hlt : (b % P).toNat < P_NAT := by
      have := Int.emod_lt_of_pos b (by decide : (0 : Int) < P)
      simp only [P, P_NAT] at *; omega
    rw [Nat.mod_eq_of_lt hlt] at hmod0
    omega

theorem goldilocks_boolean_sound {x : Int}
    (hx0 : 0 ≤ x) (hxP : x < P) (h : (x * (x - 1)) % P = 0) :
    x = 0 ∨ x = 1 := by
  rcases goldilocks_mul_eq_zero_mod_P h with h0 | h1
  · left
    rw [Int.emod_eq_of_lt hx0 hxP] at h0; exact h0
  · right
    by_cases hxzero : x = 0
    · exfalso; subst hxzero; simp [P] at h1
    · have hsub0 : 0 ≤ x - 1 := by omega
      have hsubP : x - 1 < P := by omega
      rw [Int.emod_eq_of_lt hsub0 hsubP] at h1
      omega

-- ============================================================================

theorem int_mod_add_eq {a b c d : Int} (h1 : a % P = c % P) (h2 : b % P = d % P) :
    (a + b) % P = (c + d) % P := by
  rw [Int.add_emod, h1, h2, ← Int.add_emod]

theorem int_mod_mul_eq {a b c d : Int} (h1 : a % P = c % P) (h2 : b % P = d % P) :
    (a * b) % P = (c * d) % P := by
  rw [Int.mul_emod, h1, h2, ← Int.mul_emod]

theorem int_mod_sub_eq {a b c d : Int} (h1 : a % P = c % P) (h2 : b % P = d % P) :
    (a - b) % P = (c - d) % P := by
  rw [Int.sub_emod, h1, h2, ← Int.sub_emod]

theorem monCmp_eq_iff : ∀ a b, monCmp a b = .eq → a = b
  | [], [], _ => rfl
  | [], _ :: _, h => by simp [monCmp] at h
  | _ :: _, [], h => by simp [monCmp] at h
  | a :: as, b :: bs, h => by
    simp only [monCmp] at h
    by_cases hlt : a < b
    · simp [hlt] at h
    · by_cases hgt : a > b
      · simp [hlt, hgt] at h
      · simp [hlt, hgt] at h
        have hab : a = b := by omega
        subst hab
        rw [monCmp_eq_iff as bs h]

theorem evalMonomial_monMerge (env : Nat → Int) :
    ∀ a b, evalMonomial env (monMerge a b) = evalMonomial env a * evalMonomial env b := by
  intro a
  induction a with
  | nil => intro b; simp [monMerge, evalMonomial]
  | cons x xs ih =>
    intro b
    simp only [monMerge]
    induction b with
    | nil => simp [monMergeGo, evalMonomial]
    | cons y ys ihy =>
      simp only [monMergeGo]
      by_cases hle : x ≤ y
      · simp only [hle, ↓reduceIte, evalMonomial]
        rw [ih (y :: ys), evalMonomial, Int.mul_assoc]
      · simp only [hle, ↓reduceIte, evalMonomial]
        rw [ihy, evalMonomial]
        rw [Int.mul_left_comm (env y) (env x * evalMonomial env xs)]

theorem evalPoly_pAdd (env : Nat → Int) :
    ∀ p q, evalPoly env (pAdd p q) % P = (evalPoly env p + evalPoly env q) % P := by
  intro p
  induction p with
  | nil => intro q; simp [pAdd, evalPoly]
  | cons hd ps ih =>
    rcases hd with ⟨m1, c1⟩
    intro q
    simp only [pAdd]
    induction q with
    | nil => simp [pAddGo, evalPoly]
    | cons hd2 qs ihq =>
      rcases hd2 with ⟨m2, c2⟩
      simp only [pAddGo]
      cases hcmp : monCmp m1 m2 with
      | lt =>
        simp only [evalPoly]
        rw [Int.add_emod, ih ((m2, c2) :: qs), ← Int.add_emod]
        simp only [evalPoly, Int.add_assoc]
      | gt =>
        simp only [evalPoly]
        rw [Int.add_emod, ihq, ← Int.add_emod]
        simp only [evalPoly]
        have hrearr : (c2 : Int) * evalMonomial env m2 + ((c1 : Int) * evalMonomial env m1 + evalPoly env ps + evalPoly env qs)
            = (c1 : Int) * evalMonomial env m1 + evalPoly env ps + ((c2 : Int) * evalMonomial env m2 + evalPoly env qs) := by omega
        rw [hrearr]
      | eq =>
        have hmeq : m1 = m2 := monCmp_eq_iff m1 m2 hcmp
        subst hmeq
        dsimp only
        cases hs : ((c1 + c2) % P_NAT == 0) with
        | true =>
          simp only [↓reduceIte]
          have hs0 : (c1 + c2) % P_NAT = 0 := beq_iff_eq.mp hs
          rw [ih qs]
          have hmod0 : ((c1 : Int) + (c2 : Int)) % P = 0 := by
            have : (((c1 + c2) % P_NAT : Nat) : Int) = ((c1 : Int) + (c2 : Int)) % P := by
              rw [Int.natCast_emod, Int.natCast_add]; rfl
            rw [← this, hs0]; rfl
          have hterm0 : (((c1 : Int) + (c2 : Int)) * evalMonomial env m1) % P = 0 := by
            rw [Int.mul_emod, hmod0, Int.zero_mul, Int.zero_emod]
          simp only [evalPoly]
          have hrearr : (c1 : Int) * evalMonomial env m1 + evalPoly env ps + ((c2 : Int) * evalMonomial env m1 + evalPoly env qs)
              = ((c1 : Int) + (c2 : Int)) * evalMonomial env m1 + (evalPoly env ps + evalPoly env qs) := by
            rw [Int.add_mul]; omega
          rw [hrearr, Int.add_emod (((c1 : Int) + (c2 : Int)) * evalMonomial env m1), hterm0, Int.zero_add, Int.emod_emod]
        | false =>
          simp only [Bool.false_eq_true, ↓reduceIte, evalPoly]
          rw [Int.add_emod, ih qs, ← Int.add_emod]
          have hcast : (((c1 + c2) % P_NAT : Nat) : Int) % P = ((c1 : Int) + (c2 : Int)) % P := by
            rw [Int.natCast_emod, Int.natCast_add]; simp [P, P_NAT]
          have hmul : ((((c1 + c2) % P_NAT : Nat) : Int) * evalMonomial env m1) % P
              = (((c1 : Int) + (c2 : Int)) * evalMonomial env m1) % P :=
            int_mod_mul_eq hcast rfl
          rw [Int.add_emod, hmul, ← Int.add_emod]
          have hrearr : ((c1 : Int) + (c2 : Int)) * evalMonomial env m1 + (evalPoly env ps + evalPoly env qs)
              = (c1 : Int) * evalMonomial env m1 + evalPoly env ps + ((c2 : Int) * evalMonomial env m1 + evalPoly env qs) := by
            rw [Int.add_mul]; omega
          rw [hrearr]

theorem evalPoly_pScaleAux (env : Nat → Int) (km : Nat) :
    ∀ p, evalPoly env (pScaleAux km p) % P = ((km : Int) * evalPoly env p) % P := by
  intro p
  induction p with
  | nil => simp [pScaleAux, evalPoly]
  | cons hd rest ih =>
    rcases hd with ⟨m, c⟩
    simp only [pScaleAux]
    cases hv : ((c * km) % P_NAT == 0) with
    | true =>
      simp only [↓reduceIte]
      have hv0 : (c * km) % P_NAT = 0 := beq_iff_eq.mp hv
      have hterm0 : ((km : Int) * ((c : Int) * evalMonomial env m)) % P = 0 := by
        have hck : ((c : Int) * (km : Int)) % P = 0 := by
          have : (((c * km) % P_NAT : Nat) : Int) = ((c : Int) * (km : Int)) % P := by
            rw [Int.natCast_emod, Int.natCast_mul]; rfl
          rw [← this, hv0]; rfl
        have hre : (km : Int) * ((c : Int) * evalMonomial env m) = ((c : Int) * (km : Int)) * evalMonomial env m := by
          rw [← Int.mul_assoc, Int.mul_comm (km : Int) (c : Int)]
        rw [hre, Int.mul_emod, hck, Int.zero_mul, Int.zero_emod]
      rw [ih, evalPoly, Int.mul_add, Int.add_emod, hterm0, Int.zero_add, Int.emod_emod]
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, evalPoly]
      rw [Int.add_emod, ih, ← Int.add_emod, Int.mul_add]
      have hterm : ((((c * km) % P_NAT : Nat) : Int) * evalMonomial env m) % P
          = ((km : Int) * ((c : Int) * evalMonomial env m)) % P := by
        have hck : (((c * km) % P_NAT : Nat) : Int) % P = ((c : Int) * (km : Int)) % P := by
          rw [Int.natCast_emod, Int.natCast_mul]; simp [P, P_NAT]
        have hre : (km : Int) * ((c : Int) * evalMonomial env m) = ((c : Int) * (km : Int)) * evalMonomial env m := by
          rw [← Int.mul_assoc, Int.mul_comm (km : Int) (c : Int)]
        rw [hre]; exact int_mod_mul_eq hck rfl
      exact int_mod_add_eq hterm rfl

theorem evalPoly_pScale (env : Nat → Int) (k : Nat) (p : Poly) :
    evalPoly env (pScale k p) % P = ((k : Int) * evalPoly env p) % P := by
  simp only [pScale]
  cases hkm : ((k % P_NAT) == 0) with
  | true =>
    simp only [↓reduceIte, evalPoly]
    have h0 : k % P_NAT = 0 := beq_iff_eq.mp hkm
    have hk0 : (k : Int) % P = 0 := by
      have : ((k % P_NAT : Nat) : Int) = (k : Int) % P := by rw [Int.natCast_emod]; rfl
      rw [← this, h0]; rfl
    rw [Int.mul_emod, hk0, Int.zero_mul, Int.zero_emod]
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte]
    rw [evalPoly_pScaleAux]
    have hk : ((k % P_NAT : Nat) : Int) % P = (k : Int) % P := by
      rw [Int.natCast_emod]; simp [P, P_NAT]
    exact int_mod_mul_eq hk rfl

theorem evalPoly_pNeg (env : Nat → Int) :
    ∀ p, evalPoly env (pNeg p) % P = (-evalPoly env p) % P := by
  intro p
  induction p with
  | nil => simp [pNeg, evalPoly]
  | cons hd rest ih =>
    rcases hd with ⟨m, c⟩
    simp only [pNeg]
    cases hcm : ((c % P_NAT) == 0) with
    | true =>
      simp only [↓reduceIte]
      have h0 : c % P_NAT = 0 := beq_iff_eq.mp hcm
      have hc0 : (c : Int) % P = 0 := by
        have : ((c % P_NAT : Nat) : Int) = (c : Int) % P := by rw [Int.natCast_emod]; rfl
        rw [← this, h0]; rfl
      rw [ih, evalPoly]
      have hneg : -((c : Int) * evalMonomial env m + evalPoly env rest) =
          (-(c : Int) * evalMonomial env m) + (-evalPoly env rest) := by
        rw [Int.neg_mul]; omega
      rw [hneg, Int.add_emod]
      have hterm0 : (-(c : Int) * evalMonomial env m) % P = 0 := by
        rcases Int.dvd_of_emod_eq_zero hc0 with ⟨q, hq⟩
        have hre : -(c : Int) * evalMonomial env m = P * (-(q * evalMonomial env m)) := by
          rw [hq, Int.neg_mul, Int.mul_neg, Int.mul_assoc]
        rw [hre]; exact Int.mul_emod_right P _
      rw [hterm0, Int.zero_add, Int.emod_emod]
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, evalPoly]
      have hlt : c % P_NAT < P_NAT := Nat.mod_lt c (by decide)
      have hnegc : ((P_NAT - c % P_NAT : Nat) : Int) % P = (-(c : Int)) % P := by
        have hsub : ((P_NAT - c % P_NAT : Nat) : Int) = P - ((c % P_NAT : Nat) : Int) := by
          have := Int.ofNat_sub (Nat.le_of_lt hlt)
          simpa [P, P_NAT] using this
        rw [hsub, Int.sub_emod, Int.emod_self, Int.zero_sub]
        have hcmod : ((c % P_NAT : Nat) : Int) % P = (c : Int) % P := by
          rw [Int.natCast_emod]; simp [P, P_NAT]
        rw [hcmod]
        rw [← Int.zero_sub ((c : Int) % P), ← Int.zero_sub (c : Int), Int.sub_emod 0 ((c : Int) % P), Int.emod_emod, ← Int.sub_emod]
      have hterm : (((P_NAT - c % P_NAT : Nat) : Int) * evalMonomial env m) % P =
          (-(c : Int) * evalMonomial env m) % P :=
        int_mod_mul_eq hnegc rfl
      rw [Int.add_emod, hterm, ih, ← Int.add_emod]
      have hre : -(c : Int) * evalMonomial env m + -evalPoly env rest =
          -((c : Int) * evalMonomial env m + evalPoly env rest) := by
        rw [Int.neg_mul]; omega
      rw [hre]

theorem evalPoly_pSub (env : Nat → Int) (p q : Poly) :
    evalPoly env (pSub p q) % P = (evalPoly env p - evalPoly env q) % P := by
  unfold pSub
  rw [evalPoly_pAdd, Int.add_emod, evalPoly_pNeg, ← Int.add_emod]
  have : evalPoly env p + -evalPoly env q = evalPoly env p - evalPoly env q := by omega
  rw [this]

def sumEvalList (env : Nat → Int) : List Poly → Int
  | [] => 0
  | p :: ps => evalPoly env p + sumEvalList env ps

theorem evalPoly_foldl_pAdd (env : Nat → Int) :
    ∀ ps acc, evalPoly env (ps.foldl pAdd acc) % P = (evalPoly env acc + sumEvalList env ps) % P := by
  intro ps
  induction ps with
  | nil => intro acc; simp [sumEvalList]
  | cons p rest ih =>
    intro acc
    simp only [List.foldl, sumEvalList]
    rw [ih (pAdd acc p), Int.add_emod, evalPoly_pAdd, ← Int.add_emod, Int.add_assoc]

theorem sumEvalList_pPairMerge (env : Nat → Int) :
    ∀ ps, sumEvalList env (pPairMerge ps) % P = sumEvalList env ps % P := by
  intro ps
  match ps with
  | [] => simp [pPairMerge, sumEvalList]
  | [p] => simp [pPairMerge, sumEvalList]
  | p :: q :: rest =>
    simp only [pPairMerge, sumEvalList]
    rw [Int.add_emod, evalPoly_pAdd, sumEvalList_pPairMerge env rest, ← Int.add_emod, Int.add_assoc]

theorem evalPoly_pSumListFuel (env : Nat → Int) :
    ∀ fuel ps, evalPoly env (pSumListFuel fuel ps) % P = sumEvalList env ps % P := by
  intro fuel
  induction fuel with
  | zero =>
    intro ps
    match ps with
    | [] => simp [pSumListFuel, evalPoly, sumEvalList]
    | [p] => simp [pSumListFuel, sumEvalList]
    | p :: q :: rest =>
      simp only [pSumListFuel, sumEvalList]
      rw [evalPoly_foldl_pAdd, sumEvalList]
  | succ k ih =>
    intro ps
    match ps with
    | [] => simp [pSumListFuel, evalPoly, sumEvalList]
    | [p] => simp [pSumListFuel, sumEvalList]
    | p :: q :: rest =>
      simp only [pSumListFuel]
      rw [ih (pPairMerge (p :: q :: rest)), sumEvalList_pPairMerge]

theorem evalPoly_pSumList (env : Nat → Int) (ps : List Poly) :
    evalPoly env (pSumList ps) % P = sumEvalList env ps % P :=
  evalPoly_pSumListFuel env 16 ps

theorem sumEvalList_pMulTermList (env : Nat → Int) (m : List Nat) (c : Nat) :
    ∀ q, sumEvalList env (pMulTermList m c q) % P = ((c : Int) * evalMonomial env m * evalPoly env q) % P := by
  intro q
  induction q with
  | nil => simp [pMulTermList, sumEvalList, evalPoly]
  | cons hd rest ih =>
    rcases hd with ⟨m2, c2⟩
    simp only [pMulTermList]
    cases hv : ((c * c2) % P_NAT == 0) with
    | true =>
      simp only [↓reduceIte]
      have hv0 : (c * c2) % P_NAT = 0 := beq_iff_eq.mp hv
      have hcc : ((c : Int) * (c2 : Int)) % P = 0 := by
        have : (((c * c2) % P_NAT : Nat) : Int) = ((c : Int) * (c2 : Int)) % P := by
          rw [Int.natCast_emod, Int.natCast_mul]; rfl
        rw [← this, hv0]; rfl
      rw [ih, evalPoly, Int.mul_add]
      have hterm0 : ((c : Int) * evalMonomial env m * ((c2 : Int) * evalMonomial env m2)) % P = 0 := by
        have hre : (c : Int) * evalMonomial env m * ((c2 : Int) * evalMonomial env m2) =
            ((c : Int) * (c2 : Int)) * (evalMonomial env m * evalMonomial env m2) := by
          rw [Int.mul_assoc (c : Int), Int.mul_left_comm (evalMonomial env m), ← Int.mul_assoc (c : Int)]
        rw [hre, Int.mul_emod, hcc, Int.zero_mul, Int.zero_emod]
      rw [Int.add_emod, hterm0, Int.zero_add, Int.emod_emod]
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, sumEvalList, evalPoly]
      rw [Int.add_zero, evalMonomial_monMerge, Int.add_emod, ih, ← Int.add_emod, Int.mul_add]
      have hterm : ((((c * c2) % P_NAT : Nat) : Int) * (evalMonomial env m * evalMonomial env m2)) % P =
          ((c : Int) * evalMonomial env m * ((c2 : Int) * evalMonomial env m2)) % P := by
        have hcc : (((c * c2) % P_NAT : Nat) : Int) % P = ((c : Int) * (c2 : Int)) % P := by
          rw [Int.natCast_emod, Int.natCast_mul]; simp [P, P_NAT]
        have hre : (c : Int) * evalMonomial env m * ((c2 : Int) * evalMonomial env m2) =
            ((c : Int) * (c2 : Int)) * (evalMonomial env m * evalMonomial env m2) := by
          rw [Int.mul_assoc (c : Int), Int.mul_left_comm (evalMonomial env m), ← Int.mul_assoc (c : Int)]
        rw [hre]; exact int_mod_mul_eq hcc rfl
      exact int_mod_add_eq hterm rfl

theorem evalPoly_pMul (env : Nat → Int) (p q : Poly) :
    evalPoly env (pMul p q) % P = (evalPoly env p * evalPoly env q) % P := by
  unfold pMul
  rw [evalPoly_pSumList]
  induction p with
  | nil => simp [pMulList, sumEvalList, evalPoly]
  | cons hd rest ih =>
    rcases hd with ⟨m, c⟩
    simp only [pMulList, sumEvalList, evalPoly, pMulTerm]
    rw [Int.add_emod, evalPoly_pSumList, sumEvalList_pMulTermList, ih, ← Int.add_emod, Int.add_mul]

theorem evalPoly_pConst (env : Nat → Int) (c : Nat) :
    evalPoly env (pConst c) % P = (c : Int) % P := by
  unfold pConst
  dsimp only
  cases h : ((c % P_NAT) == 0) with
  | true =>
    simp only [↓reduceIte, evalPoly]
    have h0 : c % P_NAT = 0 := beq_iff_eq.mp h
    have : ((c % P_NAT : Nat) : Int) = (c : Int) % P := by rw [Int.natCast_emod]; rfl
    rw [← this, h0]; rfl
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte, evalPoly, evalMonomial, Int.mul_one, Int.add_zero]
    rw [Int.natCast_emod]; simp [P, P_NAT]

theorem evalPoly_pVar (env : Nat → Int) (v : Nat) :
    evalPoly env (pVar v) = env v := by
  simp [pVar, evalPoly, evalMonomial]

def sumInt (lo : Nat) (f : Nat → Int) : Nat → Int
  | 0 => 0
  | n + 1 => sumInt lo f n + f (lo + n)

theorem sumInt_add (lo : Nat) (f : Nat → Int) (a b : Nat) :
    sumInt lo f (a + b) = sumInt lo f a + sumInt (lo + a) f b := by
  induction b with
  | zero => simp [sumInt]
  | succ k ih =>
    have h1 : a + (k + 1) = (a + k) + 1 := by omega
    rw [h1, sumInt, sumInt, ih]
    have h2 : lo + (a + k) = lo + a + k := by omega
    rw [h2]; omega

theorem evalPoly_pSumPow2 (env : Nat → Int) (d : Nat) :
    ∀ lo f, evalPoly env (pSumPow2 d lo f) % P = sumInt lo (fun i => evalPoly env (f i)) (2 ^ d) % P := by
  induction d with
  | zero => intro lo f; simp [pSumPow2, sumInt]
  | succ k ih =>
    intro lo f
    simp only [pSumPow2]
    rw [evalPoly_pAdd, Int.add_emod, ih lo f, ih (lo + 2 ^ k) f, ← Int.add_emod]
    have hpow : 2 ^ (k + 1) = 2 ^ k + 2 ^ k := by rw [Nat.pow_succ]; omega
    rw [hpow, sumInt_add]

theorem sumInt_congr_mod_P (lo : Nat) (f g : Nat → Int) :
    ∀ n, (∀ i, i < n → f (lo + i) % P = g (lo + i) % P) →
      sumInt lo f n % P = sumInt lo g n % P := by
  intro n
  induction n with
  | zero => intro _; simp [sumInt]
  | succ k ih =>
    intro hfg
    simp only [sumInt]
    exact int_mod_add_eq (ih (fun i hi => hfg i (by omega))) (hfg k (by omega))

-- ============================================================================

def u32Bit (x : UInt32) (i : Nat) : Int :=
  if (x.toNat / (2 ^ i)) % 2 = 1 then 1 else 0

theorem u32Bit_bool (x : UInt32) (i : Nat) : u32Bit x i = 0 ∨ u32Bit x i = 1 := by
  unfold u32Bit; split <;> simp

theorem packBits_u32Bit_aux (x : Nat) :
    ∀ n, packBits (fun i => if (x / (2 ^ i)) % 2 = 1 then 1 else 0) n = (x % (2 ^ n) : Nat) := by
  intro n
  induction n with
  | zero => simp [packBits]
  | succ k ih =>
    rw [packBits, ih]
    have hdiv : x % 2 ^ (k + 1) = x % 2 ^ k + ((x / 2 ^ k) % 2) * 2 ^ k := by
      have h1 := Nat.div_add_mod x (2 ^ k)
      have h2 := Nat.div_add_mod (x / 2 ^ k) 2
      have hpow : 2 ^ (k + 1) = 2 ^ k * 2 := Nat.pow_succ 2 k
      have hlt : x % 2 ^ k + ((x / 2 ^ k) % 2) * 2 ^ k < 2 ^ (k + 1) := by
        have hlt1 := Nat.mod_lt x (Nat.two_pow_pos k)
        have hlt2 := Nat.mod_lt (x / 2 ^ k) (by decide : 0 < 2)
        have hmul : ((x / 2 ^ k) % 2) * 2 ^ k ≤ 2 ^ k := by
          have : (x / 2 ^ k) % 2 ≤ 1 := by omega
          calc ((x / 2 ^ k) % 2) * 2 ^ k ≤ 1 * 2 ^ k := Nat.mul_le_mul_right (2 ^ k) this
          _ = 2 ^ k := Nat.one_mul _
        rw [hpow]; omega
      have hdecomp : 2 ^ (k + 1) * (x / 2 ^ k / 2) + (x % 2 ^ k + ((x / 2 ^ k) % 2) * 2 ^ k) = x := by
        have h2' : 2 ^ k * (2 * (x / 2 ^ k / 2) + (x / 2 ^ k) % 2) =
            2 ^ k * 2 * (x / 2 ^ k / 2) + ((x / 2 ^ k) % 2) * 2 ^ k := by
          rw [Nat.mul_add, ← Nat.mul_assoc, Nat.mul_comm (2 ^ k) ((x / 2 ^ k) % 2)]
        rw [h2] at h2'
        rw [hpow]
        omega
      have hmod_eq : x % 2 ^ (k + 1) = (2 ^ (k + 1) * (x / 2 ^ k / 2) + (x % 2 ^ k + ((x / 2 ^ k) % 2) * 2 ^ k)) % 2 ^ (k + 1) :=
        congrArg (· % 2 ^ (k + 1)) hdecomp.symm
      rw [hmod_eq, Nat.mul_add_mod, Nat.mod_eq_of_lt hlt]
    rw [hdiv]
    have hbit : (x / 2 ^ k) % 2 = 0 ∨ (x / 2 ^ k) % 2 = 1 := by omega
    rcases hbit with h0 | h1
    · simp [h0]
    · simp [h1]

theorem packBits_u32Bit (x : UInt32) : packBits (u32Bit x) 32 = (x.toNat : Int) := by
  have h := packBits_u32Bit_aux x.toNat 32
  have hlt : x.toNat < 2 ^ 32 := x.toBitVec.isLt
  rw [Nat.mod_eq_of_lt hlt] at h
  exact h

theorem packBits_eq_implies_bits_eq (b : Nat → Int) (x : UInt32)
    (hbits : ∀ i, i < 32 → b i = 0 ∨ b i = 1)
    (hpack : packBits b 32 = (x.toNat : Int)) :
    ∀ i, i < 32 → b i = u32Bit x i := by
  have huniq : ∀ n (f g : Nat → Int),
      (∀ i, i < n → f i = 0 ∨ f i = 1) →
      (∀ i, i < n → g i = 0 ∨ g i = 1) →
      packBits f n = packBits g n →
      ∀ i, i < n → f i = g i := by
    intro n
    induction n with
    | zero => intro f g _ _ _ i hi; omega
    | succ k ih =>
      intro f g hf hg heq i hi
      simp only [packBits] at heq
      have hbf := packBits_bounds f k (fun j hj => hf j (by omega))
      have hbg := packBits_bounds g k (fun j hj => hg j (by omega))
      have hfk := hf k (by omega)
      have hgk := hg k (by omega)
      have hkeq : f k = g k := by
        rcases hfk with h0 | h1
        · rcases hgk with g0 | g1
          · rw [h0, g0]
          · rw [h0, g1] at heq; omega
        · rcases hgk with g0 | g1
          · rw [h1, g0] at heq; omega
          · rw [h1, g1]
      have hpreveq : packBits f k = packBits g k := by rw [hkeq] at heq; omega
      by_cases hik : i = k
      · subst hik; exact hkeq
      · exact ih f g (fun j hj => hf j (by omega)) (fun j hj => hg j (by omega)) hpreveq i (by omega)
  exact huniq 32 b (u32Bit x) hbits (fun i _ => u32Bit_bool x i) (by rw [hpack, packBits_u32Bit])


theorem u32Bit_eq_testBit (x : UInt32) (i : Nat) :
    u32Bit x i = if x.toBitVec.getLsbD i then 1 else 0 := by
  unfold u32Bit
  have h : x.toBitVec.getLsbD i = ((x.toNat / 2 ^ i) % 2 == 1) := by
    rw [BitVec.getLsbD, UInt32.toNat_toBitVec, Nat.testBit, Nat.shiftRight_eq_div_pow, Nat.and_comm, Nat.and_one_is_mod]
    cases hmod : (x.toNat / 2 ^ i) % 2 with
    | zero => rfl
    | succ n =>
      have : (x.toNat / 2 ^ i) % 2 < 2 := Nat.mod_lt _ (by decide)
      have hn : n = 0 := by omega
      subst hn; rfl
  rw [h]
  cases h2 : ((x.toNat / 2 ^ i) % 2 == 1) with
  | true => simp [beq_iff_eq.mp h2]
  | false =>
    have hne : (x.toNat / 2 ^ i) % 2 ≠ 1 := fun heq => by simp [heq] at h2
    simp [hne]

theorem u32_getLsbD_ge (x : UInt32) (i : Nat) (hi : 32 ≤ i) :
    x.toBitVec.getLsbD i = false := by
  rw [BitVec.getLsbD, UInt32.toNat_toBitVec, Nat.testBit, Nat.shiftRight_eq_div_pow]
  have hlt : x.toNat < 2 ^ i := Nat.lt_of_lt_of_le x.toBitVec.isLt (Nat.pow_le_pow_right (by decide) hi)
  rw [Nat.div_eq_of_lt hlt]; rfl

theorem u32Bit_xor (x y : UInt32) (i : Nat) :
    u32Bit (x ^^^ y) i = bitXor2 (u32Bit x i) (u32Bit y i) := by
  rw [u32Bit_eq_testBit, u32Bit_eq_testBit, u32Bit_eq_testBit]
  have h : (x ^^^ y).toBitVec.getLsbD i = (x.toBitVec.getLsbD i ^^ y.toBitVec.getLsbD i) := by
    simp [UInt32.toBitVec_xor]
  rw [h]
  cases x.toBitVec.getLsbD i <;> cases y.toBitVec.getLsbD i <;> decide

theorem u32Bit_rotr32 (x r : UInt32) (hr0 : 0 < r.toNat) (hr32 : r.toNat < 32) (i : Nat) (hi : i < 32) :
    u32Bit (rotr32 x r) i = u32Bit x ((i + r.toNat) % 32) := by
  rw [u32Bit_eq_testBit, u32Bit_eq_testBit]
  unfold rotr32
  have hsub : (32 - r).toNat = 32 - r.toNat := by
    rw [UInt32.toNat_sub_of_le]
    · simp
    · change r.toNat ≤ (32 : UInt32).toNat; simp; omega
  have hr_mod : r.toNat % 32 = r.toNat := Nat.mod_eq_of_lt hr32
  have hs_mod : (32 - r).toNat % 32 = 32 - r.toNat := by rw [hsub]; exact Nat.mod_eq_of_lt (by omega)
  have hget : ((x >>> r) ||| (x <<< (32 - r))).toBitVec.getLsbD i =
      (x.toBitVec.getLsbD (r.toNat + i) || (!decide (i < 32 - r.toNat) && x.toBitVec.getLsbD (i - (32 - r.toNat)))) := by
    have h1 : (x >>> r).toBitVec.getLsbD i = x.toBitVec.getLsbD (r.toNat + i) := by
      simp [UInt32.toBitVec_shiftRight, hr_mod]
    have h2 : (x <<< (32 - r)).toBitVec.getLsbD i =
        (!decide (i < 32 - r.toNat) && x.toBitVec.getLsbD (i - (32 - r.toNat))) := by
      have hsub_mod : (4294967296 - r.toNat) % 32 = 32 - r.toNat := by omega
      have hlt_sub : i - (32 - r.toNat) < 32 := by omega
      simp [UInt32.toBitVec_shiftLeft, hi, hsub_mod, BitVec.getLsbD_eq_getElem, hlt_sub]
    rw [UInt32.toBitVec_or, BitVec.getLsbD_or, h1, h2]
  rw [hget]
  by_cases hir : i + r.toNat < 32
  · have hmod : (i + r.toNat) % 32 = i + r.toNat := Nat.mod_eq_of_lt hir
    have hlt : i < 32 - r.toNat := by omega
    have hcomm : r.toNat + i = i + r.toNat := Nat.add_comm r.toNat i
    simp [hmod, hlt, hcomm]
  · have hmod : (i + r.toNat) % 32 = i - (32 - r.toNat) := by omega
    have hnlt : ¬ (i < 32 - r.toNat) := by omega
    have hout : x.toBitVec.getLsbD (r.toNat + i) = false := u32_getLsbD_ge x (r.toNat + i) (by omega)
    simp [hmod, hnlt, hout]

theorem u32Bit_shr (x r : UInt32) (hr32 : r.toNat < 32) (i : Nat) :
    u32Bit (x >>> r) i = if i + r.toNat < 32 then u32Bit x (i + r.toNat) else 0 := by
  rw [u32Bit_eq_testBit]
  have hr_mod : r.toNat % 32 = r.toNat := Nat.mod_eq_of_lt hr32
  have hshr : (x >>> r).toBitVec.getLsbD i = x.toBitVec.getLsbD (i + r.toNat) := by
    simp [UInt32.toBitVec_shiftRight, hr_mod, Nat.add_comm]
  rw [hshr]
  by_cases hir : i + r.toNat < 32
  · simp [hir, u32Bit_eq_testBit]
  · have hout : x.toBitVec.getLsbD (i + r.toNat) = false := u32_getLsbD_ge x (i + r.toNat) (by omega)
    simp [hir, hout]

theorem u32Bit_ch32 (e f g : UInt32) (i : Nat) (hi : i < 32) :
    u32Bit (ch32 e f g) i = bitCh (u32Bit e i) (u32Bit f i) (u32Bit g i) := by
  unfold ch32
  rw [u32Bit_eq_testBit, u32Bit_eq_testBit, u32Bit_eq_testBit, u32Bit_eq_testBit]
  have h : ((e &&& f) ^^^ ((~~~e) &&& g)).toBitVec.getLsbD i =
      ((e.toBitVec.getLsbD i && f.toBitVec.getLsbD i) ^^ ((!e.toBitVec.getLsbD i) && g.toBitVec.getLsbD i)) := by
    simp [UInt32.toBitVec_xor, UInt32.toBitVec_and, UInt32.toBitVec_not, hi]
  rw [h]
  cases e.toBitVec.getLsbD i <;> cases f.toBitVec.getLsbD i <;> cases g.toBitVec.getLsbD i <;> decide

theorem u32Bit_maj32 (a b c : UInt32) (i : Nat) :
    u32Bit (maj32 a b c) i = bitMaj (u32Bit a i) (u32Bit b i) (u32Bit c i) := by
  unfold maj32
  rw [u32Bit_eq_testBit, u32Bit_eq_testBit, u32Bit_eq_testBit, u32Bit_eq_testBit]
  have h : ((a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)).toBitVec.getLsbD i =
      (((a.toBitVec.getLsbD i && b.toBitVec.getLsbD i) ^^ (a.toBitVec.getLsbD i && c.toBitVec.getLsbD i)) ^^
       (b.toBitVec.getLsbD i && c.toBitVec.getLsbD i)) := by
    simp [UInt32.toBitVec_xor, UInt32.toBitVec_and]
  rw [h]
  cases a.toBitVec.getLsbD i <;> cases b.toBitVec.getLsbD i <;> cases c.toBitVec.getLsbD i <;> decide


theorem evalPoly_pXor2 (env : Nat → Int) (px py : Poly) (vx vy : Int)
    (hx : evalPoly env px % P = vx % P) (hy : evalPoly env py % P = vy % P)
    (hbx : vx = 0 ∨ vx = 1) (hby : vy = 0 ∨ vy = 1) :
    evalPoly env (pXor2 px py) % P = bitXor2 vx vy % P := by
  unfold pXor2
  rw [evalPoly_pSub]
  have h1 : evalPoly env (pAdd px py) % P = (vx + vy) % P := by
    rw [evalPoly_pAdd]; exact int_mod_add_eq hx hy
  have h2 : evalPoly env (pScale 2 (pMul px py)) % P = (2 * vx * vy) % P := by
    rw [evalPoly_pScale, Int.mul_emod, evalPoly_pMul, ← Int.mul_emod]
    rw [Int.mul_assoc]
    exact int_mod_mul_eq rfl (int_mod_mul_eq hx hy)
  rw [int_mod_sub_eq h1 h2, xor2_poly_exact vx vy hbx hby]

theorem evalPoly_pXor3 (env : Nat → Int) (px py pz : Poly) (vx vy vz : Int)
    (hx : evalPoly env px % P = vx % P) (hy : evalPoly env py % P = vy % P) (hz : evalPoly env pz % P = vz % P)
    (hbx : vx = 0 ∨ vx = 1) (hby : vy = 0 ∨ vy = 1) (hbz : vz = 0 ∨ vz = 1) :
    evalPoly env (pXor3 px py pz) % P = bitXor3 vx vy vz % P := by
  unfold pXor3
  dsimp only
  have hxy : evalPoly env (pMul px py) % P = (vx * vy) % P := by
    rw [evalPoly_pMul]; exact int_mod_mul_eq hx hy
  have hxz : evalPoly env (pMul px pz) % P = (vx * vz) % P := by
    rw [evalPoly_pMul]; exact int_mod_mul_eq hx hz
  have hyz : evalPoly env (pMul py pz) % P = (vy * vz) % P := by
    rw [evalPoly_pMul]; exact int_mod_mul_eq hy hz
  have hxyz : evalPoly env (pMul (pMul px py) pz) % P = (vx * vy * vz) % P := by
    rw [evalPoly_pMul]; exact int_mod_mul_eq hxy hz
  have hs1 : evalPoly env (pAdd (pAdd px py) pz) % P = (vx + vy + vz) % P := by
    rw [evalPoly_pAdd]; exact int_mod_add_eq (by rw [evalPoly_pAdd]; exact int_mod_add_eq hx hy) hz
  have hs2 : evalPoly env (pScale 2 (pAdd (pAdd (pMul px py) (pMul px pz)) (pMul py pz))) % P =
      (2 * (vx * vy + vx * vz + vy * vz)) % P := by
    rw [evalPoly_pScale]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pAdd]
    exact int_mod_add_eq (by rw [evalPoly_pAdd]; exact int_mod_add_eq hxy hxz) hyz
  have hs3 : evalPoly env (pScale 4 (pMul (pMul px py) pz)) % P = (4 * vx * vy * vz) % P := by
    rw [evalPoly_pScale]
    have hre : 4 * vx * vy * vz = (4 : Int) * (vx * vy * vz) := by repeat rw [Int.mul_assoc]
    rw [hre]; exact int_mod_mul_eq rfl hxyz
  rw [evalPoly_pAdd]
  have hsub : evalPoly env (pSub (pAdd (pAdd px py) pz) (pScale 2 (pAdd (pAdd (pMul px py) (pMul px pz)) (pMul py pz)))) % P =
      (vx + vy + vz - 2 * (vx * vy + vx * vz + vy * vz)) % P := by
    rw [evalPoly_pSub]; exact int_mod_sub_eq hs1 hs2
  rw [int_mod_add_eq hsub hs3, xor3_poly_exact vx vy vz hbx hby hbz]

theorem sumInt_eq_packBits (b : Nat → Int) :
    ∀ n, sumInt 0 (fun i => ((2 ^ i : Nat) : Int) * b i) n = packBits b n := by
  intro n
  induction n with
  | zero => simp [sumInt, packBits]
  | succ k ih =>
    simp only [sumInt, packBits, Nat.zero_add]
    rw [ih, Int.mul_comm]

theorem evalPoly_pWordBits (env : Nat → Int) (gb : Nat → Poly) (b : Nat → Int)
    (hgb : ∀ i, i < 32 → evalPoly env (gb i) % P = b i % P) :
    evalPoly env (pWordBits gb) % P = packBits b 32 % P := by
  unfold pWordBits
  rw [evalPoly_pSumPow2]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (gb i)))
    (fun i => ((2 ^ i : Nat) : Int) * b i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      exact int_mod_mul_eq rfl (hgb i hi))
  rw [show (2 ^ 5 : Nat) = 32 from rfl, hcongr, sumInt_eq_packBits]

theorem evalPoly_pBigS0 (env : Nat → Int) (ga : Nat → Poly) (a : UInt32)
    (hga : ∀ i, i < 32 → evalPoly env (ga i) % P = u32Bit a i % P) :
    evalPoly env (pBigS0 ga) % P = ((bigS0 a).toNat : Int) % P := by
  unfold pBigS0
  rw [evalPoly_pSumPow2, show (2 ^ 5 : Nat) = 32 from rfl]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (pXor3 (ga ((i + 2) % 32)) (ga ((i + 13) % 32)) (ga ((i + 22) % 32)))))
    (fun i => ((2 ^ i : Nat) : Int) * u32Bit (bigS0 a) i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      refine int_mod_mul_eq rfl ?_
      rw [evalPoly_pXor3 env _ _ _ (u32Bit a ((i + 2) % 32)) (u32Bit a ((i + 13) % 32)) (u32Bit a ((i + 22) % 32))
        (hga _ (Nat.mod_lt _ (by decide))) (hga _ (Nat.mod_lt _ (by decide))) (hga _ (Nat.mod_lt _ (by decide)))
        (u32Bit_bool _ _) (u32Bit_bool _ _) (u32Bit_bool _ _)]
      unfold bigS0 bitXor3
      rw [u32Bit_xor, u32Bit_xor,
        u32Bit_rotr32 a 2 (by decide) (by decide) i hi,
        u32Bit_rotr32 a 13 (by decide) (by decide) i hi,
        u32Bit_rotr32 a 22 (by decide) (by decide) i hi]
      rfl)
  rw [hcongr, sumInt_eq_packBits, packBits_u32Bit]

theorem evalPoly_pBigS1 (env : Nat → Int) (ge : Nat → Poly) (e : UInt32)
    (hge : ∀ i, i < 32 → evalPoly env (ge i) % P = u32Bit e i % P) :
    evalPoly env (pBigS1 ge) % P = ((bigS1 e).toNat : Int) % P := by
  unfold pBigS1
  rw [evalPoly_pSumPow2, show (2 ^ 5 : Nat) = 32 from rfl]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (pXor3 (ge ((i + 6) % 32)) (ge ((i + 11) % 32)) (ge ((i + 25) % 32)))))
    (fun i => ((2 ^ i : Nat) : Int) * u32Bit (bigS1 e) i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      refine int_mod_mul_eq rfl ?_
      rw [evalPoly_pXor3 env _ _ _ (u32Bit e ((i + 6) % 32)) (u32Bit e ((i + 11) % 32)) (u32Bit e ((i + 25) % 32))
        (hge _ (Nat.mod_lt _ (by decide))) (hge _ (Nat.mod_lt _ (by decide))) (hge _ (Nat.mod_lt _ (by decide)))
        (u32Bit_bool _ _) (u32Bit_bool _ _) (u32Bit_bool _ _)]
      unfold bigS1 bitXor3
      rw [u32Bit_xor, u32Bit_xor,
        u32Bit_rotr32 e 6 (by decide) (by decide) i hi,
        u32Bit_rotr32 e 11 (by decide) (by decide) i hi,
        u32Bit_rotr32 e 25 (by decide) (by decide) i hi]
      rfl)
  rw [hcongr, sumInt_eq_packBits, packBits_u32Bit]

theorem evalPoly_pSmallS0 (env : Nat → Int) (gx : Nat → Poly) (x : UInt32)
    (hgx : ∀ i, i < 32 → evalPoly env (gx i) % P = u32Bit x i % P) :
    evalPoly env (pSmallS0 gx) % P = ((smallS0 x).toNat : Int) % P := by
  unfold pSmallS0
  rw [evalPoly_pSumPow2, show (2 ^ 5 : Nat) = 32 from rfl]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (if i + 3 < 32
      then pXor3 (gx ((i + 7) % 32)) (gx ((i + 18) % 32)) (gx (i + 3))
      else pXor2 (gx ((i + 7) % 32)) (gx ((i + 18) % 32)))))
    (fun i => ((2 ^ i : Nat) : Int) * u32Bit (smallS0 x) i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      refine int_mod_mul_eq rfl ?_
      unfold smallS0
      rw [u32Bit_xor, u32Bit_xor,
        u32Bit_rotr32 x 7 (by decide) (by decide) i hi,
        u32Bit_rotr32 x 18 (by decide) (by decide) i hi,
        u32Bit_shr x 3 (by decide) i]
      change evalPoly env (if i + 3 < 32 then _ else _) % P =
        bitXor2 (bitXor2 (u32Bit x ((i + 7) % 32)) (u32Bit x ((i + 18) % 32))) (if i + 3 < 32 then u32Bit x (i + 3) else 0) % P
      by_cases hlt : i + 3 < 32
      · simp only [hlt, ↓reduceIte]
        rw [evalPoly_pXor3 env _ _ _ (u32Bit x ((i + 7) % 32)) (u32Bit x ((i + 18) % 32)) (u32Bit x (i + 3))
          (hgx _ (Nat.mod_lt _ (by decide))) (hgx _ (Nat.mod_lt _ (by decide))) (hgx _ hlt)
          (u32Bit_bool _ _) (u32Bit_bool _ _) (u32Bit_bool _ _)]
        rfl
      · simp only [hlt, ↓reduceIte]
        rw [evalPoly_pXor2 env _ _ (u32Bit x ((i + 7) % 32)) (u32Bit x ((i + 18) % 32))
          (hgx _ (Nat.mod_lt _ (by decide))) (hgx _ (Nat.mod_lt _ (by decide)))
          (u32Bit_bool _ _) (u32Bit_bool _ _)]
        have hxor0 : ∀ u, (u = 0 ∨ u = 1) → bitXor2 u 0 = u := by
          intro u hu; rcases hu with rfl | rfl <;> decide
        have hb2 : bitXor2 (u32Bit x ((i + 7) % 32)) (u32Bit x ((i + 18) % 32)) = 0 ∨
                   bitXor2 (u32Bit x ((i + 7) % 32)) (u32Bit x ((i + 18) % 32)) = 1 := by
          rcases u32Bit_bool x ((i + 7) % 32) with h1 | h1 <;>
          rcases u32Bit_bool x ((i + 18) % 32) with h2 | h2 <;>
          rw [h1, h2] <;> decide
        rw [hxor0 _ hb2])
  rw [hcongr, sumInt_eq_packBits, packBits_u32Bit]

theorem evalPoly_pSmallS1 (env : Nat → Int) (gx : Nat → Poly) (x : UInt32)
    (hgx : ∀ i, i < 32 → evalPoly env (gx i) % P = u32Bit x i % P) :
    evalPoly env (pSmallS1 gx) % P = ((smallS1 x).toNat : Int) % P := by
  unfold pSmallS1
  rw [evalPoly_pSumPow2, show (2 ^ 5 : Nat) = 32 from rfl]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (if i + 10 < 32
      then pXor3 (gx ((i + 17) % 32)) (gx ((i + 19) % 32)) (gx (i + 10))
      else pXor2 (gx ((i + 17) % 32)) (gx ((i + 19) % 32)))))
    (fun i => ((2 ^ i : Nat) : Int) * u32Bit (smallS1 x) i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      refine int_mod_mul_eq rfl ?_
      unfold smallS1
      rw [u32Bit_xor, u32Bit_xor,
        u32Bit_rotr32 x 17 (by decide) (by decide) i hi,
        u32Bit_rotr32 x 19 (by decide) (by decide) i hi,
        u32Bit_shr x 10 (by decide) i]
      change evalPoly env (if i + 10 < 32 then _ else _) % P =
        bitXor2 (bitXor2 (u32Bit x ((i + 17) % 32)) (u32Bit x ((i + 19) % 32))) (if i + 10 < 32 then u32Bit x (i + 10) else 0) % P
      by_cases hlt : i + 10 < 32
      · simp only [hlt, ↓reduceIte]
        rw [evalPoly_pXor3 env _ _ _ (u32Bit x ((i + 17) % 32)) (u32Bit x ((i + 19) % 32)) (u32Bit x (i + 10))
          (hgx _ (Nat.mod_lt _ (by decide))) (hgx _ (Nat.mod_lt _ (by decide))) (hgx _ hlt)
          (u32Bit_bool _ _) (u32Bit_bool _ _) (u32Bit_bool _ _)]
        rfl
      · simp only [hlt, ↓reduceIte]
        rw [evalPoly_pXor2 env _ _ (u32Bit x ((i + 17) % 32)) (u32Bit x ((i + 19) % 32))
          (hgx _ (Nat.mod_lt _ (by decide))) (hgx _ (Nat.mod_lt _ (by decide)))
          (u32Bit_bool _ _) (u32Bit_bool _ _)]
        have hxor0 : ∀ u, (u = 0 ∨ u = 1) → bitXor2 u 0 = u := by
          intro u hu; rcases hu with rfl | rfl <;> decide
        have hb2 : bitXor2 (u32Bit x ((i + 17) % 32)) (u32Bit x ((i + 19) % 32)) = 0 ∨
                   bitXor2 (u32Bit x ((i + 17) % 32)) (u32Bit x ((i + 19) % 32)) = 1 := by
          rcases u32Bit_bool x ((i + 17) % 32) with h1 | h1 <;>
          rcases u32Bit_bool x ((i + 19) % 32) with h2 | h2 <;>
          rw [h1, h2] <;> decide
        rw [hxor0 _ hb2])
  rw [hcongr, sumInt_eq_packBits, packBits_u32Bit]

theorem evalPoly_pChWord (env : Nat → Int) (ge gf gg : Nat → Poly) (e f g : UInt32)
    (hge : ∀ i, i < 32 → evalPoly env (ge i) % P = u32Bit e i % P)
    (hgf : ∀ i, i < 32 → evalPoly env (gf i) % P = u32Bit f i % P)
    (hgg : ∀ i, i < 32 → evalPoly env (gg i) % P = u32Bit g i % P) :
    evalPoly env (pChWord ge gf gg) % P = ((ch32 e f g).toNat : Int) % P := by
  unfold pChWord
  rw [evalPoly_pSumPow2, show (2 ^ 5 : Nat) = 32 from rfl]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (pAdd (gg i) (pMul (ge i) (pSub (gf i) (gg i))))))
    (fun i => ((2 ^ i : Nat) : Int) * u32Bit (ch32 e f g) i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      refine int_mod_mul_eq rfl ?_
      rw [evalPoly_pAdd]
      have hmul : evalPoly env (pMul (ge i) (pSub (gf i) (gg i))) % P =
          (u32Bit e i * (u32Bit f i - u32Bit g i)) % P := by
        rw [evalPoly_pMul]
        exact int_mod_mul_eq (hge i hi) (by rw [evalPoly_pSub]; exact int_mod_sub_eq (hgf i hi) (hgg i hi))
      rw [int_mod_add_eq (hgg i hi) hmul,
        ch_poly_exact _ _ _ (u32Bit_bool e i) (u32Bit_bool f i) (u32Bit_bool g i),
        u32Bit_ch32 e f g i hi])
  rw [hcongr, sumInt_eq_packBits, packBits_u32Bit]

theorem evalPoly_pMajWord (env : Nat → Int) (ga gb gc : Nat → Poly) (a b c : UInt32)
    (hga : ∀ i, i < 32 → evalPoly env (ga i) % P = u32Bit a i % P)
    (hgb : ∀ i, i < 32 → evalPoly env (gb i) % P = u32Bit b i % P)
    (hgc : ∀ i, i < 32 → evalPoly env (gc i) % P = u32Bit c i % P) :
    evalPoly env (pMajWord ga gb gc) % P = ((maj32 a b c).toNat : Int) % P := by
  unfold pMajWord
  rw [evalPoly_pSumPow2, show (2 ^ 5 : Nat) = 32 from rfl]
  have hcongr := sumInt_congr_mod_P 0
    (fun i => evalPoly env (pScale (2 ^ i) (pSub (pAdd (pAdd (pMul (ga i) (gb i)) (pMul (ga i) (gc i))) (pMul (gb i) (gc i)))
                         (pScale 2 (pMul (pMul (ga i) (gb i)) (gc i))))))
    (fun i => ((2 ^ i : Nat) : Int) * u32Bit (maj32 a b c) i) 32 (fun i hi => by
      simp only [Nat.zero_add]
      rw [evalPoly_pScale]
      refine int_mod_mul_eq rfl ?_
      have hab : evalPoly env (pMul (ga i) (gb i)) % P = (u32Bit a i * u32Bit b i) % P := by
        rw [evalPoly_pMul]; exact int_mod_mul_eq (hga i hi) (hgb i hi)
      have hac : evalPoly env (pMul (ga i) (gc i)) % P = (u32Bit a i * u32Bit c i) % P := by
        rw [evalPoly_pMul]; exact int_mod_mul_eq (hga i hi) (hgc i hi)
      have hbc : evalPoly env (pMul (gb i) (gc i)) % P = (u32Bit b i * u32Bit c i) % P := by
        rw [evalPoly_pMul]; exact int_mod_mul_eq (hgb i hi) (hgc i hi)
      have habc : evalPoly env (pScale 2 (pMul (pMul (ga i) (gb i)) (gc i))) % P =
          (2 * u32Bit a i * u32Bit b i * u32Bit c i) % P := by
        rw [evalPoly_pScale]
        have hre : 2 * u32Bit a i * u32Bit b i * u32Bit c i =
            (2 : Int) * (u32Bit a i * u32Bit b i * u32Bit c i) := by repeat rw [Int.mul_assoc]
        rw [hre]; refine int_mod_mul_eq rfl ?_
        rw [evalPoly_pMul]; exact int_mod_mul_eq hab (hgc i hi)
      have hsum : evalPoly env (pAdd (pAdd (pMul (ga i) (gb i)) (pMul (ga i) (gc i))) (pMul (gb i) (gc i))) % P =
          (u32Bit a i * u32Bit b i + u32Bit a i * u32Bit c i + u32Bit b i * u32Bit c i) % P := by
        rw [evalPoly_pAdd]
        exact int_mod_add_eq (by rw [evalPoly_pAdd]; exact int_mod_add_eq hab hac) hbc
      rw [evalPoly_pSub, int_mod_sub_eq hsum habc,
        maj_poly_exact _ _ _ (u32Bit_bool a i) (u32Bit_bool b i) (u32Bit_bool c i),
        u32Bit_maj32 a b c i])
  rw [hcongr, sumInt_eq_packBits, packBits_u32Bit]

-- ============================================================================

theorem free_w0_canon_sound
    (w0 a1 ca e1 ce w16 cw s16 : Int)
    (ha1 : 0 ≤ a1 ∧ a1 < TWO32)
    (hca : 0 ≤ ca ∧ ca < 8)
    (he1 : 0 ≤ e1 ∧ e1 < TWO32)
    (hce : 0 ≤ ce ∧ ce < 8)
    (hw16 : 0 ≤ w16 ∧ w16 < TWO32)
    (hcw : 0 ≤ cw ∧ cw < 4)
    (hs16 : 0 ≤ s16 ∧ s16 < 3 * TWO32)
    (k0a k0e : Int)
    (hk0a : 0 ≤ k0a ∧ k0a < 4 * TWO32)
    (hk0e : 0 ≤ k0e ∧ k0e < 4 * TWO32)
    (hEqA : (a1 + TWO32 * ca - k0a - w0) % P = 0)
    (hEqE : (e1 + TWO32 * ce - k0e - w0) % P = 0)
    (hEqW : (w16 + TWO32 * cw - s16 - w0) % P = 0) :
    ∃ w0c : Int, 0 ≤ w0c ∧ w0c < TWO32 ∧
      a1 = (k0a + w0c) % TWO32 ∧
      e1 = (k0e + w0c) % TWO32 ∧
      w16 = (s16 + w0c) % TWO32 := by
  let z := a1 + TWO32 * ca - k0a
  let w0c := z % TWO32
  have hw0c_lo : 0 ≤ w0c := Int.emod_nonneg z (by decide)
  have hw0c_hi : w0c < TWO32 := Int.emod_lt_of_pos z (by decide)
  rcases Int.dvd_of_emod_eq_zero hEqA with ⟨qA, hqA⟩
  rcases Int.dvd_of_emod_eq_zero hEqE with ⟨qE, hqE⟩
  rcases Int.dvd_of_emod_eq_zero hEqW with ⟨qW, hqW⟩
  have hDiffE : (e1 + TWO32 * ce - k0e) - z = P * (qE - qA) := by
    rw [Int.mul_sub]; omega
  have hqEA : qE - qA = 0 := by simp only [P, TWO32, z] at *; omega
  have hIntE : e1 + TWO32 * ce = k0e + z := by rw [hqEA] at hDiffE; omega
  have hDiffW : (w16 + TWO32 * cw - s16) - z = P * (qW - qA) := by
    rw [Int.mul_sub]; omega
  have hqWA : qW - qA = 0 := by simp only [P, TWO32, z] at *; omega
  have hIntW : w16 + TWO32 * cw = s16 + z := by rw [hqWA] at hDiffW; omega
  have hIntA : a1 + TWO32 * ca = k0a + z := by simp only [z]; omega
  have hmod_step : ∀ (x c k : Int), 0 ≤ x → x < TWO32 → x + TWO32 * c = k + z → x = (k + w0c) % TWO32 := by
    intro x c k hx0 hx1 heq
    have h1 : (k + w0c) % TWO32 = (k + z) % TWO32 := by
      simp only [w0c]
      rw [Int.add_emod, Int.emod_emod, ← Int.add_emod]
    rw [h1, ← heq, Int.add_emod, Int.mul_emod_right, Int.add_zero, Int.emod_emod, Int.emod_eq_of_lt hx0 hx1]
  exact ⟨w0c, hw0c_lo, hw0c_hi,
    hmod_step a1 ca k0a ha1.1 ha1.2 hIntA,
    hmod_step e1 ce k0e he1.1 he1.2 hIntE,
    hmod_step w16 cw s16 hw16.1 hw16.2 hIntW⟩

-- ============================================================================
-- SECTION 8: RAW 8,192 x 247 GOLDILOCKS AIR -> AcceptedSpendTrace -> ValidSpendWitness
-- ============================================================================

/-- Raw 8,192 × 247 Goldilocks base-field execution trace (exact `TraceTable<Felt>` domain). -/
structure RawFieldTrace where
  cell   : Nat → Nat → Int
  hRange : ∀ r c, r < 8192 → c < W_COLS → 0 ≤ cell r c ∧ cell r c < P

/-- Exact closed-form periodic selector table matching `spend::periodic_table()` row-for-row
    across all 8,192 rows × 14 selectors (`P_K .. P_RHOC`). -/
def periodicVal (r s : Nat) : Int :=
  let b := r / 64
  let t := r % 64
  match s with
  | 0  => ((K[(t + 1) % 64]!).toNat : Int)
  | 1  => if 1 ≤ b ∧ b ≤ 72 ∧ t < 63 then 1 else 0
  | 2  => if 1 ≤ b ∧ b ≤ 72 ∧ t = 63 then 1 else 0
  | 3  => if t = 63 ∧ (b = 0 ∨ b = 35) then 1 else 0
  | 4  => if t = 63 ∧ (b = 1 ∨ b = 36) then 1 else 0
  | 5  => if t = 63 ∧ ((2 ≤ b ∧ b ≤ 33) ∨ (37 ≤ b ∧ b ≤ 68)) then 1 else 0
  | 6  => if t = 63 ∧ (b = 34 ∨ b = 69) then 1 else 0
  | 7  => if t = 63 ∧ (b = 70 ∨ b = 71) then 1 else 0
  | 8  => if t = 63 ∧ 2 ≤ b ∧ b ≤ 33 then ((2 ^ (b - 2) : Nat) : Int)
          else if t = 63 ∧ 37 ≤ b ∧ b ≤ 68 then ((2 ^ (b - 37) : Nat) : Int)
          else 0
  | 9  => if t = 8 ∧ (b = 2 ∨ b = 37 ∨ b = 71 ∨ b = 72) then 1 else 0
  | 10 => if 1 ≤ b ∧ b ≤ 72 then 1 else 0
  | 11 => if 64 ≤ r ∧ r < 4671 then 1 else 0
  | 12 => (if 64 ≤ r ∧ r < 4671 then 1 else 0) * (1 - (if t = 63 ∧ (b = 0 ∨ b = 35) then 1 else 0))
  | 13 => (if 64 ≤ r ∧ r < 4671 then 1 else 0) * (1 - (if t = 63 ∧ (b = 1 ∨ b = 36) then 1 else 0))
  | _  => 0

/-- Evaluation environment on transition frame `(row r, row r+1, periodic[r])`. -/
def rowEnv (T : RawFieldTrace) (r : Nat) (v : Nat) : Int :=
  if v < W_COLS then T.cell r v
  else if v < 2 * W_COLS then T.cell (r + 1) (v - W_COLS)
  else periodicVal r (v - 2 * W_COLS)

/-- ALL 249 live Rust extracted transition constraints vanish modulo Goldilocks `P` on every
    adjacent row pair `(r, r + 1)` for `r < 8191`. -/
def RawAirTransitionsHold (T : RawFieldTrace) : Prop :=
  ∀ r, r < 8191 → ∀ i, i < 249 → evalPoly (rowEnv T r) (rustCon i) % P = 0

/-- Exact boundary assertions matching `spend::assertion_cells(&pi)` (`spend.rs:521-546`). -/
structure RawBoundaryAssertions (pi : SpendPublicStmt) (T : RawFieldTrace) : Prop where
  hBal0   : T.cell 64 COL_BAL = 0
  hPos0   : T.cell 64 COL_POS = 0
  hDummy0 : pi.dummy0 = true → T.cell (2 * 64) (COL_W + 9) = 0 ∧ T.cell (2 * 64) (COL_W + 10) = 0
  hRoot0  : pi.dummy0 = false → ∀ j : Fin 8, T.cell (34 * 64 + 63) (COL_DIG + j.val) = ((pi.root j).toNat : Int)
  hNf0    : ∀ j : Fin 8, T.cell (35 * 64 + 63) (COL_DIG + j.val) = ((pi.nf0 j).toNat : Int)
  hDummy1 : pi.dummy1 = true → T.cell (37 * 64) (COL_W + 9) = 0 ∧ T.cell (37 * 64) (COL_W + 10) = 0
  hRoot1  : pi.dummy1 = false → ∀ j : Fin 8, T.cell (69 * 64 + 63) (COL_DIG + j.val) = ((pi.root j).toNat : Int)
  hNf1    : ∀ j : Fin 8, T.cell (70 * 64 + 63) (COL_DIG + j.val) = ((pi.nf1 j).toNat : Int)
  hOut0   : ∀ j : Fin 8, T.cell (71 * 64 + 63) (COL_DIG + j.val) = ((pi.cmOut0 j).toNat : Int)
  hOut1   : ∀ j : Fin 8, T.cell (72 * 64 + 63) (COL_DIG + j.val) = ((pi.cmOut1 j).toNat : Int)
  hBalEnd : T.cell (72 * 64 + 63) COL_BAL = signedField pi.valueBalance

-- ---- Basic arithmetic & evaluation helpers ----

theorem rawCon_zero {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    {r i : Nat} (hr : r < 8191) (hi : i < 249) :
    evalPoly (rowEnv T r) (fipsCon i) % P = 0 := by
  rw [← all_249_constraints_match_fips180_4_spec i hi]
  exact hT r hr i hi

theorem evalPoly_vCur (T : RawFieldTrace) (r c : Nat) (hc : c < W_COLS) :
    evalPoly (rowEnv T r) (vCur c) = T.cell r c := by
  simp [vCur, evalPoly_pVar, rowEnv, hc]

theorem evalPoly_vNxt (T : RawFieldTrace) (r c : Nat) (hc : c < W_COLS) :
    evalPoly (rowEnv T r) (vNxt c) = T.cell (r + 1) c := by
  have h1 : ¬ (W_COLS + c < W_COLS) := by omega
  have h2 : W_COLS + c < 2 * W_COLS := by omega
  simp [vNxt, evalPoly_pVar, rowEnv, h1, h2]

theorem evalPoly_vPer (T : RawFieldTrace) (r s : Nat) :
    evalPoly (rowEnv T r) (vPer s) = periodicVal r s := by
  have h1 : ¬ (2 * W_COLS + s < W_COLS) := by simp [W_COLS]; omega
  have h2 : ¬ (2 * W_COLS + s < 2 * W_COLS) := by omega
  simp [vPer, evalPoly_pVar, rowEnv, h1, h2]

theorem field_eq_of_sub_mod_P {x y : Int} (hx0 : 0 ≤ x) (hxP : x < P)
    (hy0 : 0 ≤ y) (hyP : y < P) (h : (x - y) % P = 0) : x = y := by
  rcases Int.dvd_of_emod_eq_zero h with ⟨q, hq⟩
  have hq0 : q = 0 := by simp only [P] at *; omega
  rw [hq0] at hq; omega

theorem u32_ofNat_toNat_int (x : Int) (hx0 : 0 ≤ x) (hx1 : x < TWO32) :
    ((UInt32.ofNat x.toNat).toNat : Int) = x := by
  have hnat : x.toNat < 2 ^ 32 := by simp only [TWO32] at hx1; omega
  have h1 : (UInt32.ofNat x.toNat).toNat = x.toNat := by
    simp [UInt32.toNat_ofNat', Nat.mod_eq_of_lt hnat]
  rw [h1]; omega

theorem u32_add_toNat_int (x y : UInt32) :
    ((x + y).toNat : Int) = ((x.toNat : Int) + (y.toNat : Int)) % TWO32 := by
  have h : (x + y).toNat = (x.toNat + y.toNat) % 2 ^ 32 := UInt32.toNat_add x y
  rw [h, Int.natCast_emod, Int.natCast_add]; rfl


theorem mod_add_l (x y : Int) : (x % TWO32 + y) % TWO32 = (x + y) % TWO32 := by
  rw [Int.add_emod, Int.emod_emod, ← Int.add_emod]

theorem mod_add_r (x y : Int) : (x + y % TWO32) % TWO32 = (x + y) % TWO32 := by
  rw [Int.add_emod, Int.emod_emod, ← Int.add_emod]

theorem u32_toNat_lt_two32 (x : UInt32) : (x.toNat : Int) < TWO32 := by
  have h : x.toNat < 2 ^ 32 := by rw [← UInt32.toNat_toBitVec]; exact x.toBitVec.isLt
  simp only [TWO32]; omega

theorem u32_toNat_lt_P (x : UInt32) : (x.toNat : Int) < P := by
  have := u32_toNat_lt_two32 x; simp only [TWO32, P] at *; omega

theorem beq_eq_false {a b : Nat} (h : a ≠ b) : (a == b) = false := beq_false_of_ne h

theorem u32_eq_of_toNat_int {x y : UInt32} (h : (x.toNat : Int) = (y.toNat : Int)) : x = y :=
  UInt32.eq_of_toBitVec_eq (BitVec.eq_of_toNat_eq (Int.ofNat.inj h))

theorem iv_toNat_eq_ivNat : ∀ j, j < 8 → (IV[j]!).toNat = ivNat j := by decide

theorem k0a_bounds : 0 ≤ (k0aConst : Int) ∧ (k0aConst : Int) < 4 * TWO32 := by decide
theorem k0e_bounds : 0 ≤ (k0eConst : Int) ∧ (k0eConst : Int) < 4 * TWO32 := by decide

theorem round0_a_toNat (w0 : UInt32) :
    ((sha256Round sha256Init K[0]! w0).a.toNat : Int) = ((k0aConst : Int) + (w0.toNat : Int)) % TWO32 := by
  unfold sha256Round sha256Init k0aConst
  dsimp only
  simp only [u32_add_toNat_int, mod_add_l, mod_add_r, Int.natCast_add]
  have h7 : (IV[7]!).toNat = ivNat 7 := by decide
  rw [h7]
  exact congrArg (· % TWO32) (by omega)

theorem round0_e_toNat (w0 : UInt32) :
    ((sha256Round sha256Init K[0]! w0).e.toNat : Int) = ((k0eConst : Int) + (w0.toNat : Int)) % TWO32 := by
  unfold sha256Round sha256Init k0eConst
  dsimp only
  simp only [u32_add_toNat_int, mod_add_l, mod_add_r, Int.natCast_add]
  have h3 : (IV[3]!).toNat = ivNat 3 := by decide
  have h7 : (IV[7]!).toNat = ivNat 7 := by decide
  rw [h3, h7]
  exact congrArg (· % TWO32) (by omega)

-- ---- SHA-256 Schedule indexing lemmas ----

theorem sha256ScheduleStep_size (w : Array UInt32) (n : Nat) :
    (sha256ScheduleStep w n).size = w.size + n := by
  induction n generalizing w with
  | zero => simp [sha256ScheduleStep]
  | succ k ih =>
    simp only [sha256ScheduleStep]
    rw [ih, Array.size_push]
    omega

theorem arr_getBang_eq_getElem (a : Array UInt32) (i : Nat) (hi : i < a.size) :
    a[i]! = a[i] := by
  exact getElem!_pos a i hi

theorem sha256ScheduleStep_prefix (w : Array UInt32) (n : Nat) :
    ∀ k, k < w.size → (sha256ScheduleStep w n)[k]! = w[k]! := by
  induction n generalizing w with
  | zero => intro k _; simp [sha256ScheduleStep]
  | succ m ih =>
    intro k hk
    simp only [sha256ScheduleStep]
    let wi := smallS1 w[w.size - 2]! + w[w.size - 7]! + smallS0 w[w.size - 15]! + w[w.size - 16]!
    have hlt : k < (w.push wi).size := by rw [Array.size_push]; omega
    rw [ih (w.push wi) k hlt, arr_getBang_eq_getElem (w.push wi) k hlt, arr_getBang_eq_getElem w k hk, Array.getElem_push_lt hk]

theorem sha256ScheduleStep_step (w : Array UInt32) (n : Nat) (hw : 16 ≤ w.size) :
    ∀ k, k < n →
      let res := sha256ScheduleStep w n
      res[w.size + k]! =
        smallS1 res[w.size + k - 2]! + res[w.size + k - 7]! +
        smallS0 res[w.size + k - 15]! + res[w.size + k - 16]! := by
  induction n generalizing w with
  | zero => intro k hk; omega
  | succ m ih =>
    intro k hk
    simp only [sha256ScheduleStep]
    let wi := smallS1 w[w.size - 2]! + w[w.size - 7]! + smallS0 w[w.size - 15]! + w[w.size - 16]!
    let w' := w.push wi
    cases k with
    | zero =>
      have hsz : w.size < w'.size := by simp [w', Array.size_push]
      rw [Nat.add_zero]
      rw [sha256ScheduleStep_prefix w' m w.size hsz]
      rw [sha256ScheduleStep_prefix w' m (w.size - 2) (by simp [w', Array.size_push]; omega)]
      rw [sha256ScheduleStep_prefix w' m (w.size - 7) (by simp [w', Array.size_push]; omega)]
      rw [sha256ScheduleStep_prefix w' m (w.size - 15) (by simp [w', Array.size_push]; omega)]
      rw [sha256ScheduleStep_prefix w' m (w.size - 16) (by simp [w', Array.size_push]; omega)]
      have hget_last : w'[w.size]! = wi := by
        rw [arr_getBang_eq_getElem w' w.size hsz]
        simp [w', Array.getElem_push_eq]
      have hget_lt : ∀ j, j < w.size → w'[j]! = w[j]! := fun j hj => by
        rw [arr_getBang_eq_getElem w' j (by simp [w', Array.size_push]; omega),
            arr_getBang_eq_getElem w j hj]
        exact Array.getElem_push_lt hj
      rw [hget_last, hget_lt (w.size - 2) (by omega), hget_lt (w.size - 7) (by omega),
          hget_lt (w.size - 15) (by omega), hget_lt (w.size - 16) (by omega)]
    | succ j =>
      have hw' : 16 ≤ w'.size := by simp [w', Array.size_push]; omega
      have hstep := ih w' hw' j (by omega)
      have hidx : w.size + (j + 1) = w'.size + j := by simp [w', Array.size_push]; omega
      simpa [w', wi, hidx] using hstep

theorem sha256Schedule_init (blk : Array UInt32) (hsz : blk.size = 16) (k : Nat) (hk : k < 16) :
    (sha256Schedule blk)[k]! = blk[k]! :=
  sha256ScheduleStep_prefix blk 48 k (by omega)

theorem sha256Schedule_step (blk : Array UInt32) (hsz : blk.size = 16) (t : Nat) (ht : t < 48) :
    (sha256Schedule blk)[t + 16]! =
      smallS1 (sha256Schedule blk)[t + 14]! + (sha256Schedule blk)[t + 9]! +
      smallS0 (sha256Schedule blk)[t + 1]! + (sha256Schedule blk)[t]! := by
  have h := sha256ScheduleStep_step blk 48 (by omega) t ht
  simp only [sha256Schedule]
  have h1 : blk.size + t = t + 16 := by omega
  have h2 : blk.size + t - 2 = t + 14 := by omega
  have h3 : blk.size + t - 7 = t + 9 := by omega
  have h4 : blk.size + t - 15 = t + 1 := by omega
  have h5 : blk.size + t - 16 = t := by omega
  simpa [h1, h2, h3, h4, h5] using h

-- ---- Periodic selector arithmetic helpers ----

def pIvVal (r : Nat) : Int :=
  periodicVal r 3 + periodicVal r 4 + periodicVal r 5 + periodicVal r 6 + periodicVal r 7

theorem row_div_mod (b t : Nat) (ht : t < 64) : (b * 64 + t) / 64 = b ∧ (b * 64 + t) % 64 = t := by
  omega

theorem periodic_inner (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) :
    periodicVal (b * 64 + t) 0 = ((K[t + 1]!).toNat : Int) ∧
    periodicVal (b * 64 + t) 1 = 1 ∧
    periodicVal (b * 64 + t) 2 = 0 ∧
    periodicVal (b * 64 + t) 3 = 0 ∧
    periodicVal (b * 64 + t) 4 = 0 ∧
    periodicVal (b * 64 + t) 5 = 0 ∧
    periodicVal (b * 64 + t) 6 = 0 ∧
    periodicVal (b * 64 + t) 7 = 0 ∧
    periodicVal (b * 64 + t) 8 = 0 ∧
    periodicVal (b * 64 + t) 10 = 1 ∧
    periodicVal (b * 64 + t) 11 = 1 ∧
    periodicVal (b * 64 + t) 12 = 1 ∧
    periodicVal (b * 64 + t) 13 = 1 ∧
    pIvVal (b * 64 + t) = 0 := by
  have hd : (b * 64 + t) / 64 = b := by omega
  have hm : (b * 64 + t) % 64 = t := by omega
  have hm1 : (t + 1) % 64 = t + 1 := Nat.mod_eq_of_lt (by omega)
  have hne63 : t ≠ 63 := by omega
  have hr64 : 64 ≤ b * 64 + t := by omega
  have hr4671 : b * 64 + t < 4671 := by omega
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp [periodicVal, pIvVal, hd, hm, hm1, hb1, hb72, ht, hne63, hr64, hr4671]

theorem periodic_active_row (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    periodicVal (b * 64 + t) 10 = 1 := by
  have hd : (b * 64 + t) / 64 = b := by omega
  simp [periodicVal, hd, hb1, hb72]

theorem periodic_last_row (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    periodicVal (b * 64 + 63) 1 = 0 ∧
    periodicVal (b * 64 + 63) 2 = 1 ∧
    periodicVal (b * 64 + 63) 10 = 1 := by
  have hd : (b * 64 + 63) / 64 = b := by omega
  have hm : (b * 64 + 63) % 64 = 63 := by omega
  refine ⟨?_, ?_, ?_⟩ <;> simp [periodicVal, hd, hm, hb1, hb72]

theorem periodic_pre_block (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    periodicVal ((b - 1) * 64 + 63) 1 = 0 ∧
    pIvVal ((b - 1) * 64 + 63) = 1 := by
  have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
  have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
  constructor
  · simp [periodicVal, hd, hm]
  · simp only [pIvVal, periodicVal, hd, hm, true_and]
    split <;> split <;> split <;> split <;> split <;> omega

-- ---- Helper for carry3 ----

def carry3Val (T : RawFieldTrace) (r col : Nat) : Int :=
  T.cell r col + 2 * T.cell r (col + 1) + 4 * T.cell r (col + 2)

theorem evalPoly_carry3 (T : RawFieldTrace) (r col : Nat) (hcol : col + 2 < W_COLS) :
    evalPoly (rowEnv T r)
      (pAdd (pAdd (vNxt col) (pScale 2 (vNxt (col + 1)))) (pScale 4 (vNxt (col + 2)))) % P =
    carry3Val T (r + 1) col % P := by
  unfold carry3Val
  rw [evalPoly_pAdd]
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pAdd]
    refine int_mod_add_eq (by rw [evalPoly_vNxt T r col (by omega)]) ?_
    rw [evalPoly_pScale, evalPoly_vNxt T r (col + 1) (by omega)]; rfl
  · rw [evalPoly_pScale, evalPoly_vNxt T r (col + 2) (by omega)]; rfl

theorem evalPoly_pIv (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r)
      (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7)) % P =
    pIvVal r % P := by
  unfold pIvVal
  repeat (rw [evalPoly_pAdd]; refine int_mod_add_eq ?_ ?_)
  all_goals rw [evalPoly_vPer]

-- ---- Unpacking lemmas for ALL 249 constraints (`fipsCon 0..248`) ----

-- #96..#223 (128 bit booleanity constraints: COL_A, COL_E, COL_X1, COL_X14)
theorem eval_fipsCon_bool128 (T : RawFieldTrace) (r k : Nat) (hk : k < 128) :
    let base := if k < 32 then COL_A else if k < 64 then COL_E else if k < 96 then COL_X1 else COL_X14
    let col := base + (k % 32)
    evalPoly (rowEnv T r) (fipsCon (96 + k)) % P =
      (periodicVal r 10 * (T.cell r col * (T.cell r col - 1))) % P := by
  intro base col
  have hcol : col < W_COLS := by
    simp only [col, base, COL_A, COL_E, COL_X1, COL_X14, W_COLS]
    by_cases h1 : k < 32
    · simp [h1]; omega
    · by_cases h2 : k < 64
      · simp [h1, h2]; omega
      · by_cases h3 : k < 96
        · simp [h1, h2, h3]; omega
        · simp [h1, h2, h3]; omega
  have hspec : fipsCon (96 + k) =
      pMul (vPer 10) (pMul (vCur col) (pSub (vCur col) (pConst 1))) := by
    unfold fipsCon
    have h1 : (96 + k == 0) = false := beq_eq_false (by omega)
    have h2 : (96 + k == 1) = false := beq_eq_false (by omega)
    have h3 : (96 + k == 2) = false := beq_eq_false (by omega)
    have h4 : (96 + k == 3) = false := beq_eq_false (by omega)
    have h5 : ¬ (96 + k < 36) := by omega
    have h6 : ¬ (96 + k < 68) := by omega
    have h7 : (96 + k == 68) = false := beq_eq_false (by omega)
    have h8 : (96 + k == 69) = false := beq_eq_false (by omega)
    have h9 : ¬ (96 + k < 86) := by omega
    have h10 : (96 + k == 86) = false := beq_eq_false (by omega)
    have h11 : (96 + k == 87) = false := beq_eq_false (by omega)
    have h12 : ¬ (96 + k < 96) := by omega
    have h13 : 96 + k < 224 := by omega
    simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
    rfl
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pMul, evalPoly_vCur T r col hcol]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vCur T r col hcol]
  exact int_mod_sub_eq rfl (evalPoly_pConst _ 1)

def bool9Col : Nat → Nat
  | 0 => COL_CA
  | 1 => COL_CA + 1
  | 2 => COL_CA + 2
  | 3 => COL_CE
  | 4 => COL_CE + 1
  | 5 => COL_CE + 2
  | 6 => COL_CWC
  | 7 => COL_CWC + 1
  | _ => COL_BIT

-- #224..#232 (9 carry & bit booleanity constraints)
theorem eval_fipsCon_bool9 (T : RawFieldTrace) (r k : Nat) (hk : k < 9) :
    evalPoly (rowEnv T r) (fipsCon (224 + k)) % P =
      (periodicVal r 10 * (T.cell r (bool9Col k) * (T.cell r (bool9Col k) - 1))) % P := by
  have hcol : bool9Col k < W_COLS := by
    have : k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 3 ∨ k = 4 ∨ k = 5 ∨ k = 6 ∨ k = 7 ∨ k = 8 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> decide
  have hspec : fipsCon (224 + k) =
      pMul (vPer 10) (pMul (vCur (bool9Col k)) (pSub (vCur (bool9Col k)) (pConst 1))) := by
    unfold fipsCon
    have h1 : (224 + k == 0) = false := beq_eq_false (by omega)
    have h2 : (224 + k == 1) = false := beq_eq_false (by omega)
    have h3 : (224 + k == 2) = false := beq_eq_false (by omega)
    have h4 : (224 + k == 3) = false := beq_eq_false (by omega)
    have h5 : ¬ (224 + k < 36) := by omega
    have h6 : ¬ (224 + k < 68) := by omega
    have h7 : (224 + k == 68) = false := beq_eq_false (by omega)
    have h8 : (224 + k == 69) = false := beq_eq_false (by omega)
    have h9 : ¬ (224 + k < 86) := by omega
    have h10 : (224 + k == 86) = false := beq_eq_false (by omega)
    have h11 : (224 + k == 87) = false := beq_eq_false (by omega)
    have h12 : ¬ (224 + k < 96) := by omega
    have h13 : ¬ (224 + k < 224) := by omega
    have h14 : 224 + k < 233 := by omega
    simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
    have : k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 3 ∨ k = 4 ∨ k = 5 ∨ k = 6 ∨ k = 7 ∨ k = 8 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> rfl
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pMul, evalPoly_vCur T r (bool9Col k) hcol]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vCur T r (bool9Col k) hcol]
  exact int_mod_sub_eq rfl (evalPoly_pConst _ 1)

-- Active-row booleanity theorems derived immediately via goldilocks_boolean_sound!
theorem raw_bool_A {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    T.cell (b * 64 + t) (COL_A + j) = 0 ∨ T.cell (b * 64 + t) (COL_A + j) = 1 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 96 + j) (by omega) (by omega)
  rw [eval_fipsCon_bool128 T (b * 64 + t) j (by omega)] at hz
  have hact := periodic_active_row b t hb1 hb72 ht
  have hmod : j % 32 = j := Nat.mod_eq_of_lt hj
  simp only [hj, ↓reduceIte, hact, hmod, Int.one_mul] at hz
  have hr := T.hRange (b * 64 + t) (COL_A + j) (by omega) (by simp [COL_A, W_COLS]; omega)
  exact goldilocks_boolean_sound hr.1 hr.2 hz

theorem raw_bool_E {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    T.cell (b * 64 + t) (COL_E + j) = 0 ∨ T.cell (b * 64 + t) (COL_E + j) = 1 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 96 + (32 + j)) (by omega) (by omega)
  rw [eval_fipsCon_bool128 T (b * 64 + t) (32 + j) (by omega)] at hz
  have hact := periodic_active_row b t hb1 hb72 ht
  have h1 : ¬ (32 + j < 32) := by omega
  have h2 : 32 + j < 64 := by omega
  have hmod : (32 + j) % 32 = j := by omega
  simp only [h1, h2, ↓reduceIte, hact, hmod, Int.one_mul] at hz
  have hr := T.hRange (b * 64 + t) (COL_E + j) (by omega) (by simp [COL_E, W_COLS]; omega)
  exact goldilocks_boolean_sound hr.1 hr.2 hz

theorem raw_bool_X1 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    T.cell (b * 64 + t) (COL_X1 + j) = 0 ∨ T.cell (b * 64 + t) (COL_X1 + j) = 1 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 96 + (64 + j)) (by omega) (by omega)
  rw [eval_fipsCon_bool128 T (b * 64 + t) (64 + j) (by omega)] at hz
  have hact := periodic_active_row b t hb1 hb72 ht
  have h1 : ¬ (64 + j < 32) := by omega
  have h2 : ¬ (64 + j < 64) := by omega
  have h3 : 64 + j < 96 := by omega
  have hmod : (64 + j) % 32 = j := by omega
  simp only [h1, h2, h3, ↓reduceIte, hact, hmod, Int.one_mul] at hz
  have hr := T.hRange (b * 64 + t) (COL_X1 + j) (by omega) (by simp [COL_X1, W_COLS]; omega)
  exact goldilocks_boolean_sound hr.1 hr.2 hz

theorem raw_bool_X14 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    T.cell (b * 64 + t) (COL_X14 + j) = 0 ∨ T.cell (b * 64 + t) (COL_X14 + j) = 1 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 96 + (96 + j)) (by omega) (by omega)
  rw [eval_fipsCon_bool128 T (b * 64 + t) (96 + j) (by omega)] at hz
  have hact := periodic_active_row b t hb1 hb72 ht
  have h1 : ¬ (96 + j < 32) := by omega
  have h2 : ¬ (96 + j < 64) := by omega
  have h3 : ¬ (96 + j < 96) := by omega
  have hmod : (96 + j) % 32 = j := by omega
  simp only [h1, h2, h3, ↓reduceIte, hact, hmod, Int.one_mul] at hz
  have hr := T.hRange (b * 64 + t) (COL_X14 + j) (by omega) (by simp [COL_X14, W_COLS]; omega)
  exact goldilocks_boolean_sound hr.1 hr.2 hz

theorem raw_bool9 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t k : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hk : k < 9) :
    T.cell (b * 64 + t) (bool9Col k) = 0 ∨ T.cell (b * 64 + t) (bool9Col k) = 1 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 224 + k) (by omega) (by omega)
  rw [eval_fipsCon_bool9 T (b * 64 + t) k hk] at hz
  have hact := periodic_active_row b t hb1 hb72 ht
  simp only [hact, Int.one_mul] at hz
  have hcol : bool9Col k < W_COLS := by
    have : k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 3 ∨ k = 4 ∨ k = 5 ∨ k = 6 ∨ k = 7 ∨ k = 8 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> decide
  have hr := T.hRange (b * 64 + t) (bool9Col k) (by omega) hcol
  exact goldilocks_boolean_sound hr.1 hr.2 hz

theorem raw_carry3_ca_bounds {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    0 ≤ carry3Val T (b * 64 + t) COL_CA ∧ carry3Val T (b * 64 + t) COL_CA < 8 := by
  have h0 := raw_bool9 hT b t 0 hb1 hb72 ht (by omega)
  have h1 := raw_bool9 hT b t 1 hb1 hb72 ht (by omega)
  have h2 := raw_bool9 hT b t 2 hb1 hb72 ht (by omega)
  simp only [carry3Val, bool9Col] at *
  rcases h0 with h0 | h0 <;> rcases h1 with h1 | h1 <;> rcases h2 with h2 | h2 <;>
    rw [h0, h1, h2] <;> omega

theorem raw_carry3_ce_bounds {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    0 ≤ carry3Val T (b * 64 + t) COL_CE ∧ carry3Val T (b * 64 + t) COL_CE < 8 := by
  have h0 := raw_bool9 hT b t 3 hb1 hb72 ht (by omega)
  have h1 := raw_bool9 hT b t 4 hb1 hb72 ht (by omega)
  have h2 := raw_bool9 hT b t 5 hb1 hb72 ht (by omega)
  simp only [carry3Val, bool9Col] at *
  rcases h0 with h0 | h0 <;> rcases h1 with h1 | h1 <;> rcases h2 with h2 | h2 <;>
    rw [h0, h1, h2] <;> omega

theorem raw_cwc_bounds {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    0 ≤ T.cell (b * 64 + t) COL_CWC + 2 * T.cell (b * 64 + t) (COL_CWC + 1) ∧
    T.cell (b * 64 + t) COL_CWC + 2 * T.cell (b * 64 + t) (COL_CWC + 1) < 4 := by
  have h0 := raw_bool9 hT b t 6 hb1 hb72 ht (by omega)
  have h1 := raw_bool9 hT b t 7 hb1 hb72 ht (by omega)
  simp only [bool9Col] at *
  rcases h0 with h0 | h0 <;> rcases h1 with h1 | h1 <;> rw [h0, h1] <;> omega

-- ---- #2, #3, #4..#35, #36..#67, #68, #69 state shift unpacking ----

theorem eval_fipsCon_2 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 2) % P =
      (periodicVal r 1 * (packBits (fun j => T.cell (r + 1) (COL_A + j)) 32 - T.cell r COL_AN) +
       pIvVal r * (packBits (fun j => T.cell (r + 1) (COL_A + j)) 32 - (ivNat 0 : Int))) % P := by
  have hspec : fipsCon 2 =
      pAdd (pMul (vPer 1) (pSub (pWordBits (fun j => vNxt (COL_A + j))) (vCur COL_AN)))
           (pMul (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7))
                 (pSub (pWordBits (fun j => vNxt (COL_A + j))) (pConst (ivNat 0)))) := rfl
  rw [hspec, evalPoly_pAdd]
  have hwa : evalPoly (rowEnv T r) (pWordBits (fun j => vNxt (COL_A + j))) % P =
      packBits (fun j => T.cell (r + 1) (COL_A + j)) 32 % P :=
    evalPoly_pWordBits _ _ _ (fun j hj => by rw [evalPoly_vNxt T r (COL_A + j) (by simp [COL_A, W_COLS]; omega)])
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, evalPoly_vCur T r COL_AN (by decide)]
    exact int_mod_sub_eq hwa rfl
  · rw [evalPoly_pMul]
    refine int_mod_mul_eq (evalPoly_pIv T r) ?_
    rw [evalPoly_pSub]
    exact int_mod_sub_eq hwa (evalPoly_pConst _ (ivNat 0))

theorem eval_fipsCon_3 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 3) % P =
      (periodicVal r 1 * (packBits (fun j => T.cell (r + 1) (COL_E + j)) 32 - T.cell r COL_EN) +
       pIvVal r * (packBits (fun j => T.cell (r + 1) (COL_E + j)) 32 - (ivNat 4 : Int))) % P := by
  have hspec : fipsCon 3 =
      pAdd (pMul (vPer 1) (pSub (pWordBits (fun j => vNxt (COL_E + j))) (vCur COL_EN)))
           (pMul (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7))
                 (pSub (pWordBits (fun j => vNxt (COL_E + j))) (pConst (ivNat 4)))) := rfl
  rw [hspec, evalPoly_pAdd]
  have hwe : evalPoly (rowEnv T r) (pWordBits (fun j => vNxt (COL_E + j))) % P =
      packBits (fun j => T.cell (r + 1) (COL_E + j)) 32 % P :=
    evalPoly_pWordBits _ _ _ (fun j hj => by rw [evalPoly_vNxt T r (COL_E + j) (by simp [COL_E, W_COLS]; omega)])
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, evalPoly_vCur T r COL_EN (by decide)]
    exact int_mod_sub_eq hwe rfl
  · rw [evalPoly_pMul]
    refine int_mod_mul_eq (evalPoly_pIv T r) ?_
    rw [evalPoly_pSub]
    exact int_mod_sub_eq hwe (evalPoly_pConst _ (ivNat 4))

theorem eval_fipsCon_ap (T : RawFieldTrace) (r j : Nat) (hj : j < 32) :
    evalPoly (rowEnv T r) (fipsCon (4 + j)) % P =
      (periodicVal r 1 * (T.cell (r + 1) (COL_AP + j) - T.cell r (COL_A + j)) +
       pIvVal r * (T.cell (r + 1) (COL_AP + j) - (((ivNat 1) >>> j) &&& 1 : Nat))) % P := by
  have hspec : fipsCon (4 + j) =
      pAdd (pMul (vPer 1) (pSub (vNxt (COL_AP + j)) (vCur (COL_A + j))))
           (pMul (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7))
                 (pSub (vNxt (COL_AP + j)) (pConst (((ivNat 1) >>> j) &&& 1)))) := by
    unfold fipsCon
    have h1 : (4 + j == 0) = false := beq_eq_false (by omega)
    have h2 : (4 + j == 1) = false := beq_eq_false (by omega)
    have h3 : (4 + j == 2) = false := beq_eq_false (by omega)
    have h4 : (4 + j == 3) = false := beq_eq_false (by omega)
    have h5 : 4 + j < 36 := by omega
    simp only [h1, h2, h3, h4, h5, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
  rw [hspec, evalPoly_pAdd]
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r (COL_AP + j) (by simp [COL_AP, W_COLS]; omega),
        evalPoly_vCur T r (COL_A + j) (by simp [COL_A, W_COLS]; omega)]
  · rw [evalPoly_pMul]
    refine int_mod_mul_eq (evalPoly_pIv T r) ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r (COL_AP + j) (by simp [COL_AP, W_COLS]; omega)]
    exact int_mod_sub_eq rfl (evalPoly_pConst _ _)

theorem eval_fipsCon_ep (T : RawFieldTrace) (r j : Nat) (hj : j < 32) :
    evalPoly (rowEnv T r) (fipsCon (36 + j)) % P =
      (periodicVal r 1 * (T.cell (r + 1) (COL_EP + j) - T.cell r (COL_E + j)) +
       pIvVal r * (T.cell (r + 1) (COL_EP + j) - (((ivNat 5) >>> j) &&& 1 : Nat))) % P := by
  have hspec : fipsCon (36 + j) =
      pAdd (pMul (vPer 1) (pSub (vNxt (COL_EP + j)) (vCur (COL_E + j))))
           (pMul (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7))
                 (pSub (vNxt (COL_EP + j)) (pConst (((ivNat 5) >>> j) &&& 1)))) := by
    unfold fipsCon
    have h1 : (36 + j == 0) = false := beq_eq_false (by omega)
    have h2 : (36 + j == 1) = false := beq_eq_false (by omega)
    have h3 : (36 + j == 2) = false := beq_eq_false (by omega)
    have h4 : (36 + j == 3) = false := beq_eq_false (by omega)
    have h5 : ¬ (36 + j < 36) := by omega
    have h6 : 36 + j < 68 := by omega
    simp only [h1, h2, h3, h4, h5, h6, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
  rw [hspec, evalPoly_pAdd]
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega),
        evalPoly_vCur T r (COL_E + j) (by simp [COL_E, W_COLS]; omega)]
  · rw [evalPoly_pMul]
    refine int_mod_mul_eq (evalPoly_pIv T r) ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega)]
    exact int_mod_sub_eq rfl (evalPoly_pConst _ _)

theorem eval_fipsCon_68 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 68) % P =
      (periodicVal r 1 * (T.cell (r + 1) COL_CWORD - packBits (fun j => T.cell r (COL_AP + j)) 32) +
       pIvVal r * (T.cell (r + 1) COL_CWORD - (ivNat 2 : Int))) % P := by
  have hspec : fipsCon 68 =
      pAdd (pMul (vPer 1) (pSub (vNxt COL_CWORD) (pWordBits (fun j => vCur (COL_AP + j)))))
           (pMul (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7))
                 (pSub (vNxt COL_CWORD) (pConst (ivNat 2)))) := rfl
  rw [hspec, evalPoly_pAdd]
  have hcap : evalPoly (rowEnv T r) (pWordBits (fun j => vCur (COL_AP + j))) % P =
      packBits (fun j => T.cell r (COL_AP + j)) 32 % P :=
    evalPoly_pWordBits _ _ _ (fun j hj => by rw [evalPoly_vCur T r (COL_AP + j) (by simp [COL_AP, W_COLS]; omega)])
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r COL_CWORD (by decide)]
    exact int_mod_sub_eq rfl hcap
  · rw [evalPoly_pMul]
    refine int_mod_mul_eq (evalPoly_pIv T r) ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r COL_CWORD (by decide)]
    exact int_mod_sub_eq rfl (evalPoly_pConst _ (ivNat 2))

theorem eval_fipsCon_69 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 69) % P =
      (periodicVal r 1 * (T.cell (r + 1) COL_GWORD - packBits (fun j => T.cell r (COL_EP + j)) 32) +
       pIvVal r * (T.cell (r + 1) COL_GWORD - (ivNat 6 : Int))) % P := by
  have hspec : fipsCon 69 =
      pAdd (pMul (vPer 1) (pSub (vNxt COL_GWORD) (pWordBits (fun j => vCur (COL_EP + j)))))
           (pMul (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7))
                 (pSub (vNxt COL_GWORD) (pConst (ivNat 6)))) := rfl
  rw [hspec, evalPoly_pAdd]
  have hcep : evalPoly (rowEnv T r) (pWordBits (fun j => vCur (COL_EP + j))) % P =
      packBits (fun j => T.cell r (COL_EP + j)) 32 % P :=
    evalPoly_pWordBits _ _ _ (fun j hj => by rw [evalPoly_vCur T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega)])
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r COL_GWORD (by decide)]
    exact int_mod_sub_eq rfl hcep
  · rw [evalPoly_pMul]
    refine int_mod_mul_eq (evalPoly_pIv T r) ?_
    rw [evalPoly_pSub, evalPoly_vNxt T r COL_GWORD (by decide)]
    exact int_mod_sub_eq rfl (evalPoly_pConst _ (ivNat 6))

-- ---- #86, #87 range-check bit-decomposition unpacking ----

theorem eval_fipsCon_86 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 86) % P =
      (periodicVal r 1 * (T.cell r (COL_W + 1) - packBits (fun j => T.cell r (COL_X1 + j)) 32)) % P := by
  have hspec : fipsCon 86 = pMul (vPer 1) (pSub (vCur (COL_W + 1)) (pWordBits (fun j => vCur (COL_X1 + j)))) := rfl
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vCur T r (COL_W + 1) (by decide)]
  exact int_mod_sub_eq rfl
    (evalPoly_pWordBits _ _ _ (fun j hj => by rw [evalPoly_vCur T r (COL_X1 + j) (by simp [COL_X1, W_COLS]; omega)]))

theorem eval_fipsCon_87 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 87) % P =
      (periodicVal r 1 * (T.cell r (COL_W + 14) - packBits (fun j => T.cell r (COL_X14 + j)) 32)) % P := by
  have hspec : fipsCon 87 = pMul (vPer 1) (pSub (vCur (COL_W + 14)) (pWordBits (fun j => vCur (COL_X14 + j)))) := rfl
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vCur T r (COL_W + 14) (by decide)]
  exact int_mod_sub_eq rfl
    (evalPoly_pWordBits _ _ _ (fun j hj => by rw [evalPoly_vCur T r (COL_X14 + j) (by simp [COL_X14, W_COLS]; omega)]))

-- ---- #0 & #1 round constraints unpacking ----

theorem eval_fipsCon_0_iv (T : RawFieldTrace) (r : Nat) (hround : periodicVal r 1 = 0) :
    evalPoly (rowEnv T r) (fipsCon 0) % P =
      (pIvVal r * (T.cell (r + 1) COL_AN + TWO32 * carry3Val T (r + 1) COL_CA - (k0aConst : Int) - T.cell (r + 1) COL_W)) % P := by
  unfold fipsCon
  simp only [show (0 == 0) = true from rfl, ↓reduceIte]
  rw [evalPoly_pAdd, Int.add_emod, evalPoly_pMul (rowEnv T r) (vPer 1), evalPoly_vPer, hround,
      Int.zero_mul, Int.zero_emod, Int.zero_add, Int.emod_emod, evalPoly_pMul]
  refine int_mod_mul_eq (evalPoly_pIv T r) ?_
  rw [evalPoly_pSub, evalPoly_vNxt T r COL_W (by decide)]
  refine int_mod_sub_eq ?_ rfl
  rw [evalPoly_pSub]
  refine int_mod_sub_eq ?_ (evalPoly_pConst _ k0aConst)
  rw [evalPoly_pAdd, evalPoly_vNxt T r COL_AN (by decide)]
  refine int_mod_add_eq rfl ?_
  rw [evalPoly_pScale]
  exact int_mod_mul_eq rfl (evalPoly_carry3 T r COL_CA (by decide))

theorem eval_fipsCon_1_iv (T : RawFieldTrace) (r : Nat) (hround : periodicVal r 1 = 0) :
    evalPoly (rowEnv T r) (fipsCon 1) % P =
      (pIvVal r * (T.cell (r + 1) COL_EN + TWO32 * carry3Val T (r + 1) COL_CE - (k0eConst : Int) - T.cell (r + 1) COL_W)) % P := by
  unfold fipsCon
  simp only [show (1 == 0) = false from rfl, show (1 == 1) = true from rfl, Bool.false_eq_true, ↓reduceIte]
  rw [evalPoly_pAdd, Int.add_emod, evalPoly_pMul (rowEnv T r) (vPer 1), evalPoly_vPer, hround,
      Int.zero_mul, Int.zero_emod, Int.zero_add, Int.emod_emod, evalPoly_pMul]
  refine int_mod_mul_eq (evalPoly_pIv T r) ?_
  rw [evalPoly_pSub, evalPoly_vNxt T r COL_W (by decide)]
  refine int_mod_sub_eq ?_ rfl
  rw [evalPoly_pSub]
  refine int_mod_sub_eq ?_ (evalPoly_pConst _ k0eConst)
  rw [evalPoly_pAdd, evalPoly_vNxt T r COL_EN (by decide)]
  refine int_mod_add_eq rfl ?_
  rw [evalPoly_pScale]
  exact int_mod_mul_eq rfl (evalPoly_carry3 T r COL_CE (by decide))

theorem eval_fipsCon_0_round (T : RawFieldTrace) (r : Nat)
    (a b c e f g : UInt32)
    (hround : periodicVal r 1 = 1) (hiv : pIvVal r = 0)
    (ha : ∀ i, i < 32 → T.cell (r + 1) (COL_A + i) = u32Bit a i)
    (hb : ∀ i, i < 32 → T.cell (r + 1) (COL_AP + i) = u32Bit b i)
    (hc : ∀ i, i < 32 → T.cell r (COL_AP + i) = u32Bit c i)
    (he : ∀ i, i < 32 → T.cell (r + 1) (COL_E + i) = u32Bit e i)
    (hf : ∀ i, i < 32 → T.cell (r + 1) (COL_EP + i) = u32Bit f i)
    (hg : ∀ i, i < 32 → T.cell r (COL_EP + i) = u32Bit g i) :
    evalPoly (rowEnv T r) (fipsCon 0) % P =
      (T.cell (r + 1) COL_AN + TWO32 * carry3Val T (r + 1) COL_CA -
        (T.cell r COL_GWORD + ((bigS1 e).toNat : Int) + ((ch32 e f g).toNat : Int) +
         periodicVal r 0 + T.cell (r + 1) COL_W +
         ((bigS0 a).toNat : Int) + ((maj32 a b c).toNat : Int))) % P := by
  unfold fipsCon
  simp only [show (0 == 0) = true from rfl, ↓reduceIte]
  rw [evalPoly_pAdd, Int.add_emod,
      evalPoly_pMul (rowEnv T r) (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7)),
      Int.mul_emod, evalPoly_pIv, hiv, Int.zero_emod, Int.zero_mul, Int.zero_emod, Int.add_zero, Int.emod_emod,
      evalPoly_pMul, evalPoly_vPer, hround, Int.one_mul]
  rw [evalPoly_pSub]
  refine int_mod_sub_eq ?_ ?_
  · rw [evalPoly_pAdd, evalPoly_vNxt T r COL_AN (by decide)]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pScale]
    exact int_mod_mul_eq rfl (evalPoly_carry3 T r COL_CA (by decide))
  · have hS1 := evalPoly_pBigS1 (rowEnv T r) (fun j => vNxt (COL_E + j)) e
      (fun j hj => by rw [evalPoly_vNxt T r (COL_E + j) (by simp [COL_E, W_COLS]; omega), he j hj])
    have hCh := evalPoly_pChWord (rowEnv T r) (fun j => vNxt (COL_E + j)) (fun j => vNxt (COL_EP + j)) (fun j => vCur (COL_EP + j)) e f g
      (fun j hj => by rw [evalPoly_vNxt T r (COL_E + j) (by simp [COL_E, W_COLS]; omega), he j hj])
      (fun j hj => by rw [evalPoly_vNxt T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega), hf j hj])
      (fun j hj => by rw [evalPoly_vCur T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega), hg j hj])
    have hS0 := evalPoly_pBigS0 (rowEnv T r) (fun j => vNxt (COL_A + j)) a
      (fun j hj => by rw [evalPoly_vNxt T r (COL_A + j) (by simp [COL_A, W_COLS]; omega), ha j hj])
    have hMaj := evalPoly_pMajWord (rowEnv T r) (fun j => vNxt (COL_A + j)) (fun j => vNxt (COL_AP + j)) (fun j => vCur (COL_AP + j)) a b c
      (fun j hj => by rw [evalPoly_vNxt T r (COL_A + j) (by simp [COL_A, W_COLS]; omega), ha j hj])
      (fun j hj => by rw [evalPoly_vNxt T r (COL_AP + j) (by simp [COL_AP, W_COLS]; omega), hb j hj])
      (fun j hj => by rw [evalPoly_vCur T r (COL_AP + j) (by simp [COL_AP, W_COLS]; omega), hc j hj])
    repeat (rw [evalPoly_pAdd]; refine int_mod_add_eq ?_ ?_)
    · rw [evalPoly_vCur T r COL_GWORD (by decide)]
    · exact hS1
    · exact hCh
    · rw [evalPoly_vPer]
    · rw [evalPoly_vNxt T r COL_W (by decide)]
    · exact hS0
    · exact hMaj

theorem eval_fipsCon_1_round (T : RawFieldTrace) (r : Nat)
    (e f g : UInt32)
    (hround : periodicVal r 1 = 1) (hiv : pIvVal r = 0)
    (he : ∀ i, i < 32 → T.cell (r + 1) (COL_E + i) = u32Bit e i)
    (hf : ∀ i, i < 32 → T.cell (r + 1) (COL_EP + i) = u32Bit f i)
    (hg : ∀ i, i < 32 → T.cell r (COL_EP + i) = u32Bit g i) :
    evalPoly (rowEnv T r) (fipsCon 1) % P =
      (T.cell (r + 1) COL_EN + TWO32 * carry3Val T (r + 1) COL_CE -
        (T.cell r COL_CWORD +
         (T.cell r COL_GWORD + ((bigS1 e).toNat : Int) + ((ch32 e f g).toNat : Int) +
          periodicVal r 0 + T.cell (r + 1) COL_W))) % P := by
  unfold fipsCon
  simp only [show (1 == 0) = false from rfl, show (1 == 1) = true from rfl, Bool.false_eq_true, ↓reduceIte]
  rw [evalPoly_pAdd, Int.add_emod,
      evalPoly_pMul (rowEnv T r) (pAdd (pAdd (pAdd (pAdd (vPer 3) (vPer 4)) (vPer 5)) (vPer 6)) (vPer 7)),
      Int.mul_emod, evalPoly_pIv, hiv, Int.zero_emod, Int.zero_mul, Int.zero_emod, Int.add_zero, Int.emod_emod,
      evalPoly_pMul, evalPoly_vPer, hround, Int.one_mul]
  rw [evalPoly_pSub]
  refine int_mod_sub_eq ?_ ?_
  · rw [evalPoly_pAdd, evalPoly_vNxt T r COL_EN (by decide)]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pScale]
    exact int_mod_mul_eq rfl (evalPoly_carry3 T r COL_CE (by decide))
  · have hS1 := evalPoly_pBigS1 (rowEnv T r) (fun j => vNxt (COL_E + j)) e
      (fun j hj => by rw [evalPoly_vNxt T r (COL_E + j) (by simp [COL_E, W_COLS]; omega), he j hj])
    have hCh := evalPoly_pChWord (rowEnv T r) (fun j => vNxt (COL_E + j)) (fun j => vNxt (COL_EP + j)) (fun j => vCur (COL_EP + j)) e f g
      (fun j hj => by rw [evalPoly_vNxt T r (COL_E + j) (by simp [COL_E, W_COLS]; omega), he j hj])
      (fun j hj => by rw [evalPoly_vNxt T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega), hf j hj])
      (fun j hj => by rw [evalPoly_vCur T r (COL_EP + j) (by simp [COL_EP, W_COLS]; omega), hg j hj])
    rw [evalPoly_pAdd]
    refine int_mod_add_eq (by rw [evalPoly_vCur T r COL_CWORD (by decide)]) ?_
    repeat (rw [evalPoly_pAdd]; refine int_mod_add_eq ?_ ?_)
    · rw [evalPoly_vCur T r COL_GWORD (by decide)]
    · exact hS1
    · exact hCh
    · rw [evalPoly_vPer]
    · rw [evalPoly_vNxt T r COL_W (by decide)]

-- ---- #70..#85 message window & block-load unpacking ----

def msgLoadTerm (T : RawFieldTrace) (r j : Nat) : Int :=
  let nw := T.cell (r + 1) (COL_W + j)
  let tAddr := if j = 0 then (TAG_ADDR : Int) else if j ≤ 8 then T.cell (r + 1) (COL_SK + j - 1) else 0
  let cAddr := periodicVal r 3 * (nw - tAddr)
  let cCmIn :=
    if j = 0 then periodicVal r 4 * (nw - (TAG_CM : Int))
    else if j ≤ 8 then periodicVal r 4 * (nw - T.cell r (COL_DIG + j - 1))
    else if j ≥ 11 then periodicVal r 4 * (nw - T.cell (r + 1) (COL_RHO + j - 11))
    else 0
  let cMrk :=
    if j < 8 then periodicVal r 5 * (1 - T.cell (r + 1) COL_BIT) * (nw - T.cell r (COL_DIG + j))
    else periodicVal r 5 * T.cell (r + 1) COL_BIT * (nw - T.cell r (COL_DIG + j - 8))
  let tNf :=
    if j = 0 then (TAG_NF : Int)
    else if j ≤ 8 then T.cell (r + 1) (COL_SK + j - 1)
    else if j = 9 then T.cell (r + 1) COL_POS
    else if j ≤ 14 then T.cell (r + 1) (COL_RHO + j - 10)
    else 0
  let cNf := periodicVal r 6 * (nw - tNf)
  let cCmOut := if j = 0 then periodicVal r 7 * (nw - (TAG_CM : Int)) else 0
  cAddr + cCmIn + cMrk + cNf + cCmOut

theorem eval_msgLoad_tail (T : RawFieldTrace) (r j : Nat) (hj : j < 16) (r0 : Poly) :
    let nbit := vNxt COL_BIT
    let t_addr := if j == 0 then pConst TAG_ADDR else if j ≤ 8 then vNxt (COL_SK + j - 1) else []
    let r1 := pAdd r0 (pMul (vPer 3) (pSub (vNxt (COL_W + j)) t_addr))
    let r2 :=
      if j == 0 then pAdd r1 (pMul (vPer 4) (pSub (vNxt COL_W) (pConst TAG_CM)))
      else if j ≤ 8 then pAdd r1 (pMul (vPer 4) (pSub (vNxt (COL_W + j)) (vCur (COL_DIG + j - 1))))
      else if j ≥ 11 then pAdd r1 (pMul (vPer 4) (pSub (vNxt (COL_W + j)) (vNxt (COL_RHO + j - 11))))
      else r1
    let r3 :=
      if j < 8 then pAdd r2 (pMul (pMul (vPer 5) (pSub (pConst 1) nbit)) (pSub (vNxt (COL_W + j)) (vCur (COL_DIG + j))))
      else pAdd r2 (pMul (pMul (vPer 5) nbit) (pSub (vNxt (COL_W + j)) (vCur (COL_DIG + j - 8))))
    let t_nf :=
      if j == 0 then pConst TAG_NF
      else if j ≤ 8 then vNxt (COL_SK + j - 1)
      else if j == 9 then vNxt COL_POS
      else if j ≤ 14 then vNxt (COL_RHO + j - 10)
      else []
    let r4 := pAdd r3 (pMul (vPer 6) (pSub (vNxt (COL_W + j)) t_nf))
    let r5 := if j == 0 then pAdd r4 (pMul (vPer 7) (pSub (vNxt COL_W) (pConst TAG_CM))) else r4
    evalPoly (rowEnv T r) r5 % P = (evalPoly (rowEnv T r) r0 + msgLoadTerm T r j) % P := by
  intro nbit t_addr r1 r2 r3 t_nf r4 r5
  have hnw : evalPoly (rowEnv T r) (vNxt (COL_W + j)) = T.cell (r + 1) (COL_W + j) :=
    evalPoly_vNxt T r (COL_W + j) (by simp [COL_W, W_COLS]; omega)
  have hr1 : evalPoly (rowEnv T r) r1 % P =
      (evalPoly (rowEnv T r) r0 +
        periodicVal r 3 * (T.cell (r + 1) (COL_W + j) -
          (if j = 0 then (TAG_ADDR : Int) else if j ≤ 8 then T.cell (r + 1) (COL_SK + j - 1) else 0))) % P := by
    simp only [r1, t_addr]
    rw [evalPoly_pAdd]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, hnw]
    refine int_mod_sub_eq rfl ?_
    by_cases hj0 : j = 0
    · subst hj0; simp [evalPoly_pConst]
    · have hbeq : (j == 0) = false := beq_false_of_ne hj0
      simp only [hj0, hbeq, Bool.false_eq_true, ↓reduceIte]
      by_cases hj8 : j ≤ 8
      · simp only [hj8, ↓reduceIte]
        rw [evalPoly_vNxt T r (COL_SK + j - 1) (by simp [COL_SK, W_COLS]; omega)]
      · simp [hj8, evalPoly]
  have hr2 : evalPoly (rowEnv T r) r2 % P =
      (evalPoly (rowEnv T r) r1 +
        (if j = 0 then periodicVal r 4 * (T.cell (r + 1) (COL_W + j) - (TAG_CM : Int))
         else if j ≤ 8 then periodicVal r 4 * (T.cell (r + 1) (COL_W + j) - T.cell r (COL_DIG + j - 1))
         else if j ≥ 11 then periodicVal r 4 * (T.cell (r + 1) (COL_W + j) - T.cell (r + 1) (COL_RHO + j - 11))
         else 0)) % P := by
    simp only [r2]
    by_cases hj0 : j = 0
    · subst hj0
      simp only [BEq.beq, decide_true, ↓reduceIte, Nat.add_zero]
      rw [evalPoly_pAdd]
      refine int_mod_add_eq rfl ?_
      rw [evalPoly_pMul, evalPoly_vPer]
      refine int_mod_mul_eq rfl ?_
      rw [evalPoly_pSub, evalPoly_vNxt T r COL_W (by decide)]
      exact int_mod_sub_eq rfl (evalPoly_pConst _ TAG_CM)
    · have hbeq : (j == 0) = false := beq_false_of_ne hj0
      simp only [hj0, hbeq, Bool.false_eq_true, ↓reduceIte]
      by_cases hj8 : j ≤ 8
      · simp only [hj8, ↓reduceIte]
        rw [evalPoly_pAdd]
        refine int_mod_add_eq rfl ?_
        rw [evalPoly_pMul, evalPoly_vPer]
        refine int_mod_mul_eq rfl ?_
        rw [evalPoly_pSub, hnw, evalPoly_vCur T r (COL_DIG + j - 1) (by simp [COL_DIG, W_COLS]; omega)]
      · simp only [hj8, ↓reduceIte]
        by_cases hj11 : j ≥ 11
        · simp only [hj11, ↓reduceIte]
          rw [evalPoly_pAdd]
          refine int_mod_add_eq rfl ?_
          rw [evalPoly_pMul, evalPoly_vPer]
          refine int_mod_mul_eq rfl ?_
          rw [evalPoly_pSub, hnw, evalPoly_vNxt T r (COL_RHO + j - 11) (by simp [COL_RHO, W_COLS]; omega)]
        · simp [hj11]
  have hr3 : evalPoly (rowEnv T r) r3 % P =
      (evalPoly (rowEnv T r) r2 +
        (if j < 8 then periodicVal r 5 * (1 - T.cell (r + 1) COL_BIT) * (T.cell (r + 1) (COL_W + j) - T.cell r (COL_DIG + j))
         else periodicVal r 5 * T.cell (r + 1) COL_BIT * (T.cell (r + 1) (COL_W + j) - T.cell r (COL_DIG + j - 8)))) % P := by
    simp only [r3, nbit]
    by_cases hj8 : j < 8
    · simp only [hj8, ↓reduceIte]
      rw [evalPoly_pAdd]
      refine int_mod_add_eq rfl ?_
      rw [evalPoly_pMul]
      refine int_mod_mul_eq ?_ ?_
      · rw [evalPoly_pMul, evalPoly_vPer]
        refine int_mod_mul_eq rfl ?_
        rw [evalPoly_pSub, evalPoly_vNxt T r COL_BIT (by decide)]
        exact int_mod_sub_eq (evalPoly_pConst _ 1) rfl
      · rw [evalPoly_pSub, hnw, evalPoly_vCur T r (COL_DIG + j) (by simp [COL_DIG, W_COLS]; omega)]
    · simp only [hj8, ↓reduceIte]
      rw [evalPoly_pAdd]
      refine int_mod_add_eq rfl ?_
      rw [evalPoly_pMul]
      refine int_mod_mul_eq ?_ ?_
      · rw [evalPoly_pMul, evalPoly_vPer, evalPoly_vNxt T r COL_BIT (by decide)]
      · rw [evalPoly_pSub, hnw, evalPoly_vCur T r (COL_DIG + j - 8) (by simp [COL_DIG, W_COLS]; omega)]
  have hr4 : evalPoly (rowEnv T r) r4 % P =
      (evalPoly (rowEnv T r) r3 +
        periodicVal r 6 * (T.cell (r + 1) (COL_W + j) -
          (if j = 0 then (TAG_NF : Int)
           else if j ≤ 8 then T.cell (r + 1) (COL_SK + j - 1)
           else if j = 9 then T.cell (r + 1) COL_POS
           else if j ≤ 14 then T.cell (r + 1) (COL_RHO + j - 10)
           else 0))) % P := by
    simp only [r4, t_nf]
    rw [evalPoly_pAdd]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pMul, evalPoly_vPer]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pSub, hnw]
    refine int_mod_sub_eq rfl ?_
    by_cases hj0 : j = 0
    · subst hj0; simp [evalPoly_pConst]
    · have hbeq0 : (j == 0) = false := beq_false_of_ne hj0
      simp only [hj0, hbeq0, Bool.false_eq_true, ↓reduceIte]
      by_cases hj8 : j ≤ 8
      · simp only [hj8, ↓reduceIte]
        rw [evalPoly_vNxt T r (COL_SK + j - 1) (by simp [COL_SK, W_COLS]; omega)]
      · simp only [hj8, ↓reduceIte]
        by_cases hj9 : j = 9
        · subst hj9; simp [evalPoly_vNxt T r COL_POS (by decide)]
        · have hbeq9 : (j == 9) = false := beq_false_of_ne hj9
          simp only [hj9, hbeq9, Bool.false_eq_true, ↓reduceIte]
          by_cases hj14 : j ≤ 14
          · simp only [hj14, ↓reduceIte]
            rw [evalPoly_vNxt T r (COL_RHO + j - 10) (by simp [COL_RHO, W_COLS]; omega)]
          · simp [hj14, evalPoly]
  have hr5 : evalPoly (rowEnv T r) r5 % P =
      (evalPoly (rowEnv T r) r4 + (if j = 0 then periodicVal r 7 * (T.cell (r + 1) (COL_W + j) - (TAG_CM : Int)) else 0)) % P := by
    simp only [r5]
    by_cases hj0 : j = 0
    · subst hj0
      simp only [BEq.beq, decide_true, ↓reduceIte, Nat.add_zero]
      rw [evalPoly_pAdd]
      refine int_mod_add_eq rfl ?_
      rw [evalPoly_pMul, evalPoly_vPer]
      refine int_mod_mul_eq rfl ?_
      rw [evalPoly_pSub, evalPoly_vNxt T r COL_W (by decide)]
      exact int_mod_sub_eq rfl (evalPoly_pConst _ TAG_CM)
    · have hbeq : (j == 0) = false := beq_false_of_ne hj0
      simp [hj0, hbeq]
  rw [hr5, Int.add_emod, hr4, Int.add_emod (evalPoly (rowEnv T r) r3), hr3,
      Int.add_emod (evalPoly (rowEnv T r) r2), hr2, Int.add_emod (evalPoly (rowEnv T r) r1), hr1]
  simp only [msgLoadTerm, ← Int.add_emod, Int.add_assoc]

theorem eval_fipsCon_win_lt15 (T : RawFieldTrace) (r j : Nat) (hj : j < 15) :
    evalPoly (rowEnv T r) (fipsCon (70 + j)) % P =
      (periodicVal r 1 * (T.cell (r + 1) (COL_W + j) - T.cell r (COL_W + j + 1)) + msgLoadTerm T r j) % P := by
  have h1 : (70 + j == 0) = false := beq_eq_false (by omega)
  have h2 : (70 + j == 1) = false := beq_eq_false (by omega)
  have h3 : (70 + j == 2) = false := beq_eq_false (by omega)
  have h4 : (70 + j == 3) = false := beq_eq_false (by omega)
  have h5 : ¬ (70 + j < 36) := by omega
  have h6 : ¬ (70 + j < 68) := by omega
  have h7 : (70 + j == 68) = false := beq_eq_false (by omega)
  have h8 : (70 + j == 69) = false := beq_eq_false (by omega)
  have h9 : 70 + j < 86 := by omega
  unfold fipsCon
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left, hj]
  rw [eval_msgLoad_tail T r j (by omega)]
  refine int_mod_add_eq ?_ rfl
  rw [evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vNxt T r (COL_W + j) (by simp [COL_W, W_COLS]; omega),
      evalPoly_vCur T r (COL_W + j + 1) (by simp [COL_W, W_COLS]; omega)]

theorem eval_fipsCon_85_load (T : RawFieldTrace) (r : Nat) (hround : periodicVal r 1 = 0) :
    evalPoly (rowEnv T r) (fipsCon 85) % P = msgLoadTerm T r 15 % P := by
  unfold fipsCon
  simp only [show (85 == 0) = false from rfl, show (85 == 1) = false from rfl,
    show (85 == 2) = false from rfl, show (85 == 3) = false from rfl,
    show ¬(85 < 36) from by decide, show ¬(85 < 68) from by decide,
    show (85 == 68) = false from rfl, show (85 == 69) = false from rfl,
    show (85 < 86) from by decide, show 85 - 70 = 15 from rfl,
    show ¬(15 < 15) from by decide, Bool.false_eq_true, ↓reduceIte]
  rw [eval_msgLoad_tail T r 15 (by omega)]
  rw [Int.add_emod, evalPoly_pMul (rowEnv T r) (vPer 1), evalPoly_vPer, hround,
      Int.zero_mul, Int.zero_emod, Int.zero_add, Int.emod_emod]

theorem eval_fipsCon_85_sched (T : RawFieldTrace) (r : Nat) (w1 w14 : UInt32)
    (hround : periodicVal r 1 = 1)
    (h3 : periodicVal r 3 = 0) (h4 : periodicVal r 4 = 0) (h5 : periodicVal r 5 = 0)
    (h6 : periodicVal r 6 = 0) (_h7 : periodicVal r 7 = 0)
    (hx1  : ∀ i, i < 32 → T.cell r (COL_X1 + i) = u32Bit w1 i)
    (hx14 : ∀ i, i < 32 → T.cell r (COL_X14 + i) = u32Bit w14 i) :
    evalPoly (rowEnv T r) (fipsCon 85) % P =
      (T.cell (r + 1) (COL_W + 15) + TWO32 * (T.cell r COL_CWC + 2 * T.cell r (COL_CWC + 1)) -
        (((smallS1 w14).toNat : Int) + T.cell r (COL_W + 9) + ((smallS0 w1).toNat : Int) + T.cell r COL_W)) % P := by
  unfold fipsCon
  simp only [show (85 == 0) = false from rfl, show (85 == 1) = false from rfl,
    show (85 == 2) = false from rfl, show (85 == 3) = false from rfl,
    show ¬(85 < 36) from by decide, show ¬(85 < 68) from by decide,
    show (85 == 68) = false from rfl, show (85 == 69) = false from rfl,
    show (85 < 86) from by decide, show 85 - 70 = 15 from rfl,
    show ¬(15 < 15) from by decide, Bool.false_eq_true, ↓reduceIte]
  rw [eval_msgLoad_tail T r 15 (by omega)]
  have hml0 : msgLoadTerm T r 15 = 0 := by
    simp [msgLoadTerm, h3, h4, h5, h6]
  rw [hml0, Int.add_zero, evalPoly_pMul, evalPoly_vPer, hround, Int.one_mul, evalPoly_pSub]
  refine int_mod_sub_eq ?_ ?_
  · rw [evalPoly_pAdd, evalPoly_vNxt T r (COL_W + 15) (by decide)]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pScale]
    refine int_mod_mul_eq rfl ?_
    rw [evalPoly_pAdd, evalPoly_vCur T r COL_CWC (by decide)]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pScale, evalPoly_vCur T r (COL_CWC + 1) (by decide)]; rfl
  · have hs1 := evalPoly_pSmallS1 (rowEnv T r) (fun j => vCur (COL_X14 + j)) w14
      (fun j hj => by rw [evalPoly_vCur T r (COL_X14 + j) (by simp [COL_X14, W_COLS]; omega), hx14 j hj])
    have hs0 := evalPoly_pSmallS0 (rowEnv T r) (fun j => vCur (COL_X1 + j)) w1
      (fun j hj => by rw [evalPoly_vCur T r (COL_X1 + j) (by simp [COL_X1, W_COLS]; omega), hx1 j hj])
    repeat (rw [evalPoly_pAdd]; refine int_mod_add_eq ?_ ?_)
    · exact hs1
    · rw [evalPoly_vCur T r (COL_W + 9) (by decide)]
    · exact hs0
    · rw [evalPoly_vCur T r COL_W (by decide)]

-- ---- #88..#95 digest constraints unpacking ----

def digOutVal (T : RawFieldTrace) (r : Nat) : Nat → Int
  | 0 => T.cell r COL_AN
  | 1 => packBits (fun k => T.cell r (COL_A + k)) 32
  | 2 => packBits (fun k => T.cell r (COL_AP + k)) 32
  | 3 => T.cell r COL_CWORD
  | 4 => T.cell r COL_EN
  | 5 => packBits (fun k => T.cell r (COL_E + k)) 32
  | 6 => packBits (fun k => T.cell r (COL_EP + k)) 32
  | _ => T.cell r COL_GWORD

theorem eval_fipsCon_dig (T : RawFieldTrace) (r j : Nat) (hj : j < 8) :
    evalPoly (rowEnv T r) (fipsCon (88 + j)) % P =
      (periodicVal r 2 * (T.cell r (COL_DIG + j) + TWO32 * T.cell r (COL_X1 + j) - (ivNat j : Int) - digOutVal T r j)) % P := by
  have h1 : (88 + j == 0) = false := beq_eq_false (by omega)
  have h2 : (88 + j == 1) = false := beq_eq_false (by omega)
  have h3 : (88 + j == 2) = false := beq_eq_false (by omega)
  have h4 : (88 + j == 3) = false := beq_eq_false (by omega)
  have h5 : ¬ (88 + j < 36) := by omega
  have h6 : ¬ (88 + j < 68) := by omega
  have h7 : (88 + j == 68) = false := beq_eq_false (by omega)
  have h8 : (88 + j == 69) = false := beq_eq_false (by omega)
  have h9 : ¬ (88 + j < 86) := by omega
  have h10 : (88 + j == 86) = false := beq_eq_false (by omega)
  have h11 : (88 + j == 87) = false := beq_eq_false (by omega)
  have h12 : 88 + j < 96 := by omega
  unfold fipsCon
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
  rw [evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub]
  refine int_mod_sub_eq ?_ ?_
  · rw [evalPoly_pSub]
    refine int_mod_sub_eq ?_ (evalPoly_pConst _ (ivNat j))
    rw [evalPoly_pAdd, evalPoly_vCur T r (COL_DIG + j) (by simp [COL_DIG, W_COLS]; omega)]
    refine int_mod_add_eq rfl ?_
    rw [evalPoly_pScale, evalPoly_vCur T r (COL_X1 + j) (by simp [COL_X1, W_COLS]; omega)]; rfl
  · have : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · simp [digOutVal, evalPoly_vCur T r COL_AN (by decide)]
    · exact evalPoly_pWordBits _ _ _ (fun k hk => by rw [evalPoly_vCur T r (COL_A + k) (by simp [COL_A, W_COLS]; omega)])
    · exact evalPoly_pWordBits _ _ _ (fun k hk => by rw [evalPoly_vCur T r (COL_AP + k) (by simp [COL_AP, W_COLS]; omega)])
    · simp [digOutVal, evalPoly_vCur T r COL_CWORD (by decide)]
    · simp [digOutVal, evalPoly_vCur T r COL_EN (by decide)]
    · exact evalPoly_pWordBits _ _ _ (fun k hk => by rw [evalPoly_vCur T r (COL_E + k) (by simp [COL_E, W_COLS]; omega)])
    · exact evalPoly_pWordBits _ _ _ (fun k hk => by rw [evalPoly_vCur T r (COL_EP + k) (by simp [COL_EP, W_COLS]; omega)])
    · simp [digOutVal, evalPoly_vCur T r COL_GWORD (by decide)]

-- ---- #233..#248 register, pos, balance, and value-range unpacking ----

theorem eval_fipsCon_sk (T : RawFieldTrace) (r j : Nat) (hj : j < 8) :
    evalPoly (rowEnv T r) (fipsCon (233 + j)) % P =
      (periodicVal r 12 * (T.cell (r + 1) (COL_SK + j) - T.cell r (COL_SK + j))) % P := by
  have hspec : fipsCon (233 + j) = pMul (vPer 12) (pSub (vNxt (COL_SK + j)) (vCur (COL_SK + j))) := by
    unfold fipsCon
    have h1 : (233 + j == 0) = false := beq_eq_false (by omega)
    have h2 : (233 + j == 1) = false := beq_eq_false (by omega)
    have h3 : (233 + j == 2) = false := beq_eq_false (by omega)
    have h4 : (233 + j == 3) = false := beq_eq_false (by omega)
    have h5 : ¬ (233 + j < 36) := by omega
    have h6 : ¬ (233 + j < 68) := by omega
    have h7 : (233 + j == 68) = false := beq_eq_false (by omega)
    have h8 : (233 + j == 69) = false := beq_eq_false (by omega)
    have h9 : ¬ (233 + j < 86) := by omega
    have h10 : (233 + j == 86) = false := beq_eq_false (by omega)
    have h11 : (233 + j == 87) = false := beq_eq_false (by omega)
    have h12 : ¬ (233 + j < 96) := by omega
    have h13 : ¬ (233 + j < 224) := by omega
    have h14 : ¬ (233 + j < 233) := by omega
    have h15 : 233 + j < 241 := by omega
    simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vNxt T r (COL_SK + j) (by simp [COL_SK, W_COLS]; omega),
      evalPoly_vCur T r (COL_SK + j) (by simp [COL_SK, W_COLS]; omega)]

theorem eval_fipsCon_rho (T : RawFieldTrace) (r j : Nat) (hj : j < 5) :
    evalPoly (rowEnv T r) (fipsCon (241 + j)) % P =
      (periodicVal r 13 * (T.cell (r + 1) (COL_RHO + j) - T.cell r (COL_RHO + j))) % P := by
  have hspec : fipsCon (241 + j) = pMul (vPer 13) (pSub (vNxt (COL_RHO + j)) (vCur (COL_RHO + j))) := by
    unfold fipsCon
    have h1 : (241 + j == 0) = false := beq_eq_false (by omega)
    have h2 : (241 + j == 1) = false := beq_eq_false (by omega)
    have h3 : (241 + j == 2) = false := beq_eq_false (by omega)
    have h4 : (241 + j == 3) = false := beq_eq_false (by omega)
    have h5 : ¬ (241 + j < 36) := by omega
    have h6 : ¬ (241 + j < 68) := by omega
    have h7 : (241 + j == 68) = false := beq_eq_false (by omega)
    have h8 : (241 + j == 69) = false := beq_eq_false (by omega)
    have h9 : ¬ (241 + j < 86) := by omega
    have h10 : (241 + j == 86) = false := beq_eq_false (by omega)
    have h11 : (241 + j == 87) = false := beq_eq_false (by omega)
    have h12 : ¬ (241 + j < 96) := by omega
    have h13 : ¬ (241 + j < 224) := by omega
    have h14 : ¬ (241 + j < 233) := by omega
    have h15 : ¬ (241 + j < 241) := by omega
    have h16 : 241 + j < 246 := by omega
    simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, Bool.false_eq_true, ↓reduceIte, Nat.add_sub_cancel_left]
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  rw [evalPoly_pSub, evalPoly_vNxt T r (COL_RHO + j) (by simp [COL_RHO, W_COLS]; omega),
      evalPoly_vCur T r (COL_RHO + j) (by simp [COL_RHO, W_COLS]; omega)]

theorem eval_fipsCon_246 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 246) % P =
      (periodicVal r 11 * T.cell (r + 1) COL_POS - periodicVal r 12 * T.cell r COL_POS -
       periodicVal r 8 * T.cell (r + 1) COL_BIT) % P := by
  have hspec : fipsCon 246 =
      pSub (pSub (pMul (vPer 11) (vNxt COL_POS)) (pMul (vPer 12) (vCur COL_POS)))
           (pMul (vPer 8) (vNxt COL_BIT)) := rfl
  rw [hspec, evalPoly_pSub]
  refine int_mod_sub_eq ?_ ?_
  · rw [evalPoly_pSub]
    refine int_mod_sub_eq ?_ ?_
    · rw [evalPoly_pMul, evalPoly_vPer, evalPoly_vNxt T r COL_POS (by decide)]
    · rw [evalPoly_pMul, evalPoly_vPer, evalPoly_vCur T r COL_POS (by decide)]
  · rw [evalPoly_pMul, evalPoly_vPer, evalPoly_vNxt T r COL_BIT (by decide)]

theorem eval_fipsCon_247 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 247) % P =
      (periodicVal r 11 * (T.cell (r + 1) COL_BAL - T.cell r COL_BAL) -
       periodicVal r 4 * (TWO32 * T.cell (r + 1) (COL_W + 9) + T.cell (r + 1) (COL_W + 10)) +
       periodicVal r 7 * (TWO32 * T.cell (r + 1) (COL_W + 9) + T.cell (r + 1) (COL_W + 10))) % P := by
  have hspec : fipsCon 247 =
      let nv := pAdd (pScale TWO32_NAT (vNxt (COL_W + 9))) (vNxt (COL_W + 10))
      pAdd (pSub (pMul (vPer 11) (pSub (vNxt COL_BAL) (vCur COL_BAL))) (pMul (vPer 4) nv)) (pMul (vPer 7) nv) := rfl
  rw [hspec]
  dsimp only
  have hnv : evalPoly (rowEnv T r) (pAdd (pScale TWO32_NAT (vNxt (COL_W + 9))) (vNxt (COL_W + 10))) % P =
      (TWO32 * T.cell (r + 1) (COL_W + 9) + T.cell (r + 1) (COL_W + 10)) % P := by
    rw [evalPoly_pAdd]
    refine int_mod_add_eq ?_ (by rw [evalPoly_vNxt T r (COL_W + 10) (by decide)])
    rw [evalPoly_pScale, evalPoly_vNxt T r (COL_W + 9) (by decide)]; rfl
  rw [evalPoly_pAdd]
  refine int_mod_add_eq ?_ ?_
  · rw [evalPoly_pSub]
    refine int_mod_sub_eq ?_ ?_
    · rw [evalPoly_pMul, evalPoly_vPer]
      refine int_mod_mul_eq rfl ?_
      rw [evalPoly_pSub, evalPoly_vNxt T r COL_BAL (by decide), evalPoly_vCur T r COL_BAL (by decide)]
    · rw [evalPoly_pMul, evalPoly_vPer]
      exact int_mod_mul_eq rfl hnv
  · rw [evalPoly_pMul, evalPoly_vPer]
    exact int_mod_mul_eq rfl hnv

theorem eval_fipsCon_248 (T : RawFieldTrace) (r : Nat) :
    evalPoly (rowEnv T r) (fipsCon 248) % P =
      (periodicVal r 9 * (T.cell r (COL_X1 + 28) + T.cell r (COL_X1 + 29) +
        T.cell r (COL_X1 + 30) + T.cell r (COL_X1 + 31))) % P := by
  have hspec : fipsCon 248 =
      pMul (vPer 9) (pAdd (pAdd (pAdd (vCur (COL_X1 + 28)) (vCur (COL_X1 + 29)))
                                (vCur (COL_X1 + 30))) (vCur (COL_X1 + 31))) := rfl
  rw [hspec, evalPoly_pMul, evalPoly_vPer]
  refine int_mod_mul_eq rfl ?_
  repeat (rw [evalPoly_pAdd]; refine int_mod_add_eq ?_ ?_)
  · rw [evalPoly_vCur T r (COL_X1 + 28) (by decide)]
  · rw [evalPoly_vCur T r (COL_X1 + 29) (by decide)]
  · rw [evalPoly_vCur T r (COL_X1 + 30) (by decide)]
  · rw [evalPoly_vCur T r (COL_X1 + 31) (by decide)]

-- ---- Window shift & range-check for ALL W_1..W_63 ----

/-- Canonical raw schedule word `W_k` (`1 ≤ k ≤ 63`) read from `COL_W + 1` on row `k - 1`,
    where Constraint #86 proves it equals `packBits(COL_X1) < 2^32`. -/
def rawSchedWord (T : RawFieldTrace) (b k : Nat) : Int :=
  T.cell (b * 64 + (k - 1)) (COL_W + 1)

def rawW (T : RawFieldTrace) (b k : Nat) : UInt32 :=
  UInt32.ofNat (rawSchedWord T b k).toNat

theorem raw_w1_eq_packX1 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) :
    T.cell (b * 64 + t) (COL_W + 1) = packBits (fun j => T.cell (b * 64 + t) (COL_X1 + j)) 32 ∧
    0 ≤ T.cell (b * 64 + t) (COL_W + 1) ∧ T.cell (b * 64 + t) (COL_W + 1) < TWO32 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 86) (by omega) (by omega)
  rw [eval_fipsCon_86] at hz
  have hp := (periodic_inner b t hb1 hb72 ht).2.1
  simp only [hp, Int.one_mul] at hz
  have hpb := word32_pack_bounds (fun j => T.cell (b * 64 + t) (COL_X1 + j))
    (fun j hj => raw_bool_X1 hT b t j hb1 hb72 (by omega) hj)
  have hr := T.hRange (b * 64 + t) (COL_W + 1) (by omega) (by decide)
  have hP : TWO32 < P := by decide
  have heq := field_eq_of_sub_mod_P hr.1 hr.2 hpb.1 (by omega) hz
  exact ⟨heq, by rw [heq]; exact hpb.1, by rw [heq]; exact hpb.2⟩

theorem raw_w14_eq_packX14 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) :
    T.cell (b * 64 + t) (COL_W + 14) = packBits (fun j => T.cell (b * 64 + t) (COL_X14 + j)) 32 := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 87) (by omega) (by omega)
  rw [eval_fipsCon_87] at hz
  have hp := (periodic_inner b t hb1 hb72 ht).2.1
  simp only [hp, Int.one_mul] at hz
  have hpb := word32_pack_bounds (fun j => T.cell (b * 64 + t) (COL_X14 + j))
    (fun j hj => raw_bool_X14 hT b t j hb1 hb72 (by omega) hj)
  have hr := T.hRange (b * 64 + t) (COL_W + 14) (by omega) (by decide)
  have hP : TWO32 < P := by decide
  exact field_eq_of_sub_mod_P hr.1 hr.2 hpb.1 (by omega) hz

theorem rawSchedWord_bounds {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b k : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hk1 : 1 ≤ k) (hk63 : k ≤ 63) :
    0 ≤ rawSchedWord T b k ∧ rawSchedWord T b k < TWO32 := by
  have h := raw_w1_eq_packX1 hT b (k - 1) hb1 hb72 (by omega)
  exact ⟨h.2.1, h.2.2⟩

theorem rawW_toNat_int {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b k : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hk1 : 1 ≤ k) (hk63 : k ≤ 63) :
    ((rawW T b k).toNat : Int) = rawSchedWord T b k := by
  have hb := rawSchedWord_bounds hT b k hb1 hb72 hk1 hk63
  exact u32_ofNat_toNat_int _ hb.1 hb.2

theorem raw_window_step {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) (hj : j < 15) :
    T.cell (b * 64 + t + 1) (COL_W + j) = T.cell (b * 64 + t) (COL_W + j + 1) := by
  have hz := rawCon_zero hT (r := b * 64 + t) (i := 70 + j) (by omega) (by omega)
  rw [eval_fipsCon_win_lt15 T (b * 64 + t) j hj] at hz
  have hp := periodic_inner b t hb1 hb72 ht
  have hml : msgLoadTerm T (b * 64 + t) j = 0 := by
    simp [msgLoadTerm, hp.2.2.2.1, hp.2.2.2.2.1, hp.2.2.2.2.2.1, hp.2.2.2.2.2.2.1, hp.2.2.2.2.2.2.2.1]
  rw [hp.2.1, hml, Int.one_mul, Int.add_zero] at hz
  have hr1 := T.hRange (b * 64 + t + 1) (COL_W + j) (by omega) (by simp [COL_W, W_COLS]; omega)
  have hr2 := T.hRange (b * 64 + t) (COL_W + j + 1) (by omega) (by simp [COL_W, W_COLS]; omega)
  exact field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz

theorem raw_window_diag {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    ∀ d t j, j + d < 16 → t + d < 64 →
      T.cell (b * 64 + (t + d)) (COL_W + j) = T.cell (b * 64 + t) (COL_W + (j + d)) := by
  intro d
  induction d with
  | zero => intro t j _ _; simp
  | succ m ih =>
    intro t j hjd htd
    have h1 : b * 64 + (t + (m + 1)) = b * 64 + (t + m) + 1 := by omega
    rw [h1, raw_window_step hT b (t + m) j hb1 hb72 (by omega) (by omega)]
    have h2 : COL_W + j + 1 = COL_W + (j + 1) := by omega
    rw [h2, ih t (j + 1) (by omega) (by omega)]
    have h3 : j + 1 + m = j + (m + 1) := by omega
    rw [h3]

theorem raw_window_eq_sched {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72)
    (ht : t < 64) (hj : j < 16) (hlo : 1 ≤ t + j) (hhi : t + j ≤ 63) :
    T.cell (b * 64 + t) (COL_W + j) = rawSchedWord T b (t + j) := by
  unfold rawSchedWord
  by_cases hj0 : j = 0
  · subst hj0
    have h := raw_window_diag hT b hb1 hb72 1 (t - 1) 0 (by omega) (by omega)
    have h1 : t - 1 + 1 = t := by omega
    have h2 : t + 0 - 1 = t - 1 := by omega
    simpa [h1, h2] using h
  · have h := raw_window_diag hT b hb1 hb72 (j - 1) t 1 (by omega) (by omega)
    have h1 : 1 + (j - 1) = j := by omega
    have h2 : t + (j - 1) = t + j - 1 := by omega
    rw [h1, h2] at h
    exact h.symm

-- ---- Uniform digest cell predicate (handles unreduced a_64 / e_64 & W_0!) ----

def DigestCellRepresents (T : RawFieldTrace) (b j : Nat) (expected : UInt32) : Prop :=
  ∃ out S_ cc : Int,
    0 ≤ out ∧ out < P ∧
    0 ≤ S_ ∧ S_ < 7 * TWO32 ∧
    0 ≤ cc ∧ cc < 8 ∧
    ((ivNat j : Int) + S_) % TWO32 = (expected.toNat : Int) ∧
    (out + TWO32 * cc - S_) % P = 0 ∧
    (T.cell (b * 64 + 63) (COL_DIG + j) + TWO32 * T.cell (b * 64 + 63) (COL_X1 + j) - (ivNat j : Int) - out) % P = 0

theorem digest_cell_eq_of_lt {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hj : j < 8)
    (expected : UInt32) (hrep : DigestCellRepresents T b j expected)
    (hlt : T.cell (b * 64 + 63) (COL_DIG + j) < TWO32) :
    T.cell (b * 64 + 63) (COL_DIG + j) = (expected.toNat : Int) := by
  rcases hrep with ⟨out, S_, cc, hout0, houtP, hS0, hS7, hcc0, hcc8, hexp, h1, h2⟩
  have hdig0 := (T.hRange (b * 64 + 63) (COL_DIG + j) (by omega) (by simp [COL_DIG, W_COLS]; omega)).1
  have hx := raw_bool_X1 hT b 63 j hb1 hb72 (by omega) (by omega)
  have hiv : 0 ≤ (ivNat j : Int) ∧ (ivNat j : Int) < TWO32 := by
    have := iv_toNat_eq_ivNat j hj
    have hltiv : (IV[j]!).toNat < 2 ^ 32 := (IV[j]!).toBitVec.isLt
    simp only [TWO32]; omega
  rw [← hexp]
  exact digest_word_mod32_even_unreduced
    (T.cell (b * 64 + 63) (COL_DIG + j)) (T.cell (b * 64 + 63) (COL_X1 + j))
    (ivNat j : Int) out S_ cc
    ⟨hdig0, hlt⟩ hx hiv ⟨hout0, houtP⟩ ⟨hS0, hS7⟩ ⟨hcc0, hcc8⟩ h1 h2

-- ---- Per-block 64-round SHA-256 compression soundness ----

def RawBlockW0Matches (T : RawFieldTrace) (b : Nat) (w0 : UInt32) : Prop :=
  T.cell (b * 64) COL_AN = ((k0aConst : Int) + (w0.toNat : Int)) % TWO32 ∧
  T.cell (b * 64) COL_EN = ((k0eConst : Int) + (w0.toNat : Int)) % TWO32 ∧
  rawSchedWord T b 16 =
    (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 +
     ((smallS0 (rawW T b 1)).toNat : Int) + (w0.toNat : Int)) % TWO32

def blockMsgOfW0 (T : RawFieldTrace) (b : Nat) (w0 : UInt32) : Array UInt32 :=
  #[w0, rawW T b 1, rawW T b 2, rawW T b 3,
        rawW T b 4, rawW T b 5, rawW T b 6, rawW T b 7,
        rawW T b 8, rawW T b 9, rawW T b 10, rawW T b 11,
        rawW T b 12, rawW T b 13, rawW T b 14, rawW T b 15]

theorem blockMsgOfW0_get (T : RawFieldTrace) (b : Nat) (w0 : UInt32) (k : Nat) (hk1 : 1 ≤ k) (hk15 : k ≤ 15) :
    (blockMsgOfW0 T b w0)[k]! = rawW T b k := by
  have : k = 1 ∨ k = 2 ∨ k = 3 ∨ k = 4 ∨ k = 5 ∨ k = 6 ∨ k = 7 ∨ k = 8 ∨
         k = 9 ∨ k = 10 ∨ k = 11 ∨ k = 12 ∨ k = 13 ∨ k = 14 ∨ k = 15 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
                   rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> rfl

theorem raw_block_schedule_sound {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (w0 : UInt32) (hw0 : RawBlockW0Matches T b w0) :
    let w := sha256Schedule (blockMsgOfW0 T b w0)
    w[0]! = w0 ∧ ∀ k, 1 ≤ k → k < 64 → w[k]! = rawW T b k := by
  intro w
  have hsz : (blockMsgOfW0 T b w0).size = 16 := rfl
  constructor
  · rw [sha256Schedule_init _ hsz 0 (by omega)]; rfl
  · intro k hk1 hk64
    induction k using Nat.strongRecOn with
    | ind k ih =>
      by_cases hlt16 : k < 16
      · rw [sha256Schedule_init _ hsz k hlt16, blockMsgOfW0_get T b w0 k hk1 (by omega)]
      · let t := k - 16
        have hk_eq : k = t + 16 := by omega
        have ht48 : t < 48 := by omega
        rw [hk_eq, sha256Schedule_step _ hsz t ht48]
        have h14 : w[t + 14]! = rawW T b (t + 14) := ih (t + 14) (by omega) (by omega) (by omega)
        have h9  : w[t + 9]!  = rawW T b (t + 9)  := ih (t + 9) (by omega) (by omega) (by omega)
        have h1  : w[t + 1]!  = rawW T b (t + 1)  := ih (t + 1) (by omega) (by omega) (by omega)
        rw [h14, h9, h1]
        by_cases ht0 : t = 0
        · rw [ht0]
          have hw0_eq : w[0]! = w0 := by rw [sha256Schedule_init _ hsz 0 (by omega)]; rfl
          rw [hw0_eq]
          apply u32_eq_of_toNat_int
          simp only [Nat.zero_add]
          rw [rawW_toNat_int hT b 16 hb1 hb72 (by omega) (by omega), hw0.2.2]
          simp only [u32_add_toNat_int, mod_add_l,
            rawW_toNat_int hT b 9 hb1 hb72 (by omega) (by omega)]
        · have ht_pos : 1 ≤ t := by omega
          have h0 : w[t]! = rawW T b t := ih t (by omega) ht_pos (by omega)
          rw [h0]
          -- Extract #85 on row b*64 + t
          have hz := rawCon_zero hT (r := b * 64 + t) (i := 85) (by omega) (by omega)
          have hp := periodic_inner b t hb1 hb72 (by omega)
          -- x1 and x14 bits match rawW T b (t+1) and rawW T b (t+14)
          have hx1_pack := raw_w1_eq_packX1 hT b t hb1 hb72 (by omega)
          have hx1_w : T.cell (b * 64 + t) (COL_W + 1) = ((rawW T b (t + 1)).toNat : Int) := by
            rw [raw_window_eq_sched hT b t 1 hb1 hb72 (by omega) (by omega) (by omega) (by omega),
                rawW_toNat_int hT b (t + 1) hb1 hb72 (by omega) (by omega)]
          have hx1_bits : ∀ i, i < 32 → T.cell (b * 64 + t) (COL_X1 + i) = u32Bit (rawW T b (t + 1)) i :=
            packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_X1 hT b t i hb1 hb72 (by omega) hi)
              (by rw [← hx1_pack.1, hx1_w])
          have hx14_pack := raw_w14_eq_packX14 hT b t hb1 hb72 (by omega)
          have hx14_w : T.cell (b * 64 + t) (COL_W + 14) = ((rawW T b (t + 14)).toNat : Int) := by
            rw [raw_window_eq_sched hT b t 14 hb1 hb72 (by omega) (by omega) (by omega) (by omega),
                rawW_toNat_int hT b (t + 14) hb1 hb72 (by omega) (by omega)]
          have hx14_bits : ∀ i, i < 32 → T.cell (b * 64 + t) (COL_X14 + i) = u32Bit (rawW T b (t + 14)) i :=
            packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_X14 hT b t i hb1 hb72 (by omega) hi)
              (by rw [← hx14_pack, hx14_w])
          rw [eval_fipsCon_85_sched T (b * 64 + t) (rawW T b (t + 1)) (rawW T b (t + 14))
              hp.2.1 hp.2.2.2.1 hp.2.2.2.2.1 hp.2.2.2.2.2.1 hp.2.2.2.2.2.2.1 hp.2.2.2.2.2.2.2.1
              hx1_bits hx14_bits] at hz
          have hw16_eq : T.cell (b * 64 + t + 1) (COL_W + 15) = rawSchedWord T b (t + 16) := by
            have hidx : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
            rw [hidx, raw_window_eq_sched hT b (t + 1) 15 hb1 hb72 (by omega) (by omega) (by omega) (by omega)]
          have hw9_eq : T.cell (b * 64 + t) (COL_W + 9) = rawSchedWord T b (t + 9) :=
            raw_window_eq_sched hT b t 9 hb1 hb72 (by omega) (by omega) (by omega) (by omega)
          have hw0_eq' : T.cell (b * 64 + t) COL_W = rawSchedWord T b t :=
            raw_window_eq_sched hT b t 0 hb1 hb72 (by omega) (by omega) (by omega) (by omega)
          rw [hw16_eq, hw9_eq, hw0_eq'] at hz
          have hb16 := rawSchedWord_bounds hT b (t + 16) hb1 hb72 (by omega) (by omega)
          have hb9  := rawSchedWord_bounds hT b (t + 9) hb1 hb72 (by omega) (by omega)
          have hb0  := rawSchedWord_bounds hT b t hb1 hb72 (by omega) (by omega)
          have hcw  := raw_cwc_bounds hT b t hb1 hb72 (by omega)
          have hs1_lt : ((smallS1 (rawW T b (t + 14))).toNat : Int) < TWO32 := by
            exact u32_toNat_lt_two32 (smallS1 (rawW T b (t + 14)))
          have hs0_lt : ((smallS0 (rawW T b (t + 1))).toNat : Int) < TWO32 := by
            exact u32_toNat_lt_two32 (smallS0 (rawW T b (t + 1)))
          have hS_bd : 0 ≤ (((smallS1 (rawW T b (t + 14))).toNat : Int) + rawSchedWord T b (t + 9) +
              ((smallS0 (rawW T b (t + 1))).toNat : Int) + rawSchedWord T b t) ∧
              (((smallS1 (rawW T b (t + 14))).toNat : Int) + rawSchedWord T b (t + 9) +
              ((smallS0 (rawW T b (t + 1))).toNat : Int) + rawSchedWord T b t) < 4 * TWO32 := by omega
          have hmod32 := w16_word_mod32_sound _ _ _ hb16 hcw hS_bd hz
          apply u32_eq_of_toNat_int
          rw [rawW_toNat_int hT b (t + 16) hb1 hb72 (by omega) (by omega), hmod32]
          simp only [u32_add_toNat_int, mod_add_l,
            rawW_toNat_int hT b (t + 9) hb1 hb72 (by omega) (by omega),
            rawW_toNat_int hT b t hb1 hb72 (by omega) (by omega)]


theorem sha256RunRounds_succ (w : Array UInt32) (n : Nat) (s : ShaState) :
    sha256RunRounds w (n + 1) s = sha256Round (sha256RunRounds w n s) K[n]! w[n]! := rfl

theorem sha256Compress_get (blk : Array UInt32) :
    let s := sha256RunRounds (sha256Schedule blk) 64 sha256Init
    (sha256Compress blk)[0]! = IV[0]! + s.a ∧
    (sha256Compress blk)[1]! = IV[1]! + s.b ∧
    (sha256Compress blk)[2]! = IV[2]! + s.c ∧
    (sha256Compress blk)[3]! = IV[3]! + s.d ∧
    (sha256Compress blk)[4]! = IV[4]! + s.e ∧
    (sha256Compress blk)[5]! = IV[5]! + s.f ∧
    (sha256Compress blk)[6]! = IV[6]! + s.g ∧
    (sha256Compress blk)[7]! = IV[7]! + s.h := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem raw_block_compress_sound {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (w0 : UInt32) (hw0 : RawBlockW0Matches T b w0) :
    ∀ j, j < 8 → DigestCellRepresents T b j ((sha256Compress (blockMsgOfW0 T b w0))[j]!) := by
  let msg := blockMsgOfW0 T b w0
  let w := sha256Schedule msg
  have hsched := raw_block_schedule_sound hT b hb1 hb72 w0 hw0
  let st (t : Nat) : ShaState := sha256RunRounds w t sha256Init
  -- Prove row-by-row invariant for all t < 64
  have hrow : ∀ t, t < 64 →
      (∀ i, i < 32 → T.cell (b * 64 + t) (COL_A + i) = u32Bit (st t).a i) ∧
      (∀ i, i < 32 → T.cell (b * 64 + t) (COL_AP + i) = u32Bit (st t).b i) ∧
      T.cell (b * 64 + t) COL_CWORD = ((st t).c.toNat : Int) ∧
      (∀ i, i < 32 → T.cell (b * 64 + t) (COL_E + i) = u32Bit (st t).e i) ∧
      (∀ i, i < 32 → T.cell (b * 64 + t) (COL_EP + i) = u32Bit (st t).f i) ∧
      T.cell (b * 64 + t) COL_GWORD = ((st t).g.toNat : Int) ∧
      (t < 63 → T.cell (b * 64 + t) COL_AN = ((st (t + 1)).a.toNat : Int) ∧
                T.cell (b * 64 + t) COL_EN = ((st (t + 1)).e.toNat : Int)) := by
    intro t ht
    induction t with
    | zero =>
      have hpre := periodic_pre_block b hb1 hb72
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 + 0 := by omega
      -- #2: word(na) = IV[0]
      have ha0 : ∀ i, i < 32 → T.cell (b * 64 + 0) (COL_A + i) = u32Bit (IV[0]!) i := by
        have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 2) (by omega) (by omega)
        rw [eval_fipsCon_2, hpre.1, hpre.2, Int.zero_mul, Int.zero_add, Int.one_mul, hidx] at hz
        have hpb := word32_pack_bounds (fun i => T.cell (b * 64 + 0) (COL_A + i))
          (fun i hi => raw_bool_A hT b 0 i hb1 hb72 (by omega) hi)
        have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega)
          (by decide) (by decide) hz
        rw [← iv_toNat_eq_ivNat 0 (by decide)] at heq
        exact packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_A hT b 0 i hb1 hb72 (by omega) hi) heq
      -- #3: word(ne) = IV[4]
      have he0 : ∀ i, i < 32 → T.cell (b * 64 + 0) (COL_E + i) = u32Bit (IV[4]!) i := by
        have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 3) (by omega) (by omega)
        rw [eval_fipsCon_3, hpre.1, hpre.2, Int.zero_mul, Int.zero_add, Int.one_mul, hidx] at hz
        have hpb := word32_pack_bounds (fun i => T.cell (b * 64 + 0) (COL_E + i))
          (fun i hi => raw_bool_E hT b 0 i hb1 hb72 (by omega) hi)
        have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega)
          (by decide) (by decide) hz
        rw [← iv_toNat_eq_ivNat 4 (by decide)] at heq
        exact packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_E hT b 0 i hb1 hb72 (by omega) hi) heq
      -- #4..#35: nap[j] = bit j IV[1]
      have hb0 : ∀ i, i < 32 → T.cell (b * 64 + 0) (COL_AP + i) = u32Bit (IV[1]!) i := by
        intro i hi
        have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 4 + i) (by omega) (by omega)
        rw [eval_fipsCon_ap T _ i hi, hpre.1, hpre.2, Int.zero_mul, Int.zero_add, Int.one_mul, hidx] at hz
        have hr := T.hRange (b * 64 + 0) (COL_AP + i) (by omega) (by simp [COL_AP, W_COLS]; omega)
        have hivb : (((ivNat 1 >>> i) &&& 1 : Nat) : Int) = u32Bit (IV[1]!) i := by
          unfold u32Bit
          rw [iv_toNat_eq_ivNat 1 (by decide), Nat.shiftRight_eq_div_pow, Nat.and_one_is_mod]
          have hlt2 : (ivNat 1 / 2 ^ i) % 2 = 0 ∨ (ivNat 1 / 2 ^ i) % 2 = 1 := by omega
          rcases hlt2 with h0' | h1'
          · simp [h0']
          · simp [h1']
        rw [hivb] at hz
        have hbu := u32Bit_bool (IV[1]!) i
        exact field_eq_of_sub_mod_P hr.1 hr.2 (by rcases hbu with h | h <;> rw [h] <;> decide)
          (by rcases hbu with h | h <;> rw [h] <;> decide) hz
      -- #36..#67: nep[j] = bit j IV[5]
      have hf0 : ∀ i, i < 32 → T.cell (b * 64 + 0) (COL_EP + i) = u32Bit (IV[5]!) i := by
        intro i hi
        have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 36 + i) (by omega) (by omega)
        rw [eval_fipsCon_ep T _ i hi, hpre.1, hpre.2, Int.zero_mul, Int.zero_add, Int.one_mul, hidx] at hz
        have hr := T.hRange (b * 64 + 0) (COL_EP + i) (by omega) (by simp [COL_EP, W_COLS]; omega)
        have hivb : (((ivNat 5 >>> i) &&& 1 : Nat) : Int) = u32Bit (IV[5]!) i := by
          unfold u32Bit
          rw [iv_toNat_eq_ivNat 5 (by decide), Nat.shiftRight_eq_div_pow, Nat.and_one_is_mod]
          have hlt2 : (ivNat 5 / 2 ^ i) % 2 = 0 ∨ (ivNat 5 / 2 ^ i) % 2 = 1 := by omega
          rcases hlt2 with h0' | h1'
          · simp [h0']
          · simp [h1']
        rw [hivb] at hz
        have hbu := u32Bit_bool (IV[5]!) i
        exact field_eq_of_sub_mod_P hr.1 hr.2 (by rcases hbu with h | h <;> rw [h] <;> decide)
          (by rcases hbu with h | h <;> rw [h] <;> decide) hz
      -- #68, #69: CWORD = IV[2], GWORD = IV[6]
      have hc0 : T.cell (b * 64 + 0) COL_CWORD = ((IV[2]!).toNat : Int) := by
        have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 68) (by omega) (by omega)
        rw [eval_fipsCon_68, hpre.1, hpre.2, Int.zero_mul, Int.zero_add, Int.one_mul, hidx] at hz
        have hr := T.hRange (b * 64 + 0) COL_CWORD (by omega) (by decide)
        rw [iv_toNat_eq_ivNat 2 (by decide)]
        exact field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) hz
      have hg0 : T.cell (b * 64 + 0) COL_GWORD = ((IV[6]!).toNat : Int) := by
        have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 69) (by omega) (by omega)
        rw [eval_fipsCon_69, hpre.1, hpre.2, Int.zero_mul, Int.zero_add, Int.one_mul, hidx] at hz
        have hr := T.hRange (b * 64 + 0) COL_GWORD (by omega) (by decide)
        rw [iv_toNat_eq_ivNat 6 (by decide)]
        exact field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) hz
      refine ⟨ha0, hb0, hc0, he0, hf0, hg0, fun _ => ?_⟩
      change T.cell (b * 64 + 0) COL_AN = ((sha256Round sha256Init K[0]! w[0]!).a.toNat : Int) ∧
             T.cell (b * 64 + 0) COL_EN = ((sha256Round sha256Init K[0]! w[0]!).e.toNat : Int)
      rw [hsched.1, round0_a_toNat w0, round0_e_toNat w0, Nat.add_zero]
      exact ⟨hw0.1, hw0.2.1⟩
    | succ k ih =>
      have hprev := ih (by omega)
      have hp := periodic_inner b k hb1 hb72 (by omega)
      have hidx : b * 64 + k + 1 = b * 64 + (k + 1) := by omega
      have hprev_an := (hprev.2.2.2.2.2.2 (by omega)).1
      have hprev_en := (hprev.2.2.2.2.2.2 (by omega)).2
      -- #2: word(na) = cur[AN] = (st (k+1)).a
      have ha1 : ∀ i, i < 32 → T.cell (b * 64 + (k + 1)) (COL_A + i) = u32Bit (st (k + 1)).a i := by
        have hz := rawCon_zero hT (r := b * 64 + k) (i := 2) (by omega) (by omega)
        rw [eval_fipsCon_2, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero, hidx] at hz
        have hpb := word32_pack_bounds (fun i => T.cell (b * 64 + (k + 1)) (COL_A + i))
          (fun i hi => raw_bool_A hT b (k + 1) i hb1 hb72 (by omega) hi)
        have hlt_a : ((st (k + 1)).a.toNat : Int) < P := by
          exact u32_toNat_lt_P (st (k + 1)).a
        rw [hprev_an] at hz
        have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega) (by omega) hlt_a hz
        exact packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_A hT b (k + 1) i hb1 hb72 (by omega) hi) heq
      -- #3: word(ne) = cur[EN] = (st (k+1)).e
      have he1 : ∀ i, i < 32 → T.cell (b * 64 + (k + 1)) (COL_E + i) = u32Bit (st (k + 1)).e i := by
        have hz := rawCon_zero hT (r := b * 64 + k) (i := 3) (by omega) (by omega)
        rw [eval_fipsCon_3, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero, hidx] at hz
        have hpb := word32_pack_bounds (fun i => T.cell (b * 64 + (k + 1)) (COL_E + i))
          (fun i hi => raw_bool_E hT b (k + 1) i hb1 hb72 (by omega) hi)
        have hlt_e : ((st (k + 1)).e.toNat : Int) < P := by
          exact u32_toNat_lt_P (st (k + 1)).e
        rw [hprev_en] at hz
        have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega) (by omega) hlt_e hz
        exact packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_E hT b (k + 1) i hb1 hb72 (by omega) hi) heq
      -- #4..#35: nap[j] = cur[A+j] = (st k).a = (st (k+1)).b
      have hb1' : ∀ i, i < 32 → T.cell (b * 64 + (k + 1)) (COL_AP + i) = u32Bit (st (k + 1)).b i := by
        intro i hi
        have hz := rawCon_zero hT (r := b * 64 + k) (i := 4 + i) (by omega) (by omega)
        rw [eval_fipsCon_ap T _ i hi, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero, hidx] at hz
        have hr1 := T.hRange (b * 64 + (k + 1)) (COL_AP + i) (by omega) (by simp [COL_AP, W_COLS]; omega)
        have hr2 := T.hRange (b * 64 + k) (COL_A + i) (by omega) (by simp [COL_A, W_COLS]; omega)
        rw [field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz, hprev.1 i hi]
        rfl
      -- #36..#67: nep[j] = cur[E+j] = (st k).e = (st (k+1)).f
      have hf1' : ∀ i, i < 32 → T.cell (b * 64 + (k + 1)) (COL_EP + i) = u32Bit (st (k + 1)).f i := by
        intro i hi
        have hz := rawCon_zero hT (r := b * 64 + k) (i := 36 + i) (by omega) (by omega)
        rw [eval_fipsCon_ep T _ i hi, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero, hidx] at hz
        have hr1 := T.hRange (b * 64 + (k + 1)) (COL_EP + i) (by omega) (by simp [COL_EP, W_COLS]; omega)
        have hr2 := T.hRange (b * 64 + k) (COL_E + i) (by omega) (by simp [COL_E, W_COLS]; omega)
        rw [field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz, hprev.2.2.2.1 i hi]
        rfl
      -- #68: CWORD = word(cap) = (st k).b = (st (k+1)).c
      have hc1 : T.cell (b * 64 + (k + 1)) COL_CWORD = ((st (k + 1)).c.toNat : Int) := by
        have hz := rawCon_zero hT (r := b * 64 + k) (i := 68) (by omega) (by omega)
        rw [eval_fipsCon_68, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero, hidx] at hz
        have hcap : packBits (fun j => T.cell (b * 64 + k) (COL_AP + j)) 32 = ((st k).b.toNat : Int) := by
          have hcongr : ∀ n, n ≤ 32 → packBits (fun j => T.cell (b * 64 + k) (COL_AP + j)) n = packBits (u32Bit (st k).b) n := by
            intro n hn; induction n with
            | zero => rfl
            | succ m ihm => simp [packBits, ihm (by omega), hprev.2.1 m (by omega)]
          rw [hcongr 32 (by omega), packBits_u32Bit]
        rw [hcap] at hz
        have hr := T.hRange (b * 64 + (k + 1)) COL_CWORD (by omega) (by decide)
        have hlt : ((st k).b.toNat : Int) < P := by exact u32_toNat_lt_P (st k).b
        rw [field_eq_of_sub_mod_P hr.1 hr.2 (by omega) hlt hz]; rfl
      -- #69: GWORD = word(cep) = (st k).f = (st (k+1)).g
      have hg1 : T.cell (b * 64 + (k + 1)) COL_GWORD = ((st (k + 1)).g.toNat : Int) := by
        have hz := rawCon_zero hT (r := b * 64 + k) (i := 69) (by omega) (by omega)
        rw [eval_fipsCon_69, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero, hidx] at hz
        have hcep : packBits (fun j => T.cell (b * 64 + k) (COL_EP + j)) 32 = ((st k).f.toNat : Int) := by
          have hcongr : ∀ n, n ≤ 32 → packBits (fun j => T.cell (b * 64 + k) (COL_EP + j)) n = packBits (u32Bit (st k).f) n := by
            intro n hn; induction n with
            | zero => rfl
            | succ m ihm => simp [packBits, ihm (by omega), hprev.2.2.2.2.1 m (by omega)]
          rw [hcongr 32 (by omega), packBits_u32Bit]
        rw [hcep] at hz
        have hr := T.hRange (b * 64 + (k + 1)) COL_GWORD (by omega) (by decide)
        have hlt : ((st k).f.toNat : Int) < P := by exact u32_toNat_lt_P (st k).f
        rw [field_eq_of_sub_mod_P hr.1 hr.2 (by omega) hlt hz]; rfl
      refine ⟨ha1, hb1', hc1, he1, hf1', hg1, fun hk63 => ?_⟩
      -- For k + 1 < 63, row k+2 exists inside block b, so #2 & #3 on row k+1 prove COL_AN < TWO32 & COL_EN < TWO32!
      have hp1 := periodic_inner b (k + 1) hb1 hb72 hk63
      have han_lt : 0 ≤ T.cell (b * 64 + (k + 1)) COL_AN ∧ T.cell (b * 64 + (k + 1)) COL_AN < TWO32 := by
        have hz2 := rawCon_zero hT (r := b * 64 + (k + 1)) (i := 2) (by omega) (by omega)
        rw [eval_fipsCon_2, hp1.2.1, hp1.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero] at hz2
        have hpb := word32_pack_bounds (fun j => T.cell (b * 64 + (k + 1) + 1) (COL_A + j))
          (fun j hj => by
            have h1 : b * 64 + (k + 1) + 1 = b * 64 + (k + 2) := by omega
            rw [h1]; exact raw_bool_A hT b (k + 2) j hb1 hb72 (by omega) hj)
        have hr := T.hRange (b * 64 + (k + 1)) COL_AN (by omega) (by decide)
        have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega) hr.1 hr.2 hz2
        rw [← heq]; exact hpb
      have hen_lt : 0 ≤ T.cell (b * 64 + (k + 1)) COL_EN ∧ T.cell (b * 64 + (k + 1)) COL_EN < TWO32 := by
        have hz3 := rawCon_zero hT (r := b * 64 + (k + 1)) (i := 3) (by omega) (by omega)
        rw [eval_fipsCon_3, hp1.2.1, hp1.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero] at hz3
        have hpb := word32_pack_bounds (fun j => T.cell (b * 64 + (k + 1) + 1) (COL_E + j))
          (fun j hj => by
            have h1 : b * 64 + (k + 1) + 1 = b * 64 + (k + 2) := by omega
            rw [h1]; exact raw_bool_E hT b (k + 2) j hb1 hb72 (by omega) hj)
        have hr := T.hRange (b * 64 + (k + 1)) COL_EN (by omega) (by decide)
        have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega) hr.1 hr.2 hz3
        rw [← heq]; exact hpb
      -- Apply #0 & #1 on row b*64 + k to get COL_AN and COL_EN on row b*64 + (k+1)!
      have hw_eq : T.cell (b * 64 + (k + 1)) COL_W = ((w[k + 1]!).toNat : Int) := by
        have hw0_ := raw_window_eq_sched hT b (k + 1) 0 hb1 hb72 (by omega) (by omega) (by omega) (by omega)
        simp only [Nat.add_zero] at hw0_
        rw [hw0_, hsched.2 (k + 1) (by omega) (by omega), rawW_toNat_int hT b (k + 1) hb1 hb72 (by omega) (by omega)]
      have hst_c : (st (k + 1)).d = (st k).c := rfl
      have hst_h : (st (k + 1)).h = (st k).g := rfl
      have hz0 := rawCon_zero hT (r := b * 64 + k) (i := 0) (by omega) (by omega)
      rw [eval_fipsCon_0_round T (b * 64 + k) (st (k + 1)).a (st (k + 1)).b (st (k + 1)).c
          (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g hp.2.1 hp.2.2.2.2.2.2.2.2.2.2.2.2.2
          (by intro i hi; rw [hidx]; exact ha1 i hi)
          (by intro i hi; rw [hidx]; exact hb1' i hi)
          (fun i hi => hprev.2.1 i hi)
          (by intro i hi; rw [hidx]; exact he1 i hi)
          (by intro i hi; rw [hidx]; exact hf1' i hi)
          (fun i hi => hprev.2.2.2.2.1 i hi)] at hz0
      rw [hidx, hp.1, hw_eq, hprev.2.2.2.2.2.1] at hz0
      have hSa_lt : 0 ≤ (((st k).g.toNat : Int) + ((bigS1 (st (k + 1)).e).toNat : Int) +
          ((ch32 (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g).toNat : Int) +
          ((K[k + 1]!).toNat : Int) + ((w[k + 1]!).toNat : Int) +
          ((bigS0 (st (k + 1)).a).toNat : Int) +
          ((maj32 (st (k + 1)).a (st (k + 1)).b (st (k + 1)).c).toNat : Int)) ∧
          (((st k).g.toNat : Int) + ((bigS1 (st (k + 1)).e).toNat : Int) +
          ((ch32 (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g).toNat : Int) +
          ((K[k + 1]!).toNat : Int) + ((w[k + 1]!).toNat : Int) +
          ((bigS0 (st (k + 1)).a).toNat : Int) +
          ((maj32 (st (k + 1)).a (st (k + 1)).b (st (k + 1)).c).toNat : Int)) < 7 * TWO32 := by
        have := u32_toNat_lt_two32 (st k).g
        have := u32_toNat_lt_two32 (bigS1 (st (k + 1)).e)
        have := u32_toNat_lt_two32 (ch32 (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g)
        have := u32_toNat_lt_two32 (K[k + 1]!)
        have := u32_toNat_lt_two32 (w[k + 1]!)
        have := u32_toNat_lt_two32 (bigS0 (st (k + 1)).a)
        have := u32_toNat_lt_two32 (maj32 (st (k + 1)).a (st (k + 1)).b (st (k + 1)).c)
        simp only [TWO32] at *; omega
      have ha_res := round_word_mod32_sound _ _ _ han_lt (raw_carry3_ca_bounds hT b (k + 1) hb1 hb72 (by omega)) hSa_lt hz0
      have hz1 := rawCon_zero hT (r := b * 64 + k) (i := 1) (by omega) (by omega)
      rw [eval_fipsCon_1_round T (b * 64 + k) (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g
          hp.2.1 hp.2.2.2.2.2.2.2.2.2.2.2.2.2
          (by intro i hi; rw [hidx]; exact he1 i hi)
          (by intro i hi; rw [hidx]; exact hf1' i hi)
          (fun i hi => hprev.2.2.2.2.1 i hi)] at hz1
      rw [hidx, hp.1, hw_eq, hprev.2.2.1, hprev.2.2.2.2.2.1] at hz1
      have hSe_lt : 0 ≤ (((st k).c.toNat : Int) + (((st k).g.toNat : Int) + ((bigS1 (st (k + 1)).e).toNat : Int) +
          ((ch32 (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g).toNat : Int) +
          ((K[k + 1]!).toNat : Int) + ((w[k + 1]!).toNat : Int))) ∧
          (((st k).c.toNat : Int) + (((st k).g.toNat : Int) + ((bigS1 (st (k + 1)).e).toNat : Int) +
          ((ch32 (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g).toNat : Int) +
          ((K[k + 1]!).toNat : Int) + ((w[k + 1]!).toNat : Int))) < 7 * TWO32 := by
        have := u32_toNat_lt_two32 (st k).c
        have := u32_toNat_lt_two32 (st k).g
        have := u32_toNat_lt_two32 (bigS1 (st (k + 1)).e)
        have := u32_toNat_lt_two32 (ch32 (st (k + 1)).e (st (k + 1)).f (st (k + 1)).g)
        have := u32_toNat_lt_two32 (K[k + 1]!)
        have := u32_toNat_lt_two32 (w[k + 1]!)
        simp only [TWO32] at *; omega
      have he_res := round_word_mod32_sound _ _ _ hen_lt (raw_carry3_ce_bounds hT b (k + 1) hb1 hb72 (by omega)) hSe_lt hz1
      have hstep_r : st (k + 1 + 1) = sha256Round (st (k + 1)) K[k + 1]! w[k + 1]! := rfl
      constructor
      · rw [ha_res, hstep_r]
        simp only [sha256Round, hst_h, u32_add_toNat_int, mod_add_l, mod_add_r]
        exact congrArg (· % TWO32) (by omega)
      · rw [he_res, hstep_r]
        simp only [sha256Round, hst_c, hst_h, u32_add_toNat_int, mod_add_l, mod_add_r]
  -- Now prove DigestCellRepresents T b j ((sha256Compress msg)[j]!) for all j < 8!
  have hr62 := hrow 62 (by omega)
  have hr63 := hrow 63 (by omega)
  have hlast := periodic_last_row b hb1 hb72
  have hp62 := periodic_inner b 62 hb1 hb72 (by omega)
  have hw63 : T.cell (b * 64 + 63) COL_W = ((w[63]!).toNat : Int) := by
    have hw0_ := raw_window_eq_sched hT b 63 0 hb1 hb72 (by omega) (by omega) (by omega) (by omega)
    simp only [Nat.add_zero] at hw0_
    rw [hw0_, hsched.2 63 (by omega) (by omega), rawW_toNat_int hT b 63 hb1 hb72 (by omega) (by omega)]
  have hidx63 : b * 64 + 62 + 1 = b * 64 + 63 := by omega
  -- Helper for packed bits on row 63
  have hpack_eq : ∀ (f : Nat → Int) (u : UInt32), (∀ i, i < 32 → f i = u32Bit u i) → packBits f 32 = (u.toNat : Int) := by
    intro f u hf
    have hcongr : ∀ n, n ≤ 32 → packBits f n = packBits (u32Bit u) n := by
      intro n hn; induction n with
      | zero => rfl
      | succ m ihm => simp [packBits, ihm (by omega), hf m (by omega)]
    rw [hcongr 32 (by omega), packBits_u32Bit]
  intro j hj
  have hdig_con := rawCon_zero hT (r := b * 64 + 63) (i := 88 + j) (by omega) (by omega)
  rw [eval_fipsCon_dig T (b * 64 + 63) j hj, hlast.2.1, Int.one_mul] at hdig_con
  have hcases : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 := by omega
  rcases hcases with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · -- j = 0: unreduced a_64
    let S_a := ((st 62).g.toNat : Int) + ((bigS1 (st 63).e).toNat : Int) +
        ((ch32 (st 63).e (st 63).f (st 63).g).toNat : Int) + ((K[63]!).toNat : Int) + ((w[63]!).toNat : Int) +
        ((bigS0 (st 63).a).toNat : Int) + ((maj32 (st 63).a (st 63).b (st 63).c).toNat : Int)
    have hz0 := rawCon_zero hT (r := b * 64 + 62) (i := 0) (by omega) (by omega)
    rw [eval_fipsCon_0_round T (b * 64 + 62) (st 63).a (st 63).b (st 63).c
        (st 63).e (st 63).f (st 63).g hp62.2.1 hp62.2.2.2.2.2.2.2.2.2.2.2.2.2
        (by intro i hi; rw [hidx63]; exact hr63.1 i hi)
        (by intro i hi; rw [hidx63]; exact hr63.2.1 i hi)
        (fun i hi => hr62.2.1 i hi)
        (by intro i hi; rw [hidx63]; exact hr63.2.2.2.1 i hi)
        (by intro i hi; rw [hidx63]; exact hr63.2.2.2.2.1 i hi)
        (fun i hi => hr62.2.2.2.2.1 i hi)] at hz0
    rw [hidx63, hp62.1, hw63, hr62.2.2.2.2.2.1] at hz0
    have hSa_lt : 0 ≤ S_a ∧ S_a < 7 * TWO32 := by
      have := u32_toNat_lt_two32 (st 62).g
      have := u32_toNat_lt_two32 (bigS1 (st 63).e)
      have := u32_toNat_lt_two32 (ch32 (st 63).e (st 63).f (st 63).g)
      have := u32_toNat_lt_two32 (K[63]!)
      have := u32_toNat_lt_two32 (w[63]!)
      have := u32_toNat_lt_two32 (bigS0 (st 63).a)
      have := u32_toNat_lt_two32 (maj32 (st 63).a (st 63).b (st 63).c)
      simp only [S_a, TWO32] at *; omega
    have hcc := raw_carry3_ca_bounds hT b 63 hb1 hb72 (by omega)
    have hout := T.hRange (b * 64 + 63) COL_AN (by omega) (by decide)
    refine ⟨T.cell (b * 64 + 63) COL_AN, S_a, carry3Val T (b * 64 + 63) COL_CA,
      hout.1, hout.2, hSa_lt.1, hSa_lt.2, hcc.1, hcc.2, ?_, hz0, hdig_con⟩
    have hcomp0 : (sha256Compress msg)[0]! = IV[0]! + (st 64).a := (sha256Compress_get msg).1
    have h64a : (st 64).a = (sha256Round (st 63) K[63]! w[63]!).a := rfl
    have h63h : (st 63).h = (st 62).g := rfl
    rw [hcomp0, h64a, u32_add_toNat_int, iv_toNat_eq_ivNat 0 (by decide)]
    simp only [sha256Round, h63h, u32_add_toNat_int, mod_add_l, mod_add_r, S_a]
    exact congrArg (· % TWO32) (by omega)
  · -- j = 1: a_63 = (st 64).b
    have hval := hpack_eq (fun k => T.cell (b * 64 + 63) (COL_A + k)) (st 63).a hr63.1
    simp only [digOutVal] at hdig_con; rw [hval] at hdig_con
    have hlt : ((st 63).a.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 (st 63).a
    refine ⟨((st 63).a.toNat : Int), ((st 63).a.toNat : Int), 0,
      by omega, by simp only [TWO32, P] at *; omega, by omega, by omega, by omega, by omega, ?_, by simp, hdig_con⟩
    have hcomp1 : (sha256Compress msg)[1]! = IV[1]! + (st 63).a := rfl
    rw [hcomp1, u32_add_toNat_int, iv_toNat_eq_ivNat 1 (by decide)]
  · -- j = 2: b_63 = (st 64).c
    have hval := hpack_eq (fun k => T.cell (b * 64 + 63) (COL_AP + k)) (st 63).b hr63.2.1
    simp only [digOutVal] at hdig_con; rw [hval] at hdig_con
    have hlt : ((st 63).b.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 (st 63).b
    refine ⟨((st 63).b.toNat : Int), ((st 63).b.toNat : Int), 0,
      by omega, by simp only [TWO32, P] at *; omega, by omega, by omega, by omega, by omega, ?_, by simp, hdig_con⟩
    have hcomp2 : (sha256Compress msg)[2]! = IV[2]! + (st 63).b := rfl
    rw [hcomp2, u32_add_toNat_int, iv_toNat_eq_ivNat 2 (by decide)]
  · -- j = 3: c_63 = (st 64).d
    simp only [digOutVal] at hdig_con; rw [hr63.2.2.1] at hdig_con
    have hlt : ((st 63).c.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 (st 63).c
    refine ⟨((st 63).c.toNat : Int), ((st 63).c.toNat : Int), 0,
      by omega, by simp only [TWO32, P] at *; omega, by omega, by omega, by omega, by omega, ?_, by simp, hdig_con⟩
    have hcomp3 : (sha256Compress msg)[3]! = IV[3]! + (st 63).c := rfl
    rw [hcomp3, u32_add_toNat_int, iv_toNat_eq_ivNat 3 (by decide)]
  · -- j = 4: unreduced e_64
    let S_e := ((st 62).c.toNat : Int) + (((st 62).g.toNat : Int) + ((bigS1 (st 63).e).toNat : Int) +
        ((ch32 (st 63).e (st 63).f (st 63).g).toNat : Int) + ((K[63]!).toNat : Int) + ((w[63]!).toNat : Int))
    have hz1 := rawCon_zero hT (r := b * 64 + 62) (i := 1) (by omega) (by omega)
    rw [eval_fipsCon_1_round T (b * 64 + 62) (st 63).e (st 63).f (st 63).g
        hp62.2.1 hp62.2.2.2.2.2.2.2.2.2.2.2.2.2
        (by intro i hi; rw [hidx63]; exact hr63.2.2.2.1 i hi)
        (by intro i hi; rw [hidx63]; exact hr63.2.2.2.2.1 i hi)
        (fun i hi => hr62.2.2.2.2.1 i hi)] at hz1
    rw [hidx63, hp62.1, hw63, hr62.2.2.1, hr62.2.2.2.2.2.1] at hz1
    have hSe_lt : 0 ≤ S_e ∧ S_e < 7 * TWO32 := by
      have := u32_toNat_lt_two32 (st 62).c
      have := u32_toNat_lt_two32 (st 62).g
      have := u32_toNat_lt_two32 (bigS1 (st 63).e)
      have := u32_toNat_lt_two32 (ch32 (st 63).e (st 63).f (st 63).g)
      have := u32_toNat_lt_two32 (K[63]!)
      have := u32_toNat_lt_two32 (w[63]!)
      simp only [S_e, TWO32] at *; omega
    have hcc := raw_carry3_ce_bounds hT b 63 hb1 hb72 (by omega)
    have hout := T.hRange (b * 64 + 63) COL_EN (by omega) (by decide)
    refine ⟨T.cell (b * 64 + 63) COL_EN, S_e, carry3Val T (b * 64 + 63) COL_CE,
      hout.1, hout.2, hSe_lt.1, hSe_lt.2, hcc.1, hcc.2, ?_, hz1, hdig_con⟩
    have hcomp4 : (sha256Compress msg)[4]! = IV[4]! + (st 64).e := (sha256Compress_get msg).2.2.2.2.1
    have h64e : (st 64).e = (sha256Round (st 63) K[63]! w[63]!).e := rfl
    have h63d : (st 63).d = (st 62).c := rfl
    have h63h : (st 63).h = (st 62).g := rfl
    rw [hcomp4, h64e, u32_add_toNat_int, iv_toNat_eq_ivNat 4 (by decide)]
    simp only [sha256Round, h63d, h63h, u32_add_toNat_int, mod_add_l, mod_add_r, S_e]
  · -- j = 5: e_63 = (st 64).f
    have hval := hpack_eq (fun k => T.cell (b * 64 + 63) (COL_E + k)) (st 63).e hr63.2.2.2.1
    simp only [digOutVal] at hdig_con; rw [hval] at hdig_con
    have hlt : ((st 63).e.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 (st 63).e
    refine ⟨((st 63).e.toNat : Int), ((st 63).e.toNat : Int), 0,
      by omega, by simp only [TWO32, P] at *; omega, by omega, by omega, by omega, by omega, ?_, by simp, hdig_con⟩
    have hcomp5 : (sha256Compress msg)[5]! = IV[5]! + (st 63).e := rfl
    rw [hcomp5, u32_add_toNat_int, iv_toNat_eq_ivNat 5 (by decide)]
  · -- j = 6: f_63 = (st 64).g
    have hval := hpack_eq (fun k => T.cell (b * 64 + 63) (COL_EP + k)) (st 63).f hr63.2.2.2.2.1
    simp only [digOutVal] at hdig_con; rw [hval] at hdig_con
    have hlt : ((st 63).f.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 (st 63).f
    refine ⟨((st 63).f.toNat : Int), ((st 63).f.toNat : Int), 0,
      by omega, by simp only [TWO32, P] at *; omega, by omega, by omega, by omega, by omega, ?_, by simp, hdig_con⟩
    have hcomp6 : (sha256Compress msg)[6]! = IV[6]! + (st 63).f := rfl
    rw [hcomp6, u32_add_toNat_int, iv_toNat_eq_ivNat 6 (by decide)]
  · -- j = 7: g_63 = (st 64).h
    simp only [digOutVal] at hdig_con; rw [hr63.2.2.2.2.2.1] at hdig_con
    have hlt : ((st 63).g.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 (st 63).g
    refine ⟨((st 63).g.toNat : Int), ((st 63).g.toNat : Int), 0,
      by omega, by simp only [TWO32, P] at *; omega, by omega, by omega, by omega, by omega, ?_, by simp, hdig_con⟩
    have hcomp7 : (sha256Compress msg)[7]! = IV[7]! + (st 63).g := rfl
    rw [hcomp7, u32_add_toNat_int, iv_toNat_eq_ivNat 7 (by decide)]

-- ---- Checking RawBlockW0Matches in all 3 cases (small W_0, unreduced prevDig[0], free Merkle W_0) ----

theorem raw_block_an_en_lt_two32 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    (0 ≤ T.cell (b * 64) COL_AN ∧ T.cell (b * 64) COL_AN < TWO32) ∧
    (0 ≤ T.cell (b * 64) COL_EN ∧ T.cell (b * 64) COL_EN < TWO32) := by
  have hp := periodic_inner b 0 hb1 hb72 (by omega)
  constructor
  · have hz := rawCon_zero hT (r := b * 64 + 0) (i := 2) (by omega) (by omega)
    rw [eval_fipsCon_2, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero] at hz
    have hpb := word32_pack_bounds (fun j => T.cell (b * 64 + 0 + 1) (COL_A + j))
      (fun j hj => raw_bool_A hT b 1 j hb1 hb72 (by omega) hj)
    have hr := T.hRange (b * 64 + 0) COL_AN (by omega) (by decide)
    have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega) hr.1 hr.2 hz
    simp only [Nat.add_zero] at heq hpb
    rw [← heq]; exact hpb
  · have hz := rawCon_zero hT (r := b * 64 + 0) (i := 3) (by omega) (by omega)
    rw [eval_fipsCon_3, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero] at hz
    have hpb := word32_pack_bounds (fun j => T.cell (b * 64 + 0 + 1) (COL_E + j))
      (fun j hj => raw_bool_E hT b 1 j hb1 hb72 (by omega) hj)
    have hr := T.hRange (b * 64 + 0) COL_EN (by omega) (by decide)
    have heq := field_eq_of_sub_mod_P hpb.1 (by simp only [TWO32, P] at *; omega) hr.1 hr.2 hz
    simp only [Nat.add_zero] at heq hpb
    rw [← heq]; exact hpb

theorem raw_block_round0_eqs {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    (T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - (k0aConst : Int) - T.cell (b * 64) COL_W) % P = 0 ∧
    (T.cell (b * 64) COL_EN + TWO32 * carry3Val T (b * 64) COL_CE - (k0eConst : Int) - T.cell (b * 64) COL_W) % P = 0 ∧
    (rawSchedWord T b 16 + TWO32 * (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1)) -
      (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int)) -
      T.cell (b * 64) COL_W) % P = 0 := by
  have hpre := periodic_pre_block b hb1 hb72
  have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
  have hz0 := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 0) (by omega) (by omega)
  rw [eval_fipsCon_0_iv T _ hpre.1, hpre.2, Int.one_mul, hidx] at hz0
  have hz1 := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 1) (by omega) (by omega)
  rw [eval_fipsCon_1_iv T _ hpre.1, hpre.2, Int.one_mul, hidx] at hz1
  have hp := periodic_inner b 0 hb1 hb72 (by omega)
  have hz85 := rawCon_zero hT (r := b * 64 + 0) (i := 85) (by omega) (by omega)
  have hx1_pack := raw_w1_eq_packX1 hT b 0 hb1 hb72 (by omega)
  have hx1_w : T.cell (b * 64 + 0) (COL_W + 1) = ((rawW T b 1).toNat : Int) := by
    rw [raw_window_eq_sched hT b 0 1 hb1 hb72 (by omega) (by omega) (by omega) (by omega),
        rawW_toNat_int hT b 1 hb1 hb72 (by omega) (by omega)]
  have hx1_bits : ∀ i, i < 32 → T.cell (b * 64 + 0) (COL_X1 + i) = u32Bit (rawW T b 1) i :=
    packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_X1 hT b 0 i hb1 hb72 (by omega) hi)
      (by rw [← hx1_pack.1, hx1_w])
  have hx14_pack := raw_w14_eq_packX14 hT b 0 hb1 hb72 (by omega)
  have hx14_w : T.cell (b * 64 + 0) (COL_W + 14) = ((rawW T b 14).toNat : Int) := by
    rw [raw_window_eq_sched hT b 0 14 hb1 hb72 (by omega) (by omega) (by omega) (by omega),
        rawW_toNat_int hT b 14 hb1 hb72 (by omega) (by omega)]
  have hx14_bits : ∀ i, i < 32 → T.cell (b * 64 + 0) (COL_X14 + i) = u32Bit (rawW T b 14) i :=
    packBits_eq_implies_bits_eq _ _ (fun i hi => raw_bool_X14 hT b 0 i hb1 hb72 (by omega) hi)
      (by rw [← hx14_pack, hx14_w])
  rw [eval_fipsCon_85_sched T (b * 64 + 0) (rawW T b 1) (rawW T b 14)
      hp.2.1 hp.2.2.2.1 hp.2.2.2.2.1 hp.2.2.2.2.2.1 hp.2.2.2.2.2.2.1 hp.2.2.2.2.2.2.2.1
      hx1_bits hx14_bits] at hz85
  have hw16_eq : T.cell (b * 64 + 0 + 1) (COL_W + 15) = rawSchedWord T b 16 :=
    raw_window_eq_sched hT b 1 15 hb1 hb72 (by omega) (by omega) (by omega) (by omega)
  have hw9_eq : T.cell (b * 64 + 0) (COL_W + 9) = rawSchedWord T b 9 :=
    raw_window_eq_sched hT b 0 9 hb1 hb72 (by omega) (by omega) (by omega) (by omega)
  rw [hw16_eq, hw9_eq, Nat.add_zero] at hz85
  refine ⟨hz0, hz1, ?_⟩
  have hre : rawSchedWord T b 16 + TWO32 * (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1)) -
      (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int)) -
      T.cell (b * 64) COL_W =
      rawSchedWord T b 16 + TWO32 * (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1)) -
      (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int) +
       T.cell (b * 64) COL_W) := by omega
  rw [hre]; exact hz85

theorem rawBlockW0Matches_of_eq {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (w0 : UInt32)
    (heq : T.cell (b * 64) COL_W = (w0.toNat : Int)) :
    RawBlockW0Matches T b w0 := by
  have heqs := raw_block_round0_eqs hT b hb1 hb72
  have han := raw_block_an_en_lt_two32 hT b hb1 hb72
  have hca := raw_carry3_ca_bounds hT b 0 hb1 hb72 (by omega)
  have hce := raw_carry3_ce_bounds hT b 0 hb1 hb72 (by omega)
  have hcw := raw_cwc_bounds hT b 0 hb1 hb72 (by omega)
  have hb16 := rawSchedWord_bounds hT b 16 hb1 hb72 (by omega) (by omega)
  have hb9 := rawSchedWord_bounds hT b 9 hb1 hb72 (by omega) (by omega)
  have hw0_lt : (w0.toNat : Int) < TWO32 := by exact u32_toNat_lt_two32 w0
  have hs1_lt : ((smallS1 (rawW T b 14)).toNat : Int) < TWO32 := by
    exact u32_toNat_lt_two32 (smallS1 (rawW T b 14))
  have hs0_lt : ((smallS0 (rawW T b 1)).toNat : Int) < TWO32 := by
    exact u32_toNat_lt_two32 (smallS0 (rawW T b 1))
  have hka := k0a_bounds; have hke := k0e_bounds
  rw [heq] at heqs
  have hA : (T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - ((k0aConst : Int) + (w0.toNat : Int))) % P = 0 := by
    have : T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - ((k0aConst : Int) + (w0.toNat : Int)) =
        T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - (k0aConst : Int) - (w0.toNat : Int) := by omega
    rw [this]; exact heqs.1
  have hE : (T.cell (b * 64) COL_EN + TWO32 * carry3Val T (b * 64) COL_CE - ((k0eConst : Int) + (w0.toNat : Int))) % P = 0 := by
    have : T.cell (b * 64) COL_EN + TWO32 * carry3Val T (b * 64) COL_CE - ((k0eConst : Int) + (w0.toNat : Int)) =
        T.cell (b * 64) COL_EN + TWO32 * carry3Val T (b * 64) COL_CE - (k0eConst : Int) - (w0.toNat : Int) := by omega
    rw [this]; exact heqs.2.1
  have hW : (rawSchedWord T b 16 + TWO32 * (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1)) -
      (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int) + (w0.toNat : Int))) % P = 0 := by
    have : rawSchedWord T b 16 + TWO32 * (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1)) -
        (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int) + (w0.toNat : Int)) =
        rawSchedWord T b 16 + TWO32 * (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1)) -
        (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int)) - (w0.toNat : Int) := by omega
    rw [this]; exact heqs.2.2
  simp only [Nat.add_zero] at hca hce hcw
  exact ⟨round_word_mod32_sound _ _ _ han.1 hca (by omega) hA,
         round_word_mod32_sound _ _ _ han.2 hce (by omega) hE,
         w16_word_mod32_sound _ _ _ hb16 hcw (by omega) hW⟩

theorem rawBlockW0Matches_of_prevDig {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb2 : 2 ≤ b) (hb72 : b ≤ 72) (w0 : UInt32)
    (hrep : DigestCellRepresents T (b - 1) 0 w0)
    (heq : T.cell (b * 64) COL_W = T.cell ((b - 1) * 64 + 63) (COL_DIG + 0)) :
    RawBlockW0Matches T b w0 := by
  rcases hrep with ⟨out, S_, cc, hout0, houtP, hS0, hS7, hcc0, hcc8, hexp, h1, h2⟩
  have heqs := raw_block_round0_eqs hT b (by omega) hb72
  rw [heq] at heqs
  have han := raw_block_an_en_lt_two32 hT b (by omega) hb72
  have hca := raw_carry3_ca_bounds hT b 0 (by omega) hb72 (by omega)
  have hce := raw_carry3_ce_bounds hT b 0 (by omega) hb72 (by omega)
  have hcw := raw_cwc_bounds hT b 0 (by omega) hb72 (by omega)
  have hb16 := rawSchedWord_bounds hT b 16 (by omega) hb72 (by omega) (by omega)
  have hb9 := rawSchedWord_bounds hT b 9 (by omega) hb72 (by omega) (by omega)
  have hdigR := T.hRange ((b - 1) * 64 + 63) (COL_DIG + 0) (by omega) (by decide)
  have hx := raw_bool_X1 hT (b - 1) 63 0 (by omega) (by omega) (by omega) (by omega)
  have hiv : 0 ≤ (ivNat 0 : Int) ∧ (ivNat 0 : Int) < TWO32 := by decide
  have hka := k0a_bounds; have hke := k0e_bounds
  have hs1_lt : ((smallS1 (rawW T b 14)).toNat : Int) < TWO32 := by
    exact u32_toNat_lt_two32 (smallS1 (rawW T b 14))
  have hs0_lt : ((smallS0 (rawW T b 1)).toNat : Int) < TWO32 := by
    exact u32_toNat_lt_two32 (smallS0 (rawW T b 1))
  simp only [Nat.add_zero] at hca hce hcw
  refine ⟨?_, ?_, ?_⟩
  · rw [← hexp]
    exact w0_unreduced_harmless_mod32 _ _ _ _ _ _ _ _ _ hdigR hx hiv ⟨hout0, houtP⟩ ⟨hS0, hS7⟩ ⟨hcc0, hcc8⟩
      ⟨hka.1, by omega⟩ han.1 hca h1 h2 heqs.1
  · rw [← hexp]
    exact w0_unreduced_harmless_mod32 _ _ _ _ _ _ _ _ _ hdigR hx hiv ⟨hout0, houtP⟩ ⟨hS0, hS7⟩ ⟨hcc0, hcc8⟩
      ⟨hke.1, by omega⟩ han.2 hce h1 h2 heqs.2.1
  · rw [← hexp]
    exact w0_unreduced_harmless_mod32 _ _ _ _ _ _ _ _ _ hdigR hx hiv ⟨hout0, houtP⟩ ⟨hS0, hS7⟩ ⟨hcc0, hcc8⟩
      ⟨by omega, by omega⟩ hb16 ⟨hcw.1, by omega⟩ h1 h2 heqs.2.2

def canonFreeW0 (T : RawFieldTrace) (b : Nat) : UInt32 :=
  UInt32.ofNat (((T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - (k0aConst : Int)) % TWO32).toNat)

theorem rawBlockW0Matches_free {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    RawBlockW0Matches T b (canonFreeW0 T b) := by
  have heqs := raw_block_round0_eqs hT b hb1 hb72
  have han := raw_block_an_en_lt_two32 hT b hb1 hb72
  have hca := raw_carry3_ca_bounds hT b 0 hb1 hb72 (by omega)
  have hce := raw_carry3_ce_bounds hT b 0 hb1 hb72 (by omega)
  have hcw := raw_cwc_bounds hT b 0 hb1 hb72 (by omega)
  have hb16 := rawSchedWord_bounds hT b 16 hb1 hb72 (by omega) (by omega)
  have hb9 := rawSchedWord_bounds hT b 9 hb1 hb72 (by omega) (by omega)
  have hs1_lt : ((smallS1 (rawW T b 14)).toNat : Int) < TWO32 := by
    exact u32_toNat_lt_two32 (smallS1 (rawW T b 14))
  have hs0_lt : ((smallS0 (rawW T b 1)).toNat : Int) < TWO32 := by
    exact u32_toNat_lt_two32 (smallS0 (rawW T b 1))
  simp only [Nat.add_zero] at hca hce hcw
  have hfree := free_w0_canon_sound
    (T.cell (b * 64) COL_W)
    (T.cell (b * 64) COL_AN) (carry3Val T (b * 64) COL_CA)
    (T.cell (b * 64) COL_EN) (carry3Val T (b * 64) COL_CE)
    (rawSchedWord T b 16) (T.cell (b * 64) COL_CWC + 2 * T.cell (b * 64) (COL_CWC + 1))
    (((smallS1 (rawW T b 14)).toNat : Int) + rawSchedWord T b 9 + ((smallS0 (rawW T b 1)).toNat : Int))
    han.1 hca han.2 hce hb16 hcw ⟨by omega, by omega⟩
    (k0aConst : Int) (k0eConst : Int) k0a_bounds k0e_bounds
    heqs.1 heqs.2.1 heqs.2.2
  -- Notice free_w0_canon_sound constructs the EXACT same w0c = (an + TWO32*ca - k0a) % TWO32!
  -- Rather than unpacking existential, directly prove it equals canonFreeW0 T b:
  let z := T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - (k0aConst : Int)
  have hz0 : 0 ≤ z % TWO32 := Int.emod_nonneg z (by decide)
  have hz1 : z % TWO32 < TWO32 := Int.emod_lt_of_pos z (by decide)
  have hcanon : ((canonFreeW0 T b).toNat : Int) = z % TWO32 := u32_ofNat_toNat_int (z % TWO32) hz0 hz1
  rcases hfree with ⟨w0c, hw0c0, hw0c1, hA, hE, hW⟩
  -- Prove w0c = z % TWO32 from hA + definition of z!
  have hw0c_eq : w0c = z % TWO32 := by
    have h1 : (T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - (k0aConst : Int)) % TWO32 =
        (T.cell (b * 64) COL_AN - (k0aConst : Int)) % TWO32 := by
      have hre : T.cell (b * 64) COL_AN + TWO32 * carry3Val T (b * 64) COL_CA - (k0aConst : Int) =
          (T.cell (b * 64) COL_AN - (k0aConst : Int)) + TWO32 * carry3Val T (b * 64) COL_CA := by omega
      rw [hre, Int.add_emod, Int.mul_emod_right, Int.add_zero, Int.emod_emod]
    have h2 : (T.cell (b * 64) COL_AN - (k0aConst : Int)) % TWO32 = w0c % TWO32 := by
      rw [hA, Int.sub_emod, Int.emod_emod, ← Int.sub_emod]
      have : (k0aConst : Int) + w0c - (k0aConst : Int) = w0c := by omega
      rw [this]
    have h3 : z % TWO32 = w0c % TWO32 := by simpa [z, h1] using h2
    rw [Int.emod_eq_of_lt hw0c0 hw0c1] at h3
    exact h3.symm
  unfold RawBlockW0Matches
  rw [hcanon, ← hw0c_eq]
  exact ⟨hA, hE, hW⟩

-- ---- Recursive message & digest extraction across ALL 72 blocks ----

def blkMsgRec (T : RawFieldTrace) : Nat → Array UInt32
  | 0 => Array.replicate 16 0
  | b + 1 =>
    let w0 :=
      if b + 1 = 1 ∨ b + 1 = 36 then UInt32.ofNat TAG_ADDR
      else if b + 1 = 2 ∨ b + 1 = 37 ∨ b + 1 = 71 ∨ b + 1 = 72 then UInt32.ofNat TAG_CM
      else if b + 1 = 35 ∨ b + 1 = 70 then UInt32.ofNat TAG_NF
      else if T.cell ((b + 1) * 64) COL_BIT = 0 then arr8ToWord8 (sha256Compress (blkMsgRec T b)) 0
      else canonFreeW0 T (b + 1)
    blockMsgOfW0 T (b + 1) w0


theorem blkMsgRec_succ (T : RawFieldTrace) (b : Nat) :
    blkMsgRec T (b + 1) = blockMsgOfW0 T (b + 1)
      (if b + 1 = 1 ∨ b + 1 = 36 then UInt32.ofNat TAG_ADDR
       else if b + 1 = 2 ∨ b + 1 = 37 ∨ b + 1 = 71 ∨ b + 1 = 72 then UInt32.ofNat TAG_CM
       else if b + 1 = 35 ∨ b + 1 = 70 then UInt32.ofNat TAG_NF
       else if T.cell ((b + 1) * 64) COL_BIT = 0 then arr8ToWord8 (sha256Compress (blkMsgRec T b)) 0
       else canonFreeW0 T (b + 1)) := rfl

def blkDigRec (T : RawFieldTrace) (b : Nat) : Word8 :=
  arr8ToWord8 (sha256Compress (blkMsgRec T b))

-- Helper to extract msgLoadTerm at row (b-1)*64 + 63
theorem raw_block_load_zero {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hj : j < 16) :
    msgLoadTerm T ((b - 1) * 64 + 63) j % P = 0 := by
  have hpre := periodic_pre_block b hb1 hb72
  by_cases hj15 : j < 15
  · have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 70 + j) (by omega) (by omega)
    rw [eval_fipsCon_win_lt15 T _ j hj15, hpre.1, Int.zero_mul, Int.zero_add] at hz
    exact hz
  · have hj_eq : j = 15 := by omega
    subst hj_eq
    have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 85) (by omega) (by omega)
    rw [eval_fipsCon_85_load T _ hpre.1] at hz
    exact hz

theorem raw_all_72_blocks_digest_sound {T : RawFieldTrace} (hT : RawAirTransitionsHold T) :
    ∀ b, 1 ≤ b → b ≤ 72 → ∀ (j : Nat) (hj : j < 8), DigestCellRepresents T b j (blkDigRec T b ⟨j, hj⟩) := by
  intro b
  induction b with
  | zero => intro h; omega
  | succ m ih =>
    intro hb1 hb72
    have hidx : m * 64 + 63 + 1 = (m + 1) * 64 := by omega
    have hd : (m * 64 + 63) / 64 = m := by omega
    have hm63 : (m * 64 + 63) % 64 = 63 := by omega
    have hload0 := raw_block_load_zero hT (m + 1) 0 hb1 hb72 (by omega)
    simp only [Nat.add_sub_cancel] at hload0
    have hW0Match : RawBlockW0Matches T (m + 1)
        (if m + 1 = 1 ∨ m + 1 = 36 then UInt32.ofNat TAG_ADDR
         else if m + 1 = 2 ∨ m + 1 = 37 ∨ m + 1 = 71 ∨ m + 1 = 72 then UInt32.ofNat TAG_CM
         else if m + 1 = 35 ∨ m + 1 = 70 then UInt32.ofNat TAG_NF
         else if T.cell ((m + 1) * 64) COL_BIT = 0 then arr8ToWord8 (sha256Compress (blkMsgRec T m)) 0
         else canonFreeW0 T (m + 1)) := by
      by_cases hc1 : m + 1 = 1 ∨ m + 1 = 36
      · simp only [hc1, ↓reduceIte]
        have hm0 : m = 0 ∨ m = 35 := by omega
        have heq0 : (T.cell ((m + 1) * 64) COL_W - (TAG_ADDR : Int)) % P = 0 := by
          rcases hm0 with rfl | rfl <;>
            simpa [msgLoadTerm, periodicVal, hd, hm63, hidx] using hload0
        have hr := T.hRange ((m + 1) * 64) COL_W (by omega) (by decide)
        have hval := field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) heq0
        exact rawBlockW0Matches_of_eq hT (m + 1) hb1 hb72 (UInt32.ofNat TAG_ADDR) (by simpa [TAG_ADDR] using hval)
      · simp only [hc1, ↓reduceIte]
        by_cases hc2 : m + 1 = 2 ∨ m + 1 = 37 ∨ m + 1 = 71 ∨ m + 1 = 72
        · simp only [hc2, ↓reduceIte]
          have hm0 : m = 1 ∨ m = 36 ∨ m = 70 ∨ m = 71 := by omega
          have heq0 : (T.cell ((m + 1) * 64) COL_W - (TAG_CM : Int)) % P = 0 := by
            rcases hm0 with rfl | rfl | rfl | rfl <;>
              simpa [msgLoadTerm, periodicVal, hd, hm63, hidx] using hload0
          have hr := T.hRange ((m + 1) * 64) COL_W (by omega) (by decide)
          have hval := field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) heq0
          exact rawBlockW0Matches_of_eq hT (m + 1) hb1 hb72 (UInt32.ofNat TAG_CM) (by simpa [TAG_CM] using hval)
        · simp only [hc2, ↓reduceIte]
          by_cases hc3 : m + 1 = 35 ∨ m + 1 = 70
          · simp only [hc3, ↓reduceIte]
            have hm0 : m = 34 ∨ m = 69 := by omega
            have heq0 : (T.cell ((m + 1) * 64) COL_W - (TAG_NF : Int)) % P = 0 := by
              rcases hm0 with rfl | rfl <;>
                simpa [msgLoadTerm, periodicVal, hd, hm63, hidx] using hload0
            have hr := T.hRange ((m + 1) * 64) COL_W (by omega) (by decide)
            have hval := field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) heq0
            exact rawBlockW0Matches_of_eq hT (m + 1) hb1 hb72 (UInt32.ofNat TAG_NF) (by simpa [TAG_NF] using hval)
          · simp only [hc3, ↓reduceIte]
            -- Merkle block! m ∈ [2, 33] ∨ m ∈ [37, 68]
            have hmrk : (2 ≤ m ∧ m ≤ 33) ∨ (37 ≤ m ∧ m ≤ 68) := by omega
            by_cases hbit0 : T.cell ((m + 1) * 64) COL_BIT = 0
            · simp only [hbit0, ↓reduceIte]
              have h3 : ¬ (m = 0 ∨ m = 35) := by omega
              have h4 : ¬ (m = 1 ∨ m = 36) := by omega
              have h6 : ¬ (m = 34 ∨ m = 69) := by omega
              have h7 : ¬ (m = 70 ∨ m = 71) := by omega
              have heq0 : (T.cell ((m + 1) * 64) COL_W - T.cell (m * 64 + 63) (COL_DIG + 0)) % P = 0 := by
                simpa [msgLoadTerm, periodicVal, hd, hm63, hidx, hmrk, h3, h4, h6, h7, hbit0] using hload0
              have hr1 := T.hRange ((m + 1) * 64) COL_W (by omega) (by decide)
              have hr2 := T.hRange (m * 64 + 63) (COL_DIG + 0) (by omega) (by decide)
              have hval := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
              have hprevDig := ih (by omega) (by omega) 0 (by omega)
              exact rawBlockW0Matches_of_prevDig hT (m + 1) (by omega) hb72 _ hprevDig (by simpa using hval)
            · simp only [hbit0, ↓reduceIte]
              exact rawBlockW0Matches_free hT (m + 1) hb1 hb72
    have hcomp := raw_block_compress_sound hT (m + 1) hb1 hb72 _ hW0Match
    intro j hj
    exact hcomp j hj

-- ---- Register constancy, pos accumulation, high-word range check, balance telescoping ----

theorem raw_sk_const_in_block {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hj : j < 8) :
    ∀ t, t < 64 → T.cell (b * 64 + t) (COL_SK + j) = T.cell (b * 64) (COL_SK + j) := by
  intro t ht
  induction t with
  | zero => simp
  | succ k ih =>
    have hz := rawCon_zero hT (r := b * 64 + k) (i := 233 + j) (by omega) (by omega)
    rw [eval_fipsCon_sk T _ j hj] at hz
    have hp := (periodic_inner b k hb1 hb72 (by omega)).2.2.2.2.2.2.2.2.2.2.2.1
    rw [hp, Int.one_mul] at hz
    have hr1 := T.hRange (b * 64 + k + 1) (COL_SK + j) (by omega) (by simp [COL_SK, W_COLS]; omega)
    have hr2 := T.hRange (b * 64 + k) (COL_SK + j) (by omega) (by simp [COL_SK, W_COLS]; omega)
    have hstep := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz
    have hidx : b * 64 + (k + 1) = b * 64 + k + 1 := by omega
    rw [hidx, hstep, ih (by omega)]

theorem raw_sk_const_next {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b j : Nat) (hb1 : 1 ≤ b) (hb71 : b ≤ 71) (hne35 : b ≠ 35) (hj : j < 8) :
    T.cell ((b + 1) * 64) (COL_SK + j) = T.cell (b * 64) (COL_SK + j) := by
  have hz := rawCon_zero hT (r := b * 64 + 63) (i := 233 + j) (by omega) (by omega)
  rw [eval_fipsCon_sk T _ j hj] at hz
  have hd : (b * 64 + 63) / 64 = b := by omega
  have hm : (b * 64 + 63) % 64 = 63 := by omega
  have hp12 : periodicVal (b * 64 + 63) 12 = 1 := by
    have h64 : 64 ≤ b * 64 + 63 := by omega
    have h4671 : b * 64 + 63 < 4671 := by omega
    have hne0 : b ≠ 0 := by omega
    simp [periodicVal, hd, hm, h64, h4671, hne0, hne35]
  rw [hp12, Int.one_mul] at hz
  have hidx : b * 64 + 63 + 1 = (b + 1) * 64 := by omega
  rw [hidx] at hz
  have hr1 := T.hRange ((b + 1) * 64) (COL_SK + j) (by omega) (by simp [COL_SK, W_COLS]; omega)
  have hr2 := T.hRange (b * 64 + 63) (COL_SK + j) (by omega) (by simp [COL_SK, W_COLS]; omega)
  rw [field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz, raw_sk_const_in_block hT b j hb1 (by omega) hj 63 (by omega)]

theorem raw_rho_const_in_block {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hj : j < 5) :
    ∀ t, t < 64 → T.cell (b * 64 + t) (COL_RHO + j) = T.cell (b * 64) (COL_RHO + j) := by
  intro t ht
  induction t with
  | zero => simp
  | succ k ih =>
    have hz := rawCon_zero hT (r := b * 64 + k) (i := 241 + j) (by omega) (by omega)
    rw [eval_fipsCon_rho T _ j hj] at hz
    have hp := (periodic_inner b k hb1 hb72 (by omega)).2.2.2.2.2.2.2.2.2.2.2.2.1
    rw [hp, Int.one_mul] at hz
    have hr1 := T.hRange (b * 64 + k + 1) (COL_RHO + j) (by omega) (by simp [COL_RHO, W_COLS]; omega)
    have hr2 := T.hRange (b * 64 + k) (COL_RHO + j) (by omega) (by simp [COL_RHO, W_COLS]; omega)
    have hstep := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz
    have hidx : b * 64 + (k + 1) = b * 64 + k + 1 := by omega
    rw [hidx, hstep, ih (by omega)]

theorem raw_rho_const_next {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b j : Nat) (hb1 : 1 ≤ b) (hb71 : b ≤ 71) (hne1 : b ≠ 1) (hne36 : b ≠ 36) (hj : j < 5) :
    T.cell ((b + 1) * 64) (COL_RHO + j) = T.cell (b * 64) (COL_RHO + j) := by
  have hz := rawCon_zero hT (r := b * 64 + 63) (i := 241 + j) (by omega) (by omega)
  rw [eval_fipsCon_rho T _ j hj] at hz
  have hd : (b * 64 + 63) / 64 = b := by omega
  have hm : (b * 64 + 63) % 64 = 63 := by omega
  have hp13 : periodicVal (b * 64 + 63) 13 = 1 := by
    have h64 : 64 ≤ b * 64 + 63 := by omega
    have h4671 : b * 64 + 63 < 4671 := by omega
    simp [periodicVal, hd, hm, h64, h4671, hne1, hne36]
  rw [hp13, Int.one_mul] at hz
  have hidx : b * 64 + 63 + 1 = (b + 1) * 64 := by omega
  rw [hidx] at hz
  have hr1 := T.hRange ((b + 1) * 64) (COL_RHO + j) (by omega) (by simp [COL_RHO, W_COLS]; omega)
  have hr2 := T.hRange (b * 64 + 63) (COL_RHO + j) (by omega) (by simp [COL_RHO, W_COLS]; omega)
  rw [field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz, raw_rho_const_in_block hT b j hb1 (by omega) hj 63 (by omega)]

theorem raw_pos_const_in_block {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    ∀ t, t < 64 → T.cell (b * 64 + t) COL_POS = T.cell (b * 64) COL_POS := by
  intro t ht
  induction t with
  | zero => simp
  | succ k ih =>
    have hz := rawCon_zero hT (r := b * 64 + k) (i := 246) (by omega) (by omega)
    rw [eval_fipsCon_246] at hz
    have hp := periodic_inner b k hb1 hb72 (by omega)
    rw [hp.2.2.2.2.2.2.2.2.2.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.1, hp.2.2.2.2.2.2.2.2.1,
        Int.one_mul, Int.one_mul, Int.zero_mul, Int.sub_zero] at hz
    have hr1 := T.hRange (b * 64 + k + 1) COL_POS (by omega) (by decide)
    have hr2 := T.hRange (b * 64 + k) COL_POS (by omega) (by decide)
    have hidx : b * 64 + (k + 1) = b * 64 + k + 1 := by omega
    rw [hidx, field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 hz, ih (by omega)]

theorem raw_bal_const_in_block {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) :
    ∀ t, t < 64 → (T.cell (b * 64 + t) COL_BAL - T.cell (b * 64) COL_BAL) % P = 0 := by
  intro t ht
  induction t with
  | zero => simp
  | succ k ih =>
    have hz := rawCon_zero hT (r := b * 64 + k) (i := 247) (by omega) (by omega)
    rw [eval_fipsCon_247] at hz
    have hp := periodic_inner b k hb1 hb72 (by omega)
    rw [hp.2.2.2.2.2.2.2.2.2.2.1, hp.2.2.2.2.1, hp.2.2.2.2.2.2.2.1,
        Int.one_mul, Int.zero_mul, Int.sub_zero, Int.add_zero] at hz
    rcases Int.dvd_of_emod_eq_zero hz with ⟨q1, hq1⟩
    rcases Int.dvd_of_emod_eq_zero (ih (by omega)) with ⟨q2, hq2⟩
    have hidx : b * 64 + (k + 1) = b * 64 + k + 1 := by omega
    rw [hidx]
    have hsum : T.cell (b * 64 + k + 1) COL_BAL - T.cell (b * 64) COL_BAL = P * (q1 + q2) := by
      rw [Int.mul_add]; omega
    rw [hsum]; exact Int.mul_emod_right P _

theorem raw_vhi_lt_2p28 {T : RawFieldTrace} (hT : RawAirTransitionsHold T)
    (b : Nat) (hb : b = 2 ∨ b = 37 ∨ b = 71 ∨ b = 72) :
    (rawW T b 9).toNat < 268435456 := by
  have hb1 : 1 ≤ b := by omega
  have hb72 : b ≤ 72 := by omega
  have hz := rawCon_zero hT (r := b * 64 + 8) (i := 248) (by omega) (by omega)
  rw [eval_fipsCon_248] at hz
  have hd : (b * 64 + 8) / 64 = b := by omega
  have hm : (b * 64 + 8) % 64 = 8 := by omega
  have hp9 : periodicVal (b * 64 + 8) 9 = 1 := by simp [periodicVal, hd, hm, hb]
  rw [hp9, Int.one_mul] at hz
  have h28 := raw_bool_X1 hT b 8 28 hb1 hb72 (by omega) (by omega)
  have h29 := raw_bool_X1 hT b 8 29 hb1 hb72 (by omega) (by omega)
  have h30 := raw_bool_X1 hT b 8 30 hb1 hb72 (by omega) (by omega)
  have h31 := raw_bool_X1 hT b 8 31 hb1 hb72 (by omega) (by omega)
  have hsum_bd : 0 ≤ T.cell (b * 64 + 8) (COL_X1 + 28) + T.cell (b * 64 + 8) (COL_X1 + 29) +
      T.cell (b * 64 + 8) (COL_X1 + 30) + T.cell (b * 64 + 8) (COL_X1 + 31) ∧
      T.cell (b * 64 + 8) (COL_X1 + 28) + T.cell (b * 64 + 8) (COL_X1 + 29) +
      T.cell (b * 64 + 8) (COL_X1 + 30) + T.cell (b * 64 + 8) (COL_X1 + 31) < P := by
    simp only [P]; omega
  rw [Int.emod_eq_of_lt hsum_bd.1 hsum_bd.2] at hz
  have hz28 : T.cell (b * 64 + 8) (COL_X1 + 28) = 0 := by omega
  have hz29 : T.cell (b * 64 + 8) (COL_X1 + 29) = 0 := by omega
  have hz30 : T.cell (b * 64 + 8) (COL_X1 + 30) = 0 := by omega
  have hz31 : T.cell (b * 64 + 8) (COL_X1 + 31) = 0 := by omega
  have hpack := (raw_w1_eq_packX1 hT b 8 hb1 hb72 (by omega)).1
  have h28_bd := packBits_bounds (fun j => T.cell (b * 64 + 8) (COL_X1 + j)) 28
    (fun j hj => raw_bool_X1 hT b 8 j hb1 hb72 (by omega) (by omega))
  have hpack32_eq : packBits (fun j => T.cell (b * 64 + 8) (COL_X1 + j)) 32 =
      packBits (fun j => T.cell (b * 64 + 8) (COL_X1 + j)) 28 := by
    simp [packBits, hz28, hz29, hz30, hz31]
  have hw9 : ((rawW T b 9).toNat : Int) = T.cell (b * 64 + 8) (COL_W + 1) :=
    rawW_toNat_int hT b 9 hb1 hb72 (by omega) (by omega)
  have hval : ((rawW T b 9).toNat : Int) = packBits (fun j => T.cell (b * 64 + 8) (COL_X1 + j)) 28 := by
    rw [hw9, hpack, hpack32_eq]
  have hlt : packBits (fun j => T.cell (b * 64 + 8) (COL_X1 + j)) 28 < (268435456 : Int) := by
    simpa using h28_bd.2
  omega

-- ---- MASTER REFINEMENT THEOREM: Raw 8,192 x 247 AIR -> AcceptedSpendTrace -> ValidSpendWitness ----

theorem raw_air_trace_implies_accepted_spend_trace
    (pi : SpendPublicStmt) (T : RawFieldTrace)
    (hT : RawAirTransitionsHold T) (hB : RawBoundaryAssertions pi T) :
    Nonempty (AcceptedSpendTrace pi) := by
  have hDig := raw_all_72_blocks_digest_sound hT
  -- Helper: initial word W_j (1 ≤ j ≤ 15) on row b*64 equals rawW T b j
  have hInitW : ∀ b j, 1 ≤ b → b ≤ 72 → 1 ≤ j → j ≤ 15 →
      T.cell (b * 64) (COL_W + j) = ((rawW T b j).toNat : Int) := fun b j hb1 hb72 hj1 hj15 => by
    have h1 := raw_window_eq_sched hT b 0 j hb1 hb72 (by omega) (by omega) (by omega) (by omega)
    have h2 := rawW_toNat_int hT b j hb1 hb72 hj1 (by omega)
    have h1' : T.cell (b * 64) (COL_W + j) = rawSchedWord T b j := by simpa [Nat.add_zero, Nat.zero_add] using h1
    exact h1'.trans h2.symm
  -- Helper: block-level registers
  let skReg  (b : Nat) : Word8 := fun j => UInt32.ofNat (T.cell (b * 64) (COL_SK + j.val)).toNat
  let rhoReg (b : Nat) : Rho5  := fun j => UInt32.ofNat (T.cell (b * 64) (COL_RHO + j.val)).toNat
  let posReg (b : Nat) : Nat   := (T.cell (b * 64) COL_POS).toNat
  let bitReg (b : Nat) : Nat   := (T.cell (b * 64) COL_BIT).toNat
  let sibReg (b : Nat) : Word8 := fun j =>
    if T.cell (b * 64) COL_BIT = 0 then rawW T b (8 + j.val)
    else if j.val = 0 then canonFreeW0 T b
    else rawW T b j.val
  let balReg (b : Nat) : Int :=
    if b ≤ 1 then T.cell 64 COL_BAL else T.cell ((b - 1) * 64 + 63) COL_BAL
  -- Prove bitReg booleanity
  have hBitBool : ∀ b, 1 ≤ b → b ≤ 72 → bitReg b = 0 ∨ bitReg b = 1 := fun b hb1 hb72 => by
    have hb := raw_bool9 hT b 0 8 hb1 hb72 (by omega) (by omega)
    simp only [bool9Col, Nat.add_zero] at hb
    rcases hb with h0 | h1
    · left; simp [bitReg, h0]
    · right; simp [bitReg, h1]
  -- Prove skReg & rhoReg constancy across both input halves
  have hSkConst0 : ∀ b, 1 ≤ b → b < 35 → skReg (b + 1) = skReg b := fun b hb1 hb35 => by
    funext j; simp only [skReg]
    rw [raw_sk_const_next hT b j.val hb1 (by omega) (by omega) j.isLt]
  have hSkConst1 : ∀ b, 36 ≤ b → b < 70 → skReg (b + 1) = skReg b := fun b hb36 hb70 => by
    funext j; simp only [skReg]
    rw [raw_sk_const_next hT b j.val (by omega) (by omega) (by omega) j.isLt]
  have hRhoCst0 : ∀ b, 2 ≤ b → b < 35 → rhoReg (b + 1) = rhoReg b := fun b hb2 hb35 => by
    funext j; simp only [rhoReg]
    rw [raw_rho_const_next hT b j.val (by omega) (by omega) (by omega) (by omega) j.isLt]
  have hRhoCst1 : ∀ b, 37 ≤ b → b < 70 → rhoReg (b + 1) = rhoReg b := fun b hb37 hb70 => by
    funext j; simp only [rhoReg]
    rw [raw_rho_const_next hT b j.val (by omega) (by omega) (by omega) (by omega) j.isLt]
  -- Helper: pos step between consecutive blocks
  have hPosNext : ∀ b, 1 ≤ b → b ≤ 71 →
      (T.cell ((b + 1) * 64) COL_POS -
       (if b = 35 then 0 else T.cell (b * 64) COL_POS) -
       periodicVal (b * 64 + 63) 8 * T.cell ((b + 1) * 64) COL_BIT) % P = 0 := fun b hb1 hb71 => by
    have hz := rawCon_zero hT (r := b * 64 + 63) (i := 246) (by omega) (by omega)
    rw [eval_fipsCon_246] at hz
    have hidx : b * 64 + 63 + 1 = (b + 1) * 64 := by omega
    have hd : (b * 64 + 63) / 64 = b := by omega
    have hm : (b * 64 + 63) % 64 = 63 := by omega
    have h64 : 64 ≤ b * 64 + 63 := by omega
    have h4671 : b * 64 + 63 < 4671 := by omega
    have hp11 : periodicVal (b * 64 + 63) 11 = 1 := by simp [periodicVal, h64, h4671]
    have hp12 : periodicVal (b * 64 + 63) 12 = if b = 35 then 0 else 1 := by
      have hne0 : b ≠ 0 := by omega
      by_cases h35 : b = 35
      · subst h35; simp [periodicVal, hd, hm, h64, h4671]
      · simp [periodicVal, hd, hm, h64, h4671, hne0, h35]
    rw [hidx, hp11, hp12, Int.one_mul, raw_pos_const_in_block hT b hb1 (by omega) 63 (by omega)] at hz
    by_cases h35 : b = 35 <;> simp [h35] at hz ⊢ <;> exact hz
  -- Prove pos0Init, pos0Step, pos0Hold, pos1Init, pos1Step, pos1Hold
  have hPos0_1 : T.cell (1 * 64) COL_POS = 0 := by simpa using hB.hPos0
  have hPos0InitInt : T.cell (2 * 64) COL_POS = 0 := by
    have h := hPosNext 1 (by omega) (by omega)
    have hp8 : periodicVal (1 * 64 + 63) 8 = 0 := by decide
    rw [hp8, hPos0_1] at h
    simp only [show ¬(1 = 35) from by decide, ↓reduceIte, Int.zero_mul, Int.sub_zero] at h
    have hr := T.hRange (2 * 64) COL_POS (by omega) (by decide)
    exact field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) (by simpa using h)
  have hPos1_36 : T.cell (36 * 64) COL_POS = 0 := by
    have h := hPosNext 35 (by omega) (by omega)
    have hp8 : periodicVal (35 * 64 + 63) 8 = 0 := by decide
    rw [hp8] at h
    simp only [↓reduceIte, Int.zero_mul, Int.sub_zero] at h
    have hr := T.hRange (36 * 64) COL_POS (by omega) (by decide)
    exact field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) (by simpa using h)
  have hPos1InitInt : T.cell (37 * 64) COL_POS = 0 := by
    have h := hPosNext 36 (by omega) (by omega)
    have hp8 : periodicVal (36 * 64 + 63) 8 = 0 := by decide
    rw [hp8, hPos1_36] at h
    simp only [show ¬(36 = 35) from by decide, ↓reduceIte, Int.zero_mul, Int.sub_zero] at h
    have hr := T.hRange (37 * 64) COL_POS (by omega) (by decide)
    exact field_eq_of_sub_mod_P hr.1 hr.2 (by decide) (by decide) (by simpa using h)
  -- Inductive helper for pos accumulation in input 0 & input 1 (no wrap mod P since < 2^32 < P!)
  have hPosChain : ∀ (base : Nat), (base = 2 ∨ base = 37) → T.cell (base * 64) COL_POS = 0 →
      ∀ k, k ≤ 32 →
        T.cell ((base + k) * 64) COL_POS < ((2 ^ k : Nat) : Int) ∧
        (∀ j, j < k → posReg (base + 1 + j) = posReg (base + j) + bitReg (base + 1 + j) * 2 ^ j) := by
    intro base hbase hinit k hk
    induction k with
    | zero =>
      simp only [Nat.add_zero, Nat.pow_zero]
      exact ⟨by rw [hinit]; decide, fun j hj => by omega⟩
    | succ m ih =>
      have hprev := ih (by omega)
      have hstep := hPosNext (base + m) (by omega) (by omega)
      have hne35 : base + m ≠ 35 := by omega
      have hd : ((base + m) * 64 + 63) / 64 = base + m := by omega
      have hm63 : ((base + m) * 64 + 63) % 64 = 63 := by omega
      have hp8 : periodicVal ((base + m) * 64 + 63) 8 = ((2 ^ m : Nat) : Int) := by
        rcases hbase with rfl | rfl
        · simp [periodicVal, hd, hm63, show 2 ≤ 2 + m from by omega, show 2 + m ≤ 33 from by omega]
        · simp [periodicVal, hd, hm63, show ¬(37 + m ≤ 33) from by omega,
                show 37 ≤ 37 + m from by omega, show 37 + m ≤ 68 from by omega]
      rw [hp8] at hstep
      simp only [hne35, ↓reduceIte] at hstep
      have hbit := raw_bool9 hT (base + m + 1) 0 8 (by omega) (by omega) (by omega) (by omega)
      simp only [bool9Col, Nat.add_zero] at hbit
      have hr_nxt := T.hRange ((base + m + 1) * 64) COL_POS (by omega) (by decide)
      have hr_cur := T.hRange ((base + m) * 64) COL_POS (by omega) (by decide)
      have h2m_le : ((2 ^ m : Nat) : Int) ≤ (2 ^ 31 : Nat) := by
        have := Nat.pow_le_pow_right (by decide : 0 < 2) (show m ≤ 31 from by omega); omega
      have hsum_bd : 0 ≤ T.cell ((base + m) * 64) COL_POS + ((2 ^ m : Nat) : Int) * T.cell ((base + m + 1) * 64) COL_BIT ∧
          T.cell ((base + m) * 64) COL_POS + ((2 ^ m : Nat) : Int) * T.cell ((base + m + 1) * 64) COL_BIT < ((2 ^ (m + 1) : Nat) : Int) := by
        have hpow : (2 ^ (m + 1) : Nat) = 2 ^ m + 2 ^ m := by rw [Nat.pow_succ]; omega
        rcases hbit with h0 | h1
        · rw [h0]; omega
        · rw [h1]; omega
      have hsum_P : T.cell ((base + m) * 64) COL_POS + ((2 ^ m : Nat) : Int) * T.cell ((base + m + 1) * 64) COL_BIT < P := by
        have : (2 ^ (m + 1) : Nat) ≤ 2 ^ 32 := Nat.pow_le_pow_right (by decide) (by omega)
        simp only [P]; omega
      have hsub_eq : (T.cell ((base + m + 1) * 64) COL_POS -
          (T.cell ((base + m) * 64) COL_POS + ((2 ^ m : Nat) : Int) * T.cell ((base + m + 1) * 64) COL_BIT)) % P = 0 := by
        have hre : T.cell ((base + m + 1) * 64) COL_POS -
            (T.cell ((base + m) * 64) COL_POS + ((2 ^ m : Nat) : Int) * T.cell ((base + m + 1) * 64) COL_BIT) =
            T.cell ((base + m + 1) * 64) COL_POS - T.cell ((base + m) * 64) COL_POS -
            ((2 ^ m : Nat) : Int) * T.cell ((base + m + 1) * 64) COL_BIT := by omega
        rw [hre]; exact hstep
      have heqInt := field_eq_of_sub_mod_P hr_nxt.1 hr_nxt.2 hsum_bd.1 hsum_P hsub_eq
      have hidx : base + (m + 1) = base + m + 1 := by omega
      refine ⟨by rw [hidx, heqInt]; exact hsum_bd.2, fun j hj => ?_⟩
      by_cases hjm : j = m
      · subst hjm
        have hidx2 : base + 1 + j = base + j + 1 := by omega
        simp only [posReg, bitReg, hidx2, heqInt]
        rcases hbit with h0 | h1
        · rw [h0]; simp
        · rw [h1, Int.mul_one, Int.toNat_add hr_cur.1 (by omega), Int.toNat_natCast]; simp
      · exact hprev.2 j (by omega)
  have hPosC0 := hPosChain 2 (Or.inl rfl) hPos0InitInt 32 (by omega)
  have hPosC1 := hPosChain 37 (Or.inr rfl) hPos1InitInt 32 (by omega)
  have hPos0Hold : posReg 35 = posReg 34 := by
    have h := hPosNext 34 (by omega) (by omega)
    have hp8 : periodicVal (34 * 64 + 63) 8 = 0 := by decide
    rw [hp8] at h
    simp only [show ¬(34 = 35) from by decide, ↓reduceIte, Int.zero_mul, Int.sub_zero] at h
    have hr1 := T.hRange (35 * 64) COL_POS (by omega) (by decide)
    have hr2 := T.hRange (34 * 64) COL_POS (by omega) (by decide)
    have heq := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 h
    simp [posReg, heq]
  have hPos1Hold : posReg 70 = posReg 69 := by
    have h := hPosNext 69 (by omega) (by omega)
    have hp8 : periodicVal (69 * 64 + 63) 8 = 0 := by decide
    rw [hp8] at h
    simp only [show ¬(69 = 35) from by decide, ↓reduceIte, Int.zero_mul, Int.sub_zero] at h
    have hr1 := T.hRange (70 * 64) COL_POS (by omega) (by decide)
    have hr2 := T.hRange (69 * 64) COL_POS (by omega) (by decide)
    have heq := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 h
    simp [posReg, heq]
  -- Helper: prove exact message equality for Addr(0) / Addr(1)
  have hMsgAddr : ∀ b, (b = 1 ∨ b = 36) →
      blkMsgRec T b = #[UInt32.ofNat TAG_ADDR,
        skReg b 0, skReg b 1, skReg b 2, skReg b 3, skReg b 4, skReg b 5, skReg b 6, skReg b 7,
        0, 0, 0, 0, 0, 0, 0] := fun b hb => by
    have hsk : ∀ j : Fin 8, rawW T b (j.val + 1) = skReg b j := fun j => by
      have hl := raw_block_load_zero hT b (j.val + 1) (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : (T.cell (b * 64) (COL_W + (j.val + 1)) - T.cell (b * 64) (COL_SK + j.val)) % P = 0 := by
        rcases hb with rfl | rfl <;>
          simpa [msgLoadTerm, periodicVal, hd, hm, hidx, show j.val + 1 ≠ 0 from by omega,
                 show j.val + 1 ≤ 8 from by omega] using hl
      have hr1 := T.hRange (b * 64) (COL_W + (j.val + 1)) (by omega) (by simp [COL_W, W_COLS]; omega)
      have hr2 := T.hRange (b * 64) (COL_SK + j.val) (by omega) (by simp [COL_SK, W_COLS]; omega)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
      have hw := hInitW b (j.val + 1) (by omega) (by omega) (by omega) (by omega)
      have hsk_lt : T.cell (b * 64) (COL_SK + j.val) < TWO32 := by
        rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b (j.val + 1))
      apply u32_eq_of_toNat_int
      rw [← hw, hcell, u32_ofNat_toNat_int _ hr2.1 hsk_lt]
    have hzero : ∀ j, 9 ≤ j → j ≤ 15 → rawW T b j = 0 := fun j hj9 hj15 => by
      have hl := raw_block_load_zero hT b j (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : T.cell (b * 64) (COL_W + j) % P = 0 := by
        rcases hb with rfl | rfl <;>
          simpa [msgLoadTerm, periodicVal, hd, hm, hidx, show j ≠ 0 from by omega,
                 show ¬(j ≤ 8) from by omega] using hl
      have hr1 := T.hRange (b * 64) (COL_W + j) (by omega) (by simp [COL_W, W_COLS]; omega)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 (y := (0 : Int)) (by decide) (by decide) (by simpa using heq0)
      have hw := hInitW b j (by omega) (by omega) (by omega) hj15
      apply u32_eq_of_toNat_int; rw [← hw, hcell]; rfl
    have hbm : blkMsgRec T b = blockMsgOfW0 T b (UInt32.ofNat TAG_ADDR) := by
      rcases hb with rfl | rfl
      · rw [blkMsgRec_succ]; simp
      · rw [blkMsgRec_succ]; simp
    rw [hbm]
    simp only [blockMsgOfW0,
      hsk ⟨0, by decide⟩, hsk ⟨1, by decide⟩, hsk ⟨2, by decide⟩, hsk ⟨3, by decide⟩,
      hsk ⟨4, by decide⟩, hsk ⟨5, by decide⟩, hsk ⟨6, by decide⟩, hsk ⟨7, by decide⟩,
      hzero 9 (by decide) (by decide), hzero 10 (by decide) (by decide), hzero 11 (by decide) (by decide),
      hzero 12 (by decide) (by decide), hzero 13 (by decide) (by decide), hzero 14 (by decide) (by decide),
      hzero 15 (by decide) (by decide)]
    rfl
  -- Helper: prove exact message equality for CmIn(0) / CmIn(1)
  have hMsgCmIn : ∀ b, (b = 2 ∨ b = 37) →
      blkMsgRec T b = #[UInt32.ofNat TAG_CM,
        blkDigRec T (b - 1) 0, blkDigRec T (b - 1) 1, blkDigRec T (b - 1) 2, blkDigRec T (b - 1) 3,
        blkDigRec T (b - 1) 4, blkDigRec T (b - 1) 5, blkDigRec T (b - 1) 6, blkDigRec T (b - 1) 7,
        rawW T b 9, rawW T b 10,
        rhoReg b 0, rhoReg b 1, rhoReg b 2, rhoReg b 3, rhoReg b 4] := fun b hb => by
    have hapk : ∀ j : Fin 8, rawW T b (j.val + 1) = blkDigRec T (b - 1) j := fun j => by
      have hl := raw_block_load_zero hT b (j.val + 1) (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : (T.cell (b * 64) (COL_W + (j.val + 1)) - T.cell ((b - 1) * 64 + 63) (COL_DIG + j.val)) % P = 0 := by
        rcases hb with rfl | rfl <;>
          simpa [msgLoadTerm, periodicVal, hd, hm, hidx, show j.val + 1 ≠ 0 from by omega,
                 show j.val + 1 ≤ 8 from by omega] using hl
      have hr1 := T.hRange (b * 64) (COL_W + (j.val + 1)) (by omega) (by simp [COL_W, W_COLS]; omega)
      have hr2 := T.hRange ((b - 1) * 64 + 63) (COL_DIG + j.val) (by omega) (by simp [COL_DIG, W_COLS]; omega)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
      have hw := hInitW b (j.val + 1) (by omega) (by omega) (by omega) (by omega)
      have hdig_lt : T.cell ((b - 1) * 64 + 63) (COL_DIG + j.val) < TWO32 := by
        rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b (j.val + 1))
      have hdeq := digest_cell_eq_of_lt hT (b - 1) j.val (by omega) (by omega) j.isLt _
        (hDig (b - 1) (by omega) (by omega) j.val j.isLt) hdig_lt
      apply u32_eq_of_toNat_int; rw [← hw, hcell, hdeq]
    have hrho : ∀ j : Fin 5, rawW T b (j.val + 11) = rhoReg b j := fun j => by
      have hl := raw_block_load_zero hT b (j.val + 11) (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : (T.cell (b * 64) (COL_W + (j.val + 11)) - T.cell (b * 64) (COL_RHO + j.val)) % P = 0 := by
        have hsub : COL_RHO + (j.val + 11) - 11 = COL_RHO + j.val := by omega
        rcases hb with rfl | rfl <;>
          simpa [msgLoadTerm, periodicVal, hd, hm, hidx, hsub, show j.val + 11 ≠ 0 from by omega,
                 show ¬(j.val + 11 ≤ 8) from by omega, show j.val + 11 ≥ 11 from by omega] using hl
      have hr1 := T.hRange (b * 64) (COL_W + (j.val + 11)) (by omega) (by simp [COL_W, W_COLS]; omega)
      have hr2 := T.hRange (b * 64) (COL_RHO + j.val) (by omega) (by simp [COL_RHO, W_COLS]; omega)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
      have hw := hInitW b (j.val + 11) (by omega) (by omega) (by omega) (by omega)
      have hrho_lt : T.cell (b * 64) (COL_RHO + j.val) < TWO32 := by
        rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b (j.val + 11))
      apply u32_eq_of_toNat_int; rw [← hw, hcell, u32_ofNat_toNat_int _ hr2.1 hrho_lt]
    have hbm : blkMsgRec T b = blockMsgOfW0 T b (UInt32.ofNat TAG_CM) := by
      rcases hb with rfl | rfl
      · rw [blkMsgRec_succ]; simp
      · rw [blkMsgRec_succ]; simp
    rw [hbm]
    simp only [blockMsgOfW0,
      hapk ⟨0, by decide⟩, hapk ⟨1, by decide⟩, hapk ⟨2, by decide⟩, hapk ⟨3, by decide⟩,
      hapk ⟨4, by decide⟩, hapk ⟨5, by decide⟩, hapk ⟨6, by decide⟩, hapk ⟨7, by decide⟩,
      hrho ⟨0, by decide⟩, hrho ⟨1, by decide⟩, hrho ⟨2, by decide⟩, hrho ⟨3, by decide⟩, hrho ⟨4, by decide⟩]
    rfl
  -- Helper: prove exact message equality for Merkle(i, k) blocks!
  have hMsgMrk : ∀ b, ((3 ≤ b ∧ b ≤ 34) ∨ (38 ≤ b ∧ b ≤ 69)) →
      blkMsgRec T b = merkleMsg (blkDigRec T (b - 1)) (sibReg b) (bitReg b) := fun b hb => by
    have hb1 : 1 ≤ b := by omega
    have hb72 : b ≤ 72 := by omega
    have hbit := raw_bool9 hT b 0 8 hb1 hb72 (by omega) (by omega)
    simp only [bool9Col, Nat.add_zero] at hbit
    have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
    have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
    have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
    have hp3 : periodicVal ((b - 1) * 64 + 63) 3 = 0 := by
      unfold periodicVal; simp only [hd, hm]; split <;> omega
    have hp4 : periodicVal ((b - 1) * 64 + 63) 4 = 0 := by
      unfold periodicVal; simp only [hd, hm]; split <;> omega
    have hp5 : periodicVal ((b - 1) * 64 + 63) 5 = 1 := by
      have hcond : 63 = 63 ∧ ((2 ≤ b - 1 ∧ b - 1 ≤ 33) ∨ (37 ≤ b - 1 ∧ b - 1 ≤ 68)) := by omega
      simp only [periodicVal, hd, hm, hcond]; decide
    have hp6 : periodicVal ((b - 1) * 64 + 63) 6 = 0 := by
      unfold periodicVal; simp only [hd, hm]; split <;> omega
    have hp7 : periodicVal ((b - 1) * 64 + 63) 7 = 0 := by
      unfold periodicVal; simp only [hd, hm]; split <;> omega
    have hnot1 : ¬ (b = 1 ∨ b = 36) := by omega
    have hnot2 : ¬ (b = 2 ∨ b = 37 ∨ b = 71 ∨ b = 72) := by omega
    have hnot3 : ¬ (b = 35 ∨ b = 70) := by omega
    have hb_succ : b = (b - 1) + 1 := by omega
    rcases hbit with h0 | h1
    · -- bit = 0: W_0 = prevDig 0, W_1..W_7 = prevDig 1..7, W_8..W_15 = sib
      have hleft : ∀ j : Fin 8, 1 ≤ j.val → rawW T b j.val = blkDigRec T (b - 1) j := fun j hj1 => by
        have hl := raw_block_load_zero hT b j.val hb1 hb72 (by omega)
        have heq0 : (T.cell (b * 64) (COL_W + j.val) - T.cell ((b - 1) * 64 + 63) (COL_DIG + j.val)) % P = 0 := by
          simp only [msgLoadTerm, hp3, hp4, hp5, hp6, hp7, hidx, h0, j.isLt, ↓reduceIte,
            Int.zero_mul, Int.sub_zero, Int.one_mul, Int.zero_add, Int.add_zero, ite_self] at hl
          exact hl
        have hr1 := T.hRange (b * 64) (COL_W + j.val) (by omega) (by simp [COL_W, W_COLS]; omega)
        have hr2 := T.hRange ((b - 1) * 64 + 63) (COL_DIG + j.val) (by omega) (by simp [COL_DIG, W_COLS]; omega)
        have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
        have hw := hInitW b j.val hb1 hb72 hj1 (by omega)
        have hdig_lt : T.cell ((b - 1) * 64 + 63) (COL_DIG + j.val) < TWO32 := by
          rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b j.val)
        have hdeq := digest_cell_eq_of_lt hT (b - 1) j.val (by omega) (by omega) j.isLt _
          (hDig (b - 1) (by omega) (by omega) j.val j.isLt) hdig_lt
        apply u32_eq_of_toNat_int; rw [← hw, hcell, hdeq]
      have hbm : blkMsgRec T b = blockMsgOfW0 T b (blkDigRec T (b - 1) 0) := by
        rw [congrArg (blkMsgRec T) hb_succ, blkMsgRec_succ]
        simp only [← hb_succ, hnot1, hnot2, hnot3, h0, ↓reduceIte, blkDigRec]
      rw [hbm]
      have hl1 : rawW T b 1 = blkDigRec T (b - 1) 1 := hleft ⟨1, by decide⟩ (by decide)
      have hl2 : rawW T b 2 = blkDigRec T (b - 1) 2 := hleft ⟨2, by decide⟩ (by decide)
      have hl3 : rawW T b 3 = blkDigRec T (b - 1) 3 := hleft ⟨3, by decide⟩ (by decide)
      have hl4 : rawW T b 4 = blkDigRec T (b - 1) 4 := hleft ⟨4, by decide⟩ (by decide)
      have hl5 : rawW T b 5 = blkDigRec T (b - 1) 5 := hleft ⟨5, by decide⟩ (by decide)
      have hl6 : rawW T b 6 = blkDigRec T (b - 1) 6 := hleft ⟨6, by decide⟩ (by decide)
      have hl7 : rawW T b 7 = blkDigRec T (b - 1) 7 := hleft ⟨7, by decide⟩ (by decide)
      simp only [blockMsgOfW0, merkleMsg, bitReg, sibReg, h0, Int.toNat_zero, ↓reduceIte,
        hl1, hl2, hl3, hl4, hl5, hl6, hl7]
      rfl
    · -- bit = 1: W_0..W_7 = sib, W_8..W_15 = prevDig 0..7
      have hright : ∀ j : Fin 8, rawW T b (8 + j.val) = blkDigRec T (b - 1) j := fun j => by
        have hl := raw_block_load_zero hT b (8 + j.val) hb1 hb72 (by omega)
        have heq0 : (T.cell (b * 64) (COL_W + (8 + j.val)) - T.cell ((b - 1) * 64 + 63) (COL_DIG + j.val)) % P = 0 := by
          have hsub : COL_DIG + (8 + j.val) - 8 = COL_DIG + j.val := by omega
          have hnot8 : ¬ (8 + j.val < 8) := by omega
          simp only [msgLoadTerm, hp3, hp4, hp5, hp6, hp7, hidx, h1, hnot8, hsub, ↓reduceIte,
            Int.zero_mul, Int.one_mul, Int.zero_add, Int.add_zero, ite_self] at hl
          exact hl
        have hr1 := T.hRange (b * 64) (COL_W + (8 + j.val)) (by omega) (by simp [COL_W, W_COLS]; omega)
        have hr2 := T.hRange ((b - 1) * 64 + 63) (COL_DIG + j.val) (by omega) (by simp [COL_DIG, W_COLS]; omega)
        have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
        have hw := hInitW b (8 + j.val) hb1 hb72 (by omega) (by omega)
        have hdig_lt : T.cell ((b - 1) * 64 + 63) (COL_DIG + j.val) < TWO32 := by
          rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b (8 + j.val))
        have hdeq := digest_cell_eq_of_lt hT (b - 1) j.val (by omega) (by omega) j.isLt _
          (hDig (b - 1) (by omega) (by omega) j.val j.isLt) hdig_lt
        apply u32_eq_of_toNat_int; rw [← hw, hcell, hdeq]
      have hbm : blkMsgRec T b = blockMsgOfW0 T b (canonFreeW0 T b) := by
        rw [congrArg (blkMsgRec T) hb_succ, blkMsgRec_succ]
        simp only [← hb_succ, hnot1, hnot2, hnot3, h1, show ¬((1 : Int) = 0) from by decide, ↓reduceIte]
      rw [hbm]
      have hr0 : rawW T b 8  = blkDigRec T (b - 1) 0 := hright ⟨0, by decide⟩
      have hr1 : rawW T b 9  = blkDigRec T (b - 1) 1 := hright ⟨1, by decide⟩
      have hr2 : rawW T b 10 = blkDigRec T (b - 1) 2 := hright ⟨2, by decide⟩
      have hr3 : rawW T b 11 = blkDigRec T (b - 1) 3 := hright ⟨3, by decide⟩
      have hr4 : rawW T b 12 = blkDigRec T (b - 1) 4 := hright ⟨4, by decide⟩
      have hr5 : rawW T b 13 = blkDigRec T (b - 1) 5 := hright ⟨5, by decide⟩
      have hr6 : rawW T b 14 = blkDigRec T (b - 1) 6 := hright ⟨6, by decide⟩
      have hr7 : rawW T b 15 = blkDigRec T (b - 1) 7 := hright ⟨7, by decide⟩
      simp only [blockMsgOfW0, merkleMsg, bitReg, sibReg, h1, show ¬((1 : Int) = 0) from by decide,
        show ¬((1 : Int).toNat = 0) from by decide, ↓reduceIte,
        hr0, hr1, hr2, hr3, hr4, hr5, hr6, hr7]
      rfl
  -- Helper: prove exact message equality for Nf(0) / Nf(1)
  have hMsgNf : ∀ b, (b = 35 ∨ b = 70) →
      blkMsgRec T b = #[UInt32.ofNat TAG_NF,
        skReg b 0, skReg b 1, skReg b 2, skReg b 3, skReg b 4, skReg b 5, skReg b 6, skReg b 7,
        UInt32.ofNat (posReg b),
        rhoReg b 0, rhoReg b 1, rhoReg b 2, rhoReg b 3, rhoReg b 4, 0] := fun b hb => by
    have hsk : ∀ j : Fin 8, rawW T b (j.val + 1) = skReg b j := fun j => by
      have hl := raw_block_load_zero hT b (j.val + 1) (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : (T.cell (b * 64) (COL_W + (j.val + 1)) - T.cell (b * 64) (COL_SK + j.val)) % P = 0 := by
        rcases hb with rfl | rfl <;>
          simpa [msgLoadTerm, periodicVal, hd, hm, hidx, show j.val + 1 ≠ 0 from by omega,
                 show j.val + 1 ≤ 8 from by omega] using hl
      have hr1 := T.hRange (b * 64) (COL_W + (j.val + 1)) (by omega) (by simp [COL_W, W_COLS]; omega)
      have hr2 := T.hRange (b * 64) (COL_SK + j.val) (by omega) (by simp [COL_SK, W_COLS]; omega)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
      have hw := hInitW b (j.val + 1) (by omega) (by omega) (by omega) (by omega)
      have hlt : T.cell (b * 64) (COL_SK + j.val) < TWO32 := by
        rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b (j.val + 1))
      apply u32_eq_of_toNat_int; rw [← hw, hcell, u32_ofNat_toNat_int _ hr2.1 hlt]
    have hpos9 : rawW T b 9 = UInt32.ofNat (posReg b) := by
      have hl := raw_block_load_zero hT b 9 (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : (T.cell (b * 64) (COL_W + 9) - T.cell (b * 64) COL_POS) % P = 0 := by
        rcases hb with rfl | rfl <;> simpa [msgLoadTerm, periodicVal, hd, hm, hidx] using hl
      have hr1 := T.hRange (b * 64) (COL_W + 9) (by omega) (by decide)
      have hr2 := T.hRange (b * 64) COL_POS (by omega) (by decide)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
      have hw := hInitW b 9 (by omega) (by omega) (by omega) (by omega)
      have hlt : T.cell (b * 64) COL_POS < TWO32 := by
        rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b 9)
      apply u32_eq_of_toNat_int; rw [← hw, hcell, u32_ofNat_toNat_int _ hr2.1 hlt]
    have hrho : ∀ j : Fin 5, rawW T b (j.val + 10) = rhoReg b j := fun j => by
      have hl := raw_block_load_zero hT b (j.val + 10) (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : (T.cell (b * 64) (COL_W + (j.val + 10)) - T.cell (b * 64) (COL_RHO + j.val)) % P = 0 := by
        have hsub : COL_RHO + (j.val + 10) - 10 = COL_RHO + j.val := by omega
        rcases hb with rfl | rfl <;>
          simpa [msgLoadTerm, periodicVal, hd, hm, hidx, hsub, show j.val + 10 ≠ 0 from by omega,
                 show ¬(j.val + 10 ≤ 8) from by omega, show j.val + 10 ≠ 9 from by omega,
                 show j.val + 10 ≤ 14 from by omega] using hl
      have hr1 := T.hRange (b * 64) (COL_W + (j.val + 10)) (by omega) (by simp [COL_W, W_COLS]; omega)
      have hr2 := T.hRange (b * 64) (COL_RHO + j.val) (by omega) (by simp [COL_RHO, W_COLS]; omega)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 hr2.1 hr2.2 heq0
      have hw := hInitW b (j.val + 10) (by omega) (by omega) (by omega) (by omega)
      have hlt : T.cell (b * 64) (COL_RHO + j.val) < TWO32 := by
        rw [← hcell, hw]; exact u32_toNat_lt_two32 (rawW T b (j.val + 10))
      apply u32_eq_of_toNat_int; rw [← hw, hcell, u32_ofNat_toNat_int _ hr2.1 hlt]
    have hzero15 : rawW T b 15 = 0 := by
      have hl := raw_block_load_zero hT b 15 (by omega) (by omega) (by omega)
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have heq0 : T.cell (b * 64) (COL_W + 15) % P = 0 := by
        rcases hb with rfl | rfl <;> simpa [msgLoadTerm, periodicVal, hd, hm, hidx] using hl
      have hr1 := T.hRange (b * 64) (COL_W + 15) (by omega) (by decide)
      have hcell := field_eq_of_sub_mod_P hr1.1 hr1.2 (y := (0 : Int)) (by decide) (by decide) (by simpa using heq0)
      have hw := hInitW b 15 (by omega) (by omega) (by omega) (by omega)
      apply u32_eq_of_toNat_int; rw [← hw, hcell]; rfl
    have hbm : blkMsgRec T b = blockMsgOfW0 T b (UInt32.ofNat TAG_NF) := by
      rcases hb with rfl | rfl
      · rw [blkMsgRec_succ]; simp
      · rw [blkMsgRec_succ]; simp
    rw [hbm]
    simp only [blockMsgOfW0,
      hsk ⟨0, by decide⟩, hsk ⟨1, by decide⟩, hsk ⟨2, by decide⟩, hsk ⟨3, by decide⟩,
      hsk ⟨4, by decide⟩, hsk ⟨5, by decide⟩, hsk ⟨6, by decide⟩, hsk ⟨7, by decide⟩,
      hpos9,
      hrho ⟨0, by decide⟩, hrho ⟨1, by decide⟩, hrho ⟨2, by decide⟩, hrho ⟨3, by decide⟩, hrho ⟨4, by decide⟩,
      hzero15]
    rfl
  -- Prove hBalStep across blocks 1..72
  have hBalStep : ∀ b, 1 ≤ b → b ≤ 72 →
      (balReg (b + 1) - balReg b -
        (if b = 2 then noteValue (rawW T 2 9) (rawW T 2 10)
         else if b = 37 then noteValue (rawW T 37 9) (rawW T 37 10)
         else if b = 71 then -(noteValue (rawW T 71 9) (rawW T 71 10))
         else if b = 72 then -(noteValue (rawW T 72 9) (rawW T 72 10))
         else 0)) % P = 0 := fun b hb1 hb72 => by
    by_cases hb_eq1 : b = 1
    · subst hb_eq1
      have hin := raw_bal_const_in_block hT 1 (by omega) (by omega) 63 (by omega)
      simpa [balReg] using hin
    · -- b ≥ 2: balReg (b+1) = T(b*64 + 63), balReg b = T((b-1)*64 + 63)
      have hge2 : 2 ≤ b := by omega
      have h1 : ¬ (b + 1 ≤ 1) := by omega
      have h2 : ¬ (b ≤ 1) := by omega
      simp only [balReg, h1, h2, ↓reduceIte, Nat.add_sub_cancel]
      have hin := raw_bal_const_in_block hT b hb1 hb72 63 (by omega)
      have hz := rawCon_zero hT (r := (b - 1) * 64 + 63) (i := 247) (by omega) (by omega)
      rw [eval_fipsCon_247] at hz
      have hidx : (b - 1) * 64 + 63 + 1 = b * 64 := by omega
      have hd : ((b - 1) * 64 + 63) / 64 = b - 1 := by omega
      have hm : ((b - 1) * 64 + 63) % 64 = 63 := by omega
      have h64 : 64 ≤ (b - 1) * 64 + 63 := by omega
      have h4671 : (b - 1) * 64 + 63 < 4671 := by omega
      have hp11 : periodicVal ((b - 1) * 64 + 63) 11 = 1 := by simp [periodicVal, h64, h4671]
      have hw9 := hInitW b 9 hb1 hb72 (by omega) (by omega)
      have hw10 := hInitW b 10 hb1 hb72 (by omega) (by omega)
      rw [hidx, hp11, Int.one_mul, hw9, hw10] at hz
      -- Combine (T(b*64+63) - T(b*64)) + (T(b*64) - T((b-1)*64+63) - ...) ≡ 0 mod P
      rcases Int.dvd_of_emod_eq_zero hin with ⟨q1, hq1⟩
      rcases Int.dvd_of_emod_eq_zero hz with ⟨q2, hq2⟩
      have hnv : TWO32 * ((rawW T b 9).toNat : Int) + ((rawW T b 10).toNat : Int) = noteValue (rawW T b 9) (rawW T b 10) := rfl
      rw [hnv] at hq2
      by_cases hc2 : b = 2
      · subst hc2
        have hp4 : periodicVal (1 * 64 + 63) 4 = 1 := by decide
        have hp7 : periodicVal (1 * 64 + 63) 7 = 0 := by decide
        simp only [show 2 - 1 = 1 from rfl] at hq2
        rw [hp4, hp7, Int.one_mul, Int.zero_mul, Int.add_zero] at hq2
        have hcomb : T.cell (2 * 64 + 63) COL_BAL - T.cell (1 * 64 + 63) COL_BAL - noteValue (rawW T 2 9) (rawW T 2 10) = P * (q1 + q2) := by
          rw [Int.mul_add]; omega
        simp [hcomb]
      · by_cases hc37 : b = 37
        · subst hc37
          have hp4 : periodicVal (36 * 64 + 63) 4 = 1 := by decide
          have hp7 : periodicVal (36 * 64 + 63) 7 = 0 := by decide
          simp only [show 37 - 1 = 36 from rfl] at hq2
          rw [hp4, hp7, Int.one_mul, Int.zero_mul, Int.add_zero] at hq2
          have hcomb : T.cell (37 * 64 + 63) COL_BAL - T.cell (36 * 64 + 63) COL_BAL - noteValue (rawW T 37 9) (rawW T 37 10) = P * (q1 + q2) := by
            rw [Int.mul_add]; omega
          simp [hcomb]
        · by_cases hc71 : b = 71
          · subst hc71
            have hp4 : periodicVal (70 * 64 + 63) 4 = 0 := by decide
            have hp7 : periodicVal (70 * 64 + 63) 7 = 1 := by decide
            simp only [show 71 - 1 = 70 from rfl] at hq2
            rw [hp4, hp7, Int.zero_mul, Int.one_mul, Int.sub_zero] at hq2
            have hcomb : T.cell (71 * 64 + 63) COL_BAL - T.cell (70 * 64 + 63) COL_BAL - -noteValue (rawW T 71 9) (rawW T 71 10) = P * (q1 + q2) := by
              rw [Int.mul_add]; omega
            simp [hcomb]
          · by_cases hc72 : b = 72
            · subst hc72
              have hp4 : periodicVal (71 * 64 + 63) 4 = 0 := by decide
              have hp7 : periodicVal (71 * 64 + 63) 7 = 1 := by decide
              simp only [show 72 - 1 = 71 from rfl] at hq2
              rw [hp4, hp7, Int.zero_mul, Int.one_mul, Int.sub_zero] at hq2
              have hcomb : T.cell (72 * 64 + 63) COL_BAL - T.cell (71 * 64 + 63) COL_BAL - -noteValue (rawW T 72 9) (rawW T 72 10) = P * (q1 + q2) := by
                rw [Int.mul_add]; omega
              simp [hcomb]
            · have hp4 : periodicVal ((b - 1) * 64 + 63) 4 = 0 := by
                have hne1 : b - 1 ≠ 1 := by omega
                have hne36 : b - 1 ≠ 36 := by omega
                simp [periodicVal, hd, hm, hne1, hne36]
              have hp7 : periodicVal ((b - 1) * 64 + 63) 7 = 0 := by
                have hne70 : b - 1 ≠ 70 := by omega
                have hne71 : b - 1 ≠ 71 := by omega
                simp [periodicVal, hd, hm, hne70, hne71]
              rw [hp4, hp7, Int.zero_mul, Int.sub_zero, Int.add_zero] at hq2
              have hcomb : T.cell (b * 64 + 63) COL_BAL - T.cell ((b - 1) * 64 + 63) COL_BAL - 0 = P * (q1 + q2) := by
                rw [Int.mul_add]; omega
              simp [hc2, hc37, hc71, hc72, hcomb]
  -- Helper: match boundary-asserted COL_DIG to blkDigRec
  have hAssertDig : ∀ (b : Nat) (expected : Word8), 1 ≤ b → b ≤ 72 →
      (∀ j : Fin 8, T.cell (b * 64 + 63) (COL_DIG + j.val) = ((expected j).toNat : Int)) →
      blkDigRec T b = expected := fun b expected hb1 hb72 hcell => by
    funext j
    have hlt : T.cell (b * 64 + 63) (COL_DIG + j.val) < TWO32 := by
      rw [hcell j]; exact u32_toNat_lt_two32 (expected j)
    have hdeq := digest_cell_eq_of_lt hT b j.val hb1 hb72 j.isLt _ (hDig b hb1 hb72 j.val j.isLt) hlt
    apply u32_eq_of_toNat_int; rw [← hdeq, hcell j]
  exact ⟨{
    blkMsg  := blkMsgRec T
    blkDig  := blkDigRec T
    skReg   := skReg
    rhoReg  := rhoReg
    posReg  := posReg
    bitReg  := bitReg
    sibReg  := sibReg
    balReg  := balReg
    vHiIn0  := rawW T 2 9,   vLoIn0  := rawW T 2 10
    vHiIn1  := rawW T 37 9,  vLoIn1  := rawW T 37 10
    apkOut0 := fun j => rawW T 71 (j.val + 1)
    apkOut1 := fun j => rawW T 72 (j.val + 1)
    vHiOut0 := rawW T 71 9,  vLoOut0 := rawW T 71 10
    vHiOut1 := rawW T 72 9,  vLoOut1 := rawW T 72 10
    rhoOut0 := fun j => rawW T 71 (j.val + 11)
    rhoOut1 := fun j => rawW T 72 (j.val + 11)
    hCompress := fun _ _ _ => rfl
    hMsgAddr0 := hMsgAddr 1 (Or.inl rfl)
    hMsgCmIn0 := hMsgCmIn 2 (Or.inl rfl)
    hMsgMrk0  := fun k hk => by simpa [show 3 + k - 1 = 2 + k from by omega] using hMsgMrk (3 + k) (Or.inl ⟨by omega, by omega⟩)
    hMsgNf0   := hMsgNf 35 (Or.inl rfl)
    hMsgAddr1 := hMsgAddr 36 (Or.inr rfl)
    hMsgCmIn1 := hMsgCmIn 37 (Or.inr rfl)
    hMsgMrk1  := fun k hk => by simpa [show 38 + k - 1 = 37 + k from by omega] using hMsgMrk (38 + k) (Or.inr ⟨by omega, by omega⟩)
    hMsgNf1   := hMsgNf 70 (Or.inr rfl)
    hMsgOut0  := by
      rw [blkMsgRec_succ]
      simp only [show ¬(71 = 1 ∨ 71 = 36) from by decide, ↓reduceIte, blockMsgOfW0]
      rfl
    hMsgOut1  := by
      rw [blkMsgRec_succ]
      simp only [show ¬(72 = 1 ∨ 72 = 36) from by decide, ↓reduceIte, blockMsgOfW0]
      rfl
    hBitBool  := hBitBool
    hSkConst0 := hSkConst0
    hSkConst1 := hSkConst1
    hRhoCst0  := hRhoCst0
    hRhoCst1  := hRhoCst1
    hPos0Init := by simp [posReg, hPos0InitInt]
    hPos0Step := fun k hk => hPosC0.2 k hk
    hPos0Hold := hPos0Hold
    hPos1Init := by simp [posReg, hPos1InitInt]
    hPos1Step := fun k hk => hPosC1.2 k hk
    hPos1Hold := hPos1Hold
    hVHiIn0   := raw_vhi_lt_2p28 hT 2 (Or.inl rfl)
    hVHiIn1   := raw_vhi_lt_2p28 hT 37 (Or.inr (Or.inl rfl))
    hVHiOut0  := raw_vhi_lt_2p28 hT 71 (Or.inr (Or.inr (Or.inl rfl)))
    hVHiOut1  := raw_vhi_lt_2p28 hT 72 (Or.inr (Or.inr (Or.inr rfl)))
    hBalStep  := hBalStep
    hAssertBal0   := by simp [balReg, hB.hBal0]
    hAssertBalEnd := by simp [balReg, hB.hBalEnd]
    hAssertDummy0 := fun hd => by
      rcases hB.hDummy0 hd with ⟨h9, h10⟩
      have hw9 := hInitW 2 9 (by omega) (by omega) (by omega) (by omega)
      have hw10 := hInitW 2 10 (by omega) (by omega) (by omega) (by omega)
      exact ⟨u32_eq_of_toNat_int (by rw [← hw9, h9]; rfl), u32_eq_of_toNat_int (by rw [← hw10, h10]; rfl)⟩
    hAssertDummy1 := fun hd => by
      rcases hB.hDummy1 hd with ⟨h9, h10⟩
      have hw9 := hInitW 37 9 (by omega) (by omega) (by omega) (by omega)
      have hw10 := hInitW 37 10 (by omega) (by omega) (by omega) (by omega)
      exact ⟨u32_eq_of_toNat_int (by rw [← hw9, h9]; rfl), u32_eq_of_toNat_int (by rw [← hw10, h10]; rfl)⟩
    hAssertRoot0 := fun hd => hAssertDig 34 pi.root (by omega) (by omega) (hB.hRoot0 hd)
    hAssertRoot1 := fun hd => hAssertDig 69 pi.root (by omega) (by omega) (hB.hRoot1 hd)
    hAssertNf0   := hAssertDig 35 pi.nf0 (by omega) (by omega) hB.hNf0
    hAssertNf1   := hAssertDig 70 pi.nf1 (by omega) (by omega) hB.hNf1
    hAssertOut0  := hAssertDig 71 pi.cmOut0 (by omega) (by omega) hB.hOut0
    hAssertOut1  := hAssertDig 72 pi.cmOut1 (by omega) (by omega) hB.hOut1
  }⟩

/-- END-TO-END RAW RUST AIR SOUNDNESS THEOREM:
    ANY raw `8,192 × 247` Goldilocks field trace satisfying ALL 249 live Rust extracted transition
    constraints (`rustCon 0..248`) and ALL boundary assertions (`spend::assertion_cells(&pi)`)
    witnesses a complete semantic `ValidSpendWitness pi` (ownership, commitment binding, 32-level
    Merkle membership, deterministic nullifiers, `< 2^60` note ranges, dummy zeroing, and exact
    integer value conservation). Pure Lean 4 kernel, zero `sorry`, zero `native_decide`, zero Mathlib. -/
theorem raw_rust_air_soundness
    (pi : SpendPublicStmt) (T : RawFieldTrace)
    (hT : RawAirTransitionsHold T) (hB : RawBoundaryAssertions pi T) :
    Nonempty (ValidSpendWitness pi) := by
  rcases raw_air_trace_implies_accepted_spend_trace pi T hT hB with ⟨tr⟩
  exact accepted_spend_trace_implies_spend_relation pi tr

-- ============================================================================
-- SECTION 9: COMPLETENESS, BIDIRECTIONAL EQUIVALENCE & CONCRETE NON-VACUITY
-- ============================================================================

-- ---- Part 9A: 79-word extended SHA-256 schedule matching `hash::schedule` ----

/-- Extended 79-word SHA-256 schedule (`hash::schedule(m)` in `node/src/hash.rs`).
    Words `0..63` agree identically with `sha256Schedule`; words `64..78` continue
    the same recurrence so Constraint #85 holds on all inner rows `t = 0..62`. -/
def sha256Schedule79 (blk : Array UInt32) : Array UInt32 :=
  sha256ScheduleStep blk 63

theorem sha256ScheduleStep_add (w : Array UInt32) (m n : Nat) :
    sha256ScheduleStep w (m + n) = sha256ScheduleStep (sha256ScheduleStep w m) n := by
  induction m generalizing w with
  | zero => simp [sha256ScheduleStep]
  | succ k ih =>
    have h : k + 1 + n = (k + n) + 1 := by omega
    rw [h]
    simp only [sha256ScheduleStep]
    exact ih _

theorem sha256Schedule79_prefix64 (blk : Array UInt32) (hsz : blk.size = 16) (k : Nat) (hk : k < 64) :
    (sha256Schedule79 blk)[k]! = (sha256Schedule blk)[k]! := by
  unfold sha256Schedule79 sha256Schedule
  have h63 : (63 : Nat) = 48 + 15 := rfl
  rw [h63, sha256ScheduleStep_add]
  have hsz48 : (sha256ScheduleStep blk 48).size = 64 := by
    rw [sha256ScheduleStep_size, hsz]
  exact sha256ScheduleStep_prefix (sha256ScheduleStep blk 48) 15 k (by omega)

theorem sha256Schedule79_init (blk : Array UInt32) (hsz : blk.size = 16) (k : Nat) (hk : k < 16) :
    (sha256Schedule79 blk)[k]! = blk[k]! :=
  sha256ScheduleStep_prefix blk 63 k (by omega)

theorem sha256Schedule79_step (blk : Array UInt32) (hsz : blk.size = 16) (t : Nat) (ht : t < 63) :
    (sha256Schedule79 blk)[t + 16]! =
      smallS1 (sha256Schedule79 blk)[t + 14]! + (sha256Schedule79 blk)[t + 9]! +
      smallS0 (sha256Schedule79 blk)[t + 1]! + (sha256Schedule79 blk)[t]! := by
  have h := sha256ScheduleStep_step blk 63 (by omega) t ht
  simp only [sha256Schedule79]
  have h1 : blk.size + t = t + 16 := by omega
  have h2 : blk.size + t - 2 = t + 14 := by omega
  have h3 : blk.size + t - 7 = t + 9 := by omega
  have h4 : blk.size + t - 15 = t + 1 := by omega
  have h5 : blk.size + t - 16 = t := by omega
  simpa [h1, h2, h3, h4, h5] using h

theorem sha256RunRounds_congr (w1 w2 : Array UInt32) (n : Nat) (st : ShaState)
    (heq : ∀ k, k < n → w1[k]! = w2[k]!) :
    sha256RunRounds w1 n st = sha256RunRounds w2 n st := by
  induction n with
  | zero => rfl
  | succ m ih =>
    simp only [sha256RunRounds]
    rw [ih (fun k hk => heq k (by omega)), heq m (by omega)]

-- ---- Part 9B: Carry, signed-field, posAcc & value-range arithmetic helpers ----

theorem bit_3_reconstruct : ∀ q, q < 8 →
    (((q >>> 0) &&& 1 : Nat) : Int) + (2 : Int) * (((q >>> 1) &&& 1 : Nat) : Int) +
    (4 : Int) * (((q >>> 2) &&& 1 : Nat) : Int) = (q : Int) := by decide

theorem bit_2_reconstruct : ∀ q, q < 4 →
    (((q >>> 0) &&& 1 : Nat) : Int) + (2 : Int) * (((q >>> 1) &&& 1 : Nat) : Int) = (q : Int) := by decide

theorem nat_bit_is_0_or_1 (x j : Nat) :
    ((((x >>> j) &&& 1 : Nat) : Int) = 0) ∨ ((((x >>> j) &&& 1 : Nat) : Int) = 1) := by
  have h : ((x >>> j) &&& 1) = (x >>> j) % 2 := Nat.and_one_is_mod (x >>> j)
  rw [h]
  have hlt : (x >>> j) % 2 < 2 := Nat.mod_lt _ (by decide)
  omega

theorem u32Bit_is_bool (x : UInt32) (j : Nat) : u32Bit x j = 0 ∨ u32Bit x j = 1 := by
  unfold u32Bit; split <;> simp

theorem packBits_congr (f g : Nat → Int) (n : Nat) (h : ∀ j, j < n → f j = g j) :
    packBits f n = packBits g n := by
  induction n with
  | zero => rfl
  | succ m ih =>
    simp only [packBits, ih (fun j hj => h j (by omega)), h m (by omega)]

theorem int_div_mod_P (a : Int) : a % P + P * (a / P) = a := by
  simp only [P]; omega

theorem int_div_mod_two32 (a : Int) : a % TWO32 + TWO32 * (a / TWO32) = a := by
  simp only [TWO32]; omega

theorem signedField_bounds (x : Int) : 0 ≤ signedField x ∧ signedField x < P := by
  unfold signedField
  have hP : 0 < P := by decide
  by_cases hx : x ≥ 0
  · simp only [hx, ↓reduceIte]
    exact ⟨Int.emod_nonneg x (by omega), Int.emod_lt_of_pos x hP⟩
  · simp only [hx, ↓reduceIte]
    exact ⟨Int.emod_nonneg _ (by omega), Int.emod_lt_of_pos _ hP⟩

theorem signedField_emod_P (x : Int) : signedField x % P = x % P := by
  unfold signedField
  have hP : 0 < P := by decide
  by_cases hx : x ≥ 0
  · simp only [hx, ↓reduceIte, Int.emod_emod]
  · simp only [hx, ↓reduceIte, Int.emod_emod]
    have hdiv := int_div_mod_P (-x)
    have hrm0 := Int.emod_nonneg (-x) (by omega : P ≠ 0)
    have hrmP := Int.emod_lt_of_pos (-x) hP
    by_cases hr0 : (-x) % P = 0
    · rw [hr0, Int.sub_zero, Int.emod_self]
      have hxmul : x = P * (-((-x) / P)) := by rw [Int.mul_neg]; omega
      rw [hxmul, Int.mul_emod_right]
    · have h1 : (P - (-x) % P) % P = P - (-x) % P := Int.emod_eq_of_lt (by omega) (by omega)
      rw [h1]
      have hxrew : x = P * (-((-x) / P) - 1) + (P - (-x) % P) := by
        rw [Int.mul_sub, Int.mul_neg, Int.mul_one]; omega
      conv => rhs; rw [hxrew]
      rw [Int.add_emod, Int.mul_emod_right, Int.zero_add, Int.emod_emod, h1]

theorem posAcc_lt_pow (bits : Nat → Nat) (hb : ∀ k, k < 32 → bits k = 0 ∨ bits k = 1) :
    ∀ k, k ≤ 32 → posAcc bits k < 2 ^ k := by
  intro k
  induction k with
  | zero => intro _; simp [posAcc]
  | succ m ih =>
    intro hm
    simp only [posAcc]
    have hprev := ih (by omega)
    have hbm := hb m (by omega)
    have hpow : 2 ^ (m + 1) = 2 ^ m + 2 ^ m := by rw [Nat.pow_succ]; omega
    rcases hbm with h | h <;> rw [h] <;> omega

theorem u32Bit_high_zero_of_lt_2p28 (x : UInt32) (hx : (x.toNat : Int) < 2 ^ 28)
    (j : Nat) (hj28 : 28 ≤ j) (_hj32 : j < 32) :
    u32Bit x j = 0 := by
  have hnat : x.toNat < 2 ^ 28 := by omega
  have hpow : 2 ^ 28 ≤ 2 ^ j := Nat.pow_le_pow_right (by decide) hj28
  have hdiv : x.toNat / 2 ^ j = 0 := Nat.div_eq_of_lt (by omega)
  simp [u32Bit, hdiv]

theorem vhi_lt_2p28_of_range (vHi vLo : UInt32) (hr : noteValue vHi vLo < MAX_NOTE_BOUND) :
    (vHi.toNat : Int) < 2 ^ 28 := by
  simp only [noteValue, TWO32, MAX_NOTE_BOUND] at hr
  omega

theorem u32Bit_iv_eq (k j : Nat) (hk : k < 8) :
    u32Bit (IV[k]!) j = ((((ivNat k) >>> j) &&& 1 : Nat) : Int) := by
  have h := iv_toNat_eq_ivNat k hk
  have hsh : ((ivNat k >>> j) &&& 1) = ivNat k / 2 ^ j % 2 := by
    rw [Nat.shiftRight_eq_div_pow, Nat.and_one_is_mod]
  rw [hsh]; unfold u32Bit; rw [h]
  have hlt : ivNat k / 2 ^ j % 2 < 2 := Nat.mod_lt _ (by decide)
  split <;> omega

theorem round0_sa_exact (w0 : UInt32) :
    ((sha256Init.h.toNat : Int) + ((bigS1 sha256Init.e).toNat : Int) +
      ((ch32 sha256Init.e sha256Init.f sha256Init.g).toNat : Int) +
      ((K[0]!).toNat : Int) + (w0.toNat : Int) +
      ((bigS0 sha256Init.a).toNat : Int) +
      ((maj32 sha256Init.a sha256Init.b sha256Init.c).toNat : Int)) =
    (k0aConst : Int) + (w0.toNat : Int) := by
  have hc : ((sha256Init.h.toNat : Int) + ((bigS1 sha256Init.e).toNat : Int) +
      ((ch32 sha256Init.e sha256Init.f sha256Init.g).toNat : Int) +
      ((K[0]!).toNat : Int) + ((bigS0 sha256Init.a).toNat : Int) +
      ((maj32 sha256Init.a sha256Init.b sha256Init.c).toNat : Int)) = (k0aConst : Int) := by decide
  omega

theorem round0_se_exact (w0 : UInt32) :
    ((sha256Init.d.toNat : Int) +
      ((sha256Init.h.toNat : Int) + ((bigS1 sha256Init.e).toNat : Int) +
       ((ch32 sha256Init.e sha256Init.f sha256Init.g).toNat : Int) +
       ((K[0]!).toNat : Int) + (w0.toNat : Int))) =
    (k0eConst : Int) + (w0.toNat : Int) := by
  have hc : ((sha256Init.d.toNat : Int) + (sha256Init.h.toNat : Int) +
      ((bigS1 sha256Init.e).toNat : Int) +
      ((ch32 sha256Init.e sha256Init.f sha256Init.g).toNat : Int) +
      ((K[0]!).toNat : Int)) = (k0eConst : Int) := by decide
  omega

-- ---- Part 9C: Canonical `8,192 × 247` Goldilocks trace construction (`spend::build_trace`) ----

def witSk {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) : Word8 :=
  if b ≤ 35 then w.sk0 else w.sk1

def witRho {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) : Rho5 :=
  if b ≤ 1 then (fun _ => 0) else if b ≤ 36 then w.rho0 else w.rho1

def witBit {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) : Nat :=
  if 3 ≤ b ∧ b ≤ 34 then w.bits0 (b - 3)
  else if 38 ≤ b ∧ b ≤ 69 then w.bits1 (b - 38)
  else 0

def witPos {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) : Nat :=
  if b ≤ 2 then 0
  else if b ≤ 35 then posAcc w.bits0 (min (b - 2) 32)
  else if b ≤ 37 then 0
  else posAcc w.bits1 (min (b - 37) 32)

def witBalInt {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) : Int :=
  if b ≤ 1 then 0
  else if b ≤ 36 then noteValue w.vHiIn0 w.vLoIn0
  else if b ≤ 70 then noteValue w.vHiIn0 w.vLoIn0 + noteValue w.vHiIn1 w.vLoIn1
  else if b = 71 then noteValue w.vHiIn0 w.vLoIn0 + noteValue w.vHiIn1 w.vLoIn1 - noteValue w.vHiOut0 w.vLoOut0
  else noteValue w.vHiIn0 w.vLoIn0 + noteValue w.vHiIn1 w.vLoIn1 - noteValue w.vHiOut0 w.vLoOut0 - noteValue w.vHiOut1 w.vLoOut1

def witBlockMsg {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) : Array UInt32 :=
  if b = 1 then
    #[UInt32.ofNat TAG_ADDR,
      w.sk0 0, w.sk0 1, w.sk0 2, w.sk0 3, w.sk0 4, w.sk0 5, w.sk0 6, w.sk0 7,
      0, 0, 0, 0, 0, 0, 0]
  else if b = 2 then
    #[UInt32.ofNat TAG_CM,
      w.apk0 0, w.apk0 1, w.apk0 2, w.apk0 3, w.apk0 4, w.apk0 5, w.apk0 6, w.apk0 7,
      w.vHiIn0, w.vLoIn0, w.rho0 0, w.rho0 1, w.rho0 2, w.rho0 3, w.rho0 4]
  else if 3 ≤ b ∧ b ≤ 34 then
    merkleMsg (merkleRoot w.cmIn0 w.bits0 w.sibs0 (b - 3)) (w.sibs0 (b - 3)) (w.bits0 (b - 3))
  else if b = 35 then
    #[UInt32.ofNat TAG_NF,
      w.sk0 0, w.sk0 1, w.sk0 2, w.sk0 3, w.sk0 4, w.sk0 5, w.sk0 6, w.sk0 7,
      w.pos0, w.rho0 0, w.rho0 1, w.rho0 2, w.rho0 3, w.rho0 4, 0]
  else if b = 36 then
    #[UInt32.ofNat TAG_ADDR,
      w.sk1 0, w.sk1 1, w.sk1 2, w.sk1 3, w.sk1 4, w.sk1 5, w.sk1 6, w.sk1 7,
      0, 0, 0, 0, 0, 0, 0]
  else if b = 37 then
    #[UInt32.ofNat TAG_CM,
      w.apk1 0, w.apk1 1, w.apk1 2, w.apk1 3, w.apk1 4, w.apk1 5, w.apk1 6, w.apk1 7,
      w.vHiIn1, w.vLoIn1, w.rho1 0, w.rho1 1, w.rho1 2, w.rho1 3, w.rho1 4]
  else if 38 ≤ b ∧ b ≤ 69 then
    merkleMsg (merkleRoot w.cmIn1 w.bits1 w.sibs1 (b - 38)) (w.sibs1 (b - 38)) (w.bits1 (b - 38))
  else if b = 70 then
    #[UInt32.ofNat TAG_NF,
      w.sk1 0, w.sk1 1, w.sk1 2, w.sk1 3, w.sk1 4, w.sk1 5, w.sk1 6, w.sk1 7,
      w.pos1, w.rho1 0, w.rho1 1, w.rho1 2, w.rho1 3, w.rho1 4, 0]
  else if b = 71 then
    #[UInt32.ofNat TAG_CM,
      w.apkOut0 0, w.apkOut0 1, w.apkOut0 2, w.apkOut0 3, w.apkOut0 4, w.apkOut0 5, w.apkOut0 6, w.apkOut0 7,
      w.vHiOut0, w.vLoOut0, w.rhoOut0 0, w.rhoOut0 1, w.rhoOut0 2, w.rhoOut0 3, w.rhoOut0 4]
  else if b = 72 then
    #[UInt32.ofNat TAG_CM,
      w.apkOut1 0, w.apkOut1 1, w.apkOut1 2, w.apkOut1 3, w.apkOut1 4, w.apkOut1 5, w.apkOut1 6, w.apkOut1 7,
      w.vHiOut1, w.vLoOut1, w.rhoOut1 0, w.rhoOut1 1, w.rhoOut1 2, w.rhoOut1 3, w.rhoOut1 4]
  else
    Array.replicate 16 0

theorem witBlockMsg_size {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) :
    (witBlockMsg w b).size = 16 := by
  unfold witBlockMsg
  by_cases h1 : b = 1; · simp [h1]
  simp only [h1, ↓reduceIte]
  by_cases h2 : b = 2; · simp [h2]
  simp only [h2, ↓reduceIte]
  by_cases h3 : 3 ≤ b ∧ b ≤ 34; · simp only [h3, and_self, ↓reduceIte, merkleMsg]; split <;> rfl
  simp only [h3, ↓reduceIte]
  by_cases h4 : b = 35; · simp [h4]
  simp only [h4, ↓reduceIte]
  by_cases h5 : b = 36; · simp [h5]
  simp only [h5, ↓reduceIte]
  by_cases h6 : b = 37; · simp [h6]
  simp only [h6, ↓reduceIte]
  by_cases h7 : 38 ≤ b ∧ b ≤ 69; · simp only [h7, and_self, ↓reduceIte, merkleMsg]; split <;> rfl
  simp only [h7, ↓reduceIte]
  by_cases h8 : b = 70; · simp [h8]
  simp only [h8, ↓reduceIte]
  by_cases h9 : b = 71; · simp [h9]
  simp only [h9, ↓reduceIte]
  by_cases h10 : b = 72; · simp [h10]
  simp only [h10, ↓reduceIte]; exact Array.size_replicate

/-- Round-`t` sums `s_a`, `s_e`, `s_w` matching `spend::fill_block` (`spend.rs:699-715`). -/
def blkSa (blk : Array UInt32) (t : Nat) : Int :=
  let w := sha256Schedule79 blk
  let st := sha256RunRounds w t sha256Init
  let t1 : Int := (st.h.toNat : Int) + ((bigS1 st.e).toNat : Int) +
    ((ch32 st.e st.f st.g).toNat : Int) + ((K[t]!).toNat : Int) + ((w[t]!).toNat : Int)
  t1 + ((bigS0 st.a).toNat : Int) + ((maj32 st.a st.b st.c).toNat : Int)

def blkSe (blk : Array UInt32) (t : Nat) : Int :=
  let w := sha256Schedule79 blk
  let st := sha256RunRounds w t sha256Init
  let t1 : Int := (st.h.toNat : Int) + ((bigS1 st.e).toNat : Int) +
    ((ch32 st.e st.f st.g).toNat : Int) + ((K[t]!).toNat : Int) + ((w[t]!).toNat : Int)
  (st.d.toNat : Int) + t1

def blkSw (blk : Array UInt32) (t : Nat) : Int :=
  let w := sha256Schedule79 blk
  ((smallS1 w[t + 14]!).toNat : Int) + ((w[t + 9]!).toNat : Int) +
    ((smallS0 w[t + 1]!).toNat : Int) + ((w[t]!).toNat : Int)

def blkDigOut (blk : Array UInt32) (j : Nat) : Int :=
  let w := sha256Schedule79 blk
  let st := sha256RunRounds w 63 sha256Init
  match j with
  | 0 => blkSa blk 63 % TWO32
  | 1 => (st.a.toNat : Int)
  | 2 => (st.b.toNat : Int)
  | 3 => (st.c.toNat : Int)
  | 4 => blkSe blk 63 % TWO32
  | 5 => (st.e.toNat : Int)
  | 6 => (st.f.toNat : Int)
  | _ => (st.g.toNat : Int)

theorem blkSa_bounds (blk : Array UInt32) (t : Nat) :
    0 ≤ blkSa blk t ∧ blkSa blk t < 7 * TWO32 := by
  unfold blkSa; dsimp only
  have h1 := u32_toNat_lt_two32 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).h
  have h2 := u32_toNat_lt_two32 (bigS1 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).e)
  have h3 := u32_toNat_lt_two32 (ch32 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).e
    (sha256RunRounds (sha256Schedule79 blk) t sha256Init).f (sha256RunRounds (sha256Schedule79 blk) t sha256Init).g)
  have h4 := u32_toNat_lt_two32 (K[t]!)
  have h5 := u32_toNat_lt_two32 ((sha256Schedule79 blk)[t]!)
  have h6 := u32_toNat_lt_two32 (bigS0 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).a)
  have h7 := u32_toNat_lt_two32 (maj32 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).a
    (sha256RunRounds (sha256Schedule79 blk) t sha256Init).b (sha256RunRounds (sha256Schedule79 blk) t sha256Init).c)
  omega

theorem blkSe_bounds (blk : Array UInt32) (t : Nat) :
    0 ≤ blkSe blk t ∧ blkSe blk t < 6 * TWO32 := by
  unfold blkSe; dsimp only
  have h0 := u32_toNat_lt_two32 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).d
  have h1 := u32_toNat_lt_two32 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).h
  have h2 := u32_toNat_lt_two32 (bigS1 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).e)
  have h3 := u32_toNat_lt_two32 (ch32 (sha256RunRounds (sha256Schedule79 blk) t sha256Init).e
    (sha256RunRounds (sha256Schedule79 blk) t sha256Init).f (sha256RunRounds (sha256Schedule79 blk) t sha256Init).g)
  have h4 := u32_toNat_lt_two32 (K[t]!)
  have h5 := u32_toNat_lt_two32 ((sha256Schedule79 blk)[t]!)
  omega

theorem blkSw_bounds (blk : Array UInt32) (t : Nat) :
    0 ≤ blkSw blk t ∧ blkSw blk t < 4 * TWO32 := by
  unfold blkSw; dsimp only
  have h1 := u32_toNat_lt_two32 (smallS1 (sha256Schedule79 blk)[t + 14]!)
  have h2 := u32_toNat_lt_two32 ((sha256Schedule79 blk)[t + 9]!)
  have h3 := u32_toNat_lt_two32 (smallS0 (sha256Schedule79 blk)[t + 1]!)
  have h4 := u32_toNat_lt_two32 ((sha256Schedule79 blk)[t]!)
  omega

theorem blkDigOut_bounds (blk : Array UInt32) (j : Nat) :
    0 ≤ blkDigOut blk j ∧ blkDigOut blk j < TWO32 := by
  unfold blkDigOut
  have hT : (0 : Int) < TWO32 := by decide
  match j with
  | 0 => exact ⟨Int.emod_nonneg _ (by omega), Int.emod_lt_of_pos _ hT⟩
  | 1 => exact ⟨Int.natCast_nonneg _, u32_toNat_lt_two32 _⟩
  | 2 => exact ⟨Int.natCast_nonneg _, u32_toNat_lt_two32 _⟩
  | 3 => exact ⟨Int.natCast_nonneg _, u32_toNat_lt_two32 _⟩
  | 4 => exact ⟨Int.emod_nonneg _ (by omega), Int.emod_lt_of_pos _ hT⟩
  | 5 => exact ⟨Int.natCast_nonneg _, u32_toNat_lt_two32 _⟩
  | 6 => exact ⟨Int.natCast_nonneg _, u32_toNat_lt_two32 _⟩
  | _ + 7 => exact ⟨Int.natCast_nonneg _, u32_toNat_lt_two32 _⟩

theorem blkSa_mod_eq_next_a (blk : Array UInt32) (t : Nat) :
    blkSa blk t % TWO32 = ((sha256RunRounds (sha256Schedule79 blk) (t + 1) sha256Init).a.toNat : Int) := by
  have hstep : (sha256RunRounds (sha256Schedule79 blk) (t + 1) sha256Init).a =
      (sha256Round (sha256RunRounds (sha256Schedule79 blk) t sha256Init) K[t]! (sha256Schedule79 blk)[t]!).a := rfl
  rw [hstep]
  unfold sha256Round blkSa
  dsimp only
  simp only [u32_add_toNat_int, mod_add_l, mod_add_r]
  exact congrArg (· % TWO32) (by omega)

theorem blkSe_mod_eq_next_e (blk : Array UInt32) (t : Nat) :
    blkSe blk t % TWO32 = ((sha256RunRounds (sha256Schedule79 blk) (t + 1) sha256Init).e.toNat : Int) := by
  have hstep : (sha256RunRounds (sha256Schedule79 blk) (t + 1) sha256Init).e =
      (sha256Round (sha256RunRounds (sha256Schedule79 blk) t sha256Init) K[t]! (sha256Schedule79 blk)[t]!).e := rfl
  rw [hstep]
  unfold sha256Round blkSe
  dsimp only
  simp only [u32_add_toNat_int, mod_add_l, mod_add_r]

theorem blkSw_mod_eq_w16 (blk : Array UInt32) (hsz : blk.size = 16) (t : Nat) (ht : t < 63) :
    blkSw blk t % TWO32 = (((sha256Schedule79 blk)[t + 16]!).toNat : Int) := by
  rw [sha256Schedule79_step blk hsz t ht]
  unfold blkSw
  simp only [u32_add_toNat_int, mod_add_l]

theorem blkDig_eq_compress (blk : Array UInt32) (hsz : blk.size = 16) (j : Nat) (hj : j < 8) :
    ((ivNat j : Int) + blkDigOut blk j) % TWO32 = (((sha256Compress blk)[j]!).toNat : Int) := by
  have hst64 : sha256RunRounds (sha256Schedule79 blk) 64 sha256Init =
      sha256RunRounds (sha256Schedule blk) 64 sha256Init :=
    sha256RunRounds_congr _ _ 64 sha256Init (fun k hk => sha256Schedule79_prefix64 blk hsz k hk)
  have h64_step : sha256RunRounds (sha256Schedule79 blk) 64 sha256Init =
      sha256Round (sha256RunRounds (sha256Schedule79 blk) 63 sha256Init) K[63]! (sha256Schedule79 blk)[63]! := rfl
  rcases sha256Compress_get blk with ⟨hc0, hc1, hc2, hc3, hc4, hc5, hc6, hc7⟩
  have hiv := iv_toNat_eq_ivNat j hj
  have : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · rw [hc0, ← hst64, blkDigOut, blkSa_mod_eq_next_a blk 63, u32_add_toNat_int, hiv]
  · rw [hc1, ← hst64, h64_step]; unfold sha256Round; dsimp only; simp only [blkDigOut]; rw [u32_add_toNat_int, hiv]
  · rw [hc2, ← hst64, h64_step]; unfold sha256Round; dsimp only; simp only [blkDigOut]; rw [u32_add_toNat_int, hiv]
  · rw [hc3, ← hst64, h64_step]; unfold sha256Round; dsimp only; simp only [blkDigOut]; rw [u32_add_toNat_int, hiv]
  · rw [hc4, ← hst64, blkDigOut, blkSe_mod_eq_next_e blk 63, u32_add_toNat_int, hiv]
  · rw [hc5, ← hst64, h64_step]; unfold sha256Round; dsimp only; simp only [blkDigOut]; rw [u32_add_toNat_int, hiv]
  · rw [hc6, ← hst64, h64_step]; unfold sha256Round; dsimp only; simp only [blkDigOut]; rw [u32_add_toNat_int, hiv]
  · rw [hc7, ← hst64, h64_step]; unfold sha256Round; dsimp only; simp only [blkDigOut]; rw [u32_add_toNat_int, hiv]

/-- Exact column-value function for an active block row `r = b * 64 + t` (`1 ≤ b ≤ 72`, `t < 64`). -/
def canonBlockCell (blk : Array UInt32) (t c : Nat) : Int :=
  let w := sha256Schedule79 blk
  let st := sha256RunRounds w t sha256Init
  if c < COL_AP then u32Bit st.a (c - COL_A)
  else if c < COL_E then u32Bit st.b (c - COL_AP)
  else if c < COL_EP then u32Bit st.e (c - COL_E)
  else if c < COL_CWORD then u32Bit st.f (c - COL_EP)
  else if c = COL_CWORD then (st.c.toNat : Int)
  else if c = COL_GWORD then (st.g.toNat : Int)
  else if c = COL_AN then blkSa blk t % TWO32
  else if c = COL_EN then blkSe blk t % TWO32
  else if c < COL_CE then ((((blkSa blk t / TWO32).toNat >>> (c - COL_CA)) &&& 1 : Nat) : Int)
  else if c < COL_W then ((((blkSe blk t / TWO32).toNat >>> (c - COL_CE)) &&& 1 : Nat) : Int)
  else if c < COL_X1 then ((w[t + (c - COL_W)]!).toNat : Int)
  else if c < COL_X14 then
    if t < 63 then u32Bit w[t + 1]! (c - COL_X1)
    else if c - COL_X1 < 8 then ((ivNat (c - COL_X1) : Int) + blkDigOut blk (c - COL_X1)) / TWO32
    else 0
  else if c < COL_CWC then
    if t < 63 then u32Bit w[t + 14]! (c - COL_X14) else 0
  else if c < COL_DIG then
    if t < 63 then ((((blkSw blk t / TWO32).toNat >>> (c - COL_CWC)) &&& 1 : Nat) : Int) else 0
  else
    if t = 63 then ((ivNat (c - COL_DIG) : Int) + blkDigOut blk (c - COL_DIG)) % TWO32 else 0

/-- Exact cell function for the canonical `8,192 × 247` Goldilocks trace of a `ValidSpendWitness`. -/
def canonicalCell {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (r c : Nat) : Int :=
  let b := r / 64
  let t := r % 64
  if 1 ≤ b ∧ b ≤ 72 then
    if h0 : c < COL_SK then canonBlockCell (witBlockMsg w b) t c
    else if h1 : c < COL_RHO then ((witSk w b ⟨c - COL_SK, by simp only [COL_SK, COL_RHO] at *; omega⟩).toNat : Int)
    else if h2 : c < COL_BIT then ((witRho w b ⟨c - COL_RHO, by simp only [COL_RHO, COL_BIT] at *; omega⟩).toNat : Int)
    else if c = COL_BIT then if t = 0 then (witBit w b : Int) else 0
    else if c = COL_POS then (witPos w b : Int)
    else if c = COL_BAL then signedField (witBalInt w b)
    else 0
  else 0

theorem canonBlockCell_bounds (blk : Array UInt32) (t c : Nat) :
    0 ≤ canonBlockCell blk t c ∧ canonBlockCell blk t c < P := by
  have hT : (0 : Int) < TWO32 := by decide
  have hTP : TWO32 < P := by decide
  have hbool : ∀ v : Int, (v = 0 ∨ v = 1) → 0 ≤ v ∧ v < P := fun v hv => by
    rcases hv with rfl | rfl <;> decide
  unfold canonBlockCell; dsimp only
  by_cases h1 : c < COL_AP; · simp only [h1, ↓reduceIte]; exact hbool _ (u32Bit_is_bool _ _)
  simp only [h1, ↓reduceIte]
  by_cases h2 : c < COL_E; · simp only [h2, ↓reduceIte]; exact hbool _ (u32Bit_is_bool _ _)
  simp only [h2, ↓reduceIte]
  by_cases h3 : c < COL_EP; · simp only [h3, ↓reduceIte]; exact hbool _ (u32Bit_is_bool _ _)
  simp only [h3, ↓reduceIte]
  by_cases h4 : c < COL_CWORD; · simp only [h4, ↓reduceIte]; exact hbool _ (u32Bit_is_bool _ _)
  simp only [h4, ↓reduceIte]
  by_cases h5 : c = COL_CWORD; · simp only [h5, ↓reduceIte]; exact ⟨Int.natCast_nonneg _, u32_toNat_lt_P _⟩
  simp only [h5, ↓reduceIte]
  by_cases h6 : c = COL_GWORD; · simp only [h6, ↓reduceIte]; exact ⟨Int.natCast_nonneg _, u32_toNat_lt_P _⟩
  simp only [h6, ↓reduceIte]
  by_cases h7 : c = COL_AN; · simp only [h7, ↓reduceIte]; exact ⟨Int.emod_nonneg _ (by omega), by have := Int.emod_lt_of_pos (blkSa blk t) hT; omega⟩
  simp only [h7, ↓reduceIte]
  by_cases h8 : c = COL_EN; · simp only [h8, ↓reduceIte]; exact ⟨Int.emod_nonneg _ (by omega), by have := Int.emod_lt_of_pos (blkSe blk t) hT; omega⟩
  simp only [h8, ↓reduceIte]
  by_cases h9 : c < COL_CE; · simp only [h9, ↓reduceIte]; exact hbool _ (nat_bit_is_0_or_1 _ _)
  simp only [h9, ↓reduceIte]
  by_cases h10 : c < COL_W; · simp only [h10, ↓reduceIte]; exact hbool _ (nat_bit_is_0_or_1 _ _)
  simp only [h10, ↓reduceIte]
  by_cases h11 : c < COL_X1; · simp only [h11, ↓reduceIte]; exact ⟨Int.natCast_nonneg _, u32_toNat_lt_P _⟩
  simp only [h11, ↓reduceIte]
  by_cases h12 : c < COL_X14
  · simp only [h12, ↓reduceIte]
    by_cases ht : t < 63; · simp only [ht, ↓reduceIte]; exact hbool _ (u32Bit_is_bool _ _)
    simp only [ht, ↓reduceIte]
    by_cases hk : c - COL_X1 < 8
    · simp only [hk, ↓reduceIte]
      have hbd := blkDigOut_bounds blk (c - COL_X1)
      have hiv : (ivNat (c - COL_X1) : Int) < TWO32 := by
        have : c - COL_X1 = 0 ∨ c - COL_X1 = 1 ∨ c - COL_X1 = 2 ∨ c - COL_X1 = 3 ∨
               c - COL_X1 = 4 ∨ c - COL_X1 = 5 ∨ c - COL_X1 = 6 ∨ c - COL_X1 = 7 := by omega
        rcases this with h | h | h | h | h | h | h | h <;> rw [h] <;> decide
      have h0 : 0 ≤ ((ivNat (c - COL_X1) : Int) + blkDigOut blk (c - COL_X1)) / TWO32 :=
        Int.ediv_nonneg (by omega) (by omega)
      have hlt : ((ivNat (c - COL_X1) : Int) + blkDigOut blk (c - COL_X1)) / TWO32 < 2 := by
        simp only [TWO32] at *; omega
      omega
    · simp only [hk, ↓reduceIte]; decide
  simp only [h12, ↓reduceIte]
  by_cases h13 : c < COL_CWC
  · simp only [h13, ↓reduceIte]
    by_cases ht : t < 63; · simp only [ht, ↓reduceIte]; exact hbool _ (u32Bit_is_bool _ _)
    simp only [ht, ↓reduceIte]; decide
  simp only [h13, ↓reduceIte]
  by_cases h14 : c < COL_DIG
  · simp only [h14, ↓reduceIte]
    by_cases ht : t < 63; · simp only [ht, ↓reduceIte]; exact hbool _ (nat_bit_is_0_or_1 _ _)
    simp only [ht, ↓reduceIte]; decide
  simp only [h14, ↓reduceIte]
  by_cases ht : t = 63
  · simp only [ht, ↓reduceIte]; exact ⟨Int.emod_nonneg _ (by omega), by have := Int.emod_lt_of_pos ((ivNat (c - COL_DIG) : Int) + blkDigOut blk (c - COL_DIG)) hT; omega⟩
  · simp only [ht, ↓reduceIte]; decide

theorem witPos_lt_P {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) :
    (witPos w b : Int) < P := by
  have h0 := posAcc_lt_pow w.bits0 w.hBits0
  have h1 := posAcc_lt_pow w.bits1 w.hBits1
  have hP : (2 ^ 32 : Nat) < P := by decide
  unfold witPos
  split
  · decide
  · split
    · have hle : min (b - 2) 32 ≤ 32 := Nat.min_le_right _ _
      have hlt := h0 (min (b - 2) 32) hle
      have hpow : 2 ^ (min (b - 2) 32) ≤ 2 ^ 32 := Nat.pow_le_pow_right (by decide) hle
      omega
    · split
      · decide
      · have hle : min (b - 37) 32 ≤ 32 := Nat.min_le_right _ _
        have hlt := h1 (min (b - 37) 32) hle
        have hpow : 2 ^ (min (b - 37) 32) ≤ 2 ^ 32 := Nat.pow_le_pow_right (by decide) hle
        omega

theorem witBit_is_bool {pi : SpendPublicStmt} (w : ValidSpendWitness pi) (b : Nat) :
    witBit w b = 0 ∨ witBit w b = 1 := by
  unfold witBit
  split
  · exact w.hBits0 (b - 3) (by omega)
  · split
    · exact w.hBits1 (b - 38) (by omega)
    · exact Or.inl rfl

/-- Canonical `RawFieldTrace` constructed deterministically from any `ValidSpendWitness pi`. -/
def canonicalRawTrace (pi : SpendPublicStmt) (w : ValidSpendWitness pi) : RawFieldTrace where
  cell := canonicalCell w
  hRange := fun r c _ _ => by
    suffices ∀ v : Int, v = canonicalCell w r c → 0 ≤ v ∧ v < P from this _ rfl
    intro v hv
    unfold canonicalCell at hv; dsimp only at hv
    split at hv
    · split at hv
      · rw [hv]; exact canonBlockCell_bounds _ _ _
      · split at hv
        · rw [hv]; exact ⟨Int.natCast_nonneg _, u32_toNat_lt_P _⟩
        · split at hv
          · rw [hv]; exact ⟨Int.natCast_nonneg _, u32_toNat_lt_P _⟩
          · split at hv
            · split at hv
              · rw [hv]; rcases witBit_is_bool w (r / 64) with h | h <;> rw [h] <;> decide
              · rw [hv]; decide
            · split at hv
              · rw [hv]; exact ⟨Int.natCast_nonneg _, witPos_lt_P w _⟩
              · split at hv
                · rw [hv]; exact signedField_bounds _
                · rw [hv]; decide
    · rw [hv]; decide

-- ---- Part 9D: Cell readout lemmas for `canonicalRawTrace` ----

theorem canon_cell_active {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t c : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hc : c < COL_SK) :
    (canonicalRawTrace pi w).cell (b * 64 + t) c = canonBlockCell (witBlockMsg w b) t c := by
  have hd : (b * 64 + t) / 64 = b := by omega
  have hm : (b * 64 + t) % 64 = t := by omega
  simp [canonicalRawTrace, canonicalCell, hd, hm, hb1, hb72, hc]

theorem canon_cell_A {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_A + j) =
      u32Bit (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).a j := by
  rw [canon_cell_active w b t (COL_A + j) hb1 hb72 ht (by simp [COL_A, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : COL_A + j < COL_AP := by simp [COL_A, COL_AP]; omega
  simp only [h1, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_AP {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_AP + j) =
      u32Bit (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).b j := by
  rw [canon_cell_active w b t (COL_AP + j) hb1 hb72 ht (by simp [COL_AP, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_AP + j < COL_AP) := by simp [COL_AP]
  have h2 : COL_AP + j < COL_E := by simp [COL_AP, COL_E]; omega
  simp only [h1, h2, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_E {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_E + j) =
      u32Bit (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).e j := by
  rw [canon_cell_active w b t (COL_E + j) hb1 hb72 ht (by simp [COL_E, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_E + j < COL_AP) := by simp [COL_E, COL_AP]; omega
  have h2 : ¬(COL_E + j < COL_E) := by simp [COL_E]
  have h3 : COL_E + j < COL_EP := by simp [COL_E, COL_EP]; omega
  simp only [h1, h2, h3, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_EP {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 32) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_EP + j) =
      u32Bit (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).f j := by
  rw [canon_cell_active w b t (COL_EP + j) hb1 hb72 ht (by simp [COL_EP, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_EP + j < COL_AP) := by simp [COL_EP, COL_AP]; omega
  have h2 : ¬(COL_EP + j < COL_E) := by simp [COL_EP, COL_E]; omega
  have h3 : ¬(COL_EP + j < COL_EP) := by simp [COL_EP]
  have h4 : COL_EP + j < COL_CWORD := by simp [COL_EP, COL_CWORD]; omega
  simp only [h1, h2, h3, h4, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_CWORD {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_CWORD =
      ((sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).c.toNat : Int) := by
  rw [canon_cell_active w b t COL_CWORD hb1 hb72 ht (by decide)]
  unfold canonBlockCell; simp [COL_AP, COL_E, COL_EP, COL_CWORD]

theorem canon_cell_GWORD {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_GWORD =
      ((sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).g.toNat : Int) := by
  rw [canon_cell_active w b t COL_GWORD hb1 hb72 ht (by decide)]
  unfold canonBlockCell; simp [COL_AP, COL_E, COL_EP, COL_CWORD, COL_GWORD]

theorem canon_cell_AN {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_AN = blkSa (witBlockMsg w b) t % TWO32 := by
  rw [canon_cell_active w b t COL_AN hb1 hb72 ht (by decide)]
  unfold canonBlockCell; simp [COL_AP, COL_E, COL_EP, COL_CWORD, COL_GWORD, COL_AN]

theorem canon_cell_EN {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_EN = blkSe (witBlockMsg w b) t % TWO32 := by
  rw [canon_cell_active w b t COL_EN hb1 hb72 ht (by decide)]
  unfold canonBlockCell; simp [COL_AP, COL_E, COL_EP, COL_CWORD, COL_GWORD, COL_AN, COL_EN]

theorem canon_cell_CA {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 3) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_CA + j) =
      ((((blkSa (witBlockMsg w b) t / TWO32).toNat >>> j) &&& 1 : Nat) : Int) := by
  rw [canon_cell_active w b t (COL_CA + j) hb1 hb72 ht (by simp [COL_CA, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_CA + j < COL_AP) := by simp [COL_CA, COL_AP]; omega
  have h2 : ¬(COL_CA + j < COL_E) := by simp [COL_CA, COL_E]; omega
  have h3 : ¬(COL_CA + j < COL_EP) := by simp [COL_CA, COL_EP]; omega
  have h4 : ¬(COL_CA + j < COL_CWORD) := by simp [COL_CA, COL_CWORD]; omega
  have h5 : COL_CA + j ≠ COL_CWORD := by simp [COL_CA, COL_CWORD]; omega
  have h6 : COL_CA + j ≠ COL_GWORD := by simp [COL_CA, COL_GWORD]; omega
  have h7 : COL_CA + j ≠ COL_AN := by simp [COL_CA, COL_AN]; omega
  have h8 : COL_CA + j ≠ COL_EN := by simp [COL_CA, COL_EN]; omega
  have h9 : COL_CA + j < COL_CE := by simp [COL_CA, COL_CE]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_CE {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 3) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_CE + j) =
      ((((blkSe (witBlockMsg w b) t / TWO32).toNat >>> j) &&& 1 : Nat) : Int) := by
  rw [canon_cell_active w b t (COL_CE + j) hb1 hb72 ht (by simp [COL_CE, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_CE + j < COL_AP) := by simp [COL_CE, COL_AP]; omega
  have h2 : ¬(COL_CE + j < COL_E) := by simp [COL_CE, COL_E]; omega
  have h3 : ¬(COL_CE + j < COL_EP) := by simp [COL_CE, COL_EP]; omega
  have h4 : ¬(COL_CE + j < COL_CWORD) := by simp [COL_CE, COL_CWORD]; omega
  have h5 : COL_CE + j ≠ COL_CWORD := by simp [COL_CE, COL_CWORD]; omega
  have h6 : COL_CE + j ≠ COL_GWORD := by simp [COL_CE, COL_GWORD]; omega
  have h7 : COL_CE + j ≠ COL_AN := by simp [COL_CE, COL_AN]; omega
  have h8 : COL_CE + j ≠ COL_EN := by simp [COL_CE, COL_EN]; omega
  have h9 : ¬(COL_CE + j < COL_CE) := by simp [COL_CE]
  have h10 : COL_CE + j < COL_W := by simp [COL_CE, COL_W]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_W {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 16) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_W + j) =
      (((sha256Schedule79 (witBlockMsg w b))[t + j]!).toNat : Int) := by
  rw [canon_cell_active w b t (COL_W + j) hb1 hb72 ht (by simp [COL_W, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_W + j < COL_AP) := by simp [COL_W, COL_AP]; omega
  have h2 : ¬(COL_W + j < COL_E) := by simp [COL_W, COL_E]; omega
  have h3 : ¬(COL_W + j < COL_EP) := by simp [COL_W, COL_EP]; omega
  have h4 : ¬(COL_W + j < COL_CWORD) := by simp [COL_W, COL_CWORD]; omega
  have h5 : COL_W + j ≠ COL_CWORD := by simp [COL_W, COL_CWORD]; omega
  have h6 : COL_W + j ≠ COL_GWORD := by simp [COL_W, COL_GWORD]; omega
  have h7 : COL_W + j ≠ COL_AN := by simp [COL_W, COL_AN]; omega
  have h8 : COL_W + j ≠ COL_EN := by simp [COL_W, COL_EN]; omega
  have h9 : ¬(COL_W + j < COL_CE) := by simp [COL_W, COL_CE]; omega
  have h10 : ¬(COL_W + j < COL_W) := by simp [COL_W]
  have h11 : COL_W + j < COL_X1 := by simp [COL_W, COL_X1]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_X1_inner {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) (hj : j < 32) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_X1 + j) =
      u32Bit ((sha256Schedule79 (witBlockMsg w b))[t + 1]!) j := by
  rw [canon_cell_active w b t (COL_X1 + j) hb1 hb72 (by omega) (by simp [COL_X1, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_X1 + j < COL_AP) := by simp [COL_X1, COL_AP]; omega
  have h2 : ¬(COL_X1 + j < COL_E) := by simp [COL_X1, COL_E]; omega
  have h3 : ¬(COL_X1 + j < COL_EP) := by simp [COL_X1, COL_EP]; omega
  have h4 : ¬(COL_X1 + j < COL_CWORD) := by simp [COL_X1, COL_CWORD]; omega
  have h5 : COL_X1 + j ≠ COL_CWORD := by simp [COL_X1, COL_CWORD]; omega
  have h6 : COL_X1 + j ≠ COL_GWORD := by simp [COL_X1, COL_GWORD]; omega
  have h7 : COL_X1 + j ≠ COL_AN := by simp [COL_X1, COL_AN]; omega
  have h8 : COL_X1 + j ≠ COL_EN := by simp [COL_X1, COL_EN]; omega
  have h9 : ¬(COL_X1 + j < COL_CE) := by simp [COL_X1, COL_CE]; omega
  have h10 : ¬(COL_X1 + j < COL_W) := by simp [COL_X1, COL_W]; omega
  have h11 : ¬(COL_X1 + j < COL_X1) := by simp [COL_X1]
  have h12 : COL_X1 + j < COL_X14 := by simp [COL_X1, COL_X14]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, ht, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_X1_last {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hj : j < 8) :
    (canonicalRawTrace pi w).cell (b * 64 + 63) (COL_X1 + j) =
      ((ivNat j : Int) + blkDigOut (witBlockMsg w b) j) / TWO32 := by
  rw [canon_cell_active w b 63 (COL_X1 + j) hb1 hb72 (by omega) (by simp [COL_X1, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_X1 + j < COL_AP) := by simp [COL_X1, COL_AP]; omega
  have h2 : ¬(COL_X1 + j < COL_E) := by simp [COL_X1, COL_E]; omega
  have h3 : ¬(COL_X1 + j < COL_EP) := by simp [COL_X1, COL_EP]; omega
  have h4 : ¬(COL_X1 + j < COL_CWORD) := by simp [COL_X1, COL_CWORD]; omega
  have h5 : COL_X1 + j ≠ COL_CWORD := by simp [COL_X1, COL_CWORD]; omega
  have h6 : COL_X1 + j ≠ COL_GWORD := by simp [COL_X1, COL_GWORD]; omega
  have h7 : COL_X1 + j ≠ COL_AN := by simp [COL_X1, COL_AN]; omega
  have h8 : COL_X1 + j ≠ COL_EN := by simp [COL_X1, COL_EN]; omega
  have h9 : ¬(COL_X1 + j < COL_CE) := by simp [COL_X1, COL_CE]; omega
  have h10 : ¬(COL_X1 + j < COL_W) := by simp [COL_X1, COL_W]; omega
  have h11 : ¬(COL_X1 + j < COL_X1) := by simp [COL_X1]
  have h12 : COL_X1 + j < COL_X14 := by simp [COL_X1, COL_X14]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, show ¬(63 < 63) from by decide, hj, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_X14_inner {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) (hj : j < 32) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_X14 + j) =
      u32Bit ((sha256Schedule79 (witBlockMsg w b))[t + 14]!) j := by
  rw [canon_cell_active w b t (COL_X14 + j) hb1 hb72 (by omega) (by simp [COL_X14, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_X14 + j < COL_AP) := by simp [COL_X14, COL_AP]; omega
  have h2 : ¬(COL_X14 + j < COL_E) := by simp [COL_X14, COL_E]; omega
  have h3 : ¬(COL_X14 + j < COL_EP) := by simp [COL_X14, COL_EP]; omega
  have h4 : ¬(COL_X14 + j < COL_CWORD) := by simp [COL_X14, COL_CWORD]; omega
  have h5 : COL_X14 + j ≠ COL_CWORD := by simp [COL_X14, COL_CWORD]; omega
  have h6 : COL_X14 + j ≠ COL_GWORD := by simp [COL_X14, COL_GWORD]; omega
  have h7 : COL_X14 + j ≠ COL_AN := by simp [COL_X14, COL_AN]; omega
  have h8 : COL_X14 + j ≠ COL_EN := by simp [COL_X14, COL_EN]; omega
  have h9 : ¬(COL_X14 + j < COL_CE) := by simp [COL_X14, COL_CE]; omega
  have h10 : ¬(COL_X14 + j < COL_W) := by simp [COL_X14, COL_W]; omega
  have h11 : ¬(COL_X14 + j < COL_X1) := by simp [COL_X14, COL_X1]; omega
  have h12 : ¬(COL_X14 + j < COL_X14) := by simp [COL_X14]
  have h13 : COL_X14 + j < COL_CWC := by simp [COL_X14, COL_CWC]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, ht, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_CWC_inner {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) (hj : j < 2) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_CWC + j) =
      ((((blkSw (witBlockMsg w b) t / TWO32).toNat >>> j) &&& 1 : Nat) : Int) := by
  rw [canon_cell_active w b t (COL_CWC + j) hb1 hb72 (by omega) (by simp [COL_CWC, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_CWC + j < COL_AP) := by simp [COL_CWC, COL_AP]; omega
  have h2 : ¬(COL_CWC + j < COL_E) := by simp [COL_CWC, COL_E]; omega
  have h3 : ¬(COL_CWC + j < COL_EP) := by simp [COL_CWC, COL_EP]; omega
  have h4 : ¬(COL_CWC + j < COL_CWORD) := by simp [COL_CWC, COL_CWORD]; omega
  have h5 : COL_CWC + j ≠ COL_CWORD := by simp [COL_CWC, COL_CWORD]; omega
  have h6 : COL_CWC + j ≠ COL_GWORD := by simp [COL_CWC, COL_GWORD]; omega
  have h7 : COL_CWC + j ≠ COL_AN := by simp [COL_CWC, COL_AN]; omega
  have h8 : COL_CWC + j ≠ COL_EN := by simp [COL_CWC, COL_EN]; omega
  have h9 : ¬(COL_CWC + j < COL_CE) := by simp [COL_CWC, COL_CE]; omega
  have h10 : ¬(COL_CWC + j < COL_W) := by simp [COL_CWC, COL_W]; omega
  have h11 : ¬(COL_CWC + j < COL_X1) := by simp [COL_CWC, COL_X1]; omega
  have h12 : ¬(COL_CWC + j < COL_X14) := by simp [COL_CWC, COL_X14]; omega
  have h13 : ¬(COL_CWC + j < COL_CWC) := by simp [COL_CWC]
  have h14 : COL_CWC + j < COL_DIG := by simp [COL_CWC, COL_DIG]; omega
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, ht, ↓reduceIte, Nat.add_sub_cancel_left]

theorem canon_cell_DIG_last {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (hj : j < 8) :
    (canonicalRawTrace pi w).cell (b * 64 + 63) (COL_DIG + j) =
      (((sha256Compress (witBlockMsg w b))[j]!).toNat : Int) := by
  rw [canon_cell_active w b 63 (COL_DIG + j) hb1 hb72 (by omega) (by simp [COL_DIG, COL_SK]; omega)]
  unfold canonBlockCell
  have h1 : ¬(COL_DIG + j < COL_AP) := by simp [COL_DIG, COL_AP]; omega
  have h2 : ¬(COL_DIG + j < COL_E) := by simp [COL_DIG, COL_E]; omega
  have h3 : ¬(COL_DIG + j < COL_EP) := by simp [COL_DIG, COL_EP]; omega
  have h4 : ¬(COL_DIG + j < COL_CWORD) := by simp [COL_DIG, COL_CWORD]; omega
  have h5 : COL_DIG + j ≠ COL_CWORD := by simp [COL_DIG, COL_CWORD]; omega
  have h6 : COL_DIG + j ≠ COL_GWORD := by simp [COL_DIG, COL_GWORD]; omega
  have h7 : COL_DIG + j ≠ COL_AN := by simp [COL_DIG, COL_AN]; omega
  have h8 : COL_DIG + j ≠ COL_EN := by simp [COL_DIG, COL_EN]; omega
  have h9 : ¬(COL_DIG + j < COL_CE) := by simp [COL_DIG, COL_CE]; omega
  have h10 : ¬(COL_DIG + j < COL_W) := by simp [COL_DIG, COL_W]; omega
  have h11 : ¬(COL_DIG + j < COL_X1) := by simp [COL_DIG, COL_X1]; omega
  have h12 : ¬(COL_DIG + j < COL_X14) := by simp [COL_DIG, COL_X14]; omega
  have h13 : ¬(COL_DIG + j < COL_CWC) := by simp [COL_DIG, COL_CWC]; omega
  have h14 : ¬(COL_DIG + j < COL_DIG) := by simp [COL_DIG]
  simp only [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, ↓reduceIte, Nat.add_sub_cancel_left]
  exact blkDig_eq_compress (witBlockMsg w b) (witBlockMsg_size w b) j hj

theorem canon_cell_SK {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 8) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_SK + j) = ((witSk w b ⟨j, hj⟩).toNat : Int) := by
  have hd : (b * 64 + t) / 64 = b := by omega
  have h1 : ¬(COL_SK + j < COL_SK) := by simp [COL_SK]
  have h2 : COL_SK + j < COL_RHO := by simp [COL_SK, COL_RHO]; omega
  simp only [canonicalRawTrace, canonicalCell, hd, hb1, hb72, h1, h2, and_self, ↓reduceIte, ↓reduceDIte, Nat.add_sub_cancel_left]

theorem canon_cell_RHO {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t j : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) (hj : j < 5) :
    (canonicalRawTrace pi w).cell (b * 64 + t) (COL_RHO + j) = ((witRho w b ⟨j, hj⟩).toNat : Int) := by
  have hd : (b * 64 + t) / 64 = b := by omega
  have h1 : ¬(COL_RHO + j < COL_SK) := by simp [COL_RHO, COL_SK]; omega
  have h2 : ¬(COL_RHO + j < COL_RHO) := by simp [COL_RHO]
  have h3 : COL_RHO + j < COL_BIT := by simp [COL_RHO, COL_BIT]; omega
  simp only [canonicalRawTrace, canonicalCell, hd, hb1, hb72, h1, h2, h3, and_self, ↓reduceIte, ↓reduceDIte, Nat.add_sub_cancel_left]

theorem canon_cell_POS {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_POS = (witPos w b : Int) := by
  have hd : (b * 64 + t) / 64 = b := by omega
  simp [canonicalRawTrace, canonicalCell, hd, hb1, hb72, COL_SK, COL_RHO, COL_BIT, COL_POS]

theorem canon_cell_BAL {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_BAL = signedField (witBalInt w b) := by
  have hd : (b * 64 + t) / 64 = b := by omega
  simp [canonicalRawTrace, canonicalCell, hd, hb1, hb72, COL_SK, COL_RHO, COL_BIT, COL_POS, COL_BAL]

theorem canon_cell_BIT {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_BIT = if t = 0 then (witBit w b : Int) else 0 := by
  have hd : (b * 64 + t) / 64 = b := by omega
  have hm : (b * 64 + t) % 64 = t := by omega
  simp only [canonicalRawTrace, canonicalCell, hd, hm, hb1, hb72, and_self, ↓reduceIte, ↓reduceDIte,
    show ¬(COL_BIT < COL_SK) from by decide, show ¬(COL_BIT < COL_RHO) from by decide,
    show ¬(COL_BIT < COL_BIT) from by decide]

theorem canon_carry3_CA {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    carry3Val (canonicalRawTrace pi w) (b * 64 + t) COL_CA = blkSa (witBlockMsg w b) t / TWO32 := by
  unfold carry3Val
  have h0 := canon_cell_CA w b t 0 hb1 hb72 ht (by decide)
  simp only [Nat.add_zero] at h0
  rw [h0, canon_cell_CA w b t 1 hb1 hb72 ht (by decide),
      canon_cell_CA w b t 2 hb1 hb72 ht (by decide)]
  have hbd := blkSa_bounds (witBlockMsg w b) t
  have hq0 : 0 ≤ blkSa (witBlockMsg w b) t / TWO32 := Int.ediv_nonneg hbd.1 (by decide)
  have hqlt : (blkSa (witBlockMsg w b) t / TWO32).toNat < 8 := by
    simp only [TWO32] at *; omega
  have hrec := bit_3_reconstruct (blkSa (witBlockMsg w b) t / TWO32).toNat hqlt
  rw [hrec]; omega

theorem canon_carry3_CE {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    carry3Val (canonicalRawTrace pi w) (b * 64 + t) COL_CE = blkSe (witBlockMsg w b) t / TWO32 := by
  unfold carry3Val
  have h0 := canon_cell_CE w b t 0 hb1 hb72 ht (by decide)
  simp only [Nat.add_zero] at h0
  rw [h0, canon_cell_CE w b t 1 hb1 hb72 ht (by decide),
      canon_cell_CE w b t 2 hb1 hb72 ht (by decide)]
  have hbd := blkSe_bounds (witBlockMsg w b) t
  have hq0 : 0 ≤ blkSe (witBlockMsg w b) t / TWO32 := Int.ediv_nonneg hbd.1 (by decide)
  have hqlt : (blkSe (witBlockMsg w b) t / TWO32).toNat < 8 := by
    simp only [TWO32] at *; omega
  have hrec := bit_3_reconstruct (blkSe (witBlockMsg w b) t / TWO32).toNat hqlt
  rw [hrec]; omega

theorem canon_cwc_reconstruct {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 63) :
    (canonicalRawTrace pi w).cell (b * 64 + t) COL_CWC +
      2 * (canonicalRawTrace pi w).cell (b * 64 + t) (COL_CWC + 1) =
    blkSw (witBlockMsg w b) t / TWO32 := by
  have h0 := canon_cell_CWC_inner w b t 0 hb1 hb72 ht (by decide)
  simp only [Nat.add_zero] at h0
  rw [h0, canon_cell_CWC_inner w b t 1 hb1 hb72 ht (by decide)]
  have hbd := blkSw_bounds (witBlockMsg w b) t
  have hq0 : 0 ≤ blkSw (witBlockMsg w b) t / TWO32 := Int.ediv_nonneg hbd.1 (by decide)
  have hqlt : (blkSw (witBlockMsg w b) t / TWO32).toNat < 4 := by
    simp only [TWO32] at *; omega
  have hrec := bit_2_reconstruct (blkSw (witBlockMsg w b) t / TWO32).toNat hqlt
  rw [hrec]; omega

theorem canon_dig_equals_semantic {pi : SpendPublicStmt} (w : ValidSpendWitness pi) :
    (arr8ToWord8 (sha256Compress (witBlockMsg w 1)) = w.apk0) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 2)) = w.cmIn0) ∧
    (∀ k, k < 32 → arr8ToWord8 (sha256Compress (witBlockMsg w (3 + k))) = merkleRoot w.cmIn0 w.bits0 w.sibs0 (k + 1)) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 35)) = pi.nf0) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 36)) = w.apk1) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 37)) = w.cmIn1) ∧
    (∀ k, k < 32 → arr8ToWord8 (sha256Compress (witBlockMsg w (38 + k))) = merkleRoot w.cmIn1 w.bits1 w.sibs1 (k + 1)) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 70)) = pi.nf1) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 71)) = pi.cmOut0) ∧
    (arr8ToWord8 (sha256Compress (witBlockMsg w 72)) = pi.cmOut1) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [w.hOwner0]; rfl
  · rw [w.hCmIn0]; rfl
  · intro k hk
    have hlo : 3 ≤ 3 + k ∧ 3 + k ≤ 34 := by omega
    have hne1 : 3 + k ≠ 1 := by omega
    have hne2 : 3 + k ≠ 2 := by omega
    have hsub : 3 + k - 3 = k := by omega
    simp only [witBlockMsg, hne1, hne2, hlo, hsub, ↓reduceIte]
    rfl
  · rw [w.hNf0]; rfl
  · rw [w.hOwner1]; rfl
  · rw [w.hCmIn1]; rfl
  · intro k hk
    have hlo : 38 ≤ 38 + k ∧ 38 + k ≤ 69 := by omega
    have hne1 : 38 + k ≠ 1 := by omega
    have hne2 : 38 + k ≠ 2 := by omega
    have hnot1 : ¬(3 ≤ 38 + k ∧ 38 + k ≤ 34) := by omega
    have hne35 : 38 + k ≠ 35 := by omega
    have hne36 : 38 + k ≠ 36 := by omega
    have hne37 : 38 + k ≠ 37 := by omega
    have hsub : 38 + k - 38 = k := by omega
    simp only [witBlockMsg, hne1, hne2, hnot1, hne35, hne36, hne37, hlo, hsub, ↓reduceIte]
    rfl
  · rw [w.hNf1]; rfl
  · rw [w.hCmOut0]; rfl
  · rw [w.hCmOut1]; rfl

theorem canon_bool_cell_zero {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (b t : Nat) (hb1 : 1 ≤ b) (hb72 : b ≤ 72) (ht : t < 64) :
    (∀ k, k < 128 →
      let base := if k < 32 then COL_A else if k < 64 then COL_E else if k < 96 then COL_X1 else COL_X14
      let v := (canonicalRawTrace pi w).cell (b * 64 + t) (base + k % 32)
      v = 0 ∨ v = 1) ∧
    (∀ k, k < 9 →
      let v := (canonicalRawTrace pi w).cell (b * 64 + t) (bool9Col k)
      v = 0 ∨ v = 1) := by
  constructor
  · intro k hk
    by_cases h1 : k < 32
    · simp only [h1, ↓reduceIte, Nat.mod_eq_of_lt h1]
      rw [canon_cell_A w b t k hb1 hb72 ht h1]; exact u32Bit_is_bool _ _
    · by_cases h2 : k < 64
      · simp only [h1, h2, ↓reduceIte]
        rw [canon_cell_E w b t (k % 32) hb1 hb72 ht (Nat.mod_lt _ (by decide))]; exact u32Bit_is_bool _ _
      · by_cases h3 : k < 96
        · simp only [h1, h2, h3, ↓reduceIte]
          by_cases ht63 : t < 63
          · rw [canon_cell_X1_inner w b t (k % 32) hb1 hb72 ht63 (Nat.mod_lt _ (by decide))]; exact u32Bit_is_bool _ _
          · have ht63e : t = 63 := by omega
            subst ht63e
            by_cases hj8 : k % 32 < 8
            · rw [canon_cell_X1_last w b (k % 32) hb1 hb72 hj8]
              have hbd := blkDigOut_bounds (witBlockMsg w b) (k % 32)
              have hiv : (ivNat (k % 32) : Int) < TWO32 := by
                have : k % 32 = 0 ∨ k % 32 = 1 ∨ k % 32 = 2 ∨ k % 32 = 3 ∨
                       k % 32 = 4 ∨ k % 32 = 5 ∨ k % 32 = 6 ∨ k % 32 = 7 := by omega
                rcases this with h | h | h | h | h | h | h | h <;> rw [h] <;> decide
              have h0 : 0 ≤ ((ivNat (k % 32) : Int) + blkDigOut (witBlockMsg w b) (k % 32)) / TWO32 :=
                Int.ediv_nonneg (by omega) (by decide)
              have hlt : ((ivNat (k % 32) : Int) + blkDigOut (witBlockMsg w b) (k % 32)) / TWO32 < 2 := by
                simp only [TWO32] at *; omega
              omega
            · rw [canon_cell_active w b 63 (COL_X1 + k % 32) hb1 hb72 (by omega) (by simp [COL_X1, COL_SK]; omega)]
              unfold canonBlockCell
              have hj32 : k % 32 < 32 := Nat.mod_lt _ (by decide)
              have ha1 : ¬(COL_X1 + k % 32 < COL_AP) := by simp [COL_X1, COL_AP]; omega
              have ha2 : ¬(COL_X1 + k % 32 < COL_E) := by simp [COL_X1, COL_E]; omega
              have ha3 : ¬(COL_X1 + k % 32 < COL_EP) := by simp [COL_X1, COL_EP]; omega
              have ha4 : ¬(COL_X1 + k % 32 < COL_CWORD) := by simp [COL_X1, COL_CWORD]; omega
              have ha5 : COL_X1 + k % 32 ≠ COL_CWORD := by simp [COL_X1, COL_CWORD]; omega
              have ha6 : COL_X1 + k % 32 ≠ COL_GWORD := by simp [COL_X1, COL_GWORD]; omega
              have ha7 : COL_X1 + k % 32 ≠ COL_AN := by simp [COL_X1, COL_AN]; omega
              have ha8 : COL_X1 + k % 32 ≠ COL_EN := by simp [COL_X1, COL_EN]; omega
              have ha9 : ¬(COL_X1 + k % 32 < COL_CE) := by simp [COL_X1, COL_CE]; omega
              have ha10 : ¬(COL_X1 + k % 32 < COL_W) := by simp [COL_X1, COL_W]; omega
              have ha11 : ¬(COL_X1 + k % 32 < COL_X1) := by simp [COL_X1]
              have ha12 : COL_X1 + k % 32 < COL_X14 := by simp [COL_X1, COL_X14]; omega
              simp [ha1, ha2, ha3, ha4, ha5, ha6, ha7, ha8, ha9, ha10, ha11, ha12, hj8]
        · simp only [h1, h2, h3, ↓reduceIte]
          by_cases ht63 : t < 63
          · rw [canon_cell_X14_inner w b t (k % 32) hb1 hb72 ht63 (Nat.mod_lt _ (by decide))]; exact u32Bit_is_bool _ _
          · have ht63e : t = 63 := by omega
            subst ht63e
            rw [canon_cell_active w b 63 (COL_X14 + k % 32) hb1 hb72 (by omega) (by simp [COL_X14, COL_SK]; omega)]
            unfold canonBlockCell
            have hj32 : k % 32 < 32 := Nat.mod_lt _ (by decide)
            have ha1 : ¬(COL_X14 + k % 32 < COL_AP) := by simp [COL_X14, COL_AP]; omega
            have ha2 : ¬(COL_X14 + k % 32 < COL_E) := by simp [COL_X14, COL_E]; omega
            have ha3 : ¬(COL_X14 + k % 32 < COL_EP) := by simp [COL_X14, COL_EP]; omega
            have ha4 : ¬(COL_X14 + k % 32 < COL_CWORD) := by simp [COL_X14, COL_CWORD]; omega
            have ha5 : COL_X14 + k % 32 ≠ COL_CWORD := by simp [COL_X14, COL_CWORD]; omega
            have ha6 : COL_X14 + k % 32 ≠ COL_GWORD := by simp [COL_X14, COL_GWORD]; omega
            have ha7 : COL_X14 + k % 32 ≠ COL_AN := by simp [COL_X14, COL_AN]; omega
            have ha8 : COL_X14 + k % 32 ≠ COL_EN := by simp [COL_X14, COL_EN]; omega
            have ha9 : ¬(COL_X14 + k % 32 < COL_CE) := by simp [COL_X14, COL_CE]; omega
            have ha10 : ¬(COL_X14 + k % 32 < COL_W) := by simp [COL_X14, COL_W]; omega
            have ha11 : ¬(COL_X14 + k % 32 < COL_X1) := by simp [COL_X14, COL_X1]; omega
            have ha12 : ¬(COL_X14 + k % 32 < COL_X14) := by simp [COL_X14]
            have ha13 : COL_X14 + k % 32 < COL_CWC := by simp [COL_X14, COL_CWC]; omega
            simp [ha1, ha2, ha3, ha4, ha5, ha6, ha7, ha8, ha9, ha10, ha11, ha12, ha13]
  · intro k hk
    have : k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 3 ∨ k = 4 ∨ k = 5 ∨ k = 6 ∨ k = 7 ∨ k = 8 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · simp only [bool9Col]; have h0 := canon_cell_CA w b t 0 hb1 hb72 ht (by decide); simp only [Nat.add_zero] at h0; rw [h0]; exact nat_bit_is_0_or_1 _ _
    · simp only [bool9Col]; rw [canon_cell_CA w b t 1 hb1 hb72 ht (by decide)]; exact nat_bit_is_0_or_1 _ _
    · simp only [bool9Col]; rw [canon_cell_CA w b t 2 hb1 hb72 ht (by decide)]; exact nat_bit_is_0_or_1 _ _
    · simp only [bool9Col]; have h0 := canon_cell_CE w b t 0 hb1 hb72 ht (by decide); simp only [Nat.add_zero] at h0; rw [h0]; exact nat_bit_is_0_or_1 _ _
    · simp only [bool9Col]; rw [canon_cell_CE w b t 1 hb1 hb72 ht (by decide)]; exact nat_bit_is_0_or_1 _ _
    · simp only [bool9Col]; rw [canon_cell_CE w b t 2 hb1 hb72 ht (by decide)]; exact nat_bit_is_0_or_1 _ _
    · simp only [bool9Col]
      by_cases ht63 : t < 63
      · have h0 := canon_cell_CWC_inner w b t 0 hb1 hb72 ht63 (by decide); simp only [Nat.add_zero] at h0; rw [h0]; exact nat_bit_is_0_or_1 _ _
      · have ht63e : t = 63 := by omega
        subst ht63e
        rw [canon_cell_active w b 63 COL_CWC hb1 hb72 (by omega) (by decide)]
        unfold canonBlockCell; simp [COL_AP, COL_E, COL_EP, COL_CWORD, COL_GWORD, COL_AN, COL_EN, COL_CE, COL_W, COL_X1, COL_X14, COL_CWC, COL_DIG]
    · simp only [bool9Col]
      by_cases ht63 : t < 63
      · rw [canon_cell_CWC_inner w b t 1 hb1 hb72 ht63 (by decide)]; exact nat_bit_is_0_or_1 _ _
      · have ht63e : t = 63 := by omega
        subst ht63e
        rw [canon_cell_active w b 63 (COL_CWC + 1) hb1 hb72 (by omega) (by decide)]
        unfold canonBlockCell; simp [COL_AP, COL_E, COL_EP, COL_CWORD, COL_GWORD, COL_AN, COL_EN, COL_CE, COL_W, COL_X1, COL_X14, COL_CWC, COL_DIG]
    · simp only [bool9Col]
      rw [canon_cell_BIT w b t hb1 hb72 ht]
      split
      · rcases witBit_is_bool w b with h | h <;> rw [h] <;> simp
      · exact Or.inl rfl

-- ---- Part 9E: Message-load satisfaction (`msgLoadTerm = 0` on all block boundaries!) ----

theorem canon_msgLoadTerm_zero {pi : SpendPublicStmt} (w : ValidSpendWitness pi)
    (r j : Nat) (_hr : r < 8191) (hj : j < 16) :
    msgLoadTerm (canonicalRawTrace pi w) r j = 0 := by
  generalize hb_def : r / 64 = b
  generalize ht_def : r % 64 = t
  have hrt : r = b * 64 + t := by omega
  by_cases ht63 : t = 63
  · -- Only rows with t = 63 and b ∈ 0..71 have any of periodicVal 3..7 nonzero!
    by_cases hb71 : b ≤ 71
    · have hb1 : 1 ≤ b + 1 := by omega
      have hb72 : b + 1 ≤ 72 := by omega
      have hnxt : r + 1 = (b + 1) * 64 + 0 := by omega
      have hcur : r = b * 64 + 63 := by omega
      have hnw : (canonicalRawTrace pi w).cell (r + 1) (COL_W + j) = (((witBlockMsg w (b + 1))[j]!).toNat : Int) := by
        rw [hnxt, canon_cell_W w (b + 1) 0 j hb1 hb72 (by omega) hj, Nat.zero_add,
            sha256Schedule79_init _ (witBlockMsg_size w (b + 1)) j hj]
      have hdigs := canon_dig_equals_semantic w
      unfold msgLoadTerm
      simp only [periodicVal, hb_def, ht_def, ht63, true_and]
      by_cases hA : b = 0 ∨ b = 35
      · -- Addr(0) (b=0, nxt=1) or Addr(1) (b=35, nxt=36)
        have hnot4 : ¬(b = 1 ∨ b = 36) := by omega
        have hnot5 : ¬((2 ≤ b ∧ b ≤ 33) ∨ (37 ≤ b ∧ b ≤ 68)) := by omega
        have hnot6 : ¬(b = 34 ∨ b = 69) := by omega
        have hnot7 : ¬(b = 70 ∨ b = 71) := by omega
        simp only [hA, hnot4, hnot5, hnot6, hnot7, ↓reduceIte, Int.zero_mul, Int.one_mul, Int.add_zero]
        have hsub0 : (canonicalRawTrace pi w).cell (r + 1) (COL_W + j) =
            (if j = 0 then (TAG_ADDR : Int) else if j ≤ 8 then (canonicalRawTrace pi w).cell (r + 1) (COL_SK + j - 1) else 0) := by
          rw [hnw]
          by_cases hj0 : j = 0
          · subst hj0
            rcases hA with rfl | rfl <;> (simp [witBlockMsg]; decide)
          · by_cases hj8 : j ≤ 8
            · simp only [hj0, hj8, ↓reduceIte]
              have hcol : COL_SK + j - 1 = COL_SK + (j - 1) := by simp [COL_SK]; omega
              rw [hnxt, hcol, canon_cell_SK w (b + 1) 0 (j - 1) hb1 hb72 (by omega) (by omega)]
              have hjv : j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 ∨ j = 8 := by omega
              rcases hA with rfl | rfl <;>
                rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
                simp [witBlockMsg, witSk]
            · simp only [hj0, hj8, ↓reduceIte]
              have hjv : j = 9 ∨ j = 10 ∨ j = 11 ∨ j = 12 ∨ j = 13 ∨ j = 14 ∨ j = 15 := by omega
              rcases hA with rfl | rfl <;>
                rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
                simp [witBlockMsg]
        rw [hsub0, Int.sub_self]; simp
      · by_cases hC : b = 1 ∨ b = 36
        · -- CmIn(0) (b=1, nxt=2) or CmIn(1) (b=36, nxt=37)
          have hnot5 : ¬((2 ≤ b ∧ b ≤ 33) ∨ (37 ≤ b ∧ b ≤ 68)) := by omega
          have hnot6 : ¬(b = 34 ∨ b = 69) := by omega
          have hnot7 : ¬(b = 70 ∨ b = 71) := by omega
          simp only [hA, hC, hnot5, hnot6, hnot7, ↓reduceIte, Int.zero_mul, Int.one_mul, Int.zero_add, Int.add_zero]
          by_cases hj0 : j = 0
          · subst hj0; rw [hnw]
            rcases hC with rfl | rfl <;> (simp [witBlockMsg]; decide)
          · by_cases hj8 : j ≤ 8
            · simp only [hj0, hj8, ↓reduceIte]
              rw [hnw, hcur]
              have hcol : COL_DIG + j - 1 = COL_DIG + (j - 1) := by simp [COL_DIG]; omega
              rw [hcol, canon_cell_DIG_last w b (j - 1) (by omega) (by omega) (by omega)]
              have hjv : j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 ∨ j = 8 := by omega
              rcases hC with rfl | rfl
              · have he := congrFun hdigs.1 ⟨j - 1, by omega⟩
                simp only [arr8ToWord8] at he
                rw [he]
                rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
                  (simp only [witBlockMsg, show ¬(2 = 1) from by decide, ↓reduceIte]; simp)
              · have he := congrFun hdigs.2.2.2.2.1 ⟨j - 1, by omega⟩
                simp only [arr8ToWord8] at he
                rw [he]
                rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
                  (simp only [witBlockMsg, show ¬(37 = 1) from by decide, show ¬(37 = 2) from by decide,
                    show ¬(3 ≤ 37 ∧ 37 ≤ 34) from by decide, show ¬(37 = 35) from by decide,
                    show ¬(37 = 36) from by decide, ↓reduceIte]; simp)
            · by_cases hj11 : j ≥ 11
              · simp only [hj0, hj8, hj11, ↓reduceIte]
                have hcol : COL_RHO + j - 11 = COL_RHO + (j - 11) := by simp [COL_RHO]; omega
                rw [hnw, hnxt, hcol, canon_cell_RHO w (b + 1) 0 (j - 11) hb1 hb72 (by omega) (by omega)]
                have hjv : j = 11 ∨ j = 12 ∨ j = 13 ∨ j = 14 ∨ j = 15 := by omega
                rcases hC with rfl | rfl <;>
                  rcases hjv with rfl | rfl | rfl | rfl | rfl <;>
                  simp [witBlockMsg, witRho]
              · simp [hj0, hj8, hj11]
        · by_cases hM : (2 ≤ b ∧ b ≤ 33) ∨ (37 ≤ b ∧ b ≤ 68)
          · -- Merkle(0, k) or Merkle(1, k)
            have hnot6 : ¬(b = 34 ∨ b = 69) := by omega
            have hnot7 : ¬(b = 70 ∨ b = 71) := by omega
            simp only [hA, hC, hM, hnot6, hnot7, ↓reduceIte, Int.zero_mul, Int.one_mul, Int.zero_add, Int.add_zero]
            have hbitcell : (canonicalRawTrace pi w).cell (r + 1) COL_BIT = (witBit w (b + 1) : Int) := by
              rw [hnxt, canon_cell_BIT w (b + 1) 0 hb1 hb72 (by omega)]; rfl
            rw [hbitcell]
            -- Prove prev digest at block b matches merkleRoot!
            have hprevDig : ∀ idx : Fin 8,
                (canonicalRawTrace pi w).cell r (COL_DIG + idx.val) =
                  ((if b ≤ 33 then merkleRoot w.cmIn0 w.bits0 w.sibs0 (b - 2) idx
                    else merkleRoot w.cmIn1 w.bits1 w.sibs1 (b - 37) idx).toNat : Int) := fun idx => by
              rw [hcur, canon_cell_DIG_last w b idx.val (by omega) (by omega) idx.isLt]
              rcases hM with ⟨hlo, hhi⟩ | ⟨hlo, hhi⟩
              · simp only [hhi, ↓reduceIte]
                by_cases hb2 : b = 2
                · subst hb2; have he := congrFun hdigs.2.1 idx; simp only [arr8ToWord8] at he; rw [he]; rfl
                · have hk : b - 3 < 32 := by omega
                  have h3k : 3 + (b - 3) = b := by omega
                  have he := congrFun (hdigs.2.2.1 (b - 3) hk) idx
                  simp only [arr8ToWord8, h3k, show b - 3 + 1 = b - 2 from by omega] at he
                  rw [he]
              · have hnot33 : ¬(b ≤ 33) := by omega
                simp only [hnot33, ↓reduceIte]
                by_cases hb37 : b = 37
                · subst hb37; have he := congrFun hdigs.2.2.2.2.2.1 idx; simp only [arr8ToWord8] at he; rw [he]; rfl
                · have hk : b - 38 < 32 := by omega
                  have h38k : 38 + (b - 38) = b := by omega
                  have he := congrFun (hdigs.2.2.2.2.2.2.1 (b - 38) hk) idx
                  simp only [arr8ToWord8, h38k, show b - 38 + 1 = b - 37 from by omega] at he
                  rw [he]
            -- Check bit = 0 or bit = 1
            rcases witBit_is_bool w (b + 1) with hbit0 | hbit1
            · rw [hbit0]
              by_cases hj8 : j < 8
              · simp only [hj8, ↓reduceIte, Int.natCast_zero, Int.sub_zero, Int.one_mul]
                rw [hnw, hprevDig ⟨j, hj8⟩]
                have hjv : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 := by omega
                rcases hM with ⟨hlo, hhi⟩ | ⟨hlo, hhi⟩
                · have hwb : witBit w (b + 1) = w.bits0 (b - 2) := by
                    simp only [witBit, show 3 ≤ b + 1 ∧ b + 1 ≤ 34 from by omega, show b + 1 - 3 = b - 2 from by omega, and_self, ↓reduceIte]
                  rw [hwb] at hbit0
                  have hmsg : witBlockMsg w (b + 1) =
                      merkleMsg (merkleRoot w.cmIn0 w.bits0 w.sibs0 (b - 2)) (w.sibs0 (b - 2)) 0 := by
                    simp only [witBlockMsg, show b + 1 ≠ 1 from by omega, show b + 1 ≠ 2 from by omega,
                          show 3 ≤ b + 1 ∧ b + 1 ≤ 34 from by omega, show b + 1 - 3 = b - 2 from by omega, hbit0, and_self, ↓reduceIte]
                  rw [hmsg]; simp only [hhi, ↓reduceIte, merkleMsg]
                  rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp
                · have hnot33 : ¬(b ≤ 33) := by omega
                  have hwb : witBit w (b + 1) = w.bits1 (b - 37) := by
                    simp only [witBit, show ¬(3 ≤ b + 1 ∧ b + 1 ≤ 34) from by omega,
                          show 38 ≤ b + 1 ∧ b + 1 ≤ 69 from by omega, show b + 1 - 38 = b - 37 from by omega, and_self, ↓reduceIte]
                  rw [hwb] at hbit0
                  have hmsg : witBlockMsg w (b + 1) =
                      merkleMsg (merkleRoot w.cmIn1 w.bits1 w.sibs1 (b - 37)) (w.sibs1 (b - 37)) 0 := by
                    simp only [witBlockMsg, show b + 1 ≠ 1 from by omega, show b + 1 ≠ 2 from by omega,
                          show ¬(3 ≤ b + 1 ∧ b + 1 ≤ 34) from by omega, show b + 1 ≠ 35 from by omega,
                          show b + 1 ≠ 36 from by omega, show b + 1 ≠ 37 from by omega,
                          show 38 ≤ b + 1 ∧ b + 1 ≤ 69 from by omega, show b + 1 - 38 = b - 37 from by omega, hbit0, and_self, ↓reduceIte]
                  rw [hmsg]; simp only [hnot33, ↓reduceIte, merkleMsg]
                  rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp
              · simp [hj8]
            · rw [hbit1]
              by_cases hj8 : j < 8
              · simp [hj8]
              · simp only [hj8, ↓reduceIte, Int.natCast_one, Int.one_mul]
                have hcol : COL_DIG + j - 8 = COL_DIG + (j - 8) := by simp [COL_DIG]; omega
                rw [hnw, hcol, hprevDig ⟨j - 8, by omega⟩]
                have hjv : j = 8 ∨ j = 9 ∨ j = 10 ∨ j = 11 ∨ j = 12 ∨ j = 13 ∨ j = 14 ∨ j = 15 := by omega
                rcases hM with ⟨hlo, hhi⟩ | ⟨hlo, hhi⟩
                · have hwb : witBit w (b + 1) = w.bits0 (b - 2) := by
                    simp only [witBit, show 3 ≤ b + 1 ∧ b + 1 ≤ 34 from by omega, show b + 1 - 3 = b - 2 from by omega, and_self, ↓reduceIte]
                  rw [hwb] at hbit1
                  have hmsg : witBlockMsg w (b + 1) =
                      merkleMsg (merkleRoot w.cmIn0 w.bits0 w.sibs0 (b - 2)) (w.sibs0 (b - 2)) 1 := by
                    simp only [witBlockMsg, show b + 1 ≠ 1 from by omega, show b + 1 ≠ 2 from by omega,
                          show 3 ≤ b + 1 ∧ b + 1 ≤ 34 from by omega, show b + 1 - 3 = b - 2 from by omega, hbit1, and_self, ↓reduceIte]
                  rw [hmsg]; simp only [hhi, ↓reduceIte, merkleMsg, show ¬((1 : Nat) = 0) from by decide]
                  rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp
                · have hnot33 : ¬(b ≤ 33) := by omega
                  have hwb : witBit w (b + 1) = w.bits1 (b - 37) := by
                    simp only [witBit, show ¬(3 ≤ b + 1 ∧ b + 1 ≤ 34) from by omega,
                          show 38 ≤ b + 1 ∧ b + 1 ≤ 69 from by omega, show b + 1 - 38 = b - 37 from by omega, and_self, ↓reduceIte]
                  rw [hwb] at hbit1
                  have hmsg : witBlockMsg w (b + 1) =
                      merkleMsg (merkleRoot w.cmIn1 w.bits1 w.sibs1 (b - 37)) (w.sibs1 (b - 37)) 1 := by
                    simp only [witBlockMsg, show b + 1 ≠ 1 from by omega, show b + 1 ≠ 2 from by omega,
                          show ¬(3 ≤ b + 1 ∧ b + 1 ≤ 34) from by omega, show b + 1 ≠ 35 from by omega,
                          show b + 1 ≠ 36 from by omega, show b + 1 ≠ 37 from by omega,
                          show 38 ≤ b + 1 ∧ b + 1 ≤ 69 from by omega, show b + 1 - 38 = b - 37 from by omega, hbit1, and_self, ↓reduceIte]
                  rw [hmsg]; simp only [hnot33, ↓reduceIte, merkleMsg, show ¬((1 : Nat) = 0) from by decide]
                  rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp
          · by_cases hN : b = 34 ∨ b = 69
            · -- Nf(0) (b=34, nxt=35) or Nf(1) (b=69, nxt=70)
              have hnot7 : ¬(b = 70 ∨ b = 71) := by omega
              simp only [hA, hC, hM, hN, hnot7, ↓reduceIte, Int.zero_mul, Int.one_mul, Int.zero_add]
              have hsub0 : (canonicalRawTrace pi w).cell (r + 1) (COL_W + j) =
                  (if j = 0 then (TAG_NF : Int)
                   else if j ≤ 8 then (canonicalRawTrace pi w).cell (r + 1) (COL_SK + j - 1)
                   else if j = 9 then (canonicalRawTrace pi w).cell (r + 1) COL_POS
                   else if j ≤ 14 then (canonicalRawTrace pi w).cell (r + 1) (COL_RHO + j - 10)
                   else 0) := by
                rw [hnw]
                by_cases hj0 : j = 0
                · subst hj0; rcases hN with rfl | rfl <;> (simp [witBlockMsg]; decide)
                · by_cases hj8 : j ≤ 8
                  · simp only [hj0, hj8, ↓reduceIte]
                    have hcol : COL_SK + j - 1 = COL_SK + (j - 1) := by simp [COL_SK]; omega
                    rw [hnxt, hcol, canon_cell_SK w (b + 1) 0 (j - 1) hb1 hb72 (by omega) (by omega)]
                    have hjv : j = 1 ∨ j = 2 ∨ j = 3 ∨ j = 4 ∨ j = 5 ∨ j = 6 ∨ j = 7 ∨ j = 8 := by omega
                    rcases hN with rfl | rfl <;>
                      rcases hjv with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
                      simp [witBlockMsg, witSk]
                  · by_cases hj9 : j = 9
                    · subst hj9; simp only [show ¬(9 = 0) from by decide, show ¬(9 ≤ 8) from by decide, ↓reduceIte]
                      rw [hnxt, canon_cell_POS w (b + 1) 0 hb1 hb72 (by omega)]
                      rcases hN with rfl | rfl
                      · simp [witBlockMsg, witPos, w.hPos0]
                      · simp [witBlockMsg, witPos, w.hPos1]
                    · by_cases hj14 : j ≤ 14
                      · simp only [hj0, hj8, hj9, hj14, ↓reduceIte]
                        have hcol : COL_RHO + j - 10 = COL_RHO + (j - 10) := by simp [COL_RHO]; omega
                        rw [hnxt, hcol, canon_cell_RHO w (b + 1) 0 (j - 10) hb1 hb72 (by omega) (by omega)]
                        have hjv : j = 10 ∨ j = 11 ∨ j = 12 ∨ j = 13 ∨ j = 14 := by omega
                        rcases hN with rfl | rfl <;>
                          rcases hjv with rfl | rfl | rfl | rfl | rfl <;>
                          simp [witBlockMsg, witRho]
                      · have hj15 : j = 15 := by omega
                        subst hj15
                        rcases hN with rfl | rfl <;> simp [witBlockMsg]
              rw [hsub0, Int.sub_self]; simp
            · -- CmOut(0) (b=70, nxt=71) or CmOut(1) (b=71, nxt=72)
              have hO : b = 70 ∨ b = 71 := by omega
              simp only [hA, hC, hM, hN, hO, ↓reduceIte, Int.zero_mul, Int.one_mul, Int.zero_add, Int.add_zero]
              by_cases hj0 : j = 0
              · subst hj0; rw [hnw]
                rcases hO with rfl | rfl <;> (simp [witBlockMsg]; decide)
              · simp [hj0]
    · -- b ≥ 72: periodicVal 3..7 are all 0!
      unfold msgLoadTerm
      have h3 : periodicVal r 3 = 0 := by simp [periodicVal, hb_def]; omega
      have h4 : periodicVal r 4 = 0 := by simp [periodicVal, hb_def]; omega
      have h5 : periodicVal r 5 = 0 := by simp [periodicVal, hb_def]; omega
      have h6 : periodicVal r 6 = 0 := by simp [periodicVal, hb_def]; omega
      have h7 : periodicVal r 7 = 0 := by simp [periodicVal, hb_def]; omega
      simp [h3, h4, h5, h6, h7]
  · -- t ≠ 63: periodicVal 3..7 are all 0!
    unfold msgLoadTerm
    have h3 : periodicVal r 3 = 0 := by simp [periodicVal, ht_def, ht63]
    have h4 : periodicVal r 4 = 0 := by simp [periodicVal, ht_def, ht63]
    have h5 : periodicVal r 5 = 0 := by simp [periodicVal, ht_def, ht63]
    have h6 : periodicVal r 6 = 0 := by simp [periodicVal, ht_def, ht63]
    have h7 : periodicVal r 7 = 0 := by simp [periodicVal, ht_def, ht63]
    simp [h3, h4, h5, h6, h7]

-- ---- Part 9F: COMPLETENESS THEOREM (`valid_witness_satisfies_raw_air`) ----

/-- COMPLETENESS THEOREM:
    For ANY `pi : SpendPublicStmt` and ANY semantic witness `w : ValidSpendWitness pi`,
    the canonical `8,192 × 247` Goldilocks trace `canonicalRawTrace pi w` satisfies ALL 249
    live Rust extracted transition constraints (`RawAirTransitionsHold`) AND ALL boundary
    assertions (`RawBoundaryAssertions pi`). -/
theorem valid_witness_satisfies_raw_air
    (pi : SpendPublicStmt) (w : ValidSpendWitness pi) :
    RawAirTransitionsHold (canonicalRawTrace pi w) ∧
    RawBoundaryAssertions pi (canonicalRawTrace pi w) := by
  let T := canonicalRawTrace pi w
  have hdigs := canon_dig_equals_semantic w
  constructor
  · -- 1. Verify ALL 249 transition constraints on ALL 8,191 adjacent row pairs (r, r + 1)!
    intro r hr i hi
    rw [all_249_constraints_match_fips180_4_spec i hi]
    generalize hb_def : r / 64 = b
    generalize ht_def : r % 64 = t
    have hrt : r = b * 64 + t := by omega
    have ht64 : t < 64 := by rw [← ht_def]; exact Nat.mod_lt r (by decide)
    -- Helper: periodicVal on inactive rows (b = 0 ∧ t < 63, or b ≥ 73)
    have hRoundOrIv : (1 ≤ b ∧ b ≤ 72 ∧ t < 63) ∨ (b ≤ 71 ∧ t = 63) ∨
        (b = 0 ∧ t < 63) ∨ (b = 72 ∧ t = 63) ∨ (73 ≤ b) := by omega
    -- Dispatch by constraint group i ∈ 0..248:
    by_cases hi0 : i = 0
    · subst hi0
      by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
      · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
        rw [hrt]
        have hst_step : sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init =
            sha256Round (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init)
              K[t]! (sha256Schedule79 (witBlockMsg w b))[t]! := rfl
        have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
        let st1 := sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init
        have h0 := eval_fipsCon_0_round T (b * 64 + t) st1.a st1.b st1.c st1.e st1.f st1.g
          hp.2.1 hp.2.2.2.2.2.2.2.2.2.2.2.2.2
          (fun j hj => by rw [hr1]; exact canon_cell_A w b (t + 1) j hin.1 hin.2.1 (by omega) hj)
          (fun j hj => by rw [hr1]; exact canon_cell_AP w b (t + 1) j hin.1 hin.2.1 (by omega) hj)
          (fun j hj => by
            have hce : st1.c = (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).b := by
              rw [show st1 = sha256Round _ _ _ from hst_step]; rfl
            rw [hce]; exact canon_cell_AP w b t j hin.1 hin.2.1 ht64 hj)
          (fun j hj => by rw [hr1]; exact canon_cell_E w b (t + 1) j hin.1 hin.2.1 (by omega) hj)
          (fun j hj => by rw [hr1]; exact canon_cell_EP w b (t + 1) j hin.1 hin.2.1 (by omega) hj)
          (fun j hj => by
            have hge : st1.g = (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).f := by
              rw [show st1 = sha256Round _ _ _ from hst_step]; rfl
            rw [hge]; exact canon_cell_EP w b t j hin.1 hin.2.1 ht64 hj)
        rw [h0, hr1, canon_cell_AN w b (t + 1) hin.1 hin.2.1 (by omega),
            canon_carry3_CA w b (t + 1) hin.1 hin.2.1 (by omega),
            canon_cell_GWORD w b t hin.1 hin.2.1 ht64, hp.1,
            show COL_W = COL_W + 0 from rfl, canon_cell_W w b (t + 1) 0 hin.1 hin.2.1 (by omega) (by decide),
            Nat.add_zero]
        have hhe : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).g = st1.h := by
          rw [show st1 = sha256Round _ _ _ from hst_step]; rfl
        rw [hhe]
        have hdiv := int_div_mod_two32 (blkSa (witBlockMsg w b) (t + 1))
        have hsub : blkSa (witBlockMsg w b) (t + 1) % TWO32 + TWO32 * (blkSa (witBlockMsg w b) (t + 1) / TWO32) -
            ((st1.h.toNat : Int) + ((bigS1 st1.e).toNat : Int) + ((ch32 st1.e st1.f st1.g).toNat : Int) +
             ((K[t + 1]!).toNat : Int) + (((sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int) +
             ((bigS0 st1.a).toNat : Int) + ((maj32 st1.a st1.b st1.c).toNat : Int)) = 0 := by
          have : blkSa (witBlockMsg w b) (t + 1) =
            ((st1.h.toNat : Int) + ((bigS1 st1.e).toNat : Int) + ((ch32 st1.e st1.f st1.g).toNat : Int) +
             ((K[t + 1]!).toNat : Int) + (((sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int) +
             ((bigS0 st1.a).toNat : Int) + ((maj32 st1.a st1.b st1.c).toNat : Int)) := rfl
          omega
        rw [hsub]; rfl
      · have hp1 : periodicVal r 1 = 0 := by
          simp [periodicVal, hb_def, ht_def]; omega
        rw [eval_fipsCon_0_iv T r hp1]
        by_cases hiv : b ≤ 71 ∧ t = 63
        · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
          rw [hr1, canon_cell_AN w (b + 1) 0 (by omega) (by omega) (by omega),
              canon_carry3_CA w (b + 1) 0 (by omega) (by omega) (by omega),
              show COL_W = COL_W + 0 from rfl, canon_cell_W w (b + 1) 0 0 (by omega) (by omega) (by omega) (by decide),
              Nat.add_zero]
          have hdiv := int_div_mod_two32 (blkSa (witBlockMsg w (b + 1)) 0)
          have hsa0 : blkSa (witBlockMsg w (b + 1)) 0 =
              (k0aConst : Int) + (((sha256Schedule79 (witBlockMsg w (b + 1)))[0]!).toNat : Int) :=
            round0_sa_exact _
          have hsub : blkSa (witBlockMsg w (b + 1)) 0 % TWO32 + TWO32 * (blkSa (witBlockMsg w (b + 1)) 0 / TWO32) -
              (k0aConst : Int) - (((sha256Schedule79 (witBlockMsg w (b + 1)))[0]!).toNat : Int) = 0 := by omega
          rw [hsub, Int.mul_zero]; rfl
        · have hpiv0 : pIvVal r = 0 := by
            simp only [pIvVal, periodicVal, hb_def, ht_def]
            repeat (split <;> try omega)
          rw [hpiv0, Int.zero_mul]; rfl
    · by_cases hi1 : i = 1
      · subst hi1
        by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
        · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
          rw [hrt]
          have hst_step : sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init =
              sha256Round (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init)
                K[t]! (sha256Schedule79 (witBlockMsg w b))[t]! := rfl
          have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
          let st1 := sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init
          have h1 := eval_fipsCon_1_round T (b * 64 + t) st1.e st1.f st1.g
            hp.2.1 hp.2.2.2.2.2.2.2.2.2.2.2.2.2
            (fun j hj => by rw [hr1]; exact canon_cell_E w b (t + 1) j hin.1 hin.2.1 (by omega) hj)
            (fun j hj => by rw [hr1]; exact canon_cell_EP w b (t + 1) j hin.1 hin.2.1 (by omega) hj)
            (fun j hj => by
              have hge : st1.g = (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).f := by
                rw [show st1 = sha256Round _ _ _ from hst_step]; rfl
              rw [hge]; exact canon_cell_EP w b t j hin.1 hin.2.1 ht64 hj)
          rw [h1, hr1, canon_cell_EN w b (t + 1) hin.1 hin.2.1 (by omega),
              canon_carry3_CE w b (t + 1) hin.1 hin.2.1 (by omega),
              canon_cell_CWORD w b t hin.1 hin.2.1 ht64,
              canon_cell_GWORD w b t hin.1 hin.2.1 ht64, hp.1,
              show COL_W = COL_W + 0 from rfl, canon_cell_W w b (t + 1) 0 hin.1 hin.2.1 (by omega) (by decide),
              Nat.add_zero]
          have hde : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).c = st1.d := by
            rw [show st1 = sha256Round _ _ _ from hst_step]; rfl
          have hhe : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).g = st1.h := by
            rw [show st1 = sha256Round _ _ _ from hst_step]; rfl
          rw [hde, hhe]
          have hdiv := int_div_mod_two32 (blkSe (witBlockMsg w b) (t + 1))
          have hsub : blkSe (witBlockMsg w b) (t + 1) % TWO32 + TWO32 * (blkSe (witBlockMsg w b) (t + 1) / TWO32) -
              ((st1.d.toNat : Int) +
                ((st1.h.toNat : Int) + ((bigS1 st1.e).toNat : Int) + ((ch32 st1.e st1.f st1.g).toNat : Int) +
                 ((K[t + 1]!).toNat : Int) + (((sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int))) = 0 := by
            have : blkSe (witBlockMsg w b) (t + 1) =
              ((st1.d.toNat : Int) +
                ((st1.h.toNat : Int) + ((bigS1 st1.e).toNat : Int) + ((ch32 st1.e st1.f st1.g).toNat : Int) +
                 ((K[t + 1]!).toNat : Int) + (((sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int))) := rfl
            omega
          rw [hsub]; rfl
        · have hp1 : periodicVal r 1 = 0 := by
            simp [periodicVal, hb_def, ht_def]; omega
          rw [eval_fipsCon_1_iv T r hp1]
          by_cases hiv : b ≤ 71 ∧ t = 63
          · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
            rw [hr1, canon_cell_EN w (b + 1) 0 (by omega) (by omega) (by omega),
                canon_carry3_CE w (b + 1) 0 (by omega) (by omega) (by omega),
                show COL_W = COL_W + 0 from rfl, canon_cell_W w (b + 1) 0 0 (by omega) (by omega) (by omega) (by decide),
                Nat.add_zero]
            have hdiv := int_div_mod_two32 (blkSe (witBlockMsg w (b + 1)) 0)
            have hse0 : blkSe (witBlockMsg w (b + 1)) 0 =
                (k0eConst : Int) + (((sha256Schedule79 (witBlockMsg w (b + 1)))[0]!).toNat : Int) :=
              round0_se_exact _
            have hsub : blkSe (witBlockMsg w (b + 1)) 0 % TWO32 + TWO32 * (blkSe (witBlockMsg w (b + 1)) 0 / TWO32) -
                (k0eConst : Int) - (((sha256Schedule79 (witBlockMsg w (b + 1)))[0]!).toNat : Int) = 0 := by omega
            rw [hsub, Int.mul_zero]; rfl
          · have hpiv0 : pIvVal r = 0 := by
              simp only [pIvVal, periodicVal, hb_def, ht_def]
              repeat (split <;> try omega)
            rw [hpiv0, Int.zero_mul]; rfl
      · by_cases hi2 : i = 2
        · subst hi2; rw [eval_fipsCon_2]
          by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
          · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
            rw [hrt, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero]
            have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
            rw [hr1, canon_cell_AN w b t hin.1 hin.2.1 ht64, blkSa_mod_eq_next_a]
            have hpk : packBits (fun j => T.cell (b * 64 + (t + 1)) (COL_A + j)) 32 =
                ((sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init).a.toNat : Int) := by
              rw [packBits_congr _ _ 32 (fun j hj => canon_cell_A w b (t + 1) j hin.1 hin.2.1 (by omega) hj)]
              exact packBits_u32Bit _
            rw [hpk, Int.sub_self]; rfl
          · have hp1 : periodicVal r 1 = 0 := by
              simp [periodicVal, hb_def, ht_def]; omega
            rw [hp1, Int.zero_mul, Int.zero_add]
            by_cases hiv : b ≤ 71 ∧ t = 63
            · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
              rw [hr1]
              have hpk : packBits (fun j => T.cell ((b + 1) * 64 + 0) (COL_A + j)) 32 = (ivNat 0 : Int) := by
                rw [packBits_congr _ _ 32 (fun j hj => canon_cell_A w (b + 1) 0 j (by omega) (by omega) (by omega) hj),
                    packBits_u32Bit]
                exact congrArg Int.ofNat (iv_toNat_eq_ivNat 0 (by decide))
              rw [hpk, Int.sub_self, Int.mul_zero]; rfl
            · have hpiv0 : pIvVal r = 0 := by
                simp only [pIvVal, periodicVal, hb_def, ht_def]
                repeat (split <;> try omega)
              rw [hpiv0, Int.zero_mul]; rfl
        · by_cases hi3 : i = 3
          · subst hi3; rw [eval_fipsCon_3]
            by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
            · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
              rw [hrt, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero]
              have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
              rw [hr1, canon_cell_EN w b t hin.1 hin.2.1 ht64, blkSe_mod_eq_next_e]
              have hpk : packBits (fun j => T.cell (b * 64 + (t + 1)) (COL_E + j)) 32 =
                  ((sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init).e.toNat : Int) := by
                rw [packBits_congr _ _ 32 (fun j hj => canon_cell_E w b (t + 1) j hin.1 hin.2.1 (by omega) hj)]
                exact packBits_u32Bit _
              rw [hpk, Int.sub_self]; rfl
            · have hp1 : periodicVal r 1 = 0 := by
                simp [periodicVal, hb_def, ht_def]; omega
              rw [hp1, Int.zero_mul, Int.zero_add]
              by_cases hiv : b ≤ 71 ∧ t = 63
              · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                rw [hr1]
                have hpk : packBits (fun j => T.cell ((b + 1) * 64 + 0) (COL_E + j)) 32 = (ivNat 4 : Int) := by
                  rw [packBits_congr _ _ 32 (fun j hj => canon_cell_E w (b + 1) 0 j (by omega) (by omega) (by omega) hj),
                      packBits_u32Bit]
                  exact congrArg Int.ofNat (iv_toNat_eq_ivNat 4 (by decide))
                rw [hpk, Int.sub_self, Int.mul_zero]; rfl
              · have hpiv0 : pIvVal r = 0 := by
                  simp only [pIvVal, periodicVal, hb_def, ht_def]
                  repeat (split <;> try omega)
                rw [hpiv0, Int.zero_mul]; rfl
          · by_cases hi36 : i < 36
            · have heq : i = 4 + (i - 4) := by omega
              rw [heq, eval_fipsCon_ap T r (i - 4) (by omega)]
              by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
              · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
                rw [hrt, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero]
                have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                rw [hr1, canon_cell_AP w b (t + 1) (i - 4) hin.1 hin.2.1 (by omega) (by omega),
                    canon_cell_A w b t (i - 4) hin.1 hin.2.1 ht64 (by omega)]
                have hbe : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init).b =
                    (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).a := rfl
                rw [hbe, Int.sub_self]; rfl
              · have hp1 : periodicVal r 1 = 0 := by
                  simp [periodicVal, hb_def, ht_def]; omega
                rw [hp1, Int.zero_mul, Int.zero_add]
                by_cases hiv : b ≤ 71 ∧ t = 63
                · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                  rw [hr1, canon_cell_AP w (b + 1) 0 (i - 4) (by omega) (by omega) (by omega) (by omega)]
                  have hbit := u32Bit_iv_eq 1 (i - 4) (by decide)
                  simp only [sha256RunRounds, sha256Init]
                  rw [hbit, Int.sub_self, Int.mul_zero]; rfl
                · have hpiv0 : pIvVal r = 0 := by
                    simp only [pIvVal, periodicVal, hb_def, ht_def]
                    repeat (split <;> try omega)
                  rw [hpiv0, Int.zero_mul]; rfl
            · by_cases hi68 : i < 68
              · have heq : i = 36 + (i - 36) := by omega
                rw [heq, eval_fipsCon_ep T r (i - 36) (by omega)]
                by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
                  rw [hrt, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero]
                  have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                  rw [hr1, canon_cell_EP w b (t + 1) (i - 36) hin.1 hin.2.1 (by omega) (by omega),
                      canon_cell_E w b t (i - 36) hin.1 hin.2.1 ht64 (by omega)]
                  have hfe : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init).f =
                      (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).e := rfl
                  rw [hfe, Int.sub_self]; rfl
                · have hp1 : periodicVal r 1 = 0 := by
                    simp [periodicVal, hb_def, ht_def]; omega
                  rw [hp1, Int.zero_mul, Int.zero_add]
                  by_cases hiv : b ≤ 71 ∧ t = 63
                  · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                    rw [hr1, canon_cell_EP w (b + 1) 0 (i - 36) (by omega) (by omega) (by omega) (by omega)]
                    have hbit := u32Bit_iv_eq 5 (i - 36) (by decide)
                    simp only [sha256RunRounds, sha256Init]
                    rw [hbit, Int.sub_self, Int.mul_zero]; rfl
                  · have hpiv0 : pIvVal r = 0 := by
                      simp only [pIvVal, periodicVal, hb_def, ht_def]
                      repeat (split <;> try omega)
                    rw [hpiv0, Int.zero_mul]; rfl
              · by_cases hi68e : i = 68
                · subst hi68e; rw [eval_fipsCon_68]
                  by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                  · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
                    rw [hrt, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero]
                    have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                    rw [hr1, canon_cell_CWORD w b (t + 1) hin.1 hin.2.1 (by omega)]
                    have hpk : packBits (fun j => T.cell (b * 64 + t) (COL_AP + j)) 32 =
                        ((sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).b.toNat : Int) := by
                      rw [packBits_congr _ _ 32 (fun j hj => canon_cell_AP w b t j hin.1 hin.2.1 ht64 hj)]
                      exact packBits_u32Bit _
                    have hce : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init).c =
                        (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).b := rfl
                    rw [hpk, hce, Int.sub_self]; rfl
                  · have hp1 : periodicVal r 1 = 0 := by
                      simp [periodicVal, hb_def, ht_def]; omega
                    rw [hp1, Int.zero_mul, Int.zero_add]
                    by_cases hiv : b ≤ 71 ∧ t = 63
                    · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                      rw [hr1, canon_cell_CWORD w (b + 1) 0 (by omega) (by omega) (by omega)]
                      have h2 : ((IV[2]!).toNat : Int) = (ivNat 2 : Int) := by decide
                      simp only [sha256RunRounds, sha256Init]
                      rw [h2, Int.sub_self, Int.mul_zero]; rfl
                    · have hpiv0 : pIvVal r = 0 := by
                        simp only [pIvVal, periodicVal, hb_def, ht_def]
                        repeat (split <;> try omega)
                      rw [hpiv0, Int.zero_mul]; rfl
                · by_cases hi69 : i = 69
                  · subst hi69; rw [eval_fipsCon_69]
                    by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                    · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
                      rw [hrt, hp.2.1, hp.2.2.2.2.2.2.2.2.2.2.2.2.2, Int.one_mul, Int.zero_mul, Int.add_zero]
                      have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                      rw [hr1, canon_cell_GWORD w b (t + 1) hin.1 hin.2.1 (by omega)]
                      have hpk : packBits (fun j => T.cell (b * 64 + t) (COL_EP + j)) 32 =
                          ((sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).f.toNat : Int) := by
                        rw [packBits_congr _ _ 32 (fun j hj => canon_cell_EP w b t j hin.1 hin.2.1 ht64 hj)]
                        exact packBits_u32Bit _
                      have hge : (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) (t + 1) sha256Init).g =
                          (sha256RunRounds (sha256Schedule79 (witBlockMsg w b)) t sha256Init).f := rfl
                      rw [hpk, hge, Int.sub_self]; rfl
                    · have hp1 : periodicVal r 1 = 0 := by
                        simp [periodicVal, hb_def, ht_def]; omega
                      rw [hp1, Int.zero_mul, Int.zero_add]
                      by_cases hiv : b ≤ 71 ∧ t = 63
                      · have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                        rw [hr1, canon_cell_GWORD w (b + 1) 0 (by omega) (by omega) (by omega)]
                        have h6 : ((IV[6]!).toNat : Int) = (ivNat 6 : Int) := by decide
                        simp only [sha256RunRounds, sha256Init]
                        rw [h6, Int.sub_self, Int.mul_zero]; rfl
                      · have hpiv0 : pIvVal r = 0 := by
                          simp only [pIvVal, periodicVal, hb_def, ht_def]
                          repeat (split <;> try omega)
                        rw [hpiv0, Int.zero_mul]; rfl
                  · by_cases hi85 : i < 85
                    · have heq : i = 70 + (i - 70) := by omega
                      rw [heq, eval_fipsCon_win_lt15 T r (i - 70) (by omega),
                          canon_msgLoadTerm_zero w r (i - 70) hr (by omega), Int.add_zero]
                      by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                      · have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                        rw [hrt, hr1, canon_cell_W w b (t + 1) (i - 70) hin.1 hin.2.1 (by omega) (by omega),
                            show COL_W + (i - 70) + 1 = COL_W + (i - 70 + 1) from by omega,
                            canon_cell_W w b t (i - 70 + 1) hin.1 hin.2.1 ht64 (by omega),
                            show t + 1 + (i - 70) = t + (i - 70 + 1) from by omega, Int.sub_self, Int.mul_zero]; rfl
                      · have hp1 : periodicVal r 1 = 0 := by
                          simp [periodicVal, hb_def, ht_def]; omega
                        rw [hp1, Int.zero_mul]; rfl
                    · by_cases hi85e : i = 85
                      · subst hi85e
                        by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                        · have hp := periodic_inner b t hin.1 hin.2.1 hin.2.2
                          rw [hrt]
                          have h85 := eval_fipsCon_85_sched T (b * 64 + t)
                            ((sha256Schedule79 (witBlockMsg w b))[t + 1]!)
                            ((sha256Schedule79 (witBlockMsg w b))[t + 14]!)
                            hp.2.1 hp.2.2.2.1 hp.2.2.2.2.1 hp.2.2.2.2.2.1 hp.2.2.2.2.2.2.1 hp.2.2.2.2.2.2.2.1
                            (fun j hj => canon_cell_X1_inner w b t j hin.1 hin.2.1 hin.2.2 hj)
                            (fun j hj => canon_cell_X14_inner w b t j hin.1 hin.2.1 hin.2.2 hj)
                          have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                          rw [h85, hr1, canon_cell_W w b (t + 1) 15 hin.1 hin.2.1 (by omega) (by decide),
                              canon_cwc_reconstruct w b t hin.1 hin.2.1 hin.2.2,
                              canon_cell_W w b t 9 hin.1 hin.2.1 ht64 (by decide),
                              show COL_W = COL_W + 0 from rfl,
                              canon_cell_W w b t 0 hin.1 hin.2.1 ht64 (by decide),
                              show t + 0 = t from Nat.add_zero t,
                              show t + 1 + 15 = t + 16 from by omega,
                              ← blkSw_mod_eq_w16 (witBlockMsg w b) (witBlockMsg_size w b) t hin.2.2]
                          have hdiv := int_div_mod_two32 (blkSw (witBlockMsg w b) t)
                          have hsub : blkSw (witBlockMsg w b) t % TWO32 + TWO32 * (blkSw (witBlockMsg w b) t / TWO32) -
                              (((smallS1 (sha256Schedule79 (witBlockMsg w b))[t + 14]!).toNat : Int) +
                               (((sha256Schedule79 (witBlockMsg w b))[t + 9]!).toNat : Int) +
                               ((smallS0 (sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int) +
                               (((sha256Schedule79 (witBlockMsg w b))[t]!).toNat : Int)) = 0 := by
                            have : blkSw (witBlockMsg w b) t =
                              (((smallS1 (sha256Schedule79 (witBlockMsg w b))[t + 14]!).toNat : Int) +
                               (((sha256Schedule79 (witBlockMsg w b))[t + 9]!).toNat : Int) +
                               ((smallS0 (sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int) +
                               (((sha256Schedule79 (witBlockMsg w b))[t]!).toNat : Int)) := rfl
                            omega
                          rw [hsub]; rfl
                        · have hp1 : periodicVal r 1 = 0 := by
                            simp [periodicVal, hb_def, ht_def]; omega
                          rw [eval_fipsCon_85_load T r hp1, canon_msgLoadTerm_zero w r 15 hr (by decide)]; rfl
                      · by_cases hi86 : i = 86
                        · subst hi86; rw [eval_fipsCon_86]
                          by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                          · rw [hrt, canon_cell_W w b t 1 hin.1 hin.2.1 ht64 (by decide)]
                            have hpk : packBits (fun j => T.cell (b * 64 + t) (COL_X1 + j)) 32 =
                                (((sha256Schedule79 (witBlockMsg w b))[t + 1]!).toNat : Int) := by
                              rw [packBits_congr _ _ 32 (fun j hj => canon_cell_X1_inner w b t j hin.1 hin.2.1 hin.2.2 hj)]
                              exact packBits_u32Bit _
                            rw [hpk, Int.sub_self, Int.mul_zero]; rfl
                          · have hp1 : periodicVal r 1 = 0 := by
                              simp [periodicVal, hb_def, ht_def]; omega
                            rw [hp1, Int.zero_mul]; rfl
                        · by_cases hi87 : i = 87
                          · subst hi87; rw [eval_fipsCon_87]
                            by_cases hin : 1 ≤ b ∧ b ≤ 72 ∧ t < 63
                            · rw [hrt, canon_cell_W w b t 14 hin.1 hin.2.1 ht64 (by decide)]
                              have hpk : packBits (fun j => T.cell (b * 64 + t) (COL_X14 + j)) 32 =
                                  (((sha256Schedule79 (witBlockMsg w b))[t + 14]!).toNat : Int) := by
                                rw [packBits_congr _ _ 32 (fun j hj => canon_cell_X14_inner w b t j hin.1 hin.2.1 hin.2.2 hj)]
                                exact packBits_u32Bit _
                              rw [hpk, Int.sub_self, Int.mul_zero]; rfl
                            · have hp1 : periodicVal r 1 = 0 := by
                                simp [periodicVal, hb_def, ht_def]; omega
                              rw [hp1, Int.zero_mul]; rfl
                          · by_cases hi96 : i < 96
                            · have heq : i = 88 + (i - 88) := by omega
                              rw [heq, eval_fipsCon_dig T r (i - 88) (by omega)]
                              by_cases hlast : 1 ≤ b ∧ b ≤ 72 ∧ t = 63
                              · rw [hrt, hlast.2.2, canon_cell_DIG_last w b (i - 88) hlast.1 hlast.2.1 (by omega),
                                    ← blkDig_eq_compress (witBlockMsg w b) (witBlockMsg_size w b) (i - 88) (by omega),
                                    canon_cell_X1_last w b (i - 88) hlast.1 hlast.2.1 (by omega)]
                                have hdv : digOutVal T (b * 64 + 63) (i - 88) = blkDigOut (witBlockMsg w b) (i - 88) := by
                                  have hjv : i - 88 = 0 ∨ i - 88 = 1 ∨ i - 88 = 2 ∨ i - 88 = 3 ∨
                                             i - 88 = 4 ∨ i - 88 = 5 ∨ i - 88 = 6 ∨ i - 88 = 7 := by omega
                                  rcases hjv with h | h | h | h | h | h | h | h <;> rw [h]
                                  · exact canon_cell_AN w b 63 hlast.1 hlast.2.1 (by omega)
                                  · simp only [digOutVal, blkDigOut]
                                    rw [packBits_congr _ _ 32 (fun k hk => canon_cell_A w b 63 k hlast.1 hlast.2.1 (by omega) hk)]
                                    exact packBits_u32Bit _
                                  · simp only [digOutVal, blkDigOut]
                                    rw [packBits_congr _ _ 32 (fun k hk => canon_cell_AP w b 63 k hlast.1 hlast.2.1 (by omega) hk)]
                                    exact packBits_u32Bit _
                                  · exact canon_cell_CWORD w b 63 hlast.1 hlast.2.1 (by omega)
                                  · exact canon_cell_EN w b 63 hlast.1 hlast.2.1 (by omega)
                                  · simp only [digOutVal, blkDigOut]
                                    rw [packBits_congr _ _ 32 (fun k hk => canon_cell_E w b 63 k hlast.1 hlast.2.1 (by omega) hk)]
                                    exact packBits_u32Bit _
                                  · simp only [digOutVal, blkDigOut]
                                    rw [packBits_congr _ _ 32 (fun k hk => canon_cell_EP w b 63 k hlast.1 hlast.2.1 (by omega) hk)]
                                    exact packBits_u32Bit _
                                  · exact canon_cell_GWORD w b 63 hlast.1 hlast.2.1 (by omega)
                                rw [hdv]
                                have hdiv := int_div_mod_two32 ((ivNat (i - 88) : Int) + blkDigOut (witBlockMsg w b) (i - 88))
                                have hsub : ((ivNat (i - 88) : Int) + blkDigOut (witBlockMsg w b) (i - 88)) % TWO32 +
                                    TWO32 * (((ivNat (i - 88) : Int) + blkDigOut (witBlockMsg w b) (i - 88)) / TWO32) -
                                    (ivNat (i - 88) : Int) - blkDigOut (witBlockMsg w b) (i - 88) = 0 := by omega
                                rw [hsub, Int.mul_zero]; rfl
                              · have hp2 : periodicVal r 2 = 0 := by
                                  simp [periodicVal, hb_def, ht_def]; omega
                                rw [hp2, Int.zero_mul]; rfl
                            · by_cases hi224 : i < 224
                              · have heq : i = 96 + (i - 96) := by omega
                                rw [heq, eval_fipsCon_bool128 T r (i - 96) (by omega)]
                                by_cases hact : 1 ≤ b ∧ b ≤ 72
                                · rw [hrt]
                                  rcases (canon_bool_cell_zero w b t hact.1 hact.2 ht64).1 (i - 96) (by omega) with hv | hv <;>
                                    (rw [hv]; simp)
                                · have hp10 : periodicVal r 10 = 0 := by
                                    simp [periodicVal, hb_def]; omega
                                  rw [hp10, Int.zero_mul]; rfl
                              · by_cases hi233 : i < 233
                                · have heq : i = 224 + (i - 224) := by omega
                                  rw [heq, eval_fipsCon_bool9 T r (i - 224) (by omega)]
                                  by_cases hact : 1 ≤ b ∧ b ≤ 72
                                  · rw [hrt]
                                    rcases (canon_bool_cell_zero w b t hact.1 hact.2 ht64).2 (i - 224) (by omega) with hv | hv <;>
                                      (rw [hv]; simp)
                                  · have hp10 : periodicVal r 10 = 0 := by
                                      simp [periodicVal, hb_def]; omega
                                    rw [hp10, Int.zero_mul]; rfl
                                · by_cases hi241 : i < 241
                                  · have heq : i = 233 + (i - 233) := by omega
                                    rw [heq, eval_fipsCon_sk T r (i - 233) (by omega)]
                                    by_cases hact : 64 ≤ r ∧ r < 4671
                                    · by_cases hres : t = 63 ∧ b = 35
                                      · have hp12 : periodicVal r 12 = 0 := by
                                          simp [periodicVal, hb_def, ht_def, hres]
                                        rw [hp12, Int.zero_mul]; rfl
                                      · have hb1 : 1 ≤ b := by omega
                                        have hb72 : b ≤ 72 := by omega
                                        have hr1b1 : 1 ≤ (r + 1) / 64 := by omega
                                        have hr1b72 : (r + 1) / 64 ≤ 72 := by omega
                                        have hr1eq : r + 1 = (r + 1) / 64 * 64 + (r + 1) % 64 := by omega
                                        rw [hrt, canon_cell_SK w b t (i - 233) hb1 hb72 ht64 (by omega),
                                            ← hrt, hr1eq, canon_cell_SK w ((r + 1) / 64) ((r + 1) % 64) (i - 233)
                                              hr1b1 hr1b72 (Nat.mod_lt _ (by decide)) (by omega)]
                                        have hsame : witSk w ((r + 1) / 64) = witSk w b := by
                                          unfold witSk
                                          by_cases hb35 : b ≤ 35
                                          · have hb35' : (r + 1) / 64 ≤ 35 := by omega
                                            simp [hb35, hb35']
                                          · have hb35' : ¬((r + 1) / 64 ≤ 35) := by omega
                                            simp [hb35, hb35']
                                        rw [hsame, Int.sub_self, Int.mul_zero]; rfl
                                    · have hp12 : periodicVal r 12 = 0 := by
                                        simp [periodicVal, hact]
                                      rw [hp12, Int.zero_mul]; rfl
                                  · by_cases hi246 : i < 246
                                    · have heq : i = 241 + (i - 241) := by omega
                                      rw [heq, eval_fipsCon_rho T r (i - 241) (by omega)]
                                      by_cases hact : 64 ≤ r ∧ r < 4671
                                      · by_cases hres : t = 63 ∧ (b = 1 ∨ b = 36)
                                        · have hp13 : periodicVal r 13 = 0 := by
                                            simp [periodicVal, hb_def, ht_def, hres]
                                          rw [hp13, Int.zero_mul]; rfl
                                        · have hb1 : 1 ≤ b := by omega
                                          have hb72 : b ≤ 72 := by omega
                                          have hr1b1 : 1 ≤ (r + 1) / 64 := by omega
                                          have hr1b72 : (r + 1) / 64 ≤ 72 := by omega
                                          have hr1eq : r + 1 = (r + 1) / 64 * 64 + (r + 1) % 64 := by omega
                                          rw [hrt, canon_cell_RHO w b t (i - 241) hb1 hb72 ht64 (by omega),
                                              ← hrt, hr1eq, canon_cell_RHO w ((r + 1) / 64) ((r + 1) % 64) (i - 241)
                                                hr1b1 hr1b72 (Nat.mod_lt _ (by decide)) (by omega)]
                                          have hsame : witRho w ((r + 1) / 64) = witRho w b := by
                                            unfold witRho
                                            by_cases hle1 : b ≤ 1
                                            · have hle1' : (r + 1) / 64 ≤ 1 := by omega
                                              simp [hle1, hle1']
                                            · have hle1' : ¬((r + 1) / 64 ≤ 1) := by omega
                                              by_cases hle36 : b ≤ 36
                                              · have hle36' : (r + 1) / 64 ≤ 36 := by omega
                                                simp [hle1, hle1', hle36, hle36']
                                              · have hle36' : ¬((r + 1) / 64 ≤ 36) := by omega
                                                simp [hle1, hle1', hle36, hle36']
                                          rw [hsame, Int.sub_self, Int.mul_zero]; rfl
                                      · have hp13 : periodicVal r 13 = 0 := by
                                          simp [periodicVal, hact]
                                        rw [hp13, Int.zero_mul]; rfl
                                    · by_cases hi246e : i = 246
                                      · subst hi246e; rw [eval_fipsCon_246]
                                        by_cases hact : 64 ≤ r ∧ r < 4671
                                        · have hb1 : 1 ≤ b := by omega
                                          have hb72 : b ≤ 72 := by omega
                                          have hp11 : periodicVal r 11 = 1 := by simp [periodicVal, hact]
                                          by_cases ht63 : t < 63
                                          · have hp := periodic_inner b t hb1 hb72 ht63
                                            have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                                            rw [hrt, hp.2.2.2.2.2.2.2.2.1, hp.2.2.2.2.2.2.2.2.2.2.1,
                                                hp.2.2.2.2.2.2.2.2.2.2.2.1, hr1,
                                                canon_cell_POS w b (t + 1) hb1 hb72 (by omega),
                                                canon_cell_POS w b t hb1 hb72 ht64]
                                            simp
                                          · have ht63e : t = 63 := by omega
                                            have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                                            rw [hp11, Int.one_mul, hr1,
                                                canon_cell_POS w (b + 1) 0 (by omega) (by omega) (by omega),
                                                canon_cell_BIT w (b + 1) 0 (by omega) (by omega) (by omega),
                                                hrt, ht63e, canon_cell_POS w b 63 hb1 hb72 (by omega),
                                                ← ht63e, ← hrt]
                                            simp only [↓reduceIte]
                                            by_cases hb35 : b = 35
                                            · have hp12 : periodicVal r 12 = 0 := by
                                                simp [periodicVal, hb_def, ht_def, ht63e, hb35]
                                              have hp8 : periodicVal r 8 = 0 := by
                                                simp [periodicVal, hb_def, hb35]
                                              rw [hp12, hp8, hb35]; simp [witPos]
                                            · have hp12 : periodicVal r 12 = 1 := by
                                                simp [periodicVal, hact, hb_def, ht_def, ht63e, hb35, show b ≠ 0 from by omega]
                                              rw [hp12, Int.one_mul]
                                              by_cases hm0 : 2 ≤ b ∧ b ≤ 33
                                              · have hp8 : periodicVal r 8 = ((2 ^ (b - 2) : Nat) : Int) := by
                                                  simp [periodicVal, hb_def, ht_def, ht63e, hm0]
                                                rw [hp8]
                                                have hwp : witPos w (b + 1) = witPos w b + witBit w (b + 1) * 2 ^ (b - 2) := by
                                                  unfold witPos witBit
                                                  by_cases hb2 : b = 2
                                                  · subst hb2; simp [posAcc]
                                                  · simp only [show ¬(b + 1 ≤ 2) from by omega, show b + 1 ≤ 35 from by omega,
                                                      show ¬(b ≤ 2) from by omega, show b ≤ 35 from by omega,
                                                      show 3 ≤ b + 1 ∧ b + 1 ≤ 34 from by omega, and_self, ↓reduceIte,
                                                      show b + 1 - 2 = (b - 2) + 1 from by omega,
                                                      show b + 1 - 3 = b - 2 from by omega]
                                                    rw [Nat.min_eq_left (by omega), Nat.min_eq_left (by omega)]; rfl
                                                rw [hwp]
                                                have hsub : ((witPos w b + witBit w (b + 1) * 2 ^ (b - 2) : Nat) : Int) -
                                                    (witPos w b : Int) - ((2 ^ (b - 2) : Nat) : Int) * (witBit w (b + 1) : Int) = 0 := by
                                                  rw [Int.natCast_add, Int.natCast_mul, Int.mul_comm ((witBit w (b + 1) : Nat) : Int)]; omega
                                                rw [hsub]; rfl
                                              · by_cases hm1 : 37 ≤ b ∧ b ≤ 68
                                                · have hp8 : periodicVal r 8 = ((2 ^ (b - 37) : Nat) : Int) := by
                                                    simp [periodicVal, hb_def, ht_def, ht63e, hm0, hm1]
                                                  rw [hp8]
                                                  have hwp : witPos w (b + 1) = witPos w b + witBit w (b + 1) * 2 ^ (b - 37) := by
                                                    unfold witPos witBit
                                                    by_cases hb37 : b = 37
                                                    · subst hb37; simp [posAcc]
                                                    · simp only [show ¬(b + 1 ≤ 2) from by omega, show ¬(b + 1 ≤ 35) from by omega,
                                                        show ¬(b + 1 ≤ 37) from by omega, show ¬(b ≤ 2) from by omega,
                                                        show ¬(b ≤ 35) from by omega, show ¬(b ≤ 37) from by omega,
                                                        show ¬(3 ≤ b + 1 ∧ b + 1 ≤ 34) from by omega,
                                                        show 38 ≤ b + 1 ∧ b + 1 ≤ 69 from by omega, and_self, ↓reduceIte,
                                                        show b + 1 - 37 = (b - 37) + 1 from by omega,
                                                        show b + 1 - 38 = b - 37 from by omega]
                                                      rw [Nat.min_eq_left (by omega), Nat.min_eq_left (by omega)]; rfl
                                                  rw [hwp]
                                                  have hsub : ((witPos w b + witBit w (b + 1) * 2 ^ (b - 37) : Nat) : Int) -
                                                      (witPos w b : Int) - ((2 ^ (b - 37) : Nat) : Int) * (witBit w (b + 1) : Int) = 0 := by
                                                    rw [Int.natCast_add, Int.natCast_mul, Int.mul_comm ((witBit w (b + 1) : Nat) : Int)]; omega
                                                  rw [hsub]; rfl
                                                · have hp8 : periodicVal r 8 = 0 := by
                                                    simp [periodicVal, hb_def, ht_def, ht63e, hm0, hm1]
                                                  rw [hp8, Int.zero_mul, Int.sub_zero]
                                                  have hwp : witPos w (b + 1) = witPos w b := by
                                                    have : b = 1 ∨ b = 34 ∨ b = 36 ∨ b = 69 ∨ b = 70 ∨ b = 71 := by omega
                                                    rcases this with rfl | rfl | rfl | rfl | rfl | rfl <;> simp [witPos]
                                                  rw [hwp, Int.sub_self]; rfl
                                        · have hp11 : periodicVal r 11 = 0 := by simp [periodicVal, hact]
                                          have hp12 : periodicVal r 12 = 0 := by simp [periodicVal, hact]
                                          have hp8 : periodicVal r 8 = 0 := by
                                            simp [periodicVal, hb_def, ht_def]; omega
                                          rw [hp11, hp12, hp8]; simp
                                      · by_cases hi247 : i = 247
                                        · subst hi247; rw [eval_fipsCon_247]
                                          by_cases hact : 64 ≤ r ∧ r < 4671
                                          · have hb1 : 1 ≤ b := by omega
                                            have hb72 : b ≤ 72 := by omega
                                            have hp11 : periodicVal r 11 = 1 := by simp [periodicVal, hact]
                                            by_cases ht63 : t < 63
                                            · have hp := periodic_inner b t hb1 hb72 ht63
                                              have hr1 : b * 64 + t + 1 = b * 64 + (t + 1) := by omega
                                              rw [hrt, hp.2.2.2.2.1, hp.2.2.2.2.2.2.2.1, hp.2.2.2.2.2.2.2.2.2.2.1, hr1,
                                                  canon_cell_BAL w b (t + 1) hb1 hb72 (by omega),
                                                  canon_cell_BAL w b t hb1 hb72 ht64]
                                              simp
                                            · have ht63e : t = 63 := by omega
                                              have hr1 : r + 1 = (b + 1) * 64 + 0 := by omega
                                              rw [hp11, Int.one_mul, hr1,
                                                  canon_cell_BAL w (b + 1) 0 (by omega) (by omega) (by omega),
                                                  canon_cell_W w (b + 1) 0 9 (by omega) (by omega) (by omega) (by decide),
                                                  canon_cell_W w (b + 1) 0 10 (by omega) (by omega) (by omega) (by decide),
                                                  Nat.zero_add, sha256Schedule79_init _ (witBlockMsg_size w (b + 1)) 9 (by decide),
                                                  sha256Schedule79_init _ (witBlockMsg_size w (b + 1)) 10 (by decide),
                                                  hrt, ht63e, canon_cell_BAL w b 63 hb1 hb72 (by omega),
                                                  ← ht63e, ← hrt]
                                              have hbal_mod :
                                                  (signedField (witBalInt w (b + 1)) - signedField (witBalInt w b)) % P =
                                                  (witBalInt w (b + 1) - witBalInt w b) % P := by
                                                rw [Int.sub_emod, signedField_emod_P, signedField_emod_P, ← Int.sub_emod]
                                              rw [Int.add_emod, Int.sub_emod, hbal_mod, ← Int.sub_emod, ← Int.add_emod]
                                              by_cases hc : b = 1 ∨ b = 36
                                              · have hp4 : periodicVal r 4 = 1 := by
                                                  simp [periodicVal, hb_def, ht_def, ht63e, hc]
                                                have hp7 : periodicVal r 7 = 0 := by
                                                  simp [periodicVal, hb_def, ht_def, ht63e]; omega
                                                rw [hp4, hp7, Int.one_mul, Int.zero_mul, Int.add_zero]
                                                rcases hc with rfl | rfl
                                                · simp [witBalInt, witBlockMsg, noteValue]
                                                · simp only [witBalInt, witBlockMsg, noteValue]
                                                  have h0 : (TWO32 * ↑w.vHiIn0.toNat + ↑w.vLoIn0.toNat + (TWO32 * ↑w.vHiIn1.toNat + ↑w.vLoIn1.toNat) -
                                                      (TWO32 * ↑w.vHiIn0.toNat + ↑w.vLoIn0.toNat) -
                                                      (TWO32 * ↑w.vHiIn1.toNat + ↑w.vLoIn1.toNat)) = 0 := by omega
                                                  simpa using congrArg (· % P) h0
                                              · by_cases ho : b = 70 ∨ b = 71
                                                · have hp4 : periodicVal r 4 = 0 := by
                                                    simp [periodicVal, hb_def, ht_def, ht63e]; omega
                                                  have hp7 : periodicVal r 7 = 1 := by
                                                    simp [periodicVal, hb_def, ht_def, ht63e, ho]
                                                  rw [hp4, hp7, Int.zero_mul, Int.one_mul, Int.sub_zero]
                                                  rcases ho with rfl | rfl
                                                  · simp only [witBalInt, witBlockMsg, noteValue]
                                                    have h0 : (TWO32 * ↑w.vHiIn0.toNat + ↑w.vLoIn0.toNat + (TWO32 * ↑w.vHiIn1.toNat + ↑w.vLoIn1.toNat) -
                                                        (TWO32 * ↑w.vHiOut0.toNat + ↑w.vLoOut0.toNat) -
                                                        (TWO32 * ↑w.vHiIn0.toNat + ↑w.vLoIn0.toNat + (TWO32 * ↑w.vHiIn1.toNat + ↑w.vLoIn1.toNat)) +
                                                        (TWO32 * ↑w.vHiOut0.toNat + ↑w.vLoOut0.toNat)) = 0 := by omega
                                                    simpa using congrArg (· % P) h0
                                                  · simp only [witBalInt, witBlockMsg, noteValue]
                                                    have h0 : (TWO32 * ↑w.vHiIn0.toNat + ↑w.vLoIn0.toNat + (TWO32 * ↑w.vHiIn1.toNat + ↑w.vLoIn1.toNat) -
                                                        (TWO32 * ↑w.vHiOut0.toNat + ↑w.vLoOut0.toNat) -
                                                        (TWO32 * ↑w.vHiOut1.toNat + ↑w.vLoOut1.toNat) -
                                                        (TWO32 * ↑w.vHiIn0.toNat + ↑w.vLoIn0.toNat + (TWO32 * ↑w.vHiIn1.toNat + ↑w.vLoIn1.toNat) -
                                                         (TWO32 * ↑w.vHiOut0.toNat + ↑w.vLoOut0.toNat)) +
                                                        (TWO32 * ↑w.vHiOut1.toNat + ↑w.vLoOut1.toNat)) = 0 := by omega
                                                    simpa using congrArg (· % P) h0
                                                · have hp4 : periodicVal r 4 = 0 := by
                                                    simp [periodicVal, hb_def, ht_def, ht63e, hc]
                                                  have hp7 : periodicVal r 7 = 0 := by
                                                    simp [periodicVal, hb_def, ht_def, ht63e, ho]
                                                  rw [hp4, hp7, Int.zero_mul, Int.sub_zero, Int.add_zero]
                                                  have hwb : witBalInt w (b + 1) = witBalInt w b := by
                                                    unfold witBalInt
                                                    by_cases h1 : b ≤ 35
                                                    · have h2 : ¬(b ≤ 1) := by omega
                                                      have h3 : ¬(b + 1 ≤ 1) := by omega
                                                      have h4 : b + 1 ≤ 36 := by omega
                                                      have h5 : b ≤ 36 := by omega
                                                      simp [h2, h3, h4, h5]
                                                    · have h2 : ¬(b ≤ 1) := by omega
                                                      have h3 : ¬(b + 1 ≤ 1) := by omega
                                                      have h4 : ¬(b ≤ 36) := by omega
                                                      have h5 : ¬(b + 1 ≤ 36) := by omega
                                                      have h6 : b ≤ 70 := by omega
                                                      have h7 : b + 1 ≤ 70 := by omega
                                                      simp [h2, h3, h4, h5, h6, h7]
                                                  rw [hwb, Int.sub_self]; rfl
                                          · have hp11 : periodicVal r 11 = 0 := by simp [periodicVal, hact]
                                            have hp4 : periodicVal r 4 = 0 := by
                                              simp [periodicVal, hb_def, ht_def]; omega
                                            have hp7 : periodicVal r 7 = 0 := by
                                              simp [periodicVal, hb_def, ht_def]; omega
                                            rw [hp11, hp4, hp7]; simp
                                        · -- i = 248: top 4 bits of note value high word are 0!
                                          have hi248 : i = 248 := by omega
                                          subst hi248; rw [eval_fipsCon_248]
                                          by_cases hv : t = 8 ∧ (b = 2 ∨ b = 37 ∨ b = 71 ∨ b = 72)
                                          · rcases hv with ⟨ht8, hb⟩
                                            rw [hrt, ht8]
                                            have hx : ∀ j, 28 ≤ j → j < 32 → T.cell (b * 64 + 8) (COL_X1 + j) = 0 := fun j hj28 hj32 => by
                                              rw [canon_cell_X1_inner w b 8 j (by omega) (by omega) (by decide) (by omega),
                                                  show 8 + 1 = 9 from rfl,
                                                  sha256Schedule79_init _ (witBlockMsg_size w b) 9 (by decide)]
                                              rcases hb with rfl | rfl | rfl | rfl
                                              · exact u32Bit_high_zero_of_lt_2p28 w.vHiIn0 (vhi_lt_2p28_of_range _ _ w.hRangeIn0.2) j hj28 hj32
                                              · exact u32Bit_high_zero_of_lt_2p28 w.vHiIn1 (vhi_lt_2p28_of_range _ _ w.hRangeIn1.2) j hj28 hj32
                                              · exact u32Bit_high_zero_of_lt_2p28 w.vHiOut0 (vhi_lt_2p28_of_range _ _ w.hRangeOut0.2) j hj28 hj32
                                              · exact u32Bit_high_zero_of_lt_2p28 w.vHiOut1 (vhi_lt_2p28_of_range _ _ w.hRangeOut1.2) j hj28 hj32
                                            rw [hx 28 (by decide) (by decide), hx 29 (by decide) (by decide),
                                                hx 30 (by decide) (by decide), hx 31 (by decide) (by decide)]
                                            simp
                                          · have hp9 : periodicVal r 9 = 0 := by
                                              simp [periodicVal, hb_def, ht_def, hv]
                                            rw [hp9, Int.zero_mul]; rfl
  · -- 2. Verify ALL boundary assertions (`RawBoundaryAssertions pi`)!
    refine {
      hBal0 := by
        rw [show (64 : Nat) = 1 * 64 + 0 from rfl, canon_cell_BAL w 1 0 (by decide) (by decide) (by decide)]
        rfl
      hPos0 := by
        rw [show (64 : Nat) = 1 * 64 + 0 from rfl, canon_cell_POS w 1 0 (by decide) (by decide) (by decide)]
        rfl
      hDummy0 := fun hd => by
        have hnv := w.hDummy0 hd
        simp only [noteValue, TWO32] at hnv
        have hhi : w.vHiIn0.toNat = 0 := by omega
        have hlo : w.vLoIn0.toNat = 0 := by omega
        rw [show 2 * 64 = 2 * 64 + 0 from rfl,
            canon_cell_W w 2 0 9 (by decide) (by decide) (by decide) (by decide),
            canon_cell_W w 2 0 10 (by decide) (by decide) (by decide) (by decide),
            Nat.zero_add, sha256Schedule79_init _ (witBlockMsg_size w 2) 9 (by decide),
            sha256Schedule79_init _ (witBlockMsg_size w 2) 10 (by decide)]
        simp [witBlockMsg, hhi, hlo]
      hRoot0 := fun hd j => by
        rw [canon_cell_DIG_last w 34 j.val (by decide) (by decide) j.isLt]
        have h34 := congrFun (hdigs.2.2.1 31 (by decide)) j
        simp only [arr8ToWord8] at h34
        rw [h34, w.hMerkle0 hd]
      hNf0 := fun j => by
        rw [canon_cell_DIG_last w 35 j.val (by decide) (by decide) j.isLt]
        have h35 := congrFun hdigs.2.2.2.1 j
        simp only [arr8ToWord8] at h35
        rw [h35]
      hDummy1 := fun hd => by
        have hnv := w.hDummy1 hd
        simp only [noteValue, TWO32] at hnv
        have hhi : w.vHiIn1.toNat = 0 := by omega
        have hlo : w.vLoIn1.toNat = 0 := by omega
        rw [show 37 * 64 = 37 * 64 + 0 from rfl,
            canon_cell_W w 37 0 9 (by decide) (by decide) (by decide) (by decide),
            canon_cell_W w 37 0 10 (by decide) (by decide) (by decide) (by decide),
            Nat.zero_add, sha256Schedule79_init _ (witBlockMsg_size w 37) 9 (by decide),
            sha256Schedule79_init _ (witBlockMsg_size w 37) 10 (by decide)]
        simp [witBlockMsg, hhi, hlo]
      hRoot1 := fun hd j => by
        rw [canon_cell_DIG_last w 69 j.val (by decide) (by decide) j.isLt]
        have h69 := congrFun (hdigs.2.2.2.2.2.2.1 31 (by decide)) j
        simp only [arr8ToWord8] at h69
        rw [h69, w.hMerkle1 hd]
      hNf1 := fun j => by
        rw [canon_cell_DIG_last w 70 j.val (by decide) (by decide) j.isLt]
        have h70 := congrFun hdigs.2.2.2.2.2.2.2.1 j
        simp only [arr8ToWord8] at h70
        rw [h70]
      hOut0 := fun j => by
        rw [canon_cell_DIG_last w 71 j.val (by decide) (by decide) j.isLt]
        have h71 := congrFun hdigs.2.2.2.2.2.2.2.2.1 j
        simp only [arr8ToWord8] at h71
        rw [h71]
      hOut1 := fun j => by
        rw [canon_cell_DIG_last w 72 j.val (by decide) (by decide) j.isLt]
        have h72 := congrFun hdigs.2.2.2.2.2.2.2.2.2 j
        simp only [arr8ToWord8] at h72
        rw [h72]
      hBalEnd := by
        rw [canon_cell_BAL w 72 63 (by decide) (by decide) (by decide)]
        have h72 : witBalInt w 72 = pi.valueBalance := by
          simp only [witBalInt]
          have := w.hConservation
          omega
        rw [h72]
    }

/-- FULL BIDIRECTIONAL CHARACTERIZATION (SOUNDNESS + COMPLETENESS):
    There exists a raw `8,192 × 247` Goldilocks field trace satisfying ALL 249 live Rust
    extracted transition polynomials and ALL boundary assertions for public statement `pi`
    IF AND ONLY IF there exists a valid semantic shielded-spend witness `ValidSpendWitness pi`. -/
theorem raw_rust_air_iff_valid_spend_witness (pi : SpendPublicStmt) :
    (∃ T : RawFieldTrace, RawAirTransitionsHold T ∧ RawBoundaryAssertions pi T) ↔
      Nonempty (ValidSpendWitness pi) :=
  ⟨fun ⟨T, hT, hB⟩ => raw_rust_air_soundness pi T hT hB,
   fun ⟨w⟩ => ⟨canonicalRawTrace pi w, valid_witness_satisfies_raw_air pi w⟩⟩
"####);

    lean_src.push_str(&format!(
r#"
-- ---- Part 9G: Concrete Real Rust-Verified 2-in/2-out Non-Vacuity Witness ----
-- Independently verified live in Rust via `spend::check_trace(&spend::build_trace(&wit), &pi)`.

def arr5ToRho5 (a : Array UInt32) : Rho5 := fun i => a[i.val]!

theorem arr8ToWord8_eq_of_arr_eq {{a b : Array UInt32}} (h : a = b) :
    arr8ToWord8 a = arr8ToWord8 b :=
  congrArg arr8ToWord8 h

theorem list_all_range_succ {{p : Nat → Bool}} {{n : Nat}}
    (h : (List.range (n + 1)).all p = true) :
    (List.range n).all p = true ∧ p n = true := by
  rw [List.range_succ, List.all_append] at h
  simp only [Bool.and_eq_true, List.all_cons, List.all_nil, Bool.and_true] at h
  exact h

theorem merkleRoot_eq_of_steps (nodes : Array (Array UInt32)) (bits : Nat → Nat) (sibs : Nat → Word8) :
    ∀ n, (List.range n).all (fun k =>
      sha256Compress (merkleMsg (arr8ToWord8 nodes[k]!) (sibs k) (bits k)) == nodes[k + 1]!) = true →
    merkleRoot (arr8ToWord8 nodes[0]!) bits sibs n = arr8ToWord8 nodes[n]! := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ m ih =>
    intro hall
    rcases list_all_range_succ hall with ⟨hprev, hstep⟩
    have hEq : sha256Compress (merkleMsg (arr8ToWord8 nodes[m]!) (sibs m) (bits m)) = nodes[m + 1]! :=
      beq_iff_eq.mp hstep
    simp only [merkleRoot, merkleStep, ih hprev, hEq]

def concreteRootArr    : Array UInt32 := {c_root}
def concreteNf0Arr     : Array UInt32 := {c_nf0}
def concreteNf1Arr     : Array UInt32 := {c_nf1}
def concreteCmOut0Arr  : Array UInt32 := {c_cmout0}
def concreteCmOut1Arr  : Array UInt32 := {c_cmout1}
def concreteSk0Arr     : Array UInt32 := {c_sk0}
def concreteSk1Arr     : Array UInt32 := {c_sk1}
def concreteApk0Arr    : Array UInt32 := {c_apk0}
def concreteApk1Arr    : Array UInt32 := {c_apk1}
def concreteCmIn0Arr   : Array UInt32 := {c_cmin0}
def concreteCmIn1Arr   : Array UInt32 := {c_cmin1}
def concreteRho0Arr    : Array UInt32 := {c_rho0}
def concreteRho1Arr    : Array UInt32 := {c_rho1}
def concreteApkOut0Arr : Array UInt32 := {c_apkout0}
def concreteApkOut1Arr : Array UInt32 := {c_apkout1}
def concreteRhoOut0Arr : Array UInt32 := {c_rhoout0}
def concreteRhoOut1Arr : Array UInt32 := {c_rhoout1}

def concreteSibs0Arr : Array (Array UInt32) := {c_sibs0}
def concreteSibs1Arr : Array (Array UInt32) := {c_sibs1}
def concreteNodes0   : Array (Array UInt32) := {c_nodes0}
def concreteNodes1   : Array (Array UInt32) := {c_nodes1}

def concretePos0 : UInt32 := {c_pos0}
def concretePos1 : UInt32 := {c_pos1}
def concreteBits0 (k : Nat) : Nat := (concretePos0.toNat >>> k) &&& 1
def concreteBits1 (k : Nat) : Nat := (concretePos1.toNat >>> k) &&& 1
def concreteSibs0 (k : Nat) : Word8 := arr8ToWord8 concreteSibs0Arr[k]!
def concreteSibs1 (k : Nat) : Word8 := arr8ToWord8 concreteSibs1Arr[k]!

def concretePi : SpendPublicStmt where
  root         := arr8ToWord8 concreteRootArr
  nf0          := arr8ToWord8 concreteNf0Arr
  nf1          := arr8ToWord8 concreteNf1Arr
  cmOut0       := arr8ToWord8 concreteCmOut0Arr
  cmOut1       := arr8ToWord8 concreteCmOut1Arr
  valueBalance := {c_vb}
  dummy0       := false
  dummy1       := false
  hvb          := by decide

theorem concrete_merkle0_steps :
    (List.range 32).all (fun k =>
      sha256Compress (merkleMsg (arr8ToWord8 concreteNodes0[k]!) (concreteSibs0 k) (concreteBits0 k)) ==
      concreteNodes0[k + 1]!) = true := by decide

theorem concrete_merkle1_steps :
    (List.range 32).all (fun k =>
      sha256Compress (merkleMsg (arr8ToWord8 concreteNodes1[k]!) (concreteSibs1 k) (concreteBits1 k)) ==
      concreteNodes1[k + 1]!) = true := by decide

def concreteWitness : ValidSpendWitness concretePi where
  sk0     := arr8ToWord8 concreteSk0Arr
  sk1     := arr8ToWord8 concreteSk1Arr
  apk0    := arr8ToWord8 concreteApk0Arr
  apk1    := arr8ToWord8 concreteApk1Arr
  vHiIn0  := {c_vhi_in0}
  vLoIn0  := {c_vlo_in0}
  vHiIn1  := {c_vhi_in1}
  vLoIn1  := {c_vlo_in1}
  rho0    := arr5ToRho5 concreteRho0Arr
  rho1    := arr5ToRho5 concreteRho1Arr
  cmIn0   := arr8ToWord8 concreteCmIn0Arr
  cmIn1   := arr8ToWord8 concreteCmIn1Arr
  bits0   := concreteBits0
  bits1   := concreteBits1
  sibs0   := concreteSibs0
  sibs1   := concreteSibs1
  pos0    := concretePos0
  pos1    := concretePos1
  apkOut0 := arr8ToWord8 concreteApkOut0Arr
  apkOut1 := arr8ToWord8 concreteApkOut1Arr
  vHiOut0 := {c_vhi_out0}
  vLoOut0 := {c_vlo_out0}
  vHiOut1 := {c_vhi_out1}
  vLoOut1 := {c_vlo_out1}
  rhoOut0 := arr5ToRho5 concreteRhoOut0Arr
  rhoOut1 := arr5ToRho5 concreteRhoOut1Arr
  hOwner0 := arr8ToWord8_eq_of_arr_eq (by decide)
  hOwner1 := arr8ToWord8_eq_of_arr_eq (by decide)
  hCmIn0  := arr8ToWord8_eq_of_arr_eq (by decide)
  hCmIn1  := arr8ToWord8_eq_of_arr_eq (by decide)
  hBits0  := fun k _ => by
    unfold concreteBits0
    rw [Nat.and_one_is_mod]
    have hlt : (concretePos0.toNat >>> k) % 2 < 2 := Nat.mod_lt _ (by decide)
    omega
  hBits1  := fun k _ => by
    unfold concreteBits1
    rw [Nat.and_one_is_mod]
    have hlt : (concretePos1.toNat >>> k) % 2 < 2 := Nat.mod_lt _ (by decide)
    omega
  hPos0   := by decide
  hPos1   := by decide
  hMerkle0 := fun _ => by
    have h0 : arr8ToWord8 concreteCmIn0Arr = arr8ToWord8 concreteNodes0[0]! := rfl
    have h32 : arr8ToWord8 concreteNodes0[32]! = concretePi.root := rfl
    rw [h0, ← h32]
    exact merkleRoot_eq_of_steps concreteNodes0 concreteBits0 concreteSibs0 32 concrete_merkle0_steps
  hMerkle1 := fun _ => by
    have h0 : arr8ToWord8 concreteCmIn1Arr = arr8ToWord8 concreteNodes1[0]! := rfl
    have h32 : arr8ToWord8 concreteNodes1[32]! = concretePi.root := rfl
    rw [h0, ← h32]
    exact merkleRoot_eq_of_steps concreteNodes1 concreteBits1 concreteSibs1 32 concrete_merkle1_steps
  hNf0          := arr8ToWord8_eq_of_arr_eq (by decide)
  hNf1          := arr8ToWord8_eq_of_arr_eq (by decide)
  hCmOut0       := arr8ToWord8_eq_of_arr_eq (by decide)
  hCmOut1       := arr8ToWord8_eq_of_arr_eq (by decide)
  hRangeIn0     := by decide
  hRangeIn1     := by decide
  hRangeOut0    := by decide
  hRangeOut1    := by decide
  hDummy0       := fun h => by cases h
  hDummy1       := fun h => by cases h
  hConservation := by decide

/-- NON-VACUITY CERTIFICATE:
    There exists a concrete `8,192 × 247` Goldilocks field trace satisfying ALL 249 live Rust
    extracted transition constraints (`RawAirTransitionsHold`) and ALL boundary assertions
    (`RawBoundaryAssertions concretePi`) for the real non-dummy 2-in/2-out shielded spend
    `concretePi` (whose trace also passes live Rust `spend::check_trace`). -/
theorem raw_rust_air_non_vacuous :
    ∃ T : RawFieldTrace, RawAirTransitionsHold T ∧ RawBoundaryAssertions concretePi T :=
  ⟨canonicalRawTrace concretePi concreteWitness, valid_witness_satisfies_raw_air concretePi concreteWitness⟩

#print axioms fips180_4_sha256_empty_exact
#print axioms fips180_4_sha256_abc_exact
#print axioms xor3_poly_exact
#print axioms maj_poly_exact
#print axioms all_249_constraints_match_fips180_4_spec
#print axioms goldilocks_is_prime
#print axioms goldilocks_boolean_sound
#print axioms round_word_mod32_sound
#print axioms digest_word_mod32_even_unreduced
#print axioms w0_unreduced_harmless_mod32
#print axioms sha256_64_rounds_induction
#print axioms merkle_pos_32_levels_sound
#print axioms layout_128_blocks_exact
#print axioms nullifier_deterministic_unique
#print axioms accepted_spend_trace_implies_spend_relation
#print axioms raw_air_trace_implies_accepted_spend_trace
#print axioms raw_rust_air_soundness
#print axioms valid_witness_satisfies_raw_air
#print axioms raw_rust_air_iff_valid_spend_witness
#print axioms raw_rust_air_non_vacuous

end NewsatoshiFullCircuit
"#,
        c_root    = fmt_u32_arr(&concrete_pi.root),
        c_nf0     = fmt_u32_arr(&concrete_pi.nf[0]),
        c_nf1     = fmt_u32_arr(&concrete_pi.nf[1]),
        c_cmout0  = fmt_u32_arr(&concrete_pi.cm_out[0]),
        c_cmout1  = fmt_u32_arr(&concrete_pi.cm_out[1]),
        c_sk0     = fmt_u32_arr(&sk0),
        c_sk1     = fmt_u32_arr(&sk1),
        c_apk0    = fmt_u32_arr(&apk0),
        c_apk1    = fmt_u32_arr(&apk1),
        c_cmin0   = fmt_u32_arr(&cm_in0),
        c_cmin1   = fmt_u32_arr(&cm_in1),
        c_rho0    = fmt_u32_arr(&rho0),
        c_rho1    = fmt_u32_arr(&rho1),
        c_apkout0 = fmt_u32_arr(&apk_out0),
        c_apkout1 = fmt_u32_arr(&apk_out1),
        c_rhoout0 = fmt_u32_arr(&rho_out0),
        c_rhoout1 = fmt_u32_arr(&rho_out1),
        c_sibs0   = fmt_u32_arr_list(&path0),
        c_sibs1   = fmt_u32_arr_list(&path1),
        c_nodes0  = fmt_u32_arr_list(&nodes0),
        c_nodes1  = fmt_u32_arr_list(&nodes1),
        c_pos0    = format!("0x{pos0:08x}"),
        c_pos1    = format!("0x{pos1:08x}"),
        c_vb      = concrete_pi.value_balance,
        c_vhi_in0  = format!("0x{:08x}", (v_in0 >> 32) as u32),
        c_vlo_in0  = format!("0x{:08x}", v_in0 as u32),
        c_vhi_in1  = format!("0x{:08x}", (v_in1 >> 32) as u32),
        c_vlo_in1  = format!("0x{:08x}", v_in1 as u32),
        c_vhi_out0 = format!("0x{:08x}", (v_out0 >> 32) as u32),
        c_vlo_out0 = format!("0x{:08x}", v_out0 as u32),
        c_vhi_out1 = format!("0x{:08x}", (v_out1 >> 32) as u32),
        c_vlo_out1 = format!("0x{:08x}", v_out1 as u32),
    ));

    std::fs::write(&out, lean_src).unwrap_or_else(|e| panic!("write {out}: {e}"));
    println!(
        "Extracted ALL {N_CONSTRAINTS} spend-circuit constraints ({total_terms} terms) + 114,688 periodic cells + Rust-verified 2-in/2-out witness -> {out}"
    );
}
