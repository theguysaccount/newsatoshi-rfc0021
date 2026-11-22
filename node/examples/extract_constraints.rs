//! Read the payment circuit's constraints out of the code that proves and verifies them.
//!
//!     cargo run --release --example extract_constraints -- proof/constraints.json
//!
//! `spend::eval_constraints` is generic over the field element type, and the prover, the
//! verifier and the soundness scan all call it. Here it is called once more with a field
//! element that is a polynomial: every addition and multiplication it performs is carried out
//! on polynomials over the Goldilocks field, in the variables of two rows of the trace (the
//! current and the next) and the periodic selectors. What comes out is each constraint as
//! the exact polynomial the code computes, with nothing transcribed by hand. `proof/check.py`
//! takes it from there.

use newsatoshi::spend::{self, BLK, N_CONSTRAINTS, ROWS, WIDTH};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::*;
use std::sync::{Mutex, OnceLock};
use winter_utils::{AsBytes, ByteReader, ByteWriter, Deserializable, DeserializationError, Randomizable, Serializable};
use winterfell::math::{fields::f64::BaseElement as Felt, ExtensionOf, FieldElement, StarkField};

/// A polynomial: monomial (variable ids, sorted, repeated for powers) to coefficient.
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

/// A field element that is a polynomial, kept in the arena above.
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
        write!(f, "{:?}", self)
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
        panic!("the constraints never divide")
    }
}
impl AddAssign for Sym {
    fn add_assign(&mut self, o: Sym) {
        *self = *self + o
    }
}
impl SubAssign for Sym {
    fn sub_assign(&mut self, o: Sym) {
        *self = *self - o
    }
}
impl MulAssign for Sym {
    fn mul_assign(&mut self, o: Sym) {
        *self = *self * o
    }
}
impl DivAssign for Sym {
    fn div_assign(&mut self, o: Sym) {
        *self = *self / o
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
        panic!("the constraints never invert")
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

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "proof/constraints.json".into());
    let periodic = spend::periodic_table();
    let np = periodic[0].len();
    // variables: cur[i] = i, nxt[i] = WIDTH + i, periodic[i] = 2 WIDTH + i
    let cur: Vec<Sym> = (0..WIDTH).map(|i| Sym::var(i as u16)).collect();
    let nxt: Vec<Sym> = (0..WIDTH).map(|i| Sym::var((WIDTH + i) as u16)).collect();
    let pv: Vec<Sym> = (0..np).map(|i| Sym::var((2 * WIDTH + i) as u16)).collect();
    let mut res = vec![Sym::ZERO; N_CONSTRAINTS];
    spend::eval_constraints(&cur, &nxt, &pv, &mut res);

    // the same function, evaluated on numbers, must agree with the polynomials it produced
    let mut rng = rand::thread_rng();
    use rand::Rng;
    for _ in 0..20 {
        let vals: Vec<Felt> = (0..2 * WIDTH + np).map(|_| Felt::new(rng.gen::<u64>() % Felt::MODULUS)).collect();
        let mut direct = vec![Felt::ZERO; N_CONSTRAINTS];
        spend::eval_constraints(&vals[..WIDTH], &vals[WIDTH..2 * WIDTH], &vals[2 * WIDTH..], &mut direct);
        for (c, r) in res.iter().enumerate() {
            let v = get(*r).iter().fold(Felt::ZERO, |s, (m, k)| s + *k * m.iter().fold(Felt::ONE, |p, &x| p * vals[x as usize]));
            assert_eq!(v, direct[c], "constraint {c} disagrees with the code at a random point");
        }
    }

    let mut j = String::from("{\n");
    j += &format!("\"modulus\": {},\n\"width\": {WIDTH},\n\"rows\": {ROWS},\n\"blk\": {BLK},\n\"n_periodic\": {np},\n", Felt::MODULUS);
    j += &format!("\"layout\": [{}],\n", spend::layout().iter().map(|k| format!("\"{k:?}\"")).collect::<Vec<_>>().join(","));
    // the selector values of each row of one period of the trace
    j += "\"periodic\": [\n";
    j += &periodic.iter().map(|r| format!("[{}]", r.iter().map(|x| x.as_int().to_string()).collect::<Vec<_>>().join(","))).collect::<Vec<_>>().join(",\n");
    j += "]";
    // the boundary cells, for an input that is real and for a dummy one: (column, row)
    for (name, dummy) in [("real", false), ("dummy", true)] {
        let pi = spend::SpendPublic { root: [0; 8], nf: [[0; 8]; 2], cm_out: [[0; 8]; 2], value_balance: 0, dummy: [dummy; 2], bind: [0; 8] };
        let cells: Vec<String> = spend::assertion_cells(&pi).iter().map(|(c, r, _)| format!("[{c},{r}]")).collect();
        j += &format!(",\n\"assert_{name}\": [{}]", cells.join(","));
    }
    j += ",\n\"constraints\": [\n";
    let polys: Vec<String> = res
        .iter()
        .map(|r| format!("[{}]", get(*r).iter().map(|(m, c)| format!("[[{}],{}]", m.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","), c.as_int())).collect::<Vec<_>>().join(",")))
        .collect();
    j += &polys.join(",\n");
    j += "]\n}\n";
    std::fs::write(&out, j).unwrap();
    let terms: usize = res.iter().map(|r| get(*r).len()).sum();
    println!("{} constraints, {terms} terms in all, written to {out}; checked against the code at 20 random points", res.len());
}
