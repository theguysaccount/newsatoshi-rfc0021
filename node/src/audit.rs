//! Looking for cells of the payment circuit that its constraints leave free.
//!
//! A proof shows that some table of values satisfies the circuit's constraints. If a cell
//! that matters could hold a second value with every constraint still satisfied, a prover
//! could prove something false: coins from nothing, in a pool where nobody would see them.
//! Two mechanical searches for such cells, each run on an honest table:
//!
//! 1. Change one cell at a time, to the other bit and to arbitrary values, and re-check
//!    every constraint that reads it. Each cell is then fixed, free as a bit, or free.
//! 2. Linearise the constraints at the table and compute, row by row, every direction in
//!    which a row can move while all constraints still hold to first order, whatever other
//!    cells move with it. This finds cells that are fixed only in combination with others,
//!    which the first search cannot.
//!
//! Both are compared with `expected` and `expected_slack`, which say which cells the design
//! leaves free: the masking columns, digest cells outside the row that holds a digest, and
//! bits nothing reads. Neither search is a proof of soundness. The first moves one cell at
//! a time; the second sees first-order freedom only, not a second solution at a distance
//! (a different carry, say), which `spend.rs` argues about by hand. They are evidence, and
//! a tripwire on every change to the circuit. A machine-checked proof is a condition of
//! the main network (LAUNCH.md).

use crate::spend::{self, Kind, SpendPublic, BLK, COL_BIT, COL_CWC, COL_DIG, COL_RHO, COL_RND, COL_X1, COL_X14, N_CONSTRAINTS, ROWS, WIDTH};
use rand::Rng;
use std::collections::HashMap;
use winterfell::math::{fields::f64::BaseElement as Felt, FieldElement, StarkField};
use winterfell::TraceTable;

/// What a cell may be changed to with every constraint still holding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Free {
    /// Nothing: the cell is fixed.
    No,
    /// The other bit, and nothing else.
    Bit,
    /// Anything.
    Any,
    /// Some values and not others, in a way no cell of this circuit should be.
    Odd,
}

pub struct Table {
    rows: Vec<Vec<Felt>>,
    per: Vec<Vec<Felt>>,
    asserts: HashMap<(usize, usize), Felt>,
    pub lay: Vec<Kind>,
}

/// The rows of the compressions: everything between the random blocks.
pub fn active_rows() -> std::ops::Range<usize> {
    let lay = spend::layout();
    let first = lay.iter().position(|k| k.active()).expect("an active block");
    let last = lay.iter().rposition(|k| k.active()).expect("an active block");
    first * BLK..(last + 1) * BLK
}

/// The specification for the first search: what each cell of an active row may be changed
/// to, alone.
pub fn expected(lay: &[Kind], r: usize, c: usize) -> Free {
    let (kind, t) = (lay[r / BLK], r % BLK);
    if !kind.active() || c >= COL_RND {
        return Free::Any;
    }
    let last = t == BLK - 1;
    if (COL_DIG..COL_DIG + 8).contains(&c) {
        // a digest is written on the last row of its block; the cells above it are unused
        return if last { Free::No } else { Free::Any };
    }
    if (COL_X1..COL_X1 + 32).contains(&c) {
        // on the last row the first eight are the digest's carries and the rest unused
        return if last && c - COL_X1 >= 8 { Free::Bit } else { Free::No };
    }
    if (COL_X14..COL_X14 + 32).contains(&c) || c == COL_CWC || c == COL_CWC + 1 {
        return if last { Free::Bit } else { Free::No };
    }
    if c == COL_BIT {
        // read only on the first row of a tree level
        return if t == 0 && matches!(kind, Kind::Merkle(..)) { Free::No } else { Free::Bit };
    }
    Free::No
}

/// The specification for the second search: whether a cell of an active row may move at
/// all, to first order, with any other cells moving with it. The masking columns and the
/// unused digest cells may. So may ρ's register during the first block, before any note
/// has loaded it: it holds one unused value there, the same on every row.
pub fn expected_slack(lay: &[Kind], r: usize, c: usize) -> bool {
    let (b, t) = (r / BLK, r % BLK);
    if !lay[b].active() || c >= COL_RND {
        return true;
    }
    if (COL_DIG..COL_DIG + 8).contains(&c) {
        return t != BLK - 1;
    }
    (COL_RHO..COL_RHO + 5).contains(&c) && Some(b) == lay.iter().position(|k| k.active())
}

/// An honest payment to search: two notes spent from positions whose tree paths turn both
/// ways, or one note and a dummy.
pub fn sample(dummy_second: bool) -> (spend::SpendWitness, SpendPublic) {
    use crate::note::{self, NoteTree};
    let mut rng = rand::thread_rng();
    let mut tree = NoteTree::new();
    let sks: [[u32; 8]; 2] = rng.gen();
    let rhos: [[u32; 5]; 2] = rng.gen();
    let vs = [7_000_000_123u64, if dummy_second { 0 } else { 1u64 << 40 }];
    let mut pos = [0u32; 2];
    for at in 0..12u32 {
        let i = match at {
            5 => Some(0),
            10 => Some(1),
            _ => None,
        };
        let cm = match i {
            Some(i) => note::commit(&note::address(&sks[i]), vs[i], &rhos[i]),
            None => rng.gen(),
        };
        let p = tree.append(cm);
        if let Some(i) = i {
            pos[i] = p;
        }
    }
    let total = vs[0] + vs[1];
    let w = spend::SpendWitness {
        inputs: core::array::from_fn(|i| spend::InputNote { sk: sks[i], v: vs[i], rho: rhos[i], pos: pos[i], path: tree.path(pos[i]) }),
        outputs: [
            spend::OutputNote { a_pk: note::address(&rng.gen()), v: total / 3, rho: rng.gen() },
            spend::OutputNote { a_pk: note::address(&sks[0]), v: total - total / 3 - 300_000, rho: rng.gen() },
        ],
        dummy: [false, dummy_second],
    };
    let pi = w.public(rng.gen()).expect("an honest payment");
    (w, pi)
}

impl Table {
    pub fn new(trace: &TraceTable<Felt>, pi: &SpendPublic) -> Table {
        let rows = (0..ROWS).map(|r| (0..WIDTH).map(|c| trace.get(c, r)).collect()).collect();
        let asserts = spend::assertion_cells(pi).into_iter().map(|(c, r, v)| ((r, c), v)).collect();
        Table { rows, per: spend::periodic_table(), asserts, lay: spend::layout() }
    }

    fn eval(&self, r: usize, cur: &[Felt], nxt: &[Felt], res: &mut [Felt]) {
        spend::eval_constraints(cur, nxt, &self.per[r], res);
    }

    /// Whether everything that reads cell (r, c) still holds when it is `v`.
    fn holds_with(&self, r: usize, c: usize, v: Felt, res: &mut [Felt]) -> bool {
        if self.asserts.get(&(r, c)).is_some_and(|a| *a != v) {
            return false;
        }
        let mut row = self.rows[r].clone();
        row[c] = v;
        let zero = |res: &[Felt]| res.iter().all(|x| *x == Felt::ZERO);
        if r > 0 {
            self.eval(r - 1, &self.rows[r - 1], &row, res);
            if !zero(res) {
                return false;
            }
        }
        if r + 1 < ROWS {
            self.eval(r, &row, &self.rows[r + 1], res);
            if !zero(res) {
                return false;
            }
        }
        true
    }

    /// The first search, for one cell.
    pub fn cell<R: Rng>(&self, r: usize, c: usize, rng: &mut R) -> Free {
        let mut res = vec![Felt::ZERO; N_CONSTRAINTS];
        let v = self.rows[r][c];
        let mut any = || {
            let x = Felt::new(rng.gen_range(2..Felt::MODULUS));
            self.holds_with(r, c, if x == v { x + Felt::ONE } else { x }, &mut vec![Felt::ZERO; N_CONSTRAINTS])
        };
        match (any(), any()) {
            (true, true) => return Free::Any,
            (false, false) => {}
            _ => return Free::Odd,
        }
        if v == Felt::ZERO || v == Felt::ONE {
            if self.holds_with(r, c, Felt::ONE - v, &mut res) {
                Free::Bit
            } else {
                Free::No
            }
        } else if self.holds_with(r, c, v + Felt::ONE, &mut res) || self.holds_with(r, c, v - Felt::ONE, &mut res) {
            Free::Odd
        } else {
            Free::No
        }
    }

    /// The first search over `rows`: every cell whose freedom differs from the specification.
    pub fn scan_cells(&self, rows: std::ops::Range<usize>) -> Vec<(usize, usize, Free, Free)> {
        let mut rng = rand::thread_rng();
        let mut out = vec![];
        for r in rows {
            for c in 0..WIDTH {
                let (got, want) = (self.cell(r, c, &mut rng), expected(&self.lay, r, c));
                if got != want {
                    out.push((r, c, got, want));
                }
            }
        }
        out
    }

    /// The constraints of the pair (r, r+1), linearised at the table: a row for each
    /// constraint, a column for each cell of row r and then of row r+1. Every constraint is
    /// at most quadratic in any one cell, so a central difference gives its derivative
    /// exactly; `check` confirms that on the way.
    fn jacobian(&self, r: usize, check: bool) -> Vec<Vec<Felt>> {
        let half = Felt::new(2).inv();
        let two = Felt::new(2);
        let mut j = vec![vec![Felt::ZERO; 2 * WIDTH]; N_CONSTRAINTS];
        let (mut f0, mut fp, mut fm, mut f2) = (vec![Felt::ZERO; N_CONSTRAINTS], vec![Felt::ZERO; N_CONSTRAINTS], vec![Felt::ZERO; N_CONSTRAINTS], vec![Felt::ZERO; N_CONSTRAINTS]);
        let mut pair = [self.rows[r].clone(), self.rows[r + 1].clone()];
        self.eval(r, &pair[0], &pair[1], &mut f0);
        for side in 0..2 {
            for c in 0..WIDTH {
                let v = pair[side][c];
                pair[side][c] = v + Felt::ONE;
                self.eval(r, &pair[0], &pair[1], &mut fp);
                pair[side][c] = v - Felt::ONE;
                self.eval(r, &pair[0], &pair[1], &mut fm);
                if check {
                    pair[side][c] = v + two;
                    self.eval(r, &pair[0], &pair[1], &mut f2);
                }
                pair[side][c] = v;
                for i in 0..N_CONSTRAINTS {
                    let d1 = (fp[i] - fm[i]) * half;
                    if check {
                        let d2 = (fp[i] + fm[i] - f0[i].double()) * half;
                        assert!(f2[i] == f0[i] + d1.double() + d2.double().double(), "constraint {i} is more than quadratic in cell {c}");
                    }
                    j[i][side * WIDTH + c] = d1;
                }
            }
        }
        j
    }

    /// One step of the second search. `known` spans the directions row `from` can move in,
    /// given the constraints on one side of it; the result spans those of the row beside it,
    /// given those constraints and the pair's own. Forward, `from` is row r and the result
    /// row r+1; backward, the other way about.
    fn step(&self, r: usize, known: &[Vec<Felt>], forward: bool) -> Vec<Vec<Felt>> {
        let j = self.jacobian(r, r % 61 == 0);
        let (from, to) = if forward { (0, WIDTH) } else { (WIDTH, 0) };
        let to_row = if forward { r + 1 } else { r };
        let k = known.len();
        let mut m: Vec<Vec<Felt>> = Vec::with_capacity(N_CONSTRAINTS + 8);
        for row in &j {
            if row.iter().all(|x| *x == Felt::ZERO) {
                continue;
            }
            let mut line = vec![Felt::ZERO; k + WIDTH];
            for (a, u) in known.iter().enumerate() {
                let mut s = Felt::ZERO;
                for c in 0..WIDTH {
                    if row[from + c] != Felt::ZERO && u[c] != Felt::ZERO {
                        s += row[from + c] * u[c];
                    }
                }
                line[a] = s;
            }
            line[k..].copy_from_slice(&row[to..to + WIDTH]);
            m.push(line);
        }
        // an asserted cell cannot move
        for c in 0..WIDTH {
            if self.asserts.contains_key(&(to_row, c)) {
                let mut line = vec![Felt::ZERO; k + WIDTH];
                line[k + c] = Felt::ONE;
                m.push(line);
            }
        }
        let mut out: Vec<Vec<Felt>> = nullspace(m, k + WIDTH).into_iter().map(|y| y[k..].to_vec()).collect();
        rref(&mut out, WIDTH);
        out.retain(|v| v.iter().any(|x| *x != Felt::ZERO));
        out
    }

    /// The second search over `rows`: for each row, the cells that can move to first order
    /// with all constraints on rows in `rows` (and one row either side) still holding. The
    /// rows just outside are taken as free, which is right when `rows` is `active_rows()`.
    pub fn scan_slack(&self, rows: std::ops::Range<usize>) -> Vec<Vec<usize>> {
        let full: Vec<Vec<Felt>> = (0..WIDTH).map(|c| (0..WIDTH).map(|d| if c == d { Felt::ONE } else { Felt::ZERO }).collect()).collect();
        let (lo, hi) = (rows.start, rows.end);
        let (fwd, bwd) = std::thread::scope(|s| {
            let f = s.spawn(|| {
                // forward[i] spans row lo+i's directions given everything before it
                let mut all = Vec::with_capacity(hi - lo);
                let mut cur = full.clone();
                for r in lo - 1..hi - 1 {
                    cur = self.step(r, &cur, true);
                    all.push(cur.clone());
                }
                all
            });
            let b = s.spawn(|| {
                let mut all = vec![vec![]; hi - lo];
                let mut cur = full.clone();
                for r in (lo..hi).rev() {
                    cur = self.step(r, &cur, false);
                    all[r - lo] = cur.clone();
                }
                all
            });
            (f.join().expect("forward pass"), b.join().expect("backward pass"))
        });
        fwd.iter()
            .zip(&bwd)
            .map(|(u, v)| {
                let both = intersect(u, v);
                (0..WIDTH).filter(|c| both.iter().any(|x| x[*c] != Felt::ZERO)).collect()
            })
            .collect()
    }
}

/// Reduced row echelon form, in place. Returns the pivot column of each leading row.
fn rref(m: &mut Vec<Vec<Felt>>, ncols: usize) -> Vec<usize> {
    let mut pivots = vec![];
    let mut at = 0;
    for col in 0..ncols {
        let Some(p) = (at..m.len()).find(|i| m[*i][col] != Felt::ZERO) else { continue };
        m.swap(at, p);
        let inv = m[at][col].inv();
        if inv != Felt::ONE {
            m[at].iter_mut().for_each(|x| {
                if *x != Felt::ZERO {
                    *x *= inv
                }
            });
        }
        let lead = m[at].clone();
        let nz: Vec<usize> = (col..ncols).filter(|c| lead[*c] != Felt::ZERO).collect();
        for (i, row) in m.iter_mut().enumerate() {
            if i != at && row[col] != Felt::ZERO {
                let f = row[col];
                for c in &nz {
                    row[*c] -= f * lead[*c];
                }
            }
        }
        pivots.push(col);
        at += 1;
        if at == m.len() {
            break;
        }
    }
    m.truncate(at);
    pivots
}

/// A basis of the vectors x with m·x = 0.
fn nullspace(mut m: Vec<Vec<Felt>>, ncols: usize) -> Vec<Vec<Felt>> {
    let pivots = rref(&mut m, ncols);
    let mut is_pivot = vec![false; ncols];
    pivots.iter().for_each(|p| is_pivot[*p] = true);
    (0..ncols)
        .filter(|c| !is_pivot[*c])
        .map(|free| {
            let mut x = vec![Felt::ZERO; ncols];
            x[free] = Felt::ONE;
            for (row, p) in m.iter().zip(&pivots) {
                x[*p] = -row[free];
            }
            x
        })
        .collect()
}

/// A basis of the intersection of two spans.
fn intersect(u: &[Vec<Felt>], v: &[Vec<Felt>]) -> Vec<Vec<Felt>> {
    if u.is_empty() || v.is_empty() {
        return vec![];
    }
    let n = u[0].len();
    // a·U = b·V: the null vectors of the matrix whose columns are U's vectors and −V's
    let m: Vec<Vec<Felt>> = (0..n).map(|c| u.iter().map(|x| x[c]).chain(v.iter().map(|x| -x[c])).collect()).collect();
    let mut out: Vec<Vec<Felt>> = nullspace(m, u.len() + v.len())
        .into_iter()
        .map(|y| {
            let mut x = vec![Felt::ZERO; n];
            for (a, uu) in y[..u.len()].iter().zip(u) {
                if *a != Felt::ZERO {
                    for c in 0..n {
                        x[c] += *a * uu[c];
                    }
                }
            }
            x
        })
        .collect();
    rref(&mut out, n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_algebra_over_the_field() {
        let f = |x: u64| Felt::new(x);
        // x + y + z = 0 and x − y = 0: one direction, (1, 1, −2)
        let ns = nullspace(vec![vec![f(1), f(1), f(1)], vec![f(1), -f(1), f(0)]], 3);
        assert_eq!(ns.len(), 1);
        assert!(ns[0][0] == ns[0][1] && ns[0][0] + ns[0][1] + ns[0][2] == f(0) && ns[0][2] != f(0));
        // span{(1,0,0),(0,1,0)} ∩ span{(1,1,0),(0,0,1)} = span{(1,1,0)}
        let i = intersect(&[vec![f(1), f(0), f(0)], vec![f(0), f(1), f(0)]], &[vec![f(1), f(1), f(0)], vec![f(0), f(0), f(1)]]);
        assert_eq!(i, vec![vec![f(1), f(1), f(0)]]);
        assert!(intersect(&[vec![f(1), f(0)]], &[vec![f(0), f(1)]]).is_empty());
    }

    /// The searches must find a hole when there is one. Two are planted, by switching a
    /// constraint off on one row, and each search has to report the cells that come loose.
    #[test]
    fn a_planted_hole_is_found() {
        // selector indices as in `spend.rs`: the digest row, and the rows of a compression
        const P_BND: usize = 2;
        const P_ACTROW: usize = 10;
        let (w, pi) = sample(false);
        let mut table = Table::new(&spend::build_trace(&w), &pi);
        let lay = table.lay.clone();
        let block = 4; // a tree level
        let last = block * BLK + BLK - 1;
        assert!(table.scan_cells(last..last + 1).is_empty(), "nothing loose before the hole");

        // 1. no digest equation on the block's last row: its carries become free bits
        table.per[last][P_BND] = Felt::ZERO;
        let loose = table.scan_cells(last..last + 1);
        assert!(loose.iter().any(|(_, c, got, want)| (COL_X1..COL_X1 + 8).contains(c) && *got == Free::Bit && *want == Free::No), "{loose:?}");
        table.per[last][P_BND] = Felt::ONE;

        // 2. no bit constraints on one row: no single cell comes loose, because each bit is
        // still tied into a word, but two bits can now move against each other
        let row = block * BLK + 20;
        let window = (block - 1) * BLK..(block + 2) * BLK;
        // a window sees the registers (key, ρ, position, balance) as loose, because the rows
        // that load them lie outside it; the compression's own cells are what is watched
        let watched = |r: usize, c: usize| (block * BLK..(block + 1) * BLK).contains(&r) && c < spend::COL_SK;
        let outside_spec = |slack: &[Vec<usize>]| -> Vec<(usize, usize)> {
            slack.iter().enumerate().flat_map(|(i, cols)| cols.iter().map(move |c| (window.start + i, *c))).filter(|(r, c)| watched(*r, *c) && !expected_slack(&lay, *r, *c)).collect()
        };
        assert!(outside_spec(&table.scan_slack(window.clone())).is_empty(), "nothing loose before the hole");
        table.per[row][P_ACTROW] = Felt::ZERO;
        assert!(table.scan_cells(row..row + 1).iter().all(|(_, c, ..)| *c >= spend::COL_CA), "single cells of the state stay fixed");
        let loose = outside_spec(&table.scan_slack(window.clone()));
        assert!(loose.iter().any(|(r, c)| *r == row && *c < 32), "the row's state bits move together: {loose:?}");
    }
}
