//! The payment circuit leaves free exactly the cells its design says it does: no cell that
//! carries the statement can be changed alone, or moved to first order together with any
//! others, with every constraint still holding. A hole here would be counterfeit money
//! nobody could see, so every change to the circuit has to pass this. See `src/audit.rs`
//! for what the two searches do and do not show.

use newsatoshi::audit::{self, Table};
use newsatoshi::spend;

fn table(dummy: bool) -> Table {
    let (w, pi) = audit::sample(dummy);
    let trace = spend::build_trace(&w);
    spend::check_trace(&trace, &pi).unwrap();
    Table::new(&trace, &pi)
}

#[test]
fn no_cell_of_the_circuit_is_free_but_those_specified() {
    let rows = audit::active_rows();
    for dummy in [false, true] {
        let wrong = table(dummy).scan_cells(rows.clone());
        assert!(wrong.is_empty(), "cells that differ from the specification (row, column, found, specified): {:?}", &wrong[..wrong.len().min(10)]);
    }
}

#[test]
fn no_cells_move_together_but_those_specified() {
    let rows = audit::active_rows();
    let t = table(false);
    let slack = t.scan_slack(rows.clone());
    let extra: Vec<(usize, usize)> =
        slack.iter().enumerate().flat_map(|(i, cols)| cols.iter().map(move |c| (rows.start + i, *c))).filter(|(r, c)| !audit::expected_slack(&t.lay, *r, *c)).collect();
    assert!(extra.is_empty(), "cells with first-order freedom outside the specification (row, column): {:?}", &extra[..extra.len().min(10)]);
    // and the count is the design's: three masking columns on every row, eight unused
    // digest cells on 63 rows of each of 72 compressions, and ρ's five unloaded cells on
    // the 64 rows of the first
    assert_eq!(slack.iter().map(|c| c.len()).sum::<usize>(), 3 * rows.len() + 8 * 63 * 72 + 5 * 64);
}

/// What the two searches cannot see is a second solution at a distance. The circuit has one
/// known family of them, and it is harmless: where a digest feeds the next compression as
/// its first message word, which is the one word never split into bits, that word may be
/// off by a multiple of 2^32 with the carries beside it absorbing the difference. Every
/// use of the word is modulo 2^32, so the compression and everything after it are
/// unchanged. Where a digest word feeds any other position it is split into bits, and no
/// such second solution exists. This test builds the second solution and checks both
/// halves of that claim, so a change to how digests are read cannot pass unnoticed.
#[test]
fn the_one_second_encoding_changes_nothing_that_is_read() {
    use newsatoshi::spend::{Kind, BLK, COL_AN, COL_CA, COL_CE, COL_CWC, COL_DIG, COL_W, COL_X1};
    use winterfell::math::{fields::f64::BaseElement as Felt, FieldElement};
    let (w, pi) = audit::sample(false);
    let honest = spend::build_trace(&w);
    let lay = spend::layout();
    let two32 = Felt::new(1 << 32);
    let bits3 = |t: &winterfell::TraceTable<Felt>, col: usize, r: usize| (0..3).map(|j| t.get(col + j, r).as_int() << j).sum::<u64>();
    let set3 = |t: &mut winterfell::TraceTable<Felt>, col: usize, r: usize, v: u64| (0..3).for_each(|j| t.set(col + j, r, Felt::new((v >> j) & 1)));

    // a tree level whose running node sits on the left (path bit 0), so the digest before it
    // lands in message word 0; the path of position 5 has bit 0 at every level from 3 up
    let mut tried = 0;
    for b in 1..lay.len() {
        let (Kind::Merkle(0, k), prev) = (lay[b], b * BLK - 1) else { continue };
        if (w.inputs[0].pos >> k) & 1 != 0 {
            continue;
        }
        let first = b * BLK;
        // shift the digest's first word up by 2^32 and let the carries absorb it
        let mut t = honest.clone();
        let (ca, ce) = (bits3(&t, COL_CA, first), bits3(&t, COL_CE, first));
        let cw = t.get(COL_CWC, first).as_int() + 2 * t.get(COL_CWC + 1, first).as_int();
        let room_here = ca < 7 && ce < 7 && cw < 3;
        let room_before = t.get(COL_X1, prev) == Felt::ONE || bits3(&t, COL_CA, prev) > 0;
        if !(room_here && room_before) {
            continue;
        }
        tried += 1;
        if t.get(COL_X1, prev) == Felt::ONE {
            t.set(COL_X1, prev, Felt::ZERO);
        } else {
            let c = bits3(&t, COL_CA, prev);
            set3(&mut t, COL_CA, prev, c - 1);
            t.set(COL_AN, prev, t.get(COL_AN, prev) + two32);
        }
        t.set(COL_DIG, prev, t.get(COL_DIG, prev) + two32);
        // without the carries of the next compression, the shifted word is refused
        t.set(COL_W, first, t.get(COL_W, first) + two32);
        assert!(spend::check_trace(&t, &pi).is_err());
        set3(&mut t, COL_CA, first, ca + 1);
        set3(&mut t, COL_CE, first, ce + 1);
        t.set(COL_CWC, first, Felt::new((cw + 1) & 1));
        t.set(COL_CWC + 1, first, Felt::new((cw + 1) >> 1));
        spend::check_trace(&t, &pi).expect("the second encoding satisfies every constraint");
        // and nothing else in the table moved: every digest, every state, every other word
        let changed: Vec<(usize, usize)> = (0..spend::ROWS).flat_map(|r| (0..spend::WIDTH).map(move |c| (r, c))).filter(|(r, c)| t.get(*c, *r) != honest.get(*c, *r)).collect();
        assert!(changed.iter().all(|(r, _)| *r == prev || *r == first), "{changed:?}");
        assert!(changed.iter().all(|(r, c)| *r == prev || [COL_W, COL_CA, COL_CA + 1, COL_CA + 2, COL_CE, COL_CE + 1, COL_CE + 2, COL_CWC, COL_CWC + 1].contains(c)));
        if tried == 3 {
            break;
        }
    }
    assert!(tried > 0, "no tree level in the sample had room for the second encoding");

    // the same shift where the digest feeds a word that is split into bits: the note's
    // commitment into the first tree level of position 5 (bit 1: it is the right-hand half)
    let b = lay.iter().position(|k| *k == Kind::Merkle(0, 0)).unwrap();
    let (prev, first) = (b * BLK - 1, b * BLK);
    let mut t = honest.clone();
    t.set(COL_DIG, prev, t.get(COL_DIG, prev) + two32);
    t.set(COL_W + 8, first, t.get(COL_W + 8, first) + two32);
    if t.get(COL_X1, prev) == Felt::ONE {
        t.set(COL_X1, prev, Felt::ZERO);
    } else {
        t.set(COL_AN, prev, t.get(COL_AN, prev) + two32);
        let c = bits3(&t, COL_CA, prev);
        set3(&mut t, COL_CA, prev, c.saturating_sub(1));
    }
    assert!(spend::check_trace(&t, &pi).is_err(), "a word that is split into bits cannot be shifted");
}
