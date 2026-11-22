// Search the whole payment circuit for cells its constraints leave free (src/audit.rs), on
// two honest payments: one spending two notes, one spending a note and a dummy.
// Run: cargo run --release --example soundness_scan      (about ten minutes on two cores)
use newsatoshi::audit::{self, Free, Table};
use newsatoshi::spend::{self, BLK, WIDTH};
use std::time::Instant;

fn main() {
    let rows = audit::active_rows();
    let mut failed = false;
    for dummy in [false, true] {
        let (w, pi) = audit::sample(dummy);
        let trace = spend::build_trace(&w);
        spend::check_trace(&trace, &pi).expect("an honest table satisfies the circuit");
        let table = Table::new(&trace, &pi);
        println!("payment with {}: rows {}..{}, {} columns", if dummy { "one note and a dummy" } else { "two notes" }, rows.start, rows.end, WIDTH);

        let t = Instant::now();
        let mid = (rows.start + rows.end) / 2;
        let wrong = std::thread::scope(|s| {
            let a = s.spawn(|| table.scan_cells(rows.start..mid));
            let mut b = table.scan_cells(mid..rows.end);
            let mut a = a.join().unwrap();
            a.append(&mut b);
            a
        });
        let (mut fixed, mut bit, mut any) = (0usize, 0usize, 0usize);
        for r in rows.clone() {
            for c in 0..WIDTH {
                match audit::expected(&table.lay, r, c) {
                    Free::No => fixed += 1,
                    Free::Bit => bit += 1,
                    _ => any += 1,
                }
            }
        }
        println!("  one cell at a time ({:.0} s): {} cells; by the specification {fixed} are fixed, {bit} are unused bits, {any} are free (masks and unused digest cells)", t.elapsed().as_secs_f64(), rows.len() * WIDTH);
        println!("  cells that differ from the specification: {}", wrong.len());
        for (r, c, got, want) in wrong.iter().take(20) {
            println!("    row {r} (block {} {:?}, round {}), column {c}: {got:?}, specified {want:?}", r / BLK, table.lay[r / BLK], r % BLK);
        }
        failed |= !wrong.is_empty();

        let t = Instant::now();
        let slack = table.scan_slack(rows.clone());
        let mut extra = vec![];
        let mut moving = 0usize;
        for (i, cols) in slack.iter().enumerate() {
            let r = rows.start + i;
            moving += cols.len();
            for c in cols {
                if !audit::expected_slack(&table.lay, r, *c) {
                    extra.push((r, *c));
                }
            }
        }
        println!("  first-order freedom, any cells together ({:.0} s): {moving} cells can move; outside the specification: {}", t.elapsed().as_secs_f64(), extra.len());
        for (r, c) in extra.iter().take(20) {
            println!("    row {r} (block {} {:?}, round {}), column {c}", r / BLK, table.lay[r / BLK], r % BLK);
        }
        failed |= !extra.is_empty();
    }
    if failed {
        println!("FOUND cells the specification does not account for");
        std::process::exit(1);
    }
    println!("every cell is fixed or free exactly as specified");
}
