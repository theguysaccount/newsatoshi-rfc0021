// What the chain proof will cost: count the SHA-256 compressions a verifier runs to check
// one payment proof, since a verifier written as a circuit must run each of them, and
// time how fast this machine proves rows of the circuit we already have.
// Run: cargo run --release --features count --example recursion_cost
use newsatoshi::hash::count;
use newsatoshi::note::{self, NoteTree};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use rand::Rng;
use std::time::Instant;
use winterfell::{BatchingMethod, FieldExtension, ProofOptions};

fn main() {
    let mut rng = rand::thread_rng();
    let mut tree = NoteTree::new();
    let sks: Vec<[u32; 8]> = (0..2).map(|_| rng.gen()).collect();
    let rhos: Vec<[u32; 5]> = (0..2).map(|_| rng.gen()).collect();
    let pos: Vec<u32> = (0..2).map(|i| tree.append(note::commit(&note::address(&sks[i]), 1000 + i as u64, &rhos[i]))).collect();
    let w = SpendWitness {
        inputs: core::array::from_fn(|i| InputNote { sk: sks[i], v: 1000 + i as u64, rho: rhos[i], pos: pos[i], path: tree.path(pos[i]) }),
        outputs: [OutputNote { a_pk: note::address(&rng.gen()), v: 1500, rho: rng.gen() }, OutputNote { a_pk: note::address(&sks[0]), v: 500, rho: rng.gen() }],
        dummy: [false, false],
    };
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("machine: {cores} cores");
    // rows of a SHA-256 circuit per second, from proving the payment circuit itself
    let t = Instant::now();
    let runs = 3;
    for _ in 0..runs {
        spend::prove(&w, rng.gen()).unwrap();
    }
    let secs = t.elapsed().as_secs_f64() / runs as f64;
    let rate = spend::ROWS as f64 / secs / cores as f64;
    println!("payment circuit: {} rows in {:.2} s, {:.0} rows per core-second", spend::ROWS, secs, rate);

    let show = |name: &str, options: ProofOptions| {
        let (pi, proof) = spend::prove_with(&w, [1u32; 8], options.clone()).unwrap();
        count::reset();
        spend::verify_with(&pi, &proof, options).unwrap();
        let (leaves, merges, draws, other) = count::read();
        let total = leaves + merges + draws + other;
        // one SHA-256 round per row, 64 rows a compression, as in the payment circuit
        let rows = total * 64;
        // proving cost grows a little faster than the rows (the FFTs): scale by log n
        let log_ratio = (rows as f64).log2() / (spend::ROWS as f64).log2();
        let core_secs = rows as f64 / rate * log_ratio;
        println!(
            "{name}: {} bytes; checking it runs {total} compressions ({leaves} hashing rows into leaves, {merges} merging Merkle nodes, {draws} drawing challenges, {other} other)",
            proof.to_bytes().len()
        );
        println!("  as a circuit: about {rows} rows, about {core_secs:.0} core-seconds to prove at this machine's rate, before the arithmetic around the hashes");
    };
    show("testnet payment proof", spend::options());
    show(
        "same, challenges drawn as powers of one value (algebraic batching)",
        ProofOptions::new(64, 16, 16, FieldExtension::Cubic, 8, 31, BatchingMethod::Algebraic, BatchingMethod::Algebraic),
    );
    show("mainnet payment proof", spend::main_options());
}
