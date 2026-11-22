// Measurements for the paper and README. Run: cargo run --release --example bench
use newsatoshi::chain::mine;
use newsatoshi::job;
use newsatoshi::note::{self, NoteTree};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use newsatoshi::tx::Header;
use rand::Rng;
use std::time::Instant;

fn main() {
    let mut rng = rand::thread_rng();
    println!("cores {}", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    // spend proofs
    let mut tree = NoteTree::new();
    let sks: Vec<[u32; 8]> = (0..2).map(|_| rng.gen()).collect();
    let rhos: Vec<[u32; 5]> = (0..2).map(|_| rng.gen()).collect();
    let pos: Vec<u32> = (0..2).map(|i| tree.append(note::commit(&note::address(&sks[i]), 1000 + i as u64, &rhos[i]))).collect();
    let w = SpendWitness {
        inputs: core::array::from_fn(|i| InputNote { sk: sks[i], v: 1000 + i as u64, rho: rhos[i], pos: pos[i], path: tree.path(pos[i]) }),
        outputs: [OutputNote { a_pk: note::address(&rng.gen()), v: 1500, rho: rng.gen() }, OutputNote { a_pk: note::address(&sks[0]), v: 500, rho: rng.gen() }],
        dummy: [false, false],
    };
    let (mut pt, mut vt, mut sz) = (vec![], vec![], 0);
    let mut last = None;
    for _ in 0..5 {
        let t = Instant::now();
        let (pi, proof) = spend::prove(&w, rng.gen()).unwrap();
        pt.push(t.elapsed().as_secs_f64());
        let bytes = proof.to_bytes();
        sz = bytes.len();
        let t = Instant::now();
        spend::verify_bytes(&pi, &bytes).unwrap();
        vt.push(t.elapsed().as_secs_f64());
        last = Some(proof);
    }
    let med = |v: &mut Vec<f64>| { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] };
    let p = last.unwrap();
    println!("spend proof bytes {sz}");
    println!("spend prove median ms {:.0}", med(&mut pt) * 1e3);
    println!("spend verify median ms {:.1}", med(&mut vt) * 1e3);
    println!("proven bits (list decoding) {}", p.proven_security::<spend::Hash>().ldr_bits());
    println!("conjectured bits {}", p.conjectured_security::<spend::Hash>().bits());
    println!("trace {}x{}, constraints {}, random rows {}", spend::ROWS, spend::WIDTH, spend::N_CONSTRAINTS, spend::random_rows());
    // SHA-256d hashing rate on one core
    let mut h = Header { version: 1, prev: [1; 32], commit: [2; 32], time: 0, bits: 0x1d00ffff, nonce: 0 };
    let t = Instant::now();
    let n = 3_000_000u64;
    mine(&mut h, n);
    println!("sha256d MH/s per core {:.2}", n as f64 / t.elapsed().as_secs_f64() / 1e6);
    // verified work asymmetry
    for d in [128usize, 256, 512] {
        let a: Vec<Vec<u64>> = (0..d).map(|_| (0..d).map(|_| job::reduce(rng.gen())).collect()).collect();
        let b: Vec<Vec<u64>> = (0..d).map(|_| (0..d).map(|_| job::reduce(rng.gen())).collect()).collect();
        let t = Instant::now();
        let c = job::matmul(&a, &b);
        let ct = t.elapsed().as_secs_f64();
        let t = Instant::now();
        assert_eq!(job::freivalds(&a, &b, &c, 1), None);
        let vt = t.elapsed().as_secs_f64();
        println!("matmul {d}^3 compute ms {:.1} freivalds ms {:.2} ratio {:.0}", ct * 1e3, vt * 1e3, ct / vt);
    }
}
