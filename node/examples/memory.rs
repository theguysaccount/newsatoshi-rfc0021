//! What a node holds in memory as its chain grows, measured: every byte the program has
//! allocated and not freed, counted by its allocator.
//!
//!     cargo run --release --example memory -- [NOTES] [NULLIFIERS] [BLOCKS]
//!
//! Two parts. First, the state: a state of NOTES notes and NULLIFIERS spent nullifiers, then
//! the chain's way of keeping it, a copy per block for the last 24 blocks with a block's
//! worth of payments between each. Second, the blocks: BLOCKS blocks mined into a chain kept
//! on disk, and how many of their bodies stay in memory.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::params::{subsidy, Net, Params};
use newsatoshi::state::State;
use newsatoshi::tx::PlainOut;
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

static LIVE: AtomicIsize = AtomicIsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc_zeroed(l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> f64 {
    LIVE.load(Ordering::Relaxed) as f64 / 1e6
}

fn main() {
    let arg = |i: usize, d: usize| std::env::args().nth(i).and_then(|x| x.parse().ok()).unwrap_or(d);
    let (notes, nfs, blocks) = (arg(1, 200_000), arg(2, 200_000), arg(3, 300));
    let mut rng = rand::thread_rng();

    // the state
    let base = live();
    let mut s = State::new();
    let t0 = Instant::now();
    for _ in 0..notes {
        s.append(rng.gen());
    }
    for _ in 0..nfs {
        let n = rng.gen();
        s.nullifiers.insert(n);
        s.nf_tree.insert(n);
    }
    let one = live() - base;
    println!("one state of {notes} notes and {nfs} nullifiers: {one:.1} MB (built in {:.1} s)", t0.elapsed().as_secs_f64());
    // as the chain keeps it: the state after each of the last 24 blocks, each made by
    // copying the one before and applying a block of 17 payments (34 notes, 34 nullifiers)
    let mut kept = vec![];
    let t0 = Instant::now();
    for _ in 0..24 {
        let mut next = s.clone();
        for _ in 0..34 {
            next.append(rng.gen());
            let n = rng.gen();
            next.nullifiers.insert(n);
            next.nf_tree.insert(n);
        }
        kept.push(s);
        s = next;
    }
    let all = live() - base;
    println!(
        "the state and the 24 kept before it: {all:.1} MB, {:.1} times one state; {:.1} ms a block to copy and apply",
        all / one,
        t0.elapsed().as_secs_f64() * 1000.0 / 24.0
    );
    drop(kept);
    drop(s);

    // the blocks
    let dir = std::env::temp_dir().join(format!("ns-memory-{}", rng.gen::<u64>()));
    let w = Wallet::generate();
    let base = live();
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), Some(&dir)).unwrap();
    for _ in 0..blocks {
        let out = PlainOut { a_pk: w.a_pk(), v: subsidy(c.height() + 1), rho: rng.gen() };
        let mut b = c.template(vec![out], vec![], vec![7; 120]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        c.add_block(b).unwrap();
    }
    let disk = std::fs::metadata(dir.join("blocks.dat")).map(|m| m.len()).unwrap_or(0) as f64 / 1e6;
    println!(
        "a chain of {blocks} blocks kept on disk: {:.2} MB of blocks on disk, {:.2} MB in memory in all",
        disk,
        live() - base
    );
    drop(c);
    let _ = std::fs::remove_dir_all(&dir);
}
