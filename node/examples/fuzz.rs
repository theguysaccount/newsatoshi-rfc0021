//! A mutation fuzzer for everything a stranger can make a node parse: transactions, blocks,
//! merged-mining proofs, payment proofs, memos, addresses, condition programs, JSON, light-
//! client state and nullifier proofs. It starts from valid objects and breaks them in the
//! ways attackers do (flipped bits, huge lengths, truncation, spliced and repeated runs).
//!
//!     cargo run --release --example fuzz -- [SECONDS_PER_TARGET] [FIRST_CASE]
//!
//! A finding is any of: a panic; an allocation far larger than the input could justify; an
//! input that decodes but re-encodes differently (two encodings of one object); a broken
//! proof that still verifies; a case that takes seconds. Each prints its target and case
//! number, and the run exits with status 1. The bytes of each finding are written to
//! `target/fuzz-findings/`, and can be run again alone:
//!
//!     FUZZ_REPLAY=target/fuzz-findings/block-123.bin FUZZ_TRACE_OVER=1000000 \
//!         cargo run --release --example fuzz -- 1 0 block
//!
//! `FUZZ_TRACE_OVER` prints where every allocation above that many bytes was made.

use newsatoshi::auxpow::AuxPow;
use newsatoshi::chain::{mine, Chain};
use newsatoshi::deliver;
use newsatoshi::hash::Word8;
use newsatoshi::job::{Action, Deposit};
use newsatoshi::nftree::{self, NfTree};
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::rpc::J;
use newsatoshi::script;
use newsatoshi::spend;
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::{self, Wallet};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The largest single allocation seen since it was last reset, and a hard stop.
static BIGGEST: AtomicUsize = AtomicUsize::new(0);
static CASE: AtomicU64 = AtomicU64::new(0);
static TRACE_OVER: AtomicUsize = AtomicUsize::new(usize::MAX);
static TRACING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const HARD_LIMIT: usize = 1 << 30;

struct Guard;

fn note(n: usize) {
    BIGGEST.fetch_max(n, Ordering::Relaxed);
    if n > TRACE_OVER.load(Ordering::Relaxed) && !TRACING.swap(true, Ordering::SeqCst) {
        let _ = writeln!(std::io::stderr(), "an allocation of {n} bytes:\n{}", std::backtrace::Backtrace::force_capture());
        TRACING.store(false, Ordering::SeqCst);
    }
    if n > HARD_LIMIT {
        let _ = writeln!(std::io::stderr(), "FINDING: an allocation of {n} bytes in case {}", CASE.load(Ordering::Relaxed));
        if std::env::var_os("FUZZ_TRACE").is_some() {
            let _ = writeln!(std::io::stderr(), "{}", std::backtrace::Backtrace::force_capture());
        }
        std::process::abort();
    }
}

unsafe impl GlobalAlloc for Guard {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note(l.size());
        System.alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note(l.size());
        System.alloc_zeroed(l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        note(n);
        System.realloc(p, l, n)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
}

#[global_allocator]
static ALLOC: Guard = Guard;

const INTERESTING: [u32; 12] = [0, 1, 2, 0x7f, 0x80, 0xff, 0xffff, 0x10000, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];

/// Break `seed` the way attackers do. Several mutations may stack.
fn mutate(seed: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..rng.gen_range(1..4) {
        let n = b.len();
        match rng.gen_range(0..12) {
            0 if n > 0 => {
                for _ in 0..rng.gen_range(1..9) {
                    let i = rng.gen_range(0..n);
                    b[i] ^= 1 << rng.gen_range(0..8);
                }
            }
            1 if n >= 4 => {
                // a length or count, replaced
                let i = rng.gen_range(0..n - 3);
                let v = INTERESTING[rng.gen_range(0..INTERESTING.len())];
                b[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            2 if n >= 4 => {
                // a length or count, nudged
                let i = rng.gen_range(0..n - 3);
                let v = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()).wrapping_add(rng.gen_range(0..5u32).wrapping_sub(2));
                b[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            3 if n > 0 => b.truncate(rng.gen_range(0..n)),
            4 => b.extend((0..rng.gen_range(1..64)).map(|_| rng.gen::<u8>())),
            5 if n > 8 => {
                // a run copied over another
                let len = rng.gen_range(1..(n / 2).min(4096) + 1);
                let (from, to) = (rng.gen_range(0..n - len + 1), rng.gen_range(0..n - len + 1));
                let run = b[from..from + len].to_vec();
                b[to..to + len].copy_from_slice(&run);
            }
            6 if n > 8 => {
                // a run repeated in place
                let len = rng.gen_range(1..(n / 2).min(2048) + 1);
                let at = rng.gen_range(0..n - len + 1);
                let run = b[at..at + len].to_vec();
                b.splice(at..at, run);
            }
            7 if n > 8 => {
                let len = rng.gen_range(1..(n / 2).min(4096) + 1);
                let at = rng.gen_range(0..n - len + 1);
                b.drain(at..at + len);
            }
            8 if n > 0 => {
                let i = rng.gen_range(0..n);
                b[i] = [0u8, 1, 2, 0x7f, 0x80, 0xfe, 0xff][rng.gen_range(0..7)];
            }
            9 if n > 16 => {
                let len = rng.gen_range(1..(n / 4).min(512) + 1);
                let at = rng.gen_range(0..n - len + 1);
                let fill = [0u8, 0xff][rng.gen_range(0..2)];
                b[at..at + len].iter_mut().for_each(|x| *x = fill);
            }
            10 if n >= 8 => {
                let i = rng.gen_range(0..n - 7);
                let v: u64 = [0, u64::MAX, 1 << 63, (1 << 60) - 1, 1 << 60, 0xffff_ffff_0000_0001, 0xffff_ffff_0000_0000][rng.gen_range(0..7)];
                b[i..i + 8].copy_from_slice(&v.to_le_bytes());
            }
            _ if n > 0 => {
                let i = rng.gen_range(0..n);
                b[i] = rng.gen();
            }
            _ => b.push(rng.gen()),
        }
    }
    b
}

struct Target {
    name: &'static str,
    seeds: Vec<Vec<u8>>,
    /// Err describes a finding.
    run: Box<dyn Fn(&[u8]) -> Result<(), String>>,
    /// How large an allocation one case may make.
    alloc_limit: usize,
}

fn word8(b: &[u8]) -> Word8 {
    let mut w = [0u32; 8];
    for (i, c) in b.chunks(4).take(8).enumerate() {
        let mut x = [0u8; 4];
        x[..c.len()].copy_from_slice(c);
        w[i] = u32::from_be_bytes(x);
    }
    w
}

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|x| x.parse().ok()).unwrap_or(20);
    let first: u64 = std::env::args().nth(2).and_then(|x| x.parse().ok()).unwrap_or(0);
    let only = std::env::args().nth(3);

    // real objects to start from: a funded chain, a payment, a merge-mined block, a lock, a
    // condition and its release
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    let mut blocks = vec![];
    let mine_on = |c: &mut Chain, to: &Wallet, txs: Vec<Tx>| {
        let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
        let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
        let mut b = c.template(vec![out], txs, b"fuzz".to_vec()).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        c.add_block(b.clone()).unwrap();
        b
    };
    for _ in 0..3 {
        blocks.push(mine_on(&mut c, &alice, vec![]));
    }
    let (pay, _) = alice.pay(&c, &bob.delivery_address(), COIN, DEFAULT_FEE, b"hello".to_vec()).unwrap();
    blocks.push(mine_on(&mut c, &alice, vec![pay.clone()]));
    let lock_post = newsatoshi::lock::LockPost { hash: [7; 32], timeout: c.height() + 50, claim_addr: bob.a_pk(), refund_addr: alice.a_pk(), amount: COIN };
    let (locked, _) = alice.spend(&c, None, DEFAULT_FEE, Some(Deposit::Lock(lock_post)), vec![]).unwrap();
    blocks.push(mine_on(&mut c, &alice, vec![locked.clone()]));
    let program = script::assemble("SHA256 0707070707070707070707070707070707070707070707070707070707070707 EQUAL").unwrap_or_else(|_| vec![0xa8, 0x87]);
    let salt = [9u8; 32];
    let cond_post = newsatoshi::cond::CondPost { commitment: newsatoshi::cond::commitment(&salt, &program), payouts: vec![bob.a_pk(), alice.a_pk()], timeout: c.height() + 50, refund_addr: alice.a_pk(), amount: COIN };
    let (conded, _) = alice.spend(&c, None, DEFAULT_FEE, Some(Deposit::Cond(cond_post)), vec![]).unwrap();
    blocks.push(mine_on(&mut c, &alice, vec![conded.clone()]));
    let acts = vec![
        Tx::Act(Action::Unlock { lock: [1; 32], preimage: [2; 32] }),
        Tx::Act(Action::Expire { lock: [3; 32] }),
        Tx::Act(Action::Fulfil { cond: [4; 32], payout: 1, salt, program: program.clone(), witness: vec![vec![1, 2, 3], vec![], vec![0xff; 40]] }),
    ];
    let Tx::Spend(sp) = &pay else { unreachable!() };
    let pi = sp.public().unwrap();
    spend::verify_bytes(&pi, &sp.proof).unwrap();
    let proof = sp.proof.clone();
    let tx_seeds: Vec<Vec<u8>> = [pay.clone(), locked, conded].iter().chain(acts.iter()).map(|t| t.to_bytes()).chain(blocks.iter().map(|b| b.txs[0].to_bytes())).collect();
    let block_seeds: Vec<Vec<u8>> = blocks.iter().map(|b| b.encode()).collect();

    // a merge-mined block's proof, made as a pool would make it
    let aux_seed: Option<Vec<u8>> = Some(pool_auxpow(&blocks[0].hash(), blocks[0].header.bits));

    // a nullifier tree with some spent, for proofs of spent and unspent
    let mut nft = NfTree::new();
    let spent: Vec<Word8> = (0..24).map(|_| rand::random()).collect();
    for n in &spent {
        nft.insert(*n);
    }
    let unspent: Vec<Word8> = (0..24).map(|_| rand::random()).collect();
    let nf_root = nft.root();
    let nf_seeds: Vec<Vec<u8>> = spent
        .iter()
        .chain(unspent.iter())
        .map(|n| {
            let p = nft.prove(n);
            let mut w = newsatoshi::codec::Writer::new();
            w.word8(n).u32(p.index).word8(&p.value).word8(&p.next);
            for x in &p.path {
                w.word8(x);
            }
            w.0
        })
        .collect();
    let spent_set: std::collections::HashSet<Word8> = spent.iter().copied().collect();

    let scanner = deliver::Scanner::new(&bob.sk);
    let memo = sp.memo.clone();
    let cm0 = sp.cm_out[0];

    let mut targets: Vec<Target> = vec![
        Target {
            name: "transaction",
            seeds: tx_seeds,
            alloc_limit: 4 << 20,
            run: Box::new(|b| match Tx::from_bytes(b) {
                Err(_) => Ok(()),
                Ok(t) => {
                    if t.to_bytes() != b {
                        return Err("decodes, but encodes differently".into());
                    }
                    let _ = t.id();
                    if let Tx::Spend(s) = &t {
                        let _ = s.public();
                        let _ = deliver::unpack_memo(&s.memo);
                    }
                    Ok(())
                }
            }),
        },
        Target {
            name: "block",
            seeds: block_seeds,
            alloc_limit: 8 << 20,
            run: Box::new(|b| match Block::decode(b) {
                Err(_) => Ok(()),
                Ok(blk) => {
                    if blk.encode() != b {
                        return Err("decodes, but encodes differently".into());
                    }
                    let _ = blk.tx_root();
                    let _ = newsatoshi::chain::check_work(&blk);
                    Ok(())
                }
            }),
        },
        Target {
            name: "payment proof",
            seeds: vec![proof.clone()],
            alloc_limit: 64 << 20,
            run: {
                let (pi, proof) = (pi.clone(), proof.clone());
                Box::new(move |b| match spend::verify_bytes(&pi, b) {
                    Err(_) => Ok(()),
                    Ok(()) if b == proof.as_slice() => Ok(()),
                    Ok(()) => Err("a changed proof still verifies".into()),
                })
            },
        },
        Target {
            name: "memo and envelope",
            seeds: vec![memo.clone(), memo[5..].to_vec(), vec![]],
            alloc_limit: 1 << 20,
            run: Box::new(move |b| {
                let (env, _text) = deliver::unpack_memo(b);
                for e in env.iter().flatten() {
                    let _ = scanner.open(&cm0, e);
                }
                let _ = scanner.open(&cm0, b);
                Ok(())
            }),
        },
        Target {
            name: "address and note string",
            seeds: vec![alice.address().into_bytes(), alice.delivery_address().into_bytes(), wallet::encode_note(&bob.a_pk(), 5, &[1, 2, 3, 4, 5]).into_bytes(), b"ns1".to_vec(), b"nsd1".to_vec()],
            alloc_limit: 1 << 20,
            run: Box::new(|b| {
                let s = String::from_utf8_lossy(b);
                if let Ok(a) = wallet::parse_address(&s) {
                    if wallet::encode_address(&a) != s {
                        return Err("an address that parses but is not written that way".into());
                    }
                }
                let _ = deliver::parse_any_address(&s);
                let _ = deliver::parse_delivery_address(&s);
                let _ = wallet::parse_note(&s);
                Ok(())
            }),
        },
        Target {
            name: "condition program",
            seeds: vec![program.clone(), script::assemble("2 PAYOUT EQUAL").unwrap_or_default(), (0u8..=255).collect(), vec![0xa8; 300]],
            alloc_limit: 4 << 20,
            run: Box::new(|b| {
                // the first bytes choose the witness, the rest are the program
                let k = (b.first().copied().unwrap_or(0) % 5) as usize;
                let witness: Vec<Vec<u8>> = (0..k).map(|i| b.iter().skip(i).step_by(k.max(1)).take(70).copied().collect()).collect();
                let msg = [5u8; 32];
                let t0 = Instant::now();
                let _ = script::run(b, &witness, &script::Ctx { height: 100, payout: 1, msg: &msg });
                if t0.elapsed() > Duration::from_millis(1500) {
                    return Err(format!("a program ran for {:?}", t0.elapsed()));
                }
                let _ = script::assemble(&String::from_utf8_lossy(b));
                Ok(())
            }),
        },
        Target {
            name: "json",
            seeds: vec![br#"{"jsonrpc":"1.0","id":"x\"1","method":"submitauxblock","params":["ab", 12, -3.5e2, true, null, [], {"k":[1,{"z":"\u00e9"}]}]}"#.to_vec(), b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[".to_vec(), br#""\ud800\udc00\u0000""#.to_vec()],
            alloc_limit: 4 << 20,
            run: Box::new(|b| match J::parse(b) {
                Err(_) => Ok(()),
                Ok(v) => match J::parse(v.to_json().as_bytes()) {
                    Ok(again) if again == v => Ok(()),
                    _ => Err("json that parses is written back as something else".into()),
                },
            }),
        },
        Target {
            name: "light client state",
            seeds: vec![newsatoshi::light::HeaderTip::genesis(&Params::get(Net::Reg).unwrap()).to_bytes()],
            alloc_limit: 1 << 20,
            run: Box::new(|b| match newsatoshi::light::HeaderTip::from_bytes(b) {
                Err(_) => Ok(()),
                Ok(t) => {
                    if t.to_bytes() != b {
                        return Err("decodes, but encodes differently".into());
                    }
                    Ok(())
                }
            }),
        },
        Target {
            name: "nullifier proof",
            seeds: nf_seeds,
            alloc_limit: 1 << 20,
            run: Box::new(move |b| {
                let mut r = newsatoshi::codec::Reader::new(b);
                let (Ok(nf), Ok(index), Ok(value), Ok(next)) = (r.word8(), r.u32(), r.word8(), r.word8()) else { return Ok(()) };
                let mut path = [[0u32; 8]; newsatoshi::note::DEPTH];
                for p in path.iter_mut() {
                    match r.word8() {
                        Ok(w) => *p = w,
                        Err(_) => return Ok(()),
                    }
                }
                // whatever is done to a proof, it never shows a spent coin unspent or an
                // unspent one spent
                match nftree::check(&nf_root, &nf, &nftree::NfProof { index, value, next, path }) {
                    Some(true) if !spent_set.contains(&nf) => Err("an unspent nullifier was shown spent".into()),
                    Some(false) if spent_set.contains(&nf) => Err("a spent nullifier was shown unspent".into()),
                    _ => Ok(()),
                }
            }),
        },
    ];
    if let Some(a) = aux_seed {
        targets.push(Target {
            name: "merged-mining proof",
            seeds: vec![a],
            alloc_limit: 4 << 20,
            run: Box::new(|b| match AuxPow::parse(b) {
                Err(_) => Ok(()),
                Ok(a) => {
                    if a.to_bytes() != b {
                        return Err("decodes, but encodes differently".into());
                    }
                    let _ = a.check(&word8_bytes(b), newsatoshi::auxpow::CHAIN_ID);
                    let _ = a.parent_hash();
                    Ok(())
                }
            }),
        });
    }

    std::panic::set_hook(Box::new(|_| {}));
    let mut findings = 0;
    let out = std::path::Path::new("target/fuzz-findings");
    let replay = std::env::var("FUZZ_REPLAY").ok().map(|f| std::fs::read(f).expect("the file to replay"));
    for t in &targets {
        if only.as_deref().is_some_and(|o| o != t.name) {
            continue;
        }
        if let Some(input) = &replay {
            if let Some(n) = std::env::var("FUZZ_TRACE_OVER").ok().and_then(|x| x.parse().ok()) {
                TRACE_OVER.store(n, Ordering::Relaxed);
            }
            BIGGEST.store(0, Ordering::Relaxed);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (t.run)(input)));
            TRACE_OVER.store(usize::MAX, Ordering::Relaxed);
            println!("{}: {} bytes · largest allocation {} · {:?}", t.name, input.len(), BIGGEST.load(Ordering::Relaxed), r.map_err(|_| "panic"));
            continue;
        }
        let t0 = Instant::now();
        let (mut n, mut slowest) = (first, Duration::ZERO);
        let mut seen = std::collections::HashSet::new();
        while t0.elapsed() < Duration::from_secs(secs) {
            let mut rng = StdRng::seed_from_u64(n);
            let seed = &t.seeds[rng.gen_range(0..t.seeds.len())];
            let input = if n % 50 == 0 { (0..rng.gen_range(0..2048)).map(|_| rng.gen()).collect() } else { mutate(seed, &mut rng) };
            CASE.store(n, Ordering::Relaxed);
            BIGGEST.store(0, Ordering::Relaxed);
            let c0 = Instant::now();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (t.run)(&input)));
            let took = c0.elapsed();
            slowest = slowest.max(took);
            let big = BIGGEST.load(Ordering::Relaxed);
            let finding = match r {
                Err(p) => Some(format!("panic: {}", p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default())),
                Ok(Err(e)) => Some(e),
                Ok(Ok(())) if big > t.alloc_limit.max(64 * input.len()) => Some(format!("an allocation of {big} bytes for an input of {}", input.len())),
                Ok(Ok(())) if took > Duration::from_secs(3) => Some(format!("took {took:?}")),
                _ => None,
            };
            if let Some(f) = finding {
                let key: String = f.chars().take(60).collect();
                if seen.insert(key) {
                    findings += 1;
                    let file = out.join(format!("{}-{n}.bin", t.name.replace(' ', "-")));
                    let _ = std::fs::create_dir_all(out).and_then(|_| std::fs::write(&file, &input));
                    println!("FINDING in {}: case {n}: {f} · saved to {}", t.name, file.display());
                }
            }
            n += 1;
        }
        println!("{:<24} {:>9} cases in {:>3} s · slowest {:?}", t.name, n - first, t0.elapsed().as_secs(), slowest);
    }
    if findings > 0 {
        println!("{findings} findings");
        std::process::exit(1);
    }
    println!("no findings");
}

/// The proof a pool would make for one chain: a Bitcoin coinbase carrying the commitment,
/// one more transaction beside it, and a Bitcoin header that meets `bits`.
fn pool_auxpow(aux_hash: &[u8; 32], bits: u32) -> Vec<u8> {
    use newsatoshi::auxpow::{merkle_branch, parse_tx, MERGED_MINING_HEADER};
    let mut root = *aux_hash;
    root.reverse();
    let mut script = vec![3, 0x81, 0xe0, 0x0e];
    script.extend_from_slice(&MERGED_MINING_HEADER);
    script.extend_from_slice(&root);
    script.extend_from_slice(&1u32.to_le_bytes());
    script.extend_from_slice(&0u32.to_le_bytes());
    script.extend_from_slice(b"/pool/");
    let mut t = vec![];
    t.extend_from_slice(&1u32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(script.len() as u8);
    t.extend_from_slice(&script);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&(50 * 100_000_000u64).to_le_bytes());
    t.extend_from_slice(&[1, 0x51]);
    t.extend_from_slice(&0u32.to_le_bytes());
    let mut a = AuxPow { coinbase: t, unused_hash: [0; 32], coinbase_branch: vec![[9u8; 32]], coinbase_index: 0, chain_branch: vec![], chain_index: 0, parent: [0; 80] };
    let txid = parse_tx(&a.coinbase).unwrap().txid;
    let mroot = merkle_branch(txid, &a.coinbase_branch, 0);
    a.parent[0..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    a.parent[4..36].copy_from_slice(&[7u8; 32]);
    a.parent[36..68].copy_from_slice(&mroot);
    a.parent[68..72].copy_from_slice(&1_780_000_000u32.to_le_bytes());
    a.parent[72..76].copy_from_slice(&0x1702_3a5bu32.to_le_bytes());
    for nonce in 0u32.. {
        a.parent[76..80].copy_from_slice(&nonce.to_le_bytes());
        if newsatoshi::pow::meets(&newsatoshi::hash::sha256d(&a.parent), bits) {
            break;
        }
    }
    assert!(a.check(aux_hash, newsatoshi::auxpow::CHAIN_ID).is_ok());
    a.to_bytes()
}

fn word8_bytes(b: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, x) in b.iter().take(32).enumerate() {
        h[i] = *x;
    }
    let _ = word8(&h);
    h
}
