//! Regressions for the pre-release adversarial review (findings F1, F2, S1, M1, M2, M6,
//! M7 and M11 of the attack log), plus chain sync across a fork longer than one batch.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::job::{self, Action, Job, JobClaim, JobKey, JobPost, Phase, RowOpening};
use newsatoshi::node::{self, lock, Msg, Node};
use newsatoshi::note::MAX_NOTE_VALUE;
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE, MAX_TX_BYTES};
use newsatoshi::spend::{self, SpendPublic, MAX_PROOF_BYTES};
use newsatoshi::tx::{Block, PlainOut, Spend, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn fees(txs: &[Tx]) -> u64 {
    txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum()
}

fn mine_on(c: &mut Chain, to: &Wallet, txs: Vec<Tx>) -> Block {
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees(&txs), rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], txs, vec![]).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(c.add_block(b.clone()).unwrap(), "block did not become tip");
    b
}

fn regtest() -> Chain {
    Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A funded regtest chain and one real spend from a fresh wallet.
fn funded_spend(fee: u64) -> (Chain, Tx) {
    let mut c = regtest();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for _ in 0..2 {
        mine_on(&mut c, &alice, vec![]);
    }
    let (tx, _) = alice.spend(&c, Some((bob.a_pk(), COIN)), fee, None, vec![]).unwrap();
    (c, tx)
}

/// The reviewer's attack: a spend whose "proof" is six bytes claiming log2(length) = 64.
fn poison_spend(c: &Chain) -> Tx {
    let mut rng = rand::thread_rng();
    Tx::Spend(Spend {
        anchor: c.state.tree.root(),
        nf: [rng.gen(), rng.gen()],
        cm_out: [rng.gen(), rng.gen()],
        dummy: [false, true],
        fee: DEFAULT_FEE,
        deposit: None,
        memo: vec![],
        proof: vec![1, 0, 0, 64, 0, 0],
    })
}

#[test]
fn f1_malformed_proofs_are_rejected_without_panicking() {
    let (_c, tx) = funded_spend(DEFAULT_FEE);
    let Tx::Spend(sp) = &tx else { panic!() };
    let pi = sp.public().unwrap();
    spend::verify_bytes(&pi, &sp.proof).unwrap();
    assert!(sp.proof.starts_with(&spend::context_prefix(&pi)), "the prefix is what the prover writes");
    let mut cases: Vec<Vec<u8>> = vec![vec![1, 0, 0, 64, 0, 0], vec![], vec![247]];
    let mut width = sp.proof.clone();
    width[0] = 246; // the reviewer's a2: trips SpendAir::new's width assertion if parsed
    cases.push(width);
    let mut log_len = sp.proof.clone();
    log_len[3] = 64; // 2^64 wraps to 0 inside Winterfell's decoder
    cases.push(log_len);
    cases.push(sp.proof[..sp.proof.len() / 2].to_vec());
    let mut junk = spend::context_prefix(&pi);
    junk.extend((0..5000).map(|_| rand::random::<u8>()));
    cases.push(junk);
    for i in (0..sp.proof.len()).step_by(4999) {
        let mut b = sp.proof.clone();
        b[i] ^= 0x5a;
        cases.push(b);
    }
    for (i, bad) in cases.iter().enumerate() {
        assert!(spend::verify_bytes(&pi, bad).is_err(), "case {i} accepted");
    }
}

#[test]
fn f1_poison_transactions_over_tcp_leave_the_node_alive() {
    let p = Params::get(Net::Reg).unwrap();
    let magic = p.magic;
    let c = Chain::open(p, None).unwrap();
    let tx = poison_spend(&c);
    let shared = Node::new(c);
    lock(&shared).log = false;
    let port = free_port();
    node::listen(shared.clone(), port).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    for _ in 0..3 {
        s.write_all(&Msg::Tx(tx.clone()).encode(magic)).unwrap();
    }
    std::thread::sleep(Duration::from_millis(800));
    assert!(shared.lock().is_ok(), "the node's lock was poisoned");
    assert_eq!(lock(&shared).mempool_len(), 0);
    // still serving: a new connection is greeted
    let mut s2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert!(matches!(Msg::read(&mut s2, magic, 8_000_000).unwrap(), Msg::Hello { .. }));
}

#[test]
fn f1_a_mined_poison_block_is_refused_and_never_written_to_disk() {
    let dir = std::env::temp_dir().join(format!("ns-attack-{}", rand::thread_rng().gen::<u64>()));
    let p = Params::get(Net::Reg).unwrap();
    let mut c = Chain::open(p.clone(), Some(&dir)).unwrap();
    let alice = Wallet::generate();
    mine_on(&mut c, &alice, vec![]);
    // templates skip proof checks, so the block can be built and mined
    let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(c.height() + 1), rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], vec![poison_spend(&c)], vec![]).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    let (height, tip) = (c.height(), c.tip().hash);
    assert!(c.add_block(b.clone()).is_err());
    assert_eq!(c.tip().hash, tip);
    drop(c);
    let c2 = Chain::open(p, Some(&dir)).unwrap();
    assert_eq!((c2.height(), c2.tip().hash), (height, tip));
    assert!(!c2.has(&b.hash()), "the refused block was replayed from disk");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn f2_padded_and_oversized_transactions_are_refused_everywhere() {
    let (c, tx) = funded_spend(DEFAULT_FEE);
    let Tx::Spend(sp) = &tx else { panic!() };
    let pi = sp.public().unwrap();
    // M1: padding no longer makes a second valid proof (or a second transaction id)
    let mut padded = sp.proof.clone();
    padded.extend([0xAB; 1000]);
    assert!(spend::verify_bytes(&pi, &padded).is_err());
    // a proof over this network's limit is refused by the pool and by a block; one over
    // the largest any network takes does not even decode
    let mut big = sp.clone();
    big.proof.resize(MAX_PROOF_BYTES + 1, 0);
    let big = Tx::Spend(big);
    let mut bigger = sp.clone();
    bigger.proof.resize(spend::PROOF_BYTES_CAP + 1, 0);
    assert!(Tx::from_bytes(&Tx::Spend(bigger).to_bytes()).is_err());
    let shared = Node::new(c);
    let mut n = lock(&shared);
    n.log = false;
    assert!(n.accept_tx(big.clone()).is_err());
    assert!(n.chain.template(vec![], vec![big], vec![]).is_err());
    // a transaction over the network's limit is refused by block validation itself, and
    // one over the largest any network takes does not decode: no miner can produce a block
    // its peers cannot read
    let respond = |k: u32| Tx::Act(Action::Respond { job: [9; 32], rows: (0..k).map(|i| RowOpening { i, values: vec![1; 4096], path: vec![] }).collect() });
    let huge = respond(16);
    assert!(huge.to_bytes().len() > MAX_TX_BYTES);
    assert!(respond(24).to_bytes().len() > newsatoshi::params::TX_BYTES_CAP);
    assert!(Tx::from_bytes(&respond(24).to_bytes()).is_err());
    let err = n.chain.template(vec![], vec![huge.clone()], vec![]).unwrap_err();
    assert!(err.contains("exceeds"), "{err}");
    assert!(n.accept_tx(huge).is_err());
    // the honest spend still goes through, and only once
    assert!(n.accept_tx(tx.clone()).unwrap());
    assert!(!n.accept_tx(tx).unwrap());
}

#[test]
fn s1_a_job_whose_challenge_cannot_be_answered_cannot_be_posted() {
    let k = JobKey::generate();
    let mk = |n: u32, m: u32| JobPost {
        poster_vk: k.vk(),
        poster_addr: [1; 8],
        n,
        k: 1,
        m,
        a_root: [0; 32],
        b_root: [0; 32],
        pay: COIN,
        bond_min: COIN,
        claim_by: 10,
        deliver_blocks: 5,
        window_blocks: 3,
    };
    // the reviewer's a6: n = 16, m = 4096 needs a 526,566-byte answer
    assert_eq!(job::max_respond_bytes(16, 4096), 526_566);
    assert!(job::check_post(&mk(16, 4096), 1).is_err());
    job::check_post(&mk(4096, 3075), 1).unwrap();
    assert!(job::check_post(&mk(4096, 3076), 1).is_err());
    // the bound is the exact size of a full answer
    let rows: Vec<RowOpening> = (0..16).map(|i| RowOpening { i, values: vec![7; 3000], path: vec![[0; 32]; 4] }).collect();
    let answer = Tx::Act(Action::Respond { job: [3; 32], rows });
    assert_eq!(answer.to_bytes().len(), job::max_respond_bytes(16, 3000));
}

#[test]
fn m6_pay_plus_bond_beyond_one_note_is_refused() {
    let k = JobKey::generate();
    let post = |pay: u64, bond_min: u64| JobPost {
        poster_vk: k.vk(),
        poster_addr: [1; 8],
        n: 4,
        k: 4,
        m: 4,
        a_root: [0; 32],
        b_root: [0; 32],
        pay,
        bond_min,
        claim_by: 10,
        deliver_blocks: 5,
        window_blocks: 3,
    };
    assert!(job::check_post(&post(MAX_NOTE_VALUE / 2 + 1, MAX_NOTE_VALUE / 2 + 1), 1).is_err());
    let ok = post(1 << 58, 1 << 58);
    job::check_post(&ok, 1).unwrap();
    let mut j = Job { id: [1; 32], post: ok, posted_at: 1, phase: Phase::Open };
    let claim = JobClaim { job: [1; 32], worker_vk: k.vk(), worker_addr: [2; 8], bond: MAX_NOTE_VALUE };
    assert!(job::apply_claim(&mut j, &claim, 2).is_err());
}

#[test]
fn m7_value_balance_outside_the_field_encoding_is_refused() {
    for vb in [i64::MIN, -(1i64 << 62), 1i64 << 62, i64::MAX] {
        let pi = SpendPublic { root: [0; 8], nf: [[1; 8], [2; 8]], cm_out: [[3; 8], [4; 8]], value_balance: vb, dummy: [false, true], bind: [0; 8] };
        let e = spend::verify_bytes(&pi, &spend::context_prefix(&pi)).unwrap_err();
        assert!(e.contains("value balance"), "{e}");
    }
}

#[test]
fn m11_double_spends_are_refused_in_a_block_across_blocks_and_in_the_mempool() {
    let mut c = regtest();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        mine_on(&mut c, &alice, vec![]);
    }
    // two different payments from the same note
    let mut twin = alice.clone();
    let (t1, _) = alice.spend(&c, Some((bob.a_pk(), COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let (t2, _) = twin.spend(&c, Some((bob.a_pk(), 2 * COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let (Tx::Spend(s1), Tx::Spend(s2)) = (&t1, &t2) else { panic!() };
    assert_eq!(s1.nf[0], s2.nf[0], "both spend the same note");
    assert_ne!(t1.id(), t2.id());
    // in one block: two transactions, or one transaction twice
    assert!(c.template(vec![], vec![t1.clone(), t2.clone()], vec![]).unwrap_err().contains("double spend"));
    assert!(c.template(vec![], vec![t1.clone(), t1.clone()], vec![]).unwrap_err().contains("double spend"));
    // one transaction naming the same nullifier for both inputs
    let mut s3 = s2.clone();
    s3.dummy = [false, false];
    s3.nf[1] = s3.nf[0];
    assert!(c.template(vec![], vec![Tx::Spend(s3)], vec![]).unwrap_err().contains("double spend"));
    // in the mempool, the second is refused while the first waits
    let shared = Node::new(c);
    let mut n = lock(&shared);
    n.log = false;
    assert!(n.accept_tx(t1.clone()).unwrap());
    assert!(n.accept_tx(t2.clone()).unwrap_err().contains("double spend"));
    // once the first is mined, the second is refused in any later block and by the mempool
    let picked = n.select();
    assert_eq!(picked, vec![t1.clone()]);
    mine_on(&mut n.chain, &miner, picked);
    assert!(n.chain.template(vec![], vec![t2.clone()], vec![]).unwrap_err().contains("double spend"));
    assert!(n.accept_tx(t2).unwrap_err().contains("double spend"));
}

#[test]
fn m2_the_mempool_charges_the_relay_fee_and_blocks_fill_by_fee_rate() {
    let mut c = regtest();
    let (mut a, mut b, mut d) = (Wallet::generate(), Wallet::generate(), Wallet::generate());
    let bob = Wallet::generate();
    for w in [&a, &b, &d, &bob] {
        mine_on(&mut c, w, vec![]);
    }
    let (cheap, _) = a.spend(&c, Some((bob.a_pk(), COIN)), 1_000, None, vec![]).unwrap();
    let (low, _) = b.spend(&c, Some((bob.a_pk(), COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let (high, _) = d.spend(&c, Some((bob.a_pk(), COIN)), 3 * DEFAULT_FEE, None, vec![]).unwrap();
    let shared = Node::new(c);
    let mut n = lock(&shared);
    n.log = false;
    assert!(n.accept_tx(cheap).unwrap_err().contains("minimum relay fee"));
    assert!(n.accept_tx(low.clone()).unwrap());
    assert!(n.accept_tx(high.clone()).unwrap());
    assert_eq!(n.select(), vec![high, low], "highest fee rate first");
}

#[test]
fn sync_follows_a_fork_longer_than_one_batch() {
    let mut a = regtest();
    let mut b = regtest();
    let w = Wallet::generate();
    for _ in 0..5 {
        let blk = mine_on(&mut a, &w, vec![]);
        assert!(b.add_block(blk).unwrap());
    }
    for _ in 0..3 {
        mine_on(&mut a, &w, vec![]);
    }
    for _ in 0..40 {
        mine_on(&mut b, &w, vec![]);
    }
    // a pulls from b in batches of a few blocks, always from the last block it was given
    let mut from = a.tip().hash;
    let mut rounds = 0;
    while a.tip().hash != b.tip().hash {
        let batch = b.blocks_after(&a.locator(&from), 500);
        assert!(!batch.is_empty() && batch.len() < 10);
        for blk in batch {
            from = blk.hash();
            let _ = a.add_block(blk);
        }
        rounds += 1;
        assert!(rounds < 60, "sync is not making progress");
    }
    assert_eq!(a.height(), 45);
}

#[test]
fn two_nodes_converge_over_tcp() {
    let mut ca = regtest();
    let w = Wallet::generate();
    for _ in 0..12 {
        mine_on(&mut ca, &w, vec![]);
    }
    let a = Node::new(ca);
    let b = Node::new(regtest());
    lock(&a).log = false;
    lock(&b).log = false;
    let port = free_port();
    node::listen(a.clone(), port).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    node::connect(b.clone(), &format!("127.0.0.1:{port}")).unwrap();
    let t0 = Instant::now();
    loop {
        let (ta, tb) = (lock(&a).chain.tip().hash, lock(&b).chain.tip().hash);
        if ta == tb {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "nodes did not converge");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(lock(&b).chain.height(), 12);
}
