use newsatoshi::chain::{mine, Chain};
use newsatoshi::job::{self, Action, Deposit, JobClaim, JobKey, JobPost, Phase, RowOpening};
use newsatoshi::params::{subsidy, Net, Params, COIN};
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

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

fn rand_matrix(rows: usize, cols: usize) -> Vec<Vec<u64>> {
    let mut rng = rand::thread_rng();
    (0..rows).map(|_| (0..cols).map(|_| rng.gen_range(0..u64::MAX - u32::MAX as u64)).collect()).collect()
}

#[test]
fn regtest_end_to_end() {
    let p = Params::get(Net::Reg).unwrap();
    let mut c = Chain::open(p, None).unwrap();
    let mut alice = Wallet::generate();
    let mut bob = Wallet::generate();
    let miner = Wallet::generate();

    for _ in 0..3 {
        mine_on(&mut c, &alice, vec![]);
    }
    // maturity 1: rewards of blocks 1 and 2 are spendable, block 3's is pending
    assert_eq!(alice.balance(&c), 100 * COIN);

    // ---- a private payment -------------------------------------------------------------
    let (tx, note) = alice.spend(&c, Some((bob.a_pk(), 1_250_000_000)), 10_000, None, b"first".to_vec()).unwrap();
    mine_on(&mut c, &miner, vec![tx]);
    assert_eq!(bob.balance(&c), 0, "the payee sees nothing until handed the note");
    bob.import(&note.unwrap()).unwrap();
    assert_eq!(bob.balance(&c), 1_250_000_000);
    assert_eq!(alice.balance(&c), 50 * COIN + 50 * COIN + (50 * COIN - 1_250_000_000 - 10_000));
    // supply is auditable: issued − burned − locked
    assert_eq!(c.state.issued, (4 * 50 * COIN) as u128);

    // ---- a job with a cheating worker --------------------------------------------------
    let a = rand_matrix(6, 5);
    let b_cols = rand_matrix(4, 5);
    let ak = JobKey::from_bytes(&alice.job_key).unwrap();
    let bk = JobKey::from_bytes(&bob.job_key).unwrap();
    let post = JobPost {
        poster_vk: ak.vk(),
        poster_addr: alice.a_pk(),
        n: 6,
        k: 5,
        m: 4,
        a_root: job::root_of(&a),
        b_root: job::root_of(&b_cols),
        pay: 2 * COIN,
        bond_min: 2 * COIN,
        claim_by: c.height() + 20,
        deliver_blocks: 5,
        window_blocks: 3,
    };
    let (tx, _) = alice.spend(&c, None, 1000, Some(Deposit::Post(post.clone())), vec![]).unwrap();
    let Tx::Spend(sp) = &tx else { panic!() };
    let id = job::job_id(&post, &sp.nf[0]);
    mine_on(&mut c, &miner, vec![tx]);
    assert_eq!(c.state.locked, (2 * COIN) as u128);

    let claim = JobClaim { job: id, worker_vk: bk.vk(), worker_addr: bob.a_pk(), bond: 2 * COIN };
    let (tx, _) = bob.spend(&c, None, 1000, Some(Deposit::Claim(claim)), vec![]).unwrap();
    mine_on(&mut c, &miner, vec![tx]);
    assert_eq!(c.state.locked, (4 * COIN) as u128);

    // the worker cheats on one entry
    let mut cm = job::matmul(&a, &b_cols);
    cm[2][3] = job::reduce(cm[2][3].wrapping_add(1));
    let c_root = job::root_of(&cm);
    let commit = Tx::Act(Action::Commit { job: id, c_root, sig: bk.sign(&job::msg_commit(&id, &c_root)) });
    mine_on(&mut c, &miner, vec![commit]);

    // the poster checks privately with Freivalds and finds the wrong entry
    let (i, j) = job::freivalds(&a, &b_cols, &cm, 2).expect("Freivalds catches the forgery");
    assert_eq!((i, j), (2, 3));
    let lv = |rows: &Vec<Vec<u64>>| job::tree_levels(&rows.iter().map(|r| job::leaf(r)).collect::<Vec<_>>());
    let open = |rows: &Vec<Vec<u64>>, i: u32| RowOpening { i, values: rows[i as usize].clone(), path: job::path_of(&lv(rows), i as usize) };
    let fraud = Tx::Act(Action::Fraud { job: id, a: open(&a, i), b: open(&b_cols, j), c: open(&cm, i), j });
    let burned_before = c.state.burned;
    mine_on(&mut c, &miner, vec![fraud]);
    assert_eq!(c.state.jobs[&id].phase, Phase::Closed { paid_worker: false });
    assert_eq!(c.state.burned - burned_before, (2 * COIN) as u128, "the bond is burned");
    assert_eq!(c.state.locked, 0);
    // the refund is a note alice can spend
    let refund = c.state.public_notes[&alice.a_pk()].iter().any(|(v, _)| *v == 2 * COIN);
    assert!(refund);

    // a false fraud claim is rejected
    // ---- a job with an honest worker ---------------------------------------------------
    let post2 = JobPost { claim_by: c.height() + 20, ..post.clone() };
    let (tx, _) = alice.spend(&c, None, 1000, Some(Deposit::Post(post2.clone())), vec![]).unwrap();
    let Tx::Spend(sp) = &tx else { panic!() };
    let id2 = job::job_id(&post2, &sp.nf[0]);
    mine_on(&mut c, &miner, vec![tx]);
    let claim = JobClaim { job: id2, worker_vk: bk.vk(), worker_addr: bob.a_pk(), bond: 2 * COIN };
    let (tx, _) = bob.spend(&c, None, 1000, Some(Deposit::Claim(claim)), vec![]).unwrap();
    mine_on(&mut c, &miner, vec![tx]);
    let good = job::matmul(&a, &b_cols);
    assert_eq!(job::freivalds(&a, &b_cols, &good, 2), None);
    let c_root = job::root_of(&good);
    mine_on(&mut c, &miner, vec![Tx::Act(Action::Commit { job: id2, c_root, sig: bk.sign(&job::msg_commit(&id2, &c_root)) })]);
    // an honest entry cannot be convicted
    let bad_fraud = Tx::Act(Action::Fraud { job: id2, a: open(&a, 1), b: open(&b_cols, 2), c: open(&good, 1), j: 2 });
    let tmpl = c.template(vec![], vec![bad_fraud], vec![]);
    assert!(tmpl.unwrap_err().contains("correct"));
    // finalising inside the window fails; after it, anyone may finalise
    assert!(c.template(vec![], vec![Tx::Act(Action::Finalize { job: id2 })], vec![]).is_err());
    for _ in 0..3 {
        mine_on(&mut c, &miner, vec![]);
    }
    let bob_before = bob.balance(&c);
    mine_on(&mut c, &miner, vec![Tx::Act(Action::Finalize { job: id2 })]);
    assert_eq!(bob.balance(&c) - bob_before, 4 * COIN, "the worker gets pay + bond");
    println!("height {} notes {} nullifiers {} issued {} burned {} shielded {}", c.height(), c.state.tree.len(), c.state.nullifiers.len(), c.state.issued, c.state.burned, c.state.shielded_supply());
}

#[test]
fn reorg_unwinds_a_spend_and_persistence_restores_the_tip() {
    let dir = std::env::temp_dir().join(format!("ns-test-{}", rand::thread_rng().gen::<u64>()));
    let p = Params::get(Net::Reg).unwrap();
    let mut c = Chain::open(p.clone(), Some(&dir)).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for _ in 0..3 {
        mine_on(&mut c, &alice, vec![]);
    }
    let fork = c.tip().hash;
    let (tx, _) = alice.spend(&c, Some((bob.a_pk(), COIN)), 0, None, vec![]).unwrap();
    let Tx::Spend(sp) = tx.clone() else { panic!() };
    mine_on(&mut c, &alice, vec![tx]);
    assert!(c.state.nullifiers.contains(&sp.nf[0]));
    // a competing branch of two empty blocks from the fork point wins
    let mut b1 = c.template_on(&fork, vec![], vec![], b"side".to_vec()).unwrap();
    mine(&mut b1.header, u64::MAX);
    assert!(!c.add_block(b1.clone()).unwrap(), "equal work does not reorganise");
    let st1 = c.state_at_any(&b1.hash()).unwrap();
    let _ = st1;
    let mut b2 = c.template_on(&b1.hash(), vec![], vec![], b"side".to_vec()).unwrap();
    mine(&mut b2.header, u64::MAX);
    assert!(c.add_block(b2.clone()).unwrap(), "more work reorganises");
    assert_eq!(c.tip().hash, b2.hash());
    assert!(!c.state.nullifiers.contains(&sp.nf[0]), "the spend is unwound");
    // restart from disk
    let tip = c.tip().hash;
    drop(c);
    let c2 = Chain::open(p, Some(&dir)).unwrap();
    assert_eq!(c2.tip().hash, tip);
    std::fs::remove_dir_all(&dir).ok();
}
