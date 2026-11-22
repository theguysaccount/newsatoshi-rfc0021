//! A dress rehearsal of the main network (`Net::Dry`): every rule the main network will
//! have, on a chain that is thrown away. What it checks is what a launch depends on: a
//! coinbase waits its hundred blocks, a payment proves at the main network's parameters and
//! fits its limits, the default fee clears the relay floor, a proof carries its network's
//! name and is no proof anywhere else, and two nodes agree over the wire.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::node::{self, lock, Node};
use newsatoshi::params::{min_relay_fee, subsidy, Net, Params, COIN, DEFAULT_FEE, MAX_TX_BYTES};
use newsatoshi::spend;
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn mine_on(c: &mut Chain, to: &Wallet, txs: Vec<Tx>) -> Block {
    let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], txs, b"rehearsal".to_vec()).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(c.add_block(b.clone()).unwrap());
    b
}

#[test]
fn the_main_networks_rules_run_end_to_end() {
    let p = Params::get(Net::Dry).unwrap();
    // LAUNCH.md: ten-minute blocks, a two-day half-life, a hundred blocks before a coinbase
    // can be spent, proofs of 128 queries with masked segments only
    assert_eq!((p.target_spacing, p.half_life, p.coinbase_maturity), (600, 2 * 24 * 3600, 100));
    assert_eq!((p.proof.queries, p.proof.unmasked, p.nf_tree_from), (spend::MAIN_QUERIES, false, Some(0)));
    assert_eq!((spend::MAIN.queries, spend::MAIN.unmasked, spend::MAIN.max_proof_bytes), (p.proof.queries, p.proof.unmasked, p.proof.max_proof_bytes));
    assert_ne!(spend::MAIN.tag, p.proof.tag, "the rehearsal's proofs are not the main network's");

    let mut c = Chain::open(p.clone(), None).unwrap();
    let mut alice = Wallet::generate();
    let (bob, miner) = (Wallet::generate(), Wallet::generate());
    mine_on(&mut c, &alice, vec![]);
    for _ in 0..p.coinbase_maturity - 1 {
        mine_on(&mut c, &miner, vec![]);
    }
    alice.scan(&c).unwrap();
    assert!(alice.pay(&c, &bob.delivery_address(), COIN, p.default_fee, vec![]).is_err(), "a coinbase is not spendable after 99 blocks");
    mine_on(&mut c, &miner, vec![]);
    alice.scan(&c).unwrap();

    let t0 = Instant::now();
    let (tx, _) = alice.pay(&c, &bob.delivery_address(), COIN, p.default_fee, b"rehearsal".to_vec()).unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let size = tx.to_bytes().len();
    println!("a main-network payment: proof {} bytes, transaction {size} bytes, proved in {:.1} s", sp.proof.len(), t0.elapsed().as_secs_f64());
    assert!(sp.proof.len() > spend::MAX_PROOF_BYTES, "larger than any test-network proof");
    assert!(sp.proof.len() <= p.proof.max_proof_bytes && size <= p.max_tx_bytes && size > MAX_TX_BYTES);
    assert!(p.default_fee >= min_relay_fee(size), "the default fee clears the relay floor");
    assert!(DEFAULT_FEE < min_relay_fee(size), "the test network's default fee would not");

    // the proof names its network: it is one here, and nowhere else
    let pi = sp.public().unwrap();
    assert!(sp.proof.starts_with(&spend::context_prefix_for(&spend::DRY, &pi)));
    spend::verify_bytes_for(&spend::DRY, &pi, &sp.proof).unwrap();
    assert!(spend::verify_bytes_for(&spend::MAIN, &pi, &sp.proof).is_err(), "a rehearsal proof is no main-network proof");
    assert!(spend::verify_bytes_for(&spend::TEST, &pi, &sp.proof).is_err(), "nor a test-network one");
    // renaming it in place does not carry it across: the name is in the transcript
    let (from, to) = (spend::DRY.meta(), [spend::ZK_META, b"/dr0"].concat());
    let at = sp.proof.windows(from.len()).position(|w| w == from.as_slice()).unwrap();
    let mut renamed = sp.proof.clone();
    renamed[at..at + to.len()].copy_from_slice(&to);
    let other = spend::Profile { tag: b"/dr0", ..spend::DRY };
    assert!(spend::verify_bytes_for(&other, &pi, &renamed).is_err());

    // a payment proved at the test network's parameters is turned away by the pool and by a block
    let weak_rules = Params { proof: spend::TEST, ..p.clone() };
    let mut twin = Chain::open(weak_rules, None).unwrap();
    for h in 1..=c.height() {
        assert!(twin.add_block(c.block_at(h).unwrap().clone()).unwrap());
    }
    let mut carol = alice.clone();
    let (weak, _) = carol.pay(&twin, &bob.delivery_address(), COIN, p.default_fee, vec![]).unwrap();
    assert!(Node::precheck(&weak, &p).is_err());
    let out = PlainOut { a_pk: miner.a_pk(), v: subsidy(c.height() + 1) + p.default_fee, rho: rand::thread_rng().gen() };
    let mut bad = c.template(vec![out], vec![weak], vec![]).unwrap();
    assert!(mine(&mut bad.header, u64::MAX));
    let e = c.add_block(bad).unwrap_err();
    assert!(e.contains("proof rejected"), "{e}");

    // the real one enters a pool, is mined, and a second node follows the whole chain
    Node::precheck(&tx, &p).unwrap();
    let block = mine_on(&mut c, &miner, vec![tx.clone()]);
    assert!(block.encode().len() > size);
    let mut bobs = bob.clone();
    bobs.scan(&c).unwrap();
    assert_eq!(bobs.balance(&c), COIN, "the payee finds the payment by itself");

    let height = c.height();
    let a = Node::new(c);
    let b = Node::new(Chain::open(p, None).unwrap());
    lock(&a).log = false;
    lock(&b).log = false;
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    node::listen(a.clone(), port).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    node::connect(b.clone(), &format!("127.0.0.1:{port}")).unwrap();
    let t0 = Instant::now();
    while lock(&a).chain.tip().hash != lock(&b).chain.tip().hash {
        assert!(t0.elapsed() < Duration::from_secs(60), "the second node did not follow");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(lock(&b).chain.height(), height);
}
