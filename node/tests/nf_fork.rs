//! Blocks begin to commit to the nullifier tree at a set height, and the chain carries on
//! across it: the test network's change at height 3,900, played out at height 5.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::params::{subsidy, Net, Params, COIN};
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

fn step(c: &mut Chain, to: &Wallet, txs: Vec<Tx>) {
    let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], txs, vec![]).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    c.add_block(b).unwrap();
}

#[test]
fn blocks_commit_to_the_nullifier_tree_from_the_set_height() {
    let mut params = Params::get(Net::Reg).unwrap();
    params.nf_tree_from = Some(5);
    let mut c = Chain::open(params.clone(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for _ in 0..2 {
        step(&mut c, &alice, vec![]);
    }
    let (tx, _) = alice.pay(&c, &bob.address(), COIN, 10_000, vec![]).unwrap();
    step(&mut c, &alice, vec![tx]);
    assert_eq!(c.height(), 3);
    assert_eq!(c.state.digest_parts().nf_root, None, "before the height, as blocks always were");
    assert_eq!(c.state.nf_tree.len(), 1, "the tree is kept from the start (one real input)");
    step(&mut c, &alice, vec![]);
    step(&mut c, &alice, vec![]);
    assert_eq!(c.height(), 5);
    assert!(c.state.digest_parts().nf_root.is_some(), "from it, the root is committed");
    let (tx, _) = alice.pay(&c, &bob.address(), COIN, 10_000, vec![]).unwrap();
    step(&mut c, &alice, vec![tx]);
    assert_eq!(c.state.nf_tree.len(), 2);
    // a node that replays the chain from genesis agrees at every height
    let mut replay = Chain::open(params, None).unwrap();
    for h in 1..=c.height() {
        replay.add_block(c.block_at(h).unwrap().clone()).unwrap();
    }
    assert_eq!(replay.state.digest(), c.state.digest());
}
