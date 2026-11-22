//! Hash- and time-locked payments: who can release a lock, when, to whom, and how often;
//! the escrow counter; and a lock made and claimed in one block.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::hash::sha256;
use newsatoshi::job::{payout_rho, Action, Deposit};
use newsatoshi::lock::{lock_id, LockPost, MAX_LOCK_BLOCKS};
use newsatoshi::node::{lock, Node, Shared};
use newsatoshi::note;
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

fn step(c: &mut Chain, miner: &Wallet, txs: Vec<Tx>) -> Result<(), String> {
    let fees: u64 = txs
        .iter()
        .map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 })
        .sum();
    let out = PlainOut {
        a_pk: miner.a_pk(),
        v: subsidy(c.height() + 1) + fees,
        rho: rand::thread_rng().gen(),
    };
    let mut b = c.template(vec![out], txs, vec![])?;
    assert!(mine(&mut b.header, u64::MAX));
    c.add_block(b).map(|_| ())
}

struct World {
    c: Chain,
    alice: Wallet,
    bob: Wallet,
    miner: Wallet,
}

fn world() -> World {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let alice = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        step(&mut c, &alice, vec![]).unwrap();
    }
    World {
        c,
        alice,
        bob: Wallet::generate(),
        miner,
    }
}

/// Alice locks `amount` to SHA-256(preimage), claimable by Bob for `blocks` blocks.
fn make_lock(w: &mut World, preimage: &[u8; 32], amount: u64, blocks: u32) -> ([u8; 32], LockPost) {
    let post = LockPost {
        hash: sha256(preimage),
        timeout: w.c.height() + 1 + blocks,
        claim_addr: w.bob.a_pk(),
        refund_addr: w.alice.a_pk(),
        amount,
    };
    let (tx, _) = w
        .alice
        .spend(
            &w.c,
            None,
            DEFAULT_FEE,
            Some(Deposit::Lock(post.clone())),
            vec![],
        )
        .unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let id = lock_id(&post, &sp.nf[0]);
    let locked_before = w.c.state.locked;
    step(&mut w.c, &w.miner, vec![tx]).unwrap();
    assert_eq!(w.c.state.locked, locked_before + amount as u128);
    assert!(w.c.state.locks.contains_key(&id));
    (id, post)
}

fn bob_has(w: &World, v: u64) -> bool {
    w.bob.unspent(&w.c).iter().any(|o| o.v == v)
}

#[test]
fn the_preimage_releases_a_lock_to_its_claim_address_whoever_publishes_it() {
    let mut w = world();
    let p: [u8; 32] = rand::random();
    let (id, post) = make_lock(&mut w, &p, 5 * COIN, 10);

    // a wrong preimage, a short one, an unknown lock: refused
    assert!(step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Unlock {
            lock: id,
            preimage: [7; 32]
        })]
    )
    .is_err());
    assert!(step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Unlock {
            lock: [9; 32],
            preimage: p
        })]
    )
    .is_err());
    // not before the timeout
    assert!(step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Expire { lock: id })]
    )
    .is_err());

    // the miner, not Bob, publishes it: Bob is paid all the same
    let issued = w.c.state.issued;
    step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Unlock {
            lock: id,
            preimage: p,
        })],
    )
    .unwrap();
    assert!(
        bob_has(&w, 5 * COIN),
        "the claim pays the address fixed in the lock"
    );
    assert!(!w.c.state.locks.contains_key(&id));
    assert_eq!(w.c.state.locked, 0);
    assert_eq!(
        w.c.state.issued,
        issued + subsidy(w.c.height()) as u128,
        "releasing a lock issues nothing"
    );
    let end = w.c.state.lock_ends.get(&id).unwrap();
    assert_eq!(end.preimage, Some(p));
    assert_eq!(end.lock.post, post);
    // the payout is a public note with a rho everyone can compute
    let cm = note::commit(&w.bob.a_pk(), 5 * COIN, &payout_rho(&id, 3));
    assert!(w.c.state.cm_pos.contains_key(&cm));

    // released once: a second claim and a later refund are refused
    assert!(step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Unlock {
            lock: id,
            preimage: p
        })]
    )
    .is_err());
    for _ in 0..12 {
        step(&mut w.c, &w.miner, vec![]).unwrap();
    }
    assert!(step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Expire { lock: id })]
    )
    .is_err());

    // Bob spends the payout privately, like any note
    let (tx, _) = w
        .bob
        .spend(
            &w.c,
            Some((w.alice.a_pk(), COIN)),
            DEFAULT_FEE,
            None,
            vec![],
        )
        .unwrap();
    step(&mut w.c, &w.miner, vec![tx]).unwrap();
}

#[test]
fn after_the_timeout_the_lock_goes_back_and_the_preimage_no_longer_claims() {
    let mut w = world();
    let p: [u8; 32] = rand::random();
    let (id, post) = make_lock(&mut w, &p, 3 * COIN, 4);
    let alice_before = w.alice.balance(&w.c);
    // the timeout height itself still belongs to the claim
    while w.c.height() + 1 < post.timeout {
        step(&mut w.c, &w.miner, vec![]).unwrap();
    }
    assert!(
        step(
            &mut w.c,
            &w.miner,
            vec![Tx::Act(Action::Expire { lock: id })]
        )
        .is_err(),
        "expire at the timeout height"
    );
    step(&mut w.c, &w.miner, vec![]).unwrap();
    assert!(
        step(
            &mut w.c,
            &w.miner,
            vec![Tx::Act(Action::Unlock {
                lock: id,
                preimage: p
            })]
        )
        .is_err(),
        "claim after the timeout"
    );
    step(
        &mut w.c,
        &w.miner,
        vec![Tx::Act(Action::Expire { lock: id })],
    )
    .unwrap();
    assert_eq!(w.alice.balance(&w.c), alice_before + 3 * COIN);
    assert!(!bob_has(&w, 3 * COIN));
    assert_eq!(w.c.state.lock_ends.get(&id).unwrap().preimage, None);
    assert_eq!(w.c.state.locked, 0);
}

#[test]
fn bad_terms_are_refused() {
    let mut w = world();
    let h = w.c.height();
    let mut try_lock = |post: LockPost| -> Result<(), String> {
        let (tx, _) = w
            .alice
            .spend(&w.c, None, DEFAULT_FEE, Some(Deposit::Lock(post)), vec![])?;
        step(&mut w.c, &w.miner, vec![tx])
    };
    let base = LockPost {
        hash: [1; 32],
        timeout: h + 10,
        claim_addr: [2; 8],
        refund_addr: [3; 8],
        amount: COIN,
    };
    assert!(
        try_lock(LockPost {
            timeout: h + 1,
            ..base.clone()
        })
        .is_err(),
        "timeout must be after the block"
    );
    assert!(
        try_lock(LockPost {
            timeout: h + 2 + MAX_LOCK_BLOCKS,
            ..base.clone()
        })
        .is_err(),
        "timeout too far"
    );
    assert!(
        try_lock(LockPost {
            amount: 0,
            ..base.clone()
        })
        .is_err(),
        "nothing to lock"
    );
}

#[test]
fn a_lock_made_and_claimed_while_waiting_lands_in_one_block() {
    let mut w = world();
    let shared: Shared = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    lock(&shared).log = false;
    // replay the world's blocks into the node
    for h in 1..=w.c.height() {
        let b = w.c.block_at(h).unwrap().clone();
        lock(&shared).accept_block(b, None).unwrap();
    }
    let p: [u8; 32] = rand::random();
    let post = LockPost {
        hash: sha256(&p),
        timeout: w.c.height() + 20,
        claim_addr: w.bob.a_pk(),
        refund_addr: w.alice.a_pk(),
        amount: 2 * COIN,
    };
    let (tx, _) = w
        .alice
        .spend(
            &w.c,
            None,
            DEFAULT_FEE,
            Some(Deposit::Lock(post.clone())),
            vec![],
        )
        .unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let id = lock_id(&post, &sp.nf[0]);
    let n = &mut lock(&shared);
    assert!(n.accept_tx(tx.clone()).unwrap());
    // the claim waits on the lock, in the pool: the preimage is public before any block
    assert!(n
        .accept_tx(Tx::Act(Action::Unlock {
            lock: id,
            preimage: p
        }))
        .unwrap());
    assert_eq!(n.pool_state().lock_ends.get(&id).unwrap().preimage, Some(p));
    assert!(
        !n.accept_tx(Tx::Act(Action::Unlock {
            lock: id,
            preimage: p
        }))
        .unwrap(),
        "already pooled"
    );
    let (mut b, _) = n.block_template(w.miner.a_pk(), b"t").unwrap();
    assert_eq!(b.txs.len(), 3, "coinbase, lock, claim");
    assert!(
        matches!(b.txs[1], Tx::Spend(_)),
        "the lock comes before its claim"
    );
    assert!(mine(&mut b.header, u64::MAX));
    assert!(n.accept_block(b, None).unwrap());
    assert!(n.chain.state.lock_ends.contains_key(&id));
    assert_eq!(n.chain.state.locked, 0);
}
