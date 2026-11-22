//! Coins under conditions: a two-of-three escrow released where two keys agree, a hash lock
//! that only its preimage opens and that comes back after its timeout, and the rules that
//! keep a release from being turned into another.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::cond::{self, CondPost};
use newsatoshi::hash::sha256;
use newsatoshi::job::{Action, Deposit};
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::script;
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

fn step(c: &mut Chain, miner: &Wallet, txs: Vec<Tx>) -> Result<(), String> {
    let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
    let out = PlainOut { a_pk: miner.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], txs, vec![])?;
    assert!(mine(&mut b.header, u64::MAX));
    c.add_block(b).map(|_| ())
}

/// Alice puts `amount` under `program`, payable to `payouts`, for `blocks` blocks.
fn make(c: &mut Chain, alice: &mut Wallet, miner: &Wallet, program: &[u8], payouts: Vec<[u32; 8]>, amount: u64, blocks: u32) -> [u8; 32] {
    let salt: [u8; 32] = rand::thread_rng().gen();
    let post = CondPost { commitment: cond::commitment(&salt, program), payouts, timeout: c.height() + 1 + blocks, refund_addr: alice.a_pk(), amount };
    let (tx, _) = alice.spend(c, None, DEFAULT_FEE, Some(Deposit::Cond(post.clone())), vec![]).unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let id = cond::cond_id(&post, if sp.dummy[0] { &sp.nf[1] } else { &sp.nf[0] });
    step(c, miner, vec![tx]).unwrap();
    SALTS.with(|s| s.borrow_mut().push((id, salt)));
    id
}

thread_local!(static SALTS: std::cell::RefCell<Vec<([u8; 32], [u8; 32])>> = const { std::cell::RefCell::new(vec![]) });
fn salt_of(id: &[u8; 32]) -> [u8; 32] {
    SALTS.with(|s| s.borrow().iter().find(|(i, _)| i == id).unwrap().1)
}

#[test]
fn an_escrow_pays_where_two_keys_agree_and_a_hash_lock_comes_back_after_its_timeout() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let (bob, carol, miner) = (Wallet::generate(), Wallet::generate(), Wallet::generate());
    for _ in 0..3 {
        step(&mut c, &alice, vec![]).unwrap();
    }
    let digest_before = c.state.digest();

    // a two-of-three escrow between alice (buyer), bob (seller) and carol (arbiter)
    let keys = [&alice, &bob, &carol].map(|w| w.job_key().unwrap());
    let escrow = script::assemble(&format!("2 0x{} 0x{} 0x{} 3 CHECKMULTISIG", hex::encode(keys[0].vk()), hex::encode(keys[1].vk()), hex::encode(keys[2].vk()))).unwrap();
    let payouts = vec![alice.a_pk(), bob.a_pk()];
    let id = make(&mut c, &mut alice, &miner, &escrow, payouts, 7 * COIN, 100);
    assert_eq!(c.state.conds.len(), 1);
    assert_ne!(c.state.digest_parts().conds, None, "open conditions are in the state digest");
    let sign = |k: usize, payout: u8| keys[k].sign(&cond::sign_message(&id, payout));
    let fulfil = |payout: u8, witness: Vec<Vec<u8>>| Tx::Act(Action::Fulfil { cond: id, payout, salt: salt_of(&id), program: escrow.clone(), witness });

    // one signature is not enough; signatures for bob cannot pay alice
    assert!(step(&mut c, &miner, vec![fulfil(1, vec![sign(1, 1)])]).is_err());
    assert!(step(&mut c, &miner, vec![fulfil(0, vec![sign(1, 1), sign(2, 1)])]).is_err());
    // bob and carol agree bob is paid
    let tx = fulfil(1, vec![sign(1, 1), sign(2, 1)]);
    let bytes = tx.to_bytes();
    assert_eq!(Tx::from_bytes(&bytes).unwrap(), tx, "a release travels intact");
    step(&mut c, &miner, vec![tx.clone()]).unwrap();
    assert_eq!(bob.balance(&c), 7 * COIN, "bob's payout is a note he can spend");
    assert!(step(&mut c, &miner, vec![tx]).is_err(), "released once");
    assert!(c.state.conds.is_empty() && c.state.cond_ends.contains_key(&id));
    assert_eq!(c.state.digest_parts().conds, None, "with none open, the digest has no conditions in it");
    assert_ne!(c.state.digest(), digest_before);

    // a hash lock payable to bob alone: only the preimage opens it, and after its timeout it
    // goes back to alice
    let pre = b"the swap's secret".to_vec();
    let hl = script::assemble(&format!("SHA256 0x{} EQUAL", hex::encode(sha256(&pre)))).unwrap();
    let id2 = make(&mut c, &mut alice, &miner, &hl, vec![bob.a_pk()], COIN, 2);
    let wrong = Tx::Act(Action::Fulfil { cond: id2, payout: 0, salt: salt_of(&id2), program: hl.clone(), witness: vec![b"guess".to_vec()] });
    assert!(step(&mut c, &miner, vec![wrong]).is_err());
    let other_program = Tx::Act(Action::Fulfil { cond: id2, payout: 0, salt: salt_of(&id2), program: script::assemble("1").unwrap(), witness: vec![] });
    assert!(step(&mut c, &miner, vec![other_program]).is_err(), "only the committed program runs");
    assert!(step(&mut c, &miner, vec![Tx::Act(Action::Expire { lock: id2 })]).is_err(), "not yet");
    while c.height() <= c.state.conds[&id2].post.timeout {
        step(&mut c, &miner, vec![]).unwrap();
    }
    let late = Tx::Act(Action::Fulfil { cond: id2, payout: 0, salt: salt_of(&id2), program: hl, witness: vec![pre] });
    assert!(step(&mut c, &miner, vec![late]).is_err(), "too late for the preimage");
    let before = alice.balance(&c);
    step(&mut c, &miner, vec![Tx::Act(Action::Expire { lock: id2 })]).unwrap();
    assert_eq!(alice.balance(&c), before + COIN, "the refund came back");
    assert_eq!(c.state.locked, 0, "nothing left in escrow");
}
