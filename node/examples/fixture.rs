// A real shielded payment, proved by the reference node on a freshly mined regtest chain.
// Writes the public inputs and proof for the site's in-browser verifier.
use newsatoshi::chain::{mine, Chain};
use newsatoshi::params::{subsidy, Net, Params, COIN};
use newsatoshi::tx::{hash_hex, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

fn main() {
    let out = std::env::args().nth(1).expect("output dir");
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for _ in 0..3 {
        let o = PlainOut { a_pk: alice.a_pk(), v: subsidy(c.height() + 1), rho: rand::thread_rng().gen() };
        let mut b = c.template(vec![o], vec![], vec![]).unwrap();
        mine(&mut b.header, u64::MAX);
        c.add_block(b).unwrap();
    }
    let (tx, _) = alice.spend(&c, Some((bob.a_pk(), 21 * COIN / 2)), 10_000, None, b"cypherpunks write code".to_vec()).unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let pi = sp.public().unwrap();
    // mine it, so the proof is one a node actually accepted
    let o = PlainOut { a_pk: alice.a_pk(), v: subsidy(c.height() + 1) + sp.fee, rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![o], vec![tx.clone()], vec![]).unwrap();
    mine(&mut b.header, u64::MAX);
    assert!(c.add_block(b.clone()).unwrap());
    std::fs::write(format!("{out}/pi.bin"), pi.to_bytes()).unwrap();
    std::fs::write(format!("{out}/proof.bin"), &sp.proof).unwrap();
    std::fs::write(
        format!("{out}/fixture.txt"),
        format!(
            "block {} height {}\ntx {}\nroot {}\nnf0 {}\nnf1 {}\nfee {}\nproof_bytes {}\n",
            hash_hex(&b.hash()),
            c.height(),
            hash_hex(&tx.id()),
            hex::encode(newsatoshi::hash::words_to_bytes(&pi.root)),
            hex::encode(newsatoshi::hash::words_to_bytes(&pi.nf[0])),
            hex::encode(newsatoshi::hash::words_to_bytes(&pi.nf[1])),
            sp.fee,
            sp.proof.len()
        ),
    )
    .unwrap();
    println!("ok");
}
