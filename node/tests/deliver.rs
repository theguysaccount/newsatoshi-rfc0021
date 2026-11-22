//! Payments delivered on chain: the payee's wallet finds them by looking, every memo a wallet
//! writes looks alike, and a spending key alone restores a wallet.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::deliver::{self, Scanner};
use newsatoshi::hash::{bytes_to_words, Word8};
use newsatoshi::node::{lock, Node, Shared};
use newsatoshi::params::{subsidy, Net, Params, COIN};
use newsatoshi::rpc::{self, Faucet, J};
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpStream;

fn step(c: &mut Chain, to: &Wallet, txs: Vec<Tx>) {
    let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], txs, vec![]).unwrap();
    mine(&mut b.header, u64::MAX);
    c.add_block(b).unwrap();
}

#[test]
fn a_delivered_payment_finds_its_payee_and_a_key_restores_a_wallet() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let mut bob = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..3 {
        step(&mut c, &alice, vec![]);
    }
    let (tx, note) = alice.pay(&c, &bob.delivery_address(), 12 * COIN, 10_000, b"lunch".to_vec()).unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let (env, text) = deliver::unpack_memo(&sp.memo);
    // the payment in an envelope to bob's key, the change in a box only alice opens: every
    // payment a wallet makes has this shape, whoever it pays
    assert_eq!((env[0].map(|e| e.len()), env[1].map(|e| e.len())), (Some(deliver::ENVELOPE_BYTES), Some(deliver::OWN_BOX_BYTES)));
    assert_eq!(text, b"lunch");
    assert!(note.is_some(), "the note string still works as well");
    // what a block carries once proofs are folded into the chain proof (white paper §11)
    let public = tx.to_bytes().len() - sp.proof.len();
    assert!(public <= 1_400, "a delivered payment's public part is {public} bytes");
    println!("public part of a delivered payment: {public} bytes");
    step(&mut c, &miner, vec![tx]);

    assert_eq!(bob.balance(&c), 0, "nothing until bob looks");
    assert_eq!(bob.scan(&c).unwrap(), 1);
    assert_eq!(bob.balance(&c), 12 * COIN);
    assert_eq!(bob.scan(&c).unwrap(), 0, "found once");
    let mut other = miner.clone();
    assert_eq!(other.scan(&c).unwrap(), 0, "a stranger's key opens nothing");

    // bob spends what he found, to a plain address: the old way, a note string
    let (tx, note) = bob.pay(&c, &alice.address(), 2 * COIN, 10_000, vec![]).unwrap();
    step(&mut c, &miner, vec![tx]);
    alice.import(&note.unwrap()).unwrap();

    // alice's key alone brings back her coinbase (by address) and her change (sealed to her);
    // the payment that came as a note string comes back only from the string
    let mut restored = Wallet::from_key(alice.sk);
    assert_eq!(restored.job_key, alice.job_key, "the job key comes from the spending key");
    restored.scan(&c).unwrap();
    assert_eq!(restored.balance(&c) + 2 * COIN, alice.balance(&c));
    assert_eq!(restored.delivery_address(), alice.delivery_address());

    // memo text is limited, so a memo always fits beside its envelopes
    assert!(alice.pay(&c, &bob.delivery_address(), COIN, 10_000, vec![b'x'; deliver::MEMO_TEXT_BYTES + 1]).is_err());
    assert!(alice.pay(&c, "nsd1nonsense", COIN, 10_000, vec![]).is_err());
}

fn http(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, J) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.9\r\nContent-Length: {}\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8(resp).unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    (text[9..12].parse().unwrap(), J::parse(body.as_bytes()).unwrap())
}

fn mine_one(shared: &Shared, to: &Wallet) {
    let mut n = lock(shared);
    let (mut b, _) = n.block_template(to.a_pk(), b"test").unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(n.accept_block(b, None).unwrap());
}

/// What a browser wallet does: page through the envelopes, open what it can.
fn look(port: u16, me: &Scanner, from: u32) -> (Vec<(u64, Word8)>, Vec<(u64, Word8)>, u32) {
    let (mut found, mut pending, mut at) = (vec![], vec![], from);
    loop {
        let (code, r) = http(port, "GET", &format!("/api/envelopes?from={at}"), b"");
        assert_eq!(code, 200);
        let num = |k: &str| match r.get(k) {
            Some(J::Num(n)) => n.parse::<u32>().unwrap(),
            _ => panic!("{k}"),
        };
        for (key, out) in [("items", &mut found), ("pending", &mut pending)] {
            let Some(J::Arr(items)) = r.get(key) else { panic!("{key}") };
            for it in items {
                let cm: Word8 = bytes_to_words(&hex::decode(it.get("cm").unwrap().as_str().unwrap()).unwrap().try_into().unwrap());
                let env = hex::decode(it.get("env").unwrap().as_str().unwrap()).unwrap();
                if let Some((v, _)) = me.open(&cm, &env) {
                    out.push((v, cm));
                }
            }
        }
        at = num("next");
        if at > num("tip") {
            return (found, pending, at);
        }
    }
}

#[test]
fn the_faucet_delivers_to_a_delivery_address_and_the_api_lists_envelopes() {
    let shared = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    lock(&shared).log = false;
    let faucet_wallet = Wallet::generate();
    for _ in 0..3 {
        mine_one(&shared, &faucet_wallet);
    }
    let port = rpc::serve_public(shared.clone(), "127.0.0.1", 0, Some(Faucet::new(std::sync::Arc::new(std::sync::Mutex::new(faucet_wallet.clone())), 5 * COIN))).unwrap();
    let me = Wallet::generate();
    let (code, r) = http(port, "POST", "/api/faucet", me.delivery_address().as_bytes());
    assert_eq!(code, 200, "{}", r.to_json());
    // the same wallet by its other address is the same wallet to the faucet
    assert_eq!(http(port, "POST", "/api/faucet", me.address().as_bytes()).0, 429);

    let sc = Scanner::new(&me.sk);
    let (found, pending, next) = look(port, &sc, 0);
    assert!(found.is_empty());
    assert_eq!(pending.iter().map(|p| p.0).collect::<Vec<_>>(), vec![5 * COIN], "seen while it waits for a block");
    mine_one(&shared, &faucet_wallet);
    let (found, pending, _) = look(port, &sc, next.saturating_sub(1));
    assert_eq!((found.len(), found[0].0, pending.len()), (1, 5 * COIN, 0));
    assert!(lock(&shared).chain.state.cm_pos.contains_key(&found[0].1), "the commitment is on chain");
    // the faucet's own key opens its change, not the payment
    let (theirs, _, _) = look(port, &Scanner::new(&faucet_wallet.sk), 0);
    assert!(theirs.iter().all(|(_, cm)| *cm != found[0].1));
    assert_eq!(http(port, "GET", "/api/envelopes?from=x", b"").0, 400);
}
