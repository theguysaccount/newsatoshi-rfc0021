//! The public wallet API, driven the way the browser wallet drives it: a faucet payment,
//! the note found with its path, a spend built only from what the API returned, submitted,
//! mined, and seen spent.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::hash::{bytes_to_words, words_to_bytes, Word8};
use newsatoshi::node::{lock, Node, Shared};
use newsatoshi::note::{self, DEPTH};
use newsatoshi::params::{Net, Params, DEFAULT_FEE};
use newsatoshi::rpc::{self, Faucet, J};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use newsatoshi::tx::{bind_of, Spend, Tx};
use newsatoshi::wallet::{parse_note, Wallet};
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpStream;

fn http(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, J) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.7\r\nContent-Length: {}\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8(resp).unwrap();
    let code = text[9..12].parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    (code, if body.is_empty() { J::Null } else { J::parse(body.as_bytes()).unwrap() })
}

fn mine_one(shared: &Shared, to: &Wallet) {
    let mut n = lock(shared);
    let (mut b, _) = n.block_template(to.a_pk(), b"test").unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(n.accept_block(b, None).unwrap());
}

fn w8(h: &str) -> Word8 {
    bytes_to_words(&hex::decode(h).unwrap().try_into().unwrap())
}

#[test]
fn a_browser_wallet_can_receive_spend_and_see_it_spent() {
    let shared = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    lock(&shared).log = false;
    let faucet_wallet = Wallet::generate();
    for _ in 0..3 {
        mine_one(&shared, &faucet_wallet);
    }
    let port = rpc::serve_public(shared.clone(), "127.0.0.1", 0, Some(Faucet::new(std::sync::Arc::new(std::sync::Mutex::new(faucet_wallet.clone())), 5 * 100_000_000))).unwrap();

    // the browser's key; only its address goes to the faucet
    let me = Wallet::generate();
    let (code, r) = http(port, "POST", "/api/faucet", me.address().as_bytes());
    assert_eq!(code, 200, "{}", r.to_json());
    let note_str = r.get("note").and_then(|n| n.as_str()).unwrap().to_string();
    let (a_pk, v, rho) = parse_note(&note_str).unwrap();
    assert_eq!((a_pk, v), (me.a_pk(), 5 * 100_000_000));
    // a second request from the same visitor is refused for now
    assert_eq!(http(port, "POST", "/api/faucet", me.address().as_bytes()).0, 429);

    // not on chain until a block includes it
    let cm = note::commit(&me.a_pk(), v, &rho);
    let cm_hex = hex::encode(words_to_bytes(&cm));
    let (_, r) = http(port, "GET", &format!("/api/note?cm={cm_hex}"), b"");
    assert_eq!(r.get("found"), Some(&J::Bool(false)));
    mine_one(&shared, &faucet_wallet);
    let (_, r) = http(port, "GET", &format!("/api/note?cm={cm_hex}"), b"");
    assert_eq!(r.get("found"), Some(&J::Bool(true)), "{}", r.to_json());
    let J::Arr(notes) = r.get("notes").unwrap() else { panic!() };
    let pos: u32 = match notes[0].get("pos") {
        Some(J::Num(p)) => p.parse().unwrap(),
        _ => panic!(),
    };
    let J::Arr(path_j) = notes[0].get("path").unwrap() else { panic!() };
    let path: [Word8; DEPTH] = core::array::from_fn(|i| w8(path_j[i].as_str().unwrap()));
    let root = w8(r.get("root").and_then(|x| x.as_str()).unwrap());
    assert_eq!(note::root_from_path(&cm, pos, &path), root);

    // the nullifier is the browser's to compute; unspent so far
    let nf = note::nullifier(&me.sk, pos, &rho);
    let nf_hex = hex::encode(words_to_bytes(&nf));
    let (_, r) = http(port, "GET", &format!("/api/spent?nf={nf_hex}"), b"");
    assert_eq!(r.get("spent"), Some(&J::Bool(false)));

    // spend it, from nothing but what the API returned: pay 2 coins to a friend
    let friend = Wallet::generate();
    let mut rng = rand::thread_rng();
    let fee = DEFAULT_FEE;
    let pay = OutputNote { a_pk: friend.a_pk(), v: 2 * 100_000_000, rho: rng.gen() };
    let change = OutputNote { a_pk: me.a_pk(), v: v - pay.v - fee, rho: rng.gen() };
    let wit = SpendWitness { inputs: [InputNote { sk: me.sk, v, rho, pos, path }, InputNote::dummy()], outputs: [pay, change], dummy: [false, true] };
    let bind = bind_of(fee, &None, &[]);
    let (pi, proof) = spend::prove(&wit, bind).unwrap();
    let tx = Tx::Spend(Spend { anchor: pi.root, nf: pi.nf, cm_out: pi.cm_out, dummy: [false, true], fee, deposit: None, memo: vec![], proof: proof.to_bytes() });
    let (code, r) = http(port, "POST", "/api/tx", &tx.to_bytes());
    assert_eq!(code, 200, "{}", r.to_json());
    let (_, r) = http(port, "GET", &format!("/api/spent?nf={nf_hex}"), b"");
    assert_eq!(r.get("pending"), Some(&J::Bool(true)));
    // a tampered copy is refused before it reaches the pool
    let mut bad = tx.to_bytes();
    let k = bad.len() - 100;
    bad[k] ^= 1;
    assert_eq!(http(port, "POST", "/api/tx", &bad).0, 400);

    mine_one(&shared, &faucet_wallet);
    let (_, r) = http(port, "GET", &format!("/api/spent?nf={nf_hex}"), b"");
    assert_eq!(r.get("spent"), Some(&J::Bool(true)));
    assert_eq!(http(port, "GET", "/nope", b"").0, 404);
}
