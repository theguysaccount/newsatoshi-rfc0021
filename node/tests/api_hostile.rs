//! What a hostile stranger tried against a node's public API on 10 November 2026 (attack log
//! 42 and 43): requests that never finish, questions whose answers have no end, and a crowd
//! of bad payments to check at once.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::node::{lock, Node, Shared};
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::rpc::{self, J};
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn mine_on(c: &mut Chain, to: &Wallet, txs: Vec<Tx>) {
    let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], txs, vec![]).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(c.add_block(b).unwrap());
}

fn serve(c: Chain) -> (Shared, u16) {
    let shared = Node::new(c);
    lock(&shared).log = false;
    let port = rpc::serve_public(shared.clone(), "127.0.0.1", 0, None).unwrap();
    (shared, port)
}

fn http(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let cut = resp.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
    let code = std::str::from_utf8(&resp[9..12]).unwrap().parse().unwrap();
    (code, resp[cut..].to_vec())
}

/// Attack 42. A request sent a byte at a time kept its connection, and the thread behind
/// it, for as long as the sender liked: each byte reset the clock. A request now has one
/// deadline for the whole of it.
#[test]
fn a_request_that_never_finishes_is_cut_off() {
    let (_shared, port) = serve(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let t0 = Instant::now();
    let slow = b"GET /status HTTP/1.1\r\nHost: x\r\nX-Padding: ";
    let mut sent = 0usize;
    let closed = loop {
        // a byte every half second, for ever
        let byte = [if sent < slow.len() { slow[sent] } else { b'a' }];
        if s.write_all(&byte).is_err() {
            break true;
        }
        sent += 1;
        let mut buf = [0u8; 64];
        match s.read(&mut buf) {
            Ok(0) => break true,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break true,
        }
        if t0.elapsed() > Duration::from_secs(40) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(closed, "the connection was still open after {:?}", t0.elapsed());
    assert!(t0.elapsed() >= Duration::from_secs(15), "and an honest slow start is given its time");
    // the node still answers others
    assert_eq!(http(port, "GET", "/status", b"").0, 200);
}

/// Attack 43. Three questions had answers without end: every position of a note seen many
/// times, every envelope since the first block, every header since the first block. Each
/// answer now has a size, and says where to go on from.
#[test]
fn answers_have_a_size() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let w = Wallet::generate();
    // one note paid into forty blocks: the same address, amount and randomness each time
    let rho = rand::thread_rng().gen();
    let mut cm = None;
    for _ in 0..40 {
        let out = PlainOut { a_pk: w.a_pk(), v: subsidy(c.height() + 1), rho };
        cm = Some(newsatoshi::note::commit(&out.a_pk, out.v, &out.rho));
        let mut b = c.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        assert!(c.add_block(b).unwrap());
    }
    for _ in 0..2_300 {
        mine_on(&mut c, &w, vec![]);
    }
    let tip = c.height();
    let (_shared, port) = serve(c);

    let cm_hex = hex::encode(newsatoshi::hash::words_to_bytes(&cm.unwrap()));
    let (code, body) = http(port, "GET", &format!("/api/note?cm={cm_hex}"), b"");
    let v = J::parse(&body).unwrap();
    let Some(J::Arr(notes)) = v.get("notes") else { panic!("{}", String::from_utf8_lossy(&body)) };
    assert_eq!(code, 200);
    assert!(notes.len() <= 16, "{} positions in one answer", notes.len());
    assert!(!notes.is_empty());

    let num = |v: &J, k: &str| match v.get(k) {
        Some(J::Num(n)) => n.parse::<u32>().unwrap(),
        _ => panic!("{k}"),
    };
    let (_, body) = http(port, "GET", "/api/envelopes?from=0", b"");
    assert!(body.len() <= (2 << 20) + 400_000, "{} bytes of envelopes", body.len());
    let v = J::parse(&body).unwrap();
    assert!(num(&v, "next") <= 2_000 && num(&v, "next") > 0, "one answer covers at most 2,000 blocks");
    // and the rest can still be had, a page at a time
    let (mut at, mut pages) = (num(&v, "next"), 1);
    while at <= tip {
        let (_, body) = http(port, "GET", &format!("/api/envelopes?from={at}"), b"");
        let next = num(&J::parse(&body).unwrap(), "next");
        assert!(next > at);
        at = next;
        pages += 1;
        assert!(pages < 50);
    }
    assert!(pages >= 2);

    let (_, body) = http(port, "GET", "/api/headers?from=0", b"");
    assert!(body.len() <= (2 << 20) + 400_000, "{} bytes of headers", body.len());
    let v = J::parse(&body).unwrap();
    let Some(J::Arr(hs)) = v.get("headers") else { panic!("{}", String::from_utf8_lossy(&body[..200.min(body.len())])) };
    assert!(hs.len() <= 2_000 && !hs.is_empty());
}

/// Attack 43, the payments. Checking a proof takes a core for some milliseconds, and the
/// API checked as many at once as were sent. It now checks two at a time and tells the rest
/// to come back; whatever is sent, each answer is a refusal or that, and the node goes on.
#[test]
fn a_crowd_of_bad_payments_gets_answers_and_the_node_goes_on() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for _ in 0..2 {
        mine_on(&mut c, &alice, vec![]);
    }
    let (tx, _) = alice.spend(&c, Some((bob.a_pk(), COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let good = tx.to_bytes();
    let (shared, port) = serve(c);

    let senders: Vec<_> = (0..12)
        .map(|k| {
            let good = good.clone();
            std::thread::spawn(move || {
                let (mut refused, mut busy) = (0, 0);
                for i in 0..6 {
                    // the real payment with one late byte of its proof changed: it fails only
                    // after nearly all the work of checking it
                    let mut bad = good.clone();
                    let at = bad.len() - 1 - (k * 7 + i) % 5_000;
                    bad[at] ^= 1 + (k as u8);
                    let (code, body) = http(port, "POST", "/api/tx", &bad);
                    let v = J::parse(&body).unwrap();
                    assert_ne!(v.get("ok"), Some(&J::Bool(true)), "a broken payment was accepted");
                    match code {
                        429 => busy += 1,
                        _ => refused += 1,
                    }
                }
                (refused, busy)
            })
        })
        .collect();
    let (mut refused, mut busy) = (0, 0);
    for s in senders {
        let (r, b) = s.join().unwrap();
        refused += r;
        busy += b;
    }
    println!("72 broken payments from 12 senders at once: {refused} checked and refused, {busy} told to come back");
    assert_eq!(refused + busy, 72);
    assert!(refused > 0);
    // the real payment is still taken, and the node still answers
    let (code, body) = http(port, "POST", "/api/tx", &good);
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(lock(&shared).pool_txs().count(), 1);
    assert_eq!(http(port, "GET", "/status", b"").0, 200);
}
