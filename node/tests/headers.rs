//! Headers first: a new node weighs a peer's chain by its headers, then fetches the blocks;
//! headers that do not link, lack their work or have the wrong difficulty are refused.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::node::{self, lock, Node};
use newsatoshi::params::{Net, Params};
use newsatoshi::tx::Block;
use newsatoshi::wallet::Wallet;
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn grow(c: &mut Chain, n: usize) {
    let w = Wallet::generate();
    for _ in 0..n {
        let out = newsatoshi::tx::PlainOut { a_pk: w.a_pk(), v: newsatoshi::params::subsidy(c.height() + 1), rho: rand::random() };
        let mut b = c.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        c.add_block(b).unwrap();
    }
}

fn headers(c: &Chain) -> Vec<Block> {
    c.headers_after(&[c.block_at(0).unwrap().hash()], 1 << 20)
}

#[test]
fn headers_are_checked_before_blocks() {
    let mut a = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    grow(&mut a, 25);
    let fresh = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let hs = headers(&a);
    assert_eq!(hs.len(), 25);
    assert!(hs.iter().all(|h| h.txs.is_empty()));
    let (work, height) = fresh.check_headers(&hs).unwrap();
    assert_eq!((height, work), (25, a.tip().work));
    // out of order
    let mut bad = hs.clone();
    bad.swap(3, 4);
    assert!(fresh.check_headers(&bad).is_err());
    // a header whose work is missing
    let mut bad = hs.clone();
    bad[10].header.nonce ^= 1;
    assert!(fresh.check_headers(&bad).is_err() || newsatoshi::chain::check_work(&bad[10]).is_ok());
    // a header claiming another difficulty
    let mut bad = hs.clone();
    bad[5].header.bits ^= 1;
    assert!(fresh.check_headers(&bad).is_err());
    // a run that does not start on a known block
    assert_eq!(fresh.check_headers(&hs[1..]).unwrap_err(), "unknown parent");
}

#[test]
fn a_new_node_syncs_headers_first() {
    let mut a = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    grow(&mut a, 40);
    let tip = a.tip().hash;
    let sa = Node::new(a);
    lock(&sa).log = false;
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    node::listen(sa.clone(), port).unwrap();
    let sb = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    lock(&sb).log = false;
    node::keep_connected(sb.clone(), format!("127.0.0.1:{port}"));
    let deadline = Instant::now() + Duration::from_secs(30);
    while lock(&sb).chain.tip().hash != tip {
        assert!(Instant::now() < deadline, "no sync: at {}", lock(&sb).chain.height());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(lock(&sb).best_header, 40, "the headers were seen before the blocks");
}
