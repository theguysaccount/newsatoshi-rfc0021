//! A light client follows the chain by its headers alone and checks that the tip commits to
//! the note-tree root a node reports.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::hash::{bytes_to_words, Word8};
use newsatoshi::light::HeaderTip;
use newsatoshi::node::{lock, Node, Shared};
use newsatoshi::params::{Net, Params, COIN};
use newsatoshi::rpc::{self, Faucet, J};
use newsatoshi::state::DigestParts;
use newsatoshi::tx::{Block, Header};
use newsatoshi::wallet::Wallet;
use std::io::{Read, Write};
use std::net::TcpStream;

fn get(port: u16, path: &str) -> J {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    J::parse(resp.split("\r\n\r\n").nth(1).unwrap().as_bytes()).unwrap()
}

fn post(port: u16, path: &str, body: &[u8]) -> J {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(format!("POST {path} HTTP/1.1\r\nHost: x\r\nX-Real-IP: 203.0.113.11\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    J::parse(resp.split("\r\n\r\n").nth(1).unwrap().as_bytes()).unwrap()
}

fn mine_one(shared: &Shared, to: &Wallet) {
    let mut n = lock(shared);
    let (mut b, _) = n.block_template(to.a_pk(), b"test").unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(n.accept_block(b, None).unwrap());
}

fn str_of<'a>(j: &'a J, k: &str) -> &'a str {
    j.get(k).and_then(|x| x.as_str()).unwrap_or_else(|| panic!("{k}"))
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn follow(port: u16, params: &Params, lc: &mut HeaderTip) -> Result<(), String> {
    loop {
        let r = get(port, &format!("/api/headers?from={}", lc.tip.height + 1));
        let Some(J::Arr(hs)) = r.get("headers") else { panic!() };
        let blocks: Vec<Block> = hs.iter().map(|h| Block::decode(&hex::decode(h.as_str().unwrap()).unwrap()).unwrap()).collect();
        if blocks.is_empty() {
            return Ok(());
        }
        lc.extend(params, &blocks, i64::MAX / 4)?;
    }
}

fn committed(port: u16, lc: &HeaderTip, tamper: bool) -> Result<Word8, String> {
    let r = get(port, "/api/state");
    let p = r.get("parts").unwrap();
    let num = |k: &str| str_of(p, k).parse::<u128>().unwrap();
    let mut parts = DigestParts {
        height: match p.get("height") {
            Some(J::Num(n)) => n.parse().unwrap(),
            _ => panic!(),
        },
        tree_root: bytes_to_words(&h32(str_of(p, "tree_root"))),
        nf_acc: h32(str_of(p, "nf_acc")),
        jobs: h32(str_of(p, "jobs")),
        pending: h32(str_of(p, "pending")),
        issued: num("issued"),
        burned: num("burned"),
        locked: num("locked"),
        locks: p.get("locks").map(|l| h32(l.as_str().unwrap())),
        conds: p.get("conds").map(|l| h32(l.as_str().unwrap())),
        nf_root: p.get("nf_root").map(|l| h32(l.as_str().unwrap())),
        channels: p.get("channels").map(|l| h32(l.as_str().unwrap())),
        bonds: p.get("bonds").map(|l| h32(l.as_str().unwrap())),
        rollups: p.get("rollups").map(|l| h32(l.as_str().unwrap())),
        missions: p.get("missions").map(|l| h32(l.as_str().unwrap())),
    };
    if tamper {
        parts.issued += 1;
    }
    let header = Header::from_bytes(&hex::decode(str_of(&r, "header")).unwrap().try_into().unwrap());
    lc.committed_root(&header, &h32(str_of(&r, "tx_root")), &parts)
}

#[test]
fn a_light_client_follows_the_headers_and_checks_the_committed_root() {
    let params = Params::get(Net::Reg).unwrap();
    let shared = Node::new(Chain::open(params.clone(), None).unwrap());
    lock(&shared).log = false;
    let miner = Wallet::generate();
    for _ in 0..4 {
        mine_one(&shared, &miner);
    }
    let port = rpc::serve_public(shared.clone(), "127.0.0.1", 0, Some(Faucet::new(std::sync::Arc::new(std::sync::Mutex::new(miner.clone())), 5 * COIN))).unwrap();
    let me = Wallet::generate();
    assert_eq!(post(port, "/api/faucet", me.delivery_address().as_bytes()).get("ok"), Some(&J::Bool(true)));
    mine_one(&shared, &miner);

    let mut lc = HeaderTip::genesis(&params);
    follow(port, &params, &mut lc).unwrap();
    let (height, tip, root) = {
        let n = lock(&shared);
        (n.chain.height(), n.chain.tip().hash, n.chain.state.tree.root())
    };
    assert_eq!((lc.tip.height, lc.tip.hash), (height, tip));
    assert_eq!(committed(port, &lc, false).unwrap(), root, "the tip commits to the tree the node reports");
    assert!(committed(port, &lc, true).is_err(), "a state the header does not commit to is refused");

    // the tip also commits to the nullifier tree, so a light client checks spent and unspent
    let st = get(port, "/api/state");
    let nf_root = bytes_to_words(&h32(str_of(st.get("parts").unwrap(), "nf_root")));
    let spent_nf = {
        let n = lock(&shared);
        (1..=n.chain.height()).flat_map(|h| n.chain.block_at(h).unwrap().txs.clone()).find_map(|t| if let newsatoshi::tx::Tx::Spend(sp) = t { Some(sp.nf[0]) } else { None }).unwrap()
    };
    let unspent_nf: Word8 = rand::random();
    for (nf, want) in [(spent_nf, true), (unspent_nf, false)] {
        let r = get(port, &format!("/api/spent?nf={}", hex::encode(newsatoshi::hash::words_to_bytes(&nf))));
        let p = r.get("proof").unwrap();
        let Some(J::Arr(path)) = p.get("path") else { panic!() };
        let proof = newsatoshi::nftree::NfProof {
            index: match p.get("index") {
                Some(J::Num(n)) => n.parse().unwrap(),
                _ => panic!(),
            },
            value: bytes_to_words(&h32(str_of(p, "value"))),
            next: bytes_to_words(&h32(str_of(p, "next"))),
            path: core::array::from_fn(|k| bytes_to_words(&h32(path[k].as_str().unwrap()))),
        };
        assert_eq!(newsatoshi::nftree::check(&nf_root, &nf, &proof), Some(want), "checked against the committed root");
    }

    // its state survives a reload, and it carries on from there
    let mut lc = HeaderTip::from_bytes(&lc.to_bytes()).unwrap();
    mine_one(&shared, &miner);
    mine_one(&shared, &miner);
    follow(port, &params, &mut lc).unwrap();
    assert_eq!(lc.tip.height, height + 2);
    assert!(committed(port, &lc, false).is_ok());

    // headers that skip one, or claim the wrong difficulty, are refused
    let r = get(port, "/api/headers?from=1");
    let Some(J::Arr(hs)) = r.get("headers") else { panic!() };
    let mut blocks: Vec<Block> = hs.iter().map(|h| Block::decode(&hex::decode(h.as_str().unwrap()).unwrap()).unwrap()).collect();
    let mut fresh = HeaderTip::genesis(&params);
    let mut gap = blocks.clone();
    gap.remove(2);
    assert!(fresh.extend(&params, &gap, i64::MAX / 4).is_err());
    blocks[0].header.bits ^= 1;
    assert!(fresh.extend(&params, &blocks, i64::MAX / 4).is_err());
    assert_eq!(fresh.tip.height, 0, "a failed run leaves the tip where it was");
}
