//! A chain kept on disk holds only its newest block bodies in memory and reads the rest back
//! when asked: for peers, for wallets, and for a reorganisation that reaches below them.

use newsatoshi::chain::{mine, Chain, RECENT_IN_MEMORY};
use newsatoshi::params::{subsidy, Net, Params};
use newsatoshi::tx::{Block, PlainOut};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::path::PathBuf;

fn mine_on(c: &mut Chain, to: &Wallet, tag: &[u8]) -> Block {
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1), rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], vec![], tag.to_vec()).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(c.add_block(b.clone()).unwrap());
    b
}

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("ns-storage-{}", rand::thread_rng().gen::<u64>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Every body beyond the newest is on disk only, and every block can still be read.
fn check_all(c: &Chain, blocks: &[Block]) {
    assert!(c.bodies_in_memory() <= RECENT_IN_MEMORY as usize + 2, "{} bodies in memory", c.bodies_in_memory());
    for b in blocks {
        let h = c.entry(&b.hash()).expect("known").height;
        assert_eq!(c.block_at(h).as_ref(), Some(b), "block {h} reads back as it was");
        let head = c.header_at(h).unwrap();
        assert_eq!((head.header.hash(), head.txs.len()), (b.hash(), 0));
    }
}

#[test]
fn bodies_live_on_disk_and_come_back() {
    let p = Params::get(Net::Reg).unwrap();
    let dir = tmp();
    let w = Wallet::generate();
    let mut c = Chain::open(p.clone(), Some(&dir)).unwrap();
    let a: Vec<Block> = (0..60).map(|_| mine_on(&mut c, &w, b"a")).collect();
    check_all(&c, &a);
    // what a peer catching up asks for comes from disk
    let sent = c.blocks_after(&[c.genesis], 1 << 30);
    assert_eq!(sent.len(), 60);
    assert!(sent.iter().zip(&a).all(|(x, y)| x == y));

    // a heavier branch from height 5, far below the bodies in memory
    let mut b_chain = Chain::open(p.clone(), None).unwrap();
    for x in &a[..5] {
        assert!(b_chain.add_block(x.clone()).unwrap());
    }
    let b: Vec<Block> = (0..70).map(|_| mine_on(&mut b_chain, &w, b"b")).collect();
    c.expect(b.iter().map(|x| x.hash()));
    for x in &b {
        let _ = c.add_block(x.clone()).unwrap();
    }
    assert_eq!(c.tip().hash, b_chain.tip().hash, "moved to the heavier branch");
    check_all(&c, &[&a[..5], &b[..]].concat());

    // and back again: the first branch, now heavier, is read from disk to be reconnected
    let mut a_chain = Chain::open(p.clone(), None).unwrap();
    for x in &a {
        assert!(a_chain.add_block(x.clone()).unwrap());
    }
    let more: Vec<Block> = (0..20).map(|_| mine_on(&mut a_chain, &w, b"a")).collect();
    c.expect(more.iter().map(|x| x.hash()));
    for x in &more {
        let _ = c.add_block(x.clone()).unwrap();
    }
    assert_eq!(c.tip().hash, a_chain.tip().hash, "moved back");
    let all_a = [&a[..], &more[..]].concat();
    check_all(&c, &all_a);
    // the branch it left is still readable: rivals live in side.dat or blocks.dat
    assert_eq!(c.block(&b[69].hash()).as_ref(), Some(&b[69]));

    // a restart reads the whole history back, reorganisations and all
    let tip = c.tip().hash;
    drop(c);
    let c = Chain::open(p.clone(), Some(&dir)).unwrap();
    assert_eq!((c.tip().hash, c.height()), (tip, 80));
    check_all(&c, &all_a);

    // a torn last write is cut off, and what comes after it is read back too
    drop(c);
    let file = dir.join("blocks.dat");
    let whole = std::fs::metadata(&file).unwrap().len();
    let mut f = std::fs::OpenOptions::new().append(true).open(&file).unwrap();
    std::io::Write::write_all(&mut f, &[200, 0, 0, 0, 1, 2, 3]).unwrap();
    drop(f);
    let torn = std::fs::metadata(&file).unwrap().len();
    let mut c = Chain::open(p.clone(), Some(&dir)).unwrap();
    // opening changes nothing: a wallet command beside a running node must not touch its files
    assert_eq!(std::fs::metadata(&file).unwrap().len(), torn);
    let next = mine_on(&mut c, &w, b"after");
    let rec = 4 + next.encode().len() as u64;
    assert_eq!(std::fs::metadata(&file).unwrap().len(), whole + rec, "the torn record was cut at the first write");
    drop(c);
    let c = Chain::open(p, Some(&dir)).unwrap();
    assert_eq!(c.tip().hash, next.hash());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rival_of_the_tip_waits_on_disk() {
    let p = Params::get(Net::Reg).unwrap();
    let dir = tmp();
    let w = Wallet::generate();
    let mut c = Chain::open(p.clone(), Some(&dir)).unwrap();
    for _ in 0..3 {
        mine_on(&mut c, &w, b"a");
    }
    // a block beside the tip: as heavy, so kept, but not connected
    let parent = c.active[2];
    let out = PlainOut { a_pk: w.a_pk(), v: subsidy(3), rho: rand::thread_rng().gen() };
    let mut rival = c.template_on(&parent, vec![out], vec![], b"rival".to_vec()).unwrap();
    assert!(mine(&mut rival.header, u64::MAX));
    assert_eq!(c.add_block(rival.clone()), Ok(false));
    for _ in 0..RECENT_IN_MEMORY + 3 {
        mine_on(&mut c, &w, b"a");
    }
    assert!(c.bodies_in_memory() <= RECENT_IN_MEMORY as usize + 2);
    assert_eq!(c.block(&rival.hash()).as_ref(), Some(&rival), "read back from side.dat");
    // side.dat is forgotten at a restart, and opening the chain does not touch it
    drop(c);
    let side = std::fs::metadata(dir.join("side.dat")).unwrap().len();
    let c = Chain::open(p, Some(&dir)).unwrap();
    assert!(!c.has(&rival.hash()));
    assert_eq!(std::fs::metadata(dir.join("side.dat")).unwrap().len(), side);
    let _ = std::fs::remove_dir_all(&dir);
}
