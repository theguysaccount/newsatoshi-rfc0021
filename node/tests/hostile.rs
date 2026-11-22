//! What a hostile stranger tried against a node on 10 November 2026, each kept as a test
//! (attack log 37 to 46). Before the fixes: forty junk blocks beside an old block cost nine
//! seconds of one core to make and stayed in memory for good; eight connections that asked
//! for blocks and never read the answers took 2.4 GB; sixty-four silent connections shut
//! every newcomer out; a proof of a few hundred bytes asked for 32.9 GB; and a copy of a
//! new block with other transactions under its header turned a node against the real one.

use newsatoshi::chain::{mine, Chain, NOT_HEAVIER};
use newsatoshi::node::{self, lock, Msg, Node};
use newsatoshi::params::{subsidy, Net, Params, DEFAULT_FEE};
use newsatoshi::tx::{Block, Coinbase, Header, PlainOut, Spend, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The node's limits are process-wide, so these tests take turns.
static TURN: Mutex<()> = Mutex::new(());

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn mine_on(c: &mut Chain, to: &Wallet) -> Block {
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1), rho: rand::thread_rng().gen() };
    let mut b = c.template(vec![out], vec![], vec![]).unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(c.add_block(b.clone()).unwrap());
    b
}

/// A block with a valid header on `parent` and a body of noise, as large as asked.
fn junk_block(parent: &[u8; 32], height: u32, bits: u32, time: u32, bytes: usize) -> Block {
    let mut rng = rand::thread_rng();
    let mut txs = vec![Tx::Coinbase(Coinbase { height, outs: vec![], extra: vec![] })];
    for _ in 0..bytes / 100_000 {
        let mut proof = vec![0u8; 100_000];
        rng.fill(&mut proof[..]);
        txs.push(Tx::Spend(Spend { anchor: rng.gen(), nf: [rng.gen(), rng.gen()], cm_out: [rng.gen(), rng.gen()], dummy: [false, true], fee: DEFAULT_FEE, deposit: None, memo: vec![], proof }));
    }
    // the header commits to this noise, as an attacker's would: only applying it shows it up
    let mut b = Block { header: Header { version: 1, prev: *parent, commit: [0; 32], time, bits, nonce: rng.gen() }, auxpow: None, digest: rng.gen(), txs };
    b.header.commit = newsatoshi::tx::header_commit(&b.tx_root(), &b.digest);
    assert!(mine(&mut b.header, u64::MAX));
    b
}

fn serve(c: Chain) -> (node::Shared, u16, [u8; 4]) {
    let magic = c.params.magic;
    let shared = Node::new(c);
    lock(&shared).log = false;
    let port = free_port();
    node::listen(shared.clone(), port).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    (shared, port, magic)
}

fn wait_for(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !ok() {
        assert!(t0.elapsed() < Duration::from_secs(secs), "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn greeted(port: u16, magic: [u8; 4]) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return false };
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    matches!(Msg::read(&mut s, magic, 8_000_000), Ok(Msg::Hello { .. }))
}

fn hello(c: &Chain) -> Msg {
    Msg::Hello { height: c.height(), tip: c.tip().hash }
}

/// Attack 37. Blocks beside an old block cost only their own header's work, which there is
/// next to nothing; a node kept every one, body unchecked, for good.
#[test]
fn junk_blocks_beside_an_old_block_are_not_kept() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let w = Wallet::generate();
    let first = mine_on(&mut c, &w);
    for _ in 0..30 {
        mine_on(&mut c, &w);
    }
    let genesis = c.genesis;
    let bits = first.header.bits;
    for i in 0..20 {
        let b = junk_block(&genesis, 1, bits, first.header.time + 1 + i, 1_000_000);
        let h = b.hash();
        assert_eq!(c.add_block(b).unwrap_err(), NOT_HEAVIER);
        assert!(!c.has(&h) && c.block(&h).is_none(), "a junk block was kept");
        // and nothing can be built on what was not kept
        let child = junk_block(&h, 2, bits, first.header.time + 100, 0);
        assert_eq!(c.add_block(child).unwrap_err(), "unknown parent");
    }
    assert_eq!(c.height(), 31);
    // junk that does outweigh the tip is checked, fails, and only its header is remembered
    let tip = c.tip().clone();
    let b = junk_block(&tip.hash, tip.height + 1, bits, tip.time + 1, 1_000_000);
    let h = b.hash();
    assert!(c.add_block(b).unwrap_err().contains("tx 1"));
    assert!(c.block(&h).is_none(), "an invalid block's body was kept");
    assert_eq!(c.height(), 31);
    // a rival of the tip is still kept, so that an honest race between two miners resolves
    let rival = {
        let parent = c.entry(&tip.prev).unwrap().clone();
        let out = PlainOut { a_pk: w.a_pk(), v: subsidy(parent.height + 1), rho: rand::thread_rng().gen() };
        let mut b = c.template_on(&parent.hash, vec![out], vec![], vec![1]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        b
    };
    let rh = rival.hash();
    assert!(!c.add_block(rival).unwrap());
    assert!(c.has(&rh));
}

/// The other half of attack 37: a heavier chain that forks far back is still followed,
/// because its headers are weighed first and its blocks are then expected.
#[test]
fn a_heavier_chain_that_forks_far_back_is_still_followed() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let w = Wallet::generate();
    let mut ca = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut cb = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    for _ in 0..3 {
        let b = mine_on(&mut ca, &w);
        cb.add_block(b).unwrap();
    }
    for _ in 0..40 {
        mine_on(&mut ca, &w);
    }
    for _ in 0..70 {
        mine_on(&mut cb, &w);
    }
    // by itself, a block of the other chain far behind the tip is refused
    let far = cb.block_at(4).unwrap().clone();
    assert_eq!(ca.add_block(far).unwrap_err(), NOT_HEAVIER);
    let want = cb.tip().hash;
    let (a, port, _) = serve(ca);
    let b = Node::new(cb);
    lock(&b).log = false;
    node::connect(b.clone(), &format!("127.0.0.1:{port}")).unwrap();
    wait_for("the node did not move to the heavier chain", 30, || lock(&a).chain.tip().hash == want);
    assert_eq!(lock(&a).chain.height(), 73);
}

/// Attack 38. A peer asked for blocks again and again and read none of the answers; the
/// node queued every answer.
#[test]
fn a_peer_that_never_reads_cannot_fill_memory() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let w = Wallet::generate();
    for _ in 0..300 {
        let outs: Vec<PlainOut> = (0..64).map(|k| PlainOut { a_pk: w.a_pk(), v: if k == 0 { subsidy(c.height() + 1) } else { 0 }, rho: rand::thread_rng().gen() }).collect();
        let mut b = c.template(outs, vec![], vec![7u8; 120]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        c.add_block(b).unwrap();
    }
    let genesis = c.genesis;
    let batch: usize = c.blocks_after(&[genesis], 8 << 20).iter().map(|b| b.encode().len()).sum();
    assert!(batch > 1_000_000);
    let hi = hello(&c);
    let (_shared, port, magic) = serve(c);
    let mut conns = vec![];
    for _ in 0..8 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(&hi.encode(magic)).unwrap();
        let ask = Msg::GetBlocks { locator: vec![genesis] }.encode(magic);
        for _ in 0..250 {
            let _ = s.write_all(&ask);
        }
        conns.push(s);
    }
    std::thread::sleep(Duration::from_secs(3));
    // 2,000 answers were asked for (2.4 GB); a few per peer wait, the rest were never made
    let queued = node::queued_bytes();
    assert!(queued < 8 * (6 << 20), "{} MB queued for peers that read nothing", queued >> 20);
    // and when the peers go, what waited for them is released
    drop(conns);
    wait_for("queued bytes were not released", 20, || node::queued_bytes() == 0);
    assert!(greeted(port, magic));
}

/// Attack 39. Connections that said nothing held every place a peer could take.
#[test]
fn silent_connections_do_not_keep_newcomers_out() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    node::set_timeouts(Duration::from_millis(1_500), Duration::from_millis(2_500));
    let c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let hi = hello(&c);
    let (shared, port, magic) = serve(c);
    // connections other tests in this process left open count too
    let base = node::inbound_count();
    let silent: Vec<TcpStream> = (0..80).filter_map(|_| TcpStream::connect(("127.0.0.1", port)).ok()).collect();
    std::thread::sleep(Duration::from_millis(300));
    // the door is full, but not the places the node keeps for peers of its own choosing
    assert_eq!(node::inbound_count(), 48);
    assert!(node::peer_count() < 64);
    // those who say nothing are let go, and a newcomer is greeted
    wait_for("silent connections were never let go", 10, || node::inbound_count() <= base);
    assert!(greeted(port, magic));
    // a peer that says hello and then goes quiet lasts until the idle time, no longer
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&hi.encode(magic)).unwrap();
    std::thread::sleep(Duration::from_millis(1_800));
    assert_eq!(node::inbound_count(), base + 1, "a peer that said hello was dropped at the handshake time");
    wait_for("an idle peer was never let go", 10, || node::inbound_count() <= base);
    // a frame that trickles in is cut off at the same clock: nine bytes of header, then nothing
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&hi.encode(magic)).unwrap();
    s.write_all(&magic).unwrap();
    wait_for("a stalled frame was never let go", 10, || node::inbound_count() <= base);
    drop(silent);
    node::set_timeouts(Duration::from_secs(20), Duration::from_secs(900));
    assert!(shared.lock().is_ok());
}

/// Attack 40. Answers nobody asked for: 8 MB of blocks or 4 MB of headers at any time.
#[test]
fn answers_nobody_asked_for_end_the_connection() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let hi = hello(&c);
    let (_shared, port, magic) = serve(c);
    for kind in [2u8, 9] {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(&hi.encode(magic)).unwrap();
        let mut frame = magic.to_vec();
        frame.push(kind);
        frame.extend_from_slice(&(4_000_000u32).to_le_bytes());
        s.write_all(&frame).unwrap();
        // the node hangs up before reading a byte of the payload
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut sink = vec![];
        let _ = s.read_to_end(&mut sink);
        let t0 = Instant::now();
        let closed = loop {
            if s.write_all(&[0u8; 65_536]).is_err() {
                break true;
            }
            if t0.elapsed() > Duration::from_secs(5) {
                break false;
            }
        };
        assert!(closed, "an unasked answer of kind {kind} was read");
    }
    assert!(greeted(port, magic));
}

/// Attack 41. A peer could send what fails validation for ever.
#[test]
fn a_peer_that_keeps_sending_what_fails_is_dropped() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let w = Wallet::generate();
    mine_on(&mut c, &w);
    let tip = c.tip().clone();
    let bits = c.next_bits(&tip);
    let hi = hello(&c);
    let (shared, port, magic) = serve(c);
    let base = node::inbound_count();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&hi.encode(magic)).unwrap();
    // blocks that outweigh the tip and fail: two of them and the peer is gone
    let mut sent = 0;
    for i in 0..6 {
        let b = junk_block(&tip.hash, tip.height + 1, bits, tip.time + 1 + i, 100_000);
        if s.write_all(&Msg::Block(b).encode(magic)).is_err() {
            break;
        }
        sent += 1;
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(sent <= 4, "the peer was still being listened to after {sent} bad blocks");
    wait_for("the peer was not dropped", 5, || node::inbound_count() <= base);
    assert_eq!(lock(&shared).chain.height(), 1);
    assert!(greeted(port, magic));
}

/// Attack 39, by address: a public address gets a few connections, a banned one none.
#[test]
fn one_address_cannot_take_many_places() {
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    assert!(node::is_public(ip));
    for local in ["127.0.0.1", "10.1.2.3", "192.168.1.9", "::1", "fdaa:0:1::3", "::ffff:10.0.0.1"] {
        assert!(!node::is_public(local.parse().unwrap()), "{local}");
    }
    for _ in 0..node::MAX_PER_IP {
        assert!(node::admit_inbound(ip));
    }
    assert!(!node::admit_inbound(ip), "a fifth connection from one address was taken");
    node::release_inbound(ip);
    assert!(node::admit_inbound(ip));
    for _ in 0..node::MAX_PER_IP {
        node::release_inbound(ip);
    }
    let other: IpAddr = "198.51.100.9".parse().unwrap();
    node::ban(other, 60);
    assert!(!node::admit_inbound(other));
    // an address on a private network may be a proxy carrying many peers: not limited
    let proxy: IpAddr = "fdaa:0:1::3".parse().unwrap();
    for _ in 0..20 {
        assert!(node::admit_inbound(proxy));
    }
    for _ in 0..20 {
        node::release_inbound(proxy);
    }
}

/// Attack 45. A block's hash covers its 80-byte header, and the header vouches for the
/// transactions only through a commitment that can be checked once they have all been
/// applied. So a stranger can take the header of a real block that has just been found, put
/// other transactions under it and send that first. The copy fails, as it must; what must
/// not happen is that the node then holds the failure against the hash and turns away the
/// real block and everything built on it.
#[test]
fn a_swapped_body_does_not_turn_a_node_against_the_real_block() {
    let p = Params::get(Net::Reg).unwrap();
    let mut miner = Chain::open(p.clone(), None).unwrap();
    let mut victim = Chain::open(p, None).unwrap();
    let (honest, thief) = (Wallet::generate(), Wallet::generate());
    let first = mine_on(&mut miner, &honest);
    assert!(victim.add_block(first).unwrap());

    let real = mine_on(&mut miner, &honest);
    // the same header over a coinbase that pays the stranger
    let mut forged = real.clone();
    let Tx::Coinbase(cb) = &mut forged.txs[0] else { unreachable!() };
    cb.outs[0].a_pk = thief.a_pk();
    assert_eq!(forged.hash(), real.hash());
    assert!(victim.add_block(forged.clone()).is_err(), "the forged copy must fail");
    assert_eq!(victim.height(), 1);
    // the same copy again is refused without being worked through a second time
    assert!(victim.add_block(forged).is_err());

    assert_eq!(victim.add_block(real.clone()), Ok(true), "the real block must still be taken");
    let next = mine_on(&mut miner, &honest);
    assert_eq!(victim.add_block(next), Ok(true), "and so must what is built on it");
    assert_eq!(victim.tip().hash, miner.tip().hash);
}

/// Attack 44. A payment proof states the lengths of its own parts, and the proof library
/// set aside memory for whatever length it read before reading a byte of it. A proof of a
/// few hundred bytes that claimed a part of a trillion bytes asked the machine for a
/// trillion bytes, and a machine that cannot give them stops the node. The fuzzer found
/// requests of 8.8 and 32.9 gigabytes; this is the same lie, placed by hand.
#[test]
fn a_proof_that_lies_about_its_length_is_refused_without_the_memory() {
    let p = Params::get(Net::Reg).unwrap();
    let mut c = Chain::open(p, None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for _ in 0..2 {
        mine_on(&mut c, &alice);
    }
    let (tx, _) = alice.spend(&c, Some((bob.a_pk(), newsatoshi::params::COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let pi = sp.public().unwrap();
    newsatoshi::spend::verify_bytes(&pi, &sp.proof).unwrap();

    // after the prefix: one byte, then the commitments behind a two-byte length, then the
    // first table of queried values behind its length. A length whose first byte is zero is
    // spelled in the eight bytes that follow.
    let at = newsatoshi::spend::context_prefix(&pi).len() + 1;
    let commitments = u16::from_le_bytes([sp.proof[at], sp.proof[at + 1]]) as usize;
    let len_at = at + 2 + commitments;
    for claimed in [1u64 << 33, 1 << 40, 1 << 62, u64::MAX] {
        let mut lie = sp.proof[..len_at].to_vec();
        lie.push(0);
        lie.extend_from_slice(&claimed.to_le_bytes());
        lie.extend_from_slice(&sp.proof[len_at..(len_at + 4096).min(sp.proof.len())]);
        assert!(newsatoshi::spend::verify_bytes(&pi, &lie).is_err(), "a claim of {claimed} bytes");
    }
}

/// A block's merged-mining proof and an address each have one spelling. The fuzzer found a
/// second for both: a count written the long way, and capital letters.
#[test]
fn one_thing_has_one_spelling() {
    use newsatoshi::auxpow::AuxPow;
    let mut coinbase = vec![1, 0, 0, 0, 1];
    coinbase.extend_from_slice(&[0u8; 36]);
    coinbase.extend_from_slice(&[2, 0x51, 0x51, 0xff, 0xff, 0xff, 0xff, 1]);
    coinbase.extend_from_slice(&[0u8; 8]);
    coinbase.extend_from_slice(&[1, 0x51, 0, 0, 0, 0]);
    let a = AuxPow { coinbase, unused_hash: [0; 32], coinbase_branch: vec![[9; 32]], coinbase_index: 0, chain_branch: vec![], chain_index: 0, parent: [0; 80] };
    let bytes = a.to_bytes();
    assert_eq!(AuxPow::parse(&bytes).unwrap().to_bytes(), bytes);
    // the count of the coinbase branch, one, written in three bytes instead of one
    let at = a.coinbase.len() + 32;
    assert_eq!(bytes[at], 1);
    let mut long = bytes[..at].to_vec();
    long.extend_from_slice(&[0xfd, 1, 0]);
    long.extend_from_slice(&bytes[at + 1..]);
    assert!(AuxPow::parse(&long).is_err());

    let w = Wallet::generate();
    let addr = w.address();
    assert!(newsatoshi::wallet::parse_address(&addr).is_ok());
    let shouted = format!("ns1{}", addr[3..].to_uppercase());
    assert_ne!(shouted, addr, "an address has letters in it");
    assert!(newsatoshi::wallet::parse_address(&shouted).is_err());
}

/// The file of blocks a node wrote before blocks carried their state digest is still read,
/// and is written once more in today's form. The file is in the order blocks were connected,
/// so it can hold a reorganisation: blocks that were the chain for a while, then the ones
/// that replaced them.
#[test]
fn a_chain_stored_in_the_earlier_form_is_read_and_rewritten() {
    let p = Params::get(Net::Reg).unwrap();
    let mut c = Chain::open(p.clone(), None).unwrap();
    let w = Wallet::generate();
    let mut written: Vec<Block> = (0..3).map(|_| mine_on(&mut c, &w)).collect();
    // a rival to block 3 and a block on it: the chain moves over, and both are written
    let fork = written[1].hash();
    let mut rival = vec![];
    let mut on = fork;
    for _ in 0..2 {
        let out = PlainOut { a_pk: w.a_pk(), v: subsidy(c.entry(&on).unwrap().height + 1), rho: rand::thread_rng().gen() };
        let mut b = c.template_on(&on, vec![out], vec![], b"rival".to_vec()).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        let _ = c.add_block(b.clone()).unwrap();
        on = b.hash();
        rival.push(b);
    }
    assert_eq!((c.height(), c.tip().hash), (4, on), "the chain moved to the rival branch");
    written.extend(rival.clone());
    written.push(mine_on(&mut c, &w));

    let dir = std::env::temp_dir().join(format!("ns-earlier-{}", rand::thread_rng().gen::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let record = |file: &mut Vec<u8>, rec: &[u8]| {
        file.extend_from_slice(&(rec.len() as u32).to_le_bytes());
        file.extend_from_slice(rec);
    };
    let mut earlier = vec![];
    for b in &written {
        let now = b.encode();
        // the earlier form: the same bytes without the 32 of the digest after the count
        let mut old = now[..84].to_vec();
        old.extend_from_slice(&now[84 + 32..]);
        assert!(Block::decode(&old).is_err() || !Block::decode(&old).unwrap().bound());
        record(&mut earlier, &old);
    }
    let mut today = vec![];
    for h in 1..=c.height() {
        record(&mut today, &c.block_at(h).unwrap().encode());
    }
    std::fs::write(dir.join("blocks.dat"), &earlier).unwrap();
    let opened = Chain::open(p.clone(), Some(&dir)).unwrap();
    assert_eq!((opened.height(), opened.tip().hash), (5, c.tip().hash));
    drop(opened);
    assert_eq!(std::fs::read(dir.join("blocks.dat")).unwrap(), today, "the file is the connected chain in today's form");
    assert_eq!(std::fs::read(dir.join("blocks.dat.old")).unwrap(), earlier, "and the earlier file is kept");
    assert!(!dir.join("blocks.dat.new").exists());
    let again = Chain::open(p, Some(&dir)).unwrap();
    assert_eq!((again.height(), again.tip().hash), (5, c.tip().hash));
    let _ = std::fs::remove_dir_all(&dir);
}
