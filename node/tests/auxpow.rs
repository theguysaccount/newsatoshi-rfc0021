//! Merged mining with Bitcoin: Namecoin's AuxPoW rules, the block format, and the pool RPC.

use newsatoshi::auxpow::{self, merkle_branch, AuxPow, CHAIN_ID, MERGED_MINING_HEADER};
use newsatoshi::chain::{check_work, mine, Chain};
use newsatoshi::hash::sha256d;
use newsatoshi::node::{lock, Node};
use newsatoshi::params::{subsidy, Net, Params};
use newsatoshi::pow;
use newsatoshi::rpc::{self, Rpc, J};
use newsatoshi::tx::{Block, PlainOut};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::io::{Read, Write};
use std::net::TcpStream;

fn regtest() -> Chain {
    Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap()
}

/// A Bitcoin coinbase: one null input carrying `script`, one output.
fn coinbase_tx(script: &[u8]) -> Vec<u8> {
    let mut t = vec![];
    t.extend_from_slice(&1u32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(script.len() as u8);
    t.extend_from_slice(script);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&(50 * 100_000_000u64).to_le_bytes());
    t.extend_from_slice(&[1, 0x51]);
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// The same coinbase in segwit serialization, with the 32-byte witness Bitcoin coinbases carry.
fn coinbase_tx_segwit(script: &[u8]) -> Vec<u8> {
    let plain = coinbase_tx(script);
    let mut t = plain[..4].to_vec();
    t.extend_from_slice(&[0, 1]);
    t.extend_from_slice(&plain[4..plain.len() - 4]);
    t.push(1);
    t.push(32);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&plain[plain.len() - 4..]);
    t
}

/// The commitment a pool writes into its coinbase script.
fn mm_script(root_display: &[u8; 32], size: u32, nonce: u32, prefix: &[u8], magic: bool) -> Vec<u8> {
    let mut s = prefix.to_vec();
    if magic {
        s.extend_from_slice(&MERGED_MINING_HEADER);
    }
    s.extend_from_slice(root_display);
    s.extend_from_slice(&size.to_le_bytes());
    s.extend_from_slice(&nonce.to_le_bytes());
    s.extend_from_slice(b"/pool/");
    s
}

/// A Bitcoin header over `root` whose hash does (or does not) meet `bits`.
fn parent_header(version: u32, root: [u8; 32], bits: u32, pass: bool) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&version.to_le_bytes());
    h[4..36].copy_from_slice(&[7u8; 32]);
    h[36..68].copy_from_slice(&root);
    h[68..72].copy_from_slice(&1_780_000_000u32.to_le_bytes());
    h[72..76].copy_from_slice(&0x1702_3a5bu32.to_le_bytes());
    for nonce in 0u32.. {
        h[76..80].copy_from_slice(&nonce.to_le_bytes());
        if pow::meets(&sha256d(&h), bits) == pass {
            return h;
        }
    }
    unreachable!()
}

/// Rebuild the parent header after the coinbase or its branch changed, keeping the work.
fn reseal(a: &mut AuxPow, bits: u32) {
    let txid = auxpow::parse_tx(&a.coinbase).unwrap().txid;
    let root = merkle_branch(txid, &a.coinbase_branch, 0);
    let version = u32::from_le_bytes(a.parent[0..4].try_into().unwrap());
    a.parent = parent_header(version, root, bits, true);
}

fn display(h: &[u8; 32]) -> [u8; 32] {
    let mut r = *h;
    r.reverse();
    r
}

/// The auxpow a pool would make for one chain: magic, root, size 1, nonce 0, and a parent
/// block with one more transaction after the coinbase.
fn make(aux_hash: &[u8; 32], bits: u32) -> AuxPow {
    let script = mm_script(&display(aux_hash), 1, 0, &[3, 0x81, 0xe0, 0x0e], true);
    let mut a = AuxPow { coinbase: coinbase_tx(&script), unused_hash: [0; 32], coinbase_branch: vec![[9u8; 32]], coinbase_index: 0, chain_branch: vec![], chain_index: 0, parent: [0; 80] };
    a.parent[0..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    reseal(&mut a, bits);
    a
}

fn template(c: &Chain, to: &Wallet) -> Block {
    let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1), rho: rand::thread_rng().gen() };
    c.template(vec![out], vec![], vec![]).unwrap()
}

fn merge_mined(c: &Chain, to: &Wallet) -> Block {
    let mut b = template(c, to);
    b.header.version = auxpow::auxpow_version(b.header.version);
    let h = b.hash();
    b.auxpow = Some(make(&h, b.header.bits));
    b
}

#[test]
fn merge_mined_blocks_extend_the_chain_and_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("ns-auxpow-{}", rand::thread_rng().gen::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let miner = Wallet::generate();
    {
        let mut c = Chain::open(Params::get(Net::Reg).unwrap(), Some(&dir)).unwrap();
        let b = merge_mined(&c, &miner);
        assert_eq!(check_work(&b), Ok(()));
        // the block itself need not meet the target: the Bitcoin header does the work
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
        assert!(c.add_block(b).unwrap());
        // direct mining stays allowed, and the two mix
        let mut d = template(&c, &miner);
        assert!(mine(&mut d.header, u64::MAX));
        assert!(c.add_block(d).unwrap());
        let b3 = merge_mined(&c, &miner);
        assert!(c.add_block(b3).unwrap());
        assert_eq!(c.height(), 3);
    }
    let c = Chain::open(Params::get(Net::Reg).unwrap(), Some(&dir)).unwrap();
    assert_eq!(c.height(), 3, "merge-mined blocks reload from disk");
    assert!(c.block(&c.tip().hash).unwrap().auxpow.is_some());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn work_for_one_block_does_not_carry_to_another() {
    let mut c = regtest();
    let w = Wallet::generate();
    let a = merge_mined(&c, &w);
    let mut b = template(&c, &w);
    b.header.version = auxpow::auxpow_version(b.header.version);
    b.auxpow = a.auxpow.clone();
    let e = c.add_block(b).unwrap_err();
    assert!(e.contains("missing chain merkle root"), "{e}");
    assert_eq!(c.height(), 0);
}

fn err_of(b: &Block) -> String {
    check_work(b).expect_err("expected a rejection")
}

#[test]
fn namecoin_rules_hold() {
    let c = regtest();
    let w = Wallet::generate();
    let good = merge_mined(&c, &w);
    let h = good.hash();
    let bits = good.header.bits;
    let with = |f: &dyn Fn(&mut AuxPow)| {
        let mut b = good.clone();
        f(b.auxpow.as_mut().unwrap());
        b
    };
    let script_with = |script: Vec<u8>| {
        with(&|a: &mut AuxPow| {
            a.coinbase = coinbase_tx(&script);
            reseal(a, bits);
        })
    };

    assert!(err_of(&with(&|a| a.coinbase_index = 1)).contains("not a generate"));
    assert!(err_of(&with(&|a| a.coinbase_branch = vec![[8u8; 32]])).contains("merkle root incorrect"));
    // without the magic, the root must start within the first 20 bytes
    assert!(err_of(&script_with(mm_script(&display(&h), 1, 0, &[0u8; 21], false))).contains("first 20 bytes"));
    assert_eq!(check_work(&script_with(mm_script(&display(&h), 1, 0, &[0u8; 20], false))), Ok(()));
    // exactly one magic, directly before the root
    let mut two = mm_script(&display(&h), 1, 0, &[1], true);
    two.extend_from_slice(&MERGED_MINING_HEADER);
    assert!(err_of(&script_with(two)).contains("multiple merged mining headers"));
    let mut gap = vec![1u8];
    gap.extend_from_slice(&MERGED_MINING_HEADER);
    gap.push(0);
    gap.extend_from_slice(&display(&h));
    gap.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    assert!(err_of(&script_with(gap)).contains("not just before"));
    // tree size and nonce
    assert!(err_of(&script_with(mm_script(&display(&h), 2, 0, &[1], true))).contains("size does not match"));
    let mut short = vec![1u8];
    short.extend_from_slice(&MERGED_MINING_HEADER);
    short.extend_from_slice(&display(&h));
    short.extend_from_slice(&[1, 0, 0]);
    assert!(err_of(&script_with(short)).contains("missing chain merkle tree size"));
    // the parent may not be merge-mined itself, nor carry our chain ID
    assert!(err_of(&with(&|a| {
        a.parent[0..4].copy_from_slice(&(0x2000_0000u32 | auxpow::VERSION_AUXPOW).to_le_bytes());
        reseal(a, bits);
    }))
    .contains("itself marked merge-mined"));
    assert!(err_of(&with(&|a| {
        a.parent[0..4].copy_from_slice(&(CHAIN_ID << 16).to_le_bytes());
        reseal(a, bits);
    }))
    .contains("our chain ID"));
    // the Bitcoin header has to meet our target
    assert!(err_of(&with(&|a| {
        let root: [u8; 32] = a.parent[36..68].try_into().unwrap();
        a.parent = parent_header(0x2000_0000, root, bits, false);
    }))
    .contains("insufficient proof of work"));
    // version and auxpow go together, and the version carries our chain ID
    let mut no_aux = good.clone();
    no_aux.auxpow = None;
    assert!(err_of(&no_aux).contains("without an auxpow"));
    let mut unmarked = good.clone();
    unmarked.header.version = 1;
    assert!(err_of(&unmarked).contains("not marked merge-mined"));
    let mut namecoin = template(&c, &w);
    namecoin.header.version = 1 | auxpow::VERSION_AUXPOW | (1 << 16);
    let nh = namecoin.hash();
    namecoin.auxpow = Some(make(&nh, bits));
    assert!(err_of(&namecoin).contains("without our chain ID"));
}

#[test]
fn several_chains_share_one_bitcoin_block() {
    let c = regtest();
    let w = Wallet::generate();
    let mut b = template(&c, &w);
    b.header.version = auxpow::auxpow_version(b.header.version);
    let ours = b.hash();
    let nonce = 0x5eed_u32;
    let slot = auxpow::expected_index(nonce, CHAIN_ID, 2) as usize;
    let mut leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    leaves[slot] = ours;
    let pair = |x: &[u8; 32], y: &[u8; 32]| sha256d(&[x.as_slice(), y.as_slice()].concat());
    let p = [pair(&leaves[0], &leaves[1]), pair(&leaves[2], &leaves[3])];
    let root = pair(&p[0], &p[1]);
    let branch = vec![leaves[slot ^ 1], p[(slot >> 1) ^ 1]];
    assert_eq!(merkle_branch(ours, &branch, slot as i32), root);

    let mut a = AuxPow { coinbase: coinbase_tx(&mm_script(&display(&root), 4, nonce, &[1], true)), unused_hash: [0; 32], coinbase_branch: vec![], coinbase_index: 0, chain_branch: branch, chain_index: slot as i32, parent: [0; 80] };
    a.parent[0..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    reseal(&mut a, b.header.bits);
    b.auxpow = Some(a.clone());
    assert_eq!(check_work(&b), Ok(()));
    // another slot is another chain's
    let mut wrong = b.clone();
    wrong.auxpow.as_mut().unwrap().chain_index = (slot ^ 1) as i32;
    assert!(check_work(&wrong).is_err());
    // the same tree does not place a chain with another ID at our slot
    assert!(a.check(&ours, 1).is_err() || auxpow::expected_index(nonce, 1, 2) as usize == slot);
}

#[test]
fn coinbase_in_either_serialization_has_one_txid() {
    let s = mm_script(&[5u8; 32], 1, 0, &[1], true);
    let plain = auxpow::parse_tx(&coinbase_tx(&s)).unwrap();
    let seg = auxpow::parse_tx(&coinbase_tx_segwit(&s)).unwrap();
    assert_eq!(plain.txid, seg.txid);
    assert_eq!(plain.script0, s);
    assert_eq!(seg.len, coinbase_tx_segwit(&s).len());
}

#[test]
fn hostile_auxpow_bytes_are_refused_cleanly() {
    let c = regtest();
    let good = merge_mined(&c, &Wallet::generate());
    let bytes = good.auxpow.as_ref().unwrap().to_bytes();
    assert_eq!(AuxPow::parse(&bytes).unwrap(), *good.auxpow.as_ref().unwrap());
    for cut in [0, 1, 4, 5, 40, bytes.len() / 2, bytes.len() - 1] {
        assert!(AuxPow::parse(&bytes[..cut]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(AuxPow::parse(&trailing).is_err());
    // counts far beyond the bytes present
    let mut huge = 1u32.to_le_bytes().to_vec();
    huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(AuxPow::parse(&huge).is_err());
    assert!(AuxPow::parse(&vec![0u8; auxpow::MAX_AUXPOW_BYTES + 1]).unwrap_err().contains("too large"));
    let mut rng = rand::thread_rng();
    for _ in 0..2000 {
        let n = rng.gen_range(0..400);
        let junk: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        let _ = AuxPow::parse(&junk);
    }
    // a block marked merge-mined must carry a decodable auxpow
    let mut enc = good.encode();
    enc.truncate(90);
    assert!(Block::decode(&enc).is_err());
}

fn post(port: u16, user_pass: &str, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        rpc::base64(user_pass.as_bytes()),
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp[9..12].parse().unwrap();
    (status, resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn result(body: &str) -> J {
    let v = J::parse(body.as_bytes()).unwrap();
    assert_eq!(v.get("error"), Some(&J::Null), "{body}");
    v.get("result").unwrap().clone()
}

#[test]
fn a_pool_merge_mines_through_the_rpc() {
    let shared = Node::new(regtest());
    lock(&shared).log = false;
    let node_wallet = Wallet::generate();
    let pool = Wallet::generate();
    let port = rpc::serve(Rpc::new(shared.clone(), "pool:secret", node_wallet.a_pk()), "127.0.0.1", 0).unwrap();

    assert_eq!(post(port, "pool:wrong", r#"{"method":"getblockcount","params":[],"id":1}"#).0, 401);
    let (st, body) = post(port, "pool:secret", r#"{"method":"getblockcount","params":[],"id":1}"#);
    assert_eq!((st, result(&body)), (200, J::num(0)));

    // 1. the pool asks for a block paying its own address
    let req = format!(r#"{{"jsonrpc":"1.0","id":"t","method":"createauxblock","params":["{}"]}}"#, pool.address());
    let r = result(&post(port, "pool:secret", &req).1);
    assert_eq!(r.get("chainid"), Some(&J::num(CHAIN_ID)));
    assert_eq!(r.get("height"), Some(&J::num(1)));
    let hash = r.get("hash").and_then(|h| h.as_str()).unwrap().to_string();
    let bits = u32::from_str_radix(r.get("bits").and_then(|b| b.as_str()).unwrap(), 16).unwrap();
    let mut target = [0u8; 32];
    pow::target_from_compact(bits).to_little_endian(&mut target);
    assert_eq!(r.get("_target").and_then(|t| t.as_str()), Some(hex::encode(target).as_str()));

    // 2. it writes the hash into its Bitcoin coinbase and finds a share that meets our target
    let mut internal: [u8; 32] = hex::decode(&hash).unwrap().try_into().unwrap();
    internal.reverse();
    let aux = hex::encode(make(&internal, bits).to_bytes());

    // 3. it submits the Bitcoin header, coinbase and branch
    let unknown = format!(r#"{{"id":2,"method":"submitauxblock","params":["{}","{aux}"]}}"#, "00".repeat(32));
    let (st, body) = post(port, "pool:secret", &unknown);
    assert_eq!(st, 500);
    assert!(body.contains("block hash unknown"));
    let sub = format!(r#"{{"id":3,"method":"submitauxblock","params":["{hash}","{aux}"]}}"#);
    assert_eq!(result(&post(port, "pool:secret", &sub).1), J::Bool(true));
    {
        let n = lock(&shared);
        assert_eq!(n.chain.height(), 1);
        let tip = n.chain.block(&n.chain.tip().hash).unwrap();
        assert!(tip.auxpow.is_some());
    }
    assert_eq!(result(&post(port, "pool:secret", r#"{"id":4,"method":"getbestblockhash","params":[]}"#).1), J::str(hash.clone()));

    // getauxblock without arguments pays the node's own wallet; with two, it submits
    let r = result(&post(port, "pool:secret", r#"{"id":5,"method":"getauxblock","params":[]}"#).1);
    let hash2 = r.get("hash").and_then(|h| h.as_str()).unwrap().to_string();
    let bits2 = u32::from_str_radix(r.get("bits").and_then(|b| b.as_str()).unwrap(), 16).unwrap();
    let mut internal2: [u8; 32] = hex::decode(&hash2).unwrap().try_into().unwrap();
    internal2.reverse();
    let bad = hex::encode(make(&internal, bits2).to_bytes()); // work for the old block
    let sub_bad = format!(r#"{{"id":6,"method":"getauxblock","params":["{hash2}","{bad}"]}}"#);
    assert_eq!(result(&post(port, "pool:secret", &sub_bad).1), J::Bool(false));
    let good = hex::encode(make(&internal2, bits2).to_bytes());
    let sub_good = format!(r#"{{"id":7,"method":"getauxblock","params":["{hash2}","{good}"]}}"#);
    assert_eq!(result(&post(port, "pool:secret", &sub_good).1), J::Bool(true));
    assert_eq!(lock(&shared).chain.height(), 2);

    // a batch, and an unknown method
    let (_, body) = post(port, "pool:secret", r#"[{"id":8,"method":"getblockcount"},{"id":9,"method":"nope"}]"#);
    let v = J::parse(body.as_bytes()).unwrap();
    let J::Arr(items) = v else { panic!("{body}") };
    assert_eq!(items[0].get("result"), Some(&J::num(2)));
    assert!(items[1].get("error").unwrap().get("code") == Some(&J::num(-32601)));
}
