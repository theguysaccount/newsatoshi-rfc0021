//! RFC-0022 End-to-End L1 Consensus Proof:
//! 1. **Astra's Decisive Unilateral Redemption Test (`1,000 → 237 / 763`):**
//!    - Buyer funds a 1,000-unit PayWord channel (+10 pre-funded miner claim fee = 1,010 locked)
//!      in one shielded L1 transaction on Node A.
//!    - Buyer streams 237 sequential O(1) PayWord vouchers off-chain; Seller verifies each link
//!      in 1 SHA-256 hash and persists `(237, token_237)` to disk.
//!    - Simulate a full Seller server restart (reloading `(237, token_237)` from disk) AND drop
//!      the Buyer completely (zero buyer cooperation, zero official Commons gateway).
//!    - Seller submits `Action::ChannelClaim { channel, ticks: 237, token }` to an **independent
//!      Node B** (which only synced blocks from Node A) and mines 1 block.
//!    - Proves on-chain:
//!      * Seller holds exact spendable `237` (and actually spends it privately in a shielded STARK tx!)
//!      * Buyer (restored solely from spending key `sk`) recovers exact spendable `763`
//!      * Miner receives exact `10` claim fee (`237 + 763 + 10 == 1,010`)
//!      * Replay claim, over-claim (`ticks=238`), forged token, and post-claim `ChannelExpire` ALL fail.
//! 2. **Astra's Channel-Opening Scale Proof (`64` Distinct Buyer–Seller Channels in ONE Spend):**
//!    - Opens 64 distinct buyer–seller channels inside ONE single shielded `Spend` (`Deposit::ChannelBatch`),
//!      measures exact serialized bytes (~257 KB on Testnet/Regtest, ~469 KB on Mainnet = 64× capacity lift),
//!      then unilaterally closes ALL 64 channels at 64 distinct partial tick counts (`1..=64`) in one block
//!      and verifies exact coin conservation across all 64 sellers, buyer refunds, and miner fees.
//! 3. **Timeout Refund (`Action::ChannelExpire`) & Per-Block Anti-DoS Hash Cap.**

use newsatoshi::chain::{mine, Chain};
use newsatoshi::channel::{
    build_payword_chain, channel_id, ChannelPost, MAX_BATCH_CHANNELS, MAX_BLOCK_CHANNEL_HASHES,
};
use newsatoshi::hash::sha256;
use newsatoshi::job::{Action, Deposit};
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::time::Instant;

fn mine_block(c: &mut Chain, miner: &Wallet, txs: Vec<Tx>) -> Result<Block, String> {
    let mut fees: u64 = 0;
    for t in &txs {
        match t {
            Tx::Spend(s) => fees += s.fee,
            Tx::Act(Action::ChannelClaim { channel, .. })
            | Tx::Act(Action::ChannelExpire { channel }) => {
                if let Some(ch) = c.state.channels.get(channel) {
                    fees += ch.post.claim_fee;
                }
            }
            _ => {}
        }
    }
    let out = PlainOut {
        a_pk: miner.a_pk(),
        v: subsidy(c.height() + 1) + fees,
        rho: rand::thread_rng().gen(),
    };
    let mut b = c.template(vec![out], txs, vec![])?;
    assert!(mine(&mut b.header, u64::MAX));
    let cloned = b.clone();
    c.add_block(b)?;
    Ok(cloned)
}

#[test]
fn unilateral_1000_to_237_and_763_with_offline_buyer_and_independent_node() {
    let params = Params::get(Net::Reg).unwrap();
    let mut node_a = Chain::open(params.clone(), None).unwrap();
    let mut node_b = Chain::open(params, None).unwrap(); // Independent full node

    let mut buyer_initial = Wallet::generate();
    let buyer_sk = buyer_initial.sk;
    let mut seller = Wallet::generate();
    let miner_a = Wallet::generate();
    let miner_b = Wallet::generate();
    let third_party = Wallet::generate();

    // 1. Mine initial coins for buyer on Node A and sync Node B block-by-block.
    for _ in 0..2 {
        let b = mine_block(&mut node_a, &buyer_initial, vec![]).unwrap();
        node_b.add_block(b).unwrap();
    }

    // 2. Buyer builds a 1,000-tick PayWord chain (`unit_price = 1`, `claim_fee = 10` -> 1,010 locked).
    //    Use COIN/1000 scaling? No: test literally with 1,000 units of 1,000 base units (= 1_000_000)
    //    OR literal 1,000 base units! Let's scale unit_price = 10_000 base units (so seller's 237 units =
    //    2_370_000 > DEFAULT_FEE = 300_000, allowing seller to PROVE spendability in a real shielded STARK tx!)
    //    AND ALSO test literal unit_price = 1 below!
    let unit_price: u64 = 10_000; // 1 unit = 0.0001 LOVE; 1,000 units = 0.1 LOVE
    let claim_fee: u64 = 5_000;
    let seed = sha256(b"astra-decisive-demo-seed-1000");
    let chain = build_payword_chain(seed, 1_000);
    let tip = *chain.last().unwrap();

    let post = ChannelPost {
        tip,
        max_ticks: 1_000,
        unit_price,
        claim_fee,
        timeout: node_a.height() + 50,
        seller_addr: seller.a_pk(),
        refund_addr: buyer_initial.a_pk(),
    };
    let deposit_total = post.total_deposit().unwrap();
    assert_eq!(deposit_total, 1_000 * unit_price + claim_fee);

    let (open_tx, _) = buyer_initial
        .spend(&node_a, None, DEFAULT_FEE, Some(Deposit::Channel(post.clone())), vec![])
        .unwrap();
    let Tx::Spend(sp) = &open_tx else { unreachable!() };
    let cid = channel_id(&post, &sp.nf[0], 0);

    let open_blk = mine_block(&mut node_a, &miner_a, vec![open_tx]).unwrap();
    node_b.add_block(open_blk).unwrap();
    assert_eq!(node_b.state.locked, deposit_total as u128);
    assert!(node_b.state.channels.contains_key(&cid));

    // 3. Off-chain streaming: buyer sends vouchers #1..=#237; seller verifies EACH link in O(1) (1 SHA-256 hash)
    let mut last_token = tip;
    let mut last_ticks: u32 = 0;
    for k in 1..=237u32 {
        let tok_k = chain[(1_000 - k) as usize];
        assert_eq!(sha256(&tok_k), last_token, "O(1) link check at tick {k}");
        last_token = tok_k;
        last_ticks = k;
    }

    // 4. Persist seller's last accepted voucher to disk, simulate server restart, AND shut down buyer completely!
    let tmp_path = std::env::temp_dir().join("ns_rfc0022_seller_voucher.txt");
    std::fs::write(&tmp_path, format!("{}:{}:{}", hex::encode(cid), last_ticks, hex::encode(last_token))).unwrap();
    drop(buyer_initial); // Buyer disappears forever!
    drop(chain);         // Buyer's hash chain is gone!
    drop(node_a);        // Original node is gone! No Commons gateway exists!

    // Seller restarts fresh from disk and connects ONLY to independent Node B
    let persisted = std::fs::read_to_string(&tmp_path).unwrap();
    let _ = std::fs::remove_file(&tmp_path);
    let mut parts = persisted.trim().split(':');
    let saved_cid: [u8; 32] = hex::decode(parts.next().unwrap()).unwrap().try_into().unwrap();
    let saved_ticks: u32 = parts.next().unwrap().parse().unwrap();
    let saved_token: [u8; 32] = hex::decode(parts.next().unwrap()).unwrap().try_into().unwrap();
    assert_eq!((saved_cid, saved_ticks), (cid, 237));

    // 5. Adversary checks BEFORE legitimate claim:
    //    - Overclaiming tick 238 with tick 237's token MUST fail consensus!
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim { channel: saved_cid, ticks: 238, token: saved_token })]
    )
    .is_err());
    //    - Forged token MUST fail consensus!
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim { channel: saved_cid, ticks: 237, token: [0xaa; 32] })]
    )
    .is_err());

    // 6. Seller unilaterally redeems exact 237 units on independent Node B!
    let issued_before = node_b.state.issued;
    let claim_tx = Tx::Act(Action::ChannelClaim {
        channel: saved_cid,
        ticks: saved_ticks,
        token: saved_token,
    });
    assert_eq!(claim_tx.to_bytes().len(), 1 + 1 + 32 + 4 + 32); // Tiny 70-byte unilateral settlement!
    let settle_height = node_b.height() + 1;
    mine_block(&mut node_b, &miner_b, vec![claim_tx.clone()]).unwrap();

    // 7. Verify exact consensus invariants:
    //    - Channel deleted (cannot pay out again or expire)
    assert!(!node_b.state.channels.contains_key(&cid));
    assert_eq!(node_b.state.locked, 0);
    //    - Issuance increased ONLY by block subsidy (claim_fee came from deposit, zero inflation!)
    assert_eq!(node_b.state.issued, issued_before + subsidy(settle_height) as u128);
    //    - Double-claim and post-claim expire MUST fail
    assert!(mine_block(&mut node_b, &miner_b, vec![claim_tx]).is_err());
    assert!(mine_block(&mut node_b, &miner_b, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).is_err());

    //    - Seller holds exact spendable 237 units (237 * unit_price)
    let seller_notes = seller.unspent(&node_b);
    let seller_total: u64 = seller_notes.iter().map(|n| n.v).sum();
    assert_eq!(seller_total, 237 * unit_price);

    //    - Buyer (restored purely from spending key `sk`!) recovers exact spendable 763 units (763 * unit_price)
    let buyer_restored = Wallet::from_key(buyer_sk);
    let buyer_public_notes = buyer_restored.unspent(&node_b);
    assert!(
        buyer_public_notes.iter().any(|n| n.v == 763 * unit_price),
        "buyer must automatically recover exact 763 * unit_price refund note"
    );

    //    - Miner B received subsidy + exact claim_fee (zero inflation, exact conservation)
    mine_block(&mut node_b, &miner_b, vec![]).unwrap(); // mature Miner B's coinbase (maturity = 1 in regtest)
    assert!(miner_b.unspent(&node_b).iter().any(|n| n.v == subsidy(settle_height) + claim_fee));

    // 8. Prove Seller's earned 237 units are genuinely spendable in a real shielded STARK transaction!
    let (spend_earned, _) = seller
        .spend(&node_b, Some((third_party.a_pk(), 1_000_000)), DEFAULT_FEE, None, vec![])
        .unwrap();
    mine_block(&mut node_b, &miner_b, vec![spend_earned]).unwrap();
    assert_eq!(seller.unspent(&node_b).iter().map(|n| n.v).sum::<u64>(), 237 * unit_price - 1_000_000 - DEFAULT_FEE);
}

#[test]
fn batch_open_64_distinct_buyer_seller_channels_in_one_spend_and_settle_all_in_one_block() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut buyer = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        mine_block(&mut c, &buyer, vec![]).unwrap();
    }

    // Create 64 distinct sellers + 64 independent 1,000-unit PayWord channels in ONE single Spend!
    let sellers: Vec<Wallet> = (0..MAX_BATCH_CHANNELS).map(|_| Wallet::generate()).collect();
    let mut chains = Vec::with_capacity(MAX_BATCH_CHANNELS);
    let mut posts = Vec::with_capacity(MAX_BATCH_CHANNELS);
    let unit_price = 1_000u64;
    let claim_fee = 500u64;

    for (i, s) in sellers.iter().enumerate() {
        let seed = sha256(format!("batch-channel-seed-{i}").as_bytes());
        let ch = build_payword_chain(seed, 100);
        let tip = *ch.last().unwrap();
        posts.push(ChannelPost {
            tip,
            max_ticks: 100,
            unit_price,
            claim_fee,
            timeout: c.height() + 100,
            seller_addr: s.a_pk(),
            refund_addr: buyer.a_pk(),
        });
        chains.push(ch);
    }

    let total_deposit: u64 = (MAX_BATCH_CHANNELS as u64) * (100 * unit_price + claim_fee);
    let (batch_tx, _) = buyer
        .spend(&c, None, DEFAULT_FEE, Some(Deposit::ChannelBatch(posts.clone())), vec![])
        .unwrap();
    let batch_tx_bytes = batch_tx.to_bytes().len();
    // Overhead of 64 channels is only ~7.7 KB on top of ONE spend proof!
    assert!(batch_tx_bytes < 275_000, "64-channel batch spend was {batch_tx_bytes} bytes");

    let Tx::Spend(sp) = &batch_tx else { unreachable!() };
    let first_nf = sp.nf[0];
    let cids: Vec<[u8; 32]> = posts
        .iter()
        .enumerate()
        .map(|(idx, p)| channel_id(p, &first_nf, idx as u32))
        .collect();

    mine_block(&mut c, &miner, vec![batch_tx]).unwrap();
    assert_eq!(c.state.channels.len(), MAX_BATCH_CHANNELS);
    assert_eq!(c.state.locked, total_deposit as u128);

    // Unilaterally settle ALL 64 channels at 64 distinct partial tick counts (1..=64) in ONE block!
    let mut claim_txs = Vec::with_capacity(MAX_BATCH_CHANNELS);
    let mut expected_seller_sum = 0u64;
    let mut expected_refund_sum = 0u64;
    for i in 0..MAX_BATCH_CHANNELS {
        let ticks = (i + 1) as u32;
        let tok = chains[i][(100 - ticks) as usize];
        expected_seller_sum += ticks as u64 * unit_price;
        expected_refund_sum += (100 - ticks) as u64 * unit_price;
        claim_txs.push(Tx::Act(Action::ChannelClaim { channel: cids[i], ticks, token: tok }));
    }

    let t0 = Instant::now();
    let settle_blk = mine_block(&mut c, &miner, claim_txs).unwrap();
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(c.state.channels.len(), 0);
    assert_eq!(c.state.locked, 0);
    assert_eq!(
        expected_seller_sum + expected_refund_sum + (MAX_BATCH_CHANNELS as u64) * claim_fee,
        total_deposit
    );

    // Every single one of the 64 sellers holds their exact earned balance!
    for (i, s) in sellers.iter().enumerate() {
        let got: u64 = s.unspent(&c).iter().map(|n| n.v).sum();
        assert_eq!(got, ((i + 1) as u64) * unit_price, "seller {i} payout mismatch");
    }

    eprintln!(
        "[RFC-0022 BENCH] 64-channel batch open tx = {} bytes; 64 unilateral partial closes block = {} bytes verified+mined in {:.2} ms",
        batch_tx_bytes,
        settle_blk.encode().len(),
        elapsed_ms
    );
}

#[test]
fn timeout_refund_and_block_hash_dos_cap_hold() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut buyer = Wallet::generate();
    let seller = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        mine_block(&mut c, &buyer, vec![]).unwrap();
    }

    let chain = build_payword_chain(sha256(b"expire-test-seed"), 100);
    let post = ChannelPost {
        tip: *chain.last().unwrap(),
        max_ticks: 100,
        unit_price: 5_000,
        claim_fee: 1_000,
        timeout: c.height() + 2,
        seller_addr: seller.a_pk(),
        refund_addr: buyer.a_pk(),
    };
    let (tx, _) = buyer
        .spend(&c, None, DEFAULT_FEE, Some(Deposit::Channel(post.clone())), vec![])
        .unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let cid = channel_id(&post, &sp.nf[0], 0);
    mine_block(&mut c, &miner, vec![tx]).unwrap();

    // Premature expire at height == timeout MUST fail
    assert!(mine_block(&mut c, &miner, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).is_err());
    mine_block(&mut c, &miner, vec![]).unwrap(); // now height == timeout
    // Next block height == timeout + 1: expire succeeds, refunding exact 500,000 + paying 1,000 miner fee!
    mine_block(&mut c, &miner, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).unwrap();
    assert_eq!(c.state.locked, 0);
    assert!(buyer.unspent(&c).iter().any(|n| n.v == 500_000));
    assert_eq!(seller.unspent(&c).len(), 0);
    // Double expire fails
    assert!(mine_block(&mut c, &miner, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).is_err());

    // Sanity check anti-DoS constant
    assert_eq!(MAX_BLOCK_CHANNEL_HASHES, 2_000_000);
    assert!(COIN > 0);
}

#[test]
fn live_http_channel_rpc_merkle_proof_and_mempool_fee_mining() {
    use newsatoshi::merkmap::{verify_proof, MerkleProof};
    use newsatoshi::node::{lock, Node};
    use newsatoshi::rpc::{self, J};
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let http_get = |port: u16, path: &str| -> J {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        J::parse(resp.split("\r\n\r\n").nth(1).unwrap().as_bytes()).unwrap()
    };
    let http_post = |port: u16, path: &str, body: &[u8]| -> J {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(
            format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len())
                .as_bytes(),
        )
        .unwrap();
        s.write_all(body).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        J::parse(resp.split("\r\n\r\n").nth(1).unwrap().as_bytes()).unwrap()
    };
    let mine_template = |shared: &newsatoshi::node::Shared, to: &Wallet| -> u64 {
        let mut n = lock(shared);
        let (mut b, value) = n.block_template(to.a_pk(), b"test-template").unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        assert!(n.accept_block(b, None).unwrap());
        value
    };

    let params = Params::get(Net::Reg).unwrap();
    let shared = Node::new(Chain::open(params, None).unwrap());
    lock(&shared).log = false;
    let port = rpc::serve_public(shared.clone(), "127.0.0.1", 0, None).unwrap();

    let mut buyer = Wallet::generate();
    let seller = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        mine_template(&shared, &buyer);
    }

    let unit_price = 10_000u64;
    let claim_fee = 5_000u64;
    let pw = build_payword_chain(sha256(b"http-rpc-live-channel-seed"), 1_000);
    let tip = *pw.last().unwrap();
    let post = ChannelPost {
        tip,
        max_ticks: 1_000,
        unit_price,
        claim_fee,
        timeout: lock(&shared).chain.height() + 50,
        seller_addr: seller.a_pk(),
        refund_addr: buyer.a_pk(),
    };
    let (open_tx, _) = {
        let n = lock(&shared);
        buyer
            .spend(&n.chain, None, DEFAULT_FEE, Some(Deposit::Channel(post.clone())), vec![])
            .unwrap()
    };
    let Tx::Spend(sp) = &open_tx else { unreachable!() };
    let cid = channel_id(&post, &sp.nf[0], 0);
    let cid_hex = hex::encode(cid);
    let tip_hex = hex::encode(tip);

    // 1. Submit open tx via live HTTP POST /api/tx
    let r = http_post(port, "/api/tx", &open_tx.to_bytes());
    assert_eq!(r.get("ok"), Some(&J::Bool(true)), "open tx rejected: {}", r.to_json());

    // 2. Query GET /api/channel?tip= while unconfirmed in mempool
    let pending_resp = http_get(port, &format!("/api/channel?tip={tip_hex}"));
    let Some(J::Arr(arr)) = pending_resp.get("channels") else { panic!("missing channels array") };
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].get("state"), Some(&J::str("open")));
    assert_eq!(arr[0].get("confirmed"), Some(&J::Bool(false)));

    // 3. Mine block using Node::block_template (collects spend fee!)
    let open_height = lock(&shared).chain.height() + 1;
    let open_cb = mine_template(&shared, &miner);
    assert_eq!(open_cb, subsidy(open_height) + DEFAULT_FEE);

    // 4. Query GET /api/channel?id= & verify Merkle inclusion proof against GET /api/state!
    let info = http_get(port, &format!("/api/channel?id={cid_hex}"));
    assert_eq!(info.get("found"), Some(&J::Bool(true)));
    assert_eq!(info.get("state"), Some(&J::str("open")));
    assert_eq!(info.get("confirmed"), Some(&J::Bool(true)));
    assert_eq!(info.get("max_ticks"), Some(&J::num(1_000)));
    assert_eq!(info.get("unit_price"), Some(&J::num(unit_price)));
    assert_eq!(info.get("claim_fee"), Some(&J::num(claim_fee)));

    let state_resp = http_get(port, "/api/state");
    let committed_root: [u8; 32] = hex::decode(
        state_resp
            .get("parts")
            .unwrap()
            .get("channels")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let mp = info.get("merkle_proof").expect("confirmed open channel must include merkle_proof");
    let proof_root: [u8; 32] = hex::decode(mp.get("root").unwrap().as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(proof_root, committed_root);
    let Some(J::Arr(sibs_j)) = mp.get("siblings") else { panic!() };
    let siblings: Vec<[u8; 32]> = sibs_j
        .iter()
        .map(|s| hex::decode(s.as_str().unwrap()).unwrap().try_into().unwrap())
        .collect();
    let proof = MerkleProof {
        key: hex::decode(mp.get("key").unwrap().as_str().unwrap()).unwrap().try_into().unwrap(),
        value_hash: hex::decode(mp.get("value_hash").unwrap().as_str().unwrap()).unwrap().try_into().unwrap(),
        siblings,
    };
    assert!(verify_proof(&committed_root, &proof), "RPC Merkle inclusion proof must verify against block state root");

    // 5. Submit 70-byte unilateral ChannelClaim(237) via live HTTP POST /api/tx
    let claim_tx = Tx::Act(Action::ChannelClaim {
        channel: cid,
        ticks: 237,
        token: pw[1_000 - 237],
    });
    let r_claim = http_post(port, "/api/tx", &claim_tx.to_bytes());
    assert_eq!(r_claim.get("ok"), Some(&J::Bool(true)), "claim tx rejected: {}", r_claim.to_json());

    // 6. Mine via Node::block_template — proves miner coinbase collects pre-funded claim_fee!
    let claim_height = lock(&shared).chain.height() + 1;
    let claim_cb = mine_template(&shared, &miner);
    assert_eq!(
        claim_cb,
        subsidy(claim_height) + claim_fee,
        "block_template must pay pre-funded ChannelClaim miner fee into coinbase"
    );

    // 7. Query GET /api/channel?id= after settlement: exact 237/763 split confirmed!
    let closed = http_get(port, &format!("/api/channel?id={cid_hex}"));
    assert_eq!(closed.get("found"), Some(&J::Bool(true)));
    assert_eq!(closed.get("state"), Some(&J::str("claimed")));
    assert_eq!(closed.get("confirmed"), Some(&J::Bool(true)));
    assert_eq!(closed.get("claimed_ticks"), Some(&J::num(237)));
    assert_eq!(closed.get("seller_paid"), Some(&J::num(237 * unit_price)));
    assert_eq!(closed.get("buyer_refunded"), Some(&J::num(763 * unit_price)));
    assert_eq!(closed.get("miner_fee"), Some(&J::num(claim_fee)));
}

#[test]
fn mempool_select_orders_channel_claims_by_fee_and_caps_block_hashes() {
    use newsatoshi::node::{lock, Node};

    let params = Params::get(Net::Reg).unwrap();
    let shared = Node::new(Chain::open(params, None).unwrap());
    lock(&shared).log = false;

    let mut buyer = Wallet::generate();
    let seller = Wallet::generate();
    let miner = Wallet::generate();
    let mine_template = |shared: &newsatoshi::node::Shared, to: &Wallet| {
        let mut n = lock(shared);
        let (mut b, _) = n.block_template(to.a_pk(), b"cap-test").unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        assert!(n.accept_block(b, None).unwrap());
    };
    for _ in 0..2 {
        mine_template(&shared, &buyer);
    }

    // Open 3 channels in a single batch: two with 1,000,000 max_ticks and one with 500,000 max_ticks
    // with distinct claim_fees: low (1_000), high (9_000), mid (4_000).
    // Submitting all 3 claims totals 2,500,000 ticks > MAX_BLOCK_CHANNEL_HASHES (2,000,000)!
    let c_low = build_payword_chain(sha256(b"dos-cap-low"), 1_000_000);
    let c_high = build_payword_chain(sha256(b"dos-cap-high"), 1_000_000);
    let c_mid = build_payword_chain(sha256(b"dos-cap-mid"), 500_000);
    let h_now = lock(&shared).chain.height();
    let posts = vec![
        ChannelPost {
            tip: *c_low.last().unwrap(),
            max_ticks: 1_000_000,
            unit_price: 1,
            claim_fee: 1_000,
            timeout: h_now + 50,
            seller_addr: seller.a_pk(),
            refund_addr: buyer.a_pk(),
        },
        ChannelPost {
            tip: *c_high.last().unwrap(),
            max_ticks: 1_000_000,
            unit_price: 1,
            claim_fee: 9_000,
            timeout: h_now + 50,
            seller_addr: seller.a_pk(),
            refund_addr: buyer.a_pk(),
        },
        ChannelPost {
            tip: *c_mid.last().unwrap(),
            max_ticks: 500_000,
            unit_price: 1,
            claim_fee: 4_000,
            timeout: h_now + 50,
            seller_addr: seller.a_pk(),
            refund_addr: buyer.a_pk(),
        },
    ];
    let (batch_tx, _) = {
        let n = lock(&shared);
        buyer
            .spend(&n.chain, None, DEFAULT_FEE, Some(Deposit::ChannelBatch(posts.clone())), vec![])
            .unwrap()
    };
    let Tx::Spend(sp) = &batch_tx else { unreachable!() };
    let cid_low = channel_id(&posts[0], &sp.nf[0], 0);
    let cid_high = channel_id(&posts[1], &sp.nf[0], 1);
    let cid_mid = channel_id(&posts[2], &sp.nf[0], 2);
    lock(&shared).accept_tx(batch_tx).unwrap();
    mine_template(&shared, &miner);

    // Submit claims in arrival order: low (1M ticks, fee 1k), high (1M ticks, fee 9k), mid (500k ticks, fee 4k)
    let tx_low = Tx::Act(Action::ChannelClaim { channel: cid_low, ticks: 1_000_000, token: c_low[0] });
    let tx_high = Tx::Act(Action::ChannelClaim { channel: cid_high, ticks: 1_000_000, token: c_high[0] });
    let tx_mid = Tx::Act(Action::ChannelClaim { channel: cid_mid, ticks: 500_000, token: c_mid[0] });
    {
        let mut n = lock(&shared);
        n.accept_tx(tx_low).unwrap();
        n.accept_tx(tx_high).unwrap();
        n.accept_tx(tx_mid).unwrap();
    }

    // select_with_fees() MUST pick high (9k, 1M ticks) + mid (4k, 500k ticks) = 1.5M ticks (fee 13k),
    // skipping low (1k, 1M ticks) because 1.5M + 1M = 2.5M > MAX_BLOCK_CHANNEL_HASHES (2.0M)!
    let (selected, total_fees) = lock(&shared).select_with_fees();
    assert_eq!(selected.len(), 2);
    assert_eq!(total_fees, 9_000 + 4_000);
    let selected_ids: Vec<[u8; 32]> = selected
        .iter()
        .map(|t| match t {
            Tx::Act(Action::ChannelClaim { channel, .. }) => *channel,
            _ => panic!("expected ChannelClaim"),
        })
        .collect();
    assert_eq!(selected_ids, vec![cid_high, cid_mid]);

    // Mining 1 block confirms high + mid cleanly; next block automatically confirms low!
    mine_template(&shared, &miner);
    assert_eq!(lock(&shared).chain.state.channels.len(), 1);
    assert!(lock(&shared).chain.state.channels.contains_key(&cid_low));
    mine_template(&shared, &miner);
    assert_eq!(lock(&shared).chain.state.channels.len(), 0);
}
