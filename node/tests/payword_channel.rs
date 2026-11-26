//! RFC-0022 End-to-End L1 Consensus Proof (Seller-Authorized SLH-DSA Close + Adversarial Buyer Defense):
//! 1. **Unilateral Redemption (`1,000 → 237 / 763`) + Adversarial Buyer Front-Run Defense:**
//!    - Buyer funds a 1,000-unit PayWord channel (+5,000 pre-funded miner fee) committing to both
//!      PayWord `tip` AND Seller's NIST FIPS 205 `SLH-DSA-SHA2-128s` verifying key (`seller_vk`).
//!    - Buyer streams 237 sequential O(1) PayWord vouchers off-chain; Seller verifies each link
//!      in 1 SHA-256 hash and persists `(237, token_237)` to disk.
//!    - **Adversarial Buyer Attack:** Even though Buyer holds `token_1` (every earlier voucher!),
//!      Buyer CANNOT close the channel early at `ticks = 1` (neither unsigned, nor signed with
//!      Buyer's own key, nor by replaying Seller's mempool `sig_237` on `ticks = 1`).
//!    - Simulate a full Seller server restart AND drop Buyer + Node A completely.
//!    - Seller signs `(cid, 237, token_237)` with its SLH-DSA key and submits `Action::ChannelClaim`
//!      to independent Node B → Seller holds spendable `237` (and spends it in a shielded STARK tx),
//!      Buyer recovers `763`, Miner B collects exact `claim_fee`.
//! 2. **64-Channel Batched Open (`Deposit::ChannelBatch`) & 64 Seller-Signed Closes in One Block.**
//! 3. **Timeout Refund (`Action::ChannelExpire`) & Height-Gated Hard-Fork Activation (`rfc0022_from`).**
//! 4. **Live HTTP `/api/channel` + Merkle Inclusion Proof Verification + Mempool Fee & Hash-Cap Ordering.**

use newsatoshi::chain::{mine, Chain};
use newsatoshi::channel::{
    build_payword_chain, channel_id, claim_message, ChannelPost, MAX_BATCH_CHANNELS,
    MAX_BLOCK_CHANNEL_HASHES,
};
use newsatoshi::hash::sha256;
use newsatoshi::job::{Action, Deposit};
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;
use std::time::Instant;

fn vk_of(w: &Wallet) -> [u8; 32] {
    w.job_key().unwrap().vk().try_into().unwrap()
}

fn sign_claim(seller: &Wallet, cid: &[u8; 32], ticks: u32, token: &[u8; 32]) -> Vec<u8> {
    seller.job_key().unwrap().sign(&claim_message(cid, ticks, token))
}

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
fn unilateral_1000_to_237_and_763_blocks_adversarial_buyer_and_settles_on_independent_node() {
    let params = Params::get(Net::Reg).unwrap();
    let mut node_a = Chain::open(params.clone(), None).unwrap();
    let mut node_b = Chain::open(params, None).unwrap(); // Independent full node

    let mut buyer_initial = Wallet::generate();
    let buyer_sk = buyer_initial.sk;
    let mut seller = Wallet::generate();
    let miner_a = Wallet::generate();
    let miner_b = Wallet::generate();
    let third_party = Wallet::generate();

    for _ in 0..2 {
        let b = mine_block(&mut node_a, &buyer_initial, vec![]).unwrap();
        node_b.add_block(b).unwrap();
    }

    let unit_price: u64 = 10_000;
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
        seller_vk: vk_of(&seller),
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

    // Off-chain streaming: buyer sends vouchers #1..=#237; seller verifies each in O(1)
    let mut last_token = tip;
    let mut last_ticks: u32 = 0;
    for k in 1..=237u32 {
        let tok_k = chain[(1_000 - k) as usize];
        assert_eq!(sha256(&tok_k), last_token, "O(1) link check at tick {k}");
        last_token = tok_k;
        last_ticks = k;
    }

    // ADVERSARIAL BUYER ATTACKS (before buyer goes offline!):
    // Buyer holds token_1 and attempts to close early at ticks=1 to steal 236 API calls!
    let token_1 = chain[1_000 - 1];
    let buyer_forged_sig = sign_claim(&buyer_initial, &cid, 1, &token_1);
    let seller_sig_237 = sign_claim(&seller, &cid, 237, &last_token);
    // Attack A: unsigned ticks=1 early close MUST fail!
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim { channel: cid, ticks: 1, token: token_1, sig: vec![] })]
    )
    .is_err());
    // Attack B: buyer-signed ticks=1 early close MUST fail!
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim {
            channel: cid,
            ticks: 1,
            token: token_1,
            sig: buyer_forged_sig,
        })]
    )
    .is_err());
    // Attack C: mempool front-run substituting seller's sig_237 onto (ticks=1, token_1) MUST fail!
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim {
            channel: cid,
            ticks: 1,
            token: token_1,
            sig: seller_sig_237,
        })]
    )
    .is_err());

    // Persist seller's last voucher, simulate restart, and drop buyer + Node A completely!
    let tmp_path = std::env::temp_dir().join("ns_rfc0022_seller_voucher.txt");
    std::fs::write(&tmp_path, format!("{}:{}:{}", hex::encode(cid), last_ticks, hex::encode(last_token))).unwrap();
    drop(buyer_initial);
    drop(chain);
    drop(node_a);

    let persisted = std::fs::read_to_string(&tmp_path).unwrap();
    let _ = std::fs::remove_file(&tmp_path);
    let mut parts = persisted.trim().split(':');
    let saved_cid: [u8; 32] = hex::decode(parts.next().unwrap()).unwrap().try_into().unwrap();
    let saved_ticks: u32 = parts.next().unwrap().parse().unwrap();
    let saved_token: [u8; 32] = hex::decode(parts.next().unwrap()).unwrap().try_into().unwrap();
    assert_eq!((saved_cid, saved_ticks), (cid, 237));

    // ADVERSARIAL SELLER ATTACKS:
    // Overclaiming tick 238 EVEN WITH Seller's valid SLH-DSA signature MUST fail!
    let overclaim_sig = sign_claim(&seller, &saved_cid, 238, &saved_token);
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim {
            channel: saved_cid,
            ticks: 238,
            token: saved_token,
            sig: overclaim_sig,
        })]
    )
    .is_err());
    // Forged token EVEN WITH Seller's valid signature MUST fail!
    let forged_tok = [0xaa; 32];
    let forged_sig = sign_claim(&seller, &saved_cid, 237, &forged_tok);
    assert!(mine_block(
        &mut node_b,
        &miner_b,
        vec![Tx::Act(Action::ChannelClaim {
            channel: saved_cid,
            ticks: 237,
            token: forged_tok,
            sig: forged_sig,
        })]
    )
    .is_err());

    // Legitimate seller-signed unilateral claim on independent Node B!
    let issued_before = node_b.state.issued;
    let valid_sig = sign_claim(&seller, &saved_cid, saved_ticks, &saved_token);
    let claim_tx = Tx::Act(Action::ChannelClaim {
        channel: saved_cid,
        ticks: saved_ticks,
        token: saved_token,
        sig: valid_sig,
    });
    assert_eq!(claim_tx.to_bytes().len(), 1 + 1 + 32 + 4 + 32 + 4 + 7856); // 7,930 bytes (FIPS 205 signed)
    let settle_height = node_b.height() + 1;
    mine_block(&mut node_b, &miner_b, vec![claim_tx.clone()]).unwrap();

    assert!(!node_b.state.channels.contains_key(&cid));
    assert_eq!(node_b.state.locked, 0);
    assert_eq!(node_b.state.issued, issued_before + subsidy(settle_height) as u128);
    assert!(mine_block(&mut node_b, &miner_b, vec![claim_tx]).is_err());
    assert!(mine_block(&mut node_b, &miner_b, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).is_err());

    assert_eq!(seller.unspent(&node_b).iter().map(|n| n.v).sum::<u64>(), 237 * unit_price);
    let buyer_restored = Wallet::from_key(buyer_sk);
    assert!(buyer_restored.unspent(&node_b).iter().any(|n| n.v == 763 * unit_price));

    mine_block(&mut node_b, &miner_b, vec![]).unwrap();
    assert!(miner_b.unspent(&node_b).iter().any(|n| n.v == subsidy(settle_height) + claim_fee));

    // Seller spends earned 237 units in a real shielded STARK tx!
    let (spend_earned, _) = seller
        .spend(&node_b, Some((third_party.a_pk(), 1_000_000)), DEFAULT_FEE, None, vec![])
        .unwrap();
    mine_block(&mut node_b, &miner_b, vec![spend_earned]).unwrap();
    assert_eq!(
        seller.unspent(&node_b).iter().map(|n| n.v).sum::<u64>(),
        237 * unit_price - 1_000_000 - DEFAULT_FEE
    );
}

#[test]
fn batch_open_64_distinct_buyer_seller_channels_in_one_spend_and_settle_all_in_one_block() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut buyer = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        mine_block(&mut c, &buyer, vec![]).unwrap();
    }

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
            seller_vk: vk_of(s),
            refund_addr: buyer.a_pk(),
        });
        chains.push(ch);
    }

    let total_deposit: u64 = (MAX_BATCH_CHANNELS as u64) * (100 * unit_price + claim_fee);
    let (batch_tx, _) = buyer
        .spend(&c, None, DEFAULT_FEE, Some(Deposit::ChannelBatch(posts.clone())), vec![])
        .unwrap();
    let batch_tx_bytes = batch_tx.to_bytes().len();
    assert!(batch_tx_bytes < 280_000, "64-channel batch spend was {batch_tx_bytes} bytes");

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

    // Unilaterally settle ALL 64 channels (seller-signed!) at ticks 1..=64 in ONE block!
    let mut claim_txs = Vec::with_capacity(MAX_BATCH_CHANNELS);
    for i in 0..MAX_BATCH_CHANNELS {
        let ticks = (i + 1) as u32;
        let tok = chains[i][(100 - ticks) as usize];
        let sig = sign_claim(&sellers[i], &cids[i], ticks, &tok);
        claim_txs.push(Tx::Act(Action::ChannelClaim { channel: cids[i], ticks, token: tok, sig }));
    }

    let t0 = Instant::now();
    let settle_blk = mine_block(&mut c, &miner, claim_txs).unwrap();
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(c.state.channels.len(), 0);
    assert_eq!(c.state.locked, 0);

    for (i, s) in sellers.iter().enumerate() {
        let got: u64 = s.unspent(&c).iter().map(|n| n.v).sum();
        assert_eq!(got, ((i + 1) as u64) * unit_price, "seller {i} payout mismatch");
    }

    eprintln!(
        "[RFC-0022 BENCH] 64-channel batch open tx = {} bytes; 64 SLH-DSA seller-signed closes block = {} bytes verified+mined in {:.2} ms",
        batch_tx_bytes,
        settle_blk.encode().len(),
        elapsed_ms
    );
}

#[test]
fn timeout_refund_and_height_gated_hardfork_activation_hold() {
    // Configure regtest with explicit height-gated activation at height 4!
    let mut params = Params::get(Net::Reg).unwrap();
    params.rfc0022_from = Some(4);
    let mut c = Chain::open(params, None).unwrap();
    let mut buyer = Wallet::generate();
    let seller = Wallet::generate();
    let miner = Wallet::generate();
    for _ in 0..2 {
        mine_block(&mut c, &buyer, vec![]).unwrap(); // heights 1, 2
    }

    let chain = build_payword_chain(sha256(b"expire-test-seed"), 100);
    let post = ChannelPost {
        tip: *chain.last().unwrap(),
        max_ticks: 100,
        unit_price: 5_000,
        claim_fee: 1_000,
        timeout: c.height() + 4,
        seller_addr: seller.a_pk(),
        seller_vk: vk_of(&seller),
        refund_addr: buyer.a_pk(),
    };
    let (tx, _) = buyer
        .spend(&c, None, DEFAULT_FEE, Some(Deposit::Channel(post.clone())), vec![])
        .unwrap();
    let Tx::Spend(sp) = &tx else { unreachable!() };
    let cid = channel_id(&post, &sp.nf[0], 0);

    // Height 3 < rfc0022_from (4): MUST reject RFC-0022 channel open!
    let err = mine_block(&mut c, &miner, vec![tx.clone()]).unwrap_err();
    assert!(err.contains("not active"), "expected pre-activation rejection, got: {err}");

    // Advance to height 3, then block 4 activates RFC-0022!
    mine_block(&mut c, &miner, vec![]).unwrap(); // height 3
    mine_block(&mut c, &miner, vec![tx]).unwrap(); // height 4 (active!)

    // Premature expire before timeout (height 5 <= 6) fails
    assert!(mine_block(&mut c, &miner, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).is_err());
    mine_block(&mut c, &miner, vec![]).unwrap(); // height 5
    mine_block(&mut c, &miner, vec![]).unwrap(); // height 6 == timeout
    // Height 7 > timeout: unsigned expire succeeds, refunding 500,000 + paying 1,000 miner fee!
    mine_block(&mut c, &miner, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).unwrap();
    assert_eq!(c.state.locked, 0);
    assert!(buyer.unspent(&c).iter().any(|n| n.v == 500_000));
    assert_eq!(seller.unspent(&c).len(), 0);
    assert!(mine_block(&mut c, &miner, vec![Tx::Act(Action::ChannelExpire { channel: cid })]).is_err());

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
        seller_vk: vk_of(&seller),
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

    let r = http_post(port, "/api/tx", &open_tx.to_bytes());
    assert_eq!(r.get("ok"), Some(&J::Bool(true)));

    let pending_resp = http_get(port, &format!("/api/channel?tip={tip_hex}"));
    let Some(J::Arr(arr)) = pending_resp.get("channels") else { panic!("missing channels array") };
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].get("state"), Some(&J::str("open")));
    assert_eq!(arr[0].get("confirmed"), Some(&J::Bool(false)));

    let open_height = lock(&shared).chain.height() + 1;
    let open_cb = mine_template(&shared, &miner);
    assert_eq!(open_cb, subsidy(open_height) + DEFAULT_FEE);

    let info = http_get(port, &format!("/api/channel?id={cid_hex}"));
    assert_eq!(info.get("found"), Some(&J::Bool(true)));
    assert_eq!(info.get("state"), Some(&J::str("open")));
    assert_eq!(info.get("confirmed"), Some(&J::Bool(true)));
    assert_eq!(info.get("seller_vk"), Some(&J::str(hex::encode(vk_of(&seller)))));

    let state_resp = http_get(port, "/api/state");
    let committed_root: [u8; 32] = hex::decode(
        state_resp.get("parts").unwrap().get("channels").unwrap().as_str().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let mp = info.get("merkle_proof").expect("confirmed open channel must include merkle_proof");
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
    assert!(verify_proof(&committed_root, &proof));

    // Adversarial buyer HTTP POST /api/tx attempting early close at ticks=1 MUST be rejected!
    let forged_tx = Tx::Act(Action::ChannelClaim {
        channel: cid,
        ticks: 1,
        token: pw[1_000 - 1],
        sig: sign_claim(&buyer, &cid, 1, &pw[1_000 - 1]),
    });
    let r_forged = http_post(port, "/api/tx", &forged_tx.to_bytes());
    assert_eq!(r_forged.get("ok"), Some(&J::Bool(false)));

    // Seller-signed ChannelClaim(237) via live HTTP POST /api/tx succeeds!
    let tok_237 = pw[1_000 - 237];
    let claim_tx = Tx::Act(Action::ChannelClaim {
        channel: cid,
        ticks: 237,
        token: tok_237,
        sig: sign_claim(&seller, &cid, 237, &tok_237),
    });
    let r_claim = http_post(port, "/api/tx", &claim_tx.to_bytes());
    assert_eq!(r_claim.get("ok"), Some(&J::Bool(true)), "claim tx rejected: {}", r_claim.to_json());

    let claim_height = lock(&shared).chain.height() + 1;
    let claim_cb = mine_template(&shared, &miner);
    assert_eq!(claim_cb, subsidy(claim_height) + claim_fee);

    let closed = http_get(port, &format!("/api/channel?id={cid_hex}"));
    assert_eq!(closed.get("state"), Some(&J::str("claimed")));
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

    let c_low = build_payword_chain(sha256(b"dos-cap-low"), 1_000_000);
    let c_high = build_payword_chain(sha256(b"dos-cap-high"), 1_000_000);
    let c_mid = build_payword_chain(sha256(b"dos-cap-mid"), 500_000);
    let h_now = lock(&shared).chain.height();
    let svk = vk_of(&seller);
    let posts = vec![
        ChannelPost {
            tip: *c_low.last().unwrap(),
            max_ticks: 1_000_000,
            unit_price: 1,
            claim_fee: 1_000,
            timeout: h_now + 50,
            seller_addr: seller.a_pk(),
            seller_vk: svk,
            refund_addr: buyer.a_pk(),
        },
        ChannelPost {
            tip: *c_high.last().unwrap(),
            max_ticks: 1_000_000,
            unit_price: 1,
            claim_fee: 9_000,
            timeout: h_now + 50,
            seller_addr: seller.a_pk(),
            seller_vk: svk,
            refund_addr: buyer.a_pk(),
        },
        ChannelPost {
            tip: *c_mid.last().unwrap(),
            max_ticks: 500_000,
            unit_price: 1,
            claim_fee: 4_000,
            timeout: h_now + 50,
            seller_addr: seller.a_pk(),
            seller_vk: svk,
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

    let tx_low = Tx::Act(Action::ChannelClaim {
        channel: cid_low,
        ticks: 1_000_000,
        token: c_low[0],
        sig: sign_claim(&seller, &cid_low, 1_000_000, &c_low[0]),
    });
    let tx_high = Tx::Act(Action::ChannelClaim {
        channel: cid_high,
        ticks: 1_000_000,
        token: c_high[0],
        sig: sign_claim(&seller, &cid_high, 1_000_000, &c_high[0]),
    });
    let tx_mid = Tx::Act(Action::ChannelClaim {
        channel: cid_mid,
        ticks: 500_000,
        token: c_mid[0],
        sig: sign_claim(&seller, &cid_mid, 500_000, &c_mid[0]),
    });
    {
        let mut n = lock(&shared);
        n.accept_tx(tx_low).unwrap();
        n.accept_tx(tx_high).unwrap();
        n.accept_tx(tx_mid).unwrap();
    }

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

    mine_template(&shared, &miner);
    assert_eq!(lock(&shared).chain.state.channels.len(), 1);
    assert!(lock(&shared).chain.state.channels.contains_key(&cid_low));
    mine_template(&shared, &miner);
    assert_eq!(lock(&shared).chain.state.channels.len(), 0);
}
