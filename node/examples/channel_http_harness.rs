//! Live regtest HTTP harness for cross-stack RFC-0022 PayWord Channel verification
//! (Rust L1 Consensus + Seller SLH-DSA Auth + O(log N) MerkleMap + `/api/channel` + `POST /api/tx`
//!  ↔ Node.js `@newsatoshi/402` & Python `newsatoshi_402`).
//!
//! Prints one JSON line with `{port, channel_id, tip, seed, max_ticks, unit_price, claim_fee,
//! seller, seller_vk, refund, claim_sig_237, buyer_forged_sig_1}` to stdout, then mines one
//! block via `Node::block_template` for every line written to stdin (exiting cleanly on EOF).

use newsatoshi::chain::{mine, Chain};
use newsatoshi::channel::{build_payword_chain, channel_id, claim_message, ChannelPost};
use newsatoshi::hash::sha256;
use newsatoshi::job::Deposit;
use newsatoshi::node::{lock, Node};
use newsatoshi::params::{Net, Params, DEFAULT_FEE};
use newsatoshi::rpc;
use newsatoshi::tx::Tx;
use newsatoshi::wallet::Wallet;
use std::io::{self, BufRead, Write};

fn main() {
    let params = Params::get(Net::Reg).expect("regtest params");
    let shared = Node::new(Chain::open(params, None).expect("open chain"));
    lock(&shared).log = false;
    let port = rpc::serve_public(shared.clone(), "127.0.0.1", 0, None).expect("serve_public");

    let mut buyer = Wallet::generate();
    let seller = Wallet::generate();
    let miner = Wallet::generate();
    let seller_key = seller.job_key().expect("seller job key");
    let buyer_key = buyer.job_key().expect("buyer job key");
    let seller_vk: [u8; 32] = seller_key.vk().try_into().unwrap();

    let mine_one = |to: &Wallet| -> u64 {
        let mut n = lock(&shared);
        let (mut b, cb_val) = n.block_template(to.a_pk(), b"harness").expect("template");
        assert!(mine(&mut b.header, u64::MAX));
        assert!(n.accept_block(b, None).expect("accept"));
        cb_val
    };

    for _ in 0..2 {
        mine_one(&buyer);
    }

    let seed = sha256(b"cross-stack-live-http-rfc0022-seed");
    let max_ticks = 1_000u32;
    let unit_price = 10_000u64;
    let claim_fee = 5_000u64;
    let chain = build_payword_chain(seed, max_ticks);
    let tip = *chain.last().unwrap();

    let post = ChannelPost {
        tip,
        max_ticks,
        unit_price,
        claim_fee,
        timeout: lock(&shared).chain.height() + 50,
        seller_addr: seller.a_pk(),
        seller_vk,
        refund_addr: buyer.a_pk(),
    };
    let (open_tx, _) = {
        let n = lock(&shared);
        buyer
            .spend(&n.chain, None, DEFAULT_FEE, Some(Deposit::Channel(post.clone())), vec![])
            .expect("open spend")
    };
    let Tx::Spend(sp) = &open_tx else { unreachable!() };
    let cid = channel_id(&post, &sp.nf[0], 0);
    lock(&shared).accept_tx(open_tx).expect("admit open tx");
    mine_one(&miner);

    let tok_237 = chain[(max_ticks - 237) as usize];
    let claim_sig_237 = seller_key.sign(&claim_message(&cid, 237, &tok_237));
    let tok_1 = chain[(max_ticks - 1) as usize];
    let buyer_forged_sig_1 = buyer_key.sign(&claim_message(&cid, 1, &tok_1));

    let ready = format!(
        "{{\"port\":{port},\"channel_id\":\"{}\",\"tip\":\"{}\",\"seed\":\"{}\",\"max_ticks\":{max_ticks},\"unit_price\":{unit_price},\"claim_fee\":{claim_fee},\"seller\":\"{}\",\"seller_vk\":\"{}\",\"refund\":\"{}\",\"claim_sig_237\":\"{}\",\"buyer_forged_sig_1\":\"{}\"}}",
        hex::encode(cid),
        hex::encode(tip),
        hex::encode(seed),
        seller.address(),
        hex::encode(seller_vk),
        buyer.address(),
        hex::encode(claim_sig_237),
        hex::encode(buyer_forged_sig_1),
    );
    println!("{ready}");
    io::stdout().flush().ok();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let Ok(cmd) = line else { break };
        if cmd.trim() == "quit" {
            break;
        }
        let cb_val = mine_one(&miner);
        let h = lock(&shared).chain.height();
        println!("{{\"mined\":true,\"height\":{h},\"coinbase_value\":{cb_val}}}");
        io::stdout().flush().ok();
    }
}
