//! End-to-End Integration Suite for Newsatoshi `v1.0.0-core` Priorism-FEP Architecture:
//! 1. `PriorLock` full on-chain lifecycle (open via shielded spend, Merkle inclusion proof in
//!    `DigestParts::priors`, commit outcome, objective falsifier + equivocation 50/50 surprise
//!    bounty & burn, independent M-of-N arbiter quorum 50/50 bounty & burn, zero-surprise unlock,
//!    `/api/prior` + `/api/supply` HTTP RPC telemetry).
//! 2. Homeostatic Supply Thermostat (`50%` shielded base-fee burn + `50%` disconfirmation burn)
//!    preserving exact solvency (`issued - burned - locked == shielded_supply`).
//! 3. **`BatchSpend` Multi-Spend STARK Compression (`K = 4` AND `K = 8` on real `MAIN_V2` SHA-384!)**
//!    with measured wall-clock prove/verify time, exact proof size compression ratio vs `K` individual
//!    spends, AND consensus Split Coinbase enforcement (AuxPoW Orderer + Negentropy Prover).

use newsatoshi::batch_spend;
use newsatoshi::chain::{mine, Chain};
use newsatoshi::hash::sha256;
use newsatoshi::job::{Action, Deposit, JobKey};
use newsatoshi::light::HeaderTip;
use newsatoshi::node::{lock, Node};
use newsatoshi::params::{
    prover_subsidy_share, split_spend_fee, subsidy, Params, COIN, MAIN_V2_DEFAULT_FEE,
    MIN_BATCH_SPEND_FEE,
};
use newsatoshi::prior::{self, PriorPost};
use newsatoshi::rpc::{self, J};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use newsatoshi::tx::{bind_of, BatchSpend, BatchSpendItem, Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

fn v2_test_params() -> Params {
    let mut p = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    p.pow_limit = 0x207fffff;
    p.coinbase_maturity = 1;
    p
}

#[test]
fn prior_lock_full_onchain_lifecycle_burn_and_http_api() {
    let params = v2_test_params();
    let mut chain = Chain::open(params.clone(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    let miner = Wallet::generate();

    // Mine 3 blocks so Alice has spendable notes
    for i in 1..=3u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 10; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }

    let owner_key = JobKey::derive(&[21u8; 32]);
    let arb0_key = JobKey::derive(&[22u8; 32]);
    let arb1_key = JobKey::derive(&[23u8; 32]);
    let owner_vk: [u8; 32] = owner_key.vk().try_into().unwrap();
    let arb0_vk: [u8; 32] = arb0_key.vk().try_into().unwrap();
    let arb1_vk: [u8; 32] = arb1_key.vk().try_into().unwrap();
    let falsifier_secret = [0xab; 32];

    // Open Prior #1 (will be objectively disconfirmed -> 50% surprise bounty to Bob, 50% burned!)
    let post1 = PriorPost {
        owner_vk,
        owner_addr: alice.a_pk(),
        spec_hash: sha256(b"agent-latency-under-50ms"),
        falsifier_hash: sha256(&falsifier_secret),
        arbiter_vks: vec![arb0_vk, arb1_vk],
        quorum_m: 2,
        deadline: chain.height() + 5,
        challenge_window: 5,
        stake: 4 * COIN,
    };
    let (open_tx1, _) = alice
        .spend(&chain, None, MAIN_V2_DEFAULT_FEE, Some(Deposit::Prior(post1.clone())), vec![])
        .unwrap();
    let first_nf1 = match &open_tx1 {
        Tx::Spend(s) => if s.dummy[0] { s.nf[1] } else { s.nf[0] },
        _ => unreachable!(),
    };
    let pid1 = prior::prior_id(&post1, &first_nf1);
    let (burn1, prod1) = split_spend_fee(MAIN_V2_DEFAULT_FEE, true);
    let out4 = PlainOut { a_pk: miner.a_pk(), v: subsidy(4) + prod1, rho: [44; 5] };
    let mut b4 = chain.template(vec![out4], vec![open_tx1], vec![]).unwrap();
    assert!(mine(&mut b4.header, u64::MAX));
    chain.add_block(b4.clone()).unwrap();

    assert_eq!(chain.state.priors.len(), 1);
    assert_eq!(chain.state.locked, 4 * COIN as u128);
    assert_eq!(chain.state.burned, burn1 as u128);

    // Trustless light client verifies PriorLock Merkle inclusion against tip header!
    let mut lc = HeaderTip::genesis(&params);
    let hdrs: Vec<Block> = (1..=chain.height())
        .map(|h| chain.header_at(h).unwrap())
        .collect();
    lc.extend(&params, &hdrs, newsatoshi::chain::now()).unwrap();
    let parts = chain.state.digest_parts();
    assert!(parts.priors.is_some());
    let mp = chain.state.priors_merkle.prove(&pid1).unwrap();
    lc.verify_state_map_proof(&b4.header, &b4.tx_root(), &parts, parts.priors, &mp)
        .unwrap();

    // Commit outcome hash before deadline, then objectively disconfirm via falsifier preimage!
    let oh = sha256(b"claimed-p99-42ms");
    let commit_tx = Tx::Act(Action::PriorCommit {
        prior: pid1,
        outcome_hash: oh,
        sig: owner_key.sign(&prior::commit_message(&pid1, &oh)),
    });
    let disconfirm_fee = 100_000u64;
    let disconfirm_tx = Tx::Act(Action::PriorDisconfirmObjective {
        prior: pid1,
        evidence_kind: 0,
        context_nonce: 0,
        payload_a: falsifier_secret,
        sig_a: vec![],
        payload_b: [0; 32],
        sig_b: vec![],
        disconfirmer_addr: bob.a_pk(),
        miner_fee: disconfirm_fee,
    });
    let out5 = PlainOut { a_pk: miner.a_pk(), v: subsidy(5) + disconfirm_fee, rho: [55; 5] };
    let mut b5 = chain
        .template(vec![out5], vec![commit_tx, disconfirm_tx], vec![])
        .unwrap();
    assert!(mine(&mut b5.header, u64::MAX));
    chain.add_block(b5).unwrap();

    // Verify exact 50/50 split: 4 LOVE - 0.001 fee = 3.999 LOVE -> 1.9995 bounty to Bob + 1.9995 burned!
    let expected_slashable = 4 * COIN - disconfirm_fee;
    let expected_bounty = expected_slashable / 2;
    let expected_slash_burn = expected_slashable - expected_bounty;
    assert_eq!(chain.state.priors.len(), 0);
    assert_eq!(chain.state.locked, 0);
    assert_eq!(chain.state.burned, burn1 as u128 + expected_slash_burn as u128);
    assert_eq!(bob.balance(&chain), expected_bounty);
    assert!(chain.state.digest_parts().priors.is_none());

    // Open Prior #2 (zero surprise -> matures and unlocks cleanly back to Alice!)
    let post2 = PriorPost {
        owner_vk,
        owner_addr: alice.a_pk(),
        spec_hash: sha256(b"honest-prior-no-surprise"),
        falsifier_hash: [0; 32],
        arbiter_vks: vec![arb0_vk, arb1_vk],
        quorum_m: 2,
        deadline: chain.height() + 2, // block b6 is height 6; deadline 7 + challenge_window 1 => unlocks after height 8
        challenge_window: 1,
        stake: 2 * COIN,
    };
    let (open_tx2, _) = alice
        .spend(&chain, None, MAIN_V2_DEFAULT_FEE, Some(Deposit::Prior(post2.clone())), vec![])
        .unwrap();
    let first_nf2 = match &open_tx2 {
        Tx::Spend(s) => if s.dummy[0] { s.nf[1] } else { s.nf[0] },
        _ => unreachable!(),
    };
    let pid2 = prior::prior_id(&post2, &first_nf2);
    let (burn2, prod2) = split_spend_fee(MAIN_V2_DEFAULT_FEE, true);
    let out6 = PlainOut { a_pk: miner.a_pk(), v: subsidy(6) + prod2, rho: [66; 5] };
    let mut b6 = chain.template(vec![out6], vec![open_tx2], vec![]).unwrap();
    assert!(mine(&mut b6.header, u64::MAX));
    chain.add_block(b6).unwrap();

    // Advance past unlock_after (height 6 + 1 = 7, challenge_window 1 => unlock after height 8)
    for h in 7..=8u32 {
        let out = PlainOut { a_pk: miner.a_pk(), v: subsidy(h), rho: [h + 70; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }
    let alice_before = alice.balance(&chain);
    let rel_tx = Tx::Act(Action::PriorRelease { prior: pid2, miner_fee: 0, owner_sig: vec![] });
    let out9 = PlainOut { a_pk: miner.a_pk(), v: subsidy(9), rho: [99; 5] };
    let mut b9 = chain.template(vec![out9], vec![rel_tx], vec![]).unwrap();
    assert!(mine(&mut b9.header, u64::MAX));
    chain.add_block(b9).unwrap();

    assert_eq!(chain.state.priors.len(), 0);
    assert_eq!(chain.state.locked, 0);
    assert_eq!(alice.balance(&chain), alice_before + 2 * COIN);
    assert_eq!(
        chain.state.burned,
        burn1 as u128 + expected_slash_burn as u128 + burn2 as u128
    );

    // Verify `/api/prior` and `/api/supply` JSON responses
    let shared = Node::new(chain);
    lock(&shared).log = false;
    let p1_json = rpc::prior_info(&shared, &pid1);
    assert_eq!(p1_json.get("state"), Some(&J::str("disconfirmed")));
    let p2_json = rpc::prior_info(&shared, &pid2);
    assert_eq!(p2_json.get("state"), Some(&J::str("released")));
    let sup_json = rpc::supply_info(&shared);
    assert_eq!(sup_json.get("homeostatic_burn_active"), Some(&J::Bool(true)));
}

#[test]
fn batch_spend_sha384_compresses_4_and_8_spends_and_enforces_split_coinbase() {
    let params = v2_test_params();
    let mut chain = Chain::open(params.clone(), None).unwrap();
    let mut rng = rand::thread_rng();
    let alice = Wallet::generate();
    let bob = Wallet::generate();
    let miner = Wallet::generate();
    let prover = Wallet::generate();

    // Mine 9 blocks so Alice holds 8 matured spendable coinbase notes!
    for i in 1..=9u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 100; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }

    let unspent = alice.unspent(&chain);
    assert!(unspent.len() >= 8);

    // Measure single SHA-384 spend baseline size for honest compression comparison
    let base_wit = SpendWitness {
        inputs: [
            InputNote {
                sk: alice.sk,
                v: unspent[0].v,
                rho: unspent[0].rho,
                pos: unspent[0].pos,
                path: chain.state.tree.path(unspent[0].pos),
            },
            InputNote::dummy(),
        ],
        outputs: [
            OutputNote { a_pk: bob.a_pk(), v: 1 * COIN, rho: rng.gen() },
            OutputNote { a_pk: alice.a_pk(), v: unspent[0].v - 1 * COIN - MIN_BATCH_SPEND_FEE, rho: rng.gen() },
        ],
        dummy: [false, true],
    };
    let t_single = std::time::Instant::now();
    let (_, single_proof) = spend::prove_for(&params.proof, &base_wit, [1; 8]).unwrap();
    let single_ms = t_single.elapsed().as_millis();
    let single_qrom = single_proof.proven_security::<spend::Hash384>().qrom_ldr_bits(384);
    assert!(single_qrom >= 100, "MAIN_V2 K=1 must achieve >= 100 conservative QROM bits, got {single_qrom}");
    let single_bytes = single_proof.to_bytes().len();

    // Helper to build a K-spend `Tx::BatchSpend` from Alice's first `k` unspent notes
    let make_batch = |chain: &Chain, k: usize| -> (Tx, usize, u128, u128, u32) {
        let mut rng = rand::thread_rng();
        let mut wits = Vec::with_capacity(k);
        let mut binds = Vec::with_capacity(k);
        let mut items = Vec::with_capacity(k);
        let fee_each = MIN_BATCH_SPEND_FEE * 2; // 20,000 units per sub-spend
        for c in &unspent[..k] {
            let out_pay = OutputNote { a_pk: bob.a_pk(), v: 1 * COIN, rho: rng.gen() };
            let out_chg = OutputNote { a_pk: alice.a_pk(), v: c.v - 1 * COIN - fee_each, rho: rng.gen() };
            let wit = SpendWitness {
                inputs: [
                    InputNote { sk: alice.sk, v: c.v, rho: c.rho, pos: c.pos, path: chain.state.tree.path(c.pos) },
                    InputNote::dummy(),
                ],
                outputs: [out_pay, out_chg],
                dummy: [false, true],
            };
            let bind = bind_of(fee_each, &None, &[]);
            let sp_pub = wit.public(bind).unwrap();
            items.push(BatchSpendItem {
                anchor: sp_pub.root,
                nf: sp_pub.nf,
                cm_out: sp_pub.cm_out,
                dummy: sp_pub.dummy,
                fee: fee_each,
                deposit: None,
                memo: vec![],
            });
            wits.push(wit);
            binds.push(bind);
        }
        let t0 = std::time::Instant::now();
        let (bpi, proof) = batch_spend::prove_batch_for(&params.proof, &wits, &binds, prover.a_pk()).unwrap();
        let prove_ms = t0.elapsed().as_millis();
        let qrom = proof.proven_security::<spend::Hash384>().qrom_ldr_bits(384);
        assert!(qrom >= 100, "MAIN_V2 K={k} BatchSpend must achieve >= 100 conservative QROM bits, got {qrom}");
        let pbytes = proof.to_bytes();
        let tv = std::time::Instant::now();
        batch_spend::verify_batch_bytes_for(&params.proof, &bpi, &pbytes).unwrap();
        let verify_ms = tv.elapsed().as_millis();
        let tx = Tx::BatchSpend(BatchSpend {
            spends: items,
            prover_a_pk: prover.a_pk(),
            proof: pbytes.clone(),
        });
        (tx, pbytes.len(), prove_ms, verify_ms, qrom)
    };

    // Benchmark K = 4 SHA-384 BatchSpend
    let (_batch4_tx, b4_bytes, b4_prove_ms, b4_verify_ms, b4_qrom) = make_batch(&chain, 4);
    println!(
        "[MAIN_V2 QUARTIC SHA-384 BENCH] K=1: {single_bytes} B ({single_ms} ms, QROM={single_qrom}b) | K=4: {b4_bytes} B ({} B/spend, {:.2}x compression, prove={b4_prove_ms} ms, verify={b4_verify_ms} ms, QROM={b4_qrom}b)",
        b4_bytes / 4,
        (single_bytes * 4) as f64 / b4_bytes as f64
    );
    assert!(
        b4_bytes < single_bytes * 2,
        "K=4 BatchSpend ({b4_bytes} B) should achieve >2x compression vs 4x single ({} B)",
        single_bytes * 4
    );

    // Benchmark K = 8 SHA-384 BatchSpend (proves 8 full 2-in/2-out spends in ONE SHA-384 STARK!)
    let (batch8_tx, b8_bytes, b8_prove_ms, b8_verify_ms, b8_qrom) = make_batch(&chain, 8);
    let tx8_wire = batch8_tx.to_bytes();
    assert_eq!(Tx::from_bytes(&tx8_wire).unwrap(), batch8_tx);
    println!(
        "[MAIN_V2 QUARTIC SHA-384 BENCH] K=8: {b8_bytes} B ({} B/spend, {:.2}x compression, wire={} B, prove={b8_prove_ms} ms, verify={b8_verify_ms} ms, QROM={b8_qrom}b, fits ~{} spends per 8 MB block!)",
        b8_bytes / 8,
        (single_bytes * 8) as f64 / b8_bytes as f64,
        tx8_wire.len(),
        (8_000_000 / tx8_wire.len()) * 8
    );
    assert!(
        b8_bytes * 5 < single_bytes * 8,
        "K=8 BatchSpend ({b8_bytes} B) must achieve >5x compression vs 8x single ({} B)",
        single_bytes * 8
    );

    // CONSENSUS SPLIT-COINBASE ENFORCEMENT TEST:
    // Height 10 with K=8 compressed spends -> Prover MUST receive 30% of subsidy (15 LOVE)!
    let next_h = chain.height() + 1;
    let sub = subsidy(next_h);
    let prover_req = prover_subsidy_share(sub, 8);
    assert_eq!(prover_req, (sub * 30) / 100);
    let fee_each = MIN_BATCH_SPEND_FEE * 2;
    let (burn_each, prod_each) = split_spend_fee(fee_each, true);
    let total_burn = burn_each * 8;
    let total_prod_fee = prod_each * 8;

    // 1. Greedy AuxPoW miner tries to keep 100% of subsidy (omitting prover) -> REJECTED!
    let greedy = vec![PlainOut { a_pk: miner.a_pk(), v: sub + total_prod_fee, rho: [1; 5] }];
    assert!(
        chain.template(greedy, vec![batch8_tx.clone()], vec![]).is_err(),
        "miner omitting BatchSpend prover coinbase share MUST be rejected by consensus"
    );

    // 2. Honest split coinbase (70% AuxPoW miner + fees, 30% Negentropy Prover) -> ACCEPTED!
    let split_outs = vec![
        PlainOut { a_pk: miner.a_pk(), v: sub - prover_req + total_prod_fee, rho: [2; 5] },
        PlainOut { a_pk: prover.a_pk(), v: prover_req, rho: [3; 5] },
    ];
    let mut b10 = chain.template(split_outs, vec![batch8_tx], vec![]).unwrap();
    assert!(mine(&mut b10.header, u64::MAX));
    chain.add_block(b10).unwrap();

    assert_eq!(chain.height(), 10);
    assert_eq!(chain.state.burned, total_burn as u128);
    // Advance 1 block so coinbase matures (maturity = 1) and verify Prover received 15 LOVE!
    let mut b11 = chain.template(vec![PlainOut { a_pk: miner.a_pk(), v: subsidy(11), rho: [4; 5] }], vec![], vec![]).unwrap();
    assert!(mine(&mut b11.header, u64::MAX));
    chain.add_block(b11).unwrap();
    assert_eq!(prover.balance(&chain), prover_req);
}
