//! Adversarial Red-Team & Audit Boundary Suite for Newsatoshi v2 Consensus Primitives.
//!
//! Explicitly exercises security invariants and exploit attempts across:
//! 1. RFC-0023 Sovereign L2 Rollup Vaults (tampered STARKs, bit-flipped proofs, 64-bit TVL
//!    overflow, replay withdrawal nullifiers, forged Merkle withdrawal paths)
//! 2. General-Purpose L2 zkVM Execution STARKs & Multi-Shard Aggregation (broken state chain,
//!    forged final register/state slots, failed ASSERT_EQ, overflow/underflow)
//! 3. RFC-0024 Universal Trust Bonds (self-attestation wash-trading, identical-payload fake
//!    equivocation slash, below-quorum/duplicate arbiter slash, premature unbond, over-slash)
//! 4. RFC-0027 Native Mission Launchpads (founder drain / >100% split, >10% curve fee, unbonded
//!    Sybil worker claim, double-claim task replay, over-redemption > total_shares)
//! 5. RFC-0026 BIP-9 Signaling & AuxPoW bit non-collision + ASERT Day-1 anti-instamine boundaries.

use newsatoshi::auxpow::{auxpow_version, chain_id, is_auxpow, CHAIN_ID};
use newsatoshi::bond::{self, BondPost, TrustBond};
use newsatoshi::hash::{sha256, Word8};
use newsatoshi::job::JobKey;
use newsatoshi::merkmap::MerkleMap;
use newsatoshi::mission::{self, MissionPool, MissionPost};
use newsatoshi::params::COIN;
use newsatoshi::pow::{asert_bits_staged, TARGET_SPACING};
use newsatoshi::rollup::{self, RollupBatchInputs, RollupPost, RollupVault};
use newsatoshi::signal::{self, encode_signal_version, signals_bit, MAX_SIGNAL_BIT, MIN_SIGNAL_BIT};
use newsatoshi::zkvm::{
    aggregate_shards_to_l1_batch, compile_l2_program, prove_zkvm_execution, state_slots_root,
    verify_zkvm_execution,
};
use std::collections::BTreeMap;

#[test]
fn redteam_rfc0024_bond_attacks_rejected() {
    let owner = JobKey::derive(&[1u8; 32]);
    let peer = JobKey::derive(&[2u8; 32]);
    let arb0 = JobKey::derive(&[3u8; 32]);
    let arb1 = JobKey::derive(&[4u8; 32]);
    let owner_vk: [u8; 32] = owner.vk().try_into().unwrap();
    let peer_vk: [u8; 32] = peer.vk().try_into().unwrap();
    let arb0_vk: [u8; 32] = arb0.vk().try_into().unwrap();
    let arb1_vk: [u8; 32] = arb1.vk().try_into().unwrap();
    let victim: Word8 = [99u32; 8];

    // Invalid slash_burn_bps > 10_000 rejected
    let bad_post = BondPost {
        owner_vk,
        owner_addr: [1u32; 8],
        arbiter_vks: vec![arb0_vk, arb1_vk],
        quorum_m: 2,
        unbond_delay: 10,
        slash_burn_bps: 10_001,
        stake: 5 * COIN,
        service_tag: sha256(b"redteam"),
    };
    assert!(bond::check_post(&bad_post).is_err());

    let post = BondPost {
        slash_burn_bps: 2_000,
        ..bad_post
    };
    bond::check_post(&post).unwrap();
    let bid = bond::bond_id(&post, &[7u32; 8]);
    let mut b = TrustBond {
        id: bid,
        post,
        created_at: 10,
        settled_count: 0,
        settled_volume: 0,
        slash_count: 0,
        slashed_total: 0,
        unbond_requested_at: None,
        unbond_amount: 0,
        action_nonce: 0,
    };

    // 1. Self-attestation wash trading (counterparty_vk == owner_vk) MUST fail!
    let rcpt = sha256(b"fake-self-trade");
    let amsg = bond::attest_message(&bid, 0, &rcpt, 1 * COIN, 10_000);
    assert!(bond::attest(
        &mut b,
        &rcpt,
        1 * COIN,
        10_000,
        &owner.sign(&amsg),
        &owner_vk,
        &owner.sign(&amsg),
    )
    .is_err());

    // 2. Identical-payload fake equivocation slash MUST fail!
    let same = sha256(b"identical-quote");
    let cmsg = bond::commit_message(&bid, 1, &same);
    let csig = owner.sign(&cmsg);
    assert!(bond::slash_equivocation(
        &mut b, 1, &same, &csig, &same, &csig, victim, 1 * COIN, 5_000
    )
    .is_err());

    // 3. Over-slash exceeding stake MUST fail!
    let p_a = sha256(b"quote-a");
    let p_b = sha256(b"quote-b");
    let sig_a = owner.sign(&bond::commit_message(&bid, 2, &p_a));
    let sig_b = owner.sign(&bond::commit_message(&bid, 2, &p_b));
    assert!(bond::slash_equivocation(
        &mut b,
        2,
        &p_a,
        &sig_a,
        &p_b,
        &sig_b,
        victim,
        6 * COIN,
        5_000
    )
    .is_err());

    // 4. Duplicate arbiter index in quorum slash (trying to pass 1-of-2 as 2-of-2) MUST fail!
    let ev = sha256(b"dispute-evidence");
    let qmsg = bond::quorum_slash_message(&bid, 0, &ev, &victim, 1 * COIN, 5_000);
    let qsig0 = arb0.sign(&qmsg);
    assert!(bond::slash_quorum(
        &mut b,
        &ev,
        victim,
        1 * COIN,
        5_000,
        &[(0, qsig0.clone()), (0, qsig0)],
    )
    .is_err());

    // 5. Premature unbond completion before cooldown MUST fail!
    let umsg = bond::unbond_request_message(&bid, 0, 2 * COIN);
    bond::request_unbond(&mut b, 2 * COIN, &owner.sign(&umsg), 20).unwrap();
    assert!(bond::complete_unbond(&mut b, 5_000, 29).is_err()); // delay=10 => needs >=30
    let eff = bond::complete_unbond(&mut b, 5_000, 30).unwrap();
    assert_eq!(eff.payouts[0].v + eff.miner_fee, 2 * COIN);
    assert_eq!(b.post.stake, 3 * COIN);

    // Legitimate peer attestation succeeds after unbond
    let amsg2 = bond::attest_message(&bid, b.action_nonce, &rcpt, 1 * COIN, 10_000);
    bond::attest(
        &mut b,
        &rcpt,
        1 * COIN,
        10_000,
        &owner.sign(&amsg2),
        &peer_vk,
        &peer.sign(&amsg2),
    )
    .unwrap();
    assert_eq!(b.settled_count, 1);
}

#[test]
fn redteam_rfc0023_rollup_and_zkvm_attacks_rejected() {
    let prog = compile_l2_program(
        "LOAD_STATE r0, s0\nLOAD_CONST r1, 50000\nSUB r0, r0, r1\nSTORE_STATE s0, r0\nEMIT_WITHDRAW r1\nHALT",
    )
    .unwrap();

    // 1. Underflow in zkVM SUB MUST fail proving!
    assert!(prove_zkvm_execution(&prog, [10_000, 0, 0, 0]).is_err());

    // 2. ASSERT_EQ mismatch MUST fail proving!
    let bad_assert = compile_l2_program("LOAD_CONST r0, 1\nLOAD_CONST r1, 2\nASSERT_EQ r0, r1\nHALT").unwrap();
    assert!(prove_zkvm_execution(&bad_assert, [0, 0, 0, 0]).is_err());

    // 3. Bit-flipped zkVM STARK proof MUST fail verification!
    let shard = prove_zkvm_execution(&prog, [1_000_000, 0, 0, 0]).unwrap();
    let mut flipped = shard.proof_bytes.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x01;
    assert!(verify_zkvm_execution(&shard.pub_inputs, &flipped).is_err());

    // 4. Broken state chain across multi-shard aggregation MUST fail!
    let disconnected = prove_zkvm_execution(&prog, [999_999, 0, 0, 0]).unwrap();
    assert!(aggregate_shards_to_l1_batch(
        sha256(b"vk"),
        &[shard.clone(), disconnected],
        [0u8; 32],
        [0u8; 32],
        1,
        1_000_000,
        1_000,
    )
    .is_err());

    // 5. 64-bit TVL overflow (exceeding 63-bit STARK range bound) MUST fail invariant check!
    let overflow_inputs = RollupBatchInputs {
        vk_hash: sha256(b"vk"),
        prev_state_root: shard.pub_inputs.prev_state_root,
        new_state_root: shard.pub_inputs.new_state_root,
        deposit_acc: [0u8; 32],
        withdraw_root: [0u8; 32],
        batch_seq: 1,
        batch_tx_count: 1,
        prev_tvl: (1u64 << 63) + 10,
        new_tvl: (1u64 << 63),
        batch_withdrawals: 5,
        batch_fee: 5,
    };
    assert!(overflow_inputs.check_invariants().is_err());

    // 6. Forged Merkle withdrawal proof & double-claim replay MUST fail on RollupVault!
    let post = RollupPost {
        vk_hash: sha256(b"vk"),
        genesis_root: state_slots_root(&[1_000_000, 0, 0, 0]),
        sequencer_vk: None,
        initial_tvl: 1_000_000,
        name_tag: sha256(b"redteam-l2"),
    };
    let rid = rollup::rollup_id(&post, &[3u32; 8]);
    let mut vault = RollupVault {
        id: rid,
        post,
        created_at: 1,
        state_root: shard.pub_inputs.prev_state_root,
        deposit_acc: [0u8; 32],
        deposit_count: 0,
        batch_seq: 0,
        total_l2_txs: 0,
        tvl: 1_000_000,
        pending_withdrawals: 0,
        withdraw_roots: vec![],
        claimed_withdrawals: vec![],
    };
    let wid = sha256(b"wdr-real");
    let alice = [4u32; 8];
    let mut wmap = MerkleMap::new();
    wmap.insert(wid, rollup::withdrawal_leaf_hash(&rid, 1, &wid, &alice, 50_000));
    let wroot = wmap.root();

    let agg = aggregate_shards_to_l1_batch(
        vault.post.vk_hash,
        &[shard],
        vault.deposit_acc,
        wroot,
        1,
        vault.tvl,
        1_000,
    )
    .unwrap();

    // Flip 1 byte in L1 RollupBatch STARK -> rejected!
    let mut bad_l1_proof = agg.l1_stark_proof.clone();
    bad_l1_proof[100] ^= 0xff;
    assert!(rollup::apply_batch(
        &mut vault,
        agg.l1_inputs.new_state_root,
        wroot,
        agg.l1_inputs.batch_tx_count,
        agg.l1_inputs.batch_withdrawals,
        agg.l1_inputs.batch_fee,
        &[],
        &bad_l1_proof,
        true,
    )
    .is_err());

    // Honest batch settles
    rollup::apply_batch(
        &mut vault,
        agg.l1_inputs.new_state_root,
        wroot,
        agg.l1_inputs.batch_tx_count,
        agg.l1_inputs.batch_withdrawals,
        agg.l1_inputs.batch_fee,
        &[],
        &agg.l1_stark_proof,
        true,
    )
    .unwrap();

    // Wrong recipient address with valid Merkle proof -> rejected!
    let mp = wmap.prove(&wid).unwrap();
    assert!(rollup::apply_withdraw(&mut vault, 1, &wid, [9u32; 8], 50_000, 100, &mp).is_err());
    // Honest withdrawal succeeds once, replay fails!
    rollup::apply_withdraw(&mut vault, 1, &wid, alice, 50_000, 100, &mp).unwrap();
    assert!(rollup::apply_withdraw(&mut vault, 1, &wid, alice, 50_000, 100, &mp).is_err());
}

#[test]
fn redteam_rfc0027_mission_launchpad_attacks_rejected() {
    let orch = JobKey::derive(&[61u8; 32]);
    let v0 = JobKey::derive(&[62u8; 32]);
    let trader = JobKey::derive(&[63u8; 32]);
    let trader_vk: [u8; 32] = trader.vk().try_into().unwrap();
    let pg_addr = [70u32; 8];
    let worker_addr = [71u32; 8];

    // 1. Excessive curve_fee_bps (>10%) or invalid public_goods_bps (>100%) MUST fail!
    let mut bad = MissionPost {
        orchestrator_vk: orch.vk().try_into().unwrap(),
        verifier_vks: vec![v0.vk().try_into().unwrap()],
        verifier_quorum_m: 1,
        public_goods_addr: pg_addr,
        public_goods_bps: 10_001,
        curve_fee_bps: 500,
        initial_funding: 1 * COIN,
        min_worker_bond: 1 * COIN,
        mission_hash: sha256(b"redteam-mission"),
    };
    assert!(mission::check_post(&bad).is_err());
    bad.public_goods_bps = 2_000;
    bad.curve_fee_bps = 1_001;
    assert!(mission::check_post(&bad).is_err());

    // Valid launchpad
    let post = MissionPost {
        curve_fee_bps: 500,
        ..bad
    };
    mission::check_post(&post).unwrap();
    let mid = mission::mission_id(&post, &[8u32; 8]);
    let mut pool = MissionPool {
        id: mid,
        post,
        created_at: 1,
        bounty_pool: 1 * COIN,
        curve_reserve: 0,
        total_shares: 0,
        shares_by_holder: BTreeMap::new(),
        tasks: BTreeMap::new(),
        completed_tasks: 0,
        total_bounties_paid: 0,
        action_nonce: 0,
    };

    // 2. Trader buys 10 LOVE -> tries to redeem MORE shares than minted -> MUST fail!
    mission::apply_fund(&mut pool, trader_vk, 10 * COIN, false).unwrap();
    let shares = pool.shares_by_holder[&trader_vk];
    let rmsg = mission::redeem_message(&mid, pool.action_nonce, shares + 1, &worker_addr, 1_000);
    assert!(mission::apply_curve_redeem(
        &mut pool,
        trader_vk,
        shares + 1,
        worker_addr,
        1_000,
        &trader.sign(&rmsg),
    )
    .is_err());

    // 3. Task claim with insufficient worker bond (anti-Sybil) MUST fail!
    let spec = sha256(b"lemma-x");
    let tmsg = mission::post_task_message(&mid, 1, &spec, 50_000_000);
    mission::apply_post_task(&mut pool, 1, spec, 50_000_000, &orch.sign(&tmsg)).unwrap();
    let proof = sha256(b"proof-x");
    let cmsg = mission::claim_task_message(&mid, 1, &spec, &proof, &worker_addr, 1_000);
    let vsigs = vec![(0, v0.sign(&cmsg))];

    let make_bond = |stake: u64, slashes: u32| TrustBond {
        id: sha256(b"worker-bond"),
        post: BondPost {
            owner_vk: trader_vk,
            owner_addr: worker_addr,
            arbiter_vks: vec![],
            quorum_m: 0,
            unbond_delay: 5,
            slash_burn_bps: 2_000,
            stake,
            service_tag: sha256(b"worker"),
        },
        created_at: 1,
        settled_count: 0,
        settled_volume: 0,
        slash_count: slashes,
        slashed_total: 0,
        unbond_requested_at: None,
        unbond_amount: 0,
        action_nonce: 0,
    };

    let low_bond = make_bond(50_000_000, 0);
    let slashed_bond = make_bond(2 * COIN, 1);
    let good_bond = make_bond(1 * COIN, 0);

    // Unbonded, under-bonded, and slashed workers MUST all be rejected!
    assert!(mission::apply_claim_task(&mut pool, 1, proof, worker_addr, None, 1_000, &vsigs, 10).is_err());
    assert!(mission::apply_claim_task(&mut pool, 1, proof, worker_addr, Some(&low_bond), 1_000, &vsigs, 10).is_err());
    assert!(mission::apply_claim_task(&mut pool, 1, proof, worker_addr, Some(&slashed_bond), 1_000, &vsigs, 10).is_err());

    // Honest clean bonded claim succeeds ONCE, double-claim replay MUST fail!
    mission::apply_claim_task(&mut pool, 1, proof, worker_addr, Some(&good_bond), 1_000, &vsigs, 10).unwrap();
    assert!(mission::apply_claim_task(&mut pool, 1, proof, worker_addr, Some(&good_bond), 1_000, &vsigs, 11).is_err());
}

#[test]
fn redteam_bip9_auxpow_non_collision_and_asert_bounds() {
    // Every single subset of BIP-9 signaling bits 1..=7 MUST preserve AuxPoW flag & CHAIN_ID (20051)!
    for mask in 0u32..(1u32 << 7) {
        let mut bits = Vec::new();
        for b in MIN_SIGNAL_BIT..=MAX_SIGNAL_BIT {
            if (mask & (1 << (b - 1))) != 0 {
                bits.push(b);
            }
        }
        let v = auxpow_version(encode_signal_version(1, &bits));
        assert!(is_auxpow(v), "AuxPoW bit clobbered for mask {mask:#x}");
        assert_eq!(chain_id(v), CHAIN_ID, "CHAIN_ID clobbered for mask {mask:#x}");
        for b in MIN_SIGNAL_BIT..=MAX_SIGNAL_BIT {
            let expected = bits.contains(&b);
            assert_eq!(signals_bit(v, b), expected);
        }
    }

    // Out-of-range bit 0 or bit 8+ MUST be ignored (never collides with base version or AuxPoW bit 8)
    let ignored = encode_signal_version(1, &[0, 8, 16, 31]);
    assert_eq!(ignored, 1);
    assert!(!signal::signals_bit(0xffff_ffff, 0));
    assert!(!signal::signals_bit(0xffff_ffff, 8));

    // Extreme future/past timestamps in ASERT staged launch MUST stay bounded (never panic or exceed pow_limit)
    let lim = 0x1d00ffffu32;
    let b_far_future = asert_bits_staged(lim, 0, 2016, 3600, None, 10, 10_000_000_000, 172_800, lim, TARGET_SPACING);
    assert_eq!(b_far_future, lim);
    let b_fast = asert_bits_staged(lim, 1_000_000, 2016, 3600, None, 100, 1_000_010, 172_800, lim, TARGET_SPACING);
    assert_ne!(b_fast, lim);
}

#[test]
fn redteam_zkvm_logup_rom_prevents_fake_program_drain_and_overflow() {
    // Honest L2 vault program: allows withdrawing at most 10_000_000 when s0 >= 10_000_000 via LT + JZ
    let honest_prog = compile_l2_program(
        r#"
        LOAD_STATE r0, s0
        LOAD_CONST r1, 10000000
        LT r2, r0, r1
        JNZ r2, fail
        SUB r0, r0, r1
        STORE_STATE s0, r0
        EMIT_WITHDRAW r1
        HALT
    fail:
        LOAD_CONST r3, 999
        ASSERT_EQ r2, r3
        HALT
        "#,
    )
    .unwrap();

    // Attacker writes a fake drain program trying to steal 500_000_000!
    let evil_prog = compile_l2_program(
        "LOAD_CONST r0, 500000000\nEMIT_WITHDRAW r0\nHALT",
    )
    .unwrap();

    let honest_shard = prove_zkvm_execution(&honest_prog, [50_000_000, 0, 0, 0]).unwrap();
    assert!(honest_shard.proven_bits >= 128);
    assert_eq!(honest_shard.pub_inputs.total_withdrawals, 10_000_000);

    // 1. Insufficient balance triggers the conditional branch to `fail:` -> ASSERT_EQ rejects!
    assert!(prove_zkvm_execution(&honest_prog, [5_000_000, 0, 0, 0]).is_err());

    // 2. Evil drain proof cannot masquerade under honest_prog's vk_hash (LogUp ROM rejects!)
    let evil_shard = prove_zkvm_execution(&evil_prog, [50_000_000, 0, 0, 0]).unwrap();
    let mut forged_pub = evil_shard.pub_inputs.clone();
    forged_pub.program_hash = honest_prog.program_hash;
    forged_pub.program_bytecode = honest_prog.bytecode.clone();
    assert!(verify_zkvm_execution(&forged_pub, &evil_shard.proof_bytes).is_err());

    // 3. Even if attacker mutates just program_hash while keeping evil_bytecode, hash check fails!
    let mut mismatch_pub = evil_shard.pub_inputs.clone();
    mismatch_pub.program_hash = honest_prog.program_hash;
    assert!(verify_zkvm_execution(&mismatch_pub, &evil_shard.proof_bytes).is_err());
}

#[test]
fn redteam_p2p_eclipse_defense_pq_transport_and_compact_block() {
    use newsatoshi::chain::{mine, Chain};
    use newsatoshi::node::{admit_inbound, release_inbound, CompactBlock, MAX_PER_NETGROUP};
    use newsatoshi::params::{subsidy, Net, Params, DEFAULT_FEE};
    use newsatoshi::peers::{AddrBook, MAX_PER_NETGROUP_BOOK};
    use newsatoshi::pq_transport::PqSession;
    use newsatoshi::tx::PlainOut;
    use newsatoshi::wallet::Wallet;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};

    // 1. Eclipse attacker controlling a /24 subnet (203.0.113.1..254)
    let mut book = AddrBook::default();
    let mut accepted = 0usize;
    for host in 1u8..=200 {
        if book.heard(&format!("203.0.113.{host}:8444")) {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, MAX_PER_NETGROUP_BOOK,
        "/16 netgroup cap must stop single-subnet address-book flooding"
    );
    // Add 3 honest peers from distinct /16 netgroups
    for p in ["198.51.100.1:8444", "192.0.2.1:8444", "1.1.1.1:8444"] {
        assert!(book.heard(p));
        book.good(p);
    }
    let cands = book.candidates(&HashSet::new());
    let attacker_selected = cands.iter().filter(|a| a.starts_with("203.0.113.")).count();
    assert_eq!(
        attacker_selected, 1,
        "eclipse attacker with 200 IPs in one /16 MUST get at most 1 outbound slot"
    );

    // Inbound netgroup cap (public IPs in one /16 capped at MAX_PER_NETGROUP = 8)
    let mut admitted_ips = Vec::new();
    for host in 1u8..=20 {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, host));
        if admit_inbound(ip) {
            admitted_ips.push(ip);
        }
    }
    assert_eq!(admitted_ips.len(), MAX_PER_NETGROUP);
    for ip in admitted_ips {
        release_inbound(ip);
    }

    // 2. Post-quantum NIST FIPS 203 ML-KEM-768 P2P transport blocks MITM tampering
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        PqSession::handshake_responder(&mut s, *b"nsM2").unwrap()
    });
    let mut c = TcpStream::connect(addr).unwrap();
    let mut init = PqSession::handshake_initiator(&mut c, *b"nsM2").unwrap();
    let mut resp = h.join().unwrap();
    let mut frame = init.seal_frame(b"compact-block-payload").unwrap();
    assert_eq!(resp.open_raw_frame(&frame).unwrap(), b"compact-block-payload");
    // Replay or bit-flip rejected
    assert!(resp.open_raw_frame(&frame).is_err());
    frame[4] ^= 0x80;
    assert!(resp.open_raw_frame(&frame).is_err());

    // 3. Compact Block relay reconstructs full STARK block from mempool with >95% bandwidth savings
    let mut chain = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let miner = Wallet::generate();
    let out1 = PlainOut { a_pk: alice.a_pk(), v: subsidy(1), rho: [1; 5] };
    let mut b1 = chain.template(vec![out1], vec![], vec![]).unwrap();
    assert!(mine(&mut b1.header, u64::MAX));
    chain.add_block(b1).unwrap();
    let out1b = PlainOut { a_pk: alice.a_pk(), v: subsidy(2), rho: [11; 5] };
    let mut b1b = chain.template(vec![out1b], vec![], vec![]).unwrap();
    assert!(mine(&mut b1b.header, u64::MAX));
    chain.add_block(b1b).unwrap();

    let (spend_tx, _) = alice.spend(&chain, Some((miner.a_pk(), 1 * COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let out2 = PlainOut { a_pk: miner.a_pk(), v: subsidy(3) + DEFAULT_FEE, rho: [2; 5] };
    let mut b2 = chain.template(vec![out2], vec![spend_tx.clone()], vec![]).unwrap();
    assert!(mine(&mut b2.header, u64::MAX));

    let full_bytes = b2.encode().len();
    let cb = CompactBlock::from_block(&b2, 42).unwrap();
    let mut w = newsatoshi::codec::Writer::new();
    cb.encode(&mut w);
    let compact_bytes = w.0.len();
    assert!(
        compact_bytes * 20 < full_bytes,
        "compact block ({compact_bytes} B) should be >95% smaller than full STARK block ({full_bytes} B)"
    );
    // Empty mempool reports exact missing index [1]; warm mempool reconstructs exact full block!
    assert_eq!(cb.reconstruct(&[]).unwrap_err(), vec![1]);
    let rebuilt = cb.reconstruct(&[spend_tx]).unwrap();
    assert_eq!(rebuilt.hash(), b2.hash());
    assert_eq!(rebuilt.txs.len(), b2.txs.len());
}

#[test]
fn redteam_flyclient_mmr_and_trustless_light_client_proofs() {
    use newsatoshi::chain::{mine, Chain};
    use newsatoshi::light::{FlyClientProof, HeaderTip};
    use newsatoshi::params::{subsidy, Net, Params, DEFAULT_FEE};
    use newsatoshi::tx::PlainOut;
    use newsatoshi::wallet::Wallet;

    let params = Params::get(Net::Reg).unwrap();
    let mut chain = Chain::open(params.clone(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    let mut headers = vec![chain.block_at(0).unwrap().clone()];

    for i in 1..=20u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b.clone()).unwrap();
        headers.push(b);
    }
    let (tx, _) = alice.spend(&chain, Some((bob.a_pk(), 2 * COIN)), DEFAULT_FEE, None, vec![]).unwrap();
    let spent_nf = match &tx {
        newsatoshi::tx::Tx::Spend(s) => s.nf[0],
        _ => unreachable!(),
    };
    let out_tip = PlainOut { a_pk: bob.a_pk(), v: subsidy(22) + DEFAULT_FEE, rho: [99; 5] };
    let mut b_tip = chain.template(vec![out_tip], vec![tx], vec![]).unwrap();
    assert!(mine(&mut b_tip.header, u64::MAX));
    chain.add_block(b_tip.clone()).unwrap();
    headers.push(b_tip.clone());

    // 1. O(log N) FlyClient MMR chain proof verification & forgery rejection
    let fc = FlyClientProof::prove(&headers, 4, 8).unwrap();
    let (tip_h, work) = fc.verify(headers[0].hash(), 8).unwrap();
    assert_eq!(tip_h, chain.tip().hash);
    assert_eq!(work, chain.tip().work);
    let mut forged = fc.clone();
    forged.peaks[0].work += primitive_types::U256::from(1u64);
    assert!(forged.verify(headers[0].hash(), 8).is_err());

    // 2. Trustless NoteTree + NfTree verification against committed HeaderTip
    let mut light = HeaderTip::genesis(&params);
    let hdr_only: Vec<_> = headers[1..]
        .iter()
        .map(|b| newsatoshi::tx::Block { header: b.header, auxpow: b.auxpow.clone(), digest: [0u8; 32], txs: vec![] })
        .collect();
    light.extend(&params, &hdr_only, newsatoshi::chain::now()).unwrap();
    let parts = chain.state.digest_parts();
    let cm0 = chain.state.tree.leaf(0).unwrap();
    let path0 = chain.state.tree.path(0);
    let nf_spent_proof = chain.state.nf_tree.prove(&spent_nf);
    let is_spent = light
        .verify_note_and_nullifier(
            &b_tip.header,
            &b_tip.tx_root(),
            &parts,
            &cm0,
            0,
            &path0,
            Some((&spent_nf, &nf_spent_proof)),
        )
        .unwrap();
    assert_eq!(is_spent, Some(true), "light client must prove nullifier is spent");

    let unspent_nf: Word8 = [77u32; 8];
    let nf_unspent_proof = chain.state.nf_tree.prove(&unspent_nf);
    let is_unspent = light
        .verify_note_and_nullifier(
            &b_tip.header,
            &b_tip.tx_root(),
            &parts,
            &cm0,
            0,
            &path0,
            Some((&unspent_nf, &nf_unspent_proof)),
        )
        .unwrap();
    assert_eq!(is_unspent, Some(false), "light client must prove fresh nullifier is unspent");
}

#[test]
fn redteam_mainnet_v2_sha384_end_to_end_chain_spend() {
    use newsatoshi::chain::{mine, Chain};
    use newsatoshi::params::{subsidy, Params, MAIN_DEFAULT_FEE};
    use newsatoshi::tx::PlainOut;
    use newsatoshi::wallet::Wallet;

    // Boot a live Mainnet v2 chain (384-bit SHA-384 FRI, Day-1 ASERT ramp, all RFCs active at 0)
    // using regtest-level mining target & maturity=1 so full-chain SHA-384 proving runs in ~2s!
    let mut p = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    p.pow_limit = 0x207fffff;
    p.coinbase_maturity = 1;
    assert!(p.proof.sha384, "MAIN_V2 profile must enable 384-bit SHA-384 FRI");

    let mut chain = Chain::open(p, None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();

    // Mine 2 blocks so Alice has a matured coinbase note
    for i in 1..=2u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 10; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }

    // Wallet::spend automatically dispatches SpendProver384 via prove_for(&params.proof, ...)
    let (tx, note_str) = alice
        .spend(&chain, Some((bob.a_pk(), 5 * COIN)), MAIN_DEFAULT_FEE, None, vec![])
        .unwrap();
    assert!(note_str.is_some());
    let out3 = PlainOut { a_pk: bob.a_pk(), v: subsidy(3) + MAIN_DEFAULT_FEE, rho: [33; 5] };
    let mut b3 = chain.template(vec![out3], vec![tx], vec![]).unwrap();
    assert!(mine(&mut b3.header, u64::MAX));
    // Chain::add_block verifies the 384-bit SHA-384 FRI spend proof natively in consensus!
    chain.add_block(b3).unwrap();
    assert_eq!(chain.height(), 3);
}
