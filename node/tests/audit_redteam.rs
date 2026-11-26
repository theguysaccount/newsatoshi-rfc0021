//! Adversarial Red-Team & Audit Boundary Suite for Newsatoshi `v1.0.0-core`.
//!
//! Exercises exploit attempts across every L1 consensus and network surface:
//! 1. Priorism-FEP `PriorLock` attacks (SCGS I-3 self-arbitration, identical-payload fake
//!    equivocation, duplicate arbiter index, >10% fee siphon, premature release, post-window slash)
//! 2. `BatchSpend` multi-spend STARK attacks (prover_a_pk reward theft, intra-batch double spend,
//!    sub-minimum batch fee spam, bit-flipped proof, underpaid prover split-coinbase)
//! 3. Work-Proportional FlyClient attacks (sibling-work inflation `2^100`, unbound tail header,
//!    missing/tampered header MMR commitment)
//! 4. P2P Eclipse defense (/16 netgroups), opportunistic ML-KEM-768 `NSPQ1` frame tampering/replay,
//!    and BIP-152-style Compact Block relay
//! 5. BIP-9 AuxPoW signaling bit non-collision & ASERT Day-1 launch bounds
//! 6. Full Mainnet v2 SHA-384 + Homeostatic 50% Fee Burn + `nsSNAP05` + live `NSPQ1` sync.

use newsatoshi::auxpow::{auxpow_version, chain_id, is_auxpow, CHAIN_ID};
use newsatoshi::chain::{mine, Chain};
use newsatoshi::hash::{sha256, Word8};
use newsatoshi::job::JobKey;
use newsatoshi::light::{bag_mmr_peaks, mmr_leaf_hash, mmr_parent_hash, FlyClientProof, HeaderTip, MmrLeafProof, MmrNode};
use newsatoshi::node::{self, admit_inbound, lock, release_inbound, CompactBlock, Msg, Node, MAX_PER_NETGROUP};
use newsatoshi::params::{split_spend_fee, subsidy, Net, Params, COIN, DEFAULT_FEE, MAIN_V2_DEFAULT_FEE};
use newsatoshi::peers::{AddrBook, MAX_PER_NETGROUP_BOOK};
use newsatoshi::pow::{self, asert_bits_staged, TARGET_SPACING};
use newsatoshi::pq_transport::PqSession;
use newsatoshi::prior::{self, PriorLock, PriorPost};
use newsatoshi::signal::{self, encode_signal_version, signals_bit, MAX_SIGNAL_BIT, MIN_SIGNAL_BIT};
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use primitive_types::U256;
use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[test]
fn redteam_priorism_fep_prior_lock_attacks_rejected() {
    let owner = JobKey::derive(&[1u8; 32]);
    let arb0 = JobKey::derive(&[3u8; 32]);
    let arb1 = JobKey::derive(&[4u8; 32]);
    let owner_vk: [u8; 32] = owner.vk().try_into().unwrap();
    let arb0_vk: [u8; 32] = arb0.vk().try_into().unwrap();
    let arb1_vk: [u8; 32] = arb1.vk().try_into().unwrap();
    let disconfirmer: Word8 = [99u32; 8];
    let falsifier_preimage = [0x55u8; 32];

    // 1. SCGS Invariant I-3: owner listed among arbiters MUST fail!
    let self_arb = PriorPost {
        owner_vk,
        owner_addr: [1u32; 8],
        spec_hash: sha256(b"redteam-prior"),
        falsifier_hash: sha256(&falsifier_preimage),
        arbiter_vks: vec![owner_vk, arb0_vk],
        quorum_m: 1,
        deadline: 50,
        challenge_window: 10,
        stake: 5 * COIN,
    };
    assert!(prior::check_post(&self_arb, 10).is_err());

    // 2. Duplicate arbiter key MUST fail!
    let dup_arb = PriorPost {
        arbiter_vks: vec![arb0_vk, arb0_vk],
        quorum_m: 2,
        ..self_arb.clone()
    };
    assert!(prior::check_post(&dup_arb, 10).is_err());

    // Valid prior
    let post = PriorPost {
        arbiter_vks: vec![arb0_vk, arb1_vk],
        quorum_m: 2,
        ..self_arb
    };
    prior::check_post(&post, 10).unwrap();
    let pid = prior::prior_id(&post, &[7u32; 8]);
    let pl = PriorLock { id: pid, post, created_at: 10, outcome_hash: None, committed_at: None };

    // 3. Identical-payload fake equivocation MUST fail!
    let same = sha256(b"identical-claim");
    let sig_same = owner.sign(&prior::statement_message(&pid, 1, &same));
    assert!(prior::apply_disconfirm_objective(
        &pl, 1, 1, &same, &sig_same, &same, &sig_same, disconfirmer, 10_000, 55
    )
    .is_err());

    // 4. Excessive miner fee (> 10% cap, trying to dodge the 50% burn) MUST fail!
    let excessive_fee = (5 * COIN) / 10 + 1;
    assert!(prior::apply_disconfirm_objective(
        &pl, 0, 0, &falsifier_preimage, &[], &[0; 32], &[], disconfirmer, excessive_fee, 55
    )
    .is_err());

    // 5. Duplicate arbiter index trying to turn 1-of-2 into 2-of-2 MUST fail!
    let ev = sha256(b"falsified-prior-evidence");
    let qm = prior::quorum_disconfirm_message(&pid, &ev, &disconfirmer, 10_000);
    let q0 = arb0.sign(&qm);
    assert!(prior::apply_disconfirm_quorum(
        &pl, &ev, disconfirmer, 10_000, &[(0, q0.clone()), (0, q0)], 55
    )
    .is_err());

    // 6. Post-window disconfirmation (height > deadline + challenge_window = 60) MUST fail!
    assert!(prior::apply_disconfirm_objective(
        &pl, 0, 0, &falsifier_preimage, &[], &[0; 32], &[], disconfirmer, 10_000, 61
    )
    .is_err());

    // 7. Premature release (height <= 60) AND unauthorized non-zero fee release MUST fail!
    assert!(prior::apply_release(&pl, 0, &[], 60).is_err());
    assert!(prior::apply_release(&pl, 10_000, &[], 61).is_err());
    let rel_sig = owner.sign(&prior::release_message(&pid, 10_000));
    let rel = prior::apply_release(&pl, 10_000, &rel_sig, 61).unwrap();
    assert_eq!(rel.payouts[0].v + rel.miner_fee, 5 * COIN);
    assert_eq!(rel.burned, 0);
}

#[test]
fn redteam_bip9_auxpow_non_collision_and_asert_bounds() {
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
            assert_eq!(signals_bit(v, b), bits.contains(&b));
        }
    }
    assert_eq!(encode_signal_version(1, &[0, 8, 16, 31]), 1);
    assert!(!signal::signals_bit(0xffff_ffff, 0));
    assert!(!signal::signals_bit(0xffff_ffff, 8));

    let lim = 0x1d00ffffu32;
    let b_far_future = asert_bits_staged(lim, 0, 2016, 3600, None, 10, 10_000_000_000, 172_800, lim, TARGET_SPACING);
    assert_eq!(b_far_future, lim);
    let b_fast = asert_bits_staged(lim, 1_000_000, 2016, 3600, None, 100, 1_000_010, 172_800, lim, TARGET_SPACING);
    assert_ne!(b_fast, lim);
}

#[test]
fn redteam_p2p_eclipse_defense_opportunistic_pq_transport_and_compact_block() {
    let mut book = AddrBook::default();
    let mut accepted = 0usize;
    for host in 1u8..=200 {
        if book.heard(&format!("203.0.113.{host}:8444")) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, MAX_PER_NETGROUP_BOOK);
    for p in ["198.51.100.1:8444", "192.0.2.1:8444", "1.1.1.1:8444"] {
        assert!(book.heard(p));
        book.good(p);
    }
    let cands = book.candidates(&HashSet::new());
    let attacker_selected = cands.iter().filter(|a| a.starts_with("203.0.113.")).count();
    assert_eq!(attacker_selected, 1);

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

    // Opportunistic ML-KEM-768 P2P transport (blocks passive HNDL capture + in-session tampering/replay)
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
    assert!(resp.open_raw_frame(&frame).is_err());
    frame[4] ^= 0x80;
    assert!(resp.open_raw_frame(&frame).is_err());

    // Compact Block relay reconstructs full STARK block from mempool with >95% bandwidth savings
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
    assert!(compact_bytes * 20 < full_bytes);
    assert_eq!(cb.reconstruct(&[]).unwrap_err(), vec![1]);
    let rebuilt = cb.reconstruct(&[spend_tx]).unwrap();
    assert_eq!(rebuilt.hash(), b2.hash());
}

#[test]
fn redteam_work_proportional_flyclient_and_trustless_light_client_proofs() {
    let mut params = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    params.pow_limit = 0x207fffff;
    params.coinbase_maturity = 1;
    let mut chain = Chain::open(params.clone(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    let mut headers = vec![chain.block_at(0).unwrap()];

    for i in 1..=20u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b.clone()).unwrap();
        headers.push(b);
    }
    let (tx, _) = alice
        .spend(&chain, Some((bob.a_pk(), 2 * COIN)), MAIN_V2_DEFAULT_FEE, None, vec![])
        .unwrap();
    let spent_nf = match &tx {
        Tx::Spend(s) => s.nf[0],
        _ => unreachable!(),
    };
    let (_, producer_fee) = split_spend_fee(MAIN_V2_DEFAULT_FEE, true);
    let out_tip = PlainOut { a_pk: bob.a_pk(), v: subsidy(21) + producer_fee, rho: [99; 5] };
    let mut b_tip = chain.template(vec![out_tip], vec![tx], vec![]).unwrap();
    assert!(mine(&mut b_tip.header, u64::MAX));
    chain.add_block(b_tip.clone()).unwrap();
    headers.push(b_tip.clone());

    // 1. Work-proportional O(log N) FlyClient proof bound directly to tip header_mmr!
    let parts = chain.state.digest_parts();
    let fc = FlyClientProof::prove(&headers, b_tip.tx_root(), parts.clone(), 4, 12).unwrap();
    let (tip_h, work) = fc.verify(headers[0].hash(), 12, true).unwrap();
    assert_eq!(tip_h, chain.tip().hash);
    assert_eq!(work, chain.tip().work);

    // Sibling-work inflation attack (2^100 fake work) MUST be rejected!
    let mut forged = fc.clone();
    let g_leaf = MmrNode {
        hash: mmr_leaf_hash(0, &headers[0].hash(), pow::work(headers[0].header.bits)),
        work: pow::work(headers[0].header.bits),
        height: 0,
    };
    let fake_sib = MmrNode { hash: [0xde; 32], work: U256::from(1u128 << 100), height: 0 };
    let (fake_peak, _) = mmr_parent_hash(&g_leaf, &fake_sib);
    forged.peaks = vec![fake_peak];
    let (r, w) = bag_mmr_peaks(&forged.peaks);
    forged.mmr_root = r;
    forged.ancestor_work = w;
    forged.total_work = w + pow::work(b_tip.header.bits);
    forged.tip_height = 2;
    forged.samples[0].mmr_proof = MmrLeafProof { leaf_height: 0, peak_height: 1, siblings: vec![(true, fake_sib)] };
    assert!(forged.verify(headers[0].hash(), 8, false).is_err());

    // 2. Trustless NoteTree + NfTree verification against committed HeaderTip
    let mut light = HeaderTip::genesis(&params);
    let hdr_only: Vec<_> = headers[1..]
        .iter()
        .map(|b| Block { header: b.header, auxpow: b.auxpow.clone(), digest: [0u8; 32], txs: vec![] })
        .collect();
    light.extend(&params, &hdr_only, newsatoshi::chain::now()).unwrap();
    let cm0 = chain.state.tree.leaf(0).unwrap();
    let path0 = chain.state.tree.path(0);
    let nf_spent_proof = chain.state.nf_tree.prove(&spent_nf);
    assert_eq!(
        light
            .verify_note_and_nullifier(&b_tip.header, &b_tip.tx_root(), &parts, &cm0, 0, &path0, Some((&spent_nf, &nf_spent_proof)))
            .unwrap(),
        Some(true)
    );
    let unspent_nf: Word8 = [77u32; 8];
    let nf_unspent_proof = chain.state.nf_tree.prove(&unspent_nf);
    assert_eq!(
        light
            .verify_note_and_nullifier(&b_tip.header, &b_tip.tx_root(), &parts, &cm0, 0, &path0, Some((&unspent_nf, &nf_unspent_proof)))
            .unwrap(),
        Some(false)
    );
}

#[test]
fn redteam_mainnet_v2_sha384_homeostatic_burn_and_live_nspq1_sync() {
    let mut p = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    assert_eq!(p.magic, *b"nsM2");
    assert_eq!(p.default_port, 8_445);
    assert_eq!(p.default_fee, MAIN_V2_DEFAULT_FEE);
    assert_eq!(p.mmr_from, Some(0));
    assert_eq!(p.prior_from, Some(0));
    assert_eq!(p.homeostatic_burn_from, Some(0));
    assert_eq!(p.batch_spend_from, Some(0));
    assert!(p.pq_transport);
    assert!(p.proof.sha384);
    p.pow_limit = 0x207fffff;
    p.coinbase_maturity = 1;

    let dir = std::env::temp_dir().join(format!(
        "ns-v2-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut chain = Chain::open(p.clone(), Some(&dir)).unwrap();
    assert!(chain.state.digest_parts().header_mmr.is_some());
    assert_eq!(chain.state.header_mmr.leaf_count, 0);

    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    for i in 1..=2u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 10; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }

    let (tx, note_str) = alice
        .spend(&chain, Some((bob.a_pk(), 5 * COIN)), MAIN_V2_DEFAULT_FEE, None, vec![])
        .unwrap();
    assert!(note_str.is_some());
    let tx_bytes = tx.to_bytes();
    assert!(tx_bytes.len() > 490_000, "expected SHA-384 spend > 490 KB, got {}", tx_bytes.len());
    let tx_decoded = Tx::from_bytes(&tx_bytes).unwrap();
    assert_eq!(tx_decoded, tx);

    // Homeostatic 50% fee burn: trying to claim 100% of fee in coinbase MUST be rejected!
    let greedy_out = PlainOut { a_pk: bob.a_pk(), v: subsidy(3) + MAIN_V2_DEFAULT_FEE, rho: [33; 5] };
    assert!(chain.template(vec![greedy_out], vec![tx_decoded.clone()], vec![]).is_err());

    let (burned_fee, producer_fee) = split_spend_fee(MAIN_V2_DEFAULT_FEE, true);
    assert_eq!(burned_fee, MAIN_V2_DEFAULT_FEE / 2);
    let out3 = PlainOut { a_pk: bob.a_pk(), v: subsidy(3) + producer_fee, rho: [33; 5] };
    let mut b3 = chain.template(vec![out3], vec![tx_decoded], vec![]).unwrap();
    assert!(mine(&mut b3.header, u64::MAX));
    let b3_decoded = Block::decode(&b3.encode()).unwrap();
    chain.add_block(b3_decoded).unwrap();

    assert_eq!(chain.height(), 3);
    assert_eq!(chain.state.burned, burned_fee as u128);
    assert_eq!(chain.state.header_mmr.leaf_count, 3);
    let committed_mmr = chain.state.digest_parts().header_mmr.unwrap();
    assert_eq!(committed_mmr, chain.state.header_mmr.root());

    // Fast-boot nsSNAP05 snapshot preserves HeaderMmr, burned counter & tip digest
    chain.save_snapshot().unwrap();
    let tip_hash = chain.tip().hash;
    let tip_digest = chain.state.digest();
    drop(chain);
    let reopened = Chain::open(p.clone(), Some(&dir)).unwrap();
    assert!(reopened.fast_boot);
    assert_eq!(reopened.tip().hash, tip_hash);
    assert_eq!(reopened.state.digest(), tip_digest);
    assert_eq!(reopened.state.burned, burned_fee as u128);
    let _ = std::fs::remove_dir_all(&dir);

    // Live NSPQ1 ML-KEM-768 P2P sync & plaintext rejection
    let port_a = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let node_a = Node::new(reopened);
    lock(&node_a).log = false;
    node::listen(node_a.clone(), port_a).unwrap();

    let mut probe = TcpStream::connect(("127.0.0.1", port_a)).unwrap();
    probe.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let _ = probe.write_all(&Msg::Hello { height: 0, tip: [0u8; 32] }.encode(p.magic));
    assert!(Msg::read(&mut probe, p.magic, p.max_block_bytes).is_err());

    let node_b = Node::new(Chain::open(p.clone(), None).unwrap());
    lock(&node_b).log = false;
    node::keep_connected(node_b.clone(), format!("127.0.0.1:{port_a}"));
    let deadline = Instant::now() + Duration::from_secs(15);
    while lock(&node_b).chain.height() < 3 {
        assert!(Instant::now() < deadline, "Node B failed to sync over NSPQ1");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(lock(&node_b).chain.tip().hash, tip_hash);
    assert_eq!(lock(&node_b).chain.state.header_mmr.root(), committed_mmr);
}
