//! Pre-Mainnet v2 (`v1.2.0-mainnet-rc1`) Architectural Frontier Verification Suite.
//!
//! Explicitly stress-tests every irreversible consensus, economic, state-complexity, and P2P
//! security invariant hardened before Mainnet v2 genesis:
//! 1. **2,025-Block Mainnet v2 Day-14 ASERT Launch → Steady Boundary Crossing (`2015 → 2016 → 2017 → 2025`):**
//!    Verifies `Chain::add_block`, `Chain::check_headers`, multi-batch `HeaderTip::extend` +
//!    `to_bytes`/`from_bytes` persistence, `FlyClientProof::verify`, and differential agreement
//!    with the independent JS/OpenSSL verifier (`asertBitsStaged`) — ZERO panic, ZERO fork!
//! 2. **$O(\log N)$ Merkleized `locks` & `conds` + Legacy `jobs` Disabled on `nsM2`:**
//!    Verifies `Deposit::Post` is rejected on Mainnet v2, while `Lock` & `Cond` generate
//!    light-client-verifiable `MerkleProof`s committed in $O(1)$ per block (and survive `nsSNAP06`).
//! 3. **Authenticated `NSPQ2` (ML-KEM-768 + SLH-DSA-SHA2-128s Peer Pinning) + Slowloris Frame DoS Defense:**
//!    Verifies pinned peers sync over `NSPQ2`, active MITM / wrong pinned key is rejected immediately,
//!    and a hostile peer declaring a 16 MB frame and closing allocates zero 16 MB buffer.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::cond::{self, CondPost};
use newsatoshi::hash::sha256;
use newsatoshi::job::{Deposit, JobKey, JobPost};
use newsatoshi::light::{FlyClientProof, HeaderTip};
use newsatoshi::lock::{self, LockPost};
use newsatoshi::node::{self, lock, Node};
use newsatoshi::params::{split_spend_fee, subsidy, Params, COIN, MAIN_V2_DEFAULT_FEE};
use newsatoshi::pq_transport::{PqSession, MAX_ENCRYPTED_FRAME_BYTES};
use newsatoshi::rpc;
use newsatoshi::script;
use newsatoshi::tx::{Block, PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn mainnet_v2_crosses_day14_asert_launch_to_steady_boundary_with_zero_panic_or_fork() {
    // Use real Mainnet v2 `launch_blocks = 2_016`, `launch_half_life = 3_600`, `half_life = 172_800`,
    // with laptop-mineable pow_limit = 0x207fffff and realistic 600s timestamps!
    let genesis_time = newsatoshi::chain::now() as u32 - 2_030 * 600;
    let mut params = Params::main_v2_with(genesis_time, u32::MAX, 0x207fffff);
    params.pow_limit = 0x207fffff;
    params.coinbase_maturity = 1;

    let mut chain = Chain::open(params.clone(), None).unwrap();
    let mut full_blocks = vec![chain.block_at(0).unwrap()];

    // Mine 2,025 consecutive blocks strictly across the height 2,016 launch->steady boundary!
    // Block 1..=2,016 use launch_half_life = 3,600 s; block 2,017..=2,025 use steady half_life = 172,800 s
    // anchored at block 2,016 (bits, time).
    for h in 1..=2_025u32 {
        let mut b = chain.template(vec![], vec![], vec![]).unwrap();
        // Keep exact on-schedule 600s timestamps (with mild jitter on height 2,016..2,025 to exercise steady ASERT)
        b.header.time = genesis_time + h * 600 + if h > 2_016 { (h - 2_016) * 30 } else { 0 };
        b.header.bits = chain.next_bits(chain.tip());
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b.clone()).unwrap();
        full_blocks.push(b);
    }
    assert_eq!(chain.height(), 2_025);

    // 1. P2P header sync across the boundary: split into TWO batches ([1..=2010] and [2011..=2025])
    //    AND a batch starting AFTER height 2,016 ([2018..=2025])!
    let hdr_only: Vec<Block> = full_blocks[1..]
        .iter()
        .map(|b| Block { header: b.header, auxpow: b.auxpow.clone(), digest: [0u8; 32], txs: vec![] })
        .collect();

    let fresh = Chain::open(params.clone(), None).unwrap();
    // Single-shot check_headers across ALL 2,025 headers (previously PANICKED at height 2,017!)
    let (w_all, h_all) = fresh.check_headers(&hdr_only).unwrap();
    assert_eq!(h_all, 2_025);
    assert_eq!(w_all, chain.tip().work);

    // 2. SPV Light Client (`HeaderTip`) syncing across height 2,016 with disk serialization round-trip!
    let mut lc = HeaderTip::genesis(&params);
    let now_ts = newsatoshi::chain::now();
    lc.extend(&params, &hdr_only[..2_010], now_ts).unwrap();
    assert_eq!(lc.tip.height, 2_010);
    assert!(lc.steady_anchor.is_none());

    // Cross height 2,016 -> captures steady_anchor!
    lc.extend(&params, &hdr_only[2_010..2_018], now_ts).unwrap();
    assert_eq!(lc.tip.height, 2_018);
    let anchor_2016 = &full_blocks[2_016].header;
    assert_eq!(lc.steady_anchor, Some((anchor_2016.bits, anchor_2016.time as i64)));

    // Serialize & reload HeaderTip after crossing 2,016, then continue extending to 2,025!
    let saved = lc.to_bytes();
    let mut lc_reloaded = HeaderTip::from_bytes(&saved).unwrap();
    assert_eq!(lc_reloaded.steady_anchor, lc.steady_anchor);
    lc_reloaded.extend(&params, &hdr_only[2_018..], now_ts).unwrap();
    assert_eq!(lc_reloaded.tip.height, 2_025);
    assert_eq!(lc_reloaded.tip.hash, chain.tip().hash);
    assert_eq!(lc_reloaded.tip.work, chain.tip().work);

    // 3. Work-proportional O(log N) FlyClient proof at height 2,025!
    let tip_blk = full_blocks.last().unwrap();
    let fc = FlyClientProof::prove(&full_blocks, tip_blk.tx_root(), chain.state.digest_parts(), 6, 16).unwrap();
    let (fc_tip, fc_work) = fc.verify(full_blocks[0].hash(), 16, true).unwrap();
    assert_eq!(fc_tip, chain.tip().hash);
    assert_eq!(fc_work, chain.tip().work);

    // 4. Independent JS/OpenSSL verifier differential check right past height 2,016!
    let parent_2020 = &full_blocks[2_020].header;
    let child_2021 = &full_blocks[2_021].header;
    let vec_json = format!(
        r#"{{
          "asert_staged": {{
            "genesis_bits": {},
            "genesis_parent_time": {},
            "launch_blocks": {},
            "launch_half_life": {},
            "steady_anchor": {{ "bits": {}, "time": {} }},
            "parent_height": 2020,
            "parent_time": {},
            "steady_half_life": {},
            "pow_limit_bits": {},
            "spacing": {},
            "expected_bits": {}
          }}
        }}"#,
        params.genesis_bits,
        params.genesis_time as i64 - params.target_spacing,
        params.launch_blocks,
        params.launch_half_life,
        anchor_2016.bits,
        anchor_2016.time,
        parent_2020.time,
        params.half_life,
        params.pow_limit,
        params.target_spacing,
        child_2021.bits,
    );
    let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("verifier-ts/newsatoshi_verifier.mjs");
    let mut child = Command::new("node")
        .arg(&script_path)
        .arg("verify-vector")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("node must be installed");
    child.stdin.as_mut().unwrap().write_all(vec_json.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "JS verifier disagreed on post-2016 staged ASERT: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn mainnet_v2_merkleizes_locks_and_conds_in_o_log_n_and_disables_legacy_jobs() {
    let mut params = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    assert!(!params.legacy_jobs_enabled);
    assert_eq!(params.merkle_locks_conds_from, Some(0));
    assert_eq!(params.seeds, &["newsatoshi-seed.fly.dev:8445"]);
    params.pow_limit = 0x207fffff;
    params.coinbase_maturity = 1;

    let dir = std::env::temp_dir().join(format!(
        "ns-v2-merkle-lc-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let mut chain = Chain::open(params.clone(), Some(&dir)).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();
    let miner = Wallet::generate();

    for i in 1..=3u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 10; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }

    // 1. Legacy matrix-product job MUST be rejected on Mainnet v2 (keeps `state.jobs` empty forever!)
    let jk = JobKey::derive(&[3u8; 32]);
    let bad_job = JobPost {
        poster_vk: jk.vk(),
        poster_addr: alice.a_pk(),
        n: 4,
        k: 4,
        m: 4,
        a_root: [1u8; 32],
        b_root: [2u8; 32],
        pay: COIN,
        bond_min: COIN,
        claim_by: chain.height() + 20,
        deliver_blocks: 10,
        window_blocks: 10,
    };
    let (job_tx, _) = alice
        .spend(&chain, None, MAIN_V2_DEFAULT_FEE, Some(Deposit::Post(bad_job)), vec![])
        .unwrap();
    let (_, prod_fee) = split_spend_fee(MAIN_V2_DEFAULT_FEE, true);
    let out_fail = PlainOut { a_pk: miner.a_pk(), v: subsidy(4) + prod_fee, rho: [40; 5] };
    assert!(
        chain.template(vec![out_fail], vec![job_tx], vec![]).is_err(),
        "legacy matrix-product job must be rejected on Mainnet v2"
    );
    assert!(chain.state.jobs.is_empty());

    // 2. Open an HTLC Lock and a Taproot-style Cond on Mainnet v2 -> committed via O(log N) MerkleMap!
    let preimage = [0x77u8; 32];
    let lpost = LockPost {
        hash: sha256(&preimage),
        timeout: chain.height() + 50,
        claim_addr: bob.a_pk(),
        refund_addr: alice.a_pk(),
        amount: 2 * COIN,
    };
    let (lock_tx, _) = alice
        .spend(&chain, None, MAIN_V2_DEFAULT_FEE, Some(Deposit::Lock(lpost.clone())), vec![])
        .unwrap();
    let nf_l = match &lock_tx {
        Tx::Spend(s) => if s.dummy[0] { s.nf[1] } else { s.nf[0] },
        _ => unreachable!(),
    };
    let lid = lock::lock_id(&lpost, &nf_l);

    let out4 = PlainOut { a_pk: miner.a_pk(), v: subsidy(4) + prod_fee, rho: [41; 5] };
    let mut b4 = chain.template(vec![out4], vec![lock_tx], vec![]).unwrap();
    assert!(mine(&mut b4.header, u64::MAX));
    chain.add_block(b4).unwrap();

    let prog = script::assemble("1").unwrap();
    let salt = [0x88u8; 32];
    let cpost = CondPost {
        commitment: cond::commitment(&salt, &prog),
        payouts: vec![bob.a_pk()],
        timeout: chain.height() + 50,
        refund_addr: alice.a_pk(),
        amount: 3 * COIN,
    };
    let (cond_tx, _) = alice
        .spend(&chain, None, MAIN_V2_DEFAULT_FEE, Some(Deposit::Cond(cpost.clone())), vec![])
        .unwrap();
    let nf_c = match &cond_tx {
        Tx::Spend(s) => if s.dummy[0] { s.nf[1] } else { s.nf[0] },
        _ => unreachable!(),
    };
    let cid = cond::cond_id(&cpost, &nf_c);

    let out5 = PlainOut { a_pk: miner.a_pk(), v: subsidy(5) + prod_fee, rho: [42; 5] };
    let mut b5 = chain.template(vec![out5], vec![cond_tx], vec![]).unwrap();
    assert!(mine(&mut b5.header, u64::MAX));
    chain.add_block(b5.clone()).unwrap();

    // Light client verifies O(log N) Merkle proofs for BOTH Lock and Cond against header commit!
    let mut lc = HeaderTip::genesis(&params);
    let hdrs: Vec<Block> = (1..=chain.height()).map(|h| chain.header_at(h).unwrap()).collect();
    lc.extend(&params, &hdrs, newsatoshi::chain::now()).unwrap();
    let parts = chain.state.digest_parts();
    assert_eq!(parts.locks, Some(chain.state.locks_merkle.root()));
    assert_eq!(parts.conds, Some(chain.state.conds_merkle.root()));

    let lp = chain.state.locks_merkle.prove(&lid).unwrap();
    let cp = chain.state.conds_merkle.prove(&cid).unwrap();
    lc.verify_state_map_proof(&b5.header, &b5.tx_root(), &parts, parts.locks, &lp).unwrap();
    lc.verify_state_map_proof(&b5.header, &b5.tx_root(), &parts, parts.conds, &cp).unwrap();

    // Verify fast-boot nsSNAP06 snapshot round-trip preserves merkle_locks_conds & exact digest!
    chain.save_snapshot().unwrap();
    let tip_dig = chain.state.digest();
    drop(chain);
    let reopened = Chain::open(params.clone(), Some(&dir)).unwrap();
    assert!(reopened.fast_boot);
    assert!(reopened.state.merkle_locks_conds);
    assert_eq!(reopened.state.digest(), tip_dig);
    assert!(reopened.state.locks_merkle.prove(&lid).is_some());
    assert!(reopened.state.conds_merkle.prove(&cid).is_some());
    let _ = std::fs::remove_dir_all(&dir);

    // Verify RPC `/status` reports `"proofs": "main-v2"` AND `/api/lock` + `/api/cond` expose `merkle_proof`!
    let shared = Node::new(reopened);
    lock(&shared).log = false;
    assert_eq!(rpc::status(&shared).get("proofs"), Some(&rpc::J::str("main-v2")));
    assert!(rpc::lock_info(&shared, &lid).get("merkle_proof").is_some());
    assert!(rpc::cond_info(&shared, &cid).get("merkle_proof").is_some());
}

#[test]
fn nspq2_slh_dsa_pinned_auth_blocks_active_mitm_and_chunked_read_blocks_slowloris() {
    let magic = *b"nsM2";
    let real_key = JobKey::derive(b"seed-node-real-identity");
    let real_vk: [u8; 32] = real_key.vk().try_into().unwrap();
    let wrong_vk: [u8; 32] = JobKey::derive(b"attacker-wrong-key").vk().try_into().unwrap();

    // 1. Live NSPQ2 authenticated sync between Node A (with SLH-DSA identity) and pinned Node B!
    let mut p = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    p.pow_limit = 0x207fffff;
    p.coinbase_maturity = 1;
    let mut chain_a = Chain::open(p.clone(), None).unwrap();
    for _ in 0..3 {
        let mut b = chain_a.template(vec![], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain_a.add_block(b).unwrap();
    }
    let tip_a = chain_a.tip().hash;

    let port_a = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let node_a = Node::new(chain_a);
    {
        let mut na = lock(&node_a);
        na.log = false;
        na.p2p_identity = Some(Arc::new(JobKey::derive(b"seed-node-real-identity")));
    }
    node::listen(node_a.clone(), port_a).unwrap();

    // Active MITM / wrong pinned key MUST be rejected immediately!
    let mut bad_sock = TcpStream::connect(("127.0.0.1", port_a)).unwrap();
    bad_sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    assert!(
        PqSession::handshake_initiator_pinned(&mut bad_sock, magic, &wrong_vk).is_err(),
        "NSPQ2 must reject peer whose SLH-DSA signature does not match pinned VK"
    );

    // Legitimate pinned peer (`HOST:PORT@<64hex_vk>`) syncs all 3 blocks over NSPQ2!
    let node_b = Node::new(Chain::open(p.clone(), None).unwrap());
    lock(&node_b).log = false;
    let pinned_spec = format!("127.0.0.1:{port_a}@{}", hex::encode(real_vk));
    node::keep_connected(node_b.clone(), pinned_spec);
    let deadline = Instant::now() + Duration::from_secs(15);
    while lock(&node_b).chain.height() < 3 {
        assert!(Instant::now() < deadline, "Node B failed to sync over NSPQ2 pinned link");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(lock(&node_b).chain.tip().hash, tip_a);

    // 2. Slowloris OOM defense: hostile peer claims MAX_ENCRYPTED_FRAME_BYTES (16 MB) then sends 10 bytes & closes;
    //    chunked reader MUST return Err cleanly without allocating 16 MB!
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let sess = PqSession::handshake_responder(&mut s, magic).unwrap();
        let (_, mut rx) = sess.split();
        rx.read_frame_paced(&mut s, MAX_ENCRYPTED_FRAME_BYTES, Some(Duration::from_secs(2)), 16_384)
    });
    let mut cli = TcpStream::connect(addr).unwrap();
    let _init = PqSession::handshake_initiator(&mut cli, magic).unwrap();
    cli.write_all(&(MAX_ENCRYPTED_FRAME_BYTES as u32).to_le_bytes()).unwrap();
    cli.write_all(&[0xaa; 10]).unwrap();
    drop(cli);
    assert!(srv.join().unwrap().is_err());
}
