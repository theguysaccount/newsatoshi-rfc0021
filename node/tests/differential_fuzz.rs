//! Multi-Client Differential Verification (Rust L1 <-> Independent Node.js/OpenSSL/BigInt Verifier)
//! + Deterministic 10,000-Iteration Adversarial Mutation Fuzzer
//! + Frontier E2E (Utreexo 1 KB Tracked Proofs -> Spend STARK, Pruned Disk KV, SHA-256d HeaderChain STARK, FRI Folding STARK).

use newsatoshi::auxpow::AuxPow;
use newsatoshi::batch_spend::{verify_batch_bytes_for, BatchSpendPublic};
use newsatoshi::chain::{mine, Chain};
use newsatoshi::codec::Reader;
use newsatoshi::hash::{sha256, words_to_bytes};
use newsatoshi::job::{Action, Deposit};
use newsatoshi::light::HeaderMmr;
use newsatoshi::node::CompactBlock;
use newsatoshi::params::{split_spend_fee, subsidy, Net, Params, DEFAULT_FEE, MAIN_V2_DEFAULT_FEE};
use newsatoshi::peers::{self, AddrBook};
use newsatoshi::pow;
use newsatoshi::pruned_store::{load_pruned_checkpoint, prune_chain_to_disk, DiskKvStore};
use newsatoshi::recursion::{
    prove_fri_folding, prove_header_chain_segment, verify_folded_header_segments,
    verify_fri_folding, FriFoldStep, HEADERS_PER_SEGMENT,
};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendPublic, SpendWitness};
use newsatoshi::tx::{Block, Header, PlainOut, Tx};
use newsatoshi::utreexo::{CompactNoteTree, TrackedNoteProof};
use newsatoshi::wallet::Wallet;
use std::io::Write;
use std::process::{Command, Stdio};
use winterfell::math::fields::f64::BaseElement as Felt;
use winterfell::math::FieldElement;

fn run_independent_verifier(json_payload: &str) -> (bool, String) {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../verifier-ts/newsatoshi_verifier.mjs");
    let mut child = Command::new("node")
        .arg(&script)
        .arg("verify-vector")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn independent Node.js/OpenSSL verifier");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(json_payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    (out.status.success(), stdout)
}

#[test]
fn differential_rust_vs_independent_js_openssl_verifier() {
    let mut p = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
    p.pow_limit = 0x207fffff;
    p.coinbase_maturity = 1;
    let mut chain = Chain::open(p.clone(), None).unwrap();
    let mut alice = Wallet::generate();
    let bob = Wallet::generate();

    for i in 1..=5u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 7; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }
    let (spend_tx, _) = alice
        .spend(&chain, Some((bob.a_pk(), 100_000_000)), MAIN_V2_DEFAULT_FEE, None, vec![])
        .unwrap();
    let (burned_fee, producer_fee) = split_spend_fee(MAIN_V2_DEFAULT_FEE, true);
    let out6 = PlainOut { a_pk: bob.a_pk(), v: subsidy(6) + producer_fee, rho: [66; 5] };
    let mut b6 = chain.template(vec![out6], vec![spend_tx], vec![]).unwrap();
    assert!(mine(&mut b6.header, u64::MAX));
    chain.add_block(b6.clone()).unwrap();

    let headers_hex: Vec<String> = chain
        .active
        .iter()
        .map(|h| hex::encode(chain.block(h).unwrap().header.bytes()))
        .collect();
    let mut rust_mmr = HeaderMmr::new();
    for h in &chain.active {
        let blk = chain.block(h).unwrap();
        rust_mmr.push(blk.hash(), pow::work(blk.header.bits));
    }
    let (mmr_root, _) = rust_mmr.root_and_work();

    let asert_expected = pow::asert_bits(
        0x1d00_ffff,
        1_762_473_000,
        517,
        1_762_473_600 + 517 * 480,
        3_600,
        0x1d00_ffff,
        600,
    );

    let leaves_hex: Vec<String> = chain
        .state
        .tree
        .leaves()
        .iter()
        .map(|w| hex::encode(words_to_bytes(w)))
        .collect();
    let rust_note_root = hex::encode(words_to_bytes(&chain.state.tree.root()));
    let parts = chain.state.digest_parts();
    let rust_state_digest = hex::encode(parts.digest());
    let tx_hashes: Vec<String> = b6.txs.iter().map(|t| hex::encode(t.id())).collect();

    let tok = [0x42u8; 32];
    let mut tip = tok;
    for _ in 0..10 {
        tip = sha256(&tip);
    }

    let opt_hex = |o: Option<[u8; 32]>| match o {
        Some(b) => format!("\"{}\"", hex::encode(b)),
        None => "null".to_string(),
    };

    let json_vec = format!(
        r#"{{
          "headers": [{}],
          "expected_mmr_root": "{}",
          "expected_tip_hash": "{}",
          "asert": {{
            "anchor_bits": {},
            "anchor_parent_time": 1762473000,
            "parent_height": 517,
            "parent_time": {},
            "half_life": 3600,
            "pow_limit_bits": {},
            "spacing": 600,
            "expected_bits": {}
          }},
          "note_leaves": [{}],
          "expected_note_root": "{}",
          "digest_parts": {{
            "height": {},
            "tree_root": "{}",
            "nf_acc": "{}",
            "jobs": "{}",
            "pending": "{}",
            "issued": "{}",
            "burned": "{}",
            "locked": "{}",
            "locks": {},
            "conds": {},
            "nf_root": {},
            "channels": {},
            "priors": {},
            "header_mmr": {}
          }},
          "expected_state_digest": "{}",
          "tx_hashes": [{}],
          "tip_header_hex": "{}",
          "payword": {{
            "tipHex": "{}",
            "tokenHex": "{}",
            "ticks": 10,
            "deposit": "10000",
            "unitPrice": "500",
            "sellerPaid": "4900",
            "buyerRefund": "5000",
            "minerFee": "100"
          }},
          "prior_disconfirm": {{
            "stake": "10000000",
            "bounty": "4950000",
            "burn": "4950000",
            "fee": "100000"
          }},
          "homeostatic_burn": {{
            "fee": "{}",
            "burned": "{}",
            "producer": "{}"
          }}
        }}"#,
        headers_hex.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        hex::encode(mmr_root),
        hex::encode(b6.hash()),
        0x1d00_ffffu32,
        1_762_473_600i64 + 517 * 480,
        0x1d00_ffffu32,
        asert_expected,
        leaves_hex.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        rust_note_root,
        parts.height,
        hex::encode(words_to_bytes(&parts.tree_root)),
        hex::encode(parts.nf_acc),
        hex::encode(parts.jobs),
        hex::encode(parts.pending),
        parts.issued,
        parts.burned,
        parts.locked,
        opt_hex(parts.locks),
        opt_hex(parts.conds),
        opt_hex(parts.nf_root),
        opt_hex(parts.channels),
        opt_hex(parts.priors),
        opt_hex(parts.header_mmr),
        rust_state_digest,
        tx_hashes.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        hex::encode(b6.header.bytes()),
        hex::encode(tip),
        hex::encode(tok),
        MAIN_V2_DEFAULT_FEE,
        burned_fee,
        producer_fee,
    );

    let (ok, stdout) = run_independent_verifier(&json_vec);
    assert!(ok, "Independent JS/OpenSSL verifier disagreed with Rust L1! Output: {stdout}");
    assert!(stdout.contains("\"header_commit_verified\":true"), "missing commit check: {stdout}");
    assert!(stdout.contains("\"prior_disconfirm_verified\":true"));
    assert!(stdout.contains("\"homeostatic_burn_verified\":true"));

    let bad_asert = json_vec.replace(
        &format!("\"expected_bits\": {asert_expected}"),
        &format!("\"expected_bits\": {}", asert_expected ^ 1),
    );
    assert!(!run_independent_verifier(&bad_asert).0);

    let bad_prior = json_vec.replace("\"bounty\": \"4950000\"", "\"bounty\": \"4950001\"");
    assert!(!run_independent_verifier(&bad_prior).0);
}

#[test]
fn mutation_fuzz_10000_hostile_wire_stark_batch_p2p_payloads() {
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut next_u64 = || {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };

    let pi = SpendPublic {
        root: [0; 8],
        nf: [[1; 8], [2; 8]],
        cm_out: [[3; 8], [4; 8]],
        value_balance: 0,
        dummy: [false, true],
        bind: [5; 8],
    };
    let bpi = BatchSpendPublic {
        spends: vec![pi.clone(), pi.clone()],
        prover_a_pk: [9; 8],
    };

    let mut book = AddrBook::default();
    for iter in 0..10_000u32 {
        let len = (next_u64() % 256) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (next_u64() & 0xff) as u8;
        }
        let _ = Tx::from_bytes(&buf);
        let _ = Block::decode(&buf);
        let _ = AuxPow::parse(&buf);
        let mut r = Reader::new(&buf);
        let _ = Action::decode(&mut r);
        if !buf.is_empty() {
            let mut r2 = Reader::new(&buf[1..]);
            let _ = Deposit::decode_body(buf[0], &mut r2);
        }
        let mut r3 = Reader::new(&buf);
        let _ = CompactNoteTree::decode(&mut r3);
        let mut r4 = Reader::new(&buf);
        let _ = CompactBlock::decode(&mut r4);
        if buf.len() >= 80 {
            let mut hb = [0u8; 80];
            hb.copy_from_slice(&buf[..80]);
            let _ = Header::from_bytes(&hb);
        }
        if iter % 10 == 0 {
            assert!(spend::verify_bytes_for(&spend::MAIN_V2, &pi, &buf).is_err());
            assert!(verify_batch_bytes_for(&spend::MAIN_V2, &bpi, &buf).is_err());
        }
        if let Ok(s) = std::str::from_utf8(&buf) {
            let _ = peers::valid(s);
            let _ = peers::netgroup(s);
            let _ = book.heard(s);
        }
    }
}

#[test]
fn frontier_utreexo_tracked_proof_spends_in_stark_plus_pruned_kv_and_sha384_recursion_e2e() {
    let mut compact = CompactNoteTree::new();
    let alice = Wallet::generate();
    let bob = Wallet::generate();
    let my_rho = [11, 22, 33, 44, 55];
    let my_val = 500_000_000u64;
    let my_cm = newsatoshi::note::commit(&alice.a_pk(), my_val, &my_rho);

    let mut tracked: Option<TrackedNoteProof> = None;
    for i in 0..150u32 {
        let cm = if i == 42 {
            my_cm
        } else {
            newsatoshi::note::commit(&bob.a_pk(), 1000 + i as u64, &[i, 1, 2, 3, 4])
        };
        let delta = compact.append_tracked(cm);
        if let Some(ref mut tp) = tracked {
            tp.update_on_append(&delta);
        }
        if i == 42 {
            tracked = Some(TrackedNoteProof::from_birth(cm, &delta, compact.empty_roots()));
        }
    }
    let tp = tracked.unwrap();
    assert_eq!(tp.root(), compact.root());
    assert!(compact.frontier_bytes() <= 1024);

    let wit = SpendWitness {
        inputs: [
            InputNote {
                sk: alice.sk,
                v: my_val,
                rho: my_rho,
                pos: tp.pos,
                path: tp.path,
            },
            InputNote::dummy(),
        ],
        outputs: [
            OutputNote { a_pk: bob.a_pk(), v: 200_000_000, rho: [7; 5] },
            OutputNote {
                a_pk: alice.a_pk(),
                v: my_val - 200_000_000 - DEFAULT_FEE,
                rho: [8; 5],
            },
        ],
        dummy: [false, true],
    };
    let (pi, proof) = spend::prove_for(&spend::TEST, &wit, [9; 8]).unwrap();
    assert_eq!(pi.root, compact.root());
    spend::verify_bytes_for(&spend::TEST, &pi, &proof.to_bytes()).unwrap();

    let params = Params::get(Net::Reg).unwrap();
    let mut chain = Chain::open(params, None).unwrap();
    for i in 1..=8u32 {
        let out = PlainOut { a_pk: alice.a_pk(), v: subsidy(i), rho: [i + 100; 5] };
        let mut b = chain.template(vec![out], vec![], vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        chain.add_block(b).unwrap();
    }

    let pdir = std::env::temp_dir().join(format!(
        "ns-frontier-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let rep = prune_chain_to_disk(&chain, &pdir, 2).unwrap();
    assert_eq!(rep.tail_blocks_kept, 3);
    assert!(rep.compact_note_frontier_bytes <= 1024);
    let (_, _, _, loaded_frontier, _) = load_pruned_checkpoint(&pdir).unwrap();
    assert_eq!(loaded_frontier.root(), chain.state.tree.root());
    let _ = DiskKvStore::open(&pdir.join("nullifiers"), 64).unwrap();
    let _ = std::fs::remove_dir_all(&pdir);

    let hdrs: Vec<Header> = chain
        .active[1..=8]
        .iter()
        .map(|h| chain.block(h).unwrap().header)
        .collect();
    let s1: [Header; HEADERS_PER_SEGMENT] = hdrs[0..4].try_into().unwrap();
    let s2: [Header; HEADERS_PER_SEGMENT] = hdrs[4..8].try_into().unwrap();
    let seg1 = prove_header_chain_segment(&s1).unwrap();
    let seg2 = prove_header_chain_segment(&s2).unwrap();
    let (start_prev, end_hash, count, sec) = verify_folded_header_segments(&[seg1, seg2]).unwrap();
    assert_eq!(start_prev, chain.genesis);
    assert_eq!(end_hash, chain.tip().hash);
    assert_eq!(count, 8);
    assert!(sec >= 100, "expected >= 100 conservative QROM (CMS19) bits, got {sec}");

    // Also verify real STARK-in-STARK IVC folding of the two mined header segments into ONE proof!
    let o1 = newsatoshi::recursion::prove_outer_header_segment(&s1).unwrap();
    let o2 = newsatoshi::recursion::prove_outer_header_segment(&s2).unwrap();
    let (rpi, rproof) =
        newsatoshi::recursion::prove_recursive_chain_fold((&o1.0, &o1.1), (&o2.0, &o2.1)).unwrap();
    let rqrom = newsatoshi::recursion::verify_recursive_chain_fold(&rpi, &rproof).unwrap();
    assert!(rqrom >= 100, "recursive STARK-in-STARK IVC must prove >= 100 QROM bits, got {rqrom}");
    assert_eq!(newsatoshi::hash::words_to_bytes(&rpi.start_prev_words), chain.genesis);
    assert_eq!(newsatoshi::hash::words_to_bytes(&rpi.end_hash_words), chain.tip().hash);

    let mut steps = Vec::new();
    let (mut x, mut fp, mut fn_) = (Felt::new(11), Felt::new(333), Felt::new(777));
    let inv2 = Felt::new(2).inv();
    for r in 0..32u64 {
        let alpha = Felt::new(42 + r * 19);
        steps.push(FriFoldStep { x, f_pos: fp, f_neg: fn_, alpha, next_is_neg: r % 2 == 0 });
        let folded = (fp + fn_) * inv2 + alpha * (fp - fn_) * (Felt::new(2) * x).inv();
        x = x * x;
        if r % 2 == 0 {
            fp = Felt::new(99 + r);
            fn_ = folded;
        } else {
            fp = folded;
            fn_ = Felt::new(99 + r);
        }
    }
    let (fpi, fproof) = prove_fri_folding(&steps).unwrap();
    assert!(verify_fri_folding(&fpi, &fproof).unwrap() >= 100);
}
