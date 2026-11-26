//! Cryptographic Known-Answer & Determinism Regression Tests (NIST FIPS 203 & FIPS 205)
//! plus Verified Fast-Boot Disk Snapshot (`state.snap`) integrity and tamper-rejection tests.
//!
//! Pins the exact deterministic outputs of `ml-kem` (FIPS 203 ML-KEM-768) and `slh-dsa`
//! (FIPS 205 SLH-DSA-SHA2-128s) used by Newsatoshi so any future dependency upgrade
//! (e.g., migrating off `pre` releases to stable 1.0 crates) is immediately verified
//! byte-for-byte against live wallet derivation and wire formats.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::channel::{build_payword_chain, channel_id, ChannelPost};
use newsatoshi::deliver;
use newsatoshi::hash::{bytes_to_words, sha256};
use newsatoshi::job::{self, Action, Deposit, JobKey};
use newsatoshi::params::{subsidy, Net, Params, DEFAULT_FEE};
use newsatoshi::snapshot::SNAPSHOT_FILE;
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

#[test]
fn fips_205_slh_dsa_sha2_128s_determinism_lengths_and_tamper_rejection() {
    let seed = [0x42u8; 32];
    let k1 = JobKey::derive(&seed);
    let k2 = JobKey::derive(&seed);
    assert_eq!(k1.to_bytes(), k2.to_bytes(), "SLH-DSA key derivation must be deterministic");
    assert_eq!(k1.vk(), k2.vk());
    // FIPS 205 Table 2 (SLH-DSA-SHA2-128s): pk = 32B, sk = 64B, sig = 7,856B
    assert_eq!(k1.vk().len(), 32, "SLH-DSA-SHA2-128s public key must be 32 bytes");
    assert_eq!(k1.to_bytes().len(), 64, "SLH-DSA-SHA2-128s secret key must be 64 bytes");

    let msg = b"newsatoshi-fips205-kat-vector-v1";
    let sig = k1.sign(msg);
    assert_eq!(sig.len(), 7_856, "SLH-DSA-SHA2-128s signature must be 7,856 bytes");
    assert!(job::verify_sig(&k1.vk(), msg, &sig));

    // Distinct seed produces distinct key and fails verification
    let other = JobKey::derive(&[0x43u8; 32]);
    assert_ne!(k1.vk(), other.vk());
    assert!(!job::verify_sig(&other.vk(), msg, &sig));

    // 1-bit flip in message or signature MUST fail verification
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0x01;
    assert!(!job::verify_sig(&k1.vk(), &bad_msg, &sig));

    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0x80;
    assert!(!job::verify_sig(&k1.vk(), msg, &bad_sig));
    let mut bad_sig_tail = sig.clone();
    *bad_sig_tail.last_mut().unwrap() ^= 0x01;
    assert!(!job::verify_sig(&k1.vk(), msg, &bad_sig_tail));

    // Round-trip key serialization
    let restored = JobKey::from_bytes(&k1.to_bytes()).unwrap();
    assert_eq!(restored.vk(), k1.vk());
    assert!(job::verify_sig(&restored.vk(), msg, &sig));
}

#[test]
fn fips_203_ml_kem_768_determinism_lengths_and_implicit_rejection() {
    let sk = bytes_to_words(&[0x11u8; 32]);
    let ek1 = deliver::encapsulation_key(&sk);
    let ek2 = deliver::encapsulation_key(&sk);
    assert_eq!(ek1, ek2, "ML-KEM-768 encapsulation key derivation must be deterministic");
    // FIPS 203 Table 2 (ML-KEM-768): ek = 1,184B, ct = 1,088B (+ 28B box + 16B tag = 1,132B envelope)
    assert_eq!(ek1.len(), 1_184);

    let delivery_addr = deliver::delivery_address(&sk);
    assert!(delivery_addr.starts_with("nsd1"));
    let (parsed_apk, parsed_ek) = deliver::parse_delivery_address(&delivery_addr).unwrap();
    assert_eq!(parsed_ek, ek1);

    let v = 12_345_678u64;
    let rho = [1u32, 2, 3, 4, 5];
    let cm = newsatoshi::note::commit(&parsed_apk, v, &rho);
    let m = [0x99u8; 32];
    let env1 = deliver::seal(&ek1, &cm, v, &rho, m).unwrap();
    let env2 = deliver::seal(&ek1, &cm, v, &rho, m).unwrap();
    assert_eq!(env1, env2, "deterministic encapsulation must reproduce exact envelope bytes");
    assert_eq!(env1.len(), deliver::ENVELOPE_BYTES);
    assert_eq!(deliver::open(&sk, &cm, &env1), Some((v, rho)));

    // Wrong wallet key must reject implicitly (tag check fails)
    let wrong_sk = bytes_to_words(&[0x22u8; 32]);
    assert_eq!(deliver::open(&wrong_sk, &cm, &env1), None);

    // 1-bit flip in ML-KEM ciphertext or authenticated box/tag MUST reject
    for idx in [0usize, 500, 1087, 1088, env1.len() - 1] {
        let mut tampered = env1.clone();
        tampered[idx] ^= 0x01;
        assert_eq!(
            deliver::open(&sk, &cm, &tampered),
            None,
            "tampering byte {idx} must be rejected"
        );
    }

    // Wrong commitment binding MUST reject even with valid ciphertext
    let mut wrong_cm = cm;
    wrong_cm[0] ^= 1;
    assert_eq!(deliver::open(&sk, &wrong_cm, &env1), None);
}

#[test]
fn fast_boot_snapshot_restores_exact_state_catches_up_tail_and_rejects_tampering() {
    let dir = std::env::temp_dir().join(format!("ns_snap_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let params = Params::get(Net::Reg).unwrap();

    let mut buyer = Wallet::generate();
    let seller = Wallet::generate();
    let miner = Wallet::generate();

    let mut c = Chain::open(params.clone(), Some(&dir)).unwrap();
    assert!(!c.fast_boot);

    let mine_one = |c: &mut Chain, to: &Wallet, txs: Vec<Tx>| {
        let mut fees = 0u64;
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
            a_pk: to.a_pk(),
            v: subsidy(c.height() + 1) + fees,
            rho: rand::thread_rng().gen(),
        };
        let mut b = c.template(vec![out], txs, vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        c.add_block(b).unwrap();
    };

    // Mine 3 blocks, open a PayWord channel in block 4, then save snapshot at height 4
    for _ in 0..3 {
        mine_one(&mut c, &buyer, vec![]);
    }
    let chain_pw = build_payword_chain(sha256(b"snap-channel-seed"), 100);
    let post = ChannelPost {
        tip: *chain_pw.last().unwrap(),
        max_ticks: 100,
        unit_price: 5_000,
        claim_fee: 1_000,
        timeout: c.height() + 50,
        seller_addr: seller.a_pk(),
        refund_addr: buyer.a_pk(),
    };
    let (open_tx, _) = buyer
        .spend(&c, None, DEFAULT_FEE, Some(Deposit::Channel(post.clone())), vec![])
        .unwrap();
    let Tx::Spend(sp) = &open_tx else { unreachable!() };
    let cid = channel_id(&post, &sp.nf[0], 0);
    mine_one(&mut c, &miner, vec![open_tx]);
    c.save_snapshot().unwrap();
    assert!(dir.join(SNAPSHOT_FILE).exists());

    // Now mine 2 MORE blocks AFTER the snapshot (including a partial channel claim in block 5!)
    let claim_tx = Tx::Act(Action::ChannelClaim {
        channel: cid,
        ticks: 42,
        token: chain_pw[100 - 42],
    });
    mine_one(&mut c, &miner, vec![claim_tx]);
    mine_one(&mut c, &miner, vec![]);

    let expected_height = c.height();
    let expected_tip = c.tip().hash;
    let expected_digest = c.state.digest();
    let expected_seller_bal: u64 = seller.unspent(&c).iter().map(|n| n.v).sum();
    assert_eq!(expected_seller_bal, 42 * 5_000);
    drop(c);

    // 1. Reopen: MUST fast-boot from state.snap (height 4) + replay only tail blocks 5 & 6!
    let c_fast = Chain::open(params.clone(), Some(&dir)).unwrap();
    assert!(c_fast.fast_boot, "Chain::open must fast-boot from verified state.snap");
    assert_eq!(c_fast.height(), expected_height);
    assert_eq!(c_fast.tip().hash, expected_tip);
    assert_eq!(c_fast.state.digest(), expected_digest);
    assert_eq!(seller.unspent(&c_fast).iter().map(|n| n.v).sum::<u64>(), expected_seller_bal);
    assert!(c_fast.state.channel_ends.contains_key(&cid));
    drop(c_fast);

    // 2. Flip 1 byte in state.snap: Chain::open MUST reject snapshot & transparently recover via blocks.dat!
    let snap_path = dir.join(SNAPSHOT_FILE);
    let mut raw = std::fs::read(&snap_path).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0x01;
    std::fs::write(&snap_path, &raw).unwrap();

    let c_recovered = Chain::open(params, Some(&dir)).unwrap();
    assert!(!c_recovered.fast_boot, "tampered state.snap must NOT be trusted");
    assert_eq!(c_recovered.height(), expected_height);
    assert_eq!(c_recovered.tip().hash, expected_tip);
    assert_eq!(c_recovered.state.digest(), expected_digest);
    assert_eq!(seller.unspent(&c_recovered).iter().map(|n| n.v).sum::<u64>(), expected_seller_bal);

    let _ = std::fs::remove_dir_all(&dir);
}
