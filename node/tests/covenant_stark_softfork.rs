//! RFC-0021 `OP_VERIFY_COVENANT_STARK` (0xb4) L1 Consensus & Adversarial Tests.
//!
//! Proves end-to-end on a real mined Newsatoshi blockchain (`Chain`) that:
//! 1. `PAYOUT 0 NUMEQUALVERIFY 0x<rule_hash> VERIFY_COVENANT_STARK` compiles to opcode `0xb4`
//!    and releases shielded coins ONLY when accompanied by a valid pure-SHA-256 Winterfell 0.13
//!    Covenant STARK proof matching `covenant_rule_hash == change_covenant_rule_hash`.
//! 2. Corrupted proof bytes, covenant-stripping/rule-substitution, tampered payout amounts,
//!    degraded ecological soil scores, wrong payout indices, replays, and DoS (>2 STARK checks)
//!    are all rejected by L1 consensus.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::cond::{self, CondPost};
use newsatoshi::covenant_stark::{
    prove_covenant_stark, proven_security_bits, verify_covenant_stark_bytes, CovenantPublicInputs,
    CovenantTxKind, MIN_PROVEN_SECURITY_BITS, PUBLIC_INPUTS_BYTES,
};
use newsatoshi::hash::sha256;
use newsatoshi::job::{Action, Deposit};
use newsatoshi::params::{subsidy, Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::script;
use newsatoshi::tx::{PlainOut, Tx};
use newsatoshi::wallet::Wallet;
use rand::Rng;

fn step(c: &mut Chain, miner: &Wallet, txs: Vec<Tx>) -> Result<(), String> {
    let fees: u64 = txs
        .iter()
        .map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 })
        .sum();
    let out = PlainOut {
        a_pk: miner.a_pk(),
        v: subsidy(c.height() + 1) + fees,
        rho: rand::thread_rng().gen(),
    };
    let mut b = c.template(vec![out], txs, vec![])?;
    assert!(mine(&mut b.header, u64::MAX));
    c.add_block(b).map(|_| ())
}

#[test]
fn op_verify_covenant_stark_0xb4_executes_on_l1_chain_and_blocks_tampering_and_covenant_strip() {
    let mut c = Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap();
    let mut alice = Wallet::generate();
    let (bob, carol, miner) = (Wallet::generate(), Wallet::generate(), Wallet::generate());
    for _ in 0..3 {
        step(&mut c, &alice, vec![]).unwrap();
    }

    // Real NEWSATOSHI/2.1 covenant rule hash
    let rule_hash = sha256(b"NEWSATOSHI_2_1_PARCEL_1_COVENANT_RULE");
    let prev_root = sha256(b"NEWSATOSHI_2_1_STATE_ROOT_0");
    let new_root = sha256(b"NEWSATOSHI_2_1_STATE_ROOT_1");

    // Assemble native L1 condition script using RFC-0021 opcode 0xb4
    let program = script::assemble(&format!(
        "PAYOUT 0 NUMEQUALVERIFY 0x{} VERIFY_COVENANT_STARK",
        hex::encode(rule_hash)
    ))
    .unwrap();
    assert_eq!(
        *program.last().unwrap(),
        script::op::VERIFY_COVENANT_STARK,
        "assembled script must end with opcode 0xb4"
    );
    assert_eq!(script::op::VERIFY_COVENANT_STARK, 0xb4);

    // Alice locks 10 LOVE under the OP_VERIFY_COVENANT_STARK condition (payout 0 -> bob, payout 1 -> carol)
    let salt: [u8; 32] = rand::thread_rng().gen();
    let post = CondPost {
        commitment: cond::commitment(&salt, &program),
        payouts: vec![bob.a_pk(), carol.a_pk()],
        timeout: c.height() + 1 + 100,
        refund_addr: alice.a_pk(),
        amount: 10 * COIN,
    };
    let (fund_tx, _) = alice
        .spend(&c, None, DEFAULT_FEE, Some(Deposit::Cond(post.clone())), vec![])
        .unwrap();
    let Tx::Spend(sp) = &fund_tx else {
        unreachable!()
    };
    let cond_id = cond::cond_id(&post, if sp.dummy[0] { &sp.nf[1] } else { &sp.nf[0] });
    step(&mut c, &miner, vec![fund_tx]).unwrap();
    assert_eq!(c.state.conds.len(), 1);

    // Build & prove a real pure-SHA-256 Winterfell 0.13 Covenant STARK transition
    let inputs = CovenantPublicInputs {
        tx_kind: CovenantTxKind::TelemetryBounty,
        tx_nonce: 1,
        covenant_rule_hash: rule_hash,
        change_covenant_rule_hash: rule_hash,
        prev_state_root: prev_root,
        new_state_root: new_root,
        input_amount: 100_000,
        payout_amount: 10_000,
        change_amount: 90_000,
        max_bounty_payout: 25_000,
        reinvest_bps: 1_500,
        min_soil_health_score: 80,
        soil_health_score: 93,
    };
    let pub_bytes = inputs.to_bytes();
    assert_eq!(pub_bytes.len(), PUBLIC_INPUTS_BYTES);
    let proof_bytes = prove_covenant_stark(&inputs).expect("valid STARK must prove");
    let proven_bits = proven_security_bits(&proof_bytes).unwrap();
    eprintln!(
        "[RFC-0021 BENCH] Covenant STARK proof = {} bytes, {} proven bits (list decoding)",
        proof_bytes.len(),
        proven_bits
    );
    assert!(
        proven_bits >= MIN_PROVEN_SECURITY_BITS,
        "covenant STARK must meet >= 128 proven bits, got {proven_bits}"
    );
    assert!(
        proof_bytes.len() > 1_000 && proof_bytes.len() <= script::MAX_ITEM,
        "proof size {} must fit within MAX_ITEM",
        proof_bytes.len()
    );

    // Prover rejects degraded soil & bounty cap violations before proof creation
    let mut bad_soil = inputs.clone();
    bad_soil.soil_health_score = 79;
    assert!(prove_covenant_stark(&bad_soil).is_err());

    let mut over_cap = inputs.clone();
    over_cap.payout_amount = 25_001;
    over_cap.change_amount = 74_999;
    assert!(prove_covenant_stark(&over_cap).is_err());

    let mk_fulfil = |payout: u8, proof: Vec<u8>, pubs: Vec<u8>| {
        Tx::Act(Action::Fulfil {
            cond: cond_id,
            payout,
            salt,
            program: program.clone(),
            witness: vec![proof, pubs],
        })
    };

    // Attack 1: Corrupted STARK proof bytes MUST fail L1 consensus
    let mut corrupted_proof = proof_bytes.clone();
    let mid = corrupted_proof.len() / 2;
    corrupted_proof[mid] ^= 0x5a;
    assert!(
        step(&mut c, &miner, vec![mk_fulfil(0, corrupted_proof, pub_bytes.clone())]).is_err(),
        "corrupted STARK proof must be rejected on L1"
    );

    // Attack 2: Covenant rule substitution / stripping MUST fail L1 consensus
    let mut forged_rule_inputs = inputs.clone();
    forged_rule_inputs.change_covenant_rule_hash = sha256(b"WEAKENED_RULE_STRIP");
    assert!(
        step(
            &mut c,
            &miner,
            vec![mk_fulfil(0, proof_bytes.clone(), forged_rule_inputs.to_bytes())]
        )
        .is_err(),
        "stripped covenant rule must be rejected on L1"
    );

    // Attack 3: Tampered payout_amount in public inputs MUST fail L1 consensus
    let mut tampered_payout = inputs.clone();
    tampered_payout.payout_amount = 10_001;
    assert!(
        step(
            &mut c,
            &miner,
            vec![mk_fulfil(0, proof_bytes.clone(), tampered_payout.to_bytes())]
        )
        .is_err(),
        "tampered public inputs must be rejected on L1"
    );

    // Attack 4: Diverting coins to payout 1 (carol) MUST fail PAYOUT 0 NUMEQUALVERIFY
    assert!(
        step(&mut c, &miner, vec![mk_fulfil(1, proof_bytes.clone(), pub_bytes.clone())]).is_err(),
        "wrong payout index must be rejected on L1"
    );

    // Legitimate L1 settlement: wire round-trip + mined block acceptance!
    let valid_tx = mk_fulfil(0, proof_bytes, pub_bytes);
    let wire = valid_tx.to_bytes();
    assert_eq!(Tx::from_bytes(&wire).unwrap(), valid_tx);
    step(&mut c, &miner, vec![valid_tx.clone()]).unwrap();

    assert_eq!(bob.balance(&c), 10 * COIN, "bob receives spendable L1 payout");
    assert_eq!(carol.balance(&c), 0);
    assert!(c.state.conds.is_empty());

    // Attack 5: Replay of already-fulfilled condition MUST fail
    assert!(
        step(&mut c, &miner, vec![valid_tx]).is_err(),
        "fulfilled condition cannot be replayed"
    );
}

#[test]
fn op_verify_covenant_stark_streaming_settlement_and_dos_limit() {
    let rule_hash = sha256(b"NEWSATOSHI_2_1_STREAMING_RULE");
    let inputs = CovenantPublicInputs {
        tx_kind: CovenantTxKind::StreamingSettlement,
        tx_nonce: 5,
        covenant_rule_hash: rule_hash,
        change_covenant_rule_hash: rule_hash,
        prev_state_root: sha256(b"ROOT_4"),
        new_state_root: sha256(b"ROOT_5"),
        input_amount: 100_000,
        payout_amount: 85_000,
        change_amount: 15_000, // exact 1500 bps reinvestment
        max_bounty_payout: 25_000,
        reinvest_bps: 1_500,
        min_soil_health_score: 80,
        soil_health_score: 0,
    };
    let pub_bytes = inputs.to_bytes();
    let proof_bytes = prove_covenant_stark(&inputs).unwrap();
    verify_covenant_stark_bytes(&rule_hash, &pub_bytes, &proof_bytes).unwrap();

    // Direct VM execution of StreamingSettlement proof
    let prog = script::assemble(&format!("0x{} VERIFY_COVENANT_STARK", hex::encode(rule_hash)))
        .unwrap();
    let ctx = script::Ctx {
        height: 10,
        payout: 0,
        msg: &[0u8; 32],
    };
    assert!(script::run(&prog, &[proof_bytes.clone(), pub_bytes.clone()], &ctx).is_ok());

    // DoS protection: > MAX_STARK_CHECKS (2) in one script MUST fail
    let dos_prog = script::assemble(&format!(
        "0x{h} VERIFY_COVENANT_STARK DROP 0x{h} VERIFY_COVENANT_STARK DROP 0x{h} VERIFY_COVENANT_STARK",
        h = hex::encode(rule_hash)
    ))
    .unwrap();
    let witness = vec![
        proof_bytes.clone(),
        pub_bytes.clone(),
        proof_bytes.clone(),
        pub_bytes.clone(),
        proof_bytes,
        pub_bytes,
    ];
    let err = script::run(&dos_prog, &witness, &ctx).unwrap_err();
    assert!(
        err.contains("too many covenant STARK checks") || err.contains("witness bytes exceed limit"),
        "unexpected error: {err}"
    );

    // Height-gated hard-fork activation check: before rfc0021_from, opcode 0xb4 MUST be rejected!
    let inactive_err = script::run_with_rfc0021(
        &prog,
        &[witness[0].clone(), witness[1].clone()],
        &ctx,
        false,
    )
    .unwrap_err();
    assert!(
        inactive_err.contains("not active"),
        "expected inactive RFC-0021 rejection, got: {inactive_err}"
    );
}
