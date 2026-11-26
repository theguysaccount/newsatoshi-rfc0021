//! Zero-mock end-to-end integration tests for the Newsatoshi Verifiable Economic Clearinghouse
//! & Hyperscale L2 Substrate:
//!   - Selective Institutional Auditability (`deliver::viewing_key` `nsvk1…`)
//!   - RFC-0024 Universal Trust Bonds (post, Merkle proof via HTTP `/api/bond`, dual-signed
//!     anti-wash-trading attestation, timelocked unbond cooldown, Tier-1/Tier-2 permissionless
//!     equivocation slash paying victim a spendable shielded note, Tier-3 M-of-N quorum slash,
//!     and victim actually spending their slashed compensation note with a real STARK proof!)
//!   - RFC-0023 Sovereign L2 Rollup Vaults (1-tx L2 launch, shielded L1->L2 deposit, 100,000-tx
//!     batch settlement in ONE 128-bit pure-SHA-2 Winterfell STARK proof over live HTTP
//!     `POST /api/tx`, tampered batch rejection, trustless L2->L1 Merkle withdrawal, replay lock)
//!   - RFC-0026 Collective BIP-9 Version-Bits Signaling (`GET /api/signaling` & AuxPoW bit safety)
//!   - Snapshot round-trip (`state.snap` preserving bonds + rollups) & v0.1.0 height-gate safety.

use newsatoshi::bond::{self, BondPost};
use newsatoshi::chain::{mine, Chain};
use newsatoshi::deliver::{delivery_address, memo_for, parse_delivery_address, parse_viewing_key, viewing_key, Scanner};
use newsatoshi::hash::{sha256, words_to_bytes, Word8};
use newsatoshi::job::{Action, Deposit, JobKey};
use newsatoshi::merkmap::MerkleMap;
use newsatoshi::node::{Node, Shared};
use newsatoshi::note::{self, Rho};
use newsatoshi::params::{Net, Params, COIN};
use newsatoshi::rollup::{self, RollupBatchInputs, RollupPost};
use newsatoshi::rpc::{serve_public, J};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use newsatoshi::tx::{bind_of, PlainOut, Spend, Tx};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn http_req(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, J) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        s.write_all(body).unwrap();
    }
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]);
    let code: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let json = J::parse(&raw[split + 4..]).expect("valid json");
    (code, json)
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("ns-substrate-{name}-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn mine_txs(chain: &mut Chain, miner_apk: Word8, txs: Vec<Tx>, extra_fees: u64) {
    let h = chain.height() + 1;
    let total = newsatoshi::params::subsidy(h) + extra_fees;
    let out = PlainOut { a_pk: miner_apk, v: total, rho: rand::random() };
    let mut b = chain.template(vec![out], txs, vec![]).expect("template");
    assert!(mine(&mut b.header, u64::MAX));
    chain.add_block(b).expect("add_block");
}

fn spend_deposit(
    chain: &Chain,
    sk: Word8,
    in_v: u64,
    in_rho: Rho,
    in_pos: u32,
    fee: u64,
    deposit: Deposit,
) -> (Tx, OutputNote) {
    let a_pk = note::address(&sk);
    let dep_amt = deposit.checked_amount().unwrap();
    let change_v = in_v - fee - dep_amt;
    let out0 = OutputNote { a_pk, v: 0, rho: rand::random() };
    let out1 = OutputNote { a_pk, v: change_v, rho: rand::random() };
    let wit = SpendWitness {
        inputs: [
            InputNote { sk, v: in_v, rho: in_rho, pos: in_pos, path: chain.state.tree.path(in_pos) },
            InputNote::dummy(),
        ],
        outputs: [out0, out1.clone()],
        dummy: [false, true],
    };
    let bind = bind_of(fee, &Some(deposit.clone()), &[]);
    let (pi, proof) = spend::prove_for(&chain.params.proof, &wit, bind).unwrap();
    let tx = Tx::Spend(Spend {
        anchor: pi.root,
        nf: pi.nf,
        cm_out: pi.cm_out,
        dummy: [false, true],
        fee,
        deposit: Some(deposit),
        memo: vec![],
        proof: proof.to_bytes(),
    });
    (tx, out1)
}

#[test]
fn universal_trust_bond_sovereign_l2_rollup_signaling_and_viewing_key_e2e() {
    let dir = temp_dir("full");
    let params = Params::get(Net::Reg).unwrap();
    let mut chain = Chain::open(params.clone(), Some(&dir)).unwrap();

    let funder_sk: Word8 = [11u32; 8];
    let funder_apk = note::address(&funder_sk);
    let victim_sk: Word8 = [22u32; 8];
    let victim_apk = note::address(&victim_sk);
    let l2_user_sk: Word8 = [33u32; 8];
    let l2_user_apk = note::address(&l2_user_sk);

    // Mine 2 blocks so funder has a mature 50 LOVE coinbase note
    let cb1_rho: Rho = rand::random();
    let out1 = PlainOut { a_pk: funder_apk, v: 50 * COIN, rho: cb1_rho };
    let mut b1 = chain.template(vec![out1], vec![], vec![]).unwrap();
    assert!(mine(&mut b1.header, u64::MAX));
    chain.add_block(b1).unwrap();
    mine_txs(&mut chain, funder_apk, vec![], 0);
    let cm0 = note::commit(&funder_apk, 50 * COIN, &cb1_rho);
    let pos0 = chain.state.cm_pos[&cm0][0];

    // -------------------------------------------------------------------------
    // 1. Selective Auditability: read-only ViewingKey (nsvk1...) decrypts memo
    // -------------------------------------------------------------------------
    let vk_str = viewing_key(&victim_sk);
    let auditor = Scanner::from_viewing_key(&parse_viewing_key(&vk_str).unwrap()).unwrap();
    let (_, victim_ek) = parse_delivery_address(&delivery_address(&victim_sk)).unwrap();
    let dummy_out0 = OutputNote { a_pk: victim_apk, v: 42_000, rho: rand::random() };
    let dummy_out1 = OutputNote { a_pk: funder_apk, v: 10_000, rho: rand::random() };
    let memo = memo_for(&funder_sk, &[dummy_out0.clone(), dummy_out1], [Some(&victim_ek), None], b"audit-memo").unwrap();
    let (envs, text) = newsatoshi::deliver::unpack_memo(&memo);
    assert_eq!(text, b"audit-memo");
    let cm_aud = note::commit(&victim_apk, 42_000, &dummy_out0.rho);
    assert_eq!(auditor.open(&cm_aud, envs[0].unwrap()), Some((42_000, dummy_out0.rho)));

    // -------------------------------------------------------------------------
    // 2. RFC-0024: Universal Trust Bond (post, attest, equivocation slash, victim spend!)
    // -------------------------------------------------------------------------
    let owner_key = JobKey::derive(&words_to_bytes(&funder_sk));
    let client_key = JobKey::derive(&words_to_bytes(&victim_sk));
    let arb0 = JobKey::derive(&[101u8; 32]);
    let arb1 = JobKey::derive(&[102u8; 32]);
    let owner_vk: [u8; 32] = owner_key.vk().try_into().unwrap();
    let client_vk: [u8; 32] = client_key.vk().try_into().unwrap();
    let arb0_vk: [u8; 32] = arb0.vk().try_into().unwrap();
    let arb1_vk: [u8; 32] = arb1.vk().try_into().unwrap();

    let bond_post = BondPost {
        owner_vk,
        owner_addr: funder_apk,
        arbiter_vks: vec![arb0_vk, arb1_vk],
        quorum_m: 2,
        unbond_delay: 2,
        slash_burn_bps: 2_000, // 20% burned forever, 80% paid to victim
        stake: 10 * COIN,
        service_tag: sha256(b"zktls-fiat-ramp-and-ai-compute"),
    };
    let (tx_bond, ch1) = spend_deposit(&chain, funder_sk, 50 * COIN, cb1_rho, pos0, 300_000, Deposit::Bond(bond_post.clone()));
    let bond_nf = match &tx_bond { Tx::Spend(s) => s.nf[0], _ => unreachable!() };
    let bid = bond::bond_id(&bond_post, &bond_nf);
    mine_txs(&mut chain, funder_apk, vec![tx_bond], 300_000);
    assert_eq!(chain.state.bonds[&bid].post.stake, 10 * COIN);

    // -------------------------------------------------------------------------
    // 3. RFC-0023: Sovereign L2 Rollup Vault (1-tx deploy + deposit)
    // -------------------------------------------------------------------------
    let seq_key = JobKey::derive(&[200u8; 32]);
    let seq_vk: [u8; 32] = seq_key.vk().try_into().unwrap();
    let rollup_post = RollupPost {
        vk_hash: sha256(b"hyperscale-zk-clearinghouse-l2-v1"),
        genesis_root: sha256(b"l2-genesis-root-0"),
        sequencer_vk: Some(seq_vk),
        initial_tvl: 15 * COIN,
        name_tag: sha256(b"clearinghouse-l2"),
    };
    let ch1_cm = note::commit(&funder_apk, ch1.v, &ch1.rho);
    let ch1_pos = chain.state.cm_pos[&ch1_cm][0];
    let (tx_rollup, ch2) = spend_deposit(&chain, funder_sk, ch1.v, ch1.rho, ch1_pos, 300_000, Deposit::RollupRegister(rollup_post.clone()));
    let r_nf = match &tx_rollup { Tx::Spend(s) => s.nf[0], _ => unreachable!() };
    let rid = rollup::rollup_id(&rollup_post, &r_nf);
    mine_txs(&mut chain, funder_apk, vec![tx_rollup], 300_000);
    assert_eq!(chain.state.rollups[&rid].tvl, 15 * COIN);

    // Deposit another 5 LOVE from L1 shielded pool into the L2 Rollup Vault
    let ch2_cm = note::commit(&funder_apk, ch2.v, &ch2.rho);
    let ch2_pos = chain.state.cm_pos[&ch2_cm][0];
    let (tx_rdep, _ch3) = spend_deposit(
        &chain,
        funder_sk,
        ch2.v,
        ch2.rho,
        ch2_pos,
        300_000,
        Deposit::RollupDeposit { rollup: rid, l2_recipient: sha256(b"l2-user-acct"), amount: 5 * COIN },
    );
    mine_txs(&mut chain, funder_apk, vec![tx_rdep], 300_000);
    assert_eq!(chain.state.rollups[&rid].tvl, 20 * COIN);
    assert_eq!(chain.state.rollups[&rid].deposit_count, 1);

    // -------------------------------------------------------------------------
    // 4. Live HTTP RPC Server: submit Bond actions + 100,000-tx L2 STARK batch!
    // -------------------------------------------------------------------------
    let shared: Shared = Node::new(chain);
    let port = serve_public(shared.clone(), "127.0.0.1", 0, None).unwrap();

    // Verify GET /api/bond, GET /api/rollup, GET /api/state, GET /api/signaling
    let (c_b, jb) = http_req(port, "GET", &format!("/api/bond?id={}", hex::encode(bid)), &[]);
    assert_eq!(c_b, 200);
    assert_eq!(jb.get("found"), Some(&J::Bool(true)));
    let (c_r, jr) = http_req(port, "GET", &format!("/api/rollup?id={}", hex::encode(rid)), &[]);
    assert_eq!(c_r, 200);
    assert_eq!(jr.get("tvl"), Some(&J::num(20 * COIN)));
    let (c_s, js) = http_req(port, "GET", "/api/signaling", &[]);
    assert_eq!(c_s, 200);
    assert_eq!(js.get("ok"), Some(&J::Bool(true)));

    // Submit dual-signed BondAttest over HTTP POST /api/tx
    let receipt = sha256(b"zktls-wise-transfer-98765");
    let amsg = bond::attest_message(&bid, 0, &receipt, 2 * COIN, 10_000);
    let tx_attest = Tx::Act(Action::BondAttest {
        bond: bid,
        receipt_hash: receipt,
        settled_amount: 2 * COIN,
        fee: 10_000,
        owner_sig: owner_key.sign(&amsg),
        counterparty_vk: client_vk,
        counterparty_sig: client_key.sign(&amsg),
    });
    let (code, resp) = http_req(port, "POST", "/api/tx", &tx_attest.to_bytes());
    assert_eq!(code, 200, "attest failed: {}", resp.to_json());

    // Submit permissionless Tier-1/Tier-2 Equivocation Slash over HTTP POST /api/tx
    let pa = sha256(b"api-quote-a");
    let pb = sha256(b"api-quote-b");
    let tx_eq_slash = Tx::Act(Action::BondSlashEquivocation {
        bond: bid,
        context_nonce: 99,
        payload_a: pa,
        sig_a: owner_key.sign(&bond::commit_message(&bid, 99, &pa)),
        payload_b: pb,
        sig_b: owner_key.sign(&bond::commit_message(&bid, 99, &pb)),
        victim_addr: victim_apk,
        slash_amount: 2 * COIN + 10_000,
        miner_fee: 10_000,
    });
    let (code, resp) = http_req(port, "POST", "/api/tx", &tx_eq_slash.to_bytes());
    assert_eq!(code, 200, "equivocation slash failed: {}", resp.to_json());

    // Submit 100,000-tx Sovereign L2 Rollup Batch (128-bit pure-SHA-2 STARK!) over HTTP POST /api/tx
    let wdr_id = sha256(b"l2-exit-alice-001");
    let mut wmap = MerkleMap::new();
    wmap.insert(wdr_id, rollup::withdrawal_leaf_hash(&rid, 1, &wdr_id, &l2_user_apk, 4 * COIN));
    let wroot = wmap.root();
    let new_l2_root = sha256(b"l2-state-after-100000-agent-txs");
    let dep_acc = shared.lock().unwrap().chain.state.rollups[&rid].deposit_acc;
    let prev_l2_root = shared.lock().unwrap().chain.state.rollups[&rid].state_root;
    let batch_inputs = RollupBatchInputs {
        vk_hash: rollup_post.vk_hash,
        prev_state_root: prev_l2_root,
        new_state_root: new_l2_root,
        deposit_acc: dep_acc,
        withdraw_root: wroot,
        batch_seq: 1,
        batch_tx_count: 100_000,
        prev_tvl: 20 * COIN,
        new_tvl: 16 * COIN - 50_000,
        batch_withdrawals: 4 * COIN,
        batch_fee: 50_000,
    };
    let stark_proof = rollup::prove_batch(&batch_inputs).unwrap();
    let seq_sig = seq_key.sign(&rollup::batch_sig_message(&batch_inputs));

    // Tampered batch (inflated batch_tx_count) must be rejected with HTTP 400!
    let bad_batch = Tx::Act(Action::RollupBatch {
        rollup: rid,
        new_state_root: new_l2_root,
        withdraw_root: wroot,
        batch_tx_count: 100_001,
        batch_withdrawals: 4 * COIN,
        batch_fee: 50_000,
        sequencer_sig: seq_sig.clone(),
        proof: stark_proof.clone(),
    });
    let (bad_code, _) = http_req(port, "POST", "/api/tx", &bad_batch.to_bytes());
    assert_eq!(bad_code, 400, "tampered STARK batch must be rejected");

    // Honest 100,000-tx batch accepted over HTTP!
    let tx_batch = Tx::Act(Action::RollupBatch {
        rollup: rid,
        new_state_root: new_l2_root,
        withdraw_root: wroot,
        batch_tx_count: 100_000,
        batch_withdrawals: 4 * COIN,
        batch_fee: 50_000,
        sequencer_sig: seq_sig,
        proof: stark_proof,
    });
    let (code, resp) = http_req(port, "POST", "/api/tx", &tx_batch.to_bytes());
    assert_eq!(code, 200, "honest STARK batch failed: {}", resp.to_json());

    // Submit trustless L2 -> L1 Merkle withdrawal in the very same block!
    let mp = wmap.prove(&wdr_id).unwrap();
    let tx_wdr = Tx::Act(Action::RollupWithdraw {
        rollup: rid,
        batch_seq: 1,
        withdrawal_id: wdr_id,
        recipient_addr: l2_user_apk,
        amount: 4 * COIN,
        miner_fee: 10_000,
        proof: mp,
    });
    let (code, resp) = http_req(port, "POST", "/api/tx", &tx_wdr.to_bytes());
    assert_eq!(code, 200, "rollup withdraw failed: {}", resp.to_json());

    // Mine mempool into a real block using select_with_fees() (verifying exact miner fee payout!)
    {
        let mut n = shared.lock().unwrap();
        let (selected, fees) = n.select_with_fees();
        assert_eq!(selected.len(), 4);
        assert_eq!(fees, 10_000 + 10_000 + 50_000 + 10_000);
        let h = n.chain.height() + 1;
        let out = PlainOut {
            a_pk: funder_apk,
            v: newsatoshi::params::subsidy(h) + fees,
            rho: rand::random(),
        };
        let mut b = n.chain.template(vec![out], selected, vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        n.accept_block(b, None).unwrap();
    }

    // Verify post-block consensus state, victim spendable shielded note, and L2 user exit note!
    {
        let mut n = shared.lock().unwrap();
        let st = &n.chain.state;
        // Victim got 80% of 2 LOVE = 1.6 LOVE; 20% = 0.4 LOVE burned forever!
        let vnotes = &st.public_notes[&victim_apk];
        assert_eq!(vnotes.len(), 1);
        assert_eq!(vnotes[0].0, 160_000_000);
        assert_eq!(st.burned, 40_000_000);
        // L2 user exited 4 LOVE - 10,000 fee = 3.9999 LOVE privately on L1!
        let u_notes = &st.public_notes[&l2_user_apk];
        assert_eq!(u_notes.len(), 1);
        assert_eq!(u_notes[0].0, 4 * COIN - 10_000);
        assert_eq!(st.rollups[&rid].total_l2_txs, 100_000);
        assert_eq!(st.rollups[&rid].pending_withdrawals, 0);
        assert_eq!(st.rollups[&rid].tvl, 16 * COIN - 50_000);
        assert_eq!(st.bonds[&bid].settled_count, 1);
        assert_eq!(st.bonds[&bid].slash_count, 1);

        // Victim actually SPENDS their slashed compensation note with a real STARK spend proof!
        let (vv, vrho) = vnotes[0];
        let vcm = note::commit(&victim_apk, vv, &vrho);
        let vpos = st.cm_pos[&vcm][0];
        let out0 = OutputNote { a_pk: l2_user_apk, v: 100_000_000, rho: rand::random() };
        let out1 = OutputNote { a_pk: victim_apk, v: vv - 100_000_000 - 300_000, rho: rand::random() };
        let wit = SpendWitness {
            inputs: [
                InputNote { sk: victim_sk, v: vv, rho: vrho, pos: vpos, path: st.tree.path(vpos) },
                InputNote::dummy(),
            ],
            outputs: [out0, out1],
            dummy: [false, true],
        };
        let bind = bind_of(300_000, &None, &[]);
        let (pi, proof) = spend::prove_for(&n.chain.params.proof, &wit, bind).unwrap();
        let tx_vspend = Tx::Spend(Spend {
            anchor: pi.root,
            nf: pi.nf,
            cm_out: pi.cm_out,
            dummy: [false, true],
            fee: 300_000,
            deposit: None,
            memo: vec![],
            proof: proof.to_bytes(),
        });
        mine_txs(&mut n.chain, funder_apk, vec![tx_vspend], 300_000);

        // Exact snapshot persistence round-trip preserves bonds + rollups + exact state digest!
        let expected_digest = n.chain.state.digest();
        n.chain.save_snapshot().unwrap();
        let reopened = Chain::open(params, Some(&dir)).unwrap();
        assert_eq!(reopened.state.digest(), expected_digest);
        assert_eq!(reopened.state.bonds[&bid].slash_count, 1);
        assert_eq!(reopened.state.rollups[&rid].total_l2_txs, 100_000);
    }

    // Verify v0.1.0 Mainnet height gate rejects RFC-0023 / RFC-0024 / RFC-0027 when inactive (`None`)
    let v1_main = Params::main_with(1_794_268_800, 0);
    assert_eq!(v1_main.rfc0023_from, None);
    assert_eq!(v1_main.rfc0024_from, None);
    assert_eq!(v1_main.rfc0027_from, None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pequalnp_style_mission_launchpad_bonding_curve_and_bonded_agent_swarm_e2e() {
    use newsatoshi::mission::{self, MissionPost};

    let dir = temp_dir("launchpad");
    let params = Params::get(Net::Reg).unwrap();
    let mut chain = Chain::open(params.clone(), Some(&dir)).unwrap();

    let founder_sk: Word8 = [10u32; 8];
    let founder_apk = note::address(&founder_sk);
    let agent_sk: Word8 = [20u32; 8];
    let agent_apk = note::address(&agent_sk);
    let lean_fro_apk = note::address(&[30u32; 8]);

    let cb_rho: Rho = rand::random();
    let out1 = PlainOut { a_pk: founder_apk, v: 50 * COIN, rho: cb_rho };
    let mut b1 = chain.template(vec![out1], vec![], vec![]).unwrap();
    assert!(mine(&mut b1.header, u64::MAX));
    chain.add_block(b1).unwrap();
    mine_txs(&mut chain, founder_apk, vec![], 0);
    let cm0 = note::commit(&founder_apk, 50 * COIN, &cb_rho);
    let pos0 = chain.state.cm_pos[&cm0][0];

    let orch = JobKey::derive(&[51u8; 32]);
    let checker0 = JobKey::derive(&[52u8; 32]);
    let checker1 = JobKey::derive(&[53u8; 32]);
    let trader = JobKey::derive(&[54u8; 32]);
    let trader_vk: [u8; 32] = trader.vk().try_into().unwrap();
    let agent_key = JobKey::derive(&words_to_bytes(&agent_sk));
    let agent_vk: [u8; 32] = agent_key.vk().try_into().unwrap();

    // 1. Agent posts an RFC-0024 Trust Bond (1 LOVE) so anti-Sybil min_worker_bond passes
    let bond_post = BondPost {
        owner_vk: agent_vk,
        owner_addr: agent_apk,
        arbiter_vks: vec![],
        quorum_m: 0,
        unbond_delay: 5,
        slash_burn_bps: 2_000,
        stake: 1 * COIN,
        service_tag: sha256(b"lean4-prover-agent"),
    };
    let (tx_bond, ch1) = spend_deposit(&chain, founder_sk, 50 * COIN, cb_rho, pos0, 300_000, Deposit::Bond(bond_post.clone()));
    let b_nf = match &tx_bond { Tx::Spend(s) => s.nf[0], _ => unreachable!() };
    let bid = bond::bond_id(&bond_post, &b_nf);
    mine_txs(&mut chain, founder_apk, vec![tx_bond], 300_000);

    // 2. Launch a pequalnp.money-style Mission Launchpad in 1 tx (80% contributor / 20% Lean FRO, 5% trade fee -> bounty pool!)
    let mpost = MissionPost {
        orchestrator_vk: orch.vk().try_into().unwrap(),
        verifier_vks: vec![checker0.vk().try_into().unwrap(), checker1.vk().try_into().unwrap()],
        verifier_quorum_m: 2,
        public_goods_addr: lean_fro_apk,
        public_goods_bps: 2_000, // 20% Lean FRO, 80% outside verified contributor
        curve_fee_bps: 500,      // 5% on every bonding-curve buy/sell feeds verified-work bounties!
        initial_funding: 2 * COIN,
        min_worker_bond: 1 * COIN,
        mission_hash: sha256(b"pequalnp-open-lean4-swarm"),
    };
    let ch1_cm = note::commit(&founder_apk, ch1.v, &ch1.rho);
    let ch1_pos = chain.state.cm_pos[&ch1_cm][0];
    let (tx_launch, ch2) = spend_deposit(&chain, founder_sk, ch1.v, ch1.rho, ch1_pos, 300_000, Deposit::MissionLaunch(mpost.clone()));
    let m_nf = match &tx_launch { Tx::Spend(s) => s.nf[0], _ => unreachable!() };
    let mid = mission::mission_id(&mpost, &m_nf);
    mine_txs(&mut chain, founder_apk, vec![tx_launch], 300_000);

    // 3. Launchpad buyer puts 20 LOVE into bonding curve -> 1 LOVE (5%) automatically feeds bounty_pool!
    let ch2_cm = note::commit(&founder_apk, ch2.v, &ch2.rho);
    let ch2_pos = chain.state.cm_pos[&ch2_cm][0];
    let (tx_buy, _ch3) = spend_deposit(
        &chain,
        founder_sk,
        ch2.v,
        ch2.rho,
        ch2_pos,
        300_000,
        Deposit::MissionFund { mission: mid, holder_vk: trader_vk, amount: 20 * COIN, direct_to_bounty: false },
    );
    mine_txs(&mut chain, founder_apk, vec![tx_buy], 300_000);
    assert_eq!(chain.state.missions[&mid].bounty_pool, 3 * COIN);
    assert_eq!(chain.state.missions[&mid].curve_reserve, 19 * COIN);

    // 4. Live HTTP RPC: GET /api/mission + post lemma + verified 80/20 claim + bonding-curve redeem!
    let shared: Shared = Node::new(chain);
    let port = serve_public(shared.clone(), "127.0.0.1", 0, None).unwrap();
    let (code, jm) = http_req(port, "GET", &format!("/api/mission?id={}", hex::encode(mid)), &[]);
    assert_eq!(code, 200);
    assert_eq!(jm.get("found"), Some(&J::Bool(true)));
    assert_eq!(jm.get("bounty_pool"), Some(&J::num(3 * COIN)));

    let spec = sha256(b"lemma-circuit-lower-bound.lean");
    let reward = 2 * COIN + 10_000;
    let tx_task = Tx::Act(Action::MissionPostTask {
        mission: mid,
        task_id: 1,
        spec_hash: spec,
        reward,
        sig: orch.sign(&mission::post_task_message(&mid, 1, &spec, reward)),
    });
    assert_eq!(http_req(port, "POST", "/api/tx", &tx_task.to_bytes()).0, 200);

    // Unbonded Sybil claim MUST be rejected!
    let proof_hash = sha256(b"lean4-verified-0-sorry-commit");
    let cmsg = mission::claim_task_message(&mid, 1, &spec, &proof_hash, &agent_apk, 10_000);
    let vsigs = vec![(0, checker0.sign(&cmsg)), (1, checker1.sign(&cmsg))];
    let sybil_claim = Tx::Act(Action::MissionClaimTask {
        mission: mid,
        task_id: 1,
        proof_hash,
        contributor_addr: agent_apk,
        contributor_bond_id: None,
        miner_fee: 10_000,
        verifier_sigs: vsigs.clone(),
    });
    assert_eq!(http_req(port, "POST", "/api/tx", &sybil_claim.to_bytes()).0, 400);

    // Bonded agent claim succeeds -> 1.6 LOVE to agent, 0.4 LOVE to Lean FRO!
    let bonded_claim = Tx::Act(Action::MissionClaimTask {
        mission: mid,
        task_id: 1,
        proof_hash,
        contributor_addr: agent_apk,
        contributor_bond_id: Some(bid),
        miner_fee: 10_000,
        verifier_sigs: vsigs,
    });
    assert_eq!(http_req(port, "POST", "/api/tx", &bonded_claim.to_bytes()).0, 200);

    // Mine block & check exact 80/20 shielded payouts + snapshot persistence!
    {
        let mut n = shared.lock().unwrap();
        let (selected, fees) = n.select_with_fees();
        assert_eq!(selected.len(), 2);
        assert_eq!(fees, 10_000);
        let h = n.chain.height() + 1;
        let out = PlainOut { a_pk: founder_apk, v: newsatoshi::params::subsidy(h) + fees, rho: rand::random() };
        let mut b = n.chain.template(vec![out], selected, vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        n.accept_block(b, None).unwrap();

        assert_eq!(n.chain.state.public_notes[&agent_apk][0].0, 160_000_000); // 80% outside contributor
        assert_eq!(n.chain.state.public_notes[&lean_fro_apk][0].0, 40_000_000); // 20% Lean FRO
        assert_eq!(n.chain.state.missions[&mid].completed_tasks, 1);

        let expected = n.chain.state.digest();
        n.chain.save_snapshot().unwrap();
        let reopened = Chain::open(params, Some(&dir)).unwrap();
        assert_eq!(reopened.state.digest(), expected);
        assert_eq!(reopened.state.missions[&mid].completed_tasks, 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn permissionless_zero_sequencer_l2_zkvm_onchain_stark_settlement_e2e() {
    use newsatoshi::zkvm::{compile_l2_program, prove_zkvm_execution, state_slots_root, ZkVmShard};

    let dir = temp_dir("perm-zkvm");
    let params = Params::get(Net::Reg).unwrap();
    let mut chain = Chain::open(params.clone(), Some(&dir)).unwrap();

    let funder_sk: Word8 = [41u32; 8];
    let funder_apk = note::address(&funder_sk);
    let alice_apk = note::address(&[42u32; 8]);
    let bob_apk = note::address(&[43u32; 8]);

    let cb_rho: Rho = rand::random();
    let out1 = PlainOut { a_pk: funder_apk, v: 50 * COIN, rho: cb_rho };
    let mut b1 = chain.template(vec![out1], vec![], vec![]).unwrap();
    assert!(mine(&mut b1.header, u64::MAX));
    chain.add_block(b1).unwrap();
    mine_txs(&mut chain, funder_apk, vec![], 0);
    let cm0 = note::commit(&funder_apk, 50 * COIN, &cb_rho);
    let pos0 = chain.state.cm_pos[&cm0][0];

    // Compile a deterministic L2 withdrawal + transfer program; pin its exact `program_hash`
    // as `vk_hash` on a 100% PERMISSIONLESS (`sequencer_vk: None`) L1 RollupVault!
    let prog = compile_l2_program(
        r#"
        LOAD_STATE r0, s0
        LOAD_CONST r1, 10000000
        SUB r0, r0, r1
        STORE_STATE s0, r0
        EMIT_WITHDRAW r1
        HALT
        "#,
    )
    .unwrap();

    let init_slots = [100_000_000, 50_000_000, 0, 0];
    let genesis_root = state_slots_root(&init_slots);
    let rpost = RollupPost {
        vk_hash: prog.program_hash,
        genesis_root,
        sequencer_vk: None, // ZERO SEQUENCER — 100% permissionless & L1 STARK-enforced!
        initial_tvl: 150_000_000,
        name_tag: sha256(b"permissionless-l2-zkvm"),
    };
    let (tx_reg, _ch1) = spend_deposit(
        &chain,
        funder_sk,
        50 * COIN,
        cb_rho,
        pos0,
        300_000,
        Deposit::RollupRegister(rpost.clone()),
    );
    let r_nf = match &tx_reg { Tx::Spend(s) => s.nf[0], _ => unreachable!() };
    let rid = rollup::rollup_id(&rpost, &r_nf);
    mine_txs(&mut chain, funder_apk, vec![tx_reg], 300_000);

    // Prove TWO contiguous L2 zkVM shards (128-bit pure-SHA-2 Winterfell STARKs!)
    let s1 = prove_zkvm_execution(&prog, init_slots).unwrap();
    let s2 = prove_zkvm_execution(&prog, s1.pub_inputs.final_slots).unwrap();
    assert_eq!(s2.pub_inputs.final_slots, [80_000_000, 50_000_000, 0, 0]);

    let w1_id = sha256(b"perm-zkvm-exit-1");
    let w2_id = sha256(b"perm-zkvm-exit-2");
    let mut wmap = MerkleMap::new();
    wmap.insert(w1_id, rollup::withdrawal_leaf_hash(&rid, 1, &w1_id, &alice_apk, 10_000_000));
    wmap.insert(w2_id, rollup::withdrawal_leaf_hash(&rid, 1, &w2_id, &bob_apk, 10_000_000));
    let wroot = wmap.root();

    let shared: Shared = Node::new(chain);
    let port = serve_public(shared.clone(), "127.0.0.1", 0, None).unwrap();

    // 1. ATTACK: Submitting a DIFFERENT compiled program's valid STARK proof MUST be rejected HTTP 400!
    let evil_prog = compile_l2_program(
        "LOAD_STATE r0, s0\nLOAD_CONST r1, 90000000\nSUB r0, r0, r1\nSTORE_STATE s0, r0\nEMIT_WITHDRAW r1\nHALT",
    )
    .unwrap();
    let evil_shard = prove_zkvm_execution(&evil_prog, init_slots).unwrap();
    let evil_tx = Tx::Act(Action::RollupZkVmBatch {
        rollup: rid,
        withdraw_root: wroot,
        batch_fee: 10_000,
        sequencer_sig: vec![],
        shards: vec![ZkVmShard { pub_inputs: evil_shard.pub_inputs, proof: evil_shard.proof_bytes }],
    });
    assert_eq!(
        http_req(port, "POST", "/api/tx", &evil_tx.to_bytes()).0,
        400,
        "wrong L2 program_hash MUST be rejected on L1"
    );

    // 2. ATTACK: Bit-flipping 1 byte inside an honest shard's STARK proof MUST be rejected HTTP 400!
    let mut tampered_proof = s1.proof_bytes.clone();
    tampered_proof[200] ^= 0x80;
    let tampered_tx = Tx::Act(Action::RollupZkVmBatch {
        rollup: rid,
        withdraw_root: wroot,
        batch_fee: 10_000,
        sequencer_sig: vec![],
        shards: vec![ZkVmShard { pub_inputs: s1.pub_inputs.clone(), proof: tampered_proof }],
    });
    assert_eq!(
        http_req(port, "POST", "/api/tx", &tampered_tx.to_bytes()).0,
        400,
        "tampered zkVM STARK MUST be rejected on L1"
    );

    // 3. HONEST: Submit BOTH contiguous 128-bit zkVM STARK shards directly over HTTP POST /api/tx (ZERO sequencer sig!)
    let honest_tx = Tx::Act(Action::RollupZkVmBatch {
        rollup: rid,
        withdraw_root: wroot,
        batch_fee: 25_000,
        sequencer_sig: vec![],
        shards: vec![
            ZkVmShard { pub_inputs: s1.pub_inputs, proof: s1.proof_bytes },
            ZkVmShard { pub_inputs: s2.pub_inputs.clone(), proof: s2.proof_bytes },
        ],
    });
    let (code, resp) = http_req(port, "POST", "/api/tx", &honest_tx.to_bytes());
    assert_eq!(code, 200, "honest permissionless 2-shard zkVM batch failed: {}", resp.to_json());

    // Submit both Alice & Bob trustless Merkle withdrawals in the same block!
    for (wid, addr) in [(w1_id, alice_apk), (w2_id, bob_apk)] {
        let tx_w = Tx::Act(Action::RollupWithdraw {
            rollup: rid,
            batch_seq: 1,
            withdrawal_id: wid,
            recipient_addr: addr,
            amount: 10_000_000,
            miner_fee: 1_000,
            proof: wmap.prove(&wid).unwrap(),
        });
        assert_eq!(http_req(port, "POST", "/api/tx", &tx_w.to_bytes()).0, 200);
    }

    // Mine block and verify L1 consensus state, TVL conservation, and shielded exits!
    {
        let mut n = shared.lock().unwrap();
        let (selected, fees) = n.select_with_fees();
        assert_eq!(selected.len(), 3);
        assert_eq!(fees, 25_000 + 1_000 + 1_000);
        let h = n.chain.height() + 1;
        let out = PlainOut { a_pk: funder_apk, v: newsatoshi::params::subsidy(h) + fees, rho: rand::random() };
        let mut b = n.chain.template(vec![out], selected, vec![]).unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        n.accept_block(b, None).unwrap();

        let rv = &n.chain.state.rollups[&rid];
        assert_eq!(rv.state_root, s2.pub_inputs.new_state_root);
        assert_eq!(rv.tvl, 150_000_000 - 20_000_000 - 25_000);
        assert_eq!(rv.pending_withdrawals, 0);
        assert_eq!(n.chain.state.public_notes[&alice_apk][0].0, 9_999_000);
        assert_eq!(n.chain.state.public_notes[&bob_apk][0].0, 9_999_000);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
