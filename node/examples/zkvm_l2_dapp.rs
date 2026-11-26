//! End-to-End L2 zkVM dApp Compiler, 128-Bit Pure-SHA-2 STARK Prover & RFC-0023 Aggregator Demo.
//!
//! Run:
//!   cargo run --release --example zkvm_l2_dapp

use newsatoshi::hash::sha256;
use newsatoshi::merkmap::MerkleMap;
use newsatoshi::rollup::{withdrawal_leaf_hash, RollupPost, rollup_id};
use newsatoshi::zkvm::{aggregate_shards_to_l1_batch, compile_l2_program, prove_zkvm_execution};
use std::time::Instant;

fn main() {
    let t0 = Instant::now();

    // Shard 1: Shielded L2 AMM Swap + Transfer + 10,000,000 base-unit withdrawal
    let prog1 = compile_l2_program(
        r#"
        LOAD_STATE r0, s0
        LOAD_CONST r1, 25000000
        SUB r0, r0, r1
        STORE_STATE s0, r0
        LOAD_STATE r2, s1
        ADD r2, r2, r1
        STORE_STATE s1, r2
        ASSERT_EQ r0, r2
        LOAD_CONST r3, 10000000
        SUB r0, r0, r3
        STORE_STATE s0, r0
        EMIT_WITHDRAW r3
        HALT
        "#,
    )
    .expect("compile shard 1");

    let s1_t = Instant::now();
    let shard1 = prove_zkvm_execution(&prog1, [100_000_000, 50_000_000, 0, 0]).expect("prove shard 1");
    let s1_ms = s1_t.elapsed().as_millis();

    // Shard 2: Chains off shard1.final_slots, verifies product invariant, emits 15,000,000 withdrawal
    let prog2 = compile_l2_program(
        r#"
        LOAD_STATE r0, s1
        LOAD_CONST r1, 15000000
        SUB r0, r0, r1
        STORE_STATE s1, r0
        LOAD_CONST r2, 3
        LOAD_CONST r3, 20000000
        MUL r2, r2, r3
        ASSERT_EQ r0, r2
        EMIT_WITHDRAW r1
        HALT
        "#,
    )
    .expect("compile shard 2");

    let s2_t = Instant::now();
    let shard2 = prove_zkvm_execution(&prog2, shard1.pub_inputs.final_slots).expect("prove shard 2");
    let s2_ms = s2_t.elapsed().as_millis();

    let vk_hash = sha256(b"newsatoshi-general-zkvm-v1");
    let post = RollupPost {
        vk_hash,
        genesis_root: shard1.pub_inputs.prev_state_root,
        sequencer_vk: None,
        initial_tvl: 150_000_000,
        name_tag: sha256(b"zkvm-demo-l2"),
    };
    let rid = rollup_id(&post, &[1u32; 8]);
    let w1 = sha256(b"alice-exit");
    let w2 = sha256(b"bob-exit");
    let mut wmap = MerkleMap::new();
    wmap.insert(w1, withdrawal_leaf_hash(&rid, 1, &w1, &[1u32; 8], 10_000_000));
    wmap.insert(w2, withdrawal_leaf_hash(&rid, 1, &w2, &[2u32; 8], 15_000_000));

    let agg_t = Instant::now();
    let agg = aggregate_shards_to_l1_batch(
        vk_hash,
        &[shard1.clone(), shard2.clone()],
        [0u8; 32],
        wmap.root(),
        1,
        150_000_000,
        50_000,
    )
    .expect("aggregate shards");
    let agg_ms = agg_t.elapsed().as_millis();

    println!(
        "{{\n  \"ok\": true,\n  \"shard1_proof_bytes\": {},\n  \"shard1_proven_bits\": {},\n  \"shard1_ms\": {},\n  \"shard2_proof_bytes\": {},\n  \"shard2_proven_bits\": {},\n  \"shard2_ms\": {},\n  \"aggregated_shards\": {},\n  \"total_vm_steps\": {},\n  \"l1_batch_proof_bytes\": {},\n  \"l1_batch_proven_bits\": {},\n  \"aggregate_and_prove_l1_ms\": {},\n  \"total_elapsed_ms\": {},\n  \"final_l2_slots\": {:?},\n  \"batch_withdrawals\": {},\n  \"new_tvl\": {}\n}}",
        shard1.proof_bytes.len(),
        shard1.proven_bits,
        s1_ms,
        shard2.proof_bytes.len(),
        shard2.proven_bits,
        s2_ms,
        agg.shards_verified,
        agg.total_vm_steps,
        agg.l1_stark_proof.len(),
        agg.l1_proven_bits,
        agg_ms,
        t0.elapsed().as_millis(),
        shard2.pub_inputs.final_slots,
        agg.l1_inputs.batch_withdrawals,
        agg.l1_inputs.new_tvl,
    );
}
