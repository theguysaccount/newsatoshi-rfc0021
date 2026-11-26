#![no_main]
use libfuzzer_sys::fuzz_target;
use newsatoshi::codec::Reader;
use newsatoshi::rollup::{verify_batch_proof, RollupBatchInputs};
use newsatoshi::spend::{self, SpendPublic};
use newsatoshi::zkvm::{verify_zkvm_execution, ZkVmPublicInputs, ZkVmShard};

fuzz_target!(|data: &[u8]| {
    // Hostile STARK / zkVM proof bytes MUST be cleanly rejected without panicking or excessive allocation.
    let pi = SpendPublic {
        root: [0; 8],
        nf: [[1; 8], [2; 8]],
        cm_out: [[3; 8], [4; 8]],
        value_balance: 0,
        dummy: [false, true],
        bind: [5; 8],
    };
    let _ = spend::verify_bytes_for(&spend::MAIN_V2, &pi, data);
    let _ = spend::verify_bytes_for(&spend::TEST, &pi, data);

    let rpi = RollupBatchInputs {
        vk_hash: [0x22; 32],
        prev_state_root: [0x33; 32],
        new_state_root: [0x44; 32],
        deposit_acc: [0x11; 32],
        withdraw_root: [0x55; 32],
        batch_seq: 1,
        batch_tx_count: 1,
        prev_tvl: 1_000_000,
        new_tvl: 900_000,
        batch_withdrawals: 99_000,
        batch_fee: 1_000,
    };
    let _ = verify_batch_proof(&rpi, data);

    let zpi = ZkVmPublicInputs {
        program_hash: [0x22; 32],
        program_bytecode: vec![],
        initial_slots: [1_000_000, 0, 0, 0],
        final_slots: [900_000, 0, 0, 0],
        prev_state_root: [0x33; 32],
        new_state_root: [0x44; 32],
        total_withdrawals: 99_000,
        steps_executed: 1,
    };
    let _ = verify_zkvm_execution(&zpi, data);
    let mut r = Reader::new(data);
    let _ = ZkVmShard::decode(&mut r);
});
