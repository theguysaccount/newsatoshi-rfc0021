#![no_main]
use libfuzzer_sys::fuzz_target;
use newsatoshi::batch_spend::{verify_batch_bytes_for, BatchSpendPublic};
use newsatoshi::spend::{self, SpendPublic};

fuzz_target!(|data: &[u8]| {
    let pi = SpendPublic {
        root: [0; 8],
        nf: [[1; 8], [2; 8]],
        cm_out: [[3; 8], [4; 8]],
        value_balance: 0,
        dummy: [false, true],
        bind: [5; 8],
    };
    let _ = spend::verify_bytes_for(&spend::TEST, &pi, data);
    let _ = spend::verify_bytes_for(&spend::MAIN_V2, &pi, data);

    let bpi = BatchSpendPublic {
        spends: vec![pi.clone(), pi],
        prover_a_pk: [9; 8],
    };
    let _ = verify_batch_bytes_for(&spend::TEST, &bpi, data);
    let _ = verify_batch_bytes_for(&spend::MAIN_V2, &bpi, data);
});
