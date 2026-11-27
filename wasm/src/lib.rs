//! Browser verifier: `verify(public_inputs, proof)` returns 1 for a valid MAIN_V2 shielded-spend
//! proof (192-bit classical / 104-bit CMS19 QROM Quartic F_{p^4} pure SHA-384 STARK).
use newsatoshi::spend::{self, SpendPublic};

fn no_rng(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
getrandom::register_custom_getrandom!(no_rng);

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len);
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}

/// Verify a MAIN_V2 (192-bit classical / 104-bit CMS19 QROM Quartic SHA-384) shielded spend proof.
/// 1 = valid, 0 = rejected, -1 = malformed public inputs.
#[no_mangle]
pub extern "C" fn verify(pi_ptr: *const u8, pi_len: usize, proof_ptr: *const u8, proof_len: usize) -> i32 {
    let pi = unsafe { core::slice::from_raw_parts(pi_ptr, pi_len) };
    let proof = unsafe { core::slice::from_raw_parts(proof_ptr, proof_len) };
    let Ok(p) = SpendPublic::from_bytes(pi) else { return -1 };
    match spend::verify_bytes_for(&spend::MAIN_V2, &p, proof) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Legacy v0.1.0 verifier (`spend::MAIN`, 128-bit classical Quadratic SHA-256) for archive proofs.
#[no_mangle]
pub extern "C" fn verify_v1(pi_ptr: *const u8, pi_len: usize, proof_ptr: *const u8, proof_len: usize) -> i32 {
    let pi = unsafe { core::slice::from_raw_parts(pi_ptr, pi_len) };
    let proof = unsafe { core::slice::from_raw_parts(proof_ptr, proof_len) };
    let Ok(p) = SpendPublic::from_bytes(pi) else { return -1 };
    match spend::verify_bytes_for(&spend::MAIN, &p, proof) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}
