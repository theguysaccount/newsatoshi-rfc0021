//! The main network's proof parameters: a proof made with them verifies with them and with
//! nothing else, carries at least the test network's proven security, and fits its limit.

use newsatoshi::note::{self, NoteTree};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness, MAIN_MAX_PROOF_BYTES, MAIN_QUERIES, PROVEN_BITS};
use rand::Rng;

#[test]
fn mainnet_proofs_verify_only_at_mainnet_parameters() {
    let mut rng = rand::thread_rng();
    let sk = rng.gen();
    let (v, rho) = (10_000u64, rng.gen());
    let mut t = NoteTree::new();
    let pos = t.append(note::commit(&note::address(&sk), v, &rho));
    let wit = SpendWitness {
        inputs: [InputNote { sk, v, rho, pos, path: t.path(pos) }, InputNote::dummy()],
        outputs: [OutputNote { a_pk: rng.gen(), v: 6_000, rho: rng.gen() }, OutputNote { a_pk: note::address(&sk), v: 3_000, rho: rng.gen() }],
        dummy: [false, true],
    };
    let t0 = std::time::Instant::now();
    let (pi, proof) = spend::prove_with(&wit, rng.gen(), spend::main_options()).unwrap();
    let secs = t0.elapsed().as_secs_f64();
    let bytes = proof.to_bytes().len();
    let proven = proof.proven_security::<spend::Hash>().ldr_bits();
    println!("mainnet proof: {MAIN_QUERIES} queries, {bytes} bytes, proved in {secs:.1} s, {proven} proven bits (list decoding)");
    assert!(bytes <= MAIN_MAX_PROOF_BYTES, "{bytes} bytes");
    assert!(proven >= PROVEN_BITS, "{proven} proven bits");
    spend::verify_with(&pi, &proof, spend::main_options()).unwrap();
    assert!(spend::verify_with(&pi, &proof, spend::options()).is_err(), "a mainnet proof is not a test-network proof");
    assert!(spend::verify(&pi, &proof).is_err());
    let (pi2, test_proof) = spend::prove(&wit, rng.gen()).unwrap();
    assert!(spend::verify_with(&pi2, &test_proof, spend::main_options()).is_err(), "and a weaker proof is not a mainnet proof");
}

/// The main network takes only proofs whose segments are masked, and only its own.
#[test]
fn the_main_network_takes_only_masked_proofs_that_carry_its_name() {
    use winterfell::Prover;
    let mut rng = rand::thread_rng();
    let sk = rng.gen();
    let (v, rho) = (10_000u64, rng.gen());
    let mut t = NoteTree::new();
    let pos = t.append(note::commit(&note::address(&sk), v, &rho));
    let wit = SpendWitness {
        inputs: [InputNote { sk, v, rho, pos, path: t.path(pos) }, InputNote::dummy()],
        outputs: [OutputNote { a_pk: rng.gen(), v: 6_000, rho: rng.gen() }, OutputNote { a_pk: note::address(&sk), v: 3_000, rho: rng.gen() }],
        dummy: [false, true],
    };
    let bind = rng.gen();
    let (pi, proof) = spend::prove_for(&spend::MAIN, &wit, bind).unwrap();
    let bytes = proof.to_bytes();
    assert!(bytes.len() <= MAIN_MAX_PROOF_BYTES);
    spend::verify_bytes_for(&spend::MAIN, &pi, &bytes).unwrap();
    assert!(spend::verify_bytes_for(&spend::DRY, &pi, &bytes).is_err(), "a main-network proof is not a rehearsal proof");
    assert!(spend::verify_bytes_for(&spend::TEST, &pi, &bytes).is_err());

    // the same statement proved without masks, at the main network's parameters
    let plain = spend::test_prover(spend::MAIN.options(), pi.clone()).prove(spend::build_trace_legacy(&wit)).unwrap().to_bytes();
    assert!(spend::verify_bytes_for(&spend::MAIN, &pi, &plain).is_err(), "an unmasked proof is refused");
    // and it is the mask, not the proof, that is missing: rules that allowed it would take it
    let lax = spend::Profile { unmasked: true, ..spend::MAIN };
    spend::verify_bytes_for(&lax, &pi, &plain).unwrap();
}
