use newsatoshi::note::{self, NoteTree};
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use rand::Rng;
use std::time::Instant;

fn setup() -> (SpendWitness, [u32; 8]) {
    let mut rng = rand::thread_rng();
    let mut tree = NoteTree::new();
    let sk_a: [u32; 8] = rng.gen();
    let sk_b: [u32; 8] = rng.gen();
    // some unrelated notes first
    for _ in 0..5 {
        tree.append(note::commit(&note::address(&rng.gen()), 7, &rng.gen()));
    }
    let rho_a: [u32; 5] = rng.gen();
    let rho_b: [u32; 5] = rng.gen();
    let pa = tree.append(note::commit(&note::address(&sk_a), 3_000_000_000, &rho_a));
    tree.append(note::commit(&note::address(&rng.gen()), 9, &rng.gen()));
    let pb = tree.append(note::commit(&note::address(&sk_b), 1_234_567, &rho_b));
    let w = SpendWitness {
        inputs: [
            InputNote { sk: sk_a, v: 3_000_000_000, rho: rho_a, pos: pa, path: tree.path(pa) },
            InputNote { sk: sk_b, v: 1_234_567, rho: rho_b, pos: pb, path: tree.path(pb) },
        ],
        outputs: [
            OutputNote { a_pk: note::address(&rng.gen()), v: 2_500_000_000, rho: rng.gen() },
            OutputNote { a_pk: note::address(&sk_a), v: 501_234_000, rho: rng.gen() },
        ],
        dummy: [false, false],
    };
    assert_eq!(w.inputs[0].root(), tree.root());
    (w, rng.gen())
}

#[test]
fn honest_trace_satisfies_every_constraint() {
    let (w, bind) = setup();
    let pi = w.public(bind).unwrap();
    assert_eq!(pi.value_balance, 567);
    let trace = spend::build_trace(&w);
    spend::check_trace(&trace, &pi).unwrap();
}

#[test]
fn inflation_is_caught_by_the_constraints() {
    let (w, bind) = setup();
    let pi = w.public(bind).unwrap();
    // claim a smaller fee than the trace pays: the balance assertion must fail
    let mut lie = pi.clone();
    lie.value_balance -= 1;
    let trace = spend::build_trace(&w);
    assert!(spend::check_trace(&trace, &lie).is_err());
    // claim a different nullifier
    let mut lie = pi.clone();
    lie.nf[1][3] ^= 1;
    assert!(spend::check_trace(&trace, &lie).is_err());
    // spend under a different root
    let mut lie = pi;
    lie.root[0] ^= 1;
    assert!(spend::check_trace(&trace, &lie).is_err());
}

#[test]
fn prove_verify_and_reject_tampering() {
    let (w, bind) = setup();
    let t = Instant::now();
    let (pi, proof) = spend::prove(&w, bind).unwrap();
    let prove_ms = t.elapsed().as_millis();
    let bytes = proof.to_bytes();
    let t = Instant::now();
    spend::verify(&pi, &proof).unwrap();
    let verify_ms = t.elapsed().as_micros() as f64 / 1000.0;
    println!(
        "spend proof: {} bytes, prove {} ms, verify {:.1} ms, conjectured {} bits, proven {} bits (list-decoding) / {} (unique-decoding)",
        bytes.len(),
        prove_ms,
        verify_ms,
        proof.conjectured_security::<spend::Hash>().bits(),
        proof.proven_security::<spend::Hash>().ldr_bits(),
        proof.proven_security::<spend::Hash>().udr_bits(),
    );
    assert!(proof.proven_security::<spend::Hash>().ldr_bits() >= spend::PROVEN_BITS);
    // every public field is bound
    let mut lie = pi.clone();
    lie.value_balance += 1;
    assert!(spend::verify(&lie, &proof).is_err());
    let mut lie = pi.clone();
    lie.cm_out[0][0] ^= 1;
    assert!(spend::verify(&lie, &proof).is_err());
    let mut lie = pi.clone();
    lie.bind[7] ^= 1;
    assert!(spend::verify(&lie, &proof).is_err());
    let mut lie = pi.clone();
    lie.dummy[0] = true;
    assert!(spend::verify(&lie, &proof).is_err());
    // flipping bytes in the proof breaks it
    let mut rng = rand::thread_rng();
    for _ in 0..8 {
        let mut b = bytes.clone();
        let i = rng.gen_range(64..b.len());
        b[i] ^= 1 << rng.gen_range(0..8);
        assert!(spend::verify_bytes(&pi, &b).is_err(), "tampered byte {i} accepted");
    }
}

#[test]
fn one_real_input_and_a_dummy() {
    let mut rng = rand::thread_rng();
    let mut tree = NoteTree::new();
    let sk: [u32; 8] = rng.gen();
    let rho: [u32; 5] = rng.gen();
    let p = tree.append(note::commit(&note::address(&sk), 5000, &rho));
    let mut w = SpendWitness {
        inputs: [InputNote { sk, v: 5000, rho, pos: p, path: tree.path(p) }, InputNote::dummy()],
        outputs: [
            OutputNote { a_pk: note::address(&rng.gen()), v: 4000, rho: rng.gen() },
            OutputNote { a_pk: note::address(&sk), v: 990, rho: rng.gen() },
        ],
        dummy: [false, true],
    };
    let (pi, proof) = spend::prove(&w, [0; 8]).unwrap();
    assert_eq!(pi.value_balance, 10);
    assert_eq!(pi.root, tree.root());
    spend::verify(&pi, &proof).unwrap();
    // a dummy may not carry value: the witness builder refuses, and a forged trace fails
    w.inputs[1].v = 7;
    assert!(w.public([0; 8]).is_err());
    let mut pi2 = pi.clone();
    pi2.value_balance += 7;
    let trace = spend::build_trace(&w);
    assert!(spend::check_trace(&trace, &pi2).is_err());
}

#[test]
fn values_above_the_cap_cannot_be_proved() {
    // A note worth 2^60 would let two of them wrap a sum; the circuit forbids v_hi >= 2^28.
    let mut rng = rand::thread_rng();
    let sk: [u32; 8] = rng.gen();
    let big = 1u64 << 60;
    let w = SpendWitness {
        inputs: [InputNote::dummy(), InputNote::dummy()],
        outputs: [
            OutputNote { a_pk: note::address(&sk), v: 0, rho: rng.gen() },
            OutputNote { a_pk: note::address(&sk), v: 0, rho: rng.gen() },
        ],
        dummy: [true, true],
    };
    let pi = w.public([0; 8]).unwrap();
    let trace = spend::build_trace(&w);
    spend::check_trace(&trace, &pi).unwrap();
    // now force an output of 2^60 into the trace by hand-building the witness unchecked
    let mut w2 = w.clone();
    w2.outputs[0].v = big;
    let trace = spend::build_trace(&w2);
    let mut pi2 = pi.clone();
    pi2.cm_out[0] = newsatoshi::spend::OutputNote { a_pk: w2.outputs[0].a_pk, v: 0, rho: w2.outputs[0].rho }.cm();
    pi2.value_balance = -(big as i64);
    let err = spend::check_trace(&trace, &pi2).unwrap_err();
    assert!(err.contains("constraint"), "{err}");
}

#[test]
fn proofs_mask_their_segments_and_the_earlier_kind_still_verifies() {
    use winterfell::Prover;
    let (w, bind) = setup();
    let pi = w.public(bind).unwrap();
    // a proof as the test network made them before: no metadata, three plain segments
    let legacy = spend::test_prover(spend::options(), pi.clone()).prove(spend::build_trace_legacy(&w)).unwrap().to_bytes();
    assert!(legacy.starts_with(&spend::context_prefix_legacy(&pi)));
    spend::verify_bytes(&pi, &legacy).unwrap();
    // the proofs made now: one segment more, each masked, and the metadata that says so
    let (_, p) = spend::prove(&w, bind).unwrap();
    let masked = p.to_bytes();
    assert!(masked.starts_with(&spend::context_prefix(&pi)));
    spend::verify_bytes(&pi, &masked).unwrap();
    println!("proof bytes: {} with masked segments, {} without", masked.len(), legacy.len());
    // the metadata is bound: relabelled as the earlier kind, a masked proof fails
    let mut relabelled = spend::context_prefix_legacy(&pi);
    relabelled.extend_from_slice(&masked[spend::context_prefix(&pi).len()..]);
    assert!(spend::verify_bytes(&pi, &relabelled).is_err());
    // and a masked proof still binds everything else: one flipped byte anywhere fails it
    for at in [masked.len() / 3, masked.len() / 2, masked.len() - 40] {
        let mut bad = masked.clone();
        bad[at] ^= 1;
        assert!(spend::verify_bytes(&pi, &bad).is_err(), "byte {at}");
    }
}

#[test]
fn masked_segments_add_up_to_the_composition_and_hide_its_plain_segments() {
    use winterfell::math::{fft, fields::f64::BaseElement as F, polynom, FieldElement, StarkField};
    use winterfell::{Air, CompositionPoly, CompositionPolyTrace, StarkDomain, TraceInfo};
    let (w, bind) = setup();
    let air = spend::SpendAir::new(TraceInfo::with_meta(spend::WIDTH, spend::ROWS, spend::ZK_META.to_vec()), w.public(bind).unwrap(), spend::options());
    let domain = StarkDomain::new(&air);
    let (n, cols, stride) = (domain.trace_length(), air.context().num_constraint_composition_columns(), air.context().composition_stride());
    assert_eq!((cols, n - stride), (4, spend::zk_mask_len(&spend::options())));
    // a polynomial of the composition's degree, given by its values on the constraint domain
    let mut rng = rand::thread_rng();
    let mut el = || F::new(rng.gen::<u64>() % F::MODULUS);
    let mut coeffs: Vec<F> = (0..3 * n - 2).map(|_| el()).collect();
    let ce = domain.ce_domain_size();
    coeffs.resize(ce, F::ZERO);
    let values = || fft::evaluate_poly_with_offset(&coeffs, &fft::get_twiddles::<F>(ce), domain.offset(), 1);
    let masks: Vec<Vec<F>> = (1..cols).map(|_| (0..n - stride).map(|_| el()).collect()).collect();
    let zero: Vec<Vec<F>> = (1..cols).map(|_| vec![F::ZERO; n - stride]).collect();
    let masked = CompositionPoly::new_masked(CompositionPolyTrace::new(values()), &domain, cols, stride, &masks).into_columns();
    let plain = CompositionPoly::new_masked(CompositionPolyTrace::new(values()), &domain, cols, stride, &zero).into_columns();
    for _ in 0..3 {
        let x = el();
        let sum = |c: &[Vec<F>]| c.iter().enumerate().fold(F::ZERO, |a, (i, col)| a + x.exp(((i * stride) as u64).into()) * polynom::eval(col, x));
        assert_eq!(sum(&masked), polynom::eval(&coeffs, x), "the masks cancel");
        assert_eq!(sum(&plain), polynom::eval(&coeffs, x));
        for i in 0..cols {
            assert_ne!(polynom::eval(&masked[i], x), polynom::eval(&plain[i], x), "segment {i} is masked");
        }
    }
}
