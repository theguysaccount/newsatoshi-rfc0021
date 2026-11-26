# The payment circuit, checked by machine

    cargo run --release --example extract_constraints -- proof/constraints.json
    python3 proof/check.py proof/constraints.json        # needs z3-solver from PyPI

Ten seconds in all. It ends `ALL CHECKS PASS` and exits 0, or names what failed.

## What is proven

**Theorem.** Let a trace of 8,192 rows satisfy every transition constraint of
`spend::eval_constraints` on every pair of consecutive rows (with the selectors of
`spend::periodic_table`) and every boundary cell of `spend::assertion_cells` for public
inputs (root, nf, cm_out, value_balance, dummy) with |value_balance| < 2^62. Then the
statement at the top of `src/spend.rs` holds, with the witness read from the trace: for
each input that is not a dummy there are sk, v, rho, pos and a 32-level path with

    a_pk = H(TAG_ADDR, sk),  cm = H(TAG_CM, a_pk, v, rho),  cm under `root` at pos,
    nf = H(TAG_NF, sk, pos, rho);

each output has cm_out = H(TAG_CM, a_pk, v, rho) for some a_pk, v, rho; every value is below
2^60, a dummy input's value is 0, and v_in0 + v_in1 − v_out0 − v_out1 = value_balance as
integers. H is SHA-256's compression function from its IV (FIPS 180-4, 6.2.2) on one
512-bit block.

That is the property whose absence cost Zcash's Orchard: a circuit that lets through a
payment the rules forbid, so coins can be made that nobody sees.

## What the machine checks

`examples/extract_constraints.rs` calls `spend::eval_constraints`, the function the prover,
the verifier and the soundness scan all call, with a field element that is a polynomial.
What comes out is every constraint as the exact polynomial the code computes: 249
constraints, 2,950 terms, nothing transcribed by hand. It is checked against the same
function on numbers at random points before it is written.

`check.py` writes the specification without reading the circuit's code. SHA-256's IV and
round constants are derived from the primes (square and cube roots), and its functions from
XOR, AND and NOT on bits, as FIPS 180-4 defines them. The statement's wiring (which words
each compression reads, the registers, the value, the balance) is written from the
statement. Then:

1. **Census.** The 8,191 row pairs fall into 41 classes by their selectors and by whether
   the next row is part of a compression. The selectors on every row are the statement's
   (the block layout, where rounds, block ends and loads fall, the round constants, which
   are FIPS 180-4's), and the boundary cells are the statement's, for real and dummy
   inputs.
2. **Exactness.** On every class, each of the 249 constraints is the same polynomial over
   the field as the specification's, once the variables that are bits on that class are
   reduced (x² = x). Two such polynomials that agree on every input of bits are equal, so
   this is equality on every input, not on samples. The check can fail: five small errors
   planted in the specification (a rotation off by one, Ch built wrongly, one bit of the IV,
   a swapped tag, a shift off by one) are each caught.
3. **No wrapping.** Each relation the argument reads as an equation between integers (a
   round's a and e, the schedule's W_{t+16}, the range checks, the balance) has, under the
   ranges the circuit enforces, an integer value strictly inside (−p, p) (the balance:
   inside (−p/2, p/2)). So the field equation holds exactly when the integer one does.
4. **Arithmetic** (Z3): a round's word is its sum modulo 2^32; a digest word below 2^32 is
   IV_j + state_j modulo 2^32 however its state word was encoded; W_0, the one message word
   no range check covers, gives round 0 and the schedule the honest value modulo 2^32 even
   when it is a digest word's other encoding; a value with its top four bits zero is below
   2^60.

## The argument that ties the checks together

By hand, each step citing a check above. Row r of the trace is row t = r mod 64 of block
b = r div 64; the layout is the census's.

**Bits.** On every row of an active block the booleanity constraints (exact, 2) give the
bits of a, e, the schedule's two read words, the carries and the path bit values in {0, 1}:
a field has no zero divisors.

**A compression.** Take an active block. The pair (row 63 of the block before, row 0) is a
load (exact, 2): row 0 holds the IV's a, b, c, e, f, g, round 0's results are k + W_0 for
SHA-256's constants k, and the window W_0..W_15 is the message the statement names for this
kind of block. For t = 0 … 62 the pair (t, t+1) is a round (exact, 2): b_{t+1} and f_{t+1}
are a_t's and e_t's bits; c_{t+1}, g_{t+1} are words of bits; a_{t+1}, e_{t+1} are the bits
of the results on row t; and the results on row t+1 are word + 2^32 × carry =
h + Σ1(e) + Ch(e,f,g) + K_{t+1} + W_{t+1} + Σ0(a) + Maj(a,b,c), and d + the same T1. Every
term is below 2^32: the state words by induction, K by the census, W_{t+1} by the range
check on row t. So the equation holds over the integers (3), and each result is the sum
modulo 2^32 (4), because the next row reads its bits. By induction on t the rows carry
SHA-256's state after each round, with SHA-256's message schedule: the window shifts, and
W_{t+16} = σ1(W_{t+14}) + W_{t+9} + σ0(W_{t+1}) + W_t modulo 2^32 (exact, 3, 4), each W
range-checked on some row except W_0. W_0 enters only round 0 and W_16, and either is a
constant (a tag), a free word (a tree sibling, which any value may be), or a digest word,
whose other encoding gives the same values modulo 2^32 (4). On row 63 the digest is
IV + state after 64 rounds (exact, 2), with a_64 and e_64 as unreduced sums; wherever a
digest word is read again it is either below 2^32 (compared with a public word, or read as a
range-checked message word) and so is the honest word, or it is W_0 (4).

**The wiring.** The loads (exact, 2) read: for an address, TAG_ADDR and sk; for an input
commitment, TAG_CM, the address just computed, the value's two words, rho; for a tree
level, the running node on the side the path bit names and a free sibling; for a nullifier,
TAG_NF, sk, pos, rho; for an output, TAG_CM and free words. The registers (exact, 2): sk is
unchanged except entering an address block, rho except entering an input commitment, so an
input's nullifier reads the sk and rho its address and commitment read; pos is 0 at the
first input (boundary cell), restarts at each address block, and gains 2^k × the bit of
level k, so the nullifier reads the leaf position the path climbs from. The boundary cells
fix the last level's digest to the root (real inputs), each nullifier block's digest to nf,
each output block's digest to cm_out.

**The money.** A note's value is 2^32 × W_9 + W_10 of its commitment's message. Both are
range-checked words, and on row 8 the top four bits of W_9 are zero (exact, 2), so the value
is below 2^60 (4). The balance register starts at 0 (boundary cell), gains each input's value
at its commitment and loses each output's (exact, 2), and ends at value_balance (boundary
cell). Four values below 2^60 sum to well inside (−p/2, p/2), as does any |value_balance|
below 2^62 (the verifier refuses larger), so the equation holds over the integers (3). A
dummy input's two value words are 0 (boundary cells), and no root is asserted for it.

That is the theorem. ∎

## What this does not cover, and what is trusted

- **Trusted:** that an accepted STARK proof means such a trace exists (Winterfell's
  soundness, with the masking patch in `vendor/`, under SHA-256 as a random oracle);
  SHA-256's compression function as a hash; the field arithmetic of winter-math, which the
  extraction uses; Python's integers and Z3. The step from the checks to the theorem is the
  page above, written by hand.
- **Not covered here:** the rules outside the circuit (a nullifier spent only once, the
  ledger's counters of issued and burned coins, fees), which `tests/` exercise but nothing
  proves; the conditions' script language; the chain proof, not yet built.
- **The higher bar (NOW MACHINE-CHECKED IN LEAN 4):** Zcash's Ironwood proved its balance
  in Lean, every step by machine, the composition included. `examples/extract_lean_spend.rs`
  now extracts Constraint #247 (balance register), Constraint #248 (note `< 2^60` range
  check), and the exact 8,192-row selector schedule directly out of live compiling
  `spend::eval_constraints`, `spend::periodic_table`, and `spend::assertion_cells` into
  `proof/SpendBalance.lean` (zero `sorry`, zero Mathlib, zero custom axioms; checked under
  Lean 4.36.0):

      cargo run --release --example extract_lean_spend -- proof/SpendBalance.lean
      lean proof/SpendBalance.lean

  `SpendBalance.lean` proves `extracted_constraint_247_exact`, `extracted_constraint_248_exact`,
  `note_value_strictly_below_2_pow_60`, `spend_balance_exact_integer_conservation` (full
  4,607-step induction + Goldilocks no-wrap lifting to exact `Int` equality),
  `rfc0022_channel_exact_conservation`, and `block_solvency_preserved` (`pool + locked + burned = issued`).
  Note: full SHA-256 64-round compression equivalence remains verified by `proof/check.py` (Z3)
  above; `SpendBalance.lean` covers the balance/range induction and ledger solvency composition.
