# The chain proof: what it is, what it costs, and how it gets built

The white paper's chain proof is one small proof per block that the whole history is
valid. A light client checks it in milliseconds; nodes stop carrying payment proofs in
blocks, which is what lifts the test network from about 0.5 payments a second to about 10.
Three of the open items rest on it: the chain proof, the light clients that check it, and
conditions inside shielded notes.

## What it has to prove, block by block

1. The previous block's chain proof is valid (this is the recursion).
2. Each payment proof in the block is valid: a STARK verifier, written as a circuit,
   checks each one.
3. The state moves correctly: each payment's two commitments join the note tree, each
   nullifier joins the nullifier tree, which proves it new (`src/nftree.rs`: one path
   finds the leaf below it, two paths update it), and the supply counters balance.
4. The header is valid: it links to the previous one, carries the difficulty ASERT sets
   and the work it claims (`src/chain.rs`, `check_run`).

The light client then checks one proof and the tip's commitment to the two trees' roots,
which it already does for headers and roots (`src/light.rs`).

## Built already

- The nullifier tree, with spent and unspent proofs, and blocks committing to its root
  (test network from height 3,900). Step 3 needs exactly these paths.
- The state digest as named parts (`state::DigestParts`), so a proof can expose the roots.
- The header checks as one function over a run of headers (`chain::check_run`).
- Zero knowledge over the quotient segments, so the proofs a chain proof absorbs reveal
  nothing.
- A count of every SHA-256 compression the verifier runs (`hash::count`), which measures
  step 2 exactly: `cargo run --release --features count --example recursion_cost`.

## What step 2 costs, measured

Checking one payment proof runs these SHA-256 compressions (10 Nov 2026):

| | Compressions | Rows as a circuit | Core-seconds to prove* |
|---|---|---|---|
| Test-network proof (64 queries) | 9,325: 3,805 hashing opened rows, 4,898 merging Merkle nodes, 622 drawing challenges | about 597,000 | about 540 |
| Same, with challenges drawn as powers of one value | 8,854 | about 567,000 | about 510 |
| Main-network proof (128 queries) | 16,317 | about 1,044,000 | about 980 |

\*At 1,635 rows a core-second, the rate this machine (2 cores) proves the payment circuit,
which is the same SHA-256 arithmetisation: one round a row, 64 rows a compression. The
arithmetic around the hashes (the payment circuit's constraints at one point, the DEEP
sums, FRI folding) adds a few tens of thousands of rows.

So with SHA-256 as the only assumption, absorbing a payment into the chain proof costs
roughly 500 to 1,000 core-seconds, and the aggregation tree that merges proofs pairwise
roughly doubles it. Ten payments a second means about 10,000 to 20,000 cores proving all
the time, a few hundred large servers, about a cent a payment at today's prices, paid from
fees (white paper §5). GPU provers would cut that several-fold. This is the number that
sets mainnet's real capacity, not the block size.

## Making it cheaper before building it

- **Merge Merkle nodes with one compression.** The proof system's hasher merges two
  digests with full SHA-256, two compressions with padding. The note tree already uses one
  compression under the standard IV, which is the function SHA-256's security rests on.
  A hasher that does the same for proofs halves the 4,898 merges: about 25% off.
- **Draw challenges as powers of one value** (algebraic batching): about 5% off.
- **Fewer, wider queries in the recursive layers.** A larger blowup with more grinding
  needs fewer queries for the same proven bits; every query saves a path in each tree.
- **Narrower rows.** Hashing the opened rows (3,805) scales with the trace width; a wider
  SHA-256 arithmetisation that proves two rounds a row halves the rows at the same width.

Together these plausibly bring a payment to about 5,000 compressions, about 300,000 rows.

## Build order

1. A hasher with one-compression merges and algebraic batching for the proofs the chain
   proof absorbs: a new kind of proof, marked in its metadata as masking is today.
2. A SHA-256 circuit library from the payment circuit's rounds: Merkle paths, leaf
   hashing, Fiat–Shamir draws, each tested against the native code.
3. Field arithmetic in the cubic extension, and the payment circuit's constraints
   evaluated at one point, in a circuit.
4. FRI and DEEP checks: a verifier circuit for one payment proof, tested on real proofs.
5. The state-transition circuit (note tree appends, nullifier inserts, supply) and the
   header checks.
6. Recursion: the block circuit verifies the previous block's chain proof, then a
   pairwise aggregation tree so that provers can work in parallel.
7. Prover hardware: the circuit is about a million rows a payment, beyond a laptop's
   memory; a proving market (white paper §5) runs it on servers or GPUs.

Steps 1 to 4 are a verifier circuit, the part everyone who has built recursion found
hardest, and where reviewers who have done it (Ring 0) save the most time.
