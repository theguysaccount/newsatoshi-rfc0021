# Launch

There is no premine, no developer allocation and no foundation. The genesis coinbase pays
no one. Launch proceeds in three rings; each opens only when the one before has closed.

## Ring 0 — review

The paper, this code and its measurements go to named cryptographers with one request:
break it. In particular:

- the segment masks for zero knowledge (`vendor/`, every change marked `NEWSATOSHI patch`,
  after Haböck and Al Kindi, ePrint 2024/1037), and the argument for trace randomisation
  in `src/spend.rs` that they complete;
- soundness of the spend AIR, especially the mod-2^32 argument for W_0, the digest words
  and the round results, and the value bound below 2^60; what `src/audit.rs` lists as
  free, and whether a machine-checked proof should state more than balance;
- the claim that a STARK proof of key knowledge bound into Fiat–Shamir is a signature;
- Theorem 1 (blind issuance) and Theorem 2 (linear returns);
- the settlement rules: any profitable deviation for a poster or a worker.

Ring 0 closes when every finding is fixed or answered in the attack log.

## Ring 1 — public testnet

Genesis 00000fd814d823a0bc64a84135868402998cff81e28a85b2bede5f1125d0a394, mined
2026-11-07 over a message naming Bitcoin block 974,866. Announced on the cryptography
mailing list where Bitcoin was announced. Attacks on the testnet are invited: a successful
one there is a free audit.

## Ring 2 — mainnet

**Opened 10 November 2026**, by decision, before all of the conditions below held. Genesis
`000000006ba30cc3c86ecaabcb962287e9d5fd0877c27f4b33661b4d1d3033f7`, over Bitcoin block 975,317
(`00000000000000000000087bd193c8f677628410cefab14a1638abeabd0fb9c4`). In place at opening:
1 (built, not yet reviewed from outside), 3 (built, not yet run by a pool), 5, 6, and 7 in
part. Not in place: 2 (the chain proof, which arrives by a later rule change every node
must take), 8 (an outside audit) and 9 (the test network had run three days). Until they
are, the main network's coins are experimental. The conditions as first written:

Mainnet genesis is mined only when all of these hold:

1. Zero knowledge covers the quotient segments: built, 9 Nov 2026 (Haböck and Al Kindi,
   ePrint 2024/1037, in a patched Winterfell 0.13.1). The masks cover every row a
   commitment reveals or hashes, so no salt is needed. Before mainnet: an outside review
   of the construction and its code. Mainnet accepts masked proofs only
   (`spend::verify_with` already refuses others at mainnet's parameters).
2. The chain proof (white paper §5): blocks carry payments' public parts, every block
   carries the recursive chain proof for the block six below it, and a light client
   checks one proof for the whole history.
3. Merged mining with Bitcoin (AuxPoW), alongside direct SHA-256d mining. Built on the
   testnet in Namecoin's format and calls; before mainnet, proven with at least one
   pool's own software.
4. Conditions (white paper §7): a note may commit to a circuit, and a payment may state a
   height before which it is invalid; the escrow and the lock move from built-in modules
   to conditions. Built beside the shielded pool on 9 Nov 2026 (`src/cond.rs`, a committed
   program in a small post-quantum script language); inside shielded notes they wait on
   the chain proof's recursion. The lock (SHA-256 hash and timeout, Lightning's own) is built on the
   testnet, with a swap server that trades it for Lightning payments both ways; before
   mainnet, swaps run against a live Lightning network, and at least one market maker
   other than this project runs a swap server.
5. Proof parameters with doubled query soundness, SHA-256 throughout. The quantum
   random-oracle bound is then set by the 256-bit output, about 85 proven bits; beyond
   that the argument is the cost of quantum memory. Built, 10 Nov 2026: each network states
   how its proofs are made (`spend::Profile`: queries, its own name inside every proof,
   masked only, the size limit), its transaction limit and its wallets' default fee. The
   rehearsal network (`--net rehearsal`) is the main network's rules on a chain that is
   thrown away; a payment of 461 KB, proved in 2.1 s natively and 4.6 s in WebAssembly,
   has gone through it (`tests/rehearsal.rs`, and RUNBOOK.md for the run with real nodes).
6. Nullifier pruning: decided, 9 Nov 2026 (white paper §11), and the tree built
   (`src/nftree.rs`; test-network blocks commit to its root from height 3,900, and light
   clients check spent and unspent against it). Mainnet keeps every spent nullifier, in a
   sorted Merkle tree whose root the chain proof carries: a spend proves
   its nullifier new with one path, validators store nothing, and provers and path servers
   keep up to about 150 GB a year at full blocks. Evolving nullifiers (Bowe and Miers,
   ePrint 2025/2031) would prune that, at the price of a recursive proof with every spend
   and a synchronisation service for every wallet; if provers' state ever binds, they can
   come as a second kind of note without changing the nullifiers of the first.
7. A machine-checked proof of the spend circuit: that its constraints let through no
   payment the rules forbid (each spent note in the tree, its nullifier the one it must
   produce, every value in range, inputs equal to outputs plus the public amount),
   assuming only SHA-256's properties and the proof system's soundness, and that the
   ledger's counters follow. A private pool cannot be audited by counting, so a free
   value in its circuit mints coins nobody sees: Zcash's Orchard had one from 2022 to
   June 2026, and its replacement, Ironwood, set the standard in July 2026 with a proof
   of its balance in Lean. Done in part, 10 Nov 2026 (`proof/`): every constraint, read out
   of the code as an exact polynomial, is the specification's (written from FIPS 180-4 and
   the statement) on every row; no relation wraps the field; the arithmetic is proven with
   Z3; one page by hand completes the theorem. Left: that page in a proof assistant, and
   the ledger's counters. Beside it, as before, the scan
   (`cargo run --release --example soundness_scan`, and `tests/soundness.rs` on every
   build): every active cell changed in turn, every joint first-order move solved for,
   and only the freedom `src/audit.rs` specifies found. The chain proof's circuits are
   built from the same SHA-256 rows, so their gadgets are proven once, here.
8. An audit from outside this project covers the spend circuit, the chain proof, the
   conditions and the zero-knowledge construction.
9. Ring 1 has run long enough to have been attacked in earnest.

Its genesis message names a Bitcoin block of that day. Its parameters: a pow limit of
0x1d00ffff, an ASERT half-life of two days, coinbase maturity of 100 blocks
(`Params::main_with`). RUNBOOK.md is the day itself, step by step.

Decided, 10 Nov 2026 (attack log, 49): the rule stays as planned. Starting at difficulty
1 with a two-day half-life, difficulty doubles for every 288 blocks that arrive early, and a
single 200 TH/s machine could mine 6,759 blocks in the first day instead of 144: 1.6% of all
coins to whoever arrives first. Mining opens to everyone at one announced moment and this
project's nodes do not mine at the opening. The alternatives that were weighed:

| rule | first day, one 200 TH/s machine | first day, 1 EH/s | difficulty's steady wobble |
|---|---|---|---|
| half-life 2 days (as planned) | 6,759 blocks | 10,297 | ±4% |
| half-life 12 hours | 1,896 | 2,781 | ±8% |
| half-life 4 hours | 738 | 1,033 | ±14% |
| half-life 1 hour | 293 | 367 | ±29% |
| 2 days, starting at difficulty 2^24 | 219 | 3,386 | ±4% |

The schedule's own figure is 144.

## Checkpoints

A release may name (height, hash) pairs. A node refuses any chain that contradicts them.
Satoshi added the first on 17 July 2010 in Bitcoin 0.3.2: "a simple security safeguard
that locks-in the block chain up to this point." A checkpoint cannot make, censor or
halt a block, and it asks for no trust beyond the software a node already runs.
Checkpoints lapse by rule at `checkpoint_sunset`. Until hashpower is established, wallets
wait for confirmations in proportion to the value at stake.
