# newsatoshi

Reference implementation of NEWSATOSHI/2.0: proof of work orders the ledger,
proof of negentropy validates it. The coin is LOVE (`TICKER` in `src/main.rs`; the site's
build reads it from there); one LOVE is 10^8 base units, which have no name.

- **Ordering.** SHA-256d proof of work over an 80-byte header in Bitcoin's layout, so any
  SHA-256 miner can work it. Most cumulative work wins. Difficulty by ASERT (aserti3-2d).
  Blocks can also be merge-mined with Bitcoin, in Namecoin's AuxPoW format.
- **Validity.** Every spend carries a STARK proving the spender owns the notes, the notes
  exist, the nullifiers are right and the values balance. The STARK's commitments,
  challenges and grinding are SHA-256, and so is everything it proves.
- **Ownership.** Knowledge of a 256-bit key, proven inside the spend. No signature scheme
  guards a coin and no elliptic-curve key is ever used.
- **Privacy.** Every note is shielded. A payment to a delivery address travels on chain,
  sealed to the payee's ML-KEM-768 key, so the payee's wallet finds it and a key alone
  restores a wallet; a payment to a plain address travels out of band as a note string.
- **Issuance.** Bitcoin's schedule until it reaches 0.1953125 LOVE per block, then that
  floor forever. No premine; the genesis coinbase pays no one.
- **Settlement.** Escrow for verified matrix products: bonds, a private Freivalds check,
  one-entry fraud proofs, availability challenges, SLH-DSA-SHA2-128s authorisations.

Everything that guards a coin rests on SHA-256.

## Build and run

    cargo build --release
    cargo test --release                         # 99 tests
    cargo run --release --example soundness_scan # every cell of the spend circuit, tested for freedom
    cargo run --release --example fuzz -- 120    # broken inputs for every decoder, two minutes each
    ./target/release/newsatoshi demo             # payment, honest job, cheating job, in one process

Two nodes on regtest:

    newsatoshi --datadir /tmp/a node --port 19001 --mine
    newsatoshi --datadir /tmp/b node --port 19002 --peer 127.0.0.1:19001
    newsatoshi --datadir /tmp/a send $(newsatoshi --datadir /tmp/b address --delivery) 7.5   # fee 0.003
    newsatoshi --datadir /tmp/b balance                # after the next block: found on chain

## The payment circuit, checked by machine

`proof/README.md` states the theorem: a trace that satisfies the circuit's constraints and
boundary cells proves exactly the statement, so no payment the rules forbid gets through.
`examples/extract_constraints.rs` reads every constraint out of the code as an exact
polynomial; `proof/check.py` shows each is the same polynomial as a specification written
from FIPS 180-4, on every kind of row, that nothing wraps the field, and the modular
arithmetic, with Z3. The induction that ties these together is a page by hand.

## Memory

A node keeps the newest 12 block bodies in memory and reads the rest from `blocks.dat`
(connected blocks) or `side.dat` (kept but not connected). Its state lives in persistent
collections, so the copies it keeps for reorganisations share what they have in common.
`cargo run --release --example memory` measures both.

## Attacked as a stranger would

On 10 November 2026 the running node was attacked from outside: with sockets, with a
fuzzer, and with a rehearsal of the main network. What was found is in the attack log
(entries 37 to 49) and each fix has a test that replays the attack:

- `tests/hostile.rs`: junk blocks beside an old block, peers that never read, connections
  that never speak, answers nobody asked for, a proof that lies about its own length, and
  a real block's header over other transactions.
- `tests/api_hostile.rs`: requests that never finish, answers without end, a crowd of
  broken payments.
- `examples/fuzz.rs`: real transactions, blocks, proofs, memos, addresses, programs, JSON,
  light-client state, nullifier proofs and merged-mining proofs, broken the way attackers
  break them. A finding is a panic, a request for memory the input cannot justify, two
  encodings of one thing, or a broken proof that still verifies. Each finding's bytes are
  saved so it can be run again alone.
- `tests/rehearsal.rs` and `--net rehearsal`: the main network's rules on a chain that is
  thrown away (RUNBOOK.md).

Two findings could stop or split a node, and both changed code that everything else
stands on. The proof library now sets memory aside as bytes arrive, not as a proof claims
(`vendor/winter-utils`, `vendor/winter-crypto`, marked `NEWSATOSHI patch`). And a block now
carries the digest of the state it leaves, so a node can tell, before it keeps a block or
holds anything against its hash, that the transactions are the ones the header commits to
(`Block::bound`).

The public testnet is live. It makes a block a minute, so trying a payment takes minutes
(the main network keeps Bitcoin's ten). One command joins it; with no `--peer` the node
finds the seeds itself:

    newsatoshi --net testnet node            # add --mine to mine to your own wallet

Or use it in a browser: newsatoshi.org/wallet/ makes a key in the page, gets test LOVE
from the faucet, proves payments in WebAssembly (`../walletwasm`), finds payments made to
its address on chain, follows the chain's headers itself and checks that its notes are in
the tree they commit to, sends a payment as a link anyone can claim, and shows a payment
to whoever its owner chooses.

Its genesis names Bitcoin block 974,866:

    genesis 00000fd814d823a0bc64a84135868402998cff81e28a85b2bede5f1125d0a394
    message btc 974866 00000000000000000000cebad0d2d551037f43d23b2238daed435e6fa7cebb59 work orders, proof validates

## Merged mining (for pools)

    newsatoshi --net testnet node --rpc 18556 [--rpcauth USER:PASS] [--rpcbind ADDR]

The node answers Namecoin's merged-mining calls over JSON-RPC: `createauxblock ADDRESS`,
`getauxblock` (pays the node's wallet) and `submitauxblock HASH AUXPOW`, plus
`getblockcount`, `getbestblockhash`, `getblockchaininfo`, `getdifficulty` and
`validateaddress`. Chain ID 20051 (0x4e53). A pool that merge-mines Namecoin adds this
chain as one more entry in its merged-mining tree; the Bitcoin header, coinbase and branch
it submits are checked by Namecoin's rules, and the Bitcoin header's hash must meet this
chain's target. Authentication is HTTP Basic: without `--rpcauth` a fresh password is
written to `.cookie` in the data directory, as Bitcoin Core does. The RPC binds to
127.0.0.1 and has no TLS; expose it only on a private network.

`contrib/merge_mine_sim.py` plays the pool's side, end to end, against a regtest node.

## Public API (for wallets)

`--status PORT` serves, to anyone: `GET /status`; `GET /api/note?cm=` (where a commitment
sits in the note tree, with the Merkle path a spend needs); `GET /api/spent?nf=` (with a path in the nullifier tree that proves it spent or unspent);
`GET /api/cond?id=` (a condition's terms and how it ended);
`GET /api/lock?id=` or `?hash=` (a lock's terms and state, including a claim's preimage as
soon as it is in the mempool); `POST /api/tx` (a transaction's bytes; its proof is checked
before it is pooled); and, with `--faucet COINS`, `POST /api/faucet` (an address; a private
payment back, rate limited; to a delivery address it also travels on chain); and
`GET /api/envelopes?from=HEIGHT` (the sealed notes in blocks from that height, a page at a
time, and those still waiting in the mempool); and, for light clients, `GET
/api/headers?from=HEIGHT` (headers without transactions, 2,000 at a time) and `GET
/api/state` (the tip's header, its transaction root and the parts of the state digest it
commits to, from which `light::HeaderTip::committed_root` recovers the note-tree root). Keys never reach the node: the browser
computes nullifiers, opens envelopes and proves spends.

## Conditions

Coins can be locked to a program instead of a key: two of three keys for an escrow, a hash
and a timeout, a key that may spend only after a height, or any mix. The language
(`src/script.rs`) is a small stack machine in the manner of Bitcoin's Script, with SHA-256,
the height, the payout being chosen, and SLH-DSA signatures (FIPS 205, the same keys as
jobs); every program halts. A condition commits to its program with a salt, names up to
four payout addresses, a timeout and a refund address. Up to the timeout, whoever reveals
the program and a witness that satisfies it sends the coins to the payout the program
accepts; signatures sign the condition and the payout, so a release cannot be redirected.
After it, anyone returns them to the refund address.

    newsatoshi signing-key                                   # share it with the others
    newsatoshi cond 5 --pay BUYER,SELLER --two-of-three KEY_A,KEY_B,KEY_C
    newsatoshi cond-sign CONDID 1                            # each of two parties
    newsatoshi fulfil CONDID 1 --witness SIG_A,SIG_B         # pays SELLER

`--program "SHA256 0x<hash> EQUAL"` takes any program as text (`program TEXT` shows its
bytes). A condition shows its amount, addresses and timeout, and, when used, its program,
as a script does on Bitcoin. Conditions inside shielded notes, where the chain learns only
that some condition was met, need the chain proof's recursion.

## Payments delivered on chain

One key has two addresses. `address` prints the plain one (`ns1…`); `address --delivery`
prints the delivery address (`nsd1…`, 2,444 characters: the address and an ML-KEM-768 key,
FIPS 203). A payment to a delivery address travels on chain: the payer seals the note to
that key, in the memo the proof already binds, and the payee's wallet finds it by trying
each envelope (`scan`; `balance`, `send` and `lock` look first). Every other output is
sealed to the payer's own key, so every memo looks alike and a key alone restores a wallet:

    newsatoshi --datadir /tmp/c restore KEY      # then let a node sync there, and: scan --all

The job key is derived from the same key. A payment to a plain address still needs its note
string (`receive`). A break of ML-KEM would show who paid whom; it could never move a coin,
because spending takes the payee's key, proven inside a proof built on SHA-256 alone.

## Locks and swaps with Lightning

A spend can lock coins to a SHA-256 hash and a timeout height, naming a claim address and
a refund address (`src/lock.rs`). Until the timeout, publishing the 32-byte preimage
releases the coins to the claim address, whoever publishes it; after it, anyone can return
them to the refund address. Both payouts are fixed when the lock is made, so nothing needs
signing. The hash is Lightning's payment hash, so a lock here and a Lightning payment can
be made to stand or fall together:

    newsatoshi lock 2.5 --hash H --to ADDRESS [--blocks 60]
    newsatoshi unlock LOCKID PREIMAGE
    newsatoshi expire LOCKID
    newsatoshi locks

`src/swap.rs` is a swap server on that lock, run beside an LND node (REST, `no-rest-tls`,
on a private network):

    newsatoshi --net testnet node --status 8080 --swap-lnd HOST:PORT --swap-macaroon env:LND_MACAROON \
        [--swap-rate SATS_PER_COIN] [--swap-min SATS] [--swap-max SATS] [--swap-fee-ppm N]

It adds `GET /api/swap/info`, `POST /api/swap/in` (`{"hash","address","sats"}`: a hold
invoice for the buyer's hash; once it is paid and held, the server locks coins to the
buyer, who claims them with the secret, which settles the invoice), `POST /api/swap/out`
(`{"invoice"}`: the terms on which the server pays it once the payer's lock is in a
block; paying reveals the preimage that claims the lock) and `GET /api/swap?hash=`. If a
buyer never claims, the lock refunds the server and the held payment is cancelled; if an
invoice cannot be paid, the payer's lock goes back to them. On regtest, `--swap-fake`
runs the same server against a pretend Lightning, so the flow can be tried in the browser
wallet with nothing real at stake.

## Measured (two cores)

| | |
|---|---|
| spend proof | about 249 KB; a payment with its sealed notes, about 250 KB |
| prove | 2.1 s median |
| verify | about 10 ms native, 30–50 ms as WebAssembly in a browser |
| security | 128 bits proven classically (estimator 135, capped at SHA-256's collision resistance), 128 conjectured; about 67 proven against quantum attackers |
| spend circuit | 8,192 rows × 247 columns, 249 constraints, 3,584 random rows |
| SHA-256d | 3.8–4.1 MH/s per CPU core |
| 512³ matrix product | about 2.7 s to compute, 12 ms to check |

`cargo run --release --example bench` reproduces these.

The browser verifier builds reproducibly: `sh ../wasm/build.sh` with rustc 1.97.0 and the
`wasm32-unknown-unknown` target prints SHA-256
035fd3c1fa24d6d31ee9c1e29173e197c1683240dd41506a018b83c56bb34353, the exact file the site
runs. The script copies the source to one fixed path (`/tmp/newsatoshi-wasm-build`) and
builds there, so the result does not depend on where you unpacked it. Then

    cargo run --release --example fixture -- ../wasm/fixture   # a real spend proof
    node ../wasm/test.mjs

checks that proof with it, tampers with copies, and feeds it the malformed proofs from the
attack log.

## Layout

    src/hash.rs     SHA-256 compression; SHA-256 as the STARK's hasher
    src/note.rs     addresses, commitments, nullifiers, the depth-32 note tree
    src/spend.rs    the spend circuit (AIR), trace builder, prover, verifier
    src/audit.rs    the circuit's soundness scan: which cells are free, and which may be
    src/job.rs      verified-work escrow, Freivalds, fraud proofs, SLH-DSA
    src/lock.rs     payments locked to a SHA-256 hash and a timeout
    src/deliver.rs  payments delivered on chain, sealed with ML-KEM-768
    src/light.rs    a light client: headers checked, the committed note-tree root
    src/nftree.rs   every nullifier, sorted in a Merkle tree: spent and unspent proven
    src/script.rs   the language conditions are written in
    src/cond.rs     coins under conditions: a committed program chooses the payout
    src/peers.rs    the address book through which nodes find each other
    src/swap.rs     swaps with Lightning: hold invoices, LND's REST interface, the server
    src/pow.rs      compact targets, chain work, ASERT
    src/auxpow.rs   merged mining with Bitcoin (Namecoin's AuxPoW)
    src/rpc.rs      JSON-RPC for pools; the public API for wallets; the testnet faucet
    src/params.rs   networks and the Solvency Rule
    src/tx.rs       transactions, headers, blocks
    src/state.rs    ledger state and every validity rule
    src/chain.rs    fork choice, reorganisation, storage
    src/wallet.rs   keys, note strings, scanning, building and proving spends
    src/node.rs     P2P, mempool, miner
    vendor/         Winterfell 0.13.1's air, prover and verifier, with the segment masks
    ../wasm         the verifier compiled for browsers
    ../walletwasm   the browser wallet's prover: keys, nullifiers, envelopes, spend proofs

## Read before trusting it

This is v0.1, a testnet release for review. A pre-release adversarial review found the
problems listed in the attack log (entries 21 to 33); the ones in the code are fixed and
`tests/attacks.rs` replays each attack.

0. **The spend circuit has no machine-checked proof yet.** A private coin can be
   counterfeited unseen if its circuit leaves one value free: Zcash's Orchard circuit
   did for four years, until June 2026, and nobody can prove it was never used. No count
   of the supply can catch that, here or anywhere. What stands against it here: a small
   circuit (one hash function, 249 constraints, no curves, no lookups), and a scan that
   anyone can repeat. `src/audit.rs` changes each of the circuit's 1,138,176 active cells
   in turn and requires the constraints to refuse the change unless the cell is listed
   as free, then solves for every joint first-order move and requires those to be the
   listed ones too. It finds the list and nothing else (1,079,344 cells fixed; 58,832
   free by design: randomness and cells no rule reads), and it finds a hole planted to
   check it. `tests/soundness.rs` runs it on every build and also builds the one second
   encoding a local scan cannot see (a digest word written 2^32 too large, absorbed by
   the next compression's carries) to show nothing that reads the word changes. That is
   evidence, not proof. Zcash's Ironwood pool set the standard in July 2026 with a proof
   of its balance in Lean; mainnet here waits for the same (LAUNCH.md, condition 7).

1. **Zero knowledge is built, and unreviewed.** Winterfell 0.13 does not randomise proofs,
   so the circuit does it itself: 3,584 random rows hide every trace value a proof opens,
   and three random columns mask the low-degree test. The quotient segments, which are
   opened separately, are masked as Haböck and Al Kindi set out (ePrint 2024/1037), in a
   patched Winterfell 0.13.1 (`vendor/`, each change marked `NEWSATOSHI patch`): the
   quotient is split into four segments with stride n − k instead of three, and
   neighbouring segments share a random polynomial of k = 2 × queries + 3 coefficients,
   added to one and subtracted from the other, which cancels in the sum the verifier
   checks. k covers the 2 out-of-domain points, the queried rows and the neighbouring
   rows whose hashes a commitment shows, so no salt is needed. A masked proof says so in
   its trace metadata (`spend::ZK_META`), which the transcript binds. The test network
   still accepts the unmasked proofs in its history; the main network accepts masked ones
   only. The construction is theirs; this code has had no outside reader yet.
2. **The chain proof is not built.** Each transaction carries its own proof inside its block,
   so a block holds about 32 payments and checking the chain means checking every proof.
   The white paper's design (one recursive chain proof per block, six blocks behind, so a
   phone checks the whole history in milliseconds) is the main work before mainnet, with
   conditions. Until then, the light client (`src/light.rs`, run by the wallet page) checks
   headers, the note-tree root a block commits to and, from the test network's height
   3,900, the nullifier tree's root, so that a note's being unspent is proven too:
   Bitcoin's SPV security, not validity. `CHAIN-PROOF.md` measures what the chain proof
   costs (about 9,300 SHA-256 compressions to check one payment proof inside a circuit)
   and sets out how it gets built.
3. **Post-quantum margin.** The quantum random-oracle proof loses a square: these
   parameters prove about 67 bits against a quantum attacker. Mainnet sets its parameters
   for a stated margin (see LAUNCH.md).
4. **Range checks.** The one window word never range-checked, W_0, is only used modulo 2^32;
   values are bounded below 2^60 inside the circuit. Read `eval_constraints` with that in mind.
5. **Networking** is small: per-message size caps, per-peer queues, a peer limit, proofs
   checked outside the node's lock, fee-rate mempool with a minimum relay fee, an address
   book that nodes fill for each other, and headers checked (linkage, work, difficulty,
   time, checkpoints) before any block is fetched. There is no ban score yet: a malformed
   message ends the connection, and nothing is held against the peer after it.
6. **Dependencies.** winterfell 0.13.1 (MIT), slh-dsa 0.1.0 (RustCrypto, FIPS 205),
   ml-kem 0.2.3 (RustCrypto, FIPS 203, only for delivering notes), sha2, primitive-types,
   rand, hex. slh-dsa is pinned to the pre-release of `signature` it was built against.

Attacks that land go into the next version with the attacker's name on them.

## Licence

MIT. See LICENSE.
