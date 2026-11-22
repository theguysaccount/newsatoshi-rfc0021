# Opening the main network

Prepared and run on 10 November 2026. Genesis `000000006ba30cc3c86ecaabcb962287e9d5fd0877c27f4b33661b4d1d3033f7`, over Bitcoin
block 975,317, read from two sources (mempool.space and blockstream.info agreed). The seeds
run the main network's node beside the test network's (`deploy/seed-start.sh`), without
mining. What follows is the procedure as it was run, kept for the next network.

## 0. What must be true first

`LAUNCH.md` lists the conditions. Two decisions change consensus, so both are made before
genesis and never after:

1. **Which conditions are waited for.** The path on the table: open when the payment
   circuit has its machine-checked proof (condition 7), without waiting for the chain proof
   (condition 2), which then arrives by a later rule change every node must take.
2. **The launch ramp** (attack log, 49). Decided 10 Nov 2026: as planned. Difficulty starts
   at 1 and doubles for every 288 blocks that arrive early, so a fast first miner can take
   about 1.6% of all coins in the first day. Mining opens to everyone at the announced
   moment of step 3, and the project's nodes do not mine at the opening.

## 1. The day before: freeze and prove the release

    cargo test --release                                   # 99 tests, all pass
    cargo run --release --example fuzz -- 120              # ten kinds of input, no findings
    cargo run --release --example soundness_scan           # the payment circuit, cell by cell
    cargo run --release --example extract_constraints -- proof/constraints.json
    python3 proof/check.py proof/constraints.json          # the circuit against its specification
    sh ../wasm/build.sh                                    # the browser verifier's hash

Then the rehearsal, with the release's own binary. Two nodes, a faucet, and the browser
wallet's engine making a payment through them:

    newsatoshi --net rehearsal --datadir /tmp/dry-a node --port 28644 --no-seeds \
        --mine --interval 1 --status 28080 --faucet 5
    newsatoshi --net rehearsal --datadir /tmp/dry-b node --port 28645 \
        --peer 127.0.0.1:28644 --status 28081
    # after 101 blocks (a coinbase waits 100):
    node ../walletwasm/test.mjs http://127.0.0.1:28080

It must print a proof made in WebAssembly, the payment mined, the change found by the key
alone, and a payment to a delivery address found by its payee. Stop the second node, start
it again, and it must return to the first node's tip from its own disk.

## 2. Genesis

The genesis block pays no one, and its message names a Bitcoin block found that day, so
nobody, this project included, can have mined it or anything on it earlier.

1. Take the newest Bitcoin block from two independent sources. Write one line into
   `GENESIS-MAINNET.txt`, in the test network's form:

       btc HEIGHT HASH a line of your choosing

   The whole line is at most 120 bytes, the room a coinbase has: after the height and
   the 64-character hash, about 43 characters are left for the words.

2. Build, and mine it (about 4.3 billion hashes: some twenty minutes of one core):

       cargo build --release
       newsatoshi --net mainnet genesis

3. Put the time and nonce it prints into `src/params_genesis.rs` (`MAIN`), name the seed
   nodes in `Params::main_with` (`src/params.rs`), and build again. From this build on,
   `newsatoshi --net mainnet info` prints the genesis hash. Run the tests once more.

## 3. Opening

The project does not mine. Its nodes are there to be found, not to collect the first
coins.

1. Start the seeds, in two regions, with no `--mine`:

       newsatoshi --net mainnet --datadir /data node --port 8444 \
           --external HOST:8444 --status 8080

2. Check from outside: each seed answers `/status` with network `mainnet`, the genesis
   hash, height 0, and the other seed among its peers.
3. Publish, at one moment: the source archive and its SHA-256, the genesis hash, the
   message and the Bitcoin block it names, the seeds' addresses, and the browser
   verifier's hash. Mining is open to everyone from that moment and to no one before it.
4. The site's wallet page reads the network's fee and its kind of proof from the node it
   talks to (`/status`: `fee`, `proofs`), so pointing the site at main-network nodes is a
   change to `deploy/site.nginx.conf` and nothing else.

## 4. The first week

- Watch `/status` on both seeds: height, the time since the last block, peers, mempool.
- A release checkpoint (`LAUNCH.md`) goes into the first release after the chain is a few
  days old.
- Memory: nodes hold the newest 12 block bodies and read the rest from disk, and their
  kept states share what they have in common (attack log, 50). What still grows is the
  state itself, about 565 bytes for each note with a spent nullifier: at full blocks some
  3 MB a day. A node with 4 GB lasts years; moving the state to disk is later work.

## What cannot be undone

The genesis block, the block format, the proof parameters, the issuance schedule and the
difficulty rule are fixed by the first block that others build on. Everything else in this
file can be done again.
