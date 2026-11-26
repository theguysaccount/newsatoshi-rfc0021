//! newsatoshi — the reference node and wallet.

use newsatoshi::chain::{genesis_block, mine, Chain};
use newsatoshi::job::{self, Action, Deposit, JobClaim, JobKey, JobPost, Phase, RowOpening};
use newsatoshi::cond::{self, CondPost};
use newsatoshi::lock::{lock_id, LockPost};
use newsatoshi::script;
use newsatoshi::node::{self, Node};
use newsatoshi::params::{subsidy, Net, Params, COIN};
use newsatoshi::pow;
use newsatoshi::tx::{hash_hex, PlainOut, Tx};
use newsatoshi::wallet::{self, Wallet};
use std::path::PathBuf;
use std::time::Instant;

const USAGE: &str = "newsatoshi — proof of work orders, proof of negentropy validates

usage: newsatoshi [--net regtest|testnet|rehearsal] [--datadir DIR] <command>

  node [--port P] [--peer HOST:PORT]... [--mine [--interval S] [--mine-duty PCT]]   run a full node, optionally mining
                                                (with no --peer it finds the network's seeds; --no-seeds to stay alone)
       [--maxout N] [--external HOST:PORT]       dial up to N peers from the address book it learns (default 8, 0: none);
                                                --external is the address others should reach this node at
       [--rpc PORT [--rpcbind ADDR] [--rpcauth USER:PASS]]       JSON-RPC for pools: merged mining with Bitcoin
                                                (createauxblock / getauxblock / submitauxblock, as Namecoin)
       [--status PORT [--statusbind ADDR] [--faucet COINS]]      public JSON: status, the wallet API, a testnet faucet
       [--swap-lnd HOST:PORT --swap-macaroon FILE|HEX|env:VAR    swaps with Lightning through an LND node (REST, no-rest-tls)
        [--swap-rate SATS_PER_COIN] [--swap-min SATS] [--swap-max SATS] [--swap-fee-ppm N] [--swap-network NAME]]
       [--swap-fake]                                             regtest only: swaps with a pretend Lightning, to try the flow
  info                                          chain height, tip, difficulty, supply, notes, jobs
  address [--delivery]                          your shielded address; --delivery: the long nsd1… address,
                                                payments to which arrive on chain with nothing to pass on
  balance                                       your spendable balance, once it has looked for payments delivered to you
  send ADDRESS COINS [--fee COINS] [--memo T]   prove and submit a private payment: to an nsd1… address it arrives by
                                                itself; to an ns1… address, give the payee the note it prints
  receive NOTE                                  accept a note a payer gave you
  scan [--all]                                  look for payments delivered to you (--all: the whole chain)
  restore KEY                                   a wallet from its spending key (64 hex characters), in a new --datadir
  lock COINS --hash H --to ADDRESS [--blocks N] lock coins to a SHA-256 hash: ADDRESS claims with the preimage
                                                until N blocks from now (default 60); after that they come back to you
  unlock LOCKID PREIMAGE                        release a lock to its claim address by publishing the preimage
  expire LOCKID                                 release a timed-out lock to its refund address
  locks                                         list open locks
  signing-key                                   your public signing key (SLH-DSA), for conditions and jobs
  cond COINS --pay ADDR[,ADDR..] (--program TEXT | --two-of-three KEY,KEY,KEY) [--blocks N]
                                                lock coins to a condition: a program that chooses among the
                                                payouts (the first is payout 0); after N blocks they come back
  cond-sign CONDID PAYOUT                       sign a condition's release to one payout with your signing key
  fulfil CONDID PAYOUT [--witness HEX,HEX..] [--salt HEX --program TEXT]
                                                release coins under a condition by running its program
  conds                                         list open conditions
  program TEXT                                  assemble a condition program and print it in hex
  job post A.csv B.csv --pay C --bond C [--claim N] [--deliver N] [--window N]
  job claim JOBID --bond COINS
  job commit JOBID C.csv                        commit your result's root (sign with your job key)
  job check JOBID A.csv B.csv C.csv [--fraud]   Freivalds check; with --fraud, submit the proof of a wrong entry
  job accept|finalize|refund JOBID
  jobs                                          list jobs
  demo                                          an in-process tour: payment, honest job, cheating job
";

struct Opts {
    net: Net,
    dir: PathBuf,
    rest: Vec<String>,
}

fn opts() -> Result<Opts, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut net = Net::Reg;
    let mut dir = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--net" => {
                net = Params::parse(&args[i + 1])?;
                args.drain(i..i + 2);
            }
            "--datadir" => {
                dir = Some(PathBuf::from(&args[i + 1]));
                args.drain(i..i + 2);
            }
            _ => i += 1,
        }
    }
    // every command needs a network that exists, except the one that mines the main
    // network's genesis block
    let name = match Params::get(net) {
        Ok(p) => p.name,
        Err(_)
            if net == Net::Main
                && args
                    .first()
                    .map(|a| a == "genesis" || a == "genesis-v2")
                    .unwrap_or(false) =>
        {
            "mainnet"
        }
        Err(e) => return Err(e),
    };
    let dir = dir.unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or(".".into())).join(".newsatoshi").join(name));
    Ok(Opts { net, dir, rest: args })
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1).cloned())
}

/// The coin's name and ticker. The site's build reads it from here, so this is the one switch.
const TICKER: &str = "LOVE";

fn coins(s: &str) -> Result<u64, String> {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if f.len() > 8 {
        return Err("at most 8 decimal places".into());
    }
    let whole: u64 = w.parse().map_err(|_| format!("bad amount {s}"))?;
    let frac: u64 = if f.is_empty() { 0 } else { format!("{f:0<8}").parse().map_err(|_| format!("bad amount {s}"))? };
    whole.checked_mul(COIN).and_then(|x| x.checked_add(frac)).ok_or_else(|| "amount too large".into())
}

fn fmt(v: u128) -> String {
    format!("{}.{:08}", v / COIN as u128, v % COIN as u128)
}

fn read_matrix(path: &str) -> Result<Vec<Vec<u64>>, String> {
    let t = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    t.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(',').map(|x| x.trim().parse::<u64>().map(job::reduce).map_err(|_| format!("{path}: bad entry {x}"))).collect())
        .collect()
}

fn transpose(m: &[Vec<u64>]) -> Vec<Vec<u64>> {
    if m.is_empty() {
        return vec![];
    }
    (0..m[0].len()).map(|j| m.iter().map(|r| r[j]).collect()).collect()
}

/// A macaroon given as a file, as hex, or as `env:NAME`.
fn read_macaroon(s: &str) -> Result<String, String> {
    if let Some(var) = s.strip_prefix("env:") {
        return std::env::var(var).map(|v| v.trim().to_string()).map_err(|_| format!("environment variable {var} is not set"));
    }
    if std::path::Path::new(s).exists() {
        return std::fs::read(s).map(hex::encode).map_err(|e| format!("{s}: {e}"));
    }
    if hex::decode(s.trim()).is_ok() {
        return Ok(s.trim().to_string());
    }
    Err("--swap-macaroon takes a file, hex, or env:NAME".into())
}

/// The swap server, if the flags ask for one: through an LND node, or (regtest only) with
/// a pretend Lightning for trying the flow.
fn swap_server(o: &Opts, shared: &node::Shared, wallet: &newsatoshi::rpc::SharedWallet) -> Result<Option<std::sync::Arc<newsatoshi::swap::Swap>>, String> {
    use newsatoshi::swap::{Lnd, Swap, SwapCfg};
    if o.rest.iter().any(|a| a == "--swap-fake") {
        if o.net != Net::Reg {
            return Err("--swap-fake is for regtest: its Lightning is pretend".into());
        }
        println!("swaps with a pretend Lightning (regtest)");
        let sw = Swap::new_fake(wallet.clone(), SwapCfg { in_lock_blocks: 10, out_lock_blocks: 20, out_min_left: 5, ..Default::default() });
        sw.start(shared.clone());
        return Ok(Some(sw));
    }
    let Some(addr) = flag(&o.rest, "--swap-lnd") else { return Ok(None) };
    let mac = read_macaroon(&flag(&o.rest, "--swap-macaroon").ok_or("--swap-lnd needs --swap-macaroon FILE|HEX|env:VAR")?)?;
    let mut cfg = SwapCfg::default();
    let num = |f: &str| flag(&o.rest, f).map(|x| x.parse::<u64>().map_err(|_| format!("{f} takes a number"))).transpose();
    if let Some(x) = num("--swap-rate")? {
        cfg.sats_per_coin = x.max(1);
    }
    if let Some(x) = num("--swap-min")? {
        cfg.min_sats = x;
    }
    if let Some(x) = num("--swap-max")? {
        cfg.max_sats = x;
    }
    if let Some(x) = num("--swap-fee-ppm")? {
        cfg.fee_ppm = x.min(1_000_000);
    }
    if let Some(x) = flag(&o.rest, "--swap-network") {
        cfg.ln_network = x;
    }
    println!("swaps with Lightning through {addr}: {} sats a {TICKER}, {} to {} sats, network {}", cfg.sats_per_coin, cfg.min_sats, cfg.max_sats, cfg.ln_network);
    let sw = Swap::new(std::sync::Arc::new(Lnd::new(&addr, &mac)), wallet.clone(), cfg, Some(o.dir.join("swaps.json")));
    sw.start(shared.clone());
    Ok(Some(sw))
}

fn parse_job(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| "job id must be 64 hex characters".into())
}

fn open_chain(o: &Opts) -> Result<Chain, String> {
    Chain::open(Params::get(o.net)?, Some(&o.dir))
}

/// The wallet, with any payments delivered to it since it last looked.
fn synced(path: &std::path::Path, c: &Chain) -> Result<Wallet, String> {
    let mut w = Wallet::load_or_create(path)?;
    let found = w.scan(c)?;
    if found > 0 {
        println!("{found} payment{} delivered to you", if found == 1 { "" } else { "s" });
    }
    Ok(w)
}

fn submit(o: &Opts, tx: &Tx) -> Result<(), String> {
    let p = Params::get(o.net)?;
    let port = std::fs::read_to_string(o.dir.join("port")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(p.default_port);
    node::submit(&format!("127.0.0.1:{port}"), p.magic, tx)?;
    println!("submitted {}", hash_hex(&tx.id()));
    Ok(())
}

fn opening(rows: &[Vec<u64>], i: u32) -> RowOpening {
    let lv = job::tree_levels(&rows.iter().map(|r| job::leaf(r)).collect::<Vec<_>>());
    RowOpening { i, values: rows[i as usize].clone(), path: job::path_of(&lv, i as usize) }
}

fn run() -> Result<(), String> {
    let o = opts()?;
    let cmd: Vec<&str> = o.rest.iter().map(|s| s.as_str()).collect();
    std::fs::create_dir_all(&o.dir).map_err(|e| e.to_string())?;
    let wallet_path = o.dir.join("wallet.dat");
    match cmd.as_slice() {
        ["node", ..] => {
            let p = Params::get(o.net)?;
            let port: u16 = flag(&o.rest, "--port").and_then(|x| x.parse().ok()).unwrap_or(p.default_port);
            std::fs::write(o.dir.join("port"), port.to_string()).map_err(|e| e.to_string())?;
            let chain = open_chain(&o)?;
            println!(
                "newsatoshi {} on {} — height {} tip {}{}",
                env!("CARGO_PKG_VERSION"),
                p.name,
                chain.height(),
                hash_hex(&chain.tip().hash),
                if chain.fast_boot { " (verified fast-boot snapshot)" } else { "" }
            );
            let shared = Node::new(chain);
            {
                let mut n = node::lock(&shared);
                n.listen_port = Some(port);
                n.book = newsatoshi::peers::AddrBook::open(Some(o.dir.join("peers.txt")));
                if let Some(e) = flag(&o.rest, "--external") {
                    if !newsatoshi::peers::valid(&e) {
                        return Err("--external takes HOST:PORT".into());
                    }
                    n.external = e;
                }
                println!("{} addresses known", n.book.map.len());
            }
            node::listen(shared.clone(), port)?;
            node::keepalive(shared.clone());
            let maxout: usize = flag(&o.rest, "--maxout").and_then(|x| x.parse().ok()).unwrap_or(8);
            if maxout > 0 {
                node::discover(shared.clone(), maxout, std::time::Duration::from_secs(30));
            }
            let mut named = false;
            for (i, a) in o.rest.iter().enumerate() {
                if a == "--peer" {
                    let addr = o.rest.get(i + 1).ok_or("--peer takes HOST:PORT")?.clone();
                    println!("peer {addr}");
                    node::keep_connected(shared.clone(), addr);
                    named = true;
                }
            }
            if !named && !o.rest.iter().any(|a| a == "--no-seeds") {
                let mut seeds: Vec<String> = p.seeds.iter().map(|s| s.to_string()).collect();
                if let Ok(extra) = std::env::var("NEWSATOSHI_SEEDS") {
                    for s in extra.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
                        if !seeds.iter().any(|e| e == s) {
                            seeds.push(s.to_string());
                        }
                    }
                }
                for addr in seeds {
                    println!("seed {addr}");
                    node::keep_connected(shared.clone(), addr);
                }
            }
            if let Some(sport) = flag(&o.rest, "--status") {
                let sport: u16 = sport.parse().map_err(|_| "--status takes a port")?;
                let bind = flag(&o.rest, "--statusbind").unwrap_or_else(|| "127.0.0.1".into());
                // one wallet behind the faucet and the swap server, so they never pick the same note
                let node_wallet: newsatoshi::rpc::SharedWallet = std::sync::Arc::new(std::sync::Mutex::new(Wallet::load_or_create(&wallet_path)?));
                let faucet = match flag(&o.rest, "--faucet") {
                    Some(c) => {
                        let amount = coins(&c)?;
                        println!("faucet: {} {TICKER} per request", fmt(amount as u128));
                        Some(newsatoshi::rpc::Faucet::new(node_wallet.clone(), amount))
                    }
                    None => None,
                };
                let swap = swap_server(&o, &shared, &node_wallet)?;
                let port = newsatoshi::rpc::serve_public_with(shared.clone(), &bind, sport, faucet, swap)?;
                println!("status and wallet API on http://{bind}:{port}/ (open to all)");
            }
            if let Some(rport) = flag(&o.rest, "--rpc") {
                let rport: u16 = rport.parse().map_err(|_| "--rpc takes a port")?;
                let bind = flag(&o.rest, "--rpcbind").unwrap_or_else(|| "127.0.0.1".into());
                let user_pass = match flag(&o.rest, "--rpcauth") {
                    Some(a) if a.contains(':') => a,
                    Some(_) => return Err("--rpcauth takes USER:PASS".into()),
                    None => {
                        // as Bitcoin Core: a fresh password in a file only this user can read
                        let cookie = format!("__cookie__:{}", hex::encode(rand::random::<[u8; 32]>()));
                        let path = o.dir.join(".cookie");
                        std::fs::write(&path, &cookie).map_err(|e| e.to_string())?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                        }
                        println!("rpc password in {}", path.display());
                        cookie
                    }
                };
                let w = Wallet::load_or_create(&wallet_path)?;
                let rpc = newsatoshi::rpc::Rpc::new(shared.clone(), &user_pass, w.a_pk());
                let port = newsatoshi::rpc::serve(rpc, &bind, rport)?;
                println!("rpc on {bind}:{port}; merged mining as Namecoin does, chain id {}, getauxblock pays {}", newsatoshi::auxpow::CHAIN_ID, w.address());
            }
            if o.rest.iter().any(|a| a == "--mine") {
                let w = Wallet::load_or_create(&wallet_path)?;
                println!("mining to {}", w.address());
                let secs: u64 = flag(&o.rest, "--interval").and_then(|x| x.parse().ok()).unwrap_or(if o.net == Net::Reg { 2 } else { 0 });
                let duty: u32 = flag(&o.rest, "--mine-duty").and_then(|x| x.parse().ok()).unwrap_or(100);
                node::run_miner_duty(shared.clone(), w.a_pk(), std::time::Duration::from_secs(secs), duty);
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        ["info"] => {
            let c = open_chain(&o)?;
            let t = c.tip();
            let s = &c.state;
            println!("network     {}", c.params.name);
            println!("height      {}", t.height);
            println!("tip         {}", hash_hex(&t.hash));
            println!("genesis     {}", hash_hex(&c.genesis));
            println!("next bits   {:08x} (work per block {})", c.next_bits(t), pow::work(c.next_bits(t)));
            println!("chain work  {}", t.work);
            println!("subsidy     {} per block", fmt(subsidy(t.height + 1) as u128));
            println!("issued      {}", fmt(s.issued));
            println!("burned      {}", fmt(s.burned));
            println!("in escrow   {}", fmt(s.locked));
            println!("shielded    {}", fmt(s.shielded_supply()));
            println!("notes       {}  nullifiers {}  jobs {}", s.tree.len(), s.nullifiers.len(), s.jobs.len());
        }
        ["address"] => println!("{}", Wallet::load_or_create(&wallet_path)?.address()),
        ["address", "--delivery"] => println!("{}", Wallet::load_or_create(&wallet_path)?.delivery_address()),
        ["balance"] => {
            let c = open_chain(&o)?;
            let w = synced(&wallet_path, &c)?;
            let u = w.unspent(&c);
            println!("{} in {} notes", fmt(u.iter().map(|x| x.v as u128).sum()), u.len());
        }
        ["send", addr, amount, ..] => {
            let c = open_chain(&o)?;
            let mut w = synced(&wallet_path, &c)?;
            let fee = flag(&o.rest, "--fee").map(|f| coins(&f)).transpose()?.unwrap_or(c.params.default_fee);
            let memo = flag(&o.rest, "--memo").unwrap_or_default().into_bytes();
            let t = Instant::now();
            let (tx, note) = w.pay(&c, addr, coins(amount)?, fee, memo)?;
            println!("proved in {} ms, {} bytes", t.elapsed().as_millis(), tx.to_bytes().len());
            submit(&o, &tx)?;
            if addr.trim().starts_with("nsd1") {
                println!("it travels on chain, sealed to the payee's key: their wallet finds it by itself");
            } else {
                println!("give the payee this note:\n{}", note.unwrap_or_default());
            }
        }
        ["scan", ..] => {
            let c = open_chain(&o)?;
            let mut w = Wallet::load_or_create(&wallet_path)?;
            if o.rest.iter().any(|a| a == "--all") {
                w.scanned = 0;
            }
            let found = w.scan(&c)?;
            let u = w.unspent(&c);
            println!("{found} new; through height {}, {} in {} notes", c.height(), fmt(u.iter().map(|x| x.v as u128).sum()), u.len());
        }
        ["restore", key] => {
            let mut w = Wallet::restore(&wallet_path, key)?;
            let c = open_chain(&o)?;
            let found = w.scan(&c)?;
            println!("restored {}", w.address());
            println!("{} found through height {}: {} {TICKER} spendable", found, c.height(), fmt(w.balance(&c) as u128));
            println!("a node syncing in this --datadir brings the rest of the chain; then run scan --all");
        }
        ["receive", note] => {
            let mut w = Wallet::load_or_create(&wallet_path)?;
            println!("received {}", fmt(w.import(note)? as u128));
        }
        ["lock", amount, ..] => {
            let c = open_chain(&o)?;
            let mut w = synced(&wallet_path, &c)?;
            let hash = parse_job(&flag(&o.rest, "--hash").ok_or("--hash required: SHA-256 of the preimage, 64 hex characters")?)?;
            let to = newsatoshi::deliver::parse_any_address(&flag(&o.rest, "--to").ok_or("--to required: the address that claims with the preimage")?)?.0;
            let blocks: u32 = flag(&o.rest, "--blocks").and_then(|x| x.parse().ok()).unwrap_or(60);
            let post = LockPost { hash, timeout: c.height() + 1 + blocks, claim_addr: to, refund_addr: w.a_pk(), amount: coins(amount)? };
            let (tx, _) = w.spend(&c, None, c.params.default_fee, Some(Deposit::Lock(post.clone())), vec![])?;
            let Tx::Spend(sp) = &tx else { unreachable!() };
            submit(&o, &tx)?;
            println!("lock {} until height {}", hex::encode(lock_id(&post, &sp.nf[0])), post.timeout);
        }
        ["unlock", id, preimage] => {
            submit(&o, &Tx::Act(Action::Unlock { lock: parse_job(id)?, preimage: parse_job(preimage)? }))?;
        }
        ["expire", id] => {
            submit(&o, &Tx::Act(Action::Expire { lock: parse_job(id)? }))?;
        }
        ["signing-key"] => println!("{}", hex::encode(Wallet::load_or_create(&wallet_path)?.job_key()?.vk())),
        ["program", text] => println!("{}", hex::encode(script::assemble(text)?)),
        ["cond", amount, ..] => {
            use rand::Rng;
            let c = open_chain(&o)?;
            let mut w = synced(&wallet_path, &c)?;
            let pays = flag(&o.rest, "--pay").ok_or("--pay required: the payout addresses, comma-separated")?;
            let payouts = pays.split(',').map(|a| newsatoshi::deliver::parse_any_address(a).map(|x| x.0)).collect::<Result<Vec<_>, _>>()?;
            let program = match (flag(&o.rest, "--program"), flag(&o.rest, "--two-of-three")) {
                (Some(t), None) => script::assemble(&t)?,
                (None, Some(keys)) => {
                    let k: Vec<&str> = keys.split(',').collect();
                    if k.len() != 3 {
                        return Err("--two-of-three takes three signing keys".into());
                    }
                    script::assemble(&format!("2 0x{} 0x{} 0x{} 3 CHECKMULTISIG", k[0], k[1], k[2]))?
                }
                _ => return Err("give --program TEXT or --two-of-three KEY,KEY,KEY".into()),
            };
            let salt: [u8; 32] = rand::thread_rng().gen();
            let blocks: u32 = flag(&o.rest, "--blocks").and_then(|x| x.parse().ok()).unwrap_or(1_440);
            let post = CondPost { commitment: cond::commitment(&salt, &program), payouts, timeout: c.height() + 1 + blocks, refund_addr: w.a_pk(), amount: coins(amount)? };
            let (tx, _) = w.spend(&c, None, c.params.default_fee, Some(Deposit::Cond(post.clone())), vec![])?;
            let Tx::Spend(sp) = &tx else { unreachable!() };
            let id = cond::cond_id(&post, if sp.dummy[0] { &sp.nf[1] } else { &sp.nf[0] });
            submit(&o, &tx)?;
            // the salt and program are needed to release the coins: kept here, and printed to share
            let line = format!("{} {} {}\n", hex::encode(id), hex::encode(salt), hex::encode(&program));
            use std::io::Write;
            std::fs::OpenOptions::new().create(true).append(true).open(o.dir.join("conditions.txt")).and_then(|mut f| f.write_all(line.as_bytes())).map_err(|e| e.to_string())?;
            println!("condition {} until height {}", hex::encode(id), post.timeout);
            println!("salt {}\nprogram {}", hex::encode(salt), hex::encode(&program));
            println!("(kept in {}; whoever releases the coins needs both)", o.dir.join("conditions.txt").display());
        }
        ["cond-sign", id, payout] => {
            let w = Wallet::load_or_create(&wallet_path)?;
            let payout: u8 = payout.parse().map_err(|_| "PAYOUT is a number: 0 for the first address")?;
            println!("{}", hex::encode(w.job_key()?.sign(&cond::sign_message(&parse_job(id)?, payout))));
        }
        ["fulfil", id, payout, ..] => {
            let id = parse_job(id)?;
            let payout: u8 = payout.parse().map_err(|_| "PAYOUT is a number: 0 for the first address")?;
            let (salt, program) = match (flag(&o.rest, "--salt"), flag(&o.rest, "--program")) {
                (Some(s), Some(p)) => (parse_job(&s)?, script::assemble(&p).or_else(|_| hex::decode(&p).map_err(|e| e.to_string()))?),
                _ => {
                    let kept = std::fs::read_to_string(o.dir.join("conditions.txt")).unwrap_or_default();
                    let line = kept.lines().find(|l| l.starts_with(&hex::encode(id))).ok_or("this condition's salt and program are not kept here: give --salt and --program")?;
                    let f: Vec<&str> = line.split_whitespace().collect();
                    (parse_job(f[1])?, hex::decode(f[2]).map_err(|e| e.to_string())?)
                }
            };
            let witness = match flag(&o.rest, "--witness") {
                Some(ws) => ws.split(',').map(|x| hex::decode(x).map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?,
                None => vec![],
            };
            submit(&o, &Tx::Act(Action::Fulfil { cond: id, payout, salt, program, witness }))?;
        }
        ["conds"] => {
            let c = open_chain(&o)?;
            for x in c.state.conds.values() {
                let pays: Vec<String> = x.post.payouts.iter().map(wallet::encode_address).collect();
                println!("{}  {}  until {}  payouts {}", hex::encode(x.id), fmt(x.post.amount as u128), x.post.timeout, pays.join(","));
            }
        }
        ["locks"] => {
            let c = open_chain(&o)?;
            for l in c.state.locks.values() {
                println!("{}  {}  hash {}  until {}  to {}", hex::encode(l.id), fmt(l.post.amount as u128), hex::encode(l.post.hash), l.post.timeout, wallet::encode_address(&l.post.claim_addr));
            }
        }
        ["jobs"] => {
            let c = open_chain(&o)?;
            for j in c.state.jobs.values() {
                let ph = match &j.phase {
                    Phase::Open => "open".to_string(),
                    Phase::Claimed { at, .. } => format!("claimed at {at}"),
                    Phase::Committed { at, .. } => format!("committed at {at}"),
                    Phase::Challenged { at, .. } => format!("challenged at {at}"),
                    Phase::Closed { paid_worker } => if *paid_worker { "closed: worker paid".into() } else { "closed: refunded".into() },
                };
                println!("{}  {}×{}×{}  pay {}  {}", hex::encode(j.id), j.post.n, j.post.k, j.post.m, fmt(j.post.pay as u128), ph);
            }
        }
        ["job", "post", a, b, ..] => {
            let c = open_chain(&o)?;
            let mut w = synced(&wallet_path, &c)?;
            let (a, b) = (read_matrix(a)?, read_matrix(b)?);
            let b_cols = transpose(&b);
            let pay = coins(&flag(&o.rest, "--pay").ok_or("--pay required")?)?;
            let bond = coins(&flag(&o.rest, "--bond").unwrap_or_else(|| fmt(pay as u128)))?;
            let num = |f: &str, d: u32| flag(&o.rest, f).and_then(|x| x.parse().ok()).unwrap_or(d);
            let post = JobPost {
                poster_vk: w.job_key()?.vk(),
                poster_addr: w.a_pk(),
                n: a.len() as u32,
                k: a[0].len() as u32,
                m: b_cols.len() as u32,
                a_root: job::root_of(&a),
                b_root: job::root_of(&b_cols),
                pay,
                bond_min: bond,
                claim_by: c.height() + num("--claim", 144),
                deliver_blocks: num("--deliver", 144),
                window_blocks: num("--window", 144),
            };
            let (tx, _) = w.spend(&c, None, c.params.default_fee, Some(Deposit::Post(post.clone())), vec![])?;
            let Tx::Spend(sp) = &tx else { unreachable!() };
            let first = if sp.dummy[0] { sp.nf[1] } else { sp.nf[0] };
            submit(&o, &tx)?;
            println!("job {}", hex::encode(job::job_id(&post, &first)));
        }
        ["job", "claim", id, ..] => {
            let c = open_chain(&o)?;
            let mut w = synced(&wallet_path, &c)?;
            let bond = coins(&flag(&o.rest, "--bond").ok_or("--bond required")?)?;
            let claim = JobClaim { job: parse_job(id)?, worker_vk: w.job_key()?.vk(), worker_addr: w.a_pk(), bond };
            let (tx, _) = w.spend(&c, None, c.params.default_fee, Some(Deposit::Claim(claim)), vec![])?;
            submit(&o, &tx)?;
        }
        ["job", "commit", id, cpath] => {
            let w = Wallet::load_or_create(&wallet_path)?;
            let id = parse_job(id)?;
            let c_root = job::root_of(&read_matrix(cpath)?);
            submit(&o, &Tx::Act(Action::Commit { job: id, c_root, sig: w.job_key()?.sign(&job::msg_commit(&id, &c_root)) }))?;
        }
        ["job", "check", id, a, b, cm, ..] => {
            let (a, b_cols, cm) = (read_matrix(a)?, transpose(&read_matrix(b)?), read_matrix(cm)?);
            let t = Instant::now();
            match job::freivalds(&a, &b_cols, &cm, 2) {
                None => println!("Freivalds: consistent ({} ms). Accept it with: job accept {id}", t.elapsed().as_millis()),
                Some((i, j)) => {
                    println!("Freivalds: entry ({i}, {j}) is wrong ({} ms)", t.elapsed().as_millis());
                    if o.rest.iter().any(|x| x == "--fraud") {
                        let tx = Tx::Act(Action::Fraud { job: parse_job(id)?, a: opening(&a, i), b: opening(&b_cols, j), c: opening(&cm, i), j });
                        submit(&o, &tx)?;
                    }
                }
            }
        }
        ["job", act @ ("accept" | "finalize" | "refund"), id] => {
            let w = Wallet::load_or_create(&wallet_path)?;
            let id = parse_job(id)?;
            let a = match *act {
                "accept" => Action::Accept { job: id, sig: w.job_key()?.sign(&job::msg_accept(&id)) },
                "finalize" => Action::Finalize { job: id },
                _ => Action::Refund { job: id },
            };
            submit(&o, &Tx::Act(a))?;
        }
        ["genesis"] => {
            // The main network's genesis is mined once, on the day, over a message that
            // names a Bitcoin block of that day: nobody can have mined it earlier.
            let p = match o.net {
                Net::Main => {
                    let p = Params::main_with(newsatoshi::chain::now() as u32, u32::MAX);
                    if p.genesis_message.is_empty() {
                        return Err("write the genesis message into GENESIS-MAINNET.txt and build again (RUNBOOK.md)".into());
                    }
                    let (len, max) = (p.genesis_message.len(), newsatoshi::params::MAX_COINBASE_EXTRA);
                    if len > max {
                        return Err(format!("the genesis message is {len} bytes and a coinbase carries at most {max}: shorten the line after the Bitcoin block's hash"));
                    }
                    println!("mining the main network's genesis over: {}", p.genesis_message);
                    println!("about 4.3 billion hashes on average: some twenty minutes of one core");
                    p
                }
                _ => Params::get(o.net)?,
            };
            let mut g = genesis_block(&Params { genesis_nonce: u32::MAX, ..p.clone() });
            let t = Instant::now();
            g.header.nonce = 0;
            mine(&mut g.header, u64::MAX);
            println!("time {} nonce {} hash {} ({} ms)", g.header.time, g.header.nonce, hash_hex(&g.hash()), t.elapsed().as_millis());
        }
        ["genesis-v2", ..] => {
            let btc_hash = flag(&o.rest, "--btc-block-hash")
                .ok_or("usage: newsatoshi genesis-v2 --btc-block-hash <64HEX> --btc-height <HEIGHT> [--time <UNIX>] [--bits <HEX>] [--mine]")?;
            let btc_height: u64 = flag(&o.rest, "--btc-height")
                .ok_or("missing --btc-height <HEIGHT>")?
                .parse()
                .map_err(|_| "invalid --btc-height")?;
            let msg_owned = Params::format_v2_fair_launch_message(btc_height, &btc_hash)?;
            let msg_static: &'static str = Box::leak(msg_owned.clone().into_boxed_str());
            let time: u32 = match flag(&o.rest, "--time") {
                Some(s) => s.parse().map_err(|_| "invalid --time")?,
                None => newsatoshi::chain::now() as u32,
            };
            let bits: u32 = match flag(&o.rest, "--bits") {
                Some(s) => u32::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(|_| "invalid hex --bits")?,
                None => 0x1d00_ffff,
            };
            let do_mine = o.rest.iter().any(|a| a == "--mine");
            let mut p = Params::main_v2_with(time, u32::MAX, bits);
            p.genesis_message = msg_static;
            let mut g = genesis_block(&p);
            let fp = hex::encode(newsatoshi::hash::sha256(
                format!(
                    "nsV2GEN|{msg_owned}|{time}|{bits:#010x}|{}|{}|{}",
                    p.launch_blocks, p.launch_half_life, p.half_life
                )
                .as_bytes(),
            ));
            let mined_ms = if do_mine {
                let t = Instant::now();
                g.header.nonce = 0;
                mine(&mut g.header, u64::MAX);
                Some(t.elapsed().as_millis())
            } else {
                None
            };
            println!(
                "{{\n  \"ok\": true,\n  \"network\": \"mainnet-v2\",\n  \"premine_love\": 0,\n  \"auxpow_chainid\": 20051,\n  \"fri_security_profile\": \"MAIN_V2_384_BIT_PURE_SHA2\",\n  \"asert_launch_blocks\": {},\n  \"asert_launch_half_life_sec\": {},\n  \"asert_steady_half_life_sec\": {},\n  \"rfc_activation_height\": 0,\n  \"btc_anchor_height\": {},\n  \"btc_anchor_hash\": \"{}\",\n  \"genesis_message\": \"{}\",\n  \"genesis_time\": {},\n  \"genesis_bits\": \"{:#010x}\",\n  \"mined\": {},\n  \"genesis_nonce\": {},\n  \"genesis_hash\": \"{}\",\n  \"mined_ms\": {},\n  \"params_fingerprint_sha256\": \"{}\"\n}}",
                p.launch_blocks,
                p.launch_half_life,
                p.half_life,
                btc_height,
                btc_hash.trim().to_ascii_lowercase(),
                msg_owned,
                g.header.time,
                g.header.bits,
                do_mine,
                g.header.nonce,
                hash_hex(&g.hash()),
                mined_ms.map(|m| m.to_string()).unwrap_or_else(|| "null".into()),
                fp
            );
        }
        ["demo"] => demo()?,
        _ => {
            print!("{USAGE}");
        }
    }
    Ok(())
}

fn demo() -> Result<(), String> {
    use rand::Rng;
    let mut c = Chain::open(Params::get(Net::Reg)?, None)?;
    let mut alice = Wallet::generate();
    let mut bob = Wallet::generate();
    let miner = Wallet::generate();
    let step = |c: &mut Chain, to: &Wallet, txs: Vec<Tx>| -> Result<(), String> {
        let fees: u64 = txs.iter().map(|t| if let Tx::Spend(s) = t { s.fee } else { 0 }).sum();
        let out = PlainOut { a_pk: to.a_pk(), v: subsidy(c.height() + 1) + fees, rho: rand::thread_rng().gen() };
        let mut b = c.template(vec![out], txs, vec![])?;
        mine(&mut b.header, u64::MAX);
        c.add_block(b)?;
        Ok(())
    };
    println!("genesis {}", hash_hex(&c.genesis));
    for _ in 0..3 {
        step(&mut c, &alice, vec![])?;
    }
    println!("alice mined 3 blocks; spendable {} {TICKER}", fmt(alice.balance(&c) as u128));
    let t = Instant::now();
    let (tx, _) = alice.pay(&c, &bob.delivery_address(), 12 * COIN, 10_000, vec![])?;
    let size = tx.to_bytes().len();
    println!("alice pays bob 12 {TICKER} privately: {} bytes, proved in {} ms", size, t.elapsed().as_millis());
    let t = Instant::now();
    step(&mut c, &miner, vec![tx])?;
    println!("block {} validated (proof checked) in {} ms", c.height(), t.elapsed().as_millis());
    println!("bob before he looks: {}", fmt(bob.balance(&c) as u128));
    bob.scan(&c)?;
    println!("bob after he looks:  {} (it came on chain, sealed to his key)", fmt(bob.balance(&c) as u128));

    let (n, k, m) = (64usize, 64usize, 64usize);
    let mut rng = rand::thread_rng();
    let a: Vec<Vec<u64>> = (0..n).map(|_| (0..k).map(|_| job::reduce(rng.gen())).collect()).collect();
    let b_cols: Vec<Vec<u64>> = (0..m).map(|_| (0..k).map(|_| job::reduce(rng.gen())).collect()).collect();
    let (ak, bk) = (JobKey::from_bytes(&alice.job_key)?, JobKey::from_bytes(&bob.job_key)?);
    let post = JobPost {
        poster_vk: ak.vk(),
        poster_addr: alice.a_pk(),
        n: n as u32,
        k: k as u32,
        m: m as u32,
        a_root: job::root_of(&a),
        b_root: job::root_of(&b_cols),
        pay: COIN,
        bond_min: COIN,
        claim_by: c.height() + 20,
        deliver_blocks: 5,
        window_blocks: 3,
    };
    for honest in [false, true] {
        let post = JobPost { claim_by: c.height() + 20, ..post.clone() };
        let (tx, _) = alice.spend(&c, None, 1000, Some(Deposit::Post(post.clone())), vec![])?;
        let Tx::Spend(sp) = &tx else { unreachable!() };
        let id = job::job_id(&post, &sp.nf[0]);
        step(&mut c, &miner, vec![tx])?;
        let (tx, _) = bob.spend(&c, None, 1000, Some(Deposit::Claim(JobClaim { job: id, worker_vk: bk.vk(), worker_addr: bob.a_pk(), bond: COIN })), vec![])?;
        step(&mut c, &miner, vec![tx])?;
        let t = Instant::now();
        let mut cm = job::matmul(&a, &b_cols);
        let compute = t.elapsed();
        if !honest {
            cm[41][7] = job::reduce(cm[41][7] ^ 1);
        }
        let c_root = job::root_of(&cm);
        step(&mut c, &miner, vec![Tx::Act(Action::Commit { job: id, c_root, sig: bk.sign(&job::msg_commit(&id, &c_root)) })])?;
        let t = Instant::now();
        let verdict = job::freivalds(&a, &b_cols, &cm, 1);
        let check = t.elapsed();
        println!(
            "job {} ({}×{}×{}): worker {} — compute {:?}, Freivalds {:?}",
            &hex::encode(id)[..12],
            n,
            k,
            m,
            if honest { "honest" } else { "cheats on one entry" },
            compute,
            check
        );
        match verdict {
            Some((i, j)) => {
                step(&mut c, &miner, vec![Tx::Act(Action::Fraud { job: id, a: opening(&a, i), b: opening(&b_cols, j), c: opening(&cm, i), j })])?;
                println!("  wrong entry ({i}, {j}) proven on chain: bond burned, poster refunded");
            }
            None => {
                for _ in 0..3 {
                    step(&mut c, &miner, vec![])?;
                }
                let before = bob.balance(&c);
                step(&mut c, &miner, vec![Tx::Act(Action::Finalize { job: id })])?;
                println!("  window closed with no fraud proof: worker paid {}", fmt((bob.balance(&c) - before) as u128));
            }
        }
    }
    let s = &c.state;
    println!("height {}: issued {} burned {} escrow {} shielded {}", c.height(), fmt(s.issued), fmt(s.burned), fmt(s.locked), fmt(s.shielded_supply()));
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
