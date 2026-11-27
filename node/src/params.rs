//! Consensus parameters, the Solvency Rule, and the Homeostatic Supply Thermostat.

pub const COIN: u64 = 100_000_000;
pub const HALVING_INTERVAL: u32 = 210_000;
/// The floor: 50 / 2^8 coins per block, reached at the eighth halving and kept forever.
/// 0.1953125 × 52,560 blocks ≈ 10,266 coins a year, under 0.05% of supply and falling.
/// Under `homeostatic_burn_from` (Mainnet v2), 50% of shielded transaction fees and 50% of
/// disconfirmed `PriorLock` collateral are permanently burned (`state.burned`), offsetting
/// tail issuance proportionally to real economic usage and surprise disconfirmation.
pub const SUBSIDY_FLOOR: u64 = 19_531_250;

/// Homeostatic Supply Thermostat: fraction of every shielded spend / batch-spend fee
/// permanently burned into `state.burned` when `homeostatic_burn_from` is active (50% = 5,000 bps).
pub const BASE_FEE_BURN_BPS: u64 = 5_000;

/// Minimum fee per individual sub-spend inside a `Tx::BatchSpend` (0.0001 LOVE = 10,000 units),
/// preventing zero-fee dust packing inside compressed batches.
pub const MIN_BATCH_SPEND_FEE: u64 = 10_000;

/// A memo: text, or text with envelopes that deliver notes on chain (`crate::deliver`).
pub const MAX_MEMO: usize = crate::deliver::MAX_MEMO_BYTES;
pub const MAX_COINBASE_EXTRA: usize = 120;
/// Largest encoded transaction on the test network, and everywhere the largest answer a job
/// may ask for. Each network's limit is `Params::max_tx_bytes`, enforced by block validation
/// and the mempool.
pub const MAX_TX_BYTES: usize = 400_000;
/// Largest encoded transaction on the v0.1 main network: its larger proofs, and the same room
/// for the rest of a payment.
pub const MAIN_MAX_TX_BYTES: usize = MAX_TX_BYTES - crate::spend::MAX_PROOF_BYTES + crate::spend::MAIN_MAX_PROOF_BYTES;
/// Largest encoded transaction on Mainnet v2 / Regtest (fits single Quartic SHA-384 spends and
/// up to 16-spend compressed `Tx::BatchSpend` Quartic SHA-384 STARK proofs + encrypted memos).
pub const MAIN_V2_MAX_TX_BYTES: usize = 1_500_000;
/// Largest encoded transaction any network takes: what a decoder will read, so a block one
/// node accepts is a block every node can decode.
pub const TX_BYTES_CAP: usize = MAIN_V2_MAX_TX_BYTES;
pub const MAX_BLOCK_TXS: usize = 100_000;
pub const MAX_FUTURE_SECS: i64 = 2 * 60 * 60;

/// Relay policy, not consensus: a spend must pay at least this per 1,000 bytes to enter a
/// mempool, and blocks are filled by fee rate. A 249 KB spend pays at least 0.00249 coins.
pub const MIN_RELAY_FEE_PER_KB: u64 = 1_000;
/// The wallet's default fee on the test network: covers a spend up to 300 KB at the minimum
/// rate. Each network's is `Params::default_fee`.
pub const DEFAULT_FEE: u64 = 300_000;
/// The wallet's default fee on the v0.1 main network, whose payments are about 460 KB: covers a
/// spend up to 600 KB at the minimum rate.
pub const MAIN_DEFAULT_FEE: u64 = 600_000;
/// The wallet's default fee on Mainnet v2, whose SHA-384 FRI proofs are ~510–550 KB
/// with encrypted memos: covers a spend up to 800 KB at `MIN_RELAY_FEE_PER_KB`.
pub const MAIN_V2_DEFAULT_FEE: u64 = 800_000;

/// Base units as coins, for people: "50", "1.5", "0.0025".
pub fn fmt_coins(v: u64) -> String {
    let (whole, frac) = (v / COIN, v % COIN);
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{frac:08}").trim_end_matches('0').to_string()
    }
}

pub fn min_relay_fee(tx_bytes: usize) -> u64 {
    (tx_bytes as u64 * MIN_RELAY_FEE_PER_KB).div_ceil(1000)
}

/// Split a spend fee into `(burned_fee, producer_fee)` under the Homeostatic Supply Thermostat.
/// When `homeostatic_burn_active` is false (v0.1.0 compatibility), returns `(0, fee)`.
pub fn split_spend_fee(fee: u64, homeostatic_burn_active: bool) -> (u64, u64) {
    if !homeostatic_burn_active {
        return (0, fee);
    }
    let burned = ((fee as u128 * BASE_FEE_BURN_BPS as u128) / 10_000) as u64;
    (burned, fee - burned)
}

/// Split a `BatchSpend` fee budget into `(burned_fee, prover_fee, miner_fee)`.
/// Strictly incentive-compatible: the AuxPoW miner ALWAYS keeps 100% of block subsidy plus
/// `miner_fee`, while `prover_fee` is paid out of the unburned fee share (`prover_fee <= net_fee`)
/// directly to `prover_a_pk` in the block coinbase (both bound inside the STARK proof).
pub fn split_batch_fee(
    total_fee: u64,
    prover_fee: u64,
    homeostatic_burn_active: bool,
) -> Result<(u64, u64, u64), String> {
    let (burned, net) = split_spend_fee(total_fee, homeostatic_burn_active);
    if prover_fee > net {
        return Err(format!(
            "batch prover_fee {prover_fee} exceeds unburned net fee {net}"
        ));
    }
    Ok((burned, prover_fee, net - prover_fee))
}

/// Bitcoin's schedule until it reaches the floor, then the floor forever. Depends on
/// height alone: case (a) of Theorem 1, blind and trustless.
pub fn subsidy(height: u32) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let s = if halvings >= 63 { 0 } else { (50 * COIN) >> halvings };
    s.max(SUBSIDY_FLOOR)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Net {
    /// Legacy v0.1 pre-launch canary (`nsM0`, retired in favor of `MainV2`).
    Main,
    /// Canonical `v1.2.0` Mainnet v2 (`nsM2`, Bitcoin-anchored fair launch, Quartic SHA-384 QROM >= 100b).
    MainV2,
    Test,
    Reg,
    /// The rehearsal network: every rule of the main network on a chain that is thrown
    /// away, with work a laptop can do. What launches is what was rehearsed.
    Dry,
}

#[derive(Clone, Debug)]
pub struct Params {
    pub net: Net,
    pub name: &'static str,
    pub magic: [u8; 4],
    pub pow_limit: u32,
    pub half_life: i64,
    /// Optional anti-instamine launch ramp: for heights `< launch_blocks`, ASERT uses
    /// `launch_half_life` (e.g., 3,600 s = 6 blocks/doubling), then transitions continuously
    /// to `half_life` anchored at block `launch_blocks`. `0` disables the ramp (v0.1.0 compat).
    pub launch_blocks: u32,
    pub launch_half_life: i64,
    /// Seconds between blocks that difficulty aims for: Bitcoin's ten minutes on the main
    /// network; one minute on the test network, so that testing a payment takes minutes.
    pub target_spacing: i64,
    pub coinbase_maturity: u32,
    pub max_block_bytes: usize,
    /// Largest encoded transaction.
    pub max_tx_bytes: usize,
    /// How payment proofs are made and checked: queries, the network's name, the size limit.
    pub proof: crate::spend::Profile,
    /// What the wallet pays when no fee is named.
    pub default_fee: u64,
    pub default_port: u16,
    pub genesis_time: u32,
    pub genesis_bits: u32,
    pub genesis_nonce: u32,
    pub genesis_message: &'static str,
    /// (height, block hash) pairs compiled into a release. They can only refuse a rewrite of
    /// history older than the release; they cannot make, censor or halt blocks. They lapse
    /// at `checkpoint_sunset`.
    pub checkpoints: Vec<(u32, [u8; 32])>,
    pub checkpoint_sunset: u32,
    /// Height from which blocks commit to the nullifier tree's root (`crate::nftree`).
    pub nf_tree_from: Option<u32>,
    /// Height from which RFC-0022 (seller-authorized PayWord channels & batched channel opens)
    /// is active (`None` preserves v0.1.0 rejection).
    pub rfc0022_from: Option<u32>,
    /// Height from which Priorism-FEP `PriorLock` (`crate::prior`) is active.
    pub prior_from: Option<u32>,
    /// Height from which Homeostatic Base-Fee Burn (`50%` of shielded spend fees permanently
    /// burned into `state.burned`) is active (`Some(0)` on Mainnet v2; `None` on v0.1.0).
    pub homeostatic_burn_from: Option<u32>,
    /// Height from which `Tx::BatchSpend` multi-spend STARK compression with STARK-bound
    /// `prover_fee` coinbase settlement is active.
    pub batch_spend_from: Option<u32>,
    /// Height from which blocks commit to the ancestor FlyClient Header MMR root
    /// (`DigestParts::header_mmr`, Zcash ZIP-221 style). `Some(0)` on Mainnet v2; `None` on v0.1.0.
    pub mmr_from: Option<u32>,
    /// Height from which `locks` and `conds` digest commitments use $O(\log N)$ `MerkleMap` roots
    /// instead of $O(N)$ full-map linear hashing (`Some(0)` on Mainnet v2; `None` on v0.1.0).
    pub merkle_locks_conds_from: Option<u32>,
    /// Whether legacy Freivalds matrix-product jobs (`Deposit::Post`/`Claim`) are accepted.
    /// Disabled (`false`) on Mainnet v2 (`nsM2`) so `state.jobs` stays permanently empty (`O(1)`).
    pub legacy_jobs_enabled: bool,
    /// Require post-quantum `NSPQ1`/`NSPQ2` (NIST FIPS 203 ML-KEM-768 + optional SLH-DSA pinning)
    /// P2P encryption on all peer links (`true` on Mainnet v2).
    pub pq_transport: bool,
    /// Nodes to reach when none is named with `--peer`. Any node can be one; these are
    /// only where a new node first looks.
    pub seeds: &'static [&'static str],
}

/// The test network's blocks commit to the nullifier tree from this height on.
pub const TESTNET_NF_TREE_FROM: u32 = 3_900;

pub const TESTNET_GENESIS_MESSAGE: &str = include_str!("../GENESIS-TESTNET.txt");

/// The v0.1 pre-launch canary genesis message (retired in favor of one canonical Mainnet v2
/// Bitcoin-block-anchored fair-launch genesis).
pub const MAINNET_GENESIS_MESSAGE: &str = include_str!("../GENESIS-MAINNET.txt");

/// Canonical Mainnet v2 (`nsM2`) Bitcoin-block-anchored fair-launch genesis message.
pub const MAINNET_V2_GENESIS_MESSAGE: &str = include_str!("../GENESIS-MAINNET-V2.txt");

impl Params {
    pub fn get(net: Net) -> Result<Params, String> {
        match net {
            Net::Main => match crate::params_genesis::MAIN {
                Some((time, nonce)) if !MAINNET_GENESIS_MESSAGE.trim().is_empty() => Ok(Self::main_with(time, nonce)),
                _ => Err("there is no main network yet: its genesis block is mined on the day it opens (LAUNCH.md, RUNBOOK.md)".into()),
            },
            Net::MainV2 => match crate::params_genesis::MAIN_V2 {
                Some((time, nonce)) if !MAINNET_V2_GENESIS_MESSAGE.trim().is_empty() => {
                    let mut p = Self::main_v2_with(time, nonce, 0x1d00_ffff);
                    p.genesis_message = MAINNET_V2_GENESIS_MESSAGE.trim_end();
                    Ok(p)
                }
                _ => Err("mainnet-v2 genesis not yet compiled in; pass --genesis-v2 FILE.json or run `newsatoshi genesis-v2`".into()),
            },
            Net::Test => Ok(Params {
                net,
                name: "testnet",
                magic: *b"nsT0",
                pow_limit: 0x1e0fffff,
                half_life: 3600,
                launch_blocks: 0,
                launch_half_life: 3600,
                target_spacing: 60,
                coinbase_maturity: 10,
                max_block_bytes: 8_000_000,
                max_tx_bytes: MAX_TX_BYTES,
                proof: crate::spend::TEST,
                default_fee: DEFAULT_FEE,
                default_port: 18_444,
                genesis_time: crate::params_genesis::TEST_TIME,
                genesis_bits: 0x1e0fffff,
                genesis_nonce: crate::params_genesis::TEST_NONCE,
                genesis_message: TESTNET_GENESIS_MESSAGE.trim_end(),
                checkpoints: vec![],
                checkpoint_sunset: 0,
                nf_tree_from: Some(TESTNET_NF_TREE_FROM),
                rfc0022_from: None,
                prior_from: None,
                homeostatic_burn_from: None,
                batch_spend_from: None,
                mmr_from: None,
                merkle_locks_conds_from: None,
                legacy_jobs_enabled: true,
                pq_transport: false,
                seeds: &["newsatoshi-seed.fly.dev:18444"],
            }),
            Net::Reg => Ok(Params {
                net,
                name: "regtest",
                magic: *b"nsR0",
                pow_limit: 0x207fffff,
                half_life: 3600,
                launch_blocks: 0,
                launch_half_life: 3600,
                target_spacing: 600,
                coinbase_maturity: 1,
                max_block_bytes: 8_000_000,
                max_tx_bytes: MAIN_MAX_TX_BYTES,
                proof: crate::spend::TEST,
                default_fee: DEFAULT_FEE,
                default_port: 18_544,
                genesis_time: 1_762_473_600,
                genesis_bits: 0x207fffff,
                genesis_nonce: u32::MAX, // mined deterministically at start-up
                genesis_message: "regtest",
                checkpoints: vec![],
                checkpoint_sunset: 0,
                nf_tree_from: Some(0),
                rfc0022_from: Some(0),
                prior_from: Some(0),
                homeostatic_burn_from: None,
                batch_spend_from: Some(0),
                mmr_from: None,
                merkle_locks_conds_from: None,
                legacy_jobs_enabled: true,
                pq_transport: false,
                seeds: &[],
            }),
            // The main network's rules, with what makes it a rehearsal: its own name (in
            // its proofs too), work a laptop can do, and a genesis block made at start-up.
            Net::Dry => Ok(Params {
                net,
                name: "rehearsal",
                magic: *b"nsD0",
                pow_limit: 0x207fffff,
                proof: crate::spend::DRY,
                default_port: 18_644,
                genesis_time: 1_794_268_800,
                genesis_bits: 0x207fffff,
                genesis_nonce: u32::MAX, // mined deterministically at start-up
                genesis_message: "rehearsal: the main network's rules on a chain that is thrown away",
                rfc0022_from: Some(0),
                prior_from: Some(0),
                homeostatic_burn_from: None,
                batch_spend_from: Some(0),
                mmr_from: None,
                merkle_locks_conds_from: None,
                legacy_jobs_enabled: true,
                pq_transport: false,
                seeds: &[],
                ..Self::main_with(0, 0)
            }),
        }
    }

    /// Legacy v0.1 pre-launch canary compatibility rules (`nsM0`).
    /// NOTE: The Nov 10 v0.1.0 canary chain is retired; canonical production launch uses
    /// `main_v2_with` (`nsM2`) with a single fresh Bitcoin-block-anchored genesis.
    pub fn main_with(genesis_time: u32, genesis_nonce: u32) -> Params {
        Params {
            net: Net::Main,
            name: "mainnet",
            magic: *b"nsM0",
            pow_limit: 0x1d00ffff,
            half_life: 2 * 24 * 3600,
            launch_blocks: 0,
            launch_half_life: 3600,
            target_spacing: 600,
            coinbase_maturity: 100,
            max_block_bytes: 8_000_000,
            max_tx_bytes: MAIN_MAX_TX_BYTES,
            proof: crate::spend::MAIN,
            default_fee: MAIN_DEFAULT_FEE,
            default_port: 8_444,
            genesis_time,
            genesis_bits: 0x1d00ffff,
            genesis_nonce,
            genesis_message: MAINNET_GENESIS_MESSAGE.trim_end(),
            checkpoints: vec![],
            checkpoint_sunset: 0,
            nf_tree_from: Some(0),
            rfc0022_from: None,
            prior_from: None,
            homeostatic_burn_from: None,
            batch_spend_from: None,
            mmr_from: None,
            merkle_locks_conds_from: None,
            legacy_jobs_enabled: true,
            pq_transport: false,
            seeds: &["newsatoshi-seed.fly.dev:8444"],
        }
    }

    /// Canonical `v1.2.0-mainnet-rc1` Mainnet v2 launch rules (`nsM2`):
    /// - One fresh Bitcoin-block-anchored fair-launch genesis (zero premine; Nov 10 v0.1 canary retired)
    /// - Anti-instamine Day-1 ASERT ramp (1-hour half-life for first 2,016 blocks -> 48-hour steady)
    /// - 256-bit Quartic Goldilocks + SHA-384 FRI (`spend::MAIN_V2`: >= 100 conservative CMS19 QROM bits)
    /// - Consensus-committed FlyClient Header MMR (`mmr_from: Some(0)`)
    /// - $O(\log N)$ Merkleized `locks`, `conds`, `channels`, and `priors` + legacy jobs disabled (`O(1)` digest!)
    /// - Post-quantum ML-KEM-768 + optional SLH-DSA pinned P2P transport (`pq_transport: true`)
    /// - PayWord hash-chain channels (`rfc0022_from: Some(0)`)
    /// - Priorism-FEP `PriorLock` (`prior_from: Some(0)`) + Homeostatic 50% Fee Burn
    ///   (`homeostatic_burn_from: Some(0)`) + strictly incentive-compatible `BatchSpend` prover-fee
    ///   settlement (`batch_spend_from: Some(0)`, AuxPoW miners keep 100% of block subsidy!).
    pub fn main_v2_with(genesis_time: u32, genesis_nonce: u32, genesis_bits: u32) -> Params {
        Params {
            net: Net::MainV2,
            name: "mainnet-v2",
            magic: *b"nsM2",
            default_port: 8_445,
            default_fee: MAIN_V2_DEFAULT_FEE,
            genesis_bits,
            launch_blocks: 2_016,
            launch_half_life: 3_600,
            max_tx_bytes: MAIN_V2_MAX_TX_BYTES,
            proof: crate::spend::MAIN_V2,
            rfc0022_from: Some(0),
            prior_from: Some(0),
            homeostatic_burn_from: Some(0),
            batch_spend_from: Some(0),
            mmr_from: Some(0),
            merkle_locks_conds_from: Some(0),
            legacy_jobs_enabled: false,
            pq_transport: true,
            seeds: &["newsatoshi-seed-v2.fly.dev:8445", "pool.newsatoshi.org:8445"],
            ..Self::main_with(genesis_time, genesis_nonce)
        }
    }

    /// Format the canonical Bitcoin-block-anchored fair-launch genesis message
    /// (<= 120 bytes to fit `MAX_COINBASE_EXTRA`), proving zero secret pre-mining before
    /// Bitcoin reached `btc_height`.
    pub fn format_v2_fair_launch_message(btc_height: u64, btc_block_hash_hex: &str) -> Result<String, String> {
        let h = btc_block_hash_hex.trim().to_ascii_lowercase();
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("btc_block_hash must be 64 hex characters".into());
        }
        let msg = format!("NEWSATOSHI-V2 BTC#{btc_height} {h}");
        if msg.len() > MAX_COINBASE_EXTRA {
            return Err(format!("genesis message exceeds MAX_COINBASE_EXTRA ({MAX_COINBASE_EXTRA})"));
        }
        Ok(msg)
    }

    pub fn parse(s: &str) -> Result<Net, String> {
        match s {
            "main" | "mainnet" => Ok(Net::Main),
            "main-v2" | "mainnet-v2" => Ok(Net::MainV2),
            "test" | "testnet" => Ok(Net::Test),
            "reg" | "regtest" => Ok(Net::Reg),
            "dry" | "rehearsal" => Ok(Net::Dry),
            _ => Err(format!("unknown network {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solvency_rule_and_homeostatic_splits() {
        assert_eq!(subsidy(0), 50 * COIN);
        assert_eq!(subsidy(209_999), 50 * COIN);
        assert_eq!(subsidy(210_000), 25 * COIN);
        assert_eq!(subsidy(8 * 210_000 - 1), 39_062_500);
        assert_eq!(subsidy(8 * 210_000), SUBSIDY_FLOOR);
        assert_eq!(subsidy(u32::MAX), SUBSIDY_FLOOR);
        let mut total: u128 = 0;
        for era in 0..8u32 {
            total += 210_000u128 * subsidy(era * 210_000) as u128;
        }
        assert_eq!(total, 2_091_796_875_000_000);
        let per_year = SUBSIDY_FLOOR as u128 * 52_560;
        assert!(per_year * 10_000 / total < 5);

        // Homeostatic fee burn exact conservation
        assert_eq!(split_spend_fee(800_000, false), (0, 800_000));
        assert_eq!(split_spend_fee(800_000, true), (400_000, 400_000));
        assert_eq!(split_spend_fee(800_001, true), (400_000, 400_001));

        // Incentive-compatible BatchSpend prover_fee split (miners always keep 100% subsidy!)
        assert_eq!(split_batch_fee(1_600_000, 200_000, true).unwrap(), (800_000, 200_000, 600_000));
        assert_eq!(split_batch_fee(1_600_000, 0, true).unwrap(), (800_000, 0, 800_000));
        assert_eq!(split_batch_fee(1_600_000, 800_000, true).unwrap(), (800_000, 800_000, 0));
        assert!(split_batch_fee(1_600_000, 800_001, true).is_err());
    }
}
