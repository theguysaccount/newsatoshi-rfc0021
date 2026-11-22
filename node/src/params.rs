//! Consensus parameters and the Solvency Rule.

pub const COIN: u64 = 100_000_000;
pub const HALVING_INTERVAL: u32 = 210_000;
/// The floor: 50 / 2^8 coins per block, reached at the eighth halving and kept forever.
/// 0.1953125 × 52,560 blocks ≈ 10,266 coins a year, under 0.05% of supply and falling.
pub const SUBSIDY_FLOOR: u64 = 19_531_250;
/// A memo: text, or text with envelopes that deliver notes on chain (`crate::deliver`).
pub const MAX_MEMO: usize = crate::deliver::MAX_MEMO_BYTES;
pub const MAX_COINBASE_EXTRA: usize = 120;
/// Largest encoded transaction on the test network, and everywhere the largest answer a job
/// may ask for. Each network's limit is `Params::max_tx_bytes`, enforced by block validation
/// and the mempool.
pub const MAX_TX_BYTES: usize = 400_000;
/// Largest encoded transaction on the main network: its larger proofs, and the same room
/// for the rest of a payment.
pub const MAIN_MAX_TX_BYTES: usize = MAX_TX_BYTES - crate::spend::MAX_PROOF_BYTES + crate::spend::MAIN_MAX_PROOF_BYTES;
/// Largest encoded transaction any network takes: what a decoder will read, so a block one
/// node accepts is a block every node can decode.
pub const TX_BYTES_CAP: usize = MAIN_MAX_TX_BYTES;
pub const MAX_BLOCK_TXS: usize = 100_000;
pub const MAX_FUTURE_SECS: i64 = 2 * 60 * 60;

/// Relay policy, not consensus: a spend must pay at least this per 1,000 bytes to enter a
/// mempool, and blocks are filled by fee rate. A 249 KB spend pays at least 0.00249 coins.
pub const MIN_RELAY_FEE_PER_KB: u64 = 1_000;
/// The wallet's default fee on the test network: covers a spend up to 300 KB at the minimum
/// rate. Each network's is `Params::default_fee`.
pub const DEFAULT_FEE: u64 = 300_000;
/// The wallet's default fee on the main network, whose payments are about 460 KB: covers a
/// spend up to 600 KB at the minimum rate.
pub const MAIN_DEFAULT_FEE: u64 = 600_000;

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

/// Bitcoin's schedule until it reaches the floor, then the floor forever. Depends on
/// height alone: case (a) of Theorem 1, blind and trustless.
pub fn subsidy(height: u32) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let s = if halvings >= 63 { 0 } else { (50 * COIN) >> halvings };
    s.max(SUBSIDY_FLOOR)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Net {
    Main,
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
    /// Nodes to reach when none is named with `--peer`. Any node can be one; these are
    /// only where a new node first looks.
    pub seeds: &'static [&'static str],
}

/// The testnet genesis message commits to a Bitcoin block, so the genesis block cannot
/// have been made before it. The genesis coinbase has no outputs: there is no premine.
/// The test network's blocks commit to the nullifier tree from this height on.
pub const TESTNET_NF_TREE_FROM: u32 = 3_900;

pub const TESTNET_GENESIS_MESSAGE: &str = include_str!("../GENESIS-TESTNET.txt");

/// The main network's genesis message: empty until the day (RUNBOOK.md).
pub const MAINNET_GENESIS_MESSAGE: &str = include_str!("../GENESIS-MAINNET.txt");

impl Params {
    pub fn get(net: Net) -> Result<Params, String> {
        match net {
            Net::Main => match crate::params_genesis::MAIN {
                Some((time, nonce)) if !MAINNET_GENESIS_MESSAGE.trim().is_empty() => Ok(Self::main_with(time, nonce)),
                _ => Err("there is no main network yet: its genesis block is mined on the day it opens (LAUNCH.md, RUNBOOK.md)".into()),
            },
            Net::Test => Ok(Params {
                net,
                name: "testnet",
                magic: *b"nsT0",
                pow_limit: 0x1e0fffff,
                half_life: 3600,
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
                seeds: &["newsatoshi-seed.fly.dev:18444"],
            }),
            Net::Reg => Ok(Params {
                net,
                name: "regtest",
                magic: *b"nsR0",
                pow_limit: 0x207fffff,
                half_life: 3600,
                target_spacing: 600,
                coinbase_maturity: 1,
                max_block_bytes: 8_000_000,
                max_tx_bytes: MAX_TX_BYTES,
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
                seeds: &[],
                ..Self::main_with(0, 0)
            }),
        }
    }

    /// The main network's rules (LAUNCH.md) over a genesis block with this time and nonce.
    /// The rehearsal network is these rules with the differences `Net::Dry` names, so what
    /// is rehearsed is what launches.
    pub fn main_with(genesis_time: u32, genesis_nonce: u32) -> Params {
        Params {
            net: Net::Main,
            name: "mainnet",
            magic: *b"nsM0",
            pow_limit: 0x1d00ffff,
            half_life: 2 * 24 * 3600,
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
            seeds: &["newsatoshi-seed.fly.dev:8444"],
        }
    }

    pub fn parse(s: &str) -> Result<Net, String> {
        match s {
            "main" | "mainnet" => Ok(Net::Main),
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
    fn solvency_rule() {
        assert_eq!(subsidy(0), 50 * COIN);
        assert_eq!(subsidy(209_999), 50 * COIN);
        assert_eq!(subsidy(210_000), 25 * COIN);
        assert_eq!(subsidy(8 * 210_000 - 1), 39_062_500);
        assert_eq!(subsidy(8 * 210_000), SUBSIDY_FLOOR);
        assert_eq!(subsidy(u32::MAX), SUBSIDY_FLOOR);
        // total issued by the floor height is Bitcoin's schedule to that point
        let mut total: u128 = 0;
        for era in 0..8u32 {
            total += 210_000u128 * subsidy(era * 210_000) as u128;
        }
        assert_eq!(total, 2_091_796_875_000_000); // 20,917,968.75 coins
        // and the floor is under 0.05% of that a year
        let per_year = SUBSIDY_FLOOR as u128 * 52_560;
        assert!(per_year * 10_000 / total < 5);
    }
}
