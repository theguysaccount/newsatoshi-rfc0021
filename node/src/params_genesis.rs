//! Testnet genesis, mined 2026-11-07 16:27:12 UTC over GENESIS-TESTNET.txt, which names
//! Bitcoin block 974,866. Hash 00000fd814d823a0bc64a84135868402998cff81e28a85b2bede5f1125d0a394.
pub const TEST_TIME: u32 = 1_794_068_832;
pub const TEST_NONCE: u32 = 452_534;

/// Main-network genesis, mined 2026-11-10 15:46:18 UTC (its header time) over GENESIS-MAINNET.txt, which names
/// Bitcoin block 975,317. Hash 000000006ba30cc3c86ecaabcb962287e9d5fd0877c27f4b33661b4d1d3033f7.
pub const MAIN: Option<(u32, u32)> = Some((1_794_325_578, 1_125_937_643));
