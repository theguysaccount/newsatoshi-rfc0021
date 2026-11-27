//! Testnet genesis, mined 2026-11-07 16:27:12 UTC over GENESIS-TESTNET.txt, which names
//! Bitcoin block 974,866. Hash 00000fd814d823a0bc64a84135868402998cff81e28a85b2bede5f1125d0a394.
pub const TEST_TIME: u32 = 1_794_068_832;
pub const TEST_NONCE: u32 = 452_534;

/// Main-network v0.1 canary genesis, mined 2026-11-10 15:46:18 UTC (retired in favor of MAIN_V2).
pub const MAIN: Option<(u32, u32)> = Some((1_794_325_578, 1_125_937_643));

/// Canonical Mainnet v2 (`nsM2`, `v1.2.0`) genesis, mined 2026-11-27 01:25:50 UTC over
/// `GENESIS-MAINNET-V2.txt` anchored to Bitcoin block `#977,738`
/// (`0000000000000000000163900064a4cc4807dbd8bcaf35e322e694e6c387a780`).
/// Canonical Genesis Hash: `00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8`.
pub const MAIN_V2: Option<(u32, u32)> = Some((1_795_742_750, 2_649_823_154));
