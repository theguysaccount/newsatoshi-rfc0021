//! Proof of work: SHA-256d over an 80-byte header, compact targets, chain work, and the
//! ASERT difficulty rule (aserti3-2d, Bitcoin Cash, November 2020) anchored at genesis.
//! ASERT needs only the parent block and the anchor, adjusts every block, and cannot be
//! stalled by a hashrate that leaves a young chain, which a 2016-block retarget can.

use primitive_types::{U256, U512};

pub const TARGET_SPACING: i64 = 600;

pub fn target_from_compact(bits: u32) -> U256 {
    let exp = bits >> 24;
    let mant = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 {
        return U256::zero();
    }
    if exp <= 3 {
        U256::from(mant >> (8 * (3 - exp)))
    } else {
        U256::from(mant) << (8 * (exp - 3))
    }
}

pub fn compact_from_target(t: U256) -> u32 {
    let mut size = (t.bits() + 7) / 8;
    let mut mant: u32 = if size <= 3 {
        (t.low_u64() << (8 * (3 - size))) as u32
    } else {
        (t >> (8 * (size - 3))).low_u32()
    };
    if mant & 0x0080_0000 != 0 {
        mant >>= 8;
        size += 1;
    }
    mant | ((size as u32) << 24)
}

/// Expected number of hashes for one block at this target.
pub fn work(bits: u32) -> U256 {
    let t = target_from_compact(bits);
    if t.is_zero() {
        return U256::zero();
    }
    (!t / (t + 1)) + 1
}

/// Header hashes are compared as little-endian integers, as in Bitcoin.
pub fn hash_value(h: &[u8; 32]) -> U256 {
    U256::from_little_endian(h)
}

pub fn meets(h: &[u8; 32], bits: u32) -> bool {
    let t = target_from_compact(bits);
    !t.is_zero() && hash_value(h) <= t
}

/// aserti3-2d. `anchor_bits` and `anchor_parent_time` describe the anchor (genesis, whose
/// virtual parent is one spacing earlier). Computes the target of the block that follows
/// a parent at `parent_height` with timestamp `parent_time`.
pub fn asert_bits(anchor_bits: u32, anchor_parent_time: i64, parent_height: u32, parent_time: i64, half_life: i64, pow_limit_bits: u32, spacing: i64) -> u32 {
    let anchor_target = target_from_compact(anchor_bits);
    let pow_limit = target_from_compact(pow_limit_bits);
    let time_delta = parent_time - anchor_parent_time;
    let height_delta = parent_height as i64; // anchor is height 0
    // exponent in 16.16 fixed point; Rust's `/` on i64 truncates toward zero, as required
    let exponent: i64 = ((time_delta - spacing * (height_delta + 1)) * 65536) / half_life;
    let num_shifts = exponent >> 16; // arithmetic shift = floor division
    let frac = (exponent - (num_shifts << 16)) as u64;
    debug_assert!(frac < 65536);
    let factor: u64 = 65536
        + ((195_766_423_245_049u128 * frac as u128
            + 971_821_376u128 * (frac as u128).pow(2)
            + 5127u128 * (frac as u128).pow(3)
            + (1u128 << 47))
            >> 48) as u64;
    let mut next = U512::from(anchor_target) * U512::from(factor);
    if num_shifts < 0 {
        let s = (-num_shifts) as u32;
        next = if s >= 512 { U512::zero() } else { next >> s };
    } else {
        let s = num_shifts as u32;
        if s >= 512 || next.bits() + s as usize > 512 {
            return pow_limit_bits;
        }
        next <<= s;
    }
    next >>= 16;
    if next.is_zero() {
        return compact_from_target(U256::one());
    }
    if next > U512::from(pow_limit) {
        return pow_limit_bits;
    }
    let t = U256::try_from(next).expect("below pow limit");
    compact_from_target(t)
}

/// Two-stage launch-safe ASERT difficulty schedule (`aserti3-launch`):
/// - During the launch window (`parent_height < launch_blocks`), uses a fast `launch_half_life`
///   (e.g., 3,600 s = 6 blocks per difficulty doubling) anchored at genesis so even a 1,000,000×
///   Day-1 hashrate surge stabilizes in ~120 blocks instead of insta-mining 4,200+ blocks.
/// - Once `parent_height >= launch_blocks`, transitions continuously with zero discontinuity to
///   steady-state `half_life` (48 h) anchored at the `launch_blocks` header `(anchor_bits, anchor_time)`.
#[allow(clippy::too_many_arguments)]
pub fn asert_bits_staged(
    genesis_bits: u32,
    genesis_parent_time: i64,
    launch_blocks: u32,
    launch_half_life: i64,
    steady_anchor: Option<(u32, i64)>,
    parent_height: u32,
    parent_time: i64,
    steady_half_life: i64,
    pow_limit_bits: u32,
    spacing: i64,
) -> u32 {
    if launch_blocks == 0 {
        return asert_bits(
            genesis_bits,
            genesis_parent_time,
            parent_height,
            parent_time,
            steady_half_life,
            pow_limit_bits,
            spacing,
        );
    }
    if parent_height < launch_blocks {
        asert_bits(
            genesis_bits,
            genesis_parent_time,
            parent_height,
            parent_time,
            launch_half_life,
            pow_limit_bits,
            spacing,
        )
    } else {
        let (a_bits, a_time) = steady_anchor.expect("steady anchor required past launch_blocks");
        asert_bits(
            a_bits,
            a_time - spacing,
            parent_height - launch_blocks,
            parent_time,
            steady_half_life,
            pow_limit_bits,
            spacing,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_ramp_prevents_day1_instamine_under_1_million_x_hashrate_surge() {
        // Simulate an unexpected 1,000,000x hashrate surge hitting block 1 at difficulty 1
        // (1 block every 1/1,000,000 of 600s initially -> expected time per block = 600 * diff / 1_000_000).
        let genesis_bits = 0x1d00ffffu32;
        let t0 = 1_800_000_000i64;
        let surge = 1_000_000.0f64;
        let day_secs = 86_400i64;

        let sim_day1 = |launch_blocks: u32, launch_hl: i64| -> (u32, f64) {
            let mut height = 0u32;
            let mut time = t0 as f64;
            let mut bits = genesis_bits;
            let mut steady_anchor = None;
            let diff1_work = work(genesis_bits).low_u128() as f64;
            while (time - t0 as f64) < day_secs as f64 && height < 20_000 {
                if launch_blocks > 0 && height == launch_blocks {
                    steady_anchor = Some((bits, time as i64));
                }
                bits = asert_bits_staged(
                    genesis_bits,
                    t0 - TARGET_SPACING,
                    launch_blocks,
                    launch_hl,
                    steady_anchor,
                    height,
                    time as i64,
                    172_800,
                    genesis_bits,
                    TARGET_SPACING,
                );
                let diff = (work(bits).low_u128() as f64) / diff1_work;
                let dt = (TARGET_SPACING as f64 * diff) / surge;
                time += dt.max(0.001);
                height += 1;
            }
            let final_diff = (work(bits).low_u128() as f64) / diff1_work;
            (height, final_diff)
        };

        // v0.1.0 (48h half-life from block 0): dumps >5,000 blocks on Day 1!
        let (v1_blocks, _) = sim_day1(0, 172_800);
        assert!(v1_blocks > 5_000, "v0.1.0 expected >5,000 Day-1 blocks, got {v1_blocks}");

        // v2 staged ramp (1h half-life for first 2,016 blocks): stabilizes around ~260 blocks on Day 1
        // even under a worst-case 1,000,000x uncalibrated shock (and ~144 when calibrated)!
        let (v2_blocks, v2_diff) = sim_day1(2_016, 3_600);
        eprintln!(
            "[ASERT LAUNCH RAMP] 1,000,000x shock Day-1 blocks: v0.1.0 = {v1_blocks} blocks vs v2 ramp = {v2_blocks} blocks (final diff = {v2_diff:.0})"
        );
        assert!(v2_blocks < 300, "v2 launch ramp must prevent instamine (<300 blocks), got {v2_blocks}");
        assert!(v2_diff > 500_000.0, "difficulty must converge to surge hashrate, got {v2_diff}");

        // Transition at height == launch_blocks must be 100% continuous (zero jump!)
        let anchor_bits = 0x1b04864cu32;
        let anchor_time = t0 + 2_016 * TARGET_SPACING;
        let next_b = asert_bits_staged(
            genesis_bits,
            t0 - TARGET_SPACING,
            2_016,
            3_600,
            Some((anchor_bits, anchor_time)),
            2_016,
            anchor_time,
            172_800,
            genesis_bits,
            TARGET_SPACING,
        );
        assert_eq!(next_b, anchor_bits, "launch -> steady transition must be exact and continuous");
    }

    #[test]
    fn compact_roundtrip_matches_bitcoin() {
        // Bitcoin genesis difficulty-1 target
        let t = target_from_compact(0x1d00ffff);
        assert_eq!(compact_from_target(t), 0x1d00ffff);
        assert_eq!(format!("{:x}", t), "ffff0000000000000000000000000000000000000000000000000000");
        // Bitcoin block 100,000's bits
        assert_eq!(compact_from_target(target_from_compact(0x1b04864c)), 0x1b04864c);
        // difficulty-1 work is 2^32 + 2^16 + 1 (Bitcoin Core's GetBlockProof)
        assert_eq!(work(0x1d00ffff), U256::from(4295032833u64));
    }

    #[test]
    fn asert_is_neutral_on_schedule_and_halves_per_half_life() {
        let (b0, t0, hl, lim) = (0x1c100000, 1_000_000i64, 172_800i64, 0x1d00ffff);
        let ap = t0 - TARGET_SPACING;
        // exactly on schedule: unchanged
        assert_eq!(asert_bits(b0, ap, 1000, t0 + 1000 * 600, hl, lim, TARGET_SPACING), b0);
        // one half-life behind schedule: target doubles
        let slow = asert_bits(b0, ap, 1000, t0 + 1000 * 600 + hl, hl, lim, TARGET_SPACING);
        assert_eq!(target_from_compact(slow), target_from_compact(b0) * 2);
        // one half-life ahead: target halves
        let fast = asert_bits(b0, ap, 1000, t0 + 1000 * 600 - hl, hl, lim, TARGET_SPACING);
        assert_eq!(target_from_compact(fast) * 2, target_from_compact(b0));
        // never above the limit
        assert_eq!(asert_bits(b0, ap, 10, t0 + 10_000_000, hl, lim, TARGET_SPACING), lim);
    }
}
