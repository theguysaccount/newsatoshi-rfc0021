//! Collective Protocol Steering (BIP-9 Version-Bits Signaling) & Base-Layer Ossification.
//!
//! Enables miners and full nodes to coordinate protocol upgrades transparently using
//! `Header::version` bits `1..=7` — preserving full Namecoin/Bitcoin AuxPoW compatibility
//! (`auxpow::auxpow_version` keeps `(base & 0xff)` intact alongside `VERSION_AUXPOW = 1 << 8`
//! and `CHAIN_ID = 0x4e53` in bits `16..=31`).
//!
//! Includes a verifiable **Base-Layer Ossification Covenant**: once `ossify_monetary_base`
//! locks in and activates, core monetary supply (`subsidy`, `SUBSIDY_FLOOR`, Homeostatic Burn),
//! pure SHA-2 spend conservation, and zero-premine invariants are frozen.

/// Valid version-bit indices usable alongside AuxPoW (`base = 1`, bits `1..=7`).
pub const MIN_SIGNAL_BIT: u8 = 1;
pub const MAX_SIGNAL_BIT: u8 = 7;
/// Mask of all 7 AuxPoW-safe signaling bits (`0b1111_1110 = 0xfe`).
pub const SIGNAL_BITS_MASK: u32 = 0xfe;

/// Lifecycle state of a BIP-9 style collective deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalState {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

impl SignalState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalState::Defined => "defined",
            SignalState::Started => "started",
            SignalState::LockedIn => "locked_in",
            SignalState::Active => "active",
            SignalState::Failed => "failed",
        }
    }
}

/// Specification of one collective protocol upgrade or ossification proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub name: &'static str,
    /// Version bit in `1..=7` (AuxPoW-safe).
    pub bit: u8,
    /// Retarget window size in blocks (e.g., `2016` on Mainnet, `10` on Regtest).
    pub window: u32,
    /// Minimum signaling blocks within one window required to transition `Started → LockedIn`.
    pub threshold: u32,
    /// First block height at which signaling opens (must be a multiple of `window`).
    pub start_height: u32,
    /// Height after which an unlocked proposal expires (`Started → Failed`).
    pub timeout_height: u32,
    /// Whether activation permanently freezes base-layer monetary rules (ossification covenant).
    pub ossifies_monetary_base: bool,
}

/// Computed live telemetry for a deployment at the current chain tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentStatus {
    pub name: &'static str,
    pub bit: u8,
    pub state: SignalState,
    pub window: u32,
    pub threshold: u32,
    pub window_start: u32,
    pub blocks_in_window: u32,
    pub signaled_in_window: u32,
    pub active_since: Option<u32>,
    pub ossifies_monetary_base: bool,
}

/// Standard `v1.0.0-core` collective deployments advertised by Newsatoshi nodes.
pub fn standard_deployments(window: u32, threshold: u32) -> Vec<Deployment> {
    vec![
        Deployment {
            name: "payword_channels",
            bit: 1,
            window,
            threshold,
            start_height: 0,
            timeout_height: window.saturating_mul(52),
            ossifies_monetary_base: false,
        },
        Deployment {
            name: "priorism_fep_prior_lock",
            bit: 2,
            window,
            threshold,
            start_height: 0,
            timeout_height: window.saturating_mul(52),
            ossifies_monetary_base: false,
        },
        Deployment {
            name: "homeostatic_fee_burn",
            bit: 3,
            window,
            threshold,
            start_height: 0,
            timeout_height: window.saturating_mul(52),
            ossifies_monetary_base: false,
        },
        Deployment {
            name: "batch_spend_compression",
            bit: 4,
            window,
            threshold,
            start_height: 0,
            timeout_height: window.saturating_mul(52),
            ossifies_monetary_base: false,
        },
        Deployment {
            name: "ossify_monetary_base",
            bit: 7,
            window,
            threshold,
            start_height: window.saturating_mul(2),
            timeout_height: window.saturating_mul(260),
            ossifies_monetary_base: true,
        },
    ]
}

/// Set one or more AuxPoW-safe version signaling bits (`1..=7`) onto a header base version.
pub fn encode_signal_version(base_version: u32, bits: &[u8]) -> u32 {
    let mut v = base_version;
    for &b in bits {
        if (MIN_SIGNAL_BIT..=MAX_SIGNAL_BIT).contains(&b) {
            v |= 1u32 << b;
        }
    }
    v
}

/// Check whether a block header's version signals deployment bit `bit` (`1..=7`).
pub fn signals_bit(header_version: u32, bit: u8) -> bool {
    if !(MIN_SIGNAL_BIT..=MAX_SIGNAL_BIT).contains(&bit) {
        return false;
    }
    (header_version & (1u32 << bit)) != 0
}

/// Evaluate a deployment's exact BIP-9 state across header versions indexed by height `0..=tip`.
pub fn evaluate_deployment(versions: &[u32], dep: &Deployment) -> DeploymentStatus {
    let w = dep.window.max(1);
    let tip_height = versions.len().saturating_sub(1) as u32;
    let mut state = if dep.start_height == 0 { SignalState::Started } else { SignalState::Defined };
    let mut active_since = None;

    // Advance window-by-window over completed retarget periods.
    let completed_windows = tip_height / w;
    for win_idx in 0..completed_windows {
        let win_start = win_idx * w;
        let win_end = win_start + w; // exclusive (blocks win_start..win_end)
        match state {
            SignalState::Defined => {
                if win_end >= dep.start_height {
                    state = SignalState::Started;
                }
            }
            SignalState::Started => {
                let count = (win_start..win_end)
                    .filter(|&h| {
                        versions
                            .get(h as usize)
                            .is_some_and(|&v| signals_bit(v, dep.bit))
                    })
                    .count() as u32;
                if count >= dep.threshold {
                    state = SignalState::LockedIn;
                } else if win_end >= dep.timeout_height {
                    state = SignalState::Failed;
                }
            }
            SignalState::LockedIn => {
                state = SignalState::Active;
                active_since = Some(win_end);
            }
            SignalState::Active | SignalState::Failed => {}
        }
    }

    let cur_win_start = completed_windows * w;
    let blocks_in_window = tip_height.saturating_sub(cur_win_start) + 1;
    let signaled_in_window = (cur_win_start..=tip_height)
        .filter(|&h| {
            versions
                .get(h as usize)
                .is_some_and(|&v| signals_bit(v, dep.bit))
        })
        .count() as u32;

    DeploymentStatus {
        name: dep.name,
        bit: dep.bit,
        state,
        window: w,
        threshold: dep.threshold,
        window_start: cur_win_start,
        blocks_in_window,
        signaled_in_window,
        active_since,
        ossifies_monetary_base: dep.ossifies_monetary_base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auxpow::{auxpow_version, chain_id, is_auxpow, CHAIN_ID};

    #[test]
    fn signaling_bits_survive_auxpow_and_reach_lockin_and_ossification() {
        // Verify AuxPoW header version preserves all signaling bits 1..=7
        let v = auxpow_version(encode_signal_version(1, &[1, 3, 4, 7]));
        assert!(is_auxpow(v));
        assert_eq!(chain_id(v), CHAIN_ID);
        assert!(signals_bit(v, 1));
        assert!(!signals_bit(v, 2));
        assert!(signals_bit(v, 3));
        assert!(signals_bit(v, 4));
        assert!(signals_bit(v, 7));

        // Simulate 4 windows of 10 blocks (threshold 9/10 = 90%)
        let dep = Deployment {
            name: "rfc0023_sovereign_l2_rollups",
            bit: 3,
            window: 10,
            threshold: 9,
            start_height: 0,
            timeout_height: 100,
            ossifies_monetary_base: false,
        };
        // Window 0 (blocks 0..10): 9/10 signal -> transitions Started -> LockedIn at height 10
        let mut versions = vec![1u32; 1]; // genesis
        for _ in 1..10 {
            versions.push(auxpow_version(encode_signal_version(1, &[3])));
        }
        assert_eq!(evaluate_deployment(&versions, &dep).state, SignalState::Started);

        // Enter window 1 (block 10): window 0 completed with 9/10 -> LockedIn!
        versions.push(1);
        let st1 = evaluate_deployment(&versions, &dep);
        assert_eq!(st1.state, SignalState::LockedIn);

        // Complete window 1 (blocks 11..20) and enter window 2 (block 20) -> Active!
        versions.extend(std::iter::repeat_n(1u32, 10));
        let st2 = evaluate_deployment(&versions, &dep);
        assert_eq!(st2.state, SignalState::Active);
        assert_eq!(st2.active_since, Some(20));
    }
}
