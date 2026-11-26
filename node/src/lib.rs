//! NEWSATOSHI reference node (`v1.0.0-core`).
//!
//! Proof of work orders the ledger (Bitcoin-compatible SHA-256d + AuxPoW merge-mining).
//! Pure-SHA-2 STARKs prove every shielded spend (individually or compressed via `BatchSpend`).
//! Priorism-FEP (`PriorLock` + Homeostatic Fee Burn) encodes falsifiable commitments,
//! surprise bounties, and deflationary burn directly into L1 consensus.
//! Everything in L1 consensus rests on SHA-2 (SHA-256 / SHA-384) and FIPS 205 SLH-DSA.

pub mod audit;
pub mod auxpow;
pub mod batch_spend;
pub mod chain;
pub mod channel;
pub mod codec;
pub mod cond;
pub mod deliver;
pub mod hash;
pub mod job;
pub mod light;
pub mod lock;
pub mod merkmap;
pub mod nftree;
pub mod node;
pub mod note;
pub mod params;
mod params_genesis;
pub mod peers;
pub mod pow;
pub mod pq_transport;
pub mod prior;
pub mod pruned_store;
pub mod recursion;
pub mod rpc;
pub mod script;
pub mod signal;
pub mod snapshot;
pub mod spend;
pub mod state;
pub mod swap;
pub mod tx;
pub mod utreexo;
pub mod wallet;
