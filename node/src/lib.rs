//! NEWSATOSHI reference node, v0.1.
//!
//! Proof of work orders the ledger (SHA-256d). A STARK over SHA-256 proves every
//! spend. Notes are shielded. Verified work settles through escrow and fraud proofs.
//! Hash- and time-locked payments swap with Lightning.
//! Everything rests on SHA-256.

pub mod audit;
pub mod auxpow;
pub mod chain;
pub mod channel;
pub mod deliver;
pub mod codec;
pub mod cond;
pub mod covenant_stark;
pub mod hash;
pub mod job;
pub mod light;
pub mod lock;
pub mod nftree;
pub mod node;
pub mod note;
pub mod params;
pub mod peers;
mod params_genesis;
pub mod pow;
pub mod rpc;
pub mod script;
pub mod spend;
pub mod state;
pub mod swap;
pub mod tx;
pub mod wallet;
