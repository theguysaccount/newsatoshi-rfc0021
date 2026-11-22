//! A light client: it follows the chain header by header, with the checks a full node makes
//! before it fetches a block (linkage, difficulty, work, time, checkpoints), and holds no
//! blocks. It then checks that its tip commits to the note-tree root a node reports, so a
//! wallet can confirm that its notes are in a tree the chain's work commits to.
//!
//! This is the security of Bitcoin's simplified payment verification: to fool it, a node
//! must outwork the chain. It does not show that the blocks are valid, nor that a note is
//! unspent; the chain proof (white paper §§5–6) and the main network's nullifier tree will.

use crate::chain::{check_run, genesis_block, Entry};
use crate::codec::{Reader, Res, Writer};
use crate::hash::Word8;
use crate::params::Params;
use crate::pow;
use crate::state::DigestParts;
use crate::tx::{header_commit, Block, Header};
use primitive_types::U256;
use std::collections::VecDeque;

/// The last header a light client has checked, the times of the ten before it, and the
/// work behind it.
#[derive(Clone, Debug)]
pub struct HeaderTip {
    pub tip: Entry,
    times: VecDeque<u32>,
}

impl HeaderTip {
    /// Start at the network's genesis block, which the software names.
    pub fn genesis(params: &Params) -> HeaderTip {
        let g = genesis_block(params);
        let tip = Entry { hash: g.hash(), prev: [0; 32], height: 0, time: g.header.time, bits: g.header.bits, work: pow::work(g.header.bits) };
        HeaderTip { times: VecDeque::from([tip.time]), tip }
    }

    /// Follow a run of headers on top of the tip; `now` is the time in seconds. On any
    /// failure the tip is unchanged.
    pub fn extend(&mut self, params: &Params, hs: &[Block], now: i64) -> Result<(), String> {
        if hs.iter().any(|b| !b.txs.is_empty()) {
            return Err("a header with transactions".into());
        }
        let (tip, times) = check_run(params, self.tip.clone(), self.times.clone(), hs, now)?;
        self.tip = tip;
        self.times = times;
        Ok(())
    }

    /// Check that `header`, the tip, commits to a state whose parts are `parts`; returns the
    /// note-tree root it commits to.
    pub fn committed_root(&self, header: &Header, tx_root: &[u8; 32], parts: &DigestParts) -> Result<Word8, String> {
        if header.hash() != self.tip.hash {
            return Err("that is not the header this client has followed to".into());
        }
        if parts.height != self.tip.height {
            return Err("the state is for another height".into());
        }
        if header.commit != header_commit(tx_root, &parts.digest()) {
            return Err("the header does not commit to that state".into());
        }
        Ok(parts.tree_root)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let e = &self.tip;
        let mut work = [0u8; 32];
        e.work.to_big_endian(&mut work);
        w.raw(&e.hash).raw(&e.prev).u32(e.height).u32(e.time).u32(e.bits).raw(&work).u32(self.times.len() as u32);
        for t in &self.times {
            w.u32(*t);
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Res<HeaderTip> {
        let mut r = Reader::new(b);
        let tip = Entry { hash: r.arr()?, prev: r.arr()?, height: r.u32()?, time: r.u32()?, bits: r.u32()?, work: U256::from_big_endian(&r.arr::<32>()?) };
        let n = r.u32()?;
        if n == 0 || n > 11 {
            return Err("bad light-client state".into());
        }
        let times = (0..n).map(|_| r.u32()).collect::<Res<VecDeque<u32>>>()?;
        r.finish()?;
        Ok(HeaderTip { tip, times })
    }
}
