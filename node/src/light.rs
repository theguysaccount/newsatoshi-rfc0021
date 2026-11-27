//! Light Client & Work-Proportional O(log N) FlyClient / MMR Succinct PoW Chain Proofs.
//!
//! Provides two trustless light-client verification modes:
//! 1. **Full Header SPV (`HeaderTip`):** Follows every header with full ASERT/AuxPoW/MTP checks
//!    and verifies `DigestParts` commitments to note-tree roots, nullifier-tree roots (`NfTree`),
//!    PayWord channels, and `PriorLock` state roots.
//! 2. **Work-Proportional $O(\log N)$ FlyClient / MMR Proof (`HeaderMmr` & `FlyClientProof`):**
//!    Maintains a canonical Merkle Mountain Range (MMR) over ancestor headers `[0..tip_height)`
//!    where every internal node commits to `(left_hash, left_work, right_hash, right_work, total_work)`.
//!    - Samples deterministic target **cumulative work offsets** `w_i ∈ [0, ancestor_work)`
//!      (NOT block heights!) using exact integer U512 quadratic bias (Bünz et al. 2019).
//!    - Verifies that each sample's MMR path lands in `[leaf_work_start, leaf_work_start + leaf_work)`
//!      covering `w_i`, so inflating ANY sibling node's claimed work (`sib.work`) is caught
//!      with overwhelming probability.
//!    - Binds `tip_header.commit == header_commit(tip_tx_root, tip_digest_parts.digest())`,
//!      binds `tip_digest_parts.header_mmr == Some(mmr_root)` (on Mainnet v2), and binds
//!      `tip_header.prev` to the exact rightmost leaf (`tip_height - 1`) of `mmr_root`.

use crate::chain::{check_run, check_work, genesis_block, Entry};
use crate::codec::{Reader, Res, Writer};
use crate::hash::{sha256, words_to_bytes, Word8};
use crate::merkmap::{verify_proof, MerkleProof};
use crate::nftree::{self, NfProof};
use crate::note::{root_from_path, DEPTH};
use crate::params::Params;
use crate::pow;
use crate::state::DigestParts;
use crate::tx::{header_commit, Block, Header};
use primitive_types::{U256, U512};
use std::collections::VecDeque;

/// The last header a light client has checked, the times of the ten before it, the work behind it,
/// and the optional ASERT steady-state anchor `(bits, time)` captured at `params.launch_blocks`.
#[derive(Clone, Debug)]
pub struct HeaderTip {
    pub tip: Entry,
    times: VecDeque<u32>,
    pub steady_anchor: Option<(u32, i64)>,
}

impl HeaderTip {
    pub fn genesis(params: &Params) -> HeaderTip {
        let g = genesis_block(params);
        let tip = Entry {
            hash: g.hash(),
            prev: [0; 32],
            height: 0,
            time: g.header.time,
            bits: g.header.bits,
            work: pow::work(g.header.bits),
        };
        HeaderTip {
            times: VecDeque::from([tip.time]),
            tip,
            steady_anchor: None,
        }
    }

    pub fn extend(&mut self, params: &Params, hs: &[Block], now: i64) -> Result<(), String> {
        if hs.iter().any(|b| !b.txs.is_empty()) {
            return Err("a header with transactions".into());
        }
        let (tip, times, steady_anchor) =
            check_run(params, self.tip.clone(), self.times.clone(), self.steady_anchor, hs, now)?;
        self.tip = tip;
        self.times = times;
        self.steady_anchor = steady_anchor;
        Ok(())
    }

    pub fn committed_root(
        &self,
        header: &Header,
        tx_root: &[u8; 32],
        parts: &DigestParts,
    ) -> Result<Word8, String> {
        self.verify_digest_parts(header, tx_root, parts)?;
        Ok(parts.tree_root)
    }

    pub fn verify_digest_parts(
        &self,
        header: &Header,
        tx_root: &[u8; 32],
        parts: &DigestParts,
    ) -> Result<(), String> {
        if header.hash() != self.tip.hash {
            return Err("that is not the header this client has followed to".into());
        }
        if parts.height != self.tip.height {
            return Err("the state is for another height".into());
        }
        if header.commit != header_commit(tx_root, &parts.digest()) {
            return Err("the header does not commit to that state".into());
        }
        Ok(())
    }

    pub fn verify_note_and_nullifier(
        &self,
        header: &Header,
        tx_root: &[u8; 32],
        parts: &DigestParts,
        cm: &Word8,
        pos: u32,
        cm_path: &[Word8; DEPTH],
        nf: Option<(&Word8, &NfProof)>,
    ) -> Result<Option<bool>, String> {
        self.verify_digest_parts(header, tx_root, parts)?;
        if root_from_path(cm, pos, cm_path) != parts.tree_root {
            return Err("note commitment Merkle path does not match header tree_root".into());
        }
        if let Some((nf_word, nf_proof)) = nf {
            let nf_root_bytes = parts
                .nf_root
                .ok_or("header digest does not commit to nullifier tree")?;
            let nf_root = crate::hash::bytes_to_words(&nf_root_bytes);
            let spent = nftree::check(&nf_root, nf_word, nf_proof)
                .ok_or("invalid nullifier Merkle inclusion/non-inclusion proof")?;
            return Ok(Some(spent));
        }
        Ok(None)
    }

    /// Trustlessly verify a canonical `MerkleMap` inclusion/non-inclusion proof against a
    /// header-committed root (`channels` or `priors` in `DigestParts`).
    pub fn verify_state_map_proof(
        &self,
        header: &Header,
        tx_root: &[u8; 32],
        parts: &DigestParts,
        committed_root: Option<[u8; 32]>,
        proof: &MerkleProof,
    ) -> Result<(), String> {
        self.verify_digest_parts(header, tx_root, parts)?;
        let root = committed_root.unwrap_or([0u8; 32]);
        if !verify_proof(&root, proof) {
            return Err("state MerkleMap proof failed against header commitment".into());
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let e = &self.tip;
        let mut work = [0u8; 32];
        e.work.to_big_endian(&mut work);
        w.raw(&e.hash)
            .raw(&e.prev)
            .u32(e.height)
            .u32(e.time)
            .u32(e.bits)
            .raw(&work)
            .u32(self.times.len() as u32);
        for t in &self.times {
            w.u32(*t);
        }
        if let Some((a_bits, a_time)) = self.steady_anchor {
            w.bool(true).u32(a_bits).u64(a_time as u64);
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Res<HeaderTip> {
        let mut r = Reader::new(b);
        let tip = Entry {
            hash: r.arr()?,
            prev: r.arr()?,
            height: r.u32()?,
            time: r.u32()?,
            bits: r.u32()?,
            work: U256::from_big_endian(&r.arr::<32>()?),
        };
        let n = r.u32()?;
        if n == 0 || n > 11 {
            return Err("bad light-client state".into());
        }
        let times = (0..n).map(|_| r.u32()).collect::<Res<VecDeque<u32>>>()?;
        let steady_anchor = if r.remaining() > 0 {
            if r.bool()? {
                Some((r.u32()?, r.u64()? as i64))
            } else {
                None
            }
        } else {
            None
        };
        r.finish()?;
        Ok(HeaderTip { tip, times, steady_anchor })
    }
}

// ---- Work-Proportional O(log N) FlyClient / Merkle Mountain Range (MMR) -----------------

/// Node inside a FlyClient PoW Merkle Mountain Range: commits to subtree hash + cumulative PoW work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmrNode {
    pub hash: [u8; 32],
    pub work: U256,
    pub height: u32,
}

fn u256_be(v: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    v.to_big_endian(&mut out);
    out
}

pub fn mmr_leaf_hash(block_height: u32, block_hash: &[u8; 32], work: U256) -> [u8; 32] {
    let mut buf = [0u8; 8 + 4 + 32 + 32];
    buf[..8].copy_from_slice(b"nsMMRLF1");
    buf[8..12].copy_from_slice(&block_height.to_le_bytes());
    buf[12..44].copy_from_slice(block_hash);
    buf[44..76].copy_from_slice(&u256_be(work));
    sha256(&buf)
}

pub fn mmr_parent_hash(left: &MmrNode, right: &MmrNode) -> (MmrNode, U256) {
    let total_work = left.work.saturating_add(right.work);
    let mut buf = [0u8; 8 + 32 + 32 + 32 + 32 + 32];
    buf[..8].copy_from_slice(b"nsMMRND1");
    buf[8..40].copy_from_slice(&left.hash);
    buf[40..72].copy_from_slice(&u256_be(left.work));
    buf[72..104].copy_from_slice(&right.hash);
    buf[104..136].copy_from_slice(&u256_be(right.work));
    buf[136..168].copy_from_slice(&u256_be(total_work));
    let node = MmrNode {
        hash: sha256(&buf),
        work: total_work,
        height: left.height + 1,
    };
    (node, total_work)
}

/// Bag MMR peaks right-to-left into a single 32-byte root + total cumulative PoW work.
pub fn bag_mmr_peaks(peaks: &[MmrNode]) -> ([u8; 32], U256) {
    if peaks.is_empty() {
        return ([0u8; 32], U256::zero());
    }
    let mut acc_hash = peaks.last().unwrap().hash;
    let mut acc_work = peaks.last().unwrap().work;
    for p in peaks.iter().rev().skip(1) {
        acc_work = acc_work.saturating_add(p.work);
        let mut buf = [0u8; 8 + 32 + 32 + 32];
        buf[..8].copy_from_slice(b"nsMMRBAG");
        buf[8..40].copy_from_slice(&p.hash);
        buf[40..72].copy_from_slice(&acc_hash);
        buf[72..104].copy_from_slice(&u256_be(acc_work));
        acc_hash = sha256(&buf);
    }
    (acc_hash, acc_work)
}

/// Append-only Merkle Mountain Range over headers (`O(log N)` peaks and inclusion proofs).
#[derive(Clone, Debug, Default)]
pub struct HeaderMmr {
    levels: Vec<Vec<MmrNode>>,
    pub leaf_count: u32,
}

impl HeaderMmr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, block_hash: [u8; 32], block_work: U256) {
        let h = self.leaf_count;
        let leaf = MmrNode {
            hash: mmr_leaf_hash(h, &block_hash, block_work),
            work: block_work,
            height: 0,
        };
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(leaf);
        let mut lvl = 0usize;
        while self.levels[lvl].len() >= 2 && self.levels[lvl].len() % 2 == 0 {
            let len = self.levels[lvl].len();
            let left = self.levels[lvl][len - 2].clone();
            let right = self.levels[lvl][len - 1].clone();
            let (parent, _) = mmr_parent_hash(&left, &right);
            if self.levels.len() <= lvl + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[lvl + 1].push(parent);
            lvl += 1;
        }
        self.leaf_count += 1;
    }

    /// Return the $O(\log N)$ current peaks (left-to-right, strictly descending heights).
    pub fn peaks(&self) -> Vec<MmrNode> {
        let mut out = Vec::new();
        for lvl in (0..self.levels.len()).rev() {
            let len = self.levels[lvl].len();
            if len % 2 == 1 {
                out.push(self.levels[lvl][len - 1].clone());
            }
        }
        out
    }

    pub fn root_and_work(&self) -> ([u8; 32], U256) {
        bag_mmr_peaks(&self.peaks())
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_and_work().0
    }

    pub fn encode(&self, w: &mut Writer) {
        let leaves = self.levels.first().map(|v| v.as_slice()).unwrap_or(&[]);
        w.u32(leaves.len() as u32);
        for leaf in leaves {
            w.raw(&leaf.hash).raw(&u256_be(leaf.work));
        }
    }

    pub fn decode(r: &mut Reader) -> Res<HeaderMmr> {
        let n = r.u32()? as usize;
        if n > 10_000_000 {
            return Err("too many HeaderMmr leaves in snapshot".into());
        }
        let mut mmr = HeaderMmr::new();
        if n == 0 {
            return Ok(mmr);
        }
        mmr.levels.push(Vec::with_capacity(n.min(4096)));
        for _ in 0..n {
            let hash = r.arr::<32>()?;
            let work = U256::from_big_endian(&r.arr::<32>()?);
            mmr.levels[0].push(MmrNode { hash, work, height: 0 });
            let mut lvl = 0usize;
            while mmr.levels[lvl].len() >= 2 && mmr.levels[lvl].len() % 2 == 0 {
                let len = mmr.levels[lvl].len();
                let left = mmr.levels[lvl][len - 2].clone();
                let right = mmr.levels[lvl][len - 1].clone();
                let (parent, _) = mmr_parent_hash(&left, &right);
                if mmr.levels.len() <= lvl + 1 {
                    mmr.levels.push(Vec::new());
                }
                mmr.levels[lvl + 1].push(parent);
                lvl += 1;
            }
            mmr.leaf_count += 1;
        }
        Ok(mmr)
    }

    /// Locate the unique leaf index whose cumulative work interval `[start, start + work)`
    /// contains `target_work` by walking peaks left-to-right then descending `left.work` vs `right.work`.
    pub fn find_leaf_by_work(&self, target_work: U256) -> Result<u32, String> {
        let mut cursor = U256::zero();
        for lvl in (0..self.levels.len()).rev() {
            let len = self.levels[lvl].len();
            if len % 2 == 1 {
                let peak_idx = len - 1;
                let peak = &self.levels[lvl][peak_idx];
                if target_work < cursor.saturating_add(peak.work) {
                    let mut cur_lvl = lvl;
                    let mut idx = peak_idx;
                    while cur_lvl > 0 {
                        let left_idx = idx * 2;
                        let left_work = self.levels[cur_lvl - 1][left_idx].work;
                        if target_work < cursor.saturating_add(left_work) {
                            idx = left_idx;
                        } else {
                            cursor = cursor.saturating_add(left_work);
                            idx = left_idx + 1;
                        }
                        cur_lvl -= 1;
                    }
                    return Ok(idx as u32);
                }
                cursor = cursor.saturating_add(peak.work);
            }
        }
        Err("target_work exceeds total MMR work".into())
    }

    /// Build an $O(\log N)$ Merkle inclusion proof for leaf height `leaf_idx` up to its MMR peak.
    pub fn prove_leaf(&self, leaf_idx: u32) -> Result<MmrLeafProof, String> {
        if leaf_idx >= self.leaf_count {
            return Err("leaf index out of MMR bounds".into());
        }
        let mut idx = leaf_idx as usize;
        let mut siblings = Vec::new();
        let mut peak_height = 0u32;
        for lvl in 0..self.levels.len() {
            let sib = idx ^ 1;
            if sib < self.levels[lvl].len() {
                siblings.push((sib > idx, self.levels[lvl][sib].clone()));
                idx /= 2;
                peak_height = (lvl + 1) as u32;
            } else {
                break;
            }
        }
        Ok(MmrLeafProof {
            leaf_height: leaf_idx,
            peak_height,
            siblings,
        })
    }
}

/// One $O(\log N)$ MMR leaf-to-peak proof (sibling hash + work + side flag at each tree level).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmrLeafProof {
    pub leaf_height: u32,
    pub peak_height: u32,
    /// `(sibling_is_right, sibling_node)` bottom-up from leaf to its MMR peak.
    pub siblings: Vec<(bool, MmrNode)>,
}

/// Verify an `MmrLeafProof` against `peaks`, returning `(leaf_work_start, leaf_work)` AND
/// verifying exact height-index consistency so sibling left/right directions cannot be spoofed.
fn verify_leaf_against_peaks(
    peaks: &[MmrNode],
    leaf_height: u32,
    block_hash: &[u8; 32],
    leaf_work: U256,
    proof: &MmrLeafProof,
) -> Result<(U256, U256), String> {
    if proof.leaf_height != leaf_height {
        return Err("FlyClient MMR proof leaf height mismatch".into());
    }
    if leaf_work.is_zero() {
        return Err("FlyClient leaf has zero work".into());
    }
    let mut cur = MmrNode {
        hash: mmr_leaf_hash(leaf_height, block_hash, leaf_work),
        work: leaf_work,
        height: 0,
    };
    let mut work_left_in_peak = U256::zero();
    let mut leaf_offset_in_peak: u64 = 0;
    for (lvl, (sib_is_right, sib)) in proof.siblings.iter().enumerate() {
        if sib.height != cur.height {
            return Err("FlyClient MMR sibling height mismatch".into());
        }
        cur = if *sib_is_right {
            mmr_parent_hash(&cur, sib).0
        } else {
            work_left_in_peak = work_left_in_peak
                .checked_add(sib.work)
                .ok_or("FlyClient MMR work overflow")?;
            leaf_offset_in_peak |= 1u64 << lvl;
            mmr_parent_hash(sib, &cur).0
        };
    }
    if cur.height != proof.peak_height {
        return Err("FlyClient MMR proof peak height mismatch".into());
    }
    // Locate peak and compute exact prefix leaf count and prefix cumulative work of peaks to its left.
    let mut prefix_leaves: u64 = 0;
    let mut prefix_work = U256::zero();
    let mut matched = false;
    for p in peaks {
        if p.height == cur.height {
            if p != &cur {
                return Err("FlyClient MMR leaf proof does not match committed peak".into());
            }
            matched = true;
            break;
        }
        prefix_leaves += 1u64 << p.height;
        prefix_work = prefix_work
            .checked_add(p.work)
            .ok_or("FlyClient peak prefix work overflow")?;
    }
    if !matched {
        return Err("FlyClient MMR proof targets nonexistent peak height".into());
    }
    if prefix_leaves + leaf_offset_in_peak != leaf_height as u64 {
        return Err("FlyClient MMR leaf height disagrees with binary path".into());
    }
    let leaf_work_start = prefix_work
        .checked_add(work_left_in_peak)
        .ok_or("FlyClient leaf work start overflow")?;
    Ok((leaf_work_start, leaf_work))
}

/// One work-proportional sampled ancestor header + its $O(\log N)$ MMR proof inside `FlyClientProof`.
#[derive(Clone, Debug)]
pub struct FlyClientSample {
    /// Deterministic target cumulative work offset in `[0, ancestor_work)` (`0` for genesis).
    pub target_work: U256,
    pub height: u32,
    pub header_block: Block,
    pub mmr_proof: MmrLeafProof,
}

/// Non-interactive Work-Proportional $O(\log N)$ FlyClient / MMR Succinct PoW Chain Proof.
#[derive(Clone, Debug)]
pub struct FlyClientProof {
    pub genesis_hash: [u8; 32],
    pub tip_height: u32,
    /// Ancestor MMR root over headers `[0..tip_height)` (matches `DigestParts::header_mmr`!).
    pub mmr_root: [u8; 32],
    /// Cumulative PoW work over ancestor headers `[0..tip_height)`.
    pub ancestor_work: U256,
    /// Total cumulative PoW work over `[0..=tip_height]` (`ancestor_work + work(tip)`).
    pub total_work: U256,
    pub peaks: Vec<MmrNode>,
    /// Contiguous tail headers ending at `tip` (at least `[tip-1, tip]` when `tip_height > 0`).
    pub tail_headers: Vec<Block>,
    /// Mandatory MMR inclusion proof binding `tip_header.prev` (`tip_height - 1`) to the
    /// rightmost leaf of `mmr_root` (required whenever `tip_height > 0`).
    pub tail_prev_proof: Option<MmrLeafProof>,
    /// Tip block transaction root + `DigestParts`, proving `tip_header.commit` binds state & MMR.
    pub tip_tx_root: [u8; 32],
    pub tip_digest_parts: DigestParts,
    /// Work-proportional Fiat–Shamir sampled ancestor headers (genesis anchor at index 0).
    pub samples: Vec<FlyClientSample>,
}

/// Deterministic integer-only Fiat–Shamir work-proportional sample targets in `[0, ancestor_work)`.
/// Uses exact `U512` quadratic bias toward recent work (`w_i = (W - 1) - floor(W * u_i^2 / 2^256)`),
/// always starting with `0` (genesis anchor). Zero floating-point nondeterminism.
pub fn flyclient_sample_works(
    mmr_root: &[u8; 32],
    tip_hash: &[u8; 32],
    ancestor_work: U256,
    num_samples: usize,
) -> Vec<U256> {
    if ancestor_work.is_zero() || num_samples == 0 {
        return vec![];
    }
    let mut out = Vec::with_capacity(num_samples);
    out.push(U256::zero()); // always anchor genesis at work offset 0
    if ancestor_work == U256::one() {
        return out;
    }
    let w512 = U512::from(ancestor_work);
    let mut i = 0u32;
    while out.len() < num_samples {
        let mut seed = [0u8; 8 + 32 + 32 + 4];
        seed[..8].copy_from_slice(b"nsFLYC02");
        seed[8..40].copy_from_slice(mmr_root);
        seed[40..72].copy_from_slice(tip_hash);
        seed[72..76].copy_from_slice(&i.to_le_bytes());
        let h = sha256(&seed);
        let u = u128::from_le_bytes(h[..16].try_into().unwrap());
        let u_sq = U512::from(u) * U512::from(u); // in [0, 2^256)
        let offset = (w512 * u_sq) >> 256;
        let offset256 = U256::from_big_endian(&{
            let mut be = [0u8; 64];
            offset.to_big_endian(&mut be);
            let mut lo = [0u8; 32];
            lo.copy_from_slice(&be[32..64]);
            lo
        });
        let target = ancestor_work.saturating_sub(U256::one()).saturating_sub(offset256);
        out.push(target);
        i += 1;
    }
    out
}

impl FlyClientProof {
    /// Generate a non-interactive work-proportional $O(\log N)$ FlyClient proof from the
    /// active chain blocks `[genesis (height 0), ..., tip (height N)]` and tip `DigestParts`.
    pub fn prove(
        headers: &[Block],
        tip_tx_root: [u8; 32],
        tip_digest_parts: DigestParts,
        tail_len: usize,
        num_samples: usize,
    ) -> Result<Self, String> {
        if headers.is_empty() {
            return Err("cannot build FlyClient proof for empty chain".into());
        }
        let tip_height = (headers.len() - 1) as u32;
        let tip_block = &headers[tip_height as usize];
        let tip_hash = tip_block.hash();
        let tip_work = pow::work(tip_block.header.bits);

        // MMR covers ancestor headers `[0..tip_height)` (matches consensus `state.header_mmr`!).
        let mut mmr = HeaderMmr::new();
        for b in &headers[..tip_height as usize] {
            mmr.push(b.hash(), pow::work(b.header.bits));
        }
        let peaks = mmr.peaks();
        let (mmr_root, ancestor_work) = bag_mmr_peaks(&peaks);
        let total_work = ancestor_work
            .checked_add(tip_work)
            .ok_or("FlyClient total work overflow")?;

        let min_tail = if tip_height > 0 { 2 } else { 1 };
        let keep_tail = tail_len.max(min_tail).min(headers.len());
        let tail_start = headers.len() - keep_tail;
        let tail_headers: Vec<Block> = headers[tail_start..]
            .iter()
            .map(|b| Block {
                header: b.header,
                auxpow: b.auxpow.clone(),
                digest: [0u8; 32],
                txs: vec![],
            })
            .collect();

        let tail_prev_proof = if tip_height > 0 {
            Some(mmr.prove_leaf(tip_height - 1)?)
        } else {
            None
        };

        let target_works = flyclient_sample_works(&mmr_root, &tip_hash, ancestor_work, num_samples);
        let mut samples = Vec::with_capacity(target_works.len());
        for w_target in target_works {
            let h = mmr.find_leaf_by_work(w_target)?;
            let b = &headers[h as usize];
            let mmr_proof = mmr.prove_leaf(h)?;
            samples.push(FlyClientSample {
                target_work: w_target,
                height: h,
                header_block: Block {
                    header: b.header,
                    auxpow: b.auxpow.clone(),
                    digest: [0u8; 32],
                    txs: vec![],
                },
                mmr_proof,
            });
        }

        Ok(FlyClientProof {
            genesis_hash: headers[0].hash(),
            tip_height,
            mmr_root,
            ancestor_work,
            total_work,
            peaks,
            tail_headers,
            tail_prev_proof,
            tip_tx_root,
            tip_digest_parts,
            samples,
        })
    }

    /// Trustlessly verify a `FlyClientProof` from ONLY `expected_genesis_hash`.
    /// When `require_header_mmr_commit` is true (Mainnet v2), also enforces that the tip's
    /// 80-byte PoW header cryptographically commits to `self.mmr_root` via `DigestParts::header_mmr`.
    pub fn verify(
        &self,
        expected_genesis_hash: [u8; 32],
        min_samples: usize,
        require_header_mmr_commit: bool,
    ) -> Result<([u8; 32], U256), String> {
        if self.genesis_hash != expected_genesis_hash {
            return Err("FlyClient proof genesis hash mismatch".into());
        }
        if self.tail_headers.is_empty() {
            return Err("FlyClient proof missing tail headers".into());
        }

        // 1. Verify tail headers PoW & contiguous linkage
        for (idx, b) in self.tail_headers.iter().enumerate() {
            if !b.txs.is_empty() {
                return Err("FlyClient tail header must not contain transactions".into());
            }
            check_work(b)?;
            if idx > 0 && b.header.prev != self.tail_headers[idx - 1].hash() {
                return Err("FlyClient tail headers do not link".into());
            }
        }
        let tip_block = self.tail_headers.last().unwrap();
        let tip_hash = tip_block.hash();
        let tip_work = pow::work(tip_block.header.bits);

        // 2. Verify tip header commit binds `tip_tx_root` + `tip_digest_parts` (+ `header_mmr` on v2)
        if self.tip_digest_parts.height != self.tip_height {
            return Err("FlyClient tip_digest_parts height mismatch".into());
        }
        if tip_block.header.commit != header_commit(&self.tip_tx_root, &self.tip_digest_parts.digest()) {
            return Err("FlyClient tip header does not commit to tip_digest_parts".into());
        }
        if require_header_mmr_commit && self.tip_digest_parts.header_mmr != Some(self.mmr_root) {
            return Err("FlyClient tip header does not commit to ancestor MMR root".into());
        }

        if self.tip_height == 0 {
            if tip_hash != expected_genesis_hash
                || !self.peaks.is_empty()
                || !self.ancestor_work.is_zero()
                || self.total_work != tip_work
            {
                return Err("invalid genesis FlyClient proof".into());
            }
            return Ok((tip_hash, self.total_work));
        }

        // 3. Verify MMR peaks over `[0..tip_height)` are strictly descending and bag cleanly
        if self.peaks.is_empty() {
            return Err("FlyClient proof missing ancestor MMR peaks".into());
        }
        for w in self.peaks.windows(2) {
            if w[0].height <= w[1].height {
                return Err("MMR peaks are not strictly descending in height".into());
            }
        }
        let leaf_count_from_peaks: u64 = self.peaks.iter().map(|p| 1u64 << p.height).sum();
        if leaf_count_from_peaks != self.tip_height as u64 {
            return Err("MMR peak leaf count does not match tip_height".into());
        }
        let (bagged_root, bagged_work) = bag_mmr_peaks(&self.peaks);
        if bagged_root != self.mmr_root || bagged_work != self.ancestor_work {
            return Err("FlyClient MMR root or ancestor_work mismatch".into());
        }
        if self.ancestor_work.checked_add(tip_work) != Some(self.total_work) {
            return Err("FlyClient total_work != ancestor_work + tip_work".into());
        }

        // 4. Bind `tail_headers` directly to the rightmost ancestor MMR leaf (`tip_height - 1`)!
        if self.tail_headers.len() < 2 {
            return Err("FlyClient tail must include tip and its parent for MMR tip binding".into());
        }
        let prev_block = &self.tail_headers[self.tail_headers.len() - 2];
        let prev_proof = self
            .tail_prev_proof
            .as_ref()
            .ok_or("FlyClient missing tail_prev_proof binding tail to MMR")?;
        verify_leaf_against_peaks(
            &self.peaks,
            self.tip_height - 1,
            &prev_block.hash(),
            pow::work(prev_block.header.bits),
            prev_proof,
        )?;

        // 5. Work-proportional Fiat–Shamir verification: EVERY sample's target_work MUST lie
        //    strictly inside `[leaf_work_start, leaf_work_start + leaf_work)`!
        let want_works = flyclient_sample_works(
            &self.mmr_root,
            &tip_hash,
            self.ancestor_work,
            min_samples.max(self.samples.len()),
        );
        if self.samples.len() < want_works.len() {
            return Err("FlyClient proof contains fewer work samples than required".into());
        }
        for (idx, (sample, &want_w)) in self.samples.iter().zip(want_works.iter()).enumerate() {
            if sample.target_work != want_w {
                return Err(format!("FlyClient sample {idx} target_work mismatch"));
            }
            if !sample.header_block.txs.is_empty() {
                return Err("FlyClient sample contains transactions".into());
            }
            if idx == 0 {
                if sample.height != 0 || sample.header_block.hash() != expected_genesis_hash {
                    return Err("FlyClient genesis anchor sample mismatch".into());
                }
            } else if sample.height == 0 {
                if sample.header_block.hash() != expected_genesis_hash {
                    return Err("FlyClient genesis sample hash mismatch".into());
                }
            } else {
                check_work(&sample.header_block)?;
            }
            let b_hash = sample.header_block.hash();
            let b_work = pow::work(sample.header_block.header.bits);
            let (leaf_start, leaf_w) = verify_leaf_against_peaks(
                &self.peaks,
                sample.height,
                &b_hash,
                b_work,
                &sample.mmr_proof,
            )?;
            let leaf_end = leaf_start
                .checked_add(leaf_w)
                .ok_or("FlyClient leaf work interval overflow")?;
            if sample.target_work < leaf_start || sample.target_work >= leaf_end {
                return Err(format!(
                    "FlyClient work-proportional check failed for sample {idx}: target {} not in [{leaf_start}, {leaf_end})",
                    sample.target_work
                ));
            }
        }

        Ok((tip_hash, self.total_work))
    }
}

/// Helper: format a `Word8` commitment/nullifier root as 64-char hex for light-client APIs.
pub fn word8_hex(w: &Word8) -> String {
    hex::encode(words_to_bytes(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{mine, Chain};

    #[test]
    fn flyclient_work_proportional_rejects_sibling_work_inflation_and_unbound_tail() {
        // Mine a 33-block Mainnet v2 chain (header_mmr committed from genesis!)
        let mut params = Params::main_v2_with(1_762_473_600, u32::MAX, 0x207fffff);
        params.pow_limit = 0x207fffff;
        params.coinbase_maturity = 1;
        let mut chain = Chain::open(params, None).unwrap();
        let mut headers = vec![chain.block_at(0).unwrap()];
        for _ in 0..32 {
            let mut b = chain.template(vec![], vec![], vec![]).unwrap();
            assert!(mine(&mut b.header, u64::MAX));
            chain.add_block(b.clone()).unwrap();
            headers.push(b);
        }
        let genesis_hash = headers[0].hash();
        let tip_block = headers.last().unwrap();
        let parts = chain.state.digest_parts();
        let proof = FlyClientProof::prove(&headers, tip_block.tx_root(), parts.clone(), 4, 16).unwrap();

        // 32 ancestors = single peak of height 5!
        assert_eq!(proof.peaks.len(), 1);
        assert_eq!(proof.mmr_root, parts.header_mmr.unwrap());
        let (tip_hash, total_work) = proof.verify(genesis_hash, 16, true).unwrap();
        assert_eq!(tip_hash, chain.tip().hash);
        assert_eq!(total_work, chain.tip().work);

        // EXPLOIT REGRESSION 1: Adversary inflates a sibling node's work to 2^100 to forge
        // total_work without mining real PoW (the exact vulnerability found in v0.8.0!).
        let fake_work = U256::from(1u128 << 100);
        let mut forged = proof.clone();
        // Rebuild a fake peak with massive sibling work while keeping genesis honest
        let real_genesis_leaf = MmrNode {
            hash: mmr_leaf_hash(0, &genesis_hash, pow::work(headers[0].header.bits)),
            work: pow::work(headers[0].header.bits),
            height: 0,
        };
        let fake_sib = MmrNode { hash: [0xaa; 32], work: fake_work, height: 0 };
        let (fake_parent, _) = mmr_parent_hash(&real_genesis_leaf, &fake_sib);
        forged.peaks = vec![fake_parent.clone()];
        let (f_root, f_work) = bag_mmr_peaks(&forged.peaks);
        forged.mmr_root = f_root;
        forged.ancestor_work = f_work;
        forged.total_work = f_work + pow::work(tip_block.header.bits);
        forged.tip_height = 2;
        forged.samples[0].mmr_proof = MmrLeafProof {
            leaf_height: 0,
            peak_height: 1,
            siblings: vec![(true, fake_sib)],
        };
        assert!(
            forged.verify(genesis_hash, 8, false).is_err(),
            "sibling work inflation MUST be rejected by work-proportional FlyClient!"
        );

        // EXPLOIT REGRESSION 2: Replacing tail_headers with an unrelated mined block MUST fail!
        let mut unbound_tail = proof.clone();
        let prev_idx = unbound_tail.tail_headers.len() - 2;
        unbound_tail.tail_headers[prev_idx] = headers[5].clone();
        assert!(
            unbound_tail.verify(genesis_hash, 16, true).is_err(),
            "unbound tail header MUST be rejected!"
        );

        // EXPLOIT REGRESSION 3: Tampering tip_digest_parts or mmr_root MUST fail!
        let mut bad_parts = proof.clone();
        bad_parts.tip_digest_parts.issued += 1;
        assert!(bad_parts.verify(genesis_hash, 16, true).is_err());
    }
}
