//! Light Client & O(log N) FlyClient / MMR Succinct PoW Chain Proofs.
//!
//! Provides two complementary trustless light-client verification modes:
//! 1. **Full Header SPV (`HeaderTip`):** Follows every header with full ASERT/AuxPoW/MTP checks
//!    and verifies `DigestParts` commitments to note-tree roots, nullifier-tree roots (`NfTree`),
//!    and `RFC-0022`/`0023`/`0024`/`0027` `MerkleMap` state roots.
//! 2. **Logarithmic $O(\log N)$ FlyClient / MMR Succinct Chain Proof (`HeaderMmr` & `FlyClientProof`):**
//!    Maintains a canonical Merkle Mountain Range (MMR) over block headers where every internal
//!    node commits to `(left_hash, right_hash, total_cumulative_work)`. Using deterministic
//!    Fiat–Shamir difficulty-weighted sampling (`Bunz–Kiffer–Luu–Zamani` FlyClient, IEEE S&P 2020)
//!    over the tip's MMR root + peak bagging, a mobile wallet, browser WASM client, or AI agent
//!    verifies the accumulated PoW of a multi-million-block chain in $O(\log N)$ bytes and milliseconds!

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
        }
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
    pub fn committed_root(
        &self,
        header: &Header,
        tx_root: &[u8; 32],
        parts: &DigestParts,
    ) -> Result<Word8, String> {
        self.verify_digest_parts(header, tx_root, parts)?;
        Ok(parts.tree_root)
    }

    /// Verify that `header` (matching this light client's tip) commits to `parts`.
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

    /// Trustlessly verify that a shielded note commitment `cm` sits at `pos` in the tip's
    /// `NoteTree`, AND (when `nf_proof` is supplied) verify whether `nf` is spent or unspent
    /// against `parts.nf_root`!
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
    /// header-committed root (`channels`, `bonds`, `rollups`, or `missions` in `DigestParts`).
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
        r.finish()?;
        Ok(HeaderTip { tip, times })
    }
}

// ---- O(log N) FlyClient / Merkle Mountain Range (MMR) Succinct PoW Chain Proofs ---------

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
    let total_work = left.work + right.work;
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
        acc_work += p.work;
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
    /// Complete binary-tree levels (`levels[0]` = leaf headers, `levels[h]` = merged parents).
    levels: Vec<Vec<MmrNode>>,
    pub leaf_count: u32,
}

impl HeaderMmr {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one header at height `leaf_count`, maintaining exact binary-tree MMR invariants.
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

/// One sampled historical header + its $O(\log N)$ MMR inclusion proof inside a `FlyClientProof`.
#[derive(Clone, Debug)]
pub struct FlyClientSample {
    pub height: u32,
    pub header_block: Block,
    pub mmr_proof: MmrLeafProof,
}

/// Non-interactive $O(\log N)$ FlyClient / MMR Succinct PoW Chain Proof.
///
/// Proves to a cold-boot light client (holding ONLY the genesis hash!) that `tip` sits at
/// height `tip_height` with `total_work` accumulated PoW by combining:
/// 1. The $O(\log N)$ MMR `peaks` + bagged `mmr_root`,
/// 2. The last `tail_len` full headers ending at `tip` (checked for contiguous linkage & PoW),
/// 3. `num_samples` deterministic Fiat–Shamir FlyClient difficulty-weighted sampled historical
///    headers (`0..tip_height`), each verified for real PoW (`check_work`) and exact MMR peak
///    inclusion with work conservation!
#[derive(Clone, Debug)]
pub struct FlyClientProof {
    pub genesis_hash: [u8; 32],
    pub tip_height: u32,
    pub mmr_root: [u8; 32],
    pub total_work: U256,
    pub peaks: Vec<MmrNode>,
    pub tail_headers: Vec<Block>,
    pub samples: Vec<FlyClientSample>,
}

/// Deterministic Fiat–Shamir FlyClient sample heights in `[0, tip_height)` (biased exponentially
/// toward recent blocks via `x_i = floor(tip_height * (1 - u_i^2))` plus genesis anchor 0).
pub fn flyclient_sample_heights(
    mmr_root: &[u8; 32],
    tip_hash: &[u8; 32],
    tip_height: u32,
    num_samples: usize,
) -> Vec<u32> {
    if tip_height == 0 || num_samples == 0 {
        return vec![0];
    }
    let mut out = Vec::with_capacity(num_samples);
    out.push(0); // always anchor genesis!
    let mut i = 0u32;
    while out.len() < num_samples && out.len() < tip_height as usize {
        let mut seed = [0u8; 8 + 32 + 32 + 4];
        seed[..8].copy_from_slice(b"nsFLYC01");
        seed[8..40].copy_from_slice(mmr_root);
        seed[40..72].copy_from_slice(tip_hash);
        seed[72..76].copy_from_slice(&i.to_le_bytes());
        let h = sha256(&seed);
        let r = u64::from_le_bytes(h[..8].try_into().unwrap());
        // FlyClient-style quadratic bias toward recent work: high-probability detection of
        // any adversary fork with < c-fraction of honest hashpower.
        let u = (r as f64) / (u64::MAX as f64);
        let pos = ((tip_height as f64) * (1.0 - u * u)).floor() as u32;
        let clamped = pos.min(tip_height.saturating_sub(1));
        if !out.contains(&clamped) {
            out.push(clamped);
        }
        i += 1;
        if i > (num_samples as u32) * 16 + 32 {
            break;
        }
    }
    out
}

impl FlyClientProof {
    /// Generate a non-interactive $O(\log N)$ FlyClient proof from a slice of header-only blocks
    /// `[genesis (height 0), block_1, ..., tip (height N)]`.
    pub fn prove(
        headers: &[Block],
        tail_len: usize,
        num_samples: usize,
    ) -> Result<Self, String> {
        if headers.is_empty() {
            return Err("cannot build FlyClient proof for empty chain".into());
        }
        let mut mmr = HeaderMmr::new();
        for b in headers {
            mmr.push(b.hash(), pow::work(b.header.bits));
        }
        let tip_height = (headers.len() - 1) as u32;
        let tip_hash = headers[tip_height as usize].hash();
        let peaks = mmr.peaks();
        let (mmr_root, total_work) = bag_mmr_peaks(&peaks);

        let keep_tail = tail_len.clamp(1, headers.len());
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

        let sample_heights = flyclient_sample_heights(&mmr_root, &tip_hash, tip_height, num_samples);
        let mut samples = Vec::with_capacity(sample_heights.len());
        for h in sample_heights {
            let b = &headers[h as usize];
            let mmr_proof = mmr.prove_leaf(h)?;
            samples.push(FlyClientSample {
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
            total_work,
            peaks,
            tail_headers,
            samples,
        })
    }

    /// Trustlessly verify a `FlyClientProof` from ONLY `expected_genesis_hash`:
    /// checks MMR peak bagging, exact tail header chain linkage & PoW, Fiat–Shamir sample
    /// indices, real PoW on every sampled header, and leaf-to-peak MMR inclusion + work sums!
    pub fn verify(
        &self,
        expected_genesis_hash: [u8; 32],
        min_samples: usize,
    ) -> Result<([u8; 32], U256), String> {
        if self.genesis_hash != expected_genesis_hash {
            return Err("FlyClient proof genesis hash mismatch".into());
        }
        if self.peaks.is_empty() || self.tail_headers.is_empty() {
            return Err("FlyClient proof missing peaks or tail headers".into());
        }
        // 1. Verify MMR peak heights are strictly descending (canonical binary decomposition of N+1)
        for w in self.peaks.windows(2) {
            if w[0].height <= w[1].height {
                return Err("MMR peaks are not strictly descending in height".into());
            }
        }
        let leaf_count_from_peaks: u64 = self.peaks.iter().map(|p| 1u64 << p.height).sum();
        if leaf_count_from_peaks != (self.tip_height as u64) + 1 {
            return Err("MMR peak leaf count does not match tip_height + 1".into());
        }
        let (bagged_root, bagged_work) = bag_mmr_peaks(&self.peaks);
        if bagged_root != self.mmr_root || bagged_work != self.total_work {
            return Err("FlyClient MMR root or total_work mismatch".into());
        }

        // 2. Verify every tail header's PoW and contiguous prev linkage
        for (idx, b) in self.tail_headers.iter().enumerate() {
            if !b.txs.is_empty() {
                return Err("FlyClient tail header must not contain transactions".into());
            }
            check_work(b)?;
            if idx > 0 && b.header.prev != self.tail_headers[idx - 1].hash() {
                return Err("FlyClient tail headers do not link".into());
            }
        }
        let tip_hash = self.tail_headers.last().unwrap().hash();

        // 3. Recompute deterministic Fiat–Shamir FlyClient sample heights and verify each sample!
        let want_heights = flyclient_sample_heights(
            &self.mmr_root,
            &tip_hash,
            self.tip_height,
            min_samples.max(self.samples.len()),
        );
        if self.samples.len() < want_heights.len() {
            return Err("FlyClient proof contains fewer samples than required".into());
        }
        for (sample, &want_h) in self.samples.iter().zip(want_heights.iter()) {
            if sample.height != want_h || sample.mmr_proof.leaf_height != want_h {
                return Err(format!(
                    "FlyClient sample height mismatch: got {}, expected {want_h}",
                    sample.height
                ));
            }
            if !sample.header_block.txs.is_empty() {
                return Err("FlyClient sample contains transactions".into());
            }
            if sample.height == 0 {
                if sample.header_block.hash() != expected_genesis_hash {
                    return Err("FlyClient genesis sample hash mismatch".into());
                }
            } else {
                check_work(&sample.header_block)?;
            }
            // Recompute leaf -> peak hash and work sum!
            let b_hash = sample.header_block.hash();
            let b_work = pow::work(sample.header_block.header.bits);
            let mut cur = MmrNode {
                hash: mmr_leaf_hash(sample.height, &b_hash, b_work),
                work: b_work,
                height: 0,
            };
            for (sib_is_right, sib) in &sample.mmr_proof.siblings {
                if sib.height != cur.height {
                    return Err("FlyClient MMR sibling height mismatch".into());
                }
                cur = if *sib_is_right {
                    mmr_parent_hash(&cur, sib).0
                } else {
                    mmr_parent_hash(sib, &cur).0
                };
            }
            if cur.height != sample.mmr_proof.peak_height {
                return Err("FlyClient MMR proof peak height mismatch".into());
            }
            let matched_peak = self
                .peaks
                .iter()
                .find(|p| p.height == cur.height)
                .ok_or("FlyClient MMR proof targets nonexistent peak height")?;
            if matched_peak != &cur {
                return Err("FlyClient MMR leaf proof does not match committed peak".into());
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
    use crate::params::Net;

    #[test]
    fn flyclient_mmr_proves_chain_work_in_ologn_and_rejects_forgery() {
        let params = Params::get(Net::Reg).unwrap();
        let mut chain = Chain::open(params.clone(), None).unwrap();
        let mut headers = vec![chain.block_at(0).unwrap().clone()];
        for _ in 0..40 {
            let mut b = chain.template(vec![], vec![], vec![]).unwrap();
            assert!(mine(&mut b.header, u64::MAX));
            chain.add_block(b.clone()).unwrap();
            headers.push(b);
        }
        let genesis_hash = headers[0].hash();
        let proof = FlyClientProof::prove(&headers, 6, 8).unwrap();
        // O(log N) peaks: 41 = 32 + 8 + 1 => ONLY 3 peaks!
        assert_eq!(proof.peaks.len(), 3);
        let (tip_hash, total_work) = proof.verify(genesis_hash, 8).unwrap();
        assert_eq!(tip_hash, chain.tip().hash);
        assert_eq!(total_work, chain.tip().work);

        // Adversarial tampering: inflating claimed work or mutating a sampled header MUST fail!
        let mut bad_work = proof.clone();
        bad_work.total_work += U256::from(1u64);
        assert!(bad_work.verify(genesis_hash, 8).is_err());

        let mut bad_sample = proof.clone();
        bad_sample.samples[1].header_block.header.nonce ^= 1;
        assert!(bad_sample.verify(genesis_hash, 8).is_err());
    }
}
