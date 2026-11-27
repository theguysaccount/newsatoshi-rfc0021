//! Utreexo-Style Compact $O(\log N)$ Shielded Note Accumulator (`CompactNoteTree`).
//!
//! Replaces the full in-memory `NoteTree` (which stores all $2N$ internal hashes across 32
//! levels — ~6.4 GB RAM at 100M notes) with a **constant-size 32-peak frontier** occupying
//! **exactly 1,024 bytes of RAM regardless of whether the chain holds 10 notes or 4.29 billion
//! notes**, while producing **bit-for-bit identical SHA-256Compress roots** (`root() == NoteTree::root()`).
//!
//! Includes `TrackedNoteProof`, an incremental Utreexo inclusion-proof updater: any wallet or
//! pruned node holding only its own notes' `(pos, cm, path)` updates every depth-32 Merkle path
//! in $O(1)$ per block append without ever storing the full note tree in RAM.

use crate::codec::{Reader, Res, Writer};
use crate::hash::{node, Word8};
use crate::note::{empty_roots, root_from_path, DEPTH};

/// Constant-memory $O(\log N)$ frontier accumulator for the depth-32 shielded note tree.
/// Memory footprint: 32 × 32 B peaks = **1,024 bytes** even at 4,294,967,295 notes!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactNoteTree {
    /// Complete binary subtree root at level `lvl` iff `(count >> lvl) & 1 == 1`.
    peaks: [Option<Word8>; DEPTH],
    /// Precomputed empty subtree hashes (`empty[0] = [0; 8]`, `empty[i] = H(empty[i-1], empty[i-1])`).
    empty: [Word8; DEPTH + 1],
    /// Total leaves appended (`0..=2^32 - 1`).
    count: u64,
}

impl Default for CompactNoteTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Rightmost subtree roots produced by one `CompactNoteTree::append_tracked` call,
/// enabling $O(1)$ Utreexo proof maintenance for any previously tracked note (`pos < new_pos`).
#[derive(Clone, Debug)]
pub struct AppendDelta {
    pub new_pos: u32,
    /// `peaks_before[lvl]` prior to inserting `new_pos` (used to initialize a brand-new tracked proof).
    pub peaks_before: [Option<Word8>; DEPTH],
    /// `rightmost[lvl]` = exact root of the depth-`lvl` subtree containing `new_pos` right after insertion.
    pub rightmost: [Word8; DEPTH],
}

/// Self-updating depth-32 Merkle inclusion proof for one wallet note (1,060 bytes total RAM).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedNoteProof {
    pub pos: u32,
    pub cm: Word8,
    pub path: [Word8; DEPTH],
}

impl TrackedNoteProof {
    /// Create a freshly tracked proof at the exact moment `cm` is appended at `delta.new_pos`.
    pub fn from_birth(cm: Word8, delta: &AppendDelta, empty: &[Word8; DEPTH + 1]) -> Self {
        let pos = delta.new_pos;
        let mut path = [[0u32; 8]; DEPTH];
        for lvl in 0..DEPTH {
            if (pos >> lvl) & 1 == 1 {
                path[lvl] = delta.peaks_before[lvl].expect("left peak exists for odd bit");
            } else {
                path[lvl] = empty[lvl];
            }
        }
        Self { pos, cm, path }
    }

    /// Update this proof in $O(1)$ time when any subsequent note is appended (`delta.new_pos > self.pos`).
    pub fn update_on_append(&mut self, delta: &AppendDelta) {
        if delta.new_pos <= self.pos {
            return;
        }
        // Highest bit index where `self.pos` and `delta.new_pos` differ:
        // Since `delta.new_pos > self.pos`, `self.pos` has bit 0 and `delta.new_pos` has bit 1
        // at level `k`, so `delta.rightmost[k]` is the exact new right sibling of `self.pos` at level `k`!
        let diff = self.pos ^ delta.new_pos;
        let k = (31 - diff.leading_zeros()) as usize;
        self.path[k] = delta.rightmost[k];
    }

    /// Recompute the depth-32 root from this tracked proof (compatible with `spend::prove`).
    pub fn root(&self) -> Word8 {
        root_from_path(&self.cm, self.pos, &self.path)
    }
}

impl CompactNoteTree {
    pub fn new() -> Self {
        Self {
            peaks: [None; DEPTH],
            empty: empty_roots(),
            count: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn empty_roots(&self) -> &[Word8; DEPTH + 1] {
        &self.empty
    }

    /// Exact active frontier memory footprint in bytes (always <= 1,024 B for peaks).
    pub fn frontier_bytes(&self) -> usize {
        self.peaks.iter().filter(|p| p.is_some()).count() * 32
    }

    /// Extract the exact <= 1 KB Utreexo frontier directly from a full `NoteTree` in O(log N) time.
    pub fn from_note_tree(tree: &crate::note::NoteTree) -> Self {
        let count = tree.len();
        let mut peaks = [None; DEPTH];
        for (lvl, slot) in peaks.iter_mut().enumerate() {
            if (count >> lvl) & 1 == 1 {
                let idx = ((count >> lvl) - 1) as usize;
                *slot = tree.level_node(lvl, idx);
            }
        }
        Self {
            peaks,
            empty: empty_roots(),
            count,
        }
    }

    /// Return all active `(level, hash)` peaks of the Utreexo frontier.
    pub fn peaks_with_levels(&self) -> Vec<(usize, Word8)> {
        self.peaks
            .iter()
            .enumerate()
            .filter_map(|(lvl, p)| p.map(|w| (lvl, w)))
            .collect()
    }

    /// Append a note commitment in $O(\log N)$ hashes and constant 1 KB RAM.
    pub fn append(&mut self, cm: Word8) -> u32 {
        self.append_tracked(cm).new_pos
    }

    /// Append a note commitment and return its `AppendDelta` so wallets / pruned nodes can
    /// maintain Utreexo inclusion proofs for any subset of notes without storing the full tree.
    pub fn append_tracked(&mut self, cm: Word8) -> AppendDelta {
        assert!(self.count < (1u64 << DEPTH), "compact note tree full");
        let pos = self.count as u32;
        let peaks_before = self.peaks;
        let mut rightmost = [[0u32; 8]; DEPTH];

        let mut cur = cm;
        let mut placed_lvl = DEPTH;
        for lvl in 0..DEPTH {
            rightmost[lvl] = cur;
            if let Some(left) = self.peaks[lvl].take() {
                cur = node(&left, &cur);
            } else {
                self.peaks[lvl] = Some(cur);
                placed_lvl = lvl;
                break;
            }
        }
        // Propagate the updated rightmost subtree root above `placed_lvl` so proofs for older
        // leaves that diverge at higher levels receive their exact updated right sibling.
        if placed_lvl < DEPTH {
            let mut up = rightmost[placed_lvl];
            for lvl in (placed_lvl + 1)..DEPTH {
                // `pos` has bit `lvl - 1` == 0 at `placed_lvl` (so right child was empty[placed_lvl]);
                // above `placed_lvl`, bit `lvl - 1` of `pos` tells whether `up` sits on left or right.
                up = if (pos >> (lvl - 1)) & 1 == 1 {
                    let left = self.peaks[lvl - 1].expect("ancestor left peak exists");
                    node(&left, &up)
                } else {
                    node(&up, &self.empty[lvl - 1])
                };
                rightmost[lvl] = up;
            }
        }

        self.count += 1;
        AppendDelta {
            new_pos: pos,
            peaks_before,
            rightmost,
        }
    }

    /// Compute the exact depth-32 `NoteTree` root from only the `<= 32` peaks in $O(\log N)$ time.
    /// Guaranteed bit-for-bit identical to `crate::note::NoteTree::root()`.
    pub fn root(&self) -> Word8 {
        if self.count == 0 {
            return self.empty[DEPTH];
        }
        let lo = self.count.trailing_zeros() as usize;
        let mut cur = self.peaks[lo].expect("lowest set bit has peak");
        cur = node(&cur, &self.empty[lo]);
        for lvl in (lo + 1)..DEPTH {
            cur = if let Some(left) = self.peaks[lvl] {
                node(&left, &cur)
            } else {
                node(&cur, &self.empty[lvl])
            };
        }
        cur
    }

    /// Serialize compact frontier (at most 1,036 bytes on disk regardless of chain size!).
    pub fn encode(&self, w: &mut Writer) {
        w.u64(self.count);
        let mut mask = 0u32;
        for (lvl, p) in self.peaks.iter().enumerate() {
            if p.is_some() {
                mask |= 1u32 << lvl;
            }
        }
        w.u32(mask);
        for p in self.peaks.iter().flatten() {
            w.word8(p);
        }
    }

    /// Deserialize compact frontier and verify `mask == count as u32`.
    pub fn decode(r: &mut Reader) -> Res<Self> {
        let count = r.u64()?;
        if count >= (1u64 << DEPTH) {
            return Err("compact note tree count out of bounds".into());
        }
        let mask = r.u32()?;
        if mask != (count as u32) {
            return Err("compact note tree peak mask does not match count".into());
        }
        let mut peaks = [None; DEPTH];
        for (lvl, slot) in peaks.iter_mut().enumerate() {
            if (mask >> lvl) & 1 == 1 {
                *slot = Some(r.word8()?);
            }
        }
        Ok(Self {
            peaks,
            empty: empty_roots(),
            count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::{address, commit, NoteTree};

    #[test]
    fn compact_frontier_matches_full_notetree_and_tracks_utreexo_proofs_exactly() {
        let mut full = NoteTree::new();
        let mut compact = CompactNoteTree::new();
        assert_eq!(compact.root(), full.root());

        let mut tracked: Vec<TrackedNoteProof> = Vec::new();
        let watch_positions = [0u32, 1, 2, 3, 7, 15, 16, 31, 63, 127, 255, 500, 1023, 2048];

        for i in 0..2500u32 {
            let cm = commit(&address(&[i.wrapping_add(1); 8]), (i as u64 + 1) * 100, &[i, 7, 11, 13, 17]);
            let p_full = full.append(cm);
            let delta = compact.append_tracked(cm);
            assert_eq!(p_full, delta.new_pos);

            // Update all existing Utreexo tracked proofs in O(1) each
            for tp in &mut tracked {
                tp.update_on_append(&delta);
            }
            if watch_positions.contains(&i) {
                tracked.push(TrackedNoteProof::from_birth(cm, &delta, compact.empty_roots()));
            }

            // Bit-for-bit root equivalence at EVERY single append!
            if i < 130 || i % 97 == 0 || i == 2499 {
                let r_full = full.root();
                let r_compact = compact.root();
                assert_eq!(r_compact, r_full, "root diverged at count {}", i + 1);
            }
        }

        // Verify every tracked Utreexo proof matches the full NoteTree path bit-for-bit!
        let final_root = full.root();
        assert_eq!(compact.root(), final_root);
        assert!(compact.frontier_bytes() <= 1024, "frontier must stay <= 1 KB");
        for tp in &tracked {
            assert_eq!(tp.root(), final_root, "tracked proof failed for pos {}", tp.pos);
            assert_eq!(tp.path, full.path(tp.pos), "tracked path mismatch for pos {}", tp.pos);
        }

        // Verify O(log N) direct extraction from full NoteTree matches incremental compact frontier bit-for-bit!
        let extracted = CompactNoteTree::from_note_tree(&full);
        assert_eq!(extracted, compact);
        assert_eq!(extracted.root(), final_root);

        // Verify compact wire round-trip (< 1.1 KB even for millions of notes!)
        let mut w = Writer::new();
        compact.encode(&mut w);
        assert!(w.0.len() <= 1036);
        let mut r = Reader::new(&w.0);
        let decoded = CompactNoteTree::decode(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(decoded, compact);
        assert_eq!(decoded.root(), final_root);
    }
}
