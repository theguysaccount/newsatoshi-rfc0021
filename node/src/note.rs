//! Notes, addresses, nullifiers and the note tree, all from SHA256Compress.
//!
//!   address    a_pk = C[ "nsAD", sk(8), 0(7) ]
//!   commitment cm   = C[ "nsCM", a_pk(8), v_hi, v_lo, rho(5) ]
//!   nullifier  nf   = C[ "nsNF", sk(8), pos, rho(5), 0 ]
//!   tree node  n    = C[ left(8), right(8) ]                       (depth 32)
//!
//! `C` is one SHA-256 compression under the standard IV. Values are below 2^60 so that
//! any sum of four of them stays far inside the proof system's field.

use crate::hash::{compress, node, Word8};
use imbl::Vector;

pub const TAG_ADDR: u32 = u32::from_be_bytes(*b"nsAD");
pub const TAG_CM: u32 = u32::from_be_bytes(*b"nsCM");
pub const TAG_NF: u32 = u32::from_be_bytes(*b"nsNF");

pub const DEPTH: usize = 32;
/// Largest value one note may carry (2^60 − 1 base units).
pub const MAX_NOTE_VALUE: u64 = (1u64 << 60) - 1;

pub type Rho = [u32; 5];

pub fn address(sk: &Word8) -> Word8 {
    let mut b = [0u32; 16];
    b[0] = TAG_ADDR;
    b[1..9].copy_from_slice(sk);
    compress(&b)
}

/// `commit` for consensus code: an out-of-range value is an error, never a panic.
pub fn try_commit(a_pk: &Word8, v: u64, rho: &Rho) -> Result<Word8, String> {
    if v > MAX_NOTE_VALUE {
        return Err("note value out of range".into());
    }
    Ok(commit(a_pk, v, rho))
}

pub fn commit(a_pk: &Word8, v: u64, rho: &Rho) -> Word8 {
    assert!(v <= MAX_NOTE_VALUE, "note value out of range");
    let mut b = [0u32; 16];
    b[0] = TAG_CM;
    b[1..9].copy_from_slice(a_pk);
    b[9] = (v >> 32) as u32;
    b[10] = v as u32;
    b[11..16].copy_from_slice(rho);
    compress(&b)
}

pub fn nullifier(sk: &Word8, pos: u32, rho: &Rho) -> Word8 {
    let mut b = [0u32; 16];
    b[0] = TAG_NF;
    b[1..9].copy_from_slice(sk);
    b[9] = pos;
    b[10..15].copy_from_slice(rho);
    compress(&b)
}

/// Roots of empty subtrees: EMPTY[0] is an empty leaf (all zero words).
pub fn empty_roots() -> [Word8; DEPTH + 1] {
    let mut e = [[0u32; 8]; DEPTH + 1];
    for i in 1..=DEPTH {
        e[i] = node(&e[i - 1], &e[i - 1]);
    }
    e
}

/// Append-only note tree of depth 32. Keeps every level so that any leaf's path
/// can be produced; a production node would prune, this one favours being obviously right.
#[derive(Clone, Debug)]
pub struct NoteTree {
    levels: Vec<Vector<Word8>>, // levels[0] = leaves; persistent, so copies share them
    empty: [Word8; DEPTH + 1],
}

impl Default for NoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteTree {
    pub fn new() -> Self {
        Self { levels: vec![Vector::new(); DEPTH + 1], empty: empty_roots() }
    }

    pub fn len(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    fn at(&self, level: usize, i: usize) -> Word8 {
        self.levels[level].get(i).copied().unwrap_or(self.empty[level])
    }

    pub fn append(&mut self, cm: Word8) -> u32 {
        let pos = self.levels[0].len();
        assert!((pos as u64) < (1u64 << DEPTH), "note tree full");
        self.levels[0].push_back(cm);
        let mut i = pos;
        for level in 0..DEPTH {
            let parent = i / 2;
            let left = self.at(level, parent * 2);
            let right = self.at(level, parent * 2 + 1);
            let p = node(&left, &right);
            if self.levels[level + 1].len() <= parent {
                self.levels[level + 1].push_back(p);
            } else {
                self.levels[level + 1][parent] = p;
            }
            i = parent;
        }
        pos as u32
    }

    pub fn root(&self) -> Word8 {
        self.at(DEPTH, 0)
    }

    pub fn leaf(&self, pos: u32) -> Option<Word8> {
        self.levels[0].get(pos as usize).copied()
    }

    /// Read an internal node at `(level, index)` in O(log N) for compact Utreexo frontier extraction.
    pub fn level_node(&self, level: usize, idx: usize) -> Option<Word8> {
        self.levels.get(level)?.get(idx).copied()
    }

    /// Siblings from the leaf upward.
    pub fn path(&self, pos: u32) -> [Word8; DEPTH] {
        let mut out = [[0u32; 8]; DEPTH];
        let mut i = pos as usize;
        for level in 0..DEPTH {
            out[level] = self.at(level, i ^ 1);
            i /= 2;
        }
        out
    }

    pub fn find(&self, cm: &Word8) -> Option<u32> {
        self.levels[0].iter().position(|x| x == cm).map(|p| p as u32)
    }

    /// Snapshot export: every leaf commitment in insertion order.
    pub fn leaves(&self) -> Vec<Word8> {
        self.levels[0].iter().copied().collect()
    }

    /// Fast O(N) bottom-up reconstruction of a `NoteTree` from its leaves.
    pub fn from_leaves(leaves: &[Word8]) -> Self {
        let empty = empty_roots();
        let mut levels = vec![Vector::new(); DEPTH + 1];
        if leaves.is_empty() {
            return Self { levels, empty };
        }
        levels[0] = leaves.iter().copied().collect();
        for level in 0..DEPTH {
            let prev = &levels[level];
            let parents = prev.len().div_ceil(2);
            let mut next = Vector::new();
            for p in 0..parents {
                let left = prev[p * 2];
                let right = prev.get(p * 2 + 1).copied().unwrap_or(empty[level]);
                next.push_back(node(&left, &right));
            }
            levels[level + 1] = next;
        }
        Self { levels, empty }
    }
}

/// Recompute a root from a leaf, its position and its siblings.
pub fn root_from_path(leaf: &Word8, pos: u32, path: &[Word8; DEPTH]) -> Word8 {
    let mut cur = *leaf;
    for (k, sib) in path.iter().enumerate() {
        cur = if (pos >> k) & 1 == 0 { node(&cur, sib) } else { node(sib, &cur) };
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_paths_verify() {
        let mut t = NoteTree::new();
        let mut cms = vec![];
        for i in 0..37u32 {
            let cm = commit(&address(&[i; 8]), i as u64 * 1000, &[i, 1, 2, 3, 4]);
            cms.push(cm);
            t.append(cm);
        }
        let root = t.root();
        for (i, cm) in cms.iter().enumerate() {
            assert_eq!(root_from_path(cm, i as u32, &t.path(i as u32)), root);
        }
        assert_ne!(root_from_path(&cms[3], 4, &t.path(3)), root);
    }
}
