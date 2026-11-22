//! The nullifier tree: every nullifier ever spent, kept sorted in a Merkle tree, so that one
//! path proves a nullifier spent or unspent against a root a block commits to.
//!
//! Each leaf holds a nullifier and the next larger one (zero for none). Leaf 0 holds zero,
//! below every nullifier. A nullifier is spent when a leaf holds it; it is unspent when a
//! leaf holds a smaller one whose next is larger, or none. Adding a nullifier appends one
//! leaf and changes the next of the leaf before it: two paths, which is also what the chain
//! proof will check for each spend (white paper §5). Nodes and light clients use it now:
//! a light client checks that its notes are unspent without trusting the node it asks.
//!
//!   leaf  = C[ nullifier(8), next(8) ]      node = C[ left(8), right(8) ]      (depth 32)

use crate::hash::{node, words_to_bytes, Word8};
use crate::note::{empty_roots, DEPTH};
// persistent, so a copy of the tree shares what it has in common with the original
use imbl::{OrdMap as BTreeMap, Vector};

const ZERO: Word8 = [0; 8];

#[derive(Clone, Debug)]
pub struct NfTree {
    /// (nullifier, next larger) per leaf, in insertion order.
    leaves: Vector<(Word8, Word8)>,
    /// leaf index by nullifier, in order
    index: BTreeMap<[u8; 32], u32>,
    levels: Vec<Vector<Word8>>,
    empty: [Word8; DEPTH + 1],
}

/// What proves a nullifier spent or unspent: a leaf, where it sits, and its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NfProof {
    pub index: u32,
    pub value: Word8,
    pub next: Word8,
    pub path: [Word8; DEPTH],
}

fn key(w: &Word8) -> [u8; 32] {
    words_to_bytes(w)
}

impl Default for NfTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NfTree {
    pub fn new() -> Self {
        let mut t = NfTree { leaves: Vector::new(), index: BTreeMap::new(), levels: vec![Vector::new(); DEPTH + 1], empty: empty_roots() };
        t.leaves.push_back((ZERO, ZERO));
        t.index.insert(key(&ZERO), 0);
        t.set(0, node(&ZERO, &ZERO));
        t
    }

    fn at(&self, level: usize, i: usize) -> Word8 {
        self.levels[level].get(i).copied().unwrap_or(self.empty[level])
    }

    fn set(&mut self, pos: usize, leaf: Word8) {
        let mut i = pos;
        for level in 0..=DEPTH {
            let v = if level == 0 { leaf } else { node(&self.at(level - 1, i * 2), &self.at(level - 1, i * 2 + 1)) };
            let l = &mut self.levels[level];
            while l.len() <= i {
                l.push_back(self.empty[level]);
            }
            l[i] = v;
            if level < DEPTH {
                i /= 2;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, nf: &Word8) -> bool {
        *nf != ZERO && self.index.contains_key(&key(nf))
    }

    /// Add a nullifier. It must be new and not zero.
    pub fn insert(&mut self, nf: Word8) {
        assert!(nf != ZERO && !self.contains(&nf), "a nullifier enters the tree once");
        let (_, &low) = self.index.range(..key(&nf)).next_back().expect("leaf 0 is below everything");
        let at = self.leaves.len() as u32;
        let (lv, lnext) = self.leaves[low as usize];
        self.leaves.push_back((nf, lnext));
        self.leaves[low as usize] = (lv, nf);
        self.index.insert(key(&nf), at);
        self.set(low as usize, node(&lv, &nf));
        self.set(at as usize, node(&nf, &lnext));
    }

    pub fn root(&self) -> Word8 {
        self.at(DEPTH, 0)
    }

    /// The leaf that holds `nf`, or the one below it if it is unspent, with its path.
    pub fn prove(&self, nf: &Word8) -> NfProof {
        let i = match self.index.get(&key(nf)) {
            Some(i) if *nf != ZERO => *i,
            _ => *self.index.range(..key(nf)).next_back().expect("leaf 0 is below everything").1,
        };
        let (value, next) = self.leaves[i as usize];
        let mut path = [[0u32; 8]; DEPTH];
        let mut j = i as usize;
        for (level, p) in path.iter_mut().enumerate() {
            *p = self.at(level, j ^ 1);
            j /= 2;
        }
        NfProof { index: i, value, next, path }
    }
}

/// Check a proof against a root: `Some(true)` if it shows `nf` spent, `Some(false)` if it
/// shows `nf` unspent, `None` if it shows neither.
pub fn check(root: &Word8, nf: &Word8, p: &NfProof) -> Option<bool> {
    if crate::note::root_from_path(&node(&p.value, &p.next), p.index, &p.path) != *root || *nf == ZERO {
        return None;
    }
    if p.value == *nf {
        return Some(true);
    }
    let (v, x, n) = (key(&p.value), key(nf), key(&p.next));
    (v < x && (p.next == ZERO || x < n)).then_some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spent_and_unspent_are_both_provable_and_nothing_else_is() {
        let mut t = NfTree::new();
        let nfs: Vec<Word8> = (0..40).map(|_| rand::random()).collect();
        for nf in &nfs[..30] {
            t.insert(*nf);
        }
        let root = t.root();
        for nf in &nfs[..30] {
            assert_eq!(check(&root, nf, &t.prove(nf)), Some(true));
        }
        for nf in &nfs[30..] {
            assert_eq!(check(&root, nf, &t.prove(nf)), Some(false));
            // another nullifier's proof never shows the wrong answer: at most it shows the
            // right one, when both fall in the same gap
            assert_ne!(check(&root, nf, &t.prove(&nfs[0])), Some(true));
            assert_ne!(check(&root, &nfs[0], &t.prove(nf)), Some(false));
        }
        // a proof is for one root
        let p = t.prove(&nfs[35]);
        t.insert(nfs[35]);
        assert_eq!(check(&t.root(), &nfs[35], &p), None);
        assert_eq!(check(&t.root(), &nfs[35], &t.prove(&nfs[35])), Some(true));
        // leaves sit in the order nullifiers arrived, which every node shares
        let mut u = NfTree::new();
        let mut v = NfTree::new();
        for nf in nfs.iter() {
            u.insert(*nf);
        }
        for nf in nfs.iter().rev() {
            v.insert(*nf);
        }
        assert_eq!(u.len(), 40);
        assert_ne!(u.root(), v.root());
        let mut tampered = t.prove(&nfs[36]);
        tampered.next[0] ^= 1;
        assert_eq!(check(&t.root(), &nfs[36], &tampered), None);
    }
}
