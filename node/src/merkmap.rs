//! Canonical persistent O(log N) SHA-256 Binary Merkle Map (`MerkleMap`).
//!
//! Stores `(key: [u8; 32], value_hash: [u8; 32])` pairs in a compressed binary radix trie
//! where every live key set has a **unique, insertion-order-independent** SHA-256 root:
//! - Empty subtree: `[0u8; 32]`
//! - Single-key subtree (`Leaf`): `SHA256("nsMKL" || key || value_hash)`
//! - Multi-key subtree (`Branch`): `SHA256("nsMKB" || left_hash || right_hash)`
//!
//! Structural sharing via `Arc<TrieNode>` makes `State::clone()` O(1) (single reference count
//! increment), `insert`/`remove` O(log N) (~15–21 SHA-256 hashes for 10K–1M open channels),
//! `root()` O(1) (zero hashing at block finalization), and yields compact inclusion proofs
//! verifiable by light clients against `DigestParts::channels`.

use crate::hash::sha256;
use std::sync::Arc;

pub const EMPTY_HASH: [u8; 32] = [0u8; 32];

#[inline]
fn bit(key: &[u8; 32], depth: usize) -> bool {
    (key[depth >> 3] >> (7 - (depth & 7))) & 1 == 1
}

#[inline]
pub fn leaf_hash(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 5 + 32 + 32];
    buf[..5].copy_from_slice(b"nsMKL");
    buf[5..37].copy_from_slice(key);
    buf[37..69].copy_from_slice(value_hash);
    sha256(&buf)
}

#[inline]
pub fn branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 5 + 32 + 32];
    buf[..5].copy_from_slice(b"nsMKB");
    buf[5..37].copy_from_slice(left);
    buf[37..69].copy_from_slice(right);
    sha256(&buf)
}

#[derive(Debug)]
enum TrieNode {
    Empty,
    Leaf {
        key: [u8; 32],
        value_hash: [u8; 32],
        hash: [u8; 32],
    },
    Branch {
        left: Arc<TrieNode>,
        right: Arc<TrieNode>,
        hash: [u8; 32],
    },
}

impl TrieNode {
    #[inline]
    fn hash(&self) -> [u8; 32] {
        match self {
            TrieNode::Empty => EMPTY_HASH,
            TrieNode::Leaf { hash, .. } | TrieNode::Branch { hash, .. } => *hash,
        }
    }
}

fn empty_node() -> Arc<TrieNode> {
    Arc::new(TrieNode::Empty)
}

fn make_leaf(key: [u8; 32], value_hash: [u8; 32]) -> Arc<TrieNode> {
    let hash = leaf_hash(&key, &value_hash);
    Arc::new(TrieNode::Leaf { key, value_hash, hash })
}

fn make_branch(left: Arc<TrieNode>, right: Arc<TrieNode>) -> Arc<TrieNode> {
    let hash = branch_hash(&left.hash(), &right.hash());
    Arc::new(TrieNode::Branch { left, right, hash })
}

/// Persistent O(log N) SHA-256 Merkle map keyed by 32-byte identifiers.
#[derive(Clone, Debug)]
pub struct MerkleMap {
    root: Arc<TrieNode>,
    len: usize,
}

/// Compact Merkle inclusion proof for `(key, value_hash)` against a `MerkleMap::root()`.
/// `siblings[d]` is the sibling subtree hash at bit depth `d` (`0` = root bit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl Default for MerkleMap {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMap {
    pub fn new() -> Self {
        Self { root: empty_node(), len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// O(1) root lookup (zero hashing).
    pub fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Insert or update `(key, value_hash)` in O(log N) SHA-256 calls.
    pub fn insert(&mut self, key: [u8; 32], value_hash: [u8; 32]) {
        let (new_root, is_new) = insert_node(&self.root, 0, key, value_hash);
        self.root = new_root;
        if is_new {
            self.len += 1;
        }
    }

    /// Remove `key` in O(log N) SHA-256 calls, collapsing single-leaf branches to preserve
    /// canonical uniqueness. Returns `true` if `key` was present.
    pub fn remove(&mut self, key: &[u8; 32]) -> bool {
        let (new_root, removed) = remove_node(&self.root, 0, key);
        if removed {
            self.root = new_root;
            self.len -= 1;
        }
        removed
    }

    /// Look up `value_hash` for `key` in O(log N).
    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        let mut cur = &self.root;
        let mut depth = 0usize;
        loop {
            match cur.as_ref() {
                TrieNode::Empty => return None,
                TrieNode::Leaf { key: k, value_hash, .. } => {
                    return (k == key).then_some(*value_hash);
                }
                TrieNode::Branch { left, right, .. } => {
                    cur = if bit(key, depth) { right } else { left };
                    depth += 1;
                }
            }
        }
    }

    /// Produce a Merkle inclusion proof for `key` if present.
    pub fn prove(&self, key: &[u8; 32]) -> Option<MerkleProof> {
        let mut cur = &self.root;
        let mut depth = 0usize;
        let mut siblings = Vec::new();
        loop {
            match cur.as_ref() {
                TrieNode::Empty => return None,
                TrieNode::Leaf { key: k, value_hash, .. } => {
                    return (k == key).then_some(MerkleProof {
                        key: *k,
                        value_hash: *value_hash,
                        siblings,
                    });
                }
                TrieNode::Branch { left, right, .. } => {
                    if bit(key, depth) {
                        siblings.push(left.hash());
                        cur = right;
                    } else {
                        siblings.push(right.hash());
                        cur = left;
                    }
                    depth += 1;
                }
            }
        }
    }
}

fn split_two(
    depth: usize,
    k1: [u8; 32],
    v1: [u8; 32],
    k2: [u8; 32],
    v2: [u8; 32],
) -> Arc<TrieNode> {
    debug_assert!(depth < 256 && k1 != k2);
    let b1 = bit(&k1, depth);
    let b2 = bit(&k2, depth);
    if b1 == b2 {
        let child = split_two(depth + 1, k1, v1, k2, v2);
        if b1 {
            make_branch(empty_node(), child)
        } else {
            make_branch(child, empty_node())
        }
    } else if b1 {
        make_branch(make_leaf(k2, v2), make_leaf(k1, v1))
    } else {
        make_branch(make_leaf(k1, v1), make_leaf(k2, v2))
    }
}

fn insert_node(
    node: &Arc<TrieNode>,
    depth: usize,
    key: [u8; 32],
    value_hash: [u8; 32],
) -> (Arc<TrieNode>, bool) {
    match node.as_ref() {
        TrieNode::Empty => (make_leaf(key, value_hash), true),
        TrieNode::Leaf { key: ek, value_hash: ev, .. } => {
            if *ek == key {
                (make_leaf(key, value_hash), false)
            } else {
                (split_two(depth, *ek, *ev, key, value_hash), true)
            }
        }
        TrieNode::Branch { left, right, .. } => {
            if bit(&key, depth) {
                let (nr, is_new) = insert_node(right, depth + 1, key, value_hash);
                (make_branch(left.clone(), nr), is_new)
            } else {
                let (nl, is_new) = insert_node(left, depth + 1, key, value_hash);
                (make_branch(nl, right.clone()), is_new)
            }
        }
    }
}

fn collapse_branch(left: Arc<TrieNode>, right: Arc<TrieNode>) -> Arc<TrieNode> {
    match (left.as_ref(), right.as_ref()) {
        (TrieNode::Empty, TrieNode::Empty) => empty_node(),
        (TrieNode::Leaf { .. }, TrieNode::Empty) => left,
        (TrieNode::Empty, TrieNode::Leaf { .. }) => right,
        _ => make_branch(left, right),
    }
}

fn remove_node(node: &Arc<TrieNode>, depth: usize, key: &[u8; 32]) -> (Arc<TrieNode>, bool) {
    match node.as_ref() {
        TrieNode::Empty => (node.clone(), false),
        TrieNode::Leaf { key: ek, .. } => {
            if ek == key {
                (empty_node(), true)
            } else {
                (node.clone(), false)
            }
        }
        TrieNode::Branch { left, right, .. } => {
            if bit(key, depth) {
                let (nr, removed) = remove_node(right, depth + 1, key);
                if !removed {
                    return (node.clone(), false);
                }
                (collapse_branch(left.clone(), nr), true)
            } else {
                let (nl, removed) = remove_node(left, depth + 1, key);
                if !removed {
                    return (node.clone(), false);
                }
                (collapse_branch(nl, right.clone()), true)
            }
        }
    }
}

/// Verify a `MerkleProof` against a committed `root` without holding the map.
pub fn verify_proof(root: &[u8; 32], proof: &MerkleProof) -> bool {
    if *root == EMPTY_HASH || proof.siblings.len() > 256 {
        return false;
    }
    let mut cur = leaf_hash(&proof.key, &proof.value_hash);
    for (depth, sib) in proof.siblings.iter().enumerate().rev() {
        cur = if bit(&proof.key, depth) {
            branch_hash(sib, &cur)
        } else {
            branch_hash(&cur, sib)
        };
    }
    &cur == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn canonical_order_independence_and_deep_prefix_collapse() {
        let mut pairs: Vec<([u8; 32], [u8; 32])> = (0..128u32)
            .map(|i| {
                let k = sha256(&format!("k-{i}").into_bytes());
                let v = sha256(&format!("v-{i}").into_bytes());
                (k, v)
            })
            .collect();
        // Add two adversarial keys differing only at bit 255 (the very last bit!).
        let k_a = [0u8; 32];
        let mut k_b = [0u8; 32];
        k_b[31] = 1;
        pairs.push((k_a, sha256(b"deep-a")));
        pairs.push((k_b, sha256(b"deep-b")));

        let mut fwd = MerkleMap::new();
        for (k, v) in &pairs {
            fwd.insert(*k, *v);
        }
        let mut rev = MerkleMap::new();
        for (k, v) in pairs.iter().rev() {
            rev.insert(*k, *v);
        }
        assert_eq!(fwd.len(), pairs.len());
        assert_eq!(fwd.root(), rev.root(), "root must be 100% insertion-order independent");

        // Verify proofs for every key including the 256-bit deep prefix pair
        let root = fwd.root();
        for (k, v) in &pairs {
            let p = fwd.prove(k).expect("proof");
            assert_eq!(p.value_hash, *v);
            assert!(verify_proof(&root, &p));
            // Tampering value_hash or key must fail
            let mut bad_v = p.clone();
            bad_v.value_hash[0] ^= 1;
            assert!(!verify_proof(&root, &bad_v));
            let mut bad_k = p.clone();
            bad_k.key[0] ^= 0x80;
            assert!(!verify_proof(&root, &bad_k));
        }

        // Remove all keys except k_a: must collapse ALL 256 branch levels down to single leaf!
        let mut collapsed = fwd.clone();
        for (k, _) in &pairs {
            if *k != k_a {
                assert!(collapsed.remove(k));
            }
        }
        let mut single = MerkleMap::new();
        single.insert(k_a, sha256(b"deep-a"));
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed.root(), single.root());
        assert_eq!(collapsed.prove(&k_a).unwrap().siblings.len(), 0);

        assert!(collapsed.remove(&k_a));
        assert!(collapsed.is_empty());
        assert_eq!(collapsed.root(), EMPTY_HASH);
        assert!(!verify_proof(&EMPTY_HASH, &single.prove(&k_a).unwrap()));
    }

    #[test]
    fn bench_10000_channels_ologn_inserts_and_proofs() {
        let mut map = MerkleMap::new();
        let n = 10_000u32;
        let mut keys = Vec::with_capacity(n as usize);
        let t0 = Instant::now();
        for i in 0..n {
            let k = sha256(&i.to_le_bytes());
            let v = sha256(&(i + 1_000_000).to_le_bytes());
            map.insert(k, v);
            keys.push(k);
        }
        let insert_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(map.len(), n as usize);

        let root = map.root();
        let mut total_depth = 0usize;
        let sample = 100usize;
        for k in keys.iter().step_by(n as usize / sample) {
            let p = map.prove(k).unwrap();
            total_depth += p.siblings.len();
            assert!(verify_proof(&root, &p));
        }
        let avg_depth = total_depth as f64 / sample as f64;
        assert!(avg_depth < 20.0, "expected ~14-16 avg depth, got {avg_depth:.2}");

        let t1 = Instant::now();
        for k in keys.iter().take(1_000) {
            assert!(map.remove(k));
        }
        let remove_ms = t1.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(map.len(), 9_000);
        assert_ne!(map.root(), root);

        eprintln!(
            "[MERKLEMAP BENCH] 10,000 inserts = {insert_ms:.2} ms ({:.4} ms/op), 1,000 removes = {remove_ms:.2} ms ({:.4} ms/op), avg proof depth = {avg_depth:.2} siblings",
            insert_ms / n as f64,
            remove_ms / 1_000.0
        );
    }
}
