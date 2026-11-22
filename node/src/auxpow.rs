//! Merged mining with Bitcoin (white paper §4).
//!
//! A Bitcoin miner commits the hash of a NEWSATOSHI block in its Bitcoin coinbase. If that
//! Bitcoin block's hash also meets the NEWSATOSHI target, the Bitcoin header, its coinbase
//! and the path between them are accepted as the work for the NEWSATOSHI block. No new
//! energy is spent: the same hashes order both chains.
//!
//! The format is Namecoin's AuxPoW, byte for byte, so pool software that already
//! merge-mines Namecoin can merge-mine NEWSATOSHI through the same RPC calls
//! (`createauxblock` / `getauxblock` / `submitauxblock`, see `rpc.rs`).

use crate::hash::sha256d;

/// Header version bit marking a merge-mined block.
pub const VERSION_AUXPOW: u32 = 1 << 8;
/// The chain ID sits in the version's upper 16 bits.
pub const VERSION_CHAIN_START: u32 = 1 << 16;
/// "NS". Distinct from the chain IDs in use (Namecoin 1, Dogecoin 98, Syscoin 16, ...), and
/// above 0x3fff, so no Bitcoin header can carry it: version rolling (BIP 320) only moves
/// bits 13 to 28 under the fixed top bits 001, which keeps Bitcoin's upper half in
/// 0x2000..=0x3fff.
pub const CHAIN_ID: u32 = 0x4e53;
/// Marks the commitment inside the parent coinbase's script.
pub const MERGED_MINING_HEADER: [u8; 4] = [0xfa, 0xbe, b'm', b'm'];
/// A tree of 2^30 merge-mined chains is more than enough.
pub const MAX_CHAIN_BRANCH: usize = 30;
/// A Bitcoin block of 4 MB holds fewer than 2^15 transactions.
pub const MAX_COINBASE_BRANCH: usize = 32;
/// Largest serialized auxpow accepted: room for a coinbase that pays a large pool's members.
pub const MAX_AUXPOW_BYTES: usize = 100_000;

/// The version a merge-mined block carries.
pub fn auxpow_version(base: u32) -> u32 {
    (base & 0xff) | VERSION_AUXPOW | (CHAIN_ID * VERSION_CHAIN_START)
}

pub fn is_auxpow(version: u32) -> bool {
    version & VERSION_AUXPOW != 0
}

pub fn chain_id(version: u32) -> u32 {
    version >> 16
}

/// Namecoin's slot for a chain in the tree of merge-mined chains, fixed by the tree's
/// height, a nonce the miner chose and the chain ID, so that one piece of work can never
/// count twice for the same chain.
pub fn expected_index(nonce: u32, chain_id: u32, h: usize) -> u32 {
    let mut r = nonce;
    r = r.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    r = r.wrapping_add(chain_id);
    r = r.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    r % (1u32 << h)
}

/// Bitcoin's Merkle-branch walk (SHA-256d of the two children, internal byte order).
pub fn merkle_branch(mut hash: [u8; 32], branch: &[[u8; 32]], index: i32) -> [u8; 32] {
    if index == -1 {
        return [0u8; 32];
    }
    let mut i = index;
    for other in branch {
        let mut buf = [0u8; 64];
        if i & 1 != 0 {
            buf[..32].copy_from_slice(other);
            buf[32..].copy_from_slice(&hash);
        } else {
            buf[..32].copy_from_slice(&hash);
            buf[32..].copy_from_slice(other);
        }
        hash = sha256d(&buf);
        i >>= 1;
    }
    hash
}

/// What this module needs from a Bitcoin transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTx {
    /// SHA-256d of the serialization without witness data.
    pub txid: [u8; 32],
    /// The first input's script (the coinbase script, for a coinbase).
    pub script0: Vec<u8>,
    /// Bytes the transaction took.
    pub len: usize,
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.b.len() - self.p < n {
            return Err("auxpow truncated".into());
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn hash(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// Bitcoin's CompactSize. Counts are bounded by the bytes that follow, so a hostile
    /// count fails as a truncation and never as an allocation. As in Bitcoin, a number has
    /// one spelling, the shortest: a merged-mining proof that decodes is written back
    /// byte for byte.
    fn compact(&mut self) -> Result<u64, String> {
        let (n, least) = match self.u8()? {
            0xfd => (u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64, 0xfd),
            0xfe => (self.u32()? as u64, 0x1_0000),
            0xff => (u64::from_le_bytes(self.take(8)?.try_into().unwrap()), 0x1_0000_0000),
            n => (n as u64, 0),
        };
        if n < least {
            return Err("auxpow has a number that is not in its shortest form".into());
        }
        Ok(n)
    }
    fn len_prefixed(&mut self) -> Result<&'a [u8], String> {
        let n = self.compact()?;
        if n > (self.b.len() - self.p) as u64 {
            return Err("auxpow truncated".into());
        }
        self.take(n as usize)
    }
    fn branch(&mut self, max: usize) -> Result<Vec<[u8; 32]>, String> {
        let n = self.compact()?;
        if n > max as u64 {
            return Err("auxpow merkle branch too long".into());
        }
        (0..n).map(|_| self.hash()).collect()
    }
}

/// Parse one Bitcoin transaction at the start of `b`, in either serialization.
pub fn parse_tx(b: &[u8]) -> Result<ParsedTx, String> {
    let mut c = Cur { b, p: 0 };
    let mut stripped = Vec::with_capacity(b.len().min(4096));
    stripped.extend_from_slice(c.take(4)?);
    let segwit = c.b.len() >= c.p + 2 && c.b[c.p] == 0 && c.b[c.p + 1] == 1;
    if segwit {
        c.take(2)?;
    }
    let body = c.p;
    let n_in = c.compact()?;
    if n_in == 0 {
        return Err("auxpow coinbase has no inputs".into());
    }
    let mut script0 = vec![];
    for i in 0..n_in {
        c.take(36)?;
        let s = c.len_prefixed()?;
        if i == 0 {
            script0 = s.to_vec();
        }
        c.take(4)?;
    }
    let n_out = c.compact()?;
    for _ in 0..n_out {
        c.take(8)?;
        c.len_prefixed()?;
    }
    stripped.extend_from_slice(&c.b[body..c.p]);
    if segwit {
        for _ in 0..n_in {
            let items = c.compact()?;
            for _ in 0..items {
                c.len_prefixed()?;
            }
        }
    }
    stripped.extend_from_slice(c.take(4)?);
    Ok(ParsedTx { txid: sha256d(&stripped), script0, len: c.p })
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() || needle.len() > hay.len() - from {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Proof that a Bitcoin block's work commits to a NEWSATOSHI block, in Namecoin's
/// serialization: coinbase, (unused) block hash, coinbase branch and index, chain branch and
/// index, parent header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxPow {
    /// The parent block's coinbase, as Bitcoin serializes it.
    pub coinbase: Vec<u8>,
    /// Carried for compatibility; never used, as in Namecoin.
    pub unused_hash: [u8; 32],
    pub coinbase_branch: Vec<[u8; 32]>,
    pub coinbase_index: i32,
    pub chain_branch: Vec<[u8; 32]>,
    pub chain_index: i32,
    /// The parent (Bitcoin) header.
    pub parent: [u8; 80],
}

impl AuxPow {
    pub fn parse(b: &[u8]) -> Result<AuxPow, String> {
        if b.len() > MAX_AUXPOW_BYTES {
            return Err("auxpow too large".into());
        }
        let tx = parse_tx(b)?;
        let mut c = Cur { b, p: tx.len };
        let unused_hash = c.hash()?;
        let coinbase_branch = c.branch(MAX_COINBASE_BRANCH)?;
        let coinbase_index = c.i32()?;
        let chain_branch = c.branch(MAX_CHAIN_BRANCH)?;
        let chain_index = c.i32()?;
        let parent: [u8; 80] = c.take(80)?.try_into().unwrap();
        if c.p != b.len() {
            return Err("trailing bytes after auxpow".into());
        }
        Ok(AuxPow { coinbase: b[..tx.len].to_vec(), unused_hash, coinbase_branch, coinbase_index, chain_branch, chain_index, parent })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        fn compact(out: &mut Vec<u8>, n: usize) {
            match n {
                0..=0xfc => out.push(n as u8),
                0xfd..=0xffff => {
                    out.push(0xfd);
                    out.extend_from_slice(&(n as u16).to_le_bytes());
                }
                _ => {
                    out.push(0xfe);
                    out.extend_from_slice(&(n as u32).to_le_bytes());
                }
            }
        }
        let mut out = self.coinbase.clone();
        out.extend_from_slice(&self.unused_hash);
        compact(&mut out, self.coinbase_branch.len());
        self.coinbase_branch.iter().for_each(|h| out.extend_from_slice(h));
        out.extend_from_slice(&self.coinbase_index.to_le_bytes());
        compact(&mut out, self.chain_branch.len());
        self.chain_branch.iter().for_each(|h| out.extend_from_slice(h));
        out.extend_from_slice(&self.chain_index.to_le_bytes());
        out.extend_from_slice(&self.parent);
        out
    }

    /// The hash that has to meet the NEWSATOSHI target.
    pub fn parent_hash(&self) -> [u8; 32] {
        sha256d(&self.parent)
    }

    pub fn parent_version(&self) -> u32 {
        u32::from_le_bytes(self.parent[0..4].try_into().unwrap())
    }

    /// Does this auxpow commit to the block `aux_hash` of the chain `chain_id`? Namecoin's
    /// rules, in Namecoin's order. The work itself is checked by the caller.
    pub fn check(&self, aux_hash: &[u8; 32], chain_id_: u32) -> Result<(), String> {
        if self.coinbase_index != 0 {
            return Err("auxpow is not a generate: the coinbase must be the parent's first transaction".into());
        }
        if chain_id(self.parent_version()) == chain_id_ {
            return Err("auxpow parent has our chain ID".into());
        }
        if self.chain_branch.len() > MAX_CHAIN_BRANCH {
            return Err("auxpow chain merkle branch too long".into());
        }
        let mut root = merkle_branch(*aux_hash, &self.chain_branch, self.chain_index);
        root.reverse();
        let tx = parse_tx(&self.coinbase)?;
        let parent_root: [u8; 32] = self.parent[36..68].try_into().unwrap();
        if merkle_branch(tx.txid, &self.coinbase_branch, 0) != parent_root {
            return Err("auxpow merkle root incorrect".into());
        }
        let script = &tx.script0;
        let head = find(script, &MERGED_MINING_HEADER, 0);
        let pc = find(script, &root, 0).ok_or("auxpow missing chain merkle root in parent coinbase")?;
        match head {
            Some(h) => {
                if find(script, &MERGED_MINING_HEADER, h + 1).is_some() {
                    return Err("multiple merged mining headers in coinbase".into());
                }
                if h + MERGED_MINING_HEADER.len() != pc {
                    return Err("merged mining header is not just before chain merkle root".into());
                }
            }
            None => {
                if pc > 20 {
                    return Err("auxpow chain merkle root must start in the first 20 bytes of the parent coinbase".into());
                }
            }
        }
        let rest = &script[pc + 32..];
        if rest.len() < 8 {
            return Err("auxpow missing chain merkle tree size and nonce in parent coinbase".into());
        }
        let size = u32::from_le_bytes(rest[0..4].try_into().unwrap());
        let h = self.chain_branch.len();
        if size != 1u32 << h {
            return Err("auxpow merkle branch size does not match parent coinbase".into());
        }
        let nonce = u32::from_le_bytes(rest[4..8].try_into().unwrap());
        if self.chain_index < 0 || self.chain_index as u32 != expected_index(nonce, chain_id_, h) {
            return Err("auxpow wrong index".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_index_matches_namecoin() {
        // a single chain always sits in slot 0
        assert_eq!(expected_index(0, 1, 0), 0);
        assert_eq!(expected_index(12345, CHAIN_ID, 0), 0);
        // the LCG step, computed by hand for nonce 0, chain 1, height 3
        let r = 12_345u32.wrapping_add(1).wrapping_mul(1_103_515_245).wrapping_add(12_345);
        assert_eq!(expected_index(0, 1, 3), r % 8);
    }

    #[test]
    fn chain_id_is_outside_bitcoin_version_range() {
        for v in [0x2000_0000u32, 0x3fff_e000, 0x2fff_ffff] {
            assert_ne!(chain_id(v), CHAIN_ID);
        }
        assert_eq!(chain_id(auxpow_version(1)), CHAIN_ID);
        assert!(is_auxpow(auxpow_version(1)));
    }
}
