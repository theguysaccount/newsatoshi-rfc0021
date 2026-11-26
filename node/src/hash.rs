//! SHA-256: the one primitive.
//!
//! Two faces of the same function live here:
//!   * `Sha2_256`, a Winterfell hasher, so that every Merkle commitment and every
//!     Fiat–Shamir challenge inside a proof is SHA-256;
//!   * `compress`, the raw SHA-256 compression function on one 64-byte block with the
//!     standard IV, which is what notes, nullifiers and the note tree are built from and
//!     what the spend circuit proves. Zcash's Sprout note tree used the same function
//!     (MerkleCRH = SHA256Compress, protocol spec §5.4.1.3).

use core::marker::PhantomData;
use sha2::{Digest as _, Sha256, Sha384};
use winterfell::crypto::{Digest, ElementHasher, Hasher};
use winterfell::math::{FieldElement, StarkField};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub type Word8 = [u32; 8];

#[inline]
pub fn big_s0(a: u32) -> u32 { a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22) }
#[inline]
pub fn big_s1(e: u32) -> u32 { e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25) }
#[inline]
pub fn small_s0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }
#[inline]
pub fn small_s1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }
#[inline]
pub fn ch(e: u32, f: u32, g: u32) -> u32 { (e & f) ^ (!e & g) }
#[inline]
pub fn maj(a: u32, b: u32, c: u32) -> u32 { (a & b) ^ (a & c) ^ (b & c) }

/// Message schedule extended to 79 words. Rounds use W[0..64]; the circuit keeps
/// computing the same recurrence past 64 so that one constraint holds on every row.
pub fn schedule(block: &[u32; 16]) -> [u32; 79] {
    let mut w = [0u32; 79];
    w[..16].copy_from_slice(block);
    for i in 16..79 {
        w[i] = small_s1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_s0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
    w
}

/// SHA-256 compression of one block under the standard IV (no padding).
pub fn compress(block: &[u32; 16]) -> Word8 {
    let w = schedule(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = IV;
    for t in 0..64 {
        let t1 = h
            .wrapping_add(big_s1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_s0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let s = [a, b, c, d, e, f, g, h];
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = IV[i].wrapping_add(s[i]);
    }
    out
}

/// Interior node of the note tree: SHA256Compress(left || right).
pub fn node(left: &Word8, right: &Word8) -> Word8 {
    let mut b = [0u32; 16];
    b[..8].copy_from_slice(left);
    b[8..].copy_from_slice(right);
    compress(&b)
}

pub fn words_to_bytes(w: &Word8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, x) in w.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

pub fn bytes_to_words(b: &[u8; 32]) -> Word8 {
    let mut w = [0u32; 8];
    for i in 0..8 {
        w[i] = u32::from_be_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
    }
    w
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

// ---------------------------------------------------------------------------------------
// Winterfell hasher
// ---------------------------------------------------------------------------------------

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct ShaDigest(pub [u8; 32]);

impl Digest for ShaDigest {
    fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Serializable for ShaDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for ShaDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ShaDigest(source.read_array()?))
    }
}

/// SHA-256 compressions the proof system's hasher has run, by use: hashing rows into
/// Merkle leaves, merging Merkle nodes, drawing Fiat–Shamir values, and the rest. A
/// verifier written as a circuit (the chain proof) must run exactly these, so counting
/// them while a proof is checked measures what recursion costs (`examples/recursion_cost`).
/// Counting is compiled in only with the `count` feature; without it the hasher is the
/// hash and nothing else.
pub mod count {
    #[cfg(feature = "count")]
    mod on {
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
        pub static COUNTS: [AtomicU64; 4] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
        pub fn add(kind: usize, len: usize) {
            COUNTS[kind].fetch_add(super::blocks(len), Relaxed);
        }
        pub fn reset() {
            COUNTS.iter().for_each(|c| c.store(0, Relaxed));
        }
        pub fn read() -> (u64, u64, u64, u64) {
            (COUNTS[0].load(Relaxed), COUNTS[1].load(Relaxed), COUNTS[2].load(Relaxed), COUNTS[3].load(Relaxed))
        }
    }
    pub const LEAVES: usize = 0;
    pub const MERGES: usize = 1;
    pub const DRAWS: usize = 2;
    pub const OTHER: usize = 3;
    /// Compressions SHA-256 runs on a message of `len` bytes, padding included.
    pub fn blocks(len: usize) -> u64 {
        (len as u64 + 9).div_ceil(64)
    }
    #[cfg(feature = "count")]
    pub use on::{add, read, reset};
    #[cfg(not(feature = "count"))]
    #[inline(always)]
    pub fn add(_kind: usize, _len: usize) {}
}

/// SHA-256 as the hash of a STARK: Merkle commitments, Fiat–Shamir, and grinding.
#[derive(Debug, PartialEq, Eq)]
pub struct Sha2_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha2_256<B> {
    type Digest = ShaDigest;
    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> ShaDigest {
        count::add(count::OTHER, bytes.len());
        ShaDigest(sha256(bytes))
    }

    fn merge(values: &[ShaDigest; 2]) -> ShaDigest {
        count::add(count::MERGES, 64);
        let mut h = Sha256::new();
        h.update(values[0].0);
        h.update(values[1].0);
        ShaDigest(h.finalize().into())
    }

    fn merge_many(values: &[ShaDigest]) -> ShaDigest {
        count::add(count::OTHER, 32 * values.len());
        let mut h = Sha256::new();
        for v in values {
            h.update(v.0);
        }
        ShaDigest(h.finalize().into())
    }

    fn merge_with_int(seed: ShaDigest, value: u64) -> ShaDigest {
        count::add(count::DRAWS, 40);
        let mut h = Sha256::new();
        h.update(seed.0);
        h.update(value.to_le_bytes());
        ShaDigest(h.finalize().into())
    }
}

struct ShaWriter(Sha256);

impl ByteWriter for ShaWriter {
    fn write_u8(&mut self, value: u8) {
        self.0.update([value]);
    }
    fn write_bytes(&mut self, values: &[u8]) {
        self.0.update(values);
    }
}

impl<B: StarkField> ElementHasher for Sha2_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = B>>(elements: &[E]) -> ShaDigest {
        count::add(count::LEAVES, elements.len() * E::ELEMENT_BYTES);
        if B::IS_CANONICAL {
            ShaDigest(sha256(E::elements_as_bytes(elements)))
        } else {
            let mut w = ShaWriter(Sha256::new());
            w.write_many(elements);
            ShaDigest(w.0.finalize().into())
        }
    }
}

// ---------------------------------------------------------------------------------------
// Winterfell SHA-384 hasher (384-bit / 48-byte commitments for >= 128-bit QROM soundness)
// ---------------------------------------------------------------------------------------

pub fn sha384(data: &[u8]) -> [u8; 48] {
    Sha384::digest(data).into()
}

/// 384-bit (48-byte) FIPS 180-4 SHA-384 digest for Mainnet v2 STARK FRI & Merkle trees.
/// Provides 192-bit classical collision resistance and 128-bit QROM post-quantum collision
/// resistance against Brassard–Høyer–Tapp (384 / 3 = 128), staying 100% pure SHA-2.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ShaDigest384(pub [u8; 48]);

impl Default for ShaDigest384 {
    fn default() -> Self {
        ShaDigest384([0u8; 48])
    }
}

impl Digest for ShaDigest384 {
    /// Returns the first 32 bytes for Winterfell's `DefaultRandomCoin` field-element & grinding
    /// draws (256 bits of challenge entropy >= 128-bit Grover); all Merkle commitments, tree
    /// merges, and coin reseeds use the full 48-byte (384-bit) digest via `Serializable`/`merge`.
    fn as_bytes(&self) -> [u8; 32] {
        self.0[..32].try_into().unwrap()
    }
}

impl Serializable for ShaDigest384 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for ShaDigest384 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ShaDigest384(source.read_array()?))
    }
}

/// FIPS 180-4 SHA-384 as the STARK v2 hasher: 384-bit Merkle commitments, Fiat–Shamir & grinding.
#[derive(Debug, PartialEq, Eq)]
pub struct Sha2_384<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha2_384<B> {
    type Digest = ShaDigest384;
    const COLLISION_RESISTANCE: u32 = 192;

    fn hash(bytes: &[u8]) -> ShaDigest384 {
        ShaDigest384(sha384(bytes))
    }

    fn merge(values: &[ShaDigest384; 2]) -> ShaDigest384 {
        let mut h = Sha384::new();
        h.update(values[0].0);
        h.update(values[1].0);
        ShaDigest384(h.finalize().into())
    }

    fn merge_many(values: &[ShaDigest384]) -> ShaDigest384 {
        let mut h = Sha384::new();
        for v in values {
            h.update(v.0);
        }
        ShaDigest384(h.finalize().into())
    }

    fn merge_with_int(seed: ShaDigest384, value: u64) -> ShaDigest384 {
        let mut h = Sha384::new();
        h.update(seed.0);
        h.update(value.to_le_bytes());
        ShaDigest384(h.finalize().into())
    }
}

struct Sha384Writer(Sha384);

impl ByteWriter for Sha384Writer {
    fn write_u8(&mut self, value: u8) {
        self.0.update([value]);
    }
    fn write_bytes(&mut self, values: &[u8]) {
        self.0.update(values);
    }
}

impl<B: StarkField> ElementHasher for Sha2_384<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = B>>(elements: &[E]) -> ShaDigest384 {
        if B::IS_CANONICAL {
            ShaDigest384(sha384(E::elements_as_bytes(elements)))
        } else {
            let mut w = Sha384Writer(Sha384::new());
            w.write_many(elements);
            ShaDigest384(w.0.finalize().into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn compress_matches_sha2_crate() {
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            let block: [u32; 16] = core::array::from_fn(|_| rng.gen());
            let mut bytes = [0u8; 64];
            for i in 0..16 {
                bytes[4 * i..4 * i + 4].copy_from_slice(&block[i].to_be_bytes());
            }
            let mut st = IV;
            sha2::compress256(&mut st, &[*sha2::digest::generic_array::GenericArray::from_slice(&bytes)]);
            assert_eq!(compress(&block), st);
        }
    }

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-2 Appendix B.1: SHA-256("abc")
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // and the compression function reproduces it from the padded block
        let mut block = [0u32; 16];
        block[0] = 0x61626380;
        block[15] = 24;
        assert_eq!(hex::encode(words_to_bytes(&compress(&block))), hex::encode(sha256(b"abc")));
    }
}
