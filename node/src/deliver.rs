//! Delivering notes on chain, so a payee need not be told out of band (specification §6.4).
//!
//! A wallet's delivery key is an ML-KEM-768 key pair (FIPS 203) derived from its secret key,
//! so restoring the key restores delivery. A delivery address is the ordinary address with
//! the encapsulation key appended. To deliver a payment's note, the payer encapsulates a
//! fresh shared secret to that key and encrypts the note's value and ρ under it with
//! SHA-256, bound to the note's commitment; the envelope rides in the payment's memo,
//! which the payment's proof already binds, so it cannot be stripped or altered in transit.
//! A wallet finds its notes by trying each envelope; one that opens and reproduces the
//! commitment is its own.
//!
//! A payer's notes to itself, its change, need no public key: they are sealed with a key
//! only the payer's secret derives, in 44 bytes and with SHA-256 alone. A payment to
//! someone without a delivery key is sealed to the payer's own delivery key instead, so
//! every payment a wallet makes has the same shape: one envelope and one box.
//!
//! What this adds and what it does not: a break of ML-KEM would reveal who paid whom (the
//! envelope's contents). It could never move a coin: spending still needs the payee's
//! secret key, proven inside a hash-based proof, and the envelope never touches it.

use crate::hash::{bytes_to_words, sha256, words_to_bytes, Word8};
use crate::note::{self, Rho};
use crate::spend::OutputNote;
use ::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, B32};

type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ek = <MlKem768 as KemCore>::EncapsulationKey;

pub const EK_BYTES: usize = 1184;
/// ML-KEM-768 decapsulation key byte length (FIPS 203).
pub const DK_BYTES: usize = 2400;
const CT_BYTES: usize = 1088;
const BOX_BYTES: usize = 28;
const TAG_BYTES: usize = 16;
/// One envelope: the KEM ciphertext, the encrypted value and ρ, and a tag.
pub const ENVELOPE_BYTES: usize = CT_BYTES + BOX_BYTES + TAG_BYTES;
/// A note sealed by the payer to itself: the encrypted value and ρ, and a tag.
pub const OWN_BOX_BYTES: usize = BOX_BYTES + TAG_BYTES;
const MEMO_MAGIC: &[u8; 4] = b"nsE1";
/// Text a memo may carry beside its envelopes.
pub const MEMO_TEXT_BYTES: usize = 512;
/// Largest memo: the magic, the kinds, an envelope for each output, and the text.
pub const MAX_MEMO_BYTES: usize = 5 + 2 * ENVELOPE_BYTES + MEMO_TEXT_BYTES;

/// The delivery key pair that belongs to a wallet's secret key.
fn keys(sk: &Word8) -> (Dk, Ek) {
    let sk = words_to_bytes(sk);
    let d = sha256(&[b"nsKD".as_slice(), &sk].concat());
    let z = sha256(&[b"nsKZ".as_slice(), &sk].concat());
    MlKem768::generate_deterministic(&B32::from(d), &B32::from(z))
}

/// The encapsulation key a payer needs to deliver to this wallet.
pub fn encapsulation_key(sk: &Word8) -> Vec<u8> {
    keys(sk).1.as_bytes().to_vec()
}

/// `nsd1`: the address and the encapsulation key, in hex, with a four-byte checksum.
pub fn encode_delivery_address(a_pk: &Word8, ek: &[u8]) -> String {
    let mut b = words_to_bytes(a_pk).to_vec();
    b.extend_from_slice(ek);
    format!("nsd1{}{}", hex::encode(&b), hex::encode(&sha256(&b)[..4]))
}

pub fn delivery_address(sk: &Word8) -> String {
    encode_delivery_address(&note::address(sk), &encapsulation_key(sk))
}

pub fn parse_delivery_address(s: &str) -> Result<(Word8, Vec<u8>), String> {
    let h = s.trim().strip_prefix("nsd1").ok_or("a delivery address starts with nsd1")?;
    if h.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err("a delivery address is in lower case".into());
    }
    let b = hex::decode(h).map_err(|_| "a delivery address is hex after nsd1")?;
    if b.len() != 32 + EK_BYTES + 4 {
        return Err("a delivery address has the wrong length".into());
    }
    let (body, check) = b.split_at(32 + EK_BYTES);
    if &sha256(body)[..4] != check {
        return Err("a delivery address with a typo (checksum)".into());
    }
    Ok((bytes_to_words(&body[..32].try_into().unwrap()), body[32..].to_vec()))
}

fn box_keys(ss: &[u8], cm: &Word8) -> ([u8; 32], [u8; 32]) {
    let k = sha256(&[b"nsDK".as_slice(), ss, &words_to_bytes(cm)].concat());
    let stream = sha256(&[b"nsDS".as_slice(), &k].concat());
    (k, stream)
}

fn tag(k: &[u8; 32], sealed: &[u8]) -> [u8; TAG_BYTES] {
    sha256(&[b"nsDT".as_slice(), k, sealed].concat())[..TAG_BYTES].try_into().unwrap()
}

fn plain(v: u64, rho: &Rho) -> [u8; BOX_BYTES] {
    let mut p = [0u8; BOX_BYTES];
    p[..8].copy_from_slice(&v.to_le_bytes());
    for (i, w) in rho.iter().enumerate() {
        p[8 + 4 * i..12 + 4 * i].copy_from_slice(&w.to_be_bytes());
    }
    p
}

/// Seal the note (`cm`, `v`, `ρ`) to an encapsulation key. `m` is fresh randomness.
pub fn seal(ek: &[u8], cm: &Word8, v: u64, rho: &Rho, m: [u8; 32]) -> Result<Vec<u8>, String> {
    if ek.len() != EK_BYTES {
        return Err("bad encapsulation key".into());
    }
    let ek = Ek::from_bytes(ek.try_into().map_err(|_| "bad encapsulation key")?);
    let (ct, ss) = ek.encapsulate_deterministic(&B32::from(m)).map_err(|_| "encapsulation failed")?;
    let (k, stream) = box_keys(&ss, cm);
    let mut sealed: Vec<u8> = plain(v, rho).iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    let t = tag(&k, &sealed);
    let mut out = ct.to_vec();
    out.append(&mut sealed);
    out.extend_from_slice(&t);
    Ok(out)
}

/// The key a wallet seals its own notes with.
fn own_key(sk: &Word8) -> [u8; 32] {
    sha256(&[b"nsOK".as_slice(), &words_to_bytes(sk)].concat())
}

/// Seal the note (`cm`, `v`, `ρ`) to the payer itself. Each commitment is new, so each box
/// has its own key.
pub fn seal_own(sk: &Word8, cm: &Word8, v: u64, rho: &Rho) -> Vec<u8> {
    let (k, stream) = box_keys(&own_key(sk), cm);
    let mut out: Vec<u8> = plain(v, rho).iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    let t = tag(&k, &out);
    out.extend_from_slice(&t);
    out
}

fn unseal(k: &[u8; 32], stream: &[u8; 32], sealed: &[u8], t: &[u8], a_pk: &Word8, cm: &Word8) -> Option<(u64, Rho)> {
    if tag(k, sealed) != t {
        return None;
    }
    let p: Vec<u8> = sealed.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    let v = u64::from_le_bytes(p[..8].try_into().unwrap());
    let rho: Rho = core::array::from_fn(|i| u32::from_be_bytes(p[8 + 4 * i..12 + 4 * i].try_into().unwrap()));
    (note::commit(a_pk, v, &rho) == *cm).then_some((v, rho))
}

/// Try to open an envelope or a box with this wallet's key. Returns the note's value and ρ
/// only if it opens and the note it holds is the commitment `cm` at this wallet's address.
pub fn open(sk: &Word8, cm: &Word8, env: &[u8]) -> Option<(u64, Rho)> {
    Scanner::new(sk).open(cm, env)
}

/// A read-only selective-audit viewing key (`nsvk1…`).
///
/// Allows a third-party auditor, regulator, treasury accountant, or watch-only AI service to
/// decrypt every incoming `nsd1…` delivery envelope and change box for this wallet and verify
/// exact on-chain commitments (`note::commit(a_pk, v, rho) == cm`), WITHOUT ever possessing
/// `sk` or being able to derive nullifiers, sign SLH-DSA authorizations, or spend any coin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewingKey {
    pub a_pk: Word8,
    pub own: [u8; 32],
    pub dk: Vec<u8>,
}

/// Export a wallet's read-only selective-audit viewing key (`nsvk1…`).
pub fn viewing_key(sk: &Word8) -> String {
    let (dk, _) = keys(sk);
    let a_pk = note::address(sk);
    let own = own_key(sk);
    let mut body = Vec::with_capacity(32 + 32 + DK_BYTES);
    body.extend_from_slice(&words_to_bytes(&a_pk));
    body.extend_from_slice(&own);
    body.extend_from_slice(dk.as_bytes().as_slice());
    format!("nsvk1{}{}", hex::encode(&body), hex::encode(&sha256(&body)[..4]))
}

/// Parse and checksum-verify a read-only viewing key (`nsvk1…`).
pub fn parse_viewing_key(s: &str) -> Result<ViewingKey, String> {
    let h = s.trim().strip_prefix("nsvk1").ok_or("a viewing key starts with nsvk1")?;
    if h.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err("a viewing key is in lower case".into());
    }
    let b = hex::decode(h).map_err(|_| "a viewing key is hex after nsvk1")?;
    if b.len() != 32 + 32 + DK_BYTES + 4 {
        return Err("a viewing key has the wrong length".into());
    }
    let (body, check) = b.split_at(32 + 32 + DK_BYTES);
    if &sha256(body)[..4] != check {
        return Err("a viewing key with a typo (checksum)".into());
    }
    let a_pk = bytes_to_words(&body[..32].try_into().unwrap());
    let own: [u8; 32] = body[32..64].try_into().unwrap();
    let dk = body[64..].to_vec();
    Ok(ViewingKey { a_pk, own, dk })
}

/// A wallet's scanner: its keys, derived once.
pub struct Scanner {
    dk: Dk,
    own: [u8; 32],
    a_pk: Word8,
}

impl Scanner {
    pub fn new(sk: &Word8) -> Scanner {
        Scanner { dk: keys(sk).0, own: own_key(sk), a_pk: note::address(sk) }
    }

    /// Construct a watch-only scanner from a `ViewingKey` (`nsvk1…`) with zero spend capability.
    pub fn from_viewing_key(vk: &ViewingKey) -> Result<Scanner, String> {
        if vk.dk.len() != DK_BYTES {
            return Err("bad viewing key decapsulation length".into());
        }
        let arr: &[u8; DK_BYTES] = vk.dk.as_slice().try_into().map_err(|_| "bad viewing key")?;
        let dk = Dk::from_bytes(arr.into());
        Ok(Scanner { dk, own: vk.own, a_pk: vk.a_pk })
    }

    /// The public payment address (`a_pk`) bound to this scanner.
    pub fn address(&self) -> Word8 {
        self.a_pk
    }

    /// Open an envelope (sealed to this wallet's delivery key) or a box (sealed by this
    /// wallet to itself); which one it is follows from its length.
    pub fn open(&self, cm: &Word8, env: &[u8]) -> Option<(u64, Rho)> {
        match env.len() {
            ENVELOPE_BYTES => {
                let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&env[..CT_BYTES]).ok()?;
                // ML-KEM rejects implicitly: a wrong key yields a pseudorandom secret, and the tag fails
                let ss = self.dk.decapsulate(&ct).ok()?;
                let (k, stream) = box_keys(&ss, cm);
                unseal(&k, &stream, &env[CT_BYTES..CT_BYTES + BOX_BYTES], &env[CT_BYTES + BOX_BYTES..], &self.a_pk, cm)
            }
            OWN_BOX_BYTES => {
                let (k, stream) = box_keys(&self.own, cm);
                unseal(&k, &stream, &env[..BOX_BYTES], &env[BOX_BYTES..], &self.a_pk, cm)
            }
            _ => None,
        }
    }
}

/// An address of either kind: `ns1…`, or a delivery address `nsd1…` with its key.
pub fn parse_any_address(s: &str) -> Result<(Word8, Option<Vec<u8>>), String> {
    let s = s.trim();
    if s.starts_with("nsd1") {
        let (a_pk, ek) = parse_delivery_address(s)?;
        Ok((a_pk, Some(ek)))
    } else {
        Ok((crate::wallet::parse_address(s)?, None))
    }
}

/// A spend's memo as wallets write it: a sealed note for each output, then the text. A note
/// to the payer's own address is sealed to the payer alone (a box); any other is sealed to
/// the delivery key beside it or, without one, to the payer's own delivery key (an
/// envelope). So every payment looks alike, a payee with a delivery address finds the
/// payment by itself, and the payer's key alone finds its change again.
pub fn memo_for(sk: &Word8, outs: &[OutputNote; 2], keys: [Option<&[u8]>; 2], text: &[u8]) -> Result<Vec<u8>, String> {
    use rand::Rng;
    let me = note::address(sk);
    let mut own_ek = None;
    let mut rng = rand::thread_rng();
    let mut env: [Option<Vec<u8>>; 2] = [None, None];
    for (i, o) in outs.iter().enumerate() {
        let cm = note::commit(&o.a_pk, o.v, &o.rho);
        env[i] = Some(if o.a_pk == me {
            seal_own(sk, &cm, o.v, &o.rho)
        } else {
            let ek = match keys[i] {
                Some(k) => k.to_vec(),
                None => own_ek.get_or_insert_with(|| encapsulation_key(sk)).clone(),
            };
            seal(&ek, &cm, o.v, &o.rho, rng.gen())?
        });
    }
    pack_memo(env, text)
}

fn kind_of(len: usize) -> Option<u8> {
    match len {
        ENVELOPE_BYTES => Some(1),
        OWN_BOX_BYTES => Some(2),
        _ => None,
    }
}

/// A memo that carries sealed notes: the magic, a byte giving each output's kind in two bits
/// (0 none, 1 an envelope, 2 a box), the sealed notes in output order, then any text.
pub fn pack_memo(env: [Option<Vec<u8>>; 2], text: &[u8]) -> Result<Vec<u8>, String> {
    if text.len() > MEMO_TEXT_BYTES {
        return Err("memo text too long".into());
    }
    if env.iter().all(|e| e.is_none()) {
        return Ok(text.to_vec());
    }
    let mut m = MEMO_MAGIC.to_vec();
    let mut kinds = 0u8;
    for (i, e) in env.iter().enumerate() {
        if let Some(e) = e {
            kinds |= kind_of(e.len()).ok_or("bad envelope")? << (2 * i);
        }
    }
    m.push(kinds);
    for e in env.iter().flatten() {
        m.extend_from_slice(e);
    }
    m.extend_from_slice(text);
    Ok(m)
}

/// The sealed notes and the text in a memo; a memo without the magic is all text.
pub fn unpack_memo(memo: &[u8]) -> ([Option<&[u8]>; 2], &[u8]) {
    if memo.len() < 5 || &memo[..4] != MEMO_MAGIC || memo[4] >> 4 != 0 {
        return ([None, None], memo);
    }
    let mut out = [None, None];
    let mut at = 5;
    for (i, slot) in out.iter_mut().enumerate() {
        let len = match memo[4] >> (2 * i) & 3 {
            0 => continue,
            1 => ENVELOPE_BYTES,
            2 => OWN_BOX_BYTES,
            _ => return ([None, None], memo),
        };
        if memo.len() < at + len {
            return ([None, None], memo);
        }
        *slot = Some(&memo[at..at + len]);
        at += len;
    }
    (out, &memo[at..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_note_opens_only_for_its_payee() {
        let alice: Word8 = rand::random();
        let bob: Word8 = rand::random();
        let addr = delivery_address(&alice);
        assert_eq!(addr.len(), 4 + 2 * (32 + EK_BYTES + 4));
        let (a_pk, ek) = parse_delivery_address(&addr).unwrap();
        assert_eq!(a_pk, note::address(&alice));
        assert_eq!(delivery_address(&alice), addr, "the same key, the same delivery address");
        let rho: Rho = rand::random();
        let cm = note::commit(&a_pk, 2_500, &rho);
        let env = seal(&ek, &cm, 2_500, &rho, rand::random()).unwrap();
        assert_eq!(env.len(), ENVELOPE_BYTES);
        assert_eq!(open(&alice, &cm, &env), Some((2_500, rho)));
        assert_eq!(open(&bob, &cm, &env), None, "someone else's key");
        let other = note::commit(&a_pk, 2_501, &rho);
        assert_eq!(open(&alice, &other, &env), None, "bound to its commitment");
        let mut bad = env.clone();
        bad[CT_BYTES + 3] ^= 1;
        assert_eq!(open(&alice, &cm, &bad), None, "tampered");
        let mut typo = addr.clone().into_bytes();
        typo[40] = if typo[40] == b'0' { b'1' } else { b'0' };
        assert!(parse_delivery_address(std::str::from_utf8(&typo).unwrap()).is_err());
    }

    #[test]
    fn a_box_opens_only_for_the_payer_that_sealed_it() {
        let (alice, bob): (Word8, Word8) = (rand::random(), rand::random());
        let rho: Rho = rand::random();
        let cm = note::commit(&note::address(&alice), 7, &rho);
        let b = seal_own(&alice, &cm, 7, &rho);
        assert_eq!(b.len(), OWN_BOX_BYTES);
        assert_eq!(open(&alice, &cm, &b), Some((7, rho)));
        assert_eq!(open(&bob, &cm, &b), None);
        assert_eq!(open(&alice, &note::commit(&note::address(&alice), 8, &rho), &b), None, "bound to its commitment");
    }

    #[test]
    fn memos_carry_envelopes_and_text() {
        let e = vec![7u8; ENVELOPE_BYTES];
        let o = vec![9u8; OWN_BOX_BYTES];
        let m = pack_memo([Some(e.clone()), Some(o.clone())], b"thanks").unwrap();
        assert_eq!(m.len(), 5 + ENVELOPE_BYTES + OWN_BOX_BYTES + 6);
        let (env, text) = unpack_memo(&m);
        assert_eq!((env[0], env[1], text), (Some(e.as_slice()), Some(o.as_slice()), b"thanks".as_slice()));
        let m = pack_memo([None, Some(e.clone())], b"thanks").unwrap();
        let (env, text) = unpack_memo(&m);
        assert_eq!((env[0], env[1], text), (None, Some(e.as_slice()), b"thanks".as_slice()));
        assert!(pack_memo([Some(vec![1u8; 10]), None], b"").is_err(), "only the two sizes");
        assert_eq!(pack_memo([None, None], b"plain").unwrap(), b"plain");
        assert_eq!(unpack_memo(b"plain"), ([None, None], b"plain".as_slice()));
        let full = pack_memo([Some(e.clone()), Some(e)], &[1u8; MEMO_TEXT_BYTES]).unwrap();
        assert_eq!(full.len(), MAX_MEMO_BYTES);
    }

    #[test]
    fn viewing_key_enables_read_only_selective_audit_without_sk() {
        let alice: Word8 = rand::random();
        let bob: Word8 = rand::random();
        let vk_str = viewing_key(&alice);
        assert!(vk_str.starts_with("nsvk1"));
        let vk = parse_viewing_key(&vk_str).unwrap();
        assert_eq!(vk.a_pk, note::address(&alice));
        let auditor = Scanner::from_viewing_key(&vk).unwrap();
        assert_eq!(auditor.address(), note::address(&alice));

        // Incoming payment sealed to Alice's delivery address
        let (a_pk, ek) = parse_delivery_address(&delivery_address(&alice)).unwrap();
        let rho_in: Rho = rand::random();
        let cm_in = note::commit(&a_pk, 75_000_000, &rho_in);
        let env_in = seal(&ek, &cm_in, 75_000_000, &rho_in, rand::random()).unwrap();
        assert_eq!(auditor.open(&cm_in, &env_in), Some((75_000_000, rho_in)));

        // Change box sealed by Alice to herself
        let rho_ch: Rho = rand::random();
        let cm_ch = note::commit(&a_pk, 12_500_000, &rho_ch);
        let box_ch = seal_own(&alice, &cm_ch, 12_500_000, &rho_ch);
        assert_eq!(auditor.open(&cm_ch, &box_ch), Some((12_500_000, rho_ch)));

        // Auditor cannot open Bob's notes, and corrupted checksum is rejected
        let (b_pk, b_ek) = parse_delivery_address(&delivery_address(&bob)).unwrap();
        let cm_bob = note::commit(&b_pk, 99, &rho_in);
        let env_bob = seal(&b_ek, &cm_bob, 99, &rho_in, rand::random()).unwrap();
        assert_eq!(auditor.open(&cm_bob, &env_bob), None);

        let mut bad = vk_str.into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'0' { b'1' } else { b'0' };
        assert!(parse_viewing_key(std::str::from_utf8(&bad).unwrap()).is_err());
    }
}
