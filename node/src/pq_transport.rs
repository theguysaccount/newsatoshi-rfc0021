//! Opportunistic Post-Quantum Encrypted P2P Transport (`NSPQ1`: ML-KEM-768 + SHA-256 AEAD).
//!
//! Threat model (honest scope — matches Bitcoin Core BIP-324's opportunistic model, upgraded
//! to post-quantum key exchange):
//! - **What it protects against:** Passive traffic eavesdropping and Harvest-Now-Decrypt-Later
//!   (HNDL) quantum traffic capture, plus in-session frame tampering/replay/reordering via
//!   per-direction Encrypt-then-MAC keys and monotonic 64-bit sequence numbers.
//! - **What it does NOT protect against by itself:** Active man-in-the-middle (MITM) attacks on
//!   unauthenticated peer connections. Because the ML-KEM-768 handshake is ephemeral and peers
//!   are not identity-pinned, preventing active MITM requires out-of-band peer key pinning or
//!   consensus-level validation (which always verifies PoW + STARKs independently of transport).
//! - **Wire & Crypto:** Ephemeral NIST FIPS 203 `ML-KEM-768` (1,184-byte EK, 1,088-byte CT),
//!   bound to network `magic` + both 32-byte nonces (`sha256("NSPQ1-KDF" || ...)`), followed by
//!   SHA-256-CTR + Encrypt-then-MAC keyed SHA-256 with constant-time tag comparison.
//!   Wired live into `node::handle_peer` and `node::submit_with_pq` when `params.pq_transport = true`.

use crate::hash::sha256;
use ::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, B32};
use rand::RngCore;
use std::io::{Read, Write};

pub const HANDSHAKE_MAGIC: &[u8; 5] = b"NSPQ1";
pub const EK_BYTES: usize = 1184;
pub const CT_BYTES: usize = 1088;
pub const TAG_BYTES: usize = 32;
pub const MAX_ENCRYPTED_FRAME_BYTES: usize = 16 << 20;

type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ek = <MlKem768 as KemCore>::EncapsulationKey;

/// Directional post-quantum authenticated stream cipher state.
struct CipherHalf {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    seq: u64,
}

impl CipherHalf {
    fn new(master: &[u8; 32], label_enc: &[u8], label_mac: &[u8]) -> Self {
        let enc_key = sha256(&[label_enc, master].concat());
        let mac_key = sha256(&[label_mac, master].concat());
        Self {
            enc_key,
            mac_key,
            seq: 0,
        }
    }

    fn keystream_xor(&self, seq: u64, data: &mut [u8]) {
        let mut ctr: u64 = 0;
        let mut off = 0usize;
        while off < data.len() {
            let mut blk_in = [0u8; 6 + 32 + 8 + 8];
            blk_in[..6].copy_from_slice(b"NSPQ1S");
            blk_in[6..38].copy_from_slice(&self.enc_key);
            blk_in[38..46].copy_from_slice(&seq.to_le_bytes());
            blk_in[46..54].copy_from_slice(&ctr.to_le_bytes());
            let ks = sha256(&blk_in);
            let n = (data.len() - off).min(32);
            for i in 0..n {
                data[off + i] ^= ks[i];
            }
            off += n;
            ctr += 1;
        }
    }

    fn compute_tag(&self, seq: u64, ciphertext: &[u8]) -> [u8; TAG_BYTES] {
        // Keyed SHA-256 MAC (HMAC-style inner/outer hash) over seq || len || ciphertext
        let mut inner = Vec::with_capacity(6 + 32 + 8 + 8 + ciphertext.len());
        inner.extend_from_slice(b"NSPQ1M");
        inner.extend_from_slice(&self.mac_key);
        inner.extend_from_slice(&seq.to_le_bytes());
        inner.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        inner.extend_from_slice(ciphertext);
        let h1 = sha256(&inner);
        let mut outer = [0u8; 6 + 32 + 32];
        outer[..6].copy_from_slice(b"NSPQ1O");
        outer[6..38].copy_from_slice(&self.mac_key);
        outer[38..70].copy_from_slice(&h1);
        sha256(&outer)
    }

    fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if plaintext.len() > MAX_ENCRYPTED_FRAME_BYTES {
            return Err("encrypted frame exceeds max size".into());
        }
        let seq = self.seq;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or("PQ transport sequence counter exhausted")?;
        let mut ct = plaintext.to_vec();
        self.keystream_xor(seq, &mut ct);
        let tag = self.compute_tag(seq, &ct);
        let mut frame = Vec::with_capacity(4 + ct.len() + TAG_BYTES);
        frame.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        frame.extend_from_slice(&ct);
        frame.extend_from_slice(&tag);
        Ok(frame)
    }

    fn open_frame(&mut self, ct: &[u8], tag: &[u8; TAG_BYTES]) -> Result<Vec<u8>, String> {
        let seq = self.seq;
        let expected = self.compute_tag(seq, ct);
        if !ct_eq(&expected, tag) {
            return Err("NSPQ1 authentication tag mismatch (tampered or out-of-order frame)".into());
        }
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or("PQ transport sequence counter exhausted")?;
        let mut pt = ct.to_vec();
        self.keystream_xor(seq, &mut pt);
        Ok(pt)
    }
}

#[inline]
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn derive_session_master(
    magic: [u8; 4],
    ss: &[u8],
    init_nonce: &[u8; 32],
    resp_nonce: &[u8; 32],
    ek: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(9 + 4 + ss.len() + 64 + ek.len() + ct.len());
    buf.extend_from_slice(b"NSPQ1-KDF");
    buf.extend_from_slice(&magic);
    buf.extend_from_slice(ss);
    buf.extend_from_slice(init_nonce);
    buf.extend_from_slice(resp_nonce);
    buf.extend_from_slice(ek);
    buf.extend_from_slice(ct);
    sha256(&buf)
}

/// Authenticated NIST FIPS 203 ML-KEM-768 encrypted P2P session.
pub struct PqSession {
    send: CipherHalf,
    recv: CipherHalf,
    pub session_id: [u8; 32],
}

impl PqSession {
    fn from_master(master: [u8; 32], is_initiator: bool) -> Self {
        let session_id = sha256(&[b"NSPQ1-SID".as_slice(), &master].concat());
        let i2r = CipherHalf::new(&master, b"NSPQ1-I2R-E", b"NSPQ1-I2R-M");
        let r2i = CipherHalf::new(&master, b"NSPQ1-R2I-E", b"NSPQ1-R2I-M");
        if is_initiator {
            Self {
                send: i2r,
                recv: r2i,
                session_id,
            }
        } else {
            Self {
                send: r2i,
                recv: i2r,
                session_id,
            }
        }
    }

    /// Initiator handshake: generates an ephemeral ML-KEM-768 keypair, sends
    /// `NSPQ1 || magic(4) || init_nonce(32) || ek(1184)`, receives
    /// `NSPQ1 || magic(4) || resp_nonce(32) || ct(1088)`, and decapsulates the shared secret.
    pub fn handshake_initiator<S: Read + Write>(
        stream: &mut S,
        magic: [u8; 4],
    ) -> Result<Self, String> {
        let mut rng = rand::thread_rng();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut init_nonce = [0u8; 32];
        rng.fill_bytes(&mut d);
        rng.fill_bytes(&mut z);
        rng.fill_bytes(&mut init_nonce);

        let (dk, ek): (Dk, Ek) = MlKem768::generate_deterministic(&B32::from(d), &B32::from(z));
        let ek_bytes = ek.as_bytes();
        let mut hello = Vec::with_capacity(5 + 4 + 32 + EK_BYTES);
        hello.extend_from_slice(HANDSHAKE_MAGIC);
        hello.extend_from_slice(&magic);
        hello.extend_from_slice(&init_nonce);
        hello.extend_from_slice(ek_bytes.as_slice());
        stream.write_all(&hello).map_err(|e| format!("PQ init write: {e}"))?;
        stream.flush().map_err(|e| format!("PQ init flush: {e}"))?;

        let mut resp = vec![0u8; 5 + 4 + 32 + CT_BYTES];
        stream
            .read_exact(&mut resp)
            .map_err(|e| format!("PQ resp read: {e}"))?;
        if &resp[0..5] != HANDSHAKE_MAGIC || resp[5..9] != magic {
            return Err("NSPQ1 responder magic mismatch".into());
        }
        let resp_nonce: [u8; 32] = resp[9..41].try_into().unwrap();
        let ct_slice = &resp[41..41 + CT_BYTES];
        let ct = ct_slice
            .try_into()
            .map_err(|_| "bad ML-KEM ciphertext length")?;
        let ss = dk
            .decapsulate(&ct)
            .map_err(|_| "ML-KEM-768 decapsulation failed")?;
        let master = derive_session_master(
            magic,
            ss.as_slice(),
            &init_nonce,
            &resp_nonce,
            ek_bytes.as_slice(),
            ct_slice,
        );
        Ok(Self::from_master(master, true))
    }

    /// Responder handshake: reads initiator's ephemeral ML-KEM-768 encapsulation key, encapsulates
    /// fresh shared randomness, replies with `NSPQ1 || magic(4) || resp_nonce(32) || ct(1088)`.
    pub fn handshake_responder<S: Read + Write>(
        stream: &mut S,
        magic: [u8; 4],
    ) -> Result<Self, String> {
        let mut req = vec![0u8; 5 + 4 + 32 + EK_BYTES];
        stream
            .read_exact(&mut req)
            .map_err(|e| format!("PQ req read: {e}"))?;
        if &req[0..5] != HANDSHAKE_MAGIC || req[5..9] != magic {
            return Err("NSPQ1 initiator magic mismatch".into());
        }
        let init_nonce: [u8; 32] = req[9..41].try_into().unwrap();
        let ek_slice = &req[41..41 + EK_BYTES];
        let ek = Ek::from_bytes(
            ek_slice
                .try_into()
                .map_err(|_| "bad ML-KEM encapsulation key length")?,
        );

        let mut rng = rand::thread_rng();
        let mut m = [0u8; 32];
        let mut resp_nonce = [0u8; 32];
        rng.fill_bytes(&mut m);
        rng.fill_bytes(&mut resp_nonce);

        let (ct, ss) = ek
            .encapsulate_deterministic(&B32::from(m))
            .map_err(|_| "ML-KEM-768 encapsulation failed")?;
        let mut reply = Vec::with_capacity(5 + 4 + 32 + CT_BYTES);
        reply.extend_from_slice(HANDSHAKE_MAGIC);
        reply.extend_from_slice(&magic);
        reply.extend_from_slice(&resp_nonce);
        reply.extend_from_slice(ct.as_slice());
        stream
            .write_all(&reply)
            .map_err(|e| format!("PQ reply write: {e}"))?;
        stream.flush().map_err(|e| format!("PQ reply flush: {e}"))?;

        let master = derive_session_master(
            magic,
            ss.as_slice(),
            &init_nonce,
            &resp_nonce,
            ek_slice,
            ct.as_slice(),
        );
        Ok(Self::from_master(master, false))
    }

    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        self.send.seal_frame(plaintext)
    }

    pub fn write_frame<W: Write>(&mut self, w: &mut W, plaintext: &[u8]) -> Result<(), String> {
        let frame = self.seal_frame(plaintext)?;
        w.write_all(&frame).map_err(|e| format!("PQ write frame: {e}"))
    }

    pub fn read_frame<R: Read>(&mut self, r: &mut R, max_bytes: usize) -> Result<Vec<u8>, String> {
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)
            .map_err(|e| format!("PQ read len: {e}"))?;
        let n = u32::from_le_bytes(len_buf) as usize;
        if n > max_bytes.min(MAX_ENCRYPTED_FRAME_BYTES) {
            return Err("PQ encrypted frame too large".into());
        }
        let mut ct = vec![0u8; n];
        r.read_exact(&mut ct)
            .map_err(|e| format!("PQ read ct: {e}"))?;
        let mut tag = [0u8; TAG_BYTES];
        r.read_exact(&mut tag)
            .map_err(|e| format!("PQ read tag: {e}"))?;
        self.recv.open_frame(&ct, &tag)
    }

    pub fn open_raw_frame(&mut self, raw: &[u8]) -> Result<Vec<u8>, String> {
        if raw.len() < 4 + TAG_BYTES {
            return Err("PQ frame truncated".into());
        }
        let n = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
        if raw.len() != 4 + n + TAG_BYTES {
            return Err("PQ frame length mismatch".into());
        }
        let ct = &raw[4..4 + n];
        let tag: [u8; TAG_BYTES] = raw[4 + n..].try_into().unwrap();
        self.recv.open_frame(ct, &tag)
    }

    /// Split an established `NSPQ1` session into independent send/receive halves so full-duplex
    /// P2P writer and reader threads can encrypt/decrypt concurrently without mutex contention.
    pub fn split(self) -> (PqSender, PqReceiver) {
        (
            PqSender { send: self.send },
            PqReceiver { recv: self.recv },
        )
    }
}

/// Outbound half of an established `NSPQ1` ML-KEM-768 P2P transport session.
pub struct PqSender {
    send: CipherHalf,
}

impl PqSender {
    pub fn write_frame<W: Write>(&mut self, w: &mut W, plaintext: &[u8]) -> Result<(), String> {
        let frame = self.send.seal_frame(plaintext)?;
        w.write_all(&frame).map_err(|e| format!("PQ write frame: {e}"))
    }
}

/// Inbound half of an established `NSPQ1` ML-KEM-768 P2P transport session.
pub struct PqReceiver {
    recv: CipherHalf,
}

impl PqReceiver {
    pub fn read_frame<R: Read>(&mut self, r: &mut R, max_bytes: usize) -> Result<Vec<u8>, String> {
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)
            .map_err(|e| format!("PQ read len: {e}"))?;
        let n = u32::from_le_bytes(len_buf) as usize;
        if n > max_bytes.min(MAX_ENCRYPTED_FRAME_BYTES) {
            return Err("PQ encrypted frame too large".into());
        }
        let mut ct = vec![0u8; n];
        r.read_exact(&mut ct)
            .map_err(|e| format!("PQ read ct: {e}"))?;
        let mut tag = [0u8; TAG_BYTES];
        r.read_exact(&mut tag)
            .map_err(|e| format!("PQ read tag: {e}"))?;
        self.recv.open_frame(&ct, &tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn mlkem768_p2p_handshake_encrypts_and_blocks_tampering_and_replay() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let magic = *b"nsM2";

        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut sess = PqSession::handshake_responder(&mut s, magic).unwrap();
            let msg1 = sess.read_frame(&mut s, 4096).unwrap();
            assert_eq!(msg1, b"shielded-block-header-and-stark-payload");
            sess.write_frame(&mut s, b"ack-compact-block").unwrap();
            sess.session_id
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let mut client = PqSession::handshake_initiator(&mut c, magic).unwrap();
        let raw_frame = client.seal_frame(b"shielded-block-header-and-stark-payload").unwrap();
        // Ciphertext must not contain plaintext substring
        assert!(
            !raw_frame
                .windows(8)
                .any(|w| w == b"shielded"),
            "plaintext leaked in NSPQ1 ciphertext"
        );
        c.write_all(&raw_frame).unwrap();
        let reply = client.read_frame(&mut c, 4096).unwrap();
        assert_eq!(reply, b"ack-compact-block");

        let server_sid = server.join().unwrap();
        assert_eq!(client.session_id, server_sid);

        // Adversarial MITM tamper + replay test on a fresh in-memory pair
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let a2 = l2.local_addr().unwrap();
        let h2 = thread::spawn(move || {
            let (mut s, _) = l2.accept().unwrap();
            PqSession::handshake_responder(&mut s, magic).unwrap()
        });
        let mut c2 = TcpStream::connect(a2).unwrap();
        let mut init = PqSession::handshake_initiator(&mut c2, magic).unwrap();
        let mut resp = h2.join().unwrap();

        let f0 = init.seal_frame(b"msg-0").unwrap();
        let f1 = init.seal_frame(b"msg-1").unwrap();
        // Tampering any ciphertext byte MUST fail MAC verification!
        let mut tampered = f0.clone();
        tampered[5] ^= 1;
        assert!(resp.open_raw_frame(&tampered).is_err());
        // Reordering f1 before f0 MUST fail sequence-bound MAC verification!
        assert!(resp.open_raw_frame(&f1).is_err());
        // Valid ordered delivery succeeds
        assert_eq!(resp.open_raw_frame(&f0).unwrap(), b"msg-0");
        // Replaying f0 MUST fail!
        assert!(resp.open_raw_frame(&f0).is_err());
        assert_eq!(resp.open_raw_frame(&f1).unwrap(), b"msg-1");
    }
}
