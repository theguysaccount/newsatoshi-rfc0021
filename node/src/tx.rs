//! Transactions and blocks.

use crate::auxpow::{self, AuxPow};
use crate::batch_spend::{BatchSpendPublic, MAX_BATCH_PROOF_BYTES, MAX_BATCH_SPENDS, MIN_BATCH_SPENDS};
use crate::codec::{Reader, Res, Writer};
use crate::hash::{bytes_to_words, sha256, sha256d, Word8};
use crate::job::{Action, Deposit};
use crate::note::{self, Rho};
use crate::params::{MAX_MEMO, TX_BYTES_CAP};
use crate::spend::SpendPublic;

/// An output whose opening is public: coinbase rewards. Spending it later is private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainOut {
    pub a_pk: Word8,
    pub v: u64,
    pub rho: Rho,
}

impl PlainOut {
    pub fn cm(&self) -> Word8 {
        note::commit(&self.a_pk, self.v, &self.rho)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    pub height: u32,
    pub outs: Vec<PlainOut>,
    pub extra: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub anchor: Word8,
    pub nf: [Word8; 2],
    pub cm_out: [Word8; 2],
    pub dummy: [bool; 2],
    pub fee: u64,
    pub deposit: Option<Deposit>,
    pub memo: Vec<u8>,
    pub proof: Vec<u8>,
}

impl Spend {
    /// Hash of everything the proof does not already expose, bound into Fiat–Shamir.
    pub fn bind(&self) -> Word8 {
        bind_of(self.fee, &self.deposit, &self.memo)
    }

    pub fn value_balance(&self) -> Res<i64> {
        let d = match &self.deposit {
            Some(dep) => dep.checked_amount()?,
            None => 0,
        };
        let total = self.fee.checked_add(d).ok_or("value overflow")?;
        i64::try_from(total).map_err(|_| "value overflow".into())
    }

    pub fn public(&self) -> Res<SpendPublic> {
        Ok(SpendPublic {
            root: self.anchor,
            nf: self.nf,
            cm_out: self.cm_out,
            value_balance: self.value_balance()?,
            dummy: self.dummy,
            bind: self.bind(),
        })
    }
}

pub fn bind_of(fee: u64, deposit: &Option<Deposit>, memo: &[u8]) -> Word8 {
    let mut w = Writer::new();
    w.raw(b"nsBIND").u64(fee);
    match deposit {
        None => {
            w.u8(0);
        }
        Some(d) => d.encode(&mut w),
    }
    w.bytes(memo);
    bytes_to_words(&sha256(&w.0))
}

/// One shielded 2-in/2-out sub-spend inside a compressed `BatchSpend` STARK transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSpendItem {
    pub anchor: Word8,
    pub nf: [Word8; 2],
    pub cm_out: [Word8; 2],
    pub dummy: [bool; 2],
    pub fee: u64,
    pub deposit: Option<Deposit>,
    pub memo: Vec<u8>,
}

impl BatchSpendItem {
    pub fn bind(&self) -> Word8 {
        bind_of(self.fee, &self.deposit, &self.memo)
    }

    pub fn value_balance(&self) -> Res<i64> {
        let d = match &self.deposit {
            Some(dep) => dep.checked_amount()?,
            None => 0,
        };
        let total = self.fee.checked_add(d).ok_or("value overflow")?;
        i64::try_from(total).map_err(|_| "value overflow".into())
    }

    pub fn public(&self) -> Res<SpendPublic> {
        Ok(SpendPublic {
            root: self.anchor,
            nf: self.nf,
            cm_out: self.cm_out,
            value_balance: self.value_balance()?,
            dummy: self.dummy,
            bind: self.bind(),
        })
    }
}

/// Multi-spend compressed shielded transaction: `K ∈ 2..=16` spends proved in ONE pure-SHA-2
/// Winterfell STARK. Out of the unburned sub-spend fees, an explicit STARK-bound `prover_fee`
/// is paid in the block coinbase to `prover_a_pk`, while the AuxPoW miner keeps 100% of block
/// subsidy plus all remaining `miner_fee` (strictly incentive-compatible; zero censorship!).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSpend {
    pub spends: Vec<BatchSpendItem>,
    pub prover_a_pk: Word8,
    pub prover_fee: u64,
    pub proof: Vec<u8>,
}

impl BatchSpend {
    pub fn public(&self) -> Res<BatchSpendPublic> {
        let mut spends = Vec::with_capacity(self.spends.len());
        for item in &self.spends {
            spends.push(item.public()?);
        }
        Ok(BatchSpendPublic {
            spends,
            prover_a_pk: self.prover_a_pk,
            prover_fee: self.prover_fee,
        })
    }

    pub fn total_fee(&self) -> Res<u64> {
        let mut sum: u64 = 0;
        for item in &self.spends {
            sum = sum.checked_add(item.fee).ok_or("batch fee overflow")?;
        }
        Ok(sum)
    }

    /// Exact `(burned_fee, prover_fee, miner_fee)` conservation split across all sub-spends.
    pub fn fee_split(&self, burn_active: bool) -> Res<(u64, u64, u64)> {
        let mut burned: u64 = 0;
        let mut net: u64 = 0;
        for item in &self.spends {
            let (b, p) = crate::params::split_spend_fee(item.fee, burn_active);
            burned = burned.checked_add(b).ok_or("batch burn overflow")?;
            net = net.checked_add(p).ok_or("batch net fee overflow")?;
        }
        if self.prover_fee > net {
            return Err(format!(
                "batch prover_fee {} exceeds unburned net fee {net}",
                self.prover_fee
            ));
        }
        Ok((burned, self.prover_fee, net - self.prover_fee))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tx {
    Coinbase(Coinbase),
    Spend(Spend),
    Act(Action),
    BatchSpend(BatchSpend),
}

impl Tx {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Tx::Coinbase(c) => {
                w.u8(0).u32(c.height).u32(c.outs.len() as u32);
                for o in &c.outs {
                    w.word8(&o.a_pk).u64(o.v).rho(&o.rho);
                }
                w.bytes(&c.extra);
            }
            Tx::Spend(s) => {
                w.u8(1).word8(&s.anchor).word8(&s.nf[0]).word8(&s.nf[1]);
                w.word8(&s.cm_out[0]).word8(&s.cm_out[1]).bool(s.dummy[0]).bool(s.dummy[1]).u64(s.fee);
                match &s.deposit {
                    None => {
                        w.u8(0);
                    }
                    Some(d) => d.encode(w),
                }
                w.bytes(&s.memo).bytes(&s.proof);
            }
            Tx::Act(a) => {
                w.u8(2);
                a.encode(w);
            }
            Tx::BatchSpend(bs) => {
                w.u8(3).u8(bs.spends.len() as u8).word8(&bs.prover_a_pk).u64(bs.prover_fee);
                for s in &bs.spends {
                    w.word8(&s.anchor).word8(&s.nf[0]).word8(&s.nf[1]);
                    w.word8(&s.cm_out[0]).word8(&s.cm_out[1]).bool(s.dummy[0]).bool(s.dummy[1]).u64(s.fee);
                    match &s.deposit {
                        None => {
                            w.u8(0);
                        }
                        Some(d) => d.encode(w),
                    }
                    w.bytes(&s.memo);
                }
                w.bytes(&bs.proof);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Res<Tx> {
        Ok(match r.u8()? {
            0 => {
                let height = r.u32()?;
                let n = r.u32()? as usize;
                if n > 64 {
                    return Err("too many coinbase outputs".into());
                }
                let outs = (0..n)
                    .map(|_| Ok(PlainOut { a_pk: r.word8()?, v: r.u64()?, rho: r.rho()? }))
                    .collect::<Res<Vec<_>>>()?;
                Tx::Coinbase(Coinbase { height, outs, extra: r.bytes(crate::params::MAX_COINBASE_EXTRA)? })
            }
            1 => {
                let anchor = r.word8()?;
                let nf = [r.word8()?, r.word8()?];
                let cm_out = [r.word8()?, r.word8()?];
                let dummy = [r.bool()?, r.bool()?];
                let fee = r.u64()?;
                let deposit = match r.u8()? {
                    0 => None,
                    tag => Some(Deposit::decode_body(tag, r)?),
                };
                Tx::Spend(Spend { anchor, nf, cm_out, dummy, fee, deposit, memo: r.bytes(MAX_MEMO)?, proof: r.bytes(crate::spend::PROOF_BYTES_CAP)? })
            }
            2 => Tx::Act(Action::decode(r)?),
            3 => {
                let n = r.u8()? as usize;
                if !(MIN_BATCH_SPENDS..=MAX_BATCH_SPENDS).contains(&n) {
                    return Err("batch spend count out of range".into());
                }
                let prover_a_pk = r.word8()?;
                let prover_fee = r.u64()?;
                let mut spends = Vec::with_capacity(n);
                for _ in 0..n {
                    let anchor = r.word8()?;
                    let nf = [r.word8()?, r.word8()?];
                    let cm_out = [r.word8()?, r.word8()?];
                    let dummy = [r.bool()?, r.bool()?];
                    let fee = r.u64()?;
                    let deposit = match r.u8()? {
                        0 => None,
                        tag => Some(Deposit::decode_body(tag, r)?),
                    };
                    let memo = r.bytes(MAX_MEMO)?;
                    spends.push(BatchSpendItem { anchor, nf, cm_out, dummy, fee, deposit, memo });
                }
                let proof = r.bytes(MAX_BATCH_PROOF_BYTES)?;
                Tx::BatchSpend(BatchSpend { spends, prover_a_pk, prover_fee, proof })
            }
            _ => return Err("bad tx tag".into()),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Res<Tx> {
        if b.len() > TX_BYTES_CAP {
            return Err(format!("transaction of {} bytes exceeds {TX_BYTES_CAP}", b.len()));
        }
        let mut r = Reader::new(b);
        let t = Tx::decode(&mut r)?;
        r.finish()?;
        Ok(t)
    }

    /// Identifier over the full transaction, proof included.
    pub fn id(&self) -> [u8; 32] {
        sha256d(&self.to_bytes())
    }
}

// ---- blocks --------------------------------------------------------------------------

/// 80 bytes in Bitcoin's layout, so any SHA-256 miner, from a $100 open-source board to a
/// warehouse, can work it through a standard pool protocol. The 32-byte field Bitcoin
/// uses for its transaction root carries this chain's commitment instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub prev: [u8; 32],
    pub commit: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
    pub fn bytes(&self) -> [u8; 80] {
        let mut b = [0u8; 80];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.prev);
        b[36..68].copy_from_slice(&self.commit);
        b[68..72].copy_from_slice(&self.time.to_le_bytes());
        b[72..76].copy_from_slice(&self.bits.to_le_bytes());
        b[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }
    pub fn from_bytes(b: &[u8; 80]) -> Header {
        Header {
            version: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            prev: b[4..36].try_into().unwrap(),
            commit: b[36..68].try_into().unwrap(),
            time: u32::from_le_bytes(b[68..72].try_into().unwrap()),
            bits: u32::from_le_bytes(b[72..76].try_into().unwrap()),
            nonce: u32::from_le_bytes(b[76..80].try_into().unwrap()),
        }
    }
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.bytes())
    }
}

/// Display a hash the way Bitcoin does: byte-reversed hex.
pub fn hash_hex(h: &[u8; 32]) -> String {
    let mut r = *h;
    r.reverse();
    hex::encode(r)
}

/// Bytes of an encoded block that are not its merged-mining proof or its transactions: the
/// header, the transaction count and the state digest.
pub const BLOCK_OVERHEAD: usize = 80 + 4 + 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    /// Present exactly when the header's version marks the block as merge-mined.
    pub auxpow: Option<AuxPow>,
    /// Digest of the state this block leaves behind. A block's hash covers only its header,
    /// and the header commits to the transactions and this digest together
    /// (`header_commit`); the digest alone can only be worked out by applying every
    /// transaction. Carrying it lets a node tell at once, before it keeps anything, whether
    /// these are the transactions the header vouches for (`bound`). All zero in a block
    /// sent as a header only.
    pub digest: [u8; 32],
    pub txs: Vec<Tx>,
}

pub fn merkle_root(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            // Bitcoin duplicates the last element; we pad with zeros instead, which removes
            // the CVE-2012-2459 ambiguity of a duplicated final pair.
            hashes.push([0u8; 32]);
        }
        hashes = hashes.chunks(2).map(|c| sha256d(&[c[0], c[1]].concat())).collect();
    }
    hashes[0]
}

impl Block {
    pub fn tx_root(&self) -> [u8; 32] {
        merkle_root(self.txs.iter().map(|t| t.id()).collect())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.header.bytes());
        if let Some(a) = &self.auxpow {
            w.bytes(&a.to_bytes());
        }
        w.u32(self.txs.len() as u32);
        if !self.txs.is_empty() {
            w.raw(&self.digest);
        }
        for t in &self.txs {
            w.bytes(&t.to_bytes());
        }
        w.0
    }

    pub fn decode(b: &[u8]) -> Res<Block> {
        Self::decode_as(b, true)
    }

    /// A block read back from this node's own disk. Blocks written before they carried
    /// their state digest are still read (`digest` comes back zero, and the chain works it
    /// out as it replays them). Never used for bytes from the network.
    pub fn decode_stored(b: &[u8]) -> Res<Block> {
        match Self::decode_as(b, true) {
            Ok(blk) if blk.bound() => Ok(blk),
            _ => Self::decode_as(b, false),
        }
    }

    fn decode_as(b: &[u8], with_digest: bool) -> Res<Block> {
        let mut r = Reader::new(b);
        let header = Header::from_bytes(&r.arr::<80>()?);
        let auxpow = if auxpow::is_auxpow(header.version) { Some(AuxPow::parse(&r.bytes(auxpow::MAX_AUXPOW_BYTES)?)?) } else { None };
        let n = r.u32()? as usize;
        if n > crate::params::MAX_BLOCK_TXS {
            return Err("too many transactions".into());
        }
        let digest = if n > 0 && with_digest { r.arr::<32>()? } else { [0u8; 32] };
        // room is set aside as transactions really arrive, never for a count the bytes
        // only claim: a transaction in memory is some eighty times its smallest encoding
        let mut txs = Vec::with_capacity(n.min(1024).min(r.remaining() / 5));
        for _ in 0..n {
            txs.push(Tx::from_bytes(&r.bytes(TX_BYTES_CAP)?)?);
        }
        r.finish()?;
        Ok(Block { header, auxpow, digest, txs })
    }

    /// Are these the transactions, and is this the state digest, that the header commits
    /// to? Checked before a block is kept, so that nothing a node later learns by applying
    /// the block can be blamed on a header whose real transactions it has not seen.
    pub fn bound(&self) -> bool {
        !self.txs.is_empty() && self.header.commit == header_commit(&self.tx_root(), &self.digest)
    }

    /// The limits on a block that need no knowledge of the chain. Returns its encoded size.
    pub fn check_limits(&self, max_block_bytes: usize, max_tx_bytes: usize) -> Res<usize> {
        if self.txs.len() > crate::params::MAX_BLOCK_TXS {
            return Err("too many transactions".into());
        }
        let mut size = BLOCK_OVERHEAD + self.auxpow_bytes();
        for (i, tx) in self.txs.iter().enumerate() {
            let n = tx.to_bytes().len();
            if n > max_tx_bytes {
                return Err(format!("tx {i}: {n} bytes exceeds {max_tx_bytes}"));
            }
            size += 4 + n;
        }
        if size > max_block_bytes {
            return Err(format!("block of {size} bytes exceeds the limit"));
        }
        Ok(size)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    /// Bytes the auxpow adds to the encoded block, its length prefix included.
    pub fn auxpow_bytes(&self) -> usize {
        self.auxpow.as_ref().map(|a| 4 + a.to_bytes().len()).unwrap_or(0)
    }
}

/// The header's commitment: transactions and the state they produce.
pub fn header_commit(tx_root: &[u8; 32], state_digest: &[u8; 32]) -> [u8; 32] {
    sha256d(&[b"nsBLOCK".as_slice(), tx_root, state_digest].concat())
}
