//! A wallet: one spending key, the openings of notes it has been given, and a job key.
//!
//! A payment reaches its payee in one of two ways. Paid to a delivery address (`nsd1…`), it
//! travels on chain, sealed to the payee's key (`crate::deliver`), and the payee's wallet
//! finds it by scanning. Paid to a plain address (`ns1…`), it is delivered out of band, as
//! Magic Money's coins were in 1994: the payer hands the payee a short note string, which
//! needs no assumption at all. Change is always sealed to the payer's own key, so the
//! spending key alone restores a wallet. Coinbase rewards and job payouts have public
//! openings and are found by address.

use crate::chain::Chain;
use crate::hash::{bytes_to_words, sha256, words_to_bytes, Word8};
use crate::job::{Deposit, JobKey};
use crate::note::{self, Rho, MAX_NOTE_VALUE};
use crate::spend::{self, InputNote, OutputNote, SpendWitness};
use crate::tx::{bind_of, Spend, Tx};
use rand::Rng;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Wallet {
    pub sk: Word8,
    pub job_key: Vec<u8>,
    /// Openings of notes addressed to us that are not public: received payments and change.
    pub notes: Vec<(u64, Rho)>,
    /// The height up to which the chain has been scanned for notes delivered to this wallet.
    pub scanned: u32,
    path: Option<PathBuf>,
}

/// How far back each scan looks again, for notes a reorganisation moved.
const RESCAN_BLOCKS: u32 = 12;

#[derive(Clone, Debug)]
pub struct Owned {
    pub v: u64,
    pub rho: Rho,
    pub cm: Word8,
    pub pos: u32,
    pub nf: Word8,
}

pub fn encode_address(a_pk: &Word8) -> String {
    let b = words_to_bytes(a_pk);
    format!("ns1{}{}", hex::encode(b), hex::encode(&sha256(&b)[..4]))
}

pub fn parse_address(s: &str) -> Result<Word8, String> {
    let h = s.strip_prefix("ns1").ok_or("address must start with ns1")?;
    // one address, one spelling: lower case only, so two strings that differ are two addresses
    if h.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err("address must be in lower case".into());
    }
    let raw = hex::decode(h).map_err(|_| "address is not hex")?;
    if raw.len() != 36 {
        return Err("address has the wrong length".into());
    }
    let b: [u8; 32] = raw[..32].try_into().unwrap();
    if sha256(&b)[..4] != raw[32..] {
        return Err("address checksum mismatch".into());
    }
    Ok(bytes_to_words(&b))
}

/// The string a payer gives a payee.
pub fn encode_note(a_pk: &Word8, v: u64, rho: &Rho) -> String {
    let mut b = words_to_bytes(a_pk).to_vec();
    b.extend_from_slice(&v.to_le_bytes());
    for x in rho {
        b.extend_from_slice(&x.to_be_bytes());
    }
    format!("nsnote1{}", hex::encode(b))
}

pub fn parse_note(s: &str) -> Result<(Word8, u64, Rho), String> {
    let h = s.trim().strip_prefix("nsnote1").ok_or("note must start with nsnote1")?;
    let b = hex::decode(h).map_err(|_| "note is not hex")?;
    if b.len() != 60 {
        return Err("note has the wrong length".into());
    }
    let a_pk = bytes_to_words(&b[..32].try_into().unwrap());
    let v = u64::from_le_bytes(b[32..40].try_into().unwrap());
    let rho: Rho = core::array::from_fn(|i| u32::from_be_bytes(b[40 + 4 * i..44 + 4 * i].try_into().unwrap()));
    Ok((a_pk, v, rho))
}

impl Wallet {
    pub fn generate() -> Wallet {
        Wallet::from_key(rand::thread_rng().gen())
    }

    /// A wallet for a spending key; its job key is derived from it.
    pub fn from_key(sk: Word8) -> Wallet {
        Wallet { sk, job_key: JobKey::derive(&words_to_bytes(&sk)).to_bytes(), notes: vec![], scanned: 0, path: None }
    }

    /// Restore a wallet from its spending key (64 hex characters) into a new file. Its notes
    /// come back from the chain at the next scan: change and payments delivered to it, and
    /// public notes by address. Payments that came as note strings come back only from them.
    pub fn restore(path: &Path, key_hex: &str) -> Result<Wallet, String> {
        if path.exists() {
            return Err(format!("{} exists already; restore into another --datadir", path.display()));
        }
        let b: [u8; 32] = hex::decode(key_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("a key is 64 hex characters")?;
        let mut w = Wallet::from_key(bytes_to_words(&b));
        w.path = Some(path.to_path_buf());
        w.save()?;
        Ok(w)
    }

    pub fn load_or_create(path: &Path) -> Result<Wallet, String> {
        if !path.exists() {
            let mut w = Wallet::generate();
            w.path = Some(path.to_path_buf());
            w.save()?;
            return Ok(w);
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut w = Wallet { sk: [0; 8], job_key: vec![], notes: vec![], scanned: 0, path: Some(path.to_path_buf()) };
        for line in text.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next(), it.next()) {
                (Some("sk"), Some(h), _) => w.sk = bytes_to_words(&hex::decode(h).map_err(|e| e.to_string())?.try_into().map_err(|_| "bad sk")?),
                (Some("jobkey"), Some(h), _) => w.job_key = hex::decode(h).map_err(|e| e.to_string())?,
                (Some("scanned"), Some(h), _) => w.scanned = h.parse().map_err(|_| "bad scan height")?,
                (Some("note"), Some(v), Some(r)) => {
                    let rb = hex::decode(r).map_err(|e| e.to_string())?;
                    let rho: Rho = core::array::from_fn(|i| u32::from_be_bytes(rb[4 * i..4 * i + 4].try_into().unwrap()));
                    w.notes.push((v.parse().map_err(|_| "bad value")?, rho));
                }
                _ => {}
            }
        }
        Ok(w)
    }

    pub fn save(&self) -> Result<(), String> {
        let Some(p) = &self.path else { return Ok(()) };
        let mut s = format!(
            "# NEWSATOSHI wallet. Keep this file secret: it spends your coins.\nsk {}\njobkey {}\nscanned {}\n",
            hex::encode(words_to_bytes(&self.sk)),
            hex::encode(&self.job_key),
            self.scanned
        );
        for (v, rho) in &self.notes {
            let rb: Vec<u8> = rho.iter().flat_map(|x| x.to_be_bytes()).collect();
            s += &format!("note {v} {}\n", hex::encode(rb));
        }
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, s).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, p).map_err(|e| e.to_string())
    }

    pub fn a_pk(&self) -> Word8 {
        note::address(&self.sk)
    }

    pub fn address(&self) -> String {
        encode_address(&self.a_pk())
    }

    /// The address to give payers: payments to it arrive on chain, with nothing to pass on.
    pub fn delivery_address(&self) -> String {
        crate::deliver::delivery_address(&self.sk)
    }

    pub fn job_key(&self) -> Result<JobKey, String> {
        JobKey::from_bytes(&self.job_key)
    }

    /// Accept a note string from a payer.
    pub fn import(&mut self, s: &str) -> Result<u64, String> {
        let (a_pk, v, rho) = parse_note(s)?;
        if a_pk != self.a_pk() {
            return Err("this note is addressed to someone else".into());
        }
        if !self.notes.contains(&(v, rho)) {
            self.notes.push((v, rho));
        }
        self.save()?;
        Ok(v)
    }

    pub fn unspent(&self, chain: &Chain) -> Vec<Owned> {
        let me = self.a_pk();
        let mut cands: Vec<(u64, Rho)> = chain.state.public_notes.get(&me).cloned().unwrap_or_default();
        cands.extend(self.notes.iter().copied());
        cands.sort();
        cands.dedup();
        let mut out = vec![];
        for (v, rho) in cands {
            let cm = note::commit(&me, v, &rho);
            for pos in chain.state.cm_pos.get(&cm).cloned().unwrap_or_default() {
                let nf = note::nullifier(&self.sk, pos, &rho);
                if !chain.state.nullifiers.contains(&nf) {
                    out.push(Owned { v, rho, cm, pos, nf });
                }
            }
        }
        out
    }

    pub fn balance(&self, chain: &Chain) -> u64 {
        self.unspent(chain).iter().map(|o| o.v).sum()
    }

    /// Build and prove a spend. `to` is an optional payment; `deposit` an optional job
    /// deposit paid from the public value. Returns the transaction and the note string for
    /// the payee (if any). Change returns to this wallet and is remembered.
    pub fn spend(&mut self, chain: &Chain, to: Option<(Word8, u64)>, fee: u64, deposit: Option<Deposit>, memo: Vec<u8>) -> Result<(Tx, Option<String>), String> {
        self.spend_excluding(chain, to, None, fee, deposit, memo, &std::collections::HashSet::new())
    }

    /// Pay an address of either kind. Paid to a delivery address (`nsd1…`), the payment
    /// travels on chain, sealed to the payee's key, and their wallet finds it; paid to a
    /// plain address (`ns1…`), the payee needs the note string this returns.
    pub fn pay(&mut self, chain: &Chain, to: &str, v: u64, fee: u64, memo: Vec<u8>) -> Result<(Tx, Option<String>), String> {
        let (a_pk, key) = crate::deliver::parse_any_address(to)?;
        self.spend_excluding(chain, Some((a_pk, v)), key.as_deref(), fee, None, memo, &std::collections::HashSet::new())
    }

    /// Look for notes delivered to this wallet in blocks since the last scan (and a few
    /// before it, in case of a reorganisation), remember them, and save. Returns how many
    /// were new. Set `scanned` to 0 first to look through the whole chain.
    pub fn scan(&mut self, chain: &Chain) -> Result<usize, String> {
        let from = self.scanned.saturating_sub(RESCAN_BLOCKS);
        let found = self.scan_range(chain, from);
        self.scanned = chain.height() + 1;
        self.save()?;
        Ok(found)
    }

    fn scan_range(&mut self, chain: &Chain, from_height: u32) -> usize {
        let sc = crate::deliver::Scanner::new(&self.sk);
        let mut found = 0;
        for h in from_height..=chain.height() {
            let Some(b) = chain.block_at(h) else { continue };
            for t in &b.txs {
                let Tx::Spend(sp) = t else { continue };
                let (env, _) = crate::deliver::unpack_memo(&sp.memo);
                for (i, e) in env.iter().enumerate() {
                    if let Some((v, rho)) = e.and_then(|e| sc.open(&sp.cm_out[i], e)) {
                        if !self.notes.contains(&(v, rho)) {
                            self.notes.push((v, rho));
                            found += 1;
                        }
                    }
                }
            }
        }
        found
    }

    /// As `spend`, leaving out notes whose nullifiers are in `busy` (spent by transactions
    /// still waiting in a mempool).
    /// `to_key` is the payee's delivery key, if the payment is to be delivered on chain.
    #[allow(clippy::too_many_arguments)]
    pub fn spend_excluding(
        &mut self,
        chain: &Chain,
        to: Option<(Word8, u64)>,
        to_key: Option<&[u8]>,
        fee: u64,
        deposit: Option<Deposit>,
        memo: Vec<u8>,
        busy: &std::collections::HashSet<Word8>,
    ) -> Result<(Tx, Option<String>), String> {
        let pay = to.map(|t| t.1).unwrap_or(0);
        let need = pay as u128 + fee as u128 + deposit.as_ref().map(|d| d.amount() as u128).unwrap_or(0);
        let mut coins: Vec<Owned> = self.unspent(chain).into_iter().filter(|c| !busy.contains(&c.nf)).collect();
        coins.sort_by(|a, b| b.v.cmp(&a.v));
        let chosen: Vec<Owned> = if coins.first().map(|c| c.v as u128 >= need).unwrap_or(false) {
            vec![coins[0].clone()]
        } else if coins.len() >= 2 && coins[0].v as u128 + coins[1].v as u128 >= need {
            coins[..2].to_vec()
        } else {
            return Err(format!("insufficient funds: need {need}, the two largest notes hold {}", coins.iter().take(2).map(|c| c.v as u128).sum::<u128>()));
        };
        let have: u128 = chosen.iter().map(|c| c.v as u128).sum();
        let change = (have - need) as u64;
        if change > MAX_NOTE_VALUE || pay > MAX_NOTE_VALUE {
            return Err("value out of range".into());
        }
        let mut rng = rand::thread_rng();
        let input = |c: &Owned| InputNote { sk: self.sk, v: c.v, rho: c.rho, pos: c.pos, path: chain.state.tree.path(c.pos) };
        let (in0, in1, dummy) = match chosen.as_slice() {
            [a] => (input(a), InputNote::dummy(), [false, true]),
            [a, b] => (input(a), input(b), [false, false]),
            _ => unreachable!(),
        };
        let (to_apk, to_v) = to.unwrap_or((self.a_pk(), 0));
        let out_pay = OutputNote { a_pk: to_apk, v: to_v, rho: rng.gen() };
        let out_change = OutputNote { a_pk: self.a_pk(), v: change, rho: rng.gen() };
        let memo = crate::deliver::memo_for(&self.sk, &[out_pay.clone(), out_change.clone()], [to_key, None], &memo)?;
        let wit = SpendWitness { inputs: [in0, in1], outputs: [out_pay.clone(), out_change.clone()], dummy };
        let bind = bind_of(fee, &deposit, &memo);
        let (pi, proof) = spend::prove_for(&chain.params.proof, &wit, bind)?;
        debug_assert_eq!(pi.root, chain.state.tree.root());
        let tx = Tx::Spend(Spend {
            anchor: pi.root,
            nf: pi.nf,
            cm_out: pi.cm_out,
            dummy,
            fee,
            deposit,
            memo,
            proof: proof.to_bytes(),
        });
        // remember what is ours; the payee's opening goes out as a note string
        self.notes.push((change, out_change.rho));
        if to.is_none() {
            self.notes.push((0, out_pay.rho));
        }
        self.save()?;
        let note_str = to.map(|(a, v)| encode_note(&a, v, &out_pay.rho));
        Ok((tx, note_str))
    }
}
