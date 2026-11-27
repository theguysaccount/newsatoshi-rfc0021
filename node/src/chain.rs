//! The chain: headers, fork choice by accumulated work, reorganisation, persistence.

use crate::params::{Net, Params, MAX_FUTURE_SECS};
use crate::auxpow;
use crate::pow::{self, meets};
use crate::state::{Checks, State, FULL};
use crate::tx::{header_commit, Block, Coinbase, Header, PlainOut, Tx};
use primitive_types::U256;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SNAPSHOTS: usize = 24;

/// A chain kept on disk holds in memory the bodies of only its newest blocks (and of blocks
/// it has not written anywhere): this many below the tip. Everything else is read back from
/// disk when it is asked for, so memory does not grow with the chain.
pub const RECENT_IN_MEMORY: u32 = 12;

/// A file of blocks: each record a 4-byte length and then a block's encoding.
struct Store {
    append: File,
    reader: Mutex<File>,
    /// Its length: where the next record goes.
    end: u64,
    /// Bytes past `end` to cut before the first write (a torn last record, or what an
    /// earlier run left in side.dat). Cut only by a process that writes, so a wallet command
    /// that opens the chain beside a running node never changes the node's files.
    trim: bool,
}

impl Store {
    /// Open (or make) the file; the next record goes at `keep` if given.
    fn open(path: &Path, keep: Option<u64>) -> std::io::Result<Store> {
        let append = OpenOptions::new().create(true).append(true).open(path)?;
        let len = append.metadata()?.len();
        let end = keep.map_or(len, |n| n.min(len));
        Ok(Store { append, reader: Mutex::new(File::open(path)?), end, trim: end < len })
    }

    /// Append a record; returns where its block's bytes start.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<u64> {
        if self.trim {
            self.append.set_len(self.end)?;
            self.trim = false;
        }
        let res = self.append.write_all(&(bytes.len() as u32).to_le_bytes()).and_then(|_| self.append.write_all(bytes));
        if let Err(e) = res {
            self.end = self.append.metadata().map(|m| m.len()).unwrap_or(self.end);
            return Err(e);
        }
        let at = self.end + 4;
        self.end += 4 + bytes.len() as u64;
        Ok(at)
    }

    fn read(&self, at: u64, n: usize) -> std::io::Result<Vec<u8>> {
        let mut f = self.reader.lock().unwrap_or_else(|e| e.into_inner());
        f.seek(SeekFrom::Start(at))?;
        let mut v = vec![0; n];
        f.read_exact(&mut v)?;
        Ok(v)
    }
}

/// Where a block's bytes are on disk: in `blocks.dat` (connected blocks, read back at every
/// start) or `side.dat` (blocks not connected yet, forgotten at every start), where they
/// start, and how many.
#[derive(Clone, Copy)]
struct Place {
    side: bool,
    at: u64,
    len: u32,
}
/// A block that does not outweigh the tip is kept anyway when it rivals it: when its chain
/// is within this many blocks' work of the tip's.
const NEAR_TIP_BLOCKS: u64 = 6;
/// Hashes of blocks asked for because their headers showed a heavier chain.
const MAX_WANTED: usize = 200_000;
/// Why a block was not kept: its chain does not outweigh this node's, it does not rival
/// the tip, and nothing has shown it to belong to a heavier chain.
pub const NOT_HEAVIER: &str = "not on a chain with more work";

/// Why a block was refused whose transactions or state digest are not the ones its header
/// commits to. Nothing is held against the block's hash.
pub const NOT_THIS_BODY: &str = "these are not the transactions this header commits to";

#[derive(Clone, Debug)]
pub struct Entry {
    pub hash: [u8; 32],
    pub prev: [u8; 32],
    pub height: u32,
    pub time: u32,
    pub bits: u32,
    pub work: U256,
}

/// The block's proof of work: the hash of its own header, or, for a merge-mined block, the
/// hash of the Bitcoin header whose coinbase commits to it (white paper §4).
/// The difficulty a block on top of `parent` must carry: ASERT from the genesis anchor
/// (with optional anti-instamine Day-1 launch ramp when `params.launch_blocks > 0`).
pub fn next_bits_for(params: &Params, parent: &Entry) -> Result<u32, String> {
    next_bits_for_with_anchor(params, parent, None)
}

pub fn next_bits_for_with_anchor(
    params: &Params,
    parent: &Entry,
    steady_anchor: Option<(u32, i64)>,
) -> Result<u32, String> {
    if params.net == Net::Reg {
        return Ok(params.pow_limit);
    }
    pow::asert_bits_staged(
        params.genesis_bits,
        params.genesis_time as i64 - params.target_spacing,
        params.launch_blocks,
        params.launch_half_life,
        steady_anchor,
        parent.height,
        parent.time as i64,
        params.half_life,
        params.pow_limit,
        params.target_spacing,
    )
}

/// Check a run of headers on top of `prev`, whose own time and those of the ten blocks
/// before it are `times` (oldest first), plus optional `steady_anchor` `(bits, time)` at
/// `params.launch_blocks` when `prev.height >= params.launch_blocks`. Each header links to
/// the one before, carries the difficulty ASERT sets and the work it claims, is later than
/// the median of the eleven before it and not too far ahead of `now`, and agrees with every
/// release checkpoint. Automatically captures `steady_anchor` as the run crosses
/// `params.launch_blocks`, returning `(last_entry, times, steady_anchor)`.
pub fn check_run(
    params: &Params,
    mut prev: Entry,
    mut times: std::collections::VecDeque<u32>,
    mut steady_anchor: Option<(u32, i64)>,
    hs: &[Block],
    now: i64,
) -> Result<(Entry, std::collections::VecDeque<u32>, Option<(u32, i64)>), String> {
    if params.launch_blocks > 0 && prev.height == params.launch_blocks && steady_anchor.is_none() {
        steady_anchor = Some((prev.bits, prev.time as i64));
    }
    for b in hs {
        let hd = &b.header;
        if hd.prev != prev.hash {
            return Err("headers do not link".into());
        }
        let height = prev.height + 1;
        let expected_bits = next_bits_for_with_anchor(params, &prev, steady_anchor)?;
        if hd.bits != expected_bits {
            return Err(format!("wrong difficulty at height {height}"));
        }
        check_work(b)?;
        let mut sorted: Vec<u32> = times.iter().copied().collect();
        sorted.sort_unstable();
        if sorted.is_empty() || hd.time <= sorted[sorted.len() / 2] {
            return Err(format!("timestamp not after median time past at height {height}"));
        }
        if hd.time as i64 > now + MAX_FUTURE_SECS {
            return Err("timestamp too far in the future".into());
        }
        if height <= params.checkpoint_sunset {
            if let Some((_, want)) = params.checkpoints.iter().find(|(ch, _)| *ch == height) {
                if *want != hd.hash() {
                    return Err("conflicts with a release checkpoint".into());
                }
            }
        }
        prev = Entry { hash: hd.hash(), prev: hd.prev, height, time: hd.time, bits: hd.bits, work: prev.work + pow::work(hd.bits) };
        if params.launch_blocks > 0 && height == params.launch_blocks {
            steady_anchor = Some((hd.bits, hd.time as i64));
        }
        times.push_back(hd.time);
        if times.len() > 11 {
            times.pop_front();
        }
    }
    Ok((prev, times, steady_anchor))
}

pub fn check_work(b: &Block) -> Result<(), String> {
    let hd = &b.header;
    match (&b.auxpow, auxpow::is_auxpow(hd.version)) {
        (None, false) => {
            if meets(&hd.hash(), hd.bits) {
                Ok(())
            } else {
                Err("insufficient proof of work".into())
            }
        }
        (None, true) => Err("merge-mined version without an auxpow".into()),
        (Some(_), false) => Err("auxpow on a block that is not marked merge-mined".into()),
        (Some(a), true) => {
            if auxpow::chain_id(hd.version) != auxpow::CHAIN_ID {
                return Err("merge-mined block without our chain ID".into());
            }
            if auxpow::is_auxpow(a.parent_version()) {
                return Err("auxpow parent is itself marked merge-mined".into());
            }
            if !meets(&a.parent_hash(), hd.bits) {
                return Err("insufficient proof of work".into());
            }
            a.check(&hd.hash(), auxpow::CHAIN_ID)
        }
    }
}

pub fn mine(header: &mut Header, max_tries: u64) -> bool {
    for _ in 0..max_tries {
        if meets(&header.hash(), header.bits) {
            return true;
        }
        header.nonce = header.nonce.wrapping_add(1);
        if header.nonce == 0 {
            header.time += 1;
        }
    }
    false
}

pub fn genesis_block(params: &Params) -> Block {
    let cb = Tx::Coinbase(Coinbase { height: 0, outs: vec![], extra: params.genesis_message.as_bytes().to_vec() });
    let mut b = Block {
        header: Header { version: 1, prev: [0; 32], commit: [0; 32], time: params.genesis_time, bits: params.genesis_bits, nonce: params.genesis_nonce },
        auxpow: None,
        digest: [0; 32],
        txs: vec![cb],
    };
    let st = State::new().apply(&b, params, Checks { verify_proofs: false, check_commit: false }).expect("genesis");
    b.digest = st.digest();
    b.header.commit = header_commit(&b.tx_root(), &b.digest);
    if params.genesis_nonce == u32::MAX {
        b.header.nonce = 0;
        mine(&mut b.header, u64::MAX);
    }
    b
}

pub struct Chain {
    pub params: Params,
    pub genesis: [u8; 32],
    blocks: HashMap<[u8; 32], Block>,
    index: HashMap<[u8; 32], Entry>,
    invalid: HashSet<[u8; 32]>,
    /// Blocks to keep when they arrive though they do not yet outweigh the tip (`expect`).
    wanted: HashSet<[u8; 32]>,
    /// Encoded size and number of transactions of each block held, for the status page.
    sizes: HashMap<[u8; 32], (u32, u32)>,
    /// True while blocks are read back from disk: they were connected once, so all are kept.
    loading: bool,
    pub active: Vec<[u8; 32]>,
    snapshots: HashMap<[u8; 32], State>,
    pub state: State,
    /// `blocks.dat`: every block that was connected to the active chain, in the order
    /// they were. Only these are written there, so nothing in it can fail validation at
    /// the next start, and its blocks are not checked again when they are read back.
    store: Option<Store>,
    /// `side.dat`: blocks kept but not connected (rivals of the tip, and the start of a
    /// heavier chain still arriving), so their bodies need not sit in memory either. It is
    /// emptied at every start.
    side: Option<Store>,
    /// Where each block on disk is.
    place: HashMap<[u8; 32], Place>,
    /// Blocks already in `blocks.dat`.
    persisted: HashSet<[u8; 32]>,
    pub dir: Option<PathBuf>,
    /// True when `Chain::open` restored verified state from `state.snap`.
    pub fast_boot: bool,
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

impl Chain {
    pub fn open(params: Params, dir: Option<&Path>) -> Result<Chain, String> {
        let g = genesis_block(&params);
        let gh = g.hash();
        if !meets(&gh, g.header.bits) {
            return Err("genesis does not meet its own target".into());
        }
        let st = State::new().apply(&g, &params, FULL)?;
        let entry = Entry { hash: gh, prev: [0; 32], height: 0, time: g.header.time, bits: g.header.bits, work: pow::work(g.header.bits) };
        let mut c = Chain {
            params,
            genesis: gh,
            blocks: HashMap::from([(gh, g)]),
            index: HashMap::from([(gh, entry)]),
            invalid: HashSet::new(),
            wanted: HashSet::new(),
            sizes: HashMap::new(),
            loading: false,
            active: vec![gh],
            snapshots: HashMap::from([(gh, st.clone())]),
            state: st,
            store: None,
            side: None,
            place: HashMap::new(),
            persisted: HashSet::from([gh]),
            dir: dir.map(|d| d.to_path_buf()),
            fast_boot: false,
        };
        if let Some(d) = dir {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
            let path = d.join("blocks.dat");
            // where the last whole record ends: a torn final write after it is cut off, so
            // the next block written does not land after half a record
            let mut whole = None;
            if path.exists() {
                let mut file = File::open(&path).map_err(|e| e.to_string())?;
                let size = file.metadata().map_err(|e| e.to_string())?.len();
                c.store = Some(Store { append: OpenOptions::new().append(true).open(&path).map_err(|e| e.to_string())?, reader: Mutex::new(File::open(&path).map_err(|e| e.to_string())?), end: size, trim: false });
                let mut at = 0u64;
                if let Some(snap_res) = crate::snapshot::load_verified(d, &c.genesis, size) {
                    match snap_res {
                        Ok(snap) if !snap.blocks.is_empty() => {
                            let last = snap.blocks.last().unwrap();
                            let tip_ok = c
                                .store
                                .as_ref()
                                .and_then(|s| s.read(last.at, last.len as usize).ok())
                                .and_then(|bytes| Block::decode(&bytes).ok())
                                .is_some_and(|b| b.hash() == snap.tip_hash && b.digest == snap.tip_digest);
                            if tip_ok && file.seek(SeekFrom::Start(snap.blocks_dat_end)).is_ok() {
                                for rec in snap.blocks {
                                    let h = rec.entry.hash;
                                    c.index.insert(h, rec.entry);
                                    c.active.push(h);
                                    c.sizes.insert(h, (rec.size, rec.txs));
                                    c.place.insert(h, Place { side: false, at: rec.at, len: rec.len });
                                    c.persisted.insert(h);
                                }
                                c.state = snap.state;
                                c.snapshots.insert(snap.tip_hash, c.state.clone());
                                at = snap.blocks_dat_end;
                                c.fast_boot = true;
                            } else {
                                eprintln!("state.snap tip mismatch with blocks.dat; replaying from genesis");
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("state.snap ignored ({e}); replaying blocks.dat from genesis");
                        }
                    }
                }
                let mut r = BufReader::with_capacity(1 << 20, file);
                let mut buf = vec![];
                let (mut records, mut kept, mut old_records) = (0usize, 0usize, 0usize);
                c.loading = true;
                loop {
                    let mut len = [0u8; 4];
                    if at + 4 > size || r.read_exact(&mut len).is_err() {
                        break;
                    }
                    let n = u32::from_le_bytes(len) as u64;
                    if at + 4 + n > size {
                        break; // torn final write
                    }
                    buf.resize(n as usize, 0);
                    if r.read_exact(&mut buf).is_err() {
                        break;
                    }
                    records += 1;
                    if let Ok(mut b) = Block::decode_stored(&buf) {
                        let current = b.bound();
                        if !current {
                            // Written before blocks carried their state digest. The digest
                            // is the state this block leaves on its parent, and the file is
                            // in the order blocks were connected, so the parent is here by
                            // now: usually the tip, or an earlier block where the file
                            // holds a reorganisation.
                            let no_proofs = Checks { verify_proofs: false, check_commit: false };
                            let after = if b.header.prev == c.tip().hash {
                                c.state.apply(&b, &c.params, no_proofs)
                            } else {
                                c.state_at_any(&b.header.prev).and_then(|s| s.apply(&b, &c.params, no_proofs))
                            };
                            if let Ok(st) = after {
                                b.digest = st.digest();
                                old_records += 1;
                            }
                        }
                        let h = b.hash();
                        c.persisted.insert(h);
                        if current {
                            // read back from here when it is wanted
                            c.place.insert(h, Place { side: false, at: at + 4, len: n as u32 });
                        }
                        let _ = c.add_block(b);
                        if c.index.contains_key(&h) {
                            kept += 1;
                        } else {
                            c.place.remove(&h);
                        }
                    }
                    at += 4 + n;
                }
                c.loading = false;
                drop(buf);
                whole = Some(at);
                if old_records > 0 && kept < records {
                    // a file in the earlier form that cannot be read back whole is a reason
                    // to stop, not to carry on with part of a chain
                    return Err(format!("{} holds {records} blocks in an earlier form and only {kept} could be read back; nothing was changed", path.display()));
                }
                if old_records > 0 {
                    // Every block was read back, so the file is written once more in
                    // today's form: the connected chain, in order. The new file replaces
                    // the old only when it is whole and on disk, and the old one is kept
                    // beside it as blocks.dat.old.
                    let fresh = d.join("blocks.dat.new");
                    let mut places = vec![];
                    let write = |places: &mut Vec<([u8; 32], Place)>| -> std::io::Result<u64> {
                        let mut f = std::io::BufWriter::new(File::create(&fresh)?);
                        let mut end = 0u64;
                        for h in c.active.iter().skip(1) {
                            let bytes = c.body(h).ok_or_else(|| std::io::Error::other("a block's body is missing"))?.encode();
                            f.write_all(&(bytes.len() as u32).to_le_bytes())?;
                            f.write_all(&bytes)?;
                            places.push((*h, Place { side: false, at: end + 4, len: bytes.len() as u32 }));
                            end += 4 + bytes.len() as u64;
                        }
                        f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
                        let _ = std::fs::hard_link(&path, d.join("blocks.dat.old"));
                        std::fs::rename(&fresh, &path)?;
                        Ok(end)
                    };
                    match write(&mut places) {
                        Ok(end) => {
                            eprintln!("{} rewritten in today's form: {} blocks; the earlier file is kept as blocks.dat.old", path.display(), c.active.len() - 1);
                            c.place = places.into_iter().collect();
                            whole = Some(end);
                        }
                        Err(e) => {
                            let _ = std::fs::remove_file(&fresh);
                            eprintln!("could not rewrite {}: {e}; it stays as it was", path.display());
                        }
                    }
                }
            }
            c.store = Some(Store::open(&path, whole).map_err(|e| e.to_string())?);
            // side.dat is opened when a block first needs it
            c.evict();
        }
        Ok(c)
    }

    pub fn tip(&self) -> &Entry {
        &self.index[self.active.last().unwrap()]
    }

    pub fn height(&self) -> u32 {
        self.tip().height
    }

    pub fn entry(&self, h: &[u8; 32]) -> Option<&Entry> {
        self.index.get(h)
    }

    /// A block this node holds, from memory or from disk.
    pub fn block(&self, h: &[u8; 32]) -> Option<Block> {
        self.body(h).map(Cow::into_owned)
    }

    /// The block of the active chain at `height`.
    pub fn block_at(&self, height: u32) -> Option<Block> {
        self.active.get(height as usize).and_then(|h| self.block(h))
    }

    /// The header of the active chain's block at `height`, with its merged-mining proof if
    /// it has one, and no transactions: read without reading the block's body.
    pub fn header_at(&self, height: u32) -> Option<Block> {
        self.active.get(height as usize).and_then(|h| self.head(h))
    }

    /// How many block bodies are in memory (the rest are on disk).
    pub fn bodies_in_memory(&self) -> usize {
        self.blocks.len()
    }

    fn body(&self, h: &[u8; 32]) -> Option<Cow<'_, Block>> {
        if let Some(b) = self.blocks.get(h) {
            return Some(Cow::Borrowed(b));
        }
        let p = self.place.get(h)?;
        let store = if p.side { self.side.as_ref() } else { self.store.as_ref() }?;
        let bytes = store.read(p.at, p.len as usize).ok()?;
        Block::decode(&bytes).ok().filter(|b| b.hash() == *h).map(Cow::Owned)
    }

    fn head(&self, h: &[u8; 32]) -> Option<Block> {
        if let Some(b) = self.blocks.get(h) {
            return Some(Block { header: b.header.clone(), auxpow: b.auxpow.clone(), digest: [0; 32], txs: vec![] });
        }
        let p = self.place.get(h)?;
        let store = if p.side { self.side.as_ref() } else { self.store.as_ref() }?;
        let first = store.read(p.at, 84.min(p.len as usize)).ok()?;
        let header = Header::from_bytes(first.get(..80)?.try_into().ok()?);
        let auxpow = if auxpow::is_auxpow(header.version) {
            let n = u32::from_le_bytes(first.get(80..84)?.try_into().ok()?) as usize;
            if 84 + n > p.len as usize {
                return None;
            }
            Some(crate::auxpow::AuxPow::parse(&store.read(p.at + 84, n).ok()?).ok()?)
        } else {
            None
        };
        (header.hash() == *h).then(|| Block { header, auxpow, digest: [0; 32], txs: vec![] })
    }

    /// Drop from memory the bodies that are on disk, except the newest of the active chain.
    fn evict(&mut self) {
        let tip = self.height();
        let recent = |h: &[u8; 32]| self.is_active(h) && self.index[h].height + RECENT_IN_MEMORY > tip;
        let old: Vec<[u8; 32]> = self.blocks.keys().filter(|h| self.place.contains_key(*h) && !recent(h)).copied().collect();
        for h in old {
            self.blocks.remove(&h);
        }
    }

    pub fn has(&self, h: &[u8; 32]) -> bool {
        self.index.contains_key(h)
    }

    pub fn is_active(&self, h: &[u8; 32]) -> bool {
        self.index.get(h).map(|e| self.active.get(e.height as usize) == Some(h)).unwrap_or(false)
    }

    /// Resolve the `(bits, time)` anchor at height `params.launch_blocks` along `parent`'s chain,
    /// needed by `asert_bits_staged` once `parent.height >= params.launch_blocks`.
    pub fn steady_anchor_for(&self, parent: &Entry) -> Option<(u32, i64)> {
        if self.params.launch_blocks == 0 || parent.height < self.params.launch_blocks {
            return None;
        }
        let lb = self.params.launch_blocks;
        let anchor_hash = if self.is_active(&parent.hash) {
            self.active.get(lb as usize).copied()
        } else {
            let mut cur = parent.hash;
            while let Some(e) = self.index.get(&cur) {
                if e.height <= lb {
                    break;
                }
                cur = e.prev;
            }
            self.index.get(&cur).filter(|e| e.height == lb).map(|e| e.hash)
        };
        anchor_hash
            .and_then(|h| self.index.get(&h))
            .map(|e| (e.bits, e.time as i64))
    }

    pub fn next_bits(&self, parent: &Entry) -> u32 {
        next_bits_for_with_anchor(&self.params, parent, self.steady_anchor_for(parent))
            .expect("known parent must resolve steady_anchor when past launch_blocks")
    }

    /// Median time of the last eleven blocks ending at `h`.
    pub fn mtp(&self, h: &[u8; 32]) -> u32 {
        let mut times = vec![];
        let mut cur = Some(*h);
        while let Some(x) = cur {
            if times.len() == 11 {
                break;
            }
            let e = &self.index[&x];
            times.push(e.time);
            cur = if e.height == 0 { None } else { Some(e.prev) };
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Add a block. Returns Ok(true) if it became the new tip. Header rules are checked
    /// first; a block with more work than the tip is then validated in full and connected.
    /// Whatever happens, the node ends on the most-work chain it can validate, and only
    /// connected blocks are written to disk.
    pub fn add_block(&mut self, b: Block) -> Result<bool, String> {
        let h = b.hash();
        if self.index.contains_key(&h) {
            return Ok(false);
        }
        if self.invalid.contains(&h) || self.invalid.contains(&b.header.prev) {
            self.invalid.insert(h);
            return Err("descends from an invalid block".into());
        }
        let parent = self.index.get(&b.header.prev).cloned().ok_or("unknown parent")?;
        self.check_header(&b, &parent)?;
        let height = parent.height + 1;
        let work = parent.work + pow::work(b.header.bits);
        let asked = self.wanted.remove(&h);
        if work <= self.tip().work && !asked && !self.loading {
            // A block that does not outweigh the tip costs its maker only the work of its
            // own header, which beside an old block is almost nothing. It is kept only if
            // it rivals the tip; anything else must first show, by its headers, that it
            // belongs to a heavier chain (`expect`).
            let near = work + pow::work(self.tip().bits) * U256::from(NEAR_TIP_BLOCKS) >= self.tip().work;
            if !near {
                return Err(NOT_HEAVIER.into());
            }
        }
        // The hash names the header alone. Before this node keeps the block, or holds
        // anything against that hash, the transactions and state digest must be the ones
        // the header commits to, and the block must be within the limits that need no
        // knowledge of the chain. A copy that fails here is refused and forgotten: the
        // real block of the same hash is still welcome.
        if !b.bound() {
            if asked {
                self.wanted.insert(h);
            }
            return Err(NOT_THIS_BODY.into());
        }
        let size = match b.check_limits(self.params.max_block_bytes, self.params.max_tx_bytes) {
            Ok(n) => n,
            Err(e) => {
                if asked {
                    self.wanted.insert(h);
                }
                return Err(e);
            }
        };
        self.index.insert(h, Entry { hash: h, prev: parent.hash, height, time: b.header.time, bits: b.header.bits, work });
        self.sizes.insert(h, (size as u32, b.txs.len() as u32));
        self.blocks.insert(h, b);
        let res = if work > self.tip().work { self.activate(h) } else { Ok(()) };
        if res.is_err() {
            self.reconsider();
        }
        self.persist_active()?;
        if !self.loading
            && self.dir.is_some()
            && self.tip().hash == h
            && self.height() > 0
            && self.height() % crate::snapshot::SNAPSHOT_INTERVAL == 0
        {
            let _ = self.save_snapshot();
        }
        // kept but not connected: its body goes to side.dat rather than staying in memory
        if !self.loading && !self.persisted.contains(&h) && !self.place.contains_key(&h) && self.blocks.contains_key(&h) {
            if self.side.is_none() {
                self.side = self.dir.as_ref().and_then(|d| Store::open(&d.join("side.dat"), Some(0)).ok());
            }
            if let Some(side) = self.side.as_mut() {
                let bytes = self.blocks[&h].encode();
                if let Ok(at) = side.write(&bytes) {
                    self.place.insert(h, Place { side: true, at, len: bytes.len() as u32 });
                }
            }
        }
        self.evict();
        res.map(|()| self.tip().hash == h)
    }

    fn check_header(&self, b: &Block, parent: &Entry) -> Result<(), String> {
        let hd = &b.header;
        let height = parent.height + 1;
        let want_bits = next_bits_for_with_anchor(&self.params, parent, self.steady_anchor_for(parent))?;
        if hd.bits != want_bits {
            return Err("wrong difficulty".into());
        }
        check_work(b)?;
        if hd.time <= self.mtp(&parent.hash) {
            return Err("timestamp not after median time past".into());
        }
        if hd.time as i64 > now() + MAX_FUTURE_SECS {
            return Err("timestamp too far in the future".into());
        }
        if height <= self.params.checkpoint_sunset {
            if let Some((_, want)) = self.params.checkpoints.iter().find(|(ch, _)| *ch == height) {
                if *want != hd.hash() {
                    return Err("conflicts with a release checkpoint".into());
                }
            }
        }
        Ok(())
    }

    /// Keep these blocks when they arrive: their headers were checked and add up to more
    /// work than the tip has, so the first of them must be held until the rest arrive.
    pub fn expect(&mut self, hashes: impl IntoIterator<Item = [u8; 32]>) {
        if self.wanted.len() > MAX_WANTED {
            self.wanted.clear();
        }
        self.wanted.extend(hashes.into_iter().filter(|h| !self.index.contains_key(h)).take(MAX_WANTED));
    }

    /// The entry of a block this node has, the times of the eleven blocks ending at it
    /// (oldest first), and its ASERT steady anchor (when `height >= launch_blocks`):
    /// everything `check_run` needs to check headers that follow it.
    pub fn header_base(
        &self,
        h: &[u8; 32],
    ) -> Option<(Entry, std::collections::VecDeque<u32>, Option<(u32, i64)>)> {
        let prev = self.index.get(h)?.clone();
        let steady_anchor = self.steady_anchor_for(&prev);
        let mut times = std::collections::VecDeque::new();
        let mut cur = Some(prev.hash);
        while let Some(x) = cur {
            if times.len() == 11 {
                break;
            }
            let e = &self.index[&x];
            times.push_front(e.time);
            cur = if e.height == 0 { None } else { Some(e.prev) };
        }
        Some((prev, times, steady_anchor))
    }

    /// Encoded size of a block this node holds.
    pub fn block_size(&self, h: &[u8; 32]) -> usize {
        self.sizes.get(h).map(|s| s.0).unwrap_or(0) as usize
    }

    /// Number of transactions in a block this node holds.
    pub fn block_txs(&self, h: &[u8; 32]) -> usize {
        self.sizes.get(h).map(|s| s.1).unwrap_or(0) as usize
    }

    /// Would this header be accepted on its parent? Lets the node check a block's proofs
    /// before taking its lock only for blocks that cost real work to make.
    pub fn header_ok(&self, b: &Block) -> bool {
        self.index.get(&b.header.prev).map(|p| self.check_header(b, p).is_ok()).unwrap_or(false)
    }

    /// Write every connected block that is not yet on disk, oldest first.
    fn persist_active(&mut self) -> Result<(), String> {
        if self.store.is_none() {
            return Ok(());
        }
        let fresh: Vec<[u8; 32]> = self.active.iter().rev().take_while(|h| !self.persisted.contains(*h)).copied().collect();
        for h in fresh.into_iter().rev() {
            let bytes = self.body(&h).ok_or("a connected block's body is missing")?.encode();
            let at = self.store.as_mut().unwrap().write(&bytes).map_err(|e| e.to_string())?;
            self.place.insert(h, Place { side: false, at, len: bytes.len() as u32 });
            self.persisted.insert(h);
        }
        Ok(())
    }

    /// Persist a cryptographically verified fast-boot snapshot (`state.snap`) of the current
    /// active tip and state, written atomically (`tmp` → `fsync` → `rename`).
    pub fn save_snapshot(&self) -> Result<(), String> {
        let dir = self.dir.as_ref().ok_or("in-memory chain has no directory")?;
        let store = self.store.as_ref().ok_or("no block store")?;
        if self.active.len() <= 1 {
            return Ok(());
        }
        let mut blocks = Vec::with_capacity(self.active.len() - 1);
        for h in self.active.iter().skip(1) {
            let entry = self.index.get(h).ok_or("missing active entry")?.clone();
            let (size, txs) = self.sizes.get(h).copied().unwrap_or((0, 0));
            let place = self.place.get(h).ok_or("active block not persisted in blocks.dat")?;
            if place.side {
                return Err("active block resides in side.dat".into());
            }
            blocks.push(crate::snapshot::BlockRecord {
                entry,
                size,
                txs,
                at: place.at,
                len: place.len,
            });
        }
        let tip_hash = self.tip().hash;
        let tip_digest = self.state.digest();
        let snap = crate::snapshot::ChainSnapshot {
            genesis: self.genesis,
            tip_hash,
            tip_digest,
            blocks_dat_end: store.end,
            blocks,
            state: self.state.clone(),
        };
        crate::snapshot::save_atomic(dir, &snap)
    }

    /// After a failed activation, move to the best chain that does validate.
    fn reconsider(&mut self) {
        loop {
            let tip_work = self.tip().work;
            let Some(c) = self.index.values().filter(|e| e.work > tip_work && !self.invalid.contains(&e.hash)).max_by_key(|e| e.work).map(|e| e.hash) else {
                return;
            };
            let before = self.invalid.len();
            if self.has_invalid_ancestor(&c) || self.activate(c).is_err() && self.invalid.len() == before {
                self.invalid.insert(c);
            }
            if self.tip().hash == c {
                return;
            }
        }
    }

    fn has_invalid_ancestor(&self, h: &[u8; 32]) -> bool {
        let mut cur = *h;
        while !self.is_active(&cur) {
            if self.invalid.contains(&cur) {
                return true;
            }
            cur = self.index[&cur].prev;
        }
        false
    }

    /// Hashes from `from` back to genesis: ten one by one, then doubling the step. A peer
    /// finds the last of these on its own chain and sends what follows.
    pub fn locator(&self, from: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut out = vec![];
        let mut cur = *from;
        let mut step = 1u32;
        while out.len() < 63 {
            out.push(cur);
            let e = &self.index[&cur];
            if e.height == 0 {
                return out;
            }
            if out.len() >= 10 {
                step = step.saturating_mul(2);
            }
            let target = e.height.saturating_sub(step);
            while self.index[&cur].height > target {
                cur = self.index[&cur].prev;
            }
        }
        out.push(self.genesis);
        out
    }

    /// Headers of the active chain after the first locator hash on it, each with its
    /// merged-mining proof if it has one: at most `max_bytes` of them and at most 2,000.
    pub fn headers_after(&self, locator: &[[u8; 32]], max_bytes: usize) -> Vec<Block> {
        let start = locator.iter().find(|h| self.is_active(h)).map(|h| self.index[h].height).unwrap_or(0);
        let mut out = vec![];
        let mut size = 0;
        for height in start + 1..=self.height() {
            let Some(h) = self.head(&self.active[height as usize]) else { break };
            let n = 80 + h.auxpow_bytes();
            if !out.is_empty() && (size + n > max_bytes || out.len() >= 2_000) {
                break;
            }
            size += n;
            out.push(h);
        }
        out
    }

    /// Check a run of headers (blocks without their transactions) that extends a block this
    /// node has: each links to the one before, carries the work its difficulty asks for,
    /// with the right difficulty, a time after the median of the eleven before it and not in
    /// the future, and agrees with the release checkpoints. Returns the total work and the
    /// height at the last header. Lets a node see that a peer's chain outweighs its own, at
    /// 80 bytes a block, before downloading the blocks.
    pub fn check_headers(&self, hs: &[Block]) -> Result<(U256, u32), String> {
        let first = hs.first().ok_or("no headers")?;
        let (prev, times, steady_anchor) = self.header_base(&first.header.prev).ok_or("unknown parent")?;
        let (tip, _, _) = check_run(&self.params, prev, times, steady_anchor, hs, now())?;
        Ok((tip.work, tip.height))
    }

    /// Blocks of the active chain after the first locator hash on it, at most `max_bytes`
    /// of them (always at least one if any follow) and at most 500.
    pub fn blocks_after(&self, locator: &[[u8; 32]], max_bytes: usize) -> Vec<Block> {
        let start = locator.iter().find(|h| self.is_active(h)).map(|h| self.index[h].height).unwrap_or(0);
        let mut out = vec![];
        let mut size = 0;
        for height in start + 1..=self.height() {
            let h = self.active[height as usize];
            let n = self.block_size(&h);
            if !out.is_empty() && (size + n > max_bytes || out.len() >= 500) {
                break;
            }
            let Some(b) = self.block(&h) else { break };
            size += n;
            out.push(b);
        }
        out
    }

    fn state_at(&self, h: &[u8; 32]) -> Result<State, String> {
        if let Some(s) = self.snapshots.get(h) {
            return Ok(s.clone());
        }
        // replay the active chain from genesis; these blocks were fully validated when
        // they were connected, so proofs need not be checked again
        let target = self.index[h].height;
        let mut st = State::new();
        for height in 0..=target {
            let b = self.body(&self.active[height as usize]).ok_or("a block's body is missing")?;
            st = st.apply(&b, &self.params, Checks { verify_proofs: false, check_commit: true })?;
        }
        Ok(st)
    }

    /// Validate and connect the branch ending at `new_tip`. If a block fails, it and its
    /// descendants are marked invalid, and the part of the branch that did validate is
    /// still connected when it has more work than the current tip.
    fn activate(&mut self, new_tip: [u8; 32]) -> Result<(), String> {
        let mut path = vec![];
        let mut cur = new_tip;
        while !self.is_active(&cur) {
            path.push(cur);
            cur = self.index[&cur].prev;
        }
        let fork = cur;
        path.reverse();
        let mut st = self.state_at(&fork)?;
        let mut new_snaps: Vec<([u8; 32], State)> = vec![];
        let mut failure = None;
        // blocks read back from this node's own blocks.dat were checked when they were
        // connected; their proofs are not checked again at every start
        let checks = if self.loading { Checks { verify_proofs: false, check_commit: true } } else { FULL };
        for bh in &path {
            let applied = match self.body(bh) {
                Some(b) => st.apply(&b, &self.params, checks),
                None => {
                    failure = Some(format!("block {}: its body is missing", crate::tx::hash_hex(bh)));
                    break;
                }
            };
            match applied {
                Ok(n) => {
                    st = n;
                    new_snaps.push((*bh, st.clone()));
                }
                Err(e) => {
                    let bad_height = self.index[bh].height;
                    let bad: Vec<_> = self.index.values().filter(|e| e.height >= bad_height).map(|e| e.hash).collect();
                    for x in bad {
                        if self.descends_from(&x, bh) {
                            self.invalid.insert(x);
                            // its header stays, to refuse what builds on it; its body goes
                            self.blocks.remove(&x);
                            self.sizes.remove(&x);
                            self.place.remove(&x);
                        }
                    }
                    failure = Some(format!("block {}: {e}", crate::tx::hash_hex(bh)));
                    break;
                }
            }
        }
        if let Some((last, last_state)) = new_snaps.last().cloned() {
            if self.index[&last].work > self.tip().work {
                let fork_height = self.index[&fork].height as usize;
                self.active.truncate(fork_height + 1);
                self.active.extend(path.iter().take(new_snaps.len()).copied());
                self.state = last_state;
                for (h, s) in new_snaps {
                    self.snapshots.insert(h, s);
                }
                let keep: HashSet<[u8; 32]> = self.active.iter().rev().take(SNAPSHOTS).copied().chain([self.genesis]).collect();
                self.snapshots.retain(|h, _| keep.contains(h));
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn descends_from(&self, x: &[u8; 32], anc: &[u8; 32]) -> bool {
        let target = self.index[anc].height;
        let mut cur = *x;
        loop {
            if &cur == anc {
                return true;
            }
            let e = &self.index[&cur];
            if e.height <= target {
                return false;
            }
            cur = e.prev;
        }
    }

    /// Build a block on the tip: coinbase first, then `txs`; fills the commitment.
    pub fn template(&self, coinbase_outs: Vec<PlainOut>, txs: Vec<Tx>, extra: Vec<u8>) -> Result<Block, String> {
        let tip = self.tip().hash;
        self.template_on(&tip, coinbase_outs, txs, extra)
    }

    /// Build a block on any known block (used to build competing branches in tests).
    pub fn template_on(&self, parent: &[u8; 32], coinbase_outs: Vec<PlainOut>, txs: Vec<Tx>, extra: Vec<u8>) -> Result<Block, String> {
        let parent = self.index.get(parent).cloned().ok_or("unknown parent")?;
        let base = if parent.hash == self.tip().hash { self.state.clone() } else { self.state_at_any(&parent.hash)? };
        let mut all = vec![Tx::Coinbase(Coinbase { height: parent.height + 1, outs: coinbase_outs, extra })];
        all.extend(txs);
        let time = (now() as u32).max(self.mtp(&parent.hash) + 1);
        let mut b = Block {
            header: Header { version: 1, prev: parent.hash, commit: [0; 32], time, bits: self.next_bits(&parent), nonce: 0 },
            auxpow: None,
            digest: [0; 32],
            txs: all,
        };
        let st = base.apply(&b, &self.params, Checks { verify_proofs: false, check_commit: false })?;
        b.digest = st.digest();
        b.header.commit = header_commit(&b.tx_root(), &b.digest);
        Ok(b)
    }

    /// State after any known block, active or not, by replay from genesis.
    pub fn state_at_any(&self, h: &[u8; 32]) -> Result<State, String> {
        if let Some(s) = self.snapshots.get(h) {
            return Ok(s.clone());
        }
        let mut path = vec![];
        let mut cur = *h;
        loop {
            path.push(cur);
            let e = &self.index[&cur];
            if e.height == 0 {
                break;
            }
            cur = e.prev;
        }
        path.reverse();
        let mut st = State::new();
        for bh in path {
            let b = self.body(&bh).ok_or("a block's body is missing")?;
            st = st.apply(&b, &self.params, Checks { verify_proofs: false, check_commit: true })?;
        }
        Ok(st)
    }
}
