//! Verified fast-boot disk state snapshots (`state.snap`).
//!
//! Avoids full genesis-to-tip state replay on node restart while preserving 100% trustless
//! cryptographic verification:
//! 1. Every snapshot file ends with a 32-byte SHA-256 checksum over its full header + payload.
//! 2. Snapshots are written atomically (`state.snap.tmp` → `fsync` → `rename`).
//! 3. On boot, `Chain::open` validates:
//!    - exact genesis hash match,
//!    - contiguous active header chain from genesis to `tip_hash`,
//!    - `tip_block` decoded from `blocks.dat` at its recorded offset matches `tip_hash` and `tip_digest`,
//!    - recomputed `state.digest() == tip_digest`.
//! 4. On any missing file, corruption, or digest mismatch, `Chain::open` transparently falls back
//!    to replaying `blocks.dat` from genesis.

use crate::chain::Entry;
use crate::channel::{Channel, ChannelEnd};
use crate::codec::{Reader, Res, Writer};
use crate::cond::{Cond, CondEnd};
use crate::hash::{sha256, Word8};
use crate::job::Job;
use crate::lock::{Lock, LockEnd};
use crate::merkmap::MerkleMap;
use crate::nftree::NfTree;
use crate::note::NoteTree;
use crate::state::State;
use crate::tx::PlainOut;
use primitive_types::U256;
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub const SNAPSHOT_FILE: &str = "state.snap";
pub const SNAPSHOT_INTERVAL: u32 = 50;
const SNAPSHOT_MAGIC: &[u8; 8] = b"nsSNAP01";
const MAX_SNAPSHOT_ITEMS: usize = 10_000_000;

/// Metadata for one active block (heights `1..=tip`) stored inside `blocks.dat`.
#[derive(Clone, Debug)]
pub struct BlockRecord {
    pub entry: Entry,
    pub size: u32,
    pub txs: u32,
    pub at: u64,
    pub len: u32,
}

#[derive(Clone, Debug)]
pub struct ChainSnapshot {
    pub genesis: [u8; 32],
    pub tip_hash: [u8; 32],
    pub tip_digest: [u8; 32],
    pub blocks_dat_end: u64,
    pub blocks: Vec<BlockRecord>,
    pub state: State,
}

fn write_u128(w: &mut Writer, v: u128) {
    w.raw(&v.to_le_bytes());
}

fn read_u128(r: &mut Reader) -> Res<u128> {
    Ok(u128::from_le_bytes(r.arr()?))
}

fn read_count(r: &mut Reader) -> Res<usize> {
    let n = r.u32()? as usize;
    if n > MAX_SNAPSHOT_ITEMS {
        return Err(format!("snapshot count {n} exceeds limit"));
    }
    Ok(n)
}

fn encode_state(st: &State, w: &mut Writer) {
    w.u32(st.height);
    w.bool(st.nf_committed);
    w.raw(&st.nf_acc);
    write_u128(w, st.issued);
    write_u128(w, st.burned);
    write_u128(w, st.locked);

    // NoteTree leaves (cm_pos is reconstructed deterministically on load)
    let note_leaves = st.tree.leaves();
    w.u32(note_leaves.len() as u32);
    for cm in &note_leaves {
        w.word8(cm);
    }

    // NfTree raw leaves (nullifiers set is reconstructed deterministically on load)
    let nf_leaves = st.nf_tree.raw_leaves();
    w.u32(nf_leaves.len() as u32);
    for (v, nxt) in &nf_leaves {
        w.word8(v).word8(nxt);
    }

    // Valid historical roots (anchors)
    w.u32(st.roots.len() as u32);
    for r in &st.roots {
        w.word8(r);
    }

    // Pending coinbase maturity queue
    w.u32(st.pending_coinbase.len() as u32);
    for (h, outs) in &st.pending_coinbase {
        w.u32(*h).u32(outs.len() as u32);
        for o in outs {
            w.word8(&o.a_pk).u64(o.v).rho(&o.rho);
        }
    }

    // Jobs
    w.u32(st.jobs.len() as u32);
    for j in st.jobs.values() {
        j.encode(w);
    }

    // Open locks
    w.u32(st.locks.len() as u32);
    for l in st.locks.values() {
        l.encode(w);
    }

    // Open conditions
    w.u32(st.conds.len() as u32);
    for c in st.conds.values() {
        c.encode(w);
    }

    // Open channels (channels_merkle is canonical & rebuilt on load)
    w.u32(st.channels.len() as u32);
    for ch in st.channels.values() {
        ch.encode(w);
    }

    // Public notes derived index
    w.u32(st.public_notes.len() as u32);
    for (a_pk, entries) in &st.public_notes {
        w.word8(a_pk).u32(entries.len() as u32);
        for (v, rho) in entries {
            w.u64(*v).rho(rho);
        }
    }

    // Lock ends + locks_by_hash
    w.u32(st.lock_ends.len() as u32);
    for (id, e) in &st.lock_ends {
        w.raw(id);
        e.lock.encode(w);
        w.u32(e.height);
        match &e.preimage {
            Some(p) => {
                w.bool(true).raw(p);
            }
            None => {
                w.bool(false);
            }
        }
    }
    w.u32(st.locks_by_hash.len() as u32);
    for (h, ids) in &st.locks_by_hash {
        w.raw(h).u32(ids.len() as u32);
        for id in ids {
            w.raw(id);
        }
    }

    // Condition ends
    w.u32(st.cond_ends.len() as u32);
    for (id, e) in &st.cond_ends {
        w.raw(id);
        e.cond.encode(w);
        w.u32(e.height);
        match &e.fulfilled {
            Some((payout, prog)) => {
                w.bool(true).u8(*payout).bytes(prog);
            }
            None => {
                w.bool(false);
            }
        }
    }

    // Channel ends + channels_by_tip
    w.u32(st.channel_ends.len() as u32);
    for (id, e) in &st.channel_ends {
        w.raw(id);
        e.channel.encode(w);
        w.u32(e.height);
        match &e.claimed {
            Some((ticks, token)) => {
                w.bool(true).u32(*ticks).raw(token);
            }
            None => {
                w.bool(false);
            }
        }
        w.u64(e.seller_paid).u64(e.buyer_refunded).u64(e.miner_fee);
    }
    w.u32(st.channels_by_tip.len() as u32);
    for (tip, ids) in &st.channels_by_tip {
        w.raw(tip).u32(ids.len() as u32);
        for id in ids {
            w.raw(id);
        }
    }
}

fn decode_state(r: &mut Reader) -> Res<State> {
    let height = r.u32()?;
    let nf_committed = r.bool()?;
    let nf_acc = r.arr()?;
    let issued = read_u128(r)?;
    let burned = read_u128(r)?;
    let locked = read_u128(r)?;

    // NoteTree + derived cm_pos
    let n_notes = read_count(r)?;
    let mut note_leaves = Vec::with_capacity(n_notes);
    let mut cm_pos: imbl::HashMap<Word8, Vec<u32>> = imbl::HashMap::new();
    for pos in 0..n_notes {
        let cm = r.word8()?;
        note_leaves.push(cm);
        cm_pos.entry(cm).or_default().push(pos as u32);
    }
    let tree = NoteTree::from_leaves(&note_leaves);

    // NfTree + derived nullifiers
    let n_nfs = read_count(r)?;
    let mut raw_nfs = Vec::with_capacity(n_nfs);
    let mut nullifiers: imbl::HashSet<Word8> = imbl::HashSet::new();
    for _ in 0..n_nfs {
        let v = r.word8()?;
        let nxt = r.word8()?;
        if v != [0u32; 8] {
            nullifiers.insert(v);
        }
        raw_nfs.push((v, nxt));
    }
    let nf_tree = NfTree::from_raw_leaves(raw_nfs)?;

    // Roots
    let n_roots = read_count(r)?;
    let mut roots = imbl::HashSet::new();
    for _ in 0..n_roots {
        roots.insert(r.word8()?);
    }

    // Pending coinbase
    let n_pending = read_count(r)?;
    let mut pending_coinbase = VecDeque::with_capacity(n_pending);
    for _ in 0..n_pending {
        let h = r.u32()?;
        let n_outs = read_count(r)?;
        let mut outs = Vec::with_capacity(n_outs);
        for _ in 0..n_outs {
            outs.push(PlainOut { a_pk: r.word8()?, v: r.u64()?, rho: r.rho()? });
        }
        pending_coinbase.push_back((h, outs));
    }

    // Jobs
    let n_jobs = read_count(r)?;
    let mut jobs = BTreeMap::new();
    for _ in 0..n_jobs {
        let j = Job::decode(r)?;
        jobs.insert(j.id, j);
    }

    // Open locks
    let n_locks = read_count(r)?;
    let mut locks = BTreeMap::new();
    for _ in 0..n_locks {
        let l = Lock::decode(r)?;
        locks.insert(l.id, l);
    }

    // Open conditions
    let n_conds = read_count(r)?;
    let mut conds = BTreeMap::new();
    for _ in 0..n_conds {
        let c = Cond::decode(r)?;
        conds.insert(c.id, c);
    }

    // Open channels + canonical MerkleMap
    let n_channels = read_count(r)?;
    let mut channels = imbl::OrdMap::new();
    let mut channels_merkle = MerkleMap::new();
    for _ in 0..n_channels {
        let ch = Channel::decode(r)?;
        channels_merkle.insert(ch.id, ch.value_hash());
        channels.insert(ch.id, ch);
    }

    // Public notes
    let n_pub = read_count(r)?;
    let mut public_notes: imbl::HashMap<Word8, Vec<(u64, crate::note::Rho)>> = imbl::HashMap::new();
    for _ in 0..n_pub {
        let a_pk = r.word8()?;
        let m = read_count(r)?;
        let mut list = Vec::with_capacity(m);
        for _ in 0..m {
            list.push((r.u64()?, r.rho()?));
        }
        public_notes.insert(a_pk, list);
    }

    // Lock ends + locks_by_hash
    let n_le = read_count(r)?;
    let mut lock_ends = imbl::HashMap::new();
    for _ in 0..n_le {
        let id = r.arr()?;
        let lock = Lock::decode(r)?;
        let h = r.u32()?;
        let preimage = if r.bool()? { Some(r.arr()?) } else { None };
        lock_ends.insert(id, LockEnd { lock, height: h, preimage });
    }
    let n_lbh = read_count(r)?;
    let mut locks_by_hash = imbl::HashMap::new();
    for _ in 0..n_lbh {
        let h = r.arr()?;
        let m = read_count(r)?;
        let mut ids = Vec::with_capacity(m);
        for _ in 0..m {
            ids.push(r.arr()?);
        }
        locks_by_hash.insert(h, ids);
    }

    // Condition ends
    let n_ce = read_count(r)?;
    let mut cond_ends = imbl::HashMap::new();
    for _ in 0..n_ce {
        let id = r.arr()?;
        let cond = Cond::decode(r)?;
        let h = r.u32()?;
        let fulfilled = if r.bool()? {
            let payout = r.u8()?;
            let prog = r.bytes(crate::script::MAX_PROGRAM)?;
            Some((payout, prog))
        } else {
            None
        };
        cond_ends.insert(id, CondEnd { cond, height: h, fulfilled });
    }

    // Channel ends + channels_by_tip
    let n_che = read_count(r)?;
    let mut channel_ends = imbl::HashMap::new();
    for _ in 0..n_che {
        let id = r.arr()?;
        let channel = Channel::decode(r)?;
        let h = r.u32()?;
        let claimed = if r.bool()? { Some((r.u32()?, r.arr()?)) } else { None };
        let seller_paid = r.u64()?;
        let buyer_refunded = r.u64()?;
        let miner_fee = r.u64()?;
        channel_ends.insert(
            id,
            ChannelEnd { channel, height: h, claimed, seller_paid, buyer_refunded, miner_fee },
        );
    }
    let n_cbt = read_count(r)?;
    let mut channels_by_tip = imbl::HashMap::new();
    for _ in 0..n_cbt {
        let tip = r.arr()?;
        let m = read_count(r)?;
        let mut ids = Vec::with_capacity(m);
        for _ in 0..m {
            ids.push(r.arr()?);
        }
        channels_by_tip.insert(tip, ids);
    }

    Ok(State {
        height,
        tree,
        cm_pos,
        nullifiers,
        nf_tree,
        nf_committed,
        roots,
        nf_acc,
        jobs,
        locks,
        pending_coinbase,
        issued,
        burned,
        locked,
        public_notes,
        lock_ends,
        conds,
        cond_ends,
        locks_by_hash,
        channels,
        channels_merkle,
        channel_ends,
        channels_by_tip,
    })
}

pub fn encode_snapshot(snap: &ChainSnapshot) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(SNAPSHOT_MAGIC);
    w.raw(&snap.genesis)
        .raw(&snap.tip_hash)
        .raw(&snap.tip_digest)
        .u64(snap.blocks_dat_end)
        .u32(snap.blocks.len() as u32);
    for rec in &snap.blocks {
        let mut work = [0u8; 32];
        rec.entry.work.to_big_endian(&mut work);
        w.raw(&rec.entry.hash)
            .raw(&rec.entry.prev)
            .u32(rec.entry.height)
            .u32(rec.entry.time)
            .u32(rec.entry.bits)
            .raw(&work)
            .u32(rec.size)
            .u32(rec.txs)
            .u64(rec.at)
            .u32(rec.len);
    }
    encode_state(&snap.state, &mut w);
    let mut chk_in = Vec::with_capacity(9 + w.0.len());
    chk_in.extend_from_slice(b"nsSNAPCHK");
    chk_in.extend_from_slice(&w.0);
    let checksum = sha256(&chk_in);
    w.raw(&checksum);
    w.0
}

pub fn decode_snapshot(bytes: &[u8], expected_genesis: &[u8; 32], blocks_dat_size: u64) -> Res<ChainSnapshot> {
    if bytes.len() < SNAPSHOT_MAGIC.len() + 32 {
        return Err("snapshot too short".into());
    }
    let (body, want_chk) = bytes.split_at(bytes.len() - 32);
    let mut chk_in = Vec::with_capacity(9 + body.len());
    chk_in.extend_from_slice(b"nsSNAPCHK");
    chk_in.extend_from_slice(body);
    if sha256(&chk_in) != want_chk {
        return Err("snapshot checksum mismatch".into());
    }
    let mut r = Reader::new(body);
    let magic = r.arr::<8>()?;
    if &magic != SNAPSHOT_MAGIC {
        return Err("bad snapshot magic".into());
    }
    let genesis = r.arr::<32>()?;
    if &genesis != expected_genesis {
        return Err("snapshot genesis mismatch".into());
    }
    let tip_hash = r.arr::<32>()?;
    let tip_digest = r.arr::<32>()?;
    let blocks_dat_end = r.u64()?;
    if blocks_dat_end > blocks_dat_size {
        return Err("snapshot extends beyond blocks.dat".into());
    }
    let n_blocks = read_count(&mut r)?;
    let mut blocks = Vec::with_capacity(n_blocks);
    let mut prev_hash = genesis;
    for i in 0..n_blocks {
        let hash = r.arr::<32>()?;
        let prev = r.arr::<32>()?;
        let height = r.u32()?;
        let time = r.u32()?;
        let bits = r.u32()?;
        let work = U256::from_big_endian(&r.arr::<32>()?);
        let size = r.u32()?;
        let txs = r.u32()?;
        let at = r.u64()?;
        let len = r.u32()?;
        if height != (i as u32) + 1 || prev != prev_hash {
            return Err("snapshot header chain discontinuity".into());
        }
        if at.checked_add(len as u64).is_none_or(|end| end > blocks_dat_end) {
            return Err("snapshot block offset out of bounds".into());
        }
        prev_hash = hash;
        blocks.push(BlockRecord {
            entry: Entry { hash, prev, height, time, bits, work },
            size,
            txs,
            at,
            len,
        });
    }
    if prev_hash != tip_hash {
        return Err("snapshot tip hash mismatch".into());
    }
    let state = decode_state(&mut r)?;
    r.finish()?;
    if state.height != n_blocks as u32 {
        return Err("snapshot height mismatch".into());
    }
    if state.digest() != tip_digest {
        return Err("snapshot state digest mismatch".into());
    }
    Ok(ChainSnapshot { genesis, tip_hash, tip_digest, blocks_dat_end, blocks, state })
}

/// Atomically persist `state.snap` (`state.snap.tmp` → `fsync` → `rename`).
pub fn save_atomic(dir: &Path, snap: &ChainSnapshot) -> Res<()> {
    let bytes = encode_snapshot(snap);
    let tmp = dir.join("state.snap.tmp");
    let dst = dir.join(SNAPSHOT_FILE);
    let mut f = File::create(&tmp).map_err(|e| format!("create snapshot tmp: {e}"))?;
    f.write_all(&bytes).map_err(|e| format!("write snapshot: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync snapshot: {e}"))?;
    drop(f);
    std::fs::rename(&tmp, &dst).map_err(|e| format!("rename snapshot: {e}"))?;
    Ok(())
}

/// Load and cryptographically verify `state.snap` if present.
pub fn load_verified(dir: &Path, expected_genesis: &[u8; 32], blocks_dat_size: u64) -> Option<Res<ChainSnapshot>> {
    let path = dir.join(SNAPSHOT_FILE);
    if !path.exists() {
        return None;
    }
    Some(
        std::fs::read(&path)
            .map_err(|e| format!("read snapshot: {e}"))
            .and_then(|bytes| decode_snapshot(&bytes, expected_genesis, blocks_dat_size)),
    )
}
