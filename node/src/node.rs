//! A full node: P2P gossip over TCP, a mempool ordered by fee rate, and an optional miner.
//!
//! Frame: magic(4) | kind(1) | length(4, LE) | payload. Kinds: 0 hello{height, tip},
//! 1 getblocks{locator}, 2 blocks{n × block}, 3 block, 4 tx. Each kind has its own size cap,
//! checked before any payload is read, and payloads are read as they arrive rather than
//! reserved up front. Every peer has its own writer thread and bounded queue, so a slow or
//! hostile peer stalls only itself, and proofs are verified outside the node's lock.
//!
//! What a stranger cannot do (tests/hostile.rs): hold a place without speaking (a peer says
//! hello within `HANDSHAKE_SECS` and is heard from every `IDLE_SECS`); take the places this
//! node keeps for peers it chooses itself (`MAX_INBOUND`); fill memory by asking and never
//! reading (queues are bounded in bytes, per peer and in all); send answers nobody asked
//! for; or keep sending what fails validation (`BAN_SCORE`).

use crate::chain::{mine, Chain};
use crate::codec::{Reader, Writer};
use crate::params::{min_relay_fee, subsidy, Params, TX_BYTES_CAP};
use crate::spend;
use crate::state::{State, NO_PROOFS};
use crate::peers::{self, AddrBook};
use crate::tx::{hash_hex, Block, PlainOut, Tx};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const MAX_LOCATOR: usize = 64;
/// Bytes of blocks sent in answer to one getblocks (at least one block is always sent).
const SYNC_BATCH_BYTES: usize = 8 << 20;
const MAX_SYNC_BLOCKS: usize = 500;
const MAX_PEERS: usize = 64;
/// Connections other nodes may make to this one. The rest are kept for the ones it makes
/// itself, so a crowd at the door cannot keep it from choosing its own peers.
const MAX_INBOUND: usize = 48;
/// Inbound connections from one public address.
pub const MAX_PER_IP: usize = 4;
/// A peer says hello within this long of connecting, and is heard from at least every
/// `IDLE_SECS` after: every node repeats its hello each `KEEPALIVE_SECS`.
const HANDSHAKE_SECS: u64 = 20;
const IDLE_SECS: u64 = 15 * 60;
pub const KEEPALIVE_SECS: u64 = 4 * 60;
/// A frame's payload arrives at this pace or better, after a grace period.
const MIN_BYTES_PER_SEC: usize = 8 * 1024;
const FRAME_GRACE_SECS: u64 = 30;
/// Bytes waiting to be written: to one peer (a sync batch, a block and change), and to all.
const PEER_QUEUE_BYTES: usize = SYNC_BATCH_BYTES + (12 << 20);
const TOTAL_QUEUE_BYTES: usize = 256 << 20;
/// A peer is dropped, and a public address refused for `BAN_SECS`, when what it sent has
/// failed validation this much: 50 for a block or a run of headers, 20 for a transaction.
const BAN_SCORE: u32 = 100;
const BAN_SECS: u64 = 10 * 60;
/// Headers followed from one peer before its chain must have outweighed ours.
const MAX_HEADER_RUN: usize = 50_000;
/// Mempool capacity, in blocks' worth of bytes.
const MEMPOOL_BLOCKS: usize = 4;
/// Room left in a template for the coinbase.
const COINBASE_ROOM: usize = 1_000;
const PEER_QUEUE: usize = 256;
/// Bytes of headers sent in answer to one getheaders.
const HEADERS_BYTES: usize = 4 << 20;

static PEERS: AtomicUsize = AtomicUsize::new(0);
static INBOUND: AtomicUsize = AtomicUsize::new(0);
/// Bytes queued for peers and not yet written.
static QUEUED: AtomicUsize = AtomicUsize::new(0);
static HANDSHAKE_MS: AtomicU64 = AtomicU64::new(HANDSHAKE_SECS * 1000);
static IDLE_MS: AtomicU64 = AtomicU64::new(IDLE_SECS * 1000);
/// Inbound connections by address, and addresses refused until a time.
static BY_IP: Mutex<Vec<(IpAddr, usize)>> = Mutex::new(Vec::new());
static BANNED: Mutex<Vec<(IpAddr, Instant)>> = Mutex::new(Vec::new());

/// For tests: how long a peer may take to say hello, and how long it may then stay silent.
pub fn set_timeouts(handshake: Duration, idle: Duration) {
    HANDSHAKE_MS.store(handshake.as_millis() as u64, Ordering::SeqCst);
    IDLE_MS.store(idle.as_millis() as u64, Ordering::SeqCst);
}

/// Bytes queued for peers and not yet written.
pub fn queued_bytes() -> usize {
    QUEUED.load(Ordering::SeqCst)
}

pub fn inbound_count() -> usize {
    INBOUND.load(Ordering::SeqCst)
}

fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// An address on the open internet: not this machine, not a private network. Peers that
/// arrive through a proxy on a private network share its address, so the limits by
/// address apply only to public ones.
pub fn is_public(ip: IpAddr) -> bool {
    match plain(ip) {
        IpAddr::V4(a) => !(a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified()),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// Take one more inbound connection from `ip`? Not while it is banned, and from a public
/// address only `MAX_PER_IP` at a time. A yes is counted until `release_inbound`.
pub fn admit_inbound(ip: IpAddr) -> bool {
    let ip = plain(ip);
    let now = Instant::now();
    {
        let mut b = BANNED.lock().unwrap_or_else(|e| e.into_inner());
        b.retain(|(_, until)| *until > now);
        if b.iter().any(|(x, _)| *x == ip) {
            return false;
        }
    }
    let mut m = BY_IP.lock().unwrap_or_else(|e| e.into_inner());
    let have = m.iter().find(|(x, _)| *x == ip).map(|(_, n)| *n).unwrap_or(0);
    if is_public(ip) && have >= MAX_PER_IP {
        return false;
    }
    match m.iter_mut().find(|(x, _)| *x == ip) {
        Some(e) => e.1 += 1,
        None => m.push((ip, 1)),
    }
    true
}

pub fn release_inbound(ip: IpAddr) {
    let ip = plain(ip);
    let mut m = BY_IP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = m.iter().position(|(x, _)| *x == ip) {
        m[i].1 -= 1;
        if m[i].1 == 0 {
            m.swap_remove(i);
        }
    }
}

/// Refuse a public address for a while.
pub fn ban(ip: IpAddr, secs: u64) {
    if is_public(ip) {
        BANNED.lock().unwrap_or_else(|e| e.into_inner()).push((plain(ip), Instant::now() + Duration::from_secs(secs)));
    }
}

pub enum Msg {
    Hello { height: u32, tip: [u8; 32] },
    GetBlocks { locator: Vec<[u8; 32]> },
    Blocks(Vec<Block>),
    Block(Block),
    Tx(Tx),
    /// The sender listens on `port` (at `ext`, if it gave one); `nonce` is the sender's,
    /// so a node that dialled itself can tell.
    Listen { port: u32, nonce: u64, ext: String },
    GetAddr,
    Addr(Vec<String>),
    /// Headers first: a peer's chain is weighed from its headers before its blocks are
    /// fetched. `Headers` carries blocks with no transactions.
    GetHeaders { locator: Vec<[u8; 32]> },
    Headers(Vec<Block>),
}

impl Msg {
    pub fn encode(&self, magic: [u8; 4]) -> Vec<u8> {
        let mut p = Writer::new();
        let kind = match self {
            Msg::Hello { height, tip } => {
                p.u32(*height).raw(tip);
                0
            }
            Msg::GetBlocks { locator } => {
                p.u32(locator.len() as u32);
                for h in locator {
                    p.raw(h);
                }
                1
            }
            Msg::Blocks(bs) => {
                p.u32(bs.len() as u32);
                for b in bs {
                    p.bytes(&b.encode());
                }
                2
            }
            Msg::Block(b) => {
                p.raw(&b.encode());
                3
            }
            Msg::Tx(t) => {
                p.raw(&t.to_bytes());
                4
            }
            Msg::Listen { port, nonce, ext } => {
                p.u32(*port).u64(*nonce).bytes(ext.as_bytes());
                5
            }
            Msg::GetAddr => 6,
            Msg::Addr(v) => {
                p.u32(v.len() as u32);
                for a in v {
                    p.bytes(a.as_bytes());
                }
                7
            }
            Msg::GetHeaders { locator } => {
                p.u32(locator.len() as u32);
                for h in locator {
                    p.raw(h);
                }
                8
            }
            Msg::Headers(hs) => {
                p.u32(hs.len() as u32);
                for b in hs {
                    p.bytes(&b.encode());
                }
                9
            }
        };
        let mut out = magic.to_vec();
        out.push(kind);
        out.extend_from_slice(&(p.0.len() as u32).to_le_bytes());
        out.extend_from_slice(&p.0);
        out
    }

    /// Largest payload accepted for each kind of message.
    fn cap(kind: u8, max_block: usize) -> usize {
        match kind {
            0 => 36,
            1 => 4 + 32 * MAX_LOCATOR,
            2 => 4 + SYNC_BATCH_BYTES + max_block + 4 * MAX_SYNC_BLOCKS,
            3 => max_block,
            4 => TX_BYTES_CAP,
            5 => 16 + peers::MAX_ADDR_LEN,
            6 => 0,
            7 => 4 + peers::MAX_ADDR_SEND * (4 + peers::MAX_ADDR_LEN),
            8 => 4 + 32 * MAX_LOCATOR,
            9 => 4 + HEADERS_BYTES + crate::auxpow::MAX_AUXPOW_BYTES + 100 + 2_000 * 8,
            _ => 0,
        }
    }

    pub fn read(s: &mut TcpStream, magic: [u8; 4], max_block: usize) -> Result<Msg, String> {
        Self::read_asked(s, magic, max_block, None, true, true)
    }

    /// Read one message. The peer may stay silent for `wait` before it starts (forever, if
    /// none). `blocks` and `headers` say whether a batch of blocks, or of headers, has been
    /// asked for: one that was not is refused before its payload is read.
    pub fn read_asked(s: &mut TcpStream, magic: [u8; 4], max_block: usize, wait: Option<Duration>, blocks: bool, headers: bool) -> Result<Msg, String> {
        let mut h = [0u8; 9];
        s.set_read_timeout(wait).ok();
        s.read_exact(&mut h).map_err(|e| e.to_string())?;
        if h[..4] != magic {
            return Err("wrong network".into());
        }
        if (h[4] == 2 && !blocks) || (h[4] == 9 && !headers) {
            return Err("an answer nobody asked for".into());
        }
        let n = u32::from_le_bytes(h[5..9].try_into().unwrap()) as usize;
        if n > Self::cap(h[4], max_block) {
            return Err("frame too large".into());
        }
        // the payload is read as it arrives, and has to keep a minimum pace
        let deadline = Instant::now() + Duration::from_secs(FRAME_GRACE_SECS + (n / MIN_BYTES_PER_SEC) as u64);
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; n.clamp(1, 64 * 1024)];
        while buf.len() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("frame too slow".into());
            }
            s.set_read_timeout(Some(left.min(Duration::from_secs(FRAME_GRACE_SECS)))).ok();
            let want = (n - buf.len()).min(chunk.len());
            let got = s.read(&mut chunk[..want]).map_err(|e| e.to_string())?;
            if got == 0 {
                return Err("connection closed mid-frame".into());
            }
            buf.extend_from_slice(&chunk[..got]);
        }
        s.set_read_timeout(None).ok();
        let mut r = Reader::new(&buf);
        let m = match h[4] {
            0 => Msg::Hello { height: r.u32()?, tip: r.arr()? },
            1 => {
                let k = r.u32()? as usize;
                if k == 0 || k > MAX_LOCATOR {
                    return Err("bad locator".into());
                }
                Msg::GetBlocks { locator: (0..k).map(|_| r.arr()).collect::<Result<_, _>>()? }
            }
            2 => {
                let k = r.u32()? as usize;
                if k > MAX_SYNC_BLOCKS {
                    return Err("too many blocks".into());
                }
                let mut v = Vec::with_capacity(k.min(r.remaining() / 88));
                for _ in 0..k {
                    v.push(Block::decode(&r.bytes(max_block)?)?);
                }
                Msg::Blocks(v)
            }
            3 => return Ok(Msg::Block(Block::decode(&buf)?)),
            4 => return Ok(Msg::Tx(Tx::from_bytes(&buf)?)),
            5 => Msg::Listen { port: r.u32()?, nonce: r.u64()?, ext: String::from_utf8(r.bytes(peers::MAX_ADDR_LEN)?).map_err(|_| "bad address")? },
            6 => Msg::GetAddr,
            7 => {
                let k = r.u32()? as usize;
                if k > peers::MAX_ADDR_SEND {
                    return Err("too many addresses".into());
                }
                let mut v = Vec::with_capacity(k);
                for _ in 0..k {
                    v.push(String::from_utf8(r.bytes(peers::MAX_ADDR_LEN)?).map_err(|_| "bad address")?);
                }
                Msg::Addr(v)
            }
            8 => {
                let k = r.u32()? as usize;
                if k == 0 || k > MAX_LOCATOR {
                    return Err("bad locator".into());
                }
                Msg::GetHeaders { locator: (0..k).map(|_| r.arr()).collect::<Result<_, _>>()? }
            }
            9 => {
                let k = r.u32()? as usize;
                if k > 2_000 {
                    return Err("too many headers".into());
                }
                let mut v = Vec::with_capacity(k.min(r.remaining() / 88));
                for _ in 0..k {
                    let b = Block::decode(&r.bytes(80 + crate::auxpow::MAX_AUXPOW_BYTES + 8)?)?;
                    if !b.txs.is_empty() {
                        return Err("a header with transactions".into());
                    }
                    v.push(b);
                }
                Msg::Headers(v)
            }
            _ => return Err("unknown message".into()),
        };
        r.finish()?;
        Ok(m)
    }
}

struct PoolEntry {
    tx: Tx,
    id: [u8; 32],
    size: usize,
    fee: u64,
    seq: u64,
}

impl PoolEntry {
    fn is_spend(&self) -> bool {
        matches!(self.tx, Tx::Spend(_))
    }
    /// Does `self` pay a strictly lower fee per byte than `other`?
    fn cheaper_than(&self, other: &PoolEntry) -> bool {
        (self.fee as u128) * (other.size as u128) < (other.fee as u128) * (self.size as u128)
    }
}

/// The way out to one peer: its queue, how many bytes wait in it, and its socket, closed
/// when the node lets the peer go.
struct PeerOut {
    tx: SyncSender<Arc<Vec<u8>>>,
    queued: Arc<AtomicUsize>,
    sock: Option<TcpStream>,
}

impl Drop for PeerOut {
    fn drop(&mut self) {
        if let Some(s) = &self.sock {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl PeerOut {
    /// Queue `bytes`; false if the peer is too far behind to be kept.
    fn push(&self, bytes: Arc<Vec<u8>>) -> bool {
        let n = bytes.len();
        let waiting = self.queued.load(Ordering::SeqCst);
        if (waiting > 0 && waiting + n > PEER_QUEUE_BYTES) || QUEUED.load(Ordering::SeqCst) + n > TOTAL_QUEUE_BYTES {
            return false;
        }
        self.queued.fetch_add(n, Ordering::SeqCst);
        QUEUED.fetch_add(n, Ordering::SeqCst);
        if self.tx.try_send(bytes).is_err() {
            self.queued.fetch_sub(n, Ordering::SeqCst);
            QUEUED.fetch_sub(n, Ordering::SeqCst);
            return false;
        }
        true
    }
}

pub struct Node {
    pub chain: Chain,
    /// Admitted transactions, in admission order.
    pool: Vec<PoolEntry>,
    /// The tip's state, opened for the next block, with every pooled transaction applied.
    pool_state: State,
    pool_bytes: usize,
    seq: u64,
    peers: HashMap<u64, PeerOut>,
    pub log: bool,
    /// Addresses of other nodes, and those this node is connected to by its own dialling.
    pub book: AddrBook,
    pub outbound: HashSet<String>,
    /// This node's listening port and the address it gives others, if any; and a random
    /// number that lets it recognise itself on the other end of a connection.
    pub listen_port: Option<u16>,
    pub external: String,
    nonce: u64,
    /// The highest valid header a peer has shown, for reporting sync progress.
    pub best_header: u32,
}

pub type Shared = Arc<Mutex<Node>>;

/// Take the node's lock even if a thread once panicked while holding it.
pub fn lock(shared: &Shared) -> MutexGuard<'_, Node> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

fn say(n: &Node, s: String) {
    if n.log {
        println!("{s}");
    }
}

impl Node {
    pub fn new(chain: Chain) -> Shared {
        let mut n = Node {
            chain,
            pool: vec![],
            pool_state: State::new(),
            pool_bytes: 0,
            seq: 0,
            peers: HashMap::new(),
            log: true,
            book: AddrBook::default(),
            outbound: HashSet::new(),
            listen_port: None,
            external: String::new(),
            nonce: rand::thread_rng().gen(),
            best_header: 0,
        };
        n.pool_state = n.fresh_pool_state();
        Arc::new(Mutex::new(n))
    }

    fn magic(&self) -> [u8; 4] {
        self.chain.params.magic
    }

    fn next_height(&self) -> u32 {
        self.chain.height() + 1
    }

    fn fresh_pool_state(&self) -> State {
        let mut st = self.chain.state.clone();
        st.begin_block(self.next_height(), &self.chain.params);
        st
    }

    /// The pooled transactions, in admission order.
    pub fn mempool(&self) -> Vec<Tx> {
        self.pool.iter().map(|e| e.tx.clone()).collect()
    }

    pub fn mempool_len(&self) -> usize {
        self.pool.len()
    }

    fn send(&mut self, id: u64, m: &Msg) {
        let bytes = Arc::new(m.encode(self.magic()));
        if let Some(p) = self.peers.get(&id) {
            if !p.push(bytes) {
                self.peers.remove(&id);
            }
        }
    }

    /// Bytes waiting to be written to one peer.
    fn waiting(&self, id: u64) -> usize {
        self.peers.get(&id).map(|p| p.queued.load(Ordering::SeqCst)).unwrap_or(0)
    }

    fn broadcast(&mut self, m: &Msg, except: Option<u64>) {
        let bytes = Arc::new(m.encode(self.magic()));
        let mut dead = vec![];
        for (id, p) in &self.peers {
            if Some(*id) != except && !p.push(bytes.clone()) {
                dead.push(*id);
            }
        }
        for id in dead {
            self.peers.remove(&id);
        }
    }

    /// Checks that need no chain state, including the proof. Run outside the lock.
    pub fn precheck(tx: &Tx, params: &Params) -> Result<(), String> {
        let size = tx.to_bytes().len();
        if size > params.max_tx_bytes {
            return Err("transaction too large".into());
        }
        match tx {
            Tx::Coinbase(_) => Err("coinbase outside a block".into()),
            Tx::Spend(sp) => {
                if sp.fee < min_relay_fee(size) {
                    return Err(format!("fee {} below the minimum relay fee {} for {size} bytes", sp.fee, min_relay_fee(size)));
                }
                spend::verify_bytes_cached(&params.proof, &sp.public()?, &sp.proof)
            }
            Tx::Act(_) => Ok(()),
        }
    }

    /// A transaction from outside the peer network (the wallet API), its `precheck`
    /// already passed: pooled, and announced to every peer if new.
    pub fn submit_local(&mut self, tx: Tx) -> Result<bool, String> {
        let added = self.admit(tx.clone())?;
        if added {
            self.broadcast(&Msg::Tx(tx), None);
        }
        Ok(added)
    }

    /// Transactions waiting in the pool, in admission order.
    pub fn pool_txs(&self) -> impl Iterator<Item = &Tx> {
        self.pool.iter().map(|e| &e.tx)
    }

    /// Nullifiers spent by transactions waiting in the pool.
    pub fn pool_nullifiers(&self) -> &imbl::HashSet<crate::hash::Word8> {
        &self.pool_state.nullifiers
    }

    /// The tip's state with every pooled transaction applied: what the next block would
    /// see. Locks made or released by waiting transactions show here first.
    pub fn pool_state(&self) -> &State {
        &self.pool_state
    }

    /// Check a transaction in full and admit it. Ok(false): already pooled.
    pub fn accept_tx(&mut self, tx: Tx) -> Result<bool, String> {
        Self::precheck(&tx, &self.chain.params)?;
        self.admit(tx)
    }

    /// Admit a transaction whose `precheck` passed: it must apply on top of the tip and
    /// everything already pooled. When the pool is full, cheaper spends make room; actions
    /// (which carry deadlines) outrank spends, and channel claims/expires carry their
    /// pre-funded `claim_fee` for fee-rate prioritization and miner coinbase payouts.
    fn admit(&mut self, tx: Tx) -> Result<bool, String> {
        let id = tx.id();
        if self.pool.iter().any(|e| e.id == id) {
            return Ok(false);
        }
        let size = tx.to_bytes().len();
        let fee = match &tx {
            Tx::Spend(s) => s.fee,
            Tx::Act(crate::job::Action::ChannelClaim { channel, .. })
            | Tx::Act(crate::job::Action::ChannelExpire { channel }) => {
                self.pool_state.channels.get(channel).map(|c| c.post.claim_fee).unwrap_or(0)
            }
            Tx::Act(crate::job::Action::BondAttest { fee, .. }) => *fee,
            Tx::Act(crate::job::Action::BondSlashEquivocation { miner_fee, .. })
            | Tx::Act(crate::job::Action::BondSlashQuorum { miner_fee, .. })
            | Tx::Act(crate::job::Action::BondUnbondComplete { miner_fee, .. })
            | Tx::Act(crate::job::Action::RollupWithdraw { miner_fee, .. })
            | Tx::Act(crate::job::Action::MissionClaimTask { miner_fee, .. })
            | Tx::Act(crate::job::Action::MissionCurveRedeem { miner_fee, .. }) => *miner_fee,
            Tx::Act(crate::job::Action::RollupBatch { batch_fee, .. }) => *batch_fee,
            _ => 0,
        };
        let mut new = PoolEntry { tx, id, size, fee, seq: self.seq };
        let cap = MEMPOOL_BLOCKS * self.chain.params.max_block_bytes;
        let mut victims = vec![];
        let mut room = cap.saturating_sub(self.pool_bytes);
        while room < size {
            let cheapest = self
                .pool
                .iter()
                .enumerate()
                .filter(|(i, e)| e.is_spend() && !victims.contains(i))
                .min_by(|a, b| if a.1.cheaper_than(b.1) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater });
            match cheapest {
                Some((i, e)) if !new.is_spend() || e.cheaper_than(&new) => {
                    room += e.size;
                    victims.push(i);
                }
                _ => return Err("mempool full".into()),
            }
        }
        let h = self.next_height();
        let admit_checks = crate::state::Checks {
            verify_proofs: matches!(&new.tx, Tx::Act(crate::job::Action::RollupBatch { .. })),
            check_commit: false,
        };
        let applied_fee = self.pool_state.apply_tx(&new.tx, h, &self.chain.params, admit_checks)?;
        new.fee = applied_fee;
        self.seq += 1;
        self.pool_bytes += size;
        self.pool.push(new);
        if !victims.is_empty() {
            victims.sort_unstable();
            for i in victims.into_iter().rev() {
                self.pool.remove(i);
            }
            self.rebuild_pool();
        }
        Ok(true)
    }

    /// Re-apply the pool on the current tip, dropping whatever no longer applies.
    fn rebuild_pool(&mut self) {
        let mut st = self.fresh_pool_state();
        let h = self.next_height();
        let old = std::mem::take(&mut self.pool);
        self.pool_bytes = 0;
        for mut e in old {
            if let Ok(applied_fee) = st.apply_tx(&e.tx, h, &self.chain.params, NO_PROOFS) {
                e.fee = applied_fee;
                self.pool_bytes += e.size;
                self.pool.push(e);
            }
        }
        self.pool_state = st;
    }

    /// Transactions for the next block: deadline actions first (fee-bearing channel claims
    /// and expires ordered by fee rate ahead of zero-fee actions, tie-broken by arrival),
    /// then spends by fee rate. Enforces both block byte budget and `MAX_BLOCK_CHANNEL_HASHES`.
    /// Anything that does not apply yet is retried after the rest, so an action can follow
    /// the deposit it depends on.
    pub fn select(&self) -> Vec<Tx> {
        self.select_with_fees().0
    }

    /// Like `select()`, also returning the exact sum of consensus fees (including pre-funded
    /// `ChannelClaim` and `ChannelExpire` miner fees) earned by the selected transactions.
    pub fn select_with_fees(&self) -> (Vec<Tx>, u64) {
        let h = self.next_height();
        let mut st = self.fresh_pool_state();
        let mut order: Vec<&PoolEntry> = self.pool.iter().collect();
        order.sort_by(|a, b| match (a.is_spend(), b.is_spend()) {
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
            (false, false) => {
                if b.cheaper_than(a) {
                    std::cmp::Ordering::Less
                } else if a.cheaper_than(b) {
                    std::cmp::Ordering::Greater
                } else {
                    a.seq.cmp(&b.seq)
                }
            }
            (true, true) => {
                if b.cheaper_than(a) {
                    std::cmp::Ordering::Less
                } else if a.cheaper_than(b) {
                    std::cmp::Ordering::Greater
                } else {
                    a.seq.cmp(&b.seq)
                }
            }
        });
        let budget = self.chain.params.max_block_bytes.saturating_sub(crate::tx::BLOCK_OVERHEAD + COINBASE_ROOM);
        let mut size = 0;
        let mut channel_hashes: u64 = 0;
        let mut total_fees: u64 = 0;
        let mut out = vec![];
        loop {
            let mut progress = false;
            let mut rest = vec![];
            for e in order {
                if size + 4 + e.size > budget {
                    continue;
                }
                let tx_hashes = match &e.tx {
                    Tx::Act(crate::job::Action::ChannelClaim { ticks, .. }) => *ticks as u64,
                    _ => 0,
                };
                if channel_hashes.saturating_add(tx_hashes) > crate::channel::MAX_BLOCK_CHANNEL_HASHES {
                    continue;
                }
                if let Ok(tx_fee) = st.apply_tx(&e.tx, h, &self.chain.params, NO_PROOFS) {
                    size += 4 + e.size;
                    channel_hashes += tx_hashes;
                    total_fees = total_fees.saturating_add(tx_fee);
                    out.push(e.tx.clone());
                    progress = true;
                } else {
                    rest.push(e);
                }
            }
            if !progress || rest.is_empty() {
                return (out, total_fees);
            }
            order = rest;
        }
    }

    /// Hand a block to the chain. Whatever the outcome, if the tip moved the pool is
    /// re-checked and the new tip announced.
    pub fn accept_block(&mut self, b: Block, from: Option<u64>) -> Result<bool, String> {
        let old_tip = self.chain.tip().hash;
        let res = self.chain.add_block(b);
        let tip = self.chain.tip().hash;
        if tip != old_tip {
            let txs = self.chain.block(&tip).map(|b| b.txs.len()).unwrap_or(0);
            say(self, format!("tip {} height {} txs {}", hash_hex(&tip), self.chain.height(), txs));
            self.rebuild_pool();
            if let Some(tb) = self.chain.block(&tip) {
                self.broadcast(&Msg::Block(tb), from);
            }
        }
        res
    }

    fn hello(&self) -> Msg {
        Msg::Hello { height: self.chain.height(), tip: self.chain.tip().hash }
    }
}

/// Check the proofs of blocks that are about to be connected, before the lock is taken, so
/// that validating them under the lock finds them in the verified cache. Only blocks whose
/// headers follow from a block this node has, and which would outweigh its tip, are
/// checked: making one costs all the work the chain has behind it.
fn prewarm(shared: &Shared, blocks: &[Block]) {
    let Some(first) = blocks.first() else { return };
    let (params, base, tip_work) = {
        let n = lock(shared);
        let Some(base) = n.chain.header_base(&first.header.prev) else { return };
        (n.chain.params.clone(), base, n.chain.tip().work)
    };
    let (mut prev, mut times) = base;
    let now = crate::chain::now();
    for b in blocks {
        match crate::chain::check_run(&params, prev, times, std::slice::from_ref(b), now) {
            Ok((e, t)) => {
                prev = e;
                times = t;
            }
            Err(_) => return,
        }
        if prev.work <= tip_work || !b.bound() {
            continue;
        }
        for t in &b.txs {
            if let Tx::Spend(sp) = t {
                if let Ok(pi) = sp.public() {
                    let _ = spend::verify_bytes_cached(&params.proof, &pi, &sp.proof);
                }
            }
        }
    }
}

struct PeerSlot {
    inbound: bool,
    /// The address an inbound connection was counted under.
    counted: Option<IpAddr>,
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        PEERS.fetch_sub(1, Ordering::SeqCst);
        if self.inbound {
            INBOUND.fetch_sub(1, Ordering::SeqCst);
        }
        if let Some(ip) = self.counted {
            release_inbound(ip);
        }
    }
}

/// Headers a peer is showing that do not yet outweigh this node's tip.
struct HeaderRun {
    fork: [u8; 32],
    last: crate::chain::Entry,
    times: std::collections::VecDeque<u32>,
    hashes: Vec<[u8; 32]>,
}

/// What a block that failed costs the peer that sent it. Nothing, where honest nodes can
/// differ: a parent this node lacks, a lighter chain, a clock ahead of this one.
fn block_penalty(e: &str) -> u32 {
    if e == "unknown parent" || e == crate::chain::NOT_HEAVIER || e.contains("too far in the future") {
        0
    } else {
        50
    }
}

/// Serve one connection. `dialled` is the address this node dialled to make it, if it did;
/// `counted` the address an inbound one was admitted under.
fn handle_peer(shared: Shared, mut s: TcpStream, id: u64, dialled: Option<String>, inbound: bool, counted: Option<IpAddr>) {
    let _slot = PeerSlot { inbound, counted };
    let remote = s.peer_addr().ok();
    let (magic, max_block, params) = {
        let n = lock(&shared);
        (n.magic(), n.chain.params.max_block_bytes, n.chain.params.clone())
    };
    let (tx, rx) = sync_channel::<Arc<Vec<u8>>>(PEER_QUEUE);
    let Ok(mut w) = s.try_clone() else {
        return;
    };
    let queued = Arc::new(AtomicUsize::new(0));
    let waiting = queued.clone();
    // a peer that stops reading is let go: each write makes progress or the link is closed
    w.set_write_timeout(Some(Duration::from_secs(60))).ok();
    thread::spawn(move || {
        let mut alive = true;
        for m in rx {
            if alive && w.write_all(&m).is_err() {
                alive = false;
                let _ = w.shutdown(Shutdown::Both);
            }
            waiting.fetch_sub(m.len(), Ordering::SeqCst);
            QUEUED.fetch_sub(m.len(), Ordering::SeqCst);
        }
        let _ = w.shutdown(Shutdown::Both);
    });
    {
        let mut n = lock(&shared);
        n.peers.insert(id, PeerOut { tx, queued, sock: s.try_clone().ok() });
        let hello = n.hello();
        n.send(id, &hello);
        if let Some(port) = n.listen_port {
            let m = Msg::Listen { port: port as u32, nonce: n.nonce, ext: n.external.clone() };
            n.send(id, &m);
        }
        n.send(id, &Msg::GetAddr);
    }
    let connected = Instant::now();
    let mut answered_getaddr = false;
    let mut said_hello = false;
    // the last block this peer gave us: sync continues from there, so a fork longer than
    // one batch is followed to its end rather than restarted
    let mut last_recv: Option<[u8; 32]> = None;
    // answers this node is waiting for; one that was not asked for ends the connection
    let (mut asked_blocks, mut asked_headers) = (false, false);
    let mut run: Option<HeaderRun> = None;
    let mut score = 0u32;
    loop {
        if score >= BAN_SCORE {
            if let Some(r) = remote {
                ban(r.ip(), BAN_SECS);
            }
            break;
        }
        // hello comes within the handshake time; after it, the peer is heard from now and then
        let wait = if said_hello {
            Duration::from_millis(IDLE_MS.load(Ordering::SeqCst))
        } else {
            let left = Duration::from_millis(HANDSHAKE_MS.load(Ordering::SeqCst)).saturating_sub(connected.elapsed());
            if left.is_zero() {
                break;
            }
            left
        };
        let m = match Msg::read_asked(&mut s, magic, max_block, Some(wait), asked_blocks, asked_headers) {
            Ok(m) => m,
            Err(_) => break,
        };
        match m {
            Msg::Listen { port, nonce, ext } => {
                let mut n = lock(&shared);
                if nonce == n.nonce {
                    // this node, on the other end of a connection it made itself
                    if let Some(a) = &dialled {
                        n.book.is_self(a);
                    }
                    if let Some(r) = remote {
                        n.book.is_self(&peers::listen_addr(r, port as u16));
                    }
                    if !n.external.is_empty() {
                        let e = n.external.clone();
                        n.book.is_self(&e);
                    }
                    break;
                }
                if port > 0 && port <= u16::MAX as u32 {
                    let at = if peers::valid(&ext) { ext } else { remote.map(|r| peers::listen_addr(r, port as u16)).unwrap_or_default() };
                    n.book.good(&at);
                }
            }
            Msg::GetAddr => {
                if !answered_getaddr {
                    answered_getaddr = true;
                    let mut n = lock(&shared);
                    let sample = n.book.sample(peers::MAX_ADDR_SEND);
                    n.send(id, &Msg::Addr(sample));
                }
            }
            Msg::Addr(v) => {
                let mut n = lock(&shared);
                for a in v.iter().take(peers::MAX_ADDR_TAKE) {
                    n.book.heard(a);
                }
            }
            Msg::Hello { height, tip } => {
                let mut n = lock(&shared);
                if !said_hello {
                    said_hello = true;
                    if let Some(a) = &dialled {
                        n.book.good(a);
                    }
                }
                if !n.chain.has(&tip) && height >= n.chain.height() {
                    // continue a side branch this peer is feeding us; otherwise weigh its
                    // chain by its headers first
                    match last_recv {
                        Some(h) if n.chain.has(&h) && !n.chain.is_active(&h) => {
                            let locator = n.chain.locator(&h);
                            n.send(id, &Msg::GetBlocks { locator });
                            asked_blocks = true;
                        }
                        _ => {
                            let locator = n.chain.locator(&n.chain.tip().hash);
                            n.send(id, &Msg::GetHeaders { locator });
                            asked_headers = true;
                        }
                    }
                }
            }
            Msg::GetHeaders { locator } => {
                let mut n = lock(&shared);
                // one answer at a time: a peer that has not read the last one waits
                if n.waiting(id) > HEADERS_BYTES {
                    continue;
                }
                let hs = n.chain.headers_after(&locator, HEADERS_BYTES);
                n.send(id, &Msg::Headers(hs));
            }
            Msg::Headers(hs) => {
                asked_headers = false;
                let Some(first) = hs.first() else {
                    run = None;
                    continue;
                };
                let mut n = lock(&shared);
                // these continue the run this peer was showing, or start at a block this
                // node has
                let (prev, times, fork, mut hashes) = match run.take() {
                    Some(r) if r.last.hash == first.header.prev => (r.last, r.times, r.fork, r.hashes),
                    _ => match n.chain.header_base(&first.header.prev) {
                        Some((e, t)) => (e, t, first.header.prev, vec![]),
                        None => continue,
                    },
                };
                match crate::chain::check_run(&n.chain.params, prev, times, &hs, crate::chain::now()) {
                    Ok((last, times)) => {
                        hashes.extend(hs.iter().map(|b| b.hash()));
                        if last.work > n.chain.tip().work {
                            // heavier than ours: fetch its blocks, which are kept as they
                            // come though the first of them do not yet outweigh the tip
                            n.best_header = n.best_header.max(last.height);
                            n.chain.expect(hashes);
                            let locator = n.chain.locator(&fork);
                            n.send(id, &Msg::GetBlocks { locator });
                            asked_blocks = true;
                        } else if hashes.len() < MAX_HEADER_RUN {
                            // not yet heavier: ask for the headers that follow
                            n.send(id, &Msg::GetHeaders { locator: vec![last.hash] });
                            asked_headers = true;
                            run = Some(HeaderRun { fork, last, times, hashes });
                        }
                    }
                    Err(e) => {
                        say(&n, format!("peer's headers rejected: {e}"));
                        score += 50;
                    }
                }
            }
            Msg::GetBlocks { locator } => {
                let mut n = lock(&shared);
                if n.waiting(id) > SYNC_BATCH_BYTES / 2 {
                    continue;
                }
                let blocks = n.chain.blocks_after(&locator, SYNC_BATCH_BYTES);
                let more = blocks.last().map(|b| b.hash() != n.chain.tip().hash).unwrap_or(false);
                n.send(id, &Msg::Blocks(blocks));
                if more {
                    let hello = n.hello();
                    n.send(id, &hello);
                }
            }
            Msg::Blocks(bs) => {
                asked_blocks = false;
                prewarm(&shared, &bs);
                let mut n = lock(&shared);
                let mut orphan = false;
                let mut progress = false;
                for b in bs {
                    let h = b.hash();
                    let known = n.chain.has(&h);
                    match n.accept_block(b, Some(id)) {
                        Err(e) if e == "unknown parent" => orphan = true,
                        Err(e) => {
                            let cost = block_penalty(&e);
                            if cost > 0 {
                                say(&n, format!("rejected block {}: {e}", hash_hex(&h)));
                                score += cost;
                            }
                        }
                        Ok(_) => {}
                    }
                    if !known && n.chain.has(&h) {
                        progress = true;
                        last_recv = Some(h);
                    }
                }
                if orphan && progress {
                    let locator = n.chain.locator(&n.chain.tip().hash);
                    n.send(id, &Msg::GetBlocks { locator });
                    asked_blocks = true;
                }
            }
            Msg::Block(b) => {
                prewarm(&shared, std::slice::from_ref(&b));
                let mut n = lock(&shared);
                let h = b.hash();
                match n.accept_block(b, Some(id)) {
                    Err(e) if e == "unknown parent" => {
                        // weigh the chain it belongs to by its headers before fetching it
                        let locator = n.chain.locator(&n.chain.tip().hash);
                        n.send(id, &Msg::GetHeaders { locator });
                        asked_headers = true;
                    }
                    Err(e) => {
                        let cost = block_penalty(&e);
                        if cost > 0 {
                            say(&n, format!("rejected block {}: {e}", hash_hex(&h)));
                            score += cost;
                        }
                    }
                    Ok(_) => {}
                }
            }
            Msg::Tx(t) => {
                let tid = t.id();
                // stateless checks and the proof, outside the lock
                if let Err(e) = Node::precheck(&t, &params) {
                    // a fee below this node's floor is a difference of policy, not a fault
                    if !e.contains("below the minimum relay fee") {
                        score += 20;
                    }
                    let n = lock(&shared);
                    say(&n, format!("tx {} rejected: {e}", hash_hex(&tid)));
                    continue;
                }
                let mut n = lock(&shared);
                match n.admit(t.clone()) {
                    Ok(true) => {
                        say(&n, format!("tx {} accepted, mempool {}", hash_hex(&tid), n.mempool_len()));
                        n.broadcast(&Msg::Tx(t), Some(id));
                    }
                    Ok(false) => {}
                    Err(e) => say(&n, format!("tx {} rejected: {e}", hash_hex(&tid))),
                }
            }
        }
    }
    {
        let mut n = lock(&shared);
        n.peers.remove(&id);
        if let Some(a) = &dialled {
            n.outbound.remove(a);
        }
    }
    let _ = s.shutdown(Shutdown::Both);
}

fn dial(addr: &str) -> Option<TcpStream> {
    use std::net::ToSocketAddrs;
    let sa = addr.to_socket_addrs().ok()?.next()?;
    TcpStream::connect_timeout(&sa, Duration::from_secs(5)).ok()
}

/// Keep `target` connections that this node dialled itself, chosen from its address book,
/// looking again every `every`. Also writes the book out as it changes.
pub fn discover(shared: Shared, target: usize, every: Duration) {
    thread::spawn(move || loop {
        let wanted: Vec<String> = {
            let mut n = lock(&shared);
            n.book.save();
            let have = n.outbound.len();
            if have >= target || PEERS.load(Ordering::SeqCst) >= MAX_PEERS {
                vec![]
            } else {
                let mut skip = n.outbound.clone();
                if !n.external.is_empty() {
                    skip.insert(n.external.clone());
                }
                let picks: Vec<String> = n.book.candidates(&skip).into_iter().take(target - have).collect();
                for a in &picks {
                    n.book.mark_tried(a);
                    n.outbound.insert(a.clone());
                }
                picks
            }
        };
        for a in wanted {
            let sh = shared.clone();
            thread::spawn(move || match dial(&a) {
                Some(s) => {
                    PEERS.fetch_add(1, Ordering::SeqCst);
                    let id = rand::thread_rng().gen();
                    handle_peer(sh, s, id, Some(a), false, None);
                }
                None => {
                    let mut n = lock(&sh);
                    n.outbound.remove(&a);
                    n.book.failed(&a);
                }
            });
        }
        thread::sleep(every);
    });
}

/// Peers connected right now, both directions.
pub fn peer_count() -> usize {
    PEERS.load(Ordering::SeqCst)
}

pub fn listen(shared: Shared, port: u16) -> Result<(), String> {
    // IPv6 and IPv4 together where the system allows it (private networks such as Fly's are
    // IPv6), IPv4 alone otherwise
    let l = TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port))
        .or_else(|_| TcpListener::bind(("0.0.0.0", port)))
        .map_err(|e| format!("bind {port}: {e}"))?;
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            if PEERS.load(Ordering::SeqCst) >= MAX_PEERS || INBOUND.load(Ordering::SeqCst) >= MAX_INBOUND {
                continue; // dropped: the connection closes
            }
            let ip = s.peer_addr().ok().map(|a| a.ip());
            if let Some(ip) = ip {
                if !admit_inbound(ip) {
                    continue;
                }
            }
            PEERS.fetch_add(1, Ordering::SeqCst);
            INBOUND.fetch_add(1, Ordering::SeqCst);
            let sh = shared.clone();
            let id = rand::thread_rng().gen();
            thread::spawn(move || handle_peer(sh, s, id, None, true, ip));
        }
    });
    Ok(())
}

pub fn connect(shared: Shared, addr: &str) -> Result<(), String> {
    let s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    PEERS.fetch_add(1, Ordering::SeqCst);
    let id = rand::thread_rng().gen();
    thread::spawn(move || handle_peer(shared, s, id, None, false, None));
    Ok(())
}

/// Stay connected to `addr`: connect, serve the connection until it drops, wait, repeat.
/// A peer that is down at start, or restarts, is picked up again without a restart here.
pub fn keep_connected(shared: Shared, addr: String) {
    thread::spawn(move || loop {
        if let Ok(s) = TcpStream::connect(&addr) {
            PEERS.fetch_add(1, Ordering::SeqCst);
            let id = rand::thread_rng().gen();
            lock(&shared).outbound.insert(addr.clone());
            handle_peer(shared.clone(), s, id, Some(addr.clone()), false, None);
        }
        thread::sleep(Duration::from_secs(15));
    });
}

/// Say hello to every peer now and then, so that a quiet link is known to be alive and a
/// silent one can be told from it.
pub fn keepalive(shared: Shared) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(KEEPALIVE_SECS));
        let mut n = lock(&shared);
        let h = n.hello();
        n.broadcast(&h, None);
    });
}

/// Send one transaction to a node and return.
pub fn submit(addr: &str, magic: [u8; 4], tx: &Tx) -> Result<(), String> {
    let mut s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    s.write_all(&Msg::Tx(tx.clone()).encode(magic)).map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_millis(200));
    Ok(())
}

/// Mine forever on the tip, paying `a_pk`. Re-templates when the tip changes.
/// `interval` spaces blocks out on regtest, where the target is trivial.
impl Node {
    /// A block on the tip paying `a_pk` the subsidy and the fees of the transactions the
    /// pool would put in it. The direct miner and the merged-mining RPC both use it.
    pub fn block_template(&self, a_pk: crate::hash::Word8, extra: &[u8]) -> Result<(Block, u64), String> {
        let (txs, fees) = self.select_with_fees();
        let value = subsidy(self.chain.height() + 1) + fees;
        let out = PlainOut { a_pk, v: value, rho: rand::thread_rng().gen() };
        Ok((self.chain.template(vec![out], txs, extra.to_vec())?, value))
    }
}

/// Mining steps aside while this node proves something (a faucet payment): on a small
/// shared machine the proof would otherwise wait behind the hashing.
static MINING_PAUSED: AtomicUsize = AtomicUsize::new(0);

pub struct MiningPause;

impl Drop for MiningPause {
    fn drop(&mut self) {
        MINING_PAUSED.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn pause_mining() -> MiningPause {
    MINING_PAUSED.fetch_add(1, Ordering::SeqCst);
    MiningPause
}

/// Mine on the tip, paying `a_pk`. `duty` is the share of one core to hash with, in
/// percent: a node on a small shared machine keeps most of its time for peers and proofs.
pub fn run_miner(shared: Shared, a_pk: crate::hash::Word8, interval: Duration) {
    run_miner_duty(shared, a_pk, interval, 100)
}

pub fn run_miner_duty(shared: Shared, a_pk: crate::hash::Word8, interval: Duration, duty: u32) {
    let duty = duty.clamp(1, 100);
    thread::spawn(move || loop {
        thread::sleep(interval);
        let (mut b, tip) = {
            let n = lock(&shared);
            match n.block_template(a_pk, b"newsatoshi-cpu").map(|(b, _)| b) {
                Ok(b) => (b, n.chain.tip().hash),
                Err(_) => {
                    drop(n);
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
            }
        };
        b.header.nonce = rand::thread_rng().gen();
        loop {
            while MINING_PAUSED.load(Ordering::SeqCst) > 0 {
                thread::sleep(Duration::from_millis(100));
            }
            let t = std::time::Instant::now();
            if mine(&mut b.header, 200_000) {
                let _ = lock(&shared).accept_block(b, None);
                break;
            }
            if duty < 100 {
                thread::sleep(t.elapsed() * (100 - duty) / duty);
            }
            if lock(&shared).chain.tip().hash != tip {
                break;
            }
        }
    });
}
