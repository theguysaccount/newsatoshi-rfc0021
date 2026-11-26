//! JSON-RPC for mining pools: merged mining through Namecoin's calls, so pool software that
//! already merge-mines Namecoin with Bitcoin needs only a new chain entry.
//!
//!   createauxblock ADDRESS       a block paying ADDRESS, for a pool to commit to
//!   getauxblock                  the same, paying this node's wallet
//!   getauxblock HASH AUXPOW      submit, as submitauxblock
//!   submitauxblock HASH AUXPOW   attach the Bitcoin work and submit; true if accepted
//!   getblockcount  getbestblockhash  getblockchaininfo  getmininginfo  getdifficulty
//!   validateaddress ADDRESS  help
//!
//! HTTP/1.1, Basic authentication, one request per connection, 127.0.0.1 unless told
//! otherwise. `hash` values are byte-reversed hex, as Bitcoin and Namecoin print them;
//! `_target` is the target's little-endian bytes, as Namecoin returns it.

use crate::auxpow::{self, AuxPow};
use crate::hash::Word8;
use crate::node::{lock, Shared};
use crate::pow;
use crate::tx::{hash_hex, Block};
use crate::wallet::{encode_address, parse_address};
use primitive_types::U256;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1 << 20;
const MAX_CONNECTIONS: usize = 16;
/// A whole request, head and body, arrives within this long, however slowly it is sent.
const REQUEST_SECS: u64 = 20;
/// Transactions from the public API whose proofs are being checked at once. More than
/// this are told to come back, so strangers cannot take every core.
const MAX_CHECKING: usize = 2;
/// One answer of the public API scans at most this many blocks and carries about this
/// many bytes; the caller asks again from `next`.
const SCAN_BLOCKS: u32 = 2_000;
const ANSWER_BYTES: usize = 2 << 20;
/// Bytes of blocks one answer about envelopes reads from disk.
const READ_BYTES: usize = 32 << 20;
/// Positions returned for one commitment (the latest), if the same note was made many times.
const MAX_NOTE_POSITIONS: usize = 16;

/// Read into `tmp` before `deadline`, however the bytes trickle in.
fn read_by(s: &mut TcpStream, tmp: &mut [u8], deadline: std::time::Instant) -> Result<usize, String> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        return Err("request too slow".into());
    }
    let _ = s.set_read_timeout(Some(left));
    match s.read(tmp) {
        Ok(0) => Err("connection closed".into()),
        Ok(n) => Ok(n),
        Err(e) => Err(e.to_string()),
    }
}
/// Templates handed out and not yet submitted; a pool asks again when the tip moves.
const KEEP_TEMPLATES: usize = 64;

/// A JSON value. Numbers keep their text, so a request id is echoed exactly.
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn num(n: impl std::fmt::Display) -> J {
        J::Num(n.to_string())
    }
    pub fn str(s: impl Into<String>) -> J {
        J::Str(s.into())
    }
    /// For a lock released in the mempool: whether the lock itself is already in a block.
    fn with_made(self, made: bool) -> J {
        match self {
            J::Obj(mut kv) => {
                kv.push(("made_confirmed".into(), J::Bool(made)));
                J::Obj(kv)
            }
            j => j,
        }
    }

    pub fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(kv) => kv.iter().find(|(key, _)| key == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn parse(s: &[u8]) -> Result<J, String> {
        let mut p = Parser { s, i: 0, depth: 0 };
        let v = p.value()?;
        p.ws();
        if p.i != s.len() {
            return Err("trailing characters after json".into());
        }
        Ok(v)
    }

    pub fn to_json(&self) -> String {
        let mut o = String::new();
        self.write(&mut o);
        o
    }

    fn write(&self, o: &mut String) {
        match self {
            J::Null => o.push_str("null"),
            J::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
            J::Num(n) => o.push_str(n),
            J::Str(s) => {
                o.push('"');
                for c in s.chars() {
                    match c {
                        '"' => o.push_str("\\\""),
                        '\\' => o.push_str("\\\\"),
                        '\n' => o.push_str("\\n"),
                        '\r' => o.push_str("\\r"),
                        '\t' => o.push_str("\\t"),
                        c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                        c => o.push(c),
                    }
                }
                o.push('"');
            }
            J::Arr(v) => {
                o.push('[');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    x.write(o);
                }
                o.push(']');
            }
            J::Obj(kv) => {
                o.push('{');
                for (i, (k, v)) in kv.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    J::Str(k.clone()).write(o);
                    o.push(':');
                    v.write(o);
                }
                o.push('}');
            }
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, word: &str, v: J) -> Result<J, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err("bad json literal".into())
        }
    }
    fn value(&mut self) -> Result<J, String> {
        self.ws();
        if self.depth > 32 {
            return Err("json nested too deeply".into());
        }
        let c = *self.s.get(self.i).ok_or("unexpected end of json")?;
        match c {
            b'{' => {
                self.i += 1;
                self.depth += 1;
                let mut kv = vec![];
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        if self.s.get(self.i) != Some(&b'"') {
                            return Err("object key must be a string".into());
                        }
                        let k = self.string()?;
                        self.ws();
                        if self.s.get(self.i) != Some(&b':') {
                            return Err("expected ':' in object".into());
                        }
                        self.i += 1;
                        kv.push((k, self.value()?));
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("expected ',' or '}' in object".into()),
                        }
                    }
                }
                self.depth -= 1;
                Ok(J::Obj(kv))
            }
            b'[' => {
                self.i += 1;
                self.depth += 1;
                let mut v = vec![];
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        v.push(self.value()?);
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("expected ',' or ']' in array".into()),
                        }
                    }
                }
                self.depth -= 1;
                Ok(J::Arr(v))
            }
            b'"' => self.string().map(J::Str),
            b't' => self.lit("true", J::Bool(true)),
            b'f' => self.lit("false", J::Bool(false)),
            b'n' => self.lit("null", J::Null),
            b'-' | b'0'..=b'9' => {
                let st = self.i;
                self.i += 1;
                while self.i < self.s.len() && matches!(self.s[self.i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                    self.i += 1;
                }
                Ok(J::Num(String::from_utf8_lossy(&self.s[st..self.i]).into_owned()))
            }
            _ => Err("bad json".into()),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let st = self.i;
            while self.i < self.s.len() && self.s[self.i] != b'"' && self.s[self.i] != b'\\' {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[st..self.i]).map_err(|_| "invalid utf-8 in json string")?);
            match self.s.get(self.i) {
                None => return Err("unterminated json string".into()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                _ => {
                    let e = *self.s.get(self.i + 1).ok_or("bad json escape")?;
                    self.i += 2;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let h = self.s.get(self.i..self.i + 4).ok_or("bad json escape")?;
                            let cp = std::str::from_utf8(h).ok().and_then(|h| u32::from_str_radix(h, 16).ok()).ok_or("bad json escape")?;
                            self.i += 4;
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err("bad json escape".into()),
                    }
                }
            }
        }
    }
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

fn u256_f64(x: U256) -> f64 {
    x.0.iter().rev().fold(0f64, |f, limb| f * 18_446_744_073_709_551_616.0 + *limb as f64)
}

/// Bitcoin's difficulty scale: how many times harder than a target of 0x1d00ffff.
pub fn difficulty(bits: u32) -> f64 {
    u256_f64(pow::target_from_compact(0x1d00ffff)) / u256_f64(pow::target_from_compact(bits)).max(1.0)
}

type RpcErr = (i32, String);

fn param<'a>(params: &'a [J], i: usize) -> Result<&'a str, RpcErr> {
    params.get(i).and_then(|v| v.as_str()).ok_or((-1, format!("parameter {} must be a string", i + 1)))
}

pub struct Rpc {
    shared: Shared,
    auth: String,
    payout: Word8,
    templates: Mutex<VecDeque<([u8; 32], Block)>>,
    open: AtomicUsize,
}

impl Rpc {
    pub fn new(shared: Shared, user_pass: &str, payout: Word8) -> Arc<Rpc> {
        Arc::new(Rpc {
            shared,
            auth: format!("Basic {}", base64(user_pass.as_bytes())),
            payout,
            templates: Mutex::new(VecDeque::new()),
            open: AtomicUsize::new(0),
        })
    }

    fn say(&self, s: String) {
        if lock(&self.shared).log {
            println!("{s}");
        }
    }

    /// A block for a pool to commit to in its Bitcoin coinbase.
    pub fn create(&self, a_pk: Word8) -> Result<J, RpcErr> {
        let (mut b, value, height) = {
            let n = lock(&self.shared);
            let (b, value) = n.block_template(a_pk, b"newsatoshi-aux").map_err(|e| (-1, e))?;
            (b, value, n.chain.height() + 1)
        };
        b.header.version = auxpow::auxpow_version(b.header.version);
        let h = b.hash();
        let mut target = [0u8; 32];
        pow::target_from_compact(b.header.bits).to_little_endian(&mut target);
        let out = J::Obj(vec![
            ("hash".into(), J::str(hash_hex(&h))),
            ("chainid".into(), J::num(auxpow::CHAIN_ID)),
            ("previousblockhash".into(), J::str(hash_hex(&b.header.prev))),
            ("coinbasevalue".into(), J::num(value)),
            ("bits".into(), J::str(format!("{:08x}", b.header.bits))),
            ("height".into(), J::num(height)),
            ("_target".into(), J::str(hex::encode(target))),
        ]);
        let mut t = self.templates.lock().unwrap_or_else(|e| e.into_inner());
        t.push_back((h, b));
        while t.len() > KEEP_TEMPLATES {
            t.pop_front();
        }
        Ok(out)
    }

    /// Attach the pool's auxpow to the block it was made for and submit it.
    pub fn submit(&self, hash: &str, auxpow_hex: &str) -> Result<bool, RpcErr> {
        let mut h: [u8; 32] = hex::decode(hash).ok().and_then(|b| b.try_into().ok()).ok_or((-8, "block hash must be 64 hex characters".to_string()))?;
        h.reverse();
        let raw = hex::decode(auxpow_hex).map_err(|_| (-8, "auxpow must be hex".to_string()))?;
        let aux = AuxPow::parse(&raw).map_err(|e| (-1, e))?;
        let mut b = {
            let t = self.templates.lock().unwrap_or_else(|e| e.into_inner());
            t.iter().find(|(th, _)| *th == h).map(|(_, b)| b.clone()).ok_or((-8, "block hash unknown".to_string()))?
        };
        b.auxpow = Some(aux);
        if let Err(e) = crate::chain::check_work(&b) {
            self.say(format!("auxpow for {} rejected: {e}", hash_hex(&h)));
            return Ok(false);
        }
        let res = lock(&self.shared).accept_block(b, None);
        match res {
            Ok(_) => {
                self.templates.lock().unwrap_or_else(|e| e.into_inner()).retain(|(th, _)| *th != h);
                self.say(format!("merge-mined block {} accepted", hash_hex(&h)));
                Ok(true)
            }
            Err(e) => {
                self.say(format!("merge-mined block {} rejected: {e}", hash_hex(&h)));
                Ok(false)
            }
        }
    }

    pub fn call(&self, method: &str, params: &[J]) -> Result<J, RpcErr> {
        match method {
            "createauxblock" => {
                let a_pk = parse_address(param(params, 0)?).map_err(|e| (-5, e))?;
                self.create(a_pk)
            }
            "getauxblock" if params.is_empty() => self.create(self.payout),
            "getauxblock" | "submitauxblock" => self.submit(param(params, 0)?, param(params, 1)?).map(J::Bool),
            "getblockcount" => Ok(J::num(lock(&self.shared).chain.height())),
            "getbestblockhash" => Ok(J::str(hash_hex(&lock(&self.shared).chain.tip().hash))),
            "getdifficulty" => {
                let n = lock(&self.shared);
                Ok(J::num(difficulty(n.chain.next_bits(n.chain.tip()))))
            }
            "getblockchaininfo" | "getmininginfo" => {
                let n = lock(&self.shared);
                let t = n.chain.tip();
                Ok(J::Obj(vec![
                    ("chain".into(), J::str(n.chain.params.name)),
                    ("blocks".into(), J::num(t.height)),
                    ("bestblockhash".into(), J::str(hash_hex(&t.hash))),
                    ("difficulty".into(), J::num(difficulty(n.chain.next_bits(t)))),
                    ("chainwork".into(), J::str(format!("{:064x}", t.work))),
                    ("auxpow_chainid".into(), J::num(auxpow::CHAIN_ID)),
                ]))
            }
            "validateaddress" => {
                let a = param(params, 0)?;
                let ok = parse_address(a).is_ok();
                Ok(J::Obj(vec![("isvalid".into(), J::Bool(ok)), ("address".into(), J::str(a))]))
            }
            "help" => Ok(J::str("createauxblock ADDRESS | getauxblock [HASH AUXPOW] | submitauxblock HASH AUXPOW | getblockcount | getbestblockhash | getblockchaininfo | getmininginfo | getdifficulty | validateaddress ADDRESS")),
            _ => Err((-32601, "Method not found".into())),
        }
    }

    fn one(&self, req: &J) -> J {
        let id = req.get("id").cloned().unwrap_or(J::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params: Vec<J> = match req.get("params") {
            Some(J::Arr(v)) => v.clone(),
            _ => vec![],
        };
        let (result, error) = match self.call(method, &params) {
            Ok(r) => (r, J::Null),
            Err((code, message)) => (J::Null, J::Obj(vec![("code".into(), J::num(code)), ("message".into(), J::str(message))])),
        };
        J::Obj(vec![("result".into(), result), ("error".into(), error), ("id".into(), id)])
    }

    fn handle(&self, mut s: TcpStream) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
        let (status, body) = match read_request(&mut s) {
            Err(e) => ("400 Bad Request", J::Obj(vec![("error".into(), J::str(e))]).to_json()),
            Ok((auth, body)) => {
                if !eq_ct(auth.as_bytes(), self.auth.as_bytes()) {
                    let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"jsonrpc\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    return;
                }
                match J::parse(&body) {
                    Err(e) => ("500 Internal Server Error", J::Obj(vec![("result".into(), J::Null), ("error".into(), J::Obj(vec![("code".into(), J::num(-32700)), ("message".into(), J::str(e))])), ("id".into(), J::Null)]).to_json()),
                    Ok(J::Arr(reqs)) => ("200 OK", J::Arr(reqs.iter().map(|r| self.one(r)).collect()).to_json()),
                    Ok(req) => {
                        let resp = self.one(&req);
                        let failed = !matches!(resp.get("error"), Some(J::Null));
                        (if failed { "500 Internal Server Error" } else { "200 OK" }, resp.to_json())
                    }
                }
            }
        };
        let head = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = s.write_all(head.as_bytes()).and_then(|_| s.write_all(body.as_bytes()));
    }
}

/// Compare without stopping at the first difference.
fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// One HTTP POST: the Authorization header and the body.
fn read_request(s: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(REQUEST_SECS);
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 8192];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large".into());
        }
        let n = read_by(s, &mut tmp, deadline)?;
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "request head is not text")?;
    let mut lines = head.split("\r\n");
    if !lines.next().unwrap_or("").starts_with("POST ") {
        return Err("only POST is served".into());
    }
    let mut len = None;
    let mut auth = String::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse::<usize>().ok(),
                "authorization" => auth = v.trim().to_string(),
                _ => {}
            }
        }
    }
    let len = len.ok_or("content-length required")?;
    if len > MAX_BODY {
        return Err("request body too large".into());
    }
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = read_by(s, &mut tmp, deadline)?;
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Ok((auth, body))
}

/// Serve JSON-RPC on `bind:port` (port 0 picks one). Returns the port.
pub fn serve(rpc: Arc<Rpc>, bind: &str, port: u16) -> Result<u16, String> {
    let l = TcpListener::bind((bind, port)).map_err(|e| format!("rpc bind {bind}:{port}: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            if rpc.open.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                continue;
            }
            rpc.open.fetch_add(1, Ordering::SeqCst);
            let r = rpc.clone();
            thread::spawn(move || {
                r.handle(s);
                r.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(port)
}

/// The chain as anyone may see it: what a block explorer or a status page needs.
pub fn status(shared: &Shared) -> J {
    let n = lock(shared);
    let c = &n.chain;
    let t = c.tip();
    let s = &c.state;
    let recent: Vec<J> = (0..12u32)
        .filter_map(|k| t.height.checked_sub(k))
        // headers only: the status page reads no block bodies
        .filter_map(|h| c.header_at(h).map(|b| (h, b)))
        .map(|(h, b)| {
            J::Obj(vec![
                ("height".into(), J::num(h)),
                ("hash".into(), J::str(hash_hex(&b.hash()))),
                ("time".into(), J::num(b.header.time)),
                ("txs".into(), J::num(c.block_txs(&b.hash()))),
                ("bytes".into(), J::num(c.block_size(&b.hash()))),
                ("merge_mined".into(), J::Bool(b.auxpow.is_some())),
            ])
        })
        .collect();
    J::Obj(vec![
        ("network".into(), J::str(c.params.name)),
        // what a wallet needs to pay on this network: which proofs it takes, and the fee
        // its wallets pay by default
        ("proofs".into(), J::str(match c.params.net { crate::params::Net::Main => "main", crate::params::Net::Dry => "dry", _ => "test" })),
        ("fee".into(), J::num(c.params.default_fee)),
        ("version".into(), J::str(env!("CARGO_PKG_VERSION"))),
        ("genesis".into(), J::str(hash_hex(&c.genesis))),
        ("height".into(), J::num(t.height)),
        ("tip".into(), J::str(hash_hex(&t.hash))),
        ("tip_time".into(), J::num(t.time)),
        ("now".into(), J::num(crate::chain::now())),
        ("bits".into(), J::str(format!("{:08x}", c.next_bits(t)))),
        ("difficulty".into(), J::num(difficulty(c.next_bits(t)))),
        ("chainwork".into(), J::str(format!("{:064x}", t.work))),
        ("peers".into(), J::num(crate::node::peer_count())),
        ("known_peers".into(), J::num(n.book.map.len())),
        ("best_header".into(), J::num(n.best_header.max(c.height()))),
        ("mempool".into(), J::num(n.mempool_len())),
        ("issued".into(), J::num(s.issued)),
        ("notes".into(), J::num(s.tree.len())),
        ("nullifiers".into(), J::num(s.nullifiers.len())),
        ("locks".into(), J::num(s.locks.len())),
        ("conditions".into(), J::num(s.conds.len())),
        ("channels".into(), J::num(s.channels.len())),
        ("auxpow_chainid".into(), J::num(auxpow::CHAIN_ID)),
        ("recent".into(), J::Arr(recent)),
    ])
}

/// Serve the public API on `bind:port`, to anyone, with CORS open: no secrets live here.
pub fn serve_status(shared: Shared, bind: &str, port: u16) -> Result<u16, String> {
    serve_public(shared, bind, port, None)
}

/// One HTTP request, as the public API needs it.
struct Req {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    peer: String,
    proxied: bool,
}

impl Req {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(h, _)| h == k).map(|(_, v)| v.as_str())
    }
    fn param(&self, k: &str) -> Option<&str> {
        self.query.split('&').filter_map(|kv| kv.split_once('=')).find(|(a, _)| *a == k).map(|(_, v)| v)
    }
    /// The visitor's address: Fly's proxy sets Fly-Client-IP; the site's own proxy passes
    /// it on as X-Real-IP. Believed only from a proxy (`proxied`).
    fn client(&self) -> String {
        if !self.proxied {
            return self.peer.clone();
        }
        self.header("fly-client-ip").or(self.header("x-real-ip")).unwrap_or(&self.peer).to_string()
    }
}

fn read_http(s: &mut TcpStream, max_body: usize) -> Result<Req, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(REQUEST_SECS);
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 8192];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large".into());
        }
        let n = read_by(s, &mut tmp, deadline)?;
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "request head is not text")?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if len > max_body {
        return Err("request body too large".into());
    }
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = read_by(s, &mut tmp, deadline)?;
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    let addr = s.peer_addr().ok().map(|a| a.ip());
    let peer = addr.map(|a| a.to_string()).unwrap_or_default();
    // a proxy on this machine or a private network may speak for the visitor it carries;
    // a stranger connecting directly may not name an address for itself
    let proxied = addr.map(|a| !crate::node::is_public(a)).unwrap_or(false);
    Ok(Req { method, path: path.to_string(), query: query.to_string(), headers, body, peer, proxied })
}

fn word8_hex(w: &Word8) -> String {
    hex::encode(crate::hash::words_to_bytes(w))
}

fn hex_word8(s: Option<&str>) -> Result<Word8, (u16, String)> {
    let b: [u8; 32] = s.and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok()).ok_or((400, "expected 64 hex characters".to_string()))?;
    Ok(crate::hash::bytes_to_words(&b))
}

/// What a transaction is told when the node is already checking as many as it will.
pub const BUSY: &str = "busy checking other transactions; send it again in a moment";

fn err_json(e: &str) -> J {
    J::Obj(vec![("ok".into(), J::Bool(false)), ("error".into(), J::str(e))])
}

/// Where a commitment sits in the note tree, with the path a spend needs.
pub fn note_info(shared: &Shared, cm: &Word8) -> J {
    let n = lock(shared);
    let st = &n.chain.state;
    let all = st.cm_pos.get(cm).map(|v| v.as_slice()).unwrap_or(&[]);
    let notes: Vec<J> = all[all.len().saturating_sub(MAX_NOTE_POSITIONS)..]
        .iter()
        .map(|&pos| {
            let path = st.tree.path(pos);
            J::Obj(vec![("pos".into(), J::num(pos)), ("path".into(), J::Arr(path.iter().map(|w| J::str(word8_hex(w))).collect()))])
        })
        .collect();
    J::Obj(vec![
        ("found".into(), J::Bool(!notes.is_empty())),
        ("height".into(), J::num(n.chain.height())),
        ("root".into(), J::str(word8_hex(&st.tree.root()))),
        ("notes".into(), J::Arr(notes)),
    ])
}

fn lock_json(l: &crate::lock::Lock, state: &str, confirmed: bool, tip: u32, end: Option<&crate::lock::LockEnd>) -> J {
    let p = &l.post;
    let mut kv = vec![
        ("id".into(), J::str(hex::encode(l.id))),
        ("state".into(), J::str(state)),
        ("confirmed".into(), J::Bool(confirmed)),
        ("amount".into(), J::num(p.amount)),
        ("hash".into(), J::str(hex::encode(p.hash))),
        ("timeout".into(), J::num(p.timeout)),
        ("claim".into(), J::str(encode_address(&p.claim_addr))),
        ("refund".into(), J::str(encode_address(&p.refund_addr))),
        ("at".into(), J::num(l.at)),
        ("confirmations".into(), J::num(if confirmed { (tip + 1).saturating_sub(l.at) } else { 0 })),
    ];
    if let Some(e) = end {
        kv.push(("ended_at".into(), J::num(e.height)));
        kv.push(("preimage".into(), e.preimage.map(|x| J::str(hex::encode(x))).unwrap_or(J::Null)));
    }
    J::Obj(kv)
}

/// One lock, by id: its terms and where it stands. `state` is `open`, `claimed` or
/// `refunded`; `confirmed` says whether that is in a block or only in the mempool, where a
/// claim's preimage is already public.
pub fn lock_info(shared: &Shared, id: &[u8; 32]) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let st = &n.chain.state;
    let pool = n.pool_state();
    let base = |found: bool, mut kv: Vec<(String, J)>| {
        kv.insert(0, ("found".into(), J::Bool(found)));
        kv.push(("height".into(), J::num(tip)));
        J::Obj(kv)
    };
    let body = if let Some(e) = st.lock_ends.get(id) {
        Some(lock_json(&e.lock, if e.preimage.is_some() { "claimed" } else { "refunded" }, true, tip, Some(e)))
    } else if let Some(e) = pool.lock_ends.get(id) {
        let made = st.locks.contains_key(id);
        Some(lock_json(&e.lock, if e.preimage.is_some() { "claimed" } else { "refunded" }, false, tip, Some(e)).with_made(made))
    } else if let Some(l) = st.locks.get(id) {
        Some(lock_json(l, "open", true, tip, None))
    } else {
        pool.locks.get(id).map(|l| lock_json(l, "open", false, tip, None))
    };
    match body {
        Some(J::Obj(kv)) => base(true, kv),
        _ => base(false, vec![]),
    }
}

/// A condition (`crate::cond`): its terms, and whether it is open, fulfilled (with the
/// payout and the program that chose it) or refunded, on chain or waiting for a block.
pub fn cond_info(shared: &Shared, id: &[u8; 32]) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let st = &n.chain.state;
    let pool = n.pool_state();
    let json = |c: &crate::cond::Cond, state: &str, confirmed: bool, end: Option<&crate::cond::CondEnd>| {
        let mut kv = vec![
            ("found".into(), J::Bool(true)),
            ("id".into(), J::str(hex::encode(c.id))),
            ("state".into(), J::str(state)),
            ("confirmed".into(), J::Bool(confirmed)),
            ("amount".into(), J::num(c.post.amount)),
            ("commitment".into(), J::str(hex::encode(c.post.commitment))),
            ("payouts".into(), J::Arr(c.post.payouts.iter().map(|a| J::str(encode_address(a))).collect())),
            ("timeout".into(), J::num(c.post.timeout)),
            ("refund".into(), J::str(encode_address(&c.post.refund_addr))),
            ("made_at".into(), J::num(c.at)),
            ("height".into(), J::num(tip)),
        ];
        if let Some(e) = end {
            kv.push(("ended_at".into(), J::num(e.height)));
            if let Some((p, prog)) = &e.fulfilled {
                kv.push(("payout".into(), J::num(*p)));
                kv.push(("program".into(), J::str(hex::encode(prog))));
            }
        }
        J::Obj(kv)
    };
    let end_state = |e: &crate::cond::CondEnd| if e.fulfilled.is_some() { "fulfilled" } else { "refunded" };
    if let Some(e) = st.cond_ends.get(id) {
        json(&e.cond, end_state(e), true, Some(e))
    } else if let Some(e) = pool.cond_ends.get(id) {
        json(&e.cond, end_state(e), false, Some(e))
    } else if let Some(c) = st.conds.get(id) {
        json(c, "open", true, None)
    } else if let Some(c) = pool.conds.get(id) {
        json(c, "open", false, None)
    } else {
        J::Obj(vec![("found".into(), J::Bool(false)), ("height".into(), J::num(tip))])
    }
}

/// Every lock made for a payment hash, newest last.
pub fn locks_for_hash(shared: &Shared, hash: &[u8; 32]) -> J {
    let ids: Vec<[u8; 32]> = lock(shared).pool_state().locks_by_hash.get(hash).cloned().unwrap_or_default();
    J::Obj(vec![("locks".into(), J::Arr(ids.iter().map(|id| lock_info(shared, id)).collect()))])
}

fn channel_json(
    ch: &crate::channel::Channel,
    state: &str,
    confirmed: bool,
    tip_height: u32,
    end: Option<&crate::channel::ChannelEnd>,
    merkle_proof: Option<(&crate::merkmap::MerkleProof, [u8; 32])>,
) -> J {
    let p = &ch.post;
    let budget = p.budget().unwrap_or(0);
    let total_deposit = p.total_deposit().unwrap_or(0);
    let mut kv = vec![
        ("id".into(), J::str(hex::encode(ch.id))),
        ("state".into(), J::str(state)),
        ("confirmed".into(), J::Bool(confirmed)),
        ("tip".into(), J::str(hex::encode(p.tip))),
        ("max_ticks".into(), J::num(p.max_ticks)),
        ("unit_price".into(), J::num(p.unit_price)),
        ("claim_fee".into(), J::num(p.claim_fee)),
        ("budget".into(), J::num(budget)),
        ("total_deposit".into(), J::num(total_deposit)),
        ("timeout".into(), J::num(p.timeout)),
        ("seller".into(), J::str(encode_address(&p.seller_addr))),
        ("seller_vk".into(), J::str(hex::encode(p.seller_vk))),
        ("refund".into(), J::str(encode_address(&p.refund_addr))),
        ("at".into(), J::num(ch.at)),
        ("confirmations".into(), J::num(if confirmed { (tip_height + 1).saturating_sub(ch.at) } else { 0 })),
    ];
    if let Some((proof, root)) = merkle_proof {
        kv.push((
            "merkle_proof".into(),
            J::Obj(vec![
                ("root".into(), J::str(hex::encode(root))),
                ("key".into(), J::str(hex::encode(proof.key))),
                ("value_hash".into(), J::str(hex::encode(proof.value_hash))),
                (
                    "siblings".into(),
                    J::Arr(proof.siblings.iter().map(|s| J::str(hex::encode(s))).collect()),
                ),
            ]),
        ));
    }
    if let Some(e) = end {
        kv.push(("ended_at".into(), J::num(e.height)));
        kv.push(("claimed_ticks".into(), e.claimed.map(|(t, _)| J::num(t)).unwrap_or(J::Null)));
        kv.push(("token".into(), e.claimed.map(|(_, tok)| J::str(hex::encode(tok))).unwrap_or(J::Null)));
        kv.push(("seller_paid".into(), J::num(e.seller_paid)));
        kv.push(("buyer_refunded".into(), J::num(e.buyer_refunded)));
        kv.push(("miner_fee".into(), J::num(e.miner_fee)));
    }
    J::Obj(kv)
}

/// One RFC-0022 PayWord channel, by channel id: its terms, settlement state (`open`, `claimed`,
/// or `expired`), whether that state is confirmed in a block or pending in the mempool, and a
/// canonical Merkle inclusion proof when open and confirmed.
pub fn channel_info(shared: &Shared, id: &[u8; 32]) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let st = &n.chain.state;
    let pool = n.pool_state();
    let base = |found: bool, mut kv: Vec<(String, J)>| {
        kv.insert(0, ("found".into(), J::Bool(found)));
        kv.push(("height".into(), J::num(tip)));
        J::Obj(kv)
    };
    let end_state = |e: &crate::channel::ChannelEnd| if e.claimed.is_some() { "claimed" } else { "expired" };
    let body = if let Some(e) = st.channel_ends.get(id) {
        Some(channel_json(&e.channel, end_state(e), true, tip, Some(e), None))
    } else if let Some(e) = pool.channel_ends.get(id) {
        let made = st.channels.contains_key(id);
        Some(channel_json(&e.channel, end_state(e), false, tip, Some(e), None).with_made(made))
    } else if let Some(ch) = st.channels.get(id) {
        let mp = st.channels_merkle.prove(id).map(|p| (p, st.channels_merkle.root()));
        Some(channel_json(ch, "open", true, tip, None, mp.as_ref().map(|(p, r)| (p, *r))))
    } else {
        pool.channels.get(id).map(|ch| channel_json(ch, "open", false, tip, None, None))
    };
    match body {
        Some(J::Obj(kv)) => base(true, kv),
        _ => base(false, vec![]),
    }
}

/// Every RFC-0022 PayWord channel funded for a PayWord chain tip, newest last.
pub fn channels_for_tip(shared: &Shared, tip_hash: &[u8; 32]) -> J {
    let (height, ids): (u32, Vec<[u8; 32]>) = {
        let n = lock(shared);
        (
            n.chain.height(),
            n.pool_state().channels_by_tip.get(tip_hash).cloned().unwrap_or_default(),
        )
    };
    J::Obj(vec![
        ("height".into(), J::num(height)),
        ("channels".into(), J::Arr(ids.iter().map(|id| channel_info(shared, id)).collect())),
    ])
}

fn merkle_proof_json(mp: &crate::merkmap::MerkleProof, root: [u8; 32]) -> J {
    J::Obj(vec![
        ("root".into(), J::str(hex::encode(root))),
        ("key".into(), J::str(hex::encode(mp.key))),
        ("value_hash".into(), J::str(hex::encode(mp.value_hash))),
        ("siblings".into(), J::Arr(mp.siblings.iter().map(|s| J::str(hex::encode(s))).collect())),
    ])
}

/// One RFC-0024 Universal Trust Bond, by bond id, with its canonical Merkle inclusion proof.
pub fn bond_info(shared: &Shared, id: &[u8; 32]) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let st = &n.chain.state;
    let pool = n.pool_state();
    let (b, confirmed, mp) = if let Some(b) = st.bonds.get(id) {
        let proof = st.bonds_merkle.prove(id).map(|p| (p, st.bonds_merkle.root()));
        (Some(b), true, proof)
    } else if let Some(b) = pool.bonds.get(id) {
        (Some(b), false, None)
    } else {
        (None, false, None)
    };
    let Some(b) = b else {
        return J::Obj(vec![("found".into(), J::Bool(false)), ("height".into(), J::num(tip))]);
    };
    let mut kv = vec![
        ("found".into(), J::Bool(true)),
        ("height".into(), J::num(tip)),
        ("confirmed".into(), J::Bool(confirmed)),
        ("id".into(), J::str(hex::encode(b.id))),
        ("owner_vk".into(), J::str(hex::encode(b.post.owner_vk))),
        ("owner_address".into(), J::str(encode_address(&b.post.owner_addr))),
        ("arbiter_vks".into(), J::Arr(b.post.arbiter_vks.iter().map(|v| J::str(hex::encode(v))).collect())),
        ("quorum_m".into(), J::num(b.post.quorum_m as u64)),
        ("unbond_delay".into(), J::num(b.post.unbond_delay as u64)),
        ("slash_burn_bps".into(), J::num(b.post.slash_burn_bps as u64)),
        ("stake".into(), J::num(b.post.stake)),
        ("service_tag".into(), J::str(hex::encode(b.post.service_tag))),
        ("created_at".into(), J::num(b.created_at as u64)),
        ("settled_count".into(), J::num(b.settled_count)),
        ("settled_volume".into(), J::str(b.settled_volume.to_string())),
        ("slash_count".into(), J::num(b.slash_count as u64)),
        ("slashed_total".into(), J::str(b.slashed_total.to_string())),
        ("unbond_amount".into(), J::num(b.unbond_amount)),
        ("action_nonce".into(), J::num(b.action_nonce)),
    ];
    if let Some(h) = b.unbond_requested_at {
        kv.push(("unbond_requested_at".into(), J::num(h as u64)));
    }
    if let Some((p, root)) = mp {
        kv.push(("merkle_proof".into(), merkle_proof_json(&p, root)));
    }
    J::Obj(kv)
}

/// One RFC-0023 Sovereign L2 Rollup Vault, by rollup id, with canonical Merkle inclusion proof.
pub fn rollup_info(shared: &Shared, id: &[u8; 32]) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let st = &n.chain.state;
    let pool = n.pool_state();
    let (rv, confirmed, mp) = if let Some(rv) = st.rollups.get(id) {
        let proof = st.rollups_merkle.prove(id).map(|p| (p, st.rollups_merkle.root()));
        (Some(rv), true, proof)
    } else if let Some(rv) = pool.rollups.get(id) {
        (Some(rv), false, None)
    } else {
        (None, false, None)
    };
    let Some(rv) = rv else {
        return J::Obj(vec![("found".into(), J::Bool(false)), ("height".into(), J::num(tip))]);
    };
    let mut kv = vec![
        ("found".into(), J::Bool(true)),
        ("height".into(), J::num(tip)),
        ("confirmed".into(), J::Bool(confirmed)),
        ("id".into(), J::str(hex::encode(rv.id))),
        ("vk_hash".into(), J::str(hex::encode(rv.post.vk_hash))),
        ("genesis_root".into(), J::str(hex::encode(rv.post.genesis_root))),
        ("state_root".into(), J::str(hex::encode(rv.state_root))),
        ("deposit_acc".into(), J::str(hex::encode(rv.deposit_acc))),
        ("deposit_count".into(), J::num(rv.deposit_count)),
        ("batch_seq".into(), J::num(rv.batch_seq)),
        ("total_l2_txs".into(), J::num(rv.total_l2_txs)),
        ("tvl".into(), J::num(rv.tvl)),
        ("pending_withdrawals".into(), J::num(rv.pending_withdrawals)),
        ("name_tag".into(), J::str(hex::encode(rv.post.name_tag))),
        ("created_at".into(), J::num(rv.created_at as u64)),
        (
            "withdraw_roots".into(),
            J::Arr(
                rv.withdraw_roots
                    .iter()
                    .map(|(seq, root)| {
                        J::Obj(vec![
                            ("batch_seq".into(), J::num(*seq)),
                            ("withdraw_root".into(), J::str(hex::encode(root))),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("claimed_withdrawals_count".into(), J::num(rv.claimed_withdrawals.len() as u64)),
    ];
    if let Some(vk) = &rv.post.sequencer_vk {
        kv.push(("sequencer_vk".into(), J::str(hex::encode(vk))));
    }
    if let Some((p, root)) = mp {
        kv.push(("merkle_proof".into(), merkle_proof_json(&p, root)));
    }
    J::Obj(kv)
}

/// RFC-0026: Live BIP-9 collective protocol steering & ossification signaling telemetry.
pub fn signaling_info(shared: &Shared) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let (window, threshold) = match n.chain.params.net {
        crate::params::Net::Main => (2_016, 1_815),
        crate::params::Net::Test => (144, 130),
        crate::params::Net::Reg | crate::params::Net::Dry => (10, 9),
    };
    let mut versions = Vec::with_capacity(tip as usize + 1);
    for h in 0..=tip {
        let v = n.chain.header_at(h).map(|b| b.header.version).unwrap_or(1);
        versions.push(v);
    }
    let deps = crate::signal::standard_deployments(window, threshold);
    let statuses: Vec<J> = deps
        .iter()
        .map(|d| {
            let st = crate::signal::evaluate_deployment(&versions, d);
            let mut kv = vec![
                ("name".into(), J::str(st.name)),
                ("bit".into(), J::num(st.bit as u64)),
                ("state".into(), J::str(st.state.as_str())),
                ("window".into(), J::num(st.window as u64)),
                ("threshold".into(), J::num(st.threshold as u64)),
                ("window_start".into(), J::num(st.window_start as u64)),
                ("blocks_in_window".into(), J::num(st.blocks_in_window as u64)),
                ("signaled_in_window".into(), J::num(st.signaled_in_window as u64)),
                ("ossifies_monetary_base".into(), J::Bool(st.ossifies_monetary_base)),
            ];
            if let Some(a) = st.active_since {
                kv.push(("active_since".into(), J::num(a as u64)));
            }
            J::Obj(kv)
        })
        .collect();
    J::Obj(vec![
        ("ok".into(), J::Bool(true)),
        ("height".into(), J::num(tip as u64)),
        ("deployments".into(), J::Arr(statuses)),
    ])
}

/// Hand a transaction from outside the peer network to the node: checked (the proof
/// outside the lock), pooled and announced.
pub fn submit_tx(shared: &Shared, bytes: &[u8]) -> J {
    static CHECKING: AtomicUsize = AtomicUsize::new(0);
    struct Slot;
    impl Drop for Slot {
        fn drop(&mut self) {
            CHECKING.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let tx = match crate::tx::Tx::from_bytes(bytes) {
        Ok(t) => t,
        Err(e) => return err_json(&format!("not a transaction: {e}")),
    };
    if CHECKING.fetch_add(1, Ordering::SeqCst) >= MAX_CHECKING {
        CHECKING.fetch_sub(1, Ordering::SeqCst);
        return err_json(BUSY);
    }
    let _slot = Slot;
    let params = lock(shared).chain.params.clone();
    if let Err(e) = crate::node::Node::precheck(&tx, &params) {
        return err_json(&e);
    }
    let id = hash_hex(&tx.id());
    match lock(shared).submit_local(tx) {
        Ok(_) => J::Obj(vec![("ok".into(), J::Bool(true)), ("txid".into(), J::str(id))]),
        Err(e) => err_json(&e),
    }
}

/// Envelopes in blocks from height `from`, for wallets that look for notes delivered to them
/// (`crate::deliver`): `{"tip", "next", "items": [{"h", "cm", "env"}], "pending": [...]}`, a
/// page at a time; a wallet asks again from `next` until `next` passes `tip`. `pending`
/// holds the envelopes of payments still waiting for a block.
pub fn envelopes(shared: &Shared, from: u32) -> J {
    const PAGE: usize = 200;
    fn items<'a>(txs: impl IntoIterator<Item = &'a crate::tx::Tx>, h: Option<u32>, out: &mut Vec<J>) {
        for t in txs {
            let crate::tx::Tx::Spend(sp) = t else { continue };
            let (env, _) = crate::deliver::unpack_memo(&sp.memo);
            for (i, e) in env.iter().enumerate() {
                let Some(e) = e else { continue };
                let mut kv = vec![("cm".into(), J::str(hex::encode(crate::hash::words_to_bytes(&sp.cm_out[i])))), ("env".into(), J::str(hex::encode(e)))];
                if let Some(h) = h {
                    kv.insert(0, ("h".into(), J::num(h as u64)));
                }
                out.push(J::Obj(kv));
            }
        }
    }
    let n = lock(shared);
    let tip = n.chain.height();
    let (mut found, mut pending) = (vec![], vec![]);
    let mut h = from;
    let (mut scanned, mut bytes) = (0u32, 0usize);
    // blocks are read from disk, so one answer also reads at most READ_BYTES of them
    // (always at least one block); a block with no payments in it is not read at all
    let mut read = 0usize;
    while h <= tip && found.len() < PAGE && scanned < SCAN_BLOCKS && bytes < ANSWER_BYTES && (scanned == 0 || read < READ_BYTES) {
        let hash = n.chain.active[h as usize];
        if n.chain.block_txs(&hash) > 1 || n.chain.block_size(&hash) == 0 {
            if let Some(b) = n.chain.block(&hash) {
                read += n.chain.block_size(&hash);
                let before = found.len();
                items(&b.txs, Some(h), &mut found);
                bytes += (found.len() - before) * 2 * crate::deliver::ENVELOPE_BYTES;
            }
        }
        h += 1;
        scanned += 1;
    }
    if h > tip {
        items(n.pool_txs(), None, &mut pending);
    }
    J::Obj(vec![
        ("ok".into(), J::Bool(true)),
        ("tip".into(), J::num(tip as u64)),
        ("next".into(), J::num(h as u64)),
        ("items".into(), J::Arr(found)),
        ("pending".into(), J::Arr(pending)),
    ])
}

/// Headers of the active chain from height `from`, for light clients (`crate::light`):
/// `{"tip", "next", "headers": [hex]}`, each a block's encoding without its transactions
/// (the 80-byte header and, for a merge-mined block, its auxpow), up to 2,000 at a time.
pub fn headers_from(shared: &Shared, from: u32) -> J {
    let n = lock(shared);
    let tip = n.chain.height();
    let mut hs = vec![];
    let mut h = from.max(1);
    let mut bytes = 0usize;
    while h <= tip && hs.len() < 2_000 && bytes < ANSWER_BYTES {
        if let Some(b) = n.chain.header_at(h) {
            let x = hex::encode(b.encode());
            bytes += x.len();
            hs.push(J::str(x));
        }
        h += 1;
    }
    J::Obj(vec![("ok".into(), J::Bool(true)), ("tip".into(), J::num(tip as u64)), ("next".into(), J::num(h as u64)), ("headers".into(), J::Arr(hs))])
}

/// The tip's header, its transaction root and the parts of the state digest it commits to,
/// so a light client can check the note-tree root (`crate::light`).
pub fn state_commitment(shared: &Shared) -> J {
    let n = lock(shared);
    let Some(b) = n.chain.block_at(n.chain.height()) else { return err_json("no tip") };
    let p = n.chain.state.digest_parts();
    let h32 = |b: &[u8; 32]| J::str(hex::encode(b));
    let mut parts = vec![
        ("height".into(), J::num(p.height as u64)),
        ("tree_root".into(), J::str(hex::encode(crate::hash::words_to_bytes(&p.tree_root)))),
        ("nf_acc".into(), h32(&p.nf_acc)),
        ("jobs".into(), h32(&p.jobs)),
        ("pending".into(), h32(&p.pending)),
        ("issued".into(), J::str(p.issued.to_string())),
        ("burned".into(), J::str(p.burned.to_string())),
        ("locked".into(), J::str(p.locked.to_string())),
    ];
    if let Some(l) = &p.locks {
        parts.push(("locks".into(), h32(l)));
    }
    if let Some(c) = &p.conds {
        parts.push(("conds".into(), h32(c)));
    }
    if let Some(r) = &p.nf_root {
        parts.push(("nf_root".into(), h32(r)));
    }
    if let Some(ch) = &p.channels {
        parts.push(("channels".into(), h32(ch)));
    }
    if let Some(b) = &p.bonds {
        parts.push(("bonds".into(), h32(b)));
    }
    if let Some(rv) = &p.rollups {
        parts.push(("rollups".into(), h32(rv)));
    }
    J::Obj(vec![
        ("ok".into(), J::Bool(true)),
        ("height".into(), J::num(p.height as u64)),
        ("header".into(), J::str(hex::encode(b.header.bytes()))),
        ("tx_root".into(), h32(&b.tx_root())),
        ("parts".into(), J::Obj(parts)),
    ])
}

/// The node's own wallet, shared by the faucet and the swap server.
pub type SharedWallet = Arc<Mutex<crate::wallet::Wallet>>;

/// Prove a payment from one of the node wallet's notes, without holding the node's lock
/// while proving: the note and its path are read under the lock, the proof is made outside
/// it with mining paused, and the transaction is pooled and announced. `to` is an optional
/// payment, `deposit` an optional escrow or lock. Change is remembered. Returns the
/// transaction, the first nullifier, and the payment's note string if there is one.
#[allow(clippy::too_many_arguments)]
pub fn wallet_spend(
    shared: &Shared,
    w: &mut crate::wallet::Wallet,
    to: Option<(Word8, u64)>,
    to_key: Option<&[u8]>,
    fee: u64,
    deposit: Option<crate::job::Deposit>,
    memo: Vec<u8>,
) -> Result<(crate::tx::Tx, Word8, Option<String>), (u16, String)> {
    use crate::spend::{InputNote, OutputNote, SpendWitness};
    use rand::Rng;
    let pay = to.map(|t| t.1).unwrap_or(0);
    let need = pay as u128 + fee as u128 + deposit.as_ref().map(|d| d.amount() as u128).unwrap_or(0);
    let input = {
        let n = lock(shared);
        let busy = n.pool_nullifiers();
        let mut coins: Vec<_> = w.unspent(&n.chain).into_iter().filter(|c| !busy.contains(&c.nf) && c.v as u128 >= need).collect();
        coins.sort_by(|a, b| a.v.cmp(&b.v));
        // the smallest note that covers it, so large notes stay whole for large requests
        let c = coins.into_iter().next().ok_or((503, "this node has no free coins for that right now; it refills as it mines".to_string()))?;
        InputNote { sk: w.sk, v: c.v, rho: c.rho, pos: c.pos, path: n.chain.state.tree.path(c.pos) }
    };
    let mut rng = rand::thread_rng();
    let (to_apk, to_v) = to.unwrap_or((w.a_pk(), 0));
    let out_pay = OutputNote { a_pk: to_apk, v: to_v, rho: rng.gen() };
    let change = OutputNote { a_pk: w.a_pk(), v: (input.v as u128 - need) as u64, rho: rng.gen() };
    let memo = crate::deliver::memo_for(&w.sk, &[out_pay.clone(), change.clone()], [to_key, None], &memo).map_err(|e| (400, e))?;
    let wit = SpendWitness { inputs: [input, InputNote::dummy()], outputs: [out_pay.clone(), change.clone()], dummy: [false, true] };
    let bind = crate::tx::bind_of(fee, &deposit, &memo);
    let (pi, proof) = {
        let _quiet = crate::node::pause_mining();
        let profile = lock(shared).chain.params.proof;
        crate::spend::prove_for(&profile, &wit, bind).map_err(|e| (500, e))?
    };
    let tx = crate::tx::Tx::Spend(crate::tx::Spend { anchor: pi.root, nf: pi.nf, cm_out: pi.cm_out, dummy: [false, true], fee, deposit, memo, proof: proof.to_bytes() });
    lock(shared).submit_local(tx.clone()).map_err(|e| (500, e))?;
    w.notes.push((change.v, change.rho));
    if to.is_none() {
        w.notes.push((0, out_pay.rho));
    }
    let _ = w.save();
    Ok((tx, pi.nf[0], to.map(|(a, v)| crate::wallet::encode_note(&a, v, &out_pay.rho))))
}

/// Testnet coins for anyone who asks, a few at a time: a private payment from the node's
/// own wallet, whose note goes back to the asker.
pub struct Faucet {
    wallet: SharedWallet,
    pub amount: u64,
    seen: Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl Faucet {
    pub fn new(wallet: SharedWallet, amount: u64) -> Arc<Faucet> {
        Arc::new(Faucet { wallet, amount, seen: Mutex::new(Default::default()) })
    }

    fn throttle(&self, keys: &[(String, u64)]) -> Result<(), String> {
        let now = std::time::Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, t| now.duration_since(*t).as_secs() < 24 * 3600);
        for (k, secs) in keys {
            if let Some(t) = seen.get(k) {
                let waited = now.duration_since(*t).as_secs();
                if waited < *secs {
                    return Err(format!("the faucet gives once per {} minutes here; try again in {} min", secs / 60, (secs - waited).div_ceil(60)));
                }
            }
        }
        for (k, _) in keys {
            seen.insert(k.clone(), now);
        }
        Ok(())
    }

    pub fn give(&self, shared: &Shared, address: &str, client: &str) -> Result<J, (u16, String)> {
        // either kind of address; to a delivery address the coins also travel on chain
        let (a_pk, key) = crate::deliver::parse_any_address(address).map_err(|e| (400, e))?;
        self.throttle(&[(format!("ip {client}"), 600), (format!("addr {}", encode_address(&a_pk)), 3600), ("all".into(), 5)]).map_err(|e| (429, e))?;
        let mut w = self.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let fee = lock(shared).chain.params.default_fee;
        let (tx, _, note) = wallet_spend(shared, &mut w, Some((a_pk, self.amount)), key.as_deref(), fee, None, b"faucet".to_vec())
            .map_err(|(c, e)| if c == 503 { (503, "the faucet is empty for now; it refills as its node mines".to_string()) } else { (c, e) })?;
        Ok(J::Obj(vec![
            ("ok".into(), J::Bool(true)),
            ("note".into(), J::str(note.unwrap_or_default())),
            ("value".into(), J::num(self.amount)),
            ("txid".into(), J::str(hash_hex(&tx.id()))),
        ]))
    }
}

fn respond(s: &mut TcpStream, code: u16, body: &str, head_only: bool) {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    if !head_only {
        let _ = s.write_all(body.as_bytes());
    }
}

/// The public API: `GET /status`; for wallets `GET /api/note?cm=`, `GET /api/spent?nf=`,
/// `GET /api/lock?id=` or `?hash=`, `GET /api/envelopes?from=` (notes delivered on chain),
/// `GET /api/headers?from=` and `GET /api/state` (for light clients), `GET /api/cond?id=`,
/// `POST /api/tx` (the transaction's bytes); when a
/// faucet is given, `POST /api/faucet` (an address); and when a swap server is given,
/// `GET /api/swap/info`, `POST /api/swap/in`, `POST /api/swap/out`, `GET /api/swap?hash=`.
/// Read-only except for transactions, which carry their own proofs, and the faucet and
/// swaps, which spend only the node's own coins.
pub fn serve_public(shared: Shared, bind: &str, port: u16, faucet: Option<Arc<Faucet>>) -> Result<u16, String> {
    serve_public_with(shared, bind, port, faucet, None)
}

pub fn serve_public_with(shared: Shared, bind: &str, port: u16, faucet: Option<Arc<Faucet>>, swap: Option<Arc<crate::swap::Swap>>) -> Result<u16, String> {
    // "::" listens on IPv6 and IPv4 together; where the system has no IPv6, IPv4 alone
    let l = TcpListener::bind((bind, port))
        .or_else(|e| if bind == "::" { TcpListener::bind(("0.0.0.0", port)) } else { Err(e) })
        .map_err(|e| format!("status bind {bind}:{port}: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let open = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            if open.load(Ordering::SeqCst) >= MAX_CONNECTIONS * 4 {
                continue;
            }
            open.fetch_add(1, Ordering::SeqCst);
            let (sh, open, faucet, swap) = (shared.clone(), open.clone(), faucet.clone(), swap.clone());
            thread::spawn(move || {
                let _ = s.set_write_timeout(Some(Duration::from_secs(REQUEST_SECS)));
                match read_http(&mut s, crate::params::TX_BYTES_CAP + 1024) {
                    Err(e) => respond(&mut s, 400, &err_json(&e).to_json(), false),
                    Ok(req) => {
                        let head_only = req.method == "HEAD";
                        let (code, body) = match (req.method.as_str(), req.path.as_str()) {
                            ("GET" | "HEAD", "/status" | "/") => (200, status(&sh)),
                            ("GET", "/api/note") => match hex_word8(req.param("cm")) {
                                Ok(cm) => (200, note_info(&sh, &cm)),
                                Err((c, e)) => (c, err_json(&e)),
                            },
                            ("GET", "/api/spent") => match hex_word8(req.param("nf")) {
                                Ok(nf) => {
                                    let n = lock(&sh);
                                    // with a proof against the nullifier tree, for light clients
                                    let st = &n.chain.state;
                                    let p = st.nf_tree.prove(&nf);
                                    let proof = J::Obj(vec![
                                        ("root".into(), J::str(word8_hex(&st.nf_tree.root()))),
                                        ("index".into(), J::num(p.index)),
                                        ("value".into(), J::str(word8_hex(&p.value))),
                                        ("next".into(), J::str(word8_hex(&p.next))),
                                        ("path".into(), J::Arr(p.path.iter().map(|w| J::str(word8_hex(w))).collect())),
                                    ]);
                                    (200, J::Obj(vec![("spent".into(), J::Bool(st.nullifiers.contains(&nf))), ("pending".into(), J::Bool(n.pool_nullifiers().contains(&nf))), ("proof".into(), proof)]))
                                }
                                Err((c, e)) => (c, err_json(&e)),
                            },
                            ("GET", "/api/lock") => {
                                let id = req.param("id").map(|x| hex_word8(Some(x)));
                                let hash = req.param("hash").map(|x| hex_word8(Some(x)));
                                match (id, hash) {
                                    (Some(Ok(w)), _) => (200, lock_info(&sh, &crate::hash::words_to_bytes(&w))),
                                    (None, Some(Ok(w))) => (200, locks_for_hash(&sh, &crate::hash::words_to_bytes(&w))),
                                    _ => (400, err_json("give id= or hash=, 64 hex characters")),
                                }
                            }
                            ("GET", "/api/channel") => {
                                let id = req.param("id").map(|x| hex_word8(Some(x)));
                                let tip = req.param("tip").map(|x| hex_word8(Some(x)));
                                match (id, tip) {
                                    (Some(Ok(w)), _) => (200, channel_info(&sh, &crate::hash::words_to_bytes(&w))),
                                    (None, Some(Ok(w))) => (200, channels_for_tip(&sh, &crate::hash::words_to_bytes(&w))),
                                    _ => (400, err_json("give id= or tip=, 64 hex characters")),
                                }
                            }
                            ("GET", "/api/bond") => match req.param("id").map(|x| hex::decode(x).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())) {
                                Some(Some(id)) => (200, bond_info(&sh, &id)),
                                _ => (400, err_json("id= takes 64 hex characters")),
                            },
                            ("GET", "/api/rollup") => match req.param("id").map(|x| hex::decode(x).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())) {
                                Some(Some(id)) => (200, rollup_info(&sh, &id)),
                                _ => (400, err_json("id= takes 64 hex characters")),
                            },
                            ("GET", "/api/signaling") => (200, signaling_info(&sh)),
                            ("GET", "/api/cond") => match req.param("id").map(|x| hex::decode(x).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())) {
                                Some(Some(id)) => (200, cond_info(&sh, &id)),
                                _ => (400, err_json("id= takes 64 hex characters")),
                            },
                            ("GET", "/api/headers") => match req.param("from").unwrap_or("1").parse::<u32>() {
                                Ok(from) => (200, headers_from(&sh, from)),
                                Err(_) => (400, err_json("from= takes a height")),
                            },
                            ("GET", "/api/state") => (200, state_commitment(&sh)),
                            ("GET", "/api/envelopes") => match req.param("from").unwrap_or("0").parse::<u32>() {
                                Ok(from) => (200, envelopes(&sh, from)),
                                Err(_) => (400, err_json("from= takes a height")),
                            },
                            ("POST", "/api/tx") => {
                                let r = submit_tx(&sh, &req.body);
                                let busy = r.get("error").and_then(|e| e.as_str()) == Some(BUSY);
                                (if matches!(r.get("ok"), Some(J::Bool(true))) { 200 } else if busy { 429 } else { 400 }, r)
                            }
                            (m, p) if p.starts_with("/api/swap") => match &swap {
                                None => (404, err_json("no swap server on this node")),
                                Some(sw) => {
                                    let r = match (m, p) {
                                        ("GET", "/api/swap/info") => Ok(sw.info_with(&sh)),
                                        ("POST", "/api/swap/in") => J::parse(&req.body).map_err(|e| (400, e)).and_then(|b| sw.open_in(&sh, &b, &req.client())),
                                        ("POST", "/api/swap/out") => J::parse(&req.body).map_err(|e| (400, e)).and_then(|b| sw.open_out(&sh, &b, &req.client())),
                                        ("GET", "/api/swap") => hex_word8(req.param("hash")).and_then(|h| sw.get(&crate::hash::words_to_bytes(&h))),
                                        ("POST", "/api/swap/fake/pay") => J::parse(&req.body).map_err(|e| (400, e)).and_then(|b| sw.fake_call("pay", &b)),
                                        ("POST", "/api/swap/fake/invoice") => J::parse(&req.body).map_err(|e| (400, e)).and_then(|b| sw.fake_call("invoice", &b)),
                                        _ => Err((404, "unknown swap call".to_string())),
                                    };
                                    match r {
                                        Ok(j) => (200, j),
                                        Err((c, e)) => (c, err_json(&e)),
                                    }
                                }
                            },
                            ("POST", "/api/faucet") => match &faucet {
                                None => (404, err_json("no faucet on this node")),
                                Some(f) => {
                                    let addr = String::from_utf8_lossy(&req.body).to_string();
                                    match f.give(&sh, &addr, &req.client()) {
                                        Ok(j) => (200, j),
                                        Err((c, e)) => (c, err_json(&e)),
                                    }
                                }
                            },
                            ("OPTIONS", _) => (204, J::Null),
                            _ => (404, err_json("try GET /status")),
                        };
                        let text = if code == 204 { String::new() } else { body.to_json() };
                        respond(&mut s, code, &text, head_only || code == 204);
                    }
                }
                open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(port)
}

/// The payout address a template pays, for display.
pub fn payout_address(rpc: &Rpc) -> String {
    encode_address(&rpc.payout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let src = br#"{"jsonrpc":"1.0","id":"x\"1","method":"submitauxblock","params":["ab", 12, -3.5e2, true, null, [], {}]}"#;
        let v = J::parse(src).unwrap();
        assert_eq!(v.get("method").and_then(|m| m.as_str()), Some("submitauxblock"));
        assert_eq!(J::parse(v.to_json().as_bytes()).unwrap(), v);
        assert!(J::parse(b"{\"a\":").is_err());
        assert!(J::parse(&[b'['; 100]).is_err());
        assert!(J::parse(b"\"\\u12\"").is_err());
    }

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn difficulty_scale() {
        assert!((difficulty(0x1d00ffff) - 1.0).abs() < 1e-9);
        assert!(difficulty(0x1c00ffff) > 255.0);
    }
}
