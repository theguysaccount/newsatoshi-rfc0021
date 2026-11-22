//! Swaps with Lightning: coins here for a Lightning payment, or a Lightning invoice paid
//! with coins here, and no custodian on either side.
//!
//! In (Lightning → here). The buyer's page makes a secret, keeps it, and sends its hash
//! with an address. The server answers with a hold invoice for that hash. When the
//! buyer's Lightning wallet (any of them) pays it, the payment is held, not settled,
//! because only the buyer knows the secret. The server then locks coins on this chain to
//! the same hash, payable to the buyer's address until a timeout and back to the server
//! after it. The buyer claims them by publishing the secret; the server reads it from the
//! chain and settles the Lightning payment with it. If the buyer never claims, the lock
//! refunds the server and the held payment is cancelled back to the buyer. A server that
//! has seen the secret publishes the claim itself, so a buyer who goes offline still gets
//! the coins.
//!
//! Out (here → Lightning). The payer hands the server an invoice. The server quotes the
//! coins, its address and a timeout; the payer locks coins to the invoice's own payment
//! hash, payable to the server until the timeout and back to the payer after it. Once the
//! lock is in a block, the server pays the invoice; paying reveals the preimage, which
//! claims the lock. If the payment fails, the lock goes back to the payer.
//!
//! In both directions the secret that completes one payment completes the other: neither
//! side can end up holding nothing, and the server never holds anyone's coins.
//!
//! Timing. In: a buyer can claim until the lock's timeout (`in_lock_blocks` blocks here),
//! so the held Lightning payment must stay held at least that long (`invoice_cltv` blocks
//! of the Lightning chain, with room to spare). Out: the server pays only while
//! `out_min_left` blocks of the payer's lock remain, and limits the payment to resolve
//! within `pay_cltv_limit` Lightning blocks, so the preimage arrives before the lock
//! times out.

use crate::hash::{sha256, Word8};
use crate::job::{Action, Deposit};
use crate::lock::{lock_id, LockPost};
use crate::node::{lock as node_lock, Shared};
use crate::params::{COIN, DEFAULT_FEE};
use crate::rpc::{base64, wallet_spend, SharedWallet, J};
use crate::tx::Tx;
use crate::wallet::{encode_address, parse_address};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- Lightning ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceState {
    Open,
    Accepted,
    Settled,
    Canceled,
}

#[derive(Clone, Debug)]
pub struct Decoded {
    pub hash: [u8; 32],
    pub sats: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayState {
    Unknown,
    InFlight,
    Succeeded([u8; 32]),
    Failed(String),
}

#[derive(Clone, Debug, Default)]
pub struct LnInfo {
    pub pubkey: String,
    pub alias: String,
    pub network: String,
    pub synced: bool,
    pub uri: String,
    /// What the node's channels can still receive and send, in satoshis.
    pub can_receive: u64,
    pub can_send: u64,
}

/// What the swap server needs from a Lightning node.
pub trait Lightning: Send + Sync {
    fn info(&self) -> Result<LnInfo, String>;
    /// An invoice for `hash` whose payment is held, not settled, until `settle`.
    fn hold_invoice(
        &self,
        hash: &[u8; 32],
        sats: u64,
        memo: &str,
        expiry_secs: u64,
        cltv: u32,
    ) -> Result<String, String>;
    fn invoice_state(&self, hash: &[u8; 32]) -> Result<InvoiceState, String>;
    fn settle(&self, preimage: &[u8; 32]) -> Result<(), String>;
    fn cancel(&self, hash: &[u8; 32]) -> Result<(), String>;
    fn decode(&self, invoice: &str) -> Result<Decoded, String>;
    /// Pay an invoice and wait for the outcome, up to `timeout_secs`.
    fn pay(&self, invoice: &str, max_fee_sats: u64, cltv_limit: u32, timeout_secs: u32)
        -> PayState;
    /// What the node knows of an earlier payment to `hash`.
    fn payment(&self, hash: &[u8; 32]) -> PayState;
}

fn jstr<'a>(j: &'a J, k: &str) -> Option<&'a str> {
    match j.get(k) {
        Some(J::Str(s)) | Some(J::Num(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn jnum(j: &J, k: &str) -> u64 {
    jstr(j, k).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "expected 64 hex characters".to_string())
}

/// LND's REST interface, plain HTTP on a private network (`no-rest-tls`), authorised by a
/// macaroon. Only what swaps need: hold invoices, decoding, paying, and balances.
pub struct Lnd {
    addr: String,
    macaroon: String,
}

impl Lnd {
    pub fn new(addr: &str, macaroon_hex: &str) -> Lnd {
        Lnd {
            addr: addr.to_string(),
            macaroon: macaroon_hex.trim().to_string(),
        }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&J>,
        timeout: Duration,
    ) -> Result<J, String> {
        let text = body.map(|b| b.to_json()).unwrap_or_default();
        let sa = self
            .addr
            .to_socket_addrs()
            .map_err(|e| format!("lightning node {}: {e}", self.addr))?
            .next()
            .ok_or("lightning node address")?;
        let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(10))
            .map_err(|e| format!("lightning node {}: {e}", self.addr))?;
        let _ = s.set_read_timeout(Some(timeout));
        let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nGrpc-Metadata-macaroon: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            self.macaroon,
            text.len()
        );
        s.write_all(head.as_bytes())
            .and_then(|_| s.write_all(text.as_bytes()))
            .map_err(|e| e.to_string())?;
        let mut raw = vec![];
        s.read_to_end(&mut raw)
            .map_err(|e| format!("lightning node: {e}"))?;
        let end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("lightning node: bad response")?;
        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
        let code: u16 = head.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
        let mut body = raw[end + 4..].to_vec();
        if head.contains("transfer-encoding: chunked") {
            body = dechunk(&body);
        }
        // a stream sends one JSON object per line; the last one is the outcome
        let text = String::from_utf8_lossy(&body);
        let last = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .last()
            .unwrap_or("{}");
        let j = J::parse(last.as_bytes()).map_err(|e| format!("lightning node: {e}"))?;
        let err = j.get("error").cloned().unwrap_or(J::Null);
        if code != 200 || !matches!(err, J::Null) {
            let msg = jstr(&j, "message")
                .or_else(|| jstr(&err, "message"))
                .unwrap_or("error")
                .to_string();
            return Err(format!("lightning node ({code}): {msg}"));
        }
        Ok(j.get("result").cloned().unwrap_or(j))
    }
}

fn dechunk(b: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let Some(nl) = b[i..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&b[i..i + nl])
                .split(';')
                .next()
                .unwrap_or("0")
                .trim(),
            16,
        )
        .unwrap_or(0);
        i += nl + 2;
        if size == 0 || i + size > b.len() {
            break;
        }
        out.extend_from_slice(&b[i..i + size]);
        i += size + 2;
    }
    out
}

impl Lightning for Lnd {
    fn info(&self) -> Result<LnInfo, String> {
        let t = Duration::from_secs(15);
        let gi = self.call("GET", "/v1/getinfo", None, t)?;
        let bal = self.call("GET", "/v1/balance/channels", None, t)?;
        let sat = |k: &str| bal.get(k).map(|x| jnum(x, "sat")).unwrap_or(0);
        let network = match gi.get("chains") {
            Some(J::Arr(c)) => c
                .first()
                .and_then(|x| jstr(x, "network"))
                .unwrap_or("")
                .to_string(),
            _ => String::new(),
        };
        let uri = match gi.get("uris") {
            Some(J::Arr(u)) => u.first().and_then(|x| x.as_str()).unwrap_or("").to_string(),
            _ => String::new(),
        };
        Ok(LnInfo {
            pubkey: jstr(&gi, "identity_pubkey").unwrap_or("").into(),
            alias: jstr(&gi, "alias").unwrap_or("").into(),
            network,
            synced: matches!(gi.get("synced_to_chain"), Some(J::Bool(true))),
            uri,
            can_receive: sat("remote_balance"),
            can_send: sat("local_balance"),
        })
    }

    fn hold_invoice(
        &self,
        hash: &[u8; 32],
        sats: u64,
        memo: &str,
        expiry_secs: u64,
        cltv: u32,
    ) -> Result<String, String> {
        let req = J::Obj(vec![
            ("memo".into(), J::str(memo)),
            ("hash".into(), J::str(base64(hash))),
            ("value".into(), J::str(sats.to_string())),
            ("expiry".into(), J::str(expiry_secs.to_string())),
            ("cltv_expiry".into(), J::str(cltv.to_string())),
        ]);
        let r = self.call(
            "POST",
            "/v2/invoices/hodl",
            Some(&req),
            Duration::from_secs(20),
        )?;
        jstr(&r, "payment_request")
            .map(String::from)
            .ok_or_else(|| "lightning node returned no invoice".into())
    }

    fn invoice_state(&self, hash: &[u8; 32]) -> Result<InvoiceState, String> {
        let r = self.call(
            "GET",
            &format!("/v1/invoice/{}", hex::encode(hash)),
            None,
            Duration::from_secs(15),
        )?;
        Ok(match jstr(&r, "state").unwrap_or("") {
            "ACCEPTED" => InvoiceState::Accepted,
            "SETTLED" => InvoiceState::Settled,
            "CANCELED" => InvoiceState::Canceled,
            _ => InvoiceState::Open,
        })
    }

    fn settle(&self, preimage: &[u8; 32]) -> Result<(), String> {
        let req = J::Obj(vec![("preimage".into(), J::str(base64(preimage)))]);
        self.call(
            "POST",
            "/v2/invoices/settle",
            Some(&req),
            Duration::from_secs(20),
        )
        .map(|_| ())
    }

    fn cancel(&self, hash: &[u8; 32]) -> Result<(), String> {
        let req = J::Obj(vec![("payment_hash".into(), J::str(base64(hash)))]);
        self.call(
            "POST",
            "/v2/invoices/cancel",
            Some(&req),
            Duration::from_secs(20),
        )
        .map(|_| ())
    }

    fn decode(&self, invoice: &str) -> Result<Decoded, String> {
        if !invoice.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("that is not a Lightning invoice".into());
        }
        let r = self.call(
            "GET",
            &format!("/v1/payreq/{invoice}"),
            None,
            Duration::from_secs(15),
        )?;
        Ok(Decoded {
            hash: hex32(jstr(&r, "payment_hash").unwrap_or(""))?,
            sats: jnum(&r, "num_satoshis"),
            expires_at: jnum(&r, "timestamp") + jnum(&r, "expiry"),
        })
    }

    fn pay(
        &self,
        invoice: &str,
        max_fee_sats: u64,
        cltv_limit: u32,
        timeout_secs: u32,
    ) -> PayState {
        let req = J::Obj(vec![
            ("payment_request".into(), J::str(invoice)),
            ("timeout_seconds".into(), J::num(timeout_secs)),
            ("fee_limit_sat".into(), J::str(max_fee_sats.to_string())),
            ("cltv_limit".into(), J::num(cltv_limit)),
            ("no_inflight_updates".into(), J::Bool(true)),
        ]);
        match self.call(
            "POST",
            "/v2/router/send",
            Some(&req),
            Duration::from_secs(timeout_secs as u64 + 30),
        ) {
            Ok(p) => payment_state(&p),
            Err(e)
                if e.contains("already paid")
                    || e.contains("already exists")
                    || e.contains("in transition") =>
            {
                match self.decode(invoice) {
                    Ok(d) => self.payment(&d.hash),
                    Err(_) => PayState::Unknown,
                }
            }
            Err(e) => PayState::Failed(e),
        }
    }

    fn payment(&self, hash: &[u8; 32]) -> PayState {
        let want = hex::encode(hash);
        match self.call(
            "GET",
            "/v1/payments?include_incomplete=true&reversed=true&max_payments=500",
            None,
            Duration::from_secs(20),
        ) {
            Ok(r) => match r.get("payments") {
                Some(J::Arr(ps)) => {
                    let mine: Vec<&J> = ps
                        .iter()
                        .filter(|p| jstr(p, "payment_hash") == Some(want.as_str()))
                        .collect();
                    if let Some(p) = mine.iter().find(|p| jstr(p, "status") == Some("SUCCEEDED")) {
                        return payment_state(p);
                    }
                    if mine.iter().any(|p| jstr(p, "status") == Some("IN_FLIGHT")) {
                        return PayState::InFlight;
                    }
                    mine.last()
                        .map(|p| payment_state(p))
                        .unwrap_or(PayState::Unknown)
                }
                _ => PayState::Unknown,
            },
            Err(_) => PayState::Unknown,
        }
    }
}

fn payment_state(p: &J) -> PayState {
    match jstr(p, "status").unwrap_or("") {
        "SUCCEEDED" => match jstr(p, "payment_preimage").map(hex32) {
            Some(Ok(x)) => PayState::Succeeded(x),
            _ => PayState::Unknown,
        },
        "FAILED" => PayState::Failed(
            jstr(p, "failure_reason")
                .unwrap_or("payment failed")
                .to_string(),
        ),
        "IN_FLIGHT" | "INITIATED" => PayState::InFlight,
        _ => PayState::Unknown,
    }
}

/// Lightning in memory, for tests: hold invoices a test can pay, invoices of a payee the
/// fake can pay. Invoices read `lnfake1<hash>x<sats>x<expiry>`. Nothing moves.
#[derive(Default)]
pub struct FakeLn {
    inner: Mutex<FakeInner>,
}

#[derive(Default)]
struct FakeInner {
    held: HashMap<[u8; 32], (u64, InvoiceState, Option<[u8; 32]>)>,
    payees: HashMap<[u8; 32], [u8; 32]>,
    paid: HashMap<[u8; 32], PayState>,
    fail: bool,
}

impl FakeLn {
    pub fn new() -> Arc<FakeLn> {
        Arc::new(FakeLn::default())
    }
    fn inner(&self) -> std::sync::MutexGuard<'_, FakeInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// A payer's wallet pays a hold invoice: the payment is now held.
    pub fn payer_pays(&self, invoice: &str) -> Result<(), String> {
        let d = self.decode(invoice)?;
        let mut i = self.inner();
        let e = i.held.get_mut(&d.hash).ok_or("no such invoice")?;
        if e.1 != InvoiceState::Open {
            return Err("invoice not open".into());
        }
        e.1 = InvoiceState::Accepted;
        Ok(())
    }
    /// The preimage a payer learns when a held payment settles.
    pub fn payer_receipt(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.inner().held.get(hash).and_then(|e| e.2)
    }
    /// An invoice from a payee somewhere on Lightning; returns it and its preimage.
    pub fn payee_invoice(&self, sats: u64) -> (String, [u8; 32]) {
        let p: [u8; 32] = rand::random();
        let h = sha256(&p);
        self.inner().payees.insert(h, p);
        (
            format!("lnfake1{}x{sats}x{}", hex::encode(h), now() + 3600),
            p,
        )
    }
    pub fn set_fail_payments(&self, fail: bool) {
        self.inner().fail = fail;
    }
    pub fn held_state(&self, hash: &[u8; 32]) -> Option<InvoiceState> {
        self.inner().held.get(hash).map(|e| e.1)
    }
}

impl Lightning for FakeLn {
    fn info(&self) -> Result<LnInfo, String> {
        Ok(LnInfo {
            pubkey: "02fake".into(),
            alias: "fake".into(),
            network: "fake".into(),
            synced: true,
            uri: String::new(),
            can_receive: 10_000_000,
            can_send: 10_000_000,
        })
    }
    fn hold_invoice(
        &self,
        hash: &[u8; 32],
        sats: u64,
        _memo: &str,
        expiry_secs: u64,
        _cltv: u32,
    ) -> Result<String, String> {
        self.inner()
            .held
            .insert(*hash, (sats, InvoiceState::Open, None));
        Ok(format!(
            "lnfake1{}x{sats}x{}",
            hex::encode(hash),
            now() + expiry_secs
        ))
    }
    fn invoice_state(&self, hash: &[u8; 32]) -> Result<InvoiceState, String> {
        self.inner()
            .held
            .get(hash)
            .map(|e| e.1)
            .ok_or_else(|| "no such invoice".into())
    }
    fn settle(&self, preimage: &[u8; 32]) -> Result<(), String> {
        let h = sha256(preimage);
        let mut i = self.inner();
        let e = i.held.get_mut(&h).ok_or("no such invoice")?;
        match e.1 {
            InvoiceState::Accepted => {
                e.1 = InvoiceState::Settled;
                e.2 = Some(*preimage);
                Ok(())
            }
            InvoiceState::Settled => Err("invoice already settled".into()),
            _ => Err("invoice not accepted".into()),
        }
    }
    fn cancel(&self, hash: &[u8; 32]) -> Result<(), String> {
        let mut i = self.inner();
        let e = i.held.get_mut(hash).ok_or("no such invoice")?;
        if e.1 == InvoiceState::Settled {
            return Err("invoice already settled".into());
        }
        e.1 = InvoiceState::Canceled;
        Ok(())
    }
    fn decode(&self, invoice: &str) -> Result<Decoded, String> {
        let rest = invoice
            .strip_prefix("lnfake1")
            .ok_or("that is not a Lightning invoice")?;
        let mut it = rest.split('x');
        let hash = hex32(it.next().unwrap_or(""))?;
        let sats = it
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or("bad invoice")?;
        let expires_at = it
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or("bad invoice")?;
        Ok(Decoded {
            hash,
            sats,
            expires_at,
        })
    }
    fn pay(&self, invoice: &str, _max_fee: u64, _cltv: u32, _timeout: u32) -> PayState {
        let Ok(d) = self.decode(invoice) else {
            return PayState::Failed("bad invoice".into());
        };
        let mut i = self.inner();
        let r = if i.fail {
            PayState::Failed("no route".into())
        } else {
            match i.payees.get(&d.hash) {
                Some(p) => PayState::Succeeded(*p),
                None => PayState::Failed("unknown payee".into()),
            }
        };
        i.paid.insert(d.hash, r.clone());
        r
    }
    fn payment(&self, hash: &[u8; 32]) -> PayState {
        self.inner()
            .paid
            .get(hash)
            .cloned()
            .unwrap_or(PayState::Unknown)
    }
}

// ---- the swap server ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SwapCfg {
    /// The price: satoshis per coin. Set by whoever runs the server.
    pub sats_per_coin: u64,
    pub min_sats: u64,
    pub max_sats: u64,
    /// The server's fee, in parts per million, both directions.
    pub fee_ppm: u64,
    /// Blocks here that a buyer's lock stays claimable.
    pub in_lock_blocks: u32,
    /// Blocks here a payer's lock must run, and how many must remain when the server pays.
    pub out_lock_blocks: u32,
    pub out_min_left: u32,
    pub out_confirmations: u32,
    pub invoice_expiry_secs: u64,
    /// Final CLTV delta of hold invoices, in blocks of the Lightning chain.
    pub invoice_cltv: u32,
    /// Most Lightning blocks a payment may lock up, and the routing fee allowed.
    pub pay_cltv_limit: u32,
    pub pay_fee_ppm: u64,
    pub pay_fee_min_sats: u64,
    pub pay_timeout_secs: u32,
    /// How long a quote for paying an invoice stands without a lock.
    pub quote_secs: u64,
    /// What to call the Lightning network, for people.
    pub ln_network: String,
}

impl Default for SwapCfg {
    /// The test network's terms: one coin is 1,000 test satoshis, with one-minute blocks
    /// here and Mutinynet's thirty-second blocks on the Lightning side.
    fn default() -> Self {
        SwapCfg {
            sats_per_coin: 1_000,
            min_sats: 1_000,
            max_sats: 100_000,
            fee_ppm: 0,
            in_lock_blocks: 30,
            out_lock_blocks: 120,
            out_min_left: 60,
            out_confirmations: 1,
            invoice_expiry_secs: 900,
            invoice_cltv: 200,
            pay_cltv_limit: 80,
            pay_fee_ppm: 10_000,
            pay_fee_min_sats: 10,
            pay_timeout_secs: 60,
            quote_secs: 1800,
            ln_network: "Lightning".into(),
        }
    }
}

impl SwapCfg {
    /// Coins (base units) a buyer gets for `sats`, after the fee.
    pub fn coins_for(&self, sats: u64) -> u64 {
        (sats as u128 * COIN as u128 * (1_000_000 - self.fee_ppm.min(1_000_000)) as u128
            / (self.sats_per_coin as u128 * 1_000_000)) as u64
    }
    pub fn pay_fee_limit(&self, sats: u64) -> u64 {
        (sats * self.pay_fee_ppm / 1_000_000).max(self.pay_fee_min_sats)
    }
    /// Coins (base units) a payer locks to have `sats` paid, routing fee and fee included.
    pub fn coins_to_pay(&self, sats: u64) -> u64 {
        let total = (sats + self.pay_fee_limit(sats)) as u128
            * COIN as u128
            * (1_000_000 + self.fee_ppm) as u128;
        total.div_ceil(self.sats_per_coin as u128 * 1_000_000) as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum St {
    /// In: invoice issued, not yet paid.
    AwaitingPayment,
    /// In: payment held, coins locked to the buyer.
    Locked,
    /// Out: quote issued, waiting for the payer's lock.
    AwaitingLock,
    /// Out: lock found; paying the invoice.
    Paying,
    /// In: settled. Out: invoice paid and the lock claimed.
    Done,
    /// The lock went back: in to the server (the held payment cancelled), out to the payer.
    Refunded,
    /// Nothing happened before the quote or invoice ran out.
    Expired,
    Failed,
}

impl St {
    fn name(&self) -> &'static str {
        match self {
            St::AwaitingPayment => "awaiting_payment",
            St::Locked => "locked",
            St::AwaitingLock => "awaiting_lock",
            St::Paying => "paying",
            St::Done => "done",
            St::Refunded => "refunded",
            St::Expired => "expired",
            St::Failed => "failed",
        }
    }
    fn parse(s: &str) -> St {
        match s {
            "awaiting_payment" => St::AwaitingPayment,
            "locked" => St::Locked,
            "awaiting_lock" => St::AwaitingLock,
            "paying" => St::Paying,
            "done" => St::Done,
            "refunded" => St::Refunded,
            "expired" => St::Expired,
            _ => St::Failed,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rec {
    pub hash: [u8; 32],
    pub dir: Dir,
    pub state: St,
    pub sats: u64,
    pub coins: u64,
    pub invoice: String,
    /// In: the buyer's claim address. Out: the server's.
    pub addr: Word8,
    pub timeout: u32,
    pub lock: Option<[u8; 32]>,
    pub preimage: Option<[u8; 32]>,
    pub created: u64,
    pub updated: u64,
    /// Nothing more to watch.
    pub closed: bool,
    pub info: String,
}

impl Rec {
    fn to_json(&self) -> J {
        let o = |x: Option<[u8; 32]>| x.map(|v| J::str(hex::encode(v))).unwrap_or(J::Null);
        J::Obj(vec![
            ("hash".into(), J::str(hex::encode(self.hash))),
            (
                "dir".into(),
                J::str(if self.dir == Dir::In { "in" } else { "out" }),
            ),
            ("state".into(), J::str(self.state.name())),
            ("sats".into(), J::num(self.sats)),
            ("coins".into(), J::num(self.coins)),
            ("invoice".into(), J::str(&self.invoice)),
            ("address".into(), J::str(encode_address(&self.addr))),
            ("timeout".into(), J::num(self.timeout)),
            ("lock".into(), o(self.lock)),
            ("preimage".into(), o(self.preimage)),
            ("created".into(), J::num(self.created)),
            ("updated".into(), J::num(self.updated)),
            ("closed".into(), J::Bool(self.closed)),
            ("info".into(), J::str(&self.info)),
        ])
    }
    fn from_json(j: &J) -> Option<Rec> {
        let h = |k: &str| jstr(j, k).and_then(|s| hex32(s).ok());
        Some(Rec {
            hash: h("hash")?,
            dir: if jstr(j, "dir")? == "in" {
                Dir::In
            } else {
                Dir::Out
            },
            state: St::parse(jstr(j, "state")?),
            sats: jnum(j, "sats"),
            coins: jnum(j, "coins"),
            invoice: jstr(j, "invoice")?.to_string(),
            addr: parse_address(jstr(j, "address")?).ok()?,
            timeout: jnum(j, "timeout") as u32,
            lock: h("lock"),
            preimage: h("preimage"),
            created: jnum(j, "created"),
            updated: jnum(j, "updated"),
            closed: matches!(j.get("closed"), Some(J::Bool(true))),
            info: jstr(j, "info").unwrap_or("").to_string(),
        })
    }
    /// The public view. A preimage here is already public: the server learns it only
    /// from the chain (in) or from paying the invoice (out), and publishes it to claim.
    fn public(&self) -> J {
        self.to_json()
    }
}

type Err = (u16, String);

pub struct Swap {
    ln: Arc<dyn Lightning>,
    wallet: SharedWallet,
    pub cfg: SwapCfg,
    recs: Mutex<HashMap<[u8; 32], Rec>>,
    paying: Arc<Mutex<HashSet<[u8; 32]>>>,
    seen: Mutex<HashMap<String, Instant>>,
    info_cache: Mutex<Option<(Instant, Result<LnInfo, String>)>>,
    path: Option<PathBuf>,
    /// Set on a regtest node that swaps with Lightning in memory, for trying the flow.
    fake: Option<Arc<FakeLn>>,
}

impl Swap {
    pub fn new(
        ln: Arc<dyn Lightning>,
        wallet: SharedWallet,
        cfg: SwapCfg,
        path: Option<PathBuf>,
    ) -> Arc<Swap> {
        let mut recs = HashMap::new();
        if let Some(p) = &path {
            if let Ok(text) = std::fs::read(p) {
                if let Ok(J::Arr(v)) = J::parse(&text) {
                    for r in v.iter().filter_map(Rec::from_json) {
                        recs.insert(r.hash, r);
                    }
                }
            }
        }
        Arc::new(Swap {
            ln,
            wallet,
            cfg,
            recs: Mutex::new(recs),
            paying: Default::default(),
            seen: Default::default(),
            info_cache: Mutex::new(None),
            path,
            fake: None,
        })
    }

    /// A swap server whose Lightning lives in memory, with two extra calls that stand in
    /// for someone else's Lightning wallet: `POST /api/swap/fake/pay {"invoice"}` pays a
    /// hold invoice, and `POST /api/swap/fake/invoice {"sats"}` makes an invoice to pay.
    /// For regtest only: nothing real moves.
    pub fn new_fake(wallet: SharedWallet, cfg: SwapCfg) -> Arc<Swap> {
        let ln = FakeLn::new();
        let cfg = SwapCfg {
            ln_network: "fake".into(),
            ..cfg
        };
        Arc::new(Swap {
            ln: ln.clone(),
            wallet,
            cfg,
            recs: Default::default(),
            paying: Default::default(),
            seen: Default::default(),
            info_cache: Mutex::new(None),
            path: None,
            fake: Some(ln),
        })
    }

    /// The stand-in Lightning wallet's calls (fake mode only).
    pub fn fake_call(&self, what: &str, body: &J) -> Result<J, Err> {
        let ln = self
            .fake
            .as_ref()
            .ok_or((404, "not a demo swap server".to_string()))?;
        match what {
            "pay" => ln
                .payer_pays(
                    jstr(body, "invoice")
                        .unwrap_or("")
                        .trim()
                        .trim_start_matches("lightning:"),
                )
                .map(|_| J::Obj(vec![("ok".into(), J::Bool(true))]))
                .map_err(|e| (400, e)),
            "invoice" => {
                let (inv, _) = ln.payee_invoice(jnum(body, "sats").max(1));
                Ok(J::Obj(vec![
                    ("ok".into(), J::Bool(true)),
                    ("invoice".into(), J::str(inv)),
                ]))
            }
            _ => Err((404, "unknown call".into())),
        }
    }

    fn recs(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Rec>> {
        self.recs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, recs: &HashMap<[u8; 32], Rec>) {
        let Some(p) = &self.path else { return };
        let mut v: Vec<&Rec> = recs.values().collect();
        v.sort_by_key(|r| r.created);
        let text = J::Arr(v.iter().map(|r| r.to_json()).collect()).to_json();
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }

    fn update(&self, hash: &[u8; 32], f: impl FnOnce(&mut Rec)) {
        let mut recs = self.recs();
        if let Some(r) = recs.get_mut(hash) {
            f(r);
            r.updated = now();
        }
        self.save(&recs);
    }

    fn ln_info(&self) -> Result<LnInfo, String> {
        let mut c = self.info_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((t, r)) = c.as_ref() {
            if t.elapsed() < Duration::from_secs(10) {
                return r.clone();
            }
        }
        let r = self.ln.info();
        *c = Some((Instant::now(), r.clone()));
        r
    }

    fn throttle(&self, client: &str) -> Result<(), Err> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
        if let Some(t) = seen.get(client) {
            if now.duration_since(*t) < Duration::from_secs(5) {
                return Err((429, "one swap every few seconds, please".into()));
            }
        }
        seen.insert(client.to_string(), now);
        if self
            .recs()
            .values()
            .filter(|r| matches!(r.state, St::AwaitingPayment | St::AwaitingLock))
            .count()
            > 500
        {
            return Err((503, "too many open swaps; try again shortly".into()));
        }
        Ok(())
    }

    /// The largest lock the server could make now: its largest free note, less the fee.
    fn free_coins(&self, shared: &Shared) -> u64 {
        let w = self.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let n = node_lock(shared);
        let busy = n.pool_nullifiers();
        w.unspent(&n.chain)
            .into_iter()
            .filter(|c| !busy.contains(&c.nf))
            .map(|c| c.v)
            .max()
            .unwrap_or(0)
            .saturating_sub(DEFAULT_FEE)
    }

    /// `GET /api/swap/info`: the price, the limits, and whether each direction is open now.
    pub fn info_with(&self, shared: &Shared) -> J {
        let cfg = &self.cfg;
        let li = self.ln_info();
        let (ok, li) = match li {
            Ok(i) => (i.synced, i),
            Err(_) => (false, LnInfo::default()),
        };
        let coins = self.free_coins(shared);
        let in_max = cfg
            .max_sats
            .min(li.can_receive)
            .min((coins as u128 * cfg.sats_per_coin as u128 / COIN as u128) as u64);
        let out_max = cfg
            .max_sats
            .min(li.can_send.saturating_sub(cfg.pay_fee_limit(li.can_send)));
        J::Obj(vec![
            ("ok".into(), J::Bool(true)),
            ("network".into(), J::str(&cfg.ln_network)),
            ("lightning_up".into(), J::Bool(ok)),
            ("node".into(), J::str(&li.pubkey)),
            ("uri".into(), J::str(&li.uri)),
            ("alias".into(), J::str(&li.alias)),
            ("sats_per_coin".into(), J::num(cfg.sats_per_coin)),
            ("fee_ppm".into(), J::num(cfg.fee_ppm)),
            ("min_sats".into(), J::num(cfg.min_sats)),
            ("max_sats".into(), J::num(cfg.max_sats)),
            (
                "in".into(),
                J::Obj(vec![
                    ("available".into(), J::Bool(ok && in_max >= cfg.min_sats)),
                    ("max_sats".into(), J::num(in_max)),
                ]),
            ),
            (
                "out".into(),
                J::Obj(vec![
                    ("available".into(), J::Bool(ok && out_max >= cfg.min_sats)),
                    ("max_sats".into(), J::num(out_max)),
                ]),
            ),
            ("in_lock_blocks".into(), J::num(cfg.in_lock_blocks)),
            ("out_lock_blocks".into(), J::num(cfg.out_lock_blocks)),
        ])
    }

    /// `POST /api/swap/in` `{"hash", "address", "sats"}`: a hold invoice for the hash.
    pub fn open_in(&self, shared: &Shared, body: &J, client: &str) -> Result<J, Err> {
        let cfg = &self.cfg;
        let hash =
            hex32(jstr(body, "hash").unwrap_or("")).map_err(|e| (400, format!("hash: {e}")))?;
        let addr = parse_address(jstr(body, "address").unwrap_or("")).map_err(|e| (400, e))?;
        let sats = jnum(body, "sats");
        if sats < cfg.min_sats || sats > cfg.max_sats {
            return Err((
                400,
                format!("between {} and {} sats, please", cfg.min_sats, cfg.max_sats),
            ));
        }
        if self.recs().contains_key(&hash) {
            return Err((
                400,
                "that payment hash was used before; make a new secret".into(),
            ));
        }
        self.throttle(client)?;
        let coins = cfg.coins_for(sats);
        if coins == 0 || self.free_coins(shared) < coins {
            return Err((
                503,
                "the swap server has no coins to sell that many right now".into(),
            ));
        }
        let memo = format!("NEWSATOSHI test coins: {}", crate::params::fmt_coins(coins));
        let invoice = self
            .ln
            .hold_invoice(
                &hash,
                sats,
                &memo,
                cfg.invoice_expiry_secs,
                cfg.invoice_cltv,
            )
            .map_err(|e| (502, e))?;
        let t = now();
        let r = Rec {
            hash,
            dir: Dir::In,
            state: St::AwaitingPayment,
            sats,
            coins,
            invoice,
            addr,
            timeout: 0,
            lock: None,
            preimage: None,
            created: t,
            updated: t,
            closed: false,
            info: String::new(),
        };
        let j = r.public();
        let mut recs = self.recs();
        recs.insert(hash, r);
        self.save(&recs);
        Ok(j)
    }

    /// `POST /api/swap/out` `{"invoice"}`: the terms on which the server pays it.
    pub fn open_out(&self, shared: &Shared, body: &J, client: &str) -> Result<J, Err> {
        let cfg = &self.cfg;
        let inv = jstr(body, "invoice")
            .unwrap_or("")
            .trim()
            .trim_start_matches("lightning:")
            .to_ascii_lowercase();
        let d = self.ln.decode(&inv).map_err(|e| (400, e))?;
        if d.sats == 0 {
            return Err((400, "the invoice must name an amount".into()));
        }
        if d.sats < cfg.min_sats || d.sats > cfg.max_sats {
            return Err((
                400,
                format!("between {} and {} sats, please", cfg.min_sats, cfg.max_sats),
            ));
        }
        if d.expires_at < now() + 600 {
            return Err((
                400,
                "that invoice expires too soon; ask for a fresh one".into(),
            ));
        }
        if let Some(r) = self.recs().get(&d.hash) {
            if r.dir == Dir::Out && r.state == St::AwaitingLock {
                return Ok(r.public());
            }
            return Err((400, "that invoice was handled before".into()));
        }
        self.throttle(client)?;
        if let Ok(li) = self.ln_info() {
            if li.can_send < d.sats + cfg.pay_fee_limit(d.sats) {
                return Err((
                    503,
                    "the swap server cannot send that much over Lightning right now".into(),
                ));
            }
        }
        let addr = self.wallet.lock().unwrap_or_else(|e| e.into_inner()).a_pk();
        let tip = node_lock(shared).chain.height();
        let t = now();
        let r = Rec {
            hash: d.hash,
            dir: Dir::Out,
            state: St::AwaitingLock,
            sats: d.sats,
            coins: cfg.coins_to_pay(d.sats),
            invoice: inv,
            addr,
            timeout: tip + 1 + cfg.out_lock_blocks,
            lock: None,
            preimage: None,
            created: t,
            updated: t,
            closed: false,
            info: String::new(),
        };
        let j = r.public();
        let mut recs = self.recs();
        recs.insert(d.hash, r);
        self.save(&recs);
        Ok(j)
    }

    /// `GET /api/swap?hash=`.
    pub fn get(&self, hash: &[u8; 32]) -> Result<J, Err> {
        self.recs()
            .get(hash)
            .map(|r| r.public())
            .ok_or((404, "no swap for that hash".into()))
    }

    pub fn get_rec(&self, hash: &[u8; 32]) -> Option<Rec> {
        self.recs().get(hash).cloned()
    }

    /// Run `tick` every two seconds, for as long as the process lives.
    pub fn start(self: &Arc<Self>, shared: Shared) {
        let me = self.clone();
        std::thread::spawn(move || loop {
            me.tick(&shared);
            std::thread::sleep(Duration::from_secs(2));
        });
    }

    fn submit(shared: &Shared, tx: Tx) -> Result<(), String> {
        node_lock(shared).submit_local(tx).map(|_| ())
    }

    /// Move every open swap one step.
    pub fn tick(&self, shared: &Shared) {
        let open: Vec<Rec> = self
            .recs()
            .values()
            .filter(|r| !r.closed)
            .cloned()
            .collect();
        for r in open {
            match (r.dir, r.state) {
                (Dir::In, St::AwaitingPayment) => self.in_awaiting(shared, &r),
                (Dir::In, St::Locked | St::Done | St::Refunded) => self.in_locked(shared, &r),
                (Dir::Out, St::AwaitingLock) => self.out_awaiting(shared, &r),
                (Dir::Out, St::Paying) => self.out_paying(shared, &r),
                (Dir::Out, St::Done | St::Failed | St::Expired | St::Refunded) => {
                    self.out_settle(shared, &r)
                }
                _ => self.update(&r.hash, |x| x.closed = true),
            }
        }
    }

    fn in_awaiting(&self, shared: &Shared, r: &Rec) {
        match self.ln.invoice_state(&r.hash) {
            Ok(InvoiceState::Accepted) => self.make_lock(shared, r),
            Ok(InvoiceState::Canceled) => self.update(&r.hash, |x| {
                x.state = St::Expired;
                x.closed = true;
            }),
            Ok(InvoiceState::Settled) => self.update(&r.hash, |x| x.state = St::Done),
            Ok(InvoiceState::Open) => {
                if now() > r.created + self.cfg.invoice_expiry_secs + 60 {
                    let _ = self.ln.cancel(&r.hash);
                    self.update(&r.hash, |x| {
                        x.state = St::Expired;
                        x.closed = true;
                    });
                }
            }
            Err(e) => self.update(&r.hash, |x| x.info = e),
        }
    }

    fn make_lock(&self, shared: &Shared, r: &Rec) {
        let mut w = self.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let tip = node_lock(shared).chain.height();
        let post = LockPost {
            hash: r.hash,
            timeout: tip + 1 + self.cfg.in_lock_blocks,
            claim_addr: r.addr,
            refund_addr: w.a_pk(),
            amount: r.coins,
        };
        match wallet_spend(
            shared,
            &mut w,
            None,
            None,
            DEFAULT_FEE,
            Some(Deposit::Lock(post.clone())),
            b"swap".to_vec(),
        ) {
            Ok((_, nf0, _)) => {
                let id = lock_id(&post, &nf0);
                self.update(&r.hash, |x| {
                    x.state = St::Locked;
                    x.lock = Some(id);
                    x.timeout = post.timeout;
                    x.info = String::new();
                });
            }
            Err((_, e)) => {
                let _ = self.ln.cancel(&r.hash);
                self.update(&r.hash, |x| {
                    x.state = St::Failed;
                    x.closed = true;
                    x.info = format!("could not lock coins: {e}");
                });
            }
        }
    }

    /// In, after the lock: settle when the secret shows, finish the buyer's claim if they
    /// have not, refund after the timeout otherwise.
    fn in_locked(&self, shared: &Shared, r: &Rec) {
        let Some(id) = r.lock else { return };
        let (end, open, confirmed_end, tip) = {
            let n = node_lock(shared);
            let pool = n.pool_state();
            (
                pool.lock_ends.get(&id).cloned(),
                pool.locks.get(&id).cloned(),
                n.chain.state.lock_ends.get(&id).cloned(),
                n.chain.height(),
            )
        };
        let preimage = end.as_ref().and_then(|e| e.preimage).or(r.preimage);
        if let Some(p) = preimage {
            if r.state != St::Done {
                match self.ln.settle(&p) {
                    Ok(()) => self.update(&r.hash, |x| {
                        x.state = St::Done;
                        x.preimage = Some(p);
                    }),
                    Err(e) if e.contains("already settled") => self.update(&r.hash, |x| {
                        x.state = St::Done;
                        x.preimage = Some(p);
                    }),
                    Err(e) => self.update(&r.hash, |x| {
                        x.preimage = Some(p);
                        x.info = e;
                    }),
                }
            }
            // paid: see the buyer's coins all the way into a block
            if let Some(l) = open {
                if end.is_none() && tip < l.post.timeout {
                    let _ = Self::submit(
                        shared,
                        Tx::Act(Action::Unlock {
                            lock: id,
                            preimage: p,
                        }),
                    );
                }
            }
            if confirmed_end.is_some() {
                self.update(&r.hash, |x| x.closed = true);
            }
            return;
        }
        match (end, open) {
            (Some(_), _) => {
                // refunded to us: release the held payment back to the buyer
                let _ = self.ln.cancel(&r.hash);
                self.update(&r.hash, |x| {
                    x.state = St::Refunded;
                    if confirmed_end.is_some() {
                        x.closed = true;
                    }
                });
            }
            (None, Some(l)) => {
                if tip >= l.post.timeout {
                    let _ = Self::submit(shared, Tx::Act(Action::Expire { lock: id }));
                }
            }
            (None, None) => {
                if now() > r.updated + 600 {
                    let _ = self.ln.cancel(&r.hash);
                    self.update(&r.hash, |x| {
                        x.state = St::Failed;
                        x.closed = true;
                        x.info = "the lock never reached a block".into();
                    });
                }
            }
        }
    }

    /// Out: wait for the payer's lock to be buried, with time left, then pay.
    fn out_awaiting(&self, shared: &Shared, r: &Rec) {
        let found = {
            let n = node_lock(shared);
            let st = &n.chain.state;
            let tip = n.chain.height();
            st.locks_by_hash
                .get(&r.hash)
                .into_iter()
                .flatten()
                .filter_map(|id| st.locks.get(id))
                .find(|l| {
                    l.post.claim_addr == r.addr
                        && l.post.amount >= r.coins
                        && l.post.timeout >= tip + self.cfg.out_min_left
                        && tip + 1 >= l.at + self.cfg.out_confirmations
                })
                .map(|l| l.id)
        };
        match found {
            Some(id) => {
                self.update(&r.hash, |x| {
                    x.state = St::Paying;
                    x.lock = Some(id);
                });
                self.spawn_pay(shared, r.hash, r.invoice.clone(), id);
            }
            None => {
                // a lock that arrives later is never paid: `out_settle` returns it to its
                // payer after its timeout
                if now() > r.created + self.cfg.quote_secs {
                    self.update(&r.hash, |x| {
                        x.state = St::Expired;
                        x.info = "no lock arrived in time; a lock made later goes back to its payer after its timeout".into();
                    });
                }
            }
        }
    }

    fn spawn_pay(&self, shared: &Shared, hash: [u8; 32], invoice: String, id: [u8; 32]) {
        {
            let mut p = self.paying.lock().unwrap_or_else(|e| e.into_inner());
            if !p.insert(hash) {
                return;
            }
        }
        let (ln, paying, cfg, shared) = (
            self.ln.clone(),
            self.paying.clone(),
            self.cfg.clone(),
            shared.clone(),
        );
        let sats = self.recs().get(&hash).map(|r| r.sats).unwrap_or(0);
        let outcome = Arc::new(Mutex::new(None));
        let out2 = outcome.clone();
        let h = std::thread::spawn(move || {
            let st = ln.pay(
                &invoice,
                cfg.pay_fee_limit(sats),
                cfg.pay_cltv_limit,
                cfg.pay_timeout_secs,
            );
            *out2.lock().unwrap_or_else(|e| e.into_inner()) = Some(st);
            paying
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&hash);
        });
        // a fast payment is finished here; a slow one by `out_paying` on a later tick
        let deadline = Instant::now() + Duration::from_millis(1500);
        while !h.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let st = outcome.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(st) = st {
            self.finish_pay(&shared, hash, id, st);
        }
    }

    fn finish_pay(&self, shared: &Shared, hash: [u8; 32], id: [u8; 32], st: PayState) {
        match st {
            PayState::Succeeded(p) if sha256(&p) == hash => {
                let sent = Self::submit(
                    shared,
                    Tx::Act(Action::Unlock {
                        lock: id,
                        preimage: p,
                    }),
                );
                self.update(&hash, |x| {
                    x.state = St::Done;
                    x.preimage = Some(p);
                    x.info = sent.err().unwrap_or_default();
                });
            }
            PayState::Succeeded(_) => self.update(&hash, |x| {
                x.info = "the node returned a preimage that does not match".into()
            }),
            PayState::Failed(e) => self.update(&hash, |x| {
                x.state = St::Failed;
                x.info = format!(
                    "payment failed: {e}; the lock goes back to the payer after its timeout"
                );
            }),
            PayState::InFlight | PayState::Unknown => {}
        }
    }

    fn out_paying(&self, shared: &Shared, r: &Rec) {
        if self
            .paying
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&r.hash)
        {
            return;
        }
        let Some(id) = r.lock else { return };
        match self.ln.payment(&r.hash) {
            PayState::Unknown => self.spawn_pay(shared, r.hash, r.invoice.clone(), id),
            st => self.finish_pay(shared, r.hash, id, st),
        }
    }

    /// Out, after the payment: see the claim into a block; or, if the payment failed or
    /// never started, return the payer's lock once it times out.
    fn out_settle(&self, shared: &Shared, r: &Rec) {
        let ids: Vec<[u8; 32]> = match r.lock {
            Some(id) => vec![id],
            None => node_lock(shared)
                .pool_state()
                .locks_by_hash
                .get(&r.hash)
                .cloned()
                .unwrap_or_default(),
        };
        let mut all_closed = true;
        for id in ids {
            let (end, open, confirmed_end, tip) = {
                let n = node_lock(shared);
                let pool = n.pool_state();
                (
                    pool.lock_ends.get(&id).cloned(),
                    pool.locks.get(&id).cloned(),
                    n.chain.state.lock_ends.get(&id).cloned(),
                    n.chain.height(),
                )
            };
            if confirmed_end.is_none() {
                all_closed = false;
            }
            match (end, open, r.state, r.preimage) {
                (None, Some(l), St::Done, Some(p))
                    if tip < l.post.timeout && l.post.claim_addr == r.addr =>
                {
                    let _ = Self::submit(
                        shared,
                        Tx::Act(Action::Unlock {
                            lock: id,
                            preimage: p,
                        }),
                    );
                }
                (None, Some(l), _, _) if tip >= l.post.timeout => {
                    let _ = Self::submit(shared, Tx::Act(Action::Expire { lock: id }));
                }
                (Some(e), _, St::Failed | St::Paying, _) if e.preimage.is_none() => {
                    self.update(&r.hash, |x| x.state = St::Refunded)
                }
                _ => {}
            }
        }
        if all_closed && (r.lock.is_some() || now() > r.created + self.cfg.quote_secs + 3 * 86_400)
        {
            self.update(&r.hash, |x| x.closed = true);
        }
    }
}
