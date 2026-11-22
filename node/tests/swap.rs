//! Swaps with Lightning, through the public API, against a Lightning node in memory:
//! buying coins with a held Lightning payment, paying a Lightning invoice with coins, and
//! every way each can fail without anyone losing what they put in.

use newsatoshi::chain::{mine, Chain};
use newsatoshi::hash::{sha256, words_to_bytes};
use newsatoshi::job::{payout_rho, Action, Deposit};
use newsatoshi::lock::{lock_id, LockPost};
use newsatoshi::node::{lock, Node, Shared};
use newsatoshi::note;
use newsatoshi::params::{Net, Params, COIN, DEFAULT_FEE};
use newsatoshi::rpc::{self, J};
use newsatoshi::swap::{FakeLn, InvoiceState, Lightning, Swap, SwapCfg};
use newsatoshi::tx::Tx;
use newsatoshi::wallet::{parse_address, Wallet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

fn http(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, J) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nX-Real-IP: 198.51.100.{}\r\nContent-Length: {}\r\n\r\n", rand::random::<u8>(), body.len());
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8(resp).unwrap();
    let code = text[9..12].parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    (
        code,
        if body.is_empty() {
            J::Null
        } else {
            J::parse(body.as_bytes()).unwrap()
        },
    )
}

fn s<'a>(j: &'a J, k: &str) -> &'a str {
    match j.get(k) {
        Some(J::Str(x)) | Some(J::Num(x)) => x,
        _ => panic!("no {k} in {}", j.to_json()),
    }
}

struct Rig {
    shared: Shared,
    ln: Arc<FakeLn>,
    swap: Arc<Swap>,
    server: Arc<Mutex<Wallet>>,
    miner: Wallet,
    port: u16,
}

fn mine_one(r: &Rig) {
    let mut n = lock(&r.shared);
    let (mut b, _) = n.block_template(r.miner.a_pk(), b"test").unwrap();
    assert!(mine(&mut b.header, u64::MAX));
    assert!(n.accept_block(b, None).unwrap());
}

fn cfg() -> SwapCfg {
    SwapCfg {
        in_lock_blocks: 5,
        out_lock_blocks: 8,
        out_min_left: 3,
        out_confirmations: 1,
        ..SwapCfg::default()
    }
}

fn rig(cfg: SwapCfg) -> Rig {
    let shared = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    lock(&shared).log = false;
    let server = Arc::new(Mutex::new(Wallet::generate()));
    let ln = FakeLn::new();
    let swap = Swap::new(ln.clone(), server.clone(), cfg, None);
    let port =
        rpc::serve_public_with(shared.clone(), "127.0.0.1", 0, None, Some(swap.clone())).unwrap();
    let r = Rig {
        shared,
        ln,
        swap,
        server: server.clone(),
        miner: Wallet::generate(),
        port,
    };
    // the server's coins: two block rewards, matured
    let sa = server.lock().unwrap().a_pk();
    for _ in 0..2 {
        let mut n = lock(&r.shared);
        let (mut b, _) = n.block_template(sa, b"server").unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        n.accept_block(b, None).unwrap();
    }
    mine_one(&r);
    r
}

fn submit(r: &Rig, tx: &Tx) -> (u16, J) {
    http(r.port, "POST", "/api/tx", &tx.to_bytes())
}

/// The buyer's side of a swap in: a secret, a one-off key, and a request for `sats`.
fn ask_in(r: &Rig, sats: u64) -> ([u8; 32], Wallet, J) {
    let p: [u8; 32] = rand::random();
    let k = Wallet::generate();
    let body = format!(
        r#"{{"hash":"{}","address":"{}","sats":{sats}}}"#,
        hex::encode(sha256(&p)),
        k.address()
    );
    let (code, j) = http(r.port, "POST", "/api/swap/in", body.as_bytes());
    assert_eq!(code, 200, "{}", j.to_json());
    (p, k, j)
}

fn lock_of(r: &Rig, hash: &[u8; 32]) -> [u8; 32] {
    let rec = r.swap.get_rec(hash).unwrap();
    rec.lock.expect("locked")
}

#[test]
fn any_lightning_wallet_buys_coins_and_no_one_holds_them_in_between() {
    let r = rig(cfg());
    let (code, info) = http(r.port, "GET", "/api/swap/info", b"");
    assert_eq!(code, 200);
    assert_eq!(
        info.get("in").and_then(|x| x.get("available")),
        Some(&J::Bool(true)),
        "{}",
        info.to_json()
    );

    let (p, k, j) = ask_in(&r, 5_000);
    let h = sha256(&p);
    assert_eq!(
        s(&j, "coins"),
        (5 * COIN).to_string(),
        "5,000 sats at 1,000 a coin"
    );
    // the same hash cannot be sold twice
    let body = format!(
        r#"{{"hash":"{}","address":"{}","sats":5000}}"#,
        hex::encode(h),
        k.address()
    );
    assert_eq!(http(r.port, "POST", "/api/swap/in", body.as_bytes()).0, 400);

    // nothing is locked until the payment is held
    r.swap.tick(&r.shared);
    assert!(r.swap.get_rec(&h).unwrap().lock.is_none());
    r.ln.payer_pays(s(&j, "invoice")).unwrap();
    r.swap.tick(&r.shared);
    let id = lock_of(&r, &h);
    mine_one(&r);
    let (_, lj) = http(
        r.port,
        "GET",
        &format!("/api/lock?id={}", hex::encode(id)),
        b"",
    );
    assert_eq!(s(&lj, "state"), "open", "{}", lj.to_json());
    assert_eq!(lj.get("confirmed"), Some(&J::Bool(true)));
    assert_eq!(s(&lj, "claim"), k.address());
    assert_eq!(s(&lj, "amount"), (5 * COIN).to_string());
    // the held payment is not settled: the server does not know the secret
    assert_eq!(r.ln.held_state(&h), Some(InvoiceState::Accepted));

    // the buyer claims; the secret is public as soon as the claim is pooled
    let (code, _) = submit(
        &r,
        &Tx::Act(Action::Unlock {
            lock: id,
            preimage: p,
        }),
    );
    assert_eq!(code, 200);
    r.swap.tick(&r.shared);
    assert_eq!(
        r.ln.held_state(&h),
        Some(InvoiceState::Settled),
        "the server settles with the buyer's own secret"
    );
    assert_eq!(
        r.ln.payer_receipt(&h),
        Some(p),
        "the buyer's Lightning wallet holds the proof of payment"
    );
    mine_one(&r);
    let (_, sj) = http(
        r.port,
        "GET",
        &format!("/api/swap?hash={}", hex::encode(h)),
        b"",
    );
    assert_eq!(s(&sj, "state"), "done");

    // the coins are the buyer's: a note at the one-off key's address, found by the public rho
    let cm = note::commit(&k.a_pk(), 5 * COIN, &payout_rho(&id, 3));
    let (_, nj) = http(
        r.port,
        "GET",
        &format!("/api/note?cm={}", hex::encode(words_to_bytes(&cm))),
        b"",
    );
    assert_eq!(nj.get("found"), Some(&J::Bool(true)));
    let mut kw = k.clone();
    let main = Wallet::generate();
    let (tx, _) = {
        let n = lock(&r.shared);
        kw.spend(
            &n.chain,
            Some((main.a_pk(), 5 * COIN - DEFAULT_FEE)),
            DEFAULT_FEE,
            None,
            vec![],
        )
        .unwrap()
    };
    assert_eq!(
        submit(&r, &tx).0,
        200,
        "the buyer sweeps the coins to their own key"
    );
    r.swap.tick(&r.shared);
    mine_one(&r);
    r.swap.tick(&r.shared);
    assert!(r.swap.get_rec(&h).unwrap().closed);
}

#[test]
fn a_buyer_who_never_claims_has_the_payment_cancelled_and_the_server_keeps_its_coins() {
    let r = rig(cfg());
    let (p, _k, j) = ask_in(&r, 3_000);
    let h = sha256(&p);
    r.ln.payer_pays(s(&j, "invoice")).unwrap();
    let before = { r.server.lock().unwrap().balance(&lock(&r.shared).chain) };
    r.swap.tick(&r.shared);
    let id = lock_of(&r, &h);
    for _ in 0..8 {
        mine_one(&r);
        r.swap.tick(&r.shared);
    }
    mine_one(&r);
    r.swap.tick(&r.shared);
    let rec = r.swap.get_rec(&h).unwrap();
    assert_eq!(
        rec.state.clone() as u8,
        newsatoshi::swap::St::Refunded as u8,
        "{:?}",
        rec
    );
    assert_eq!(
        r.ln.held_state(&h),
        Some(InvoiceState::Canceled),
        "the payer's sats go back"
    );
    assert_eq!(
        lock(&r.shared)
            .chain
            .state
            .lock_ends
            .get(&id)
            .unwrap()
            .preimage,
        None
    );
    let after = { r.server.lock().unwrap().balance(&lock(&r.shared).chain) };
    assert_eq!(
        after,
        before - DEFAULT_FEE,
        "the server is out only the fee of its lock"
    );
    // too late now: the secret no longer claims
    assert_eq!(
        submit(
            &r,
            &Tx::Act(Action::Unlock {
                lock: id,
                preimage: p
            })
        )
        .0,
        400
    );
}

#[test]
fn an_unpaid_invoice_expires_and_locks_nothing() {
    let r = rig(SwapCfg {
        invoice_expiry_secs: 0,
        ..cfg()
    });
    let (p, _k, j) = ask_in(&r, 2_000);
    let h = sha256(&p);
    assert!(!s(&j, "invoice").is_empty());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // the server waits a minute past the invoice's expiry before giving up on it
    r.swap.tick(&r.shared);
    assert!(r.swap.get_rec(&h).unwrap().lock.is_none());
    assert_eq!(lock(&r.shared).mempool_len(), 0);
}

/// A payer with coins, and the terms the server quoted for paying `invoice`.
fn quote_out(r: &Rig, invoice: &str) -> (Wallet, J) {
    let mut payer = Wallet::generate();
    {
        let mut n = lock(&r.shared);
        let (mut b, _) = n.block_template(payer.a_pk(), b"payer").unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        n.accept_block(b, None).unwrap();
    }
    mine_one(r);
    payer.notes.clear();
    let (code, j) = http(
        r.port,
        "POST",
        "/api/swap/out",
        format!(r#"{{"invoice":"{invoice}"}}"#).as_bytes(),
    );
    assert_eq!(code, 200, "{}", j.to_json());
    (payer, j)
}

fn lock_for(r: &Rig, payer: &mut Wallet, q: &J, amount: u64, timeout: u32) -> [u8; 32] {
    let post = LockPost {
        hash: hex::decode(s(q, "hash")).unwrap().try_into().unwrap(),
        timeout,
        claim_addr: parse_address(s(q, "address")).unwrap(),
        refund_addr: payer.a_pk(),
        amount,
    };
    let (tx, _) = {
        let n = lock(&r.shared);
        payer
            .spend(
                &n.chain,
                None,
                DEFAULT_FEE,
                Some(Deposit::Lock(post.clone())),
                vec![],
            )
            .unwrap()
    };
    let Tx::Spend(sp) = &tx else { unreachable!() };
    assert_eq!(submit(r, &tx).0, 200);
    lock_id(&post, &sp.nf[0])
}

#[test]
fn coins_pay_a_lightning_invoice_and_the_payment_itself_claims_them() {
    let r = rig(cfg());
    let (invoice, preimage) = r.ln.payee_invoice(4_000);
    let (mut payer, q) = quote_out(&r, &invoice);
    let coins: u64 = s(&q, "coins").parse().unwrap();
    assert!(
        coins >= 4 * COIN,
        "the routing-fee allowance is on top: {coins}"
    );
    let timeout: u32 = s(&q, "timeout").parse().unwrap();
    let id = lock_for(&r, &mut payer, &q, coins, timeout);
    // not paid while the lock waits in the pool
    r.swap.tick(&r.shared);
    assert_eq!(
        r.ln.payment(&sha256(&preimage)),
        newsatoshi::swap::PayState::Unknown
    );
    mine_one(&r);
    r.swap.tick(&r.shared);
    let h = sha256(&preimage);
    let rec = r.swap.get_rec(&h).unwrap();
    assert_eq!(
        rec.preimage,
        Some(preimage),
        "paying the invoice revealed its preimage: {:?}",
        rec
    );
    // the payment's own preimage claims the lock for the server
    let server_before = { r.server.lock().unwrap().balance(&lock(&r.shared).chain) };
    mine_one(&r);
    r.swap.tick(&r.shared);
    let n = lock(&r.shared);
    assert_eq!(
        n.chain.state.lock_ends.get(&id).unwrap().preimage,
        Some(preimage)
    );
    assert_eq!(
        r.server.lock().unwrap().balance(&n.chain),
        server_before + coins
    );
    drop(n);
    assert!(r.swap.get_rec(&h).unwrap().closed);
}

#[test]
fn a_failed_payment_returns_the_lock_to_the_payer() {
    let r = rig(cfg());
    r.ln.set_fail_payments(true);
    let (invoice, preimage) = r.ln.payee_invoice(2_000);
    let h = sha256(&preimage);
    let (mut payer, q) = quote_out(&r, &invoice);
    let coins: u64 = s(&q, "coins").parse().unwrap();
    let id = lock_for(&r, &mut payer, &q, coins, s(&q, "timeout").parse().unwrap());
    mine_one(&r);
    let before = { payer.balance(&lock(&r.shared).chain) };
    r.swap.tick(&r.shared);
    assert_eq!(
        r.swap.get_rec(&h).unwrap().state as u8,
        newsatoshi::swap::St::Failed as u8
    );
    for _ in 0..12 {
        mine_one(&r);
        r.swap.tick(&r.shared);
    }
    let n = lock(&r.shared);
    assert_eq!(
        n.chain.state.lock_ends.get(&id).unwrap().preimage,
        None,
        "refunded, by the server, unasked"
    );
    assert_eq!(payer.balance(&n.chain), before + coins);
    drop(n);
    assert_eq!(
        r.swap.get_rec(&h).unwrap().state as u8,
        newsatoshi::swap::St::Refunded as u8
    );
}

#[test]
fn the_server_pays_only_for_a_lock_that_covers_the_invoice_with_time_to_spare() {
    let r = rig(cfg());
    let (invoice, preimage) = r.ln.payee_invoice(3_000);
    let h = sha256(&preimage);
    let (mut payer, q) = quote_out(&r, &invoice);
    let coins: u64 = s(&q, "coins").parse().unwrap();
    let tip = lock(&r.shared).chain.height();
    // short by one unit, and long enough: not paid
    lock_for(
        &r,
        &mut payer,
        &q,
        coins - 1,
        s(&q, "timeout").parse().unwrap(),
    );
    mine_one(&r);
    // enough coins, but too little time left
    lock_for(&r, &mut payer, &q, coins, tip + 4);
    mine_one(&r);
    r.swap.tick(&r.shared);
    assert_eq!(
        r.ln.payment(&h),
        newsatoshi::swap::PayState::Unknown,
        "neither lock is paid"
    );
    // an invoice handled before is not quoted again
    let (code, _) = http(
        r.port,
        "POST",
        "/api/swap/out",
        format!(r#"{{"invoice":"{invoice}"}}"#).as_bytes(),
    );
    assert_eq!(code, 200, "a quote still waiting is returned as it stands");
    let (code, _) = http(
        r.port,
        "POST",
        "/api/swap/out",
        br#"{"invoice":"lnbc1notreal"}"#,
    );
    assert_eq!(code, 400);
}

// ---- the LND client, against a stand-in that answers as LND's REST interface does ------

use newsatoshi::swap::Lnd;
use std::collections::HashMap;
use std::net::TcpListener;

#[derive(Default)]
struct FakeLndState {
    /// hold invoices: hash -> (state, preimage once settled)
    held: HashMap<[u8; 32], (String, Option<[u8; 32]>)>,
    /// invoices of a remote payee: hash -> preimage
    payees: HashMap<[u8; 32], [u8; 32]>,
    payments: Vec<([u8; 32], [u8; 32])>,
    macaroons_seen: usize,
}

fn b64(data: &[u8]) -> String {
    rpc::base64(data)
}

fn unb64(s: &str) -> Vec<u8> {
    let mut out = vec![];
    let (mut buf, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => break,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// Answer one request as LND would, chunked like grpc-gateway's streams.
fn fake_lnd(st: Arc<Mutex<FakeLndState>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = vec![];
            let mut tmp = [0u8; 4096];
            let (head, body) = loop {
                let n = c.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break (String::new(), vec![]);
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(e) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..e]).to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    while buf.len() < e + 4 + len {
                        let n = c.read(&mut tmp).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    break (head, buf[e + 4..].to_vec());
                }
            };
            let first = head.lines().next().unwrap_or("").to_string();
            let mut parts = first.split(' ');
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let mut s = st.lock().unwrap();
            if head
                .to_ascii_lowercase()
                .contains("grpc-metadata-macaroon: 0201")
            {
                s.macaroons_seen += 1;
            } else {
                let _ = c.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 46\r\n\r\n{\"code\":16,\"message\":\"expected 1 macaroon\"}  ");
                continue;
            }
            let req = if body.is_empty() {
                J::Null
            } else {
                J::parse(&body).unwrap()
            };
            let field = |k: &str| match req.get(k) {
                Some(J::Str(x)) | Some(J::Num(x)) => x.clone(),
                _ => String::new(),
            };
            let ok = |j: String| (200, j, false);
            let (code, text, chunked) = match (method, path) {
                ("GET", "/v1/getinfo") => ok(r#"{"identity_pubkey":"02aa","alias":"fake-lnd","synced_to_chain":true,"chains":[{"chain":"bitcoin","network":"regtest"}],"uris":["02aa@127.0.0.1:9735"]}"#.into()),
                ("GET", "/v1/balance/channels") => ok(r#"{"balance":"500000","local_balance":{"sat":"500000","msat":"500000000"},"remote_balance":{"sat":"500000","msat":"500000000"}}"#.into()),
                ("POST", "/v2/invoices/hodl") => {
                    let h: [u8; 32] = unb64(&field("hash")).try_into().unwrap();
                    assert!(!field("value").is_empty() && !field("cltv_expiry").is_empty());
                    s.held.insert(h, ("OPEN".into(), None));
                    ok(format!(r#"{{"payment_request":"lnbcrt1hold{}","add_index":"1","payment_addr":"{}"}}"#, hex::encode(h), b64(&[1; 32])))
                }
                ("GET", p) if p.starts_with("/v1/invoice/") => {
                    let h: [u8; 32] = hex::decode(&p[12..]).unwrap().try_into().unwrap();
                    match s.held.get(&h) {
                        Some((state, _)) => ok(format!(r#"{{"r_hash":"{}","state":"{state}","value":"5000"}}"#, b64(&h))),
                        None => (404, r#"{"code":5,"message":"unable to locate invoice","details":[]}"#.into(), false),
                    }
                }
                ("POST", "/v2/invoices/settle") => {
                    let p: [u8; 32] = unb64(&field("preimage")).try_into().unwrap();
                    match s.held.get_mut(&sha256(&p)) {
                        Some(e) if e.0 == "ACCEPTED" => {
                            *e = ("SETTLED".into(), Some(p));
                            ok("{}".into())
                        }
                        _ => (500, r#"{"code":2,"message":"invoice still open","details":[]}"#.into(), false),
                    }
                }
                ("POST", "/v2/invoices/cancel") => {
                    let h: [u8; 32] = unb64(&field("payment_hash")).try_into().unwrap();
                    if let Some(e) = s.held.get_mut(&h) {
                        e.0 = "CANCELED".into();
                    }
                    ok("{}".into())
                }
                ("GET", p) if p.starts_with("/v1/payreq/") => {
                    let inv = &p[11..];
                    match inv.strip_prefix("lnbcrt1pay") {
                        Some(rest) => {
                            let (h, sats) = rest.split_once('s').unwrap();
                            ok(format!(r#"{{"destination":"03bb","payment_hash":"{h}","num_satoshis":"{sats}","timestamp":"{}","expiry":"3600","cltv_expiry":"40"}}"#, newsatoshi::swap::now()))
                        }
                        None => (500, r#"{"code":2,"message":"invalid index of 1","details":[]}"#.into(), false),
                    }
                }
                ("POST", "/v2/router/send") => {
                    assert_eq!(req.get("no_inflight_updates"), Some(&J::Bool(true)));
                    assert!(!field("fee_limit_sat").is_empty());
                    let inv = field("payment_request");
                    let h: [u8; 32] = hex::decode(inv.strip_prefix("lnbcrt1pay").unwrap().split_once('s').unwrap().0).unwrap().try_into().unwrap();
                    let p = s.payees.get(&h).copied();
                    let line = match p {
                        Some(p) => {
                            s.payments.push((h, p));
                            format!(r#"{{"result":{{"payment_hash":"{}","value":"4000","payment_preimage":"{}","status":"SUCCEEDED","failure_reason":"FAILURE_REASON_NONE"}}}}"#, hex::encode(h), hex::encode(p))
                        }
                        None => format!(r#"{{"result":{{"payment_hash":"{}","payment_preimage":"0000000000000000000000000000000000000000000000000000000000000000","status":"FAILED","failure_reason":"FAILURE_REASON_NO_ROUTE"}}}}"#, hex::encode(h)),
                    };
                    (200, format!("{{\"result\":{{\"payment_hash\":\"{}\",\"status\":\"IN_FLIGHT\"}}}}\n{line}\n", hex::encode(h)), true)
                }
                ("GET", p) if p.starts_with("/v1/payments") => {
                    let ps: Vec<String> = s.payments.iter().map(|(h, p)| format!(r#"{{"payment_hash":"{}","payment_preimage":"{}","status":"SUCCEEDED"}}"#, hex::encode(h), hex::encode(p))).collect();
                    ok(format!(r#"{{"payments":[{}]}}"#, ps.join(",")))
                }
                _ => (404, r#"{"code":5,"message":"Not Found"}"#.into(), false),
            };
            drop(s);
            let reason = if code == 200 { "OK" } else { "Error" };
            let resp = if chunked {
                let mut r = format!("HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
                for part in text.split_inclusive('\n') {
                    r += &format!("{:x}\r\n{part}\r\n", part.len());
                }
                r += "0\r\n\r\n";
                r
            } else {
                format!("HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{text}", text.len())
            };
            let _ = c.write_all(resp.as_bytes());
        }
    });
    port
}

#[test]
fn the_lnd_client_speaks_lnds_rest_interface() {
    let st = Arc::new(Mutex::new(FakeLndState::default()));
    let lnd_port = fake_lnd(st.clone());
    let lnd = Lnd::new(&format!("127.0.0.1:{lnd_port}"), "0201036c6e64");
    let info = lnd.info().unwrap();
    assert_eq!(
        (
            info.alias.as_str(),
            info.network.as_str(),
            info.synced,
            info.can_send
        ),
        ("fake-lnd", "regtest", true, 500_000)
    );
    assert!(
        Lnd::new(&format!("127.0.0.1:{lnd_port}"), "beef")
            .info()
            .is_err(),
        "a wrong macaroon is refused"
    );

    // a swap in, end to end through the client
    let shared = Node::new(Chain::open(Params::get(Net::Reg).unwrap(), None).unwrap());
    lock(&shared).log = false;
    let server = Arc::new(Mutex::new(Wallet::generate()));
    let swap = Swap::new(Arc::new(lnd), server.clone(), cfg(), None);
    let port =
        rpc::serve_public_with(shared.clone(), "127.0.0.1", 0, None, Some(swap.clone())).unwrap();
    let r = Rig {
        shared,
        ln: FakeLn::new(),
        swap: swap.clone(),
        server: server.clone(),
        miner: Wallet::generate(),
        port,
    };
    let sa = server.lock().unwrap().a_pk();
    for _ in 0..2 {
        let mut n = lock(&r.shared);
        let (mut b, _) = n.block_template(sa, b"server").unwrap();
        assert!(mine(&mut b.header, u64::MAX));
        n.accept_block(b, None).unwrap();
    }
    mine_one(&r);
    let (code, info) = http(port, "GET", "/api/swap/info", b"");
    assert_eq!(code, 200);
    assert_eq!(
        info.get("lightning_up"),
        Some(&J::Bool(true)),
        "{}",
        info.to_json()
    );

    let (p, _k, j) = ask_in(&r, 5_000);
    let h = sha256(&p);
    assert!(s(&j, "invoice").starts_with("lnbcrt1hold"));
    r.swap.tick(&r.shared);
    assert!(
        r.swap.get_rec(&h).unwrap().lock.is_none(),
        "open invoice: nothing locked"
    );
    st.lock().unwrap().held.get_mut(&h).unwrap().0 = "ACCEPTED".into(); // the buyer's payment arrives, held
    r.swap.tick(&r.shared);
    let id = lock_of(&r, &h);
    mine_one(&r);
    assert_eq!(
        submit(
            &r,
            &Tx::Act(Action::Unlock {
                lock: id,
                preimage: p
            })
        )
        .0,
        200
    );
    r.swap.tick(&r.shared);
    assert_eq!(
        st.lock().unwrap().held.get(&h).unwrap(),
        &("SETTLED".to_string(), Some(p))
    );

    // a swap out: the invoice decoded, paid over the stream, the preimage claiming the lock
    let pp: [u8; 32] = rand::random();
    let ph = sha256(&pp);
    st.lock().unwrap().payees.insert(ph, pp);
    let (mut payer, q) = quote_out(&r, &format!("lnbcrt1pay{}s4000", hex::encode(ph)));
    assert_eq!(s(&q, "sats"), "4000");
    let coins: u64 = s(&q, "coins").parse().unwrap();
    let lid = lock_for(&r, &mut payer, &q, coins, s(&q, "timeout").parse().unwrap());
    mine_one(&r);
    r.swap.tick(&r.shared);
    assert_eq!(r.swap.get_rec(&ph).unwrap().preimage, Some(pp));
    mine_one(&r);
    assert_eq!(
        lock(&r.shared)
            .chain
            .state
            .lock_ends
            .get(&lid)
            .unwrap()
            .preimage,
        Some(pp)
    );
    // a bad invoice is refused with LND's own words
    let (code, e) = http(
        port,
        "POST",
        "/api/swap/out",
        br#"{"invoice":"lnbcrt1junk"}"#,
    );
    assert_eq!(code, 400);
    assert!(s(&e, "error").contains("invalid index"), "{}", e.to_json());
    assert!(st.lock().unwrap().macaroons_seen > 8);
}
