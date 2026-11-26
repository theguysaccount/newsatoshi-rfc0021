//! The browser wallet's WebAssembly: addresses, note strings, nullifiers, spend proofs and
//! the opening of payments delivered on chain, computed where the key lives. Nothing here
//! talks to the network; the page does.
//!
//! Every export returns a status (0 ok, negative on error) and leaves its result, or the
//! error's text, in a buffer the page reads with `out_ptr` / `out_len`. Randomness comes
//! from the page's `crypto.getRandomValues` through the import `env.random_fill`.

use newsatoshi::deliver::{memo_for, parse_any_address, Scanner};
use newsatoshi::hash::{bytes_to_words, sha256, words_to_bytes, Word8};
use newsatoshi::job::{payout_rho, Action, Deposit};
use newsatoshi::lock::{lock_id, LockPost};
use newsatoshi::note::{self, Rho, DEPTH};
use newsatoshi::rpc::J;
use newsatoshi::spend::{self, InputNote, OutputNote, SpendWitness};
use newsatoshi::tx::{bind_of, hash_hex, Spend, Tx};
use newsatoshi::wallet::{encode_address, encode_note, parse_address, parse_note};
use rand::Rng;

#[link(wasm_import_module = "env")]
extern "C" {
    fn random_fill(ptr: *mut u8, len: usize);
}

fn page_rng(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    unsafe { random_fill(buf.as_mut_ptr(), buf.len()) };
    Ok(())
}
getrandom::register_custom_getrandom!(page_rng);

static mut OUT: Vec<u8> = Vec::new();

fn set_out(b: Vec<u8>) {
    unsafe { OUT = b };
}

fn done(r: Result<String, String>) -> i32 {
    match r {
        Ok(s) => {
            set_out(s.into_bytes());
            0
        }
        Err(e) => {
            set_out(e.into_bytes());
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    unsafe { (*core::ptr::addr_of!(OUT)).as_ptr() }
}

#[no_mangle]
pub extern "C" fn out_len() -> usize {
    unsafe { (*core::ptr::addr_of!(OUT)).len() }
}

fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(p, n) }
}

fn w8(h: &str) -> Result<Word8, String> {
    let b: [u8; 32] = hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("expected 64 hex characters, got {h:.20}"))?;
    Ok(bytes_to_words(&b))
}

fn rho_hex(r: &Rho) -> String {
    hex::encode(r.iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<u8>>())
}

fn hex_rho(h: &str) -> Result<Rho, String> {
    let b = hex::decode(h).map_err(|_| "rho is not hex")?;
    if b.len() != 20 {
        return Err("rho must be 20 bytes".into());
    }
    Ok(core::array::from_fn(|i| u32::from_be_bytes(b[4 * i..4 * i + 4].try_into().unwrap())))
}

fn u64_of(j: Option<&J>) -> Result<u64, String> {
    match j {
        Some(J::Str(s)) | Some(J::Num(s)) => s.parse().map_err(|_| format!("bad amount {s}")),
        _ => Err("missing amount".into()),
    }
}

/// A fresh 32-byte spending key, from the page's randomness, as hex.
#[no_mangle]
pub extern "C" fn new_key() -> i32 {
    let k: [u8; 32] = rand::thread_rng().gen();
    done(Ok(hex::encode(k)))
}

/// The address of a key (hex): `ns1…`.
#[no_mangle]
pub extern "C" fn address(p: *const u8, n: usize) -> i32 {
    done((|| {
        let sk = w8(std::str::from_utf8(bytes(p, n)).map_err(|_| "not text")?)?;
        Ok(encode_address(&note::address(&sk)))
    })())
}

/// The delivery address of a key (hex): `nsd1…`. Payments to it arrive on chain, sealed to
/// the key, and `scan` finds them.
#[no_mangle]
pub extern "C" fn delivery_address(p: *const u8, n: usize) -> i32 {
    done((|| {
        let sk = w8(std::str::from_utf8(bytes(p, n)).map_err(|_| "not text")?)?;
        Ok(newsatoshi::deliver::delivery_address(&sk))
    })())
}

/// Envelopes from `GET /api/envelopes`, tried with a key: `{"sk", "items": [{"cm", "env"}]}`
/// gives the notes among them delivered to it, `[{"cm", "value", "rho", "note"}]`.
#[no_mangle]
pub extern "C" fn scan(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let sk = w8(r.get("sk").and_then(|x| x.as_str()).ok_or("sk")?)?;
        let J::Arr(items) = r.get("items").ok_or("items")? else { return Err("items".into()) };
        let (sc, a_pk) = (Scanner::new(&sk), note::address(&sk));
        let mut found = vec![];
        for it in items {
            let cm = w8(it.get("cm").and_then(|x| x.as_str()).ok_or("cm")?)?;
            let env = hex::decode(it.get("env").and_then(|x| x.as_str()).ok_or("env")?).map_err(|_| "env is not hex")?;
            if let Some((v, rho)) = sc.open(&cm, &env) {
                found.push(J::Obj(vec![
                    ("cm".into(), J::str(hex::encode(words_to_bytes(&cm)))),
                    ("value".into(), J::str(v.to_string())),
                    ("rho".into(), J::str(rho_hex(&rho))),
                    ("note".into(), J::str(encode_note(&a_pk, v, &rho))),
                ]));
            }
        }
        Ok(J::Arr(found).to_json())
    })())
}

fn net_params(r: &J) -> Result<newsatoshi::params::Params, String> {
    let net = newsatoshi::params::Params::parse(r.get("net").and_then(|x| x.as_str()).unwrap_or("testnet"))?;
    newsatoshi::params::Params::get(net)
}

fn light_info(lc: &newsatoshi::light::HeaderTip) -> J {
    J::Obj(vec![
        ("state".into(), J::str(hex::encode(lc.to_bytes()))),
        ("height".into(), J::num(lc.tip.height)),
        ("hash".into(), J::str(hash_hex(&lc.tip.hash))),
        ("work".into(), J::str(lc.tip.work.to_string())),
    ])
}

/// Follow headers as a light client: `{"net", "state": hex or null (from genesis),
/// "headers": [hex from GET /api/headers], "now": seconds}` gives `{"state", "height",
/// "hash", "work"}`.
#[no_mangle]
pub extern "C" fn light_follow(p: *const u8, n: usize) -> i32 {
    use newsatoshi::light::HeaderTip;
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let params = net_params(&r)?;
        let mut lc = match r.get("state").and_then(|x| x.as_str()) {
            Some(h) => HeaderTip::from_bytes(&hex::decode(h).map_err(|_| "state is not hex")?)?,
            None => HeaderTip::genesis(&params),
        };
        let J::Arr(hs) = r.get("headers").ok_or("headers")? else { return Err("headers".into()) };
        let mut blocks = vec![];
        for h in hs {
            blocks.push(newsatoshi::tx::Block::decode(&hex::decode(h.as_str().ok_or("header")?).map_err(|_| "header is not hex")?)?);
        }
        lc.extend(&params, &blocks, num::<i64>(r.get("now"), "now")?)?;
        Ok(light_info(&lc).to_json())
    })())
}

/// The note-tree root a light client's tip commits to: `{"net", "state", "header",
/// "tx_root", "parts"}` from GET /api/state gives `{"root", "height"}`, or an error if the
/// header is not the client's tip or does not commit to those parts.
#[no_mangle]
pub extern "C" fn light_root(p: *const u8, n: usize) -> i32 {
    use newsatoshi::light::HeaderTip;
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let lc = HeaderTip::from_bytes(&hex::decode(r.get("state").and_then(|x| x.as_str()).ok_or("state")?).map_err(|_| "state is not hex")?)?;
        let hb: [u8; 80] = hex::decode(r.get("header").and_then(|x| x.as_str()).ok_or("header")?).ok().and_then(|b| b.try_into().ok()).ok_or("header is 80 bytes")?;
        let tx_root = hex32(r.get("tx_root").and_then(|x| x.as_str()).ok_or("tx_root")?)?;
        let p = r.get("parts").ok_or("parts")?;
        let h = |k: &str| hex32(p.get(k).and_then(|x| x.as_str()).ok_or(k.to_string())?);
        let parts = newsatoshi::state::DigestParts {
            height: num(p.get("height"), "height")?,
            tree_root: w8(p.get("tree_root").and_then(|x| x.as_str()).ok_or("tree_root")?)?,
            nf_acc: h("nf_acc")?,
            jobs: h("jobs")?,
            pending: h("pending")?,
            issued: num(p.get("issued"), "issued")?,
            burned: num(p.get("burned"), "burned")?,
            locked: num(p.get("locked"), "locked")?,
            locks: match p.get("locks") {
                Some(J::Str(s)) => Some(hex32(s)?),
                _ => None,
            },
            conds: match p.get("conds") {
                Some(J::Str(s)) => Some(hex32(s)?),
                _ => None,
            },
            nf_root: match p.get("nf_root") {
                Some(J::Str(s)) => Some(hex32(s)?),
                _ => None,
            },
            channels: match p.get("channels") {
                Some(J::Str(s)) => Some(hex32(s)?),
                _ => None,
            },
        };
        let root = lc.committed_root(&newsatoshi::tx::Header::from_bytes(&hb), &tx_root, &parts)?;
        let mut out = vec![("root".into(), J::str(hex::encode(words_to_bytes(&root)))), ("height".into(), J::num(parts.height))];
        if let Some(r) = parts.nf_root {
            out.push(("nf_root".into(), J::str(hex::encode(r))));
        }
        if let Some(r) = parts.channels {
            out.push(("channels".into(), J::str(hex::encode(r))));
        }
        Ok(J::Obj(out).to_json())
    })())
}

/// Check a nullifier's proof from `GET /api/spent` against a nullifier-tree root the chain
/// commits to: `{"nf", "root", "proof": {"index", "value", "next", "path"}}` gives
/// `{"spent": true|false}`, or an error if the proof shows neither.
#[no_mangle]
pub extern "C" fn nf_check(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let nf = w8(r.get("nf").and_then(|x| x.as_str()).ok_or("nf")?)?;
        let root = w8(r.get("root").and_then(|x| x.as_str()).ok_or("root")?)?;
        let pr = r.get("proof").ok_or("proof")?;
        let J::Arr(path) = pr.get("path").ok_or("path")? else { return Err("path".into()) };
        if path.len() != DEPTH {
            return Err("path must have 32 hashes".into());
        }
        let mut pw = [[0u32; 8]; DEPTH];
        for (k, h) in path.iter().enumerate() {
            pw[k] = w8(h.as_str().ok_or("path")?)?;
        }
        let proof = newsatoshi::nftree::NfProof {
            index: num(pr.get("index"), "index")?,
            value: w8(pr.get("value").and_then(|x| x.as_str()).ok_or("value")?)?,
            next: w8(pr.get("next").and_then(|x| x.as_str()).ok_or("next")?)?,
            path: pw,
        };
        let spent = newsatoshi::nftree::check(&root, &nf, &proof).ok_or("the proof shows neither spent nor unspent")?;
        Ok(J::Obj(vec![("spent".into(), J::Bool(spent))]).to_json())
    })())
}

/// The root a note's Merkle path leads to: `{"cm", "pos", "path": [32 hex]}`.
#[no_mangle]
pub extern "C" fn path_root(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let cm = w8(r.get("cm").and_then(|x| x.as_str()).ok_or("cm")?)?;
        let pos: u32 = num(r.get("pos"), "pos")?;
        let J::Arr(path) = r.get("path").ok_or("path")? else { return Err("path".into()) };
        if path.len() != DEPTH {
            return Err("path must have 32 hashes".into());
        }
        let mut pw = [[0u32; 8]; DEPTH];
        for (k, h) in path.iter().enumerate() {
            pw[k] = w8(h.as_str().ok_or("path")?)?;
        }
        Ok(hex::encode(words_to_bytes(&note::root_from_path(&cm, pos, &pw))))
    })())
}

/// A note string, opened: address, value, rho and its commitment, as JSON.
#[no_mangle]
pub extern "C" fn open_note(p: *const u8, n: usize) -> i32 {
    done((|| {
        let s = std::str::from_utf8(bytes(p, n)).map_err(|_| "not text")?;
        let (a_pk, v, rho) = parse_note(s)?;
        let cm = note::commit(&a_pk, v, &rho);
        Ok(J::Obj(vec![
            ("address".into(), J::str(encode_address(&a_pk))),
            ("value".into(), J::str(v.to_string())),
            ("rho".into(), J::str(rho_hex(&rho))),
            ("cm".into(), J::str(hex::encode(words_to_bytes(&cm)))),
        ])
        .to_json())
    })())
}

/// The nullifier a spend of this note at this position will publish: `{"sk","pos","rho"}`.
#[no_mangle]
pub extern "C" fn nullifier(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let sk = w8(r.get("sk").and_then(|x| x.as_str()).ok_or("sk")?)?;
        let pos: u32 = match r.get("pos") {
            Some(J::Num(s)) | Some(J::Str(s)) => s.parse().map_err(|_| "pos")?,
            _ => return Err("pos".into()),
        };
        let rho = hex_rho(r.get("rho").and_then(|x| x.as_str()).ok_or("rho")?)?;
        Ok(hex::encode(words_to_bytes(&note::nullifier(&sk, pos, &rho))))
    })())
}

fn hex32(h: &str) -> Result<[u8; 32], String> {
    hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("expected 64 hex characters, got {h:.20}"))
}

fn num<T: std::str::FromStr>(j: Option<&J>, what: &str) -> Result<T, String> {
    match j {
        Some(J::Num(s)) | Some(J::Str(s)) => s.parse().map_err(|_| format!("bad {what}")),
        _ => Err(format!("missing {what}")),
    }
}

/// A fresh secret for a Lightning swap: `{"preimage", "hash"}`, the hash being SHA-256 of
/// the preimage, as Lightning's payment hash is.
#[no_mangle]
pub extern "C" fn new_secret() -> i32 {
    let p: [u8; 32] = rand::thread_rng().gen();
    done(Ok(J::Obj(vec![("preimage".into(), J::str(hex::encode(p))), ("hash".into(), J::str(hex::encode(sha256(&p))))]).to_json()))
}

/// The transaction that releases a lock to its claim address: `{"lock", "preimage"}`.
#[no_mangle]
pub extern "C" fn unlock_tx(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let lock = hex32(r.get("lock").and_then(|x| x.as_str()).ok_or("lock")?)?;
        let preimage = hex32(r.get("preimage").and_then(|x| x.as_str()).ok_or("preimage")?)?;
        let tx = Tx::Act(Action::Unlock { lock, preimage });
        Ok(J::Obj(vec![("tx".into(), J::str(hex::encode(tx.to_bytes()))), ("txid".into(), J::str(hash_hex(&tx.id())))]).to_json())
    })())
}

/// The transaction that returns a timed-out lock to its refund address: `{"lock"}`.
#[no_mangle]
pub extern "C" fn expire_tx(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let lock = hex32(r.get("lock").and_then(|x| x.as_str()).ok_or("lock")?)?;
        let tx = Tx::Act(Action::Expire { lock });
        Ok(J::Obj(vec![("tx".into(), J::str(hex::encode(tx.to_bytes()))), ("txid".into(), J::str(hash_hex(&tx.id())))]).to_json())
    })())
}

/// The note a released lock pays: `{"lock", "tag": "claim"|"refund", "address", "amount"}`
/// gives `{"note", "cm"}`. Its opening is public, so anyone can compute it; only the key
/// behind the address can spend it.
#[no_mangle]
pub extern "C" fn payout_note(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let lock = hex32(r.get("lock").and_then(|x| x.as_str()).ok_or("lock")?)?;
        let tag = match r.get("tag").and_then(|x| x.as_str()) {
            Some("claim") => 3,
            Some("refund") => 4,
            _ => return Err("tag is claim or refund".into()),
        };
        let a_pk = parse_address(r.get("address").and_then(|x| x.as_str()).ok_or("address")?)?;
        let v: u64 = num(r.get("amount"), "amount")?;
        let rho = payout_rho(&lock, tag);
        Ok(J::Obj(vec![
            ("note".into(), J::str(encode_note(&a_pk, v, &rho))),
            ("cm".into(), J::str(hex::encode(words_to_bytes(&note::commit(&a_pk, v, &rho))))),
        ])
        .to_json())
    })())
}

/// Build and prove a payment. Request (JSON):
///   {"sk": hex, "inputs": [{"value","rho","pos","path":[32 hex]}] (one or two),
///    "outputs": [{"address","value"}] (one or two), "fee", "memo": text,
///    "net": "test" (the default), "main" or "dry",
///    "lock": {"hash", "timeout", "claim", "refund", "amount"} (optional)}
/// A lock takes `amount` from the inputs, beyond the outputs and the fee. An output to a
/// delivery address (`nsd1…`) is sealed to its key and travels on chain; any other output is
/// sealed to `sk`'s own key, so every memo looks alike.
/// Result: {"tx": hex bytes, "txid", "notes": [note string per output], "nf": [hex, hex],
/// "lock": id (with a lock)}.
#[no_mangle]
pub extern "C" fn prove(p: *const u8, n: usize) -> i32 {
    done((|| {
        let r = J::parse(bytes(p, n))?;
        let sk = w8(r.get("sk").and_then(|x| x.as_str()).ok_or("sk")?)?;
        let J::Arr(ins) = r.get("inputs").ok_or("inputs")? else { return Err("inputs".into()) };
        let J::Arr(outs) = r.get("outputs").ok_or("outputs")? else { return Err("outputs".into()) };
        if ins.is_empty() || ins.len() > 2 || outs.is_empty() || outs.len() > 2 {
            return Err("one or two inputs and one or two outputs".into());
        }
        let fee = u64_of(r.get("fee"))?;
        let text = r.get("memo").and_then(|m| m.as_str()).unwrap_or("").as_bytes().to_vec();
        let mut inputs = vec![];
        for i in ins {
            let J::Arr(path) = i.get("path").ok_or("path")? else { return Err("path".into()) };
            if path.len() != DEPTH {
                return Err("path must have 32 hashes".into());
            }
            let mut pw = [[0u32; 8]; DEPTH];
            for (k, h) in path.iter().enumerate() {
                pw[k] = w8(h.as_str().ok_or("path")?)?;
            }
            let pos: u32 = match i.get("pos") {
                Some(J::Num(s)) | Some(J::Str(s)) => s.parse().map_err(|_| "pos")?,
                _ => return Err("pos".into()),
            };
            inputs.push(InputNote { sk, v: u64_of(i.get("value"))?, rho: hex_rho(i.get("rho").and_then(|x| x.as_str()).ok_or("rho")?)?, pos, path: pw });
        }
        let dummy = [false, inputs.len() == 1];
        if inputs.len() == 1 {
            inputs.push(InputNote::dummy());
        }
        let mut rng = rand::thread_rng();
        let (mut outputs, mut keys) = (vec![], vec![]);
        for o in outs {
            let (a_pk, key) = parse_any_address(o.get("address").and_then(|x| x.as_str()).ok_or("address")?)?;
            outputs.push(OutputNote { a_pk, v: u64_of(o.get("value"))?, rho: rng.gen() });
            keys.push(key);
        }
        let real_outs = outputs.len();
        if outputs.len() == 1 {
            // a zero-value second output to the payer's own address
            outputs.push(OutputNote { a_pk: note::address(&sk), v: 0, rho: rng.gen() });
            keys.push(None);
        }
        let outputs = [outputs[0].clone(), outputs[1].clone()];
        let memo = memo_for(&sk, &outputs, [keys[0].as_deref(), keys[1].as_deref()], &text)?;
        let post = match r.get("lock") {
            None | Some(J::Null) => None,
            Some(l) => Some(LockPost {
                hash: hex32(l.get("hash").and_then(|x| x.as_str()).ok_or("lock hash")?)?,
                timeout: num(l.get("timeout"), "lock timeout")?,
                claim_addr: parse_any_address(l.get("claim").and_then(|x| x.as_str()).ok_or("lock claim")?)?.0,
                refund_addr: parse_any_address(l.get("refund").and_then(|x| x.as_str()).ok_or("lock refund")?)?.0,
                amount: num(l.get("amount"), "lock amount")?,
            }),
        };
        let deposit = post.clone().map(Deposit::Lock);
        let wit = SpendWitness { inputs: [inputs[0].clone(), inputs[1].clone()], outputs: outputs.clone(), dummy };
        let bind = bind_of(fee, &deposit, &memo);
        // the network the payment is for: its proofs carry its name and its number of queries
        let profile = match r.get("net").and_then(|x| x.as_str()) {
            None | Some("test") | Some("reg") => spend::TEST,
            Some("main") => spend::MAIN,
            Some("dry") => spend::DRY,
            Some(other) => return Err(format!("unknown network {other}")),
        };
        let (pi, proof) = spend::prove_for(&profile, &wit, bind)?;
        let tx = Tx::Spend(Spend { anchor: pi.root, nf: pi.nf, cm_out: pi.cm_out, dummy, fee, deposit, memo, proof: proof.to_bytes() });
        let notes: Vec<J> = outputs.iter().take(real_outs).map(|o| J::str(encode_note(&o.a_pk, o.v, &o.rho))).collect();
        let mut kv = vec![
            ("tx".into(), J::str(hex::encode(tx.to_bytes()))),
            ("txid".into(), J::str(hash_hex(&tx.id()))),
            ("notes".into(), J::Arr(notes)),
            ("nf".into(), J::Arr(pi.nf.iter().map(|x| J::str(hex::encode(words_to_bytes(x)))).collect())),
        ];
        if let Some(p) = &post {
            kv.push(("lock".into(), J::str(hex::encode(lock_id(p, &pi.nf[0])))));
        }
        Ok(J::Obj(kv).to_json())
    })())
}
