//! The language conditions are written in (`crate::cond`): a small stack machine in the
//! manner of Bitcoin's Script, with SHA-256, the block height, the payout being chosen, and
//! post-quantum signatures (SLH-DSA-SHA2-128s, FIPS 205, the scheme job keys use).
//!
//! A program runs on a stack of byte strings that its witness fills, bottom first, and
//! succeeds when it ends with a true value on top: any string with a non-zero byte. Numbers
//! are little-endian, at most eight bytes, and zero is the empty string. Every program
//! halts: there are no loops, and its length, steps, stack and signature checks are capped.
//!
//! Signatures sign the condition and the payout chosen (`cond::sign_message`), so a
//! signature for one payout cannot be used to choose another. A program that releases
//! coins without a signature, such as a bare hash lock, should name its payout with
//! `PAYOUT <n> NUMEQUALVERIFY`, or have one payout only: whoever sees the witness in a
//! pending transaction could otherwise submit it with another payout first.

use crate::hash::sha256;

pub const MAX_PROGRAM: usize = 10_000;
/// Largest stack/witness item: accommodates SLH-DSA-SHA2-128s signatures (7,856 bytes).
pub const MAX_ITEM: usize = 8_192;
/// Total witness byte budget across all witness items (anti-DoS bound).
pub const MAX_WITNESS_BYTES: usize = 131_072;
pub const MAX_STACK: usize = 64;
pub const MAX_STEPS: usize = 1_000;
pub const MAX_SIGCHECKS: usize = 16;
pub const MAX_WITNESS: usize = 32;
const MAX_KEYS: usize = 16;

pub mod op {
    pub const FALSE: u8 = 0x00;
    pub const PUSHDATA1: u8 = 0x4c;
    pub const PUSHDATA2: u8 = 0x4d;
    /// `OP_1` .. `OP_16` push the numbers 1 to 16.
    pub const N1: u8 = 0x51;
    pub const N16: u8 = 0x60;
    pub const IF: u8 = 0x63;
    pub const NOTIF: u8 = 0x64;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const VERIFY: u8 = 0x69;
    pub const DROP: u8 = 0x75;
    pub const DUP: u8 = 0x76;
    pub const SWAP: u8 = 0x7c;
    pub const SIZE: u8 = 0x82;
    pub const EQUAL: u8 = 0x87;
    pub const EQUALVERIFY: u8 = 0x88;
    pub const NOT: u8 = 0x91;
    pub const BOOLAND: u8 = 0x9a;
    pub const BOOLOR: u8 = 0x9b;
    pub const NUMEQUAL: u8 = 0x9c;
    pub const NUMEQUALVERIFY: u8 = 0x9d;
    pub const LESSTHAN: u8 = 0x9f;
    pub const GREATERTHAN: u8 = 0xa0;
    pub const SHA256: u8 = 0xa8;
    pub const CHECKSIG: u8 = 0xac;
    pub const CHECKSIGVERIFY: u8 = 0xad;
    pub const CHECKMULTISIG: u8 = 0xae;
    pub const CHECKMULTISIGVERIFY: u8 = 0xaf;
    /// Pop n: true if the block that runs the program is at height n or later.
    pub const AFTER: u8 = 0xb1;
    /// Pop n: true if the block that runs the program is below height n.
    pub const BEFORE: u8 = 0xb2;
    /// Push the index of the payout being chosen.
    pub const PAYOUT: u8 = 0xb3;
}

/// What a program can see of the world: the height of the block that runs it, the payout
/// being chosen, and the message signatures must sign.
pub struct Ctx<'a> {
    pub height: u32,
    pub payout: u8,
    pub msg: &'a [u8; 32],
}

pub fn truthy(x: &[u8]) -> bool {
    x.iter().any(|b| *b != 0)
}

/// A number's encoding: little-endian with no trailing zero bytes, so zero is empty.
pub fn num_bytes(n: u64) -> Vec<u8> {
    let b = n.to_le_bytes();
    let len = 8 - (n.leading_zeros() / 8) as usize;
    b[..len].to_vec()
}

fn num(x: &[u8]) -> Result<u64, String> {
    if x.len() > 8 {
        return Err("a number is at most eight bytes".into());
    }
    let mut b = [0u8; 8];
    b[..x.len()].copy_from_slice(x);
    Ok(u64::from_le_bytes(b))
}

fn boolean(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        vec![]
    }
}

struct Machine<'a> {
    stack: Vec<Vec<u8>>,
    ctx: &'a Ctx<'a>,
    sigchecks: usize,
}

impl Machine<'_> {
    fn pop(&mut self) -> Result<Vec<u8>, String> {
        self.stack.pop().ok_or_else(|| "the stack is empty".to_string())
    }
    fn push(&mut self, x: Vec<u8>) -> Result<(), String> {
        if x.len() > MAX_ITEM {
            return Err("item too large".into());
        }
        if self.stack.len() >= MAX_STACK {
            return Err("stack too deep".into());
        }
        self.stack.push(x);
        Ok(())
    }
    fn check_sig(&mut self, pk: &[u8], sig: &[u8]) -> Result<bool, String> {
        self.sigchecks += 1;
        if self.sigchecks > MAX_SIGCHECKS {
            return Err("too many signature checks".into());
        }
        Ok(crate::job::verify_sig(pk, self.ctx.msg, sig))
    }
    /// `<sig_1> .. <sig_k> k <pk_1> .. <pk_n> n`: true if the k signatures are by k of the n
    /// keys, in the same order.
    fn check_multisig(&mut self) -> Result<bool, String> {
        let n = num(&self.pop()?)? as usize;
        if n > MAX_KEYS {
            return Err("too many keys".into());
        }
        let mut pks = (0..n).map(|_| self.pop()).collect::<Result<Vec<_>, _>>()?;
        pks.reverse();
        let k = num(&self.pop()?)? as usize;
        if k > n {
            return Err("more signatures than keys".into());
        }
        let mut sigs = (0..k).map(|_| self.pop()).collect::<Result<Vec<_>, _>>()?;
        sigs.reverse();
        let mut next = 0;
        for sig in &sigs {
            loop {
                if next == pks.len() {
                    return Ok(false);
                }
                let pk = pks[next].clone();
                next += 1;
                if self.check_sig(&pk, sig)? {
                    break;
                }
            }
        }
        Ok(true)
    }
}

/// Run `program` with `witness` on the stack. `Ok` means the condition is met.
pub fn run(program: &[u8], witness: &[Vec<u8>], ctx: &Ctx) -> Result<(), String> {
    if program.len() > MAX_PROGRAM {
        return Err("program too long".into());
    }
    if witness.len() > MAX_WITNESS {
        return Err("witness too long".into());
    }
    let total_witness_bytes: usize = witness.iter().map(Vec::len).sum();
    if total_witness_bytes > MAX_WITNESS_BYTES {
        return Err("witness bytes exceed limit".into());
    }
    let mut m = Machine { stack: vec![], ctx, sigchecks: 0 };
    for w in witness {
        m.push(w.clone())?;
    }
    // for each open IF, whether its branch runs
    let mut branches: Vec<bool> = vec![];
    let (mut pc, mut steps) = (0usize, 0usize);
    while pc < program.len() {
        steps += 1;
        if steps > MAX_STEPS {
            return Err("too many steps".into());
        }
        let o = program[pc];
        pc += 1;
        let running = branches.iter().all(|b| *b);
        // pushes: read the data whether or not the branch runs
        if (0x01..=0x4b).contains(&o) || o == op::PUSHDATA1 || o == op::PUSHDATA2 {
            let len = match o {
                op::PUSHDATA1 => {
                    let l = *program.get(pc).ok_or("program ends inside a push")? as usize;
                    pc += 1;
                    l
                }
                op::PUSHDATA2 => {
                    let b = program.get(pc..pc + 2).ok_or("program ends inside a push")?;
                    pc += 2;
                    u16::from_le_bytes([b[0], b[1]]) as usize
                }
                n => n as usize,
            };
            let data = program.get(pc..pc + len).ok_or("program ends inside a push")?.to_vec();
            pc += len;
            if running {
                m.push(data)?;
            }
            continue;
        }
        match o {
            op::IF | op::NOTIF => {
                let take = if running {
                    let t = truthy(&m.pop()?);
                    if o == op::IF {
                        t
                    } else {
                        !t
                    }
                } else {
                    false
                };
                branches.push(take);
                continue;
            }
            op::ELSE => {
                let b = branches.last_mut().ok_or("ELSE without IF")?;
                *b = !*b;
                continue;
            }
            op::ENDIF => {
                branches.pop().ok_or("ENDIF without IF")?;
                continue;
            }
            _ => {}
        }
        if !running {
            // check the opcode exists even in a branch that does not run
            if !known(o) {
                return Err(format!("unknown opcode {o:#04x}"));
            }
            continue;
        }
        match o {
            op::FALSE => m.push(vec![])?,
            op::N1..=op::N16 => m.push(vec![o - op::N1 + 1])?,
            op::VERIFY => {
                if !truthy(&m.pop()?) {
                    return Err("VERIFY failed".into());
                }
            }
            op::DROP => {
                m.pop()?;
            }
            op::DUP => {
                let x = m.stack.last().ok_or("the stack is empty")?.clone();
                m.push(x)?;
            }
            op::SWAP => {
                let (a, b) = (m.pop()?, m.pop()?);
                m.push(a)?;
                m.push(b)?;
            }
            op::SIZE => {
                let n = m.stack.last().ok_or("the stack is empty")?.len() as u64;
                m.push(num_bytes(n))?;
            }
            op::EQUAL | op::EQUALVERIFY => {
                let eq = m.pop()? == m.pop()?;
                if o == op::EQUALVERIFY {
                    if !eq {
                        return Err("EQUALVERIFY failed".into());
                    }
                } else {
                    m.push(boolean(eq))?;
                }
            }
            op::NOT => {
                let x = m.pop()?;
                m.push(boolean(!truthy(&x)))?;
            }
            op::BOOLAND | op::BOOLOR => {
                let (a, b) = (truthy(&m.pop()?), truthy(&m.pop()?));
                m.push(boolean(if o == op::BOOLAND { a && b } else { a || b }))?;
            }
            op::NUMEQUAL | op::NUMEQUALVERIFY | op::LESSTHAN | op::GREATERTHAN => {
                let b = num(&m.pop()?)?;
                let a = num(&m.pop()?)?;
                let r = match o {
                    op::LESSTHAN => a < b,
                    op::GREATERTHAN => a > b,
                    _ => a == b,
                };
                if o == op::NUMEQUALVERIFY {
                    if !r {
                        return Err("NUMEQUALVERIFY failed".into());
                    }
                } else {
                    m.push(boolean(r))?;
                }
            }
            op::SHA256 => {
                let x = m.pop()?;
                m.push(sha256(&x).to_vec())?;
            }
            op::CHECKSIG | op::CHECKSIGVERIFY => {
                let pk = m.pop()?;
                let sig = m.pop()?;
                let ok = m.check_sig(&pk, &sig)?;
                if o == op::CHECKSIGVERIFY {
                    if !ok {
                        return Err("CHECKSIGVERIFY failed".into());
                    }
                } else {
                    m.push(boolean(ok))?;
                }
            }
            op::CHECKMULTISIG | op::CHECKMULTISIGVERIFY => {
                let ok = m.check_multisig()?;
                if o == op::CHECKMULTISIGVERIFY {
                    if !ok {
                        return Err("CHECKMULTISIGVERIFY failed".into());
                    }
                } else {
                    m.push(boolean(ok))?;
                }
            }
            op::AFTER | op::BEFORE => {
                let n = num(&m.pop()?)?;
                let h = ctx.height as u64;
                m.push(boolean(if o == op::AFTER { h >= n } else { h < n }))?;
            }
            op::PAYOUT => m.push(num_bytes(ctx.payout as u64))?,
            _ => return Err(format!("unknown opcode {o:#04x}")),
        }
    }
    if !branches.is_empty() {
        return Err("IF without ENDIF".into());
    }
    match m.stack.last() {
        Some(x) if truthy(x) => Ok(()),
        _ => Err("the program did not end true".into()),
    }
}

fn known(o: u8) -> bool {
    NAMES.iter().any(|(_, c)| *c == o) || (op::N1..=op::N16).contains(&o)
}

const NAMES: &[(&str, u8)] = &[
    ("FALSE", op::FALSE),
    ("0", op::FALSE),
    ("TRUE", op::N1),
    ("IF", op::IF),
    ("NOTIF", op::NOTIF),
    ("ELSE", op::ELSE),
    ("ENDIF", op::ENDIF),
    ("VERIFY", op::VERIFY),
    ("DROP", op::DROP),
    ("DUP", op::DUP),
    ("SWAP", op::SWAP),
    ("SIZE", op::SIZE),
    ("EQUAL", op::EQUAL),
    ("EQUALVERIFY", op::EQUALVERIFY),
    ("NOT", op::NOT),
    ("BOOLAND", op::BOOLAND),
    ("BOOLOR", op::BOOLOR),
    ("NUMEQUAL", op::NUMEQUAL),
    ("NUMEQUALVERIFY", op::NUMEQUALVERIFY),
    ("LESSTHAN", op::LESSTHAN),
    ("GREATERTHAN", op::GREATERTHAN),
    ("SHA256", op::SHA256),
    ("CHECKSIG", op::CHECKSIG),
    ("CHECKSIGVERIFY", op::CHECKSIGVERIFY),
    ("CHECKMULTISIG", op::CHECKMULTISIG),
    ("CHECKMULTISIGVERIFY", op::CHECKMULTISIGVERIFY),
    ("AFTER", op::AFTER),
    ("BEFORE", op::BEFORE),
    ("PAYOUT", op::PAYOUT),
];

/// The bytes that push `data`.
pub fn push(data: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    match data.len() {
        0 => out.push(op::FALSE),
        n @ 1..=0x4b => out.push(n as u8),
        n @ 0x4c..=0xff => out.extend_from_slice(&[op::PUSHDATA1, n as u8]),
        n => {
            out.push(op::PUSHDATA2);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

/// The bytes that push the number `n` (`OP_n` for 1 to 16).
pub fn push_num(n: u64) -> Vec<u8> {
    match n {
        1..=16 => vec![op::N1 + n as u8 - 1],
        _ => push(&num_bytes(n)),
    }
}

/// Assemble a program from text: opcode names (with or without `OP_`), decimal numbers,
/// and data as `0x` followed by hex. For example a two-of-three escrow:
/// `2 0x<key A> 0x<key B> 0x<key C> 3 CHECKMULTISIG`.
pub fn assemble(text: &str) -> Result<Vec<u8>, String> {
    let mut out = vec![];
    for tok in text.split_whitespace() {
        let t = tok.trim_start_matches("OP_").trim_start_matches("op_");
        if let Some(h) = t.strip_prefix("0x") {
            out.extend(push(&hex::decode(h).map_err(|_| format!("bad hex: {tok}"))?));
        } else if let Ok(n) = t.parse::<u64>() {
            out.extend(push_num(n));
        } else if let Some((_, c)) = NAMES.iter().find(|(name, _)| name.eq_ignore_ascii_case(t)) {
            out.push(*c);
        } else {
            return Err(format!("unknown word: {tok}"));
        }
    }
    if out.len() > MAX_PROGRAM {
        return Err("program too long".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobKey;

    fn ctx(height: u32, payout: u8, msg: &[u8; 32]) -> Ctx<'_> {
        Ctx { height, payout, msg }
    }

    #[test]
    fn numbers_hashes_heights_and_branches() {
        let m = [7u8; 32];
        let pre = b"open sesame".to_vec();
        let lock = assemble(&format!("SHA256 0x{} EQUAL", hex::encode(sha256(&pre)))).unwrap();
        assert!(run(&lock, &[pre.clone()], &ctx(1, 0, &m)).is_ok());
        assert!(run(&lock, &[b"wrong".to_vec()], &ctx(1, 0, &m)).is_err());
        // after height 100 payout 1, before it payout 0
        let p = assemble("IF 100 AFTER VERIFY PAYOUT 1 NUMEQUAL ELSE 100 BEFORE VERIFY PAYOUT 0 NUMEQUAL ENDIF").unwrap();
        assert!(run(&p, &[vec![1]], &ctx(100, 1, &m)).is_ok());
        assert!(run(&p, &[vec![1]], &ctx(99, 1, &m)).is_err());
        assert!(run(&p, &[vec![]], &ctx(99, 0, &m)).is_ok());
        assert!(run(&p, &[vec![]], &ctx(99, 1, &m)).is_err(), "the payout is part of the condition");
        assert_eq!(num_bytes(0), Vec::<u8>::new());
        assert_eq!(num_bytes(300), vec![0x2c, 0x01]);
        assert!(run(&assemble("300 0x2c01 NUMEQUAL").unwrap(), &[], &ctx(0, 0, &m)).is_ok());
    }

    #[test]
    fn two_of_three_signatures() {
        let keys: Vec<JobKey> = (0..3).map(|_| JobKey::generate()).collect();
        let pks: Vec<String> = keys.iter().map(|k| format!("0x{}", hex::encode(k.vk()))).collect();
        let prog = assemble(&format!("2 {} {} {} 3 CHECKMULTISIG", pks[0], pks[1], pks[2])).unwrap();
        let msg = [5u8; 32];
        let sig = |i: usize| keys[i].sign(&msg);
        assert!(run(&prog, &[sig(0), sig(2)], &ctx(1, 0, &msg)).is_ok());
        assert!(run(&prog, &[sig(1), sig(2)], &ctx(1, 0, &msg)).is_ok());
        assert!(run(&prog, &[sig(2), sig(0)], &ctx(1, 0, &msg)).is_err(), "in the keys' order");
        assert!(run(&prog, &[sig(0), sig(0)], &ctx(1, 0, &msg)).is_err(), "one key cannot sign twice");
        assert!(run(&prog, &[sig(0), sig(2)], &ctx(1, 0, &[6u8; 32])).is_err(), "signatures sign the payout");
        assert!(run(&prog, &[sig(0)], &ctx(1, 0, &msg)).is_err());
        let one = assemble(&format!("{} CHECKSIG", pks[1])).unwrap();
        assert!(run(&one, &[sig(1)], &ctx(1, 0, &msg)).is_ok());
        assert!(run(&one, &[sig(0)], &ctx(1, 0, &msg)).is_err());
    }

    #[test]
    fn programs_are_bounded() {
        let m = [0u8; 32];
        assert!(run(&assemble("1 IF 1").unwrap(), &[], &ctx(0, 0, &m)).is_err(), "IF without ENDIF");
        assert!(run(&[0xff], &[], &ctx(0, 0, &m)).is_err(), "unknown opcode");
        assert!(run(&assemble("0 IF 1 ELSE 1 ENDIF").unwrap(), &[], &ctx(0, 0, &m)).is_ok());
        assert!(run(&[op::FALSE, op::IF, 0xff, op::ENDIF, op::N1], &[], &ctx(0, 0, &m)).is_err(), "unknown even unrun");
        assert!(run(&vec![op::N1; MAX_STACK + 1], &[], &ctx(0, 0, &m)).is_err(), "stack bounded");
        let long: Vec<u8> = std::iter::repeat([op::N1, op::DROP]).take(MAX_STEPS).flatten().chain([op::N1]).collect();
        assert!(run(&long, &[], &ctx(0, 0, &m)).is_err(), "steps bounded");
        assert!(run(&[0x05, 1, 2], &[], &ctx(0, 0, &m)).is_err(), "a push past the end");
        assert!(assemble("FROB").is_err());
    }
}
