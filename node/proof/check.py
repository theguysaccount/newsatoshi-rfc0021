#!/usr/bin/env python3
"""Machine checks of the payment circuit against its specification.

    cargo run --release --example extract_constraints -- proof/constraints.json
    python3 proof/check.py proof/constraints.json

The constraints come from the code (examples/extract_constraints.rs evaluates the very
function the prover and verifier use, on polynomials). The specification is written here,
from FIPS 180-4 and from the statement in src/spend.rs, without reading the circuit's code:
SHA-256's constants are derived from the primes, its functions from XOR, AND and NOT.

What is checked, for every pair of consecutive rows of the 8,192:

  1. Census. Each row pair is classified by its selectors and by whether the next row is
     part of a compression. Every class is one the specification describes.
  2. Exactness. On each class, every one of the 249 constraints is the same polynomial as
     the specification's, over the field, once the variables that are bits on that class
     are reduced (x*x = x). Two multilinear polynomials that agree on every input of bits
     are the same polynomial, so this is equality on every input, not on samples.
  3. No wrapping. Every relation the soundness argument reads as an equation between
     integers (the rounds, the message schedule, the digest, the values and the balance)
     has, under the ranges the circuit enforces, an integer value strictly between -p and
     p. So the field equation holds exactly when the integer equation does.
  4. Arithmetic lemmas (Z3): what those integer equations imply modulo 2^32, including the
     two places a word is not reduced (W_0 and a digest word), which are shown harmless.

Exit status 0 only if every check passes.
"""

import json, re, sys, itertools, pathlib

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"

# ---- SHA-256 from FIPS 180-4, derived rather than copied -----------------------------------

def primes(n):
    out, k = [], 2
    while len(out) < n:
        if all(k % q for q in out if q * q <= k):
            out.append(k)
        k += 1
    return out

def icbrt(n):
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y

import math
IV = [math.isqrt(q << 64) & 0xFFFFFFFF for q in primes(8)]          # sqrt fractions, 4.2.2/5.3.3
K = [icbrt(q << 96) & 0xFFFFFFFF for q in primes(64)]               # cube root fractions, 4.2.2
assert IV[0] == 0x6A09E667 and K[0] == 0x428A2F98 and K[63] == 0xC67178F2

def rotr(x, r): return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF
def big_s0(x): return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def big_s1(x): return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def ch(x, y, z): return (x & y) ^ (~x & z & 0xFFFFFFFF)
def maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)

# The statement's domain tags and tree depth (src/note.rs)
note = (SRC / "note.rs").read_text()
TAG = {k: int.from_bytes(re.search(rf'pub const TAG_{k}: u32 = u32::from_be_bytes\(\*b"(....)"\)', note).group(1).encode(), "big")
       for k in ("ADDR", "CM", "NF")}
DEPTH = int(re.search(r"pub const DEPTH: usize = (\d+);", note).group(1))

# ---- the trace's columns (src/spend.rs, the layout the statement describes) -----------------
spend = (SRC / "spend.rs").read_text()
COL = {m.group(1): int(m.group(2)) for m in re.finditer(r"pub const COL_(\w+): usize = (\d+);", spend)}
WIDTH = int(re.search(r"pub const WIDTH: usize = (\d+);", spend).group(1))
PER = ["K", "ROUND", "BND", "ADDR", "CMIN", "MERKLE", "NF", "CMOUT", "W", "VCHK", "ACTROW", "ACT", "SKC", "RHOC"]
for i, name in enumerate(PER):
    assert re.search(rf"const P_{name}: usize = {i};", spend), name

data = json.load(open(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).parent / "constraints.json"))
P = data["modulus"]
assert P == 2**64 - 2**32 + 1 and data["width"] == WIDTH
ROWS, BLK = data["rows"], data["blk"]
KSYM = 10_000                  # the round constant, kept as one symbol: proven for every value

def cur(c, i=0): return COL[c] + i
def nxt(c, i=0): return WIDTH + COL[c] + i

# ---- polynomials over GF(p): {sorted tuple of variable ids: coefficient} --------------------

def poly(d): return {m: c % P for m, c in d.items() if c % P}
def const(c): return poly({(): c})
def var(v): return {(v,): 1}
def add(*ps):
    out = {}
    for p in ps:
        for m, c in p.items():
            out[m] = (out.get(m, 0) + c) % P
    return {m: c for m, c in out.items() if c}
def scale(p, k): return poly({m: c * k for m, c in p.items()})
def sub(a, b): return add(a, scale(b, -1))
def mul(a, b):
    out = {}
    for ma, ca in a.items():
        for mb, cb in b.items():
            m = tuple(sorted(ma + mb))
            out[m] = (out.get(m, 0) + ca * cb) % P
    return {m: c for m, c in out.items() if c}
ONE, ZERO = const(1), {}

def reduce_bits(p, bits):
    """x*x = x for every variable that is a bit."""
    out = {}
    for m, c in p.items():
        mm = []
        for v in m:
            if v in bits and mm and mm[-1] == v:
                continue
            mm.append(v)
        mm = tuple(mm)
        out[mm] = (out.get(mm, 0) + c) % P
    return {m: c for m, c in out.items() if c}

# Boolean functions on bits, as polynomials (exact on 0/1)
def XOR(a, b): return sub(add(a, b), scale(mul(a, b), 2))
def AND(a, b): return mul(a, b)
def NOT(a): return sub(ONE, a)
def word(bits): return add(*[scale(b, 1 << i) for i, b in enumerate(bits)])
def bitsof(colname, row):
    f = cur if row == 0 else nxt
    return [var(f(colname, i)) for i in range(32)]
def ROTR(x, r): return [x[(i + r) % 32] for i in range(32)]                  # bit i of ROTR_r(x)
def SHR(x, s): return [x[i + s] if i + s < 32 else ZERO for i in range(32)]
def XOR3w(a, b, c): return [XOR(XOR(a[i], b[i]), c[i]) for i in range(32)]
def S0(x): return word(XOR3w(ROTR(x, 2), ROTR(x, 13), ROTR(x, 22)))
def S1(x): return word(XOR3w(ROTR(x, 6), ROTR(x, 11), ROTR(x, 25)))
def s0(x): return word(XOR3w(ROTR(x, 7), ROTR(x, 18), SHR(x, 3)))
def s1(x): return word(XOR3w(ROTR(x, 17), ROTR(x, 19), SHR(x, 10)))
def CH(e, f, g): return word([XOR(AND(e[i], f[i]), AND(NOT(e[i]), g[i])) for i in range(32)])
def MAJ(a, b, c): return word([XOR(XOR(AND(a[i], b[i]), AND(a[i], c[i])), AND(b[i], c[i])) for i in range(32)])

# ---- the specification of one row pair, given its selectors ---------------------------------

def k0():
    """Round 0 from the IV, everything but W_0 (FIPS 180-4, 6.2.2 step 3)."""
    a, b, c, d, e, f, g, h = IV
    t1 = h + big_s1(e) + ch(e, f, g) + K[0]
    return t1 + big_s0(a) + maj(a, b, c), d + t1

def spec(sel):
    s = lambda n: sel[PER.index(n)]
    p_round, p_bnd, p_addr, p_cmin, p_merkle, p_nf, p_cmout = (s(n) for n in ("ROUND", "BND", "ADDR", "CMIN", "MERKLE", "NF", "CMOUT"))
    p_w, p_vchk, p_actrow, p_act, p_skc, p_rhoc = (s(n) for n in ("W", "VCHK", "ACTROW", "ACT", "SKC", "RHOC"))
    p_iv = p_addr + p_cmin + p_merkle + p_nf + p_cmout          # a compression starts on the next row
    kk = var(KSYM)
    # the state of round t+1 on the pair (t, t+1): a..h
    a, b, c = bitsof("A", 1), bitsof("AP", 1), bitsof("AP", 0)
    d = var(cur("CWORD"))
    e, f, g = bitsof("E", 1), bitsof("EP", 1), bitsof("EP", 0)
    h = var(cur("GWORD"))
    W = lambda r, j: var((cur if r == 0 else nxt)("W", j))
    carry = lambda col: add(var(nxt(col, 0)), scale(var(nxt(col, 1)), 2), scale(var(nxt(col, 2)), 4))
    T1 = add(h, S1(e), CH(e, f, g), kk, W(1, 0))
    T2 = add(S0(a), MAJ(a, b, c))
    k0a, k0e = k0()
    out = []
    # a_{t+2} and e_{t+2}, kept as a word plus a 3-bit carry; on a block's first row, round 0
    an = add(var(nxt("AN")), scale(carry("CA"), 1 << 32))
    en = add(var(nxt("EN")), scale(carry("CE"), 1 << 32))
    out.append(add(scale(sub(an, add(T1, T2)), p_round), scale(sub(an, add(const(k0a), W(1, 0))), p_iv)))
    out.append(add(scale(sub(en, add(d, T1)), p_round), scale(sub(en, add(const(k0e), W(1, 0))), p_iv)))
    # the bits of a_{t+1}, e_{t+1} are the word computed on the row before (or the IV)
    out.append(add(scale(sub(word(a), var(cur("AN"))), p_round), scale(sub(word(a), const(IV[0])), p_iv)))
    out.append(add(scale(sub(word(e), var(cur("EN"))), p_round), scale(sub(word(e), const(IV[4])), p_iv)))
    ivbit = lambda i, j: const((IV[i] >> j) & 1)
    a_c, e_c = bitsof("A", 0), bitsof("E", 0)
    for j in range(32):                                   # b_{t+1} = a_t
        out.append(add(scale(sub(b[j], a_c[j]), p_round), scale(sub(b[j], ivbit(1, j)), p_iv)))
    for j in range(32):                                   # f_{t+1} = e_t
        out.append(add(scale(sub(f[j], e_c[j]), p_round), scale(sub(f[j], ivbit(5, j)), p_iv)))
    out.append(add(scale(sub(var(nxt("CWORD")), word(c)), p_round), scale(sub(var(nxt("CWORD")), const(IV[2])), p_iv)))   # c_{t+2} = b_{t+1}
    out.append(add(scale(sub(var(nxt("GWORD")), word(g)), p_round), scale(sub(var(nxt("GWORD")), const(IV[6])), p_iv)))
    # the message window and what each kind of compression reads (the statement)
    sk = [var(nxt("SK", i)) for i in range(8)]
    rho = [var(nxt("RHO", i)) for i in range(5)]
    dig = [var(cur("DIG", i)) for i in range(8)]
    bit, pos = var(nxt("BIT")), var(nxt("POS"))
    x1, x14 = bitsof("X1", 0), bitsof("X14", 0)
    for j in range(16):
        if j < 15:
            r = scale(sub(W(1, j), W(0, j + 1)), p_round)                       # the window shifts
        else:                                                                   # W_{t+16}
            cw = add(var(cur("CWC")), scale(var(cur("CWC", 1)), 2))
            r = scale(sub(add(W(1, 15), scale(cw, 1 << 32)), add(s1(x14), W(0, 9), s0(x1), W(0, 0))), p_round)
        addr = [const(TAG["ADDR"])] + sk + [ZERO] * 7                           # address = H(TAG, sk)
        r = add(r, scale(sub(W(1, j), addr[j]), p_addr))
        cm = {0: const(TAG["CM"]), **{i: dig[i - 1] for i in range(1, 9)}, **{11 + i: rho[i] for i in range(5)}}
        if j in cm:                                                            # cm = H(TAG, a_pk, v, rho)
            r = add(r, scale(sub(W(1, j), cm[j]), p_cmin))
        node = dig[j] if j < 8 else dig[j - 8]                                 # the running node, left or right
        r = add(r, scale(mul(NOT(bit) if j < 8 else bit, sub(W(1, j), node)), p_merkle))
        nf = [const(TAG["NF"])] + sk + [pos] + rho + [ZERO]                    # nf = H(TAG, sk, pos, rho)
        r = add(r, scale(sub(W(1, j), nf[j]), p_nf))
        if j == 0:
            r = add(r, scale(sub(W(1, 0), const(TAG["CM"])), p_cmout))
        out.append(r)
    out.append(scale(sub(W(0, 1), word(x1)), p_round))                         # range checks of W_{t+1}, W_{t+14}
    out.append(scale(sub(W(0, 14), word(x14)), p_round))
    state = [var(cur("AN")), word(bitsof("A", 0)), word(bitsof("AP", 0)), var(cur("CWORD")),
             var(cur("EN")), word(bitsof("E", 0)), word(bitsof("EP", 0)), var(cur("GWORD"))]
    for j in range(8):                                                         # H_j = IV_j + state_j, carry in X1[j]
        out.append(scale(sub(add(dig[j], scale(x1[j], 1 << 32)), add(const(IV[j]), state[j])), p_bnd))
    for colname in ("A", "E", "X1", "X14"):
        for x in bitsof(colname, 0):
            out.append(scale(mul(x, sub(x, ONE)), p_actrow))
    for v in [cur("CA", i) for i in range(3)] + [cur("CE", i) for i in range(3)] + [cur("CWC", 0), cur("CWC", 1), cur("BIT")]:
        out.append(scale(mul(var(v), sub(var(v), ONE)), p_actrow))
    for i in range(8):                                                         # sk and rho stay the same
        out.append(scale(sub(sk[i], var(cur("SK", i))), p_skc))
    for i in range(5):
        out.append(scale(sub(rho[i], var(cur("RHO", i))), p_rhoc))
    # the position: bit k of a tree path enters with weight 2^k, carried within an input
    out.append(sub(sub(scale(pos, p_act), scale(var(cur("POS")), p_skc)), scale(bit, p_w)))
    v = add(scale(W(1, 9), 1 << 32), W(1, 10))                                 # a note's value: v_hi * 2^32 + v_lo
    out.append(add(scale(sub(var(nxt("BAL")), var(cur("BAL"))), p_act), scale(v, -p_cmin), scale(v, p_cmout)))
    out.append(scale(add(x1[28], x1[29], x1[30], x1[31]), p_vchk))             # v_hi < 2^28
    return out

# ---- 1. census -----------------------------------------------------------------------------

per = data["periodic"]
layout = data["layout"]
bitcols = lambda base: [base + COL[c] + i for c, n in (("A", 32), ("E", 32), ("X1", 32), ("X14", 32), ("CA", 3), ("CE", 3), ("CWC", 2)) for i in range(n)] + [base + COL["BIT"]]
apep = lambda base: [base + COL[c] + i for c in ("AP", "EP") for i in range(32)]
classes = {}
for r in range(ROWS - 1):
    sel = tuple(per[r][1:])                                # the round constant is a symbol
    act_cur, act_nxt = per[r][PER.index("ACTROW")], per[r + 1][PER.index("ACTROW")]
    classes.setdefault((sel, act_cur, act_nxt), []).append(r)
print(f"census: {ROWS - 1} row pairs fall into {len(classes)} classes")
fail = 0

# ---- 2. exactness --------------------------------------------------------------------------

cons = [poly({tuple(m): c for m, c in con}) for con in data["constraints"]]
assert len(cons) == 249
kpos = 2 * WIDTH + PER.index("K")

def exactness(show=False):
    bad = 0
    for (sel, act_cur, act_nxt), rows in sorted(classes.items(), key=lambda kv: kv[1][0]):
        full = (0,) + sel
        # bits on this pair: the booleanity constraints of an active row, and b_t, f_t of an
        # active row by induction (they equal bits of the row before, or of the IV)
        bits = set()
        if act_cur:
            bits |= set(bitcols(0)) | set(apep(0))
        if act_nxt:
            bits |= set(bitcols(WIDTH)) | set(apep(WIDTH))
        want = [reduce_bits(x, bits) for x in spec(full)]
        for i, con in enumerate(cons):
            got = {}
            for m, c in con.items():
                mm, k = [], c
                for v in m:
                    if v == kpos:
                        mm.append(KSYM)
                    elif v >= 2 * WIDTH:
                        k = k * full[v - 2 * WIDTH] % P
                    else:
                        mm.append(v)
                if k:
                    key = tuple(sorted(mm))
                    got[key] = (got.get(key, 0) + k) % P
            got = reduce_bits({m: c for m, c in got.items() if c}, bits)
            if got != want[i]:
                bad += 1
                if show and bad <= 5:
                    print(f"  MISMATCH: constraint {i} on rows like {rows[0]}: {len(sub(got, want[i]))} terms differ")
    return bad

bad = exactness(show=True)
fail += bad
print(f"exactness: 249 constraints x {len(classes)} classes, {bad} mismatches")

# The check must be able to fail: each of these small errors in the specification is caught.
saved = dict(S0=S0, CH=CH, IV=list(IV), TAG=dict(TAG), s1=s1)
mutants = {
    "Sigma0 rotating by 23 instead of 22": lambda: globals().update(S0=lambda x: word(XOR3w(ROTR(x, 2), ROTR(x, 13), ROTR(x, 23)))),
    "Ch as (e AND f) XOR (e AND g)": lambda: globals().update(CH=lambda e, f, g: word([XOR(AND(e[i], f[i]), AND(e[i], g[i])) for i in range(32)])),
    "one bit of the IV changed": lambda: IV.__setitem__(3, IV[3] ^ 1),
    "the nullifier's tag swapped for the commitment's": lambda: TAG.update(NF=TAG["CM"]),
    "sigma1 shifting by 9 instead of 10": lambda: globals().update(s1=lambda x: word(XOR3w(ROTR(x, 17), ROTR(x, 19), SHR(x, 9)))),
}
for name, mutate in mutants.items():
    mutate()
    n = exactness()
    fail += n == 0
    print(f"self-test: a specification with {name} is caught: {n} mismatches")
    globals().update(S0=saved["S0"], CH=saved["CH"], s1=saved["s1"])
    IV[:] = saved["IV"]
    TAG.clear(); TAG.update(saved["TAG"])

# The rows: the selectors put each kind of step where the statement says, and the round
# constants on the rows are FIPS 180-4's.
kinds = ["Rand"] + [k for i in range(2) for k in [f"Addr({i})", f"CmIn({i})"] + [f"Merkle({i}, {d})" for d in range(DEPTH)] + [f"Nf({i})"]] + ["CmOut(0)", "CmOut(1)"]
kinds += ["Rand"] * (ROWS // BLK - len(kinds))
assert layout == kinds, "the block layout is the statement's"
last = kinds.index("CmOut(1)")
G = lambda r, n: per[r][PER.index(n)]
for r in range(ROWS):
    b, t = divmod(r, BLK)
    k, nk = kinds[b], kinds[b + 1] if b + 1 < len(kinds) else "Rand"
    act = k != "Rand"
    want = {"ROUND": int(act and t < 63), "BND": int(act and t == 63), "ACTROW": int(act),
            "ADDR": int(t == 63 and nk.startswith("Addr")), "CMIN": int(t == 63 and nk.startswith("CmIn")),
            "MERKLE": int(t == 63 and nk.startswith("Merkle")), "NF": int(t == 63 and nk.startswith("Nf")),
            "CMOUT": int(t == 63 and nk.startswith("CmOut")),
            "W": (1 << int(nk.split(", ")[1][:-1])) if t == 63 and nk.startswith("Merkle") else 0,
            "VCHK": int(act and t == 8 and k[:4] in ("CmIn", "CmOu")),
            "ACT": int(BLK <= r and r + 1 < (last + 1) * BLK), "K": K[(t + 1) % 64]}
    want["SKC"] = want["ACT"] * (1 - want["ADDR"])
    want["RHOC"] = want["ACT"] * (1 - want["CMIN"])
    for n, v in want.items():
        if G(r, n) != v:
            fail += 1
            print(f"  ROW MISMATCH: row {r} selector {n} is {G(r, n)}, the statement says {v}")
            break
row0 = lambda k: kinds.index(k) * BLK
row63 = lambda k: kinds.index(k) * BLK + BLK - 1
dig = lambda row: [[COL["DIG"] + j, row] for j in range(8)]
real = [[COL["BAL"], BLK], [COL["POS"], BLK]]
dummy = [[COL["BAL"], BLK], [COL["POS"], BLK]]
for i in range(2):
    real += dig(row63(f"Merkle({i}, {DEPTH - 1})")) + dig(row63(f"Nf({i})"))
    dummy += [[COL["W"] + 9, row0(f"CmIn({i})")], [COL["W"] + 10, row0(f"CmIn({i})")]] + dig(row63(f"Nf({i})"))
for o in range(2):
    real += dig(row63(f"CmOut({o})"))
    dummy += dig(row63(f"CmOut({o})"))
real.append([COL["BAL"], row63("CmOut(1)")])
dummy.append([COL["BAL"], row63("CmOut(1)")])
ok = sorted(map(tuple, data["assert_real"])) == sorted(map(tuple, real)) and sorted(map(tuple, data["assert_dummy"])) == sorted(map(tuple, dummy))
fail += not ok
print(f"rows: the {ROWS} rows carry the statement's selectors and FIPS 180-4's round constants; the boundary cells are the statement's: {ok}")

# ---- 3. no wrapping ------------------------------------------------------------------------
# Ranges the circuit enforces on an active pair (each by a constraint shown exact above):
# bits are 0 or 1; c_t, g_t are words of bits; a_{t+1}, e_{t+1} (AN, EN) are words of the next
# row's bits; W_{t+1} and W_{t+14} are words of X1, X14; every other window word is one of
# those on another row, except W_0 of a compression; the round constant is a 32-bit word.
def bound(p, rng):
    lo = hi = 0
    for m, c in p.items():
        c = c - P if c > P // 2 else c
        vals = [rng[v] for v in m]
        prods = [math.prod(x) for x in itertools.product(*vals)] if vals else [1]
        lo += min(c * x for x in prods)
        hi += max(c * x for x in prods)
    return lo, hi

W32 = (0, 2**32 - 1)
def ranges(row_t, unbounded=()):
    rng = {KSYM: W32}
    for v in bitcols(0) + apep(0) + bitcols(WIDTH) + apep(WIDTH):
        rng[v] = (0, 1)
    for v in [cur("CWORD"), cur("GWORD"), nxt("CWORD"), nxt("GWORD"), cur("AN"), cur("EN"), nxt("AN"), nxt("EN")]:
        rng[v] = W32
    for j in range(16):
        rng[cur("W", j)] = rng[nxt("W", j)] = W32
    for v in unbounded:
        rng[v] = (0, P - 1)
    return rng

IDX = {"a": 0, "e": 1, "w16": 70 + 15, "x1": 86, "x14": 87, "dig": 88}
round_sel = next(k for k in classes if k[0][PER.index("ROUND") - 1] == 1 and k[1] and k[2])
sp = spec((0,) + round_sel[0])
rng = ranges(0)
bits01 = set(v for v, r in rng.items() if r == (0, 1))
for key, name in [("a", "a of each round"), ("e", "e of each round"), ("w16", "W_{t+16}, on rows where W_t is range-checked (all but row 0)"),
                  ("x1", "the range check of W_{t+1}"), ("x14", "the range check of W_{t+14}")]:
    lo, hi = bound(reduce_bits(sp[IDX[key]], bits01), rng)
    ok = -P < lo and hi < P
    fail += not ok
    print(f"no wrap: {name}: integer value in [{lo}, {hi}], {'inside' if ok else 'OUTSIDE'} (-p, p)")
# the balance: four values below 2^60, so the sum of their signs is far from p/2
vmax = 2**60 - 1
lo, hi = -2 * vmax, 2 * vmax
ok = -P // 2 < lo and hi < P // 2
fail += not ok
print(f"no wrap: the balance of two inputs and two outputs below 2^60 lies in [{lo}, {hi}], inside (-p/2, p/2): {ok}")

# ---- 4. arithmetic lemmas ------------------------------------------------------------------
import z3

def prove(name, hyps, goal):
    s = z3.Solver()
    s.add(*hyps)
    s.add(z3.Not(goal))
    r = s.check()
    global fail
    fail += r != z3.unsat
    print(f"lemma: {name}: {'proved' if r == z3.unsat else 'NOT PROVED (' + str(r) + ')'}")

an, c, S, dig, x, ivj, out, k, w0 = z3.Ints("an c S dig x ivj out k w0")
two32 = 2**32
# a round: a word below 2^32 plus 2^32 times a carry below 8 equals the sum: the word is the
# sum modulo 2^32 (the sum of seven words is below 2^35, so the carry fits)
prove("a round's word is its sum modulo 2^32",
      [0 <= an, an < two32, 0 <= c, c < 8, 0 <= S, S < 7 * two32, an + two32 * c == S],
      an == S % two32)
# A digest word is DIG_j + 2^32 x = IV_j + out_j in the field, x a bit, and out_j is either a
# word of bits (below 2^32) or a round's result a_64 or e_64, which nothing reduces: it is only
# known that out + 2^32 c = S for its sum S (below 7 * 2^32) and some carry c below 8. These
# lemmas take the general case. Wherever a digest word is read again it is either known to be
# below 2^32 (compared with a public word: the root, a nullifier, an output commitment; or read
# as a message word W_1..W_15, each range-checked on some row) or it is read as W_0.
S_, cc = z3.Ints("S cc")
digest = [0 <= dig, dig < P, z3.Or(x == 0, x == 1), 0 <= ivj, ivj < two32, 0 <= out, out < P,
          0 <= S_, S_ < 7 * two32, 0 <= cc, cc < 8, (out + two32 * cc - S_) % P == 0,
          (dig + two32 * x - ivj - out) % P == 0]
prove("a digest word below 2^32 is (IV_j + state_j) mod 2^32, however its state word was encoded",
      digest + [dig < two32], dig == (ivj + S_) % two32)
# W_0, the one message word no range check covers, enters only round 0 (a_1 = k + W_0 and
# e_1 = k' + W_0, each split as a word plus a carry below 8) and the schedule (W_16, carry below
# 4). Whatever field element it is, each sees the honest digest word modulo 2^32.
for which, kconst in zip("ae", k0()):
    prove(f"W_0 taken from a digest word gives round 0's {which} the honest value modulo 2^32",
          digest + [k == kconst, 0 <= an, an < two32, 0 <= c, c < 8, (an + two32 * c - k - dig) % P == 0],
          an == (k + (ivj + S_) % two32) % two32)
prove("W_0 taken from a digest word gives the schedule the honest value modulo 2^32",
      digest + [0 <= k, k < 3 * two32, 0 <= an, an < two32, 0 <= c, c < 4, (an + two32 * c - k - dig) % P == 0],
      an == (k + (ivj + S_) % two32) % two32)
# a note's value: v_hi below 2^28 (its top four bits are zero) and v_lo a word: v < 2^60
vh, vl = z3.Ints("vh vl")
prove("a note's value is below 2^60", [0 <= vh, vh < 2**28, 0 <= vl, vl < two32], vh * two32 + vl < 2**60)

print("ALL CHECKS PASS" if fail == 0 else f"{fail} CHECKS FAILED")
sys.exit(1 if fail else 0)
