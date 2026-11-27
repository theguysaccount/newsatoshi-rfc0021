#!/usr/bin/env node
/**
 * Newsatoshi Independent Consensus Verifier Client (Zero-Dependency Node.js / OpenSSL / BigInt)
 *
 * Shares ZERO code with the Rust reference node (`node/src/`). Independently implements from
 * first principles using OpenSSL SHA-256 (`node:crypto`) and exact 256/512-bit JS `BigInt`:
 *   1. 80-byte Bitcoin-compatible Header parsing, SHA-256d, compact target, PoW & chain work
 *   2. Exact `aserti3-launch` & steady-state ASERT difficulty math (`pow::asert_bits_staged`)
 *   3. Namecoin AuxPoW (`CHAIN_ID = 0x4e53 = 20051`, `0xfabe6d6d`, `expected_index`, coinbase branch)
 *   4. CVE-2012-2459-safe zero-padded Merkle root, `header_commit("nsBLOCK")`, & `DigestParts`
 *      (`nsSTATE` + optional `locks`, `C`, `N`, `P`, `K` `priors`, and Genesis-#0 `F` `header_mmr`)
 *   5. Raw FIPS 180-4 `SHA256Compress` NoteTree (`nsAD`, `nsCM`, `nsNF`, depth-32 Utreexo frontier)
 *   6. Work-proportional O(log N) FlyClient `HeaderMmr` peak bagging & cumulative work verification
 *   7. PayWord hash-chain conservation, Priorism-FEP `PriorLock` 50/50 surprise-bounty & burn
 *      conservation, and Homeostatic Base-Fee Burn conservation (`50%` burned / `50%` producer).
 *
 * Used for multi-client differential cross-verification against the Rust L1 node in CI.
 */
import crypto from "node:crypto";
import fs from "node:fs";

export const CHAIN_ID = 0x4e53; // 20051 ("NS")
export const VERSION_AUXPOW = 1 << 8;
export const MERGED_MINING_HEADER = Buffer.from([0xfa, 0xbe, 0x6d, 0x6d]);
export const NOTE_DEPTH = 32;
export const MAX_NOTE_VALUE = (1n << 60n) - 1n;

/** Canonical Newsatoshi Mainnet v2 (nsM2, v1.2.0) genesis & staged ASERT parameters. */
export const MAINNET_V2_PARAMS = {
  network: "mainnet-v2",
  magic: "nsM2",
  btc_anchor_height: 977738,
  btc_anchor_hash: "0000000000000000000163900064a4cc4807dbd8bcaf35e322e694e6c387a780",
  genesis_hash_display: "00000000ba1cdad4aa8e82d6613b4df536394c41008fc3a0914a47a44604b9c8",
  genesis_time: 1795742750,
  genesis_bits: 0x1d00ffff,
  pow_limit_bits: 0x1d00ffff,
  spacing: 600,
  launch_blocks: 2016,
  launch_half_life: 3600,
  steady_half_life: 172800,
};

// ---- SHA-256 (OpenSSL) + Raw FIPS 180-4 SHA256Compress (for NoteTree) ----------------

export function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

export function sha256d(buf) {
  return sha256(sha256(buf));
}

const SHA256_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

/** Raw FIPS 180-4 SHA-256 compression on 16 u32 words (standard IV, no padding). */
export function sha256Compress(words16) {
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) w[i] = words16[i] >>> 0;
  for (let i = 16; i < 64; i++) {
    const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
    const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }
  let [a, b, c, d, e, f, g, h] = SHA256_IV;
  for (let t = 0; t < 64; t++) {
    const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const t1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
    const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const t2 = (S0 + maj) >>> 0;
    h = g; g = f; f = e; e = (d + t1) >>> 0;
    d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  return new Uint32Array([
    (SHA256_IV[0] + a) >>> 0, (SHA256_IV[1] + b) >>> 0,
    (SHA256_IV[2] + c) >>> 0, (SHA256_IV[3] + d) >>> 0,
    (SHA256_IV[4] + e) >>> 0, (SHA256_IV[5] + f) >>> 0,
    (SHA256_IV[6] + g) >>> 0, (SHA256_IV[7] + h) >>> 0,
  ]);
}

export function wordsToBytes(w8) {
  const b = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) b.writeUInt32BE(w8[i] >>> 0, i * 4);
  return b;
}

export function bytesToWords(buf) {
  const w = new Uint32Array(8);
  for (let i = 0; i < 8; i++) w[i] = buf.readUInt32BE(i * 4);
  return w;
}

export function noteNode(left8, right8) {
  const b = new Uint32Array(16);
  b.set(left8, 0);
  b.set(right8, 8);
  return sha256Compress(b);
}

export function noteEmptyRoots() {
  const e = [new Uint32Array(8)];
  for (let i = 1; i <= NOTE_DEPTH; i++) {
    e.push(noteNode(e[i - 1], e[i - 1]));
  }
  return e;
}

/** Independent Utreexo-style O(log N) NoteTree root computation from leaves. */
export function computeNoteTreeRoot(leafHexList) {
  const empty = noteEmptyRoots();
  if (leafHexList.length === 0) return wordsToBytes(empty[NOTE_DEPTH]).toString("hex");
  const peaks = new Array(NOTE_DEPTH).fill(null);
  let count = 0;
  for (const hex of leafHexList) {
    let cur = bytesToWords(Buffer.from(hex, "hex"));
    for (let lvl = 0; lvl < NOTE_DEPTH; lvl++) {
      if (peaks[lvl] !== null) {
        cur = noteNode(peaks[lvl], cur);
        peaks[lvl] = null;
      } else {
        peaks[lvl] = cur;
        break;
      }
    }
    count++;
  }
  let lo = 0;
  while (((count >>> lo) & 1) === 0) lo++;
  let cur = noteNode(peaks[lo], empty[lo]);
  for (let lvl = lo + 1; lvl < NOTE_DEPTH; lvl++) {
    cur = peaks[lvl] !== null ? noteNode(peaks[lvl], cur) : noteNode(cur, empty[lvl]);
  }
  return wordsToBytes(cur).toString("hex");
}

// ---- PoW, Compact Targets, Chain Work, and Exact BigInt ASERT ------------------------

const MAX_U256 = (1n << 256n) - 1n;

export function targetFromCompact(bits) {
  const u = bits >>> 0;
  const exp = u >>> 24;
  const mant = BigInt(u & 0x007fffff);
  if ((u & 0x00800000) !== 0) return 0n;
  if (exp <= 3) return mant >> BigInt(8 * (3 - exp));
  return mant << BigInt(8 * (exp - 3));
}

export function compactFromTarget(t) {
  if (t <= 0n) return 0;
  const bitLen = t.toString(2).length;
  let size = Math.floor((bitLen + 7) / 8);
  let mant = size <= 3
    ? Number((t << BigInt(8 * (3 - size))) & 0xffffffffn)
    : Number((t >> BigInt(8 * (size - 3))) & 0xffffffffn);
  if ((mant & 0x00800000) !== 0) {
    mant >>>= 8;
    size += 1;
  }
  return ((mant & 0x00ffffff) | ((size & 0xff) << 24)) >>> 0;
}

export function workFromBits(bits) {
  const t = targetFromCompact(bits);
  if (t === 0n) return 0n;
  return ((MAX_U256 - t) / (t + 1n)) + 1n;
}

export function hashToLeBigInt(hashBuf32) {
  let acc = 0n;
  for (let i = 31; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(hashBuf32[i]);
  }
  return acc;
}

export function meetsTarget(hashBuf32, bits) {
  const t = targetFromCompact(bits);
  return t > 0n && hashToLeBigInt(hashBuf32) <= t;
}

export function parseHeader(buf80) {
  if (buf80.length !== 80) throw new Error(`bad header length ${buf80.length}`);
  return {
    version: buf80.readUInt32LE(0),
    prev: buf80.subarray(4, 36),
    commit: buf80.subarray(36, 68),
    time: buf80.readUInt32LE(68),
    bits: buf80.readUInt32LE(72),
    nonce: buf80.readUInt32LE(76),
    hash: sha256d(buf80),
  };
}

/** Exact BigInt implementation of `aserti3-2d` (matches Rust `pow::asert_bits` bit-for-bit). */
export function asertBits(anchorBits, anchorParentTime, parentHeight, parentTime, halfLife, powLimitBits, spacing) {
  const anchorTarget = targetFromCompact(anchorBits);
  const powLimit = targetFromCompact(powLimitBits);
  const timeDelta = BigInt(parentTime) - BigInt(anchorParentTime);
  const heightDelta = BigInt(parentHeight);
  // BigInt `/` truncates toward zero — identical to Rust i64 `/`!
  const exponent = ((timeDelta - BigInt(spacing) * (heightDelta + 1n)) * 65536n) / BigInt(halfLife);
  // Arithmetic right shift (floor division by 2^16)
  const numShifts = exponent >> 16n;
  const frac = exponent - (numShifts << 16n);
  const factor = 65536n + (
    (195766423245049n * frac + 971821376n * frac * frac + 5127n * frac * frac * frac + (1n << 47n)) >> 48n
  );
  let next = anchorTarget * factor;
  if (numShifts < 0n) {
    const s = -numShifts;
    next = s >= 512n ? 0n : (next >> s);
  } else {
    if (numShifts >= 512n) return powLimitBits >>> 0;
    next = next << numShifts;
    if (next > (1n << 512n) - 1n) return powLimitBits >>> 0;
  }
  next = next >> 16n;
  if (next === 0n) return compactFromTarget(1n);
  if (next > powLimit) return powLimitBits >>> 0;
  return compactFromTarget(next);
}

/** Exact BigInt two-stage Day-1 launch ramp + steady-state ASERT (matches Rust `pow::asert_bits_staged`). */
export function asertBitsStaged(
  genesisBits,
  genesisParentTime,
  launchBlocks,
  launchHalfLife,
  steadyAnchor,
  parentHeight,
  parentTime,
  steadyHalfLife,
  powLimitBits,
  spacing,
) {
  if (launchBlocks === 0) {
    return asertBits(genesisBits, genesisParentTime, parentHeight, parentTime, steadyHalfLife, powLimitBits, spacing);
  }
  if (parentHeight < launchBlocks) {
    return asertBits(genesisBits, genesisParentTime, parentHeight, parentTime, launchHalfLife, powLimitBits, spacing);
  }
  if (!steadyAnchor) {
    throw new Error(`missing ASERT steady anchor at height ${launchBlocks}`);
  }
  return asertBits(
    steadyAnchor.bits,
    steadyAnchor.time - spacing,
    parentHeight - launchBlocks,
    parentTime,
    steadyHalfLife,
    powLimitBits,
    spacing,
  );
}

/** Independent Merkle root (CVE-2012-2459 zero-padded, NOT Bitcoin duplicated tail). */
export function merkleRoot(txHashHexes) {
  if (txHashHexes.length === 0) return Buffer.alloc(32);
  let level = txHashHexes.map((h) => Buffer.from(h, "hex"));
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(Buffer.alloc(32));
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256d(Buffer.concat([level[i], level[i + 1]])));
    }
    level = next;
  }
  return level[0];
}

export function headerCommit(txRootBuf, stateDigestBuf) {
  return sha256d(Buffer.concat([Buffer.from("nsBLOCK"), txRootBuf, stateDigestBuf]));
}

function u128LeBuf(valBigInt) {
  const b = Buffer.alloc(16);
  let x = BigInt(valBigInt);
  for (let i = 0; i < 16; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

/** Independent `DigestParts::digest()` computation (incl. Genesis-#0 FlyClient `header_mmr`!). */
export function computeStateDigest(parts) {
  const chunks = [
    Buffer.from("nsSTATE"),
    (() => { const b = Buffer.alloc(4); b.writeUInt32LE(parts.height >>> 0, 0); return b; })(),
    Buffer.from(parts.tree_root, "hex"),
    Buffer.from(parts.nf_acc, "hex"),
    Buffer.from(parts.jobs, "hex"),
    Buffer.from(parts.pending, "hex"),
    u128LeBuf(parts.issued),
    u128LeBuf(parts.burned),
    u128LeBuf(parts.locked),
  ];
  if (parts.locks) chunks.push(Buffer.from(parts.locks, "hex"));
  if (parts.conds) chunks.push(Buffer.from("C"), Buffer.from(parts.conds, "hex"));
  if (parts.nf_root) chunks.push(Buffer.from("N"), Buffer.from(parts.nf_root, "hex"));
  if (parts.channels) chunks.push(Buffer.from("P"), Buffer.from(parts.channels, "hex"));
  if (parts.priors) chunks.push(Buffer.from("K"), Buffer.from(parts.priors, "hex"));
  if (parts.header_mmr) chunks.push(Buffer.from("F"), Buffer.from(parts.header_mmr, "hex"));
  return sha256(Buffer.concat(chunks)).toString("hex");
}

// ---- Independent FlyClient Header MMR Verification -----------------------------------

function u256BeBuf(valBigInt) {
  const b = Buffer.alloc(32);
  let x = BigInt(valBigInt);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

export function mmrLeafHash(height, blockHashBuf, workBigInt) {
  const h = Buffer.alloc(4);
  h.writeUInt32LE(height >>> 0, 0);
  return sha256(Buffer.concat([Buffer.from("nsMMRLF1"), h, blockHashBuf, u256BeBuf(workBigInt)]));
}

export function mmrParentHash(left, right) {
  const totalWork = left.work + right.work;
  const hash = sha256(Buffer.concat([
    Buffer.from("nsMMRND1"),
    left.hash,
    u256BeBuf(left.work),
    right.hash,
    u256BeBuf(right.work),
    u256BeBuf(totalWork),
  ]));
  return { hash, work: totalWork, height: left.height + 1 };
}

export function computeHeaderMmrRoot(headersHexList) {
  const levels = [];
  let leafCount = 0;
  for (const hex of headersHexList) {
    const hd = parseHeader(Buffer.from(hex, "hex"));
    const w = workFromBits(hd.bits);
    if (!meetsTarget(hd.hash, hd.bits)) {
      throw new Error(`header ${leafCount} failed PoW target`);
    }
    const leaf = { hash: mmrLeafHash(leafCount, hd.hash, w), work: w, height: 0 };
    if (levels.length === 0) levels.push([]);
    levels[0].push(leaf);
    let lvl = 0;
    while (levels[lvl].length >= 2 && levels[lvl].length % 2 === 0) {
      const len = levels[lvl].length;
      const parent = mmrParentHash(levels[lvl][len - 2], levels[lvl][len - 1]);
      if (levels.length <= lvl + 1) levels.push([]);
      levels[lvl + 1].push(parent);
      lvl++;
    }
    leafCount++;
  }
  const peaks = [];
  for (let lvl = levels.length - 1; lvl >= 0; lvl--) {
    if (levels[lvl].length % 2 === 1) peaks.push(levels[lvl][levels[lvl].length - 1]);
  }
  if (peaks.length === 0) return { root: Buffer.alloc(32).toString("hex"), totalWork: "0" };
  let accHash = peaks[peaks.length - 1].hash;
  let accWork = peaks[peaks.length - 1].work;
  for (let i = peaks.length - 2; i >= 0; i--) {
    const p = peaks[i];
    accWork += p.work;
    accHash = sha256(Buffer.concat([
      Buffer.from("nsMMRBAG"),
      p.hash,
      accHash,
      u256BeBuf(accWork),
    ]));
  }
  return { root: accHash.toString("hex"), totalWork: accWork.toString() };
}

// ---- Independent PayWord / PriorLock / Homeostatic-Burn Conservation Checks ----------

export function verifyPayWordClaim({ tipHex, tokenHex, ticks, deposit, unitPrice, sellerPaid, buyerRefund, minerFee }) {
  let cur = Buffer.from(tokenHex, "hex");
  for (let i = 0; i < ticks; i++) cur = sha256(cur);
  if (cur.toString("hex") !== tipHex) return { ok: false, reason: "payword hash chain mismatch" };
  const gross = BigInt(ticks) * BigInt(unitPrice);
  const dep = BigInt(deposit);
  const s = BigInt(sellerPaid), r = BigInt(buyerRefund), f = BigInt(minerFee);
  if (gross > dep) return { ok: false, reason: "ticks exceed deposit" };
  if (s + r + f !== dep) return { ok: false, reason: "conservation violation" };
  return { ok: true };
}

export function verifyPriorDisconfirm({ stake, bounty, burn, fee }) {
  const st = BigInt(stake), bo = BigInt(bounty), bu = BigInt(burn), f = BigInt(fee);
  if (f * 10n > st) return { ok: false, reason: "miner fee exceeds 10% cap" };
  if (bo + bu + f !== st) return { ok: false, reason: "prior disconfirm conservation violation" };
  const slashable = st - f;
  if (bo !== slashable / 2n || bu !== slashable - bo) {
    return { ok: false, reason: "prior disconfirm 50/50 split mismatch" };
  }
  return { ok: true };
}

export function verifyHomeostaticBurn({ fee, burned, producer }) {
  const f = BigInt(fee), bu = BigInt(burned), pr = BigInt(producer);
  if (bu !== f / 2n || pr !== f - bu || bu + pr !== f) {
    return { ok: false, reason: "homeostatic 50/50 fee burn mismatch" };
  }
  return { ok: true };
}

// ---- Independent Namecoin/Bitcoin AuxPoW Verification (chainid = 20051) --------------

function readCompact(buf, pos) {
  const b0 = buf[pos];
  if (b0 < 0xfd) return [b0, pos + 1];
  if (b0 === 0xfd) return [buf.readUInt16LE(pos + 1), pos + 3];
  if (b0 === 0xfe) return [buf.readUInt32LE(pos + 1), pos + 5];
  return [Number(buf.readBigUInt64LE(pos + 1)), pos + 9];
}

function parseBtcTx(buf) {
  let p = 0;
  const parts = [];
  parts.push(buf.subarray(p, p + 4)); p += 4;
  const segwit = buf[p] === 0 && buf[p + 1] === 1;
  if (segwit) p += 2;
  const bodyStart = p;
  let nIn; [nIn, p] = readCompact(buf, p);
  if (nIn === 0) throw new Error("auxpow coinbase has no inputs");
  let script0 = Buffer.alloc(0);
  for (let i = 0; i < nIn; i++) {
    p += 36;
    let sLen; [sLen, p] = readCompact(buf, p);
    if (i === 0) script0 = buf.subarray(p, p + sLen);
    p += sLen + 4;
  }
  let nOut; [nOut, p] = readCompact(buf, p);
  for (let i = 0; i < nOut; i++) {
    p += 8;
    let sLen; [sLen, p] = readCompact(buf, p);
    p += sLen;
  }
  parts.push(buf.subarray(bodyStart, p));
  if (segwit) {
    for (let i = 0; i < nIn; i++) {
      let items; [items, p] = readCompact(buf, p);
      for (let j = 0; j < items; j++) {
        let iLen; [iLen, p] = readCompact(buf, p);
        p += iLen;
      }
    }
  }
  parts.push(buf.subarray(p, p + 4)); p += 4;
  return { txid: sha256d(Buffer.concat(parts)), script0, len: p };
}

function merkleBranch(hash32, branch, index) {
  let h = Buffer.from(hash32);
  let i = index;
  for (const sib of branch) {
    h = (i & 1) !== 0
      ? sha256d(Buffer.concat([sib, h]))
      : sha256d(Buffer.concat([h, sib]));
    i >>= 1;
  }
  return h;
}

export function expectedAuxIndex(nonce, chainId, h) {
  let r = (Math.imul(nonce >>> 0, 1103515245) + 12345) >>> 0;
  r = (r + (chainId >>> 0)) >>> 0;
  r = (Math.imul(r, 1103515245) + 12345) >>> 0;
  return r % (1 << h);
}

/** Independently parse & verify a Namecoin-format Bitcoin AuxPoW proof for a Newsatoshi block. */
export function verifyAuxPow(auxHash32, headerBits, auxBuf, chainId = CHAIN_ID) {
  const tx = parseBtcTx(auxBuf);
  let p = tx.len;
  p += 32; // unused block hash
  let cbLen; [cbLen, p] = readCompact(auxBuf, p);
  const cbBranch = [];
  for (let i = 0; i < cbLen; i++) { cbBranch.push(auxBuf.subarray(p, p + 32)); p += 32; }
  const cbIndex = auxBuf.readInt32LE(p); p += 4;
  let chLen; [chLen, p] = readCompact(auxBuf, p);
  const chBranch = [];
  for (let i = 0; i < chLen; i++) { chBranch.push(auxBuf.subarray(p, p + 32)); p += 32; }
  const chIndex = auxBuf.readInt32LE(p); p += 4;
  const parent = auxBuf.subarray(p, p + 80); p += 80;
  if (p !== auxBuf.length) throw new Error("trailing bytes in auxpow");
  if (cbIndex !== 0) throw new Error("auxpow coinbase_index != 0");
  const parentVer = parent.readUInt32LE(0);
  if ((parentVer >>> 16) === chainId) throw new Error("auxpow parent has our chain ID");
  const parentHash = sha256d(parent);
  if (!meetsTarget(parentHash, headerBits)) throw new Error("auxpow parent PoW fails target");
  const parentRoot = parent.subarray(36, 68);
  if (!merkleBranch(tx.txid, cbBranch, 0).equals(parentRoot)) {
    throw new Error("auxpow coinbase merkle branch mismatch");
  }
  const root = Buffer.from(merkleBranch(auxHash32, chBranch, chIndex)).reverse();
  const script = tx.script0;
  const pc = script.indexOf(root);
  if (pc < 0) throw new Error("auxpow chain root missing in coinbase script");
  const head = script.indexOf(MERGED_MINING_HEADER);
  if (head >= 0) {
    if (script.indexOf(MERGED_MINING_HEADER, head + 1) >= 0) throw new Error("duplicate merged mining header");
    if (head + 4 !== pc) throw new Error("chain root does not immediately follow 0xfabe6d6d");
  } else if (pc > 20) {
    throw new Error("chain root too deep without merged mining header");
  }
  const after = pc + 32;
  if (script.length < after + 8) throw new Error("auxpow coinbase missing size/nonce");
  const treeSize = script.readUInt32LE(after);
  const mergeNonce = script.readUInt32LE(after + 4);
  if (treeSize !== (1 << chBranch.length)) throw new Error("auxpow tree size mismatch");
  if (chIndex !== expectedAuxIndex(mergeNonce, chainId, chBranch.length)) {
    throw new Error("auxpow chain_index != expected_index");
  }
  return {
    parent_hash_display: Buffer.from(parentHash).reverse().toString("hex"),
    coinbase_tag_ascii: script.toString("latin1").replace(/[^\x20-\x7e]/g, ""),
  };
}

/** Decode a `/api/headers` HeaderBlock hex entry (80-byte header + optional length-prefixed AuxPoW). */
export function decodeHeaderBlock(hexStr) {
  const buf = Buffer.from(hexStr, "hex");
  if (buf.length < 84) throw new Error("truncated header block");
  const headerBuf = buf.subarray(0, 80);
  const hd = parseHeader(headerBuf);
  let p = 80;
  let auxpow = null;
  if ((hd.version & VERSION_AUXPOW) !== 0) {
    const auxLen = buf.readUInt32LE(p); p += 4;
    auxpow = buf.subarray(p, p + auxLen); p += auxLen;
  }
  return { headerBuf, hd, auxpow };
}

/** Independently download & verify the live Newsatoshi Mainnet v2 (nsM2) chain end-to-end. */
export async function verifyLiveMainnetV2(baseUrl = "https://newsatoshi.org/mainnet") {
  const base = baseUrl.replace(/\/+$/, "");
  const getJson = async (path) => {
    const r = await fetch(base + path, { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error(`HTTP ${r.status} on ${base + path}`);
    return r.json();
  };
  const status = await getJson("/status");
  if (status.network !== "mainnet-v2") {
    throw new Error(`expected network=mainnet-v2, got ${status.network}`);
  }
  if (status.genesis !== MAINNET_V2_PARAMS.genesis_hash_display) {
    throw new Error(`genesis mismatch: got ${status.genesis}`);
  }
  const allHeaders = [];
  let next = 1;
  while (next <= status.height) {
    const page = await getJson(`/api/headers?from=${next}`);
    if (!page.ok || !Array.isArray(page.headers) || page.headers.length === 0) break;
    for (const hHex of page.headers) allHeaders.push(hHex);
    next = page.next;
  }
  const state = await getJson("/api/state");
  const fly = await getJson("/api/flyclient");

  // Reconstruct canonical Genesis #0 internal hash from display hex
  const genInternal = Buffer.from(MAINNET_V2_PARAMS.genesis_hash_display, "hex").reverse();
  let prevHash = genInternal;
  let parentTime = MAINNET_V2_PARAMS.genesis_time;
  let steadyAnchor = null;
  let auxpowCount = 0;
  let totalWork = workFromBits(MAINNET_V2_PARAMS.genesis_bits);
  const mmrLevels = [[{
    hash: mmrLeafHash(0, genInternal, totalWork),
    work: totalWork,
    height: 0,
  }]];

  const pushMmr = (height, blockHashBuf, w) => {
    const leaf = { hash: mmrLeafHash(height, blockHashBuf, w), work: w, height: 0 };
    mmrLevels[0].push(leaf);
    let lvl = 0;
    while (mmrLevels[lvl].length >= 2 && mmrLevels[lvl].length % 2 === 0) {
      const len = mmrLevels[lvl].length;
      const parent = mmrParentHash(mmrLevels[lvl][len - 2], mmrLevels[lvl][len - 1]);
      if (mmrLevels.length <= lvl + 1) mmrLevels.push([]);
      mmrLevels[lvl + 1].push(parent);
      lvl++;
    }
  };
  const bagMmr = () => {
    const peaks = [];
    for (let lvl = mmrLevels.length - 1; lvl >= 0; lvl--) {
      if (mmrLevels[lvl].length % 2 === 1) peaks.push(mmrLevels[lvl][mmrLevels[lvl].length - 1]);
    }
    let accHash = peaks[peaks.length - 1].hash;
    let accWork = peaks[peaks.length - 1].work;
    for (let i = peaks.length - 2; i >= 0; i--) {
      accWork += peaks[i].work;
      accHash = sha256(Buffer.concat([Buffer.from("nsMMRBAG"), peaks[i].hash, accHash, u256BeBuf(accWork)]));
    }
    return { root: accHash.toString("hex"), totalWork: accWork };
  };

  let tipHeader = null;
  let tipAncestorMmr = null;
  const maxHeight = Math.min(allHeaders.length, state.height);
  for (let i = 0; i < maxHeight; i++) {
    const h = i + 1;
    const { hd, auxpow } = decodeHeaderBlock(allHeaders[i]);
    if (!hd.prev.equals(prevHash)) {
      throw new Error(`height ${h}: prev hash link broken`);
    }
    const expectedBits = asertBitsStaged(
      MAINNET_V2_PARAMS.genesis_bits,
      MAINNET_V2_PARAMS.genesis_time - MAINNET_V2_PARAMS.spacing,
      MAINNET_V2_PARAMS.launch_blocks,
      MAINNET_V2_PARAMS.launch_half_life,
      steadyAnchor,
      h - 1,
      parentTime,
      MAINNET_V2_PARAMS.steady_half_life,
      MAINNET_V2_PARAMS.pow_limit_bits,
      MAINNET_V2_PARAMS.spacing,
    );
    if (hd.bits !== expectedBits) {
      throw new Error(`height ${h}: ASERT bits mismatch (got 0x${hd.bits.toString(16)}, expected 0x${expectedBits.toString(16)})`);
    }
    if ((hd.version & VERSION_AUXPOW) !== 0) {
      if (!auxpow) throw new Error(`height ${h}: missing auxpow payload`);
      if ((hd.version >>> 16) !== CHAIN_ID) throw new Error(`height ${h}: wrong auxpow chain ID`);
      verifyAuxPow(hd.hash, hd.bits, auxpow, CHAIN_ID);
      auxpowCount++;
    } else if (!meetsTarget(hd.hash, hd.bits)) {
      throw new Error(`height ${h}: native PoW fails target`);
    }
    if (h === MAINNET_V2_PARAMS.launch_blocks) {
      steadyAnchor = { bits: hd.bits, time: hd.time };
    }
    if (h === maxHeight) {
      // State at height `h` commits to ancestor header MMR `[0..h-1]`!
      tipAncestorMmr = bagMmr();
      tipHeader = hd;
    }
    const w = workFromBits(hd.bits);
    totalWork += w;
    pushMmr(h, hd.hash, w);
    prevHash = hd.hash;
    parentTime = hd.time;
  }

  // Independently verify `nsSTATE` digest + `header_commit("nsBLOCK")` against live tip header!
  let stateCommitVerified = false;
  if (state.ok && tipHeader && state.height === maxHeight) {
    const dig = computeStateDigest(state.parts);
    const expectedCommit = headerCommit(Buffer.from(state.tx_root, "hex"), Buffer.from(dig, "hex"));
    if (!expectedCommit.equals(tipHeader.commit)) {
      throw new Error("live tip header_commit(tx_root, nsSTATE) mismatch!");
    }
    if (tipAncestorMmr && state.parts.header_mmr !== tipAncestorMmr.root) {
      throw new Error(`live header_mmr mismatch: got ${state.parts.header_mmr}, computed ${tipAncestorMmr.root}`);
    }
    stateCommitVerified = true;
  }

  return {
    ok: true,
    verifier: "newsatoshi-independent-js-openssl-v1.2.1",
    endpoint: base,
    network: status.network,
    genesis_verified: MAINNET_V2_PARAMS.genesis_hash_display,
    verified_height: maxHeight,
    tip_hash: Buffer.from(prevHash).reverse().toString("hex"),
    auxpow_blocks_verified: auxpowCount,
    asert_staged_verified_all_blocks: true,
    ancestor_mmr_root_verified: tipAncestorMmr ? tipAncestorMmr.root : null,
    total_chainwork: totalWork.toString(),
    state_commitment_verified: stateCommitVerified,
    flyclient_api_header_mmr_bound: Boolean(fly.ok && fly.header_mmr_bound),
  };
}

// ---- CLI Differential Vector Runner --------------------------------------------------

export function verifyVectorBundle(vec) {
  const out = { ok: true };
  if (vec.headers) {
    let prevHash = null;
    for (let i = 0; i < vec.headers.length; i++) {
      const hd = parseHeader(Buffer.from(vec.headers[i], "hex"));
      if (!meetsTarget(hd.hash, hd.bits)) {
        return { ok: false, reason: `header ${i} failed PoW` };
      }
      if (prevHash && !hd.prev.equals(prevHash)) {
        return { ok: false, reason: `header ${i} prev mismatch` };
      }
      prevHash = hd.hash;
    }
    const mmr = computeHeaderMmrRoot(vec.headers);
    out.mmr_root = mmr.root;
    out.mmr_total_work = mmr.totalWork;
    if (vec.expected_mmr_root && mmr.root !== vec.expected_mmr_root) {
      return { ok: false, reason: `mmr_root mismatch: got ${mmr.root} expected ${vec.expected_mmr_root}` };
    }
    if (vec.expected_tip_hash && prevHash.toString("hex") !== vec.expected_tip_hash) {
      return { ok: false, reason: "tip hash mismatch" };
    }
  }
  if (vec.asert) {
    const a = vec.asert;
    const bits = asertBits(a.anchor_bits, a.anchor_parent_time, a.parent_height, a.parent_time, a.half_life, a.pow_limit_bits, a.spacing);
    out.asert_bits = bits;
    if (a.expected_bits !== undefined && bits !== (a.expected_bits >>> 0)) {
      return { ok: false, reason: `asert_bits mismatch: got ${bits} expected ${a.expected_bits}` };
    }
  }
  if (vec.asert_staged) {
    const s = vec.asert_staged;
    const bits = asertBitsStaged(
      s.genesis_bits,
      s.genesis_parent_time,
      s.launch_blocks,
      s.launch_half_life,
      s.steady_anchor ?? null,
      s.parent_height,
      s.parent_time,
      s.steady_half_life,
      s.pow_limit_bits,
      s.spacing,
    );
    out.asert_staged_bits = bits;
    if (s.expected_bits !== undefined && bits !== (s.expected_bits >>> 0)) {
      return { ok: false, reason: `asert_staged_bits mismatch: got ${bits} expected ${s.expected_bits}` };
    }
  }
  if (vec.note_leaves) {
    const root = computeNoteTreeRoot(vec.note_leaves);
    out.note_root = root;
    if (vec.expected_note_root && root !== vec.expected_note_root) {
      return { ok: false, reason: `note_root mismatch: got ${root} expected ${vec.expected_note_root}` };
    }
  }
  if (vec.digest_parts) {
    const dig = computeStateDigest(vec.digest_parts);
    out.state_digest = dig;
    if (vec.expected_state_digest && dig !== vec.expected_state_digest) {
      return { ok: false, reason: `state_digest mismatch: got ${dig} expected ${vec.expected_state_digest}` };
    }
    if (vec.tx_hashes && vec.tip_header_hex) {
      const txRoot = merkleRoot(vec.tx_hashes);
      const commit = headerCommit(txRoot, Buffer.from(dig, "hex"));
      const hd = parseHeader(Buffer.from(vec.tip_header_hex, "hex"));
      if (!commit.equals(hd.commit)) {
        return { ok: false, reason: "header_commit mismatch" };
      }
      out.header_commit_verified = true;
    }
  }
  if (vec.payword) {
    const r = verifyPayWordClaim(vec.payword);
    if (!r.ok) return r;
    out.payword_verified = true;
  }
  if (vec.prior_disconfirm) {
    const r = verifyPriorDisconfirm(vec.prior_disconfirm);
    if (!r.ok) return r;
    out.prior_disconfirm_verified = true;
  }
  if (vec.homeostatic_burn) {
    const r = verifyHomeostaticBurn(vec.homeostatic_burn);
    if (!r.ok) return r;
    out.homeostatic_burn_verified = true;
  }
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cmd = process.argv[2];
  if (cmd === "verify-vector") {
    const src = process.argv[3] ? fs.readFileSync(process.argv[3], "utf8") : fs.readFileSync(0, "utf8");
    const vec = JSON.parse(src);
    const res = verifyVectorBundle(vec);
    process.stdout.write(JSON.stringify(res) + "\n");
    process.exit(res.ok ? 0 : 1);
  } else if (cmd === "--self-test") {
    const emptyRoot = computeNoteTreeRoot([]);
    const bits = asertBits(0x1d00ffff, 1762473000, 0, 1762473600, 172800, 0x1d00ffff, 600);
    if (bits !== 0x1d00ffff) {
      console.error("ASERT neutral test failed:", bits.toString(16));
      process.exit(1);
    }
    console.log(JSON.stringify({ ok: true, verifier: "newsatoshi-independent-js-openssl", empty_note_root: emptyRoot, asert_neutral_bits: "0x" + bits.toString(16) }));
  } else if (cmd === "--live") {
    const url = process.argv[3] || "https://newsatoshi.org/mainnet";
    verifyLiveMainnetV2(url)
      .then((res) => {
        console.log(JSON.stringify(res, null, 2));
        process.exit(0);
      })
      .catch((err) => {
        console.error(JSON.stringify({ ok: false, error: err.message }));
        process.exit(1);
      });
  } else {
    console.error("usage: newsatoshi_verifier.mjs verify-vector [file.json] | --self-test | --live [https://newsatoshi.org/mainnet]");
    process.exit(2);
  }
}
