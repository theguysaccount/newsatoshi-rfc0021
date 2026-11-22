import fs from 'fs';
const dir = new URL('.', import.meta.url).pathname;
const wasm = fs.readFileSync(dir + 'target/wasm32-unknown-unknown/release/ns_verify.wasm');
const mod = await WebAssembly.compile(wasm);
let ex = null;
const fresh = () => { ex = new WebAssembly.Instance(mod, {}).exports; };
fresh();
const pi = fs.readFileSync(dir + 'fixture/pi.bin'), proof = fs.readFileSync(dir + 'fixture/proof.bin');
// The verifier is built to abort rather than unwind, so a hostile input could trap it.
// A trap is a rejection; the instance is replaced before the next check.
function run(piB, prB) {
  const t = performance.now();
  try {
    const a = ex.alloc(piB.length); new Uint8Array(ex.memory.buffer, a, piB.length).set(piB);
    const b = ex.alloc(Math.max(prB.length, 1)); new Uint8Array(ex.memory.buffer, b, prB.length).set(prB);
    return [ex.verify(a, piB.length, b, prB.length), performance.now() - t];
  } catch (e) { fresh(); return ['trap', performance.now() - t]; }
}
let [ok, ms] = run(pi, proof); console.log('genuine', ok, ms.toFixed(1) + ' ms');
[ok, ms] = run(pi, proof); console.log('genuine again', ok, ms.toFixed(1) + ' ms');
let rejected = 0;
for (let k = 0; k < 6; k++) { const p = Buffer.from(proof); const i = 64 + Math.floor(Math.random() * (p.length - 64)); p[i] ^= 1 << (k % 8); if (run(pi, p)[0] !== 1) rejected++; }
console.log('tampered proofs rejected', rejected, 'of 6');
const lie = Buffer.from(pi); lie[192] ^= 1; console.log('value balance changed ->', run(lie, proof)[0]);
const lie2 = Buffer.from(pi); lie2[100] ^= 1; console.log('output commitment changed ->', run(lie2, proof)[0]);
// the review's malformed inputs are refused before anything parses them
console.log('six-byte proof ->', run(pi, Buffer.from([1, 0, 0, 64, 0, 0]))[0]);
const w = Buffer.from(proof); w[0] = 246; console.log('trace width byte changed ->', run(pi, w)[0]);
console.log('padded proof ->', run(pi, Buffer.concat([proof, Buffer.alloc(1000, 0xab)]))[0]);
[ok] = run(pi, proof); console.log('genuine after all of that', ok);
