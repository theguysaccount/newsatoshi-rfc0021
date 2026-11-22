// End to end, as the browser wallet does it, against a running node's public API:
//   node test.mjs http://127.0.0.1:PORT
// The node says which network it is: the kind of proof it takes and the fee its wallets pay.
// A fresh key, testnet coins from the faucet, the note found with its path, a payment
// proved here in WebAssembly, submitted, and seen spent.
import fs from 'fs';
const api = process.argv[2];
const dir = new URL('.', import.meta.url).pathname;
const bytes = fs.readFileSync(dir + 'target/wasm32-unknown-unknown/release/ns_wallet.wasm');
let mem;
const { instance } = await WebAssembly.instantiate(bytes, { env: { random_fill: (p, n) => {
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(new Uint8Array(mem.buffer, p + i, Math.min(65536, n - i)));
} } });
const w = instance.exports; mem = w.memory;
const enc = new TextEncoder(), dec = new TextDecoder();
function call(fn, arg) {
  let r;
  if (arg === undefined) r = w[fn]();
  else { const b = enc.encode(arg); const p = w.alloc(b.length); new Uint8Array(mem.buffer, p, b.length).set(b); r = w[fn](p, b.length); }
  const out = dec.decode(new Uint8Array(mem.buffer, w.out_ptr(), w.out_len()).slice());
  if (r !== 0) throw new Error(fn + ': ' + out);
  return out;
}
const get = async (path) => (await fetch(api + path)).json();
// up to ten minutes: the public test network makes a block a minute, on average
const wait = async (cond, what) => { for (let i = 0; i < 600; i++) { const v = await cond(); if (v) return v; await new Promise(r => setTimeout(r, 1000)); } throw new Error('timed out: ' + what); };

const sk = call('new_key'); const addr = call('address', sk);
console.log('address', addr.slice(0, 24) + '…');
const f = await (await fetch(api + '/api/faucet', { method: 'POST', body: addr })).json();
if (!f.ok) throw new Error('faucet: ' + f.error);
const note = JSON.parse(call('open_note', f.note));
console.log('faucet note', note.value, 'cm', note.cm.slice(0, 16) + '…');
const info = await wait(async () => { const r = await get('/api/note?cm=' + note.cm); return r.found && r; }, 'note on chain');
const pos = info.notes[0].pos;
const nf = call('nullifier', JSON.stringify({ sk, pos, rho: note.rho }));
console.log('on chain at', pos, 'spent?', (await get('/api/spent?nf=' + nf)).spent);
const friend = call('address', call('new_key'));
const status = await get('/status');
const net = status.proofs || 'test', fee = String(status.fee || 300000), pay = '200000000';
console.log('network', status.network, '· proofs', net, '· fee', fee);
const change = (BigInt(note.value) - BigInt(pay) - BigInt(fee)).toString();
const t = performance.now();
const res = JSON.parse(call('prove', JSON.stringify({ sk, inputs: [{ value: note.value, rho: note.rho, pos, path: info.notes[0].path }],
  outputs: [{ address: friend, value: pay }, { address: addr, value: change }], fee, net, memo: 'from the browser' })));
console.log('proved in', ((performance.now() - t) / 1000).toFixed(1), 's; tx', res.tx.length / 2, 'bytes; memory', (mem.buffer.byteLength / 1048576).toFixed(0), 'MB');
const sub = await (await fetch(api + '/api/tx', { method: 'POST', body: Buffer.from(res.tx, 'hex') })).json();
console.log('submitted', sub.ok ? sub.txid.slice(0, 16) + '…' : sub.error);
await wait(async () => (await get('/api/spent?nf=' + nf)).spent, 'spend mined');
const paid = JSON.parse(call('open_note', res.notes[0]));
const there = await wait(async () => { const r = await get('/api/note?cm=' + paid.cm); return r.found && r; }, 'payee note');
console.log('spent: yes; the friend\'s note is on chain at', there.notes[0].pos, 'worth', paid.value);

// Delivery on chain: the key alone finds its own change again, and a payment to a delivery
// address reaches its payee with nothing passed to them.
async function look(key) {
  const found = [];
  for (let at = 0; ;) {
    const r = await get('/api/envelopes?from=' + at);
    const items = r.items.concat(r.pending);
    if (items.length) found.push(...JSON.parse(call('scan', JSON.stringify({ sk: key, items }))));
    at = r.next;
    if (at > r.tip) return found;
  }
}
const ch = JSON.parse(call('open_note', res.notes[1]));
if (!(await look(sk)).some(n => n.cm === ch.cm)) throw new Error('the key did not find its own change');
console.log('the key alone finds its change:', ch.value);
const chOn = await wait(async () => { const r = await get('/api/note?cm=' + ch.cm); return r.found && r; }, 'change on chain');
const sk2 = call('new_key'), to2 = call('delivery_address', sk2);
const pay2 = '100000000';
const res2 = JSON.parse(call('prove', JSON.stringify({ sk, inputs: [{ value: ch.value, rho: ch.rho, pos: chOn.notes[0].pos, path: chOn.notes[0].path }],
  outputs: [{ address: to2, value: pay2 }, { address: addr, value: (BigInt(ch.value) - BigInt(pay2) - BigInt(fee)).toString() }], fee, net, memo: 'delivered' })));
const sub2 = await (await fetch(api + '/api/tx', { method: 'POST', body: Buffer.from(res2.tx, 'hex') })).json();
if (!sub2.ok) throw new Error('submit: ' + sub2.error);
const got = await wait(async () => (await look(sk2)).find(n => n.value === pay2), 'the delivered payment');
const gotOn = await wait(async () => { const r = await get('/api/note?cm=' + got.cm); return r.found && r; }, 'delivered note on chain');
console.log('paid to a', to2.length, 'character delivery address; the payee found', got.value, 'by itself, on chain at', gotOn.notes[0].pos);
