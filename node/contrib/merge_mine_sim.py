"""Merge-mine a NEWSATOSHI node the way a pool does, to test an integration end to end.

Start a node with `newsatoshi --net regtest node --rpc 19556`, then run
`python3 merge_mine_sim.py 19556 ~/.newsatoshi/regtest/.cookie`.
It asks for a block (getauxblock), writes the hash into a Bitcoin coinbase after the
merged-mining magic fabe6d6d, grinds a Bitcoin header to the NEWSATOSHI target and
submits the header, coinbase and branch (submitauxblock), in Namecoin's format."""
import base64, hashlib, json, struct, sys, urllib.request
port, cookie_path = int(sys.argv[1]), sys.argv[2]
auth = base64.b64encode(open(cookie_path).read().strip().encode()).decode()
def rpc(method, params):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", json.dumps({"jsonrpc": "1.0", "id": "sim", "method": method, "params": params}).encode(),
                                 {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return json.load(e)
d = lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest()
t = rpc("getauxblock", [])["result"]
print("template", {k: t[k] for k in ("hash", "chainid", "height", "bits", "coinbasevalue")})
root = bytes.fromhex(t["hash"])                      # display order, as pools write it
script = b"\x03\x01\x02\x03" + b"\xfa\xbemm" + root + struct.pack("<II", 1, 0) + b"/sim-pool/"
cb = struct.pack("<I", 2) + b"\x01" + b"\x00" * 32 + b"\xff" * 4 + bytes([len(script)]) + script + b"\xff" * 4 \
     + b"\x01" + struct.pack("<Q", 312500000) + b"\x01\x51" + b"\x00" * 4
target = int.from_bytes(bytes.fromhex(t["_target"]), "little")
for nonce in range(1 << 32):
    parent = struct.pack("<I", 0x20000000) + b"\x11" * 32 + d(cb) + struct.pack("<III", 1780000000, 0x17023a5b, nonce)
    if int.from_bytes(d(parent), "little") <= target:
        break
aux = cb + b"\x00" * 32 + b"\x00" + struct.pack("<i", 0) + b"\x00" + struct.pack("<i", 0) + parent
print("submit", rpc("submitauxblock", [t["hash"], aux.hex()]))
print("count", rpc("getblockcount", [])["result"], "best", rpc("getbestblockhash", [])["result"] == t["hash"])
print("info", rpc("getblockchaininfo", [])["result"])
