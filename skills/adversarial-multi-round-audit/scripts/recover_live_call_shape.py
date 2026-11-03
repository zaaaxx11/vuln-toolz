#!/usr/bin/env python3
"""
RECOVER THE LIVE SELECTOR / CALL SHAPE FROM A REAL TRANSACTION.

WHY THIS EXISTS
---------------
Hand-built selectors fail (skill error #8). PUSH4/`in` bytecode scans are only a
hypothesis: modern solc dispatchers, batchers, and proxies can hide a selector from
a naive scan, and the miss reads as "the live contract is a different version" —
which invalidates a whole round of analysis that was actually correct.

The only ground truth for "what does this contract accept" is a transaction the
chain already accepted. This script enumerates them.

USAGE
-----
    # 1. list every tx that ever targeted the contract, with selector + receipt status
    python3 recover_live_call_shape.py --address 0x6747...bc0c

    # 2. dump the full calldata of the most recent SUCCESSFUL tx and decode its args
    python3 recover_live_call_shape.py --address 0x6747...bc0c --dump

    # 3. decode a specific tx by hash (against the artifact ABI if you have one)
    python3 recover_live_call_shape.py --tx 0x5a34...7ae8 \
        --abi out/RelayExecutor.sol/RelayExecutor.json

WHY THE EXPLORER AND NOT eth_getBlockByNumber
---------------------------------------------
Full-block scans are O(blocks) round-trips and die on rate-limited RPCs (a 5-minute
scan produced zero progress in one session). The explorer's txlist endpoint returns
the whole history in one request. Use eth_getLogs/eth_getBlockReceipts only to
cross-check a specific claim.

PITFALLS THIS SCRIPT ENCODES
----------------------------
* `to == contract` is what you want. A log whose `topics[2] == contract` usually means
  the contract RECEIVED a transfer, not that it was CALLED. Conflating the two is how
  you end up decoding a differently-shaped batch payload and concluding the wrong
  contract is live.
* A tx may be a BATCHER calldata (`aggregate3` = 0x82ad56cb) whose sub-call targets
  the contract you care about. Decode the outer batch, walk the (target, allowFail,
  data) tuples, then match target. Offsets inside aggregate3 are NESTED — each element
  offset is relative to the array start, and each `bytes` offset is relative to the
  element start. A flat walk produces garbage like `target=0x...60`. If you see a
  target that looks like a small offset, your walk is wrong — do not "fix" it by
  guessing.
* Nonce/struct field types are not always uint256. A `bytes32` nonce changes the
  selector invisibly. Prefer decoding a real tx over recomputing a signature.
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request

TIMEOUT = 30


def http_json(url):
    req = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())


def explorer_txlist(explorer, address, offset=100):
    q = urllib.parse.urlencode({
        "module": "account", "action": "txlist", "address": address,
        "sort": "desc", "page": 1, "offset": offset,
    })
    url = f"{explorer.rstrip('/')}/api?{q}"
    data = http_json(url)
    if data.get("status") != "1" and not data.get("result"):
        return [], data
    res = data.get("result")
    if not isinstance(res, list):
        return [], data
    return res, data


def cmd_list(args):
    txs, raw = explorer_txlist(args.explorer, args.address, args.limit)
    if not txs:
        print(f"no txlist returned. raw keys: {list(raw)[:5]}")
        print("explorer may require a different endpoint shape; try:")
        print(f"  {args.explorer}/api/v2/addresses/{args.address}/transactions?filter=to")
        return 1

    print(f"'{args.address}' — {len(txs)} tx (newest first)\n")
    print(f"{'block':>10}  {'sel':>10}  {'status':>4}  {'from':42}")
    print("-" * 74)
    for t in txs:
        sel = (t.get("input") or "0x")[:10]
        ok = "OK" if str(t.get("isError")) == "0" and str(t.get("txreceipt_status", "1")) == "1" else "FAIL"
        print(f"{t.get('blockNumber', '?'):>10}  {sel:>10}  {ok:>4}  {t.get('from', '')[:42]}")
    print()
    print("Next: pick a OK row and run with --tx <hash> --abi <artifact> to decode args.")
    return 0


def cmd_dump(args):
    txs, _ = explorer_txlist(args.explorer, args.address, 200)
    ok = [t for t in txs
          if str(t.get("isError")) == "0" and str(t.get("txreceipt_status", "1")) == "1"]
    if not ok:
        print("no successful tx found")
        return 1
    t = ok[0]
    print(f"tx    : {t['hash']}")
    print(f"block : {t.get('blockNumber')}")
    print(f"from  : {t.get('from')}")
    print(f"to    : {t.get('to')}")
    print(f"gas   : {int(t.get('gas', '0'))}")
    inp = t.get("input") or "0x"
    print(f"sel   : {inp[:10]}   calldata {(len(inp) - 2) // 2} bytes")
    print()
    print("=== first 8 words ===")
    body = inp[10:]
    for i in range(min(8, len(body) // 64)):
        w = body[i * 64:(i + 1) * 64]
        print(f"  word[{i}] 0x{w}   (uint {int(w, 16) if w else 0})")
    print()
    print("NOTE: a small uint here is usually an ABI OFFSET, not a value.")
    print("      Decode with eth_abi using the artifact ABI, do not eyeball it.")
    return 0


def cmd_tx(args):
    url = f"{args.rpc}"
    payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                          "method": "eth_getTransactionByHash",
                          "params": [args.tx]}).encode()
    req = urllib.request.Request(url, payload, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        res = json.loads(r.read().decode())
    tx = res.get("result")
    if not tx:
        print(json.dumps(res, indent=1)[:400])
        return 1
    real = bytes.fromhex(tx["input"][2:])
    print(f"sel = 0x{real[:4].hex()}   {len(real)} bytes   to={tx['to']}")

    if args.abi:
        from eth_abi import decode as abi_decode
        abi = json.load(open(args.abi))["abi"]
        sel = "0x" + real[:4].hex()
        match = None
        for f in abi:
            if f.get("type") != "function":
                continue
            t = f["type"]
            if t.startswith("tuple"):
                continue
            try:
                from eth_utils import keccak
                sig = f["name"] + "(" + ",".join(
                    "(" + ",".join(c["type"] for c in i["components"]) + ")" + i["type"][5:]
                    if i["type"].startswith("tuple") else i["type"]
                    for i in f["inputs"]) + ")"
                if "0x" + keccak(text=sig)[:4].hex() == sel:
                    match = f
                    break
            except Exception:
                continue
        if not match:
            print("!! no ABI entry matched this selector.")
            print("   Either the ABI is from a different build, or the selector is a")
            print("   different overload. Do NOT hand-write a signature to explain it.")
            return 1
        types = []
        for i in match["inputs"]:
            if i["type"].startswith("tuple"):
                inner = ",".join(c["type"] for c in i["components"])
                types.append("(" + inner + ")" + i["type"][5:])
            else:
                types.append(i["type"])
        vals = abi_decode(types, real[4:])
        print(f"\n=== decoded {match['name']} ===")
        for name_in, v in zip(match["inputs"], vals):
            label = name_in.get("name") or name_in["type"]
            s = repr(v)
            print(f"  {label:22} = {s[:160]}")
    return 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--address")
    p.add_argument("--explorer", default="https://explorer.chain.relay.link")
    p.add_argument("--rpc", default="https://rpc.chain.relay.link")
    p.add_argument("--tx")
    p.add_argument("--abi")
    p.add_argument("--dump", action="store_true")
    p.add_argument("--limit", type=int, default=100)
    a = p.parse_args()

    if a.tx:
        return cmd_tx(a)
    if not a.address:
        p.print_help()
        return 2
    return cmd_dump(a) if a.dump else cmd_list(a)


if __name__ == "__main__":
    sys.exit(main())
