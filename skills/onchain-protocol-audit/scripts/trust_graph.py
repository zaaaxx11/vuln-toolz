#!/usr/bin/env python3
"""
Trust-graph bootstrap for a live on-chain protocol audit.

One command that answers, for any address you hand it:
  1. Is it a contract, and how big?
  2. What does its verified source say (name, file_path, compiler)?
  3. WHO DOES IT TRUST?  -> decoded_constructor_args, the highest-yield datum in the workflow
  4. What does it hold?   -> ERC20 balances of the candidate assets
  5. What is its role/authority footprint?

Usage:
    python3 trust_graph.py --rpc https://app.example.com/api/rpc/1 --addr 0xDEAD... [--chain 1]
    python3 trust_graph.py --rpc ... --addr 0xA --addr 0xB --assets 0xUSDC,...
    python3 trust_graph.py --rpc ... --addr 0xA --explorer https://eth.blockscout.com --out /tmp/tg.json

Read-only. Sends eth_getCode / eth_call / eth_getLogs / explorer GETs only.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

UA = {
    "accept": "application/json",
    "user-agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "Chrome/128 Safari/537.36"),
}

# Common ERC20 assets to check balances for. Override with --assets.
DEFAULT_ASSETS = {
    "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "WBTC": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
    "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
}


def keccak_selector(sig: str) -> str:
    from eth_utils.crypto import keccak
    return "0x" + keccak(text=sig)[:4].hex()


def http_json(url, data=None, headers=None, timeout=30):
    hdrs = dict(UA if headers is None else headers)
    body = json.dumps(data).encode() if data is not None else None
    if body is not None:
        hdrs["content-type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs,
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class Rpc:
    def __init__(self, url, delay=0.3):
        self.url = url
        self.delay = delay
        self._id = 0

    def call(self, method, params):
        self._id += 1
        try:
            j = http_json(self.url, {"jsonrpc": "2.0", "id": self._id,
                                     "method": method, "params": params})
        except urllib.error.HTTPError as e:
            return {"__http_error": e.code}
        time.sleep(self.delay)
        if isinstance(j, dict) and "error" in j:
            return {"__revert": str(j["error"].get("message"))[:120]}
        return j.get("result")

    def eth_call(self, to, data, frm=None):
        p = {"to": to, "data": data}
        if frm:
            p["from"] = frm
        return self.call("eth_call", [p, "latest"])

    def code_len(self, addr):
        c = self.call("eth_getCode", [addr, "latest"])
        if not isinstance(c, str) or not c.startswith("0x"):
            return 0
        return (len(c) - 2) // 2


def dec_addr(h):
    return "0x" + h[2:][-40:] if isinstance(h, str) and h.startswith("0x") and len(h) >= 42 else None


def dec_uint(h):
    return int(h, 16) if isinstance(h, str) and h.startswith("0x") and len(h) > 2 else None


def explorer_fetch(explorer, addr):
    """Blockscout v2. Returns (meta, source_files) or (None, None)."""
    try:
        d = http_json(f"{explorer}/api/v2/smart-contracts/{addr}")
    except Exception:
        return None, None
    meta = {
        "name": d.get("name"),
        "file_path": d.get("file_path"),
        "compiler_version": d.get("compiler_version"),
        "is_verified": d.get("is_verified"),
        "proxy_type": d.get("proxy_type"),
        "sourcify_repo_url": d.get("sourcify_repo_url"),
        "decoded_constructor_args": d.get("decoded_constructor_args"),
        "remappings": (d.get("compiler_settings") or {}).get("remappings"),
    }
    sc = d.get("source_code") or ""
    if sc.startswith("{"):
        try:
            files = json.loads(sc)
        except Exception:
            files = {"main.sol": sc}
    else:
        files = {d.get("file_path") or "main.sol": sc}
    return meta, files


def parent_imports(files):
    """Extract parent contract names from import lines -> the next things to fetch."""
    names = set()
    for content in files.values():
        for line in (content or "").splitlines():
            line = line.strip()
            if line.startswith("import"):
                # import {X} from "src/...";  /  import "src/...";
                if "{" in line and "}" in line:
                    inner = line[line.index("{") + 1:line.index("}")]
                    for part in inner.split(","):
                        n = part.split(" as ")[0].strip()
                        if n and n != "*":
                            names.add(n)
    return sorted(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True, help="JSON-RPC endpoint (often the app's own proxy)")
    ap.add_argument("--addr", action="append", required=True)
    ap.add_argument("--assets", default="", help="comma list of ERC20 addresses")
    ap.add_argument("--explorer", default="", help="e.g. https://eth.blockscout.com")
    ap.add_argument("--out", default="")
    ap.add_argument("--chain", default="")
    args = ap.parse_args()

    assets = dict(DEFAULT_ASSETS)
    if args.assets:
        assets = {}
        for a in args.assets.split(","):
            a = a.strip()
            if a:
                assets[a] = a

    rpc = Rpc(args.rpc)
    report = {"rpc": args.rpc, "chain": args.chain, "nodes": []}

    for addr in args.addr:
        print(f"\n=== {addr} ===", flush=True)
        node = {"address": addr}
        clen = rpc.code_len(addr)
        node["code_len"] = clen
        print(f"  code: {clen} bytes" + ("   (wrong chain? or not a contract)"
                                        if clen == 0 else ""), flush=True)

        if clen == 0:
            report["nodes"].append(node)
            continue

        # holder balances of the candidate assets
        bal = {}
        for nm, tok in assets.items():
            r = rpc.eth_call(tok, keccak_selector("balanceOf(address)")
                             + addr[2:].rjust(64, "0"))
            raw = dec_uint(r) if isinstance(r, str) else None
            dec = 6 if nm == "USDC" else (6 if nm == "USDT" else 18)
            if raw is not None:
                bal[nm] = {"raw": raw, "human": round(raw / (10 ** dec), 6)}
        node["balances"] = bal
        if bal:
            print("  balances:", json.dumps(bal), flush=True)

        if args.explorer:
            meta, files = explorer_fetch(args.explorer, addr)
            if meta:
                node["explorer"] = meta
                print(f"  name: {meta['name']}   file: {meta['file_path']}", flush=True)
                print(f"  verified: {meta['is_verified']}  compiler: {meta['compiler_version']}",
                      flush=True)
                ctor = meta.get("decoded_constructor_args") or []
                if ctor:
                    print("  CONSTRUCTOR ARGS (trust graph):", flush=True)
                    for a in ctor:
                        if isinstance(a, list) and len(a) == 2:
                            val = a[0]
                            label = (a[1] or {}).get("name", "?")
                            print(f"      {label:26} = {val}", flush=True)
                        else:
                            print(f"      {a}", flush=True)
                parents = parent_imports(files)
                if parents:
                    node["parent_imports"] = parents
                    print(f"  PARENTS TO FETCH (from imports): {parents}", flush=True)
                node["source_files"] = list(files.keys())
        report["nodes"].append(node)

    out = json.dumps(report, indent=1)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        print(f"\nwrote {args.out}", flush=True)
    else:
        print("\n" + out)


if __name__ == "__main__":
    main()
