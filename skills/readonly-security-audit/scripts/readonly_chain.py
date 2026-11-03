#!/usr/bin/env python3
"""Read-only probe harness for DeFi audits — NEVER signs, never broadcasts.

Two layers, both importable:

  1. Module-level paced helpers (the original harness) — 1 req/s pacing, JSON-RPC
     + Royco-style API helpers, so a survey script is ~15 lines instead of
     re-implementing HTTP + pacing every time:

         from readonly_chain import rpc, api, apicall, pace, show
         r = rpc("eth_blockNumber", [])
         show(r)
         j = api("POST", "/api/v1/vault/explore", {})
         raw = apicall("0xVault", "0x70a08231...")

  2. A `Chain` class with ABI-encoded calls + log/topic discovery:

         c = Chain(["https://ethereum-rpc.publicnode.com"])
         c.block_number()
         c.code_len("0xBA13...")
         c.call(vault, "getPoolTokens(address)", (pool,), outtypes=["address[]"])
         c.event_topics(vault, from_block, to_block)   # discover topic0 values
         c.match_topics(observed, [sig1, sig2])         # map signatures -> topics

Pure stdlib + eth_abi + eth_utils (both present in most project venvs).
Deliberately avoids `web3` (heavy, often absent).
"""
import json
import time
import urllib.error
import urllib.request

from eth_abi import decode as abi_decode, encode as abi_encode
from eth_utils import keccak

DEFAULT_RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
]

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json",
}


def selector(signature: str) -> bytes:
    """4-byte function selector from a canonical signature."""
    return keccak(text=signature)[:4]


def _arg_types(signature: str):
    inner = signature[signature.index("(") + 1:signature.rindex(")")]
    return [t.strip() for t in inner.split(",")] if inner else []


# ======================================================================
# Layer 1 — paced module-level helpers (original harness)
# ======================================================================

_last = [0.0]


def pace(min_gap=1.0):
    """Sleep so consecutive requests are at least `min_gap` seconds apart."""
    dt = time.time() - _last[0]
    if dt < min_gap:
        time.sleep(min_gap - dt)
    _last[0] = time.time()


def rpc(method, params, chain=1, app="https://app.royco.org", headers=None, raw=False):
    """JSON-RPC against the app's own proxy (or any host) — read-only methods only."""
    h = {"origin": "https://app.royco.org", "content-type": "application/json"}
    if headers:
        h.update(headers)
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    if raw:
        body = params if isinstance(params, (dict, list)) else params
    pace()
    t0 = time.time()
    try:
        r = urllib.request.Request(f"{app}/api/rpc/{chain}", data=json.dumps(body).encode(),
                                   headers=h, method="POST")
        resp = urllib.request.urlopen(r, timeout=60)
        payload = resp.read()
        status = resp.status
        rheaders = dict(resp.headers)
    except urllib.error.HTTPError as e:
        payload = e.read()
        status = e.code
        rheaders = dict(e.headers)
    except Exception as e:                     # noqa: BLE001
        return {"status": 0, "wall": round(time.time() - t0, 3), "json": {"error": str(e)},
                "len": 0, "headers": {}}
    try:
        j = json.loads(payload)
    except Exception:                          # noqa: BLE001
        j = payload.decode("utf-8", "replace")[:4000]
    return {"status": status, "wall": round(time.time() - t0, 3), "json": j,
            "len": len(payload), "headers": rheaders}


def api(method, path, payload=None, headers=None, chain=1, app="https://app.royco.org"):
    """Call the app's REST API (GET/POST). READ-ONLY endpoints only."""
    h = {"origin": "https://app.royco.org", "content-type": "application/json"}
    if headers:
        h.update(headers)
    url = f"{app}{path}"
    pace()
    t0 = time.time()
    try:
        if method == "GET":
            req = urllib.request.Request(url, headers=h, method="GET")
        else:
            req = urllib.request.Request(url, data=json.dumps(payload or {}).encode(),
                                         headers=h, method="POST")
        resp = urllib.request.urlopen(req, timeout=90)
        payload = resp.read()
        status = resp.status
    except urllib.error.HTTPError as e:
        payload = e.read()
        status = e.code
    except Exception as e:                     # noqa: BLE001
        return {"status": 0, "wall": round(time.time() - t0, 3), "json": {"error": str(e)},
                "len": 0, "headers": {}}
    try:
        j = json.loads(payload)
    except Exception:                          # noqa: BLE001
        j = payload.decode("utf-8", "replace")[:4000]
    return {"status": status, "wall": round(time.time() - t0, 3), "json": j,
            "len": len(payload), "headers": {}}


def apicall(to, data, chain=1, block="latest"):
    """Raw eth_call with a hex `data` payload."""
    r = rpc("eth_call", [{"to": to, "data": data}, block], chain=chain)
    return r.get("json", {})


def show(r, keys=None, maxlen=2500):
    """Pretty-print a response dict returned by rpc()/api()."""
    print("STATUS", r.get("status"), "WALL", r.get("wall"), "LEN", r.get("len"))
    j = r.get("json")
    s = json.dumps(j, indent=1) if not isinstance(j, str) else j
    print(s[:maxlen])
    if len(s) > maxlen:
        print("...TRUNC", len(s))
    return j


# ======================================================================
# Layer 2 — Chain class: ABI-encoded calls + log/topic discovery
# ======================================================================


class Chain:
    def __init__(self, rpcs=None, timeout=30, tries=4, app=None):
        self.rpcs = list(rpcs or DEFAULT_RPCS)
        self.timeout = timeout
        self.tries = tries
        self.app = app

    # ---------------------------------------------------------------- rpc
    def rpc(self, method, params=None, url=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params or []}).encode()
        urls = [url] if url else self.rpcs
        last = None
        for attempt in range(self.tries):
            for u in urls:
                try:
                    req = urllib.request.Request(u, data=body, headers=HEADERS)
                    r = json.load(urllib.request.urlopen(req, timeout=self.timeout))
                    if "error" in r:
                        return r
                    return r
                except Exception as e:      # noqa: BLE001 - rotate on any failure
                    last = e
            time.sleep(1.0 + attempt)       # backoff, then rotate the next RPC
        return {"error": str(last)}

    # ------------------------------------------------------------- helpers
    def block_number(self) -> int:
        return int(self.rpc("eth_blockNumber")["result"], 16)

    def code_len(self, addr: str) -> int:
        r = self.rpc("eth_getCode", [addr, "latest"])
        return (len(r.get("result", "0x")) - 2) // 2

    def call(self, to, signature, args=(), block="latest", outtypes=None):
        """eth_call with manual ABI encoding. `args` in eth_abi python form."""
        types = _arg_types(signature)
        data = selector(signature)
        if types:
            data += abi_encode(types, list(args))
        r = self.rpc("eth_call", [{"to": to, "data": "0x" + data.hex()}, block])
        if "result" not in r:
            raise RuntimeError(f"eth_call failed: {r.get('error')}")
        raw = bytes.fromhex(r["result"][2:])
        return abi_decode(outtypes, raw) if outtypes else raw

    def try_call(self, to, signature, args=(), block="latest", outtypes=None):
        try:
            return self.call(to, signature, args, block, outtypes)
        except Exception as e:              # noqa: BLE001
            return {"error": str(e)[:300]}

    # --------------------------------------------------------------- logs
    def logs(self, address, from_block, to_block, topic0=None):
        topics = [topic0] if topic0 else []
        r = self.rpc("eth_getLogs", [{"address": address, "fromBlock": hex(from_block),
                                      "toBlock": hex(to_block), "topics": topics}])
        return r.get("result") or []

    def event_topics(self, address, from_block, to_block):
        """Discover the distinct topic0 values emitted by a contract.

        This is the reliable way to reverse-engineer event signatures: collect the
        observed topic0 set first, THEN test candidate keccak signatures against it.
        Guessing signatures blind and filtering eth_getLogs by topic0 usually
        returns zero because the canonical signature string is long and easy to
        get wrong (structs, enums, nested tuples).
        """
        seen = set()
        for L in self.logs(address, from_block, to_block):
            seen.add(L["topics"][0])
        return seen

    def match_topics(self, observed, signatures):
        """Map candidate signature strings onto an observed topic0 set."""
        out = {}
        for sig in signatures:
            h = "0x" + keccak(text=sig).hex()
            out[sig] = h if h in observed else None
        return out
