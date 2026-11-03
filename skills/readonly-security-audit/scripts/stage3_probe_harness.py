#!/usr/bin/env python3
"""Paced read-only web+chain probe harness for stage-3 adversarial validation.

Read-only by construction: it can issue JSON-RPC reads (eth_call, eth_getLogs,
eth_getCode, eth_blockNumber, eth_getStorageAt) and HTTP GET/POST against the
target's own REST API. It deliberately has NO eth_sendRawTransaction helper and
NO signing code — an audit harness that can broadcast does not belong in a skill
directory.

Requires: requests (or falls back to urllib). Stdlib + requests only.

Usage:
    from stage3_probe_harness import Harness
    h = Harness(app="https://app.example.org", origin="https://app.example.org",
                rpc_path="/api/rpc/{chain}")
    h.rpc("eth_blockNumber")
    h.api("POST", "/api/v1/vault/explore", {})
    h.api_get("/api/v1/market/explore")
    h.call("0xVault...", "balanceOf(address)", ("0xabc...",), outtypes=["uint256"])

Pacing: every request waits until >= min_gap seconds since the previous one
(default 1.05s) — satisfies the "about 1 request per second" rule that audit
briefs impose, and keeps a scripted survey from becoming the DoS being measured.
"""
import json
import time

try:
    import requests
    _HAVE_REQUESTS = True
except ImportError:                                   # pragma: no cover
    _HAVE_REQUESTS = False
    import urllib.error
    import urllib.request

DEFAULT_ORIGIN = "https://app.royco.org"


class Harness:
    def __init__(self, app="https://app.royco.org", origin=None, rpc_path="/api/rpc/{chain}",
                 min_gap=1.05, timeout=60):
        self.app = app.rstrip("/")
        self.origin = origin or DEFAULT_ORIGIN
        self.rpc_path = rpc_path
        self.min_gap = min_gap
        self.timeout = timeout
        self._last = 0.0
        self.count = 0

    # ------------------------------------------------------------- pacing
    def _pace(self):
        dt = time.time() - self._last
        if dt < self.min_gap:
            time.sleep(self.min_gap - dt)
        self._last = time.time()
        self.count += 1

    def _headers(self, extra=None):
        h = {"origin": self.origin, "content-type": "application/json",
             "accept": "application/json"}
        if extra:
            h.update(extra)
        return h

    # ---------------------------------------------------------- transport
    def _send(self, method, url, body=None, headers=None):
        self._pace()
        t0 = time.time()
        if _HAVE_REQUESTS:
            r = requests.request(method, url, headers=self._headers(headers),
                                 json=body, timeout=self.timeout)
            status, raw, hdrs = r.status_code, r.content, dict(r.headers)
        else:
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(url, data=data, headers=self._headers(headers),
                                         method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status, raw, hdrs = resp.status, resp.read(), dict(resp.headers)
            except urllib.error.HTTPError as e:
                status, raw, hdrs = e.code, e.read(), dict(e.headers)
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw.decode("utf-8", "replace")[:4000]
        return {"status": status, "wall": round(time.time() - t0, 3),
                "len": len(raw), "json": parsed, "headers": hdrs}

    # ---------------------------------------------------------------- rpc
    def rpc(self, method, params=None, chain=1, headers=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        url = self.app + self.rpc_path.format(chain=chain)
        return self._send("POST", url, body, headers)

    def call(self, to, signature, args=(), outtypes=None, chain=1, block="latest"):
        """eth_call with manual ABI encoding (no web3 dependency)."""
        from eth_abi import encode as abi_encode, decode as abi_decode
        from eth_utils import keccak
        inner = signature[signature.index("(") + 1:signature.rindex(")")]
        types = [t.strip() for t in inner.split(",")] if inner else []
        data = keccak(text=signature)[:4]
        if types:
            data += abi_encode(types, list(args))
        r = self.rpc("eth_call", [{"to": to, "data": "0x" + data.hex()}, block], chain=chain)
        if "result" not in r.get("json", {}):
            return {"error": r["json"].get("error"), "raw": r}
        raw = bytes.fromhex(r["json"]["result"][2:])
        if outtypes:
            return abi_decode(outtypes, raw)
        return raw

    def get_storage(self, address, slot, chain=1):
        return self.rpc("eth_getStorageAt", [address, slot, "latest"], chain=chain)

    def code_len(self, address, chain=1):
        r = self.rpc("eth_getCode", [address, "latest"], chain=chain)
        res = r.get("json", {}).get("result", "0x")
        return (len(res) - 2) // 2

    # ---------------------------------------------------------------- api
    def api(self, method, path, payload=None, headers=None, base=None):
        url = (base or self.app) + path
        return self._send(method, url, payload, headers)

    def api_get(self, path, headers=None, base=None):
        return self.api("GET", path, None, headers, base)

    def api_post(self, path, payload=None, headers=None, base=None):
        return self.api("POST", path, payload if payload is not None else {}, headers, base)

    # -------------------------------------------------------------- output
    def show(self, r, maxlen=2000, label=""):
        """Print a probe result in a compact, citable form."""
        j = r.get("json")
        s = json.dumps(j, indent=1) if not isinstance(j, str) else j
        head = f"{label} STATUS {r.get('status')} WALL {r.get('wall')}s LEN {r.get('len')}"
        print(head)
        print(s[:maxlen])
        if len(s) > maxlen:
            print(f"...TRUNC total={len(s)}")
        return j

    def survey(self, paths, method="GET", payload=None, base=None, maxlen=600):
        """Batch N path probes into ONE run — the biggest tool-call lever.

        Each item is (method, path) or path or (method, path, payload).
        """
        results = {}
        for item in paths:
            if isinstance(item, str):
                m, p, pl = method, item, payload
            elif len(item) == 2:
                m, p = item
                pl = payload
            else:
                m, p, pl = item
            r = self.api(m, p, pl, base=base)
            body = r.get("json")
            brief = (json.dumps(body)[:maxlen] if not isinstance(body, str) else body[:maxlen])
            results[p] = {"method": m, "status": r["status"], "wall": r["wall"],
                          "len": r["len"], "body": brief}
            print(f"{m:5s} {p}\n      -> {r['status']} wall={r['wall']}s len={r['len']} :: {brief[:300]}")
        return results
