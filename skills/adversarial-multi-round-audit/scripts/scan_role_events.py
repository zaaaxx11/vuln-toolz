#!/usr/bin/env python3
"""scan_role_events.py — full-history RoleGranted/RoleRevoked census with cursor
pagination done correctly, plus MANDATORY reconciliation against live hasRole().

Why this script exists: a hand-rolled version advanced the block window when a page
had no cursor, silently skipping pages and producing 12 fabricated "active holders".
This one follows every cursor to exhaustion PER WINDOW, writes each response to disk
as it arrives, and refuses to print an "active holders" list that live state disagrees
with.

Usage:
    python scan_role_events.py --rpc URL --contract ADDR --role-hash 0x... \
        [--role-name OPERATOR_ROLE] [--outdir ./out] [--span 400000]

    # verify the live predicate selector too (default hasRole(bytes32,address))
    ... optional --predicate 'hasRole(bytes32,address)'

Exit codes: 0 = census consistent with live state, 2 = MISMATCH (method defective),
            3 = instrument invalid (positive control returned nothing).

Requires: pycryptodome  (pip install pycryptodome)  — no eth_utils needed.
"""
import argparse, json, os, sys, time
import urllib.request

try:
    from Crypto.Hash import keccak as _k
except ImportError:
    sys.exit("install pycryptodome: python -m pip install pycryptodome")


def keccak(b):
    h = _k.new(digest_bits=256)
    h.update(b if isinstance(b, bytes) else b.encode())
    return h.digest()


def sel(sig):
    return "0x" + keccak(sig)[:4].hex()


def topic(sig):
    return "0x" + keccak(sig).hex()


def pad_addr(a):
    assert len(a) == 42 and a.startswith("0x"), f"not a 40-hex address: {a!r}"
    return "0" * 24 + a[2:].lower()


class Rpc:
    def __init__(self, url, timeout=55, tries=4):
        self.url, self.timeout, self.tries = url, timeout, tries

    def __call__(self, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params}).encode()
        last = None
        for i in range(self.tries):
            try:
                req = urllib.request.Request(
                    self.url, body, {"Content-Type": "application/json"})
                return json.loads(
                    urllib.request.urlopen(req, timeout=self.timeout).read().decode())
            except Exception as e:  # noqa: BLE001 - transport noise, retry
                last = str(e)
            time.sleep(1.0 + i)
        return {"error": {"message": str(last)}}


def scan(rpc, contract, topic0, span, tip, outdir, tag, log, start_block=1):
    """Cursor pagination correct form: exhaust cursors per window, then advance."""
    events, lo, guard = [], start_block, 0
    while lo <= tip and guard < 200:
        guard += 1
        hi = min(lo + span - 1, tip)
        cursor, page = None, 0
        while guard < 200:
            guard += 1
            page += 1
            p = {"fromBlock": hex(lo), "toBlock": hex(hi),
                 "address": contract, "topics": [topic0]}
            if cursor:
                p["cursor"] = cursor
            d = rpc("eth_getLogsWithCursor", [p])
            path = os.path.join(outdir, f"{tag}_{lo}_{page}.json")
            with open(path, "w") as fh:
                fh.write(json.dumps(d)[:200000])
            if "result" not in d:
                log(f"  {tag} ERR lo={lo} page={page} cur={bool(cursor)}: "
                    f"{str(d.get('error'))[:80]}")
                break
            r = d["result"] if isinstance(d["result"], dict) else {}
            logs = r.get("logs") or []
            for x in logs:
                events.append((
                    "0x" + x["topics"][2][26:],
                    int(x["blockNumber"], 16),
                    int(x.get("logIndex", "0x0"), 16),
                ))
            nc = r.get("cursor") or r.get("nextCursor")
            log(f"  {tag} win {lo}-{hi} page {page}: +{len(logs)} cursor={'y' if nc else 'n'}")
            if nc:
                cursor = nc
            else:
                break                      # window EXHAUSTED -> advance lo
        lo = hi + 1
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--contract", required=True)
    ap.add_argument("--role-hash", required=True)
    ap.add_argument("--role-name", default="ROLE")
    ap.add_argument("--predicate", default="hasRole(bytes32,address)")
    ap.add_argument("--span", type=int, default=400000)
    ap.add_argument("--outdir", default="./out")
    ap.add_argument("--control-tx", default=None,
                    help="a known-good tx hash; its receipt block is the positive control")
    ap.add_argument("--deploy-block", type=int, default=1,
                    help="block the contract was deployed at. Scan starts here. "
                         "FIND THIS FIRST from the explorer txlist (sort=asc, first row "
                         "with contractAddress == target). Starting at 1 with a full-"
                         "history cursor scan burns the whole round budget; starting "
                         "too late silently hides every early grant.")
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    rpc = Rpc(a.rpc)

    def log(m):
        print(m, flush=True)

    d = rpc("eth_blockNumber", [])
    if "result" not in d:
        log(f"INSTRUMENT-INVALID: eth_blockNumber failed {d}")
        return 3
    tip = int(d["result"], 16)
    role = a.role_hash[2:] if a.role_hash.startswith("0x") else a.role_hash
    log(f"contract={a.contract} role={a.role_name} tip={tip} span={a.span}")

    # ---- L1 positive control: known block must yield a log ----
    if a.control_tx:
        rc = rpc("eth_getTransactionReceipt", [a.control_tx]).get("result") or {}
        if rc.get("blockNumber"):
            blk = int(rc["blockNumber"], 16)
            q = rpc("eth_getLogs", [{"fromBlock": hex(blk), "toBlock": hex(blk),
                                     "address": rc["to"]}])
            n = len(q.get("result") or []) if "result" in q else 0
            log(f"L1 control: block {blk} -> {n} logs")
            if n == 0:
                log("INSTRUMENT-INVALID: positive control returned 0 logs")
                return 3

    G = scan(rpc, a.contract, topic("RoleGranted(bytes32,address,address)"),
             a.span, tip, a.outdir, "granted", log, a.deploy_block)
    R = scan(rpc, a.contract, topic("RoleRevoked(bytes32,address,address)"),
             a.span, tip, a.outdir, "revoked", log, a.deploy_block)
    log(f"grants={len(G)} revokes={len(R)}")
    json.dump({"grants": G, "revokes": R},
              open(os.path.join(a.outdir, "events.json"), "w"), indent=1)

    # ---- reconcile against live state (MANDATORY) ----
    def u(r):
        return int(r, 16) if isinstance(r, str) and len(r) >= 66 else None

    pred = sel(a.predicate)
    cands = sorted({x[0] for x in G} | {x[0] for x in R})
    bad, active = [], []
    log("\n=== reconciliation: derived vs live ===")
    for addr in cands:
        try:
            pa = pad_addr(addr)
        except AssertionError:
            bad.append((addr, "malformed address in event log"))
            continue
        lastg = max([b for x, b, _ in G if x == addr], default=0)
        lastr = max([b for x, b, _ in R if x == addr], default=0)
        exp = 1 if (lastg > lastr and lastg > 0) else 0
        live = u(rpc("eth_call", [{"to": a.contract,
                                   "data": pred + role + pa}, "latest"]).get("result"))
        code = rpc("eth_getCode", [addr, "latest"]).get("result", "0x")
        kind = "EOA" if len(code) <= 2 else f"contract({len(code)//2-1}B)"
        flag = "" if live == exp else "  <-- MISMATCH"
        if live == exp and exp == 1:
            active.append((addr, kind))
        if live != exp:
            bad.append((addr, f"derived={exp} live={live}"))
        log(f"  {addr[:14]}… {kind:16s} lastG={lastg} lastR={lastr} "
            f"exp={exp} live={live}{flag}")

    log("\n=== ACTIVE holders (only if reconciliation is clean) ===")
    if bad:
        log(f"POSITIVE-CONTROL FAILED on {len(bad)} address(es): {bad[:4]}")
        log("=> METHOD DEFECTIVE. Do not report this census. Re-scan; do not rationalise.")
        return 2
    for addr, kind in active:
        log(f"  {addr}  {kind}")
    log("census consistent with live state")
    return 0


if __name__ == "__main__":
    sys.exit(main())
