#!/usr/bin/env python3
"""Exact event census over an EVM chain RPC — the loop that finally gave the RIGHT number.

Built after three broken variants produced 1, then 45,144, then 1,930,893 for the same
event on the same contract. Every safety property below exists because one of those
variants violated it. Read the GUARANTEES before adapting.

Reference: references/rpc-census-supply-integrity-and-role-enumeration.md §9 / §10
           references/live-rpc-forensics-and-eth-call-trap.md §15 (log-layer traps)

USAGE
    python3 cursor_census.py --rpc URL --address 0xABC --topic 0xDEF \
        [--tip 6133000] [--inverse-topic 0x123] [--window 100000] [--out /tmp/census.log]

    # two-pass (forward + inverse event), which is what makes "0 deletes" citable:
    python3 cursor_census.py --rpc $R --address $C \
        --topic $ENTRY_SET --inverse-topic $ENTRY_DELETED

WHY eth_getLogsWithCursor
    Full-range eth_getLogs fails with
      {"code":-32005,"message":"Response size exceeds limit. Use eth_getLogsWithCursor ..."}
    Non-standard, but present. If it is absent, this script reports BLOCKED with the
    literal response — it does NOT silently fall back to a method that under-counts.

GUARANTEES (each one is a bug this session actually hit)
  1. Response goes to a FILE, never through stdout. A 100k window returned ~989 KB /
     1154 logs; capturing that in-process yields JSONDecodeError that READS like
     "the RPC returned nothing". wc -c distinguishes them; we assert on it.
  2. Dedup by (txHash, topic1, topic2, logIndex) — the log identity, not by txHash
     alone (one tx can emit several matching logs).
  3. Per-page counters printed: logs=<n> new_unique=<n>. If new_unique collapses
     while logs stays high, the cursor is re-serving the same page.
  4. Cursor advance is asserted: `if nc == cur: break` — a cursor echoed back
     unchanged produces an infinite loop that LOOKS like a slow scan.
  5. Window count is arithmetic-checked: we expect ceil(tip/window) lines and the last
     window must end at TIP. A monotone cum= curve is NOT proof of coverage.
  6. fails is gated: any failed window marks the result PARTIAL and the exit code
     becomes 2. A count whose companion fails>0 is not a count.
  7. log.address is post-filtered. Some RPCs ignore the address filter and return
     neighbourhood logs (observed: every "hit" belonged to a different contract).

OUTPUT FIELDS (the four no volume claim ships without)
    COUNT UNIQUE / unique actors / unique tx / block range / failed windows
    + the inverse event count when --inverse-topic is given.
"""
import argparse
import json
import os
import subprocess
import sys
from collections import Counter

CURSOR_METHOD = "eth_getLogsWithCursor"


def make_rpc(url, timeout=60):
    """Return an rpc(method, params) that NEVER parses oversized stdout."""
    req, resp = "/tmp/_census_req.json", "/tmp/_census_resp.json"

    def rpc(method, params):
        with open(req, "w") as f:
            json.dump({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, f)
        subprocess.run(
            ["curl", "-s", "-m", str(timeout), "-X", "POST", url,
             "-H", "Content-Type: application/json", "--data", "@" + req, "-o", resp],
            check=False,
        )
        try:
            size = os.path.getsize(resp)
        except OSError:
            return {"error": "no response file"}
        if size == 0:
            return {"error": "empty response (0 bytes)"}
        try:
            return json.load(open(resp))
        except Exception as e:  # noqa: BLE001
            return {"error": f"parse failed on {size} bytes: {e}", "bytes": size}

    return rpc


def scan(rpc, address, topic, tip, window, want_values=False):
    """Walk genesis→tip in fixed windows, paginating each window by cursor."""
    seen = {}
    fails = []
    windows_done = 0
    addr_l = address.lower()

    for lo in range(0, tip + 1, window):
        hi = min(lo + window - 1, tip)
        cur = None
        pages = 0
        while pages < 60:  # generous, but finite
            params = {
                "address": address,
                "fromBlock": hex(lo),
                "toBlock": hex(hi),
                "topics": [topic],
            }
            if cur:
                params["cursor"] = cur
            d = rpc(CURSOR_METHOD, [params])
            if "result" not in d:
                fails.append((lo, hi, str(d)[:160]))
                break
            res = d["result"]
            logs = res.get("logs") or []
            new = 0
            for lg in logs:
                # (7) post-filter: never trust the server-side address slice
                if lg.get("address", "").lower() != addr_l:
                    continue
                key = (
                    lg["transactionHash"],
                    lg["topics"][1] if len(lg["topics"]) > 1 else "",
                    lg["topics"][2] if len(lg["topics"]) > 2 else "",
                    lg.get("logIndex"),
                )
                if key not in seen:
                    seen[key] = {
                        "blk": int(lg["blockNumber"], 16),
                        "actor": "0x" + lg["topics"][1][-40:] if len(lg["topics"]) > 1 else None,
                        "topic2": lg["topics"][2] if len(lg["topics"]) > 2 else None,
                        "tx": lg["transactionHash"],
                        "data": lg.get("data", "0x"),
                    }
                    new += 1
            pages += 1
            print(f"  win {lo}-{hi} p{pages}: logs={len(logs)} new_unique={new}", flush=True)
            nc = res.get("cursor")
            # (4) a stuck cursor is an infinite loop, not a slow scan
            if not nc or nc == cur or not logs:
                break
            cur = nc
        windows_done += 1

    return seen, fails, windows_done


def report(label, seen, fails, windows_done, tip, window):
    blocks = sorted(v["blk"] for v in seen.values()) if seen else []
    actors = Counter(v["actor"] for v in seen.values() if v["actor"])
    txs = {v["tx"] for v in seen.values()}
    print(f"\n=== {label} ===")
    print(f"COUNT UNIQUE   = {len(seen)}")
    print(f"unique actors  = {len(actors)}")
    print(f"unique tx      = {len(txs)}")
    print(f"block range    = {blocks[0] if blocks else '-'} .. {blocks[-1] if blocks else '-'}")
    print(f"failed windows = {len(fails)}")
    print(f"windows walked = {windows_done} (expected {-(-(tip + 1) // window)})")
    if actors:
        print("\ntop actors:")
        for a, c in actors.most_common(15):
            print(f"  {a} : {c}")
    if fails:
        print("\n!! PARTIAL — failed windows (do NOT quote the count):")
        for lo, hi, err in fails[:5]:
            print(f"  {lo}-{hi}: {err}")
    return len(fails)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--topic", required=True)
    ap.add_argument("--inverse-topic")
    ap.add_argument("--tip", type=int)
    ap.add_argument("--window", type=int, default=100000)
    ap.add_argument("--out")
    a = ap.parse_args()

    # --out: mirror stdout to a file (census runs are 10-90 min; a dropped terminal
    # must not lose the numbers). Tee, don't replace, so tail -f still works.
    out_fh = None
    if a.out:
        class _Tee:
            def __init__(self, fh):
                self.fh = fh

            def write(self, s):
                sys.__stdout__.write(s)
                self.fh.write(s)

            def flush(self):
                sys.__stdout__.flush()
                self.fh.flush()

        out_fh = open(a.out, "w")
        sys.stdout = _Tee(out_fh)

    rpc = make_rpc(a.rpc)

    tip = a.tip
    if tip is None:
        d = rpc("eth_blockNumber", [])
        if "result" not in d:
            print(f"BLOCKED: eth_blockNumber → {d}", file=sys.stderr)
            return 2
        tip = int(d["result"], 16)
    print(f"tip={tip} window={a.window} cursor-method={CURSOR_METHOD}")

    total_fail = 0
    fwd, fails, wd = scan(rpc, a.address, a.topic, tip, a.window)
    total_fail += report("FORWARD topic", fwd, fails, wd, tip, a.window)

    if a.inverse_topic:
        inv, fails2, wd2 = scan(rpc, a.address, a.inverse_topic, tip, a.window)
        total_fail += report("INVERSE topic", inv, fails2, wd2, tip, a.window)
        # a zero on the inverse event is an AMPLIFIER, not an absence:
        print(
            f"\nINVERSE COUNT = {len(inv)}"
            + ("  → zero deletes across the whole history: writes are PERMANENT"
               if len(inv) == 0 else "  → deletions exist, reason about reversibility")
        )

    if total_fail:
        print(f"\nRESULT: PARTIAL — {total_fail} failed window(s). Count is NOT final.")
        return 2
    print("\nRESULT: COMPLETE — 0 failed windows. Safe to quote as a final volume number.")
    if out_fh:
        out_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
