#!/usr/bin/env python3
"""
census_instances.py — enumerate DISTINCT instances of a trust-bearing contract
BEFORE analysing any of them.

Implements SKILL.md pitfall 30 ("ONE EXECUTOR, ONE ORACLE, ONE MAPPING"). A
campaign that tests one executor and one signer can produce a confident REFUTED
verdict while a sibling deployment with a weaker trust model sits unexamined.

What it does
------------
1. Pull every tx that ever called the seed address via explorer `txlist`.
2. Decode each successful call's calldata and extract a caller-specified set of
   "identity" fields at known word offsets (executor, resolver, oracle/signer, hub...).
3. Print the DISTINCT SET for each field. Any set with size > 1 and elements you
   have not analysed is an UNAUDITED SURFACE — that is the whole point.
4. Emit a `--json` blob suitable for appending to hunt_state.json.

Usage
-----
    python3 census_instances.py \
        --explorer https://explorer.chain.relay.link \
        --address 0x6747c7e64b90dccc0d54f865cbd9513156adbc0c \
        --selector 432994b7 \
        --field order:11 --field resolver:1 --field signer:3

    # field spec = NAME:WORD_INDEX   (0-based 32-byte word index into calldata
    #                                  AFTER the 4-byte selector)
    # Verify each index with `--dump <txhash>` before trusting the census --
    # an offset read as a value yields addresses that look plausible and are wrong
    # (references/abi-and-field-verification.md Rule 11).

Exit codes
----------
    0  census completed; sets printed
    1  no transactions found (verify the address/selector before concluding "unused"
       -- sub-calls do not appear in txlist, see SKILL.md pitfall 20)
    2  argument / fetch error

Design notes
------------
- explorer `txlist` is ONE request for full history; a block scan is O(blocks) and
  dies on rate-limited RPCs (a 5-minute sweep produced zero progress in-session).
- Only tx whose `to` == address are direct calls. A log with topics[2] == address
  means the contract RECEIVED something, not that it was CALLED.
- Never fabricate a tx hash or field value to make this run (pitfall 29). If the
  fetch fails, the answer is "fetch failed", not a placeholder.
"""
import argparse
import json
import sys
import time
import urllib.request


def fetch_json(url: str, attempts: int = 4, timeout: int = 25):
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001 - want the last error for reporting
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"fetch failed after {attempts} attempts: {last}")


def txlist(explorer: str, address: str, offset: int = 100):
    url = (
        f"{explorer.rstrip('/')}/api?module=account&action=txlist"
        f"&address={address}&sort=desc&page=1&offset={offset}"
    )
    data = fetch_json(url)
    if data.get("status") == "0" and not data.get("result"):
        return []
    res = data.get("result") or []
    return res if isinstance(res, list) else []


def word(raw: bytes, idx: int):
    """Return 32-byte word `idx` of calldata (after the 4-byte selector)."""
    start = idx * 32
    chunk = raw[start:start + 32]
    return chunk if len(chunk) == 32 else None


def as_address(w: bytes):
    """Interpret a word as an address (low 20 bytes) only if the top 12 are zero."""
    if w is None or any(w[:12]):
        return None
    addr = "0x" + w[12:].hex()
    if addr == "0x" + "00" * 20:
        return None  # zero address is not an instance
    return addr


def as_uint(w: bytes):
    return None if w is None else int.from_bytes(w, "big")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--explorer", required=True, help="e.g. https://explorer.chain.relay.link")
    ap.add_argument("--address", required=True, help="seed contract to census")
    ap.add_argument("--selector", required=True, help="4-byte hex, with or without 0x")
    ap.add_argument("--field", action="append", default=[], metavar="NAME:WORD_IDX",
                    help="identity field to enumerate (repeatable)")
    ap.add_argument("--offset", type=int, default=100, help="txlist page size (default 100)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    sel = args.selector.lower().removeprefix("0x")
    fields = []
    for spec in args.field:
        if ":" not in spec:
            sys.exit(f"bad --field spec: {spec!r} (want NAME:WORD_IDX)")
        name, idx = spec.rsplit(":", 1)
        fields.append((name, int(idx)))
    if not fields:
        print("WARNING: no --field given; only tx counts will be reported", file=sys.stderr)

    try:
        txs = txlist(args.explorer, args.address, args.offset)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    if not txs:
        print(
            "NO TRANSACTIONS FOUND.\n"
            "  Do NOT conclude 'unused / dead code' from this alone (SKILL.md pitfall 20).\n"
            "  A contract driven as a SUB-CALL from a batcher never appears in txlist.\n"
            "  Cross-check: does it appear in eth_getLogs value flow? Is there another\n"
            "  contract whose calldata references this address?",
            file=sys.stderr,
        )
        sys.exit(1)

    hits = [t for t in txs if (t.get("input", "0x")[2:10].lower() == sel)]
    ok = [t for t in hits if str(t.get("isError")) == "0"]

    sets = {name: {} for name, _ in fields}
    for t in ok:
        raw = bytes.fromhex(t["input"][2:])[4:]
        for name, idx in fields:
            w = word(raw, idx)
            val = as_address(w)
            if val is None:
                u = as_uint(w)
                val = str(u) if u is not None else None
            if val is None:
                continue
            sets[name].setdefault(val, []).append(t["hash"])

    out = {
        "seed_address": args.address,
        "selector": "0x" + sel,
        "tx_total": len(txs),
        "tx_matching_selector": len(hits),
        "tx_successful": len(ok),
        "distinct": {n: sorted(v) for n, v in sets.items()},
    }

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"seed       : {args.address}")
        print(f"selector   : 0x{sel}")
        print(f"txs        : {len(txs)} total / {len(hits)} matching selector / {len(ok)} successful")
        print()
        for name, vals in out["distinct"].items():
            n = len(vals)
            flag = "  <-- MULTIPLE INSTANCES: audit EACH before any global verdict" if n > 1 else ""
            print(f"{name:12}: {n} distinct{flag}")
            for v in vals:
                print(f"    {v}")

    # The trap this script exists to catch.
    multi = {n: v for n, v in out["distinct"].items() if len(v) > 1}
    if multi:
        print()
        print("!! MORE THAN ONE INSTANCE PER FIELD.")
        print("   Scope every REFUTED verdict to the instance actually tested.")
        print("   Write 'gate solid on <X>; <Y> UNAUDITED', never 'the gate is solid'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
