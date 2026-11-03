#!/usr/bin/env python3
"""
immutable_delta_proof.py -- prove (or disprove) that two deployments of the same
contract differ ONLY in immutables / EIP-712 domain separator, and not in logic.

Companion to references/decode-and-proof-traps.md §1a.

Why this exists: two addresses can share BYTE-IDENTICAL verified source yet have
different runtime bytecode, because immutables and the domain separator are baked
in at deploy time. Eyeballing a diff listing is not proof -- and hand-rolled run
splitters get the grouping wrong (per-byte grouping reported 55 "runs" of 1-11
bytes where the truth was 15 runs of exactly 20 and 32 bytes).

Method: fetch eth_getCode for both, group differing bytes into contiguous runs,
blank every run in BOTH copies, then assert the remainders are identical. If they
are, not a single opcode differs.

Usage:
  python immutable_delta_proof.py <addr_a> <addr_b> [--rpc URL]

Exit codes: 0 = masked-identical (benign redeployment), 1 = logic differs or
fetch problem. Always read the printed slot table before quoting the verdict.
"""
import json
import sys
import urllib.request

DEFAULT_RPC = "https://rpc.chain.relay.link"


def rpc(url, method, params, _id=1):
    body = json.dumps({"jsonrpc": "2.0", "id": _id, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    try:
        raw = urllib.request.urlopen(req, timeout=45).read().decode()
    except urllib.error.HTTPError as exc:          # libraries return errors as HTTP bodies
        raw = exc.read().decode()
    return json.loads(raw)


def get_code(url, addr):
    r = rpc(url, "eth_getCode", [addr, "latest"])
    if "error" in r:                                # check error BEFORE result, always
        raise SystemExit(f"eth_getCode failed for {addr}: {r['error']}")
    code = r["result"]
    return code[2:] if code.startswith("0x") else code


def group_runs(hex_a, hex_b):
    """Contiguous differing-BYTE runs, as (byte_offset, byte_len).

    The bug this replaces: grouping per differing character instead of per
    byte yields many small runs and a mask that misses the slot boundaries.
    """
    limit = min(len(hex_a), len(hex_b))
    idx = [i for i in range(0, limit, 2) if hex_a[i:i + 2] != hex_b[i:i + 2]]
    if not idx:
        return []
    runs, cur = [], [idx[0]]
    for x in idx[1:]:
        if x == cur[-1] + 2:
            cur.append(x)
        else:
            runs.append((cur[0] // 2, (cur[-1] - cur[0]) // 2 + 1))
            cur = [x]
    runs.append((cur[0] // 2, (cur[-1] - cur[0]) // 2 + 1))
    return runs


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        raise SystemExit(__doc__)
    url = DEFAULT_RPC
    if "--rpc" in sys.argv:
        url = sys.argv[sys.argv.index("--rpc") + 1]
    addr_a, addr_b = args[0], args[1]

    a, b = get_code(url, addr_a), get_code(url, addr_b)
    print(f"A {addr_a}  runtime bytes = {len(a)//2}")
    print(f"B {addr_b}  runtime bytes = {len(b)//2}")

    if len(a) != len(b):
        print("[!] WARNING: runtime length differs -- this is NOT a pure immutable delta.")
        print("    Compare lengths before anything else; do not mask across a size change.")
        return 1

    runs = group_runs(a, b)
    if not runs:
        print("bytecode identical -> same deployment, nothing to prove.")
        return 0

    print(f"\ndiffering runs: {len(runs)}")
    for off, ln in runs:
        flag = ""
        if ln not in (20, 32):
            flag = "   <- NOT a 20B/32B slot: inspect"
        print(f"  offset=0x{off:04x} len={ln:2d}B  A=0x{a[off*2:(off+ln)*2]}  "
              f"B=0x{b[off*2:(off+ln)*2]}{flag}")

    ma, mb = list(a), list(b)
    for off, ln in runs:
        for k in range(off * 2, (off + ln) * 2):
            ma[k] = mb[k] = "0"
    masked_identical = ("".join(ma) == "".join(mb))

    total = sum(ln for _, ln in runs)
    n20 = sum(1 for _, ln in runs if ln == 20)
    n32 = sum(1 for _, ln in runs if ln == 32)
    print(f"\ntotal differing bytes = {total} of {len(a)//2} "
          f"({100.0*total/(len(a)//2):.2f}%)")
    print(f"runs of 20B (immutable addresses) = {n20}; runs of 32B (domain sep/bytes32) = {n32}")
    print(f"after masking those {len(runs)} runs, code identical? "
          f"{'YES' if masked_identical else 'NO'}")

    if masked_identical:
        print("\n=> PROVEN: every differing byte lies inside an immutable slot or the")
        print("   domain separator. Not one opcode differs.")
        print("   Pair this with: identical verified source (md5) + identical ABI fn set")
        print("   before writing 'benign redeployment' as a verdict.")
        return 0

    print("\n=> LOGIC DIFFERS (or runs were mis-grouped). Treat as high signal:")
    print("   re-group, then read the disassembly around each residual offset.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
