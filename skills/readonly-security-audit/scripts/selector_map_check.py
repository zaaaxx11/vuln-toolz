#!/usr/bin/env python3
"""
Selector-map checker for diamond / facet audits.

Two jobs, both read-only:

  1. --sig-check <tree>   Recompute every `// Sig: 0x........` comment in the source
                          with `cast sig` and report mismatches. A mismatch means the
                          routing table and the source disagree. It also surfaces
                          functions that exist in NO facet (compute the selector for a
                          signature you suspect is missing and grep for it).

  2. --deployed-map <json> [<json> ...]
                          Walk Safe transaction-builder health-audit payloads and print
                          the authoritative live facetAddress -> [selectors] map for the
                          factory / community / strategy diamonds. No RPC needed.

Usage:
    python3 selector_map_check.py --sig-check /path/to/pkg/contracts/src
    python3 selector_map_check.py --deployed-map /path/to/pkg/contracts/transaction-builder/*-health-audit.json
    python3 selector_map_check.py --selftest

Exit codes: 0 = clean, 1 = mismatches / errors found.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys

SIG_COMMENT = re.compile(r"//\s*Sig:\s*(0x[0-9a-fA-F]{8})\s*$")
# A function header line: name(params) visibility ... modifiers
FUNC_HEADER = re.compile(
    r"^\s*function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", re.MULTILINE
)
# Signature reconstruction needs the full header up to the opening brace or ';'
FUNC_BLOCK = re.compile(
    r"^\s*function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^;{}]*?)\)\s*"
    r"(?:external|public|internal|private|payable)?[^{;]*",
    re.MULTILINE | re.DOTALL,
)

FACET_KEYS = ("facets", "communityFacets", "strategyFacets")


def cast_available():
    return shutil.which("cast") is not None


def cast_sig(signature):
    """Return the 4-byte selector for a Solidity signature, or None."""
    try:
        out = subprocess.run(
            ["cast", "sig", signature],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip().lower()


def iter_sol_files(root):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("lib", "node_modules", "out", "cache", "abis")]
        for fn in sorted(filenames):
            if fn.endswith(".sol"):
                yield os.path.join(dirpath, fn)


def strip_comments_keep_sigs(text):
    """Remove block/line comments but keep `// Sig: 0x...` markers so we can pair them."""
    # Pull the Sig comments out first, replace with a placeholder.
    sigs = []
    def _stash(m):
        sigs.append(m.group(1))
        return f"@@SIG{len(sigs)-1}@@"
    text = SIG_COMMENT.sub(_stash, text)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return text, sigs


def sig_check(root, verbose=False):
    """Verify every `// Sig: 0x...` comment against `cast sig`."""
    if not cast_available():
        print("ERROR: `cast` (foundry) not on PATH — cannot recompute selectors.", file=sys.stderr)
        print("       Install foundry or verify the selectors by hand with `cast sig '<sig>'`.", file=sys.stderr)
        return 1

    checked = mismatches = unverified = 0
    for path in iter_sol_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"  ! unreadable {path}: {exc}")
            continue

        body, _ = strip_comments_keep_sigs(raw)
        # Collect function headers in order, then pair each with the next Sig comment
        # that appears after it in the raw text.
        headers = list(FUNC_BLOCK.finditer(body))
        if not headers:
            continue
        sig_marks = list(SIG_COMMENT.finditer(raw))
        if not sig_marks:
            continue

        # Map: byte offset in raw -> signature string
        header_sigs = []
        for h in headers:
            name, params = h.group(1), h.group(2)
            # Normalise whitespace in the parameter list.
            params = re.sub(r"\s+", " ", params).strip()
            sig = f"{name}({params})" if params else f"{name}()"
            header_sigs.append((h.start(), sig))

        for m in sig_marks:
            claimed = m.group(1).lower()
            # Find the nearest preceding function header in the raw text.
            # Sig comments are written after the function they annotate, so the
            # closest header at or before the comment is the right one.
            preceding = [s for off, s in header_sigs if off < m.start()]
            if not preceding:
                continue
            signature = preceding[-1]
            actual = cast_sig(signature)
            if actual is None:
                unverified += 1
                if verbose:
                    print(f"  ? {path}: cannot compute selector for {signature!r} "
                          f"(struct/tuple params need an explicit signature)")
                continue
            checked += 1
            if actual != claimed:
                mismatches += 1
                print(f"  MISMATCH {path}")
                print(f"    comment claims {claimed}  but  cast sig '{signature}' -> {actual}")

    print(f"\n[sig-check] {checked} selector comments verified, {mismatches} mismatch(es), "
          f"{unverified} unverifiable (tuple/struct params).")
    if mismatches:
        print("[sig-check] A mismatch means the routing table and the source disagree — "
              "resolve before trusting either.")
    return 1 if mismatches else 0


def walk_facets(node, path=""):
    """Recursively find dicts that look like facet maps."""
    found = []
    if isinstance(node, dict):
        # A facet entry: address -> list of selectors
        vals = list(node.values())
        looks_like_entry = (
            vals and all(isinstance(v, list) for v in vals)
            and all(all(isinstance(s, str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", s) for s in v) for v in vals)
        )
        if looks_like_entry:
            found.append((path, node))
        for k, v in node.items():
            found.extend(walk_facets(v, f"{path}/{k}"))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(walk_facets(v, f"{path}[{i}]"))
    return found


def deployed_map(paths):
    """Print the live facetAddress -> [selectors] map from Safe health-audit payloads."""
    total = 0
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"  ! {p}: {exc}")
            continue
        print(f"\n=== {p} ===")
        for path, node in walk_facets(data):
            if not node:
                continue
            print(f"  [{path}]")
            for addr, sels in node.items():
                print(f"    {addr}  ({len(sels)} selectors)")
                for s in sels:
                    print(f"        {s}")
                total += len(sels)
    print(f"\n[deployed-map] {total} selectors across {len(paths)} file(s).")
    print("Cross-check these against `cast sig` output: a selector in the deployed map with no")
    print("matching source function is either removed code or a different overload.")
    return 0


def selftest():
    """Validate the Sig-comment parser against known cases."""
    cases = [
        ("// Sig: 0x223e5479\nfunction addStrategy(address _newStrategy) public {", "0x223e5479"),
        ("// Sig: 0xfb1f6917\nfunction rejectPool(address _strategy) public {", "0xfb1f6917"),
        ("// Sig: 0x82d6a1e7\nfunction addStrategyByPoolId(uint256 poolId) public {", "0x82d6a1e7"),
        ("// Sig: 0xce7e2cd3\nfunction createPool(address _token, CVStrategyInitializeParamsV0_3 memory _params, Metadata memory _metadata) public returns (uint256 poolId, address strategy) {", "0xce7e2cd3"),
        ("// Sig: 0x82b18ef4\nfunction createPool(address _strategy, address _token, CVStrategyInitializeParamsV0_3 memory _params, Metadata memory _metadata) public returns (uint256 poolId, address strategy) {", "0x82b18ef4"),
        ("// Sig: 0xf2d774e7\nfunction setCommunityParams(CommunityParams memory _params) external {", "0xf2d774e7"),
        ("// Sig: 0x1f931c1c\nfunction diamondCut(IDiamondCut.FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external onlyOwner {", "0x1f931c1c"),
    ]
    ok = True
    for text, expected in cases:
        m = SIG_COMMENT.search(text)
        if not m or m.group(1).lower() != expected.lower():
            print(f"  FAIL: expected {expected}, got {m.group(1) if m else None}")
            ok = False
    # Function-header extraction must survive a multi-line signature.
    multi = ("function createPool(\n    address _token,\n"
             "    CVStrategyInitializeParamsV0_3 memory _params,\n"
             "    Metadata memory _metadata\n) public returns (uint256 poolId, address strategy) {")
    h = FUNC_BLOCK.search(multi)
    if not h or h.group(1) != "createPool":
        print(f"  FAIL: multi-line header not parsed (got {h.group(1) if h else None})")
        ok = False
    else:
        params = re.sub(r"\s+", " ", h.group(2)).strip()
        if "CVStrategyInitializeParamsV0_3 memory _params" not in params:
            print(f"  FAIL: params mangled: {params!r}")
            ok = False
    print("  PASS" if ok else "  FAILED")
    print("\nNote: `cast sig` is the source of truth. This selftest only validates the parser;")
    print("run --sig-check on a real tree to validate the selectors themselves.")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sig-check", metavar="TREE",
                    help="recompute every `// Sig: 0x...` comment under TREE")
    ap.add_argument("--deployed-map", nargs="+", metavar="JSON",
                    help="print facetAddress -> [selectors] from health-audit payloads")
    ap.add_argument("--selftest", action="store_true", help="validate the parser")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    rc = 0
    if args.sig_check:
        rc |= sig_check(args.sig_check, verbose=args.verbose)
    if args.deployed_map:
        rc |= deployed_map(args.deployed_map)
    if not (args.selftest or args.sig_check or args.deployed_map):
        ap.print_help()
    return rc


if __name__ == "__main__":
    sys.exit(main())
