#!/usr/bin/env python3
"""Notary-verifier scan — find attestation endpoints that notarise a caller's declaration.

Technique (readonly-security-audit / references/signature-binding-sign-vs-execute.md §5e):
an endpoint whose handler verifies a signature and then *immediately* returns a minted
message, with NO intervening chain read / registry lookup / DB read, is a notary. What the
signature MEANS (did the event happen? has the delay elapsed?) is then unverified, and any
party that benefits from the declared outcome can assert it.

Heuristic, not proof: it ranks candidates. Each hit still needs the §5e proof ladder
(L1 accept / L1' stranger-rejected control / L2 on-chain-domain-valid + field-binding check).

Usage:
    python3 notary_verifier_scan.py <src_dir> [--max-gap 25]

Prints one line per candidate:
    <file>:<line>  verify=<fn>  gap=<n lines>  reads=<none|list>
"""
import re
import sys
from pathlib import Path

VERIFY_RE = re.compile(
    r"\b(verifyTypedData|verifyMessage|recoverTypedDataAddress|recoverMessageAddress|"
    r"isValidSignature|ecrecover|ecdsaVerify)\s*\("
)
# anything that constitutes "the verifier checked the world", not just the signature
READ_RE = re.compile(
    r"(\.read\.|getContract|publicClient|rpc\.|fetch\(|axios|\.query\(|\.findOne|"
    r"\.getEntry|\.balanceOf|callStatic|readContract|\.select\()"
)
RETURN_RE = re.compile(r"\breturn\b")
FUNC_RE = re.compile(r"(?:function\s+(\w+)|(?:public|private|async)\s+(?:async\s+)?(\w+)\s*\()")


def scan_file(path: Path, max_gap: int):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    hits = [(i, m.group(1)) for i, ln in enumerate(lines) if (m := VERIFY_RE.search(ln))]
    for idx, fn in hits:
        gap_reads = []
        for off in range(1, max_gap + 1):
            j = idx + off
            if j >= len(lines):
                break
            ln = lines[j]
            if RETURN_RE.search(ln):
                break
            if READ_RE.search(ln):
                gap_reads.append(ln.strip()[:110])
        # a verifier with no world-read before its return = notary candidate
        if not gap_reads:
            print(f"{path}:{idx + 1}  verify={fn}  gap=<={max_gap}  reads=none")
        else:
            joined = " | ".join(gap_reads[:2])
            print(f"{path}:{idx + 1}  verify={fn}  gap=<={max_gap}  reads={joined}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    root = Path(sys.argv[1])
    max_gap = 25
    if "--max-gap" in sys.argv:
        max_gap = int(sys.argv[sys.argv.index("--max-gap") + 1])
    if not root.exists():
        print(f"no such path: {root}")
        return 2
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*")
        if p.suffix in {".ts", ".js", ".mjs", ".go", ".py", ".rs"}
        and "node_modules" not in p.parts and "dist" not in p.parts
    )
    for f in files:
        scan_file(f, max_gap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
