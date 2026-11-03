#!/usr/bin/env python3
"""First-pass gate scanner for diamond/EIP-2535 facet directories.

Companion to `readonly-security-audit` ->
`references/diamond-facet-access-control-mapping.md`.

WHAT THIS IS
    A candidate list. It extracts every `function` in every .sol file under the given
    directory and reports the ones whose modifier list is empty. That is the set of
    functions most likely to be missing an access-control gate.

WHAT THIS IS NOT
    A finding list. Inherited modifiers (from a base facet), internal helpers, `view`/
    `pure` getters, and functions gated by an inline `if (msg.sender ...)` all appear
    here as false positives. Never claim "no access control" from this output alone --
    read the base facet and the function body.

USAGE
    python3 facet_gate_scan.py <facets-dir> [--all] [--selftest]

    <facets-dir>   directory containing facet .sol files (e.g. src/CVStrategy/facets)
    --all          also print functions that DO have modifiers. Use this to eyeball
                   WHICH RESOLVER each gate calls -- see finding class #1
                   (owner-resolution asymmetry), which is invisible without it.
    --selftest     run the built-in sample and exit. Run this FIRST, before trusting
                   the parser's output on a real tree.

SOLIDITY SYNTAX NOTE (why this parser is shaped the way it is)
    Modifiers come AFTER the parameter list, not before it:
        function allocate(bytes memory _data, address _sender)
            external payable onlyAllo onlyInitialized nonReentrant { ... }
    A naive regex that captures only the text between the function name and the opening
    paren finds NOTHING and reports every function as ungated -- a scanner that cries
    wolf on 100% of the codebase is worse than no scanner. This parser does a
    balanced-paren scan to the end of the parameter list, then reads the region up to
    `{` or `;`, cuts it at the `returns` keyword, and strips `override(...)` groups.

EXIT CODE
    0 on success, 1 on selftest failure, 2 on usage/path error.
    This is a discovery aid, not a gate.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Language keywords that are NOT access-control modifiers. Anything left after
# filtering these is treated as a modifier.
NON_GATE_KEYWORDS = {
    "public", "external", "internal", "private", "pure", "view", "payable",
    "virtual", "override", "constant", "immutable", "indexed", "returns",
    "memory", "calldata", "storage", "pointer",
}

# Substrings that suggest a token IS a gate.
GATE_HINTS = (
    "only", "auth", "owner", "admin", "council", "member", "allo", "registry",
    "initialized", "reentrant", "paused", "pause", "when", "non", "require",
    "check", "gate", "role", "safe", "strategy", "enabled",
)

FUNC_NAME_RE = re.compile(r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)")


def blank_comments_and_strings(src: str) -> str:
    """Replace comment and string-literal CONTENTS with spaces, preserving length and
    every newline.

    Preserving length is what lets line numbers computed on the blanked source be
    correct for the original file. Deleting the characters instead would shift every
    offset and silently misreport line numbers.
    """
    out = list(src)
    i, n = 0, len(src)

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = i
            while j < n and src[j] != "\n":
                j += 1
            blank(i, j)
            i = j
        elif c == "/" and nxt == "*":
            j = i + 2
            while j < n and not (src[j] == "*" and j + 1 < n and src[j + 1] == "/"):
                j += 1
            end = min(j + 2, n)
            blank(i, end)
            i = end
        elif c in ('"', "'"):
            quote = c
            j = i + 1
            while j < n and src[j] != quote:
                if src[j] == "\\" and j + 1 < n:
                    j += 1
                j += 1
            blank(i + 1, min(j, n))
            i = j + 1
        else:
            i += 1
    return "".join(out)


def line_of(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def extract_modifiers(region: str) -> list[str]:
    """Turn the text between the parameter list and `{`/`;` into a modifier list.

    Handles `returns (...)`, `override(IFoo)`, and visibility/mutability keywords.
    """
    cut = re.split(r"\breturns\b", region, maxsplit=1)[0]
    cut = re.sub(r"\([^()]*\)", " ", cut)  # drop override(...) groups
    tokens = [t for t in re.split(r"[\s,]+", cut.strip()) if t]
    return [t for t in tokens if t not in NON_GATE_KEYWORDS]


def scan_source(src: str) -> list[tuple[int, str, list[str]]]:
    """Return [(line, function_name, modifiers)] for every function in src."""
    results: list[tuple[int, str, list[str]]] = []
    for m in FUNC_NAME_RE.finditer(src):
        name = m.group(1)
        i = m.end()
        n = len(src)
        while i < n and src[i] in " \t\r\n":
            i += 1
        if i >= n or src[i] != "(":
            continue  # e.g. the word "function" in prose; no parameter list follows
        depth, j = 0, i
        while j < n:
            ch = src[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            continue
        k = j + 1
        buf: list[str] = []
        while k < n and src[k] not in "{;":
            buf.append(src[k])
            k += 1
        if k >= n:
            continue
        results.append((line_of(src, m.start()), name, extract_modifiers("".join(buf))))
    return results


def classify(mods: list[str]) -> str:
    if not mods:
        return "NO-MODIFIER"
    gated = [x for x in mods if any(h in x.lower() for h in GATE_HINTS)]
    if gated:
        return "GATE:" + ",".join(gated)
    return "OTHER:" + ",".join(mods)


SELFTEST_SOL = '''
contract Sample is Base {
    // a normal gated function
    function a() external onlyOwner {}
    /* block comment with function ghost() external {} inside */
    function b(uint256 x) public view returns (uint256) { return x; }
    function c(address g) external {
        if (!isAuth(msg.sender)) { onlyCouncilSafeOrMember(); }
    }
    function d() external payable nonReentrant whenNotPaused {}
    function e() internal {}
    function f() public override(ISomething) onlyCouncilSafe {}
    modifier onlyOwner() { _; }
    string s = "function notReal() external {}";
}
'''

SELFTEST_EXPECT = {
    "a": "GATE:onlyOwner",
    "b": "NO-MODIFIER",
    "c": "NO-MODIFIER",
    "d": "GATE:nonReentrant,whenNotPaused",
    "e": "NO-MODIFIER",
    "f": "GATE:onlyCouncilSafe",
}


def selftest() -> int:
    src = blank_comments_and_strings(SELFTEST_SOL)
    found = {name: classify(mods) for _, name, mods in scan_source(src)}
    ok = True
    for name, want in sorted(SELFTEST_EXPECT.items()):
        got = found.get(name, "<not found>")
        if got != want:
            ok = False
        print(f"  [{'PASS' if got == want else 'FAIL'}] {name}: expected {want!r}, got {got!r}")
    for ghost in ("ghost", "notReal"):
        if ghost in found:
            print(f"  [FAIL] {ghost}: should have been blanked as comment/string content")
            ok = False
        else:
            print(f"  [PASS] {ghost}: correctly ignored (comment/string content)")
    print("SELFTEST " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("facets_dir", nargs="?", help="directory containing facet .sol files")
    ap.add_argument("--all", action="store_true",
                    help="also print functions that have modifiers")
    ap.add_argument("--selftest", action="store_true",
                    help="run the built-in sample and exit")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.facets_dir:
        ap.error("facets_dir is required unless --selftest is given")

    root = Path(args.facets_dir)
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    files = sorted(root.rglob("*.sol"))
    if not files:
        print(f"error: no .sol files under {root}", file=sys.stderr)
        return 2

    no_mod: list[tuple[str, int, str]] = []
    gated: list[tuple[str, int, str, str]] = []

    for f in files:
        src = blank_comments_and_strings(f.read_text(encoding="utf-8", errors="replace"))
        for lineno, name, mods in scan_source(src):
            verdict = classify(mods)
            if verdict == "NO-MODIFIER":
                no_mod.append((f.name, lineno, name))
            elif args.all:
                gated.append((f.name, lineno, name, verdict))

    print(f"# scanned {len(files)} file(s) under {root}")
    print()
    print(f"## NO-MODIFIER candidates ({len(no_mod)}) -- verify each against the base facet")
    if not no_mod:
        print("  (none)")
    for fname, lineno, name in no_mod:
        print(f"  {fname}:{lineno}  {name}()")

    if args.all:
        print()
        print(f"## functions WITH modifiers ({len(gated)})")
        print("## eyeball WHICH RESOLVER each gate uses (effectiveOwner vs raw proxyOwner)")
        for fname, lineno, name, verdict in gated:
            print(f"  {fname}:{lineno}  {name}()  [{verdict}]")

    print()
    print("REMINDER: inherited modifiers live in the base facet, not here. A NO-MODIFIER")
    print("entry is a candidate, never a finding. Read the base facet before concluding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
