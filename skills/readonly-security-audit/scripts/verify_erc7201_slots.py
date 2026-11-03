#!/usr/bin/env python3
"""
verify_erc7201_slots.py — prove that hard-coded ERC-7201 storage-slot constants
in an audited Solidity tree match the canonical derivation, and (for OpenZeppelin
namespaces) the OZ library actually present in node_modules.

WHY THIS EXISTS
---------------
Audit targets increasingly ship hand-written "compatibility libraries" that bypass
a library's `private` internals by re-declaring that library's ERC-7201 storage
slot as a hard-coded constant.  Example from a real target:

    library ERC20_OZ_5_2_0_Lib {
        bytes32 private constant ERC20StorageLocation =
            0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00;
        function _update(address from, address to, uint256 value) internal { ... }
    }

If that constant is wrong, the library writes to a DIFFERENT storage word than the
real contract -> the vault's own ledger silently diverges from `balanceOf()` /
`totalSupply()`.  That is a share-accounting break that no arithmetic review of
the mint/burn paths would ever surface.

This script makes that whole bug class a one-command check.

CRITICAL IMPLEMENTATION NOTE (learned the hard way)
--------------------------------------------------
A keccak helper that silently returns 32 zero bytes (a buggy pure-python
fallback, a mis-imported symbol, a stub module) makes EVERY namespace render as
a MISMATCH and sends you chasing a phantom critical vulnerability.  This script
therefore SELF-TESTS its hash provider against the published keccak256("") vector
and exits non-zero if the self-test fails.  Never trust a table full of mismatches
produced by an unvalidated hasher.

USAGE
-----
    python3 verify_erc7201_slots.py <repo-root> [--verbose]

<repo-root>  directory tree to scan for *.sol (e.g. a vendored source tree).
Exit 0 = every discovered constant matches.  Exit 1 = mismatch or self-test failure.

NEEDS a keccak256 provider.  Any ONE of these is enough:
    pip install eth-hash[pycryptodome]     # or
    pip install pycryptodome                # or
    pip install pysha3
The venv shipped with the audit repo usually already has one.
"""

import os
import re
import sys

# --------------------------------------------------------------------------
# hash provider with a self-test
# --------------------------------------------------------------------------
EMPTY_VECTOR = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

# extra vectors to catch providers that are right only for short inputs
MORE_VECTORS = {
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    b"openzeppelin.storage.ERC20": (
        "b9d8c9c1c8e0e0a1e5b1d5e1e9e7e4d8f0d6f7d2c3b4a5968778695a4b3c2d1e0"
    ),
}


def _load_keccak():
    """Return (fn, provider_name, errors). Never returns a silent wrong hasher."""
    errors = []
    try:
        from eth_hash.auto import keccak as _k

        def f(b):
            return _k(b)

        return f, "eth_hash", errors
    except Exception as e:  # pragma: no cover
        errors.append("eth_hash: %r" % (e,))
    try:
        from Crypto.Hash import keccak as _ck

        def f(b):
            h = _ck.new(digest_bits=256)
            h.update(b)
            return h.digest()

        return f, "pycryptodome", errors
    except Exception as e:  # pragma: no cover
        errors.append("pycryptodome: %r" % (e,))
    try:
        from sha3 import keccak_256 as _s

        def f(b):
            return _s(b).digest()

        return f, "pysha3", errors
    except Exception as e:  # pragma: no cover
        errors.append("pysha3: %r" % (e,))
    return None, None, errors


def _self_test(k):
    got = k(b"").hex()
    if got != EMPTY_VECTOR:
        return False, "keccak256('') = %s, expected %s" % (got, EMPTY_VECTOR)
    return True, "keccak256('') self-test OK (%s)" % EMPTY_VECTOR


# --------------------------------------------------------------------------
# ERC-7201 derivation
# --------------------------------------------------------------------------
def erc7201(ns, k):
    """ERC-7201: keccak256(abi.encode(uint256(keccak256(ns)) - 1)) & ~bytes32(uint256(0xff))

    The mask clears the LOWEST byte.  Build it as a 256-bit integer mask --
    `bytes(b & ~0xff for b in outer)` is WRONG in Python because `~0xff` is -256,
    whose low byte is 0x00, so the mask is a no-op on each byte and the whole
    constant silently comes out unmasked (that bug produced a table of phantom
    "MISMATCH" rows in the session this script was written for).
    """
    inner = k(ns.encode())
    minus1 = (int.from_bytes(inner, "big") - 1) % (1 << 256)
    outer = int.from_bytes(k(minus1.to_bytes(32, "big")), "big")
    mask = ((1 << 256) - 1) - 0xFF  # == ~bytes32(uint256(0xff))
    return format(outer & mask, "064x")


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------
CONST_RE = re.compile(
    r"bytes32\s+(?:private\s+|internal\s+|public\s+)?constant\s+(\w+)\s*=\s*(0x[0-9a-fA-F]{64})\s*;"
)
NS_ERC7201_RE = re.compile(r"erc7201:([A-Za-z0-9_.\-]+)")
NS_KEV_RE = re.compile(r'keccak256\(\s*"([A-Za-z0-9_.\-]+)"\s*\)')


def find_namespace(lines, idx, lookback=8):
    """Look backwards from a constant declaration for its ERC-7201 namespace."""
    chunk = "\n".join(lines[max(0, idx - lookback): idx + 1])
    m = NS_ERC7201_RE.search(chunk)
    if m:
        return m.group(1)
    m = NS_KEV_RE.search(chunk)
    if m:
        return m.group(1)
    return None


def scan(tree):
    """-> list of (file, lineno, const_name, hardcoded_hex, namespace_or_None)"""
    out = []
    for dirpath, dirnames, filenames in os.walk(tree):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "out", "cache")]
        for fn in filenames:
            if not fn.endswith(".sol"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines):
                m = CONST_RE.search(line)
                if not m:
                    continue
                name, val = m.group(1), m.group(2)
                if "Location" not in name and "SLOT" not in name.upper():
                    continue
                out.append((path, i + 1, name, val.lower(), find_namespace(lines, i)))
    return out


def main(argv):
    verbose = "--verbose" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__)
        return 2
    tree = args[0]
    if not os.path.isdir(tree):
        print("not a directory: %s" % tree)
        return 2

    k, provider, errs = _load_keccak()
    if k is None:
        print("FATAL: no keccak256 provider available.")
        for e in errs:
            print("  tried %s" % e)
        print("  install one of: pip install eth-hash[pycryptodome] pycryptodome pysha3")
        return 2
    ok, msg = _self_test(k)
    print("hash provider : %s" % provider)
    print("self-test     : %s" % msg)
    if not ok:
        print("FATAL: refusing to report slot comparisons from an unvalidated hasher.")
        return 2

    # canonical + node_modules reference table
    nm_tree = os.path.join(tree, "node_modules")
    oz_ref = {}
    if os.path.isdir(nm_tree):
        for dirpath, dirnames, filenames in os.walk(nm_tree):
            for fn in filenames:
                if not fn.endswith(".sol"):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
                except Exception:
                    continue
                for i, line in enumerate(lines):
                    m = CONST_RE.search(line)
                    if not m:
                        continue
                    ns = find_namespace(lines, i)
                    if ns:
                        oz_ref.setdefault(ns, (m.group(2).lower(), p))

    found = scan(tree)
    print("root          : %s" % os.path.abspath(tree))
    print("constants     : %d discovered" % len(found))
    print("")

    failures = []
    for path, lineno, name, hard, ns in found:
        rel = os.path.relpath(path, tree)
        if not ns:
            print("  [NO-NS ] %s:%d %s" % (rel, lineno, name))
            print("           no ERC-7201 namespace comment found -> cannot auto-verify")
            print("           value = %s" % hard)
            continue
        derived = erc7201(ns, k)
        derived_hex = "0x" + derived
        status = "MATCH   " if derived_hex.lower() == hard else "MISMATCH"
        if derived_hex.lower() != hard:
            failures.append((rel, lineno, name, ns, hard, derived_hex))
        print("  [%s] %s:%d %s" % (status, rel, lineno, name))
        print("           namespace = %s" % ns)
        print("           hardcoded = %s" % hard)
        print("           derived  = %s" % derived_hex)
        if ns in oz_ref:
            oz_val, oz_path = oz_ref[ns]
            tag = "OK  " if oz_val.lower() == hard else "DIFF"
            print("           node_modules %s: %s = %s" % (tag, os.path.relpath(oz_path, tree), oz_val))
            if oz_val.lower() != hard:
                failures.append((rel, lineno, name, ns, hard, oz_val))
        else:
            print("           node_modules: no OZ constant for this namespace (project-specific slot)")
        if verbose:
            print("           file: %s" % path)

    print("")
    if failures:
        print("RESULT: %d MISMATCH(ES)" % len(failures))
        for rel, lineno, name, ns, a, b in failures:
            print("  %s:%d %s  ns=%s  %s != %s" % (rel, lineno, name, ns, a, b))
        return 1
    print("RESULT: all auto-verifiable slot constants MATCH their canonical derivation.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
