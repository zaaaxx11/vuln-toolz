#!/usr/bin/env python3
"""
build_selector_from_artifact.py — build a call's selector + calldata from the COMPILED ARTIFACT.

Why: hand-writing a Solidity signature for a struct-heavy function produces selectors that
silently do not exist in the deployed bytecode. Three different hand-built signatures for
`execute(request, callResolver, callResolverData, oracle, signature)` gave
0x9d79c526 / 0xba028c6e / 0x5a8351d1 — none present in the target — which read as
"the live contract is a different version" and nearly produced a Critical on the wrong contract.
The artifact is the ground truth for the type list.

Usage:
  python3 build_selector_from_artifact.py <artifact.json> <functionName>
  python3 build_selector_from_artifact.py out/RelayExecutor.sol/RelayExecutor.json execute

  # encode calldata too (pass args as JSON on stdin):
  echo '{"request": [...]}' | python3 build_selector_from_artifact.py art.json execute --encode

Notes:
  * struct components are flattened recursively: tuple -> (t1,t2,...)
  * tuple[] -> (t1,t2)[] is emitted correctly by type_string()
  * ALWAYS then verify the selector exists in live bytecode:
        eth_getCode(target) and check `sel in code` — but remember a PUSH4/PUSH3 scan is a
        HYPOTHESIS, not proof (compilers also emit selectors as shr(224,...) compares).
        Ground truth = source-verified explorer source, or a real tx's calldata.
"""
import json
import sys

try:
    from eth_utils import keccak
except ImportError:
    sys.exit("pip install eth-utils")


def type_string(inp):
    """Recursively flatten a struct component into a canonical ABI type string."""
    t = inp["type"]
    if t.startswith("tuple"):
        suffix = t[len("tuple"):]          # "", "[]", "[2]", "[][3]" ...
        inner = ",".join(type_string(c) for c in inp.get("components", []))
        return "(" + inner + ")" + suffix
    return t


def build(artifact_path, fn_name):
    abi = json.load(open(artifact_path))["abi"]
    for f in abi:
        if f.get("type") == "function" and f.get("name") == fn_name:
            sig = f["name"] + "(" + ",".join(type_string(i) for i in f["inputs"]) + ")"
            sel = "0x" + keccak(text=sig)[:4].hex()
            return sig, sel, f
    raise SystemExit(f"function {fn_name!r} not found in artifact")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    art, fn = sys.argv[1], sys.argv[2]
    sig, sel, spec = build(art, fn)

    print(f"signature : {sig}")
    print(f"selector  : {sel}")
    print(f"inputs    : {[(i['name'], type_string(i)) for i in spec['inputs']]}")
    print()
    print("NEXT: verify against live bytecode, and remember a bytecode scan is a hypothesis:")
    print("  eth_getCode(target) -> check sel; if absent, compare len(deployedBytecode) vs artifact")
    print("  equal size + working sibling getters  => same contract, YOUR SIGNATURE IS WRONG")
    print("  different size                        => genuinely a different deployment, stop")

    if "--encode" in sys.argv:
        from eth_abi import encode as abi_encode
        args = json.load(sys.stdin)
        types = [type_string(i) for i in spec["inputs"]]
        print()
        print("calldata  : " + sel + abi_encode(types, args).hex())


if __name__ == "__main__":
    main()
