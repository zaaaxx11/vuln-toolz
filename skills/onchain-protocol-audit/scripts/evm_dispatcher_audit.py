#!/usr/bin/env python3
"""EVM live-bytecode dispatcher audit.

Fetches runtime bytecode for an address, decodes the opcode stream, extracts the
real Solidity dispatcher table (PUSH4 <sel> EQ|GT|LT|SLT PUSH2 <tgt> JUMPI), and
VALIDATES every jump target against genuine JUMPDEST positions.

The validation step is the whole point: a selector in the dispatcher table is NOT
evidence that the function is callable. A JUMPI to a non-JUMPDEST cannot be taken,
so those branches are dead code. Skipping this check turns "vestigial selector
table" into a fabricated "N hidden entrypoints" CRITICAL.

See references/bytecode-dispatcher-forensics.md for the method and interpretation
rules (which three claims must stay strictly apart).

Usage:
    python3 evm_dispatcher_audit.py --rpc https://rpc.example --addr 0xAbC...
    python3 evm_dispatcher_audit.py --rpc ... --addr ... --abi out/RelayHub.sol/RelayHub.json
    python3 evm_dispatcher_audit.py --file /tmp/live.hex --abi ...   # offline

Exit codes:
    0  ran clean; 2  invalid jump targets found (review them, do NOT call them hidden);
    3  transport/decode failure (nothing was concluded).
"""

import argparse
import json
import subprocess
import sys

# ---------------------------------------------------------------- opcode tables
CMP_OPS = {0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ"}
OP_NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x07: "SMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL",
    0x1C: "SHR", 0x1D: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE",
    0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
    0x3B: "EXTCODESIZE", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
    0x5A: "GAS", 0x5B: "JUMPDEST", 0xA0: "LOG0", 0xA1: "LOG1", 0xA2: "LOG2",
    0xA3: "LOG3", 0xA4: "LOG4", 0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}


def rpc(url, method, params, timeout=60):
    """POST via curl to a temp file. Large eth_getCode payloads must not go
    through a size-capped stdout channel (see census ref 9c)."""
    import tempfile, os
    req = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, req)
    req.close()
    out = req.name + ".out"
    try:
        subprocess.run(
            ["curl", "-s", "-m", str(timeout), "-X", "POST", url,
             "-H", "Content-Type: application/json", "--data", "@" + req.name, "-o", out],
            check=True,
        )
        with open(out) as f:
            body = f.read()
        if not body:
            raise RuntimeError("empty response body (transport, not decode)")
        return json.loads(body)
    finally:
        for p in (req.name, out):
            try:
                os.unlink(p)
            except OSError:
                pass


def disassemble(code_hex):
    """Linear sweep. Returns [(pc, name_or_int, imm_hex_or_None)]."""
    raw = code_hex.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        B = bytes.fromhex(raw)
    except ValueError as e:
        raise RuntimeError(f"bad hex in bytecode: {e}")
    ins, i = [], 0
    while i < len(B):
        op = B[i]
        if 0x60 <= op <= 0x7F:                      # PUSH1..PUSH32
            n = op - 0x5F
            ins.append((i, f"PUSH{n}", B[i + 1:i + 1 + n].hex()))
            i += 1 + n
        else:
            ins.append((i, op, None))
            i += 1
    return ins


def extract_dispatcher(ins):
    """PUSH4 <sel> followed within 2 instrs by a comparison opcode."""
    d = {pc: (nm, imm) for pc, nm, imm in ins}
    found = {}
    for idx, (pc, nm, imm) in enumerate(ins):
        if nm == "PUSH4" and imm and imm != "00000000":
            for j in range(idx + 1, min(idx + 3, len(ins))):
                o = ins[j][1]
                if isinstance(o, int) and o in CMP_OPS:
                    entry = (pc, CMP_OPS[o])
                    # prefer the first (lowest-pc) occurrence for a given selector
                    found.setdefault(imm, entry)
                    break
    return found, d


def validate_targets(ins, d):
    """Return (good, bad) where each item is (selector, target_int).
    Requires the canonical EQ PUSH2 <tgt> JUMPI tail after the PUSH4."""
    jumpdests = {pc for pc, op, _ in ins if op == 0x5B}
    good, bad = [], []
    for pc, nm, imm in ins:
        if nm != "PUSH4" or not imm:
            continue
        eq = d.get(pc + 5, (None,))[0]
        push2 = d.get(pc + 6, (None, None))
        jumpi = d.get(pc + 9, (None,))[0]
        if eq == 0x14 and push2[0] == "PUSH2" and jumpi == 0x57:
            tgt = int(push2[1], 16)
            (good if tgt in jumpdests else bad).append((imm, tgt))
    return good, bad, jumpdests


def load_repo_abi(path):
    """Map selector -> signature from a Foundry artifact or a bare ABI list."""
    blob = json.load(open(path))
    abi = blob["abi"] if isinstance(blob, dict) and "abi" in blob else blob
    from eth_utils import keccak
    out = {}
    for item in abi:
        if item.get("type") != "function":
            continue
        def t(io):
            ty = io.get("type", "")
            if ty.startswith("tuple"):
                inner = ",".join(t(c) for c in io.get("components", []))
                return f"({inner})" + ty[len("tuple"):]
            return ty
        sig = f"{item['name']}({','.join(t(i) for i in item.get('inputs', []))})"
        out[keccak(text=sig)[:4].hex()] = sig
    return out


def resolve_names(selectors):
    """Best-effort cast 4byte. Misses are UNKNOWN, not hidden."""
    names = {}
    for s in selectors:
        try:
            r = subprocess.run(["cast", "4byte", s], capture_output=True, text=True, timeout=20)
            line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            names[s] = line or "(unknown)"
        except Exception:
            names[s] = "(unknown)"
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc")
    ap.add_argument("--addr")
    ap.add_argument("--file", help="offline: path to a file containing runtime hex")
    ap.add_argument("--abi", help="Foundry artifact JSON or ABI list to diff against")
    ap.add_argument("--json-out")
    a = ap.parse_args()

    try:
        if a.file:
            code = open(a.file).read()
        elif a.rpc and a.addr:
            r = rpc(a.rpc, "eth_getCode", [a.addr, "latest"])
            if "result" not in r:
                print(f"eth_getCode failed: {r.get('error')}", file=sys.stderr)
                return 3
            code = r["result"]
        else:
            print("need --file or (--rpc and --addr)", file=sys.stderr)
            return 3

        ins = disassemble(code)
    except RuntimeError as e:
        print(f"FAILED (nothing concluded): {e}", file=sys.stderr)
        return 3

    if len(code.strip()) <= 2:
        print("address has NO CODE (codesize 0) — not a contract", file=sys.stderr)
        return 3

    disp, d = extract_dispatcher(ins)
    good, bad, jumpdests = validate_targets(ins, d)

    print(f"bytecode bytes         : {(len(code.strip()) - 2) // 2}")
    print(f"instructions           : {len(ins)}")
    print(f"valid JUMPDESTs        : {len(jumpdests)}")
    print(f"dispatcher selectors   : {len(disp)}")
    print(f"  jump target VALID    : {len(good)}")
    print(f"  jump target INVALID  : {len(bad)}   <-- dead branches")

    bad_sel = {s for s, _ in bad}
    good_sel = {s for s, _ in good}
    all_sel = sorted(bad_sel | good_sel)
    names = resolve_names(all_sel)

    repo = load_repo_abi(a.abi) if a.abi else None

    if bad:
        print("\n=== DEAD BRANCHES (JUMPI target is NOT a JUMPDEST) ===")
        print("These are NOT callable. Do not report them as hidden entrypoints.")
        for s, tgt in sorted(bad):
            print(f"  {s}  {names.get(s,'(unknown)'):48s} -> 0x{tgt:04x}")

    if repo is not None:
        live_all = set(all_sel)
        not_in_repo = sorted(live_all - set(repo))
        repo_absent = sorted(set(repo) - live_all)
        print(f"\n=== DIFF vs repo ABI ({a.abi}) ===")
        print(f"live selectors   : {len(live_all)}")
        print(f"matched to repo  : {len(live_all & set(repo))}")
        print(f"live-only        : {len(not_in_repo)}  (of which DEAD: {len([s for s in not_in_repo if s in bad_sel])})")
        print(f"repo-only        : {len(repo_absent)}")
        if not_in_repo:
            print("\n  live-only:")
            for s in not_in_repo:
                tag = "DEAD" if s in bad_sel else "LIVE"
                print(f"    [{tag:4s}] {s}  {names.get(s,'(unknown)')}")
        if repo_absent:
            print("\n  repo-only (absent from live dispatcher):")
            for s in repo_absent:
                print(f"    {s}  {repo[s]}")

    if a.json_out:
        json.dump({
            "valid": sorted(good), "invalid": sorted(bad),
            "selectors": all_sel, "names": names,
            "not_in_repo": not_in_repo if repo is not None else None,
            "repo_absent": repo_absent if repo is not None else None,
        }, open(a.json_out, "w"), indent=1)
        print(f"\nwrote {a.json_out}")

    print("\nREMINDER: a selector table entry is a hypothesis. Only a valid JUMPDEST")
    print("target + a succeeding eth_call is evidence. Localise claim strength:")
    print("  'bytecode != repo build'  <- selector diff + dead branches + slot drift")
    print("  'hidden callable function' <- requires a succeeding behavioural call")
    return 2 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
