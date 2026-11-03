#!/usr/bin/env python3
"""Resolve an obfuscator.io string-array bundle into {index: literal} JSON.

Usage:
    deobfuscate_stringarray.py <bundle.js> <out.json> [--check "26408=handleOpenUrl" ...] [--static]

Why this exists
---------------
obfuscator.io turns every string literal into `someFn(12345)`. Grepping for a
method name like `openExternal` returns 0 hits even though the call exists,
because the identifier is computed: `this[e(26408)]`.

Method
------
1. Find `function NAME(){const|var|let VAR=[`  -> the array function.
   obfuscator.io emits `var` as often as `const`; matching only `const` fails
   on perfectly good bundles.
2. Bracket-match to the closing `]`, tracking quote/backtick/escape state.
   Do NOT stop at the first `}` -- template literals and nested objects contain
   braces and will truncate the array.
3. Find the decoder and its offset N. Two shapes:
       function DEC(i,e){return i=i-N,ARR()[i]}          (return form)
       function I(i,_){i=i-102;var E=N(),t=E[i];return t} (self-assignment form)
   The self-assignment form is the dangerous one -- keying only on the return
   form silently yields offset 0 and shifts every string by N.
4. Find the rotation IIFE `(function(i,e){const r=DEC,a=i(); ...})(ARRFN, seed)`.
5. **Execute** array + rotation in node to get the true runtime order, then emit
   {"N": "literal"} keyed by the index the code actually uses.
6. If node is unavailable (or --static), solve the rotation count k by
   brute-forcing the checksum IIFE in pure Python. The checksum calls
   `parseInt` on array elements, which obfuscator.io satisfies with
   pseudo-numeric tokens like `"313179jxAcMn"`, so the elements must be parsed
   with a leading-digit regex, not `int()`.

Why execution matters (the old limitation, now fixed)
-----------------------------------------------------
The bundle ends with a self-rotating IIFE:

    (function(i,e){const r=DEC,a=i();for(;;)try{ ...checksum... break;
        a.push(a.shift())}catch{a.push(a.shift())}})(ARRFN, 679827);

The loop mutates the array at load time. A pure literal parse is only correct by
luck. This script runs the real loop in node (the bundle's own code) and reads
the array afterwards, so the map is the runtime truth.

`--static` skips node and uses the literal order (fallback when node is absent).
Either way, pass `--check` for a few known index=value pairs: a silently shifted
map produces confident nonsense.

Every bundle has its OWN array function and its OWN offset -- resolve each file
(and each `*.js` in the asar) separately, never reuse a map across bundles.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile


def find_array_function(src: str):
    """Locate `function NAME(){const VAR=[` and return (name, start_of_bracket, fn_start)."""
    # `function NAME(){var VAR=[` -- obfuscator.io emits `var` as often as `const`
    # (Krisp's webWindowPreload.js used `function N(){var i=[...]`).
    for m in re.finditer(
        r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{\s*(?:const|var|let)\s+([A-Za-z_$][\w$]*)\s*=\s*\[", src
    ):
        return m.group(1), m.end() - 1, m.start()
    for m in re.finditer(
        r"([A-Za-z_$][\w$]*)\s*=\s*function\s*\(\s*\)\s*\{\s*(?:const|var|let)\s+([A-Za-z_$][\w$]*)\s*=\s*\[", src
    ):
        return m.group(1), m.end() - 1, m.start()
    return None, None, None


def match_bracket(src: str, start: int) -> int:
    """Return index of the `]` closing the `[` at `start`, quote-aware."""
    i, depth, quote, esc = start, 0, None, False
    while i < len(src):
        c = src[i]
        if quote:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                quote = None
        else:
            if c in "\"'`":
                quote = c
            elif c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise ValueError("unbalanced array literal")


def normalise(arr_txt: str) -> str:
    """Make a JS array literal parseable by json.loads (static fallback only).

    JS-only escapes that json.loads rejects: `\\'` (escaped single quote) and
    `\\x41`/`\\u{...}` forms. Krisp's preload.js contained `\\'` and made the
    naive `json.loads` raise "Expecting value: line 1 column 500".
    """
    t = arr_txt.replace("`", '"')
    t = t.replace("\\'", "'")                      # JS escaped single quote -> plain
    t = re.sub(r"(?<!\\)\n", r"\\n", t)
    t = re.sub(r"(?<!\\)\r", r"\\r", t)
    t = re.sub(r"(?<!\\)\t", r"\\t", t)
    return t


def split_top_level(arr_txt: str) -> list:
    """Split an array literal on top-level commas, quote/escape aware.

    Used when the literal still will not parse as JSON (mixed quote styles,
    stray control chars). Returns the raw element strings; the caller unquotes.
    """
    parts, buf, quote, esc, depth = [], "", None, False, 0
    for c in arr_txt:
        if quote:
            buf += c
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                quote = None
            continue
        if c in "\"'":
            quote = c; buf += c; continue
        if c == "[":
            depth += 1; buf += c; continue
        if c == "]":
            depth -= 1; buf += c; continue
        if c == "," and depth == 0:
            parts.append(buf); buf = ""; continue
        buf += c
    parts.append(buf)
    return [p for p in parts if p.strip()]


def unquote(el: str) -> str:
    """Unquote a single JS string element to a Python str."""
    p = el.strip()
    if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
        return json.loads(p)
    if len(p) >= 2 and p[0] == "'" and p[-1] == "'":
        body = p[1:-1].replace("\\'", "'").replace('"', '\\"')
        return json.loads('"' + body + '"')
    return p


def solve_rotation(src: str, arr: list, offset: int):
    """Brute-force the rotation count k when node is unavailable.

    The rotation loop is `a.push(a.shift())` -- each pass moves element 0 to the
    end, so after k passes the decoder's `arr[(n-off+k) % len]` is correct.
    The checksum IIFE pins k exactly:

        (function(i,e){for(var r=DEC,a=i();;)try{
            var o=-parseInt(r(589))/1+parseInt(r(355))/2*(-parseInt(r(430))/3)+...;
            if(o===e)break; a.push(a.shift())}catch{a.push(a.shift())}})(ARRFN, 918266)

    Key subtlety: the checksum calls `parseInt` on *array elements*, so the
    elements it indexes must be numeric-looking. obfuscator.io satisfies this
    with pseudo-random tokens like `"313179jxAcMn"` -> parseInt gives 313179.
    A plain `int(v)` fails on those; use the leading-digit parse below.
    """
    m = re.search(
        r"\(function\((\w+),(\w+)\)\{for\(var (\w+)=(\w+),(\w+)=\1\(\);;\)try\{var o=(.*?);if\(o===\2\)break;",
        src,
    )
    if not m:
        return None
    expr = m.group(6)
    seed = re.search(r"\}\)\(" + re.escape(m.group(1)) + r",(\d+)\)", src)
    if not seed:
        return None
    target = int(seed.group(1))
    toks = re.findall(r"([+-]?)\s*(?:parseInt\()?(\w+)\((\d+)\)\)?(?:/(\d+))?", expr)
    if not toks:
        return None

    def leading_int(v):
        if not isinstance(v, str):
            return float("nan")
        mm = re.match(r"\s*[+-]?\d+", v)
        return int(mm.group(0)) if mm else float("nan")

    n_arr = len(arr)
    for k in range(n_arr):
        vals, ok = [], True
        for _sign, _fn, num, _den in toks:
            v = leading_int(arr[(int(num) - offset + k) % n_arr])
            if v != v:
                ok = False
                break
            vals.append(v)
        if not ok:
            continue
        total = 0.0
        for (sign, _fn, _num, den), v in zip(toks, vals):
            d = int(den) if den else 1
            total += (-v if sign == "-" else v) / d
        if total == target:
            return k
    return None


def find_offset(src: str, arrfn: str) -> int:
    """Find the decoder's `i = i - N` shift.

    Two shapes exist. The self-assignment form is the one that bites:
        function I(i,_){i=i-102;var E=N(),t=E[i];return t}
    The first pattern (`return X = X - N`) does not match it, so the offset
    silently defaulted to 0 and every string came out shifted by 102.
    """
    # self-assignment inside the decoder body (most common in newer builds)
    for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*=\s*\1\s*-\s*(\d+)", src):
        return int(m.group(2))
    for m in re.finditer(r"return\s+[A-Za-z_$][\w$]*\s*=\s*[A-Za-z_$][\w$]*\s*-\s*(\d+)", src):
        return int(m.group(1))
    for m in re.finditer(
        r"=\s*([A-Za-z_$][\w$]*)\s*-\s*(\d+)\s*,\s*" + re.escape(arrfn) + r"\(\)", src
    ):
        return int(m.group(2))
    return 0


def find_rotation(src: str, arrfn: str):
    """Return (decoder_name, rotation_js) for `(function(i,e){const r=DEC,a=i(); ...})(ARRFN, seed);`."""
    m = re.search(r"\(function\(i,e\)\{const r=([A-Za-z_$][\w$]*),a=i\(\);", src)
    if not m:
        return None, None
    end = src.find("})(" + arrfn + ",", m.start())
    if end < 0:
        return m.group(1), None
    semi = src.find(");", end)
    if semi < 0:
        return m.group(1), None
    return m.group(1), src[m.start():semi + 2]


def extract_array_function(src: str, arrfn: str, fn_start: int, bracket_end: int) -> str:
    """Slice the whole array function, terminating on `<arrfn>()}` (not the first `}`)."""
    term = src.find(arrfn + "()}", bracket_end)
    if term < 0:
        raise ValueError("could not find array-function terminator '<arrfn>()}'")
    return src[fn_start:term + len(arrfn + "()}"]


def run_in_node(arr_fn_src: str, resolver: str, offset: int, arrfn: str, rot: str):
    """Execute array + rotation in node; return the final array (runtime truth)."""
    if shutil.which("node") is None:
        return None
    js = (
        arr_fn_src + "\n"
        + f"function {resolver}(i,e){{return i=i-{offset},{arrfn}()[i]}}\n"
        + (rot or "") + "\n"
        + f"process.stdout.write(JSON.stringify({arrfn}()));\n"
    )
    fd, tmp = tempfile.mkstemp(suffix=".js")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(js)
    try:
        r = subprocess.run(["node", tmp], capture_output=True, text=True, timeout=180)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def main() -> int:
    argv = sys.argv[1:]
    checks = []
    keep = []
    static_only = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--check" and i + 1 < len(argv):
            checks.append(argv[i + 1]); i += 2; continue
        if a.startswith("--check="):
            checks.append(a.split("=", 1)[1]); i += 1; continue
        if a == "--static":
            static_only = True; i += 1; continue
        keep.append(a); i += 1

    if len(keep) < 2:
        print(__doc__)
        return 2
    src_path, out_path = keep[0], keep[1]
    src = open(src_path, encoding="utf-8", errors="ignore").read()

    arrfn, bstart, fn_start = find_array_function(src)
    if not arrfn:
        print("ERROR: could not locate the string-array function", file=sys.stderr)
        return 1
    bend = match_bracket(src, bstart)
    offset = find_offset(src, arrfn)
    dec_name, rot = find_rotation(src, arrfn)

    arr = None
    mode = "static-literal"
    if not static_only:
        try:
            arr_fn_src = extract_array_function(src, arrfn, fn_start, bend)
            arr = run_in_node(arr_fn_src, dec_name or "DEC", offset, arrfn, rot)
            if arr is not None:
                mode = "node-rotated"
        except Exception as exc:  # noqa: BLE001 - fall back, never hard-fail here
            print(f"note: node rotation unavailable ({exc}); falling back", file=sys.stderr)

    if arr is None:
        arr_txt = src[bstart:bend + 1]
        try:
            arr = json.loads(normalise(arr_txt))
        except (json.JSONDecodeError, ValueError):
            # Mixed quote styles / stray control chars: split top-level and
            # unquote element by element.
            try:
                arr = [unquote(e) for e in split_top_level(arr_txt)]
                mode = "static-split"
            except Exception as exc:  # noqa: BLE001
                print(f"ERROR: could not parse the array literal ({exc})", file=sys.stderr)
                return 1

    if static_only or mode == "static-literal" or mode == "static-split":
        # The literal order is only correct if the rotation IIFE never ran.
        # Solve k from the checksum so the map matches runtime behaviour.
        n_arr0 = len(arr)
        k = solve_rotation(src, arr, offset)
        if k is not None:
            # `a.push(a.shift())` is a LEFT rotation: element 0 goes to the end.
            # After k passes, literal index i holds what was at (i+k) % n.
            # So the corrected array is arr[k:] + arr[:k] -- NOT arr[-k:]+arr[:-k],
            # which is the right-rotation mirror and yields a confidently wrong map.
            arr = arr[k % n_arr0:] + arr[: k % n_arr0] if k else arr
            mode += f"+rot{k}"
            print(f"rotation: solved k={k} from the checksum IIFE")
        else:
            print(
                "WARNING: could not solve the rotation count; the literal order may be wrong.\n"
                "        Pass --check with known index=value pairs to confirm.",
                file=sys.stderr,
            )

    mapping = {str(i + offset): v for i, v in enumerate(arr)}
    with open(out_path, "w") as fh:
        json.dump(mapping, fh)

    print(f"array fn : {arrfn}")
    print(f"decoder  : {dec_name}")
    print(f"strings  : {len(arr)}")
    print(f"offset   : -{offset}")
    print(f"mode     : {mode}")
    print(f"wrote    : {out_path}")

    if checks:
        bad = 0
        for c in checks:
            idx, _, expected = c.partition("=")
            got = mapping.get(idx)
            ok = got == expected
            bad += 0 if ok else 1
            print(f"  [{'OK ' if ok else 'BAD'}] ({idx}) expected={expected!r} got={got!r}")
        if bad:
            print(f"\n{bad} check(s) FAILED -- index map or rotation is wrong.", file=sys.stderr)
            print("Try --static to compare, and re-verify the decoder offset and array function.", file=sys.stderr)
            return 1
        print(f"all {len(checks)} check(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
