#!/usr/bin/env python3
"""De-obfuscate a Nuxt `window.__NUXT__=(function(a,b,...){return {...}})(...args)` blob.

Nuxt ships its full runtime config in the HTML, but obfuscates values into the IIFE
parameters (e.g. `mulesoftApiClientSecret:z`). This maps params->args so you recover
the REAL value instead of the literal `z`.

Usage:
  python3 resolve_nuxt_state.py <file.html> [key1 key2 ...]

With no keys, prints every resolved value that looks secret/URL-ish. Also base64-decodes
`"eyJ..."` values (Nuxt base64-encodes many nested config objects).
"""
import re, json, base64, sys


def normalize(t: str) -> str:
    return t.replace("\\u002F", "/").replace("\\/", "/")


def split_top(s: str):
    """Split a JS argument list on top-level commas (respect strings + brackets)."""
    out, depth, cur, instr, esc = [], 0, "", None, False
    for c in s:
        if instr:
            cur += c
            if esc: esc = False
            elif c == "\\": esc = True
            elif c == instr: instr = None
        else:
            if c in "\"'": instr = c; cur += c
            elif c in "([{": depth += 1; cur += c
            elif c in ")]}": depth -= 1; cur += c
            elif c == "," and depth == 0: out.append(cur.strip()); cur = ""
            else: cur += c
    if cur.strip(): out.append(cur.strip())
    return out


def match_block(txt, i, open_c, close_c):
    """Return index of the close char matching txt[i]==open_c, skipping strings."""
    depth, instr, esc = 0, None, False
    while i < len(txt):
        c = txt[i]
        if instr:
            if esc: esc = False
            elif c == "\\": esc = True
            elif c == instr: instr = None
        else:
            if c in "\"'": instr = c
            elif c == open_c: depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0: return i
        i += 1
    return -1


def dequote(s):
    return s[1:-1] if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0] else s


def maybe_b64(v):
    s = dequote(v.strip())
    if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", s) and s.startswith("eyJ"):
        try:
            return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
        except Exception:
            return None
    return None


def main():
    raw = normalize(open(sys.argv[1], encoding="utf-8", errors="replace").read())
    keys = sys.argv[2:]

    start = raw.find("(function(")
    if start < 0:
        print("no __NUXT__ IIFE found", file=sys.stderr); return
    pclose = raw.index("){", start)
    params = [p.strip() for p in raw[start + len("(function("):pclose].split(",")]

    ridx = raw.index("return {", pclose)
    brace = raw.index("{", ridx)
    end_brace = match_block(raw, brace, "{", "}")
    body = raw[brace + 1:end_brace]

    after = raw[end_brace + 1:]
    ai = after.index("(")
    args_str = after[ai + 1:match_block(after, ai, "(", ")")]
    args = split_top(args_str)
    mapping = dict(zip(params, args))
    print(f"# params={len(params)} args={len(args)}", file=sys.stderr)

    pairs = re.findall(
        r'[,{]([A-Za-z][A-Za-z0-9_]{2,60}):("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[A-Za-z_$][A-Za-z0-9_$]{0,3})',
        body)
    seen = {}
    for k, v in pairs:
        seen.setdefault(k, v)

    for k, v in sorted(seen.items()):
        if keys and k not in keys:
            continue
        if not keys and not re.search(r"client|secret|key|token|passw|url|host|endpoint|id$", k, re.I):
            continue
        if v in mapping:                       # obfuscated -> resolve
            real = dequote(mapping[v])
            src = f"  (var {v})"
        else:
            real = dequote(v)
            src = ""
        dec = maybe_b64(real)
        if dec is not None:
            print(f"### {k} (b64-decoded):\n{dec}\n")
        else:
            print(f"{k} = {real}{src}")


if __name__ == "__main__":
    main()
