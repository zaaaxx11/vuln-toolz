#!/usr/bin/env python3
"""Extract API route literals from a .NET/Blazor WASM assembly.

Why this exists: the biggest finding of a 9-round corporate estate hunt came from
extracting 351 route literals out of a 4.7 MB Blazor app assembly and sweeping them —
113 endpoints answered HTTP 200 to an anonymous client, including employee records
with ASP.NET Identity password hashes. See
references/blazor-wasm-and-dotnet-api-recon.md §3b.

.NET metadata user-strings are UTF-16LE, so plain `strings` finds almost nothing.

Usage:
    # 1. fetch the assembly (gzip form; check `file` before parsing — without
    #    Accept-Encoding the server may hand back the SPA fallback HTML instead)
    curl -s -H 'Accept: application/wasm' -H 'Accept-Encoding: gzip' \
         -o App.wasm https://host/_framework/App.wasm
    file App.wasm                       # "gzip compressed data" or "WebAssembly binary"

    # 2. decompress if needed, then extract
    gunzip -c App.wasm > App.bin 2>/dev/null || cp App.wasm App.bin
    python3 wasm_route_extract.py App.bin [--min-len 4] [--prefix api]

Output: one route per line on stdout, sorted. Pipe into a paced prober:
    python3 wasm_route_extract.py App.bin > routes.txt
    # then sweep with scripts/paced_probe.py (<=1 req/sec)
"""
import re
import sys


def extract(path: str, min_len: int = 4, prefix: str = "api") -> list:
    data = open(path, "rb").read()
    # .NET user-string heap is UTF-16LE; latin-1 pass catches ASCII-only literals.
    found = set()
    for enc in ("utf-16-le", "latin-1"):
        s = data.decode(enc, errors="ignore")
        for m in re.findall(r"[\x20-\x7e]{%d,220}" % min_len, s):
            if re.match(r"^/?%s/" % re.escape(prefix), m, re.I):
                found.add(m.strip())
    return sorted(found)


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 1
    path = args[0]
    min_len = 4
    prefix = "api"
    for a in sys.argv[1:]:
        if a.startswith("--min-len="):
            min_len = int(a.split("=", 1)[1])
        if a.startswith("--prefix="):
            prefix = a.split("=", 1)[1]
    routes = extract(path, min_len, prefix)
    for r in routes:
        print(r)
    print("# %d routes from %s" % (len(routes), path), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
