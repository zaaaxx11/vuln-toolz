#!/usr/bin/env python3
"""Pre-auth route census for an Odoo source tree.

Usage: python3 route_census.py /path/to/odoo_src [out.json]

Prints the auth breakdown and the list of PRE-AUTH (auth='none'/'public') files.
Those files are the only ones worth reading for a pre-auth hunt. Also flags
raw-string SQL and Markup/Response sinks inside them.
"""
import collections
import json
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
OUT = sys.argv[2] if len(sys.argv) > 2 else "routes_preauth.json"

route_re = re.compile(r"@http\.route\((.*?)\)\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", re.S)
auth_re = re.compile(r"""auth\s*=\s*['"](none|public|user|bearer|calendar|outlook)['"]""")
type_re = re.compile(r"""type\s*=\s*['"](http|json)['"]""")

SQL_SINK = re.compile(r"(cr\.execute|_execute|SQL\()\s*\(?\s*(?:f['\"]|['\"].*?['\"]\s*[%+]|.*?\.format\()")
MARKUP_SINK = re.compile(r"Markup\s*\(|make_response\s*\(|Response\s*\(|\|\s*safe\b")
VARISH = re.compile(r"[%{]\s*\(?\s*[a-z_][a-z0-9_]*|\b(kw|kwargs|post|params|request\.params)\b")

routes = []
for base in ("odoo", "addons"):
    for dp, _dn, fn in os.walk(os.path.join(ROOT, base)):
        if "/tests" in dp or "/static/" in dp or "/i18n/" in dp:
            continue
        for f in fn:
            if not f.endswith(".py"):
                continue
            p = os.path.join(dp, f)
            try:
                src = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for m in route_re.finditer(src):
                deco, fname = m.group(1), m.group(2)
                am, tm = auth_re.search(deco), type_re.search(deco)
                paths = [x for x in re.findall(r"""['"]([^'"]+)['"]""", deco) if x.startswith("/")]
                routes.append(((am.group(1) if am else "user"), (tm.group(1) if tm else "http"),
                               fname, os.path.relpath(p, ROOT), paths[:3]))

print("== routes by auth ==")
for k, v in collections.Counter(r[0] for r in routes).most_common():
    print(f"  {k:10} {v}")

pre = [r for r in routes if r[0] in ("none", "public")]
files = sorted({r[3] for r in pre})
print(f"\n== PRE-AUTH routes: {len(pre)}  in {len(files)} files ==")

for tag, pat in (("SQLi", SQL_SINK), ("Markup/Response", MARKUP_SINK)):
    hits = []
    for rel in files:
        try:
            lines = open(os.path.join(ROOT, rel), encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines, 1):
            if pat.search(ln) and VARISH.search(ln):
                hits.append((rel, i, ln.strip()[:140]))
    print(f"\n== [{tag}] {len(hits)} candidate line(s) in pre-auth files ==")
    for rel, i, ln in hits[:30]:
        print(f"  {rel}:{i}: {ln}")

json.dump(pre, open(OUT, "w"), indent=1)
print(f"\nwrote {OUT}")
