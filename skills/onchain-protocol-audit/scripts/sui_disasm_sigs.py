#!/usr/bin/env python3
"""
Extract public/entry function signatures + capability structs from Sui Move
bytecode disassembly (v6) saved as JSON from the Sui GraphQL endpoint.

WHY THIS EXISTS
  The public Sui GraphQL endpoint's `package{modules{nodes{name}}}` resolver
  returns the WRONG package's module list. `module(name:){disassembly}` is
  accurate. This script parses those saved disassembly blobs.

  Also: Move disassembly has NO `fun` keyword. Functions are
  `public <name>(...)` / `entry <name>(...)`, with generics AFTER the name:
  `public new_adl_params<Ty0>(Arg0: &AdminCap, ...)`. A naive
  `re.findall(r'public fun', ...)` returns 0 matches.

USAGE
  # 1. fetch a module's disassembly (accurate resolver)
  curl -s -X POST https://graphql.mainnet.sui.io/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ package(address:\"0xPKG\"){ module(name:\"MOD\"){ name disassembly } } }"}' \
    -o modules/PKG_MOD.json

  # 2. extract
  python3 sui_disasm_sigs.py modules/*.json            # all files
  python3 sui_disasm_sigs.py modules/PKG_admin.json    # one file
  python3 sui_disasm_sigs.py modules/*.json --caps     # capability structs only
  python3 sui_disasm_sigs.py modules/*.json --grep AdminCap

  NOTE: do NOT pipe curl into this script (security scanner blocks
  `curl | interpreter`). Save to a file first -- that also gives you the
  evidence artefact.
"""
import json
import re
import sys
import glob

# `public|entry <name><generics>(` -- generics sit between name and paren
FUN_RE = re.compile(r'^(public|entry) ([A-Za-z0-9_]+)(<[^>]*>)?', re.M)
STRUCT_RE = re.compile(r'^struct ([A-Za-z0-9_]+) has ([^{]+)\{', re.M)
MODULE_RE = re.compile(r'^module ([0-9a-f]{64})\.([A-Za-z0-9_]+) \{', re.M)


def balanced_args(dis, start):
    """Scan a balanced paren group. `[^)]*` FAILS on `Option<String>`,
    `&Market<Ty0>`, and nested generics."""
    if start >= len(dis) or dis[start] != '(':
        return None
    depth, i = 1, start + 1
    while i < len(dis) and depth:
        depth += (dis[i] == '(') - (dis[i] == ')')
        i += 1
    return re.sub(r'\s+', ' ', dis[start + 1:i - 1])


def parse(path):
    with open(path, encoding='utf-8') as fh:
        d = json.load(fh)
    pkg = d.get('data', {}).get('package')
    if not pkg or not pkg.get('module'):
        return None
    mod = pkg['module']
    dis = mod.get('disassembly') or ''
    m = MODULE_RE.search(dis)
    declared_pkg, declared_mod = (m.group(1), m.group(2)) if m else ('?', mod.get('name'))

    funs = []
    for mm in FUN_RE.finditer(dis):
        args = balanced_args(dis, mm.end())
        if args is None:
            continue  # not a function declaration
        funs.append((mm.group(1), mm.group(2) + (mm.group(3) or ''), args))

    caps = [(sm.group(1), sm.group(2).strip())
            for sm in STRUCT_RE.finditer(dis)
            if re.search(r'(AdminCap|UpgradeCap|CallerCap|OwnerCap|Treasury|Cap)', sm.group(1))]

    return {
        'file': path,
        'name': mod.get('name'),
        'declared_pkg': declared_pkg,
        'declared_mod': declared_mod,
        'funs': funs,
        'caps': caps,
        'dis': dis,
    }


def main(argv):
    args = [a for a in argv[1:] if not a.startswith('--')]
    caps_only = '--caps' in argv
    grep = None
    if '--grep' in argv:
        grep = argv[argv.index('--grep') + 1]

    paths = []
    for a in (args or []):
        paths.extend(sorted(glob.glob(a)) or [a])

    for p in paths:
        r = parse(p)
        if not r:
            print(f"### EMPTY / no module field: {p}")
            continue
        if grep:
            for kind, name, a in r['funs']:
                if grep.lower() in name.lower() or grep.lower() in a.lower():
                    print(f"{r['declared_pkg'][:10]}::{r['name']:26} [{kind}] {name}({a})")
            continue
        print('=' * 78)
        print(f"FILE: {r['file']}")
        print(f"MODULE: {r['name']}  (declared: {r['declared_pkg']}.{r['declared_mod']})")
        print(f"public/entry funs: {len(r['funs'])}")
        if r['caps'] and not caps_only:
            print("capability structs:")
            for n, ab in r['caps']:
                print(f"    struct {n} has {ab}")
        if caps_only:
            for n, ab in r['caps']:
                print(f"    struct {n} has {ab}")
            continue
        for kind, name, a in r['funs']:
            print(f"  [{kind}] {name}({a})")


if __name__ == '__main__':
    main(sys.argv)
