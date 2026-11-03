#!/usr/bin/env python3
"""decode_ru.py <glob> — decode base64 redirect_url cookies from captured .hdr files.

Pitfall handled: the broker sometimes emits a literal '%3D' padding marker inside
the cookie value, which makes naive b64decode raise
"number of data characters (297) cannot be 1 more than a multiple of 4".
Strip %3D, then try pads 0-3 against both standard and urlsafe alphabets.

Usage: python3 decode_ru.py '*h1_t*'
"""
import base64
import glob
import os
import re
import sys

EV = os.environ.get("RT_EV", "/home/ubuntu/predator-recon/current/evidence/redteam")
pat = sys.argv[1] if len(sys.argv) > 1 else "*"


def dec(v):
    v = v.replace("%3D", "").replace("%3d", "")
    for pad in range(4):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return fn(v + "=" * pad).decode("utf-8", "replace")
            except Exception:
                pass
    return None


for f in sorted(glob.glob(os.path.join(EV, pat + ".hdr.txt"))):
    raw = open(f, errors="replace").read()
    vals = [v for v in re.findall(r"redirect_url=([^;\n]*)", raw) if v != "deleted"]
    print("==", os.path.basename(f).replace(".hdr.txt", ""))
    if not vals:
        print("    (no redirect_url set)")
    for v in vals:
        d = dec(v)
        print("    ", d if d else "UNDECODABLE len=%d" % len(v))
