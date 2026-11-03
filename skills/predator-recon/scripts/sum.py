#!/usr/bin/env python3
"""sum.py <glob> — status / body-len / body-md5 / <title> differ table over evidence files.

Discriminates catch-all hosts and refutation outcomes: on a catch-all every body
md5 is identical, so the table proves the host is closed instead of assuming it.
Usage: python3 sum.py '*h1_t*'      (run from the evidence dir, or set RT_EV)
"""
import glob
import hashlib
import os
import re
import sys

EV = os.environ.get("RT_EV", "/home/ubuntu/predator-recon/current/evidence/redteam")
pat = sys.argv[1] if len(sys.argv) > 1 else "*"
files = sorted(glob.glob(os.path.join(EV, pat + ".raw.txt")))


def title(b):
    m = re.search(r"<title[^>]*>(.*?)</title>", b, re.S | re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else ""


print("%-46s %-14s %7s %-8s %s" % ("LABEL", "STATUS", "LEN", "BODYMD5", "TITLE"))
print("-" * 120)
for fp in files:
    label = os.path.basename(fp).replace(".raw.txt", "")
    raw = open(fp, errors="replace").read()
    idx = raw.find("=" * 78)
    if idx != -1:
        raw = raw[idx + 79:]
    if "\r\n\r\n" in raw:
        h, b = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        h, b = raw.split("\n\n", 1)
    else:
        h, b = raw, ""
    status = loc = ""
    for line in h.splitlines():
        if line.startswith("HTTP/"):
            status = line.strip()
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
    md5 = hashlib.md5(b.encode("utf-8", "replace")).hexdigest()[:8]
    print("%-46s %-14s %7d %-8s %s" % (label, status, len(b), md5, title(b)))
    if loc:
        print("%-46s   LOC: %s" % ("", loc[:150]))
