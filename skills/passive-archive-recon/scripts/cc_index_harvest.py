#!/usr/bin/env python3
"""Harvest the Common Crawl URL index for a set of hosts across crawl IDs.

Usage:
  python3 cc_index_harvest.py <hosts.txt> <out.jsonl>

hosts.txt: one pattern per line, e.g.
  *.example.com
  www.example.com/*
  api.example.com/*

Writes deduped rows (urlkey, url, status, mime, filename, offset, length, _index).
Only talks to index.commoncrawl.org — passive.

Gotchas:
  * `*.sub.domain` and even `host/*` can 504 under load -> retry with backoff;
    a body of {"message":"No Captures found ..."} is a CLEAN NEGATIVE (not archived).
  * results are capped (~500/query); query multiple crawl IDs to widen coverage.
"""
import json, time, os, sys, urllib.request, urllib.parse

UA = "passive-recon"
INDICES = ["CC-MAIN-2026-39", "CC-MAIN-2026-34", "CC-MAIN-2026-30",
           "CC-MAIN-2026-25", "CC-MAIN-2026-21", "CC-MAIN-2026-17",
           "CC-MAIN-2025-30", "CC-MAIN-2025-13", "CC-MAIN-2024-51",
           "CC-MAIN-2023-50"]


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for a in range(5):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            time.sleep(4 + a * 4)
    return None


def main():
    hosts = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
    outpath = sys.argv[2]
    rows = []
    for idx in INDICES:
        for h in hosts:
            q = (f"https://index.commoncrawl.org/{idx}-index?url="
                 f"{urllib.parse.quote(h)}&output=json&limit=500")
            txt = get(q)
            if not txt:
                print(f"FAIL {idx} {h}", flush=True); continue
            if txt.strip().startswith("<html>") or "No Captures" in txt:
                print(f"none {idx} {h}", flush=True); continue
            n = 0
            for line in txt.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line); r["_index"] = idx; rows.append(r); n += 1
                except Exception:
                    pass
            print(f"ok   {idx} {h}: {n}", flush=True)
            time.sleep(1.5)
    seen, dedup = set(), []
    for r in rows:
        k = (r.get("url"), r.get("status"))
        if k in seen:
            continue
        seen.add(k); dedup.append(r)
    with open(outpath, "w") as f:
        for r in dedup:
            f.write(json.dumps(r) + "\n")
    print(f"TOTAL {len(rows)} dedup {len(dedup)} -> {outpath}", flush=True)


if __name__ == "__main__":
    main()
