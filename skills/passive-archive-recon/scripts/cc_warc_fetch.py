#!/usr/bin/env python3
"""Fetch Common Crawl WARC records by byte-range and extract the HTTP body.

Usage:
  python3 cc_warc_fetch.py <cc-rows.jsonl> <outdir>

Each input line is a CC index JSON row with keys: url, filename, offset, length,
status (optionally _index). Only talks to data.commoncrawl.org — passive.

Key gotchas handled:
  * range returns MULTIPLE gzip members -> decompress only the FIRST member
  * the decompressed blob is WARC headers + HTTP headers + body -> strip both
"""
import json, sys, os, zlib, urllib.request, hashlib, re

UA = "passive-recon"  # set to your program UA if one is required


def decompress_first_member(raw: bytes) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip container
    try:
        out = d.decompress(raw) + d.flush()
    except Exception:
        out = b""
    return out


def fetch_record(filename, offset, length, timeout=120):
    url = f"https://data.commoncrawl.org/{filename}"
    start = int(offset)
    end = start + int(length) + 200000  # generous; server truncates at object end
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Range": f"bytes={start}-{end-1}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return decompress_first_member(raw)


def strip_headers(warc_bytes):
    i = warc_bytes.find(b"\r\n\r\n")           # end of WARC header block
    if i < 0:
        return warc_bytes, ""
    rest = warc_bytes[i + 4:]
    j = rest.find(b"\r\n\r\n")                 # end of HTTP header block
    body = rest[j + 4:] if j >= 0 else rest
    return body, warc_bytes[:i].decode("utf-8", "replace")


def main():
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    manifest = []
    for r in rows:
        try:
            data = fetch_record(r["filename"], r["offset"], r["length"])
            body, wh = strip_headers(data)
            sha = hashlib.sha256(body).hexdigest()
            base = re.sub(r"[^A-Za-z0-9._-]", "_", r["url"])[-90:]
            path = os.path.join(outdir, base)
            with open(path, "wb") as f:
                f.write(body)
            print(f"OK  {r['url']} -> {base} ({len(body)}b) sha256={sha[:16]}")
            manifest.append({"url": r["url"], "path": path, "size": len(body),
                             "sha256": sha, "status": r.get("status"),
                             "index": r.get("_index"), "warc": wh})
        except Exception as e:
            print(f"FAIL {r.get('url')}: {e}")
    with open(os.path.join(outdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()
