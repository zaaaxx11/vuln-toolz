#!/usr/bin/env python3
"""Generic paced read-only probe harness (<=1 request/second to any host).

Use for gateway route enumeration / bypass-class observation / host classification.
Sends NO credentials. Captures status + headers + body snippet.

Usage:
  python3 paced_probe.py paths  https://api.target.com / /api /api/v1 ...
  python3 paced_probe.py hosts  api.target.com www.target.com ...
  python3 paced_probe.py raw    https://api.target.com/api/..;/     # single explicit URL

Edit BASELINE-level extras (headers) below. Keep pace at >=1.05s. Do not add -L (never follow).
"""
import sys, time, subprocess, json

PACE = 1.05  # seconds between requests — DO NOT lower for real targets/third-party APIs
UA = "Mozilla/5.0 (compatible; recon/1.0)"
EXTRA = []  # e.g. ["-H","X-Forwarded-For: 127.0.0.1"] to test header trust

def probe(url):
    p = subprocess.run(
        ["curl", "-s", "-i", "--max-time", "15", "-o", "/dev/stdout",
         "-w", "\n@@@%{http_code}", "-H", f"User-Agent: {UA}"] + EXTRA + [url],
        capture_output=True, text=True)
    out = p.stdout
    body, _, code = out.rpartition("@@@")
    hdr = body.split("\r\n\r\n")[0] if "\r\n\r\n" in body else body
    tail = body.split("\r\n\r\n")[-1].replace("\n", " ")[:120]
    get = lambda k: next((l.strip() for l in hdr.split("\n") if l.lower().startswith(k)), "-")
    return code.strip(), get("server:"), get("location:"), get("www-authenticate:"), \
           ("cf-ray" in hdr.lower()), tail

def main():
    mode = sys.argv[1]
    rows = []
    if mode == "paths":
        base = sys.argv[2].rstrip("/")
        targets = [base + p for p in sys.argv[3:]]
    elif mode == "hosts":
        targets = ["https://" + h + "/" for h in sys.argv[2:]]
    elif mode == "raw":
        targets = sys.argv[2:]
    else:
        print(__doc__); return
    for i, url in enumerate(targets):
        code, srv, loc, wa, cf, tail = probe(url)
        print(f"{url}\t{code}\tsrv={srv}\tcf-ray={cf}\twa={wa}\tloc={loc[:70]}\tbody={tail}", flush=True)
        rows.append(dict(url=url, code=code, server=srv, location=loc, www_auth=wa, cf=cf, body=tail))
        if i < len(targets) - 1:
            time.sleep(PACE)
    json.dump(rows, open("/tmp/paced_probe_out.json", "w"), indent=1)
    print("\n[wrote /tmp/paced_probe_out.json]")

if __name__ == "__main__":
    main()
