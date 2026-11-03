#!/usr/bin/env python3
"""Paced payment-flow pre-auth probe harness.
Probes each flow endpoint with 4 shapes (GET, GET+Origin, OPTIONS preflight, POST {}),
paced at 1 req/sec, with an operator header. Benign payloads only; no real purchases.

Usage:
  python3 payment_probe.py <base_url> <endpoints_json_file> [operator_header]

endpoints_json_file: one JSON array of endpoint paths, e.g.
  ["/mgpg_phx/payment_methods", "/mgpg_phx/validate_captcha", "/pornhubx/init-purchase-flow-data"]

Writes request+response (headers + body[:1500]) per probe to evidence_payment_probe.txt.
"""
import subprocess, time, json, sys, os

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://www.pornhub.com"
EP_FILE = sys.argv[2] if len(sys.argv) > 2 else None
OPHDR = sys.argv[3] if len(sys.argv) > 3 else "X-Bug-Bounty: zaaaxx"
EVID = os.environ.get("EVID", "evidence_payment_probe.txt")

endpoints = json.load(open(EP_FILE)) if EP_FILE else []

def curl(method, url, extra=None, data=None, label=""):
    time.sleep(1.1)  # strict 1 req/sec pacing
    cmd = ["curl", "-sS", "-D", "-", "-o", "/tmp/pp_body.txt",
           "--max-time", "25", "-X", method, "-H", OPHDR]
    if extra: cmd += extra
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "--data", data]
    cmd += [url]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
    body = open("/tmp/pp_body.txt", encoding="utf-8", errors="replace").read()
    rec = f"\n##### {label}\n$ {' '.join(cmd)}\n--- HEADERS ---\n{out.stdout}\n--- BODY[:1500] ---\n{body[:1500]}\n"
    with open(EVID, "a") as f: f.write(rec)
    status = [l for l in out.stdout.splitlines() if l.lower().startswith("http/")]
    acao = [l for l in out.stdout.splitlines() if l.lower().startswith("access-control")]
    print(f"[{label}] {status[-1] if status else '??'} | ACAO: {acao} | body[:160]={body[:160]!r}")

with open(EVID, "w") as f:
    f.write(f"=== Payment-flow pre-auth probe ===\nBase: {BASE}\nOperator: {OPHDR}\nPacing: 1.1s/req. Benign payloads only.\n")

for ep in endpoints:
    url = BASE + ep
    curl("GET", url, label=f"GET {ep}")
    curl("GET", url, extra=["-H", "Origin: https://evil.com"], label=f"GET+Origin(evil.com) {ep}")
    curl("OPTIONS", url, extra=["-H", "Origin: https://evil.com",
                                "-H", "Access-Control-Request-Method: POST",
                                "-H", "Access-Control-Request-Headers: content-type"],
         label=f"OPTIONS-preflight {ep}")
    curl("POST", url, data="{}", extra=["-H", "Origin: https://evil.com"], label=f"POST{{}} {ep}")

print("\nDone. Evidence:", EVID)
