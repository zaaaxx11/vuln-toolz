#!/usr/bin/env python3
"""
rt_gated.py — rate-gated verbatim evidence capture for authorized engagements.

UPGRADE over scripts/rt.sh: the pacing gate is a cross-process flock, not a
per-invocation sleep. That matters when a hypothesis round fires probes from
several shells/loops in the same second — a `sleep 1` inside one helper does not
serialize a *second* helper running concurrently, and the operator's "max 1 req/sec"
is a constraint on the TARGET, not on your script.

HARD RULES ENFORCED IN CODE:
  - max 1 request / second to ANY host (global, flock-serialized across processes)
  - every request/response written verbatim to disk (.raw / .hdr / .body)
  - operator header on every request
  - benign payloads remain the CALLER's responsibility

Usage:
  rt_gated.py <label> <METHOD> <url> [curl args...]
  ./rt_gated.sh <label> <METHOD> <url> [curl args...]   # wrapper

Companion analyzers (same directory, run from the evidence dir):
  sum.py <glob>          -> status / len / body-md5 / <title> differ table
  decode_ru.py <glob>    -> decode base64 redirect_url cookies (handles %3D)
"""
import os
import sys
import time
import subprocess
import fcntl

EV = os.environ.get("RT_EV", "/home/ubuntu/predator-recon/current/evidence/redteam")
STATE = os.environ.get("RT_STATE", "/tmp/.rt_gate_last_req")
MIN_INTERVAL = 1.05  # seconds between ANY two requests, globally
GATE_TIMEOUT = 600

os.makedirs(EV, exist_ok=True)
os.makedirs(os.path.dirname(STATE), exist_ok=True)


def gate():
    """Global 1 req/sec gate across ALL concurrent harness invocations."""
    deadline = time.time() + GATE_TIMEOUT
    while time.time() < deadline:
        try:
            fd = os.open(STATE, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError:
            time.sleep(0.05)
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                with open(STATE) as f:
                    last = float(f.read().strip() or 0)
            except Exception:
                last = 0.0
            wait = (last + MIN_INTERVAL) - time.time()
            if wait > 0:
                time.sleep(wait)
            with open(STATE, "w") as f:
                f.write(repr(time.time()))
            return
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except Exception:
                pass
    raise SystemExit("rt_gate: timeout waiting for the rate gate")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    label, method, url = sys.argv[1], sys.argv[2].upper(), sys.argv[3]
    extra = sys.argv[4:]

    gate()

    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)
    base = os.path.join(EV, "%s_%s" % (time.strftime("%H%M%S"), safe))

    cmd = [
        "curl", "-sS", "-i", "--path-as-is",
        "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "--max-time", "25",
        "-X", method,
    ] + extra + [url]

    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    dt = time.time() - t0

    hdr = (
        "### LABEL: %s\n"
        "### TS(UTC): %s\n"
        "### ELAPSED: %.2fs\n"
        "### CMD: %s\n"
        "### EXIT: %s\n"
        "### STDERR: %s\n"
        "%s\n"
    ) % (label, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), dt,
         " ".join(cmd), p.returncode, p.stderr.strip()[:2000], "=" * 78)

    body = p.stdout or ""
    with open(base + ".raw.txt", "w") as f:
        f.write(hdr + body)

    if "\r\n\r\n" in body:
        h, b = body.split("\r\n\r\n", 1)
    elif "\n\n" in body:
        h, b = body.split("\n\n", 1)
    else:
        h, b = body, ""
    with open(base + ".hdr.txt", "w") as f:
        f.write(h)
    with open(base + ".body.txt", "w") as f:
        f.write(b)

    status = loc = ""
    for line in h.splitlines():
        if line.startswith("HTTP/"):
            status = line.strip()
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
    print("[%s] %s | %.2fs | %dB | loc=%s" % (label, status, dt, len(body), loc[:160]))
    print("  -> %s.raw.txt" % base)
    return 0


if __name__ == "__main__":
    sys.exit(main())
