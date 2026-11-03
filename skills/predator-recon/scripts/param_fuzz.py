#!/usr/bin/env python3
"""
param_fuzz.py — paced pre-auth parameter-surface fuzzer with evidence capture.

Reusable harness for "edge-bombard the parameter surface, find divergences from
baseline" rounds. Pacing is enforced IN CODE (hard 1 req/sec + jitter), never by
the caller's discipline. Every request writes a numbered raw evidence file
containing the full request, full response, and a curl repro line.

USAGE
-----
  # 1. Edit TARGETS below (endpoint -> param list, numeric params flagged).
  # 2. Run in the BACKGROUND — a paced sweep of ~700 requests takes ~15 min and
  #    will be killed if run inline:
  python3 param_fuzz.py > sweep.log 2>&1 &
  # 3. Analyse:
  python3 param_fuzz_analyze.py results.jsonl

DESIGN RULES (do not "optimise" these away)
-------------------------------------------
* ONE request at a time, `time.sleep(1.05 + jitter)` before every call. No
  threads, no connection pooling reuse across the pace gate, no retries.
* Baseline AND a no-match control per endpoint. The baseline is NOT the
  reference — the control is. See references/param-surface-fuzzing.md.
* Raw md5 of the body is recorded but NEVER used as the divergence signal.
  Frameworks rotate per-request tokens; see the normalizer.
* Benign payloads only. The variant set is type/edge-case confusion
  (empty, null, 0, -1, huge, unicode, overlong, encoded, double-encoded,
  boolean, float) plus one canary string for reflection checks. No exploit
  strings, no shell, no volumetric loops.
* Evidence file per request: request line, headers, body, response status,
  headers, body (capped), md5, and a copy-pasteable curl repro.
"""
import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.parse

import requests

requests.packages.urllib3.disable_warnings()

# --------------------------------------------------------------------------
# CONFIG — edit per engagement
# --------------------------------------------------------------------------
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# endpoint group -> (url, [params], {numeric params}, extra headers)
# extra headers is where you put engagement cookies (e.g. a browser-pin bypass).
TARGETS = {
    # "forum/search.php": ("https://forum.example.com/search.php",
    #                      ["keywords", "author", "t"],
    #                      {"t"}, {}),
}

BENIGN = "zxq7benign"        # benign value that should NOT match anything
CONTROL = "zzqqxx7nomatch"   # plain non-matching control value
CANARY = "ZXQ7CANARY"        # reflection canary

VARIANTS = [
    ("empty",   ""),
    ("null",   "null"),
    ("zero",   "0"),
    ("neg1",   "-1"),
    ("bignum", "999999999"),
    ("rtl",    "\u0627\u0644\u0639\u0631\u0628\u064a\u0629"),   # Arabic
    ("long200", "A" * 200),
    ("enc",    "%2e%2e%2f"),
    ("dblenc", "%252e%252e%252f"),
    ("canary", CANARY),
]
NUM_VARIANTS = [("true", "true"), ("1e9", "1e9")]

METHODS = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "DELETE", "TRACE"]
HDR_PROBES = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "canary.invalid"),
    ("X-Original-URL", "/canary"),
    ("X-Rewrite-URL", "/canary"),
    ("Forwarded", "for=canary.invalid;host=canary.invalid"),
    ("X-Host", "canary.invalid"),
    ("X-Custom-Canary", CANARY),
    ("Referer", "https://canary.invalid/"),
    ("Origin", "https://canary.invalid"),
]
CONTENT_TYPES = [
    ("application/x-www-form-urlencoded", "q=" + BENIGN),
    ("application/json", '{"q":"%s"}' % BENIGN),
    ("text/plain", "q=" + BENIGN),
    ("application/xml", "<q>%s</q>" % BENIGN),
]

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.S | re.I)


# --------------------------------------------------------------------------
class Pacer:
    """Hard global request-rate limiter."""

    def __init__(self, interval=1.05, jitter=0.12):
        self.interval = interval
        self.jitter = jitter
        self._last = 0.0

    def wait(self):
        now = time.time()
        remaining = self.interval - (now - self._last)
        if remaining > 0:
            time.sleep(remaining + random.uniform(0, self.jitter))
        self._last = time.time()


class Fuzzer:
    def __init__(self, outdir, pace_interval=1.05, verbose=True):
        self.outdir = outdir
        self.evdir = os.path.join(outdir, "evidence")
        os.makedirs(self.evdir, exist_ok=True)
        self.pacer = Pacer(pace_interval)
        self.verbose = verbose
        self.results = []
        self._n = 0
        self.session = requests.Session()

    # -- evidence ---------------------------------------------------------
    def _curl(self, method, url, headers, body):
        parts = ["curl -sk -X", method, "-m", "20"]
        for k, v in headers.items():
            if k.lower() == "accept-encoding":
                continue
            parts += ["-H", "'%s: %s'" % (k, v.replace("'", "'\\''"))]
        if body:
            parts += ["--data-binary", "'%s'" % body.replace("'", "'\\''")]
        parts.append("'%s'" % url)
        return " ".join(parts)

    def _write_evidence(self, rec, headers, raw, rhdr, cookies):
        fn = os.path.join(self.evdir, "fuzz_%04d_%s.txt" % (
            rec["n"], re.sub(r"[^A-Za-z0-9_.-]+", "_", rec["tag"])[:70]))
        with open(fn, "w") as f:
            f.write("### PARAM-FUZZ EVIDENCE  #%d\n" % rec["n"])
            f.write("TAG: %s\nNOTE: %s\n\n===== REQUEST =====\n" % (rec["tag"], rec["note"]))
            f.write("%s %s HTTP/1.1\nHost: %s\n" % (
                rec["method"], rec["full"], rec["url"].split("/")[2]))
            for k, v in headers.items():
                if k != "Host":
                    f.write("%s: %s\n" % (k, v))
            if cookies:
                f.write("Cookie: %s\n" % "; ".join("%s=%s" % kv for kv in cookies.items()))
            if rec["body"]:
                f.write("\n%s\n" % rec["body"])
            f.write("\n===== RESPONSE =====\nHTTP %s   (%.2fs)\n" % (rec["status"], rec["dt"]))
            for k, v in rhdr.items():
                f.write("%s: %s\n" % (k, v))
            f.write("\n--- BODY (%d bytes, md5=%s) ---\n" % (len(raw), rec["md5"]))
            txt = raw.decode("utf-8", "replace")
            f.write(txt[:20000])
            if len(txt) > 20000:
                f.write("\n...[truncated, %d total bytes]" % len(txt))
            f.write("\n\n===== REPRO =====\n%s\n" %
                    self._curl(rec["method"], rec["full"], headers, rec["body"]))
        return fn

    # -- one paced request ------------------------------------------------
    def probe(self, tag, method, url, params=None, headers=None, body=None,
              ctype=None, cookies=None, note="", allow_redirects=False):
        self.pacer.wait()
        h = {"User-Agent": UA, "Accept": "*/*",
             "Accept-Language": "en-US,en;q=0.9",
             "Accept-Encoding": "gzip, deflate, br", "Connection": "close"}
        if headers:
            h.update(headers)
        if ctype:
            h["Content-Type"] = ctype
        ck = dict(cookies or {})

        self._n += 1
        full = url
        if params:
            full = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params, safe="[]%")

        t0 = time.time()
        err = ""
        try:
            r = self.session.request(method, url, params=params, data=body,
                                     headers=h, cookies=ck, timeout=20,
                                     verify=False, allow_redirects=allow_redirects)
            status, raw, rhdr = r.status_code, r.content, dict(r.headers)
        except Exception as e:                                  # noqa: BLE001
            status, raw, rhdr = 0, b"", {}
            err = "%s: %s" % (type(e).__name__, str(e)[:160])
        dt = round(time.time() - t0, 2)

        if raw[:2] == b"\x1f\x8b":                               # gzip magic
            try:
                import gzip
                raw = gzip.decompress(raw)
            except Exception:                                   # noqa: BLE001
                pass

        m = TITLE_RE.search(raw)
        title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:120] if m else ""

        rec = dict(n=self._n, tag=tag, method=method, url=url, full=full,
                   params=params or {}, body=body or "", status=status,
                   title=title, size=len(raw),
                   md5=hashlib.md5(raw).hexdigest(),
                   location=(rhdr.get("Location") or rhdr.get("location") or "")[:300],
                   setcookie=(rhdr.get("Set-Cookie") or rhdr.get("set-cookie") or "")[:300],
                   server=rhdr.get("Server", ""), dt=dt, err=err, note=note,
                   evidence=self._write_evidence(rec, h, raw, rhdr, ck))
        self.results.append(rec)
        if self.verbose:
            print("  [%04d] %-52s %-4s %-7s %s" % (
                rec["n"], tag[:52], rec["status"], rec["size"],
                rec["title"][:44]), flush=True)
        return rec

    # -- phase 1: parameter variants --------------------------------------
    def param_set(self, group, url, params, numeric=(), cookies=None,
                  extra_headers=None):
        prim = params[0]
        self.probe("%s|BASELINE" % group, "GET", url,
                   params={prim: BENIGN}, cookies=cookies,
                   headers=extra_headers, note="baseline benign on %s" % prim)
        self.probe("%s|CONTROL" % group, "GET", url,
                   params={prim: CONTROL}, cookies=cookies,
                   headers=extra_headers, note="no-match control on %s" % prim)
        for p in params:
            vs = list(VARIANTS) + (list(NUM_VARIANTS) if p in numeric else [])
            for vname, vval in vs:
                self.probe("%s|%s=%s" % (group, p, vname), "GET", url,
                           params={p: vval}, cookies=cookies,
                           headers=extra_headers,
                           note="variant %s on %s" % (vname, p))

    # -- phase 2a: method confusion ---------------------------------------
    def method_set(self, group, url, cookies=None, extra_headers=None):
        for m in METHODS:
            b = "q=%s" % BENIGN if m in ("POST", "PUT") else None
            self.probe("METHOD|%s|%s" % (group, m), m, url, body=b,
                       ctype="application/x-www-form-urlencoded" if b else None,
                       cookies=cookies, headers=extra_headers,
                       note="method confusion %s" % m)

    # -- phase 2b: header probes ------------------------------------------
    def header_set(self, group, url, cookies=None):
        for hn, hv in HDR_PROBES:
            self.probe("HDR|%s|%s" % (group, hn), "GET", url,
                       headers={hn: hv}, cookies=cookies,
                       note="header %s: %s" % (hn, hv))

    # -- phase 2c: content-type confusion ---------------------------------
    def ctype_set(self, group, url, cookies=None):
        for ct, bd in CONTENT_TYPES:
            self.probe("CT|%s|%s" % (group, ct.split(";")[0]), "POST", url,
                       body=bd, ctype=ct, cookies=cookies,
                       note="content-type %s" % ct)

    def save(self, path):
        with open(path, "w") as f:
            for r in self.results:
                f.write(json.dumps(r) + "\n")
        print("saved %d records -> %s" % (len(self.results), path), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="paramfuzz_out")
    ap.add_argument("--pace", type=float, default=1.05)
    ap.add_argument("--phase", default="params",
                    choices=["params", "methods", "headers", "ctypes", "all"])
    args = ap.parse_args()

    if not TARGETS:
        print("Edit TARGETS in this script first.", file=sys.stderr)
        return 2

    fz = Fuzzer(args.out, args.pace)
    for group, (url, params, numeric, extra) in TARGETS.items():
        print("== %s" % group, flush=True)
        if args.phase in ("params", "all"):
            fz.param_set(group, url, params, numeric, extra_headers=extra)
        if args.phase in ("methods", "all"):
            fz.method_set(group, url, extra_headers=extra)
        if args.phase in ("headers", "all"):
            fz.header_set(group, url)
        if args.phase in ("ctypes", "all"):
            fz.ctype_set(group, url)
    fz.save(os.path.join(args.out, "results.jsonl"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
