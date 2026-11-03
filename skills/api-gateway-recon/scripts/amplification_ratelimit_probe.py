#!/usr/bin/env python3
"""N-item amplification + rate-limit-absence battery (read-only, paced, hard-capped).

Reports the number a report actually needs: wall time per N, marginal cost per item, response
bytes per item, egress amplification, and whether any 429 / X-RateLimit-* appeared on a burst.

  # amplification across N (template must contain the literal marker __CMDS__)
  python3 amplification_ratelimit_probe.py \
      --url https://app.royco.org/api/v1/decoder/decode \
      --template-file body.json --sizes 1,10,50,100 \
      --cmd 0xa9059cbb0000 --cmd 0xd0e30db0 --origin https://app.royco.org

  # rate-limit absence only
  python3 amplification_ratelimit_probe.py --url https://app.royco.org/api/rpc/1 \
      --template-file rpc_blocknumber.json --sizes none --burst 10

body.json / rpc_blocknumber.json are small JSON files with __CMDS__ where the repeated items go
(e.g. {"script":{"commands":[__CMDS__],"state":["0x"]},"chainId":1}).

Design rules baked in (learned the hard way):
  * ALWAYS sample several N — a single N cannot separate a fixed RTT floor from per-item cost.
  * Marginal cost = (t_max - t_min) / (n_max - n_min). Flat within noise => ~1.0x, i.e. NO
    amplification; say "no CPU amplification, egress Nx" instead of inventing a DoS.
  * Quote the item shape next to the numbers: a degenerate item (unknown selector, zero address)
    short-circuits locally and will always look flat. A flat run on a degenerate body refutes
    nothing about the resolving path.
  * Burst is SERIAL on purpose. Never raise concurrency to "confirm" a DoS you are warning about.
  * MAX_REQUESTS is a hard stop so a typo cannot become the attack.
"""
import argparse, json, sys, time, urllib.request, urllib.error

MAX_REQUESTS = 40


def build_body(template, cmds):
    return template.replace("__CMDS__", ",".join(cmds))


def call(url, body_text, origin, timeout):
    data = body_text.encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    if origin:
        req.add_header("origin", origin)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        raw, code, hdrs = r.read(), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        raw, code, hdrs = e.read(), e.code, dict(e.headers)
    except Exception as e:  # network/timeout — keep it visible, do not silently drop
        return None, time.time() - t0, 0, {}, repr(e)
    return code, time.time() - t0, len(raw), hdrs, raw


def rl_headers(h):
    return {k: v for k, v in h.items()
            if k.lower().startswith(("x-ratelimit", "ratelimit", "retry-after"))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--template-file", required=True)
    ap.add_argument("--cmd", action="append", default=[])
    ap.add_argument("--sizes", default="1,10,50,100")
    ap.add_argument("--burst", type=int, default=10)
    ap.add_argument("--origin", default="")
    ap.add_argument("--pause", type=float, default=1.1, help="seconds between requests (<=1 req/s)")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--max-items", type=int, default=100, help="hard cap on items per request")
    a = ap.parse_args()

    template = open(a.template_file, encoding="utf8").read()
    sent = 0

    def fire(cmds):
        nonlocal sent
        if sent >= MAX_REQUESTS:
            sys.exit(f"stopping: MAX_REQUESTS={MAX_REQUESTS} reached")
        sent += 1
        return call(a.url, build_body(template, cmds), a.origin, a.timeout)

    rows = []
    if a.sizes.strip().lower() != "none":
        for n in [int(x) for x in a.sizes.split(",") if x.strip()]:
            n = min(n, a.max_items)
            cmds = [a.cmd[i % len(a.cmd)] for i in range(n)] if a.cmd else []
            code, dt, ln, hdrs, raw = fire(cmds)
            rows.append((n, code, dt, ln))
            print(f"N={n:<4} code={code} wall={dt:7.3f}s bytes={ln:>8} "
                  f"B/item={(ln / n) if n else 0:8.1f} rl={rl_headers(hdrs)}", flush=True)
            time.sleep(a.pause)

        ok = [r for r in rows if isinstance(r[1], int)]
        if len(ok) >= 2:
            (n1, _, t1, _), (n2, _, t2, _) = ok[0], ok[-1]
            if n2 != n1:
                marg = (t2 - t1) / (n2 - n1)
                print(f"\nmarginal cost per item = {marg * 1000:.4f} ms  "
                      f"(baseline RTT floor ~{t1:.3f}s at N={n1})")
                print("amplification factor = %.2fx server-seconds per request-second"
                      % (max(t2, 0.001) / max(t1, 0.001)))
                print("NB: flat wall time => ~1.0x => NO CPU amplification; report egress "
                      "separately and describe the item shape used.")

    if a.burst:
        print(f"\nburstrom: {a.burst} identical requests, serial, pause={a.pause}s")
        codes, rlh = [], set()
        for i in range(a.burst):
            code, dt, ln, hdrs, raw = fire([a.cmd[0]] if a.cmd else [])
            codes.append(code)
            rlh |= set(rl_headers(hdrs))
            print(f"  #{i} code={code} wall={dt:6.3f}s", flush=True)
            if i < a.burst - 1:
                time.sleep(a.pause)
        print(f"codes={codes}")
        print("429 seen: %s | rate-limit headers: %s"
              % (429 in codes, rlh or "NONE"))
        print("state it as SERIAL, not concurrent — that is the finding, not a load test.")


if __name__ == "__main__":
    main()
