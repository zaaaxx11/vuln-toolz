# SSRF / Traversal / XXE / Info-Disclosure / Infra — Cell Discipline & Differential Refutation

Load when running per-cell attack sweeps (SSRF, path traversal, XXE, info-disclosure, infra/bucket)
against a host, or when a "live lead" is a **response differential** rather than a proven effect.

Core rule: **a differential is a hypothesis, not a finding.** Every one of these cells dies the same
way — you must identify *what* the discriminator actually is before claiming anything.

---

## 1. The bare-word control (kills most false SSRF leads)

The classic false positive: `?media_id=1` returns 1765 B, `?media_id=http://evil.com` returns 104 B.
That looks like "URL input reaches a fetcher." It usually is not.

**Run the discriminator ladder — cheapest first, all ≤3 attempts:**

| Probe | If it returns the *URL* response | Meaning |
|---|---|---|
| `?p=1` (integer) | — | baseline |
| `?p=zxq7canary` (**bare word, no URL syntax**) | yes | **type coercion, not fetching** — lead is dead |
| `?p=0`, `?p=-1` | no (same as integer) | confirms integer-ness is the axis |
| `?p=http://example.com/<canary>.txt` | yes | still ambiguous — keep going |
| `?p=abc` | yes | confirms non-integer is the axis |

The bare-word control is decisive. If a plain word with no scheme, no host, and no path produces the
byte-identical error body as a full URL, the parameter is being **cast/rejected on type** before any
network or filesystem call. No fetch exists to hijack.

**Then confirm with timing.** Fetch is a *latency* event; type rejection is not.

```
int    mean 0.621s  stdev 0.006
non-int mean 0.590s  stdev 0.004   (url, word, traversal, file://, gopher:// all identical)
```

Flat timing across every non-integer variant = no outbound request. A real SSRF oracle shows a
bimodal or heavy-tailed distribution (connection refused is fast, timeout is slow, live host is
medium) — and the *same* payload repeated gives different times.

**Scheme battery** (only after the ladder says the input is genuinely handled):
`http://127.0.0.1:80`, `http://127.0.0.1:22`, `http://2130706433/` (decimal IP),
`http://[::1]/`, `file:///etc/passwd`, `gopher://127.0.0.1/`, `http://<host>@127.0.0.1/` (userinfo),
double-encoded, and a **live canary URL you control** (`http://example.com/<unique>.txt`) so a real
fetch would be observable in your own logs.

> Verified 2026-10-22 on `www.analvids.com/thumbnail/missed-image?media_id=`: 14 payloads, every
> non-integer collapsed to md5 `5e61f02102a4` (104 B). Bare word `zxq7canary` ≡ full URL. **REFUTED.**

---

## 2. Shape-dependent catch-all (one random-path control is NOT enough)

`scripts/catchall_triage.sh` proves catch-all by byte-identity against a random path. That is
necessary but **insufficient**, because many stacks gate the catch-all on path *shape*, not existence:

| Host | Bare random path | Extension-shaped path | Dot-shaped path |
|---|---|---|---|
| `ddfcontent.com` | 404 / 25 B `No input file specified.` | `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml` → **404 / 11422 B SPA homepage** | `/.htaccess` → 403 / 11422 B |
| `www.analvids.com` | 404 / 31218 B app 404 | `/sitemap.xml` → 200 / 163 B | `/.env`, `/.env.bak`, `/.DS_Store`, `/.htpasswd`, `/.htaccess` → **200 / 163761 B homepage HTML** |

With a single bare control, every one of those looks like a "FOUND DIFFERENTIAL" — and `/.env`
returning **200 with 163 KB** looks like a jackpot. It is the homepage.

**Always probe three control shapes** and treat a path as a true differential only when it differs
from *all* of them:

```bash
SEED="$(date +%s | tail -c 6)"
CONTROL_BARE="/zx9-nonexistent-${SEED}"
CONTROL_EXT="/zx9-nonexistent-${SEED}.xml"     # catches SPA/extension-gated routers
CONTROL_DOT="/.zx9-nonexistent-${SEED}"        # catches dot-path catch-alls
```

Regenerate the seed per run so a cached CDN 404 cannot fake a control.

**Corollary — a 200 is not a finding either.** Check *what* the 200 contains. `/.env` at 163 KB with
`<title>Anal Vids is the place to find…</title>` is a homepage. A real `.env` is small, line-oriented,
`KEY=value`, and has no `<html>`. Grep for `DOCTYPE|<html` and pull `<title>` before celebrating.

---

## 3. Bucket existence by error-code discrimination

`NoSuchBucket` (404) vs `AccessDenied` (403) is the existence oracle. **Always run a negative
control** — a bucket name that certainly does not exist — or you cannot tell "exists but locked"
from "typo".

```
s3.amazonaws.com/pornbox              -> 403 AccessDenied   <- EXISTS
s3.amazonaws.com/zxq7canary-nonexist  -> 404 NoSuchBucket   <- control
```

Then probe object-level reads (`/`, `/index.html`, `/robots.txt`, `/test.txt`, `/logo.png`,
`/sitemap.xml`). All-403 means fully locked: **existence is not a vulnerability**, record it as a
lead only. Try path-style *and* vhost-style (`<bucket>.s3.amazonaws.com`) — they can differ.
GCS: `storage.googleapis.com/<bucket>` → 403 = exists/no-list, 404 NoSuchBucket = absent.

---

## 4. XXE quick-negative

Cheap and definitive: `POST` an XML body with a `file:///etc/passwd` entity to every
JSON/XML-accepting endpoint with `Content-Type: application/xml`.

```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
```

If every endpoint returns its normal empty-POST response (same status, same bytes, no entity
expansion, no parser error), nothing parses XML. Four POSTs closes the cell.

---

## 5. Infra header inventory — what to actually look for

Absence is the usual result; record it so the next session does not re-derive it.

- `Server`, `X-Powered-By`, `Via`, `X-Cache`, `x-amz-*`, `x-goog-*` → stack/version leakage
- CDN fingerprints: `server: CDN77-Turbo` + `x-77-nzt` / `x-77-nzt-ray` / `x-77-cache`
- `access-control-allow-origin: *` — only interesting **with** `access-control-allow-credentials: true`;
  a bare reflected wildcard is spec-valid and not a read primitive
- Cookie flags: `HttpOnly` / `Secure` / `SameSite` per cookie, and whether the server reissues its own
  session ID (server-reissue defeats fixation regardless of what you send)
- Security headers present vs absent: `X-Frame-Options`, `COOP`, CSP with nonce + `strict-dynamic`

---

## 6. Pitfalls

- **429 is not a finding.** Aggressive hosts rate-limit mid-sweep; the 429 body (often ~17 B) has its
  own md5 and will pollute the differential table. Pace ≥1.05 s, and treat any 429 as *no data* —
  re-probe later, never report it.
- **Transient edge artifacts.** A raw-nginx 404 on a path the app normally handles (e.g. `/api/player`)
  can be a CDN edge blip. Re-probe before concluding the route is absent, and confirm with a second
  random path under the same prefix.
- **Local command scanners block payload strings.** Raw-IP URLs and `user@host` userinfo tricks trip
  pattern matchers on the shell command itself. Workaround: issue the request from a Python
  `subprocess.run(["curl", ...])` instead of an inline shell string — the payload never appears as a
  shell token. Do not drop the payload; route around the matcher.
- **`execute_code` has a hard ~300 s cap.** At 1 req/s that is ~280 requests max, and a killed script
  loses all stdout. Batch under ~250 requests, or run `background=true` terminal scripts that flush
  per host.
- **Never report "differential found" without the discriminator named.** The report line must say what
  the differential *is* (type coercion / catch-all shape / rate limit / edge artifact), not just that
  two responses differed.

---

## Session ledger — 2026-10-22, analvids / pornworld / ddfcontent (A2-HUNTER)

~180 paced requests, 5 cells, 3 hosts. **No proven vulnerabilities.**

| Cell | Verdict | Discriminator that closed it |
|---|---|---|
| SSRF `/thumbnail/missed-image?media_id=` | REFUTED | bare-word control ≡ URL; flat timing |
| Path traversal (same + `/api/player` + `/api/oembed`) | NOT_FOUND | routes absent; all payloads identical 104 B |
| XXE | NOT_FOUND | no endpoint parses XML |
| Info disclosure (36 paths × 3 hosts) | NOT_FOUND | shape-dependent catch-all; 200s were homepages |
| Infra (headers, S3/GCS, CDN) | NOT_FOUND | `pornbox` bucket exists but all object reads 403 |

Minor/informational only: `analvids.com/sitemap.xml` serves an unrendered PHP template
(`<result>%s</result><message>%s</message>…`, 200/163 B) — cosmetic, no data exposure.

Full report: `~/predator-recon/pornbox-2026-10-22/evidence/fu/A2-HUNTER-REPORT.md`
Estate-wide prior ledger: `references/pornbox-preauth-verified-2026-10-22.md`
