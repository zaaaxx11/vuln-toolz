# CDN-edge disposition triage — deciding live / dead / hiding for a batch of dev+staging hosts

Use when handed a **short list of dev/staging subdomains** (4–10 names) and asked "map what is
reachable, find pre-auth exposure, capture evidence". The failure mode of this task is not missing a
bug — it is **mislabeling a dead host as a mystery** ("maybe it's gRPC", "maybe it's a non-HTTP
service") and burning the budget grinding it, or conversely declaring "nothing" on a host whose
negative you did not actually prove.

Two disciplines kill both failure modes: **timeout-calibrated edge reading** and
**byte-identity catch-all proof**.

---

## 1. The 40-second rule (the highest-value lesson)

On a Cloudflare-fronted host, a short client timeout **silently fabricates a mystery**.

```
curl -m 15 / -m 25   →  curl: (28) Operation timed out ... 0 bytes received
                         TLS handshake fine, subject/issuer correct, verify code 0
```

That looks like: a hang, a non-HTTP protocol, a gRPC endpoint, a broken origin, a "service that
never speaks first". I initially wrote "could be a gRPC/non-HTTP service" — wrong. At **40–45 s**
Cloudflare gives up on the origin first and emits its own error page:

```
HTTP/2 522
server: cloudflare
<body>error code: 522</body>     ← 16 bytes
```

**Rule: never classify a CF-fronted host from a sub-30s timeout.** Re-run the single failing host
with `-m 45`. A real 522/524/521 lands as a clean verdict instead of an unbounded mystery. Ordering
matters: cheap 12–15 s probes for the mass sweep, then one 45 s confirmation for each host that came
back empty.

Corollary: `tls=0` / `verify return code: 0` on a host that returns zero bytes proves **the edge and
cert are fine**, so the failure is origin-side — not a DNS or TLS problem. Say that in the report.

---

## 2. Cloudflare edge error codes as host-disposition verdicts

| Edge response | Body | Meaning | Verdict | Action |
|---|---|---|---|---|
| `522` | `error code: 522` (16 B) | CF connected to *nothing*; origin TCP connect timed out | **ERROR — origin dead** | Re-check later; valid cert ⇒ intended to be live |
| `530` + `error code: 1016` | `error code: 1016` (17 B) | **Origin DNS error** — CF resolved the proxied origin name and it **does not resolve** | **ERROR — dangling origin** | Subdomain-takeover *candidate* (see caveat) |
| `503` + nginx padding comments | `<center><h1>503 Service Temporarily Unavailable</h1></center>` + `<!-- a padding to disable MSIE and Chrome friendly error page -->` ×5 | **Real origin nginx is alive**, every upstream/vhost backend is down | **NOTHING — but re-check target** | Highest-value recheck: front end provisioned, one deploy from exposure |
| `301` identical on every path | 134 B nginx/CF 301 page | catch-all redirect stub, no app | **NOTHING** | Follow the chain (see §4) |
| `1016`/`530` on a *non-root* path too | same 17 B | consistent edge failure, not path routing | **ERROR** | — |

**Discriminating a real origin 5xx from a CF-generated one:** CF's own error pages are tiny
(`error code: NNN`, 16–17 bytes) and carry no HTML wrapper. An origin page has real HTML — and the
**`<!-- a padding to disable MSIE and Chrome friendly error page -->` repeated-comment block is an
nginx signature you will not see from Cloudflare's edge**. That single difference decides whether the
host is "edge can't reach origin" (dead) or "origin up, app down" (recheck tomorrow).

**1016 caveat, state it honestly:** because the name is proxied, `dig` returns only the Cloudflare
anycast IPs — **the origin CNAME target is unobservable from the edge**. So 1016 proves the origin
record is broken, but **cannot** by itself prove the target is claimable by a third party. Record it
as *takeover candidate pending origin identification* (passive DNS / historical certs), never as a
confirmed takeover. Getting this wrong is how a report gets bounced.

---

## 3. Catch-all proof by byte-identity (generalizes the SPA-shell pitfall)

The SKILL's existing catch-all pitfall uses **body size** (9-byte SPA shell) to discriminate. That
generalizes: on a **redirect stub (301) or a dead-upstream stub (503)** the status code is constant
too, so use a **random-path control plus an md5 of the body**.

Protocol per host:

1. `GET /zx9-nonexistent-4471` (a random path that cannot exist) → record status + `md5(body)`.
2. `GET` each attack path — `/.env`, `/actuator`, `/config.js`, `/robots.txt`, `/api/health`,
   `/openapi.json` → record status + `md5(body)`.
3. **All md5s identical to the control ⇒ proven catch-all ⇒ no differential exists ⇒ host is
   closed.** The control is the whole argument: `/.env` returning the *same bytes* as a random path
   is positive proof that path-name does not influence the response.
4. Any md5 **differing** from the control ⇒ a real route — that is the lead, chase it.

Worked output (6 paths each, one `md5` per host = whole verdict):

```
dev.naorisprotocol.com        /  /random  /.env  /actuator  /robots.txt  /api/health
                              all → 301, md5 ffab428d2113   ⇒ CATCH-ALL, nothing
dev-smartspy...com            /  /random  /.env  /actuator/env  /config.js  /openapi.json
                              all → 503, md5 5a0434684914   ⇒ CATCH-ALL, nothing
```

Without the control you would have six `503`s and no way to claim `/.env` isn't served. With it the
negative is defensible and cheap (12 requests for two hosts).

**Report shape:** name the catch-all fingerprint explicitly (status + body md5 + control) so a
triager reading your scan output can't misread `503` as "your scanner was blocked" or `301` as
"endpoint moved".

### 3b. ONE control is not enough — catch-all is often SHAPE-gated

§3's protocol assumes the catch-all is universal. On real application stacks it frequently is not:
the catch-all is gated on **path shape**, so a bare random path and an extension-bearing or
dot-prefixed path get *different* catch-all bodies. Verified 2026-10-22 on the pornbox estate:

| Host | Bare random path | Extension-shaped | Dot-shaped |
|---|---|---|---|
| `ddfcontent.com` | 404 / 25 B `No input file specified.` | `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml` → **404 / 11422 B SPA homepage** | `/.htaccess` → 403 / 11422 B |
| `www.analvids.com` | 404 / 31218 B app 404 | `/sitemap.xml` → 200 / 163 B | `/.env`, `/.env.bak`, `/.DS_Store`, `/.htpasswd`, `/.htaccess` → **200 / 163761 B homepage HTML** |

With a single bare control every one of those reads as "FOUND DIFFERENTIAL", and `/.env` returning
**200 with 163 KB** reads as a jackpot. It is the homepage. **Probe three control shapes** — bare,
extension-bearing, dot-prefixed — and count a path as a true differential only when it differs from
*all* of them. Also remember **a 200 is not a finding**: check what the 200 contains (grep
`DOCTYPE|<html`, pull `<title>`) before reporting it.

`scripts/catchall_triage.sh` now implements the three-shape control automatically. Full treatment,
including the SSRF/traversal/XXE cell discipline, in
`references/ssrf-differential-refutation.md`.

---

## 4. Follow the redirect chain to its terminus — it may be an unenumerated domain

A "canonical alias" disposition is not the end of the lead. Walk it:

```
dev.naorisprotocol.com   → 301 → https://naorisprotocol.com/ (apex)
naorisprotocol.com       → 307 → https://www.naorisquantumprotocol.com/   ← NEW APEX
www.naorisquantumprotocol.com → 200, server: Vercel, x-powered-by: Next.js, 322,974 B
```

The batch was `naorisprotocol.com`; the terminus was **`naorisquantumprotocol.com`** — a domain that
appeared in none of the prior intel for this target. That reframes the whole operation: the six dead
hosts were stubs, and the real surface sits on a sibling apex reachable only by following the chain.

Then: CT the discovered apex (`certspotter … domain=<new-apex>&include_subdomains=true`) and hand the
resulting name list to the next batch. One extra GET turned a 6-host dead end into a new enumeration
root.

Also grep the terminus HTML before declaring it a new surface — a Next.js *marketing* site is not an
API. Mine for `NEXT_PUBLIC_*`, `/api/*`, `.js.map` refs, and `https://` host inventory. In this case
all four were empty (static marketing build, only GTM/YouTube/LinkedIn refs), so the honest note was
"new domain, marketing-only at root — value is in `/_next/static/` chunks, not the landing page".

---

## 5. Evidence-capture harness for a batch

Per-probe file containing: request line, operator header, UTC timestamp, full response headers,
`curl` exit code, body byte count, and the first 3 KB of body. One file per probe keeps every claim
in the report citable to a raw artifact and makes the "no response arrived" case auditable
(`CURL_EXIT: 28`, `BODY_BYTES: 0`) instead of an unsupported assertion.

`scripts/catchall_triage.sh` implements §1+§3 mechanically (paced, per-path status + md5, auto
CATCH-ALL verdict, evidence files). `scripts/rt.sh` remains the general hypothesis-round capturer.

Operational notes:
- Keep the **random-path control in the same run** as the attack paths, same timeout, same headers —
  a control captured under different conditions proves nothing.
- Port 80 plain-HTTP probes can trip local execution policy and rarely reveal anything a 443 edge
  characterization doesn't. Prefer https; skip port 80 rather than seeking approval for it.
- `urlscan.io` `domain:` search returning `{"total": 0}` is a **corpus gap** (they only keep ~30
  days), not evidence the target is inactive. Record it in the gaps section.

---

## 6. Worked case — Naoris batch A, 2026-10-22 (6 hosts, zero findings)

All six on Cloudflare (`172.66.40.193`, `172.66.43.63`), TLSv1.2 ECDHE-ECDSA-CHACHA20-POLY1305,
issuer `Cloudflare TLS Issuing ECC CA 3`, HSTS preload. **No bot challenge was hit on any host** —
so every negative below is real origin behaviour read *through* the proxy, not WAF rejection. State
this early in the report; it's what makes the negatives trustworthy.

| Host | Edge | Disposition |
|---|---|---|
| `apiagent` | 522 @45 s (looked like an infinite hang @25 s) | origin dead, cert live |
| `devapiagent` | 522 @40 s | origin dead, cert live |
| `dev` | 301 ×6 paths, md5-identical → apex → 307 → new apex | redirect stub |
| `www.dev` | 530 / `error code: 1016` | dangling origin (takeover candidate, CNAME unobservable) |
| `dev-smartspy` | 503 nginx w/ MSIE padding ×6 paths, md5-identical | origin up, all upstreams down |
| `smartspy` | 301 ×6 paths, md5-identical to `dev`'s | redirect stub |

Deliverable verdicts used only three words — **ERROR / NOTHING / FOUND** — because a batch triage
report's job is disposition per host, not narrative. Coverage: 22 evidence files, 1 host with no
response at all (documented as such), port 80 untested (policy), urlscan 0 rows (corpus gap).
