# On-disk artifact discovery + Host-header canonicalization discriminator

Companion to the cookie-consumer and redirect-refutation sections in SKILL.md. Two techniques from a worked tube-estate flank (MindGeek/Ayló, Intigriti, operator header `X-Bug-Bounty: zaaaxx`, 1 req/sec, benign `example.com` payloads).

## 1. On-disk artifact discovery (zero-cost, zero-rate-limit)

Before any live probing, mine the HTML/JS you ALREADY saved in a prior campaign's workspace. Auth-flow endpoints are almost always string literals in the page config, not guessable paths.

The single highest-value grep — the homepage HTML's inline config object:
```
grep -oE 'forgotPasswordUrl[^,]*' <saved-homepage>.html
# → forgotPasswordUrl: "/front/lost_password"   (the real endpoint, pre-auth)
```
Then confirm the guessed alternates are dead (all 404): `/user/forgot_password`, `/user/forgot-password`, `/password/forgot`, `/user/recover`.

**Why this beats path-guessing:** the app's own config names the route. Guessing produces 404 noise; the config literal produces the live endpoint on the first probe. Same pattern applies to any `...Url:` / `...Path:` / `endpoint:` literal in inline config (`apiBase`, `ssoUrl`, `resetUrl`, etc.).

**Sub-app JS bundle trees are separate from the main site's.** A sibling property (e.g. `shorties.ai`) loads its OWN bundle tree under a distinct CDN path:
```
# main site:  /www-static/js/lib/ph-functions.js
# shorties:   /www-static/shortiesai/js/lib/ph-functions.js   ← different tree
```
Extract the full `<script src>` list from the sibling's homepage HTML (`grep -oE 'src="[^"]*\.js[^"]*"' <sibling-homepage>.body`), then fetch each bundle and grep for the cookie/consumer name. **A consumer absent from the main tree is often still absent from the sibling tree** — that absence is itself the finding (consumer is browser-side/post-auth, not in any reachable bundle).

**Pitfall — the 213-byte 404 trap.** When fetching CDN JS, a wrong path returns a **213-byte error stub, not a 404 status you notice**. Always `wc -c` the fetched body: 213 bytes = stub = wrong path, re-derive the path from the homepage `<script src>` list rather than guessing subpaths.

## 2. Host-header canonicalization ≠ Host-header injection (the discriminator)

When `Host: evil.com` on a pre-auth endpoint returns a **301**, the reflex is "host-header injection." It usually is NOT. Run the discriminator before writing it up:

**Discriminator — is the 301 `Location` host attacker-controllable?**
- Read the `Location` header. If it is **hardcoded to the canonical host** (`www.pornhub.com`) regardless of the injected Host → **canonicalization guard, REFUTED.** The scheme may vary by Host class (recognized ph-domain → `https://`, unknown → `http://`) but the **host portion is fixed** — no URL injection, no reset-link poisoning.
- Only if `Location` embeds the attacker's Host string is it a real injection.

**The three Host-classes to test (each a different verdict):**
| Probe | Result | Verdict |
|---|---|---|
| `Host: evil.com` / `www.evil.com` / `localhost` / `evil.com:80` | 301 → `http://www.<canonical>/...` | canonicalization (unknown-host class) |
| `Host: <bare-apex>` / `Host: sub.www.<apex>` | 301 → `https://www.<canonical>/...` | canonicalization (recognized-host class, https) |
| `Host: 127.0.0.1` | **403** | localhost blocked at edge |
| `X-Forwarded-Host: evil.com` | **200, no reflection** | XFH NOT trusted by this vhost |

**Body-reflection control (the one that kills the false positive):** the only Host-mutating header that returns 200 is `X-Forwarded-Host`. Fetch the full body with `-H "X-Forwarded-Host: evil.com"` and count `evil.com` occurrences. **Zero occurrences + canonical `<link rel=canonical>` + relative form action = no reflection = REFUTED.** Do not claim injection from the 301 alone.

**Empty-Host quirk:** `curl -H "Host:"` sends no Host header but HTTP/2 preserves the `:authority` pseudo-header from the URL, so it returns the baseline 200 — not a separate case, don't over-read it.

## 3. Redirector-path refutation (the `/pforward/` pattern)

A path that 301s is usually a **trailing-slash normalizer**, not a redirector:
- `GET /pforward/` → `301 Location: /pforward` (slash-strip, same-host)
- `GET /pforward` → **404 soft-route returning the full homepage** (1.0MB)
- `GET /pforward/?url=https://example.com/...` → `301 Location: /pforward?url=<percent-encoded>` — the external value is **only URL-encoded into the preserved query string, never placed in `Location`**.

Test the full param-name battery (`url u to next redirect d target return dest continue go link out`) — on this class of host they are ALL inert (query-passthrough only). A 301 that preserves the query and stays same-origin is **not an open redirect**; only a `Location` that points off-host is.

## 4. Prefix-normalizing SPA router (the shorties.ai pattern)

Some single-page apps route EVERY path through a prefix normalizer:
- Every path → `301 Location: /shorties/<path>` (app-prefix injection)
- Every `/shorties/<path>` → **404** except the homepage `/`
- Only `/robots.txt` is live (200, benign)

**CORS probe discipline on such a router:** send `Origin: https://evil.com` on GET *and* OPTIONS across the candidate API paths (`/api/shorten`, `/api/links`, `/v1/shorten`, `/api/v1/*`). **No `access-control-allow-origin` header anywhere = no CORS surface** — report as a clean negative, don't pad.

**Short-link redirect params:** `GET /<token>?<param>=https://example.com/...` for the full param battery → all `301 Location: /shorties/<token>?<param>=<url-encoded>`. Same-host, query-preserve → **no open redirect**. Bare `/<token>` → `301 → /shorties/<token>` (404).

## 5. Egress-blocked hosts

A host that resolves (e.g. to `66.254.114.153`) but times out on **both 80 and 443** (curl rc=28) is firewalled at the network level from this egress. **Do not attempt raw-IP curls** — the harness safety filter blocks `http://<ip>/` URLs (pattern `tirith:raw_ip_url`); use the hostname only, and record the timeout honestly as REJECTED (unreachable), not as a finding.

## Verdict discipline (the deliverable)

Every probe family ends in one of: **REJECTED** (control proved it inert), **NOT FOUND** (consumer not in any reachable artifact — needs a browser session), or a real finding. A clean negative IS the deliverable — state it explicitly with the probe table rather than padding the report. All backed by captured request+response in evidence files (`evidence_<prefix>_*.txt`).

Worked session: `/home/ubuntu/ph-hunt/followup/R_HOST_REDIRECT.md` (106 evidence files, ~60 paced probes, all five families REFUTED/NOT-FOUND — no pre-auth RCE chain on the flank).
