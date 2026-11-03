# CDN cache-key bifurcation + cookie-consumer endpoint discovery (Ayló/MindGeek estate)

Worked on the MindGeek/Ayló tube estate (pornhub.com / redtube.com / tube8.com /
youporn.com + the `ei.phncdn.com` static CDN). Two techniques that generalize to
any bug-bounty target with a CDN fronting a cookie-driven flow.

## Technique 1 — CDN cache-key bifurcation (security-header / integrity-gate bypass)

A CDN may serve the **same path** from two cache profiles depending on whether a specific
query parameter is present. The two profiles can differ in **security posture** (a hash /
integrity header, `cache-control`, even body content), because the cache key includes the
query string.

**Detection recipe (read-only, 1 req/sec):**
```bash
# Baseline (no param) — capture security headers
curl -s -i 'https://cdn.example.com/robots.txt'
# Then add the app's cache-buster param with ANY value
curl -s -i 'https://cdn.example.com/robots.txt?cache=anything'
curl -s -i 'https://cdn.example.com/robots.txt?cache=2026102002'   # the real build value
```
Diff: `x-pending-security`, `cache-control`, `x-cdn-diag`, and the body (`Disallow` vs
`Allow` on robots.txt). On `ei.phncdn.com` the no-param path returns
`x-pending-security: A valid hash was not supplied.` + `max-age=10415627` + robots
`Disallow: /`, while the `?cache=<any>` path drops the security header, sets
`max-age=86401`, and serves robots `Allow: /`.

**Adversarial validation — run these BEFORE calling it a finding (all REFUTED on this
estate, but they are the checks that decide):**
1. **Header/body injection via the param:** `?cache=2026102002%0d%0aSet-Cookie:%20evil=1`
   and `?cache=...%0d%0aX-Injected:%20yes` → if the injected header/body does NOT appear,
   CRLF is neutralized (it was). No injection.
2. **Request-header reflection (classic poisoning vector):** send a unique marker in
   `User-Agent`, `X-Forwarded-Host`, `X-Forwarded-For`, `Referer`, `Accept-Language` and
   grep the response for the marker. If unreflected in BOTH profiles, cache poisoning via
   header echo is dead (it was).
3. **Content divergence on sensitive assets — fetch the REAL bundles, not just robots.**
   The old conclusion "real assets are byte-identical" came from testing only
   `interval-helper.js` (1635B), which happens to be a build-stable legacy helper. When
   the full home-page asset list is fetched under BOTH profiles and sha256-compared, the
   **CSS and one JS bundle DO diverge** (stable across repeated fetches):
   - `/www-static/css/generated-header.css` — 725,659B (gated) vs 738,965B (ungated)
   - `/www-static/css/commons-non-critical.css` — 40,206B vs 40,318B
   - `/www-static/css/flags/round_flag.css`, `/www-static/css/global-backgrounds.css` — divergent
   - `/www-static/js/lib/ph-functions.js` — 22,530B vs 23,242B
   - media (`*.jpg`/`*.gif`), `interval-helper.js`, `front-index.js`,
     `premium-modals.js`, `atlasbundle.min.js`, `crossdomain.xml` — IDENTICAL.
   **Divergence = build generation, not attacker-chosen content:** the gated profile serves
   a stale 2026-09-10 build (`?cache=2026091006` url-fragments, missing the
   `.ph-icon-trust-signal` rule), the un-gated profile serves the current 2026-10-21
   build. Both are first-party; no secrets, no reflected headers, no injected content.
   So it is a reportable cache-key/security-posture inconsistency (low/info), NOT a
   HIGH — an attacker cannot choose the un-gated profile's content via the param.
   **Lesson: "byte-identical real assets" must be verified across the full asset
   inventory, not one file — build-stale CSS/JS divergence is real and stable.**
4. **Semicolon trap:** `?cache=2026102002;evil` re-selects the GATED profile — a semicolon
   in the param value breaks the cache-key match. Useful as a discriminator that the
   bifurcation is key-driven, not value-driven.

**Verdict ladder:** bifurcation + security-header inconsistency = reportable (CDN serves a
gated and a non-gated cache profile for the same path). It becomes a HIGH only if (a) a
reflected header exists in the un-gated profile, or (b) a sensitive asset diverges between
profiles *with attacker-controllable content*. Neither held from egress → **THEORETICAL
(low/info)** — upgraded from the earlier "no divergence on real assets" claim.

**Cross-domain policy side-findings (static enumeration, predictable names only — no brute
force):**
- `vortex.pornhub.com/crossdomain.xml` = `<allow-access-from domain="*"/>` (legacy Flash
  any-domain policy, `last-modified` 2014, `accept-ranges`, `206` on `Range`). Low/legacy.
- `ei.phncdn.com/crossdomain.xml` allows `*.pornhub.com`, `*.pornhubpremium.com`,
  `*.thumbzilla.com`, `*.mgcorp.co`, `*.phncdn.com`, and **`*.local`** — an internal-domain
  wildcard in a public policy is an oddity worth a note.
- Enumerate only well-known names (`robots.txt`, `crossdomain.xml`,
  `clientaccesspolicy.xml`, `sitemap.xml`, `.well-known/security.txt`, `server-status`,
  `stub_status`, `nginx.conf`, `.htaccess`, `web.config`, `config.json`, `phpinfo.php`,
  `index.html`, `assetlinks.json`, `apple-app-site-association`, `m3u8`, `manifest`).
  34 predictable names → all 404 on this estate; only the two crossdomain files + robots
  were live.

## Technique 2 — Cookie-consumer endpoint discovery from inline JS

When a cookie name appears in an `essentialCookiesList`-style disclosure but no obvious
endpoint consumes it, **read the inline JS of the page that sets the cookie** — the consumer
URL is often a string literal there.

```bash
curl -s 'https://enter.pornhubpremium.com/' \
  | grep -oE "var [a-zA-Z]+CookieURL?\s*=\s*'[^']+'"
```
Found: `var premiumRedirectCookieURL = '//www.pornhub.com/user/premium_redirect_cookie?ajax=1';`

**Then probe the consumer and read what it actually does with the cookie:**
```bash
curl -s -i 'https://www.pornhub.com/user/premium_redirect_cookie?ajax=1'
curl -s -i 'https://www.pornhub.com/user/premium_redirect_cookie?ajax=1&url=https://example.com/PWN'
curl -s -i 'https://www.pornhub.com/user/premium_redirect_cookie?redirect=https://example.com/PWN' \
  -H 'Cookie: premium_redirect=https://example.com/Cookie-PWN; redirect=https://example.com/Redirect-Cookie-PWN'
```
**Adversarial validation for the open-redirect hypothesis:** the endpoint returned `200`
with an **empty body** and **always** set `set-cookie: premium_redirect=1` — a hardcoded
*boolean*, ignoring the attacker's `url`/`redirect` params and incoming cookie value. No
`Location:` header was ever produced. That is a **cookie-setter (flag=1)**, not a redirector
→ open-redirect REFUTED.

**CORS — the empty-ACAO trap (CORRECTION, high value).** The endpoint *also* emits
`access-control-allow-origin:` (empty) + `access-control-allow-credentials: true` +
`access-control-allow-methods: GET, POST` when **no `Origin` header is sent** — and an
empty ACAO is indeed inert. **But that is only the no-Origin case.** Send ANY `Origin`
header and the endpoint **reflects it verbatim** and keeps `access-control-allow-credentials: true`:
```bash
curl -s -i 'https://www.pornhub.com/user/premium_redirect_cookie?ajax=1' \
  -X OPTIONS -H 'Origin: https://evil.example.com' \
  -H 'Access-Control-Request-Method: POST'
# -> access-control-allow-origin: https://evil.example.com
#    access-control-allow-credentials: true
```
Verified reflecting: `null`, `https://evil.example.com`, `http://evil.example.com`,
`https://google.com`, even `evil://example.com` — i.e. **any Origin string**, on GET,
POST, and OPTIONS alike. This is a genuine **arbitrary-Origin CORS reflection + credentials**
misconfiguration (reportable low/medium), scoped to this endpoint family (`/front/cookie_kill_ajax`
behaves the same; `www.pornhub.com/` and `/view_video.php` with `Origin` do NOT reflect —
endpoint-specific, not site-wide). **The earlier "not exploitable as CORS" conclusion was a
false negative caused by probing only the no-Origin case.** Always probe the CORS surface with
a *sent* `Origin` header, not just the header-less baseline. Impact ceiling from egress: the
response body is empty (no victim data to read), so it becomes an exfil only if an
*authenticated* session makes this endpoint return user data — untestable without a session
vantage.

**Consumer-side verification (grep the real bundles, not just inline page JS).** The cookie
consumer lives in a JS bundle, not the inline `<script>`: `premium-modals.js` contains
```js
premiumRedirectCookieURL = '//www.pornhub.com/user/premium_redirect_cookie?ajax=1'
...
MG_Utils.ajaxCall({url:premiumRedirectCookieURL+"&do=delete",cache:!1,
  xhrFields:{withCredentials:!0},crossDomain:!0}).done(function(){
    window.location.href=MG_Utils.getData(
      document.querySelector('[id*="go-to-pornhub"]'),"pornhub-redirect")})
```
So the consumer **deletes** the flag via `&do=delete` (verified: `?ajax=1&do=delete` → 200
and **no** `set-cookie: premium_redirect`), then redirects to `data-go-to-pornhub
data-pornhub-redirect` — a **server-rendered data attribute**, not attacker-controllable from
egress. The cookie is a boolean "user accepted premium redirect" flag, not a URL carrier —
which is the structural reason the CSRF/open-redirect chain dies at the consumer step.
Recipe: `curl -s <cdn>/<bundle>.js | grep -o '.\{60\}<cookieName>.\{120\}'` for every
cookie in the essential list, across both CDN cache profiles.

**General lesson:** a cookie in an "essential" list is a *tracking/session marker*, not
necessarily an auth token. Before assuming a cookie is forgeable/redirect-controlling, find
its consumer and observe whether any client input reaches a `Location:`/state-changing
output. On this estate the `rp=<int>:<base64sig>` cookie was likewise server-generated random
(random 9-10 digit int + 8 opaque bytes), regenerated per request, and a cross-domain forged
`rp` was ignored/overwritten — a rate-limit/session marker, not forgeable without the signing
key (which is absent from all egress-visible JS/config).

## Chain-level verification discipline (linker + verifier pattern)

When a task asks to "assemble N candidate chains and verify each step end-to-end":
1. **Every step needs a captured response** — a chain is real only if EVERY hop has a
   raw capture. A rejected chain with the exact breaking step and response is a valid result.
2. **Mark each step VERIFIED/REJECTED separately** from the whole-chain verdict.
3. **Chase the consumer, not just the setter:** the CSRF/open-redirect chain died because
   the consumer (premium-modals.js) deletes the flag and redirects to a server-rendered
   attribute — the setter being forgeable was irrelevant.
4. **Age-gate / flag cookies: test the FULL matrix, including the deletion behavior.**
   On this estate every injected age cookie (`accessAgeDisclaimerPH`, `age_verified`,
   `accessPH`, `avukredirecturl`, `premium_redirect`, shorties.ai `Referer`) was answered
   with `set-cookie: accessAgeDisclaimerPH=deleted; expires=Thu, 01 Jan 1970; Max-Age=0`
   on every path — the server deletes the client-set flag in the SAME response that issues
   the redirect, so no race window is observable from egress.
5. **Open-redirect probes must use benign targets only** (e.g. `example.com`), and a
   same-domain canonical redirect (`shorties.ai/` → `https://www.shorties.ai/`) is not an
   open redirect. 20+ redirect-parameter names (url/to/next/redirect/u/link/goto/dest/
   destination/return/returnTo/continue/out/off/c/s/go) all preserved the param in a
   same-domain URL — REFUTED.
6. **Staging preflight (OPTIONS) is NOT data:** `api-stage*` returns 200 + `ACAO: *`
   on OPTIONS with a **0-byte body**, while real GET+Origin → 401 with no CORS headers.
   A wildcard preflight with no body is not an exfil vector.

## Pacing / scope discipline (unchanged)
- ≤1 req/sec, `X-Bug-Bounty: zaaaxx`, GET-only unless the task authorizes POST.
- The `premium_redirect_cookie` endpoint accepts POST (`access-control-allow-methods: GET, POST`);
  a benign empty POST was validated this round (same 200 + hardcoded `premium_redirect=1`).
- Browser-side cookie consumption (e.g. `avukredirecturl` read by JS after an age-gate click)
  needs a real browser session; from egress with curl the cookie is never reflected, so the
  JS-side consumption stays UNKNOWN.
