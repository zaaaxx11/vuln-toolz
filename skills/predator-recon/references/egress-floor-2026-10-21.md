# Egress floor + Fastly PURGE + Cloudflare challenge (2026-10-21)

Captured during the MindGeek/Ayló RCE hunt (Intigriti scope). This is the
conclusive egress ladder and the two techniques that emerged: an unauthenticated
Fastly PURGE (real finding) and the Cloudflare managed-challenge floor (why the
POST surface stayed untestable).

## 1. The conclusive egress floor

Target: `blog.mainhub.com` (WordPress.com Atomic + Cloudflare managed challenge).

| Vantage | GET | POST | Notes |
|---|---|---|---|
| Direct curl (43.157.224.222) | 200 | **429** | Atomic per-IP POST limiter |
| Tor exit (94.142.244.16) | 200 | **429** | POST budget follows the limiter, not the IP |
| r.jina.ai (residential) | 200 | GET-only | silently downgrades POST→GET; has its OWN WAF |
| 13+ CORS proxies | — | 0 forward body | allorigins GET-only (CL:0); rest 522/429/403/dead |
| Headless Chromium (stealth) | **403** | 403 challenge | "Checking your browser..." never clears |
| Headed Chromium under xvfb-run | **403** | 403 challenge | same — challenge needs real residential egress |
| Fleet VPS (Soya/Soraya/Simon) | unreachable | — | port 22 timeout / needs key |

**Reporting rule:** when POST is 429/403 from every vantage, the POST surface is
**UNTESTABLE (floor)** — record it as such. Never write "no vuln" for a surface
you could not reach.

## 2. Fastly PURGE — unauthenticated cache eviction (VERIFIED, low-med)

Host: `document-review.pornhub.com` (Fastly edge, `X-Served-By: cache-sin-wsap###-SIN`,
`Via: 1.1 varnish`).

### Discovery
`PURGE <any-path>` → `HTTP/1.1 200 OK`, `Content-Type: application/json`,
body `{ "status": "ok", "id": "440031-1792359329-122594" }` — **no auth header,
no API key, no Surrogate-Key**. The `id` format is `<edge-id>-<epoch>-<rand>`.

### Verification recipe (prove the eviction is real)
1. Warm: `GET /assets/css/page.css` ×2 → second response `x-cache: HIT, x-cache-hits: 1`
2. Purge: `PURGE /assets/css/page.css` → 200 ok
3. Re-GET → `x-cache: MISS, x-cache-hits: 0` — the cached object was actually evicted

### Scope
- Works on **any path**: `/`, `/assets/css/page.css`, `/api/upload`, even nonexistent
  (`/nonexistent-page-xyz` → `{"status":"ok"}`)
- Works on **POST-protected paths**: `POST /api/upload` → 401, but `PURGE /api/upload` → 200
- Soft-purge via `Surrogate-Key: __fb:cloudrun` also returns ok
- PURGE with a body, or with `X-HTTP-Method-Override: POST`, still purges (verb is honored, body/override ignored)

### Host-specific
The same `PURGE /` on the main www host (openresty) → **405 Not Allowed**.
Probe each host separately; do not generalize.

### Impact
Cache-eviction / origin-load amplification: an unauthenticated attacker can
repeatedly purge arbitrary objects, forcing origin refetches. Low-to-medium.
Also a misconfiguration signal (Fastly service configured with open purge).

### Bonus: Fastly-Debug header (info disclosure)
`GET /` + `Fastly-Debug: 1` returns:
```
Surrogate-Key: __fb:cloudrun document-review.pornhub.com
  mg-document-review __fb:mg-document-review:live
  __fb:mg-document-review:__channel:live:__version:c9f76efb5211dd4e
  __fb:fh:origin_v3 __fb:fh:origin-server:prod
Fastly-Debug-Path: (D cache-sin-wsap440046-SIN 1792583963)
                   (F cache-sin-wsss1830021-SIN 1792583963)
Fastly-Debug-TTL: (M cache-sin-wsap440046-SIN - - -)
Fastly-Debug-Digest: 98f4a76f8811b1094ffb71d2e32e5fb02c5ca0acb71c586b10459d2d3e5ebf49
```
Discloses: internal service name (`mg-document-review`), deploy version channel
(`c9f76efb5211dd4e`), backend naming (`fh:origin_v3`, `fh:origin-server:prod`),
and the two-tier cache path (edge `cache-sin-wsap###-SIN` → shield
`cache-sin-wsss1830021-SIN`). Debug headers are NOT returned on the 401 POST path.

### Related hypothesis REFUTED: cache poisoning
`Surrogate-Key: EVIL`, `X-Forwarded-Host/Server`, `Forwarded: host=`, `X-Original-URL`,
`X-Rewrite-URL`, `X-Forwarded-For` on GET / → all 200 with **byte-identical bodies**
(len=1912), no reflection of attacker value, no cache-key change. `Vary` is fixed:
`cookie, need-authorization, x-fh-requested-host, accept-encoding`. PURGE evicts;
it does not inject. Poisoning needs a reflected header — none exists here.

## 3. Cloudflare managed challenge — why headless/xvfb fails

### Stack
blog.mainhub.com sits behind WordPress.com Atomic **plus** a Cloudflare managed
challenge. The vantage behavior splits by client class:
- curl → Atomic 429 (rate-limit, `x-ac: NN.sin _atomic_bur`)
- headless Chromium → Cloudflare 403 "Checking your browser..."

### What was tried (all failed)
- Headless Chromium + stealth init-script: `navigator.webdriver=undefined`,
  `navigator.languages=['en-US','en']`, `navigator.plugins=[1,2,3,4,5]`,
  `window.chrome={runtime:{}}`, locale=en-US, timezone=America/Toronto,
  `--disable-blink-features=AutomationControlled`
- Headed Chromium under `xvfb-run -a --server-args="-screen 0 1366x768x24"` +
  `--start-maximized`
- Waited 30s (10×3s polls) — title stayed "Checking your browser..."
- In-page `fetch('/wp-json/jetpack/v4/connection', {method:'POST'})` → 403
  (challenge page, not 429)

### Challenge payload analysis
`GET /__challenge/probes.js?v=2f8d89405f2c` → **194,648 chars** obfuscated JS
(`vm_0x…` names, string-array rotation). Contains **99 base64 blobs ≥200 chars**;
decoded bytes have **printable ratio 0.37–0.45 = encrypted payloads/ciphertext**
(Turnstile-style proof-of-work + browser fingerprinting). Not solvable by naively
executing the JS; needs a real browser fingerprint + residential reputation.

### Only unlocks
Real residential proxy or a challenge-solving service — both outside a
read-only/no-credential budget. Report the POST surface as FLOOR.

### Playwright path gotcha
`/usr/bin/chromium-browser` is a broken snap symlink on this box. The real
binary: `/home/ubuntu/.cache/ms-playwright/chromium-<ver>/chrome-linux64/chrome`
(versions present: chromium-1223, 1228, 1243). Point `executable_path` there.

## 4. Jina WAF false-positive control (mandatory)

When using `https://r.jina.ai/<url>` as a read-proxy, Jina's OWN Cloudflare layer
blocks URLs that contain path-traversal patterns (`../`, `..%2f`) or cloud metadata
IPs (`169.254.169.254`, `metadata.google.internal`). The response is a
**"Sorry, you have been blocked … You are unable to access jina.ai"** cf-wrapper
HTML page — from Jina, not the target.

**False-positive shape observed:**
- `oembed/1.0/proxy?url=http://169.254.169.254/...` → HTML "200" (looked like SSRF)
- `fluent-auth/.../view-file?file=../../wp-config.php` → HTML "200" (looked like traversal)
- Benign control `?url=https://example.com/` → 401 JSON (the real target behavior)

**Control rule:** always run a benign-URL probe in the same batch. If the benign
probe returns JSON/401 while the "interesting" URL returns HTML, the HTML is
Jina-side. Only claim a finding when the body is JSON or target-branded content.

## 5. WP-API intel harvested (read-only, via Jina)

- `GET /wp-json/jetpack/v4/connection` → 200:
  `{"isActive":true,"isStaging":false,"isInSafeMode":false,"isRegistered":true,
  "isUserConnected":false,"hasConnectedOwner":true,...,"isPublic":true,
  "registrationFailure":null}` — Jetpack is connected to WP.com with a connected owner.
- `GET /wp-json/wpcom/v2/mailchimp` → 200:
  `{"code":"not_connected","connect_url":"\/wp-admin\/options-writing.php","site_id":241009683}`
  — WP.com site_id 241009683 (info).
- `GET /wp-json/complianz/v1/banner` → `{"consenttype":"optout","region":"us",
  "version":"7.6.7","banner_version":"108"}` (Complianz GDPR plugin fingerprint).
- `GET /wp-json/complianz/v1/cookie_data` → `{"statistics":{"Google-Analytics":
  ["_gid","_ga","_ga_"],"Automattic":["tk_qs"]}}`.
- Route counts: jetpack/v4 = 130 routes (60+ POST), fluent-auth = 63 routes
  (46 POST incl. install-plugin, upload-image, view-file, delete-file,
  restore-file, reinstall-core), wpcom/v2 = 142 routes (65 POST),
  seopress/v1 = 60 routes (27 POST), kb-design-library = 24 routes
  (ai/generate-content, process_images), bricks/v1 = 16 routes (render_element).
- All state-changing routes → 401 `rest_forbidden` / `invalid_user_permission_*`.
- POST-only routes answer 404 `rest_no_route` to GET (e.g.
  `/jetpack/v4/remote_register` — methods=[POST,PUT,PATCH]). Classify from the
  namespace index, not from the GET probe.

## 6. Error-message escalation ladder (auth-gate oracle)

`log_user_cookie_consent` maps its gate stack from the error sequence:
1. no token → `Error during token validation.`
2. token + session cookies → `User is not logged in.`

Each distinct message = one gate crossed. Use the ladder to confirm a discovered
nonce is real (validation-ladder change), learn the next gate, and avoid
brute-forcing a gate already satisfied. Pair the homepage-embedded per-request
nonce with the cookie jar from the same fetch.
