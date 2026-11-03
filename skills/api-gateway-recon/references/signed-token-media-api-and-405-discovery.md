# Signed-token media APIs, 405 route discovery, and the no-server-gate correction

Worked on the Ayló/MindGeek tube estate (pornhub.com), read-only, `X-Bug-Bounty` header, ≥1 req/sec. All findings below are REFUTATIONS or INFO-grade — the value is the control that kills the false positive before it reaches a report.

## 1. 405-on-GET = live route behind the SPA catch-all (route discovery)

The SPA 200-catch-all trap (identical byte-size 200s, see `info-disclosure-path-sweep.md`) hides real API routes. Discriminator: **GET → 405 with an `Allow` header** = a real route exists; the SPA shell returns 200/404, never 405.

Probe ladder (all free, pre-auth):
1. `curl -s -i -X GET /api/upload` → `405` + `Allow: POST, OPTIONS` → route is LIVE
2. `OPTIONS` → `200` + `Allow` header (method enumeration, no auth needed)
3. `POST {}` → `401` = auth-gated (report "route exists, auth required", not "no surface")

Worked: `document-review.pornhub.com/api/upload` — GET 405, OPTIONS `Allow: POST, OPTIONS`, POST `{}` → `401 {"body":"Error","status":401}`. Host fingerprints: `Server: Google Frontend`, `X-Served-By: cache-sin-wsap*-SIN` (**Fastly**), `Vary: cookie, need-authorization`, `alt-svc: h3`.

Auth-bypass matrix on a 401 route (all measured → 401, i.e. gate is strict): `Authorization: Bearer x/null`, `X-API-Key`, `X-Auth-Token`, `X-Forwarded-Authorization`, `X-Original-URL`, `X-Rewrite-URL`, `Cookie: need-authorization=false|granted`.

Pitfall: don't confuse 405-on-GET with "method wrong on a static file" — check that `Allow` lists real verbs and that `OPTIONS` answers 200.

## 2. Signed-token media API — the session-bound-`k` refutation

Pattern: `GET /video/get_media?s=<base64url(JSON)>` where JSON = `{"k":"<40-hex>","t":<expiry>}` plus a trailing ~11-byte MAC. Returns `200` JSON with `videoUrl` signed CDN URLs (mp4 with `validfrom/validto/rate/burst/ip/hash` params).

The seductive false positive: manipulate `s` (extend `t` +1 day, strip the MAC, flip the MAC, swap `k`) → still **`200`** (NOT 401/403!) → looks like "MAC not validated, token forgeable".

The control that kills it — **cross-session replay**: take `s` issued to session A (cookie jar A), replay it with session B's cookies → `200 []` (empty array). `s` with no cookies at all → `200 []`. The `k` is a **per-request nonce bound to the issuing session cookie** — it even changes between two consecutive requests for the same video (fetch the same `viewkey` twice, decode two different `k` values). So:

- MAC leniency is real but moot — `k` is unpredictable and non-reusable, so nothing is forgeable
- IDOR is dead — `k` for video X is only valid for video X within the issuing session
- The signed mp4 URL itself binds `ip=<requester egress>` — replay from a different egress IP fails (full manipulation matrix → `404|213B`)

Verdict template: "token manipulation returns 200-but-empty; the discriminator is cross-session replay → `200 []` ⇒ session-bound token, REFUTED as IDOR/forgery."

## 3. Pre-auth state-changing endpoint without CSRF — the "no-effect-without-session" control

`POST /api/v1/user/dismiss_reactivate_subscription` → `200 {"success":1,"message":"Success!"}` pre-auth, no CSRF token, no Origin reflection. Looks like CSRF.

Control: does it have any measurable effect without an authenticated session? No set-cookie, no observable state change — it's a UI-modal preference. A state-changing endpoint that accepts unauthenticated POSTs but only acts on an authenticated session is CSRF-moot (same discipline as the GraphQL CSRF-moot rule in `web-api-recon`): a design note, not a finding. Contrast: `POST /user/log_user_cookie_consent` → `{"success":false,"message":"User is not logged in."}` (correctly gates, different message per endpoint — a useful auth-map signal).

## 4. Pre-auth OAuth request-token minting (non-injectable callback)

`GET /sso/xprovider?origin_item_id=1` → `200 {"authorizationUrl":"https://api.twitter.com/oauth/authorize?oauth_token=<server-generated>"}`. Every request mints a fresh request token. Injection matrix (`redirect_uri`/`callback`/`redirect`/`url`/`next`/`return`/`state`/`origin`/`oauth_callback`) → **all ignored**; `authorizationUrl` always points to the IdP with a server-generated token. Legit OAuth flow, callback pinned server-side → not an open redirect, not an SSRF. INFO at most (pre-auth token minting).

## 5. The "no server-side gate" mental-model correction

Do not assume an age/consent wall is server-enforced. `GET /view_video.php?viewkey=<real>` → **200 with full ~1.5MB player HTML pre-auth**, including signed `videoUrl` m3u8/mp4 URLs in the HTML itself. The consent cookie (`accessAgeDisclaimerPH`) is a client-side preference the server **deletes deterministically** on every response (with-cookie → always deleted; without-cookie → never set; zero intermittent window) — a TOCTOU/race on it is dead by construction. Before building any age-gate-bypass chain, spend one cheap GET verifying the gated content is actually server-gated. If the player HTML is already pre-auth, the "gate" is a UX modal, not an access control — redirect the hunt.

## 6. Time-boxed multi-flank hunt workflow (60-min budget)

- 2 leaf sub-agents as flanks, each with a distinct hypothesis family (here: REDTEAM = host-header/redirector/shorties; HUNTER = mirrors/age-race/modelhub/CDN-locale) and its own evidence directory + report `.md`; the orchestrator takes the single highest-yield track solo (here: the newly-discovered media API).
- Each flank deliverable: hypothesis table → paced probes (≥1s) → per-probe evidence files → per-hypothesis verdict (REJECTED with reason, or finding with transcript).
- Orchestrator integrates flank verdicts + solo findings into one FLOOR statement ending with the explicit "only remaining path requires X, which exceeds the read-only constraint" line.
- Expect ~300–400 paced requests in 60 min across all three tracks. Flanks over-delivered (~85 requests vs ~40 planned) on a differential matrix — trim locale×asset matrices early.

## 7. Egress vantage asymmetry (WordPress.com Atomic)

A shared hoster can block your egress IP at IP level (WordPress.com Atomic → persistent `429` on `POST /xmlrpc.php`) while GETs still work via a reader proxy (r.jina.ai) and POSTs fail even via public proxies (proxy IPs get 429 too — datacenter ranges are bulk-blocked; free proxies also die after ~1 hit). Consequence: **POST-class testing is dead from every vantage you can afford** — do not burn budget re-testing POSTs; pivot to GET-only discovery and record the untestable surface in the FLOOR.
