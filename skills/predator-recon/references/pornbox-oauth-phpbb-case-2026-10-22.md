# PornBox / AnalVids estate — OAuth-bridge + phpBB-catch-all case ledger (2026-10-22)

Scope: `www.pornbox.com`, `www.analvids.com`, `www.ddfcontent.com`, `www.pornworld.com`
(HackerOne/Bugcrowd-style export; all `eligible_for_bounty=true`, `max_severity=critical`;
pornbox.com carries availability/confidentiality/integrity = high → no DoS, no volumetric scans,
1 req/s pacing).

## Estate topology (PROVEN)

| Node | Role | Notes |
|---|---|---|
| `forum.pornbox.com` | phpBB3 board + "Karma MOD" + custom `/auth/*` bridge | catch-all host (see below); cookies `phpbb3_hu43l_u/k/sid`, `FORUMSESSID`, `VER_BTSPORN=1017` |
| `www.analvids.com` | PHP app (main content site) | `/api/*` JSON API, per-request 16-char CSRF, reCAPTCHA on forgot-password |
| `account.analvids.com` | **GTFPASS SSO/OAuth broker** for the whole estate | `/authorize`, `/login`, `/api/user-data`, `/api/jdialog/<site>.js` |
| `www.pornbox.com` | SPA shell only (3497 B cookie-error page) | CSP references `*.gtflixtv.com`, `wss://pornbox.com/socket.io/` |
| `ddfcontent.com` | legacy PHP site | `ajax.php?module=<login\|register\|contactus\|select>`, reCAPTCHA-gated |
| `pornworld.com` | tour app | **UNRESOLVED**: every path except `/` returns 400 (34354 B); `tour_app` HttpOnly cookie set on `/` |
| `cdn77-video.gtflixtv.com` | signed-URL media CDN | `/<b64>,<epoch>/<sha1>/5/<a>/<b>/<clip>/1.mp4` |

## PROVEN — browser-pin gate bypass (public constant IS the gate)

`GET /auth/login` → 301 `/auth/browser-pin?redirect=...` → a 515-byte page that loads
`https://account.analvids.com/api/jdialog/btsporn.js` and polls for `window.BROWSER_PIN`.
That JS contains:

```js
var pin_hash = '5CRSRZOBDZLXP5X36US9I1FV9V4WHO02RSU4NGFIL45B5LFSWU';
```

Replaying it as a cookie skips the interstitial entirely:

```
Cookie: JDIALOG3=5CRSRZOBDZLXP5X36US9I1FV9V4WHO02RSU4NGFIL45B5LFSWU
GET /auth/login  ->  302 https://account.analvids.com/authorize?response_type=code
  &action=login&client_id=btsporn&scope=web&browser_pin=<same pin>
  &redirect_uri=https%3A%2F%2Fforum.pornbox.com%2Fauth%2Fresponse%3Fredirect%3D...%26client_id%3Dbtsporn
```

- `www.pornbox.com` uses the same pattern with a different constant
  (`/jdialog/box/1.js` → `E1AEC2OMYH834HON7P4L7C7FQUY6AUSCWWLB3TKWZL9XRF8F5H`).
- `VER_BTSPORN=1017` / `VER_GTFPASS=1017` are build markers set on every response — NOT the gate.
- The broker stores the full authorize URL base64-encoded in a `redirect_url` cookie
  (`finish=1` appended), Max-Age 86400.

## PROVEN — OAuth broker pre-login validation matrix (no credentials used)

`account.analvids.com/authorize`:

| Input | Result | Reading |
|---|---|---|
| unknown `client_id` (e.g. `evil`) | **302 → redirect_uri host** `?error=Website+"evil"+not+found` | broker sends the error to the *supplied* redirect_uri |
| `client_id=btsporn` + evil redirect_uri (evil host, suffix `forum.pornbox.com.evil.com`, userinfo `forum.pornbox.com@evil.com`, path traversal) | **200 error page, no redirect** | redirect_uri IS validated per-client |
| `client_id=btsporn` + legit redirect_uri | 301 → `/login` | normal flow |
| `client_id=` (empty) | 302 → redirect_uri `?error=Website+""+not+found` | same reflection |
| `client_id=btsporn%20` | 302 → redirect_uri `?error=invalid_client` | distinct string = client exists, id malformed |
| `client_id=gtfpass` / `legalporn` / `box` | 301 → `/login` | all valid estate clients |

Oracle value: one unauthenticated request per variant maps client existence + redirect_uri
validation without ever logging in.

## PROVEN — `/auth/response` redirect validation (forum.pornbox.com)

| `redirect` value | Result |
|---|---|
| no `code` param at all | **302 → the redirect target** (no code validation before redirect) |
| `code=GARBAGE` | 200 error page |
| `error=...` | 200 error page |
| `https://evil.example.com`, `//evil.example.com`, `https://forum.pornbox.com.evil.com/x`, `https://user@forum.pornbox.com/x`, `https://sub.forum.pornbox.com/x` | 302 → `https://forum.pornbox.com/` (rejected) |
| `https://forum.pornbox.com:8443/x` | **302 → allowed** (port not restricted) |
| `https://forum.pornbox.com//evil.com/x` | **302 → allowed** (path-relative; browser stays on-host — not exploitable) |
| `https://forum.pornbox.com/adm/index.php`, `/ucp.php?mode=login`, `/mcp.php`, `/auth/logout` | 302 → allowed (any same-host path) |

Lead: the callback redirects to an attacker-chosen *same-host* path with **no code present** —
useful for post-phish/post-XSS chaining, not a standalone finding.

## phpBB catch-all discrimination (forum.pornbox.com)

Unknown path → **200, title `PornBox.com • Index page`, ~63640 B** (body length drifts per path
because the path is echoed into the page — md5 is NOT a stable discriminator; use `<title>`).

| Path | Status | Title | Verdict |
|---|---|---|---|
| `/` `/index.php` | 200 | Index page | real |
| `/search.php` | 200 | Search | real |
| `/memberlist.php` `/posting.php` `/report.php` | 200 | Information | real (login-wall) |
| `/ucp.php?mode=login` `/mcp.php` `/viewonline.php` | 200/302 | Login / UCP / MCP | real |
| `/viewforum.php` `/viewtopic.php` | 404 | Information | real 404 |
| `/feed.php?mode=topics` | 200 | (Atom XML) | real |
| `/docs/CHANGELOG.html` `/install/` `/adm` | 200 | **Index page** | **FAKE — absorbed by catch-all** |
| `/adm/index.php` | 401 (12 B) | — | **real ACP, HTTP-auth gated** |
| `/config.php` | 404 (548 B) | — | real 404 (different body) |

`/auth/*` map: `/auth/login` `/auth/register` `/auth/sso` `/auth/callback` `/auth/token`
`/auth/refresh` `/auth/session` `/auth/status` `/auth/check` → 301 (pin gate);
`/auth/logout` → 200; `/auth_handler` → 200 JSON `{"result":"error","message":"Not authorized
(code #xxxxx)","exception_type":"loggable"}` (error-code oracle; code changes per request);
`/auth/browser-pin?redirect=x` → 200 error page.

## www.analvids.com pre-auth API surface

| Endpoint | Behaviour |
|---|---|
| `/api/user-data` | 200 `{"is_authorized":false,"website_user_id":null,"username":"guest","source_website_id":19}` |
| `/api/join-price` | 200 `{"join_price":"€26.61"}` |
| `/api/sign-in/form` | 200 form, **per-request 16-char CSRF** (validated: stale → `Page is expired`) |
| `/api/forgot-password/form` | 200 form, CSRF + reCAPTCHA (`6LdImfMqAAAAABhw7YUzcg_Y9PaqkGHjyNQdWz_x`); POST without captcha → `Please complete the CAPTCHA` (strict gate) |
| `/api/support/form` + POST `/api/support` | 200 `{"result":"ok"}` with valid CSRF; missing CSRF → field-level errors (CSRF enforced) |
| `/autocomplete?query=` | 200 JSON (Model/Scene results) |
| `/api/casting/thumbnail/click?casting_id=N` | **arbitrary numeric ID accepted, no ownership check**; 2nd click on same ID → `Duplicate casting click` (session dedup) → free ID-existence oracle |
| `/api/casting/content/click/<contentId>?source_website_id=&niche=&landing=1` | `niche` loosely validated (`anal`, `abc`, `999`, `-1`, `1e5` ok; `[]`, `anal,test`, `anal%20` → `Wrong niche`); `source_website_id` not validated (any value accepted) |
| `/api/cart?product_offer=...&redirect=...` | 302 → `/member-area` → 302 → `/api/go-to-box` → 302 → `/`; only `PRODUCT_OFFER_MEMBERSHIP_PLAN_30_DAYS` resolves, others 404; `redirect` always normalised to `/` (no open redirect) |
| `/api/go-to-box?from=` | all `from` values → `/` (no open redirect) |
| `/thumbnail/missed-image` | returns an error page inside JSON (error oracle) |
| `/member-area` | 302 chain to `/` when unauthenticated |

Bundle: `https://www.analvids.com/assets/js/app.js?rev=1017` (367 KB) — endpoint list extracted
from it; `userData` cached in `localStorage["user2"]` (client-side only).

## CDN77 signed media URLs

`https://cdn77-video.gtflixtv.com/aWV_Q9xgotjYaauS_Ghlxw==,1989961200/2ac238e68ae7d243b066e9c04cac446e82f46e99/5/10343/1041/16/1.mp4`
→ 200, 28.5 MB, `video/mp4`, **fetched pre-auth from a public watch page**.
Changing the clip segment or the sha1 → 403 (868 B). Directory listing → 403.
OPEN LEAD: confirm whether clip 16 is the free preview or full premium content (the watch page
carries an "ACCESS NOW" CTA and app.js gates on `has_goods` — verify paywall status before
claiming premium-content exposure).

## ddfcontent.com ajax.php

| `module` | Response (pre-auth, valid CSRF, no captcha) |
|---|---|
| `login` `register` `contactus` | `{"success":false,"message":"The response parameter is invalid or malformed."}` — identical for empty/garbage/`null` token → **strict server-side reCAPTCHA** (identical-message matrix = strict gate) |
| `select` `` (empty) `forgot` `reset` `profile` `logout` | `{"success":false,"message":"No permission"}` — module allowlist |

CSRF is per-fetch (40-hex, changes every page load); `generated_at` epoch also per-fetch.
`?module=registration` renders the real registration form (email, company_name, first/last name).

## pornworld.com — UNRESOLVED disposition

`/` → 200 (126 KB, sets `tour_app` HttpOnly + `sxc_visitor_id`); **every other path** (`/api/`,
`/login`, `/admin`, `/robots.txt`, `/sitemap.xml`, random) → **400 with a 34354-byte body**.
Not yet classified: tour-app gate, WAF rule, or framework 400. Homepage emits
`access-control-allow-origin: *` + full method/header allowlists **without**
`access-control-allow-credentials` (spec-valid INFO). CSP `connect-src` includes
`myapi.agego.com` / `verifycdn.agego.com` (age-verification vendor).

## REFUTED this session

- Open redirect on `/api/go-to-box`, `/api/cart`, `/auth/response` (external hosts) — all
  normalised to same-host root.
- redirect_uri bypass on the OAuth broker (evil host / suffix / userinfo / traversal) — validated.
- Price tampering via `/api/cart` `product_offer` — unknown offers 404, known offer resolves
  server-side; no client-trusted price.
- CSRF absence on analvids `/api/support`, `/api/sign-in` — enforced (per-request token).
- CDN77 URL forgery — sha1 path binding enforced (403 on tamper).
- reCAPTCHA bypass on ddfcontent — strict, identical-message matrix.

## Orchestration notes

3 leaf subagents (ARCHITECT / RED-TEAMER / FUZZ-ENGINEER) were dispatched in parallel with the
full evidence set embedded in each prompt; the orchestrator kept probing in parallel. The session
hit the 90-iteration cap **before the subagent results re-entered** — on multi-hour hunts, reserve
orchestrator iterations: front-load everything the leaves need into the dispatch prompt (done
here) and keep own-probing to short verification commands, because leaf results arrive as new
messages and a capped session loses them.
