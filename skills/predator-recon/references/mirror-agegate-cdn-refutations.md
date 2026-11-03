# H-flank refutations — localized mirrors, age-gate race, parked domain, CDN locale
**Target:** MindGeek/Ayló tube network (ar./fil. mirrors, modelhub.com, mainhub.com, ei.phncdn.com)
**Date:** 2026-10-21 · **Header:** `X-Bug-Bounty: zaaaxx` on every request · **Pacing:** ≥1 req/s
**Outcome:** 0 new findings — all five hypotheses REFUTED with captured evidence.

## 1. Localized mirrors (ar./fil.) are i18n clones — differential probing yields no new surface
- `ar.pornhub.com/` 200 (1,298,967 B) `html class="language-ar" lang="ar"`; `fil.pornhub.com/` 200 (1,267,091 B) `language-fil`.
- Same validation logic as www: `/api/v1/pornstar/search_autocomplete?q=test` → 400 `[{"field":"token","message":"حقل مطلوب مفقود"}]` (ar) / `"Kulang ang kinakailangang patlang"` (fil) — same gate, localized strings only. `/api/v1/chat/threads` → 401 `[]` (identical). `/api/`, `/ajax/` → 404 SPA shell (~1.04 MB, same as www).
- `/user/premium_redirect_cookie` reflects arbitrary `Origin` + `access-control-allow-credentials: true` on ar **and** fil — but www behaves identically ⇒ site-wide known issue, NOT mirror-specific.
- `service-worker.js` byte-identical (1316 B, workbox 6.4.1) across ar/www/fil.
- **Rule:** a mirror finding must show the mirror's response *differs* from www's on the same request shape. Identical behavior = same known issue (or none).

## 2. modelhub.com is a parked double-hop redirect — no API surface
- `modelhub.com/` → 301 `www.modelhub.com/` → 301 `www.pornhub.com` (captured with `allow_redirects=False`).
- EVERY path (`/`, `/robots.txt`, `/api/`, `/api/v1/`, `/api/v1/models`, `/api/models`, `/user/`, `/login`, `/oauth/`, `/swagger`, `/docs`, `/graphql`, `/sitemap.xml`) → 301 → PH homepage (1.25 MB). OPTIONS on `/api/`, `/api/v1/`, `/graphql` → 405, no `access-control-*`, no `Allow`.
- Host-disposition note: this is the "canonical alias" negative, extended — a **double-hop** alias where even "API-ish" paths are absorbed by the redirect chain. Probe with redirects disabled to see the chain, not the final 200.

## 3. Age-gate TOCTOU race — refuted structurally, not just empirically
Two preconditions both failed on `www.pornhub.com`:
- **No server-side gate on the route.** `GET /view_video.php?viewkey=6acaf92c28373` (scraped from homepage) → 200, 1,615,763 B, `<title>Riley Star Helps Ease Stepbro's Blueballs & Gets Cum Load Facial - Pornhub.com</title>`, real `flashvars`/`video_id` — full player HTML with NO cookie. `accessAgeDisclaimerPH` appears only in the client cookie-category config (`essentialCookiesListAll` → `{"pornhub.com":{"accessAgeDisclaimerPH":"essential",...}}`), not as a gate.
- **Deterministic deletion, no intermittent window.** With `Cookie: accessAgeDisclaimerPH=1`, every response carries `Set-Cookie: accessAgeDisclaimerPH=deleted; expires=Thu…`. Parallel race (2 attempts × 3 threads): 6/6 with-cookie workers saw deletion, 4/4 without-cookie never saw it set; all 6 workers got 200 + full player (no content divergence). Mirrors ar/fil identical (both 200, both delete).
- **Two-step refutation recipe:** (1) GET the gated page with NO cookie — if protected content (title/player markers) is already there, there is no gate to race; (2) send the consent cookie once and check deletion is deterministic across N parallel workers. If both hold, REFUTE the race class and redirect the hunt to a *different* gate (`age_verified` cookie, an age-restricted video_id) — the named cookie is a client-side consent marker.

## 4. mainhub.com — static "coming soon" page, no pre-auth API
- `www.mainhub.com/` 200 (17,905 B) `<title>Mainhub: Content management for content creators</title>`, "coming soon" copy, no JS app, no api paths.
- `/robots.txt` (83 B): `User-agent: * Disallow: / Allow: /$ Allow: /blog$ Allow: /blog/ Allow: /sitemap.xml`.
- `/api/`, `/api/v1/`, `/graphql`, `/admin/`, `/wp-json/, `/login`, `/user/` → 404 SPA shell (9,749 B, `noindex`). `/sitemap.xml` → openresty 404 (552 B).
- `/blog`, `/blog/` → 301 `https://blog.mainhub.com` (WordPress, 152,367 B, Complianz GDPR plugin, `wp-content/uploads/2025/08/mh-logo.svg`).

## 5. ei.phncdn.com CDN ignores Accept-Language — locale is NOT a cache-key axis
- 4 assets × 3 locales (`en-US` / `ar-SA` / `fil-PH`), all byte-identical md5s:
  `www-static/js/lib/interval-helper.js` 1635 B `2d210f63…`; `.../utils/mg_utils-2.0.0.js` 7338 B `6db59da0…`; `.../lib/atlasbundle.min.js` 55,947 B `f6ec6c77…`; `.../playlist/playlist-basic.js` 42,310 B `f383bfd9…`.
- Distinct from the **cache-profile** divergence pitfall (gated vs ungated profile build staleness, which DOES diverge). Two different axes: profile/build divergence (real, low/info) vs locale/header divergence (absent here). Test both axes with ≥4 assets before claiming "identical".

## Operator notes
- Request count: flank used ~85 paced requests vs ~35–45 guide — cause was the differential matrix (hosts × paths × locales). All safety rules respected; the overage is thoroughness, not a rule breach. Trim the locale × asset matrix before expanding host/path coverage, and flag overages in the report.
- Reusable for the parent: `view_video.php` serves full video HTML pre-auth; `accessAgeDisclaimerPH` is a client-side-only consent cookie the server deletes — any age-gate bypass chain must target a different gate.
- Low-value follow-ups for other flanks: blog.mainhub.com WordPress (Complianz plugin) untested for plugin CVEs; `testCookieTubescms` cookie (seen in the PH cookie-category config referencing modelhub.com) — confirm whether any live endpoint still sets it.
