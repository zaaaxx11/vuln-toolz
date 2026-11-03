# Service-Worker recon (MindGeek tube network case study + method)

Target class: sites that ship a Workbox-backed service worker plus a client
"SW starter" that registers it behind a server-side feature flag.

## 1. Inventory the SW files first (they are small and directly fetchable)

Tube networks (pornhub/redtube/tube8/youporn) expose:
- `/service-worker.js` — the PH Workbox shell (≈1.3KB). Often most routes are
  **commented out**; read the *uncommented* `registerRoute` calls only.
- `/generated-service_worker.js` — the redtube/tube8/youporn Workbox shell
  (≈2KB). Redtube uses workbox **4.1.1**, tube8/youporn **5.1.2**; tube8 and
  youporn are byte-identical.
- `/generated-service_worker_starter.js` — the client-side registrar (ES6 class,
  ~6.6KB gzipped — `gunzip` it before reading). It reads `page_params.sw_starter_setup`
  and registers `serviceWorkerPath`.

Recipe: fetch each with `curl -A "<UA>" -H "X-Bug-Bounty: <op>" -s`, save body +
headers, `sha256sum` for divergence. Gzipped bodies start with magic `\x1f\x8b` —
`cp x.gz && gunzip -c x.gz > x.decoded.js` before grep/read.

## 2. The registration gate is a SERVER-SIDE flag, not a URL/cookie lever

PH registers `/service-worker.js` **iff** `typeof page_params.holiday_promo_prem !== 'undefined'`;
redtube/tube8/youporn register `serviceWorkerPath` **iff** `page_params.holiday_promo`
is truthy; otherwise they `unregister()` all SWs and `location.reload(true)`.

**Pitfall (learned here):** `?holiday_promo_prem=1` and `Cookie: holiday_promo_prem=1`
both FAIL — the flag is injected server-side into the `page_params` object literal in
the HTML. Worse, **curl and a real browser get different variants**: curl's bot-detected
HTML leaves `holiday_promo` undefined, the real browser's HTML sets
`page_params.holiday_promo === true` (and defines `holiday_promo_prem`). So a curl-only
sweep will wrongly conclude "SW never registers". Verify the gate in the live browser:
```js
page_params.holiday_promo            // true on real visit
Object.keys(page_params).includes('holiday_promo_prem')
Object.getOwnPropertyDescriptor(page_params,'holiday_promo') // writable:true, no getter
```
`page_params` is a plain writable data object — but you cannot define the *initial* value
client-side, so the registration gate is not a bypass surface.

## 3. Cache-poisoning (cacheFirst keyed on request URL) — the trap

Redtube/tube8/youporn register `cacheFirst({cacheName:'rt-js', maxEntries:100,
cacheableResponse:{statuses:[0,200]}})` for regexes like `/.*\/cdn_files\/redtube\/js\/.*/`.
That regex **matches any host**, including `attacker.example.com/cdn_files/redtube/js/evil.js`
(verify with `regex.test(url)`). The tempting conclusion — "attacker URL gets cached and
served to all visitors" — is WRONG. Live tests on the active SW show:
- same-origin **404** fetch → `rt-js` cache stays empty (`statuses:[0,200]` excludes 404);
- cross-origin **no-cors opaque** (status 0) fetch → `rt-js` cache stays empty (workbox
  4.1.1/5.1.2 do not persist opaque responses in this config / served from HTTP cache
  without invoking the SW fetch handler);
- cross-origin `<script src>` to a matching CDN URL → `rt-js` cache stays empty.
The attacker also cannot mint a `200` at a `phncdn.com`/`rdtcdn.com` URL (MindGeek-owned
CDNs). **Net: no pre-auth cache-poisoning primitive.** Report the regex-matches-any-host
surface as theoretical, with the live refutation captured.

`importScripts` is also safe: the Workbox loader hardcodes
`https://storage.googleapis.com/workbox-cdn/releases/<ver>/` and only honours
`modulePathPrefix`/`modulePathCb` if the SW calls `workbox.setConfig()` — these SWs don't.

## 4. Divergence between CDN profiles: test the SW artifact, not just page assets

Earlier tracks proved page CSS/JS diverges between gated/ungated CDN profiles. For the
**service-worker artifacts themselves**, test `?cache=<build>` vs no-param:
- PH `/service-worker.js` is **byte-identical** across `?cache=2026102002`,
  `?cache=2025010101`, and no-param (same sha256) — no SW divergence.
- redtube starter on `ei.rdtcdn.com` is **byte-identical** gated vs ungated.
So "SW content divergence" is REFUTED for the SW files even when page assets diverge.

## 5. The real (post-auth) sink: push → `clients.openWindow(notification.data)`

Redtube/tube8/youporn SWs contain:
```js
addEventListener("push", e => {
  const t = e.data.json(); // {messageTitle,messageBody,redirectionUrlOnClick}
  showNotification(t.messageTitle, {data: decodeURIComponent(t.redirectionUrlOnClick).replace(/&amp;/gi,"&"), ...});
});
addEventListener("notificationclick", e => { e.notification.close(); clients.openWindow(e.notification.data); });
```
`clients.openWindow` with attacker-influenceable `redirectionUrlOnClick` is an open-window
sink — **but** firing it needs (a) a victim push subscription
(`pushManager.getSubscription()` — NONE on a fresh client) and (b) the server's VAPID key
(`applicationServerPublicKey` is server-side). Post-auth/server-side only, not a pre-auth chain.
Also note these SWs have **no** `skipWaiting`, `clients.claim`, or `navigationPreload`.

## 6. Verdict template

For each SW hypothesis, capture the raw body + the live refutation and mark:
- cache-poisoning: REJECTED (opaque/404 not cached; attacker can't mint 200 on CDN host)
- registration bypass via `holiday_promo_prem`: REJECTED (server-injected `page_params` flag)
- SW content divergence: REJECTED (byte-identical across `?cache=`)
- `importScripts` attacker URL: REJECTED (workbox hardcoded to Google CDN)
- push `clients.openWindow`: REAL but not pre-auth (needs push sub + server push)

Worked artifacts for the MindGeek case: `/home/ubuntu/ph-hunt/followup/`
(`V1_SERVICEWORKER.md`, `evidence_V1_sw_fetch*.txt`, decoded bodies in `followup/js/`).
