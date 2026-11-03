# Estate trust-graph & authority-boundary mapping (the ARCHITECT track)

Class-level method for a brief that says *"map every node, every edge, every authority
boundary; rank sinks by reachability × impact"* across a **multi-app estate** (a forum +
a content app + an SSO/OAuth broker, typically sharing one apex brand).

Distilled from the PornBox/AnalVids architect round (2026-10-22): `forum.pornbox.com`
(phpBB3 + custom `/auth/` bridge), `www.analvids.com` (PHP app), `account.analvids.com`
(OAuth broker). Desk + light probing only, 1 req/sec, GET-only, no auth, no disruptive
testing — ~90 requests total.

Use when the deliverable is a **graph**, not a finding list. The graph is the product;
findings fall out of it.

---

## 0. Read the scope file as a node list, not a target list

A program scope CSV/JSON is the authoritative node inventory. Parse it into three
columns before probing anything: `identifier`, `asset_type`, `max_severity`. Two
traps:

- **In-scope ≠ registered.** A host can be in program scope and still be absent from
  the broker's `redirect_uri` allowlist. Record the set difference explicitly — it is
  a finding (see §5).
- **`max_severity` is per-asset, not per-bug.** Rank sinks against the asset's own
  ceiling, not the program's global max.

## 1. `robots.txt` is a free, authoritative route inventory — fetch it on EVERY host

The single highest-yield request of the round. `www.analvids.com/robots.txt` (200,
2 KB) disclosed, with zero probing:

```
Disallow: /api/  /index/filter  /member-area  /search/
Disallow: /forum/adm  /forum/cache  /forum/files  /forum/includes
          /forum/language  /forum/store  /forum/cron.php
          /forum/download/file.php  /forum/karma.php  /forum/memberlist.php
          /forum/posting.php  /forum/search.php  /forum/ucp.php
Crawl-delay: 5   Host: www.analvids.com/
Sitemap: https://www.analvids.com/sitemap.xml
```

What that buys you:

- **The mount point.** `/forum/*` proves the phpBB instance is mounted *under the
  analvids app*, not only at its own apex. Two names, one codebase tree.
- **The phpBB file inventory** (`adm`, `cache`, `files`, `includes`, `language`,
  `store`, `cron.php`, `download/file.php`, `karma.php`) — the standard phpBB attack
  surface, handed over.
- **The custom-route hints** (`/member-area`, `/index/filter`) that no JS bundle
  mentioned.
- **`Crawl-delay`** tells you the operator's own pacing expectation — honour it.

**Asymmetry is signal.** `forum.pornbox.com/robots.txt` → **404** while
`www.analvids.com/robots.txt` → 200. A host that serves no robots.txt is either
freshly deployed or deliberately unindexed; either way its route map must come from
JS/config instead. Fetch robots.txt on all three hosts and record which answered.

## 2. Map the FULL redirect chain before probing any single node

Each hop is a separate trust boundary, and the chain tells you where authority is
delegated. The PornBox pre-auth spine, recovered with ~8 GETs:

```
/ucp.php?mode=login
  → 302 /auth/login?forum_auth=1&redirect=/auth_handler?forum_action=forum_sign_in&redirect_after=…
  → 301 /auth/browser-pin?redirect=<urlencoded /auth/login>
  → 200 (loads https://account.analvids.com/api/jdialog/btsporn.js, then location.href = redirect)
  → account.analvids.com/authorize?response_type=code&action=login&client_id=btsporn
       &scope=web&browser_pin=<pin>&redirect_uri=https://forum.pornbox.com/auth/response?redirect=…&client_id=btsporn
  → 301 /login
  → POST /login/attempt
  → 302 /auth/response?code=…            ← the callback that consumes the code
```

**The structural finding is in hop 2–3:** phpBB's *native* UCP login/register is
302-redirected into a custom bridge, i.e. **phpBB's own authentication is replaced
outright**. Any phpBB-auth bug class (session fixation in `ucp.php`, `sid` handling,
`form_token` reuse) is likely dead code on this install — do not spend the round
there. Conversely the custom bridge is now the single highest-value auth surface in
the estate, and it is *not* phpBB (so phpBB CVE templates don't apply to it).

**Prove the replacement, don't assume it.** `/ucp.php` → 302 into `/auth/login`;
`/ucp.php?mode=login` → 302; `/ucp.php?mode=register` → 302 into `/auth/register`.
Three consistent redirects = the bridge owns auth.

## 3. The doubled-prefix 301 is a rewrite-rule tell

`/api/auth/sso` → **301 → `/api/api/auth/sso`** → 200. A path that 301s to *itself
with a duplicated prefix* is a rewrite rule blindly prepending `/api` to a path that
already carries it. Two uses:

- **It reveals the real backend mount.** The terminus (`/api/api/auth/*`) is what the
  app actually routes; the pretty path is cosmetic. Probe the terminus.
- **It is a routing bug in its own right** (INFO/low): a naive prefix-prepend rewrite
  usually means the rule was written as `^/ → /api/` rather than
  `^(?!/api/) → /api/`. Such rules routinely also swallow `//`, `/./`, and
  backslash variants — worth three cheap probes, not a campaign.

Confirmed doubled-prefix routes: `sso`, `callback`, `token`, `refresh`, `session`,
`status`, `check`. Confirmed *non*-doubled (real routes): `login`, `register`,
`logout`, `auth_handler`, `response`, `browser-pin`. Record both lists — the split
tells you which namespace is proxied and which is first-party.

## 4. Host-disposition: two different 404 behaviours inside one estate

Enumeration strategy is host-specific. On this estate:

| Host | Unknown-path behaviour | Consequence |
|---|---|---|
| `forum.pornbox.com` | **soft catch-all** — `/sitemap.xml` → 200, 63,635 B, title `PornBox.com • Index page` (vs `/index.php` 63,620 B) | Status code cannot discriminate. Use body size + `<title>` as the differ. |
| `www.analvids.com` | **real 404** — unknown path → 404 + 31 KB `Page not found` page | Status code works. Enumerate normally. |
| `account.analvids.com` | **301 → `/login`** for most unknowns | Absorbs into the login gate; a 301 is not a route. |

Generalization of the existing catch-all pitfall: **run the random-path control on
every host before trusting a single status code**, and record the fingerprint
(`bytes` + `title` + `md5`) so a triager can reproduce your negatives.

## 5. The `redirect_uri` allowlist is an explicit host registry — inventory it

The broker validates `redirect_uri` by **exact host**, ignoring port and path
entirely. Measured (all unauthenticated, 1 req/s):

| `redirect_uri` host | Verdict |
|---|---|
| `forum.pornbox.com` (any path, `:8080`, `:443`) | **ACCEPTED** |
| `www.analvids.com`, `analvids.com`, `account.analvids.com` | **ACCEPTED** |
| `pornworld.com` | **ACCEPTED** |
| `ddfcontent.com` | **REJECTED** |
| `notforum.pornbox.com`, `xforum.pornbox.com`, `sub.forum.pornbox.com` | **REJECTED** (not a suffix match) |
| `forum.pornbox.com.evil.com`, `//evil.com/`, `evil.com#forum.pornbox.com`, `userinfo@evil` | **REJECTED** |

**The finding is the asymmetry:** `pornworld.com` and `ddfcontent.com` are *both* in
program scope, but only `pornworld.com` is registered at the broker. A scope asset
that the identity provider does not recognise is either (a) not yet onboarded — a
configuration gap, or (b) onboarded under a different `client_id`. Enumerate the
registered set (one request per candidate host) and publish the set difference
against the scope file. That table *is* a reportable deliverable.

Also note **ports are ignored** (`:8080` accepted) — so the allowlist is
host-string-only, and any future host added to it inherits an unvalidated path.

## 6. `browser_pin` is a cookie-bound nonce, not a credential — prove the binding

The previous round recorded "`browser_pin` is not validated at the broker". This
round established the **mechanism**, which changes how you write it up:

- Fetching `https://account.analvids.com/api/jdialog/btsporn.js` **with a cookie
  jar**, then again with the same jar → **identical `pin_hash` both times**.
- Fetching it five times **without** a jar → **five different `pin_hash` values**.
- ⇒ the pin is **stable per `JDIALOG3` cookie value**: a per-browser nonce, not a
  static secret and not a broker-validated credential.
- The JS sets it with `pin_domain = null` ⇒ `document.cookie` ⇒ **host-only for
  whichever document executes it**. Since the script is loaded cross-origin from
  `account.analvids.com` into a `forum.pornbox.com` page, the same cookie name
  `JDIALOG3` exists on two hosts with different values — a **shared-namespace
  cookie across the estate** (inference from `pin_domain=null` + the direct-fetch
  jar; capture the forum-side cookie to promote it to PROVEN).
- A garbage pin, an empty pin, and *no pin at all* all produce the same
  `301 → /login`. So the pin is genuinely not a gate at `/authorize` — but say
  *"not a gate at the authorize step; enforcement is downstream"*, not
  *"not validated"*.

**Templated-endpoint amplifier:** `/api/jdialog/btsporn.js` and
`/api/jdialog/box/1.js` are **byte-identical apart from the `pin_hash` line**. The
endpoint is templated on the path segment, so enumerating segments
(`btsporn`, `box/1`, `box/2`, …) enumerates **every site sharing the broker**, and
the only per-site secret is the initial pin. Free client inventory.

## 7. Pre-auth `/api/user-data` is an entitlement-schema disclosure amplifier

An unauthenticated "who am I" endpoint is not just a guest check — it names every
entitlement type in the system, which becomes your IDOR/authz target list.
`GET account.analvids.com/api/user-data` (no auth) returned:

```json
{"result":"ok","website_id":18,"client_id":"gtfpass","website_name":"AnalVids ID",
 "country_id":360,"geo_zones":[3,17],"currency_id":2,"temporary":true,
 "player_mode":"iframe","is_only_lp_user":true,"poll":"waiting_purchase",
 "disable_autologin":true,
 "goods":{"gallery_level":{…},"membership":{…},"box_space":{…},"memberships":[],
          "contents":[],"discount_level":[],"content_tickets":0,
          "free_tickets":{"has_free_tickets":false,"downloads_left":0,"amount":0,
                          "per_day":1},"has_any_goods":false,"has_lp_trial":false,
          "content_scopes":[],"has_tkt_membership":false}}
```

Every key under `goods` is a **named entitlement** (`gallery_level`, `membership`,
`box_space`, `content_tickets`, `free_tickets`, `discount_level`, `content_scopes`) —
that is the authz test matrix, handed over pre-auth. Also leaked: geo/zone/currency
resolution, `disable_autologin:true` (so autologin is off — don't hunt it), and
`per_day:1` free-download allowance.

**Cross-site ID mapping leak:** the `www` variant returned `source_website_id:19`
while the broker returned `website_id:18` — two different site IDs for what is
nominally one estate. Record the mapping; it matters for any cross-app session or
entitlement confusion.

## 8. GET-reachable validation oracles: the `/form` suffix convention and the odd one out

Form routes on `www.analvids.com` follow `/api/<name>/form` (HTML) +
`/api/<name>` (POST handler). Probing the POST handler with **GET** splits them:

| GET | Response | Read |
|---|---|---|
| `/api/sign-in` | `200` + `{"fields":{"login":{"isEmpty":…},"password":{"isEmpty":…},"csrf":{"isEmpty":"Csrf token is invalid. Refresh page and try again."}}}` | **Field inventory + CSRF enforced**, zero credentials sent |
| `/api/forgot-password`, `/api/support`, `/api/register` | `200` + `{"message":"Page not found"}` | GET not routed; the `/form` variant is the real path |

`/api/sign-in` is the odd one out: it runs full validation on GET. That gives you
the exact expected field names and confirms server-side CSRF enforcement **without
sending a single credential** — the cheapest possible auth-surface map. Do this on
every form endpoint before writing any login-flow test.

Same pattern on content endpoints — pre-auth parameter oracles:
`/thumbnail/missed-image` → `"Required parameter 'content_id' is not specified in
request"`; `/api/casting/thumbnail/click?casting_id=1` →
`{"message":"Duplicate casting click"}` (**stateful dedup, reachable pre-auth with
no auth**); `/api/casting/thumbnail/view?casting=1` and
`/api/casting/content/click/1` → `{"result":"ok"}`.

## 9. Cookie-flag audit — read every `Set-Cookie`, not just the session one

The phpBB install issues, over HTTPS:

```
phpbb3_hu43l_u=1;  phpbb3_hu43l_k=;  phpbb3_hu43l_sid=<32hex>
  expires=+1 year; path=/; domain=forum.pornbox.com; HttpOnly; SameSite=Lax
FORUMSESSID=<24 alnum>; path=/; HttpOnly
```

Findings in those two lines: **no `Secure` attribute on any of them** (issued over
HTTPS, downgrade-writable), **no `SameSite` on `FORUMSESSID`**, and a
**one-year session TTL** on a forum. The `phpbb3_hu43l_` prefix is the cookie-name
prefix; `_u=1` is the guest user_id.

The broker's `redirect_url` cookie is worse and only appears on ACCEPTED
`/authorize` probes:

```
redirect_url=<base64 of the full authorize URL incl. browser_pin>;
  Max-Age=86400; path=/; domain=account.analvids.com
  — no HttpOnly, no Secure, no SameSite
```

A 24-hour, JS-readable cookie carrying the complete authorize URL (pin included) on
the identity broker. Low severity on its own; it is the read-back half of any
broker-host XSS.

## 10. Template leakage in an XML error body

`GET www.analvids.com/sitemap.xml` → `200` with a 163-byte body that is the
**raw format string**, not a filled-in error:

```xml
<?xml version="1.0" encoding="utf-8"?><body><result>%s</result><message>%s</message>
<exception_type>%s</exception_level>%s</exception_level></body>
```

The XML error formatter is emitting its own `sprintf` template. Information
disclosure (reveals the internal error envelope shape) and a robustness bug. Grep
every XML/JSON error endpoint for literal `%s` / `%d` in the body — it is a
one-line check that most sweeps miss because they only read the status code.

## 11. Extra auth layers are a distinct disposition — record `401 + WWW-Authenticate` separately

`GET forum.pornbox.com/adm/index.php` → **`401` + `WWW-Authenticate: Basic
realm="Admin Area"`**, 12-byte body `Unauthorized`, `server: nginx`.

That is **nginx-level HTTP Basic Auth sitting in front of the phpBB ACP** — a second,
independent gate ahead of phpBB's own session authz. Consequences for the graph:

- It is a **separate credential store** from forum accounts. Basic-auth creds are
  frequently shared, static, and never rotated — a distinct brute-force/credential-
  stuffing surface (do not attack it in a read-only round; *record* it).
- It means the phpBB ACP's own authz is **defence-in-depth, not the perimeter** —
  an ACP bug that assumes "only admins reach this" is still gated, but a basic-auth
  leak bypasses phpBB entirely.
- Add `401 + WWW-Authenticate` to the host-disposition vocabulary alongside
  NXDOMAIN / 403-challenge / 522 / 530-1016: it is neither "down" nor "open".

## 12. Modified phpBB: fingerprint the MOD, and admit when the version is unknown

`forum.pornbox.com` carries **`Karma functions powered by Karma MOD © 2007, 2009
m157y`** in the footer. Two consequences:

- **Version fingerprinting by template is unreliable.** No `<meta name="generator">`,
  no version string in any body, only `Powered by phpBB`. Record the phpBB version as
  **UNKNOWN / NOT_CHECKED** — never "probably 3.3.x". A wrong version guess sends the
  whole CVE-matching phase at ghosts.
- **The MOD is its own attack surface.** Karma MOD is 2007–2009-era third-party code
  bolted onto phpBB; it is very likely unmaintained and is *not* covered by phpBB's
  own security history. `karma.php` is in the robots.txt disallow list — enumerate
  its parameters as a first-class target, separately from core phpBB.

## 13. Live-but-gated routes: the error text is the gate oracle

These all returned `200` with an "Information" page rather than 403 — the route is
live, the *content* is gated. The message tells you which gate:

| Route | Message | Gate |
|---|---|---|
| `/viewonline.php` | `You are not authorised…` + login link | auth |
| `/memberlist.php` | `You are not authorised to view the member list or profiles.` | auth |
| `/report.php` | `You must select at least one post to perform this action.` | input (needs a post id) |
| `/viewforum.php?f=2` | `The forum you selected does not exist.` | **id enumeration** — real ids are far higher (f=253 observed in archived HTML) |
| `/viewtopic.php?t=1` | `The requested topic does not exist.` | id enumeration |
| `/posting.php` | `The requested topic does not exist.` | id enumeration |
| `/mcp.php` | (login page) | auth |

`/feed.php` → **`200 application/atom+xml`, 28 KB, no auth** — a public feed is a
pre-auth content read surface (topics, post excerpts, usernames) and a cheap
enumeration source for real forum/topic IDs. Rank it as a sink.

## 14. Ranking sinks: reachability × impact, with the axes named

Score each node on two independent axes and publish the arithmetic so the ranking is
auditable:

- **Reachability** — how many trust boundaries must be crossed from an
  unauthenticated Internet position?
  - `0` = reachable with no credential and no state (`/feed.php`, `/api/user-data`,
    `/api/sign-in` GET, `/autocomplete`, `/thumbnail/missed-image`)
  - `1` = reachable after crossing one gate (the broker `/authorize` with a
    allowlisted `redirect_uri`; `/auth/browser-pin` with any `redirect` value)
  - `2` = needs a session or a second host (`/auth/response?code=`, `/member-area`)
  - `3` = needs the extra auth layer (`/adm/` behind Basic Auth)
- **Impact** — what the sink grants, against the asset's own `max_severity`:
  session/identity takeover > entitlement/IDOR > pre-auth content read >
  info disclosure > robustness.

Worked top-of-list from this estate (full graph in the round report):

| # | Sink | Reach | Impact | Why |
|---|---|---|---|---|
| 1 | `/auth/response` (OAuth callback) | 2 | identity | consumes `code`; the only node that mints trust |
| 2 | `account.analvids.com/authorize` | 1 | identity | host allowlist holds but path/scheme/port unvalidated; spans sibling brands |
| 3 | `/api/sign-in` (GET validation oracle) | 0 | credential | field inventory + CSRF state, no auth |
| 4 | `/api/user-data` (broker) | 0 | entitlement | full goods/entitlement schema pre-auth |
| 5 | `/auth/browser-pin?redirect=` | 1 | redirect | **`redirect` reflected verbatim into inline `location.href`** (PROVEN reflection; arbitrary scheme/host UNTESTED) |
| 6 | `/api/go-to-box` | 0 | redirect | `302 → www.analvids.com/`; the named untested link for the cross-app chain |
| 7 | `/feed.php` | 0 | content | 28 KB public Atom, no auth; real forum/topic IDs |
| 8 | `/adm/index.php` | 3 | admin | Basic-Auth gate in front of the ACP; separate credential store |
| 9 | `karma.php` (Karma MOD) | 1 | RCE-ish | 2007–2009 third-party MOD, unmaintained, params unknown |
| 10 | `/api/casting/thumbnail/click` | 0 | integrity | stateful dedup, pre-auth, no auth |

## 15. Honesty rules for a graph deliverable

- **A node you could not reach is NOT_CHECKED, never "clean."** Say which vantage
  limited you (GET-only, no session, no credential).
- **PROVEN reflection ≠ PROVEN redirect.** If a param lands verbatim in a
  `location.href` assignment but you only tested a benign value, write
  "PROVEN reflection / THEORETICAL open redirect" and name the exact next probe
  (`?redirect=javascript:alert(1)`, `?redirect=https://evil.example.com/`).
- **Publish the set differences.** scope-vs-broker-allowlist, templated-JS-sites-vs
  -scope, doubled-prefix-routes-vs-first-party-routes. Set differences are findings.
- **Every edge needs a captured request/response.** A graph edge asserted without
  an artifact is a guess; label it as such or drop it.
- **Rank, then stop.** The brief asks for a ranked inventory, not an exploit. Name
  the top 10, give each a reachability score, an impact score, and the one probe
  that would promote or kill it — then hand it to the next round.
