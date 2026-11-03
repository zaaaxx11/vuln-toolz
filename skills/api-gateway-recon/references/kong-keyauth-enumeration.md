# Worked example — Kong key-auth enumeration (api.mediamarktsaturn.com)

Session date 2026-10 · read-only, ≤1 req/sec · MediaMarktSaturn YesWeHack (authorized).
Target host is the **parent-group** domain — every finding flagged "confirm with program owner".

## Fingerprint
```
HTTP/2 401 · www-authenticate: Key
server: kong/3.14.0.12-enterprise-edition
x-kong-request-id / x-kong-response-latency: present
via: 1.1 google · alt-svc: h3
{"message":"No API key found in request","request_id":"<32hex>"}
```

## Credential location proof (placeholder values only)
| Location sent | Status | Body | Meaning |
|---|---|---|---|
| `apikey: X` | 401 | `Unauthorized` | correct location, wrong value |
| `x-api-key: X` | 401 | `Unauthorized` | correct location |
| `?apikey=X` | 401 | `Unauthorized` | correct location |
| `api-key` / `authorization` / `key` / `token` | 401 | `No API key found in request` | wrong location |

## Route enumeration — the blanket-401 result (NEGATIVE, high value)
30 curated paths (`/`, `/api`, `/api/v1`, `/api/v2`, `/v1`, `/v2`, `/v3`, `/graphql`, `/health`,
`/status`, `/metrics`, `/admin`, `/routes`, `/services`, `/consumers`, `/products`, `/search`,
`/catalog`, `/user`, `/users`, `/auth`, `/login`, `/checkout`, `/cart`, `/orders`, `/media`,
`/assets`, `/content`, `/dts-eu`, `/eco-eu`) → **all identical 401** `No API key found in request`,
same body length, only `request_id` differs.
⇒ Kong enforces key-auth globally (catch-all). Status-code route enum is unproductive here. Say so.

## Bypass / normalization probe matrix (observation only)

| # | Probe | Shape | Status | Observation |
|---|---|---|---|---|
| 1 | trailing slash | `/api/` | 401 | no change |
| 2 | double leading slash | `//api` | 401 | no change |
| 3 | double trailing slash | `/api//` | 401 | no change |
| 4 | dot segment | `/api/./` | 401 | no change |
| 5 | dot prefix | `/./api` | 401 | no change |
| 6 | **semicolon matrix** | `/api/..;/` | **302** | pre-auth normalization redirect (below) |
| 7 | encode 'a' | `/%61pi` | 401 | no change |
| 8 | encode slash | `/api%2f` | 401 | no change |
| 9 | **null byte** | `/api%00` | **400** | `Bad request request_id: …` — distinct class |
| 10 | case upper | `/API` | 401 | no change |
| 11 | case mixed | `/Api` | 401 | no change |
| 12-17 | `X-Forwarded-For/-Host/-Proto/-Path/-Prefix`, `X-Real-IP` | — | 401 | **all ignored** for auth (good posture) |
| 18 | trailing slash + `apikey: X` | — | 401 `Unauthorized` | key loc still honoured |
| 19 | **header case variant** `ApiKey: X` | — | 401 `Unauthorized` | header name **case-insensitive** |
| 20 | `?apikey=` (empty) | — | 401 | empty value = absent |

### 302 characterization
| Path | Status | Location |
|---|---|---|
| `/api/..;/` | 302 | `https://api.mediamarktsaturn.com/` |
| `/api/..;/v1` | 302 | `…/v1` |
| `/api/.;/` | 302 | `…/api/` |
| `/..;/` | 302 | `…/` |
| `/api/../` | 401 | (none — plain `..` does not redirect) |
| `/;` , `/;x` , `//` | 401 | (none) |
| `/api%00`, `/%00` | 400 | (none) |

**Verdict:** same-host redirect, every target re-401s ⇒ **no open redirect, no auth bypass** → INFO only.

## Passive subdomain map
- **crt.sh → HTTP 502 twice** (outage) ⇒ fell back to **certspotter** (200). Lesson encoded in SKILL.md.
- certspotter: 49 unique `*.mediamarktsaturn.com`, incl. non-prod `marketplace-dev/-int/-qa`,
  `fraud-dev`, `raw.payment-dev`, `gw.payment-test`, `gcgw.payment`, `sell-dev/-int/-qa`,
  `sasviya.dev`, `datahub-qa`, `dt-qa`, `monitoring.dmc-qa`, `gbs-workflows-predev`, Atlassian
  (`confluence./jira.atlassian`).
- urlscan (total=4): `auth.…media/login/user?t=<token>`, `delivery.…`, `mediawalletservice.…`.
- HTTP GET / classification:
  - **no cf-ray** (direct, higher value): `marketplace-dev/-qa` (istio-envoy 403), `fraud-dev`
    (istio-envoy 301 → `/ui/`), `raw.payment-dev` (istio-envoy 404), `gw.payment-test` (istio-envoy 404),
    `qrmaker` (IIS 10.0 200), `careers` (Apache 200), `auth` (Google Frontend 302 `/ui/idp/initiate`).
  - CF-fronted (cf-ray yes): `www`, `sell-dev/-qa`, `api.payment-dev`, `cms-images.mmst.eu`,
    `assets.mmsrg.com`, `mms-retailmedia.com`.
  - **IN SCOPE:** `delivery.mediamarkt.de` / `delivery.saturn.de` → Google Frontend 404, CSP refs
    `app1.falconide.com` (Netcore/Pepipost ESP). These are subdomains of in-scope `mediamarkt.de`/`saturn.de`.

## Ranked pre-auth hypotheses delivered
1. `delivery.mediamarkt.de` / `.saturn.de` [IN SCOPE] → ESP/delivery app, no CF → path enum of unsubscribe/token handling.
2. non-prod istio hosts (marketplace-dev/…, fraud-dev, raw.payment-dev, gw.payment-test) [parent] → no CF, dev/test diagnostics.
3. `auth.` IdP [parent] → `?t=<token>` query handling.
4. `api.…` path normalization [INFO] → `..;/` pre-auth 302, non-exploitable.
5. `qrmaker` IIS 10.0 [parent] → legacy stack quirks.

## Addendum (2nd subagent pass, same session) — two extra techniques

### GFE canonicalization 302 (distinct from the Kong `..;/` one)
`GET /%2e/admin` (junk `apikey: x`) → **`302 Location: https://api.mediamarktsaturn.com/admin`**.
Key tell: the response has **NO `server: kong` header** — it is the **Google Cloud HTTPS LB (GFE)**
canonicalizing the dotted segment *before* Kong sees it (`alt-svc: h3`, `cache-control: private`).
Redirect target `/admin` itself re-401s ⇒ same-host, non-exploitable, INFO only.
Contrast: `/..%2fadmin` → **`400 Bad request`** (Kong's own error, keeps `server: kong`).
⇒ Discriminate gateway-normalizer vs LB-normalizer by the presence/absence of `server: kong`.

### Pre-auth 200 non-prod UIs (calibration — do not overclaim)
Two non-prod hosts answered `200` **unauthenticated**:
- `datahub-qa.mediamarktsaturn.com` — open-source **DataHub** (`/config` → 200 JSON,
  `application=datahub-frontend`, `appVersion=1.6.0`; `/manifest.json` name "DataHub"). **BUT**
  `/api/graphql`, `/api/v2/graphql`, `/api/graphiql` → **401** (auth enforced). UI+config open,
  data API protected → report as low; explicitly state the API is NOT an unauth data leak.
- `gbs-workflows-predev.mediamarktsaturn.com` — "GBS Web Applications" SPA, CNAME
  `frontend-<hash>.feature.gbs-workflows.d-p.io` (vendor feature-branch env), no WAF → reachable non-prod.

### OAuth client_id harvest → DEV IdP discovery
Three non-prod hosts `302` into a **DEV IdP** (`auth-dev.mediamarktsaturn.com`, 35.227.192.202),
disclosing `client_id`s: `dt-qa` → `dynatrace_perf`; `int-catmansuite` → `catman_suite`;
`monitoring.dmc-qa` → `dmc_reverse_proxy`. The IdP host did **not** appear as a CT leaf — found only
via the redirects. Lead only; not probed.
