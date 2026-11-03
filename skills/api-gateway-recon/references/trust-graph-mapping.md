# Trust-graph mapping — cross-domain cookie trust + infra-plane separation

Session date 2026-10 · read-only GET recon, ≤1 req/sec, `X-Bug-Bounty: <handle>` header,
Chrome/131 UA. Target: Ayló/MindGeek adult-tube estate (pornhub/redtube/tube8/youporn +
premium + mainhub + thumbzilla). Deliverable: a machine-readable trust graph + ranked
top-10 sink list. Method is class-agnostic — reuse on any multi-brand web estate.

## Why a trust graph, not just a host list

A bug-bounty estate is a **set of trust boundaries**, not a list of hosts. The high-value
questions are: which hosts share session cookies, which are staging mirrors of production,
which sit on a *different* infra plane (AWS/GCP vs self-hosted), and which sink class
(upload / redirector / API / staging / filter-test) each reachable host is. Rank sinks by
reachability × impact, tag every claim VERIFIED / INFERRED / UNKNOWN.

## Technique 1 — Cross-domain cookie trust map from config disclosure (highest yield)

A 404/edge page on an uploader or app host often ships the **full SPA shell with inline
config**. On `upload.pornhub.com/` (HTTP 404 but a 1 MB pornhub.com shell) the inline
config disclosed:

```js
var COOKIE_DOMAIN = 'pornhub.com';
var baseUrl = 'https://www.pornhub.com';
var cbConsent = '3';
var essentialCookiesListAll = JSON.parse('{...}');   // ← the trust map
```

`essentialCookiesListAll` is a JSON map of **every third-party domain the core will set/read
cookies on**, with the cookie names marked `essential`. This is the trust graph's crown
jewel — it names the cross-domain SSO / age-verification / redirect broker that spans the
whole estate. Extract it locally (no extra request):

```python
import re, json
body = open("upload_404.body", encoding="utf-8", errors="replace").read()
m = re.search(r"essentialCookiesListAll\s*=\s*JSON\.parse\('(.*?)'\)", body, re.S)
cfg = json.loads(m.group(1).encode().decode('unicode_escape'))  # unescape JS string
# cfg = {"pornhub.com": {...}, "pornhubpremium.com": {...}, "thumbzilla.com": {...}, ...}
```

**What to look for in the map:**
- Cookie names like `stage_sso_token`, `password_reset_hash`, `desired_username`,
  `email2faModal`, `premium_redirect`, `avukredirecturl`, `accessPH`/`accessAgeDisclaimer*`
  shared across >1 domain ⇒ a **shared SSO + age-verification + redirect broker**.
- `ats`, `atsd/atsm/atstrackPiece1-4` on a premium domain ⇒ JWT-shaped entitlement token.
- Ad/tracker domains with an empty list `[]` ⇒ allowlisted, no cookies (ad plane).
- A domain you did **not** expect in the estate (e.g. `shorties.ai`, `modelhub.com`) ⇒
  a sibling brand sharing the session jar — expand scope.

**Other inline-config disclosures worth grepping every HTML/JS shell for:**
`COOKIE_DOMAIN`, `baseUrl`, `cbDomainName`, `cbConsent`, `isLoggedInUser`,
`isPlatformMobile`, `isPremiumDomainBanner`, `window.__NUXT__`, `__NEXT_DATA__`.

## Technique 2 — Infra-plane separation (fingerprint every host, then bucket)

Classify each reachable host by `server:` + `via:` + `x-cache:` + `cf-ray`/`x-amz-cf-pop`.
Hosts on a **different plane than the core** are a distinct trust boundary and usually less
defended. On this estate the planes were:

| Plane | Signature | Example hosts | Note |
|---|---|---|---|
| Self-hosted core | `server: openresty`, no CF | www.* tubes, api.pornhub.com | no WAF on our egress |
| Static/JS CDN | `ei.phncdn.com` / `ei.rdtcdn.com` / `ea.t8cdn.com` / `ea.ypncdn.com` | JS/CSS | shared build pipeline (`?cache=YYYYMMDDNN` / `v=<hash>`) |
| **AWS redirector** | `server: awselb/2.0` + `via: 1.1 ...cloudfront.net` + `x-amz-cf-pop` | `url.pornhub.com`, `url.mainhub.com` | **only AWS surface** — separate boundary; 404 body `Path doesn't exist - DC04` |
| Origin (direct-hit) | `400 Bad request <dedXXXX>` or `403` nginx | `origin/sorigin/vorigin.pornhub.com`, `vortex.pornhub.com` | expect edge/Host headers; reachable only via CDN |
| Staging (Basic-auth) | `401` + `www-authenticate: Basic realm="..."` | `api-stage{,2,3}.pornhub.com`, `stage{2,11,13}-api.redtube.com`, `www-stage.pornhub.com`, `stage.redtube.com` | **two distinct realms = two staging deployments** |
| GCP-hosted | `server: Google Frontend` | `document-review.pornhub.com` | no WAF; ships an Uppy upload widget |
| Outsourced | `server: cloudflare` → 302 to vendor | `form.pornhub.com` → zoho.com | form builder |

**The `..;/` / dotted-segment 302 and the blanket-401 catch-all** from the main SKILL apply
here too — run those probes on any API-plane host you find.

## Technique 3 — 401 signature analysis (real gate vs bypassable shell)

A `401` is only a finding if it is a **real** auth gate. Discriminate:

- **Real Basic-auth:** response carries `www-authenticate: Basic realm="<name>"` and a
  stock nginx/openresty 401 body. The realm string is a fingerprint — **two different
  realms (`Authorization Required` vs `stage-auth`) = two separate staging deployments**
  with independent credentials; a leak on one does not imply a leak on the other.
- **Bypassable JS gate / SPA 200-catch-all:** a `200` with identical byte-size HTML for
  every path (see the SPA-200-catch-all section in the main SKILL) — not a real gate.
- **Intermittent reachability:** a host that answers `200` once then `connect-refused`
  (e.g. `testfiltering.pornhub.com`, nginx) is **UNSTABLE**, not dead — flag it, retry from
  a different egress before declaring it unreachable.

## Technique 4 — Redirector / uploader logic is UNKNOWN from the root

`url.pornhub.com/` and `url.mainhub.com/` return `404 Path doesn't exist - DC04` for `/`,
`?u=`, and `?url=`. **Do not conclude "no redirector"** — the real redirect path lives at a
deeper route not enumerable by GET-guessing. Harvest the path format from the **affiliate
links** embedded in the tube homepages (`a.adtng.com`, `ar.redtube.com`, `ar.pornhub.com`,
`ads.trafficjunky.net` are the affiliate hosts that feed it), then test open-redirect/SSRF
on the discovered path. Same for uploaders: the upload form action is path-gated behind
login; the 404 shell proves the host is live and wired into the session, not that upload is
reachable pre-auth.

## Trust-graph JSON schema (deliverable)

```json
{
  "nodes": [
    {"id":"upload.pornhub.com","host":"...","tier":"T1|T2|CT","type":"upload_app|api|redirector|stage_api|origin|...",
     "status":"200|401|400|403|000","server":"openresty|awselb/2.0|Google Frontend|nginx|",
     "waf":"NONE|CLOUDFLARE_INTERSTITIAL","reach":"public|gated-basic-auth|direct-400|forbidden|intermittent|dead|unknown",
     "note":"one-line evidence"}
  ],
  "edges": [
    {"src":"upload.pornhub.com","dst":"pornhub.org","flow":"essentialCookiesListAll: shares session/age-verif cookies cross-domain"}
  ]
}
```

Node `type` vocabulary that worked: `web_app, api, upload_app, redirector, filter_test,
paywall_login, doc_upload, stage_api, stage_web, origin, encoder, file_storage, streaming,
forms, partner_portal, cms, cdn, email, telephony`. Edge `flow` strings carry the evidence
(e.g. `frontend calls /api/v1/*`, `sets ats JWT`, `realm=stage-auth`).

## Top-10 sink ranking format

Rank by **reachability × impact**, and for each sink give: status/server/waf, raw evidence,
why it ranks here, and a **red-team next step** (explicitly out of scope for the read-only
architect track). Tag each line VERIFIED (raw capture on disk) / INFERRED / UNKNOWN. Keep an
explicit **gaps** section (intermittent hosts, unknown redirector logic, partial JS coverage)
and state that no POST/exploit testing was performed.

## Worked artifacts (this session)
- `/home/ubuntu/ph-hunt/architect/trust_graph.json` — 35 nodes / 40 edges
- `/home/ubuntu/ph-hunt/architect/ARCHITECT_REPORT.md` — full report + top-10
- `/home/ubuntu/ph-hunt/architect/upload_config.json` — leaked `essentialCookiesListAll`
- `/home/ubuntu/ph-hunt/architect/probes/*.body|hdr` — raw captures

## Pitfalls
- **Do not report a 404-on-root as "host dead"** — an uploader 404 can serve a 1 MB shell
  with the cross-domain cookie map. Read the body before classifying.
- **Do not guess redirector paths** — harvest them from affiliate links; root 404s are
  expected and non-informative.
- **Two 401 realms = two deployments** — never assume one staging fleet from similar hostnames.
- **Intermittent ≠ dead** — retry before writing "unreachable"; note the egress.
- **Pacing:** a per-host `sleep(1)` loop over ~300 hosts exceeds inline tool timeouts — run
  long sweeps as a background script with `notify_on_complete` and flush one line per host
  (see `predator-recon` "Pacing" pitfall).
