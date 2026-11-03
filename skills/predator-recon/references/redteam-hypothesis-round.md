# Red-Team Hypothesis Round — attack fragile assumptions

Methodology + a fingerprint taxonomy of attack-surface signatures, distilled from an
authorized bug-bounty round against a multi-brand adult-tube network (MindGeek-style:
pornhub/redtube/tube8/youporn/mainhub). Use this when a program hands you a subdomain
list and asks you to "attack the fragile assumptions" rather than run a scanner.

## The round loop

1. **Enumerate hypotheses, one per fragile assumption** (open redirect on url.* hosts,
   reflection/SSRF oracle on a test host, API surface + CORS, staging-auth mechanism,
   edge-host behavior, cookie/session surface).
2. **Attack each hypothesis to refutation or confirmation** — one request shape at a
   time, innocuous target (`https://example.com`), no brute force, no credential
   spraying. Honor the operator's rate limit literally (`sleep 1` inside the helper,
   not between commands).
3. **Capture verbatim request+response to disk** for every claim. A claim without a
   raw artifact is a rumor.
4. **Classify every hypothesis**: PROVEN (raw artifact) / THEORETICAL (needs a
   precondition you couldn't obtain) / **REFUTED (disproved with evidence — keep the
   refutation, it is a finding)**.
5. **Publish a FLOOR** if nothing chains: coverage log (R1..Rn), why the floor is
   structural, what human input would unblock it. Never pad a report to hide an empty
   result.

## Fingerprint taxonomy (reusable recon signatures)

These are class-level signatures, not target-specific. Bucket any new host into one
before spending effort.

### Dead / retired URL-shortener (refutes open-redirect hypotheses cheaply)
- `server: awselb/2.0`, `x-cache: Error from cloudfront`, `via: ...cloudfront.net`
  (CloudFront → ALB), `content-type: text/plain`.
- **Every** path and query-param shape returns the same 404 with a fixed body
  (`Path doesn't exist - DC04`, 25 bytes) and **no `Location` header**.
- Lesson: a `url.<brand>.com` subdomain is not automatically a redirector. Probe
  ~13 param names (`url,u,next,redirect,target,to,link,continue,return,dest,g,path,
  site,uri`) + path forms (`/https://example.com`, `//example.com`, `/\/example.com`,
  `/curl`, `/url`, `/links`, `/redirect`) once; if all 404 identically, the service is
  a dead edge and the open-redirect hypothesis is REFUTED before you burn more time.

### CNAME-to-third-party trap (do not treat as first-party surface)
- A subdomain under the target apex can be a **CNAME to an unrelated vendor**
  (seen: `testfiltering.pornhub.com` → `testfiltering.com`, 194.164.92.131).
- Verify with `dig <host> CNAME +short` / `nslookup -type=CNAME` **before** probing.
- Such hosts are usually static beacons (e.g. an adult-content-filter test page that
  `postMessage`s a token to the vendor origin). No input is reflected, no SSRF oracle.
- CORS on these is typically pinned to the vendor origin (`access-control-allow-origin:
  http://testfiltering.com` + `allow-credentials: true` + `frame-ancestors`) — fixed
  origin, so **not** attacker-controllable and not exploitable. Do not mistake a
  credentials:true CORS for a misconfig when the origin is a constant.

### CORS preflight wired BEFORE the auth gate (the live attack class)
- A host that returns `401 www-authenticate: Basic` on GET/POST may return
  **`HTTP/2 200` with `access-control-allow-origin: *`** on `OPTIONS` — the CORS
  preflight handler runs before the Basic-auth gate.
- Response also leaks `access-control-allow-methods` (e.g. `POST,GET`) and
  `access-control-allow-headers` (e.g. `Content-Type,Content-Length,Referer,User-Agent,Origin`),
  and this holds even with `Access-Control-Request-Headers: authorization`.
- **Severity is LOW/informational unless `access-control-allow-credentials` is also
  set**: the preflight body is 0 bytes (no data), GET/POST still 401, and without
  allow-credentials there is no authenticated cross-origin read. Report it as
  method-confusion on the auth gate + method/header disclosure, not as a data breach.
- Test shape: `curl -X OPTIONS -H "Origin: https://evil.example" -H
  "Access-Control-Request-Headers: authorization" https://host/any/path`.

### Two-shape staging-auth fingerprinting
- **Shape A (openresty)**: `401`, `www-authenticate: Basic realm="Authorization
  Required"`, `server: openresty`, sets a load-balancer affinity cookie
  (`RNLBSERVERIDPH=<id>; path=/`) + `__s`/`__l` tracking cookies. OPTIONS bypasses
  (see above). TRACE → 405.
- **Shape B (minimal)**: `401`, `www-authenticate: Basic realm="stage-auth"`, **no
  `server` header**, **no cookies**, body `You need a valid user and password...`.
  Enforces 401 on **all** methods including OPTIONS — no bypass.
- Empty basic-auth creds (`-u ":"`, `Authorization: Basic Og==`) do **not** bypass
  either shape — don't waste requests on it.
- Fingerprinting the shape tells you which hosts are worth the OPTIONS-bypass test
  (only Shape A) and which are hard gates (Shape B).

### Three "stage host states" and what each means
- **401 (both shapes above)** — auth gate is live and enforced.
- **503 "Service Unavailable / No server is available"** — a load-balancer with **no
  healthy backend**. **No auth is enforced at the LB**; the gate only appears when a
  backend comes up. Sets `__s`/`__l`. Revisit if the backend recovers — this is the
  misconfiguration lead.
- **NXDOMAIN from your vantage** — internal-only DNS; the name exists in the subdomain
  list but doesn't resolve publicly. Not a finding, just a dead end from this egress.

### Live static server behind a directory-deny
- `/` → 403 (nginx, directory-level deny) but `/robots.txt` → **200** (static file
  serving works, `last-modified` may be ancient, `etag` present, `accept-ranges`).
- OPTIONS → 405, HEAD `/` → 403, unknown paths → 404. The 403 is path-specific, not
  a global block — enumerate static files before concluding the host is closed.

### Signed-token-gated edge (always 400)
- Every request shape (`/`, `/healthz`, `?id=`, `/video?viewkey=`, `/embed/<id>`)
  returns `400 Bad request / Your browser sent an invalid request. <br><ded-id>` with
  `cache-control: no-cache`, no `server` header. The `<ded-id>` varies per request.
  Needs a signed token you don't have — REFUTE for the round, don't grind.

### Pre-auth cookie jar + per-request token rotation (session surface)
- An API gateway may set a large cookie jar on an **anonymous GET /**: `ua`,
  `platform`, `bsdd`, `ss`, `sessid` (1yr), `fg_<hash>` feature-gates (~30d),
  `comp_detect-cookies`, `__s`/`__l`, and an HttpOnly rate-limit token
  `rp=<int>:<base64sig>;path=/`.
- `sessid` / `ss` / `rp` **regenerate on every request** — a per-request token-rotation
  surface worth a dedicated session study. Note method-dependent routing too: the same
  host may answer GET → "Not Found" but POST → "Down for Maintenance 403".

### Wildcard DNS to a PaaS (Vercel / Netlify / Pages) — resolving is not existing
- **Every** candidate subdomain resolves (`dig` returns PaaS anycast IPs round-robin), so a
  20-name guess list looks like a 20-host estate. It is one wildcard record.
- Discriminator: all names return the same platform catch-all (`server: Vercel` + identical
  `404` shell / `DEPLOYMENT_NOT_FOUND`). No per-host content, no per-host cookies.
- Rule: `dig` success proves only the wildcard. Probe `/` on 2–3 names, classify the edge, and
  stop enumerating once the bodies are byte-identical — the estate does not exist.
- Corollary: a `project-<deployment-id>.vercel.app` alias guess is worth **one** request; if it
  answers `DEPLOYMENT_NOT_FOUND`, the deployment is not publicly aliased — move on.

### Server-advertised rate limits name their own scope
- Read `ratelimit-policy` / `ratelimit-limit` / `ratelimit-remaining` / `ratelimit-reset`
  before designing any credential or fuzz loop. Observed on one backend: `/health` advertised
  `200;w=900` (global, shared across routes — the counter visibly decrements from unrelated
  probes) while `/api/admin/login` advertised `10;w=900`. That single header pair told us the
  login brute-force budget with zero guesswork.
- A shared global counter also means your own recon burns the same budget — pace accordingly
  and re-read `ratelimit-remaining` before a sensitive batch.

### Middleware-protected page ≠ unreachable page (percent-encoding)
- `GET /admin/x` → `307 /login`; `GET /%61dmin/x` → `200` with `x-matched-path: /admin/x`.
  Matchers compare the raw path; the router normalizes it. The bypassed response is the
  prerendered shell and leaks the route's chunk manifest → full client bundle recovery.
  Full recipe: `web-api-recon` → `references/nextjs-admin-bundle-recovery.md`.


## Evidence-capture pattern (the reusable helper)

One paced curl per test, verbatim request+response to a named file, operator header on
every request. `sleep 1` lives **inside** the helper so pacing survives any call site.
See `scripts/rt.sh`. For a multi-host sweep (dozens of hosts), write the loop to a
script and run it `background=true` + `notify_on_complete=true`, flushing one result
line per host so a kill preserves partial output — never restart the whole sweep, just
re-run the failed tail.

## Anti-delusion rules (cheap checks before you claim)

- A `200` from a proxy/reader is not a bypass — grep the body for an expected marker
  before recording a PASS (status-code-only checks manufacture bypasses).
- A host being reachable is not a config weakness — classify the edge (`server:` header,
  CloudFront vs Akamai vs openresty) before calling one locale the weak link.
- `access-control-allow-origin: *` with no `allow-credentials` is disclosure, not a
  cross-origin data read.
- Reachability ≠ authorization: intersect discovered hosts against the program scope and
  report the intersection, never the raw enumeration.
