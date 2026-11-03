# Next.js middleware-gated admin dashboard — matcher mapping, cookie leak, open-endpoint triage

Worked case: `xxx.current.finance` (Oct 2026) — a Next.js App Router + **Turbopack** internal admin
dashboard behind Cloudflare, briefed to find an auth bypass yielding a valid admin session without the
password, then an admin endpoint that executes code. Outcome: **no bypass, no RCE** — but three
reportable informational/low findings and a clean negative-result methodology that generalizes.

This is the **middleware-gate** pattern, distinct from `nextjs-bff-proxy-and-outbound-fetch.md`
(which covers a rewrite-proxy *hop* between two hosts). Here the gate is `middleware.ts` on the same
host, in front of both pages and API routes, with no upstream hop to probe.

## 1. Map the middleware matcher boundary BEFORE claiming any bypass

The single highest-value move. A middleware `matcher` is a path pattern, and **what it does NOT match
falls through to Next.js routing** — which produces a *different* status than the gate. That
difference is how you tell "gated" from "matcher gap" from "ungated by design".

Probe each candidate route with these variants (one request each, ≤1 req/s, `--path-as-is` for the
traversal rows):

| Variant | Status | Meaning |
|---|---|---|
| `/route` (exact) | `307 → /login?from=...` | **gated** — middleware matched |
| `/route/` (trailing slash) | `308 → /route` | Next.js trailing-slash normalization, then re-evaluated |
| `//route` (double slash) | `308 → /route` | protocol-relative normalization, then re-evaluated |
| `/route.json` / `/ROUTE` / `/route%20` | `307` | matcher still matches (extension/case/encoding-insensitive) |
| `/route/x` (extra segment) | `404` (full Next.js not-found page) | **matcher gap** — gate never ran |
| `/route/./x`, `/route//x` | `404` / `308` | same class |
| `/route` that is *intentionally* public | `200` | ungated by design |

**The 404-vs-307 split is the finding-shaped signal.** On the worked case, every `/api/statistic/*`
sibling returned `307`, but `/api/statistic/liquidation-health/<anything>` returned `404` with a
**46,362-byte** Next.js not-found page. That proved the matcher *excludes* the
`liquidation-health` prefix rather than default-denying — a coverage gap, reportable as
informational/hardening, **not** an auth bypass.

### The control that decides "gap" vs "bypass" (run it, always)

A matcher gap is only interesting if traversal *through* it reaches a gated route. Test both
directions:

```
/api/statistic/liquidation-health/../lend-summary        → 404   (traversal from ungated prefix: dead)
/api/statistic/liquidation-health/%2e%2e/lend-summary    → 404   (percent-encoded: dead)
/api/statistic/liquidation-health/..%2flend-summary      → 404   (mixed: dead)
/lend-summary/../lend-summary                            → 307   (traversal from gated prefix: still gated)
/api/auth/session/../lend-summary                        → 307   (still gated)
```

If traversal from the ungated prefix yields `404` and traversal from a gated prefix still yields
`307`, **the gate holds** — write the gap up as a hardening note, not a bypass. Also expect
Cloudflare to intercept some shapes outright (`..;` → `403`, ~5 KB CF error page) — that is the WAF,
not the origin, and not a finding.

### Normalization is not a bypass (do not overclaim)

`/api/auth/./session` → `200` and `/api/auth/../auth/session` → `200` look like wins. They are
Next.js collapsing the path to the *same ungated route* that `/api/auth/session` already serves
without auth. Confirm by checking the un-normalized path is already ungated; if it is, the normalized
`200` proves nothing.

## 2. The real session cookie name leaks from the logout route

The client bundle only exposes the **localStorage** key (e.g. `pebble_insight_app_access_v1`), which
is *not* the cookie. The actual cookie name is disclosed by the logout handler's `Set-Cookie`:

```
GET /api/auth/logout
→ 307
  location: https://localhost:5000/login
  set-cookie: app_access=; Path=/; Secure; HttpOnly; SameSite=lax
```

Two findings from one request:

- **Cookie name** (`app_access`) — needed before any forgery attempt is meaningful. `HttpOnly;
  Secure; SameSite=lax` is correct; note it as a positive.
- **Internal origin leak** — `location:` is an absolute URL built from a configured internal base
  (`https://localhost:5000`) instead of a relative path. Report as low-severity info disclosure:
  confirms a local service and port. Mitigation is a one-liner (return `Location: /login`).

**Method:** `curl -s -D - -o /dev/null <host>/api/auth/logout` and read `set-cookie` + `location`.
Identical with and without a cookie present, so it needs no session.

## 3. Triage an unauthenticated endpoint: bug or by design?

An open endpoint on an *admin* host looks like a bypass until you root-cause it. The decisive test is
whether the **public** site's bundle calls it:

```js
// extracted from the PUBLIC dashboard bundle, not the admin one
async function checkLiquidationApiAlive(){
  try{
    return {name:"Liquidation",
      status:!!(await axios.create({
        baseURL:"https://xxx.current.finance", timeout:5e3
      }).get("/api/statistic/liquidation-health")).data?.data?.status}
  }catch{ return {name:"Liquidation", status:!1} }
}
```

If a public bundle has `baseURL:"https://<admin-host>"` and GETs that path, the endpoint is an
**intentional public liveness probe** feeding a status panel — report as informational at most, and
say so explicitly so a downstream agent does not re-report it as a bypass.

Then confirm it is genuinely inert before closing it:

- Parameter probes (`?cmd=`, `?debug=`, `?callback=`, `?name=`, `?status=`) → byte-identical constant.
- Method matrix → `GET 200`, `HEAD 200`, `OPTIONS 204`, `POST/PUT/DELETE/PATCH 405`.

If all of that holds, there is no injection or write surface and the endpoint is a read-only constant.

## 4. Prove the backends are separate (kills the "shared API" theory)

Hit the *same* API path on the admin host and its public sibling:

```
dashboard.current.finance/api/lend/summary   → 200 {"code":0,...,"data":[{"name":"MainMarket",...}]}
xxx.current.finance/api/lend/summary          → 307 /login?from=%2Fapi%2Flend%2Fsummary
```

Different answers ⇒ separate apps, separate gates. Do not assume an endpoint open on one host is open
on the other; test each host independently.

## 5. A middleware-gated admin app usually has NO client-reachable data API

String-extract the admin bundle (`grep -ohE '"/api/[a-zA-Z0-9_./{}$-]+"' *.js | sort -u`). On the
worked case the *only* client-referenced API paths were:

```
/api/auth/login   /api/auth/logout   /api/auth/restore   /api/auth/session
```

All dashboard data (23 page routes: lend-summary, liquidation-analysis, report/*, vault-monitor, …)
is **server-side rendered behind the gate**. Consequence: there is no client-reachable admin API
surface to attack at all. The hunt collapses to (a) the four auth endpoints and (b) the matcher
boundary. Say this explicitly in the report — it explains *why* the negative is credible rather than
merely unproven.

Also check for an execution primitive while you are in the bundle: app-level `exec` / `spawn` /
`child_process` / `revalidatePath` / `"use server"` / server-reference IDs. On the worked case every
hit was Next.js framework machinery (`revalidateEntireCache`, `clearCacheNodeDataForSegment`,
`hmrRefreshReducer`, `serverActionReducer`, `actionAsyncStorage`) — router/cache internals, zero
app-level invocation. Turbopack builds also **do not ship** `/_next/static/BUILD_ID`,
`buildManifest.js`, `app-build-manifest.json`, `routes-manifest.json` (all `404`), so do not spend
requests there.

## 6. Timing-oracle honesty under a no-brute-force budget

With a small permitted sample, you can report **"no oracle observed"** but never **"no oracle
exists"**. Measured on the worked case (5 candidates, one attempt each):

```
password=""         → 401 {"ok":false,"error":"Invalid password"}  t=0.366535
password="admin"    → 401 {"ok":false,"error":"Invalid password"}  t=0.160279
password="password" → 401 {"ok":false,"error":"Invalid password"}  t=0.340868
password="current"  → 401 {"ok":false,"error":"Invalid password"}  t=0.303203
password="pebble"   → 401 {"ok":false,"error":"Invalid password"}  t=0.342310
```

Spread 0.16–0.37 s with no correlation to correctness ⇒ consistent with network jitter. Correct
wording: *"no timing oracle observed within the permitted sample budget; absence not proven."* Pair it
with the uniform error body (`{"ok":false,"error":"Invalid password"}` for every wrong password,
`{"ok":false,"error":"Invalid JSON"}` only for a malformed body) — the error-shape channel is the
cheap oracle and it was flat too.

## 7. Report shape for a clean negative

A "no RCE, no bypass" result is a deliverable, not a failure. Structure that survived review:

- **VERDICT first**, leading with the negative, then the 2–3 genuine informational/low findings.
- **CLAIM vs PROOF table** — one row per claim, each with the real response; mark negatives
  `CONFIRMED (negative)` and the headline objective `NOT FOUND`.
- **REFUTED** — every near-miss killed, *with the evidence that killed it*. Include your own
  harness artifacts here so they are never propagated.
- **UNTESTED** — handoff items, highest-value first. For a gated admin app the top item is always the
  **post-authenticated surface** (unmapped by design, since no session was obtained).
- **CONFIDENCE** with explicit caveats: sample budget, unobserved token format, unmapped post-auth
  surface. State what the negative does *not* prove.
