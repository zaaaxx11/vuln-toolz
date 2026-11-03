# Pre-auth GraphQL introspection + SPA endpoint mining

Worked run (MediaMarkt/Saturn, YesWeHack). Pacing 1 req/s. Reproduce the method, not the hosts.

## The tactic

Once the CT/DNS sweep yields a reachable **in-scope, non-CF** host that serves an SPA, do NOT stop at
"SPA, no surface". Mine the bundle and probe the API:

1. `GET /` → note `<title>` + asset list (`/assets/index-*.js` = Vite; `main.*.js` + `polyfills.*` +
   `runtime.*` = Angular; `_next/` = Next).
2. Pull the bundle and grep for the API base + client type:
   - `apollographql-client-name` / `go.apollo.dev` ⇒ **Apollo = GraphQL client**.
   - `uri[:=]\s*["']([^"']+)` ⇒ the GraphQL URI (seen: `/graphql`).
   - `["'](/api/[^"']+)["']` ⇒ REST paths.
   - `["'](https?://[a-z0-9.-]+\.[a-z]{2,})["']` ⇒ **off-domain backends** (vendor APIs).
3. Probe the GraphQL endpoint pre-auth, GET first then POST.

## The discriminator that saves the report (do this before claiming anything)

| Request | Response | Meaning |
|---|---|---|
| `GET /graphql` | `400 {"error":"GraphQL query is missing."}` | **endpoint EXISTS** — a GET handler is wired |
| `GET /graphql` | `200 text/html` (SPA shell) or `404` | no GraphQL here — the SPA catch-all ate it |
| `POST /graphql` `{"query":"{__typename}"}` | `200 {"data":{"__typename":"Query"}}` | **executing pre-auth** |
| `POST /graphql` `{"query":"{__schema{queryType{name}}}"}` | `200 {"data":{"__schema":{...}}}` | **full introspection pre-auth ⇒ finding** |

Worked result: `store.<brand>.de` (in-scope, `Google Frontend`, **no CF**) → `GET /graphql` `400`, then
`POST` `{"query":"{__schema{queryType{name}}}"}` → `200` with schema. Unauthenticated introspection on a
customer-facing production host. Contrast: `datahub-qa.<group>.com` `/api/graphql` → `401` (gated) —
**always probe; do not assume either way from the SPA alone.**

Only introspection (`__schema`) is OBSERVATION. Do NOT enumerate/execute business queries beyond the
schema skeleton without explicit authorization — that crosses from recon into exploitation.

## Off-domain backend pattern (vendor rewards/incentive apps)

A brand SPA whose backend is a **vendor** domain is a scope question *and* a trust boundary:

- `vorteile.<brand>.de` → title **"Incentify"** (Angular) → bundle pointed all API calls at
  **`https://api.praemienkontor.de/api`** (third-party incentives provider).
- Endpoint names in the bundle: `CAMPAIGN_GET_BY_TOKEN`, `ADDITIONAL_INFO_GET_BY_TOKEN`,
  `cash-back-accountOwner`, `user-token` ⇒ **token-in-path endpoints** (IDOR/token-leak class, worth a
  manual authz test if the vendor is in scope).
- Vendor host behaviour: `/api` `401 {"code":401}`, `/health` `417` with a JSON component list
  (`[{"name":"cdn","result":true},...]`), unknown paths `404 {"message":"Not found","code":404}`.
- A **vendor** domain is usually OUT of the program's scope even when the brand host is in scope — flag
  it, and report only the in-scope brand host's behaviour.

## Ordering lesson (cost me the run's budget)

The parent-group estate (`api.<group>.com`, grafana, sasviya, datahub, istio non-prod) is larger and
more seductive, but every finding there needs program-owner scope confirmation ⇒ possibly unreportable.
**Rank by `reportable × reachable × auth-gap`: reachable IN-SCOPE non-CF hosts first.** Here the only
live pre-auth finding (`store.<brand>.de` GraphQL) sat in-scope and was found last.
