# Next.js Admin Panel — Post-Auth Surface Hunt (no credentials)

Companion to §4.15 theory **T1** (admin panel takeover) and T2 (web2 backend). Use when the
target is a password-gated internal dashboard (`xxx.<apex>`, `/login`) and you have **no
session**. Budget ~15 min. No brute force, no destructive actions, every claim needs a real
response or file:line.

The honest verdict is usually **"no unauthenticated execution primitive"** — and that is a
complete deliverable when the refutations are documented. Worked on `xxx.current.finance`
(Next.js 15 + Turbopack, Cloudflare-fronted, password-only auth).

---

## 1. First move: download the login page's chunk list, not just the HTML

`curl -s <login-url>` and grep the `<script src>` tags. That gives you the complete
**unauthenticated** chunk inventory — everything the login page and app shell load before
auth. On the worked target that was 16 chunks / 767 KB, and it was *sufficient* to answer
most of the post-auth questions negatively.

```bash
curl -s "https://xxx.current.finance/login" -H "User-Agent: <browser UA>" \
  | grep -oE 'src="[^"]+"'
# -> /_next/static/chunks/9c6c2449860630bc.js, ... (16 chunks)
```

Then bulk-download and grep locally. **Do not try to enumerate more chunks** — see §5.

---

## 2. The auth endpoint behaviour matrix (run this first, it is 6 curls)

Probe paced (~1 req/sec, `sleep 1` between). The *shape* of the responses is the finding.

| Probe | Expected-good | What a BAD answer looks like |
|---|---|---|
| `POST /api/auth/login` `{}` | 401 `{"ok":false,"error":"Invalid password"}` | 500 / stack trace |
| `POST /api/auth/login` empty body | **400** `{"ok":false,"error":"Invalid JSON"}` | 401 (parse after compare) |
| `POST /api/auth/login` `{"password":["a","b"]}` | 401 "Invalid password" | 500 (type confusion) |
| `POST /api/auth/login` `{"password":{"length":1}}` | 401 "Invalid password" | 500 |
| `POST /api/auth/login` no `Content-Type` | 401 (body still parsed) | 415 |
| `GET /api/auth/login` | **405** | 200 |
| `GET /api/auth/restore?token=x` | **405** (POST-only) | 200 |
| `POST /api/auth/restore` `{"token":""}` | 401 `{"ok":false,"error":"Invalid or expired session"}` | distinct "malformed" error |
| `POST /api/auth/restore` 200-char junk token | **byte-identical 401** | different error (oracle!) |
| `POST /api/auth/restore` alg=none JWT | byte-identical 401 | 200 (JWT forgery) |
| `POST /api/auth/restore` `{}` | byte-identical 401 | 400 |
| `POST /api/auth/logout` no session | 200 `{"ok":true}` | 401 (fine either way) |
| `GET /api/auth/session` no cookie | 200 `{"lockEnabled":true,"authenticated":false}` | 500 |

**The oracle test is the whole point.** Four structurally-different invalid inputs
(empty / long-junk / alg=none-JWT / missing-field) collapsing to one byte-identical 401 body
**refutes** token-format, length, charset, and JWT-vs-opaque oracles in one pass. Record the
exact body string — it is what makes the refutation checkable.

**No brute force.** With a "no brute force" constraint, test a short *allowed* candidate list
once each (product name, company name, `admin`, `password`, common variants) and report that
all returned the identical 401. Uniform-401-across-all-shapes is itself the evidence of a
correctly-built endpoint — say so rather than apologising for not cracking it.

**Type-confusion ladder is cheap and worth running.** array / object / missing / wrong
content-type all returning the same 401 kills mass-assignment, prototype-pollution, and
type-confusion hypotheses without a single valid credential.

---

## 3. RSC payloads are gated identically to HTML — prove it

Next.js server components stream as `text/x-component`. A naive hunter tests only HTML and
concludes "the route is protected"; a careful one proves the **data** is protected too.

```bash
curl -s -o /tmp/rsc -w "%{http_code} %{size_download}B\n" \
  "https://xxx.current.finance/dashboard" \
  -H "User-Agent: <browser UA>" -H 'Accept: text/x-component' -H 'RSC: 1'
# -> 307 24B /login?from=%2Fdashboard
```

Run it on every admin route. `307 /login?from=<path>` for all of them = no RSC bypass.
Also test the **server-action dispatch path** directly:

```bash
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" -X POST \
  "https://xxx.current.finance/dashboard" \
  -H 'Accept: text/x-component' -H 'Next-Action: 00000000000000000000000000000000' \
  -H 'Content-Type: application/json' -d '[]'
# -> 307 24B   (middleware blocks before any action dispatch)
```

---

## 4. Server actions: what "not enumerable" looks like, and how to prove it

The single most common false lead in this class. `createServerReference` and
`registerServerReference` appear in the bundle and look like app-level server actions —
**they are the Next.js client runtime**. Confirm by reading the surrounding string:

```js
// 111269ca2828637b.js
createServerReference=function(e,t){function r(){var r=Array.prototype.slice.call(arguments);return t(e,r)}...}
registerServerReference=function(e,t){return E(e,t,null),e}
// ...and the giveaway:
throw Error('Trying to call a function from "use server" but the callServer option was not implemented in your router runtime.')
```

The `"use server"` hit is the runtime's **own error message**, not an app directive. Run all
four greps and record the zero counts — that is the proof:

```bash
grep -oE '\$ACTION_ID_[A-Za-z0-9_]*' *.js          # -> 0
grep -oE '"[A-Za-z0-9_-]{30,60}"' *.js             # -> only React/Radix/Turbopack symbols
grep -o 'registerServerReference[^;]\{0,150\}' *.js # -> runtime definition only
grep -o '.\{80\}use server.\{80\}' *.js            # -> runtime error string only
```

`Next-Action` header constant lives in `9c6c2449860630bc.js`:
`n="rsc",o="next-action",u="next-router-state-tree",...d="text/x-component"`.
The dispatch POST is in `6bd6e25093e0fc9c.js`:
`R=await fetch(e.canonicalUrl,{method:"POST",headers:{Accept:a.RSC_CONTENT_TYPE_HEADER,[a.ACTION_HEADER]:p,...}})`.

**Verdict to write:** *the app's server actions, if any, live in per-route chunks loaded
post-auth; without a session there is no action ID to invoke and no chunk to read.*
Label it UNTESTED (auth-blocked), not "no server actions exist".

---

## 5. Static assets: the middleware-matcher asymmetry

```bash
GET /_next/static/chunks/30a6048308408cf8.js  -> 200   # NOT gated
GET /_next/build-manifest.json                -> 307 /login?from=%2F_next%2Fbuild-manifest.json
GET /_next/static/BUILD_ID                    -> 404
GET /_next/static/chunks/app-build-manifest.json        -> 404
GET /_next/static/chunks/turbopack-manifest.json        -> 404
GET /_next/static/chunks/ssr-manifest.json              -> 404
GET /_next/static/chunks/client-reference-manifest.json -> 404
GET /_next/static/chunks/middleware-manifest.json       -> 404
GET /_next/static/chunks/server-reference-manifest.json -> 404
GET /_next/static/chunks/                     -> bare dir name, no index
```

Two facts worth recording:
- **Static chunks are unauthenticated** — so anything shipped to the client is public. Grep
  them hard for secrets (§6). Not a vuln, but it bounds what "leaked" can mean.
- **Every manifest path 404s** (Turbopack builds don't emit them), so you **cannot enumerate
  the full chunk set** without a session. Do not burn calls guessing hashes.
- The matcher covers `/_next/build-manifest.json` but not `/_next/static/*` — a config
  asymmetry worth one line in the report as optional hardening, not a finding.

---

## 6. The two negative greps that bound the whole surface

Run both across every downloaded chunk and publish the counts:

```bash
grep -ohE 'https?://[a-zA-Z0-9./_-]{4,60}' *.js | sort -u | grep -v 'nextjs.org\|reactjs.org\|w3.org\|react.dev\|github.com/facebook\|npmjs\|unpkg\|cdn'
grep -ohE '0x[a-fA-F0-9]{40,64}' *.js | sort -u
```

On the worked target: only `localhost`, core-js, radix-ui docs URLs; **zero Sui addresses**.
Meaning: the admin dashboard resolves **all** chain data server-side and holds no hardcoded
package IDs, admin addresses, RPC URLs, or webhook hosts in the client. That single result
refutes a large family of "hardcoded secret / internal endpoint" hypotheses at once.

Also grep the API surface — the complete client-visible endpoint list:

```bash
grep -ohE '"/api/[a-zA-Z0-9_/{}$.-]*"' *.js | sort -u
# -> /api/auth/login, /api/auth/logout, /api/auth/restore, /api/auth/session
```

Four auth endpoints and nothing else means **there is no client-side data API to attack**;
everything else is RSC. Say that explicitly — it explains why the unauth surface is empty.

---

## 7. Where the session token lives (bundle archaeology)

The localStorage key is exported as a named constant — grep the export, not the literal:

```bash
grep -ohE 'APP_ACCESS_SESSION_LS_KEY[^,;}]{0,60}' *.js | sort -u
# 73c73ea2efa14ebb.js module 917200:
#   e.s(["APP_ACCESS_SESSION_LS_KEY",()=>t]);let t="pebble_insight_app_access_v1"
```

Then read the **session guard** to learn the full auth contract (in `b8ef5db8cff6a794.js`):

```js
axios.get("/api/auth/session",{withCredentials:!0})
  -> if(!lockEnabled || authenticated) return;
  -> o = localStorage.getItem(APP_ACCESS_SESSION_LS_KEY)
  -> s = (await axios.post("/api/auth/restore",{token:o},{withCredentials:!0})).data
  -> on 401: localStorage.removeItem(...)
  -> on success: localStorage.setItem(APP_ACCESS_SESSION_LS_KEY, s.sessionToken)  // ROTATION
  -> router.refresh()
```

And the login form (`30a6048308408cf8.js`, module 174082 `LoginForm`):
`fetch("/api/auth/login",{method:"POST",...,body:JSON.stringify({password:d})})` →
`localStorage.setItem(APP_ACCESS_SESSION_LS_KEY, r.sessionToken)` →
`router.replace(from)` where `from` is validated `startsWith("/") && !startsWith("//")`
(**open-redirect guarded** — check this, it is a real bug class when absent).

Three durable facts to extract and report:
- **Token rotation on restore** — a leaked token is single-use-ish, downgrading token-theft
  impact.
- **`withCredentials:!0` is set but no `Set-Cookie` is ever issued** (verify with `curl -D -`)
  → credentials mode is vestigial; auth is bearer-in-body + localStorage. No cookie to
  hijack, and no CSRF surface.
- **Login error is rendered verbatim** into `<p role="alert">` — check whether the server
  ever returns attacker-influenced text there (reflected-XSS candidate).

---

## 8. Refuting "the admin app shares the backend" — one header

When the target has sibling hosts (`api.<apex>`, `dashboard.<apex>`), the tempting theory is
that an auth bypass on the shared backend reaches admin data. Refute it with the `vary`
header:

```
xxx.current.finance/api/auth/session -> vary: rsc, next-router-state-tree,
                                        next-router-prefetch, next-router-segment-prefetch
api.current.finance/                  -> vary: Origin, Access-Control-Request-Method, ...
dashboard.current.finance/            -> 307 -> /lend-summary  (public, no auth redirect)
```

`vary: rsc, ...` is a **Next.js-specific** header set. It proves the Next.js origin itself
answers the admin `/api/auth/*` routes — there is no Spring/gateway hop for a backend auth
bypass to traverse. Cloudflare strips `x-powered-by` on all three, so headers alone cannot
*confirm* sharing; but they are enough to **refute** the specific "bypass the backend, reach
admin" chain. Write it as REFUTED with the header quoted.

---

## 9. Report shape (same as §7 of the parent reference)

Skeleton on disk FIRST, append every ~5 tool calls. Lead the VERDICT with the negative:
*"No unauthenticated execution primitive. The admin panel is correctly gated at middleware
for HTML, RSC, and all `/api/*` except the single known health endpoint."*

Then:
- **claim-vs-proof table** — one row per refutation, each with the exact status + body or
  `file:line` in the chunk.
- **REFUTED** — alg=none JWT, token oracle, type confusion, RSC bypass, server-action
  reachability, backend sharing.
- **UNTESTED** — name the auth-blocked surface precisely: alert-rule schema
  (`/experiment/alert?tab=rules`), Telegram wallet-bind page, vault-monitor, per-route server
  chunks and any `use server` action IDs. "More testing" is not an entry.
- **Operational-risk section** — if the on-chain half surfaced a hot wallet holding admin
  caps (§10), report it here at true severity (informational), never inflated.

---

## 10. Pitfalls specific to this class

- **`createServerReference` in the bundle is not an app server action.** It is the client
  runtime. Prove it with the four greps in §4 before writing anything about server actions.
- **A 405 on a GET is not a bypass failure.** `GET /api/auth/restore?token=x` → 405 means
  POST-only, which is correct. Do not record it as "blocked" or "refused".
- **A query string on a GET-only route can 405.** `GET /api/statistic/liquidation-health?x=1`
  → 405 while the bare path → 200. Note it, then move on — no state change, no reflection.
- **Trailing slash → 308, not 404.** `POST /api/statistic/liquidation-health/` → 308 to the
  canonical path. Normalise before probing siblings.
- **`/_next/static/*` returning 200 is not a finding.** It is the default Next.js behaviour.
  The only reportable version is "chunks are public, and they contain no secrets" — which is
  a *refutation*, published as such.
- **Don't guess chunk hashes.** All Turbopack manifest paths 404; enumeration needs a session.
- **`curl | python3` is blocked by the terminal guard** (re-confirmed this session). Write to
  `/tmp/x.json` first, then `python3 -c "...json.load(open('/tmp/x.json'))..."` — which also
  produces the evidence artefact for free.
- **Pace the probes.** `sleep 1` between requests. A password-gated internal dashboard behind
  Cloudflare will rate-limit a burst, and a 429 mid-matrix corrupts the comparison you are
  trying to make.
