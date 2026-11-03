# OAuth2/OIDC Device-Code Grant + Identity-Provider Enumeration Oracles (no credentials)

Worked on a three-host estate (`netbird.<apex>`, `vault.<apex>`, `projects.<apex>`), all read-only,
≤1 req/sec. Covers: extracting a real `client_id` from a SPA bundle, running the full RFC 8628
device-code lifecycle unauthenticated, building a **body-based** enumeration oracle, and the
redirect-chain discipline that refutes a tempting open-redirect.

---

## 1. OIDC discovery — the authority is almost never the web root

A `404` on `GET /.well-known/openid-configuration` at an SPA root is **not** a negative. Next.js
(and every other catch-all SPA host) answers every unknown path with its own shell, so the
well-known probe 404s while a perfectly good OIDC server sits one path segment down.

**Order of operations — bundle first, then probe:**

1. `curl -s https://host/` → grep `/_next/static/chunks/[A-Za-z0-9_.-]*\.js` (turbopack) or
   `/_nuxt/` (Nuxt) → download each chunk.
2. Grep the chunks for the runtime-config literal. On turbopack builds the whole config is one
   exported object: `537797,(e,t,r)=>{t.exports={auth0Auth:"false",authAuthority:"https://host/oauth2",authClientId:"netbird-dashboard",authClientSecret:"",authScopesSupported:"openid profile email groups",authAudience:"netbird-dashboard",redirectURI:"/nb-auth",silentRedirectURI:"/nb-silent-auth",...}}`
   Grep for `t.exports={` and for the key names directly — `authClientId`, `authAuthority`,
   `authClientSecret`, `authScopesSupported`, `authAudience`, `redirectURI`, `silentRedirectURI`.
3. Take `authAuthority` and probe **`<authority>/.well-known/openid-configuration`**. On the worked
   case `https://host/oauth2/.well-known/openid-configuration` → `200` with the full document.

**Public-client tell:** `authClientSecret: ""` combined with `auth0Auth:"false"` means a public
client — no secret is required for the device-code flow, which is exactly why the flow is
issuable by anyone.

### What the discovery doc gives you for free

`grant_types_supported`, `scopes_supported`, `token_endpoint_auth_methods_supported`, and
`device_authorization_endpoint`. Read it before guessing endpoints. Also grab
`<authority>/keys` (JWKS) — on the worked case it answered `200` unauthenticated with two RSA
keys and their `kid`s, which is what you need for any later alg-confusion test.

---

## 2. Device-code grant lifecycle (RFC 8628), measured

```
POST <authority>/device/code
  Content-Type: application/x-www-form-urlencoded
  client_id=<from bundle>&scope=<from bundle>
→ 200 {"device_code":"...","user_code":"NBRK-CBGT",
       "verification_uri":"https://host/oauth2/device",
       "verification_uri_complete":"...?user_code=NBRK-CBGT",
       "expires_in":300,"interval":5}

POST <authority>/token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  &device_code=<dc>&client_id=<cid>
```

### Error differential table (the actual evidence)

| Probe | Response | What it proves |
|---|---|---|
| valid code, no user action | `400 {"error":"authorization_pending"}` | flow live, code valid, poll loop works |
| immediate second poll | `400 {"error":"slow_down"}` | **server-side throttle exists** — respect `interval` |
| bogus device_code | `400 {"error":"invalid_request","error_description":"Invalid Device code."}` | code format/lookup is checked |
| valid code + **wrong** `client_id` | `400 {"error":"authorization_pending"}` | **device code is NOT bound to client_id at the token endpoint** |
| `grant_type=client_credentials` | `400 unauthorized_client "Public clients cannot use client_credentials grant."` | grant correctly restricted |
| `grant_type=password` | `400 unsupported_grant_type` | not enabled |
| `grant_type=token-exchange` | `400 invalid_request "Requested connector does not exist."` | enabled but connector-gated |
| `POST <authority>/token/introspect` token=junk | `200 {"active":false}` | introspection accepts unauthenticated POST |

The wrong-`client_id` row is the interesting one: it means anyone holding a device_code can poll
it under any client_id. Not a token theft by itself, but it is a real deviation from the
"bind the code to the requesting client" hardening and worth a line in the report.

### Verification-URI flow (maps the victim-side UX)

```
POST <authority>/device/auth/verify_code   user_code=NBRK-CBGT
→ 302 Location: <authority>/auth?client_id=netbird-dashboard&client_secret=&redirect_uri=%2Foauth2%2Fdevice%2Fcallback&response_type=code&scope=openid+profile+email+groups&state=NBRK-CBGT
```

Note `state=<the user_code>` and `client_secret=` echoed empty into the authorize URL. A wrong
user_code returns `400` with a rendered `Invalid user code.` — a **validity oracle** for user
codes. `GET <authority>/device/callback` with no `code` → `400`; with a forged `code`+`state` →
`400`. So the callback is not trivially forgeable, but the user_code oracle plus the 300s expiry
is the realistic attack surface (phishing the code, not breaking the flow).

---

## 3. Body-based enumeration oracle (Vaultwarden `/identity/accounts/prelogin`)

The highest-value generalizable technique from this session.

```
POST https://vault.<apex>/identity/accounts/prelogin
Content-Type: application/json
{"email":"target@example.com"}
→ 200 {"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null,
       "kdfSettings":{...},"salt":null}
```

**Always `200` — the differential is in the BODY, not the status and not the clock.** Measured
timing was flat (0.543 s / 0.623 s / 0.546 s), so a timing oracle is useless here while the body
oracle is 100% deterministic. Signature classes observed:

| Class | Body |
|---|---|
| A | `{"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}` |
| B | `{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}` |
| C | `{"kdf":1,"kdfIterations":6,"kdfMemory":32,"kdfParallelism":4}` |

### Method (apply to any "always-200 prelogin"-style endpoint)

1. **Send 5+ probes across at least two domains** before theorising. Same-domain probes returned
   *different* classes, so the discriminator is not the domain — it is per-address server state.
2. **Repeat every class 2×** to establish determinism. One address (`support@…`) flipped between
   `kdfIterations:5000` and `600000` across batches — flag that as a *secondary, non-deterministic*
   signal and never build the headline finding on it.
3. **Map normalization** — this tells you how to build the wordlist:
   - `ADMIN@KAIROS-IT.COM` → same class as lowercase ⇒ **case-insensitive**
   - `" admin@kairos-it.com "` → same class ⇒ **whitespace trimmed**
   - `admin@kairos-it.com.` → **different** class ⇒ trailing dot **not** stripped (string-sensitive)
4. Report the oracle as the finding, with the class table and the normalization rules. Do **not**
   run a large wordlist — the deliverable is the proven differential, not a harvested user list.

### Companion signals on the same host

- **Admin panel:** `GET /admin` → `200` (rebranded "Kairos Vault Admin", `server: Rocket`),
  login form `POST /admin` with field `token`. Differential: `""`/`test`/`admin` → `401`;
  a random 24-char token → **`429` "Too many requests, try again later."** So brute-force
  protection exists but only trips after N attempts, with **no `Retry-After`** and no observed
  persistent lockout. The 401-vs-429 split is itself the oracle for "keep guessing" — stop when
  you see 429 rather than rotating identity.
- **SSO enforcement:** `POST /identity/connect/token grant_type=password` →
  `400 {"message":"SSO sign-in is required"}`. Local password auth is off; don't waste the budget
  on password spraying.
- **CSP header as vendor intel:** the response CSP listed
  `child-src 'self' https://*.duosecurity.com https://*.duofederal.com` and
  `frame-src` with the same hosts ⇒ Duo Security SSO in the path. Read CSP for the auth stack
  before probing it.
- **Registration:** confirm disabled from *both* surfaces (`/identity/accounts/register` 404 on
  GET and POST, `/api/accounts/register` 404) — a 404 on one verb only is not proof.

---

## 4. OpenProject anon API + the open-redirect refutation

### Anonymous API surface

`/api/v3/*` returned a **byte-identical `401`** for all 18 resources probed (projects,
work_packages, users, grids, types, statuses, custom_fields, categories, news, wiki_pages, me,
principals, queries, versions, time_entries, memberships, roles, my, help_texts) — including the
`/api/v3/users/2/preferences` href that the config endpoint itself leaked. That is the
blanket-401 pattern: auth is enforced before routing, so route enumeration by status is
unproductive. Say so explicitly.

**What *is* anonymous, and is worth reporting:**

| Path | Leak |
|---|---|
| `/api/v3/configuration` | `userDefaultTimezone: Asia/Jakarta`, `activeFeatureFlags`, `maximumAttachmentFileSize`, and `_links.userPreferences.href: /api/v3/users/2/preferences` — **leaks an internal user id** |
| `/health_checks/all` | `database: PASSED`, **schema version `20260917165643`**, timings |
| `/health_checks/default` | `default: PASSED Application is running` |
| `/scim/v2/Users`, `/scim/v2/ServiceProviderConfig` | `404` ⇒ SCIM not deployed (explicit negative) |

### Open redirect — REFUTED, and here is the discipline that refuted it

Tempting chain that does **not** hold:

```
GET /login?back_url=//evil.com
→ 302 Location: /login/omniauth/oidc-kairos-entra?back_url=%2F%2Fevil.com     (on-host)
GET /login/omniauth/oidc-kairos-entra?back_url=%2F%2Fevil.com
→ 200, contains <input type="hidden" name="origin" id="origin" value="//evil.com" />   (stored, unvalidated)
POST /auth/oidc-kairos-entra  origin=https://evil.com
→ 302 Location: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize?...    (off-host, but the IDP)
```

The `origin` value **is** accepted and stored unvalidated, and the POST proceeds to the identity
provider. But the offsite value is **not carried into the IdP authorize URL** (zero occurrences of
the canary host in the `Location`), and:

- `GET /auth/failure?message=invalid_credentials&origin=//evil.com` → `302 Location: /login`
  (sanitized — the failure path does not honour `origin`)
- `GET /oauth/authorize?client_id=zzq&redirect_uri=https://evil.com&response_type=code`
  → `302 Location: /login?back_url=%2Foauth%2Fauthorize...` — terminates on-host
- Forged callback `?code=zzq&state=zzq` → `401`

**Rule:** a redirect that stays on-host through the entire chain is **not** an open redirect.
Follow with `curl -sL -D - --max-redirs 5` and read the **final** `Location` plus the final page
title before writing anything up. A stored-but-unforwarded `origin` field is an INFO note at most.

**Bonus leak from the same chain** (report it, it is real): the IdP handoff discloses the Entra
tenant id, the app's `client_id`, the exact `redirect_uri`, and the scope —
`login.microsoftonline.com/aeff13d6-.../oauth2/v2.0/authorize?client_id=98e2abc0-...&redirect_uri=https%3A%2F%2Fprojects.<apex>%2Fauth%2Foidc-kairos-entra%2Fcallback&response_type=code&scope=openid%20email%20profile`.

---

## Pitfalls

- **Never report a `404` on `/.well-known/openid-configuration` as "no OIDC".** Pull the bundle,
  read `authAuthority`, probe `<authority>/.well-known/openid-configuration`.
- **Never claim an enumeration oracle from a single probe.** Two repeats per class, minimum, and
  call out any address that flips.
- **Never claim an open redirect from a same-host `302`.** Follow to the final `Location`.
- **A `429` is a stop signal, not an obstacle.** When the admin-token endpoint returned 429 the
  correct move was to stop and record the protection, not to rotate UA/IP and keep guessing.
- **`client_secret=` echoed empty into an authorize URL is not a secret leak** — it is a public
  client. Rank it as INFO.
- **Timing oracles need a control.** Three samples with a 0.08 s spread prove nothing; if the
  body already carries the differential, use the body and say the timing channel was flat.
- **Pace everything at ≤1 req/sec** (`scripts/paced_probe.py`). Device-code polling has a
  server-enforced `interval`; honour it or you get `slow_down` and burn the code's 300 s life.
