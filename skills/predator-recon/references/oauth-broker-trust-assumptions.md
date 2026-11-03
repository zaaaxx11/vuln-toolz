# OAuth authorize-broker trust assumptions — attack matrix

Class-level method for attacking an **OAuth 2.0 authorization-code broker**
(`/authorize`, `/oauth/authorize`, `/auth`, `/oauth2/authorize`) on an authorized
target. Distilled from a hypothesis round against `account.analvids.com/authorize`
(PornBox/AnalVids estate, 2026-10-22) — 23 probes, ~35 requests, 1 req/sec.

Use when a brief names an OAuth callback/authorize endpoint, or when JS/config
disclosure hands you a `client_id` + `redirect_uri` pair and you need to know
whether the broker can be made to land an authorization `code` somewhere useful.

---

## 1. Capture the CONTROL first — before any variant

Fire the known-legit parameter set once and save it. Everything after is a diff
against this. On the worked case the control was:

```
GET /authorize?response_type=code&action=login&client_id=btsporn&scope=web
    &browser_pin=<pin>&redirect_uri=<urlencoded legit callback>
→ 301 Location: /login?
```

Then decode **every** `Set-Cookie` on the response, not just the status. The
broker emitted a base64 `redirect_url` cookie containing the *entire reconstructed
authorize URL* with `finish=1` appended — that cookie is your oracle for what the
broker accepted, echoed, and will replay after login. A status-code-only read
misses it completely.

**Robust decoder pitfall:** the cookie value sometimes carries a literal `%3D`
padding marker that breaks naive `base64.b64decode` (raises *"number of data
characters cannot be 1 more than a multiple of 4"*). Strip `%3D`/`%3d`, then try
pads 0–3 against both `b64decode` and `urlsafe_b64decode`. Two of ten values
needed this.

---

## 2. The three-outcome taxonomy (classify every probe into one)

| Outcome | Signature | Meaning |
|---|---|---|
| **ACCEPTED** | `301/302 → /login` + `redirect_url` cookie set | Request passed validation, forwarded to the login gate. **Decode the cookie** to see exactly what was preserved. |
| **REJECTED** | `200` + generic error page | Request refused *before* the login gate. |
| **REGISTRY-MISS** | `302 → <redirect_uri host>/auth/response?error=Website "X" not found` | `client_id` failed the website-registry lookup. |

**Do not read the rejection error code as an oracle.** The worked broker emitted
`An error occurred (code #<10 random chars>)` with a **fresh random code on every
request** (`tqzzt43rv1`, `jjejy0atju`, `fpp6oaevor`, `kg66tq8pta`, `xmhcmy95yn`).
A per-request random code carries zero information — build any escalation ladder
on **message text**, never on the code value. (Contrast with a *deterministic*
error-code oracle, which is a real finding — test determinism by repeating one
shape twice before believing either.)

**The REGISTRY-MISS redirect target is itself a trust observation.** The error is
sent to the **host the caller supplied in `redirect_uri`** — so the broker derives
its error destination from input whose *path* it does not validate. Benign on an
allowlisted host, but record it: it proves the broker trusts caller-supplied
redirect components for error routing.

---

## 3. The probe matrix (one hypothesis per row, each with its refutation test)

Run each as a single request against the control. Innocuous targets only
(`example.com`, `evil.<legit-host>`, canary strings).

| # | Hypothesis | Probe | Refutation test |
|---|---|---|---|
| 1 | Arbitrary external `redirect_uri` | `redirect_uri=https://example.com/cb` | external host ⇒ REJECTED (200 error page) ⇒ **REFUTED** |
| 2 | Subdomain allowlist bypass | `redirect_uri=https://evil.forum.pornbox.com/...` | REJECTED ⇒ allowlist is host-exact, not suffix |
| 3 | Userinfo parser confusion | `redirect_uri=https://forum.pornbox.com@example.com/...` | REJECTED ⇒ parser not fooled by userinfo |
| 4 | HPP on `redirect_uri` | legit + `example.com` in the same query | REJECTED ⇒ duplicate handling safe |
| 5 | Double-encoding | `https%253A%252F%252F...` | REJECTED ⇒ single-decode only |
| 6 | Path validation | `redirect_uri=https://<allowed>/attackerpath` | ACCEPTED ⇒ **path is NOT validated** |
| 7 | Scheme validation | `redirect_uri=http://<allowed>/...` | ACCEPTED ⇒ scheme NOT validated |
| 8 | Path-less / root | `https://<allowed>` and `https://<allowed>/` | ACCEPTED ⇒ no path requirement |
| 9 | Fragment / extra params | `.../cb#CANARY`, `&evil=CANARY` | ACCEPTED, both preserved verbatim in `redirect_url` |
| 10 | Raw unencoded `redirect_uri` | slashes left unencoded | ACCEPTED, normalized by the server |
| 11 | Arbitrary `client_id` | `client_id=evilclient`, `client_id=` | REGISTRY-MISS ⇒ **REFUTED** |
| 12 | `client_id` HPP | legit + `evilclient` | last value wins ⇒ REGISTRY-MISS (documents parse order) |
| 13 | Known-sibling `client_id` | try every sibling brand in scope | only registered IDs pass; enumerate which are registered (a free client_id inventory) |
| 14 | `browser_pin` as broker auth | wrong pin | ACCEPTED identically to the legit pin, pin preserved in cookie ⇒ **not validated at the broker** |
| 15 | `response_type` validation | `response_type=token` | ACCEPTED unchallenged ⇒ not validated at the broker |
| 16 | Missing `state` | arbitrary extra param passes through untouched | nothing generates or echoes `state` ⇒ login-CSRF / code-injection exposure (THEORETICAL until the callback is tested) |
| 17 | Cross-app redirect inside the estate | `client_id=<A>` + `redirect_uri=https://<sibling-brand>/cb` | ACCEPTED ⇒ the allowlist spans sibling brands, not just the one client's host |

---

## 4. Verdict discipline (what the matrix actually proved)

On the worked case the **primary hypothesis (open redirect / arbitrary client_id)
was REFUTED with evidence** — keep that refutation in the report, it is a finding.
What survived were three *narrower* items:

- **THEORETICAL — cross-application redirect inside the estate.** Host allowlist
  holds, but path/scheme/fragment are unvalidated, and the allowlist spans sibling
  brands. Exploitation needs one more link: any endpoint on an allowed host that
  reflects a query string or performs a redirect. **Name the concrete untested
  chain** (e.g. `redirect_uri=https://<allowed>/api/go-to-box?url=https://evil.example.com`
  when `/api/go-to-box` is a known 302) and carry it to the next round — do not
  upgrade it to PROVEN without the captured response.
- **THEORETICAL — no `state`.** Inferred from passthrough behaviour, not proven.
- **PROVEN (low) — non-HttpOnly `redirect_url` cookie** carrying the full authorize
  URL including `browser_pin`, readable by any JS on the broker host. Measured
  attributes: `Max-Age=86400; path=/; domain=account.analvids.com` with **no
  `HttpOnly`, no `Secure`, no `SameSite`** — a 24-hour, JS-readable cookie holding
  the complete authorize URL. It is the read-back half of any broker-host XSS.

---

## 4b. Second-round measurements that sharpened the matrix (same broker)

Four corrections/additions from the follow-up round — treat these as current state,
superseding the vaguer wording above.

**The `redirect_uri` allowlist is an explicit host registry: exact-match, port-blind,
not a suffix match.** Measured unauthenticated at 1 req/s:

| `redirect_uri` host | Verdict |
|---|---|
| `forum.pornbox.com` (any path, `:8080`, `:443`) | **ACCEPTED** |
| `www.analvids.com`, `analvids.com`, `account.analvids.com` | **ACCEPTED** |
| `pornworld.com` | **ACCEPTED** |
| `ddfcontent.com` | **REJECTED** |
| `notforum.pornbox.com`, `xforum.pornbox.com`, `sub.forum.pornbox.com` | **REJECTED** (not a suffix match) |
| `forum.pornbox.com.evil.com`, `//evil.com/`, `evil.com#forum.pornbox.com`, userinfo `legit@evil` | **REJECTED** |

**The reportable item is the scope-vs-registry set difference** — `pornworld.com`
and `ddfcontent.com` are both in program scope, but only `pornworld.com` is
registered at the broker. Enumerate the registered set (one request per candidate
host) and publish the difference against the scope file. Ports being ignored also
means any host later added to the registry inherits an unvalidated path.

**`browser_pin` is a cookie-bound nonce — say so precisely.** Fetching
`/api/jdialog/btsporn.js` **with a cookie jar** twice → **identical `pin_hash`**;
five times **without** a jar → **five different values**. The pin is stable per
`JDIALOG3` cookie: a per-browser nonce, not a static secret and not a
broker-validated credential. A garbage pin, an empty pin, and *no pin at all* all
produce the same `301 → /login`. Correct wording: *"not a gate at the authorize
step; enforcement is downstream"*, **not** a flat "not validated".

Two amplifiers on the same endpoint: the JS sets the cookie with
`pin_domain = null` ⇒ host-only `document.cookie`, so the **same `JDIALOG3` name
exists on two estate hosts with different values** (shared-namespace cookie —
capture the forum-side value to promote to PROVEN); and `/api/jdialog/btsporn.js`
vs `/api/jdialog/box/1.js` are **byte-identical apart from the `pin_hash` line**,
so the endpoint is templated on the path segment and enumerating segments
enumerates **every site sharing the broker** for free.

**`/api/auth/*` doubles its prefix on a 301.** `/api/auth/sso` → **301 →
`/api/api/auth/sso`** → 200. The terminus is what the app actually routes; the
pretty path is cosmetic. The rule shape (`^/ → /api/` rather than
`^(?!/api/) → /api/`) is itself an INFO/low routing bug and usually also swallows
`//`, `/./`, and backslash variants. Confirmed doubled: `sso`, `callback`,
`token`, `refresh`, `session`, `status`, `check`. Confirmed first-party (not
doubled): `login`, `register`, `logout`, `auth_handler`, `response`,
`browser-pin`.

**The callback that consumes the code is `/auth/response`.** Reachable pre-auth; it
returns the generic error page with a fresh random code on every request
(`?code=test&state=test` included) — consistent with the "random code is not an
oracle" rule. It remains the top-ranked untested sink: does it trust a
`redirect`/`next` param, and does it leak the code in the body?

---

## 5. Anti-delusion rules specific to OAuth brokers

- **A self-host `redirect_uri` is not an open redirect.** `redirect_uri=/cb`
  returning `Location: /cb` is correct behaviour. Only an *external* control
  (`https://evil.example.com/`) promotes the hypothesis, and only if the `Location`
  actually points there.
- **Follow the redirect before writing it up.** A `302` with `-o /dev/null` tells
  you a normalizer fired, not what the destination does. Re-run with `-L -D -` and
  read the final status.
- **A random per-request error code is not an oracle** (see §2). Test determinism
  first: repeat one shape twice.
- **`browser_pin` / nonce / `action` params that pass through the broker are not
  broker-side controls.** They are enforced downstream. Prove where enforcement
  lives before claiming either "validated" or "bypassable".
- **Enumerate the registered `client_id` set** — it is free (one request each) and
  it tells you which sibling apps share the broker, which is exactly the surface a
  cross-app redirect needs.
- **Never send a real authorization code anywhere.** Canary strings and
  `example.com` only; the deliverable is the broker's *validation behaviour*, not a
  hijacked session.

---

## 6. Next-round targets on this class (in priority order)

1. **The callback that consumes the code** (`/auth/response`, `/auth_handler`) —
   does it trust a `redirect`/`next` param? Does it leak the code in the body?
   *(Now known: `/auth/response` is the callback and is reachable pre-auth; the
   param-trust question is still open.)*
2. **CORS on the broker + callback** (`Origin: https://evil.example.com` on GET,
   POST, OPTIONS) — cheap and parallelisable.
3. **A 302 endpoint on an allowlisted host** — completes the cross-app chain.
   *(Now known: `/api/go-to-box` on `www.analvids.com` returns `302 → /` pre-auth
   with no auth and no params — the named candidate; test whether it accepts a
   `url`/`redirect` param and reflects it.)*
4. **Error-oracle on the callback** — ladder on message text, not code value.
5. **phpBB / forum pre-auth params** — control-first (no-match control string
   before any quote payload). *(Now known: phpBB's native auth is replaced by the
   custom `/auth/` bridge, so deprioritise phpBB session/`form_token` classes and
   prioritise the bridge + `karma.php` from the Karma MOD.)*
6. **`/auth/browser-pin?redirect=`** — the `redirect` value is reflected **verbatim
   into an inline `location.href = "<value>"`** assignment (PROVEN reflection with a
   benign value). Test arbitrary scheme/host (`javascript:`, `https://evil.example.com`)
   to promote to a PROVEN open redirect / DOM-XSS sink. This is currently the
   cheapest remaining promotion in the class.
