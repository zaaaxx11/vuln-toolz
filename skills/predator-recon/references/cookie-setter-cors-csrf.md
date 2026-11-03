# Cookie-setter + reflected-Origin CORS + CSRF

The follow-up-pass counterpart to the "cookie-setter is not a redirector" refutation.
**A refuted hypothesis in one direction does not exhaust an endpoint.** Re-sweep the same
response for CORS and CSRF before closing it. (Real case: MindGeek/Intigriti target,
`POST/OPTIONS /user/premium_redirect_cookie` — refuted as a redirector in an earlier
round, then confirmed here as a cross-origin cookie-setter with permissive CORS.)

## The finding (captured 2026-10-21)

Endpoint: `POST` and `OPTIONS` `https://www.pornhub.com/user/premium_redirect_cookie`

Cross-origin request, **no CSRF token**, attacker-controlled Origin:

```
OPTIONS /user/premium_redirect_cookie HTTP/2
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type
```
→ `HTTP/2 200` with:
```
access-control-allow-origin: https://evil.com        ← arbitrary Origin reflected verbatim
access-control-allow-credentials: true
access-control-allow-methods: GET, POST
access-control-allow-headers: X-Requested-With, Content-Type, *
set-cookie: premium_redirect=1; ...; domain=pornhub.com; secure; SameSite=None
```

Same on the state-changing POST (`Content-Type: text/plain`, body `premium_redirect=1`,
`Origin: https://evil.com`, `Referer: https://evil.com/`, no token) → `200`, same
reflected CORS, same cookie set on the apex domain.

Origin reflection is attacker-controlled: verified for `https://evil.com`,
`https://attacker.example`, `null`, and an `application/json` POST.

### Two ACAO behaviors on one endpoint — know the difference
| Request shape | `access-control-allow-origin` | Exploitable? |
|---|---|---|
| GET-like / no-ACAO shapes | empty (`access-control-allow-origin:`) | **No** — empty ACAO is not a wildcard; browsers reject it |
| POST / OPTIONS (state-changing) | reflected `https://evil.com` etc. | **Yes** — arbitrary Origin + `credentials: true` = full CORS read-back |

The earlier pass had only seen the *empty*-ACAO variant and (correctly) called that
non-exploitable — but stopped there. The reflected variant appears on the POST/OPTIONS
shapes, and that is the reportable one.

## Discrimination step — is it endpoint-specific or site-wide?

Send the same `Origin: https://evil.com` to sibling pages:

```bash
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://www.pornhub.com/
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://www.pornhub.com/view_video.php
```

If the siblings do **not** emit `access-control-*`, the permissive CORS is
**endpoint-specific** (reportable as a misconfiguration on that endpoint). If *every*
route reflects it, it is site-wide CORS (different report, often higher impact).

In the captured case: siblings returned no `access-control-*` → endpoint-specific.

## What is and isn't attacker-controllable

- The **Origin is reflected** → any origin can read the response via `fetch()`.
- The **cookie value is hardcoded** (`premium_redirect=1`) — the attacker cannot inject an
  arbitrary value into it. So this is a CSRF + permissive-CORS misconfiguration, not an
  arbitrary-cookie-injection. Severity depends on what `premium_redirect` gates downstream.
- The cookie is set on the **apex domain** with `SameSite=None; Secure` → cross-site usable.

## PoC recipe (paced, 1 req/sec)

```bash
# 1) Preflight — proves reflection + cookie-set with zero CSRF friction
curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type" \
  "https://www.pornhub.com/user/premium_redirect_cookie"

# 2) State-changing POST — proves the cookie sets cross-origin with no token
curl -s -D - -o /dev/null -X POST \
  -H "Content-Type: text/plain" \
  -H "Origin: https://evil.com" -H "Referer: https://evil.com/" \
  --data "premium_redirect=1" \
  "https://www.pornhub.com/user/premium_redirect_cookie"

# 3) Control — sibling page should NOT reflect (proves endpoint-specific)
sleep 1
curl -s -D - -o /dev/null -H "Origin: https://evil.com" "https://www.pornhub.com/"
```

Grep the outputs for `access-control-allow-origin` and `set-cookie: premium_redirect`.

## Triage checklist for any cookie-setter endpoint

1. Probe it with `GET`, `POST`, **and** `OPTIONS` — the exploitable CORS shape is often
   only on the state-changing methods.
2. Vary the `Origin` across several attacker values (incl. `null`) — is it reflected
   verbatim, or fixed/empty?
3. Is `access-control-allow-credentials: true` present alongside a reflected Origin?
4. Does the response `set-cookie` on the apex domain with `SameSite=None`?
5. Is there any CSRF token / Origin allowlist check? (Here: none.)
6. Run the sibling-page control to scope endpoint-specific vs site-wide.
7. Check the JS bundles for the cookie's consumer to argue impact
   (`grep -oE "premium_redirect[^;]+" *.js`).

---

## CSRF-negative control — the empty-body test (kills false CSRF findings)

A POST endpoint that returns a success message with **no CSRF token supplied** looks like a
missing-CSRF finding. It usually is not. The banner is often rendered unconditionally on any
POST, so the response carries no information about whether anything was processed.

**Run all four controls before writing VERIFIED:**

| Control | Expected if the endpoint really processes | Verdict if identical |
|---|---|---|
| `GET` the form page | no success banner | — |
| `POST` with a **completely empty body** | validation errors / no banner | **REFUTED — UI state** |
| `POST` with garbage CSRF token | CSRF error, or the same banner | same banner ⇒ token not checked *and* nothing processed |
| `POST` from a fresh session, no cookies | same as above | same ⇒ no session binding |

Worked case (pornworld.com `/report-content`, 2026-10-22): GET the form → 22,767 B, no
banner. POST with a valid token, POST with **no** token, POST with garbage token, and POST
with an **empty body** → all four byte-identical at 22,990 B carrying
`<div class="alert alert-success">Your report has been submitted successfully</div>`.
The "Please provide the URL(s)" string that looked like a validation error was static
`form-text` help copy inside the form, not a server-side rejection.

**What would promote it:** a *second-order* signal — the submitted value appearing in a
later readable page, a distinct validation error for a specific malformed field, or a
response that differs between the empty body and a populated one. Without one of those,
record REFUTED and do not submit: a false CSRF report burns program credibility.

**Corollary — single-use token semantics.** A related endpoint (`analvids /api/support`)
accepted exactly one POST per CSRF token then returned `{"result":"error","message":"Page
not found"}` on reuse. That is correct single-use + session-bound behaviour with a
misleading error message — INFO at most, not a finding.

## CSP `report-uri` — an unauthenticated write sink by design

If a host's own CSP declares `report-uri /report/violation`, that endpoint must accept
arbitrary unauthenticated POSTs from any browser that loads the page. Probe it with a
well-formed CSP-report JSON and with garbage:

```
POST /report/violation   Content-Type: application/csp-report   {"csp-report":{...}}  → 200 "OK"
POST /report/violation   -d "x=1"                                                        → 200 "OK"
```

No auth, no rate limit observed. This is a **log-spam / storage-exhaustion primitive if the
backend persists reports** — but persistence is unverifiable from an external vantage, so
record INFO/LOW and say so plainly rather than claiming a DoS you cannot demonstrate.
