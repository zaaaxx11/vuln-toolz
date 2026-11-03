# Payment-flow pre-auth probe methodology

**When to use:** a target's homepage/inline config exposes a purchase/upgrade flow
(`PURCHASE_PHX`, `checkout`, `payment`, `subscription` config blobs). Goal: enumerate the
flow's endpoints and test pre-auth for price/config disclosure, captcha leniency, CORS
reflection, and price/state reflection — WITHOUT credentials and WITHOUT completing a purchase.

Rules of engagement (operator-set): 1 req/sec pacing, benign payloads only, no real purchases,
no brute force, operator header on every request.

## Step 1 — Mine the config blob, not just the routes

The inline config (`var PURCHASE_PHX = {...}`) is the endpoint map. It lists the flow's
URLs, the reCAPTCHA site key, and per-flow flags. Grep:

```bash
curl -s https://target/ > home.html
grep -oE 'var [A-Z_]+ = \{[^;]+;' home.html          # config blobs
grep -oE '"urls":\{[^}]+\}' home.html                 # endpoint map
grep -oE '0x4[A-Za-z0-9_-]{30,}' home.html            # reCAPTCHA/Turnstile keys
```

**Key lesson:** a *config/bootstrap endpoint* (`/pornhubx/init-purchase-flow-data`) is often
**live pre-auth** and returns not just prices but **the rest of the flow's endpoint names** and
the **external payment-gateway base URI**. Always probe the endpoints a config endpoint lists
— it is a discovery amplifier. Observed: `init-purchase-flow-data` → 200 pre-auth with
`initialAmount:9.99`, `productId`, per-request `productSku`/`packageSku`/`packageUuid`, plus
two undisclosed siblings (`/mgpg_phx/init_single_purchase`, `/mgpg_phx/finalize_process_purchase`)
and the gateway `https://mgpg2.probiller.com/api/`.

## Step 2 — Per-endpoint method matrix

For each flow endpoint run 4 shapes, paced: `GET`, `GET+Origin: https://evil.com`,
`OPTIONS` preflight (+ `Access-Control-Request-Method: POST`), `POST {}` (JSON).
Record status + `access-control-*` headers + body shape for each cell.

**Read the matrix this way:**
- Same validation message for GET/OPTIONS/POST (e.g. `{"message":"No price package selected."}`)
  → **server-side validation independent of method/Origin** — no method-confusion surface.
- A JSON API that answers `{"success":false,"message":"Missing parameter."}` on empty input
  (not the SPA 404 page) → the endpoint is **live pre-auth** and validates server-side.
- **No `access-control-allow-origin` on any cell** → no cross-origin surface (contrast with
  the cookie-setter family in `cookie-setter-cors-csrf.md`).
- Bare `GET` returning the SPA "Page Not Found" shell → client-routed path; needs a param.
- Hard `403 "Down for Maintenance"` on all methods → endpoint parked/disabled at the edge.

## Step 3 — Captcha-leniency test (refutable hypothesis)

Probe `validate_captcha` with 6 benign shapes: `{}`, `{"captcha":""}`,
`{"captcha":"INVALID_BENIGN_TEST_TOKEN"}`, all-empty standard fields, and the
**form-encoded** shape the client JS actually sends (`g-recaptcha-response=&captcha=`).

**Discriminator:** identical message across every shape = **strict server-side gate, no
leniency** (REJECTED). *Distinct* messages per shape (e.g. "missing field" vs "invalid
token") = an error-escalation oracle (see the predator-recon "error-message escalation
ladder" pitfall) worth mapping. Never claim a bypass from a single shape.

## Step 4 — External payment-gateway CORS posture

The config's `mgpgBaseUri` points at a third-party processor. Probe it read-only:
`GET`/`POST {}` with `Origin: https://evil.com`. Observed posture on
`mgpg2.probiller.com/api/`: `access-control-allow-origin: *` **AND**
`access-control-allow-credentials: true` on any Origin, plus
`access-control-expose-headers: *, x-auth-token, x-session-id` and
`x-mgpg-correlation-id`/`x-mgpg-trace-id` on every response.

**Classification rule:** `*` + `credentials: true` is **spec-invalid** — browsers refuse to
honor the response as credentialed, so it is **not a working cross-origin read primitive**.
Report as INFO (permissive posture disclosure), not a CORS bypass. The exposed auth-header
names (`x-auth-token`, `x-session-id`) reveal the gateway's auth transport for later
session-vantage work. The correlation/trace ids are useful for request tracing.

## Step 5 — Static-secret vs per-request nonce (the cookie-jar test)

Flow pages often embed a `data-callback-url` or similar opaque token. Decide whether it is a
**static shared secret** or a **per-request nonce** by fetching the page **twice with the same
cookie jar**:

- Value changes across the two loads (even with the same jar) → **per-request/per-page-load
  nonce**. Observed: `data-callback-url` = 108 chars = 80 random base64url bytes, different
  on every load; the anti-CSRF `token` field rotates the same way.
- Value is stable across loads → candidate static secret (then test offline forgery / cross-host
  reuse per the "offline token-forgery test" pitfall).

A per-request nonce has **no cross-session replay value** — it must be harvested per-flow. Do
not report it as a leaked static secret.

## Step 6 — Client-side price-logic audit (mass-assignment / price tampering)

Grep the modal HTML for price fields. **Discriminator:** are the price elements populated
server-side or empty-then-filled-by-JS?

- Modal ships **empty** `paymentCost`/`paymentDiscount`/`paymentCurrency` elements and the
  authoritative `initialAmount`/`initialTotalAmount` come from the **server response** →
  price is **server-authored**, not client-trusted → **no pre-auth price-tampering surface**.
- Only finding in the config: `pricePackageUserSelected:[]` (empty array) → no client-side
  price computation the server could be tricked into trusting.
- `POST {}` to the price-submission endpoint returns a server validation message and echoes
  nothing → no mass-assignment / parameter-pollution reflection.

## Verdict framing

Separate what is **VERIFIED pre-auth disclosure** (price catalog, payment-method list, endpoint
names, gateway URI — all real, low/info) from what is **REJECTED** (captcha leniency, CORS on
first-party payment endpoints, price reflection, static-secret leak) from what is **INFO**
(external gateway `*`+credentials posture). The purchase *execution* endpoints reject empty
input server-side and are gated behind login + valid captcha + a per-session nonce — so there is
**no pre-auth path to fund theft / business-logic abuse** from egress. State that floor explicitly.

Worked case: MindGeek/Intigriti 2026-10-21 (`V2_PAYMENT.md`, `evidence_V2_payment_probes.txt`).
