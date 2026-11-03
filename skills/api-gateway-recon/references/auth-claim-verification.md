# Auth-Claim Verification — transcripts of four killed false positives

All four of these looked like findings and were **refuted** by running a control. Use them as the
template when a candidate "auth bypass / XSS / CSRF / open redirect" appears.

Program context: MediaMarkt/Saturn (YesWeHack), egress was Cloudflare-walled on all branded hosts, so
the reachable surface was the group/estate hosts (see `non-cf-sibling-surface.md`).

---

## 1. JWT alg confusion on SAS Viya (`/SASLogon`)

Discovery doc disclosed the alg list:

```
GET https://sasviya.dev.<group>.com/SASLogon/.well-known/openid-configuration
→ 200 {"issuer":".../SASLogon/oauth/token",
       "token_endpoint_auth_signing_alg_values_supported":["RS256","HS256"],
       "id_token_signing_alg_values_supported":["RS256","HS256"], ...}
```

`HS256` next to `RS256` *looks* like classic alg confusion. JWKS was public:

```
GET /SASLogon/token_keys
→ {"keys":[{"kty":"RSA","kid":"legacy-token-key","use":"sig","x5c":["MIIDBDCCAeyg..."]}]}
```

Build a token with the JWKS `kid`, HMAC-SHA256 `header.payload` with three candidate secrets, and
send as Bearer to `/SASLogon/userinfo`:

| secret used for HMAC | response |
|---|---|
| PEM certificate (from `x5c[0]`) | `401 {"error":"invalid_token","error_description":"Could not verify token signature."}` |
| SubjectPublicKeyInfo PEM (`cryptography` public_bytes) | `401 ... same` |
| empty string | `401 ... same` |
| `alg:none` (no signature) | `401 {"error":"invalid_token","error_description":"kid claim not found in JWT token header"}` |

**Verdict: NOT_FOUND.** Missing `kid` is rejected before signature verification, and the HS256 path is
not accepted — correct implementation. `HS256` appearing in an alg list is a *capability declaration*,
never a finding by itself.

Repro helper:

```python
from cryptography import x509
from cryptography.hazmat.primitives import serialization
cert = x509.load_der_x509_certificate(base64.b64decode(jwks["keys"][0]["x5c"][0]))
pubpem = cert.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
# b64u = urlsafe_b64encode(...).rstrip(b"=")
# sig  = hmac.new(secret, h + b"." + p, hashlib.sha256).digest()
```

---

## 2. Custom-header auth oracle (Azure App Service backend)

A QR-generator SPA (`qrmaker.<group>.com`) called an Azure backend
(`prd-mms-qr-maker.azurewebsites.net`) with a bespoke header. Two-stage response:

```
GET /api/qr/count/all                      → 400 {"message":"missing requestor header"}
GET /api/qr/count/all   mms-requestor-id: test    → 404 {"message":"requestor not found"}
GET /api/qr/count/all   mms-requestor-id: admin   → 404 {"message":"requestor not found"}
GET /api/qr/count/all   mms-requestor-id: 1       → 404 {"message":"requestor not found"}
```

**Verdict: NOT a bypass, IS an enumeration oracle (info).** The header value is validated against a
registry. The two distinct errors let you tell "unchecked" from "checked"; the second is only useful
for enumeration, which is out of policy — one placeholder value is the whole test.

The header name came from the SPA bundle, so the discovery order is: bundle grep for the fetch
wrapper → header name → probe. Do not guess header names.

---

## 3. Reflection inside `__NEXT_DATA__` is not XSS

Next.js IdP error page:

```
GET https://auth.<group>.com/ui/errors/oauth?clientId=store_backoffice
      &redirectUri=<PAYLOAD>&type=REDIRECT_URI_ERROR
→ 404 (219 KB)  <script id="__NEXT_DATA__" type="application/json">{"props":{...},
     "query":{"clientId":"store_backoffice",
              "redirectUri":"\"\u003e\u003cimg src=x onerror=alert(1)\u003e",
              "type":"REDIRECT_URI_ERROR"}, ...}</script>
```

Note the encoding: `<` → `\u003c`, `>` → `\u003e`, `"` → `\"`. A substring check for
`onerror=alert(1)` returns **True** because the letters `onerror=alert(1)` are untouched — but they
sit inside a JSON script block and are **inert**.

Payloads tried — all neutralised: `"><script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`,
`"><svg onload=alert(1)>`, `javascript:alert(1)`. Same for the `clientId` and `type` params.

**Verdict: NOT XSS.** The rule: promote only if a raw `<` tag survives. Substring-matching a payload
whose special characters are absent is the trap.

---

## 4. CSRF on an unauthenticated GraphQL mutation — moot, don't double-report

The endpoint accepted a no-preflight simple content type:

```
POST /graphql   Content-Type: application/x-www-form-urlencoded
body: query=mutation{payment(id:"x"){confirmPayment{id state}}}
→ 200 {"data":{"payment":null}}
```

`text/plain` and `application/graphql` → `400 {"error":"GraphQL query is missing."}`;
`application/json` → executes. So form-urlencoded is accepted and executes.

**Verdict: CSRF is MOOT here.** The same endpoint serves unauthenticated queries *and* mutations, so
there is no session to ride — the real finding is the **missing authentication** on a state-changing
mutation. Reporting it twice (once as CSRF, once as broken auth) would be a duplicate.

Related: `GET /graphql?query={...}` → `400 {"error":"GraphQL query is missing."}` — GET does **not**
execute, so the mutation cannot be driven by an `<img>`/link; it needs a POST.

---

## 5. Protocol-relative redirect_uri → 500 (anomaly, low)

```
/oauth/auth?client_id=store_backoffice&response_type=code&state=x&redirect_uri=https%3A%2F%2Fevil.com
→ 302 Location: /ui/errors/oauth?...&redirectUri=https%3A%2F%2Fevil.com&type=REDIRECT_URI_ERROR   (correct rejection)

/oauth/auth?...&redirect_uri=%2F%2Fevil.com
→ 500  body: Error occurred: 58a84e2e-1347-48c6-b56f-66ac1169c40b                                 (unhandled exception)
```

Also rejected correctly: `https://<app>.<group>.com.evil.com/auth` and
`https://evil.com@<app>.<group>.com/auth`.

**Verdict:** the redirect_uri validator is correct (no open redirect, no OAuth token theft). The
protocol-relative case only yields an unhandled exception + correlation id — an error-handling note,
low severity. Do not inflate it.

---

## The general rule

Every item above had a *plausible* finding shape. What separated finding from noise was a **control
request**:

1. Send the benign variant alongside the malicious one and diff.
2. Follow the redirect and read the FINAL status.
3. For reflection: verify the escaping at the sink, not the substring.
4. For auth: distinguish "header absent" from "header present but rejected".
5. If a second finding would describe the same request, you have one finding, not two.
