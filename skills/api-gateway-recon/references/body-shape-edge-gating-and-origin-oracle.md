# Body-Shape Edge Gating + the Origin-Reached Oracle

When an API host answers `401 {"error":"Unauthorized"}` on some requests and `400 FST_ERR_VALIDATION`
on others, the split is usually **not** the path and **not** the auth header — it is the **shape of your
JSON body**. A CloudFront/Lambda@Edge (or any edge function) parses the request body and blocks when a
specific *set of top-level keys* is present. This is a distinct class from the path-independent
blanket-401 in SKILL.md §"The two findings that matter most", and it needs its own method.

Worked end-to-end on `oracle.relay.link` (Relay Protocol oracle, Fastify + CloudFront), a
signature-attestation API where every interesting endpoint was gated this way.

---

## 1. The discriminator: did I reach the origin at all?

Before interpreting any status, learn the two response families. They are byte-distinguishable and
that distinction is the whole oracle.

| Response | Emitted by | Meaning |
|---|---|---|
| `{"error":"Unauthorized"}` (24 B, `content-type: application/json`, no `code`) | **edge** | body matched the gate rule; origin never ran |
| `{"message":"body must have required property 'chainId'","code":"FST_ERR_VALIDATION"}` | **origin (Fastify)** | schema validation ran ⇒ request passed the edge |
| `{"message":"Body is not valid JSON but content-type is set to 'application/json'","code":"FST_ERR_CTP_INVALID_JSON_BODY"}` | origin | body reached Fastify but was mangled |
| `{"statusCode":415,"code":"FST_ERR_CTP_INVALID_MEDIA_TYPE","error":"Unsupported Media Type",...}` | origin | content-type gate |
| `{"message":"Route POST:/x not found","error":"Not Found","statusCode":404}` | origin | routing ran ⇒ path is real-but-wrong-verb, or genuinely absent |
| CloudFront HTML `400 ERROR ... The request could not be satisfied` (915 B, `text/html`) | **CloudFront itself** | malformed at the HTTP framing layer, before any app |

**Rule:** the Fastify `code:` field is your origin-reached proof. A `FST_ERR_VALIDATION` naming a
specific missing property is *stronger* evidence than a 200 — it tells you the edge let you through
AND the exact schema. Collect these deliberately; they are free route/schema enumeration.

Corollary: `415` on `--data` without `content-type`, and `400 body must be object` on `text/plain`,
both prove the origin is alive and parsing. Use them as liveness probes when the gate blocks
everything else.

## 2. Characterizing a body-key-presence gate — six steps

Run these in order. Each is one or two requests.

**Step 1 — the drop-one-field differential.** Send the endpoint's full required field set → `401`.
Then remove exactly one field → `400 FST_ERR_VALIDATION` naming that field. Repeat per field. If
*every* single-field removal flips 401→400, the gate requires the complete set and the origin's own
validation error is what you get for anything less. This simultaneously proves (a) the gate is at the
edge, (b) it is key-presence-based, and (c) the endpoint's full required schema.

**Step 2 — minimal trigger set (greedy reduction).** Start from the full set, drop one key at a time,
keep the drop if the response is still `401`. Converges on the minimal triggering combination.
Measured on `/attestations/transfer/v1`: all 9 required keys
(`chainId, currency, amount, recipient, nonce, expiration, ownerChainId, owner, ownerSignature`) —
no smaller subset triggered. On `/attestations/withdraw-request-authorization/v1`: the 7 required keys
(`chainId, currency, amount, spenderChainId, spender, receiver, nonce`) triggered **with no signature
field present at all**, and `recoverMode:true` + deposit fields did not exempt it.
Do **not** brute-force all 2^n subsets — the greedy pass is n requests and finds the same answer.

**Step 3 — value independence.** Resend the minimal set with every value `""`, then with every value
`"x"`. Still `401` both times ⇒ the rule keys on *key names*, not values. This rules out
content/keyword inspection and tells you the edge is doing a structural JSON parse.

**Step 4 — key-name evasion matrix.** Test, each as a separate request:
case variants (`ownersignature`, `OWNERSIGNATURE`), unicode-escaped key (`"owner\u0053ignature"`),
whitespace-padded key, prefixed/suffixed key (`xownerSignature`, `ownerSignatureX`), the key nested
one level down, and the key inside an array. Measured: **all** reached the origin (400) — the gate is
a literal, case-sensitive, top-level-only key match. Nested/array placement defeats it, which is
itself worth reporting (the edge parse is shallower than the app's).

**Step 5 — endpoint-to-endpoint inconsistency.** Map which endpoints are gated and which are not.
Measured: `transfer/v1`, `withdraw-request-authorization/v1`, `depository-withdrawals/v3`,
`signatures/nonce-mapping/v2`, `signatures/no-fill-or-refund/v1`,
`signatures/withdraw-params-mapping/v1`, `withdraw-gas-payment-authorization/v1` all gated — but
`withdraw-and-fill/v2` and `withdraw-and-refund/v2` passed the edge with a full `orderSignature`
present (origin returned `400 body/order must have required property 'version'`). An inconsistent
gate is a finding in its own right: it shows the rule set is hand-maintained per route and drifts.

**Step 6 — bypass-class battery (expect mostly negatives, record them).** `X-Forwarded-For`,
`X-Real-IP`, `Forwarded`, `x-api-key` junk/empty, double-slash, trailing slash, path case,
`%2F`-encoded separators, dot-segments, HTTP/1.1 vs HTTP/2, verb change (PUT), `Origin`/`Referer`
spoof. Measured: **all** still `401`. Report these as explicit negatives — they are what proves the
gate is not a naive path/header filter.

## 3. Live OpenAPI vs local source — the spec is ahead of the checkout

If a local repo checkout is available, **always pull the live spec and diff it against the source.**
Fastify's `@fastify/swagger` in `mode: "dynamic"` serves the *running* route table at
`/documentation/json` (and `/documentation` for the UI) — and it is frequently **unauthenticated**
even when every `/attestations/*` route is gated.

Measured: live `/documentation/json` → `200`, 163,993 bytes, listing
`/attestations/withdraw-and-fill/v2`, `/attestations/withdraw-and-refund/v2`, and
`/attestations/signatures/withdraw-params-mapping/v1` — **none of which existed in the local
`src/api/` tree** (which had only `withdraw-and-fill/v1`). Two payoffs:

1. Undocumented endpoints are named, with their full request schemas, for free.
2. The live spec's `required[]` arrays hand you Step 1's field set without guessing.

Also useful: the live spec is the authority on *which version is deployed*. Do not assume the
checkout matches production.

## 4. Transfer-Encoding / chunked at a CloudFront edge — three different outcomes

Three ways to send a chunked body, three different results. Know which one you are actually doing.

| Method | What actually goes on the wire | Result |
|---|---|---|
| `curl -H 'Transfer-Encoding: chunked' --data-binary @f` | curl **still sends `content-length`**; the header is a lie the edge may or may not honour | reached origin but body mangled → `FST_ERR_CTP_INVALID_JSON_BODY` |
| raw socket / `http.client` with a generator (true chunked) | real `transfer-encoding: chunked` framing | CloudFront `400` HTML "The request could not be satisfied" — killed at the edge, never reaches origin |
| `curl -T file` (forces genuine chunked upload) | real chunked | same as plain request (401 if gated) |

**Lesson:** never trust `-H 'Transfer-Encoding: chunked'` with curl — verify with `-v` and read the
`>` request headers. If you need true chunked, use `-T` or a Python generator. And a CloudFront
`400` HTML page is an *edge* verdict, not an origin one — do not read it as "the app rejected my
payload".

## 5. Rate-limit reality at the edge

- **Measure before theorizing.** 120 back-to-back POSTs → `Counter({'401': 120})`, **zero 429, zero
  `x-ratelimit-*` / `retry-after` headers at any point**. State that the burst was serial, not
  concurrent — that gives the number without becoming the DoS you are warning about.
- **`X-Forwarded-For` spoofing is moot when the limiter keys on `req.ip`.** Fastify's `req.ip` behind
  a CDN is the *edge's* address, identical for every client, so (a) the limiter cannot discriminate
  real clients and (b) no client-supplied header changes the bucket. Rotating `X-Forwarded-For:
  10.9.$i.1` across 30 requests changed nothing. Read the source (`createFixedWindowRateLimiter` +
  `unauthenticatedRateLimiter.check(req.ip)`) to confirm rather than inferring from the header dump.
- **Exemption paths are worth mapping.** `/lives/v1` was exempt from *both* the limiter and the body
  gate (40 rapid requests → all `200 {"status":"ok"}`). In the source the preHandler hook skips
  `req.url === "/"`, `/documentation*`, and `/lives*`. An exempt path is a free liveness/health
  oracle and a place where the gate's absence is provable.

## 6. Budget discipline — the failure mode this session actually hit

The engagement burned its entire tool-call budget on Steps 1–6 and **never wrote the deliverable
report**. The characterization was solid; the output was a verbal summary. Encode this:

- **Write the report skeleton to disk in the first few calls**, before the probe matrix. Append
  findings as they land. A probe matrix with no artifact is not a deliverable.
- **Cap characterization.** Six steps × ~2 requests is the whole job. If the gate holds after the
  bypass battery, stop and write up what you have — do not keep inventing bypass classes.
- **Separate PROVEN from BLOCKED, explicitly.** When the edge gate prevents the *core* test surface
  (here: cross-VM signature differentials, digest reuse across `operation`, amount/nonce type
  coercion), those items are **UNTESTED — blocked by edge gate**, not REFUTED. Say so in the report
  and name what would unblock them (a valid API key, or direct origin access). Do not let a
  source-code reading stand in for a live proof, and do not quietly drop the items either.
- Source-code analysis of the blocked surface is still worth recording as *hypotheses with the
  reasoning attached* (e.g. "`operation` is inside the signed payload ⇒ domain separation should
  hold; `amount` is `Type.String()` ⇒ numeric coercion should be rejected by validation") — clearly
  labelled as unverified, so the next session can test them the moment the gate is passed.

## 7. Report shape for this class

1. **Gate map** — endpoint · minimal trigger key-set · gated? · evidence (one request/response pair each).
2. **Origin-oracle table** — the Fastify/edge response families observed, with the `code:` values.
3. **Undocumented endpoints** — live-spec paths absent from the local checkout, with their schemas.
4. **Rate-limit / exemption** — burst counts, 429 count, header presence, exempt paths, XFF result.
5. **Bypass battery** — every class tried, with the negative recorded.
6. **Leak check** — stack traces / internal paths / versions in any error body (expect none when the
   app uses an `errorWrapper` that maps non-external errors to a generic message — say REFUTED
   explicitly rather than hunting further).
7. **BLOCKED / UNTESTED** — the items the gate prevented, and the unblock condition.
