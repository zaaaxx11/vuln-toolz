# .NET / Blazor estates — recon recipe + the traps that cost the most

Worked on a real 8-round corporate estate hunt (`kairos-it.com`, AS17451 Biznet). Every claim below
is backed by an executed request in that session. Nothing here is target-specific — the techniques
transfer to any ASP.NET Core / Blazor / IIS estate.

---

## 1. The empty-body trap — the most expensive mistake of the session

**An endpoint that returns a static/zero payload to an empty body is NOT a stub.**

Measured, twice, on the same endpoint family:

```
POST /api/external/iq-score/finish   {}                        -> 200
  {"correctAnswers":0,"totalAnswered":0,"totalQuestions":60,"iqScoreValue":0,
   "message":"You've completed the IQ Score test."}

POST /api/external/iq-score/finish   {"TestResultID":2}        -> 200
  {"correctAnswers":52,"totalAnswered":60,"totalQuestions":60,"iqScoreValue":140, ...}
POST /api/external/iq-score/finish   {"TestResultID":7}        -> 200
  {"correctAnswers":41,...,"iqScoreValue":118, ...}
POST /api/external/iq-score/finish   {"TestResultID":100}      -> 200
  {"correctAnswers":40,...,"iqScoreValue":116, ...}
```

The `{}` response was written off as a hardcoded stub and the endpoint was closed as "no surface"
for **five consecutive rounds**. With the ID parameter — a field name already proven to exist on a
*sibling* endpoint in the same controller — it was a full unauthenticated cross-tenant data read.

**Rule:** before closing any endpoint as a stub / no-op / static, re-send it with every parameter
name you have already confirmed elsewhere in the same controller, and enumerate the ID space
(1,2,3,5,7,10,25,50,100). A zero-valued response to an empty body is the *default branch* of the
handler, not evidence that the handler does nothing.

**Corollary — the read/write pair.** The same controller exposed an unauthenticated **write** IDOR
(`/audit`, `TestResultID` accepted and persisted, FK-violation 500 vs 200 as an existence oracle)
and an unauthenticated **read** IDOR (`/finish`). When you find one anonymous endpoint on a
controller, assume the whole controller is anonymous and enumerate the verb × parameter matrix on
every sibling before writing up only the one you found.

---

## 2. ASP.NET Core ProblemDetails is a free DTO oracle

When every guessed body returns a generic `400 Bad Request Exception`, stop guessing fields. ASP.NET
Core's `System.Text.Json` conversion errors name the CLR type of every property, and the
`[FromBody]` parameter name, in the response body:

```
POST /api/external/iq-score/audit   {"TestResultID":"abc"}

400 {"type":"https://tools.ietf.org/html/rf9110#section-15.5.1",
     "title":"One or more validation errors occurred.","status":400,
     "errors":{"dto":["The dto field is required."],
               "$.TestResultID":["The JSON value could not be converted to System.Int64. ..."],
               "$.EventType":["... could not be converted to System.String. ..."],
               "$.EventData":["... could not be converted to System.String. ..."],
               "$.SecondsLeft":["... could not be converted to System.Nullable`1[System.Int32]. ..."]},
     "traceId":"00-d76a272452dd9db9c2aa73b4d7b9c541-d22e38aed3a77202-00"}
```

What this yields in one request:
- the `[FromBody]` **parameter name** (`dto`) — so you know the wrapper shape;
- the **CLR type** of every property (`Int64`, `String`, `Nullable<Int32>`, datetime);
- a **fully-qualified DTO class name** when you send a wrong-typed *wrapper*:
  `{"dto":"x"}` / `[]` → `"...could not be converted to
  HRIS.Application.External.DTOs.IQScoreSubmitAnswerRequestDto. Path: $ ..."`;
- a **`traceId`** (W3C traceparent) usable for log correlation and for proving two requests hit the
  same deployment.

Cheaper and more complete than body-guessing. Also note the **verb-discrimination** value: the same
endpoint returns `405` on GET, `400`+validation on a malformed body, and `500` (empty body, EF
`"An error occurred while saving the entity changes"`) once binding succeeds but the handler throws.
Four distinct signatures = four distinct facts about the route.

**Route-existence ladder on Kestrel** (use instead of guessing):

| Response | Meaning |
|---|---|
| `404` | no route (or SPA catch-all — check byte-size first) |
| `405` + empty body | **route exists, wrong verb** |
| `400` + `errors{}` / `traceId` | route exists, model bound, validation failed |
| `500` + empty body | route exists, handler threw (often a null-ref on a missing session) |
| `401` + `www-authenticate: Bearer` | route exists, globally auth-gated |

A `500` with an **empty** body is the interesting one: it means the request got past model binding
and the global auth filter, and the handler needs state you do not have (a started session, a valid
parent row). It is a lead, not a dead end — find the state creator.

---

## 3. Blazor WASM assembly extraction

A Blazor WASM app ships its entire client contract as downloadable .NET assemblies. The route is
`/_framework/blazor.boot.json` → `resources.assembly` → `/_framework/<name>.wasm`.

```bash
# 1. boot.json lists every assembly (values are integrity hashes, not paths)
curl -s https://host/_framework/blazor.boot.json | jq -r '.resources.assembly | keys[]'

# 2. fetch the custom ones — request gzip so the server sends the compressed form
curl -s -H 'Accept: application/wasm' -H 'Accept-Encoding: gzip' \
     -o HRIS.Application.wasm https://host/_framework/HRIS.Application.wasm
#    -> "gzip compressed data, original size modulo 2^32 1415957"
gunzip -c HRIS.Application.wasm > hris.bin          # 1.4 MB uncompressed

# 3. .NET metadata strings are UTF-16LE; plain `strings` finds almost nothing
python3 - <<'PY'
import re
data = open("hris.bin","rb").read()
s = data.decode("utf-16-le", errors="ignore")
allstr = set(re.findall(r'[\x20-\x7e]{4,220}', s))
for m in sorted(allstr):
    if re.search(r'(?i)https?://|\.internal|baseurl|apiurl|endpoint|secret|apikey|connectionstring', m):
        print(m[:190])
PY
```

**Pitfall that wastes 20 minutes:** without `Accept-Encoding: gzip` the server may hand back the
**SPA fallback HTML** (identical byte size to `index.html`, e.g. 2955 bytes) for a `.wasm` path —
looks like a 200 "download" that yields nothing. Check `file` / `content-type: application/wasm`
before parsing. Also: some hosts serve the raw uncompressed module; `file` tells you which.

**What it yielded on the worked case** (from `HRIS.Application.wasm`, 431 KB compressed / 1.4 MB raw):
- internal hostname `https://ats.apps.internal.kairos-it.com/` (publicly resolvable, same IP as the
  public API host);
- entity names (`ExternalRecruitment`, `ExternalApplication`, `IQScoreResult`,
  `AttentionSnapshot`, `ApplicantRecord`);
- service methods (`NominateToVacancyAsync`, `RejectCandidateAsync`);
- workflow status vocabulary (`SCHEDULED`, `RESCHEDULED`, `SUBMITTED`, `REJECTED`, `HIRED`,
  `SCREEN`, `INTERVIEW`, `OFFER`, `TESTING`);
- business-rule error strings that reveal invariants
  (`"Cannot reschedule: the applicant has already started or completed the Attention test."`,
  `"Target vacancy not found, inactive, or not accessible."`);
- the fact that applicants are **HR-invited**, not self-registered — which tells you a
  self-registration wordlist attack on the login/enumeration endpoint is the wrong shape.

**Correction from a later estate:** the claim that routes are "usually not in the client assembly"
held for the HRIS app but is **false in general**. On a second estate the app assembly
(`Promisys.App.Internal.wasm`, 4.7 MB compressed) contained **351 route literals**; sweeping all of
them produced **113 endpoints returning HTTP 200 to an anonymous client** — the single biggest
finding of that hunt. See §3b for the extraction recipe and the ranked disclosure table.
What you always get regardless: the domain model, the config key names (`ApiBaseUrl`), and the
internal hostnames. Pair it with the ProblemDetails oracle (§2) for the wire contract.

**Also grab `appsettings.json` from the app's own origin** — on this estate both the production and
the QA Blazor host served it with `200` and no auth, leaking the API base URL
(`{"API":{"BaseUrl":"https://ats-api.kairos-it.com"}}`). Try `appsettings.{Development,Staging,Test}.json`
too.

---

## 3b. Route-literal extraction from the app assembly — the highest-yield move

The §3 correction came from a second estate where the app assembly carried the full route table.
This is the recipe, and it generalises to any Blazor-WASM-client-for-its-own-API app.

**Extraction.** Same UTF-16LE parse as §3, but grep for route shapes rather than config values:

```python
import re
data = open("Promisys.App.Internal.bin","rb").read()   # gunzip -c first
s = data.decode("utf-16-le", errors="ignore")
allstr = set(re.findall(r'[\x20-\x7e]{4,220}', s))
routes = sorted(m for m in allstr if re.match(r'^/?api/', m, re.I))
# 351 route literals, e.g.
#   /api/internal/utility/get-all-employee
#   /api/internal/vendor/get-vendor-all
#   /api/internal/master/get-audit-logs
#   /api/internal/Contract/generatesc03
```

**Then sweep every route with `GET`** (paced ≤1 req/sec) and bucket by status. On the worked case:
**113 routes returned `200` with no `www-authenticate` header at all.** The `405` bucket is a
second wave — those are live routes where GET is disallowed, so POST/PUT/DELETE may be
unauthenticated too (test with `{}`; on the worked case all 405s stayed 405, i.e. GET-only).

**Ranked disclosures that came out of it (all PROVEN, all anonymous):**

| Route | Size | Content |
|---|---|---|
| `/api/internal/utility/get-all-employee` | 90,888 B | **50 employee records incl. ASP.NET Identity v3 `passwordHash`** (`AQAAAAIAAYag…` = PBKDF2-SHA1 ×1000, 128-bit salt), `normalizedEmail`, `userId` GUIDs, `isEmailConfirmed`, `mfaTypeId`, `accessFailedCount` |
| `/api/internal/vendor/get-vendor-all` | 1,004,119 B | 407 vendor records — vendor numbers, addresses, phones, shareholder names, CIVD numbers, risk categories |
| `/api/internal/master/get-vendor-hse-cert-question` | 2,703,675 B | 84 HSE certification question/answer records |
| `/api/internal/master/get-email-list` | 265,226 B | 247 email templates — `subjectTemplate`, `bodyTemplate` HTML, `requiredParameters`, `emailLink` |
| `/api/internal/SourcingRequest/GetService` | 363,362 B | service catalogue |
| `/api/internal/Contract/generatesc03` / `generatesc05` | ~287 KB each | **anonymous server-side PDF generation** (`content-disposition: attachment; filename=SC03.pdf`, iTextSharp 3.7.7.0, 4 embedded images) |
| `/api/internal/master/get-audit-logs` | 5,923 B | audit trail — `actorEmail`, `ipaddress`, `userAgent`, `actionType: "FailedLogin"`, `detail` |
| `/api/internal/dashboard/get-total-contract-value` | — | contract-value aggregates |

**Three things to check before writing it up:**

1. **Multi-tenancy.** The employee records carried `clientId: 10` and emails on a *client's* domain
   (`@indowoil.com`), not the operator's. That reframes severity: it is third-party PII + credential
   exposure, not just an internal leak. Always read `clientId` / the email domain before sizing.
2. **Password-hash format.** Decode the prefix before claiming crackability:
   `AQAAAAIAAYag` = Identity V3, PBKDF2-SHA1, **1000 iterations** (weak by modern standards);
   `AQAAAAEAACcQ` = V2 (older). State the algorithm and iteration count — "crackable" without the
   format is hand-waving.
3. **The audit log is itself a finding.** It exposed live `FailedLogin` events with actor email, IP
   and user-agent — including an in-progress brute-force against `admin@admin.com` from a third-party
   IP timestamped minutes before the probe. A publicly readable audit trail is both a disclosure and
   an incident signal worth flagging to the operator.

**Negative to record honestly:** `/api/internal/utility/get-vendor-by-id-async?vendorId=1..10` (and
`id`/`vendorID`/`VendorId` variants) all returned an all-null `vendorId: 0` object — the parameter
name is wrong or the handler ignores it. An IDOR candidate that returns empty is **not** an IDOR;
say so rather than implying one.

---

## 4. Host-header pivot when CT reveals `*.internal.<apex>` names that do not resolve

Cert transparency routinely exposes `hris-api.qa.internal.<apex>`, `career.qa.internal.<apex>`,
`koda.qa.internal.<apex>` that return **NXDOMAIN** from public resolvers. Do not discard them —
they are real vhosts on IPs you may already have.

```bash
# against an IP you already know is live
curl -sk -H "Host: hris-api.qa.internal.kairos-it.com" https://103.93.129.150/ -w '%{http_code}'
#   401  + server: Kestrel + www-authenticate: Bearer   -> the QA API
curl -sk -H "Host: career.qa.internal.kairos-it.com"  https://103.93.129.150/ -w '%{http_code}'
#   200  + nginx + "Kairos Career" Blazor shell
curl -sk -H "Host: hris.qa.internal.kairos-it.com"     https://103.93.129.150/ -w '%{http_code}'
#   403  Forbidden
```

Then re-run the **entire** anonymous-endpoint battery against the internal vhost. On the worked
case the QA host carried the same `/api/external/*` bypass as production, and the QA database held
*real* candidate scores — QA environments are frequently less scrubbed than production.

Sweep every resolved IP you own with every unresolved internal name; one box served three internal
vhosts. `403 Forbidden` (9-byte body) is a vhost that exists but is edge-blocked — record it, it is
still surface intelligence.

---

## 5. Reverse-order control for status-code differentials (kills false oracles)

A differential that looks like an enumeration oracle is **not** one until you re-run the probe
sequence in **reverse order**.

Measured false positive: 20 provider names sent to an anonymous social-login endpoint split
cleanly — 7 × `404 {"code":"PROVIDER_NOT_FOUND"}` and 13 × `429 {"message":"Too many requests"}`.
That reads as "these 13 providers exist, they got past the not-found check and hit a rate limiter."

Re-run in reverse order, after the limiter reset:

```
custom 404 · google 404 · x 404 · linkedin 429 · discord 429 · microsoft 404 · github 404
azure  404 · entra  429 · gitlab  429 · okta     404 · auth0      404 · keycloak  404
oidc   429 · saml   429 · apple   404
```

`linkedin`/`discord` (previously 404) now 429; `azure` (previously 429) now 404. The split is
**positional**, not semantic ⇒ pure rate limiting, **no oracle**. Reported as a negative.

**Rule:** any "exists vs not-exists" inference drawn from a status-code split across ≥5 sequential
probes must be re-validated with the order reversed (and ideally with the timing column attached).
If the split moves, it is the limiter. This also applies to user-enumeration claims: on the same
estate, a login endpoint returned `{"error":"Invalid password"}` for a likely-real address but the
limiter (429, sticky >340 s) blocked the non-existent-user control — so the finding was filed as
**SUSPECTED / not proven**, not as user enumeration.

---

## 6. Shared-cert / SNI mismatch across vhosts — proof pattern + workaround

When many vhosts sit behind one reverse proxy, they often share a single certificate that covers
only one name. Prove it and reach the service anyway:

```python
import ssl, socket, http.client
ctx = ssl._create_unverified_context()
def req(host, path):
    c = http.client.HTTPSConnection(IP, 443, context=ctx, timeout=12)
    # send the CERT's name as SNI, the VHOST's name as Host
    c.sock = ctx.wrap_socket(socket.create_connection((IP, 443), timeout=12),
                             server_hostname="netbird.<apex>")
    c.request("GET", path, headers={"Host": host, "User-Agent": "Mozilla/5.0"})
    r = c.getresponse(); return r.status, r.read()
```

Measured on 8 vhosts behind one IP: own-SNI handshake → `SSLError: TLSV1_ALERT_INTERNAL_ERROR`;
`netbird.<apex>` SNI → handshake OK, cert `CN=netbird.<apex>`, SAN `DNS:netbird.<apex>` only.
That is a **certificate-misconfiguration finding** (8 names served by a cert that covers none of
them), and the SNI override is the reachability workaround. `curl --connect-to` does **not** work
for this (it rewrites the connection target but still sends the original SNI) — use Python
`server_hostname`.

A vhost that answers `404 page not found` with `content-type: text/plain` (Go's `http.NotFound`)
behind a working handshake means the **proxy route exists but no backend app is bound** — record as
"vhost present, app down", not "no surface".

---

## 7. CT source calibration — crt.sh can be 200 and still useless

| Source | Result on the worked estate |
|---|---|
| `crt.sh/?q=%25.<apex>&output=json` | `200`, **2 names** — only `*.kairos-it.com` + apex (one wildcard cert) |
| `certspotter /v1/issuances?domain=<apex>&include_subdomains=true&expand=dns_names` | `200`, **175 certs / 100 unique DNS names** |

A wildcard-only crt.sh response is **not** evidence of a small estate. Always run certspotter as
the primary and treat crt.sh as the fallback (it also 502'd repeatedly here). The 100 certspotter
names were what produced the entire host inventory — including the internal/QA names in §4 and the
`*.apps.<apex>` service estate.

---

## 8. Report-shape discipline that this session enforced

- **Correct earlier rounds in writing.** The stub misclassification (§1) survived five rounds
  because each round's report repeated the earlier verdict instead of re-testing. When a new probe
  contradicts an earlier verdict, say so explicitly and restate the finding at its new severity.
  Practical form: at the top of every round, list the previous round's "closed / negative" items and
  name the 2–3 whose evidence is weakest (empty body, single probe, guessed parameter name) — those
  get re-tested first.
- **One anonymous controller implies a family.** The `iq-score` module was found in round 2; the
  structurally identical `attention-test` module (§A2b in SKILL.md) was not found until round 9.
  Enumerate sibling module names from the assembly's `*WebService` / `*Service` class names and
  re-run the full battery on each — including an independent FK sweep, because the ID sets differ.
- **Label SUSPECTED separately from PROVEN.** Two items (OmniRoute user-enum, stored-XSS via an
  audit-write field) were real leads that the available controls could not settle. Filing them as
  findings would have been fabrication; filing them as SUSPECTED with the blocking control named is
  the honest deliverable.
- **A clean negative is a deliverable.** The firewalled `/24` was closed with six independent
  proofs (own TCP probes, a third-party nmap from *their* egress, a real-browser reader, 13 proxy
  services, zero CT certs, zero archive captures). "No public path exists" with that evidence is
  worth more than another proxy rotation.
- **Verify a subagent's headline before reporting it.** The 113-endpoint breach arrived as a
  subagent summary; it was re-requested directly (status, `www-authenticate` count, record count,
  field names, hash prefix) before it entered the report. Subagent summaries are self-reports —
  spot-check the number that carries the severity.
