# Follow-Up Pass — Bug Taxonomy Coverage Matrix

Use when the operator asks to **hunt what the first pass missed** ("follow-up", "untouched surface",
"everything not checked yet"). The first pass produces findings; this pass produces a *coverage
ledger* over every bug class, so "nothing else found" becomes a measured claim instead of a shrug.

Rule of the pass: **no re-checking already-found bugs — only gaps.** Every untouched surface is live
until proven otherwise.

## Step 1 — Build the coverage matrix from the first-pass findings

Mark each class with exactly one status:

- **FOUND** — covered *and* something real came out.
- **NOT_FOUND** — you tested it and it held (a clean negative is a result).
- **NOT_CHECKED** — never touched.

Attack priority: **NOT_CHECKED > NOT_FOUND > FOUND.** Every NOT_CHECKED cell needs a reason it stays
untouched; an unexplained blank is the only unacceptable entry.

| # | Cat | Bug type | Status |
|---|-----|----------|--------|
| 1 | Authn | Broken auth (bypass, weak session) | |
| 2 | Authz | IDOR / BOLA / missing object checks | |
| 3 | Authz | Priv-esc (vertical / horizontal) | |
| 4 | Inject | SQLi (in-band, blind, OOB) | |
| 5 | Inject | Cmd injection / SSTI / expression | |
| 6 | Inject | XSS (stored, reflected, DOM) | |
| 7 | Logic | Business logic (price, qty, state) | |
| 8 | Logic | Race / TOCTOU | |
| 9 | Logic | Mass assignment / prototype pollution | |
| 10 | SSRF | SSRF (internal, cloud metadata) | |
| 11 | XXE | XML external entity | |
| 12 | Deser | Insecure deserialization | |
| 13 | Crypto | Weak crypto / hardcoded secrets | |
| 14 | JWT | alg=none, key confusion, claim tamper | |
| 15 | CORS | Misconfig (null, wildcard+creds) | |
| 16 | CSRF | Missing/weak CSRF on state change | |
| 17 | Redir | Open redirect / header injection | |
| 18 | Path | Traversal / LFI / RFI | |
| 19 | Info | Info disclosure (debug, .git, backup) | |
| 20 | Infra | Misconfig (default creds, S3, admin) | |

## Step 2 — Hunt the cheap NOT_CHECKED cells yourself, delegate the bulk

Sequential fan-out beats parallel when the subagent provider falls over (see
`subagent-driven-development` → the fast-batch-`404` mode). Give each hunter a *cell range*, the exact
reachable host list, and the pacing rule — never "test everything".

Highest yield per unit effort on a locked-down estate:
- **#15 CORS** — one `Origin: https://evil.com` request per API host; look for `ACAO` reflection +
  `ACAC: true`. Seconds to run, frequently a real (if low) finding. Absence of `ACAO` is NOT_FOUND.
- **#13 secrets** — regex the JS bundles you *already downloaded* (`AIza…`, `sk_live_…`, `AKIA…`,
  `-----BEGIN … PRIVATE KEY-----`, JWT triples, Sentry DSN). **Then test exploitation before
  reporting**: a Google key that returns `REQUEST_DENIED` without a referer is *restricted* → NOT_FOUND.
- **#19 info disclosure** — `/.git/HEAD`, `/.env`, `/config.json`, `/actuator/*`, `/swagger*`,
  `/backup.zip`, `/server-status`. **A `200` that returns the SPA `index.html` is not a finding** —
  compare `Content-Length` against the known SPA shell before calling it a leak.
- **#14 JWT** — pull the JWKS, then run the confusion control: sign `HS256` with the PEM cert / the
  public-key PEM / an empty secret, plus `alg:none`. All `401` → properly validated → NOT_FOUND.
- **#4 injection** — send *malformed* args to the API and compare responses. Identical bodies with no
  error differential = no signal; do not report a hunch.

## Step 3 — Finding format (`FU-###`)

Every new finding carries all of these, or it is not a finding:

```
ID:       FU-001
Type:     taxonomy #
Endpoint: METHOD /path
Request:  exact HTTP (headers + body)
Response: exact evidence snippet
Impact:   concrete damage
Chain:    links to other findings
Verdict:  VERIFIED | REJECTED (reason)
```

## Step 4 — Anti-delusion rules (per cell)

- **No claim without a concrete request that proves it.**
- **No "potentially vulnerable"** — a PoC or nothing.
- **Can't reproduce → REJECTED, with the reason recorded.**
- **Max 3 attempts per cell, then move on** — and mark the cell honestly rather than grinding.
- **Never fabricate a response.** Paste only what the server actually returned.
- **Retracting your own finding is a win.** A `302` that "looked like a bypass" and follows to the same
  `401` belongs in REFUTED, spelled out.

## Step 5 — Chain, then close

Chain priority (each step needs its own evidence):

1. Auth bypass → data mutation (priv-esc)
2. IDOR → admin access (lateral)
3. Injection → RCE
4. SSRF → metadata → cloud creds
5. Deserialization → RCE
6. Logic + race → duplicate payouts / paywall bypass

Close the report with:

- **Chain exploits** — multi-step, each step cited; if the chain needs a precondition you could not
  obtain (e.g. a valid opaque id), say so plainly instead of implying it works.
- **Gaps remaining** — the still-NOT_CHECKED cells *and why* (no reachable input sink; the target
  surface is WAF-locked) — so the next run starts one level deeper.
- **Blocker** — the single thing a human could provide that unlocks the most surface (clean/residential
  egress, program rules-of-engagement).

## Worked outcomes from the source session (what "as a class" looks like)

- **FOUND:** unauth GraphQL introspection + prod stack-trace + an unauthenticated state-changing
  mutation on an in-scope non-WAF host (#1, #7, #19).
- **NOT_FOUND with reasons:** #15 CORS across 9 hosts (no `ACAO`), #13 (Google key restricted by
  referer), #14 (HS256 confusion + `alg:none` all rejected), #4 (8 injection variants, no differential),
  #16 CSRF moot (endpoint is unauthenticated → no session to ride), #20 (~655 probes, zero leaks).
- **NOT_CHECKED with reasons:** #6/#8/#9/#10/#11/#12 — the reachable pre-auth surface exposes no
  corresponding input sink, and the WAF-locked primary apps could not be exercised at all.
