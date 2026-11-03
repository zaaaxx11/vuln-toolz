# FOLLOW-UP 4-Agent Orchestration (A1 → A2 → A3/A4)

For an explicit "hunt what the general prompt missed" / untouched-surface request.
Do NOT re-run the original attack tracks — run the coverage-driven pipeline.

## Pipeline shape (dispatch A1 + A2 + A3/A4 together, all background)

### A1 MAPPER — desk work only, ZERO new probes
- Read all prior artifacts (final report, per-track reports, raw JSON/evidence files).
- Build the 20-type bug taxonomy matrix. For each type mark:
  - **FOUND** = real finding with captured evidence (pointer to file + observation)
  - **NOT_FOUND** = tested and clean/refuted (pointer to what refuted it)
  - **NOT_CHECKED** = never touched — WHY it matters (attack hypothesis) + cheapest probe to close it
- Also enumerate: (a) surfaces never probed (hosts from CT/cookie-map/HTML never GET'd),
  (b) JS bundles not yet fetched/analyzed, (c) HTTP methods not tested on discovered endpoints.
- Output: `A1_COVERAGE_MATRIX.md`. Tally line: `X FOUND · Y NOT_FOUND · Z NOT_CHECKED`.

### A2 HUNTER — attack NOT_CHECKED cells only
- Constraint set: operator header on every request, strict 1 req/sec (`time.sleep(1.1)` between
  requests, enforced inside the script), NO brute force, NO credential testing on 401 hosts,
  GET-first (POST only where a form/endpoint clearly invites it, benign data only).
- One curated PoC attempt per cell, **max 3 attempts per cell then move on**.
- Capture every request+response verbatim to `evidence_A2_<topic>.txt`.
- Verdict per cell: VERIFIED (real finding + evidence) / REJECTED (reason). "Potentially
  vulnerable" without a captured response = a lie. Do not fabricate status codes or bodies.
- Priority within the cell list: secrets-in-unfetched-JS > untouched hosts > CSRF on
  discovered state-changers > JWT variants > DOM XSS sinks > legacy endpoints > races.

### A3 LINKER — assemble candidate chains
- Candidate chains only from R1+R2+A2 findings; every step must cite a finding ID (F1, F2...)
  or new A2 evidence.
- For each chain: state `[Trigger] → [Effect] → [Trust Boundary Crossed]` per step.
- Include the adversarial "killer argument" per chain: "why this ISN'T exploitable" — then
  test THAT.

### A4 VERIFIER — kill or prove each chain end-to-end
- Run the cheap verification requests (same pacing rules) for every step of every chain.
- **A chain is real only if EVERY step has a captured response.** A broken step kills the chain
  — report which step broke with the exact response.
- Verdicts: VERIFIED chain (all steps) / PARTIALLY VERIFIED (mechanism real, exploit impact
  missing) / REJECTED chain (step + response that killed it).

## Dispatch prompts — key clauses that worked
- Give every agent: known-intel block (so they don't re-probe what's known), file paths to
  read first, operator constraints (header, pacing, no-brute-force, read-only scope), and the
  honesty rule ("a claim without a captured response is a lie").
- Give A2 a **negative list** ("KNOWN ALREADY — do NOT re-test: ...") so it spends its budget
  only on untouched cells.
- Give A3/A4 the prior findings as an F1..Fn register so chain steps cite IDs, not prose.
- Give A4 explicit permission to reject: "rejected chains are valid results."

## Pacing discipline (learned the hard way)
- 1 req/sec is a constraint, not a suggestion. Per-host `sleep(1)` loops over ~30+ hosts
  exceed inline tool timeout (300s) — write the sweep to a script and run it in the
  background with `notify_on_complete=true`, flushing one result line per probe so partial
  output survives a kill.
- On `exit 000`/empty curl output: check `returncode` first. Exit 6 = DNS resolution failure
  (NXDOMAIN from this egress — the name is decommissioned, NOT "down"); exit 28 = timeout.
  Do not mislabel these as HTTP status.
- 429s on shared/WordPress-Atomic edges clear in ~2s — a single spaced retry, then move on.

## Convergence rule
Two independent tracks reporting the same artifact (different prompts, no shared state) =
high confidence — cite the convergence in the report. A finding reported by only one track
deserves a dedicated re-probe by the orchestrator before promotion (real case: the
orchestrator re-ran A2's reflected-Origin CORS claim verbatim and confirmed all four Origin
shapes reflected, then found the same response also carried `set-cookie`).

## Worked case (MindGeek/Intigriti, 2026-10-21)
- A1: 4 FOUND / 2 NOT_FOUND / 14 NOT_CHECKED from R1+R2 artifacts, zero probes.
- A2: attacked NOT_CHECKED cells → VERIFIED: reflected-Origin CORS + credentials on
  `/user/premium_redirect_cookie`; REJECTED: secrets-in-JS (9 bundles grepped, zero hits),
  DOM XSS (sinks consume server data only), age-gate race (server deletes cookie in every
  combination). Host disposition: ar/fil.pornhub.com live localized mirrors; partners/cms2/
  emailer/smtp/call/webdisk/rtsp = NXDOMAIN; encoder = port filtered; modelhub = canonical
  alias to www.pornhub.com.
- A3/A4: 5 candidate chains → 0 fully-verified, 1 partially-verified (CDN cache-profile
  divergence = build staleness, low/info), 4 rejected with the exact breaking step.
- Orchestrator adds: full-homepage-HTML mining (payment-flow map, reCAPTCHA keys, legal
  entity, cookie-map domains), API autocomplete surface + token-gate error ladder, SQLi
  no-match control refutation.

## Anti-patterns
- ❌ Re-running the original 4 attack tracks on the follow-up (they already reported; the
  value now is the NOT_CHECKED cells).
- ❌ A1 doing probes (its matrix is invalidated if it touches the target — it must map from
  artifacts only).
- ❌ Promoting a single-track finding without an orchestrator re-probe.
- ❌ Writing the final report before A4's per-step verdicts exist.
- ❌ Padding a "no chain" result — publish the FLOOR statement instead (what was covered,
  why the floor is structural, what human input would unblock it).
- ❌ Delegating LIVE attack probes to leaf subagents on an asserted-but-undocumented
  authorization. A leaf may (legitimately) refuse the network phase and return static-only
  work — budget wasted, and the parent still has to run the probes. Give leaves desk/static
  tasks (bundle archaeology, matrix building, report assembly) and run state-changing or
  attack-shaped probes from the orchestrator session yourself.
- ❌ Trusting a subagent's "route missing / catch-all 404" verdict without reading the
  captured request line. Real case: a script concatenated `curl <host> /api/admin/login`
  **with a space**, so the probe requested `/` and produced `404 Cannot POST /` — reported as
  a missing mount and nearly triggered a pointless mount-enumeration round. The same path
  from the orchestrator answered `401 {"error":"Invalid credentials"}`. Always re-fingerprint
  the actual request URL (or re-run one probe) before pivoting on a negative.
- ⚠️ A `307 → /login` on `/admin/x` does NOT mean the admin page HTML is unreachable.
  Percent-encoded paths (`/%61dmin/x`) often slip past the middleware matcher and return the
  prerendered shell + chunk manifest — the cheapest route to full source recovery. See
  `web-api-recon` → `references/nextjs-admin-bundle-recovery.md`.

