# HunterOS run-reality audit, 2026-11-02 (HunterOS 0.7.0, commit 6af7172)

Read-only audit of the last 5 hunt runs on `/home/ubuntu/.hunter/ledger.db`.
All 5 targeted `https://github.com/relayprotocol/relay-settlement`
(scope `relay-bounty-full`). No code modified.

## Ground truth (the table to trust)

| run | elapsed_ms | turns | probes s/r/hit | http_request | evidence | findings rows | finding_created ev | run_ended `findings` |
|---|---|---|---|---|---|---|---|---|
| R-dbe115cf7fdc | 422 491 | 133 | 0/0/0 | 36 | 64 | **2** | 2 | **0** |
| R-83e035cedb37 | 746 460 | 188 | 10/10/**0** | 53 | 101 | **3** | 3 | **0** |
| R-d017c3d05c0b | 172 680 | 60 | 0/0/0 | 5 | 5 | 0 | 0 | 0 |
| R-508386349588 | 221 057 | 60 | 0/0/0 | 48 | 45 | 0 | 0 | 0 |
| R-08728744a220 | 131 378 | 24 | 0/0/0 | 33 | 23 | 0 | 0 | 0 |

Every run's `phase_ended{phase:collect}` also reads `{"findings":0}`.
`gates_failed=1` in all 5; `gate_blocked=0` in all 5 (the claim gate refused nothing).

## Bug 1 — run_ended counts the engine's inline return, not the store

`src/hunter/workflow/pipeline.py`:
- `:370` `created: list[tuple[Finding, CandidateFinding]] = []`
- `:372` `for candidate in result.candidates:` ← only engine-returned candidates
- `:409` `{"phase":"collect","findings":len(created)}`
- `:524` `"findings": len(created)` in the `run_ended` payload
- `:533` `findings = ledger.findings(run_id)` — correct, but **after** the event is emitted

The LLM agent creates findings mid-loop via the `create_finding_request` tool,
which writes straight to the ledger. Those never enter `created`. Consequence:
`run_ended.findings == 0` on every agent-driven run, regardless of real findings.
The `RunSummary` object at `:535-540` is right; the *event* is wrong.

Downstream damage: the retro reads the event, so
`retro_recorded.lessons` contains `"No findings across 9 recorded coverage rows
— target hardened or scope too narrow."` (run R-4a9f745c394e). A miscount
manufactured a false statement about the target's security posture.

Verify ladder side effect: `engine_event` with `stage='verify'` returns **0 rows**
for R-dbe and R-83. `:419` `for finding, candidate in created:` iterated an empty
list because `created == []`. So the ladder was *never fed*, and the `verify`
gate failed for lack of input — `gates_failed: 1` with `finding_rows: 3` is
self-consistent, not a contradiction.

Correct query, always:
```sql
SELECT COUNT(*) FROM findings WHERE run_id='<id>';
```

## Bug 2 — run_probe advertises endpoint/param and ignores them

`src/hunter/agent/tools.py`:
- `:1660-1666` schema declares `check_id`, `endpoint`, `param`; description says
  "All checks are available."
- `:422` reads only `check_id`
- `:434` `module.run(engine_ctx, ctx.target_url.rstrip("/"), recon)` — base URL is
  always the run target

The model cannot aim a probe. Combined with bug-1's sibling problem (a hardened
repo page), this made 10 turns of `run_probe` structurally worthless in R-83.

## Bug 3 (related) — probe HTTP traffic is not persisted

Probes go through `ctx.http`, but only `probe_started` / `probe_result` events
land. No exchange payload. So you cannot read, from the ledger, what status or
headers a probe actually received. The 7 github.com `http_exchange` records in
R-83 are from the agent's own `http_request` / `browser_*` calls
(EV-0251…EV-0265), not the probes. To get probe ground truth you must re-issue
the requests yourself — and then label them as live re-requests, not the run's bytes.

## Why 10/10 probes returned zero (target shape, not hardening)

`run_probe` base was `https://github.com/relayprotocol/relay-settlement`; every
probe appends a hardcoded path. Live re-verification (read-only GET,
`follow_redirects=False`):

```
GET  .../relay-settlement              -> 200  csp=y xfo=y xcto=y   (missing-headers CANNOT fire)
GET  .../relay-settlement/static/      -> 404  text/plain           (dir-listing needs 200+text/html)
GET  .../relay-settlement/.env         -> 404  text/plain           (sensitive-file needs 200+markers)
GET  .../relay-settlement/search?q=…   -> 302  -> github.com/search?q=repo%3A…  (reflected-xss never sees its payload)
GET  .../relay-settlement/goto?url=…   -> 404  text/plain           (open-redirect needs 3xx+Location==payload)
POST .../relay-settlement/transfer     -> 422  text/html            (unauth-action needs "transfer complete")
TRACE .../relay-settlement/            -> 405  text/html            (method-tamper needs 2xx)
```

Probe preconditions, from source (`src/hunter/engine/deterministic/probes/`):
each module hardcodes `ENDPOINT`/`TARGET_PATH` plus a body/status signal —
`reflected_xss.py:16-30`, `sql_error.py:19-37`, `open_redirect.py:21-28`,
`path_traversal.py:23-36`, `unauth_action.py:15-26`, `method_tamper.py:20-29`,
`dir_listing.py:16-31`, `exposed_files.py:29-53`, `headers.py:17-27`.
The conventional app skeleton they assume: `/`, `/login`, `/search`, `/transfer`,
`/download`, `/goto`, `/static/`, `/backup/users.sql`, `/invoice`, `/admin`.

Conclusion: 0 hits was the *correct* answer for this target and carries no
information about Relay's security. The probes work; the target has no surface
for them.

## Strategy split (same target, wildly different runs)

- **R-dbe115cf7fdc — the working template.** 133 turns, read
  `raw.githubusercontent.com/.../RelayHub.sol`, `RelayExecutor.sol`,
  `RelayOracleV2.sol`, `RelayOracleIdempotencyStore.sol`, `README.md`; produced
  F-0016 (low, `erc20Views` overwrite on supply→0) and F-0017 (medium,
  `RelayExecutor` unresolvable-input skim). Zero wasted probes.
- **R-83e035cedb37.** 188 turns, correctly pulled
  `api.github.com/repos/…/git/trees/<sha>?recursive=1` (EV-0256) — then burned 10
  turns on unsteerable probes at the repo page, while its 3 real findings came
  from `api.relay.link` side-host exploration.
- **R-d017c3d05c0b.** 110 of 117 tool calls were `shell_exec`, 5 HTTP requests,
  60 turns, 0 findings. A shell session, not a hunt.
- **R-08728744a220 / R-508386349588.** 33 and 48 `http_request` respectively,
  **zero** `read_file` / `search_files`. Never read the source on a source target.

## What was actually on the ledger

- R-83: F-0013 (medium, access-control) `unauth-depositaddress-reindex|POST|https://api.relay.link/transactions/deposit-address/reindex`;
  F-0014 (info, self-ruled-out in its own title — Allocator deployed on Aurora, not Relay Chain);
  F-0015 (low) same endpoint, throttle keyed on address not caller.
- R-dbe: F-0016, F-0017 (contract source, as above).
- **No finding in any of the 5 runs was on the run's own target.** Every one came
  from a side host the agent reached on its own initiative.

## Host classification for the recommendation (§I instrument-to-target)

Read-only live probing of all 13 scope hosts:

| host | state | probe applicability |
|---|---|---|
| `api.relay.link` | live JSON API; `GET /`→404 `application/json`; **no CSP / XFO / XCTO**; PUT/DELETE→404; TRACE→405 | **`missing-headers` fires.** Best probe target in scope; also where F-0013/F-0015 live, and `expand_finding` gets real siblings (`/transactions/deposit-address`) |
| `api.testnets.relay.link` | live JSON API, headers absent | same class, testnet |
| `relay.link`, `www.relay.link` | **429**, `server: Vercel`, headers absent | bot wall — probing now measures the WAF, not the app |
| `docs.relay.link` | 200, csp=y xfo=y **xcto absent** | one probe could fire; docs surface |
| `support.relay.link` | 302 → `/en/`, Cloudflare, all headers present | hardened |
| `rpc.chain.relay.link` | live JSON-RPC; earlier run R-ae0bbd74e21d fired `missing-headers` and **overturned it as a false positive** (headers proven present, probe had hit a 403 empty-body `GET /`) | don't re-run blindly |
| `chain.relay.link`, `link.relay.link`, `explorer.relay.link` | **NXDOMAIN** (`ConnectError: Name or service not known`) | unusable |

## expand_finding mechanics (why host choice matters)

`src/hunter/agent/tools_expand.py`: `_origin_of(ctx)` returns the base of
`ctx.target_url`; `derive_targets` (`:90-134`) seeds on the finding endpoint, its
path parent, and `?page=2`/`?id=1`/`?redirect=/`/`?debug=1` variants; every
candidate passes `_in_scope` (`:67-73`, fail-closed — any raise ⇒ drop).
On a repo-page target the origin is `https://github.com`, so expansion can only
ever derive `github.com/...` URLs, which have no API surface. Against
`api.relay.link` it derives genuine in-scope siblings.

## Honest limits of this audit

- Probe wire traffic unpersisted (bug 3) ⇒ probe status codes are live
  re-requests by the auditor, not the run's own bytes. They agree with the
  0-hit outcome but are not the same evidence.
- F-0013/F-0015 were **not tested** — `POST .../reindex` is state-changing and
  out of scope for a read-only audit. Status `candidate`, never replayed.
- Exact reason the three low-turn runs stopped (budget / context / provider
  timeout / model choice) is not in the ledger. `budget.wall_seconds: 0` and
  `max_iterations: 0` are "unlimited", so budget does not explain it.
- `cost_usd: 0.0` on every sampled `agent_turn` — the provider reports no
  pricing, so per-run cost is unknown.
