---
name: agent-harness-hardening
description: "Audit and harden an AI agent harness/runtime from the inside out: failure containment, JSON stdout purity, retry/backoff, event/tool vocabulary drift, tool-schema-vs-handler drift, timeouts, replay/verify ladder resilience, fail-closed validators, append-only ledger retention, and read-only run-reality audits of an on-disk hunt ledger. Use when working inside HunterOS / hunt-os and something fails silently, aborts the run, emits malformed JSON, ignores Retry-After, rejects valid findings; when a run reports zero findings / 'target hardened' / zero probe hits and you must decide whether that is a counting bug, an unsteerable probe, or the wrong target shape; when asked to audit the last N runs from the ledger and report what the agent actually did; when comparing against Hermes/reference impl; or when designing retention over an append-only store."
---

# Agent Harness Hardening & Self-Audit

Class-level skill for reviewing, debugging, and hardening an AI agent harness/runtime from the inside out. This is NOT application security or bug-bounty web recon; it is the meta-layer where tool calls, LLM routing, retry, stdout contracts, and failure masking meet.

## Core Contracts

1. **Failure containment is non-negotiable.** A single tool, replay, evidence write, or retry failure must NOT abort the run. It must degrade to a recorded error string / "not reproduced" / empty evidence, and the loop must continue.
2. **Machine-readable stdout is sacred under `--json`.** Library code must not print human-facing Rich panels, progress text, or skill-save confirmations to stdout during a JSON-emitting command.
3. **Retry/backoff must honor `Retry-After`.** Parsing the header/body and then discarding it is a bug, not a no-op.
4. **Event kinds / tool names / status enums are a vocabulary contract.** The validator’s allowed set and the producer’s emitted set must be kept in sync; missing entries cause silent run rejection.
5. **Timeouts and iteration caps are hard requirements** on every outbound call and loop. “It usually returns fast” is not a timeout.

## Audit Checklist

Run in order on any agent harness.

### A. Loop-Level Failure Containment

- **Tool dispatch:** is every `registry.dispatch()` / tool call wrapped so exceptions become `ToolOutcome(ok=False, ...)` or an error string returned to the model, never a raised exception?
- **Parallel batches:** same rule applies to the whole batch, not just individual items.
- **Post-dispatch side effects:** `_store_evidence`, hook calls, budget updates — do any of these have unguarded paths that can raise and escape the loop?
- **Budget/interrupt checks:** are they individually guarded so a broken implementation cannot stop the loop?

### B. Stdout/Stderr Purity Under `--json`

- Search for `print(` and Rich `console.print(...)` in library code paths reachable from a `--json` command.
- Auto-curation / skill save / diagnostics banners must use stderr, or a `Console(file=sys.stderr)`, or be suppressed entirely when `console=None` / JSON mode is active.
- Confirm tests that parse `--json` stdout actually parse the whole output, not just the first JSON object.

### C. Retry/Backoff Correctness

- Verify `Retry-After` header/body is parsed **AND used** for sleep duration, not just stored.
- Verify bounded retry count; unbounded hammering on 429 is a finding.
- Verify fallback only triggers on classified transient errors, not on auth/config/terminal errors.

### D. Vocabulary / Schema Drift

- Every tool-emitted event kind / finding key / status string must exist in the canonical validator list.
- Missing vocabulary entries manifest as “entire run rejected with no findings” — check the validator logs/events table when a clean target returns zero findings unexpectedly.
- **Grep the producer, not just the consumer.** `grep -rn '_emit(ctx, "' src/` then diff that set against the validator's allowed list. A single unregistered kind kills the whole run at ClaimGate, and the error surfaces far from the emit site.
- **Cross-surface vocabularies drift too.** `action_class` advertised in a tool JSON-schema but only validated as `.strip() or "read"` is the same bug class as a missing event kind: the LLM can emit a value the ledger's downstream enum check rejects. Audit `jsonschema`/tool-param descriptions against the enum actually enforced.
- **Check that a tool *consumes* every parameter it advertises.** (HunterOS `_run_probe`, `tools.py:1660-1666` schema vs `:422-434` handler): the schema promised `endpoint` and `param`, `run_probe`'s description said "All checks are available", but the handler read only `check_id` and always built the URL from `ctx.target_url`. Ten probes were aimed at a hardcoded path on the wrong host; the model could not steer them no matter what it passed. Audit by diffing `ToolSpec.parameters` keys against the keys the handler actually reads — a schema superset is a lie told to the model, and it corrupts the agent's strategy (it will keep retrying an unsteerable tool instead of switching instruments). Frozen proof it also blocks: an ignored `endpoint` is the difference between "probe the repo landing page" and "probe the live API host that is actually in scope."

### E. Timeouts & Iteration Caps

- Every HTTP call site must have an explicit timeout.
- **Stdlib DNS has no timeout at all.** `socket.getaddrinfo()` blocks on a black-holed resolver with no knob. Wrap it on a daemon thread with a hard `join(timeout)` deadline; raise `TimeoutError` on the caller thread. The same applies to any `socket`/`ssl` call that takes no timeout argument.
- **Parallel fan-out timeouts must exceed a single tool's budget.** A batch wait of `5.0s` against tools that legitimately take 20–60s guillotines every call, and the caller's "on timeout, fall back to serial" path silently destroys the fan-out. Set the batch wait near or above the per-tool budget (e.g. 60s), not at a token "sane default".
- The agent loop must have a hard iteration cap independent of model behavior.
- Subagent budgets must be independent from parent budgets, or explicitly shared if intended.

### F. Fail-Closed Validators (anti-forgery integrity)

The most dangerous swallow in a proof-bearing harness is one that guards a **validator**, not a convenience path. Pattern to hunt:

```python
def _allowed_ids() -> set[str]:
    try:
        return set(load_taxonomy().keys()) | {"unknown"}
    except Exception:
        return {"unknown"}          # <-- FAIL-OPEN: the gate is now a no-op
```

If the taxonomy fails to load, the allow-list collapses to `{"unknown"}` and every finding carrying the literal `"unknown"` passes — precisely when the validator is broken. **A validator that cannot load its rules must raise, not widen.** Same shape applies to: schema-version `PRAGMA` reads defaulting to `0`, key-resolution errors defaulting to `""` (produces a misleading 401 instead of a config error), and evaluation helpers that turn a ledger-read failure into an empty finding set (reporting 100% recall against nothing).

Rule: **fail-open is correct for observability, fail-closed is mandatory for authorization, integrity, and accounting.** Split the two deliberately — carry tolerances (broken budget hook, cost-pricing lookup) may swallow; guards (klass taxonomy, evidence binding, key resolution, recall scoring) may not.

### G. Append-Only Stores: archive, never delete

When the ledger enforces append-only via SQLite triggers (`RAISE(ABORT)` on UPDATE/DELETE), a retention/GC feature is an **integrity operation**, not housekeeping. Never `DELETE` to reclaim space — a broken hash chain destroys the whole anti-forgery premise.

Correct sequence, all verified before any destructive step:

1. Copy the run's rows into a sealed artifact (`archive/<run_id>.db`) with its own schema and hash chain.
2. **Re-verify the hash chain on the copy.** Not just row counts.
3. Only then purge from the live DB, and only inside one `BEGIN IMMEDIATE`: `DROP TRIGGER` → `DELETE ... WHERE run_id=?` → recreate triggers from the schema fragment. `DROP TRIGGER` is not protected by `no_delete`; the transaction is what keeps it safe. **Recreate triggers by re-executing each captured `sqlite_master` row's SQL verbatim, one `execute()` per trigger.** Never `executescript()` inside that transaction (it commits first), and never split the DDL on `;` — trigger bodies are `BEGIN … END` and often contain internal semicolons, which truncates the statement and raises `OperationalError: incomplete input`.
4. On any verification failure → `ROLLBACK`, live rows untouched. Write the test that proves this.
5. Never archive or purge a run that is still **open**, regardless of age.

Proof obligations for retention tests: `--dry-run` mutates nothing (row counts *and* file mtime identical); age alone never overrides open status; a failed archive verification leaves the live DB byte-identical.

**Three verification traps that make retention tests lie — check these before believing a result:**

- **`BEFORE DELETE` never fires on an empty table.** A guard test that deletes from a zero-row table gets no exception whether the trigger exists or not. Seed a candidate row first, `commit()` inside the `pytest.raises` block, and run the same probe against a hand-built scratch DB as a negative control. In this session that control run alone prevented a false CRITICAL "append-only is permanently lost" report — the triggers were intact at 27/27 with byte-identical DDL.
- **A hand-written `SELECT <explicit columns>` mapper goes stale after the migration.** `runs()` still selected only the 7 pre-migration columns, so `closed_at` never left the DB layer, every run looked open, and `gc --apply` skipped everything while reporting `{'candidates': 0}`. The retention code was correct; the accessor was silently lossy. When a collector returns zero candidates on qualifying data, print the **accessor's** output before debugging the collector.
- **Time-window tests cannot fake the past through the public API.** Seeding via `append_message()` stamps `time.time()`, so nothing is ever old enough. Add a keyword-only `created_at: float | None = None` to the insert API and accept `now=` on the collector — do not monkeypatch `time.time()`, which leaks into hash digests and ordering.

### H. Reported Counts Must Come From The Store, Not The Inline Return

The single highest-value bug class when a run "found nothing": the harness reports on the **engine's inline return value** while the agent writes findings **directly to the store** mid-loop. Those are two different populations, and the counter silently means "engine returned", not "run produced".

HunterOS case: `pipeline.py:372` iterated `result.candidates` into `created`, `:409`/`:524` reported `len(created)` in `phase_ended`/`run_ended`, and `:533` re-read `ledger.findings(run_id)` *after* emitting the event. Result: 5 of 5 runs printed `findings: 0, verified: 0` while the ledger held 2 and 3 real candidate findings — and because the retro reads the *event*, it wrote lessons like `"No findings … target hardened or scope too narrow"`. A miscount manufactured a false conclusion about the target.

Audit procedure:
- Find every count in a summary/report event. Trace each to its source. If the source is a loop over an engine return, ask **"can the agent create rows by another path?"** (`create_finding_request`, `add_evidence`, a ledger-backed tool). If yes, the count is wrong for every agent-driven run.
- **The event is the artifact, not the returned object.** Something downstream (retro, curator, CI gate, user-facing report) consumes the event long after the object is garbage-collected. A correct `RunSummary` does not rescue an incorrect `run_ended` payload.
- Verify against the store every time: `SELECT COUNT(*) FROM findings WHERE run_id=?` and compare to the event. Never trust `run_ended`/`summary` narrative for "did this run find anything".
- **Run `stage='verify'`-keyed event queries before blaming the ladder.** Zero rows for a stage usually means the ladder was *fed nothing* (`for finding, candidate in created` over an empty list at `:419`), not that it ran and failed — and it also means the `verify` gate fails for lack of input, so `gates_failed: 1` alongside `findings_rows: 3` is self-consistent, not contradictory.
- Cross-check `coverage_record` rows and `probe_started`/`probe_result` pairs the same way. A run with 188 turns and 27 coverage rows but 0 claim attempts is a *strategy* fact; a run with 3 finding rows and `findings: 0` is a *counting* bug. Distinguish them before writing either up.

### I. When a Run Reports Zero: Target Shape vs Probe Rigidity vs Strategy

"Do the probes return zero because the target is hard?" is answerable from the ledger in three ordered questions. Answer them in order — the answer changes the recommendation.

1. **Target shape (structural, most common).** Read each probe module. Every probe is a *fixed request shape* against a conventional app skeleton (`/`, `/login`, `/search`, `/transfer`, `/download`, `/goto`, `/static/`, `/backup/users.sql`). Enumerate each probe's firing precondition (a specific header absent, a specific status, a body marker). Then ask whether those endpoints exist at all on the target. A repo landing page / docs site / hardened CDN returns 404 for all of them, so 10/10 `candidates: 0` is the *correct* answer and carries no information about app security. Empirical method: re-issue each probe's exact request shape by hand (read-only GETs, `follow_redirects=False`) and record status + content-type + the headers the probe keys on. Confirm the precondition is false *before* the probe is even sent.
2. **Probe rigidity (harness bug).** Were the probes even steerable? Check §D's schema-vs-handler diff. If `endpoint`/`param` are ignored, zero hits say nothing about the target — the instrument was never aimed.
3. **Strategy (agent behavior).** Distinct runs on the same target diverge enormously. Compare per-run `tool` histograms (`json_extract(payload,'$.tool')` over `engine_event`):
   - a run whose calls are dominated by `shell_exec` (e.g. 110 of 117) is a shell session, not a hunt;
   - a run with dozens of `http_request` and **zero** `read_file`/`search_files` against a *source* target never read the source;
   - a high-turn run that navigated `raw.githubusercontent.com` / `api.github.com` tree APIs and produced source-derived findings is the *working* template.

**Instrument-to-target matching rule:** repo/source target → `api.github.com` + `raw.githubusercontent.com`/`local_roots`, skip endpoint probes entirely. Live JSON API → header/probe checks fire (a missing-CSP `404 application/json` root will fire `missing-headers` where a hardened CDN page cannot). HTML app skeleton → the full probe set applies. Probing a repo landing page with endpoint probes is the single most common waste of 10 turns; the fix is choosing the host, not tuning the probe.

Report the honest verdict per probe: `no_issue_found` (precondition false — the endpoint doesn't exist) is not the same as "hardened". Never let a green 0-hit scan become evidence of security on a target whose surface it never touched.

### J. Verify-Ladder and Retro Hygiene

- **Judge a run by the store, not the event** (see §H). State the query in the report so the reader can re-run it.
- A retro that consumes a miscounted event will produce a *plausible* but false lesson. When auditing, read `retro_recorded` and check its premises against the finding rows before quoting it as fact.
- `candidate` status with no verify-stage events means "never attempted", not "replayed and failed". Say which.

## Successor Rule: never plan retention without reading the schema

Before designing session/retention policy, query the actual store. Real numbers from a live harness reframed the whole design: 468K ledger / 728 events / 6 runs at 0.1 KB average payload ≈ 1–2 MB/month, while the chat store held 36 sessions in 50 days. Conclusion inverted — the ledger was never the growth problem; the disposable chat sessions were. **Measure before architecting**, and state the projection to the user so the design targets the real pressure.

## Reference Implementation Pattern (Hermes)

Use this as the comparison baseline:

- Tool error → string result, loop continues: `agent/tool_executor.py:633`
- Retry → outer conversation loop reads `retry_after`/`Retry-After`, adaptive backoff, SDK `max_retries=0`: `agent_runtime_helpers.py:1807-1810`, `3155-3168`
- Per-item failure in a batch → that item fails, rest continue
- Prompt caching → never mutate cached system prompt mid-conversation

## Support Files

- `references/hunteros-harness-hardening-session-2026-11-01.md` — concrete HunterOS bugs fixed in one session, with exact file:line, breakage, fix, and verify steps.
- `references/hunteros-audit-and-retention-2026-11-01-p2.md` — full-tree subagent audit (fail-open validators, DNS/parallel timeout traps, vocabulary drift), verified-vs-inflated severity, and the **retention/session-lifecycle design**: measured ground truth, append-only archive-then-purge algorithm, promotion eligibility rule, and the required test invariants.
- `references/retention-build-outcome-2026-11-02.md` — what the retention build actually cost: six production defects found while implementing the spec (stale `SELECT` mapper killing GC, DDL semicolon truncation, unquoted YAML frontmatter, wrong finding-lookup key, un-fakeable timestamps), plus the false-CRITICAL trigger-scare and how the negative control resolved it.
- `references/hunteros-run-reality-audit-2026-11-02.md` — the run-reality audit that produced §H/§I: 5 runs, the `run_ended`-vs-store miscount (event 0, store 2 and 3), the ignored `run_probe` `endpoint`/`param`, unpersisted probe traffic, the probe-precondition table proving a repo page can fire none of the 10 probes, per-run strategy split (110/117 `shell_exec` vs the `raw.githubusercontent.com` working template), and a 13-host live classification with the `api.relay.link` recommendation.
- `scripts/hunteros_run_reality_audit.py` — run this first on any HunterOS ledger. Opens sqlite `mode=ro`, prints per-run turns / stage profile / probe and tool histograms / store-vs-event findings counts, flags `MISCOUNT` and duplicate closes, and ends with every finding row. Replaces hand-typing the query set.
- Applies the trigger/guard test-design traps in depth: `python-sqlite-feature-development` → `references/trigger-guard-verification-traps.md`.

## Output Format for Findings

```
file:line | class | what breaks | severity | evidence
```

Severity:
- **HIGH:** run abort, data loss, JSON contract corruption, unlimited spend/loop
- **MEDIUM:** silent masking of real errors, retry ignored, timeout missing on outbound call
- **LOW:** cosmetic stdout leak that only affects non-JSON runs, best-effort telemetry swallow

## Pitfalls

- **“It already has `except Exception`”** — not all swallows are equal. The bug is whether the caller treats the result as success, whether the error is recorded, and whether the run continues.
- **“dispatch already wraps it”** — that only covers the handler. Post-dispatch side effects and loop bookkeeping are separate failure surfaces. This session's real HIGH was exactly here: `dispatch` was correctly guarded while `_store_evidence` two lines later was not.
- **“the wrapper carries it”** — when you fix a value's plumbing, check every container it passes through. `retry_after` was correctly parsed into `ClassifiedError`, then a downstream exception class hardcoded `self.retry_after = None` and un-did the fix. Verified-fixed-once is not fixed.
- **“tests pass”** — tests may mock the failure surface. Reproduce with a real broken ledger / malformed URL / 429-with-Retry-After before declaring it fixed.
- **“the model caused it”** — malformed URLs and bad tool args are model outputs; the harness must handle them as tool errors, not unhandled exceptions.
- **A stale test that pins an old architecture looks like a code bug.** When a test monkeypatches a module the production path no longer uses (e.g. patching `router.ProviderRouter` after the default moved to `NativeProvider`), the failure is the *test's* outdated contract, not a regression. Diagnose by reading the factory/default, then either update the fixture to select the seam under test (`wire: litellm`) or move the test — never weaken the assertion to make it pass.
- **Trace the whole chain before blaming the last component.** The reported symptom was `InvalidURL: Invalid port: 'NNNNNhttp:'` in replay. It was a *cascade*: an unregistered event kind rejected the run, and an unguarded replay loop converted that into a crash that got misattributed to URL concatenation. Four separate code areas were cleared before the real two culprits were found. When a symptom names component X, prove X first — the message is often the last domino, not the push.
- **A pre-existing red CI is not your regression.** Establish a baseline before fixing anything (`git stash` → measure → restore), so you can distinguish "I broke this" from "this was already broken" and can honestly report improvement (87 → 84) rather than imply you fixed it all.
- **Harness-level gates can veto your own conversation.** An output-guard plugin that rejects bare strong-claim tokens cannot distinguish definition from assertion. Check for such a gate before writing long explanatory text containing claim keywords; if misconfigured, disable it rather than contorting the prose.
- **URL repair must precede the validity check, not follow it.** When ungluing malformed URLs (hosthttps://path), checking for :// and bailing BEFORE the unglue rejects the exact shape it was written to repair. Fix (validated v0.7.0): unglue first, then check :// only for already-valid URLs. A run that hits this produces ScopeViolation at hunt end, losing all evidence.
- **`urlparse()` puts bare hosts in `path`, not `hostname`.** `urlparse("api.relay.link")` returns `hostname=None`, `path="api.relay.link"`. Any classifier that relies on `parsed.hostname` silently returns `unknown` for scheme-less targets. Fix: re-parse with `https://` prefix when `scheme` is empty and the token contains a dot. Validated in `target_classifier.py` — all 6 test targets pass after fix.
- **Ruff is not installed in the venv by default.** CI calls `python -m ruff check` but the venv doesn't have it. `uv pip install ruff` needed before local lint. New code must pass ruff before push — common traps: unused imports (F401), f-strings without placeholders (F541), lines >110 chars (E501), SIM105 `try/except/pass` → `contextlib.suppress`.

## Parallel Audit Fan-Out

Splitting a harness audit across subagents works well **only if you partition by file ownership**, not by topic. Three parallel readers over the same tree is safe; three parallel *editors* over the same file corrupt each other. For an implementation fan-out:

1. Write the spec to a file in the repo (`docs/…-SPEC.md`) and have every agent read it first — a spec in the prompt drifts between agents.
2. Assign each agent an explicit "FILES YOU OWN" list and name the files it must NOT touch.
4. Require each agent to return the **verbatim test output line**, not a claim of success. In practice two of three agents self-reported success while their own test files still failed on real defects (invalid YAML frontmatter, wrong lookup key). A per-part green count is the only acceptable evidence.
5. Re-read any shared file immediately before patching it. Ownership lists are advisory — tooling may warn `was modified by sibling subagent … after this agent's last read`, meaning overlap already happened.
6. Report partial coverage honestly: `PROVEN` per part with executed green tests, `UNPROVEN-BLOCKED` for a part whose safety-net path never fired. Never round "8/12 after fixing six defects myself" up to "done".
4. Put the shared contracts (invariants the tests must prove) in the spec, so the three implementations converge without coordinating.
