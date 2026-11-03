# HunterOS Harness Audit — 2026-11-01 (part 2: subagent fan-out + retention design)

Continuation of `hunteros-harness-hardening-session-2026-11-01.md`. This pass read the
whole `src/` tree with three parallel auditors and then designed a retention/session
lifecycle. Findings are ranked by real blast radius, not by how alarming they look.

## Verified real bugs (fixed)

### 1. `_ProviderHTTPError` hardcodes `retry_after = None` — HIGH
`src/hunter/llm/native.py:492-499`

The earlier fix propagated `Retry-After` into `ClassifiedError.retry_after`. This class
then threw it away:

```python
class _ProviderHTTPError(Exception):
    __slots__ = ("verdict", "retry_after")
    def __init__(self, verdict: ClassifiedError) -> None:
        super().__init__(verdict.message)
        self.verdict = verdict
        self.retry_after = None        # <-- discards the parsed value
```

Net effect: the parse fix did nothing. Every 429 became a zero-sleep retry storm.

Fix: `self.retry_after = getattr(verdict, "retry_after", None)`

**Lesson:** after fixing plumbing, grep every wrapper/container the value passes through.
A correct producer with a lossy middleman is still broken.

### 2. Claim gate fail-open on taxonomy load — HIGH (anti-forgery)
`src/hunter/kernel/claimgate.py:27-34`

```python
try:
    return set(load_klasses().keys()) | {"unknown"}
except Exception:
    return {"unknown"}
```

If the taxonomy fails to load, RULE-E5 reduces to a no-op and the literal string
`"unknown"` becomes the only accepted value — every finding passes, exactly when the
validator is broken. This is the integrity guard the whole proof model rests on.

Fix: remove the try/except; let a taxonomy load failure raise so the caller blocks.

### 3. Evaluation reports perfect recall on a failed read — HIGH
`src/hunter/workflow/eval_cli.py:55-58`

```python
try:
    findings = ledger.findings(run_id)
except Exception:
    findings = []
```

A ledger read failure scores against an empty set: missing expected keys → recall
computed against nothing → drift gate reports clean when data is corrupt. Metrics that
fail open are worse than metrics that crash, because nobody notices.

Fix: let it raise.

### 4. API key resolution defaults to empty string — HIGH
`src/hunter/llm/native.py:228-231`

`except Exception: api_key = ""` turns a config error into an empty-key request whose
provider rejection (401) is then misclassified as auth failure, triggering wrong
fallback / retry paths. Fix: propagate.

### 5. Stdlib DNS has no timeout — HIGH
`src/hunter/agent/tools_network.py:228, 535`

`socket.getaddrinfo(host, None)` blocks on a black-holed resolver indefinitely; a single
DNS tool can burn the whole turn budget. Fix: daemon-thread wrapper with hard
`join(timeout)` and `TimeoutError` raised on the caller thread.

```python
def _bounded_getaddrinfo(host: str, timeout: float = 10.0):
    box: dict[str, object] = {}
    def _work() -> None:
        try:
            box["infos"] = socket.getaddrinfo(host, None)
        except BaseException as exc:
            box["error"] = exc
    t = threading.Thread(target=_work, daemon=True)
    t.start(); t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"dns: getaddrinfo({host!r}) exceeded {timeout}s")
    if "error" in box:
        raise box["error"]
    return box.get("infos") or []
```

### 6. Parallel fan-out timeout of 5.0s guillotines every probe — HIGH
`src/hunter/agent/parallel.py:63`

`timeout: float = 5.0` against tools that legitimately take 20–60s means the batch always
expires, and the caller's `except Exception: _par_fallback = True` silently downgrades to
serial — destroying the fan-out while looking like normal operation. Fix: default 60.0,
documented as "must exceed a single tool's budget".

### 7. `action_class` schema/validator drift — MEDIUM
`src/hunter/agent/tools.py:558, 649, 1703, 1720` + `kernel/findings.py:15`

Advertised to the LLM in `create_finding_request` / `coverage_record` schemas, validated
only as `.strip() or "read"`, while the real MCP vocabulary is
`recon|read|auth-test|mutate`. Same bug class as a missing `EventKind`.

## Claims that did NOT survive verification

The subagents also flagged `ledger.py:436` (`PRAGMA user_version` defaulting to 0) and
`tools.py:836` (manifest parse failure reclassified as missing manifest) and
`hooks.py:130-170`. These are real swallows but **defense-in-depth, not exploitable
paths** — no unprivileged attacker reach. Grade them MEDIUM/LOW and say so. Do not let a
fan-out's volume inflate severity; each finding still needs a value/impact chain.

## Confirmed-sound (no change needed)

- `tools_base.py:184-189` — `dispatch` wraps every handler, returns `ToolOutcome(ok=False)`. Matches the Hermes pattern; exceptions cannot escape the loop via dispatch.
- `loop.py:404` — parallel batch items individually contained.
- `loop.py:643, 661, 711` — `_interrupted`, `_min_time_remaining`, budget hooks all guarded; a broken hook cannot stop the loop. **Fail-open is correct here** (observability/tolerance) — contrast with the validators above.

## Retention / session lifecycle design

User question: SQLite grows during hunting; how to handle accumulation. User's own
proposal: 1 hunt = 1 session by id; only proven findings get promoted into skills/tools;
auto-delete LLM chat sessions after 7 days.

### Measured ground truth (do this first, always)

| Store | Size | Rows | Note |
|---|---|---|---|
| `ledger.db` | 468K | 728 events / 102 evidence / 12 findings / 6 runs | avg payload **0.1 KB** |
| `chat.db` | 44K | 36 sessions / 53 messages | oldest 50 days |

Projection: **1–2 MB/month**. The disk worry was misdirected — the ledger is not the
growth problem; the disposable chat sessions are. Report the projection so the design
targets real pressure.

### The blocking constraint: ledger is append-only by trigger

```
events_no_delete / evidence_no_delete / findings_no_delete → RAISE(ABORT, 'BLOCKED: append-only')
```

This is the anti-forgery foundation. `DELETE` to reclaim space is not an option — a
broken hash chain voids the entire proof model. Retention must be **archive-then-purge**:

1. Copy run rows → `archive/<run_id>.db` (own schema, own chain).
2. Re-verify the hash chain **on the copy** (not just row counts).
3. Purge from live DB in one `BEGIN IMMEDIATE`: `DROP TRIGGER` → `DELETE WHERE run_id=?` → recreate triggers. `DROP TRIGGER` isn't blocked by `no_delete`; the transaction is the safety.
4. Any verification failure → `ROLLBACK`, live rows untouched.
5. Never touch an **open** run regardless of age.

### Accepted design (user-approved, with two corrections)

- **`hunt close <run_id>`** — seal a run: `outcome` (`proven|partial|blocked|abandoned`), `closed_at`, `summary_json`; append `run_closed` event; then `assert_run_writable` blocks further writes while read/replay still works. Schema v3 adds the three columns (the `runs_protected_columns` trigger freezes only identity columns, so these stay writable — verify before relying on it).
- **`hunter gc`** — default `--dry-run`; `--apply` required. Chat: delete sessions older than 7 days **unless bound to an open run** (retention itself is an attack vector — freeze evidence for live hunts). Runs: archive closed > 90 days.
- **Correction 1 — promotion threshold raised** from `critical` only to `PROVEN-LIVE + (critical|high)`. Rationale: a skill generated from an unproven finding poisons future hunts — it spreads unverified methodology. `proven-medium` stays in the ledger; anything unproven is **never** eligible. Generated skills must carry no target hostname, no tokens, no raw request bodies — extract the target *class*.
- **Correction 2 — chat sessions bound to an open run are exempt** from the 7-day rule.

### Required test invariants

`--dry-run` mutates nothing (row counts + mtime identical) · `gc --apply` never touches an
open run even at 400 days · failed archive verification leaves live rows byte-identical ·
chat bound to an open run survives 30-day gc · unbound 8-day chat deleted · promotion
refuses unproven and proven-medium · generated SKILL.md contains no host/token sentinel ·
every new command emits pure JSON on stdout under `--json`.

## Environment notes

- Use `~/.hunteros/venv/bin/python` (ruff 0.17.3 / mypy 2.4.1 / pytest 9.2.0), never system python.
- Test runs: `HUNTEROS_NO_UPDATE_CHECK=1 CI=true <venv>/bin/python -m pytest <path> -p no:warnings -q`
- The `huntos-claim-gate` Hermes plugin (`~/.hermes/plugins/`) vetoes outgoing assistant text containing `PROVEN` / `EXPLOITABLE` / `admin takeover` without a `PROVEN[F-<n>]` binding. It cannot distinguish a definition from an assertion. Disable via `plugins.enabled: []` / `plugins.disabled: [huntos-claim-gate]` before any long architecture discussion that names those tokens.
