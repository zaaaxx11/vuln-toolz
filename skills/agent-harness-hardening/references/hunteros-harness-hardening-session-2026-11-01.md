# HunterOS Hardening Session — 2026-11-01

Concrete bugs found, fixed, and verified in this session. Use as reproduction recipes and proof-of-fix references for future HunterOS audits.

## Fixed: Replay Ladder Crash Aborts Whole Run

**File:** `src/hunter/workflow/pipeline.py:411-427`
**Class:** failure containment / replay stage
**What broke:** `_replay_candidate()` raised `InvalidURL: Invalid port: '35501http:'` out of the ladder. Because the ladder had no per-finding guard, one bad replay turned a `completed` run into `failed` and discarded every real finding.
**Fix:** wrap each `_replay_candidate()` call in `try/except Exception`; on failure set `reproduced=False`, record `error_text`, and continue to the next finding.
**Verify:** `hunt --json --engine deterministic` against a local vault target returns `status: completed` with findings intact even when a replay path is forced to fail.

## Fixed: Evidence-Store Crash Aborts Agent Loop

**File:** `src/hunter/agent/loop.py:554-561`
**Class:** failure containment / post-dispatch side effect
**What broke:** `_store_evidence()` calls `ledger.add_evidence(...)` without guard. A locked DB / schema drift raised through the loop and killed the run even though the tool itself succeeded.
**Fix:** guard `_store_evidence()` with `try/except Exception`; on failure set `evidence_ids=[]` and record `stats["error"]` once.
**Verify:** inject a fake ledger whose `add_evidence` raises; the run must finish with `finished=True` and the tool result still returned to the model.

## Fixed: Auto-Curate Writes Human Text to stdout During `--json`

**Files:** `src/hunter/agent/curator.py:186-220`
**Class:** JSON stdout purity
**What broke:** `review_and_save()` always instantiated `Console()` and printed a Rich “Skill preview” Panel plus `saved <path>` to stdout. Inside a hunt, auto-curate calls this with `console=None`, which still became a real Console and leaked text into the JSON document.
**Fix:** treat `console=None` as unattended quiet mode; only print preview/save messages when a Console is explicitly passed.
**Verify:** `hunt --json --engine mock` must parse cleanly; `Skill preview` and `saved <path>` must not appear in stdout. Note: localhost scope warning already correctly goes to stderr.

## Fixed: Missing `browser_render` in EventKind Vocabulary

**File:** `src/hunter/kernel/ledger.py`
**Class:** vocabulary drift
**What broke:** the `browser_render` tool emitted event kind `browser_render`, which was absent from the allowed `EventKind` list. ClaimGate rejected the entire run.
**Fix:** add `browser_render` to the allowed vocabulary.
**Verify:** a hunt that uses `browser_render` should no longer be rejected at the claim gate for unknown event kind.

## Fixed: `retry_after` Parsed but Not Propagated Into Retry Decision

**File:** `src/hunter/llm/native.py`
**Class:** retry / backoff correctness
**What broke:** `Retry-After` seconds were parsed from the response but never attached to the classified error returned to the router, so the outer loop could not honor it.
**Fix:** propagate `retry_after` through `ClassifiedError` so the router/loop can sleep the requested duration instead of hammering.
**Verify:** mock a 429 with `Retry-After: 2`; subsequent retry must wait, not immediately re-request.

## Reference: Hermes Comparison Points

- Hermes tool error → string result, loop continues (`agent/tool_executor.py:633`)
- Hermes retry → outer loop reads `retry_after`, adaptive backoff, SDK `max_retries=0` (`agent_runtime_helpers.py:1807-1810`, `3155-3168`)
- Hermes iteration cap → `IterationBudget` with per-agent cap and refund for `execute_code` turns (`agent/iteration_budget.py`)
