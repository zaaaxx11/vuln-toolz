# Retention build outcome — 2026-11-02

Implementing `docs/RETENTION-SPEC.md` (Parts A/B/C) across three parallel TDD
sub-agents. This file records **what the spec did not anticipate**. Read it
before starting any archive-then-purge or promotion feature: six production
defects surfaced during implementation, four of them outside the part that was
being written.

## Per-part outcome (honest coverage)

| Part | Scope | Result |
|---|---|---|
| A | run lifecycle / `hunt close` | **23/23 green** — `PROVEN` |
| C | promotion → skills/tools | **20/20 green** after 3 defects fixed by hand — `PROVEN` |
| B | `hunter gc` / retention | **8/12**, 4 red — `UNPROVEN-BLOCKED` |

Do not report this as "done". The blocked part is the one whose safety net
(rollback when archive verification fails) never raised in test.

## Defects found, ranked by blast radius

### 1. Stale `SELECT` mapper turned GC into a permanent no-op — CRITICAL-in-effect
`kernel/ledger.py` `runs()`

Schema v3 added `outcome`, `closed_at`, `summary_json`. The accessor still
selected the pre-migration 7 columns, so `closed_at` never left the DB layer.
Every consumer saw `closed_at is None` ⇒ "open" ⇒ `gc --apply` skipped
**every** run while returning `{'candidates': 0}` — a healthy-looking empty
result hiding a total no-op.

Diagnosis took the longest of any bug here because the retention code was
correct. The breakthrough was printing the accessor's own output
(`print(list(ledger.runs()))`) instead of querying the table.

Also note: this bug would have silently disabled `hunt close`'s sealing
guarantees downstream, so it was found by Part B but belonged to Part A's file.

### 2. Trigger DDL split on `;` — HIGH
28 triggers existed; `findings_insert_requires_evidence` embeds a `;` inside its
`BEGIN … END` body. `"\n".join(sql_rows).split(";")` truncated it →
`OperationalError: incomplete input`, aborting the purge transaction on the
most dangerous path in the codebase. Fix: re-execute each `(name, sql)` row
verbatim, one `execute()` per trigger, inside the same `BEGIN IMMEDIATE`.

### 3. Generated frontmatter was invalid YAML — HIGH (silent)
`promote._render_skill_md` emitted `f"description: {title}"`. A title
containing `": "` makes YAML read a nested mapping → the entire frontmatter
fails to parse → the SKILL.md is written to disk but can never be loaded back.
Worse than an exception: it looks like a successful promotion.

Fix: `f"description: {json.dumps(desc)}"`. Plus two adjacent fixes — a
deterministic fallback when the title is empty (avoids `description: null`,
also invalid), and redaction **before** the 199-char truncation (truncating
first can bisect a hostname and leave a recognisable fragment).

### 4. Promotion lookup rejected the identifier operators use — HIGH (usability)
`_resolve_target` matched only the opaque ledger `key`, so `promote F-0001`
raised `KeyError` on the exact string printed in every report. Now resolves
`F-0001`, bare `1`, and the raw key, and the error lists what was searched.

### 5. Retention tests could not fake the past — build blocker
`ChatStore.append_message` stamped `time.time()`, so seeded rows were never
older than the cutoff and `gc_chat` legitimately reported `deleted: 0` on
correct code. Fix: keyword-only `created_at: float | None = None`. Rejected
monkeypatching `time.time()` — it leaks into the hash chain.

### 6. False CRITICAL: "append-only guard permanently lost"
After `purge_run`, a probe did `DELETE FROM events` and got no
`IntegrityError`. Symptoms looked catastrophic: the guard that protects the
whole anti-forgery model appeared removed.

Three compounding mistakes in the probe:
1. The table was **empty** — `BEFORE DELETE` is row-level, nothing to fire on.
2. `commit()` was never called, so the deferred transaction hid the state.
3. The first control test used the same flawed probe, so it "confirmed" the
   bug instead of isolating it.

Resolution: seed a row, `commit()` inside `pytest.raises`, and re-run the same
probe on a hand-built scratch DB. Result: guard **INTACT**, 27/27 triggers
present, DDL byte-identical. The code was never broken.

**Rule:** run a negative control (hand-built fixture, known-good) before
escalating any guard-loss finding. If the control fails the same way, the test
is wrong.

## Parallel fan-out observations

Three agents, disjoint file lists, still overlapped: one patched
`kernel/ledger.py` (owned by another part) to fix bug 1. The tool warned
`was modified by sibling subagent … after this agent's last read`.

- Re-read shared files immediately before patching, regardless of ownership.
- Verify each part by **running its test file**, never by the summary. Two of
  three agents self-reported success with failing tests.
- Give agents the spec as a file in the repo (`docs/RETENTION-SPEC.md`), not in
  the prompt — prompt copies drift between agents.

## Remaining open items (state, not instructions)

- Part B: `test_purge_run_rolls_back_when_verification_fails` and
  `test_purge_run_recreates_triggers_and_append_only_survives` did not raise.
  `verify_archive` checks the event hash chain + manifest sha256; the failing
  test deletes `findings` rows from the archive, which changes the file hash,
  so the suspected cause is manifest write/read ordering relative to
  `_archive_schema`. Unproven — needs a run, not a claim.
- `test_cli_gc_json_output` expects an `archived` key the CLI report does not
  emit yet.
- Flaky `test_two_chat_audits_do_not_bleed_state` (~1/6) — vault server race,
  unrelated to retention.
