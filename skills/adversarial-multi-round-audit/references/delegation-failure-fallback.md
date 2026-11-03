# Delegation-failure fallback: when the subagent batch dies, the round is not over

Observed failure mode (real, one session): a 3-agent fan-out dispatched for a round returned
`TASK 1/3 completed — HTTP 504 Request timed out after 3 retries`,
`TASK 2/3 interrupted`, `TASK 3/3 interrupted` after ~1905 s. **Zero report files on disk, zero
test files written.** The round appeared "done" because the batch callback fired.

## The trap

A batch-complete callback is NOT evidence of coverage. `status=completed` can still carry an API
error instead of a summary; `status=interrupted` carries nothing. If you accept the callback as the
round result, you ship a round with **no evidence at all** and may repeat its conclusions from
memory — which is how fabricated verdicts enter a ledger.

## Mandatory reconciliation (do this before reporting a batch result)

1. **Check the artifacts, not the status.** For every task, verify the file it was supposed to
   produce actually exists and is non-trivial:
   `<report>.md` exists AND has size, `<Test>.t.sol` exists AND compiles, script output log is
   non-empty. Absence = that task produced nothing.
2. **Read the real error field.** `error` first, `result` second — an `error` string means the
   agent never ran the work regardless of what the summary claims.
3. **Never paraphrase an interrupted agent.** No summary exists; anything you attribute to it is
   invention.

## The fallback: do the round inline, immediately

Do not re-dispatch blindly into the same failure (the 504 was on the *parent's* model path, not on
the task). The highest-value move is to execute the round yourself in one focused pass:

- Write the fork test file directly, run `forge test --match-contract <X> -vv`, and let the PASS/
  FAIL lines be the evidence.
- Budget one compile+run cycle per fix; expect checksum (error **9429**) and keyword (`alias` is
  reserved — use `ali`, `acct`) rejects. `emit log_*` inside a `view` test fails (rule 8961) —
  drop `view`.
- Report the honest line: **"batch failed technically (504 + interrupt), so this round does not
  satisfy the 'bring the troops' requirement — I did it inline."** The user values the correction
  over a silent gap.

## What still counts as "troops"

If the user's standing instruction is "ajak pasukan / spawn sub agent", a dead batch does NOT
satisfy it. Say so explicitly and either (a) re-dispatch with a lighter model/task split, or
(b) state that the round is single-agent and let the user decide. Do not claim mutual correction
happened when no second agent returned output.

## Re-dispatch guidance when you do retry

- Split by **artifact**, not by theme: one agent per (test file, report file) pair so a killed
  agent leaves a clearly-named gap instead of an ambiguous one.
- Give each agent an explicit, per-agent file path to write, plus "write the file incrementally so
  a kill still leaves partial evidence".
- Keep the round's verdict gate on YOUR side (you read the artifacts), never on the agent's
  self-report.
