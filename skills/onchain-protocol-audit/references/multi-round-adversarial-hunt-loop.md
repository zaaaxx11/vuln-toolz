# Multi-round adversarial hunt loop (the 6-hour CDC pattern)

Session detail from the current.finance hunt (2026-10-28), where the operator's standing order
was *"jangan berhenti/menyerah sebelum 6 jam"* — do not stop or give up before 6 hours — plus
*"spawn sub agent cdc thinking, saling koreksi"* (spawn subagents with CDC thinking, mutually
correcting). This file owns the **orchestration loop**; `move-defi-audit-patterns.md` owns the
audit technique and `readonly-security-audit` owns the adversarial verdict vocabulary.

---

## 1. CDC divergent-first — generate incompatible theories BEFORE any probe

"CDC" here means **Concurrent Divergent Convergence**: before touching the target, write down
**3+ theories that are genuinely incompatible**, grouped by *research idea*, not by wording.
Three agents all chasing "SQLi" differently is ONE family — redirect two elsewhere.

For a DeFi protocol with a web2 tier, the four that were actually used:

| # | Theory | Why it is incompatible with the others |
|---|---|---|
| T1 | Admin panel auth bypass → post-auth execution primitive | assumes the secret is the gate |
| T2 | Web2 backend RCE (SSTI/deser/SpEL/SSRF/actuator) | assumes a server-side sink exists |
| T3 | On-chain → off-chain bridge (keeper/oracle executes on manipulable state) | assumes the RCE is in a bot, not a web app |
| T4 | Supply chain (npm, CI/CD, dependency confusion) | assumes the compromise is upstream of deployment |

**Premature convergence is death.** If two lanes start producing the same class of finding,
that is a signal to redirect one, not a sign of confirmation. Keep incompatible routes alive
until each has independent depth; cross-pollinate only after that.

---

## 2. Batch dispatch — 3 narrow lanes, each with the skeleton-first contract

Dispatch in batches of 3 (the practical concurrency ceiling). Every lane brief carries:

1. **The closed-surface list** — explicit "do NOT re-probe" enumeration. Without it, lanes
   re-burn budget on surfaces already refuted.
2. **The already-live findings list** with `file:line` — so a lane builds on them instead of
   re-deriving or re-reporting.
3. **The skeleton-first contract**: *"AKSI PERTAMA: create `<file>.md` with the full report
   skeleton … Then APPEND every 5 tool calls. The report must ALWAYS exist on disk."* This is a
   deliverable contract, not a style preference — a lane that times out with no file is a total
   loss even if its analysis was correct.
4. **Hard constraints** stated verbatim: read-only, never broadcast, never fabricate a code
   line, every claim needs `file:line` or a real response, pacing, the working venv path.
5. **A stated priority order** when the lane has multiple questions ("prioritise (f) first — it
   can kill the whole chain"). That ordering IS the budget plan.

### The parent works the most critical question in parallel — do not idle

While the batch runs, the parent takes the single question that decides the most, and answers it
independently. In this session that was the **unit trace** for `close_factor_bypass_min_value`
(whole USD vs base units — the difference between "dust, ignore" and "reachable, report").

Two payoffs: (a) the headline finding stops depending on an unverified assumption, and (b) when
the adversary lane later reports, the parent can adjudicate its claim immediately instead of
taking it on faith.

---

## 3. The adversary lane — dispatch an agent whose job is to DISPROVE

After a chain survives the first rounds, dispatch a lane explicitly tasked with killing it. Give
it the six questions (manipulability + window, unit trace, atomicity, live tolerances, who can
reach the entry, post-action guard) and say plainly: *"Your job is to DISPROVE it. If it survives
your attack, it is real. If it does not, say so plainly. Zero ego."*

**Split it if it is large.** The first adversary dispatch hit a provider 504 after 50 calls and
produced nothing usable. The re-dispatch split the same six questions into two lanes of 2-3 each,
each with an explicit call/time budget and a priority order, and both completed. Rule: **a lane
that times out is a scoping failure, not a task failure — re-dispatch narrower, never re-send the
same oversized brief.**

---

## 4. Verify every subagent claim before it enters the report

This is the rule that saved the report three separate times. Subagents are self-reports, not
verified facts:

- A lane claimed the ADL `close_factor` was unclamped (allowing >100% forced closure). The parent
  pulled `adl_admin` — a module not yet on disk — and found the clamp at `0 < Arg8 <= 10000`.
  **REFUTED.**
- A lane claimed the leverage package had "zero oracle guards across 11 modules", implying a full
  bypass. Grepping `Call <lending_pkg>::` showed it invokes the lending package's gated entry
  points. **Refined to a much narrower (and correct) claim.**
- A lane refuted L-03 because the cited module did not exist. The functionality lived in a
  differently-named module and the defect was present. **The refutation was wrong.**

Pattern: **re-derive the load-bearing claim from primary sources before repeating it.** When the
re-derivation disagrees with the subagent, the subagent loses and the correction is recorded in
the artifact.

---

## 5. Round-reporting discipline

Report to the operator once per batch landing, and make every report carry:

1. **The honest headline first** — if the round produced zero RCE, say "Nol RCE di produksi" in
   the first line. Never bury a null result.
2. **What was refuted, with the killer evidence** — negative results are deliverables. A table of
   closed surfaces with the specific probe that killed each is as valuable as a finding.
3. **Self-corrections, named plainly** — "I was wrong twice about X; here is the evidence that
   corrected me." An operator trusting the report needs to see the error-correction trail.
4. **What remains open**, ranked by value, and an explicit offer of the next direction rather
   than silently continuing or silently stopping.
5. **Constraint compliance stated** — zero tx broadcast, zero brute force, zero destructive
   actions. On a long hunt this is what lets the operator keep saying "lanjut".

### When the operator says "lanjut" / "no stop, before 6 hours"

That is an instruction to keep dispatching, not to pad. Each new round must open a **genuinely
unexplored lane** — if the only remaining work is re-verification of already-live findings, say so
and propose the next unexplored surface instead of manufacturing rounds. The honest end of a long
loop is *"all surfaces mapped, here is the ranked residue"*, not *"I found something because you
wanted me to."*

---

## 6. Scorecard discipline across rounds

Keep a running verdict table for every finding the hunt touches, and revise the **headline and
summary table, not just the body**, whenever adversarial review narrows a claim. A report whose
headline still says "four compounding defects / fund theft" while the body says "three defects /
operator risk / bounded blast radius" is internally inconsistent and a reviewer will trust it
less, not more. When you lower a claim, lower it everywhere it appears and cite the evidence that
lowered it.

Also keep the count honest: if the scorecard says "14 LIVE" and then lists 18 IDs, fix the number
before shipping. Two such inconsistencies were caught and corrected in this session; both would
have been visible to any careful reader.
