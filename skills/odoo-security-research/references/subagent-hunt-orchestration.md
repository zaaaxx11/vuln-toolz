# Orchestrating sub-agent hunts (parallel surface sweeps without losing the work)

Odoo's pre-auth surface sweeps parallelise well — one agent per class (money flow, broken authz,
template layer, module families). But the delegation layer has sharp edges, all of them learned the
hard way in one session where **two agents capped out mid-hunt**.

## Hard facts (measured, not assumed)

| Fact | Consequence |
|---|---|
| A leaf sub-agent has a **hard tool-iteration cap ≈ 50 calls / ~11–12 min** | Enough to `-i` modules, plant fixtures and probe — **not** enough to also write the report. Both agents in the reference session hit the cap *at the report step*. |
| If the brief doesn't demand incremental writes, **the entire report is lost** | Agent #1: `SUBAGENT_MONEYFLOW.md` never existed → the parent had to reconstruct it from the cached summary. Agent #2, given the instruction, left a usable skeleton. |
| Dispatching **more than one at a time fails** | Send them **sequentially**, one per turn/round. |
| The parent's copy of a result summary is **truncated** (head + tail) | The full text is at a cache path the payload names (`.../delegation/subagent-summary-*.txt`). Read *that file* for the middle — the verdict and the evidence table usually live there. |
| Agent summaries are **self-reports**, and the file may not exist | Never relay a verdict before checking the disk (below). |

## Mandatory clauses in every brief

1. **Incremental writing — the single most important line.** Verbatim:
   > Create `<ABSOLUTE PATH>.md` AT THE START with a skeleton, and APPEND/EDIT it after EVERY
   > significant step (setup done, each probe, each verdict). Never hold results only in your head.
   > Keep each shell command small; prefer one focused probe per call.
2. **Own-lab-only, no DoS, no fabricated results.** State plainly: *"an honest negative is a valid,
   valuable deliverable; an invented success is not."* A negative is data — the reference session's
   two negatives closed the money-flow and website-content surfaces outright.
3. **Proof standard.** Object state in the DB *before* the request + a unique planted marker string
   actually appearing in the unauthenticated response + **a control run** (public sibling behaves
   differently / a wrong-or-absent token fails). Say explicitly: *"'HTTP 200' alone is not proof of a
   leak."*
4. **Give the already-eliminated list verbatim.** Otherwise the agent burns its whole budget
   re-deriving dead surfaces. Paste the current surface-status board from `SKILL.md` §9/§10 plus §4.
5. **Deliverable = a named file path + a short final summary.** Both, and say the summary must be in
   the operator's language if the user is non-English.

## Copy-paste brief skeleton

```
You are hunting Odoo 18.0 (github.com/odoo/odoo, branch 18.0) for <CLASS>. Prove it LIVE or return
an honest negative.

== CRITICAL WORKFLOW RULE ==
Create <ABS_PATH>.md AT THE START with a skeleton and APPEND/EDIT it after EVERY significant step.
Never hold results only in your head. Keep shell commands small; one focused probe per call.

== LAB ALREADY RUNNING (use it; do NOT build a new one) ==
- sudo docker ps → <pg container> + <odoo container> (version). Docker needs sudo.
- Odoo http://127.0.0.1:8069 ; postgres host (container-to-container) = db, user/pass <...>
- dbfilter = ^<db>$ is set and REQUIRED for auth='public' routes to be reachable (no session +
  multiple DBs ⇒ only auth='none' routes are served, public routes 404). Do not remove it.
- DB <db>; admin login db=<db> / admin / admin. DB role is a superuser.
- Install: sudo docker exec <odoo> odoo -d <db> -i <modules> --without-demo=all --stop-after-init
  --db_host=db --db_user=odoo --db_password=odoo   (then: sudo docker restart <odoo>)
- SQL: sudo docker exec <pg> psql -U odoo -d <db> -c "SELECT ..."
- Python: sudo docker exec -i <odoo> odoo shell -d <db> --db_host=db --db_user=odoo
  --db_password=odoo --no-http < script.py   (inside, `env` exists; END WITH env.cr.commit()
  or your whole fixture setup is discarded)

== SOURCE ==  <path to the 18.0 checkout> + the specific controller/model files for this surface.

== ODOO'S QUALIFYING CLASSES ==  SQLi in public API · XSS · broken auth/session allowing
unauthorized access · broken sandboxing → code execution.
Non-qualifying (auto-close): SSRF, user enumeration, open redirect, rate-limiting, header/SSL,
default ACL/record-rule config, public info disclosure, prior-ATO-required.

== ALREADY ELIMINATED — DO NOT REDO == <paste the current elimination list verbatim>

== TEST DESIGN == <the exact fixtures to plant, the exact routes to probe, with ids/fields>

== HARD RULES == own lab only · no DoS · NEVER fabricate · show state-before + marker-in-response +
control run · if it stalls, mark BLOCKED and move on.

== DELIVERABLE == <ABS_PATH>.md written incrementally: verdict PROVEN|NEGATIVE; for a proven bug the
route, auth level, raw request/response, DB state, at-fault file:line, impact and the control run;
for a negative, each surface tried and the precise control that blocked it. Then print a short
final summary.
```

## Parent duties after every return (do these, in order)

1. **Verify the artifact on disk.** `ls -la <expected path>` — if the agent says it "would have"
   written it, it does not exist. Reconstruct it from the cached full summary (the payload names the
   path) and say plainly that you completed it.
2. **Spot-check one factual claim against ground truth.** The money-flow agent claimed specific
   modules/providers/products were installed and configured; a `psql` query confirmed them
   (`payment_provider` custom=enabled, demo=test). Setup claims are cheap to verify and expensive to
   trust.
3. **Independently re-run the single key claim** before relaying it — one `curl`. In the reference
   session the `/slides/slide/<id>/share` title leak was re-run with its controls and matched exactly;
   that is what turns a self-report into a finding.
4. **Read the middle of the cached summary**, not just the truncated head/tail — that is where the
   verdict table lives.
5. **Complete the file yourself** if the agent capped out before its verdict, marking which parts are
   the agent's probes and which you verified.