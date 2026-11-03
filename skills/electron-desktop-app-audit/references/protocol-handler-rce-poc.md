# Turn a static protocol-handler finding into a dynamic PoC

> **Order the asks cheapest-first.** Before this runbook, ask for the zero-setup probe: an
> **already-registered** OS scheme with a harmless visible effect (`ms-settings:` opens Settings;
> `mailto:` opens the mail client). One `.ics` plus one click settles *reachability* with no script
> and no registry edit; escalate to L0–L4 only when **process-level** evidence is demanded.
> On the Krisp hunt the operator was given the PowerShell runbook when a single `.ics` would have
> settled it — the heavy artifact got deferred, the cheap one would have been run on the spot.
> A runbook nobody runs produces zero evidence, however well designed.

A static `shell.openExternal` chain is HIGH confidence and **zero** severity. This is the
procedure that converts it, using payloads that cannot damage the operator's machine.

## The design constraint

Do **not** reach for `ms-msdt:`, `ms-appinstaller:`, `search-ms:` as the primary payload when
the PoC runs on someone else's box. Those are real handlers: `ms-appinstaller:` installs a
remote package, `ms-msdt:` spawns diagnostic tooling, `search-ms:` leaks NTLM or pulls remote
content. They can break the host or trip AV — and the finding does not need them.

**What the finding actually claims is narrower and easier to prove:** an arbitrary scheme
reaches `shell.openExternal`, so Windows executes a program of the attacker's choosing.
Prove exactly that with a handler you control.
`scripts/poc_protocol_handler.ps1` registers `HKCU\Software\Classes\<scheme>` (no admin) whose
command appends one timestamped line to a log file. Handler fires ⇒ code execution is proven,
with no side effects. Keep the `ms-*` variants in the report as *impact discussion*, not as the
PoC payload.

## Procedure

**L0 — handler self-test (the control that makes the whole thing non-false-positive).**
Install the handler, `start <scheme>:selftest`, confirm exactly one log line, then delete the
log. If the self-test writes nothing the harness is broken; any later "no execution observed"
is a false negative, not evidence the target is safe.

**L1 — build the invite.** `scripts/gen_calendar_poc_ics.py "<scheme>:calendarjoin"`.
It writes the payload into all five conference/URL fields because any single field may be
dropped by whichever calendar the victim uses, and a dropped field produces a no-op that
reads like a secure app.

**L2 — deliver.** Mail the `.ics` to the calendar address, Accept it, wait for the client's
sync interval.

**L3 — trigger.** Click Join in the app. Note the *exact* UI affordance — "Join", "Open
meeting", a tray notification action — because the report has to name the single click.

**L4 — verify.**
```powershell
Get-Content <log>          # expect: [...] FIRED   "poc-zoya:calendarjoin"
```
Optional corroboration when process-creation auditing is on: `Get-WinEvent -FilterHashtable
@{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-10)}` filtered on the handler
name. Do not require it — auditing is usually off, and the log line is the proof.

## Expected vs actual vs control — all three, always

| | Observation |
|---|---|
| **Expected (safe)** | log stays empty; app normalises or rejects the scheme |
| **Actual (bug)** | one log line containing the injected URI |
| **Control** | log empty *before* the Join click; only the manual `selftest` line ever appears |

## When the log stays empty

The most likely cause is **not** a safe sink — it is the *unproven hop*: the backend normalised
the field before it ever reached the client. Check the server side directly rather than
concluding anything: with the account's token, `GET` the calendar endpoint
(`/calendar-events/2` and any `*-with-meeting-bots` sibling) and inspect the field in the raw
response.

- Field still holds the payload ⇒ provenance is proven; the client deliberately refused it, so
  the finding is a **blocked** branch, not a bug. Write that.
- Field was rewritten ⇒ the *sink* is still unvalidated but unreachable via this input. The
  finding degrades to "defence missing, no demonstrated input path" — say exactly that. Do not
  round it back up because the code still looks bad.

## Handing the PoC to the operator

When the operator holds the only matching OS host, ship a **runbook bundle**, not a payload:

- numbered steps, each with the exact command to paste;
- the L0 control stated as mandatory and first;
- expected vs actual per step;
- cleanup commands (uninstall the handler, delete the log, remove the calendar event);
- a "send back" list: the log file, a screenshot of the app UI showing the trigger affordance,
  and before/after state for any session-swap claim;
- one line stating what a **failure** means, so the operator does not read a silent no-op as
  "nothing here".

Package it as a zip with a README that opens with the constraint that made the design benign.
An operator who understands why the payload is harmless will actually run it.

## What this does and does not upgrade

It upgrades **CONFIDENCE: HIGH → PROVEN** for the sink-and-execution claim, which is what makes
a Critical submission defensible. It does **not** by itself prove prevalence, blast radius, or
that an unprivileged remote attacker can reach the input — those stay as named assumptions in
the report.
