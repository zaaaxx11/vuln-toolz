# Engagement Closure & Handoff — proven-only reporting, resume state, disk hygiene

Everything here was learned closing out a multi-hour "find one pre-auth RCE chain"
engagement where the headline chain died. The deliverable shifted from an exploit to an
honest findings package, and three process lessons came out of that shift.

---

## 1. Classify every finding into PROVEN / DEAD-END / UNTESTED before writing anything

The single most useful artifact of the closing session was a three-bucket table. It
stopped the report from drifting back toward the disproven headline and gave the user
something actionable in one screen.

| Bucket | Definition | Example from this engagement |
|---|---|---|
| **PROVEN** | executed, with real output (finalized tx / curl response / file written) | `join_channel` no gate (finalized tx), Jinja2 `lookup('pipe')` RCE (file written), mass disclosure (3,954 records) |
| **DEAD-END** | tested and failed, with the error code recorded | forged membership → `InvalidMembership 6002`; self-authorize → `Unauthorized 6000`; program upgrade hijack → `authority opt = 0` |
| **UNTESTED** | identified but not executed, with the exact blocker | forged 160-byte account — needs 34,120 lamports |

**Never let an UNTESTED item sit next to PROVEN items without its blocker stated in
lamports / bytes / a named missing input.** "Cannot test due to insufficient funds" is
not a blocker statement; "rent 1,463,040 vs balance 1,428,920 → deficit 34,120 lamports"
is.

**Do not re-litigate DEAD-END items when the user says "cari terus".** They are asking
for *new* surface, not a re-run. The correct move is the systematic sweep (every writer
of the privilege field, then every state struct, then every handler with no membership
account at all) — which is how the zero-auth `add_meta` / `delete_meta` pair surfaced
after the privilege-field graph had already been declared closed.

---

## 2. "Is this a bug or just a theory?" — the answer the user actually wants

Asked directly: *"ini bug apa cuma theori, atau vuln biasa?"* The useful answer is a
two-table split, not a definition:

1. **Real, executed vulnerabilities** — each with class + severity. In this engagement
   seven of them, all in well-known classes (broken access control, IDOR, CORS
   misconfiguration, anonymous access, injection, hardcoded credentials).
2. **Theories that failed** — the pre-auth RCE chain, the forged-membership bypass, the
   PENDING→AUTHORIZED escalation.

Then the reframe that matters for a bounty submission: **these are ordinary
vulnerabilities, and that is good.** No exotic zero-day, no complex exploit chain — just
missing permission checks, which is exactly what bounty programs pay for. The practical
consequence is a framing rule:

> Do **not** submit the dead chain as the headline. A report that leads with a
> disproven "pre-auth RCE" gets rejected and damages the credibility of the seven real
> findings sitting behind it. Lead with the proven mass-disclosure + unauth-write, then
> the RCE-with-prerequisite, then the access-control gaps.

---

## 3. Resume state goes in a FILE, not memory — when the user asks for it that way

The user's instruction was explicit: **"jangan di memmory, cukup buat file saja."**
Memory was also at its char limit and the batch write failed six times — the file was
the right call regardless.

Write `<engagement>/RESUME_STATE.md` with these sections, in this order:

1. **PROVEN findings** — each with its proof artifact (tx signature, curl output, file
   path). A signature is worth more than a paragraph.
2. **DEAD ENDS — do NOT re-litigate** — a table of theory → why it failed → the error
   code. This is the section that saves the next session the most time.
3. **Verified mechanics** — the measured facts (borsh sizes, enum variant numbering,
   discriminator semantics, IDL-vs-source struct shape) so they are never re-derived.
4. **NEXT STEPS** — prioritized, each with its blocker stated numerically.
5. **KEY FILES** — path → what it is, so scripts are not rewritten.
6. **HARD RULES learned** — the operational ones (simulateTransaction is free, public RPC
   rate limits, subagent concurrency limits, verify subagent on-chain claims).

Then clean the disk in the same turn — see §4.

---

## 4. Disk hygiene after a Rust/Solana audit session

Anchor workspaces are disk-hungry and a full disk surfaces as *misleading* errors
(`final link failed: No space left on device`, `couldn't create a temp dir`, an
OpenSSL build failure). Check before and after.

```bash
df -h /                                    # before starting, and before reporting done
du -sh <root>/*/ | sort -rh | head -15     # find the hogs
du -sh <root>/*/target 2>/dev/null | sort -rh
rm -rf <repo>/target /tmp/<scratch-dirs>   # build artifacts + PoC scratch
```

What is safe to delete after the session:
- every `target/` directory (build artifacts — re-derivable, and the biggest hogs)
- `/tmp` scratch from standalone PoC harnesses
- prior subagents' `target/` dirs

What must survive: cloned repos' source, `findings/*.md`, PoC scripts, the resume-state
file, and any wallet keypair (chmod 600).

In this session: 423 MB free → 3.1 GB free by deleting `target/` dirs and `/tmp` scratch,
with all findings, scripts, and the burner keypair intact.

---

## 5. Session-shape lesson: budget the re-diagnosis

This engagement reached **four different verdicts on the same question** (forge dead →
offset mismatch → forge alive → forge dead with unisolated cause). Each flip was driven
by a new measurement, and each had to be stated explicitly rather than quietly
overwritten.

For any long "find the chain" engagement, plan for it:

- Keep a running verdict line and update it visibly when evidence overturns it.
- When you overturn your own conclusion, say so **with the evidence that overturned it**.
- Never let a correction harden into a permanent claim in either direction — including
  the corrective claim. The macro-source reading killed the "must be program-owned"
  theory, but the residual cause of the byte-correct forge failure was still unisolated
  and was reported as such.

A proven "no escalation exists" is a complete deliverable. An unproven "RCE" is not.
