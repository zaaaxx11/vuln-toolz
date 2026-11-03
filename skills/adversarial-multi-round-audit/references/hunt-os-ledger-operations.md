# HUNT-OS ledger: operating an external hunt ledger from inside Hermes

Session-proven operating notes for driving the `hunt` CLI (HunterOS, `zaaaxx11/HunterOS`)
as the audit ledger instead of a hand-rolled `hunt_state.json`. Companion to
`adversarial-multi-round-audit` — that skill owns the *reasoning*; this file owns the
*ledger mechanics* and the traps that cost real cycles.

## 1. Is this a HUNT-OS skill at all?

`hunt-os` is a **ledger + router**, not a hunting playbook. It owns:

- the `hunt` CLI (SQLite ledger: targets, phases, findings, leads, waves, reports)
- a 50-skill corpus at `skills/<category>/<name>/SKILL.md` (recon/web2/web3/cdc/verification)
- role doctrine at `roles/<name>.md`
- a claim gate at `hooks/claim_gate.py`

Everything in `hunt-os/SKILL.md` is *contract text* (RoE, evidence ladder, "the CLI is the
only write door"). Real technique lives in the corpus, loaded one file at a time — never
bulk-loaded.

**Repo shape:** `zaaaxx11/HunterOS` is a Claude Code plugin (`.claude-plugin/`, `commands/`,
`hooks/`, `mcp/`, `agents/`, `skills/`, `marketplace.json`) *plus* a Python distribution
(`huntos` wheel, release assets + `SHA256SUMS`).

## 2. Install

```bash
git clone --depth 1 https://github.com/zaaaxx11/HunterOS.git /tmp/HunterOS
# READ install.sh to the closing brace BEFORE running it (it is 11 KB and touches $HOME)
bash /tmp/HunterOS/install.sh
```

The installer is well-behaved: downloads the wheel from the GitHub release, verifies
**SHA256 fail-closed**, installs into an isolated `~/.HunterOS/venv`, activates atomically
with rollback. Verify the release exists first — `releases/latest/download/SHA256SUMS`
returns empty if no release was published.

**`--adapter hermes` is a no-op pointer.** Its own help text says "no-op idea-injection
pointer" — it does *not* install skills into Hermes. To actually land the skill corpus:

```bash
hunt install --adapter generic --dir ~/.hermes/skills --mode router
hunt install --adapter generic --dir ~/.hermes/skills --check   # -> "check OK: N files verified clean"
```

Then confirm `~/.hermes/skills/hunt-os/SKILL.md` exists and `skill_view(name='hunt-os')`
resolves. `--check` returning a file count is the only trustworthy "installed" signal.

## 3. Bringing an in-flight audit into the ledger

Adopting HUNT-OS mid-campaign (after N manual rounds) is the common case. Order matters:

```bash
cd ~/work/relay-hunt                 # the ledger lives in the CWD
hunt target add "<name>" "<url>" --chain <id> --notes "<what N prior rounds already mapped>"
hunt target roe <id> --hosts "..." --actions "recon,read" --notes "<explicit read-only statement>"
hunt score <target> <ev>             # ev is YOUR evidence assessment, not a claim
```

Phase ladder is **gated by artifacts** — you cannot jump:

```text
scoring → recon        needs ev > 0
recon   → classify     needs artifact type=surface_map
classify→ hunting      needs artifact type=attack_plan
```

```bash
hunt artifact <target> surface_map  surface_map.md
hunt artifact <target> attack_plan  attack_plan.md
hunt phase <target> <next-phase>
```

Both artifacts must be **real documents**, not stubs: the surface map is the address/role/
entrypoint census you already have; the attack plan must state what is *still open* and
list the anti-repeat registry, so a future session cannot re-open a dead angle.

## 4. `klass` is a closed vocabulary — the ledger rejects invented taxonomy

```
hunt klass list   # Access, Oracle, Reentrancy, Sig, Arithmetic, ExternalCall, Logic, Upgradeable, Web2, Unknown
hunt finding add --target 1 --title "..." --klass <one-of-the-above> ...
```

An unknown `--klass` returns `BLOCKED: unknown klass`. That is a feature: do not invent
categories to make a finding fit, pick the nearest real one and put the nuance in the title.

**Case is significant and the vocabulary is small.** `logic`, `auth`, `Known`, `Design` are
all rejected. Copy a literal byte-for-byte from `hunt klass list`:

```
Access  Arithmetic  ExternalCall  Logic  Oracle  Reentrancy  Sig  Unknown  Upgradeable  Web2
```

Four consecutive submissions were burned guessing capitalisation (`logic`, `auth`, `Known`)
before dropping to `Access`. If in doubt run `hunt klass list` first — it is one cheap call
and it prints the exact strings.

### 4a. Positional order is `target_id title klass` — not `--target`, and the finding id is not a target id

```
hunt finding add 1 "<title>" Access --severity high --action read --falsifier "<...>"
                  ^target_id  ^title  ^klass
```

Two failure strings, two different mistakes:

```
BLOCKED: target #13 not found        -> the FIRST positional is target_id; you passed a finding number
BLOCKED: unknown klass 'Logic'       -> the THIRD positional is klass; case/spelling wrong
```

`hunt target list` gives the real target ids (in this campaign there is exactly one: `1`).
The finding's own id is assigned by the CLI and echoed back (`finding #13 added`). Also:
`--action` is `recon|read|auth-test|mutate`, **not** `read-only`.

## 4b. Downgrading a finding: `retitle` has NO `--severity`

There is no severity-edit verb. `hunt finding retitle --help` shows exactly two flags:

```
usage: hunt finding retitle [-h] --id ID --title TITLE
```

Passing `--severity info` returns `hunt: error: unrecognized arguments: --severity info`
and the retitle does **not** happen. The severity lives in the finding's recorded state, so
a downgrade (HIGH → INFO) is expressed by rewriting the title to carry the verdict and the
reason:

```bash
hunt finding retitle --id 13 \
  --title "Hub#2 ADMIN=single EOA 0x71d8…; mint() uncapped and _burn() sender-free BY CODE,
           but surface DORMANT: ORACLE_ROLE never set and GATEWAY_VM_ALLOCATOR_ALLOWED never
           written, so zero reachable mint/burn path exists even for the admin"
```

```text
RULE  a downgrade must be written into the title, in the same round as the evidence that
      caused it. Leaving the old HIGH title in place while the reasoning moved on is how a
      ledger ends up with a loud claim nobody can defend.

RULE  put BOTH halves in the title: the code-level defect AND why it is unreachable.
      "mint() uncapped, but DORMANT — key never written" is defensible; either half alone
      is misleading in opposite directions.
```

Also note `hunt finding add` help is not printed by `hunt finding add --help` in all builds —
run `hunt finding --help` or infer from `hunt target list` output. When in doubt, the working
invocation is the positional one in §4a.

## 5. `lead park` requires a TWO-SIDED tripwire: `"observable :: check"`

```
BLOCKED: lead L-8 retrigger must be 'observable :: check' (separator' :: ' required, both sides non-empty)
```

Every dead hypothesis must be parked with:

- **observable** — the on-chain/API fact that would fire
- **check** — the exact call that observes it

```bash
hunt lead park --lead 11 --retrigger "registered-dead lockbox 0xaa6ff104 gains mintingMaxLimitOf > 0 :: call mintingMaxLimitOf(0xaa6ff104); non-zero opens a cross-token path"
```

A one-sided string ("RelayMultisigSigner is deployed") is rejected. Write both halves or
you lose the park entirely. **Tripwires are strictly better than a flat `dead_hypotheses`
array**: they encode the condition that resurrects the hypothesis, so a later session can
re-check cheaply instead of re-deriving impossibility.

### 5a. Parking the same lead twice fails

```
BLOCKED: lead L-1 is parked — only open or mutating leads can park
```

`park` overwrites nothing. To revise a tripwire you must `reopen` first:

```bash
hunt lead reopen --lead 1 --evidence "administrative correction: placeholder retrigger being replaced"
hunt lead park   --lead 1 --retrigger "<real> :: <real>"
```

The `--evidence` on a reopen is a *record*, so state honestly that it is a metadata
correction and not an observed on-chain change. (Do not let the CLI's willingness to
accept any string turn into a fabricated observation.)

## 6. Batch-driving the CLI: always set `PATH`

The installer places the binary in `~/.HunterOS/venv/bin` and **does not** modify the
calling shell's `PATH` durably. Every script that shells out to `hunt` must begin with:

```bash
export PATH="/home/ubuntu/.HunterOS/venv/bin:$PATH"
```

Loop-drivers over many leads/findings should print `parked` / `BLOCKED` per line rather
than switching on exit codes — `hunt` returns 0 for several logical blocks and prints the
reason to stdout only.

## 7. Reading the ledger: `hunt brief` is the anti-repeat door

`hunt brief <target>` prints phase, ev, every finding with its **falsifier**, the whole
open-lead queue, and a CONTRADICTIONS block. Treat the contradictions block as the work
queue:

```
!! 2 loud claim(s) (critical/high) still theoretical with no evidence
!! 1 unclassified finding(s) — taxonomy hasn't learned this yet
```

The first line is the ledger telling you a HIGH finding has no PoC. That message is
correct and should be acted on (run the falsifier), not silenced by promoting the finding.

## 8. Evidence ladder, and what `overturn` means

```text
theoretical → in-code/reproducible → proven-live
        ↘ overturn (adversary/evidence wins at any stage; audit trail kept)
```

- `hunt verify <id> {fork_receipt,tx_hash,http_transcript} <body>` attaches a verification
  method. `in-code` needs a reproducible body; `proven-live` needs real execution.
- `hunt finding promote --id <int> --evidence-ref <ref> --poc-path <path>` — **POC PATH IS
  MANDATORY**. You cannot climb the ladder without a PoC artifact on disk. **A path is
  not a run**: `hunt poc run --id <int> --poc-path <file>` must return
  `exit=0 sha256:...` first, else `BLOCKED: this PoC has never been executed — existence
  is not execution`. That run executes in the HUNT-OS venv, which has no
  `eth_utils`/`eth_account` — see `references/poc-execution-and-portability.md`
  (portable keccak, PASS/FAIL claim harness, retitle-vs-overturn after a partial
  disproof).
- `hunt finding overturn --id <int> --by "<why the falsifier was met>"` — and the `--id` is
  an **integer**, not `F-1`. Passing the display label returns
  `error: argument --id: invalid int value: 'F-1'`. The display form is `F-<n>`; the API
  wants `n`. Cheap to avoid, easy to lose a turn to.
- An **overturn with a met falsifier is a legitimate result**, not a failure: the code can
  genuinely contain the weak pattern while live data shows the premise that guards it is
  respected. Record it as overturn with the live evidence, and say in the title what the
  residual design risk is.

## 9. Ledger + own-skill composition

Do not duplicate: `adversarial-multi-round-audit` owns the reasoning discipline (positive
controls, decode traps, verdict labels); HUNT-OS owns durable state. Practical split —

| Concern | Owner |
|---|---|
| What to test next, and why it's not a repeat | ledger (`hunt brief`, `hunt lead next`) |
| How to decode calldata / prove a gate | `adversarial-multi-round-audit` refs |
| Tripwire text for a dead angle | ledger `lead park` (two-sided, mandatory) |
| Verdict labels (HIGH-ROLE-ONLY / INFERRED-GATE / ARMED) | `adversarial-multi-round-audit` |

A hand-rolled `hunt_state.json` and the ledger can coexist only briefly — migrate, then
treat the CLI as the write door, because two ledgers that disagree is worse than one that
is incomplete.
