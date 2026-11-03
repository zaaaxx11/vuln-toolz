# Verifying / refuting prior-round findings against deployed bytecode

Companion to `sui-move-exploit-patterns.md` (which covers *finding* bugs) and
`sui-move-onchain-audit.md` (recon). This file covers the **adversarial verification round**:
you are handed a list of candidate findings (often from a public audit workspace — see
recon file §7 item 6) and must return PROVEN / REFUTED / UNTESTED for each, against
**deployed immutable bytecode**, read-only, no transactions broadcast.

Worked end-to-end on a live Sui mainnet lending/leverage protocol (current.finance,
44-module lending package, all `Immutable`). 39 tool calls, 3 findings adjudicated,
1 live / 2 refuted.

---

## 0. The report file is the FIRST action, not the last

Create `findings/<TRACK>.md` with the full skeleton **before the first probe**:

```
VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE /
MITIGATION / VERIFICATION
+ STATUS BOARD (id | claim | verdict | confidence)
+ CLAIM-VS-PROOF table (claim | proof type | source | status)
+ REFUTED
+ UNTESTED
+ TOOL CALL LOG
```

Then append every ~5 tool calls. The file must **always exist on disk** — a session that
dies mid-probe leaves the partial evidence, not nothing. This is the same skeleton as
recon file §8, but for verification rounds the STATUS BOARD is the load-bearing part:
a reader should get the verdict distribution in one glance without reading any section.

---

## 1. THE technique: exhaustive caller-set enumeration to REFUTE a gate claim

The most common verification-round finding is of the form *"X blocks Y"* — a circuit
break blocks repay, a pause blocks withdrawal, a lock blocks liquidation. These are
usually **false**, and the refutation is one grep plus a full read.

### 1.1 The two-step proof

**Step 1 — enumerate every caller of the gate function.** Not "does repay call it";
enumerate the *closed set* of callers across the whole disassembly tree:

```bash
grep -rn 'has_circuit_break_triggered' evidence/disasm/
```

Worked result on a 62-module tree — 23 hits, and the caller set is small and closed:

```
liquidate_v1.txt:61, liquidate_v2.txt:61, liquidate.txt:61   <- liquidation
enter_market.txt:83, emode/enter_market.txt:83               <- enter market
liquidity_mining.txt:38                                      <- liquidity mining
flash_loan.txt:159                                           <- flash loan
emode/emode_admin.txt:48, :168, :228                         <- admin paths
```

**Step 2 — read the claimed-blocked function's full prologue and gate sequence** and
confirm zero references. For `handle_repay` (market.txt:1049-1168+) the gates present
were: non-zero amount, obligation-belongs-to-market, and
`enforce_post_borrow_repay_invariant`. Nothing else.

### 1.2 Why this is stronger than "I grepped repay and found nothing"

A single negative grep can be wrong — wrong module name, wrong function, a wrapper you
did not know about. The **closed caller set** cannot be wrong: if the set is enumerated
across every module and the target function is absent, the claim is refuted regardless of
how the call is spelled. Publish the full set in the report; it is the evidence.

### 1.3 The inversion is usually the real story

When a gate does not block the claimed path, check what it *does* block — the finding is
often the opposite of the claim. Worked case: circuit break blocks **liquidation**
(liquidate*.txt:61), so a triggered break *protects* borrowers from seizure while leaving
repay fully open. Publish that inversion explicitly; it converts a refutation into a
useful security note.

### 1.4 Also check the admin-only and no-auto-lift facts

For any gate claim, three sub-questions settle severity:

```bash
# who can set it?
grep -n 'trigger_circuit_break' evidence/disasm/market_admin.txt
#   -> public trigger_circuit_break<Ty0>(Arg0: &AdminCap, ...)   <- admin only

# who can clear it?
grep -n 'discharge_circuit_break' evidence/disasm/market_admin.txt
#   -> public discharge_circuit_break<Ty0>(Arg0: &AdminCap, ...)

# is there a time-based auto-lift? (look for &Clock in the core, not the admin wrapper)
grep -n 'trigger_circuit_break\|discharge_circuit_break' evidence/disasm/market.txt
#   -> market.txt:175 / :202 — NEITHER takes &Clock, no timestamp field written
```

The core functions take no `&Clock` and write no timestamp, so there is **no auto-lift** —
only a manual admin `discharge`. That is a real operational property worth one line, and
it is invisible if you only check "is repay blocked".

---

## 2. Refuting an accounting/reentrancy claim on Sui

The claim shape: *"there is a window between the ledger mutation and the cash mutation
where an attacker can re-enter."*

### 2.1 The hot-potato check kills it in one read

Sui's linear types close the EVM flash-loan reentrancy class at **compile time**. Check
the abilities clause on the returned struct:

```bash
grep -n -A3 'struct FlashLoan' evidence/disasm/market.txt
#   -> struct FlashLoan<phantom Ty0, phantom Ty1> {      <- NO `has` clause at all
```

No `drop`, no `store`, no `key` → the value **cannot be discarded or leaked**. It must be
consumed by `repay_flash_loan` in the same transaction. Combined with Sui's no-reentrancy-
on-a-single-object rule, the reentrancy window does not exist. Cite the abilities line as
killer evidence in the REFUTED section.

### 2.2 Then check the ORDERING anyway — and report the direction of any drift

Even with no reentrancy, an accounting asymmetry can exist. Trace which fields each path
reads vs writes:

```bash
# does the outflow decrement the field the gate reads?
grep -n 'MutBorrowFieldGeneric\[3\](Reserve.cash' evidence/disasm/_r.txt
```

Worked result: `flash_loan_withdraw` (_r.txt:758-769) splits `underlying_balance` only and
**never writes `Reserve.cash`**, while `withdraw_underlying` (_r.txt:726-733) does
decrement it. So across a flash-loan round trip `cash` is net **+fee** while
`underlying_balance` is net 0.

**The severity turns entirely on the direction of the drift:**

| Direction | Effect on solvency gates | Verdict |
|---|---|---|
| `cash` drifts **UP** vs real balance | gates get **stricter** (`cash - ceil(cash_reserve) > amount`) | **Safe.** Cannot over-borrow or over-withdraw. |
| `cash` drifts **DOWN** vs real balance | gates get **looser** | **Exploitable.** Users can withdraw more than exists. |

Publish the direction with the gate arithmetic. "Cash drifts up, so the gates are
conservative" is a refutation with a documented residual; "cash drifts down" would be a
finding. Never report the asymmetry without the direction — that is the difference between
a note and a bug.

### 2.3 Confirm the ledger-before-cash ordering

Read the handler and confirm the obligation ledger is mutated before the reserve cash:

```
market.txt:953    obligation::try_borrow_asset      <- ledger first
market.txt:1027   reserve::borrow_amount            <- cash second
```

And confirm the interest accrual order in the refresh path:

```
market.txt:2362   accrue_interest (Reserve)         <- reserve index first
market.txt:2370   obligation::accrue_interest       <- obligation ledger second
```

Reserve-before-obligation means the obligation can never be credited *less* interest than
the reserve accrued. That ordering is the correct one; say so, because the reverse would
be a finding.

---

## 3. Verifying a namespace / squatting claim

Claim shape: *"an attacker can squat a shared namespace and deny it to legitimate users."*

### 3.1 The four facts that decide it

| Fact | How to read it | Worked value |
|---|---|---|
| Namespace is **global**, not per-user | the struct field lives on the shared object | `Referral.code_owner: Table<String, address>` (referral.txt:28) |
| **Length** of the generated key | `LdConst` feeding the generator | `LdConst[1](u64: 6)` (referral.txt:352) |
| **Alphabet** | the `LdU8` constants around the `Mod` | `LdU8(36)` + `Mod`, `LdU8(48)` ('0'), `LdU8(87)` ('a'-10) → base-36 `[0-9a-z]` |
| **Retry on collision** | is there a backward branch after the collision abort? | **None** — single draw, hard `Abort` |

```bash
# the collision check
grep -n -A12 'generate_referral_code' evidence/disasm/referral.txt | grep -E 'contains|Not|BrFalse|Abort'
#   -> table::contains -> Not -> BrFalse(43) -> Abort   (no loop back to re-draw)
```

### 3.2 The codespace arithmetic, and the honest bound

36^6 = **2,176,782,336**. State it, then immediately bound it: at ~1 registration per
transaction, exhaustion is **not economically feasible**. REFUTE the exhaustion sub-claim
explicitly, so the report is not read as claiming 2 billion codes can be taken.

### 3.3 What IS live: targeted vanity squatting + progressive DoS

Two real consequences survive the exhaustion refutation:

1. **Vanity squatting.** Any 6-char `[0-9a-z]` string is a valid code, so an attacker who
   crosses the (cheap) qualification threshold can pre-register high-value codes —
   dictionary words, brand names, repeated characters. Check whether any removal path
   exists: `grep -n 'table::remove' <module>.txt` → **zero hits** means the code is lost
   permanently.
2. **Progressive DoS on honest users.** Because generation is single-attempt with a hard
   abort, a legitimate user who draws an already-taken code gets a transaction failure
   rather than a re-draw. As the table fills, honest generation fails at a rising rate.
   This is a self-inflicted DoS that scales with squatting — publish it as part of IMPACT.

### 3.4 Check the referee side too

A referee can usually only map to an **existing** code:

```
referral.txt:518-526   try_map_referral_code aborts if !contains(code_owner, code)
referral.txt:533-541   aborts on self-reference
```

So squatting a guessable code is also a **rebate-harvesting** primitive: every referee who
maps to it credits the squatter's rebate balance. Name that, it raises severity from
griefing to profit.

---

## 4. Pitfalls specific to verification rounds

- **Do not present disassembly line numbers as `file:line`.** When the Move source is
  unavailable (the usual case — recon file §7), say so plainly: *"all code evidence is
  on-chain bytecode disassembly, not source."* Cite as `module.txt:LINE`, never as a repo
  path. (Same rule as recon file §7.)
- **A harness-only PoC is not evidence.** If a prior round's PoC defines its own structs
  (`struct Reserve { cash: u64 }` inside the test module) it proves nothing about the
  deployed struct. Re-derive from disassembly and say in the report which PoCs were
  harness-only. See exploit-patterns §2.3(d) for the three tells.
- **Absence-of-code claims need the closed-set proof.** "No admin path removes a code" is
  only credible with the grep that returned zero, quoted in EVIDENCE.
- **Keep PROVEN / REFUTED / UNTESTED as three separate labels** and never merge them.
  A finding can be PROVEN structurally while its *exploitability* is UNTESTED (no tx
  broadcast) — publish both halves.
- **UNTESTED is a real section, not a dumping ground.** List each open question with the
  exact query shape that would answer it (e.g. "live `code_owner` table size — needs an
  object query on the `Referral` object ID, which was not resolved"). That is what makes
  the next round cheap.
- **Default values are not live values.** `referral.txt:872` shows
  `0 => u64: 10000` for the deposit threshold, but the deployed object may have been
  updated via `update_referral_config`. Cite the default as a default, and put the live
  value in UNTESTED.

---

## 5. Budget discipline for a ~15-minute verification round

The worked round was 39 calls for 3 findings. The shape that fits the budget:

| Phase | Calls | What |
|---|---|---|
| Skeleton | 1 | `write_file`, full skeleton + status board |
| Per finding: locate | 2-3 | grep for the entry point + the gate function |
| Per finding: read | 3-5 | the function body, the callee, the collision/abilities check |
| Per finding: write | 1-2 | patch the section in |
| Finalize | 3 | status board, claim-vs-proof table, REFUTED/UNTESTED |

Batch independent reads into one assistant turn (two `read_file` calls on different
modules cost one round-trip). Never serialize a read that does not depend on a previous
read's result. The report file is appended at each milestone, so a budget overrun still
leaves a complete artifact.
