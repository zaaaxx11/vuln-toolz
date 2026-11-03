# Chain-closure audit — when the honest deliverable is a closure table, not a finding

Companion to `references/truncation-and-reachability-discipline.md` §2 (capability ≠
reachability), `references/unbound-parameter-and-permissionless-injection.md` §6
(guard ORDER), and `references/derived-address-identity.md` (is the "victim" a derived
alias? does its balance refill? did a prefix ever get resolved by scanning BLOCKS
rather than a filtered txlist?). Read this when the hunt has proven a real defect but every attempt to
turn it into value movement dies at a gate, and the rounds keep producing near-misses.

The trap this file prevents: **once a defect is proven, every subsequent round starts
from "how do I get past this gate" instead of "is this gate passable at all"**. That
framing produces confidently-announced breakthroughs that are demolished one round
later. In this campaign it happened four times in a row (R29→R30→R31).

---

## 1. The shape of the ending

Not every authorized-scope audit ends in a CRITICAL. A defensible ending looks like:

```text
FINDING   : <the proven defect>            -> IN-CODE, graded by holder census
NON-FINDINGS: N gates enumerated, each closed with one labelled probe
DELIVERABLE : the closure table + the removal condition for each gate
```

The closure table **is** the report. It says: "here is every way in, here is why each
is shut, here is the one thing that would reopen it." That is more useful to a protocol
than a speculative writeup, and it is not a failure to produce it.

**Never manufacture a finding to avoid ending a hunt.** The pressure to keep an active
campaign productive is exactly what produced the false headlines below.

---

## 2. The four near-misses, in order, with the tell that each carried

| # | Announced | Killed by | Tell that was visible before announcing |
|---|---|---|---|
| 1 | "200 trillion units — REAL FUNDS FOUND" | tuple field was `chainId`, not `supply` | struct had no supply field in the ABI `internalType` |
| 2 | "6.89 M units real balance on Hub#1" | ids were `tid % 10**12` from a display print | every id was a 12-digit number on a 256-bit field |
| 3 | "`setOperator` from attacker → CRITICAL" | body is `_setOperatorFor(msg.sender, …)` | positive control (victim on itself) also reverted |
| 4 | "`callResolver` unbound → redirect token to attacker" | `HUB.transfer` takes `from = address(this)` | the NatSpec + one body read would have shown it |
| 5 | "victim balance swinging 0↔8.3e9 → bypass is live & draining" | the address was a **derived `spenderAlias`**; churn is the fill/burn design | balances that **refill** between thefts are pools, not victims |
| 6 | "Allocator#1 unfindable — prefix invalid" (held 14 rounds) | address was `tx.to` in blocks already being fetched | `txlist` is a **filtered** view; a contract called by many EOAs never appears in it |

Rows 5–6 are detailed in `references/derived-address-identity.md`; they are the two
distinct failures of *instrument choice* rather than of decode.

All four were **self-caught** and publicly retracted. The retraction discipline worked;
the *announcement* discipline did not. Cost: four rounds of noise in the ledger.

### The one rule that kills all four

> **Before interpreting any call result, answer: which parameter of which function is
> the sink, and whose balance does that sink debit?**

If the answer is `address(this)` / `msg.sender`, an attacker-chosen parameter elsewhere
in the call **cannot** reach a third party's balance. That question takes one `grep` of
the sink and settles the majority of "unbound parameter" theories without a probe.

---

## 3. Enumerate gates as rows; close them with one probe each

When a proven defect has no path to value, stop hunting and start **enumerating**. One
labelled row per gate, each with the probe that closed it and the condition that reopens
it:

```text
GATE                              PROBE RESULT                      REOPENED BY
callResolver (UNBOUND)            from=Executor, so third party       executor gaining a
                                  balance unreachable   [CLOSED]      caller-supplied `from`
orderAddress                      inside signed digest   [CLOSED]     digest change
receiver                          inside signed digest   [CLOSED]     digest change
nonce / deadline                  signed + usedRequests  [CLOSED]     —
ORACLE_ROLE on Executor           1 holder, 2-of-5 msig  [CLOSED]     new oracle, or signer compromise
multisig threshold                4 checks, all correct  [CLOSED]     threshold set to 0 (onlyOwner)
OPERATOR_ROLE on Hub              1 holder, a contract   [CLOSED]     EOA grant anywhere
                                  with no caller-reachable
                                  transferFrom           [CLOSED]
```

Two properties make this valuable: it is **falsifiable** (each row has a probe), and it
names **who can reopen it** (the monitoring note), which pure "no exploit found" prose
never does.

---

## 4. Reading a guard "chain" correctly — the L-level audit

For a privilege chain `attacker → contract A → contract B → value`, audit each link for
**caller identity**, not for the presence of a check:

```text
L1  can the attacker call A's entrypoint with chosen args?        (often yes — public)
L2  does A's body pass attacker-chosen input to B as a DEBIT of a third party?
      - HUB.transfer(x, …)      -> debits address(this). Attacker wants debit=victim. CLOSED.
      - HUB.transferFrom(v, …)  -> debits `v`. Attacker wants v=victim. Needs A to accept v.
L3  is `v` bound to something the attacker cannot produce?        (signature, digest field)
L4  is the signature unforgeable and un-replayable?               (threshold, usedRequests, deadline)
```

**L2 is where three of the four near-misses died.** `transfer` vs `transferFrom` in the
callee is the entire difference — `transfer(callResolver, id, amt)` moves
*the caller's own* tokens, no matter who is named first in the argument list.

Write the sink signature down before reasoning about the argument list:

```python
# grep the sink, do not infer it
#   HUB.transfer(receiver, id, amount)          -> balanceOf[msg.sender][id] -= amount
#   HUB.transferFrom(sender, receiver, id, amt) -> balanceOf[sender][id]    -= amount
# same-looking call sites, opposite debit side
```

---

## 5. `eth_call` success on a composite path does not move value

A composite entrypoint that returns cleanly in `eth_call` proves only that the gates
before the first state-dependent failure were cleared. It proves **nothing** about
whether value would move if mined, and nothing about whether an attacker could trigger
it. Keep the two labelled lines from
`truncation-and-reachability-discipline.md` §2:

```text
CLAIM A (capability): the differential is clean; the privileged contract can debit a
                      third party.                        -> PROVEN
CLAIM B (reachability): an attacker can become / drive that privileged contract.
                                                          -> UNPROVEN or REFUTED, state which
```

If a round closes B as REFUTED, **the finding does not disappear** — it stays IN-CODE at
the level the holder census supports. Refuting reachability changes the *severity*, not
the *existence*, of the defect. Conflating those two is how real defects get dropped.

---

## 6. Round-budget heuristic: when to stop hunting

```text
IF  the defect is proven
AND N consecutive rounds produced no new gate opening
AND each round's best idea was killed by a body/source read
THEN stop hunting, write the closure table, and name the reopen conditions.
```

Two consecutive rounds without a *new mechanism* is the BLOCKED trigger (CDC §3). A round
that only re-tests a refuted hypothesis is not a round; it is churn, and churn is what
produces the announcement failures in §2.

The correct next deliverable at that point is a **single-finding report** in the standard
format — VULN / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE / MITIGATION /
VERIFICATION plus the claim-vs-proof table — carrying the proven defect at its honest
grade with the closure table as COVERAGE.

---

## 6b. Prove the closure empirically — the binding test is often the whole ending

A closure table built from *source reading* ("the digest includes `keccak(receiver)`,
therefore substitution is impossible") is only an argument. It becomes **evidence** with a
mutation harness, which is read-only, cheap, and needs no fork or key:

```text
receiver XOR 1 bit   -> digest CHANGED
amount   +1          -> digest CHANGED
nonce    +1          -> digest CHANGED
data  byte-by-byte   -> 5664 bytes tested, 0 unbound
cross-allocator      -> digest DIFFERS (no cross-instance replay)
(spender,nonce) dup  -> 2nd tx REVERTED (nonce ledger live)
census 2,420 wd      -> 1 "collision" = identical params already reverted
```

That block, not a paragraph of reasoning, is what closes the parameter-substitution
class. Prefer spending the last rounds on **mutation evidence for the closure** rather
than on one more speculative gate. Harness + verdict template:
`references/signature-binding-verification.md`.

Corollary: a round that produces a **REFUTED with a measured number** is a productive
round. Two rounds that each only re-theorise a closed gate are churn (§6).

---

## 6c. Do not let a system sweep become a finding factory

A systematic enumeration (all builder registrations across all chains → batch
`eth_getCode`) is the correct move *before* theorising about one instance, and it also
keeps you honest: 161 entries swept produced **one** suspicious row, and that row turned
out to be a legitimate deprecation (builder zeroed, zero withdrawals afterwards).

The failure mode to avoid: the sweep surfaces an anomaly, the anomaly "confirms" the
theory you already had, and the row is written up before the receipt is pulled. The sweep
only ever generates **candidates**; every candidate still needs the receipt/deploy-tx
evidence chain from Rule 19. Also watch for decode garbage in sweep output (an undecoded
`bytes` chainId printed as raw control characters) — fix the decoder before quoting counts
from the table.

---

## 6d. The mirror audit — prove the DEFENCE is effective, not just that the gate is closed

§3–§6c audit gates that block **you**. Do the mirror too: enumerate the controls the
protocol deployed to bound **its own** risk, then prove each one actually bounds
something. A control can be present, allowlisted, correctly coded, and **inert** — and
that is a reportable HIGH on a path where the loss would land.

Checklist per control:

```text
1. locate it        (rate limiter, fee calculator, circuit breaker, cooldown, cap)
2. is it WIRED?     oracle.isRateLimiter(x) == true; isFeeCalculator(x) == true
3. read LIVE params (not deploy scripts, not docs — the deployed storage)
4. does the parameterisation defeat the purpose?
5. is it even REACHED in production? decode the action stream and count
```

### The worked case — a USD token bucket with `rate == capacity`

```text
getBucket("base")   -> tokens 1e22, capacity 1e22, rate 1e22, enabled true
getBucket("solana") -> tokens 1e22, capacity 1e22, rate 1e22, enabled true
history: 66 BucketConfigSet events, ALL in one block, ALL capacity=rate=10,000 USD
```

The contract's own NatSpec defines the bound as `~ capacity + rate*T`. With `rate == capacity`:

```text
refill empty -> full = capacity/rate = 1.000 s
=> the bucket is never meaningfully depleted
=> the mechanism degenerates from a RATE limit into a PER-DEPOSIT CEILING
=> no cumulative and no per-window constraint at all
```

That is the opposite of what a rate limiter is for, and the opposite of its documentation.
Grade it as **control-ineffectiveness, HIGH**, and always add the reachability line:
*"real loss still requires the oracle key — this is a defence-in-depth failure, not an
unprivileged exploit."*

### The general shape to hunt

```text
rate == capacity            -> no rate limit, only a burst cap
capacity == type(uint256).max -> unlimited, enable=false in disguise
threshold == 1 on a "multisig" -> single key
maxFee == type(uint256).max  -> no fee cap (see the fee-calculator note below)
cooldown == 0                -> no cooldown
```

### Distinguish INERT from DORMANT — they grade differently

| observation | label | grade |
|---|---|---|
| control wired, params defeat purpose, path exercised live | **INERT** | HIGH control failure |
| control wired+correct, but the path never executes (`feeCalculator == 0` in 19/19) | **DORMANT** | hardening note, not a finding |
| control absent entirely | design gap | grade by blast radius |

For DORMANT, do **not** promote to a finding — but *do* record the guard gap that would
make it live. In the worked case:

```solidity
if (fee.amount != 0) HUB.transferFrom(fee.payer, fee.recipient, fee.currency, fee.amount);
```

`fee.payer` comes straight from oracle-attested `data`
(`abi.decode(data,(uint256,uint256,uint256,address,address))`) with no binding to the
deposit's own payer; the only gates are `feePayer != 0`, `feeAmount <= maxFeeAmount`, and
the calculator allowlist. Combined with a global-operator hub, that `transferFrom` would
need **no allowance**. Report as: LATENT / UNPROVEN, "the payer field is
controller-chosen and the allowlist is the only guard — validate fee.payer against the
deposit's payer and cap fee.amount independently." That is the honest boundary between a
design note and a claimed vulnerability.

### Counting reachability is the cheap half

Before grading a fee/limiter path, decode the action stream and count:

```text
MINT 18,466 | TRANSFER 18,460 | BURN 0 | FAST_MINT 17
                                          ^^^^^^^^^^^ 17 of 36,879 = the whole sample
```

17 FAST_MINTs is small enough to **read every one by hand**. Do that rather than sampling —
the payoff in the worked case was `feeCalculator == 0x0` in 19/19, which killed a
"attacker-controlled fee payer drains balances" theory in one pass and downgraded it from
CRITICAL to LATENT.

## 7. Retraction protocol (used four times here, keep it)

When a claim announced in an earlier round collapses:

1. State the retraction **first**, in its own block, before any new result.
2. Name the exact mechanism (`tid%10**12`, `w[6]` not the tokenId, field 5 is chainId).
3. Mark it struck in the ledger with the reason, not silently dropped.
4. Do **not** substitute a replacement number unless it was re-derived from a fetch in
   that same run.
5. Count retractions in the round summary. A high count is not shameful — a round with
   zero self-refutations is under-checked (Rule 14/checklist item 10).
