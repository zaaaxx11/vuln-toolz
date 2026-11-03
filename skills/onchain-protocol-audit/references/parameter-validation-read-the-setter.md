# Validating a parameter claim — read the SETTER, not just the consumer

Companion to `sui-move-composed-chain-method.md` (build the chain) and
`finding-verification-against-bytecode.md` (adjudicate a list). This file covers one specific,
recurring error class that produced a **false LIVE** in a multi-round loop and cost a published
correction: **claiming a parameter is unvalidated after reading only the consumer.**

Worked case: `current.finance`, ADL subsystem, round 5 of a 6-hour hunt.

---

## 1. The failure, in full

A subagent dispatched to hunt cross-market composition returned this as its headline:

> **C-01 — ADL `close_factor` is an unclamped admin-set Decimal (potential >100% forced closure).**
> `adl::close_factor()` returns the raw `DeleverageParams.close_factor` Decimal
> (`adl.txt:397-403`). It flows into `LiquidationParams.close_factor` at `market.txt:1537`
> (debt-ADL) and `market.txt:1711` (collateral-ADL) with **no `float::le(one)` clamp** at either
> site.

Every line of that was accurate. The conclusion was wrong.

The consumer side really is unclamped — `adl::close_factor` is a bare `ImmBorrowField` +
`ReadRef` + `Ret`, and both `market.txt` sites really do `Pack[6](LiquidationParams)` straight
after the call. But the **producer** clamps it. `adl_admin::new_adl_params`
(`adl_admin.txt:34-70`) range-checks the argument that becomes `close_factor`:

```
adl_admin.txt:20-32
 20: LdU64(0)
 21: CopyLoc[8](Arg8: u64)
 22: Lt
 23: BrFalse(29)
 24: CopyLoc[8](Arg8: u64)
 25: LdConst[0](u64: 10000)
 26: Le                              <- 0 < Arg8 <= 10000
 27: StLoc[10](loc1: bool)
 31: MoveLoc[10](loc1: bool)
 32: BrFalse(34)
 38: Call error::invalid_params_error(): u64
 39: Abort

adl_admin.txt:59-62
 59: MoveLoc[8](Arg8: u64)
 60: LdConst[0](u64: 10000)
 61: Call float::from_quotient(u64, u64): Decimal   <- Arg8/10000, so max = 1.0
 62: StLoc[11](loc2: Decimal)
```

Field order in `DeleverageParams` (`adl.txt:27-34`):
`target_amount, liquidation_factor_base, liquidation_factor_hourly_drop,
liquidation_incentive_base, liquidation_incentive_daily_penalty, close_factor`.

So `Arg8 → close_factor`, constrained to `(0, 10000]` bps = **`(0, 1.0]`**. The >100%
forced-closure scenario is unreachable through the admin setter. **REFUTED.**

### Why it was missed

`adl_admin` was **not on disk**. The subagent enumerated the modules it had, found
`enable_collateral_deleverage` / `enable_debt_deleverage` were `public(friend)` with no caller in
the disassembled set, and concluded "the setter lives in an un-disassembled admin module — but the
consumer side is unclamped, which is the exploitable half." That inference is reasonable and it is
still wrong, because "un-disassembled" is a **fixable** state, not a fact about the chain.

**The fix is one GraphQL call.** Pull the missing module before concluding:

```graphql
{ package(address: "0xPKG") { module(name: "adl_admin") { disassembly } } }
```

---

## 2. The rule

> **A parameter-validation claim is only credible once the SETTER has been read.**
> "The consumer does not clamp X" is an observation. "X is unvalidated" is a claim about the
> whole write path, and the write path ends at the setter.

Corollaries:

1. **If the setter module is not on disk, pull it.** It is one call. "Un-disassembled" is not
   evidence of absence — it is evidence you have not looked.
2. **If the setter genuinely cannot be reached** (module absent from the package, or the field is
   written by a path you cannot enumerate), say *"producer-side validation UNTESTED — setter
   module `<name>` not retrievable"*. That is a different, honest verdict from "unclamped".
3. **Read the struct field order before mapping arguments to fields.** In the worked case the
   clamp is on `Arg8`, and `Arg8` is only the close factor because of the field order in
   `DeleverageParams`. Mapping by position without reading the struct is how you clamp the wrong
   parameter.

---

## 3. The narrower defect that survives — PARTIAL validation

Refuting C-01 did not leave nothing. `new_adl_params` takes **six** parameters and range-checks
**two**:

| Arg | Field | Divisor | Validated? |
|---|---|---|---|
| Arg3 | `target_amount` | — | no |
| Arg4 | `liquidation_factor_base` | 10000 | **yes** (`0 < x <= 10000`) |
| Arg5 | `liquidation_factor_hourly_drop` | 1000 | **no** |
| Arg6 | `liquidation_incentive_base` | 10000 | **no** |
| Arg7 | `liquidation_incentive_daily_penalty` | 1000 | **no** |
| Arg8 | `close_factor` | 10000 | **yes** (`0 < x <= 10000`) |

```
adl_admin.txt:47-49
 47: MoveLoc[5](Arg5: u64)
 48: LdConst[1](u64: 1000..)
 49: Call float::from_quotient(u64, u64): Decimal    <- no range check

adl_admin.txt:51-53
 51: MoveLoc[6](Arg6: u64)
 52: LdConst[0](u64: 10000)
 53: Call float::from_quotient(u64, u64): Decimal    <- no range check

adl_admin.txt:55-57
 55: MoveLoc[7](Arg7: u64)
 56: LdConst[1](u64: 1000..)
 57: Call float::from_quotient(u64, u64): Decimal    <- no range check
```

**This is its own defect class and it is worse than no validation**, because the two checks that
*are* present create false confidence — a reviewer sees `0 < x <= 10000` guards and assumes the
function validates its inputs.

`Arg7` (`liquidation_incentive_daily_penalty`) is unbounded and feeds
`adl::liquidation_incentive` = `base + penalty × days_since_activation` (`adl.txt:445-465`), which
is itself uncapped. So an admin typo on Arg7 produces an arbitrarily large liquidation incentive.
Admin-gated → robustness/operational finding, not a theft primitive. But it is real, it is not in
the public audit, and it is the *correct* version of the claim the subagent was reaching for.

**Rule:** when you refute a "no validation" claim by finding *some* validation, immediately
enumerate **which** parameters are covered. Partial validation is a finding in its own right, and
it is usually the thing the original claim was groping toward.

---

## 4. The same trap in a second guise — "zero guards" that is not a bypass

The same session produced a second overclaim from the same instinct. A subagent reported:

> **C-03 — Leverage package prices with raw spot, zero oracle guards across 11 modules.**

True as stated (the entire `lev/` tree contains exactly one oracle call,
`leverage_obligation.txt:306`, and it is the raw-spot one), but the implied conclusion — *the
leverage package bypasses the lending market's risk gate* — is false. The leverage package calls
into the lending package's gated entry points:

```
Call borrow::borrow
Call deposit::deposit
Call enter_market::enter_market_with_emode
Call flash_loan::borrow_flash_loan
Call flash_loan::repay_flash_loan_increase_referral_qualification
```

so the lending market's internal risk gate **is** enforced on those operations. What is unguarded
is the leverage package's **own valuation layer** — `get_price_usd` → `get_collateral_price` /
`get_usd_value`, which drive `request_leverage`, `complete_leverage`, `withdraw_size`,
`withdraw_leverage`, `request_reduce_*`.

**Correct statement:** the leverage package's own valuation runs on raw spot while the lending
operations it invokes run on guarded prices — the same asymmetry as H-02, in a different package.
Not a full bypass; a real mispricing surface on every leverage entry and exit.

**Rule:** "module X never calls guard G" is a fact about X. Before converting it to "X bypasses
the system's protection", enumerate what X *does* call. The protection may be enforced one layer
down, and the finding is then an asymmetry rather than a bypass — which is a different (and
usually smaller) claim.

---

## 5. The orchestrator-side discipline this implies

In a multi-round loop with subagents, the orchestrator is the only party who can catch this class,
because the subagent that wrote the claim is the one most committed to it.

1. **Never publish a subagent's LIVE finding without reading the cited lines yourself.** This
   session refuted two subagent claims (C-01, C-03-naive) in the same round, both with bytecode
   the subagent had already cited. Neither took more than a few calls.
2. **When you refute one, re-read the sibling claims in the same report.** Overclaiming is a
   *style*, not an isolated mistake — a subagent that overclaimed C-01 probably overclaimed
   C-02/C-03 too. In the worked case, C-02 and C-04 survived; C-03 needed refinement.
3. **Publish the correction in the report, not just in chat.** The report is the artifact that
   outlives the session. A silent edit means the next reader inherits the wrong claim. Name the
   subagent's error and the bytecode that killed it — that is what stops the next session
   re-deriving the false LIVE.
4. **Keep the narrowed finding.** Refuting the overclaim is not the same as finding nothing. The
   partial-validation defect (§3) and the valuation-asymmetry refinement (§4) are both real and
   both more precise than what was originally claimed.

---

## 6. Pitfalls

- **`public(friend)` with no visible caller does not mean the setter is unreachable.** It means
  the caller is in a module you have not pulled. Pull it.
- **Argument position ≠ field position.** Read the struct declaration before mapping `ArgN` to a
  field name. The clamp was on `Arg8`; `Arg8` is the close factor only because of
  `DeleverageParams`' field order.
- **A `from_quotient(x, 10000)` is a scale, not a bound.** The bound is whatever range check
  precedes it. `Arg8/10000` with `0 < Arg8 <= 10000` gives `(0, 1.0]`; without the check it gives
  an unbounded Decimal.
- **Do not let a refutation delete the finding.** "The close factor is clamped" and "three of six
  parameters are unvalidated" are both true. Report both.
