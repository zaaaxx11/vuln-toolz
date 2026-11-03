# Leverage / market arithmetic refutation — and the version trap that invalidates a whole tier

Worked case: a lane brief asking to hunt "leverage package internal arithmetic + unreviewed
market-module logic" for a fund-theft or state-corruption bug, plus re-verify 17 Sherlock
findings against "current deployed bytecode". ~15 min, READ-ONLY.

Two deliverables came out of it, and the second one mattered more than the first:

1. A clean **REFUTED** set for all five leverage-arithmetic hypotheses in the brief.
2. A **provenance correction**: the brief's "v2, Immutable" addresses were both **v1**, so every
   finding was against superseded bytecode and could not be called live.

---

## 1. The five leverage hypotheses, and the cheap test that kills each

The brief named five specific theories. All five died, each on a single structural observation.
The method generalises to any "the wrapper package's arithmetic is exploitable" brief.

| # | Hypothesis | The kill | Where to look |
|---|---|---|---|
| 1 | Swap path integrates Cetus; min-amount-out can be 0 | **No DEX import exists at all.** Full `use` inventory across every module = lending pkg + `float` + oracle + Sui framework. `borrow_swap`/`swap_borrow` name a collateral↔debt *role* swap inside the lending market, not a trade. | module header `use` block, lines ~3-24 of each |
| 2 | Manipulated spot price inflates the borrowed amount | **Every price read feeds an `event::emit`.** Map each call site of the price accessor to its consumer; if all consumers are events, no amount is derived from a price. All value-moving amounts are caller-supplied `u64` passed straight into the lending package. | grep the accessor, then read each enclosing function's tail |
| 3 | Request/complete split reads price at complete → stale-price manipulation | **No price is stored, and the split cannot be stretched.** Both hot-potato structs have **zero abilities** (no `has` clause) → cannot be stored/dropped/transferred → must be consumed same-tx or the PTB aborts. The `mark_leverage_ongoing` flag therefore can never be left stuck, because an unconsumed potato rolls the whole tx back. | `struct ... <phantom ...> { ... }` declarations — check for a `has` clause |
| 4 | Flash loan can be repaid with less than borrowed | `required = fee + loan_amount`, both read from the **trusted `FlashLoan` receipt object** minted by the protocol, not attacker input. `coin::value < required` → abort. | the `complete_*` function's comparison block |
| 5 | A delegate holding the owner cap can drain a user position | The cap is an **owned** object (`has store, key`) that *embeds* an `ObligationOwnerCap`. Every delegate fn takes it by **shared** reference and returns withdrawn value to the caller. There is no delegate-only extraction path. | the cap struct + the delegate module's signatures |

### 1.1 The only real arithmetic in the package — and why it holds

Two helpers were the entire arithmetic surface. Both derive from a `collateral_amount` function
returning `(underlying, ctoken, exchange_rate)` with `underlying = floor(exchange_rate * ctoken)`.

- `enforce_ctoken_deduciton`: aborts if `requested > underlying_total`, then returns
  `min(ceil(requested / exchange_rate), ctoken_total)`. The clamp is defensive and correct —
  `ceil(floor(r*c)/r) <= c` always holds, so it never silently over-withdraws.
- `enforce_collateral_deduciton_by_percentage`: `percentage >= 100` → full balance; else
  `floor(percent * ctoken)` / `floor(percent * underlying)`. A `u8` max of 255 is caught by the
  `>= 100` branch, so `from_percent` never sees an out-of-range input.

**Rule: state the rounding direction explicitly.** Both `floor` in the protocol's favour or
neutral — that sentence is the finding, and it is what makes a REFUTED verdict credible rather
than a shrug.

### 1.2 The downgrade that the negative result earns

The pre-known finding in this lane was "leverage prices off unguarded `user_oracle::get_spot_price`
with no divergence guard". Once you establish that every price read is event-only, that finding
**materially downgrades for the wrapper package specifically**: an unguarded accessor cannot
inflate a borrowed amount when no amount is derived from it. The real oracle exposure lives in the
lending core's health checks, not in the wrapper's arithmetic. Say this explicitly — it is the
difference between "I found nothing" and "I relocated the finding to where it actually is".

---

## 2. The version trap — the most important thing in this file

### 2.1 What happened

The brief supplied two "VERIFIED FACTS": leverage at `0x042a1a41…` and lending at `0xfe1d89…`,
both described as "v2, Immutable", with the conclusion "anything unfixed is still exploitable".

Live GraphQL said otherwise:

```
object(address:"0x042a1a41…"){ asMovePackage { address version } }  -> version:1
object(address:"0xaab00c77…"){ asMovePackage { address version } }  -> version:2
object(address:"0xfe1d89…"){ asMovePackage { address version } }    -> version:1
object(address:"0x45bae04…"){ asMovePackage { address version } }   -> version:2
```

Both packages had been **upgraded**. The disassembly on disk carried the **v1** module headers:

```
evidence/disasm/lev/leverage_obligation.txt:2  -> module 42a1a418bf977d5306aa783288eebbc2e3ca9200b533fba7feda521e60d199e.leverage_obligation
evidence/disasm/market.txt:2                   -> module fe1d8929d13b00aaecd7642dec1c6d41cab82882a1b139efa46bf61dfd6380bf.market
```

So an entire Sherlock re-verification tier — H-01, H-02, and 12 M-xx rows — was auditing
**superseded code** while believing it was auditing the live deployment.

### 2.2 The resolver confusion, resolved

`package(address:"0x042a1a41…")` returns `0xaab00c77…`. That looks like the resolver is
fabricating, and it cost two calls to settle. It is not:

- `package(address:)` follows the **upgrade chain to the latest version** and answers with the
  latest version's data for the whole package family.
- `object(address:)` returns the **exact object** you asked for.

Control test that proves the resolver is honest:

```
package(address:"0xdeadbeef…")  -> null
```

If the control returns `null`, the "wrong" answer is upgrade resolution, not corruption. (This
matches the existing `references/sui-move-onchain-audit.md` upgrade-linkage section — the new
lesson is applying it to *your own brief's premises*, not just to a bundle-vs-repo mismatch.)

### 2.3 The three-call gate, before round 1

1. `object(address:){asMovePackage{version}}` on **every** address the brief names.
2. `package(address:)` on each, to get the latest in the chain.
3. Confirm the `module <pkgid>.<name>` header in your disassembly matches the ID you intend to
   audit.

If (3) disagrees, **re-pull before writing a single finding**. Write the version into the report
skeleton next to the address — a version-less address is not evidence.

### 2.4 How to publish the invalidation

Do not quietly downgrade. Put a **provenance correction** section at the top of the report that:

- names the stale address and the live address side by side,
- quotes the four RPC responses,
- states plainly that the brief's premise ("Immutable") was false,
- lists which findings are affected,
- gives the exact re-verification steps for the next round.

Then set confidence honestly: "pattern present in v1 bytecode: CERTAIN. Still live in v2: LOW."
A finding you cannot call live is not a finding — but the v1 evidence is still worth keeping,
because it tells the next round exactly what to grep for.

---

## 3. The oracle-accessor asymmetry, done as a complete inventory

This is the reusable form of the existing §5.1 oracle-divergence method. Instead of diffing two
modules ad hoc, **enumerate every oracle call site in the module and map each to its enclosing
function and its guard strength.** On the worked target the entire `market` module had only 7:

| line | accessor | enclosing function | guarded? |
|---|---|---|---|
| 2511 | `get_price` | `validate_liquidation` (close-factor check) | no |
| 2590 | `get_spot_price` | `liquidate_calculate_seize_ctokens` | **no** |
| 2596 | `get_spot_price` | `liquidate_calculate_seize_ctokens` | **no** |
| 2719 | `get_spot_price_with_check` | `collaterals_usd_for_liquidation` | yes |
| 2832 | `get_spot_price_with_check` | `debts_value_usd_for_liquidation` | yes |
| 2947 | `get_price_with_check` | `debts_value_usd_non_liquidation` | yes |
| 3093 | `get_price_with_check` | `collaterals_usd_non_liquidation` | yes |

Seven rows, and the finding is visible in one glance: **the two unguarded reads are both in the
seizure function, while both eligibility functions are guarded.** A grep for the accessor names
plus a "which function contains this line" pass produces this table in about four tool calls.
Publish the table — it is far stronger evidence than a prose claim, and it makes the asymmetry
checkable by a triager.

Two details worth recording:

- The guarded variants additionally load the market's `ema_spot_tolerance` table and pass it as
  the tolerance argument — so the guard is *configured*, not hardcoded. Note where the tolerance
  comes from.
- The normal risk gate (`is_obligation_safe`) routes through the `*_non_liquidation` pair **and**
  additionally calls `ensure_secondary_checks_passed`. The liquidation path never calls it. That
  is a second, independent asymmetry layered on the first — worth its own row in the report.

---

## 4. Reading a Sui `Table` config value when the inner object is not addressable

`Market.ema_spot_tolerance` is a `GenericCoinTypeStorage<Decimal>`. The object payload shows a
`table` with an `id`, a nested `table.id`, a `size`, and a `keys.contents` list — but **no values**,
and the inner table ID is not directly queryable:

```
object(address:"<inner-table-id>")  -> {"object":null}
```

Dead ends hit, in order (record these so they are not re-probed):

- `dynamicField` / `dynamicFields` → **unknown field** on this endpoint.
- `multiGetDynamicFields(keys:[{parent, name:{type, value}}])` → `unknown field "value"`.
- `multiGetDynamicFields(keys:[{parent, name:{type, literal}}])` → "Name must specify either both
  'type' and 'bcs', or 'literal'".
- `multiGetDynamicFields(keys:[{parent, name:{type, bcs}}])` with a length-prefixed BCS TypeName →
  returns `[null]` (the encoding was still not what the indexer wanted).
- `object(address:){asMoveObject{dynamicField(...)}}` → same literal/bcs constraint.

**What DID work, and is enough for the report:** the table's **existence and size** are readable
from the parent object payload (`ema_spot_tolerance` → `size: 18`, keys listed). Publish that, and
name the per-asset numeric values as UNTESTED with the blocker stated. Do not spend more than a
few calls on it — the asymmetry finding does not depend on the numeric tolerance, only on the fact
that eligibility passes one and seizure does not.

Related: the `emode_group_registry` was readable the same way (`next_group_id: 15`, 15 groups) —
useful as a live-market sanity check even when group contents are not.

---

## 5. Report shape for a lane that mostly refutes

When a lane's honest answer is "the arithmetic is clean, but your premise was wrong", the report
still needs the full skeleton on disk from call 1 (the brief demanded it, and it is the right
instinct — see §8 of the SKILL.md). Fill it in this order:

1. **VULNERABILITY** — lead with the premise failure, then the strongest real code finding, then
   the negative result. The negative result is a deliverable, not an apology.
2. **ENTRY / CHAIN / IMPACT** — for each live finding, the entry point, the step-by-step chain with
   file:line at every step, and the impact with a number where one exists.
3. **POC** — read-only reproduction steps for the *next* round, since this round could not execute.
4. **EVIDENCE** — split explicitly into "static bytecode citation (v1)" and "real RPC response".
5. **CONFIDENCE** — one row per finding, with "present in v1" and "live in v2" as **separate
   rows**. Never collapse them.
6. **VERIFICATION** — the 17-row table with four states: YES / PARTIAL / UNTESTED / (implicitly)
   REFUTED. Name the missing module for every UNTESTED row.
7. **CLAIM-VS-PROOF** — including the negative claims (C1 "no DEX exists" is a claim and deserves
   a proof).
8. **REFUTED** — numbered, each with the kill and the file:line. This is what stops the next
   session re-probing.
9. **UNTESTED** — named blockers, not a vague "out of budget". "`limiter` module not on disk,
   blocks M-06" is actionable; "ran out of time" is not.

---

## 6. Pitfalls specific to this lane

- **A brief's "VERIFIED FACTS" block can be stale.** Treat it as a hypothesis to check, not a
  premise to build on. The version check is three calls.
- **`use`-list inventory beats reading every function.** To prove "no DEX", grep the `use` blocks
  across all modules once. That is the whole proof.
- **Map price accessors to consumers before concluding anything about them.** An unguarded
  accessor feeding only events is a different (much smaller) finding than one feeding an amount.
- **Zero-ability structs are the answer to every "can this be stretched across transactions"
  question.** Check for a `has` clause first; it is one line and it settles the whole theory.
- **`&` inside a shell heredoc gets eaten by the terminal guard.** Appending a report block with
  `cat >> file <<'EOF'` containing `take_revenue(&AdminCap, ...)` trips the foreground-`&` check
  and the whole append fails. Use the `patch` tool for any content containing `&`, `|`, or `;` in
  a Move signature. (Already in the SKILL.md pitfalls — it fired again here, on the access-control
  report, so it is worth repeating.)
- **Don't pipe `curl` into a Python interpreter** in this toolchain; the scanner blocks it. Write
  to a file first, then read the file — which also produces the evidence artefact for free.
- **A `u8` percentage is bounded by the `>= 100` branch, not by `from_percent`.** Read the guard
  before hypothesising an overflow.
- **State the rounding direction as a sentence.** "Both floor in the protocol's favour or neutral"
  is the finding in a REFUTED arithmetic verdict.
