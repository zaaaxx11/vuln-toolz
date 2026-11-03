# Defending a composed chain — the kill-questions, answered before the adversary asks

Companion to `sui-move-composed-chain-method.md` (how to BUILD the chain) and
`sui-move-arithmetic-refutation.md` (how to refute). This file is the third move: **you have a
four-defect chain and a triager will try to kill it with six questions.** Answer them yourself,
with bytecode, before anyone else does. A chain that survives its own adversary is a finding; one
that does not is a draft.

Worked case: `current.finance`, the M-14 + M-12 + M-08 + H-02 liquidation chain.

---

## 1. THE question that decides the chain: what UNIT is the threshold in?

Every "below-threshold bypass" finding lives or dies on the denomination of the threshold. If
`close_factor_bypass_min_value = 5` means 5 base units of USDC (0.000005 USD), the bypass is
dust-only and the finding is noise. If it means $5, it is a realistic small-position threshold and
the finding is real.

**Never assume. Trace the compared value end-to-end.**

`market.txt`, `validate_liquidation`:

```
 97: Call debt::unsafe_debt_amount(&Debt): Decimal        <- debt amount (Decimal)
104: Call user_oracle::get_price(...): Decimal             <- price
108: Call coin_decimals_registry::decimals(...): u8        <- coin decimals
109: Call value::coin_value(Decimal, Decimal, u8): Decimal
110: Call float::ceil(Decimal): u64                        <- rounded to u64
112: ImmBorrowField[13](LiquidationParams.close_factor_bypass_min_value: u64)
114: Le
```

Then read `value::coin_value` itself (`value.txt:16-30`):

```
 5: MoveLoc[0](Arg0: Decimal)      <- price
 6: MoveLoc[1](Arg1: Decimal)      <- amount
 7: Call float::mul(Decimal, Decimal): Decimal
 8: MoveLoc[3](loc3: Decimal)      <- 10^decimals
 9: Call float::div(Decimal, Decimal): Decimal
```

`price × amount / 10^decimals` → **whole USD**, not base units. For USDC (6 decimals), a
threshold of `5` is **$5.00**, not 0.000005 USDC.

**Rule:** for any threshold compared against a value derived from `amount × price / 10^decimals`,
the threshold is denominated in whole USD. Publish the trace, not the conclusion — the trace is
what makes the claim checkable and what stops the next session re-deriving it.

**Corollary that strengthens the chain:** because M-08 makes the check *per debt asset*, an
obligation with five $4 debt legs ($20 total) has **every** leg under the threshold. A per-item
bound on an unbounded-length collection is an aggregate bypass (see composed-chain §3).

---

## 2. The second kill-question: is the guard CONFIGURED but simply not read?

A triager will say "surely the protocol has an EMA/spot tolerance — you are claiming they forgot."
Distinguish **missing** from **present-but-unused**. They are different findings.

`MainMarket`'s `ema_spot_tolerance` table has **18 entries — one per asset** (USDC, USDT, USDSUI,
USDB, USDY, FDUSD, HASUI, STSUI, CERT, AFSUI, SPRING_SUI, LBTC, BTC, XBTC, SUI, ETH, COIN, SVBTC),
table id `0xd10a423aebcdd6ce58194f7c7107e822caac791c0ff965b1be5fc49fdb65f757`.

So the mechanism is **configured for every asset**. The defect is not that tolerances are absent
— it is that `validate_liquidation` (tier 0) and `liquidate_calculate_seize_ctokens` (tier 1)
**never read the table**, while the borrow/withdraw risk gate (tier 3) does.

**Report it that way.** "The protocol forgot to configure a tolerance" invites "file a config
ticket". "The protocol configured a per-asset tolerance and the liquidation path does not read
it" is a code defect with a one-line fix, and it is much harder to wave away.

**Note the honest limit:** the per-asset numeric values are not exposed by the public indexer
(dynamic-field values for this table are not indexed), so the *width* of the divergence window
could not be measured. State that as UNTESTED with the blocker named — do not infer a number.

---

## 3. Dispatch an adversary whose job is to kill your own finding

The strongest validation move in a multi-round loop. When the headline chain is assembled, dispatch
a subagent with an explicit **disprove** brief, not a confirm brief. Give it the chain and the six
questions, and tell it: *"If it survives your attack, it is real. If it does not, say so plainly.
Zero ego."*

The six questions, in the order they kill:

| # | Question | Why it kills |
|---|---|---|
| 1 | Is the EMA manipulable, and what is its window? | If the EMA cannot be moved inside one tx, the unchecked-EMA defect is theoretical |
| 2 | **What unit is the threshold in?** | Dust-only → finding collapses (§1) |
| 3 | Is the multi-asset attack atomic or interruptible? | If N separate txs are each re-gated by a health check, the aggregate bypass may not compose |
| 4 | What are the live per-asset tolerances? | Tight tolerances bound the divergence window |
| 5 | How many whitelisted callers hold the permission? | If only 2 and both are the protocol's own, "attacker" becomes "operator" — severity changes class |
| 6 | Is there a post-seizure guard the findings miss? | A health re-check or max-seize cap after the seizure would block the chain |

**Answer 2 and 5 yourself before dispatching** — they are the two that most often collapse a chain,
and both are answerable in a few calls. Then let the adversary work 1, 3, 4, and 6.

**Question 5 is a severity reclassification, not a refutation.** If only two whitelisted
liquidators exist and both are the protocol's own operators, the chain is still real — but it is
**operator risk**, not third-party theft. Say so explicitly. A triager who discovers that after
you claimed "fund theft" discounts everything else in the report.

---

## 4. Refuting an audit finding by INVERTED direction (M-16 worked case)

A public audit claimed "circuit break blocks repay" — i.e. a user could be trapped accruing
interest. The deployed bytecode says the opposite, and the proof is a count:

```
grep -c 'has_circuit_break_triggered' market.txt   ->  1
```

**One** occurrence in a 115,846-char module — and it is the function's own definition at line 274.
The gate is enforced from *other* modules:

| Module | Line | Operation gated |
|---|---|---|
| `enter_market.txt` | 83 | entering a market |
| `flash_loan.txt` | 159 | flash loans |
| `liquidate.txt` | 61 | **liquidations** |
| `liquidity_mining.txt` | 38 | reward claims |

`trigger_circuit_break` / `discharge_circuit_break` both require `&AdminCap`
(`market_admin.txt:166`, `:202`).

And the two operations the audit said were blocked are **not gated at all**:

- `handle_repay` (market.txt:1049) — no circuit-break check in the function body
- `handle_withdraw` (market.txt:603) — no circuit-break check, **but** it still calls
  `is_obligation_safe` (market.txt:732), so an unhealthy position cannot be drained

**Method:** when an audit claims "X is blocked", grep the guard function's name across the module
and count. One hit (the definition) means the gate lives elsewhere — then grep the whole corpus
for callers and map each to its operation. The map is the refutation.

**The residual observation, stated at true severity:** circuit break pauses *new* risk-taking
(enter, flash-loan, liquidate, claim) while leaving repayment and collateral withdrawal open. That
is the correct design. Report the inversion plainly — "the audit had the direction backwards" — and
do not inflate the correct behaviour into a finding.

---

## 5. Scorecard arithmetic — the failure mode that keeps recurring

Every round of a multi-round loop produces a headline number, and every round is an opportunity to
publish a number that contradicts your own table. This session got it wrong three times in a row:

- wrote "12 LIVE" above a table listing 18 LIVE rows
- wrote "14 LIVE" then listed 18
- wrote "18 verdicts resolved, 18 LIVE" while also listing 4 REFUTED (18 + 4 ≠ 18)

**The rule, and it is mechanical:** count the rows in your own table, then write the headline from
the count. State the buckets explicitly:

```
LIVE    — <list>
REFUTED — <list>
UNTESTED — <list>
```

If the buckets do not sum to the total, the headline is wrong. Fix it before publishing, and say
"correction" when you fix a previously-published number — never silently edit it.

**Also publish the upgrade-fixed-nothing claim only when you have the md5.** "v1 ≡ v2 by md5 for
every module cited" is what makes "unfixed = still live" a valid headline. Without it, that claim
is an assumption.

---

## 6. The five-line report block for a defended chain

```
VULNERABILITY: Composed liquidation chain — unchecked gate price + close-factor bypass
               + per-asset bound + raw-spot seizure
ENTRY:        Whitelisted liquidator (PackageCallerCap, permission bit 2).
              N holders = <measured>; if all are protocol operators, severity is
              OPERATOR RISK, not third-party theft — stated explicitly.
CHAIN:        M-14 (market.txt:2511, unchecked EMA on the may-liquidate gate)
              -> M-12 (market.txt:112-118, early Ret skips close_factor below bypass_min)
              -> M-08 (market.txt:121-132, close_factor enforced per debt asset)
              -> H-02 (market.txt:2586-2596, seizure priced off raw get_spot_price)
UNIT PROOF:   bypass_min is whole USD, not base units — value::coin_value does
              price*amount/10^decimals then ceil (value.txt:16-30, market.txt:109-110).
              $5 threshold = $5.00. Per-asset check (M-08) puts every leg of a
              multi-asset obligation under it.
CONFIG:       tolerance IS configured per asset (18 entries) — the defect is that
              validate_liquidation and the seize function do not read it.
IMPACT:       Full position closure at an attacker-favourable price.
POC:          structural — every link is a bytecode citation; no tx broadcast
EVIDENCE:     market.txt:2505-2596 + value.txt:16-30 + live MarketConfiguration per market
CONFIDENCE:   PROVEN (bytecode) / config values read live
ADVERSARY:    dispatched to disprove; kill-questions 2 and 5 answered above before dispatch
MITIGATION:   route validate_liquidation through get_price_with_check; apply close_factor
              per obligation, not per debt asset; remove the early-return bypass
VERIFICATION: v1≡v2 by md5, so the finding holds for the deployed upgrade
```

---

## 7. Kill-question 6 answered with bytecode — the guards the four findings DO miss

There are four guards around the seizure. None refutes the chain, but **one of them materially
constrains it**, and the report must say so before an adversary does.

| Guard | Where | What it does | Stops the chain? |
|---|---|---|---|
| Permission + circuit break | `liquidate.txt:48-70` `pre_liquidation_check`, called at `:268` | `app::ensure_has_permission(&ProtocolApp, ID, whitelist_admin::liquidation())` then `market::has_circuit_break_triggered` → abort `market_under_circuit_break` | No — narrows the attacker set (see Q5) |
| **Health gate with 1% buffer** | `market.txt:2387-2497` `ensure_liquidate_borrow_allowed`, called from `liquidation_inner` at `:1856` | `debts_value_usd_for_liquidation` (:2405) + `collaterals_usd_for_liquidation` (:2415); `liquidation_ltv_threshold_override` branch (:2419-2433) else raw `debts > collaterals` (:2452-2454) → abort `liquidation_obligation_still_safe`; then :2474-2483 `LdU64(101)/LdU64(100) → from_quotient → mul(debts) → le(collaterals, debts*1.01)` → abort | **Partially — this is the real constraint** |
| Seizure cap at borrower balance | `market.txt:1913-1938` (B7) | `obligation::ctoken_amount_by_coin` (:1911) vs computed seize (:1906); `Lt` (:1915) → `BrFalse(139)`; if the borrower holds less, seize is capped to their balance (:118-138) | No — caps over-seizure, not price |
| Post-seizure accounting | `liquidate.txt:73` `post_liquidation`, called at `:303` | re-borrows the obligation, recomputes debt / `borrow_index`, `liquidity_miner::get_borrow_reward_type`, reward accrual | No health re-check in the first 160 instructions |

**The nuance that matters — and it is the strongest thing an adversary can find.** The health gate
at :2405/:2415 prices the obligation through `debts_value_usd_for_liquidation` /
`collaterals_usd_for_liquidation`, which are **tier 2** (`get_spot_price_with_check`, see
composed-chain §1). The close-factor gate at :2511 is **tier 0** (unchecked `get_price`).

So the obligation must be genuinely underwater by >1% *as measured by the checked accessor*, while
the tier-0 gate is fed a divergent EMA. That is not free: the attacker needs a real ~1%
underwater position **and** a divergent EMA at the same instant. It bounds the chain to positions
that are already marginal — it does not refute it, but *"full position closure at an
attacker-favourable price"* must be qualified to *"closure of an already-marginal position"*.

**Report the qualification yourself.** An adversary that surfaces a real constraint you already
published is worth far more than one that finds nothing.

**Also refute the lazy version of this question:** staleness is *not* missing.
`x_oracle::get_usd_price` (`oracle_x_oracle.txt:293-414`) calls
`price_feed::ensure_timestamp_not_stale` on **both** the ema and the spot component — at :372 and
:379 (SUI-base path) and :406 and :411 (final path). Any claim that "the oracle has no staleness
gate" dies on those four calls.

---

## 8. Kill-question 1 answered — the EMA is not computed on-chain, it is PUSHED

This is the answer that moves M-14 from "theoretical" to "reachable", and it was missing from the
original chain write-up.

`oracle_price_feed.txt:12-16`:

```
struct PriceFeed has copy, drop, store {
    spot: PriceFeedComponent,
    ema: Option<PriceFeedComponent>,
    twap: Option<PriceFeedComponent>
}
```

The EMA is a **stored** `PriceFeedComponent { value: u64, update_time: u64 }`, not a function of
price history. It is written by `price_feed::set` (`oracle_price_feed.txt:36-48`), reachable only
from `x_oracle::update_price_feed` (`oracle_x_oracle.txt:933-967`, `public(friend)`).

The write path's entry surface, `oracle_update.txt`:

```
 42: public start_update<Ty0>(): OracleUpdateHotPotato<Ty0>
 49: public(friend) insert_price_feed<Ty0>(Arg0: OracleUpdateHotPotato<Ty0>, Arg1: u8, Arg2: PriceFeed): OracleUpdateHotPotato<Ty0>
 60: public complete_update<Ty0>(Arg0: OracleUpdateHotPotato<Ty0>, Arg1: &mut XOracle)
227: 45: Call x_oracle::update_price_feed(&mut XOracle, BaseToken, TypeName, PriceFeedComponent, PriceFeedComponent)
```

`start_update` and `complete_update` are **`public` and carry no `&AdminCap`** — the hot-potato
pattern is the only thing between any caller and a price write. So *"is the EMA manipulable"*
reduces to: **what does `insert_price_feed` validate?**

**That body was not read in the worked session** (`oracle_update.txt:49-59`, ~10 instructions).
It is the single highest-value next read for this chain. Until it is read, report the EMA as
*"the write surface is permissionless at the signature level; the validation inside
`insert_price_feed` is the remaining unknown"* — which is already a far sharper question than
"is the EMA manipulable", and it is honest.

**Generalisable rule:** when a finding says "unchecked EMA", first ask whether the EMA is
*computed* or *stored*. A stored EMA turns the question into "who can write it", and that answer
lives in the **writer's** access-control signature — not in the reader you started from. Grep the
accessor, then grep the setter.

---

## 9. Reading the live numbers behind these answers

`sui-graphql-config-and-table-reads.md` — the working `MarketConfigurationKey` query, the
`Decimal` wire format (`{"value":"200000000000000000"}` = 0.20, 18-dp), the three dynamic fields a
Market actually exposes, and the full list of GraphQL shapes that return `null` for
`sui::table::Table` values. Read it before promising a live per-asset number: `ema_spot_tolerance`
values are **not** indexer-retrievable, and that blocker is named rather than guessed.
