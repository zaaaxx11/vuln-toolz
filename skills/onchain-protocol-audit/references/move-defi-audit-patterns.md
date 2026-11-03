# Move/Sui DeFi audit — the patterns that actually produced findings

Condensed from a multi-round live audit of a Sui Move lending/leverage protocol. Every claim here
was verified against deployed bytecode or live on-chain data. Read this alongside SKILL.md; this
file holds the *technique*, SKILL.md holds the *protocol*.

> **Note:** SKILL.md is at its 100k size ceiling and can no longer accept new technique entries.
> All new Move/Sui audit technique goes HERE, in this reference file. Add a `##` section and, if
> the pattern is likely to be searched for, mention it in the file's own section list below.

**Section list:** §1 audit-findings re-verification · §2 oracle-accessor divergence + the
four-tier map + liveness inversion + **the freeze's mitigation path** + **the self-healing trap** ·
§3 off-chain surface · §4 adversarial self-validation · §5 later-round patterns ·
§6 whitelist/capability hygiene — orphan-row→dead-bit chain, single-holder SPOF, the "second
capability store" question · §7 attribution discipline — matching all declarations, and the
pair-scoped-pricing refutation.

**Sibling technique file:** `references/evm-foundry-and-offchain-api-audit.md` — EVM/Solidity
side. Covers the Foundry monorepo build root trap (`forge test` must run from the repo root,
not the package dir), recovering artifacts from interrupted subagents, what a re-dispatch brief
must carry, auditing a dApp's Next.js API routes (set-difference method for routes holding a
server private key, rate-limit identity from client-settable headers, EIP-712 claim/authorize
flow checklist), and — for multi-contract trust-graph briefs — §11: nested-struct imports, OZ
tag pinning, the non-enumerable role census, SDK-encoded `bytes` mapping keys, the five
trust-graph questions that produce findings, and the **COMPILE ≠ PROVE** rule (a harness that
keeper/oracle surface. Read it when the target is EVM or has a web2
keeper/oracle surface.

**Second sibling technique file:** `references/trust-graph-role-reachability-and-latent-findings.md`
— for EVM trust-graph briefs, the three things that decide severity: decoding a real tx to find a
privileged contract the manifest omitted (§1), ADMIN-EOA→pluggable-module→drain composition (§2),
and **checked arithmetic accidentally guarding a missing authz check** — `panic 0x11` must be
separated from a real guard with an `amount = 0` control, verdict LATENT critical not refuted (§3).
Plus mapping-key mismatch between eligibility and cap (§4), LIVE/LATENT/UNDEPLOYED labelling (§5),
and the bounded-20-line summary contract (§6).

---

## 1. THE AUDIT-FINDINGS RE-VERIFICATION LOOP

When a public audit repo exists (Sherlock/Code4rena/Cantina — e.g. `0xca1x/sherlock-audit-*`),
**do not trust a single one of its findings and do not dismiss them either.** Re-verify every one
against the *deployed* bytecode. Three distinct outcomes, all valuable:

1. **CONFIRMED LIVE** — still in the deployed module. If the package was upgraded since the audit
   and the module is byte-identical, the team *shipped the upgrade without fixing it*. Much
   stronger report than the original finding.
2. **REFUTED** — the audit was wrong. Two shapes:
   - **Wrong module name.** The audit cites `reward_manager`; the deployed package has no such
     module (GraphQL `module(name:)` → `null`). The functionality lives in a differently named
     module (`liquidity_mining_reward_manager`) and the defect IS present there. *Absence of the
     named module is not absence of the bug — find the real module before refuting.*
   - **Inverted direction.** The audit claims "circuit break blocks repay". Deployed code gates
     only `enter_market` / `flash_loan` / `liquidate` / `liquidity_mining`; `handle_repay` and
     `handle_withdraw` are ungated. The design is correct; the audit had it backwards.
3. **REFINED** — directionally right, numerically wrong. "decimals > 18 aborts" — the real cliff
   is `decimals >= 20` because `u64::pow(10, 20)` overflows while `10^19` fits. Trace the actual
   consumer to find the true boundary.

**Audit PoCs are harness-only.** Most contest PoCs reproduce a *model* of the bug in a standalone
package, not the deployed code. They prove nothing about mainnet. Every verdict must come from
deployed bytecode `file:line`.

### Producer-vs-consumer clamp rule (this produced a wrong report)

Finding an unclamped value at a *consumer* site is not a finding. A subagent reported "ADL
`close_factor` is unclamped, allows >100% forced closure" after reading only `market.txt` where
the value is packed into a struct. The clamp was in `adl_admin::new_adl_params`
(`0 < Arg8 <= 10000` → `from_quotient(Arg8, 10000)` → max 1.0).

**Always pull the admin module that constructs the struct before claiming a missing bound.**

The inverse also holds and is the more useful direction: a value that IS clamped may have
*sibling parameters in the same function that are not*. In that same function only 2 of 6 params
were range-checked — `liquidation_incentive_base` and `liquidation_incentive_daily_penalty` went
straight to `from_quotient` with no validation. That was the real (narrower) finding.

### Unit-tracing rule for threshold constants

A config constant like `close_factor_bypass_min_value = 5` is meaningless until you trace the
value it is compared against. Walk the arithmetic end-to-end in bytecode:

```
debt::unsafe_debt_amount(&Debt): Decimal
user_oracle::get_price(...): Decimal
coin_decimals_registry::decimals(...): u8
value::coin_value(Decimal, Decimal, u8): Decimal   <- = price * amount / 10^decimals
float::ceil(Decimal): u64
Le  vs  LiquidationParams.close_factor_bypass_min_value: u64
```

That resolved "5" as **$5.00 whole USD**, not 0.000005 USDC base units — the difference between
"dust-only, ignore" and "reachable, report". **Never report a threshold finding without the unit
trace.**

---

## 2. ORACLE-ACCESSOR DIVERGENCE — the four-tier map

The highest-value pattern in a Move lending protocol: **the same protocol pricing the same asset
through accessors of different strength.** Map every accessor and which function uses it. A real
target had FOUR tiers, not the two or three you would guess:

| Tier | Accessor | Strength | Used by |
|---|---|---|---|
| 0 | `get_price` | EMA only, **no divergence check** | the may-liquidate gate |
| 1 | `get_spot_price` | raw spot, no check | the **seize amount** calculation |
| 2 | `get_spot_price_with_check` | spot + tolerance | eligibility value |
| 3 | `get_price_with_check` + `ensure_secondary_checks_passed` | strongest | borrow/withdraw risk gate |

The exploitable shape: **tier 0/1 on the money-moving path, tier 3 on the depositor-protection
path.** A single liquidation transaction can pass through three different regimes. Grep the whole
package for each accessor name and count call sites per function — the asymmetry is visible
immediately and *is* the finding.

### The "unchecked read only decides a branch" refutation (kills most tier-0 findings)

Before reporting a tier-0 accessor as exploitable, ask **what the returned value is used FOR.** If
the unchecked read only selects a code path (a boolean branch) and the actual money movement is
sized by a checked accessor, the finding is much weaker than the tier map suggests.

current.finance (2026-10-28): the only unchecked `get_price` (EMA) read in the liquidation path,
market.txt:2511, feeds solely the `Le` comparison against
`close_factor_bypass_min_value` at :2521 — i.e. it decides *whether the close-factor bypass
applies*. The repay amount and the seized amount are both computed downstream from
`get_spot_price` / `get_spot_price_with_check`. Report it as "the unchecked read gates a branch,
it does not size the transfer", and cite both the branch site and the sizing site.

### Is the "EMA" actually an EMA? (the overwrite-vs-smooth test)

Do not assume a field named `ema` is a computed moving average. In Move, check whether the writer
**smooths** (`ema = ema*(1-a) + new*a`) or **overwrites** (`WriteRef` of the incoming component).
current.finance `price_feed::set` (oracle_price_feed.txt:36-48) does
`MutBorrowField[0](PriceFeed.ema)` + `WriteRef` — a wholesale assignment. `PriceFeedComponent` is
`{value: u64, update_time: u64}` with **no window, accumulator, or smoothing constant anywhere in
the struct.**

Consequence: the "EMA" is whatever the upstream publisher pushed (there, Pyth's own off-chain EMA
via `pyth_adaptor::refresh_pyth_price`). **An attacker cannot move it by trading on the same
chain** — it only changes when a new oracle update transaction is submitted. That removes
same-transaction manipulation as a primitive and usually downgrades the finding to "wait for a
genuine price move to propagate", which is not an attack. Always state whose window it is and
whether it is visible in the audited package's bytecode at all.

Pair this with the staleness check: `get_usd_price` calls `ensure_timestamp_not_stale` on *both*
spot and ema (oracle_x_oracle.txt:372, 379, 406, 411) against a per-asset
`price_delay_tolerance_ms`, so a stale EMA aborts rather than silently serving an old price.

### Liveness inversion (do not miss this)

The same `ensure_secondary_checks_passed` that stops a manipulated price also **freezes the
market** when a feed goes stale. Pull the app's public oracle check API and look for `passed=0`
rows. A real target had **7 of 20 feeds failing** — five stale at 5.1× their `maxTimeGapMs`
(71 days vs a 14-day cap), one with a 20.79% divergence.

Consequence: a market whose primary asset's feed is stale cannot borrow, withdraw, **or be
liquidated** (the liquidator's own eligibility check aborts first), so its obligations are
silently frozen while the protocol still counts the TVL. **Often more urgent than any
price-manipulation finding, and invisible if you only read code.**

Always cross-check the live feed table against the per-market asset lists, and check *hidden*
markets separately — they are the ones nobody is watching.

### The one-way-exit asymmetry — the part that makes a freeze a trap

"Frozen" is not one condition. Before reporting a liveness failure, **map which operations the
failing feed actually gates, per operation.** The gate is reached through a call graph, and the
asymmetry between operations is the finding:

```
handle_borrow   (call at :1010) ─┐
                                  ├─► is_obligation_safe (:2988)
handle_withdraw (call at :732)  ─┘        ├─► debts_value_usd_non_liquidation (:2878)
                                          │        └─► ensure_secondary_checks_passed (:2940)
                                          └─► collaterals_usd_non_liquidation (:3014)
                                                   └─► ensure_secondary_checks_passed (:3086)

handle_repay (:1049-1168)   -> ZERO oracle calls in the entire function body
handle_mint  (:468-601)    -> takes NO &XOracle parameter at all
handle_liquidation          -> gated via the may-liquidate gate's own oracle read
```

Resulting per-operation table for a failing asset:

| Operation | Gated? | Consequence |
|---|---|---|
| deposit / mint | **NO** (no `&XOracle` in signature) | can still add collateral |
| repay | **NO** (zero oracle calls in body) | can still pay down debt |
| borrow | **YES** (via `is_obligation_safe`) | cannot borrow |
| withdraw | **YES** (via `is_obligation_safe`) | **cannot withdraw collateral** |
| liquidate | **YES** on the may-liquidate gate, but **NOT** on the secondary check (see below) | see the mitigation-path section |

**A user can repay and deposit but cannot withdraw, and their position cannot be liquidated — the
exit door is one-way.** That is materially worse than a symmetric freeze, and it is the sentence
that belongs in the report. Verify the ungated operation by scanning its *whole body* for any
oracle call, not by assuming symmetry with its siblings. The fastest tell is the **signature**:
an entry point that takes no `&XOracle` cannot be oracle-gated at all.

The full mitigation-path investigation (who can unfreeze, the `checkSource` cross-reference,
and the liquidation asymmetry) is the next section — read them together.

### Quantify the blast radius before ranking the finding

Map every failing asset to its market and count obligations per market. In current.finance the
first pass reported "EthenaMarket's 20 obligations frozen" — which turned out to be **0.04% of
the exposure**. The real numbers:

| Market | Assets | Obligations | Failing assets |
|---|---|---|---|
| MainMarket | 18 | **54,287** | AFSUI, CERT, STSUI, USDSUI |
| EmberMarket | 5 | 874 | ESUI |
| Market01 | 2 | 208 | SUSN |
| EthenaMarket | 3 | 20 | SUI_USDE |
| **TOTAL** | | **55,715** | **55,389 (99.4%) affected** |

**Never rank a liveness finding off the market you happened to look at first.** Pull
`obligations.size` and `assets.table.keys` for *every* market object, then intersect with the
failing-feed list. Note the JSON path quirk that cost a round here: obligations live at
`obligations.size`, **not** `obligations.table.size` (assets/reserves/tolerance use `table.size`).
Check the top-level key list before assuming a uniform shape.

### Verify the call graph, not just the call-site count

A `grep -c` on a gate function tells you how many times it is called; it does **not** tell you
which operations those calls affect. In this session the first pass claimed the secondary check
gates "every guarded path — borrow/withdraw risk gate" on the strength of two call sites, and
both were inside `*_non_liquidation` valuation helpers reached only through
`is_obligation_safe`. The claim was directionally right for borrow/withdraw but the *reasoning*
was wrong, and it would have been wrong in the opposite direction for `repay`.

**Method:** for each call site, walk up to the enclosing function, then walk up again to that
function's callers, until you reach a user-facing entry point. Only then say "operation X is
gated". Record the chain in the report as a code block — it is the evidence, and it is what let
the asymmetry be spotted at all.

### Hidden-market discovery

Diff the DefiLlama adapter's market-object list against the app bundle's `LEND_HIDDEN_MARKETS`
array. Markets hidden from the UI are still live on-chain and still counted in TVL. Enumerate each
one's obligations and asset feeds independently — they can be in opposite states (one frozen, one
healthy).

### The freeze's mitigation path — who can unfreeze, and can a user exit at all

Discovering `passed=0` feeds (liveness inversion above) is only half the job. The report an
operator needs answers four questions, and each has a different evidence source:

**(1) Who can refresh a failing feed?** Trace the writer of the *pass flag*, not of the price.
In current.finance the flag lives in a dynamic field (`FeedCheckersPassKey` →
`XOracleAssetRegistry<bool>`, oracle_x_oracle.txt:627-635) and is written ONLY by
`x_oracle::update_feed_check_passed` (:637-665), whose sole caller is
`update::complete_update` (oracle_update.txt:122). `complete_update` is **`public`** (:60) —
but it consumes an `OracleUpdateHotPotato` hot potato that only the three `public` refresh
modules can fill (`refresh_pyth_price_feed` oracle_pyth_update.txt:49,
`refresh_stork_price_feed` oracle_stork_oracle.txt:70,
`refresh_admin_ref_price_feed` oracle_admin_ref_feed.txt:81), because
`insert_price_feed` is `public(friend)` (oracle_update.txt:49). So the *primary* price is
permissionless to refresh; the *check* price is not.

**(2) Which source is the check, and is it admin-gated?** `check_secondary`
(oracle_update.txt:243-322) reads `asset::check_source(&AssetConfig)` and looks that key up in
the potato's `VecMap<u8, PriceFeed>`. Absent → emits `NoSecondaryCheck` and returns **false**
(`LdFalse` at :259, `BrFalse(53)` at :264). Cross-reference the app's public check API: every
failing feed carried `checkSource: 255` — the admin-reference source — whose only writer is
`admin_ref_feed::admin_set_ref_price` (:25) behind **`&AdminCap`**. That single cross-reference
is the whole answer: **the freeze is not self-healing; it needs the oracle `AdminCap` holder to
push a fresh reference price.** `refresh_admin_ref_price_feed` (:81-137) divides
`reference::updated_at` by 1000 to get seconds, so an admin-set ref does satisfy the staleness
leg. `checkStatus` decodes as 0=pass, 1=timeGap, 2/3=deviation; `lowerBoundBps`/`upperBoundBps`
are per-asset (500/500 typical, 9999 for WAL — which is why WAL's 4520 bps deviation still
passes).

**(3) Can a user exit a position in a failing asset?** Grep the gate across the package and
count call sites *per entry point* — the asymmetry map IS the answer. Re-derive it; do not
inherit the previous round's claim.

| Operation | Entry point | Takes `&XOracle`? | Secondary-check gated? |
|---|---|---|---|
| deposit / mint | `market::handle_mint` (market.txt:468) | **no** | **never aborts** |
| repay | `market::handle_repay` (:1049) | **no** | **never aborts** |
| withdraw | `market::handle_withdraw` (:603) | yes | aborts if **any** debt or collateral type fails |
| borrow | `market::handle_borrow` (:789) | yes | same |
| liquidate | `market::handle_liquidation` (:1221) | yes | **not** on the secondary check |

The signature is the fastest tell: an entry point that takes no `&XOracle` cannot be
oracle-gated at all. For the gated ones, follow into `is_obligation_safe` (:2988) →
`debts_value_usd_non_liquidation` (:2940) and `collaterals_usd_non_liquidation` (:3086): each
loops **every** debt type and **every** collateral type and calls
`ensure_secondary_checks_passed` on each. One failing asset anywhere in an obligation freezes
withdraw and borrow for that whole obligation — including assets that are perfectly healthy.

**Liquidation is the asymmetry worth reporting.** The `_for_liquidation` twins
(`debts_value_usd_for_liquidation` :2763, `collaterals_usd_for_liquidation` :2643) call
`user_oracle::get_spot_price_with_check` — the EMA/spot tolerance — but **never**
`ensure_secondary_checks_passed`. A package-wide grep for the gate returns exactly two call
sites, both inside the `_non_liquidation` helpers. Consequence: **a failing feed blocks the
borrower's exit but not the liquidator's entry** — the opposite of the depositor-protection
intent, and invisible unless you count call sites per helper instead of assuming twins share
a gate. (Note `get_price_with_check` / `get_spot_price_with_check` in oracle_user_oracle.txt
do NOT call the secondary check themselves — they only enforce EMA-vs-spot tolerance. The
secondary check is always a separate explicit call site.)

**(4) Is the pass flag itself attackable?** The hot-potato shape creates a hypothesis worth
testing: `start_update` is `public` and `complete_update` is `public`, and
`extract_primary_feed` aborts (`primary_source_missing`, :149-157) only when the *primary* key
is missing — not the check key. So a caller supplying a fresh primary feed while omitting the
check source drives `check_secondary` to `false` and writes `passed=0`. **Verify before
reporting**: confirm the check-source key is genuinely absent from a primary-only refresh (and
that no other module re-populates it), and check whether `update_primary`'s
`price_time_regressed` guard (:214-220) constrains who may submit. If it holds, this is a
**permissionless feed-freeze primitive** — any user can flip a healthy feed to failing without
the AdminCap, which inverts the entire mitigation story. Mark it UNTESTED until the VecMap keys
are confirmed on-chain.

### The self-healing trap — do NOT conclude "automatic recovery" from a public entry point

A later round of the same session **regressed on this exact point** and the correction is worth
recording because the wrong version is the more attractive sentence.

`complete_update` (`oracle_update.txt:60`) is `public` and takes no `&AdminCap`, and
`check_secondary` + `update_feed_check_passed` both run inside it. It is tempting to conclude
"the freeze is self-healing, the update bot will fix it". **That conclusion is only valid if the
hot potato can actually be filled by that bot** — and `insert_price_feed`
(`oracle_update.txt:49`) is `public(friend)`, so only friend modules can populate it. The three
refresh modules that can are `refresh_pyth_price_feed`, `refresh_stork_price_feed`, and
`refresh_admin_ref_price_feed`; and for the failing feeds the check source was `255` — the
admin-reference source — whose only writer is `admin_set_ref_price` behind `&AdminCap`.

**Rule: trace the whole hot-potato fill path before calling a public entry point a recovery
mechanism.** A `public` consumer of a `public(friend)`-produced value is not permissionless.
State the mitigation as "needs the oracle AdminCap holder to push a fresh reference price", and
reserve "self-healing" for the case where you have confirmed the filling module is itself
permissionless *for that asset's check source*.

This is the same producer-vs-consumer discipline as the clamp rule in §1, applied to
*permissions* instead of bounds.

### Indexer gaps on capability holders — the control-query discipline

When the brief asks "who holds `app::AdminCap`" and `objects(filter:{type})` returns zero for a
cap you have already resolved elsewhere, run a **control query** for a cap type in the same
package family that you *have* resolved (`flp::AdminCap` returned a holder). Control succeeds +
target returns 0 ⇒ **indexer-blocked, not absent**. Report the holder as UNKNOWN and name the
resolution path (authenticated explorer API, local indexer, or walking the creation tx). Also
note that a protocol typically has **several distinct AdminCaps** (market, oracle, FLP,
leverage) — resolving one holder tells you nothing about the others, and for a feed freeze the
*oracle* cap is the only one that matters.

### Per-asset vs per-obligation enforcement

When a risk parameter (close factor, cap, limit) is enforced inside a function generic over one
asset pair, it is enforced **per asset**, not per position. A multi-asset obligation can be closed
far more aggressively than the configured factor intends. Check whether the caller loops internally
or must issue N transactions, and whether state changes between legs re-price and block later
ones.

### Attributing a bytecode line to its function — match ALL declarations, not just `public`

This cost a whole wrong severity rating and is the single cheapest mistake to avoid. A disassembly
file contains **`public`, `public(friend)`, `entry`, AND bare private helper declarations**
(`helper<Ty0>(Arg0: …, …) {`). A regex that only matches `^(public|public\(friend\)|entry)\s`
silently drops every private helper, so every line after the last public function gets attributed
to that function — no matter how far away it is.

Symptom to recognise: six "unbounded scan" lines spread across ~800 lines of file all resolve to
one function (`repay_flash_loan`), which is absurd on its face. current.finance: market.txt is
3,142 lines with **36** `public`-family declarations but **50** declarations total. Matching all
50 resolved the six sites to **six different helpers**:

| Line | Enclosing helper (private) |
|---|---|
| 2223 | `refresh_obligation_assets_interest` |
| 2331 | `refresh_obligation_borrow_interest` |
| 2664 | `collaterals_usd_for_liquidation` |
| 2783 | `debts_value_usd_for_liquidation` |
| 2895 | `debts_value_usd_non_liquidation` |
| 3035 | `collaterals_usd_non_liquidation` |

The working matcher: `re.match(r'^[a-z_]+<[^>]*>\(', s) or re.match(r'^(public|public\(friend\)|entry)\s', s)`
— then walk declarations to find the nearest preceding one for any target line.

**Why it mattered:** the mis-attribution supported a HIGH-severity "attacker bricks the protocol"
gas-DoS claim. Correct attribution showed all six scans read `&Obligation<Ty0>` — **the caller's
own obligation** — with no market-wide loop anywhere in the package. The finding is a
**self-inflicted** gas DoS and drops to LOW-MEDIUM. Same lines, opposite severity.

**Rule: before ranking any "unbounded loop / gas exhaustion" finding, attribute every scan site
to its true enclosing function and check whose obligation it reads.** If it reads only the
caller's, the attacker pays for their own DoS and can still be liquidated by a caller supplying
more gas.

### The "one failing asset freezes everything" hypothesis — test it against the pricing path

The natural composition hypothesis is: a failing oracle feed + unbounded obligation = an
obligation that can never be liquidated. **Refuted by counting oracle calls in the seize path.**
`liquidate_calculate_seize_ctokens` (market.txt:2572+) makes exactly **two** `get_spot_price`
calls (:2590 collateral, :2596 debt) — the pair being liquidated, not every asset in the
obligation. An obligation holding five assets where one feed is failing still liquidates fine on
any healthy pair.

**Method:** grep the seize/liquidation helper for oracle calls and count them. Two calls ⇒
pair-scoped ⇒ the freeze blocks operations *on that asset*, not the whole position. This is the
cheapest possible refutation of an amplifier claim and it takes one grep.

---

## 3. OFF-CHAIN SURFACE — what actually closes

Record these as *closed with evidence* so a future session does not re-probe:

| Surface | Killer evidence |
|---|---|
| Spring Boot actuator | 12+ paths × 2 hosts: heapdump/threaddump/loggers/jolokia/gateway all 404 while `/actuator/health` lives |
| NestJS GraphQL | 404 across 4 paths |
| Next.js `/_next/image` SSRF | `remotePatterns` allowlist returns `"url" parameter is not allowed`; CDN edge blocks metadata IPs with a challenge page — **two independent layers** |
| POST deser/SSTI | sanitized error envelope, zero stack traces across 14 payload shapes |
| SSE parameter injection | every input → generic `System error` |
| Admin-panel auth | session token has **no format oracle** (every invalid input → byte-identical 401); `alg=none` JWT rejected; server actions gated by middleware *before* dispatch; no `Set-Cookie` so no cookie session to hijack |

### CI guard-ordering trap (the real supply-chain finding)

A lockfile-diff guard that runs in a *later step* than `pnpm install` does not prevent code
execution — the `postinstall` from the PR's dependency set has already run by the time the guard
writes its error string. **Read the step order, not just the presence of a guard.**

Diff the fork against its **true upstream** to distinguish "inherited weakness" from "regression
the team introduced" — the latter is far more reportable. A sibling repo that kept the guard and a
fork that deleted it is the proof.

### Hardcoded-credential hunt

Look for obfuscated literals in tracked CI scripts, not just `.env` files. A Caesar-shifted
(`+2`, mod-95) GitHub PAT in a `const junk = '...'` decoded to a valid `ghp_` classic token.
Test liveness **once**, read-only (`GET /user`), and report it as a historical leak if it returns
401 — a dead credential still proves the team committed a real one publicly, and the
"obfuscation" is reversible in one line.

### Indexer inconsistency (record it, do not conclude from it)

Public GraphQL indexers return `0 nodes` for queries that are demonstrably wrong — e.g.
`objects(filter: {type})` returning zero for a capability type whose holder you have already
fetched by address, and `address(addr).objects` returning zero for an address known to hold
objects. When a query contradicts a directly-fetched object, mark the claim
**UNVERIFIED (indexer-limited)** rather than confirming or refuting it.

Schema quirks that cost calls: `AddressOwner.owner` is not consistently selectable, `objects()`
needs `nodes`, and dynamic-field *values* for some tables are not indexed at all (`with_keys`
exposes keys but not values).

**Concrete working vs failing selections** (each failure below burned a real call — copy the
working shape, don't rediscover it):

| Want | Fails | Works |
|---|---|---|
| owner address | `owner { json }`, `owner { ... on AddressOwner { owner { address } } }`, and **`owner { ... on AddressOwner { address } }`** — bare `address` fails because `Address` is an OBJECT type that demands a subfield selection | `owner { __typename ... on AddressOwner { address { address } } }` — **ONE call, no two-step resolution needed** |
| dynamic-field value | `value { json }`, `asMoveValue { json }` | `value { __typename ... on MoveValue { json } }` |
| dynamic-field name type | `name { json }` (returns only `{"dummy_field":false}`) | `name { type { repr } }` |
| a whole `VecMap` | — | the `MoveValue` form above returns `{"contents":[{"key":…,"value":…}]}` in ONE response |

So the two-step recipe for any permission/config map is: (1) `dynamicFields{ nodes{ name{ type{
repr } } } }` to find the key type, (2) re-query with `value{ ... on MoveValue { json } }` to get
the entire contents array. Do not paginate per key.

Also: `object(address:)` returns `{"data":null}` (not an error) for an object that has been
deleted — that is how you detect the orphan rows described in §4(e). And when a type-filtered
`objects()` query returns rows, always read `pageInfo.hasNextPage` before concluding the count.

---

## 4. ADVERSARIAL SELF-VALIDATION (mandatory before shipping a chain)

### Report-skeleton contract on multi-question briefs (hard requirement)

When the brief mandates "create the report file FIRST, then APPEND every N tool calls, the report
must ALWAYS exist on disk" — that is a **deliverable contract, not a style preference**. On a
live-audit session the tool budget can be exhausted mid-investigation, and a report that only
exists at the end is a failed task even if the analysis was correct.

1. **Call 1 writes the skeleton** with every mandated section present as a placeholder
   (VULNERABILITY/ENTRY/CHAIN/IMPACT/POC/EVIDENCE/CONFIDENCE/MITIGATION/VERIFICATION +
   claim-vs-proof table + REFUTED + UNTESTED). Never start with investigation.
2. **Append, never rewrite.** After every ~5 tool calls, append a log block with what was
   established and which verdicts moved. Earlier evidence must survive later edits.
3. **Land each answered question in the file the moment it is answered** — do not batch all
   findings into one closing write. In the current.finance R2 run the (e) answer (the decisive
   one) was written to disk immediately and therefore survived; the CHAIN/IMPACT/CONFIDENCE
   sections were left as placeholders because they were deferred to a final pass that never came.
   **Reserve the last ~10 calls for closing the remaining sections**, and if the budget is tight,
   write a short honest "unfinished sections" note rather than leaving bare placeholders.
4. When the session does truncate, say so plainly in the final message and name exactly which
   sections are placeholders — do not present a partial file as complete.
5. Use the brief's exact section headings. Adding your own structure on top makes the artifact
   fail the user's downstream check.
6. **The append cadence is the first thing to slip, and it slips silently.** R12 repeated the R2
   failure: the skeleton was written on call 1 (correct), but the ~5-call append checkpoints were
   never fired because the investigation was absorbing every call. **Budget the appends as
   first-class calls, not as leftover work** — on a 35-call budget that is ~6 appends, so
   reserve them up front and treat "investigation is going well" as a signal to append *sooner*,
   not later. A cheap discipline that works: after each append, note in the file which sections
   are still placeholders, so a truncated file is self-describing.
7. **When the budget does run out, the final message is the deliverable of last resort.** R12
   ended with the full analysis only in chat. Write the findings into the file *before*
   composing the closing message, even if that means a single dense append rather than polished
   per-section prose. A file with raw-but-complete content beats a polished chat message and a
   skeleton on disk.

Dispatch an agent whose explicit job is to **disprove** the chain, and answer six questions with
bytecode or live data:

- (a) is the manipulable input actually manipulable, and over what window?
- (b) what UNIT is the threshold constant in — traced end-to-end?
- (c) is the multi-step attack atomic or interruptible between steps?
- (d) what are the live configured tolerance values?
- (e) who can actually reach the entry point — an outsider, or only the protocol's own operator?
- (f) is there a post-seizure / post-action guard the findings missed?

**(e) decides severity:** if only two whitelisted liquidators exist and both are the protocol's
own, the "attacker" is the operator and the finding is **operator risk, not theft**. **(f) can
kill the chain outright.**

### Answering (e) for real — read the live permission table, don't infer it from holders

The decisive query is **not** "who holds the capability object" but "what does the live permission
map say". On Sui these are different questions and the second is the one that matters:

1. Find the app root object (here `ProtocolApp`), then enumerate its dynamic fields and read the
   **name type** to locate the whitelist key:
   `object(address:){ asMoveObject{ dynamicFields(first:10){ nodes{ name{ type{ repr } } } } } }`
   → look for a key like `app::PackageWhitestKey`.
2. Read that field's **value** — for a `VecMap<ID,u32>` this returns the whole contents array in
   one response:
   `... dynamicFields{ nodes{ name{ json } value{ __typename ... on MoveValue { json } } } } }`
   → `{"contents":[{"key":"0x…","value":4}, …]}`. Every permission bit for every cap, in one call.
3. Decode the bitfield from the *admin module's* constants, not from guesswork. current.finance
   `whitelist_admin.txt` exposes them as trivial functions: `flash_loan()=0` (:9-13),
   `enter_market_with_emode()=1` (:15-19), `liquidation()=2` (:21-25), `adl()=3` (:27-31). The
   check is `1 << perm` then `BitAnd` (app module `ensure_has_permission`). So value `4` =
   liquidation only, `3` = flash_loan+emode, `5` = flash_loan+adl.
4. **Cross-check against live objects, and expect the two to disagree.** `objects(filter:{type:
   "...::app::PackageCallerCap"})` returned exactly 2 live objects while the VecMap held 4 rows —
   two rows point at objects that no longer exist. Those are orphan rows: `burn_whitelist`
   (whitelist_admin.txt:52) removes the row *and* burns the cap, so a row surviving while the
   object is gone means the cap was deleted by direct object deletion, not via the admin function.
   Harmless in itself, but **do not stop there** — an orphan row means a *permission bit may have
   silently lost its only holder*, which is a liveness finding, not a hygiene note. See §6.

**Then answer the obtainability half explicitly**, citing the gate on every path:
- `mint_new_whitelist(&AdminCap, …)` (:33) — requires `AdminCap`, and mints with permission
  **0** (`LdU32(0)` at :46), so a fresh cap has no rights at all.
- `update_permission(&AdminCap, …, u8, bool)` (:100) — requires `AdminCap`; sets/clears
  `1 << perm` (:125-128); index must be `< 4` (:106) else `invalid_params_error`.
- `burn_whitelist(&mut ProtocolApp, PackageCallerCap)` (:52) — **no AdminCap gate**; anyone
  holding a cap can burn *their own*. Note it cannot escalate.
- `remove_whitelist(&AdminCap, …)` (:86) — requires `AdminCap`.

If every path to the needed bit requires `AdminCap` and the `AdminCap` holder is unresolved
(see the indexer-gap rule in §3), the verdict is: **outsider cannot obtain it → operator risk.**
State the cap count, the bit values, and the gate for each path in the report — "1 liquidator, not
2" is a far stronger sentence than "liquidators are whitelisted".

Also worth noting when the holder set is small: a cap's permissions are keyed by **capability
object ID**, not by package address, so `update_permission` can mutate an arbitrary cap's bits.
Flag that as a separate design observation (permissions are not bound to a package), but do not
conflate it with an outsider-reachable escalation.

**If you cannot answer (b) and (e), you do not have a finding — you have a hypothesis.**

### (d) "live tolerance values" — three different knobs, only one is the one you want

When the brief asks for live `ema_spot_tolerance` (or any per-asset risk parameter), there are
usually **three similarly-named values** and conflating them produces a wrong answer:

1. **The lending-side tolerance** — `Market.ema_spot_tolerance: GenericCoinTypeStorage<Decimal>`
   (market.txt:49), written only by `market_admin::update_market_ema_spot_tolerance`
   (market_admin.txt:286-296) behind `&AdminCap`. This is the one the lending gates consume.
2. **The oracle-side deviation bounds** — `lowerBoundBps` / `upperBoundBps` in the app's public
   oracle check API (current.finance `evidence/check_table.json`: 500/500 for most feeds, 9999 for
   WAL). These bound the `update` module's secondary check. **A different knob.**
3. **The staleness window** — `price_delay_tolerance_ms` (oracle_x_oracle.txt:416-446) and the
   feed table's `maxTimeGapMs`. Also different.

**The lending tolerance is often genuinely unretrievable read-only.** It lives in a nested
dynamic-field table whose per-asset values are not exposed by `contents.json` — you get the table
id and size, not the entries. Do not substitute knob #2 and present it as the answer; report
knob #1 as **UNRETRIEVABLE**, name the writer function and its gate, and state what *is*
retrievable (table exists, N entries, admin-only writer). A wrong number here silently invalidates
every severity estimate built on it.

What you *can* usually prove statically, and should: **which gates actually consume the
tolerance.** Grep `ImmBorrowFieldGeneric[7](Market.ema_spot_tolerance)` and follow each site into
its `is_obligation_safe` / `*_for_liquidation` helper — in current.finance both
`debts_value_usd_for_liquidation` (:2832) and `collaterals_usd_for_liquidation` (:2719) pass it
into `get_spot_price_with_check`. That is the mitigation statement the finding needs, and it is
available even when the numeric value is not.

### Function-name drift between the brief and the deployed module

The brief will cite a function name that does not exist in the disassembly — current.finance's R1
report cited `validate_liquidation` at market.txt:2511, but the code lives inside
`ensure_liquidate_borrow_allowed` (declared at market.txt:2387). **Do not report this as a
refutation.** Same code, corrected name; say so explicitly ("no function by that name in v2; the
cited line is inside X") and continue. The substance of the finding is unaffected. This is the
same discipline as the wrong-module-name case in §1 — locate the real container before judging.

For a Move target the (c) and (f) answers come from the same three reads: the entry-point
signature (does it take a vector or a single coin?), the inner function's linearity (is there a
loop over debt/deposit types?), and the post-action function read all the way to its `Ret`. See
§4's bytecode subsections below for what each of those looks like when it does and does not block
the chain. The generic stage-3 workflow (verdict vocabulary, budget rules, report-skeleton
contract) is in `readonly-security-audit` →
`references/adversarial-validation-and-cross-tier-chains.md`.

### Subagent failure handling

A long adversarial task can hit a provider 504 timeout after exhausting its call budget. When
that happens, **re-dispatch split into two narrower lanes with an explicit call/time budget and a
stated priority order** ("prioritise (f) first — it can kill the whole chain") rather than
treating the task as done or re-sending the same oversized brief.

### Reconstructing a seize/price formula from bytecode (do not paraphrase it — derive it)

When the brief asks for "the exact formula", the answer is an **instruction-by-instruction
accumulator table**, not prose. Method that worked (current.finance liquidation, 2026-10-28):

1. Find the call site and read off which *local* each argument came from — that tells you what
   the generic parameters actually are. Example: `liquidate_calculate_seize_ctokens<Ty1, Ty2>`
   called with `Arg0 = reserve::exchange_rate<Ty0>` where `Ty0` is the **collateral** market
   type, not the debt type. Getting this backwards inverts the whole formula.
2. Read the callee body linearly and build the table: `instr | file:line | operation | accumulator`.
   The `StLoc`/`CopyLoc` chain is what disambiguates which Decimal is which.
3. Watch for the `Decimal + Decimal` pair at the start of a multiply chain — that is the
   `R + R×i = R(1+i)` bonus construction, and it is the single most important line in the
   formula. In current.finance it is market.txt:2611-2615.
4. Record the decimal-scaling (`pow10_u64` per `coin_decimals_registry::decimals`) and the final
   `float::floor` → u64. Skipping the floor makes every predicted number off by up to 1 unit.
5. Publish the formula as a code block plus the equivalent USD reading
   (`seize_value ≈ repay_value × (1+incentive)`), so a reader can sanity-check magnitude without
   re-deriving.

**Bound the incentive at BOTH sites and report the difference.** The same value can be clamped
where it is constructed and unclamped where it is read. current.finance:
`emode_admin::create_emode_params_inner` validates `Arg3 < 10000` then `from_quotient(Arg3,10000)`
(emode_admin.txt:307-316, :345-348) — but `emode::liquidation_incentive` is a bare field read
(emode.txt:654-660) and `update_collateral` writes it raw (emode.txt:354-355). Verdict shape:
"bounded at config time; NOT clamped at use time; holds in practice only because the package is
Immutable and the writers are `public(friend)` behind AdminCap-gated entry points." Note the
contrast with the ADL `close_factor`, which IS clamped at use time — do not conflate siblings.

### Quantity clamp vs value cap — the distinction that decides (f)

When asked "is there a post-seizure guard", separate three different things that all look like
protection:

- **Quantity clamp** — seized units ≤ the obligation's actual balance of that collateral
  (current.finance market.txt:1913-1938, with a proportional repay rescale at :1920-1925). Real,
  and easy to miss because it sits *inside* the seize path rather than after it.
- **Value cap** — seized USD ≤ repaid USD × (1 + max_bonus). Usually **absent**.
- **State assert** — post-mutation health/invariant check. Usually **absent**.

A chain can be fully viable with a quantity clamp present, because the bonus extraction happens
*within* the available collateral. Reporting "no guard exists" when a quantity clamp does is an
overstatement a reviewer will catch; reporting the clamp as if it capped value is the opposite
error. Name all three separately with file:line.

### Inter-leg accessor asymmetry — why "interruptible" is stronger than "not atomic"

The generic answer to "is the multi-step attack atomic?" is "no loop in the signature ⇒ N
transactions". The *useful* answer is what re-runs between legs. In current.finance every leg
re-enters `ensure_liquidate_borrow_allowed`, which re-prices the whole obligation through
`debts_value_usd_for_liquidation` / `collaterals_usd_for_liquidation` — and those use
`get_spot_price_with_check` (market.txt:2832, :2719), **a different and stronger accessor than the
one the finding exploits** (EMA `get_price` at market.txt:2511, raw `get_spot_price` at :2590/:2596).

So the manipulation that feeds the close-factor bypass does **not** propagate into the inter-leg
health gate. That is a materially stronger refutation than "it needs N transactions", and it comes
straight out of the four-tier accessor map in §2. Always cross-check which tier each gate uses
before concluding a multi-leg chain is viable.

Also confirm the helper **return-value order** before using it in a health comparison —
`debts_value_usd_for_liquidation` returns `(weighted, raw)` (market.txt:2873-2874) and
`collaterals_usd_for_liquidation` returns `(weighted, raw)` (market.txt:2758-2759). Reading them
backwards silently inverts the gate.

### The post-action function is usually bookkeeping — prove it, don't assume it

`post_liquidation` (liquidate.txt:73-228) looks like a guard by name and position (called after
`handle_liquidation` returns). It is not: liquidity-miner reward updates (:153-167) + event
emission (:225-227). Read it to the `Ret` before calling it either way, and cite the
`event::emit` + `Ret` pair as the proof. Same discipline as the "read the whole file before
adjudicating" rule in readonly-security-audit.

### Self-correction discipline

Record your own wrong claims in the report with the evidence that corrected them. One session
produced three: a refutation based on a missing module name, a "no guard" claim based on reading
only the first 50 lines of a file, and a provenance claim about which bytecode version was live.
Each was caught by verifying against primary sources rather than accepting a summary.

**Never report a subagent's claim without re-deriving it yourself.** When you correct yourself,
say so plainly in the artifact so the error is not repeated.

---

## 5. FOUR MORE PATTERNS FROM THE SAME TARGET (later rounds)

### Permissionless namespace squatting with single-attempt generation

A referral/invite-code system is a **global** `Table<String, address>` with a short fixed-length
random code and **no retry loop**. current.finance:

```
referral.txt:28    code_owner: Table<String, address>     <- GLOBAL namespace, not per-user
referral.txt:32    LdConst[1](u64: 6)                     <- length hardcoded to 6
referral.txt:20-21 LdU8(36); Mod                          <- base-36 alphabet [0-9a-z]
referral.txt:39    Call table::contains<String, address>(...): bool
referral.txt:41    BrFalse(43)
referral.txt:46    Abort                                  <- SINGLE ATTEMPT, abort, NO retry
```

**6 chars × base-36 = 36^6 = 2,176,782,336 codes**, one draw, hard abort on collision, entry
permissionless (gated only by a deposit threshold), and **no `table::remove` anywhere** so a
squatted code is gone permanently.

Three things to report separately, because they have different severities:
- **Vanity/reference squatting** — an attacker pre-registers predictable or desirable codes and
  farms the rebate. Real, low severity.
- **Probabilistic DoS on honest users** — a user who draws a taken code gets a hard `Abort`, not
  a re-draw, and pays gas per retry. Real, low severity.
- **Full namespace exhaustion** — almost always **REFUTED**. 2.18 billion codes is not
  economically exhaustible; say so explicitly rather than implying it.

Cross-check the live table size against the code space to calibrate: `code_owner` had **121**
entries against 2.18 billion possible — squatting is realistic, exhaustion is not.

### Ended-program stranded custody (the "no exit path" pattern)

A program that has been terminated (`has_ended: true`) but whose module has **no withdraw/claim
function** leaves real funds stranded. Verify all four legs before reporting:

1. **Is the deposit gate correct?** `ensure_not_stop` on `deposit` (flp.txt:2) — if yes, no *new*
   funds enter, which bounds the loss.
2. **Is it real custody or a ledger entry?** Trace the deposit call. current.finance
   `flp.txt:375` `deposit::deposit` moved the coins into the MainMarket as **actual cTokens** —
   real custody, not an accounting number. This is the difference between "stranded ledger
   balance" and "stranded coins".
3. **Does the admin cap have any fund-moving function?** `flp::AdminCap` had none — the cap can
   administer but cannot extract.
4. **Is there a path through another module?** Check whether the lending market or any other
   module can be used to move the position.

If all four hold, the funds are **permanently stranded** and the finding is a straightforward
fund-loss report, not a vulnerability requiring an attacker.

### Cross-package valuation asymmetry (refines §2's four-tier map)

The four-tier accessor map applies **within** a package. The same asymmetry exists **across**
packages, and it is easy to over-claim. current.finance's leverage package:

- `leverage_obligation.txt:306` calls `user_oracle::get_spot_price` — raw spot, no guard — and it
  is the **only** oracle call in all 11 modules (six modules `use x_oracle` and never call it).
- **But** the leverage package *does* invoke the lending package's gated entry points
  (`borrow::borrow`, `deposit::deposit`, `enter_market::enter_market_with_emode`,
  `flash_loan::borrow_flash_loan`), so the lending market's internal risk gate **is** enforced on
  those operations.

**The correct claim is therefore narrow:** the leverage package's *own valuation layer*
(`get_price_usd` → `get_collateral_price` / `get_usd_value`, which drive `request_leverage`,
`complete_leverage`, `withdraw_size`, `withdraw_leverage`, `request_reduce_*`) runs on raw spot,
while the lending operations it invokes run on guarded prices. **Not a full bypass — a
mispricing surface on every leverage entry and exit.**

Grep for `Call <lending_pkg>::` in the dependent package before claiming it bypasses anything;
then state precisely which layer is unguarded.

### Headline-revision discipline (when adversarial review narrows a finding)

Adversarial validation frequently narrows a headline finding. When it does, **revise the headline
and the summary table, not just the body** — a report whose headline still says "four compounding
defects / fund theft" while the body says "three defects / operator risk / bounded blast radius"
is internally inconsistent and a reviewer will trust it less, not more.

The current.finance headline was revised from:

> "M-14 + M-12 + M-08 + H-02 … four compounding defects … full position seizure at an
> attacker-favourable price"

to:

> "a composed on-chain finding that adversarial review narrowed but did not kill … three
> compounding defects … **operator risk, not unauthenticated theft** … a post-seizure guard
> exists that the four findings missed … M-08 is not atomic"

Each revision names the specific bytecode evidence that forced it. The rule: **when you lower a
claim, lower it everywhere it appears, and cite the evidence that lowered it.**

---

## 6. WHITELIST / CAPABILITY HYGIENE — the orphan-row-to-liveness chain

The follow-up question to §4's permission map: **is every live row's permission bit still
actually held by a live object, and is each bit held by enough holders?** This is a distinct
lane from §4 and it produced the session's headline finding.

### The orphan-row → dead-bit chain (the part that is easy to miss)

An orphan row is not just untidy state. Work the bit arithmetic:

1. Read the live VecMap contents array (one call, see §4 step 2) → decode each row's bitfield.
2. Resolve every key as an object (`object(address:){ address version owner{...} }`) — a
   **`{"data":null}` return means the row is orphaned**.
3. **Subtract the orphaned rows' bits from the live set.** Any bit that only orphaned rows held
   is now held by *nobody*, and every operation gated on that bit is **permanently dead on
   mainnet**.

current.finance (2026-10-28, R12): the VecMap held 4 rows — values `3, 5, 4, 3`. Two keys
returned `null`. The orphan with value `5` was the **sole holder of bit 3 (`adl`)**. So ADL —
`liquidate_v2.txt:320` and `:381` — cannot execute at all. That is a functional outage, and it
was invisible to a pass that only counted rows.

**Always state the surviving bit→holder-count table explicitly**, e.g.:

| Bit | Operation | Live holders | Verdict |
|---|---|---|---|
| 0 | flash_loan | 2 | OK |
| 1 | enter_market_with_emode | 2 | OK |
| 2 | liquidation | **1** | **SPOF** |
| 3 | adl | **0** | **DEAD** |

### Single-holder bit = SPOF, and the owner type decides the severity

For any bit with exactly one live holder, resolve the holder's **owner `__typename`**:

- `AddressOwner` → **EOA, one private key, no threshold, no timelock.** Report as a
  single point of failure. The owner's other objects (coins, obligations) corroborate it: a
  multisig holder shows multisig objects, an EOA shows coins + obligations.
- `ConsensusAddressOwner` / `ObjectOwner` → multisig or another object; materially better.

Then split the impact two ways, because they are different findings:

- **Key lost** → the gated operation is blocked **permanently**. Check whether recovery is even
  possible on-chain: `mint_new_whitelist` needs `AdminCap` and mints with permission **0**
  (`whitelist_admin.txt:46`), and `update_permission` can only mutate bits on a row that
  **already exists** (`vec_map::get_mut` on the passed ID). So there is no on-chain path that
  creates a *new* cap with the needed bit except mint-then-update under `AdminCap`. If the
  `AdminCap` is held by the same EOA, the SPOF is the whole permission system.
- **Key compromised** → the holder can invoke the gated operation at will. Pair with the
  oracle-accessor map in §2: a permission that *triggers* an operation does not bound its
  *magnitude*, so a compromised liquidation cap plus a manipulable price read is an over-seize
  primitive. State that the permission gates *who may act*, not *how much may be taken*.

### Can an orphan row be reactivated? (object-ID derivation)

**No, in practice.** A Sui object ID is `hash(tx_digest || counter)`, so the same ID cannot
recur absent a hash collision. A minted cap gets a fresh ID and lands in a *new* row.

Two consequences worth reporting:

- **`update_permission` can still write to an orphan row** — it takes an `ID`, not a cap
  reference (`whitelist_admin.txt:100`, `vec_map::get_mut` at :123, `WriteRef` at :28/:39), with
  no existence check. So an admin can set an orphan row to any bitfield. **It is inert**: the
  call sites pass the caller's *own* cap ID, and that object no longer exists, so it can never
  be presented as a transaction argument. Report as state pollution, not as a live escalation.
- **`burn_whitelist` cannot clean an orphan** — it consumes the cap by value (`Arg1:
  PackageCallerCap`) and calls `app::burn_cap` (:82), so it needs the object to still exist.
  The **only** cleanup path for an orphan row is `remove_whitelist(&AdminCap, &mut ProtocolApp,
  ID)` (:86-98), which takes just an ID. Name it explicitly in MITIGATION — it is the
  actionable fix, and it is frequently unused.

### The "second capability store" question — count references, not rows

When a brief asserts a discrepancy like "14 references vs 4 live rows", **do not assume a hidden
store.** Grep the capability type name across the disassembly tree and bucket the hits by file:

- Hits that are **struct fields, function signatures, and `MutBorrowField`/`ImmBorrowField`**
  are *code references*, not data rows. In current.finance the "14" was exactly the hit count in
  `lev/leverage_app.txt` — all code, zero rows.
- A genuinely separate store shows up as a **different container type**. There, the leverage
  package held `LeverageApp.protocol_caller_cap: vector<PackageCallerCap>`
  (`lev/leverage_app.txt:25`) — a **vector, not a VecMap, with no permission bits at all**,
  capped at one element (`accept_protocol_caller_cap` :57 aborts `already_assigned_caller_cap`
  if `VecLen != 0`; `borrow_protocol_caller_cap` :109 aborts `no_caller_cap` if `VecLen != 1`).

So the correct answer is nuanced and worth stating precisely: **there IS a second capability
store, but it is a borrow-and-return slot, not a permission store.** It holds at most one cap,
delegates all authorization back to the lending package's VecMap, and its revoke path
(`revoke_protocol_caller_cap` :80 → `burn_whitelist` :105) is the *only* production caller of
`burn_whitelist` — which is itself the likely explanation for why orphan rows exist at all.

**Report the shape of the second store (container type, element cap, whether it carries
permissions, and who can write it) rather than a yes/no.** A yes/no answer to "is there a second
store" is almost always wrong in both directions.

### Enumerating the permission model completely

The bit definitions are usually **trivial constant-returning functions** in the admin module
(`whitelist_admin.txt:9-31`: `flash_loan()=0`, `enter_market_with_emode()=1`,
`liquidation()=2`, `adl()=3`). Enumerate them, then grep for every `ensure_has_permission`
call site and record **which bit each entry point demands**:

| Entry point | Call site | Bit demanded |
|---|---|---|
| `flash_loan.txt` | :49-50 | 0 |
| `enter_market.txt` / `emode/enter_market.txt` | :50-51 | 1 |
| `liquidate.txt` / `_v1` / `_v2` | :59 | 2 |
| `liquidate_v2.txt` | :320, :381 | 3 |

Two traps:

- **The upper bound is enforced, so there is no bit 4+.** `update_permission` aborts on
  `perm >= 4` (:105-107, `Lt` against const `4`). State the model as closed rather than leaving
  higher bits implied.
- **The module that *implements* the check may be missing from your disassembly set.** In this
  session `app::ensure_has_permission` / `whitelist_mut` / `mint_cap` / `burn_cap` were called
  from six modules but the `app` module itself was absent from `evidence/disasm/`. Grep for the
  helper name and check whether its defining module is on disk; if not, mark the check's
  *internal* semantics (abort-vs-return-false on a missing row) **UNTESTED** rather than
  inferring it from the call sites.

---

## 7. ATTRIBUTION DISCIPLINE + SUBAGENT FAILURE HANDLING

### Attributing a bytecode line to its function — match ALL declarations, not just `public`

This cost a whole wrong severity rating and is the cheapest mistake in the whole file to avoid.
A disassembly file contains **`public`, `public(friend)`, `entry`, AND bare private helper
declarations** (`helper<Ty0>(Arg0: …, …) {`). A regex that only matches
`^(public|public\(friend\)|entry)\s` silently drops every private helper, so every line after the
last public function gets attributed to that function — no matter how far away it is.

Symptom to recognise: six "unbounded scan" lines spread across ~800 lines of file all resolving
to one function (`repay_flash_loan`), which is absurd on its face. current.finance: market.txt is
3,142 lines with **36** `public`-family declarations but **50** declarations total. Matching all
50 resolved the six sites to **six different helpers**:

| Line | Enclosing helper (private) |
|---|---|
| 2223 | `refresh_obligation_assets_interest` |
| 2331 | `refresh_obligation_borrow_interest` |
| 2664 | `collaterals_usd_for_liquidation` |
| 2783 | `debts_value_usd_for_liquidation` |
| 2895 | `debts_value_usd_non_liquidation` |
| 3035 | `collaterals_usd_non_liquidation` |

The working matcher:

```python
re.match(r'^[a-z_]+<[^>]*>\(', s) or re.match(r'^(public|public\(friend\)|entry)\s', s)
```

then walk declarations to find the nearest preceding one for any target line.

**Why it mattered:** the mis-attribution supported a HIGH-severity "attacker bricks the protocol"
gas-DoS claim. Correct attribution showed all six scans read `&Obligation<Ty0>` — **the caller's
own obligation** — with no market-wide loop anywhere in the package. The finding is a
**self-inflicted** gas DoS and drops to LOW-MEDIUM. Same lines, opposite severity.

**Rule: before ranking any "unbounded loop / gas exhaustion" finding, attribute every scan site
to its true enclosing function and check whose obligation it reads.** If it reads only the
caller's, the attacker pays for their own DoS and can still be liquidated by a caller supplying
more gas. Also check the *cost to build* the inflated state — if each added asset requires a real
deposit or borrow, the primitive is capital-intensive and further bounded.

### The "one failing asset freezes everything" hypothesis — test it against the pricing path

The natural composition hypothesis is: a failing oracle feed + unbounded obligation = an
obligation that can never be liquidated. **Refuted by counting oracle calls in the seize path.**
`liquidate_calculate_seize_ctokens` (market.txt:2572+) makes exactly **two** `get_spot_price`
calls (:2590 collateral, :2596 debt) — the pair being liquidated, not every asset in the
obligation. An obligation holding five assets where one feed is failing still liquidates fine on
any healthy pair.

**Method:** grep the seize/liquidation helper for oracle calls and count them. Two calls ⇒
pair-scoped ⇒ the freeze blocks operations *on that asset*, not the whole position. This is the
cheapest possible refutation of an amplifier claim and it takes one grep.

### Subagent failure modes — two distinct shapes, one response

Long adversarial lanes fail in two different ways, and the response differs:

| Failure | Signature | Response |
|---|---|---|
| **Provider timeout** | `status=failed`, 504 after exhausting the call budget | re-dispatch **split into two narrower lanes** with an explicit call/time budget and a stated priority order ("prioritise (f) first — it can kill the whole chain") |
| **Model unavailable** | `HTTP 404: Model not available` returned as the *summary* — the subagent ran, burned its budget, and produced nothing usable | **do not re-dispatch the same brief.** The lane's questions are answerable from artifacts already on disk; do them yourself. |

The second shape is the dangerous one because it *looks* like a completed task. A summary that is
an HTTP error string is not a result. **When a lane returns an error string rather than findings,
and the underlying questions are answerable from bytecode/evidence already on disk, answer them
directly** — in this session all three questions of the failed lane were resolved in two terminal
calls against the existing disassembly, which was far cheaper than a third dispatch.

General rule that generalises: **a failed delegation is not a blocker when the evidence is local.**
Check whether the question is answerable from on-disk artifacts before spending another dispatch.

### Re-dispatch scope arithmetic (why the second attempt must be smaller)

The first failure was a 50-call budget on a brief with six sub-questions. The successful
re-dispatch used **25 calls / 8 minutes / 3 questions / 400-word output cap / "write VERDICT
FIRST"**. Roughly a 2-3× reduction in scope per retry, plus an explicit instruction to write the
verdict before investigating so a truncated run still leaves the answer on disk. See
`orchestrator-tdd-subagents` → `references/scope-arithmetic-anti-timeout.md` for the general form.
