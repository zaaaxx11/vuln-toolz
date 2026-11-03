# Oracle liveness, hidden markets, and the custody refutation

Companion to `sui-move-composed-chain-method.md` (build the chain) and
`defending-composed-chain-kill-questions.md` (defend it). This file covers the finding classes
those two do NOT: **liveness** (a feed that is accurate but not refreshed), **hidden-market
exposure**, and two refutation patterns that killed plausible hypotheses this session.

Worked case: `current.finance`, Sui Move lending, cross-market / cross-package composition lane.

---

## 1. A finding class the oracle work missed: LIVENESS, not manipulation

Every prior oracle finding on this target was *manipulation* — unchecked EMA, raw spot, tolerance
not read. The orthogonal class is **liveness**: a feed whose `checkTimeMs` is older than its
`maxTimeGapMs`. The effect is the opposite of manipulation and much easier to miss:

`x_oracle::ensure_secondary_checks_passed` (`oracle_x_oracle.txt:181-291`) **aborts** when the
feed checker has not passed. It is called on every guarded path — borrow, withdraw, and
liquidation (`market.txt:2945`, `market.txt:3086`). So a stale feed does not let an attacker in;
it **locks everyone out, including liquidators**.

Worked evidence (live check-table response, `evidence/check_table.json`):

| Asset | Market | passed | checkStatus | deviationBps | timeGapMs | maxTimeGapMs |
|---|---|---|---|---|---|---|
| `sui_usde::SUI_USDE` | EthenaMarket (hidden) | **0** | 1 | **8** | 6,150,136,164 (~71d) | 1,209,600,000 (14d) |
| `xaum::XAUM` | MatrixGoldMarket (hidden) | 1 | 0 | 0 | 772 ms | 15,000 ms |

**`deviationBps=8` is the decoy.** The price is accurate to 8bps. An agent that checks only
deviation marks this feed healthy and walks past a 5.1× staleness breach.

**Rule:** read `timeGapMs` against `maxTimeGapMs` *per asset*, and never infer health from
`deviationBps` alone. A tiny deviation with a huge gap is the signature of an abandoned feed, and
it is the most dangerous state for a lending market — the asset cannot be borrowed, withdrawn, or
liquidated.

**Severity framing — do not inflate.** This is not fund theft. It is *frozen obligations on a
hidden market*: N positions that the protocol itself cannot liquidate. Report it as a
liveness/solvency issue at that severity. Claiming "attacker steals" here gets the whole report
discounted.

---

## 2. Hidden markets are a first-class exposure surface

Six `Market<Ty0>` objects exist on-chain; **two are absent from the UI** (MatrixGoldMarket,
EthenaMarket) and both hold live obligations. Enumerate markets by object type, never by what the
dashboard shows.

```python
q = '{ object(address: "%s"){ asMoveObject { contents { type { repr } } } \
      dynamicFields(first: 50){ nodes { name { type { repr } } } } } }'
```

All six returned identical dynamic-field sets — `ADLRegistryKey`, `CircuitBreakKey`,
`MarketConfigurationKey` — so *structural* checks are uniform across markets. What differs is
**config and feed health per market**, which is exactly where the finding lives. Check every
market's `MarketConfigurationKey` and every asset's feed row; do not sample one market and
generalise.

---

## 3. The custody refutation — read WHO the cap argument is before claiming stranded funds

**Hypothesis (plausible, wrong):** a module with a public `deposit` and no withdraw/claim must be
holding user funds with no exit → stranded-funds bug.

**Refutation:** trace the owner/cap argument of the *inner* deposit call. `flp.txt:375`:

```
95: MoveLoc[3](Arg3: &ObligationOwnerCap)      <- the CALLER's own cap
96: Call deposit::deposit<MainMarket, Ty0>(&ProtocolApp, &mut Market<MainMarket>,
        &ObligationOwnerCap, Coin<Ty0>, &Clock, &TxContext)
```

The coins land in the **caller's** obligation, not in the module's shared object. The module only
increments `total_amount` and `obligation_flps[id]` — it is a **quota ledger, not a vault**. The
user exits through the normal `withdraw` path on their own obligation.

**Rule:** "deposit exists, withdraw does not" is never sufficient. Read the cap argument. If it is
the caller's, there is no custody and no stranded-funds finding.

**Corollary check that closed it completely:** the accrual divisors. SUI ÷ `5e12` and USDC ÷ `5e9`
both normalise to "per 5,000 units" — consistent, so no unit-mismatch bug either. When you
refute a custody claim, also verify the unit arithmetic before publishing the refutation.

---

## 4. The shared-sink refutation — different entry point ≠ different guard

**Hypothesis (plausible, wrong):** the ADL entry points (`liquidate_adl_borrow`,
`liquidate_adl_deposit`) bypass guarded pricing, because they take a different
`whitelist_admin::adl()` permission and build their own `LiquidationParams`.

**Refutation:** grep for the shared inner function before claiming a bypass.

```
liquidate.txt:338  -> market::handle_debt_auto_deleverage      -> liquidation_inner (market.txt:1558)
liquidate.txt:399  -> market::handle_collateral_auto_deleverage -> liquidation_inner (market.txt:1749)
```

Both ADL handlers funnel into the **same** `liquidation_inner` that normal liquidation uses, which
calls `debts_value_usd_for_liquidation` / `collaterals_usd_for_liquidation` →
`user_oracle::get_price_with_check` (guarded, `oracle_user_oracle.txt:78-145`).

**Rule:** before writing "path X bypasses guard G", grep the corpus for the sink G protects and
check whether X reaches it. A distinct entry point with distinct params usually shares the sink.

**What survived from the same analysis (publish this instead):** the ADL *parameters* are
admin-set and unclamped on the consumer side. `adl::close_factor()` (`adl.txt:397-403`) returns the
raw Decimal and flows into `LiquidationParams.close_factor` at `market.txt:1537` and `:1711` with
no `float::le(one)` clamp; the only consumer is `ensure_liquidate_borrow_allowed`
(`market.txt:2530`). Likewise `adl::liquidation_incentive` (`adl.txt:445-465`) grows linearly with
`secs/86400` with no cap. The setter lives in an un-disassembled admin module, so this is a
**consumer-side hardening gap**, not a proven exploit — label it that way.

---

## 5. GraphQL patterns that worked (Sui mainnet)

**Dynamic field by name** — the `bcs` for a `struct X has drop { dummy_field: bool }` key is
`"AA=="` (false):

```graphql
{ object(address: "0x41f3d76a...") {
  dynamicField(name:{type:"0xfe1d...::market::MarketConfigurationKey", bcs:"AA=="}) {
    value { ... on MoveValue { type { repr } json } } } } }
```

**Owner union — introspect before guessing.** The correct shape is
`owner { ... on AddressOwner { address { address } } }` — **double-nested**. Guessing
`{ owner { address } }` fails twice. Full introspection recipe and the indexer-inconsistency
control test are in `sui-move-indexer-inconsistency.md` §3.

**Decimal serialisation:** a Move `Decimal` comes back as an 18-decimal integer *string*.
`"200000000000000000"` = `0.20`. Never parse it as a float without dividing by `1e18`.

**Empty registry read:** `collaterals.table.table.size = "0"` and `borrows.size = "0"` proves the
ADL registry is dormant — `get_borrow_deleverage` would abort `adl_emode_group_not_found`. Reading
an empty registry is positive evidence, not a null result.

---

## 6. Report discipline the user demanded (encode this, it is a hard requirement)

- **Create the report skeleton on disk before the first analysis call.** The report must ALWAYS
  exist on disk — a crash mid-session must not lose the deliverable.
- **Append every N tool calls** (user specified 5), not at the end. Budget the round and append on
  schedule even if a section is still `_PENDING`.
- Required sections: `VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE /
  MITIGATION / VERIFICATION`, plus a **claim-vs-proof table**, a **REFUTED** table, and an
  **UNTESTED** table.
- **Every claim needs `file:line` or a real GraphQL response.** No claim from memory or inference.
- Publish refutations with the same prominence as findings — the REFUTED table is what makes the
  LIVE table credible.
