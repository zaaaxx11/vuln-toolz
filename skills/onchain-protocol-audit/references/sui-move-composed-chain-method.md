# Composed on-chain chains — the method that beat the bug list

Worked case: `current.finance`, Sui Move, lending + leverage, 6-hour RCE brief.
The deliverable that mattered was **not** an RCE (there is no OS process to own on a Move target).
It was a **four-defect chain that composes inside one transaction**, assembled from findings that
were individually rated "Medium" by a public Sherlock audit.

This reference is the method. It generalises to any protocol where you have disassembly.

---

## 0. Why chains beat lists

A bug list says "here are 12 Mediums". A triager reads it as noise. A chain says:

```
M-14 (gate prices debt with an UNCHECKED EMA)
  → M-12 (below-threshold value early-returns, close_factor never applied)
    → M-08 (close factor is per-debt-asset, so a multi-asset obligation sums past it)
      → H-02 (seizure amount priced off RAW SPOT)
```

...and each link has a `file:line`. That is one sentence of impact — *a liquidator can close 100%
of a position at an attacker-favourable price* — backed by four citations. Severity stops being
the sum of the parts and becomes the product.

**The chain is the finding. Report the chain.**

---

## 1. Step 1 — enumerate EVERY call site of the accessor family, then rank by guard strength

Do not grep the function you suspect. Grep the **accessor name** across the whole module.

```bash
grep -n 'user_oracle::get_price'        market.txt   # EMA-only, no tolerance arg
grep -n 'user_oracle::get_spot_price'   market.txt   # raw spot, no tolerance arg
grep -n 'user_oracle::get_price_with_check\|get_spot_price_with_check' market.txt
grep -n 'ensure_secondary_checks_passed' market.txt
```

Worked result on `market.txt` (115,846 chars):

| Tier | Accessor | Line | Consumer |
|---|---|---|---|
| 0 | `get_price` — EMA only, **no check** | **2511** | `validate_liquidation` — the **may-liquidate gate** |
| 1 | `get_spot_price` — raw spot | 2590, 2596 | `liquidate_calculate_seize_ctokens` — **how much is seized** |
| 2 | `get_spot_price_with_check` | 2719, 2832 | `collaterals/debts_usd_for_liquidation` — eligibility value |
| 3 | `get_price_with_check` **+ `ensure_secondary_checks_passed`** | 2940-2947, 3086-3093 | `*_non_liquidation` — the **borrow/withdraw risk gate** |

**The first pass found three tiers and missed tier 0**, because it grepped the seizure function
instead of the accessor family. Tier 0 is on the *gate* — upstream of every other defect — and it
is the weakest.

**The headline is the inversion, not the bug:** the path that protects depositors
(borrow/withdraw) gets the strongest treatment; the path that takes collateral from borrowers
(liquidation) gets the weakest, three times over in one transaction.

### The scope-creep check that upgrades severity

```bash
grep -rc 'with_check' evidence/disasm/     # per-module count
```

A package-wide **zero** means every entry point prices off raw spot — that converts a
whitelist-gated module bug into an **any-user subsystem bug**. Run it *before* writing up.

---

## 2. Step 2 — read the gate function's FULL bytecode for a SECOND defect in the same block

The chain was invisible until the ~20 instructions *after* the oracle call were read.

`market.txt:2505-2530`, `validate_liquidation`:

```
 99: MoveLoc[7](Arg7: &XOracle)
102: Call emode::get_oracle_base_token(&EModeGroup): BaseToken
103: MoveLoc[8](Arg8: &Clock)
104: Call user_oracle::get_price(&XOracle, TypeName, BaseToken, &Clock): Decimal   <- TIER 0
105: CopyLoc[12](loc3: Decimal)
109: Call value::coin_value(Decimal, Decimal, u8): Decimal
110: Call float::ceil(Decimal): u64
111: CopyLoc[0](Arg0: &LiquidationParams)
112: ImmBorrowField[13](LiquidationParams.close_factor_bypass_min_value: u64)
113: ReadRef
114: Le
115: BrFalse(119)          <- if debt_value <= bypass_min -> branch to 116
116: MoveLoc[0](Arg0: &LiquidationParams)
117: Pop
118: Ret                   <- EARLY RETURN: close_factor NEVER APPLIED
119: MoveLoc[12](loc3: Decimal)
120: MoveLoc[0](Arg0: &LiquidationParams)
121: ImmBorrowField[14](LiquidationParams.close_factor: Decimal)   <- only if above threshold
```

Two defects in one block:
1. the price comes from the **unchecked** accessor (M-14);
2. a below-threshold value **early-returns**, so the configured `close_factor` is never applied
   (M-12) — the liquidator may close **100%** instead of 20-30%.

**Method:** when you find a weak accessor, keep reading the block. The weak input usually feeds a
branch, and the branch usually has a second problem.

### Live config to publish alongside

Read each market's `MarketConfigurationKey` dynamic field — never quote the code's default:

| Market | close_factor | bypass_min_value |
|---|---|---|
| MainMarket | 0.20 | 5 |
| AltCoinMarket | 0.30 | 5 |
| EmberMarket | 0.30 | 5 |
| Market01 | 0.20 | 20 |
| MatrixGoldMarket (hidden) | 0.30 | 5 |
| EthenaMarket (hidden) | 0.30 | 5 |

---

## 3. Step 3 — ask "is this bound per ITEM or per AGGREGATE?"

`market.txt:2530-2532`:

```
121: ImmBorrowField[14](LiquidationParams.close_factor: Decimal)
123: Call float::mul(Decimal, Decimal): Decimal)     <- close_factor * repay_amount
128: Call float::le(Decimal, Decimal): bool
131: Call error::liquidation_close_factor_exceeded(): u64
132: Abort
```

`liquidate_calculate_seize_ctokens<Ty0, Ty1>` is generic over the **collateral type** `Ty0` and the
**debt type** `Ty1` — one pair per call. So the check is per debt asset, and a **multi-asset
obligation is validated once per asset**: each individual asset stays inside its close factor while
the *sum* approaches 100%.

**Amplifier:** H-03's unbounded asset scan (6 call sites, `MAX_ASSETS`×0) makes building such an
obligation cheap. Two independent findings become one attack primitive.

**Rule:** before scoring any bound, ask whether it is enforced per item or per aggregate. Per-item
bounds on an unbounded-length collection are an aggregate bypass.

---

## 4. Step 4 — the staleness gap is config, not code

The `XOracle` object carries `price_delay_tolerance_ms = 30000` — matching the documented
"staleness gate". The **per-asset** `maxTimeGapMs` in the live check-table is
**1,209,600,000 ms = 14 days** for every asset, and five assets' admin-reference check prices are
already ~71 days old.

**40,320× looser than the documented value.** The object-level tolerance is not the operative
bound.

**Rule:** read both the object-level and the per-asset override before quoting any "gate" value.
The doc quotes the object; the code obeys the override.

---

## 5. Step 5 — diff the market's asset list against the public oracle table

```python
# MainMarket assets, live
j = gql('{ object(address: "<market>") { asMoveObject { contents { json } } } }')
assets = j["assets"]["table"]["keys"]["contents"]        # 18 entries, full coin types
```

Worked result: 18 assets on-chain, 20 feeds in the public check-table, and **six of MainMarket's
assets absent from it** — `USDC, USDT, FDUSD, USDB, USDY, SUI`, i.e. the highest-liquidity ones.
Conversely 8 check-table feeds belong to *other* markets.

**Do not call it a gap immediately.** The `XOracle.prices` table has **size 2** and the bytecode
has `base_token_from_u8`, `x_oracle::usd()`, `x_oracle::sui()` — so there are two `BaseToken`s
(USD and SUI) and the missing six are almost certainly quoted on the SUI base, with the dashboard
rendering only the USD table. The table's `keys` are not indexer-visible (`with_keys` false), so
this could not be confirmed directly.

**Report it as an open question with a testable answer**, and state the stakes: if the non-USD base
has a weaker secondary check, the whole chain is exploitable on exactly the assets holding the most
value — and the protocol's only transparency surface does not show them at all.

---

## 6. Step 6 — re-verify the public audit, and expect the audit's numbers to be wrong

Full method in SKILL.md §9. The three lessons that only appeared this session:

1. **The PoCs are harness-only.** They model the bug in a standalone package. They generate
   hypotheses; they prove nothing about mainnet. Grep the deployed disassembly for the construct
   the finding names.
2. **A named module that does not exist is a hard refutation.** `reward_manager` →
   `module: null` from GraphQL killed two findings in one call.
3. **"LIVE (refined)" when the audit's number is off.** M-07's "decimals > 18 aborts" is really
   "≥ 20" (`u64::pow(10, decimals)`; 10^19 fits, 10^20 aborts). Publish the real cliff.

Worked scorecard: **12 LIVE / 3 REFUTED / 2 UNTESTED** of 17 — and because the package upgrade
preserved those modules byte-for-byte (md5-identical `liquidate`, identical `market` call counts),
**the upgrade fixed none of them.** That is the reportable headline.

---

## 7. Report shape for a composed chain

```
VULNERABILITY: Composed liquidation chain — unchecked gate price + close-factor bypass
               + per-asset bound + raw-spot seizure
ENTRY:        Whitelisted liquidator (PackageCallerCap, permission bit 2)
CHAIN:        M-14 (market.txt:2511, unchecked EMA on the may-liquidate gate)
              -> M-12 (market.txt:112-118, early Ret skips close_factor below bypass_min)
              -> M-08 (market.txt:121-132, close_factor enforced per debt asset)
              -> H-02 (market.txt:2586-2596, seizure priced off raw get_spot_price)
IMPACT:       Full position closure at an attacker-favourable price. VaR $58.16M TVL,
              55,669 obligations across 6 markets (2 hidden from the UI).
POC:          structural — every link is a bytecode citation; no tx broadcast
EVIDENCE:     market.txt:2505-2596 + live MarketConfiguration per market
CONFIDENCE:   PROVEN (bytecode) / config values read live
MITIGATION:   route validate_liquidation through get_price_with_check; apply close_factor
              per obligation, not per debt asset; remove the early-return bypass
VERIFICATION: v1≡v2 by md5, so the finding holds for the deployed upgrade
```

Then publish, separately and honestly:
- the **REFUTED** table (split-brain registry, leverage arithmetic, oracleUpdate reflection,
  L-03/L-04/M-10, `reward_manager` absent);
- the **UNVERIFIED** table (deployer-EOA admin-cap claim the orchestrator could not replicate
  through an inconsistent indexer — neither confirmed nor refuted);
- the **provenance clarification** (resolver follows upgrade linkage; objects keep their creating
  version's type stamp; both statements are true at once).
