# AMM liquidity-venue audits: quote-vs-execution divergence → theft or integration bug?

Companion to `readonly-security-audit` for the case where a DeFi tranche/market integrates an
external AMM (Balancer V3, Uniswap v3, Curve) as a **secondary liquidity venue**, and the
hypothesis is "the venue's quote diverges from its execution path → value extraction".

Worked reference case: Royco Day-v2 kernel + Balancer V3 venue (ST-share ↔ quote-asset pool),
audit 2026-10-22. The hypothesis was REFUTED as theft; the residual is an integration bug.

---

## 1. The transient-cache killer (fastest REFUTAL in this whole class)

Most protocols of this generation "preview then execute". The instinctive fear: *the execute path
reads a price cached by the preview, so a third party moves the pool between the two*.

**Check the cache's storage class before anything else.** Modern Solidity transient storage
(`TSTORE`/`TLOAD`) is cleared by the EVM at the end of **every transaction**. A preview and the
later execute are in different transactions, so a transient cache can never carry a stale price
across them.

Royco example (`src/libraries/Cache.sol`):

```solidity
57|   uint256 slotValue = _getTransientStorageSlot(_key).asUint256().tload();
70|   _getTransientStorageSlot(_key).asUint256().tstore((_value | _CACHE_SET_MASK));
```

And the *only* writers of the venue-price key are guarded by `DispatchMode.SIMULATE`:

```
src/libraries/logic/DepositLogic.sol:138
    if (_mode == DispatchMode.SIMULATE) Cache._write(CacheKey.LPT_ASSET_PRICE, toUint256(lptAssetPrice));
```

Two extra facts worth stating in the report because they kill the hypothesis completely:

- The SIMULATE branch of the venue callback **reverts** to unwind (`revert DispatchLogic.SIMULATION_RESULT(...)`),
  so the transient write that follows is rolled back with the frame.
- The execute path deliberately **writes nothing** and re-prices the settled pool **live** through a
  manipulation-resistant oracle (`LPOracleBase.computeTVL() / vault.totalSupply(bpt)`).

### The named-return-zero red herring

```solidity
function addBalancerV3Liquidity(...) returns (uint256 lptAssets, NAV_UNIT lptAssetPrice) {
    ...
    if (_mode == DispatchMode.SIMULATE) {
        revert DispatchLogic.SIMULATION_RESULT(abi.encode(lptAssets, IRoycoDayKernel(address(this)).queryLPTAssetOracle()));
    }
    ...
    // EXECUTE falls through -> returns (lptAssets, 0)
}
```

The `lptAssetPrice` named return is **never assigned at all** — the value lives inside the revert
payload. Grep every consumer of the returned tuple and check the `SIMULATE` guard before concluding
"the execute path uses a bogus zero price". In Royco both consumers
(`DepositLogic.sol:138`, `RedemptionLogic.sol:155`) are `if (_mode == DispatchMode.SIMULATE)`-guarded,
so the zero is a **dead value**, not a live one.

**Verdict shape:** `REFUTED — the execute path cannot use a stale preview price`, with the three
independent reasons (transient storage / per-tx lifetime, preview reverts and unwinds, execute
re-prices live at the oracle).

---

## 2. Slippage bounds — where they actually live

On an AMM venue the slippage guard is usually **inside the AMM's own parameters**, not in the
integrating protocol. Enumerate them; each is a hard revert inside the AMM:

| Bound | Typical location |
|---|---|
| `minBptAmountOut` / `minAmountsOut` | the AMM `addLiquidity`/`removeLiquidity` call params |
| oracle-derived floor minus a configured slippage tolerance | the integrator's own pre-check |

Two facts decide whether the bounds are sound:

1. **Who supplies the bound?** If the *caller of the transaction* supplies it, there is no
   server-side default that could be stale. If a protocol-owned default is used, check when it was
   last refreshed.
2. **Is the floor priced at the spot or at the manipulation-resistant oracle?** A floor derived from
   the *pool's own spot price* is sandwichable; a floor derived from an oracle mark is not. Royco
   derives the reinvestment floor from the oracle and subtracts a configured tolerance:
   `minLPTAssetsOut = equivalentLPTAssetsForValue.mulDiv(WAD - maxReinvestmentSlippageWAD, WAD, Ceil)`.

Also check the failure mode: Royco's reinvestment is **best-effort** (`DispatchLogic._tryExecute`),
so a breached floor leaves the premium idle rather than settling a bad trade. That is a
correctness property worth stating — a best-effort wrapper around a slippage-bounded trade is
safer than a mandatory one.

---

## 3. The value-neutrality test — the actual discriminator

The task is "quote says X, execution does Y". The magnitude of X-vs-Y is **not** the question.
The question is **who loses money**. Two numbers decide it.

### (a) Round-trip value of the depositor

Recompute the full post-operation state and ask what the user's shares are worth *after* the
deposit, at the new share price:

```
post NAV     = preEffectiveNAV + depositNAV
post supply  = preSupply + sharesMinted
post price   = post NAV / post supply
user value   = post price * sharesMinted
```

Royco result: depositor paid **100.000000 NAV**, received 95.011876e18 shares, post price
**1.0525000000** → user value **100.000000 NAV**. **Exactly the deposit. Zero loss.**

The share-count gap (4.99%) is fully offset by the share price (1.0 → 1.0525). A share-count gap
with a compensating price move is *not* extraction.

### (b) The counterfactual block — quantify what a REAL bug would be worth

This is the highest-value presentation trick in this class. Show what the user *would* have
extracted if the divergence had been in the dangerous direction:

```
HYPOTHETICAL if 100.000000e18 shares were minted (the view's number):
  post price       = 1.0477272727 NAV/share
  depositor value  = 104772727272727265280.000000 NAV
  -> over-mint gain= 4772727272727272448.000000 NAV  (what a REAL bug would be worth)
```

Now the report says, with numbers, both (i) what happens — nothing — and (ii) what would happen if
the hypothesis were right — 4.77% of the deposit drained from existing LPT holders. It converts
"inconclusive" into "the dangerous direction is worth exactly X and it does not happen".

### Direction table

| Execute vs view | Direction | Classification |
|---|---|---|
| fewer shares than quoted | depositor short-changed in *count* | MEDIUM integration bug **if** value-neutral |
| more shares than quoted | over-mint | **REAL** — extraction from existing holders |
| redeem pays less than view | view over-promises | MEDIUM integration bug if value-neutral |
| redeem pays more than view | over-payment | REAL |

Then check BOTH legs. Royco's LPT view is conservative on both sides:
`convertToShares` over-states shares (100.000000e18 vs 95.011876e18 actual) and `convertToAssets`
under-states assets (100.000000 NAV vs 105.250000 NAV actual). A view that over-promises on
deposit and under-promises on redeem is *self-consistent as a conservative quote* — and an
integrator using it as `minSharesOut` will always revert, which is the integration symptom.

---

## 4. RECOMPUTE every prior report's numbers from source

The prior report in the same repo (`findings/D_contracts.md` §7) published:
`view 100.000000e18 vs exec 95.238095e18, 4.76% gap`.

**The source produces a different number.** `lptEffectiveNAV` is not `lptRawNAV + idlePremium`;
it is

```
lptEffectiveNAV = lptRawNAV + _convertToValue(lptOwnedSTShares, stTotalSupply, stEffectiveNAV, Floor)
                 = 1000e18 + (1050e18+1)*50e18/(1000e18+1)
                 = 1049.999999999999999999e18      <- not 1050e18
```

so the execution number is **95.011876e18** and the gap is **4.9881%**, not 95.238095e18 / 4.76%.

**Rule: never inherit a number from a previous finding document. Recompute it from the source
constants and paste the recomputation.** The prior report's figure is a *correction*, not a new
bug — say exactly that, so it is not mistaken for a discrepancy in the code.

The recomputation must mirror the source arithmetic exactly, including the virtual-shares/value
offset (`VIRTUAL_SHARES = 1`, `VIRTUAL_VALUE = 1`) and the `Math.Rounding` mode at each call site.
Getting the rounding direction wrong is the single most common way to produce a wrong
"reproduction" of someone else's number.

**Suggested artifact:** a small deterministic Python script that reimplements
`_convertToShares` / `_convertToValue` / `_getLPT...EffectiveNAV` with the constants read off the
source, run it, and paste the output. It is reproducible evidence and it makes the correction
checkable by the reader.

---

## 5. Unbalanced-add fee drag — and a trap

Balancer V3 `AddLiquidityKind.UNBALANCED` charges the pool's swap fee on the **imbalanced
portion** of the add. If the add is balanced relative to the pool's marginal prices, the fee is
zero; the drag scales with how far the two legs are from balanced at the pool's marginal price.

**Trap:** a hand-rolled "imbalance = |leg0Value - leg1Value|" model produced **0 fee in every
scenario**, including a deliberately lopsided 100 ST + 200 quote add into a 1000/1000 pool. The
model was wrong (it compared leg values at the *pool* price instead of computing the fee the
Vault actually charges on the swap that equalises the position). Do not publish a fee-drag
number from a simplified model.

**Correct approach:** prove it with the real Vault semantics — either
(a) a Foundry fork against the live Balancer V3 Vault (it is deployed on mainnet at
`0xBA1333333333a1BA1108e8412F11850a5c319BA9`, and `IVault.addLiquidity` returns the
`swapFeeAmountsRaw` per token in the `LiquidityAdded` event, so the fee is directly observable),
or (b) a unit test against a mock that reproduces the Vault's exact unbalanced-add math — and
then **state plainly which of the two you did**.

If the vendored Balancer monorepo contains **only interfaces + `BalancerPoolToken` + `VaultGuard`**
(no `Vault.sol` implementation, no factories/routers/test-utils), you cannot build the real Vault
locally. State that as a scope limit and either fork the deployed Vault or use the mock with an
explicit "mock, reproduces the Vault semantics" label.

**Who bears the drag:** the fee stays in the pool and accrues to all LPs pro-rata. The LPT tranche
is the pool's LP (it custodies the BPT), so the fee is *not* a loss to the LPT — it is the pool's
revenue. The drag is only a loss if the integrator's own accounting marks the BPT below the fee
adjusted value. Check that before calling it drag: **do not assume the fee is a loss to the
protocol that receives it.**

---

## 6. Double-counting check for "idle premium" style holdings

When a tranche holds two kinds of assets — a pool position (BPT) *and* an idle holding of another
tranche's shares (here: the LPT holds idle senior-tranche shares as accrued liquidity premium) —
the classic question is whether the idle holding is counted **twice**: once inside the pool's
value and once as a direct claim.

Trace every place the idle holding enters a NAV:

| Where | What it adds |
|---|---|
| `lptEffectiveNAV = lptRawNAV + _convertToValue(lptOwnedSTShares, stTotalSupply, stEffectiveNAV)` | the idle shares valued at the senior rate — ONCE |
| `lptRawNAV` (oracle value of `totalLPTAssets`) | the BPT pool position — the pool's own TVL, which is the *other* leg of the trade |

The two are distinct assets **as long as the idle shares were never added into the pool**. The
reinvestment path (`attemptLiquidityPremiumReinvestment`) is where they could merge: it debits
`lptOwnedSeniorTrancheShares` and credits `totalLPTAssets` with the minted BPT in the same
statement. If that debit is missing, the idle shares would be counted once as a direct claim and
again as BPT inside `lptRawNAV` — a real double-count. **Read the debit, don't infer it.**

Also check the reverse: is the idle ST claim *excluded* from the redeem path's scaling, or
included? `AssetLedgerLogic._scaleAssetClaims` scales `stShares` alongside `lptAssets` and `nav`
— so the idle shares are a proportional claim of every LPT holder, and the redeem flow's
`lptRedeemMultiAsset` explicitly adds `lptAssetClaims.stShares` to the withdrawn shares and
redeems them (`RedemptionLogic.sol:159-161`). That is the correct treatment; it also explains why
the *view* zeroes `stShares` (to stop the LPT share price dropping on reinvestment slippage) and
why the view's NAV therefore diverges from execution.

---

## 7. Live-state practicalities that cost real time

### RPC endpoints

- `https://eth.llamarpc.com` → HTTP **525** at audit time.
- `https://rpc.ankr.com/eth` → "Unauthorized: You must authenticate your request with an API key".
- `https://ethereum-rpc.publicnode.com` → works.
- The project's own RPC proxy (`POST https://app.royco.org/api/rpc/1`) → works and served the
  *same* block height as publicnode, so it can be used as a second source for cross-checks.

Always probe candidate RPCs with `eth_blockNumber` first and rotate. Put the working list in the
report so the reader can reproduce.

### `eth_getLogs` and event signatures — do NOT guess

Filtering `eth_getLogs` by a topic0 you computed from a hand-written canonical signature usually
returns **zero** for long/struct-bearing events (the canonical string has structs, enums, nested
tuples; one wrong token ⇒ no match). The reliable sequence:

1. Pull **all** logs from the address over a recent block range with `topics: []`.
2. Collect the **distinct topic0 values** observed.
3. Only then test candidate signature strings against that observed set.

In this session that step is what produced the correct `PoolRegistered` and `LiquidityAdded`
topic hashes after the guessed ones all returned 0 logs.

### Finding the deployed market

The verified-source dumps (`_meta.json`) carry **no address** — mapping `src/<Name>/` to a live
contract needs a separate source. Routes that worked:
- the project's own API (`POST /api/v1/vault/explore`, `/api/v1/market/explore`) with
  `origin: https://app.royco.org`;
- the factory's `trancheToKernel(address)` / `getMarket(address)` view functions (RoycoFactory);
- `eth_getLogs` on the factory for `MarketDeploymentCompleted`.

**Budget discipline (learned the hard way here):** the address hunt consumed roughly a third of
the session's tool-call budget and the session still ended truncated. For an audit whose questions
are answerable from source + arithmetic, do the source-level analysis **first** and treat live
addresses as an enhancement for the parts that truly need live state (fee drag, pool balances).
Front-load the report skeleton and append as you go so a truncated session still lands a usable
artifact.

---

## 8. Report section shape that worked

Per hypothesis: **mechanism → numbers recomputed from source → adversary run → verdict**, with
the verdict words `PROVEN / REFUTED / BLOCKED` (or `HOLDS / BROKEN` if the house style uses the
invariant vocabulary). The brief's own wording wins; mirror it.

Required elements per the brief:

- `file:line` anchors for every claim.
- The numeric values **actually computed by a command that was run**, with the command and its
  output pasted in.
- A verdict with a **reason**, and "BLOCKED" used honestly when the evidence needed (live pool
  state, an address, a fork) was not obtainable — do not silently drop that scope.

For the AMM-venue class specifically, always include:

1. the transient-vs-persistent storage finding (kills the sandwich hypothesis in one line);
2. the three slippage bounds with their file:line;
3. the round-trip value table (pre/post NAV, supply, price, user value) — the proof of neutrality;
4. the counterfactual "what a real bug would be worth" block;
5. the recomputation of any inherited numbers, flagged as a **correction**;
6. an explicit statement of who bears the AMM fee (usually the pool, i.e. the protocol itself).
