# Finding-closure arithmetic — how to KILL a finding you already reported

Reporting a finding is half the job. The other half is **closing it honestly** — either proving it
exploitable or proving it is not, with numbers. This reference collects the four closure techniques
that decided verdicts in the Royco round-5 session, with the exact scripts and their output.

Every number below came from a command that was actually run against a live read-only RPC.

---

## 1. Value-neutrality: the quote-divergence killer

**The finding as reported:** the LPT tranche's view `convertToShares` prices against `lptRawNAV`
while execution prices against `lptEffectiveNAV`. Worked example gap: **4.76%** (later corrected to
4.9881%). Looks like an attacker deposits 100 NAV and receives shares worth 104.77.

**The closure script** (`zoya_r5f.py`, run against source semantics — no chain needed):

```python
S = 1000 * 10**18            # LPT supply
lptRawNAV = 1000 * 10**18
premium = 50 * 10**18        # idle ST shares held for the LPT
stEffNAV = 1050 * 10**18
stSupply = 1000 * 10**18
dep = 100 * 10**18

lptEffNAV   = lptRawNAV + (premium * stEffNAV) // stSupply   # ValuationLogic.sol:98
exec_shares = (dep * S) // lptEffNAV
view_shares = (dep * S) // lptRawNAV

post_nav    = lptEffNAV + dep
post_supply = S + exec_shares
post_price  = (post_nav * 10**18) // post_supply             # SCALE FIRST
dep_value   = (exec_shares * post_price) // 10**18
round_trip  = dep_value - dep
```

**Output:**

```
lptEffectiveNAV        = 1,052,500,000,000,000,000,000
exec shares minted     = 95,011,876,484,560,570,071 = 95.011876 e18
view shares            = 100,000,000,000,000,000,000 = 100.000000 e18
share-count gap        = 4.988124 e18 (4.9881%)
post-deposit price     = 1,052,500,000,000,000,000 = 1.0525000000 NAV/share
depositor's value      = 99,999,999,999,999,999,999 = 100.000000 e18  (paid 100.000000 e18)
ROUND-TRIP P&L         = -1 = -0.000000000 e18 (-0.000000000%)
```

**The counterfactual that makes the refutation credible** — what a *real* bug would be worth:

```
post price (view)      = 1,047,727,272,727,272,727 = 1.0477272727 NAV/share
depositor value (view) = 104,772,727,272,727,272,700 = 104.772727 e18
over-mint gain         = +4,772,727,272,727,272,700 = +4.772727 e18 (+4.7727%)
```

**The other leg** (redeem side) — check it too, because a divergence is only "value-neutral" if it is
conservative in *both* directions:

```
view  convertToAssets  = 100,000,000,000,000,000,000 = 100.000000 e18
exec  claims.nav       = 105,250,000,000,000,000,000 = 105.250000 e18
view UNDERSTATES by    = 5.250000 e18 (5.2500%)
```

Source anchors: `RoycoVaultTranche.sol:140-144` zeroes `trancheClaims.stShares` and swaps `nav` to
`state.lptRawNAV` for the view; execution uses `lptEffectiveNAV` plus the real idle-ST claim
(`AssetLedgerLogic.sol:53-58`).

**Verdict template:**

| Claim | Verdict |
|---|---|
| The divergence exists | PROVEN (4.9881%, not 4.76%) |
| It is an ERC-4626-compliant quote | NO — MEDIUM, integration bug |
| A third party can arbitrage it | REFUTED — the premium is accountant-computed, not a user input |
| The same user can round-trip for profit | REFUTED — round-trip P&L = −1 wei |
| It is a value-extraction path | REFUTED — value-neutral by construction |

**Also correct the original number in the earlier report.** `D_contracts.md` printed 4.76% because it
assumed `lptEffectiveNAV = 1050e18` exactly; the source produces `1049.999999999999999999e18`. Say
"correction, not a new bug" explicitly.

---

## 2. Fee waterfall: yield-theft vs principal-theft

**The finding as reported:** `MAX_PROTOCOL_FEE_WAD = 1e18` (`RoycoDayAccountant/src/libraries/
Constants.sol:28`) lets a `restricted` role set the protocol fee to 100%. Framed as a potential
fund-theft invariant break.

**The closure read** — `FeeAndLiquidityPremiumLogic.sol:84-93`:

```solidity
NAV_UNIT retainedSeniorNAV = (_state.stEffectiveNAV - _state.lptLiquidityPremium - _state.stProtocolFee);
liquidityPremiumShares = _convertToShares((_state.lptLiquidityPremium - _state.lptProtocolFee), retainedSeniorNAV, _stTotalSupply, Floor);
stProtocolFeeShares     = _convertToShares((_state.stProtocolFee + _state.lptProtocolFee), retainedSeniorNAV, _stTotalSupply, Floor);
```

The carve-outs are `lptLiquidityPremium` (senior yield routed to the LPT) and `stProtocolFee` (a
slice of senior yield). The source comment at `:65-66` states it outright: *"no assets enter or
leave"*, *"NAV-neutral and coverage-neutral"*. The Junior fee is the same shape (`:47-53`, priced
against `jtEffectiveNAV - jtProtocolFee`).

**Whose yield, per lever:**

| Lever | Whose yield | Anchor |
|---|---|---|
| `stProtocolFeeWAD` | Senior tranche yield | `:44` mints ST shares to `protocolFeeRecipient` |
| `jtProtocolFeeWAD` | Junior tranche yield | `:47-53` |
| `lptYieldShareProtocolFeeWAD` | LPT liquidity premium | `:88-92` — remitted as **senior** shares to the protocol |
| `jtYieldShareProtocolFeeWAD` | Junior yield share | `RoycoDayAccountant.sol:717` |

**Max USD at risk — compute it, do not assert it:**

```
measured TVL (totalSupply x getRate) = $48,615.72
if protocol fee = 100% of yield and yield = 100% of TVL (worst case): $48,615.72
if protocol fee = 100% of yield and yield = 10% APR over 1 year: $4,861.57
```

**Verdict template:** *WEAKENED → REFUTED as fund theft; SURVIVES as LOW/INFO privileged-config
observation.* Report as "protocol fee cap permits 100% of yield; trust assumption on the fee-admin
role", with the waterfall arithmetic as proof that principal is safe.

**The cross-check that strengthens it:** grep the sibling family for its caps.

```
ConcreteAsyncVault_srRoy/src/lib/StateSetterLib.sol:13:  MAX_MANAGEMENT_FEE = 1_000;   # 10%
ConcreteAsyncVault_srRoy/src/lib/StateSetterLib.sol:16:  MAX_PERFORMANCE_FEE = 3_000;   # 30%
```

The Day-accountant family caps at 100%; the Concrete family at 10%/30%. That inconsistency is the
strongest evidence the `1e18` is an oversight rather than deliberate design — flag it as **fee
policy**, not a vulnerability.

---

## 3. RPC-proxy allowlist oracle (see SKILL.md §4.10 for the full table)

Send a deliberately malformed payload per candidate method and read which layer rejected it:

- `-32600 "Unsupported method: X on CHAIN"` → proxy blocked it (deny list)
- `-32602 "failed to decode signed transaction"` → forwarded, EVM tried to parse
- `-32000 "transaction not found"` → forwarded, node looked the hash up
- `-32601 "method not found"` → forwarded, upstream lacks it

The finding is the **gap**: an operator who denies `eth_sendTransaction`, `admin_peers`,
`personal_listAccounts` and `anvil_impersonateAccount` but forgets `eth_sendRawTransaction` and
`debug_traceTransaction` has an open relay. MEDIUM — free broadcast + internal trace visibility,
**not** fund theft.

---

## 4. The self-attack checklist (kills your own best chain)

Four questions, answered in the report:

1. **Is there a signed-payload oracle?** Enumerate every endpoint that could return a transaction the
   app asked a user to sign. All 404 ⇒ nothing to replay.
2. **Can the payload be mutated?** `eth_sendRawTransaction` broadcasts verbatim; changing nonce or
   recipient invalidates the signature.
3. **Does the victim's key ever touch the app?** SIWE-style auth proves it does not.
4. **Does the relay add capability?** Broadcasting is already free on any public RPC.

**Verdict template:** *NOT EXPLOITABLE as a fund-theft chain*, followed by the residual findings at
their true severity (MEDIUM relay, LOW write-on-GET, LOW unbounded range).

---

## 5. Live-state closure reads that settled the verdicts

```
# authority owner / vault wiring
authority.owner()     = 0x61a4df921e2d209acd99c55001281d4050ef583d
boringSafe.owner()    = 0x74d1fafa4e0163b2f1035f1b052137f3f9bad5cc   <- vault owns the safe  ✅
vault.hook()          = 0x60ebb5d1454bb99aa35f63f609e79179b342b0b8
vault.authority()     = 0x754213afb8ecb6d15f169bfd378fb685f5cb0d4a
vault.currentEpoch    = 6
vault.maxRewardId     = 0

# accountant live state
exchangeRate       = 1000000        (1.0 USDC/share)
allowedUpper       = 10050          (100.5%)
allowedLower       = 9950           (99.5%)
lastUpdateTs       = 1743097151     (Mar 2025)
isPaused           = 0
minUpdateDelay     = 0 s            <-- no time gate  (LOW)
platformFee        = 0
performanceFee     = 23749451159961600   <-- absurd, capped at 50% by the setter (LOW, hygiene)
```

All ten accountant mutators revert `UNAUTHORIZED` for an arbitrary caller, including for the address
holding the largest share balance:

```
enter(assetAmount=0, shares=1e20) FREE MINT by 0x9ec2   REVERT UNAUTHORIZED
exit(holder's shares -> attacker USDC) by 0x9ec2        REVERT UNAUTHORIZED
manage(...) by 0x9ec2                                   REVERT Invalid params   <- encoding, not auth
accountant.updateExchangeRate(2.0) by 0x9ec2            REVERT UNAUTHORIZED
accountant.updatePayoutAddress(attacker) by 0x9ec2      REVERT UNAUTHORIZED
teller.setShareLockPeriod(0) by 0x9ec2                  REVERT UNAUTHORIZED
teller.addChain(eid=30101, …, target=attacker) by 0x9ec2 REVERT
```

---

## 6. Scripting pitfalls that cost time (all lint/runtime, all fixable)

| Symptom | Cause | Fix |
|---|---|---|
| `f-string expression part cannot include a backslash` | Python < 3.12 f-string rule | extract to a variable: `dec = bytes.fromhex(...).rstrip(b"\x00").decode(...)` |
| `TypeError: can only concatenate str (not bytes) to str` | `raw[0:32][-40:]` is `bytes` | `"0x" + raw[12:32].hex()` |
| `unsupported format string passed to NoneType.__format__` | a reverted `eth_call` returned `None` | guard with `v if v is not None else 'ERR'` |
| `keccak(hex(4))` → `TypeError` | `eth_utils.keccak` needs bytes/int | `base_int.to_bytes(32, "big")` |
| Pyright flags `sys.stdout.reconfigure` | `TextIO` annotation | use `python -u` or `flush=True` instead |
| `eth_getLogs` over 4.3M blocks never returns | unbounded sweep on a busy token | bound to the deployment block, chunk ~6,000 |
| `post_nav / post_supply` → 0 | integer division without scaling | `(post_nav * 10**18) // post_supply` |

⚠️ **After fixing any of these, re-run the script into the SAME evidence path.** A stale `.out` that
still shows the pre-fix number is worse than no file at all: the next session greps `evidence/`,
finds the bogus figure, and trusts it over the corrected report. This session's `r5f.out` still
showed the −100% round-trip after the script had been fixed and the report updated to −1 wei.

Quarantine protocol for a run you cannot trust — rename, don't delete:

```
mv r4v.out r4v.out.BUGGY_DO_NOT_CITE      # the run is wrong
# then write r4v.out.SUPERSEDED naming the defect + the authoritative file
```

Deleting loses the audit trail; leaving it unnamed invites a miscite. Then publish an
**"Evidence integrity notes"** section in the final report listing every traceback'd or superseded
file, its crash line, and whether any quoted number depends on it. A traceback at the *end* of a
file is usually harmless — the numbers above it printed before the crash — but say so explicitly
rather than leaving the triager to guess.

---

## 7. The one-line lesson

**A finding is not finished when you have evidence it exists. It is finished when you have the
arithmetic that says whether it can be profited from.** Publish both the divergence and the
round-trip; publish both the fee cap and the waterfall; publish both the relay gap and the four
reasons it is not a theft chain. That is what separates a report a triager acts on from one they
close as informational.
