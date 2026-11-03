# DeFi / Solidity invariant hunting — fund-theft invariants

Companion to `readonly-security-audit` for the smart-contract case: source already on disk,
read-only, deliverable is a findings file with file:line evidence and a per-invariant verdict.
Worked reference case: Royco tranche/market ("Day" v2 kernel) audit, 2026-10-22.

The single most important mindset shift vs a web audit: **most fund-theft invariants in a
well-built protocol are structurally dead, and proving that is the deliverable.** A confident
"5 HOLDS / 1 REFUTED, here are the two real residual findings and they are not theft" is a
better output than a manufactured HIGH. Never inflate a quote bug into a drain.

---

## Step 0 — map the real architecture before reading any math

Directory names lie. Before testing anything, establish which contract actually holds the
pricing/burn authority:

```bash
find <dir> -name "*.sol" -not -path "*/lib/*" -not -path "*/node_modules/*" | xargs wc -l | sort -n
grep -rn "function <entrypoint>" --include=*.sol --exclude-dir={lib,node_modules} .
```

In the Royco case the tranche seam looked like ERC4626 but only did
`safeTransferFrom(msg.sender -> kernel)` then forwarded to `kernel.inkindDeposit()`
(`RoycoVaultTranche.sol:67-78`). **All pricing lived in the kernel** (`DepositLogic.sol:75`).
Analysing the seam's `convertToShares` as if it were the mint authority would have produced a
completely wrong report — the view is not the authority, and the two can disagree (see
"conservative side" below).

Always answer: *which function actually mints? which actually transfers out?*

---

## Structural-refutation checklist (run this FIRST — it kills whole bug classes)

| Architecture property | What it makes impossible | How to verify |
|---|---|---|
| NAV derived from **storage ledger** (`$.totalCollateralAssets`), not `IERC20.balanceOf` | Donation / first-depositor inflation — a raw token transfer cannot move the price | `grep -n "_getCollateralNAV\|totalCollateralAssets"`; confirm NAV reads the ledger var and the var only moves in `_creditAssets`/`_debitAssets` |
| Pollution-resistant: `require(collateralNAV == stEff + jtEff)` as a **hard revert on every sync** | Share-count theft, over-withdrawal, mis-attributed loss — any imbalance reverts | find the `require(... NAV_CONSERVATION ...)` and confirm it is in BOTH pre-op and post-op sync |
| Pre-op sync runs **inside the same tx** as the redeem | "Exit after loss is known but before it is socialised" — there is no window | trace redeem → `preOpSync...` → waterfall, confirm all in one call frame |
| Per-operation post-op state requires (`deltaCollateralNAV < 0 && deltaLPTRawNAV == 0` …) | Ops that quietly move value between ledgers | read the `if (_op == Operation.X)` block in `postOpSync` |
| Virtual shares/value offset present | Naive inflation attack | note the MAGNITUDE: `VIRTUAL_SHARES = 1, VIRTUAL_VALUE = 1` is a 1-wei offset, not 1e18 — fine when NAV can't be donated into, weaker otherwise. State which regime you are in. |
| Redemption output == debited ledger == transferred amount | Skim between "computed" and "sent" | compare `_scaleAssetClaims` → `_debitAssets` → `_remitClaims` field by field |
| Shared-custody pool: transfer-out ≤ amount just minted/redeemed | Async entry points that custody user assets AND pay out the same token are a drain target | check `sharesAtExecutionTime = tranche.deposit(..., address(this))` then verify every subsequent transfer sums to ≤ that |

If a project has the conservation `require` + ledger-based NAV + atomic pre-op sync, say so
explicitly and up front. That is the finding.

---

## Invariant families (test in this order, stop at one solid BROKEN)

1. **Share accounting.** `convertToShares`/`convertToAssets` rounding direction on BOTH legs.
   Mint must floor; redeem must floor; every component of the scaled claim must floor.
   Verify by reading the `Math.Rounding.X` argument at each call site, not by reading the
   docstring.
2. **Loss allocation.** Is loss applied at claim time or accrued continuously? Look for a
   lockup/epoch/withdrawal-queue path that skips it. Loss waterfalls need: junior-first,
   residual to senior, conservation re-checked after.
3. **Fund-movement authority.** For each function that moves value out: exact `msg.sender`
   check, and whether refunds read from **storage** or from **calldata**. `cancelX(Struct calldata)`
   is only safe if it hashes the full calldata and looks the hash up (Royco `:544,547-553`);
   a refund computed from calldata fields is a drain.
4. **Fee accounting.** double-claim (is there a `delete` before transfer?), non-owner claim
   (keyed on `msg.sender`?), and the setter bound (see config-bound class).
5. **Points/reward entitlement.** two `award` overloads — the one taking `(to, amount, ip)`
   needs `msg.sender == hub && allowedIPs[ip]`, not just the caller check.
6. **Whitelist/registry access control.** `addAllowedVault`/`addAllowedIP`/`registerTemplate`
   — `onlyOwner`/`restricted` is the whole answer; say so and move on.

---

## The "conservative side" discriminator — quote bug vs actual theft

The highest-value judgement call in this class. When a view function disagrees with the
execution path, **work out which side the user loses on**:

- If execution gives the user *less* than the view promises (or redeems *less*), it is a
  **quote/integration bug** (MEDIUM at worst, ERC4626-compliance), not theft. Show the
  arithmetic resolves to fair value: `95.238 shares × 1.05 NAV/share = 100 deposited`.
- If execution gives the user *more* than the view, or more than their pro-rata claim, it is
  real.

Royco worked example (`RoycoVaultTranche.sol:140-144,162` vs `AssetLedgerLogic.sol:53-58`):
the LPT view uses `lptRawNAV` while execution uses `lptEffectiveNAV` (raw + idle premium).
100e18 deposit quoted **100.000000e18** shares, executed **95.011876e18** (−4.9881%) when 50e18
idle premium existed. Conservative side → classified MEDIUM, explicitly *not* fund theft.

> **Correction (2026-10-22, Balancer-venue run).** An earlier version of this file stated
> "95.238095e18, 4.76% gap" — that number was **wrong**. Recomputed from source:
> `lptEffectiveNAV = lptRawNAV + _convertToValue(lptOwnedSTShares, stTotalSupply, stEffectiveNAV, Floor)`
> = `1000e18 + (1050e18+1)*50e18/(1000e18+1)` = `1049.999999999999999999e18` (**not** `1050e18`),
> so execution mints `(1000e18+1)*100e18/(1049.999999999999999999e18+1)` = **95.011876e18**
> and the gap is **4.9881%**. The original finding (MEDIUM integration bug, not theft) stands;
> only the arithmetic changed. **Recompute inherited numbers — never copy them forward.**

Quantify every quote divergence with a concrete number. "Mismatch" without an arithmetic
example is not a finding. And add the **counterfactual block**: state what the user *would* have
extracted if the divergence ran the other way (here: if the view's 100.000000e18 shares had been
minted, the depositor would have taken **+4.7727 NAV per 100 NAV deposited**, 4.77% of existing
LPT holders' value). A number for "what a real bug is worth" is what makes the REFUTED verdict
land. The full worked procedure lives in `references/amm-venue-quote-vs-execution.md`.

---

## Config-bound class (`MAX_*_WAD = 1e18`)

A setter bound of `1e18` is a 100% bound, not a safety bound. Check what the fee is levied on:

- `fee = gain.mulDiv(feeWAD, WAD)` → 100% of **yield**. Principal untouched → **LOW / parameter
  risk**, report the recommendation (cap ~20%) but do not call it fund theft.
- `fee` levied on transferred principal, or `setFee` after deposits without a sync → that IS
  a break.

Also check the setter is `restricted`/`onlyOwner` — if it is, it is a trust assumption, not an
attacker path. Say which.

---

## On-chain harness (real numbers, no fabrication)

Prefer the target's own RPC proxy if it exposes one — it is the path of least resistance and
still read-only:

```bash
curl -s -X POST https://app.royco.org/api/rpc/1 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'

# ERC20 balanceOf(address) selector = 0x70a08231 + 32-byte left-padded address
curl -s -X POST https://app.royco.org/api/rpc/1 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"<token>","data":"0x70a08231000000000000000000000000<addr>"},"latest"]}'
```

Always pin the block number in the report and decode the hex to a human number yourself
(`0x263ec = 156,652`). Also `eth_getCode` non-empty to prove the contract is live.

For product TVL, the project's own explore endpoints beat marketing copy: `POST
/api/v1/vault/explore` and `/api/v1/market/explore` with `origin: https://app.royco.org`
return `tvlUsd` per market. **Value-at-risk caps severity** — a $129k TVL deflates a headline
"$3.1B all-time volume" claim and should be stated plainly so the reader can prioritise.

### Public RPC endpoints — probe before you commit

Availability changes; probe with `eth_blockNumber` first and rotate. Observed 2026-10-22:

| Endpoint | Result |
|---|---|
| `https://eth.llamarpc.com` | HTTP **525** |
| `https://rpc.ankr.com/eth` | "Unauthorized: You must authenticate your request with an API key" |
| `https://ethereum-rpc.publicnode.com` | **works** |
| the project's own RPC proxy (`POST https://app.royco.org/api/rpc/1`) | **works**, same block height as publicnode → use as a cross-check source |

`scripts/readonly_chain.py` in this skill does the rotation + backoff for you (stdlib +
`eth_abi`/`eth_utils`, no `web3` dependency; it never signs or broadcasts).

### The money trail — resolve it before you call anything insolvent

The most embarrassing false positive available in this class of audit is
**"the API says TVL $48,610 but the vault only holds $156"**. That headline is a hypothesis, not a
finding, and it is usually wrong.

Resolve it in four steps:

1. **Sweep every contract in the trust graph**, not just the vault. For each address the app/API
   exposes (vault, accountant, hook/teller, safe, solver, any proxy) call `balanceOf` on the asset.
   Then **sweep the asset's `Transfer` logs** for the vault as `from`/`to`, summed per counterparty —
   that surfaces holders the API never names.
2. **Fingerprint every top counterparty** before interpreting it:
   `GET /api/v2/smart-contracts/{addr}` → `name`, `file_path`, `implementations`. A big balance in a
   contract you do not recognise is normally a **third-party escrow** (Circle CCTP `TokenDeposit`,
   Stargate pool, a market), not a protocol bug. Blockscout also lists balances for you directly:
   `GET /api/v2/addresses/{addr}/tokens`.
3. **Publish a backing ratio, not a headline**:
   `backing = (Σ USDC across all trust-graph contracts) / (totalSupply × accountant.getRate())`.
   State the residual and attribute it (bridge-in-flight), labelling the attribution as such.
4. **Close the drain surface** with `eth_call` simulations as an unprivileged caller
   (`withdraw`/`sweep`/`transfer` all reverting = not an open drain).

Worked example (Royco USDC vault `0x74d1`, 2026-10-22): vault held $156.65, `boringSafe`/teller/
accountant all held **0**, and the Transfer-log sweep put **$46,635.66 (95.93%)** in `0xa1e2481a`,
an `ERC1967Proxy` whose implementation is Circle CCTP `TokenDeposit`. Backing ratio **95.927424%**,
residual $1,979.91 attributable to bridge-in-flight. All unprivileged drain simulations reverted.
Full transcript: `references/money-trail-resolution.md` in the `onchain-protocol-audit` skill.

Two corollaries that also belong in the report:

- **A `DepositForBurn`-style signature returning 0 events is positive refutation evidence** for a
  hypothesised money path — record it as a refutation, not a gap.
- **Events are history, not current state.** A capability granted in an old
  `RoleCapabilityUpdated` event may be revoked now. Try current-state getters (`canCall`,
  `doesUserHaveRole`) before reporting role abuse; if they revert, label the map historical and the
  live capability set UNKNOWN. Related: if a selector present in the *verified source* reverts on
  live state, and the bytecode size / `PUSH32` constants / mapping-slot scan do not match the source
  either, the deployed code may not be the verified source — do not build a finding on that source.

### `eth_getLogs`: discover topic0, do NOT guess signatures

Filtering `eth_getLogs` by a topic0 you computed from a hand-written canonical signature usually
returns **zero** for long/struct-bearing events — the canonical string carries structs, enums and
nested tuples, and one wrong token means no match. The reliable sequence:

1. Pull **all** logs from the address over a recent block range with `topics: []`.
2. Collect the **distinct topic0 values** observed.
3. *Then* test candidate signature strings against that observed set.

In the Royco Balancer-V3 run every guessed signature returned 0 logs; the observed-topic0
discovery step is what produced the correct `PoolRegistered` / `LiquidityAdded` hashes.

### Finding the deployed contract when the source dump has no address

`_meta.json` carries no address, so mapping `src/<Name>/` to a live contract needs another route:
the project's own explore API, the factory's `trancheToKernel(address)` / `getMarket(address)`
view functions, or `eth_getLogs` on the factory for a deployment event. **Budget this** — see
minimum discipline #8 in SKILL.md. Front-load the source-level analysis; treat live addresses as
an enhancement for the questions that genuinely need live state (fee drag, pool balances).

---

## Source-dump gotchas (Blockscout verified dumps)

- `_meta.json` carries `name`, `compiler_version`, `proxy_type`, `implementations`, `is_verified`
  — but **no `address`**. You therefore cannot map `src/<Name>/` to a deployed address, so
  **bytecode-vs-source diff is UNTESTED**. Say that; do not imply you verified deployment.
- Some dirs embed the address (`BoringVault_0x74d1`), most do not. Check the dir name before
  assuming you have a handle.
- `proxy_type: null` + `implementations: []` means the dump is a bare implementation, not the
  live proxy — another reason live-state claims need a separate address source.
- Version-pin check: `compiler_version` per tree (`v0.8.35` for the tranche stack, `0.8.27`
  for the older hub) tells you which trees are one system. Mixed versions across dirs = two
  product generations coexisting; do not audit them as one.

---

## Report shape that landed

Markdown file, written **incrementally** (see the draft-first/append variant in SKILL.md —
the user mandated "append after every N tool calls, never only at the end"). Sections:

1. Header: scope, source provenance (`is_verified: true`, compiler), RPC + block number proving
   read-only live access.
2. Architecture map table — "which file actually holds pricing/authority". This is what stops
   you auditing the wrong layer.
3. **Invariant table**: `# | invariant | verdict | evidence` with verdicts
   **HOLDS / REFUTED / BROKEN / UNTESTED** and file:line in every evidence cell.
4. One section per invariant: the mechanism, then the adversary run ("can X do Y?" → why not,
   with the line that blocks it).
5. Real findings with numbers (F1 MEDIUM quote divergence, F2 LOW config bound).
6. **Value at risk** from real on-chain/API data, with the API figure and the independent
   `eth_call` figure both shown (they differ — say which is which).
7. **"Yang TIDAK teruji"** — explicit UNTESTED table with the reason (no address → no bytecode
   diff; needs live pool state; oracle time-series). Never silently drop scope.
8. Recommendations.

Language: match the request. This user asks for **Indonesian prose with English technical
terms** — keep `mint`, `redeem`, `share`, `sync`, `waterfall`, `coverage utilization` in English
inside Indonesian sentences.

---

## Pitfalls

- **Do not audit the view layer as the authority.** `previewDeposit`/`convertToShares` can be
  pure decoration; find the mint.
- **Do not call a `require`-enforced invariant "untested".** If conservation is a hard revert on
  every path, that is a HOLDS with the line cited — a stronger result than a fuzz you did not run.
- **Do not stop at the first suspicious helper.** `SelfLiquidationLogic` looked like a JT-funded
  bonus leak; reading the post-op accounting (`jtEff -= bonus; stEff -= (W - bonus)`) plus the
  conservation require showed it is exactly neutral. Prove the negative before reporting.
- **Sums must be shown.** Whenever a split happens (receiver + executor bonus, user + protocol
  fee), verify `partA + partB == total`, and that the entry point custodies no other user's
  tokens of that type.
- **A permissionless keeper/executor is not a bug.** Check it is bounded by
  `request.amount >= executedAmount` + a request-time reference, then call it by design.
- Never edit a single file. The deliverable is the report.
