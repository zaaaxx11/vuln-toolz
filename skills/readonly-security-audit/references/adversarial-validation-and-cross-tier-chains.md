# Adversarial validation of prior findings + cross-tier chain hunting

Companion to `readonly-security-audit` (initial audit) and `defi-invariant-hunting.md` (invariant
hunting). This is the **third stage**: a brief that says *"you are the ADVERSARY, try to KILL these
existing findings, and find the one missing link between them."*

Worked reference case: Royco (app.royco.org + Royco Day tranche stack), 2026-10-22.

---

## 1. The brief shape and the verdict vocabulary

A stage-3 brief names **existing finding files** (not source), and asks for per-finding verdicts plus a
chain verdict. Use a DIFFERENT vocabulary from stage 1 or stage 2 — mixing them is how a stage-3 report
gets misread as a fresh audit:

| Verdict | Meaning | Must be paired with |
|---|---|---|
| **SURVIVES** | adversary attack ran and failed to break it | the exact attack that failed |
| **WEAKENED** | the finding is real but the impact/severity is smaller than reported | the reduced number |
| **REFUTED** | the adversary broke the finding's premise — it is not a bug | the evidence that kills it |
| **EXPLOITABLE / NOT EXPLOITABLE** | for the cross-tier chain | the exact step where it breaks |

Never let a stage-3 report restate the stage-1 finding as if newly discovered. The question is
**"can I kill this?"**, so the report body is dominated by *attacks attempted and why they failed*.

---

## 2. The three kill-tests for a quote-divergence finding (F1 archetype)

A view function uses NAV basis A while execution uses basis B. Stage 1 concluded "conservative side →
MEDIUM integration bug". To kill it, run these three, in order:

1. **Third-party arbitrage.** Can someone who is *not* the depositor capture the gap? Requires a
   two-sided market: does the divergence create a price at which one side of the same asset trades
   below fair value? Test by asking: is the divergent basis *observable and actionable* by a third
   party, or is it purely a per-user quote mismatch that nets to zero at execution?
   → If the gap only moves *the depositor's own share count* and the shares are worth exactly what
   was deposited at the post-deposit price, there is no third-party arb. **Refutation arithmetic**:
   `95.238095e18 shares × 1.05 NAV/share = 100.000000e18` — the depositor is made whole.
2. **Same-user round-trip.** Deposit into tranche X, immediately exit via tranche Y in the same market.
   Compute the round-trip P&L with real numbers. If the round trip returns ≈ the deposit minus
   rounding dust, there is no extraction.
3. **Design-vs-defect.** Is the divergent term an **owner-set, market-specific parameter** (the
   protocol's idle-liquidity premium, a per-market yield-share cap) rather than a hardcoded
   constant? If the divergent component is the *point* of the market design, then the "bug" is a
   documentation gap, not a defect.
   → Evidence to look for in source: the term is computed from `$.maxLPTYieldShareWAD` /
   `$.minLiquidityWAD` (owner-settable via `restricted` setters) rather than a constant. In the
   Royco case the LPT premium is `lptLiquidityPremium = stGain.mulDiv(_twLPTYieldShareAccruedWAD, …)`
   — driven by `maxLPTYieldShareWAD` + a YDM `previewYieldShare(...)`, both owner-configured per market.
   → Also check the **analogue parameter in the product API**: `POST /api/v1/market/explore` returned
   `frontendFee: "40000000000000000"` (4%, per-market, owner-set) — the same "owner-set fee" idiom.
   That is the strongest "this is market design" evidence available.

**Verdict discipline:** a quote divergence that is (a) conservative-sided, (b) not third-party-
arbitrable, (c) not same-user-profitable, (d) driven by an owner-set parameter ⇒ **WEAKENED** to
"integration/ERC4626-compliance surface", and explicitly **not** a fund-theft invariant break.
Do not upgrade it back to MEDIUM because the percentage is large — state the percentage AND that the
absolute value at risk is the round-trip dust, not the gap.

---

## 3. The kill-test for a config-bound finding (F2 archetype)

`MAX_PROTOCOL_FEE_WAD = 1e18` looks like "fee can be 100%". The adversary must answer **whose money**.

Read the waterfall and write the **precise order**, in order, with line numbers:

```
RoycoDayAccountant._previewSyncTrancheAccounting (RoycoDayAccountant.sol:389-526)

 LOSS branch (:418-433)
   loss = lastCollateralNAV - collateralNAV
   jtImpermanentLossIncurred = min(loss, jtEffectiveNAV)   -> JT absorbs first
   residual loss                                          -> stEffectiveNAV -= loss
 GAIN branch (:434-522)
   gain = collateralNAV - lastCollateralNAV
   :440  repay JT impermanent loss FIRST  (restoration, never fee-bearing)
   :453  stGain = gain * stEffectiveNAV / lastCollateralNAV ;  jtGain = gain - stGain
   :459  jtProtocolFee = jtGain * jtProtocolFeeWAD / WAD      <- fee on JT's YIELD
   :495  jtRiskPremium     = stGain * twJTYieldShareWAD / (elapsed*WAD)
   :496  lptLiquidityPremium= stGain * twLPTYieldShareWAD/(elapsed*WAD)
   :503  jtProtocolFee     += jtRiskPremium * jtYieldShareProtocolFeeWAD / WAD
   :512  lptProtocolFee     = lptLiquidityPremium * lptYieldShareProtocolFeeWAD / WAD
   :517  stProtocolFee      = stGain * stProtocolFeeWAD / WAD   <- fee on SENIOR's YIELD
   :526  require(collateralNAV == stEffectiveNAV + jtEffectiveNAV)
```

Answers this yields, all citable:
- The fee is computed on **gain / premium legs only**. Principal (`lastCollateralNAV`) is never
  multiplied by the fee. ⇒ **100% fee takes 100% of YIELD, never principal.**
- `stProtocolFee` is charged on **senior** yield, `jtProtocolFee` on **junior** yield, and the
  yield-share fee on the **premium that flows ST→JT / ST→LPT**. So "whose yield" depends on which
  setter: senior yield / junior yield / the risk premium / the liquidity premium. Name all four.
- ⇒ **privileged-config risk, not a fund-theft invariant break.** Say that sentence explicitly.
- **Max USD at risk** = the *yield*, not the TVL. Bound it as (measured TVL) × (max plausible APY),
  not as TVL. With TVL ≈ $48,610 (Royco USDC vault, `tvlUsd` from `POST /api/v1/vault/explore`) and
  even a 100% APY, the fee-at-100% steals ≈ **$48.6k/yr** of yield, while the *principal* $48.6k is
  untouchable. Give both numbers — the ratio is the argument.
- **Can it actually be set to 1e18?** Grep the whole tree, not just the constant:
  `grep -rn "MAX_PROTOCOL_FEE_WAD\|ProtocolFeeWAD" src/` — the constant is **duplicated in more than
  one tree** (RoycoDayAccountant + RoycoJuniorTranche both define `MAX_PROTOCOL_FEE_WAD = 1e18`), so a
  fix must touch every copy. Then check the setter guard:
  `require(_stProtocolFeeWAD <= MAX_PROTOCOL_FEE_WAD)` ⇒ `1e18 <= 1e18` **passes**. The bound is a
  tautology at the top of the range. Also check for a *second* cap elsewhere (init params, a factory
  validation, an AccessManager role scope) before declaring it settable.

**Access-control detail worth stating:** `restricted` in this codebase is OpenZeppelin
`AccessManagedUpgradeable.restricted` → `_checkCanCall(_msgSender(), _msgData())` — the authority is an
**AccessManager**, i.e. a per-function-selector role grant. So the trust assumption is
"the AccessManager admin can grant `setSeniorTrancheProtocolFee` to itself/a collaborator". Name that.

---

## 4. Cross-tier chain hunting — the actual deliverable

The brief asks for "the one missing link". Build the chain as **numbered steps, each with the evidence
that either carries it forward or kills it**, and state the kill point explicitly.

Candidate handoff points to test (web tier → on-chain tier):

| # | Candidate link | Test | Kill condition |
|---|---|---|---|
| a | unauthenticated RPC forwards `eth_sendRawTransaction` | is there any endpoint that returns a **user-signed payload** (a tx the app asked a user to sign)? | no endpoint returns signed bytes ⇒ nothing to replay |
| b | unauthenticated `/simulate/{addr}` calls RPC with a user-supplied address | does it disclose anything not already public via `/api/v1/position/*`? | response ⊆ public block/balance data ⇒ no new disclosure |
| c | write-on-GET `/api/v1/contract/{chain}/{addr}` creates a DB row | does any other endpoint read that table and serve it back as a trusted record (stored/reflected XSS, poisoned cache)? | the row is only ever read back as `contractName/abi/source` for that same address, and the address is regex-validated ⇒ no reflection |
| d | unbounded `eth_getLogs` | does it expose private/internal event streams beyond `/api/v1/position/*`? | all logs are public chain data ⇒ no new surface |

### The chain-killer that actually worked: **bundle route inventory ≠ live route table**

This is the single highest-value discovery of the whole stage-3 run, and it generalizes:

```bash
# 1. mine BOTH bundle trees for route strings
grep -ohE 'api/v1/[a-zA-Z0-9/_.-]+' js/*.js appjs/*.js | sort -u
```

This surfaced a Day/keeper tier that E_web2 never saw:

```
api/v1/day/preview/deposit        api/v1/day/preview/redeem
api/v1/day/request/transaction   api/v1/day/transaction
api/v1/day/requests/eligibility  api/v1/day/route-quote
api/v1/day/acquisition/*          api/v1/day/market/{chainId}/{addr}
api/v1/keeper/queue /pending /signers /executors /account/{addr}
api/v1/token/balance/{chain}/{addr}   api/v1/token/allowance/{chain}/{addr}/{owner}
api/v1/ecosystem/explore   api/v1/stats/global   api/v1/feed/market
```

That looks like a huge new attack surface — **it does not exist on the live target**:

```
GET  /api/v1/day/market/1/0xdc4e…6db                 -> 404 Cannot GET …
POST /api/v1/day/preview/deposit                      -> 404
GET  /api/v1/keeper/status                            -> 404
GET  /api/v1/token/balance/1/0x74d1…5cc               -> 404
GET  /api/v1/openapi/json                             -> 404
```
(same 404 body on `api.royco.org` directly ⇒ identical route table on both hosts).

**Why it 404s:** the `js/` tree is a **newer build than the deployed backend**. The bundle is a
*hypothesis generator*, never evidence of a live route. **Always verify each bundle-mined path with
one live request before it enters a chain.** And note the production consequence: the Day tranche
system that F1/F2 live in is **contract-only, not wired to the web tier** — so no web→on-chain handoff
exists for the very findings under attack. That fact alone kills the entire chain.

**Corollary for chain hunting:** the strongest "missing link" result is frequently a **negative**
("the tier that would carry the link is not deployed"), and that is a legitimate, well-evidenced
deliverable. Write it as `NOT EXPLOITABLE — the link does not exist at step N` with the 404 evidence.

---

## 5. On-chain address discovery when the source dump has no address

`_meta.json` in Blockscout-style dumps carries `address_hash` **only for proxy trees**. That is
enough to bootstrap live reads:

```
RoycoEntryPointProxy/_meta.json:10  "address_hash": "0xf30adF306d453e638785a2319dcE43E110F8E720"
RoycoFactoryProxy/_meta.json:10      "address_hash": "0x3E051925bdeFBAC937119BB064510ed4C863E532"
```
The `constructor_args` of those proxies also embed the implementation address
(`RoycoDayBalancerV3Kernel/_meta.json: "0x…ba1333333333a1ba1108e8412f11850a5c319ba9"`).

Useful selectors (compute with `keccak(text=sig)[:4]`):

| Signature | Selector |
|---|---|
| `kernel()` | `0xd4aae0c4` |
| `accountant()` | `0x4fb3ccc5` |
| `seniorTranche()` | `0xa639d0dc` |
| `juniorTranche()` | `0x86d4779e` |
| `liquidityProviderTranche()` | `0x2ce9dcab` |
| `collateralAsset()` | `0xaabaecd6` |
| `lptAsset()` | `0xdb51ac49` |
| `convertCollateralAssetsToValue(uint256)` | `0x70d2f51b` |
| `convertLPTAssetsToValue(uint256)` | `0x588fe437` |
| `totalCollateralAssets()` | `0xe7531781` |
| `totalLPTAssets()` | `0x64929632` |
| `lptOwnedSeniorTrancheShares()` | `0xb0c2a3ba` |
| `getState()` | `0x1865c57d` |
| `marketDeployer()` | `0xbb1e4531` |
| `isTemplateEnabled(address)` | `0xb193d2cb` |

**Read config straight out of ERC-7201 storage** when no getter exists — the slot constants are in
source (`bytes32 private constant _ROYCO_DAY_ACCOUNTANT_STORAGE_SLOT = 0x3eb9440b…3200;`), so
`eth_getStorageAt(accountant, slot)` returns the packed struct. Same trick for the kernel
(`0xc366ce7b…fec00`), the tranche (`0xb29e56aa…3900`), the entry point (`0x03bd8d61…ef00`) and the
factory (`0x40ecf137…7500`).

**Expect accessors on AccessManager-gated proxies to revert.** `accountant()`, `kernel()`,
`getState()` on the entry-point proxy and `getTemplates()`/`templates()` on the factory proxy all
returned `{"code":3,"message":"execution reverted"}`, and `marketDeployer()` returned
`0x0000…0000` — the proxy is an AccessManager shell whose target is reached by
`_checkCanCall`-gated dispatch, not by public getters. A revert there is **not** "the contract is
absent"; it is "the public surface is intentionally sealed". Say that, and fall back to
`eth_getStorageAt` / event logs.

---

## 6. The "prove this ISN'T exploitable" self-pass

The brief may ask you to attack your own best chain. Do it explicitly and in writing — it is a
separate deliverable section, and it is what converts "I found a chain" into "here is the chain and
here is exactly where it dies":

For each numbered step, ask: *what is the attacker missing?* Typical answers to look for:
- the signed payload never leaves the user's browser (bundle grep shows `signTransaction` happens in
  the wallet client, `sendRawTransaction` only ever carries the user's own signature);
- the disclosed field is already public chain data;
- the written row is never reflected into a trusted field;
- the tier that would carry the link is not deployed (404).

---

## 7. Tool-call budget discipline (learned the hard way)

A stage-3 brief is 4 sub-goals × (adversary attack + live numbers + verdict) and will exceed a
50-iteration cap if you spend the budget on discovery. Rules that keep it alive:

- **Front-load the report skeleton.** Write the file with the verdict table and `PENDING` markers
  BEFORE any probing, then append. (See the draft-first/append variant in SKILL.md.)
- **≤8 tool calls per finding** before you must have a verdict line written for it. A verdict with
  partial evidence beats no verdict.
- **Append after every ~5 tool calls**, not at the end — a stage-3 session that times out with the
  file unwritten is a total loss, and the partial evidence trail is worth more than a perfect report.
- **Batch independent live probes into ONE python script** (one `write_file`, one `terminal` run) —
  a 10-endpoint survey script is 2 tool calls instead of 20. This is the single biggest lever.
- Keep a small reusable harness module (`pace()` at 1 req/s, `rpc()`, `api()`, `apicall()`) so each
  new script is ~15 lines instead of re-implementing HTTP + pacing.
- Reserve the **last ~4 tool calls** for the final verdict table + summary.

### Honour an explicit question-priority order literally

When the brief says "prioritise (f) first — it can kill the whole chain", that ordering IS the
budget plan. Read the post-action path and the guard sites **before** any formula reconstruction or
impact analysis. A chain killed by a guard found on call 3 saves the entire remaining budget; a
beautifully derived formula for a chain that was already dead is wasted work. Resist the pull of the
interesting analysis — the kill-test is the highest-value call in the session.

Concretely (current.finance R3, 2026-10-28): the brief ordered (f) → (c) → (vi). Answering in that
order meant the "no post-seizure guard" verdict landed early, which reframed (c) and (vi) from
"build the exploit" to "bound the exploit" — a materially different and more honest report.

### Report-skeleton contract when the user mandates it

If the brief specifies the exact section list (e.g. `VULNERABILITY/ENTRY/CHAIN/IMPACT/POC/EVIDENCE/
CONFIDENCE/MITIGATION/VERIFICATION + claim-vs-proof table + REFUTED + UNTESTED`), reproduce those
headers verbatim as the skeleton, initialise every claim row to `UNVERIFIED`, and flip rows to
`CONFIRMED`/`REFUTED` as evidence lands rather than at the end. Add a short `## VERDICT` at the top
and update it live so a reader opening the file mid-session sees the current answer. Verify the file
landed (grep the target dir for a sentinel) before reporting done.

### Move/Sui bytecode targets: borrow the formula method

For a Sui/Move target the same stage-3 discipline applies, plus the bytecode-specific technique —
reconstructing a seize/price formula as an instruction-by-instruction accumulator table, bounding a
parameter at both its construction and its read site, and separating a **quantity clamp** from a
**value cap** from a **state assert** when answering "is there a post-seizure guard". That method
lives in `onchain-protocol-audit` → `references/move-defi-audit-patterns.md`. Load it whenever the
target is `.move` disassembly rather than Solidity.

Pitfall: a `terminal` heredoc `cat >> F.md <<'EOF' … EOF` is fine **unless** the body contains `&`
(the foreground guard reads it as backgrounding and rejects the whole command) or a scan regex with
`@`/`\-` (security scanner rejects it). When in doubt, write the section with `write_file` to a temp
file and append it with a python one-liner.

---

## 8. Language and shape

Match the brief's language. For this Royco brief the deliverable was written in **English with the
technical nouns preserved** (`view`, `execution`, `waterfall`, `protocol fee`, `round-trip P&L`),
tables for verdicts, and **every number accompanied by the command that produced it** — the brief
demanded "Include every command you ran and its raw output for each number. Numbers must be real,
not estimates." Honor that literally: paste the raw `eth_call` hex and the decoded value, the raw
HTTP status + byte length, and the wall time.

Final section shape for a stage-3 report:

1. Header: role, mandate (read-only, no broadcast), date, live block number pinned.
2. Baseline established (RPC block, target identity proof via `eth_getCode` + `name()/symbol()`).
3. §1 API surface reality-check (bundle vs live route table).
4. §2 F1 — attack attempts, the three kill-tests, verdict + evidence.
5. §3 F2 — waterfall order, whose-yield answer, max USD at risk, setter-cap analysis, verdict.
6. §4 The chain — numbered steps, the kill point, `EXPLOITABLE / NOT EXPLOITABLE`.
7. §5 Self-refutation pass.
8. §6 What was NOT tested and why (honest scope).
