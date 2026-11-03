# Severity triage for a PROVEN theft primitive — "who funds it" decides Critical vs High vs Medium

Condensed from the round that answered the severity-determining question for an already-proven
`RelayExecutor.callResolver` bug (unsigned plan fields let any EOA front-run an oracle-signed
order and keep everything above the victim's signed floor). The bug was proven; the *severity*
was the open question, and it dropped from a claimed **CRITICAL to HIGH** on chain evidence alone.

**Section list:** §0 the rule · §1 the three-candidate funding test (run this first) · §2 why
"burn, no mint" is the whole answer · §3 replay triad · §4 the cap formula · §5 the batch negative ·
§6 assertion traps that make your own tests lie · §7 write-up shape · 
§8 **PROVEN as a gate — the four labels (PROVEN / UNPROVEN-BLOCKED / UNPROVEN-INCONCLUSIVE / REFUTED) and the operator's "no errors, no blockers" bar** · 
§9 **oracle-manipulation briefs: the severity ceiling is set by the consumer, not the oracle**
→ deep method in `oracle-manipulation-refutation.md`.

---

## 9. ORACLE-MANIPULATION BRIEFS — grade the CONSUMER, not the oracle

A price-oracle brief ("prove attacker can manipulate the price used for mint/burn/withdraw") grades
itself with one question asked **before** any gate analysis:

> Does the manipulated price reach the `amount` that mint/burn/withdraw actually uses?

Sweep the consumers first — it costs two greps and fixes the ceiling for the whole engagement:

```bash
grep -rn "resolveUsdPrice\|resolveBidAsk\|IPricingOracle\|IBidAskOracle" --include=*.sol contracts/ \
  | grep -v "<OracleFile>.sol"
grep -n -i "price\|oracle" contracts/<Executor/OracleV2/Hub/Allocator>.sol
```

If the executor returns only `oracle`-as-**signer** (`ORACLE_ROLE`, `isValidSignatureNow`) and zero
`price`, the amount is **attested, not computed** and the vector is refuted in one paragraph.
Everything else is a planner: consumers whose only effect is *how much budget is debited* (rate
limiter) or *how big the fee is* (bps calculator) cap the grade at LOW/role-only regardless of how
manipulable the price is.

Two traps that manufacture false Criticals, both hit this session:

1. **`MAX_*_UPPER_BOUND` is a configuration ceiling, not the enforced value.** Read three things and
   quote the *storage* one as production: the constant (e.g. 300), the per-route storage
   (`feedRoutes(id).maxAgeSeconds` → **30**), and any second per-provider cap
   (`providerMaxFutureSeconds` → **12**). Reporting the constant as live is a self-inflicted FP.
2. **Signature verification is usually in the adapter, not the oracle.** The oracle delegates via
   `IPriceFeedAdapter(adapter).decodeAndVerify(feedId, updateData)` where `updateData` comes from a
   **precompile**, not a caller parameter, and the adapter gates `onlyOracle`. So "the oracle doesn't
   verify signatures" is not a finding.

Also read the consumer's *arithmetic* before assigning severity: a limiter whose live params are
`rate == capacity == 10000e18` refills to full in one second, so underpricing saves nothing and
overpricing only hits the ceiling sooner — a fully-controlled price there is **economically inert**.

Report shape that worked: per-hypothesis verdict (`GATE-EXISTS` / `ROLE-ONLY` / `REFUTED` /
`DEAD-CODE` / `BLOCKED`) each with file:line or raw hex, plus an explicit `KOREKSI DIRI` block
listing which of your own predictions the evidence overturned. Quantify dead code by line share
("~45% of this 772-line module has zero non-test consumers"), never as a footnote.

---

## 0. THE RULE

> A proven theft primitive is **Critical only if the loss is socialized** — minted from
> nothing, or debited from a shared balance (protocol pool, other users' claims, insurance
> vault). If the attacker can only take value that was already routed through *the victim's own
> order*, the blast radius is per-order and the honest grade is **High**, no matter how
> permissionless or repeatable it is.

Never grade on "how easy is it to call". Grade on **who ends up poorer**. The single question to
answer before writing a severity line:

```
After the exploit, does totalSupply of ANY token INCREASE?
  YES -> a mint path exists        -> insolvency possible -> Critical (verify the mint caller's role!)
  NO, supply decreases or is flat  -> value is MOVED or DESTROYED -> bounded -> High at most
```

Answer it with one forge assertion, not with prose:

```solidity
assertEq(hub.totalSupply(tokenIn), snapA.supplyIn,  "input supply unchanged (no mint)");
assertLe(hub.totalSupply(tokenOut), snapA.supplyOut, "output supply never increases");
assertEq(snapA.supplyOut - hub.totalSupply(tokenOut), MIN_OUT, "exactly the floor was BURNED");
```

`assertLe`/`assertEq` on `totalSupply` is the cheapest severity oracle in the whole audit. It is
also the assertion most often *missing* from an exploit PoC that claims Critical.

---

## 1. THE THREE-CANDIDATE FUNDING TEST

When a PoC shows "victim's guaranteed payout was honoured while attacker kept the surplus",
there are exactly three possible funders. Enumerate them and kill two with measured deltas:

| candidate | what it implies | how to prove/refute |
|---|---|---|
| **(A) protocol mint** — Hub/token mints the payout | shared supply inflation ⇒ everyone's claim dilutes ⇒ **Critical** | `totalSupply` delta of the payout token; plus `grep` the mint's modifier — if `mint` is `onlyRole(OPERATOR_ROLE)` and the exploiting contract holds **no** such role, a mint path is *structurally impossible* |
| **(B) a venue / solver escrow** — pre-funded inventory, or a balance mapping the contract is authorised over | bounded to that inventory ⇒ **High** | balance delta of the venue **and** of an *unrelated* solver account (must be delta 0) |
| **(C) purely off-chain accounting** — nothing moves on-chain, only a record | **Medium** | check whether the settlement path **burns** the amount on-chain; a burn is NOT "purely off-chain" |

Snapshot struct + one helper keeps this readable and re-runnable for every test:

```solidity
struct Snap { uint256 supplyIn; uint256 supplyOut; uint256 exOut; uint256 aliasOut;
              uint256 attackerOut; uint256 victimRecvOut; uint256 venueOut; uint256 otherSolverOut; }
function _snap() internal view returns (Snap memory s);   // 8 balanceOf + 2 totalSupply
```

Then each test = `Snap a = _snap(); _attack(); Snap b = _snap();` and assert deltas. Four tests is
the right size: **no-mint**, **funder identity**, **conservation identity**, **bystander untouched**.

The **conservation identity** is the one that convinces a triager, because it can only pass if you
have accounted for every unit:

```solidity
assertEq(attackerGain + victimCredit + burned, venueSpend, "no value from nowhere");
```
Measured: `31_000e6 + 0 + 999_000e6 == 1_030_000e6` — attacker took the 3% spread, **97% of the
order's value was destroyed**, nothing created.

---

## 2. WHY "BURN, NO MINT" IS THE WHOLE ANSWER

The pattern that produced the downgrade, worth recognising on sight:

```solidity
// finalize: withdraw = post-call balance the executor happens to hold of the OUTPUT id
uint256 withdrawAmount = HUB.balanceOf(address(this), tokenOutId);
if (withdrawAmount < request.outAmountMinimum) revert InsufficientMinimumAmount(...);
_fundSpenderAlias(tokenOutId, withdrawAmount);         // executor -> derived alias
ALLOCATOR.submitWithdrawRequest({... amount: withdrawAmount ...});
// allocator: records payloads[hash] = payload, then
HUB.burn(spenderAlias, tokenId, params.amount);        // alias is a burn-only pass-through
```

Consequences to assert explicitly, because each one flips a severity word:

1. **The spender alias is empty before *and* after** (`balanceOf(alias) == 0` both sides). It is a
   burn pass-through, not an escrow. So "a solver's alias was charged" is not a claim you can make.
2. **The victim's receiver is never credited on-chain** in that currency (`receiverOut delta == 0`).
   The "guaranteed payout" is satisfied by an attestation of an amount that was **already
   destroyed**. Cross-chain the user may or may not be made whole by off-chain treasury — say
   "user receives nothing on-chain", not "user loses nothing".
3. **A zero-amount withdrawal is accepted** whenever the signed floor is `0` (guard is
   `withdraw < floor`, and `0 < 0` is false). Prove it: floor = 0 ⇒ payload amount 0, burn 0,
   attacker takes **100%** of converted output (10_300 bps of input). Then check whether `0` is
   *attacker-reachable* — it lives inside the signed digest, so it is a **signing-policy risk, not
   attacker control**. Grade the risk to the honest path, never the pathological one.
4. **`mint`/`burn` modifier vs. the exploiter's roles.** Grep the token's `mint`: if it is
   `onlyRole(OPERATOR_ROLE)` and the executor/resolver holds only its own `ADMIN_ROLE`/
   `ORACLE_ROLE`, write "*structurally impossible to create supply*" — that sentence is what
   downgrades Critical to High.

---

## 3. REPLAY TRIAD — answer all three, they are different bugs

A digest-keyed `usedRequests[digest]` looks like it closes replay. Verify which *dimensions* it
covers, because the interesting one is always the field the bug is about:

| # | attempt | expected | how to test |
|---|---|---|---|
| Q1 | identical request + identical resolver, twice | `RequestAlreadyExecuted(digest)` | expectRevert on the selector |
| Q2 | identical signed request, **different callResolver / plan** the second time | must ALSO revert — swapping the unbound field must not re-arm | expectRevert with a *different* resolver address and different calldata |
| Q3 | same orderAddress, **new oracle signature (new nonce)** | passes the digest check, then fails on state: `EmptyOrderBalance` — a top-up to the same order address is re-stealable | decode the raw revert data: `0xf99da7c6` = `EmptyOrderBalance(address,uint256)` — confirm with `cast sig "EmptyOrderBalance(address,uint256)"` |

Q2 is the one people forget: it is the exact question "does mutating the unbound field let me run
the same authorisation again?". Prove it with the *fewest* moving parts — reuse the same struct,
change only the resolver argument.

Q3's answer is not "replayable": it is "**one authorisation ⇒ one execution**; repeat losses need
repeat orders". Say it that way, and note when the missing amplification is a *field that is not in
the struct at all* (e.g. no `chainId` in the order struct — the only chainId is in the EIP712
domain, so cross-chain replay needs the same signer + same executor address on another chain, which
is a different finding, not a multiplier).

Also settle the **guard-order** question from the source, it takes 10 seconds and closes the topic:
`usedRequests[digest] = true` is set in `_validateRequest`, the **first** statement of `execute()`,
**before** any transfer. State that line number.

---

## 4. THE CAP FORMULA — write it as arithmetic, not prose

```
attackerNet(order) = quoteOut(input) − max(outAmountMinimum, 0)
victimLoss(order)  = input   (full source balance — the pull is balanceOf, not an amount field)
protocolBurn       = outAmountMinimum
```

Then test the two bounds that determine whether the formula is *attacker-widened*:

- **Is the cap field signed?** Submit a *lowered* `outAmountMinimum` under the original signature →
  must revert (`InvalidSignature`). If it does, the attacker cannot widen its take; the extraction
  is capped at the surplus above the user's own slippage protection — i.e. **exactly what a
  legitimate solver would have earned**. That comparison is the single most useful sentence in the
  report: it tells the triager the honest margin and the theft are the same number.
- **Test a floor of 1 and a floor of 0** and assert the closed form
  (`stolen == quote − keepFor`), so the formula is proven at both ends rather than asserted once.

---

## 5. THE BATCH NEGATIVE — cheap, and it kills the "mega-impact" upgrade

Triage always asks "can one mutation hit N orders?" Settle it in three tests:

1. **Selector/dispatcher probe** — the exploiting contract has exactly one state-changing
   entrypoint (single struct, no array, no `executeBatch`, no Merkle root, no `multicall`). Enumerate
   the selectors you tried and report "no batch/Merkle/multicall selector resolves".
2. **Batch-wrapper test** — `Multicall3.aggregate3` around **two** independently signed `execute()`
   calls: assert `stolen == 2 × (quote − floor)`. Linear, not multiplicative: 2 orders = 2 losses,
   each with its own authorisation.
3. **Signature-reuse test** — one signature submitted against a *different* `orderAddress` →
   revert. This is what proves the digest binds the order, closing the "one signature covers the
   batch" worry.

A clean negative here is worth writing up explicitly; it is the difference between High and a
triager dismissing the report as inflated.

---

## 6. ASSERTION TRAPS — where my own tests lied first

Foundry only tells you what you assert; a wrong *expectation* reads exactly like a broken exploit.
Three that fired in this round, all fixed in one edit:

| trap | symptom | fix |
|---|---|---|
| assumed "supply unchanged" for the token that is **burned** | `assertEq(supplyOut before/after)` failed by exactly `MIN_OUT` | the burn is the *finding* — assert the exact delta (`a − b == amount`) or `assertLe` for "never increases" |
| assumed the victim's receiver is **credited** on-chain | `receiverOut delta` came out `0 != MIN_OUT` | that zero IS the impact statement; assert `== 0` and say "burn-only settlement" |
| assumed which guard fires on a drained order | `vm.expectRevert(EmptyOrderBalance)` → "next call did not revert as expected" | it *did* revert, with different data. Use a low-level `call`, log `ok`/returndata, then decode the 4-byte selector yourself |

The third one generalises into a rule for this whole class: **when you are not certain which guard
trips, do not `expectRevert` on a guessed selector.** Do:

```solidity
(bool ok, bytes memory ret) = address(target).call(abi.encodeWithSelector(...));
emit log_named_string("reverted?", ok ? "NO" : "YES");
emit log_named_bytes("revert data", ret);
// then: cast sig "ErrorName(uint256,address)"  -> compare to the first 4 bytes
```
Ambiguous `expectRevert` also hides *silent success*, which is the failure mode that would otherwise
turn a non-finding into a fake finding.

---

## 7. WRITE-UP SHAPE THAT SURVIVES TRIAGE

Answer the exact question asked, in this order, one line each, before any prose:

1. **Who funds it** — name the candidate you proved and the balance that moved, quoting the delta.
2. **Replay** — "not replayable: one authorisation ⇒ one execution", with the revert selector.
3. **Cap** — the closed-form formula plus the comparison to the honest solver margin.
4. **Amplification** — the explicit negative (no batch, no mint, bystanders untouched).
5. **Grade** — one paragraph: why not Critical (not socialized, supply only decreases, bystander
   delta 0), why not Medium (permissionless, repeatable, near-total per-order loss, victim not
   even credited).

Keep **prose sections and forge output adjacent**: every claim in the artifact should sit directly
above the `[PASS]` line and the printed number that proves it. Write the artifact **incrementally**
(one append per sub-question) — the funding answer is usually enough to fix the grade, and it lands
long before the batch analysis does.

---

## 8. PROVEN IS A GATE, NOT A MOOD — the user's bar, and the four labels that replace "forged"

Cut from a live session where the operator stopped the workflow with:

> *"no, kita tidak akan maju jadi proven ketika belom 100% proven tanpa error maupun blocker"* —
> no, we will not advance to proven while it is not 100% proven, without errors and without blockers.

and earlier: *"di forge proven, ketika mainnet jadi unproven"* — forge-proven is not mainnet-proven.
Both are correct and both must be obeyed literally. Encode it as a **state machine**, not an adjective:

| Label | Requirement (all must hold) |
|---|---|
| **PROVEN** | executed artifact with raw output + **zero errors** + **zero blockers** + every guard passed by the real path. Anything less is one of the three below. |
| **UNPROVEN — BLOCKED** | the primitive is reachable in code, but a specific named gate stops the live path (missing key, unfound storage slot, un-replayable entrypoint). **Must name the gate.** |
| **UNPROVEN — INCONCLUSIVE** | the control/baseline probe itself failed, so the comparison carries no information. (A/B/C matrix where A reverts.) |
| **REFUTED** | a positive control ran and contradicted the hypothesis. Only this one licenses "not a bug". |

Rules that follow mechanically:

1. **A failed baseline is not a refutation.** "A revert ⇒ INCONCLUSIVE" must be printed as that word.
   Saying "only B succeeded" when A also reverted is the single easiest way to fabricate a finding —
   and the operator will ask "did the baseline pass?" immediately.
2. **Never let an unresolved gate be absorbed into a severity word.** If the last hop needs a 2-of-5
   multisig signature, the verdict is *UNPROVEN — requires oracle cooperation*, full stop. Do not
   ship it as HIGH "because the code path exists". This is the difference between §0's honest
   Critical→High downgrade and an inflated claim that dies on the triager's first read.
3. **Bytecode-equal + source-clean ≠ mainnet-proven.** Proof A/C (`live-rpc` §16f) license "the repo
   logic is the deployed logic". They do **not** license "an attacker can do this". The gap is
   exactly the reachability tests of `live-rpc` §18/§19 — run them or label UNPROVEN.
4. **Report the blocker as a first-class deliverable.** A round that ends BLOCKED with a named gate,
   a named missing artifact (e.g. "the Hub balance mapping slot — 20+ derivations returned zero"), and
   a precise next step is a **successful** round. A round that ends with a smoothly written for-Critical
   narrative over an unproven hop is a failure even if every sentence is technically defensible.
5. **When the operator pushes back on a claim, do not defend it — re-grade it.** The correct response
   to *"belum 100%"* is to restate the status as UNPROVEN with the blocker named, in the same message,
   not to add supporting detail. Adding detail reads as advocacy and is the fastest way to lose the
   audit's credibility.

**Never invent the missing probe output to close the gap.** If the storage slot could not be located,
the sentence is "slot not located — reachability UNPROVEN", never a plausible-looking balance delta.
A fabricated number that happens to look right is the one failure no later round can repair.

