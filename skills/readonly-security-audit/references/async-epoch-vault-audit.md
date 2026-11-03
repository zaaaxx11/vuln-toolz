# Async / epoch-settled vault audits — methodology

Second-generation playbook for auditing vaults where the user does NOT get their
assets synchronously. Two sub-flavours appear in practice and they must not be
confused:

| Flavour | Shape | Where the price is fixed |
|---|---|---|
| **request/nonce** | `requestRedeem(nonce)` -> `executeRedeem(nonce)` | usually REQUEST time (with explicit yield-forfeiture) |
| **epoch/queue** | `redeem()` -> queued in epoch N -> `processEpoch()` -> `claim()` | usually EXECUTE time |

The two have completely different invariants. Read the code and identify which
one you have BEFORE hunting.

---

## Step 1 — find the real state machine; do not assume the task's framing

The task statement (or the interface docstring, or the README) often describes a
`requestDeposit`/`requestRedeem` API that **does not exist in the code**. In this
session the brief asked to trace `requestDeposit -> pending -> executeDeposit`,
but the source had **no such functions**: deposits were synchronous and only
redemptions were queued.

Verification command (always run it):

```bash
grep -rn "function request\|function execute\|function claim\|function process\|function closeEpoch" --include=*.sol <tree>
```

Corollary: **the module named in the brief may not be the driver at all.**
Check the wiring before analysing:

```bash
grep -rn "<TargetContractName>" --include=*.sol <other-tree>/src/ | head
```

If zero hits, the two systems are separate product lines that merely share a
brand name. Say so plainly in the report as a *premise correction* — it changes
which findings belong to the target. (Concretely: a Day-tranche entry point with
`navAtRequestTime` yield-forfeiture was NOT the driver of a Concrete-style async
vault that has no request struct and no nonce at all.)

---

## Step 2 — classify each leg: sync vs async

Build this table first. It reframes every later question.

| Leg | Mechanism | Where |
|---|---|---|
| deposit/mint | sync | parent impl |
| redeem/withdraw | async when `isQueueActive` | override of `_executeWithdraw` |

A vault can be a **hybrid**: deposits land instantly, redemptions queue. The
classic "user deposits then immediately redeems at a stale price" attack does
not apply to a hybrid the way it applies to a fully-async vault.

---

## Step 3 — where is the price captured? (the Q2 question)

Trace the *value* through the state machine and see whether it is PERSISTED or
DISCARDED.

```
redeem(shares, receiver, owner)
  assets := shares * price(requestTime)          <-- computed
  ...
  _executeWithdraw(caller, receiver, owner, assets, shares)
      if (isQueueActive) {
          _transfer(owner, address(this), shares)   // shares parked in the vault
          userEpochRequests[receiver][epoch] += shares
          totalRequestedSharesPerEpoch[epoch] += shares
          return assets                              // <-- the REQUEST-TIME value is DISCARDED
      }
```

If the request-time `assets` is computed, used only for a limit check and an
event, and then dropped — **there is no stored request-time price to redeem
against**. The classic stale-price double-spend is then **structurally dead**,
and the honest verdict is BLOCKED with the line that kills it.

The epoch price is written exactly once, at processing:

```solidity
epochPricePerSharePlusOne[epoch] = sharePrice + 1;   // "+1" so 0 means "unprocessed"
```

and read back as `epochPricePlusOne - 1`.

**Do not confuse "the request recorded an `assets` number" with "the request
recorded a price".** If only a SHARE COUNT is stored, there is no price
reference to hold stale.

Corollary — who bears the move between request and execute?
**Everyone, pro-rata, at the execute-time price.** The requester bears it fully:
they queued shares, and the epoch price is whatever the vault is worth when the
epoch closes. This is a *feature* (no front-running) but it IS a risk that must
be stated with numbers.

---

## Step 4 — rounding direction, exhaustively (the Q3 question)

Enumerate EVERY mulDiv / convert site into a table before judging any of them.
For each: expression, rounding arg, who benefits, correct?

ERC-4626 conventions (these are the *correct* ones, not bugs):
- deposit / previewDeposit / convertToShares -> **Floor** (vault gets the rounding)
- mint / previewMint -> **Ceil**
- withdraw / previewWithdraw -> **Ceil** (on shares)
- redeem / previewRedeem / convertToAssets -> **Floor** (on assets)

Look for:
- **Ceil where Floor is required** -> vault loses (share inflation risk)
- **Floor where Ceil is required** -> user loses (share deflation risk)

A repeatable one-wei-per-call leak needs a *repeatedly callable* path that
rounds in the caller's favour. Check repeatability, not just direction:
`claimWithdrawal` per epoch, `cancelRequest` per request, `processEpoch` per
epoch.

### The subtle one: the epoch price includes the shares being redeemed

If the queue implementation *parks shares in the vault* (transfers them in) and
only burns them later at processing, then at price-computation time:

```
totalSupply  == (shares still owned by LPs) + (shares parked for THIS epoch)
totalAssets  == ledger, not yet reduced
price        = floor( 10**decimals * (totalAssets + 1) / (totalSupply + 1) )
```

More supply in the denominator -> **LOWER price**. So the price is
*conservative for users*, not inflationary. Verify numerically, and assert
`epochPrice <= hypotheticalPriceIfParkedSharesWereExcluded`.

The `+1`/`+1` virtual offset is a **1-wei** offset, not 1e18 — so the vault is
NOT in the naive-inflation-attack regime, but it is also not immune if NAV can
be donated into. Determine which regime you are in and say so.

### Cancels refund shares, not assets

If `cancelRequest` returns SHARES 1:1 (a `_transfer`, not an asset conversion),
then **no rounding asymmetry is possible on the cancel path at all** — the
refund is exact by construction. Check this before writing "the classic
async-vault cancel bug where a cancel refunds slightly less than was deposited".
That bug requires an ASSET-denominated refund with a different rounding than
the deposit. If the refund is share-denominated, REFUTE it with the line.

---

## Step 5 — filling / partial execution (the Q4 question)

Two distinct sub-questions:

(a) **Is the refund rounding symmetric with the original deposit?**
For a share-denominated queue: yes, trivially. For an asset-denominated one:
compare the rounding used at request-fill vs at cancel-refund.

(b) **Is the request-time NAV scaled correctly on a partial fill?**
In nonce-style async vaults the partial fill usually rescales a stored
request-time NAV proportionally:

```solidity
navOfSharesLeftToRedeem = request.navAtRequestTime.mulDiv(sharesLeftToRedeem, request.shares, Floor);
request.navAtRequestTime = request.navAtRequestTime - navOfSharesLeftToRedeem;
```

Note this is **Floor on the residual** — the residual keeps the LOWER NAV, so a
partially-filled request loses a hair of its request-time NAV. Check whether the
split is `a + b == original` exactly or whether Floor silently drops dust.

**Cross-epoch move** (`moveRequestToNextEpoch`): moving a request forward must
decrement the old epoch's aggregate and increment the new one, or the epoch
aggregate drifts and `processEpoch` burns/mints against a wrong total.

---

## Step 6 — access control + reentrancy (the Q5 question)

Enumerate EVERY function that moves value out and record its guard:

| Function | Guard | Can a third party act for someone else? |
|---|---|---|
| `claimWithdrawal(epochIDs)` | none (self-scoped) | NO — it reads `userEpochRequests[msg.sender]` |
| `claimWithdrawal(user, epochIDs)` | role | YES but only to the named user |
| `cancelRequest(epochID)` | none (self-scoped) | NO |
| `cancelRequest(user, epochID)` | role | YES but only to the named user |
| `processEpoch()` | role + nonReentrant | n/a |
| `closeEpoch()` | role | n/a |

**A self-scoped `claimWithdrawal` that reads `userEpochRequests[msg.sender]` is
safe from "execute on someone else's request and steal the proceeds"** — there
is no `user` parameter to redirect. State that with the line.

### The role-grant gap to check

Compare what `_initialize` GRANTS against what the privileged functions
REQUIRE. A frequent shape:

```solidity
// StateInitLib
_setRoleAdmin(WITHDRAWAL_MANAGER, WITHDRAWAL_MANAGER_ADMIN);
_setRoleAdmin(WITHDRAWAL_MANAGER_ADMIN, WITHDRAWAL_MANAGER_ADMIN);
_grantRole(WITHDRAWAL_MANAGER_ADMIN, initialVaultManager, sender);
// -> grants the ADMIN of WITHDRAWAL_MANAGER, never WITHDRAWAL_MANAGER itself
```

If `processEpoch` is `onlyRole(WITHDRAWAL_MANAGER)` and nobody was ever granted
that role, the epoch machine cannot advance. If the admin later grants it, the
admin can process epochs at will. Either way, report it — but mark the live
impact **UNTESTED** until you read the live deployment's role table.

### Reentrancy on the request->execute->transfer path

Check whether the asset transfer happens before or after the state write, and
whether the vault has a guard on that specific path. A transfer-out path that
updates the ledger *before* transferring is the safe ordering. If a
`claimWithdrawal`-style function decrements `pastEpochsUnclaimedAssets` AFTER
the transfer, a reentrant token callback could double-claim.

Also check the **`_lockedAssets()` hook**: if the vault subtracts reserved
(`pastEpochsUnclaimedAssets`) from its withdrawable balance, a queued claim must
not be spendable by a concurrent synchronous redeem.

---

## Step 7 — compare against the standard sibling

A standard ERC-4626 sibling (same family, synchronous) is a great oracle: any
guard the sibling has and the async variant lacks is a lead. Concretely diff:

- does the sibling subtract reserved amounts before computing maxWithdraw?
- does the sibling burn before transferring? (and does the async one?)
- does the sibling have `nonReentrant` on every state-changing entry point?
- does the sibling have a `require(balance >= locked)` on allocate?

And the reverse: **the async variant's extra machinery can introduce bugs the
sibling has no analogue for** (epoch aggregates, price storage, claim
accounting). Absence of a guard in the sibling is not evidence of a bug in the
async variant.

---

## Reporting shape for this class

- Lead with the **premise correction** if the brief's stated flow differs from
  the code. It changes which findings belong to the target.
- Give the exact state-machine trace with `file:line` for every hop.
- Give a **rounding table** (every site) — reviewers trust the table, not prose.
- For each hypothesis: verdict + the arithmetic that killed it. Keep REFUTED
  hypotheses in the report with their arithmetic; do not silently drop them.
- State the **settlement-price regime** plainly: request-time vs execute-time,
  and who bears the move.
- If the live deployment address is unknown, mark deployment-dependent claims
  UNTESTED with the reason — do not imply you verified deployment.
