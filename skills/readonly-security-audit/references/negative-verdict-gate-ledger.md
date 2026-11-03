# Negative-verdict discipline for fund-theft hunts

How to make "no theft chain exists" an auditable result instead of a shrug. Distilled from the
Gardens v2 multi-round hunt (2026-10-29/30) where 16 chains were analysed, 2 were proven, and the
rest were blocked by real gates.

---

## 1. Build the gate ledger FIRST, not last

When the objective is "find one pre-auth fund-theft chain", enumerate every access-control gate
between an untrusted caller and each fund-moving sink **before** deep-diving any single vector.
Record `gate name → file:line → what it checks`.

Worked example (Gardens v2, 7 gates):

| # | Gate | Checks |
|---|---|---|
| 1 | `checkSenderIsMember` | `votingPowerRegistry.isMember(sender)` |
| 2 | `onlyCouncilSafe` | `msg.sender == registryCommunity.councilSafe()` |
| 3 | `onlyRegistryCommunity` | `msg.sender == registryCommunity` |
| 4 | `onlyStrategyEnabled` | `enabledStrategies[strategy]` |
| 5 | `onlyOwner` | `effectiveOwner()` (factory proxyOwner) |
| 6 | arbitrator binding | `proposal.disputeInfo.disputeId == _disputeID` |
| 7 | Allo pool admin | `msg.sender == community` (attacker cannot become manager) |

Once the ledger exists, every new candidate chain is evaluated in seconds: *which gate does it
cross, and does it actually hold?*

## 2. Record each blocked chain WITH its blocking gate

Sixteen one-line entries cost ten minutes and turn the negative verdict into something a reviewer
can check:

```
CHAIN #5  deactivateMemberInStrategy missing onlyStrategyEnabled
          -> blocked: memberActivatedInStrategies[victim][attackerStrategy] is false,
             and activateMemberInStrategy DOES check onlyStrategyEnabled
```

Do not write "ruled out" without naming the gate. "Ruled out" is unfalsifiable; "blocked by gate
#4 because X" is checkable.

## 3. "Ungated" is a hypothesis, not a finding

An entry point with no access modifier is where the investigation *starts*. Two recurring traps
that turn a promising ungated entry into a dead end:

**(a) A permissionless creator that can only build things it owns is self-penalizing.**
`createPool()` with no modifier looks alarming until you notice the caller can only create pools
inside its own community — that is self-harm and non-eligible under most bounty rules.

The interesting version is when a **parameter** lets the created object bind to *someone else's*
namespace. Concretely: a params struct carrying `registryCommunity` as a caller-supplied field,
assigned verbatim in `initialize()` instead of `address(this)`. That converts "permissionless
self-pool creation" into "pool injection into an arbitrary victim community" — a real finding.
**Always read what the callee does with each caller-supplied address field.**

**(b) A missing guard on one function is often closed by the caller's guard.**
`distribute()` lacking a membership check looks like a hole until you notice it is `onlyAllo` and
the Allo entry point requires `_isPoolAdmin`, where the pool admin is the community contract
itself. Trace the *caller* of any `onlyXxx`-gated function before calling the missing inner guard
a vulnerability.

## 4. Prove an internal gate through a public consumer

When the check you want to demonstrate is `internal` with no public view, find a public function
that reverts on it and assert the revert selector is **anything other than** the gate's error
selector. A revert with a different selector proves the gate passed.

```solidity
(bool ok, bytes memory err) = target.call(abi.encodeWithSignature("someGateConsumer()"));
assertFalse(ok);                                              // it did not succeed outright
assertFalse(err.length >= 4 && bytes4(err) == GATE_SELECTOR); // but not because of the gate
```

**Do not go hunting for a same-named `view` on the wrong contract.** In Gardens v2,
`canExecuteAction(address,address)` lives on the *sybil scorer* (`ISybilScorer`), not on the
strategy — calling it on the strategy returns garbage and fails the assertion. Confirm which
contract actually declares the function before writing the probe.

## 5. Grep for the modifier on the line AFTER the signature

Signature-only greps produce false "ungated" positives:

```solidity
function removeStrategy(address _strategy) public {   // looks ungated
    if (msg.sig == bytes4(0)) revert();
    onlyCouncilSafe();                                 // ← the gate, next line
    _removeStrategy(_strategy);
}
```

Always open the function body before reporting a missing access control.

## 6. Interrupted subagents leave artefacts on disk

Parallel `delegate_task` children that return `status=interrupted` with no summary have often
already written their test/PoC files to the shared repo. **Check the filesystem before
re-dispatching** — one interrupted Architect run in this session still yielded 7 passing forge
tests that became the session's strongest evidence.

When re-dispatching, put the build command in `context` (repo root, full root-relative
`--match-path`) or the child burns its whole budget rediscovering it.

## 7. Report shape for a negative verdict

```
PROVEN:      <finding> — <test name> PASS, <file:line>
BLOCKED:     <chain> — <gate> at <file:line>, because <reason>
NOT REACHED: <area> — <gate> disables it on the production path
OPEN:        <lead> — <what would have to be true>
```

Never collapse BLOCKED and NOT REACHED into "nothing found". The distinction is the difference
between "this is safe" and "this is safe *on the production configuration*".

---

## 8. A minimum-output check is a PRICE FLOOR, not an access gate

Do not ledger `outAmountMinimum` (or any `minAmountOut` / `minReceived` / slippage bound) as a gate
that BLOCKS a chain. It does not gate *access*; it only bounds *quantity*. The distinction decides
whether a finding is reported or wrongly dismissed.

Worked case (HUNT C, Relay Protocol). `RelayExecutor._finalizeWithdraw` asserts
`balanceOf(this, tokenOut) >= outAmountMinimum` and then withdraws **the whole balance**. Ledgering
that as a gate produces "blocked — minimum output enforced", which is wrong on both counts:

- The attacker satisfies it trivially by *paying* the minimum (supply output from own inventory, or
  swap only the covered part), and keeps the difference.
- The loss is therefore **not zero**, it is `netInput − outAmountMinimum` exactly. Measured at two
  points: `minOut` 95% → skim `5e`; `minOut` 1% → skim `99e`.

So when you meet a floor-style check, the ledger entry must be
`BOUNDED (not blocked) — loss = <formula>, attacker chooses the slack`, and you must report which
signed parameter controls the attacker's headroom. A user-signed slippage tolerance is the
attacker's budget; "the user signed it" is not a mitigation, because the user signed a *price*, not
authorisation for 99% of their input to leave.

Corollary for the gate ledger: classify every gate as **access** (identity/permission — blocks),
**state** (one-shot/replay — blocks), or **quantity** (floor/cap — bounds). Only the first two belong
in the BLOCKED column.
