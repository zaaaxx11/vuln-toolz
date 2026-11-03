# Multi-agent Foundry verification rounds — harness-role discipline

Companion to `readonly-security-audit`, `references/defi-invariant-hunting.md` and
`references/auditor-tester-phase.md`. Use when the brief says: **"you are AGENT N — RED-TEAMER,
attack these N invariants with REAL Foundry tests, report pass/fail honestly, append per claim,
don't claim an exploit without forge output, print a 20-line summary."**

Worked cases:
- Relay Protocol settlement (RelayHub / RelayExecutor / RelayAllocator / WithdrawGasPayer),
  4 claims, 18 tests, 0 exploit — authorization-gate round, 2026-10-30 (§0–§6).
- Same protocol, HUNT C: BasicCallResolver + RelayExecutor per-order value interception, 6 claim
  files, 35 tests, 65/65 green, 3 proven vectors — value-flow round, 2026-10-30 (§7).

---

## 0. The failure mode this reference exists to kill

**In the previous round, 4 tests "failed" because the fixture granted roles to the wrong
address — not because of a bug.** A fixture defect that produces a red test looks exactly like a
finding, and it is the single most expensive error in this class: it burns the round and it
credits a non-existent vulnerability.

Non-negotiable order of operations:

1. Grant every role the harness needs.
2. **Assert each grant** with `assertTrue(hasRole(...), "fixture: <name>")` inside the shared
   `setUp` helper, before any test body runs.
3. Only then write the attack.

```solidity
function _a2SetUp() internal {
  vm.prank(admin); hub.grantRole(hub.OPERATOR_ROLE(), address(allocator));
  vm.prank(admin); hub.grantRole(hub.OPERATOR_ROLE(), address(gasPayer));
  vm.startPrank(admin); executor.grantRole(executor.ORACLE_ROLE(), address(oracle)); vm.stopPrank();

  // Fixture sanity: no conclusion may rest on a broken fixture.
  assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), address(allocator)), "fixture: allocator op");
  assertTrue(executor.hasRole(executor.ORACLE_ROLE(), address(oracle)), "fixture: oracle role");
}
```

If a test still fails, the first question is **"is the harness wrong?"**, not "is this a bug?".

---

## 1. Role-plumbing facts to establish before granting anything

Read these, do not assume:

| Question | Why it bites |
|---|---|
| Which role is the **admin** of the role you are granting? | OZ `AccessControl` uses `_setRoleAdmin(ROLE, ADMIN_ROLE)`. A test contract that granted itself `ADMIN_ROLE` can grant everything; a test contract that granted itself only `OPERATOR_ROLE` **cannot** — `grantRole` reverts `AccessControlUnauthorizedAccount`. This is exactly what produced `AccessControlUnauthorizedAccount(0x7FA9…, 0xa498…=ADMIN_ROLE)` in the worked case. |
| Does the helper contract hold the role **in its own name**? | A burn/transfer helper (`WithdrawGasPayer`, `RelayExecutor`) calls `hub.burn(...)`, so **it** needs `OPERATOR_ROLE`, not the test contract. Grant to `address(helper)`. |
| Is `isOperator(account, operator)` per-account or role-wide? | `hasRole(OPERATOR_ROLE, operator) \|\| _isOperator[account][operator]` means **any** role holder is operator for **every** account. That is a privilege-model finding, not a bug in your test — and it also means granting `OPERATOR_ROLE` too liberally in the fixture masks real authorization behavior. |
| Is the entry actually permissionless? | `payGas` is callable by anyone *with a valid oracle signature* — the authority is the signature, not the caller. `vm.prank(attacker)` is correct and should be used deliberately to prove that. |
| Does the fixture actor need the role **itself**, not just admin over it? | `_setRoleAdmin(OPERATOR_ROLE, ADMIN_ROLE)` grants the *right to hand out* `OPERATOR_ROLE`; it does **not** grant `OPERATOR_ROLE`. So an admin that must also *call* `mint`/`burn` needs an explicit `grantRole(OPERATOR_ROLE, admin)`. Symptom: the grants all succeed and then a later fixture line reverts `AccessControlUnauthorizedAccount(admin, 0x9766…=OPERATOR_ROLE)`. Read the *role hash* in the error, not the function name — it tells you which role is actually missing. |

`vm.prank` is consumed by the **first external call**, and that includes a call made while
evaluating the *arguments* of the call you meant to prank. This is the highest-yield harness trap in
this class and it is silent:

```solidity
vm.prank(admin);
hub.grantRole(hub.OPERATOR_ROLE(), address(executor)); // grantRole runs as the TEST CONTRACT
//   ^^^^^^^^^^^^^^^^^^^^^ staticcall eats the prank
// -> AccessControlUnauthorizedAccount(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496, 0xa498…=ADMIN_ROLE)
```

Fixes, in order of preference: use `vm.startPrank`/`stopPrank`; or cache the id to a local
(`bytes32 opRole = hub.OPERATOR_ROLE();`) before pranking. The reported `sender` in the revert is the
give-away — if it is the test contract's own address, the prank never landed. Note this composes
**on top of** the pre-existing note below: `expectRevert` likewise binds to the next call, so neither
cheatcode survives an argument-evaluation call.

`vm.prank` + `vm.expectRevert(CustomError.selector, args)` does **not** compose the way it reads:
`expectRevert` binds to the *next* call. When a call is made through an internal helper that first
does something else (nah), pass the expected error explicitly and keep the helper short, or inline
the call. When unsure, `try/catch` and log — then tighten.

---

## 2. Test-per-claim shape (this is what "test that really fails when the bug exists" means)

For each invariant write **both directions**, and label them:

- **positive/authorization test** — the legitimate path must succeed (proves the harness works).
- **negative test** — the attack must revert, with the **exact custom error + args**:
  ```solidity
  vm.expectRevert(abi.encodeWithSelector(
      RelayAllocator.CallerIsNotApproved.selector, attacker));
  ```
- **bug-condition test** — the assertion states the *insecure* condition, so the test
  **PASSES while the bug is absent** and the message names the bug:
  ```solidity
  assertFalse(allocator.usedNonces(key, req.nonce), "BUG: failed signature burned the nonce");
  assertLe(credited, 1 ether, "BUG: withdrawal swept the executor's pre-existing balance");
  ```
  That inversion is the trick: you cannot write a test that fails "when the bug exists" without
  the bug being present, so assert the *invariant* and put `BUG:` in the failure string. When the
  suite is green, the invariant holds; the string documents what a red would have meant.

A PASS is **negative evidence** — say so explicitly in the report ("PASS membuktikan aman"),
never silently drop it.

---

## 3. Probing techniques that produced real answers

- **Alias/collision questions → getter first, no attack needed.** Before building a forged-spender
  exploit, call the derivation function directly on each candidate encoding:
  `Utils.generateAddress(chain, abi.encodePacked(addr))` vs `abi.encode(addr)` vs
  `abi.encode(uint256(uint160(addr)))` vs `abi.encode(bytes32(uint256(...)))`. One test, four logs,
  and the answer is decisive. Note the trap it revealed: those last three are the **same** 32-byte
  padded form (so they are one alias, not three) and all differ from the packed form — meaning they
  point at a *different, empty* alias and hold no funds. No collision, no vector.
- **EIP-712 digest-level aliasing:** hash `keccak256(bytes field)` for each encoding and assert the
  digests differ. Cheaper and more convincing than a full exploit.
- **Nonce ordering:** the question "is the nonce consumed before or after verification?" is
  answered by a bad-signature attempt followed by `assertFalse(usedNonces[...])`, then a good
  signature followed by `assertTrue`. Also test the ERC-1271/threshold path separately — it often
  writes the nonce on a different line.
- **External balance sweeping:** pre-position a residual balance in the actor
  (`hub.mint(address(executor), outId, 500 ether)`) and assert what the victim is credited. This is
  how `withdrawAmount = balanceOf(this)` (full-balance, not `+= amountOut`) gets **proven** rather
  than suspected. Distinguish "invariant broken but unattacker-controlled" (informational, the funds
  go to the *signed* receiver) from "attacker gains".
  **Do not pre-judge this as informational.** A full-balance read is unattacker-controlled only if the
  actor's balance is not attacker-fillable. When the same contract also receives per-order funding in
  the same tx, the attacker *can* fill it, and the class upgrades to reachable. Probe both:
  (a) residual balance swept with **no** signature and **no** role
  (`resolver.execute(req, false, payload)` called directly, bypassing the executor), and
  (b) the two-step chain — run one order so the actor ends up holding `netInput`, then sweep it. If
  either logs a non-zero attacker balance, this is theft, not an observation. See §7.
- **Fee/plan binding:** when a request is oracle-signed, enumerate exactly which parameters the digest
  covers. Call the contract's own `hashXRequest(req)` twice around building two *different* payloads
  — if the digest is invariant while the payload differs, the execution plan is unsigned.
- **Reentrancy:** attacker resolver calls back into the entry; log the inner revert bytes and
  identify the selector (`0x3ee5aeb5` = `ReentrancyGuardReentrantCall()`).
- **Digest mismatch finds:** build the digest by hand in the test (domain separator + struct hash)
  and `vm.sign` with `vm.addrAndKey("spenderEOA")`. If the signature is rejected, your digest is
  wrong before the contract is.

---

## 4. Debug loop for a red test that is the harness's fault

1. `forge test --match-contract X -vv` — read the error string, not the name.
   `AccessControlUnauthorizedAccount(addr, roleHash)` → role plumbing (§1).
   `panic: arithmetic underflow (0x11)` → your expectation about who can succeed is wrong; convert to
   `try/catch` and log which branch ran.
2. `forge test --match-test X -vvvv` — the call trace shows exactly how far the tx got.
   A trace ending at `[Revert] call to non-contract address 0x…bEEF` means the **resolver was never
   deployed** and the attack was vacuous, not blocked. Deploy a real resolver.
   The same revert with `address 0x0000000000000000000000000000000000000000` is a different bug class:
   token contracts that emit ERC-20 mirror events call out to a per-token `ERC20View`; a token that
   was never minted has no view deployed at address 0. Fixture fix — `hub.mint(address(0xFEED),
   tokenOutId, 1)` in `setUp` to materialise the view. Nothing to do with the vulnerability.
3. A `try` target that "secretly succeeded" (e.g. a hub `burn` on a zero balance) can produce an
   empty-length revert string. Do not conclude "blocked"; check the trace.
4. After each fix rerun the whole suite (`forge test`, no `--match`) so a fixture change cannot
   silently break a sibling claim.

Clean up probe files (`A2Probe*.t.sol`) before reporting — a leftover probe test is a false claim in
the summary count.

---

## 5. Reading a "no exploit found" result honestly

Three separable outputs, all of them deliverable:

- **SAFE / PASS** — invariant holds, with the line that enforces it and the test that demonstrates
  it. Negative evidence is the primary product of a red-team round.
- **FINDING (privilege-model, not attacker-reachable)** — e.g. `isOperator` role-wide, a burn helper
  with `OPERATOR_ROLE`, a fee with no per-spender cap whose only bound is the oracle's signature.
  State explicitly *which* trust assumption is the barrier (operator key / oracle signature), so it
  is not mistaken for a bug an outside user can trigger.
- **FINDING (latent invariant break)** — e.g. a full-balance sweep or a params hash that omits the
  spender (two spenders share one gas payment record → the second is unlocked for free). Documented
  in NatSpec or not, these are LOW/informational revenue-leak or residual-balance classes; do not
  upgrade them to theft without an unprivileged path.

Never collapse the three. A report that says "18/18 PASS, 0 attacker-reachable fund loss, plus 4
design observations" is stronger than one that promotes an observation into a claim.

---

## 6. Deliverable mechanics

- Write the report file **incrementally from the first claim**, appending each verdict with the
  verbatim forge block underneath it (the mandate said "append per claim"; honour it literally).
- Downstream agents need the **literal** forge lines, not a paraphrase: paste the
  `[PASS] test_... (gas: N)` block and the `Suite result:` line, including any `Logs:` lines that
  carry the numbers (`alias balance before/after`, `hash A == hash B`).
- Persist one `A2Base.sol` with `_a2SetUp()` (roles + assertions + shared builders/requests/digest
  helpers) and one `A2ClaimN.t.sol` per claim. Copying a proven workspace
  (`cp -r /tmp/work-agent2 /tmp/work-agent5`) and **re-pointing the remappings** is faster and safer
  than re-creating the harness; verify the target repo is untouched at the end
  (`git status --porcelain <contracts-dir> | wc -l` → 0).
- Close with the mandated N-line summary where **every line carries the literal forge verdict**.

---

## 7. Value-flow rounds: "who ends up holding it" (worked case, HUNT C)

Distinct from the earlier round whose claims were authorization gates. Here the entrypoints were
*already* permissionless and the question was **where the value lands**. Method that worked:

- **Never assert an attacker balance before tracing who takes the value first.** A test asserting
  "attacker holds 100% of input" failed with `0 != 100e` — not a bug, and not a blocked attack: the
  swapper pulled the input from the resolver one call earlier, so there was nothing left to sweep.
  The honest finding was the *negative* one (no double-dip of input **and** output).
- **Read the contract's own NatSpec for the admitted behaviour.** `_runCalls` docstring said the
  resolver "may retain the funded input or source output independently, provided it returns at least
  the signed minimum output". That sentence *is* the vulnerability class: the guard protects the
  **receiver**, not the **input**. When a docstring concedes a capability, write the test that
  exercises the cap.
- **Bracket the loss with two parameter points, not one.** Two orders differing only in
  `outAmountMinimum` (95% vs 1%) gave skim of `5e` vs `99e`, establishing
  `loss = netInput − outAmountMinimum` as a formula rather than an anecdote. A formula is what a
  triager accepts; a single number invites "that's just slippage".
- **Confirm the deployed bytecode equals your local build before claiming production relevance.**
  Diff `forge inspect`/`out/<C>.json` `deployedBytecode` against `cast code <addr>`: identical except
  for the immutable address (first diff landed at the `PUSH32` of the hub) means the PoC describes the
  real contract. Then `cast call hasRole(...)` on prod for every role you assume absent.
- **Enumerate the deployed selector set** (`cast` on the ABI + `4byte`) to prove a contract has *no*
  admin rescue function — 2 functions (`HUB()`, `execute(...)`) is a much stronger statement than
  "grep found nothing".
- **Turn a disproven hypothesis into a permanent negative test.** Rewrite the failing claim as
  `test_X_...IsImpossible()` asserting attacker balance `== 0` and what *actually* happened (input
  sitting in the swapper). The suite goes green, and the negative result cannot be re-claimed next
  round. Never delete the hypothesis silently and never leave it red.
- **A green suite is a hard requirement; a stale red test is a defect in your own deliverable.**
  Finish with a single bare `forge test` and paste the totals line
  (`65 tests passed, 0 failed`) — and check the count went *up* by the number of tests added, so no
  pre-existing baseline test was broken or silently skipped.
