# On-chain EIP-712 binding proof + max-extraction PoC

Companion to `signature-binding-sign-vs-execute.md`. That file proves the sign-vs-execute
gap at the **service/SDK layer** (HTTP, viem, Fastify). This one proves the same class of
gap at the **on-chain layer**, where the deliverable is a `forge test` with exact numbers.
Proven on Relay Protocol `RelayExecutor.sol` (finding C6/R10), 2026-10-30: 158 tests green.

Trigger: "build the exploit PoC for the digest-malleability finding", "demonstrate maximum
realisable value extraction", "self-contained forge test", "report exact numbers".

**Third axis — the DOMAIN, not the fields:** `eip712-domain-separator-replay-audit.md`
asks "is this digest bound to ONE contract on ONE chain?". It carries the `eip712Domain()`
census (and why `DOMAIN_SEPARATOR()` reverts under OZ v5), the `vm.chainId` cross-chain
proof, the twin-deployment cross-contract test **plus the shared-allocator trap that
invalidates the obvious version of it**, hand-rolled `Utils.buildDomainSeparator` parity,
and the 1271 split (does a second verifier re-wrap the digest? Relay: it does not — one
digest, dead oracle domain). Read it before reasoning about replay; every field question
below assumes the domain is already sound.

---

## 1. The mechanical field-binding table — never classify by reading source

Reading the struct and eyeballing the typehash is how you mis-classify a field. Derive it
**from the deployed contract itself**: mutate the field, re-digest through the contract's
own public hasher, compare to baseline.

```solidity
function _assertBound(string memory name, ExecuteAndWithdrawRequest memory r) internal {
  bytes32 before   = _d(_mk());   // baseline
  bytes32 afterMut = _d(r);       // one field mutated
  emit log_named_string("FIELD", name);
  emit log_named_bytes32("  digest before", before);
  emit log_named_bytes32("  digest after ", afterMut);
  emit log_string(before == afterMut ? "  VERDICT: *** UNBOUND ***" : "  VERDICT: bound");
  assertTrue(before != afterMut, string.concat("FIELD IS UNBOUND: ", name));
}
```

One test per field, each calling `_assertBound`. A bound field's test PASSES (digest
changed); an intentionally-unbound field asserts `assertEq(d1, d2)` — the digest is
**byte-identical** across two different intended plans.

Rules that made this trustworthy:

- **`before != afterMut` is the assertion for BOUND.** Do not invert this and do not
  `assertEq` for bound fields — a silently-reverting mutation then reads as "bound".
- **`after` is a reserved keyword** in Solidity. Name it `afterMut`.
- **`emit log_*` cannot live in a `view`/`pure` function.** Strip both qualifiers from
  every test that logs, or the file fails with a wall of `Error (8961)`.
- **Emit a `test_Z05_printTable()`** that writes the whole binding table via `log_string`.
  The log itself becomes the report deliverable — paste it straight into the write-up.

## 2. `execute()` parameters are the highest-yield candidate

The struct is usually fully bound. Look at what the *function signature* takes that the
struct does not contain:

```solidity
function execute(
  ExecuteAndWithdrawRequest calldata request,  // <- signed
  address callResolver,                        // <- NOT in the digest
  bytes calldata callResolverData,             // <- NOT in the digest
  address oracle,                              // <- caller-chosen, ORACLE_ROLE-gated
  bytes calldata signature
)
```

`callResolver` receives **100% of the order input** via `_runCalls` before untrusted logic
runs. It is structurally unexpressible in the digest:
`hashExecuteAndWithdrawRequest(ExecuteAndWithdrawRequest)` has no parameter for it. That is
the whole finding — no crypto break.

Enumerate **all** out-of-digest candidates and give each a verdict, including the dead ones:

| candidate | verdict |
|---|---|
| `callResolver` | EXPLOITABLE — attacker's contract receives whole input |
| `callResolverData` | EXPLOITABLE — arbitrary bytes drive the production resolver |
| `oracle` arg | not exploitable alone — gated by `ORACLE_ROLE`; caller may pick any *authorised* oracle |
| `fees` / `deadline` | **bound** — verified, discarded |

Listing the dead candidates explicitly is what stops the report reading like you never
considered them (same discipline as `negative-verdict-gate-ledger.md`).

## 3. Read the settlement layer before writing any assertion

**This is the trap that cost the most cycles.** Asserting "the receiver's balance increases"
looked obviously right and was **wrong**. `RelayAllocator._submitWithdrawRequest` **burns**
the spender-alias tokens on the hub and stores a payload for an off-chain depository to
release funds against:

```solidity
// RelayAllocator.sol — submitWithdrawRequest
uint256 tokenId = Utils.generateTokenId(params.chainId, params.currency);
bool result = RelayHub(HUB).burn(spenderAlias, tokenId, params.amount);
```

So the beneficiary is **never credited on-chain**, in honest execution or hostile. The only
real observables are (a) order-input balance deltas and (b) the amount written into the
withdraw payload.

The correct assertion reads the payload:

```solidity
function _withdrawAmount(bytes32 h) internal view returns (uint256) {
  bytes memory p = allocator.payloads(h);
  require(p.length != 0, "no payload");
  (, uint256 amount, , ) = abi.decode(p, (string, uint256, bytes, bytes32));
  return amount;
}
```

**When a PoC assertion fails, decide FIRST whether the assertion or the exploit is wrong.**
Here the exploit was fine and the assertion encoded a false model of the protocol. Rewriting
the test to match reality is correct; bending the test until the original claim "passes" is
how a false finding ships. State the correction in the report — it is evidence of rigour.

Same principle as `signature-binding-sign-vs-execute.md` §7: your own scaffold is the #1
false-positive source.

## 4. Max-extraction PoC — the four assertions a triager cannot dismiss

A PoC that shows "the attacker got some money" is refutable. Assert the full economic frame:

```solidity
// 1. the auth is plan-agnostic — this is the primitive itself
assertEq(executor.hashExecuteAndWithdrawRequest(r), victimDigest,
         "digest blind to callResolver");
// 2. attacker captures the whole order value
assertEq(attackerInAfter - attackerInBefore, INPUT, "attacker takes 100% of input");
// 3. the victim's signed guarantee is STILL MET -> slippage guard cannot save them
assertEq(withdrawAmt, MIN_OUT, "signed minOut still met");
// 4. attacker's net is the exact closed form
assertEq((attackerInAfter - attackerInBefore) - fillSpent, INPUT - MIN_OUT,
         "net extraction = INPUT - MIN_OUT");
```

Assertion **3 is the load-bearing one.** If the signed floor is satisfied, nothing on-chain
and no victim-side monitoring flags the fill, and the attacker's take is exactly the victim's
slippage tolerance. Without 3, a reviewer replies "their slippage guard would have caught it".

Also state the attacker's cost surface explicitly: **no role, no signature over anything it
supplied, no capital beyond one order's minimum output.**

## 5. Always run the worst case against the PRODUCTION resolver

"The attacker had to deploy a malicious resolver" invites dismissal. Check whether the repo
ships a generic resolver that already does arbitrary calls + sweeps — `BasicCallResolver`
does:

```solidity
struct Call  { address to; bytes data; }
struct Sweep { address recipient; uint256 tokenId; }
function execute(ExecuteAndWithdrawRequest calldata, bool, bytes calldata data) external {
  (Call[] memory calls, Sweep[] memory sweeps) = abi.decode(data, (Call[], Sweep[]));
  for (...) { (bool ok, bytes memory res) = calls[i].to.call(calls[i].data); ... }
  for (...) { HUB.transfer(sweeps[i].recipient, sweeps[i].tokenId, balance); }
}
```

With `callResolverData` unsigned, that is a complete exploit using **zero attacker-authored
contracts**. Lead the report with this version.

- The structs are **nested inside the contract** — `BasicCallResolver.Call`, not a bare
  `Call`. A top-level `import {Call, Sweep}` fails `Error (2904): Declaration not found`.
- `Sweep` moves the **whole** balance, so sweeping everything leaves 0 for the executor and
  trips `InsufficientMinimumAmount`. Leave exactly the signed floor behind.
- Route the floor to the **executor** explicitly. Paying "back to `msg.sender`" pays the
  *resolver*, not the executor, and the min-out check then fails with a confusing `0 != MIN`.

## 6. Compose primitives, don't just relabel them

Chaining a separate finding (here C2, "surplus above `outAmountMinimum` is unprotected") onto
the binding bug is legitimate **only if both legs move real value**. A test that computes
"surplus = fill − floor" and asserts it, while nothing actually transfers that surplus to the
attacker, is a relabelled number, not a second exploit.

Real composition looks like: C6 decides **who owns** the execution value; C2 decides **how
much of it is unprotected**. Both legs transfer, both are asserted, both are logged.

## 7. Run the griefing arm and report it as a NEGATIVE

Mutating the resolver to return nothing makes `_finalizeWithdraw` revert
`InsufficientMinimumAmount`, which rolls back the fund pull **and** the
`usedRequests[digest] = true` write. Post-state: victim funds intact, attacker profit 0,
order still fillable.

Test it with `vm.expectRevert()` and assert the rolled-back balances. Writing
`test_Z02_grief_blockOrder` that *passes by proving non-exploitability* is a deliverable —
it closes the direction instead of leaving it unconsidered.

## 8. Foundry harness gotchas that ate cycles here

- **Roles need `_setRoleAdmin` to point at an admin the fixture holds.** A fresh
  `RelayHub(admin)` grants `ADMIN_ROLE` but `OPERATOR_ROLE`'s admin may be `ADMIN_ROLE`;
  grant both in the same `startPrank` block or every later `mint` reverts
  `AccessControlUnauthorizedAccount`.
- **`OPERATOR_ROLE` on the allocator is required** — it burns on withdraw. Missing grant
  shows up late as `AccessControlUnauthorizedAccount` inside `submitWithdrawRequest`, far
  from the cause.
- **`transferFrom` needs an operator or allowance.** Call
  `hub.setOperator(address(executor), true)` as the order owner in `setUp`, mirroring real
  onboarding. Otherwise `_pullOrderFunds` underflows.
- **Checksummed literal addresses.** `address(0xBEEF)` silently resolves to the wrong value;
  use the true checksum form (`0x00bEEf`) or `makeAddr`. This one masqueraded as a protocol
  bug for several cycles — the trace showed a *different* address receiving tokens.
- **Debug with `-vvvv` and grep the transfer lines**, not your own logs:
  `forge test --match-test X -vvvv 2>&1 | grep "Transfer(caller"`. When no Transfer event
  appears at all, the branch never executed — that discriminates "wrong recipient" from
  "no transfer".
- **Discriminate warnings from failures** in output:
  `forge test ... 2>&1 | grep -v "Warning\|^ *|\|^ *-->\|^$"`.

## 9. Report numbers to quote

Keep the exact integers — a table with real values is the deliverable:

| metric | value |
|---|---|
| victim signed digest | `0xa4566d9b…292a3` |
| digest after resolver swap | `0xa4566d9b…292a3` (**identical**) |
| attacker input gain | 1,000,000,000,000 (100% of order input, 6dp) |
| fill spent | 999,000,000,000 |
| victim withdraw payload | 999,000,000,000 (**floor met**) |
| **net profit** | **1,000,000,000 = INPUT − MIN_OUT** |

Production-resolver worst case: **31,000,000,000** out units (live quote 1,030,000e6 −
signed floor 999,000e6), floor still paid.
