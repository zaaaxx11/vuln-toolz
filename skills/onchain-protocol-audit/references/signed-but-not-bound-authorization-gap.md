# Signed-but-not-bound: authorization over one object, execution over another

Condensed from the Relay Protocol hunt round that produced its **single strongest and best-evidenced**
finding. This is the generalisation of `references/unguarded-value-sweeping-entrypoints.md`
(§"there is no signature at all") — here there *is* a signature, and it simply doesn't cover the
field that decides the outcome.

Companion to `evm-foundry-and-offchain-api-audit.md` §15 ("the signature binds too little").

**Section list:** §1 the shape and the two-line diagnostic · §2 the forge proof that survives review ·
§3 the loss formula · §4 the sibling bug in the web tier (sign-vs-execute gap across layers) ·
§5 scanner discipline — zero results are a parse bug until proven otherwise · §6 the guard-that-isn't ·
§7 honest severity downgrade from the orchestrator's own scan.

---

## 1. THE SHAPE — and the two-line diagnostic

```solidity
// RelayExecutor.sol:131-137 — the developers wrote the admission themselves
/// @dev The solver-selected `callResolver` and
///      `callResolverData` are not direct fields in the EIP-712 request, so a
///      generic execution plan can be refreshed after authorization.
function execute(
    ExecuteAndWithdrawRequest calldata request,   // ← oracle-signed
    address callResolver,                          // ← NOT in the digest
    bytes calldata callResolverData                // ← NOT in the digest
) external {
    _validateRequest(request, oracle, signature);  // binds request only
    address(ICallResolver(callResolver).execute(request, ..., callResolverData));
}
```

Diagnostic that finds this class in any codebase, two greps:

```bash
# (a) every signature/authorization validator, and the exact field list it hashes
grep -rn "createSignaturePayload\|_TYPEHASH\|abi.encode(\|keccak256(abi.encode" --include=*.sol contracts/
# (b) every call site that passes an address or bytes blob the validator never saw
grep -rn "\.execute(\|\.call(\|delegatecall" --include=*.sol contracts/ | grep -v test
```

Then answer one question per entrypoint: **is every argument that changes the outcome present in the
digest?** If not, the caller chooses the outcome after the victim authorises it.

**The tell is a docstring that explains why the omission is fine.** Phrases like *"can be refreshed
after authorization"*, *"typically the executor"*, *"is expected to be"*, *"specialised implementations
may require their own commitment"* are the author telling you the invariant is **not enforced**. Grep
for them:

```bash
grep -rn "after authorization\|can be refreshed\|typically\|expected to be\|assumed to be called by" --include=*.sol contracts/
```

## 2. THE FORGE PROOF — show the digest is invariant while the payload is not

The finding is only credible if the digest is byte-identical across two materially different payloads.
That is one test, and it needs no exploit at all:

```solidity
bytes32 d1 = executor.hashRequest(req, resolverA, payload192);
bytes32 d2 = executor.hashRequest(req, resolverB, payload256);
assertEq(d1, d2);   // identical ⇒ the payload is not bounded by the signature
assertEq(payload192.length != payload256.length, true);
```

Real output:

```
digest before: 0xb9f4e6cc69aaaf09e4bf532195c3a6641169092df6727c4328a48ee259e413c7
digest after : 0xb9f4e6cc69aaaf09e4bf532195c3a6641169092df6727c4328a48ee259e413c7
payload len  : 192 → 256
attacker: 0 → 100e18        victim: 100e18 → 0
PROVEN: payload jahat dieksekusi di bawah signature sah
```

Two additional tests make the claim airtight rather than anecdotal:

- **`sigIsDomainBound()`** — replaying the same signature against a second executor instance must
  revert. This *narrows* the finding honestly (the domain separator does its job) and proves you
  tested the boundary instead of assuming it.
- **`minOutIsBound()`** — confirms which fields *are* bound, so the report can state precisely what
  the victim still controls.

**The same test flipped positive also proves the negative claim** — e.g. a resolver that *retains* the
funded input rather than forwarding it is legitimate per the contract's own docstring
(`"may retain the funded input ... provided it returns at least the signed minimum output"`), which
means the retention itself is by design and only the missing commitment makes it theft-able.

## 3. THE LOSS FORMULA — one number, every route

When you test several routes (honest solver, cheapest-route skimmer, resolver-retains-input,
front-run resolver-swap) they converge on the same arithmetic:

```
loss = netInput − outAmountMinimum
```

Verified across three independent test suites with matching numbers:

| route | minOut | skimmable |
|---|---|---|
| honest route | anything | **0** |
| surplus skim | 95 % | **5e18** |
| surplus skim | 1 % | **99e18** |
| zero slippage | 100 % | **0** |

Publish the formula, not the anecdote. It converts a pile of recon into one sentence a triager can
check: *the maximum extractable value is exactly the slippage tolerance the user signed.* It also
falsifies the tempting overclaim ("attacker takes everything") — at `minOut == 100 %` there is nothing
to take, and saying so first is what makes the rest credible.

## 4. THE SIBLING BUG IN THE WEB TIER — one class, two layers

The identical defect appeared in the off-chain signer, independently:

```js
// signature-verification.ts:67-79 — what the owner signs
export function createSignaturePayload(req) {
  return { chainId, currency, amount, ... };      // ← no `depository`
}

// withdraw-request-authorization/v1.ts:165-177 — what the oracle signs
const depository = req.body.depository ?? chain.depository;  // ← attacker-controlled
```

And on-chain the corresponding check *does* bind it
(`RelayAllocator.sol:365-385`, `keccak256(params.depository)` in the digest) — so the gap is purely
sign-vs-execute, not a missing check anywhere.

Proof pattern: one legitimate signature, vary **only** the unbound field, show HTTP 200 with a
*different* oracle signature each time:

```
K0/K1 default       => 200 sig=0x6951e1ea…  (IDENTICAL — the binding works for bound fields)
K2 DepositAddrMgr   => 200 sig=0x1abf3fb4…
K3 0x…dEaD          => 200 sig=0x3037a4a4…
K4 3-byte 0xffffff  => 200 sig=0x2770b0ad…  (length not validated)
```

**Generalisation worth carrying:** when hunting a protocol with both a contract tier and a signing
service, run the "is every outcome-deciding field in the digest?" question **twice** — once per tier.
The same author writes the same omission in both places.

## 5. SCANNER DISCIPLINE — a zero is a parse bug until proven otherwise

Before publishing "there is no second X", make the scanner prove it can see the *first* one.

```python
# event PayloadBuilderSet(string indexed chainId, bytes indexed depository, address indexed builder)
#  ↑ ALL THREE INDEXED ⇒ they live in topics[1..3]; `data` is empty
chain_id = bytes.fromhex(topics[1][2:]).decode()   # correct
depo     = topics[2]                               # indexed bytes ⇒ keccak HASH, not the value
```

The failed attempt returned:

```
total 161  chainIds 0  multi 0        ← total>0 but keys==0 ⇒ decoder bug, NOT a finding
```

Corrected scan:

```
total 161  chainIds 83  multiByHash 0
```

**Rules:**
1. `total > 0 && distinct_keys == 0` ⇒ **always** a decoder bug. Assert both, don't infer.
2. `indexed bytes`/`indexed string` in a log gives you `keccak(value)`, not the value. Never print it
   as a decoded address — and don't use it as a set key while pretending it's the literal value.
3. Report the failed attempt explicitly with its cause. A silent retry looks like the first number was
   right.

## 6. THE GUARD THAT ISN'T — `hasRole` returning true is not the same as reachable value

`cast call` gates that pass can still lead nowhere. Two traps hit in one round:

```bash
# (1) allowance check whose `account` argument is never read
#     isOperator(account, operator) returns true if `operator` holds OPERATOR_ROLE — `account` discarded
#     and the call site passes msg.sender as `operator`, so ANY operator-role holder skips allowance
#     → real bug, but the holders are protocol contracts ⇒ not attacker-reachable. Report as latent.

# (2) rate-limit bypass that needs a signed action to trigger
#     `rateLimiter == address(0)` skips allowlist + consume — but `actions` bytes are INSIDE the
#     digest, so only the multisig can produce one. DEAD as an attacker vector.
```

**Rule:** for every "guard can be skipped when X == 0 / X == address(0)" finding, ask *who can set X*.
If the setter input is inside the signed payload, the bypass is a design choice by the trust anchor,
not a vulnerability. State it as such and move on.

## 7. HONEST SEVERITY DOWNGRADE — the orchestrator's own scan outranks the child's report

The subagent reported the web-tier gap as **HIGH**. The orchestrator's independent scan then showed
**0 chainIds have more than one depository** across 161 historical `PayloadBuilderSet` events — so the
cross-depository replay has **no second depository to target**.

Correct output:

> Bug is real and PROVEN at the signing layer (HTTP 200 with attacker-chosen `depository`).
> Severity downgraded HIGH → **MEDIUM (latent)**: it activates the day a second depository is
> registered on an existing chainId. Scan evidence: 161 events, 83 chainIds, 0 with `>1`.

Write the downgrade **above** the finding, with the number that caused it. A hunter who publishes a
downgrade alongside its own reasoning is more credible than one who only publishes wins — and the
downgrade is what a triager will independently check first.

---

## Mitigation, stated in one line

```solidity
// solver-supplied execution plan must be committed to by the signer
bytes32 constant TYPEHASH = keccak256(
    "ExecuteAndWithdrawRequest(...address callResolver,bytes32 callResolverDataHash)"
);
// and on the service side: put every field the executor reads into the owner-signed payload
```

Fix shape is always the same: **if execution reads it, the signer must sign it.**
