# Decode Hygiene — a five-retraction post-mortem

Five findings were retracted in a single audit session. Every one came from a claim built on a
decode that was never validated against source. This file is the checklist that would have
prevented all five. Load it whenever a finding rests on a hand-written decoder or a raw-number read.

---

## 1. Dynamic event `data` is not a 32-byte word grid

**Failure:** an event with dynamic params (`PayloadBuilt(bytes32 indexed, bytes payload,
bytes32[] hashesToSign)`) was scanned by slicing `data` into 64-hex chunks and treating
address-shaped chunks as addresses. This manufactures phantom values: offsets and length words
from the dynamic fields land in the grid and read as addresses.

**Manifestation:** a "suspicious receiver" `0xb2000000…2feb517dfec7415344` with six embedded zero
bytes, presented as a dead address that withdrawals were being sent to.

**Refutation:** properly ABI-decoded 609 live payloads — the address appeared in **0** of them.

**Rule:** resolve the outer offsets (`idx = word//32`) to the dynamic region, read its length,
then decode inside it. Anchor the decode on a value already known from calldata (e.g. the request
`amount`); if the anchor does not appear, the decoder is wrong, not the target.

## 2. Divide by decimals before calling a number large

**Failure:** a raw `11900673838987117933` wei-USD value was read as a decimal number and reported
as **$11.9 million** in a single rate-limiter consumption. It is **$11.90**. The whole "rate
limiter is inert because it approved a $12M spend" finding collapsed.

**Rule:** always print the raw integer **and** the decimals-divided value side by side
(`11900673838987117933 → 11.90`). If the paired print is not in the artifact, the claim is not
ready. This also produced the correct conclusion: 14 consumptions totalling $170.07, zero
capacity violations, limiter working as designed.

## 3. Prove a mapping is empty with the RIGHT key encoding

**Failure:** `payloadBuilders[chainId][depository]` was probed with numeric chain ids
(`"1"`, `"8453"`, `"42161"`, `"137"`, …) and `abi.encode(depository)`; it returned
`0 registered pairs`, and the report was about to say "the withdraw path is dead".

**Reality:** the key is the chain **NAME** (`"base"`, `"ethereum"`) and the `bytes` key is
`abi.encodePacked` (20 B), not `abi.encode` (32 B):

```
payloadBuilders("base", abi.encodePacked(0x4cD00E38…)) = 0x6bc7e632…   ← hit
payloadBuilders("base", abi.encode(0x4cD00E38…))       = 0x0000…0000  ← miss
payloadBuilders("8453", abi.encodePacked(0x4cD00E38…)) = 0x0000…0000  ← miss
```

**Rule:** before concluding a registry is empty, probe all four combinations — {name string,
numeric string} × {`encodePacked`, `encode`}. Corroborate with the event emission count: 4,532
`PayloadBuilt` events from that exact contract meant the registry could not be empty regardless of
what the probe said. **A probe result that contradicts an event census means the probe is wrong.**

## 4. Distinguish the gate you found from the gate that binds

**Failure:** an owner-only `setPayloadBuilder` registry was named the binding blocker for an
unprivileged chain. It was already open for a real pair.

**Reality:** the binding gate was `consumeSpenderSignature` three frames deeper, evaluated with
`msg.sender` = the external caller. `isOperator(alias, allocator) == TRUE` (the allocator holds the
global role) but `isOperator(alias, randomAttacker) == false`.

**Rule:** for each candidate gate, ask "who must satisfy this, and is that the attacker?" Then
assert the negative explicitly — `isOperator(alias, randomAttacker) == false` IS the deliverable
when the chain is blocked. A blocked chain needs one falsifiable assertion naming the blocker.

## 5. Isolate a revert before blaming an internal call

**Failure:** a ~985M-gas revert on mint was attributed to `_createERC20View`.

**Reality:** a 985M-gas revert is the fork runner exhausting gas inside `create`. Isolation showed
mint of one fresh tokenId worked (~946k gas), a repeat mint of the SAME id worked, and only a
second DISTINCT id reverted.

**Rule:** build the 2×2 isolation matrix (fresh vs same vs distinct) before naming the culprit.
High gas near the block limit is a runner artifact, not a finding.

## 6. Measure keys and roles; do not assume them

- Walk `owner()` / admin / role holders to the account, then `cast code` it.
  Codesize `0` = EOA = **one private key**, not a multisig and not a timelock.
- Check `nonce` on the chain where the key actually signs. `nonce 0` there = it has never signed
  there; saying "active owner key" without that check is an unsupported claim.
- Collapse the deployed instance set before quoting blast radius. 78 chains reduced to
  **3 depository addresses ⇄ 3 allocator EOAs ⇄ 1 owner EOA** — which reframes a "per-chain" bug
  as a single-key bug. That census is usually the strongest finding in the report.
- Check whether an admin role can even revoke: a hub with **no `DEFAULT_ADMIN_ROLE` holder** means
  a granted role is permanent. Verify, then state it.

## 7. Retraction discipline

When a decode fails these checks:

1. Write the retraction file (`RETRACTION_Rn.md`) naming **which check** it violated.
2. Keep it in the workspace. It is evidence of method, not a loss.
3. Never upgrade a claim to PROVEN to unblock a round, and never delete the retracted finding from
   the ledger — mark it dead with the refuting artifact path.

A recorded retraction is diagnostic value; a defended wrong finding destroys the whole report.
