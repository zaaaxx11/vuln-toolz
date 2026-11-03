# Relay Settlement Protocol — Source-Audit Reference

Worked case: red-team of the Relay hub/allocator/oracle/depository/rate-limiter stack
(`RelayHub`, `RelayAllocator`, `RelayOracleV2`, `RelayOracleMultisig`,
`RelayDepository`, `RelayUsdRateLimiter`, `EthereumVmPayloadBuilder`,
`MulticallRouter`, `RelayFundingPool`, `WithdrawGasPayer`).

## Architecture (one-session mental model)

```
oracle (multisig/ECDSA)
  └─ signs Execution { idempotencyKey, actions[] }
      └─ RelayOracleV2.executeMultiple()
          ├─ ORACLE_ROLE gate on `oracle` arg
          ├─ idempotency store markExecuted(idempotencyKey)
          └─ _executeAction per action
              ├─ MINT      → HUB.mint(to, tokenId, amount) [OPERATOR_ROLE]
              ├─ BURN      → HUB.burn(from, tokenId, amount) [OPERATOR_ROLE]
              ├─ TRANSFER  → HUB.transferFrom(from, to, tokenId, amount)
              └─ FAST_MINT → rateLimiter.consume + feeCalculator + HUB.mint

spender / operator / platform
  └─ RelayAllocator.submitWithdrawRequest()
      ├─ suspend[alias] check FIRST
      ├─ caller = spender | operator | signature
      │   └─ consumeSpenderSignature()
      │       ├─ ECDSA.tryRecover on digest
      │       └─ ORACLE_MULTISIG.isValidSignatureNow(digest, sig)  [fallback]
      ├─ build payload via IPayloadBuilder
      ├─ HUB.burn(spenderAlias, tokenId, amount)
      └─ emit PayloadBuilt (hashesToSign for depository signature)

depository / router chain
  └─ RelayDepository.execute(CallRequest, allocatorSig)
      ├─ expiration check
      ├─ allocator.isValidSignatureNow(eip712Hash, sig)
      ├─ dedupe on structHash
      └─ _executeCalls() → low-level call{value:c.value}(c.data)
```

## Key findings classes (CONFIRMED / REFUTED)

### 1. `executeMultiple` try/catch does NOT bypass ORACLE_ROLE — but it DOES leak the executed set

`executeMultiple` (RelayOracleV2.sol:~170-181) loops `try this.execute(...) catch { emit ExecutionFailed }`.
Each `this.execute` call re-enters `_execute`, which re-checks `hasRole(ORACLE_ROLE, oracle)` and
`oracleMultisig.isValidSignatureNow`. The skip only avoids revert on a failing *action* inside an
already-authenticated execution. **Verdict: REFUTED — no unprivileged mint path.**

**Residual (LOW), do not omit it:** the catch is bare `catch {}`, so it also swallows
`UnauthorizedOracle`, `InvalidSignature` and `AlreadyExecuted`. Because `executeMultiple` itself is
**unpermissioned**, any caller can use the emitted `ExecutionFailed` events as an *oracle
validity / already-executed probe* against a batch of guessed idempotency keys. Also note each
`this.execute` is its own revert scope, so a batch is **not atomic across executions** — a reverting
execution does not roll back earlier successful ones. Atomicity holds *within* one execution only
(`markExecuted` precedes the action loop, so re-entering `execute` with the same key hits
`AlreadyExecuted`).

### 2. Oracle signature binds all request fields

`_hashExecution` includes `idempotencyKey` + `keccak256(abi.encodePacked(actionHashes))`.
`_withdrawRequestDigest` includes `spenderChainId`, `spender`, `receiver`, `nonce`, `amount`, etc.
Changing any field changes the digest → signature invalid. Cross-chain replay, spender substitution,
and nonce substitution without a new signature are all blocked. **Verdict: REFUTED.**

### 3. `generateAddress` packed encoding IS constructible — "theoretical" was wrong

- Nonce consumed under `keccak256(params.spender)` (`RelayAllocator.sol:~337`).
- Burn alias = `Utils.generateAddress(params.spenderChainId, params.spender)` (`RelayAllocator.sol:~260-263`),
  defined at `Utils.sol:~24-30` as `uint160(keccak256(abi.encodePacked(chainId, token)))`.

An earlier revision of this file called the collision "theoretically possible but not practically
constructible". **That was wrong.** `chainId` is a dynamic `string` and `token` a dynamic `bytes`, so
`abi.encodePacked` emits no length prefix and the field boundary is unlabelled. The identity is
always constructible: pick any hex-valid UTF-8 string `s`, then
`generateAddress(c, t) == generateAddress(c ‖ s, t[len(s):])`. Verified against the real SDK in
`references/encoding-digest-layer-fuzzing.md` (`chain="ethereum" len=20` ≡ `chain="ethereu" len=21`
with a `0x6d…` byte — same alias).

The **refutation therefore has to come from the gates, not from "not constructible"**:

- `payloadBuilders[chainId][depository]` (`RelayAllocator.sol:~81`, `~250-253`) keys on the **string**
  `chainId`, so a forged `chainId` must already be a configured key — a partial-offset trick cannot
  invent a new chain string out of thin air.
- Every auth branch requires `params.spender.length == 20` while the collision lives in the
  `len != 20` dimension — structurally mutually exclusive (see the auth-≡-length section of the
  encoding reference).
- Alias collision ≠ control: the alias is a bare ERC-6909 balance slot with no key.

**Verdict: LATENT DESIGN BUG with a reachable constructor (deployment-hygiene risk), not an
exploit.** Report it as "becomes live the day a chain is configured with a name that is another
chain's id concatenated with hex-leading address bytes". Fix: `abi.encode(chainId, token)` or a
`bytes32 chainId`. Do not repeat the "not constructible" phrasing.

### 4. Depository: permissionless entry + one allocator signature = arbitrary call primitive

`RelayDepository.execute` (`contracts/depository/RelayDepository.sol:~149-175`) checks allocator
signature, expiration, and dedupe, then executes arbitrary `CallRequest` calls with `value`. No
per-request value cap. **`is Ownable, EIP712` — no `AccessControl`, no role gate, no
`ReentrancyGuard`, no `nonReentrant`, no `receive()`/`fallback()`** (`:20`). It holds user deposits
(`depositErc20` at `:119-131`) and performs `c.to.call{value: c.value}(c.data)` inside an
`unchecked` loop (`:198`, slither-disabled at `:197`).

Three separate things to report — do not merge them:

1. **Key-management:** one compromised allocator key drains everything. KEY-MANAGEMENT RISK.
2. **Missing reentrancy guard:** structurally confirmed (`:20` has no guard). Impact is *bounded*
   because `callRequests[structHash] = true` is set at `:171` **before** `_executeCalls` at `:174`,
   so re-entering with the *same* request reverts `CallRequestAlreadyUsed`. The residual is two
   *different* still-valid signed requests, plus `allowFailure = true` calls (`:201-203`) that keep
   going after failure. Mark exploitability UNTESTED unless you build the harness.
3. **ERC-1271 trust surface:** `allocator` is mutable (`setAllocator`, `:91-99`) and verified via
   `SignatureCheckerLib` — which accepts **both** ECDSA and ERC-1271. If the deployed `allocator`
   is a contract whose `isValidSignature` is permissive, `execute` degrades into an open
   arbitrary-call primitive on a deposit-holding contract. State the deployed allocator's type
   before assigning severity.

### 4b. Gateway depository signature-trust blast radius (broader than the plain depository)

`RelayGatewayDepository.execute` verifies the allocator's EIP-1271 signature over arbitrary
`Call[]` execution, gated only by local `callRequests[structHash]` replay protection. Unlike
`RelayOracleV2`, it has **no shared `RelayOracleIdempotencyStore`** and no allowlist of
call-targets. The allocator signature is therefore the broadest arbitrary-execution primitive in
the depository layer. State the deployed allocator's type (EOA vs EIP-1271 contract) before
assigning severity: an EOA oracle limits the blast radius to key compromise, while a permissive
contract oracle degrades `execute` into an open call-forwarder on a deposit-holding contract.

### 4c. Typehash↔struct correspondence: verified CORRECT (do not re-litigate)

A prior concern that `_CALL_TYPEHASH` could mismatch the struct is **REFUTED — they match exactly**:
`RelayDepository.sol:~65-73` declares
`"CallRequest(Call[] calls,uint256 nonce,uint256 expiration)Call(address to,bytes data,uint256 value,bool allowFailure)"`
against the struct in `contracts/depository/utils/RelayDepositoryStructs.sol:9-24`. Field order,
names and types all agree, the referenced-type (`Call(...)`) suffix is present, and the sub-typehash
is *also* prefixed to each per-call hash (`:230-238`) — so the digest is unambiguous. The struct
hash at `:245-253` correctly commits `bytes data` as its `keccak256`, which is the standard EIP-712
encoding for a dynamic member. Gateway variant likewise correct
(`RelayGatewayDepository.sol:~95-103`, `~384-405` vs `RelayGatewayDepositoryStructs.sol:11-16`), with
`bytes32 transferSpecHash` as a static member between the typehash and `Call[]`.
Domains differ (`"RelayDepository"` at `:271` vs `"RelayGatewayDepository"`) ⇒ no cross-domain replay.
**When a brief asks "check for a typehash/struct mismatch", the answer here is NO — and saying so with
these line numbers is the finding.**

### 5. Rate limiter chainId is raw-string keyed (no canonicalization)

`RelayUsdRateLimiter._chainKey` returns `keccak256(bytes(chainId))`. Two casings (`"Ethereum"` vs
`"ethereum"`) split the budget. Not a direct theft vector, but an ops/config hazard. **Verdict:
LOW — operational risk only.**

### 6. `suspended[]` is checked before signature path

`RelayAllocator.sol:~269-271` reverts on `suspended[spenderAlias]` before `consumeSpenderSignature`
is reached. A suspended spender cannot reach the nonce-consuming fallback. **Verdict: REFUTED.**

### 7. Hub ERC6909: no allowance underflow, ERC20View creation is safe

`transferFrom` uses checked arithmetic; `_createERC20View` is idempotent. `approveFor` gated by
`erc20Views[id] == msg.sender`. `_burn` subtracts without pre-check but is `onlyRole(OPERATOR_ROLE)`
and checked arithmetic reverts on underflow. **Verdict: REFUTED.**

### 8. OracleMultisig: threshold, sorting, malleability, duplicates — all correct

- `signatures.length % 65 == 0`
- `signer <= lastSigner` enforced
- `ECDSA.tryRecover` (non-malleable)
- `seenSigners` prevents duplicates
- `signatureCount >= threshold` **Verdict: REFUTED.**

### 9. The `usedNonces` invariant in the NatSpec DOES NOT HOLD (LOW–MEDIUM)

`RelayAllocator.sol:~92-93` claims nonces are "shared by spender across direct ECDSA and
oracle-verified signatures". True *between* the two signature paths, **false for the
spender/operator branch**, which never touches `usedNonces` at all — `consumeSpenderSignature` is
only reached when the caller is **not** already authorised (`:269-273`).

Consequences, both CONFIRMED-BY-CODE:

- An alias holder / operator can submit unlimited requests reusing **one** nonce. The only remaining
  replay barrier is the `payloads[]` cache (`:284`), and `withdrawRequestHash = keccak256(abi.encode(params))`
  (`:283`) **includes `params.amount`** — so requests differing only in amount are distinct hashes and
  every one of them passes. The cache therefore does not bound the family.
- Griefing: pre-submit a nonzero amount under the signer's nonce to permanently consume
  `usedNonces[spenderKey][nonce]`, so the legitimately signed request later arriving via the
  *signature* path is rejected at `:338` → `CallerIsNotApproved` (`:278`). A signature killed on arrival.

Also a real CEI break: `payloads[withdrawRequestHash] = payload` at `:296` is written **before** `HUB.burn` at `:301`
and before `IPayloadBuilder.hashesToSign` at `:312`. Classic recursion into
`_submitWithdrawRequest` is impossible because `RelayHub.burn` (`RelayHub.sol:~393-400`) is a pure
in-memory solvency-ledger decrement with **no receiver hook** — so report the CEI ordering as the
defect and the *state-pollution* as the impact, not "reentrancy".

### 10. Precision: composed truncation ⇒ free fee, or permanent per-chain DoS

Two independent `_toUsdValue` implementations (`fee-calculators/RelayBpsFeeCalculator.sol:~95-106`,
`rate-limiters/RelayUsdRateLimiter.sol:~311-326`) truncate **twice**: `fullMulDiv(...)` rounds down,
then `_normalizeUsdDecimals(..., usdPriceDecimals, 18)` divides again. Cheap or low-decimal assets
therefore price to exactly `0`. Two divergent outcomes from the same root cause:

- **Fee side:** `feeUsdValue == 0` ⇒ `feeAmount` stays 0 (`:76`), `FeeExceedsMax` never fires, and
  `InvalidFeeRecipient`/`InvalidFeePayer` are **skipped** because both are guarded by
  `feeAmount != 0` (`:83-88`). FAST_MINT is free *and* zero-address validation is bypassed.
- **Limiter side:** `consume` treats `usdValue == 0` as a hard **reject** (`:168-172`, deliberately:
  "would consume nothing and always pass = unlimited"), so **every** FAST_MINT on that chain reverts
  `FastMintRejected` (`RelayOracleV2.sol:~359-365`) until an admin reconfigures. That is a
  chain-level liveness bug, not a bypass — easy to mis-file in the wrong direction.

Second-order: `resolveCanConsume` (`:250-268`) mirrors `consume` but reads a memory snapshot
**without** the `tokens > capacity` guard that `consume` has at `:155-160`, so if that invariant ever
broke the pre-check says `true` while the real `consume` says `false`.

**Safe by contrast (do not file these):** rounding never goes *up* (no payer drain); `_normalizeUsdDecimals`
for `d != 18` cannot overflow (`10**(255-18) < 2^256`) and reverts fail-closed on the multiply-up path.

### 11. Casts: the brief's concern was inverted

`nonce: uint256(params.nonce)` (`RelayAllocator.sol:~405`) is a **widening** `bytes32 → uint256`
conversion — exact, lossless. The real truncation is the opposite direction:
`payload-builders/LighterVmPayloadBuilder.sol:~284` (into a `uint64` field) and
`payload-builders/SolanaVmPayloadBuilder.sol:~149-160` (`uint64(keccak256(...))`). Solidity explicit
downcasts do **not** revert. Not a replay risk (allocator keys on full-width `bytes32`), but two
`params.data` values differing above 2^64 produce the same destination-chain nonce while consuming
different idempotency slots — a duplicate the off-chain signer cannot see in the hash. Note the
inconsistency: `LighterVmPayloadBuilder._toUint64` (~`:329-334`) *does* revert, Solana's does not.

## Retracted findings — keep these retractions on file

Recording a retraction is worth more to the next auditor than a lingering unfounded Medium.

**"RelayExecutor marks `usedRequests[digest] = true` before verifying the signature ⇒ front-run DoS."**
The ordering *is* `:203` check → `:206` mark → `:208` verify, which looks like a burn-before-verify.
It is **NOT exploitable**: the revert at `:208` unwinds the whole frame, rolling back the write at
`:206`, so the mark does not survive. Report as REFUTED (stylistic footgun only). Generalisable rule:
**before filing any mark-before-check finding, ask whether the rejecting branch reverts** — if it
reverts, the mark is rolled back and there is no persistent poisoning.

**"`RelayDepository.sol` is absent from the snapshot."** It is at
`contracts/depository/RelayDepository.sol`. A `search_files` for `_hashCallRequest|_executeCalls`
that returns matches in a *different* file (the payload-builder mirror) is not evidence of absence —
`ls contracts/depository/` settles it. This reversal changed two verdicts and forced a report rewrite;
confirm a file's existence with a directory listing before writing "cannot verify".

## Repeated checks that always apply to this protocol family

1. **Dead-code / player-mismatch check**: for every helper contract the brief names
   (`RelayOracleIdempotencyStore`, `RelayPriceOracle`, etc.), run `eth_getCode` on every
   address the deployment manifest names. If 0 bytes → DEAD-CODE verdict, stop. If no deploy
   script and no manifest key exists → off-chain-only ABI, not an on-chain actor.
2. **WHO-CAN-WRITE table**: for every role the store/limiter defines, sweep ALL contract addresses
   in the manifest with `hasRole`, not just the obvious oracle address. A writer absent from the
   manifest is a deploy-addr mismatch; a manifest writer missing the role on-chain is a
   DIVERGENT-STATE finding.
3. **Domain separator ≠ message chainId**: grep the domain builder for `evmChainId` /
   `signatureChainId` / `verifyingChain`. If domain and message use different sources, cross-chain
   replay is possible even when the message commits to `chainId`.
4. **Payload builder nonce is block.number-committed**: `EthereumVmPayloadBuilder.computeNonce`
   includes `block.number`, so the same params rebuilt in a later block yield a fresh nonce.
   This kills simple nonce-replay claims against the depository path.
5. **try/catch skip semantics**: `executeMultiple` skipping a failed execution does NOT consume
   the idempotency key (it was marked *outside* the try, in `_execute`). This means a failed
   action is re-attestable — confirm whether this is intended (slow-path retry) or a replay gap.
6. **Archive-RPC limits for volume/event claims**: When a finding depends on scanning all
   `Transfer`/`Executed`/`FastMint` logs from block 0 (e.g. "18,460 transfers to EOA X",
   "76–85% supply concentration"), a single RPC timeout or archive-tier block makes the claim
   UNPROVEN from live state, not REFUTED. State the RPC constraint explicitly and either (a) obtain
   an archive-enabled endpoint, or (b) downgrade the verdict to UNPROVEN with the exact blocker.
   Do not let a timeout become a silent assumption.
7. **DORMANT-surface grading**: A source-level primitive that is real but currently unreachable
   because no observed execution uses the relevant code path is **DORMANT**, not CONFIRMED or LATENT.
   Canonical example: `RelayBpsFeeCalculator.calculateFee` accepts an arbitrary `feePayer` from
   oracle-attested `data`, and `_executeFastMint` would call `HUB.transferFrom(fee.payer, ...)`
   with no depositor binding — but every observed FAST_MINT used `feeCalculator=address(0)`, so
   the path is structurally valid but operationally asleep. Grade as DORMANT; re-elevate to
   CONFIRMED only when a live execution or manifest config proves the calculator is wired.
8. **Gateway depository signature-trust blast radius**: `RelayGatewayDepository.execute` verifies
   the allocator's EIP-1271 signature over arbitrary `Call[]` execution, gated only by local
   `callRequests[structHash]` replay protection. Unlike `RelayOracleV2`, it has **no shared
   `RelayOracleIdempotencyStore`** and no allowlist of call-targets. The allocator signature is
   therefore the broadest arbitrary-execution primitive in the depository layer. State the deployed
   allocator's type (EOA vs EIP-1271 contract) before assigning severity: an EOA oracle limits
   the blast radius to key compromise, while a permissive contract oracle degrades `execute` into an
   open call-forwarder on a deposit-holding contract.

## Report shape for this class

Use **CONFIRMED-BY-CODE / REFUTED-BY-CODE / PARTIALLY CONFIRMED-BY-CODE** per invariant,
with file:line for every claim. Negative findings are first-class: a refuted attack path with
the exact line that blocks it is as valuable as a confirmed exploit.
