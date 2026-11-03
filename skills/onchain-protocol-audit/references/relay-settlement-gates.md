# Relay Settlement Gate Findings

Use this when auditing Relay-like hub/allocator/oracle/depository systems where unprivileged
exploit chains are claimed to end at owner-set builder/payload registries.

**STATUS: the original "payloadBuilders gate blocks everything" conclusion was CORRECTED by a
live fork run. Read the CORRECTION section before reusing the older text.**

---

## CORRECTION — the builder registry is NOT the binding gate

An earlier version of this file said the unprivileged chain "stops here" at
`payloadBuilders[chainId][depository] != address(0)`. A later fork run showed:

1. **The registry is populated and the gate is OPEN for real pairs.** A naive 8-guess probe
   returned `0 registered pairs` and nearly produced a false "path is dead" verdict. Two
   independent mistakes caused it:
   - **`chainId` is the chain NAME string, not the numeric id.** `payloadBuilders("base", …)`
     returns a builder; `payloadBuilders("8453", …)` returns `address(0)`.
   - **The `depository` `bytes` key is `abi.encodePacked`, not `abi.encode`.**
     `abi.encodePacked(dep)` (20 bytes) hits; `abi.encode(dep)` (32 bytes) returns zero.
   Probe both forms before concluding a registry entry is empty.
2. **The real binding gate is spender authorization inside `_submitWithdrawRequest`:**
   `callerIsSpender || callerIsOperator || consumeSpenderSignature(params, signature)`.
   `callerIsOperator` is evaluated with `msg.sender` = the EXTERNAL caller, so the allocator's
   own global OPERATOR_ROLE does NOT make an arbitrary caller pass.
3. **Fork-proven on live state:** `isOperator(alias, allocator) = TRUE` but
   `isOperator(alias, randomAttacker) = false`. The attacker path dies at
   `consumeSpenderSignature` (valid ECDSA by `params.spender` over the request digest).

**Lesson:** before declaring an owner-set registry the blocker, prove it is empty *with the
correct key encoding*. A registry that is open plus a signature gate further in is a very
different report from a registry that is closed.

---

## Operator-role amplification (still true, still not an unprivileged path)

- `RelayHub.isOperator(account, operator)` ignores `account` for `OPERATOR_ROLE` holders, so the
  role holder can mint/burn arbitrary aliases. Proven live:
  `isOperator(0x…0001 | 0x1111…1111 | 0x6856c6f…, ALLOCATOR) = TRUE`.
- `RelayHub.burn(sender, id, amount)` is `onlyRole(OPERATOR_ROLE)` with NO ownership or chain
  validation — fork test burned 500,000e18 from an arbitrary alias.
- `RelayHub` exposes **no `DEFAULT_ADMIN_ROLE` holder**, so a granted role cannot be revoked
  through the hub. Check this explicitly; it changes the severity of key compromise.
- None of the above creates an unprivileged path. It only matters once the attacker holds the
  role or can reach a contract that holds it.

## Key-compromise blast radius (the strongest live finding)

Measure this whenever the "final gate" turns out to be a signature or an owner call:

- Walk `owner()` / `admin()` / role holders to the underlying account, then `cast code` it.
  Codesize `0` = EOA = single private key, not a multisig or timelock.
- Cross-check `nonce` on the chain where the key actually signs. A key with `nonce 0` on the
  settlement chain has never signed there — worth stating explicitly instead of implying it is
  active.
- Enumerate the deployed instance set before quoting blast radius: 78 chains can collapse to
  **3 depository addresses ⇄ 3 allocator EOAs ⇄ 1 owner EOA**. That reframes a "per-chain" bug
  as a single-key bug.
- Report the measured value at risk, not a vibe: read `totalSupply(id)` per live tokenId and
  convert with the token's decimals.

## Alias / tokenId derivation and its real limits

- `generateAddress(chainId, account) = address(uint160(keccak256(abi.encodePacked(chainId, account))))`
- `generateTokenId(chainId, token) = uint256(keccak256(abi.encodePacked(chainId, token)))`
- Both use `abi.encodePacked` over a dynamic `string chainId` + dynamic `bytes`, so a packed
  collision is arithmetically real (`chain="1"` + 20-byte account collides with
  `chain="1\xaa"` + 19-byte account). It is **gated** by the `params.spender.length == 20` check
  on the user-supplied path. Print the gate, do not hand-wave it.
- **Alias ≠ authenticated account.** `callerIsSpender` compares `msg.sender` to
  `address(bytes20(params.spender))`, while the burn target is
  `generateAddress(spenderChainId, spender)`. The attacker can only burn an alias derivable from
  ITS OWN spender bytes; hitting a victim alias needs a keccak preimage. Say this outright —
  it kills the "burn the victim's alias" story cleanly.
- `spenderKey = keccak256(params.spender)` **excludes `spenderChainId`**, so the nonce space is
  shared, BUT the EIP-712 digest DOES bind `spenderChainId`, so cross-chain replay is dead.
  Verify which side binds before claiming replay.
- Hub live tokenIds are keyed by chain NAME + 20-byte token (native = 20 zero bytes),
  e.g. `keccak("ethereum" ++ bytes20(0))`. Brute short chain names against a captured live
  tokenId to recover the real key rather than assuming numeric ids.

## Withdraw payload structure (what the builder actually emits)
## Withdraw payload structure (what the builder actually emits)

`EthereumVmPayloadBuilder.buildPayload` ALWAYS emits `calls[0] = transfer(currency, receiver, amount)` and conditionally appends `calls[1] = {to: routed.router, dataHash: routed.dataHash}`.
`receiver` and `amount` come straight from `params`, and
`computeNonce = keccak(block.number, address(this), chainId, depository, params)` is fully
public/predictable. Consequence: IF you find a way into `_submitWithdrawRequest` with a funded
alias, funds flow to an attacker-chosen `receiver`. That is the highest-value open lead; the
`data`/router branch is separately allowlisted via `CONFIG.getConfigValue(routerKey) == 1`.

## Burn-to-zero probe when `receiver = address(0)` with a valid spender signature

This is a common claim against `EthereumVmPayloadBuilder`: "use a valid signature to burn an alias by sending funds to zero." Audit conclusion: the builder accepts `receiver=0`, but the signature binding kills the cross-alias burn story unless the signer explicitly authorized `receiver=0`.

- **Builder acceptance**: `EthereumVmPayloadBuilder.buildPayload()` only rejects `params.receiver.length != 20`; it does not reject the zero address. So `receiver=0x0` produces a valid payload with a transfer-to-zero or native burn-to-zero leg.
- **Burn source is still the spender alias**: `RelayAllocator._submitWithdrawRequest()` derives `spenderAlias = Utils.generateAddress(params.spenderChainId, params.spender)` and burns from that alias only. `receiver` affects output destination only.
- **Signature binding**: `consumeSpenderSignature()` verifies the EIP-712 digest over the full `WithdrawRequest`, including `keccak256(params.receiver)` among other fields. Replaying or modifying `receiver` invalidates the digest; only a signature that explicitly authorized `receiver=0` can authorize the burn.
- **No commitment-swap on the transfer leg**: the routed commitment (`dataHash`) only covers the router call appended after the transfer. The transfer call is always explicit calldata (`dataHash == 0`), so there is no later commitment preimage swap that can redirect it.

**Verdict hygiene**: report `receiver=0` acceptance as a low-severity fund-loss / griefing surface in the depository/executor path, but do not upgrade it to a critical burn-via-stolen-signature bug without proof that the signer authorized `receiver=0`. The independent signature gate is the decisive negative evidence.

**Resolved by foundry PoC (authorization direction confirmed):** `test_F1_burnToZeroReceiver` PASS —
after ONE `submitWithdrawRequest` with `receiver = address(0)`, the alias balance is `0` and
`totalSupply(id)` is `0`. So the sequence is *submit → burn → payload to zero*, and the burn
lands **before** anything downstream can reject it. Two consequences worth stating in a report:
- The precondition is "signer signed `receiver=0`", i.e. it is a **footgun** (UI/SDK/backend can
  produce it), not an attacker primitive. Say exactly that instead of inflating it.
- All **10** payload builders only check `params.receiver.length` (e.g.
  `EthereumVmPayloadBuilder.sol:120`); the only value check is
  `HederaVmPayloadBuilder.sol:235` (`InvalidAccount`). Zero builders reject the zero address.
- The missing second layer is allocator-side: `RelayAllocator.sol:284-308` builds + burns with no
  `receiver != 0` validation. That is the right fix location, not the 10 builders.

## `hub.transfer(0, …)` is an unbounded, unrecoverable burn (F-1 class)

`RelayHub.transfer` (`RelayHub.sol:228-241`) and `transferFrom` (`:249-273`) both do
`balanceOf[receiver][id] += amount` with **no zero-address check**, and `Hub.transfer` has no ACL
at all. PoC: `test_F3_transferToZeroAddressBurns` PASS — 5e18 moved to `balanceOf[address(0)]`,
and **`totalSupply` did NOT decrease**. Two findings in one: irreversible fund destruction, plus
an accounting divergence (supply still counts value nobody can ever withdraw). There is no
`sweep`/`recover`/`unburn`, and `mint`/`burn` are `onlyRole`. Report as its own item — it is
independent of the withdraw path.
**Amended:** the "unrecoverable"/"nobody can ever withdraw" wording is WRONG — see
**"Burn-to-zero is RECOVERABLE"** below. The balance is recoverable by `OPERATOR_ROLE` or by the
hub's own `ERC20View`; only the *user* cannot recover it.

## Expiration does NOT protect funds — burn precedes execution

`EthereumVmPayloadBuilder.sol:152-156` sets `expiration = block.timestamp + expirationDelay`
(live `ETHEREUM_VM_EXPIRATION = 0xe10` = **3600 s**, per
`packages/multisig-tools/scripts/generate-arc-zorro-tron-config.ts:60`), and
`RelayDepository.sol:156-158` enforces it. But `burn()` and the `payloads[]` write already
happened in `submitWithdrawRequest`. So a request that misses the 1-hour window is **funds gone,
payload dead**. Never present expiration as a refund/safety mechanism in Relay — it is a
loss-amplifier. Verify the live delay from the config script before quoting it.

## Depository duplicate-ID griefing

Event-only depositories that accept duplicate `id` values enable griefing, but usually not fund
loss. Classify as griefing unless the depository lets the attacker withdraw or redirect funds.

## Same-alias, different-tokenId mint

Minting two distinct tokenIds to the same alias was observed reverting at ~985M gas. Isolate it
before blaming a specific internal call: a single fresh tokenId mints fine (~946k gas) and a
repeat mint of the SAME id is fine — only the second DISTINCT id reverts. A 985M-gas revert is
the fork runner exhausting gas inside `create`, so check for a real deploy-side barrier
(ERC20View creation) rather than assuming an auth bug.

## Rate-limiter config MEASURED: `rate == capacity` ⇒ self-healing in 1 block

The earlier ledger row said the limiter is mint-only and RBAC-gated (still true). This session
measured its actual numbers on the live fork and they matter for any "drain ⇒ freeze" claim:

```
getBucket("base") = TokenBucket{
  tokens     : 1e22   (=$10,000 at USD_DECIMALS=18)
  lastUpdated: <ts> (uint32)
  isEnabled  : true
  capacity   : 1e22
  rate       : 1e22   <-- refill per SECOND, i.e. 1x capacity per second
}
USD_DECIMALS() = 18    <-- returns uint256, NOT uint8
```

`rate == capacity` means an exhausted bucket is **fully replenished inside one block**. Read the
rate/capacity ratio from `getBucket` before writing any "permanent DoS via drain" sentence — on
this deployment the ratio is 1, so the answer is "self-healing", full stop.

Also measured: `consume()` on a tokenId with no price route reverts `0xd4b07aa5`
(`FeedRouteNotFound`) **even when pranked as the oracle**. So "compromised CONSUMER_ROLE drains the
budget" is itself unreachable for unpriced tokenIds. Check which tokenIds the price oracle actually
routes before assuming the drain primitive is live.

## Relay ABI corrections (6 wrong signatures were carried in the brief/summary)

Every one of these was asserted wrongly and cost a compile/run cycle. Ground them in source
(`~/.huntos/workspaces/relay-settlement-*/smart-contracts`) rather than reconstructed bytecode:

| Symbol | WRONG | RIGHT |
|---|---|---|
| limiter address checksum | `0x23aFd9e0348C058ebA84c434D9c6b508cEA764E6` | `0x23AFd9E0348C058EBA84C434d9C6B508CEA764E6` (lowercase-ish forms fail Solidity error **9429**) |
| `consume` | `consume(string,address,uint256)` | `consume(uint256 tokenId, uint256 amount, bytes data)` — `onlyRole(CONSUMER_ROLE)`, **returns bool, does NOT revert** when over budget |
| `getBucket` return | `(uint128,uint128,uint128,uint128,bool)` | `TokenBucket{uint128 tokens; uint32 lastUpdated; bool isEnabled; uint128 capacity; uint128 rate}` — **field ORDER decides ABI decode**; wrong order = bare `EvmError: Revert` with no clue |
| `USD_DECIMALS()` | `uint8` | `uint256` (public constant 18) |
| `payloads` | `view returns (bytes)` | `view returns (bytes memory)` |
| `usedNonces` writes | "any submit" | ONLY inside `consumeSpenderSignature`, which **early-returns when `signature.length == 0`** (`RelayAllocator.sol:329-334`). `submitWithdrawRequest` passes `bytes("")` ⇒ the unsigned path never touches `usedNonces` at all |

That last one is a real lead in the opposite direction: the unsigned `submitWithdrawRequest` path
skips nonce bookkeeping entirely. It is not a freeze, but it is a candidate replay surface —
test it separately instead of folding it into a lock claim.

**Source tree beats bytecode reconstruction.** `cast interface -c 537713` fails (no Etherscan key
for the chain) and Sourcify was unreachable, but the full contract source lives under
`~/.huntos/workspaces/relay-settlement-*/smart-contracts/contracts/`. Check there FIRST; it turns
selector guessing into a grep.

## Freeze / fund-lock vector ledger (all 6 hypotheses REJECTED, each with a named gate)

Run this table before re-deriving any "attacker locks the hub / alias / withdrawal queue" story.
Every row was tested in-session; all 13 tests PASS (i.e. the *rejection* is proven).

| Hypothesis | Dies at | Proof |
|---|---|---|
| Nonce griefing to block a victim's withdraw | Need a valid victim signature over the attacker's `receiver` | `test_V5` → `CallerIsNotApproved`; `test_V1` only passes when handed the victim's sig (= theft, not griefing) |
| `payloads[]` storage-growth DoS | `callerIsSpender \|\| callerIsOperator \|\| sig` (`RelayAllocator.sol:265-281`) | only the alias owner can spam ⇒ self-harm; 343k–366k gas/payload, 384 B each |
| Rate-limiter drain ⇒ withdrawal DoS | `onlyRole(CONSUMER_ROLE)` (`RelayUsdRateLimiter.sol:132`) **and** it is only called from `FAST_MINT` (`RelayOracleV2.sol:362`) — `RelayAllocator` never calls it | `test_F5` revert `AccessControlUnauthorizedAccount` |
| `callRequests` / idempotency pre-fill | written only after allocator sig validates (`RelayDepository.sol:161-171`); `markExecuted` is `WRITE_ROLE` (`RelayOracleIdempotencyStore.sol:119`) | source-read |
| ERC-6909 tokenId / ERC20View collision | `CREATE` (not CREATE2) from the hub itself + idempotent guard (`RelayHub.sol:543-545`); `_mint` needs `OPERATOR_ROLE` (`:383`) | `test_V3` PASS |
| `RelayExecutor.usedRequests` latch | set before auth (`RelayExecutor.sol:206`) but the whole tx rolls back ⇒ no latch | source-read |
| Rate-limiter drain ⇒ "permanent" fast-mint freeze | bucket `rate == capacity` (both `1e22`) ⇒ refills fully in ONE block; plus `FeedRouteNotFound` blocks unpriced tokenIds | `test_1c`/`test_1d` PASS — NO-LOCK |
| Nonce burn via attacker submit | `consumeSpenderSignature` early-returns on empty sig; unsigned `submitWithdrawRequest` never writes `usedNonces`; signed path keys on `keccak256(params.spender)` | `test_2b`/`test_2c`/`test_2d` PASS — NO-LOCK |
| `payloads[]` pre-fill | no external setter exists — probed 4 candidate selectors, all `callable: false`; write site is after all three gates (`RelayAllocator.sol:296`) | `test_3a` PASS |
| ERC20View "lock" of a second tokenId | failure attaches to the **tokenId**, not the alias: the same id fails for ANY recipient and succeeds for ANY recipient when fresh ⇒ nothing ever moved, nothing stranded | `test_4b` PASS |
| TokenId squatting with `mint(...,0)` | `onlyRole(OPERATOR_ROLE)`; and a 0-mint is a **gas OPTIMIZATION** for the next deposit (53k vs 916k gas), not a squat | `test_5a`/`test_5c` PASS |

**`RelayHub.burn()` panics on insufficient balance** (`0x4e487b71`, arithmetic underflow). Loyal
matrix: mint 10 → burn 1 OK; burn 100>9 panic; burn never-minted id panic; burn 0 OK; burn-all OK;
burn-again panic. Verdict **NO-LOCK** — the panic is inside one tx so everything rolls back
atomically; `usedNonces` and `payloads` stay unwritten. Cite it as an unclean-revert quality note,
never as a freeze.

**`suspended[]` is `onlyOwner`** — pranked as an attacker it reverts
(`test_T6_suspended_is_privileged_only` PASS, `attacker suspend() success: no`). Alias freeze exists
but is PRIVILEGED-ONLY: never a reportable unprivileged finding.

### Replay after the unsigned path: killed by `payloads[hash]`, not by `usedNonces`
`usedNonces` genuinely is written ONLY inside `consumeSpenderSignature`
(`RelayAllocator.sol:351`,`:357`), so the `callerIsSpender`/`callerIsOperator` paths never touch it.
That looks like a replay hole and is not one, because a second guard covers it independent of the
nonce: `payloads[withdrawRequestHash]` is written on first submit and blocks a byte-identical
resubmit, `params.nonce` is part of that hash, and the builder nonce is
`keccak(block.number, …)` so it rotates every block. Fork-proven
(`test_T3`/`test_T4` PASS, `payloads(hash).length == 0` pre-submit, builder registered for
`("base", abi.encodePacked(depository))`).
**Rule: before calling a missing-`usedNonces` write a replay bug, enumerate EVERY other dedupe /
idempotency guard on the same path.** Two independent anti-replay layers here.

**Two reusable lessons from this sweep:**
1. **A rate limiter on the deposit path is not a withdrawal gate.** Before crediting any limiter
   with "freeze" impact, `grep 'IRateLimiter(.*).consume'` and confirm which contract calls it.
   In Relay it is mint-only; draining it slows *deposits*, and `FastMintRejected` reverts the whole
   execution **without consuming the idempotency key** (`RelayOracleV2.sol:411-413`), so nothing is
   permanently lost.
2. **Nonce-space sharing is not a griefing primitive on its own.** `spenderKey =
   keccak(params.spender)` (`RelayAllocator.sol:337`) omits the chain, so all chains share a nonce
   space — but every write to `usedNonces` sits behind `consumeSpenderSignature`, which needs a
   real key. Also `computeNonce` includes `block.number`
   (`EthereumVmPayloadBuilder.sol:241`), so a squatted nonce is **recoverable on the next block**.
   Check for a block-derived nonce before claiming permanent lockout.

## Public-RPC log-scan geography bleed (cost 3 wasted scans in one session)

Scanning `eth_getLogs` on a public settlement-chain RPC (`https://rpc.chain.relay.link`)
returns **structurally inconsistent results depending on the block window**, and this
manufactures false "0 events ⇒ surface is dead" verdicts:

| Window thrown at it | Result |
|---|---|
| 40–100 blocks, addresses OR topics filter | logs returned correctly |
| 300 / 800 blocks | `result: []` — silently empty, no error |
| 12k-block chunked loop of 20-block windows | works, but each curl is ~0.2 s ⇒ whole scan ~2 min |

So an unbounded "scan the last N thousand blocks" script reports **0 matches** and looks
like proof the event never fires. It is not. Rules that actually hold here:

- **Probe span sensitivity first.** Submit the SAME query at 40 / 100 / 300 / 800 blocks.
  If the wide windows return `[]` while the narrow one returns hits, the endpoint has a
  log-window cap and every wide-window negative is worthless.
- **Drive wide scans as a 20-block-window loop with a small sleep**, not one large range.
  Trade: ~5 chunks/s at 0.2 s each ⇒ budget ~2 min per 1.5k blocks. Plan the round budget
  around that instead of letting a 600 s script timeout kill it.
- **Never conclude "no such events exist" from a single wide-range empty result.** Cross-checks
  that cost nothing and settle it: pull ANY log from the contract with no topic filter in a
  40-block window and enumerate `topics[0]` with a `Counter` — that reveals which events are
  actually live and gives you the real topic0 set to filter on.
- Topic0 must be computed against the SOURCE event signature, not a guess:
  `cast keccak "Transfer(address,address,address,uint256,uint256)"` →
  `0x1b3d7edb…` (ERC-6909 five-arg form). A 3-arg ERC-20 `Transfer` hash returns zero logs
  forever and looks exactly like an empty surface.

### ERC-6909 Transfer log layout (relay-style hub, verified live)
`topics = [topic0, from, to, id]` and `data = abi.encode(caller, amount)` — i.e. **four indexed
topics, two unindexed data words**. The `id` is `topics[3]`, NOT `data[0]`. Reading amount from
`data[0]` yields the caller address and silently corrupts every volume figure.

### Token-id census via storage getter, not events
When you need "which tokenIds actually exist / are active", the cheap and correct path is the
contract's own getter: `erc20Views(uint256)` selector `0x548834ba`, called per candidate tokenId
over `eth_call`. That gave 94 distinct tokenIds and proved **0 tokenIds with activity but no
ERC20View** — a direct, cheap refutation of the "ERC20View lock leaves funds stranded" story,
without needing a single event scan. Prefer a storage getter over a log scan whenever one exists.

## Frozen-vs-not: the ERC20View "lock" is a non-issue
`RelayHub._createERC20View` (`RelayHub.sol:542-551`) is idempotent (returns early when
`erc20Views[tokenId] != address(0)`) and only ever called when `totalSupply[id] == 0`. Verified
on 76 live tokenIds with balance activity: **every one has an ERC20View**. So a tokenId can never
have funds and no view. The earlier ~985M-gas "second distinct tokenId reverts" observation is a
fork-runner artifact inside `CREATE`, not a fund lock — do not upgrade it into a freeze finding.

## Off-chain footgun class: `isOperator` returns TRUE for ANY account (verify the actual body)

A very common misreading of Relay-style hubs: the report claims "`hub.isOperator(<any address>, <operator>) = true`
is a global permission bypass." **Read the body before believing it:**

```solidity
// RelayHub.sol:177-182
function isOperator(address account, address operator) public view returns (bool) {
  return hasRole(OPERATOR_ROLE, operator) || _isOperator[account][operator];
}
```

`account` is honoured on the `_isOperator` branch. The `hasRole` branch is the normal OpenZeppelin
semantic "a role holder is an operator for everyone" — which is EXACTLY how `RelayAllocator`
legitimately burns from an alias (`callerIsOperator`). So:

- `isOperator(0x…0001, ALLOCATOR) = TRUE` is **not** a bug; it is the designed path. Only `operator`
  is being checked on that branch, and the role holder must actually BE the operator argument.
- An external attacker calling `_submitWithdrawRequest` with `msg.sender = attacker` gets
  `isOperator(alias, attacker)` → `hasRole(OPERATOR_ROLE, attacker) = false` and
  `_isOperator[alias][attacker] = false` ⇒ **false**. `GateProbe.t.sol` fork-proved this.
- Therefore the whole "any account can burn any alias" story collapses. The only way to exploit the
  role branch is to BE the role holder (allocator) or call through a contract that holds it.

**Report rule:** before writing "global operator bypass", grep the `isOperator` implementation and
run the attacker-side assertion (`isOperator(alias, randomAttacker) == false`). If the assertion
holds, the finding is dead — do not ship it as a permission bug.

## Burn-to-zero is RECOVERABLE — severity depends on who can call the recovery leg

Corrects the F-1 "unrecoverable" wording above. `hub.transfer(0, …)` really does move value to
`balanceOf[address(0)]` with `totalSupply` unchanged, but that balance is **not** bricked — it can
be pulled back out, and the puller determines the real severity:

- **`ERC20View.transferFrom(0, me, id, amt)` works.** `RelayHub.transferFrom` short-circuits the
  allowance check when `msg.sender == erc20Views[id]` (`RelayHub.sol:258`), so the hub's own view
  contract can drain `address(0)` with no allowance. Fork-proven: seeded 30e18 to zero, view pulled
  it to 0, test contract received 30e18 (`test_R1_erc20view_can_pull_from_zero` PASS).
- **An arbitrary EOA cannot do the same.** Calling `ERC20View.transferFrom` directly from an
  attacker address (or from the hub with an attacker `msg.sender`) reverts —
  selector `0x2cf85d96` (allowance error). Fork-proven (`test_R3` PASS, revert data captured,
  attacker balance stays 0).
- **Recovery therefore requires `OPERATOR_ROLE` or the ERC20View itself** (`test_R2` PASS).

So the honest finding is **"unprivileged permanent destruction of your OWN balance + a
`totalSupply`/`balanceOf` accounting divergence"** — irreversible from the user's side, recoverable
only by protocol privilege. It is *not* "protocol funds permanently lost" and it is *not* a
steal primitive. Grading note: writing "irrecoverable" without testing the recovery leg was the
overclaim; always attempt the recovery path BEFORE quoting severity.

### The negative test `vm.prank(address(0))` does NOT prove unrecoverability
`vm.prank(address(0))` **succeeds** as an identity — a test asserting "address(0) cannot send must
revert" FAILS, because forge happily acts as the zero address (it is just bytes). A `[FAIL: next
call did not revert as expected]` on such a test is NOT evidence of a protocol hole; it is a
harness assumption that doesn't hold. Prove unrecoverability *structurally* — no private key exists
for `address(0)`, and the only in-contract paths are role-gated or the ERC20View shortcut.

## Severity must be re-derived from the ATTACKER's value, not from the code path

`hub.transfer(0, …)` is code-real, attacker-callable, and produces zero attacker value. Two
independent checks kept killing escalated versions of it:

| Claim | Check that kills it | Result |
|---|---|---|
| "Attacker redirects a victim's balance to 0" | `transferFrom(victim, 0, …)` pranked as attacker | reverts (allowance) |
| "Attacker destroys protocol value" | `transfer(0, …)` pranked as attacker | reverts (no balance) |
| "Oracle-signed TRANSFER to 0 destroys funds" | reachable — `_executeAction` TRANSFER calls `hub.transferFrom(from, to, …)` with no zero check | true, but requires an oracle signature ⇒ **privileged / footgun**, not attacker primitive |

Rule: for every burn/destroy reachability row, fill in (a) can an unprivileged caller trigger it,
(b) whose value moves, (c) can the attacker convert the result to anything. If (a) is "self only"
or (c) is "nothing", the row is a DESIGN-OBSERVATION, not a bounty finding.

## Live-data verdict: burn-to-zero never happened on production
Scanned ~11.4k `Transfer` logs over the last ~1000 hub blocks: 757 events have
`topics[2] == address(0)`. **All 757 are legitimate burns from `submitWithdrawRequest`**
(selector `0x771dc6a2`, `to == allocator 0x613D3c58…`), sender is the sweeper/allocator, and they
arrive batched in the same tx as the withdraw. Confirmed by state: `balanceOf(address(0), usdcId) = 0`
across 79 active tokenIds, and `totalSupply` matches the view's `totalSupply()`. So the zero-address
path is **latent in production** — quote it as reachable code, not as an observed incident.

**Log-filter trap that cost a cycle:** `eth_getLogs` with a hand-built `topic0` returned 0 for
`PayloadBuilt` even though the event is live. Compute `topic0` from the SOURCE signature
(`cast keccak "PayloadBuilt(bytes32,bytes,bytes32[])"`) — a guessed/truncated topic silently
yields an empty surface that looks exactly like "the event never fires".

## Freeze vs. drain vs. burn are three different reports — do not merge them

The user will reject a mixed report. Keep them separated and label each with reachability:

| Class | Definition | Reportable if |
|---|---|---|
| **Drain** | move value to an attacker-controlled address | unprivileged AND value lands with attacker |
| **Freeze / lock** | value stays in place but becomes unusable by its owner | unprivileged AND recovery needs a role/multisig |
| **Burn / destruction** | value leaves the accounting for everyone | any caller, if reachable without a role |
| **Privileged abuse** | requires a role, owner key, or admin call | **NOT reportable as a contract bug** — key-management risk |

`hub.transfer(address(0), id, amount)` and `hub.transferFrom(x, address(0), …)` are **burn**, not
freeze: the value is destroyed, `totalSupply` does not move, and nothing is recoverable. They are
also **unprivileged but self-directed** — an attacker cannot aim them at someone else's balance
without an allowance. Say "unrecoverable destruction + broken solvency accounting", not "attacker
freezes victims".

## A "successful" exploit that returns no value is a non-finding

`isOperator` says the allocator may burn any alias. Running that fork test (burn 500,000e18 from a
random alias) PASSES — and produces **zero profit**: the tokens burned are internal ERC-6909
balances with no redemption path for the attacker. Before escalating any permission-bypass result,
ask: *what does the attacker actually receive?* If the answer is "a burned balance in the
protocol's own ledger", the impact section is empty. Either find the follow-on leg that converts
internal balance into chain value, or downgrade the finding to a design observation.

## Speed-vs-verify note

A full freeze sweep is affordable: `yarn install` + `forge test --match-path 'test/Freeze/*'` `yarn install` + `forge test --match-path 'test/Freeze/*'`
compiled 148 files in ~10 s and ran 13 tests in ~40 s. Do **not** shortcut to source-reading only —
the `test_F3` `totalSupply`-unchanged result and the `receiver=0` supply-zero result are both facts
that reading alone would have stated wrongly.

## Foundry harness roles (cost 4 red compile/run cycles in one session)

### Harness bugs that manufacture FAKE verdicts (grep these before reporting a revert)

Five "failures" in one session were all harness artifacts, and three of them looked exactly like
protocol gates. Fix these before you write a single word about a blocker:

- **`vm.prank` is consumed by the NEXT call, including a nested getter.** `hub.burn(x, id,
  hub.balanceOf(...))` spends the prank on `balanceOf`, so `burn` runs as the test contract and
  reverts `AccessControlUnauthorizedAccount(0x7FA9385bE10…, OPERATOR_ROLE)`. It reads like a
  protocol auth bug; it is your own prank. **Rule: any expression with a nested call needs
  `vm.startPrank`/`vm.stopPrank`.** Same trap inside a helper: a `vm.prank` at the end of a helper
  leaks forward and silently authorises an unrelated later call.
- **`console.log` is a cheatcode ⇒ must not be in a `view`/`pure` test.** Forge reports it as a
  bare `EvmError: Revert` on a test whose only odd feature is a log. Drop the `view`.
- **`console.log("label", str)` does not compile** where `str` is a `string` variable in this
  forge-std. Split into two statements: `console.log("label:"); console.log(str);`
- **`address[N] constant` is illegal** (error 9259). Return the array from an `internal pure`
  function instead.
- **Stack-too-deep** in a long test: extract `_sel(bytes)`, `_try(...)`, `_seed(...)` helpers rather
  than reaching for `--via-ir` (which changes codegen and can mask the thing you are measuring).

Also, when an assertion fails on a decoded struct field, suspect **field order** before suspecting
the contract: a wrong `TokenBucket` layout produced `rate = 1e22` where the test expected `1`, and
the real answer was "my struct put `rate` where `lastUpdated` lives".

- The grant *caller* must hold `ADMIN_ROLE`. Putting `vm.prank(allocatorOwner)` on
  `hub.grantRole(...)` fails with `AccessControlUnauthorizedAccount(…, 0xa49807…)` = the admin
  role hash. Grant `ADMIN_ROLE` to the harness first, then grant `OPERATOR_ROLE` to the allocator
  (the real deployment's allocator is an operator, because the withdraw path calls `burn`).
- `makeAddrAndKey` returns **`(address, uint256)`** — writing `(pk, addr)` is a compile error.
- `address(0xD3P0)` is not valid Solidity hex; use `address(uint160(0xD3B0))`.
- Don't shadow builtins/keywords: `exp` (where array assignment was wanted) and `view` both fail.
- Missing `lib/forge-std` is a repo gap, not a bug: `curl` the release tarball into `lib/forge-std`,
  and run `yarn install` at the monorepo root for `node_modules/solady` + `@openzeppelin`.
- Enumerate the registry with BOTH `encodePacked` and `encode`, and with NAME-string chain ids,
  before ordering any "gate is closed" test.
- Add control tests: non-operator burn MUST fail; operator path MUST work; `owner()`/codesize
  must be asserted, not assumed.
- Assert the negative explicitly (`isOperator(alias, randomAttacker) == false`) — that assertion
  IS the deliverable when the chain is blocked.

## Decode hygiene that cost five retractions in one session

- **Never hand-parse event `data` into 32-byte words when the event has dynamic params.** Offsets
  from one dynamic field bleed into your word grid and manufacture fake "addresses" (observed: a
  phantom `0xb2000000…` receiver that appeared in 0 of 609 payloads when properly ABI-decoded).
  Use `abi.decode` semantics or `cast`/forge with the real ABI.
- **Divide by the token decimals before calling a number large.** A raw `11900673838987117933`
  wei-USD value is $11.90, not $11.9 million. This produced one full retraction; the fix is to
  print the divided value alongside the raw integer every time.
- Read the struct definition from source BEFORE writing a decode. The real
  `WithdrawRequest` also carries `receiver` and `data`; a decode written from memory silently
  dropped two fields.
