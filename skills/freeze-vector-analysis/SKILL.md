---
name: freeze-vector-analysis
description: >
  Audit "freeze / lock / drain" claims against a live on-chain protocol by measuring
  real economics, scanning event history, and checking whether the claimed vector has
  already occurred. Use when the user asks whether funds/aliases/nonces can be frozen,
  whether a rate-limiter or limiter module can be drained, or whether any freeze vector
  is already observable on-chain. Focus: economic viability + empirical evidence, not
  just source-reading.
  Trigger: 'freeze vector', 'analisis freeze', 'drain the bucket', 'alias stuck',
  'nonce freeze', 'rate limiter freeze', 'freeze sudah terjadi', 'freeze on-chain',
  'buktikan freeze', 'ekonomi freeze'.
---

# Freeze Vector Analysis

Class-level workflow for proving or disproving freeze/lock/drain claims on a live protocol.

## Method

### 1. Separate the classes first

Before measuring anything, label each claim as one of:

- **Drain**: value moves to an attacker-controlled address.
- **Freeze / lock**: value stays in place but becomes unusable by its owner; recovery needs a role/multisig.
- **Burn / destruction**: value leaves the accounting for everyone.
- **Privileged abuse**: needs a role/owner/admin call. NOT reportable as a contract bug.

Mixed reports get rejected. Keep them separated.

### 2. Measure rate-limiter / bucket economics from `getBucket` live

For any limiter or bucket module:

1. Call `getBucket(chainId)` for every claimed victim chain.
2. Record `capacity`, `rate`, `isEnabled`. Compute `capacity / rate`.
3. If `rate >= capacity`, the bucket self-heals in ≤ 1 block. State that explicitly.
4. Run the full event census (see §3) and compute:
   - total consumed
   - max per event
   - max per block
   - min remaining bucket
   - count of events that left bucket < $1
   - count that left bucket == $0
5. Measure actual gas cost of the attacker path; compare attacker cost vs victim loss.
6. Confirm who holds the consumer role: `hasRole(CONSUMER_ROLE, <addr>)`.
   If the role is NOT held by the withdraw path, that path cannot drain the bucket.
7. Confirm via source grep whether `consume()` is called from the withdraw path or only
   from `FAST_MINT` / mint path. If only from mint, classify as deposit slow-down, not freeze.

### 3. Run the full event census, not a sample

For rate-limiter events (e.g. `TokensConsumed`):

```bash
# Reliable: chunked cast logs
cast logs --address <limiter> <topic0> --from-block <start> --to-block <end> --rpc-url <rpc>
```

For ERC-6909 Transfer events on a hub:

```bash
cast keccak "Transfer(address,address,address,uint256,uint256)"
# => 0x1b3d7edb...  (five-arg form)
```

Then scan with the same chunked `cast logs` approach. Do not use a single unbounded range;
many public RPCs silently return `[]` for wide windows.

Parse into a table: block, tx, amount, remaining, chainTopic.

### 4. Check "already happened" with economic thresholds

A freeze vector is "already happened" only if:

- There is a **sustained** inflow pattern to the frozen object (alias / vault / queue),
  not a single inbound transfer.
- The bucket was ever driven to near-zero or below the victim's normal operational need.
- There is **repeatability**: the same actor / pattern / amount class appears multiple times.

For dust / griefing: look for amount = 0, amount = 1 wei, or repeated identical micro-amounts
across many blocks from the same caller. `consume()`-style modules usually reject amount = 0
and usdValue = 0 fail-closed; verify this in source before claiming a dust path.

### 5. Cross-chain nonce sharing is not a freeze by itself

If `usedNonces` keys on `keccak256(params.spender)` without chainId:

- The nonce space IS shared across chains for the same spender bytes.
- But every write requires a real spender signature over the EIP-712 digest that DOES bind
  `spenderChainId`. Attacker cannot force this.
- If `computeNonce = keccak(block.number, address(this), chainId, depository, params)`,
  a squatted nonce is recoverable on the next block. Do not claim permanent lockout without
  checking for a block-derived nonce.

## RPC scanner gotchas

### `eth_getLogsWithCursor` shape

Some RPCs return a dict, not a list:

```python
res = rpc("eth_getLogsWithCursor", [filter])
# WRONG: got = res.get("result", [])
# RIGHT:
if isinstance(res, dict):
    got = res.get("logs", [])
    cursor = res.get("cursor")
else:
    got = res or []
    cursor = r.get("cursor")
```

A wrong branch silently produces zero decoded events even when logs exist.

### Wide-window log emptiness

`eth_getLogs` on some public RPCs:

- 40–100 blocks: works
- 300–800 blocks: returns `[]` with no error
- >10k blocks: timeout / oversize

Probe span sensitivity before trusting a negative. When wide windows are empty, `cast logs`
is the reliable fallback.

### Budgeting wide scans

Drive wide scans as a 20-block-window loop with a small sleep. Budget ~2 min per 1.5k blocks.
Plan the round budget around that; do not let a 600s script timeout kill the scan.

## Repeatability / economic viability rubric

| Factor | Freeze-viable if |
|---|---|
| Attacker cost | ≪ victim loss (ideally < 1%) |
| Recovery time | Long (hours/days), not seconds |
| Repeatability | Attacker can repeat without new input from victim |
| Evidence | Pattern appears ≥ 2x in live history, or code proves unilateral exploitability |
| Gas vs value | Gas ≪ value at risk, and attacker keeps the value |

## Output contract

For each vector, state:

1. **Dies at**: the exact gate (function + line) that blocks the unprivileged path.
2. **Proof**: source-read, fork test name, or live census statistic.
3. **Economic verdict**: cost to attacker, loss to victim, recovery time, repeatability.
4. **Already happened?**: YES / NO / PARTIAL, with the live evidence (block, tx, amount).

Do not upgrade a finding to "freeze" without all four fields.

## References

- `references/relay-settlement-gates.md` — corrected Relay hub/allocator/oracle gates,
  freeze vector ledger, and ABI corrections. Read before re-deriving any Relay freeze story.
- `references/freeze-economics-measurement.md` — template for the live rate-limiter census,
  RPC scanner patterns, and the 6-point live-chain economics checklist.
