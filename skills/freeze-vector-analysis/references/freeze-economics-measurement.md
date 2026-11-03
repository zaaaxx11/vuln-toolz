# Freeze Economics Measurement Template

Use this template when measuring the economics of any rate-limiter / bucket / freeze
vector on a live chain. It encodes the exact probes, calculations, and decision rules
from the Relay session (chain 537713, Nov 2026).

## Live probes

```bash
# 1. Bucket state per claimed victim chain
cast call <limiter> "getBucket(string)((uint128,uint32,bool,uint128,uint128))" <chain> --rpc-url <rpc>

# 2. USD decimals
cast call <limiter> "USD_DECIMALS()(uint256)" --rpc-url <rpc>

# 3. Who holds CONSUMER_ROLE?
CR=$(cast keccak "CONSUMER_ROLE")
cast call <limiter> "hasRole(bytes32,address)(bool)" $CR <addr> --rpc-url <rpc>

# 4. Topic0 for limiter event (e.g. TokensConsumed)
cast keccak "TokensConsumed(string,uint256,uint256)"

# 5. Actual fast-mint tx gas
cast tx <txhash> --rpc-url <rpc> | grep gasUsed
```

## Event census recipe

1. Compute topic0 from the actual event signature in source.
2. Run `cast logs --address <limiter> <topic0> --from-block 0 --to-block latest --rpc-url <rpc>`.
3. Parse each event into: block, tx, chainTopic, amount, remaining.
4. Convert amount to USD: `amount_raw / 1e18` because `USD_DECIMALS = 18`.
5. Compute the table below. State every number.

| Metric | Formula / source | Value |
|---|---|---|
| capacity ($) | `getBucket(...).capacity / 1e18` | |
| rate ($/s) | `getBucket(...).rate / 1e18` | |
| full refill (s) | `capacity / rate` | |
| total consumed ($) | sum(amount across all events) | |
| max per event ($) | max(amount) | |
| max per block ($) | max(sum(amount) grouped by block) | |
| blocks with >1 event | count of blocks with multiple events | |
| min remaining ($) | min(remaining) | |
| events leaving bucket < $1 | count where remaining < 1 | |
| events leaving bucket == $0 | count where remaining == 0 | |

## Economic viability rubric

| Factor | Freeze-viable if |
|---|---|
| Attacker cost | ≪ victim loss (ideally < 1%) |
| Recovery time | Long (hours/days), not seconds |
| Repeatability | Attacker can repeat without new input from victim |
| Evidence | Pattern appears ≥ 2× in live history, or code proves unilateral exploitability |
| Gas vs value | Gas ≪ value at risk, AND attacker keeps the value |

## RPC scanner pattern (public chain with narrow log-window cap)

```python
STEP = 20000  # reduce if "Max retries exceeded"
for b in range(0, latest, STEP):
    to = min(b + STEP, latest)
    # cast logs is more reliable than eth_getLogs for wide scans
    subprocess.run(["cast", "logs", "--address", limiter, topic0,
                    "--from-block", str(b), "--to-block", str(to),
                    "--rpc-url", rpc])
    time.sleep(0.2)
```

## Decision rule

If `rate >= capacity`, write this sentence verbatim:

> "An exhausted bucket is fully replenished inside one block. Read the rate/capacity ratio
> from `getBucket` before writing any 'permanent DoS via drain' sentence — on this deployment
> the ratio is N, so the answer is 'self-healing', full stop."

If `hasRole(CONSUMER_ROLE, allocator) == false`, write:

> "The allocator does not hold CONSUMER_ROLE. It cannot drain the bucket itself."

## Cross-chain nonce sharing test

Source check:
- If `usedNonces[keccak256(params.spender)][nonce]` omits chainId, note that the nonce space IS shared.
- Check whether `computeNonce` includes `block.number`. If yes, squatted nonce is recoverable next block.
- Check whether unsigned path writes `usedNonces`. If `consumeSpenderSignature` early-returns on empty sig, unsigned path never touches it.

Live check:
```bash
# Does the allocator hold CONSUMER_ROLE?
cast call <limiter> "hasRole(bytes32,address)(bool)" $CR <allocator> --rpc-url <rpc>

# Does the limiter log show consumption from a tx NOT originating at the allocator?
# If yes, another actor holds the role.
```
