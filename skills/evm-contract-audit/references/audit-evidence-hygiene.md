# AGENT-C Audit Evidence Hygiene Notes (2026-11-01)

## 1. Hash/event repro must match the toolchain that produced the claim
- A quoted keccak256 result for `abi.encodePacked(chainId, token)` should be reproduced in Solidity **and** in Python using the same encoding (`abi.encodePacked` semantics), not just one path.
- In Solidity, `bytes1(0x00)` literals need explicit casting; `new bytes(19)` + loop is the safe portable pattern.
- If reproduction in Solidity contradicts the quoted hex, the quoted hex is wrong—even if it came from a prior audit.

## 2. tokenId / generateAddress asymmetry
- `generateAddress` may enforce a length gate (e.g. `spender.length == 20`) while `generateTokenId` does not. Treat them as separate assumptions; do not assume both are gated.
- 20-vs-20 keccak collision is computationally infeasible; 20-vs-19 is blocked by the length gate in `generateAddress`, but a missing gate in `generateTokenId` remains a structural inconsistency even without a known collision.

## 3. Token-bucket rate limiter semantics
- Continuous refill formula: `tokens = min(capacity, tokens + rate * dt)`.
  - Per-call max debit = `usdValue` (if `capacity >= usdValue`).
  - Per-block worst-case = `capacity` (because refill is re-evaluated once per block on first call).
  - Steady-state ceiling = `rate` USD/second.
- If `capacity == rate`, the bucket refills in 1 second and the mechanism degenerates into a per-call ceiling with no aggregate limit—opposite of rate-limiting.

## 4. Fee/math rounding direction in Solidity
- Solidity integer division floors. In fee/math conversion chains, the bounded failure mode is **undercharge to zero**, not overcharge.
- Downstream guards that check `feeAmount != 0` are bypassed by undercharge; upstream `maxFeeAmount` guards do not help because the path exits early with zero.

## 5. Foundry test compilation gotchas
- Helper functions defined inside the test contract are visible throughout the contract body. If Solidity says “not visible,” check source-order declaration or accidental shadowing.
- `bytes1`/`bytes` literals in loops need explicit casts: `out[i] = bytes1(b)` where `b` is a `uint8`.

## 6. Event log querying
- `cast logs` topic-string parsing is brittle for events with multiple non-indexed params. Use topic0 hex directly or fall back to `web3.py` `eth_getLogs` with the explicit topic array.
