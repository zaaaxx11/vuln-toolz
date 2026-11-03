# RelayHub-Style Operator Fund-Movement Audit Notes

Source pattern examined: `RelayHub.sol` + paired `ERC20View.sol`.

## Key distinction: internal accounting vs external fund movement

In hub-style ERC-6909 implementations, operator functions often move only internal
`balanceOf`/`totalSupply` state. That is balance inflation/deflation, not a real
external fund transfer.

## Operator surface to enumerate

- `mint(receiver, id, amount)` — internal supply increase.
- `burn(sender, id, amount)` — internal supply decrease.
- `setOperatorFor(account, operator, approved)` — privilege change.
- `transfer(receiver, id, amount)` — owner-initiated internal move.
- `transferFrom(sender, receiver, id, amount)` — approved/operator-initiated internal move.
- `approve / approveFor / permit` — allowance changes only.

## External fund movement signals to look for

- Any function accepting a `receiver`/`to`/`recipient` parameter and also calling:
  - `call{value: ...}`, `transfer`, `send`
  - ERC-20 `transfer`/`transferFrom`
  - `msg.sender.call{value: x}`
- `withdraw`, `sweep`, `claim`, `payout`, `setFeeRecipient`
- `receive()` / `fallback()` that can be triggered to trap incoming value
- External view/bridge contracts (`ERC20View` or similar) that can trigger real
  token transfers on the hub’s behalf.

## Burn is not a withdrawal path even if uncapped

If `burn()` has no receiver parameter and emits `Transfer(msg.sender, sender, address(0), ...)`,
it cannot send funds to an attacker-controlled address. Treat uncapped burn as a
supply-deflation issue, not theft.

## ERC20View / adapter pitfalls

- View contracts may call hub functions that alter state.
- `approveFor` restricted to the registered ERC20View address can become a state-changing
  entrypoint if the view is upgradeable or if multiple tokens share infrastructure.
- `emitTransferEvent` / `emitApprovalEvent` are event-only helpers; they do not move funds.

## Verdict hygiene

State the exact function signature and destination parameter, then classify:

1. Direct arbitrary fund movement to attacker address: PROVEN / REFUTED / NOT APPLICABLE
2. Internal balance inflation without external asset backing: PROVEN / REFUTED
3. Indirect path via external contract dependency: PROVEN / REFUTED / REQUIRES DEEPER REVIEW
