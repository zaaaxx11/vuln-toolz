# Relay ExecuteAndWithdrawRequest — Validation Gap Classification

Proven on `relay-protocol-oracle` HUNT B round 4, 2026-10-30.
Companion to `signature-binding-sign-vs-execute.md` §5g (the same finding class
generalised).

> ## ⚠️ READ THIS FIRST — THIS FILE'S ORIGINAL TABLE WAS WRONG
>
> The first version of this reference classified nine fields as **FORMAT-ONLY** and
> ranked them as exploit windows ("Redirects entire withdrawal payout to attacker").
> **Every value-bearing row was refuted in the following session.** Verified against
> `normalizeOrder` in the settlement SDK: `receiver`, `outCurrency`, `outAmountMinimum`,
> `outChainId`, `fees[].recipient`, `fees[].amount`, `deadline` are all **inside the
> `hashStruct(Order)` preimage**, and the resulting `orderId` is compared to the real
> on-chain `depositId` (`index.ts:326`). Mutating any of them breaks the equality ⇒ the
> deposit is not real ⇒ rejected.
>
> Correct verdict: **BOUND-VIA-HASH**, not FORMAT-ONLY. See
> `stealth-auth-spoof-hunting.md` §2.1 for the general mechanism and the mandatory
> preimage test. The table below is retained **corrected**; the "What Is Missing"
> section describes what a *reader* will not find, not an exploitable absence.

## Corrected field classification

The authoritative test is `getOrderId = hashStruct(ORDER_EIP712_TYPES, normalizeOrder(order))`
from `@relay-protocol/settlement-sdk/dist/order/index.js`. `normalizeOrder` emits every
one of these fields into the hashed payload:

```
version, solverChainId, solver, salt,
inputs[].payment.{chainId,currency,amount,weight},
inputs[].refunds[].{chainId,recipient,currency,minimumAmount,deadline,extraData},
output.{chainId,deadline,extraData},
output.payments[].{recipient,currency,minimumAmount,expectedAmount},
output.calls[],
fees[].{recipientChainId,recipient,currencyChainId,currency,amount}
```

| Field | Verdict | Basis |
|-------|---------|-------|
| `inChainId` | CHECKED | matched vs `orderInput.payment.chainId` (`index.ts:340`) |
| `inCurrency` | CHECKED | matched vs deposit currency until fees charged (`index.ts:371-399`) |
| `orderAddress` | CHECKED | recomputed from `depositor + depositId + timestamp + chainId + vmType` (`index.ts:356-362`) |
| `depository` | CHECKED (static config) | from chain config, not request (`index.ts:1658`, `:1716`) |
| `outChainId` | **BOUND-VIA-HASH** | in `output.chainId` preimage ⇒ mutating breaks `depositId == orderId` |
| `outCurrency` | **BOUND-VIA-HASH** | in `output.payments[].currency` preimage |
| `outAmountMinimum` | **BOUND-VIA-HASH** | in `output.payments[].minimumAmount` preimage |
| `receiver` | **BOUND-VIA-HASH** | in `output.payments[].recipient` preimage |
| `fees[].recipient` | **BOUND-VIA-HASH** | in `fees[].recipient` preimage |
| `fees[].amount` | **BOUND-VIA-HASH** | in `fees[].amount` preimage |
| `deadline` | **BOUND-VIA-HASH** | in `output.deadline` preimage |
| `data` | FORMAT-ONLY, **inert** | caller-supplied, but consumer reads `receiver: params.receiver` (signed request) — see below |
| `nonce` | FORMAT-ONLY | pass-through (`index.ts:210`, `:246`); replay guard is `usedRequests[digest]` on-chain, one-shot |

## The only genuinely-outside-the-preimage field: `data`

`data` is caller-controlled `bytes` whose **length is attacker-chosen** (52 → 68 → 56 bytes
demonstrated by executing the real signing harness). That part is real. But it does not
route value:

```solidity
// payload-builders/GatewayVmPayloadBuilder.sol:266
receiver: params.receiver,          // ← from the SIGNED request, not from data
data:     data.destinationData      // ← caller blob goes here, payload metadata only
```

⇒ a caller-controlled field still needs a **consumer that routes value by it**. Check the
consumer before grading. Here there is none.

## The real preparer-side findings that DO stand

These were confirmed in source and are the durable output of the engagement:

1. **Advisory API auth** — `src/http-server.ts:70-89`: an invalid/absent `x-api-key` does not
   reject; it only applies a per-IP rate limit, then `return done()`. All 14 attestation routes
   reachable keyless at limited QPS. No roles, no scopes (`src/common/api-key.ts`, flat map).
2. **`force` bypass** — `solver-fills/v1.ts` and `solver-refunds/v1.ts` accept `force: true`,
   gated only by that advisory key. Schema text: *"Force attestation even if the order solver
   fill is not valid."* Path hardcodes `totalWeightedInputPaymentBpsDiff: 0n`, skipping all
   payment verification. Strongest ENTRY in the target — but one layer above the money.
3. **Input currency unconstrained after fees** — `index.ts:371-399` + route schema comment
   *"afterwards any currency is allowed"*. Live census: `feesChargedByOrderAddress == true` on
   40/40, then 120/120 sampled orders — so the gate is always open in production, **but**
   0/120 orders held more than one token, so the primitive has no exploitable state.

## Why the chain still does not close (STRUCTURAL CEILING)

```
orderId = hashStruct(Order{…everything…})
required: deposit.result.depositId === orderId      // index.ts:326, :882 filter
⇒ every payout field is cryptographically anchored to a real deposit
⇒ forging an order requires the solver's signature over it
⇒ "attacker holds no keys" and "value moves to attacker" are mutually exclusive here
```

Verdict: `BLOCKED — STRUCTURAL`. See `stealth-auth-spoof-hunting.md` §7.1.

## Key files

| File | Lines | Purpose |
|------|-------|---------|
| `src/services/attestation/index.ts` | 303-312 | `orderId` derivation + `verifyMessage` over it |
| `src/services/attestation/index.ts` | 326 | `deposit.result.depositId !== orderId` ⇒ throw (the anchor) |
| `src/services/attestation/index.ts` | 882 | `deposits.filter(d => d.result.depositId === orderId)` (same anchor, fill path) |
| `src/services/attestation/index.ts` | 262-443 | `_attestExecuteAndWithdrawDeposit` |
| `src/services/attestation/index.ts` | 1638-1735 | `_getExecuteAndWithdrawDestination` |
| `src/common/signer.ts` | 99-162 | `signExecuteAndWithdrawRequestMessage` — signs verbatim |
| `node_modules/@relay-protocol/settlement-sdk/dist/order/index.js` | 40-140 | `ORDER_EIP712_TYPES` + `normalizeOrder` + `getOrderId` ← **the file that settles the argument** |
| `contracts/payload-builders/GatewayVmPayloadBuilder.sol` | 266 | `receiver: params.receiver` — proves `data` cannot redirect |
