# Unauthenticated JSON APIs as a reconnaissance surface (off-chain lane)

When the on-chain lanes are exhausted and the verdict is "zero keyless path", the
remaining honest surface is the **off-chain API that feeds the on-chain system**. This
is not a lesser lane: it is where deposit addresses, order ids, solver identities, and
per-user lifecycle data live. Treat it with the same evidence discipline as `eth_call`.

## §1 — Probe shape

```bash
# discovery: cheap, no auth, no key leakage in the URL
curl -s -m 20 -H 'accept: application/json' \
  -o /tmp/rN/raw_requests_sample.json -w 'http=%{http_code} size=%{size_download}\n' \
  'https://api.relay.link/requests/v2?limit=50'
```

Rules that kept this lane honest:

- **Save the raw payload to disk the instant it arrives.** Rate limits (HTTP 429)
  arrive within seconds and the window is non-repeating. `requests: 0` after a
  successful pull is a **429**, not an empty dataset — never report "no orders found"
  without checking `%{http_code}`.
- **Positive control for the API is the previous successful response**, timestamped.
  A later `{}` or empty list proves nothing about the data.
- **Analyse offline from the saved artifact.** Do not re-hit the endpoint to answer a
  question you can answer with `json.load`.
- Public means public: only read what the service already publishes to any browser.
  No auth bypass, no forged headers, no interception.

## §2 — What a relay/order API leaks (and why each field matters)

Real shape observed (`GET /requests/v2?limit=50`, 200 OK, no auth):

```json
{
 "id": "0x1793456952e7a8815c34e22d9b15c8c865efb247e60e5a279e18a1ef2ede0c06",
 "status": "success | failure",
 "user": "0x2410ba6c65f989ee2e536255a1661277618186c7",
 "recipient": "AZbUBun9KBEYjaBCAbRrLRhKmzrUYWwWE3Pf6K6yTrJE",
 "depositAddress": {
   "address": "0x3bed95be45e9d157e5b3f73a00faf5cca9a9170d",
   "depositAddressType": "open",
   "depositor": "0xf89d7b9c864f589bbf53a82105107622b35eaa40",
   "depositTxHash": "0x6c2ccdc5fdaff92351f1c9435016ecc5abb39b9a724896c336b619c522f782f1"
 },
 "data": {
   "inTxs": [{ "data": { "to": "0x0729e2a4...", "data": "0xcd6e13f7...", "hash": "0x6038ea5a..." }}],
   "outTxs": [{ "hash": "...", "chainId": 792703809, "status": "success" }],
   "failReason": "TRANSACTION_REVERTED",
   "fees": {...}, "slippageTolerance": "100", "subsidizedRequest": false
 },
 "protocol": {
   "orderId": "0x57def038...", "hubType": "onchain", "isWithdrawable": false,
   "solver": { "address": "0xf70da978...", "protocolChainId": "base", "chainId": 8453 },
   "deposit":  { "origin": { "chainId": 1337, "currency": "0x0000...0000", "depository": "0x66cf0aac..." } },
   "settlement": { "destination": { "fills": [{ "chainId": 792703809, "transactionId": "65vm4wua..." }] } }
 }
}
```

Field → question it answers:

| field | use |
|---|---|
| `depositAddress.type == "open"` | address is NOT reserved per-order → front-run candidate **if** reusable. That is a hypothesis, not a finding, until proven. |
| `depositAddress` null vs filled | how many live orders expose a pre-published address; count it, don't assume |
| `protocol.solver.address` | who actually executes orders — compare against `/chains` `solverAddresses` |
| `inTxs[].data.data` | **full broadcast calldata** — decode actions, find embedded signatures |
| `outTxs[].status` / `failReason` | which legs reverted, which never landed at all |
| `id` / `orderId` / `onchainId` | three *different* hashes. Do not assume which one is the on-chain idempotency key — see §4, and **`references/offchain-key-derivation-proof.md`** for the resolved answer |

**Resolved (later round).** This question is answerable, and was answered:
`protocol.orderId` **is** the on-chain event `id` verbatim (11/11), `protocol.deposit.origin.
onchainId` is an unrelated per-order asset hash, and the value the oracle actually enforces is
`protocol.deposit.attestation.execution.idempotencyKey` — **none of the three you would guess**.
Run the procedure in `references/offchain-key-derivation-proof.md`; it turns the
"which hash is the key" question from an assumption into a measurement.

## §3 — Cross-endpoint identity graph

`GET /chains` returns per-chain `solverAddresses`, `contracts.*`, `depositAddressEnabled`,
`withdrawalFee`. Build the intersection before believing any narrative:

```python
KNOWN = {'0x71d8be89...': 'ADMIN/owner', '0xbdcd959c...': 'Allocator#2', ...}
solvers = {s.lower(): [c['name'] for c in chains if s in (c.get('solverAddresses') or [])]
           for c in chains for s in (c.get('solverAddresses') or [])}
print('solver ∩ internal:', {a: KNOWN[a] for a in solvers if a in KNOWN})
```

A solver that is **not** an internal contract (0 intersection, high chain count) means
the execution layer is external — which reframes every "who can trigger this" question.
One address appearing in 51/59 chains as a plain EOA is a single key of enormous blast
radius: report it as exposure, not as a bug.

Also read the flags: `disabled`, `partialDisableLimit`, `depositAddressEnabled`.
`depositAddressEnabled: true` on N chains is the precondition for the whole deposit-
address class of attack; without it the class is moot.

## §4 — Negative controls that actually discriminate

The trap: a getter that accepts any input and returns `0` looks like a clean answer.

```python
# isExecuted(bytes32) returned 0x000...0 for the two candidate keys  -> "not executed"
# control A: a RANDOM hash also returns 0                            -> getter is uninformative
# control B: you must find at least ONE hash it returns 1 for, or the probe is VOID
```

```text
RULE  a view getter that returns the zero value for a random input is not evidence.
      Its "0" for your candidate is the same 0 as for garbage.
RULE  a negative control must fail DIFFERENTLY from the positive control. Same output
      on both arms = PROBE-INVALID, discard the reading entirely.
RULE  three hashes in an order object (id / orderId / onchainId) are not interchangeable.
      Prove which one the contract keys on; do not pick the one whose `isExecuted`
      happened to exist as a selector.
RULE  ...and "prove which one" includes proving it is NONE of them. The enforced key can be
      a fourth value that only exists inside the attestation blob. Compare against
      `attestation.execution.idempotencyKey` before concluding any order field is the key.
```

## §5 — What this lane legitimately yields

```text
LOW   unauthenticated order history endpoint exposing user, recipient, status, and
      full calldata for every order                              -> information disclosure
INFO  solver census: who executes, on how many chains, internal vs external
INFO  deposit-address mode per chain (open vs reserved) + which chains enable it
INFO  operational tempo: e.g. 60 chains configured inside 655 blocks = a scripted loop,
      one chain's builder set to address(0) = deliberate feature shutdown
```

Any escalation above LOW requires **proving the address is reusable** (send a second
deposit and observe a stale order claiming it) or **proving an unspent signature is
replayable**. Until one of those is executed, label the rest `HYPOTHESIS` and keep it
out of the findings ledger.

## §6 — Follow a leaked address to its bytecode BEFORE writing a finding (worked NULL result)

The `depositAddress` lane looked like the strongest keyless path for two rounds. It
produced **nothing**, and the way it was closed is the reusable part.

```text
STEP 1  depositAddress rate: 3 / 250 orders = 1.2%  -> rare, so sample per STATUS
        (/requests/v2?status=refund|success|failure) instead of relying on offset,
        which the endpoint silently ignores (two "pages" returned the same 50 ids).
STEP 2  type=="open"   -> address == user. The user parks their own Hub balance; no new
        address exists, nothing can be front-run. Class CLOSED in one comparison.
STEP 3  type=="strict", user==0x000…0, status=="refund" -> the only interesting row.
        stateChanges showed 10,000,000 USDC.e leaving the depositAddress and arriving at
        a well-funded contract (69,239 USDC.e). Tempting.
STEP 4  eth_getCode the depositAddress: 44 BYTES, nonce 1 -> NOT an EOA, a forwarder.
STEP 5  disassemble it: 3d3d3d3d 363d3d37 363d73 <PUSH20 impl> … f4 … 5b f3
        = minimal proxy, DELEGATECALL to a FIXED implementation baked into bytecode
        (not upgradeable). Two different depositAddresses had IDENTICAL bytecode.
STEP 6  eth_getCode the impl: 893 B, 3 selectors in the dispatch table (scan PUSH4+EQ).
        Calling each on the CLONE returned:
          0x095bdbc8 -> revenue recipient (0x4cd00e38…)
          0x2dd31000 -> router (0x1df43ab5…) — the same `to` seen in inTxs[].data
          0xc88d6b91 -> revert
        No owner, no withdraw, no sweep, no setters.
STEP 7  PROVE the money moves by MEASURING, not by reading:
          clone balance @ blk(deposit)   = 10,000,000
          clone balance @ blk(deposit)+1 = 0
          clone balance @ latest         = 0,   nonce = 1
        Deposit arrives and is forwarded in the next block. Zero stranded balance.
VERDICT NULL — a correct deposit forwarder. Report the API leak as LOW only.
```

```text
RULE  a small (≤64 byte) code base at an externally-supplied address is a PROXY/FORWARDER.
      Disassemble it: PUSH20 + DELEGATECALL tells you the implementation; if the target is
      a literal, it is not upgradeable and there is no owner to hijack.
RULE  scan the implementation for its selector dispatch table (PUSH4 ... EQ) and CALL each
      selector on the CLONE (state) and the IMPL (no state). Returns = real getters;
      revert = not part of that surface. That is a full ABI recovery with no explorer.
RULE  "funds left the address" is not "funds were stolen". Pin the balance at the deposit
      block and the next block. If it is 0 at both ends of the forwarding window, the flow
      is by design. A well-funded recipient contract is revenue, not the attacker.
RULE  explorer source retrieval fails often (Blockscout 403/Cloudflare, Etherscan v2 needs
      a key). Bytecode + selector probing is the fallback and it is sufficient — do not
      stall a lane on a missing verified source.
```

