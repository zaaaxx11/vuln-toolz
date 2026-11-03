# Stealth auth-spoof hunting in a PREPARER→AUTHORIZER→EXECUTOR backend

Condensed from a Relay Protocol session (oracle attestation backend + on-chain core) hunting
ONE chain where the attacker holds **no keys / HSM / MPC / admin** and yet the system
authorizes and executes value to them (Bitget-2026 shape: backend hit, keys safe).

This file is the *hunt discipline* for the class. It is deliberately a record of **what worked,
what almost worked, and the three specific ways a "found it!" chain died** — because in this
engagement every kill came from finding the **second binding constraint** the first pass missed.

---

## 1. The structural model that actually holds up

Draw it before touching code. Every preparer hunt is the same five-node graph:

```
PREPARE  (API route / queue / callback / relayer)
   │  attacker-influenceable FIELDS
   ▼
AUTHORIZE (validator / signer)
   │  what is CHECKED vs only FORMAT-validated
   ▼
SIGN      (signTypedData / KMS / multisig)
   │  signs VERBATIM whatever it is handed
   ▼
EXECUTE   (contract / sink)
   │  which BINDINGS actually constrain the transfer
   ▼
DRAIN     (who receives, how much, can it repeat)
```

**The recurring law:** a backend signer is almost always a *dumb signer*. The security does not
live in the signer — it lives in whichever layer computes the **identifiers**. Hunt the identifier
derivation, not the signature.

**Mandatory per-arrow label:** for each arrow, name the SECOND channel that would catch a lie.
If an arrow has no second channel, that arrow is the teller window — write it down as a candidate
and then go find the binding constraint that closes it.

---

## 2. Field classification is the actual deliverable

For every field in the signed struct, produce one of:

| Class | Meaning | Exploitability |
|---|---|---|
| **CHECKED** | cross-verified against on-chain state or a signature the attacker cannot forge | dead |
| **CHECKED (config)** | verified against static chain config, not live state | usually dead |
| **FORMAT-ONLY** | type/hex/length validated, then signed verbatim | **window — chase it** |
| **UNENFORCED** | accepted and signed, no check anywhere | **window — chase it** |

Then rank FORMAT-ONLY fields by *what the executor does with them*. A FORMAT-ONLY field that
only feeds a log is worthless; one that selects an address, an amount, or a token is the chain.

**Concrete example worth remembering:** in Relay's withdraw path, `inputCurrency` was documented
in the route schema as *"Must match the deposit currency until the order's fees are charged,
**afterwards any currency is allowed**"* — the schema comment itself was the finding. The inline
comment in the service said the same: *"Afterwards none of them constrain the pull."* **Read the
schema descriptions and the comments; teams document their own weakenings.**

---

## 3. The three kill-shapes (memorise these — they killed 4 chains in one session)

### Kill-shape A — the amount is pinned to the attacker's own deposit
`recover`-style slow-refund paths. Attacker *can* create a real deposit with an arbitrary
`depositId` (depository takes `id` as a free parameter — verify this, it is common). But then:

```
amount    === deposit.result.amount        // attacker's own 1 wei
owner     === deposit.result.depositor     // attacker
recipient === deposit.result.depositor     // attacker
nonce     =  getDeterministicId(...)       // derived server-side, not caller-supplied
```

Every guard is individually reasonable; together they make the path **self-refund only**.
> **Lesson:** before chasing a forged-identifier chain, grep the consumer for
> `amount ===`, `owner ===`, `recipient ===` against the *deposit* record. If all three pin to
> the deposit's own depositor, the chain pays zero and you stop immediately.

### Kill-shape B — the identifier is a hash of attacker-supplied content
`orderId = hashStruct(ORDER_EIP712_TYPES, normalizeOrder(order))` binding `solver + salt +
inputs + output + fees`. A filter like

```ts
deposits.filter((d) => d.result.depositId === orderId)
```

looks like the perfect gate to break — until you notice `orderId` is a **keccak of the whole
order struct**. To make your forged order hash to a victim's `depositId` you need a preimage.
> **Lesson:** when you see `X === hash(Y)` gating value, resolve `hash` *before* designing the
> chain. If it is a struct hash over signed content, the gate is cryptographic and the chain is
> over. Do not spend rounds looking for "flexible" fields in `Y` hoping for a collision.

### Kill-shape C — the injected bytes have no consumer
Attacker-controlled `data` reached a signed `SetEntry.data` (raw string concat with no length
check — real, executable, verified). Then the hunt died because:

```
grep -rn "getEntry(" --include=*.sol .   →  ONE hit: the definition itself
```

No contract reads the field. The backend reads `getEntry()` but destructures only
`const [, createdAt]` and discards `data`.
> **Lesson:** a signed-but-unread field is not a vulnerability. **Count consumers before
> counting severity.** `grep` the getter name across the whole contract tree; if the only hit is
> the getter's own definition, the chain is decorative.

---

## 4. `encodePacked` collision — check the shape, it is usually NOT exploitable

`getOrderAddress` used `encodePacked(["string","bytes","uint256","bytes32"], …)` while a
`getOrderAddressSafe` variant used `abi.encode` and carried the comment *"prevent hash collisions
with variable-length arguments (VIG-SP-014)"*. This looks like free money. It is not:

- `string` and `bytes` are variable-length, **but**
- `uint256` and `bytes32` are **fixed 32 bytes**, so the boundary between them cannot shift.
- Two adjacent variable-length fields, or a variable field followed by a fixed one *where the
  fixed one is last*, is where collisions actually live.

Verified experimentally (viem): packed address ≠ safe address for identical inputs, and
cross-boundary `chainId`↔`depositor` manipulation produced different addresses.
> **Lesson:** do not report `encodePacked` by pattern-matching the function name. Write the
> 6-line node/viem test that tries the adjacent-variable-length shift. If the types after the
> variable one are all fixed-size, the finding is a **compatibility divergence**, severity
> informational — the team already knows (it is why the `Safe` variant exists).

---

## 5. API-layer auth: "advisory" auth is the real entry

The single highest-value structural find in the session was not a crypto flaw:

```ts
const apiKey = req.headers["x-api-key"];
if (!isValidApiKey(apiKey)) {
  const rateLimit = unauthenticatedRateLimiter.check(req.ip);
  if (!rateLimit.allowed) return reply.code(429);
}
return done();          // request WITHOUT a valid key still proceeds
```

And `isValidApiKey` was a flat membership check over an env-parsed map — **no roles, no scopes,
no privileged key space**. Consequences to check on every preparer target:

1. **`force` / `skip-verification` flags gated on "has any API key"** — if all keys are equal,
   the flag is effectively public. Relay's schema literally read *"Force attestation even if the
   order solver fill is not valid"* and the code path set `totalWeightedInputPaymentBpsDiff: 0n`,
   bypassing every payment check. This is the **strongest available entry point** even when the
   final value transfer is gated — report it as the entry, then be honest that impact needs the
   binding constraint broken.
2. Missing HMAC / request signing / nonce-replay cache / idempotency store at the HTTP boundary.
   `idempotencyKey` existing only as an EIP-712 *field* is not replay protection.
3. Every `*/signatures/*` route where the only check is "the caller proved control of an address
   they themselves named" — that is authentication, **not** authorization. Enumerate these
   separately from the routes that re-attest on-chain events.

---

## 6. Live-verification recipes that paid off

**Hub-style `(id => mapping(addr => bal))` slot discovery.** Brute-forcing `keccak(addr ++ slot)`
returned "no hit in base 0..19". The winning derivation was the nested one:

```python
slot = keccak( uint256(tokenId) ++ keccak( address ++ uint256(base) ) )   # base = 4 here
```

Method that found it: take a **real holder with a known balance**, dump candidate slots, match the
**known balance value** — do not try to match a zero. Then confirm with a state-override probe.

**Reading balances "now" is meaningless after execution.** All 40 orders read `0` at `latest`
because they had already been drained. Two fixes: (a) read `eth_getStorageAt` at
`hex(execBlock - 1)`, (b) if you want a token census, iterate the real `Executed` log set and
pin per-order blocks — never sample at tip.

**`eth_getLogs` size limits.** A 2 000-block span over a busy contract already returns
`Response size exceeds limit`. The RPC names its own fix in the error text:
`eth_getLogsWithCursor`. Page it and dedupe.

---

## 7. Reporting discipline for this class

Output the standard nine sections, plus these three honesty lines that made the report survive
review:

- **Every PROVEN row must have a live/test output behind it.** Fourteen EntrySet pages, a
  `getOrderAddress` slot hit, a live `SET_ENTRY_TYPEHASH` match — all cited by value.
- **REFUTED rows are content, not embarrassment.** The four killed chains (self-refund pinning,
  struct-hash gate, unread injected bytes, encodePacked) are what prove the hunt was real and
  that the surviving candidate was not the first thing you liked.
- **A best-remaining candidate reported as `GATHER-INTEL`, not PROVEN.** When the entry is proven
  and the authorizer is proven, but the value transfer is still gated, say exactly that:
  "partial chain, one binding constraint unresolved". Never promote on the strength of the
  components you did verify.

**Detector-blind spot to always flag:** a `force`-style bypass leaves *normal-looking* logs and a
perfectly valid oracle signature. The only detection signal is a business-logic differential
(attested amount vs on-chain paid amount), which is exactly the field the bypass sets to `0n`.
Say so explicitly in DETECTION — "logs normal, signature valid, detection must come from
reconciliation, not signatures."
