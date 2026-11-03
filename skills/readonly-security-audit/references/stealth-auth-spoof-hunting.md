# Stealth auth-spoof hunting in a PREPARE→AUTHORIZE→SIGN→EXECUTE→DRAIN backend

Condensed from a Relay Protocol session (oracle attestation backend + on-chain core) hunting ONE
chain where the attacker holds **no keys / HSM / MPC / admin** and yet the system authorizes and
executes value to them (Bitget-2026 shape: backend hit, keys safe, hot+warm drained).

This is the *hunt discipline* for the class — a record of what worked, what almost worked, and the
three specific ways a "found it!" chain died. **In this engagement every kill came from finding the
second binding constraint the first pass missed.**

---

## 1. The structural model

Draw it before touching code.

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

**Recurring law:** a backend signer is almost always a *dumb signer*. Security does not live in the
signer — it lives in whichever layer computes the **identifiers**. Hunt the identifier derivation,
not the signature.

**Per-arrow obligation:** name the SECOND channel that would catch a lie. An arrow with no second
channel is the teller window — record it as a candidate, then go find the binding constraint that
closes it.

---

## 2. Field classification IS the deliverable

For every field in the signed struct, produce exactly one of:

| Class | Meaning | Exploitability |
|---|---|---|
| **CHECKED** | cross-verified against on-chain state or an unforgeable signature | dead |
| **CHECKED (config)** | verified against static chain config, not live state | usually dead |
| **BOUND-VIA-HASH** | never compared explicitly, but it is inside the preimage of a hash that IS anchored to real state | dead |
| **FORMAT-ONLY** | type/hex/length validated, then signed verbatim | **window — chase it** |
| **UNENFORCED** | accepted and signed, no check anywhere | **window — chase it** |

Rank FORMAT-ONLY fields by *what the executor does with them*. A FORMAT-ONLY field feeding a log is
worthless; one selecting an address, amount, or token IS the chain.

### 2.1 ⚠️ BOUND-VIA-HASH is the class that manufactures fake CRITICALs

This is the single most expensive classification error in the whole hunt, and it happened at scale:
a field-classifier subagent returned a ranked table of **eight "FORMAT-ONLY" rows** — `receiver`,
`fees[].recipient`, `fees[].amount`, `outAmountMinimum`, `outCurrency`, `outChainId`, `nonce`,
`deadline` — each stamped *"Redirects entire withdrawal payout to attacker."* **Every value-bearing
row was wrong.** Accepting that table would have shipped a fabricated Critical.

The mechanism: `receiver` really is never compared (`index.ts:1559` does nothing but copy it through),
but the whole order is hashed and the hash must equal the on-chain `depositId`:

```ts
orderId = hashStruct(ORDER_EIP712_TYPES, normalizeOrder(order));   // index.ts:303
if (deposit.result.depositId !== orderId) throw externalError(...); // index.ts:326
// ORDER_EIP712_TYPES covers Output.payments[].recipient/.currency/.minimumAmount/.expectedAmount,
// Output.deadline/.calls/.extraData, Fee.recipient, Fee.amount
```

⇒ mutate `receiver` ⇒ `orderId` changes ⇒ `depositId == orderId` breaks ⇒ the deposit is not real.
**Cryptographically bound, merely not explicitly checked.** "FORMAT-ONLY" was the wrong verdict.

**Mandatory test before believing ANY row of such a table:**
1. Open the hashed struct type definition (`ORDER_EIP712_TYPES`, `abi.encode` layout, the Solidity
   `struct` passed to `hashStruct`). List every field.
2. For each claimed-unvalidated field, ask **"is it in the preimage?"** Yes → `BOUND-VIA-HASH`, stop.
3. Find the equality anchoring the hash to live state (`depositId == orderId`, `usedRequests[digest]`,
   nonce store). Present ⇒ mutation ⇒ hash mismatch ⇒ rejected.
4. Also diff **normalized-vs-signed**: does the form that gets hashed differ from the raw form that
   gets signed/executed? That divergence is where the real bug hides. Here they matched ⇒ none.

Only fields genuinely **outside** the preimage are windows. In this target that was `data` — a `bytes`
blob whose length was caller-controlled — but reading `GatewayVmPayloadBuilder.sol` showed
`receiver: params.receiver` (from the signed request), so even `data` could not redirect the payout.
**A caller-controlled field still needs a consumer that routes value by it.** Check the consumer.

**Reporting obligation:** when your verification contradicts a subagent artifact, say it by row —
`A1 FORMAT-ONLY → actually BOUND-VIA-HASH(Output.payments[].recipient)` — and patch the artifact or
write a counter-artifact. Leaving the wrong table on disk makes the next round re-derive the same
fiction.

**Read the schema descriptions and inline comments — teams document their own weakenings.** In this
target the route schema said of `inputCurrency`: *"Must match the deposit currency until the order's
fees are charged, **afterwards any currency is allowed**."* The service comment echoed it:
*"Afterwards none of them constrain the pull."* That sentence was the finding.

---

## 3. The three kill-shapes that end most chains

### Kill-shape A — amount is pinned to the attacker's own deposit
`recover`-style slow-refund paths. Attacker *can* create a real deposit with an arbitrary
`depositId` (depository often takes `id` as a free parameter — verify, it is common). But then:

```
amount    === deposit.result.amount       // attacker's own 1 wei
owner     === deposit.result.depositor    // attacker
recipient === deposit.result.depositor    // attacker
nonce     =  getDeterministicId(...)      // derived server-side, not caller-supplied
```

Each guard is individually reasonable; together the path is **self-refund only**.
> Before chasing a forged-identifier chain, grep the consumer for `amount ===`, `owner ===`,
> `recipient ===` against the *deposit* record. If all three pin to the deposit's own depositor,
> the chain pays zero — stop immediately instead of building a PoC.

### Kill-shape B — the identifier is a hash of attacker-supplied content
```ts
deposits.filter((d) => d.result.depositId === orderId)
```
looks like the perfect gate to break — until `orderId = hashStruct(ORDER_EIP712_TYPES,
normalizeOrder(order))` binding `solver + salt + inputs + output + fees`. Matching a victim's
`depositId` requires a preimage.
> When you see `X === hash(Y)` gating value, **resolve `hash` before designing the chain**. If it is
> a struct hash over signed content, the gate is cryptographic and the chain is over. Do not burn
> rounds hunting "flexible" fields inside `Y` hoping for a collision.

### Kill-shape C — injected bytes with no consumer
Attacker-controlled `data` reached a signed `SetEntry.data` via raw string concat with no length
check (real, executable, verified end-to-end). Then:
```
grep -rn "getEntry(" --include=*.sol .   →  ONE hit: the definition itself
```
No contract reads the field; the backend destructures only `const [, createdAt]` and discards `data`.
> A signed-but-unread field is not a vulnerability. **Count consumers before counting severity.**
> grep the getter name across the whole contract tree; if the only hit is the getter's own
> definition, the chain is decorative.

---

## 4. `encodePacked` collision — check the shape, it is usually NOT exploitable

`getOrderAddress` used `encodePacked(["string","bytes","uint256","bytes32"], …)` while a
`getOrderAddressSafe` variant used `abi.encode` with the comment *"prevent hash collisions with
variable-length arguments (VIG-SP-014)"*. Looks like free money. It is not:

- `string` and `bytes` are variable-length, **but**
- `uint256` and `bytes32` are **fixed 32 bytes**, so the boundary cannot shift.
- Collisions live where two *adjacent* variable-length fields sit, or a variable field is followed
  by another variable field — not where every following type is fixed-size.

Verified experimentally (viem): packed address ≠ safe address for identical inputs, and
cross-boundary `chainId`↔`depositor` manipulation produced different addresses.
> Never report `encodePacked` by pattern-matching the function name. Write the 6-line node test that
> attempts the adjacent-variable-length shift. If everything after the variable field is fixed-size
> the finding is a **compatibility divergence**, informational — the team already knows (that is why
> the `Safe` variant exists).

---

## 5. API-layer auth: "advisory" auth is the real entry

The highest-value structural find was not a crypto flaw:

```ts
const apiKey = req.headers["x-api-key"];
if (!isValidApiKey(apiKey)) {
  const rateLimit = unauthenticatedRateLimiter.check(req.ip);
  if (!rateLimit.allowed) return reply.code(429);
}
return done();          // request WITHOUT a valid key still proceeds
```

`isValidApiKey` was a flat membership check over an env-parsed map — **no roles, no scopes, no
privileged key space**. Check these on every preparer target:

1. **`force` / skip-verification flags gated on "has any API key"** — if all keys are equal, the
   flag is effectively public. One target's schema read literally *"Force attestation even if the
   order solver fill is not valid"*, and the path set `totalWeightedInputPaymentBpsDiff: 0n`,
   bypassing every payment check. This is the **strongest available entry** even when the final
   value transfer stays gated — report it as ENTRY, then be honest that impact needs the binding
   constraint broken.
2. Missing HMAC / request signing / nonce-replay cache / idempotency store at the HTTP boundary.
   An `idempotencyKey` existing only as an EIP-712 *field* is not replay protection.
3. Every `*/signatures/*` route whose only check is "caller proved control of an address they
   themselves named" — that is authentication, **not** authorization. Enumerate these separately
   from routes that re-attest on-chain events.

---

## 6. Live-verification recipes that paid off

**Nested `(id => mapping(addr => bal))` slot discovery.** Brute-forcing `keccak(addr ++ slot)`
returned "no hit in base 0..19". Winning derivation was nested:

```python
slot = keccak( uint256(tokenId) ++ keccak( address ++ uint256(base) ) )   # base = 4 here
```

Method: take a **real holder with a known balance**, dump candidate slots, match the **known balance
value** — never try to match a zero. Confirm with a state-override probe.

**Reading balances at `latest` is meaningless after execution.** All sampled orders read `0` because
they had already been drained. Two fixes: (a) `eth_getStorageAt` at `hex(execBlock - 1)`, (b) build a
token census from the real `Executed` log set with per-order block pinning — never sample at tip.

**`eth_getLogs` size limits.** A 2 000-block span over a busy contract already returns
`Response size exceeds limit`. The RPC names its own fix: `eth_getLogsWithCursor`. Page it, dedupe,
write every page to disk.

**Selector extraction must handle `PUSH3`.** Authentic 4-byte selectors with two leading zero bytes
(`0x00fdd58e balanceOf(address,uint256)`) are dispatched via `PUSH3 0xfdd58e`, not `PUSH4`. A
`PUSH4`-only extractor reports the function as "MISSING" and you build a false narrative on top of a
tool artifact. **Always cross-check a "function is absent" claim with a live `eth_call`** — a
successful call proving presence beats a disassembler that says otherwise.

---

## 7. Reporting discipline for this class

Standard nine-section output, plus three honesty lines that made the report survive review:

- **Every PROVEN row must have live/test output behind it** — cite by value (page counts, slot hits,
  live getter matches), never by assertion.
- **REFUTED rows are content, not embarrassment.** The killed chains are what prove the hunt was
  real and that the surviving candidate was not the first thing you liked. Four kills in one session
  is a strong report, not a weak one.
- **A best-remaining candidate with an unbroken binding constraint is `GATHER-INTEL`, not PROVEN.**
  When ENTRY is proven and AUTHORIZE is proven but the value transfer is still gated, say exactly
  that: "partial chain, one binding constraint unresolved". Never promote on the strength of the
  components you did verify.

**Detector blind spot to always flag:** a `force`-style bypass leaves *normal-looking logs* and a
perfectly valid oracle signature. The only detection signal is a business-logic differential
(attested amount vs on-chain paid amount) — which is precisely the field the bypass forces to `0n`.
State that explicitly under DETECTION: "logs normal, signature valid; detection must come from
reconciliation, not signatures."

### 7.1 The STRUCTURAL-CEILING verdict — declaring the floor IS the deliverable

Some targets cannot host the Bitget shape at all, and saying so precisely is a better report than a
stretch chain. The distinguishing test, after many killed chains, came down to one question:

> **Is value bound to a signature the attacker cannot produce, or to authorization a backend can
> mint?**

In this target every value path ended at `depositId == orderId` where `orderId = hashStruct(order)`
over `solver + salt + inputs + output + fees`. Every payout field (`receiver`, amounts, fees,
destination chain) is inside that preimage. Therefore the backend compromises that ARE real —
**advisory API auth**, **`force:true` skipping payment verification**, **a signer that signs anything
handed to it** — all stop one layer above the money, because the layer beneath them re-derives the
identifier cryptographically.

Phrase it as a design asymmetry, not a research failure:

> `BLOCKED — STRUCTURAL: the preparer layer is genuinely broken (proven), but it cannot emit value
> because every execution path re-derives its payout target from a signature the attacker cannot
> forge. The Bitget shape does not transplant: that model assumes authorization is the last gate,
> and here a signature is.`

Contrast with the three states from `onchain-protocol-audit` §3e — they are not interchangeable:

| State | Meaning |
|---|---|
| `PROVEN` | real end-to-end execution, real output |
| `BLOCKED — gate X` | exact line known; a key leak or a code fix would unblock it |
| `BLOCKED — STRUCTURAL` | no attacker action unlocks it; the design is sound *at this seam* |

**Do not let proven-component momentum promote the verdict.** ENTRY proven + AUTHORIZE proven +
SIGN proven, with the transfer still gated = `GATHER-INTEL`. The components being real does not make
the chain real. And when the operator's model itself is the blocker, say that — the deliverable is
the map plus the honest ceiling, not a manufactured drain.

**Corollary worth carrying to the next target:** a backend finding still deserves its own grade even
when the stealth chain dies. This hunt produced a standalone **HIGH** (`isOperator(account, operator)`
returning `hasRole(OPERATOR_ROLE, operator)` — `account` never consulted ⇒ role holders have global
authority with zero per-account scoping, plus `burn(anySender, …)` with no `sender == msg.sender`).
Grade it and report it separately; never inflate it to Critical, never bury it because the chain
failed.

---

## 8. Multi-agent split that worked

Three divergers, dispatched in parallel with disjoint scopes:
1. **Field classifier** — every signed field → CHECKED / BOUND-VIA-HASH / FORMAT-ONLY, with file:line.
2. **Route enumerator** — all API entry points → which unvalidated field reaches the signer, plus
   the global auth model. (This agent found the advisory-auth flaw.)
3. **Contract-side second channel** — any value movement without a fresh signature or role, tested
   live against RPC.

Then a single chainer (you) verifies each claim against source and live state before accepting it.
**Verify subagent claims independently — one of the three produced a plausible chain that died on a
signature check it had not read.**

### 8.1 The brief must state that "unvalidated" ≠ "exploitable"

Task 1 above is the highest-risk delegation in this class, because a classifier's output *looks*
authoritative (ranked table, file:line per row) while being systematically wrong. Write into the
brief, verbatim:

> *"A field is only FORMAT-ONLY if it is **outside the preimage** of every hash that anchors the
> request to real state. Before marking any field unvalidated, open the EIP-712/`hashStruct` type
> definition and check membership. If the field is in the preimage, classify it `BOUND-VIA-HASH` and
> say which equality that hash is compared against. Do not assign impact to a field you have not
> verified is outside the hash."*

Without that sentence the classifier answers a narrower question ("is it explicitly compared?") and
stamps severity on the answer. Eight rows came back wrong that way in one dispatch.

Also require a **per-row counterargument** in the artifact: `field | in preimage? | which equality
anchors it | verdict`. A row that cannot fill columns 2–3 is a hypothesis, not a finding.

### 8.2 Divergence still pays — but only the honest arm survives

Across the dispatch the arms split cleanly:

| Arm | Output | Survival |
|---|---|---|
| Field classifier | 8 "FORMAT-ONLY, exploitable" rows | **0/8 survived** verification |
| Route enumerator | advisory-auth + force-bypass entry | **survived** (confirmed in source) |
| Contract second channel | every candidate DISPROVEN with raw output | **survived as negative evidence** |

Two of three arms were useful, and the most valuable single artifact was the **all-DISPROVEN** one —
it is what let the report assert "no signature-free, role-free value channel" with evidence instead
of absence. Keep dispatching divergers, but budget your own verification on the arm whose output is
a *table of claims*, not the arms whose output is *raw output or negatives*.
