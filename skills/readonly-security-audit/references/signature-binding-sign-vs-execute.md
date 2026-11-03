# Signature-Binding Audit — the sign-vs-execute gap

Class: "does what the signer authorized equal what actually executes?" Proven on
Relay Protocol HUNT B (`relay-protocol-oracle` off-chain service +
`relay-settlement` Solidity/`smart-contracts` + SDK + hub RPC), 2026-10-30.
Companion to `encoding-digest-layer-fuzzing.md` (same target family; that file
covers byte-level collision math, this one covers *semantic* binding).

Scope note: this file is the **off-chain / service** layer. When the same gap must be
proven at the **on-chain** layer as a forge test with exact numbers — the contract's
`execute(request, resolver, resolverData, oracle, sig)` shape, where the unsigned
parameter rather than a missing struct field is the bug — use
`onchain-eip712-binding-poc.md`.

**Before any of the below: is the DOMAIN itself sound?** `eip712-domain-separator-replay-audit.md`
is the replay axis — `eip712Domain()` census across every deployed verifier, cross-chain
(`vm.chainId` + OZ's runtime rebuild) and cross-contract (twin deployment) replay proofs,
the `Utils.buildDomainSeparator` parity check for hand-rolled domains, and the 1271 split:
does a second verifier (`RelayOracleMultisig`) re-wrap the executor's digest in its own
EIP-712 domain? On Relay it does not, so there is exactly one digest — proved by showing a
domain-wrapped signature is REJECTED. §1's field table is only meaningful once the domain
that encloses those fields is bound to one contract on one chain.

This is distinct from digest fuzzing. Digest fuzzing asks "can two inputs share
a hash?". Binding asks "is every field that changes behaviour actually inside
the thing the signer signed?" The second class needs no crypto break at all —
and that is what makes it high severity and easy to miss.

**Section list:** §1 three-way field table (A/B/C) · §2 proof ladder (hold signature, vary field) ·
§3 on-chain precondition census before severity · §4 literal HTTP evidence from an unmodifiable
service (Fastify `inject`) · §5 rate-limit findings + honest bound ·
**§5b EIP-712 domain `chainId` ≠ `message.chainId` (split-chain binding)** ·
**§5c schema validation that rewrites evidence (Ajv `coerceTypes`, nested unknown keys)** ·
**§5d `x-api-key` as rate-limit exemption only — not authentication** ·
**§5e declaration attestations — verifier is a notary, semantics are the bug (second-defect hunts)** ·
**§5f dynamic-type injection — an A/B-verified field that the *SDK* concatenates into a `bytes`** ·
§6 report shape · **§7 your own scaffold is the #1 false-positive source** ·
**§7b standalone `viem` proof-script traps** ·
**§7c enumerate-every-entry-point briefs — the per-route triage deliverable**.

## 1. The three-way comparison (do this first, it is the whole technique)

For each verifier, build a table of three payloads and diff them *field by field*:

| Layer | Where to read it |
|---|---|
| **A. What the signer signs** | the SDK / service `createSignaturePayload` / message builder |
| **B. What the verifier compares** | the `verify*` call site — argument object literal |
| **C. What the executor consumes** | normalisation → signing → on-chain digest struct |

Every field in **C** that is absent from **A∪B** is a candidate finding. Every
field in **C** that the caller supplies *after* verification (body-controlled) is
a candidate exploit. The gap is the bug; no key recovery required.

Worked instance (Relay):

```js
// A: src/common/signature-verification.ts:67-79
const createSignaturePayload = (operation, data) => ({
  operation, chainId, currency, amount,
  ownerChainId, owner, recipient, nonce,
  additionalData: data.additionalData,
});                          // <-- `depository` ABSENT

// B: withdraw-request-authorization/v1.ts:147-160
await verifyWithdrawalSignature({ data: { chainId, currency, amount,
  ownerChainId: req.body.spenderChainId, owner: req.body.spender,
  recipient: req.body.receiver, nonce, additionalData }, signature });

// C: same file :165-177
normalizeWithdrawRequest({ ..., depository: req.body.depository ?? chain.depository! })
```

`depository` is attacker-controlled in C, absent in A and B ⇒ forgery.
On-chain made it worse, not better:

```solidity
// RelayAllocator.sol:365-385 — the EXECUTOR binds it
keccak256(params.depository),
// :255 — and it selects the payload builder
address builder = payloadBuilders[params.chainId][params.depository];
// EthereumVmPayloadBuilder.sol:175 — and it is the EIP-712 verifyingContract
Utils.buildDomainSeparator(SIGNING_DOMAIN, SIGNATURE_VERSION, evmChainId, address(bytes20(depository)))
```

So the owner's personal_sign authorized *less* than the contract checked. The
mismatch is the finding: "a field that determines execution is not covered by
the owner's signature." Compare against the DrawAuthorization class in the
brief — same shape.

## 2. Proof ladder — a 200 is not proof; a stable signature is

Cheapest decisive test: **hold the signature fixed, vary only the suspect field**.

```bash
# one ownerSignature, N depository values
K0 omitted        => 200  oracleSig=0x6951e1ea...   <-- identical
K1 real depository=> 200  oracleSig=0x6951e1ea...   <-- IDENTICAL to K0
K2 other address  => 200  oracleSig=0x1abf3fb4...   <-- DIFFERENT
K3 0x…dEaD        => 200  oracleSig=0x3037a4a4...
K4 0xffffff (3B!) => 200  oracleSig=0x2770b0ad...   <-- no length validation
K5 0x…llo-world   => 500  Invalid byte sequence (viem)   <-- unhandled throw
```

Reading the matrix:
- **K0 == K1 identical signature** ⇒ the field genuinely is outside the digest
  (not merely "accepted"). This is the core proof; without it a 200 could just
  mean "ignored".
- **K2–K4 distinct signatures, all 200** ⇒ the service *signs* the attacker's
  value. That is the forgery.
- **K4 short-length 200** ⇒ no `bytes`-length validation before the signer.
- **K5 clean 500** ⇒ raw library throw not wrapped in `externalError` — a real
  (low) finding: error-class leak / inconsistent error contract.

## 3. Always run the on-chain precondition census before assigning severity

A binding gap is only as severe as the number of things it can be re-pointed
at. Do not stop at "MEDIUM/HIGH, depends on deployment" — enumerate it.

- Check the registry the field keys into. Relay: `payloadBuilders[chainId][depository]`
  is set by owner-only `setPayloadBuilder(string,bytes,address)` with
  **arbitrary bytes** as the key.
- Census the actual state, then let it set severity:

```js
// 152 PayloadBuilderSet events, all 3 params INDEXED
// topics = [sig, keccak(chainId), keccak(depository), builder]
// result: total chainIds=96, dengan >1 depository=0
```

⇒ **zero** chainIds had a second depository ⇒ cross-depository replay had *no
target today* ⇒ severity dropped HIGH → **MEDIUM (latent)**, and K3/K4 became
"oracle signs an unregistered depository, but execution reverts
`NoPayloadBuilder`" = griefing, not drain. Saying this explicitly is what keeps
the finding credible; claiming HIGH without the census is the overclaim that
gets reports rejected.

### RPC recipe when `eth_getLogs` is blocked by size

Relay hub RPC rejects wide scans: `{"code":-32005,"message":"Response size
exceeds limit. Use eth_getLogsWithCursor or reduce the number of logs
requested"}`. Use the cursor method and decode by topic:

```js
const r = await rpc("eth_getLogsWithCursor", [
  { address: ALLOCATOR, fromBlock: hex(start), toBlock: hex(end), topics: [T0] },
]);
// decode events whose params are ALL indexed
const chainTopic = l.topics[1], depTopic = l.topics[2];
const builder = "0x" + l.topics[3].slice(26);   // address in topic
```

Pitfall that cost a cycle: `decodeAbiParameters([...], l.data)` returned nothing
because `data` was `"0x"` — all three params were **indexed**. Always
`JSON.stringify` one raw log before writing a decoder.

## 4. Getting literal HTTP evidence out of a service you must not modify

The brief demands literal status+body. Order of attack:

1. **Is it actually alive?** `curl -s -o /dev/null -w "%{http_code}" /lives/v1`.
   Print that before anything else; "MATI" is a legitimate deliverable.
2. **Build it in the repo** (`npx tsc -b`) and run `dist/` with env. A clean
   build is also your proof the source was not truncated (§1b of
   `secret-leak-and-masking.md`).
3. **When a real listener is awkward (missing env, redacted config), drive the
   real handler via Fastify `inject`** — same route, same schema, same code
   path, no network:

```js
process.env.ENVIRONMENT = "testnets.prod";
process.env.ECDSA_PRIVATE_KEY = "0x1111…11";     // throwaway local key
const app = Fastify(); app.register(route, { prefix: "" });
const res = await app.inject({ method: "POST", url: "/…/v1",
  headers: { "content-type": "application/json", "x-api-key": "testkey" },
  payload: body });
console.log(res.statusCode, res.body);
```

State plainly in the report which evidence came from a live socket vs `inject`,
and that keys were throwaway. Never imply a live-oracle response you did not get.

4. **Forging a *legitimate* owner signature locally** is allowed and necessary —
you are proving the gap, not stealing funds. Sign the exact A-layer payload with
a local key (`privateKeyToAccount` + EIP-191 `signMessage` over the
stable-stringified payload), then that signature is valid for every C-layer
variant.
   - Harness gotcha: `json-stable-stringify` **drops `undefined` keys**, so an
     `additionalData: undefined` field vanishes from the payload. Match the
     target's stringifier exactly or you will chase a phantom verify failure.
   - When HTTP says "invalid signature" but in-process verify passes, the
     difference is argument shape (e.g. `signature` vs `sigRaw`), not crypto.

## 5. Rate-limit findings — and the honest bound

Two separate verdicts came out of the same probe, do not blur them:

- `X-Forwarded-For` rotation produced **identical** 18-of-20 429 as no-XFF ⇒
  `trustProxy` off ⇒ XFF bypass **MATI**. Same-shaped probe, opposite result
  from a trust-proxy-enabled target — always run both arms.
- Schema validation runs **before** `preHandler`, so body-invalid requests never
  reach the limiter: 60 invalid ⇒ 60×400, **zero 429**; 20 valid ⇒ 2×200 +
  18×429. That is a genuine unlimited-CPU-path finding — but it is **not** a way
  to obtain signatures, because invalid bodies never reach signing and valid
  bodies stay capped at 2/window. Write both halves; the second half is what
  stops the finding being overclaimed as an oracle-flood.

## 5b. EIP-712 domain `chainId` ≠ `message.chainId` — the split-chain binding bug

A distinct sub-class of the sign-vs-execute gap that §1's field table **misses**, because the
offending field *is* present in A and B — it just comes from two different request fields.

Proven on the same Relay target, `nonce-mapping/v2` (HUNT B follow-up):

```ts
// src/services/attestation/index.ts:1181-1187
const message = { chainId: data.walletChainId, ... };   // ← mapping key

// :1189-1203
const signatureChain = await getChain(data.signatureChainId);
verifyTypedData({ domain: NONCE_MAPPING_DOMAIN(
    Number(signatureChain.additionalData?.evmChainId)),  // ← verifying domain
  message, ... });

// :1208-1215  mapping is then keyed on walletChainId
```

`walletChainId` and `signatureChainId` are **independent body fields**, both allowlisted by
`getChain`, and nothing asserts they match. So a signature made under domain `ethereum(1)` is
accepted and recorded as a mapping for `optimism`. Proof is a local `signTypedData` +
two `verifyTypedData` calls — no oracle needed:

```
verifies under domain 1  : true     # what the endpoint actually checks
verifies under domain 10 : false    # the honest domain for the claimed chain
```

Generalise: for **every** EIP-712 verifier, ask *which request field feeds the domain separator,
and which feeds the typed `message`*. If they are not the same field (or not cross-checked),
the domain separator is unbinding and cross-chain replay reasoning collapses. Grep the domain
builder for `evmChainId`, `additionalData?.evmChainId`, `signatureChainId`, `verifyingChain`.

## 5c. Schema "validation" that rewrites evidence (Ajv coercion + nested stripping)

Two Fastify/Ajv behaviours that silently make *what you sent* ≠ *what got verified*. Both bite
when you read a schema, believe it, and stop.

**(a) `coerceTypes` is on by default.** `Type.String()` does not reject a number — it converts it:

```js
// POST with chainId:8453, amount:1000000 (numbers), recipient:true (boolean)
STATUS 200
BODY {"chainId":"8453","amount":"1000000","recipient":"true", ...}
```

Consequences worth reporting: a boolean reaches `encodeAddress()` as the string `"true"`; the
digest verified is **not** the digest the caller computed; request logs and verified payload
diverge, so forensic attribution breaks. Fix is `ajv: { coerceTypes: false }` or `pattern`-tightened
`Type.String`. Always probe with deliberately wrong JSON types and log the echoed body.

**(b) Nested objects without `additionalProperties:false` are NOT stripped.** Default
`removeAdditional` applies at the **root body** only. A nested `Type.Object({...}, {description})`
whose options omit `additionalProperties:false` lets arbitrary keys through:

```
payload  additionalData: {"evil-key": {...}}     # not in schema at all
BODY     {"additionalData":{"evil-key":{...}},"hasEvil":true}
```

If that object is then spread into the signed payload (as `additionalData` is, at
`signature-verification.ts:78`), the oracle signs **attacker-chosen keys**. Impact is hash
grinding (every shape → different `withdrawRequestHash` for an economically identical request,
dodging hash-keyed dedup) plus broken auditability — not proto pollution (`__proto__` is dropped
by `JSON.parse`; don't claim pollution). Probe both levels: top-level unknown key *and* nested.

## 5d. `x-api-key` used only as a rate-limit exemption is not authentication

Read the hook before concluding "auth exists". Relay:

```ts
// http-server.ts:60-90 — single global preHandler
const apiKey = req.headers["x-api-key"];
if (!isValidApiKey(apiKey)) {
  const rateLimit = unauthenticatedRateLimiter.check(req.ip);
  if (!rateLimit.allowed) return reply.code(429)...;   // the ONLY rejection path
}
return done();                                          // valid OR invalid key both reach handler
```

There is no 401/403 anywhere. Live proof that it is not auth: a bogus key and **no** key both
reach the handler (`500` from config-thrown errors is *handler ran*, not *rejected*):

```
bogus-key status: 500 | no-key status: 500 | any 401/403?: false
```

This matters because the service is a **signing oracle** — 14 `POST` endpoints that return oracle
signatures. Report it as the auth finding it is (unauthenticated callers can drive the signer,
burn third-party RPC, and grind hashes), while stating the remaining bound honestly: per-handler
owner-signature checks validate *that the owner consented*, not *who may ask*. Also check whether
valid keys get any quota — a `key → bool` map means "valid key = unlimited", the opposite of a
control.

## 5e. Declaration attestations — the verifier is a NOTARY, and that is the bug

Sub-class of §1 that the field table also misses, because **A = B exactly**: the verifier and the
minter agree perfectly. What is missing is in **C** — the *world state* the signature was supposed
to commit to. Anyone re-auditing a service that already has one proven signature bug should hunt
here first, because it needs no crypto break and no field gap.

Proven on the same Relay target, second independent defect (`no-fill-or-refund/v1`, HUNT B round 2):

```ts
// src/services/attestation/index.ts:1253-1281
const message = { chainId: data.solverChainId, solver: data.solver, orderId: data.orderId };
const isValidSignature = await verifyTypedData({ address: data.solver, ... });   // pure verify
if (!isValidSignature) throw externalError("Invalid signature");
const solver = generateAddress({ ... });
return { genericMapping: getNoFillOrRefundMessage(solver, data.orderId) };      // mint, no query
```

The oracle performs **no chain read at all**. It never checks the order exists, that the fill window
elapsed, or that any refund delay passed. "This order was not filled" is asserted entirely by the
party that profits from it. SDK side confirms the mint is a pure function of
`(solver, orderId)` — `data` is the constant `0x01`, `nonce = sha256(solver:orderId)`
(`generic-mapping.js:28-45`).

**Detector** — for every endpoint that returns a signature, ask what the verifier *reads* besides
the signature:

| Verifier reads | Class | Verdict |
|---|---|---|
| fields of the signed message only | notary | the *semantics* are unverified ⇒ hunt here |
| message fields + on-chain state / registry / deposit existence | assertion | the attestation asserts something |
| message fields + a deadline / nonce / attempt record | bounded declaration | acceptable |

Grep for the `verify*` call and confirm whether **any** `getContract`/RPC/DB read sits between it
and the `return` of the minted message. If not, the endpoint notarises whatever the caller says.
Mechanised: `scripts/notary_verifier_scan.py <src_dir>` lists every `verify*`/`recover*`/`ecrecover`
call site with the world-reads found before its `return` (`reads=none` = candidate, rank first).

**Proof that works without a live server** (this is the decisive evidence, and it is cheap):

```
[L1]  oracle accepts the solver's declaration                   : true
[L1'] a stranger signing as the solver (negative control)        : false   # not a forgery bug
[L2]  oracle countersignature valid under the on-chain domain   : true    # submit-ready
entry inputs                       : user, id, data, nonce
any binding to a fill/amount/depositor/deadline ?                  false
```

`[L1']` is the load-bearing control: it proves you are reporting a **semantic** bug, not a signature
forgery. Without it a reviewer reads "the oracle accepts my signature" and rejects the report.
`[L2]` proves the minted object is directly submittable by checking it against the contract's own
EIP-712 domain (`EIP712("RelayGenericMapping","1")` at `RelayGenericMapping.sol:73`) — copy the
domain name/version from the constructor, never from the service.

**Severity discipline — read the consumer's gates BEFORE calling it theft.** The declaration fed a
`recoverMode` path that bypasses the user's signature, which looks like a drain. Two gates in
`recover-mode-verification.ts` capped it:

- `:176-181` — `recipient` MUST equal `deposit.result.depositor` ⇒ the attacker cannot redirect funds;
- `:90-96` — the nonce is derived from `depositOnchainId` ⇒ replay collapses onto one withdraw hash.

Result: **not theft, a commitment break / forced slow refund** (solver unilaterally refuses an
order it already priced, locking its own hub balance). Reported HIGH, explicitly not Critical.
That paragraph is what made it credible. Same rule as §3 and
`negative-verdict-gate-ledger.md` §8: enumerate the consumer gates, then let them set severity.

Generalised checklist for "attestation that something did **not** happen":

1. Does the signed struct contain a deadline or an attempt/observation record? If not, the
   declaration can be made at t=0 for an event due at t=+∞.
2. Does the service hold, or accept, any proof the declaring party *tried* and failed?
3. Can the declaring party be the beneficiary of the declared outcome? (solver profits from refund,
   counterparty profits from default). If yes, self-declaration is unenforceable.
4. Does the minted counter-object key onto state that the declaring party does not control?
5. Which consumer gates cap the blast radius — redirect, replay, amount?

## 5f. Dynamic-type injection — an A/B-verified field that the *SDK* concatenates into a `bytes`

Third sub-class the §1 field table misses, and the one most likely to be the real entry on a
signing oracle. Here the field **is** in A and B, is genuinely covered by a signature, and the
verifier does its job — but the *message builder* splices a caller-supplied string into a
variable-length field with no length check. The bug lives one layer below the verifier, in
`node_modules`, so nobody auditing the route sees it.

Proven on Relay `signatures/nonce-mapping/v2` (HUNT B round 3):

```ts
// route  src/api/attestations/signatures/nonce-mapping/v2.ts:14-43
depositor: Type.String(...)          // no pattern, no minLength/maxLength — free-form

// service src/services/attestation/index.ts:1194-1206
// the ONLY check is that the caller controls `wallet`; `depositor` is never format-checked
verifyTypedData({ address: data.wallet }, ...)                       // passes
// :1215-1221
return { genericMapping: getNonceMappingMessage(user, data.nonce, data.id, data.depositor) };

// SDK node_modules/@relay-protocol/settlement-sdk/dist/messages/v2.2/generic-mapping.js:7-22
data: depositId + (depositor ? depositor.slice(2) : ""),   // RAW CONCAT, NO LENGTH CHECK
// and SetEntry.data is type "bytes" in src/common/signer.ts:35
```

`bytes` on-chain packs as `offset ‖ length ‖ data`, so **the attacker chooses the length.**
`slice(2)` only strips the `0x` prefix; nothing rejects a 68-byte "address". Verified by driving
the real SDK function with a throwaway key local-`signTypedData` (no server, per §7b):

```
[1] well-formed  data bytes = 52          # depositId(32) + depositor(20)
[2] attacker     data bytes = 68          # depositor + 16 appended bytes
    id equality (id = sha256("NONCE_MAPPING:"+nonce), user NOT bound): true
[3] signed OK; verifyTypedData(acct) == true: true
[5] SetEntry has no deadline/expiry field: true
```

**Detector — read every message builder, not just the route.** For each endpoint that mints a
signature, open the SDK function calls in the `return` and grep it for string concatenation
into a field typed `bytes` / `bytes32` / `bytes[]`:

- `a + b`, `${x}`, `.slice(2)`, `padStart/padEnd`, `Buffer.concat` — all suspicious.
- Any `.slice(` on a caller-supplied address is a tell that the code *assumes* a 20-byte input
  without enforcing it.
- A field typed `bytes` in the EIP-712 struct with **no** `bytes32` width is inherently
  length-injectable when its content is assembled from user strings; a `bytes32` field is not.

Grep pattern that finds the whole class fast:
`grep -rnE '(data|id|nonce|extraData)\s*:\s*[^,]*\+\s' node_modules/<sdk>/dist/**/*.js`

Mechanised: `scripts/dynamic_type_concat_probe.mjs <repo-root> [sdk-dist-glob]` — stage 1 ranks
every concat-into-dynamic-field / `.slice(2)` site in `src/` and the SDK dist; stage 2
(`--exec <module> <fn>`) imports the real builder and prints the `data` length for well-formed vs
padded inputs, which is the §5f proof line. Run it from the repo root (§7b rule 1).

**Second, independent property to check in the same builder: is an identifier bound to the
actor?** Here `id = sha256("NONCE_MAPPING:" + nonce)` — `user` is **not** in the hash, so the
entry id is identical for every user and every chain. Combined with `walletChainId` vs
`signatureChainId` being free body fields (§5b), the same signed mapping is replayable across
users and chains, and there is no deadline in `SetEntry` at all. Two defects from one 15-line
SDK function; report them as the properties they are (length injection, unbound key) rather
than as one vague "nonce mapping is weak".

**Severity discipline.** Bound it the way §5e does: this endpoint's output is a *hub mapping
entry*, so impact = whoever consumes `SetEntry.data`. State the consumer and its checks
(`_decodeNonceMappingData` in `hyperliquid-vm/index.ts:785-799` branches on `data.length === 106`,
so an over-long `data` falls through to `{ id: data }` and the depositor attribution is lost /
reinterpreted). "Oracle signs an attacker-shaped mapping payload" is the proven claim; a fund
path is conditional and must be labelled so.


Buckets, explicitly separated:
- **PROVEN** — with the literal matrix (K0..K5), file:line at every hop.
- **MATI** — a table of hypothesis | status | why. Include RCE-negative
  ("no `eval`/`Function`/`child_process`/deserialize, no `@fastify/static`, no
  `readFile(req.*)`"), and note that a 500 from a raw viem throw is still not RCE.
- **Latent** — real math, no reachable constructor; name the precondition
  ("second depository on same chainId").
- Endpoints with **zero authorization** are worth recording even when harmless:
  `withdraw-requests/v1` has no `ownerSignature` check at all, but it only
  proxies read-only `hashesToSign` from the hub ⇒ **MATI as forgery**, LOW as a
  read-hash/RPC-cost oracle. Don't inflate it, don't omit it.

## 5g. Solver-order output fields are FORMAT-ONLY — the "signs whatever the preparer gives it" class

Sub-class of §1 where **A = B = C at the crypto layer** (the signer genuinely
signs the exact struct the executor consumes), but **C is assembled from
attacker-influenceable input** without on-chain cross-validation of output-side
fields. The signer is not the bug; the preparer's trust in solver-signed order
content is.

Proven on Relay `execute-and-withdraw/{fill,refund}/v1` (HUNT B round 4):

```ts
// src/services/attestation/index.ts:1528-1567  (fill)
private async _getExecuteAndWithdrawFillRequest(data) {
  const { deposit, orderAddress, inCurrency, output } = data.attested;
  ...
  return {
    inChainId: inChain.id,            // CHECKED: from deposit.data.chainId
    inCurrency,                       // CHECKED: deposit + order input cross-checked
    outChainId: destination.outChainId,          // FORMAT-ONLY: orderOutput.chainId
    outCurrency: destination.outCurrency,        // FORMAT-ONLY: orderOutputPayment.currency
    outAmountMinimum: output.minimumAmount,      // FORMAT-ONLY: orderOutputPayment.minimumAmount
    depository: destination.depository,          // CHECKED (static config)
    orderAddress,                      // CHECKED: recomputed from deposit
    receiver: destination.receiver,    // FORMAT-ONLY: orderOutputPayment.recipient
    data: destination.data,            // FORMAT-ONLY: caller additionalData
    fees: output.fees,                 // FORMAT-ONLY: order.fees[].recipient + amount
    nonce: data.nonce,                 // FORMAT-ONLY: pass-through, no uniqueness check
    deadline: output.deadline.toString(), // FORMAT-ONLY: order-signed, intentionally not checked against block.timestamp
  };
}
```

`_attestExecuteAndWithdrawDeposit` (lines 262-443) does the *input-side* validation:
- Verifies order signature (`verifyMessage` on `orderId`, lines 303-312)
- Matches deposit `onchainId` to order `depositId` (lines 320-328)
- Validates input currency matches deposit until fees charged (lines 379-399)
- Computes `inCurrency` from deposit / order input (lines 366-373)

But it **never checks**:
- `order.output.payments[0].recipient` against the depositor or any on-chain identity
- `order.output.payments[0].minimumAmount` against any balance, rate, or on-chain amount
- `order.output.chainId` against any on-chain destination registry
- `order.output.payments[0].currency` against any token registry
- `order.fees[].recipient` against any treasury/solver registry
- `order.fees[].amount` against any fee schedule or bps cap
- `order.output.deadline` against `block.timestamp` (explicitly skipped for peer determinism, line 1563-1565)
- `data.nonce` for uniqueness or replay (no mapping lookup anywhere)

The signer (`src/common/signer.ts:99-162`) signs the struct verbatim — no business
validation, no field-level checks. The schema (`src/api/utils.ts:460-487`) only
type-validates strings/arrays.

**Classification template for this class:**

| Field | CHECKED / FORMAT-ONLY | Evidence |
|-------|----------------------|----------|
| `inChainId` | CHECKED | Derived from `deposit.data.chainId`; matched against `orderInput.payment.chainId` |
| `inCurrency` | CHECKED | Cross-checked against `deposit.result.currency` and `orderInput.payment.currency` until fees charged |
| `orderAddress` | CHECKED | Deterministically recomputed from `depositor + depositId + timestamp + chainId + vmType` |
| `depository` | CHECKED (static config) | Read from `destinationChain.depository` or `_getConfiguredDepository`; not attacker-influenceable via request |
| `outChainId` | FORMAT-ONLY | Taken from `orderOutput.chainId`; only checked that it is a known chain in config |
| `outCurrency` | FORMAT-ONLY | Taken from `orderOutputPayment.currency`; only normalized via `encodeAddressToHex` |
| `outAmountMinimum` | FORMAT-ONLY | Taken from `orderOutputPayment.minimumAmount`; no balance/rate/on-chain check |
| `receiver` | FORMAT-ONLY | Taken from `orderOutputPayment.recipient`; only normalized via `encodeAddressToHex` |
| `fees[].recipient` | FORMAT-ONLY | Taken from `order.fees[].recipient`; only normalized via `generateAddress` |
| `fees[].amount` | FORMAT-ONLY | Taken from `order.fees[].amount`; no bps cap or on-chain validation |
| `nonce` | FORMAT-ONLY | Pass-through from request body; no uniqueness/replay check |
| `deadline` | FORMAT-ONLY | Taken from order; intentionally not checked against local/block time |
| `data` | FORMAT-ONLY | Caller-supplied `additionalData`; only routing metadata validated in gateway path |

**The preparer-side spoofing chain (no oracle key required):**

1. Attacker controls the backend preparer layer (API route input, SSRF, callback
   injection, queue item poisoning).
2. Injects a forged `order` with attacker-chosen `output.payments[0].recipient`,
   `minimumAmount`, `chainId`, `fees[].recipient`, `fees[].amount`, and a
   valid-looking `orderSignature` (compromised/forged solver keypair).
3. Fastify schema (`executeAndWithdrawRequestSchema`) only type-validates — no
   checks on output fields against authoritative state.
4. `_attestExecuteAndWithdrawDeposit` verifies deposit matches `orderId` and
   currency, but does **not** validate output recipient, amount, fee recipients,
   or destination chain.
5. `_getExecuteAndWithdrawFillRequest` copies forged order values verbatim into
   `ExecuteAndWithdrawRequest`.
6. `signExecuteAndWithdrawRequestMessage` signs them with the oracle key.
7. `RelayExecutor` on-chain honors the signed `receiver` / `fees` / `outAmountMinimum`,
   transferring funds to the attacker.

**Detector — for every signing endpoint that consumes an order/solver object:**
After verifying the order signature, grep whether the service performs **any**
on-chain read that validates the order's *output* fields (recipient, amount,
currency, chainId, fees). If the only reads are input-side (deposit existence,
currency match, orderId linkage), the output fields are FORMAT-ONLY.

**Severity discipline — the static-config exception is not a fix.** `depository`
being read from chain config means it is not attacker-influenceable via the request
body, but it is still not dynamically validated against on-chain state at execution
time. Report it as **CHECKED (static config)** with that exact wording, not as
fully CHECKED.

**The `deadline` design-choice trap.** When the code comment explicitly says
"Derived from the order (rather than local time) so that all peer oracles produce
an identical signed request," that is a deliberate FORMAT-ONLY choice. Do not
report it as a bug unless the consumer contract also skips `block.timestamp`
validation — and if it does, the finding is **on-chain**, not off-chain.

## 7. Your own scaffold is the #1 false-positive source — re-confirm against the real route

A bypass that "works" only in your harness is the most common way to ship a bogus finding.
This session produced one and caught it:

- Probe used a **mock route re-using an endpoint's schema**, not the endpoint itself. The mock
  returned `200` where the real route returned `429`, and it looked like a prefix-based
  rate-limit bypass (`/lives/../attestations/...`, since `http-server.ts:65` skips `/lives`).
- Re-testing against the real registered handler: `plain: 429 | lives-prefixed: 429` — **MATI**.
  Fastify normalises the URL *before* `preHandler`, so `req.url` is already canonical.

Rules this bought:

1. **Never cite a status code from a stub you registered.** If you need a schema, import the real
   route module and register *it*; if you must stub, label the result "harness only, not evidence".
2. **Any 200/404 you did not expect is suspect in both directions.** A missing schema on a stub
   route turns "would be rejected" into "200" and manufactures a bypass. Print `res.body`, not just
   the code.
3. **Re-run every PROVEN item once more before writing it up**, against the same object the report
   will describe. Cheap; it is the difference between a report and a retraction.
4. When a hypothesis dies, write it into a **MATI table with the disproof**, not into silence.
   `N1 /lives prefix bypass — MATI: normalized before preHandler, plain 429 == prefixed 429` is a
   deliverable; deleting it makes the report look like the vector was never considered.

Same discipline as `negative-verdict-gate-ledger.md` §2: an unfalsifiable "ruled out" is worthless,
a named disproof is checkable.

### 7b. Standalone `viem` proof scripts (no server) — the traps that eat a cycle

Two-round second-defect hunts are often best proven **without any HTTP**: model the oracle's exact
`signTypedData`/`verifyTypedData` call, since the question is about the digest, not the transport.
Rules that came out of HUNT B round 2:

1. **Run the script from the repo root, not `/tmp`.** `import "viem"`/the target SDK resolves from
   `<repo>/node_modules`; a script in `/tmp` exits 1 on `ERR_MODULE_NOT_FOUND`. Keep PoCs as
   untracked files at the repo root (`git status --short` to confirm nothing tracked was touched).
2. **`viem` validates EIP-712 addresses hard, including the checksum.** A fabricated
   `verifyingContract` of the right length with wrong case throws
   `InvalidAddressError: Address must match its checksum counterpart`. Use the **lowercase** form for
   placeholders (`0x0b5d8a1c…`, 40 hex chars). Note the length error and the checksum error are the
   same exception — a 39-char address reports "must be a hex value of 20 bytes".
3. **Copy the domain from the contract constructor, the struct from the SDK.** `EIP712("Name","ver")`
   in Solidity and the `{name, version}` in the service's `signTypedData` drift; cite both.
4. **When the primitive you need isn't exported, port it — do not invent it.** First draft of the
   nonce-mapping PoC guessed the id as `sha256("entry:user:nonce")`; the real SDK is
   `sha256("NONCE_MAPPING:" + nonce)` (user is NOT in the id). Read
   `node_modules/<pkg>/dist/**/*.js` and port verbatim with a `// verbatim port of file:line`
   comment. An invented hash makes the "proof" worthless and is the fastest way to ship a false
   finding.
5. **Check your decode branch against real bytes before asserting on it.** A `data.length === 106`
   decode silently fell through to `depositor: undefined` because I asserted the wrong length in the
   conditional — the FAIL line, not the PASS lines, is what caught it. Print intermediate values
   (`length`, `slice` output) so a wrong branch is visible in the transcript.
6. **Prefer a real SDK encoder for magic bytes.** Capture `encodeAction(...)`/`encode*` output from
   `node -e` and paste it, rather than hand-assembling padded hex — hand-assembled literals in a
   proof are unaudited surface for exactly the mistake you are hunting.

### 7c. Enumerate-every-entry-point briefs — the triage deliverable
A brief worded "enumerate all X entry points and identify which route accepts an
attacker-influenceable field that flows unvalidated into the signer" is a **coverage** task, not
a single-finding task. The reviewer's real question is *did you look at all of them, and can you
justify why the other 13 are clean.* Shape the artifact so that is self-evident:

1. **Read the registration file first, not the routes.** `src/api/index.ts` gives the authoritative
   list in one read; directory listings mislead (route dirs vs `signatures/*` nesting). Count
   routes and state the count.
2. **Global auth hook before any route.** One `preHandler` decides the auth model for all of them
   (§5d). Establishing "no key ⇒ rate-limited, not rejected" once collapses 14 per-route auth
   discussions into one paragraph and stops you re-arguing it.
3. **One table, every route, one row each:** route | file | service method | signer reached.
   This is the proof of enumeration and costs one pass.
4. **A CLEARED table with the reason, not silence** (§7 rule 4). "`deposit-address-triggers` —
   safe: hash recomputed AND cross-checked on-chain `triggers(triggerHash) == orderId`
   (`index.ts:1131-1143`)" is worth more than three paragraphs on the one you picked.
5. **Rank the survivors in one table**, with the unverified field named in its own column.
6. **Say which cleared routes were the *obvious* candidates.** The ones the brief points at are
   usually defended — on Relay, deposit-address-triggers had a hub lookup and withdraw-requests
   read `hashesToSign` from the allocator. Reporting "the hinted routes are clean, here is the
   one that is not, and here is why" is the deliverable. Do not force a finding onto a hinted route.
7. **Reserve a section for cross-cutting issues** found on the way; they are often stronger than
   any single route: advisory auth, no replay/idempotency at the boundary, an `idempotencyKey`
   that is only an EIP-712 field nothing consumes server-side.
8. **A force/skip escape hatch is a finding of its own.** Relay `solver-refunds/v1:982-1021`
   skips *all* refund verification when `force: true`, gated only on `isValidApiKey` — the same
   non-privileged rate-limit key. Grep every body schema for booleans named `force`, `skip*`,
   `unsafe`, `bypass` and trace each to the verification it disables.

### 7d. Answering a "find a SECOND, independent defect" brief

When defect #1 is already proven, the brief is a *classification* problem as much as a hunting one.
Structure the work so the new finding cannot be confused with the old one:

- **Name the root cause of #1 explicitly** before hunting, then refuse candidates that share it.
  Relay: F2 = message body `chainId` vs EIP-712 domain `chainId` split. A fourth candidate
  (`no-fill-or-refund` also splitting body/domain) was proven with a 5-line `hashTypedData` diff and
  reported as **SAME ROOT CAUSE AS F2, not a new defect** — with the digest-difference output as the
  evidence for that call. Reporting a re-skin of #1 as an independent bug destroys the report.
- **Ship a "candidates that turned out to be F2" section.** It converts near-misses into evidence of
  thoroughness instead of leaving them as silent omissions (§7 rule 4).
- **Rank by proof strength honestly.** Table at the top: ID | title | severity | proof script |
  ✅ run status. Then per-finding: code path with `file:line`, verbatim executed output, why
  exploitable, the gates that cap it, fix. Where a finding's impact depends on code outside the repo,
  mark it **"PROVEN at the API/oracle layer, impact conditional on integrator"** — never present a
  conditional as a proven payout path.
- **Re-run every script before writing up** (`for f in f2b_*.mjs; do node "$f" >/dev/null && echo OK $f; done`).
