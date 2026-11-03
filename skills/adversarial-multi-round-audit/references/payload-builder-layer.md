# Payload-builder layer — the last unread ring around an allocator/executor

Companion to `references/unbound-parameter-and-permissionless-injection.md` (the digest
omits the resolver) and `references/chain-closure-audit.md` §3 (enumerate gates as rows).
Read this when the executor and allocator are both closed and the only component nobody
has read is the thing that turns a withdrawal request into a **signable hash**.

It is the ring most likely to be skipped, for three bad reasons:

- it is registered by a setter (`setPayloadBuilder`), so it does not appear in the
  allocator's ABI;
- its entrypoints are `view`/`pure`, so it "cannot do anything";
- there are many of them, one per chain, so the census looks like a chore.

All three are wrong. The builder decides **exactly which fields are in the digest the
signer approves**. A builder that omits a field hands the attacker that field.

---

## 1. Census the builders from the SETTER, not from a getter

The obvious getter is a trap. `payloadBuilders(chainId, depository)` returned
`0x0000…0000` for **every** chain on **both** allocators, while 50/50 of the live
transactions were executing withdrawals successfully. Two independent wrong readings were
available and both were tempting:

```text
WRONG  "no builders installed, so _buildPayload must be internal"   (it was not)
WRONG  "the getter key is (chainId, keccak(depository))"            (guessing keys)
RIGHT  harvest setter CALLDATA from the txlist — the arg encoding is ground truth
```

The setter is the source of record because it is what actually ran:

```python
SEL_SET = '0x9a48730c'          # setPayloadBuilder(string,bytes,address)
for page in range(1, 9):        # walk the whole history, not page 1
    for t in txlist(ALLOCATOR, page=page, sort='asc'):
        if t['input'][:10] == SEL_SET:
            w  = t['input'][10:]
            WS = [w[i*64:(i+1)*64] for i in range(len(w)//64)]
            o1, o2 = int(WS[0], 16)//32, int(WS[1], 16)//32   # two dynamic args
            chain = read_dyn(WS, o1)                            # string
            dep   = read_dyn(WS, o2)                            # bytes
            builder = '0x' + WS[2][-40:]                        # static address last
```

One pass over ~800 txs produced **40+ chain registrations** and **18 distinct builder
addresses across 8 VM families** — including chains with no public docs.

```text
EthereumVmPayloadBuilder    x3 instances   (all EVM chains; ECDSA EIP-712)
SolanaVmPayloadBuilder      x2
GatewayVmPayloadBuilder     x4              (arc-gateway)
LighterVmPayloadBuilder     x2
HyperliquidVmPayloadBuilder x1
TonVmPayloadBuilder         x1              (Ed25519)
TronVmPayloadBuilder        x1
BitcoinVmPayloadBuilder     x1
XrpVmPayloadBuilder         x1
0xafa3eb5b (6,900 B)        x1   <- NO verified source. Do not silently drop it.
```

```text
RULE  a getter returning 0 for every key is a GETTER-FORM TRAP, not an absence.
      Cross it with the setter's calldata before writing "not installed".

RULE  every distinct builder address is a separate trust boundary. Group by VM family
      for reading, but census by ADDRESS — two Ethereum builders can be different
      revisions (4,483 B / 7,951 src vs 5,893 B / 13,679 src here).

RULE  a builder with no verified source is an UNREAD component. Label it, keep it in
      the coverage table, and say the closure is partial over it.
```

---

## 2. What a builder can and cannot do — decide this before reading 18 sources

A builder is `view`/`pure` by construction. It cannot move value. So the only question
that matters is:

> **Which field of the signed hash does the builder let the caller choose?**

That reframes the audit from "find a bug" to "print the digest preimage, field by field,
and mark each one CONSTANT / FROM-PARAMS / FROM-CHAIN-STATE."

Worked case (`EthereumVmPayloadBuilder`, `buildPayload` L75–121):

```solidity
if (params.receiver.length != 20) revert InvalidReceiverLength(...);   // validated
if (params.currency.length != 20) revert InvalidCurrencyLength(...);   // validated

CallRequest memory request = CallRequest({
  calls: new Call[](1),
  nonce: computeNonce(params),                      // keccak(block.number, nonce, currency,
  expiration: block.timestamp + expirationDelay     //        receiver, data, amount)
});

if (currencyAddress == address(0))
  request.calls[0] = Call({ to: receiverAddress, data: "", value: params.amount });
else
  request.calls[0] = Call({ to: currencyAddress,
                            data: abi.encodeWithSignature("transfer(address,uint256)",
                                                          receiverAddress, params.amount),
                            value: 0 });
return abi.encode(request);
```

Field table that closes it:

| field in digest | source | attacker-chosen? |
|---|---|---|
| `calls[0].to` | `receiver` (len 20 enforced) or `currency` | yes — **but it is the signed field**, so the signer approves it |
| `calls[0].data` | `transfer(receiver, amount)` | derived from the same signed fields |
| `calls[0].value` | `params.amount` | yes — signed |
| `nonce` | `keccak(block.number, nonce, currency, receiver, data, amount)` | derived; 6 fields, none omitted |
| `expiration` | `block.timestamp + CONFIG value` | chain state + config |
| domain separator | `CONFIG` evmChainId + `depository` | chain state |

**Verdict: BERSIH / NOT-EXPLOITABLE.** Every attacker-chosen field is inside the hash the
signer approves, and `computeNonce` binds all six request fields — no two distinct
withdrawals can share a nonce in one block.

---

## 3. The two things that DO go wrong in builders

### 3a. A constant that should be a parameter — or the reverse

Check every field the struct writes that is **not** in the params:

```solidity
// TonVmPayloadBuilder L133-140 — the correct shape
TonTransferRequest memory request = TonTransferRequest({
  receiver:    bytes32(params.receiver),
  amount:      uint128(params.amount),          // validated <= MAX_TON_COINS
  createdAt:   uint32(block.timestamp),
  queryId:     _computeQueryId(params),         // keccak(block.number, nonce, currency,
  subwalletId: SUBWALLET_ID,                    //         receiver, data, amount)
  timeout:     TIMEOUT
});
```

`subwalletId` and `timeout` are **contract constants**, not params. That is the safe
direction: a caller cannot redirect the transfer to a subwallet of their choosing, and
cannot extend the window.

The dangerous direction is the mirror: a field that determines **whose wallet the funds
leave from** being read from `params`. When you see a digest preimage, mark every
sender-side field and confirm each is a constant or a chain-state value:

```text
[sender identity]  subwalletId  -> CONSTANT        SAFE
[destination]      receiver     -> params, SIGNED  SAFE (signer approves it)
[window]           timeout      -> CONSTANT        SAFE
[uniqueness]       queryId      -> hash of params + block.number   SAFE
[uniqueness]       createdAt    -> block.timestamp                 SAFE
```

If `[sender identity]` ever resolves to `params.*`, stop — that is the finding.

### 3b. A bounded-uniqueness field (collision surface, griefing only)

`_computeQueryId` is a **23-bit** value with a documented remap:

```solidity
uint32 raw = uint32(uint256(keccak256(abi.encode(
    block.number, params.nonce, params.currency,
    params.receiver, params.data, params.amount
)))) & QUERY_ID_MASK;                       // 2**23 ~ 8.4M slots

if ((raw & 0x3FF) == FORBIDDEN_BIT_NUMBER)  // bit_number 1023 traps in Highload V3
    raw &= uint32(~uint32(0x3FF));          // remap to slot 0 — preserves `shift`
```

The NatSpec admits the arithmetic itself:

> *"The 23-bit query-id space (~8.4M slots) is uniform but not collision free: by the
> birthday bound, ~3k distinct withdrawals within a single TIMEOUT window have a
> noticeable collision probability. Highload V3 rejects messages whose `(shift,
> bit_number)` slot is already consumed, so the off-chain assembler is expected to detect
> that rejection and re-build at a later block."*

Grade this **LOW / griefing**, and say why in one line: a collision makes the transfer
revert, the assembler rebuilds at a later block (`block.number` changes ⇒ new `queryId`),
**no value moves and no value is lost**. The forced remap to slot 0 adds bias on top of
the birthday bound — still DoS, still recoverable.

```text
RULE  a collision in a NONCE/ID space is griefing until you can show a replay that
      re-uses a consumed slot with DIFFERENT semantics. Rejection + rebuild = LOW.

RULE  a developer comment that admits a probability bound is a gift: quote it verbatim
      in the report, then grade it honestly (LOW), do not inflate it.
```

---

## 4. `hashesToSign` takes RAW caller bytes — the on-chain/off-chain boundary

Every builder here splits into two functions:

```text
buildPayload(chainId, depository, params) -> bytes payload      // constructs
hashesToSign(chainId, depository, payload) -> bytes32[]         // hashes
```

`hashesToSign` does `abi.decode(payload, (CallRequest))` with **no check that `payload`
came from `buildPayload`**. That looks alarming and is a common false positive. Resolve it
by asking where the trust boundary actually is:

```text
ON-CHAIN consequence of arbitrary payload:
  hashesToSign returns a hash of attacker-authored content.
  A hash with no signature moves nothing.            -> NOT a vulnerability on-chain.

OFF-CHAIN consequence:
  IF the assembler signs whatever hashesToSign returns, without cross-checking that
  the payload is the one buildPayload produced, THEN the signer approves arbitrary
  calldata.                                          -> off-chain bug, unprovable from RPC.
```

```text
RULE  never claim this on-chain. Say exactly: "the contract returns a hash of
      caller-supplied bytes; whether that is exploitable depends on whether the
      off-chain signer validates the payload, which cannot be observed from RPC."
      That sentence is honest and costs nothing. Claiming it as a finding does not
      survive triage.

RULE  the SAME function pair means `hashesToSign`'s domain separator is also built from
      caller-supplied `depository` (length-checked to 20). Check the length check, then
      move on — the domain binding is the signer's job, not the builder's.
```

---

## 4a. The CONFIG store the builders depend on — one hop further out

Every EVM/Solana/Gateway builder here resolves its domain, vault/depository, token and
fee values through a **single shared `Config` contract** (`CONFIG.getConfigValue(key)`).
Reach it from the builder, not from the explorer:

```python
raw('eth_call', [{'to': BUILDER, 'data': sel('CONFIG()')}, 'latest'])   # 4,380-char source
```

Five builders across four VM families all returned **the same** config address. That is
the real trust root of the whole payload layer — one contract governs domain mappings,
destination depositories, per-chain tokens, gas fees and allocator allowlists for 40+
chains. Read it before declaring the builder ring closed.

What it looks like when it is done right (Relay `Config`, 132 lines):

```solidity
modifier onlyAllocatorOwner() {
  if (msg.sender != IRelayAllocatorOwner(allocator).owner()) revert CallerIsNotAllocatorOwner(msg.sender);
}

function setAllocator(address newAllocator) external onlyAllocatorOwner {
  _validateAllocator(newAllocator);        // only asserts owner() != 0 — no whitelist
  allocator = newAllocator;                // swaps the SOURCE OF AUTHORITY
}
```

Two things worth knowing, neither of which is a finding on its own:

1. **Authority is borrowed live, not stored.** `Config` has no `owner()` of its own; the
   gate reads `allocator.owner()` at call time. So an `Ownable.transferOwnership` on the
   allocator silently transfers config authority too. Confirm the handover is visible in
   history rather than assuming it: `owner()` read at `eth_call` block tags straddling the
   suspected handover showed `0xf3d6…` up to blk 2,472,183 and `0x71d8…` from blk 2,872,000 —
   exactly two senders across 86 txs, all `status=0x1`.
2. **`setAllocator` is circular, therefore not an escalation.** Swapping the allocator
   changes who may subsequently set values, but the call itself is gated by the *current*
   allocator's owner. An attacker without that key cannot enter the loop. Say this out
   loud, because "setAllocator has no whitelist" reads scarier than it is.

Negative-control it anyway — a gate you only read is a gate you have not tested:

```text
N1 setAllocator(0xcafe) from 0xcafe           -> 0xb97d242b CallerIsNotAllocatorOwner(0xcafe)
N2 setAllocator(0xdead) from 0xbeef           -> 0xb97d242b CallerIsNotAllocatorOwner(0xbeef)
N3 setAllocator(0x0)    from OWNER            -> 0xf05b016f InvalidAllocator(0x0)
P1 setAllocator(A2)     from OWNER  [CONTROL+] -> OK 0x
P2 setAllocator(A2)     from FORMER owner     -> 0xb97d242b   (proves the handover landed)
```

Two *different* revert selectors on the negative arms is the proof there are two distinct
gates and both are live. If every arm reverts with the same selector, you have only found
one check — keep reading the function.

```text
RULE  a config/settings contract behind a builder is a GATE, not plumbing. Its setters
      are the authority root; census them from txlist SELECTORS (not from `grep function`),
      then verify status with eth_getTransactionReceipt — txlist may omit isError.

RULE  when a setter has ZERO calls in history, that is a fact to report, not evidence of
      safety. Test it with a positive control.

RULE  "no whitelist on the replacement target" is INFO unless the gating condition is
      attacker-reachable. Circular gates are not escalations; write the sentence.
```

Tables worth building while you are there, because they cost one RPC each and close
several questions at once:

```text
tx count into Config            86, all status=0x1
distinct senders                2 (deployer-era, then post-handover owner)
setAllocator count              0                -> never used, but tested live
owner() at straddling blocks    changes only at the documented handover
```

---

## 4a-1. DERIVING the config keys — never guess the formula (two rounds burned)

`Config` is a **dumb KV store**: 4,380 bytes, two mappings, zero string literals, zero
`keccak`. The keys are minted by the *readers*:

```solidity
L21  mapping(bytes32 => bytes32) private values;
L24  mapping(bytes32 => bool)    private valueExists;
L95  setConfigValue(bytes32 key, bytes32 value)   external onlyAllocatorOwner
L125 getConfigValue(bytes32 key) external view returns (bytes32 value)
```

Because there is nothing to guess *inside* `Config`, brute-forcing key names against the
written-key set is guaranteed to fail if the preimage shape is even slightly wrong. It was:

```solidity
// WRONG — tried for two rounds, 0/113 match
keccak256(abi.encodePacked(PREFIX, chainIdString))

// RIGHT — 47/113 match, including two values independently established via a live getter
keccak256(abi.encodePacked(PREFIX, keccak256(bytes(chainId))))
```

Note the **double hash**: the chain id is hashed to a `bytes32` *first*, then packed. The
address-scoped variant has no such step:

```solidity
getAllocatorAllowedKey(address a) = keccak256(abi.encodePacked(ALLOCATOR_ALLOWED_PREFIX, a))  // 20 raw bytes
```

Procedure that works, in order:

1. Read `Config` to confirm it holds no derivation logic (if it does, you are done — read it).
2. Read the **active** builder, not an old revision: `keccak256("PREFIX_NAME")` constants and
   the `get*Key()` functions live there. Verify the source is available (`impl` builders often
   are not — pick one that is).
3. Anchor on a key whose value you already know from a **live getter** (`getGasFeeKey("x")` →
   `3500`). Recompute candidate formulas until one reproduces that value AND appears in the
   written-key set. Only then is the shape proven.
4. Sweep the proven shape over every known chain id and every written key.

```text
RULE  a config store with no string literals is not "unreadable", it is BORROWED. The
      derivation lives in the consumer. Read the consumer that is CURRENTLY registered
      (from the setter's calldata), not a historical revision.

RULE  a guessed key preimage is a fabricated identifier. Do not report "key X = 8 allowed
      allocators" from a prefix you invented — 0 matches against the written-key set means
      the FORMULA is wrong, not that the value is absent. Retract before publishing.

RULE  anchor-before-sweep: no formula is accepted until it reproduces a value you already
      know from an independent live read. Sweeps over unanchored formulas produce confident
      nonsense at scale.
```

### The finding this unlocks: a registered-but-dead surface

Once the keys decode, the *absence* of one becomes provable rather than suspected:

```text
ALLOCATOR_ALLOWED keys written by the admin:        0 of 113
getAllocatorAllowedKey(x) -> getConfigValue(key):   UNSET for all 14 probed allocators
_isEnabled(key): try CONFIG.getConfigValue(key) returns (bytes32 v) { return v != 0; }
                 catch { return false; }            // FAIL-CLOSED
=> buildPayload reverts AllocatorNotAllowed for EVERY allocator, including the legit one
=> the whole Gateway builder family (and any minter behind it) is DORMANT
```

That downgraded a HIGH "uncapped mint + sender-free burn behind an admin key" to **INFO**,
because the *code* defect was real but **no reachable path existed — not even for the admin**.
Cross-check against history before believing it: the gateway chain family had **zero
withdrawals ever**, which is the corroborating signal a dormant surface leaves behind.

```text
RULE  CAPABILITY ≠ REACHABILITY applies at DEPLOYMENT level too. "Admin can mint uncapped"
      is not a finding if the mint is gated by a config key that was never written. Probe
      the *reader's* fallback (fail-open vs fail-closed) and the config value itself.

RULE  a feature that is registered but has zero historical traffic in a lane that should
      show traffic is a DORMANT SURFACE. Grade it INFO, name the missing activation key,
      and state plainly: "reachable by nobody, including the admin."

RULE  never let "the code allows it" survive as HIGH once you have shown "nothing can call
      it". Downgrade explicitly, in the same round, in the ledger.
```

---

## 4b. Gateway-family builders: two hashes, one digest — the receiver trap

`GatewayVmPayloadBuilder` is the only family whose `curve()` returns **`"Ecdsa/Eddsa"`**
and whose `hashesToSign` returns **two** entries. That asymmetry is where a reviewer
wants to find the bug, so close it explicitly rather than hand-waving.

```solidity
// buildPayload L93-114 — params.data is attacker-chosen
GatewayVmPayloadData memory data = abi.decode(params.data, (GatewayVmPayloadData));
if (!_isEnabled(getAllocatorAllowedKey(data.allocator))) revert AllocatorNotAllowed(...);
if (gatewayPayload.burnIntent.maxFee > paidAmount) revert FeeExceedsPaidGas(...);

// _buildBurnIntent L222-241
sourceDepositor:      addressToBytes32(data.allocator),   // attacker-chosen + allowlisted
destinationRecipient: routing.destinationDepository,      // FROM CONFIG
sourceSigner:         addressToBytes32(data.allocator),   // attacker-chosen + allowlisted
destinationCaller:    routing.destinationDepository,      // FROM CONFIG

// hashesToSign L141-145 — BOTH hashes returned
hashes[0] = CircleGatewayCodec.hashBurnIntent(burnIntent);
hashes[1] = destinationBuilder.hashExecutionPayload(...);   // params.receiver lives here
```

The correct close is a three-link chain, and all three links must hold:

```text
1. destinationRecipient is CONFIG, not params   -> circle-level funds cannot be redirected
2. params.receiver is in hashes[1]              -> not silently dropped
3. the allocator STORES every hash it receives  -> see below
```

That third link is the one people skip. In the allocator:

```solidity
bytes32[] memory _hashesToSign = IPayloadBuilder(builder).hashesToSign(
    params.chainId, params.depository, payload);
for (uint256 i; i < _hashesToSign.length; ++i)     // ALL of them, not just [0]
  hashesToSign[withdrawRequestHash][i] = _hashesToSign[i];
```

Then the digest the spender actually signs must contain `receiver` **and** `data`
(otherwise `data.allocator` is free to swap):

```solidity
// _withdrawRequestDigest — all 10 fields
abi.encode(PAYLOAD_TYPEHASH, keccak256(bytes(chainId)), keccak256(depository),
  keccak256(currency), amount, keccak256(bytes(spenderChainId)), keccak256(spender),
  keccak256(receiver), keccak256(data), nonce)
```

```text
RULE  a multi-hash builder is only safe if the allocator persists ALL hashes AND the
      request digest binds the params the payload was built from. Verify all three in
      order; any one missing is a real finding, and the first two alone look clean.

RULE  a field named `allocator` inside `params.data` is a SIGNER/PAYER selector. Treat
      it as attacker-controlled until an allowlist check AND digest inclusion both prove
      otherwise.
```

---

## 4c. Bitcoin/UTXO builders: validate the DESTINATION script, not just the change script

`BitcoinVmPayloadBuilder` is the largest source in the corpus (26,680 chars) and the
easiest place to assume symmetry that does not exist:

```solidity
bytes memory receiverScript   = _protocolAddressToScript(params.receiver);  // L84 — no follow-up check
bytes memory feeChangeScript  = bitcoinParams.feeChangeScript;
_validateStandardOutputScript(feeChangeScript);                             // L86 — validated
uint64 allocatorChange = _computeAllocatorChange(params.amount, bitcoinParams.allocatorUtxos,
                                                 allocatorChangeScript);    // constructor constant
```

Read `_protocolAddressToScript` to its closing brace before concluding anything; here it
turned out to be **strict** (legacy tag `0xFF` with `[1] ∈ {0x00,0x05}`; witness v0 only
20/32; witness v1–16 program 2–40), with a single `revert InvalidBitcoinAddress` fallback.
That is why the asymmetry is safe: the parser itself is the gate.

The one real gap is a cross-function inconsistency worth a **LOW**:

```text
_protocolAddressToScript L508  v1-16 accepts programLength 2..40
_isWitnessScript        L607  v1-16 accepts programLength 2..40
Bitcoin Core consensus        witness v1 must be exactly 32 bytes
```

A v1 output with a 2-byte program builds fine and is **unspendable** — funds burned. It
still requires the spender's signature over `receiver`, so it is self-inflicted griefing,
not theft. Grade LOW and say so in one line.

```text
RULE  in UTXO builders, ask which script is validated and which is not:
      change/fee scripts usually ARE checked; the destination is usually only parsed.
      Read the parser to its closing brace — a strict parser is a valid gate, an
      absent one is the finding.

RULE  a valid-looking validator is not a consensus validator. Compare the builder's
      length/version bounds against the CHAIN's consensus rules; a mismatch that lets
      the builder emit an unspendable output is LOW/griefing, not value loss.
```

---

## 5. Closure table row for the builder ring

Add one row per VM family to `chain-closure-audit.md` §3. Shape:

```text
GATE                     PROBE / READ RESULT                        REOPENED BY
EVM builder (40+ chains) computeNonce binds 6/6 fields; all         a builder revision
                         attacker-chosen fields are signed  [CLOSED] that reads the sender
                                                                     from params
Solana builder           receiver len 32, currency 0|32,           a vault address read
                         amount<=uint64, vault from CONFIG  [CLOSED] from params
Ton builder              subwalletId=TIMEOUT const; native-only;     jetton support added
                         receiver len 32 enforced         [CLOSED] (currently rejected)
Ton queryId             23-bit, remap to slot0 -> reverb+rebuild    a slot re-used with
                         only; no value moves              [LOW]    different semantics
Gateway builder          destinationRecipient=CONFIG; two hashes    allocator stops
                         both persisted; digest binds receiver+data   persisting hashes[1]
                                                           [CLOSED]  or drops `data`
Bitcoin builder          destination parsed strictly; change         v1 witness output
                         script validated; v1 program 2..40        becoming spendable
                         accepted -> unspendable output    [LOW]
Config store (all VMs)   onlyAllocatorOwner live-reads              a setter that stops
                         allocator.owner(); setAllocator 0 calls;    reading owner() live,
                         N1/N2 N3/P1/P2 controls all live  [CLOSED] or an addConfigValue
                                                                     path without the gate
Config key derivation    keccak(PFX ‖ keccak(bytes(chainId)))        a reader that packs
                         47/113 decoded, anchored on live getter    chainId UNHASHED, or
                         values; PFX from the ACTIVE builder [CLOSED] a new prefix family
                                                                     introduced
Gateway allocator        ALLOCATOR_ALLOWED written 0/113;           admin writes the
allowlist (the            _isEnabled fail-closed; every allocator   allowlist key — then
activation key)          UNSET -> builder DORMANT for everyone,     the whole gateway mint
                         admin included                    [INFO]   path becomes live
Builder 0xafa3eb5b       no verified source                        unread — coverage
                         -> UNREAD, keep in coverage table [OPEN]   claim must say so
```

---

## 6. Checklist

```text
[ ] builders censused from setter CALLDATA, not from a getter that returned 0
[ ] every distinct builder ADDRESS listed (not just VM families); each is its own gate
[ ] builder with no verified source labelled UNREAD, not omitted
[ ] digest preimage printed field-by-field with CONSTANT / PARAMS / CHAIN-STATE marks
[ ] every SENDER-side field (subwalletId, from, source wallet) confirmed CONSTANT
[ ] uniqueness field (nonce / queryId) checked for full param binding
[ ] bounded-ID collision graded LOW/griefing unless a semantic replay is shown
[ ] hashesToSign raw-payload behaviour stated as an ON/OFF-CHAIN boundary, not a finding
[ ] developer comments admitting a bound quoted verbatim in the report
[ ] CONFIG/settings contract behind the builders read; its setters censused by SELECTOR
[ ] config setters negative-controlled (two distinct selectors = two live gates)
[ ] config KEY FORMULA derived from the ACTIVE builder and ANCHORED on a value known from
    a live getter — never guessed from a constant's name
[ ] config keys swept only after the formula reproduced a known value; 0/N match means the
    FORMULA is wrong, not that the key is absent
[ ] every allowlist/enable key the builder checks was probed for existence; an unwritten
    key + fail-closed reader = DORMANT surface -> INFO, not HIGH
[ ] a dormant surface corroborated by zero historical traffic in that lane before grading
[ ] multi-hash builders: ALL hashes persisted by the allocator AND params bound in digest
[ ] UTXO builders: destination parser read to its closing brace, not assumed symmetric
[ ] validator bounds compared against CHAIN CONSENSUS, not just internal consistency
```
