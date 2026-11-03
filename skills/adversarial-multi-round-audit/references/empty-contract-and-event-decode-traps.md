# EMPTY-BUILDER / EMPTY-CONTRACT FALSE POSITIVES

Two independent decoding/truth failures produced a fabricated "CRITICAL data-loss"
finding on live mainnet. Both were caught only by re-probing. This file is the
checklist that prevents both.

## Failure 1 — `eth_getCode` returning `0x` is NOT proof a contract is absent

Symptom observed:

```
eth_getCode(builder, 'latest')   -> 0x          (empty)
eth_getCode(builder, 5003102)    -> 0x
eth_getCode(builder, 6190000)    -> 0x
eth_getCode(builder, 'latest')   -> 6887 bytes  (later, same call!)
```

Meanwhile the explorer `txlist` for that address showed a real deploy:

```
blk 5002576  from=0x28c5..  to=  sel=0x60e06040  contractAddress=0xda7a..  <- CREATE
```

Diagnosis: the RPC node served incomplete historical state for that address
(archive gap / load-balanced node not in sync). The contract existed the whole
time.

## Failure 1b — `eth_getCode` is unreliable for **historical** blocks, even when `latest` works

The same address, probed across blocks, produced a clean bisect that looks like a
deployment timeline but is pure node artefact:

```
blk 5,003,102   0 bytes      <- registration block
blk 5,274,775   0 bytes      <- the "burned" withdrawal
blk 5,400,000   0 bytes
blk 6,190,000   0 bytes
blk 'latest'    6,887 bytes  <- contract is REAL and was deployed at 5,002,576
```

The contract was deployed at blk **5,002,576** (visible via `txlist` `contractAddress`
on a CREATE tx) and live the entire time. The archive node simply did not serve
historical `eth_getCode` for that address. **A zero at a historical block is not
evidence of absence at that block.**

### Rules
1. **Never conclude "contract does not exist" from a single `eth_getCode`.**
2. Cross-check with `?module=account&action=txlist&address=<ADDR>` — a
   `contractAddress` field on a deploy tx proves existence, with the deploy block.
3. Re-issue `eth_getCode` at `latest` **more than once**; a flapping response
   means the node is unreliable for that address, not that code is absent.
4. **A historical-block zero must be overruled by a deploy tx.** If `txlist` shows a
   CREATE to the address at block N, the code existed from N onward — regardless of
   what `eth_getCode(addr, N+k)` says. Mark the historical read `NODE-ARTEFACT`, not
   `EMPTY`.
5. When timing matters (was the contract live when the event fired?), do **not**
   bisect `eth_getCode`. Instead take the historical **receipt of the tx in question**
   and read whether the call succeeded plus what it emitted — receipts are ground
   truth in a way historical state reads are not on a load-balanced RPC fleet.
6. If `getsourcecode` returns `ContractName=None`, that only means *unverified*
   — it is not evidence of absence either. Always pair it with a live control
   address that IS verified and one that is definitely an EOA, and compare.
7. A "builder points at empty address" hypothesis must ALSO survive:
   - deploy tx exists? (txlist)
   - code at `latest` repeated probes? (2×)
   - a real withdrawal succeeded after the suspected break? (receipt `status`)

## Failure 2 — event ABI decode: offset word is NOT a length word

Event with two dynamic params plus an indexed param:

```solidity
event PayloadBuilt(bytes32 indexed withdrawRequestHash, bytes payload, bytes32[] hashesToSign);
```

`data` head layout (after the indexed topic is removed):

```
w[0] = offset(payload)
w[1] = offset(hashesToSign)
...
w[o_p] = len(payload)
w[o_h] = len(hashesToSign)
```

The bug: reading `w[2]` as "array length" when `w[2]` is actually
`len(payload) == 0x1e0 == 480`. The script printed "ARRAY LENGTH = 0" and the
whole run concluded funds were burned with no payload. In reality
`hashesToSign.length == 1` and `payload` was a full 480-byte struct.

### Rules
1. For any event with ≥2 dynamic params, resolve **each** offset independently:
   `idx = int(word,16)//32`, then `length = int(words[idx],16)`.
2. **Sanity-anchor every decode against a value you already know from calldata.**
   In this case the request was `amount = 1_200_000` and the decoded payload
   should contain `0x124f80`. It did. That anchor alone would have killed the
   false finding instantly.
3. If a decoded dynamic field comes back `length == 0`, treat it as a
   **decode-bug signal first**, contract behaviour second. Re-decode by hand.
4. A zero-length result plus a `status=0x1` receipt is a contradiction:
   a legitimate burn-without-payload would usually revert or emit a distinct
   error path. Contradiction ⇒ re-derive, don't report.
5. Print the raw word array (`w[i] = ...`) before interpreting. Visible words
   make offset bugs obvious; summaries hide them.

## Failure 2b — `bytes[]` inside an event: element offsets are relative to `arr+1`, NOT `arr`

**The highest-frequency decode bug in round loops.** It produced two wrong readings of the
same production event stream in one session, and both looked plausible enough to report.

Event carrying an array of dynamic blobs:

```solidity
event Executed(bytes32 indexed idempotencyKey, bytes[] actions);
```

Correct layout, with `W = data` split into 32-byte words:

```text
W[0]        = 0x20              offset to the array
W[arr]      = n                 length, where arr = int(W[0],16)//32
W[arr+1..]  = n element offsets, EACH RELATIVE TO (arr+1)     <-- the tripwire
```

Resolving one element:

```python
arr  = int(W[0], 16) // 32
n    = int(W[arr], 16)
base = arr + 1                       # offsets are measured from HERE
for k in range(n):
    rel  = int(W[base + k], 16) // 32
    hdr  = base + rel                # word holding this element's length
    blen = int(W[hdr], 16)
    body = "".join(W[hdr+1 : hdr+1+(blen+31)//32])
```

### The two failure signatures this produces

Both were observed on the *same* event type, in sequence:

```text
BUG A: hdr = arr + rel        (off by one word)
  -> every element shifts by one word
  -> you read the NEXT element's type byte
  -> "actionType=0 (MINT) x18466, actionType=2 (TRANSFER) x18462"   <- 1:1 micratio is the tell
     In truth: 18,466 MINT, 18,460 TRANSFER — the ratio was real, but by luck;
     a concurrent 2-action sample decoded as "MINT+MINT" and was read as MINT+TRANSFER.

BUG B: treating W[1] as the count instead of W[arr]
  -> n=1 for a 2-element array, or parse_error for every row
```

### Rules

1. **Off-by-one in array-of-dynamic offsets shows up as a `1:1` distribution** across two
   type values. Real protocol traffic is never that cleanly bimodal. Treat near-exact 1:1 as
   a decode bug until proven otherwise.
2. **Always dump the full word array for ONE known-complex row** before aggregating. Pick a
   row you already know has ≥2 elements (scan for a row whose `len` word is `2`), print every
   word with its index, and hand-verify the offsets. Aggregates hide this; a single dump exposes it.
3. **Anchor on a value you already know.** If a decoded `amount` matches a number you fetched
   independently, the base is right. If decoded addresses are all `0x000…0003` / `0x000…0002`,
   you are reading type bytes, not addresses.
4. Decoding `bytes[]` of heterogeneous actions means **the type byte is a free parameter you
   must never assume** — read it, print the distribution, and only then group.
5. This applies identically to `bytes[]`, `string[]`, and arrays of dynamic tuples. The
   `arr+1` base is an ABI rule, not a contract quirk.

## Failure 3 — 44-byte "deposit address" is a forwarder, not a vulnerable vault

A per-order `depositAddress` returning 44 bytes of code invites the read "tiny proxy,
maybe swappable implementation → steal deposits". Measured, it was a hard-coded
EIP-1167-style clone:

```
3d3d3d3d 363d3d37 363d73 <20-byte IMPL> 363d3d37363d34 f4 3d3d93 80 3e 602a57 fd 5b f3
```

Rules:
1. **Decode the PUSH20 out of the bytecode.** If the implementation is a literal in
   the runtime code, the proxy is **not upgradeable** — "swap the impl" is off the
   table and the whole line of inquiry dies honestly.
2. Fetch the implementation's code and list its selectors. 893 bytes / 3 selectors is
   a forwarding helper (revenue recipient getter, router/impl getter, revert). Nothing
   in it holds funds.
3. **Prove where the money goes with a historical token balance, not a narrative.**
   `balanceOf(clone, depositBlock)` = 10,000,000 then
   `balanceOf(clone, depositBlock+1)` = 0 and `nonce(clone)` = 1 is a complete proof
   of pass-through forwarding. Funds never rest ⇒ no orphan, no drain, no finding.
4. A clone deployment that is byte-identical across sampled orders confirms one shared
   implementation — enumerate 2+ clones and `diff` the code before generalising.
5. Same trap shape for `depositAddressType:"open"`: if `depositAddress.address` equals
   the order's `user`, it is the user's own address and is safe by construction.
   Compare the strings exactly; do not infer "predictable ⇒ front-runnable".

## Retraction discipline

When a probe contradicts a delivered claim:
- Retract in the same channel, explicitly, in a table: claim → status (`SALAH` / `BATAL`).
- State the mechanical cause (which line, which word, which call) — not a vague apology.
- Never let the retracted item linger in the ledger as "probably still valid".
- Re-state the surviving ledger after retraction so the operator sees ground truth.

## Coverage note (Relay-style allocator/builder stacks)

A systematic sweep is cheap and should precede any claim about a specific
builder. Enumerate **every** `setPayloadBuilder` tx per allocator, take the final
builder per chain, then batch `eth_getCode` across them. One sweep (161 entries)
turned an alleged isolated bug into "1 empty entry, and it was a legitimate
deprecation with zero withdrawals after". Sweep first, then theorise.
