# ABI / Field-Verification Discipline

Every phantom finding in this session traced to **one root cause**: naming a field
before proving what it contains. Seven distinct errors, same class. None were
caught by the subagent that made them — each was caught by an independent probe.

Treat this file as a checklist you run *before* any claim leaves your mouth.

---

## The seven errors (all one class)

| # | Wrong conclusion | Truth | What would have caught it |
|---|---|---|---|
| 1 | `encodePacked` collision only works for some strings | UTF-8 2-byte makes it worse, not better | re-derive the encoding from the actual bytes |
| 2 | local ABI says `id` indexed, `amount` in data | live has `id` in `topics[3]`, `caller++amount` in data | `eth_getLogs` one raw sample |
| 3 | "live Hub bytecode ≠ repo source" | identical (explorer-verified) | compare selectors + storage layout, not size |
| 4 | `topics[1]` = caller (2,776 calls) | `topics[1]` = `from`; `data.w0` = caller | one `eth_getTransactionReceipt` cross-check |
| 5 | "allowance bypass — 1 unit drains all" | hard panic `0x11` above cap | **assert result is not a revert before SUCCESS** |
| 6 | `getSigners()` returned five `0x` addresses | offset decode wrong; real signers exist | decode with `eth_abi` and sanity-check |
| 7 | "`usedNonces` is read but never written" | write is at L113; `sed` window ended at L110 | read the function to its closing brace |
| 8 | "the live contract is a different version, `execute` is absent" | same contract; three hand-built selectors were all wrong | compare `len(eth_getCode)` vs artifact `deployedBytecode` length; build the selector from the artifact |
| 9 | "FAIL only" tracing a 21-byte spender through `relayAllocator` | `spenderAlias` is derived **before** the `len == 20` gate — 4 consumers, 1 gated | this is the Rule 7 inverse; see Rule 8 below |
| 10 | "`eth_call` reverts ⇒ the gate rejected me" | this RPC returns `{"code":3}` with **empty revert data**; a revert does not name the gate | replay a real tx's calldata, or mark UNPROVEN |

---

## Rule 1 — `error` before `result`, always

The single highest-frequency false positive in live RPC work. A reverting
`eth_call` returns either `{"error": {...}}` or `{"result": "0x"}`.

```python
res = rpc("eth_call", [tx, "latest"])
if "error" in res:                 # CHECK THIS FIRST
    return {"status": "REVERT", "reason": res["error"].get("data")}
out = res.get("result")
if out in (None, "0x", "0x0"):
    return {"status": "EMPTY"}     # NOT success
return {"status": "OK", "raw": out}
```

A panic code is your friend, not noise:

| Revert data prefix | Meaning |
|---|---|
| `0x11` | arithmetic underflow/overflow (panic) |
| `0x118cdaa7` | `OwnableUnauthorizedAccount` |
| `0xe2517d3f` | `AccessControlUnauthorizedAccount` |
| `0x2cf85d96` etc. | custom error — resolve via the verified ABI, never guess |

---

## Rule 2 — live event layout beats local ABI, every time

Compiled local ABI can drift from deployed bytecode (different compiler
settings, different release tag, patched source). The chain is the witness.

**Procedure:**
1. Pull exactly one log: `eth_getLogs` with a narrow 20–50 block window.
2. Print `topics` array and `data` length, raw.
3. Compute `keccak(signature)` locally for every candidate ordering and compare
   against `topics[0]`. If no candidate matches, the local ABI is wrong — stop.
4. Write down the resolved layout **before** writing any parser.

```python
# resolved example from the session (authoritative, from live logs)
#   topics[0] = 0x1b3d7edb...   <- differs from keccak(local signature)
#   topics[1] = from
#   topics[2] = to
#   topics[3] = id
#   data      = caller(32B) ++ amount(32B)
```

**Never** infer a layout from "the ABI says". Never infer it from a subagent's
summary. Print the raw.

---

## Rule 3 — one receipt per parsed field, before any census

Before counting anything by a parsed field, resolve one sample end-to-end
against `eth_getTransactionReceipt`:

- `tx.from` = the EOA that signed
- event `caller` / `data.w0` = the immediate `msg.sender` (may be an internal
  contract: executor, oracle, resolver)
- `from`/`to` fields = token owner movement, **not** the caller

In this session a passive holder with `nonce=0` and `balance=0` was labelled
"#1 caller, 30% of all activity" purely from a mislabelled `topics[1]`. One
receipt disproved it instantly. The economic-action framing was wrong by an
entire identity.

**Sanity gate:** if an address is credited with thousands of calls, verify it is
a contract (`eth_getCode`) or has non-zero nonce. An EOA with `nonce=0` cannot
be any `msg.sender` at all. That single check kills whole classes of phantom
findings.

---

## Rule 4 — read a function to its closing brace

`sed -n '55,110p'` cuts mid-function. Concluding "the write is missing" from a
truncated window produced error #7.

- Use `grep -n "function NAME" -A 60` and read until the brace closes.
- Or extract the whole function block programmatically and print it whole.
- If the claim is "X is never written", prove it with `grep -n "X"` across the
  **whole file**, not a range.

---

## Rule 5 — decode with a library, then sanity-check the shape

Hand-rolled offset walking is a suspect. A wrong offset produced five empty
addresses and nearly a "signers are 0x0 → forgeable threshold" conclusion.

- Prefer `eth_abi.decode` on the raw result.
- Sanity-check the shape: a `2-of-5` multisig must return 5 distinct non-zero
  addresses. If it returns zeroes, **your decode is broken**, not the contract.
- Differential test: encode a known value with `eth_abi`, decode it back, compare.

---

## Rule 6 — "no guard on the code" is not a vulnerability

Repeated pattern: find a missing `address(0)` check / missing `require`, declare
HIGH. This is almost always wrong.

**The question is never "is the guard missing" — it is "can an unprivileged
attacker reach the missing guard with a value they control".**

Worked example from this session:

```
_mint(receiver, id, amount) has no receiver != address(0) guard.
=> claim: HIGH.

Actual test:
  balanceOf(address(0), usdcTokenId)             = 0
  transferFrom(address(0) -> attacker, 1)        = panic 0x11
  transferFrom(address(0) -> attacker, 1e9)      = panic 0x11
  isOperator(address(0), attacker)               = 0
  allowance(address(0), attacker)                = 0
=> attacker cannot touch the trapped balance at all.
=> verdict: INFO. Standard ERC20 behaviour. Not a finding.
```

**Checklist before calling a missing guard a vulnerability:**
1. Who can reach the path (resolve every gate in between)?
2. Does the resulting state harm anyone other than the actor?
3. Can a third party monetise the harmed state? (Can they withdraw/liquidate it?)
4. If the answer is "only the privileged actor harms itself" → INFO, not HIGH.

---

## Rule 7 — a gate on ONE use-site does not gate the derived value

The inverse error, and the one that nearly hid a real (if inert) issue.

```solidity
address alias = generateAddress(params.chainId, params.spender);   // ALL bytes, no length check
bool callerIsSpender = params.spender.length == 20 && ...;         // gate here
bool callerIsOperator = hub.isOperator(alias, msg.sender);         // uses derived value
```

The `length == 20` gate guards **only** `callerIsSpender`. Everything downstream
consumes `alias`, which was derived from unvalidated bytes. Auditing the gate at
one use-site and declaring the whole path safe is how a genuine collision path
survives review.

**Procedure:** for any derived value (hash, alias, address, id), grep **every**
consumer and confirm each one is independently gated. Count them. State the
count in your verdict.

In this session: 4 consumers of `spenderAlias` — `isOperator`, `suspended`,
`consumeSpenderSignature`, `HUB.burn`. Only one was length-gated. The path was
still inert because the other three had their own gates, but the reasoning
required enumerating all four, not one.

---

## Rule 8 — never compute a selector by hand (error #8)

Hand-written struct signatures are wrong more often than right, and the failure mode is
*catastrophic in the wrong direction*: a missing selector reads as "the live contract is a
different version", which invalidates an entire round of analysis that was actually correct.

```python
# === WRONG: three attempts, three different selectors, all absent from the bytecode
"execute((string,bytes,...,(address,uint256)[],uint256,uint256),address,bytes,address,bytes)"  -> 0x9d79c526
# artifact components used verbatim, nested tuple kept                                    -> 0xba028c6e
# flattened, but nonce assumed uint256                                                   -> 0x5a8351d1

# === RIGHT: build from the artifact, flattening struct components
def type_string(inp):
    t = inp["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(type_string(c) for c in inp["components"]) + ")" + t[5:]
    return t
sig = f["name"] + "(" + ",".join(type_string(i) for i in f["inputs"]) + ")"
```

Then the discriminant that resolves the ambiguity:

```python
live = eth_getCode(TARGET)
art  = json.load(open("out/X.sol/X.json"))["deployedBytecode"]["object"]
len(live) == len(art)     # EQUAL -> same contract, your signature is wrong
                          # DIFFERENT -> genuinely another deployment; stop and say so
```

`nonce` being `bytes32` instead of `uint256` is invisible in a terse component dump and
silently changes the selector. Always read the declared `type`, never infer it.

Script: `scripts/build_selector_from_artifact.py`.

### Rule 8b — when you inherit a selector table, VERIFY it against a real tx before trusting any of it

The worst selector failure is not a wrong hash — it is a **wrong hash that is written down
somewhere you trust**. In this campaign a hand-built table asserted
`depositNative(uint256,bytes32) = 0x171377a9` and `depositNative(address,uint256,bytes32) =
0x8b2d6fa0`, and both were carried forward as fact.

**CORRECTION (later round, measured):** the live call is `0x49290c1c =
depositNative(address receiver, uint256 amount, bytes32 id)` — a **three-argument** function,
matching neither guessed signature. It was additionally recorded here as a two-argument
`depositNative(address,bytes32)`; that was also wrong. Two independent confirmations:

```text
input length = 0x49290c1c + 3*32 bytes = 100 bytes     (68 would be two args)
tx.value     = 1211516837221661                        (non-zero, and amount IS still a param)
```

So `tx.value != 0` does **not** prove the amount is absent from the signature. Both an
`amount` parameter and a `msg.value` can be present. Signature arity must come from the
calldata length, never from the presence of value.

Consequences that cost the whole round:

```text
1. A Foundry fork PoC calling 0x171377a9 reverted with EMPTY data.
2. Empty revert data was read as "the gate rejected me" (Rule 9) -> "id uniqueness is enforced".
3. The opposite was true: two real mainnet txs proved duplicate ids ARE accepted.
```

**The one-command ground truth.** Take a real tx hash that emitted the event you care
about, and read its calldata rather than any ABI:

```bash
cast 4byte 0x<first-4-bytes-of-input>      # -> depositNative(address,bytes32)
```

```python
tx = rpc('eth_getTransactionByHash', [REAL_TX])['result']
print(tx['input'][:10])                      # selector, as actually used
print(len(tx['input'][2:]) // 2, 'bytes')    # total calldata length
print('value:', int(tx['value'], 16))         # if amount is here, it is NOT a parameter
```

**Three discriminants, all mandatory before writing a PoC:**

| Check | Kills |
|---|---|
| `cast 4byte <selector>` resolves | wrong signature family |
| `(len(input) - 2 - 8) % 64 == 0` | a phantom "unexpected trailing bytes" claim |
| **byte length ÷ 32 == the argument count you assumed** | wrong arity — the one nobody checks |

The third one is the one nobody checks, and it cuts **both** ways. `depositNative(address,
bytes32)` *looks* like it is missing an amount, so a reviewer assumes the amount lives in
`msg.value` and writes a two-arg PoC — which reverts on a function that does not exist. The
mirror error is assuming `tx.value > 0` proves no amount parameter; it proves nothing. Count
bytes, and let the count name the arity.

```python
n_args = (len(tx['input']) - 2 - 8) // 64     # 100 bytes -> 3 args
print(n_args, 'args')     # cross-check against cast 4byte's signature length
```

**Selector tables are evidence, not configuration.** Any selector in a notes file,
a prior round's summary, or a previous agent's artifact gets re-derived from a live tx
before it is used in a probe. One real tx hash beats five hundred lines of ABI.

---

## Rule 22 — hex-string length is not byte length; a "malformed calldata" claim is ALWAYS your slice

The embedding counterpart to Rule 8b, and it produced a **retracted finding**: a claimed
"68-byte payload with an undeclared 4-byte trailing tail `0x865d8597`, therefore a
message-ambiguity primitive". There was no tail. `4 + 32 + 32 = 68`, which is a
perfectly-formed 2-argument call.

The whole error was slicing and then counting the wrong unit:

```python
inp = tx['input'][10:]          # strip '0x' + selector -> 68 HEX CHARS = 34 BYTES
print(len(inp))                 # 68  <- read as "68 bytes"
# then:  "68 bytes, and a 2-arg ABI only needs 64"  -> invented a 4-byte tail
```

**Two units, never mix them:**

```python
body_hex = tx['input'][10:]              # characters
body_bytes = len(body_hex) // 2          # BYTES  <- always divide by 2
assert (len(tx['input']) - 2 - 8) % 64 == 0, 'misaligned'
```

| Expression | Unit | 2-arg encode gives |
|---|---|---|
| `len(tx['input'])` | hex chars incl `0x` | `2 + 8 + 128 = 138` |
| `len(tx['input'][10:])` | hex chars, no selector | `128` |
| `(len(tx['input']) - 2) // 2` | **bytes** | `68` |

Symptom checklist for this bug: the "extra bytes" are fewer than 32, they sit at the very
end, and the resulting `len` is a multiple of 4 but not of 32. `68` is a multiple of 4.
That is the tell — **`68` is a correct calldata length, and reading it as "not a multiple
of 32" means you compared bytes against a byte-standard without dividing.**

**The discipline.** Before any claim of the form "the calldata is malformed / has a
trailing tail / carries an undeclared field", run the alignment assert on **bytes**. If it
passes, there is nothing there and the honest report is RETRACTION, not a downgraded
finding. A malformed-calldata claim is high-severity if true and humiliating if false —
it is worth the one extra division.

**Corollary — self-retraction is a first-class deliverable.** Two of the three "anomalies"
in that round were arithmetic, not the target. Both were retracted in writing
(`RETRACTION_F7.md`, `CORRECTED.md`) naming the exact slice that caused them, before any
further rounds were spent. Withdrawing your own claim costs one message; letting it reach a
report costs the engagement.

---

## Rule 9 — the instrument that returns nothing proves nothing

Two errors on the same day, one root cause: **an empty result was read as a negative finding.**

| Instrument | Apparent conclusion | Reality |
|---|---|---|
| `sed -n '55,110p' file.sol` | "`usedNonces[nonce] = true` is missing" | it is at L113, two lines past the window |
| `eth_call` on this RPC | "the gate rejected me (different revert per gate)" | this node returns `{"code":3,"message":"execution reverted"}` with **empty revert data** for every revert — the reason is simply not transmitted |

Positive control before any negative claim:
- If the claim is "this write does not exist", `grep -n <symbol>` the **whole file** and read
  the function to its closing brace first.
- If the claim is "this call is gated", prove the harness can see a *different* outcome at all —
  a sibling getter that does return data, a selector that *is* in the bytecode. Only then is a
  revert meaningful. With swallowed revert data, a revert cannot tell you *which* gate fired;
  use a real historical transaction's calldata as the ground truth, or mark UNPROVEN.

---

## Rule 10 — interrupted ≠ empty

A fan-out where every subagent reports `status=interrupted` with zero partial output is not
evidence that no work was done. Always check the artifact directory before re-dispatching:

```bash
ls -la /tmp/r<N>/     # *.md files, raw/ dumps, helper scripts
```

In this session the batch summary read `interrupted / partial output: Operation interrupted` for
all three agents — yet the directory held 95 + 44 + 32 lines of evidence-bearing scripts, and the
single real (medium) finding of the round came out of one of them. Discarding interrupted
subagent work silently is how a real finding gets lost.

---

## Rule 11 — ABI offsets are in BYTES, not words — and that error silently yields plausible garbage

The highest-frequency *mechanical* decode bug, and the nastiest because it does not crash: it returns
small integers that look like real pointers. `0x160`, `0x180`, `0x1a0` are perfectly believable offsets.

```python
# === WRONG — treats the slot index as the byte offset
def u(hexstr, word_idx): return int(hexstr[word_idx*64:(word_idx+1)*64], 16)
base = u(data, 1)          # -> 0x160  (the VALUE stored, misread as a position)

# === RIGHT — read the pointer, then index the hex string by BYTES
def u(h, byte_off):  return int(h[byte_off*2:byte_off*2+64], 16)   # *2 = bytes->hex chars
def dyn(h, base, rel):
    p = base + rel; ln = u(h, p); return h[(p+32)*2 : (p+32+ln)*2]

struct_base = u(data, 32)          # slot 0 holds a pointer, in bytes
chain_str   = bytes.fromhex(dyn(data, struct_base, 0))
```

Symptoms that you have this bug, in the order they appeared:
1. `UnicodeDecodeError` on a `string` field, with the error byte sitting at position ~31 — that is the
   **padding or the next pointer** bleeding into your slice, not a malformed payload.
2. `ValueError: invalid literal for int() with base 16: ''` — you walked past the end of the hex string,
   i.e. your byte offset was ~32× too large.
3. Every decoded field is a tiny round number (`0x160`, `0x1c0`, `0x200`) — those are offsets read as values.

**Never trust a decoded struct on the first pass.** Cross-check against a value you already know is in
the payload. The definitive move: `grep` the raw calldata hex for a known 20-byte address you got from the
brief/explorer, note the character position, and confirm your decoder reads that same position.

```python
# ground-truth anchor: find where a known address actually lives
known = "ffc84e09362a8a2ced180c7c977a47d490de1110"
idx = calldata.find(known)                 # char index -> byte = idx // 2
print(f"address at byte {idx//2}, slot {idx//64}")   # -> aligned slot wins outright
```

That one line settled a field in a single run after three failed offset hypotheses. **When a struct's
field turns out to sit flat at an aligned slot (no pointer indirection), say so and stop decoding** — a
fixed-width `address` inside a struct is inline, not behind a pointer, so `fields_that_are_addresses` can
often be read directly by slot. Static structs of fixed-width types have **no** per-field offsets at all;
only dynamic members (`string`, `bytes`, arrays) carry pointers.

---

## Rule 12 — placeholder provenance: never invent an input value

The failure mode that produces findings from nothing. It happens while **writing the proof script**, which is why
no amount of analytical rigour catches it — the reasoning is fine, the input was fiction.

Observed three times in fifteen minutes in one session:

```python
'eth-USDC':  0xae90 + 0                       # 44688. Not a tokenId. Arithmetic on a "value".
TOKEN_IDS = ['0xbf2f7b0e0e6b…' ]              # 64 hex chars of invention
rpc('eth_getTransactionByHash', ['0x2734c34f4ddd7459da0a1d4ea0…'])   # padded to look complete
```

The third class is the dangerous one. A fabricated `tokenId` passed to `balanceOf(order, id)` returns a **real
`0`**, which reads as *"this order address holds nothing → path is dead"*. **A negative finding manufactured from
invented input** — and it looks exactly like a verified negative.

**Rules:**

- **Every literal in an evidence script must trace to a fetch or a `file:line`.** No `+ 0`, no ellipsis inside a
  hex string, no truncated-then-padded hash, no `# placeholder`.
- **If you do not have the value, the next line is a fetch** (`rpc`, `curl`, `grep` over an existing artifact) —
  never a stand-in. In-session the correct move was `grep`ing the census output that already existed: 30 seconds.
- **Read your own script top-to-bottom immediately before running it**, scanning only for: unfetched literals,
  the word "placeholder", `…` inside quotes, arithmetic on something that is meant to be an identifier.
- **A stub you intend to fill is a STOP signal**, not a stub. Scripts that ship with "fill this in" comments get
  run un-filled.

This is the same root cause as the self-refutation streak — naming a value before proving it — but worse, because a
fabricated *input* propagates silently through every downstream number and leaves no trace in the output.

---

## Rule 13 — decode an event from its raw topics, then verify against a value you already know

Two near-miss phantom exploits in one round, both from the same mistake: reading
`data` words at assumed positions without first confirming how many words are
**indexed** vs **in data**.

The `Executed` event was declared as
`Executed(address,uint256,uint256,uint256,uint256,bytes32)` — 6 params. The ABI is
correct, but three of those params are `indexed`, so the log arrives as:

```
topics = [sig, orderAddress, tokenInId, tokenOutId]     # 4 topics
data   = [orderBalance, withdrawAmount, withdrawRequestHash]   # 3 words, NOT 5
```

Parser used `ws[1]` and `ws[2]` as `(orderBalance, withdrawAmount)`. In reality
`ws[2]` is the **32-byte request hash**, so `withdrawAmount` came out as
`8.95e76` — a number so absurd it read as a catastrophic drain. It was a decode bug.

**Rule: `data` word count = params − indexed count.** Derive it, don't assume:

```python
ev = next(e for e in abi if e["type"] == "event" and e["name"] == "Executed")
indexed = sum(1 for i in ev["inputs"] if i.get("indexed"))
print(f"{len(ev['inputs'])} params, {indexed} indexed -> data words = {len(ev['inputs']) - indexed}")
# 6 params, 3 indexed -> data words = 3   (if len(data)//64 != 3, your layout is wrong)
```

**Then anchor the decode on a primary control, not on plausibility.** Dump one
raw log and locate a value whose correct interpretation you already know:

```python
known_token_id = "bf442206ca81b4b0b8b1b3f0a290c277e9b2d7269209615d306c15a8cd8d3938"
log = receipt["logs"][k]
print("tokenId in topics? ", any(known_token_id in t for t in log["topics"]))
print("tokenId in data?   ", known_token_id in log["data"])
```

That single test moves the field from `data` to `topics` and settles the layout
outright. Two independent confirmations make it conclusive: a **same-signature
log** whose values you can predict (here `orderBalance == withdrawAmount == 100000`
in 7/7 events, which matches the transfer amounts already collected).

### The absurd-magnitude tripwire

Any decoded amount at or beyond ~10²⁴ for a normal token is **a decode error before
it is a finding**. Token supplies live in 10¹⁸–10²⁷ for 18-decimal assets; `10⁷⁶`
does not exist. Stop, dump the raw hex, and re-derive the layout. Reporting first
and checking later is how a marshal-grade fabrication ends up in the ledger.

Corollary: **a `data` word that is exactly 32 random bytes is far more likely a hash
than an amount.** Hashes decode to uniformly huge integers; amounts rarely do.

---

## Rule 14 — a positive control must be *empirically* live, not merely non-error

"Query returned a value" is not a working control. Three separate controls passed
this session while proving nothing:

| Control | Passed because | Actually |
|---|---|---|
| `totalSupply(0)` on Hub#1 and Hub#2 | both returned `0` without error | tokenId `0` doesn't exist — the query was healthy, the *subject* was empty |
| `balanceOf(VICTIM, tokenId)` at Hub#2 | returned `0`, no revert | two deployments don't share state; expecting the victim funded in both is a malformed invariant |
| "all 8-hex candidate addresses unverifiable" | check was written to always pass | self-satisfying assertion — not a check at all |

**A control earns its name only when it returns a value you can predict and verify.**
The working form:

```python
# WRONG: control passes on emptiness
ok = total_supply(0) is not None

# RIGHT: control must be non-zero and match a known quantity
v = balanceOf(HUB1, VICTIM, TID)
ck('C5', 'control: victim funded (query proven live)', v is not None and v > 0, f"balance={v}")
```

And when a control returns zero, ask **"is the subject empty, or is my instrument
blind?"** — then find a subject you *know* is non-empty (the victim's real balance,
a tokenId pulled from a real `Transfer` log) and confirm the same code path reports
a non-zero number.

### Guard against self-satisfying assertions

Any check whose condition is `True` by construction (`assert True`, `if len(x) <
99999: pass`, a claim that only restates its own premise) must be rewritten or
deleted. Test: **what observation would make this line print FAIL?** If nothing
would, it is not a control — it is decoration that inflates `13/13 PASS`.

### Threshold invariants must match the architecture

`victim funded in Hub#1 AND Hub#2` fails on a correct system when the two Hub
deployments are separate ledgers. Before writing an `and`, verify the two subjects
are supposed to share state. If they are independent worlds, the invariant is
`any(...)`, not `all(...)` — and the fix belongs in the claim, not the assertion.

---

## Rule 18 — a helper that returns `0x`-prefixed hex will splice `0x` INTO your calldata

The single most expensive bug of one session, and it never raised an exception. A
REVERT with `data: None` / `-32602 Invalid params` was chased through the contract's
logic for many turns while the real cause was one string concatenation.

```python
def pad(b):
    h = b.hex()
    return h.ljust(((len(h) + 63) // 64) * 64, '0')   # -> NO prefix (ok)

# later "improved" to build a full data blob and prefix it once:
def pad(b):
    ...
    return '0x' + h.ljust(...)                        # -> NOW PREFIXED

# and the caller does:
data = sel + W(32) + ''.join(fields) + ''.join(blobs)
```

Result: `...000002a00xec21200a4357…` — the literal `0x` sits 586 chars into the blob.
The RPC rejects the whole payload. **Every probe in the set fails identically**, which
reads as "the gate blocks everyone" / "the contract is a different version".

### The two-line defence (put both in every encoder)

```python
blob = '0x' + sel[2:] + W(32) + ''.join(head) + ''.join(tails)
assert all(c in '0123456789abcdef' for c in blob[2:]), 'non-hex char in calldata'
# length check must account for the 4-byte selector:
assert (len(blob) - 2 - 8) % 64 == 0, f'misaligned calldata len={len(blob)}'
```

### Same-class variants that all bit in one session

| bug | symptom | fix |
|---|---|---|
| `pad()` returns prefixed hex, spliced into a blob | `0x` mid-string | `pad(...)[2:]` at every splice site |
| `S()`/`Sel()` returns prefixed hex, concatenated with words | `0x` at position 0 of the blob body | `sel[2:]`, prefix once at the end |
| a `0x`-prefixed nonce passed into `W(...)` | 66-char word, misaligned | `W(int(nonce, 16))`, never `W('0x'+…)` |
| `assert '0x' not in data[2:]` written inside an **f-string message** | assert "fails" on its own error text | plain message, no `0x` in it |
| selector counted as a word in the alignment assert | `len % 64 == 0` fails on correct calldata | subtract `8` for the 4-byte selector |

### The rule, stated for reuse

**Normalise once, at the boundary.** Pick one convention — either every helper returns
bare hex and you prefix exactly once, or every helper returns `0x`-prefixed and you use
a `concat()` that strips. Mixing the two produces a *plausible-length* blob with `0x`
buried inside, and no exception is raised anywhere.

Corollary: **`Invalid params` / `data: None` on a call whose calldata you built by hand
is an ENCODER bug until proven otherwise** — check index/alignment of `0x` and total
length before re-reading the contract. See Rule 9 (an empty result is not a finding).

The old `pad(v)` also silently produced a **1-char-short tail** when `len(v) % 32 == 0`,
because `ljust` on the *hex length* rounds differently from padding *bytes*. Return
`W(len(v)) + (v.hex() padded to a multiple of 64 chars)`, and for `len(v) == 0` still
emit the length word (`W(0)`) with an empty tail.

---

A prefix carried in notes from an earlier round (`0x613d3c58`) is **not an address**.
Three rounds were spent scanning for it and probing it:

```text
explorer txlist address=0x613d3c58   -> {"message":"Invalid address format","result":null}
eth_getCode    0x613d3c58…<guessed>  -> 0x   (reads as "no contract here")
scan of 300 hub txs + 100 executor txs -> zero occurrences of the prefix
```

None of that is evidence the contract does not exist. It is evidence the *identifier*
was never resolved.

**Rule: never let an 8-char prefix reach a tool.** Resolve the full address from a real
occurrence first — `tx.from` / `tx.to` / a 32-byte word inside calldata — then probe.

```python
# harvest a full address FROM data, never reconstruct it
found = set()
for t in txlist(HUB):
    for f in ('from', 'to'):
        if t.get(f, '').lower().startswith(PREFIX):
            found.add(t[f])
    found |= set(re.findall(PREFIX + r'[0-9a-f]{32}', t.get('input', '')))
```

If the harvest returns empty, the honest report is **"address unresolved; this contract
does not appear in the activity of the instances I scanned"** — not "the contract is
absent" and not an invented suffix. A guessed suffix produces a *valid-looking* address
whose `eth_getCode` returns `0x`, which then reads as a dead-end finding about a
contract that was never the target.

### Rule 16a — `txlist` is a FILTERED view; scan BLOCKS for a prefix

The harvest above walks `txlist(HUB)` / `txlist(EXECUTOR)`, which only contains txs where
those contracts appear as `from`/`to`. **A contract that thousands of unrelated EOAs call
directly is invisible to every such scan** — which is why the prefix in this campaign
survived 14 rounds of "not found" across 300 Hub txs, 100 Executor txs and the Oracle.
It was `0x613d3c588f6b8f89302b463f8f19f7241b2857e2`: 8,496 bytes of live code, verified
source, taking 50/50 of its recent calls.

Resolution requires iterating **blocks**, not filtered lists — and every block you already
fetched for another reason carries the answer:

```python
found = set()
for B in blocks_i_already_fetched:                 # e.g. blocks around a balance change
    r = raw('eth_getBlockByNumber', [hex(B), True]).get('result') or {}
    for t in r.get('transactions') or []:
        for f in ('from', 'to'):
            v = (t.get(f) or '').lower()
            if v.startswith(PREFIX):
                found.add(v)
```

Corollary worth acting on immediately: **an address that is the `to` of many unrelated
EOAs is a public entrypoint** — the highest-value place to look for attacker-reachable
paths. A per-instance profile (`HUB()`, `ORACLE()`, `owner()`, recent selectors) is one
script away once the address resolves, and the instance's `owner()`/`ORACLE()` may differ
from its sibling even when bytecode is identical.

See `references/derived-address-identity.md` §1.

## Rule 17 — the sibling instance is where the funds are; probe BOTH before judging impact

The same audit proved an authorization bypass on a deployment holding `totalSupply == 0`,
spent a round establishing `SUPPLY-LEDGER DIVERGENCE`, and then found on the sibling hub
six token ids with real, non-zero `balanceOf(victim, tid)` totalling ~6.9e9 units.

The rule that generalises: **when the instance under test is empty, the very next
question is whether a sibling is funded** — not "is this dead", and not "hunt harder for
a holder in the empty one". Same bytecode, same trust boundary, different ledger state
is the common shape (see `references/multi-instance-trust-map.md`).

Order of operations for any impact claim:

```text
1. enumerate instances of the family (deploy block, HUB(), owner(), codesize)
2. for EACH instance: totalSupply(tid) AND balanceOf(actor_you_care_about, tid)
3. localise the bypass on whichever instance is CHEAPEST to reach the gate on
4. state impact on whichever instance is FUNDED - these may not be the same instance
```

Corollary for `transfer`/`burn` gating: a clean differential proving `transfer` is safe
(`from = msg.sender` only, `isOperator`-gated) on the funded hub is a real REFUTED and
must be recorded — it does not weaken the authorization finding from the other hub, and
they must not be merged into one verdict line.



`Panic(0x11)` in a `transferFrom` has **two** independent sources, and a probe that hits the wrong one
measures nothing while looking exactly like a refutation.

```solidity
if (msg.sender != sender && !isOperator(sender, msg.sender) && erc20Views[id] != msg.sender) {
  uint256 allowed = allowance[sender][msg.sender][id];        // SOURCE A
  if (allowed != type(uint256).max) allowance[sender][msg.sender][id] = allowed - amount;
}
balanceOf[sender][id] -= amount;                              // SOURCE B — OUTSIDE the guard
```

Source B fires for **every** caller when `balanceOf[sender] == 0`, *before* the allowance question is
decided. So probing an unfunded sender returns the same panic for the operator and for an attacker, and the
differential is destroyed.

This nearly refuted a finding that was already proven live on a sibling instance. The tell:

```text
from = operator   -> Panic(0x11)
from = attacker   -> Panic(0x11)      <-- IDENTICAL. This is a shared precondition failure.
```

A real gate produces **different outcomes** (`result != None` vs revert). Identical panic on both arms is
`PROBE-INVALID`. Never write `REFUTED` from it.

**Preconditions before any `transferFrom` differential probe — assert and print all three:**

```python
ck('balanceOf(sender, id) > 0', bal is not None and bal > 0, f'bal={bal}')
ck('totalSupply(id) > 0',       ts  is not None and ts  > 0,  f'ts={ts}')
# THEN differential:
#   from = operator-holder  -> expect result 0x…01 or 0x0000…0000 (no revert)
#   from = attacker         -> expect revert
```

Multi-instance corollary: two deployments of the identical bytecode can have **opposite** verdicts purely
because one is funded and one is not (`totalSupply == 0` on the sibling). Resolve which instance actually
holds value before probing, or you will audit an empty world and call the bug dead. See
`references/multi-instance-trust-map.md`.

---


Answer all seven in writing:

1. **Where is the raw hex?** No hex → UNPROVEN. Not "probably".
2. **Did I read the `error` field?** If unsure, re-run.
3. **What would a subagent say to break this?** If I cannot answer, it is not
   defensive enough.
4. **Is this role-gated?** If ADMIN/OPERATOR/ORACLE is required → label
   `HIGH-ROLE-ONLY`, never Critical.
5. **Did I build the selector from the artifact, and is it actually in the target?**
   If not, the target might not be the contract I audited.
6. **Does the exploit survive the profit identity?** If the attacker funds the
   injection and the victim receives the swept value, profit is zero → design note,
   not a finding.
7. **Can I point at where every input value came from?** Each tokenId, address, tx
   hash and amount in the PoC must be a fetched value or a `file:line`. Any stand-in
   invalidates the run — including (especially) a "clean zero" result.
8. **Is every control empirically live?** Each PASS line needs a failure mode that
   could realistically have fired. Delete or rewrite any check that cannot print FAIL
   (Rule 14). A `13/13 PASS` containing one tautology is a `12/12` with a lie in it.
9. **Did both arms of my differential revert IDENTICALLY?** If yes → `PROBE-INVALID`,
   not `REFUTED`. Verify `balanceOf(sender) > 0` and `totalSupply(id) > 0` on the
   *instance actually under test* first (Rule 15).
10. **Did I kill any claim of my own this round?** Every round must end with an explicit
    list of claims generated *and discarded* during it. A round that produced no
    self-refutation is either trivial or under-checked — in this session two
    near-delivered false reports (a "hub with no admins" and an "unauthorised grant")
    were both killed by this step, and that list is the proof the gate ran.
11. **Did I name any struct field from its position instead of from the ABI?** Read the
    declared `internalType`/`components` before writing a decoder. A `chainId` read as a
    `supply` field produced a headline "REAL FUNDS FOUND — 200 trillion units" that was
    pure fabrication-by-decoding. Categories of number that require a label before use:
    **supply ≠ value**, `totalSupply > 0` ≠ funds present, `balanceOf == 0` for every
    actor you guessed ≠ "the world is empty" (it means you never found a holder).
    **If `totalSupply > 0` survives ~50 distinct holder probes that all return `0`, stop
    probing and reclassify — the getter is not the balance ledger**
    (`SUPPLY-LEDGER DIVERGENCE`), which also fully closes out a standalone `burn()`
    `Panic(0x11)` rather than inviting another round of fund-hunting.
    See `references/decode-and-proof-traps.md` §5a / §5b.

---

## Rule 19 — EIP-712 calibration: take the TYPEHASH from the BYTECODE, not from the repo

When a signature-recovery loop yields **N distinct random addresses, one each**, your
digest is wrong — it is *not* N different signers. That symptom is unambiguous and was
misread for four rounds (`correction #47`) while 12 encoding combinations were
brute-forced against a source file that was never the deployed contract.

**The decisive move, and it takes one script:** the typehash is a `PUSH32` constant
sitting in the runtime bytecode. Extract it and compare to `keccak(signature_you_assumed)`.

```python
code = rpc('eth_getCode', [TARGET, 'latest'])[2:]
# every PUSH32 = 0x7f followed by 32 bytes
cands = {code[i+2:i+66] for i, c in enumerate(code) if c == '7f'}
for c in cands:
    h = keccak(c_bytes)
    if h == keccak(b'CallRequest(...)'):
        print('typehash MATCHES source -> source == bytecode')
    # no match at all -> the struct you are hashing is not the struct that was deployed
```

Pair it with `eip712Domain()` read on-chain — never with the domain you inferred:

| Field | How you get it | Trap |
|---|---|---|
| `fields` | `eip712Domain()` word 0 | **`0x0f` is a BITMASK, not a count/huge int.** `0x0f` = all four fields present |
| `name` / `version` | dynamic — offset at word 1 / word 2, **byte offsets into the blob** | read the offset words, don't assume the strings sit at fixed slots |
| `chainId` | `eip712Domain()` | **may not match the chain you are on.** A `137` domain on a chain-537713-looking target is legal (a deployer reusing a Polygon domain) and invalidates every digest you calibrated against the local chain id |
| `verifyingContract` | `eip712Domain()` | must match the contract actually doing `isValidSignatureNow` |

**Anti-pattern that cost 12 failed combinations:** cycling `abi.encode` vs
`abi.encodePacked` on the call-hash array, varying field order, varying the
`\x19\x01` prefix. Once the domain and typehash are byte-verified those variations
are noise — if they all still fail, the **struct shape** is wrong, not the encoding.
Go back to the bytecode and the `.sol` for the struct definition.

**Stop rule:** after ~3 structurally distinct digest hypotheses all fail, label the
question **UNPROVEN** and say so. Do not emit a 13th combination. An unresolved digest
means you cannot state whether the entrypoint is open *or* closed — and both are
findings you are not entitled to.

---

## Rule 20 — a source file in your repo is not the deployed contract

A local `.sol` with a similar name is a **file system fact**, not a chain fact. In this
session `RelayGatewayDepository.sol` sat next to `RelayDepository.sol`, and the mere
existence of the Gateway file nearly branded the target as a Gateway (`correction #50`).
The two contracts differ on the single most important axis: **the Gateway whitelists the
token (`if (token != USDC) revert`) and has a `depositsEnabled` kill switch; the plain
Depository has neither.**

**Identity must be established by selector-set membership in the live bytecode:**

```python
def sel(sig): return keccak(sig.encode())[:4].hex()
evidence = {name: (sel(sig) in code) for name, sig in {
    'execute':      'execute(((address,bytes,uint256,bool)[],uint256,uint256),bytes)',
    'depositErc20': 'depositErc20(address,address,uint256,bytes32)',
    'sweepAll':     'depositErc20(address,address,bytes32)',
    'allocator':    'allocator()',
    'callRequests': 'callRequests(bytes32)',
    # discriminating set for the sibling:
    'GATEWAY_WALLET':   'GATEWAY_WALLET()',
    'depositsEnabled':  'depositsEnabled()',
    'USDC':             'USDC()',
}.items()}
```

Then read the result as a **discriminant table**, not a similarity score:

| Observed | Verdict |
|---|---|
| core selectors present, `GATEWAY_WALLET`/`depositsEnabled`/`USDC` **absent** | plain Depository — **token whitelist and kill switch do NOT exist here** |
| those three present | Gateway — whitelist + `depositsEnabled` exist, and are live gates you must test |

Getting this wrong inverts the security conclusion on the *same bytecode-sized*
contract. Two contracts can be near-identical in size and share most selectors while
differing on exactly the gate you care about. Always enumerate the **negative**
selectors too — the one that is *missing* is often the finding.

Corollary: bytecode-embedded creation templates reveal siblings
(`602c3d8160093d39f33d3d3d3d363d3d37363d73` = an EIP-1167 creator). Follow the
factory → impl → clone chain before deciding which implementation you audited.

---

## Rule 21 — auth-open is not a vulnerability; run the FUND-DESTINATION test

The strongest-looking no-key finding of the campaign, and it is correctly **NONE**.
An unpermissioned `depositErc20(depositor, token, amount, id)` accepted an arbitrary
`depositor` with no `msg.sender` check — proven on mainnet, not in theory:

```text
19,170 events / 54k blocks   no whitelist   no depositsEnabled   amount=0 accepted
35/40 sampled txs:  event.depositor != tx.from      <- the field IS free
top depositor      0xfe9fc1e5…  678 events  total 19,465,065.17  (a payment aggregator)
real flow: user -> router 0x00000000000fb5c9…(sel 0x0a3c4405) -> depositErc20(depositor=user)
```

Volume alone reads as an exploit in progress. The adjudication is three questions, in
this order — **all three must fail for it to be a finding:**

1. **Who pays?** `safeTransferFrom(msg.sender, address(this), amount)` — the caller
   funds it from their own balance. Free spoofing is impossible.
2. **Where do the funds go?** Into the contract, **not** to `depositor`. A free
   `depositor` field is a *credit attribution label*, not a withdrawal claim.
3. **Can the credited party monetise it without a further gate?** No — withdrawal
   still requires `execute()` with an allocator signature. Setting someone else's
   credit is a **donation**, not an attack.

**Name the identity explicitly in the verdict:** `AUTH-OPEN-BY-DESIGN` + the
aggregator role that legitimises it, plus the evidence that the free field is
*normal usage* (19k events, 87.5% third-party depositor). A field that is free **and
used by thousands of legitimate counterparties** is a feature. A field that is free and
**used by nobody** is an untested surface — different report.

**When the off-chain consumer is out of reach, say so.** Whether the backend credits
from the event without re-checking `tx.from` is a *backend* fact. You cannot prove it
from chain data. The honest line is: "*event is not bound to `msg.sender`; backend
correlation is unverified; the heavy third-party usage pattern indicates the backend
accepts this by design*" — then stop. Do **not** promote an unverifiable backend
assumption into a Critical.

**And run the pUSD check before shouting "fake token".** A 61-byte, unusual-prefix
token that shows up in deposit logs is very likely a legitimate **EIP-1967 minimal
proxy** (`0xc011a7e1…` = Polymarket USD, `totalSupply` 470M). Verify
`name()`/`symbol()`/`totalSupply()` before writing the word "fake" (`correction #52`).
