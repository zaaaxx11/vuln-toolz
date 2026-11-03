# Decode & proof traps — the four classes that each destroyed a round's verdict

Companion to `references/abi-and-field-verification.md` and
`references/selector-and-getter-form-traps.md`. Everything below is a **new** failure
class, each of which produced a wrong-on-the-record claim in a single campaign.

> **Also read** `references/empty-contract-and-event-decode-traps.md` §"Failure 2b" for the
> `bytes[]`-in-an-event offset base (`arr+1`, not `arr`) — the highest-frequency decode bug
> in round loops, and a distinct class from the tuple/struct cases below.

---

## §1 — TWO SIBLING INSTANCES, TWO DIFFERENT SOURCE REVISIONS

The single most expensive bookkeeping error in the session. A round was spent reading
"the Executor source" and comparing it to "the Executor ABI", then concluding a
contradiction existed in the protocol. The contradiction did not exist — **there were
two Executors with different entrypoints**, and the source of one was being read while
the address of the other was being probed.

```text
0x6747c7e6  RelayExecutor  ACTIVE   execute(request, callResolver, callResolverData, oracle, signature)
0x797b3ce4  RelayExecutor  ACTIVE   execute(request, callResolver, callResolverData, oracle, signature)   (same shape)
0x1e39aaff  RelayExecutor  NEWER    execute(request, Call[] calls, oracle, signature)   <- OPERATOR REVOKED

The unsigned-`calls[]` attack surface existed ONLY in the revision whose OPERATOR role
had already been revoked. The active revision replaced it with a fixed `callResolver`
address — a materially different (and much tighter) trust boundary.
```

**The tell that should have fired immediately:** the ABI signature list did not contain
the function the source defines.

```python
# BEFORE reading any source for a verdict, do BOTH:
live_len = int(rpc("eth_getCode", [addr, "latest"])["result"].__len__()) // 2
art_len  = len(artifact["deployedBytecode"]["object"]) // 2 - 1
ck("bytecode length matches the source's artifact", live_len == art_len,
   f"live={live_len} art={art_len}")

# and confirm the source's own function is in the LIVE ABI
abi = explorer_getabi(addr)
sigs = {f"{f['name']}({','.join(type_string(i) for i in f['inputs'])})"
        for f in abi if f["type"] == "function"}
ck("source fn present in live ABI", my_sig in sigs, f"have={len(sigs)} fns")
```

When either check fails, **stop auditing and map the deployment set first** (see
`references/multi-instance-trust-map.md`). Do not reconcile source against a
different address — every downstream conclusion inherits the mismatch. A source-derived
claim about revision A says nothing about revision B, in either direction: it can
manufacture a finding (surface that was removed) or hide one (surface that was added).

Corollary for severity: "the vulnerable pattern was **replaced** in the active
revision" is a legitimate mitigation observation and belongs in the verdict. It is not
a finding, and it does not transfer to the revision you were originally asked about.

### 1a. "SAME SOURCE, DIFFERENT BYTECODE" — prove the delta is immutables, don't eyeball it

Two deployments can be **byte-identical in verified source** (same md5, zero diff) and
still have different runtime bytecode. That is the normal, benign case — immutables
(`HUB`, `ALLOCATOR`, library links, `address(this)`) and the EIP-712 domain separator are
baked in at deploy time. The trap is *asserting* that, by eye, from a diff listing.

First attempt printed a hand-waved line and was wrong twice over: the run-splitter
grouped contiguous differing bytes per-byte (reporting **55** runs, lengths 1/4/6/7/11),
so the mask covered the wrong spans and the final comparison said
`code identical? NO` — a false alarm. Grouping runs on **byte offsets** gave the truth:

```python
diff_idx = [i for i in range(0, min(len(a), len(b)), 2) if a[i:i+2] != b[i:i+2]]
runs, runs_ok = [], diff_idx[:1]
for x in diff_idx[1:]:
    if x == runs_ok[-1] + 2: runs_ok.append(x)
    else: runs.append((runs_ok[0] // 2, (runs_ok[-1] - runs_ok[0]) // 2 + 1)); runs_ok = [x]
runs.append((runs_ok[0] // 2, (runs_ok[-1] - runs_ok[0]) // 2 + 1))

ma, mb = list(a), list(b)                     # a, b = stripped '0x' runtime hex
for off, ln in runs:
    for k in range(off * 2, (off + ln) * 2):
        ma[k] = mb[k] = "0"                   # blank the slot in BOTH
assert "".join(ma) == "".join(mb)             # <- this is the proof
```

Result that closes the question:

```text
[bytecode] differing runs: 15
[bytecode] total differing bytes = 312 of 9131 (3.42%)
[bytecode] after masking those 15 runs, code identical? YES
[bytecode] runs of 20 bytes (immutable addresses) = 14; runs of 32 bytes (EIP-712 domain sep) = 1
```

`14 × 20B + 1 × 32B = 312` — **every** differing byte sits inside an immutable slot or
the domain separator; not one opcode differs. That is a computed claim, defensible in a
report. Also print the decoded slots so the reader can see them (`0x…02c7` was `HUB`,
repeated 8×; `0x…1920` was `address(this)`).

Rules:

- **Never** write "no logic differences" from a visual diff scan. Mask-and-compare, or
  say UNPROVEN.
- Expect the counts to be **round numbers**: ~20 bytes per address immutable, 32 per
  bytes32/domain separator. A run of 17 or 23 bytes means you mis-grouped or the delta
  is *not* just data — investigate, do not average it away.
- If masked comparison still differs, you have found (or mis-derived) a real logic
  delta. Treat as high signal, not as noise.
- Independent of bytecode: confirm **byte-identical source** and **identical ABI
  function set** separately. All three together (source, masked bytecode, ABI) is what
  makes "this is a benign redeployment" a verdict instead of a guess.

---

## §2 — LOCALISE A PANIC BY CALLING THE INNER FUNCTION DIRECTLY

A composite entrypoint that reverts with `Panic(0x11)` tells you *nothing* about which
step reverted. Four rounds were spent treating that panic as "the authorization gate
rejected me", then as "the gate passed and burn failed", alternating.

The one comparison that settles it — call the suspect inner function yourself, as the
same `from`, outside the wrapper:

```python
# wrapper (composite path) — reverts, reason unclear
gc = rpc("eth_call", [{"from": OPERATOR, "to": ALLOC, "data": submit_calldata}, "latest"])

# inner function in isolation — same caller, same victim alias
inner = rpc("eth_call", [{"from": OPERATOR, "to": HUB,
                          "data": sel("burn(address,uint256,uint256)")
                                  + pad(alias_victim) + token_id + amount}, "latest"])

print("wrapper:", (gc.get("error") or {}).get("data"))
print("inner  :", (inner.get("error") or {}).get("data"))
```

Outcome table:

| wrapper | inner | conclusion |
|---|---|---|
| `Panic(0x11)` | `Panic(0x11)` — byte-identical | wrapper **cleared its gates**; panic came from the inner call's own precondition (usually `balanceOf == 0`). The gate question is ANSWERED: not rejected. |
| `Panic(0x11)` | clean result | inner call is fine ⇒ wrapper reverted *before* reaching it ⇒ find the earlier guard. |
| `CallerIsNotApproved` | n/a | wrapper's own authorization gate fired — inner call never attempted. |

The same technique localises any composite revert: for each `revert`-capable step in the
body, re-run that step standalone with identical arguments. Whichever standalone call
reproduces the wrapper's exact revert bytes is the culprit.

**Then name the precondition, don't stop at the panic.** `Panic(0x11)` from
`balanceOf[sender] -= amount` means the *victim alias held zero*. The correct verdict
line is "gate bypassed; inner call failed on empty balance" — not "blocked".

---

## §3 — REPLAY OF A SUCCESSFUL TX IS NOT A CONTROL (nonce consumption)

Attempting to replay a `status=0x1` transaction as a "the harness works" control
returned `CallerIsNotApproved` at both the original block and `latest`. Read naively,
that says the harness is broken or the gate is inconsistent. Neither.

```solidity
function consumeSpenderSignature(...) {
  if (signature.length == 0) return false;
  bytes32 spenderKey = keccak256(params.spender);
  if (usedNonces[spenderKey][params.nonce]) return false;   // <- already burned by the real tx
  ...
}
```

The nonce was consumed by the mined transaction, so the replay legitimately fails and
the caller falls through to `!callerAuthorized` ⇒ `CallerIsNotApproved`. **This is the
anti-replay working, not a bug and not a broken harness.**

Rules:
- **A successful past tx cannot be replayed as a positive control.** It is single-use by
  construction. If you need a control for a signature-gated path, mint a **fresh nonce**
  and prove the gate distinguishes caller classes instead.
- Block choice does not help: consumed state is consumed at every height ≥ its
  consumption block. Replaying at the original block still sees post-tx state for the
  mapping write that happened *in* that tx (same class as "`eth_call` at a successful
  tx's own block reverts").
- The revert you get back may be a **different error** than the guard you are studying
  (`CallerIsNotApproved` from a signature-fallback path). Resolve the error selector
  against the verified ABI before naming the gate.

Positive-control substitute that actually works — a caller-class differential on a
**fresh nonce**:

```python
for label, frm, spender in [
    ("non-operator, foreign spender", ATTACKER, VICTIM_SPENDER),   # expect: CallerIsNotApproved
    ("operator,      foreign spender", OPERATOR, VICTIM_SPENDER),   # expect: NOT CallerIsNotApproved
    ("non-operator, own spender",      ATTACKER, ATTACKER),         # expect: NOT CallerIsNotApproved
]:
    r = eth_call(from=frm, to=ALLOC, data=build(spender, fresh_nonce()))
    print(label, classify(r))
```

Live output from the campaign:

```text
T2  msg=EOA          spender=VICTIM   -> CallerIsNotApproved    <- negative control ALIVE
T1  msg=Executor     spender=VICTIM   -> Panic                  <- gate BYPASSED
T4  msg=Allocator    spender=VICTIM   -> Panic                  <- gate BYPASSED
T3  msg=Executor     spender=self     -> Panic                  <- positive control healthy
T5  msg=EOA          spender=self     -> Panic                  <- positive control healthy
```

Exactly one class is rejected. That pattern — one arm naming the gate, every other arm
getting past it — is what a proof of a bypass looks like. Note the **positive controls
(T3/T5) also return Panic, not success**: success is unreachable without a valid
builder payload and a funded alias, so "not rejected by *this* gate" is the correct
assertion, not "returns a result".

---

## §4 — DYNAMIC-ARG ENCODING: head offsets vs tuple-start pointer

Two separate wrong conclusions in one round came from mis-encoding / mis-decoding the
argument block. Both produced *plausible* output, which is what makes this class
expensive.

### 4a. Encoding a `(string,bytes)` getter

```python
# WRONG — head claimed the first dynamic arg starts at byte 64, but it starts at 32
sel + W(64) + '0'*64 + ...            # -> getter returned nothing / reverted into a false FAIL

# RIGHT — with exactly two dynamic args the head is: offset1=32, offset2=32+len1_padded
def enc_two_dynamic(sel, a: bytes, b: bytes):
    pad = lambda x: x.hex().ljust(((len(x)+31)//32)*32*2, '0')
    o1 = 32
    o2 = 32 + 32 + ((len(a)+31)//32)*32
    return (sel + W(o1) + W(o2)
            + W(len(a)) + pad(a)
            + W(len(b)) + pad(b))
```

The FAIL that came out of this was reported as "the payload builder is not installed on
this deployment" — a false negative about the *target*, caused entirely by the encoder.
**When a getter you expect to be populated returns zero, re-encode it a second way before
believing the zero.**

### 4b. Decoding a single dynamic-tuple argument

For `f((string,bytes,bytes,uint256,string,bytes,bytes,bytes,bytes32))`:

```text
calldata = selector ‖ offset_to_tuple ‖ <tuple body>
                              ^ 0x20 (32) when the tuple is the only argument
```

The tuple body then holds **9 field slots**, where each dynamic field holds a pointer
*relative to the tuple body start*:

```text
w[0]=chainId_ptr  w[1]=depository_ptr  w[2]=currency_ptr  w[3]=amount(uint)
w[4]=spenderChainId_ptr  w[5]=spender_ptr  w[6]=receiver_ptr  w[7]=data_ptr
w[8]=nonce(bytes32)
```

Reading the tuple as if it started at slot index 2 (i.e. treating the selector-arg offset
as a word index) shifts **every** field by two and yields a self-consistent but entirely
wrong picture — in this case `chainId="ton"` appearing in the `depository` position and the
nonce landing where `chainId` should be. It decoded cleanly. It was wrong.

**Anchor before trusting a tuple decode** (same discipline as the byte-vs-word rule in
`abi-and-field-verification.md` Rule 11):

```python
known_id = "a63129dd..."           # a value you already fetched from a real log/tx
i = calldata.find(known_id)
print(f"known value at byte {i//2}, slot {i//64}")
# If your decoder puts that value in a different field, your base is off. Fix the base; do not
# rationalise the mismatch.
```

Sanity invariants that catch a shifted tuple in one line each:

```python
ck("amount is a plausible magnitude", 0 < amount < 10**30, f"amount={amount}")
ck("chainId decodes to printable ascii", all(32 <= c < 127 for c in chain_id_bytes))
ck("depository length is 20 or 32", len(depository) in (20, 32), f"len={len(depository)}")
```

If `chainId` contains non-printable bytes you are reading padding or the wrong pointer —
stop, do not `errors="replace"` your way past it. (Silently substituting U+FFFD is how a
decode bug becomes a "weird chain name" in the report.)

---

## §5 — "HUB IS EMPTY" IS A FINDING-SEVERITY INPUT, NOT A REASON TO SKIP THE GATE PROOF

An authorization bypass was proven (see §3) while the affected deployment held
`totalSupply(tokenId) == 0` and every relevant alias balance was `0`. The temptation was
to downgrade the whole line of inquiry to INFO and move on. Both halves matter and they
are separate claims:

```text
CLAIM A (authorization): an OPERATOR-role holder can pass the spender gate with an
                         arbitrary victim spender.        -> PROVEN, this is the finding.
CLAIM B (impact):        that path can move this victim's funds today.
                                                          -> not demonstrated: balance is 0.
```

Report A and B as **separate labeled lines**. Never fuse them into "HIGH because funds
could move" (unsupported) or delete A because B is empty (loses a real defect).

Before writing B, check the empty-ness properly — one tokenId is not the deployment:

```python
for tid in candidate_token_ids:              # every id that appears in that hub's logs
    print(tid, total_supply(hub, tid), balance_of(hub, alias_victim, tid))
```

Also check the **sibling instance**: the same bytecode on another hub can be funded even
while this one is not (`references/multi-instance-trust-map.md`, and Rule 15 in
`abi-and-field-verification.md`). "Empty at block N" is a snapshot; the label is
`INERT AT <block>`, never DEAD.

### 5a. A metadata-registration event is not a mint — never read `totalSupply` as value

The same campaign then swung the other way. `totalSupply(tid)` came back large for 11
token ids on a hub that had only 52 lifetime txs (`setTokenMetadata` ×26, role ops ×25,
one deploy, **zero deposits**). That got reported as "REAL FUNDS FOUND — 200 trillion
units". It was neither real funds nor explainable from the txs that existed.

The decode that produced the error: `setTokenMetadata(uint256,(string,string,uint8,string,uint256,string))`
was read as `(name, symbol, decimals, chainFamily, supply, extra)` and `supply=792703809`
was announced as an amount. That field is the **chainId** (Solana). The struct has no
supply field at all. Both errors were self-inflicted and both nearly shipped.

Rules that would have blocked it:

- **Match the tuple arity to the ABI before naming any field.** `internalType` in the
  explorer ABI spells the tuple out (`tuple(string,string,uint8,string,uint256,string)`).
  A field you *infer* from position is a guess, not data.
- **`totalSupply > 0` is not value.** ERC1155 supply can be accounting, test inventory,
  faucet stock, or a metadata artefact. Supply is a **number**, not a price. Do not write
  "funds", "$X", or "trillions" off a supply read.
- **Cross-check supply against a value-moving event.** If a hub shows supply but its entire
  history contains no `TransferSingle` / `TransferBatch` / deposit, then you do not yet
  know where that supply came from — say exactly that, and stop. "Unknown provenance" is
  the honest label.
- **Holder discovery comes before impact.** `balanceOf` needs an address; do not guess
  addresses to make a story work. Enumerate holders from real transfer logs inside the
  narrow block windows the RPC will actually serve, or read `eth_getStorageAt` slots —
  otherwise the impact claim stays UNPROVEN.

Severity hygiene when supply exists but no holder is found: report the authorization
defect (CLAIM A) at its proven level and label impact `INERT AT <block> — no alias holder
with non-zero balance identified`. Never inflate with a supply number.

### 5b. `totalSupply > 0` with EVERY `balanceOf == 0` means the getter is not the ledger

The follow-up round tried to rescue the supply reading by brute-forcing holders: 70
candidate addresses (7 base actors × 9 chainId alias derivations) × 5 token ids, all
`balanceOf == 0`, while `totalSupply` stayed in the millions-to-quintillions.

That combination is **not** "we haven't found the holder yet" after 70 probes — it is
evidence the two getters do not read the same storage:

```text
totalSupply(tid) = 6822923201361962     (non-zero)
balanceOf(any, tid) = 0                 for 70 distinct candidates
=> totalSupply is NOT Σ _balances here. Unknown accounting, not missing holder.
```

Standard ERC-1155 defines `totalSupply` as the sum over holders; a deployment where
that identity fails is a **custom accounting surface** and must be described as such:

- Correct label: `SUPPLY-LEDGER DIVERGENCE — totalSupply populated, no reachable holder
  across N probed candidates; burn() therefore reverts on empty balance (consistent)`.
- Forbidden: "hidden holders exist", "supply is locked", "funds are trapped". All three
  are stories built on a getter whose relation to balances you just disproved.
- The divergence also **explains** an otherwise confusing `Panic(0x11)` from `burn()`:
  §2's "localise the panic" result (`burn` panics standalone with the same bytes) plus
  "no holder has balance" is a complete, closed explanation. Do not keep hunting for a
  fund-moving path once those two facts agree.

**Probe budget rule:** stop at ~50 candidates. Past that, the expected information per
request is near zero and the finding is about the getter, not about holders.

---

### 5c. A REBASING BALANCE IS NOT A CONSTANT — pin ONE block or every probe lies

A whole section of a round was spent chasing a `Panic(0x11)` that was an artefact of
time, not of state. Each `eth_call` with `"latest"` resolves to a *different* block, and
this token was a rebasing position whose `balanceOf` moves every block:

```text
balanceOf(VICTIM, TID) read across ~10 minutes of the same audit round:
  398746456  (figure carried in from the brief)
  1013602562
  10000000
  30256187870
  31258271651
  60501868215
  721387940
```

Three wrong conclusions were nearly drawn from that spread: "the context figure is stale,
someone converted out" (wrong — it rebases), "the balance underflows, so the drain is
blocked" (wrong — the balance grew after the read), and "VICTIM cannot even self-transfer,
so the hub is broken" (wrong — the amount was read at a later block than the send).

**Pin every read and every probe in a differential to one block number, and re-read the
balance at that same block for the amount:**

```python
HEAD = rpc("eth_blockNumber", [])["result"]          # pin ONCE for the whole section
bal  = eth_call(HUB, balanceOf_sel + A(VICTIM) + W(TID), block=HEAD)
amt  = int(bal, 16)                                   # amount read at the SAME height
r    = eth_call(HUB, transferFrom_sel + A(VICTIM) + A(ATK) + W(TID) + W(amt),
                frm=probe, block=HEAD)                # probe at the SAME height
```

Verification that the pin is real — repeat the same call at the pinned height and require
byte-identical results before believing any single reading:

```text
pin@head  178177840  178177840  178177840  178177840  178177840   <- 5/5, deterministic
pin@-5    60687473597  60687473597  60687473597                  <- 5/5, deterministic
```

Same block ⇒ identical every time. Different blocks ⇒ different numbers, legitimately.
So: **variance across calls is a block-height artefact until proven otherwise.** Do not
build a narrative about the token, the protocol, or the victim's behaviour on an unpinned
spread. When a balance "changes under you", print the block number next to it.

Corollary: a brief-supplied balance is a **hint, never a constant**. Re-read it, pin it,
and state the height you used in the verdict (`INERT AT <block>` style).

---

## §6 — TRUNCATED PRINT FED BACK AS INPUT (the least visible bug in the whole kit)

Two consecutive rounds were built on token ids that had been silently mangled **one line
before printing**:

```python
print(f'  tid={tid%10**12}  victim={v:,}  supply={sup:,}')      # <- for display only
...
json.dump([tid for tid,_ in have], ...)                          # <- WRONG id saved
```

`tid % 10**12` kept the last 12 decimal digits. The 256-bit id was then re-used as if it
were the real id, so the *next* round reported `balanceOf(VICTIM) == 0` for six ids and
concluded "no holder / funds gone". The lookup was correct; the id was fake.

```text
SYMPTOM : balances that were non-zero one round earlier are all exactly 0
          for every id, at every account
CAUSE   : the id was reformatted for human display and the reformatted value was
          persisted or fed to the next probe
FIX     : never mutate an identifier. Print a SEPARATE display field.

  short = tid % 10**12          # display
  print(f"tid=0x{tid:064x}  (~{short})")
  out.append(str(tid))          # full precision, always
```

Mandatory guards:

- Round-trip every id/address before use: `assert int(saved, 16) == original_full_value`.
- Prefer hex with fixed width (`f"0x{tid:064x}"`) over decimal in all artifacts —
  truncation of a decimal string looks like a legitimate number; a 64-hex string that
  lost characters is visibly wrong.
- Any balance that "disappeared" between rounds is a **state-or-bug** question. Check the
  id round-trip **before** concluding the chain changed. State does not vanish; your
  variable does.

Generalising (this is the same class as `truncation-and-reachability-discipline.md`, but
for **identifiers** rather than output rendering): whenever a value crosses from one
script to the next, it must cross as a value, never as output intended for a human.


