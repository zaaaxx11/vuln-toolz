# Bytecode disassembly + storage-override forensics on a live contract

Condensed from a Relay Protocol session where the ONLY way to progress was to
dissect two unverified deployed contracts (`RelayHub`, and a "batcher" wrapper
that fronted `RelayExecutor`) and use `eth_call` state override to build the
test the target would not otherwise allow.

Read this when:
- the source repo does not match the deployed bytecode,
- the entrypoint you must hit is unverified / undocumented,
- `cast call --from X` would be impersonation (useless as an authz proof),
- `debug_traceCall` / `eth_getProof` are unsupported and revert data is swallowed,
- you need to test a function whose precondition (`usedRequests[digest]`,
  balance, allowlist) cannot be satisfied for real.

---

## 1. Disassembling a deployed contract without source

```bash
cast code 0xTARGET --rpc-url $R > t.hex      # hex string, no 0x prefix
cast disassemble $(cat t.hex) > disasm.txt   # one instruction per line
wc -l disasm.txt                              # ~2.4k lines for ~3.4 KB of code
```

`cast disassemble` output is `offset: MNEMONIC operand` per line. That is all you
need for dispatcher extraction — no pyevmasm required.

### 1.1 Extracting the dispatcher — the `PUSH3` trap (BURNED ME)

The canonical Solidity dispatcher is `DUP1 PUSH4 <sel> EQ PUSH2 <dest> JUMPI`.
**A selector whose first byte is `0x00` is emitted as `PUSH3`, not `PUSH4`.**

Real transcript from the session:

```
000001fb: PUSH3 0xfdd58e
000001ff: EQ
00000200: PUSH2 0x0248
00000203: JUMPI
```

`0x00fdd58e` is `balanceOf(address,uint256)`. A naive extractor that greps only
`PUSH4` misses it and you will conclude — wrongly, and in writing — that the
contract is not ERC-1155. That false negative cost a full round.

Correct extraction:

```python
lines = open("disasm.txt").read().splitlines()
sels = []
for i, l in enumerate(lines):
    if "PUSH4" in l or "PUSH3" in l:              # <-- PUSH3 is mandatory
        v = l.split()[-1]                          # e.g. "0xfdd58e"
        if "EQ" in " ".join(lines[i+1:i+3]):
            sels.append("0x" + v[2:].rjust(8, "0"))   # normalize to 4 bytes
```

Notes:
- Normalize with `.rjust(8,"0")` so `PUSH3 0xfdd58e` becomes `0x00fdd58e`.
- Handle `PUSH2`/`PUSH1` too if you go below 3 bytes (same bug class).
- `PUSH3`/`PUSH4` also appear as plain constants (address fragments like
  `0xDDD361727C…`, chain ids like `0x083471`). A candidate is only a real
  selector if followed by `EQ` and a `JUMPI`.
- **Verify each candidate by calling it.** A selector that returns data is real.
  A selector that reverts on empty calldata may still be real (it needs args) —
  so a revert is not disproof, but a return value is proof.

Cross-check against a known reference implementation. In this session 12 of the
16 extracted selectors matched `Multicall3` exactly (`0x82ad56cb` aggregate3,
`0x252dba42` aggregate, `0x3408e470` getChainId, `0x4d2301cc` getEthBalance,
`0x42cbb15c` getBlockNumber, `0x0f28c97d` getCurrentBlockTimestamp…), which
immediately identified the "mystery batcher" as a stock `Multicall3` deployment.
Diffing extracted selectors against a known ABI is the cheapest attribution
technique available.

### 1.2 Reading a contract's own idea of its hash

Before reimplementing any EIP-712 / struct hash in Python, check whether the
contract exposes a getter for it:

```bash
cast call $TARGET "hashExecuteAndWithdrawRequest((...))" <args> --rpc-url $R
```

If it does, ask the contract instead of guessing. In the session the local
reimplementation matched the on-chain getter exactly (`0x3930fd17…b6d12d`),
which converted "my hashing might be wrong" into "my hashing is right, so the
revert must be elsewhere." That single call replaces a whole class of dead ends.

Then independently confirm the signature against the real verifier:

```bash
cast call $ORACLE "isValidSignature(bytes32,bytes)" <digest> <sig> --rpc-url $R
# expected magic value: 0x1626ba7e
```

Also check which verifier the runtime actually contains — grep the bytecode for
each candidate selector:

```python
sel in eth_getCode(target).lower()   # "7f035d73" isValidSignatureNow -> absent
                                     # "1626ba7e" isValidSignature    -> present
```

Source may say `isValidSignatureNow` while the deployed contract only implements
ERC-1271 `isValidSignature`. Trust the bytecode.

---

## 2. `eth_call` state override — testing preconditions you cannot satisfy

Probe support first: if the call returns data, override is available; if it
errors with an unsupported-method message, fall back to source reasoning + forge.

`chain-specific `stateDiff` override works even when the node reports
`hasStorageLayout: false` and the forge artifact carries no `storageLayout`
field — you just have to derive the slot yourself.

### 2.0 Override ENCODING — 90 minutes lost to this (BURNED ME, twice)

Some RPCs (Observe/Relay-style stacks) reject any non-32-byte-padded hex with a
nonsense error. The error text blames the wrong thing, so it reads like "this RPC
does not support overrides":

```
{"message":"Invalid params","data":"invalid string length at line 1 column 4779"}
{"message":"Invalid params","data":"odd number of digits at line 1 column 138"}
{"message":"Invalid params","data":"invalid type: sequence, expected a map at line 1 column 1"}
{"message":"Invalid params","data":"unknown field `balance`,`nonce`,`code`,`state`,`stateDiff`..."}
```

Each message is actually telling you the SHAPE rule. Decode them:

| Error text | Real cause |
|---|---|
| `invalid string length` / `odd number of digits` | value not 32-byte padded: `"0x1"` / `"0x309"` are rejected → use `"0x" + hex.rjust(64,"0")` |
| `invalid type: sequence, expected a map` | you passed the uniswap-style ARRAY form `[{address, stateDiff}]`; this node wants an OBJECT keyed by address |
| `unknown field <slot>` | you put the slot map directly under the address instead of inside `state`/`stateDiff` |

The only accepted shape on that node:

```python
ov = { TARGET: { "stateDiff": { "0x" + slot_hex_64: "0x" + val_hex_64 } } }
# also accepted: {"state": {...}} for full-slot replace, {"code": "0x..."} for injection
# NOT accepted: a list of {address, stateDiff} dicts
```

**The general lesson, and it applies beyond overrides: when an override produces
`Invalid params` rather than a revert, the harness is broken — not the target.**
Do not start re-deriving slots or doubting the layout. First prove override
works at all (§2.0b), then continue. A whole run of "DISPROVEN" gathered while
the harness was silently 400-ing is worthless.

### 2.0b Prove the harness with a control contract BEFORE any candidate test

Minimum viable sanity, ~2 minutes, do it once per RPC:

```solidity
contract Bal { uint256 public x; function setX(uint256 v) external { x = v; }
               function getX() external view returns (uint256) { return x; } }
```

1. `eth_call` to `0x…9101` with `{code: <Bal runtime>}` only → `getX()` = `0`
2. same, plus `stateDiff {"0x…00": 0x…05 (padded)}` → `getX()` = `0x…05` ✅

Only after both pass is a revert from a real target meaningful. Record this in
the report's Methodology section — it is what licenses every DISPROVEN below it.

### 2.1 Simple mapping slot

`mapping(K => V)` at declared slot `S`:

```
slot = keccak256(abi.encode(key, S))          # key < 32 bytes (e.g. address)
```

```python
def w(x): return int(x).to_bytes(32, "big")
def a(x): return bytes.fromhex(x[2:]).rjust(32, b"\0")
slot = keccak(a(attacker) + w(S))
ov = {TARGET: {"stateDiff": {"0x" + slot.hex(): "0x" + "00"*32}}}
```

Verify the override actually landed by reading the value back through a getter
in a second `eth_call` carrying the same override. Never assume.

### 2.2 Two-level mapping — do not guess, search

`mapping(A => mapping(B => V))` has **four** plausible layouts:

```
keccak( keccak(abi(A) ++ S) ++ abi(B) )      # A-major, the common one
keccak( abi(B) ++ keccak(abi(A) ++ S) )      # B-major
keccak( keccak(abi(B) ++ S) ++ abi(A) )
keccak( abi(A) ++ keccak(abi(B) ++ S) )
```

Plus the declared base slot `S` is unknown when there is no source — it can be
anywhere in 0..40 given inherited storage.

**Do not hand-derive. Brute-force with a MARK and detect via the getter.** Write
`0xDEADBEEF` into each candidate slot, then call the getter; the layout that
returns `0xDEADBEEF` is the real one.

```python
MARK = 0xDEADBEEF
for base in range(0, 41):
    for label, k in layouts(attacker, tid, base):
        ov = {HUB: {"stateDiff": {"0x"+k.hex(): "0x"+hex(MARK)[2:].rjust(64,"0")}}}
        r = eth_call(getter_calldata, override=ov)
        if r and int(r, 16) == MARK:
            print("SLOT+LAYOUT FOUND", label, base, k.hex())
            return base, k
```

Session result: `base = 4`, layout `keccak( abi(tokenId) ++ keccak(abi(addr) ++ slot4) )`
— the id-major variant, which is why all four hand-guesses failed first.

Guardrail: an override that silently fails looks identical to a correct negative.
Always keep a **positive control** — override a slot you DO know (e.g. slot 0 for
`totalSupply`) and confirm the getter changes. If the control fails, override is
not being applied and every negative result in the run is void.

### 2.2b Finding a REAL holder first — synthetic addresses make slot search useless

The MARK brute-force only works against an account whose value you know. A
random or zero address has `0` at every slot, so *every* layout "matches" nothing
and the search returns no hits — easily misread as "layout is exotic."

Get a real, currently-nonzero holder from the Hub's own logs (mint events have
`from == 0`; plain-transfer recipients also work and are better because they can
still hold a balance):

```python
TR = "0x1b3d7edb…"                      # Transfer event topic0, from the source ABI
latest = int(rpc("eth_blockNumber", [])["result"], 16)
logs = rpc("eth_getLogs", [{"address": HUB, "topics": [TR],
                            "fromBlock": hex(latest - 30), "toBlock": "latest"}])["result"]
for lg in logs:
    t = lg["topics"]                     # skip from==0 (mint) — those are consumed downstream
    acc, tok = "0x" + t[2][-40:], t[3]
    if rpc_balanceOf(acc, tok) > 0:      # first hit is your witness
        break
```

Then run the layout search against that `(acc, tok, balance)` triple and require
the candidate slot's `cast storage` value to equal the live `balanceOf` exactly:

```
layout hit: keccak(tokenId ‖ keccak(owner ‖ 4))  ->  0x269225bb…0321cb  ==  95583475  ✅
```

**Confirm override on that same real slot before trusting any downstream test:**
set it to `0x…0309` and require `balanceOf` to return `0x…0309`. Two facts in one
call: the layout is right AND overrides are landing.

### 2.2c Never scan per-address with individual `cast call` loops

A `for addr in candidates: cast call balanceOf(...)` loop here took **>180 s for
~30 addresses** and blew two timeouts; the same work batched through `eth_getLogs`
plus a `curl --max-time 20` JSON-RPC helper finished in seconds. Per-address
`cast` spawns a process and a TLS handshake each time.

```python
def rpc(m, p):                       # one connection, JSON body, hard timeout
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p})
    out = subprocess.run(["curl","-s","-X","POST",RPC,"-H","content-type: application/json",
                          "--data-binary",body,"--max-time","20"],
                         capture_output=True, text=True).stdout
    return json.loads(out) if out else {"error":"timeout"}
```

Always `--max-time`. Without it a single stalled request hangs the whole scan and
you cannot tell "no holders" from "network stuck".

### 2.3 Overriding a boolean "already consumed" flag

`mapping(bytes32 => bool) usedRequests` — the key is the digest you computed:

```python
slot = keccak(abi.encode([bytes32, uint256], [digest, USED_SLOT]))
```

Confirm the flag is real before overriding: read it at the tx block (expect `1`)
and at `block-1` (expect `0`). If both are `0`, your digest or slot is wrong —
stop and fix that instead of proceeding.

**Critical caveat learned the hard way:** overriding the flag is only meaningful
if the baseline (unmodified) call then SUCCEEDS. If the control call still
reverts, every comparison built on top of it is meaningless. Report
`INCONCLUSIVE — baseline failed`, never `tested and refuted`.

### 2.4 When override cannot help: the caller-identity wall

If the transaction's real `to` is a wrapper (batcher/proxy/router), `eth_call`
against the inner target executes with a **different `msg.sender`** than real
traffic. Symptoms: baseline reverts no matter how much gas you give it, and
routing through the wrapper also reverts because the wrapper has its own
un-audited access control.

Do not chase this into a fabrication. Legitimate exits:
1. Reproduce the wrapper's checks from its bytecode (§1) and satisfy them.
2. Prove the primitive via source + a forge test, and label it **UNPROVEN on
   mainnet — blocked by <exact gate>**.
3. Report the blocker explicitly as an open item.

---

## 3. `panic: arithmetic underflow` is NOT an access-control error

Screaming distinction that changed a conclusion in this session:

| Revert | Means |
|---|---|
| `AccessControlUnauthorizedAccount` / `OwnableUnauthorizedAccount` / custom `Unauthorized(...)` | there IS a permission check and you failed it |
| `panic: arithmetic underflow or overflow (0x11)` | the function ran, reached balance arithmetic, and the balance was insufficient — **no permission gate on this path at all** |

So `transfer(dst, id, 1)` reverting with `0x11` from a zero-balance address is
*evidence the token has no transfer allowlist*, not evidence you were blocked.
Confirm with a second method (state-override a balance in, then the same call
returns `true`) before writing it down — this is the double-probe rule.

## 3b. NEVER state-override the contract you are testing (BURNED ME — fake PROVEN)

The subagent in the Relay session reported `aggregate3` "PROVEN working" on the
batcher. It was not. Its harness injected `{code: <Multicall3 runtime>}` at the
batcher's OWN address via a `code` override — so the test called a *different
contract* and passed. It then caught its own error and retracted.

**Rule: `code` override goes on a HELPER address you deploy (`0x…9001`), never on
the target.** Overriding the target's bytecode means you are no longer auditing
the target. Same for `stateDiff` on the target's own logic slots.

What IS legitimate:
- `stateDiff` on a **victim / attacker / holder** slot to manufacture a
  precondition the target would otherwise never see (balance, allowance, flag).
- `code` on a scratch helper you wrote, to act as the attacker (`from`) when the
  RPC refuses plain EOA `from` or you need a contract caller.

Every "PROVEN" must answer: *which bytecode executed?* If the answer is "the one
I injected", it is not the target's behaviour. Revolve any claim built on it.

---

## 3c. Revert-selector forensics: the revert REASON is the finding

`panic 0x11` tells you "no permission gate here" (§3). Go one level deeper — the
**exact** revert pins down *which* check fired, and that is usually the vuln.

Session: `Hub.transferFrom(victim → attacker, 1)` after overriding the victim's
balance reverted `panic 0x11` and NOT `Unauthorized` / `ERC6909: insufficient
allowance`. Reading `RelayHub.sol:255-268` explained it:

```solidity
uint256 allowed = allowance[sender][msg.sender][id];
if (allowed != type(uint256).max)
    allowance[sender][msg.sender][id] = allowed - amount;   // underflow, no revert
balanceOf[sender][id] -= amount;                            // balance check only
```

⇒ **allowance is silently decremented, never enforced as a cap.** A 1-unit
approval permits moving the entire balance. That is a real Medium finding, and it
was *only visible* because the revert was `0x11` rather than an auth error.

Technique: when a call reverts, decode `data` and classify by *category*
(auth vs arithmetic vs custom error). Then `grep` the source for the arithmetic
site and ask "what enforces the limit here?" If the answer is "nothing, it just
underflows", you have a finding.

> ### ⚠️ RETRACTED — a LATER session re-tested this on the live contract and it was FALSE
>
> A follow-up round ran the exact probe against `RelayHub` at `0xDDD3…9318` and got:
>
> ```
> allowance(vic, atk, tid) = 0,  transferFrom(vic -> atk, amount > 0)
>   -> REVERT: panic: arithmetic underflow or overflow (0x11)
> ```
>
> `allowed - amount` **underflows and reverts**, so the allowance IS a real cap.
> There is no "1-unit approval moves the balance" bug. The original conclusion
> came from conflating two calls — a *reverting* large amount and then a
> *non-reverting* small one — and reading the second's `0x…01` as a bypass, when
> in fact `amount <= allowance` made it legitimately succeed.
>
> **The reusable rule:** a `0x…01` return only refutes "blocked" if the amount you
> passed actually EXCEEDED the cap. Any underflow / no-cap claim needs a 3-row
> matrix at the same block: (1) `allowance=0, amount=1` → expect revert;
> (2) `allowance=1e6, amount=1e18` → expect revert (cap binds); (3) `allowance=1e6,
> amount=1e6` → expect `true` (positive control proving the harness works).
> Row 3 is mandatory — without it, rows 1–2 reverting could just mean the override
> never landed.
>
> Full treatment: `inherited-findings-and-silent-rpc-failures.md` §2.

---

Pattern: `amount = token.balanceOf(address(this))` inside a settlement contract.
Combined with a permissionless `token.transfer` into that contract, the naive
chain is "attacker injects tokens → next settlement sweeps them → attacker
wins." That is backwards.

## 3d. Role check that ignores its account argument — a repeatable bug class

Highest-value pattern from the Relay session. Read every `isOperator` /
`isApproved` / `canSpend`-style helper for whether it actually **uses** the
`account` parameter:

```solidity
// RelayHub.sol:181  — account is DEAD when operator holds the role
function isOperator(address account, address operator) public view returns (bool) {
    return hasRole(OPERATOR_ROLE, operator) || _isOperator[account][operator];
}
//                    ^^^^^^^ account never consulted on the role branch
```

=> every `OPERATOR_ROLE` holder is an operator of **every account**, with no
consent, no allowance, no `setOperator` call. Sibling function:

```solidity
function burn(address sender, uint256 id, uint256 amount)
    public onlyRole(OPERATOR_ROLE) { _burn(sender, id, amount); }   // no sender==msg.sender
```

**Probe that proves it without touching the target's bytecode** — override the
victim's balance slot only, then ask the helper about an address that never
interacted:

```
isOperator(victim, Allocator) = 1        # victim never approved anything
Allocator.transferFrom(victim -> Allocator, 1e6) -> 0x...01  SUCCESS
```

**Severity discipline (this is where inflation happens):** this needs
`OPERATOR_ROLE`, so it is **HIGH, not Critical**. Calling it "any user drains any
user" is false and a triager will reject it. Frame it as: *privileged, but with
zero per-account scoping -> single-key blast radius, and the destructive `burn`
variant means one leaked operator key permanently destroys every balance.*
Always include the role census (holder set); a single EOA holding ADMIN on three
contracts plus OPERATOR on the hub is the real risk statement. Also report the
asymmetry when a contract holds `OPERATOR_ROLE` on the hub but has **no admin of
its own**.

---

## 3e. Signature-binding filters: find the ONE line that closes every value path

Across 20+ rounds the Relay hunt kept producing near-miss chains: forge the
`solver`, forge the `depositId`, forge the `orderId`. Every one died on the same
line:

```typescript
if (deposit.result.depositId !== orderId) throw externalError("Deposit does not reference order id");
// index.ts:326 (execute) — equivalent filter at index.ts:882 (solver fill/refund)
orderId = hashStruct(ORDER_EIP712_TYPES, normalizeOrder(order))   // binds solver+salt+inputs+output+fees
```

**Method: when chains keep dying at one equality check, stop hunting new sources
of the left-hand value and go audit the derivation of the right-hand value.**
If `orderId` is a hash over attacker-chosen fields, the attacker must reproduce a
victim's exact order — a keccak preimage. That is a structural ceiling, and the
correct report says so:

> `BLOCKED — STRUCTURAL: any path to value requires a signature over an order the
> attacker cannot reconstruct.`

**Distinguish three end states — they are not interchangeable:**

| State | Meaning |
|---|---|
| `PROVEN` | real end-to-end execution, real output |
| `BLOCKED — gate X` | exact line known; a fix or a key leak would unblock it |
| `BLOCKED — STRUCTURAL` | no attacker action unlocks it; design is sound here |

Report the third honestly instead of looping. Declaring the floor IS the deliverable.

---

## 3f. Dead-contract check FIRST — ~10 s that can invalidate a whole direction

Before reverse-engineering any unverified contract, prove it is alive. Three
cheap calls:

```python
eth_getLogs({"address": T, "fromBlock": "0x0", "toBlock": "latest"})   # [] => never used
eth_getBalance(T, "latest")                                            # 0x0
eth_getTransactionCount(T, "latest") + recent-block scan of tx.to      # 0 hits
```

Session: a "promising virgin attack surface" batcher returned **0 logs ever, 0
balance, 0 tx in 400 blocks** — a deployed-and-abandoned orphan. That closed the
direction in one call after a subagent had burned 150 API calls guessing its ABI
layout. Do this before the ABI work, not after. Dead-but-deployed is
**NONE / INFORMATIONAL**, not bounty material.

Sibling check when the code DOES exist elsewhere: hash the runtime and look for
the same code on other chains at the same address. Same address + different hash
means it is not a stock fork deployment and no known-good calldata exists to copy
the ABI from — budget accordingly instead of brute-forcing further.

### 3f.1 `SHL 5` in an ABI decoder is usually `n*32` bounds arithmetic, NOT an element stride

A subagent read this and concluded "array stride = 2 words", then built its next
round of payloads on it:

```
0x09bc PUSH8 0xffffffffffffffff
0x09d0 PUSH1 0x20; DUP4; ADD
0x09d6 DUP4; PUSH1 0x20; DUP3; PUSH1 0x05; SHL; DUP6; ADD; ADD; GT; ISZERO; JUMPI revert
```

Reading the surrounding `GT / ISZERO / JUMPI` pattern shows the real meaning:
`base + n*32 <= calldatasize` — a **calldata bounds check**. The subagent caught
its own error and retracted (good), but the wrong reading had already been written
into an artifact and would have poisoned the next round.

**Rule: never infer an array stride from a `SHL` alone.** Read the whole
compare-and-revert sequence. To get the real element shape, look for the mask that
builds each field:

```
0x0719 PUSH1 0x01; PUSH1 0x01; PUSH1 0xa0; SHL; SUB; AND   ; -> 20-byte mask = address
0x0745 PUSH1 0x40; DUP2; ADD                               ; -> next word at +0x40
```

That is what tells you the head is 3 words. Structural inference beats arithmetic
guessing, and it survives the case where the decoder is non-standard.

Related: a custom offset validator (here masking the offset word with `~0x5e` and
bounds-checking it against calldatasize) will reject every canonical-layout payload
you construct. When 15 layouts revert and only `n=0` returns, the conclusion is
"this entrypoint's decoder is non-standard and unreachable via canonical encoding",
not "target filtering blocks me". Say that plainly and move on.

---

## 3g. VERIFY SUBAGENT "FORMAT-ONLY" CLAIMS AGAINST TRANSITIVE HASH BINDING (BURNED a whole round)

A subagent produced a ranked table of eight "FORMAT-ONLY / unvalidated" fields
(`receiver`, `fees[].recipient`, `fees[].amount`, `outAmountMinimum`, `outCurrency`,
`outChainId`, `nonce`, `deadline`) each marked *"Redirects entire withdrawal payout to
attacker."* **Every value-bearing row was wrong**, and the parent would have shipped a
fabricated Critical if it had trusted the summary.

The reason is a classification error that recurs constantly: the subagent asked
*"is this field explicitly cross-checked?"* and answered "no". The correct question is
*"is this field bound to something authenticated, transitively?"*

```typescript
// Looks unvalidated: index.ts:1559 just copies it through
receiver: destination.receiver,          // <- from output.recipient, never grepped/compared

// But the whole order is hashed, and the hash must equal the on-chain depositId:
orderId = hashStruct(ORDER_EIP712_TYPES, normalizeOrder(order));   // index.ts:303
if (deposit.result.depositId !== orderId) throw ...;               // index.ts:326
// ORDER_EIP712_TYPES covers: Output.payments[].recipient, .currency, .minimumAmount,
// .expectedAmount, Output.deadline, .calls, .extraData, Fee.recipient, Fee.amount
```

⇒ changing `receiver` changes `orderId`, which breaks the `depositId == orderId`
equality, which makes the deposit unreal. The field is **cryptographically bound, just
not explicitly checked**. "FORMAT-ONLY" was the wrong verdict and "exploitable" was a
fiction.

**Reusable test — run it before believing any field-classification table:**

1. Open the signed-struct type definition (`ORDER_EIP712_TYPES`, `abi.encode` layout,
   Solidity `struct` used in `hashStruct`). List every field.
2. For each "unvalidated" field, ask: **is it in the hashed preimage?** If yes, it is
   bound — write `BOUND-VIA-HASH`, not `FORMAT-ONLY`.
3. Find the equality that anchors the hash to real state (`depositId == orderId`,
   `usedRequests[digest]`, a nonce store). If one exists, mutation ⇒ hash mismatch ⇒ reject.
4. Only fields **outside** the preimage are genuinely attacker-free. Those are the real
   candidates. In the Relay run: `data` (a `bytes` blob whose length was caller-controlled)
   was outside the order hash — but reading `GatewayVmPayloadBuilder.sol`
   (`receiver: params.receiver`) showed even it could not redirect the payout, because
   the destination comes from the signed `receiver`, not from inside `data`.

**Corollary — normalize-vs-sign divergence.** Also check whether the *normalized* form
that gets hashed differs from the raw field that gets signed/executed. That gap is where
real bugs live. Here they matched, so there was none.

**Reporting rule:** when your own verification contradicts a subagent artifact, say so
explicitly and by table — `A1 claims FORMAT-ONLY → actually BOUND-VIA-HASH(Output.payments[].recipient)`.
Then patch the artifact or write a counter-artifact. Leaving the wrong table on disk
means the next round re-derives the same fake finding.

---

## 3h. Role-gated global authority: how to grade it without inflating

Sibling of §3d, sharpened after a second pass. The question a triager asks first is
*"who can reach it"*. Answer with a role census, computed live, not from docs:

```python
S = sel("hasRole(bytes32,address)")
for name, H in CONTRACTS.items():
    for rl in ["OPERATOR_ROLE","ADMIN_ROLE","ORACLE_ROLE","EDITOR_ROLE","DEFAULT_ADMIN_ROLE"]:
        holders = [c for c in CANDIDATES if call(H, S + rolehash(rl) + ad(c)) == 1]
```

Findings worth stating in the report beyond the bug itself:
- **One EOA holding ADMIN on three contracts + OPERATOR on the hub** = the true risk
  surface. Name it.
- **A contract holding `OPERATOR_ROLE` on the hub but having NO admin of its own** =
  unintentional `renounceRole`. Report the asymmetry.
- **A `burn(anySender, ...)` under a role with no `sender == msg.sender` check** turns a
  transfer-capable compromise into permanent destruction. That is the sentence that
  justifies HIGH over "informational privileged function".

Grade: **HIGH** — privileged, zero per-account scoping, single-key blast radius. **Not
Critical** unless an unprivileged path reaches it. Writing "any user drains any user"
when it needs a role is the inflation failure mode.

---

## 3i. `isOperator` global-transfer proof — the exact probe that works

When the helper is read-only and gated (`isOperator` is `view`), you cannot test it by
"being" the role holder. Override the **victim's** state and ask the helper about an
address that never interacted:

```python
# 1. victim balance slot (base found by MARK brute, §2.2) — override ONLY this
ov = {HUB: {"stateDiff": {victim_balance_slot: "0x" + w(1_000_000)}}}
# 2. ask the helper — no role needed, it is a view
eth_call({"to": HUB, "data": ISOP + ad(victim) + ad(ALLOCATOR)}, over=ov)   # -> 1
# 3. now actually move it, with `from` = the role-holding CONTRACT, not the attacker EOA
eth_call({"to": HUB, "from": ALLOCATOR,
          "data": TF + ad(victim) + ad(ALLOCATOR) + w(tid) + w(1_000_000)}, over=ov)  # -> 0x...01
```

Two facts are proven in one shot: the role holder has authority over an unrelated
account, and the value actually moves. `from` must be the role holder — using the
attacker EOA proves nothing and reverts with `panic 0x11`, which reads like a
refutation of the very bug you are proving.

Also note what does NOT close it: `erc20Views[id] != msg.sender` is a bypass branch, but
`erc20Views` is only writable by `_createERC20View` (`new ERC20View(tokenId)`, contract-
owned), so an attacker cannot enter that branch. Check the assignment site before
claiming a third bypass route.

---

---

## 3j. The FORCE-CALL hunt: proving a privileged contract cannot be induced to act for you

A recurring engagement shape: *"find a path that makes a role-holding contract
(Allocator / Executor / Oracle / View wrapper) call `transferFrom`/`burn` for an
attacker who has no key."* Almost always the answer is BLOCKED, and the value of
the run is the **exhaustive, evidenced closure** — not a new bug. Work it in this
order; each step independently kills a class of hypothesis.

### Step 1 — Enumerate the SINK call-sites, not the entrypoints

Never start from "what functions are public". Start from the sink and walk
backwards:

```bash
grep -rn "transferFrom(\|\.burn(\|\.transfer(" contracts/ --include=*.sol \
  | grep -v mocks
```

Tabulate every hit as `file:line → caller contract → gate`. In the Relay run that
was 8 sites across 6 contracts, and the table itself became the deliverable:

| sink site | who reaches it | gate |
|---|---|---|
| `RelayAllocator.sol:301 burn(alias,…)` | anyone (external) | payload-builder configured **and** spender/operator/sig |
| `RelayExecutor.sol:304 transferFrom(orderAddress,…)` | anyone (external) | MSIG ORACLE_ROLE sig over full digest + `usedRequests` |
| `RelayOracleV2.sol:284/296/370` | anyone | MSIG sig over every action byte |
| `ERC20View.sol:225 transferFrom(from,…)` | anyone | **its own** allowance check (:208) |
| `WithdrawGasPayer.sol:181 burn(alias,…)` | anyone | `isValidSignatureNow` + `gasPayments` write-once |
| `BasicCallResolver.sol:100 transfer` | auth'd execute | only `address(this)` balance |

**Confirmed by a second, later run:** `BasicCallResolver.execute(...)` (L75) is `external nonReentrant` with **no
access control at all** — no `msg.sender == EXECUTOR`, no whitelist on `call_.to`, no whitelist on `call_.data`. An
attacker can call it directly and it will happily perform `call_.to.call(call_.data)` and then sweep its own Hub
balance to any `sweep.recipient`. **That is still not a finding**: a live role census returned `hasRole(X,
resolver) == 0` for all ten role hashes (with `hasRole(OPERATOR, EXECUTOR) == 1` as the positive control), and
`balanceOf(resolver, tokenId{0,1}) == 0`, `eth_getBalance == 0`. Unguarded arbitrary-call surface on a **broke,
roleless** contract exposes nothing. Report as INFO / DEAD-END, and say the role census is what closes it — not the
absence of a guard. This is the exact shape of pitfall #13 in `adversarial-multi-round-audit`.

If every row has a gate column filled, you are done — say so.

### Step 2 — Prove the one primitive that IS open, then state the asymmetry

`isolate the door` with a 5-row differential matrix (override victim storage only):

```
[T1] HUB.transfer(victim→attacker)  as attacker, victim balance set  -> revert (self-only)
[T2] HUB.burn(victim)               as attacker, victim balance set  -> revert AccessControlUnauthorizedAccount
[T3] HUB.transferFrom(victim→atk)   as ALLOC                         -> TRUE
[T4] HUB.transferFrom(victim→atk)   as EXEC                          -> TRUE
[T5] HUB.transferFrom(victim→atk)   as ORACLE2                       -> TRUE
```

T1/T2 vs T3-T5 in one screen is the whole finding: **direct paths are closed,
operator context is the only door.** It also kills the lazy claim "any user can
move any user" before you write it.

### Step 3 — Role census live, and the graph, not just the holders

```python
for H in [HUB, EXEC, ALLOC, ORACLE2]:
    for r in ["OPERATOR_ROLE","ORACLE_ROLE","ADMIN_ROLE"]:
        for c in CANDIDATES + [ATTACKER, "0x"+"00"*20]:
            call(H, sel("hasRole(bytes32,address)") + rolehash(r) + ad(c))
```

What to record: who holds what on **which** contract, and the *direction* of
authority (a signer that is ORACLE_ROLE but not hub-operator can authorise one
action, not standing transfers). Include the zero address — some deployments
leave `hasRole(0x0)` true via a published default.

### Step 4 — Bytecode checks that skip entire hypotheses in ~10 s

```python
b = bytes.fromhex(eth_getCode(BATCHER)[2:])
b.count(0xf4)   # DELEGATECALL — 0 means it can never become a role proxy
b.count(0xff)   # SELFDESTRUCT opcode (beware: 0xff is also PUSH-data)
```

Verify the role predicate is really **inlined** the way source says. Here the Hub
compiles `hasRole(OP,operator) || _isOperator[account][operator]` inline, which is
*why* an operator ignores the `account` argument (§3d) — confirm before asserting.

### Step 5 — When the gate is an EIP-712 signature, audit the SIGNER, not the chain

`orderAddress` / `sender` / `amount` being inside the digest makes the on-chain
comparison unbeatable; the only question left is whether the off-chain service
will sign an attacker-chosen value. Grep the service for capability flags and for
the equality that anchors the signed hash to real state:

```typescript
if (req.body.force) { if (!isValidApiKey(apiKey)) return reply.status(400)... }
// api-key.ts: hasOwnProperty(config.apiKeys, key) && config.apiKeys[key]  -> server-side allowlist
if (deposit.result.depositId !== orderId) throw externalError("Deposit does not reference order id")
```

Then diff the signer's `types` array field-for-field against the Solidity typehash
string — a mismatch (missing field, wrong order, different domain `verifyingContract`)
is a *real* Critical because it means signatures are portable. In this run they
matched exactly and `force` was both key-gated and deposit-bound ⇒ BLOCKED.

### Step 6 — Close the cheap wrapper surfaces explicitly (one table row each)

Multicall3 / batcher / resolver sandbox / generic-mapping / balance-viewer. For
each: does it hold a Hub role? does it `delegatecall`? does it have a Hub handle
at all? `RelayGenericMapping` was an *open writer with no sink* (no `RelayHub`
import ⇒ no primitive), which is worth one line so nobody re-hunts it.

### Step 7 — Write the verdict as a closure table, severity graded honestly

| state | meaning |
|---|---|
| no-role path to move value | **Critical** |
| role/sig-gated path | **HIGH**, labelled "requires role" |
| every row gated, primitives isolated | **BLOCKED — closure evidenced** |

A BLOCKED verdict with 7 evaluated surfaces and raw output per row is a finished
deliverable. Do not dress it up as a bug to please the brief.

### Pitfalls specific to this hunt

- `submitWithdrawRequest`-style entrypoints that revert for *everyone* are
  **fail-closed** (unconfigured builder), not a hidden path — bisect by sender
  (attacker / the contract itself / zero address) before theorising. Use the
  artifact's own selector list; guessed selectors produced two rounds of "always
  reverts" noise here.
- `ALLOC.ORACLE()` vs `ORACLE_MULTISIG()` — a revert does not mean the concept is
  absent, it means your selector name is wrong. Pull the live selector set from
  `out/<Name>.sol/<Name>.json` and compute from that.
- If a function's selector is **not in the deployed bytecode**, do **not** immediately conclude the contract is a
  different version. Three checks, in this order:
  1. `len(eth_getCode)` vs `len(artifact.deployedBytecode)` — **equal length means same contract**, so the selector
     you searched for is wrong, not the deployment. (This cost a near-miss Critical: `execute` "absent", three
     hand-built selectors all wrong, contract actually identical at 9131 bytes both sides.)
  2. A PUSH4/PUSH3 byte scan is a **hypothesis, not proof** — modern compilers also compare `shr(224, calldataload(0))`
     against embedded constants. Absence from a scan proves nothing.
  3. Ground truth is source-verified explorer source, or a real transaction's calldata replayed.
  Build the signature from `out/<X>.sol/<X>.json` (flatten struct components; watch `bytes32` vs `uint256` for
  nonces) — helper: `adversarial-multi-round-audit/scripts/build_selector_from_artifact.py`.
- A `0` from a MARK probe where you *expect* a hit means re-derive the keccak
  argument ORDER first; `keccak(id ‖ keccak(owner ‖ base))` vs the reverse cost a
  full false-negative round here.

---

**Before assigning severity, write the profit identity.** Who pays the injected
amount? If the answer is the attacker, profit is zero:

```
attacker injects D  ->  victim's order sweeps D to victim's receiver
=> attacker -D, victim +D  => attacker profit = 0
```

And check whether residue can persist *between* transactions at all:

```python
# executor balance immediately BEFORE each historical execution
balanceOf(executor, tokenOutId) at block N-1  ->  0 for 6/6 samples
```

If the contract is always empty between executions (EVM atomicity, plus a design
where every inflow is consumed in the same tx), there is nothing to steal. A
total-balance sweep with a permanently-zero balance is **defensive design**, not
a vulnerability. Verdict: AVOID / LOW — not bounty material, and saying so
honestly is the correct outcome.

Deliverable shape for this class:

```
FACT (code):       withdrawAmount = balanceOf(this, tokenOutId)
FACT (mainnet):    balance before each execute = 0 (n/6)
FACT (mainnet):    permissionless transfer into target = true
PROFIT IDENTITY:   attacker funds the injection => net 0
VERDICT:           real design weakness, zero attacker profit, NOT exploitable
```

---

## 5. Fast triage recipes

```bash
# Is this wrapper a stock Multicall3?
cast code $B --rpc-url $R > b.hex
cast disassemble $(cat b.hex) | grep -E "PUSH(3|4)" | head -40
# then: cast call $B 0x3408e470  -> chain id, 0x82ad56cb -> aggregate3

# Does the target's runtime contain the verifier I think it uses?
for s in 7f035d73 1626ba7e 00fdd58e; do
  cast code $T --rpc-url $R | grep -qi "$s" && echo "$s present" || echo "$s absent"
done

# Ask the contract for its own digest instead of reimplementing EIP-712
cast call $T "hashExecuteAndWithdrawRequest((...))" <args> --rpc-url $R

# Read a boolean mapping flag at the tx block and one block earlier
cast storage $T <keccak(key,slot)> --block <txblock>   --rpc-url $R
cast storage $T <keccak(key,slot)> --block <txblock-1> --rpc-url $R
```

---

## 6. Pitfalls checklist

- `PUSH3` selectors exist. Missing them creates false "function absent" claims.
- A selector present in the dispatcher is not proof it is callable-and-useful —
  call it; and a revert on empty calldata is not proof it is absent.
- `hasStorageLayout: false` on the node ≠ override unsupported. Derive the slot.
- Two-level mappings: brute-force with MARK, do not hand-guess. Keep a positive
  control override so you know overrides are landing at all.
- Always pin `eth_call`/`getStorageAt` to an explicit block; `latest` moves under
  you and manufactures fake deltas.
- If `tx.to` is a wrapper, your `eth_call` sender is wrong — say BLOCKED rather
  than dressing up a failed control as a refutation.
- `panic 0x11` means arithmetic, not authorization.
- **Never `code`-override the contract under test** — you would be auditing a
  different contract. Helper address only. Any PROVEN built on an injected
  runtime must be retracted.
- Check whether every `isOperator`/`isApproved` helper actually uses its
  `account` argument. A role branch that ignores `account` = global authority.
- Dead-contract triage (0 logs / 0 balance / 0 incoming tx) BEFORE ABI work.
- When chains keep dying at one equality check, audit the derivation of the
  comparison's right-hand side — it is often a hash binding, i.e. STRUCTURAL.
- Severity: role-gated global authority is HIGH, not Critical, unless an
  unprivileged path reaches it. State the holder set.
- **A subagent's "FORMAT-ONLY / unvalidated field" table is a hypothesis, not a
  finding.** Before repeating it, check whether the field is inside the signed
  struct's hash preimage (`ORDER_EIP712_TYPES`, `abi.encode`, `hashStruct`). If it
  is, the verdict is `BOUND-VIA-HASH` and mutation breaks the equality that anchors
  the hash to real state. Eight "exploitable" rows collapsed this way in one round.
- A sweep/injection chain with attacker-funded input has zero profit. Compute the
  identity before inventing a severity.
- Delegated subagent returning `failed` may still have written a full artifact to
  disk. `ls` and read it before re-running the work.
- Report each claim with its raw output. Where the control failed, the honest
  verdict is `INCONCLUSIVE` / `UNPROVEN — blocked by <gate>`, never PROVEN.
