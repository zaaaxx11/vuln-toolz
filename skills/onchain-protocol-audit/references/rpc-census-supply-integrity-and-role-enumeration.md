# RPC self-disclosure, atomic census, supply-integrity checks, and full-registry role enumeration

Condensed from a Relay Protocol on-chain round (chainId 537713) whose brief was three questions:
*unidentified contracts/roles · permissionless paths into privileged functions · tokens with
suspicious supply*. The authz answers were mostly negative — the value was in **four techniques that
each turned a blocked probe into literal evidence**, plus **three false positives defused**.

Companion to `live-rpc-forensics-and-eth-call-trap.md` (that file = events/logs/`eth_call` traps;
this one = **counting and census at scale**, plus **supply arithmetic** and **deployment-registry
sweeps**).

**Section list:** §1 the RPC tells you which method to use · §2 `aggregate` vs `aggregate3` — and why
your hand-rolled ABI encoder is the bug · §3 block-pinning + atomically-consistent reads (the
"value moved between two calls" trap) · §4 storage-layout drift proven by slot-race, not by
assertion · **§4a the RAW-SLOT TRAP: `cast storage $C 6` is always 0 for a mapping — reading the
bare slot fabricates a false retraction; use `keccak(key||slot)`** ·
§5 supply-integrity checks: `ΣbalanceOf ≠ totalSupply`, sink addresses, concentration ·
§6 census a whole deployment manifest by role, in batches · §7 the three false positives · §8
report shape for a mostly-negative round · **§9 HISTORY CORRECTION: 1 → 45,144 → 1,930,893 —
the same census run three ways, and the four fields every volume claim needs** ·
**§10 a RE-RUNNABLE census script (`scripts/cursor_census.py`) — 100k windows, dedup, responses to
file, `fails` gating; run this INSTEAD of hand-writing a fifth variant of the loop** ·
**§11 counting the SENDERS of a write-gated surface: one sender ≠ one owner, and a nonce tells you
which kind of caller you are looking at**.

---

## 1. THE RPC NAMES THE METHOD YOU NEED — in its own error text

Full-range `eth_getLogs` failed, and the error was not a dead end:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32005,
 "message":"Response size exceeds limit. Use eth_getLogsWithCursor or reduce the number of logs requested"}}
```

`eth_getLogsWithCursor` is **non-standard and undocumented for this endpoint** — and it worked:

```bash
rpc eth_getLogsWithCursor '[{"address":["0xDDD3…9318"],
  "topics":["0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859"]}]'
# → {"result":{"logs":[…],"cursor":"…"}}
```

**Rule: read the `error.message` as a hint, then *try the method it names* before declaring the
capability missing.** Same for `eth_getProof` → `{"code":-32004,"message":"Method eth_getProof not
supported"}` — that one really is absent, so record it as BLOCKED *with the literal response*, not
as "couldn't enumerate".

Related, and worth a probe on every unfamiliar chain RPC:

```bash
for m in eth_getLogsWithCursor eth_getProof debug_traceCall trace_block eth_simulateV1; do
  printf '%-22s ' "$m"; rpc "$m" '[]' | head -c 120; echo
done
```

**Pagination contract:** the cursor came back `null` at the end with only 19 logs and no
`fromBlock` echo — so always drive the loop on the *returned* cursor, never on your block range:

```python
cursor, all_logs = None, []
while True:
    req = {"fromBlock": "0x0", "toBlock": "latest", "address": [TARGET], "topics": [TOPIC]}
    if cursor: req["cursor"] = cursor
    r = rpc("eth_getLogsWithCursor", [[req]])
    logs  = r["result"]["logs"]; all_logs += logs
    cursor = r["result"].get("cursor")
    print(f"page +{len(logs)} total={len(all_logs)} cursor={cursor}")
    if not cursor or not logs: break
```

### 1a. A `fails` COUNTER NEXT TO A COUNT IS A WARNING, NOT A FOOTNOTE

The same census was first run with plain `eth_getLogs` in 25k-block chunks, accumulating a
`fails` tally. Output:

```
EntrySet: 1  EntryDeleted: 0  fails:103
```

**103 of 104 chunks failed and the script still printed a clean-looking `1`.** Read naively,
"1 EntrySet" is a devastating research result: *the contract is a dead husk with a single
write*. The truth was **45,144 writes**. The two numbers came from the same contract, same
topic, same day — the difference is entirely the method.

Rules that follow:

- **A count whose companion `fails` is non-zero is not a count.** Either the script exits
  non-zero when `fails > 0`, or the number is prefixed with `PARTIAL`. There is no third
  option, because a partial count and a complete count are indistinguishable once written
  down.
- **When two methods disagree by 4 orders of magnitude, the *smaller* one is the broken one.**
  `eth_getLogs` failing on response-size limits returns `error`, and a `try/except: continue`
  turns each error into a silent absence. `eth_getLogsWithCursor` (§1) existed the whole time.
- **Re-run the census with the cursor method before writing any volume number.** The corrected
  figure changes the finding's whole character: 1 write = "abandoned contract", 45k writes =
  "actively-operating surface with a real attack window". Volume is load-bearing evidence here,
  not colour.
- Corollary for genesis-wide sweeps: a full `0x0 → latest` cursor request **timed out** (server
  hangs rather than paginating), so walk **backwards in ~40k-block windows**, each window
  paginated by its own cursor. And assert the cursor actually advances
  (`if nc == cur: break`) — a cursor echoed back unchanged produces an infinite loop that
  looks like a slow scan (observed: 45k duplicate rows from a stuck cursor, all at the same
  block range).

---

## 2. `aggregate` REVERTS, `aggregate3` DOESN'T — and your encoder is the usual culprit

Two independent failures that look identical:

```console
aggregate(...)   → {"code":3,"message":"execution reverted"}     # reverts if ANY inner call reverts
aggregate3(...)  → works, allowFailure=true per call is honoured
```

Use **`aggregate3((address,bool,bytes)[])`** whenever any element might revert (sweeping unknown
token ids, probing `hasRole` on addressed that aren't contracts). `aggregate` is all-or-nothing.

**The second, subtler failure:** a hand-rolled Python encoder of the tuple array produced
`execution reverted` for *correct-looking* input. Diffing against `cast calldata` showed the first
offset word differed. Do not debug your ABI encoder under time pressure — **delegate encoding to
`cast calldata` and only decode in Python**:

```python
def agg3_calldata(calls):                       # calls = [(addr, calldata_hex), …]
    arg = "[" + ",".join(f"({a},true,{d})" for a, d in calls) + "]"
    return subprocess.run(["cast","calldata","aggregate3((address,bool,bytes)[])",arg],
                          capture_output=True, text=True, check=True).stdout.strip()
```

Same law as `evm-foundry-and-offchain-api-audit.md` §11: an encoder/decoder you wrote is a
hypothesis; the tool that ships is the ground truth.

**Decoding `aggregate3` return** (`(bool success, bytes returnData)[]`): offsets are relative to the
start of the **return-data payload after the array length word**. If you get `success=false` with
empty `returnData` on *every* element, your decode is wrong before the chain is.

---

## 3. BLOCK-PIN EVERYTHING — "the value changed between my two calls" is not a finding

Symptom that nearly became a fabricated anomaly report: `ERC20View.totalSupply()` read `14.37e9`,
then `Hub.totalSupply(tid)` read `2.30e9` — a ~6.25x "discrepancy". Re-read seconds later: `6.88e9`.
The chain was live and the numbers simply moved.

**Two fixes, both mandatory before any comparison claim:**

**(a) Pin the block.** Every `eth_call` / `eth_getStorageAt` pair must name the same block:

```bash
BN=$(rpc eth_blockNumber "[]" | jq -r .result)          # e.g. 0x5d9622
rpc eth_call         "[{\"to\":\"$C\",\"data\":\"$DATA\"},\"$BN\"]"
rpc eth_getStorageAt "[\"$C\",\"$SLOT\",\"$BN\"]"
```

**(b) Prefer a single atomic `aggregate3` over N sequential calls.** One `aggregate3` executes all
sub-calls against one state root. This is what turns "supply mismatch" from a race artifact into a
real assertion:

```console
$ python3 atomic.py
tids=7 addrs=15  (single atomic aggregate3)
tid=…73383  totalSupply=16528621369  balance[top]=14087451086  SUM=14087451086  DIFF=-2441170283
# tokens with supply mismatch: 7/7
```

**Beware the string-compare trap** when comparing `cast` output to raw JSON: `cast` prints
`14249692385 [1.424e10]` while `eth_getStorageAt` returns `0x…`. Compare the **numeric value**
(hex-to-int of the raw `result`), never the formatted string — a naive `[ "$A" = "$B" ]` reports
`match=NO` on byte-identical numbers. This produced a false "no match" three times in a row before
the cause was spotted.

---

## 4. STORAGE-LAYOUT DRIFT — prove it by slot-race with a negative control

Claim "live bytecode ≠ repo" is worth nothing without a slot-level proof. The method that works
without `eth_getProof` (unsupported) and without scanning nested mappings:

1. Brute-force the slot base by computing `keccak(abi.encode(key, N))` for `N = 0..12` and comparing
   to the getter's return. Two hits (e.g. `totalSupply` → **6**, `erc20Views` → **8**) pin the layout.
2. Then run the **same-block, negative-control test** — this is the deliverable:

```console
block              = 0x5d9622
eth_call return    = 0x…04d02e0b79   (20672547705)
storage slot base6 = 0x…04d02e0b79   (20672547705)   ← LIVE layout
storage slot base3 = 0x…0000000000   (0)             ← REPO layout
>>> MATCH base=6 (live)
```

The `base3 == 0` row is what makes it a proof rather than a coincidence: it shows the repo's
declared slot is *empty on the live contract*, so the ordering/length of the storage block changed.

```python
K = keccak(abi_encode(uint256 key, uint256 slot_base))   # cast keccak $(cast abi-encode 'f(uint256,uint256)' $KEY $BASE)
```

### 4a. THE RAW-SLOT TRAP — `cast storage $C 6` returns 0 for a *mapping*, and that 0 is meaningless

**This nearly caused a retraction of a CORRECT finding.** Trying to independently verify a worker's
storage-layout claim, the probe was:

```bash
cast storage $HUB 6 --rpc-url $R     # → 0x0000…0000
cast storage $HUB 3 --rpc-url $R     # → 0x0000…0000
```

Both zero ⇒ the instinct was *"slot 6 is empty too, the worker's claim is wrong."* **That conclusion
was wrong, and the worker was right.** A Solidity `mapping` does not store anything at its declared
slot — that slot is *never written*; it is only the base for `keccak256(abi.encode(key, slot))`.
Reading the raw slot therefore returns 0 **for every mapping, always, on every contract**. It is not
a control, not evidence, and not a negative result. It is a wasted call that fabricates a false
refutation.

The correct probe for `mapping(uint256 => uint256) public totalSupply` at key `TID`:

```bash
# WRONG — always 0 for any mapping
cast storage $HUB 6

# RIGHT — hash the key with the slot base
cast keccak 0x$(printf '%064x' $TID)$(printf '%064x' 6) \
  | xargs -I{} cast storage $HUB {} --rpc-url $R
```

Full working reproduction (same block, `eth_call` as the reference value):

```python
cd = cast calldata 'totalSupply(uint256)' $TID
ret = rpc("eth_call", [{"to": HUB, "data": cd}, blk])          # 0x…1148a58f0 = 4639578352
for base in (3, 5, 6, 8):
    kh = cast keccak "0x" + f"{TID:064x}" + f"{base:064x}"
    print(base, rpc("eth_getStorageAt", [HUB, kh, blk]))
# 3 → 0            ← repo layout, EMPTY  (the negative control)
# 5 → 0
# 6 → 0x…1148a58f0 ← LIVE layout, MATCHES eth_call
# 8 → 0x…fb0fadd3… ← erc20Views address (slot base 8)
```

Rules that follow:

- **A single-key mapping's value is at `keccak(key || slot)`; a nested mapping is
  `keccak(innerKey || keccak(outerKey || slot))`.** Never read the bare slot.
- For a **dynamic array** it is different again: length lives at the declared slot, elements at
  `keccak(slot) + i`.
- Only a **plain `uint256`/`address` state variable** actually occupies its declared slot. If a
  layout claim is about one of those, `cast storage $C $SLOT` *is* valid — check the declaration
  (`grep -n "public uint256\|public address"`) before choosing the probe.
- **`keccak(key, slot)` needs the key left-padded to 32 bytes and the slot too** — `cast keccak
  0x<64 hex><64 hex>` is the cheap way to build it; `cast abi-encode` also works.
- **Always pair the candidate slot with the repo's slot as a negative control** in the *same block*.
  Zero-on-repo + match-on-live is the proof. Zero-because-you-read-a-raw-mapping-slot proves nothing.

**Self-correction discipline:** when a probe refutes a worker's claim, the first hypothesis should be
*"my probe is wrong"*, not *"the worker is wrong"* — especially for storage, ABI decoding
(`live-rpc-forensics-and-eth-call-trap.md` §11), and event topics (§15a). Re-derive with a second
independent method (here: `cast call` the getter and compare) before writing a retraction.

**Rule:** any "bytecode differs from source" claim ships with `(getter_value == storage[base_live])`
AND `(storage[base_repo] == 0)`. Otherwise it is an assertion, and per
`live-rpc-forensics-and-eth-call-trap.md` §2 the only other admissible route is the verified-source
diff.

---

## 5. SUPPLY-INTEGRITY: three checks that find real anomalies, ranked by signal

The brief's "suspicious supply" question has three cheap, high-signal probes.

### 5a. `Σ balanceOf(h, id) ≠ totalSupply(id)` — the mint/burn accounting invariant

If the contract's `_mint`/`_burn` update `totalSupply[id]` and `balanceOf[receiver][id]` in the same
statement pair, then `Σ balanceOf == totalSupply` **must** hold for every id. Read the two source
functions first (that establishes the invariant), then test it atomically (§3b).

Finding: `7/7` ids mismatched in one atomic batch → there are holders **outside your enumerated
address set**, not a race. The correct output is a table `id | totalSupply | SUM | DIFF` plus the
honest residual: *"holder set incomplete; nested mapping not enumerable, `eth_getProof` unsupported"*.
Do **not** convert an incomplete holder set into "unbacked supply" — that requires proving the sum is
complete, which a non-enumerable mapping prevents.

### 5b. Concentration + sink-address detection (this is the real anomaly)

Per-id, compute `top_holder_share` and `n_holders`. Then classify the top holder:

```console
$ cast codesize 0xd5fa4f58…   → 0      # NOT a contract
$ cast nonce    0xd5fa4f58…   → 0x0    # never sent a tx
$ cast balance  0xd5fa4f58…   → 0x0    # never received native value
share=99.0827% holders=1               # solana-USDC
```

`codesize 0 + nonce 0 + balance 0 + holds ~all of a token` = **sink / burn-style address**, not a
compromised key. Two opposite conclusions must be stated correctly:

- **lowers** the "sudden drain by the holder" risk (key unknowable / intentionally dead), and
- **raises** the integration risk: `totalSupply` is misleading to any consumer, liquidity is
  structurally absent, and one point holds all supply.

Also rule out derivation before calling it a mystery: `cast compute-address` from each protocol
contract at nonce `0..5` — no match means it is not a CREATE child of the protocol. And confirm it
holds no role (`hasRole` for every role hash you found).

### 5c. Token-mirror hygiene — check for hidden value-moving functions

For every token-view contract, dump selectors and resolve them, specifically looking for
`mint`/`burn`/`withdraw`/`sweep`/`rescue`:

```bash
sels $VIEW | while read s; do printf "0x%s %s\n" "$s" "$(cast 4byte $s 2>/dev/null | head -1)"; done
```

All six views at `codesize 3874` (identical template) exposing only
`name/symbol/decimals/totalSupply/balanceOf/allowance/transfer/transferFrom/approve/tokenId/hub/tokenURI/emitTransferEvent/emitApprovalEvent`
⇒ clean mirror, no withdrawal surface. **A view with a `sweep`/`rescue` selector would be the whole
finding** — this check is 2 minutes and outputs a citable selector list.

---

## 6. CENSUS A DEPLOYMENT MANIFEST BY ROLE — batched, never per-address

The registry had **49** unique addresses (not the 31 an earlier partial sweep implied — always
de-duplicate the whole JSON tree, not one branch):

```python
s = set()
def walk(o):
    if isinstance(o, dict):  [walk(v) for v in o.values()]
    elif isinstance(o, list): [walk(v) for v in o]
    elif isinstance(o, str) and len(o) == 42 and o.startswith("0x"): s.add(o.lower())
```

Then read the role hashes **from the contracts, never hardcode them**:

```bash
ORACLE_ROLE=$(cc $ORA 'ORACLE_ROLE()(bytes32)')      # 0x68e79a7b…  ← NOT keccak("ORACLE_ROLE")
ADMIN_ROLE=$(cc  $ORA 'ADMIN_ROLE()(bytes32)')       # 0xa4980720…  (this one matches OZ)
HUB_OP=$(cc      $HUB 'OPERATOR_ROLE()(bytes32)')
```

**Per-address `cast call` loops time out at ~49 addresses** (observed: killed at 180 s after 28).
Batch instead: `3 × N` `hasRole` calls into one `aggregate3`, chunks of ~10 addresses, and print the
holder table. Result on this target was clean and citable:

```
only 4 of 49 hold any role:
  0x2a72eb8c…  ORACLE_ROLE      (oracleMultisig)
  0x613d3c58…  Hub OPERATOR     (Allocator)
  0x6747c7e6…  Hub OPERATOR     (Executor)
  0xd180dc3b…  Hub OPERATOR     (OracleV2 itself)
```

Two readings that matter:

- **The oracle holding `Hub.OPERATOR_ROLE` is by design**, not a new escalation: the only way to use
  it is through the signature-gated execute path. But it means *compromise of the oracle multisig =
  unbounded mint*, which is worth one sentence in the report.
- **A role with ZERO registry holders is a finding about *where* admin lives.** `ADMIN_ROLE` held by
  none of the 49 ⇒ the admin is outside the manifest (on this target: a single EOA reachable via a
  1-of-1 Safe). "Nobody in the registry holds it" is a lead, not a non-result.

---

## 7. THREE FALSE POSITIVES, defused — reuse these shapes

**(a) A `codesize 0` address in the manifest is usually a per-chain placeholder.** `0xab86c681…`
appeared 54 times with zero code and zero nonce — the instinct is "ghost contract / forgotten
deploy". Reality:

```bash
python3 -c "…find parent key of 0xab86c681…"   # PARENT KEY: /multicallRouters/abstract
```

It is a sentinel for the ~50 chains the protocol does not support yet. **Locate the address's parent
key in the manifest before calling it a ghost** — the same address filling every unsupported chain is
a placeholder, not a backdoor.

**(b) Permissionless wrapper ≠ permissionless power.** `executeMultiple(...)` had **no access
modifier** and **swallowed every inner revert** in a `try/catch`, so every probe returned `0x`
"success" for both an attacker *and* a bad signature:

```console
oracle=ATTACKER  → {"result":"0x"}      # looks like it went through
oracle=MULTISIG  → {"result":"0x"}      # also "succeeds" with a forged sig
```

The trap: a function that catches reverts is **unprobeable at its own entrypoint**. Simulate the
*inner* `execute()` instead, which is where the guards actually live:

```console
execute() from attacker  → 0x91e47843…dead                  UnauthorizedOracle(0xdead)
execute() from multisig  → 0xd855c4f4…2a72eb8c…             InvalidSignature(0x2a72eb8c…)
```

Two independent controls (role + EIP-1271), both proven by revert selector — **not** an amplifier.
Also note `pickModuleProvider`-style `try/catch` swallowing is why the *outer* function's success
return is not evidence of anything.

**(c) A single-key owner with no timelock is the real high finding — but the path matters.**
`Allocator` used plain `Ownable`, `owner()` = an EOA, and `pendingOwner()` **reverted** (no 2-step).
Differential probe nails it:

```console
from owner EOA  → 0x                                      transferOwnership succeeds
from attacker   → 0x118cdaa7…dead                         OwnableUnauthorizedAccount(0xdead)
```

The honest framing: `transferOwnership` is not exploitable *by an attacker*; the finding is
**"single private key controls the contract, irreversibly, with no timelock/acceptance step"**.
Report it as key-compromise blast radius + missing recovery latency — never as "anyone can take
ownership". And the inverse check is cheap and worth stating: no EIP-1967 impl/admin/beacon slot on
any of the four core contracts ⇒ **fully immutable**, which is simultaneously *no upgrade backdoor*
and *no patch path*. Both halves belong in the same paragraph.

---

## 8. REPORT SHAPE FOR A MOSTLY-NEGATIVE ROUND

When the brief asks three questions and two answer "no", the deliverable is a **findings table with
explicit verdicts**, including the refutations:

```markdown
| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | Allocator owner = single EOA, no timelock, not 2-step | HIGH | Proven (differential simulate) |
| F4 | Live bytecode ≠ repo (slot base 6 vs 3) | MEDIUM | Proven (slot-race + control) |
| F5 | ΣbalanceOf ≠ totalSupply on 7/7 ids (atomic) | MEDIUM | Proven; holder set incomplete |
| F3 | executeMultiple permissionless but double-gated | INFO | Refuted (inner execute revert selectors) |
| F7 | "Ghost contract" in manifest | — | FALSE POSITIVE (per-chain placeholder) |
```

Three discipline points that made this round credible:

1. **Every refutation gets a severity and a status, right next to the real findings** — it is the
   artifact that stops the next session re-deriving a dead class (see
   `live-rpc-forensics-and-eth-call-trap.md` §16d).
2. **BLOCKED is its own verdict**, with the literal failing response attached
   (`eth_getProof not supported`). Never silently drop a sub-question.
3. **Re-verify your own report's key claims before shipping.** Two claims in the draft were stale
   (supply numbers from a moving chain, and a slot match that failed on string-compare). Both were
   caught by re-running the exact command into the final document — build the verification commands
   so they can be pasted straight from the report.

---

## 9. THE SAME CENSUS, THREE DIFFERENT ANSWERS — and the four fields that stop it

The worst number in a hunt is one you already told the user. This happened here: the same
`EntrySet` census on the same contract produced **1**, then **45,144**, then **1,930,893**. Only
the third is real. All three runs exited 0 and printed clean output.

| Run | Method | Number | Why it was wrong |
|---|---|---|---|
| 1 | `eth_getLogs`, 25k chunks, `try/except: continue` | **1** | 103/104 chunks failed on response-size; errors became silent absences (§1a) |
| 2 | `eth_getLogsWithCursor`, walk-back + counters | **45,144** | loop broke out of the *window* on first empty page and never advanced the outer range for most windows; the count came from a handful of windows |
| 3 | `eth_getLogsWithCursor`, 100k windows 0→tip, dedup, responses to file | **1,930,893** | **correct** — 0 failed windows, 0 duplicate rows |

**The tell nobody notices:** run 2's per-window log printed `cum=<n>` and the cumulative curve
looked plausible (a monotone climb to 45k). A monotone curve *feels* validated. It is not — it only
says the loop ran, not that it covered the range. Add the arithmetic check: with `TIP/100_000 + 1`
windows, the number of printed window lines must equal the expected count, and the last line's block
range must end at `TIP`.

### 9a. The four fields — no volume claim ships without all four

```
EntrySet UNIQUE   = 1,930,893        ← deduped by (txHash, user, id, logIndex)
unique users      =   244,865        ← tells you concentration, not just volume
unique tx         = 1,930,893        ← == EntrySet ⇒ 1 write per tx (no batching); a mismatch means batching or duplicates
block range       = 999,365 .. 6,133,000   ← proves the walk reached genesis AND tip
failed windows    = 0 / 0            ← the only acceptable value for a "final" label
```

`EntryDeleted = 0` was the fifth, and it was load-bearing rather than decorative: zero deletes across
1.93M writes is what turned "squat is theoretically permanent" into "**every key ever written is
locked**" (`signature-gated-entry-writes-and-bytecode-identity.md` §3). **Always count the inverse
event** — a zero there is an amplifier, not an absence.

### 9b. Deduplicate by the log identity, and print both counters

```python
key = (lg["transactionHash"], lg["topics"][1], lg["topics"][2], lg.get("logIndex"))
if key not in seen:
    seen[key] = {...}; new += 1
```
Print `logs=<len(page)> new_unique=<new>` per page. If `new_unique` collapses toward 0 while `logs`
stays high, the cursor is re-serving the same page — the stuck-cursor failure from §1a, now visible
instead of silent.

### 9c. Large responses must go to a FILE, not through stdout

A 100k-block window on a busy contract returned **989 KB / 1154 logs per page**. Piping that through
`curl | python3` or capturing it via a tool whose output channel is size-capped produced
`JSONDecodeError: Expecting value: line 1 column 1` — which reads exactly like "the RPC returned
nothing". It did not; the buffer was dropped.

```bash
curl -s -m 60 -X POST $RPC -H 'Content-Type: application/json' \
  --data @/tmp/_req.json -o /tmp/_resp.json     # -o, then json.load(open(...))
```

**Never diagnose "empty response" from a parse error.** Distinguish them: `wc -c /tmp/_resp.json`
first. A parse error with a large file = your decoder; a parse error with a 0-byte file = the
request. This single check separated two of this round's three bad numbers.

### 9d. When you must correct a number you already shipped

Ship the correction as its own artifact (`R27_FullEnumeration.md`), keep the old value in a
comparison table with the reason it was wrong, and patch the earlier report so the stale number
cannot be quoted from it later. Deleting the wrong figure destroys the audit trail; leaving it
un-patched destroys the report. Do both halves.

---

## 11. COUNTING THE SENDERS OF A WRITE-GATED SURFACE — three senders, three different answers

After a volume census (§9) the next question is always *"who actually sends these writes?"*, and the
answer decides severity (see `signature-gated-entry-writes-and-bytecode-identity.md` §5/§5a). Three
probes, in this order, each cheaper than the one before it is *decisive*:

```bash
# 1. sender of a sampled tx — no explorer needed
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["'$TX'"]}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['from'])"

# 2. what KIND of address is it
cast codesize $FROM   # 0 ⇒ EOA, nonzero ⇒ contract/bot
cast nonce    $FROM   # high nonce ⇒ long-lived hot key, 0 ⇒ freshly minted / unused
cast balance  $FROM   # 0 balance + high nonce ⇒ gas funded per-tx, i.e. an operational relayer

# 3. does it hold the role the gate is supposed to require — LIVE, not from a grant census
cast call $C "hasRole(bytes32,address)(bool)" $ROLE $FROM
```

**The reading that cost a retraction:** senders were first labelled "operator backend holding
`EDITOR_ROLE`" from a `RoleGranted` scan, which framed the defect as *bounded* (trusted callers). A
live `hasRole` returned **false** for all of them, and a `RoleRevoked` sweep showed why: the role had
been revoked ~800k blocks earlier. The corrected reading **raised** the finding (the gate really is
signature-only in daily operation) rather than lowering it.

**Nonce as a caller classifier** — genuinely useful and rarely used:

| codesize | nonce | reading |
|---|---|---|
| 0 | high (>100) | operational hot key / relayer — long history, likely protocol-run |
| 0 | 0 | single-use key, or an address that only ever *received* |
| >0 | any | contract — decode its logs rather than guessing its purpose |

Do not stop at one sender. Sample **at least 4**, including the **earliest** write in contract
history (find it by walking backwards in windows, §1a): if the first-ever writer also held no role,
the sentence "the contract never checked caller identity, not on day one" is proven rather than
inferred.
