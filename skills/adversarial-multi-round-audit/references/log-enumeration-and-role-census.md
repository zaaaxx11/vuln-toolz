# Log enumeration & role census — `eth_getLogs` traps, cursor pagination, and the event-vs-state reconciliation rule

Companion to SKILL.md pitfall 30 (MULTI-INSTANCE CENSUS) and
`references/live-call-surface-census.md`. Read this the moment a role/permission
census has to go **historical** rather than "last N blocks".

The headline: on a rate-limited RPC, `eth_getLogs` returning `[]` is
**indistinguishable from "no such logs"** unless you (a) know the RPC's real
pagination method and (b) already hold a positive control for the *same query
shape*. Both were learned the expensive way.

---

## 1. `eth_getLogs` returns `[]` when it should return logs — check for a cursor method

Observed on `rpc.chain.relay.link` (a Frontier/Polkadot-EVM style endpoint):

```text
eth_getLogs  without topics, huge range   -> {"code": -32005,
                                              "message": "Response size exceeds limit.
                                              Use eth_getLogsWithCursor or reduce
                                              the number of logs requested"}
eth_getLogs  with topics, valid 500-blk    -> {"result": []}      <-- LOOKS like "no logs"
eth_getLogs  single block of a known tx    -> {"result": [ ... ]}  <-- works
```

So `eth_getLogs` **can** work, but silently under-reports across wide ranges
instead of erroring. `[]` is therefore not evidence of absence.

**The error message is the documentation.** When the RPC names a method, try it
verbatim before inventing pagination:

```python
p = {"fromBlock": hex(lo), "toBlock": hex(hi),
     "address": addr, "topics": [topic0, roleHash]}
d = raw("eth_getLogsWithCursor", [p])     # -> {"result": {"logs": [...], "cursor": "..."}}
```

Schema discovered by probing (do not guess — probe):

| field | verdict |
|---|---|
| `fromBlock` / `toBlock` / `address` / `topics` / `blockHash` | accepted |
| `limit` | **REJECTED** — `unknown field 'limit', expected one of fromBlock, toBlock, address, topics, blockHash` |
| `cursor` (top-level in the params object) | accepted, continues the scan |
| response shape | `{"result": {"logs": [...], "cursor": "<opaque>"}}` |

Other forms to try when a method name is unknown, cheapest first:

```text
1. the exact string from the RPC's own error message
2. same params, plus "cursor" from the previous response
3. [filter, {fromBlock, toBlock}] as two positional params   (usually WRONG:
   produced "trailing characters" / InvalidParams)
```

`eth_getLogsWithCursor` with `fromBlock: 0x1, toBlock: latest` and no chunking
**times out**. Chunk it — 400k–800k blocks per request worked; 800k returned
`invalid block range` near the chain tip, so clamp `toBlock` to the tip.

---

## 2. Cursor pagination: follow the cursor to exhaustion PER WINDOW

This is the bug that cost an entire 30-minute round and produced 12 wrong rows.

```text
WRONG:
  p = window(lo, hi); if cursor: p["cursor"] = cursor
  ... if nc and logs: cursor = nc
      else:          cursor = None; lo = hi + 1     <-- ADVANCES WINDOW ON A
                                                        TRUNCATED PAGE
RIGHT:
  for each window:
      cursor = None
      loop:
          d = getLogsWithCursor(window + cursor)
          emit(d.logs)
          nc = d.cursor
          if nc is None: break          # window exhausted, NOW advance lo
          cursor = nc
      lo = hi + 1
```

Why it silently corrupts results: a window may return a page with `logs` intact
but **an empty cursor string**, or `logs` empty while a cursor still exists. The
"if no cursor, advance" branch treats either as end-of-window and skips every
remaining page. You then hold a **partial** event set with no error anywhere.

### The reconciliation rule (non-negotiable)

**Never ship a role/permission census that came from event scan alone.** Cross-check
every derived holder against live state:

```text
derived_active = (last Grant block > last Revoke block) and last Grant exists
assert  hasRole(hub, ROLE, addr) == derived_active      for EVERY address seen
```

In-session, 12 of 13 "active" holders returned `hasRole == 0` live. The event scan
was partial; the state was right. Had the check not run, the report would have
claimed **12 OPERATOR EOAs on a production hub** — a fabricated CRITICAL.

If any row mismatches: **the method is defective, not the contract.** Re-scan, do
not rationalise. Report the mismatch in the round output as a method defect even
if the re-scan is cut off by budget.

Corollary trap: `RoleGranted` and `RoleRevoked` must be scanned **with the same
pagination care**. A grant at block 274,240 whose revoke sits at 3,087,734 is
invisible to any window-limited scan; only a full-history scan resolves it.

---

## 3. Control hierarchy for log queries (a "0 results" probe needs all three)

```text
L1  query shape works      : the exact same fromBlock/toBlock/address/topics
                             form, on a block KNOWN to contain a log
L2  topic works            : pull that known block by number, confirm the
                             expected topic0 appears
L3  address filter works   : same block, address = the contract under audit
```

Concretely: take a tx you already decoded (`execute()` on the executor), fetch its
receipt, read `blockNumber`, then `eth_getLogs{fromBlock: blk, toBlock: blk,
address: receipt.to}` and assert non-empty. Only then is "0 RoleGranted events"
a measurement rather than an instrument failure.

A control that returns `0` is **not** a control. Same rule as pitfall 17 applied to
logs. If L1–L3 all return zero, the verdict is `INSTRUMENT-INVALID`, never
"no events exist".

---

## 4. Role-hash vs selector (re-stated because it recurs every census)

```text
selector  = keccak("grantRole(bytes32,address)")[:4]        = 0x2f2ff15d   (calldata)
event     = keccak("RoleGranted(bytes32,address,address)")  = 0x2f878811…  (topic0)
role hash = keccak("OPERATOR_ROLE")  (the RETURN value of OPERATOR_ROLE())
          = 0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929
```

`0x2f2ff15d` is also **not** the role hash. Three separate 32/4-byte strings live in
this one area; mixing any two produces a query that silently matches nothing.
Verified role hashes in this family:

```text
OPERATOR  0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929
ADMIN     0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775
EDITOR    0x21d1167972f621f75904fb065136bc8b53c7ba1c60ccd3a7758fbee465851e9c
```

`getRoleMemberCount` / `getRoleMember` are frequently **absent** from the deployed
ABI — that is exactly when `RoleGranted`/`RoleRevoked` scanning is the only path,
which is why §1–§3 matter.

---

## 5. Zero grants in the recent window ≠ zero holders

13 grants and 14 revokes existed on the audited hub; **all of them** sat in blocks
175,552–175,723, 206,647, 274,240, 2,752,628 and 3,087,734–3,087,809 — while the
tip was 6,176,000. A "last 7,000 blocks" scan correctly returned `0` and that zero
was worthless. Any holder census must start at the deploy block.

### 5a. Find the deploy block FIRST — before any scan

Do not start at block 1 "to be safe". On a multi-million-block chain a full-history
cursor scan at 300–400k blocks/request is 15–20 requests **plus** cursor pages per
window, and it will eat a 30-minute round before printing a single line.

```bash
# ground truth for the deploy block — first row whose contractAddress is the target
curl -s "…/api?module=account&action=txlist&address=<ADDR>&sort=asc&page=1&offset=5"
```

Then start the scan at that block. Two traps this avoids:

- **Scan too early** → budget gone, no output (the round-19 failure).
- **Scan too late** → early grants invisible, census looks clean and is wrong.

Worked example: a sibling hub's deploy sat at block **2,256,613** while a naive
`lo = 1` scan with 400k windows never reported it. The consequence was a
"0 `RoleGranted` events" reading that contradicted a live `hasRole == 1`. The
contradiction was resolved only after reading the **deploy tx receipt** and finding
`RoleGranted(OPERATOR_ROLE, oracle)` at block 2,256,677.

### 5b-0. BEFORE any scan: is the role even registered on THIS instance?

A census answers "who holds ROLE here". It does not answer "can ROLE ever be held
here", and the difference has decided two separate lanes. Run `getRoleAdmin` first —
one call, before you spend a round enumerating holders of a role that cannot exist:

```python
getRoleAdmin(bytes32 role)   # eth_call, 32-byte return
# == keccak("ADMIN_ROLE")  -> role is admin-managed; find hasRole(ADMIN, X) and X can self-grant
# == keccak("ROLE")        -> self-administered
# == 0x00…00 / UNKNOWN     -> ROLE WAS NEVER SET UP on this instance
```

Observed in-session on a sibling hub that had a full `AccessControl` role hierarchy for
OPERATOR / ADMIN / EDITOR:

```text
getRoleAdmin(OPERATOR) = ADMIN         getRoleAdmin(EDITOR) = ADMIN
getRoleAdmin(ADMIN)    = ADMIN         getRoleAdmin(ORACLE) = UNK   <-- never initialised
```

The consequence was not cosmetic. That hub's `RelayOracleV2.execute()` requires
`hasRole(ORACLE_ROLE, oracle)`, so **every** call reverts `UnauthorizedOracle`
permanently — the `mint`/`burn` path through the oracle is **closed by construction**.
Eight prior candidate probes had returned `False`, which had been carried forward as a
soft "provisional" thread for two rounds when one structural call would have killed it.

```text
WEAK    hasRole(ROLE, x) == False for 8 candidates   -> "no holder found"   (account-scoped)
STRONG  getRoleAdmin(ROLE) == UNK                    -> "gate unopenable"   (structural)
ALSO    getRoleAdmin(TARGET) == ADMIN and hasRole(ADMIN, K)
                                                     -> K can self-grant TARGET in 1 tx
```

The third line is the escalation primitive and belongs in the severity, not a footnote:
`_setRoleAdmin(OPERATOR_ROLE, ADMIN_ROLE)` plus a single-EOA ADMIN means an uncapped
`mint` gate is one `grantRole` away from being held by that key's holder.

Corollary for the census itself: a `False` from `hasRole` and an unregistered role print
identically if you only look at the boolean. `getRoleAdmin` is what separates
"nobody has it" from "it cannot be had".

### 5b. "0 grant events" against a live `hasRole == 1` is a METHOD alarm, not a finding

This is the highest-value diagnostic in the whole census. When they disagree:

```text
1. STOP. The event set is wrong, not the contract. Never write "unauthorised grant".
2. Pull the contract's FULL tx list (explorer txlist) and filter input[:10] for
   grantRole 0x2f2ff15d / revokeRole 0xd547741f. The senders ARE the admins.
3. Read those tx receipts directly: status + decoded RoleGranted topics.
   Explorer isError/isError==0 is not proof — read the receipt.
4. Only then re-scan events from the deploy block and reconcile.
```

The `grantRole`/`revokeRole` sender list is often faster and more reliable than a
full event scan for answering "who holds admin", because it is bounded by tx count
rather than chain length. Note the senders are the admins **at the time of the
call** — a deployer who later renounced shows as a sender but has `hasRole == 0`
today. Handover is normal; check the current holder separately.

### 5b-1. The bounded fast path that actually cracks it: txlist, not event scan

When §5b fires, run this **before** spending another round on cursor pagination.
It took this session three consecutive rounds to stop scanning and start reading
transaction lists; the answer came in one request.

```text
1. explorer txlist for the CONTRACT (not the holder), sort=asc
2. keep rows whose input[:10] is grantRole 0x2f2ff15d / revokeRole 0xd547741f
3. for each: eth_getTransactionReceipt -> assert status == 0x1
4. decode the receipt's RoleGranted topics -> (role, account)   <-- ground truth
```

Why this beats a full-history scan on a cheap RPC:

| | full-history event scan | txlist + receipts |
|---|---|---|
| work bound | chain length ÷ span × pages | number of txs to that contract |
| fails on | truncated cursor pages, span limits, 429 | nothing, if the explorer indexes |
| cost | 15–20+ requests per role, per instance | one page + one receipt per grant |

For a role-administered contract this is single-digit requests total. Decode
receipts rather than trusting the explorer's `isError` field:

```text
explorer isError == 0  ->  NOT proof of success (field often omitted/empty)
receipt.status == 0x1  ->  proof
receipt.logs[*].topics -> RoleGranted(role, account, sender); account = topics[2][26:]
```

Corollary: **read the deploy receipt too.** A constructor-time `_grantRole` emits
the same event as a later `grantRole`, so a deploy-block receipt is a legitimate
grant row and must appear in the census. This is how a "0 `RoleGranted`" reading
was finally reconciled against a live `hasRole == 1`.

### 5b-3. When a hub is "quiet", read its TXLIST + RECEIPTS — not `eth_getLogs`

A hub returned `0` logs for a 4-million-block `eth_getLogsWithCursor` window, which was
read out as *"this hub has never emitted an event"*. It had 52 lifetime txs and **29
real logs**. The wide-range query was silently empty (same failure as §1); the receipts
were not.

```text
WRONG instrument: eth_getLogsWithCursor(fromBlock=deploy, toBlock=tip, address=hub)
                  -> logs: []            (reads as "no events ever")

RIGHT instrument: explorer txlist(address=hub, offset=100, page 1..N)
                  -> 52 txs -> eth_getTransactionReceipt each -> 29 logs
```

Cheap and bounded: the work is `tx count`, not chain length. For any contract with a
few hundred txs or fewer, this is the **first** instrument to reach for — it answers
"what has this contract ever done" in one pass and cannot silently truncate.

Decode the inventory rather than trusting event names:

```python
# topic0 census over receipts, THEN identify each by keccak(signature)
0x2f8788117e7eff1d  RoleGranted(bytes32,address,address)
0xf6391f5c32d9c69d  RoleRevoked(bytes32,address,address)     # NOT a token event
0xbd79b86ffe0ab8e8  RoleAdminChanged(bytes32,bytes32,bytes32)
```

`RoleRevoked` topics read `[sig, role, account, sender]` — so `topics[2]` is **who lost
the role** and `topics[3]` is **who revoked it**. Getting these backwards invents an
"unauthorised grant" out of a routine revocation sweep. In-session this surfaced a role
holder (`0x9b36f128…`, 8172 B, `HUB()` = the hub) that no prior census had listed.

Also: `0xb2d4699d` ≠ `transfer`. It is `setTokenMetadata(uint256,(string,string,uint8,
string,uint256,string))`. **Resolve every selector against the verified ABI before
naming it** — same rule as Rule 8 in `abi-and-field-verification.md`, applied to
calldata instead of to selectors you build. A guessed name for an observed selector is
how a metadata-registration call gets counted as a deposit.

### 5b-4. Explorer `tokentx` returns 0 for contract addresses — use Transfer events

`module=account&action=tokentx&address=<CONTRACT>` came back empty for a token hub
that demonstrably held balances. Do not read that as "no holders". Enumerate
holders from `Transfer` logs (`eth_getLogsWithCursor`, topic0 =
`Transfer(address,address,uint256,uint256)` for ERC-1155-style hubs) or from the
`Executed`/domain events already decoded in earlier rounds, then confirm each with
`balanceOf` before using it as a victim. Confirming `balanceOf > 0` is not
optional — see §3-0 of `references/helper-exemption-and-allowance-bypass.md`.

### 5b-5. Find the token ids by decoding calldata, not by reading a getter

Holder enumeration needs a token id, and hubs rarely expose `tokenIds()`. The ids
are sitting in the contract's own tx list:

```python
# every hub transfer carries the id as a static word — but pick the RIGHT word
for t in txlist(hub):
    inp = t["input"]
    if inp[:10] != SEL: continue
    W = [inp[10:][i*64:(i+1)*64] for i in range((len(inp)-10)//64)]
    ids.add(int(W[1], 16))     # VERIFY the index against the ABI signature first
```

The index is **not** guessable across contracts. For `transfer(address,uint256,uint256)`
it is `W[1]`; for `transfer(address,address,uint256,uint256,bytes)` it is `W[2]`
(`W[0]` = receiver, `W[1]` = sender, and a prior round's `W[6]` was pure invention).
**Resolve `input[:10]` against the ABI, write out the parameter order, then pick the
index.** Two rounds were burned on `W[6]` and then on a nonexistent struct field.

Then, before using an id anywhere, round-trip it (see §6 of
`references/decode-and-proof-traps.md`) — 256-bit ids must never be reformatted for
display and reused.

### 5b-6. `eth_getStorageAt` / `eth_getProof` are NOT the holder-discovery shortcut

When `balanceOf` lookups come back zero across many candidates, the instinct is to
read the balance mapping slot directly. Two reasons that usually fails and is not
worth a round:

- The mapping slot must be derived (`keccak(abi.encode(key, slot))` for
  `mapping(address => mapping(uint256 => uint256))`), i.e. you still need the exact
  address — the very thing you lack.
- Nested mappings mean the slot index depends on declaration order, which the
  verified source gives but a **proxy/implementation split** can contradict.

Prefer: receipts (§5b-3) → ids from calldata (§5b-5) → `balanceOf` confirmation.
If after ~50 address candidates everything is `0` while `totalSupply` is not, the
conclusion is `SUPPLY-LEDGER DIVERGENCE` (see `decode-and-proof-traps.md` §5b),
not "keep probing storage".


### 5c. A live holder with no visible grant path is usually a sibling contract

Before calling an unexpected holder suspicious, resolve it: `HUB()`, `owner()`,
`getSourceCode` (name + verified source length). In-session, an unexplained
`OPERATOR_ROLE` holder turned out to be the sibling **RelayAllocator** whose
`HUB()` returned exactly the hub under audit, and whose `owner()` was that hub's
`ADMIN`. That made it by-design, not a finding — and reporting it would have been
a fabricated CRITICAL. Same for a `RelayOracle` / `RelayExecutor` pair: a revoked
holder plus a differently-addressed live one is a **migration**, not an anomaly.

Corollary: a contract holding `OPERATOR_ROLE` on the hub it drives is expected
(the allocator must be able to `burn`). The finding, if any, is the operator
predicate being **global** — see `references/permission-model-global-operator.md`.

---

## 6. Budget discipline for these scans (this is what kills rounds)

```text
BAD   one synchronous scan of full history inside the agent loop  -> 180 s tool
      timeout, no output, round consumed
OK    (timeout 290 PYBIN script.py > r18/a3.log 2>&1 &); sleep 75; tail -30 r18/a3.log
```

Rules:

- Every RPC response gets written to a file **as it arrives** (`json.dumps(r)` into
  `r18/logs_N.json`), so a killed process still leaves evidence.
- Print progress per window (`lo`, `cursor present?`, count) — a log with zero
  lines at +100 s means the script is stuck, not slow.
- Budget a full-history census at **2–4 minutes per contract**, not 30 s. If the
  round budget is 30 min, start the census first and do source reading while it runs.
- A reconciliation pass is a **second** run. Do not append it to the scan script;
  if the scan eats the budget you lose both. Write the event set to disk, then
  reconcile in a separate short script.
