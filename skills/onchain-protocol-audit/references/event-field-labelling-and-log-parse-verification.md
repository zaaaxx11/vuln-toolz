# Event-field labelling, log-parse verification, and the ground-truth ladder

Condensed from a Relay Protocol round (chainId 537713, Hub `0xDDD3…9318`) that produced **five
self-corrections of the same shape**: a field was given a *name* before that name was verified
against an external ground truth. Two of those mistakes were one line away from shipping a
**fake Critical** (`ΣbalanceOf ≠ totalSupply`, 96/96 tokens) and a **fake ATO** ("this EOA is
the Hub's most active caller, 2 776×").

Companion files: `inherited-findings-and-silent-rpc-failures.md` §2/§4 (probe discriminates?),
`rpc-census-supply-integrity-and-role-enumeration.md` §9/§11 (volume + sender counting),
`live-rpc-forensics-and-eth-call-trap.md` §15a (event topics).

**Section list:** §1 the failure shape · §2 ground-truth ladder · §3 indexed-vs-data: never
assume, read it off one raw log · §4 `eth_getLogs` vs `eth_getBlockReceipts` cross-check ·
§5 nonce/codesize as the identity oracle · §6 supply-integrity: a wrong layout produces
96/96 "mismatches" · §7 dangling-view / codeless-mirror sweep · §8 checklist.

---

## 1. THE FAILURE SHAPE — label before verify

Five variants of one bug, all in one session:

| # | What was assumed | Ground truth | Cost if shipped |
|---|---|---|---|
| 1 | `chr(0xDE)` is 1 byte in UTF-8 | 2 bytes (`c3 9e`) | collision script invalid |
| 2 | `id` lives in `data[0:32]` | `id` is **indexed** (`topics[3]`) | 96/96 phantom "supply mismatch" |
| 3 | `caller` = `topics[1]` | `topics[1]` = **`from`** (holder) | EOA with `nonce 0` accused of 2 776 Hub calls |
| 4 | Hub bytecode lacks `balanceOf` | verified source has all 36 fns | architecture misread for a whole round |
| 5 | `0x…01` return = "transfer succeeded" | the call had reverted | fake allowance-bypass Medium |

Every one was caught by a **second, independent observation** — never by re-reading the same
code or re-running the same call. That is the whole lesson: *the instrument that produced the
wrong answer cannot be the instrument that refutes it.*

**Rule:** before you name a field, a slot, a selector-diff, or a return value, write down the
**external fact** that would prove the name wrong, and go get that fact first. Naming is a
claim; treat it like one.

---

## 2. THE GROUND-TRUTH LADDER

Cheap → expensive, each one independent of the previous. Climb to whichever rung settles the
question, then stop.

```
1. VERIFIED SOURCE      explorer.chain.<host>/api/v2/smart-contracts/<addr>  (is_verified)
                        → beats any bytecode heuristic (PUSH4 scan, disassembly, size diff)
2. COMPILED ARTIFACT    out/<C>.sol/<C>.json → ABI (event input order + `indexed` flags)
                        forge inspect <C> storage-layout    (slot bases, types)
3. RECEIPT / TX         eth_getTransactionReceipt(txh).from   ← who actually sent it
                        eth_getTransactionByHash(txh).input  ← what was actually called
4. RAW LOG              4 topics + data, read once, byte offsets hand-counted
5. DERIVED STATE        eth_call getters, logs replay, computed balances
6. HEURISTIC            PUSH4 scan, codesize comparison, selector guess, event-name guess
```

Rung 6 sits at the **bottom** for a reason. During this session a PUSH4 scan of the Hub
reported "3 functions missing" and "39 unknown selectors"; both were ERC20View selectors and
Solidity panic constants blended into the code blob. **A verified-source fetch at rung 1 would
have cost one HTTP call and settled it.** Always try rung 1 first on an explorer-backed chain.

Same law already recorded in `rpc-census…md` §2 for ABI encoders and `bytecode-disassembly…md`
for selectors: *the artifact the deployer shipped is ground truth; your decoder is a hypothesis.*

---

## 3. INDEXED vs DATA — read it off ONE raw log, never from memory

Solidity event layout is fully determined by the ABI's `indexed` flags, and **the same event
name can have different flags on a different deployment**. Here three successive guesses were
all wrong on the *same* contract:

```python
# ABI (from out/RelayHub.sol/RelayHub.json):
# Transfer(address caller /*NOT indexed*/, address indexed from, address indexed to,
#          uint256 indexed id, uint256 amount /*NOT indexed*/)
```

The correct decode, confirmed against `eth_getTransactionReceipt().from`:

```
topics[0] = signature            (NOT keccak("Transfer(address,address,address,uint256,uint256)")
                                  — parameter NAMES differ, so the topic differs)
topics[1] = from                 address(0) ⇒ mint
topics[2] = to
topics[3] = id                   uint256, indexed
data.w0   = caller               = msg.sender INSIDE the Hub  (NOT tx.from!)
data.w1   = amount
```

Two distinct traps inside one event:

**(a) `data.w0` is not `tx.from`.** An EOA calls OracleV2; OracleV2 calls the Hub; the event's
`caller` is OracleV2. Verified on live data:

```
RECEIPT.from (ground truth msg.sender of the TX) = 0x2134c27b…
data.w0   (msg.sender inside the Hub)            = 0xd180dc3b…  ← OracleV2
```

Never mix the two in a report. "Caller of the Hub" and "sender of the tx" are different actors
and conflating them turns an infrastructure contract into a human attacker.

**(b) Count non-indexed words before slicing.** If `len(data) == 64` there are two non-indexed
fields; if `32`, one. Print `len(data)//32` for the first few logs and *derive* the layout
instead of hard-coding offsets:

```python
for l in logs[:5]:
    print(len(l["topics"]), len(l["data"])//2//32)   # e.g. 4 topics, 2 words
```

**Cheapest possible check (do this first, always):** ABI is right there in the build output.

```bash
python3 -c "
import json;js=json.load(open('out/RelayHub.sol/RelayHub.json'))
[print(e['name'],[(i['name'],i['type'],i['indexed']) for i in e['inputs']])
 for e in js['abi'] if e.get('type')=='event' and e['name'] in ('Transfer','Approval')]"
```

Ten seconds, and it removes an entire class of fabricated findings.

---

## 4. `eth_getLogs` vs `eth_getBlockReceipts` — cross-check, and settle disagreements with code

A subagent reported `eth_getLogs` was dead on this RPC ("returns `[]` for every range including
`fromBlock: 0x0`") and built its census on `eth_getBlockReceipts`. The main thread was getting
2 094 Hub logs from `eth_getLogs` over the same window. **Both scripts exited 0.**

Resolution — same 6 blocks, both methods, compare the *set* of `(txHash, logIndex)`:

```python
a_set = {(l["transactionHash"].lower()+":"+l["logIndex"]) for l in getLogs(addr, bn, bn)}
b_set = {(lg["transactionHash"].lower()+":"+lg["logIndex"])
         for rc in getBlockReceipts(bn) if rc for lg in rc.get("logs",[])
         if lg["address"].lower() == addr.lower()}
print(len(a_set), len(b_set), a_set == b_set)
```

Result:

```
block      getLogs  receipts   match
6160290          20        20   EQUAL
6160291          20        20   EQUAL
6160294          22        22   EQUAL
TOTAL            62        62
mismatch blocks = 0
```

`eth_getLogs` worked. The subagent's `[]` almost certainly came from a range too large for the
endpoint (silently rejected) rather than from a dead method — see
`inherited-findings-and-silent-rpc-failures.md` §3, which documents the genuinely-silent variant.

**Why the disagreement was invisible:** this chain produced **~1 tx per block**, so many blocks
really are empty. A run of `[]` reads as "method broken" when it is simply "chain is quiet".
Before concluding a method is dead, test it on a block you **know** is non-empty.

**Rule:** two agents disagreeing about a data source is resolved by a 6-line differential on a
handful of blocks — never by seniority, confidence, or who ran longer. And when the two methods
agree, record *that* in the report; it converts a counted number into an audited number
(`rpc-census…md` §9's four-field discipline, applied to method choice).

---

## 5. NONCE + CODESIZE — the identity oracle that kills false ATO claims

A holder address (`0xd5fa4f58…`) was accused of being the Hub's most active caller (2 776×)
because a scan script labelled `topics[1]` as "caller". Three calls killed it:

```
eth_getCode                → 0 bytes     (EOA)
eth_getTransactionCount    → 0           (NEVER sent a single tx)
eth_getBalance             → 0           (empty)
hub.hasRole(OPERATOR_ROLE) → 0
hub.hasRole(ADMIN_ROLE)    → 0
```

**An EOA with `nonce 0` cannot be `msg.sender` of 2 776 transactions.** The contradiction is
arithmetic, not judgement — that is what makes it a decisive refutation rather than a doubt.
The address was in fact a **passive holder** receiving mints, which matched the other
subagent's independent read of it as a victim/sink.

Add this triple to every "X is the caller/operator/attacker" claim:

```bash
cast codesize $A    # 0 ⇒ EOA, >0 ⇒ contract (decode its logs, don't guess)
cast nonce    $A    # 0 + alleged activity ⇒ contradiction
cast balance  $A
```

Cross-reference `rpc-census…md` §11's nonce table — `codesize 0 + nonce 0` means *recipient
only*, and that reading is cheap enough to run **before** writing the sentence that accuses it.

---

## 6. SUPPLY INTEGRITY — a wrong layout manufactures 96/96 "mismatches"

The most dangerous near-miss of the round. Two successive scripts printed:

```
0x17b8e9d9…   mint=14,000   burn=0   netDelta=14,000   ΔSupply=0   MISMATCH
0x613d3c58…   mint=9.09e22  burn=0   netDelta=9.09e22  ΔSupply=0   MISMATCH
...  96/96 MISMATCH
```

Both were **artefacts of §3**: `id` was read from `data` where it was indexed, and worse, an
`amount` of `7.17e48` appeared — an impossible magnitude that was itself the alarm. After the
decode was fixed against the receipt-verified layout, 20+ ids all reconciled exactly:

```
0x00fe5719..  mint=129,585,668  burn=0  net=129,585,668  dSupply=129,585,668  OK
0x032b562f..  mint=16,193,128,100,986,384,170  burn=12,894,487,914,446,958,631
              net=3,298,640,186,539,425,539  dSupply=same  OK
```

**Sanity gates that would have caught it in one glance:**

- **Magnitude.** Compare every parsed amount against `totalSupply(id)` from the chain. A `mint`
  larger than the live supply by 30 orders of magnitude is a decode bug, 100 % of the time.
- **Shape.** Token ids decoded as `0x17b8e9d9…c479`, `0x6747c7e6…bc0c` — these are *addresses*.
  Real ids are `keccak` output and look uniformly random. If your "ids" look like addresses,
  you sliced an address field.
- **Direction.** A real imbalance usually has a *reason* pattern; 96/96 uniform failure is an
  instrument result, not a contract result. Per
  `inherited-findings-and-silent-rpc-failures.md` §2: a probe that fails 100 % of the time on
  the first run is broken until the positive control passes.
- **Positive control first.** Reconcile the *simplest* id by hand (fewest logs, one mint, zero
  burns) before running the whole set. If id #1 does not reconcile, stop and fix the parser.

Cross-reference `rpc-census…md` §5a: even a *correct* parse leaves `ΣbalanceOf ≠ totalSupply`
as UNPROVEN if your holder set is incomplete (non-enumerable mapping). The honest output is a
table plus "holder set incomplete", never "unbacked supply".

---

## 7. DANGLING / CODELESS MIRROR SWEEP — the last live hypothesis, and how to close it in one pass

`_emitERC20ViewEvent` calls `IERC20View(erc20Views[id]).emitTransferEvent(...)` on **every**
mint/burn/transfer. If `erc20Views[id]` ever pointed at an address with no code, the high-level
call would revert on the extcodesize check — and if it pointed at an orphan (old view after a
re-create), events would silently stop matching state. That was the final open lane.

Sweep — for **every** id seen in logs, read the pointer and the code size, and compare against
supply:

```python
view = eth_call(HUB, sel("erc20Views(uint256)") + f"{tid:064x}")[-40:]
cs   = (len(eth_getCode(view)) - 2)//2
sup  = int(eth_call(HUB, sel("totalSupply(uint256)") + f"{tid:064x}"), 16)
# cs == 0 and view != 0  =>  DANGLING (finding)
```

Result:

```
OK view       = 85
NO view       = 0
DANGLING view = 0
```

All 85 ids → a contract at codesize **3 874**, identical template. Lane closed with evidence.

**Two supporting facts worth capturing because they generalise:**

- **A codesize histogram is a provenance check.** 85 views at *exactly* 3 874 bytes = one
  template, no mutated/orphan copies. Any outlier size in that column is the anomaly to chase.
  (`rpc-census…md` §5c already uses codesize for mirror hygiene — same idea, pointed at
  pointers instead of selectors.)
- **Absence of a lifecycle event is evidence, not proof.** `ERC20ViewCreated` never appeared in
  200 blocks (only `Transfer` did), yet 85 views exist — because creation happened earlier than
  the scanned window. Do **not** write "views are never created"; write "no creation events in
  the scanned window, N views present ⇒ creation predates it". A time-boxed scan only ever
  speaks about its window.

Rate-limit note for a sweep of this size (85 ids × 2 calls): chunk it, sleep on 429, and write
every response to a file as you go — a partial sweep you can inspect beats a timeout you cannot.

---

## 8. CHECKLIST

- Name a field only after an **external** fact confirms the name. Write down the refuting fact
  *first* if you can't.
- Climb the ground-truth ladder: verified source → compiled ABI/`forge inspect` → receipt →
  raw log → derived state → heuristics. **PUSH4 scans and codesize diffs are rung 6.**
- Event layout comes from the ABI's `indexed` flags, per deployment. Dump them, don't recall them.
- Count non-indexed words (`len(data)//32`); derive offsets; never hard-code `data[0:32]` for `id`.
- `data.w0` (inner `msg.sender`) ≠ `tx.from` (tx signer). Both are useful; conflating them
  fabricates attackers out of infrastructure.
- Suspect `eth_getLogs` is broken? Differential 6 blocks against `eth_getBlockReceipts` by
  `(txHash, logIndex)` set. On a quiet chain, empty blocks are normal — test a known non-empty one.
- An accused caller with `nonce 0` is a mathematical impossibility. Run the
  codesize/nonce/balance/hasRole quad before writing any "X called the Hub" sentence.
- Amounts that exceed `totalSupply` by orders of magnitude are parser bugs. Reconcile the
  simplest id by hand before running the set; a 100 %-failure result is an instrument report.
- Sweep pointers, not just selectors: `pointer → codesize → supply` for every id closes the
  dangling/orphan-mirror lane in one pass, and the codesize histogram proves template uniformity.
- A time-boxed scan speaks only about its window — phrase absences accordingly.
- Log every self-correction with the retracted value quoted. Five of them in one session is not
  embarrassing, it is the audit trail that stopped two fake Criticals.
