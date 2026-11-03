# Contract liveness & mutation-result forensics

Two self-corrections from a live target (Relay chain 537713) that cost a full round each.
Both are **methodology failures that produce confident false conclusions**, and both recur on
any bytecode-only target.

---

## 1. `eth_getLogs` returning `[]` does NOT mean "dead contract"

**What I concluded:** batcher `0x03a2…54d3` had zero logs across all history, zero balance, so I
wrote *"DEAD CONTRACT — never called, no attack surface"* and moved on.

**What was true:**

```
block 6151763  tx 0x39400a212918a5736850e40f90191ae64526d867988576949bdb77b5cd55ae42
  to      : 0x03a246e0bff569bca1cc76d25d6529a86b6154d3   (the "dead" batcher)
  status  : 0x1  SUCCESS   gasUsed: 11,033,369
  input   : 4,324 bytes, selector 0x82ad56cb
  logs    : NONE        <-- emits no events, which is why getLogs missed it
```

The contract is a **log-silent** Multicall-style forwarder. Production traffic, zero events.

### Liveness checklist — run all four, never one

| Probe | Catches | Misses |
|---|---|---|
| `eth_getLogs(address=X, 0→latest)` | event-emitting contracts | **log-silent contracts** ← the trap |
| `eth_getTransactionCount(X)` | (contracts always return 0 — useless) | everything |
| `eth_getBalance(X)` | funded contracts | unfunded-but-used |
| **block scan for `tx.to == X`** | **any real usage** | — |

Block-scan recipe (the one that worked):

```python
tip = int(rpc("eth_blockNumber")["result"], 16)
for back in range(0, N):
    blk = rpc("eth_getBlockByNumber", [hex(tip - back), True])["result"]
    for tx in blk["transactions"]:
        if (tx.get("to") or "").lower() == TARGET.lower():
            record(tx["hash"], tx["input"], tx["from"], tx["value"])
```

Scan at least a few thousand blocks before declaring anything dead. If the batcher had been
genuinely dead, this costs ~$0 and 2 minutes; if it is alive, it hands you **real calldata**,
which is the next section.

---

## 2. Real calldata beats guessing a non-standard decoder

Hand-built payloads failed ~15 times against a `0x82ad56cb` dispatcher because I assumed
canonical Multicall3 ABI. The real layout, read off the live transaction:

```
word0 : 82ad56cb + 24 zero bytes      selector RIGHT-padded to a full word (non-standard)
word1 : 0x20                          offset to the call array
word2 : n                             number of calls (2)
word3 : 0x40                          offsets begin
word4 : 0x0440 || ORACLE_V2(20B)      offset AND address PACKED into one word
```

⇒ **element offsets are 20-byte (uint160), not 32-byte.** Every 32-byte-offset payload reverts.
`n = 0` with the same header returns SUCCESS — good cheap probe that your header is right.

**Rule: before reverse-engineering a decoder, look for one real transaction.** A successful
`tx.input` is ground truth that no amount of brute force reproduces. Locate every known address
by byte offset to map the struct:

```python
for name, addr in KNOWN_ADDRESSES.items():
    b = bytes.fromhex(addr.lower()); i = 0
    while (p := raw.find(b, i)) >= 0:
        print(f"{name} byte={p} word={p//32} pos={p%32}")
        i = p + 1
```

Cross-chain code identity is a dead end for this (5 chains had code at the same address,
none matched the keccak) — the block scan is the reliable path.

---

## 3. When a mutation returns SUCCESS, verify WHICH BYTES changed

The dangerous variant. I patched the address at byte offset 144 believing it was the Executor
dispatch target, got `result` instead of a revert, and concluded **"the batcher forwards to
arbitrary targets — no dispatch validation."** Wrote it in a report.

**It was the OracleV2 address.** Deleting it removed the signature check, so the aggregate ran
with an empty result. Not free dispatch — a disabled validator.

Control tests that exposed it:

| mutation | result |
|---|---|
| OracleV2 addr @byte144 → probe | SUCCESS (validation removed) |
| Executor addr @byte1168 → probe | **REVERT** `0x0964dde4…` |
| target → `EOA-no-code` (0x…bEEf) | **REVERT** `0x0964dde4…` ← impossibility test |
| both targets → probe | REVERT |

**`EOA-no-code` succeeding or failing is the discriminator.** A call to an address with no code
*can* succeed in the EVM (returns empty), so it is not conclusive alone — but if it **reverts
identically to the real target**, the revert is coming from before dispatch, not from the call.

### Mandatory sequence for any mutation experiment

1. **Control** — replay unmutated; record the exact revert selector.
2. **Single-variable** — change ONE field, confirm which byte offset it actually lives at by
   re-running the address locator, not by assumption.
3. **Impossibility probe** — mutate to something that cannot possibly work (`0x0`, `EOA-no-code`,
   `address(this)`); if the result is *better*, you are disabling a check, not achieving dispatch.
4. **Diff the revert selectors.** Same selector across all mutations ⇒ the failure is upstream of
   your change ⇒ your change was inert.
5. **Attribute the revert selector to a contract.** `eth_getCode` every candidate and grep for the
   4 bytes. Here `0x0964dde4` was in *none* of Batcher/Executor/OracleV2/Hub/BasicCallResolver —
   proving the revert came from a downstream contract, i.e. replay failed on consumed state.

```python
# revert-selector attribution
for name, a in CONTRACTS.items():
    code = rpc("eth_getCode", [a, "latest"])["result"][2:]
    print(f"{name}: contains {SEL}: {SEL in code}")
```

A selector absent from every local contract is a signal you are re-executing **stale state**, not
finding a bug.

---

## 4. Replay of a historical tx usually reverts — that is correct behaviour

The real calldata reverted on `eth_call` because the order it referenced had already been
executed (`usedRequests[digest]` consumed, balances drained). Do not read that as "the calldata is
invalid" or "the decoder rejects it". Distinguish:

- **decoder rejection** ⇒ fails on any input, including `n=0`
- **state rejection** ⇒ decode succeeds, execution fails at a business check

Test `n=0` (or the minimal valid header) separately. If minimal succeeds and full reverts, your
decoder understanding is correct and the revert is state.

---

## Lessons, compressed

1. `eth_getLogs == []` ⇒ **unknown**, never "dead". Block-scan `tx.to`.
2. Find a **real transaction** before reverse-engineering any decoder. It is faster and authoritative.
3. Any SUCCESS from a mutation ⇒ re-derive which bytes you actually touched before believing it.
4. Plate-mutation impossible values; identical revert selectors = inert change.
5. Attribute revert selectors to contracts; absent everywhere ⇒ stale state, not a vuln.
