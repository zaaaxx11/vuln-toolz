# Derived-address identity — and recovering an "unfindable" address

Two traps that both look like protocol behaviour and both produce confident wrong
conclusions. Companion to `references/abi-and-field-verification.md` Rule 16 (truncated
address) — this file is what Rule 16 was missing, plus the mirror-image trap of treating
a *derived* address as an independent victim.

---

## §1 — Rule 16 was insufficient: the address was never missing, the search was

Rule 16 says "harvest the full address from `tx.from` / `tx.to` / calldata". That is
correct but underspecified, and the underspecification cost **14 rounds** in this
campaign. The contract was declared "unfindable" from R14 through R31, with a written
ledger note reading:

```text
Allocator#1 address UNKNOWN — prefix 0x613d3c58 yields explorer
{"message":"Invalid address format"}; zero occurrences across 300 Hub#1 txs
+ 100 Executor#1 txs + Oracle#1 txs; do not invent the remaining hex.
```

The address was `0x613d3c588f6b8f89302b463f8f19f7241b2857e2` — **8,496 bytes of live
code, verified source, receiving 50/50 of its recent transactions as
`submitWithdrawRequestWithSignature`**. It was found in one line once the search changed:

```python
# the block was ALREADY being fetched to trace a balance change.
# the address was in `to` of real transactions in that block, all along.
for B in [6178988, 6179029, 6179030, 6179071]:
    blk = raw('eth_getBlockByNumber', [hex(B), True])['result']
    for t in blk['transactions']:
        if (t.get('to') or '').lower().startswith(PREFIX):
            FULL.add(t['to'].lower())
# -> {'0x613d3c588f6b8f89302b463f8f19f7241b2857e2'}
```

### Why the previous searches failed

| Search performed | Why it returned nothing |
|---|---|
| explorer `txlist?address=0x613d3c58` | rejects short addresses — a **tool error**, not absence |
| `eth_getCode` on a guessed suffix | returned `0x`, read as "no contract" — measured a **fabricated** address |
| scan `txlist` of Hub#1 / Executor#1 / Oracle#1 | only walks txs where those are `from`/`to`; a contract called by **other** EOAs never appears there |
| prefix never matched | the address **was** in those scans' blocks, just not in the filtered `txlist` |

The last row is the real lesson: **`txlist(addr)` is a filtered view.** A contract that
thousands of unrelated EOAs call directly is invisible to a `txlist` of any *other*
contract. But it is plainly visible in `eth_getBlockByNumber(..., True)`.

### Rules

```text
RULE  a prefix is a SEARCH KEY, never a probe input. Probe only 40 hex chars.

RULE  to find a contract by prefix, iterate BLOCKS, not txlists. Every tx you
      already fetched for another reason carries `to` — match the prefix there.

RULE  a tool that rejects your identifier ("Invalid address format") has told you
      about ITSELF, not about the chain. Never record that as a negative finding.

RULE  an address that is a `to` target of many unrelated EOAs is a PUBLIC ENTRYPOINT.
      That is the highest-value place to look for attacker-reachable paths — a
      contract nobody calls is not a target; one with 50/50 inbound calls is.
```

The moment the address resolved, its profile took one script:

```text
Allocator#1  0x613d3c588f6b8f89302b463f8f19f7241b2857e2
  HUB()    = 0xddd361727c22a01eb137880678a20b0beae69318   <- the FUNDED hub
  ORACLE() = 0x2a72eb8cf0233a3dc6198683c83b1078de6fa2b0   <- same 2-of-5 msig
  owner()  = 0xf61a305199fa1135d76ffab3752d42f55cbd775a   <- EOA, not a multisig
  recent   = 50/50 tx = 0x771dc6a2 submitWithdrawRequestWithSignature
```

Note `owner() == EOA` versus the sibling's `owner() == multisig`: **instance profiles
differ even when the bytecode is identical.** Always read `owner()`/`ORACLE()`/`HUB()`
per instance rather than carrying one instance's trust model to the other.

---

## §2 — A derived alias is not a victim; a volatile balance is not an exploit

The same round found `balanceOf(VICTIM, tid)` swinging across ~90 blocks:

```text
blk 6,178,982  ->   224,678,047
blk 6,178,984  ->   540,328,853
blk 6,178,986  ->   940,328,853
blk 6,178,988  ->             0     <- emptied
blk 6,178,989  ->    12,000,000
blk 6,179,009  ->             0     <- emptied
blk 6,179,029  -> 8,370,617,539
blk 6,179,030  ->             0     <- emptied
blk 6,179,071  ->   687,722,142
```

Nine changes in ninety blocks, three resets to zero, and one 37× jump. `eth_call` at a
**fixed** block was deterministic (3/3 identical), so the data was real — the reading of
it was not. This was briefly framed as "proof the global-operator bypass is live and
draining".

The decode that dissolved it:

```text
tx to Allocator#1, blk 6,179,136
  spenderChainId = "base"
  spender        = 0xf70da97812cb96acdf810712aa562db8dfa3dbef
  amount         = 1,038,333,980
  spenderAlias   = keccak("base" ++ spender)[12:] = 0xd5fa4f5834722d85d95f45387ed60ce09ba4e36f
                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                        == "VICTIM"
```

**"VICTIM" was never a victim.** It is `spenderAlias`, a deterministic function of
`(chainId, spender)` — a protocol-internal scratch account. Its balance churns because
that is the designed flow, every single time:

```text
Executor._finalizeWithdraw
  -> _fundSpenderAlias   HUB.transfer(spenderAlias, tid, amount)     FILLS alias
  -> ALLOCATOR.submitWithdrawRequest(...)
       -> HUB.burn(spenderAlias, tid, amount)                        EMPTIES alias
       -> payload builder issues the withdrawal to `receiver`
```

Fill, burn, fill, burn. High volatility is the **signature of a healthy alias**, not of
a compromise.

### Rules

```text
RULE  before calling any address a victim, compute whether it is a DERIVED address:
        alias = keccak(chainId ++ abi.encodePacked(spender))[12:]
      If it matches, it is protocol-internal. It holds value by design; its balance
      movement is mechanism, not theft. Do not report it as user funds.

RULE  a balance that moves without a txlist entry is a STORAGE-MODEL question first,
      and an exploit question a distant second. Ask: who writes this slot, and is that
      writer designed to run constantly?

RULE  volatility magnitude is not evidence. Churn + resets + refills = an account that
      is filled and drained on purpose. Exploit evidence looks like a ONE-WAY move out
      of an account that had no incoming flow.

RULE  "balance changed" is never a finding. The finding must name the WRITER and show
      that the writer was invoked with an attacker-chosen input.
```

### The generalisable tell

When a suspected victim's balance is **replenished** between thefts, the theft model is
wrong. Real drains do not refill themselves. A refilling balance means you have found a
pool, a float, or a derived scratch account — something the protocol fills on purpose.

---

## §2b — Once the alias resolves, the CONFUSION is the finding to grade, not the balance

`spenderAlias` being protocol-internal does not end the investigation — it redirects it.
The alias is the account `burn()` debits, so the only question left is whether an
attacker can name a **real** alias with real balance and then act on it. Both halves were
already answerable:

```text
Q  is spenderAlias reachable by the caller?   callerIsSpender  ||  callerIsOperator
                                             where callerIsOperator = HUB.isOperator(spenderAlias, msg.sender)
Q  can the attacker substitute a funded alias?
     no — digest binds keccak(spender), and spender must equal msg.sender (len 20) for the
     self path, or the signature path needs the spender's key / the oracle multisig
```

The lesson is about **reporting discipline**, not exploitability: an audit whose central
claim was "the victim's balance is being drained" must explicitly retract that claim in the
final report, naming the mechanism that explains the number. A silent drop of a retracted
claim reads as a cover-up to triage; a labelled correction reads as rigour.

```text
RULE  when a headline observation is retracted, the retraction is a deliverable. State
      (a) what was claimed, (b) the mechanism that actually explains it, (c) which
      evidence survives and which is now mechanism-not-bug.

RULE  "derived alias" is NOT "harmless". It is a real account with real balance. Re-ask
      who can name it and who can spend from it — the answer just moves the finding from
      "drain" to "gate analysis".
```

---

## §2c — Balance-churn forensics: the cheap disambiguator before block-walking

Before spending rounds walking blocks, spend one script on three facts. They separate
"exploit" from "mechanism" for free:

```text
1  eth_getCode(victim)                 -> 0x means EOA: storage it "owns" is written by OTHERS
2  explorer txlist(victim)             -> 0 entries + moving balance = a DERIVED or POOLED account
3  determinism check at a FIXED block  -> same value 3x = real state, not RPC noise
```

In this campaign all three fired (`0x` code, 0 txs, 3/3 identical at fixed block) and the
first conclusion drawn was still "live drain". They are necessary and not sufficient: none
of them can see **who** wrote the slot. Only decoding a real tx that names the address can.

```text
RULE  "EOA with 0 txs and a moving balance" is the DEFINITION of a derived/pool account.
      Treat it as a discriminator, not as an anomaly.

RULE  these three facts are cheap but they do not identify the writer. Do not let a clean
      determinism check become a substitute for decoding the write.
```

---

## §3 — Verification script for §1 and §2

Both checks are cheap and belong before any impact claim:

```python
from Crypto.Hash import keccak

def derive_alias(chain_id: str, spender_hex: str) -> str:
    """Matches the protocol's Utils.generateAddress for a 20-byte spender."""
    spender = bytes.fromhex(spender_hex.removeprefix('0x'))
    h = keccak.new(digest_bits=256)
    h.update(chain_id.encode() + spender)          # abi.encodePacked(string, bytes)
    return '0x' + h.digest()[12:].hex()

# CONTROL: verify against an alias you already know from a real withdrawal.
KNOWN = '0xf9692c9feda7f2e503f797dbbf8855caa1ba6422'
assert derive_alias('relay', '0x6747c7e64b90dccc0d54f865cbd9513156adbc0c') == KNOWN
# -> 'packed' encoding confirmed; the enc(string,bytes) variant does NOT match.
```

Encoding note: for this protocol the alias is `keccak(chainId ++ packed_spender)`, **not**
`keccak(abi.encode(string, bytes))`. The two differ, and only the packed form reconstitutes
a known alias — always run the control above before computing a new one.

```python
def find_by_prefix(prefix: str, blocks: list[int]) -> set[str]:
    """Resolve a prefix to full addresses from blocks, not from filtered txlists."""
    found = set()
    for B in blocks:
        r = raw('eth_getBlockByNumber', [hex(B), True]).get('result') or {}
        for t in r.get('transactions') or []:
            for f in ('from', 'to'):
                v = (t.get(f) or '').lower()
                if v.startswith(prefix.lower()):
                    found.add(v)
    return found
```

---

## §4 — Checklist

```text
[ ] is the "victim" a DERIVED alias? (compute it — do not eyeball it)
[ ] does the balance REFILL between movements? (refill => pool/alias, not theft)
[ ] is the writer of the slot named, and is it designed to run constantly?
[ ] if a headline claim was retracted, is the retraction written into the report?
[ ] after "derived alias", did I re-ask who can NAME it and who can SPEND from it?
[ ] was every prefix resolved to 40 hex chars from block-level tx data?
[ ] was any "address not found" backed by a block scan, or only by a filtered txlist?
[ ] did I read owner()/ORACLE()/HUB() per instance rather than reusing a sibling's?
[ ] is there ONE-WAY outflow from an account with no incoming flow? (that is the real signal)
```
