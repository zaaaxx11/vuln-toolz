# Source ≠ deploy: struct-order drift, dispatcher-entry recovery, and gate probes that actually prove a gate

Condensed from a 53-round Relay Protocol hunt that spent **two full rounds analysing a source file
whose deployed struct layout had the fields in a different order**. Every conclusion built on that
file was invalid; the fix is a 4-command gate that costs two minutes.

Companions: `bytecode-dispatcher-forensics.md` (§2/§3 jump-target validation — the deeper version of
step 2 below), `live-rpc-forensics-and-eth-call-trap.md` §2 (verified-source diff),
`signature-gate-and-verifier-audit.md`, `signed-but-not-bound-authorization-gap.md`.

---

## 1. THE GATE — run before writing any finding that cites a source line

Local checkout is **not** proof of deployed behaviour. Verified-source-on-explorer is not proof the
explorer's source is your checkout. Run all four:

```bash
# 1. ABI diff — methodIdentifiers of the LOCAL source
forge inspect src/Target.sol:Target methodIdentifiers --skip test --skip script

# 2. selector inventory of the LIVE bytecode (dispatcher idiom only — see §2)
#    grep the hex for '8063<sel>1461' / '...1457' / '...1450' patterns

# 3. intersect. live-only OR repo-only ⇒ different build, full stop.

# 4. diff the struct FIELD ORDER, not just the function names
```

### The exact failure that motivates this file

```
source lokal : CallRequest{ Call[] calls; bytes32 transferSpecHash; uint256 nonce; uint256 expiration }
deploy       : CallRequest{ bytes32 transferSpecHash; Call[] calls; uint256 nonce; uint256 expiration }
                                          ↑ fields SWAPPED → different selector
plus         : initializeUsdc(address) exists ONLY in the deployed dispatcher
```

Consequences that follow mechanically:

- `execute(...)` selector computed from the local struct (`0x2ea64c9a`) **does not exist on-chain**.
  Two rounds were spent brute-forcing signatures, then hand-rolling a tuple encoder, before
  `forge inspect` answered in one command.
- Any hand-built calldata from the local layout is garbage — it will revert in a way that looks like
  a security gate and is actually a misencoding.
- Every "the source says X" finding must be relabelled `IN-CODE — deploy parity UNVERIFIED`.

**Label discipline:** two distinct, non-interchangeable claims.

| Label | Meaning |
|---|---|
| `PROVEN — deployed bytecode @ <addr>` | reproduced against live code / live `eth_call` |
| `IN-CODE — deploy parity UNVERIFIED` | true of the checkout only |

Never let the second be written as the first, even when the source is explorer-verified.

## 2. Recover the real ABI from bytecode — dispatcher only, never a bare `PUSH4` sweep

A raw scan for `0x63` + 4 bytes returns every PUSH4 in the file: constant literals, error selectors
buried in revert blocks, function pointers used for external calls. On one contract this yielded
**63 "selectors"**; the real dispatch table had **21 entries**.

The real idiom is a comparison followed by a jump:

```
DUP1  PUSH4 <sel>  EQ|GT|LT  PUSH2 <dest>  JUMPI
```

In raw hex that is `8063<sel4>14 61<dest2> 57` (and `10`/`11`/`12` for the
binary-search pivots on larger contracts). Grep for the pair, not the sel:

```python
import re
txt = code_hex[2:]
entries = []
for m in re.finditer('8063', txt):
    p = m.start()
    sel   = txt[p+4:p+12]
    after = txt[p+12:p+16]
    if after.startswith(('14', '10', '11', '12')):
        entries.append((sel, after))
```

Then resolve names with `forge inspect ... methodIdentifiers` (authoritative, local) rather than
`cast 4byte` (incomplete coverage). **`cast 4byte` misses are unknown, not hidden.**

Bonus signal: the **first** `PUSH4` compared in the dispatcher
(e.g. `80631e1d1b0a14610177`) is usually the most-called function — worth naming first.

## 3. `eth_call` with a bare selector returning `0x` empty revert is NORMAL

Not evidence of absence. solc's dispatcher reverts with **empty** revert data when calldata is
shorter than the function's argument list. An entire round was nearly built on
"everything reverted ⇒ the contract is a stub/delegate" — wrong; the contract was healthy and the
probe was under-length.

**Always batch a positive control against the same address:**

```
owner()            → 0x000…33eb6a49…       ✅ RPC + code healthy
eip712Domain()     → 0x0f00…                ✅
<probe selector>   → revert 0x              ← now interpretable as "needs args"
```

If the control ALSO fails, the harness is broken — fix it before concluding anything. Same rule as
`bytecode-dispatcher-forensics.md` §5 and §9c, applied to argument-less probes.

## 4. GATE PROBES — prove a gate exists without holding the key

The productive primitive for "is this path gated?" when you cannot sign.

```
build calldata with a MAXIMALLY VALID body:
  - attacker-chosen transferSpecHash / nonce / deadline (all plausible values)
  - zero / garbage signature
→ eth_call → read WHICH custom error comes back
```

| Revert | Meaning |
|---|---|
| `InvalidSignature()` `0x8baa579f` | signature gate is the FIRST check and it fired ⇒ path requires the key. **Positive result.** |
| `Unauthorized()` `0x82b42900` | an access check fired first (usually `onlyOwner`) |
| anything else | keep digging — the signature gate may be *after* a weaker check |
| no revert, `0x` result | the body executed for free — investigate immediately |

Encoding: **never hand-roll the tuple.** Write a forge test that calls
`abi.encodeWithSignature(...)` on the real struct and `console.logBytes(cd)` the result. One test
file, always correct, no offset arithmetic to get wrong.

```solidity
struct Call { address to; bytes data; uint256 value; bool allowFailure; }
struct Req  { bytes32 tsh; Call[] calls; uint256 nonce; uint256 expiration; }   // ← DEPLOYED order
bytes memory cd = abi.encodeWithSignature(
    "execute((bytes32,(address,bytes,uint256,bool)[],uint256,uint256),bytes,bytes,bytes)",
    req, hex"00", hex"00", hex"00");
console.logBytes(cd);
```

## 5. Reading an `onlyOwner` gate straight out of bytecode

Solady `Ownable` fingerprint — proves `onlyOwner` even with no source, no verified ABI:

```
638b78c6d8   PUSH4 0x8b78c6d8        ← OWNER_SLOT constant
1954         SLOAD
3303         CALLER
…   SUB
6382b42900   PUSH4 Unauthorized()
5f526004601cfd   PUSH0 MSTORE; PUSH1 04; PUSH1 1c; REVERT
```

Grep the code hex for `6382b42900` and read the ~45 bytes before it. Finding `8b78c6d8 … 54 … 33 …
90 3` immediately preceding an `Unauthorized()` revert block **is** the proof. No `eth_call` needed
beyond confirming the same error live.

Corollary: `0x8b78c6d8` appearing in a naive `PUSH4` harvest is the OWNER_SLOT constant, **not** a
function — do not report it as a selector.

## 6. Locating a live contract that no doc names

Backend probes returning 404 / stub do not mean the contract is absent. Derive it from traffic:

```python
# 1. token transfers into a known wallet
logs = eth_getLogs(Transfer, topics=[TR, None, padded(wallet)], fromBlock, toBlock)
# 2. per log: tx = eth_getTransactionByHash; collect (tx.from, tx.input[:10], tx.to[:10])
Counter((f, sel, to10)).most_common()
# 3. the MINORITY pattern with an unexpected `to` is the contract you want;
#    then re-fetch one tx for the full 40-hex `to`.
```

That is how a second depository implementation was found after 51 rounds of assuming only one existed.
Bound the window (5k blocks per `eth_getLogs` call) and cap the loop — a block-by-block
`eth_getBlockByNumber(full)` scan over thousands of blocks will time out first.

## 7. Contract-identity corroboration (cheap, do it every time)

Match the deployed custom-error selectors against the local source's error declarations. A hit on
several at once (`Unauthorized()`, `InvalidSignature()`, `CallFailed(bytes)`,
`GatewayAttestationSetsNotSupported()`, `InvalidGatewayAttestationEncoding()`) plus matching event
topic0 is strong evidence the deployed build is the same *code family* even when the struct order or
an init function diverges. Report the divergence and the corroboration together — they are not in
conflict.

An **unmatched** error selector is still usable evidence: read it from the revert block in the
bytecode instead of guessing names. A 40-word brute of `Name(args)` variants usually misses and
costs more than reading the 20 bytes around the `PUSH4`.

## 8. Event-parameter trust (a real class, found this way)

`depositErc20` on the target emits `RelayErc20Deposit(depositor, token, amount, id)` where `amount`
comes from the **call parameter**, not from a `balanceOf` delta — while the transfer uses
`safeTransferFrom` which only checks the return value / success flag. A token whose `transferFrom`
returns `true` without moving funds, or a fee-on-transfer token, makes the event claim more than
arrived.

Proven with a forge test (fake token returning `true` with 0 movement → event says 1,000,000, balance
delta 0; fee token 10% → event 1,000,000, balance 900,000). **But it is `EXTERNAL-DEPENDENT`, not
`EXPLOITABLE`:** whether it is a bug depends on whether the off-chain credit engine reads the event
or the balance. If the backend is unreachable, label it `MEDIUM — external-dependent, UNPROVEN` and
say exactly what evidence is missing. Do not inflate it to HIGH because the PoC is clean.

Same pattern to look for anywhere: **event fields sourced from caller-supplied parameters rather
than measured state.**

## 9. Round hygiene that this hunt earned

- **Overlapping `eth_getLogs` windows duplicate rows.** Always dedup by `(txHash, logIndex)` — or at
  minimum `(tx, id)` — before computing uniqueness. A "duplicate event id ⇒ ID reuse" lead turned out
  to be one log counted twice by two overlapping ranges. Verify with `blk` **and** `tx` equal before
  calling it a collision.
- **`id = 0` succeeding is `LOW in-code`, not a finding by itself.** Three deposits with
  `id = 0x00…00` from a single test EOA proves the field is unvalidated; it does not prove replay,
  because the credit engine's dedup behaviour is off-chain.
- **`eth_call` that does not revert proves neither state change nor event emission** — only that the
  path is reachable. Say "reachable", not "succeeds".
- **A single shared `isValidSignatureNow` across N contracts is one custody risk, not N bugs.**
  Report it once as key-custody (F-16 class), and do not re-file it per contract.
- **After 50+ rounds with 0 no-key path, say so plainly.** "Every value-moving path requires
  `allocator.isValidSignatureNow`; single point of failure = the allocator key; no code bug found" is
  the honest deliverable. Never manufacture a HIGH to close a long hunt.
