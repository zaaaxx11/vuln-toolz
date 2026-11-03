# Selector & getter-form traps — the family that manufactures "this function is missing"

Five distinct wrong conclusions in a single round, all from the **call shape**, never from the target.
The tell is always the same: a probe reverts or returns zero, and the tempting reading is
"the contract lacks this function / this value is zero".

---

## 1. Role hash ≠ role getter selector

```text
ADMIN_ROLE()      selector = 0x75b238fc        -> returns 0xa4980720…1775
OPERATOR_ROLE()   selector = 0xf5b541a6        -> returns 0x97667070…b929
```

The 32-byte value (`0xa4980720…`) is what `hasRole(bytes32,address)` takes as its **argument**.
Sending it as `eth_call` **calldata** hits a nonexistent selector and reverts.

Why this is dangerous and hard to notice:
- `hasRole(0xa4980720…, addr)` **works perfectly** — the hash is correct as an argument.
- So every role *check* in the campaign was valid, while every "does this Hub expose ADMIN_ROLE?"
  probe was silently bogus. A clean-looking result built on a fake call shape.
- Whole false hypothesis it produced: *"Hub#2 is missing 17 functions including balanceOf"* —
  every one of those probes was sending hand-built calldata to a selector that was never a function.

Rule: **the selector is `keccak("NAME(types)")[:4]`. The role hash is the getter's RETURN value.**
Never interchange them. Compute selectors from the explorer ABI, mutate nothing.

## 2. Argument-type mismatch — the getter exists but the shape is wrong

```text
erc20Views(bytes32)  -> revert   (looks absent)
erc20Views(uint256)  -> 0x…ed     (exists, both hubs)
```

`RelayExecutor`'s nonce really is `bytes32`; `RelayHub`'s token id really is `uint256`.
Guessing the wrong one on a *getter* looks identical to a missing function.

Procedure that closes it in one step: **fetch the ABI from the explorer, derive selectors
mechanically, never type them.**

```python
abi = json.loads(getabi(address)["result"])
for f in abi:
    if f["type"] != "function": continue
    ins = ",".join(i["type"] for i in f["inputs"])
    print("0x" + keccak(text=f"{f['name']}({ins})")[:4].hex(), f["name"])
```

Then diff the selector **sets** of the two instances. Set equality is the cheap proof that
"different byte length ⇒ different feature set" is false.

## 3. Same ABI + different byte length = different BUILD, not different feature set

```text
Hub#1 13864 B  sha e8460ce8      36 functions / 8 events / 11 errors
Hub#2 13507 B  sha 6860f552      36 functions / 8 events / 11 errors   IDENTICAL
common prefix 10 B, common suffix 65 B, neither contains the other
```

- Equal ABI ⇒ no missing entrypoint; stop looking for a feature delta.
- 10-byte common prefix ⇒ **not** an immutables-only patch (that leaves a long prefix). Two
  separate compilations, or a source change that preserved the interface.
- Therefore: do **not** claim "Hub#2 is the older/weaker version". Claim only what is measured —
  interface identical, runtime divergent, behaviour unverified per-function. Anything further
  needs a per-function differential, not a byte-length comparison.

Also: do not read a solc version out of the trailing bytes unless you have parsed the CBOR
metadata properly. `int.from_bytes(code[-2:],'big')` yields nonsense (`47401`) and is **not** a
metadata length — it is two arbitrary opcode bytes. A fabricated provenance datum is worse than
none (SKILL.md pitfall 29).

## 4. Truncated topic preview reads as "zero address"

```python
[x[:12] for x in log['topics']]
# ['0xb3fd507183', '0x0000000000', '0x0000000000', '0xa403fbe654']
#                    ^ trimmed prefix of a REAL address
```

`0x0000000000` is what a truncated left-pad **looks like**. It is not a zero value.
This nearly became the finding "owner and spender are both address(0) ⇒ malformed Approval event".

Controls that settle it in one line:
```python
sum(1 for L in logs if int(L['topics'][1],16) != 0)   # -> 1289/1289 non-zero
set(len(L['topics']) for L in logs)                   # -> {4}
set(len(L['data'])   for L in logs)                   # -> {66}
```

Rule: **never display a truncated hex field as evidence.** Print `len()`, `int(…,16)`, or the
full 32 bytes. A preview is for human scanning only, never for a verdict.

## 5. Two contracts, one shared token: name the ACTIVE one from limits, not from a pointer

```text
XERC20 0xb1d88ca1…
  .lockbox()          -> 0xaa6ff104…          (looks authoritative)
  .mintingMaxLimitOf(0xaa6ff104…) -> 0           <- DEAD
  .mintingMaxLimitOf(0xe1b402a9…) -> 2**255-1    <- ACTIVE, and it is not the pointer target
ERC20 behind active lockbox  = arbitrum-USDC
ERC20 behind pointer target  = arc-gateway-USDC      (reserve 273,418,775, limit 0)
```

Getters lie by omission: `lockbox()` returns a configured address, not a functional one.
The **rate-limit numbers** are what tell you which path can actually move value.

Cross-token drain hypothesis: `_withdraw` calls `XERC20.burn(msg.sender, amount)` then
`ERC20.safeTransfer(_to, amount)` — the XERC20 does not know *which* lockbox burned, so a
deposit on one lockbox and withdrawal on another would swap assets. Refuted only because the
second lockbox has limit 0. Check the limits of **every** lockbox holding the same XERC20 before
declaring the surface dead, and again before declaring it exploitable.

Closing probes for this class (all cheap, all `eth_call`):
```text
setLimits(...)   -> "Ownable: caller is not the owner"   (plain string revert = readable)
setLockbox(...)  -> 0x2029e525                            (custom error: decode from ABI)
mint(addr,1e18)  -> 0x0b6842aa                            (rate-limit/NotBridge, NOT AccessControl)
```
`mint` reverting with a **limit** error rather than `AccessControlUnauthorizedAccount` tells you
the gate is a per-bridge rate limit, i.e. a different (and weaker-looking but real) control.
Name the gate, don't just say "it reverts".

## 5b. THE TRUNCATED-WORD FAMILY — `r[2:66]` is right for a 20-byte address and WRONG for a 32-byte word

`eth_call` returns a left-padded word. One slice offset cannot serve both shapes, and the wrong
offset does not error — it returns a **plausible-looking shorter value** that you then treat as the
answer. Two live instances in one session, both from `r[2+24:66]` (correct for `address`,
silently drops 6 bytes off a `bytes32`):

```text
ADMIN_ROLE()    reported 0xa18f56e8913cf4a201fbe287825b095693c21775   (20 B — IMPOSSIBLE, role hashes are 32 B)
                actual   0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775
getRoleAdmin(x) reported 0x000…000 for EVERY role                     (artefact of the same bad slice)
                actual   0xa4980720…  = ADMIN_ROLE   <- self-admin, the whole finding
hasRole(ADMIN, 0x71d8be89) reported 0  -> "owner has no role"
                actual                    1  -> owner is the SOLE ADMIN                          (after fix)
```

**Self-check that catches it every time: print `len(hex)-2` next to the value.**

```python
def w0(r):                        # full word, no assumptions
    return "0x" + r[2:66]         # 64 hex chars = 32 bytes
assert len(w0(r)) - 2 == 64, f"word is {len(w0(r))-2} hex, expected 64"
```

- `address` return ⇒ the value lives in the **low** 20 bytes; `"0x" + r[2:66][-40:]`.
- any `bytes32`/`uint256` return ⇒ the whole 64-char word; **never** apply a 24-char skip.
- A role hash, a selector-adjacent getter, or any 32-byte constant coming back as 40 hex chars is
  definitionally your bug, not the chain's. Same rule as §4: a value you displayed to yourself is
  not evidence until its **width** is checked.
- Worst case is the one above: the truncation made `hasRole` read `0` for a real holder, which
  argued *the opposite* of the truth (\"owner has no power\" vs \"owner is the only power\").

## 5c. Block-scan arithmetic: a binary search that can return its own lower bound

Locating a contract's deploy block with
`lo,hi = 2_800_000, tip; while lo<hi: …` returns **`lo` unchanged when code already exists at the
lower bound** — a number indistinguishable from a real answer, after which a log scan of the wrong
range reports `0 logs` with total confidence.

```text
deploy block: 2800000        <- exactly lo. NOT a measurement.
total RoleGranted: 0         <- scanned blocks 2.80M–2.83M, the contract was elsewhere
```

Rules:
- Seed the search with a lower bound you have **verified has no code** (`eth_getCode(addr, hex(lo))
  == "0x"`), or take the deploy block from the explorer's txlist/creation tx.
- Cap the search span before running: `(hi-lo)/step` queries. A 2.8M→6.16M scan at 20k windows is
  ~170 queries **per topic filter**; six filters = 1,014 requests and a guaranteed timeout. Compute
  the count first, and if it exceeds ~50, change method (explorer `txlist`), don't raise the timeout.
- `0 logs` from an unverified range is **not** evidence of absence. If the range itself is
  unproven, the result is void — same class as pitfall 17 (instrument, not observation).
- Prefer the direct question. \"Who holds this role?\" is `hasRole(hash, candidate)` over a short
  candidate list (deployer, both executors, both oracle owners, both admins) — a handful of
  `eth_call`s, no scan, no range assumption. Log mining is only needed for \"who held it *historically*\".

## 6. Helper-contract allowance: read the guard, and read the exemption branch

`ERC20View.transferFrom` really does check allowance (`L207-222`), so "anyone can pull via the
view" is dead — but the branch matters:

```solidity
if (msg.sender != from) {
  uint256 a = hub.allowance(from, msg.sender, tokenId);
  if (a < type(uint256).max) {          // <- infinite approval SKIPS the decrement
    if (a < value) revert ERC20ViewInsufficientAllowance(...);
    hub.approveFor(from, msg.sender, tokenId, a - value);
  }
}
hub.transferFrom(from, to, tokenId, value);   // passes because erc20Views[id] == msg.sender
```

So the residual question is never "is there a guard" but **"does any victim hold an infinite
approval to an address an attacker can act through"**. State that as the remaining condition;
do not re-report "no allowance check" once the check is found.
