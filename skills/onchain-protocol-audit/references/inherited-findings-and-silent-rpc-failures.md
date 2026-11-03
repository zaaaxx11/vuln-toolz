# Inherited-finding re-validation, dead `eth_getLogs`, and keyless-address freezes

Condensed from a Relay Protocol round (chainId 537713, Hub `0xDDD3…9318`) that opened with a
**brief carrying pre-baked slot numbers and a pre-baked "finding"**. Both were wrong. The
round's real output was four reusable refutation techniques. Read this when you inherit a
prior session's notes, a brief's assumed storage layout, or a "we already found X" claim.

Companion files: `bytecode-disassembly-and-state-override.md` (slot/layout mechanics),
`rpc-census-supply-integrity-and-role-enumeration.md` (§1 error-message-driven method
discovery — this file covers the case where the RPC lies *silently* instead).

**Section list:** §1 the brief's slot table was wrong, and how to catch it · §2 an inherited
"finding" that was a probe artifact · §3 `eth_getLogs` returns `[]` and exits 0 ·
§4 the "succeeds for everyone" probe proves nothing · §5 keyless-address fund freeze ·
§6 un-reproducible EIP-712 domain — report the smell, never claim the exploit.

---

## 1. THE BRIEF'S STORAGE TABLE IS A HYPOTHESIS — re-derive it before any probe

The brief stated `totalSupply = slot 5`, `_isOperator = slot 6`. Both wrong. Truth, proven
two ways (override-and-observe + raw-slot negative control):

```
_isOperator  base 3   (brief said 6)
balanceOf    base 4
allowance    base 5
totalSupply  base 6   (brief said 5)
```

**The two were simply swapped.** Consequence: every override built from the brief's table
writes a slot that means something else — and because both are 32-byte mappings, the write
*lands* (no error), reads back `0`, and you write down a confident negative. Or, worse, it
lands on the other mapping and produces a confident *positive*.

**Cheap discriminator, run before any candidate test:** Mark a sentinel into each candidate
base and ask *the getter you want to influence which base fed it*:

```python
MARK = 0xDEADBEEF
def feeds(base, getter_calldata):
    ov = {C: {"stateDiff": {"0x" + slot(base): "0x" + w(MARK)}}}
    return int(callto(C, getter_calldata, override=ov) or 0, 16) == MARK
```

One call per (base, getter) pair. Session output pinned it in four probes:

```
base 3 -> b6363cf2 isOperator     feeds ✅
base 4 -> 70a08231 balanceOf      feeds ✅
base 5 -> 598af9e7 allowance      feeds ✅
base 6 -> bd85b039 totalSupply    feeds ✅
```

**Rule:** a brief's `(name, slot)` table ships as `UNVERIFIED` in the report until a sentinel
probe confirms each row. Say "brief asserted slot 5; live layout is slot 6" explicitly in
Methodology — it is also evidence the target differs from the docs, which is itself relevant.

---

## 2. AN INHERITED "FINDING" WAS A PROBE ARTIFACT — reproduce before you build

The prior session's notes claimed: *"`allowance` is silently decremented, never enforced as a
cap, so a 1-unit approval moves the entire balance."* It was written up as a **Medium**.

Re-tested against the live contract:

```
allowance = 0,  call transferFrom(victim -> atk, amount > 0)
  -> REVERT: panic: arithmetic underflow or overflow (0x11)
```

`allowed - amount` **underflows and reverts**. The allowance *is* a real cap. There is no bug.

The prior session reached the opposite conclusion because its single probe conflated two
calls: a *reverting* large amount, then a *non-reverting* small one, and it read the second
call's `0x…01` as "the cap was bypassed" when in fact `amount <= allowance` made that call
legitimately succeed.

**The lesson is narrow and mechanical: a `0x…01` return only refutes "blocked" if the amount
you passed actually EXCEEDED the cap.** Any underflow/no-cap claim needs a three-row matrix,
same block, same overrides:

| # | allowance | amount | expected if cap is real |
|---|---|---|---|
| 1 | `0` | `1` | revert (`0x11`) — proves a floor exists |
| 2 | `1e6` | `1e18` | revert (`0x11`) — proves the cap binds |
| 3 | `1e6` | `1e6` | `true` — positive control, proves your harness works |

Row 3 is mandatory. Without it, rows 1–2 reverting could mean your override never landed.

**When you inherit a finding, re-run its exact probe first.** Cost: 5 minutes. Saving: a
retracted Medium in a triager's inbox. Also grep the prior notes for the *words*
"silently"/"never enforced"/"always" — those are the phrases that get written off a single
probe.

---

## 3. `eth_getLogs` RETURNED `[]` AND EXITED 0 — the silent-absence failure mode

On this RPC, `eth_getLogs` returns a well-formed empty array for **every** range, including
`fromBlock: 0x0`, on a chain producing ~1,100 logs per 30 blocks:

```python
rpc("eth_getLogs", [{"address": HUB, "fromBlock": "0x0", "toBlock": "latest"}])
# -> {"jsonrpc":"2.0","id":1,"result":[]}     0 errors, 0 warnings
```

This is worse than an error. `rpc-census…md` §1a covers the case where the RPC *tells* you
(HTTP 400, `response size exceeds limit`, "use `eth_getLogsWithCursor`"). Here it says
nothing, so `try/except: continue` and a bare `result == []` are indistinguishable from "the
contract was never used". Every census built on it reports **0**.

**Working substitute — `eth_getBlockReceipts`, filter client-side:**

```python
def scan(b0, b1, topic0_prefix=None):
    logs = []
    for b in range(b0, b1 + 1):
        r = rpc("eth_getBlockReceipts", [hex(b)])
        for blk in (r.get("result") or []):
            for lg in blk.get("logs", []):
                if topic0_prefix and not lg["topics"][0].startswith(topic0_prefix):
                    continue
                lg["blockNumber"] = int(lg["blockNumber"], 16)
                logs.append(lg)
    return logs
```

30 blocks → 366 `Transfer` events across 206 `(view, holder)` pairs. The data was always
there.

**Detection rule — test the method against a range you KNOW is non-empty before trusting a
zero.** Any of these is a cheap oracle:

```bash
# a block you know emitted something (from an explorer, or the target's own deploy tx)
rpc eth_getLogs '[{"address":"0xTARGET","fromBlock":"0x5D9622","toBlock":"0x5D9622"}]'
# if [] here but the explorer shows logs -> the method is a no-op, not the contract
```

Then confirm `eth_getBlockReceipts` finds them in that same block. **Never write "0 events"
from a single method's empty array** — cross-check with one second method, exactly as
`rpc-census…md` §9 requires for volume numbers. A silent-empty `eth_getLogs` is the same
failure class as a size-capped one, one step harder to notice.

Also cheap and worth trying first on unfamiliar RPCs, in this order:
`eth_getLogs` → `eth_getLogsWithCursor` → `eth_getBlockReceipts` → `debug_traceBlockByNumber`.

---

## 4. A CALL THAT "SUCCEEDS" FOR `0x0` PROVES NOTHING — check for a discriminating probe

`setOperator(op, approved)` was probed as a possible **account takeover**: does it let an
attacker write the *victim's* operator row?

```
from attacker  -> 0x…01 success
from victim    -> 0x…01 success
from 0x000…000 -> 0x…01 success     <-- the tell
```

A zero-address caller succeeding is impossible for any real gate. Both earlier rows are
therefore **not evidence of anything** — the call is shape-valid and writes an
attacker-keyed row regardless of who calls.

**Rule: before reading a success as a bypass, prove the probe discriminates.** For any
"can I act on victim's behalf" hypothesis the probe MUST include a row where the *correct*
answer is failure:

| sender | arg | if the gate is real |
|---|---|---|
| attacker | `operator = attacker` | success (writes own row) |
| attacker | `operator = victim` | **still success** — but writes attacker's row, so this proves nothing |
| attacker | target = victim's own row | need a *state* read afterward, not a return value |

Return values from `setOperator`-shaped setters are useless. The state read is the proof —
and if state can't be persisted (`eth_call` doesn't), pivot to a *second contract* that reads
the state, or to `stateOverride` + a getter on the same slot.

Corollary: writes keyed on `msg.sender` are structurally unreachable for ATO. Verify the
source line passes `msg.sender` into the helper before spending a round on it, and check
explicitly for ERC2771 (`trustedForwarder`, `execute`, `isTrustedForwarder`) plus any
`delegatecall` relay — no forwarder means `msg.sender` cannot be spoofed, full stop.

---

## 5. KEYLESS-ADDRESS FUND FREEZE — the highest-value real pattern in this round

`Utils.sol:24`:

```solidity
function generateAddress(string memory chainId, bytes memory account)
    external pure returns (address virtualAddress) {
  return address(uint160(uint256(keccak256(abi.encodePacked(chainId, account)))));
}
```

Callers (`RelayExecutor.sol:347 _fundSpenderAlias`, `RelayAllocator.sol:260`,
`WithdrawGasPayer.sol:172`) use it to mint a "spender alias" and then **transfer real value to
it**:

```solidity
address spenderAlias = Utils.generateAddress(_SPENDER_CHAIN_ID, abi.encodePacked(address(this)));
if (!HUB.transfer(spenderAlias, tokenId, withdrawAmount)) revert HubTransferFailed(...);
```

`keccak256(...)` truncated to 20 bytes is **not a keypair**. No private key exists for it, so
`msg.sender == spenderAlias` is unforgeable, and (verified) the alias is code-less:

```
eth_getCode(0x6c7d1f98…)  -> 0x     (EOA-shaped, no code to receive/forward)
hub.balanceOf(alias, tid) -> 0
hub.isOperator(alias, atk) -> 0
hub.suspended(alias)      -> 0
```

Any value landing there is **permanently frozen** — no sweep, no rescue selector, no role can
move it (transfer requires `msg.sender == owner`).

**Generalize the check — it is four cheap calls and it catches a whole class:**

```
1. grep the codebase for a derivation helper: keccak/abi.encodePacked -> address, CREATE2 salt
2. for every sink that receives that derived address, ask: does a private key exist?
   - codesize == 0 AND the address is a hash of public inputs  ->  KEYLESS
3. enumerate callers that push value to it (transfer/transferFrom/mint)
4. confirm no rescue path: no sweep/rescue selector, no role that can move another's balance
```

**Severity discipline:** freeze requires the caller path to fire, which here is inside an
oracle-signature-gated `execute()`. So it is **HIGH with prerequisites**, not Critical. The
sentence to write: *"funds sent to `spenderAlias` are unrecoverable; the trigger is gated by
ORACLE_ROLE signature, so this is a design flaw whose blast radius is every completed
withdrawal once reached, not an unprivileged drain."*

Sibling false-positive to rule out first: `rpc-census…md` §5b already documents a
`codesize 0 + nonce 0 + balance 0` address holding ~99% supply — read it as **sink**, and
state both halves (lowers key-theft risk, raises integration risk). §5 here is the *active*
version of the same shape: the protocol deliberately routes value to it.

---

## 6. UN-REPRODUCIBLE EIP-712 DOMAIN — report the smell, never claim the exploit

`PERMIT_TYPEHASH()` matched a non-standard 6-field typehash **exactly**:

```
0x93037fc8…a672 == keccak("Permit(address owner,address spender,uint256 tokenId,"
                          "uint256 value,uint256 nonce,uint256 deadline)")
```

`eip712Domain()` decoded cleanly: `name="RelayHub"`, `version="1"`, `chainId=537713`,
`verifyingContract=0xDDD3…9318`.

But `DOMAIN_SEPARATOR()` = `0x186915e4…795b` while the docs-consistent derivation gives
`0xe62d5bd2…9930`. Brute-forced: 4 name spellings × 3 versions × 3 verifyingContract
candidates × 11 chainIds × with/without `bytes32 salt` × an ERC-712 variant without chainId.
**Zero matches.** Nor was a self-signed permit (`owner == spender == attacker`) accepted under
any of the **720** orderings of the 6 typehash fields — all reverted.

**What to do with this:** it is an *unresolved negative*, and it goes in the report as one.

- State the three facts (typehash match, domain fields, unreproducible separator) with raw
  values. The typehash match is what makes it suspicious rather than a wrong guess.
- Name the two candidate explanations: a separator cached/hard-coded at deploy for a
  different `verifyingContract` or chain, **or** a PUSH32 baked for another deployment.
  If the latter, permits signed for that deployment would verify here — cross-deployment
  replay.
- Explicitly say you could not demonstrate it (no signer key) and therefore **do not claim
  it**. Write `BLOCKED — unproven; follow-up: diff the PUSH32 at the DOMAIN_SEPARATOR return
  site against every Relay Hub on Polygon/Base/Arbitrum.`
- Remember the 720-ordering sweep is also *evidence of absence* for the "wrong field order"
  bug class — say so, it saves the next round.

A brute-force that returns nothing is still a result. Log the search space so the next
session does not re-run it.

---

## 7. INTEGRATION-SURFACE FINDING WORTH ONE LINE IN EVERY ERC20-MIRROR AUDIT

`ERC20View.transfer` / `transferFrom` **return `false`** instead of reverting on failure
(`return hub.transferFrom(...)`), while `transfer(2**256-1)` with a 1e18 balance reverts with
`panic 0x11` (the *inner* arithmetic reverts, but a plain insufficient-allowance path returns
`false`).

Any integrator or contract that only checks "did the call revert" will treat a failed transfer
as success. It is not a theft primitive and does not belong in the critical list — but it is a
real, provable, citable line:

> `ERC20View.transfer` returns `false` on insufficient allowance rather than reverting; callers
> must check the return value.

Verify by calling `transfer` with `amount > balance` under an override and reading the raw
return word (`0x…00`) versus the panic on overflow. Two probes, both instant.

---

## 8. PITFALLS CHECKLIST

- A brief's `(name, slot)` table is a hypothesis. Sentinel-probe each row before any override.
- Swapped sibling slots (5↔6) still "work" — the write lands, reads back 0, and you ship a
  confident false negative. Only a sentinel read catches it.
- Re-run an inherited finding's exact probe. Grep prior notes for "silently" / "never
  enforced" / "always" — single-probe claims.
- An underflow/no-cap claim needs the 3-row matrix (zero-allowance revert, over-cap revert,
  exact-cap success). Without row 3 the harness is unproven.
- `eth_getLogs` can return `[]` with **zero errors** on a busy chain. Verify against a known
  non-empty block; fall back to `eth_getBlockReceipts` + client-side filter.
- A call succeeding for `0x0` proves the probe does not discriminate — discard the whole
  probe, not just that row.
- Setter return values are not authz evidence. Read state through a *second* contract.
- `keccak256(...)`-derived 20-byte addresses are keyless. Any value sent there is frozen
  forever; check for rescue selectors, then grade HIGH-with-prerequisites if the trigger is
  role-gated.
- Un-reproducible `DOMAIN_SEPARATOR` → report as unproven design smell + follow-up. Log the
  brute-force space so it is not redone.
- `transfer` returning `false` > reverting: one citable integration line, not a severity.
- Self-correction goes in the report as its own section, quoting the retracted value. Deleting
  it destroys the audit trail; leaving it un-annotated lets it be re-quoted.
