# Proving a ROLE-FREE / SIGNATURE-FREE value channel (or proving none exists)

Condensed from a Relay Protocol (Hub/Executor/Allocator/Oracle) engagement whose
brief was: *"find a contract-side second channel that moves value WITHOUT a fresh
oracle signature and without any role — test every candidate live, label
PROVEN/DISPROVEN with raw output."* Final result: **no such channel; 7 candidates
DISPROVEN, 1 BLOCKED by an on-chain fact.** The value of the run was the negative
being *credible*, not the finding being exciting.

Read this when the ask is an authorization-shape question ("is there any path
that skips the gate?") rather than a specific bug hypothesis.

---

## 1. Frame it as a role-free REACHABILITY question, not a bug hunt

The deliverable is a matrix. Build it before testing anything:

```
value-bearing contract(s)  x  every external/public function  ->  gate required
```

For each function record exactly one gate class:

| Gate class | How to confirm live |
|---|---|
| `onlyRole(X)` / `onlyOwner` | call it as attacker, expect `AccessControlUnauthorizedAccount`/`Ownable` |
| signature (ECDSA / EIP-1271) | call with `0x`+130 zero bytes, expect `InvalidSignature` not success |
| self-binding (`msg.sender == arg`) | call with a real victim as arg from attacker |
| operator/allowance relationship | `isOperator(victim, attacker)` → must read `false` |
| **NO GATE** | only claim this after a *positive* call returns value |

Then rank candidates by "could an attacker reach the value-mover with `msg.sender`
being themselves?" A function that is unguarded but that only moves
`balanceOf[msg.sender]` is **not** a channel — it is a self-service no-op. Say so
plainly instead of writing it up.

### The single most important distinction

```
moves OTHER accounts' value  +  no gate   => critical
moves CALLER's own value     +  no gate   => not a finding
```

`Hub.transfer()` is gate-free and moves value; it moves *your* value. That is the
whole reason the second channel does not exist. State this explicitly, because a
reader who sees "unguarded function that moves value" will otherwise think you
found it.

---

## 2. A reverted `eth_call` is a NEGATIVE result, not a PROOF

Geth/erigon return `{"code":3,"message":"execution reverted"}` with **no revert
data** by default. That means you cannot tell *which* of five guards fired, and
you cannot claim "the signature check rejected me" — you can only claim "the call
did not succeed."

Consequences for the writeup:

- **PROVEN needs a successful call that visibly moved value** (balance delta,
  `true` return, or the getter changing under override). A revert never proves a
  positive.
- **DISPROVEN needs a control that shows the calldata was well-formed.** If both
  your attack call *and* your control revert, you have proven nothing — you have
  probably encoded the struct wrong. See §3.
- When `debug_traceCall` is unavailable, get the revert reason another way:
  compare against a **deliberately-unauthorized** variant (attacker instead of the
  real role holder). If both revert identically, you learned nothing about
  ordering — go read the source (`grep -n "function\|onlyRole\|msg.sender"`) and
  cite the source line for the guard, while still labelling the live test as
  "did not succeed" rather than "blocked by guard X".
- Always send a generous explicit gas (`0x2dc6c0` = 3,000,000) so `OOG` cannot be
  confused with a revert.

## 3. Encoding traps that manufacture fake DISPROVENs

Two of them cost real rounds here:

1. **Tuple-literal parsing in `cast calldata`** — `cast` cannot parse `('relay',
   ('relay',0x,0x54,…))`; it errors on the bare `0x`. Symptom: empty calldata and
   a revert that looks like an authz failure. Fix: ABI-encode the members and
   concatenate manually, or use `cast abi-encode "f(<types>)" args` then prepend
   the selector:
   ```python
   payload = cast_abi_encode(["string","bytes","bytes","uint256","string","bytes","bytes","bytes","uint256"], vals)
   calldata = sel + payload[2:]
   ```
2. **`cast tx --json` / `cast receipt --json` shape drift** — some versions wrap
   output as `{schema_version, success, data, errors, warnings}` so `d["input"]`
   raises `KeyError`. Do not fight it; use raw JSON-RPC:
   ```python
   rpc("eth_getTransactionByHash", [tx])["result"]["input"]
   rpc("eth_getTransactionReceipt", [tx])["result"]["logs"]
   ```
   Also note `cast 4byte <selector>` and `cast calldata-decode` are cheap ways to
   identify an unknown entrypoint before reading any source.

## 4. Mined-by-construction dead ends: check for them before testing

Before spending calls on a candidate, verify its **precondition exists on this
chain at all**. In this session:

- `payloadBuilders["relay"][depository] == 0x0` (live getter) ⇒ the entire
  `submitWithdrawRequest → HUB.burn` path reverts `NoPayloadBuilder` **before**
  the authorization check ever runs. Any "test" of that path is testing a
  nonexistent deployment, not a guard. Verdict: `BLOCKED by absent dependency`,
  which is different from DISPROVEN and must be labelled differently.
- `hasRole(ORACLE_ROLE, oracleContract) == false` — the *contract* is not the role
  holder; the 2-of-5 multisig is. Querying the wrong subject would have made the
  signature gate look bypassable.

Pattern: for each candidate, enumerate the runtime-only facts it depends on
(payload builder set, role held by X, token exists, allowlist populated) and read
them with a getter first. A missing precondition is an *absent* attack surface,
not a *hardened* one — and conflating the two is the most common way a report
gets inflated.

## 5. Report shape that survives triage

Per candidate, one block, no prose padding:

```
## C<n> — <one-line claim>  →  PROVEN / DISPROVEN / BLOCKED

Surface (source): <file:line> gate = <exact expression>
Test:             <exact calldata / override used, gas, from>
Raw:              <verbatim JSON-RPC result or return hex>
Control:          <the call that proves the test itself is well-formed>
Verdict:          <one sentence, names the gate that fails>
```

Non-negotiables:

- **Control line is mandatory.** Without it every DISPROVEN is unfalsifiable.
- **BLOCKED ≠ DISPROVEN.** Missing dependency ⇒ BLOCKED; present guard that
  rejected you ⇒ DISPROVEN; only a successful value-moving call ⇒ PROVEN.
- Put the harness validation (control contract + real-slot override proof) in a
  **Methodology** section up front. That section is what makes a wall of
  DISPROVENs credible instead of lazy.
- Write the file **incrementally** as candidates finish. A long sweep can be cut
  off mid-run (it was, at iteration limit) — evidence that only exists in the
  transcript is evidence lost. Append each verdict with its raw output the moment
  it is observed.

## 6. Pitfalls checklist

- "Unguarded function that moves value" is usually self-service. Check *whose*
  balance moves.
- A blank `execution reverted` is not attribution of a guard.
- Both-sides-revert ⇒ your encoding is broken, not the target hardened.
- Confirm the precondition exists live before testing the guard.
- Per-address `cast call` loops time out; batch via `eth_getLogs` + one curl helper.
- Override values must be 32-byte padded, and the address-keyed **object** form is
  the one some nodes accept. Prove override with a control contract first.
- Label BLOCKED separately from DISPROVEN. Do not upgrade a blocked path to a
  finding, and do not downgrade a genuine guard rejection to "probably fine".
- Deliverable is a matrix of gate classes, not a narrative.
