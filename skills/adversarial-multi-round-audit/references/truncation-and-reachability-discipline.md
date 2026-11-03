# Display truncation vs. probe input — and proving a capability you cannot reach

Two failure classes from the round that finally *proved* a global-operator
bypass. Both are self-inflicted; neither is caught by re-reading the reasoning,
because the reasoning was correct and the numbers were printed that way on purpose.

---

## §1 — A TRUNCATED PRINT IS NOT AN IDENTIFIER (this cost two rounds and one retracted headline)

A `256`-bit `tokenId` was printed as `tid%10**12` to keep the table narrow. That is a
fine *display* choice. It became a data bug when the printed value was copy-pasted
back into the next round's probe script as the token id.

```python
# R27 — display only, never intended to be read back
print(f'  tid={tid%10**12}  victim={v:,}  supply={sup:,}')

# R28 — the truncated value became an INPUT. Not the real tokenId.
CANDS = [245435211328, 309620547462, 294071515448, ...]   # copied from the table above
for tid in CANDS:
    balanceOf(VICTIM, tid) == 0  for all six   ->  "victim holds nothing"
```

The "victim holds nothing" conclusion was published. It was **false**. Re-running with
the ids harvested from calldata (`w[1]` read as a full 256-bit word) gave six funded
tokens totalling ~6.36e9 units. The retraction had to be issued mid-report.

```text
WRONG (truncated id as input):  6/6 balanceOf == 0  -> "no funds"
RIGHT (full 256-bit id):        6/6 non-zero        -> ~6.36e9 units held
```

### §1b — THE WORST VARIANT: completing a truncated 20-hex address with invented hex

The same discipline, applied to addresses instead of tokenIds, and this one produced a
fully-formed **fictional EOA** that returned real-looking answers.

```python
# census print — correct display, keeps the table narrow
print(f'    blk {b:>9,} grant OPERATOR -> {ac}  by {frm[:12]}')
#             ^ full account printed          ^ sender TRUNCATED to 10 hex

# next round — the truncated prefix became an "address"
ROOT = '0xf3d63166f0cad3b8b7f5f2b3ff0d05a5a0b9a3d5'      # INVENTED TAIL
eth_getCode(ROOT)    -> '0x'        (no code — reads as "EOA")
eth_getTransactionCount(ROOT) -> 0  (reads as "dormant key, never used")
eth_getBalance(ROOT) -> 0           (reads as "abandoned")
```

Every one of those three answers is a **valid response from the RPC for an address that
does not exist**. The conclusion drafted from them — *"there is a ROOT key sitting at
nonce 0, dormant"* — was one sentence away from publication. The real sender,
re-fetched from the explorer's full `from` field, was
`0xf3d63166f0ca56c3c1a3508fce03ff0cf3fb691e` with **nonce 911** and 49 contract
deployments.

```text
TRUNCATED + INVENTED TAIL : nonce 0, 0 tx, 0 ETH      -> "dormant root key"
REAL ADDRESS (full fetch) : nonce 911, 49 deploys     -> "the deployer, handover clean"
```

Why this class is more dangerous than a modulo: a `%`-mangled tokenId returns *zero
balances* (an obviously suspicious result). A synthetic address returns the **exact
profile a dormant/air-gapped key would have** — nonce 0, no code, no balance. The
fabrication is **corroborated by the chain** instead of contradicted by it. There is no
internal-consistency alarm to catch it.

```text
RULE  never pad, never complete, never "fill in" a truncated address. 10 hex is not an
      address, it is a prefix; the only legitimate source of the other 30 is a fetch.
RULE  an address that answers nonce=0 AND code=0x AND balance=0 is NOT evidence of a
      dormant key. It is equally consistent with a typo. Disambiguate by re-fetching
      the address from an authoritative artifact (explorer `from`/`to`/`contractAddress`
      field, a receipt, or calldata) — never by adding hex yourself.
RULE  verify the identity of any literal 42-character string you are about to call an
      actor: len(x)==42, x[:2]=='0x', and x in the set of addresses the explorer returned.
RULE  any truncation of an ADDRESS must print an ellipsis AND the full value to a
      JSON sidecar in the same breath (§1 above), because a prefix is far more
      tempting to "finish" than a modulo'd integer.
```

### Rules

- **Display formatting must be visibly lossy.** If a value is truncated for the table,
  print it with an explicit marker and keep the full value in a JSON sidecar:
  ```python
  print(f'  tid=0x{tid:064x}'[:22] + f'…  victim={v:,}')   # note the ellipsis
  json.dump({str(t): v for t, v in have}, open(f'/tmp/r{n}/balances.json','w'))
  ```
  An ellipsis is a stop sign for the next round. `tid%10**12` is not — it looks like
  a complete number.
- **Never re-enter a value that came out of a `print()`.** Inputs come from a fetch or
  from a JSON artifact written by a fetch. This is Rule 12 (placeholder provenance)
  wearing a disguise: the literal *did* trace to a fetch once, then got mangled on the
  way through the terminal.
- **`%` on an identifier is fabrication.** `%`, `//`, `[:12]`, `int(...[:18],16)` applied
  to a tokenId / hash / address all produce a valid-looking value that will be accepted
  by the RPC and return a real, meaningful, wrong answer.
- **Correction protocol:** when a retired claim is found to rest on a truncated input,
  retract it in the same breath as the fix, state the exact mechanism, and do not
  substitute a fresh "correct" number without re-deriving it from a fetch in that same
  run. A retraction followed by an unverified replacement is worse than the retraction.

---

## §2 — PROVING A CAPABILITY ≠ PROVING REACHABILITY (label the chain, don't inflate or bury it)

The strongest result of the campaign, and the one most likely to be mis-graded in
either direction.

```text
isOperator(<ANY account>, Executor1) == 1     for 10/10 probed accounts,
                                              including address(0) and 0x…dead
isOperator(VICTIM, <anyone but Executor1>) == 0   10/10
=> isOperator discards its `account` argument entirely when hasRole(OPERATOR_ROLE, operator)

transferFrom(VICTIM -> 0xcafe, 1)
  from = VICTIM        -> OK        (positive control, ALIVE)
  from = 0xcafe        -> Panic     (rejected)
  from = Executor1     -> OK        *** value moved ***
  from = Allocator2    -> Panic     (rejected)
```

Two real results, **two different claims**, and the campaign nearly merged them into
one CRITICAL:

| claim | status | what it means |
|---|---|---|
| A. `isOperator` is globally privileged; `transferFrom` from that operator moves a third party's balance | **PROVEN** (differential with live positive control, value observed moving in `eth_call`) | the defect is real |
| B. an attacker can reach that path | **UNPROVEN** | `msg.sender` must *be* Executor1; the attacker cannot become it |

**This is `ARMED-BY-FUNDING`/capability, not an exploit, until B is answered.** Report
both lines, labelled, every time. Do not demote A because B failed; do not promote A
because the differential was clean.

### How to close B (the reachability half)

The question is never "is the capability there" — it is **"is there a caller-reachable
function whose internal `msg.sender` is the privileged contract"**. Enumerate:

```python
# every function on the privileged contract, with mutability — no guessing
for f in abi:
    if f['type'] == 'function':
        print(sel(f), sig(f), f['stateMutability'])
```

Then for each `nonpayable` entrypoint, grep its body for the value-moving sink:

```text
grep -n 'transferFrom|\.transfer\(|\.burn\(|_fundSpenderAlias' src_exec.sol
```

In this campaign the sink scan was decisive and cheap: Executor1's ABI is 16 functions
with exactly **one** non-view entrypoint (`execute`), and every `HUB.transfer(...)` in
its body passes `address(this)` as the implicit sender — `transferFrom` appears **zero**
times. That asymmetry (a working `transferFrom` capability on the Hub, and *no caller*
in the privileged contract that invokes it with a foreign `from`) is the honest
BLOCKED/UNPROVEN label.

```text
sink reached with attacker-chosen `from`  -> escalate to CRITICAL, build the fork PoC
sink reached, `from` pinned to address(this) -> capability is inert; label and stop
sink absent entirely                        -> say so; the differential was a capability
                                               demo, not a finding
```

### Adjacent surface worth one call before closing

When a permission map exposes `setOperator` / `setOperatorFor` / `grantRole`, probe
whether a *non-privileged* caller can set itself as operator for a victim. If it can,
B collapses into A and the chain closes:

```python
# 0xcafe attempts to make itself operator FOR the victim
eth_call(from=CAFE, to=HUB, data=sel('setOperatorFor(address,address,bool)')
         + pad(VICTIM) + pad(CAFE) + W(1))
# OK / no AccessControl selector  -> CRITICAL path exists
# AccessControlUnauthorizedAccount 0xe2517d3f -> correctly gated, chain stays BLOCKED
```

---

## §4 — A non-reverting setter is NOT a finding until you have read its body

The `setOperatorFor` probe above (gated, chain stays BLOCKED) was immediately followed
by a **second** setter that returned `OK` from the attacker address, and that `OK` was
briefly announced as "CRITICAL".

```solidity
// RelayHub.sol:216-221 — note: there is no `account` parameter at all
function setOperator(address operator, bool approved) public returns (bool result) {
  return _setOperatorFor(msg.sender, operator, approved);
  //                       ^^^^^^^^^^ first argument is ALWAYS msg.sender
}
```

Probe result and its three possible readings:

```text
probe : setOperator(VICTIM, true) from=0xcafe   -> OK (no revert)
naive : "CAFE granted itself over VICTIM"        -> CRITICAL (WRONG)
real  : "CAFE made VICTIM an operator over CAFE" -> harmless, and the reverse
                                                      of what was claimed
```

The tell that was ignored for one exchange: `setOperatorFor(VICTIM, CAFE, true)` from
**VICTIM itself** also reverted with `AccessControlUnauthorizedAccount`. A function that
the victim cannot call on itself is role-gated, not owner-gated — the "self" control was
mis-designed, and its failure was nearly filed as a protocol anomaly.

```text
RULE  read the body to the closing brace BEFORE interpreting any successful eth_call
      on a state-mutating function. Confirm which parameters exist and which are
      replaced by msg.sender / address(this).

RULE  if your positive control reverts, the probe set is VOID — not evidence of a
      finding and not evidence of an anomaly. Pick controls from the actual role
      census, never from "the victim should be able to do this to itself".

RULE  a setter's parameter list IS the vulnerability surface. `setOperator(address,bool)`
      cannot be an escalation primitive; `setOperatorFor(address,address,bool)` can.
      Check arity before arity-adjacent reasoning.
```

What the gated probe legitimately bought: `setOperatorFor` is `onlyRole(OPERATOR_ROLE)`,
so no attacker can manufacture a per-account operator grant. Combined with the global
`isOperator`, that narrows the entire severity question to **"who holds OPERATOR_ROLE"** —
which the role census answers, and which is where §2's grading table lives.

### §4a — grade by holder count, and let the census do it

```text
census: hasRole(OPERATOR_ROLE, X) over every address seen so far
        1 holder, a contract with no caller-reachable transferFrom  -> HIGH (inert capability)
        1 holder that IS a caller-reachable router                    -> CRITICAL
        any EOA holder                                               -> CRITICAL
```

The severity of a capability finding is not a property of the bypass — it is a property
of the holder set. Never finalise a grade before the census row exists.

---

## §5 — A RECORDED FACT IS NOT A LIVE FACT (re-verify the thing you are building on)

Two consecutive rounds, two claims that each rested on a value established **earlier in
the campaign** and never re-measured:

```text
claim  "Hub#2 has no ORACLE_ROLE holder — all 8 candidates returned False"
       -> implied "the oracle lane is provisionally dead", left open as a thread

truth  the question was malformed. getRoleAdmin(ORACLE_ROLE) on that hub returns
       UNKNOWN — the role was never SET UP there at all
       => hasRole(_, ORACLE_ROLE) is structurally always false
       => execute()/executeMultiple() always revert UnauthorizedOracle
       => the lane is closed by CONSTRUCTION, not by "no candidates matched"
```

A `False` from `hasRole` means "this account lacks the role". It does **not** mean "the
role is unassignable". Those are different verdicts, and only the second one closes a
lane. One extra call (`getRoleAdmin(ROLE)`) converts a weak "all candidates False"
negative into a structural "role undefined ⇒ gate can never open" proof — a much
stronger and permanent result.

```text
WEAK    hasRole(ROLE, x) == False  for x in {8 candidates}   -> "no holder found"
STRONG  getRoleAdmin(ROLE) == UNK (role unregistered)         -> "gate unopenable"
        getRoleAdmin(ROLE) == ADMIN  + hasRole(ADMIN, A)     -> "A can manufacture a holder"
```

**Always run the role-admin chain before concluding anything about a role gate.** It
also answers the escalation question in the same request: if `getRoleAdmin(TARGET) ==
ADMIN` and `hasRole(ADMIN, K)` is true, then **K can self-grant TARGET** with one tx —
which is a severity input, not a footnote.

```python
# the three calls that decide a role gate, in order
getRoleAdmin(ROLE)            # UNK -> gate unopenable; ADMIN -> find a self-grant path
hasRole(ROLE, candidate)      # who holds it NOW
hasRole(ADMIN, candidate)     # who can MAKE a holder
```

Same failure mode on the custody question: a newly discovered admin was graded before
anyone checked whether the original deployer still held the role. When checked, the
deployer had **zero** remaining authority (ADMIN False on both hubs, no `owner()` on any
of 10 core contracts, balance drained) — so the story was a clean **handover**, not two
live root keys. Both the "root still holds admin" claim and the "ROOT key dormant" claim
from §1b were retracted in the same round.

```text
RULE  re-verify, in the current round, every fact a new claim depends on. Prior-round
      values are leads, not premises. "Established last round" is not a source.
RULE  a negative from hasRole is ACCOUNT-SCOPED. Only getRoleAdmin closes a GATE.
RULE  when a new privileged actor appears, measure the OLD one's remaining authority
      before writing "two roots" or "handover" — roles, owner() on every core contract,
      and balance. Handovers are the normal case.
RULE  state which of the two you proved:
        "no holder exists"          -> account census only
        "role cannot be assigned"   -> structural, gate closed
```

---

## §6 — A SAVED "VERIFIED SOURCE" FILE CAN BE A TRUNCATED HALF (the worst integrity bug of the campaign)

Distinct from §1b: no value was mangled here. The *file* was incomplete, and every
conclusion drawn from it was drawn against code that did not exist.

```text
R42: fetched source for RelayOracleV2 0x795f9464  -> saved 8,688 B, labelled "verified"
     concluded "execute()/executeMultiple() are signature-gated on _hashTypedDataV4"
     *and* separately recorded selector 0x432994b7 as "execute"

R45: re-fetched the SAME address from the explorer
     ContractName = RelayOracleV2, compiler v0.8.28, source = 16,797 B
     executeMultiple(Execution[],address,bytes[]) = 0x31bf395b
     execute(Execution,address,bytes)             = 0xf48443e7
     -> both ABSENT from the 8,688 B file. Half the contract had never been read.
     -> 0x432994b7 is not an Oracle selector at all; it is Executor#2 0x797b3ce4.
```

The conclusion happened to survive (an independent live `payGas` probe also showed the
signature gate), but **as evidence for that contract the R42 analysis was void.** Two
separate failure modes fed each other:

1. a truncated fetch written to disk and thereafter treated as ground truth;
2. a **selector literal inherited from a prior round and never re-derived**, which then
   silently pointed the ABI-search at the wrong contract's bytecode.

The disambiguating test is cheap and must run before any source-derived claim:

```python
# 1. the source must be COMPLETE — check for the contract's own closing brace
src.count('{')  vs  src.count('}')        # unequal  -> truncated, re-fetch
'}\n' not in src.strip()[-50:]            # no trailing brace -> truncated

# 2. the bytecode must CONTAIN the selectors the source declares
code = eth_getCode(addr)                  # lowercase hex, no 0x
for name in ['execute(Execution,address,bytes)', 'executeMultiple(Execution[],address,bytes[])']:
    assert sel(name) in code, f'{name} declared in source but absent from bytecode'

# 3. any selector literal used in a probe must be re-derived THIS round from the
#    function signature — never copy-pasted from a previous round's notes
```

```text
RULE  "verified source" means: fetched this session, brace-balanced, AND at least one
      selector from the source found in eth_getCode(addr). Length alone proves nothing.
RULE  a selector is a derivation, not a fact. Recompute sel(signature) every round;
      a copied selector silently redirects the whole analysis to another contract.
RULE  when a probe selector is ABSENT from the target's bytecode, the target is NOT
      what you think it is, OR your source is a fragment. Resolve which before
      writing any sentence containing the word "gated". Do not push the conclusion
      into the ledger in the meantime.
RULE  if you have been citing a file for several rounds, re-fetch it once at the start
      of a fresh session. Truncated fetches do not heal; they get load-bearing.
```

Retraction protocol for this class: retract the *evidentiary status* ("this analysis was
built on a fragment"), state whether the conclusion was independently re-derived, and do
not quietly keep the old citation as if it still supported the claim.

---

## §3 — Checklist before writing any verdict that contains a number

```text
[ ] every literal in the script traces to a fetch or JSON artifact — no % , no [:n]
[ ] no address was completed by hand: every 42-char literal appears verbatim in an
    explorer/receipt/calldata artifact fetched this session
[ ] printed identifiers carry an ellipsis or a full-hex form, never a modulo
[ ] before grading a role gate: getRoleAdmin(ROLE) was called (UNK vs ADMIN changes the verdict)
[ ] any "verified source" file is brace-balanced AND one of its selectors appears in eth_getCode
[ ] every selector literal in the probe was re-derived this round from `keccak(sig)[:4]`
[ ] every fact a new claim depends on was re-measured THIS round, not inherited
[ ] when a new admin appears, the old one's remaining authority was measured
[ ] the positive control returned a NON-ZERO / NON-REVERT value (Rule 14)
[ ] each arm of the differential got a DIFFERENT outcome (else PROBE-INVALID)
[ ] capability (A) and reachability (B) are two separate labelled lines
[ ] every state-mutating eth_call's function body was read before interpretation
[ ] the OPERATOR/holder census row exists before the grade is written
[ ] at least one claim generated this round was killed and listed
```

