# Permission-model audit — global-operator escalation, and the two decode bugs that faked findings around it

Companion to `references/helper-exemption-and-allowance-bypass.md` and
`references/selector-and-getter-form-traps.md`. Read this when a contract has
**two** authorization concepts (`hasRole` and a per-account operator map) that are
combined in one boolean.

---

## 1. THE PATTERN: `operator ||` collapses a per-account grant into a global one

```solidity
// RelayHub.sol:177-182
function isOperator(address account, address operator) public view returns (bool) {
  return hasRole(OPERATOR_ROLE, operator) || _isOperator[account][operator];
  //     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ `account` IS NEVER USED HERE
}
```

Consumers treat `isOperator(sender, msg.sender)` as "may act on `sender`'s
balances", which is correct for the second term and **catastrophically wrong for
the first**: any `OPERATOR_ROLE` holder is an operator for *every account*.

```solidity
// RelayHub.sol:255-263
if (msg.sender != sender && !isOperator(sender, msg.sender) && erc20Views[id] != msg.sender) {
  uint256 allowed = allowance[sender][msg.sender][id];
  if (allowed != type(uint256).max) allowance[sender][msg.sender][id] = allowed - amount;
}
```

Consequence: one `OPERATOR_ROLE` holder can `transferFrom` **any holder's** tokens
with no allowance and no per-account grant.

### Why this is a design flaw and not always a Critical

Grade it by *who holds the role*, not by the shape of the bypass:

| role holders | grade | framing |
|---|---|---|
| only contracts that are supposed to route value (allocator / executor) | HIGH — design flaw, blast radius = everything | "OPERATOR_ROLE is a global super-operator over every balance" |
| any EOA | CRITICAL | an EOA can drain any holder directly, no oracle/signature needed |
| only multisig / timelocked admin | MEDIUM — documented centralisation | still report the *globalness*, it is not what the name implies |

Never write "operators can move tokens" — that is expected. Write **"the
per-account argument is discarded, so the grant is not per-account"**, with the
`file:line` of the discarded parameter.

### 1a. TURNING THE FINDING FROM NAMED INTO QUANTIFIED — measure the production sweep

§1 says the grant is not per-account. That is a **shape** statement, and a triager can wave
it off as "the operator is our own contract". The upgrade to a reportable HIGH is a
**measurement**: decode the operator's action stream from real logs and count what it
actually moves, to whom, in what proportion of supply.

The full method, in order:

```text
1. Identify the action multiplexer on the privileged contract.
   grep for an enum / actionType / a bytes[] blob decoded by tag.
   RelayOracleV2: enum ActionType { MINT, BURN, TRANSFER, FAST_MINT }
2. Pull the event that carries the blobs (here `Executed(bytes32,bytes[])`).
   Paginate with eth_getLogsWithCursor — a wide eth_getLogs on the hub RPC
   returns "Response size exceeds limit" and silently truncates.
3. Decode every action's type byte (see empty-contract-and-event-decode-traps.md 2b
   for the arr+1 offset base — this is exactly where that bug bites).
4. Emit a frequency table. A type you assumed was dead code showing 18,460 hits
   means your threat model skipped half the contract.
5. For each `from` in the balance-moving action, eth_call isOperator(from, PRIVILEGED).
   It returns true for ALL of them — and that is the mechanical consequence of §1,
   NOT evidence of abuse. Say so; do not dress it up.
6. Diff the SET of `from` addresses against the set of addresses that ever RECEIVED
   a mint. A near-total union means "sweep of balances it was custodian of", not
   "arbitrary theft". One address outside the union is the only interesting row.
7. Resolve every distinct `to`. `eth_getCode` == 0x means a bare EOA sink.
8. Measure concentration: balanceOf(sink, tokenId) / totalSupply(tokenId) per token.
```

Worked result from a real session (hub chain, 40k blocks):

```text
MINT      18,466    TRANSFER  18,460    BURN 0    FAST_MINT  17
TRANSFER from-addresses: 18,454 distinct  (~1 sweep per account)
`to` for the sweep: one address, codesize 0  => bare EOA
supply held by that EOA: 84.67% / 78.96% / 76.75% on three tokenIds
```

### How to grade that composite

```text
global-operator + sweep-to-bare-EOA + majority supply
  => HIGH centralisation finding, titled with the unit figure
     e.g. "hub custody swept to a single EOA holding 76-85% of supply on 3 tokenIds"
  NOT an unprivileged exploit — nothing is reachable without a key.
```

Three things must appear in the writeup or it is incomplete:

1. the `file:line` where the parameter is discarded (§1);
2. the **measured** volume (`18,460 sweeps`, not "could sweep");
3. the sink identity (`codesize 0 => EOA, no multisig`) and the % of supply.

And one thing must appear as an explicit negative: **no keyless path.** A custody finding
that reads like a drain is the inflation failure mode; state `requires a key` in the title
line itself.

### 1b. The `sweep to EOA` does NOT retroactively make the global-operator a bug

Tempting but wrong: "the operator is already sweeping everyone, so the global grant is
being exercised and is therefore exploitable." Both clauses are false as an inference.

- The sweeps are the **intended** settlement flow (deposit → mint to user → sweep to
  settlement). Predicting them as an attack is a category error.
- The global grant's danger is **who may exercise it**, not whether it is exercised. A
  contract legitimately sweeping daily is still a contract whose compromise = total loss.

Record the two as SEPARATE findings that multiply risk, and say so: "F-global-operator
raises the blast radius of F-custody-EOA from 'user funds' to 'every account'." Do not
merge them into one inflated Critical.

### Detection procedure (cheap, do it every time you see a permission predicate)

```text
1. grep every function that returns bool and takes (address, address)
2. for each, ask: is EVERY parameter used in every `||` / `&&` branch?
3. a parameter used in only one branch of an OR => that branch's grant is broader
   than the name suggests
4. grep call sites: does the caller pass a meaningful value for that parameter?
   if callers pass the value but the callee ignores it, the bug is in the callee
```

Audit the same shape in: `isApprovedForAll`, `isDelegate`, `canSpend`,
`isAuthorized(owner, spender)`, `hasPermission(account, actor)`.

---

## 2. Decode bug A — calldata word offsets shift by one when argument 0 is a struct

Cost in-session: an entire round spent reporting a resolver at `0x…0440` with
`codelen=0`, and a near-miss "oracle is a phantom address" claim.

```text
execute(ExecuteAndWithdrawRequest request, address callResolver,
        bytes callResolverData, address oracle, bytes signature)

word[0] = 0xa0          <- OFFSET to struct, not an argument value
word[1] = callResolver   <- correct, the first STATIC arg lands here
word[2] = offset of callResolverData
word[3] = oracle
word[4] = offset of signature
```

Reading `w[2]`/`w[4]` yields `0x440` / `0x520` — block-offset-looking numbers that
pass a naive `20-byte address` slice check (`'0'*24 + w[24:]`). Both had
`codelen = 0`, which is the tell.

### The tell, and the check

```text
SYMPTOM : an address decodes to a small number (0x3e0, 0x440, 0x520, 0x180)
          or has codelen == 0 while the contract is definitely deployed
CAUSE   : you read an offset/length word as an address
FIX     : get the ABI via explorer getabi, count the inputs, THEN walk:
          dynamic arg (bytes/string/tuple) contributes a 32B OFFSET in the head;
          static arg contributes its value; a tuple arg's head contribution is
          its offset when the tuple itself is dynamic
```

Mandatory guard in any decode script:

```python
cr = '0x' + w(inp, 1)[24:]
assert len(cr) == 42
assert rpc('eth_getCode', [cr, 'latest']) not in ('0x', '0x0'), f"decoded {cr} has no code"
```

Cross-check against something already known: the decoded `oracle` must equal the
oracle you independently fetched from the constructor/registry. When it matched
`0x2a72eb8c…` (the value from a prior round), the decoder was proven correct.

---

## 3. Decode bug B — an incorrectly padded address produces a 28-hex word

```python
P = lambda a: '0'*24 + a[2:]          # assumes `a` is a 40-hex address
P('0xbeef') -> '0'*24 + 'beef'  = 28 hex chars, NOT 64
```

The RPC then returns `execution reverted` with **`data: None`** — no custom-error
selector at all. That empty `data` is indistinguishable from "the gate fired and
the node stripped the revert reason", so it reads as a *passing* gate probe.

Cost in-session: `approveFor` probes against a real guard returned `data=None`
three times and were nearly written up as "the guard is not enforced". After
padding to 40 hex the same calls returned
`0x09eaed7c…` = `OnlyERC20ViewCanCallApproveFor(address)`, proving the guard.

### Rules

- Every address literal must be `assert len(a) == 42 and a.startswith('0x')` before
  padding. Short hex like `0xdead` / `0xbeef` is **not** an address.
- `P('0xdead')` is 64 chars because `'0'*24 + 'dead'` = 28… **and 24+4=28**, so it is
  *also* wrong — the coincidence that `0xdead` happens to look plausible is why this
  survives review. Assert length, do not eyeball.
- A revert with `data: None` is **INCONCLUSIVE, never PASS**. A gate that fires with
  a custom error must produce its selector; absence of a selector means the revert
  came from somewhere else (bad calldata, wrong arg count, ABI mismatch).
- Tests that assert `is_revert` must assert `selector in str(response)`, not merely
  "it reverted". Otherwise C1..Cn can all "PASS" on malformed calldata.

---

## 4. Differentiating "gate fired" from "arithmetic panicked"

Same probe, different `from`, two different meanings:

```text
from = OPERATOR_ROLE holder  -> 0x0000…0000        no revert: allowance path skipped
from = random address        -> 0x4e487b71…0011    Panic(0x11) on allowed - amount
```

`Panic(0x11)` proves the **allowance line executed**; its absence in the operator
row proves that line was **skipped**. The pair is the differential. One row alone is
ambiguous — a plain revert could be the balance check, the paused check, or a bad
encoder (§3).

Include one row per branch of the `if` you are testing, plus a negative control
with an address that satisfies none of them.

---

## 5. What `eth_call` can and cannot prove here

`eth_call` with `from=<operator>` returning success proves **the code path exists**.
It does **not** prove value moved — no state is written. Report:

> "the allowance branch is skipped for OPERATOR_ROLE holders (**proven by
> differential**); real value movement additionally requires a mined tx."

Do not upgrade to "funds can be drained" on an `eth_call`. That upgrade needs either
a fork test with a real state transition, or a mined transaction.

### 5c. THE `amount=0` CONTROL — the cheapest way to prove a gate PASSED (not "the flow died")

§4's advice — "one row per branch, plus a negative control" — is necessary but not
sufficient. Both arms reverting **identically** is ambiguous: a shared precondition
failure (`Panic(0x11)` on an unfunded balance) looks exactly like a shared gate. The
fix that settles it in one call: **re-run the exact same request with `amount = 0`.**

```text
amount=1, msg=operator, spender=operator  -> REVERT Panic(0x4e487b71)   ambiguous
amount=1, msg=stranger, spender=stranger  -> REVERT Panic(0x4e487b71)   ambiguous
amount=0, msg=operator, spender=operator  -> RESULT 0x3250…19ea (hash)  GATE PASSED
amount=0, msg=stranger, spender=stranger  -> RESULT 0xcb08…f3ba (hash)  GATE PASSED
```

`amount=0` makes the downstream debit a no-op, so the call reaches and returns the
happy path *without* the arithmetic that was masking it. Two things follow:

- **Positive control for free.** An EOA naming *itself* returns a hash → the
  `callerIsSpender` leg is empirically live and the harness can observe success at all.
- **`Panic(0x11)` is localised to the sink, not the gate.** If `amount=0` succeeds and
  `amount=1` panics with the *same* revert for every caller class, the gate was passed
  and the panic is in the balance math. That is a **NOT-EXPLOITABLE-by-authorization**
  reading, not a `PROBE-INVALID` one.

Rules:

- Try `amount=0` **before** concluding a losing differential. It costs one call and
  converts an ambiguous `Panic` pair into a labelled verdict.
- The success value is a **storage-derived hash** (e.g. `withdrawRequestHash`). Capture
  it — two different callers returning *different* hashes proves the flow ran to
  completion and the params were actually consumed.
- `amount=0` succeeding does **not** mean `amount>0` succeeds. It proves the gate and
  the pre-burn flow; the sink's own preconditions still have to be satisfied separately.
- Do not report the `amount=0` success as a finding. It is an instrument reading.

#### 5c-i. `amount=0` CAN ALSO BE PASSED BY A CALLER THAT HAS NO RIGHT TO MOVE FUNDS

Read the `amount=0` reading carefully — "gate passed" is only true if the *right* gate
was consulted. On a per-account operator hub the allowance branch is **skipped
entirely** when `msg.sender == sender`, and skipped again when the operator holds a
global role. With `amount=0` and no funded balance there is nothing left to reject:

```text
amount=0, from=ATTACKER EOA (no role) -> OK      <- NOT a bypass, and NOT a control
amount=0, from=VICTIM itself          -> OK
amount=0, from=EXEC1                  -> OK
```

Every row succeeding means the probe got **past the arithmetic** without ever
exercising the authorization decision — the same failure mode §4 warns about, reached
from the other side. Before quoting an `amount=0` row as a control:

- **An unattached caller must be REJECTED.** If `ATTACKER` also gets `OK`, the
  `amount=0` arm has no discriminating power; it is an ABI/decoder check at best.
- Reverse the polarity deliberately: an `amount=0` probe is a *positive* control only
  when at least one non-privileged caller still reverts.
- The real authorization differential needs `amount>0` at a **pinned block** with a
  balance that actually covers it (see `decode-and-proof-traps.md` §5c on rebasing
  balances). Otherwise `Panic(0x11)` fires for the attacker *and* the victim and proves
  nothing.

### 5c-ii. A FAILED `transferFrom` FOR THE VICTIM'S OWN SELF-TRANSFER MEANS YOUR PROBE IS BROKEN

Strongest single tell that a value-moving probe is unusable: the token's own holder
cannot transfer to itself.

```text
transferFrom(VICTIM -> DEAD, amount) from=VICTIM -> REVERT Panic(0x11)
```

The holder being unable to move its own tokens is almost never a protocol property —
it means `amount` exceeded `balanceOf[sender][id]` **at the height the probe ran**. Check,
in this order:

```text
1. was balanceOf read at the SAME pinned block as the transfer?   (rebasing / new block)
2. does the getter return the value the sink debits?              (decode-and-proof-traps §5b)
3. is the tokenId the full 64-hex uint256, un-truncated?           (§6)
4. is `amount` the raw integer, not a display-formatted string?
```

Until the self-transfer control passes, every executor row in the same table is
**INCONCLUSIVE**, not evidence of a bypass. Report the table as void rather than reading
the middle rows.

### 5d. Which address is actually debited — check the alias/derived address holds funds

A sink that takes a **derived** address (`spenderAlias`, a hash-named vault, a
counterfactual address) may be structurally sound and still point at nothing:

```text
balanceOf(VICTIM, tokenId)          = 88094785     <- the real holder
balanceOf(alias(base), tokenId)     = 0            <- what the sink debits
balanceOf(alias(polygon), tokenId)  = 0
burn(alias(*), tokenId, 1)          -> Panic(0x11)  (all variants)
burn(VICTIM, tokenId, 1) from OPERATOR -> RESULT 0x…01   <- CONTROL+ moves real value
```

Two separate conclusions live here and must not be merged:

1. the allocator's `burn` leg debits an **empty** alias → the `Panic` is a balance
   precondition, not an authorization signal;
2. the victim's real balance can only be burned via `Hub.burn(VICTIM,…)`, which is
   `onlyRole(OPERATOR_ROLE)` → revert `0xe2517d3f` for every non-operator, **including
   the victim itself**. That is the correct gate, and it is the answer.

If `Utils.generateAddress` / `generateTokenId` source is unavailable, alias candidates
are guesses — say so, and note that the verdict survives anyway because the gate
(`L279`) fires *before* the alias is consumed.

### 5e. What the final verdict line should look like

```text
NOT-EXPLOITABLE  (no unprivileged burn; only an OPERATOR_ROLE holder can burn,
                  and that is the intended privileged path, not a bypass of
                  RelayAllocator#2)
```

State the grade against the **function under audit**, not against the whole protocol.
A global-operator capability that the audited contract never reaches is *not* that
contract's exploit; record it separately as the §1 design finding.

### 5a. THE SETTER TRAP — a non-reverting setter `eth_call` is not a finding

Three times in one session a "CRITICAL" was one source read away from being false.
A setter that stores `msg.sender` implicitly looks, from `eth_call` output alone,
like an attacker writing on someone else's behalf.

```solidity
// RelayHub.sol:216-221 — there is NO `account` parameter at all
function setOperator(address operator, bool approved) public returns (bool result) {
  return _setOperatorFor(msg.sender, operator, approved);   // first arg is ALWAYS msg.sender
}
```

A probe `setOperator(VICTIM, true) from=0xcafe` → `OK`. That reads as "CAFE
granted itself over VICTIM". It actually means "CAFE made VICTIM an operator over
CAFE" — the exact reverse, and harmless.

**RULE: read the function body to its closing brace BEFORE interpreting any
successful `eth_call` on a state-mutating function.** Specifically confirm which
parameters are used and which are replaced by `msg.sender` / `address(this)`.

Corollary for controls: if the *positive control* (the legitimate caller doing the
legitimate thing) reverts, the whole probe set is **VOID**, not evidence. Here
`setOperatorFor` was `onlyRole(OPERATOR_ROLE)`, so "VICTIM calling it on itself"
correctly reverted — the control was mis-designed, and its failure was reported as
an anomaly for a while before the modifier was read.

```text
SYMPTOM : legitimate-self control reverts with AccessControlUnauthorizedAccount
CAUSE   : the function is role-gated, so "self" is not an authorized caller at all
FIX     : pick the control from the actual role census, not from "the victim should
          be allowed to do this to itself"
```

What the setter probe DOES establish, and is worth keeping: `setOperatorFor` is
`onlyRole(OPERATOR_ROLE)`, so an attacker cannot manufacture a per-account grant.
Combined with the global-operator finding it narrows the blast radius question to
"who holds the role" — which is §1's grading table.

### 5b. Two revert selectors that are the same finding twice

`0xe2517d3f` = `AccessControlUnauthorizedAccount(address,bytes32)`. Getting this
from `burn()` on every row — including the token's own holder — means **the gate
exists and the probe never reached balance math**. Do not read that as "burn is
gated by balance"; read it as "burn is gated by role, and my probe was the wrong
caller". Name revert selectors from the ABI (`getabi` → hash every `type:"error"`
entry) before writing any verdict; an unnamed `execution reverted` is a coin flip.


---

## 7. `_setRoleAdmin(X, ADMIN_ROLE)` + a single-EOA ADMIN = an uncapped mint key

The highest-leverage shape found across 43 rounds, and the one most easily dismissed
because every individual step is "just an admin function". Audit it as a **chain**, not
as four separate setters.

```solidity
// RelayHub.sol:163-166 (constructor)
_setRoleAdmin(OPERATOR_ROLE, ADMIN_ROLE);   // ADMIN can grant/revoke OPERATOR
_setRoleAdmin(EDITOR_ROLE,   ADMIN_ROLE);
_setRoleAdmin(ADMIN_ROLE,    ADMIN_ROLE);   // ADMIN is self-administering
_grantRole(ADMIN_ROLE, adminAddress);       // one address, passed in at deploy

// RelayHub.sol:379 / 393
function mint(address receiver, uint256 id, uint256 amount) external onlyRole(OPERATOR_ROLE)
function burn(address sender,   uint256 id, uint256 amount) external onlyRole(OPERATOR_ROLE)

// RelayHub.sol:478-487 / 493-499
function _mint(address receiver, uint256 id, uint256 amount) internal {
  balanceOf[receiver][id] += amount;      // NO cap, NO supply check
  totalSupply[id] += amount;
}
function _burn(address sender, uint256 id, uint256 amount) internal {
  balanceOf[sender][id] -= amount;        // `sender` is a FREE PARAMETER
}                                          // no allowance, no msg.sender == sender
```

Three properties compose into a one-key drain:

```text
1. ADMIN is the role-admin of OPERATOR            -> ADMIN can self-grant OPERATOR (1 tx)
2. mint() has no cap and no per-token supply rule -> amount is whatever the minter says
3. _burn() trusts its `sender` argument           -> an operator can erase ANY holder's balance
                                                     without approval or consent
```

The chain to report is a fixed four-line sequence, and it fits in one line per step:

```text
TX1  adminEOA -> HUB.grantRole(OPERATOR_ROLE, adminEOA)
TX2  adminEOA -> HUB.mint(adminEOA, tokenId, totalSupply-or-more)
     -- or -- HUB.burn(victim, tokenId, balanceOf[victim]) then mint to self
TX3  withdraw via the normal rail
```

### Grading: this is custody, not a vulnerability — say so in the title

```text
attacker needs NO key                     -> VULN / CRITICAL
attacker needs a key that IS one plain EOA -> HIGH, titled "single-key custody of <X> units"
attacker needs a key behind multisig/timelock -> MEDIUM/LOW, centralisation note
```

`mint`/`burn` requiring `OPERATOR_ROLE` is **correct gating**, not a finding. The finding
is that the role graph collapses to one un-timelocked EOA which can manufacture the role
it needs. Write the unit figure into the title (`60,010,002 units across 2 tokenIds`) —
a custody finding without a blast radius is not triageable.

### 7a. The three checks that turn "admin functions exist" into a graded finding

```text
1. getRoleAdmin(TARGET_ROLE) == keccak("ADMIN_ROLE")  and  hasRole(ADMIN, X) == true
      => X can self-grant TARGET_ROLE. No further reachability work needed.
2. census the OPERATOR holders, then for EACH contract holder ask:
      does it expose a caller-reachable entrypoint that reaches mint/burn/transferFrom?
   (all three in-session held: an executor, a gas-payer, an oracle module)
3. for each such entrypoint, confirm the signature gate actually binds the sink args:
      every parameter that reaches the sink must be inside the digest.
      payGas    -> digest covers payerChainId, payer, currency, amount, expiration
                   + all 10 request fields                    -> CLOSED
      execute   -> digest covers keccak of every action blob   -> CLOSED (for that path)
```

If step 3 closes but the role in step 1 is reachable, the finding stands at HIGH-custody
and **no keyless path exists**. Say that explicitly — a clean "0 keyless paths after N
probes" is a legitimate and valuable round output, not a failed round.

### 7b. Do not grade a mint-cap absence on a path that is structurally dead

An uncapped `mint` reachable only through `hasRole(ORACLE_ROLE, oracle)` where
`getRoleAdmin(ORACLE_ROLE)` returns UNKNOWN is **unreachable by construction** — see
`log-enumeration-and-role-census.md` §5b-0. Report the missing cap as a hardening note
under the custody finding; do not open a separate HIGH for a gate that can never open.

---

## 6. Resolver/helper "does not inherit privileges" claims — verify, don't assume

The NatSpec said *"caller-supplied logic runs with the resolver as `msg.sender`, so it
does not inherit this contract's operator privileges"*. That is a **claim about
deployment**, and it was true here — but only because the concrete resolvers held
`hasRole(OPERATOR_ROLE) == 0` on both hubs.

```text
rescuer/resolver address comes from CALLER-SUPPLIED calldata  -> attacker picks it
executor calls it via external call (ICallResolver(x).execute)  -> resolver is msg.sender
=> the ONLY thing preventing escalation is that no privileged resolver is registered
```

So the audit item is a **role census over the set of resolvers actually used**,
derived from real calldata (`execute()` txs → decode `callResolver`), not from
source comments. A future resolver registered with the role silently converts a
"documented safe pattern" into a full drain. That is a MONITORING/INFO-worthy note,
worth stating even when the current set is clean.
