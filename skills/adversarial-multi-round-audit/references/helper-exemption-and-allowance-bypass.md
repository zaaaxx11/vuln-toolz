# Bypass-the-Allowance Round — auditing a trusted helper that is EXEMPTED from a parent's guard

The round that follows a REFUTED takeover. Round N killed "attacker takes over the trusted helper
(ERC20View / executor / resolver / adapter)". Round N+1 asks the only question left:

> **If I cannot become the exempted caller, what can the exempted caller be MADE to do?**

Trigger phrases: *"serang jalur yang SUDAH TERBUKTI ADA"*, "bypass allowance", "only X can call Y",
"`mapping[id] == msg.sender` exemption", "the helper is the only entity that can move someone else's balance".

---

## 0. Why this round usually ends REFUTED (and why you still run it)

A `msg.sender == trustedHelper` exemption in the parent looks like a wide-open hole. It almost never is,
because the **helper re-implements the guard on the way in**, and that second guard has no exemption.
The parent's bypass is real; it is simply unreachable without the helper's cooperation.

So the deliverable is a **two-layer gate proof**, not a finding:

```text
Layer 1 (parent)  : guard skipped when msg.sender == helper        -> CONFIRMED ALIVE
Layer 2 (helper)  : guard re-implemented before calling parent     -> CONFIRMED ALIVE
Attacker reach    : cannot be msg.sender == helper (takeover REFUTED in round N)
=> REFUTED, with one positive control proving layer 1 really is bypassable
```

Both layers must be probed. Proving only layer 2 gives you "it reverted" without knowing *why the design
would otherwise be fatal*; proving only layer 1 gives you a fake CRITICAL.

---

## 1. Read the helper source to the closing brace BEFORE probing

Do not start with `eth_call`. Grep the contract and answer six questions with `file:line`:

| Question | What you are looking for |
|---|---|
| Is `transferFrom` public / permissionless? | `function transferFrom(...) public` with no modifier — then who guards the body? |
| Does it check allowance itself? | an `if (msg.sender != from)` + `allowance()` + custom revert inside the helper |
| Where does it read/write allowance? | `hub.allowance(...)` vs local storage — decides whether the helper or the parent owns the ledger |
| Any `mint` / `burn` / `initialize`? | a mint on the helper = supply forgery; `initialize` = the retry of round N |
| Is `totalSupply` a pass-through? | `return hub.totalSupply(id)` = read-only, cannot be manipulated from the helper |
| Fallback / delegatecall? | answered by the opcode walk, §4 |

Reference shape (Relay `ERC20View.sol`):

```solidity
// ERC20View.sol:201-230  — public, no modifier
function transferFrom(address from, address to, uint256 value) public returns (bool) {
  if (msg.sender != from) {                                  // <-- LAYER 2
    uint256 currentAllowance = hub.allowance(from, msg.sender, tokenId);
    if (currentAllowance < type(uint256).max) {
      if (currentAllowance < value)
        revert ERC20ViewInsufficientAllowance(msg.sender, currentAllowance, value);
      hub.approveFor(from, msg.sender, tokenId, currentAllowance - value);   // decrement in PARENT
    }
  }
  bool success = hub.transferFrom(from, to, tokenId, value);  // <-- parent exempts this msg.sender
  ...
}
```

Parent side:

```solidity
// RelayHub.sol:255-263
if (msg.sender != sender && !isOperator(sender, msg.sender) && erc20Views[id] != msg.sender) {
  uint256 allowed = allowance[sender][msg.sender][id];
  if (allowed != type(uint256).max)
    allowance[sender][msg.sender][id] = allowed - amount;     // <- underflow guard, see §3
}
```

---

## 2. Allowance-ledger ownership (the H2 probe)

The question "is allowance stored in the helper or the parent" decides who can be tricked into writing it.

```text
helper.approve(spender, v)      -> parent.approveFor(msg.sender, spender, id, v)
parent.approveFor(...)          -> require(msg.sender == trustedHelper[id]) else revert
parent.allowance[owner][spender][id]
```

Consequences worth stating explicitly in the report:

- Only the helper can write the parent's allowance mapping. `approveFor` called directly by an attacker
  must revert — **probe it** and name the selector (`OnlyERC20ViewCanCallApproveFor` → `0x09eaed7c`).
- The write direction is `allowance[msg.sender][spender]`, i.e. **the caller's own budget given to
  `spender`**. So `helper.approve(victim, 12345)` from an attacker succeeds, returns `true`, and emits
  `Approval(attacker, victim, 12345)` — while writing budget the attacker already owns. **On-chain inert**,
  but a live UI/event-phishing surface. Grade `INFO/LOW`, never CRITICAL.
- If the helper has no allowance storage of its own (only `immutable hub` + `immutable tokenId`), the
  "helper-local ledger" hypothesis is dead before any probe.

---

## 3. The underflow-coincidence trap — a revert for the WRONG reason reads as a gate

Probing `parent.transferFrom(victim, attacker, id, 1)` **directly from an attacker** — the most obvious
probe against the proven-live bypass — reverts with:

```text
0x4e487b71 0000...0011      Panic(0x11) = arithmetic underflow
```

That is **not** the allowance gate refusing you. It is `allowed - amount` where `allowed == 0`, i.e.
`0 - 1`, on the line *before* the allowance is used. Solidity 0.8 checked arithmetic did the work.

Why this matters:

- It reverts **before** the balance move, so the probe is a true negative (no theft) — but if you report it
  as "the allowance check stopped me" you have mis-attributed the gate and you will not notice the
  `amount == 0` hole in §3a.
- The genuine "is the bypass reachable" question is answered by the **positif control** in §5, not by this.

Rule: run the same probe with three amounts (`1`, `type(uint256).max`, `0`) and label each revert by
selector. `Panic(17)` ≠ `InsufficientAllowance` ≠ `AccessControl` — they mean three different things about
which line fired.

### 3-0. `Panic(0x11)` has TWO sources in `transferFrom` — allowance AND the balance ledger

This is the trap that nearly produced a **false refutation of a live finding**. The prior round had proven
the operator bypass alive on hub A. Probing the same predicate on hub B returned `Panic(0x11)` for both the
operator and the attacker — which reads as "the bypass does not work here". It was wrong.

`transferFrom` has two independent checked subtractions:

```solidity
// RelayHub.sol:255-267 (order matters)
if (msg.sender != sender && !isOperator(sender, msg.sender) && erc20Views[id] != msg.sender) {
  uint256 allowed = allowance[sender][msg.sender][id];
  if (allowed != type(uint256).max)
    allowance[sender][msg.sender][id] = allowed - amount;   // <-- SOURCE A: allowance underflow
}
balanceOf[sender][id] -= amount;                            // <-- SOURCE B: balance underflow
```

`balanceOf[sender] -= amount` is **outside** the guard. So if the chosen `sender` holds **zero balance** on
that instance, *every* caller — operator or not — panics on source B **before** the allowance question is
ever decided. The probe measures nothing.

**Mandatory precondition before any `transferFrom` differential probe:**

```text
1. balanceOf(sender, tokenId) on THE SAME instance must be > 0   (assert, print it)
2. totalSupply(tokenId) on that instance must be > 0             (a sibling instance is often empty)
3. THEN run from=operator vs from=attacker on identical calldata
```

In-session: the "target" hub had `totalSupply(TID) == 0` and the victim's balance `0` — a second, undeployed
sibling world. The same predicate on the funded hub returned `0x0000…0000` (no revert) for the operator and
`Panic(0x11)` for the attacker. Same contract code, opposite verdict, and the only difference was funding.

**The discriminator that catches this automatically:** if the operator path and the attacker path revert with
the *identical* selector, you have not found a gate — you have found a shared precondition failure. A real
differential gate gives **different outcomes** (`result != None` vs `revert`). Identical panic on both arms =
`PROBE-INVALID`, never `REFUTED`.

### 3a. `amount == 0` defeats the underflow coincidence — permissionless zero-value transfer

```text
allowed = 0; 0 != MAX  ->  allowance = 0 - 0 = 0   (no underflow)
=> parent.transferFrom(victim, attacker, id, 0) SUCCEEDS: 0x…01
```

Real, repeatable, and **not** a value bypass. Impact is log/indexer spam: an `Transfer(victim, victim,
attacker, id, 0)` event for any address of your choosing. Subgraphs that fail to filter `amount > 0` will
record phantom transfers for arbitrary victims. Grade `INFO/LOW` with that exact framing — "permissionless
zero-value transfer for log pollution", never "allowance bypass".

Also check for a receiver callback before inflating this: a pure ERC-20-style ledger with no external call
to `to` has no reentrancy hook, so the zero-value path is inert beyond logs.

---

## 4. Bytecode: walk opcodes, NEVER substring-scan

`code.count("f4")` = 16 and `code.count("ff")` = 46 on a contract with **zero** DELEGATECALL and zero
SELFDESTRUCT. Those are nibbles inside PUSH data. Reporting proxies/selfdestruct from a substring count is a
fabricated structural claim.

```python
code = bytes.fromhex(rpc("eth_getCode", [addr, "latest"])["result"][2:])
PUSH = set(range(0x60, 0x80))          # PUSH1..PUSH32
ops, i = {}, 0
while i < len(code):
    op = code[i]; ops[op] = ops.get(op, 0) + 1
    i += 1 + (code[i] - 0x5f if op in PUSH else 0)     # skip the pushed payload
for o, n in [(0xf4,"DELEGATECALL"), (0xf1,"CALL"), (0xf2,"CALLCODE"),
             (0xf0,"CREATE"), (0xf5,"CREATE2"), (0xfa,"STATICCALL"), (0xff,"SELFDESTRUCT")]:
    print(n, ops.get(o, 0))
print("minimal proxy prefix:", code.hex().startswith("363d3d373d3d3d363d73"))
```

Anything non-zero here is the finding; zero everywhere plus a non-`363d3d…` prefix is the proof that the
helper is a full contract with **no foreign code path** — which is what closes "can it be made to run an
attacker's implementation". Complements `onchain-protocol-audit` → `references/proxy-takeover-and-reinit-closure.md`.

---

## 5. THE DECISIVE POSITIVE CONTROL: impersonate the helper

Every other probe in this round is a revert, and reverts on this RPC family are ambiguous. The one call that
licenses the entire verdict is `eth_call` with `from = <the helper address>`:

```text
from = 0xec468c69… (the ERC20View)  ->  parent.transferFrom(victim, attacker, id, 1000)  ->  OK 0x…01
```

Zero allowance, funds moved. That single row proves:

1. the parent's bypass is **alive on chain**, not just in source;
2. the only thing stopping an attacker is `msg.sender` identity — never the allowance logic;
3. round N's takeover refutation is the load-bearing result, so its evidence must be carried into this
   report verbatim.

Pair it with the attacker row on the **same call shape** so the differential is one variable:

```text
from = attacker  -> REVERT
from = helper    -> OK
```

---

## 6. Required matrix before any verdict

Do not report from one probe. Minimum, all in one artifact append:

```text
3 different helper instances x 2 different victims x 2 amounts
  + attacker self-move        (balance 0 -> Panic 17 expected, NOT a finding)
  + helper.transfer()         (from hardcoded to msg.sender -> cannot target others)
  + direct parent.approveFor  (must revert with Only…CanCallApproveFor)
  + positive control from=helper (§5)
  + opcode walk (§4)
```

For real victims: derive balances from chain. See pitfall 29 — do not accept an address from the brief
without verifying `balanceOf > 0` first, and if the brief's address does not resolve to a full 40-hex
address, say so in the report rather than padding it into something plausible.

---

## 7. Grading table for this class

| Result | Grade |
|---|---|
| `helper.transferFrom(victim→attacker)` reverts with the helper's own `InsufficientAllowance` on every instance/victim | REFUTED, carry the round-N takeover refutation |
| parent bypass provably alive via `from=helper` | structural note: enforcement delegated to the helper; fragile if a new helper is registered without a matching check |
| `amount == 0` succeeds | INFO/LOW — permissionless zero-value transfer, log pollution |
| helper emits `Approval` for a direction it did not write | INFO/LOW — UI/event phishing surface, on-chain inert |
| helper-local allowance ledger, or allowance written for a `from` the caller chooses | CRITICAL candidate — re-probe on 3 instances + 2 victims before writing it |
