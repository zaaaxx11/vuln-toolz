# Unbound parameters & permissionless injection

The dual of Rule 7 in `abi-and-field-verification.md`. Rule 7 asks *"is the derived value gated at every consumer"*.
This file asks the mirror question, which is where this session's only real find came from:

> **Which security-relevant parameter is missing from the signed digest?**

A digest that binds 12 fields looks thorough. The finding is in field 13 that nobody listed.

---

## 1. The worked case

```solidity
// RelayExecutor.sol — digest preimage (L367-383)
keccak256(abi.encode(
  TYPEHASH,
  keccak256(bytes(request.inChainId)),  keccak256(request.inCurrency),
  keccak256(bytes(request.outChainId)), keccak256(request.outCurrency),
  request.outAmountMinimum,             keccak256(request.depository),
  request.orderAddress,                 keccak256(request.receiver),
  keccak256(request.data),              _hashFees(request.fees),
  request.nonce,                        request.deadline
))
```

Eleven value-bearing fields, all bound. What is **not** there:

| Omitted | Consequence |
|---|---|
| the pulled **amount** | `_pullOrderFunds` reads `HUB.balanceOf(orderAddress, tokenId)` and transfers **the whole live balance**, not a signed amount |
| `callResolver` | caller-supplied address that receives the working capital (`HUB.transfer(callResolver, tokenInId, netInput)`) |
| `callResolverData` | arbitrary bytes forwarded to that resolver |

And the developer wrote it down as a deliberate trade-off:

```solidity
/// @dev ... The solver-selected `callResolver` and `callResolverData` are not direct fields in the
///      EIP-712 request, so a generic execution plan can be refreshed after authorization.
///      A specialized resolver may require its own commitment through a signed request field.
///      The signed minimum output is the receiver's only economic guarantee.
```

Two things to extract from a comment like this:
1. **The security model is stated explicitly.** "The signed minimum output is the receiver's only economic
   guarantee" is the design admitting the delta above `outAmountMinimum` is unprotected.
2. **"may require"** — the commitment for a specialised resolver is optional, not mandatory. Any resolver that does
   not implement its own commitment leaves the substitution open for that resolver.

Sibling admission in `_pullOrderFunds`:

```solidity
/// @dev The protocol must assign each order an exclusive, non-reused address
///      because this function consumes its complete live balance.
```

That is an **off-chain promise** written as a NatSpec, not an on-chain invariant. Grep for wording like
`must`, `is expected to`, `assumes`, `the protocol guarantees` in `@dev` blocks — each one is a place where the code
delegates a safety property to something you cannot audit.

---

## 2. Procedure

1. **Print the digest preimage**, one field per line, from the source (not the ABI summary).
2. **List every parameter of the executing function.** Mark each `BOUND` or `UNBOUND`.
3. For every `UNBOUND`, walk to its sink:
   `transfer`, `transferFrom`, `burn`, `call`, `delegatecall`, storage write.
4. Ask whether an unprivileged actor can influence the sink input:
   - is the inflow permissionless? (ERC-6909 `transfer(receiver, id, amount)` is `public`; anyone can donate to any
     address, including another user's order address)
   - is the address caller-supplied with no allowlist?
   - is the calldata blob caller-supplied?
5. **Run the profit identity before assigning a severity.**

### The profit identity — the gate that kills most of these

```
attacker injects D into a sink the victim's own execution will sweep
          -> execution sends D (plus victim funds) to the VICTIM's receiver
=> attacker -D, victim +D  =>  attacker profit = 0  =>  NOT exploitable
```

A real finding needs a **destination** the attacker controls that the victim's execution pays into. In the case
above that is `callResolver` — but it only pays if the attacker wins a front-run race against the legitimate solver,
and the resulting state cannot be proven without a real signed request.

So the honest verdict was:

```
REAL DESIGN WEAKNESS  — digest omits the pulled amount and the resolver
ZERO ATTACKER PROFIT (proven by identity)  — attacker-funded injection is net-negative
UNPROVEN ON MAINNET   — needs a real oracle signature, i.e. not keyless
```

Severity: **MEDIUM / design-risk**, never Critical. Writing Critical here would be the inflation failure mode, and
a triager will answer with the profit identity in one line.

---

## 3. Checklist to run every round

```
[ ] Digest preimage printed field-by-field
[ ] Function parameter list compared against it; BOUND/UNBOUND table produced
[ ] Each UNBOUND traced to a sink
[ ] Inflow permissionlessness checked (public transfer / donation)
[ ] Destination address checked for allowlist / digest membership
[ ] Profit identity written out algebraically
[ ] If profit = 0  -> report as design note, do NOT elevate
[ ] If profit > 0 -> require a raw calldata replay or a signed-request PoC before writing Critical
```

---

## 4. Adjacent pattern: "whole-balance pull"

Any sink of the shape

```solidity
uint256 amount = token.balanceOf(holder);
token.transferFrom(holder, address(this), amount);
```

is a **whole-balance sweep**. Two properties to check:

1. **Is `holder` bound to the signature?** If yes, the attacker cannot redirect it — only donate into it (net 0).
2. **Is the contract's own balance zero between executions?** Sample `balanceOf(contract, id)` at `block N-1` for
   several historical executions. If it is always 0, EVM atomicity plus a consume-in-same-tx design means there is
   no resident pot to steal — defensive design, not a vulnerability. Say so.

A sweep with a permanently-zero resident balance is a **design note**, and saying that plainly is the correct
deliverable.

---

## 5. The gate that usually sits under the unbound parameter: membership is per-PAIR, not per-address

Before you accept "the attacker can inject into the victim's sink", check **how the sink is authorised**. In the
worked case the pull was:

```solidity
orderBalance = HUB.balanceOf(orderAddress, tokenId);        // whole balance
HUB.transferFrom(orderAddress, address(this), tokenId, orderBalance);
```

and `RelayHub.transferFrom` skips the allowance branch entirely when

```solidity
msg.sender != sender && !isOperator(sender, msg.sender) && erc20Views[id] != msg.sender
```

So the real precondition is **`isOperator(orderAddress, EXECUTOR) == true`** — an entry in a
`mapping(account => mapping(operator => bool))`, i.e. **per-pair**, not per-address. `allowance` was 0 in all three
live samples and irrelevant.

Measured live (three addresses that had sent funds to the executor):

```
from                                        codesize  balance  allowance  isOperator
0x3e31b81… (EOA)                                   0        0          0       1
0xb24ac15b… (BasicCallResolver)                 1925        0          0       1
0x27eb5ab… (EOA)                                   0        0          0       1
```

**Consequence for the attack story.** Anyone can raise a victim's *balance* (the ERC-6909 `transfer` is public), but
nobody can create the *pair*. `setOperator(operator, bool)` is public yet writes `_setOperatorFor(msg.sender, …)` —
it can only ever grant rights over the caller's own account. `setOperatorFor(account, operator, bool)` needs
`OPERATOR_ROLE`. So the injection primitive exists and the authorisation does not.

Lesson: when a `transferFrom` sits behind a custom `isOperator`, enumerate the **key tuple** of the mapping and ask
which of its components the attacker can choose. Injection ≠ authorisation; state that separation explicitly in the
report instead of letting "permissionless transfer" imply "permissionless pull".

---

## 6. Guard ORDER decides whether a differential probe is valid at all

The executor's validation sequence is:

```
L193  hasRole(ORACLE_ROLE, oracleMultisig)     // a PARAMETER, not the caller
L197  block.timestamp > deadline -> revert RequestExpired
L201  digest = _executeAndWithdrawRequestDigest(request)
L203  usedRequests[digest] -> revert RequestAlreadyExecuted
L209  isValidSignatureNow(digest, signature) -> revert InvalidSignature
```

There is **no `msg.sender` check anywhere**, so `execute()` is callable by anyone — but the only probe that proves it
must get *past* the deadline gate first. Three variants (original calldata, `callResolver` swapped, attacker as
`from`) all came back `0x15642292 = RequestExpired(uint256)` because the historical request had expired: the
experiment was void, not conclusive. Doing it right requires a **live** request, i.e. a fresh oracle signature.

The valid version of the same question, answered without forging anything, is the two-pointer differential:

```
[P1] attacker `from`, real request, callResolver SWAPPED
[P2] legitimate `from`, same request, callResolver ORIGINAL
```

If both return the **same** revert, the function never read the caller — that is your proof of "no caller gate".
If they return **different** reverts, the caller is being checked. In-session P1/P2 both returned
`0xd855c4f4 = InvalidSignature(oracle)`, and crucially **not** `0xe2517d3f = AccessControlUnauthorizedAccount` and
**not** `0x91e47843 = UnauthorizedOracle`. That single distinction is the difference between
`INFERRED-GATE / MEDIUM` and `BLOCKED`: the attacker clears every guard except the unforgeable one.

Corollary: never report an identical revert across variants as "they agree" unless you can show the variants reached
the guard under test. A distinct revert constant is the proof.

