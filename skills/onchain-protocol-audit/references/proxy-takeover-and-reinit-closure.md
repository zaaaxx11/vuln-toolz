# Killing a "take over / re-init the helper contract" angle — in 6 checks, with evidence

The angle sounds unbeatable: *"`Hub.transferFrom()` has a bypass branch `erc20Views[id] != msg.sender`,
so whoever controls `erc20Views[id]` can move **anyone's** balance without allowance. Can an attacker
re-initialise or hijack the view/helper contract and become that address?"*

It is a real question every time a contract has a trusted-partner branch. It also dies fast, and the
deliverable is a **table of six independent closures**, not prose. Worked twice on a live EVM deployment
(ERC20View `0xfb0fadd3…`, Hub `0xDDD3…9318`); verdict REFUTED with 0 attacker authority.

---

## 0. The order that matters

Cheap → expensive. Each step alone can end the round.

| # | Check | Cost | Kills |
|---|---|---|---|
| 1 | Source: does `initialize`/setter exist **at all**? | 1 read | re-init class |
| 2 | Source: are the "config" vars `immutable`? | same read | storage-overwrite class |
| 3 | Live bytecode: is it a clone/proxy? | 1 `eth_getCode` | implementation-write class |
| 4 | Runtime **hash** across instances | N × `eth_getCode` | shared-code assumption |
| 5 | Write-site census for the trusted address mapping | 1 grep | setter/repoint class |
| 6 | Explorer: ABI + txhistory + creation events | 3 requests | "maybe an admin path exists" |

---

## 1. "No `initialize()`" is not the same as "`initialize()` is guarded badly"

Read the file to the closing brace and grep the *whole* repo before theorising about guard strength.
In the session: 259-line file, **zero** `initialize`, `initialized`, `owner`, `setHub`, `upgradeTo`,
no `delegatecall`. There was no weak guard to bypass — the capability was never written.

**Do not stop at the source.** Confirm on the deployed bytecode and on the verified ABI, because the
repo may not be what is deployed:

```python
code = rpc("eth_getCode", [V, "latest"])["result"]
"8129fc1c" in code     # initialize()      -> False
"158ef93e" in code     # initialized()     -> False
```

Selector scan is a *hypothesis* (see §1.1 of `bytecode-disassembly-and-state-override.md` — `PUSH3`
trap, and `shr(224, …)` dispatchers). Absence is only conclusive once the ABI + a live call agree:

```text
explorer ?module=contract&action=getabi  -> 14 functions, 0 admin/owner/initialize
eth_call initialize()  -> {"error":{"code":3,"message":"execution reverted"}}  # fallback, no data
```

Revert with **no revert data** = the fallback ran = no such function. A real function that reverts
carries a selector or custom-error payload.

---

## 2. `immutable` config = no storage to overwrite (kills H4 outright)

```solidity
contract ERC20View {
  IHub public immutable hub;      // L105
  uint256 public immutable tokenId;  // L107
  constructor(uint256 _tokenId) { hub = IHub(msg.sender); tokenId = _tokenId; }
}
```

Two declarations, both `immutable`, nothing else in storage. Immutables are **embedded in the runtime
bytecode at deploy time**, so there is no SLOAD and no slot an attacker (or any later function) can
re-point. State this as a structural argument, then verify it behaviourally in §4 — `hub()` and
`tokenId()` must return *different* values per instance.

Corollary worth writing in the report: if the trusted address in the bypass branch is an immutable on a
contract with no mutable storage, **there is no write primitive anywhere in that contract's address
space**. That is the sentence that closes the class.

---

## 3. Clone vs full contract — use the EIP-1167 prefix, not the size

Every instance being the same size is *expected* for identical compiled artifacts and means nothing.

```python
CLONE = "363d3d373d3d3d363d73"           # EIP-1167 minimal proxy prefix
is_clone = code.startswith("0x" + CLONE) or CLONE in code[:60]
```

- Clone (`0x363d3d373d3d3d363d73…5af43d82803e903d91602b57fd5bf3`): the implementation address is
  embedded **in the clone's own code** and settable only by whoever deployed that clone (or by an
  initializer, back to §1). Enumerate that owner before assuming "anyone can write the implementation".
- Full contract: look for a real dispatcher, e.g. jump table `80633c130d901161008c57` and
  `4e487b71` = `Panic(uint256)` from the compiler.

Session: prefix was `0x608060405234801561001057600080fd5b50600436106100ea57…` → **not** a clone.
3874 bytes on all instances, because it was 3874 bytes of *actual code* each time.

---

## 4. Runtime hash across instances — the check people skip

"This bytecode is identical for 85/255 tokenIds" is an observation, not a finding. Hash the runtime of
several instances and require them to **differ**:

```python
for tid, addr in sample:
    c = rpc("eth_getCode", [addr, "latest"])["result"]
    print(addr, (len(c)-2)//2, hashlib.sha256(c.encode()).hexdigest()[:16],
          rpc("eth_call", [{"to": addr, "data": "0x17d70f7c"}, "latest"]))   # tokenId()
```

```text
0x14f247ce…  3874  a384d269b00d465a  tokenId -> 0x49b165e8…
0x6265338f…  3874  aadb4fd7ade89901  tokenId -> 0x4f3b5369…
0xfb0fadd3…  3874  e91cae511228a78c  tokenId -> 0xa09361e6…
```

Same length, **different hash, different immutable** → independent contracts, no shared implementation,
no single write target. This is the single most convincing artifact for the "not a clone" argument.

---

## 5. Write-site census for the trusted address

The bypass branch is only exploitable if *something* can write the mapping. Find every writer:

```bash
grep -n "erc20Views\|<mapping name>" contracts/*.sol
```

Session result — exactly one writer, guarded and idempotent:

```solidity
function _createERC20View(uint256 tokenId) internal returns (address) {
  if (erc20Views[tokenId] != address(0)) return erc20Views[tokenId];  // L543 idempotent
  ERC20View erc20View = new ERC20View(tokenId);                       // L547 CREATE
  erc20Views[tokenId] = erc20ViewAddress;                             // L550 only write
}
```

Confirm no `setERC20View` / `updateERC20View` / address-typed param exists in the public ABI (§6).

**Three-way bifurcation of "predictable address":**

| `new`/CREATE opcode | attacker can pre-place code? | verdict |
|---|---|---|
| `CREATE` (nonce-derived, predictable) | yes, front-run the nonce | **DoS only** — `new` reverts on collision |
| `CREATE2` (salt-derived, predictable) | yes, but only if salt is attacker-influenced | DoS, or a real hijack if they control the salt *and* the first deploy |
| `new` behind `if (mapping != 0)` idempotent guard | no | none |

Predictable ≠ hijackable. A successful pre-placement makes the *legit* deploy revert — that is
**availability**, not theft. Grade it LOW/INFO and say "requires predicting the deployer's exact nonce
and front-running the first creation for that id".

---

## 6. Explorer triangulation: ABI, txhistory, creation events

Three cheap requests that turn "maybe an admin path exists" into a closed question.

```text
1. action=getabi               -> enumerate functions; 0 setter/owner/upgrade/initialize = closed
2. action=txlist&sort=asc      -> methodId histogram of EVERY tx ever
3. logs topic0=keccak("Created(uint256,address)")  -> one event per id? duplicates = a re-point path
```

Session: 10 lifetime txs on the view = 9× `a9059cbb` (transfer) + 1× `095ea7b3` (approve);
**0 administrative**. Creation events: 255 events / 255 unique ids / 255 unique addresses → no id was
ever re-pointed. Loop the explorer pages (`page=1..10, offset=255`) — the first page looked complete but
was 25% of the set, and "255 unique addresses" is a far stronger claim than "10 pages returned rows".

---

## 7. The positive controls that make the negatives mean something

A REFUTED built only on reverts is worthless. Pin the instrument first:

| control | expected | what it proves |
|---|---|---|
| `name()` / `hub()` / `tokenId()` on the view | decodes | your selector encoding + RPC are right |
| `erc20Views(id)` on the parent | == the view you are testing | you are attacking the real registered instance |
| `totalSupply(id)` on the parent | nonzero **and changing** | the token is live, not a dummy id |
| `setSomething(...)` from `0x…dEaD` | revert `0xe2517d3f` + args + role hash | AccessControl is actually enforced on this contract |
| **`initialize()` sent to an EOA** | `{"result":"0x"}` (success, empty) | **the RPC does NOT fake reverts for nonexistent code** |
| `PUSH4` scan on a known selector | hit | the scan itself works |

That EOA row is the one people miss. If `eth_call` to a plain EOA returns `0x` rather than an error,
then a revert from a contract is the contract's own revert — not an RPC artifact. Without it, "it
reverted" is uninterpretable.

---

## 8. Residual risks to report instead of a finding

When the takeover fails, do not end with "nothing". Harvest the real observations:

- **CREATE-collision DoS** (§5) — LOW/INFO, availability only.
- **Silent no-op emitters.** `emitTransferEvent(...)` / `emitApprovalEvent(...)` guarded by
  `if (msg.sender == hub) { emit ...; }` — anyone can call them and get success with **no event**. Not a
  spoofing vector (good), but worth one line so nobody re-hunts it as an event-injection bug.
- **The bypass branch is the *only* allowance gate in the parent.** If it is immutable and
  unwritable, the parent's allowance logic is the sole gate — say so, and note that the parent's
  allowance check must therefore be audited on its own merits (it is a separate angle; here it panicked
  with `0x4e487b71`+`0x11` on a zero allowance, i.e. a cap that holds).
- Closing sentence: *"<mapping[id]> cannot be re-pointed: no initializer exists, the config is
  immutable, the instance is not a clone, all 255 instances hash differently, and exactly one guarded
  internal write site exists. No attacker gains allowance authority over any holder."*

---

## Pitfalls

- **"Same size everywhere" ≠ clone.** Only the EIP-1167 prefix proves a clone; only a differing runtime
  hash disproves shared code.
- **A PUSH4 hit is not a selector.** In the session, 14 of the 29 `PUSH4` operands were compiler
  constants / dead code, none present in the verified ABI. Rank candidates by "is it in the ABI and does
  a call return decodable data".
- **Don't call the angle DEAD until the ABI is checked.** Source + bytecode can both look closed while
  the verified ABI still exposes a setter (`setERC20View`) — check all three.
- **`initialize` absence has three independent confirmations** (source grep, bytecode scan, live call +
  ABI). Report all three; a triager will ask for the second and third.
- **Do not write the mapping's trusted address into the report as "safe" without the write-site count.**
  The count is the evidence.
