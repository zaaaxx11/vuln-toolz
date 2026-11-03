# Live-bytecode dispatcher forensics: proving "the repo is not the deployment" from the bytecode itself

Condensed from a Relay Protocol round where the question was *"is the Solidity repo actually the
code running at `0xDDD3…9318`?"*. Two prior references had proved **value identity**
(`eip712Domain()` + typehashes + selectors, `signature-gated-entry-writes-and-bytecode-identity.md`
§4) and refuted **layout identity** (`totalSupply` at slot 6 live vs 3 repo,
`rpc-census-supply-integrity-and-role-enumeration.md` §4). This file answers the third and hardest
version: **read the runtime bytecode and enumerate what it can actually reach.**

The reusable content is a five-step method, and one **near-miss that produced a false
"14 hidden functions" claim** — the most instructive part, because the extraction technique was
sound and the *interpretation* was not.

Companions: `live-rpc-forensics-and-eth-call-trap.md` §2 (verified-source diff — try that first),
§16/§16f (domain identity, value ≠ layout), and `signature-gated-entry-writes-and-bytecode-identity.md`
§4 (the 6-call identity proof).

**When the repo-line finding you are trying to license is a digest-membership claim** (a signed
struct field, or an `execute()` *parameter* that steers where funds go), read
`eip712-field-binding-and-unsigned-parameters.md` instead of re-deriving the field list by hand: it
carries the mechanically-generated binding table, the "a parameter is structurally unexpressible in
the digest" class, and the `INPUT − MIN_OUT` quantification that makes the finding defensible.

**Section list:** §1 when to reach for disassembly at all · §2 extract candidate selectors ·
§3 **the bit that matters: validate every jump target against real `JUMPDEST`s** · §4 interpret
correctly (diff ≠ vulnerability; dead branch ≠ backdoor) · §5 the behavioural control that closes it ·
§6 **the near-miss, and the two hypotheses that explain dead dispatcher branches** · §7
consequences for every earlier source-level finding · §8 re-runnable script pointer ·
**§9 the POSITIVE case — proving byte-EXACT equality (a sibling contract, same protocol: 17/17
selectors live, 0 dead branches, 0 residual bytes)** · §9a unlinked-artifact placeholders and
immutable-slot normalisation, the two things that make a correct diff look wrong · §9b the
`SHL` phantom-selector trap · §9c the `op == 0x5b` membership bug that fakes "everything is dead" ·
§9d recomputing the EIP-712 digest as the strongest logic-identity proof · §9e creation-block
bisection when "no logs" makes role holders look absent ·
**§10 why you run §9 on the contract carrying your BEST finding, and ship §7+§9 as one sentence
(a divergent Hub + a byte-exact Executor is what re-licenses the repo-line CRITICAL)** ·
§10a address resolution from a truncated handover, and the "no getter points that way" trap ·
**§11 the EIP-712 domain-layer census — the 6-call routine kill for cross-contract/cross-chain replay,
plus the `DOMAIN_SEPARATOR()`-doesn't-exist-on-OZ-v5 correction.**

---

## 1. WHEN TO DISASSEMBLE — and when not to

Cheapest first. Do **not** start here:

| Question | Method | Cost |
|---|---|---|
| Is the logic the same? | `eip712Domain()` + `TYPEHASH()` + `cast selectors` (identity file §4) | ~6 calls |
| Is the storage layout the same? | slot-race with a repo-slot negative control (census file §4) | ~4 calls |
| Is the *source* the same? | Blockscout `/api/v2/smart-contracts/$A` + whitespace-normalised diff (`live-rpc` §2) | 1 call |
| **What can this bytecode actually reach?** | **disassembly + jump-target validation (this file)** | ~10 min local |
| Is the *deployed* code even my checkout? | **ABI + struct-order diff + live gate probe → `source-vs-deploy-parity-and-gate-probes.md`** | ~2 min |

Reach for disassembly when: the contract is **unverified** (no source to diff), or when a selector
inventory shows functions the repo does not declare and you need to know whether they are *live* or
*vestigial*. On this target both were true at once, and the honest answer turned out to be
"vestigial" — which the disassembly proved and a selector dump alone could not.

```bash
curl -s -m 60 -X POST $RPC -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["'$A'","latest"]}' \
  -o /tmp/hub_code.json
python3 -c "import json;c=json.load(open('/tmp/hub_code.json'))['result'];open('/tmp/live.hex','w').write(c);print('bytes:',(len(c)-2)//2)"
# → bytes: 13864
```

## 2. EXTRACT CANDIDATE SELECTORS — decode the opcode stream, never grep the hex

`grep`-ing a hex blob for a selector string is wrong twice over: it matches inside `PUSH` immediates
that are *constants*, and it misses selectors split across the stream. Decode properly:

```python
B = bytes.fromhex(open('/tmp/live.hex').read().strip()[2:])
ins, i = [], 0
while i < len(B):
    op = B[i]
    if 0x60 <= op <= 0x7f:                      # PUSH1..PUSH32
        n = op - 0x5f
        ins.append((i, f"PUSH{n}", B[i+1:i+1+n].hex()))
        i += 1 + n
    else:
        ins.append((i, op, None))               # keep op as int; name it later
        i += 1
```

**Then match the real dispatcher idiom**, which is a comparison, not a bare constant:

```
DUP1  PUSH4 <sel>  EQ|GT|LT|SLT  PUSH2 <target>  JUMPI
```

Solidity emits **binary search** for larger contracts, so `GT`/`LT`/`SLT` appear alongside `EQ`.
Matching only `PUSH4 + EQ` undercounts; matching only `PUSH4` overcounts badly (66 raw `PUSH4`
immediates vs **48** real dispatcher entries on this contract — the extras were constants like
`0x05f5e100` = 100000000 and embedded error selectors).

```python
CMP = {0x10:"LT", 0x11:"GT", 0x12:"SLT", 0x13:"SGT", 0x14:"EQ"}
found = {}
for idx,(pc,name,imm) in enumerate(ins):
    if name == "PUSH4" and imm and imm != "00000000":
        for j in range(idx+1, min(idx+3, len(ins))):
            if isinstance(ins[j][1], int) and ins[j][1] in CMP:
                found[imm] = (pc, CMP[ins[j][1]]); break
```

Resolve names with `cast 4byte <sel>` in a loop, and **treat `cast 4byte` misses as unknown, not as
"hidden"** — 4byte coverage is incomplete and a miss means nothing on its own.

## 3. VALIDATE EVERY JUMP TARGET — this is the step that decides "hidden function" vs "dead code"

The selector table alone is **not** evidence that a function is callable. A `JUMPI` to an address
that is not a `JUMPDEST` cannot be taken; the EVM reverts on the invalid jump. So for each
`PUSH4 <sel> EQ PUSH2 <tgt> JUMPI`, resolve `<tgt>` and check it appears in the linear-sweep
`JUMPDEST` set:

```python
jumpdests = {pc for pc,op,_ in ins if op == 0x5b}
d = {pc:(nm,imm) for pc,nm,imm in ins}

good, bad = [], []
for pc,nm,imm in ins:
    if nm == "PUSH4" and imm:
        # PUSH4 at pc, EQ at pc+5, PUSH2 at pc+6, JUMPI at pc+9
        if d.get(pc+5,(None,))[0]==0x14 and d.get(pc+6,(None,))[0]=="PUSH2" and d.get(pc+9,(None,))[0]==0x57:
            tgt = int(d[pc+6][1], 16)
            (good if tgt in jumpdests else bad).append((imm, tgt))
print(f"valid: {len(good)}   INVALID: {len(bad)}")
```

Result on this contract:

```
valid targets: 34      INVALID targets: 14
```

and every one of the 14 mapped to an address with no `JUMPDEST`:

| Selector | Function | JUMPI target | `JUMPDEST`? |
|---|---|---|---|
| `06fdde03` | `name()` | `0x0ef` | ❌ |
| `095ea7b3` | `approve(address,uint256)` | `0x10d` | ❌ |
| `17d70f7c` | `tokenId()` | `0x130` | ❌ |
| `18160ddd` | `totalSupply()` | `0x165` | ❌ |
| `23b872dd` | `transferFrom` | `0x16d` | ❌ |
| `313ce567` | `decimals()` | `0x180` | ❌ |
| `365a86fc` | `hub()` | `0x19a` | ❌ |
| `3c130d90` | `tokenURI()` | `0x1d9` | ❌ |
| `70a08231` | `balanceOf(address)` | `0x1e1` | ❌ |
| `95d89b41` | `symbol()` | `0x1f4` | ❌ |
| `a6d49dca` | `emitTransferEvent` | `0x1fc` | ❌ |
| `a9059cbb` | `transfer` | `0x211` | ❌ |
| `dd62ed3e` | `allowance` | `0x224` | ❌ |
| `f23b6fa2` | `emitApprovalEvent` | `0x237` | ❌ |

**Do not skip this check.** Without it, the previous step's output — "14 functions exist in the live
bytecode that the repo does not declare" — reads as *14 hidden entrypoints*, which is a fabricated
CRITICAL. With it, the same data reads *14 unreachable branches*, which is a compiler/upgrade artefact.

**Sanity constant worth knowing:** this contract's linear sweep found **496** valid `JUMPDEST`s across
8,534 instructions. A wildly different count (tens) means your sweep desynchronised — almost always
because a `PUSHn` immediate was swallowed as opcodes, or vice versa. Verify the sweep by checking that
the standard dispatcher prologue decodes cleanly before trusting any downstream count.

## 4. INTERPRET CORRECTLY — three claims to keep strictly apart

The same bytecode supports three very different statements. Shipping the wrong one wrecks the report:

| Claim | Evidence needed |
|---|---|
| "The live bytecode implements an ERC-20 interface the repo does not" | selector table only — **weak**, ABI ≠ bytecode behaviour |
| "The live bytecode is not this repo's build" | selector diff **+** dead branches **+** slot drift (census §4) — **strong** |
| "There is a hidden callable function" | valid jump target from a `JUMPI` **and** a behavioural call that succeeds — **must be proven, not inferred** |

This round established the **second** claim and explicitly declined the third:

> **Proven:** live bytecode ≠ compilation of repo `RelayHub.sol`. The strongest evidence is not the
> ABI diff (ABIs diverge without bytecode diverging) but **three inserted storage variables** plus
> **14 dispatcher branches jumping to non-`JUMPDEST` addresses**.
> **NOT proven:** exploitability. A dead branch is a revert, not an entrypoint. **Zero funds moved,
> zero privilege gained.** This is an audit-baseline correction, not a bounty finding.

The ERC-standard shape change was consistent and worth one line: live exposes
`balanceOf(address)`/`name()`/`transfer` (ERC-20) while the repo declares
`balanceOf(address,uint256)`/`name(uint256)` (ERC-1155) — and the two repo-only selectors
(`00ad800c`, `00fdd58e`) are absent from the live dispatcher entirely.

## 5. THE BEHAVIOURAL CONTROL — an `eth_call` that separates "needs args" from "cannot be reached"

`execution reverted` is ambiguous on its own: an unknown selector, a missing argument, and an invalid
jump all produce it. **You need a successful control in the same call batch.** Otherwise you cannot
tell "dead branch" from "I called it wrong" — which is exactly the mistake that produced a retraction
in `live-rpc` §16g.

```bash
# controls: selectors whose jumps ARE valid
cast call $A "OPERATOR_ROLE()(bytes32)"   # → 0x97667070c5…4fa9b929   ✅ data
cast call $A "ADMIN_ROLE()(bytes32)"      # → 0xa4980720…93c21775     ✅ data
cast call $A "DEFAULT_ADMIN_ROLE()(bytes32)"  # → 0x0000…0000        ✅ data

# dead branches
cast call $A "name()(string)"        # → execution reverted
cast call $A "totalSupply()(uint256)"# → execution reverted
cast call $A "balanceOf(address)(uint256)" 0x1111…1111  # → execution reverted

# and the repo-only ERC-1155 signatures actually SUCCEED:
cast call $A "name(uint256)(string)" $TID   # → 0x…0020 + zero-padded string
```

That last pair is the whole argument in two lines: the *repo's* selector answers, and the
*selector-table-only* ones do not. Note the direction — it inverts the naive reading. A selector that
appears in the dispatcher table is not thereby callable.

## 6. THE NEAR-MISS — how a sound method produced a false claim, twice, in ten minutes

Recorded because the method is right and the *inference* is what failed, identically to
`live-rpc` §5a/§16g.

1. **First wrong turn — "32 hidden selectors."** A bare `PUSH4` scan returned 66 immediates, 32 of
   which had no repo match. Reading that as "32 undocumented functions" is tempting and wrong: most
   were constants (`0x05f5e100` = `100000000`) and OZ error selectors
   (`0x4e487b71` `Panic(uint256)`, `0xf645eedf` `ECDSAInvalidSignature()`). **Filter to the
   dispatcher comparison idiom (§2) before counting anything.**
2. **Second wrong turn — "14 hidden ERC-20 functions."** Filtering properly left 14 real dispatcher
   entries. Still not callable — the `eth_call` controls in §5 were what exposed it.
3. **Third, and the one that resolved it — jump-target validation (§3).** All 14 targets were
   non-`JUMPDEST`.

**Two hypotheses explain dead dispatcher branches, and you should state them as hypotheses:**

- **Stripped-upgrade artefact** — an interface (here: ERC-20) was added and later disabled by shifting
  code, leaving a stale selector table behind.
- **Compiler layout divergence** — the deployment was built with different inheritance/source than the
  repo, so jump tables were generated for a layout that no longer holds.

Both mean the same operational thing: **the repo is not the source of truth for this contract.** Do
not pick between them without a build to compare against.

**The transferable rule:** *a selector in the dispatcher table is a hypothesis; a valid `JUMPDEST`
target plus a succeeding `eth_call` is evidence.* Validate before you name a function "hidden".

## 7. CONSEQUENCE — relabel every earlier source-level finding

This is the real deliverable of a bytecode-identity round, and it is uncomfortable by design. Once
"repo ≠ deployment" is proven, every finding whose evidence is a *repo line number* loses its live
guarantee:

| Finding | Evidence basis | Status against live |
|---|---|---|
| Digest omits `callResolver` (C6/R10) | repo `RelayExecutor.sol:132-137` | **not verified** against live |
| `setEntry` hijack (R24) | **live bytecode directly** (typehash + domain + selectors + real tx decode) | **holds** ✅ |
| Protobuf guard, allocator auth | repo only | **not verified** |

The rule that follows, and it is the reason to do this work at all:

> Findings proved **directly against live bytecode** (typehash, domain separator, selector, decoded
> production calldata) survive a repo/deployment split. Findings proved only against a **repo line
> number** do not — they must be re-derived from the bytecode or downgraded to "repo-level defect,
> live applicability unproven".

Closing move: identify which surviving findings are bytecode-proved, and say plainly which of the
strongest ones now carry a caveat. On this target the top-impact finding (C6/R10) moved from
"PROVEN" to "repo-verified, live unverified" while a MEDIUM (R24) became the most defensible item —
an inversion that the report has to state rather than hide.

## 8. RE-RUNNABLE SCRIPT

`scripts/evm_dispatcher_audit.py` implements §2+§3 against a live address: fetches code, decodes the
opcode stream, extracts the `PUSH4+cmp` dispatcher table, validates every jump target against real
`JUMPDEST`s, diffs the result against a supplied ABI JSON, and prints the valid/invalid split with a
loud warning when `invalid > 0`. Run it instead of hand-writing a fourth variant of the sweep.

---

# §9. THE POSITIVE CASE — proving the deployed code is byte-EXACTLY the repo build

The Hub round above proved **inequality** (14 dead branches, slot drift). A later round on the
**sibling contract of the same protocol** (`RelayExecutor`, `0x6747c7e6…bc0c`) asked the opposite
question and got the opposite answer — which is the more common and more useful outcome:

```
Total live selectors                      17
Matched to repo ABI                       17
Live-only (absent from repo)               0
Dead branches (invalid jump target)        0
Storage drift                             NO
Residual byte differences outside immutables  0
```

**Both rounds used the same method.** That is the point: the pipeline that finds dead branches
should be run even when you expect none, and "0 dead" is a *finding* worth shipping — it licenses
every repo-line-number finding in the report (the inverse of §7's relabelling problem).

Reusable deltas this round added to §1–§8:

| Step | What to do |
|---|---|
| Region bound | Take the dispatcher region as `pc 0 .. <target of the calldatasize<4 guard>`. Comparisons outside it are *body* comparisons (see §9b). |
| Pivot vs entry | A constant with **only** `GT`/`LT` is a binary-search pivot. A constant with an `EQ` whose target is a valid `JUMPDEST` is an **entry**. Classify on that, never on "has any comparison". |
| Completeness | Prove the ABI is complete in both directions: repo-only count must also be 0. A selector diff that only reports live-only subscribes to the fantasy that the repo can't be *missing* live code. |

## §9a. Two things that make a CORRECT diff report a mismatch (both are tooling, not the target)

**1. Unlinked library placeholders.** `forge build` output for a contract that uses a non-inlined
library contains `__$<34-hex-char-hash>$__` where the 20-byte library address belongs. A naive
`repo_bytes == live_bytes` therefore **always** differs, and the difference looks like a source
delta. Resolve from the artifact's own link map first:

```python
dep = art["deployedBytecode"]
for f, libs in dep["linkReferences"].items():
    for lib, refs in libs.items():
        for r in refs:            # r = {"start": byte_offset, "length": 20}
            print(r["start"], ".hex()[start*2:…] =", obj[r["start"]*2:(r["start"]+r["length"])*2])
# → __$1902c390c93916f9a8eabb998427d3b515$__  at bytes 968, 3222, 5115
```

Then substitute the **live** library address recovered from the live code at those same offsets
(here all three were `0xecd3184b…b3761b6`, which also cross-checks against the deployment inventory).

Three parsing traps inside this one step, each of which cost a run:

- **The placeholder is `73__$hash$__`, not `__$hash$__`.** The leading `73` is a real `PUSH20`
  opcode; replacing the whole token silently corrupts the code. Replace **only** `__$hash$__`.
- **`deployedBytecode.object` starts with `0x`**, which `bytes.fromhex` rejects outright
  (`ValueError: non-hexadecimal number found … at position 1`). `.removeprefix("0x")`.
- **Don't infer "unlinked" from a length mismatch.** Here repo and live were *identical lengths*
  (9131 both) and still differed — length equality is not evidence of linkage.

**2. Immutable slots legitimately differ per deployment.** Constructor-set `immutable`s
(`HUB`, `ALLOCATOR`, cached `address(this)`, `_cachedChainId`, EIP-712 `_hashedName`/`_hashedVersion`/
domain separator) are baked into the runtime code at fixed offsets. Compare **byte ranges from the
compiler's own `immutableReferences`**, don't eyeball them:

```python
imm = [(r["start"], r["start"]+r["length"]) for refs in dep["immutableReferences"].values() for r in refs]
raw    = [i for i in range(len(R)) if R[i] != L[i]]
resid  = [i for i in raw if not any(a <= i < b for a,b in imm)]
print(len(raw), "differing bytes;", len(resid), "OUTSIDE immutables")
# → 334 differing bytes; 0 OUTSIDE immutables
```

`resid == 0` **is** the proof of byte-exact equality. Report it exactly that way — "334 bytes differ,
all inside 17 compiler-declared immutable ranges, 0 residual, identical CBOR metadata tail" is far
stronger than a bare "matches".

**Then check the immutables are semantically right, not merely "allowed to differ".** A wrong
constructor argument is a real finding hiding inside a normalised slot:

```python
# astId → value, decoded from the live code at each range
49199 → 0x…6747c7e6…bc0c   == address(this)                    ✅
49197 → 0x83471 = 537713   == eth_chainId                       ✅
49206 → "RelayExecutor"    == EIP712 name short-string          ✅
4420  → "1"                == EIP712 version                    ✅
6585  → keccak("RelayExecutor")   == _hashedName                ✅
6625  → keccak("1")              == _hashedVersion              ✅
6504  → keccak(0x1901‖…)         == recomputed domainSeparator  ✅  ← see §9d
```

## §9b. THE `SHL` PHANTOM SELECTOR — a `PUSH4` operand is not a dispatcher entry

§2's constant-filter does not catch this one, because the `PUSH4` **is** followed by `EQ` a few
instructions later. The pattern that invents a function out of thin air:

```
     801: SUB
     802: NOT
     803: DUP3
     804: AND
     805: PUSH4 7965db0b      ← looks exactly like a dispatcher entry
     810: PUSH1 e0
     812: SHL                 ← …but it is an operand to SHL
     813: EQ                  ← comparing two in-memory values, NOT the calldata selector
```

This is the body of `supportsInterface(bytes4)`, comparing `type(X).interfaceId` constants. A
"`PUSH4` followed (within k instructions) by `EQ`" classifier reported it as an 18th selector and
"live-only ⇒ undocumented function". Two cheap discriminators, use both:

1. **Region bound** (§9 table): entry comparisons live in the dispatcher region, `pc <` the
   calldatasize-guard target. This one is at `pc 805`, far outside.
2. **Behavioural negative control**: `cast call $A 0x7965db0b` → `execution reverted`. A real
   entry point cannot revert *and* be listed; with 0 dead branches, a revert on a selector means
   "not in the dispatch table", full stop.

Note the subtlety that makes this dangerous: `supportsInterface(0x7965db0b)` returns **`true`** — the
constant is genuinely used. So a "does it respond?" probe on the *right* function says yes, and on
the *left* one says no. Only the calldata-prefix call distinguishes them.

## §9c. THE `op == 0x5b` MEMBERSHIP BUG — how to fake "all 17 branches are dead"

Worth its own section because the failure mode is *symmetric to the finding*, so it reads as a
spectacular result rather than a bug. One decode used name-keys and one used raw ints; the
membership test compared them:

```python
ins = [(pc, f"op{op:02x}", None), …]                 # names like "op5b"
jumpdests = {p for p, n, _ in ins if n == "JUMPDEST"}   # ← NEVER matches "op5b"
# …
DEAD (target not JUMPDEST): 17 ['75b238fc', '9f1a1c03', …]   ← every single selector
```

**The tell is the shape of the result, not the code:** *every* entry failing is never a target
artifact — a real contract does not have 100% dead branches (the Hub, the worst case seen, was 14/48).
When your dead-branch count equals your selector count, the bug is in the junction between two
representations in your own script.

Guards to build in:

- **Derive the JUMPDEST set and the comparison scan from the same decode.** Never let one path use
  names and the other use opcodes.
- **Assert a known-good selector passes first.** Pick the selector you have already proven callable
  via `cast call` and assert its target is in `jumpdests` before interpreting anything else.
- **Print the raw count next to the interpretation** (`valid JUMPDEST count: 322`) so a zero-width set
  is visible immediately.
- **The overcount is itself a sanity signal:** naive `0x5b` byte count was **330** vs **322** decoded
  `JUMPDEST`s. Those 8 bytes are `0x5b` operands of `PUSHn`, i.e. data, not jump targets. If those two
  numbers are equal, suspect a decode that isn't skipping `PUSH` immediates at all.

## §9d. RECOMPUTE THE EIP-712 DIGEST — the strongest logic-identity proof available

`eip712Domain()` + a `TYPEHASH()` getter prove those *values* match. They do not prove the contract
**uses** them in the order/encoding the repo does. For any contract with a `view` hashing function
(here `hashExecuteAndWithdrawRequest`, no signature required), call it and recompute the same digest
offline from the repo's source string. Equality proves typehash string, field order, and domain
separator all at once — a tampered TYPEHASH or reordered struct cannot reproduce the value.

```bash
cast call $EXEC "hashExecuteAndWithdrawRequest((...))(bytes32)" \
  "(relay,0x,relay,0x,0,0x,0x..01,0x,0x,[],0x00..00,0)"
# → 0x98c17e4d83a7f947a02d6f0c3fc304eb82aaf0e5b1b067f5c2cfd5b76ca34768
```

```python
TY  = keccak(text="ExecuteAndWithdrawRequest(...)Fee(address recipient,uint256 amount)")
structHash = keccak(TY + keccak(text="relay") + keccak(b"") + keccak(text="relay") + keccak(b"")
                    + (0).to_bytes(32,"big") + keccak(b"") + order_addr_padded
                    + keccak(b"") + keccak(b"") + keccak(b"")      # fees[] empty ⇒ keccak("")
                    + bytes(32) + (0).to_bytes(32,"big"))
digest = keccak(b"\x19\x01" + domain_separator + structHash)
# → 0x98c17e4d…   MATCH ✅
```

Encoding rules that decide whether your recomputation is admissible (same law as `live-rpc` §16c —
mirror the *literal* expression):

- `bytes`/`string` fields are hashed **individually**: `keccak(value)`, then the 32-byte result is a
  struct member. Not `abi.encode(...)` of the whole tuple.
- A dynamic array member is `keccak(concat of encoded elements)`; **empty array ⇒ `keccak("")`**, not
  `bytes32(0)`.
- `address` is left-padded to 32 bytes; `uint256` big-endian.
- The prefix is `\x19\x01`, then the domain separator, then the struct hash.

Choosing the probe args: pick the all-zero/shortest legitimate values (`""`, `0x`, empty array,
zero nonce/deadline) so the recomputation has the fewest encoding branches to get wrong. One
verifying value is enough to license the whole scheme.

## §9e. "NO LOGS" ≠ "NO ROLE HOLDERS" — bisect the creation block for the constructor args

The trap, in full, because it produced **two consecutive wrong statements in one report**:

```
logs ever emitted by executor (any topic) = 0
nonce = 0, balance = 0
hasRole(ADMIN_ROLE, protocolSafe)  = false
hasRole(ADMIN_ROLE, executor)      = false
hasRole(ADMIN_ROLE, <6 infra addrs>) = false for all
```

The natural reading — "deployed but unstaffed, no role holders" — is **wrong**. Storage proved
`_roles[ADMIN_ROLE].adminRole == ADMIN_ROLE`, i.e. the constructor *did* run `_setRoleAdmin`, so an
admin must exist. The admin was simply an address nobody had thought to probe.

**Find it from the deployment tx.** Historical `eth_getCode` works on this RPC, so bisect to the
exact creation block and read the constructor args off the deployment calldata:

```python
# bisect: first block where code is present
def has_code(n): return len(rpc("eth_getCode",[A,hex(n)])["result"]) > 2
lo, hi = 0, int(rpc("eth_blockNumber",[])["result"],16)
while lo + 1 < hi:
    mid = (lo+hi)//2
    if has_code(mid): hi = mid
    else:             lo = mid
# → first block WITH code: 2874304, last WITHOUT: 2874303
tx = rpc("eth_getBlockByNumber",[hex(2874304),True])["result"]["transactions"]
# creation tx has to == null / ""
# input tail: constructor args are the last 3×32 bytes (after immutable/creation code)
admin, hub, allocator = [ "0x"+w[24:] for w in [tail[0:64], tail[64:128], tail[128:192]] ]
# → admin      = 0xf61a305199fa1135d76ffab3752d42f55cbd775a
# → hub        = 0xddd361727c22a01eb137880678a20b0beae69318   (== live HUB() immutable ✅)
# → allocator  = 0x613d3c588f6b8f89302b463f8f19f7241b2857e2   (== live ALLOCATOR() ✅)
```

Then verify the decoded admin **live**: `hasRole(ADMIN_ROLE, 0xf61a…)` → `true`. Two of the three
constructor args matching live immutables is what licenses trusting the third (the one with no getter).

**Payoff for storage-layout proof.** `_roles[ADMIN_ROLE].hasRole[admin]` is now a **non-zero** word,
which is the discriminator §4 of the census file could not run while every mapping looked empty:

```bash
cast storage $E $(keccak(admin ‖ keccak(ADMIN_ROLE ‖ 0)))   # → 0x…0001   base slot 0 ✅
cast storage $E $(keccak(admin ‖ keccak(ADMIN_ROLE ‖ 1)))   # → 0x…0000   negative control ✅
```

Two independent grants (ADMIN and ORACLE holders) giving the same 1/0 pair makes the slot-0
conclusion airtight — layout identity established with a **positive witness**, not by absence of
evidence. This is the concrete way to close §16f's "value identity ≠ layout identity" gap when the
target's own mappings are all empty.

**Also: re-probe role holders before asserting any absence.** The first draft of this section claimed
"no ORACLE_ROLE holder was found"; probing the multisig the protocol docs named showed
`hasRole(ORACLE_ROLE, 0x2a72…b0) == true` all along. The admin is the *deployer-independent*
constructor argument; the deployer EOA (`0xf3d6…691e`) was **not** privileged at all — an easy
inversion when reading deployment notes.

---

# §10. THE STRATEGIC USE OF §9 vs §7 — run BOTH contracts, and say which one is which

The two rounds above (§7 inequality on the Hub, §9 equality on the Executor) happened on the **same
protocol, same repo, same day**. That pairing is worth more than either result alone, and it is the
shape to aim for whenever a repo-vs-live question is open:

| | Hub (`0xDDD3…9318`) | Executor (`0x6747c7e6…bc0c`) |
|---|---|---|
| selectors live / matched / live-only | 48 / 34 / 14 | 17 / 17 / 0 |
| dead branches | **14** | **0** |
| storage drift | **yes** (3 slots) | no |
| residual bytes outside immutables | — (not built this way) | **0** |
| verdict | repo ≠ deployment | repo == deployment |

**Why you ship both sentences together:** the inequality result alone invites the objection *"maybe
your whole method is wrong / this repo is just stale everywhere"*. The equality result on a sibling
contract from the same repo refutes that objection and simultaneously **licenses the repo-line
findings for the matched contract only**:

> The Hub diverges but the Executor is byte-exact. That asymmetry proves the divergence is localized,
> and it is what makes the Executor's repo-line findings (C6/R10) shippable as live findings.

So the deliverable of a divergence round is not "everything is unverified" — it is a **per-contract
label table**, where exactly one column changes:

| Finding | Basis | Live status |
|---|---|---|
| `callResolver` outside digest (C6/R10) | repo line `RelayExecutor.sol:132-137` **+ byte-exact proof (§9)** | **PROVEN live** ✅ |

**The severity was later demoted to HIGH, and NOT because of any of the above.** Byte-exactness only
licenses *what the code does*; it says nothing about *who pays*. The follow-up round measured the
funder and found a burn, not a mint, no solver escrow, no replay and no batch ⇒ `HIGH` with the cap
`quote − MIN_OUT` per order. Full measurement, mechanism, and the three-probe recipe:
`eip712-field-binding-and-unsigned-parameters.md` **§10b**. Read it before writing a severity word on
any callResolver-class finding — the byte-exact proof here is necessary but not sufficient.
| `setEntry` hijack (R24) | live bytecode directly (typehash/domain/selector) | holds ✅ |
| Protobuf guard, allocator auth | repo only, no code-identity proof run | **unverified** ⚠️ |

The inversion this creates is the interesting part and must be stated, not hidden: at the start of the
day the top-impact finding was "proven" and a MEDIUM was secondary; after §7 alone the MEDIUM became
the most defensible item; after §9 the top-impact finding **regained** its standing because its
contract was byte-exact. **A finding's label moves in both directions during one hunt — track it per
contract, not per report.**

**Cost note:** §9 is ~10 minutes of local work once §2/§3 exist, and it is the difference between a
CRITICAL you can defend and a CRITICAL a triager kills with "is this even the deployed code?".
Run it on the contract that carries your best finding, first.

## §10a. ADDRESS RESOLUTION — nobody says "the executor"; you must derive it, and two traps

The brief handed over a truncated address (`0x6747c7e68b15b0c0e0e4e0e…`) and a *suggested* selector
to resolve it (`0x365a86fc`). **Both were wrong**, and the second one is the reusable trap:

- **No Hub getter returns the executor.** `0x365a86fc` is `hub()` — it is a getter *on the executor
  pointing back at the Hub*, i.e. the edge exists in the opposite direction from the one assumed.
  Cross-contract pointers are worth grep-ing in both directions before trusting a proposed resolver.
- **Resolve by self-consistency, then confirm by function:** take the candidate from prior artefacts
  (`/tmp/hunt7/`, `/tmp/f4/*.json`) and prove it by calling the contract's own getters —
  `HUB()` and `ALLOCATOR()` must return the addresses you already know from other rounds. Two
  independent immutable variables agreeing with the known inventory is the confirmation; a truncated
  hex string is not an address.

```bash
cast call $CAND "HUB()(address)"       --rpc-url $RPC   # → 0xDDD3…9318  (known Hub ✅)
cast call $CAND "ALLOCATOR()(address)" --rpc-url $RPC   # → 0x613D…57E2  (known Allocator ✅)
cast codesize $CAND                    --rpc-url $RPC   # → 9131, nonzero
```

Only then spend the ~10 minutes on §9. Resolving the wrong address produces a flawless proof about a
contract nobody asked about.

---

# §11. "RESOLVE THE DOMAIN LAYER" IS A ROUTINE KILL, NOT A ROUTINE FINDING — budget it as 15 minutes

The natural next hypothesis after `callResolver` (an unsigned *parameter*) is the **domain separator
itself**: cross-contract replay if two verifiers share name/version, cross-chain replay across the 59
chains Relay spans. It is a good hypothesis and it is almost always **dead on OZ v5**, in a way worth
knowing before you spend a round.

**The three-line census that closes it** — run on *every* EIP-712 verifier in the protocol, in one
batch:

```bash
cast call $C "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])" --rpc-url $R
```

| contract | name | chainId source | verifyingContract |
|---|---|---|---|
| RelayExecutor prod / staging | `RelayExecutor` | `block.chainid` | `address(this)` |
| RelayGenericMapping prod / staging | `RelayGenericMapping` | `block.chainid` | `address(this)` |
| RelayAllocator | `RelayAllocator` | `block.chainid` | `address(this)` |
| RelayHub | `RelayHub` | `block.chainid` | `address(this)` |

Every verifier has a **unique `name`** ⇒ no cross-contract collision; every `verifyingContract` is
`address(this)` ⇒ never zero/misconfigured; every `chainId` reads `block.chainid` ⇒ no stale
immutable. That is the whole class dead, and it took six calls.

**Two corrections to carry into future briefs:**

- **`DOMAIN_SEPARATOR()` does not exist on OZ v5** — it reverts. Only `eip712Domain()` is exposed.
  A brief that tells a worker to call `DOMAIN_SEPARATOR()` sends it chasing a phantom, and it will
  burn calls confirming absence. (Same family as the §10a truncated-address mistake: **the brief's
  suggested probe is a hypothesis, not a fact** — a worker that contradicts it is doing its job.)
- Staging deployments exist and are easy to mistake for duplicates. Enumerating **prod and staging
  pairs** is how you produce the confidence that the divergence found in §7 is localized rather
  than systemic — the same reason §10 ships both contracts.

**Report shape for this outcome:** it is a *refutation with a table*, which `live-rpc` §16d says to
ship with the same weight as a finding. "Cross-chain replay: dead, four verifiers, four distinct
names, `address(this)`, `block.chainid`" is a real deliverable — it stops the next round from
re-opening it, and it costs six calls instead of a delegation batch.


