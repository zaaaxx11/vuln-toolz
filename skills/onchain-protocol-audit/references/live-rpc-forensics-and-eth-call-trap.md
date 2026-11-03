# Live-RPC forensics: explorer fallbacks, verified-source extraction, and the `eth_call` state trap

Condensed from a Relay Protocol (settlement + oracle attestation) session where the public RPC
degraded mid-hunt and the *verification method itself* nearly produced a fabricated critical.
Companion to `references/evm-foundry-and-offchain-api-audit.md` (§10 covers source/deployment
drift; this file covers how you get the source and the logs when the RPC will not cooperate).

**Sibling reference — read it for counting at scale:**
`references/rpc-census-supply-integrity-and-role-enumeration.md` covers the *volume* problems this
file does not: RPC methods that name themselves in their own error text (`eth_getLogsWithCursor`),
`aggregate` vs `aggregate3` (+ the hand-rolled-encoder bug), block-pinning vs the "value moved
between two calls" false anomaly, storage-layout drift proven by slot-race with a negative control,
supply-integrity checks (`ΣbalanceOf ≠ totalSupply`, sink-address detection by
`codesize/nonce/balance == 0`), and a whole-manifest role census via batched `aggregate3` (per-address
`cast call` loops time out at ~49 addresses).

**Sibling reference — read it for signature-gated REGISTRIES/mappings:**
`references/signature-gated-entry-writes-and-bytecode-identity.md` is the authz-shape catalogue for
"write an entry for `user`" contracts: the `user`-is-a-free-parameter hijack (no `msg.sender`
binding ⇒ bearer-token signature ⇒ mempool front-run), the **global flat `usedNonces`** anti-pattern
(cross-user AND cross-typehash DoS from one `mapping(bytes32=>bool)`), no-overwrite ⇒ permanent
squat, the **6-call bytecode↔source identity proof** (`cast selectors $(cast code …)` + live
`TYPEHASH()` + `eip712Domain()` vs recomputed `cast keccak`), the "who sends the writes" frequency
bound that decides MEDIUM vs HIGH, the mirror-the-function Foundry pattern, and how to re-derive a
subagent's crypto claim in your own script instead of trusting its harness. **Also read §16f below
before trusting that identity proof for anything storage-related.**

**Section list:** §1 RPC timeouts → Blockscout `module=logs` · §2 verified source extraction +
the mandatory diff · §3 `erc20Views[id]`-style mappings are enumerable via their creation event ·
§4 **`eth_call` has no state — the trap that manufactures false positives** · §5 the
"approver without authorization" class, and how to bound it · §5a **THE RETRACTION: that class
was a misread — the guard was there, and here is why the trace fooled me** · §6 **only the
first 5–40 lines of a function body get read when you grep — the missing-guard root cause** ·
§7 **Foundry fixture failures (`AccessControlUnauthorizedAccount` in `setUp`) are harness bugs,
not findings — plus the real role-wiring each constructor needs** · §8 signature-freshness ·
§9 boundary-of-trust · §10 delegation budget · §11 **nested-tuple ABI decode offset trap (a bad
offset invented a fake chainId) + bytecode-as-truth when the build won't run** · §12 **two events,
one name — recompute the topic before believing a 0 count; mirror ERC20View is not a mintable
token** · §13 **`rate == capacity` means the token bucket limits nothing** · §14 **the five probes
that prove a mint path is dead, cheapest first** · §15 **all-`indexed` events live in `topics` (empty
`data`), swallowed parse errors fake a zero, and an RPC can return logs from the WRONG address
despite the `address` filter** · §16 **identifying an undeclared privileged contract via its
`eip712Domain()` name + `TYPEHASH` delta, not disassembly — and why "holds OPERATOR_ROLE" ≠ "can mint"** ·
§16b **an UNBOUND field is only a finding if a CONSUMER reads it (the consumer-re-derivation law)** ·
§16c **hash-encoding parity — reproduce the library's exact `abi.encode`, or your PoC numbers are fiction** ·
§16d **round-closing discipline — ship the refutation with the same weight** ·
§16g **"my probe reverted" ≠ "the contract is dead" — the DOUBLE-PROBE LAW, and the LOCKED-BUT-LIVE ghost closed by inbound-tx evidence** ·
§17 **identifying an unlabelled fronting contract by selector-census fingerprint (Multicall3 in seven calls) + the one probe that decides whether the wrapper is a bypass** ·
§18 **"sweep the whole balance" — the four reachability tests that separate design from theft, and why `panic 0x11` proves an absent ACL but not fundability** ·
§19 **the historical-data gate — `usedRequests`-style guards, the A/B/C three-variant matrix, and the INCONCLUSIVE-not-refuted verdict word** ·
§10.7 **`status=completed` + "artifact never written" = lost work — enforce the file write as the definition of done, and re-verify the shared forge build after every batch** ·
§10.9 **re-dispatch NARROWLY (one blocking question), not the same five-part brief**.

**Follow-on reference for §8's ordering rule:** when a signed-struct lead survives step 1 of §8, the
next move is not another reasoning pass — it is a forge-generated binding table plus the
"unsigned *parameter*" class in `eip712-field-binding-and-unsigned-parameters.md`. That file also
carries the `INPUT − MIN_OUT` quantification and the no-attacker-contract variant that survive
triage, and it is where the four §8 dead chains' method was generalised into a one-file proof.

---

## 1. RPC HANGS → BLOCKSCOUT `module=logs`, NOT `api/v2/.../logs`

**Symptom:** `cast logs --from-block 0 --to-block latest` on a busy contract:

```
Error: MPP HTTP request to https://rpc.chain.relay.link/ failed: ... operation timed out
```

Full-range `eth_getLogs` against a chain RPC is the single most common way to burn a round.
Public/indexer RPCs rate-limit or flat-out drop the request; the timeout reads like "the chain is
down" when it is really "your query was too wide".

**Two explorer APIs exist and only one takes a topic filter.** These are *different* APIs; mixing
them wastes calls:

```bash
# ✗ blockscout v2 address-logs: 422 "Unexpected field: topic0"
curl -s "https://explorer.chain.relay.link/api/v2/addresses/$HUB/logs?topic0=$T"

# ✓ blockscout v2 without a filter — works, newest ~50 only
curl -s "https://explorer.chain.relay.link/api/v2/addresses/$HUB/logs" -o /tmp/hublogs.json
#   → {"items":[{block_number, transaction_hash, decoded:{method_call, parameters[]}, ...}]}

# ✓ Etherscan-compatible module API — DOES take topic0 + full range
T=$(cast keccak "ERC20ViewCreated(uint256,address)")
curl -s "https://explorer.chain.relay.link/api?module=logs&action=getLogs&fromBlock=0&toBlock=latest&address=$HUB&topic0=$T" \
  -o /tmp/viewlogs.json
#   → {"status":"1","result":[{topics:[...],data:"0x",blockNumber:"0x2b56b",transactionHash:"0x…"}]}
```

Notes that cost calls:

- The `api/v2` endpoint returns **only the newest 50 items** — it is a UI feed, not a log query.
  If your answer needs the whole history (a registry, a factory census), it will silently lie by
  truncation.
- `/api?module=transaction&action=gettxinfo&txhash=…` also works and gives `from`/`to`/`methodId`,
  which is how you answer "who deployed/called this" without a full RPC.
- Piping a curl into `python3` in one shell command trips the security scanner
  (*"Pipe to interpreter"*). Write the file first, then parse it with `execute_code` — one fewer
  approval prompt and a reusable artifact.
- If a contract's source is *verified*, you rarely need `cast logs` at all: fetch the verified
  source (§2) and enumerate from the source's own event declarations.

---

## 2. VERIFIED-SOURCE EXTRACTION — then DIFF it against the repo, don't assume

The fast path to ground truth on a live target, and the one that made the whole session's code
reading valid:

```bash
curl -s "https://explorer.chain.relay.link/api/v2/smart-contracts/$ORACLE" -o /tmp/o_sc.json
```

Keys that matter: `name`, `is_verified`, `compiler_version`, `source_code` (main file),
`additional_sources[{file_path, source_code}]` (every import — this is how you get `RelayHub.sol`
when only `RelayOracleV2` is the verified entrypoint), `abi`.

**The mandatory diff** (whitespace-normalised, so formatting churn does not fake a mismatch):

```python
import json, re
d = json.load(open('/tmp/o_sc.json'))
norm = lambda s: re.sub(r'\s+', '', s)
add = {x['file_path']: x['source_code'] for x in d.get('additional_sources') or []}
open('/tmp/hub_verified.sol','w').write(add['contracts/RelayHub.sol'])
# then compare against the clone:
#   norm(verified) == norm(open('/tmp/relay-settlement/.../RelayHub.sol').read())
```

Two outcomes, both useful:

| Diff result | What it buys you |
|---|---|
| **identical** | every repo read is now a read of the live code — say so in the report, once, as the evidence baseline |
| **differs** | you found drift *before* building a finding on the wrong build (§10 of the technique-bank reference) — re-derive from verified source |

**Do not skip this because "the repo is probably the deployment".** One `diff` upgraded every
subsequent claim in the session from "repo says" to "deployed code says". Conversely, §10 of the
companion reference is the case where it would have saved a whole chain from being thrown away.

---

## 3. A MAPPING WITH NO GETTER IS STILL ENUMERABLE — via its creation event

`RelayHub` exposes `erc20Views(uint256 id) → address`, but you cannot guess the `id`
(`uint256(keccak256(abi.encodePacked(chainId, token)))` — see `Utils.generateTokenId`; a
plausible-looking keccak guess **reverts with `error code 3`**, which reads like a wrong function
when it is really a wrong key).

Instead of guessing, census from the registration event (§1) and read the contract's own
immutables back:

```bash
# topics[1] = tokenId, topics[2] = ERC20View address
cast call $VIEW "hub()(address)"      --rpc-url $RPC   # → equals $HUB  ("this view is Hub-authentic")
cast call $VIEW "tokenId()(uint256)"  --rpc-url $RPC   # → matches topics[1]
cast call $HUB  "erc20Views(uint256)(address)" $TOKENID --rpc-url $RPC  # → matches $VIEW
```

Three-way agreement (event ↔ view immutables ↔ hub mapping) is the proof that the view you are
about to reason about is genuinely wired to the target, not attacker-forged. On this target:
254 events, 254 unique tokenIds, 254 unique views, all agreeing — so the mapping census is
complete, not sampled.

**Corollary:** a contract deployed *by* the protocol (`hub = IHub(msg.sender)` in the constructor)
is not automatically *authenticated* by the protocol. Anyone can deploy a new `ERC20View`
pointing at the real Hub — the constructor only records `msg.sender`. If the Hub's privileged
functions key trust on "the caller is some ERC20View", the attacker-supplied sibling is inside
the trust boundary. Check whether the Hub keeps its own allowlist of views before concluding
either way (§5).

---

## 4. `eth_call` HAS NO STATE — the trap that manufactures false positives

The most dangerous false positive of the session. Sequence that produced it:

```bash
# 1. call a state-mutating function via eth_call and see it "succeed"
cast call $HUB "approveFor(address,address,uint256,uint256)(bool)" 0xdEaD 0xbEEF $T 5 --from $VIEW
# → true

# 2. trace it — the trace shows ONLY the emit, no revert
cast call --trace $HUB "approveFor(...)" ... --from $VIEW
# → emit Approval(owner:0xdEaD, spender:0xbEEF, amount:5) ; Return 0x…01 ; Gas 49336

# 3. read the state back — and get the OLD value
cast call $HUB "allowance(address,address,uint256)(uint256)" 0xdEaD 0xbEEF $T
# → 0        ← because the approveFor write evaporated with the eth_call
```

`eth_call` is a **simulation against the current state**. Every write it performs is discarded
when it returns. So:

- A successful `eth_call` proves **reachability + that no guard reverted** — it does *not* prove
  the state changed.
- Reading state back after an `eth_call` will ALWAYS show the pre-call value, no matter how
  correct the write is. `allowance == 0` after `approveFor` returning `true` is **not** evidence
  of a bug and **not** evidence of a fix.
- A nice extra: the deliberate second call to check persistence repeated the identical write, so
  even "prepare then execute" via two `eth_call`s cannot be chained. There is no persistence
  lane; stop trying.

**What to do instead** — pick the cheapest lane that actually commits or fully simulates:

1. `forge test --fork-url $RPC` with `assertEq(hub.allowance(...), expected)` after the call.
2. `cast call --trace` and read the **trace/logs** as the evidence (the `emit Approval(...)` line
   with the exact args *is* the proof that the write path executed; the gas figure proves it did
   real work), never the post-hoc getter.
3. `eth_simulateV1` / `anvil --fork` if available, then read state normally.

**Rule for the report:** `eth_call` output is admissible as *"the function is reachable and the
guard did not revert, args accepted verbatim"*. It is **never** admissible as *"state was
modified"* or *"an attacker can therefore steal"*. That sentence requires a fork test or a
broadcast tx with an explorer-visible hash.

---

## 5. THE "APPROVER WITHOUT AUTHORIZATION" CLASS — and how to bound it

Shape found on the live target:

```solidity
// RelayHub
function approveFor(address owner, address spender, uint256 id, uint256 amount) external returns (bool) {
    allowance[owner][spender][id] = amount;      // ← no msg.sender check anywhere
    _emitERC20ViewEvent(id, ...);
    emit Approval(owner, spender, id, amount);
    return true;
}
```

Confirmed by trace from an arbitrary `--from`: bare `emit` + `return true`, no revert, arg-order
accepted verbatim. Any caller can write any owner's allowance for any token id.

**Do not ship this as fund theft.** Bound it with three probes:

1. **Is the value-moving path gated by the allowance, or by the caller's identity?**
   `Hub.transferFrom` on this target skips the allowance branch when `msg.sender` is the
   registered `erc20Views[id]` — and reverts with `panic 0x11` (underflow) when the balance is
   short, which is the *balance* check talking, not the allowance. So the forged allowance buys
   nothing on its own.
2. **Who consumes `allowance(owner, X, id)` as authorization?** grep every consumer, not the
   writer. ERC20View consumes it *only* for `msg.sender != from` and decrements before the call.
   The real question is whether any privileged component (`Executor`, `Allocator`, `GasPayer`)
   treats a Hub allowance as a permission — if one does, the forgery becomes control-flow hijack
   and the severity jumps. **This is the hop that must be resolved before any severity word.**
3. **Is the sibling setter reachable?** On this target `isOperator` = `hasRole(OPERATOR_ROLE) ||
   _isOperator[account][operator]`, and `Allocator._submitWithdrawRequest` treats
   `isOperator(spenderAlias, msg.sender)` as sufficient authorization to `burn` a spender's
   balance. So the chain `forge approval/operator bit → pass `callerIsOperator` → burn → payload`
   is real *only if* the `_isOperator` writer is also unguarded. Read that writer before writing
   the chain. If it is gated, the whole branch is BLOCKED — record it as BLOCKED with the gate
   cited so the next session does not re-derive it.

Honest label while unresolved: **"broken access control on the allowance layer — PROVEN
unauthenticated write of `ApproveFor`; fund-theft impact UNPROVEN pending the operator-setter
read."** Naming the unresolved hop is what keeps the finding credible; asserting theft and being
wrong costs the whole report.

---

## 5a. THE RETRACTION — §5's class was a MISREAD. The guard existed; the trace lied by agreement.

A later round on the same target re-tested §5 with a Foundry harness and the whole class
**evaporated**. Writing it down because the failure mode is subtle and will recur.

**What the deployed code actually says** (`ERC20View`-gated, guard on the *second* statement):

```solidity
function approveFor(address owner, address spender, uint256 id, uint256 amount) public returns (bool result) {
  if (erc20Views[id] != msg.sender) {
    revert OnlyERC20ViewCanCallApproveFor(msg.sender, erc20Views[id]);
  }
  allowance[owner][spender][id] = amount;
  ...
}
```

**Why the `cast call --trace` "proof" was worthless.** The probe was
`cast call $HUB "approveFor(...)" ... --from $VIEW` where `$VIEW` was resolved as
`hub.erc20Views($TOKENID)` — i.e. **the single caller that the guard accepts**. The trace then
legitimately showed `emit Approval(...)` and `Return 0x…01` with no revert. I read "no revert from
an arbitrary `--from`" when in fact I had deliberately chosen the one `--from` that passes. The
`emit`-only trace looked like a missing guard because the guard *passed*; a passing `if (x) revert`
is invisible in a trace.

**Rule: a negative probe is only evidence if you also ran the POSITIVE-CONTROL probe.** Before
claiming "no guard", replay the same call from an address the guard is supposed to reject:

```bash
# control: a caller that is NOT erc20Views[id] MUST revert
cast call $HUB "approveFor(address,address,uint256,uint256)(bool)" $A $B $ID 1 \
  --from 0x000000000000000000000000000000000000dEaD
# → expect: execution reverted: OnlyERC20ViewCanCallApproveFor(...)
# If this SUCCEEDS, only then do you have the finding. If it reverts, the class is closed.
```

**Cheapest tell that a guard exists: grep the custom errors.** Every guarded path on an
audited-but-professional codebase declares a named `error`. One grep would have killed the
claim in one call:

```bash
grep -rn "error .*Only\|error .*Unauthorized\|error .*CanCall\|error .*NotAllowed" src/
# RelayHub.sol:45  error OnlyERC20ViewCanCallApproveFor(address caller, address expectedView);
# RelayHub.sol:306     revert OnlyERC20ViewCanCallApproveFor(msg.sender, erc20Views[id]);
```

The error name is the guard's signature. **Before writing "no check on function X", grep the
error declarations and confirm none of them is produced by X.** Relation to SKILL.md's
"reverse-engineer by revert selectors": errors you *find in source* are the inverse of that
technique — an undeclared error you cannot produce is a guard you have not found yet.

**Second tell, visible in the harness itself:** when the Foundry test called `approveFor` from the
attacker EOA it failed with `OnlyERC20ViewCanCallApproveFor(attacker, 0x037e…3f3)`. The revert
name was never in the code I had read (because I had read the *repo* build and reasoned from
memory of it) — a revert string you don't recognise is **proof you have not read the deployed
function body**. Stop analysis, re-read that exact function from the verified source, then
continue.

**Net cost of this miss:** one full round of the hunt, plus a retracted finding already put in
front of the user. The lesson is not "be careful" — it is **"an absence-of-guard claim requires a
positive control, always, no exceptions."**

---

## 6. THE MISSING-GUARD ROOT CAUSE: you only read the first 5–40 lines

§5a happened because the function *body* was never read past the pinned excerpt. Both of these are
the same failure, and it is the highest-frequency false-positive generator in access-control work:

1. **`sed -n 'A,Bp'` / `read_file offset+limit` windows that start at the function signature and
   end before the first `if`.** `approveFor(owner, spender, id, amount)` has four lines of
   parameter list before the body starts — a 40-line window starting at the signature often
   contains zero guard lines.
2. **`grep -n "^  function "` output treated as a function inventory.** That lists the `public`
   *declaration*; the gate is in the body (and sometimes in a modifier on the next line — see
   `evm-foundry-and-offchain-api-audit.md` §7a).

**Mechanical fix, before any authz claim:**

```bash
# print the WHOLE function, signature to closing brace
awk '/function approveFor\(/,/^  }/' RelayHub.sol
# or ask the question directly instead of reading: does this function produce a revert?
sed -n "$(grep -n 'function approveFor' RelayHub.sol | cut -d: -f1),+25p" RelayHub.sol | grep -n "revert\|require\|only"
```

```python
# read_file windowing that GUARANTEES the body: locate the signature, then read signature+40
sig = [i for i, l in enumerate(open(p), 1) if 'function approveFor(' in l][0]
read_file(p, offset=sig, limit=45)
```

**Verification gate (put this in the findings log, per claim):**

| Question | Evidence required |
|---|---|
| Is the function guarded? | full body read, signature→closing brace, cited as `file.sol:line-line` |
| Does the guard fire for a non-privileged caller? | positive-control `cast call --from <rejected-address>` → revert |
| Does the body call an internal/parent check? | grep `_check\|_require\|isOperator\|hasRole` within the body |
| Could the guard pass trivially? | "the caller controls the identity the check demands" (`evm-…` §8) |

No row, no claim. This table is cheap; the retraction was not.

---

## 7. FOUNDRY HARNESS FIXTURE FAILURES ARE NOT FINDINGS — separate them before reporting

The retraction in §5a surfaced through a hand-built `RedTeamBase` fixture, and that fixture then
produced **4 more FAILs that looked like live vulnerabilities and were not**. Recognise the shape
instantly: a test whose *`setUp()`* reverts, or whose revert is
`AccessControlUnauthorizedAccount`, says nothing about the target — it says your harness did not
grant the role.

Real transcript from that run:

```
[FAIL: AccessControlUnauthorizedAccount(0x…A11cE, 0x9766…b929)] setUp() (gas: 0)
```

`0x9766…b929` = `keccak256("OPERATOR_ROLE")`. The fixture called `hub.mint(...)` from `admin`
without granting `admin` `OPERATOR_ROLE` first — so the mint reverted inside `setUp`, and *every*
test in the suite failed at the same line with the same error. Four failures, one cause, zero
findings.

**Triage rule: group FAILs by revert reason before interpreting any of them.**

| Revert reason | Means |
|---|---|
| `AccessControlUnauthorizedAccount(<your fixture addr>, <role hash>)` | fixture bug — role not granted. Decode the hash: `OPERATOR_ROLE 0x9766…`, `ADMIN_ROLE 0xa498…`, `ORACLE_ROLE 0x68e7…` |
| failure inside `setUp()` | fixture bug — the body never ran, the test proves nothing |
| `panic 0x11` | arithmetic underflow — usually a *balance* check talking, not the guard you thought |
| named custom error you did **not** expect | either a real guard (§5a) or a missing role — resolve which before writing it down |

**Copy the real deployment's role wiring, don't invent it.** Read the constructor first — the admin
role name differs per contract and guessing it wastes a round:

```solidity
// RelayHub
_setRoleAdmin(OPERATOR_ROLE, ADMIN_ROLE); _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
_grantRole(ADMIN_ROLE, adminAddress);
// RelayExecutor — note ORACLE_ROLE's admin is ADMIN_ROLE, and there is no DEFAULT_ADMIN_ROLE use
_setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE); _setRoleAdmin(ORACLE_ROLE, ADMIN_ROLE);
_grantRole(ADMIN_ROLE, admin);
```

Gotchas that cost calls on this target:

- `grantRole(DEFAULT_ADMIN_ROLE, …)` **reverts** — these contracts set ADMIN_ROLE as its own
  role-admin and never use OZ's `DEFAULT_ADMIN_ROLE`. Grant `ADMIN_ROLE`.
- The `vm.startPrank` target must be the *actual* admin the constructor received, and
  `vm.stopPrank()` must bracket each contract's grant block — a prank left open across a
  `new Contract(...)` silently deploys from the wrong sender.
- Minting to fund an order/deposit address requires `OPERATOR_ROLE`; grant it to `admin` before
  the `mint`, not just to the Executor/Allocator.
- Cross-check each grant against live chain with `cast call <c> "hasRole(bytes32,address)(bool)"`
  before trusting the fixture — on this target `ORACLE_ROLE` was held by the **multisig**
  `0x2a72…b0` and NOT by the owner EOA (a subagent had it backwards; `cast` settled it in one call).

**Report hygiene:** a suite result of the form `N passed, M failed` where all M share one
`AccessControlUnauthorizedAccount` in `setUp` must be reported as **"harness fixture broken,
M hypotheses UNTESTED"** — never as M negatives, never as M findings. Untested is its own
verdict, and collapsing it into either PASS or FAIL is the fabrication path.

---

## 8. SIGNATURE-FRESHNESS TRAP: the fields *are* in the typehash — proven, not assumed

The single highest-yield way to kill an "oracle-signed request lets attacker alter field X" chain.
On Relay this killed **four** separate candidate chains in one round, each in under ten minutes,
because the answer lives in one file that nobody reads first: the **off-chain signing/hashing
implementation**, not the Solidity.

**The four dead chains and the one-line kill for each:**

| Candidate chain | Kill condition | Where it was answered |
|---|---|---|
| Alter `request.fees[].recipient` → oracle signs → `Executor._chargeFees` drains the victim's deposit address | `fees` must NOT be in `getOrderId` digest | `packages/sdk/src/order/index.ts` `normalizeOrder()` L174–183 + `ORDER_EIP712_TYPES.Fee` |
| Forge `derivationFields` (deposit address) against a real `orderId` | every derivation field must be bound to the solver-signed order | `packages/lit-deposit-address/src/attestation/index.ts` `verifyOrderData()` L217–390 |
| Substitute `inputDepository` in a deposit-address trigger | field must be inside the EIP-712 trigger hash the oracles sign | same file, `verifyDepositAddressTriggerAttestation()` L146–193 |
| `WithdrawGasPayer.payGas` fee drain / replay | `feeAmount`+`feeCurrency`+all request fields must be in the typehash, and payment must be write-once | `contracts/WithdrawGasPayer.sol` `PAY_GAS_TYPEHASH` L48–51 + `gasPayments[h] != 0` L168 |

**Step 0 of every "signed struct" hypothesis — read the type definition, not the checker:**

```bash
# the whole struct, as the signer sees it
grep -n "EIP712_TYPES\|TYPEHASH" -A30 contract.sol | head -50
grep -n "export const ORDER_EIP712_TYPES\|export const .*_TYPES" -A40 packages/sdk/src/**/*.ts
# then the normalizer that feeds it — a type entry that normalize() omits is silently unsigned
grep -n "export const normalizeOrder\|normalize.*= (" -A60 packages/sdk/src/order/index.ts
```

The trap is asymmetric: reading the **on-chain verifier** (`_validateRequest`, `_payGasDigest`)
tells you what the *contract* wants; reading the **off-chain signer** tells you what the *oracle
actually signs*. A field can be in the typehash but missing from the struct the service builds
(false negative — chain dead), or in the service's struct but not the contract's digest (false
positive — nothing to exploit). **Both files, always.**

**When the target ships the signing logic in TypeScript, the TS file is primary evidence** — cite
it with `file:line` exactly like Solidity. A chain that survives "field X is not in the digest" has
already failed; do not escalate it to a severity word on the theory that "the oracle probably
doesn't validate it anyway".

**Ordering rule for a request-authorization chain.** Before writing any oracle-mediated chain,
answer these in order and stop at the first "yes, bound":

1. Is the mutable field inside the off-chain signed struct? → if yes, **DEAD**, move on.
2. Do the on-chain contract and the off-chain signer hash the *same* field set (encoding parity:
   `abi.encode` vs `keccak256(bytes())` per field, `uint256` vs `string` chainId)? → mismatch is a
   real finding, but a *collision* finding, not "unbound field".
3. Is there a write-once guard on the request hash (`mapping h => 0`, nonce consumed)? → if yes, no
   replay, whatever the caller does.
4. Only then: is the caller free to supply these signed values (i.e. is the signature the *only*
   gate, and can a non-privileged user legitimately obtain one)?

Step 4 is where most "public endpoint + signature = authz" chains actually die: the endpoint is
public and the caller is free, but the **signer refuses to sign attacker-chosen values**, which is
step 1 restated. Say "chain closed at step 1, `fees` is a member of `Fee` and `normalizeOrder`
binds it" — that sentence ends the hunt honestly and is cheaper than a fork PoC.

---

## 9. Boundary-of-trust enumeration after N failures — what is actually left

After five refuted candidates on one target, the honest next move is not "hunt harder"; it is to
enumerate **which fields the signer will sign but which no verifier re-binds**, and which code runs
*after* the last signature check. Those are the only two shapes left. Relay's survivors at that
point, worth checking in this order:

- **Encoding collisions** (`Utils.generateAddress` / `generateTokenId`): can two distinct
  `(family, chainId, address)` tuples produce one token id? Address representations with different
  padding (20-byte `address` vs left-padded `bytes32` vs bytes-hex with/without `0x`) collapsing to
  one id is a real fund-routing bug, and it is purely mechanical to test — no oracle needed.
- **Post-signature execution** (`Executor._runCalls` / `callResolver`): anything the resolver does
  after `_finalizeWithdraw` is outside the digest. Reentrancy into a second request while the first
  is mid-flight is the classic; the digest binding does not help here.
- **Nonce-add ordering** in `consumeSpenderSignature`: added before or after verification decides
  whether a failed signature can burn a nonce (griefing) or a valid one can be replayed.
- **Cross-VM address decoding** (solana bs58, ton `wc:hex`, xrp X-address vs classic, bitcoin
  types): does one *textual* address decode to two different byte strings, or two texts to one?

**Closing statement discipline.** When every candidate dies, the deliverable is the negative map —
a table of `candidate | verdict | the single line that decided it`. Do **not** fill the required
report template (VULN/ENTRY/CHAIN/IMPACT/POC) with a refuted candidate; an empty-but-true "no chain"
report outranks a full report built on a dead chain. §5a's retraction is the precedent.

---

## 10. DELEGATION BUDGET: `max_iterations: 50` returns zero artifacts on a 4k-line repo

Observed across two batches on this target: **4 subagents, `api_calls=50` each, `status=completed`,
zero files written**, because the iteration budget was consumed reading source and the agent was
cut off mid-analysis, before the write. Their `completed` status and fluent summary read like
success — the summaries described work in progress.

Mitigations, in order of value:

1. **Instruct incremental writes in the delegation prompt.** *"Create `/tmp/aN_report.md` at the
   start and append after each finding — do not wait until the end."* This is the single change
   that turns a capped run into a usable artifact.
2. **Raise the budget for hunts:** `hermes config set delegation.max_iterations 150`. Keep 50 for
   smoke tests and single-file tasks.
3. **Cap concurrency at 3** (`delegation.max_concurrent_children`); a 4th task in one
   `delegate_task` call is rejected outright, not queued — split into two calls.
4. **Verify on disk, never on the summary.** `ls /tmp/a*.md` + file size + mtime. A subagent's
   "COMPLETE" is a self-report; the artifact or it did not happen.
5. **Give each subagent the already-refuted list in its `context`** (this session's table above)
   or it will re-derive the same dead chains and burn its budget doing so.
6. **`api_calls=55` + `status=completed` + an 11-line artifact = an INFRASTRUCTURE death, not a
   finished task.** The third failure mode, distinct from the two above: the run died at the
   provider edge and the harness still stamped it `completed`. Read the literal error in the
   summary before believing the status:

   ```
   API call failed after 3 retries: HTTP 502: {"title":"Error 502: Bad gateway",
   "detail":"The origin web server returned an invalid or incomplete response..."}
   ```

   With no fleet brief to write incrementally, the agent was killed mid-read and left a
   500-byte file that *looked* like a completed section ("## 1. Protobuf utils — GUGUR").
   **Size-check every artifact against its claim**: an 11-line file for a "5 builders +
   call-resolvers" task is a fragment, however confident the summary reads.

   Recovery: **do not re-dispatch the same brief** — finish the abandoned slice yourself, in the
   parent, cheapest-first. Read that worker's file for the partial scope it *did* cover, then
   resume from the first unread item. Here one worker died on builders, so the parent read
   Hyperliquid `_deriveNonce` and the Hedera serializers directly and closed the class in ~10
   calls. Re-delegating would have re-spent 55 calls to reach the same point.

   **Severity of a fleet gap is not a finding.** A worker dying is a gap in *your* coverage, not
   evidence about the target — never let "we didn't get to it" migrate into a report as a
   negative result (`rpc-census-supply-integrity-and-role-enumeration.md` §8's BLOCKED verdict is
   the correct shape).

7. **`status=completed` + a summary that says the artifact was never written = the work is GONE.**
   The variant that hides best, because the summary is fluent, detailed, and *correct* — it just
   lives only in the delegation return value, not on disk. Two of three workers in one batch did
   this: one explicitly wrote *"`/tmp/hunt7/T_DOMAIN.md` was never written — this summary contains
   the content, but it must be dumped there."*

   **The fix belongs in the brief, not in the retry.** Require the file write as the *first* action
   and the *only* definition of done:

   > "Buat `/tmp/hunt7/<NAME>.md` di MENIT PERTAMA (boleh kosong), lalu append tiap sub-topik
   > selesai. File yang tidak ada di disk = tugas GAGAL, walau summary-mu panjang."

   Then **`ls -la /tmp/hunt7/*.md` before reading any summary.** A missing or stale-mtime file is
   the real status; the summary text is a claim about work that may have evaporated.

8. **A worker can also break your shared build.** A subagent that leaves a non-compiling test in
   the forge workspace poisons *every* later run (`mv test/S01..S05_Scale.t.sol /tmp/qs/` was one
   worker's unblock move — correct of it, but it means the parent's `forge test` count is no longer
   comparable to the previous round's). **After every batch: run the full suite yourself, then
   quarantine each failing file to `/tmp/*.bak`, then re-run.** Distinguish the three kinds —
   harness scaffolding bugs (`vm.prank: cannot overwrite a prank`), broken shared fixtures
   (`AccessControlUnauthorizedAccount` in `setUp`, `live-rpc` §7), and a *real* passing finding
   inside a broken file (keep that one, quarantine its neighbours). Report the final clean count as
   `N passed, 0 failed` with the quarantined list, never the raw batch number.

9. **RE-DISPATCH NARROWLY, not the same brief — and make the FIRST question the deliverable.**
   When a worker dies (§10.6, §10.7) the instinct is to re-send the identical brief; that re-spends
   the budget to reach the same decision point. What worked instead:

   | Broken brief | Re-dispatched as |
   |---|---|
   | ONE task with 5 sub-questions (who funds it + replay + cap + batch + severity) | **one** question: *who funds the payout* — the rest explicitly deferred |
   | "write the report at the end" | "append after your FIRST finding, ≥4 appends, partial progress must survive a death" |
   | no hypothesis framing | the three candidate answers enumerated in the prompt (mint / escrow / burn) so the worker cannot invent a fourth narrative |

   The narrowed run finished in **349s / 28 calls** (versus 1478s / 38 calls for the dead attempt),
   wrote 4 sections, and produced the number that demoted a CRITICAL to HIGH. **A single blocking
   question beats a five-part brief** — a worker holds one question to completion, and a partial
   answer to the one question that gates severity is worth more than five partial answers.

**Verbatim subagent-prompt fragment that worked** (adapt per target):

> "Output WAJIB ditulis ke `/tmp/aN_topic.md` — tulis file lebih awal, append per temuan, jangan
> tunggu selesai. Fakta yang SUDAH TERBUKTI MATI (jangan ulang): <list>. JANGAN klaim tanpa
> file:line. Cetak 20 baris ringkasan berisi hasil literal."

---

## 11. ABI DECODE OF NESTED TUPLES — the word-offset trap that invented a fake chainId

Second Relay round (oracle infinite-mint hunt). Two hedged reads were **wrong in the same way**:
`abi.decode` offsets were computed from the *start of the calldata blob* instead of from the
*start of the containing tuple*. Both were caught only by cross-checking against an event. Record
the method, because the failure mode is silent — a wrong offset yields plausible garbage, not an
error.

**Symptom:** decoding `action` (an element of `bytes[]`) by treating word 0 as a struct field:

```python
W = lambda i: act[i*64:(i+1)*64]
type = int(W(0),16)        # ✗ act[0:64] is the ABI *slot* for the bytes element, not the type
```

Output looked real — `feeCalculator=0x0`, `rateLimiter=0x23af…`, `rateLimiterData` len 0 — and I
wrote "the production tx passes an EMPTY rateLimiterData, therefore `consume('')` reverts,
therefore live code differs from repo". **Three wrong conclusions stacked on one bad offset.**

**Fix — anchor the offset, then re-read every word relative to it:**

```python
base = int(W(0),16)                       # first word may itself be the tuple's byte offset
p    = base if base < len(act)//2 else 0  # base==0x20 => tuple starts at word 0 of the blob
F    = lambda n: act[(p//64+n)*64 : (p//64+n+1)*64]
```

**The mandatory cross-check: reconcile the decode against an EVENT, not against the source.**
`TokensConsumed(string indexed chainId, uint256, uint256)` gave `topics[1] =
0x9186606d55c5…`, which did not match `keccak("qarbitrum")` — the value my broken decode had
produced. Brute-forcing a small candidate list found the real string:

```python
for c in ["arbitrum","ethereum","base","optimism","polygon","qarbitrum", ...]:
    if "0x"+rpc("web3_sha3",["0x"+c.encode().hex()])["result"][2:] == topics[1]:
        print("MATCH:", c)          # → arbitrum
```

Lesson: **any decoded string/uint that a production event also carries is free verification.**
Decode → hash the candidate → compare to `topics`. If they disagree, the *decode* is wrong, not
the chain. Never let a decode anomaly become a "live code differs from repo" claim — that claim
requires the §2 verified-source diff or a bytecode disasm, and on this target the disasm showed
`isFeeCalculator → calculateFee → isRateLimiter → consume → revert FastMintRejected` in exactly the
repo order.

**Bytecode-as-source-of-truth when there is no build:** `cast build`/`forge build --skip test` fails on missing
`node_modules`/`lib` → don't stall. Dump `cast code`, `grep -c <selector>` to prove a call site
exists (`ca922f6e` = `consume` present ⇒ the guard *is* reached), and read the `PUSH4 <errsel>`
neighbours to recover which `revert CustomError()` sits on each branch:

```bash
grep -o "63ca922f6e" /tmp/live.hex | wc -l      # 1  => consume is called
python3 -c "c=open('/tmp/live.hex').read(); i=c.find('63ca922f6e'); print(c[i-500:i+600])"
#  ...63136bdd8d60e11b = FeeCalculatorNotAllowed ; 6306819ca1 = FastMintRejected (JUMPI 0x1509)
```

That ten-line window settled "does the deployed contract actually call the rate limiter" far
cheaper than a full Foundry rebuild.

## 12. TWO events, ONE name — check the SIGNATURE, not the topic name

`eth_getLogs` on the oracle for `Executed(bytes32,bytes[])` returned **0** while the contract was
demonstrably minting 262 times. Cause: two contracts each declare `Executed`, with *different*
signatures, and the store's copy is the one in the receipt:

```
keccak("Executed(bytes32,bytes[])")  = 0xa3c855af…   RelayOracleV2.sol:48     (emitted by oracle)
keccak("Executed(bytes32,address)")  = 0x59c3746e…   RelayOracleIdempotencyStore.sol:24
```

**Before concluding "this event never fired", recompute the topic from every declaration site** —
`grep -rn "event Executed\|event Transfer\|event Approval" contracts/` — and run the count once per
candidate topic. A zero-count on a *plausible* topic is far more often a wrong topic than a dead
path. Corollary: never report "0 events ⇒ feature unused" from one topic; that exact shortcut
almost buried the only live mint path on the target.

Same trap in the ERC-20/6909 direction: a receipt showing `Transfer(from=0x0, to=X, amount)` at a
token address does **not** imply a mint. On this target `0x805d6a1a…` was an `ERC20View` mirror
whose `emitTransferEvent(address,address,uint256)` (`0xa6d49dca`) fabricates Transfer logs;
`cast selectors` + `cast 4byte` on the unlabelled selectors (`0xf23b6fa2` = `emitApprovalEvent`)
identified it in two calls. **`name()/symbol()/totalSupply()` succeeding does not make it an
ERC-20** — check for `minter`/`MINTER_ROLE`/`_mint` selectors before theorising a mint.

## 13. "RATE LIMITER" THAT LIMITS NOTHING: `rate == capacity`

A live config finding worth checking on *every* protocol shipping a token-bucket limiter. Read the
bucket parameters, not just whether the limiter is wired:

```
getBucket("arbitrum") -> tokens=1e22  capacity=1e22  rate=1e22  isEnabled=True   (18dp → $10,000)
```

With `refill = min(capacity, tokens + timeDiff*rate)` and `rate == capacity`, **one second of
elapsed time refills the bucket to full**. The limiter degenerates into a per-request burst cap
($10k) with *unbounded throughput*. Proof in one call:

```bash
cast call $LIMITER "resolveCanConsume(uint256,uint256,bytes)(bool)" $TOKENID 9000000000 \
  $(cast abi-encode "f(string)" arbitrum)     # → true, right after 245 mints consumed budget
```

Also mine the limiter's own consumption event to learn the **real** key format:
`TokensConsumed(string indexed chainId, …)` showed `chainId = "arbitrum"`, not the `"qarbitrum"`
a config file suggested — a wrong key name is **fail-closed** (`!isEnabled → return false`), so a
guessed chain id makes the limiter look broken when it is misconfigured-by-name only.

**Classify honestly:** a cosmetic limiter is a *solvency / trust-model* finding (unbounded loss if
2-of-N signers are compromised), **not** an attacker-without-role finding. Mint path stayed
`onlyRole(OPERATOR_ROLE)` throughout; the limiter was downstream of a signature gate.

## 14. PROVING A NEGATIVE on a mint path — the checklist that ends the hunt

For "can an unprivileged attacker mint to an arbitrary address", the deliverable is a table of
`path | prerequisite | attacker-without-role? | verdict`, each row backed by a literal command.
The five probes that actually decide it, cheapest first:

1. **Direct call from a throwaway EOA** — `cast call $HUB "mint(...)" --from 0x…bEEF` →
   `AccessControlUnauthorizedAccount(0x…bEEF, 0x97667070…)`. That hash is `keccak("OPERATOR_ROLE")`;
   print the hash→name mapping so the reader doesn't have to trust you.
2. **Enumerate the real holders**, don't trust the deployment JSON: `eth_getLogs` on the role
   contract for `RoleGranted`/`RoleRevoked` (chunked ≤ 400k blocks, retry) → then re-verify each
   candidate live with `hasRole`. On this target an on-chain holder existed that was absent from
   `prod.json`.
3. **Check the caller you *think* is trusted** — the production relayer EOA had **no**
   `OPERATOR_ROLE`; only the oracle did. This collapses "relayer is an EOA, therefore mintable" in
   one call.
4. **Abolish the argument-confusion class by reading the signature**: if the auth function takes a
   *single* `address` parameter used for both `hasRole(...)` and `isValidSignatureNow(...)`, there
   are no two arguments to swap — the hypothesis cannot exist. State it as dead with the line.
5. **Check the second source in the idempotency store** (`store.sources(i)`): a V1 oracle present
   in the store may still call `mint` — but if `HUB.hasRole(OPERATOR_ROLE, v1) == false`, its mint
   reverts and V1 adds zero surface. Enumerate `sourceCount()`, don't assume one.

**And record the residual non-mint findings** (unguarded resolver that can sweep stray balances,
`feeCalculator == address(0)` disabling fee collection, single-EOA `ADMIN_ROLE` that can
self-grant `ORACLE_ROLE`). A "MATI" verdict with four real secondary findings is a better
deliverable than a stretched mint claim.

---

## 15. **EVENT FIELDS ARE OFTEN ALL `indexed` — parse `topics`, not `data` (and the RPC that ignores your `address` filter)**

Two silent-truncation failures from the same session, both of which produce a **plausible wrong
number** instead of an error. Both nearly changed a severity verdict.

### 15a. All-indexed events put everything in `topics`, so `data` is `0x`

A census script decoding `PayloadBuilderSet` from `log.data` returned **"161 logs parsed, 0
chainIds"** — and the natural (wrong) reading is *"the event carries nothing"*. Cause:

```solidity
event PayloadBuilderSet(
  string indexed chainId,
  bytes  indexed depository,
  address indexed builder
);
```

With every field `indexed`, `data` is empty and the payload lives in `topics[1..3]`. The first
script silently `continue`d on every log because `len(topics) < 4` / parse failure, and the run
*completed successfully* with a zero.

**Rules:**

- Before writing any `eth_getLogs` parser, `grep -n "event <Name>" -A6` and look at the `indexed`
  keywords. Count them: `len(topics) == 1 + n_indexed`.
- A parser that filters by `len(topics)` or wraps per-log parse in `try/except: pass` can return a
  **zero result that looks like a valid negative**. Never report a census count from a loop whose
  every iteration was swallowed. Print `parsed/total` and fail loudly when `parsed == 0 && total > 0`.
- **`string indexed` / `bytes indexed` are stored as `keccak256(value)`, NOT the value.** You can
  count distinct hashes per chain but you cannot read the chainId back out. To recover the actual
  string you must brute it (`keccak("arbitrum") == topics[1]` — §11's technique) or get it from the
  tx calldata. A census that needs the *values* must read calldata, not logs.

Corrected census that settled a MEDIUM/HIGH severity call:

```
total 161  chainIds 83  multiByHash 0
```

i.e. **no chainId has more than one depository** ⇒ a cross-depository replay stayed LATENT with
zero live targets, severity downgraded on evidence rather than on a subagent's opinion.

### 15b. The RPC silently returned LOGS FROM OTHER CONTRACTS

Same target, later round: `eth_getLogs({address: 0x17b8e9d9…})` over a 3k range returned **5 hits**,
and I wrote *"the contract is ACTIVE, 16 events"*. Every one of those logs had
`log.address == 0x03a246e0…`, a completely different contract. The RPC **ignored the `address`
filter** for that range and returned neighbourhood logs.

The only tell is checking the field you assumed was filtered:

```python
for lg in r["result"]:
    assert lg["address"].lower() == TARGET.lower(), f"RPC ignored address filter: {lg['address']}"
```

**Verify the filter, every time, on the first result** — 30 seconds of code vs. a retracted
"active contract" claim. Same family as §12 (topic name ≠ topic hash) and §11 (plausible garbage):
**the RPC layer and the log layer each have their own way of quietly giving you the wrong
answer**. Post-filter in the client; never trust the server-side slice.

### 15c. Consequence for reporting

Both failures above are the *negative-evidence* form: they made "nothing there" look like a
nonzero result and vice versa. Any census claim in a report should carry the **raw counter**
(`161 parsed / 161 total`) and the **assertion that filtered out foreign rows**. Without those two
numbers the census is unfalsifiable, and an unfalsifiable census is how a HIGH becomes a MEDIUM
after you have already told the user.

---

## 16. IDENTIFYING AN UNDECLARED CONTRACT → read its **EIP-712 domain**, not its bytecode

The highest-value four calls in the final round. A contract held `OPERATOR_ROLE` on the Hub, was
absent from `prod.json`, absent from the repo, and had one unrecognised entrypoint selector. It
looked like a backdoor.

**Do not start with disassembly.** Start with the domain:

```bash
cast call $GHOST "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])" --rpc-url $R
# 0x0f
# "WithdrawGasPayer"     <-- IDENTITY, straight from the contract's own mouth
# "1"
# 537713
# 0x17B8E9d9…            <-- verifyingContract == itself
# 0x00…00
# []
```

`SIGNING_DOMAIN` is a `public constant` in the source (`WithdrawGasPayer.sol:42`) and it is baked
into the deploy-time domain separator, so **the name survives even when the source is unpublished**.
One call went from "unknown privileged contract" to "undeclared v2 of a known contract".

**Then fingerprint version drift by typehash, not by codesize** (codesize only says "different";

```bash
cast call $GHOST "PAY_GAS_TYPEHASH()(bytes32)" --rpc-url $R        # new
cast call $OLD   "PAY_GAS_TYPEHASH()(bytes32)" --rpc-url $R        # old
cast call $GHOST "ORACLE_MULTISIG()(address)"  --rpc-url $R
cast call $GHOST "HUB()(address)"              --rpc-url $R
```

Then **prove which build matches the repo** by re-hashing the source string:

```python
from eth_hash.auto import keccak
keccak(b"PayGas(string chainId,bytes depository,bytes currency,uint256 amount,"
       b"string spenderChainId,bytes spender,bytes receiver,bytes data,"
       b"bytes32 nonce,bytes feeCurrency,uint256 feeAmount)").hex()
# 0x601bdcfa… == OLD live  ⇒  old == repo
# 0xf44f4790… == NEW live and matches NO repo variant ⇒  the signed struct CHANGED
```

**This is the finding**, not the address itself: the live v1 matched the repo typehash exactly, and
v2's typehash matches nothing — so `PayGas` gained/lost a field between versions. On a codebase
where §8 already killed four chains because fields were or weren't in the digest, an undocumented
**typehash change on a privileged contract** is exactly where the next unbound-field bug lives.

Confirm benign-vs-hostile with activity, not vibes:

```bash
cast nonce $GHOST   # txs sent FROM it
cast balance $GHOST
cast tx $(cast receipt $GRANT_TX …)      # grantRole, status 1, from the owner multisig
```

Zero nonce + zero balance + zero real logs ⇒ **deployed, privileged, never used**. Combined with
`grant(new) → 17 blocks → revoke(old)`, the honest verdict is *"planned rotation, undeclared"*, and
the report says so instead of accusing a backdoor. Severity: LOW as a finding, **but the typehash
delta is the lead worth chasing.**

### §16-g. "but my probe reverted" is NOT "the contract is dead" — the ghost was LIVE

The §16 verdict above was **half wrong**, and the way it went wrong is the most reusable lesson in
this file. `cast call $GHOST "0x8bf6531e" <hand-built args>` reverted with `error code 3`, and that
single probe became *"entrypoint reverts ⇒ contract inactive"*. It was written into the round's
conclusion. A later round searched the ghost's own address for inbound txs and found **4 successful
transactions**, gas 3.2–3.9M, status `0x1`, all recent:

```
0xfec965c6…  blk 6121036  gas 3255870  status 0x1
0x85678f05…  blk 6122299  gas 3255870  status 0x1
0x9b705151…  blk 6123560  gas 3948342  status 0x1
0xd40dabf3…  blk 6125244  gas 3915102  status 0x1
```

**The contract was alive the whole time.** The entrypoint needed arguments the hand-built calldata
did not satisfy — a wrong-input revert is indistinguishable from a "contract is dead" revert when
you only look at the error code.

**The correct probe order for "is this contract used?", cheapest and most decisive first:**

```bash
# 1. Inbound transactions to the address — THE ground truth. Not the getter, not a call.
cast logs --address $GHOST --from-block <recent> 2>/dev/null | head   # or eth_getLogs / cursor method
# 2. Receipts of those txs: status + gasUsed + log count
#    status 0x1 + gasUsed 3.2M + 3 logs  ⇒ real work happened, definitionally
# 3. Only then interpret WHAT it did (decode the logs)
```

Interpreting those 4 txs settled the round properly — and the truth was benign, which is exactly
why the discipline matters:

| log | contract | content |
|---|---|---|
| log0 | `RelayHub` | lock `tokenId 3500` recorded against the ghost |
| log1 | token `0xec468c69…` | `Transfer` → **`0x0`**, amount **3500** = **BURN** (`arc-gateway-USDC`, 6dp) |
| log2 | ghost | 3-field event carrying the salt |

So the ghost is the **legitimate `WithdrawGasPayer` v2**: gas-payer token is burned as the
withdrawal fee, Hub records the matching lock. The caller `0xa984c4ca…` is an EOA with
`codesize 0`, balance 0, nonce 894, and **no role on the Hub or on the ghost** — consistent with
"anyone may submit a withdrawal that burns their own gas-payer". Not a backdoor.

**What survived from §16:** the `eip712Domain()` identity technique was correct and is what made
the 4 txs interpretable at all. What died was **the inference from one failed call to contract
liveness.** Keep the identification method; delete the liveness claim unless it comes from
inbound-tx evidence.

**Generalised rule — the DOUBLE-PROBE LAW:**

> No "X does not exist / is not used / is not reachable" claim ships on one probe. Two
> *independent* methods, in different layers, must agree.

| Claim | Probe 1 (fails how) | Probe 2 (the one that decides) |
|---|---|---|
| "mapping slot is empty" | `cast storage` raw slot → always 0 | `keccak(key‖slot)` vs `eth_call` getter (§4a of the census ref) |
| "entrypoint is dead" | `cast call` with hand-built args → revert | **inbound txs + receipts** (this section) |
| "event never fired" | one topic → count 0 | recompute topic from every declaration (§12) |
| "census is N" | `eth_getLogs` chunked → N with `fails>0` | cursor method, dedup, `fails == 0` (§9 census ref) |
| "no guard on function X" | trace shows no revert | positive-control call from a rejected caller (§5a) |

Every row is the **same bug wearing different clothes**: a single probe returned a clean-looking
negative, and the negative was an artifact of the probe. This target produced that failure **four
separate times in one session** — twice from my own probes, twice from a careless reading — and
each time the expensive part was not the retraction but having already told the user the wrong
answer.

**Cost accounting, so the trade-off is honest:** probe 2 in every row above is one extra call.
The retractions it prevents cost a full round each, plus credibility. There is no version of this
where skipping the second probe is cheaper.

**And when the second probe overturns you, say so in those words.** The winning round on this
target opened with *"ini menjawab pertanyaan ghost — dan hasilnya bukan yang kuduga"* and then gave
the 4 tx hashes. Shipping the correction with the same weight as the original claim (see §16d) is
what keeps a long hunt credible; quietly dropping the wrong conclusion is what makes the whole
report unauditable.

### Pitfall discovered en route: the domain `name` may be SMALLER than the contract's role
`WithdrawGasPayer` held `OPERATOR_ROLE` on the Hub (so it can `burn`) while never being able to
mint. Reading "holds OPERATOR_ROLE ⇒ can mint" is the same overreach as §5's "unguarded setter ⇒
theft": **enumerate what the role actually gates** (`grep -n "onlyRole(OPERATOR_ROLE)"` on the Hub)
before assigning impact.

---

## 16b. THE OTHER HALF OF §8 — an UNBOUND field is only a finding if a CONSUMER reads it

§8's ordering rule kills a chain when the field *is* bound. This is the failure that happens when
the field is genuinely **unbound** and you get excited before checking who reads it. Relay round 3:
`WithdrawGasPayer` records gas payments under `withdrawParamsHash`, and that hash **omits both
`feeCurrency` and `feeAmount`** — while the signed oracle digest **does** include them (R12/R13,
12/12 forge). A real sign-vs-record asymmetry. Verdict: **not a vulnerability.**

The reason is a general law worth carrying into every "unbound field" claim:

> **Binding is the union of two questions.** (a) Is the field in the digest? (b) Does any *consumer*
> compare the recorded value against its own independently-derived value? A field can be outside the
> digest and still not exploitable, because the consumer re-derives it and bounds the gap.

Here the three consumers each closed the loop themselves:

```solidity
// payload-builders/GasPaidPayloadBuilder.sol:74-86
paidAmount = IWithdrawGasPayer(GAS_PAYER).gasPayments(withdrawParamsHash);
if (paidAmount == 0) revert GasNotPaid(withdrawParamsHash);   // unpaid -> refuse

// and each VM builder then bounds the REAL fee by the prepaid one:
// TonVmPayloadBuilder.sol:150     if (paidAmount < gasFee)              revert PaidGasBelowGasFee
// GatewayVmPayloadBuilder.sol:112 if (gatewayPayload.burnIntent.maxFee > paidAmount) revert FeeExceedsPaidGas
// XrpVmPayloadBuilder.sol:150     if (data.fee > paidAmount)            revert FeeExceedsPaidGas
```

So a small prepaid amount can never cover a larger real fee. What remains — one request occupying
one gas-payment slot across currencies — is **by design** (docstring `GasPaidPayloadBuilder.sol:52-58`).

**Mandatory step before any "unbound field" severity word:** `grep -rn "_requireGasPaid\|<the
recorder mapping>\|paidAmount"` and read every *consumer*, not just the recorder. Enumerate
`file:line` for each comparison. If every consumer re-derives and bounds, the finding is dead and
the one-line killer is *"consumer X at file:line bounds it"* — same class of terminal sentence as
§8 step 1.

### 16c. HASH-ENCODING PARITY — reproduce the library's exact `abi.encode`, or your numbers are fiction

The `withdrawParamsHash` above is defined by a shared **library**, not by a typehash:

```solidity
// payload-builders/GasPaidPayloadBuilder.sol:34
return keccak256(abi.encode(chainId, depository, params));   // ← NO typehash prefix
```

My first test (R12) fed this through a *typehash* structure, because every other digest on this
target had one. The hashes it printed were therefore **not the contract's hashes** — a pure
fabrication risk even though every assertion "passed". R13 re-implemented the encoding verbatim
(dynamic `string` offset, dynamic `bytes` offset, struct offset, then the inline struct) and only
then were the numbers admissible.

**Rule:** when mirroring a hash for a PoC, copy the *literal* expression — `keccak256(abi.encode(...))`
vs `keccak256(abi.encode(TYPEHASH, ...))` vs `keccak256(abi.encodePacked(...))` — and cite the
`file:line` **of the library function**, not of the caller. Then confirm one computed hash against a
live on-chain value (`cast call <c> "<hashFn>(...)"`) before trusting the rest of the suite. A
14-line Foundry suite that reproduces the wrong encoding passes 100% and proves nothing.

Related: `params.data` (the VM payload blob) IS inside `withdrawParamsHash` (R13 test A), so the
"swap the VM payload after paying gas" variant of this class is closed at the encoding layer too.

### 16d. Round-closing discipline: report the refutation, with the same weight

Round 3 shipped zero findings and was still worth the cycles, because the deliverable stated
plainly: *"dugaan-ku salah, forge yang benar"* — with the passing test names as the evidence. Two
things to copy:

- A hypothesis you killed **yourself** belongs in the final report next to the PROVEN ones. It costs
  nothing (you already ran the test) and it stops the next session from re-deriving it.
- Count the growth honestly: `19 suites · 77 tests · 0 failed`, up from the previous round's 65 —
  because a negative suite is a real artifact, not wasted work.

---

SKILL.md's `description` is already at the 1024-char cap, so the pointer block cannot be extended.
SKILL.md's **body is also at its 100,000-char hard ceiling** (`skill_manage` patch refuses growth),
so new technique must land in `references/` and be cross-linked from an existing reference — this
file and `rpc-census-supply-integrity-and-role-enumeration.md` are the entry points. Future sessions
should read the references directly.

**Size-ceiling note for maintainers:** if a future round needs room, the honest fix is splitting
SKILL.md, not appending. Until then, add a cross-link header to the nearest sibling reference. The four sections above cover gaps in the
existing technique bank:

| Gap | Section |
|---|---|
| Nested-tuple `abi.decode` offset errors silently produce plausible fake values; reconcile decoded strings/uint against a production event's `topics` | §11 |
| `eth_getLogs` returning 0 for an event name that *does* fire — two contracts, two signatures | §12 |
| A token-bucket limiter with `rate == capacity` is decorative; classify as solvency/trust-model, not attacker-without-role | §13 |
| The five cheapest probes that turn "can an unprivileged attacker mint?" into a verdict table | §14 |
| All-`indexed` events put the payload in `topics` (empty `data`); per-log parse swallowed by `try/except` yields a fake zero; `string indexed` is a hash, not the string | §15a |
| An RPC can return logs from the WRONG address, ignoring the `address` filter — post-filter on `log.address` | §15b |
| Identifying an undeclared privileged contract via `eip712Domain()` name + typehash delta instead of disassembly | §16 |
| An unbound field is only exploitable if a CONSUMER fails to re-derive it — grep every consumer before assigning severity | §16b |
| Mirror a library hash with its literal `abi.encode` expression (typehash-or-not), or a passing PoC proves nothing | §16c |
| A `block.timestamp`-derived field (nonce/validStart) is **safe** when `buildPayload` writes it into the struct `hashesToSign` then hashes — the hash boundary decides, not the mutability | §16e |
| A fleet worker that dies at the provider edge (HTTP 502) still reports `status=completed`; size-check the artifact and finish the slice yourself instead of re-dispatching | §10.6 |
| `eip712Domain()`+typehash matching the repo does **NOT** prove the deployed storage layout matches — value-identity and layout-identity are separate proofs, and both are needed | §16f |

### 16e. A `block.timestamp`-DERIVED FIELD IS SAFE IF IT LANDS IN THE STRUCT THAT GETS HASHED

The mirror image of §8, and the fastest way to kill a whole family of "nonce/time drift" leads in a
payload builder. Shape that looks exactly like a finding:

```solidity
// HyperliquidVmPayloadBuilder.sol:361-366
function _deriveNonce(bytes calldata data) internal view returns (uint64 nonce) {
  uint64 nonceSeed = abi.decode(data, (uint64));
  return uint64(block.timestamp * 1000) + (nonceSeed % 1000);   // ← mutable, caller-influenced
}
```

Reasoning that produced a false lead: *"`block.timestamp` is not in the signed calldata, so the
nonce at execution ≠ the nonce that was signed ⇒ replay/drift (same class as R14 Solana)."*

**It is dead, and the check is two reads.** The order of operations is what matters:

```solidity
// buildPayload (L149-155) CONSTRUCTS the request, run-time nonce included:
parameters: abi.encode(_buildSendAssetRequest(chainId, params))   // → request.nonce = _deriveNonce(...)

// hashesToSign (L160-198) then DECODES that same payload and hashes it:
SendAssetRequest memory request = abi.decode(decoded.parameters, (SendAssetRequest));
hashes[0] = toTypedDataHash(domainSeparator, hashSendAssetRequest(request));

// hashSendAssetRequest (L289-306) includes it:
abi.encode(SEND_ASSET_TYPEHASH, …, request.amount, request.fromSubAccount, request.nonce)
```

`buildPayload` → `hashesToSign` is **one composed call** in a single `view` execution, so the
derived nonce is *inside* the digest. There is no interval for it to drift across. The consumer
(the off-chain signer) signs the payload **after** the builder produced it, not before.

**The decision rule:**

| Question | Verdict |
|---|---|
| Is the derived value assigned into the request/struct **before** `hashesToSign` hashes it? | **DEAD** — it is signed |
| Does `hashesToSign` re-derive it independently of the payload it was given? | check — a *divergence* between the two derivations is the real bug |
| Is the derived value read by the **executing** side from a different source than the hashed struct? | **live lead** — this is R14-Solana's shape |
| Does the payload get rebuilt between hashing and execution (separate tx / later block)? | **live lead** — the only way drift is reachable |

**Distinguish from R14:** Solana's nonce genuinely changed between two *separate* invocations for
what should have been one payload. Here the value is computed once, inside the call whose hash is
then signed. Same words ("nonce derived from block time"), opposite verdicts — **which side of the
hash boundary it sits on is the entire question**, and it is answered by reading whether the hasher
decodes the built payload or rebuilds it.

**Hedera, same file, worth copying as positive practice:** its `_computeValidStartNanos` is
`pure` and mixes `params.nonce, currency, receiver, amount, data` — *deliberately* no
`block.number`, with the reason in the docstring ("so that off-chain code can reproduce the payload
from the same parameters"). When a builder goes out of its way to keep derivation reproducible, the
drift class is closed by construction; say so instead of hunting it.

---

## 16f. VALUE-IDENTITY ≠ LAYOUT-IDENTITY — `eip712Domain()` matching is not a storage-layout proof

Two proofs live in different references and they can **contradict each other without either being
wrong**. This session hit exactly that, and the contradiction was nearly reported as a worker error.

**Proof A — value identity** (`signature-gated-entry-writes-and-bytecode-identity.md` §4): the
deployed contract computes the same `TYPEHASH`, `ORACLE_ROLE`, function selectors and
`eip712Domain()` (`name` / `version` / `chainId` / `verifyingContract`) as the repo source. Cheap
(~6 calls), and it correctly licenses "every repo read is a read of the live code" **for logic**.

**Proof B — layout identity** (`rpc-census-supply-integrity-and-role-enumeration.md` §4): read
`totalSupply(tid)` via `eth_call` and locate it by slot-race. On this target the live contract kept
it at base **6**, while the repo declares it at base **3** (and `erc20Views` at 8 vs 5).

```
block 0x5d9622, same block for every read:
  eth_call totalSupply(TID)      = 4639578352
  keccak(TID || 3)  (repo layout) = 0            ← negative control
  keccak(TID || 6)  (live layout) = 4639578352   ← MATCH
  keccak(0 || 8)                  = 0xFB0fadd3…  ← erc20Views, live layout
```

**Both were true simultaneously.** The deployed bytecode implements the same functions with the same
typehashes, but **three storage variables were inserted before deployment**, shifting every slot
after them. So:

> `eip712Domain()` / typehash / selector equality proves the *logic* you are reading is the deployed
> logic. It says **nothing** about where state lives. A contract can be logic-identical to the repo and
> storage-incompatible with it.

**Why it matters:** any finding that depends on *state semantics* — "this mapping is the one the
getter reads", "`_isOperator` is at the same slot the other function writes", a proxy/upgrade
comparison, or reasoning about which variable an assembly/`sstore` touches — is unsound on
value-identity alone. Findings that depend only on *control flow* (missing `msg.sender` binding, an
unguarded `setEntry`, a digest that omits a field) survive, because those are decided by the bytecode
paths the hashes already proved identical.

**Decision table before shipping any repo-based finding:**

| Finding depends on | Proof required |
|---|---|
| control flow, digest membership, missing modifier, guard absence | Proof A (`eip712Domain` + typehashes + selectors) — sufficient |
| storage slot, getter↔variable binding, proxy layout, state migration | Proof A **and** Proof B — slot-race with a repo-slot negative control |
| totalSupply/balance arithmetic | Proof B, block-pinned, ideally one atomic `aggregate3` (§3 of the census file) |

**Proof C — byte-exact code equality (`bytecode-dispatcher-forensics.md` §9) supersedes all three.**
If the deployed runtime code equals the repo's linked build byte-for-byte (0 residual bytes after
normalising `immutableReferences`), then *every* repo fact is a live fact, layout included — the
declaration order that produces slots is compiled into the code. Use it when it is available:

| Situation | Reach for |
|---|---|
| Repo artifact builds and you can link it | **Proof C** — strongest, and it settles layout without a slot-race |
| Unverified contract / no build | Proof A alone will not cover layout — fall back to Proof B (§4a slot-race) |
| Mappings all empty, so slot-race returns 0 for every candidate (see §9e of the dispatcher file) | Proof C, or bisect the creation tx for a **non-zero** witness |

The inverse direction matters too: Proof C **failing** is the §7-of-the-dispatcher-file relabelling
event — every repo-line-number finding needs re-derivation. So run it either way; both outcomes
change the report.

**And the self-correction rule that this produced** (`census` §4a, worth repeating at the point of
use): when a raw-slot probe returns `0` and refutes someone, **the first hypothesis is that your probe
is wrong** — a bare mapping slot is *always* 0. `cast storage $C 6` returning zero is not a control;
`keccak(key||slot)` is. Half this file's traps share one shape: *a cheap probe produced a clean number,
and the number was about your tooling, not the target.*

---

## 17. IDENTIFYING AN UNLABELLED FRONTING CONTRACT — the selector-census fingerprint beats disassembly

Session: a Relay transaction's `to` address was **not** the contract whose event it emitted. The outer
call went to `0x03a246e0bff569bca1cc76d25d6529a86b6154d3`, `tx.to`, whose runtime code was 3,379 bytes.
Every `eth_call` replay — direct to the executor *and* through this wrapper — reverted with **no
revert data**. The wrapper looked like an opaque blocker.

**Do not start with a disassembler.** Extract the dispatcher selectors and *fingerprint* them;
most fronting contracts are a known public deployment.

```bash
cast code $WRAPPER --rpc-url $R > /tmp/w.hex
cast disassemble $(cat /tmp/w.hex) > /tmp/w.txt
# selector = PUSH4 whose next instructions include EQ
python3 - <<'EOF'
lines=open('/tmp/w.txt').read().splitlines()
for i,l in enumerate(lines):
    if 'PUSH4' in l and 'EQ' in ' '.join(lines[i+1:i+4]):
        print(l.split()[-1])
EOF
```

Then the decisive move — **call every selector with empty calldata and read which ones answer**. A
contract's *read* methods answer with no arguments; its writers revert on empty data. Two categories,
zero ambiguity:

```
0x3408e470 -> 0x…83471          == 537713  ⇒ getChainId()
0x42cbb15c -> 0x…5ddbc3                   ⇒ getBlockNumber()
0x86d516e8 -> 0x…3b9aca00                 ⇒ getCurrentBlockGasLimit()
0x0f28c97d -> timestamp                   ⇒ getCurrentBlockTimestamp()
0x3e64a696 -> 0x07                        ⇒ getBasefee()
0x27e86d6e -> 32-byte hash                ⇒ getLastBlockHash()
0xa8b0574e -> 0x0                         ⇒ getCurrentBlockCoinbase()
0x82ad56cb, 0x252dba42, 0x4d2301cc, … -> execution reverted   ⇒ writers
```

Those seven are **Multicall3's exact getter set**, and `0x82ad56cb` is
`aggregate3((address,bool,bytes)[])` (its sibling `0x252dba42` = `aggregate`). One `cast call` per
selector resolved "opaque 3,379-byte blocker" to a **public Multicall3 deployment** — no
decompiler, no source, no explorer.

**Verify the identification functionally, not by selector alone:**

```python
cd = "0x82ad56cb" + abi_encode(["(address,bool,bytes)[]"],
        [[(TARGET, False, keccak(TARGET_GGETTER)[:4])]])
```

If `aggregate3` returns the target's getter output, the wrapper **is** a call forwarder. Confirmed:
`aggregate3 → HUB()` returned `0xDDD36172…` (the real Hub address).

### 17a. The question this immediately answers — and the one it does not

A public Multicall3 in front of your target changes `msg.sender`: `TARGET` now sees
`msg.sender == multicall3`. **Whether that is a vulnerability is decided by one comparison, not by
the wrapper:**

| Probe | Result | Verdict |
|---|---|---|
| privileged fn called directly from attacker EOA | REVERT | — |
| **same** privileged fn via `aggregate3` from attacker | **REVERT** | `msg.sender` is *not* the trust anchor → **no bypass** |
| same fn via wrapper **succeeds** where direct fails | — | privilege bypass — this is the finding |

Worked example (`grantRole(ADMIN_ROLE, attacker)`): both paths revert. Dead. Record it as
`DEAD: msg.sender not trusted`, in one line, and move on — **do not** spend the round building a
"via-batcher" narrative after this probe fires.

**Corollary that is easy to miss:** a wrapper being public also means **anyone can batch N calls to
your target in one tx**. Run the shape census on real traffic before believing that matters:

```python
# how many calls to TARGET does a typical batched tx contain?
shapes = Counter(sum(1 for c in outer if c[0].lower()==TARGET) for tx in txs)
# {1: 1144}  ⇒ no caller ever batches 2 executions ⇒ the cross-call-residue class has ZERO live targets
```

`{1: 1144}` is a **positive negative** — it does not prove the batch path is safe, it proves the
attack shape has never occurred, which is the honest way to state it.

## 18. "SWEEP THE WHOLE BALANCE" — the reachability tests that separate design from theft

Shape that reads as a critical and usually is not:

```solidity
// _finalizeWithdraw
uint256 withdrawAmount = HUB.balanceOf(address(this), tokenOutId);   // ENTIRE balance, not this order's
_fundSpenderAlias(tokenOutId, withdrawAmount);
```

Same in the input direction: `_runCalls` sends `HUB.balanceOf(this, tokenInId)` — again the whole
balance — to the caller-supplied resolver. **Both legs are "whatever the contract holds right now".**
That is only safe if the contract is *always empty* between executions. Test it in this order; the
first row alone usually decides.

**Test 1 — ratio census against the emitting event.** If every execution reports
`withdrawAmount / orderBalance ∈ (0, 1]` with a median just under 1, the sweep is bounded by the
order's own size in practice:

```
withdraw/orderBalance  min 0.5441  med 0.9931  p95 0.9985  max 1.0000
cases where withdraw > orderBalance*2: 0 / 1144
```

**Test 2 — the block-before balance. This is the one that actually proves the sweep runs.**

```python
# for each real execution at block B: read TARGET's balance at block B-1
balance_before = eth_call(balanceOf(TARGET, tokenOutId), block=B-1)
# then compare with the event's withdrawAmount
```

```
block     before_bal   withdrawAmount
5964387            0           408,258
5923828            0        19,972,366
6037147            0        14,683,936
```

`before == 0` for every sample ⇒ the contract holds nothing between executions ⇒ **there is nothing
to sweep that is not the current order's own output**. The sweep is *real in code* and *inert in
state*. Say exactly that: "code path confirmed, reachability requires a way to park foreign tokens in
the target between `_pullOrderFunds` and `_finalizeWithdraw`, and no such path was found."

**Test 3 — can an outsider even put tokens there?** Distinguish the revert *name*, because this is
where the answer lives:

| Revert | Means |
|---|---|
| `Unauthorized` / `AccessControlUnauthorizedAccount` / a named `OnlyX` error | there **is** an access gate — the deposit path is closed |
| **`panic 0x11` (arithmetic under/overflow)** | **no permission check at all** — it's the `balance -= amount` underflow talking |
| `ERC1155InsufficientBalance` | same — balance check only |

`panic 0x11` on a transfer from a zero-balance attacker is *evidence of an absent ACL*, not of a bug.
It proves the primitive is open; it does **not** prove the attacker can acquire the token. Separate
those two sentences in the report or the triager will merge them for you.

**Test 4 (the one that ends it) — locate the balance mapping slot.** If you cannot mint the token and
cannot find the slot, the theft chain is **BLOCKED**, not PROVEN. When nested-mapping derivations
(`keccak(keccak(a(addr)++base)++id)` and its permutations, both key orders, bases 0–13) all return
zero, say **"slot not located — reachability UNPROVEN"** and stop. Do not narrate a chain on the
strength of the code path alone.

**Also worth noticing while you are in there:** a `feesChargedByOrderAddress[order]` boolean set
*unconditionally* before the fee loop means the first execution (even with `fees == []`) permanently
disables fee collection for that order. That is a **revenue/design** observation, not theft — and it
is un-exploitable through a failed execution because the whole tx rolls back atomically.

## 19. THE HISTORICAL-DATA GATE — `usedRequests`-style guards and how to get past them without a key

When an execution contract guards with `mapping(bytes32 => bool) usedRequests`, every replay of a real
tx's calldata reverts regardless of which argument you swap — the guard fires on the *digest*, and the
digest is identical across your variants. Three escalating ways through, in cost order:

1. **Ask the contract for the digest** — `hashExecuteAndWithdrawRequest(tuple)` (selector present in the
   live bytecode: check `cast code` for `9c24b7d1`-style `PUSH4` before assuming it exists). Then
   `usedRequests(digest)` at block `B-1` (expect `0`) and at `B` (expect `1`). That pair **proves your
   reimplementation of the hashing is exact** — a far stronger claim than "my Python matches my Python".
2. **Re-implement the hash verbatim** and cross-check against #1. Free verification of encoding parity
   (`live-rpc` §16c): dynamic-field offsets are relative to the *tuple start*, `string` chainIds are
   `keccak256(bytes(s))` hashed not encoded, and per-item structs are `abi.encode(typehash, …)` **per
   element**, not one `abi.encode` of the array. Get any of those wrong and you will "discover" that
   the guard is set when it is not.
3. **State override** to force the guard slot to `0`:
   ```python
   key = keccak(abi_encode(["bytes32","uint256"], [digest, SLOT]))   # mapping slot, from
   ov  = {TARGET: {"stateDiff": {"0x"+key.hex(): "0x"+"00"*32}}}    # `forge inspect <C> storage-layout`
   eth_call({"to": TARGET, "data": real_calldata, "from": real_sender, "gas": "0x3b9aca0"}, hex(B), ov)
   ```
   **A three-variant matrix is the whole test:** A = exact real calldata, B = same but with the
   attacker-chosen parameter swapped, C = same but with a field that *is* in the digest edited.
   Verdicts: **A success + B success + C revert ⇒ the parameter is genuinely unbound.**
   A revert ⇒ **INCONCLUSIVE, not a refutation** — the baseline must pass before the comparison
   means anything. Print that verdict word explicitly; it is the difference between "unproven" and
   "disproven" and the user will (rightly) hold you to it.

4. **If the entry contract is `msg.sender`-sensitive (through a batcher), replay through the batcher**
   with the real `from`. Same override. Still revert ⇒ stop guessing and read the *sequence* of
   `_validateRequest`: `hasRole(ORACLE_ROLE, oracle)` → `block.timestamp > deadline` → `usedRequests`
   → `isValidSignatureNow`. Then test each gate **independently** with a direct `eth_call` to the
   component that owns it — e.g. `ORACLE.isValidSignature(digest, sig)` returning the EIP-1271 magic
   `0x1626ba7e` proves the signature is valid even when the whole `execute()` reverts. One gate at a
   time, each a separate call, is what turns "always reverts" into a named blocker.

**The honest stopping rule:** if the signature is genuine and the only remaining blocker is
"the oracle would have to sign my modified request", the finding is **UNPROVEN — requires oracle
cooperation**, and no amount of clever `eth_call` changes that. Do not let an unresolved gate be
papered over with a severity word.

**Detecting the gate type from bytecode**, useful before writing any probe:

```bash
code=$(cast code $TARGET --rpc-url $R)
for s in isValidSignatureNow_bytes32_bytes isValidSignature_bytes32_bytes; do …
# 7f035d73 (isValidSignatureNow) absent + 1626ba7e (isValidSignature) present in the MULTISIG
#   ⇒ the executor calls EIP-1271, so the oracle is a contract (multisig), not an EOA
#   ⇒ a 130-byte signature is 2-of-N, not a single secp256k1 sig
```

Ferret out the domain *before* blaming your own hashing: the EIP-712 domain of the **signer**, not of
the verifier, is what the digest was computed under. Reading `eip712Domain()` from the wrong contract
produced an entire session's worth of "my digest does not match" (name was `RelayOracleMultisig`;
the executor's own domain was irrelevant).




