# Signature-gated "write an entry for someone else" contracts: hijack classes + bytecode↔source identity proof

Condensed from a Relay Protocol round on `RelayGenericMapping`
(`0x822b4c4713433c6b88547845850a39343bf0957e`, chainId 537713): a small (164-line) contract that
stores arbitrary per-user data gated by an oracle EIP-712 signature. Four code defects were
PROVEN by forge and the deployed code was proven identical to the repo in ~6 calls. Verdict
shipped as **MEDIUM** (griefing/DoS), not fund theft — the discipline point at the end.

Companion files: `live-rpc-forensics-and-eth-call-trap.md` (§2 verified-source diff, §16
`eip712Domain()` identity, §16b consumer law), 
`rpc-census-supply-integrity-and-role-enumeration.md` (§1 `eth_getLogsWithCursor`, §6 role census),
and **`bytecode-dispatcher-forensics.md`** — read that one when §4's value-identity proof is not
enough and you must show the deployed bytecode is not this repo's build at all: it extracts the
dispatcher table from runtime code, **validates every `JUMPI` target against real `JUMPDEST`s**
(the step that separates "hidden entrypoint" from "dead branch"), and gives the relabelling rule for
every finding that was only ever proved against a repo line number.
**§9 of that file is the INVERSE case and the one you should reach for first when you expect a match:**
byte-**exact** equality proof — link the artifact's `linkReferences` placeholders, normalise the
compiler's `immutableReferences` ranges, and report `0 residual bytes`; plus the two traps that make a
correct diff look like a source delta, the `SHL` phantom selector, the `op == 0x5b` bug that fakes
"all branches dead", recomputing the EIP-712 digest as the strongest logic-identity proof, and
creation-block bisection when "0 logs" makes role holders look absent.
This file is the **authz-shape catalogue** for signature-gated writes plus the **fastest available
proof that live bytecode == repo source**.

**Section list:** §1 the `user`-is-a-parameter hijack (no `msg.sender` binding) · §2 the global flat
nonce namespace (cross-user AND cross-typehash DoS) · §3 no-overwrite ⇒ squat is permanent ·
§4 prove deployed == repo with selectors + typehash + domain · §5 who actually sends the writes
(the finding's real frequency bound) · **§5a check `hasRole` at read time — a `RoleRevoked` census
can RAISE severity: the senders holding no role at all proves the gate is signature-only, not
operator-only** · **§5b the FIRST-EVER write + its sender's historical role — converts "could be
triggered" into "operating mode since deploy", in two block numbers** · §6 mirror-the-function
Foundry pattern · §7 severity
discipline for data-plane (non-fund) findings · §8 subagent-claim verification.

---

## 1. `user` IS A PARAMETER ⇒ THE CALLER IS NOT THE BENEFICIARY

The shape to grep for on any signature-gated registry, mapping, or attestation store:

```solidity
function setEntry(
  address user,          // ← FREE PARAMETER
  bytes32 id,
  bytes calldata data,
  bytes32 nonce,
  address oracleMultisig,
  bytes calldata oracleSignature
) external {             // ← NO modifier, NO msg.sender reference anywhere
  if (id == bytes32(0)) revert EmptyId();
  if (data.length == 0) revert EmptyData();
  if (_entries[user][id].createdAt > 0) revert EntryAlreadyExists(user, id);
  if (usedNonces[nonce]) revert NonceAlreadyUsed(nonce);
  if (!hasRole(ORACLE_ROLE, oracleMultisig)) revert UnauthorizedOracle(oracleMultisig);

  bytes32 digest = _hashTypedDataV4(
    keccak256(abi.encode(SET_ENTRY_TYPEHASH, user, id, keccak256(data), nonce))
  );
  if (!oracleMultisig.isValidSignatureNow(digest, oracleSignature)) {
    revert InvalidOracleSignature(oracleMultisig);
  }
  usedNonces[nonce] = true;
  _entries[user][id] = Entry(data, block.timestamp);
}
```

Three separate questions must be answered, and they are *not* the same question:

| Question | If "no" | Consequence |
|---|---|---|
| Is `user` == `msg.sender`? | anyone can write for anyone | **front-run / substitution** |
| Is the write keyed per-user anywhere? | collisions across users | **cross-user DoS** |
| Can an existing entry be replaced? | squat is permanent | **permanent griefing** |

**The basis for the finding is the signature, not the caller.** A valid oracle signature is a
bearer token: whoever presents it first wins, because nothing in the calldata binds the tx to the
beneficiary's address. So the honest gate question is *"can a non-privileged party obtain or
observe one valid signature?"* — not *"can they call the function?"* (they always can; it has no
modifier).

**When `user` is a free parameter, the front-run is in-mempool, not in-role.** Anyone watching the
pending pool sees `(user, id, data, nonce, signature)` and submits the identical calldata first.
Nothing distinguishes the two txs.

Grep for the inverse to confirm the guard is genuinely absent (per
`live-rpc-forensics-and-eth-call-trap.md` §5a, an absence claim needs a positive control):

```bash
awk '/function setEntry\(/,/^  }/' RelayGenericMapping.sol | grep -n "msg\.sender\|_msgSender\|onlyRole\|require"
# empty output ⇒ genuinely unbound (this is the finding, cite the awk range)
```

---

## 2. `usedNonces` IS A GLOBAL FLAT MAP — two collision classes from one line

```solidity
mapping(bytes32 => bool) public usedNonces;   // ← NOT keyed by user
```

One line, two independent defects:

**(a) Cross-user collision.** Nonce reuse is only safe when the nonce namespace is scoped to the
principal. A flat map means user A consuming nonce `n` permanently blocks user B from using `n`.
Nonces are usually derived deterministically (hash of request fields), so a collision is reachable,
not merely theoretical.

**(b) Cross-typehash collision.** `setEntry` uses `SET_ENTRY_TYPEHASH`, `deleteEntry` uses
`DELETE_ENTRY_TYPEHASH`, and both consume the **same** `usedNonces`. Burning a nonce in one bricks
the paired operation in the other. Any two functions sharing a nonce store while using different
typehashes is this bug.

**The fix shape to recommend** (both halves, or you have only patched one):

```solidity
mapping(address user => mapping(bytes32 nonce => bool)) public usedNonces;   // scope to principal
// and namespace by action if the two operations must not share:
mapping(address => mapping(bytes32 => mapping(bytes8 action => bool))) ...
```

**Live confirmation that the map is global and real** — don't infer it from the source alone.
Decode a real tx's calldata to get its actual nonce argument, then read the map:

```bash
# calldata → args (setEntry: 0 user, 1 id, 2 data-offset, 3 nonce, 4 oracleMultisig, 5 sig-offset)
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX\"]}" \
  | python3 -c "import sys,json;b=json.load(sys.stdin)['result']['input'][10:];print([b[i:i+64] for i in range(0,len(b),64)][3])"

cast call $GM "usedNonces(bytes32)(bool)" 0x<that-nonce>   --rpc-url $RPC   # → true
cast call $GM "usedNonces(bytes32)(bool)" 0x1111…1111      --rpc-url $RPC   # → false (negative control)
```

The `true`/`false` pair is the whole proof: the map is real, is global (nothing user-scoped in the
key), and is written by production traffic.

---

## 3. NO-OVERWRITE ⇒ ANY SQUAT IS PERMANENT

```solidity
if (_entries[user][id].createdAt > 0) revert EntryAlreadyExists(user, id);   // setEntry
```

`createdAt` is used as an existence flag, and it is only ever cleared by `deleteEntry` (which itself
requires an oracle signature and a nonce). So:

- One write per `(user, id)`, **forever**, unless the oracle signs a delete **and** wins the race.
- Combined with §1 (anyone can write) this is permanent griefing: an attacker who observes a single
  valid signature can lock a `(user, id)` pair permanently with garbage data.

**Check the overwrite path before claiming perpetuity** — `grep -n "createdAt\|delete _entries\|_entries\[" contract.sol`
and enumerate every writer. If the only clear path is the same gated function, the squat is
permanent; state which function is the escape hatch.

---

## 4. PROVE DEPLOYED == REPO IN ~6 CALLS (selectors + typehash + domain)

For a contract that is **not** the one you already diffed, this is faster than fetching verified
source and is equally admissible — it binds *values the bytecode computes* to *values the source
computes*.

```bash
RPC=...; A=0x822b4c4713433c6b88547845850a39343bf0957e

cast codesize $A --rpc-url $RPC                       # nonzero ⇒ real contract (here 5670)
cast selectors $(cast code $A --rpc-url $RPC)         # full (selector, argtypes, mutability) inventory
cast call $A "SET_ENTRY_TYPEHASH()(bytes32)" --rpc-url $RPC
cast call $A "ORACLE_ROLE()(bytes32)"        --rpc-url $RPC
cast call $A "ADMIN_ROLE()(bytes32)"         --rpc-url $RPC
cast call $A "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])" --rpc-url $RPC

# repo side — recompute, never copy:
cast keccak "SetEntry(address user,bytes32 id,bytes data,bytes32 nonce)"
cast sig    "setEntry(address,bytes32,bytes,bytes32,address,bytes)"
```

`cast selectors` on runtime bytecode is the highest-value single call here: it yields the **exact
argument types** of every external function, which is precisely what you need to (a) match the repo's
function signatures, (b) decode production calldata, and (c) notice extra functions the repo does not
declare. Compare its `nonpayable` rows against `grep -n "^  function" contract.sol`.

**The pass condition is value equality, not resemblance:**

| Probe | Live | Repo (`cast keccak` / constructor) |
|---|---|---|
| `SET_ENTRY_TYPEHASH()` | `0x1a4153ec…92eb` | `keccak("SetEntry(address user,bytes32 id,bytes data,bytes32 nonce)")` = `0x1a4153ec…92eb` ✅ |
| `eip712Domain()` | `"RelayGenericMapping"` / `"1"` / `537713` / `0x822b4C47…` | `EIP712("RelayGenericMapping","1")` ✅ |
| `setEntry` selector | `0x0ab75d46` | `cast sig` = `0x0ab75d46` ✅ |

Once those three match, every repo read is a read of the live code — say it once as the evidence
baseline (same rule as `live-rpc-forensics-and-eth-call-trap.md` §2, but available when verified
source is not).

**Bonus:** `eip712Domain()` also proves the **chainId** the contract expects. A signature-domain /
message-chainId split (see §8) becomes concrete only when you have both numbers.

---

## 5. WHO ACTUALLY SENDS THE WRITES — this is the frequency bound on your finding

The census that decided severity: sample production txs from the event and resolve `from`:

```bash
# tx → sender, no explorer needed
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX\"]}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['from'])"
```

Result on this target: every sampled `EntrySet` sender was an address labelled as an operator backend
address — *at first read* said "holding `EDITOR_ROLE` on the hub", i.e. **the protocol backend sends the
writes, not end users**. That is the difference between "attacker front-runs users in the mempool daily"
(HIGH/Critical) and "the defect is real but the mempool never contains a user-originated signed write"
(MEDIUM).

> **⚠️ That role label was wrong, and §5a is why.** The `EDITOR_ROLE` reading came from an earlier,
> never-revoked grant pass, not from a live `hasRole` check. Re-running `hasRole` (and scraping
> `RoleRevoked`) showed those same senders hold **no role at all**. Keep the paragraph below as the
> correct shape of the argument, but treat **the initial role label as a hypothesis, not a finding** —
> §5a exists because this exact sentence got written before it was verified.

**Report both halves explicitly:**

> Contract has no caller binding (PROVEN). In production, writes are sent by operator-held
> addresses holding `EDITOR_ROLE`, so user-originated signed writes are not currently observable in
> the mempool. Any party who obtains one valid oracle signature (leak, replay, log scrape, cache)
> can front-run it. → MEDIUM, not HIGH.

This is not hedging — it is the difference between a claim you can defend and one a triager kills
with one line of block-explorer data.

### 5a. CHECK WHETHER THE ROLE IS STILL HELD — the census can *raise* severity, not just lower it

The frequency bound above was first written as *"senders hold `EDITOR_ROLE` ⇒ trusted operators ⇒
MEDIUM"*. That framing was **wrong in the target's favour**. Running a `RoleRevoked` census (the
mirror of the `RoleGranted` census in `rpc-census-supply-integrity-and-role-enumeration.md` §6)
showed those exact senders had their `OPERATOR_ROLE` **revoked** at block 176758 — long before they
sent the writes:

```bash
HUB=0xDDD3…9318
OP=$(cc $HUB 'OPERATOR_ROLE()(bytes32)')
for a in 0x6d878dc1… 0x9bee034f… 0x1a341143…; do
  printf "%-14s OPERATOR=" ${a:0:12}
  cc $HUB "hasRole(bytes32,address)(bool)" $OP $a      # → false, false, false
done
```

So the addresses that actually write `setEntry` in production hold **no role at all** — neither
`Hub.OPERATOR_ROLE` nor the mapping contract's own `ORACLE_ROLE` (only the multisig holds that).
The gate really is *signature-only*. That **strengthens** defect §1 rather than bounding it:

> The contract's real operating mode *is* "anyone bearing a valid signature may write". Production
> merely happens to use honest bearers. The defect is not hypothetical — it is how the contract
> works every day; only the actors are currently benign.

**Lessons:**

- **`RoleGranted` alone is not a roster.** Grant-then-revoke is common (early rotation, key hygiene),
  and `hasRole` at *read time* is the only truth. Any "this address is privileged" claim needs
  `hasRole` live, plus the revoke side of the census to see the churn.
- Scrape **both** `RoleGranted` and `RoleRevoked` topics; a role's `roster` is grants minus revokes,
  and a `RoleRevoked` you did not expect is usually **key rotation** — confirm by looking for the
  paired grant in nearby blocks (`grant(new) @5629662 → revoke(old) @5629679`) before writing
  "compromised".
- When the revocation *helps* the attacker's case, say so explicitly. Severity discipline (§7) is not
  "always downgrade" — it is "follow the evidence", in whichever direction it points.
- Ten addresses revoked in the same two blocks = **bulk rotation**, not ten compromises. Read the
  block numbers before the narrative.

### 5b. THE FIRST-EVER WRITE SETTLES "is this the design or a regression?"

After §5a showed the current senders hold no role, one question remained: *was `setEntry` ever
caller-bound, and it regressed?* The cheapest possible answer is the **oldest event in the
contract's history** — find it, then resolve its sender's role at that historical moment.

Find it by walking **backwards in windows** and stopping at the first non-empty one (a full-range
cursor query hangs — see `rpc-census-supply-integrity-and-role-enumeration.md` §1a):

```python
for lo in range(0, 1_000_001, 100_000):          # 100k windows from genesis
    hi = lo + 99_999; ...                        # one hit in 900k–1M, zero in the other ten
```

```console
user   = 0xdbafeeb6a096e83bf5804579129e2d96d7ff9bed
id     = 0x5c34103c30bde74642a0e3f0f2d42759af4ad8c353766ac75b98590aef84869d
block  = 999365            # ~11 months before tip
sender = 0x2be3df6c50fb1b11d8189c2d4de5c16f6712fac4
```

Three reads turned that into the strongest sentence in the report:

```bash
# 1. the entry is still live and unchanged — the squat-permanence claim (§3) in one call
cast call $GM "getEntry(address,bytes32)(bytes,uint256)" $USER $ID --rpc-url $RPC
# → (0xa16fda76…b972eb, 1773852175)

# 2. the sender's role TODAY
cast call $HUB "hasRole(bytes32,address)(bool)" $OPERATOR_ROLE $SENDER   # → false
cast call $GM  "hasRole(bytes32,address)(bool)" $ORACLE_ROLE   $SENDER   # → false

# 3. the sender's role HISTORY — is it in the revoked list, and when?
#    cross-reference the RoleRevoked census: 0x2be3df6c revoked @176758
```

Sender revoked at block **176,758**, wrote the entry at block **999,365** — i.e. **822,000 blocks
after losing the role it supposedly needed.** That single comparison converts the finding from *"a
code defect that could in principle be triggered"* into:

> The contract never checked caller identity — not on day one, not now. Its real operating mode is
> "anyone bearing a valid signature may write". Production merely happens to use honest bearers.

**Why this beats more theoretical analysis:** a reviewer's first objection to any
permissionless-write finding is *"surely it was gated once and you're looking at a bug"*. The
genesis write plus a historical role check answers it with two block numbers. Cost: one backwards
window scan plus three `cast call`s.

**Report shape for the permanence claim** — pair the earliest write with the no-overwrite guard
(§3) and the read-back, and the whole chain is falsifiable in three commands:

| Claim | The single command that proves it |
|---|---|
| permissionless since deploy | first `EntrySet` sender holds no role, at a block *after* its revocation |
| entries never change | `getEntry()` returns the original `createdAt` today |
| squat is permanent | only clear path is `deleteEntry`, itself signature+nonce gated (§3) |

### 5c. THE INVERSE-EVENT COUNT IS THE AMPLIFIER — `EntryDeleted == 0` across a full census

§3 says "no-overwrite ⇒ squat is permanent" from the *source*. The census makes it a measurement:

```
EntrySet UNIQUE   = 1,930,893
EntryDeleted UNIQ = 0            ← zero deletes in 1.93M writes
unique users      =   244,865
```

Zero deletes is not a null result to be dropped — combined with §3 it upgrades the claim from
"permanent unless the oracle signs a delete **and** wins the race" to:

> Every key ever written to this contract is still locked. There is no evidence any `deleteEntry` has
> ever succeeded, in the contract's entire history.

**So count the inverse event in the same sweep.** It costs one extra topic parameter and turns a
source-derived assertion into a 1.93M-sample measurement. If the inverse count is *high*, that is
equally important — it tells you the escape hatch is real and your permanence claim must be softened.

### 5d. CONCENTRATION CHANGES THE BLAST-RADIUS SENTENCE, NOT THE SEVERITY WORD

The same census yielded a top-user table:

| User | EntrySet |
|---|---|
| `0x9928901b…` | **1,195,680** (61.9%) |
| `0x106f690c…` | 9,801 |
| `0xe1e8e4bd…` | 3,226 |

One account holds 62% of everything. Two things follow, and they point in opposite directions:

- It **sharpens the impact sentence**: one leaked bearer signature aimed at `0x9928901b…` locks a key
  that 1.19M writes depend on — a materially worse outcome than squatting a random user.
- It does **not** change the severity word. Severity tracks *what the stored value controls*
  (§7), and here it still controls opaque bytes, not balances. **Concentration is blast-radius
  colour on a MEDIUM, not a reason to upgrade it.** Writing "MEDIUM, but the top holder accounts for
  62% of entries" is both honest and more useful than a stretched HIGH.

---

## 6. MIRROR-THE-FUNCTION FOUNDRY PATTERN (small contract, fast PASS/FAIL)

For a contract this small (or for a single suspicious function in a large one), do **not** attempt to
build the full repo. Copy the literal function into a test contract and get green/red:

```solidity
contract GenericMappingMirror {
    bytes32 public constant SET_ENTRY_TYPEHASH =
        keccak256("SetEntry(address user,bytes32 id,bytes data,bytes32 nonce)");
    struct Entry { bytes data; uint256 createdAt; }
    mapping(address => mapping(bytes32 => Entry)) internal _entries;
    mapping(bytes32 => bool) public usedNonces;
    mapping(address => mapping(bytes32 => bool)) public hasRole_;
    // … errors copied verbatim so expectRevert can match by selector …
    function setEntry(address user, bytes32 id, bytes calldata data, bytes32 nonce, address oracleMultisig) external {
        /* body copied VERBATIM, minus the signature-verification call */
    }
}
```

Rules that keep the mirror honest:

- **Copy the body literally**, including the order of the guards. A "cleaned up" mirror tests your
  rewrite, not the target. Keep a comment with the source `file:line` range you copied.
- **Drop only the parts that need deployed dependencies** (here: `isValidSignatureNow` and
  `hasRole` — replaced with a settable `mapping`/bool). Note the substitution in a comment; a
  substituted `hasRole` is fine because the *finding is not about the signature check*.
- **Copy the custom errors verbatim** so `vm.expectRevert(abi.encodeWithSelector(X.selector, …))`
  compiles and matches. Matching by selector is what makes the test evidence rather than assertion.
- One test per defect, named for the defect (`test_R24_a_frontrunSubstitutesEntry`). A passing file
  of 4 tests is a citable artifact; one big test is not.
- `emit log_string(...)` inside the test so `-vv` output carries the claim text next to `[PASS]`.

Then run and quote the run:

```bash
forge test --match-contract R24_GenericMappingHijack -vv
# [PASS] test_R24_a_frontrunSubstitutesEntry …  PROVEN-1: no msg.sender binding → permanent griefing
# Suite result: ok. 4 passed; 0 failed
```

**Harness hygiene that bit this session:** fleet-authored test files with stale struct constructors
break `forge test` at *compile* time, so one broken unrelated file hides the whole suite. Quarantine
rather than delete — the fleet agent may still be editing them:

```bash
mv test/C6_Builders.t.sol /tmp/C6B.bak     # out of the tree, kept as evidence
forge test 2>&1 | tail -3                  # 121 tests passed, 0 failed
```

Report the quarantined files in the round summary. A suite that cannot compile reports zero
information; a suite with three files parked outside the tree reports real information.

---

## 7. SEVERITY DISCIPLINE FOR DATA-PLANE (non-fund) FINDINGS

Four proven defects on this contract still shipped as **MEDIUM**, and that was correct:

| Aspect | Verdict |
|---|---|
| Code defect | PROVEN (4/4 forge + live typehash/domain match) |
| Contract deployed & in use | PROVEN (45k+ `EntrySet` events) |
| Exploitable **without** an oracle signature | **NOT proven** |
| Exploitable **with** one leaked/observed valid signature | PROVEN in mirror |
| Direct fund impact | **NONE** — the mapping stores arbitrary bytes, not balances |

The rule: **enumerate what the stored value controls before assigning a severity.** This contract
stores opaque `bytes` for `(user, id)`; nothing in the repo reads it to move funds. A hijacked entry
is data corruption and griefing, ~MEDIUM. Escalate to HIGH/CRITICAL only when a *consumer* turns the
stored entry into an authorization decision or a value transfer — grep for `getEntry(` / the mapping
readers exactly as `live-rpc-forensics-and-eth-call-trap.md` §16b demands for unbound fields.

Do **not** inflate because the number of faults is four. Four proven MEDIUM-class defects is a
MEDIUM finding; the count belongs in the write-up, not in the severity word.

---

## 8. VERIFY A SUBAGENT'S CRYPTOGRAPHIC CLAIM WITH YOUR OWN SCRIPT

A subagent reported a HIGH: EIP-712 domain `chainId` derived from `signatureChainId` while the
signed struct's `chainId` field came from `walletChainId` — two independent user-supplied fields,
no cross-check, so a signature minted under chain A is accepted and recorded as chain B. Plausible,
well-cited (`index.ts:1182` vs `:1197`), and the subagent claimed a passing test.

Two independent checks before accepting it, both cheap:

**(a) Read the exact cited lines yourself.** The claim survived — `chainId: data.walletChainId` in
the message, `NONCE_MAPPING_DOMAIN(Number(signatureChain.additionalData?.evmChainId))` in the domain,
and the schema (`nonce-mapping/v2.ts`) declares both as free `Type.String()`. Confirming the line
numbers and the absence of a cross-check is the *minimum* bar for citing a subagent finding.

**(b) Reproduce the crypto in a standalone script, not in their harness.** Their test file failed
`ts-jest` on missing global types; re-running it was a dead end. A 25-line ESM script using the real
library settled it in one run:

```javascript
const sig = await acct.signTypedData({ domain: DOMAIN(1), types, primaryType:"NonceMapping", message });
const asServer  = await verifyTypedData({ address: acct.address, domain: DOMAIN(1),  types, primaryType:"NonceMapping", message, signature: sig });
const asCorrect = await verifyTypedData({ address: acct.address, domain: DOMAIN(10), types, primaryType:"NonceMapping", message, signature: sig });
// asServer=true, asCorrect=false  ⇒ the signature is NOT bound to the chain it is recorded under
```

Output that decides it: `verified under domain 1 (server): true` / `verified under domain 10
(correct): false`. Note the script must live **inside** the repo dir for `node` to resolve
`node_modules` (a copy in `/tmp` failed `ERR_MODULE_NOT_FOUND`).

**Why not just trust it:** the same fleet run also produced a 4byte lookup mapping `0x01ffc9a7`
(ERC-165 `supportsInterface`) to `pizza_mandate_apology(uint256)` and built a "source registry"
narrative on top of it. Nonsense selectors are the tell that a worker is guessing from an API
instead of reading the source. **Every subagent supply-list gets spot-checked; the ones that matter
(severity-bearing, chain-bearing) get fully re-derived.**

Corollary for a real split-domain finding: cryptographic validity is not impact. Ship it as
"binding defect PROVEN, on-chain impact UNPROVEN pending the contract that consumes the mapping" —
which is exactly the step that was still open at the end of the round.
