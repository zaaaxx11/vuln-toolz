# Delegation in a round loop — fan-out, and how to read what comes back

Companion to `references/chain-closure-audit.md` §2 (near-misses) and
`references/truncation-and-reachability-discipline.md`. Used when two or more unread
components are sitting in parallel and the user says "paralel, spawn sub agent".

The trap this file prevents is **not** the usual "subagents hallucinate". It is the
inverse, and it happened here: a subagent's report was **correct**, the main thread
mis-remembered its own earlier output, **publicly accused the subagent of fabricating**,
and then had to verify and retract. That is a self-inflicted credibility hit in front of
the user, and it is easy to avoid.

---

## 1. What to fan out (and what not to)

Good parallel units are **independent, source-closed components with a binary verdict**:

```text
[x] one function's authorization gate, against one contract's source
[x] sibling-instance diff (A vs B) where both sources are already on disk
[x] an unread module's public surface, judged NOT-EXPLOITABLE / EXPLOITABLE
[ ] anything needing the parent's chain state to interpret   -> serialize it
[ ] "find me a bug somewhere"                                -> no anchor, no verdict
```

Two is usually right. Three is the ceiling worth the coordination cost; beyond that the
summaries stop being readable in one pass.

Give each child:

```text
- absolute paths to the sources already on disk (do not let it re-fetch and re-derive)
- the exact contract address(es) and the tokenId/amount to probe with
- the literal output path for script AND log  (so the parent can read the artifact)
- the required verdict vocabulary: EXPLOITABLE / NOT-EXPLOITABLE / INCONCLUSIVE
- "do not fabricate; if a probe fails, report the failure"
```

Requiring a **file path** for the log is the highest-value instruction. It means the
parent can check the claim instead of trusting the prose, and it survives summarisation.

---

## 2. Reading a returned summary: verify the CLAIM, not the vibe

A subagent summary is a **self-report**. That cuts in both directions:

```text
subagent says X is gated -> may be true, may be a body it only skimmed
subagent says Y is missing -> may be false negative from its own tool error
```

But also:

```text
parent REMEMBERS X as ungated -> parent may simply be wrong
```

Here the child reported `burn()` is `onlyRole(OPERATOR_ROLE)` at `src_HUB1.sol:397` and
`_burn` at `:493-499`. The parent had, four rounds earlier, concluded from a *revert
selector* that `burn` was gated — and had **never read the declaration line**. Because the
parent's own mental model only had "reverts with `AccessControlUnauthorizedAccount`", the
child's precise file:line claim looked like an invention. It was not:

```solidity
L393-400  function burn(address sender, uint256 id, uint256 amount)
              public onlyRole(OPERATOR_ROLE) returns (bool result)   // gate IS declared here
L493-499  function _burn(address sender, uint256 id, uint256 amount) internal {
              balanceOf[sender][id] -= amount;    // <- the Panic(0x11) source, one layer down
```

Both loops then reconciled: the R24 `Panic` and the R29 `AccessControl` had always been
**two different layers of the same function**, not a contradiction.

```text
RULE  before calling a subagent claim wrong, re-read the file:line it cites.
      One read_file call. If the line says what the child says, the parent's model was
      the stale artifact — say so, in those words, and move on.

RULE  the parent's own memory of its own earlier conclusion is NOT evidence. Selector
      inference ("it reverted with 0xe2517d3f, so there is a role check") is weaker than
      a declaration read ("public onlyRole(...)"). When they collide, the read wins.

RULE  a subagent that cites file:line + a log path can be checked in one call and
      should be. A subagent that cites only prose is the one to distrust.

RULE  never accuse fabrication in the user-facing message before checking. If you are
      wrong, the retraction costs more than the original doubt.
```

---

## 3. Reconcile, don't just concatenate

Two reports land and the useful act is to fold them into **one** ledger state:

```text
CHILD A  burn() on Allocator#2       -> NOT-EXPLOITABLE (gate L265-281, 5 checks)
CHILD B  Executor#2 vs Executor#1    -> NOT-EXPLOITABLE (byte-identical, 312/9131 B
                                        delta = 14x20B immutables + 1x32B domain sep)
PARENT   F-10 (global isOperator)    -> unchanged, still IN-CODE, grade by holder census
```

Two things to extract that the children cannot see from inside their own brief:

1. **Corrections to the parent's assumptions.** Child A found `hasRole(OPERATOR_ROLE,
   Executor#2) == 0` on Hub#1 — the parent had been carrying "Executor#2 is an operator"
   in its context for several rounds. That is a **context bug**, and it must be fixed in
   the next round's brief, not just noted.
2. **Confirmations that upgrade a parent claim's evidence class.** Child B proved
   `Executor#2` is a clean redeployment *by masked bytecode comparison*, which is
   stronger than the parent's ABI-shape argument. Upgrade the evidence, keep the grade.

```text
RULE  a child's correction of a parent assumption is worth more than its verdict —
      it prevents the next N rounds from re-deriving from a false premise. Lead with it.

RULE  when a child's method is stronger than the parent's (masked bytecode > ABI shape;
      live differential > static read), adopt the method for the parent's own claims too.
```

---

## 3b. Numeric claims from children need their own check — but the check is cheap

The same fan-out also delivered a bytecode census: "runtime is 9,131 B on both; 15 runs
differ by exactly 312 B (14×20-byte immutables + 1×32-byte domain separator = 3.42%); after
masking, zero opcodes differ." Prose like that is exactly the shape a plausible-sounding
hallucination takes, so it has to be spot-checked rather than believed or dismissed.

The decisive detail is that **`eth_getCode` length already bounds the claim**:

```text
len(getCode(EX1)) - 2)/2 == len(getCode(EX2)) - 2)/2      # size equality is one RPC each
source md5 of getsourcecode(EX1) == that of getsourcecode(EX2)   # identical verified source
```

When both the deployed size and the verified-source hash match, "same code, different
immutables" is the only remaining explanation and the child's masked-diff is corroborative
rather than load-bearing. So the check costs two calls, and it converts an unverifiable
opcode claim into a bounded one.

```text
RULE  verify a child's NUMERIC claim against a coarser invariant you can measure yourself
      (deployed byte size, source hash, digest). You do not have to reproduce its full
      differential to accept it — you have to bound it.

RULE  "byte-identical modulo immutables" is a much stronger statement than "same ABI" or
      "same function list". When a child establishes the stronger one, the parent's
      weaker argument should be replaced in the report, and the grade stays the same.
```

---

## 4b. Severity inflation is the dominant child failure — re-derive the gate, don't inherit the label

Children are good at *finding* and bad at *grading*. Both directions of error appear in one
batch, so grade every child finding yourself against Rule 6 and Rule 21.

**Observed inflation.** A child ranked `RelayDepository.execute` as **Critical** because
"no access control, no `nonReentrant`, holds user deposits, makes arbitrary `call{value:}`".
Two facts collapse it, both one read away:

```solidity
// RelayDepository.sol:245-255 — callHashes are INSIDE the signed structHash
structHash = keccak256(abi.encode(_CALL_REQUEST_TYPEHASH,
              keccak256(abi.encodePacked(callHashes)), request.nonce, request.expiration));
eip712Hash = _hashTypedData(structHash);              // domain-bound
if (!allocator.isValidSignatureNow(eip712Hash, signature)) revert InvalidSignature();
```

```text
1. `calls[]` is committed by the digest -> an attacker cannot inject a call. Not open.
2. `callRequests[structHash] = true` is set BEFORE `_executeCalls`
   -> re-entry with the SAME request reverts CallRequestAlreadyUsed.
   Re-entry needs a SECOND valid allocator signature.
=> the whole surface is "if the allocator key is compromised, funds drain".
   That is a key-management trust assumption, not a code bug. Medium at most.
   The missing nonReentrant is real but is defence-in-depth debt with no reachable path.
```

**Observed deflation is the opposite risk:** a child marks something `UNTESTED` that a
single `read_file` settles. The alias-holder "can burn a legit signature's nonce" claim
(`agent3_fuzz.md` §7(b)) died on one read:

```solidity
// RelayAllocator.sol:273-276 — the signature path is the ONLY branch that touches usedNonces
bool callerAuthorized = callerIsSpender || callerIsOperator;
if (!callerAuthorized) { callerAuthorized = consumeSpenderSignature(params, signature); }
// -> alias-holder and operator branches never call it -> never write usedNonces
// -> they CANNOT mark another party's nonce. Self-griefing at most. REFUTED.
```

```text
RULE  a child's severity tag is a suggestion; its file:line is the deliverable.
      Re-derive the grade from the cited lines, in the parent, before it reaches the user.
RULE  "no access control / no guard / no nonReentrant" is NOT a severity argument.
      Ask the two questions that decide it: what commits the input, and what blocks re-entry.
RULE  a child's own `UNTESTED` is a work item for the parent, not a verdict. One read
      often settles it — and settling it is cheaper than carrying it for three rounds.
RULE  when a child retracts its own finding mid-report (revert-unwinds-state, EVM
      semantics), keep the retraction and its reasoning in the ledger. A self-retracted
      child is more trustworthy than a confident one; record WHY it died so nobody re-opens it.
```

## 4c. A child hitting its iteration cap may return findings and NO file

Three children were dispatched with an explicit "write `/path/agentN_*.md`" instruction.
One burned its budget reading and returned prose only: *"I hit the iteration cap before the
deliverable file could be written."* The read was real and the citations were usable — but
there was nothing on disk, so the artifact-of-record did not exist.

```text
[x] before using a child's report, stat/read its declared output path
[x] if missing: salvage the summary from the delegate result, write it to disk YOURSELF
    under the intended name, and mark it "reconstructed from subagent summary"
[x] budget the brief so the write is not the last step it can afford — put
    "write the file FIRST, then keep refining" in the brief
[ ] never cite a child's file as evidence without having read that file
```

Corollary: a child that reports `forge build fails, remappings unresolved` is reporting
**environment**, not a code fact. Here one child could not build in-workspace (`lib/`,
`node_modules/` absent) but ran experiments in a scratch project with real output. Its
verdicts were still usable — the build failure was scoped, not global. Distinguish
"this contract is unbuildable" from "my checkout lacks deps".

---

## 5. Closing out a fan-out

```text
[ ] each child's verdict recorded with its log path
[ ] each child's declared output file READ (not assumed written) — see §4c
[ ] each child's SEVERITY re-derived from its cited file:line — see §4b
[ ] every child claim that contradicts the parent: re-read the cited file:line
[ ] every child NUMERIC claim bounded by a coarser invariant measured in the main thread
[ ] any parent assumption a child falsified: fixed in the next brief AND stated to user
[ ] any child method stronger than parent's: adopted
[ ] child self-retractions preserved in the dead-hypothesis ledger with their reasoning
[ ] components still unread after the fan-out: named explicitly in coverage
[ ] no fabricated-accusation: any doubt about a child was checked before being voiced
```
