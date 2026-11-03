---
name: adversarial-multi-round-audit
description: "Live adversarial multi-round security audit loops with mandatory cross-verification. Use for 'hunt terus', round loops, subagent fan-out, or reconciling prior claims before elevation. Covers: round-loop engine AND the HUNT-OS `hunt` CLI ledger, brief design, live RPC verification, ABI ground-truthing, artifact-built selectors, revert-selector naming, positive controls, EIP-1271, gate ORDER, allowance-bypass, PLACEHOLDER-PROVENANCE, MULTI-INSTANCE CENSUS, GETTER-FORM TRAPS, STRUCT-DECODE TRAPS, CAPABILITY-vs-REACHABILITY, HAND-BUILT-CALLDATA BUGS, CONFIG rings and CONFIG-KEY DERIVATION, SOURCE-INTEGRITY, OFF-CHAIN API RECON, DORMANT-SURFACE grading, Gateway two-hash receivers, EIP-712 DIGEST CALIBRATION (compile, don't brute-force), EVENT-ATTESTED VOLUME, EIP-1167 FORWARDER FALSE POSITIVES, EIP-7702 DELEGATION IDENTITY, FABRICATED-ADDRESS-FROM-TRUNCATION, ADDRESS-PROFILE STALENESS, LOG-SCAN GEOGRAPHY-BLEED, IDENTIFIER-UNIQUENESS CENSUS, CHILD-SEVERITY RE-DERIVATION, REVERT-IS-NOT-A-GUARD, verdict hygiene."
---

# Adversarial Multi-Round Audit

Run a live target audit as **timed adversarial sprints** with **mandatory cross-verification** and **contradiction resolution**. This skill governs the orchestration layer; pair it with a domain skill (e.g. `onchain-protocol-audit`, `readonly-security-audit`) for target-specific probes.

## When to use

- User asks for repeated hunt rounds, subagent fan-out, or "hunt terus".
- Previous subagent claims conflict with each other or with your own probes.

## Two traps that create fabricated findings — read before any exploit claim

- `eth_getCode` returning `0x` is **NOT** proof a contract is absent. Cross-check
  `?module=account&action=txlist&address=<ADDR>` for a deploy tx (`contractAddress`)
  and re-probe `eth_getCode` at `latest` more than once. Historical/archive gaps make
  live contracts read as empty.
- In an event with ≥2 dynamic params, an **offset word is not a length word**. Resolve
  each offset (`idx = word//32`) then read the length there. Anchor the decode against
  a value already known from calldata (e.g. the request `amount`) — if the anchor
  doesn't appear, the decoder is wrong, not the target.
- A `status=0x1` receipt plus a decoded zero-length array is a contradiction ⇒
  re-derive by hand; do not report it as data loss.
- **Support file:** `references/relay-settlement-decode-hygiene.md` — five-retraction post-mortem
  (dynamic-event word-grid parsing that fabricates phantom addresses, missing decimal division,
  registry emptiness proven with the wrong key encoding, gate-identity confusion, revert isolation).
  Load it whenever a claim rests on a hand-written decoder.
- Full checklist + retraction format: `references/empty-contract-and-event-decode-traps.md`.
- You need to defend a finding against adversarial rebuttal before elevating it.
- Timer/sprint discipline is required (e.g. 60-minute hard stops).
- **Every remaining path was declared signature/role-gated.** Then the gate is the target: switch to
  `onchain-protocol-audit` → `references/signature-gate-and-verifier-audit.md` (resolve the LIVE verifier address,
  byte-flip binding differential, minimal-call rule, per-consumer gate matrix).

## Support files

| File | Use |
|---|---|
| `scripts/round_loop_engine.py` | Stateful round dispatcher. Externalises the dead-hypothesis ledger so round N+1 cannot re-test what round N refuted. Run it as cron STEP 0. |
| `scripts/build_selector_from_artifact.py` | Builds a call's selector + calldata from the compiled **artifact** (`out/<X>.sol/<X>.json`), flattening struct components. Use instead of hand-writing signatures — hand-written ones silently miss every struct-typed function. |
| `scripts/recover_live_call_shape.py` | **Ground truth when the selector still can't be found.** Explorer `txlist` → every tx that ever hit the contract with selector + receipt status → `--dump` the newest SUCCESSFUL calldata → `--tx --abi` to decode real args. Encodes the two traps: `topics[2]==contract` means it RECEIVED, not that it was CALLED; and nested `aggregate3` offsets. |
| `scripts/census_instances.py` | **Run this BEFORE round 1, not after round 20.** Enumerates the DISTINCT values of every identity field (executor, resolver, oracle/signer, hub) across all real txs, so sibling deployments with a different trust model cannot hide behind a verdict scoped to one instance. Exits non-zero on "no txs" with the reminder that sub-calls never appear in `txlist`. See pitfall 30. |
| `references/eip1271-verifier-forge-probes.md` | **The verifier-audit round itself.** The 11-input `isValidSignature` forge matrix (empty / 1B / 64B / 65B-junk / 129B / 130B-zero / 130B-ff / dup / reversed / 1-valid+65B-junk / high-s) with expected `0x0000…` for each; the **anvil-fork positive control** (`stateDiff` is silently ignored by some RPCs, `anvil_setStorageAt` is not); the **`unsafe_sign_hash` vs `encode_defunct` trap** that makes every hand-built sig recover to the wrong address; the **left-pad mapping-slot bug** that fakes an empty `isSigner` and a Critical; decoding slot order from the `MSTORE`/`SHA3` pair in runtime; and the `getRoleAdmin` amplification check. |
| `references/multi-instance-trust-map.md` | **Companion to the census.** What to do once a set has size > 1: compare immutables directly (`HUB()` vs `hub()` casing trap), build the per-instance trust matrix (separate `balanceOf` ledgers, disjoint signer sets), prove two signers are the *same source* via selector-set equality before hunting their bugs, and grade unguarded entrypoints on **funding history from receipts**, not current balance (REAL/INERT/ARMED-BY-FUNDING vs DEAD-CODE). Includes the cross-instance guard-order table that flips INCONCLUSIVE → structural REFUTED. |
| `references/live-call-surface-census.md` | Is the surface **used**, and how is it reached? `txlist` over block-scanning, the sub-call/batcher blind spot, cross-instance bytecode-length vs runtime-hash. **§4a** = the `balanceOf == 0` is a SNAPSHOT trap (a broke contract may be a periodically-funded one), the "resolver never executed" false negative, and the receipt-based positive control that makes a zero balance a real measurement. |
| `references/abi-and-field-verification.md` | The 7-error checklist: `error`-before-`result`, live-event-layout-over-local-ABI, one-receipt-per-field, read-to-closing-brace, library-decode-over-hand-walking, "missing guard ≠ vulnerability", "a gate on ONE use-site does not gate the derived value". **Read this before publishing any finding.** |
| `references/selector-and-getter-form-traps.md` | **The call-shape family that manufactures "this function is missing".** Role hash vs role getter selector (`0xa4980720` is a RETURN value, `0x75b238fc` is the selector); wrong argument type on a getter (`erc20Views(bytes32)` vs `(uint256)`); equal-ABI/different-bytecode = different build not a weaker version (prefix/suffix containment test); truncated hex preview rendering `0x0000000000` for a real address; pointer-getter vs live rate-limit to find the ACTIVE instance among siblings sharing one token; the infinite-approval exemption branch. |
| `references/unbound-parameter-and-permissionless-injection.md` | The complement of Rule 7: which signed parameters are **NOT** in the digest, `pull-whole-balance` sinks, permissionless top-up, and the profit-identity gate that decides whether a real unbound parameter is a bounty or a zero-profit curiosity. **§5** = why `isOperator` membership is per-**pair** (injection ≠ authorisation); **§6** = guard ORDER vs the two-pointer differential that proves "no caller gate". |
| `references/proxy-takeover-and-reinit-closure.md` | (in `onchain-protocol-audit`) The **"can an attacker take over / re-init / re-point the trusted helper contract?"** angle — the one that looks strongest and dies fastest. Six ordered checks: no-`initialize`-at-all proof (source + bytecode + ABI, 3 independent), `immutable` config ⇒ no storage to overwrite, EIP-1167 prefix vs "same size" fallacy, **runtime-hash across instances** (same length ≠ shared code), write-site census for the trusted mapping, explorer ABI+txlist+creation-event triangulation. Includes the CREATE vs CREATE2 vs idempotent-guard DoS-only table and the **EOA `initialize()` control** (`result: "0x"`) that proves the RPC is not faking reverts. |
| `references/helper-exemption-and-allowance-bypass.md` | **The round AFTER a refuted takeover**: "if I can't become the exempted caller, what can the exempted caller be made to do?" — the two-layer gate proof (parent bypass alive + helper re-implements the guard), allowance-ledger ownership, the `Panic(17)` underflow-coincidence trap, the `amount == 0` permissionless hole, and the **`from=<helper>` positive control** that licenses the whole verdict. |
| `references/hunt-os-ledger-operations.md` | **When an EXTERNAL ledger (HUNT-OS / `hunt` CLI) owns state instead of `hunt_state.json`.** Install without trusting `--adapter hermes` (it is a no-op pointer), phase gates that need real `surface_map`/`attack_plan` artifacts, the closed `--klass` vocabulary, `lead park --retrigger "<observable> :: <check>"` two-sided tripwires (and that a parked lead must be `reopen`ed before re-parking), `finding promote` requiring a PoC path, and `overturn --id` taking an **int** (`1`) not the display label (`F-1`). Also why tripwires beat a flat dead-hypothesis array. |
| `templates/sweep_poc_foundry.t.sol` | **Copy-and-modify Foundry PoC scaffold** for a whole-balance-sweep sink, always shipped with its paired negative control. Encodes the six harness pitfalls that cost real iterations: test-file-relative import paths, explicit `forge-std/console.sol` import, `makeAddr()` being stateful (kills `view`), the OPERATOR_ROLE grant ladder needed before setUp runs, **reading a deep revert as failure when the drain already succeeded**, and `expectRevert()` without a selector swallowing harness typos. |

## Struct-heavy signatures: never compute a selector by hand

**Error #8 of the self-refutation streak.** `execute(request, callResolver, callResolverData, oracle, signature)`
returned selector `0x9d79c526` (hand-written `((string,bytes,…))`), then `0xba028c6e` (from the artifact's
`components`), then `0x5a8351d1` (flattened) — **none of which existed in the deployed bytecode**, while two sibling
getters in the same contract did. That looked like "the live contract is a different version" and nearly produced a
Critical drafted on a contract that may not be the target.

Rules:
- **Read the ABI artifact, not the `.sol`.** `out/X.sol/X.json` → for each `input`, if `type` starts with `tuple`,
  replace it with `'(' + ','.join(component.type) + ')'` (recursive for nested tuples). Do not trust
  `internalType: "struct Foo"` and do not guess field order from the source's declaration order.
- **`uint256` vs `bytes32` for nonces changes the selector and is invisible in a terse type list.** `nonce` was
  `bytes32` here; a `uint256` assumption produced three wrong selectors in a row. Read the artifact's declared types.
- **A missing selector is not proof of a different contract.** Before concluding "live ≠ repo", compare
  `len(deployedBytecode)` live vs artifact — equal size plus equal getter selectors means same contract, wrong
  selector. Then fix your signature. Declaring a version mismatch from a failed PUSH4/`in` search is the same
  root-cause class as naming a field before proving it.
- **Only source-verified explorer source or a live calldata replay is ground truth** for what a function accepts.
  Bytecode selector scans are a hypothesis (see `onchain-protocol-audit` §1.1 on the `PUSH3` trap).
- **When the artifact-built selector is STILL absent from the bytecode, stop computing and go find a real
  transaction.** The chain accepted that call, so its `input` is the answer. Explorer `txlist` (one request, full
  history) beats a full-block scan, which is O(blocks) and dies on rate-limited RPCs — a 5-minute
  `eth_getBlockByNumber` sweep produced literally zero progress in this session. Use
  `scripts/recover_live_call_shape.py`.
  - `to == contract` is what identifies a call. A log with `topics[2] == contract` means the contract **received a
    transfer**, not that it was called — chasing those produced two "hits" that decoded into a completely different
    contract's calldata.
  - Modern targets route through a **batcher** (`aggregate3`, selector `0x82ad56cb`). Walk the
    `(address target, bool allowFail, bytes data)[]` tuples; offsets are **nested** (element offset relative to array
    start, `bytes` offset relative to element start). A flat walk yields nonsense like `target=0x…60` — that
    nonsense is your walker's bug, not a finding.
  - Payoff in-session: the real selector was `0x432994b7` and *was* in the bytecode scan all along — the hand-built
    signatures had simply never matched it. One `txlist` call ended a 40-minute detour.

## The unbound-parameter class (check it every round)

> **Permission predicates with two concepts:** a predicate shaped
> `return hasRole(ROLE, actor) || perAccountMap[account][actor];` **discards
> `account` in the first branch**, turning a per-account grant into a global one
> over every holder's balance. Detection procedure, grading table by who holds the
> role, and the two calldata-decode bugs that fake findings in this area
> (struct-offset shift, 28-hex address padding → `data: None`):
> `references/permission-model-global-operator.md`.
>
> **§5c — the `amount=0` control.** When a differential for a `burn`/`withdraw` gate
> reverts identically on every arm, re-run the *same* request with `amount = 0`. A
> success (a storage-derived hash) proves the gate PASSED and localises the shared
> `Panic(0x11)` to the sink's balance math — the difference between an ambiguous
> `PROBE-INVALID` pair and a labelled `NOT-EXPLOITABLE` verdict. **§5d — derived
> alias vs real holder:** confirm the address the sink actually debits holds the
> token (`balanceOf(alias, tid)`) before reading its revert as an authz signal; the
> real holder may only be burnable through the role-gated Hub entrypoint.
>
> **Hand-built calldata (`build_request`-style encoders):** a `pad()`/`Sel()` that
> returns `0x`-prefixed hex will splice a literal `0x` *inside* the blob, and then
> every probe in the set fails identically — reading as "the gate blocks everyone"
> or "wrong contract version". See `references/abi-and-field-verification.md` Rule 18.

> **Benign-redeployment claims need a computed proof, not a diff glance.** Same verified
> source + different runtime bytecode is normal (immutables + EIP-712 domain separator).
> Run `scripts/immutable_delta_proof.py <addrA> <addrB>`: it groups differing bytes into
> contiguous runs, blanks them in both copies and asserts the remainders match. Expect
> ~20-byte runs (address immutables) and 32-byte runs (bytes32/domain separator); a run
> of 17 or 23 bytes means mis-grouping *or* a real logic delta. See
> `references/decode-and-proof-traps.md` §1a — a hand-rolled per-byte splitter reported
> 55 phantom runs where the truth was 15.

> **Pin ONE block for any balance-vs-amount differential.** Rebasing positions change
> `balanceOf` every block; comparing a balance read at block N against a transfer probed
> at block N+3 manufactures phantom `Panic(0x11)`s and "someone drained it" narratives.
> If the token's own holder fails a self-transfer, your probe is `INCONCLUSIVE`, not
> evidence. See `references/decode-and-proof-traps.md` §5c.

> **Multisig thresholds are cosmetic until you read `owner()`; role censuses are
> PER-CONTRACT; and three positive controls fail on your own instrument (token contract
> holding its own supply, `isExecuted(random)==0`, and nested-mapping getter signatures).
> See `references/multisig-owner-and-oracle-roles.md` — read it before grading anything
> "protected by 2-of-3" or declaring a module inert because a role is unset elsewhere.

> **Role / permission census across history:** do not trust `eth_getLogs` alone.
> Rate-limited RPCs silently return `[]` across wide ranges and expose a
> `*WithCursor` method instead; a partial event scan produced 12 fabricated
> "active OPERATOR EOAs" that live `hasRole` refuted. Follow the cursor to
> exhaustion **per window**, then reconcile every derived holder against live
> `hasRole` before writing a single row. Full procedure, schema table, control
> hierarchy and budget discipline: `references/log-enumeration-and-role-census.md`.
> Runnable implementation (correct cursor loop + mandatory reconciliation, exit 2 on
> mismatch): `scripts/scan_role_events.py`.

Rule 7 asks *"is the derived value gated at every consumer"*. The dual question, and the one that produced this
session's only real (medium) find:

> **Which security-relevant parameter is NOT inside the signed digest?**

```
digest binds: chainIds, currencies, outAmountMinimum, depository, orderAddress, receiver, data, fees, nonce, deadline
digest omits: the PULLED AMOUNT — _pullOrderFunds uses balanceOf(orderAddress), i.e. "whole live balance"
also omitted : callResolver + callResolverData (documented as intentional, "plan can be refreshed after authorization")
```

Procedure, in order:
1. Print the digest preimage field-by-field. Enumerate **every** parameter of the executing function and mark
   `BOUND` / `UNBOUND`.
2. For each `UNBOUND` field, find the sink it reaches (`transfer`, `transferFrom`, `call`, `delegatecall`).
3. Check whether an unprivileged actor can influence that sink's input: permissionless inflow (`transfer` is
   `public` on an ERC-6909 hub), a settable address, a caller-supplied calldata blob.
4. **Then run the profit identity** — this is what separates a reportable weakness from a curiosity:

```
attacker injects D into a victim-controlled sink -> victim's own execution sweeps D to the VICTIM's receiver
=> attacker -D, victim +D => attacker profit = 0  => NOT exploitable, design note only
```

A real finding exists only when the attacker also controls a **destination** the victim's execution sends value to
(`callResolver`-style sink where the substituted address receives the working capital). If the destination is inside
the digest, the unbound `amount` is worthless to the attacker and the honest verdict is
`REAL DESIGN WEAKNESS / ZERO ATTACKER PROFIT`.
## Support files added for identity/decode traps

- `references/eip7702-delegation-and-smart-account-id.md` — a **23-byte**
  `0xef0100 ‖ 20B` code prefix is an EIP-7702 delegation designator (NOT an EIP-1167
  clone, NOT an EOA). Decode it, profile the delegate by its `PUSH4` selector set
  (ERC-7579 / ERC-4337 fingerprints), and check `tx.from == beneficiary` +
  `ModuleInstalled` logs before grading an aggregator-shaped address. Includes the
  log-scan geography-bleed caveat (overlapping `eth_getLogs` windows manufacture fake
  "duplicate id").
- `references/signature-binding-verification.md` — now also carries the *stop
  brute-forcing* procedure for digest calibration (compile the real contract, subclass
  it to expose the internal hasher, `vm.parseBytes` the on-chain calldata, `abi.decode`
  instead of hand-offsetting), the `fs_permissions` fix for `vm.readFile`, and the
  `nonce`-is-a-random-256-bit-value trap.

Full worked example: `references/unbound-parameter-and-permissionless-injection.md`.

## The dead-hypothesis ledger (non-negotiable)

Context compaction destroys "what we already disproved". Without an external
ledger the agent re-tests the same negative every round — this session spent
hours re-proving an allowance bypass that had already been refuted with a panic
code.

Maintain a state file (`hunt_state.json`) with:

```json
{
  "rounds_completed": 9,
  "dead_hypotheses": ["allowance underflow bypass (panic 0x11)", "supply mismatch (...)"] ,
  "proven_findings": [{"id":"F1","sev":"LOW","title":"...","evidence":"...","status":"INERT"}],
  "next_angles": ["ResolverSandbox...", "permit() high-s malleability..."]
}
```

Rules:
- **Never spawn a round on an angle already in `dead_hypotheses`.** The brief
  must quote the dead list so the subagent does not wander back into it.
- Every REFUTED/BLOCKED verdict gets appended to the ledger *in the same turn*,
  with the refuting evidence — not just "blocked".
- `next_angles` is a queue, consumed 3 per round. When empty, either invent new
  angles from untouched files (`ls *.sol`, diff against the ledger) or stop and
  say so. Do not spawn filler rounds.
- Run `scripts/round_loop_engine.py` as cron STEP 0 so the loop advances itself
  and the round number, artifact dir, and angle list are consistent across
  sessions.

**Upgrade when available: park with a TRIPWIRE, not just a string.** A flat
`dead_hypotheses: ["X"]` only records impossibility; it cannot tell a later
session when impossibility stops being true. HUNT-OS's `lead park --retrigger
"<observable> :: <check>"` forces both halves — the on-chain fact that fires and
the exact call that observes it — so a dead angle re-arms itself instead of
being re-derived. If the `hunt` CLI is installed, prefer it as the write door
and see `references/hunt-os-ledger-operations.md`; keep `hunt_state.json` only
as the offline fallback. Never run both as authoritative — two ledgers that
disagree is worse than one that is incomplete.

## Subagent brief design

**Reference files — read the one that matches the round.**

| File | Read it when |
|---|---|
| `references/abi-and-field-verification.md` | **Always, before any claim leaves your mouth.** Rules 1–22, each one a real self-inflicted error. Rule 8b: re-derive an INHERITED selector from a real tx (`cast 4byte`) before building a PoC. Rule 22: hex-string length ≠ byte length — a "malformed calldata / trailing tail" claim is your own slice until proven otherwise. |
| `references/identifier-uniqueness-probing.md` | The contract takes a caller-chosen `bytes32 id` / nonce / reference that an off-chain service treats as an idempotency key. Archive-free log census, duplicate detection, byte-identical-tx proof, and the verdict ladder that stops an anomaly being over-claimed as a loss. |
| `references/decode-and-proof-traps.md` | A decoded number looks too large, or a struct field's meaning was assumed from position. |
| `references/selector-and-getter-form-traps.md` | A getter or selector seems absent from the bytecode. |
| `references/multi-instance-trust-map.md` | The instance under test is empty — check siblings before declaring it dead. |
| `references/event-attested-volume-and-token-trust.md` | Using event volume as impact evidence, or evaluating an unknown token. |
| `references/poc-execution-and-portability.md` | Writing or porting a Foundry PoC; fork RPC failures. |
| `references/delegation-fanout-discipline.md` | **Before dispatching subagents** — the interrupted-summary trap (Rule 10) and keeping fan-out agents off each other's route. |


- **One angle per subagent.** Never give two subagents the same angle; if they diverge, you cannot tell which method is right.
- **Angles must be new.** Before spawning, list what previous rounds already covered. Exclude those. Pick untouched surfaces.
- **Angle must be falsifiable.** Every hypothesis needs a clear test that can return BLOCKED or REFUTED.
- **Mandatory adversarial self-attack.** Each brief must include: "For every finding, attack it yourself first. Prove it is NOT exploitable before you call it PROVEN."
- **Mandatory positive control.** Each brief must also include: "Every 'X is absent / zero / not gated' claim needs a positive control proving your instrument can see a known-present case (query a known role-holder; confirm a sibling getter's selector IS in the bytecode). Without it, a zero means your harness is wrong, not that the gate is missing."
- **State the budget's real shape.** A "60-minute timer" is not a guarantee: in this session all three agents were killed at the wrapper limit (1316 s) with `status=interrupted`, and two had produced zero summary text while still writing 95/44/32 lines to disk. Tell subagents to **append after every finding, not at the end** — the interrupt will arrive mid-turn.
- **Two independent methods per claim.** Require at least two different RPC/tool/analysis paths per finding.
- **Incremental append.** Subagents must write findings to a shared file **incrementally** (min 5–6 appends), not only at the end. This preserves partial work if the sprint is killed.

  **Pick the append MECHANISM deliberately — `write_file` is not an append.** `write_file` replaces the entire
  file. In this session append #1 was silently destroyed by a second `write_file` that "added" append #2, and the
  loss was only caught because a sibling-agent warning mentioned the file had changed. Rules:
  - Use the **`patch`** tool against the last line of the artifact to append (`old_string` = current tail,
    `new_string` = tail + new section). It is idempotent-ish and returns a diff you can eyeball.
  - If the artifact is shared with sibling subagents, `read` it immediately before every write; several agents
    writing the same file will clobber each other regardless of tool.
  - Shell `cat >>` works but trips command guards when the prose contains `&` / `&&` (heredoc bodies included).
    Prefer `patch`; if you must use a heredoc, keep the body free of shell metacharacters.
  - **Verify the append landed**: `grep -n "^## APPEND" <file>` after each one. A section header count that does
    not increase means you lost work, not that you saved it.
  - Self-corrections go in their **own numbered append** (`## APPEND #4 — KOREKSI`) rather than by silently
    editing earlier text. A reader diffing the artifact must see that claim X was retracted and why, with the
    refuting evidence. Strike-through the stale line in place *and* write the correction section.
- **Raw evidence requirement.** No claim is PROVEN without raw RPC response hex, revert reason, or source file:line. Theories without raw evidence = UNPROVEN.

## Verification protocol (must-do, not optional)

1. **Always inspect `error` before `result`.** This is the single most common false-positive source in live RPC audits. If a call reverts, mark it explicitly as `REVERT`; never treat empty/`None` result as `SUCCESS`.
2. **Never trust local ABI as live truth for events.** Derive live `topic0` and data layout from `eth_getLogs` / `eth_getTransactionReceipt` before building parsers.
3. **Verify field labels with an independent ground truth.** Before counting or classifying by a parsed field, cross-check one sample against a receipt or reference. Wrong labels create phantom findings.
4. **Verify explorer source == deployed bytecode** before concluding functions are missing. Bytecode-size/selector deltas are frequently artifacts.
5. **Distinguish `tx.from` (EOA) from `msg.sender` (immediate caller).** Internal relayers, executors, and oracles sit between them. Never attribute economic action to an address without this distinction.
6. **Resolve revert SELECTORS to names from the artifact ABI — the selector, not the message, is the evidence.**
   This RPC returns `{"code":3,"message":"execution reverted"}` with empty data for many calls, but a real
   transaction whose calldata is replayed returns full revert data. When data IS present, map it:
   ```python
   for e in abi:
       if e["type"] == "error":
           sig = e["name"] + "(" + ",".join(i["type"] for i in e["inputs"]) + ")"
           print(keccak(text=sig)[:4].hex(), sig)
   ```
   In-session this converted a vague "it reverts" into the decisive verdict: replaying a real tx from an attacker
   address produced `0xd855c4f4 = InvalidSignature(oracle)` — **not** `0xe2517d3f = AccessControlUnauthorizedAccount`
   and **not** `0x91e47843 = UnauthorizedOracle`. That distinction is the entire difference between "no caller gate
   exists, only the signature stops me" and "the caller is rejected". Two custom errors that look alike
   (`InvalidSignature` vs `UnauthorizedOracle`) decide the finding; never report a revert without its name.

## Subagent contradiction resolution

When two subagents disagree on a fact:

1. Do not average. Do not pick the more convenient one.
2. Run your own probe on 3–5 samples.
3. If the contradiction is about RPC behavior (e.g. `eth_getLogs` dead vs alive), test both methods on the same blocks.
4. If the contradiction is about an address's role (e.g. victim vs operator), check `eth_getCode`, `nonce`, `balance`, and role hashes before trusting either framing.
5. Record the resolution explicitly in the shared artifact file with the disproven claim and the correcting evidence.

## False-positive traps

0. **THE BIGGEST MISS: N rounds audited the CONSUMER, nobody audited the SIGNER.** When every remaining path is
   "signature-gated", the gate *is* the target. Auditing only the call sites produces the same `BLOCKED` verdict
   forever while the actual bug (if any) sits in the verifier. Always pivot one round to the trusted party itself:
   - who is the trusted oracle/verifier address **live** (`eth_call` the consumer's `ORACLE_MULTISIG()` / `oracle` /
     `hasRole(ORACLE_ROLE, addr)`), not who the repo says;
   - is that address **deployed at all** (absent from `deployments/*.json` and repo-wide grep = the repo contract is
     a decoy; the live trust anchor is a different contract);
   - is the verifier's own signing entrypoint unguarded, does it ever `delete` state, can its owner/threshold be
     changed, and is its `threshold()`/`getSigners()` read live.
1. **Label-before-verify.** Assigning a parsed field a role name (e.g. `topics[1]` → "caller") without cross-checking one receipt.
2. **ABI drift.** Live event signature may differ from local compiled ABI. Re-decode after any `0x` mismatch.
3. **Subagent contradiction as noise.** Treat contradictions as first-class signals, not noise.
4. **Role/slot misnumbering.** Storage layout may differ from brief assumptions. Use `forge inspect storage-layout` or equivalent as ground truth.
5. **`eth_call` impersonation limits.** Some RPCs reject `from` = unknown address with "not on the list". This is an instrumentation limit, not a contract revert. Do not treat it as proof of a revert path.
6. **`eth_getLogs` window limits.** 50 blocks/query is safe; 200 blocks may hit response-size limits. Split queries. Do not conclude the method is dead from one oversized query failure.
7. **Voter/caller misattribution.** `Transfer.caller`/`data.w0` is `msg.sender` to Hub, which may be an internal relayer, not the original EOA. Receipt `tx.from` is the EOA.
8. **"eth_call returned `0x` with a HUGE payload == bypass" — a real fake CRITICAL in this session.** Replaying an
   11 KB transaction payload with the signature zeroed returned `{"result":"0x"}`; the conclusion "signature not
   enforced" was wrong. A large `eth_call` payload can silently fail partway (gas/size/internal try-catch) and still
   return empty data. **The real bypass probe is a MINIMAL crafted call to the single entrypoint** (one struct, one
   action, 130 zero bytes of signature). That returned `0xd855c4f4` = `InvalidSignature(0x2a72…)` and settled it in
   one shot. Rule: *never conclude `SUCCESS` from an empty result on a big replayed payload; rebuild the call minimal.*
9. **Your own ABI decoding is a suspect, not a witness.** A hand-rolled offsets walker on the same payload produced
   "20 executions share ONE signature blob" (would have been a Critical digest-collision). `eth_abi.decode` refused
   the layout, which was the tell. If a decoded structure implies a cryptographic impossibility, assume your offset
   arithmetic is wrong, then confirm with the differential test in `onchain-protocol-audit`
   (`references/signature-gate-and-verifier-audit.md` §2).
10. **Frame committed in the brief ("prove the signer is forgeable") eats evidence.** Three hypotheses were FALSIFIED
    (missing EIP-712 domain separator in the verifier, signer forge, replay). Say so explicitly in the report — a
    correctly falsified hypothesis with raw evidence is a deliverable, not a failed round.
11. **THE SELF-REFUTATION STREAK — 7 for 7 in one session, all one root cause.** Every single wrong conclusion came
    from *naming a field or a state before proving it*, not from bad analysis. Signals you are about to repeat it:
    - you are about to write "there is no X" from a `sed` window that ends mid-function → **grep the whole file**;
    - you are about to write "the layout is Y" from the local compiled ABI → **print one raw log first**;
    - you are about to write "SUCCESS" from an `eth_call` → **check `error` first**;
    - you are about to credit an address with economic action → **check `nonce`/`eth_getCode` first**.
    Full checklist: `references/abi-and-field-verification.md`. Read it before publishing.
12. **A gate on ONE use-site does not gate the derived value.** `alias = derive(unchecked_bytes)` is computed BEFORE
    `if (len == 20)` guards a sibling boolean; every downstream consumer uses `alias`, not the validated input. Grep
    **all** consumers of any derived value (hash/alias/address/id), count them, confirm each is independently gated,
    and state the count in the verdict. Auditing one gate and declaring the path safe is how real collision paths
    survive review.
13. **"Missing guard" ≠ vulnerability.** A missing `address(0)` check, missing `require`, missing length check is only
    a finding if an unprivileged attacker can *reach* it with a value they control and a third party can monetise the
    resulting state. In this session `_mint(receiver=address(0))` looked HIGH; testing showed
    `balanceOf(0)==0`, `transferFrom(0→attacker)` = panic `0x11`, `isOperator(0,attacker)==0` — attacker cannot touch
    the trapped balance. Verdict: INFO. Standard ERC20 behaviour, not a bug.
14. **Error #8: hand-computed selector → false "the live contract is a different version".** A struct-heavy
    `execute(...)` produced three different selectors by hand (nested tuple, artifact components, flattened) and none
    was present in the bytecode, while two sibling getters were. That read as a version mismatch and nearly became a
    Critical drafted against the wrong contract. **Compare `len(eth_getCode)` against the artifact's
    `deployedBytecode` length FIRST** — equal size plus working getters means your signature is wrong, not the
    deployment. Build selectors with `scripts/build_selector_from_artifact.py`, never by hand. Watch `bytes32` vs
    `uint256` for nonces: it changes the selector and is invisible in a terse type list.
15. **Errors #9/#10 on the same day, same root: an instrument that returns nothing proves nothing.**
    - A `useNonces` write was declared missing from a `sed` window ending at L110; the write was at L113.
    - `eth_call` on this RPC returned `{"code":3,"message":"execution reverted"}` with **empty revert data**, so a
      gate-differential test using revert reason cannot discriminate. When revert data is swallowed, a revert is not
      evidence of *which* gate fired — switch to calldata replay of a real historical tx, or mark UNPROVEN.
    Rule: before writing "X does not exist", prove the instrument can see X at all (a positive control — the
    sibling getter that DOES respond, the selector that IS in the bytecode).
16. **Interrupted ≠ empty.** A fan-out whose subagents all report `status=interrupted` with zero partial output
    frequently still left full artifacts on disk. `ls -la /tmp/r<N>/` and read them before re-dispatching. Two of
    three interrupted agents here had written 95 and 44 lines of usable, evidence-bearing work — one of which
    contained the only real finding of the round.

17. **THE POSITIVE-CONTROL RULE — the technique that ended a 10-error streak.** Every "X is absent / X is zero /
    X is not gated" conclusion needs a **positive control** proving the instrument can see a *known-present* thing
    in the same call shape. Without it, "no data" is indistinguishable from "wrong harness", and the default
    interpretation (a finding) is almost always wrong.
    ```text
    "resolver has no role"          -> also query isOperator/role of a KNOWN role-holder; must return 1
    "selector is not in bytecode"   -> also confirm two sibling getters' selectors ARE in it
    "eth_call shows no caller gate" -> also confirm a DIFFERENT revert exists for a different broken input
    ```
    Worked example from this session: `hasRole(OPERATOR, resolver)=0` was meaningless until
    `hasRole(OPERATOR, Executor)=1` on the same line proved the encoding was right — *then* the zero was real. A
    subagent that supplies a positive control alongside a negative is worth more than three that don't.

18. **Source-proven ≠ live-proven ≠ exploitable. Name which one you have.** This session produced seven
    `SOURCE-PROVEN` facts (`execute()` has no `onlyRole`; `callResolver`/`inAmount` absent from the digest;
    whole-balance pull; permissionless top-up; live `isOperator(x, exec)=1`) and **zero** exploits. Every severity
    inflation path starts by silently upgrading a source fact to an exploit. Keep three separate tables in the
    report — *proven (method named)*, *failed to prove*, *severity + why not higher* — and never let a source fact
    appear in a PROVEN bullet without its verification method attached.

19. **When the target reverts on an expired deadline, you learn nothing about the gate you're testing.** Three
    prick differential variants all returned `RequestExpired` because the historical request's deadline had passed —
    the deadline check sits *before* the digest/signature checks, so all three died at the same wall and the
    experiment was void. Read the guard **order** in the source before designing a differential probe, and confirm
    your variants actually reach the guard under test (a distinct revert constant is the proof). If they can't,
    say UNPROVEN rather than reporting the identical revert as agreement.

19a. **…BUT guard order also RESCUES a verdict that looks inconclusive. Read which revert you got, not that you got one.**
    The mirror image of 19, and it flips `INCONCLUSIVE` into `REFUTED` honestly. Testing a cross-instance replay, the
    historical request's deadline had long expired — the lazy read is "RequestExpired, so expiry masked the test,
    INCONCLUSIVE". The actual revert was `0x91e47843 = UnauthorizedOracle(0x2a72…)`, and in the source
    (`RelayExecutor.sol:193` role check, `:197` deadline check) the **role check precedes the deadline check**:

    ```text
    replay original calldata onto instance B  -> UnauthorizedOracle   (role gate fired FIRST)
    swap in the oracle that IS authorised on B -> RequestExpired       (now the deadline gate is reachable)
    swap that oracle back onto instance A      -> UnauthorizedOracle   (symmetric control)
    ```

    Row 1 alone would be ambiguous. Rows 1+2 together are decisive: the *only* thing that changed between them was
    whether the oracle held the role on that instance, so expiry was never what stopped row 1 — the role gate was,
    and it fires before expiry can be considered. Verdict: **REFUTED (structural), not INCONCLUSIVE.**

    Generalise: an expired/irrelevant guard is only fatal to your test if it is the guard that fires. To earn a
    structural refutation:
    1. Read the guard order in source and cite `file:line` for both gates.
    2. Get the *earlier* gate's revert on the real attempt.
    3. **Show a variant that reaches the later gate** (change only the one input the earlier gate tests). Without
       this second row you have not shown the pipeline runs at all, and a decode/setup failure would look identical.
    4. Add the reverse control on the sibling instance to prove the query itself is sound.
    When you cannot establish the order from source, fall back to the honest `INCONCLUSIVE` — do not infer it.

20. **A "census" answered by the wrong index is a false negative with a credible number attached.** Asking the
    explorer for a contract's tx history returned **1 tx = the deployment**, which reads as "this public unguarded
    `execute()` has never been called → dead surface → INFO". The contract was in fact invoked repeatedly as a
    *sub-call* from a batcher: the tx's `to` was the batcher, so `txlist?address=RESOLVER` never sees it. Before
    declaring a surface unused, distinguish **direct calls** (`to == target`) from **sub-calls** (target appears only
    inside another contract's calldata / only as an event emitter). Cheap disambiguator: if the target shows up in
    `eth_getLogs` value flow but has ~0 direct txs, it is being driven indirectly — say
    `reached only via <wrapper>`, not `never called`. One corrected line flipped a "dead code" verdict into
    "live path, alive and funded".

21. **"Threshold can never be 0" is a claim about EVERY writer, not the setter.** After auditing `setThreshold`
    (`newThreshold == 0 || > signers.length → revert`) it is tempting to close the multisig. But the field is also
    written by the **constructor** and can be re-derived by **`removeSigner`** (which must re-check
    `signers.length - 1 >= threshold`). A `threshold == 0` state makes `for (i = 0; i < 0; i++)` a no-op and
    `_validateSignatures` returns `true` for ANY digest — free signature forgery on a 2-of-5. Enumerate every write
    site of a safety-critical scalar (`grep -n "threshold"`), then test the reachable end states, not the happy path.
    Same rule for `signers.length`, `isSigner[]`, `owner`, and any `paused`/`initialized` flag.

22. **Two subagents reporting "0 logs" vs "9,101 logs" from the same method is a harness bug, not a data dispute —
    and it silently changes every count downstream.** One side had an oversized/incorrect filter; the other a bad
    pagination. Resolve by running the same query on the same 5 blocks both ways and diffing, then record the
    resolution in the artifact. Never average, never pick the convenient number. (Same class as pitfall 3, but here
    the contradiction was about the *instrument* and it invalidated a caller-frequency table used to label an
    address as "victim" vs "hot wallet".)

23. **"IDENTICAL BYTECODE LENGTH ACROSS N INSTANCES" IS NOT A CLONE — and it is the most seductive false lead in a
    takeover angle.** A brief asserted "3874 bytes identical for 85 tokenIds ⇒ EIP-1167 clone ⇒ ask who can write the
    implementation". Wrong framing, and it would have sent the round hunting a non-existent implementation slot.
    Discriminators, in this order:
    - EIP-1167 prefix test: `code.startswith("0x363d3d373d3d3d363d73")`. Here the prefix was
      `0x608060405234801561001057000080fd5b…` with a real jump table (`80633c130d901161008c57`) and `4e487b71`
      (`Panic(uint256)`) — a **full contract**, not a delegate-proxy.
    - **Hash the runtime of several instances and require them to DIFFER.** Identical compiled artifacts produce
      identical *size*, not identical *code*: `a384d269` / `aadb4fd7` / `e91cae51` at 3874 bytes each, with
      different `tokenId()` returns, is the artifact that actually closes the question.
    - Immutables are embedded at deploy time, so per-instance divergence is expected and is *evidence of
      independence*, not of mutation.
    Same trap, same session, for the file itself: two declarations, both `immutable` ⇒ **zero mutable storage ⇒ no
    slot any function could ever overwrite.** Establish that before hunting "who can write the initialized flag" —
    there may be no flag and no storage.

24. **"No `initialize()` exists" needs THREE confirmations, and the third one is what makes it REFUTED instead of
    UNPROVEN.** Source grep alone invites "maybe the repo ≠ deployment". Run all three:
    ```text
    (1) grep whole repo/files to the closing brace  -> 0 hits
    (2) `"8129fc1c" in eth_getCode(...)`            -> False   (scan = hypothesis, per pitfall 14)
    (3) explorer getabi: 0 initialize/admin/owner + live eth_call -> revert with NO revert data (= fallback ran)
    ```
    Revert carrying **no data** means the fallback executed, i.e. the function is absent. A function that exists but
    fails always carries a selector or custom-error payload. Then run the control that licenses the whole verdict:
    **send `initialize()` to a plain EOA — it must return `{"result":"0x"}`, not an error.** If the chain returns
    empty success for nonexistent code, then a revert from a real contract is the contract's own revert, not an RPC
    artifact. Without that row, "it reverted" is uninterpretable and a triager will say so.

25. **Predictable address ≠ hijackable address. Grade the residual honestly.** `new X()` is `CREATE` (nonce-derived),
    so the brief's "attacker can predict the address" is true and still worthless: pre-placing code at that address
    makes the legitimate `new` **revert on collision** — availability, not theft, and it needs the exact nonce plus a
    front-run of a role-gated mint. Table it as LOW/INFO and move on. Only attacker-controlled `CREATE2` salts, or a
    non-idempotent creation path, would turn it into a takeover. When the takeover is REFUTED, still harvest the
    residual: silent-no-op emitters (`if (msg.sender == hub) emit …` — callable by anyone, emits nothing, not a
    spoofing vector), and the observation that the bypass branch is the *only* allowance gate in the parent, so the
    parent's allowance logic deserves its own round.

26. **THE FRONT-RUN-DEPOSIT CLASS — the strongest-sounding hypothesis in fund custody, and the one that dies to a
    CSPRNG salt.** Pattern: a protocol derives per-order deposit/order addresses; the brief claims they are
    deterministic and public, so an attacker predicts the victim's address, plants a drain path, and harvests the
    deposit. It sounds fatal and is usually REFUTED — but each sub-claim must be killed **separately**, and the
    attempt is where the real finding hides. Run these five probes in order:

    ```text
    (1) Is the derivation salted, and is the salt actually random ON-CHAIN?
        -> decode the live `salt`/`nonce` field from N real txs (not from the source default).
           Report bit-length distribution, not a single sample.
    (2) Is the derived address per-order unique, or constant per user/solver?
        -> census the field across every real tx. "7 tx -> 7 distinct" kills determinism outright.
    (3) Does the derivation actually produce the observed address at all?
        -> run the derivation against the real value. Include a CONTROL: the same function must
           reproduce a value you computed twice (proves the harness is deterministic, not broken).
           Zero hits on a working harness = "this function is not the source", which is a finding
           about the BRIEF, not about the target.
    (4) Is the derived address a contract or an EOA, and does it have history?
        -> eth_getCode + explorer txlist. An EOA with 0 txs has NO state to plant -> sub-claim (b) dies.
    (5) Is the address inside the signed digest?
        -> if yes, the attacker cannot hijack a victim's request, only issue their own. Then the
           verdict is INFERRED-GATE, not front-run.
    ```

    Live worked example: salt decoded across 200 txs gave `bits min/max 249/256`, `tiny(<2^32) = 0` — a full
    256-bit CSPRNG value, so prediction is 2^256 work and sub-claim (a) dies. `orderAddress` was **7 tx → 7
    distinct** (not deterministic per solver), and the brief's assumed formula produced **0 hits** across 12 chain
    strings × 5 candidate addresses while the control reproduced its own value exactly. All three of the attack's
    necessary conditions — predict, plant, harvest — failed independently. Verdict: **REFUTED / NOT EXPLOITABLE**.

    **The residual is usually `pull-whole-balance`, and it is NOT a front-run.** The same code typically sweeps
    `balanceOf(orderAddress)` rather than the requested `inAmount`. That is a real weakness (address reuse or a
    stray top-up leaks the second order's funds) but requires a valid signed request, so it grades INFERRED-GATE /
    medium — report it under its own name, never as "front-run deposit". See pitfall 27 for why the collision
    sub-angle needs a different reflex.

27. **A PACKING AMBIGUITY THE ATTACKER MUST CONSTRUCT IS NOT AN ATTACK — check WHO controls both halves.**
    `abi.encodePacked(string, bytes)` with no separator/ length prefix genuinely is ambiguous:
    `generateAddress("base", 0x4243||R19) == generateAddress("baseBC", R19)` reproduces exactly, and it is fine to
    prove that (`assertEq` on the two preimages). The trap is presenting it as a collision attack. Ask:
    **who supplies each side of the ambiguous pair?**

    ```text
    attacker controls BOTH sides        -> self-alias. Attacker only aliases an address they
                                           already own. ZERO new control. Not a finding.
    attacker controls ONE side, the
    other is the victim's               -> re-derive: the ambiguous pair maps to the VICTIM's
                                           address, not to a fresh attacker address. Attacker has
                                           gained nothing and still needs the signed request.
    attacker wants a NEW address that
    collides with the victim's          -> second-preimage on keccak256 = 2^160 work. MUSTAHIL.
    ```

    The cheap mechanical check: shift-split the victim's account bytes across the two packed arguments
    (`chain' = chain || acct[:k]`, `acct' = acct[k:]` for k in 1..20) and confirm every hit equals the **original
    target**. If all hits == target, the ambiguity is an alias, not an attack — write that line in the report.
    Never let "collision proven" stand in for "collision exploitable"; that is the same laundering as pitfall 18.

28. **A HYPOTHESIS THAT DIES ON THE SOURCE MAY STILL HAVE A LIVE WRONG-MENTAL-MODEL BEHIND IT — say whose bug it is.**
    When a refuted path's root cause is "the brief assumed a formula the code does not use", that is a **finding
    about the brief**, and the honest deliverable is a table row `brief said X / ground truth said Y / evidence`.
    In this session the brief carried an exact address and an exact formula (`generateAddress(inChainId, solver)`);
    the live census showed 7 distinct addresses and zero formula hits. Reporting "REFUTED" alone throws away the
    most useful output of the round — future rounds must not re-import the same false premise. Feed it straight into
    the dead-hypothesis ledger as a *premise* entry, not just a conclusion entry.

29. **PLACEHOLDER PROVENANCE — the fabrication mode that produces fake CRITICALs, and it happens while writing the
    PROOF SCRIPT, not while analysing.** In this session the same defect occurred **three times in 15 minutes**:
    writing a script that needs a real value (tokenId, tx hash, address) and inserting a plausible stand-in instead
    of fetching it.

    ```python
    'eth-USDC':  0xae90 + 0,                       # stand-in. equals 44688, not a tokenId
    TOKEN_IDS = ['0xbf2f7b0e0e6b…0a0b0c…']         # invented hex, 64 chars of fiction
    tx = rpc('eth_getTransactionByHash', ['0x2734c34f4ddd7459da0a1d4ea0…'])   # padded to look whole
    ```

    All three were caught before running, because each script was **read back before execution**. That read-back is
    the only control that works. Two of the three would have merely errored; the dangerous one is the third — a
    fabricated `tokenId` returning a real `0` from `balanceOf`, which reads as *"order addresses hold nothing, path
    is dead"* — a **negative finding manufactured from invented input**.

    Rules:
    - **Every literal in an evidence script must trace to a fetch or a `file:line`. No exceptions, no `+ 0`, no
      truncated-then-padded hashes.** If you do not have the value, the next line is a `rpc()`/`curl`/`grep` call,
      not a guess.
    - **Read your own script top-to-bottom immediately before executing it.** Look only for: literals you did not
      fetch, `# placeholder`, ellipses inside a hex string, arithmetic on a "value" (`0xae90 + 0`).
    - **A stub that must be filled is a STOP signal, not a stub.** In this session the correct response to "I need
      the real tokenId" was `grep`ing the existing census artifact — 30 seconds — not writing a plausible one.
    - This is the same root as the self-refutation streak (pitfall 11): naming a value before proving it. The
      difference is that a fabricated *input* propagates silently into every downstream number, so the error is not
      even visible in the output.
    - Corollary for subagents: reject any brief that hands them an address/formula the brief itself did not derive
      live (see pitfall 28 — a brief-supplied false premise produced a whole refuted angle).

30. **ONE EXECUTOR, ONE ORACLE, ONE MAPPING — the coverage illusion that wastes a whole campaign.** Thirty-plus
    hypotheses were tested against a single `RelayExecutor` and a single 2-of-5 multisig before a calldata census
    revealed the target had **two** executors and **two** different oracles:

    ```text
    exec=0x6747c7e6…  resolver=0xb24ac15b…  signer=0x2a72eb8c…  (the 2-of-5 multisig audited for 20+ rounds)
    exec=0x797b3ce4…  resolver=0x4cece2e5…  signer=0xcc60889a…  <-- never examined, different trust model
    ```

    Every "the signature gate is unbreakable" verdict was scoped to the multisig. The second signer is not that
    multisig, so **its gate was never audited at all** — a live, unexamined attack surface hiding behind a
    confident refutation.

    Rules:
    - **Before round 1, enumerate instances, not just entrypoints.** Census the *distinct* values of every
      identifying field across real txs: executor/to-contract, resolver, oracle/signer, hub, implementation. `set()`
      size > 1 means there are sibling deployments with possibly different security posture.
    - **Scope every REFUTED verdict to the instance(s) you tested.** Write `"gate solid on signer 0x2a72…; signer
      0xcc60… UNAUDITED"`, never `"signature gate is solid"`.
    - Re-derive the whole gate matrix per instance: a second signer may be a single EOA, a 1-of-1, an EOA with a
      public key, or a contract with a totally different approval path. Same selector ≠ same trust.
    - The tell that you are in this trap: your census output line reads `signers: {...}` with a **set** that has
      more than one element and only one was analysed.

    **30a. THE SIBLING INSTANCE IS A SEPARATE LEDGER, NOT A COPY — and the engine cannot see its own findings.**
    Two follow-ons to pitfall 30, both hit in the same session *after* the census was finally run:

    ```text
    Executor#2.HUB() = 0x3C0be5a7F32a7dFB70C156b81eB747D0E5287F30   13507 bytes   <- DIFFERENT Hub
    Executor#1.HUB() = 0xDDD361727C22A01EB137880678A20b0BEaE69318   13864 bytes
    ```
    Same source, same 9131-byte executor runtime, different immutable ⇒ **completely separate `balanceOf`
    ledger, separate ERC-6909 supply, separate `orderAddress` state.** Do not carry a balance/role/allowance
    observation from instance A to instance B; re-measure on B or say UNAUDITED. Two traps this exposed:
    - **Getter name casing silently fakes a version mismatch.** `hub()` reverted on the executor while `HUB()`
      returned the real Hub. An absent selector reads exactly like "different contract" (pitfall 14). Before
      concluding anything from a reverting getter, try the ALL-CAPS / `getX` / `xAddress` variants — immutable
      public getters use the declared identifier verbatim.
    - **Per-instance admin/role separation is the actual security posture, and it deserves its own row.** Here
      `ADMIN`/`ORACLE`/`OPERATOR` holders were fully disjoint between the two systems (oracle#1 = 2-of-5,
      oracle#2 = 2-of-3, zero signer overlap, owner#2 not an OPERATOR anywhere). That is GOOD practice — report
      it as isolation, not as a finding, and note that a single leaked key no longer crosses instances. The
      *weaker* threshold (2-of-3, all EOA) belongs in the report as blast-radius, not as a code bug.

    **30b. THE ROUND ENGINE ITSELF CAN RE-SERVE DEAD ANGLES — fix state before spawning, not after.**
    `scripts/round_loop_engine.py` treats "a string in `next_angles`" as a live angle; it never re-reads
    `dead_hypotheses`. A round whose results were never written back therefore gets re-issued verbatim:

    ```text
    $ python3 round_engine.py
    === ROUND 14 ===
      A2. ERC20View initialized flag — re-init attack    <- REFUTED two rounds earlier
      A3. front-run deposit: predict depositAddress      <- REFUTED two rounds earlier
    ```
    Mandatory BEFORE advancing a round:
    1. Append every REFUTED/BLOCKED hypothesis (with refuting evidence) to `dead_hypotheses` **in the
       reconciliation turn** — not "later". If the session ended before Phase 3, the next session's first act is
       to write the ledger, not to spawn.
    2. Purge `next_angles` of anything whose text overlaps a dead entry. Cheap check:
       `for a in next_angles: assert not any(k in a for k in dead_keywords)`.
    3. Add the *newly opened* surfaces the previous round discovered (sibling instance, second oracle, second
       hub, funded resolver) — a refuted round almost always leaves 2–4 fresh angles behind.    4. Only then advance. A round is cheap to re-run and expensive to waste: 60 minutes on a two-round-old
       refutation is the single largest time sink observed in this campaign.

31. **A NO-AUTH FUNCTION IS "INERT", NOT "SAFE" — and the funding event is the finding.** `BasicCallResolver
    .execute()` is `external nonReentrant` with **no** role check, no `msg.sender` check, body loops
    `call_.to.call(call_.data)` and then sweeps `HUB.balanceOf(address(this), tokenId)` to an
    attacker-chosen `recipient`. Its own NatSpec admits it: *"intended to hold no Hub roles … must not be
    authorized over unrelated accounts."* Graded from a current `balanceOf == 0` probe alone, this reads as
    INFO/DEAD-CODE and gets filed away.

    The session's strongest positive control came from the **receipt of a real production tx**, not from a
    balance read:

    ```text
    Hub#2 Transfer  Executor#2 -> Resolver#2  amt 8,030,600,319,327,198
    Hub#2 Transfer  Resolver#2 -> alias       amt 5,085,195,328,750,034
    => the unguarded entrypoint DID hold funds mid-cycle. "balance 0" is a SNAPSHOT (see
       references/live-call-surface-census.md §4a), not a property.
    ```

    Rules:
    - Score an unguarded entrypoint on **"does it ever hold value"**, proven from a receipt's Transfer logs —
      never on the present balance. `balanceOf == 0 right now` answers a different question.
    - If it held value even transiently, the residual risk is: *any stray direct transfer to this address is
      sweepable by anyone*. Say exactly that, and name the trigger (solver sends outside the normal cycle).
      Verdict: **REAL / CURRENTLY-INERT / ARMED-BY-FUNDING** — distinct from DEAD-CODE.
    - Pair it with a positive control that the balance channel itself works (same tokenId derived from a real
      tx, cross-checked against the `Executed` event's `topics[3]`), otherwise a zero balance is uninterpretable
      (pitfall 17).

32. **FAILING TO EMPTY-FUND IS NOT A FAILED ROUND — an unguarded-but-empty contract is a reportable latent
    condition.** Do not discard it as "no impact". If the whole audit yields no keyless drain, the deliverable
    set is still: the unguarded `execute()` paths (armed, inert), the per-instance trust split, the SPOFs, the
    unbound digest fields, and the INFERRED-GATE medium. Ledger each with the *condition that would arm it*.

33. **MAPPING-SLOT LEFT-PAD: a getter that disagrees with raw storage means YOUR SLOT MATH IS WRONG — not that the
    mapping is empty.** Reading `isSigner[x]` at `keccak(20_raw_address || slot)` returns `0` for every address, on
    every slot 0–11, while the `isSigner(x)` getter says `true` for all three known signers. That contradiction looks
    like *"the mapping is uninitialised ⇒ validation is vacuous"* and it nearly produced a Critical. The key is a
    **32-byte ABI word**, so the address is LEFT-padded into the high bytes:

    ```python
    keccak(addr_bytes        + slot.to_bytes(32,'big'))          # WRONG: 0 forever
    keccak(b"\x00"*12+addr_bytes + slot.to_bytes(32,'big'))      # RIGHT
    cast index address <addr> 4        # ground truth; != cast index uint256
    ```

    Rules: (a) when a **getter and `eth_getStorageAt` disagree, the getter wins** and you go fix your slot math —
    never conclude the RPC is lying or the mapping is empty; (b) do not infer slot numbers from declaration order
    either (`Ownable2Step` sits at slots 0–2 ahead of your state; confirmed values were owner@2, `signers.length`@5,
    `threshold`@6, `isSigner`@4); (c) with a working slot you can then decode it from runtime — the `MSTORE` pair
    before `SHA3` gives slot and key frame (`6004 6020 52` → `mem[0x20]=4`; `5f 90 81 52` → `mem[0]=key`).
    Details: `references/eip1271-verifier-forge-probes.md` §3.

34. **A POSITIVE CONTROL CAN FAIL FOR A REASON THAT IS NOT THE CONTRACT — check the signing FRAME first.**
    With two throwaway keys correctly registered as signers (`anvil_setStorageAt`, verified via the getter) and two
    valid sigs in ascending order, `isValidSignature` still returned `0x0000…`. That is the classic control-failure
    and the instinct is "the contract must require something else". The actual cause: `encode_defunct(primitive=db)`
    prepends the EIP-191 `\x19Ethereum Signed Message:` frame, so `tryRecover` recovers a **different address** than
    the one registered. Use `Account.unsafe_sign_hash(db, key)` when the verifier consumes a raw `bytes32`.
    Recognise the symptom: *control fails even though signer registration and sort order are proven correct* ⇒ suspect
    the frame, the digest, or the padding — not the target. Two more control-failure traps in the same family:
    - **`eth_call` `stateDiff` overrides are silently ignored** by some RPCs — no error, just the un-overridden
      result, which is indistinguishable from "the sig is invalid". Use `anvil --fork-url` +
      `anvil_setStorageAt` (that one is honoured).
    - **`cast sig` returns a 4-byte selector**, not a 32-byte topic0. `eth_getLogs` with it as `topics[0]` fails with
      a cryptic `Invalid variadic value or array type`. Use `cast keccak "RoleGranted(bytes32,address,address)"`.

35. **THE BRIEF'S HUB/ANCHOR ADDRESS CAN BE THE WRONG CONTRACT — "no roles found" is only meaningful on the contract
    the consumer actually reads.** `hasRole(ADMIN, owner)` returned `false` on the hub address supplied in context,
    which read as clean. There were **two** hubs: `0xDDD3…9318` (13864 B) and `0x3C0b…7F30` (13507 B). On the real
    one — proven by **selector-set equality against `out/RelayHub.sol/RelayHub.json` (34/34)** and confirmed via the
    executor's own `HUB()` getter — the same owner was the **sole `ADMIN_ROLE` holder**, and
    `getRoleAdmin(OPERATOR_ROLE) == ADMIN_ROLE`, i.e. unilateral `grantRole` to anyone.

    The reporting discipline matters as much as the find: this is real and it is **key-gated**. Write both halves in
    one breath — *"owner key compromise ⇒ grantRole(OPERATOR_ROLE, attacker) ⇒ execute() passes every gate"* AND
    *"this is HIGH-ROLE-ONLY, it does not constitute a keyless path"*. Half of it alone reads as either a
    buried Critical or a severity inflation. And when the funnel is `false`, run the positive control first: a known
    holder on the same hub must return `true` (see pitfall 17) — otherwise you have audited the wrong address.

36. **THE UNDERFLOW COINCIDENCE — a revert for the WRONG reason looks exactly like the gate holding.** Probing
    the *proven-live* bypass directly from an attacker (`parent.transferFrom(victim, attacker, id, 1)` where the
    parent exempts `msg.sender == helper`) reverts `0x4e487b71…0011` = **`Panic(0x11)`, arithmetic underflow** —
    because `allowed(0) - amount(1)` underflows on the line *before* the allowance is consumed. The lazy read is
    "the allowance gate stopped me", which is wrong twice: the gate never ran, and you have missed that the same
    path **succeeds with `amount == 0`** (`0 - 0 = 0`, no underflow) as a permissionless zero-value transfer for
    log/indexer pollution.

37. **"I could not decode it" is a decode-bug signal, not a finding.** Two fabricated findings in one session,
    both from the sentence shape *"the probe returned zero/empty ⇒ the system is broken."*
    - `hashesToSign` "length = 0" → claimed "funds burned with no payload, CRITICAL data loss". Cause: read word
      `w[2]` (an **offset**, `0x1e0` = 480) as an array length. Real length was `1`, payload was a full 480-byte
      struct.
    - `eth_getCode(addr, blk)` = `0x` across a block range → claimed "builder points at an empty address". Cause:
      the archive node did not serve historical code. Contract was live since its CREATE at an earlier block.
    **Rules.** A word equal to a small multiple of `0x20` (`0x20`, `0x40`, `0x1e0`, …) is an **offset, never a
    length** — resolve each dynamic param independently: `idx = int(w,16)//32; length = words[idx]`. **Anchor every
    decode against a value already known from calldata** (request said `amount = 1_200_000`, so the payload must
    contain `0x124f80`) — one line kills the false finding. A zero-length array in a `status=0x1` tx that spent
    full gas is a **contradiction** ⇒ re-derive, don't report. A historical-block "empty" answer must be overruled
    by a deploy tx in `txlist` or by the tx **receipt** (receipts are ground truth; historical state reads on a
    load-balanced RPC fleet are not — see `references/empty-contract-and-event-decode-traps.md` §Failure 1b).
    **Retraction is a first-class output**: publish a claim→status table (`SALAH` / `BATAL`), name the mechanical
    cause (which word, which call), re-state the surviving ledger. A quietly dropped claim is indistinguishable
    from a fabricated one.

38. **Prove cryptographic binding by MUTATION, not by reading `keccak(field)`.** Reading `keccak(receiver)` in the
    source is not proof that substituting `receiver` changes the digest — and the entire "spoof the destination
    without a key" hypothesis rests on exactly that. Mutate **every byte** of the largest dynamic field and print
    `N bytes tested, M unbound` (a number, not a boolean); also XOR one bit of `receiver`, `amount +1`, `nonce +1`,
    and verify `digest(P, ALLOC_A) != digest(P, ALLOC_B)` for cross-instance replay. Measured on a 5,664-byte
    payload: `5664 tested, 0 unbound` — that closed the whole parameter-substitution class for the target.
    **`hashesToSign` ≠ the user's request digest**: a builder's hash array binds the *execution payload* while the
    user's EIP-712 digest binds the *request struct* — two independent signatures (measured `0x64d01f56…` vs
    `0x2a598476…`). State both, and require an **injectivity** check on the builder's serialisation (fixed-width
    padding / length prefix / type tag), because a payload hash is only as safe as its encoding.
    **A duplicate `(spender, nonce)` is not automatically a finding** — pull both receipts; if the second is
    `status=0x0` with 0 logs, that is proof the nonce ledger **works** (clean REFUTED), not "nonce reuse".
    Full harness + verdict template: `references/signature-binding-verification.md`.
    Rules:
    - **Run every revert-class probe at three amounts: `1`, `type(uint256).max`, `0`.** Each returns a different
      selector (`Panic(17)` vs `InsufficientAllowance` vs success) and only the triple tells you which line fired.
    - **`Panic(17)` is never evidence of a gate.** It means checked arithmetic fired first — re-read the source
      order and find the real gate, or admit the probe did not reach it (same family as pitfall 19).
    - **An exemption bypass is only falsified by a positive control that ENGAGES it**: `eth_call` with
      `from = <the exempted helper address>`, same call shape, must return `OK`. Attacker-row reverts prove
      nothing about the bypass being dead — they prove you are not the helper. One `from=helper` row is what
      licenses "bypass alive, unreachable".
    - **Bytecode proxy/proxy-like claims need an opcode walk, never `count("f4")`.** On a contract with zero
      DELEGATECALL and zero SELFDESTRUCT, `count("f4")` returned **16** and `count("ff")` returned **46** — nibbles
      inside PUSH payloads. Walk with `i += 1 + (code[i]-0x5f if op in PUSH else 0)` and skip PUSH1..32 data;
      full recipe in `references/helper-exemption-and-allowance-bypass.md` §4.
    This is the round that pitfall 25's closing line calls for ("the parent's allowance logic deserves its own
    round"). Verdict shape when all six sub-hypotheses die: **REFUTED x6 + INFO for the `amount == 0` path and the
    wrong-direction `Approval` event** — a clean, defensible zero rather than a manufactured CRITICAL.

37. **THE GETTER-FORM FAMILY — five wrong verdicts in one round, every one a call-shape bug.** All five produced the
    same tempting sentence: *"this contract lacks that function / this value is zero"*. None of them was about the
    target. Full recipes: `references/selector-and-getter-form-traps.md`.

    ```text
    role hash used as calldata        ADMIN_ROLE() is 0x75b238fc; 0xa4980720 is its RETURN value
                                      -> hasRole(hash, addr) works, so every role CHECK was valid
                                      -> every "does this hub expose ADMIN_ROLE?" probe was bogus
                                      -> produced the false hypothesis "hub#2 missing 17 functions"
    wrong argument type on a getter   erc20Views(bytes32) reverts / erc20Views(uint256) returns
                                      bytes32 vs uint256 nonce is invisible in a terse type list
    equal ABI, different byte length  Hub#1 13864 B / Hub#2 13507 B, 36 fn + 8 event + 11 error IDENTICAL
                                      => different BUILD, not a missing-feature version. 10-byte common
                                         prefix means it is NOT an immutables-only patch; neither
                                         contains the other. Claim only what was measured.
    truncated hex preview as evidence [t[:12] for t in topics] renders 0x0000000000 for a REAL address
                                      -> nearly shipped "owner and spender are both address(0)"
                                      -> never display a clipped hex field as evidence; print int(x,16)
    pointer getter vs live limits     XERC20.lockbox() -> 0xaa6ff104 (mintingMaxLimit 0 = DEAD)
                                      the ACTIVE lockbox 0xe1b402a9 is NOT the pointer target (limit 2^255-1)
                                      -> measure limits on every instance sharing the token, both before
                                         calling a surface dead and before calling it exploitable
    ```

    Rules: (a) **selector = `keccak("name(types)")[:4]`, role hash = a getter's return value** — never interchange;
    (b) derive every selector from the explorer ABI, diff the selector **sets** across instances, never hand-type;
    (c) same ABI + different runtime ⇒ say *build differs, behaviour unverified*, never *older/weaker version*;
    (d) do not mine a compiler version out of trailing bytes (`int.from_bytes(code[-2:])` gives nonsense like `47401`
    and is not a metadata length — a fabricated provenance datum is worse than none, pitfall 29);
    (e) an exemption branch that *skips* a decrement on `type(uint256).max` means the residual question is
    "does any victim hold an infinite approval to an address the attacker can act through" — not "is there a guard";
    (f) **check the WIDTH of every value before believing it** — `r[2+24:66]` is an `address` slice and silently
    truncates a 32-byte `bytes32`/role hash to 40 hex chars. This produced three wrong readings in one turn,
    including `hasRole(ADMIN, owner)=0` when the owner was the **sole ADMIN** — a false negative that argued the
    opposite of the truth. Always `assert len(word)-2 == 64` for word-shaped returns, and print `len()` beside the
    value (references/selector-and-getter-form-traps.md §5b);
    (g) **a deploy-block binary search seeded at a bound that already has code returns that bound**, and the
    subsequent log scan then reports `0 logs` for a range the contract was never in. Verify the lower bound has no
    code, or take the block from the explorer creation tx; and compute `(hi-lo)/step × number_of_filters` before
    running (a 3.3M-block scan over six filters is ~1,014 requests = guaranteed timeout). `0 logs` from an
    unverified range is void, not evidence — and "who holds role X" is a handful of `hasRole` calls, not a scan
    (references/selector-and-getter-form-traps.md §5c).

  events (references/abi-and-field-verification.md Rule 2). **`data` word count = params − indexed params**;
  assuming all params land in `data` made a 32-byte request hash decode as `withdrawAmount = 8.9×10⁷⁶` and nearly
  became a "catastrophic drain" finding. Any decoded amount past ~10²⁴ is a decode bug first, finding second.
- **TAUTOLOGY AUDIT before recording a PoC.** For every `ck(...)` line ask: what observation would make this print
  FAIL? A check that cannot fail is decoration that inflates `13/13 PASS`. `totalSupply(0) == 0 on both Hubs`
  "proved" a live query while the subject was simply empty; `victim funded in Hub#1 AND Hub#2` failed on a correct
  system because the two deployments never shared state (invariant should have been `any`). Controls must return a
  value you can predict and verify — a zero control means "find a subject you know is non-empty first".

38. **THE SELF-ADMIN ROLE CHAIN — one EOA can be the entire second instance, and that is HIGH-ROLE-ONLY, not a
    bypass.** `getRoleAdmin(ADMIN_ROLE) == ADMIN_ROLE` means no `DEFAULT_ADMIN_ROLE` sits above it: the holder can
    `grantRole(ADMIN_ROLE, anyone)` unilaterally, therefore `grantRole(OPERATOR_ROLE / ORACLE_ROLE, attacker)`, and
    then `execute()` passes every gate on that instance.

    ```text
    getRoleAdmin(ADMIN_ROLE)    -> ADMIN_ROLE    <- self-admin, no approval above it, no timelock, no 2-of-N
    getRoleAdmin(OPERATOR_ROLE) -> ADMIN_ROLE
    hasRole(ADMIN, 0x71d8be89)  -> 1             on Hub#2 ONLY
    hasRole(ADMIN, 0x71d8be89)  -> 0             on Hub#1   (per-instance disjointness is GOOD practice)
    ```

    Rules:
    - `getRoleAdmin` is the amplification question, and it is one `eth_call` per role. Run it on **every** instance;
      a self-admin role with a single EOA holder is the strongest finding an otherwise-clean audit produces.
    - **Report both halves in one breath** — *"key compromise ⇒ grantRole ⇒ every gate opens"* AND *"HIGH-ROLE-ONLY,
      not keyless"*. Half alone reads as a buried Critical or a severity inflation (pitfall 18/35).
    - `getRoleMemberCount` / `getRoleMember` are **AccessControlEnumerable** and are frequently absent from a plain
      `AccessControl` hub. A revert there is not "no holders" (pitfall 17) — use `hasRole(hash, candidate)` over a
      short candidate list (deployer, each executor, each oracle owner, each admin, each known operator).
    - Harvest the neighbours while you are in there: a candidate-list sweep here surfaced an **OPERATOR holder that
      appeared in no prior report**. Enumerate candidates you have never tested, not just the ones already in context.

39. **EMPTY `result` FROM A LOG-API IS AMBIGUOUS — three different causes, zero information.** Explorer
    `module=logs&action=getLogs` returned `{"status":"0","message":"No logs found","result":null}`; that shape is
    produced by a missing required param (block range), an unsupported module, *and* a genuinely empty range. It is
    not evidence of absence. Either send a full explicit `fromBlock`/`toBlock` range or fall back to `hasRole`/
    `txlist`; and when a `status:0` appears, name which of the three causes you ruled out before using the result at
    all.

40. **DECODE A STRUCT FROM ITS REAL ABI SHAPE, NOT FROM A WORD OFFSET YOU PICKED — and read the STRUCT DEFINITION before you name a field.** Two failures in one round, both from guessing:

    ```text
    (a) the field does not exist at all
        hypothesis: "inAmount is not bound in the EIP-712 digest"
        reality   : the struct (ExecuteAndWithdrawRequest) has NO inAmount field.
                    The pull is a documented WHOLE-BALANCE read:
                      RelayExecutor.sol:299  orderBalance = HUB.balanceOf(orderAddress, tokenId)
                      /// @dev "...consumes its complete live balance."
                      225  withdrawAmount = HUB.balanceOf(address(this), tokenOutId)
        => the finding survives but had been NAMED wrong for 13 rounds. Grep the
           struct definition (call-resolvers/ICallResolver.sol) FIRST, then verify
           membership with the digest preimage (RelayExecutor.sol:367-383).
    (b) the offset was an ARRAY LENGTH
        words[off_req + 12] = 4  ->  read as "inAmount = 4"
        4 was the length prefix of a following dynamic field, not an amount.
    ```

    Rules:
    - **Locate the struct in source (`grep -rn "struct .*Request"`), print its fields in declaration order, and only then map calldata words.** With dynamic members (`string`/`bytes`/`Fee[]`) the ABI head is *offset pointers*, so field *k* is not word *k* of the data you see.
    - **A decoded value that is impossible is a decode bug, not a finding.** `inAmount = 4`, a negative balance, a 20-byte "role hash", a deadline in 1970 — every one of these is your arithmetic, full stop (same root as pitfall 37f, `assert len(word)-2 == 64`).
    - **Whole-balance reads deserve two separate questions.** *Sink 1* sweeps the `orderAddress` balance; *Sink 2* sweeps the **executor's own** balance into the withdrawal path. Ask about Sink 2 as well — the executor is a shared, long-lived contract, so a residual balance is cross-order exposure, not just a top-up prank.
    - **Prove the premise that guards the whole-balance read, don't assume it.** The NatSpec for Sink 1 states the security condition: *"the protocol must assign each order an exclusive, non-reused address."* Test exactly that: census `orderAddress` across all real txs for reuse (7 tx → 7 distinct = premise holds), and sample `balanceOf(executor, tokenOutId)` one block after each execution (0 in 14/14 = no residual). Premise holds ⇒ **overturn with a met falsifier**, not a Critical.

41. **THE POSITIVE CONTROL CAN BE *IN THE DATA ITSELF* — use a value that MUST move.** When the thing you want to prove is a **zero** (balance 0, no residual, no allowance), a single zero proves nothing (pitfall 17). The cheapest control here was not a second address but a second *time*: `totalSupply` read twice returned `52,614,007,474` then `52,754,718,702`. That single delta licensed the whole "the zero balances are real" verdict — the channel is live, the node is synced, the tokenId is right. Prefer a naturally-moving counter (`totalSupply`, a nonce, a block height) as the control over a contrived second probe, and quote both readings with their timestamps.

42. **THE INSTALLER CAN RESHUFFLE YOUR TOOLCHAIN — pin the interpreter in every evidence script.** Installing a Python CLI into its own venv rewrote what `python3` resolved to, and the next script died on `ModuleNotFoundError: eth_utils` even though the package was installed. This is environment state, not a finding: the fix is to invoke the interpreter explicitly (`/usr/bin/python3 script.py`) and to record which interpreter ran. Never conclude a probe "failed to produce evidence" when the import never happened, and never let a `--help` run through a venv mask the real interpreter for later steps.

- If a subagent claims a hardened path is bypassable, require raw calldata / storage diff / revert reason, not a theory.
- When subagents disagree, run your own probe; never publish one side's verdict as ground truth.
- A subagent that claims "3 hours complete" but wrote nothing for the last 90 minutes is still producing partial work; read the artifact file, not just the summary.

## Sprint structure

- **Phase 0 — Advance the round (1 min):** run `scripts/round_loop_engine.py`. It advances the round number, picks 3
  angles not in `dead_hypotheses`, creates `/tmp/r{N}/`, and prints the brief scaffold. If it exits 2, invent new
  angles from untouched files or stop — do not spawn filler. If it exits 3, the queue was **purged of angles that
  re-tested dead hypotheses**: that is the engine saving you a wasted round, so treat the purge as work to be redone
  (invent genuinely new angles), never as a bug to route around.
- **Phase 1 — Angle definition (5 min):** Quote the relevant slice of `dead_hypotheses` into each brief so subagents
  cannot wander back into refuted territory. Each angle must be **new** and **falsifiable**.
- **Phase 2 — Sprint (50 min):** Subagents run in parallel. They write incrementally. You run your own probes on any live claim they make.
- **Phase 3 — Reconciliation (5 min):** Read all artifacts. Identify contradictions. Run your own probes to resolve them. Elevate only PROVEN findings. **Update `hunt_state.json` in the same turn** — dead hypotheses appended with the refuting evidence, new proven findings added, used angles removed. **If the session ends before this step, the next session's FIRST act is to write the ledger — not to spawn** (pitfall 30b: the engine re-serves dead angles otherwise).

## Verdict labels

- **PROVEN:** Raw evidence exists, adversarial self-attack failed, two independent methods agree.
- **HIGH-ROLE-ONLY:** Requires ADMIN/OPERATOR/ORACLE role. Not attacker-reachable without key compromise.
- **BLOCKED:** Two rounds of probing produced no forward progress and no evidence. Mark and move on.
- **UNPROVEN:** Theory or single-method claim without raw evidence.
- **REFUTED:** Evidence proves the opposite of the original claim.
- **OVERTURNED:** The falsifier written down at hypothesis time was actually met against live data, so the claim drops off the ladder while the code pattern remains as a named design risk. Distinct from REFUTED (the claim was wrong) and from BLOCKED (no evidence either way). Write the verdict as *"code contains X; live data shows premise Y holds ⇒ no attacker path; residual = design-risk-by-documentation"* — and never let an overturn silence the residual, because the premise (exclusive address, single-use nonce, funded-only-briefly) is a protocol *obligation*, not an enforced invariant.
- **DEAD-CODE:** The contract/path exists in the repo but nothing in production calls it (verify with a repo-wide
  grep for consumers **and** absence from `deployments/*.json`). Report it, but severity collapses — a public
  unguarded function on an unreferenced contract exposes nothing. Do not inflate to HIGH because the code "looks bad".
  **Not the same as ARMED-BY-FUNDING** (pitfall 31): a contract that never runs *and* never holds value is
  DEAD-CODE; one that runs and has held value in a real receipt but sits at 0 now is INERT/ARMED — keep the labels
  apart in both directions.
- **REAL / INERT / ARMED-BY-FUNDING:** The unguarded path exists and is reachable, currently holds nothing, but a
  receipt proves it **has** held value mid-cycle. Anyone can sweep whatever arrives next. Report with the arming
  trigger named (e.g. "a direct solver transfer outside the normal cycle"). This is a latent condition worth a
  writeup, not a Critical — and never a DEAD-CODE discard.
- **INFERRED-GATE (the one that keeps a session honest):** the code has no guard, but the only thing standing between
  an attacker and value is a cryptographic secret you cannot forge (oracle signature, threshold multisig). Public
  entrypoint + zero access control + a signature check that fires *last* is **not** a Critical, and it is **not**
  blocked — it is a design weakness whose severity depends on signature availability. Label it
  `INFERRED-GATE / MEDIUM`, prove the gate is the ONLY obstruction by showing the attacker gets past every earlier
  guard (distinct revert constant is the proof), then explicitly state what would upgrade it to Critical
  (a leaked/obtainable signature, a replayed approval, an unbound field the signer doesn't see).
- **INFO:** Missing guard / hygiene defect with no attacker-reachable impact path (`address(0)` mint, mixed-case
  bech32 accepted, non-`==20` length pin). Report honestly as INFO; never launder it into HIGH.

## Honest-outcome reporting

**A refuting PoC is a deliverable — record it as one.** When a finding is closed by
proving the attack *cannot* fire (helper has no role, no balance, gate names
`msg.sender`), do not promote it and do not leave the loud title in place:
`hunt poc run` the refuting script, then `retitle` the finding so `hunt status` stops
advertising a claim you just disproved. A `PASS` line whose text reads
`"... claim DISCARDED (reason)"` documents the correction inside the artifact itself.
See `references/poc-execution-and-portability.md` §5–7.

A round that finds nothing is a valid deliverable. What makes it trustworthy is
the **count of what was ruled out**, not the count of findings:

- Report the refuted hypotheses with their refuting evidence, side by side.
- Never write "the protocol is safe". Write "N paths tested, N raw evidences, no
  keyless path found" — that is a bounded claim you can defend.
- When a subagent's claim is REFUTED by your own probe, say so explicitly and
  show both the claim and the disproving hex. Silent dropping of subagent output
  is how a fabricated Critical ships.
- Zero-Critical rounds still produce value: the design-risk / centralisation
  observations (e.g. one EOA holding both the multisig owner slot and
  OPERATOR_ROLE on the value contract) are reportable as SPOF, not as exploits.
