# Trust-graph briefs: role-reachability, checked-arithmetic accident guards, and latent-vs-live labeling

Condensed from an AGENT-1 "architect" round on Relay Protocol (chain 537713) whose deliverable was
a code-derived trust-boundary map, not a single chain: entrypoint table per contract, data flow per
function, invariant list with enforcement status, and user-input→privileged-logic touchpoints.

Companion to `references/evm-foundry-and-offchain-api-audit.md` §11 (the mechanics) and
`references/live-rpc-forensics-and-eth-call-trap.md` (the `eth_call` trap). This file holds the
three things that repeatedly decided severity on that brief.

**Section list:** §1 the privileged-contract you were not handed · §2 `mint`/`burn` without a cap is
a design property, not a finding — but WHICH contract holds the operator role is the finding ·
§3 checked arithmetic can close a missing-guard bug accidentally — and that is a LATENT critical ·
§4 mapping-key mismatch: two checks that look like one · §5 latent-vs-live labeling, and why an
undeployed module still belongs in the map · §6 the 20-line summary contract ·
**§7 the CENSUS DEMOTION — how a chain-state enumeration turned two would-be HIGHs into MATI and
LATENT, and why this must be a mandatory step before any severity word** ·
**§8 READ BOUNDED, NEVER WHOLE — the read-budget discipline that lets a wide-map brief finish, and
the "absence by inventory" rule that makes a negative claim defensible**.

---

## 1. THE PRIVILEGED CONTRACT YOU WERE NOT HANDED

The brief listed Hub, Executor, Allocator, ERC20View, DepositAddressManager, WithdrawGasPayer.
The contract that actually mattered — `RelayOracleV2` at `0xd180dc3b…` — was in **none of them**,
and held `OPERATOR_ROLE` on the Hub, i.e. unbounded `mint`/`burn`/`transferFrom`.

**How it surfaced: decode a real transaction, not the deployment manifest.** The manifest lists
what the team considers "the protocol". The executor's call graph lists what the chain actually
trusts:

```bash
cast tx 0x9ff2ca45…f718 --rpc-url $RPC | head -20    # from / to / selector / input
cast codesize 0x6496D6C81Be24c10de548024f0431a6D9D6f8777 --rpc-url $RPC   # 3808 → a contract
cast codesize 0xd180dc3b8cb71b185c563b6e4857592ca93dacaf --rpc-url $RPC   # 8687 → a contract
cast call 0xd180dc3b… "HUB()(address)" --rpc-url $RPC                     # → the Hub
```

**Then census the role over the discovered address, not just the manifest's:**

```bash
OP=$(cast keccak "OPERATOR_ROLE")
cast call $HUB "hasRole(bytes32,address)(bool)" $OP 0xd180dc3b… --rpc-url $RPC   # → true
```

`cast call ... hasRole(...)` returning `true` for a contract nobody mentioned is the whole finding's
foundation. **Rule: before writing the entrypoint table, take one `Executed`/`Executed`-style event,
resolve the tx's `to` addresses, and role-census every one of them.** The manifest is a claim; the
call graph is evidence. In this session that single step promoted a minor oracle helper into the
protocol's mint authority.

Second payoff from the same decode: the verified source of the surprise contract was
`additional_sources`-free (single file, 16,797 chars) and diffed against the repo to a
whitespace-only, param-rename-only delta — which let every subsequent `file:line` from the clone be
cited as deployed truth. See `live-rpc-forensics-and-eth-call-trap.md` §2 for the diff mechanics.

---

## 2. `mint`/`burn` WITHOUT A CAP IS A DESIGN PROPERTY — but which contract holds the role is not

For a settlement protocol, `HUB.mint(to, id, amount)` with no ceiling, called from a
signature-gated oracle, is the architecture. Do not report "unbounded mint" as a finding; report
**what the signer can be made to sign, and who controls the modules the signer trusts.**

The productive decomposition on this target:

| Layer | Question | Evidence here |
|---|---|---|
| Signature gate | Does an unauthorized caller reach the action loop? | `hasRole(ORACLE_ROLE, oracle)` + `isValidSignatureNow` — `RelayOracleV2.sol:401,:407`; probed live → revert `InvalidSignature` (`0xd855c4f4`) |
| Playload gate | Can the caller choose `amount`/`to`? | no — both are inside `_hashExecution` (`:430-456`); only the signer picks them |
| **Module gate** | Can a lower-privileged actor install code the signer will call? | **yes-ish** — `addFeeCalculator`/`addRateLimiter` are `onlyRole(ADMIN_ROLE)` (`:220,:201`), and ADMIN is a single EOA |
| Value gate | Is any on-chain cap applied to the minted amount? | **no** (`:277`, `:374`) — bounded only by off-chain policy |

So the honest sentence is not "unbounded mint"; it is:

> "Mint authority is a 2-of-5 oracle signature over an action that names `(to, tokenId, amount)`.
> No on-chain ceiling exists. The one-shaped hole is that the oracle's *pluggable modules* —
> `feeCalculator`, `rateLimiter` — are registered by a **single EOA holding `ADMIN_ROLE`**, so that
> key can install a calculator whose return value drives `HUB.transferFrom(fee.payer → fee.recipient)`
> (`:342-344` → `:370`) with `ORACLE`-grade authority."

**Registry-admin-is-an-EOA is the recurring real finding in modular protocols.** Grep every
`onlyRole(ADMIN_ROLE)` writer that takes an *address* (not a value) and resolve that address's
holder on-chain. `addFeeCalculator`, `addRateLimiter`, `setPayloadBuilder`, `addSigner` all have
this shape. Then state the composition: does the installed module's output reach a
role-privileged call? If yes, ADMIN-EOA + signature = drain.

---

## 3. CHECKED ARITHMETIC CAN CLOSE A MISSING-GUARD BUG ACCIDENTALLY — call it LATENT, not refuted

The most instructive near-miss. On-chain, `Hub.transferFrom` has no caller check beyond an `if`
that merely *conditions* allowance decrement (`RelayHub.sol:255-263`):

```solidity
if (msg.sender != sender && !isOperator(sender, msg.sender) && erc20Views[id] != msg.sender) {
  uint256 allowed = allowance[sender][msg.sender][id];
  if (allowed != type(uint256).max)
    allowance[sender][msg.sender][id] = allowed - amount;   // underflow when allowed < amount
}
balanceOf[sender][id] -= amount;                            // ← the only real gate
```

No `revert` on the unauthorized branch. Yet theft does not happen, because `allowed - amount`
underflows (panic `0x11`) whenever the attacker has less allowance than `amount`.

**The two-probe pair that distinguishes "guard exists" from "arithmetic accidentally blocks it":**

```bash
# amount = 0 → succeeds. Proves there is NO authorization check, only arithmetic.
cast call $HUB "transferFrom(address,address,uint256,uint256)(bool)" $VICTIM $ATK $ID 0 --from $ATK
# → true

# amount > 0 with allowance 0 → panic 0x11, NOT a named access-control error.
cast call $HUB "transferFrom(address,address,uint256,uint256)(bool)" $VICTIM $ATK $ID 500000000000000000 --from $ATK
# → panic 0x11
```

**Read the revert KIND.** A protocol named error (`OnlyERC20ViewCanCallApproveFor`) means a guard
exists — retract (`live-rpc-forensics-and-eth-call-trap.md` §5a). A **bare `panic 0x11`** means the
code reached unchecked arithmetic with no authorization gate, and the panic is doing the guarding.
Those are opposite diagnoses with the same-looking output, and the `amount = 0` control is what
separates them: a real guard rejects `amount = 0` too; underflow does not.

**Severity label: LATENT CRITICAL, not "refuted", not "critical".** The exact sentence:

> "No authorization check exists before the balance debit (`RelayHub.sol:255-263`). The function is
> currently non-exploitable only because `allowed - amount` underflows. The moment any allowance
> ≥ `amount` exists from victim to attacker — including a 1-wei approval, or an approval to
> Executor/Allocator — the entire victim balance is transferable by a third party."

Verification that keeps it honest: `allowance(victim, Executor)` and `allowance(victim, Allocator)`
were both `0`, so it is not live today. Cite those zeros; they are what stops the latent claim from
reading as an active exploit.

**Generalised hunting question:** for every `if (unauthorized) { accounting }` with no `revert` in
the branch, ask *what arithmetic runs in that branch, and does it underflow?* This is a distinct
class from the "modifier on the next line" traps (`evm-foundry-and-offchain-api-audit.md` §7a) —
here the gate is genuinely absent and a *different* mechanism is silently compensating.

---

## 4. MAPPING-KEY MISMATCH — two checks that look like one

In `RelayFundingPool.debit`, accessibility and accounting are keyed differently, and the difference
is a live accounting hole:

```solidity
// per-leg record: correctly scoped
if (drawRecords[draw.orderAddress][draw.account][draw.legIndex]) revert AlreadyDrawn(...);   // :377

// cap: keyed per TOKEN, so "per order" is really "per order per token"
uint256 orderTotal = orderDraws[draw.orderAddress][draw.account][draw.token] + draw.amount;  // :395-397
if (orderTotal > config.perOrderCap) revert PerOrderCapExceeded(...);                          // :398
```

The config struct's `perOrderCap` is documented as "maximum total amount one order's draws may
take" (`IRelayFundingPool.sol:21-22`). The implementation makes it `cap × n_tokens` per order.
**Doc-vs-key mismatch on composite mapping keys is a one-look finding once you read the key tuple
instead of the variable name.**

The same file has a second, sharper instance — the authorization struct omits the field the
accounting uses:

```solidity
struct DrawAuthorization { address account; address orderAddress; }   // IRelayFundingPool.sol:51-54
// hash covers only those two:                                        :681-692
// yet the draw consumes sponsorshipConfig[account][TOKEN] and debits a specific token
```

So one authorizer signature authorizes **every token** the account has configured. That is exactly
the `evm-…` §13c "authorization/effect binding gap" family, applied to a token dimension instead of
a chain-id dimension.

**Checklist when auditing any per-account draw/spend authorization:**

1. Write out the mapping key tuple for the **eligibility** check and for the **cap/accounting**
   check, side by side. Any dimension in one but not the other is the hole.
2. Write out the signed struct's fields. Every field that selects *which resource* is consumed
   (`token`, `vault`, `asset`, `legIndex`) must be in the signed struct.
3. Confirm the revert **rolls back** the accounting it wrote (`:413` before `:420-433`) — if the
   record write precedes an external call in the same tx it is safe, but only because of revert
   semantics; say so rather than assuming a `nonReentrant` saved it.

---

## 5. LATENT-vs-LIVE LABELLING — an undeployed module still belongs in the map

Half of this session's findings were in `RelayFundingPool` + `PoolDrawResolver`, which turned out to
have **zero** on-chain presence:

```bash
# 0 → module never deployed on this chain
curl -s ".../api?module=logs&action=getLogs&fromBlock=0&toBlock=latest&topic0=$(cast keccak 'Deposited(address,address,address,uint256)')"
# → {"result":[], "message":"No logs found"}
curl -s "...&topic0=$(cast keccak 'DrawLegExecuted(address,address,address,bytes32,uint8,address,address,uint256,uint256)')"
# → 0 results
```

**The cheap liveness test for any module: find one event only that module can emit, query it with
`fromBlock=0`.** Zero results is strong evidence of non-deployment (and `cast codesize` on the
address, if you have one, is conclusive).

**Do not drop those findings, and do not rank them alongside live ones.** Split the report:

| Label | Meaning | Ranking |
|---|---|---|
| **LIVE** | code deployed on the audited chain AND the preconditions hold today | real severity |
| **LATENT** | code deployed, preconditions absent today (allowance `0`, rate-limiter registered, role unheld) | severity + the exact enabling condition |
| **UNDEPLOYED** | module absent from the chain | keep in the map, out of the risk ranking; it is a *design* review of code that will ship |

A trust-graph brief is a map, so undeployed modules still get their entrypoint rows — but marking
them UNDEPLOYED up front prevents a reviewer from thinking the map conflates shipped and planned
code. Say it in the verification section, once, with the log query as evidence.

---

## 6. THE 20-LINE SUMMARY CONTRACT — rank by exploitable-now, disclose the rest

When the brief demands a bounded closing summary ("print 20 lines: strongest candidates +
file:line"), the failure mode is 20 items of equal weight, half of which are latent. Structure it:

1. **Lines 1–5: LIVE, highest impact first.** Each = one claim + `file:line` + the on-chain fact that
   makes it live.
2. **Lines 6–15: LATENT or design-property.** Each names the *enabling condition* in the same line
   ("latent: needs any allowance ≥ amount").
3. **Lines 16–20: root-of-trust + UNDEPLOYED.** Including the single-EOA root, since it bounds the
   severity of everything above.
4. **Then a priority table** (`P0/P1/P2` × finding × `file:line` × concrete patch). This is what an
   operator acts on, and it costs nothing to add after the 20 lines.

**Do not let a latent item outrank a live one in the numbered list** even if it feels more severe —
the reader's first five lines are what they triage. Put the enabling condition inline so the ranking
is self-justifying, and never write "attacker can steal" for a path that needs a precondition the
chain does not currently satisfy.

---

## 7. THE CENSUS DEMOTION — enumerate the chain state before writing a severity word

Two findings in one multi-round hunt were argued at HIGH from source code, and both died to a
five-minute chain-state census. Neither was a logic error — the code said exactly what it said. What
was missing was the *population* the code ranged over. **A bug with zero instances is not a bug.**

### 7a. Case one: the mint authority that could not mint

Source read: `RelayOracleV2` holds `Hub.OPERATOR_ROLE` (`true`, confirmed live) and calls
`HUB.mint(...)` at `:277` and `:374` with no on-chain ceiling. That reads as infinite mint.

Census that killed it:

```bash
# 1. is the oracle's own auth gate bypassable?  No — role check and signature check are the SAME variable
sed -n '393,407p' RelayOracleV2.sol
#   function _execute(Execution calldata execution, address oracleMultisig, bytes calldata signature)
#   :401  if (!hasRole(ORACLE_ROLE, oracleMultisig)) revert UnauthorizedOracle();
#   :407  if (!oracleMultisig.isValidSignatureNow(digest, signature)) revert InvalidSignature();
#   one address, checked twice → no argument-order confusion, no substitution

# 2. is the live bytecode the repo source?  All 21 selectors match; no adminMint/forceExecute
cast selectors $(cast code $ORACLE --rpc-url $RPC); cast 4byte 0x32acd8f9

# 3. is it upgradeable?  EIP-1967 impl slot must be zero
cast storage $ORACLE 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC

# 4. can an unprivileged caller reach mint at all?
cast call $HUB "mint(address,uint256,uint256)(bool)" 0x…dEaD 1 1000000 \
     --from 0x000000000000000000000000000000000000bEEF --rpc-url $RPC
# → AccessControlUnauthorizedAccount(0x…bEEF, 0x9766…b929)   ← keccak("OPERATOR_ROLE"), decoded
```

Verdict: **MATI**. The role is real, the mint is real, no unprivileged path exists. Report the role
census (every `OPERATOR_ROLE` holder, with grant/revoke block numbers) as the map, and drop the
"infinite mint" framing entirely.

### 7b. Case two: the signature forgeability with no target

Source read + live HTTP proof: the withdraw-authorization signer omits `depository` from the owner
digest, so one owner signature yields oracle signatures over any depository (see
`evm-foundry-and-offchain-api-audit.md` §16d). Proven with `200` responses and differing oracle
signatures. That reads as HIGH cross-depository drain.

Census that demoted it — **count the population the freedom ranges over**:

```python
# every PayloadBuilderSet on the Allocator, grouped by chainId → set of depositories
# tip-block scan; chunk to dodge "Response size exceeds limit"
# → total 152 events | 96 distinct chainIds | chainIds with >1 depository: 0
```

Zero chains have two depositories ⇒ "replay onto a different depository" has **no address to replay
onto**. An arbitrary depository value still gets signed, but execution reverts `NoPayloadBuilder`.
Verdict: **MEDIUM latent**, enabling condition written down explicitly ("becomes HIGH the moment a
second depository is registered for an existing chainId").

### 7c. The rule this generalises to

For every finding whose severity depends on *how many things exist*, run the census **before**
choosing the severity word:

| Finding shape | The census | Demotes to |
|---|---|---|
| Cross-module / cross-depository replay | count registrations per chainId | latent if every chainId has exactly 1 |
| Role-holder is an EOA | `eth_getLogs` `RoleGranted`/`RoleRevoked` from 0, then `hasRole` each | map it; severity depends on who holds it |
| Rate-limit / cap bypass | count the cap's dimensions vs the key's dimensions | already covered by §4 |
| "Anyone can call" | negative call from an unrelated EOA, dark-reading the **decoded** revert | MATI if a named protocol error returns |

Practical notes that cost time on this target:

- `eth_getLogs` over `fromBlock=0` on a busy contract returns *"Response size exceeds limit. Use
  eth_getLogsWithCursor"* — chunk by ~50k blocks, or use the explorer's cursor endpoint.
- A **swallowed** log-query error reads as "zero results". One agent concluded `Executed = 0` for a
  tx that clearly executed 20 actions. Always cross-check a zero-result query against a known
  positive (that tx hash) before believing it.
- The **grant chain is evidence**: block numbers of `RoleGranted`/`RoleRevoked` showed a privileged
  contract granted 17 blocks *before* its predecessor was revoked, and surfaced a live
  `OPERATOR_ROLE` holder present in **no deployment manifest** — a finding the source read alone
  could never have produced.

**Reporting discipline:** run the census, and when it demotes a finding, say so in the report with
the number. *"Code-level real; population scan shows 0 instances; LATENT, not live"* earns more
credibility than a HIGH that a triager collapses in thirty seconds — and the census is what lets
you claim the remaining findings with confidence.

---

## 8. READ BOUNDED, NEVER WHOLE — the read-budget discipline for wide-map briefs

A trust-graph brief on a large Foundry repo (~70 `.sol` files, several of which are 400–700 lines)
will exhaust the turn budget long before the map is written *if* every contract is read end to end.
On the session that produced this file, whole-file reads of Hub/OracleV2/Allocator/Executor/
PoolResolverBase/FundingPool consumed the entire iteration allowance and **the deliverable was never
written**. The read was complete and correct; the artifact did not exist. That is a failed brief.

### 8a. The three-tool loop

Never open a 500-line contract cold. For every contract on the brief:

1. **Outline first — one `search_files`, not a read.** Get the skeleton with a single content search
   and read the *shape*, not the body:
   ```
   pattern: function |onlyRole|ROLE =|event |error |immutable|mapping\(
   ```
   This yields the entrypoint table row for the whole file in ~50 lines of output, including every
   role gate, every state variable, and every custom error. **This is enough to write most of the
   trust-graph node.** Do it for all files before deep-reading any file.
2. **Read only the security-relevant span.** Once the outline has told you which function matters,
   read a bounded window around it (`offset`/`limit`, 60–230 lines). Cite `file:line` from that
   window.
3. **Reserve whole-file reads for the ≤5 contracts that are the actual trust roots** (the mint
   authority, the burn authority, the signature verifier, the fund pool, the resolver). Everything
   else is outline + targeted span.

Also: **do not re-read a file you already read.** `read_file` warns
`idempotent_no_progress_warning` after repeat calls. In this session that warning fired repeatedly on
`RelayOracleMultisig`, `RelayMultisigSigner`, `Utils`, `SignedPricingOracle`, `ResolverSandbox` — the
content was already in hand and the re-reads bought nothing but lost iterations. If a result is in the
transcript, use it.

### 8b. Sectioned reads have a hidden cost — duplicate work across context windows

Reading a 500-line contract as `1–200` / `201–560` costs two calls and, after a compaction, tends to
get **re-read from scratch** because the earlier result is gone. Prefer one bounded read of the span
that matters over two reads of the whole file. If you must read a file whole, read it once, and
immediately write its node into the deliverable file so the finding survives a compaction.

**Write the deliverable incrementally, section by section, as each contract is mapped.** A partial
trust-graph document on disk beats a complete map in a context window that then expires. If the
brief's output is a markdown doc, create it after the outline pass and append as you go.

### 8c. "ABSENCE BY INVENTORY" — how to defend a negative claim

Trust-graph briefs generate negative claims ("there is no depository contract", "no on-chain deposit
verification exists"). Those are load-bearing findings and they need stronger evidence than a failed
grep.

**A grep that returns 0 is not proof of absence.** Two distinct failure modes:

- `search_files` with an alternation pattern (`depositNative|depositErc20|contract RelayDepository`)
  can return `total_count: 0` or a malformed `? matches` for reasons unrelated to the code. Treat a
  zero/`?` from a compound pattern as **inconclusive**, never as evidence.
- A construct can exist under a different name than the brief assumes. Here, `RelayDepository` did
  not exist — deposit logic lived in `deposit-addresses/RelayDepositAddressManager.sol` plus a
  `funding-pools/` dir the brief never mentioned.

**The defensible sequence:**

1. Enumerate the full inventory once: `find contracts -name '*.sol' | sort` (and `| wc -l`). This is
   the sole ground truth for "what files exist" — cheap, one call, survives re-reading.
2. Re-run the negative search as **single literal terms**, one at a time, not alternations
   (`RelayDepository`, then `depositNative`, then `depository`).
3. Cross-check with a *positive* control: search a term you know exists in the same tree and confirm
   it returns matches. If the positive control also returns 0 or `?`, your search tool is misbehaving
   and every conclusion from it is void.
4. Then state the negative with its basis: *"No `RelayDepository` contract exists — full inventory of
   N `.sol` files contains none; deposit-address logic is `deposit-addresses/RelayDepositAddressManager.sol`."*

### 8d. The negative-claim paragraph that actually carried this brief

The single most valuable sentence in the map was a *negative* one, and it only became writable after
the inventory + targeted reads:

> "The on-chain chain of custody starts at the oracle signature, not at a deposit. There is no
> `RelayDepository` in the repo. `RelayDepositAddressManager.trigger` (`:91-130`) records a trigger
> hash and calls a **caller-chosen** `pricingOracle` (`:110-111`) — it mints nothing and is never
> consulted by the oracle. So deposit → attestation is **off-chain / UNKNOWN**, and
> `OracleV2._execute` → `HUB.mint` (`:277`, `:374`) is enforced only by the multisig signature."

Note the three-part shape, which is the template for every "trust boundary is off-chain" finding:

1. **Name the absence** and its evidentiary basis (inventory).
2. **Name the nearest on-chain contract** that looks like it does the job, and show it does not
   (with the `file:line` of the caller-chosen parameter that proves it's unattested).
3. **Name the exact `file:line` where the privileged effect is applied**, so the reader sees the
   whole gap in one paragraph.

`UNKNOWN` is a legitimate and honest label for an off-chain hop. Do not upgrade it to "vulnerable";
put it in the map, mark it, and let severity follow from whether an attacker can influence the
off-chain signer's inputs (see `references/offchain-signing-services-and-split-binding.md`).
