# Diamond / EIP-2535 facet access-control mapping

Companion to `readonly-security-audit` for the case where the brief is **"map access control
on every facet and find where untrusted input crosses into privileged logic"** on a diamond
contract. Worked reference case: Gardens `CVStrategy` diamond (8 facets + base facet,
`pkg/contracts/src/CVStrategy/`), 2026-10-29.

## Why this is NOT the fund-theft invariant hunt

`references/defi-invariant-hunting.md` delivers **a verdict per invariant** (BROKEN / HOLDS /
REFUTED / UNTESTED). That is the wrong shape here. This brief asks a *structural* question:
who can call what, and which parameters are attacker-supplied. The deliverable is an
**authority map**, in four parts:

1. **Modifier-primitive table** — every gate defined in the base facet, with its exact
   semantics and line number.
2. **Per-facet function inventory** — every external/public function, its gate, and whether
   the gate is inline or inherited.
3. **Untrusted-input → privileged-sink crossing list** — each crossing with the parameter,
   the sink, what validation exists, and what is missing.
4. **Trust-root summary** — which principal is the root for which capability, so the reader
   knows what a compromise of each root buys.

Do not force severity verdicts. A finding here is "parameter X reaches sink Y with only gate
Z", not "CRITICAL". The user's question is a mapping question; answer it as one.

## Mandatory read order — base facet FIRST

This is the single highest-value rule in this class. In a diamond:

- Facets are **delegatecall targets**. They execute in the diamond's storage context, and
  their access-control modifiers are **inherited from the base facet**, not written inline.
- So a facet file read in isolation looks like it has *no* gates at all. Every gate is in
  `<Diamond>BaseFacet.sol` (or a shared library like `PauseFacetBase.sol`).
- Conversely, the main contract (`CVStrategy.sol`) is mostly **stub functions** that call
  `_delegateToFacet()`. Reading it as the implementation produces a report about nothing.

Read order that works:

```
1. <Diamond>BaseFacet.sol          ← modifiers, storage layout, shared helpers, pause helpers
2. shared libraries (PauseFacetBase, LibPauseStorage, storage libs)
3. facets/*.sol                    ← one by one; now the inherited gates are legible
4. <Diamond>.sol                   ← stubs + _delegateToFacet + diamondCut + init
5. the trust targets: RegistryFactory, RegistryCommunity + its facets,
   arbitrator, sybil scorer, collateral vault, escrow + escrow factory, proxy-owner helper
6. the enum/struct definitions (ICVStrategy.sol) — status enums decide which branches are live
```

Step 5 is not optional. "Where does untrusted input cross into privileged logic" is answered
by what the *receiving* contract does with the value, not by what the facet checks. Two
findings in the worked case only became findings after reading the receiver:
`registerSafe` in `SafeArbitrator.sol` has **no access control at all**, and
`modifyThreshold` in `PassportScorer.sol` authorizes `msg.sender == _strategy` — which the
strategy itself satisfies, so the strategy sets its own sybil gate.

## Mechanical first pass — scripts/facet_gate_scan.py

Run the selftest FIRST, then scan:

```bash
python3 scripts/facet_gate_scan.py --selftest          # verify the parser before trusting it
python3 scripts/facet_gate_scan.py <path-to-facets-dir> --all
```

It parses each `.sol` file, extracts `function` signatures with their modifier list, and
prints functions whose modifier list is empty. **It is a candidate list, not a finding list** —
inherited modifiers, `internal` helpers, `view`/`pure` getters, and functions gated by an
`if` inside the body all produce false positives. Use it to decide what to read closely,
never to claim "no access control".

⚠️ **The script was written in a session where the terminal tool was unavailable, so it has
never been executed against a real tree.** The `--selftest` flag exists precisely so the next
session can validate it in one command before relying on its output. If the selftest fails,
fix the parser or fall back to grep — do not publish its output as findings.

Two parser facts worth knowing before you trust the output:

- **Solidity modifiers come AFTER the parameter list**, not before it:
  `function allocate(bytes memory _data, address _sender) external payable onlyAllo ...`.
  The first version of this script captured only the region between the function name and
  the opening paren — which is always empty — so it reported *every* function as ungated.
  A scanner that cries wolf on 100% of the codebase is worse than no scanner. The current
  version does a balanced-paren scan to the end of the parameter list and reads modifiers
  from after it.
- `--all` is the more useful mode for finding class #1 (owner-resolution asymmetry): it
  prints every function *with* its modifiers, so you can eyeball which gates call
  `effectiveOwner()` and which call raw `proxyOwner()`. The asymmetry is invisible in the
  NO-MODIFIER list.

## Finding classes that recur in diamonds

Each of these was present in the worked case. Check for all of them.

### 1. Owner-resolution asymmetry (the highest-yield class)

A diamond often has TWO ways to resolve "the owner":

```solidity
function effectiveOwner() internal view returns (address) {   // base facet
    address currentOwner = proxyOwner();
    if (currentOwner.code.length == 0) return currentOwner;
    try IOwnableLike(currentOwner).owner() returns (address r) { return r == address(0) ? currentOwner : r; }
    catch { return currentOwner; }
}
```

Most admin paths use `effectiveOwner()` (which resolves through a `ProxyOwner` contract to
the real owner). **One facet used the raw `proxyOwner()` instead** — in the worked case
`CVPauseFacet._pauseOwner()` returned `proxyOwner()`, so `setPauseController` / `pause` /
`unpause` required the `ProxyOwner` *contract* as `msg.sender` while every sibling admin
function accepted the resolved owner.

**How to find it:** grep every `onlyOwner`-family gate in every facet and compare which
resolver each one calls. Any facet that resolves differently from its siblings is a finding.
Then ask what the difference means *in production* (where `proxyOwner()` is a contract) versus
in tests (where it is an EOA) — the bug is often invisible in tests.

### 2. Gate-downgrade bypass (the "authorized wallet" escape hatch)

Pattern:

```solidity
function connectSuperfluidGDA(address gda) external {
    if (!_isRegistryFactoryAuthorizedWallet(msg.sender)) {
        onlyCouncilSafeOrMember();     // ← weaker gate reached when the bypass fails
    }
    ...
}
```

The intent is "keeper/factory wallets skip the council check". The effect is that the
**member-level gate is the real gate** for everyone who is not a factory wallet, and
`onlyCouncilSafeOrMember` is satisfiable by anyone on an open allowlist. So a council-only
operation is reachable by any member.

**How to find it:** grep for `if (!_is...Authorized...)` / `if (!keepers[...])` followed by a
gate call. For each, ask: *what is the weakest principal that reaches the body?* Then trace
what that principal can do with the parameters. In the worked case the parameter was a raw
`gda` address flowing into `supertoken.connectPool(gda)` — arbitrary pool binding under a
member-level gate.

### 3. Validated-but-exempt parameter

```solidity
if (_registry != address(0) && _registry != address(registryCommunity)) {
    if (!IRegistryFactory(...).isContractRegistered(_registry)) revert NotAllowed(...);
}
votingPowerRegistry = _registry == address(0) ? IVotingPowerRegistry(address(registryCommunity)) : IVotingPowerRegistry(_registry);
```

The validation looks complete until you notice the exemption list. `address(0)` and the
community itself skip the registry check entirely. Then ask **what the parameter becomes**:
here it became the oracle for `isMember` (gating proposal creation, allocation, disputes) and
`getMemberPowerInStrategy` (conviction weight + the `totalPointsActivated` threshold
denominator). A settable oracle for the threshold denominator is a governance-manipulation
primitive even when the setter is trusted.

**Rule:** for every validated parameter, enumerate the exempt values AND trace what the
parameter is later *read as*. Validation of the setter is not validation of the consequence.

### 4. Timeout path that skips both the auth check and the bound

```solidity
bool isTimeOut = block.timestamp > proposal.disputeInfo.disputeTimestamp + arbitrableConfig.defaultRulingTimeout;
if (!isTimeOut && msg.sender != address(arbitrableConfig.arbitrator)) revert OnlyArbitrator(...);
if (!isTimeOut && _ruling > 2) revert InvalidRuling(_ruling);
```

After the timeout, **anyone** can call, and `_ruling` is unbounded. In the worked case the
unbounded value turned out to be harmless because the `isTimeOut || _ruling == 0` branch
ignores `_ruling` and uses `defaultRuling` — but the *open* call is still a finding (anyone
can force dispute resolution), and the skipped bound is a latent hazard if the branch logic
ever changes.

**Rule:** when a check is guarded by `!isTimeOut`, read the timeout branch's *use* of the
parameter before deciding severity. Report the open call; report the unbounded value as
latent if it is currently unused.

### 5. Unguarded public mutator

`wrapIfNeeded()` was `public` with no modifier, doing `approve` + `upgrade` on the strategy's
own balances. No theft (funds stay in the strategy) but any address can trigger the state
change and consume the approval. Grep for `public`/`external` functions with an empty
modifier list and no `if (msg.sender ...)` in the body — that is what
`scripts/facet_gate_scan.py` surfaces.

### 6. Register-then-trust (the receiver has no gate)

The facet calls `arbitrator.registerSafe(tribunalSafe)` where `tribunalSafe` is
**never validated** — and `SafeArbitrator.registerSafe` is:

```solidity
function registerSafe(address _safe) external {
    arbitrableTribunalSafe[msg.sender] = _safe;   // no access control whatsoever
    emit SafeRegistered(msg.sender, _safe);
}
```

`executeRuling` then authorizes purely on `disputes[id-1].tribunalSafe`. So the value written
here becomes the ruling authority for every dispute under that config version.

**Rule:** for every `X.registerY(addr)` / `X.setY(addr)` call from a facet, read the receiver's
gate. A validated caller does not imply a validated parameter, and an unvalidated parameter
does not imply an unguarded receiver — you have to check both ends.

### 7. Setter-becomes-oracle

`setPoolParams` → `sybilScorer.modifyThreshold(address(this), _sybilScoreThreshold)`, and
`PassportScorer.modifyThreshold` allows `msg.sender == _strategy`. The strategy therefore
writes its own sybil gate. Same shape as #6: the receiver's gate is satisfied by the caller
by design, so the "council-gated upstream" claim is the only thing standing between a
parameter and a privilege change. State that explicitly.

### 8. Parameters that are decoded but never validated

`registerRecipient(bytes _data, address _sender)` decodes a `CreateProposal` struct and uses
`proposal.beneficiary` as the eventual payout target, `proposal.requestedToken` (validated
against the pool token **only for `ProposalType.Funding`**), and `proposal.poolId` — which is
decoded and **never compared to the actual `poolId`**. Allo-gated, so not attacker-reachable
today, but it is exactly the kind of latent hole that becomes live when a new caller is added.

**Rule:** for every `abi.decode`, list each field and mark it validated / unvalidated /
conditionally-validated. The conditional ones are the interesting ones.

## Second worked case: RegistryCommunity (2026-10-29) — new finding classes

Same brief, different diamond (`pkg/contracts/src/RegistryCommunity/`: 6 facets + base facet +
`RegistryCommunity.sol` stubs). It produced finding classes the CVStrategy case did not — and it
also produced the most expensive process failure in this skill so far.

### ⛔ PROCESS FAILURE FIRST: this session died at the iteration ceiling with no report

The session burned ~30 calls reading six facets + base + main contract and then verifying every
downstream claim (RegistryFactory, Allo `_createPool`, `CVPowerFacet`, `CVAdminFacet`,
`GoodDollarSybil`, `PassportScorer`, the deployed selector map, the advisory ledger) — then hit
the 50-call ceiling and 504'd on the closing summary. **No report landed.** The analysis was
right and worthless.

For a mapping brief the Report Shape D rule is not optional:

- **Write the report skeleton by call ~5** — the four section headers plus a PENDING table.
- **Append after every ~5 calls.** Never rewrite.
- **Cap verification at ~10 calls.** Source-level analysis answers most of the question; live
  selector maps and downstream receivers are enhancements, not prerequisites.
- Reserve the last ~10 calls for the closing summary.

### 9. Unguarded public entry that mints a privileged object

`CommunityPoolFacet.createPool(...)` — **both overloads are `public` with no modifier**
(`CommunityPoolFacet.sol:58,103`). No `onlyCouncilSafe`, no `onlyOwner`, no member check.
Consequences, all inside one function:

- deploys a fresh `ERC1967Proxy` from the factory's strategy template,
- `_grantRole(allowlistRole, _params.initialAllowlist[i])` for up to 10,000
  **attacker-supplied** addresses (`CommunityPoolFacet.sol:77-79`),
- `_grantRole(ALLOWLIST_ADMIN_<poolId>, strategy)` + `_setRoleAdmin(...)`,
- `CVStrategy(...).transferOwnership(proxyOwner())`.

So "who can create a pool" is **anyone**, and pool creation is itself a role-granting operation.
In the CVStrategy case every mutator had a gate; here the highest-consequence function has none.
**Check the object-creation entry for a gate before anything else — creation is the
privilege-minting step.**

### 10. Untrusted ID → arbitrary address → privileged registration

```solidity
function addStrategyByPoolId(uint256 poolId) public {        // council-gated
    address strategy = address(allo.getPool(poolId).strategy);
    _addStrategy(strategy);
}
```

`poolId` is unconstrained and `allo` is the **shared protocol Allo**, not a per-community
registry. Any pool ID from any community resolves to an arbitrary strategy address, which is
written to `enabledStrategies[strategy] = true` and then becomes a contract that
`increasePower` / `decreasePower` calls for **every member of this community**
(`CommunityPowerFacet.sol:168,194`).

**Rule:** when a function takes a numeric ID and resolves it through a shared registry, the ID is
untrusted input even when the caller is trusted. Ask *whose namespace is this ID space?*

### 11. `msg.sender == <parameter>` gates let the parameter act on arbitrary third parties

```solidity
function activateMemberInStrategy(address _member, address _strategy) public {
    onlyRegistryMemberAddress(_member);
    onlyStrategyEnabled(_strategy);
    onlyStrategyAddress(msg.sender, _strategy);   // msg.sender must BE the strategy
    ...
    memberPowerInStrategy[_member][_strategy] = pointsToIncrease;
```

The gate authenticates the *caller*; `_member` is **completely unconstrained**. Any enabled
strategy contract can activate — and via `deactivateMemberInStrategy` deactivate — **any address
in the community**, including addresses that never interacted with it. Combined with #10 (council
can enable an arbitrary address as a "strategy") this is a full member-state manipulation
primitive.

**Rule:** a gate of the form `msg.sender == _param` says nothing about the *subject* parameter.
Always ask separately who the subject can name.

### 12. Arbitrary external call into an unvalidated address

`_addStrategy` does, on an address that only needs to be non-zero:

```solidity
ISybilScorer sybilScorer = CVStrategy(payable(_newStrategy)).sybilScorer();
if (address(sybilScorer) != address(0)) { sybilScorer.activateStrategy(_newStrategy); }
```

Two problems: an arbitrary external call (`sybilScorer()`) into an address with no code check,
and `GoodDollarSybil.activateStrategy` (`GoodDollarSybil.sol:97-99`) has **no access control at
all** — it just sets `strategies[_address].active = true`. The community writes another
contract's privilege state through a receiver that never checks the caller.

**Rule:** for every `X.foo()` on a parameter-supplied address, read the receiver's gate. This is
finding class #6 generalised — the receiver's gate is the only thing between a trusted caller and
an arbitrary write.

### 13. Partial parameter guarding (the timelock covers a subset of the struct)

`setCommunityParams(CommunityParams)` takes seven fields. When `totalMembers > 0` only three
(`registerStakeAmount`, `isKickEnabled`, `covenantIpfsHash`) go through `_queueGuardedParams` →
owner approval. The other four — `communityFee`, `feeReceiver`, `communityName`,
`councilSafe` — are applied **immediately, with no guard and no approval**
(`CommunityAdminFacet.sol:173-186`).

**Rule:** when a struct is "guarded", enumerate every field and mark which ones the guard
actually covers. A guard on 3 of 7 fields is a finding about the 4, not a control.

### 14. The approval path skips the bound the direct path enforces

`setBasisStakedAmount` is `onlyCouncilSafe` **and** `onlyEmptyCommunity`
(`CommunityAdminFacet.sol:107-114`). But `approvePendingCommunityParams` — owner-gated — sets
`registerStakeAmount` with **no empty-community check at all**
(`CommunityAdminFacet.sol:210-213`), and applies every queued field atomically with no
per-field selection. The indirect path is strictly more powerful than the direct one.

This is finding class #4 in a new costume: not a timeout branch, an **approval branch**. Same
question — *what does this branch skip that the sibling path enforces?*

### 15. Event-only setter (a governance control that writes nothing)

```solidity
function setArchived(bool _isArchived) external {
    if (msg.sig == bytes4(0)) revert();
    onlyCouncilSafe();
    emit CommunityArchived(_isArchived);      // ← no storage write, ever
}
```

`archived` is never stored and there is no `isArchived()` getter. The council can emit an
"archived" event that changes nothing. **Rule:** for every setter, confirm a storage write
exists. An event is not state.

### 16. Inconsistent counter guard between sibling mutators

`unregisterMember` decrements defensively — `if (totalMembers > 0) { totalMembers -= 1; }` — with
a comment explaining it resyncs contracts that skipped the counter until an upgrade.
`kickMember`, the sibling that removes a member by force, does `totalMembers -= 1;`
**unguarded** (`CommunityMemberFacet.sol:146`). If the counter is ever stale/low (which the first
function's own comment concedes happened historically), `kickMember` reverts on underflow and the
kick feature is bricked for that community.

**Rule:** when one mutator has a defensive guard and its sibling does not, the guard's comment
usually tells you the state it defends against is real.

### 17. Duplicated exemption lists that drift

`CommunityBaseFacet._isPauseSelector` (12 selectors) and the private
`RegistryCommunity._isPauseSelector` (14 selectors) are two copies of the same list and they
**disagree** — the main contract exempts `setPauseFacet(address)`, the base facet does not. Same
class as #1 (owner-resolution asymmetry): a duplicated policy where one copy was updated and the
other was not.

**Rule:** grep for two functions with the same name in the same package and diff their bodies.

### 18. Storage that is never written

`initialMembers` is declared, read by `createPool` (passed as the Allo managers array), and
**never assigned anywhere** (`grep -rn "initialMembers\s*="` → 0 hits). Every pool is therefore
created with an empty manager list. Not a vulnerability, but the "initial members become pool
managers" design is dead code — say so, so the reader does not reason about a control that does
not exist.

### 19. Trust-root facts worth stating explicitly for this diamond

- **Pause authority is the protocol owner, not the council.** `CommunityPauseFacet` inherits
  `PauseFacetBase`, whose `_pauseOwner()` returns `owner()` resolved through
  `ProxyOwnableUpgrader.owner()`. A community council cannot pause its own community.
- **`owner()` resolves recursively**: if `proxyOwner()` is a contract it calls `.owner()` on it,
  falling back to the contract address itself on failure. "The owner" may be two hops away, and a
  `try/catch` failure silently degrades to the contract address.
- **`COUNCIL_MEMBER` is one role with `DEFAULT_ADMIN_ROLE` as its admin**, granted at
  `initialize` and moved only by the two-step `setCouncilSafe` → `acceptCouncilSafe`. No
  multi-council, no per-capability roles.
- **Membership is permissionless when `registerStakeAmount == 0`** — `registerMember()` has no
  gate beyond that check (`CommunityMemberFacet.sol:76-85`). Documented as intended, but it is
  the trust boundary for every zero-stake community.

### Techniques that paid off (reuse these)

1. **`cast sig` to verify `// Sig: 0x...` comments.** Every facet function in this repo carries a
   hand-written selector comment. Recompute it: `cast sig "addStrategy(address)"` → `0x223e5479`.
   A mismatch means routing table and source disagree — and it also catches functions that **do
   not exist at all** (`setCommunityName`, `getCommunityParams`, `isArchived` all return
   selectors that appear in no facet, i.e. they are not part of this diamond's surface).
   Automate with `scripts/selector_map_check.py --sig-check`.
2. **The deployed facet map lives in `transaction-builder/*-health-audit.json`.** Walk it for keys
   ending in `facets` and you get the authoritative live `facetAddress → [selectors]` map for
   factory, community and strategy — no RPC needed. This is how you answer "is this code
   production-reachable" before spending calls on it. Automate with
   `scripts/selector_map_check.py --deployed-map`.
3. **Read the repo's own `AGENTS.md` security workflow first.** The root `AGENTS.md` mandates the
   advisory-eligibility workflow (read `security/advisory-history.md` +
   `security/known-non-eligible-findings.md`, match by root cause) — so the dedup step is a repo
   instruction, not just good practice. It also documents the facet-refresh flow and that
   `config/networks.json` is the source of truth for live addresses.
4. **Recognise the `if (msg.sig == bytes4(0)) revert();` idiom** (present on 10 functions across
   `CommunityStrategyFacet` / `CommunityAdminFacet` / `BaseStrategyUpgradeable`). It is a
   defensive guard against being reached with sub-4-byte calldata, not dead code — do not report
   it as one.

## Third worked case: the trust graph + forge PoC (2026-10-29)

Brief: *"Map the complete trust graph … identify every trust boundary + unverified assumption.
Find where user/untrusted input crosses into privileged logic (diamondCut, upgrade,
initializer, registry factory, proxy owner). Produce a ranked list of trust-boundary violations
with exact file:line evidence. If any violation is provable, write a forge PoC test."*

Same diamond family, different deliverable: not an authority map, a **trust graph** — nodes are
principals/contracts, edges are the calls that cross a boundary, output is a ranked violation
list with executable PoCs. Six of seven PoCs passed on the first run.

### New finding classes

**#20. Permissionless creation of a governed object where the creator names the governor.**
`RegistryFactory.createRegistry(params)` has no modifier (`RegistryFactory.sol:213-221`). The
params struct carries `_councilSafe` and `_feeReceiver`, and `RegistryCommunity.initialize`
does `_grantRole(COUNCIL_MEMBER, params._councilSafe)` (`RegistryCommunity.sol:334`). An
attacker therefore mints a community whose council **is the attacker**, then drives
council-gated state changes (`setCommunityFee`, `setBasisStakedAmount`, `addStrategy`,
`kickMember`, `setArchived`). Distinct from class #9 — there the attacker gets a pool; here the
attacker gets a **governance role over a factory-templated object**.
**Rule:** for every permissionless `create*`, read what roles the created object grants and who
names the grantee. "Anyone can create X" is INFO when X grants no authority and a finding when
the creator names the governor.

**#21. Untrusted trigger → trusted payload delegatecall.**
`CommunityPoolFacet.createPool` (unguarded, class #9) calls `_configureStrategyFacets`, which
reads `IRegistryFactory(registryFactory).getStrategyFacets()` — factory-owner-controlled facet
cuts + init + initCalldata (`RegistryFactory.sol:167-175`) — and calls
`IDiamondCut(strategyProxy).diamondCut(cuts, init, initCalldata)`
(`CommunityPoolFacet.sol:93`). `LibDiamond.initializeDiamondCut` then does
`_init.delegatecall(_calldata)` (`LibDiamond.sol:213`).
An untrusted caller triggers a delegatecall whose payload is factory-controlled. **Report both
halves separately** — a trusted payload does not make an untrusted trigger safe, and an
untrusted trigger does not make a trusted payload dangerous. This is the "sink PROVEN / trigger
NOT reachable" discipline applied to a delegatecall.
**Rule:** for every ungated entry that reaches a delegatecall, separate *who supplies the
payload* from *who supplies the trigger*.

**#22. Owner-resolution scope: `ProxyOwner` is safe from `upgradeAccess`; downstream is not.**
`ProxyOwner.owner()` returns `upgradeAccess` when set (`ProxyOwner.sol:35-40`), **but**
`ProxyOwner._checkOwner()` requires `proxyOwner()` (`ProxyOwner.sol:94-98`). So `upgradeAccess`
**cannot** call `transferOwnership` or `upgradeTo` on the ProxyOwner itself — both revert
`OwnableUnauthorizedAccount`. The boundary is crossed **downstream only**:
`ProxyOwnableUpgrader.owner()` resolves recursively (`ProxyOwnableUpgrader.sol:22-35`), and
`CVStrategy._checkOwner()` accepts `proxyOwner()` **or** the resolved `owner()`
(`CVStrategy.sol:391-399`).
⚠️ **This corrects an assumption that cost a PoC iteration.** The first ARCH-04 test asserted
`upgradeAccess` could `upgradeTo` the ProxyOwner; the forge trace disproved it. State the scope
of an ownership claim before publishing it — "upgradeAccess is the effective owner" is true
downstream and false on the ProxyOwner.
**Rule:** when claiming a principal is "the effective owner", name the contract(s) the claim
holds for, and test the boundary contract itself, not only a downstream one.

**#23. Recursive `owner()` resolution makes a contract owner a full ownership-capture vector.**
`ProxyOwnableUpgrader.owner()`: if `proxyOwner()` has code, call `proxyOwner().owner()` and
return the result; on failure fall back to `proxyOwner()` (`ProxyOwnableUpgrader.sol:22-35`). A
contract owner whose `owner()` returns an attacker address therefore makes the attacker the
effective owner of everything downstream. PoC: deploy `EvilOwner{ownerAddr: attacker}`,
`transferOwnership(evil)`, assert `proxy.owner() == attacker`, then `attacker.upgradeTo(impl2)`
succeeds.
**Rule:** any `try IOwnableLike(x).owner()` resolution delegates authority to `x`'s
implementation. Note the fallback path separately — it returns `proxyOwner()` and is the only
thing preventing a revert-loop DoS.

### The forge PoC recipe for a Foundry monorepo

The brief said "if any violation is provable, write a forge PoC test". These path rules cost
~6 calls to discover:

1. **Run `forge test` from the REPO ROOT, not from the package dir.** `foundry.toml` sets
   `src = 'pkg/contracts/src'`, `test = 'pkg/contracts/test'` relative to root, so
   `--match-path` is `pkg/contracts/test/<file>.t.sol`. Running from `pkg/contracts` with
   `--match-path "test/<file>.t.sol"` reports "no tests match the provided pattern".
2. **Imports in a test at `pkg/contracts/test/` are `../src/...`, not `../../src/...`.** A test
   drafted outside the tree needs its relative paths rewritten (`../helpers/`, `../shared/`,
   `../script/` likewise).
3. **Reuse the repo's existing fixture stack instead of building a new one.** `setUp` in
   `test/RegistryTest.t.sol` (AlloSetup + RegistrySetupFull + SafeSetup +
   StrategyDiamondConfigurator + CommunityDiamondConfigurator) is the known-good harness. Copy
   it and keep only the pieces the PoC needs.
4. **Struct definitions may live in the interface file, not the contract.**
   `CVStrategyInitializeParamsV0_3` is declared in `ICVStrategy.sol:143-156`; importing it from
   `CVStrategy.sol` fails with "Declaration not found". Check the interface file first.
5. **Pre-existing unrelated compile errors are bypassed with `--skip`, not fixed.**
   `test/shared/TERC20.sol` has `override` on non-overriding functions;
   `forge test --skip TERC20 --skip GV2ERC20` runs the rest. Report the pre-existing defect; do
   not patch a production tree to make a PoC compile.
6. **A failing PoC is a finding about your assumption, not about the contract.** Read the trace
   before rewriting the assertion — see #22.
7. **`forge build` is cached** ("No files changed, compilation skipped") once the tree has
   compiled, so a second run is fast. Start the build in the background on call ~2-3 if the
   tree is cold.

### Budget note

The trust-graph brief is the most call-hungry variant in this class: it names five specific
surfaces (diamondCut, upgrade, initializer, registry factory, proxy owner) and demands PoCs.
Three parallel subagents covered storage layout, CVStrategy facets, and community facets; the
third hit the 50-iteration ceiling with no report and its territory had to be read directly.
Write the findings skeleton before the fan-out, and expect to read at least one subagent's
territory yourself.

## Report shape that landed

Markdown, in the chat (the user did not ask for a file), four sections:

1. **Modifier-primitive table** — `| primitive | line | semantics |`. Include the resolver
   each gate uses, because that is what makes #1 visible.
2. **Per-facet inventory** — one block per facet, `function (lines) → gate (line)`, plus a
   note for functions with no gate. Mark views separately.
3. **Crossings** — numbered, each with: parameter → sink (both with line numbers), the gate,
   what is validated, what is missing, and the consequence. Keep the "council-gated, but…"
   qualifier on every one — this user wants the precondition stated, not hidden.
4. **Trust-root summary** — a short list of roots and what each buys, ending with the
   structural observation: *every authorization decision reads from contract storage, none
   trusts an attacker-supplied address for authorization; the exposures are (a) broad/weak
   gates on privileged operations, (b) unvalidated parameters reaching privileged sinks,
   (c) resolution inconsistencies and one unguarded public mutator.*

That last sentence is the actual answer to "where does untrusted input cross into privileged
logic" — say it plainly rather than leaving the reader to infer it from 14 numbered items.

## Pitfalls

- **Do not read a facet before the base facet.** You will report "no access control" on
  functions that are gated by an inherited modifier.
- **Do not report the main contract as the implementation.** In a diamond it is stubs +
  `_delegateToFacet()`.
- **Do not confuse a validated *caller* with a validated *parameter*.** They are independent
  findings and the second is the one this brief asks for.
- **Do not skip the receivers.** `registerSafe`, `modifyThreshold`, `grantRole`,
  `withdrawCollateral` all live outside the facet and their gates decide whether a
  facet-level "council-gated" claim is meaningful.
- **Do not omit the enum definitions.** `ProposalStatus` / `ProposalType` decide which
  branches are reachable; a check that looks missing may be unreachable for the only status
  the code can be in.
- **Do not edit anything.** Same hard contract as every other audit in this skill.
- **State preconditions, not severities.** "Council-gated, but the parameter is
  unconstrained beyond factory registration" is the correct register.
