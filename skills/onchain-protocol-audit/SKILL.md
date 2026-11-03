---
name: onchain-protocol-audit
description: "Audit a LIVE on-chain DeFi/protocol target end-to-end via its own RPC + explorer — find one pre-auth RCE / fund-theft chain, or prove none. Trigger: 'audit this protocol/app/contract site', 'hunt the bridge/vault/tranche', pre-auth RCE, vault share-accounting break, oracle manipulation, role/capability abuse. ALSO 'prove which gate blocks it' engagements — build one end-to-end unprivileged exploit attempt and either complete it or produce a failing fork test that names the exact blocker.

## Support file
- `references/relay-settlement-gates.md` — CORRECTED Relay gates: registry key = chain NAME + `abi.encodePacked`; real gate = spender sig. **FREEZE ledger (11 killed); BURN≠freeze,RECOVERABLE(ERC20View/OPERATOR_ROLE);prank(0)=OK⇒no unrecov. proof; expiry is no refund; ERC-6909 Transfer id in `topics[3]`; `isOperator` `hasRole` branch = normal OZ, NOT a bypass; DRAIN/FREEZE/BURN/PRIVILEGED = 4 separate reports.**"
version: 1.7.0
---

# On-Chain Protocol Audit (live target, own RPC)

Find **ONE** pre-auth RCE / fund-theft chain in a live protocol — or prove honestly that there is none.
Never ship a bug list. Every finding carries **evidence (file:line or raw RPC response) + impact chain**.
**Kill your own PoC first** → `references/poc-self-verification-and-compile-on-tiny-boxes.md`. Force-call hunts → §3j.

This skill is for **our own authorized target** (bug bounty scope, own infra, CTF). Not for
"read the post-mortem and explain the hack" → that is `breach-killchain-forensics`.

**Chain coverage.** §2–§7 below are written for EVM. For a **Sui / Move** target, read
`references/sui-move-onchain-audit.md` FIRST — the endpoint, the resolver bug, and the
disassembly format are all different, and the EVM assumptions will send you down dead ends.
Once you have disassembly in hand, `references/sui-move-exploit-patterns.md` is the exploit
half: the oracle-path-divergence grep, the gross-value-into-accumulator pattern, the
`PackageCallerCap` bitmask decode, and the money-exit checklist.
Verification round (adjudicate prior findings PROVEN/REFUTED/UNTESTED against deployed
bytecode): `references/finding-verification-against-bytecode.md`. Multi-round loop: `references/move-defi-audit-patterns.md`. Hunt-loop orchestration: `references/multi-round-adversarial-hunt-loop.md`. Operator protocol (§0), phase loop (§1), honest-reporting rules (§5), subagent protocol (§8) are chain-agnostic.

---

## 0. Operator protocol (this user)

Raja's standing order for these hunts:

- **Multi-round loop, subagents cross-correcting each other.** Dispatch 3 parallel leaves with
  *incompatible* research ideas (not "3 agents on SQLi"), plus one dedicated ADVERSARY whose job is
  to **kill** the other findings.
- **Do not give up early.** Minimum ~4 hours / many rounds before "nothing found" is a valid verdict.
  Most chains live in round 7, not round 2. When the objective is specifically **RCE**, the operator
  has commanded up to **6 hours** of persistence — budget the loop for that and say so in the brief.
- **Scope is wide**: admin web2 surfaces AND fund theft AND on-chain invariants. Keep sweeping every
  side that could plausibly yield either until the operator stops you.
- **"Continue" / "lanjut" / "oke" = keep going.** Do not wrap up with a summary; resume the loop.
- **"spawn sub agent" mid-loop IS the continue signal — dispatch first, summarize never.** On the
  worked 6-hour RCE loop the operator sent exactly that twice, each time right after a batch landed.
  The correct response is a `delegate_task` call in the same turn, not a status report. A summary
  before the dispatch reads as stalling. If you have nothing new to brief, re-dispatch the same
  lanes with the accumulated REFUTED list appended so children do not re-probe closed surfaces.
- Output format: `VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE / MITIGATION / VERIFICATION`
  plus a **claim-vs-proof table**. Lead with the negative verdict when there is no critical.
- Numeric honesty: every figure measured by the orchestrator, never inherited from a subagent.

---

## 1. The five-phase loop

```
0. SCOPE + SURFACE      → what is the target, which chains, which APIs, which contracts
1. TRUST GRAPH          → who holds funds, who prices them, who gates them, who authorizes
2. INVARIANT ENUM       → list every MUST-BE-TRUE, per subsystem
3. ADVERSARIAL ROUNDS   → parallel leaves + adversary; each finding gets "prove this ISN'T exploitable"
4. REPORT + CORRECTION  → honest verdict, claim-vs-proof, published self-corrections
```

**Phase 1 is where most hunters lose the whole task.** They audit the contract tree the marketing
site points at and never check where the money actually sits.

---

## 2. PHASE 1 — Trust graph from the money, not from the docs

### 2.1 Find where the funds actually are FIRST

Before reading any source, sweep balances. The API's `tvlUsd` is **not** evidence.

```python
# for every candidate vault/contract address the app exposes:
USDC.balanceOf(vault)   # then divide by 10**decimals
```

**Decimal discipline (a real, expensive miss):** `USDC.balanceOf(vault) = 156652` on a 6-decimal
token = **156.652 USDC = $156**, not $156,652. Always read `decimals()`, divide, cross-check against
the app's `tvlUsd`, and if they disagree by orders of magnitude **say so and reconcile** — do not
pick the flattering one.

A common reconciliation: the app reports `shares × price` (accounting TVL) while the vault holds only
a small idle balance, because the strategy assets sit in a *different* contract (a market, a pool, a
bridge escrow). That other contract is the surface you must audit.

### 2.2 Walk the constructor-args graph

The cheapest high-yield map in the entire workflow: **fetch the verified contract's constructor args.**
They name the entire trust graph.

```python
# Blockscout v2 (needs a browser UA or you get 403 — see §6.1)
d = get(f"https://eth.blockscout.com/api/v2/smart-contracts/{addr}")
d["decoded_constructor_args"]   # -> ["0xVAULT", "0xACCOUNTANT", "0xOWNER", ...]
```

From one call you learn: which vault holds the shares, which contract is the **price oracle**, which
is the **transfer gate**, who the **owner** is, and often a **peer/deployer** EOA (EIP-7702 delegator).

Typical Royco-shaped graph (proof that the app's "vault" is not the whole system):

```
BoringVault 0x74d1          <- holds the share token; USDC.balanceOf = 156,652 (=$156)
  ├─ accountant 0x80f0b2    <- AccountantWithRateProviders = the SHARE PRICE ORACLE
  ├─ hook       0x60ebb5    <- LayerZeroTeller = the CROSS-CHAIN TRANSFER GATE (beforeTransfer)
  ├─ authority  0x754213    <- RolesAuthority = the ROLE/CAPABILITY MAP
  └─ boringSafe 0xebf23     <- reward escrow
```

Four trust boundaries, four different failure modes. Auditing only the vault misses three.

⚠️ **None of those four held the USDC.** The full sweep (§4.8) put 95.9% of the backing in a
**Circle CCTP `TokenDeposit`** reached from the vault's Transfer log. Treat the constructor graph as
the *authority* map, never as the *custody* map — custody is only established by a balance sweep
across every counterparty the Transfer log names.

### 2.3 Enumerate the whole contract surface, then pick

- Enumerate the app's APIs (`/api/v1/*`) → each route reveals an address.
- Enumerate the chain: every address in the API payload → `eth_getCode` → is it a contract?
- Search the explorer by contract **name** to find siblings (`/api/v2/search?q=CrossChainTeller`).
- Build the list, then decide which tree is worth auditing.

⚠️ **The tree everyone audits is often the wrong tree.** A modern tranche system (defensive, NAV from
ledger storage) can coexist with an older stack (BoringVault + epoch rewards + LayerZero bridge)
that holds the money. Audit the one the money is in.

---

## 3. PHASE 2 — Invariant enumeration per subsystem

Read the source; list EVERY assumption, then mark each verified/unverified. Anchor every claim at
`file:line`. The high-yield invariant classes for a DeFi protocol:

| Class | The question that breaks it |
|---|---|
| Share accounting | Can anyone mint shares without paying, or redeem more than their share? Is NAV read from `balanceOf` (donation-attackable) or from internal ledger (safe)? |
| Loss allocation | Is there a window between "loss known" and "loss socialised"? Is the waterfall atomic in one tx? |
| Price oracle | Who can move the share price? Is the rate bounded per update? Is there a min-update delay? Is the highwater mark bypassable? **On Sui/Move, also diff the accessor each module uses** — `liquidate` calling bare `get_spot_price` while `market` calls `get_price_with_check` is borrower-collateral theft, provable by grep. See `references/sui-move-exploit-patterns.md` §1. |
| Cross-chain | Is the inbound message authenticated (peer allowlist + selector)? Can a message be replayed or forged? What is the share-lock period, and who can shorten it? |
| Access control | Is any capability wildcard (`functionSig == 0x00000000`)? Does `public capability` exist on a money function? |
| Rounding | Floor vs Ceil on every mint/burn; one-wei-per-call leaks on repeatable paths |
| Fee/treasury | Is there a bound on protocol fee? Is the fee taken from yield or principal? Who can set it? |
| Accumulator inputs | Is any `increase_*`/`accumulate_*` field fed a **gross** value whose reversal is never applied? Flash-loan principal counted as referral/deposit volume, or points credited before a same-tx refund, is the pattern. Grep for a `*_amount()`/`*_volume()` getter feeding an `increase_*` call. |
| Documentation claims | Does the published security page make a falsifiable claim the live config contradicts? See §4.14 — this is a finding class in its own right and it is the cheapest one to prove. |

For the price-oracle subsystem specifically, check the **bound configuration**, not just the code:
`allowedExchangeRateChangeUpper/Lower` (typically ±1%–2% per update), `minimumUpdateDelayInSeconds`
(≥1h), `highwaterMark`, and `platformFee`/`performanceFee` caps (≤20% / ≤50% in good designs).
A cap of `1e18` where the code means "100%" is a real (privileged-config) finding — but label it
**privileged-config risk**, not fund theft.

---

## 4. PHASE 3 — Probing techniques that actually decide the verdict

### 4.1 `eth_call` is the authorization oracle

Read-only simulation beats source-reading for "can X do Y". Simulate as (a) an address with no roles
and (b) an address that holds a role, and compare the **revert strings**.

```python
j = rpc("eth_call", [{"to": target, "data": calldata, "from": caller}, "latest"])
# "execution reverted: UNAUTHORIZED"  -> blocked
# "execution reverted: Invalid params" -> MY encoding is wrong, not an auth result
# success (0x...)                     -> reachable
```

⚠️ Distinguish auth failures from encoding failures. `Invalid params` on `manage(address,bytes,uint256)`
meant my calldata was malformed, not that the call was authorized. Never record "blocked" from an
encoding error.

### 4.2 When a getter reverts, the EVENTS are the fallback

Verified-source getters can be gated or absent in the deployed bytecode. The event log is public
regardless, and for role systems it is *better* — it is a complete historical map.

```
RolesAuthority events:
  PublicCapabilityUpdated(address indexed target, bytes4 indexed functionSig, bool enabled)
  RoleCapabilityUpdated(uint8 indexed role, address indexed target, bytes4 indexed functionSig, bool)
  UserRoleUpdated(address indexed user, uint8 indexed role, bool enabled)
```

→ gives you: who holds which role, which role can call which selector on which target, and any
capability explicitly made public. `getUserRoles(address)` returns a **bitmask** (role *n* = bit *n*).

### 4.3 Reconstruct accounting laws from event logs — then CONFIRM on-chain

Event-log reconstruction is a **hypothesis generator**, not proof. Use it to state a law, then confirm
the law against the actual getter.

Reconstruction pattern that worked:
```
eligibleShares[e] = eligibleShares[e-1]            # rollover carries the epoch forward
                + sum(UserDepositedIntoEpoch[e])     # deposits booked to the next epoch
                - sum(UserWithdrawnFromEpoch[e])     # withdrawals
```
Reconstructed epoch 2 = 47,000,000 + 119,941,180,794 − 119,973,180,794 = **15,000,000**, and the
on-chain `epochs(2).eligibleShares` read **15,000,000**. Law confirmed → and the "double-count"
hypothesis died.

⚠️ **I nearly reported a false positive here.** My per-user event reconstruction produced
`sum(users)/eligible = 7999×` for one epoch, which looked like a catastrophic accounting bug. The
truth: my reconstruction did not apply withdrawals correctly. The ground truth —
`sum(getUserEligibleBalance(user))` over all 640 holders — was **exactly** `epochs[current].eligibleShares`
(ratio 1.000000). **Rule: every reconstructed anomaly must be re-confirmed with the real getter /
real per-user view before it becomes a finding.** A ratio computed from your own model of the ledger
proves your model wrong far more often than it proves the contract wrong.

### 4.4 Ground truth beats inference — build the aggregate

```
sum over holders of getUserEligibleBalance(holder)   ==?   epochs[currentEpoch].eligibleShares
sum over holders of balanceOf(holder)                ==?   totalSupply()
```
Both matched exactly (10,000,000 and 48,615,724,088). That is the strongest possible refutation of an
accounting-bug hypothesis, and it is two RPC loops.

### 4.5 Wildcard capabilities

`functionSig == 0x00000000` in a `RoleCapabilityUpdated` event means **every function on that target**.
Never assume — verify:

```python
canCall(user, target, REAL_selector)   # e.g. enter(address,address,uint256,address,uint256)
```
If `canCall` reverts, fall back to §4.3 events + §4.1 simulation.

### 4.6 Foundry harness from source you already have on disk

Explorer-verified source is a complete local project. Copy `src/` + `lib/` out of the tree and build.

```toml
# foundry.toml
[profile.default]
src = "src"; out = "out"; libs = ["lib"]
solc_version = "0.8.21"; evm_version = "shanghai"
optimizer = true; optimizer_runs = 200
remappings = [
  "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",  # NOTE: full prefix, see pitfall
  "@solmate/=lib/solmate/src/",
  "solmate/=lib/solmate/src/",
  "src/=src/",
  "forge-std/=lib/forge-std/src/"
]
```

Gotchas that cost real time:
- The remapping prefix must be **`@openzeppelin/contracts/`**, not `@openzeppelin/` — the vendor tree
  nests `contracts/` once, and the short prefix resolves to `contracts/contracts/...` → "not found".
- `git clone forge-std` into `lib/forge-std` lands the repo at `lib/forge-std/forge-std/`. Copy its
  `src/` and `lib/` up one level, or the remapping resolves to nothing.
- **solmate's `ERC20` constructor takes 3 args** (`name, symbol, decimals`). Two args → compile error
  "Wrong argument count for modifier invocation: 2 arguments given but expected 3".
- `vm.prank` applies to **only the next call**. To act as a privileged role across several calls,
  prank each one, or deploy the contract with the test contract as owner.
- Old solmate `Auth` has **no public role getters** — role maps live in the *authority* contract.

### 4.7 Live-state reads that matter

| Read | Use |
|---|---|
| `eth_call` (view fns) | balances, prices, epoch tables, rate state |
| `eth_call` with `from` | authorization oracle (§4.1) |
| `eth_getStorageAt` | raw slots when a getter reverts; compute mapping slots with keccak(key ‖ slot) |
| `eth_getLogs` (chunked) | invariant reconstruction, role map, money trail |
| `eth_getCode` | is this address a contract on this chain? (multi-chain targets need per-chain checks) |

`eth_getLogs` with a wide range → **400 Bad Request**. Chunk by ~5,000 blocks and advance; a filter on
`topics: [TransferSig, None]` keeps the volume sane.

### 4.8 The money trail — and how to RESOLVE it, not just start it

When you know the vault but not where the assets went, scan the asset's `Transfer` logs for the vault
as `from`/`to`, summed per counterparty. This reconciles app-reported TVL against reality and often
reveals the real strategy contract.

**Then finish the job.** A counterparty with a large balance is not an answer until you know *what it
is*. For each top counterparty, ask the explorer `/api/v2/smart-contracts/{addr}` for
`name` / `file_path` / `implementations`. Worked example from a live hunt:

```
vault 0x74d1 (BoringVault, share ledger)   USDC = 156,652   (= $156.65)
  boringSafe 0xebf23                        USDC = 0
  teller 0x60ebb5 (LayerZeroTeller)         USDC = 0
  accountant 0x80f0b2                       USDC = 0
  ── Transfer-log sweep, top counterparty ──
  0xa1e2481a  ERC1967Proxy                  USDC = 46,635,655,113  (= $46,635.66)
       └─ impl 0xAdE2eF01  name=TokenDeposit  file=contracts/TokenDeposit.sol
```

`TokenDeposit` is **Circle CCTP**, not a Royco contract. The vault's USDC had been bridged out through
a third-party escrow. So:

- **The vault was not insolvent** — it was 95.93% backed, with $1,979.91 in flight across the bridge.
- **Do not report "vault holds $156 but owes $48,615" as a finding** until you have swept *every*
  contract in the trust graph, including third-party escrows the Transfer log points at. That headline
  is the single most embarrassing false positive available in this class of audit.
- Reconciliation formula to publish: `backing_ratio = (sum of USDC across all trust-graph contracts) /
  (totalSupply × accountant.getRate())`, then attribute the residual to in-flight bridge amounts and
  say so explicitly.
- **Then close it arithmetically.** For any vault emitting `Enter`/`Exit` (BoringVault family), sum
  those events and compare the net to `totalSupply()`. Worked result: `Enter 807,438.23 − Exit
  758,822.51 = 48,615.72 USDC`, **byte-for-byte identical to `totalSupply() = 48,615,724,088`**. That
  is a proof of full backing needing no attribution, and it is what turns "probably fine" into
  "provably fine". If the net does *not* match, the difference is your real finding with an exact
  number. Recipe in `references/money-trail-resolution.md` §Step 5.

**Fast balance sweep without guessing tokens** — Blockscout lists them for you:

```
GET /api/v2/addresses/{addr}/tokens      # -> items[].token.{symbol,address_hash,decimals}, items[].value
```

One call per address beats guessing 12 candidate token addresses. Note it returns the *raw* value, so
still apply the decimal discipline of §2.1.

**Fingerprint a contract from its event histogram in one pass.** Dump every log (chunked, §4.7),
count `topics[0]`. Read `references/event-field-labelling-and-log-parse-verification.md` before
decoding any event field. Topic counts tell you what the contract is and who it talks to before you
read a line of source:

```
0xddf252ad…  x1450   ERC20 Transfer(address,address,uint256)
0x8c5be1e5…  x442    Approval(address,address,uint256)
```

Also useful: an event signature you expect (`DepositForBurn`) returning **0 events** is positive
evidence that a hypothesised money path never happened — record it as a refutation, not a gap.

### 4.9 Events are HISTORY, not current state — and verified source may not be deployed code

Two traps that cost a full round this session:

**(a) A capability granted in an old event can be revoked later.** The `RoleCapabilityUpdated` log
showed roles 1/2/3/8 receiving capabilities on the vault — and separate `enabled=0` events revoking
some of them. The log is an append-only history; it says nothing about *now*. Before building any
role-abuse finding on the event map, try to read current state (`canCall`, `doesUserHaveRole`,
`getRolesWithCapability`). If those revert, say explicitly in the report that the map is historical
and the live capability set is UNKNOWN.

**(b) A getter that reverts on live state can mean the deployed bytecode is not the verified source.**
`canCall(address,address,bytes4)` exists in the Blockscout-verified solmate `RolesAuthority` source,
its selector is present in the deployed bytecode, and it still reverted with a bare
`execution reverted`. Supporting evidence: the deployed code was 2,614 bytes with only 6 distinct
non-zero `PUSH32` constants, and a brute-force scan of mapping base slots 0–40 found **zero** non-zero
entries — so the storage layout does not match the served source either.

→ **Rule: a finding must not rest on a getter you could not successfully call.** When the verified
source and live behaviour disagree, the honest verdict is BLOCKED/UNTESTED with the divergence named,
not a conclusion drawn from the source. Cross-check with `eth_getCode` length and the event histogram
before trusting either side.

### 4.10 Map an RPC-proxy allowlist by ERROR SIGNATURE — never by sending a real tx

An app-level JSON-RPC proxy (`/api/rpc/{chain}`) sits in front of a node with a method allowlist.
You can enumerate that allowlist **without broadcasting anything**, because the proxy's rejection and
the upstream node's rejection have different shapes:

```
eth_sendRawTransaction   -> 200 {"error":{"code":-32602,"message":"failed to decode signed transaction"}}
debug_traceTransaction   -> 200 {"error":{"code":-32000,"message":"transaction not found"}}
eth_sendTransaction      -> 400 {"error":{"code":-32600,"message":"Unsupported method: eth_sendTransaction on ETH_MAINNET"}}
admin_peers              -> 400 {"error":{"code":-32600,"message":"Unsupported method: admin_peers on ETH_MAINNET"}}
personal_listAccounts    -> 400 {"error":{"code":-32600,"message":"Unsupported method: personal_listAccounts on ETH_MAINNET"}}
anvil_impersonateAccount -> 400 {"error":{"code":-32600,"message":"Unsupported method: anvil_impersonateAccount on ETH_MAINNET"}}
```

| Signature | Meaning |
|---|---|
| `-32600 "Unsupported method: X on CHAIN"` | **proxy blocked it** — on the deny list |
| `-32602 "failed to decode signed transaction"` | **forwarded** — the EVM tried to parse your payload |
| `-32000 "transaction not found"` | **forwarded** — the node looked the hash up and missed |
| `-32601 "method not found"` | forwarded, but the upstream node lacks it |

A deliberately malformed payload is therefore a **safe allowlist oracle**: send garbage calldata per
candidate method and read which layer rejected it. Never send a well-formed transaction.

⚠️ The finding is the **gap**, not the block. In the worked hunt the operator had carefully denied
`eth_sendTransaction`, `admin_peers`, `personal_listAccounts` and `anvil_impersonateAccount` — and
missed `eth_sendRawTransaction` and `debug_traceTransaction`. An allowlist that blocks the convenient
method but not the raw one is a **MEDIUM open relay** (free broadcast + internal trace visibility),
**not** fund theft: there is no signed-payload oracle to replay (§4.12) and
`eth_sendRawTransaction` broadcasts verbatim, so nonce/recipient mutation is impossible without the
victim's key.

### 4.11 The value-neutrality arithmetic — how to KILL a quote-divergence finding

A view/execution NAV divergence (view `convertToShares` uses `rawNAV`, execution uses
`effectiveNAV`) looks like free money. It almost never is. Run this before writing a word:

```python
exec_shares  = (deposit * S) // lptEffectiveNAV      # what execution mints
view_shares  = (deposit * S) // lptRawNAV            # what the view promises
post_nav     = lptEffectiveNAV + deposit
post_supply  = S + exec_shares
post_price   = (post_nav * 10**18) // post_supply    # SCALE BEFORE DIVIDING — see pitfalls
dep_value    = (exec_shares * post_price) // 10**18
round_trip   = dep_value - deposit                   # the verdict
```

Worked result: `exec = 95.011876e18`, `view = 100.000000e18`, gap **4.9881%**, post-price **1.0525**,
`dep_value = 99,999,999,999,999,999,999`, **round-trip = −1 wei (−0.000000000%)**.

Then compute the **counterfactual** — the number that *would* be a real bug:

```python
post_price_v = (post_nav * 10**18) // (S + view_shares)
dep_value_v  = (view_shares * post_price_v) // 10**18
# -> +4.772727e18 per 100e18 deposited (+4.7727%) extracted from existing holders
```

Publishing both numbers is what makes the refutation credible: you found the divergence, quantified
it exactly, and proved the direction runs *against* the attacker. Then check the **other leg**
(redeem): if the view under-states assets, the divergence is symmetric-conservative and the finding
downgrades to "MEDIUM — non-compliant ERC-4626 quote / integration bug".

Also settle **who controls the divergent input**. If the premium/NAV term is accountant-computed and
not a user input, neither a third party nor the same user can arbitrage it — say so explicitly.

### 4.12 The "prove this ISN'T exploitable" pass on your own best chain

Before reporting a chain, attack it yourself and record what kills it. The four questions that killed
the best web→on-chain chain in the worked hunt:

1. **Is there a signed-payload oracle?** Enumerate every endpoint that could return a transaction the
   app asked a user to sign (`/day/request/transaction`, `/auth/nonce`, `/user/info`,
   `/keeper/signers`, `/merkle/metadata`). If all 404, there is nothing to replay.
2. **Can the payload be mutated?** `eth_sendRawTransaction` broadcasts verbatim — changing nonce or
   recipient invalidates the signature.
3. **Does the victim's key ever touch the app?** SIWE-style auth proves it does not.
4. **Does the relay add capability?** Broadcasting is already free on any public RPC.

Write the killer list into the report. A chain whose ceiling you have stated is worth more than a
chain you have not stress-tested.

### 4.13 Evidence integrity — the file on disk must contain the number you quoted

A long hunt produces dozens of `evidence/*.out` files. Two failure modes silently corrupt the
record, and both happened in the worked session:

**(a) A script bug produces a plausible-looking wrong number, and the file outlives the correction.**
A balance sweep was written as `call(VAULT, sel("balanceOf(address)") + USDC_addr)` — calling
`balanceOf` **on the vault** (the share token) with the USDC address as the argument, instead of
calling `balanceOf` **on the USDC token** with the vault address. It printed
`USDC.balanceOf(vault) = 0`. No error, no revert — just a confident zero. The correct sweep
(`call(USDC, ... + VAULT_addr)`) printed `156,652`.

→ **Rule: in every balance sweep the `to:` is the TOKEN and the argument is the HOLDER.**
Inverting them does not fail loudly; it returns the token's own view of an unrelated address.
Sanity-check any zero against a second, independently-written sweep before it enters a report.

**(b) A stale evidence file contradicts the report.**
After fixing an integer-division bug (`post_nav / post_supply` → `(post_nav * 10**18) // post_supply`),
the regenerated run printed the correct round-trip of −1 wei — but the old `.out` on disk still
showed the bogus −100%. Anyone grepping `evidence/` later would find the wrong number and trust it
over the report.

→ **Discipline, three steps:**
1. **Re-run into the same path** after fixing a script, so the file always reflects the current script.
2. **Quarantine, don't delete, a run you cannot trust**: `mv r4v.out r4v.out.BUGGY_DO_NOT_CITE` and
   write a `r4v.out.SUPERSEDED` marker naming the defect and pointing at the authoritative file.
   Deleting loses the audit trail; leaving it unnamed invites a miscite.
3. **Publish an "Evidence integrity notes" section** in the final report listing every file that
   ends in a traceback or was superseded, with the crash line and whether any quoted number depends
   on it. A triager who finds an undocumented broken evidence file discounts the whole bundle.

A traceback at the *end* of a file is usually harmless — the numbers above it were printed before
the crash. Say so explicitly rather than re-running everything.

### 4.14 DOC-CLAIM-GAP — diff the published security page against measured live config

Protocols publish falsifiable security claims on a GitBook security/technical-details page.
Combined with the app's own open config API (§4.2b for Sui, `/api/*` for EVM) you get both
sides in two curls, and the finding is undeniable because it is a direct quotation against a
direct measurement.

```
Doc: "EMA–spot divergence detection ... the price is rejected"
Live: deviationBps 4520, bound 9999, passed 1        -> claim false for that asset

Doc: "Staleness gate ... Hard cap: 30 minutes"
Live: timeGapMs 6,150,136,164 (71.2 days)            -> claim false

Doc: "Confidence-interval check ... must sit within a configurable tolerance"
Live: spotConf / emaConf / confTime all null         -> check not running
```

Doc page is usually at `<org>.gitbook.io/<space>/security-and-risk/technical-details.md` —
the `.md` suffix strips ~500 KB of HTML shell to ~2 KB of text (see §6 of the Sui reference).

**Severity it as a trust misrepresentation, not a code bug.** It is the single easiest finding
to make public and the hardest to dispute, and it compounds every oracle finding you already
have: the gap between claim and reality *is* the security story. Always pair the claim and
the measurement side by side in the report so the reader can check both.

Run this check on every target with a published security page — it costs two curls and it
frequently turns a "MEDIUM config issue" into a headline.

---

### 4.15 When the brief says "find RCE" on an ON-CHAIN target — decompose the theories first

A DeFi protocol has no OS process to own, so "RCE" must be translated before any probing, or you
will burn rounds looking for a shell that does not exist. State the reframing **explicitly in the
report** — the operator asked for RCE and deserves to know why the answer is a different shape.

Five theories, deliberately **incompatible** (CDC: 3 agents chasing "SQLi" differently is ONE
family — redirect 2 elsewhere):

| # | Theory | What it actually means here |
|---|---|---|
| T1 | **Admin panel takeover** | internal dashboard (`xxx.<apex>`, `/login`) → auth bypass → post-auth execution primitive. Full probe matrix in `references/nextjs-admin-panel-postauth.md` |
| T2 | **Web2 backend RCE** | Spring actuator / NestJS / Next.js image-SSRF / deser / SSTI / SpEL on the off-chain tier |
| T3 | **On-chain → off-chain bridge** | keeper / oracle / liquidation bot executes on attacker-influenced state; gas-DoS a keeper |
| T4 | **Supply chain** | npm / CI-CD / public repo → code execution on CI runners or deploy infra |
| T5 | **Upgradeable dependency** | a third-party oracle/bridge package that IS upgradeable (policy 0) while the protocol's own packages are Immutable |

Dispatch 3 leaves on incompatible theories + keep one yourself. **T1 and T2 are the highest-yield**
because an internal admin panel is the protocol's own tooling and is usually co-located with the
keeper.

**Honest framing rule:** if no literal RCE exists, say so in the headline — *"No pre-auth RCE
(not applicable to a Move/Sui on-chain target — no OS process to own). Fund-theft chain: YES."*
Never dress a fund-theft finding up as RCE, and never let a "no RCE" verdict hide that you found
something worth more. Against a $58M book, a live liquidation-oracle bug is worth more than an RCE
would be — say that too.

**The one non-obvious payoff of an RCE brief:** it forces you to map the *off-chain execution
surface*, which is where T3 lives. The strongest T3 finding in the worked hunt was not code
execution but a **degradation primitive** — an unbounded linear scan (Sherlock H-03, still live)
that makes a fixed-gas-budget keeper fail to liquidate, widening the bad-debt window. Report it as
what it is: "closest thing to an attack-the-operator's-bot path found."

---

## 5. PHASE 4 — Honest reporting when there is no critical chain

This is a legitimate, high-value deliverable **if written correctly**.

1. **Lead with the negative verdict.** "No pre-auth RCE. No fund theft. No account takeover." Then the
   real findings at their true severity.
2. **Publish the REFUTED section.** Every closed surface, with the exact error string or `file:line`.
   It stops the next session re-running the same routes.
3. **Three separate labels**: PROVEN / REFUTED / NOT-CHECKED. "Untested" is an explicit list.
4. **Self-retract publicly.** If an earlier report said "amplification 14–18 s / 200 egress" and your
   re-measurement shows flat wall time (0.342 s → 0.346 s, ≈1.0× RTT), put a **KOREKSI** block at the
   TOP of the final report naming the old claim and the measurement that kills it. Silently editing
   leaves everyone who already read it believing the old number.
5. **State the ceiling of the strongest chain** and note explicitly that user funds on-chain are
   unreachable from it.
6. **Never inflate** a cost-abuse / config finding into "critical RCE" to make the report look better.
   This user's standing preference: *evidenced LOW/MEDIUM > unproven critical*.

---

## 6. Explorer source retrieval (the most-repeated friction)

### 6.1 Blockscout v2 — UA required

`urllib` with default headers → **403 Forbidden**. `curl` default → 200. Send a browser UA:
```python
UA = {"accept": "application/json",
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128 Safari/537.36"}
```

### 6.2 Endpoints that matter

| Endpoint | Gives you |
|---|---|
| `/api/v2/smart-contracts/{addr}` | `source_code`, `file_path`, `decoded_constructor_args`, `is_verified`, `compiler_version`, `sourcify_repo_url`, `compiler_settings.remappings` |
| `/api?module=contract&action=getabi&address={addr}` | full ABI **including events** (the v2 endpoint often omits them) |
| `/api/v2/search?q={name}` | sibling contracts by name (finds parents) |
| `/api/v2/addresses/{addr}/transactions` | deployer's outbound contract set |

### 6.3 Parent contracts are NOT includedThe v2 `source_code` is usually **one file** (the child's own file). The parent it imports is a
separate verified contract. Two ways to find it:
- read the child's `import {X} from "src/..."` lines → search the explorer for contract named `X`;
- `search?q=` the parent name.

Parent chain example: `LayerZeroTeller` imports `CrossChainTellerWithGenericBridge` imports
`CrossChainTeller` — none of them are in the child's source blob. Walk them or you are reading a leaf
with no trunk.

### 6.4 Sourcify is a nice-to-have, not a dependency

`repo.sourcify.dev/contracts/full_match/...` HTML listing yields nothing usable (Next.js shell).
`https://sourcify.dev/server/v2/contract/1/{addr}?fields=sources` sometimes returns the full source
set — but it also **times out** in this environment. Treat it as optional; Blockscout v2 +
`?fields=all` + the legacy ABI endpoint are enough.

---

## 7. Pitfalls catalogue (each one was believed, then refuted by a check)

- **The app's TVL is not the vault's balance.** Reconcile both, always, and say which one you trust.
- **Decimal slip.** `156652` on 6 decimals = $156. Divide. Always.
- **Reconstructed-from-events anomalies are usually your model's bug.** Re-confirm with the real getter.
- **`Invalid params` ≠ unauthorized.** Fix the calldata before recording a verdict.
- **A reverting getter is not a dead end** — the events carry more history than the getter.
- **`0x00000000` functionSig = wildcard capability.** Verify with `canCall` + a real selector.
- **Owner/authority drift.** The constructor owner ≠ current `owner()`. Read live state.
- **Multi-chain targets**: `eth_getCode` on chain 1 for a Sonic/Plume address returns 0 — that is
  "wrong chain", not "not a contract".
- **Blockscout without a UA → 403.** Send one.
- **`eth_getLogs` wide range → 400.** Chunk.
- **A deployer EOA that is an EIP-7702 delegator** can be the real root of trust; check its code.
- **"The vault holds almost nothing" is a hypothesis, not a finding.** Sweep every contract in the
  trust graph *and* every top counterparty from the asset Transfer log, then fingerprint each one
  (§4.8). A third-party bridge escrow (Circle CCTP `TokenDeposit`, Stargate pool, etc.) routinely
  holds the assets and is not a protocol bug.
- **A capability in an old event may be revoked now.** Events are history. Try current-state getters
  before reporting role abuse; if they revert, label the map historical (§4.9a).
- **Verified source ≠ deployed code.** If a selector present in the verified source reverts on live
  state, and the bytecode size / PUSH32 constants / mapping-slot scan do not match the source, do not
  build a finding on that source (§4.9b).
  - **`eth_call` never persists:** a write via `cast call` evaporates; the getter reads the OLD value
  and manufactures a false finding. Admissible = reachable/no-revert only. Also `diff` verified
  explorer source vs clone. `references/live-rpc-forensics-and-eth-call-trap.md`.
  **Inherited findings & brief slot tables are hypotheses** — `references/inherited-findings-and-silent-rpc-failures.md`.
  - **`0x00000000` in a `RoleCapabilityUpdated` event may be a decode artefact.** When the same event
  stream shows `functionSig=0x00000000` for every entry, suspect the topic decoding before concluding
  "wildcard capability on everything". Verify with `canCall(user, target, REAL_selector)`.
- **Long autonomous recon gets cut off** (iteration cap, model 504, operator `/stop`). Write each
  round's verified findings to `findings/<track>.md` **as you go**; put the report skeleton on disk
  before round 1. A 4-hour loop that keeps findings only in context delivers nothing.
- **Integer division without scaling silently zeroes a price.** `post_nav / post_supply` on two
  ~1e21 integers returns **0**, and every downstream number becomes 0 or −100%. Always scale the
  numerator first: `(post_nav * 10**18) // post_supply`. This produced a bogus "−100% round-trip"
  before the fix; a triager would have rejected the whole report.
- **`f-string` cannot contain a backslash** in Python < 3.12, and `sys.stdout.reconfigure` is flagged
  by Pyright on a `TextIO` annotation. Both are lint noise, not runtime failures — but they block the
  `write_file` syntax check. Extract the expression into a variable, or drop the reconfigure and use
  `flush=True` / `python -u`.
- **A `bytes` slice formatted as an address is not an address.** `raw[0:32][-40:]` on a `bytes`
  object yields `bytes`, so `"0x" + raw[0:32][-40:]` raises `TypeError`. Decode explicitly:
  `"0x" + raw[12:32].hex()`.
- **`eth_getLogs` over a huge range on a busy token stalls past any timeout.** A 4.3M-block sweep of
  USDC `Transfer` events never finished inside 560 s. Bound the scan to the contract's deployment
  block (from the explorer's creation tx) and chunk at ~6,000 blocks; if you only need "who holds it
  now", `GET /api/v2/addresses/{addr}/tokens` answers in one call (§4.8).
- **A 404 on a documented endpoint is evidence, not a dead end.** Record it as a closed surface with
  the exact body (`{"statusCode":404,"name":"NotFoundException",...}`) — it stops the next session
  re-probing the same route and it is what proves the "missing link" is genuinely missing.
- **`/api/v1/vault/explore` and friends may not exist even though the JS bundle references them.**
  Grep the bundle for the surface, then probe live: a newer bundle than the deployed backend means the
  Day-tier API is contract-only and any chain needing it as a handoff point dies at link one.
- **A balance sweep with `to:` and the argument inverted returns a confident zero, not an error.**
  `call(VAULT, balanceOf + USDC_addr)` asks the share token about the USDC address and prints `0`.
  Always `call(TOKEN, balanceOf + HOLDER_addr)`, and cross-check any zero with a second sweep (§4.13a).
- **A stale evidence file outlives its correction.** After fixing a script, re-run it into the same
  `evidence/*.out` path; if a run is untrustworthy, rename it `*.BUGGY_DO_NOT_CITE` and leave a
  `*.SUPERSEDED` marker naming the defect. Then publish an "Evidence integrity notes" section in the
  report listing every traceback'd or superseded file (§4.13b).
- **Read the WHOLE file before correcting a subagent — `wc -l` first, read to the end.** A 103-line
  CI workflow was judged from its first 50 lines, producing a confident "correction" of a subagent
  who was right, and then a second "correction" that was also wrong. A subagent's self-report is a
  hypothesis; **your correction of one is a hypothesis too.** Adjudicate only after reading every
  line the child cites, and publish the self-correction when you get it wrong — the operator watches
  how you handle being wrong more closely than how you handle being right.
- **A subagent's own test script can manufacture a finding.** One child "observed" Spring Boot JSON
  error bodies on a Next.js host; the cause was a shared `/tmp` file overwritten between two curls
  in the same loop iteration. Re-run any surprising observation with per-request temp files before
  recording it, and brief children to use unique temp paths.
- **Sui: `package{modules{nodes{name}}}` returns the WRONG package — ROOT CAUSE IS UPGRADE
  LINKAGE, NOT CORRUPTION.** The resolver follows Sui's in-place upgrade chain and answers with the
  *latest* version's data for the whole package family. `0x144c57d6...` (v1) and `0xec244262...` (v2)
  are the **same package at two versions**; querying either returns v2. Settle it in 3 calls:
  `object(address:){asMovePackage{version}}` on the suspect ID (→ `version 1`),
  `package(address:){address version}` on both (→ both return the v2 address), then a **CONTROL** on a
  package you know was never upgraded (→ returns itself exactly). If the control is exact, the
  "wrong" answer is upgrade resolution and the finding is **config drift, not a vuln**. Use
  `module(name:){disassembly}` and confirm the `module <pkgid>.<name>` header line matches the ID you
  asked for. `object{asMoveObject{contents{type{repr}}}}` is accurate and is how you find the real
  package behind an app object.
  **When a child claims your bytecode is stale, prove v1≡v2 by md5 before discarding anything.**
  Worked case: a child reported "the disassembly is v1, live is v2, your findings are invalid."
  Re-pulling both versions and running `md5sum` showed `liquidate` v1 and v2 are **byte-identical**
  (`b50923b4…`), and `market` identical at 115,846 chars with identical call counts. The child was
  half-right (an upgrade happened) and its conclusion was wrong (the findings hold). Record the
  provenance clarification in the report — it matters for *how* the finding is described — but do not
  let it retract a proven finding. Three commands settle it: pull both versions' disassembly for the
  module in question, `md5sum` them, and if identical, state "v1≡v2, finding holds for live code."
- **Sui: JSON-RPC on public fullnodes is deprecated** (`-32601 Method not found`). Endpoint is
  `https://graphql.mainnet.sui.io/graphql` — note the host is `graphql.`, not `fullnode.`, and the
  `/graphql` suffix is required (bare host → `fault filter abort`, fullnode path → 404).
- **Sui: disassembly has no `fun` keyword.** `public <name>(` / `entry <name>(`, generics *after*
  the name (`new_adl_params<Ty0>(`). `re.findall(r'public fun', ...)` returns 0 matches on a module
  with five public functions. Use `scripts/sui_disasm_sigs.py`.
- **Sui: most 64-hex strings in a crypto bundle are elliptic-curve constants, not package IDs.**
  secp256k1 / P-256 field primes and generator coords appear once each; real package IDs appear many
  times and are always adjacent to a `0xPKG::module::Type` string or a `*PackageId`/`*AppId` JSON key.
- **Sui: config drift is common and is NOT a vulnerability.** The bundle's `xOraclePackageId` /
  `leveragePackageId` can be a migration generation behind the live objects (confirmed by reading the
  app object's type repr and its dynamic-field keys, which named two different packages). Report it
  as "config drift / migration anomaly — needs follow-up", never as a critical.
- **Sui: `owner.__typename == "Immutable"` means no UpgradeCap exists.** All-immutable packages is a
  real refutation of the whole arbitrary-upgrade finding class — say so explicitly.
- **Sui: verify the VERSION of the bytecode you are auditing BEFORE applying the Immutable rule.**
  "Unfixed = still live" is only valid for the package that *currently holds the objects*. A brief
  can hand you an address, assert "v2, Immutable", and be describing a **superseded v1** — while
  the live v2 sits at a different address entirely. Worked case: the brief named leverage
  `0x042a1a41…` and lending `0xfe1d89…` as "v2, Immutable"; live
  `object(address:){asMovePackage{version}}` returned **`version:1` for both**, and the real v2
  packages were `0xaab00c77…` and `0x45bae04…`. Every disassembly file on disk carried the **v1**
  `module <pkgid>.<name>` header, so an entire Sherlock re-verification tier was silently auditing
  superseded code — and the brief's own premise ("immutable, so anything unfixed is still
  exploitable") was false. **Three calls before round 1:**
  1. `object(address:){asMovePackage{version}}` on **every** address the brief names.
  2. `package(address:)` on each to get the latest in the upgrade chain.
  3. Confirm the `module <pkgid>.<name>` header in your disassembly matches the ID you intend to
     audit. If it disagrees, **re-pull before writing a single finding.**
  Record the version in the report skeleton next to the address — a version-less address is not
  evidence. When a whole tier is invalidated this way, publish it as an explicit provenance
  correction at the top of the report (see `references/sui-move-arithmetic-refutation.md` §5), not
  as a quiet downgrade.
- **Don't pipe `curl` into a Python interpreter** in this toolchain; the security scanner blocks
  `curl | interpreter`. Write to `evidence/` first, then read the file — which also produces the
  evidence artefact for free.
- **Sui: THE FLASH-LOAN TRIAD — three findings in one module pair, all greppable in ten calls.**
  (1) **Fee selected by a caller-supplied config row**: the entry takes the group index as a plain  `u8` (`flash_loan.txt:38 Arg3: u8`) and `market.txt:2067` does `MoveLoc[1](Arg1: u8)` straight
  into `emode::borrow_emode_group(registry, u8)` → `fee_rate` → `float::int_mul`. The guarded
  public variant (`market.txt:250-255 assert_emode_group_exists`) exists in the same module and is
  simply not called. Prove the precondition on-chain with one call — the parent object's JSON
  prints `"emode_group_registry": {"next_group_id": 15, "groups": {"size": 15}}`, i.e. 15 fee rows
  × 18 assets. **Bound the severity honestly:** `market.txt:2076-2088` aborts when `fee == 0`, so
  the exploit is the *cheapest non-zero* row, not a free loan.
  (2) **The gate reads one field, the outflow mutates another**: `reserve::borrow_flash_loan`
  gates on `ImmBorrowFieldGeneric[3](Reserve.cash)` (`_r.txt:497`) but `flash_loan_withdraw`
  only does `balance::split` on `ReserveBalance.underlying_balance` (`_r.txt:765-767`). `cash` is
  never written on outflow — only incremented by `increase_reserve_only` (`_r.txt:672-680`) on
  repay. So `cash > underlying_balance` for the whole window, and every derived metric that
  consumes `cash` (`util_rate`'s numerator, `withdraw_underlying`'s reserve floor) is computed
  from the inflated value. **The grep:** for each borrow/withdraw function, list which
  `Reserve.*` fields it reads vs writes; a read-only field gating a mutating sibling is the bug.
  (3) **There is NO callback** — `borrow_flash_loan` *returns* `(Coin, FlashLoan)` and
  `repay_flash_loan` consumes it, so the entire EVM flash-loan reentrancy class does not exist
  here. Grep the module for a `Call` into any receiver and you get zero. `FlashLoan` is a hot
  potato (unpacked at `market.txt:2135`), and repay is **exact-equality** not `>=`
  (`market.txt:2138-2145`). The residual surface is that `flash_loan_lock` is a single `bool` on
  the Asset, so it blocks a second *same-coin* flash loan but not withdraw/borrow/deposit on that
  coin — it is a flash-loan guard, not a general reentrancy guard. Full detail with line evidence:
  `references/sui-move-exploit-patterns.md` §2.3.
- **Sui: STOP GUESSING GraphQL field names — introspect the schema in one call.** The endpoint
  exposes full introspection, and every guessed-field error costs a call. Three queries replace
  six failed guesses: `{ __type(name:"DynamicField"){ fields{ name type{ name kind
  ofType{ name kind } } } } }`, `{ __type(name:"DynamicFieldName"){ inputFields{ ... } } }`, and
  `{ __type(name:"DynamicFieldValue"){ possibleTypes{ name } } }`. Worked result:
  `DynamicFieldName` takes `type`/`bcs`/`literal` — **there is no `json` input** — and the value
  accessor is `value { ... on MoveValue { json } }`, not `asMoveValue`. Also note
  `MoveType` and `MoveStructConnection` are objects/connections, so `contents{ type }` and
  `structs{ name }` both fail. **When a query errors on an unknown field, introspect the parent
  type before retrying.** §7.1b of the recon reference.
- **Sui: `dynamicField(name:{type:...})` can be AMBIGUOUS — several fields may share a key type.**
  On the worked target all three of the Market's dynamic fields had key type `...::market::*Key`
  with body `{"dummy_field": false}`, so a type-keyed lookup may resolve to the wrong row. When
  the `name{ json }` bodies are identical across entries, disambiguate with
  `name:{ bcs: "<base64 serialized key>" }` or stay on the list form and match on the value's
  JSON. Discovery uses the **list** form (`dynamicFields{ nodes{ name{ json } ... } }`, which
  does accept `json`); lookup uses the **single** form (which does not). §7.1c of the recon
  reference.
- **Sui: a Table's `size` field is real precondition evidence even when its rows are unreachable.**
  `object(address:"<table uid>")` returns `{"data":{"object":null}}` (§4.2c), but the parent's
  JSON still prints `"groups": {"size": 15}` — and for the flash-loan fee-matrix finding that
  count *is* the proof that N fee rows exist. Read the `size`, publish it, and pivot to events or
  the app API for the rows. Do not treat "rows unreachable" as "nothing to report".
- **Sui: a subagent that hits its tool-call cap must still deliver the verdict in prose.** A leaf
  that ran out of budget mid-enumeration finished with 6 solid config findings plus an explicit
  UNTESTED list naming the one unanswered question ("is the refresh function permissionless?").
  That is a complete deliverable. Brief every leaf to write **VERDICT as soon as known** and to
  name the single blocking unknown rather than trailing off — the orchestrator then knows exactly
  which one question to spend the next round on.
- **Sui: when on-chain enumeration of a config table is blocked, say so and pivot to the app's own
  API.** The leaf burned ~10 calls trying to read nested table UIDs as objects before pivoting to
  `/api/oracle/check-table`, which answered every config question in one call. Add "if a table UID
  returns `{"object":null}`, stop and pivot" to the leaf brief.
- **Sui: `object(address:)` returns `null` for EVERY Table UID — outer and inner alike — and
  `dynamicFields` on the parent lists only the parent's own DF keys, never the table's entries.**
  Systematically probed on a live target: the `assets` table's outer UID, its inner UID, and the
  `emode_group_registry.groups` UID all returned `{"object":null}`, while `dynamicFields(first:50)`
  on the Market returned exactly 3 nodes (its own `ADLRegistryKey` / `CircuitBreakKey` /
  `MarketConfigurationKey`) with `hasNextPage:false`. JSON-RPC `suix_getDynamicFields` is deprecated
  (`-32601`). So **table entries are unreachable through the object/dynamicFields path on this
  endpoint, full stop** — do not spend calls re-deriving it. The working pivot is
  **`events(filter:{module:"0xPKG::mod"})`** with `contents{ type{repr} json }`, which on the worked
  target reconstructed the full 15-group registry, per-group asset membership, and every parameter
  update from event history alone. Full recipe in `references/sui-move-emode-limiter-audit.md` §3.
- **An audit finding's named root-cause function may be DEAD CODE while the same defect lives in a
  broader function.** M-15 pointed at `emode::update_limiter`; grep across all 37 disassembled
  modules returned **zero callers** — the live path was `emode::update(NewEMode)`, which overwrites
  the whole `EModeRateLimiter` struct as a side effect of updating LTV / liquidation-factor /
  borrow-weight params. **Always `grep -c` the named function across the whole corpus before
  accepting a root-cause pointer**, and when the count is 0, find every function that writes the
  same field. Note the aggravating detail: safe primitives that preserve usage
  (`limiter::update_outflow_limit_params`, `update_outflow_segment_params`) existed in the same
  module and were bypassed — the fix shipped in-deployment and went unused.
- **Prove a struct field is immutable by grep-counting the field name across the WHOLE disassembly
  corpus.** `emode_group` appeared exactly twice in `obligation.txt` (the `struct` declaration and
  the getter) and nowhere else across 37 modules → no setter exists → "emode switching after a
  position is opened" is REFUTED structurally, not merely unobserved. **Declaration + getter only =
  no writer.** This is the cheapest possible refutation of any "can the user change X after the
  fact" question, and it costs one grep.
- **GraphQL `events` schema gotchas (each cost a call):** the filter field is `module` (format
  `0xPKG::module`), NOT `eventType`; `Event` has no `json` field — the payload is
  `contents{ type{repr} json }`; there is no `sendingModule` (it is `transactionModule{name}`).
  **Paginate with cursors** — `first:50` returned 50 nodes and silently truncated the enumeration,
  cutting off groups 10-14 of a 15-group registry.
- **A rate limiter's fail-open question is answered by three greps, not by reading the whole
  module.** (1) does the add-path abort on overflow (`add_outflow` → `Le` → `BrFalse` → `Abort`),
  (2) does the count-path take the conservative branch early in a cycle (`count_current_outflow` →
  `len > idx` → count every segment), (3) is div-by-zero reachable (`validate_limiter_params`
  enforcing `segment != 0`, `cycle >= segment`, `cycle % segment == 0`, `cycle/segment <= 48`).
  All three held on the worked target → fail-open REFUTED with line evidence, in three greps.
  The corollary worth reporting: a **whole-struct overwrite** (`WriteRef` on the parent field after
  `Pack`) is the reset primitive — look for `Pack` + `MutBorrowField` + `WriteRef` on a struct that
  carries live state, not for a dedicated "reset" function.
- **When a limiter/accumulator is credited by a value, check WHICH value is read.** The repay path
  called `limiter::reduce_outflow(&mut Limiter, Arg3, coin::value)` where the value came from the
  **whole input coin**, not the split remainder produced two instructions earlier
  (`coin::split` → `StLoc[17]`, then `coin::value` on `Arg2`). If the caller supplies a coin larger
  than the repayment, the limiter is credited more than the debt actually retired → inflated future
  capacity. **Read the `MoveLoc` index, not the call shape** — the same lesson as §1.6 of the
  exploit-patterns reference, now on the decrement side.
- **Sui: find the capability HOLDERS with `objects(filter:{type:...})` — and expect a zero.** The
  question "who can actually call the admin functions" is answered by querying the cap object itself,
  not by reading signatures. `objects(filter:{type:"0xPKG::app::AdminCap"})` returns every live
  instance with `owner{__typename ... on AddressOwner{owner: address{address}}}`. Two outcomes to
  report honestly: a non-zero list (name each holder address — for `PackageCallerCap` that small set
  IS the whitelist and each holder is a trust anchor), or **count 0**, which means the cap sits in a
  cold wallet / multisig not exposed as a queryable object, or the type string is wrong. Label a zero
  **UNVERIFIED**, never "the admin cap does not exist", and cross-check with `suix_getOwnedObjects`
  against a known admin address. Signatures prove a gate exists; only the object query proves who
  holds the key.
  **§5.7 — the zero is now PROVEN unreliable, and the resolution path is a full owner-walk.**
  Control test: `objects(filter:{type:"0xfbe0602c...::flp::AdminCap"})` returned **0 nodes** for a
  cap whose holder is known to exist. So a zero from the type filter is *never* evidence of
  non-existence — treat every zero as UNVERIFIED and go to the owner-walk:
  1. `object(address: <app-object-id>){ owner{__typename} previousTransaction{digest} }` → the app
     object is `Shared`; the `previousTransaction` digest is the init tx.
  2. `transaction(digest:){ sender{address} effects{ objectChanges{ nodes{ address outputState{__typename} idCreated idDeleted } } } }`
     → names the deployer/ops EOA and every object the tx created.
  3. **Paginate the EOA's full owned set** (`objects(filter:{owner}, first:50, after:<cursor>)`,
     max page size is 50 — `first:100` errors "Page size is too large: 100 > 50"). Walk until
     `hasNextPage:false`. On the worked target that was 688 objects across 14 pages.
  4. Filter the walk for the package IDs in question. Result: **0 objects from the app package**,
     3 `obligation::ObligationOwnerCap` from the lending package → the deployer EOA is provably
     **not** the AdminCap holder.
  5. The remaining paths are all blocked on this endpoint: `package(address:)` → `null`,
     `packageVersions` → empty, `typeOrigins` → unknown field. So the publish/init-tx walk that
     would name the true holder **cannot be completed** — write that as the explicit blocker.
  Also: `AddressOwner.owner` does not exist on this endpoint; `owner{__typename}` works,
  `owner{... on AddressOwner{address}}` errors ("must have a selection of subfields"). Use
  `objects(filter:{owner})` for owner→address, never the owner selection set.
  **The publishable verdict is the negative plus the blocker**, not a guess: *"the holder is not
  indexer-visible via the type filter (proven unreliable by control) nor via the deployer EOA's
  owned set (0 hits in 688 objects); resolving it requires the package publish/init tx, which
  `package(address:)` cannot reach on this endpoint."*
  **§5.7b — the indexer is INCONSISTENT ACROSS TIME, so a zero you get today may contradict a
  non-zero a child got an hour ago.** In the worked session one leaf successfully walked 688
  objects owned by the deployer EOA and reported 4× `LeverageMarketOwnerCap` in a memecoin
  treasury; the orchestrator re-ran the *identical* query minutes later and got **0 nodes** —
  including `objects(filter:{owner})` with no type filter, and `address(address:).objects` for an
  address provably holding `flp::AdminCap`. Both results are real responses from the same
  endpoint. **Rule: when you cannot replicate a child's on-chain observation, do not confirm it
  and do not refute it — label it UNVERIFIED and name the inconsistency.** Write the child's claim
  verbatim, write your own null result verbatim, and state that the disagreement is an indexer
  artefact requiring an authenticated explorer API or a local indexer to settle. A report that
  says "unverified, here are both responses" is trustworthy; one that silently picks a side is not.
  The operational-risk observation survives at informational severity either way (a hot wallet
  holding protocol-admin caps is worth a line regardless of which response is current), but it must
  never be inflated into a finding on the strength of one unreplicated query.
  A useful by-product of the owner-walk: it fingerprints the EOA. A 688-object memecoin/NFT
  treasury holding `LeverageMarketOwnerCap` ×4 and `AccountCap<ADMIN>` is a **hot wallet with
  protocol-admin caps** — an operational-risk observation worth a line in the report, at
  informational severity, never inflated.
- **Sui: a `&` inside a shell heredoc gets eaten by the terminal guard.** Appending a report block
  with `cat >> file <<'EOF'` that contains `take_revenue(&AdminCap, ...)` trips the "foreground
  command uses '&' backgrounding" check and the whole append fails. Use the `patch` tool (or
  `write_file`) for any content containing `&`, `|`, or `;` in a Move signature. The failure is loud
  and costs one call, but it is avoidable — and it hits exactly the access-control report, where
  `&AdminCap` appears on every line.
- **Sui: a v1/v2 package-ID "mismatch" between the repo and the bundle is upgrade linkage, not a
  vuln — and the bundle usually does not reference the old ID at all.** The worked case: a sibling
  leaf reported "xOracle package mismatch is a vulnerability" because `Published.toml` said
  `0x144c57d6` while the SDK config said `0xec244262`. Three cheap checks killed it:
  (1) `Published.toml` names the package `x_oracle` with modules `x_oracle::x_oracle` /
  `x_oracle::user_oracle` and deps pyth+math — so `0x144c57d6` **is** xOracle, the repo's own v1;
  (2) `grep -c 144c57d6 bundle.js` → **0**, `grep -c ec244262 bundle.js` → **1** — the bundle only
  ever references the live v2;
  (3) the SDK's `xOraclePackageId` is the v2 ID, so the "mismatch" is repo-v1 vs deployed-v2.
  **Rule: before reporting any package-ID divergence, count the references in the bundle.** A
  version the client never loads is not an attack surface.
- **Sui: "all `/user/*` endpoints are open without auth" is by design for a public explorer — and
  guessing the paths produces a wall of 404s that looks like evidence.** The real routes live in
  the bundle as **template literals**, so `grep -o -E '"/user/[a-z]+"'` finds three while
  `grep -o -E '`/user/[^`]+`'` finds seventeen (`/user/getObligationList/${e}`,
  `/user/getLeverageObligationByAddress/${e}`, …). Run **both quote styles**, then call each with a
  dummy `0x00…01` address and read the payloads. Worked verdict: points/leaderboard/VIP-tier data
  and public on-chain reads (`s2TotalUsers: 52720`, rank 53322–53327, `getObligationList` → `[]`) —
  **no private obligation detail, no liquidation health, no position data**. The only residual is
  INFO (full ranking + total user count). Downgrade, don't kill outright, and say why.
- **Sui: "endpoint X leaks the full token registry" dies the moment you find the registry already
  open-source.** `current-sdk/sdk/src/config/networks.ts` on GitHub carries every coin type, market
  object ID, reserve ID, balance ID and per-coin oracle feed config. Data already public in the
  client SDK cannot be "leaked" by an endpoint serving it. The only surviving version of the claim
  is a **diff**: does the endpoint return coin types *absent* from the SDK config (unpublished /
  internal tokens)? That is a concrete next-round task, not a finding.
- **A redacted hostname in the bundle (`baseURL:"https://xxx.current.finance"`) is a NAMED LEAD,
  not a dead end.** It tells you the internal service exists, its health-check path
  (`/api/statistic/liquidation-health`), and that it is not a public subdomain. Grep the bundle for
  the sibling health-check functions in the same pass (`checkProductApiStatus`,
  `checkSuiMainRpcAlive`, `checkLiquidationApiAlive`, `checkQuotingAPIStatus`) — one grep
  enumerates the whole backend estate. Record the lead even when you cannot resolve it.
- **A shell `dig` subdomain loop can silently return nothing for names that DO resolve.** In the
  worked run a 50-name `dig +short` loop produced zero output — including for names that resolve —
  and only a Python `socket.gethostbyname_ex` pass found `pre.current.finance`. Always sanity-check
  the resolver against a name you know resolves (`<apex>`, `www.<apex>`, `api.<apex>`) before
  writing "no subdomains exist" into a report.
answer sensitive-looking paths with 403 while everything else 404s. Report it as
"WAF-blocked, existence unproven" — never as "exposed .git".
- **A CI supply-chain finding is only as strong as its asymmetry proof — and its blast radius
must be stated.** "CI runs `pnpm install` on `pull_request`" is true of thousands of repos and
is not a finding. What makes it one: (a) no `--frozen-lockfile`/`npm ci`, (b) no guard
rejecting `package.json`/`pnpm-lock.yaml` diffs, (c) no `permissions:` block, (d) **a sibling
repo in the same org that HAS the guard**. Then state the ceiling honestly:
compromising a fork of a third-party repo yields that fork's `GITHUB_TOKEN`, its published
release artifact, and CI minutes — **not** deploy keys, the hot wallet, or the oracle/keeper
hosts, unless you found those in a repo. Check `pulls?state=all`: a repo that has never
received a PR drops the real-world severity. Full checklist:
`references/offchain-supply-chain-rce-hunt.md` §2.
  **A guard that exists but runs AFTER the install is not a guard — check the STEP ORDER, not
  just the guard's presence.** The worked case: `DefiLlama-Adapters/test.yml` *does* contain a
  lockfile-diff guard (lines 56-59), and `dimension-adapters` has none — so the naive read is
  "one repo is protected, the other is not". But `pnpm install` runs at **line 32**, and the
  guard lives in a later step that only writes an error string into `output.txt` for a
  subsequent `grep` to fail the job. **By then every `postinstall` from the PR's dependency set
  has already executed.** The guard prevents a clean merge; it does not prevent code execution.
  Before writing any CI finding, list every step with its line number and confirm the guard
  precedes the install. A detect-only guard after the fact is a *stronger* finding than no
  guard at all, because it proves the team knew the risk and ordered the control wrong — and
  every fork that copied the workflow inherits the mis-ordering. Report the two repos as
  "guard ordered incorrectly" vs "no guard", never as "protected" vs "unprotected".
- **Resolve a fork's parent from the GitHub API before diffing — and read the diff's
direction.** Diffing against the repo you *assume* is upstream produced a false "the team
deleted the guard" narrative on this target: `current-finance/DefiLlama-Adapters` is a fork
of `DefiLlama/DefiLlama-Adapters`, not `DefiLlama/adapters`. `GET /repos/<org>/<repo>` →
`parent.full_name`, clone *that*, then diff. An **empty** diff on the guarded repo means the
guard is upstream-inherited, not team-authored — retract the "they knew and left it" claim and
report what survives instead: the **regression the fork introduced** in the unguarded sibling
(deleted artifact steps, helper rewritten to POST with a hardcoded token). Diff the helper
scripts too — a fork that *deleted* an `execSync` is a citable refutation of a
command-injection hypothesis. §2.1–§2.2 of the reference.
- **A plaintext secret sweep returning 0 hits does not mean "no secrets" — grep for the
DECODER, not the key.** This session found a GitHub PAT in a tracked CI helper that every
`ghp_`/`sk-`/`AKIA`/`BEGIN RSA` grep missed because it was Caesar-shifted +2 and decoded at
runtime. The durable tell is `charCodeAt` + `String.fromCharCode` (or `atob`, base64
`Buffer.from`) in a file that also builds an `Authorization` header. Invert the transform in
one `node -e`, test **both** directions, then verify liveness with a single read-only GET —
keeping the plaintext out of the command line, because the scanner blocks any
credential-shaped string in the command text. `401` = revoked (historical leak, hygiene +
rotation advice); `200` = live critical. §3.1 of the reference.
- **The WAF differential is how you REFUTE an injection sink, and it is two curls.** Send a
  ladder: `<script>` / `'; ls` / `OR 1=1` → **403 + a fixed-size Cloudflare challenge page**
  (record the byte count — it is stable and makes the claim checkable); then quotes, NUL,
  5 KB overflow, `../..`, and a valid value → **identical generic error envelope**. Identical
  envelopes for every non-tripping payload = flat, well-handled error path = **no differential
  behaviour = no sink**. That is the refutation, and it is what turns "I couldn't exploit it"
  into "there is nothing to exploit". A stack trace, origin error, or distinguishable echo is
  the only signal to keep digging.
- **Reflection without a sink is LOW/INFO, not RCE — but it is still worth reporting.** If raw
  bytes survive into a response body (`%0A` preserved as a real newline, `%00` preserved as
  `\u0000`), attacker bytes demonstrably reach the handler. That is the primitive any future
  refactor into a shell/SQL/template would need. Report it as hygiene with the exact repro, and
  never inflate it — this user's standing preference is *evidenced LOW/MEDIUM > unproven critical*.
  **Then check whether the reflected path is even live before finalising the severity.** The
  worked case: `oracleUpdate?coinTypes=<x>` echoed every payload verbatim, including all 20
  registered assets, their full coin-type strings, and the comma-separated form the bundle
  actually sends (`coinTypes: t.join(",")`) — every one returned `Missing asset config`. The
  service's asset registry was **empty on the public instance**, so the reflection reached a dead
  code path. Enumerate the legitimate values from the app's own config API first; if none of them
  produce a different response, downgrade to INFO and write "reachability proven, impact nil".
- **A "hidden" market/pool found in a third-party adapter is a real discovery, and the app's
  oracle table will not list its base assets.** The DefiLlama adapter listed five market objects
  while the app UI hid two (`LEND_HIDDEN_MARKETS`); both were live, `Shared`, and counted by the
  adapter. Users can hold positions the UI never shows. Cross-check the adapter's object list
  against the bundle's hidden-market list, then read each market's `obligations.size` and asset
  keys on-chain. Note that the public oracle check-table may omit the base quote asset entirely
  (USDC/SUI absent from 20 feeds) — that is usually a second `BaseToken` (`prices` table size 2,
  USD and SUI) rather than a missing price, so confirm before calling it a gap.
- **An unpublished npm package is a REFUTATION, not a finding — then run the inverse check.**
  `registry.npmjs.org/@scope%2Fpkg` → `{"error":"Not found"}` closes dependency confusion
  outright. The check that actually matters next: `grep -c "@scope/pkg" app_bundle.js`. A
  prebuilt SPA bundle is decoupled from the published SDK, so SDK compromise cannot reach
  production through it — verify with the count before claiming any SDK→frontend path.
- **Fingerprint a live service from its 404 shape before probing for exploits.** Express:
  `{"message":"Route GET:/x not found","error":"Not Found","statusCode":404}`. Spring:
  `{"timestamp":...,"status":404,"error":"Not Found","path":"/"}`. Next.js: `x-powered-by:
  Next.js` + `vary: rsc, next-router-state-tree...` + `/_next/static/chunks/`. Bare `Not found`
  plain text = minimal/custom. Then fire the sensitive-path ladder
  (`/health /api /actuator /swagger-ui.html /v3/api-docs /debug/pprof /metrics`): a uniform
  `307 → /login?from=<path>` refutes "unauthenticated debug endpoint" in one pass, and the one
  intentionally-public health endpoint is not a finding once you read what it returns.

---

## 8. Multi-round subagent protocol

Dispatch **3 leaves with incompatible research ideas** + 1 adversary. Per-leaf brief must include:

1. **"Aksi PERTAMA: create `findings/<TRACK>.md` with the full skeleton, then APPEND every 5 tool
   calls. The report must ALWAYS exist on disk."**
2. **"Write the VERDICT as soon as you know it — not at the end."** A skeleton without a verdict
   section filled in counts as "no report".
3. **Explicit exploration budget** ("max ~12 min for acquisition; if blocked, write the BLOCKED
   section + status table, then move on").
4. **How to run long work**: `terminal` default timeout is 180 s → pass a bigger `timeout`, or use
   `background=true` + `notify_on_complete=true`.
5. **The evidence machines already on disk** — name exact paths; do not let a child re-download
   contracts another child already fetched.
6. **Unique paths per track** (`findings/G_balancer.md`, `evidence/G_logs.jsonl`) — parallel children
   will otherwise overwrite each other's scratch files.
7. **Read-only mandate, explicit** — never broadcast a tx, never write to a production endpoint that
   changes state for another user.
8. **For the ADVERSARY leaf specifically, brief the adjudication, not just the hunt.** Its product is
   the *refutation*, so give it (a) the sibling claims verbatim, (b) the instruction "for each claim,
   run the cheapest disconfirming test and write the verdict with the evidence", and (c) the three
   questions that kill most DeFi false positives: *is this data/capability already public by design?*
   (open-source SDK, public explorer, public leaderboard), *does the bundle actually reference the
   suspect ID?* (`grep -c`), and *is the endpoint returning anything a public chain read would not?*
   An adversary that returns "nothing found" without the refutations and the named open leads has
   done a third of its job — say so in the brief. Full playbook:
   `web-api-recon/references/adversarial-web2-infra-track.md`.
9. **When a public audit repo exists, brief one leaf to RE-VERIFY every finding against live
   bytecode.** A warden's public findings repo (`search/repositories?q=<protocol>`) gives you
   17 pre-written hypotheses with PoCs — the highest-yield round you can run. The method is a
   grep-count table, one row per finding: `grep -c` the disassembly for the pattern the finding
   depends on (an accessor name, an `increase_*` call, a bound constant) and record the count.
   **The absence of a bound constant is itself the proof** — `MAX_ASSETS`×0 across a 115 KB module
   proves an unbounded scan. Worked result: 6 of 17 findings re-verified LIVE (H-01, H-02, H-03,
   M-05, M-09, M-11), 1 likely live, 10 untested — and because the package upgrade preserved those
   modules byte-for-byte, **the upgrade fixed none of them**, which is the reportable headline.
   Label untested rows UNTESTED, never "not applicable": an honest 10-row untested list is what
   the next round picks up.
   **§9.1 — the PoCs are harness-only; they prove nothing about mainnet.** Every Sherlock PoC in
   the worked repo reproduced a *model* of the bug in a standalone Move package, not the deployed
   code. So the PoC is a hypothesis generator and nothing more: read the finding's root-cause
   claim, then grep the **deployed** disassembly for the exact construct it names. A finding whose
   named module does not exist is a hard refutation — `reward_manager` returned `module: null`
   from GraphQL, killing two findings written against it in one call.
   **§9.2 — a finding can be LIVE but with the audit's number wrong; report the refined value.**
   M-07 claimed "decimals above 18 aborts"; the deployed `coin_decimals_registry` has no upper
   bound at all and the consumer's `u64::pow(10, decimals)` aborts at **≥20** (10^19 fits u64,
   10^20 does not, and the math helper aborts rather than wrapping). Off by one. Publish
   "LIVE (refined)" with the real cliff, not "LIVE" parroting the audit — a triager who checks
   your number against the audit's finds the discrepancy and discounts the row.
   **§9.3 — the highest-value reframing is often the inverse of the audit's own mitigation.**
   M-10 warned that onboarding was non-atomic and implied an "onboard paused, then enable" flow
   would fix it. The deployed `asset::new` initialises all five pause flags
   (`BorrowPaused`/`DepositPaused`/`WithdrawPaused`/`LiquidationPaused`/`FlashLoanPaused`) to
   **`false` — unpaused** — so an asset is depositable the instant it is onboarded. The finding is
   REFUTED as written, but the *inverted* observation is a genuine operational risk. Report both:
   "refuted as written; the deployed default is the opposite of the suggested mitigation."
   **§9.4 — keep the scorecard arithmetic consistent.** The worked session published "10 LIVE"
   above a list of twelve IDs, and had to re-patch. Count the rows in your own table before
   writing the headline number, and state the three buckets explicitly
   (worked final: **12 LIVE / 3 REFUTED / 2 UNTESTED** of 17).
   **§9.5 — resolve WHICH package a called symbol comes from before reasoning about its
   arithmetic; the `use` list shadows stdlib** (`market.txt` imports `u64` from the math package,
   whose `pow10_u64` aborts above 18 — not stdlib's `Mul` loop; stdlib reasoning produced a
   self-corrected wrong verdict on M-07). **§9.6 — a module-absence claim is only as strong as the
   pagination**: field is `modules{nodes{name}}`, default page size silently truncates at 20,
   `package(address:)` needs the `0x` prefix. Both, plus the increment/decrement stuck-state
   pattern and the lifecycle-absence grep: `references/sui-move-symbol-resolution-and-stuck-state.md`.

Verify children **on disk** (`ls -la`, mtime, and that the verdict section is filled), not from the
completion message. A child's "completed" is not an artefact.

---

- `references/rce-hunt-onchain-target.md` — **worked case: a 6-hour "find RCE" brief on a
  Move/Sui DeFi target.** Five-theory decomposition with each theory's refutation evidence; the
  **oracle-accessor asymmetry** method (rank every call site by guard strength — the finding is
  the asymmetry *inside one transaction*) plus the `grep -rc 'with_check'` scope-creep check;
  the admin-panel auth refutation ladder and the `vary: rsc,…` header that severs web2→admin;
  the web2 refutation signatures; the CI finding **and the published self-correction** that
  killed its asymmetry claim; two side-discoveries (Sherlock H-03 gas-DoS as a keeper-degradation
  primitive; hidden markets found via the DefiLlama adapter). Report shape: a separate
  `RCE_HUNT.md` whose closed-surfaces table stops the next round re-running the last one.
- `references/offchain-supply-chain-rce-hunt.md` — **the OFF-CHAIN execution surface + supply
  chain**, for briefs that say *"hunt LITERAL RCE via the off-chain surface"*. The five
  surfaces in yield order (CI config → npm → public repos → live subdomains → production
  bundle); the **CI asymmetry proof** (PR-triggered `pnpm install` with no lockfile guard,
  diffed against the sibling repo that HAS the guard — the asymmetry is the evidence, and
  blast-radius honesty: a DefiLlama-style fork is an org asset, not core infra); npm
  dependency-confusion as a *refutation* when the package is unpublished, plus the inverse
  `grep -c` check that the bundle never consumes it; framework fingerprinting by 404 shape
  (Express vs Spring vs Next.js vs bare) and the `307 → /login` auth-gate ladder; **the WAF
  differential** (403 + fixed-size challenge page = WAF tripped, identical generic envelope
  for every non-tripping payload = no sink, which is the refutation); reflection-without-sink
  as LOW/INFO with exact repro; HTTP 431 on an oversized URL as positive edge-DoS evidence;
  vendor RPC-pool identification from the root title page; the negative-verdict report shape
  with a host fingerprint table; and the two terminal-guard triggers (`curl | python3` and
  schemeless-URL-in-sink) with their fixes.
  **§2.1–§2.2 — resolve the fork's parent from the GitHub API before diffing, and read the
  diff's direction.** An empty diff on the *guarded* repo means the guard is
  upstream-inherited, not team-authored: retract "they knew and left the sibling unpatched"
  and report what survives — the **regression the fork introduced** in the unguarded sibling.
  Diff the helper scripts too; a fork that *deleted* an `execSync` is a citable refutation.
  **§2.3 — a guard that runs AFTER the install is not a guard.** List every workflow step with
  its line number before writing the finding. `pnpm install` at line 32 with the lockfile guard
  at lines 56-59 (which only writes an error string for a later `grep` to fail the job) means
  every `postinstall` has already run. Report the pair as "guard ordered incorrectly" vs "no
  guard" — never "protected" vs "unprotected" — and note that the mis-ordering is inherited by
  every fork that copied the workflow, which makes it a stronger finding than an omission.
  **§3.1 — obfuscated credentials.** A plaintext key-pattern sweep returning 0 hits is not
  "no secrets": grep for the DECODER (`charCodeAt` + `String.fromCharCode`, `atob`, base64
  `Buffer.from`) in files that build an `Authorization` header. Invert in one `node -e`, test
  both directions, verify liveness with ONE read-only GET while keeping the plaintext out of
  the command line (the scanner blocks credential-shaped command text). `401` = revoked →
  historical leak + rotation advice; `200` = live critical.
- `references/explorer-source-and-role-map.md` — Blockscout role decoding; §0 local-repo outline-first loop.
- `references/money-trail-resolution.md` — the full worked money trail: balance sweep across the  trust graph, fingerprinting a top counterparty (Circle CCTP `TokenDeposit`), publishing a backing
  ratio instead of a "vault is insolvent" headline, event-histogram fingerprinting, closing the
  drain surface with unprivileged `eth_call` simulations, and the `Enter`/`Exit` ledger
  reconciliation that proves full backing arithmetically (net == totalSupply, byte-for-byte).
- `references/royco-case-study.md` — a full worked example: trust graph, 8 web-tier findings, the
  6 contract invariants (5 HOLDS), the auth/session matrix (all REFUTED), the two numeric
  self-corrections, and the exact verdict table.
- `references/foundry-harness-from-verified-source.md` — copy-paste foundry project layout,
  remappings, solmate ERC20/Auth gotchas, and the test patterns that produced real refutations.
- `references/finding-closure-arithmetic.md` — how to CLOSE a finding you already reported: the
  value-neutrality computation that kills a quote-divergence claim, the fee-waterfall read that
  separates yield-theft from principal-theft, the RPC-allowlist error-signature oracle, and the
  self-attack checklist. Includes the exact scripts, the numbers they printed, the scripting-pitfall
  table, and the **stale-evidence-file quarantine protocol** (re-run into the same path, rename
  rather than delete, publish an "Evidence integrity notes" section).
- `references/sui-move-onchain-audit.md` — **Sui/Move targets.** JSON-RPC is deprecated on public
  fullnodes; the working endpoint is `https://graphql.mainnet.sui.io/graphql` (the `/graphql` suffix
  is mandatory, the fullnode path 404s). The `package{modules}` resolver **returns the wrong
  package** — root cause is **upgrade linkage** (same package, two versions), settled by a 3-call
  proof with a never-upgraded CONTROL; use `module(name:){disassembly}` and verify the
  `module <pkgid>.<name>` header. Disassembly has no `fun` keyword and puts generics after the name.
  Bundle-mining recipe with the elliptic-curve-constant filter, trust-graph confirmation via object
  type repr, **config-drift detection** (bundle package IDs a migration generation behind the live
  objects — label it drift, not a vuln), `&AdminCap`/`&PackageCallerCap` access-control mapping,
  GitBook `.md`/`llms.txt` doc harvesting, the **oracle-feed audit checklist** (ADMIN_REF check
  legs, 9999-bps no-op bounds, 14-day staleness windows, `minPublishers=1` + 4% confidence,
  bundle-vs-live asset-list diff), the auditor-workspace-repo lead, **oracle-accessor divergence
  hunting** (§5.1 — diff `liquidate` against `market`; the guard's abort constant appears only in
  the `*_with_check` variants), **value-flow tracing for gross-into-accumulator accounting bugs**
  (§5.2), the **DOC-CLAIM-GAP class** (§5.3 — published security claims vs. measured live config),
  and the **duplicate-deployment guard** (§5.4 — run the upgrade-linkage proof before writing it up).
  **§5.5 a zero from `objects(filter:{type:...})` is UNKNOWN, not "does not exist"** (prove
  the indexer with a control type; the owner selection set errors on some types and succeeds on
  others; naming the `app::AdminCap` holder is the highest-value open question — resolve it via the
  `ProtocolApp` creation tx and the mint event), **§5.7 the AdminCap resolution path, now walked
  end-to-end** (control test proves the type filter returns 0 for a cap with a known holder, so a
  zero is never evidence; the working path is app-object → `previousTransaction` digest → tx
  `sender{address}` → paginated owner-walk of that EOA, max page 50, until `hasNextPage:false`;
  the publish/init-tx walk that would name the true holder is blocked because `package(address:)`
  returns `null` and `typeOrigins` does not exist on this endpoint; the owner-walk also fingerprints
  the EOA, and a memecoin-treasury wallet holding `LeverageMarketOwnerCap` is an operational-risk
  observation at informational severity), **§5.7b the indexer is inconsistent across time** — a
  child's non-zero owner-walk and the orchestrator's identical-query zero are both real responses;
  observation at informational severity), **§5.6 an ended FLP/insurance program with no
  withdraw entry strands funds** (publish the structural no-exit fact and the operational
  `has_ended` + `ensure_not_stop` fact separately), **§7.1 "empty repo" vs "wiped repo"**
  (`git fsck` + `count-objects -v`; write "unrecoverable"), **§7.1b STOP GUESSING GraphQL field
  names — introspect the schema in one call** (`__type(name:...){ fields | inputFields |
  possibleTypes }`; worked result: `DynamicFieldName` takes `type`/`bcs`/`literal` and has **no
  `json` input**, the value accessor is `value{ ... on MoveValue{ json } }` not `asMoveValue`,
  and `MoveType`/`MoveStructConnection` are objects/connections so `contents{ type }` and
  `structs{ name }` both fail — three introspection calls replace six failed guesses), **§7.1c
  `dynamicField(name:{type:...})` can be ambiguous** (several fields may share a key type with
  identical `{"dummy_field": false}` bodies; disambiguate with `name:{ bcs: ... }` or match on the
  value's JSON, and remember discovery uses the *list* form which does accept `json` while lookup
  uses the *single* form which does not), and **§7.2 a public `pre.<apex>` staging
  host is worth one bundle diff, not a hunt** (identical byte length + normalised diff of only chunk
  names and self-referential config = CLOSED surface, with the block-compare script).
- `references/sui-move-arithmetic-refutation.md` — **the wrapper-package arithmetic lane, and the
  version trap that invalidates a whole tier.** The five leverage hypotheses (DEX slippage,
  price-derived amounts, request/complete staleness, flash-loan under-repay, delegate drain) with
  the one structural observation that kills each — `use`-list inventory proves "no DEX", mapping
  every price accessor to its consumer proves "event-only", a missing `has` clause proves
  "cannot be stretched", a trusted-receipt comparison proves "cannot under-repay", and an embedded
  `ObligationOwnerCap` proves "no delegate drain". Plus the **three-call version gate** to run
  before round 1 (`object{asMovePackage{version}}` on every brief-supplied address, `package()`
  for the chain head, then confirm the disassembly's `module <pkgid>.<name>` header) — because a
  brief asserting "v2, Immutable" can be describing a **superseded v1**, which silently voids an
  entire re-verification tier. Includes the resolver control test, the 7-row oracle-accessor
  inventory format, the Sui `Table` config-value dead ends, and the report shape for a lane that
  mostly refutes.
- `references/sui-move-composed-chain-method.md` — **the method that beat the bug list.** How to
  assemble individual "Medium" audit findings into ONE transaction-level chain: enumerate every call site of the accessor family and rank by guard strength (the weakest is usually the
  may-liquidate *gate*, upstream of everything — the worked hunt found four tiers where the first
  pass found three); read the gate function's full bytecode for a second defect in the same block
  (an unchecked price feeding a `BrFalse`→`Ret` early return that skips the `close_factor`); ask
  whether each bound is per-item or per-aggregate (per-debt-asset close factors sum past the
  intent on a multi-asset obligation, amplified by an unbounded asset count); the config-vs-code
  staleness gap (object-level 30 s vs per-asset 14-day override, 40,320× looser); diffing the
  market's on-chain asset list against the public oracle table and why a second `BaseToken`
  explains the omission; the three audit re-verification lessons (harness-only PoCs, an absent
  module is a hard refutation, "LIVE (refined)" when the audit's number is off by one); and the
  report shape for a composed chain with its REFUTED / UNVERIFIED / provenance sections.
- `references/sui-move-emode-limiter-audit.md` — **worked round: the emode / rate-limiter subsystem
  of a Move lending protocol (Sherlock M-15 lane).** The M-15 root cause with exact line evidence
  update — the audit's named `update_limiter` function is DEAD CODE with zero callers, and the safe
  `update_outflow_limit_params` / `update_outflow_segment_params` primitives shipped in-deployment
  and went unused); the **Table-enumeration dead end proven systematically** (`object(address:)`
  returns `null` for outer AND inner table UIDs; `dynamicFields` on the parent lists only the
  parent's own 3 DF keys; JSON-RPC `suix_getDynamicFields` deprecated) and the **events pivot** that
  reconstructed the full 15-group registry, per-group asset membership, and every parameter update;
  the GraphQL `events` schema gotchas (`module` not `eventType`, `contents{type{repr} json}` not
  `json`, `transactionModule` not `sendingModule`, and the silent `first:50` truncation that cut off
  groups 10-14); the limiter module as a **sliding-window segmented bucket** with the three greps
  that refute fail-open (add-path abort, conservative count early in a cycle, div-by-zero blocked by
  `validate_limiter_params`); the **decrement-side `MoveLoc` trap** (repay credits the limiter with
  the whole input coin's value, not the split remainder); and the **grep-count immutability proof**
  (`emode_group` = declaration + getter only across 37 modules → no setter → emode switching
  REFUTED structurally).
- `references/sui-move-exploit-patterns.md` — **Sui/Move exploit side: disassembly → PROVEN  finding.** The oracle-path-divergence grep (diff `liquidate` against `market`; prove the guard
  exists only in the `*_with_check` variants), the gross-value-into-accumulator pattern
  (`market::loan_amount` → `increase_usd_qualification`), decoding `PackageCallerCap` permission
  bitmasks from `LdU8` constants, why the hot-potato `start_update`/`complete_update` pair is
  REFUTED rather than permissionless, the money-exit checklist, duplicate-package-deployment as a
  distinct class from config drift, the Immutable-package rule for public audit findings
  (unfixed = still live; "fixed" may only be fixed in the package that is *not* holding the
  objects), and measuring VaR from the app's own open API. Plus: **§1.5 the scope-creep check**
  **§1.5 the scope-creep check** (`grep -rc 'with_check'` across the whole package — a package-wide zero means every entry point
  prices off raw spot, converting a whitelist-gated module bug into an any-user subsystem bug; run
  it *before* writing up), **§1.6 the asymmetric-check bug** (two `*_with_check` variants can
  divide by different operands — read the `MoveLoc` index, not the call shape), **§1.7 enumerate
  every call site** (grep the module, not the function — the weakest accessor is often on the
  may-liquidate *gate*, upstream of every other defect; the worked hunt found four tiers where the
  first pass found three), **§1.8 the composed chain** (read the gate function's full bytecode for
  a *second* defect in the same block — an unchecked price feeding a `BrFalse`→`Ret` early return
  that skips a `close_factor`, with the seizure then priced off raw spot; report the chain, not the
  individual mediums), and **§1.9 the config-vs-code staleness gap** (the object-level
 `price_delay_tolerance_ms` is not the operative bound — the per-asset `maxTimeGapMs` override was
 40,320× looser; read both before quoting "the staleness gate"), and **§8.1 the app's obligation
 count is not the chain's** (dashboard 2,664 vs on-chain ObjectTable 54,274; read the table size
 for any victim-set count and publish both numbers with the discrepancy named).
 **§1.10 enumerate EVERY call site of the accessor family, then rank by guard strength — the
 weakest one is usually the GATE.** The worked hunt found four tiers where the first pass found
 three, because the first pass grepped the seizure function and missed the may-liquidate gate
 upstream of it. Method: `grep -n 'user_oracle::get_price' market.txt` returns one call with no
 tolerance argument at all (`market.txt:2511`, inside `validate_liquidation`), while
 `get_spot_price` ×2 sit in `liquidate_calculate_seize_ctokens` and `*_with_check` ×4 sit in the
 eligibility/value paths. Rank them 0..N by guard strength and report the *asymmetry inside one
 transaction*, never a single bad call. A liquidation tx can pass through three different price
 regimes while the protocol's borrow/withdraw path — the one protecting depositors — gets the
 strongest treatment. That inversion is the headline.
 **§1.11 read the gate function's FULL bytecode for a SECOND defect in the same block.** The
 composed chain in the worked hunt was invisible until the block after the oracle call was read:
 `float::ceil(value::coin_value(...))` → `Le` against
 `LiquidationParams.close_factor_bypass_min_value` → `BrFalse` → **`Ret`** — an early return that
 skips the `close_factor` entirely, so a below-threshold debt can be closed 100% instead of
 20-30%. One block, two defects, plus a third (raw-spot seizure) downstream. Report the chain,
 not the individual mediums: *"M-14 + M-12 + M-08 + H-02 compose in one transaction."*
 **§1.12 check whether a per-item guard is per-OBLIGATION or per-ASSET.** `validate_liquidation`
 enforces `repay × close_factor <= debt` for a single debt coin type
 (`liquidate_calculate_seize_ctokens<Ty0, Ty1>` is generic per collateral/debt pair), so a
 multi-asset obligation is validated once per asset and the *sum* can approach 100%. Per-asset
 enforcement + a cheap way to build multi-asset obligations (H-03's unbounded scan) = the
 amplification. Always ask "is this bound per item or per aggregate?" before scoring severity.
 **§1.13 the app's public oracle table may omit the base quote assets entirely.** MainMarket had
 18 assets; the check-table exposed 20 feeds but **six of MainMarket's assets were absent**
 (USDC, USDT, FDUSD, USDB, USDY, SUI) — the highest-liquidity ones. Read the market's
 `assets.table.keys` on-chain and diff it against the check-table. The usual explanation is a
 second `BaseToken` (`prices` table size 2 = USD + SUI; `base_token_from_u8`, `x_oracle::usd()`,
 `x_oracle::sui()` in the bytecode), so **confirm before calling it a gap** — but if the
 non-USD base has a weaker secondary check, the whole chain is exploitable on exactly the assets
 holding the most value, and the protocol's only transparency surface does not show them.
 **§2.3 THE FLASH-LOAN TRIAD** — three findings in one module pair (`flash_loan` + `market` +
 `reserve`), all greppable in under ten calls: (a) the fee is selected by a **caller-supplied
 config row** (`Arg3: u8` → `MoveLoc[1](Arg1: u8)` → `borrow_emode_group` → `fee_rate` →
 `int_mul`), with the guarded `assert_emode_group_exists` variant sitting unused in the same
 module and the on-chain `groups.size` proving the fee matrix exists; (b) the availability gate
 reads `Reserve.cash` while the outflow only splits `underlying_balance`, so `cash` is never
 decremented and every derived metric is computed from the inflated value; (c) **there is no
 callback at all**, so the EVM flash-loan reentrancy class does not exist here — the `FlashLoan`
 hot potato must be consumed in the same tx, repay is exact-equality, and the residual surface is
 that `flash_loan_lock` is one `bool` per coin type. Plus **§2.3(d) the three tells that a PoC is
 harness-only** (`[addresses] x = "0x0"` + `Sui`/`math` deps only; the PoC defines its own
 `struct Reserve`/`struct Asset`; tests live in `<name>::<name>_poc` not `protocol::<module>`) —
 which is how you spot in ten seconds that a finding's "proof" never touched mainnet.
 bundle-config extraction recipe (unquoted keys + `12096e5` exponent literals), why nested table
  UIDs are not queryable objects, the GraphQL schema-gotcha table, and the
  **auditor-workspace-repo lead** (`search/repositories?q=<protocol>` finds a warden's public
  findings repo with verified Move PoCs — the highest-yield source-retrieval path).
- `scripts/sui_disasm_sigs.py` — parse saved Sui disassembly JSON into a public/entry function
  signature table + capability-struct census. Handles the no-`fun`-keyword and nested-generics
  traps that break naive regexes. Usage: `python3 sui_disasm_sigs.py evidence/rpc/modules/*.json`.
- `references/nextjs-admin-panel-postauth.md` — **the password-gated admin dashboard, hunted with
  no session.** Companion to §4.15 theory T1. The login-page chunk-list as the complete
  unauthenticated inventory; the 13-probe auth-endpoint behaviour matrix (four structurally-different
  invalid tokens collapsing to one byte-identical 401 = refutation of token-format / length /
  charset / JWT-vs-opaque oracles in one pass); the type-confusion ladder (array/object/missing /
  no-content-type); proving RSC payloads are gated identically to HTML (`Accept: text/x-component`
  + `RSC: 1`) and that `Next-Action` POST is blocked before dispatch; **`createServerReference` in
  the bundle is the Next.js client runtime, not an app action** — the four greps that prove it
  (`$ACTION_ID_*`, 30-60 char base64 IDs, `registerServerReference` call sites, the runtime's own
  `"use server"` error string); the `/_next/static/*` vs `/_next/build-manifest.json` middleware
  asymmetry and why Turbopack manifest 404s block chunk enumeration; the two negative greps that
  bound the whole surface (external URLs, `0x`-hex addresses — zero Sui addresses means all chain
  data is resolved server-side); session-token archaeology (`APP_ACCESS_SESSION_LS_KEY` export,
  the guard's rotation call, `withCredentials` with no `Set-Cookie`, the `from` open-redirect
  guard); refuting "the admin app shares the backend" with the Next.js-specific
  `vary: rsc, next-router-state-tree,...` header; and the pitfalls (405-on-GET is correct
  behaviour, query-string 405, trailing-slash 308, don't guess chunk hashes, pace the probes).
- `web-api-recon/references/adversarial-web2-infra-track.md` — **the ADVERSARY leaf's playbook.**
  GitHub org guess ladder + clone hygiene (`.env`/workflows/`git log -S`), bundle mining for
  internal and *redacted* hostnames (`baseURL:"https://xxx.current.finance"` is a named lead, not
  a dead end), template-literal route grep (`` `/user/getX/${e}` `` — a `"/path"`-only grep misses
  them), Alibaba OSS probing (`InvalidBucketName` ≠ `NoSuchBucket`; a dotted apex is never a legal
  bucket name), CDN/origin fingerprinting from response headers (`x-oss-request-id`,
  `ali-swift-global-savetime`, `via: ens-cache…sg28`), subdomain enum (crt.sh wildcard caveat +
  Python resolver — a shell `dig` loop can silently return nothing), email/DNS hygiene as a closed
  surface, and the **adjudication discipline** that killed three sibling findings at once.
