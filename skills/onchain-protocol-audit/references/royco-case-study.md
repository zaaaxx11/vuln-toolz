# Royco case study — a full worked example

Target: `www.royco.org` (Next.js) · `app.royco.org` · `api.royco.org` · contracts on Ethereum 1,
Sonic 146, HyperEVM 999, Plume 98866.
Shape: tranche-based yield marketplace (modern "Day" v2 stack) + an older BoringVault/staker
stack that actually held the balance, + a LayerZero cross-chain bridge as the share-transfer gate.
Outcome: **no pre-auth RCE, no fund theft, no account takeover** — with two numeric self-corrections
and ~30 closed surfaces. This is the reference for what an honest negative verdict looks like.

---

## 1. The trust graph (all of it, from 4 RPC calls + 2 explorer calls)

```
BoringVault 0x74d1fafa4e0163b2f1035f1b052137f3f9bad5cc   (18482 bytes)
  holds the share token; USDC.balanceOf = 156,652 (= $156.65 at 6 decimals)
  ├─ accountant 0x80f0B206B7E5dAa1b1ba4ea1478A33241ee6baC9
  │    AccountantWithRateProviders  -> THE SHARE-PRICE ORACLE
  ├─ hook       0x60ebb5d1454bb99aa35f63f609e79179b342b0b8
  │    LayerZeroTeller (18078 bytes) -> THE CROSS-CHAIN TRANSFER GATE (beforeTransfer)
  ├─ authority  0x754213afb8ecb6d15f169bfd378fb685f5cb0d4a
  │    RolesAuthority (2614 bytes)   -> THE ROLE/CAPABILITY MAP
  ├─ boringSafe 0xebf2320189bdaf96fa9a2966b49c966693615e86  (reward escrow)
  └─ Deployer   0x47Cec90FACc9364D7C21A8ab5e2aD9F1f75D740C
       owner = 0xf8553c8552f906C19286F21711721E206EE4909E  (EIP-7702 delegator EOA, role bit 33)
```

Plus the modern tranche tree (14 verified trees on disk): `RoycoDayAccountant`, `RoycoDayEntryPoint`,
`RoycoDayBalancerV3Kernel`, `RoycoSeniorTranche`, `RoycoJuniorTranche`,
`RoycoLiquidityProviderTranche`, `RoycoFactory`, `RecipeMarketHub` v1/v2, `RoycoEntryPoint_Dawn`,
`ConcreteAsyncVault_srRoy`, `BoringVault_0x74d1`.

**The decisive move:** the API advertises `tvlUsd = 48,610.96` for "Royco USDC" while the vault
actually holds **$156** of USDC. The accounting TVL is `shares × price` (48,615.724088 shares ×
1 USDC); the idle balance is tiny because strategy assets sit elsewhere (Plume markets). That
mismatch is what forced the hunt into the BoringVault + bridge + oracle stack — which no amount of
reading the (much more defensive) Day tranche would have revealed.

---

## 2. Round-by-round outcome

| Round | Track | Outcome |
|---|---|---|
| 1 | web tier | 8 findings, all MEDIUM/LOW |
| 2 | contract invariants (Day tranche) | 5 HOLDS, 1 REFUTED, 1 privileged-config bound |
| 3 | auth / session (SIWE) | every attack path REFUTED, with the exact error string |
| 4 | BoringVault + LayerZero + oracle | trust graph mapped, all privileged paths REFUTED |

---

## 3. Round 2 — contract invariants (5 HOLDS)

Modern tranche architecture is genuinely well defended. The reasons, with anchors:

| Invariant | Verdict | Why |
|---|---|---|
| Share accounting / inflation / donation | **HOLDS** | NAV read from **ledger storage** (`ValuationLogic.sol:26-29`), not `balanceOf` ⇒ donation attack structurally dead. All rounding **Floor** (`AssetLedgerLogic.sol:151-154`). |
| Junior/Senior loss exit window | **REFUTED (no window)** | Loss socialisation is **atomic in one tx**: pre-op sync (`RedemptionLogic.sol:72`) → waterfall (`RoycoDayAccountant.sol:424-433`) → conservation `require` (`:526`). |
| RecipeMarketHub v2 fund movement | **HOLDS** | `offer.ap/ip != msg.sender` reverts (`:544,563`), `isWeirollOwner` (`:732,797`), `onlyRecipeMarketHub` (`WeirollWallet.sol:118`) |
| Fee double-claim / non-owner | **HOLDS** | claim-then-`delete` (`RecipeMarketHub.sol:281-285`) |
| Points entitlement | **HOLDS** | `Points.sol:104,111,58,69` |
| Protocol-fee cap | **BROKEN as a bound** | `Constants.sol:28` `MAX_PROTOCOL_FEE_WAD = 1e18` ⇒ 100% of **yield** (not principal) is settable by a `restricted` role. **Privileged-config risk, not fund theft.** |

Value at risk, measured: `USDC.balanceOf(0x74d1…)` = 156,652 raw = **$156.65**; the Day-v2 tranche
TVL across 3 vaults ≈ **$129,124**; RecipeMarketHub = 811 markets, sample page-1 TVL ≈ $3,240.

---

## 4. Round 3 — auth/session: the error-message differential

The single most productive technique of the whole session. Backend needed **two cookies**:

| Cookie | Contents | Attributes | Role |
|---|---|---|---|
| `royco.session` | unsigned JSON `{id, walletAddress, userId, expiresAt, isActive}` | `HttpOnly; Secure; SameSite=Lax; Domain=app.royco.org; Max-Age=31536000` | opaque 32-byte session id → **DB lookup** |
| `wagmi.store` | wagmi state `{state:{connections:{__type:"Map",value:[[uid,{accounts:[addr],chainId,connector}]]},chainId,current},version:2}` | **`httpOnly=False`**, `Domain=.royco.org` | the *connected wallet address* as auth input |

The error ladder that mapped the logic:

```
no cookie at all                 -> 401 "Invalid session"
only royco.session               -> 401 "Invalid session"
only wagmi.store                 -> 401 "Invalid session"
both, wallets disagree           -> 401 "Connected wallet does not match session wallet"
both, session.id fabricated      -> 401 "Invalid session"
both, wallets agree              -> 201 + user payload
```

### SIWE validation matrix (all PROVEN by simulation)

| Variant | Result |
|---|---|
| `domain: https://evil.com` | 401 `Domain mismatch in SIWE message` |
| `domain: https://app.royco.org.evil.com` | 401 `Domain mismatch in SIWE message` |
| `URI: https://evil.com` | 401 `Invalid SIWE URI, must be https://app.royco.org` |
| `Chain ID: 999` | 401 `Invalid SIWE message or signature` |
| expiry in the past | 401 `Unauthorized` |
| **no expiry line at all** | **201 + cookie** (expiry optional) |
| blank statement | 401 `Invalid SIWE statement, must be "Sign in with Ethereum to Royco app. P…"` |
| nonce replayed | 201 then 401 `Invalid or expired nonce` |
| never-issued nonce | 401 `Invalid or expired nonce` |

### The decisive ATO test — REFUTED

Hypothesis: `body.address` is not bound to the signature ⇒ attacker signs with their own key but
writes the victim's address in the body.

```
attacker = 0x36bBb0358448c1f07858C118140e0873174C81be
victim   = 0xBe0fF0163fD108F41D5Cd3237007659fc64190eF
nonce    : requested for the VICTIM address            -> 201
message  : names the VICTIM address, signed by ATTACKER
POST /api/v1/auth/login {address: victim, message, signature: attacker_sig}
  -> 401 "Unauthorized"      (no cookie issued)
```

**Backend verifies the signature against the address written in the *message*, not the body field.**
No impersonation path.

### Cookie tampering matrix (all REFUTED)

| Tamper | Result |
|---|---|
| session(A) + wagmi(B), cross-wallet | 401 `Connected wallet does not match session wallet` |
| session claims `walletAddress` → other | 201 but **still wallet A** (claims ignored) |
| session claims `userId` → other | 201 but **still user A** |
| session `id` → random hex | 401 `Invalid session` |
| wagmi `accounts` → `0x0` | 401 `Connected wallet does not match session wallet` |

`wagmi.store` being `httpOnly=False` is real but **not** an ATO: it is only an address input, and a
valid `royco.session` (DB-verified id) is still required.

### Write-endpoint DTO enumeration with a valid session

| Endpoint | Anon | Valid session |
|---|---|---|
| `POST /api/v1/user/edit` | 401 | 400 `Please verify your email first to access this feature.` — email-verification gate precedes the DTO; `points`/`balanceUsd`/`verified`/`id`/`userId` all rejected |
| `POST /api/v1/market/create` | 400 | 400 `Bad Request Exception` |
| `POST /api/v1/auth/logout` | 401 | 201 |
| `POST /api/v1/auth/revalidate` | 401 | — |

---

## 5. Round 4 — the BoringVault / bridge / oracle stack

### 5.1 The epoch-accounting hypothesis that DIED (and how)

`BoringChef` stores participation in a `uint128` balance ledger with epoch rollovers. Two
appending hypotheses looked alarming:

- `epochs[3].eligibleShares = 617,760,757,078` vs `totalSupply = 48,615,724,088` (12.7×).
- Per-user event reconstruction gave `sum(users)/eligible = 7999×` for epoch 2 and `51×` for epoch 7.

**Both were my model's bug.** The event-law reconstruction:

```
eligibleShares[e] = eligibleShares[e-1] + deposits[e] - withdrawals[e]
epoch 2: 47,000,000 + 119,941,180,794 - 119,973,180,794 = 15,000,000
on-chain epochs(2).eligibleShares                     = 15,000,000   ✓ law confirmed
```

and the ground truth from the real getter:

```
sum over 640 holders of getUserEligibleBalance(holder) = 10,000,000
epochs[currentEpoch=6].eligibleShares                 = 10,000,000   ratio 1.000000
sum over holders of balanceOf(holder)                  = 48,615,724,088
totalSupply()                                         = 48,615,724,088
```

**Accounting is exactly consistent.** Both anomalies were artifacts of a reconstruction that did not
apply withdrawals the way the contract does. Never promote a reconstructed anomaly without a
getter-confirmed cross-check.

### 5.2 Role map from events, and the wildcard question

`RolesAuthority` events yielded: 14 public-capability events, 82 role-capability events, 46
user-role events. Roles observed: 1,2,3,4,5,7,8,9,10,11,12,14,15,16,17,21,22,23,31,32,33.

Every capability event carried `functionSig = 0x00000000` (wildcard). Verification via
`eth_call` simulation: `enter`/`exit`/`manage`/`updateExchangeRate`/`updatePayoutAddress`/
`setShareLockPeriod`/`addChain`/`bulkWithdraw` all returned `UNAUTHORIZED` for **both** a role-free
address **and** an address that held the relevant role bits.

→ the deployed authority is stricter than the event log suggests. **All privileged paths closed.**

### 5.3 Live oracle state (the price bound check)

`AccountantWithRateProviders` for the vault: `startingExchangeRate = 1e6` (1.0 USDC/share),
`allowedExchangeRateChangeUpper = 10100` (1.01×), `allowedExchangeRateChangeLower = 9900` (0.99×),
`minimumUpdateDelayInSeconds = 21600` (6 h), `platformFee = 0`, `performanceFee = 1000` (10%),
`payoutAddress = 0x0000…0001`. Teller `shareLockPeriod = 86400` (24 h). Oracle bounds are sane.

---

## 6. The web-tier findings that DID survive

| # | Finding | Verdict | Evidence |
|---|---|---|---|
| W1 | The Next.js proxy **lends its service credential** to every anonymous visitor | **PROVEN** | `api.royco.org/api/v1/user/stats` → 401 `No authentication token provided`; identical request via `app.royco.org` → 201 + data |
| W2 | CORS reflects any origin + `Access-Control-Allow-Credentials: true` | **PROVEN config, NOT exploitable** | `Origin: https://evil.example` → ACAO echoes it, ACAC true, 47 KB body readable — but auth is a **header**, so there is no ambient authority. Real impact = open credentialed relay. |
| W3 | `POST /api/v1/simulate/{sender}` unauthenticated, does real work | **PROVEN** | 201, 2.451 s server-side per request, no 429 in 10/10, ≥20 txns accepted |
| W4 | `GET /api/v1/contract/{chain}/{addr}` is a **write-on-GET** | **PROVEN** | 5/5 random addresses → 5 new DB rows; miss 0.695–1.575 s vs hit 0.268 s; `lastUpdated` identical across calls |
| W5 | `POST /api/rpc/{chain}` unmetered + `eth_getLogs` unbounded | **PROVEN** | 10×200 with no 429; `0x0`→`latest` accepted; **502,976 bytes for ONE block** (1000 blocks ≈ 500 MB — extrapolated, never executed) |
| W6 | Public positions / leaderboard (rank 1 = $35.8M) | **PROVEN, LOW** | privacy + targeting, on-chain-derivable anyway |
| W7 | First-party Supabase anon JWT in the client bundle | **PROVEN leak / REFUTED exploit** | project `istbjtfzjcnstpzunkje`, JWT 208 chars; live → `401 Legacy API keys are disabled` (2026-04-20) — one dashboard toggle from live |
| W8 | `wagmi.store` is `httpOnly=False` on `.royco.org` | **PROVEN, LOW** | real cookie captured in a browser with a mock injected wallet; not an ATO without a valid `royco.session` |

---

## 7. The two numeric self-corrections (the most valuable part)

**Correction 1 — the amplification claim.** Round 1 reported `/decoder/decode` = "200 outbound
lookups, 14–18 s server time". That was **wrong** — it was an unreplicated subagent timing.
Re-measurement, N = 1/10/50/100 at 1 req/s:

| N | wall | bytes |
|---|---|---|
| 1 | 0.342 s | 750 |
| 10 | 0.279 s | 9,120 |
| 50 | 0.312 s | 46,360 |
| 100 | 0.346 s | 100,920 |

Amplification ≈ **1.0×** — pure RTT, no egress. Published as a **KOREKSI** block at the top of the
final report naming the old claim and the measurement that kills it.

**Correction 2 — the decimal slip.** Round 2 wrote "`USDC.balanceOf(0x74d1…)` = **156,652 USDC**"
on a 6-decimal token. The real figure is **156.652 USDC = $156.65**. 1000× overstatement of the
single most important number in the report. Caught only by cross-checking against the app's own
`tvlUsd` (48,610.96) — which does not match either, because the app reports accounting TVL
(shares × price), not the idle balance.

---

## 8. Final verdict table (shape to copy)

| Layer | Verdict | Proof basis |
|---|---|---|
| Auth / session | no ATO, no privilege escalation | SIWE matrix + cookie-tamper matrix + DTO enumeration, every row with its exact error string |
| On-chain invariants (Day tranche) | 5 HOLDS, 1 REFUTED, 1 privileged-config bound | file:line anchors |
| BoringVault epoch accounting | consistent (ratio exactly 1.000000) | getter-confirmed aggregate |
| Role / capability | all privileged paths closed | event map + `eth_call` simulation |
| Cross-chain bridge | no forgeable path found; `idToChains` empty for all common LZ eids; `shareLockPeriod` 24 h; lock cannot be shortened without a role | live state + simulation |
| Web tier | 8 findings, MEDIUM/LOW, none touching user principal | request/response pairs |

**Strongest surviving chain (stated with its ceiling):**
`[anon] GET /api/v1/contract/{chain}/{random}` → 1 DB row + 1 upstream fetch per request, unmetered
→ row/index growth + provider quota burn → API degradation for all users.
`[anon] /api/rpc/{chain}` + `eth_getLogs` unbounded (502 KB/block) → cost borne by the provider.
**On-chain user funds are unreachable from these paths.** Do not call it critical RCE or fund theft.

---

## 9. Round 5 — the closure round (what turned a bug list into a verdict)

Round 5's job was not to find more. It was to **close** what rounds 1–4 had reported, because three
of the four headline findings did not survive their own arithmetic. This is the part of the case
study worth copying.

### 9.1 F1 (LPT quote divergence) — REFUTED as value extraction

The 4.76% gap is real, but the round-trip is **−1 wei**:

```
exec shares minted     = 95,011,876,484,560,570,071   (95.011876 e18)
view shares            = 100,000,000,000,000,000,000  (100.000000 e18)
share-count gap        = 4.9881%          <-- D_contracts.md printed 4.76%; corrected
post-deposit price     = 1.0525000000 NAV/share
depositor's value      = 99,999,999,999,999,999,999   (paid 100.000000 e18)
ROUND-TRIP P&L         = -1 wei  (-0.000000000%)
counterfactual (if the view's number were minted): +4.7727% extracted from existing holders
```

The share-count gap is compensated 1:1 by the share price. The redeem leg is conservative in the
other direction (view under-states assets by 5.25%). The premium is accountant-computed, not a user
input, so neither a third party nor the same user can arbitrage it.
**Downgrade: MEDIUM — non-compliant ERC-4626 quote / integration bug.**

### 9.2 F2 (`MAX_PROTOCOL_FEE_WAD = 1e18`) — REFUTED as fund theft

`FeeAndLiquidityPremiumLogic.sol:84-93` proves the fee is a **yield reallocation**:
`retainedSeniorNAV = stEffectiveNAV - lptLiquidityPremium - stProtocolFee`, and the source comment
at `:65-66` says *"no assets enter or leave"*, *"NAV-neutral and coverage-neutral"*. Principal is
structurally untouched. Max realistic exposure = the protocol's annual yield (**$4,861.57/yr** on
the measured $48,615.72 TVL at 10% APR), not the TVL.

Cross-check that strengthens the report: the sibling Concrete/srRoy family caps management fee at
**10%** and performance fee at **30%** (`StateSetterLib.sol:13,16`). The 100% Day-accountant cap
looks like an oversight — flag as **fee policy**, not a vulnerability.

### 9.3 The RPC allowlist gap — the one NEW MEDIUM that survived

```
eth_sendRawTransaction   -> 200 -32602 "failed to decode signed transaction"   # FORWARDED
debug_traceTransaction   -> 200 -32000 "transaction not found"                 # FORWARDED
eth_sendTransaction      -> 400 -32600 "Unsupported method: … on ETH_MAINNET"  # BLOCKED
admin_peers              -> 400 -32600 "Unsupported method: … on ETH_MAINNET"  # BLOCKED
personal_listAccounts    -> 400 -32600 "Unsupported method: … on ETH_MAINNET"  # BLOCKED
anvil_impersonateAccount -> 400 -32600 "Unsupported method: … on ETH_MAINNET"  # BLOCKED
```

The operator denied the convenient methods and missed the raw ones. **MEDIUM open relay**, not fund
theft — no signed-payload oracle exists (every candidate endpoint 404s) and a raw tx broadcasts
verbatim.

### 9.4 The missing link — broken at link one

The live backend is an **older build** than the JS bundle. `/api/v1/day/*`, `/api/v1/keeper/*`,
`/api/v1/token/balance`, `/api/v1/simulate/{addr}`, `/api/v1/position/{addr}` all **404**. The
Day-tier API is contract-only, so any chain needing it as a web→on-chain handoff dies immediately.
Write-on-GET on `/api/v1/contract/{chain}/{addr}` is real (LOW) but not chainable: the address
charset is hex-only so no XSS payload persists, and no reachable endpoint reflects the value.

### 9.5 Live oracle state (correcting §5.3 of this document)

The earlier round read `minimumUpdateDelayInSeconds = 21600` and `performanceFee = 1000`. The
round-5 re-read of the same contract gave:

```
minUpdateDelay     = 0 s            <-- no time gate at all
performanceFee     = 23749451159961600   <-- absurd (≈2.37e15%); setter caps at 50%
lastUpdateTs       = 1743097151     (Mar 2025 — rate untouched for ~19 months)
platformFee        = 0
exchangeRate       = 1000000        allowedUpper = 10050   allowedLower = 9950
```

**Lesson: re-read live state in the closure round.** A bound that looked sane in round 4 had drifted,
and the drift is itself a LOW finding (config hygiene). Never carry a live-state number forward from
an earlier round without re-reading it.

### 9.6 Final round-5 verdict table

| ID | Finding | Severity | Verdict |
|---|---|---|---|
| V1 | `/api/rpc/*` allowlist gap (`eth_sendRawTransaction`, `debug_traceTransaction`) | **MEDIUM** | PROVEN |
| V2 | Write-on-GET DB row via `/api/v1/contract/{chain}/{addr}` | LOW | PROVEN |
| V3 | Unbounded `eth_getLogs` range | LOW | PROVEN |
| V4 | `MAX_PROTOCOL_FEE_WAD = 1e18` (100% of yield) | LOW | PROVEN, config risk |
| V5 | LPT quote divergence 4.9881% | MEDIUM integration | PROVEN, value-neutral |
| V6 | `performanceFee` absurd value | LOW hygiene | PROVEN |
| V7 | `minUpdateDelay = 0` | LOW | PROVEN |
| F1/F2/F3/F10 | arbitrage / fee theft / amplification / stale price | — | **REFUTED** |
| — | "vault insolvent" | — | **REFUTED** (95.93% backed, CCTP in-flight) |

**No fund-theft or share-inflation invariant break in any target.**
