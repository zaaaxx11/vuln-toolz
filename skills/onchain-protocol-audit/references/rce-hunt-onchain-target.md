# RCE brief on an on-chain DeFi target — worked case (current.finance, 2026-10-28)

Condensed from a 6-hour sovereign RCE loop. Kept for the **method**, not the target.

## 1. Reframe before probing

The brief said "find ONE critical pre-auth RCE." The target is a Sui Move lending protocol —
there is no OS process to own. Five incompatible theories were dispatched (CDC: 3 agents on
"SQLi" differently is ONE family — redirect 2 elsewhere):

| # | Theory | Outcome |
|---|---|---|
| T1 | Admin panel (`xxx.<apex>`, Next.js, single-password) auth bypass → post-auth execution | **REFUTED** — see §3 |
| T2 | Web2 backend RCE (Spring actuator / NestJS GraphQL / Next.js image-SSRF / deser / SSTI / SpEL) | **REFUTED** — see §4 |
| T3 | On-chain → off-chain bridge (keeper/oracle bot executes on attacker state) | **REFUTED** — Pyth Lazer sound; but H-03 gas-DoS live |
| T4 | Supply chain (npm / CI / public repo) | **ONE REAL WEAKNESS** — SC-01, see §5 |
| T5 | Upgradeable dependency package | Pyth Lazer `State` has `upgrade_cap` policy 0 + **1** trusted signer — inherited trust risk, not a bug |

Headline written honestly: *"No pre-auth RCE (not applicable to a Move/Sui on-chain target —
no OS process to own). Fund-theft chain: YES."* Then noted that against a $58M book the
fund-theft finding is worth more than an RCE would be. Never dress theft up as RCE; never let
"no RCE" hide the real find.

## 2. The highest-value find came from the reframing, not from RCE hunting

Mapping T3 forced a full oracle-accessor census of the `market` module, which revealed **three
tiers of strength**, with the money-moving path on the weakest:

| Tier | Function | Accessor | Extra guard | Used for |
|---|---|---|---|---|
| 1 | `liquidate_calculate_seize_ctokens` | `get_spot_price` | **none** | **how much collateral is seized** |
| 2 | `collaterals/debts_usd_for_liquidation` | `get_spot_price_with_check` | EMA/spot tolerance from `Market.ema_spot_tolerance` | whether liquidation is allowed |
| 3 | `*_usd_non_liquidation` | `get_price_with_check` | tolerance **+ `ensure_secondary_checks_passed`** | borrow/withdraw risk gate |

`handle_liquidation` calls **both** tier 2 and tier 1 in the same tx → one transaction sees two
price regimes. A liquidator who moves spot away from EMA *inside* the tolerance window enlarges
the seizure without changing eligibility.

**Method that generalises:** don't stop at "module X uses the unguarded accessor." Enumerate
**every** accessor call site in the module and rank them by guard strength. The finding is the
*asymmetry between tiers inside one transaction*, which is far stronger than a single bad call.
Grep recipe: `grep -n 'get_spot_price\|get_price_with_check\|get_spot_price_with_check' <mod>.txt`
then read the surrounding function for which tier each belongs to.

**Scope-creep check that upgraded the finding:** `grep -rc 'with_check'` across the *whole*
package. The leverage package returned **0 across all 11 modules** — its `get_price_usd` is the
sole accessor and it is raw spot. That converted a whitelist-gated module bug into an
any-user subsystem bug (leverage entry needs only an `ObligationOwnerCap` the attacker holds).
Run this *before* writing up.

## 3. T1 — admin panel auth refutation ladder

All five probes are one curl each and all five held:

```
GET  /api/auth/session            -> 200 {"lockEnabled":true,"authenticated":false}
POST /api/auth/restore {"token":""}          -> 401 (byte-identical)
POST /api/auth/restore {"token":"<200 chars>"} -> 401 (byte-identical)
POST /api/auth/restore  alg=none JWT          -> 401 (byte-identical)
GET  /api/auth/restore?token=x                -> 405 (POST-only)
POST /<route>  Accept: text/x-component, Next-Action: 000…0, body [] -> 307 -> /login
```

No token oracle of any kind; no cookie session to hijack (no `Set-Cookie` anywhere); server
actions gated before dispatch. **`vary: rsc, next-router-state-tree…` on `/api/auth/*` proves
the Next.js origin answers it itself** — not a proxy to the public API tier — so a bypass on
the API tier cannot reach admin data. That single header severs the whole web2→admin chain.

The one open path was `/api/statistic/liquidation-health` (200, no auth) while every
`/api/statistic/*` sibling 307s. Payload was one boolean. Verdict: **by-design health check
for external monitoring — LOW, not an auth bypass.** Read the payload before calling it a
finding; a boolean is not data.

## 4. T2 — web2 refutation signatures worth remembering

- **Next.js `/_next/image` SSRF:** `400 "url" parameter is not allowed` for *every* external
  URL including `169.254.169.254`, `[::1]`, decimal/hex IP, IPv4-mapped, userinfo-confusion,
  and protocol-relative (`//` gets its own explicit guard). Raw-IP/metadata hostnames are
  additionally 403'd at the Cloudflare edge **before** origin. Two independent layers — the
  refutation is that both hold, and the error string tells you which layer answered.
- **POST deser/SSTI/SpEL:** 14 payload shapes (nested, `__proto__`, 5000-digit, unicode,
  `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `${T(java.lang.Runtime)…}`, non-JSON, 100 KB)
  produced exactly **two** sanitized envelopes and **zero** stack traces. A flat error path
  across the whole ladder is the refutation.
- **Actuator:** 12+ paths × 2 Spring hosts, all 404. Only `/actuator` link index + `/actuator/health`
  live. No heapdump → no in-memory secret harvest; no Jolokia → no classic Jolokia RCE.
- **NestJS:** `/graphql` + 3 variants all 404 → GraphQL not enabled → no introspection surface.
- **SSE param injection:** every payload (SSTI, 5 KB, `../..`, CRLF) → identical generic
  envelope. No differential = no sink.

## 5. T4 — the CI finding, and the correction that made it honest

`dimension-adapters` + `DefiLlama-Adapters` both run `on: [pull_request]` → `pnpm install`
**without `--frozen-lockfile`**, in `test-adapter.yml`, `ts-check.yml`,
`build-modules-and-alert.yml`, and `test.yml`. A fork PR adding a dependency gets its
`postinstall` executed on a runner holding `GITHUB_TOKEN`.

**Self-correction published in the report:** a subagent claimed the sibling repo *had* a
lockfile guard and this one uniquely lacked it. Direct file comparison showed **both lack it** —
it is the upstream DefiLlama pattern, inherited verbatim. Novelty dropped; risk unchanged.
**Rule: before claiming an asymmetry, diff the sibling file yourself.** The asymmetry *is* the
evidence, so a wrong asymmetry claim collapses the whole finding.

Blast radius stated honestly: compromising a third-party-repo fork yields that fork's
`GITHUB_TOKEN`, its release artifact, and CI minutes — **not** deploy keys, the hot wallet, or
the oracle/keeper hosts. Precondition (does the repo accept fork PRs?) was unverifiable because
the GitHub API rate-limited the IP — recorded as unverified rather than assumed.

Refutations in the same lane, all cheap: `@current-protocol/current-sdk` **not published** to
npm (closes dependency confusion); `private: true` with no install scripts; `grep -c` the
package name in `app_bundle.js` → **0**, so a prebuilt SPA bundle never consumes the SDK and
SDK compromise cannot reach production through it.

## 6. Two side-discoveries worth the detour

- **Sherlock H-03 (obligation gas DoS) still live.** Six call sites linearly scan
  `debt_types`/`deposit_types` with no bound; no `MAX_ASSETS` constant anywhere in the module.
  An attacker inflates an obligation until borrow/withdraw/liquidate exceed a fixed gas budget.
  Framed as a **degradation primitive against the off-chain execution surface** — a keeper with
  a fixed budget fails to liquidate, widening the bad-debt window. That is the closest thing to
  "attack the operator's bot" an on-chain target offers.
- **Hidden markets found via the DefiLlama adapter.** The adapter listed five market objects;
  the app UI hid two (`LEND_HIDDEN_MARKETS`). Both live on-chain with real obligations. **The
  adapter file is a trust-graph source the marketing site never mentions** — always read the
  DefiLlama/TVL adapter for the full object list.

## 7. Report shape that landed

`RCE_HUNT.md` separate from the main audit report, structured as: honest framing table (5
theories × status) → one section per theory with its refutation evidence → closed-surfaces
table (so the next session does not re-probe) → live-leads list → operator-constraints-honoured
block. The closed-surfaces table is the highest-value artifact: it is what stops round 3 from
re-running round 1.
