# Sui/Move emode + rate-limiter audit — worked round (M-15 lane)

Worked target: `current-finance` lending protocol, Sui mainnet.
Lending package v2 `0x45bae0425e9098ce5cba3d3fa2836220ad24c9f88aa0dffffb5a52b49319fc70`
(module set under package ID `0xfe1d8929d13b00aaecd7642dec1c6d41cab82882a1b139efa46bf61dfd6380bf`),
MainMarket object `0x41f3d76aee8b20e53f7d0d395fdc09e241e683c7bc5d0f69674b545ee42549df`.

Brief: verify Sherlock M-15 ("updating emode limiters resets current usage") against deployed
bytecode, enumerate the 15 live emode groups with limiter state, deep-dive the limiter module for
fail-open paths, check emode-switching-after-position. READ-ONLY, ~15 min budget.

---

## 1. Verdict

**M-15 CONFIRMED LIVE — admin-gated, silent, and broader than the audit describes.**

The reset is not in a dedicated "update limiter" function. It is inside `emode::update`, which means
**every** emode parameter update (LTV, liquidation factor, borrow weight, flash-loan fee) wipes live
rate-limiter usage as a side effect. Safe primitives that preserve usage exist in the same module
and are bypassed.

---

## 2. Root cause — exact lines

`evidence/disasm/emode/emode.txt` `update(&mut EMode, NewEMode)` at **471-554**:

```
543   MoveLoc[7](loc5: NewLimiter)
544   Call limiter::new_from_struct(NewLimiter): Limiter
545   CopyLoc[10](loc8: &mut EModeRateLimiter)
546   MutBorrowField[11](EModeRateLimiter.deposit: Limiter)
547   WriteRef                          <-- whole-struct overwrite
548   MoveLoc[3](loc1: NewLimiter)
549   Call limiter::new_from_struct(NewLimiter): Limiter
550   MoveLoc[10](loc8: &mut EModeRateLimiter)
551   MutBorrowField[12](EModeRateLimiter.borrow: Limiter)
552   WriteRef                          <-- whole-struct overwrite
```

`evidence/disasm/emode/limiter.txt` `new_from_struct` **32-52** → `:49 build_segments(u32,u32)`,
`:50 Pack[0](Limiter)`.
`build_segments` **248-283** → `:253 VecPack(13,0)`, `:16 LdU64(0)`, `:17 Pack[3](Segment)` —
**every segment value initialised to 0**. Usage is structurally unrecoverable; there is no
"carry forward" path anywhere in the module.

### Live caller (admin-gated)

`evidence/disasm/emode/emode_admin.txt` `public update_asset_in_emode_group<Ty0,Ty1>` at **218**:

```
226-228  market::has_circuit_break_triggered<Ty0>  -> Not -> BrFalse -> Abort (market_under_circuit_break)
243-248  app::validate_market<Ty0> ; app::ensure_version_matches(&ProtocolApp)
252-255  market::emode_registry_mut<Ty0> ; emode::borrow_mut_emode(&mut EModeGroupRegistry, u8, TypeName)
257-258  emode::update(&mut EMode, NewEMode)        <-- the reset
275-276  event::emit<EModeUpdated<NewEMode>>        <-- carries only the NEW params, not prior `used`
```

No user-reachable path. `&AdminCap` + `&ProtocolApp` + version match + circuit-break check.

### The named root-cause function is DEAD CODE

M-15's root cause pointed at `emode::update_limiter` (`emode.txt:379-399`) — the same defect
(`new_from_struct` → `MutBorrowField[11/12]` → `WriteRef`). Grep across all 37 disassembled modules
returned **zero callers**. The live path is `emode::update`.

### Bypassed safe primitives (the aggravating factor)

`limiter.txt:72-79  update_outflow_limit_params(&mut Limiter, u64)` — `WriteRef` on
`outflow_limit` only.
`limiter.txt:81-101 update_outflow_segment_params(&mut Limiter, u32, u32)` — writes durations and
rebuilds segments.

Neither is called from `emode`. **The fix shipped in-deployment and went unused.**

### Blast radius

One admin tx per (group, asset) clears both limiters for that pair. MainMarket has 15 groups × 18
assets = up to 270 resettable limiter instances; each reset re-opens up to `outflow_limit` of
additional outflow per limiter for the remainder of the sliding window. No event carries the prior
`used`, so the reset is unobservable off-chain.

---

## 3. Enumerating the 15 groups when Table entries are unreachable

### 3.1 What does NOT work (do not re-derive)

`object(address:)` returns `null` for every Table UID — outer and inner alike:

```
0xb3508fbc…  (assets table outer UID)     -> {"object":null}
0x45b19663…  (assets table inner UID)     -> {"object":null}
0x0e2666d6…  (emode_group_registry.groups)-> {"object":null}
```

`dynamicFields(first:50)` on the Market returns exactly its own 3 DF keys
(`ADLRegistryKey`, `CircuitBreakKey`, `MarketConfigurationKey`), `hasNextPage:false` — **never the
table's entries**. JSON-RPC `suix_getDynamicFields` is deprecated (`-32601 Method not found`).

The parent object's own JSON *does* give you the registry head, which is enough to state the count:

```graphql
{ object(address: "<market>") { asMoveObject { contents { json } } } }
# -> emode_group_registry: { next_group_id: 15, groups: { id: "0x0e2666d6…", size: "15" } }
```

### 3.2 What DOES work — events

```graphql
{ events(first: 50, filter: { module: "0xfe1d89…::emode_admin" }) {
    nodes { timestamp contents { type { repr } json } transactionModule { name } } } }
```

Schema gotchas that each cost a call:
- filter field is **`module`** (format `0xPKG::module`), NOT `eventType`;
- `Event` has no `json` field — payload is **`contents{ type{repr} json }`**;
- no `sendingModule` — it is **`transactionModule{name}`**;
- **paginate with cursors** — `first:50` returned 50 nodes and silently truncated, cutting off
  groups 10-14.

### 3.3 Reconstructed registry (MainMarket)

All 15 groups created `2026-03-23T13:05:05.532Z` by operator
`0xfbe0602c6901ff987dd4de8e762698209b611dd983bdf5f011e2da2d3b9fd532`, all with
`oracle_base_token = 0`.

| gid | assets (from `EModeUpdated` what=0) |
|---|---|
| 0 | USDC, USDT, USDSUI, USDB, FDUSD, USDY, BTC, XBTC, LBTC, SUI, ETH, HASUI, STSUI, CERT, AFSUI, SPRING_SUI (16) |
| 1 | HASUI, SUI |
| 2 | STSUI, SUI |
| 3 | AFSUI, SUI |
| 4 | CERT, SUI |
| 5 | SPRING_SUI, SUI |
| 6 | USDY, SUI |
| 7 | USDY, USDC, USDT, USDB, USDSUI |
| 8-14 | truncated by pagination — UNTESTED |

Other markets share the same group IDs 0-3 (EmberMarket gid 0-3, AltCoinMarket/EthenaMarket/
MatrixGoldMarket gid 0) — the `NewEModeGroupEvent.market` field disambiguates.

**Per-group limiter state (limit + used) is BLOCKED** — the Table is a child object and
`object(address:)` returns null for it. The on-chain view `emode.txt:706-724
limiter_usage() -> RateLimitUsage * RateLimitUsage` is the correct PoC hook; call it per
(group, asset) to name the group with the highest `used`. Label this UNTESTED, not refuted.

---

## 4. Limiter module deep-dive (`limiter.txt`)

### 4.1 Structure

```
struct Limiter  { outflow_limit: u64, outflow_cycle_duration: u32,
                  outflow_segment_duration: u32, outflow_segments: vector<Segment> }   :5-10
struct NewLimiter { outflow_limit, outflow_cycle_duration, outflow_segment_duration }   :12-16
struct Segment  { index: u64, value: u64 }                                             :22-25
struct RateLimitUsage { limit: u64, usage: u64 }                                       :27-30
```

A **sliding-window segmented bucket**, not a token bucket. `outflow_segments.len() ==
outflow_cycle_duration / outflow_segment_duration`.

### 4.2 Time-based decay

`add_outflow` **103-170**:
```
127-132  idx  = now / outflow_segment_duration
134-139  slot = idx % outflow_segments.len()
149-159  if segment.index != idx { segment.index = idx; segment.value = 0 }   // rollover
160-169  segment.value += amount
```

`count_current_outflow` **285-365** sums segments where
`segment.index >= idx - len + 1` (`:332-338`).

### 4.3 Fail-open — REFUTED (three greps)

1. **Add-path aborts on overflow.** `add_outflow :108-118`:
   `count_current_outflow + amount <= outflow_limit` → `Le` → `BrFalse(12)` → `Abort`. Fail-closed.
2. **Count-path is conservative early in a cycle.** `count_current_outflow :25-28`:
   `len > idx` → `LdTrue` → count **every** segment. No undercount window at cycle start.
3. **Div-by-zero unreachable.** `validate_limiter_params :367-414` enforces
   `segment != 0` (`:369-378`), `cycle >= segment` (`:379-388`),
   `cycle % segment == 0` (`:389-400`), `cycle/segment <= 48` (`:401-412`) — max 48 segments.
   Caveat: `new_from_struct` does not itself validate, but every `NewLimiter` originates from
   `create_new_limiter_change :54-70`, which does.

### 4.4 Decrement-without-outflow — CANDIDATE, UNTESTED

`market.txt:1197-1201` (repay) calls `limiter::reduce_outflow(&mut Limiter, Arg3, coin::value)`
where `:124-125` reads the value of **`Arg2` (the whole input coin)**, not the split remainder
`loc12` produced at `:99-103 coin::split`. If the caller supplies a coin larger than the repayment,
the limiter is credited more than the debt actually retired → inflated future borrow capacity.
Needs the repay entry function to close. HIGH-CONFIDENCE / UNTESTED.

### 4.5 Scope (naming is inverted; behaviour is symmetric)

| Limiter | Meters | Credited by |
|---|---|---|
| `deposit` | **withdrawals** (`market.txt:735-780`, `:138-142 add_outflow`) | **deposits** (`market.txt:525-620`, `:100-103 reduce_outflow`) |
| `borrow` | **borrows** (`market.txt:880-930`, `:94-97 add_outflow`) | **repays** (`:122-126 reduce_outflow`) |

Both directions covered; no unidirectional gap.

---

## 5. emode switching after position — REFUTED (invariant holds)

`obligation.txt:64-92 new<Ty0>` sets `emode_group` once at `:10-11`
(`MoveLoc[1](Arg1: u8); PackGeneric[0](Obligation<Ty0>)`). The only other reference to the field in
the entire disassembly corpus is the getter `obligation.txt:41-46`. **No setter exists anywhere** →
emode is immutable per obligation.

`enter_market.txt`:
- `:22-33 enter_market` always uses `market::lending_default_emode_group()` (`:39`).
- `:45-58 enter_market_with_emode` requires `&PackageCallerCap` +
  `app::ensure_has_permission` (`:48-51`).

A normal user cannot select an emode group at all, let alone switch one. No timelock is needed
because no switch path exists.

---

## 6. Report shape used

```
VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE / MITIGATION / VERIFICATION
+ claim-vs-proof table
+ REFUTED
+ UNTESTED
```

Skeleton written to disk FIRST (`findings/N_emode.md`), then appended every 5 tool calls — per the
operator's standing order. When the iteration cap hit, the append-ready content was delivered in
prose so the report could be completed on disk in the next turn.

### UNTESTED list carried forward

- Per-group limiter state (limit + used) — blocked on Table enumeration; use
  `emode::limiter_usage()` per (group, asset).
- gid 8-14 asset membership — truncated by event pagination.
- Repay over-credit candidate (§4.4) — needs the repay entry function.
- M-13 vs M-12 duplication — M-13 file never opened.
