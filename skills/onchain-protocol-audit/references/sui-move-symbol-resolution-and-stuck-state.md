# Sui/Move — symbol resolution, enumeration integrity, and stuck-state patterns

Three classes of mistake that produced a wrong finding or a weak claim this session, plus the
cheap checks that prevent each. Companion to `sui-move-composed-chain-method.md` (§9.1–§9.4,
audit re-verification) and `sui-move-onchain-audit.md` (endpoint + resolver traps).

---

## 1. Resolve WHICH package a called symbol comes from BEFORE reasoning about its arithmetic

### The trap

`market.txt` line 4:

```
use f01bf3d01c8f50247fdf597e3f565b865e00b4a20a01b353d44d71c993f36e9a::u64;
```

So every `Call u64::pow10_u64(u8): u64` and `Call u64::pow(u64, u8): u64` inside `market`
resolves to the **math package's** `u64` module — NOT stdlib `0x1::u64`. The two have
materially different implementations.

**stdlib `0x1::u64::pow`** (pulled for comparison) is a squaring loop over raw `Mul`:

```
6:  CopyLoc[3](loc1: u8)
7:  LdU8(1)
8:  Ge
...
17: CopyLoc[2](loc0: u64)
18: MoveLoc[2](loc0: u64)
19: Mul                                  <- raw multiply, no explicit bound
```

**math package `f01bf3d0…::u64::pow10_u64`** is a hardcoded lookup table:

```
0:  CopyLoc[0](Arg0: u8)
1:  LdU8(0)
2:  Eq
3:  BrFalse(7)
4:  LdU64(1)                             <- decimals == 0 -> 1
...
126: MoveLoc[0](Arg0: u8)
127: LdU8(18)
128: Eq
129: BrFalse(131)
131: LdConst[0](u64: 10)
132: Abort                               <- decimals > 18 -> ABORT, code 10
133: LdU64(1000000000000000000)          <- decimals == 18
```

The whole function is `LdU8(n) → Eq → BrFalse` chains with a final `Abort`. There is no
multiplication at all.

### The wrong finding this produced

M-07 (Sherlock) claims "decimals above 18 can brick core paths". I confirmed the registry has no
upper bound (`coin_decimals_registry.txt:36-48` passes `coin::get_decimals` straight through;
`register_decimals_inner` only checks `!table::contains`), then reasoned about the *consumer*
using **stdlib** `pow` semantics:

- `value.txt:21-22` → `u64::pow(10, decimals)`
- `10^19 = 1e19 < u64::MAX = 1.8446e19` → fits
- `10^20` → overflows → aborts

So I wrote **"LIVE (refined): the real cliff is decimals ≥ 20, not > 18 — the Sherlock claim is
off by one."** That was wrong. The actual consumer in the liquidation path is
`market.txt:2604` / `market.txt:2609` → `u64::pow10_u64(decimals)`, which resolves to the math
package and **aborts at decimals > 18 exactly as Sherlock said**. My "refinement" inverted the
correct answer into an error, and it would have been published as a confident correction of the
audit.

### The check (one grep, one pull)

Before writing ANY claim about overflow, saturation, rounding, or abort behaviour of a called
function:

1. **Read the module's `use` list.** `grep -n "^use " <module>.txt`. Every `Call X::f(...)` in
   that module resolves through one of these — and a locally-vendored `u64` / `float` / `u128`
   shadows the stdlib name.
2. **Pull the defining package's disassembly** for the function you are about to characterise.
   `package(address:){module(name:){disassembly}}` with the `0x` prefix.
3. **Then** reason about behaviour.

Cost: one grep plus one GraphQL call. What it buys: not publishing an inverted verdict.

### Applies to

`float`, `u64`, `u128`, `math_error` — the math package at
`0xf01bf3d01c8f50247fdf597e3f565b865e00b4a20a01b353d44d71c993f36e9a` vendors all four. Any
protocol that vendors its own numeric helpers will shadow stdlib names, and the shadowed
implementation is usually *stricter* than stdlib (explicit aborts rather than wrapping), which
means stdlib reasoning under-states the blast radius.

---

## 2. Enumeration integrity — a module-absence claim is only as strong as the pagination

### The schema gotchas (each cost a call)

```graphql
# WRONG — "Unknown field \"name\" on type \"MoveModuleConnection\""
query($p: SuiAddress!){ package(address:$p){ modules { name } } }

# RIGHT
query($p: SuiAddress!){ package(address:$p){ modules(first:50){ nodes { name }
                                                          pageInfo { hasNextPage endCursor } } } }
```

- The connection field is **`nodes`**, not the bare scalar.
- **The default page size is 20.** A single unpaginated call on the 44-module lending package
  returned exactly 20 modules. It did not error, and nothing in the response screamed
  "truncated" unless you read `pageInfo.hasNextPage`.
- `package(address:)` requires the **`0x` prefix**. A bare 64-hex string fails with
  `Failed to parse "SuiAddress": Missing '0x' prefix`.
- Paginate with `after: <endCursor>` until `hasNextPage:false`.

### Why this matters for verdicts

A "module does not exist" claim is a **hard refutation** — it is one of the strongest moves
available (it killed M-04 outright this session: the Sherlock root cause cited
`reward_manager.move`, which is absent; the real module is
`liquidity_mining_reward_manager`). But the refutation is only valid if the enumeration that
produced it was complete.

**Rule: before asserting a module is absent, paginate to `hasNextPage:false` and print the total
count.** Worked result: 44 modules, `reward_manager` absent,
`liquidity_mining_reward_manager` present. That is a citable refutation. "I queried and got
null on the first page" is not.

---

## 3. Stuck-state patterns — the increment/decrement asymmetry

### The pattern

A counter that is **incremented unconditionally** but **decremented only inside a time-gated
branch** is a permanent-brick primitive, even when both halves look individually correct.

Worked case (L-03, `liquidity_mining_reward_manager.txt`):

**Increment** — ops 122-129 of `update_obligation_reward_manager`, fires whenever an
`ObligationReward` slot is first filled:

```
122: CopyLoc[14](loc10: &mut PoolReward)
123: ImmBorrowField[12](PoolReward.num_obligation_reward_managers: u64)
124: ReadRef
125: LdU64(1)
126: Add
127: MoveLoc[14](loc10: &mut PoolReward)
128: MutBorrowField[12](PoolReward.num_obligation_reward_managers: u64)
129: WriteRef
```

**Decrement** — ops 84-90 of `claim_rewards`, inside a branch guarded on end-time:

```
71: Call clock::timestamp_ms(&Clock): u64
73: ImmBorrowField[4](PoolReward.end_time_ms: u64)
75: Ge                                  <- now >= end_time_ms
76: BrFalse(92)                         -> SKIP the decrement
...
84: ImmBorrowField[12](PoolReward.num_obligation_reward_managers: u64)
86: LdU64(1)
87: Sub
```

**Consumer** — `close_pool_reward` (ops 24-30) requires the counter to be exactly zero:

```
24: MoveLoc[5](loc2: u64)
25: LdU64(0)
26: Eq
27: BrFalse(29)
29: Call error::liquidity_mining_not_all_rewards_claimed(): u64
30: Abort
```

**Consequence:** an obligation that accrues a reward slot and exits its position *before*
`end_time_ms` never has its counter decremented, because the decrement is gated on a timestamp
the exiter has no reason to wait for. `close_pool_reward` then aborts forever, the reward
`Balance` stays trapped in the `PoolReward` Bag, and the stale table entry keeps being iterated
by every subsequent `update_obligation_reward_manager` call — which is the same unbounded-scan
gas primitive as H-03, on a second path.

### The check

When you find an `Add` writing a counter field, immediately:

1. `grep` the field name across the whole corpus for every `Sub` / `WriteRef` that could lower it.
2. Read the **guard on each decrement site** — is it unconditional, or gated on time / a role /
   a state flag the relevant actor may never satisfy?
3. Ask: *is there an actor who can increment but who can never reach the decrement branch?*

An unguarded increment paired with a guarded decrement is a stuck-state finding. Report it as
"LIVE (refined)" with the specific unreachable actor named — not as the audit phrased it.

---

## 4. Lifecycle absence — prove "no cleanup path" by grepping for the removal call

### The method

A claim like "obligations can never be closed" is proven by **absence of the removal call across
the entire corpus**, not by reading the create path.

Worked case (L-02):

- `enter_market.txt:66-90` → `obligation::new` → `market::handle_new_obligation`
- `market.txt:443-450` → `handle_new_obligation` is add-only:
  `object_table::add<ID, Obligation<Ty0>>(&mut ObjectTable<ID, Obligation<Ty0>>, ID, ...)`
- **`grep -rn "object_table::remove"` across every disassembled module → ZERO hits.**

The only `remove` calls in the whole package were `oracle_asset_registry.txt:93`
(`table::remove`), `obligation.txt:319` (`wit_table::remove`), and `oracle_x_oracle.txt:923`
(`table::remove`) — all in unrelated subsystems.

### The nuance that makes the claim precise

Read **both levels** before writing "nothing is ever cleaned":

- `obligation.txt:265-323` `unsafe_repay_debt_only` **does** clean the inner per-asset debt
  table — ops 35-44: `if (!debt::has_debt(&Debt)) wit_table::remove<ObligationDebts, ...>`.
- `obligation.txt:144-163` `withdraw_ctokens` → `ctoken_table::split_ctoken`, which does not
  delete the collateral type entry from the `CTokenTable`.
- The `Obligation` object itself and its `Market.obligations` table entry are **never** removed.

So the accurate finding is: *inner per-asset debt entries are reclaimed; the obligation object
and its market-table slot are permanent.* The imprecise version ("no cleanup exists") would have
been wrong, and a triager reading `unsafe_repay_debt_only` would have caught it.

This is the same cheap structural move as the declaration+getter-only immutability proof
(`emode_group` appearing exactly twice across 37 modules → no setter → REFUTED), applied to
lifecycle instead of mutability. **Add-only + no removal call anywhere = permanent state.**

---

## 5. Single-attempt generators over a small GLOBAL namespace

### The pattern

A code/ID generator that makes **one** random attempt and aborts on collision, over a namespace
that is small enough to saturate, is a griefing finding — and the namespace size is computable
from bytecode constants.

Worked case (M-03, `referral.txt:311-381`):

```
31: MoveLoc[1](Arg1: &Random)
32: LdConst[1](u64: 6)                  <- length 6
34: Call generate_random_string(&Random, u64, &mut TxContext): String
36: CopyLoc[0](Arg0: &mut Referral)
37: ImmBorrowField[4](Referral.code_owner: Table<String, address>)
39: Call table::contains<String, address>(...): bool
40: Not
41: BrFalse(43)
45: Call error::referral_invalid_referral_code(): u64
46: Abort                              <- single attempt, no retry loop
```

Charset (`referral.txt:802-869`, `generate_random_string`):

```
19: Call random::generate_u8(&mut RandomGenerator): u8
20: LdU8(36)
21: Mod                                <- base 36
23: CopyLoc[9](loc6: u8)
24: LdU8(10)
25: Lt
28: LdU8(48)  / 30: Add                <- 0-9
33: LdU8(87)  / 35: Add                <- a-z
```

Namespace = **36^6 = 2,176,782,336**.

### The second half of the check — is the namespace global or per-user?

`referral.txt:28-30`:

```
code_owner:      Table<String, address>,
referrer_code:   Table<address, String>,
referee_to_code: Table<address, String>,
```

`code_owner` is keyed by the **code string alone** — globally namespaced. Two users cannot hold
the same code, and an attacker registering codes shrinks the space for everyone else. If the
uniqueness table had been keyed `(address, String)` the finding would have collapsed to
"user retries their own collision", which is noise.

### Method

1. Count the attempts (one `generate_random_string` call, or a loop?).
2. Read the length `LdConst`, the modulus, and the two `Add` constants → compute the space.
3. Check the **key of the uniqueness table** — global or per-user.
4. Report the namespace size as a measured number, never "small".

---

## 6. Report-shape lesson from this round

When a lane is mostly refutations and refinements, the scorecard arithmetic must match the table.
This session published "4 of 10 CONFIRMED LIVE" above a table whose rows read 4 LIVE + 1 REFUTED
+ 1 REFUTED-BY-ABSENCE + 4 LIVE-refined. Count the rows in your own table before writing the
headline number, and state the buckets explicitly (see §9.4 in the parent skill).

Also worth keeping: the deployed package was byte-identical across v1 and v2 for every module
cited (`market.txt`, `market_v1.txt`, `market_v2.txt` all 115,846 bytes), so the upgrade fixed
none of these. When v1≡v2 by md5, say so — it is what makes "unfixed = still live" a valid
headline rather than an assumption.
