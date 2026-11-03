# Reading live Sui Move config via public GraphQL — what works, what is a dead end

Companion to `defending-composed-chain-kill-questions.md` (which cites this file) and
`sui-move-composed-chain-method.md`. Worked case: `current.finance` MainMarket,
`0x41f3d76aee8b20e53f7d0d395fdc09e241e683c7bc5d0f69674b545ee42549df`, verified 2026-10-28.

Endpoint: `https://graphql.mainnet.sui.io/graphql`. JSON-RPC on public fullnodes is **dead** —
`suix_getDynamicFieldObject` returns `-32601 Method not found. JSON-RPC on public fullnodes has
been deprecated.` Do not try it.

---

## 1. THE working recipe — `MarketConfigurationKey`

This is how you get live `close_factor` / `close_factor_bypass_min_value` instead of quoting the
code default. It works because `MarketConfigurationKey` is a real
`dynamic_field::Field<MarketConfigurationKey, MarketConfiguration>`.

```python
q = """
query($id: SuiAddress!, $first: Int) {
  object(address: $id) {
    asMoveObject {
      dynamicFields(first: $first) {
        pageInfo { hasNextPage endCursor }
        nodes { name { type { repr } json } contents { type { repr } json } }
      }
    }
  }
}
"""
```

Find the node whose `name.type.repr` ends `::market::MarketConfigurationKey`, then read
`contents.json.value`. Live MainMarket result:

```json
{"close_factor": {"value": "200000000000000000"}, "close_factor_bypass_min_value": "5"}
```

**`Decimal` wire format:** `{"value": "200000000000000000"}` is 18-decimal fixed point = **0.20**.
Do not read it as 2e17, as a float, or as a dollar amount. `close_factor_bypass_min_value` is a
bare `u64` string (`"5"`), not a `Decimal` — the asymmetry is real and matches the bytecode
(`ImmBorrowField[13](... : u64)` vs `ImmBorrowField[14](... : Decimal)`).

## 2. A Market object exposes exactly THREE dynamic fields

`dynamicFields` on a Market returns only:

| name.type.repr suffix | contents.json.value |
|---|---|
| `::market::ADLRegistryKey` | `AutoDeleverageRegistry` (collaterals + borrows tables) |
| `::market::CircuitBreakKey` | `false` |
| `::market::MarketConfigurationKey` | `{close_factor, close_factor_bypass_min_value}` |

Everything else — `assets`, `reserves`, `ema_spot_tolerance`, `obligations`,
`liquidity_miner` — is a **plain struct field**, and its `sui::table::Table` entries are **not**
enumerated by `dynamicFields`. Top-level keys of the Market JSON are exactly:
`['id','assets','reserves','ema_spot_tolerance','emode_group_registry','obligations','liquidity_miner']`.

## 3. Dead ends — every one of these was tried and returned null. Do not re-burn the calls.

Target: the `ema_spot_tolerance` Table, outer id `0xe9bbe8bdda4d060197b2759b9249b4d2ccaff651cfbd7cf7fb26dca250c76b10`,
inner TableVec id `0xd10a423aebcdd6ce58194f7c7107e822caac791c0ff965b1be5fc49fdb65f757`.

| Attempt | Result |
|---|---|
| `object(address: <table inner id>)` | `{"data":{"object":null}}` |
| `object(address: <table outer id>)` | `{"data":{"object":null}}` |
| `multiGetObjects(keys: [{address: <table id>}])` | `[null]` |
| `dynamicField(name: {type:"0x1::string::String", bcs: ...})` on the Market | `null` |
| `dynamicObjectField(name: {...})` on the Market | `null` |
| `multiGetDynamicObjectFields(keys: [...])` on the Market | `[null]` |
| `dynamicFields(first: 50)` on the TableVec id | `{"data":{"object":null}}` |
| `object(address, rootVersion: 1)` on a table id | `null` |
| JSON-RPC `suix_getDynamicFieldObject` | `-32601` deprecated |

**`bcs` must be base64, not hex.** Hex returns
`Failed to parse "Base64": Invalid Base64 (occurred while parsing "DynamicFieldName")`.
Correct encoding for a `String` / `TypeName` key:
`base64( ULEB128(len(utf8_bytes)) || utf8_bytes )` — i.e. a one-byte length prefix for keys
under 128 chars, then the bytes.

**`ObjectKey` is an input object, not a scalar:** `multiGetObjects(keys: [{address: "0x.."}])`.
Passing a bare string fails with `Expected input type "ObjectKey"`.

## 4. Honest conclusion — and why it does not sink the finding

Per-entry **values** of a `sui::table::Table` / `GenericCoinTypeStorage` are **not retrievable
through the public GraphQL indexer**. You can read the **keys** (the `keys.contents` array — 18
full coin types for MainMarket) but not the values.

So for `ema_spot_tolerance`: the per-asset numeric widths are **UNTESTED, blocker named**. Do not
infer a number, do not assume a default.

**What survives without the values, and it is the reportable claim:** the table has 18 entries,
one per asset, so the tolerance mechanism is *configured*. The defect is that
`validate_liquidation` (market.txt:2511) and `liquidate_calculate_seize_ctokens`
(market.txt:2586-2596) **never read the table**, while the borrow/withdraw risk gate does.
"The protocol configured a per-asset tolerance and the liquidation path does not read it" is a
code defect with a one-line fix. "The protocol forgot to configure a tolerance" invites
"file a config ticket" and dies.

**Rule:** before promising a live number, check whether the target field is a
`dynamic_field::Field` (readable) or a `Table` entry (not readable). `MarketConfigurationKey` is
the former; `GenericCoinTypeStorage` is the latter.

## 5. Pagination

`dynamicFields` `endCursor` is opaque — pass it straight back as `after`. Always read
`pageInfo.hasNextPage` rather than assuming one page. MainMarket needs one call (3 nodes,
`hasNextPage: false`), but a market with many dynamic fields will not.

## 6. Report-on-disk discipline (user's standing instruction for audit sessions)

When the brief says *"the report must ALWAYS exist on disk"*:

1. **First tool call of the session writes the full skeleton** — every section header
   (VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE / MITIGATION /
   VERIFICATION) plus the claim-vs-proof table, a REFUTED section and an UNTESTED section, all
   pre-populated with `UNTESTED` status rows.
2. **Append to a `## PROGRESS LOG` section every N tool calls** (N=5 in the worked session),
   using `patch` with `old_string` = the trailing marker / last log entry, never a full rewrite.
3. Keep a `<!-- APPEND HERE -->` marker or anchor on the last written line so the append target is
   unambiguous.
4. Update the `VERDICT` line at the top on every append — a reader who opens the file mid-session
   must see the current answer in the first screen, not have to scroll to the log.

This is what makes a session that hits the tool-call ceiling still deliver a usable artifact: the
findings are on disk, dated, and cited, even if the final synthesis never got written.
