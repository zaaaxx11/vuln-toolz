# Sui / Move on-chain audit playbook

Worked end-to-end on a live Sui mainnet DeFi target (lending + leverage/margin layer).
Everything below was verified against real RPC responses. Nothing is inferred.

---

## 1. The endpoint situation (read this first — it costs 6+ calls otherwise)

**JSON-RPC on public Sui fullnodes is DEPRECATED.** `POST https://fullnode.mainnet.sui.io`
with `suix_getObject` returns:

```json
{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found. JSON-RPC on public
fullnodes has been deprecated. Please migrate to gRPC or GraphQL endpoints."}}
```

The working endpoint is **GraphQL**, and the path suffix is mandatory:

| URL | Result |
|---|---|
| `https://fullnode.mainnet.sui.io/graphql` | **404** |
| `https://graphql.mainnet.sui.io` | `fault filter abort` (no path) |
| **`https://graphql.mainnet.sui.io/graphql`** | **works** ✅ |

Smoke test before anything else:

```bash
curl -s -X POST https://graphql.mainnet.sui.io/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ chainIdentifier }"}'
# -> {"data":{"chainIdentifier":"4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S"}}
```

Send a browser UA on everything; several Sui-adjacent APIs 403 without one.

Third-party explorers (`suivision.xyz`, `suiscan.xyz`, `api-suivision.xyz`) returned
`403 Your IP or provider is blocked` or empty bodies from this environment. Do not build
the workflow on them; the official GraphQL endpoint is enough.

---

## 2. THE resolver bug — `package()` lies, `module(name:)` does not

This is the single most expensive trap. The public GraphQL endpoint's
`package(address:){ modules{ nodes{ name } } }` resolver **can return a different
package's module list**.

Observed, repeatedly, with the address inlined (not a variable-aliasing artefact):

```
query 0xfe1d8929...6380bf  -> returned package 0x45bae042...19fc70 (20 modules)
query 0x144c57d6...0a92c   -> returned package 0xec244262...3fd769 (14 modules)
query 0x042a1a41...d199e   -> returned package 0xaab00c77...2aade47 (11 modules)
query 0xfbb9f951...58eccf  -> returned package 0xfbb9f951...58eccf  (correct, 1 module)
```

### 2.1 ROOT CAUSE — it is upgrade linkage, not corruption

A later session settled this. It is **not random and not a broken indexer**.
`package(address:)` follows the Sui **upgrade linkage** and returns the *latest*
version's data for whatever package family the address belongs to. On Sui an
in-place upgrade keeps the SAME package address, so `0x144c57d6...` and
`0xec244262...` are the *same* package at different versions, and the resolver
answers both with v2.

**The 3-call proof chain — run it before you call anything a "rogue package":**

```graphql
# (a) is it a package at all, and at what version?
{ object(address:"0x144c57d6..."){ address
    asMovePackage{ __typename address version } } }       # -> MovePackage, version 1
{ package(address:"0xec244262..."){ address version } }    # -> version 2

# (b) CONTROL — a package you know was never upgraded
{ package(address:"0x45bae042..."){ address version } }    # -> returns ITSELF exactly
```

If the control returns its own address, the resolver is exact-match for
non-upgraded packages and the "wrong" answer for the other ID is upgrade
resolution. **Verdict: config drift / migration anomaly, NOT a vulnerability.**

### 2.2 The mixed-package-type signature

When a live object's own type is stamped by v1 while its dynamic-field keys are
stamped by v2, that is the same migration artefact seen from the object side:

```
xOracleId 0x7aca2c7d... -> 0x144c57d6...::x_oracle::XOracle        (v1 type)
  dynamic field keys:
    0x144c57d6...::x_oracle::PythPriceFeedKey                       (v1)
    0xec244262...::x_oracle::PythProFeedKey                          (v2)
    0xec244262...::x_oracle::AssetRegistryKey                        (v2)
    0xec244262...::x_oracle::AdminRefRegistryKey                     (v2)
    0xec244262...::x_oracle::FeedCheckersPassKey                     (v2)
    0xec244262...::x_oracle::StorkFeedRegistryKey                    (v2)
    0xec244262...::x_oracle::PricesDelayToleranceMsKey               (v2)
```

Sui objects keep the type they were created with; upgrade compatibility is handled
by the runtime, not by re-stamping. Only flag it if some *consumer* does an exact
`type ==` match instead of the upgrade-aware `is` check — and even then it is a
code-quality note, not a critical.

### 2.3 What IS accurate

```graphql
# 1. module disassembly, by name — accurate
{ package(address:"0xPKG"){ module(name:"market_type"){ name disassembly } } }

# 2. object type repr — accurate, and this is how you find the REAL package
{ object(address:"0xOBJ"){ address version
    owner{__typename ... on Shared{initialSharedVersion}}
    asMoveObject{ contents{ type{ repr } } } } } }

# 3. dynamic field keys — accurate
{ object(address:"0xOBJ"){ asMoveObject{ contents{ json } }
    dynamicFields{ nodes{ name{ type{ repr } } } } } }
```

`moduleBcs` also works but is base64 bytecode — `disassembly` is human-readable.

**Consequence:** you must already know a module's *name* to fetch it. Get names from
the JS bundle (grep for `pkg::module::Type` strings), from the object type repr, or by
guessing the conventional names (`app`, `admin`, `x_oracle`, `leverage_app`,
`price_feed`, `asset_registry`, `oracle_admin`, `update`, `user_oracle`).

---

## 3. Disassembly format quirks (burned 4 tool calls)

Move bytecode v6 disassembly:

```
// Move bytecode v6
module fe1d8929d13b00aaecd7642dec1c6d41cab82882a1b139efa46bf61dfd6380bf.adl_admin {
use 0000000000000000000000000000000000000000000000000000000000000002::clock;

struct NewADLSetEvent has copy, drop {
	market: TypeName,
	...
}

public new_adl_params<Ty0>(Arg0: &AdminCap, Arg1: &ProtocolApp, Arg2: &Market<Ty0>, ...): DeleverageParams {
L9:	loc0: bool
B0:
	0: LdU64(0)
	...
```

- **There is no `fun` keyword.** Functions are `public <name>(...)` or `entry <name>(...)`.
  `re.findall(r'public fun', dis)` returns **0** even when 5 public functions exist.
- Generics come **after** the name, before the paren: `new_adl_params<Ty0>(`.
- Args are positional and named `Arg0, Arg1, ...` with full types — this is the entire
  access-control story (see §5).
- Structs: `struct AdminCap has store, key {`.
- The `module` line repeats the full package ID — a free cross-check that you fetched
  the module you think you did.

Working extraction regex (see `scripts/sui_disasm_sigs.py`):

```python
for mm in re.finditer(r'^(public|entry) ([A-Za-z0-9_]+)(<[^>]*>)?', dis, re.M):
    start = mm.end()
    if dis[start] != '(': continue          # not a function decl
    depth, i = 1, start + 1                 # balanced-paren scan; [^)]* FAILS on
    while i < len(dis) and depth:           # nested generics like &Market<Ty0>
        depth += (dis[i] == '(') - (dis[i] == ')')
        i += 1
    args = re.sub(r'\s+', ' ', dis[start+1:i-1])
```

---

## 4. Trust graph: from the JS bundle, then CONFIRM on-chain

### 4.1 Mining the bundle

The app bundle is the richest source. Minified, so use `grep -oE` and never read raw
matching lines (they are 10k+ chars each):

```bash
cd evidence
# candidate package/object IDs
grep -oE '0x[0-9a-f]{64}' app_bundle.js | sort | uniq -c | sort -rn

# Move type strings — the highest-signal pattern
grep -oE '0x[0-9a-f]{64}::[a-z_0-9]+::[A-Za-z_0-9]+' app_bundle.js | sort -u

# module::function call sites
grep -oE '[a-z_]+::[a-z_]+' app_bundle.js | sort | uniq -c | sort -rn | head -60

# the config object that ties it together
grep -oE '.{600}protocolPackageId.{900}' app_bundle.js | head -1
```

**Filter out elliptic-curve constants.** Most 64-hex hits in a crypto bundle are
secp256k1 / NIST P-256 constants, not Sui IDs:

```
0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f   <- secp256k1 n
0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff   <- P-256 p
0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798   <- Gx
0x0000000000000000000000000000000000000000000000000000000000000002   <- 0x2 framework
```

Rule of thumb: a real package ID appears **many times** and is always adjacent to a
`::module::Type` string or a `PackageId`/`AppId`/`Id` JSON key. A curve constant appears
once, alone. Also `0x0000...0002` is the Sui framework — ignore.

**Look for the config object.** Bundles commonly embed a `NETWORK_CONFIGS` /
`getNetworkConfig` literal with `flpPackageId`, `protocolPackageId`,
`leveragePackageId`, `xOraclePackageId`, `coinDecimalsRegistryId`, `xOracleId`,
`leverageAppId`, plus a `markets[]` array of `{name, type, objectId, emodeGroups}`.
One grep of ±900 chars around `protocolPackageId` yielded the entire map.

**Fingerprint the fork.** Module names identify the lineage fast. `market_type`,
`obligation_query`, `market_query`, `lbtc`, `hasui`, `usdy`, `afsui` = a
**Scallop-protocol fork**. Knowing the upstream tells you which invariants were
inherited and which are novel.

### 4.2 CONFIRM every ID on-chain — and expect config drift

Never ship a bundle-derived package ID without an RPC check. Two checks per ID:

```graphql
# existence + ownership + version
{ object(address:"0xID"){ address version
    owner{__typename ... on Shared{initialSharedVersion} ... on Immutable{__typename}} } }
```

Then, for every *app/config object ID*, read its **type repr**:

```graphql
{ object(address:"0xAPPID"){ asMoveObject{ contents{ type{ repr } } } } }
```

**This is where the real finding lives.** In the worked hunt the bundle said
`leveragePackageId = 0xaab00c77...` and `xOraclePackageId = 0xec244262...`, but the live
objects typed as:

```
leverageAppId 0xbfcd97b3... -> 0x042a1a41...::leverage_app::LeverageApp
xOracleId     0x7aca2c7d... -> 0x144c57d6...::x_oracle::XOracle
```

Two packages **not present anywhere in the bundle config**. Cross-checking the XOracle
object's dynamic-field keys showed entries from *both* packages
(`0x144c57d6...::x_oracle::PythPriceFeedKey` alongside
`0xec244262...::x_oracle::PythProFeedKey/AssetRegistryKey/AdminRefRegistryKey/
FeedCheckersPassKey/StorkFeedRegistryKey/PricesDelayToleranceMsKey`) — the signature of
a **package migration**, not a vulnerability. Label it exactly that: *config drift /
migration anomaly, needs follow-up*, never "critical". See §2.1 for the 3-call proof.

### 4.2b THE HIGHEST-YIELD ORACLE SOURCE IS THE APP'S OWN CHECK API

For a lending/leverage protocol, the **fastest route to the full oracle config is not
on-chain at all** — it is the frontend's own oracle-status endpoint, usually open with
no auth. Probe these before burning GraphQL calls:

```
https://<app>/api/oracle/check-table      # worked, no auth, 13 KB
https://<app>/api/oracle/status
https://<app>/api/prices
```

Grep the bundle for the route: `grep -oE '/api/[a-z0-9/_-]*oracle[a-z0-9/_-]*' app_bundle.js`.

The response typically gives you, **per asset, in one call**:

| Field | What it tells you |
|---|---|
| `spotPrice` / `emaPrice` | live primary price |
| `checkSpot` / `checkEma` / `checkSpotRaw` | the cross-validation leg |
| `primarySource` / `checkSource` | `1`=Pyth, `2`=Stork, `255`=**ADMIN_REF** |
| `deviationBps` | live divergence between the two legs |
| `lowerBoundBps` / `upperBoundBps` | **the validation band** — the real finding surface |
| `maxTimeGapMs` | freshness window |
| `timeGapMs` | how stale the check leg actually is right now |
| `passed` / `checkStatus` | whether the feed currently passes |

Then **cross-reference against the bundle's embedded config object** (§4.1), which
carries the per-asset `pyth{feedId, channelId, minPublishers, spotConfBps, emaConfBps}`,
`config{primarySourceId, checkSourceId, lowerBoundBps, upperBoundBps, maxUpdateTimeGapMs}`,
and `stork{feedName, emaFeedName}`. The two together answer every oracle-config question
without touching a single dynamic-field table.

**The oracle-config audit checklist** (each item is a real finding class):

1. **`checkSourceId == 255` (ADMIN_REF) on many assets.** Not automatically a vuln — check
   whether *any* asset has `primarySourceId == 255` (that WOULD be admin-priced). What is a
   finding: the admin leg being the *only* cross-check, combined with measured staleness.
2. **`lowerBoundBps`/`upperBoundBps` near 9999.** A ±99.99% band makes the cross-check a
   no-op. In the worked hunt WAL and DEEP had 9999/9999 while every other asset sat at
   500 (5%) or 100 (1%) — and WAL was live-passing at **4487 bps (44.87%) divergence**.
   That is the single cleanest oracle finding available and it needs no source code.
3. **`maxUpdateTimeGapMs` in the millions.** 1,209,600,000 ms = **14 days**. Majors get
   15 s; every LST/wrapped asset can sit 2 weeks stale. Publish the per-asset table.
4. **`minPublishers == 1`** plus **`spotConfBps >= 400`** (4%). Single-publisher feeds with
   a 4% confidence tolerance are the loosest Pyth acceptance in the system.
5. **A live asset in the bundle but ABSENT from the check-table** (or vice versa). In the
   worked hunt the bundle listed 27 assets, the live table 20 — 7 configured assets had
   no live feed. That is a config-drift finding, and it is invisible from either source
   alone. **Always diff the two lists.**

**Bundle-config extraction recipe** (the object literal is not valid JSON — unquoted keys
and `15e3`/`12096e5` exponent literals):

```python
import re, json
src = open('evidence/app_bundle.js', encoding='utf-8', errors='replace').read()
i = src.find('xOracle:{')                       # or whatever the config key is
start = i + len('xOracle:'); depth = 0; j = start
while j < len(src):                             # brace-match to the end of the object
    depth += (src[j] == '{') - (src[j] == '}')
    if depth == 0: break
    j += 1
blob = src[start:j+1]
blob = re.sub(r'([{,]\s*)([A-Za-z_]\w*)\s*:', r'\1"\2":', blob)          # quote keys
blob = re.sub(r'(?<![\w."])(\d+(?:\.\d+)?)[eE](\d+)(?![\w"])',
              lambda m: repr(float(m.group(1))*10**int(m.group(2))), blob)  # 12096e5 -> 1209600000.0
cfg = json.loads(blob)
```

⚠️ **`15e3` and `12096e5` are NOT valid JSON.** `json.loads` fails with
`Expecting property name enclosed in double quotes` — that error is the *unquoted keys*,
and it fires before you ever see the exponent problem. Fix keys first, then exponents,
or you will debug the wrong thing.

### 4.2c Table UIDs inside a registry struct are NOT top-level objects

The dynamic-field *values* of an app object are `Table`/`VecMap` structs whose `id` field
is a **UID nested inside the parent**, not an independently-addressable object:

```json
"value": { "type": {"repr": "0xPKG::asset_registry::XOracleAssetRegistry<0xPKG::asset::AssetConfig>"},
           "json": { "assets": { "id": "0x24f66ea7...288d", "size": "26" } } }
```

`object(address:"0x24f66ea7...288d")` returns `{"data":{"object":null}}`. **Do not spend
calls trying to enumerate table contents this way** — the UID is not queryable as an
object. You get the registry's *size* (useful: it tells you how many assets are
configured, and an empty `size: 0` is a real signal) but not its rows. Read the rows from
the bundle config (§4.2b) or from module disassembly instead.

### 4.3 Ownership verdicts

| `owner.__typename` | Meaning |
|---|---|
| `Immutable` | **No UpgradeCap. Cannot be upgraded. Positive security signal.** |
| `Shared{initialSharedVersion}` | A live shared object (market, oracle, app registry) — the mutable state |
| `AddressOwner` / `ObjectOwner` | Privately held — check who |

A protocol whose packages are all `Immutable` has **no arbitrary-upgrade surface**.
Say so explicitly; it is a real refutation of a whole finding class.

---

## 5. Access control from disassembly

The `Arg0: &AdminCap` / `Arg1: &ProtocolApp` pattern is the whole story. Read it directly.

**Admin-gated (require a capability object):**

```
adl_admin.new_adl_params<Ty0>(Arg0: &AdminCap, Arg1: &ProtocolApp, Arg2: &Market<Ty0>, ...)
adl_admin.enable_collateral_adl<Ty0,Ty1>(Arg0: &AdminCap, Arg1: &ProtocolApp, Arg2: &mut Market<Ty0>, ...)
asset_admin.onboard_new_asset<Ty0,Ty1>(Arg0: &AdminCap, Arg1: &ProtocolApp, Arg2: &mut Market<Ty0>, ...)
asset_admin.update_market_asset_config<Ty0,Ty1>(Arg0: &AdminCap, ...)
emode_admin.onboard_new_emode_group<Ty0>(Arg0: &AdminCap, Arg1: &ProtocolApp, ...)
decimals_admin.register_decimals<Ty0>(Arg0: &AdminCap, Arg1: &ProtocolApp, ...)
leverage_admin.onboard_market<Ty0>(Arg0: &AdminCap, Arg1: &mut LeverageApp, ...)
leverage_admin.inject_protocol_caller_cap(Arg0: &AdminCap, Arg1: &mut LeverageApp, Arg2: PackageCallerCap)
```

**Caller-capability gated (only registered packages):**

```
flash_loan.borrow_flash_loan<Ty0,Ty1>(Arg0: &ProtocolApp, Arg1: &PackageCallerCap, ...)
enter_market.enter_market_with_emode<Ty0>(Arg0: &ProtocolApp, Arg1: &PackageCallerCap, ...)
```

**User-reachable (only need the app + the user's own obligation cap):**

```
deposit.deposit<Ty0,Ty1>(Arg0: &ProtocolApp, Arg1: &mut Market<Ty0>, Arg2: &ObligationOwnerCap, Coin<Ty1>, ...)
borrow.borrow<Ty0,Ty1>(Arg0: &ProtocolApp, Arg1: &ObligationOwnerCap, Arg2: &mut Market<Ty0>, ...)
withdraw.withdraw_as_coin<Ty0,Ty1>(Arg0: &ProtocolApp, ..., Arg2: &ObligationOwnerCap, ...)
leverage_obligation.open_obligation<Ty0>(Arg0: &ProtocolApp, Arg1: &LeverageApp, Arg2: &LeverageMarket, ...)
leverage_swap_borrow.request_leverage<Ty0,Ty1,Ty2>(Arg0: &ProtocolApp, Arg1: &LeverageApp, ..., Arg4: &mut LeverageMarketOwnerCap, ...)
```

**The verdict pattern to publish:** for every public/entry function, answer
*is it admin-only? is a capability object required? can anyone call it?* — with the
exact signature as evidence. `&AdminCap` in `Arg0` on every `*_admin` module function,
with zero exceptions, is a clean access-control result. `&PackageCallerCap` on
flash-loan and eMode entry means only whitelisted packages can use them — also clean.

### 5.1 Oracle-accessor divergence hunting — the highest-yield bytecode technique

Lending protocols routinely ship **several price accessors of differing strength** in the
same oracle package. The finding is when a money-moving path calls the weak one while the
risk checks call the strong one. This needs no source repo — pure disassembly grep.

```bash
# Which accessor does the liquidation module use?
grep -n 'user_oracle' evidence/disasm/liquidate.txt
#   -> 2 hits, both get_spot_price, zero *_with_check   == FINDING

# Which accessor do the risk-check paths use?
grep -c 'with_check' evidence/disasm/market.txt
#   -> 4   == the guarded path exists in the same package
```

Identify the guard by its abort constant — it appears **only** inside the guarded
accessors:

```bash
grep -n 'ema_spot_price_too_different' evidence/disasm/oracle_user_oracle.txt
```

Read the raw accessor's body. If it terminates at `check_price(...)` and `check_price`
aborts solely on a zero price (`oracle_zero_price_error`), then the raw accessor has **no
divergence, no freshness, and no confidence** check — while its sibling computes
`|ema - spot| / spot`, asserts `<= maxDiff`, and aborts otherwise.

**Also check for an asymmetric divergence computation**: one accessor divides by spot,
its sibling by EMA. Same nominal check, materially different effective tolerance.

**Report framing that lands:** *"the deployed code has N oracle accessors with N different
strengths, and the weakest one sits on the money-moving path."* Pair it with the
access-control fact that the caller needs a `PackageCallerCap` — that bounds who can
trigger it, which is what keeps the severity honest.

### 5.2 Value-flow tracing for accounting bugs

Trace a value from its source to its accumulator through the bytecode and look for an
accumulator fed by a **gross** rather than **net** quantity. Worked example —
flash-loan principal counted as referral qualification:

```bash
grep -n 'loan_amount\|increase_usd_qualification\|track_referral' evidence/disasm/flash_loan.txt
#   125:  market::loan_amount(&FlashLoan): u64          <- gross borrowed notional
#   130:  track_referral(&mut Referral, address, u64, ...)
#   242:  referral::increase_usd_qualification(&mut Referral, address, u64)
```

The qualification input is the gross notional with no subtraction of the simultaneous
repayment. The general pattern: any `increase_*_qualification` / `accumulate` /
`add_*_volume` call whose argument traces back to a borrow/loan amount rather than a
deposit amount.

### 5.3 DOC-CLAIM-GAP — diff published security claims against live config

Protocols publish falsifiable security claims on a GitBook security page. Combined with
the app's own open oracle API (§4.2b) you get both sides in two curls, and the finding is
undeniable because it is a direct quotation against a direct measurement.

```
Doc: "EMA–spot divergence detection ... the price is rejected"
Live: deviationBps 4520, bound 9999, passed 1        -> claim false for that asset

Doc: "Staleness gate ... Hard cap: 30 minutes"
Live: timeGapMs 6,150,136,164 (71.2 days)            -> claim false

Doc: "Confidence-interval check ... must sit within a configurable tolerance"
Live: spotConf / emaConf / confTime all null         -> check not running
```

The docs page is usually at
`<org>.gitbook.io/<space>/security-and-risk/technical-details.md` — the `.md` trick from
§6 applies and strips it to ~2 KB.

This is not a code bug; it is a **trust misrepresentation**. Severity it as such, and
always pair it with the config evidence so the claim and the measurement sit side by side.

### 5.4 "Duplicate deployment" is usually upgrade linkage — verify before reporting

The resolver follows upgrade linkage (§2.1), so **two addresses returning identical module
lists are normally ONE package at two versions**, not two deployments. Run the §2.1
3-call proof chain before calling anything a duplicate:

- `object(suspect).asMovePackage.version` → v1
- `package(both).version` → both report v2
- control on a never-upgraded package → returns its own address exactly

Only if the proof chain fails (both genuinely independent, both `Immutable`, live objects
consistently typed by one) is it a real duplicate — and even then it is a **latent
hygiene issue**, not fund theft, unless some consumer resolves package IDs from config
rather than from live object types. Label it exactly that. In the worked hunt this was
initially written up as a finding and the §2.1 proof downgraded it to config drift.

---

```python
for sm in re.finditer(r'^struct ([A-Za-z0-9_]+) has ([^{]+)\{', dis, re.M):
    if re.search(r'(AdminCap|UpgradeCap|CallerCap|OwnerCap|Treasury|Cap)', sm.group(1)):
        print(sm.group(1), 'has', sm.group(2).strip())
```

`has store, key` on `AdminCap` / `PackageCallerCap` / `LeverageMarketOwnerCap` = a
transferable object capability. That is normal for Sui, but note it: a transferable
admin cap means the *holder address* is the trust anchor, and you should try to
identify it (it will be a multisig, per the protocol's own docs).

### 5.5 CORRECTION — a zero from `objects(filter:{type:...})` is NOT "the cap does not exist"

An earlier version of this file said a zero count means "the cap sits in a cold wallet /
multisig not exposed as a queryable object, or the type string is wrong." That is right,
but the *evidence* needed sharpening, because the same session produced both outcomes:

```
flp::AdminCap            -> 1 object, owner 0xfbe0602c...   (AddressOwner)
app::PackageCallerCap    -> 2 objects, owners 0xa11dad45..., 0xcadb2f05...
app::AdminCap            -> 0 objects
```

**The zero is only meaningful if the indexer is demonstrably working for that query shape.**
Prove it with a control type you know has instances (`flp::AdminCap` worked in the same
session, with the identical selection set). If the control returns results and the target
type returns none, the absence is real *for that query* — but it still does not establish
"no AdminCap exists". It establishes **UNKNOWN**, and the report must say UNKNOWN.

Also note the selection set is schema-inconsistent across types in the same session:
`owner { ... on AddressOwner { owner { address } } }` succeeded for `flp::AdminCap` and
errored `Unknown field "owner" on type "AddressOwner"` for `app::AdminCap`. When a type
errors rather than returning empty, **that is a query bug, not a result** — try
`owner { __typename }`, the bare-address form, and a control type before concluding anything.

**Why this matters more than it looks:** the `app::AdminCap` holder is the principal whose
compromise turns every config-level finding (oracle bounds, stale admin refs, fee caps) into
a direct exploit. Naming it is the single highest-value open question in the audit. Resolve
it by walking the `ProtocolApp` creation transaction and the `AdminCap` mint event, or by
scanning the deployer EOA's owned objects — not by one `objects(filter:)` call.

### 5.6 An ended insurance/FLP program can strand funds — read the state flag both ways

`flp` had no withdraw/claim entry (§5.2 of the exploit file) *and* `has_ended: true`. Two
separate facts, both worth publishing:

- **No exit function** = structural: the recorded balances cannot be claimed by anyone.
- **`has_ended: true` + `deposit` gated by `ensure_not_stop`** = operational: no *new* funds
  can enter either. That half is correct design and worth saying — it is what stops the
  finding from being "still bleeding".

Worked state: `total_amount {usdc_flp_amount: 310, sui_flp_amount: 334}`,
`obligation_flps.size: 33`. Small in absolute terms, but a **total loss with no recovery
path**, and the defect generalises: *a program that can be stopped but not unwound.* Note
also that an FLP-style ledger is usually a claim on lending-market reserves rather than a
separate custody contract — say so, so the reader does not picture coins locked in an
unreachable address.

---

## 6. Reading the protocol's own docs (cheap, high signal)

GitBook-hosted docs expose clean markdown and a full index:

```bash
curl -s https://<org>.gitbook.io/<space>/llms.txt            # full page index
curl -s https://<org>.gitbook.io/<space>/<path>/page.md      # append .md to ANY page URL
```

The `.md` suffix works on every page and strips the ~500 KB HTML shell down to ~2 KB of
text. `llms.txt` gives you the complete sitemap in one call. On the worked target this
surfaced the governance model (Watcher / Param-Modifier / SuperAdmin roles with
timelocks), the on-chain safeguards (per-second token-bucket outflow limiter, 24h
sliding-window limiter, per-asset borrow/supply caps), and the oracle design
(EMA primary + spot divergence check, staleness gate, confidence-interval check,
feed pinning) — all of which became REFUTED entries in the report.

---

## 7. Finding the Move source repo (usually the hard part)

The bundle rarely links it. What was tried, in order of yield:

1. **GitHub org repo list** — `curl -s https://api.github.com/orgs/<org>/repos?per_page=100`.
   Returned 45 KB of JSON but zero repo names matched (the org's public repos are
   unrelated). Worth one call.
2. **`git ls-remote` on guessed names** — `current-finance/contracts`,
   `current-finance/current-finance-move`, `CurrentSUI/current-finance`, etc. All
   "Repository not found". Guessing org/repo slugs is low-yield; don't spend more than
   ~4 attempts.
3. **GitHub search API** — `search/repositories?q=<name>+sui+move`. Returned empty
   result sets here. (`search/code` needs auth — `401 Requires authentication`.)
4. **Audit-report PDFs** — the bundle linked
   `https://scalebit.xyz/reports/20260730-Svalbard-Final-Audit-Report.pdf`. Audit
   reports almost always name the package IDs and the repo. **This is the highest-yield
   un-tried lead — do it early, not last.**
   ⚠️ **Verify whose audit it is before citing it.** The PDF linked from the target's own
   marketing site turned out to be an audit of **Svalbard Capital** — a cross-chain BTC
   wrapper the protocol uses as *collateral*, not an audit of the protocol itself. Read
   the "Project Information" page (page 2 of a ScaleBit report) and check the
   `Source Code` repo URL and the `Files in Scope` paths against your target before
   treating any `file:line` from it as evidence about the target.
   If it IS a partner audit, it is still useful in a different way: it tells you which
   third-party assets are collateral in your target, and those partners have their own
   public repos (`github.com/Svalbard-Capital/contracts`) worth auditing separately.
5. **The docs' audit-reports page** — lists Sherlock / Movebit / Asymptotic / Zellic
   reports. Same reasoning.
6. **⭐ SEARCH FOR THE AUDITOR'S PUBLIC WORKSPACE REPO — this is the lead that
   actually paid off.** `search/repositories?q=<protocol name>` surfaced
   `0xca1x/sherlock-audit-current-finance-2026`, a warden's personal workspace holding
   **the entire finding set with verified Move PoCs**. It contained 6 oracle findings
   (H-02, M-05, M-11, M-14, M-17) with harnesses, raw `sui move test` output, and
   quantified impact — corroborating evidence worth more than a day of source reading.

   ```bash
   # find it
   curl -s "https://api.github.com/search/repositories?q=<protocol-name>"
   # list everything in it (one call, recursive)
   curl -s "https://api.github.com/repos/<owner>/<repo>/git/trees/main?recursive=1"
   # read the submodule pointer — the target repo is usually a git submodule
   curl -s "https://raw.githubusercontent.com/<owner>/<repo>/main/.gitmodules"
   ```

   The workspace's `findings/*-analysis.md` are the richest artefacts: root cause with
   `file:line` into the target repo, pre-conditions, attack path, and a **Validation
   Status** section. Read the analysis variant, not the `*-issue.md` variant.

   ⚠️ The `target_repo/` is a **git submodule pointing at a private/404 repo**
   (`sherlock-audit/2026-03-<contest>-<warden>.git` → 404 on both `main` and `master`).
   You get the findings but not the source. Still a massive win: the findings cite exact
   `file:line`, which tells you what to look for in the disassembly.

**When the source is unavailable, say so plainly and pivot to disassembly.** The honest
report states: *"no Move source retrieved; all code evidence is on-chain bytecode
disassembly, not source"*. Do not present disassembly line numbers as `file:line`.

### 7.1 "Empty repo" vs "wiped repo" — prove which

A repo that clones successfully but contains nothing is ambiguous, and the difference
matters to a triager. Three commands settle it:

```bash
cd <cloned-repo> && git fsck --lost-found && git reflog && git count-objects -v
```

```
count: 0 / in-pack: 0 / packs: 0 / garbage: 0
notice: HEAD points to an unborn branch (main)
```

Zero objects and zero packs = the **history was wiped**, not just the files deleted. Write
**"unrecoverable"**, not "empty" — and note that a repo whose description still says
"Content coming real soon!!!" with a recent push date is a repo that *had* content. That is
worth one line in the report as a supply-chain observation (the team demonstrably can
publish and then remove contract source), but it is not a vulnerability.

### 7.2 A public `pre.<target>` staging host is a cheap closed-surface proof

If DNS resolves `pre.<apex>`, diff its bundle against prod. Identical byte length plus a
normalised diff of only chunk-hash names and self-referential config means the staging
environment adds no attack surface — and saying so stops the next session re-spending
budget on it.

```bash
curl -s https://pre.<apex>/ | grep -oE 'src="[^"]*\.js"'
curl -s https://pre.<apex>/assets/<chunk>.js -o pre.js
md5sum pre.js <prod bundle>       # lengths equal, hashes differ -> chunk renaming only
```

Then normalise and block-compare (2000-char blocks, char-level first-divergence inside each
differing block):

```python
import re
def norm(s):
    s = re.sub(r'[A-Za-z0-9_-]{8,}-[A-Za-z0-9_-]{8}\.js', 'CHUNK.js', s)
    s = re.sub(r'index-[A-Za-z0-9_-]{6,10}\.js', 'index-H.js', s)
    return s
na, nb = norm(prod), norm(pre)
for i in range(0, len(na), 2000):
    if na[i:i+2000] != nb[i:i+2000]:
        ba, bb = na[i:i+2000], nb[i:i+2000]
        j = 0
        while j < min(len(ba), len(bb)) and ba[j] == bb[j]: j += 1
        k = j
        while k < min(len(ba), len(bb)) and ba[k] != bb[k]: k += 1
        print(f'=== @{i} char {j} ===\n PROD: {ba[max(0,j-80):k+80]!r}\n PRE : {bb[max(0,j-80):k+80]!r}')
```

Worked result: 3 semantic diffs, all benign — self-referential `APP_DOMAIN`, a separate
Mixpanel token with `debug:true`, and chunk filenames. **Zero** differences in contract
package IDs, API hosts, feature flags, or whitelist logic. Report as CLOSED, and note the
`debug:true` analytics as an information-hygiene nit rather than a vulnerability.

### 7.1 GraphQL schema gotchas that each cost a call

The Sui GraphQL schema is stricter than it looks. Errors are precise — read them, don't
retry blindly:

| You wrote | Error | Fix |
|---|---|---|
| `$a: Address!` | `Variable "a" cannot be of non-input type "Address"` | use **`String!`** — `Address` is an output type, not an input type |
| `upgradeCap{__typename}` on `MovePackage` | `Unknown field "upgradeCap" on type "MovePackage"` | the field does not exist; use `object{asMovePackage{version}}` |
| `modules(first:60)` | `Page size is too large: 60 > 50` | cap is **50** |
| `module(package:...,module:...)` | `Unknown field "module" on type "Query"` | it is `package(address:){ module(name:){...} }`, nested |
| `asPackage` | `Did you mean "asMovePackage"?` | it is `asMovePackage` |
| `dynamicFields{ name{ repr } }` | `Unknown field "repr" on type "MoveValue"` | use `name{ type{ repr } json }` |
| `dynamicFields{ valueJson }` | `Unknown field "valueJson" on type "DynamicField"` | use `value{ ... on MoveValue{ type{repr} json } }` |
| `object{ ... pageInfo }` | `Unknown field "pageInfo" on type "Object"` | `pageInfo` lives on the **connection**, not the object |
| `... on MoveObject{ asMoveObject{...} }` | `Unknown field "asMoveObject" on type "MoveObject"` | drop it — you are already inside `asMoveObject` |
| `object{ ... on MoveObject{ contents } }` | `Fragment cannot be spread here as objects of type "Object" can never be of type "MoveObject"` | the fragment goes INSIDE `asMoveObject`: `object{ asMoveObject{ contents } }` |
| `functions{ name }` on a module | `Unknown field "name" on type "MoveFunctionConnection"` | it is a **connection** — `functions{ nodes{ name ... } }` |
| `parameters{ type{ repr } }` | `Unknown field "type" on type "OpenMoveType"` | `OpenMoveType` has **`repr` directly** — `parameters{ repr }`, no nesting |
| `owner{ ... on AddressOwner{ address } }` | `Field "address" of type "Address" must have a selection of subfields` | `Address` is an OBJECT — `owner{ ... on AddressOwner{ address{ address } } }` (double `address`) |
| `objects(filter:{type:$t})` with `$t: Address!` | `Variable "t" cannot be of non-input type "Address"` | `$t: String!` — same input-type rule as every other address arg |
| `dynamicField(name:{json:"..."})` | `Unknown field "json" of type "DynamicFieldName"` | `DynamicFieldName` takes **`type` (String) / `bcs` (Base64) / `literal` (String)** — there is no `json` input |
| `dynamicField(...){ asMoveValue{ json } }` | `Unknown field "asMoveValue" on type "DynamicField"` | the accessor is `value { ... on MoveValue { json } }` |
| `contents{ type }` | `Field "type" of type "MoveType" must have a selection of subfields"` | `MoveType` is an object — `contents{ type{ repr } }` |
| `package(...){ module{ structs{ name fields } } }` | `Unknown field "name" on type "MoveStructConnection"` | `structs` is a connection — `structs{ nodes{ name fields{ name type } } }` |
| `object(address:"<table uid>")` | `{"data":{"object":null}}` | a nested Table UID is not an object (§4.2c) — read the `size` from the parent, pivot for rows |

The `... on MoveValue{ type{repr} json }` fragment is the workhorse for reading dynamic
field values. For nested objects use `... on MoveObject{ address }`.

### 7.1b STOP GUESSING FIELD NAMES — introspect the schema in one call

Every gotcha in the table above cost a call because the field name was guessed. The endpoint
exposes full introspection, so discover the shape instead:

```graphql
# what can I select on a type?
{ __type(name:"DynamicField"){ fields{ name type{ name kind ofType{ name kind } } } } }
# what can I pass as an input?
{ __type(name:"DynamicFieldName"){ inputFields{ name type{ name kind ofType{ name kind } } } } }
# what are the concrete types behind an interface/union?
{ __type(name:"DynamicFieldValue"){ possibleTypes{ name } } }
```

Worked result on the live endpoint:

```
DynamicField        -> ... value :: DynamicField ...
DynamicFieldValue   -> possibleTypes: [MoveObject, MoveValue]
MoveValue           -> asAddress, asVector, bcs, display, extract, format, json, type
DynamicFieldName    -> type (String), bcs (Base64), literal (String)
```

That is three calls that replace six failed guesses. **When a query errors on an unknown
field, introspect the parent type before retrying.**

### 7.1c Reading ONE dynamic field by key — and the ambiguity trap

Discovery (what keys exist, and their JSON shape) uses the **list** form, which does accept
`json` on the name:

```graphql
{ object(address:"0xMARKET"){ dynamicFields(first: 20){ nodes{ name{ json } value{ ... on MoveValue{ json } } } } } }
```

Lookup by key uses the **single** form, and the key is NOT json:

```graphql
{ object(address:"0xMARKET"){ dynamicField(name:{type:"0xPKG::market::EModeGroupRegistryKey"}){ value{ ... on MoveValue{ json } } } } }
```

⚠️ **Several dynamic fields can share a key type.** On the worked target all three of the
Market's dynamic fields had key type `...::market::*Key` with body `{"dummy_field": false}`,
so `name:{type:"..."}` alone is **ambiguous** and may resolve to the wrong row. When the
`name{ json }` bodies are identical across entries, disambiguate with
`name:{ bcs: "<base64 of the serialized key>" }`, or stay on the list form and match on the
value's JSON instead. Do not assume a type-keyed lookup is unique.

⚠️ **A nested Table's rows still will not resolve.** The registry's `groups` field is a
`Table` whose `id` is a UID inside the parent (§4.2c): `object(address:"<table uid>")`
returns `{"data":{"object":null}}`. You get `size` — which is real precondition evidence
(e.g. `"groups": {"size": 15}` proves 15 fee rows exist) — but not the rows. For the rows,
pivot to the app's own API or to module disassembly, exactly as §4.2c says.

**Batch independent queries into one curl** — two packages, two objects — with a `sleep 1`
between calls to stay friendly. One `terminal` call can run 4–6 GraphQL queries and print
all results, which matters a lot under a tool-call budget.

---

## 8. Report skeleton that worked

`findings/<TRACK>.md` created as the FIRST action, appended every ~5 tool calls:

```
VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE /
MITIGATION / VERIFICATION
+ claim-vs-proof table (Claim | Proof (RPC / file:line) | Status)
+ REFUTED
+ UNTESTED
+ APPEND LOG (one block per 5 tool calls)
```

Save every raw RPC response to `evidence/rpc/` — `pkg_<id>.json`,
`modules/<pkg>_<module>.json`, `xoracle_obj.json` — plus a consolidated
`all_signatures.txt`. A future session (or the adversary subagent) can then re-verify
without re-querying.

---

## 9. Sui-specific pitfalls

- **`package{modules}` returns the wrong package.** Use `module(name:){disassembly}`.
  Verify the `module <pkgid>.<name>` header line matches the ID you asked for.
- **No `fun` keyword in disassembly.** `public <name>(` / `entry <name>(`.
- **`[^)]*` fails on generic args.** `&Market<Ty0>` contains no `)` but
  `Option<String>` and nested generics break naive patterns — use a balanced-paren scan.
- **`/graphql` on the fullnode 404s; the host is `graphql.mainnet.sui.io`.**
- **Curve constants masquerade as package IDs.** Require repetition + `::module::Type`
  adjacency.
- **Config drift is common and is NOT a vulnerability.** The bundle's package IDs can be
  a migration generation behind the live objects. Confirm via object type repr, then
  label it "config drift / migration anomaly — needs follow-up".
- **A shared object's `initialSharedVersion` is a useful stability anchor** — it never
  changes, so it is safe to cite in a report.
- **Don't pipe `curl` into `python3`** in this toolchain — the security scan flags
  `curl | interpreter`. Write to a file under `evidence/`, then read it. This also gives
  you the evidence artefact for free.
- **`.dev` / lookalike-TLD endpoints get flagged** by the command scanner. Prefer the
  documented official endpoint over a community node.
- **`package{modules}` returning a "wrong" package is UPGRADE LINKAGE, not corruption.**
  Run the 3-call proof (§2.1) — `asMovePackage{version}` on the suspect, `package{version}`
  on both, and a CONTROL on a never-upgraded package — before calling anything a rogue
  package. Same-package-two-versions is the normal explanation.
- **A live object's type can be stamped by v1 while its dynamic fields are stamped by v2.**
  That is the migration artefact from the object side (§2.2), not a type-confusion bug.
- **Table UIDs nested in a registry struct are not queryable objects.**
  `object(address:"<table uid>")` → `{"object":null}`. You get the `size` only. Read rows
  from the bundle config or disassembly (§4.2c).
- **The app's own open oracle-status API beats on-chain enumeration.** Try
  `/api/oracle/check-table` (and bundle-grep for the route) before spending GraphQL calls.
  It returns per-asset bounds, sources, live divergence and staleness in one 13 KB call
  (§4.2b).
- **`15e3` / `12096e5` exponent literals break `json.loads` on a bundle config object.**
  Quote the keys FIRST, then convert exponents, or the error message points at the wrong
  problem (§4.2b).
- **Diff the bundle's asset list against the live check-table.** 27 configured vs 20 live
  meant 7 assets had no feed at all — invisible from either source alone (§4.2b item 5).
- **A `lowerBoundBps`/`upperBoundBps` of 9999 is the cleanest oracle finding there is.**
  It needs no source code: the live API already prints the divergence that the band is
  supposed to reject. In the worked hunt WAL passed at 4487 bps under a ±99.99% band.
- **Diff the protocol's published security page against the live config — the
  DOC-CLAIM-GAP class.** Docs claimed EMA/spot divergence rejection, a 30-minute staleness
  hard cap, and a confidence-interval check; the live table showed a 45% divergence passing
  under a 9999-bps band, a 71-day-stale admin reference, and every confidence field `null`.
  Two curls, undeniable, and it compounds every oracle finding you already have (§5.3).
- **Two addresses with identical module lists are ONE package at two versions until proven
  otherwise.** Run the §2.1 3-call proof before writing up a "duplicate deployment"
  finding; in the worked hunt that call was an over-call the proof immediately downgraded
  to config drift (§5.4).
- **An audit PDF linked from the target's own site may audit an integration partner, not
  the target.** Check the Project Information page and `Files in Scope` paths before citing
  any `file:line` from it (§7 item 4).
- **`checkSource == 255` (ADMIN_REF) is only a finding in combination.** No asset had
  `primarySourceId == 255`, so admin could not set prices directly. The finding was the
  *staleness of the admin leg* (1.3–71 days measured) combined with a 14-day tolerance.
  Report the combination, not the constant.
- **`search/repositories?q=<protocol>` finds the auditor's public workspace repo.** That
  is where verified findings + Move PoCs live, and it is a better corroboration source
  than the (usually private) target repo (§7 item 6).
- **Sui GraphQL input variables must be `String!`, not `Address!`.** `Address` is an
  output type. This is the single most common first-query failure (§7.1).
- **`modules(first:N)` caps at 50.** Asking for 60 returns a validation error, not a
  truncated page.
- **A zero from `objects(filter:{type:"...::app::AdminCap"})` is UNKNOWN, not "does not
  exist".** Prove the indexer works with a control type in the same session before trusting
  any zero, and expect the owner selection set to error on some types while succeeding on
  others (§5.5). Naming the AdminCap holder is the highest-value open question in the audit —
  resolve it via the `ProtocolApp` creation tx and the mint event, not one filter call.
- **The app's obligation count is not the chain's.** Dashboard said 2,664 for MainMarket;
  the on-chain `Market.obligations` ObjectTable size was 54,274 (~20×). For any victim-set
  or exposure count, read the on-chain table size and publish both numbers with the
  discrepancy named (§8.1 of the exploit file).
- **Run `grep -rc 'with_check'` across the WHOLE package before writing up an oracle
  divergence.** A package-wide zero means every entry point in it prices off raw spot, which
  converts a whitelist-gated module bug into an any-user subsystem bug. One command, and it
  changes the severity conversation (§1.5 of the exploit file).
- **An ended FLP/insurance program with no withdraw entry strands funds.** Publish the
  structural fact (no exit function) and the operational fact (`has_ended: true` plus
  `deposit` gated by `ensure_not_stop`, so it is not still bleeding) separately (§5.6).
- **"Empty repo" vs "wiped repo"** — `git fsck` + `count-objects -v` distinguishes them;
  write "unrecoverable", not "empty" (§7.1).
- **A public `pre.<apex>` staging host is worth one bundle diff, not a hunt.** Identical
  byte length + normalised diff of only chunk names and self-referential config = CLOSED
  surface (§7.2).
