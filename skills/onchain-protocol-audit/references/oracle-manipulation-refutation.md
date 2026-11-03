# Oracle-manipulation hunts — refuting the vector by proving price never reaches the mint amount

Companion to `oracle-liveness-and-hidden-markets.md` (liveness class, Sui) and
`unguarded-value-sweeping-entrypoints.md` (the "no guard at all" class). This file covers the third
outcome a price-oracle brief can have: **every manipulation hypothesis is individually closed, and
the reason is structural — the price module is wired only into budget/fee planners, never into the
`amount` that mint/burn/withdraw uses.**

Worked case: Relay `RelayPriceOracle.sol` (772 lines) on chain 537713, asked to prove whether an
attacker can manipulate prices used for mint/burn/withdraw. Verdict: **REFUTED**, no CRITICAL.
Everything below is the reusable method plus the exact evidence shapes, so the next engagement
reaches the same verdict in one pass instead of six rounds.

---

## 1. THE ORDER OF OPERATIONS — answer "who consumes the price" BEFORE any gate analysis

The brief will hand you 7 hypotheses (staleness, future ts, signature, replay, batch, adapter,
consumer) and it is natural to start at H1. **Do not.** Every one of them collapses in importance if
the answer to H7 is "nobody in the value path". Run the consumer sweep first — it costs two greps
and it decides the severity ceiling for the whole engagement.

```bash
# (a) who calls the price API at all?
grep -rn "resolveUsdPrice\|resolveBidAsk\|IPricingOracle\|IBidAskOracle" --include=*.sol contracts/ \
  | grep -v "<OracleFile>.sol"

# (b) does the mint/burn/withdraw executor touch price ANY way?
grep -n -i "price\|oracle" contracts/RelayOracleV2.sol contracts/RelayHub.sol \
  contracts/RelayExecutor.sol contracts/RelayAllocator.sol contracts/WithdrawGasPayer.sol
```

Grep (b) returning ONLY `oracle`-as-signer (`ORACLE_ROLE`, `isValidSignatureNow`, `UnauthorizedOracle`)
and zero `price` is the refutation, written down. In the Relay case `RelayOracleV2._executeAction`
decodes `amount` straight out of the oracle-signed payload and calls
`HUB.mint(hubToAddress, hubTokenId, amount)` (`RelayOracleV2.sol:269-301`, `:374`). No conversion,
no price read. State it in those terms: **the amount is attested, not computed.**

Then classify the consumers you did find into severity tiers:

| Consumer | What price changes | Ceiling if price were fully attacker-controlled |
|---|---|---|
| rate limiter (`RelayUsdRateLimiter._toUsdValue`) | budget consumption | DoS or budget bypass — **not** mint size |
| fee calculator (`RelayBpsFeeCalculator._toUsdValue`) | fee amount | fee over/under-charge, capped by attested `maxFeeAmount` |
| deposit-address manager | hash preimage (`triggerHash`) | replay/ID collision surface |
| signed-price fallback | fallback price | gated on solver signature |

Anything whose only effect is *how much budget is debited* is a planner, not a mint. Say so and the
severity for the whole oracle lane drops to LOW/role-only in one paragraph.

---

## 2. THE SEVEN GATES — where each one actually lives (do not assume the oracle holds them)

A recurring trap: the oracle contract looks like it should verify signatures, and it does not. It
delegates. Read the delegation before writing "signature not bound".

| Hypothesis | Gate location in the Relay stack | Verdict shape |
|---|---|---|
| **H1 staleness** | oracle `_resolveFeed` L668 `expiration = publishTime + route.maxAgeSeconds`; L674 `if (block.timestamp > expiration) revert PriceExpired` | GATE EXISTS; ceiling = config value |
| **H2 future ts** | L661-665 `publishTime > block.timestamp + providerMaxFutureSeconds[providerId]` → revert; setter capped L326 | GATE EXISTS; per-provider, not global |
| **H3 signature** | **NOT in the oracle.** L653 calls `IPriceFeedAdapter(adapter).decodeAndVerify(route.feedId, updateData)`; `updateData` comes from `PriceOraclePrecompile.getFeedUpdate(...)` L648, **not a user parameter**; adapter has `onlyOracle` (`StorkFastAdapter.sol:175`) | CLOSED — attacker cannot supply data or call the adapter |
| **H4 replay / nonce** | none in the oracle; only `cachedPublishTimes` rollback guard L678-691 (`<` reverts, `>` writes, `==` passes). Idempotency is a *different* contract on the mint lane | REFUTED for profit — replay gives no better price |
| **H5 batch / index mismatch** | `setFeedRoutes` L255-268 length-equal check; every resolver single-array → single-output, cap L471/L489 etc. | REFUTED — the two-array `tokenId[]`/`price[]` API does not exist |
| **H6 adapter injection** | `setPriceFeedAdapter` L297 `onlyOwner` + binding `adapter.ORACLE() == address(this)` L308-325 | ROLE-ONLY (trust the owner) |
| **H7 consumer** | see §1 | often DEAD-CODE / REFUTED |

**Rule:** when a brief says "check whether `decodeAndVerify` verifies the signature", the honest
answer is often *"the oracle does not; the adapter does, and the attacker-facing surface is the
oracle, whose input is precompile-sourced."* Write it that way; do not report "missing signature
check" on the oracle.

**The `MAX_*_UPPER_BOUND` trap (this is the one that generates false positives).** A constant named
`MAX_AGE_SECONDS_UPPER_BOUND = 300` is a **ceiling on configuration**, not the enforced value. The
enforced value is per-route storage. Two drafts of this audit wrote "owner can set 300s → 5-minute-old
price accepted" before the on-chain read showed the production route at **30s**. Always resolve
`upper bound` (constant) vs `actual` (storage) vs `per-provider` (second mapping) as three separate
reads, and quote all three:

```
MAX_AGE_SECONDS_UPPER_BOUND()        = 300      (constant, config ceiling)
feedRoutes(USDC_BASE).maxAgeSeconds  = 30       (the enforced value — quote THIS)
providerMaxFutureSeconds(provider)   = 12       (second, independent per-provider cap)
MAX_FUTURE_SECONDS_UPPER_BOUND()     = 60       (constant, config ceiling)
```

Reporting the constant as the live value is a self-inflicted false positive. Reporting all three
with the storage one named "production value" is a finding-grade statement.

---

## 3. LIVE EVIDENCE — the exact `eth_call` set, with the selectors already decoded

Retrieve prod addresses from the repo manifest first — never guess:
`deployments/contracts/prod.json` (per-chain) and `packages/networks/src/networks/relay.ts`
(`prod.priceOracle`). Relay chain 537713 = `https://rpc.chain.relay.link`, earliest block 1215200.

```python
# selectors (keccak first 4 bytes)
owner()                         8da5cb5b
feedRoutes(uint256)             978be198
priceFeedAdapters(bytes32)      8b14f904
providerMaxFutureSeconds(b32)   <compute>
cachedPublishTimes(b32,b32)     <compute>
resolveUsdPrice(uint256)        2d40ab58
resolveUsdPrices(uint256[])     c332e29f
decodeAndVerify(bytes32,bytes)  b5fc7a3b
setPriceFeedAdapter(...)        daa9aacb   # onlyOwner probe
consume(uint256,uint256,bytes)  <compute>  # rate-limiter role probe
```

`feedRoutes` returns a packed 5-word struct — decode positionally, do not trust the ABI name
ordering (`providerId, feedId, currencyDecimals, maxAgeSeconds, exists`):

```
0x477a6446...18d1   providerId
0x3570e5a0...7ab63  feedId
0x...0006           currencyDecimals = 6
0x...001e           maxAgeSeconds = 30      <-- the number that matters
0x...0001           exists = true
```

**Revert selectors you WILL hit — map them once, up front.** Print `error` before `result` and never
label a revert as success:

```
d86ad9cf  UnauthorizedCaller(address)              <- adapter gate: onlyOracle
118cdaa7  OwnableUnauthorizedAccount(address)      <- onlyOwner
4ee8ebd4  PriceTimestampTooFarInFuture(uint256,uint256)
62101450  PriceExpired(uint256,uint256)
14ec93c7  PriceTimestampRollback(bytes32,bytes32,uint256,uint256)
b452d8a4  PriceBatchTooLarge(uint256,uint256)
a09c4a71  FeedRouteNotFound(uint256)
b08afaaf  PriceFeedAdapterNotFound(bytes32)
2a864497  InvalidPublishTime()
e7d28d10  NonPositivePrice(int128)
e2517d3f  AccessControlUnauthorizedAccount(address,bytes32)
```

A permissionless read returning a `Price` struct is the positive control — it proves the probes run
at all and gives you `publishTime`/`expiration` to compute the live freshness window
(`expiration - publishTime` should equal the route's `maxAgeSeconds`, here exactly 30).

**Bytecode-vs-source check without forge** (deployed contract, no source available locally):
scan the runtime hex for `63<8 hex>` (PUSH4 dispatch constants) and diff the selector set against
`forge inspect`/known signatures. Relay's 7945-byte runtime yielded exactly the 10 real selectors +
47 custom-error selectors → no hidden unguarded setter. Fold in the arithmetic/panic selectors
(`4e487b71`) so you do not mistake them for entrypoints.

---

## 4. THE STRUCTURAL REFUTATION — when the limiter makes manipulation worthless

The strongest refutation this session was not an oracle gate; it was reading the *consumer's*
arithmetic. `RelayUsdRateLimiter._calculateRefill` (`L380-388`):

```solidity
return FixedPointMathLib.min(capacity, tokens + timeDiff * rate);
```

with live bucket values read on-chain:

```
getBucket("base")  tokens=10000e18  capacity=10000e18  rate=10000e18/s  isEnabled=true
```

`rate == capacity` means **one second of elapsed time refills the bucket to full**. The limiter is
therefore not a rate limiter at all — it is a hard per-request ceiling (`capacity < usdValue` at
L168), and the "rate" dimension does nothing.

Consequence chain for an oracle brief, and it is decisive:

- **Underprice** → smaller `usdValue` → nothing saved, because the budget was already full. No
  profit, no capacity unlocked.
- **Overprice** → larger `usdValue` → hits the `capacity` ceiling *sooner*. Strictly worse for the
  attacker. It does not increase what can be minted, because mint size never came from the price.

So even a fully-controlled price in this lane is **economically inert**. Always read the consumer's
refill/cap formula and its live parameters before assigning severity to an oracle finding; a
manipulable price into a non-binding constraint is informational.

Same discipline on the fee side: `RelayBpsFeeCalculator` caps with an oracle-attested
`maxFeeAmount` (L65-78). The cap is an *upper* bound, so a **lower** price does lower the fee — that
is the only real residual surface, and it requires the provider-signed feed to actually move.

---

## 5. DEAD CODE IS A FINDING — count it, do not footnote it

`resolveBidAsk*` + `IBidAskOracle` accounted for **23 references inside the 772-line oracle (~45% of
the file)** and had **zero non-test consumers**:

```bash
grep -rn "resolveBidAsk" --include=*.sol . | grep -v "<OracleFile>.sol"
# -> test/StorkFastAdapter, test/RelayPriceOracle, test/ChainlinkDataStreamsAdapter, and the
#    interface declaration itself. Nothing in contracts/.
```

Report shape that worked: "N% of the module is unreachable in production; it has no value-path
consumer, it enlarges the audit surface, and it should be deleted rather than deployed." Quantify the
line share — "half of this contract is dead" lands, "bid/ask appears unused" gets skimmed.

Also worth flagging while you are in the file: the oracle never checks `usdPrice == 0` (only
`publishTime == 0`, L657-659). Both live adapters revert `NonPositivePrice` upstream so it is
unreachable today — file it as defense-in-depth, not a bug, and say exactly that.

---

## 6. SELF-CORRECTION DISCIPLINE FOR THIS LANE

Two predictions were wrong mid-audit and were corrected on the record rather than quietly dropped.
Carry this habit: it is what keeps a REFUTED report credible.

1. **"Owner can set maxAge 300 / maxFuture 60"** → production storage was 30 / 12. Constants
   misread as live values. Fix: §2's three-read rule.
2. **H5 predicted `tokenId[]`/`price[]` index mismatch** → no such dual-array API exists; all
   resolvers are single-array in, single-array out. Fix: grep the interface signatures before
   theorising about a mismatch. Two rounds with no proof = mark BLOCKED/REFUTED, not "likely".

Write a `KOREKSI DIRI` block in the report listing what you predicted and what the evidence said.
A refutation that silently deletes its own earlier guesses reads as a guess; one that shows the
correction reads as an audit.

---

## 7. CHECKLIST — oracle brief, ~30 minutes to a defensible verdict

1. Read the oracle in full; mark every `require`/`revert`/custom error with file:line.
2. **Consumer sweep first (§1).** Does any consumer fold price into `amount`? If no → severity
   ceiling is LOW; say it in the first paragraph of the report.
3. Resolve constants vs storage vs per-provider caps (§2). Quote the storage value as production.
4. Read the adapter's caller gate and where `updateData` originates — signature verification is
   usually there, not in the oracle.
5. Live: `codesize`, `owner()`, `feedRoutes(realTokenId)`, adapter address, `ORACLE()` binding,
   per-provider caps, one `resolveUsdPrice` positive control, one negative `consume`/setter probe.
   Map every revert selector to its custom error before writing a verdict.
6. Read the consumer's refill/cap formula + live params. Non-binding constraint → inert (§4).
7. Count dead-code line share (§5).
8. Emit per-hypothesis verdict as PROVEN-CRITICAL / ROLE-ONLY / GATE-EXISTS / REFUTED / DEAD-CODE /
   BLOCKED, each with file:line or raw hex. Append incrementally to the report file.
