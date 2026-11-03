# Relay Protocol audit notes (session-specific reference)

Produced during a live hunt on the Relay Protocol settlement + oracle stack.
Use these as prior art / false-positive guards / verification recipes for future engagements.

## Confirmed code patterns

- `RelayExecutor.execute` does NOT bind `callResolver` / `callResolverData` in the EIP-712 digest. Developer comment in `RelayExecutor.sol` explicitly says they are "not direct fields in the EIP-712 request".
- `BasicCallResolver.execute` is `external nonReentrant` with NO caller guard. It sweeps `HUB.balanceOf(address(this), tokenId)` to `sweep.recipient`.
- `RelayHub.transferFrom` has no authz; underflow is accidentally covered for `amount > 0`, but `amount == 0` returns true and emits ERC-20 `Transfer` (event-spoof only, no balance change).
  - **RETRACTED (later session re-test):** the "allowance silently decremented, 1-unit approval moves the balance" claim is **FALSE** on the live Hub. `allowed - amount` underflows and reverts `panic 0x11`, so allowance IS enforced as a cap. See `bytecode-disassembly-and-state-override.md` §3c (retraction box) and `inherited-findings-and-silent-rpc-failures.md` §2 for the 3-row matrix that must be run before any no-cap claim.
- **Live storage layout differs from the brief's table** (slot 5↔6 were swapped): `_isOperator=3`, `balanceOf=4`, `allowance=5`, `totalSupply=6`. Sentinel-probe every row before overriding — see `inherited-findings-and-silent-rpc-failures.md` §1.
- `eth_getLogs` returns `[]` with **zero errors** on this RPC for every range incl. `fromBlock:0x0`. Use `eth_getBlockReceipts` + client-side filter for any census. See §3 of the same file.
- `Utils.generateAddress` = `address(keccak256(chainId ‖ account))` — **keyless**. `_fundSpenderAlias` (Executor:347, Allocator:260, WithdrawGasPayer:172) transfers value to it ⇒ permanently frozen funds. HIGH with prerequisites (trigger is ORACLE_ROLE-gated). See §5.
- `ERC20View.transfer`/`transferFrom` return `false` rather than reverting on insufficient allowance — integration hazard, not a theft primitive. See §7.
- `RelayHub.isOperator(account, operator)` parameter order matters: the second argument is `msg.sender`, so an operator can act on behalf of any account.
- `RelayOracleV2` holds `Hub.OPERATOR_ROLE`; uncapped `HUB.mint` is gated behind `rateLimiter`. When `rateLimiter == address(0)`, the allowlist + consume checks are skipped.
- `RelayAllocator.sol` callerIsSpender / spender chain auth ignores `spenderChainId`; token binding in draw authorization drops `token`.

## Delivered-source facts from the repo clone (source-side, supersedes manifest assumptions)

Verified by full-source read of the Foundry repo (`contracts/`, ~70 `.sol`). These are the *source*
claims a trust-graph brief cites; pair each with the live-RPC confirmation above before any severity.

- **No `RelayDepository` contract exists.** (Earlier code paths in these notes refer to
  `params.depository` — that is an *opaque bytes field*, not a contract address.) Deposit-address
  logic is `deposit-addresses/RelayDepositAddressManager.sol:91-130` + a `deposit-addresses/oracle/`
  dir (`IPricingOracle`, `BasicPricingOracle`, `SignedPricingOracle`). Missing from the brief were
  `funding-pools/` (`RelayFundingPool`, `RelayFundingPoolFactory`, `IRelayFundingPool`),
  `call-resolvers/` (`PoolDrawResolver`, `ResolverSandbox`, `PoolResolverBase`),
  `payload-builders/gateway/` (Circle Gateway), `price-adapters/` (Stork/Chainlink DS),
  `aurora-xcc/` + `ChainSignatures.sol` (NEAR signing), `precompiles/`, `routers/`.
- **`RelayDepositAddressManager.trigger` is unauthenticated and mints nothing.** It takes a
  **caller-chosen** `pricingOracle` (`:110-111`), resolves prices against it, folds them into a
  trigger hash, and stores the order id. No role gate. It is **never called by `RelayOracleV2`** — so
  deposit → oracle attestation is an **off-chain hop** with no on-chain verification. Label that
  boundary `UNKNOWN`, not "vulnerable" (see `trust-graph-role-reachability-and-latent-findings.md` §8d).
- **`RelayOracleV2.execute` / `executeMultiple` are fully public** (`:154-195`). Auth is carried
  per-call as `(oracle, signature)` and checked in `_execute`: `hasRole(ORACLE_ROLE, oracleMultisig)`
  `:401`, `isValidSignatureNow` `:407`, then `IDEMPOTENCY_STORE.markExecuted` `:413`. `executeMultiple`
  *continues past* failures (`:169-177`) and emits `ExecutionFailed`.
- **FAST_MINT bypass is explicit and per-deposit**: `rateLimiter == address(0)` skips the allowlist
  check and `consume` entirely (`:356-366`), and `feeCalculator == address(0)` skips fees
  (`:338-345`). Both are reachable only via an oracle attestation naming zero — so it is the signer's
  choice, and the honest finding is about *who shapes the payload the signer sees*.
- **`RelayAllocator` burns with its own copy of the hub permission**: `submitWithdrawRequest` →
  `RelayHub.burn(spenderAlias, tokenId, params.amount)` `:301` with `params.amount` user-supplied.
  Caller auth = `callerIsSpender` `:265-266` ∥ `isOperator(spenderAlias, msg.sender)` `:267` ∥
  `consumeSpenderSignature` `:275,:329-362`. **`consumeSpenderSignature` also accepts an
  `ORACLE_MULTISIG` signature (`:356`)** — the multisig can therefore authorize any spender's burn.
  Owner controls `setPayloadBuilder` `:207` and `suspend`/`unsuspend` `:214,:221`.
- **`spenderChainId` is not bound in the burn path** — `spenderAlias` is derived at `:260-263` from
  `params.spenderChainId`, while the signed `PAYLOAD_TYPEHASH` (`:72-75`) covers it, so a signature
  minted for one spender chain is replayable only within its own digest; confirm per-case.
- **`WithdrawGasPayer.payGas` is permissionless** (`:141`) with an `ORACLE_MULTISIG` EIP-712 signature
  (`:152`), and burns `feeAmount` from the **spender alias** (`:181`) — a signed fee payment burns
  someone else's hub balance. Replay closed by the write-once `gasPayments` record (`:168`).
- **`RelayFundingPool.debit`** gates: `onlyRole(RESOLVER_ROLE)` `:368`, `whenNotPaused`,
  `nonReentrant`, per-account resolver allowlist `:374`, one-shot `drawRecords[order][account][leg]`
  `:377`, config expiry `:384`, authorizer signature `:387`, `perOrderCap` on
  `orderDraws[order][account][token]` `:395-405`, budget `:406-418`. `credit` also requires
  `RESOLVER_ROLE` (`:278`). Two `withdraw` paths: `WITHDRAWER_ROLE` `:456` and permissionless
  account-signed `:466`; neither is pausable (deliberate).
- **`ResolverSandbox` holds no roles** by design (`ResolverSandbox.sol:20-67`) — solver calls run
  there so a nested `pool.debit()` cannot succeed. `PoolResolverBase` binds the payload via
  `request.nonce == keccak256(resolver ‖ keccak256(executionData))` (`:162-172`).
- **`RelayMultisigSigner`** is NEAR chain-signatures: `approveSignature` `onlyOwner` (`:102`),
  `sign` is **public** but requires a stored approval (`:124`), and the callback is restricted to
  `AuroraSdk.nearRepresentitiveImplicitAddress(address(this))` (`:177-185`).
- **`RelayOracleMultisig`** = EIP-1271 with `Ownable2Step`; signers/threshold mutable by owner
  (`addSigner` `:102`, `removeSigner` `:118`, `setThreshold` `:145`); `_validateSignatures` requires
  ascending signer order and counts only the first `threshold` signatures (`:176-227`).

## Trust-graph brief outcome (process note, not a finding)

A source-only trust-map brief on this repo ran out of turn budget on whole-file reads and **never
wrote its deliverable** — the map existed only in context. Use the outline-first loop in
`trust-graph-role-reachability-and-latent-findings.md` §8, and write the doc incrementally.



Full method in `oracle-manipulation-refutation.md`. Facts confirmed on-chain this session:

- `RelayPriceOracle` = `0x1d01F24bc185a45a02EB20E599571ab46c830B7F` (15890 B runtime), owner =
  `0xf61a305199fa1135d76ffab3752d42f55cbd775a`.
- **`RelayOracleV2` never reads price.** `_executeAction` decodes `amount` from the oracle-signed
  payload and calls `HUB.mint(...)` directly (L269-301, L374). Amount is **attested, not computed**.
- Price consumers are only: `RelayUsdRateLimiter` (budget), `RelayBpsFeeCalculator` (fee),
  `RelayDepositAddressManager` (hash preimage), `SignedPricingOracle` (fallback).
- Route USDC-base (`tokenId 0xbf4422…3938`): providerId `0x477a6446…18d1`, feedId `0x3570e5a0…7ab63`,
  currencyDecimals 6, **`maxAgeSeconds = 30`** (NOT the 300 constant), `exists=true`.
  `providerMaxFutureSeconds = 12` (NOT the 60 constant). `MAX_AGE_SECONDS_UPPER_BOUND()=300`,
  `MAX_FUTURE_SECONDS_UPPER_BOUND()=60`, `MAX_PRICE_BATCH_SIZE()=32` are **config ceilings only**.
- Adapter = `StorkFastAdapter` `0x76aeaf8cdd04c7ca88fdfec3c064a49ab8b069f5`; its `ORACLE()` →
  `0x1d01…` (bound correctly), `STORK_FAST_VERIFIER()` `0xbb4105f349072b15e300f3daeb701ef986ae5372`.
  Attacker call → `0xd86ad9cf` UnauthorizedCaller. No `owner()`/`admin()` surface on the adapter.
- `setFeedRoute`/`setPriceFeedAdapter` → `0x118cdaa7` OwnableUnauthorizedAccount from an EOA.
- Batch >32 → `0xb452d8a4` PriceBatchTooLarge(33,32). Unknown tokenId → `0xa09c4a71`
  FeedRouteNotFound. Direct `RL.consume` from EOA → `0xe2517d3f` AccessControlUnauthorizedAccount.
- `resolveUsdPrice*` are **permissionless** and `_resolveFeed` writes `cachedPublishTimes` (L690).
  Benign today (cache stores publishTime only, no price) but it is public state mutation — worth a
  hardening note, not a finding.
- **~45% of the 772-line oracle is dead in production**: `resolveBidAsk*` + `IBidAskOracle` have
  only test consumers.
- **`RelayUsdRateLimiter` prod (`0x23afd9e0348c058eba84c434d9c6b508cea764e6`) is effectively not a
  rate limiter**: bucket `base` live = `tokens=capacity=rate=10000e18`, and `_calculateRefill` =
  `min(capacity, tokens + Δt*rate)` → refills to full in 1s. Only the `capacity` hard ceiling
  (10,000 USD/request) binds. **This, not the oracle, is the real exposure lever — audit separately.**
- Fee calc prod `0xdd7d96282b7fda7c83aca1ed8d09733ad51caa09`; both it and the limiter have
  `PRICE_ORACLE()` → `0x1d01…` and are allowlisted in OracleV2 (`isRateLimiter`/`isFeeCalculator`=1).

## Web2 / API signature-scope class bug

- Endpoint: `POST /attestations/withdraw-request-authorization/v1`.
- Owner signature payload omits `depository`; server verifies only the omitted set, then signs an allocator request with attacker-chosen `depository`.
- On-chain allocator digest DOES bind `depository`, so the returned oracle signature is valid for the attacker-chosen depository.
- This is an authorization-scope bug, not RCE. Severity depends on whether multiple depositories are registered for the same `chainId`.

## Forge / foundry workflow recipes

- Baseline: run `forge test` first; record suite/test counts before adding new PoC files.
- Harness traps:
  - `vm.prank` is consumed by external calls inside argument evaluation; cache role constants and use `vm.startPrank/stopPrank`.
  - `ADMIN_ROLE != OPERATOR_ROLE`; granting one does not grant the other.
  - Contract-typed args to `hasRole(..., address)` need explicit `address(...)` cast.
- Regression hygiene: do not edit shared base fixtures or unrelated existing tests when adding PoCs.

## Verification commands

- Live chain: `https://rpc.chain.relay.link`, chainId `537713`.
- Hub: `0xDDD361727C22A01EB137880678A20b0BEaE69318`
- Resolver: `0xb24ac15b9da6d88e283ffe048befe02e188ea64e`
- Oracle: `0xd180dc3b8cb71b185c563b6e4857592ca93dacaf`
- Multisig: `0x2a72eb8cf0233a3dc6198683c83b1078de6fa2b0`
- Use `cast chain-id`, `cast call`, `cast codesize` for live checks.

## Mempool / front-run window

- `_runCalls` funds the resolver and calls `ICallResolver.execute` in the same `nonReentrant` execute call.
- Resolver balance is transient per order; standing-balance loot is only present after failed/partial execution.
- Mainnet execution proof for resolver-intercept vectors requires a fork-based same-block front-run demo.
