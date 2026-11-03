# Multi-Gen Oracle / Idempotency-Store Audit

Applies when the brief names a read-only viewer/lens contract plus a shared idempotency
store consumed by multiple oracle generations (e.g. `RelayHubBalanceViewer` +
`RelayOracleIdempotencyStore`). The worked case is the Relay protocol round-11 A2 run.

## Quick verdict tree

```
viewer deployed? NO  -> DEAD-CODE. Stop. Report: off-chain ABI only, no on-chain risk.
viewer deployed? YES -> is it called by any on-chain contract?
                           NO  -> severity drops; report as off-chain helper with same formulas as on-chain.
                           YES -> audit alias/tokenId derivation divergence, then state-manipulation surface.
```

## 1. Viewer / helper contract

### 1.1 Liveness gate (do this FIRST)
- `eth_getCode <address>` for every candidate address from deployment manifests.
- `0x` / 0 bytes => **DEAD-CODE**. No further runtime analysis applies.
- Also grep for deploy scripts: `script/Deploy*.s.sol` + manifest keys `{prod,dev,stag,test}.json`.
  If neither exists, the contract is **not deployed** regardless of source presence.

### 1.2 Alias / tokenId derivation divergence
- Read `_aliasOf`, `aliasOf`, `tokenIdOf`, `tokenInfo`, `balanceOf` in the viewer.
- Read the corresponding derivation in the on-chain consumer (e.g. `Utils.generateAddress`,
  `Utils.generateTokenId`, or the Hub's own mint/deposit path).
- Compare as **byte-for-byte**: same inputs → same outputs?
  - If formulas are identical => **no divergence**; viewer is a transparent lens.
  - If formulas differ (e.g. viewer uses `abi.encodePacked` where hub uses `abi.encode`) =>
    **DIVERGENT-VIEW** finding: same account can show two different balances depending on
    which contract you ask.
- `abi.encodePacked(string,bytes)` collision is a **real risk** when variable-length
  inputs can be re-parsed as shorter + tail-padded bytes (e.g. `chainId = "eth"`,
  `token = 0x0001` vs `chainId = "ethereum"`, `token = 0x00...001`). Prove with the
  real SDK (`eth_utils.keccak` + `eth_abi.encode`) before citing.

### 1.3 balanceOf alias vs account split
When `balanceOf(chainId, account, token)` returns **two balances**:
- `aliasBalance` = Hub balance of `_aliasOf(chainId, account)` (virtual address).
- `accountBalance` = Hub balance of `address(bytes20(accountBytes))` (only for 20-byte accounts).

If a downstream on-chain contract sums these two values without documenting which side it
cares about, that is a **GABUNG-SALDO** finding (same user-visible account mapped to two
distinct Hub balances, reported as one number).

### 1.4 Who consumes the viewer?
- `grep -rln 'RelayHubBalanceViewer\|balanceViewer' --include='*.sol' --include='*.ts' .`
- If only off-chain (SDK, indexer, UI) => severity drops to INFO/LOW.
- If an on-chain contract calls `viewer.balanceOf(...)` and uses the result in a transfer,
  allowance, or mint decision => **CRITICAL candidate**; verify the divergence proof above.

## 2. Shared Idempotency Store

### 2.1 Liveness + role census
- `eth_getCode` on the store. If live, read role constants from artifact selectors:
  `ADMIN_ROLE()` / `WRITE_ROLE()` / `MAX_SOURCES()`.
- `hasRole(WRITE_ROLE, <addr>)` for EVERY address in the deployment manifest (oracles,
  multisigs, executors, helpers). Do NOT stop at the "obvious" writer.
- Record the **WHO-CAN-WRITE table** in the report. A writer outside the manifest, or a
  manifest address that does not hold the role on-chain, is a divergent-state / deploy-addr
  mismatch.

### 2.2 Source-array state
- `sourceCount()` + `sources(i)` for `i=0..sourceCount-1`.
- For each source `s`: `isSource(s)` (should be `true`) + `hasRole(WRITE_ROLE, s)` (should be
  `false` — sources are read-only mirrors, not writers).
- `addSource(address)` must be `onlyRole(ADMIN_ROLE)`. Any source added by a non-admin is a
  **fake-source injection** finding.

### 2.3 Fake-source bypass refutation
The usual hypothesis: "attacker adds a source that always returns `true`, then replays an
old key to make the store think the action is already executed." Evaluate:

| Hypothesis | Refutation path |
|---|---|
| Attacker adds malicious source | `addSource` is `onlyRole(ADMIN_ROLE)`. Admin is a multisig 2-of-5. |
| Attacker calls `markExecuted` directly | `onlyRole(WRITE_ROLE)`. Positive control: `markExecuted` from an EOA must revert with `AccessControlUnauthorizedAccount(eoa, WRITE_ROLE)`. |
| Attacker controls a source contract's `isExecuted` response | The source is an immutable-address external contract. If it is a legacy oracle, its state is controlled by its own writer role, not the store. If the source is permissionless (anyone can flip `isExecuted`), the worst case is **DoS** (all new keys return `true`), not replay. For replay you need `isExecuted=false`; a malicious source cannot force that. |
| Key domain collision | If dedup is keyed only by `bytes32 idempotencyKey` (no `source` domain), that is intentional when bridging oracle generations. Prove with a real historical key: `store.isExecuted=true`, `store.isStored=false`, `source.isExecuted=true` => bridge works. If the design reversed (`source.isExecuted` only consulted when `isStored` is false, but `isStored` is never written for legacy keys), then legacy keys are **not** deduped => replay risk. |

### 2.4 Replay-bridge validation (worked example)
For a store with one legacy oracle as source:
1. Pull a real historical tx from the legacy oracle (selector `executeMultiple` or `execute`).
2. Extract the idempotencyKey from the tx input.
3. Query live:
   - `store.isStored(key)` -> expect `0x...00` (legacy keys not written to new store).
   - `store.isExecuted(key)` -> expect `0x...01` (bridge via source).
   - `source.isExecuted(key)` -> expect `0x...01` (legacy oracle remembers).
   - `newOracle.isExecuted(key)` -> expect `0x...01` (delegates to store).
4. If all four match the expectation, the replay bridge is **PROVEN working**.
5. Negative control: `store.markExecuted(key)` from a non-writer must revert with the exact
   `AccessControlUnauthorizedAccount(non_writer, WRITE_ROLE)` custom error.

## 3. Role / state divergence audit (multi-contract)

When two oracle generations share a store, build this table:

| Contract | Role | On-chain? | Formula match with source |
|---|---|---|---|
| viewer (lens) | none | DEAD / YES | compare `_aliasOf`/`tokenIdOf` to Hub |
| oracle V1 (writer) | WRITE_ROLE | YES | signature verify + `markExecuted` |
| oracle V2 (source) | none | YES | `isExecuted` only, no write |
| legacy oracle (source) | none | YES | `isExecuted` only, no write |

A **divergence** is any row where the on-chain state contradicts the source claim:
- source says role granted, `hasRole` says no.
- source says `isExecuted=true`, store says `isExecuted=false` for the same key.
- viewer formula differs from Hub formula for the same inputs.

## 4. Control-positive / control-negative discipline

Every claim needs at least one control:
- **Positive control**: known-good caller on a known-good path returns expected result.
  Example: `store.isExecuted(zeros32)` returns `false` (store is fresh).
- **Negative control**: known-bad caller on a privileged path reverts with the *expected*
  custom error selector, not a generic OOG or revert. Example:
  `markExecuted` from `0x...dead` -> `0xe2517d3f...` = `AccessControlUnauthorizedAccount`.
  If the selector is wrong, your calldata encoding is broken, not the contract.

## 5. Reporting template (multi-gen brief)

Use this shape for the deliverable:

```markdown
### Sasaran N — <name>: <verdict>
- **Status**: DEAD-CODE / BYPASS-DIBATASI / DIVERGENT-VIEW / PROVEN-WORKING
- **Alamat deployed**: <address or "TIDAK ADA">
- **eth_getCode**: <bytes / 0-byte>
- **WHO-CAN-WRITE**: <table>
- **Dampak**: <none / replay / double-execute / balance misreport>
- **Skenario**: <one-paragraph attacker path, or "tidak relevan karena DEAD-CODE">
- **Bukti live**: <raw hex selector + revert data or success result>
```

For DEAD-CODE verdicts, also state:
- Manifest absence (which env JSON, which key).
- Script absence (`script/Deploy*.s.sol` grep result).
- Consumer scan result (`grep -rln '<contract>' --include='*.sol' .` -> only its own test).

## 6. Pitfalls

- **`eth_getLogs` empty is NOT proof a contract is dead.** A contract with only view calls
  and no events emits no logs. Use `eth_getCode`, not log counts, to prove liveness.
- **A source that returns `true` for every key is DoS, not replay.** Do not conflate
  "attacker can block all future executions" with "attacker can re-execute an old action."
  Replay requires `isExecuted=false`; DoS sources produce the opposite.
- **Multi-gen key domain = global on purpose.** A `bytes32`-only dedup key across two oracle
  generations means "any execution ever accepted by any trusted oracle is final." That is the
  desired invariant. Adding `source` as a domain would *re-enable* replay of legacy keys —
  which is the bug, not the fix.
- **Role census must cover ALL manifest addresses, not just the named oracle.** In the worked
  case the multisig (`0xf61a...`) and executor (`0x6747...`) were checked; only the oracle
  held `WRITE_ROLE`. Stopping at "obvious writer" would have missed a divergent-state
  finding if one existed.
- **Viewer `balanceOf` dual-balance is a feature, not a bug — until a contract sums them.**
  A helper that reports both `aliasBalance` and `accountBalance` is correct in isolation.
  The bug appears only when an on-chain caller adds the two values and treats the sum as
  spendable balance.
