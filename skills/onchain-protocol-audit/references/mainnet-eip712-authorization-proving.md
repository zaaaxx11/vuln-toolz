# Mainnet EIP-712 Authorization Proving

Condensed from a Relay Protocol session where a forge-proven `callResolver`-outside-digest finding was taken to mainnet `eth_call` and survived an adversarial kill-pass.

Companion to `references/live-rpc-forensics-and-eth-call-trap.md` (the `eth_call` state-trap, Blockscout fallbacks, and verified-source diff) and `references/signature-gated-entry-writes-and-bytecode-identity.md` (the unbound-field consumer-re-derivation law).

## Golden path for EIP-712-gated `execute()` flows

1. **Build the exact structHash** the contract uses, but use the live `eip712Domain()` result, not a guessed domain.
2. **Compute `digest = keccak256("\x19\x01" ++ domainSeparator ++ structHash)`**.
3. **Confirm on-chain**: if the contract exposes `hashXxxRequest(...)`, call it. If it returns the same digest, you now have an independent verification that your struct encoding is byte-exact.
4. **Confirm signature validity**: call `oracle.isValidSignature(digest, sig)` on the oracle itself. Valid magic = `0x1626ba7e`; invalid = `0x...00...` or revert. This is the real mainnet sanity check that the captured signature actually matches the captured digest.
5. **Override only the replay guard**: if `usedRequests[digest]` is the only blocker, override that specific mapping slot via `stateDiff`. Read it back with `eth_getStorageAt` at the tx block and at `block-1` to confirm before/after.
6. **Call through the real entrypoint**: if the live tx goes `EOA → batcher → executor`, your `eth_call` must too. Calling the executor directly can revert for reasons unrelated to the finding.
7. **Compare three variants** at the same block:
   - A: exact real calldata
   - B: ONLY `callResolver` swapped
   - C: ONLY an in-digest field mutated
   Baseline A must succeed for B/C to be meaningful.

## Pitfalls captured here

- Domain separator is oracle-specific, not executor-specific; signature is over the oracle's domain, not `address(this)`.
- 130-byte signatures = multisig; treat as opaque, do not try to reconstruct offline.
- `stateDiff` works for owned storage slots; always verify the override applied by re-reading the slot.
- `eth_call` through a batcher can require the batcher's own access control; if baseline fails, isolate whether it's your override or the batcher gate before drawing conclusions.
- Forge-level severity downgrades from real mainnet conservation tests must be reflected in the final report; do not ship a `Critical` claim that your own tests disprove.

## Verification receipts from this session

- `hashExecuteAndWithdrawRequest(...)` on `RelayExecutor` returned the exact digest recomputed from live calldata.
- `oracle.isValidSignature(digest, sig)` returned `0x1626ba7e` (ERC-1271 magic valid) against the captured signature from a real executed tx.
- `eth_getStorageAt` confirmed `usedRequests[digest] == 1` at the tx block and `0` at `block-1`, validating the slot computation.
- 1,144 live `Executed` events all used the same `callResolver` (`0xb24ac15b…`); zero floors of `outAmountMinimum == 0`.

## When this reference applies

Trigger: any live on-chain finding whose exploitability depends on an EIP-712 signed struct plus an *unsigned function parameter*; any audit that needs to upgrade from forge-only to mainnet-confirmed; any severity downgrade caused by conservation/profitability tests on a real calldata census.
