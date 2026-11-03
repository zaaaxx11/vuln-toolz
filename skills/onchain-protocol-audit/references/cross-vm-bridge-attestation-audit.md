# Cross-VM bridge/attestation protocols — the interop trust surface

Condensed from an in-depth recon + code read of Relay Protocol (`relayprotocol/relay-settlement` +
`relayprotocol/relay-protocol-oracle`, Oct 2026). Relay is the canonical shape of the class:
**an off-chain oracle attests + signs, an on-chain allocator burns + builds a payload, a per-VM
payload builder serializes it, and a depository on the destination chain releases funds.** Every
non-EVM VM gets its own builder, its own signature scheme, and its own address encoding — that
multiplication is where the bugs live.

**Section list:** §1 protocol shape & where the trust actually sits · §2 the ownerless
public-entry-point teardown (do this first) · §3 signature-scheme inventory — the divergence
table · §4 EIP-1271 N-of-M verifier reading checklist · §5 digest canonicalisation traps ·
§6 the off-chain oracle API surface (openapi, auth gate, probe order) · §7 scope/budget
arithmetic for these programs · §8 the honest-verdict vocabulary.

---

## 1. PROTOCHE SHAPE — and where the trust sits

Relay-style architecture, in dependency order:

```
user funds ──► DEPOSITORY (per chain, per VM) ──► HUB (one chain, ERC-6909 multi-token)
                                                     │  balanceOf[owner][tokenId]
                                                     │  tokenId = keccak(chainId ++ currency)
                                                     │  owner address = keccak(chainId ++ account)
                                                     ▼
                        EXECUTOR (oracle-signed request → pulls order funds → runs a
                                  solver-supplied callResolver → submits withdraw)
                                                     ▼
                        ALLOCATOR (builds payload via IPayloadBuilder, burns hub balance,
                                   stores hashesToSign)
                                                     ▼
                        ORACLE MULTISIG (EIP-1271, N-of-M) signs hashesToSign
                                                     ▼
                        destination DEPOSITORY releases funds to receiver
```

Two things to internalise before auditing anything:

1. **Aliases, not addresses.** `generateAddress(chainId, encodedAccount)` and
   `generateTokenId(chainId, encodedBytes)` mean every cross-chain identity is a keccak of
   `(string chainId, bytes account)`. Anywhere the two sides disagree on the *encoding* of a chain
   id (`"1"` vs `"ethereum"` vs hex) you get two distinct aliases for the same user. Grep both
   call sites of every alias derivation and diff the argument encoding — this is the cheapest
   cross-VM bug class and it needs no exploit primitives.
2. **The hub is an operator-permissioned ledger, not a token.** `isOperator(account, operator)`
   returns true for **any holder of `OPERATOR_ROLE`** — a global role — *or* a per-account
   `_isOperator` entry. So a single role grant (executor, gas payer, any helper) is a global
   transfer right on every account's balance. Enumerate role holders on-chain, not from
   deployment docs.

---

## 2. OWNERLESS PUBLIC ENTRY POINTS — teardown FIRST

Bridge/allocator protocols carry a family of `public` functions with no modifier that look
catastrophic. In Relay:

| Function | Guard | What actually happens |
|---|---|---|
| `RelayAllocator.submitWithdrawRequest(params)` | **none** | caller-authorized as spender \| hub-operator \| spender ECDSA sig \| **oracle-multisig signature over `_withdrawRequestDigest(params)`** |
| `RelayAllocator.submitWithdrawRequestWithSignature(params, sig)` | **none** | same, with an explicit receiver sig |
| `RelayHub.approveFor(owner, spender, id, amount)` | `erc20Views[id] == msg.sender` | only the token's own view contract |
| `RelayHub.transferFrom(sender, receiver, id, amt)` | allowance **only if** `msg.sender != sender && !isOperator(sender,msg.sender) && erc20Views[id] != msg.sender` | **no allowance decrement at all** when the caller is the token's ERC20View |

Do the teardown in this order, and write each step's verdict into the findings log even when it
closes — the next session must not re-probe:

1. **Is the unguarded path reachable by an outsider?** `submitWithdrawRequest` is guarded by
   `callerIsSpender || isOperator(spenderAlias, msg.sender) || consumeSpenderSignature(...)`.
   Every leg demands an existing balance or a signature, so the primitive is "burn someone's hub
   balance into a payload addressed to a receiver *the request specifies*" — which is only
   useful if the payload builder ignores/mis-binds the receiver. **Follow the receiver into
   `buildPayload`**; do not report the unguarded entry point itself.
2. **Digest domain separation.** `consumeSpenderSignature` digest is a full EIP-712 struct over
   (chainId, depository, currency, amount, spenderChainId, spender, receiver, data, nonce). Then
   it falls back to `ORACLE_MULTISIG.isValidSignatureNow(digest, signature)` — a *contract-wide*
   N-of-M oracle signature. If the same oracle digest is also accepted on the executor path or any
   other endpoint, you have a **signature-domain bleed**. Build the list of every
   `_hashTypedDataV4` consumer across the repo and check whether their domain names differ.
3. **Nonce scoping.** `usedNonces[keccak(spender)][nonce]` — the key is the raw `spender` bytes,
   **not the derived alias**. Two requests with different `spenderChainId` but the same
   `spender` bytes share a nonce namespace. Conversely a request whose `spender` is 20-byte-encoded
   vs 32-byte-encoded for the same address gets a different namespace → replay surface. Check
   whether any encoding is accepted both ways.
4. **ERC-6909 view bypass.** `transferFrom` skips the allowance branch when
   `erc20Views[id] == msg.sender`. `erc20Views[id]` is written once in `_createERC20View` when
   `totalSupply[id] == 0` — so **the first mint of a token id fixes its view contract forever**,
   and `_createERC20View` early-returns if already set. An attacker who can get the first mint of
   a token id (they usually can: `mint` is operator-only, but a *deposit* of a new currency mints)
   controls the "view" whose calls bypass allowances. Trace who can trigger the first mint.
5. **Pre-validation state writes.** `RelayExecutor._validateRequest` sets
   `usedRequests[digest] = true` **before** verifying the signature. A revert rolls it back, so it
   is safe — but that requires the caller to be a plain EOA/contract call. If any path reaches it
   with a `try/catch` wrapper upstream, the flag survives a failed verification → **free griefing
   of any authorized request**. Grep for `try` around `execute(`.

---

## 3. SIGNATURE-SCHEME INVENTORY — build the divergence table

Every VM gets its own verifier in the oracle service. That table *is* the attack surface: one
digest, seven verification algorithms, and each one was written against a different wallet spec.

Canonical pattern (Relay `src/common/signature-verification.ts`):

```
digest = sha256(json-stable-stringify({operation, chainId, currency, amount,
                                       ownerChainId, owner, recipient, nonce,
                                       additionalData?}))
```

`operation` (`"withdrawal" | "transfer" | "gas-payment"`) is the only domain separation between
operations — **the payload has no verifying contract, no chain binding, and no expiry.**
`additionalData` is free-form and included in the digest but its *meaning* is per-VM.

| VM | Verification | Trap to check |
|---|---|---|
| ethereum-vm / hyperliquid-vm | `verifyMessage` over **two** encodings: `{raw: 0x<digest>}` AND the UTF-8 string `"0x<digest>"`, then EIP-1271 on-chain fallback | accepting both encodings doubles the replay surface across heterogeneous wallets — check whether the signed object is identical |
| lighter-vm | `owner` is an **L2 account index**; oracle resolves index → `l1_address` via Lighter API, then EVM personal-sign | the trust hop: whoever controls that Lighter API mapping controls the owner identity |
| tron-vm | `keccak256("\x19TRON Signed Message:\n" + len + msg)` over the digest, then `recoverAddress` | length is the *string* length, not bytes — check for multi-byte mismatch |
| solana-vm | ed25519 over the **hex string** `Buffer.from(digest,"utf-8")` (not the 32 raw bytes) | the comment says raw bytes trip Phantom's anti-tx check — so the signed bytes are the ASCII hex; verify the *other* side signs the same thing |
| ton-vm | TonConnect `signData` envelope `sha256(0xffff ‖ "ton-connect/sign-data/" ‖ addr(BE) ‖ domainLen ‖ domain ‖ timestamp(BE64) ‖ "txt" ‖ payloadLen ‖ payload)`; pubkey from `get_public_key` getter | `timestamp` and `domain` come from **caller-supplied `signatureMetadata`** — domain is checked against a suffix allowlist (`domain === cfg \|\| domain.endsWith("."+cfg)`), timestamp is **not checked at all** → unbounded replay window |
| bitcoin-vm | `bip322-js` `verifySignature(owner, digest, base64)` — covers BIP-137 + BIP-322 | library covers P2PKH/P2SH/P2WPKH/P2TR; check what it does on a malformed base64 vs a wrong sig (silent false?) |
| xrp-vm | owner signs a **never-submittable `AccountSet`** tx whose single Memo is `"0x<digest>"`; constraints: `Fee=="0"`, `Sequence==0`, `SetFlag/ClearFlag/TicketSequence` absent, memo count == 1, `deriveAddress(SigningPubKey) == tx.Account == owner` | the "never-submittable" claim rests on `Fee 0` + `Sequence 0`; verify against the current ledger floor and whether a `TicketSequence` path can re-validate it |

**The single highest-yield cross-VM finding shape:** `operation` is the only separator, so a
signature obtained for `transfer` on VM A must be proven unusable for `withdrawal` on VM B and
for a different `ownerChainId`. Enumerate endpoints that call each `verifyXSignature` and confirm
the operation string is correct at *every* call site — one wrong constant is a full
cross-operation replay.

---

## 4. EIP-1271 N-OF-M VERIFIER — reading checklist

`RelayOracleMultisig` is a from-scratch multisig (not Safe). Read these five things in order:

1. `threshold` vs `signers.length` invariants in the constructor and in `removeSigner`
   (must refuse to drop below threshold) and `setThreshold` (`0 < t <= len`).
2. `_validateSignatures`: `signatureCount = signatures.length / 65` then
   `if (signatureCount < threshold) return false;` then loops `i < threshold` only.
   → **extra trailing signatures are ignored**, and a `signatures.length` not divisible by 65
   silently truncates. Neither is a break, but state it.
3. Ascending-sort check `if (signer <= lastSigner) return false;` — this is what prevents
   duplicate signatures. Confirm it exists and is `<=` not `<`.
4. **`ECDSA.tryRecover` returns `(address(0), NoError)` for `v ∉ {27,28}` with high-`s` values
   that OpenZeppelin's library accepts as malleable.** Check the OZ version's malleability policy
   and whether `address(0)` can ever pass `isSigner[address(0)]` (constructor must reject zero
   signer — confirm it does).
5. **Live census beats the source:** `getSignerCount()`, `threshold()`, `getSigners()`, `owner()`
   on the deployed contract. A 2-of-5 with a 5-key set is a very different severity than 2-of-2,
   and the doc never tells you which. Also note `owner()` — in Relay it was an EOA, which makes the
   *management* plane a single key even though the *signing* plane is 2-of-5.

---

## 5. DIGEST / CANONICALISATION TRAPS

- **`abi.encode` vs `abi.encodePacked`** in every typehash computation. `keccak256(bytes(chainId))`
  vs `keccak256(chainId)` mismatches silently produce a different digest on the two sides
  (Solidity `string` vs `bytes` keccak are identical, but `bytes memory` built from calldata is
  not always the same length).
- **Struct field order in the TYPEHASH string must match the `abi.encode` call order exactly.**
  Diff them character by character — a swapped `depository`/`orderAddress` is invisible to the
  compiler and fatal to verification.
- **Array hashing**: `_hashFees` uses `keccak256(abi.encodePacked(feeHashes))` (not
  `abi.encode`) — correct for `bytes32[]`, but verify no `bytes`/`string` element is packed.
- **Caller-supplied fields excluded from the digest.** In `RelayExecutor`, `callResolver` and
  `callResolverData` are **not** in the EIP-712 request — the doc says a generic execution plan
  can be refreshed after authorization. That means the oracle authorizes *the request*, and an
  untrusted resolver executes *arbitrary logic* with the funded input. The only economic guarantee
  is `outAmountMinimum`. **That gap is the intended design — check whether a specialized resolver
  that *does* need commitment has its own signed field, and whether the resolver can retain the
  input balance.** Read `ICallResolver.execute` and the sandbox wrapper for what the resolver can
  reach (`ResolverSandbox`, `PoolResolverBase`).

---

## 6. THE OFF-CHAIN ORACLE API SURFACE

Reference implementations ship open. Probe order that worked:

```bash
# 1. is the service up (no auth required for /lives)
curl -s https://oracle.<host>/lives/v1
# 2. the full route list — Swagger/OpenAPI, usually public
curl -s https://oracle.<host>/documentation/json -o /tmp/openapi.json
# 3. schema shape per route WITHOUT a valid key: post {} and read the Fastify validator
curl -s -X POST https://oracle.<host>/attestations/transfer/v1 \
     -H 'content-type: application/json' -d '{}'
# → {"message":"body must have required property 'chainId'","code":"FST_ERR_VALIDATION"}
```

That last trick is the whole point: **Fastify/TypeBox leaks the required-property ladder one
field at a time**, so you can reconstruct the request schema with zero credentials. Iterate
adding the named field until you get past validation; the first `{"error":"Unauthorized"}` is
where the actual auth gate is.

Facts to extract from the reference repo (`grep -rn "url:" src/api`):

- The route list in `src/api/index.ts` is **often narrower than the deployed OpenAPI doc** —
  undocumented versions (`/v2`, `/v3`) live in prod but not on the checked-out branch. Diff the two
  lists; the undocumented ones are unaudited by definition.
- Auth is a single `preHandler` hook: `isValidApiKey(req.headers["x-api-key"])`, and an invalid
  key only *rate-limits* (fixed window per IP) rather than rejecting — except routes that
  explicitly return `Unauthorized`. So "open endpoint" and "rate-limited endpoint" are different
  verdicts; read the hook before claiming unauthenticated access.
- `resolveOracleQuorum` fans out to peers and **counts distinct `oracleSigner` values against an
  `ORACLE_SIGNERS` allowlist** before returning a multi-sig bundle. Look for the comparison
  function: if it compares canonicalised *response bodies* rather than the signed hashes, a peer
  returning a different-but-equivalent encoding splits the quorum.

---

## 7. SCOPE / BUDGET ARITHMETIC FOR THESE PROGRAMS

Relay's bounty page (2026) is a good template for a **matrix-priced, privileged-gate-excluding**
program:

- Severity S1–S4 × likelihood L1–L3 → fixed base table ($500–$100k), then multiplicative
  modifiers (×1.5 unrecoverable, ×1.25 hard-to-fix / silent, ×0.75 expensive / pausable+monitored,
  ×0.5 bounded sub-pool), floor $500, cap $100k.
- **Freeze downgrades one likelihood tier** (floored at L1) unless the freeze is a step toward theft.
- **Privileged-only paths are non-eligible**: owner / operator / solver / oracle. You must show an
  unprivileged party reaches the role *or induces the privileged party to act*. This is the single
  most important line on the page — read it before ranking anything.
- **S4/S3 require a runnable PoC** ("explanations without code are not accepted"). Plan the forge
  harness at scope time, not at write-up time.
- Out of scope: already-exploited attacks, phishing/social-engineering/compromised keys,
  third-party-composition bugs whose root cause is not in the target's code, DoS with no fund
  loss, and any explicitly carved-out sub-protocol (Relay Vaults). **Enumerate the carved-out
  product names and check the repo actually excludes them** — a shared monorepo often puts an
  out-of-scope contract in the same package.
- Payment requires KYC/KYB and a W-8BEN/W-9; one email per vulnerability, `support@`-style intake.

Booking rule that keeps a session honest: **write the S×L verdict and the modifier list into the
findings log the moment a finding is proven, before writing prose.** A finding with a proven
mechanism and no severity arithmetic is 30% of a report; the arithmetic is the other 70% and it is
the part that decays fastest when a session is long.

---

## 8. HONEST-VERDICT VOCABULARY

Use these five words and nothing else for a cross-VM/bridge surface, because "vulnerability" is
almost always the wrong word at first pass:

| Verdict | Meaning |
|---|---|
| **DESIGN GAP** | The behaviour is intentional and documented (e.g. `callResolver` not in the digest) but creates a trust asymmetry worth flagging. Reportable as S1/informative at best. |
| **MECHANISM PROVEN** | You can point at the exact code path and the exact inputs. No exploit device yet. |
| **EXPLOIT PROVEN** | A runnable PoC (forge test / live `eth_call` against deployed bytecode) reproduces the impact. Only this word supports an S3+ claim. |
| **REFUTED** | You tested it and it does not hold. Needs the same evidence quality as a positive. Cite the guard/early-return by file:line. |
| **UNTESTED** | Mechanism plausible, verification blocked (need a key, a chain state, a funded account). Never elevate. |

The failure mode this file exists to prevent: reading an unguarded `public` allocator/executor
entry point, seeing an oracle-signature fallback, and writing "signature replay → total drain"
before tracing whether the digest is domain-separated, whether the nonce namespace is shared, and
whether an outsider can produce any of the preconditions. Three of those four checks are greps.
