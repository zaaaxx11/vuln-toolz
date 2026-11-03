# EIP-712 DOMAIN SEPARATOR audit — replay across contracts, chains, and the signer/verifier split

Third axis of the same family. `signature-binding-sign-vs-execute.md` asks *"is every field that
changes behaviour inside the digest?"*. `onchain-eip712-binding-poc.md` proves that at the forge
layer. **This file asks a different question: is the digest itself bound to one contract on one
chain — or is one oracle signature redeemable everywhere that code is deployed?**

Proven on Relay Protocol (`relay-settlement/smart-contracts` + `relay-protocol-oracle`), 2026-10-30.
Verdict on that target: **no cross-contract and no cross-chain replay** — 10/10 forge tests green,
real-ECDSA viem output, live `eip712Domain()` on both prod and staging. The value is the method and
the traps; six of them cost this session a round each.

Trigger: "audit the EIP-712 domain separator", "cross-chain signature replay", "cross-contract
replay", "can a signature from X be replayed on Y", "is chainId actually in the separator",
"hunting for signature replay across every verifier".

---

## 0. The four questions, in order — do not skip to code

| # | Question | How it is answered | If the answer is "yes, bound" |
|---|---|---|---|
| 1 | Is `verifyingContract` = `address(this)` (or a deliberate, registered address)? | live `eip712Domain()`, compare to the contract's own address | the contract axis is closed |
| 2 | Is `chainId` read at **call time** (`block.chainid`), not cached at construction? | `eip712Domain().chainId` under `vm.chainId()` flips | the chain axis is closed |
| 3 | Do the off-chain signer's domain params reproduce the on-chain separator **byte-for-byte**? | rebuild the separator from `signer.ts`'s literals + hash, `assertEq` | the signer/verifier split is closed |
| 4 | Does any *second* verifier sit between the signer and the digest (a 1271 multisig, a registry, a proxy) that re-wraps the digest? | read the `isValidSignatureNow` target's `isValidSignature` | the "one digest" claim holds |

Only after all four are "bound" is the domain layer clean. Question 4 is the one everyone forgets,
and it is where the only interesting residual on this target lived (§5).

---

## 1. `eip712Domain()` is the whole census — one call, per verifier

OZ v5 exposes `eip712Domain()`. **`DOMAIN_SEPARATOR()` often does not exist** and reverts — on Relay
every verifier reverted it, including the ones that had a working `eip712Domain()`. Do not read that
revert as "contract broken"; read it as "wrong getter for this OZ version".

```bash
# the tuple order matters: fields, name, version, chainId, verifyingContract, salt, extensions
cast call $C "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])" --rpc-url $R
```

If `cast` prints the per-field list as `0x00…00` / `[]` for the trailing slots and a full string for
`name`, **you decoded the wrong signature**: the `(...)` return-type annotation has to match exactly,
and a struct-returning getter wants the tuple form. When in doubt call it raw and decode by hand:

```bash
cast call $C "eip712Domain()" --rpc-url $R
# 0x0f | offset 0xe0 | offset 0x120 | chainId | verifyingContract | salt | extensions-len | "Name" | "1"
#  ^ 0x0f = all four standard fields present. A field bit missing means that field is NOT in the hash.
```

`fields == 0x0f` is itself an assertion worth making: `0x1f` would mean a `salt` is mixed in (and
then name/version/chainId/address may matter less), and anything without the `0x04` bit has **no
`chainId` at all** — an instant cross-chain replay finding, discovered in one call.

**Census the deployed config, not the repo.** Read the service's own config JSON for the addresses
(`hub.mainnets.prod.json`, `hub.mainnets.stag.json`) — that is what the signer actually targets — then
`eip712Domain()` each one. On Relay this surfaced that staging and prod run the *same source* at two
addresses on the same chain, which is exactly the cross-contract question worth asking.

## 2. Cross-CHAIN: the separator must move when `block.chainid` moves

OZ caches the separator in storage and rebuilds it when `block.chainid` changes. Prove both halves:

```solidity
// (a) the digest function tracks chainId
vm.chainId(CHAIN_A);
bytes32 dA = ex.hashExecuteAndWithdrawRequest(req);
bytes memory sig = _sig(dA);                 // sign while the EVM reports A
vm.chainId(CHAIN_B);
bytes32 dB = ex.hashExecuteAndWithdrawRequest(req);
assertTrue(dB != dA, "digest did not change with chain id");
assertTrue(ecrecover(dB, v, r, s) != oracleSigner, "REPLAY: chain-A sig recovered on chain B");

// (b) the getter tracks it too — this is the regression guard for the cached-immutable footgun
vm.chainId(CHAIN_A); (, , , uint256 c1, , , ) = ex.eip712Domain();
vm.chainId(CHAIN_B); (, , , uint256 c2, , , ) = ex.eip712Domain();
assertEq(c1, CHAIN_A); assertEq(c2, CHAIN_B);
```

`vm.chainId` is the cheap way to simulate a fork / a chainId migration — the exact scenario where a
hand-rolled `immutable DOMAIN_SEPARATOR` computed in the constructor goes stale. **If the repo ever
replaces OZ `EIP712` with a constructor-cached separator, test (b) flips to FAIL.** That is why (b)
belongs in the suite permanently, not just in the write-up.

Also assert the *other* three fields do not move, so `chainId` is provably the only cross-chain
separator: `name`, `version`, and `verifyingContract` are identical on every chain, so if `chainId`
is ever dropped there is nothing else left.

## 3. Cross-CONTRACT: two deployments, identical name/version, different address

The twin-deployment shape (staging next to prod, or a v2 next to a v1 on the same chain) is the
realistic cross-contract replay. Two ways to prove it, and **take the second**:

- **Weak (rejected):** deploy the twin with its own Hub/Allocator for isolation, then observe
  `InsufficientMinimumAmount` on the twin. That reverts *after* the signature check, so it proves
  nothing about the domain — and worse, on a shared allocator the first withdraw **consumes the
  payload**, so the twin's replay dies on the *allocator's* replay guard and the test silently
  measures the wrong control. This cost three iterations.
- **Strong (ship this):** assert the digest is contract-dependent, then assert the twin dies at
  `InvalidSignature` **before any state change**, with `usedRequests[digest] == false` afterwards and
  the same `(req, sig)` pair *succeeding* on the intended contract as the positive control.

```solidity
assertTrue(ex1.hashExecuteAndWithdrawRequest(r) != ex2.hashExecuteAndWithdrawRequest(r),
           "same digest on two contracts => replayable");
vm.prank(attacker);
vm.expectRevert(abi.encodeWithSelector(RelayExecutor.InvalidSignature.selector, oracleSigner));
ex2.execute(req_, resolver, "", oracleSigner, sig);
assertFalse(ex2.usedRequests(digest), "ex2 consumed ex1's digest");
// positive control on ex1 … then assert usedRequests is TRUE there
```

Pairwise-distinctness is a one-test assertion over the whole set: collect the separators of every
verifier in the repo at one `block.chainid` and assert `ds[i] != ds[j]` for all pairs. On Relay:
Executor / Hub / Allocator / GenericMapping all distinct, prod-vs-staging executors distinct.

## 4. The hand-rolled separator (payload builders) — `Utils.buildDomainSeparator`

Not every verifier uses OZ. Relay's payload builders compute the separator themselves and read
`chainId` **from a config mapping**, not from `block.chainid`:

```solidity
// payload-builders/EthereumVmPayloadBuilder.sol:166-180
uint256 evmChainId = uint256(CONFIG.getConfigValue(getEvmChainIdKey(chainId)));
bytes32 domainSeparator = Utils.buildDomainSeparator(SIGNING_DOMAIN, SIGNATURE_VERSION, evmChainId,
                                                     address(bytes20(depository)));
```

Three consequences, all assertable:

1. **Parity with OZ is a real test, not a formality.** Expose the `internal pure` helper through a
   thin probe contract and `assertEq` it against the OZ-layout hash for several inputs. One drifted
   character in the type string (`"EIP712Domain(string name,string version,uint256 chainId,address
   verifyingContract)"`) silently breaks every gate signature in the system.
2. **`verifyingContract` here is the DEPOSITORY, not the builder.** That is deliberate (signatures
   target the depository), but it means the domain is *shared by every builder instance* on the same
   `(name, version, evmChainId, depository)`. Assert that the depository is what varies, and record
   which field is the binding one for this verifier family.
3. **`evmChainId` comes from `CONFIG`, so the cross-chain guarantee depends on data, not code.** A
   mis-keyed `getEvmChainIdKey(chainId)` entry makes two chains share a separator even though the
   code is perfect. Check the key derivation separately from the hash.

Related, and it bit this session's primitive assumptions: **the Relay chain's own chainId (537713) is
not an EVM spoke's chainId.** The same `RelayExecutor` code, at the same address, on Arbitrum Sepolia
gets `421614`. Any reasoning that mixes "the hub chain" with "the spoke chain" produces a domain
comparison between two different things.

## 5. THE ORACLE / VERIFIER SPLIT — one digest or two?

The highest-value structural question on any oracle-attested protocol, and Relay's answer is clean
because of *where* verification happens:

```solidity
// RelayExecutor._validateRequest — on-chain, the ORACLE SIGNER ADDRESS is typed (IERC1271)
if (!hasRole(ORACLE_ROLE, oracleMultisig)) revert UnauthorizedOracle(oracleMultisig);
bytes32 digest = _executeAndWithdrawRequestDigest(request);   // ONE digest
if (usedRequests[digest]) revert RequestAlreadyExecuted(digest);
usedRequests[digest] = true;                                  // consumed BEFORE the check
if (!oracleMultisig.isValidSignatureNow(digest, signature)) revert InvalidSignature(oracleMultisig);
```

`RelayOracleMultisig.isValidSignature(hash, sig)` recovers ECDSA **directly over `hash`**. It never
calls `_hashTypedDataV4`, so it never wraps the digest in its own EIP-712 domain. Consequences:

- There is exactly **one** digest from signer to verifier. No second layer to drift.
- The multisig still *inherits* `EIP712("RelayOracleMultisig", "1")` — so it owns a **dead domain**
  that no code path ever hashes under. Verify the deadness the right way: `eip712Domain()` and
  `DOMAIN_SEPARATOR()` both revert on the deployed multisig (no public getter, because nothing calls
  the internal one). A domain with no getter is not automatically dead — but a domain with no
  `_hashTypedDataV4` call site is, and `grep -n "_hashTypedDataV4" RelayOracleMultisig.sol` settles
  it in one call.
- **The negative control that makes this credible:** sign the executor's digest *wrapped* in the
  multisig's domain and show it is REJECTED. If a second EIP-712 layer would have been accepted, the
  two layers are interchangeable and the "one digest" claim is false.

```solidity
bytes32 od = keccak256(abi.encodePacked("\x19\x01", multisigDS, execDigest));
bytes memory sig = _sortedSig(od);          // 2-of-2 over the WRAPPED digest
assertTrue(msig.isValidSignature(execDigest, sig) != bytes4(0x1626ba7e));
vm.expectRevert(abi.encodeWithSelector(RelayExecutor.InvalidSignature.selector, address(msig)));
exec.execute(r, resolver, "", address(msig), sig);
```

Note `usedRequests[digest] = true` is written **before** `isValidSignatureNow` — a failed signature
still burns the digest. That is a griefing surface (anyone can front-run a request to its digest and
make it unexecutable) rather than a replay, and it is worth one line in the report either way.

## 6. Off-chain ↔ on-chain parity, mechanically

Rebuild the separator from the *service's own literals*, then compare to the live getter. This is the
assertion that kills "the signer and the verifier disagree about the domain":

```js
// viem — src/common/signer.ts declares {chainId: evmChainId, name:"RelayExecutor",
//                                       verifyingContract: executorAddress, version:"1"}
const ds = keccak256(encodeAbiParameters(
  parseAbiParameters('bytes32, bytes32, bytes32, uint256, address'),
  [DOMAIN_TYPEHASH, keccak256(toHex(name)), keccak256(toHex(version)), BigInt(chainId), verifyingContract],
));
// compare to cast call $C "eip712Domain()" decoded fields
```

On Relay: `match = true` for both `RelayExecutor` and `RelayGenericMapping`, with
`evmChainId=537713` / `executorAddress=0x6747…bc0c` from `hub.mainnets.prod.json`.

**Hash both directions of the mismatch before writing anything.** A separator mismatch is a real
finding only if it is (a) an encoding disagreement (`uint256` vs `string` chainId, absent vs
`keccak256("")` version, checksum casing) or (b) an address/chain disagreement. Reproduce the
library's literal expression — same rule as `signature-binding-sign-vs-execute.md` §7b and
`live-rpc-forensics-and-eth-call-trap.md` §16c. A 20-line script that hashes its own wrong
reconstruction proves nothing and reads like proof.

## 7. Pure-crypto cross-chain matrix (no chain, no forge, 30 lines)

The cheapest possible evidence, and it does not depend on the repo compiling:

```js
for (const c of [537713, 1, 8453, 42161, 421614]) rows.push({ c, ds: buildDS(c), digest: hashTypedData(...) });
sig = await acct.signTypedData({ domain: domainFor(537713), ... });
for (const r of rows)
  console.log(r.c, await recoverTypedDataAddress({ domain: domainFor(r.c), message, signature: sig }));
// 537713 → 0x7099… (VALID)   every other chain → a different, non-signer address
```

Report it as `distinct separators: 5/5 · distinct digests: 5/5` plus the recovered-address column.
That table is what a triager reads; the forge suite is what backs it.

## 8. Pitfalls that cost rounds here

- **`DOMAIN_SEPARATOR()` does not exist in OZ v5.** Only `eip712Domain()`. Both reverting on a
  contract means "no public getter", not "contract dead" — see §5 for the correct liveness test.
- **A `cast call` with the wrong return signature prints plausible garbage** (`0x0f`, `0x00…00`,
  `[]`) instead of erroring. If `name`/`version` come back empty on a contract you know is
  EIP-712, your tuple annotation is wrong, not the contract. Re-call raw.
- **`eth_getLogs` returning empty is not "no activity".** On the Relay RPC both `eth_getLogs` and
  `eth_getLogsWithCursor` returned silently empty (exit 0, no logs). Do not build a census on it —
  and do not conclude anything from the empty result. Prefer `eip712Domain()` + config JSON, which
  are state reads and always answer. (`live-rpc-forensics-and-eth-call-trap.md` §1 has the explorer
  fallbacks when you genuinely need logs.)
- **`vm.prank` ordering in Foundry fixtures.** `vm.prank(admin); contract.foo(); vm.startPrank(admin);`
  fails with *"cannot overwrite a prank until it is applied at least once"* — and the stack trace
  points at `setUp()` with no line. Use `startPrank`/`stopPrank` blocks exclusively inside `setUp`.
  A `vm.prank` consumed by a call that reverts still counts as unapplied.
- **`address(0x50LVER)` is a compile error, not an address.** Hex literals need real hex; keep vanity
  "names" to `makeAddr("solver")` or `address(0x5017E)`.
- **`vm.expectRevert` with an exact selector needs the inner call to fail for the RIGHT reason.** If
  the inner call reverts earlier (`InsufficientMinimumAmount` before `InvalidSignature`), the test
  fails with the *observed* selector and you learn the ordering — read that selector, it is the trace.
  Better: assert the *mutation* (`usedRequests == false`) rather than only the revert, so an early
  revert cannot masquerade as the check you meant to test.
- **A self-funded resolver is the cheapest way to reach `_finalizeWithdraw`.** When the executor
  pulls input but has zero output balance, everything downstream reverts
  `InsufficientMinimumAmount`. Either fund the executor's output token, set `req_.outCurrency =
  inCurrency` so the pulled input *is* the output balance, or mint inventory to a resolver that
  re-pays `req.outAmountMinimum` — the last one worked cleanly and mirrors real vampire resolvers.
- **`Fee[] memory noFees = new Fee[](0);` then `fees: noFees`.** `fees: new Fee[](0)` inline inside a
  struct literal idiom-fails in some solc versions; hoist the empty array.
- **State the scope of "safe".** "No replay" was proven for: the deployed verifiers' `eip712Domain()`,
  OZ's chainId rebuild, the off-chain signer's literals, and the 1271 split. It was **not** proven for
  the payload builders' `CONFIG`-sourced `evmChainId` data (§4.3) — that is a config-correctness
  dependency, and the report says so instead of claiming a closed chain.

## 9. Report shape that survived

| verdict | evidence cited |
|---|---|
| domain table (name / version / chainId source / verifyingContract / DS) per deployed verifier | live `eip712Domain()` + locally recomputed DS |
| cross-contract replay: NEGATIVE | pairwise-distinct separators; twin dies at `InvalidSignature`; `usedRequests` untouched; positive control on the intended contract |
| cross-chain replay: NEGATIVE | 5/5 distinct separators and digests, recovered-address column, `vm.chainId` flip, OZ rebuild guard |
| oracle digest: NO MISMATCH | `RelayOracleMultisig.isValidSignature` recovers over the raw executor digest; oracle-domain-wrapped signature REJECTED |
| residual / by-design | dead `RelayOracleMultisig` domain; `usedRequests` written before the 1271 check (griefing, not replay); `CONFIG`-sourced `evmChainId` is a data dependency |

Write the negative verdict with the same weight as a positive finding — and include the *rejected*
weaker test (§3) so the next session does not rebuild it.
