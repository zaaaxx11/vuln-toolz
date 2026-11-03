# Handoff-Chain Mapping for Multi-Component Protocols (the "chainer" role)

## When to use

Brief shapes that mean this class:

- "peta handoff" / "cari jalur di mana output satu komponen menjadi input komponen lain"
- "apakah ada step yang bisa attacker lengkapi sendiri?"
- a multi-agent audit where one agent owns **cross-component chains** while others own single
  components (e.g. "AGENT 4 — CHAINER (handoff + admin web2)")
- any protocol split across repos: hub-chain Solidity contracts + an off-chain
  attestation/oracle service + a TEE signing action (Lit Action / PKP) + per-VM payload
  builders + SDK packages.

The deliverable is **documented chains**, each written step-by-step with `file:line` for every
hop plus the real deployed address/endpoint, and a verdict per hop:
**PROVEN** (executed or read on-chain) / **INFERENCE** (source-only) / **UNTESTED** (needs live
state you could not read). Never present a source line as live behaviour without the on-chain
check, and never present an on-chain observation as the design.

## Method (4 steps)

1. **Enumerate every component's entry point first.** For the oracle service the route table IS
   the attack surface — read `src/api/index.ts` (or the equivalent registration list) and then
   each route file's schema + handler. Enumerating routes from source is polite and complete;
   guessing paths against the live API is neither.
2. **Build the data-flow graph.** For each hop write: "component A produces X (field list) →
   component B consumes X as Y". The interesting hops are where the producer and consumer
   *interpret the same bytes differently*.
3. **Ask the chainer's question at every hop: who can supply this field, and is it committed
   anywhere the attacker cannot reach?** Signed/committed = safe. Supplied at execution time =
   attacker-completable (or at minimum resolver-retainable).
4. **Verify the live wiring read-only with `cast`** before claiming a chain (recipes below).
   Label anything unverified UNTESTED — a role table read from source is a design claim, not a
   fact.

## Recurring finding classes (generalized from the Relay settlement run)

1. **Permissionless registration + attestation blindness.** A `trigger()`-style entry with no
   access control records `hash → orderId`. If the hash binds an *id* but not the *derivation
   fields*, and the off-chain attestor only checks `triggers[hash] == orderId`, an attacker can
   register alternate derivation fields (different `salt`, different `outputRecipient`) for the
   same order and obtain a valid attestation for a different derived address. Check whether the
   verifier re-derives the fields against the signed order or only compares the id.
2. **Committed vs execution-time-supplied fields.** Diff the EIP-712 struct against the
   `execute()` parameters. Anything in the latter (`callResolver`, `callResolverData`, calldata
   hiding behind a `dataHash` commitment) is attacker-completable if the attacker can also
   produce the signed request — and even when they cannot, the resolver may retain value as
   long as the signed minimum output is met. Also note deterministic nonces
   (`keccak256(block.number, address(this), chainId, depository, params)`): predictability is
   not itself a bug, but it removes an entropy assumption worth stating.
3. **Once-per-key accounting on an influenceable key.** `feesChargedByOrderAddress[addr]`-style
   one-shot guards are sound only if the key is exclusive per order. If the off-chain service
   already compensates (oracle omits fees once the flag flips), the finding is "invariant
   asserted in a comment but not enforced on-chain" — cite the comment, cite the off-chain
   mitigation, and rate it accordingly.
4. **Signature-authorized spend of a third party's balance.** `payGas`-style functions callable
   by *anyone* holding a valid oracle signature, burning from an alias derived from request
   fields. The four questions: is there a per-spender cap? Can one signature be replayed across
   different parameter sets (is the nonce inside the signed struct)? Do byte-identical params
   share one record between two spenders? Is there any refund path? A doc comment that admits
   "anyone can submit a payment carrying a valid oracle signature" is the finding's own
   evidence — quote it.
5. **Gas/fee payment keyed by params hash.** `keccak256(chainId, depository, params)` keying
   means two spenders with byte-identical parameters share one record: first payer burns,
   second reverts `AlreadyPaid`. Griefing and free-ride depending on submission order.

## `cast` verification recipes (all read-only)

- **Chain sanity first:** `eth_chainId` against the deployment JSON's `chainId` before
  trusting any address.
- **Role holders:** `cast call <c> "hasRole(bytes32,address)(bool)" <role> <candidate>` for
  every plausible candidate (oracle multisig, oracle contract, owner EOA, admin safe). Role id
  = `keccak256("ORACLE_ROLE")` etc.
- **Grant enumeration:** `cast logs --from-block 0 "RoleGranted(bytes32,address,address)"
  --address <c>` — on a slow public RPC a full-range scan can time out; bound the range or
  fall back to candidate probing and label the result UNTESTED rather than "no other holders".
- **Immutable getter that reverts:** try the getter, then `cast storage <c> 0`, then consider
  that the deployed bytecode may predate the field. **A reverting getter is a version-drift
  signal, not a dead end.**
- **Derived alias checks:** `cast keccak $(cast abi-encode "f(string,bytes)" "relay" <addr>)`
  → last 20 bytes, then `cast call <hub> "isOperator(address,address)(bool)" <alias> <op>`.
- **String-keyed mappings:** `cast call <allocator>
  "payloadBuilders(string,bytes)(address)" "ethereum" <depository>`.
- **Builder → gas-payer binding:** `cast call <builder> "GAS_PAYER()(address)"`.
- **Multisig signer set:** `cast call <ms> "getSigners()(address[])"` + `threshold()`.

## Deployed-lags-repo pitfall (decides live vs UNTESTED)

Worked example from the Relay run:

- Repo source says the Executor's oracle is the multisig, but on-chain
  `hasRole(ORACLE_ROLE, oracleMultisig) = false` while the **owner EOA holds ORACLE_ROLE**.
- `GAS_PAYER()` answers on the Gateway payload builder but **reverts** on the TON and XRP
  builders that inherit the same mixin in source.
- `Allocator.ORACLE_MULTISIG()` reverts while `Allocator.HUB()` answers fine.

Conclusion pattern: cite the source line as the **design**, cite the `cast` output as the
**live state**, and label the delta explicitly (misconfiguration / older deployment /
unverified). Do not silently pick one.

## Repo-leak recon — what a clean bill looks like

- `.env.example` with placeholder values (`ECDSA_PRIVATE_KEY=0x`) plus configs that substitute
  env vars (`httpRpcUrl: "$ETHEREUM_RPC_URL"`) = no hardcoded secrets. **Say so explicitly**;
  silence reads as "not checked".
- `.gitleaks.toml` allowlist paths are a **map of where high-entropy strings live**
  (deployment records, test fixtures, transaction dumps). Read those files — they usually carry
  the production addresses you need for the on-chain verification step.
- CI workflows that consume only `github.token` = no secret-exposure surface; note the check.
- Grep `0x[a-fA-F0-9]{64}` and filter out bit-mask constants, EIP-712 typehashes, and tx hashes
  before calling anything a key.
- Oracle API surface: unauthenticated Swagger UI at `/documentation`, `/lives` and `/` excluded
  from the rate limiter, default unauthenticated limit ~2 req/s per IP — enough for polite
  enumeration, and worth reporting as the actual exposed surface.

## Budget discipline (this class kills sessions)

The brief mandates an output file ("write /tmp/agent4_chain.md, min 3 documented chains + a
20-line summary"). **Write the skeleton by call ~5 and append per finding.** The Relay session
burned its entire budget reading five components end-to-end plus `cast` verification and never
wrote the file — a complete analysis that produced zero deliverable. Suggested split:
~40% reading, ~20% verifying, ~40% writing. `cast` calls are cheap; reading contracts + service
+ action + SDK end-to-end is not.
