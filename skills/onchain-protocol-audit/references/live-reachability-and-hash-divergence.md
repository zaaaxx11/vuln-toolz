# Live reachability gating + the two-hashes-from-one-struct divergence class

Condensed from a multi-round hunt on Relay Protocol's settlement contracts
(`RelayAllocator` + `payload-builders/*`). The defect class below is
reusable across any "allocator/solver signs per-VM payloads" architecture.
The *process* lesson at §12.1 cost the most rounds and generalises to every
on-chain audit.

---

## §12.1 Census the deployed config BEFORE assigning severity

The single highest-leverage step, and the one most often skipped. A finding in
a contract that ships in the repo but is **not wired into the live deployment**
is *latent*, not *live*. Say so explicitly — don't discover it in triage.

Method (no explorer API key needed, works on any range-filtered JSON-RPC):

1. Pull the target's own event log over its full history. Use a
   **range-based** `eth_getLogs` (`fromBlock`/`toBlock`), not cursor-based
   APIs — a bare `eth_getLogsWithCursor` query can return `logs: []` with a
   null cursor *even for a contract that definitely has events*, which reads
   exactly like "no events" and sends you down the wrong path. Validate your
   query shape first against an event you know exists.
2. Decode the config-registration events (here `PayloadBuilderSet(chainId,
   depository, builder)`). Collect the set of registered implementation
   addresses.
3. For each distinct address, call the identity accessor (`family()`,
   `version()`, `name()`) via `eth_call` and group.
4. Compare that live set against the inheritance graph in the repo. Any
   contract whose guard lives in an *unregistered* base or sibling is not
   reachable in production.

Worked result: 12,385 `PayloadBuilt` events, 83 `PayloadBuilderSet` events, but
only **two** distinct builders wired — `family()` = `ethereum-vm` and
`solana-vm`. The XRP / TON / Gateway builders existed in the repo and carried
the guard, and were simply never registered. That flipped the report from
"Critical, live" to "Medium, latent — exploitable on any deployment that
registers a gas-paid builder."

Practical notes:
- `keccak256` for topic0 = use pycryptodome (`Crypto.Hash.keccak.new`), not
  `sha3_256`. `cast keccak` also works.
- Chain ids in this protocol were *strings* (`"arbitrum"`, `"linea"`, …), so
  recover them by matching `keccak256(name)` against the topic word, not by
  reading a numeric chainId.
- Depository addresses likewise appear as topic words; enumerate the distinct
  set rather than assuming one.
- Record block numbers per `(chain, depository, builder)` tuple — it gives you
  the config-change timeline for free.

## §12.2 The divergence class: two hashes computed from one request struct

This is a *pattern*, not a one-off. When a contract computes both

- a **replay/idempotency key** over the *full* request, and
- a **policy/entitlement key** over a *projected subset* of that request,

then any field present in the first but absent from the second becomes an
unbound degree of freedom. The replay guard structurally cannot catch an
attack that lives in the difference set, because the two requests are
legitimately distinct.

Worked instance (`RelayAllocator` + `GasPaidPayloadBuilder`):

| hash | preimage | includes spender? |
|---|---|---|
| `withdrawRequestHash` — replay guard, `payloads` mapping | `keccak256(abi.encode(params))`, full `WithdrawRequest` | **yes** |
| `withdrawParamsHash` — gas-payment key, `gasPayments` mapping | `keccak256(abi.encode(chainId, depository, BuildPayloadParams))` where `BuildPayloadParams = {currency, amount, receiver, nonce, data}` | **no** |

`_buildPayload` constructs `BuildPayloadParams` and silently drops `spender`
and `spenderChainId`. `WithdrawGasPayer.payGas` burns the *payer's* alias and
records under that narrower key. Consequence: attacker picks
`(chainId, depository, currency, amount, receiver, nonce, data)` byte-identical
to a victim's request; the victim's burn satisfies `_requireGasPaid` for the
attacker's build; the attacker pays zero gas. `withdrawRequestHash` still
differs (spender differs) so the replay guard passes it through.

Impact framing that triagers accept: this is **fee externalisation / shared-cost
abuse, not principal theft** — each party's `amount` is burned from their own
alias. Bounded by the per-request fee cap. Call it Medium, repeatable per
victim payment, and note it defeats the entire purpose of the prepayment
contract.

### How to hunt this class efficiently

1. Grep for every function that hashes a request struct:
   `grep -n "keccak256(abi.encode" <dir>`.
2. Build the field table above. Any asymmetry in field coverage is a lead.
3. Identify which key gates a *privilege* (payment, allowlist, rate limit,
   nonce) vs merely dedup. The privilege key is the one that matters.
4. Prove by constructing two requests that differ **only** in the dropped
   field, showing the privilege key is identical and the dedup key is not.
5. Test harness requirement: build both requests with an **identity-nonce**
   (`keccak256(abi.encode(receiver, seq, fee, amount))`, deliberately
   *spender-independent*). If your test helper keys the nonce on the spender,
   the two structs diverge, the hash mismatch hides the bug, and you will
   chase a phantom revert instead. This was the actual blocker for several
   rounds.

## §12.3 Role wiring in Foundry fixtures for allocator/payer architectures

Two distinct traps, both of which produce `AccessControlUnauthorized` that
looks like a protocol bug:

1. **Find *which* contract is `msg.sender` at the failing frame.** Do not assume
   it is your test actor or the top-level caller. In this architecture the
   *allocator* — not the payer and not the test — calls `RelayHub.burn`. The
   allocator therefore needs `OPERATOR_ROLE`. Read the `-vvvv` trace for the
   reverting frame's `msg.sender`, then grant that address.
2. **Multiple deployments of the same contract.** A test that constructs its
   own `RelayHub` *and* an allocator that was given a different hub address
   will grant the role on the wrong instance. Match the address in the revert
   against the constructor args before granting anything.

Grant roles *after* the last deployment, in one block, and include the
protocol components (allocator, gas payer) as legitimate role holders — mirror
production. Do not grant the attacker's EOA a role you wouldn't grant it on
mainnet; that invalidates the PoC.

## §12.4 Distinguish "no data slot" from "no commitment" before reporting

A signed struct omitting a field looks like an unsigned-input bug. Check
whether the field reaches the signer through an *oblique channel* first.

Worked instance (TON builder): `TonTransferRequest` has no `data` field, so
`hashesToSign` cannot see `params.data`, while the gas-payment key *does*
include it — which looks exploitable. But `_computeQueryId` folds
`keccak256(block.number, nonce, currency, receiver, data, amount)` into a
23-bit `queryId`, and the signed Highload V3 cell commits that `queryId`
(13-bit shift + 10-bit bit_number). So `data` IS covered, lossily. The honest
finding is "lossy commitment, griefing-only ceiling already documented" — not
"unsigned input". Write the negative result down; it saves the next round.

Generalised: before claiming an unbound field, trace the field **forward**
through every derivation to the final signed preimage. Only fields that die in
the derivation chain are unbound.

## §12.5 Cheap closure checks that avoid false positives

Run these before writing anything up; each killed a plausible-looking lead in
this engagement.

- **`permit`**: single implementation? deadline checked? per-owner nonce
  *inside* the typed-data digest? nonce incremented *before/at* the allowance
  write? domain separator via `_hashTypedDataV4`? All yes ⇒ clean, no replay.
- **ECDSA malleability**: check the OZ version. OZ ≥ 4.7 `tryRecover` returns
  `RecoverError.InvalidSignatureS` for high-S, so `(r, n−s)` fails. Confirm
  every recovery site checks `NoError` (or uses `recover`, which reverts). Also
  confirm no nonce/hash is keyed on `s` itself — if it isn't, malleability has
  no escalation path even in principle. A 2-test probe (`high-S rejected`,
  `low-S not blocked *by the S check*`) is enough.
- **Attacker-configurable view/adapter contracts**: grep for *every* writer of
  the mapping. If the only writer is an internal `_create*` invoked from a mint
  path, a third party cannot repoint it. Bounded — say so.
- **`abi.encodePacked` of dynamic arrays**: unpacked `encodePacked` on
  `bytes32[]`/dynamic types can concatenate ambiguously. Here
  `hashCallRequest` used `encodePacked(callHashes)` with all elements
  fixed-width `bytes32`, which is safe. Verify element width before flagging.
- **`dataHash == 0` in a `{data, dataHash}` struct**: zero is usually the
  documented "inline data supplied" sentinel, with the hash substituted at
  hash-time (`if (dataHash == 0) dataHash = keccak256(data)`). Read the
  substitution site before calling zero-value an unvalidated input.

## §12.6 When hand-decoding ABI is eating the round budget, switch

Decoding live event payloads by hand (`int.from_bytes` limb arithmetic) burned
many rounds in this session. The failure mode is subtle: off-by-one-limb
offsets produce *plausible* values (a real-looking address, a real-looking
length) that are simply shifted, so you don't notice you're wrong — you just
get numbers that don't match and re-guess.

Heuristics that actually worked:

- **Print every limb with its offset first.** `for i in range(0, len, 32):
  print(i, hex(u(i)))`. Two rounds of that beats five rounds of targeted
  slicing. Look for the tell: an offset word whose value is `32`, `64`, `96`,
  `128` sits *ahead* of each dynamic member — count them.
- **A leading `32` in limb 0 means one wrapper layer.** `abi.encode(bytes)` of
  a struct adds an offset; `abi.decode(payload, (bytes))` then
  `abi.decode(inner, (T))`.
- **`n * 32` vs `n` confusion**: for a dynamic array, `limb[0] = n` (count) and
  the element offsets follow *inside* the array data region; the array's own
  offset points to the count word. Getting this backwards yields an absurd
  count (e.g. `n = 96` when the payload is 448 bytes) — a good self-check.
- **Give up on hand-decoding after ~3 attempts and use the compiler.** Write a
  Foundry test importing the *real* struct type (`import {Call,
  CallRequest} from "relay-contracts/payload-builders/…"`) and
  `abi.decode(payload, (CallRequest))`. Mirror structs you retype by hand
  differ in field order/`bool` packing from the original and revert in ways
  indistinguishable from a genuine encoding bug.
- If a decode test still reverts while the hand-decode looks sane, the payload
  bytes you captured are probably not the full `abi.encode` output (nested
  wrapper or a sliced field). Re-extract the exact event `data` and compare
  lengths against `4 + 32*expected_limbs`.

**Rule of thumb:** a decode test that fails is a *harness* problem until
proven otherwise. It must never be left red in the deliverable — either fix it
or delete it and cite the hand-decode in the write-up. A red test in the
deliverable reads as a broken finding.

## §12.7 Repo build hygiene during a hunt

- A pre-existing broken test file blocks *all* compilation and therefore all
  new tests. Move it aside (`mv test/<file> /tmp/…`) rather than editing it —
  do not silently "fix" code you are auditing, and do not let a harness
  failure get attributed to your finding.
- `grep -n "test\s*=\|exclude\|src\s*=" foundry.toml` before assuming the test
  glob is `test/`.
- When a function must call a state-mutating helper, the compiler rejects
  `view` (`Function cannot be declared as view…`). This is noise, not a
  finding; drop `view` from the test signature.
- `opts.hash` changed in Foundry 1.x — `vm.envOr`/cheatcode signatures drift;
  when a cheatcode call fails cryptically, check the installed forge version
  before doubting the test logic.
