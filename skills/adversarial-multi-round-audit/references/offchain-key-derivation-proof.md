# Proving the off-chain idempotency key (closing the "UNVERIFIED" row)

`identifier-uniqueness-probing.md` ends its ladder at *"off-chain key derivation from `id` =
UNVERIFIED — state it, stop"*. That is correct discipline, but it is a **fallback**. Most
relay/bridge/settlement backends publish their attestation over a public API, and one
read-only GET resolves the entire vulnerability class. This file is the procedure.

**Worked result (Relay, 2026-11):** the user-supplied `id` is *not* the oracle key. Verdict
`KEY=INDEPENDENT`. Duplicate ids collapse to one mint + one refund. **NOT VULNERABLE.**

---

## §1 — Find the lookup that takes an identifier

Probe the identifier-shaped query params until one returns a record:

```bash
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
for q in "hash=$TX" "orderId=$ID" "txHash=$TX" "requestId=$ID"; do
  curl -s -m 30 -A "$UA" "https://api.relay.link/requests/v2?$q" \
    -o "/tmp/r_$q.json" -w "$q -> http=%{http_code} size=%{size_download}\n"
done
```

Lesson from the live run: the **path form** `/requests/v2/<id>` and `/currencies/v2` were
404, `/requests/v3` was 400 `x-api-key required`, and `/intents/status/v2?requestId=` returned
`{"status":"unknown"}` for *both* a tx hash and an orderId — i.e. the obvious endpoint was a
decoy. The real lookups were the **query params** `?hash=` and `?orderId=`. Enumerate params,
don't infer the route from the collection URL.

Rate limits are brutal and non-repeating: `GET /requests/v2` 429s within ~2 calls. Space
successive calls 20–60 s. Save every payload to disk on arrival (`offchain-api-recon.md` §1).

## §2 — Read the attestation out of the record

The record carries the backend's own execution envelope. Field path that mattered:

```text
protocol.orderId                              <- equals the on-chain event id, VERBATIM
protocol.deposit.origin.onchainId             <- a DIFFERENT hash (per-order asset namespace)
protocol.deposit.origin.transactionId         <- the deposit tx hash
protocol.deposit.relay.hash                   <- NOT global; shared across orders of one asset
protocol.deposit.attestation.execution.idempotencyKey   <- THE ORACLE KEY
protocol.deposit.attestation.attestations[].oracleContract
protocol.deposit.attestation.attestations[].oracleChainId
protocol.deposit.attestation.attestations[].signature
protocol.settlement.attestation.execution.idempotencyKey  <- separate key, same oracle
```

**The trap this file exists to prevent:** `protocol.orderId == event id` is true in 11/11
records, and the reflex is to conclude *"the backend keys on the user id → vulnerability."*
It does not. `orderId` is a **label**. The value the contract enforces is
`idempotencyKey`, and it is a completely different 32 bytes. Always name the field the
oracle consumes; never the field that merely looks like an id.

## §3 — Get the oracle address and its chain

`/chains` does **not** list the oracle, and `/oracles`, `/protocol/oracles`, `/relayers`,
`/fast/oracle`, `/chains/oracles` were all 404. The oracle is only reachable through the
per-order attestation. Its chain id (`537713`) was **absent from `/chains`** — a private hub
chain.

Resolve the hub RPC by probing candidate hosts (`hub.relay.link` → 404, then
`rpc.chain.relay.link` → `{"result":"0x83471"}` = 537713). Always confirm:

```bash
RPC=https://rpc.chain.relay.link
[ "$(cast chain-id --rpc-url $RPC)" = "537713" ] || echo 'WRONG CHAIN — stop'
cast code $ORACLE --rpc-url $RPC | head -c 20     # non-empty or the address is wrong
```

A per-order `oracleChainId` that appears nowhere in the public chain list is normal for hub
architectures. Do not conclude the oracle is unreachable; find its RPC.

## §4 — The decisive on-chain read

```bash
O=0xd180dc3b8cb71b185c563b6e4857592ca93dacaf
cast call $O "isExecuted(bytes32)" $IDEM_KEY --rpc-url $RPC    # -> 0x…01
cast call $O "isExecuted(bytes32)" $ORDER_ID --rpc-url $RPC    # -> 0x…00
```

`isExecuted` selector was `0xe52cb36a`, recovered by running `cast selectors` over the
disassembled runtime, then resolving unlabeled ones through 4byte.directory. Do the same for
`execute(bytes,address,bytes) = 0x32acd8f9`.

Run it across **every** resolved record and tabulate — a single row proves nothing:

```text
isExecuted(idempotencyKey)      = 1   11 / 11
isExecuted(orderId = user id)   = 0   11 / 11
```

Also record a **negative** for the derivation: brute-force `keccak(…)` over every order field
and pair (packed *and* `abi.encode`), plus `keccak(actions[0])`. **Zero hits over 19
templates** is itself the evidence that the key is server-generated state, not a hash of
anything the client controls.

## §5 — Prove the guard fires *before* signature validation

`isExecuted()` being true is state; it does not prove the write path consults it. Confirm by
`eth_call`-ing `execute()` read-only with a **dummy** signature and comparing arms:

```text
unused key + 65-byte dummy sig   -> revert UnauthorizedOracle(0x…40)   (reaches auth)
used   key + 65-byte dummy sig   -> bare revert, no revert data, ~0 gas (short-circuits earlier)
```

The used key aborting *earlier* than the unused one is the behavioural proof of an
idempotency guard. A key that is merely absent from an executed-set would revert identically
on both arms.

```text
RULE  isExecuted(key)==true   shows a check WAS satisfied once.
RULE  the different-arms test shows the check is ENFORCED on the way in.
      You need both before claiming replay is blocked.
RULE  empty revert data is not a finding (Rule 9) — but a used-key bare revert vs an
      unused-key NAMED revert IS a differential, because the two arms differ. State which
      arm produced which.
```

## §6 — Run it on a real duplicate-id pair (this is the verdict)

Grab a duplicate from the census (`identifier-uniqueness-probing.md` Step 4), then resolve
**each** tx separately:

```bash
curl "…/requests/v2?orderId=$DUP_ID"        # -> 1 record, inTx = tx1
curl "…/requests/v2?hash=$TX1"              # -> same record
curl "…/requests/v2?hash=$TX2"              # -> a SECOND record, status "refund"
```

Observed for both duplicate pairs:

```text
tx1 -> status success,  outTx on dest chain
tx2 -> status refund,   refund tx on origin chain
both records share the SAME deposit idempotencyKey  (and the same settlement key)
isExecuted(that key) == 1
refund tx: to = depositor, value = principal - fee, input = the same id
```

That is the whole verdict: **two deposits with one `id` produce one key, one mint, one
refund.** Funds are conserved, no double-spend, Not Vulnerable. The residual is a
**fee-only self-grief** (~0.4 % of amount) and an INFO that a non-unique caller-chosen
`orderId` makes the API index ambiguous/shadowable in a UI — neither moves value.

## §7 — Verdict lines, and the shape that would have been Critical

```text
KEY=DERIVED_FROM_USER_ID      -> duplicates share one key -> COLLAPSE -> safe
                                 duplicates get distinct keys -> DOUBLE-SPEND -> Critical
KEY=DERIVED_FROM_TXHASH       -> cannot collide by construction -> class closed
KEY=INDEPENDENT (unforgeable) -> user id is a label only -> safe
KEY=UNKNOWN                   -> only after §1–§6 all fail; say which step failed
```

The finding you are looking for is the **second row**: two deposits, same `id`, **different**
`idempotencyKey`s, **both** `isExecuted == 1`. Everything in this file exists to let you tell
that apart from the first row, which looks identical in the logs and is safe.

## Pitfalls

- **`orderId == event id` is not `key == event id`.** The single most expensive misread in
  this class. 11/11 equality on the wrong field still proves nothing.
- **A field named `onchainId` inside the API need not be the on-chain event id.** Here it was
  a per-order asset hash, unrelated to the `id` in the log.
- **`protocol.deposit.relay.hash` was not global** — it repeated across all orders of one
  asset. Never treat a repeated field as a constant until you have tabulated it.
- **Don't hand-build `execute()` calldata and trust the revert.** Struct-tuple offset packing
  produces `UnauthorizedOracle(<garbage>)` for the wrong reasons. Use the differential
  (used vs unused key), which survives a malformed envelope better than an absolute reading.
- **`isExecuted` is likely not a plain `mapping` at slot 0..N.** Probing
  `keccak(key ‖ 0..9)` returned all-zero on this oracle (namespaced/EnumerableSet store).
  Absence of the slot is not `false`; the getter is the oracle, not the storage.
- **Archive `eth_getLogs` dies past ~10 k blocks** (`-32602 Archive requests require a
  personal token`). Sweep forward in ~900-block chunks; a bounded window still finds
  duplicates (5 pairs in 28 246 logs).
