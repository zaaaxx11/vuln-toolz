# Identifier-Uniqueness Probing (duplicate-id census on live logs)

**When to use.** A deposit / bridge / settlement / claim contract takes a caller-supplied
`bytes32 id` (or any opaque identifier) and some *off-chain* service is supposed to treat it
as an idempotency key. You want to know whether the contract enforces uniqueness, and whether
a caller can pick an identifier that collides with someone else's.

This works **read-only, pre-signature, with no ABI trust** — it is pure log arithmetic.

---

## Why this probe is high value

The most common real shape of this bug class:

```solidity
function depositNative(address depositor, bytes32 id) external payable {
    // no mapping, no nonce, no `require(!used[id])`
    emit RelayNativeDeposit(depositor, msg.value, id);
}
```

Uniqueness is **assumed downstream**, enforced nowhere on chain. If the off-chain service
derives its idempotency key from `id`, then:

- one legitimate retry ⇒ one of the two deposits can never be minted (silent user loss), or
- one attacker with 1 wei ⇒ the victim's chosen `id` is burned before they land (griefing).

Neither is provable from the contract alone. Both are *strongly indicated* the moment you can
show duplicate ids exist in production and that the write path has no guard.

---

## Step 1 — dump a narrow log window (archive-free)

Public RPCs reject wide ranges with `-32602 Archive requests require a personal token`. Do not
conclude the endpoint is broken — narrow the window.

```python
for w in (200, 500):                      # blocks back from head
    r = rpc('eth_getLogs', [{'address': TARGET,
                             'fromBlock': hex(head - w),
                             'toBlock':   'latest'}])
    if 'result' in r:
        break
```

**Read `error` before `result`** (see Rule 1 of `abi-and-field-verification.md`). A 200-block
window on a busy depository is still several MB of logs and is plenty.

## Step 2 — decode ids positionally, per event signature

Do this **per topic**, because a contract emitting several deposit events puts the id at
different word offsets:

```python
words = [data[2:][i:i+64] for i in range(0, len(data) - 2, 64)]
if topics[0] == SIG_NATIVE:          # RelayNativeDeposit(address,uint256,bytes32)
    ident = '0x' + words[2]
elif topics[0] == SIG_ERC20:         # RelayErc20Deposit(address,address,uint256,bytes32)
    ident = '0x' + words[3]
```

Anchor the offset on a value you already know before trusting it: pull one tx receipt, find
the id you can see in the calldata, confirm the decoder reads that same position (Rule 13).

## Step 3 — the census

```python
from collections import Counter
c = Counter(ids)
dups = {k: v for k, v in c.items() if v > 1}
print(f"deposits={len(ids)} unique={len(c)} DUPLICATES={len(dups)} "
      f"unique_senders={len(set(senders))}")
```

**Aggregate across every window you fetched** — a duplicate can straddle a boundary. And
de-duplicate the *logs* properly: if two windows overlap, you will manufacture duplicates
that do not exist. Key each deposit on `(txHash, logIndex)`, not on the raw log object.

## Step 4 — pin the duplicate to two distinct txs

A duplicate id is only meaningful if it came from **two separate transactions**. Two logs in
one tx is a loop; two txs 21 blocks apart is a user double-submitting and the contract
happily accepting it.

```python
hits = [l for l in logs if DUP_ID[2:34] in l['data']]
for h in hits:
    print(int(h['blockNumber'], 16), h['transactionHash'], int(h['logIndex'], 16))
```

Then compare the two `eth_getTransactionByHash` inputs. **Byte-identical calldata** across
two txs is the cleanest possible proof: same depositor, same amount, same id, accepted twice.

---

## Step 5 — before calling it a finding, run the FUND-DESTINATION test

Duplicate ids are **an anomaly, not a loss**. The three questions (same gate as Rule 21):

1. **Who pays?** The deposit is funded from the caller's own balance / `msg.value`. An
   attacker burning an id costs themselves gas, but it does *not* take the victim's funds.
2. **What does the contract do with the duplicate?** It emits a second event. No state is
   corrupted on chain. Funds are held, not stolen.
3. **Can the victim actually lose?** Only if the off-chain attestation keys on `id`. That is
   a **backend fact you cannot prove from chain data.**

**Honest verdict ladder:**

| Established | Label |
|---|---|
| no `used[id]` guard in source | `PROVEN BY CODE` |
| duplicates exist in real logs | `PROVEN LIVE` (anomaly) |
| byte-identical duplicate txs | `PROVEN LIVE` (strongest form) |
| off-chain key derivation from `id` | `UNVERIFIED` — state it, stop |
| griefing with real victim loss | **not claimable** without the above |

Report the anomaly and the code-level absence of a guard. Do **not** promote an unverifiable
backend assumption into Critical — the same trap Rule 21 describes for `depositor` spoofing.

### Step 5d — you CAN often close the "off-chain key" row. Do this before writing UNVERIFIED.

`UNVERIFIED` is the *fallback*, not the default. The row above is only unprovable if you have
not looked; the backend frequently publishes its own attestation, and one read-only GET
resolves the whole class. See **`references/offchain-key-derivation-proof.md`** for the full
procedure; the shape is:

```text
1. find the API lookup that takes a tx hash or the id   -> /requests/v2?hash= | ?orderId=
2. read the attestation out of the record              -> protocol.deposit.attestation
3. identify the real key the contract enforces         -> .execution.idempotencyKey
4. compare it against the caller-supplied id           -> equal? derived from user : independent
5. confirm on-chain with isExecuted(key) vs isExecuted(id)
6. RE-RUN on a duplicate-id pair                       -> same key? one mint + one refund = SAFE
```

Step 6 is the one that converts "duplicates exist" into a **verdict**. Without it you have an
anomaly; with it you know whether duplicates collapse or double-spend.

```text
RULE  a duplicate-id anomaly grades on the BACKEND's key, not on the contract's missing guard.
      Same key on both deposits -> collapsed -> safe (maybe a fee-only self-grief).
      Different keys            -> double-spend -> that is the Critical, now PROVEN.
RULE  "the API's `orderId` equals the event id" is NOT "the backend keys on the event id".
      Check the field the oracle actually consumes, not the field that looks like an id.
```

---

## Step 6 — the free-parameter companion probe

The same contracts usually take a free attribution field (`depositor`, `from`, `beneficiary`)
that is unbound from `msg.sender`. Test it in one fork call:

```solidity
// real ABI, verified from a live tx — see Rule 8b
function depositNative(address depositor, bytes32 id) external payable;

vm.prank(attacker);
depositor.depositNative{value: 1 ether}(victim, keccak256("x"));
// event now attributes a 1 ETH deposit to `victim`, paid by `attacker`
```

This is almost always **AUTH-OPEN-BY-DESIGN** (a credit label, not a withdrawal claim) —
grade it as such, and pair it with the duplicate-id census so the report shows you tested
both the label and the identifier.

---

## Step 5b — a REVERT is not a uniqueness guard (the trap that inverts this whole probe)

The census says duplicates exist. Before you conclude "the contract *does* enforce uniqueness,
my PoC just hit the guard", check what actually reverted. In this campaign a fork PoC calling
a hand-built selector reverted with **empty data**, and that empty revert was read as
"the gate rejected me ⇒ ids must be unique". The opposite was true — the real live txs already
proved duplicates are accepted.

```text
empty revert data  ->  NOT evidence of any guard        (Rule 9)
                       it is the absence of information
correct conclusion ->  your calldata is wrong, or the node swallows revert reasons
```

**Order of proof, and it is not negotiable:**

```text
1. census on live logs          -> duplicates EXIST or do not      (chain fact)
2. real tx calldata             -> the ABI, from a real tx        (Rule 8b)
3. fork PoC with THAT ABI       -> reproduces acceptance          (confirms 1)
4. only then: does a guard exist? -> read the source, find the mapping
```

A PoC that reverts does **not** outrank a live census that found duplicates. Chain data beats
your harness. If they disagree, the harness is wrong — every time, without exception, because
the census is measured and the PoC is constructed.

Corollary for fork tests specifically: `vm.createSelectFork` on a public RPC can fail to
resolve or rate-limit, producing a revert that looks identical to a logic revert. Assert the
fork is live before trusting any revert — deposit a known-good call first (`test_A_*`), and only
then read the negative test. A suite whose first test passes for the wrong reason poisons the rest.

## Step 5c — grade the pair, not the individual findings

This probe almost always produces **two** findings that only mean something together:

```text
F-a  free attribution field (depositor/from/beneficiary unbound from msg.sender)
F-b  caller-chosen id with no on-chain uniqueness guard, duplicates live in production
```

Each alone grades as INFO/AUTH-OPEN-BY-DESIGN and a reviewer will (correctly) dismiss it.
Together they describe one attack shape: *attacker picks a victim's intended id, burns it with
dust, and the victim's later deposit is un-attestable.* Lead with the composed chain and put
each half underneath it — never let a reader see only the halves.

```text
RULE  when two findings compose into a chain, the report's headline is the CHAIN.
      Each part carries its own grade; the chain carries its own, higher-stakes grade.
RULE  state the chain's grade honestly too: if the final link is a backend assumption,
      the chain is UNPROVEN end-to-end no matter how solid the two halves are.
```

## Pitfalls

- **`topics.length == 1` means every field is in `data`.** No indexed id ⇒ you cannot filter
  with `topics[1]`. Decode `data` or you will scan the wrong bytes.
- **Overlapping windows inflate `unique` and destroy `dups`.** Always key on `(tx, logIndex)`.
- **A duplicate inside one transaction is not evidence** — it is a loop in the emitter.
- **Don't infer the amount parameter from the event.** `amount` in the event may come from
  `msg.value`; check `tx.value` before writing a PoC signature (Rule 8b).
- **Fork tests on public RPCs revert from rate limits**, not just logic. Re-run before
  theorising; `HTTP 403` and empty revert data are different failures.
- **A reverting PoC does not disprove a passing census.** See Step 5b — the constructed
  harness loses to the measured chain, always.
- **`vm.createSelectFork` needs a warm-up call before you trust any negative test.** A dead
  fork and a logic revert are indistinguishable. Run one known-good call first.
- **Don't let the two halves of the finding (free field + duplicate id) get reported
  separately** — a reviewer dismisses each alone. Step 5c.
