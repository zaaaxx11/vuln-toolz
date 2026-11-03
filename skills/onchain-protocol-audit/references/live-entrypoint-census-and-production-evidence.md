# Live-census of a specific entrypoint: turn "capability" into "observed on chain" (or prove it never happened)

Condensed from a Relay Protocol round where the open criticism on a well-proven `callResolver`
finding was *"this is all forge — is it theoretical?"*. The answer came from decoding **1,144 real
`Executed` events** on the live chain, and the reusable part is the pipeline plus what each outcome
is allowed to say.

Companion: `eip712-field-binding-and-unsigned-parameters.md` §10b (the severity measurement that this
census then re-grounded in production data), `bytecode-dispatcher-forensics.md` §9 (prove the
deployed contract IS the repo first — otherwise the calldata you decode is from a different program).

**Section list:** §1 the question this answers, and the three things it does NOT prove ·
§2 pipeline (event → txs → inner call → decoded parameter) · §3 **the batcher indirection trap** ·
§4 the two censuses (caller identity + parameter distribution) · §5 how to read the result ·
§6 the counter-intuitive conclusion that makes the finding STRONGER.

---

## 1. WHAT A LIVE CENSUS PROVES — and the three things it does not

| Claim | Census evidence | Verdict |
|---|---|---|
| The parameter is caller-supplied by external EOAs, not locked by the protocol | N distinct EOAs, all `codesize == 0`, each passing their own value | **PROVEN** |
| The protocol does no whitelist/allowlist validation of it | every call carries the value verbatim into the contract | **PROVEN** (negative, but on-chain) |
| The behaviour is *being exploited right now* | attacker-pattern transactions | **usually NOT shown** — do not imply it |
| The impact number | census gives distribution, not a PoC | keep the forge number for impact |
| That the parameter is *dangerous* | — | census never proves danger; the digest analysis does |

The honest sentence a census licenses is precisely:

> "Over the last N blocks the protocol executed M times; the value was supplied by K distinct EOAs
> with no variation and no allowlist; therefore the parameter is genuinely attacker-selectable in
> production, and the mechanism proven in forge applies to live traffic."

Anything past that ("users are being drained") is fabrication unless you find an actual attack tx.

## 2. PIPELINE — event → tx → inner call → decoded parameter

```python
# 1. topic: compute it from the event SIGNATURE, never from memory (live-rpc §12)
TOPIC = keccak(text="Executed(address,uint256,uint256,uint256,uint256,bytes32)").hex()

# 2. page the range with the cursor method (census ref §9) — `cast logs` full-range times out
logs = get_logs(address=EXEC, topics=[TOPIC], fromBlock=tip-400_000, toBlock=tip)
txs  = sorted({l["transactionHash"] for l in logs})     # dedup: one tx can emit several

# 3. batch-fetch the txs (JSON-RPC batch, 50 per request) — 1,144 txs in ~8 round trips
q = [{"jsonrpc":"2.0","id":i,"method":"eth_getTransactionByHash","params":[h]} for i,h in enumerate(chunk)]

# 4. decode, and count errors loudly
```

**Always print `decoded N / errors M`.** A census loop whose every iteration was swallowed by
`try/except: pass` returns a clean zero that reads as a valid negative (`live-rpc` §15a). If
`decoded == 0 and total > 0`, the bug is your decoder.

## 3. THE BATCHER INDIRECTION TRAP — the tx `to` is not your contract

The first pass showed `tx.to == 0x03a246e0…` (not the executor) and
`selector 0x82ad56cb` = **`aggregate3((address,bool,bytes)[])`** — a Multicall3-style batcher. Two
consequences that each cost a run:

1. **Decoding the outer calldata as `execute(...)` yields nothing.** You must unwrap to the inner
   call first:

```python
calls = abi_decode(["(address,bool,bytes)[]"], bytes.fromhex(tx["input"][10:]))[0]
for (target, allow_failure, calldata) in calls:
    if target.lower() == EXEC.lower():  # ← the real call
        ...
```

2. **Do not guess the inner selector from a signature you half-remember.** My hand-composed
   `execute((uint256,…),address,bytes,address,bytes)` hashed to `0x04546190`; the deployed selector
   was `0x432994b7`. The authority is the **build artifact**:

```python
art = json.load(open("out/RelayExecutor.sol/RelayExecutor.json"))
[f for f in art["abi"] if f.get("name")=="execute"]
# → 0x8446ce98 execute(tuple,address,bytes,address,bytes)  ← the REPO's spelling
# → 0x432994b7 is what the live dispatcher actually answers  ← trust the chain, then reconcile
```

When artifact and live disagree, that is a **finding about the deployment**, not a decoder bug — but
you must notice it. Here the tuple was nested inside one `components` entry and re-spelled between
builds; the practical move is: get the *layout* from the artifact, then confirm the selector by
finding it in the live dispatcher (`bytecode-dispatcher-forensics.md` §2/§3) or by matching a real
calldata prefix.

3. **Positional slot reading works when ABI decode fights you.** With a flat head of 32-byte words,
   the parameter at index `k` is just `word[k]`:

```python
w = inner_calldata[4:]
request_offset = int.from_bytes(w[0:32], "big")     # first word is usually an offset
resolver = "0x" + w[32:64][12:].hex()               # index 1 → the callResolver parameter
oracle   = "0x" + w[96:128][12:].hex()              # index 3
# a tuple's field k lives at request_offset + k*32
out_amount_minimum = int.from_bytes(w[request_offset+4*32 : request_offset+5*32], "big")
```

Hand-slot reading is *more* reliable than a spec you reconstructed, and it cross-checks against the
event topics for free.

## 4. THE TWO CENSUSES WORTH RUNNING

**(a) Who submits** — identity and diversity of the caller:

```python
senders = Counter(tx["from"] for tx in txs)
for s in senders:
    code = rpc("eth_getCode", [s, "latest"])
    print(s, "codesize", 0 if code in (None,"0x") else (len(code)-2)//2)
```

`codesize == 0` on every sender is what rules out "the protocol's own relayer does this" and
establishes permissionless entry. Also check whether the **signer/authority** ever appears as a
sender — on this target the oracle multisig never submitted a single tx through the entrypoint, so
the callers were third parties, not operators.

**(b) Distribution of the free parameter** — the answer is usually a *single* value:

```
RESOLVERS used: 0xb24ac15b… (BasicCallResolver) × 1,144   ← 100%
distinct resolvers = 1        distinct senders = 10
outAmountMinimum: 934548 ×4 … 9,800,000 ×3;  zero floors = 0
```

Include the **floor/hard-parameter distribution** because it is what prevents an overclaim: with
`zero floors = 0` you can say *"the 100%-extraction variant is reachable in code but has never
occurred in production"* — a much stronger, and much more honest, sentence than either "users are
being drained" or "it's only theoretical".

## 5. HOW TO READ THE RESULT — four outcomes, four sentences

| Census outcome | The sentence you may ship |
|---|---|
| parameter varies across many EOAs | "attacker-selectable in production; no allowlist" (strengthens a forge finding) |
| parameter is a single constant, many EOAs | **the strongest shape**: nobody validates it, and everybody happens to pass the same safe value — latent, not exploited |
| you find a tx matching the attack pattern | now you have a *live incident*, and severity climbs with the value moved |
| zero executions in range | the feature is dormant — say "no live traffic", the forge finding stands as capability only |

## 6. WHY "1,144 EXECUTIONS, ZERO EXPLOITS" MADE THE FINDING STRONGER

The instinct is that a clean census weakens the report ("nothing happened"). Invert it. The
transferable argument:

> Over 340,000 blocks the parameter took **exactly one value** across 10 independent EOAs. A protocol
> that considered that parameter security-relevant would show variation or a check. What the census
> shows is a **constant value that is never re-verified** — i.e. every honest participant is
> accidentally safe, and the first dishonest one is not.

That framing is honest, falsifiable, and cites counts. It also survives the triager's "so it's just
MEV" objection better than any prose: the point is not that the bug fired, it is that **nothing in
the deployed system prevents it from firing.**

**Ship rule:** pair the census numbers with the forge PoC — census establishes *reachability in
production*, forge establishes *impact*. Neither alone is a finding; both together are.
