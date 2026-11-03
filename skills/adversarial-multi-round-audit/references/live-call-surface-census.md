# Live-contract call-surface census

How to find out whether a deployed contract is actually **used**, and how it is **reached** — three traps that each
produced a wrong verdict in one session.

---

## 6. `eth_call` params are POSITIONAL and the block tag is mandatory — a doubled `0x` reads as a contract bug

Two distinct encoder bugs, both of which surface as plausible *contract* behaviour:

```text
{'to':H2,'data':'0x'+sel+tid}                    # tid already starts with '0x'
  -> {"code":-32602,"message":"Invalid params",
      "data":"invalid value: string \"0xbd85b0390xa09361e654…\", expected a valid hex string"}

{'to':H2,'data':'0x'+sel+P(addr)+tid,'latest'}   # '0x…' left INSIDE the params dict
  -> {"code":-32602,"message":"Invalid params","data":"invalid value: string \"0x91d1485497…\""}
```

Both read as `Invalid params` on a call you believe is valid, and the natural next thought is
"this contract has no such function". It does. Rules:

```text
RULE  strip the 0x exactly ONCE:  '0x' + sel + word_hex   where word_hex has NO prefix
RULE  the block tag is a separate PARAM, never a dict entry:
        raw('eth_call', [{'to':a,'data':d}, 'latest'])
      {'to':…, 'data':…, 'block':'latest'} is silently invalid on strict clients
RULE  a repeated '0x' inside the hex data is the tell: grep your error string for '0x0x'
      or for a selector immediately followed by '0x'
```

A helper that always takes bare hex words makes this class unreachable:

```python
def w(x):                      # accept int, '0x…', or bare hex -> exactly one 0x in output
    if isinstance(x, int):  return f'{x:064x}'
    return x[2:] if x.startswith('0x') else x
def call(to, sel, *words):
    return raw('eth_call', [{'to': to, 'data': '0x' + sel + ''.join(w(x) for x in words)}, 'latest'])
```

Corollary for role censuses: run them through this helper, not through ad-hoc string
concatenation. An `Invalid params` on 3 of 11 `hasRole` candidates in a census is an encoder
bug, and if you had reported the 3 as `False` you would have invented an ownership finding.

---

## 7. Direct tx history ≠ usage: the sub-call blind spot

An explorer `txlist` for a contract returned **exactly one row — its deployment**. That reads as "never used, dead
surface, INFO". It was in fact invoked repeatedly *inside a batcher's `aggregate3`*: the transaction's `to` was the
batcher, so indexing by the inner contract's own address never sees those calls. The same contract held `isOperator`
rights on the hub and had moved 4.89 M units in one run.

```text
direct   : explorer txlist where tx.to == target
indirect : target appears as a `target` inside another contract's calldata (decode the aggregate3
           (address,bool,bytes)[] tuples), or as a value-flow counterparty in eth_getLogs
```

If value flow exists but direct txs ≈ 0, label it **live-but-indirect**, never DEAD-CODE.

Related traps:
- A log with `topics[2] == contract` means the contract **received** a transfer, not that it was called. Chasing those
  produced two "hits" whose calldata decoded into a completely different contract.
- Nested `aggregate3` offsets are relative to their own tuple start. A flat walk yields nonsense like
  `target=0x…60` — that is the walker's bug, not a target address.

## 3. Selector absence/presence is a hypothesis in BOTH directions

For "find transactions to contract X":

```text
1. explorer: /api?module=account&action=txlist&address=X&sort=desc&page=1&offset=50
2. read input[:10] per row, and txreceipt_status / isError
3. eth_getTransactionByHash for the interesting rows -> full calldata
```

A 6,000-block `eth_getBlockByNumber` sweep (full tx list per block) ran **5+ minutes twice and printed zero progress**
on a rate-limited RPC — 2 round-trips per block. One `txlist` request returned the full history in ~3 s. A staggered
`for back in range(0, 30000)` sweeper is the wrong instrument; keep it only for chains with no explorer index.

Payoff in-session: the real `execute` selector was `0x432994b7`, recovered from one `txlist` row, after three
hand-built selectors and ~40 minutes had failed.

## 3. Selector absence/presence is a hypothesis in BOTH directions

```
len(eth_getCode)  ==  len(artifact.deployedBytecode)   -> SAME CONTRACT: your signature is wrong
```

Equal length at 9131 bytes on both sides, while `execute` "was not in the bytecode", nearly produced a Critical
drafted against a contract that was never changed. Rules:

- Compare bytecode lengths **first**, before concluding "live ≠ repo".
- A `PUSH4`/`PUSH3` scan proves nothing when a selector is *absent* (modern compilers also compare
  `shr(224, calldataload(0))` against embedded constants).
- Presence in a scan does not confirm *which* function a selector belongs to either — the real `0x432994b7` **was**
  in the scan all along; the hand-built signatures had simply never matched it.
- Only two things close the question: source-verified explorer source, or a real transaction's calldata replayed.

Struct-heavy signatures: build them from `out/<X>.sol/<X>.json`, flattening `components`. Do **not** trust
`internalType: "struct Foo"` or declaration order in the `.sol`. `bytes32` vs `uint256` for a nonce changes the
selector and is invisible in a terse type list.

## 4. Grade a public unguarded function by surface, not by scariness

`BasicCallResolver.execute()` is `external nonReentrant` with **no access control at all**: it decodes
`(Call[], Sweep[])`, runs `call_.to.call(call_.data)` for each with no target/data allowlist, then sweeps its own Hub
balance to any `sweep.recipient`. Live role census returned `hasRole(X, resolver) == 0` for all ten role hashes, with
`hasRole(OPERATOR, EXECUTOR) == 1` as the positive control.

Verdict: **INFO**. An unguarded arbitrary-call surface on a **currently broke, roleless** contract exposes nothing.
What closes it is the role census and the balance census — not the absence of a guard. Say that explicitly instead of
dressing "looks bad" up as a severity.

### 4a. CORRECTION — a zero balance is a SNAPSHOT, not a property of the contract

The INFO above was **wrong as a permanent label**, and the error is a repeatable one. Follow-up round on the sibling
deployment (`0x4cece2e5…`) established:

```text
"resolver never executed"    -> FALSE. txlist showed 4 real execute() txs (selector 0x432994b7),
                                all oracle=0xcc60889a… resolver=0x4cece2e5…
"resolver holds no funds"    -> TRUE now, FALSE historically. Its own receipt shows Hub#2 Transfer
                                from=Executor#2 to=Resolver#2 then from=Resolver#2 to=alias.
"the 4 prefix hashes the brief gave are unusable" -> FALSE. They were in the resolver's txlist
                                the whole time; a truncated hash only fails on direct eth_getTransactionByHash.
```

Three lessons, in order of how much they cost:

- **`balanceOf == 0` does not refute a fund-handling surface — it only dates your observation.** Before writing
  "path is dead / broke / nothing to steal", pull the contract's **own receipt history** and look for a Transfer
  whose `from` is the contract under audit. A contract that has *ever* held funds and swept them is a live,
  periodically-funded surface, and the correct label is `INERT AT <block>`, never DEAD-END.
- **A truncated tx hash is resolvable via `txlist`, not via `eth_getTransactionByHash`.** The latter validates the
  string (32-byte length) and rejects `0x2734c34f`; the explorer index returns the full hash for the same prefix.
  Do not conclude "brief gave me unusable hashes" — go to the index and match the prefix.
- **Better still: the `from` field of the sweep itself is your positive control for `balanceOf`.** "Resolver balance
  is 0" is uninterpretable alone; "resolver balance is 0, and here is a receipt where this exact `(account, tokenId)`
  pair moved a non-zero amount" makes the zero a real measurement. This is pitfall 17 applied to *balances* rather
  than to roles — the strongest control is one that proves the instrument saw a non-zero in the same shape.

### 4b. CORRECTION — `totalSupply(0) == 0` is NOT a positive control when ids aren't small integers

A PoC used `totalSupply(0)`, `totalSupply(1)`, `totalSupply(2)` as its "the query instrument is alive" control and
scored **14/14 PASS** while the control proved nothing: every one of those ids simply does not exist on that
ERC-6909-style hub. The ids in this system are **full 32-byte hashes**, not `0,1,2`.

```text
WRONG control : totalSupply(0) > 0            -> 0, and 0 is indistinguishable from "broken query"
RIGHT control : pick the id from a REAL log, then assert a KNOWN-HOLDER balance > 0 for that same id
```

Procedure — derive the id from chain, never from the ABI's `uint256`:

1. Pull one successful receipt for the path under audit.
2. Read the hub's own `Transfer`-shaped log: the id often sits in `topics[3]` (32 bytes), not in `data`.
3. Use that literal (e.g. `0xa7834a7b349a34e2a18eb597251edf52aba8e3aea24d7021dc1c76cc7a857ab7`) for *both* sides:
   `balanceOf(suspect, ID)` and `balanceOf(knownHolder, ID)`.
4. The second value must be **non-zero** — that is the control. If it is also 0, your id is wrong; stop.

Also: `balanceOf(address,uint256)` takes the id **left-padded as a uint256**, so a 32-byte hex string is passed
verbatim, while an address must be `'0'*24 + addr[2:]`. Getting this wrong returns `None`/empty for *both* the
suspect and the control — which is how a broken encoder looks exactly like "no funds present". A `None` from
`eth_call` is INCONCLUSIVE, never zero.

`mapping(uint256 => uint256) public totalSupply` with `uint256 id` still accepts arbitrarily large keys; "the id is
too big to be a real key" is not a valid objection, but "id 0 is empty" absolutely is.

