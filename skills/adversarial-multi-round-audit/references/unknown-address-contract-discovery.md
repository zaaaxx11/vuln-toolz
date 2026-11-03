# Locating an unknown-address contract, and proving the deployed bytecode matches your source

Two failures that cost a session 3 rounds of wrong conclusions:

1. The audited contract had a **sibling** (same source file, second deployment) that was never
   touched because nobody knew its address. It was found only after 52 rounds.
2. The GateWay analysis was built from the **local source file**; the deployed bytecode used a
   **different `execute` signature**, so `0x2ea64c9a` was absent from the live contract.

Both are cheap to prevent. Neither involves guessing.

---

## 1. Reverse-locating an address from behaviour alone

You know a contract *must* exist (source file present, live value flowing) but you do not know
where. Do not scan blocks — a per-block `eth_getBlockByNumber(full=True)` sweep over 3,000 blocks
times out on public RPC and returns nothing. Use **event logs → tx → `to`**.

### The chain

```
step 1  pick an event whose emitter you DO know (a token Transfer to a known vault is ideal)
step 2  eth_getLogs over a bounded window -> log.transactionHash
step 3  eth_getTransactionByHash(hash) -> tx.input[:10]  (selector) and tx.to
step 4  group by (tx.from, selector, tx.to); a selector unique to the missing contract
        appears with a `to` you have never seen -> THAT IS IT
```

Worked example:

```text
eth_getLogs  USDC.Transfer(to = GATEWAY_WALLET)  over 200k blocks  ->  72 logs
group by tx.from + selector:

  52  from 0x0c1a7a5d…  sel 0xe9ae5c53  to 0x1da38a31…   ERC-7579 execute, unrelated
  15  from 0xd20a6c9f…  sel 0x47e7ef24  to 0x7777…11000eE direct gateway deposit
   3  from 0x7d9ddd26…  sel 0xe8017952  to 0x06622432…   <-- depositErc20(4-arg)
   1  from 0x5444a6f1…  sel 0x47e7ef24  to 0x7777…11000eE
   1  from 0x17cffbd5…  sel 0x47e7ef24  to 0x7777…11000eE

0xe8017952 is depositErc20(address,address,uint256,bytes32) — a signature that exists ONLY
in RelayGatewayDepository.sol. `to` = 0x06622432E1CF0A943C1Bde11Fa6464eE695870D7.
```

Why the selector is the discriminator: `tx.to` alone is ambiguous (routers, proxies, EOAs all
appear). A selector that appears in **exactly one source file** maps the transaction to the
implementation identity, not just to some address.

### Bounded scans, not searches

- `eth_getLogs` with a fixed 5,000-block window looped over ~40 iterations costs ~40 requests.
  A block-by-block full-tx sweep over the same span costs 3,000+ and times out.
- Cap the total before starting. If the estimate exceeds ~50 requests, change method.
- Overlapping windows create duplicate logs — always dedup by `(tx_hash, log_index)`. See
  `references/eip7702-delegation-and-smart-account-id.md` "Census hygiene" for the false
  "duplicate id" this produced.

### Confirm the found address before trusting it

`eth_getCode` length alone proves nothing — many addresses have code. Confirm identity by
**intersecting the live selector set with selectors derived from the source you hold**:

```python
# source-side: hash every external function signature in the .sol file
# byte-side:  extract PUSH4 constants, filter 0x00-prefixed
```

```text
RelayGatewayDepository expected          live 0x06622432… (11,868 B)
  0xe8017952 depositErc20(…,uint256,…)   MATCH
  0x5a1ee3ac depositErc20(…,bytes32)     MATCH
  0xbf83f2a2 setAllocator(address)       MATCH
  0x9f04586c setDepositsEnabled(bool)    MATCH
  0x17580158 isTransferSpecHashUsed      MATCH
  0x9fb01cc5 gatewayMint(bytes,bytes)    MATCH
  0x82b42900 Unauthorized()              MATCH
  0x8baa579f InvalidSignature()          MATCH
  0xa5fa8d2b CallFailed(bytes)           MATCH
```

Custom **error** selectors are the strongest fingerprint — they are rarely present in
contracts that merely share a function name. Ten-or-so simultaneous matches is identity.

---

## 2. When a `PUSH4` is a call target, not a dispatcher entry

A selector appearing in the bytecode does **not** mean the function is externally callable.
Distinguish by reading the bytes **around** the constant:

```text
6340c10f1960e01b81526001600160a01b038a81166004830152602482018a9052919250908216906340c10f19906044016020604051808303815f875a…
      ^^^^^^^^                                                                                                                                   ^^^^^^^^
      PUSH4 mint(address,uint256) as an ABI calldata constant                                                used as a CALL target
```

- **Dispatcher entry**: the constant sits inside the selector comparison chain near the
  function-dispatch `EQ`/`JUMPI` block, reached from calldata offset 0.
- **Call constant**: preceded by `…60e01b81…` (PUSH4 + shift/mstore into memory) and followed by
  `…6044016020604051808303815f875a…` (gas + CALL). This is an internal call being built.

Verification that settles it in one probe — call it and see whether it can execute at all:

```text
eth_call MINTER.mint(attacker, 1e6)  from attacker   ->  REVERT (no result)
=> mint is NOT a public entry point on this contract. The "free mint" hypothesis is dead.
```

Do not ship "the mint selector is present ⇒ anyone can mint". Reachability is a probe, not a
string match. (Same family as `CAPABILITY-vs-REACHABILITY` in SKILL.md.)

---

## 3. Local source is a HYPOTHESIS until the deployed selector set matches it

The repository source and the deployed contract can be **different builds of different
generations**. Symptom: one selector you derived from source is simply not in the live bytecode.

```text
source RelayGatewayDepository.sol -> execute(CallRequest,bytes,bytes,bytes) = 0x2ea64c9a
live   0x06622432…                -> 0x2ea64c9a ABSENT from the PUSH4 set

consequence: the struct has a different field set (probably transferSpecHash ordering),
             so the gate ORDER and the hash contents read from source are NOT automatically
             the deployed behaviour.
```

Rules that follow:

- Derive the selector set from **both** sides every time and diff them. Any source-derived
  selector missing from bytecode invalidates every conclusion that relied on that function's
  source body — gate order, hash field list, revert conditions.
- State it as a correction, not a footnote: *"source analysis for function X does not apply to
  this deployment; gate must be re-verified against bytecode."*
- The remaining identification still stands if enough **other** selectors match (functions,
  custom errors, events). You can be confident about *which contract* it is while being
  unsure about *one function's* implementation. Hold both facts simultaneously.

---

## 4. "I could not find it" is a hypothesis, and it expires

In this session the sequence was:

```text
R52 early : "RelayGatewayDepository mungkin TIDAK di-deploy di Polygon sama sekali"
R52 late  : found at 0x06622432…, depositsEnabled = TRUE, live activity in last 200k blocks
```

The first statement came from *searching the wrong way* (explorer API, blockscout search,
per-block sweep) and being blocked — not from evidence of absence. Write the distinction into
the round note: **"not found by method X" ≠ "does not exist"**. Only `eth_getCode == "0x"` at a
*known* address proves absence, and you cannot run that without an address.

Before concluding non-existence, exhaust the behavioural route (§1) — it needs no explorer, no
API key, and no address as input.
