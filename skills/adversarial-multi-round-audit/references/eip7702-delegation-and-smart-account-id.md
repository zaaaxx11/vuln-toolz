# Reading a 23-byte `0xef0100…` — EIP-7702, not a clone, not an EOA

A "contract" identity check that returns a **23-byte** codesize is not a truncated
EIP-1167 clone and not a plain EOA. It is an **EIP-7702 delegation designator**:

```
0xef0100 ‖ <20-byte delegate address>      = 23 bytes total
```

Decode it before doing anything else:

```python
b = bytes.fromhex(code[2:])
assert b[:3] == b'\xef\x01\x00', 'not an EIP-7702 designator'
delegate = '0x' + b[3:23].hex()
```

## Why this matters for grading

Getting this right changes the entire verdict. The same observation —
"this address received 19.4M in deposits attributed to it and holds 30k USDC" — reads
as a **vulnerability** if you think it is an arbitrary contract, and as **ordinary
infrastructure** once you know it is a delegated smart account that supplies its own
signature.

An address that (a) appears as `depositor`/beneficiary in thousands of events,
(b) holds real value, and (c) has a code prefix you didn't recognise, is far more
likely a **payment processor / settlement account** than a victim. Confirm with:

| Check | Expected for a legitimate processor |
|---|---|
| `tx.from` of the events | **equals** the beneficiary itself (self-deposit loop) |
| amounts | tightly clustered, repetitive (same order size, repeated) |
| token | one dominant token, not a spread of junk |
| `ModuleInstalled` logs | present or absent consistently; absent ≠ vulnerability |
| `eth_call` on multiple unknown selectors | returns **different** revert data per selector |

`tx.from == beneficiary` for the great majority of the sample is the decisive signal:
nobody is being *forced* to attribute deposits to that address. If instead every
`tx.from` is distinct, that is the aggregator/relayer pattern — also legitimate, just
a different one. Neither is a finding.

## Profiling the delegate implementation

Unknown selector sets are the fastest fingerprint. Pull `PUSH4` constants out of the
bytecode and match against a candidate list:

```python
sels = set()
for i in range(len(b) - 4):
    if b[i] == 0x63:                       # PUSH4
        v = b[i+1:i+5]
        if v != b'\x00\x00\x00\x00' and v[0] != 0:
            sels.add('0x' + v.hex())
```

Then hash candidate signatures and intersect. Signatures confirmed on live targets:

```
0xe9ae5c53  execute(bytes32,bytes)                 ERC-7579
0xd691c964  executeFromExecutor(bytes32,bytes)     ERC-7579
0xd03c7914  supportsExecutionMode(bytes32)         ERC-7579
0x84b0196e  eip712Domain()                         EIP-5267
0xb0d691fe  entryPoint()                           ERC-4337
0xb760faf9  addDeposit()                           EntryPoint deposit
0x205c2878  withdrawTo(address,uint256)            EntryPoint deposit
0xc399ec88  getDeposit()
0x35567e1a  getNonce(address,uint192)
0xd087d288  getNonce()
0x1626ba7e  isValidSignature(bytes32,bytes)        ERC-1271
0x0b135d3f  isValidSignature(bytes,bytes)          ERC-1271 (legacy)
```

`executeFromExecutor` in the selector set only tells you the *code path exists*. It
does **not** mean a module is installed. Two cheap checks before you write a word
about it:

- `supportsExecutionMode(bytes32)` — `0x00` (call) and `0x01000000` (delegatecall)
  both returning `1` is normal for a full 7579 account.
- `eth_getLogs` for `ModuleInstalled(uint256,address)` /
  `ModuleUninstalled(uint256,address)` over a wide block range on
  `address = <account>`. Zero results means no module was installed in that window —
  which means no executor to impersonate. Note the window you scanned; zero in
  200k blocks is weak, zero in 700k is worth stating.

## The pattern this protects against

Auditing an aggregator-shaped address and finding `executeFromExecutor` in the
delegate is the setup for a false HIGH ("anyone can execute via a module"). The
installed-module census plus a `tx.from == beneficiary` check converts it to a clean
INFO/architecture note in one step. Do those two probes before theorising.

## Census hygiene (bit again during this session)

Scanning logs in overlapping block windows produces a **duplicate event** that looks
exactly like an on-chain ID reuse. Before claiming "duplicate `id`", dedup by
`(tx_hash, log_index)` — or at minimum `(tx_hash, id)` — and confirm the count drops to
zero. In this session the "duplicate" was the same tx, same block, same id collected
twice by two overlapping `eth_getLogs` ranges. Retract it explicitly when it happens;
`id` uniqueness was 19,169/19,169 after dedup.
