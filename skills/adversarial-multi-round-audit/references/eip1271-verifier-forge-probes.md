# EIP-1271 multisig verifier: forge probes, storage decoding, and the slot bug that fakes a Critical

Condensed from a round that audited a live 2-of-3 EOA `RelayOracleMultisig` (`0xcc60889a…`) whose brief asked
*"find a keyless attacker path"*. Answer: **none** — but the round nearly shipped a fake Critical, and the near-miss
is the most reusable thing in it.

Companion to `onchain-protocol-audit → references/signature-gate-and-verifier-audit.md` §3 (which gives the source
audit ORDER). This file gives the **live probe matrix** and the **storage-decoding** side.

---

## 1. The forge matrix: you must actually run all of these

Reading the source and saying "there is a `length/65 < threshold` check" is not a test. Run the live matrix; every
row is a hypothesis someone will raise in triage.

```python
SEL  = "1626ba7e"                        # isValidSignature(bytes32,bytes)
DIGEST = "11"*32

def enc(sig_hex):                        # head = digest + offset(0x40), tail = len + right-padded data
    d = bytes.fromhex(sig_hex); L = len(d)
    return "0x"+SEL+DIGEST+"%064x"%0x40+"%064x"%L+d.hex().ljust(((L+31)//32)*64,'0')
```

| input | expected if sound | what it catches |
|---|---|---|
| `""` (0 bytes) | `0x00000000` | threshold bypass on empty |
| `"00"` (1 byte) | `0x00000000` | length not multiple of 65 |
| 64 bytes | `0x00000000` | one-short truncation |
| 65 B `r=1,s=1,v=27` | `0x00000000` | junk that still decodes |
| 129 bytes | `0x00000000` | `len/65` integer-division shortcut |
| 130 B all-zero | `0x00000000` | `v=0` accepted without 27/28 normalisation |
| 130 B all-`ff` | `0x00000000` | `r,s` out of curve range |
| 2 identical valid sigs | `0x00000000` | duplicate-signer acceptance |
| 2 valid sigs **reverse** order | `0x00000000` | missing monotonic `signer > lastSigner` |
| 1 valid + 65 B junk | `0x00000000` | junk counted toward threshold |
| high-s malleated (`s'=n-s`, `v'=55-v`) | `0x00000000` | missing `s > n/2` check |

Return shape: `bytes4` comes back as **one ABI-padded word**, `0x1626ba7e` + 56 zeros. A bare `0x` would mean the
fallback ran (function absent). Never confuse the two.

### Non-obvious reading: extra signatures are NOT a bug
`for (i = 0; i < threshold; i++)` means a 195-byte blob (3 sigs) on a 2-of-N **returns MAGIC** — the third sig is
ignored. That is correct and expected; only the first `threshold` sigs are examined. Do not file it. The thing worth
filing is the inverse: 2 valid sigs + junk when `threshold=3` — that must fail, and does.

---

## 2. The positive control that makes the matrix mean anything

Eight `0x0000…` results in a row are worthless until you have shown the same harness can emit `0x1626ba7e`.
`eth_call` state overrides (`stateDiff`) are **silently ignored** by some RPCs — they return the un-overridden result
rather than erroring, which looks exactly like "the sig is invalid". Do the control on a fork instead:

```bash
anvil --fork-url <RPC> --port 8546          # real code + real storage
```

```python
k    = Account.create()
sig  = Account.unsafe_sign_hash(db, k.key).signature.hex()   # RAW digest, NOT encode_defunct
slot = keccak(bytes(12) + bytes.fromhex(addr[2:]) + (4).to_bytes(32,'big'))
rpc("anvil_setStorageAt", [ORACLE, "0x"+slot.hex(), "0x"+"00"*31+"01"])
```

`anvil_setStorageAt` **is** honoured, unlike `stateDiff`. Then: 2 sorted real sigs ⇒ `0x1626ba7e` (control passes);
1 sig, dup sig, reversed order, empty ⇒ `0x0000…`. Now the negative results are a measurement.

**`encode_defunct` is the trap that eats an hour.** `isValidSignature` recovers from the raw `bytes32` it is handed;
`encode_defunct(primitive=…)` prepends the EIP-191 `\x19Ethereum Signed Message:` frame, so every "valid" signature
you build recovers to a *different* address and everything returns `0x0000…`. Use `Account.unsafe_sign_hash`.
Symptom to recognise: even with correct signers registered and sorted, the control fails → suspect the signing
frame, not the contract.

---

## 3. Storage decoding: the left-pad bug that manufactures a fake Critical

This is the pitfall to carry forward. Reading `isSigner[addr]` at the wrong slot returns **0 for every address**,
which reads as *"the signer mapping is empty ⇒ nothing can ever validate ⇒ or by inversion, whatever I send gets
through"* — a Critical built entirely from an off-by-padding bug.

```python
# WRONG — 20 raw bytes. Never matches.
keccak(addr_bytes        + slot.to_bytes(32,'big'))
# RIGHT — the key is a 32-byte ABI word (address LEFT-PADDED in the HIGH bytes)
keccak(b"\x00"*12+addr_bytes + slot.to_bytes(32,'big'))
```

`cast index address <addr> <slot>` is the ground truth for this; `cast index uint256 … 4` is a *different* hash.
Decoding slot order from runtime bytecode — the `MSTORE` pair before `SHA3` tells you both the slot and the key
frame:

```text
6004 6020 52    PUSH1 04 / PUSH1 20 / MSTORE   -> mem[0x20] = slot 4
5f 90 81 52     PUSH0 / SWAP1 / DUP2 / MSTORE  -> mem[0x00] = key (left-padded word)
6040 90 20 54   PUSH1 40 / SWAP1 / SHA3 / SLOAD -> keccak(mem[0..0x40]) = keccak(key||slot)
60 ff 16        AND 0xff                        -> bool
```

The tell that you have it wrong: `isSigner(x)` returns `true` while `eth_getStorageAt` at your computed slot is `0`
for every x. **When a getter and raw storage disagree, the getter is right and your slot math is wrong** — do not
conclude the RPC is lying, and do not conclude the mapping is uninitialised. Confirm with `cast index`, then move on.

Corollary: don't infer storage layout from declaration order either. `Ownable2Step` occupies slots *before* your
contract's own state (`slot 2 = owner`, `slot 5 = signers.length`, `slot 6 = threshold` here). Read the live slots
(`threshold()` is easy to verify) and work outward from a value you can confirm, rather than from source order.

---

## 4. "Owner holds a role" — check the RIGHT hub, and check `getRoleAdmin`

The highest-value finding in this class is not in the verifier; it's in who can rewrite the verifier's owner.

```text
oracle.owner()                                   -> 0x71d8be89…   (EOA, codesize 0)
hub.hasRole(ADMIN_ROLE,  0x71d8be89…)            -> true          <-- sole holder
hub.getRoleAdmin(OPERATOR_ROLE)                  -> ADMIN_ROLE
=> owner key compromise ⇒ grantRole(OPERATOR_ROLE, attacker)
```

Two traps that each cost real time:

- **The brief's hub address can be the wrong hub.** Two `RelayHub`s existed (`0xDDD3…9318` and `0x3C0b…7F30`);
  the first returned `false` for everything and looked reassuring. Identify a hub by **selector-set equality against
  the artifact** (34/34 here), then confirm via the consumer's own `HUB()` getter. A "no roles found" result is
  only meaningful once you've proven you hit the contract the executor actually reads.
- **`getRoleAdmin` is where amplification lives.** Holding ADMIN on a contract whose ADMIN is *its own* admin means
  `grantRole` to anyone, unilaterally — no second approver. That is the SPOF sentence for the report:
  *one EOA key ⇒ full control of the settlement flow*, and it is **HIGH-ROLE-ONLY / key-compromise**, never keyless.

Report it with the honest boundary: the chain is real (`ADMIN` → `grantRole(ORACLE_ROLE, attackerContract)` →
`execute()` passes every gate), and it still requires the private key, so it does **not** answer "keyless path
exists". Say both halves in one paragraph or a triager will read the role finding as a severity inflation.

---

## 5. Verdict template for this class

```text
H1 same source as instance #1?   YES — 15/15 selectors, 22-byte runtime diff confined to EIP-712 strings
H2 magics value under threshold? NO  — 8-input matrix all 0x0000, control PASSES on fork
H3 loop bound = threshold?       SAFE — i<threshold at 0x7ef, count<threshold at 0x7d9 (bytecode + live)
H4 nonce / replay?               no nonce by design; consumer has usedRequests[digest] (file:line)
H5 owner in roles elsewhere?     ADMIN_ROLE sole holder on real hub → SPOF, key-gated
H6 signer overlap?               zero overlap, 8 unique addresses → isolation (positive finding)
=> no keyless attacker path. Residual: single-EOA admin with unilateral grant powers.
```

That shape — five refutations plus one honestly-bounded strengthening — is the deliverable. The count of what was
ruled out is the trust signal; there is no Critical and saying so plainly is the correct outcome.
