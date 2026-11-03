# Cryptographic Binding Verification of a Signed Request Digest

How to *prove* (not assume) that a signature over a request struct binds every field
the builder/executor will later consume. This is the decisive test that closes or
opens the entire class of "attacker substitutes `receiver` / `amount` / `data`
without holding a key" — which is the core of any Deposit→Drain auth-spoof chain.

A read-only digest-reconstruction harness answers it in one run, at zero risk, with
no fork and no key. Run it **before** any fork/PoC effort.

---

## The claim under test

```
WithdrawRequest { chainId, depository, currency, amount, spenderChainId,
                  spender, receiver, data, nonce }
digest = EIP712(domain(name,version,chainId,verifyingContract), structhash(all 9))
```

If any single byte of `receiver` or `data` can change **without changing `digest`**,
an off-chain assembler that signs/binds by digest can be steered to a different
destination while the user's signature still validates. That is the exploit shape.

### Sensitivity (byte-level mutation) — the primary test

```python
def digest_of(P, alloc):
    body = (PT
        + keccak(P['chainId'].encode())          # string  -> keccak(utf8)
        + keccak(P['depository'])                # bytes   -> keccak(raw)
        + keccak(P['currency'])
        + P['amount'].to_bytes(32, 'big')        # uint256 -> raw word
        + keccak(P['spenderChainId'].encode())
        + keccak(P['spender'])
        + keccak(P['receiver'])
        + keccak(P['data'])
        + P['nonce'].to_bytes(32, 'big'))
    sh  = keccak(body)
    dom = keccak(DTS + keccak(b'RelayAllocator') + keccak(b'1')
                 + (537713).to_bytes(32, 'big') + bytes.fromhex(alloc[2:]))
    return keccak(b'\x19\x01' + dom + sh)

# mutate EVERY byte of `data`, not just one
bad = 0
for i in range(len(P['data'])):
    P2 = dict(P); d = bytearray(P['data']); d[i] ^= 0x01; P2['data'] = bytes(d)
    if digest_of(P2, alloc) == baseline: bad += 1
```

Real result on a 5,664-byte Bitcoin payload: `byte tested = 5664, unbound = 0`.
Print the count of *unbound* positions, not just a boolean — `0/5664` is the evidence,
`False` is an opinion.

Also mutate `receiver` (XOR 1 bit), `amount` (+1), `nonce` (+1). All three must move
the digest. One line each, and it converts "the source shows `keccak(receiver)`" into
a measured property.

### Cross-instance domain separation

```python
digest_of(P, ALLOC_A1) != digest_of(P, ALLOC_A2)   # must differ
```

Equal digests across two allocator instances means a signature for one authorises the
other — a real cross-instance replay path. Probe it explicitly; don't assume the
`verifyingContract` term does its job.

### Nonce-replay census (catches the false positive and the real one)

```python
Counter((P['spender'].hex(), P['nonce']) for _, _, _, P in records)   # dupes?
Counter(digest_of(P, alloc).hex() for ... )                          # collisions?
```

A duplicate `(spender, nonce)` pair is **not** automatically a finding. Resolve both
txs' receipts:

```
blk 2,178,945  status=0x1  PayloadBuilt emitted   <- first use wins
blk 2,178,948  status=0x0  REVERT, 0 logs         <- replay correctly rejected
```

Identical-calldata duplicate where the second **reverts** is *proof the nonce ledger
works*, i.e. a clean REFUTED. Reporting it as "nonce reuse" is the classic
gate-passed-vs-not error. Never write a finding from the census alone — always pull
the receipts.

---

## Two-signature stacks: `hashesToSign` ≠ request digest

A builder layer commonly emits its own `hashesToSign` array. **That array is not the
user's request digest** — it is the payload hash that the allocator/oracle signs.

Measured:

```
EIP712 request digest        = 0x64d01f56e844bf8605d3fe92cdd94cadac8b52b8c58bdd9626…
PayloadBuilt hash[0]         = 0x2a598476fe57a99bb33031c148158347e695ffebdf7fc62b07…
SAME? NO
```

Consequences to state in the verdict:
- The user's signature binds `receiver`/`amount`/`data` (proven by mutation test).
- The builder's hash binds the *execution payload*, which is derived from those same
  params — so it is safe **only if** the derivation is injective.
- Therefore an injectivity check on the builder's serialisation is mandatory
  (fixed-width zero-padded hex, length-prefixed fields, or type tags). A
  concatenation of variable-length fields with no separator is a collision surface
  even when both digests are individually correct.

If `hashesToSign` cannot be reproduced off-chain (raw, non-EIP712 `personal_sign`
payload, or a domain you can't replicate), say so plainly and mark that sub-claim
`UNPROVEN — off-chain, not claimable`. Do not promote it.

---

## Harness hygiene (cheap, and each one has already caused a bad run)

1. **Anchor on a calldata value.** The request carries `amount`; the decoded payload
   must contain the same number (`0x124f80` for 1,200,000). If it doesn't, your
   decode is wrong — stop before interpreting.
2. **Enumerate from `txlist` filtered by selector** (`0x771dc6a2`), not from logs.
   `eth_getLogs` over big ranges silently returns `[]`.
3. **Print raw words (`w[i] = …`) before any interpretation.** Summaries hide offset
   bugs; raw word arrays expose them.
4. **Write every RPC response to a file** and read with `tail -40`. Tool output for
   long scripts frequently collapses to "exit 0, 1 lines".
5. **A non-reverting `eth_call` does not prove a state change.** For "did this
   succeed and what did it emit", use `eth_getTransactionReceipt` + decode `logs`.
6. **`eth_call`-only differentials on an empty target are meaningless.** An address
   with no code returns `0x` successfully for *every* selector — that "passes" and
   looks like a live control. Always include a positive control on an address that
   provably has code and reverts differently.

---

## Verdict template

```
BINDING TEST (all executed)
  receiver XOR 1 bit   -> digest CHANGED ✅
  amount   +1          -> digest CHANGED ✅
  nonce    +1          -> digest CHANGED ✅
  data  byte-by-byte   -> N bytes tested, 0 unbound ✅
  cross-allocator      -> digest DIFFERS ✅ (no cross-instance replay)
  (spender,nonce) dup  -> 1 pair; 2nd tx REVERTED ✅ (nonce ledger live)
  records parsed       -> 2,420 withdrawals, 1 digest collision (identical params, reverted)

VERDICT: parameter-substitution path CLOSED.
```

---

## Calibrating the digest against real calldata (the 12-variant dead end)

When the calldata is already on-chain, you can go further than theory: recover the
signer from each historical signature and require it to equal the known `allocator`.
**If every recovery returns a distinct random address, count = 1 for each — that is
your calibration signal, not a discovery.** 182 recovered "signers" all appearing
exactly once means the digest is wrong. A correct digest collapses all of them onto
one address.

### STOP BRUTE-FORCING. Compile the contract and ask it for the digest.

The 12-variant matrix is the *fallback*, not the method. Once you have the verified
source (or a plausible one whose typehashes match the bytecode), do this instead —
it converges in one run and every earlier "encoding theory" becomes irrelevant:

1. **Clone the real deps and build the harness in-repo.** `git submodule update` often
   fails on a partial checkout (`pathspec did not match`); just
   `mkdir -p lib && git clone --depth 1 <repo> lib/<name>` into the repo's own
   `lib/` (respect its `remappings.txt`) and run `forge test` **there**.
2. **Subclass the target to expose the internal hasher.** A one-line
   `contract H is RelayDepository { function h(CallRequest calldata r) external view
   returns (bytes32 s, bytes32 d) { return _hashCallRequest(r); } }` gives you the
   contract's *own* `structHash` + `digest`. Sign with `vm.sign` against that digest
   and `execute()` will accept it. Any hand-reimplemented hash that disagrees is
   simply wrong.
3. **Put the real calldata in `test/` and read it with `vm.parseBytes(vm.readFile(...))`.**
   Foundry refuses `vm.readFile` outside allowed paths — the usable fix is a
   `fs_permissions = [{ access = "read", path = "./" }]` entry under
   `[profile.default]` in `foundry.toml` (there is **no** `--fs-permissions` CLI flag;
   put the file under `test/`). Without this you get
   `the path … is not allowed to be accessed for read operations`.
4. **Fork to a pinned block and decode with `abi.decode`.** Let the compiler lay out
   the struct. This alone killed a 6-round offset bug: the real layout was
   `CallRequest{ Call[] calls; uint256 nonce; uint256 expiration; }` — 3 fields, not
   the 4 the hand-decode assumed.

### The two wrong-shape traps that survive a "correct-looking" decode

- **`nonce` is frequently a random 256-bit value, not `1` and not a counter.** A
  hand-decode that reports the same `nonce` for every historical tx (e.g. "nonce = 1
  in 182/182") is an *offset artefact*, not a design flaw. Always cross-check: a real
  non-repeating nonce should produce 182 **distinct** `structHash` values — and so
  should a random nonce. If your decode says `nonce` is constant *and* the structHashes
  are unique, the decode is wrong, not the contract.
- **Solady `_hashTypedData` does not read `eip712Domain()` output.** The domain
  separator comes from `_domainNameAndVersion()`; `eip712Domain()` merely *reports*
  it. Reading `eip712Domain()` gives you name/version/chainId/verifyingContract
  correctly — keep that — but never conclude the domain is wrong because your manual
  `keccak("EIP712Domain(string name,string version,uint256 chainId,address
  verifyingContract)", …)` disagrees with a *harness deployed on a different chain*.
  Compute the domain for the chain you are asserting about, and state the chainId.

### Close the loop: replay and reentrancy, both cheap once the digest works

With a valid digest you can settle two questions in the same harness run:

- **Replay:** for each historical request, evaluate
  `callRequests(structHash)` on a fork and bucket
  `{sig valid} × {already used} × {not expired}`. "6/6 valid, 6/6 used, 3/6 unexpired"
  is a clean REFUTED — dedup is per-structHash and set *before* the call.
- **Reentrancy:** deploy the contract locally with a test allocator, sign **two**
  requests, have the beneficiary's `receive()` re-enter `execute()` with the second.
  If nested execution lands (`depth = 2`, beneficiary paid twice from one tx) then
  there is no global `nonReentrant`. Say exactly what that means: **it requires two
  allocator signatures**, so it is a defense-in-depth gap for a batching allocator —
  **not** a no-key drain. Grade MEDIUM and label the prerequisite in the same sentence.


### Diagnose in this order (each step cheap, each eliminates a class)

1. **Print the raw word array before any struct theory.** One dump of `w[0..n]` kills
   most offset errors. Do not skip to "struct layout is probably…".
2. **Read `eip712Domain()` on-chain** (`0x84b0196e`). Never assume the Solady default
   `name`/`version` — a contract can ship `name "RelayDepository"`, `version "1"`, and
   a wrong assumption here invalidates every downstream recovery. `fields = 0x0f`
   means name+version+chainId+verifyingContract present, with name/version at the
   `0xe0`/`0x120` word offsets.
3. **Beware truncated RPC result printing.** A domain buffer read through a shell
   pipeline can drop trailing words; `fields` then parses as a 2^250-sized integer and
   every offset looks insane. Save the response to a file, then parse the file length
   (`len(hex)/2` should be a multiple of 32).
4. **Confirm typehashes exist in the deployed bytecode.** Compute
   `keccak(signature-string)` for each candidate and require the hex to appear in
   `eth_getCode`. Present ⇒ source == bytecode for that struct. Absent ⇒ the verified
   source is not the deployed one, or the struct has extra fields.
5. **Check `r < n`, `s < n`, `v ∈ {27,28}`** on a sample signature. If those hold, the
   signature is structurally valid and the problem is 100% digest-side. Include
   `s <= secp256k1n/2` — a high-`s` sample hints at non-standard normalisation.
6. **Mutate the encoding, not the theory.** A 12-cell matrix covers nearly everything:
   `{keccak(packed hs), keccak(abi.encode(hs))} × {1901 prefix, no prefix} ×
   {nonce,expiration order}`. Any cell is accepted only if its top recovered address
   repeats across ≥2 txs **and** equals the allocator.

### When it still fails — the honest verdict

After a full matrix miss, write:

```
DIGEST RECONSTRUCTION: FAILED (12 variants: packed/encode × 1901/none × n_e/e_n).
  Every recovery → distinct address, count=1. No signature verified against allocator.
  ⇒ `execute()` can be called NEITHER "closed" NOR "open" on cryptographic grounds.
  What IS proven: allocator key is a prerequisite; `Call.target` is not whitelisted;
                  nonce is a free parameter (dedup is structHash-only) and all N
                  observed structHashes were unique; signature sits in public calldata.
```

Do **not** promote a signature-replay claim from "signatures are public + dedup by
structHash" alone. Replay needs a *specific unexecuted (calls, nonce, expiration)
triple with a live expiration*; enumerate for it (histogram structHashes, compare
`expiration` vs now) and report the counts. "107/182 still live but 182/182 unique"
is a clean negative, and it is reportable.

### Sender/receiver identity is a finding-shaped observation, not a finding

A suspiciously regular pattern (e.g. `sender == transfer recipient` in 182/182 txs)
usually describes **intended** self-service fee withdrawal. Report it as
architecture ("this is the fee cash-box; the executor is the beneficiary"), and put
the risk where it belongs: **no target whitelist ⇒ one key leak drains every token
the contract holds.** Grade that key-custody, not "vulnerability".

### Never silently keep a stale address profile

An address characterised in an earlier round as "nonce 0, dormant solver" may in fact
have millions of txs and a five-figure balance. Re-measure `code / nonce / native
balance / token balance` at the start of every round that reuses a profile, and if the
numbers moved, retract the old claim explicitly in the round's corrections list.

