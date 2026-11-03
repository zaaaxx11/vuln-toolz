# Encoding / Digest Layer Fuzzing Across VMs (SDK ↔ contracts)

Class: "find REAL bugs in the encoding & digest layer, prove with execution" — an AGENT-N style
audit where the deliverable is a file of *executed* counter-examples, not prose. Worked case:
Relay Protocol (`packages/sdk` TS + `smart-contracts` Solidity + an off-chain oracle), brief named
four focus points (address derivation collision, tokenId collision, amount/nonce/chainId encoding,
cross-VM `encodeAddress`).

## The rule that makes or breaks the report

**Execute the SDK's own functions, never a hand-written "port".** A port proves your port, not
the target. Recipe:

```bash
mkdir -p /tmp/work-<id> && cd /tmp/work-<id> && npm init -y
npm i --no-audit --no-fund viem bs58 bech32 bitcoinjs-lib @ton/core tronweb ripple-address-codec tsx
# tsx can import the repo's TS directly, resolving through its own node_modules:
npx tsx -e 'const {encodeAddress} = require("/abs/path/repo/packages/sdk/src/utils.ts"); console.log(...)'
```

If the SDK's `node_modules` is absent, symlink/copy the scratch install into the repo root
(`cp -rn /tmp/work-<id>/node_modules/* /abs/repo/node_modules/`) — the SDK's own relative imports
then resolve without touching its package.json.

Two gotchas that silently produce WRONG findings:

- **ERN `bs58` is ESM-only**: `const bs58 = require("bs58").default ?? require("bs58")`.
- **`bech32m` is a named export** of the same package: `const { bech32, bech32m } = require("bech32")`.

## Harness bug that fakes a result (cost 4 iterations here)

A hand-typed hex constant with an **odd digit count** silently loses its last nibble:
`"77bff20c60e522dfaa3350c39b030a5d004e83"` parses to **19** bytes, so a crafted P2PKH script is
24 bytes instead of 25 and `bitcoin.address.fromOutputScript` throws "has no matching Address" —
which looks like a real protocol finding. Always assert the length first:

```js
const h = Buffer.from(HEX, "hex"); if (h.length !== 20) throw new Error("bad fixture " + h.length);
```

Better: derive fixtures from real libraries (`toOutputScript(officialAddr).slice(3,23)`) instead of
typing hashes by hand. Generalise the rule: **every scratch "finding" must be reproduced once with
generated, length-verified fixtures before it goes in the report.**

## Deterministic construction > brute force

Brute-force hashing (240k preimages) almost always yields 0 collisions and proves nothing. The
finding comes from *deriving* the ambiguity arithmetic:

- `abi.encodePacked(string chainId, bytes account)` has **no length prefix for the string**, so the
  boundary between the two fields is ambiguous. Pick the split you want and solve for the inputs:

  ```
  preimage = "1" || 0x30abab…ab(20B)  ==  "10" || 0xabab…ab(19B)
  → identical preimage → identical keccak256 (proved in one script)
  ```

  Then check **reachability**: does any encoder in the target actually emit a 19-byte account?
  (`hyperliquid-vm` accepting 1..20 bytes does; `ethereum-vm`'s hard `!==20` check kills it.)
  A deterministic identity that no code path can construct is a **design bug**, not an exploit —
  say exactly that and keep it out of the "exploitable" bucket.
- Report the brute force as *negative evidence* with the number ("240,000 preimages, 240,000 unique
  digests, 0 collisions"), because reviewers ask for it.

## High-yield checks in this layer (all found real bugs here)

1. **Sentinel address vs a real system address.** Native-currency sentinels are the zero-ish
   address of the VM: EVM 20 zero bytes (no key ⇒ unreachable), Solana
   `11111111111111111111111111111111` = **System Program** (a real, occupied address ⇒ sentinel
   collision). Grep `getVmTypeNativeCurrency` and check whether *any* real account equals it.
2. **Variable-length encodings inside a fixed field.** `hyperliquid-vm` 1..20 bytes, `bitcoin-vm`
   21..34, `lighter-vm` producing **16** bytes from `padStart(32,"0")` on a hex string. Asymmetric
   lengths are the precondition for every boundary-ambiguity bug.
3. **Numeric coercion.** `Number(address)` loses precision above 2^53 — two distinct uint64
   account indices (`9007199254740992` vs `…993`) map to identical bytes. Prove with both calls.
4. **Bech32 validation gaps.** Witness version/length legality is NOT checked by a
   `decode()`-only path: v0 with an 11- or 21-byte program is accepted (BIP141 allows only 20/32),
   witness version 17 is accepted (BIP350 max 16). Also `startsWith("bc1")` is case-sensitive ⇒
   valid UPPERCASE addresses are rejected, while mixed-case (illegal per BIP173) is accepted after
   `toLowerCase()`. Cross-check: is there an `encode`/`decode` round-trip that also fails to
   validate (so the invalid value silently survives)?
5. **`encode`/`decode` asymmetry.** `decodeAddress` may be stricter than `encodeAddress` (BTC legacy
   accepting only version 0x00/0x05) — round-trip then fails for values the encoder accepted.
6. **Width contracts.** Contract field `bytes32 nonce` + ABI `encodeAbiParameters` ⇒ a 1-byte
   `0x01` is REJECTED (strict), while another surface treats nonce as `uint256`. Verify that
   `0x…01` (32B) and `uint256 1` produce the same digest — that turns "looks like a collision" into
   "strictness mismatch", which is the honest verdict.
7. **Parser leniency.** `viem` `hexToBytes` accepts odd-length hex (`0x0` → 1 byte `0x00`), so
   `"0x0"` and `"0x00"` hash identically, while `"0X00"` is treated as **ASCII text** (4 bytes) →
   different digest. Three visually-identical strings, two digests. Also
   `BigInt`-normalised amounts (`"1000"`, `"0x3e8"`, `"+1000"`, `" 1000 "`) collapse to one digest
   (safe), while a **string** `chainId` (`"1"` vs `"01"`) does NOT normalize (representation-sensitive).
8. **Which hashing scheme each surface uses.** `encodeAbiParameters` (tuple) and EIP-712
   `hashStruct` are length-prefixed ⇒ structurally immune to field-boundary ambiguity. Say so
   explicitly when the brief asks "can abi.encode vs encodePacked mismatch here?" — the answer for
   those two functions is NO, and the mismatch lives in the `encodePacked(string,bytes)` derivation
   helpers instead.

## Proving a packed-preimage identity when the SDK is unavailable

When the TS SDK's `node_modules` is missing and you only have Solidity, you do **not** need the full
repo harness — a standalone 3-file Foundry scratch project is enough and is 10x faster:

```bash
mkdir -p /tmp/k/src && cd /tmp/k
printf '[profile.default]\nsrc="src"\nout="out"\nsolc_version="0.8.28"\n' > foundry.toml
# src/K.sol  : contract K { function raw(string calldata a, bytes calldata b) external pure returns (bytes memory) { return abi.encodePacked(a,b); } }
# src/T.sol  : a contract with an event that emits both raw() outputs and both keccak256s
forge test --match-test ... -vvvv | grep -E "emit|Return"
```

Read the real return bytes, not a Python re-implementation. **Printing the preimages is what
catches a wrong split** — this session's first attempt used `raw("1aabb", hex"cc")` expecting a
collision with `raw("1", hex"aabbcc")` and got *different* preimages (`0x31aabbcc` vs
`0x3161616262cc`), because `a` is simultaneously a hex digit and a printable letter, so the two
splits differ in **length**, not just boundary. The successful construction needs the appended
fragment to be a valid hex string of *even* length whose bytes continue the address, e.g.
`("eth", 0x30ab…ab)` ≡ `("eth0", 0xab…ab)`.

Lesson: a packed-collision claim is only real when you print both preimages and they are
**byte-identical**. Reasoning about the split in your head produces off-by-a-nibble artifacts.

### Do not reach for anvil to "just deploy and call it"

Trying to inline a helper contract into another's initcode (adjusting `CODECOPY` offsets, appending
runtime bytes, `anvil --create`) burned four iterations and failed twice on tail-detection. It buys
nothing: `forge test` exposes `internal`/`public` helpers just as well, and `cast` is enough for
pure functions (`cast keccak <hex>`, `cast abi-encode --packed "f(string,bytes)" ...`). Prefer the
scratch-foundry route; treat manual initcode surgery as a last resort.

## `abi.encodePacked(bytes32[])` is uniformly SAFE — say so and move on

Briefs love to ask "is `keccak256(abi.encodePacked(actionHashes))` ambiguous?" for a
`bytes32[]`. The answer is always **no**: `bytes32` is statically sized, so packed encoding is plain
fixed-32-byte concatenation, `N` elements ⇒ exactly `32*N` bytes, and the element count is
recoverable from the preimage length. Two arrays of different length cannot collide. Audit paths that
use it (`_hashExecution`, `_hashFees`, `_hashCallRequest`, gateway variants) as one row with a single
REFUTED verdict citing each line — do not re-derive it four times. **The bug class needs ≥2 dynamic
types**; point the effort at `encodePacked(string, bytes)` derivation helpers instead.

- **Write the findings file incrementally** (skeleton + append per finding). The brief usually
  says so; treat it as a hard requirement, and note at the top that the repo was left pristine.
- **Re-read every cited `file:line` from source before finalising.** Hand-written line numbers drift
  by ±5 and a reviewer who checks one and finds it wrong discounts the whole report. In the Relay
  run, `usedRequests` was cited at `:205/210/212` but actually sits at `:203/206/208`. Grep the exact
  symbol with `-B3 -A3` and copy the printed numbers.
- **Confirm a file EXISTS before writing "cannot verify it".** A `search_files` for a function name
  that returns hits only in a *mirror* file is **not** evidence the real file is missing. The Relay
  run shipped a "`RelayDepository.sol` is not present in this snapshot" claim; the file was at
  `contracts/depository/RelayDepository.sol` all along, and its real content overturned two verdicts
  and forced a full rewrite. One `ls contracts/<dir>/` prevents this. Before any "file absent" claim,
  list the directory.
- **When you must retract a finding, retract it explicitly in the file** — a labelled
  `## Retracted findings` section with the reason (often: "the rejecting branch reverts, so the
  state write is rolled back"). A visible retraction is far more credible than a quiet deletion, and
  it stops the next auditor re-filing the same non-issue. If the report was already written with the
  bad finding, correct it and add a correction notice at the top.
- If you add temporary tracing to a repo file, `git checkout --` it afterwards and **say so in the
  report** — plus verify with `git status --short | wc -l` → 0.
- Keep three buckets separate and labelled: (a) **provable/reachable** (fund or authk impact),
  (b) **latent design bug** (math is real, no reachable constructor — write "cannot be triggered in
  this repo today" and name the precondition), (c) **REFUTED / by-design** (checksum casing, tokenId
  low-20 == derived address, TON `EQ`/`UQ` same hash, XRP tagged X-address correctly rejected).
  False positives in bucket (c) kill a report's credibility faster than a missing finding.
- If the live oracle/API is edge-gated (`/lives/v1` 200 but everything else `401
  {"error":"Unauthorized"}`), state BLOCKED with the exact status codes and make clear every number
  in the report comes from local execution of the real SDK — never imply an oracle response.

## Pure-Python port IS the right method when the target is Solidity-only (inverted rule)

The "never port" rule above applies when the *source of truth is TS/Python you can import*. When the
target is a Solidity `library` with `internal`/`private` functions (no deployed address, no ABI), it
is NOT callable — you cannot `cast call` it, and it may be inlined into a viewer contract you can't
locate. Then a **line-by-line Python port is the correct ground truth**, on two conditions:

1. **Port every branch of the dispatcher, not just the decoder.** `encode()` is usually a
   fallthrough chain (`hex? → bech32-prefixed? → base58 → length gate`). Port the fallthrough too,
   including "returns `ok=false` and silently tries base58 next" — that's where real bugs hide.
2. **Validate the port against the repo's own test vectors before trusting any fuzz output.**
   Grep the test file for `internal constant …_BYTES = hex"…"` pairs and assert your port reproduces
   them. 5/5 matching = port is trustworthy; `MISMATCH` = your port is wrong, not the contract.

```
OK  bc1qar0srrr7xfkvy5l6 00e8df01…2c42
OK  TR7NHqjeKQxGTCi8q8ZY 41a614f8…13c
```
Skip this and you write findings about a bug that only exists in your own code.

**Solidity-specific port hazards** (each cost an iteration, all silently produce false negatives):
- Comparisons are byte-vs-int: `_bech32Word` does `b += 32` on a `uint8` then compares against a
  charset — in Python that becomes `int(byte)`, and `int in set_of_str` is always `False`, so every
  bech32 address "fails checksum". Fix: `chr(b) in CHARSET`.
- Do **not** add `& 0xFFFFFFFF` where the Solidity is `uint256`. `chk = ((chk & 0x1ffffff) << 5) ^ v`
  with only the low 25 bits masked out is *equivalent* to the BIP-173 `uint32` version — the mask
  makes the width irrelevant. Verify by computing both and asserting equality (`contract 0x1`,
  `spec 0x1`) instead of "reasoning" about uint widths.
- `(1 << bits) - 1` with `bits == 0` evaluates to `0`, so `acc & 0 != 0` is `False` → the check
  **passes vacuously**. Look like a bug, is a no-op given the upstream `% 8 >= 5` guard. Check
  whether the guard already excludes the dangerous case before filing it.

## Fuzzer bugs that fake a checksum bypass (cost 2 iterations here)

A "1000 checksum bypasses" result was **entirely my fuzzer**: `random.choice(ALPHABET)` for the
replacement char can pick the *same* char that was there, so the mutation is a no-op and the
"tampered" string is byte-identical. Always assert the mutation actually changed the input:

```python
alt = random.choice([c for c in B58 if c != s[p]])   # guaranteed different
t   = s[:p] + alt + s[p+1:]
assert t != s
```

And classify the *reject reason*, don't just count accepted/rejected — the 15 remaining "not caught"
cases were `Unsupported` (mutating the leading digit changes the decoded **length**, so it never
reaches the checksum comparison). A residual bucket you can't explain is a fuzzer bug until proven
otherwise.

## Domain separation: the finding that survives a correct-checksum decoder

The highest-value result in this layer is usually NOT a broken checksum (they're almost always
correct) — it's **two families whose byte forms are identical because nothing tags the family**.
Worked case: `witness[0] = bytes1(version)` stores the *numeric* witness version, and `_decodeHex`
also emits numeric bytes, so `bc1qar0…` (BTC segwit v0) and `0x00e8df01…` (hex) are the **same
bytes → same alias → same token slot**:

```
bytes same: True | alias: 275fa81e033af4a5 / 275fa81e033af4a5 | SAME ALIAS: True
tron TR7NH… vs hex 0x41a614… → SAME ALIAS: True
```

Checks to run: for each supported family, take a real address, hex-encode the decoded bytes, and
re-feed the hex. If it round-trips, the family is **impersonable as a pre-encoded hex string**
(docstring "hex of any length = pre-encoded bytes for any other family" is the usual enabler).
Then check whether the discriminator you *do* see is reversible: legacy BTC gets `0xff || payload`,
but `"0xff0062e9…"` as hex decodes straight back to the same bytes, so the discriminator only
separates families *within* the base58 path.
Also probe the inverse asymmetry — P2TR is 33 bytes and `byteLength > 32` rejects it in `_decodeHex`,
so that family is *not* hex-impersonable. Asymmetries cut both ways; report which direction.

## Downstream gate analysis: auth ≡ length is the refutation, not the blocker

When the brief says "there's a `len==20` gate that blocks it", **verify where the gate sits relative
to the hash**. Worked case (`RelayAllocator`):

```solidity
address spenderAlias = Utils.generateAddress(params.spenderChainId, params.spender); // NO gate
bool callerIsSpender = params.spender.length == 20 && address(bytes20(params.spender)) == msg.sender;
```

`params.spender` is free calldata `bytes`, so the collision is **reachable** (proven:
`chain="ethereum" len=20` ≡ `chain="ethereu" len=21` with `0x6d…`, same alias). But every auth
branch — `callerIsSpender`, ECDSA `recover == bytes20(spender)`, `setOperator` (needs `msg.sender ==
alias` ⇒ private key), oracle multisig — **also requires `length == 20`**. The collision lives in the
`len != 20` dimension, auth lives in the `len == 20` dimension: **structurally mutually exclusive**.
That is a much stronger refutation than "a gate blocks it", and it survives the obvious rebuttal
("then just use a 20-byte spender"). Say it that way.

Two more gates to check before writing PROVEN:
- Can the attacker even **fund** the collided alias? Needs a registered payload builder / chain id —
  `payloadBuilders["ethereu"]` is zero ⇒ `revert NoPayloadBuilder`, so not even credit is possible.
- Is the alias a contract or a bare balance slot? If `balanceOf[alias]` on an ERC-1155 with
  `transfer()` using `msg.sender`, a collision gives you *no key* — two parties just share a slot
  neither can withdraw. Collision ≠ control; state this explicitly.

## "Dead code" is a real finding — measure it before and on-chain

Grep the import graph, then confirm on the live chain:
```bash
grep -rn "import.*HubAddressCodec" contracts/     # → 1 file: the read-only viewer
grep -rn "\.encode()" contracts/ | grep -v <lib>  # → only viewer call sites
# and: the Hub itself does not expose the derivation
eth_call HUB.aliasOf("arbitrum","0x2170…")  → {"error":{"code":3,"message":"execution reverted"}}
```
If the codec only lives in an inlined viewer that isn't in `deployments/` or the multisig
`transactions/prod/`, then it is **read-only display code, not a funds path** — that sentence should
lead the severity discussion. Dropping a severity from CRITICAL to LOW because the surface is
unreachable is a correct, valuable outcome, not a failed hunt.

## Correct the brief's on-chain claims with your own evidence

The brief asserted a colliding tokenId was "NYATA di produksi". `eth_call` on the real Hub:
`totalSupply=0`, `name=""`, `symbol=""`, `erc20Views=0` → **not registered, zero assets**. Do this
check every time a brief hands you an address/tokenId as "already live"; a mathematically valid
collision over an empty slot has zero financial impact today, and saying so is the correction the
report needs. Report it as an explicit self-correction block, not a buried caveat.

## Cross-references

- `references/handoff-chain-mapping-multirepo-protocol.md` — the multi-repo handoff map (this class
  is usually one role in that larger chain).
- `references/foundry-redteam-multi-claim-rounds.md` — the getter-first technique and the
  SAFE-vs-finding-vs-latent output discipline, which this class shares.
