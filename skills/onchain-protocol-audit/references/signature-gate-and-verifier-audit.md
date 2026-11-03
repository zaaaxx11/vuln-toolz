# Signature-gate audits: prove the verifier is sound, or find the keyless forge

Condensed from a Relay Protocol session whose brief was *"prove a keyless attacker can forge the MSIG signature
so all four signature-gated paths collapse"*. The answer was **no** — and the value of the run is the reusable
procedure that produced that answer with raw hex, plus three falsified hypotheses corrected in writing.

Read this when:
- the remaining un-audited surface is a **signature / EIP-1271 / multisig / oracle signer**,
- you inherit "N subagents said this path is BLOCKED because it needs a signature",
- you are tempted to call an `eth_call` result a bypass.

---

## 1. First: who is the signature verifier, LIVE?

Repo source is not the trust anchor. Resolve all four, in order:

```python
# a) which address does the consumer actually trust?
call(EXECUTOR, sel("ORACLE_MULTISIG()"))        # immutable in WithdrawGasPayer
call(EXECUTOR, sel("ORACLE()"))                 # different contracts use different names
call(ORACLE_V2, sel("hasRole(bytes32,address)") + rolehash("ORACLE_ROLE") + ad(CANDIDATE))

# b) is that address even deployed?
eth_getCode(cand, "latest")["result"]           # "0x" => never deployed

# c) is the repo's own signer contract referenced anywhere?
grep -rn "RelayMultisigSigner" contracts/ script/ test/   # only deploy script + test harness => DECOY
python3 -c "import json;d=json.load(open('deployments/contracts/prod.json'));..."  # absent => not in prod

# d) what are the verifier's own trust parameters?
call(MSIG, sel("threshold()"))                  # -> 2
call(MSIG, sel("owner()"))                      # -> EOA (often ALSO a role holder on the hub)
call(MSIG, sel("getSigners()"))                 # -> address[] ; then eth_getCode each => EOA vs contract
```

Session result: the repo's `RelayMultisigSigner.sol` (Aurora/NEAR chain-signatures bridge) was **never deployed and
never referenced**; the live oracle was `RelayOracleMultisig 0x2a72…b0`, threshold 2 of 5 EOAs, owner
`0xf61a…775a`, and that owner **also held `OPERATOR_ROLE` on the hub**. Report that as *the* risk statement:
owner-key compromise ⇒ `addSigner()` / `threshold(1)` ⇒ 1-of-1 ⇒ free mint. That is **HIGH-ROLE-ONLY / key
compromise**, never "keyless".

---

## 2. The differential test that proves a signature is (or is not) bound to the actions

Do **not** reason about digests. Mutate the payload and keep the signature:

```python
base = bytearray(tx_input_without_selector)
base[SIG_OFF+32:] = b"\x00" * (len(base)-SIG_OFF-32)   # zero the signature blob, KEEP length
def probe(pos=None):
    m = bytearray(base)
    if pos: m[pos] ^= 0xFF
    r = rpc("eth_call", [{"from": ATTACKER, "to": TARGET, "data": "0x"+m.hex(), "gas": "0x2dc6c0"}, "latest"])
    return "SUCCESS" if ("result" in r and not r.get("error")) else "REVERT:"+r["error"]["message"]
```

Then interpret by **zone**, because the payload has structurally different regions:

| flip position | zeroed-sig result | reading |
|---|---|---|
| idempotencyKey / array offsets (zone A) | REVERT | already-executed / decoder guard — not signature |
| inside action bytes (zone B) | REVERT | **signature IS bound** ← the finding |
| trailing padding / unused slots | `0x` | ignored bytes; not evidence of anything |

Session: 66 evenly-spaced flips across the real 11 KB payload → **66/66 revert**, so the signature commits to every
action byte. Combined with "real calldata replays to `0x`", that is two independent confirmations.

**The minimal-call rule (do this instead of trusting a big payload):**

```python
# one execution, one action, 130 zero bytes of signature
data = "0x" + sel("execute((bytes32,bytes[]),address,bytes)") + encode(
    ["(bytes32,bytes[])","address","bytes"],
    [(b"\xaa"*32, [encode(["uint8","address","uint256","uint256"],[0, ATTACKER, 0, 10**18])]),
     MSIG, b"\x00"*130]).hex()
```

Result: `0xd855c4f4 + 0x2a72…b0` = `InvalidSignature(0x2a72…)`. Confirmed by three sibling probes:
`oracle=0x0` → `0x91e47843` = `UnauthorizedOracle(0)`; `deadline=1` → `0x15642292` = `RequestExpired(1)`;
`WithdrawGasPayer.payGas(…, sig=0)` → `0xda027c9a` = `InvalidOracleSignature(0x2a72…)`.

Decode every custom selector from source before naming it:

```python
for s in ["InvalidSignature(address)","UnauthorizedOracle(address)","RequestExpired(uint256)",
          "InvalidOracleSignature(address)","GasAlreadyPaid(bytes32)"]:
    print(s, keccak(text=s)[:4].hex())
```

A typed revert with the expected argument is the strongest possible *negative* evidence — quote it verbatim.

---

## 3. Audit the verifier source in this order

1. **Signature composition** — concatenated 65-byte sigs? `length/65 < threshold` check? `ECDSA.tryRecover` vs
   `recover` (tryRecover = revert-free false, so a malformed sig cannot brick the path).
   **The load-bearing distinction is `for (i = 0; i < threshold; i++)` vs `i < signatureCount`.** With
   `i < signatureCount` and no minimum, a blob that decodes to N sigs loops N times against a *count* the caller
   controls — so the count must be independently pinned (`if (signatureCount < threshold) return false;`) AND the
   loop must bound on `threshold`. Verify BOTH at runtime, not just in source: `SLOAD` of the threshold slot
   appearing in the loop condition is the proof (`0x7ef SLOAD slot 6` here). Note that extra signatures beyond
   `threshold` being ignored (`195 B` on a 2-of-N still returns MAGIC) is correct, not a bug.
   Live forge matrix + fork positive control: `adversarial-multi-round-audit →
   references/eip1271-verifier-forge-probes.md`.
2. **Duplicate/malleability guard** — monotonic `signer > lastSigner` (ascending sort) blocks the same key twice.
   Absence of this is a real Critical in multisig code.
3. **Authorization** — `isSigner[recovered]`. Check the writer: `addSigner` should be `onlyOwner`.
4. **Domain separation — who owns it?** Session finding: `_validateSignatures` verifies the *raw digest it is given*;
   the consumer (`RelayOracleV2._hashExecution`, `RelayExecutor._executeAndWithdrawRequestDigest`) builds the EIP-712
   digest. **That is correct design, not a missing-domain-separator bug.** An initial hypothesis to the contrary was
   falsified — check the caller before claiming replayability across contracts/chains.
5. **Entrypoint guards** — for a chain-signatures style signer:
   - `approveSignature` — must be `onlyOwner`; grep every writer of `approvedSignatures`.
   - `sign(data, curve, gas, cbGas)` — public is fine **iff** it re-reads `approvedSignatures[key][curve]` and
     reverts `SignatureNotApproved()` otherwise. Public + no approval = arbitrary signing primitive = Critical.
   - `signatureCallback(curve, hash)` — must check `msg.sender == <derived NEAR/Aurora implicit address of
     address(this)>`. Without that guard, `signatures[hash][curve] = promiseResult(0).output` is attacker-writable.
   - `init()` — must not re-run and must not touch owner/nearSigner/signerPath. Setters for those are ATO vectors.
6. **Deletion / replay** — `delete signatures[...]` after use? If never deleted, the signature is eternal **at the
   signer layer**; whether that is exploitable depends entirely on the consumers' nonce stores:
   `usedRequests[digest]`, `gasPayments[paramsHash]`, `usedNonces[spenderKey][nonce]`,
   `IDEMPOTENCY_STORE.markExecuted(key)`. Enumerate them, then grade: eternal signature + no consumer nonce =
   replay-HIGH; eternal signature + all consumers nonce'd = NOT exploitable.
7. **Griefing on public request entrypoints** — `sign()` increments `pendingSignatures[key][curve]` before the
   external call; a race lets anyone occupy the 5-minute window and make the honest relayer's second call `return`
   early. Real but **LOW/INFO** (delay only, no asset loss, first-come applies to everyone). Say that, do not inflate.

---

## 4. Consumer-side gate matrix (the closure table to deliver)

| consumer | role gate | sig gate | anti-replay | live probe |
|---|---|---|---|---|
| `RelayOracleV2._execute` | `hasRole(ORACLE_ROLE)` | `isValidSignatureNow(digest)` | `IDEMPOTENCY_STORE.markExecuted` | `0xd855c4f4` |
| `RelayExecutor._validateRequest` | `hasRole(ORACLE_ROLE)` | `isValidSignatureNow` | `usedRequests[digest]` (written *before* verify, fine — reverts roll back) | `0xd855c4f4` / `0x15642292` |
| `WithdrawGasPayer.payGas` | **none** | `isValidSignatureNow` | `gasPayments[hash]` write-once | `0xda027c9a` |
| `RelayAllocator.consumeSpenderSignature` | none | `tryRecover == spender` **or** MSIG 1271; empty sig ⇒ `false` early | `usedNonces[spenderKey][nonce]` | source |
| `RelayGenericMapping` set/delete | `hasRole(ORACLE_ROLE)` | `isValidSignatureNow` | — | same pattern |

One row per consumer, gate column filled ⇒ **BLOCKED — closure evidenced**, which is a finished deliverable.

---

## 5. Verdict labels used here

- `PROVEN-CRITICAL` — keyless end-to-end, raw output shows value moving to the attacker.
- `HIGH-ROLE-ONLY` — needs a key/role; then state the blast radius and the holder set (e.g. one EOA = multisig owner
  **and** hub operator).
- `BLOCKED` — two rounds, no forward progress, keep the raw revert as the reason.
- `REFUTED` / `FALSIFIED` — you claimed it, then killed it with evidence. **Write it down and correct yourself in the
  report**; the three falsifications (domain separator, single-blob-for-N-executions, zero-sig success) were the most
  valuable lines in the final document.
- `UNPROVEN` — no raw hex means no claim. Hard rule from the brief, keep it.
