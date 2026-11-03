# Off-chain signature services: split-domain binding, and how to verify a subagent's crypto claim yourself

Condensed from the round that found **F2 — the nonce-mapping split-chainId bug** in Relay Protocol's
TypeScript attestation service, and from the three audit rounds (R21/R22/R23) that ran alongside it.

Companion to `evm-foundry-and-offchain-api-audit.md` §5/§16d (EIP-712 claim-flow checklists) and to
`trust-graph-role-reachability-and-latent-findings.md` §7 (census before severity). This file covers
what those don't: the **off-chain signing service** as a target in its own right, the specific bug
shape where a signature is valid but bound to the *wrong* chain, and the verification protocol for
crypto claims that arrive from a subagent.

**Section list:** §1 The split-binding bug shape · §2 The 40-line viem verifier that settles it ·
§3 Why `jest`/`ts-jest` will fight you and the ESM escape hatch · §4 The impact gate — do not report
until the on-chain consumer is read · §5 Chain-scan mechanics that actually finish · §6
`hasRole` roster census — the live-state check that beats the event list.

---

## 1. THE SPLIT-BINDING BUG SHAPE — one signature, two chain ids

The classic EIP-712 audit asks *"is field X inside the signed struct?"*. This is a different and
easier-to-miss shape: **field X is signed, but the domain separator is built from a *different*
input than the struct, so the same signature is valid under chain A and recorded as belonging to
chain B.**

```ts
// attestation/index.ts — NONCE_MAPPING_DOMAIN built from signatureChainId
const NONCE_MAPPING_DOMAIN = (chainId: number) => ({
  name: "RelayNonceMapping", version: "2", chainId,
  verifyingContract: zeroAddress,
});

// :1182  message.chainId  ← walletChainId   (becomes the mapping key)
const message = { chainId: data.walletChainId, wallet: …, depositor: …, id: …, nonce: … };

// :1197  domain chainId   ← signatureChain.additionalData.evmChainId  (a DIFFERENT field)
const isValidSignature = await verifyTypedData({
  address: data.wallet,
  domain: NONCE_MAPPING_DOMAIN(Number(signatureChain.additionalData?.evmChainId)),
  types: NONCE_MAPPING_TYPES, primaryType: "NonceMapping",
  message, signature: data.signature,
});

// :1208  the mapping is then recorded against walletChainId
const walletChain = await getChain(data.walletChainId);
const user = generateAddress({ family: walletChain.vmType, chainId: walletChain.id, address: data.wallet });
```

Both `walletChainId` and `signatureChainId` are **user-supplied, independent request fields** — the
API schema (`nonce-mapping/v2.ts:16` and `:31`) declares them separately with no cross-validation.
There is no `if (walletChainId !== signatureChainId) throw`.

**Detection recipe — run this on every service that has a domain builder taking a parameter:**

```bash
# 1. find every place a domain separator is constructed
grep -rn "chainId,\s*$\|name:.*version:\|domain:" src/ --include=*.ts | grep -i domain -A2

# 2. for each, list the fields the DOMAIN consumes vs the fields the MESSAGE consumes
grep -rn "walletChainId\|signatureChainId\|evmChainId" src/ --include=*.ts

# 3. the bug is present when the domain's chain id comes from a *different field*
#    than the message's chain id, with no equality check between them
```

The tell: the domain builder is a **function of a parameter** rather than of a constant. A
multi-chain protocol *has* to parameterise it; the bug is that the parameter is attacker-chosen
and never compared against the chain the struct claims.

**Generalises to**: `sourceChainId`/`destChainId`, `signChainId`/`executeChainId`,
`verifyingChain`/`payloadChain` — any service where a signature is verified under one chain context
but stored/executed under another. Also covers the `nonce` and `deadline` variants: a nonce signed
for chain A being consumed on chain B is the same class.

---

## 2. THE 40-LINE VIEM VERIFIER — settle the claim before you believe it

When a subagent reports "PoC kriptografis ✅" for a signature bug, **do not propagate it**. A
cryptographic claim is either executable in 40 lines or it is not a finding. This script needs only
the repo's `node_modules` (viem is already a dependency of any such service).

```js
// node f2verify.mjs   (run from the service's repo root, ESM — see §3)
import { privateKeyToAccount } from "viem/accounts";
import { verifyTypedData } from "viem";

const DOMAIN = (chainId) => ({ name: "RelayNonceMapping", version: "2", chainId,
  verifyingContract: "0x0000000000000000000000000000000000000000" });
const TYPES = { NonceMapping: [
  { name: "chainId", type: "string" }, { name: "wallet", type: "address" },
  { name: "depositor", type: "address" }, { name: "id", type: "bytes32" },
  { name: "nonce", type: "uint256" }] };

const acct = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const msg  = { chainId: "optimism", wallet: acct.address,
  depositor: "0x1111111111111111111111111111111111111111",
  id: "0x" + "ab".repeat(32), nonce: 7n };

// sign under the domain the ATTACKER picks (chainId 1), struct claims optimism
const sig = await acct.signTypedData({ domain: DOMAIN(1), types: TYPES,
  primaryType: "NonceMapping", message: msg });

const asServer  = await verifyTypedData({ address: acct.address, domain: DOMAIN(1),
  types: TYPES, primaryType: "NonceMapping", message: msg, signature: sig });
const asCorrect = await verifyTypedData({ address: acct.address, domain: DOMAIN(10),
  types: TYPES, primaryType: "NonceMapping", message: msg, signature: sig });

console.log("asServer :", asServer);   // true  → server accepts
console.log("asCorrect:", asCorrect);  // false → but it is NOT bound to optimism
console.log(asServer === true && asCorrect === false ? "F2 TERVERIFIKASI" : "F2 GUGUR");
```

Real output from the round:

```
message.chainId (mapping key) = optimism
domain chainId dipakai server  = 1
verified under domain 1  (server) : true
verified under domain 10 (correct): false
F2 TERVERIFIKASI
```

**Why this is the right shape of proof:** the pair `(true, false)` is what makes it a finding.
`true, true` would mean the signature is chain-agnostic (worse, different bug). `false, *` means the
attack does not work. **Always print both verifications** — a single `true` proves nothing, because
a signature verified under the domain it was made for always returns `true`.

**Second control worth adding:** sign under the *correct* domain and verify under the *wrong* one,
to show the check is real and not an artifact of how you built `TYPES`.

---

## 3. `jest`/`ts-jest` WILL FIGHT A STANDALONE CRYPTO TEST — use the ESM escape hatch

A `.test.ts` dropped into the repo's own `test/unit/` fails on things unrelated to the bug:

```
error TS2582: Cannot find name 'describe' / 'it' / 'expect'
error TS2737: BigInt literals are not available when targeting lower than ES2020
error TS6133: 'signatureChainId' is declared but its value is never read
```

That is the repo's ts-jest config being stricter than the thing you are trying to prove. **Do not
spend rounds fixing their TypeScript settings.** Write the same logic as a plain `.mjs` file and
run it with `node`:

```bash
cp /tmp/f2verify.mjs ./f2verify.mjs   # MUST live inside the repo so node resolves ./node_modules/viem
node f2verify.mjs
```

Two gotchas that cost time:
- **The script must sit inside the repo directory.** Running `node /tmp/x.mjs` gives
  `ERR_MODULE_NOT_FOUND` because Node resolves `viem` relative to the script's location, not the cwd.
- **`.mjs`, not `.js`** if the repo is ESM (`"type": "module"`); and use `-e`-free top-level `await`,
  which `.mjs` permits.

Also: deleting the throwaway `.test.ts` afterwards keeps the repo clean. A test that fails to compile
is not evidence and should not be left behind to confuse the next round.

---

## 4. THE IMPACT GATE — a valid signature bug is not a finding until the consumer is read

The split-binding proof above is **cryptographically complete and impact-incomplete.** The signature
is accepted; that is established. What is *not* established is that the mis-recorded mapping reaches
money.

The gate, in order:

```bash
# 1. what does the service do with the value AFTER verifying the signature?
grep -rn "getNonceMappingMessage\|genericMapping" src/ --include=*.ts | grep -v "nonce-mapping/v2.ts"

# 2. is there an on-chain contract that consumes it?
grep -rn "genericMappingAddress" src/ --include=*.ts          # → getContract({ address: hubInfo.genericMappingAddress })

# 3. does that contract exist in the Solidity repo?
ls contracts/ | grep -i "generic\|mapping"                     # → RelayGenericMapping.sol
```

**Until step 3 is read, the correct label is: `PROVEN (cryptographic) / IMPACT UNPROVEN`.** Saying
"attacker can shift nonce mappings across chains" when you have not read `RelayGenericMapping.sol` is
the exact overclaim the truth-supremacy rule forbids.

The honest sentence shape when the gate is still open:

> "Signature accepted cross-chain — proven with viem (`true/false` pair above). The mis-recorded
> mapping flows to `genericMappingAddress` (`attestation/index.ts:1409`), whose consumer is
> `RelayGenericMapping.sol` — **not yet read**. Fund impact UNPROVEN; the chain is a DoS/desync
> unless that contract lets the mapping move value."

Two outcomes and how each is reported:
- Consumer moves value on a mismatched key → this is a real cross-chain replay/desync bug, HIGH.
- Consumer only stores a record → DoS / state-desync, MEDIUM at best, and name the exact
  divergence ("mapping recorded for chain B while signature authorises chain A").

---

## 5. CHAIN-SCAN MECHANICS THAT ACTUALLY FINISH

`eth_getLogs` over `fromBlock=0` on a high-volume chain is the single biggest time sink in this class
of audit. Four facts learned expensively:

| Problem | Fix |
|---|---|
| `"Response size exceeds limit"` on wide ranges | chunk by **25,000 blocks** (50k also overflowed on RPCs with many events per block) |
| `cast logs` with a topic filter times out at 180s | do it in Python with `curl -m 20` per chunk, not `cast` |
| A scan dies silently and writes nothing | **write the output file only after the loop, and print a done marker**; check `ls -l` on the log, not just the process status |
| `nohup … &` inside `terminal(background=true)` reports `exited` immediately | the wrapper shell exits, the python keeps running — poll with `ps aux \| grep <script>.py \| wc -l`, not the tool's status |

The scan skeleton that survived three rounds:

```python
import json, subprocess
R = "https://rpc.example"; T = "0x<topic>"; HUB = "0x<contract>"
found, fails = [], 0
for start in range(0, TIP, 25000):
    end = min(start + 24999, TIP)
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{
        "address": HUB, "fromBlock": hex(start), "toBlock": hex(end), "topics":[T]}]})
    r = subprocess.run(["curl","-s","-m","20","-X","POST",R,
        "-H","Content-Type: application/json","--data",body], capture_output=True, text=True)
    try: d = json.loads(r.stdout)
    except: fails += 1; continue
    if "error" in d: fails += 1; continue
    for lg in d.get("result") or []:
        if lg["address"].lower() != HUB.lower(): continue      # ← MANDATORY, see below
        found.append((lg["topics"][1], "0x"+lg["topics"][2][-40:], int(lg["blockNumber"],16)))
open("/tmp/scan.log","w").write(f"found {len(found)} fails {fails}\n" + "\n".join(map(str,found)))
print("done", len(found), "fails", fails)
```

**Two rules baked into that skeleton:**
1. **Assert `log.address` per log.** On this RPC, `topics`-only queries returned logs from *unrelated
   contracts* — the address filter was ignored. Every scan must re-check `log.address` client-side or
   you will role-census a stranger's contract and invent a finding.
2. **Report `fails`.** A scan with 40 failures and 3 hits is not a census. Print both numbers and say
   so in the artifact ("122 chunks, 0 failed") — that sentence is what makes the result usable.

---

## 6. `hasRole` ROSTER CENSUS — the event list is not the state

`RoleGranted` events give you *history*; `hasRole` gives you *current authority*. The gap between
them is where a "role holder" turns out to be revoked, and where a live privileged address turns up
that no event near the tip would show.

The two-pass method:

```bash
# PASS 1 — enumerate grants from genesis (chunked scan from §5, topic = keccak("RoleGranted(bytes32,address,address)"))
# keccak("RoleGranted(bytes32,address,address)") = 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d

# PASS 2 — verify EVERY candidate's CURRENT state, per role
for c in $CANDIDATES; do
  printf "%s " $c
  for R in $OPERATOR $ADMIN $EDITOR $DEFAULT_ADMIN; do
    cast call $HUB "hasRole(bytes32,address)(bool)" $R $c --rpc-url $RPC | tr -d '\n'; printf " "
  done; echo
done
```

**Always read the role constants from the contract, not from the repo** — and expect some to be
absent. On this target `ORACLE_ROLE()` **reverted** on the Hub even though the repo defines it:

```bash
cast call $HUB "OPERATOR_ROLE()(bytes32)"      --rpc-url $RPC   # 0x9766…b929  OK
cast call $HUB "EDITOR_ROLE()(bytes32)"        --rpc-url $RPC   # 0x21d1…1e9c  OK
cast call $HUB "ORACLE_ROLE()(bytes32)"        --rpc-url $RPC   # REVERT — not exposed on this contract
```

A reverting getter is not a finding; it means the role lives on a different contract. Do not write
"ORACLE_ROLE missing" in a report.

**The output that earns its keep** is a two-column table: *granted at block N* vs *holds it now*. In
this round that table showed:

- `0xf61a3051…` — **EOA** (`codesize 0`, `nonce 217`) holding **both `OPERATOR` and `ADMIN`**. No
  multisig, no timelock. One private key = `mint`/`burn`/`grantRole` unbounded. **This is
  centralisation risk disclosure, not a bounty finding** — it fails the "not privileged-role-only"
  gate. Report it in the RISK LINE section, never as the finding.
- A ghost contract (`WithdrawGasPayer` v2) still holding `OPERATOR` with **0 transactions and no
  manifest entry** — the grant-chain evidence from `trust-graph-…md` §7c, reproduced.
- Eight live `EDITOR` holders — real but low impact (metadata rewrite → phishing surface), and the
  severity word depends on what EDITOR can actually call.

**Write the roster as its own artifact** (`R23_Roles.md`) with the event block numbers, the live
`hasRole` truth table, and an explicit "no new unprivileged path" verdict. It is the document that
lets every later round stop re-deriving who has power.
