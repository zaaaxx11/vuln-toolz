# Explorer source retrieval + role/capability decoding

Everything needed to go from "an address on a DeFi site" to "the complete trust graph, with source".

---

## 0. When the source is a LOCAL repo, not an explorer

If the target ships a Foundry repo (or you were handed a workspace path), skip §1 entirely and use
the outline-first loop instead of reading files end to end:

```
search_files(pattern: "function |onlyRole|ROLE =|event |error |immutable|mapping\\(|contract ")
```

one call per contract gives the entrypoint table row — every role gate, state var and custom error —
in ~50 lines. Then `read_file` only the span that matters. Full method and the read-budget
rationale: `trust-graph-role-reachability-and-latent-findings.md` §8. That section also covers
"absence by inventory" (proving a contract does *not* exist with `find … -name '*.sol' | sort` plus
single-literal re-searches and a positive control) — a compound/alternation search returning 0 is
**not** evidence of absence.

---

## 1. Blockscout v2 — the working endpoint set

Base: `https://<chain>.blockscout.com` (eth = `https://eth.blockscout.com`).

### 1.1 The UA gate

```python
UA = {"accept": "application/json",
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128 Safari/537.36"}
```

`urllib.request` with default headers → **403 Forbidden**.
`curl` with default headers → 200.
This cost ~15 minutes once. Send the UA always.

### 1.2 Endpoint map

| Endpoint | Key fields | Use |
|---|---|---|
| `/api/v2/smart-contracts/{addr}` | `source_code`, `file_path`, `decoded_constructor_args`, `is_verified`, `compiler_version`, `sourcify_repo_url`, `compiler_settings.remappings`, `proxy_type`, `implementations` | the primary fetch |
| `/api?module=contract&action=getabi&address={addr}` | full ABI **with events** | v2 often omits events; the legacy endpoint includes them |
| `/api/v2/search?q={name}` | items[] with `address_hash` + `name` | find sibling/parent contracts by name |
| `/api/v2/addresses/{addr}/transactions` | items[].to | a deployer's contract set |

### 1.3 `source_code` shape

- **Not a JSON object** → it is a single file; write it to `<name>/<file_path>`.
- **Starts with `{`** → it is a JSON map of `path → content`; write each file, preserving dirs.
- Write a `_meta.json` alongside with `name / compiler_version / is_verified / file_path /
  decoded_constructor_args` so later sessions can re-derive the graph without re-fetching.

### 1.4 Parents are NOT in the child's blob

The v2 `source_code` for a child is usually **one file**. Read the child's `import {X} from
"src/..."` lines → the parent `X` is a **separate verified contract**. Find it with
`/api/v2/search?q=X` (exact contract name) and fetch its `file_path`.

Real chain that needed walking:

```
LayerZeroTeller            (file: src/base/Roles/CrossChain/Bridges/LayerZero/LayerZeroTeller.sol)
  └─ imports CrossChainTellerWithGenericBridge
       └─ imports CrossChainTeller
```

Reading only the leaf gave me the bridge's *admin* functions and none of its *money* functions.

⚠️ Beware name collisions: `search?q=CrossChainTeller` returned **4 different** contracts across
different projects (different authority, different usdc/usyc). **Disambiguate by constructor args**,
not by name. The right one shares the vault address you're auditing.

### 1.5 Sourcify — optional, times out

- `https://repo.sourcify.dev/contracts/full_match/1/<checksummed>/` → a Next.js HTML shell, useless.
- `https://sourcify.dev/server/v2/contract/1/<addr>?fields=sources` → sometimes returns the whole
  source set, but **timed out** in this environment. Treat as a bonus, never a dependency.
- Blockscout exposes `sourcify_repo_url` in the v2 payload — record it, don't depend on it.

---

## 2. Constructor args = the whole trust graph in one call

`decoded_constructor_args` is a list of `[value, {name, type, internalType}]`. It is the single
highest-yield datum in the whole workflow.

```python
d = get(f"https://eth.blockscout.com/api/v2/smart-contracts/{addr}")
for a in d.get("decoded_constructor_args") or []:
    print(a)   # e.g. ['0x74d1fAfa4e...', {'name': '_vault', 'type': 'address'}]
```

What to extract by name pattern:

| Arg name pattern | Means |
|---|---|
| `_vault`, `vault` | where the share token / funds live |
| `_accountant`, `accountant` | the **price oracle / rate provider** |
| `_owner`, `owner` | root of trust (may be an EIP-7702 delegator EOA) |
| `_authority`, `_auth` | the role/capability registry |
| `_delegate`, `_peer` | peer/deployer EOA |
| `_bridge`, `_lzEndPoint`, `_endpoint` | cross-chain transport |
| `_usdc`, `_base`, `_asset` | the underlying asset + decimals anchor |
| `_rateProvider` | external price feed |
| `startingExchangeRate`, `allowedExchangeRateChange*`, `minimumUpdateDelayInSeconds`, `platformFee`, `performanceFee` | **oracle safety bounds, read straight from the constructor** |

Worked example (Royco):

```
LayerZeroTeller(
  _owner      = 0x47Cec90FA...   -> Deployer contract
  _vault      = 0x74d1fAfa...   -> BoringVault (holds the share token)
  _accountant = 0x80f0B206...   -> AccountantWithRateProviders (the share-price oracle)
  _weth       = 0xC02aaA39...   -> WETH
  _lzEndPoint = 0x1a440760...   -> LayerZero EndpointV2
  _delegate   = 0x47Cec90FA...  -> same Deployer
  _lzToken    = 0x6985884C...   -> LayerZeroToken
)

Deployer(_owner = 0xf8553c85...  <- EIP-7702 delegator EOA, holds role bit 33)
RolesAuthority(_owner = 0x47Cec90FA..., _authority = 0x0)
```

Then follow `_owner` one hop further: `Deployer` is itself a contract whose owner is
`0xf8553c85…` — that EOA is the real root of trust and holds role bit 33 in the authority.

---

## 3. Roles / capability decoding

### 3.1 The two authority patterns

**solmate `RolesAuthority`** (bytecode 2614 bytes here):

```solidity
canCall(user, target, sig) =
    isCapabilityPublic[target][sig]
    || bytes32(0) != getUserRoles[user] & getRolesWithCapability[target][sig];
getUserRoles(user) -> bytes32   // role n = bit n
getRolesWithCapability(target, sig) -> bytes32
isCapabilityPublic(target, sig) -> bool
```

**OpenZeppelin `AccessManager`** (`restricted` modifier) is a different shape — check
`authority()` and the contract's `isAuthorized`/`canCall` interface before assuming solmate.

### 3.2 Events are the ground truth (and better than the getter)

```
PublicCapabilityUpdated(address indexed target, bytes4 indexed functionSig, bool enabled)
RoleCapabilityUpdated(uint8 indexed role, address indexed target, bytes4 indexed functionSig, bool enabled)
UserRoleUpdated(address indexed user, uint8 indexed role, bool enabled)
```

From the log you get the **entire historical map**: who was ever granted what, who was ever made
public, and every revocation (enabled=false). Decode:

- `target` = `topics[1][-40:]`, `functionSig` = `topics[2][-8:]` (public cap) / `topics[3][-8:]` (role cap).
- role number = `int(topics[1], 16)` (role cap) / `int(topics[2], 16)` (user role).
- `enabled` = `int(data[0:64], 16)`.

⚠️ **`functionSig == 0x00000000` means WILDCARD — every function on that target.** Never assume
either way; confirm with a real selector:

```python
canCall(user, target, sel("enter(address,address,uint256,address,uint256)"))
```

### 3.3 Getters that revert

In the audited deployment, `isCapabilityPublic`, `getRolesWithCapability`, and `canCall` **all
reverted** while `getUserRoles`, `doesUserHaveRole`, `owner`, and `authority` worked. The deployed
bytecode carried a newer/different version than the verified source. Consequences:

- Do not conclude "no public capability" from a reverting getter.
- Fall back to the **event log** + `eth_call` simulation.
- `doesUserHaveRole(user, role)` DID work and was enough to map who holds what.

### 3.4 Storage-layout fallback

If a getter is unusable and events don't carry the bit, read the slot directly. solmate `Auth`
layout: `slot 0 = owner`, `slot 1 = authority`, then mappings from `slot 2`.

```python
from eth_utils.crypto import keccak
def map_slot(key: bytes, slot: int) -> int:
    return int.from_bytes(keccak(key + slot.to_bytes(32, "big")), "big")
def m2(k1: bytes, k2: bytes, slot: int) -> int:
    return int.from_bytes(keccak(k1 + keccak(k2 + slot.to_bytes(32, "big"))), "big")
```

Confirm the base slot by checking `slot 0`/`slot 1` against `owner()`/`authority()` first, then
scan candidate bases.

---

## 4. The decisive simulation set

For a money-moving contract, simulate each privileged call twice — once as a **role-free
address** and once as a **role-holder** — and compare revert strings:

| Call | Expected when unauthorized |
|---|---|
| `enter(from, asset, amount, to, shares)` | `UNAUTHORIZED` |
| `enter(from, asset, 0, to, BIG_SHARES)` | `UNAUTHORIZED` (free mint) |
| `exit(to, asset, amount, from, shares)` | `UNAUTHORIZED` |
| `manage(target, data, value)` | `UNAUTHORIZED` **or** `Invalid params` (the latter = my encoding) |
| `updateExchangeRate(newRate)` | `UNAUTHORIZED` |
| `updatePayoutAddress(addr)` | `UNAUTHORIZED` |
| `setShareLockPeriod(0)` | `UNAUTHORIZED` |
| `addChain(eid, allowFrom, allowTo, target, gas)` | `UNAUTHORIZED` |

A role-holder **also** getting `UNAUTHORIZED` means the role mapping does not grant that function —
which is itself the finding (or the proof that capability registration used a wildcard that the
deployed code interprets differently).

Also simulate the **hook** separately, since it is a `view` and reverts loudly:
`teller.beforeTransfer(from, to, operator)` → if it returns `0x` for a locked pair, the lock is not
enforcing on that path.

---

## 5. Multi-chain targets

An address on Sonic/Plume/HyperEVM read through an Ethereum RPC returns `codelen = 0`. That is
**"wrong chain"**, not "not a contract". Always check which chain the app says the market lives on,
then query that chain's RPC (the app usually proxies several: `POST /api/rpc/{chainId}`).
