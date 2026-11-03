# Foundry harness for upgradeable ERC-4626 vault audits

Recipe that unblocks the most common blocker when auditing an *upgradeable* vault
whose implementation contract calls `_disableInitializers()` in its constructor.

Use this when: the target is an ERC-4626 / vault implementation deployed behind a
proxy, you need to execute its real code paths (not just read them), and you must
not broadcast anything to production.

---

## 0. Never deploy the implementation directly

`UpgradeableVault` (Concrete-style) does:

```solidity
constructor(address factoryAddr) {
    _disableInitializers();          // <-- blocks initialize() on the impl
    factory = factoryAddr;
}
```

So `impl.initialize(...)` reverts `AlreadyInitialized()`. You MUST deploy an
ERC-1967 proxy and initialize through it.

## 1. Directory scaffold (new dir, never inside the audited tree)

```
<work>/test_<name>/
  foundry.toml
  src/                 # VERBATIM copy of the audited tree's src/  (read-only source stays untouched)
  src/test/            # your mocks live here
  test/                # your .t.sol files
  lib/forge-std/       # copy from an existing harness on disk if network is unavailable
  node_modules/        # copy the OZ packages the audited tree imports
```

`foundry.toml` that works for a project importing BOTH `@openzeppelin/contracts/`
and the legacy `@openzeppelin-contracts/` alias (both spellings are in the wild):

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib", "node_modules"]
solc_version = "0.8.28"      # see "solc version" below
evm_version = "shanghai"
optimizer = true
optimizer_runs = 200
remappings = [
    "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
    "@openzeppelin-contracts/=node_modules/@openzeppelin/contracts/",
    "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
    "@openzeppelin-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
    "forge-std/=lib/forge-std/src/",
    "src/=src/"
]
```

## 2. solc version — pick one that can compile the target

| Target feature | Minimum solc |
|---|---|
| `require(cond, CustomError())` | **0.8.26** |
| `require(cond, CustomError())` + `bytes.concat` | 0.8.24+ / 0.8.26 |
| `transient` storage (`tstore`) | 0.8.24 + cancun evm |
| plain `revert CustomError()` | 0.8.4 |

If the target uses custom errors in `require`, **0.8.24 fails to compile** with
`Undeclared identifier ... Note: Candidate: function require(bool)`. Set
`solc_version = "0.8.28"` (or the target's own declared compiler version from its
`_meta.json`). This is a compiler-version issue, not a code issue — do not
"fix" the source to accommodate it.

## 3. Mocks you will need

### ERC-20 mock
The vendored OZ tree is often **pruned** to only the files the target actually
imports — `token/ERC20/ERC20.sol` is frequently ABSENT, so `import {ERC20} from
"@openzeppelin/contracts/token/ERC20/ERC20.sol"` fails to resolve. Write a
minimal mock implementing `IERC20` + `IERC20Metadata` directly (both of those
ARE present in the pruned tree). ~60 lines, no inheritance.

### Factory mock
The implementation stores `factory` as an **immutable** set in its constructor, and
`initialize()` requires `msg.sender == factory`. Order matters:

```solidity
// 1. factory FIRST (it does not need to know the impl)
MockFactory f = new MockFactory(address(this));
// 2. impl, pointing at the factory
ConcreteAsyncVaultImpl impl = new ConcreteAsyncVaultImpl(address(f));
// 3. proxy
MockVaultProxy proxy = new MockVaultProxy(address(impl), "");
vault = ConcreteAsyncVaultImpl(address(proxy));
// 4. now initialize through the factory
f.initVault(address(vault), 1, address(this), data);
```

The factory mock takes the vault address as a **parameter** — that breaks the
circular dependency (factory -> impl -> factory) without CREATE2 prediction.

### Proxy
The vendored OZ tree usually lacks `proxy/ERC1967/ERC1967Proxy.sol`. Copy it
(and its deps `ERC1967Utils.sol`, `interfaces/IERC1967.sol`, `utils/StorageSlot.sol`)
from another on-disk project that vendors full OZ (e.g. a factory/proxy tree in
the same audit repo). Copy them into
`node_modules/@openzeppelin/contracts/proxy/...` and
`node_modules/@openzeppelin/contracts/interfaces/IERC1967.sol`.

**Gotcha:** OZ's `ERC1967Proxy` constructor reverts `ERC1967ProxyUninitialized()`
when `data.length == 0` in some versions. Workarounds, in order of preference:
1. deploy with the real init calldata as `data` (but then the factory check
   `msg.sender == factory` fails, because the proxy calls the impl itself);
2. use a tiny local proxy that stores the impl in the ERC-1967 slot and does
   NOT run the uninitialized check;
3. patch the vendored copy's constructor check.

Option 2 is the cleanest for audit purposes — write a 25-line proxy:

```solidity
contract AuditProxy {
    bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    constructor(address impl) { assembly { sstore(IMPL_SLOT, impl) } }
    fallback() external payable {
        assembly {
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}
```

That runs the REAL implementation code with REAL proxy storage semantics and no
OZ init-guard friction.

## 4. Overloaded-function selector errors

A vault with `claimWithdrawal(uint256[])` and `claimWithdrawal(address,uint256[])`
breaks `vault.claimWithdrawal.selector` with
`Member "claimWithdrawal" not unique after argument-dependent lookup`.
Use `abi.encodeWithSignature("claimWithdrawal(uint256[])", ids)` instead.

## 5. Struct-typed params in `abi.encode`

`abi.encode(IAllocateModule.AllocateParams({...}))` needs the **qualified** name
(`IAllocateModule.AllocateParams`), not the bare name, when the struct is
declared inside an interface.

## 6. Console logging

`forge-std/Console2.sol` may be absent; `forge-std/console.sol` (lowercase, and
`console.log` not `console2.log`) is the safe import:

```solidity
import {console} from "forge-std/console.sol";
```

## 7. Reading vault internals in tests

Useful handles that expose the accounting you need to assert on:
- `vault.cachedTotalAssets()` — the ledger the vault prices off
- `vault.totalSupply()` — includes shares parked in the vault for queued requests
- `vault.balanceOf(address(vault))` — shares parked by pending withdrawals
- `vault.getUserEpochRequest(user, epoch)` — queued shares
- `vault.getEpochPricePerShare(epoch)` — locked epoch price
- `vault.pastEpochsUnclaimedAssets()` — reserved-but-unclaimed

## 8. Assert on conservation, not just on "no revert"

A test that only checks "it didn't revert" proves nothing about an invariant.
Always assert the arithmetic identity, e.g.:

```solidity
assertEq(aliceClaimable, aliceShares.mulDiv(lockedPrice, 1e18, Math.Rounding.Floor));
assertEq(vault.totalSupply(), 0, "all shares burned");
assertEq(asset.balanceOf(address(vault)), 0, "vault drained");
assertLe(vault.cachedTotalAssets(), 1, "cachedTotalAssets ~0");
```

## 9. Copying files

`cp -r src node_modules` can silently produce a nested/partial copy when the
destination already exists. Verify the tree after copying:

```bash
find node_modules/@openzeppelin -name "*.sol" | head -20
```

If a file is missing, look for it in ANOTHER on-disk project that vendors the
full library before reaching for the network.
