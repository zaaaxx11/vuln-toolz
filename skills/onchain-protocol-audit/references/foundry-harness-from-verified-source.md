# Foundry harness from explorer-verified source

Build a runnable Solidity test project out of contracts you already downloaded from a block
explorer. Lets you turn "I read the code and think X is broken" into "the compiler and the runtime
say the opposite".

---

## 1. Layout

```
test_boring/
├── foundry.toml
├── lib/
│   ├── forge-std/            # git clone --depth 1 https://github.com/foundry-rs/forge-std
│   ├── solmate/              # copied from the explorer's tree
│   └── openzeppelin-contracts/
├── src/                      # copied from the explorer's tree
└── test/
    └── BoringChefEpoch.t.sol
```

Copy out of the fetched tree, don't re-fetch:

```bash
mkdir -p src lib test
cp -r ../src/<TreeName>/src/* src/
cp -r ../src/<TreeName>/lib/* lib/
```

---

## 2. foundry.toml

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.21"
evm_version = "shanghai"
optimizer = true
optimizer_runs = 200
remappings = [
  "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
  "@solmate/=lib/solmate/src/",
  "solmate/=lib/solmate/src/",
  "src/=src/",
  "forge-std/=lib/forge-std/src/"
]
```

### The remapping prefix trap (cost ~20 min)

The vendor tree nests `contracts/` **once**:
`lib/openzeppelin-contracts/contracts/utils/Address.sol`.

- `"@openzeppelin/=lib/openzeppelin-contracts/contracts/"` + import `@openzeppelin/contracts/utils/Address.sol`
  → resolves to `lib/openzeppelin-contracts/contracts/contracts/utils/Address.sol` → **"not found"**.
- ✅ `"@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"` → resolves correctly.

Always print the resolved remappings (`forge build` echoes them) and read the path before trusting
the compile error.

### forge-std clone nesting

```bash
git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
# -> the repo lands at lib/forge-std/forge-std/
cp -r lib/forge-std/forge-std/src lib/forge-std/
cp -r lib/forge-std/forge-std/lib lib/forge-std/ 2>/dev/null
```
Or just set the remapping to `forge-std/=lib/forge-std/forge-std/src/`. Copying up one level is
less confusing for the next session.

---

## 3. solmate API gotchas

| Gotcha | Detail |
|---|---|
| `ERC20` constructor | **3 args**: `ERC20(name, symbol, decimals)`. Two args → `Error (2973): Wrong argument count for modifier invocation: 2 arguments given but expected 3`. |
| `Auth` has no role getters | solmate `Auth` exposes only `owner()` and `authority()`. Role maps live in the **authority** contract (`RolesAuthority` etc.) — import and query that, or read storage. |
| `require` string | solmate `Auth.requiresAuth` reverts with the plain string `"UNAUTHORIZED"` — that exact string is a *feature* when matching on-chain reverts. |
| `Authority` interface | `canCall(address user, address target, bytes4 functionSig) external view returns (bool)` — 3 args, and the *selector* is the last one (solmate, not OZ's 3-arg `canCall` variant). |

---

## 4. Test patterns that produced real refutations

### 4.1 The double-count hypothesis

```solidity
function test_H1_rolloverAccumulatesEligibleSharesBeyondSupply() public {
    _enter(address(0xA1), 1000e6, address(0xA1), 1000e6);
    _enter(address(0xA2), 1000e6, address(0xA2), 1000e6);
    _enter(address(0xA3), 1000e6, address(0xA3), 1000e6);
    assertEq(vault.totalSupply(), 3000e6);

    _roll();  emit log_named_uint("epoch1 eligible", _elig(1));
    _roll();  emit log_named_uint("epoch2 eligible", _elig(2));
    _roll();  emit log_named_uint("epoch3 eligible", _elig(3));
    emit log_named_uint("FINAL supply", vault.totalSupply());
}
```

Key: **do not assert the hypothesis.** Log the numbers and assert only what you are certain of
(`totalSupply`). The measurement decides the hypothesis; a pre-written assertion just decides that
your test is wrong.

### 4.2 Acting as a privileged role

`vm.prank` covers **only the next call**. Two working shapes:

```solidity
// (a) prank each privileged call individually
vm.prank(manager);
vault.enter(from, ERC20(address(asset)), assets, to, shares);

// (b) make the test contract the owner at construction
vault = new BoringVault(address(this), "Name", "SYM", 6);
// then address(this) == owner and `user == owner` short-circuits `isAuthorized`
```

⚠️ If you deploy with the test contract as owner and then `vm.prank(manager)`, you get
`UNAUTHORIZED` — that is a **test bug**, not a finding. Decide which shape you want and stay in it.

### 4.3 uint128 truncation probe

```solidity
function test_H3_uint128Truncation() public {
    uint256 huge = type(uint128).max + 1;     // 2^128
    _enter(address(0xA1), 1, address(0xA1), huge);
    assertEq(vault.balanceOf(address(0xA1)), huge, "erc20 keeps full value");
    uint128 userElig = vault.getUserEligibleBalance(address(0xA1));
    emit log_named_uint("ERC20 balance", vault.balanceOf(address(0xA1)));
    emit log_named_uint("uint128 ledger", uint256(userElig));
}
```
(Here the test hit an arithmetic underflow inside the contract first — which is *itself* the
finding: the ledger cannot represent the balance, so the arithmetic reverts.)

### 4.4 `vm.warp` lint noise

`vm.warp(block.timestamp + 1 days)` triggers `environment-read-across-mutation`. Use
`uint256 t = vm.getBlockTimestamp(); vm.warp(t + 1 days);` to silence it.

---

## 5. Reading the output

```
Ran 3 tests for test/BoringChefEpoch.t.sol:BoringChefEpochTest
[FAIL: UNAUTHORIZED] test_H1_...(gas: 157605)
[FAIL: panic: arithmetic underflow or overflow (0x11)] test_H3_...(gas: 364)
Suite result: FAILED. 0 passed; 3 failed
```

- `UNAUTHORIZED` → **prank/owner shape problem** (see §4.2), not a contract vulnerability.
- `panic 0x11` → real arithmetic revert inside the contract → **that is the finding**; read which
  expression overflowed.
- `-vv` gives the full trace; `-vvvv` adds the emitted logs.

---

## 6. When a fork is impossible

For a "quote vs execution" or "price manipulation" hypothesis, a **fork at a recent block** on a
public RPC is ideal. If it is unavailable, say so plainly in the report and fall back to a
unit-level test with a mock that reproduces the *documented* semantics of the real venue — and label
which one you did. Never imply a mock result came from a fork.
