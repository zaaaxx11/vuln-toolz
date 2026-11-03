# Multisig-is-cosmetic, oracle-owns-its-roles, and three self-inflicted control failures

Companion to `references/permission-model-global-operator.md` and
`references/log-enumeration-and-role-census.md`. Read this when a grade depends on
"it needs a multisig", or when a role census says a module is inert.

---

## 1. `onlyOwner` ON A MULTISIG DESTROYS THE THRESHOLD

A multisig is usually the *reason* a finding gets downgraded ("2-of-3, so MEDIUM at
most"). Verify that before spending it — the multisig's own admin surface frequently
erases it in two transactions.

```solidity
// RelayOracleMultisig.sol:102 / 145  (OZ-Ownable multisig, 6,892 B, v0.8.28)
function addSigner(address signer) external onlyOwner {   // no signer-count cap,
  isSigner[signer] = true; signers.push(signer);          // no consent from peers,
}                                                         // no timelock
function setThreshold(uint256 t) external onlyOwner {
  if (t == 0 || t > signers.length) revert InvalidThreshold(t, signers.length);
  threshold = t;                                          // 1 is valid
}
```

`owner()` returned `0x71d8be89…` — the same EOA that held `ADMIN_ROLE` on the oracle.
So the 2-of-3 was decorative: `addSigner(self)` → `setThreshold(1)` → sign alone.
Two transactions, one key, no other signer ever consulted.

```text
CHAIN TO TRACE whenever a grade depends on "it's a multisig":
1. threshold()                 -> e.g. 2
2. getSigners() / signers(i)   -> e.g. 3 addresses
3. owner()                     -> WHO? cross-check against every privileged EOA already
                                  known from the same system (admin, allocator owner, deployer)
4. for EVERY onlyOwner fn      -> addSigner / removeSigner / setThreshold / setGuardian /
                                  upgradeTo / transferOwnership:
                                  is multisig approval required *by the modifier*, or only by
                                  Ownable? (shared MessageHashUtils + approveHash = real;
                                  bare onlyOwner = cosmetic)
5. is owner() a signer? is owner() the ADMIN-ROLE holder?
   => threshold is cosmetic. Grade single-key custody regardless of the threshold value.
```

Correct sentence for the report: **"threshold 2-of-3, but `owner()` can add a signer and
lower the threshold in 2 tx — the threshold is cosmetic, effective custody is 1 EOA."**
Never write "protected by 2-of-3" unless `owner()` and the role-admin are themselves the
multisig or a timelock.

Getter-form note: `getThreshold()`, `signersCount()`, `required()` all reverted while
`threshold()` and `signers(uint256)` worked. Probe several name forms before declaring
the getter surface absent.

---

## 2. A ROLE CENSUS IS PER-CONTRACT — ORACLE ROLE LIVES IN THE ORACLE

A whole round censused `hasRole(ORACLE_ROLE, …)` **on the Hub** and concluded
"ORACLE_ROLE was never configured here, so the oracle module is inert". It was
configured — in `RelayOracleV2`, which is its **own** `AccessControl` instance.

```solidity
// RelayOracleV2.sol:401 -- bare `hasRole` resolves to this.hasRole, the oracle's own
if (!hasRole(ORACLE_ROLE, oracle)) revert UnauthorizedOracle(oracle);
```

```text
RULE: for every `hasRole(...)` in source, resolve WHICH contract's hasRole it is.
  inherited AccessControl in the same file   -> census that contract
  IHub(hub).hasRole(...)                     -> census the hub
  bare hasRole with no AccessControl import  -> find the base contract, then census that
NEVER carry a role census from contract A onto contract B.
```

`getRoleAdmin(ORACLE_ROLE)` also returned a **custom** admin constant
(`0xa4980720…21775`), not `DEFAULT_ADMIN_ROLE` (`0x00…00`). So look up the parent's
holder with `hasRole(0xa4980720…, x)`; do not assume `DEFAULT_ADMIN` is the parent.

Live answer that made the trust graph legible:

```text
RelayOracleV2  ADMIN_ROLE(0xa4980720…) -> 0x71d8be89… (EOA)
               ORACLE_ROLE(0x68e79a7b…) -> 0xcc60889a… (RelayOracleMultisig)
RelayOracleMultisig owner()            -> 0x71d8be89…  (SAME EOA)
```

One EOA = oracle role-admin + multisig owner + hub ADMIN + allocator owner. Draw that
convergence explicitly — the convergence is the finding, not the individual roles.

### 2a. `_executeAction` with arbitrary `from`/`to` is the oracle role's real payload

Do not stop at "the oracle can mint". Read the action dispatcher; the transfer leg is
usually strongest:

```solidity
// RelayOracleV2.sol:269-296
MINT     -> HUB.mint(hubToAddress, id, amount)                          // to: arbitrary
BURN     -> HUB.burn(hubFromAddress, id, amount)                        // from: arbitrary
TRANSFER -> HUB.transferFrom(hubFromAddress, hubToAddress, id, amount)  // BOTH arbitrary
```

The Hub's `transferFrom` if-block only *skips* the allowance debit; it never `require`s
a positive allowance, and the balance subtraction underflows to `Panic(0x11)` when funds
are missing. So an oracle-role holder moves anyone's balance directly. Phrase it as
**"ORACLE_ROLE ⇒ move any holder's Hub balance to any address"**, then grade on who
holds ORACLE_ROLE (§1's owner() check).

---

## 3. THREE POSITIVE CONTROLS THAT FAIL ON YOUR INSTRUMENT, NOT THE TARGET

Each produced a false "surface is empty" reading in one session.

```text
A) balanceOf(tokenContract) == 0 is CORRECT and proves nothing.
   A token contract does not hold its own supply. Five "unhealthy" RPCs were rejected
   for returning 0 on the token contract itself.
   FIX: balanceOf(a known holder) at a PINNED historical block. In-session the correct
   control was balanceOf(0x4cd00e38…) @ blk 96,502,503 == 10,000,000 (the deposit amount
   read straight out of the order's stateChanges), vs 0 at blk+1.

B) A getter returning 0 for a random hash is NOT evidence of "not executed".
   isExecuted(0xdead…) == 0 AND isExecuted(realKey) == 0  -> no discriminating power;
   the key you picked is simply not the one it indexes. Find the real key by event scan
   or drop the probe. Do not report the 0.

C) A getter that reverts for EVERY argument may be the wrong SIGNATURE.
   Declared `mapping(address => mapping(uint256 => uint256)) public balanceOf`
   => signature is balanceOf(address,uint256). Sending balanceOf(address) reverted for
   both the expected-populated and the random address, and read as "no allowance exists
   anywhere". Re-derive the signature from the declaration and re-run until a KNOWN
   value (60,010,002) comes back. If the known value never returns, the instrument is
   broken, not the target.
```

Nested-mapping getters are the recurring trap: `mapping(address=>mapping(address=>
mapping(uint256=>uint256)))` = three args. Count the nesting depth, then build the
calldata; never reuse a selector you already had in the script from an earlier contract.

---

## 4. TRUNCATED VERIFIED-SOURCE: the saved file is the trap

A saved `src_<name>.sol` that ends mid-contract makes every selector derived from it
wrong, and the absence of an expected function reads as "the contract doesn't have it".

```text
SYMPTOM : selectors from your saved source are ABSENT from on-chain bytecode
          (execute/executeMultiple "not in bytecode"), yet the address IS that contract
CAUSE   : the saved source was a truncated half (8,688 B saved of a 16,797 B contract)
FIX     : re-fetch and CHECK SIZE + brace balance + that EVERY function you rely on has
          its selector present in eth_getCode. Only then is the source usable as evidence.
```

The verdict can survive a truncated source and still be unsound as *evidence* — say so
explicitly ("conclusion survived independently, R42 oracle analysis invalid as evidence")
rather than silently keeping the earlier round's citations.

Corollary: `0x432994b7` was carried for several rounds as "`execute`" when it is the
**Executor** contract's selector, not the oracle's. Derive selectors per-address from
that address's own ABI/bytecode; never reuse a selector across contracts in the same
system because the name sounds the same.
