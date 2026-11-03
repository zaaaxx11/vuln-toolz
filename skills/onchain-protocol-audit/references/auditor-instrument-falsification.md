# Falsifying your own instrument BEFORE reporting a finding

> **Gate for every mint/burn/supply finding** (also applies to any balance/accounting invariant).
> Five checks: `forge inspect` storage layout (never guess), decode events from the compiled ABI,
> assert log coverage reaches the tip, enumerate holder sets (never filter), and verify the
> arithmetic is self-consistent before blaming the contract. `onlyRole`-gated privileged paths are
> **HIGH, not Critical**. Slots, formulas and the Foundry fallback below.

Distilled from a RelayHub (ERC6909 mint/burn/supply) audit where **every single candidate finding
started life as a bug in the auditor's own measurement**, not in the contract. Four separate
"confirmed" bugs were self-refuted. Use this checklist before writing any finding up.

## The core failure mode
Live-chain audits invite confident claims built on: guessed storage slots, guessed event layouts,
partial log history, and filtered holder sets. Each of those silently manufactures a *supply
mismatch / orphaned balance / lost funds* story that reads perfectly and is entirely fake.

## Mandatory falsification round (run on EVERY candidate finding)

### 1. Storage layout: never guess, always extract
```bash
forge inspect <Contract> storage-layout
```
Guessed slots produce tests that "prove" nothing. In this session `balanceOf`/`totalSupply` were
assumed at 5/6 and are actually at **4/6** (`erc20Views=8`). Every `stateOverride` test built on the
wrong slots was invalid and had to be re-run.

If you must hand-compute (OZ AccessControl style):
```
roleSlot    = keccak(abi.encode(ROLE_BYTES32, uint256(0)))
hasRoleSlot = keccak(abi.encode(account, roleSlot))
```
Then **verify against live state** — a correct formula makes a known role holder read `0x…01`:
```python
eth_getStorageAt(hub, hex(hasRoleSlot), "latest")  # expect ...0001 for a real holder
```
That single check is what separated a real proof from four wrong ones this session.

### 2. Event layout: decode from the compiled ABI, not from signature guesses
ERC6909 `Transfer` here is `Transfer(caller /*data*/, from /*topic1*/, to /*topic2*/, id /*topic3*/,
amount /*data*/)` — three indexed args plus two data words. Guessing "id in data word 0" gave
perfectly plausible token ids whose balances all read 0.
```bash
python3 -c "import json;d=json.load(open('out/X.sol/X.json'));\
print([(a['name'],[i['indexed'] for i in a['inputs']]) for a in d['abi'] if a['type']=='event'])"
```

### 3. Log coverage: assert the range, don't assume it
The harvester silently stopped at block **328,909** of a **6,158,953** tip — 5% of history. The
"missing supply" was entirely un-pulled mints.
```python
assert max(log_blocks) >= tip - 100, "INCOMPLETE HISTORY — no conclusion allowed"
```
Always print `min(block)..max(block)` vs tip next to any invariant claim. If it fails, the finding
is dead, not "promising".

### 4. Holder sets: enumerate, never filter
A `if net_delta != 0` filter silently dropped the one real holder, manufacturing a
"totalSupply>0 with ZERO holders" impossibility. Build the address universe from *all* addresses
appearing in that id's logs (`from`, `to`, and any address-shaped data word), including net-zero ones.

### 5. Invariant math sanity
Before calling `totalSupply != ΣbalanceOf` a bug, ask "could my numbers even be self-consistent?"
Here `totalSupply` (5.796e21) exceeded the sum of *every mint I had* (3.43e20) — the arithmetic alone
said "you are missing data", before any external check.

## Severity honesty rules learned
- `onlyRole(OPERATOR_ROLE)` on the privileged primitive + no unprivileged caller path ⇒ **HIGH
  role-gated, NOT Critical**. Do not inflate to Critical because the impact is permanent.
- "Entire balance" sweeps (`balanceOf(address(this), id)`) look like a shared-pot drain but are
  usually self-clearing: verify by reading the actual live balance of the contract. Ours was **0** —
  the finding was parked as UNPROVEN rather than reported.
- Distinguish **unvalidated input accepted** (real, e.g. `_mint(receiver==address(0))` with no zero
  check) from **reachable by an attacker** (needs oracle signature). Say both things.

## Fastest path to an *executable* proof
When live `eth_call` is blocked (RPC allowlisting `from` addresses, "Contract creation is only
allowed from allowed addresses"), stop fighting the RPC and move to Foundry with the verified
source, which was **byte-identical** to the deployed bytecode:
```bash
diff <(curl -s .../smart-contracts/$ADDR | jq -r .source) contracts/X.sol   # confirm identity first
forge test --match-contract <Test> -vv
```
A passing/failing local test on identical source outranks any amount of `eth_call` hand-waving.

## Reporting shape that survived scrutiny
Show the refuted hypotheses in the final report (a table), with the exact evidence that killed each.
An audit that only lists wins reads as unverified; the refutation log is what makes the one real
finding credible.
