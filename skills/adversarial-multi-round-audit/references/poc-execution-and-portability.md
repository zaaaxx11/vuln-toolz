# Writing PoCs that survive a strict ledger's own re-execution

Companion to `references/hunt-os-ledger-operations.md`. That file covers the ledger
mechanics; this one covers what happens the moment you hand a PoC to the ledger —
because `hunt poc run` re-executes your script in **its own interpreter**, and a
locally-passing PoC can arrive as `BLOCKED: poc run failed with exit 1`.

## 1. "Existence is not execution"

```
BLOCKED: this PoC has never been executed — existence is not execution
```

`hunt finding promote` requires a PoC **path**, but a path is not a run. The gate
passing order is:

```bash
hunt poc run --id <int> --poc-path <file> --timeout <s>   # must be exit=0 FIRST
hunt finding promote --id <int> --evidence-ref "<ref>" --poc-path <file>
```

`hunt poc run` prints `poc run recorded: exit=0 sha256:xxxxxxxxxxxx` on success. That
sha is the artifact the ledger will re-check — copy it into the `--evidence-ref` string
so the finding carries its own provenance. If `poc run` returns
`BLOCKED: poc run failed with exit 1 — a failed PoC is evidence of nothing`, the
finding cannot climb, no matter how good the reasoning is.

## 2. The PoC is executed in the HUNT-OS venv, not yours

`~/.HunterOS/venv` is an isolated venv. It **shadows `python3` on `PATH`** once you've
prepended `~/.HunterOS/venv/bin`, and it does **not** ship the crypto libraries your
scripts probably import (`eth_utils`, `eth_account`, `eth_abi`, `pycryptodome`).

Consequence: the script passes when you run it with `/usr/bin/python3` and exits 1
inside `poc run`. This masquerades as "my PoC is wrong" and burns a cycle hunting a
logic bug that does not exist.

**Make PoCs interpreter-independent instead of pinning an interpreter.** Two swaps
remove the whole dependency class:

```python
# instead of: from eth_utils import keccak
from Crypto.Hash import keccak as _k
def keccak(b):
    h = _k.new(digest_bits=256)
    h.update(b if isinstance(b, bytes) else b.encode())
    return h.digest()

S = lambda s: '0x' + keccak(s)[:4].hex()   # selector helper, same call shape as before
```

`pycryptodome` is pure-python-installable and tiny; install it into the HUNT-OS venv
once with `~/.HunterOS/venv/bin/python -m pip install pycryptodome eth-account -q`
(note: on some installs the venv `pip` shim is broken — call `python -m pip`, which
is the reliable form anyway).

Verify the port with a known constant before trusting a run:

```python
assert S('hasRole(bytes32,address)') == '0x91d14854'
assert S('transfer(address,uint256)') == '0xa9059cbb'
```

**Rule:** a deterministic `assert` on a published selector is the cheapest possible
proof that the keccak path works in *this* interpreter. Put it at the top of the PoC.

## 3. Keep the PoC runnable by `/usr/bin/python3` too

Don't "fix" portability by hardcoding one interpreter — that breaks the other. The
keccak swap above means the same file runs under every venv on the box. That is the
goal: **one file, no interpreter assumptions.**

## 4. PoC self-report structure: numbered claims with PASS/FAIL, exit code drives the gate

The ledger's gate is the exit code, so structure the script around it:

```python
results = []
def ck(cid, desc, cond, detail):
    results.append((cid, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {cid}  {desc}\n        {detail}")

ck('C1', 'target has >=50 tx of the selector', len(txs) >= 50, f"found {len(txs)}")
...

passed = sum(1 for _, c in results if c)
print(f"\n=== HASIL: {passed}/{len(results)} PASS ===")
sys.exit(0 if passed == len(results) else 1)
```

Why this shape and not `assert`:

- Every claim prints on **both** branches, so a failure tells you *which* claim broke
  rather than dying at line 40 with a traceback.
- The detail line carries the observed value, so the transcript is evidence, not just
  a verdict.
- Partial passes are visible. A 6/7 run is a diagnosis; a traceback is not.

## 5. A PoC that passes but whose claim is wrong is worse than a failing one

Twice in one session a PoC reached green while still printing an unsupported claim in
its final banner and docstring. That is the most dangerous output a PoC can produce,
because the ledger records it as evidence.

**Fix on every disproof:** when you discard a sub-claim, edit **three** places —
the docstring, the check that encoded it, and the final `print()` summary line. Grep
the file for the discarded term afterwards:

```bash
grep -n "XERC20" poc_f3.py     # must return nothing, or only the "DISCARDED" note
```

Prefer a positive check that records the disproof explicitly:

```python
ck('C5', 'XERC20-owner claim DISCARDED (Hub source has no lockbox)', True,
   "source audit: only erc20Views/tokenMetadata/balanceOf/allowance/totalSupply/nonces")
```

A `PASS` line whose text says "DISCARDED" documents the correction in the artifact
itself, which is exactly what a later reader needs.

## 6. PoC that refutes the finding still exits 0

Some findings are best closed by a PoC that proves the *absence* of the attack. That
is legitimate and should be recorded — but name it honestly in the final line:

```
PoC F-4 LULUS-REFUTED: resolver has no role, no balance, execute() can only sweep its own holdings.
F-4 = ARMED-BUT-EMPTY (bukan vulnerability).
```

Then **do not promote it as a vulnerability** — retitle the finding so the ledger's
title matches the conclusion (`hunt finding retitle --id N --title "..."`), otherwise
`hunt status` keeps displaying a loud claim for something you just disproved.

## 7. Retitle is bookkeeping, not evidence

`hunt finding retitle --id <int> --title "<new>"` fixes a mangled or now-wrong title.
It does **not** change status, and it is blocked on `overturned`/`archived`. So:

- Disproved a sub-claim but the finding still stands → **retitle** (remove the claim).
- Disproved the whole finding → **`overturn --id <int> --by "<falsifier met>"`**, not retitle.

Every promoted finding should have a title that states only what the PoC actually
proved. Titles drift from bodies constantly; check them after any partial disproof.

## 9. Multi-word `data` fields: count indexed params before parsing

When a decoded log/struct yields an absurdly large amount (`10⁷⁶`, `10⁷⁷`), the
parser is wrong — not the contract. Hashes and pointers decode to uniformly huge
integers and masquerade as amounts.

```python
# derive the data-word count from the ABI, never assume
ev = next(e for e in abi if e["type"] == "event" and e["name"] == "Executed")
n_indexed = sum(1 for i in ev["inputs"] if i.get("indexed"))
expected = len(ev["inputs"]) - n_indexed          # 6 params - 3 indexed = 3 words
assert len(log["data"]) // 64 == expected, "layout wrong — dump raw before parsing"
```

Full worked example + the absurd-magnitude tripwire live in
`references/abi-and-field-verification.md` Rule 13.

## 9b. Foundry/Solidity PoCs: checksum the addresses BEFORE writing the logic

Solidity ≥0.8 rejects any address literal that is not EIP-55 checksummed. Copy-pasting
lowercase addresses from `cast`/explorer output produces a wall of compile errors and
**zero tests run**, which is the expensive part: you lose the whole PoC cycle to a
formatting issue.

```text
Error (9429): This looks like an address but has an invalid checksum.
Correct checksummed address: "0xDd7d96282B7FdA7c83ACA1ed8d09733Ad51CaA09".
```

Rules:

1. **Generate the literals, never hand-copy them.** Normalise every address through a
   checksum function before it enters the `.sol` file:

   ```bash
   cast to-check-sum-address 0xddd361727c22a01eb137880678a20b0beae69318
   # -> 0xDDD361727C22A01EB137880678A20b0BEaE69318
   ```

2. **Or sidestep it entirely**: declare addresses as `address constant X = address(0x...)`
   lowercase inside a `function`, or store them as `uint160`/`bytes20` and cast. The
   compiler only enforces checksums on bare `address` literals.

   ```solidity
   address constant HUB_L = 0xddd361727c22a01eb137880678a20b0beae69318; // REJECTED
   function hub() internal pure returns (address) {
       return address(uint160(0xddd361727c22a01eb137880678a20b0beae69318)); // accepted
   }
   ```

3. The error names the **correct** checksum in the message. Batch-fix by extracting every
   `Correct checksummed address: "0x…"` line from one compile run rather than fixing them
   one at a time.

4. Related Foundry friction worth pre-empting in the same pass:
   - `vm.createSelectFork("<rpc>")` in `setUp()` must point at an RPC that actually
     serves the target chain — a hub's own RPC (not publicnode) for hub contracts.
   - A repo-level `forge build` failure from missing `lib/`/`node_modules` does **not**
     block a standalone PoC directory with its own deps; keep PoCs in their own
     `poc_x/` with `foundry.toml` + `lib/forge-std`.
   - `vm.prank(addr)` only affects the **next** call. A PoC that pranks once and then
     makes three calls silently runs two of them as the test contract.

5. Verify the PoC compiled **and** ran, separately — `forge build` succeeding is not
   evidence. Quote the `[PASS]` lines with gas, e.g.:

   ```text
   [PASS] test_B_oracle_moves_balance_without_allowance() (gas: 83385)
   ```

   No `[PASS]` line ⇒ no PoC. A compile error is `UNPROVEN`, never "the exploit is real
   but I couldn't test it".

## 10. Controls must be able to fail (tautology audit)

Before recording a PoC, grep its `ck(...)` lines and ask of each one: **what
observation makes this FAIL?** Any line that cannot fail is decoration, and it
inflates the pass count into a number that overstates the evidence.

```bash
grep -n "ck(" poc.py | grep -E ", True,|True\)$"    # candidates for tautology
```

A claim like *"candidates could not be verified (addresses truncated)"* passed as
`True` is not a control — it is an admission that the check was never performed.
Write it as `False`/INCONCLUSIVE or delete it. The transcript that carries it is
weaker than one with an honest 12/13.

## Final gate

`hunt finding add <target_id> <title> <klass> --severity <s> --falsifier "<...>"` —
the falsifier is what a future session (or an adversary role) will try to satisfy.
`hunt brief` prints it beside every finding. A finding added without one cannot be
cleanly attacked later, so write it while the hypothesis is fresh.

`--klass` is closed vocabulary (`hunt klass list`): `Access, Arithmetic, ExternalCall,
Logic, Oracle, Reentrancy, Sig, Upgradeable, Web2, Unknown`. Crypto/signature-path
findings belong on **`Sig`**; a `--klass design` returns
`BLOCKED: unknown klass 'design'` and the guidance to insert as `Unknown`.

`--surface` and `target_id` are **integers**, not names/strings. Passing a dotted
function path to `--surface` yields `invalid int value`.

## 11. Refuting a finding is a first-class outcome

A finding closed by a PoC that proves the *absence* of the attack is worth as much
as a positive one — and it must go through the same ladder:

```bash
hunt poc run     --id <int> --poc-path poc_fN.py --timeout 250    # exit=0
hunt finding overturn --id <int> --by "<falsifier met, with observed numbers>"
```

Use `overturn`, **not** `promote`, when the PoC disproves the claim. `promote`
would climb the evidence ladder for something you just killed. The `--by` string
should carry the measured numbers so a later reader does not have to re-run:

```
poc_f8.py 6/6 PASS: 7/7 Executed events nyata punya orderBalance==withdrawAmount==100000
(excess=0); Executor saldo 0 untuk 3 tokenId nyata; kontrol positif VICTIM balance
2498465619154662818 terbaca.
```

Also retitle if the title carries a claim you discarded — see §7. A ledger row
whose title says "XERC20 owner" while the body says "claim discarded" is a lie
that `hunt status` will happily show to the next session.

## Final gate
