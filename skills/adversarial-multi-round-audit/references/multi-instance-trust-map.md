# Multi-Instance Trust Map — how to census, compare, and grade sibling deployments

Companion to SKILL.md pitfall 30 / 30a / 30b / 31. Read this the moment a census
prints a set with more than one element.

## Why one verdict is not enough

A campaign can spend 20+ rounds proving a signature gate is unbreakable against
**one** signer, while a sibling deployment with a **weaker** signer sits live and
unexamined. The verdict is true and the coverage claim is false. That gap is the
single most expensive failure mode in round-loop auditing: nothing errors, the
reports look rigorous, and the weakest instance is the one nobody read.

## Step 1 — census identity fields, not just entrypoints

Run `scripts/census_instances.py` against the seed contract. Identity fields that
must be enumerated as SETS (size > 1 ⇒ unaudited surface):

| field | why it matters |
|---|---|
| `to` / executor | separate `usedRequests`, `feesCharged*`, separate `HUB` immutable |
| `resolver` | may be unguarded, may hold funds, may be dead |
| `oracle` / `signer` | threshold and signer set define real forgery cost |
| `hub` | **separate balance ledger** — the biggest one; see step 2 |
| implementation | upgradeable proxies re-point trust |

## Step 2 — compare the immutables directly, don't assume sharing

```text
Executor#1.HUB() = 0xDDD361727C22A01EB137880678A20b0BEaE69318   13864 B
Executor#2.HUB() = 0x3C0be5a7F32a7dFB70C156b81eB747D0E5287F30   13507 B
```

Same 9131-byte executor runtime, same source, **different Hub**. Consequences:

- `balanceOf`, `totalSupply`, `allowance`, `orderAddress` state are **not shared**.
  A zero measured on Hub#1 says *nothing* about Hub#2.
- `usedRequests` is per-contract, so a digest consumed on A is unconsumed on B —
  but that only matters if a signer is authorised on both. Test it, don't infer it.
- A different Hub byte-length (357 B here) means a **different version**, not a
  redeploy. Treat missing functions as a version delta until proven otherwise.

**…BUT verify the delta before you name it.** After fetching both ABIs the delta
turned out to be **zero functions**: 36 functions / 8 events / 11 errors, identical
sets, identical role hashes, on both hubs. And the containment test settled what kind
of divergence it was:

```text
Hub#1 13864 B / Hub#2 13507 B
common prefix 10 B, common suffix 65 B, H2 ⊄ H1, H1 ⊄ H2
```

A 10-byte common prefix rules out "immutables-only patch" (that leaves a long shared
prefix). It also means neither build contains the other, so it is **two separate
compilations** — a source or compiler change that preserved the interface.

Therefore the honest sentence is *"interface identical (proven), runtime divergent
(measured), per-function behaviour unverified"*. Never *"Hub#2 is the older/weaker
version"* — that is a severity claim built on a byte count. Only a per-function
differential earns it.

The genuinely different observation, which **is** reportable, is per-instance state:
`totalSupply(base-USDC)` was `0x0c3181f4d1` on one hub and `0x171f31b3` on
the other, and `erc20Views(tokenId)` returned a different adapter address on each
(3874 B vs 3774 B, both with an identical `tokenId()`). Separate ledgers, separate
adapters — measure both, carry neither across.

### Getter-name trap
An immutable declared `IHub public immutable HUB` exposes `HUB()`, not `hub()`.
A reverting `hub()` reads identically to "different contract" and will send you
chasing a version mismatch that does not exist. Before concluding anything from a
revert, try: exact declared name, ALL-CAPS, `getX()`, `xAddress()`. Only then treat
the absence as real (and only with the three-confirmation drill in pitfall 24).

## Step 3 — per-instance trust matrix (the reportable artifact)

```text
                     INSTANCE A                        INSTANCE B
hub                  0xDDD3…9318 (13864 B)             0x3C0b…7F30 (13507 B)
executor             0x6747c7e6…                       0x797b3ce4eb08038256fe69bcfeec532a83e350c2
admin                0xf61a3051…                       0x71d8be89…
oracle             2-of-5 msig 0x2a72eb8c…          2-of-3 EOA 0xcc60889a…
signers            5 EOA (all codesize 0)             3 EOA (all codesize 0), 0 overlap
resolver             0xb24ac15b… (0 direct tx)         0x4cece2e5… (held funds mid-cycle)
real executions      3                                 4
```

Read the matrix, not the marketing:

- **Zero signer overlap is a genuine control.** One leaked key does not cross
  instances. Report it as isolation / blast-radius containment — a *positive*
  observation, not a finding.
- **A weaker threshold (2-of-3 all-EOA vs 2-of-5) is a config choice, not a code
  bug.** Grade it as blast radius in the report's architecture section. Only a code
  defect (zero-threshold, dup-signer acceptance, loop bound = signatureCount) is a
  vulnerability; verify the two contracts are even the same source first
  (`methodIdentifiers` set-equality, plus runtime diff limited to the EIP-712
  constants embedded by the constructor).

## Step 4 — prove the verifier is the same code before hunting its bugs

```text
artifact methodIdentifiers (15)  ==  on-chain dispatcher selectors (15)   -> MATCH
runtime live 3642 B  vs  artifact 3642 B, 22 bytes differ, all inside the
    embedded EIP-712 domain strings                                      -> identical logic
```

Set equality of selectors plus a diff confined to constructor-embedded immutables
is what licenses "same source, different args". Without it, "oracle #2 has a
different trust model" may be a claim about a completely different program.

## Step 5 — grade unguarded entrypoints on funding history, not current balance

```text
unguarded execute(): sweeps HUB.balanceOf(address(this), tokenId) -> attacker recipient
balanceOf now          : 0
receipt of real tx     : Resolver#2 -> 8,030,600,319,327,198 -> swept onward
```

`balance == 0` is a snapshot. The receipt proves the contract **does** hold value
mid-cycle. Correct grade:

> **REAL / CURRENTLY-INERT / ARMED-BY-FUNDING** — anyone can sweep any funds that
> arrive outside the normal cycle. Trigger: a direct solver transfer.

That is materially different from `DEAD-CODE` (never reachable, nothing to take).
Keep them as separate verdict labels; collapsing them either inflates a non-issue
or buries a live latent condition.

## Reading guard order across instances (cross-instance replay)

```text
replay A's calldata onto B (A's oracle)  -> UnauthorizedOracle    role gate, RelayExecutor.sol:193
swap in B's own oracle                  -> RequestExpired        deadline gate, :197
swap B's oracle back onto A             -> UnauthorizedOracle    symmetric control
```

Row 1 alone would be ambiguous (deadline long expired). Rows 1+2 prove the role
gate fires **before** deadline, so expiry never masked anything — that converts
`INCONCLUSIVE` into a structural `REFUTED`. Row 3 proves the query is sound in both
directions. See SKILL.md pitfall 19a for the general procedure.
