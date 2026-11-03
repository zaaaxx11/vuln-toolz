# UNAUDITED-SURFACE hunting — finding a genuinely NEW bug in a partially-audited repo

Condensed from a round hunting "one genuinely new bug" in the *remaining*
unaudited surface of a partially-audited Solidity protocol (payload builders,
allocator payload path, view/accounting contract, ECDSA/permit handling).
The scope shape — "everything already known is off-limits, find something
new" — has its own failure modes and its own definition of done.

---

## 1. The definition of done

A "new" bug is only reportable if you can state, in one sentence, **what the
victim loses and who gains it.** If you can't, you have a mechanism, not a
finding. This session produced four mechanisms that dissolved on inspection
and one that survived; the four are as valuable as the one, but only if you
write down why they died.

Keep a running ledger with three columns: *hypothesis · verdict · why*.
Every dead lead goes in it. This is what stops you re-deriving the same
disproof in round six.

## 2. Ordering: reachability before depth

Before reading a single line of the unaudited contract, ask **is it live?**

Partially-audited repos routinely ship contracts that are never registered,
never granted a role, never wired into the production deployment. A five-minute
census (see `onchain-protocol-audit` →
`references/live-reachability-and-hash-divergence.md` §12.1) reclassifies your
findings from "Critical" to "latent" honestly and up front, instead of
discovering it under triage pressure.

Do this first, not last. If the surface isn't live, still hunt it — but label
it latent from the first sentence of the write-up, and say which deployment
*would* expose it.

## 3. Prioritise the live surface, then the inherited guards

Rank candidates by *how much other code trusts them*, not by how unusual they
look. Guards that are `internal` and mixed in via a base contract
(`_requireGasPaid`, `_onlyApproved`, `_checkDeadline`) are trusted by every
inheritor, so a flaw there multiplies. This is how the session's surviving
finding was located: a base-contract policy key, not a VM-specific serializer.

## 4. Prove with two requests that differ in exactly one field

The canonical PoC shape for an unbound field:

```
r1 := (all fields identical to the victim's)
r2 := r1 with ONLY the disputed field changed  (here: spender)
assert policyKey(r1) == policyKey(r2)   // guard is bypassed
assert dedupKey(r1)  != dedupKey(r2)    // dedup cannot catch it either
```

If the second assertion is *equal*, the bug is not the one you think — the
request would be a replay and the existing guard handles it.

**Harness trap that cost several rounds:** the test's request-nonce helper was
keyed on the spender. That made `r1` and `r2` diverge in a *second* field, the
policy keys stopped matching, and the guard fired with a protocol-named error
that looked like "the bug isn't there." Build nonces/ids deliberately
**spender-independent** when the spender is the field under test. Generalise:
the only field allowed to differ between your two requests is the one you are
testing.

## 5. Independent arbiter, not self-consistency

Serializer/hash tests written against the same Solidity that produced the value
prove only self-consistency. When the claim is "this digest commits to the
wrong thing", reimplement the serializer in Python (Keccak via pycryptodome,
`hashlib`/`cryptography` for the rest) from the *specification*, and compare.
A test that passes both directions is still only a serializer round-trip; it
does not establish that the serialized content is the intended content.

## 6. Closure checks — cheap disproofs, run them first

Each of these killed a lead in one step and should be a reflex:

- **Unbounded fee / unbounded amount?** Grep for the bound *and the
  post-condition that ties it to what was actually paid*
  (`if (fee > paidAmount) revert FeeExceedsPaidGas`). A constant cap plus a
  paid-amount tie means the "no bound" hypothesis is dead.
- **`permit`**: single implementation, deadline checked, per-owner nonce inside
  the digest, nonce incremented, `_hashTypedDataV4` domain separator. All yes ⇒
  clean.
- **ECDSA malleability**: OZ ≥ 4.7 `tryRecover` returns `InvalidSignatureS` for
  high-S. Confirm every site checks `NoError`/uses `recover`, and that no
  nonce is keyed on `s`. A two-test probe settles it.
- **Attacker-configurable adapter/view**: grep *every writer* of the mapping.
  Only writer is an internal `_create*` called from a mint path ⇒ bounded, say
  so and move on.
- **Field "not in the signed struct"**: trace it *forward* through every
  derivation into the final preimage. `data` → `queryId` → signed cell means
  it IS covered (lossily). Only fields that die in the derivation are unbound.
- **`dataHash == 0`**: usually the documented inline-data sentinel, substituted
  at hash time. Read the substitution before flagging.

Reporting these as *explicit negative results* is part of the deliverable — it
tells the reviewer what you covered and saves the next auditor the round.

## 7. Severity framing for cost-externalisation bugs

Non-principal-theft defects get overgraded constantly. Ask:

- Whose balance is debited? (Here: each party's own `amount` came from their
  own alias — so *not* theft.)
- What does the attacker actually obtain? (A withdrawal processed without
  paying its network fee; the shared reserve eats it.)
- Is it capped? Is it repeatable? (Per-request cap; repeatable per victim
  payment.)
- Does it defeat the purpose of a named control? (Yes — the prepayment
  contract.)

That combination is **Medium**: repeatable cost externalisation that nullifies
a purpose-built control. Say "fee externalisation, not principal theft"
explicitly so the triager can't grade it up or down by guess.

## 8. Deliverable hygiene

- Every claim carries `file:line` on the *defective* line, not the function.
- Include the two-hash / two-key table when the bug is a coverage asymmetry —
  it is the fastest way to make the reviewer see it.
- One red test invalidates the write-up. If a decode/fixture test won't go
  green, either fix it or delete it and cite the hand-verified result. Never
  ship a failing test alongside a "PROVEN" finding.
- State live vs latent per finding, with the census numbers that justify it.
