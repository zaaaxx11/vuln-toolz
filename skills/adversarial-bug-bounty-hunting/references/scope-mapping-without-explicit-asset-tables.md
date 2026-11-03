# Scope mapping — when the program has NO in-scope asset table

## The trap

You expect the OpenZeppelin/Immunefi shape: a table of contract addresses
marked "in scope". Many programs — especially those that own their whole stack
— publish the **inverse** instead. Relay's bounty page (`docs.relay.link/security/bounties`,
rev 2026-10-19) states scope as a principle:

> "This framework applies across Relay's **protocol and services**.
> Relay Vaults is a separate protocol and is **not covered** by this program."

There is **no in-scope asset list anywhere on the page.** Scope is defined by
**exclusion**, not enumeration. Grep for `in scope` returns nothing; the only
explicit asset names on the whole page are the ones being *excluded*.

If you answer "here are the in-scope assets" by inventing a table, you have
fabricated a finding. Say the table does not exist, then derive the boundary.

## Protocol: derive scope from three sources, in this order

1. **The bounty page** — the exclusion list, the payout matrix, PoC
   requirements, eligibility gates. Read the `.md` source (see
   `docs-extraction-and-scope-mapping.md`).
2. **The trust-model / security page** — this is where the *actual attack
   surface* is described even though it never says "in scope". Look for
   headings like `Trust Model`, `Depository`, `Oracle`, `Hub`, `Allocator`,
   `Security Council`. Every component with a trust property described is a
   hunting target.
3. **The addresses page + a live API** — turns abstract components into
   concrete, verifiable targets.

**Step 3 is the one that pays.** The docs said "80+ Depository contracts".
The live chain API gave the exact number:

```bash
curl -sL "https://api.relay.link/chains" -o chains.json   # 160 KB, HTTP 200
python3 -c "
import json; from collections import Counter
ch = json.load(open('chains.json'))['chains']
print('total:', len(ch))
print(Counter(c['vmType'] for c in ch))"
# total: 59  -> {'evm': 50, 'svm': 2, 'lvm': 2, 'bvm': 1, 'tonvm': 1, 'hypevm': 1, 'tvm': 1, 'xrpvm': 1}
```

Now "80+ depositories" is an auditable inventory with VM breakdown, and
`depositAddressEnabled` (55/59) tells you which chains have the richer surface.
**Cite the API call and the count you computed** — that is PROVEN, where the
doc's "80+" is marketing rounding.

## Classify every exclusion by its *practical* meaning

A bare list of "not eligible" items is not useful to a hunter. Translate each
into what it forbids you to do:

| Exclusion (verbatim shape) | Practical meaning |
|---|---|
| "Attacks the reporter has already exploited" | Never touch live funds. PoC on fork/localnet only. |
| "Phishing / social engineering / compromised key" | No human-layer attacks. |
| "Third-party protocols we compose with, unless root cause is in our code" | **Read the conditional** — a bug *in the integration code* is still in scope. This is often where the real find is. |
| "DoS with no fund loss and no path to fund loss" | Pure griefing is dead. Need a fund-loss path. |
| "Theoretical issues with no viable PoC" | Theory alone is rejected. |
| "Product X (whole product, listed by contract name)" | Hard exclusion — even if the vendor audits it and links the audit report from their own security page. **Cross-links mislead.** |

## The hidden exclusions — read the matrix footnotes, not just the "out of scope" heading

These disqualify reports without appearing under the out-of-scope heading:

- **Admin-only functions are capped, and often not eligible at all.** Relay:
  functions behind `onlyOwner`/role are S1 *max*, and a report is **not
  eligible** if the only path needs a privileged role (owner/operator/solver/
  oracle) and you can't show an unprivileged party can reach or induce it.
  Always check whether the program caps privileged-role bugs.
- **Bugs that don't fire under normal operation** — same clause family.
- **Duplicates** — first submission wins, no automatic reward. **Dated**
  internal records beat you; raw scanner output does *not* count as
  "previously known".
- **Config-dependent bugs** — if the config is live in production it's real;
  if only theoretical, likelihood drops to L1.

## Convert scope into a hunting priority — do the math on the matrix

Do not hand over a flat asset list. Rank targets by **expected payout**, which
is `severity ceiling × realistic likelihood × modifiers`. Relay's worked
example: a `execute`-path signature replay is S4 (drain-all) × L2 (needs
setup) = $50k base, ×1.5 unrecoverable = **$75k**, capped at $100k. A fee
rounding drift is S2 × L3 = $10k, then ×0.5 bounded ×0.75 pausable = **$4k**.
Same effort class, 25× the payout. Aim at the former.

**A signal worth acting on:** where the repo ships a focused test suite for a
module (`RelayUsdRateLimiter`, `RelayBpsFeeCalculator`, `SignedPricingOracle`,
`GenericMapping`, `RelayMultisigSigner`), the developers have already thought
hardest about that module. Dense assumptions = dense places for an assumption
to be wrong. High-likelihood targets sit there even when severity is capped.

## Reporting the scope map — the honesty shape

Deliver, in this order:

1. **State plainly that no explicit in-scope asset table exists**, quoting the
   sentence that defines scope instead. Give the doc revision date.
2. **In-scope map**, split into: on-chain contracts (with addresses + chain),
   components-by-trust-property, source-code repos (with pinned commit), and
   services/hosts.
3. **Out-of-scope list**, verbatim items, each translated to practical meaning.
4. **Hidden exclusions** the matrix implies but the heading omits.
5. **Eligibility rules** that gate payment (KYC/KYB, payment channel, PoC bars
   per severity, duplicate/known-issue policy) — with the caveat that policy
   clauses may carry *effective dates* ("applies to reports submitted on or
   after…"), so read which version binds you.
6. **Payout-ranked target order** so the hunt has a plan, not just a list.

End with a status table separating what is PROVEN (page read, API returned N
chains, address list fetched) from what is UNPROVEN (any actual bug — no code
read yet). A scope map is not a finding.
