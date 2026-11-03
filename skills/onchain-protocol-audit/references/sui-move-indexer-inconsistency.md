# Indexer-inconsistency handling — UNVERIFIED is a fourth verdict state

Companion to `sui-move-onchain-audit.md` §5.5 (the `objects(filter:)` zero trap) and
`sui-move-arithmetic-refutation.md` §2 (the version trap). This file covers the *third* class of
"the tool gave me an answer I cannot trust" — and the reporting discipline that keeps a report
honest when the tooling is the unreliable part.

---

## 1. The symptom: the same query shape returns results for one type and nothing for another

Within a single session, against the same endpoint, with an identical selection set:

```
objects(filter: {type: "0xfbb9f951...::flp::AdminCap"})            -> 1 node  ✅
objects(filter: {type: "0xfe1d8929...::app::AdminCap"})            -> 0 nodes
objects(filter: {type: "0xfe1d8929...::app::PackageCallerCap"})    -> 0 nodes
objects(filter: {type: "0xfe1d8929...::obligation::ObligationOwnerCap"}) -> 0 nodes
objects(filter: {type: "0xfe1d8929...::market::Market<...>"})      -> 0 nodes
objects(filter: {type: "0xfe1d8929...::app::ProtocolApp"})         -> 0 nodes
```

The control type (`flp::AdminCap`, a different package) returns a result. Every type in the
lending package returns nothing — **including `ProtocolApp` and `Market`, objects that were
fetched directly by address in the same session and demonstrably exist.**

Then the address-owner form fails too:

```
address(address: "<known flp::AdminCap holder>") { objects(first: 50) { nodes { ... } } }
   -> 0 nodes          # for an address that provably holds an object
```

And a subagent reports having walked **688 owned objects** for a deployer EOA through the same
query shape minutes earlier.

**Conclusion: the indexer is inconsistent, not the chain.** A zero from this indexer is not
evidence of absence — it is evidence that *this query, for this package, at this moment*, returned
nothing.

---

## 2. The rule — four states, and UNVERIFIED is one of them

A verdict is only one of four values. Collapsing them is the failure mode:

| State | Means | Requires |
|---|---|---|
| **PROVEN** | the defect is in deployed bytecode | `file:line` + the module header line confirming the package ID |
| **REFUTED** | the defect is not there | a positive kill (absent module, zero-ability struct, guard present) |
| **UNTESTED** | not investigated | a named blocker, not "out of budget" |
| **UNVERIFIED** | **a claim exists that I could not replicate** | the claim, its source, the exact query I ran, and the result |

**UNVERIFIED is not a soft REFUTED.** It says: someone reported X; I tried to confirm X with the
obvious query and got a result inconsistent with X; I am not asserting X is false and I am not
asserting it is true. That is a real state and it belongs in the report.

Worked case: a subagent reported that the `ProtocolApp` deployer EOA
`0x6a8388e2e8602c7a945d3dc2ab8cb31a0b64c1dd08eac2269af100eabfa4887a` is a 688-object
memecoin/NFT treasury wallet holding **4× `LeverageMarketOwnerCap`** and a
`0x21d001e8...::account::AccountCap<ADMIN>`. The orchestrator re-ran the identical query and got
**0 nodes**. Neither result was discarded — the finding was published as **UNVERIFIED**, with the
operational recommendation (rotate those caps into cold/multisig) stated as conditional.

---

## 3. The control test — run it before trusting any zero

One extra query, and it decides whether a zero means anything:

```graphql
# a type you KNOW has instances, queried in the same session with the same selection set
{ objects(filter: {type: "<known-good type>"}, first: 5) { nodes { address } } }
```

- **Control returns results, target returns zero** → the zero is *possibly* real for that query,
  but it still does not establish absence. Publish **UNKNOWN/UNVERIFIED**.
- **Control also returns zero** → the indexer is broken for this package or this query shape.
  Every zero in the session is void. Say so explicitly and pivot to a different evidence source.
- **Target type ERRORS instead of returning empty** → that is a query bug, not a result. Try
  `owner { __typename }`, the bare-address form, and the control type before concluding anything.

The schema is also inconsistent *across types in the same session*:
`owner { ... on AddressOwner { owner { address } } }` succeeded for `flp::AdminCap` and errored
`Unknown field "owner" on type "AddressOwner"` for `app::AdminCap`. When one type errors and
another succeeds, the difference is in the indexer, not in the chain.

---

## 4. What to do instead when the indexer will not answer

Ranked by yield. Do not burn more than ~4 calls on any one of them.

1. **Read the object directly by address.** `object(address:){ asMoveObject{ contents{ json } } } }`
   is accurate even when `objects(filter:)` is not. If you already know an object ID, this is the
   whole answer.
2. **Read the parent's JSON for `size` and `keys.contents`.** A registry's row count and key list
   are printed in the parent payload even when the rows are not addressable (§4.2c of the recon
   file). `"groups": {"size": 15}` is real precondition evidence.
3. **Walk events.** `events(first:50, filter:{module:"0xPKG::mod"})` reconstructs state history
   when the current state is unreachable. Paginate with cursors — `first:50` silently truncates.
4. **Introspect instead of guessing.** `__type(name:"Object"){ fields{ name } }` costs one call
   and replaces six failed guesses (§7.1b of the recon file).
5. **State the blocker and move on.** An authenticated explorer API (Suiscan/Suivision key), a
   local indexer, or a walk of the creation transaction will resolve it. Name which one.

---

## 5. How to publish it

In the report's UNVERIFIED section, four lines per claim:

```
Claim:        deployer EOA 0x6a8388e2... holds 4x LeverageMarketOwnerCap + AccountCap<ADMIN>
Source:       subagent M, findings/M_postauth.md
My check:     objects(filter:{owner,type}) and address(...).objects -> 0 nodes
Verdict:      UNVERIFIED — indexer returned 0 for every lending-package type in the same
              session, including ProtocolApp and Market which I fetched directly by address.
              Not confirmed, not refuted.
Action if true: rotate those caps into cold/multisig (operational, conditional)
```

And in the CLOSED SURFACES table, mark the row honestly:

```
| Deployer-EOA admin-cap claim | UNVERIFIED | identical queries return 0 nodes (indexer
|                              |            | inconsistency); not confirmed, not refuted |
```

**Never upgrade UNVERIFIED to REFUTED to make the report look cleaner.** A refutation you cannot
demonstrate is worse than an open question, because the next session will trust it and skip the
check.
