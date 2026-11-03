---
name: hunt-target-classifier
description: "Classify any free-form hunt target into a structured spec — contract/bridge/chain/repo/domain/SPA — with chain→RPC resolution and scope extraction. Use when a target arrives as prose ('audit the relay settlement contracts'), when the agent must decide WHAT kind of thing it's hunting, or when resolving owner/repo vs domain/path ambiguity."
---

# Hunt Target Classifier

Turns a free-form target description into a **structured, actionable spec**. The hardest part isn't the LLM call — it's the deterministic disambiguation that prevents the classic traps.

## The 6 Target Kinds

| Kind | Signal | Audit path |
|------|--------|-----------|
| `contract` | `0x` address (+ optional chain) | EVM: forge build → slither → source read |
| `bridge` | bridge name / cross-chain mention | Cross-contract: both sides + msg verification |
| `chain` | RPC URL or chain ID | Node audit: namespace census, admin leak |
| `repo` | `owner/repo` or git URL | Source audit: clone → static → dynamic |
| `domain` | hostname / URL | Web audit: recon → probe → verify |
| `dir` | local filesystem path | Local audit: jail-bound, read-only |

## Trap 1 — `0x` address is NOT a hostname

The scope gate matches hostnames. A bare `0x…` in the hosts list gets treated as an unresolvable host and **every request to the real RPC host is judged out-of-scope**. Rule: strip scheme, split on `/`, then filter with a full regex match against the address pattern — addresses go to `addresses`, only true hostnames go to `hosts`.

```python
hosts = [
    h for h in (re.sub(r"^https?://", "", rpc).split("/")[0] if rpc else "", *extra_hosts)
    if h and not _ADDRESS_RE.fullmatch(h)
]
```

## Trap 2 — `owner/repo` vs `domain/path`

Both are `a/b`. Heuristic chain (deterministic, before any LLM):
1. Scheme present → domain.
2. Exactly 2 parts, neither contains a dot as TLD marker → looks like owner/repo.
3. Part 0 looks like a domain (has dot + known TLD) → it's a domain, not a repo.

## Trap 3 — local vs remote

`dir` targets resolve inside a **jail** (state dir + local_root). A single root keeps the old `Path` contract for direct comparison; multiple roots wrap in a multi-root object. Relative paths resolve against the FIRST jail root only — document this, it bites operators.

## Chain → RPC table

Free-form "audit on mainnet" must map to a concrete RPC. Keep a curated table (chain name → public RPC + chain ID) and let the LLM pick the chain, then resolve the RPC deterministically. Never let the model invent an RPC URL.

## Manifest shape (what downstream expects)

```python
{
    "name": f"contract-{address[:10]}-{chain_id}",
    "hosts": [...],          # hostnames only, deduped
    "addresses": [...],      # 0x addresses, separate
    "kind": "contract",
    "chain_id": 1,
    "rpc": "https://...",
}
```

## Resolution order (deterministic first, LLM last)

1. Regex salvage: address? RPC? git URL? hostname? — extract what's parseable.
2. Deterministic classification of the residue.
3. Only for genuine ambiguity (prose like "audit the relay settlement contracts locally") call the LLM with a strict schema.
4. Log the LLM decision — `logger(f"LLM parsed contract target {addr} on chain {chain} via {rpc}")`.

## Trigger phrases
- "audit the X contracts" (prose target)
- "ini target-nya apa?"
- agent confused contract vs domain vs repo
- building target intake for any hunting agent

## Reference implementation
`target_classifier.py` (deterministic classification + contract family grouping) and `target_resolve.py` (LLM-assisted resolution, chain→RPC table, regex salvage) from the HunterOsHarness engine.