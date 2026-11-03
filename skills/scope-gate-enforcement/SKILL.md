---
name: scope-gate-enforcement
description: "Enforce fail-closed scope boundaries on any hunting agent — validate every target against allowed hosts/domains before any request is sent. Use when building a hunt engine, when an agent talks to out-of-scope targets, or when you need structural (not advisory) scope enforcement."
---

# Scope Gate Enforcement

The difference between a security scanner and a weapon: a scope gate that **fails closed**. Advisory scoping (warnings, `-F` flags) doesn't count — the agent will ignore it. The gate must structurally prevent any request to an out-of-scope host.

## The Gate Contract

```python
class ScopeGate:
    allowed_hosts: set[str]          # the allowlist
    allowed_chains: set[int]         # chain IDs (only for chain targets)

    def allows_target(self, host: str) -> bool:
        """Return True if host is within any allowed host."""
        # Fail closed: a child task inherits the parent's hosts
        # and scope IS the budget — don't expand, don't warn, block.
        if not self.allowed_hosts:
            return False  # empty allowlist = nothing in scope
        return any(self._matches(host, allowed) for allowed in self.allowed_hosts)
```

## The 0x address trap

A bare `0x` contract address must NEVER be treated as a hostname. When building the hosts list for scope validation, strip addresses with a full regex match FIRST:

```python
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
hosts = [h for h in raw_hosts if not _ADDRESS_RE.fullmatch(h)]
```

An `0x...` in the hosts list → the gate treats it as an unresolvable host → every request to the real RPC endpoint is judged out-of-scope. **Addresses go to `addresses`; hostnames go to `hosts`. Never mix them.**

## Scope inheritance

A child task inherits the parent's scope. A hunt against `example.com` spawns a child — the child can only probe `example.com`. Expanding scope mid-hunt is forbidden.

## Local root scope

For file-based audits, the scope is a jail. A path is in scope ONLY when it resolves inside one of the configured jail roots. Multiple roots are supported (state dir + local_root). Absolute paths are NOT automatically escapes — they're resolved and re-checked against the jail list.

```python
resolved = Path(raw_path).resolve()
if not ctx.scope.allows_local_root(resolved):
    return Blocked("search.jail_violation")
```

## The hard rules

1. **Empty allowlist = nothing in scope.** Always.
2. **`0x` addresses are NOT hostnames.** Filter them first.
3. **Children inherit parent scope.** Never expand.
4. **Scope is structural, not advisory.** Block at the gate, don't warn.
5. **Fail closed.** Any ambiguity → blocked.

## Checklist — before any hunting agent goes live

1. [ ] Every target validated against the allowlist before ANY request?
2. [ ] Addresses and hostnames are separate lists — never mixed?
3. [ ] Scope is inherited, not expanded, for child tasks?
4. [ ] Local path resolution is jail-bound (multiple roots)?
5. [ ] Empty allowlist → denies everything (fail closed)?

## Trigger phrases
- "scope gate"
- "out-of-scope target"
- "agent probing wild targets"
- "fail closed scope enforcement"
- building any hunting agent

## Reference implementation
`scope.py` (fail-closed structural scope enforcement with host allowlist, code-based scope, and jail-bound local root resolution) from HunterOsHarness.