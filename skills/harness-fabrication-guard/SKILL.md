---
name: harness-fabrication-guard
description: "Guard an agent harness against fabricated findings — the evidence-or-nothing enforcement layer. Use when a hunt/agent reports findings, when you must verify a claim isn't invented, when promotion requires proof, or when building a security agent that must never claim a vulnerability without evidence."
---

# Harness Fabrication Guard

The #1 failure mode of autonomous security agents is **fabricating findings**. This skill enforces the evidence-or-nothing discipline extracted from a production hunt engine (HunterOsHarness). Five rules make fabrication structurally impossible — not just discouraged.

## The Five Evidence Rules (E1–E5)

Every finding must pass ALL five before it can be promoted. A single failure = the finding stays a candidate.

| # | Rule | Gate | Blocks |
|---|------|------|--------|
| E1 | **THEORETICAL → CANDIDATE** | requires ≥1 evidence ID | "I think there's a bug" |
| E2 | **CANDIDATE → VERIFIED** | requires PoC artifact on disk | "trust me, it's real" |
| E3 | **VERIFIED → PROVEN** | requires independent confirmation | self-confirmation |
| E4 | **status change** | requires `poc_path` / `logs_path` when claimable | proof-less promotion |
| E5 | **monotonic** | status can only move forward | downgrading to hide failure |

## Implementation — the ClaimGate

The core is a `validate_status_change()` function. Its logic (portable to any language):

```python
def validate_status_change(current, new_status, evidence_count, poc_path=None, logs_path=None):
    # E1: promotion requires cited evidence
    if current == THEORETICAL and new_status == CANDIDATE:
        if evidence_count < 1:
            raise Blocked("THEORETICAL→CANDIDATE requires >=1 evidence")
    # E4: verified/proven promotion requires artifacts
    if new_status in (VERIFIED, PROVEN) and not (poc_path and logs_path):
        raise Blocked("promotion requires poc_path AND logs_path on disk")
    # E2: candidate→verified needs a real PoC file
    if current == CANDIDATE and new_status == VERIFIED:
        if not poc_path or not _file_exists(poc_path):
            raise Blocked("CANDIDATE→VERIFIED requires a PoC artifact on disk")
    # E3: verified→proven needs independent confirmation marker
    if current == VERIFIED and new_status == PROVEN:
        if not _has_independent_confirmation():
            raise Blocked("VERIFIED→PROVEN requires independent confirmation")
    # E5: no going backwards
    if _rank(new_status) < _rank(current):
        raise Blocked("cannot downgrade a finding")
    return True
```

## Supporting Guards

### 1. Redaction — never leak secrets into findings
Before any finding is emitted, scrub it:
- AWS keys (`AKIA[0-9A-Z]{16}`)
- JWTs (`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)
- ETH private keys (64-hex)
- Bearer tokens, mnemonic phrases, `sk-`/`sk_live_` keys
- Connection strings (`postgres://`, `redis://`, `*.up.railway.app`)

### 2. Scope gate — fail closed on out-of-scope targets
A target is in-scope ONLY if it matches the host allowlist. Any mismatch = blocked, not warned. The gate must never resolve a bare `0x` address as a hostname (that's the classic escape).

### 3. Budget governor — runs can't run away
Track iteration + cost + wall-clock. Warn at 70/85/95% of budget; hard-stop at 100%. No unlimited runs.

### 4. Zombie reaping — dead daemons can't fabricate
A daemon is reaped only when its state dir is GONE or no valid `pid.json` backs it. Live dirs are never touched.

## Checklist — before trusting any finding

1. [ ] Does the finding cite ≥1 evidence ID? (E1)
2. [ ] Is the status change monotonic? (E5)
3. [ ] For VERIFIED: does a PoC artifact exist on disk? (E2/E4)
4. [ ] For PROVEN: was there independent confirmation? (E3)
5. [ ] Are secrets redacted from the finding + logs?
6. [ ] Was the target in-scope by the host allowlist?

## Trigger phrases
- "apakah finding ini asli?"
- "agent nge-fabricate findings"
- "claim gate", "evidence-or-nothing"
- "jangan percaya agent, verify dulu"
- Building any autonomous security agent

## Data files
Reference implementation + the 37-class taxonomy live in:
- `claimgate.py` — the five-rule validator
- `redaction.py` — secret scrubbing
- `taxonomy.py` + `_data/taxonomy/klasses.json` — 37 bug classes