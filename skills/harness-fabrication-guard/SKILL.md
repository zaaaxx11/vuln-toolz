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
| E2 | **CANDIDATE → VERIFIED** | requires PoC artifact on disk + logs | "trust me, it's real" |
| E3 | **VERIFIED → PROMOTED** | ≥2 evidence; second is independent re-verification | single-reporter promotion |
| E4 | **PROMOTED → PROVEN_LIVE** | `poc_path` + `logs_path` + independent re-verify bound | proof-less live claim |
| E5 | **monotonic** | status can only move forward | downgrading to hide failure |

## Implementation — the ClaimGate

The core is a `validate_status_change()` function. Its logic (portable to any language):

```python
def validate_status_change(current, new_status, evidence_count, poc_path=None, logs_path=None, independent_verified=False):
    # E1: THEORETICAL → CANDIDATE requires ≥1 evidence
    if current == THEORETICAL and new_status == CANDIDATE:
        if evidence_count < 1:
            raise Blocked("THEORETICAL→CANDIDATE requires >=1 evidence")
    # E2: CANDIDATE → VERIFIED requires PoC + logs on disk
    if current == CANDIDATE and new_status == VERIFIED:
        if not poc_path or not _file_exists(poc_path):
            raise Blocked("CANDIDATE→VERIFIED requires PoC artifact on disk")
        if not logs_path or not _file_exists(logs_path):
            raise Blocked("CANDIDATE→VERIFIED requires logs_path on disk")
    # E3: VERIFIED → PROMOTED requires ≥2 evidence AND second is independent
    if current == VERIFIED and new_status == PROMOTED:
        if evidence_count < 2:
            raise Blocked("VERIFIED→PROMOTED requires >=2 evidence (second = independent)")
        if not independent_verified:
            raise Blocked("VERIFIED→PROMOTED requires independent second verification bound to evidence")
    # E4: PROMOTED → PROVEN_LIVE requires poc_path + logs_path + independent re-verify
    if current == PROMOTED and new_status == PROVEN_LIVE:
        if not poc_path or not _file_exists(poc_path):
            raise Blocked("PROMOTED→PROVEN_LIVE requires poc_path on disk")
        if not logs_path or not _file_exists(logs_path):
            raise Blocked("PROMOTED→PROVEN_LIVE requires logs_path on disk")
        if not independent_verified:
            raise Blocked("PROMOTED→PROVEN_LIVE requires independent re-verification")
    # E5: monotonic — no downgrades
    if _rank(new_status) < _rank(current):
        raise Blocked("cannot downgrade a finding (monotonic)")
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

## Checklist — before trusting any finding (HunterOS pipeline)

1. [ ] Does the finding cite ≥1 evidence ID? (E1: THEORETICAL→CANDIDATE)
2. [ ] For VERIFIED: PoC + logs on disk? (E2: CANDIDATE→VERIFIED)
3. [ ] For PROMOTED: ≥2 evidence AND second is independent re-verification? (E3: VERIFIED→PROMOTED)
4. [ ] For PROVEN_LIVE: poc_path + logs_path + independent re-verification bound? (E4: PROMOTED→PROVEN_LIVE)
5. [ ] Is the status change monotonic? (E5)
6. [ ] Are secrets redacted from the finding + logs?
7. [ ] Was the target in-scope by the host allowlist?

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