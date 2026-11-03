# HunterOsHarness Core Modules

Extracted from [HunterOsHarness](https://github.com/zaaaxx11/HunterOsHarness) —
a production security hunt engine. **Reference modules**, not drop-in runtime.

| Module | Lines | Purpose |
|---|---|---|
| `toolchain.py` | 978 | 28 binary wrappers (nuclei, foundry, slither, sqlmap...) |
| `claimgate.py` | 222 | Finding status validation — THEORETICAL→CANDIDATE→VERIFIED |
| `target_classifier.py` | 339 | Classifies targets (contract/bridge/chain/repo/domain) |
| `target_resolve.py` | 333 | Resolves free-form target descriptions to structured specs |
| `scope.py` | 233 | Scope gate — domain/host/chain validation |
| `daemon_health.py` | 437 | Zombie daemon reaping + memory pressure backpressure |
| `budget.py` | 135 | Run cost control — wall time + token budget enforcement |
| `taxonomy.py` | 133 | Vulnerability classification (CWE-like) |
| `redaction.py` | 115 | Safe text redaction |
| `phases.py` | 871 | Multi-phase execution (recon→probe→verify→report) |

## Why these are useful

Each module solves one hard problem in building an autonomous security agent:
- **claimgate** — prevents agents from promoting findings without evidence
- **target_classifier** — tells the agent WHAT to audit (contract vs API vs repo)
- **toolchain** — 28 production-tested binary wrappers with install hints
- **daemon_health** — keeps long-running hunts alive under memory pressure
- **budget** — caps wall time + token spend per run

## Installation



For the full engine. These extracted modules are for study and reference.
