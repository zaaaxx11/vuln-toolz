# hunter — Reference Modules from HunterOsHarness

These modules are **reference implementations extracted from HunterOsHarness v0.7.0**
(`/home/ubuntu/HunterOsHarness/src/hunter/`), placed here as standalone,
readable code for studying the architecture of an evidence-first security-audit
agent harness. They are **not** a runnable HunterOsHarness installation.

## What this is (and isn't)

- **Is:** 10 of the most instructive standalone modules from the harness,
  adapted so each file can be read and imported on its own. Every internal
  `hunter.*` import that can't be satisfied standalone is guarded with a
  `try/except ImportError` fallback and a `# DEP: pip install hunter-os-harness`
  marker pointing at the original import. Logic was **not** modified — only
  imports were made survivable, and `from __future__ import annotations` was
  stripped per task spec.
- **Isn't:** a working Harness. Modules that depend on the ledger, the engine
  base contract, or the taxonomy data file will use minimal in-file stand-ins
  at import time. To run the real thing, install the full harness:
  `pip install hunter-os-harness` (or clone the repo and `pip install -e .`).

## The modules

| File | Source path | What it teaches |
|------|-------------|-----------------|
| `claimgate.py` | `kernel/claimgate.py` | The claim gate — RULES E1–E5 that make unbacked claims impossible. Evidence ladder THEORETICAL→CANDIDATE→VERIFIED→PROMOTED→PROVEN_LIVE. The core "evidence or nothing" doctrine. |
| `target_classifier.py` | `workflow/target_classifier.py` | Deterministic, fail-closed target classification (`api`/`web`/`repo`/`contract`/`bridge_path`), subdomain merging, Solidity contract family grouping. Zero LLM, zero guessing. |
| `target_resolve.py` | `workflow/target_resolve.py` | LLM-assisted target resolution: deterministic gate as fast path, LLM parse behind it, regex salvage, fail-closed refusal. Bare `0x` contract address handling + built-in chain→RPC table. |
| `scope.py` | `tools/scope.py` | **The crown jewel for safety.** Structural (not prompt-based) fail-closed scope enforcement. Exact hostname matching, localhost always allowed, scheme-unglue repair, scope manifests. |
| `daemon_health.py` | `daemon_health.py` | Zombie daemon reaping (conservative: only reap when state dir is gone or unclaimed), memory-pressure backpressure, claim gate. Has a real CLI (`python -m hunter.daemon_health`). |
| `budget.py` | `llm/budget.py` | Thread-safe RunBudget: iteration + cost + wall-clock governor with staged 70/85/95% cost warnings and a stop-file override. |
| `taxonomy.py` | `taxonomy.py` | Bug-class taxonomy loader + validator (`klass` vocabulary for findings). Requires `_data/taxonomy/klasses.json` (package data, not extracted) — falls back to `{"unknown"}` fail-closed. |
| `phases.py` | `phases.py` | **The pipeline soul.** Ledger-enforced 7-phase state machine (SCORE→RECON→CLASSIFY→HUNTING→VERIFY→REPORT→RETRO). Events-only state, gates that read only the ledger, append-only transitions. |
| `redaction.py` | `kernel/redaction.py` | RULE-E3 secret redaction. Broad credential-shape patterns (AWS, provider tokens, JWT, ETH private keys, Telegram/Discord, auth headers) with digest-key exemptions. |
| `toolchain.py` | `agent/toolchain.py` | **The most valuable module.** Real binary wrappers (forge/cast/slither/masscan/nuclei/gobuster/sqlmap) that resolve at call time, report absence honestly with exact install commands, run in a minimal-env jail, and are scope-gated. |

## How to use these

### 1. Read them as a design reference
Each module is self-documenting — the docstrings explain the *doctrine*
(why fail-closed, why absence-is-a-result, why structural-not-prompt).
Start with `scope.py` and `claimgate.py` to understand the two pillars of the
harness: **nothing happens out of scope**, and **no claim without evidence**.

### 2. Import a single module
```python
import sys; sys.path.insert(0, "/home/ubuntu/vuln-toolz")

from hunter.scope import ScopeSet, ScopeViolation, localhost_scope
scope = localhost_scope()
scope.check_url("http://127.0.0.1:8080/health")  # OK

from hunter.redaction import redact_text
redact_text("Authorization: Bearer <your-token>")  # -> "Authorization: [REDACTED]"

from hunter.target_classifier import classify_target
classify_target("https://api.foo.com")  # -> "api"
```
Standalone modules (`scope`, `redaction`, `target_classifier`,
`target_resolve`, `daemon_health`, `budget`, `phases`, `toolchain`) import
cleanly with no external dependencies. `claimgate` and `taxonomy` reference
the taxonomy/findings and use in-file fallbacks when the full package isn't
present.

### 3. Adapt them for your own agent
Copy the *pattern*, not necessarily the code:
- **Scope gate** → put any network call behind a structural check that runs
  in code before the socket opens, never in a prompt.
- **Claim gate** → refuse to persist a finding/claim unless evidence artifacts
  are bound to it.
- **Budget governor** → track iterations/cost/wall-clock with staged wind-down
  warnings and a user stop-file that outranks everything.
- **Toolchain wrappers** → resolve binaries at call time, report absence
  honestly, run children in a minimal env, scope-gate the filesystem.

## Adapting notes (what changed vs. source)

- `from __future__ import annotations` stripped from every file (per task).
- Internal imports wrapped in `try/except ImportError` with `# DEP:` markers:
  - `phases.py`: `hunter.errors`, `hunter.kernel.events`, `hunter.kernel.findings`
    → in-file `HunterError` / `Event` / `EventKind` / `FindingStatus` stand-ins.
    `Ledger`/`EngineResult` type hints → `Any` runtime stand-in (TYPE_CHECKING
    imports don't execute, so an `else` branch supplies the names).
  - `budget.py`: `hunter.llm.base.RunBudget` → dataclass stand-in.
  - `toolchain.py`: `.tools_base` (ToolContext/ToolOutcome/ToolSpec) and
    `..tools.scope` (ScopeViolation) → in-file dataclasses / local
    `hunter.scope` fallback.
  - `claimgate.py`: `.findings` and `hunter.taxonomy` → in-file stand-in.
- No logic, behavior, thresholds, or rule semantics were changed.

## Running the real thing

```bash
pip install hunter-os-harness     # or: git clone <repo> && pip install -e .
```
These reference files will then pick up the real `hunter.*` imports in their
`try` branches and use the genuine ledger, base contracts, and taxonomy data.
