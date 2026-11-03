---
name: long-hunt-ops-survival
description: "Keep long-running autonomous security hunts alive — zombie daemon reaping, memory pressure backpressure, and run budget enforcement. Use when a hunt run dies silently, a daemon leaks, the box OOMs mid-flight, a run never finishes, or when building an agent that must survive multi-hour operations."
---

# Long-Hunt Ops Survival

Two silent killers of autonomous hunts: **zombie daemons** eating RAM and **runaway budgets**. This skill encodes the exact rules a production hunt engine uses to survive multi-hour operations.

## Zombie Daemon Reaping — the conservative rule

A daemon is reaped **ONLY** when:
- its state directory is **GONE**, OR
- no valid `pid.json` backs it.

A daemon whose state dir still exists is **never touched**, even if it looks idle. Why: a test run spawns a real daemon per case; missed teardown leaves it polling a dead dir. But live dirs = the daemon may be mid-hunt. Killing it corrupts the ledger.

```python
def reap_zombies():
    for zombie in zombie_candidates():
        if _proc_exists(zombie.pid):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(zombie.pid, signal.SIGKILL)
```

## Memory Pressure Backpressure

The #1 bug: the worker claims the next task the moment the previous finishes. Under memory pressure that's exactly wrong — the new hunt allocates, the box swaps or OOM-kills, the run dies mid-flight with a corrupted ledger.

**Rule: refuse to claim while available memory is below a floor. Re-arm on the next poll. The queue IS the backpressure, not a crash.**

```python
if available_mb < MEMORY_FLOOR_MB:
    return ClaimGateBlocked("memory pressure — hold claim")
```

Where `available_mb` comes from the system snapshot, `float("inf")` when unbounded (round it for the payload — JSON can't hold inf).

## Run Budget Governor

Every run needs three caps, all enforced thread-safe:

| Cap | Default | Warn at | Stop at |
|-----|---------|---------|---------|
| iterations | 60 | 70% | 100% |
| cost USD | 3.0 | 85% | 100% |
| wall clock | 20 min | 95% | 100% |

Staged warnings, then hard stop. No unlimited runs, ever.

```python
usage = budget.usage()
if usage.ratio() >= 1.0:
    raise BudgetExhausted()
```

## The session lock — cross-process, cross-platform

Two processes must never hold the same hunt session. Lock the `.lock` file in the session dir:
- POSIX: `fcntl.flock(fd, LOCK_EX | LOCK_NB)`
- Windows: `msvcrt.locking(fd, LK_NBLCK, 1)`
- Non-blocking → on `OSError` raise `SessionExists`.

Wrap the yield in try/finally so the lock always releases.

## Checklist before deploying a long hunt

1. [ ] Every daemon has a bounded lifetime? (state dir gone → reap)
2. [ ] Memory floor enforced before task claims?
3. [ ] Iteration + cost + wall-clock budgets set?
3. [ ] Iteration + cost + wall-clock budgets set?
4. [ ] Session lock is cross-platform (fcntl + msvcrt)?
5. [ ] On any kill, ledger is append-only + never corrupted?

## Trigger phrases
- "hunt-nya mati diam-diam"
- "daemon zombie"
- "OOM di tengah run"
- "agent ga pernah selesai"
- building a daemonized security agent
- run budget / token budget / wall-clock limit

## Reference implementation
`daemon_health.py` (zombie reaping + memory backpressure + claim gate CLI) and `budget.py` (thread-safe iteration/cost/wall-clock governor) from HunterOsHarness.