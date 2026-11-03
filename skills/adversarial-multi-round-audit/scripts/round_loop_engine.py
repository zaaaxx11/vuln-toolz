#!/usr/bin/env python3
"""
ROUND LOOP ENGINE — stateful angle dispatcher for adversarial multi-round audits.

WHY THIS EXISTS
---------------
Round-based hunting fails in one specific way: round N+1 re-tests what round N
already REFUTED, because the "what is dead" knowledge lives only in the chat
context window. Once compaction hits, it is gone and the agent burns hours
re-proving the same negative.

This script externalises that knowledge into a JSON state file. Each invocation
advances exactly one round: it picks the next 3 angles that are NOT in
`dead_hypotheses`, records the start, and prints a brief-ready block.

USAGE
-----
    python3 round_loop_engine.py            # advance one round, print brief
    python3 round_loop_engine.py --status   # show state without advancing
    python3 round_loop_engine.py --add-angle "..."
    python3 round_loop_engine.py --kill "hypothesis text"

Wire it into a cron job so the loop runs itself:

    cron prompt STEP 0: run this, read output, spawn 3 subagents on the angles.

FILES
-----
    /tmp/hunt_state.json   state (edit via --add-angle / --kill, not by hand)
    /tmp/r_rounds.log      append-only round log
    /tmp/r{N}/             per-round artifact dir (created on advance)

EXIT CODES
----------
    0  round advanced
    2  NO_ANGLES_LEFT — must invent new angles (read repo, find untouched files)
    3  every queued angle collided with dead_hypotheses — queue purged, invent new angles
"""
import json
import sys
import os
import datetime

STATE = os.environ.get("HUNT_STATE", "/tmp/hunt_state.json")
LOG = os.environ.get("HUNT_LOG", "/tmp/r_rounds.log")

ANGLES_PER_ROUND = 3


def load(path=STATE):
    with open(path) as f:
        return json.load(f)


def save(s, path=STATE):
    with open(path, "w") as f:
        json.dump(s, f, indent=2)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(line):
    with open(LOG, "a") as f:
        f.write(f"{utcnow()} {line}\n")


def show_status(s):
    print(f"target            : {s.get('target')}")
    print(f"rounds completed  : {s.get('rounds_completed')}")
    print(f"verdict           : {s.get('verdict')}")
    print(f"dead hypotheses   : {len(s.get('dead_hypotheses', []))}")
    print(f"proven findings   : {len(s.get('proven_findings', []))}")
    print(f"angles remaining  : {len(s.get('next_angles', []))}")
    cur = s.get("current_round")
    if cur:
        print(f"current round     : {cur.get('round')} ({cur.get('status')})")
        for i, a in enumerate(cur.get("angles", []), 1):
            print(f"   A{i}. {a}")


def _norm(text):
    """Lowercase alnum-only, for fuzzy dead/queued comparison."""
    return "".join(c for c in text.lower() if c.isalnum())


def _tokens(text):
    """Content words long enough to be discriminating."""
    return {t for t in _norm_split(text) if len(t) >= 5}


def _norm_split(text):
    out, cur = [], []
    for c in text.lower():
        if c.isalnum():
            cur.append(c)
        else:
            if cur:
                out.append("".join(cur))
                cur = []
    if cur:
        out.append("".join(cur))
    return out


def is_dead(angle, dead):
    """True if `angle` looks like it re-tests something already refuted.

    Two signals, either is enough:
      1. substring containment on normalised text (short/verbatim re-issue), or
      2. >= 3 shared discriminating content words.
    Deliberately conservative on (2): a re-worded *new* angle that merely shares
    the word "resolver" must still get through.
    """
    a_norm = _norm(angle)
    a_tok = _tokens(angle)
    for d in dead:
        d_norm = _norm(d)
        if not d_norm:
            continue
        if a_norm and (a_norm in d_norm or d_norm in a_norm):
            return True
        d_tok = _tokens(d)
        if len(a_tok & d_tok) >= 3:
            return True
    return False


def purge_dead_angles(s):
    """Drop queued angles that collide with the dead ledger. Mutates and returns
    (kept, dropped). This is the guard that stops round N+1 re-running round N-1."""
    dead = s.get("dead_hypotheses", [])
    if not dead:
        return list(s.get("next_angles", [])), []
    kept, dropped = [], []
    for a in s.get("next_angles", []):
        (dropped if is_dead(a, dead) else kept).append(a)
    s["next_angles"] = kept
    return kept, dropped


def advance(s):
    kept, dropped = purge_dead_angles(s)
    if dropped:
        save(s)
        print("!! PURGED angles that re-test dead hypotheses (they are NOT new):")
        for a in dropped:
            print(f"   - {a[:110]}")
        print("   An angle is only valid if the ledger does not already refute it.")
        print()

    angles = s.get("next_angles", [])
    if not angles:
        return 3 if dropped else 2

    rnd = s.get("rounds_completed", 0) + 1
    picked = angles[:ANGLES_PER_ROUND]
    s["next_angles"] = angles[ANGLES_PER_ROUND:]
    s["rounds_completed"] = rnd
    s["current_round"] = {
        "round": rnd,
        "started": utcnow(),
        "angles": picked,
        "status": "running",
    }
    save(s)
    log(f"ROUND {rnd} START angles={json.dumps(picked, ensure_ascii=False)}")

    d = f"/tmp/r{rnd}"
    os.makedirs(d, exist_ok=True)

    print(f"=== ROUND {rnd} — {utcnow()} — budget {s.get('round_duration_min', 60)} min ===")
    print(f"dead hypotheses accumulated : {len(s.get('dead_hypotheses', []))}")
    print(f"proven findings             : {len(s.get('proven_findings', []))}")
    print()
    print("=== ANGLES THIS ROUND (each must be a NEW, falsifiable surface) ===")
    for i, a in enumerate(picked, 1):
        print(f"  A{i}. {a}")
    print()
    print(f"angles remaining after this round: {len(s['next_angles'])}")
    print(f"artifact dir: {d}")
    print()
    print("REMINDERS to embed in every subagent brief:")
    print("  - check the 'error' field BEFORE reading 'result'")
    print("  - raw hex required for any PROVEN claim")
    print("  - attack your own finding first: prove it is NOT exploitable")
    print("  - 2 rounds with no new evidence -> mark BLOCKED and move on")
    print("  - append INCREMENTALLY (>=3x), never only at the end")
    print(f"  - the dead-hypothesis list is authoritative: do not re-test it")
    print("  - no literal in an evidence script may be invented (pitfall 29)")
    return 0


def main(argv):
    if len(argv) > 1 and argv[1] == "--status":
        show_status(load())
        return 0

    if len(argv) > 2 and argv[1] == "--add-angle":
        s = load()
        s.setdefault("next_angles", []).append(argv[2])
        save(s)
        print(f"added angle ({len(s['next_angles'])} queued)")
        return 0

    if len(argv) > 2 and argv[1] == "--kill":
        s = load()
        s.setdefault("dead_hypotheses", []).append(argv[2])
        save(s)
        print(f"recorded dead hypothesis ({len(s['dead_hypotheses'])} total)")
        return 0

    s = load()
    return advance(s)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
