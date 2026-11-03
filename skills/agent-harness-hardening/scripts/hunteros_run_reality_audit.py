#!/usr/bin/env python3
"""Read-only "run reality" audit for a HunterOS / hunt-os ledger.

Answers: what did the last N runs ACTUALLY do, and does the run_ended event
agree with the store? Implements sections D, H, I, J of the
agent-harness-hardening skill.

    python3 hunteros_run_reality_audit.py [--db PATH] [--runs N]

Read-only by construction: opens sqlite with mode=ro. Never writes, never
commits. Safe against a live ledger.

The central check is the run_ended-vs-store diff. In HunterOS 0.7.0
`run_ended.findings` is `len(created)` where `created` only holds findings the
ENGINE returned inline (pipeline.py:372/409/524); agent findings created via
`create_finding_request` land in the `findings` table and are never counted.
So the event reads 0 while the store holds real rows. Trust the store.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

DEFAULT_DB = Path.home() / ".hunter" / "ledger.db"


def connect(db: Path) -> sqlite3.Connection:
    if not db.exists():
        sys.exit(f"no ledger at {db}")
    # mode=ro: a typo here can never mutate the append-only store.
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True)


def one(conn: sqlite3.Connection, sql: str, args: tuple = ()):
    row = conn.execute(sql, args).fetchone()
    return row[0] if row else None


def payload_events(conn: sqlite3.Connection, run_id: str, kind: str) -> list[dict]:
    out = []
    for (raw,) in conn.execute(
        "SELECT payload FROM events WHERE run_id=? AND kind=? ORDER BY seq", (run_id, kind)
    ):
        try:
            out.append(json.loads(raw))
        except Exception:
            out.append({"_unparseable": raw[:200]})
    return out


def count(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> int:
    return one(conn, sql, args) or 0


def audit(conn: sqlite3.Connection, n: int) -> list[dict]:
    ids = [
        r[0]
        for r in conn.execute(
            "SELECT run_id FROM runs ORDER BY rowid DESC LIMIT ?", (n,)
        )
    ]
    rows = []
    for rid in ids:
        ended = (payload_events(conn, rid, "run_ended") or [{}])[-1]
        collect = next(
            (
                p
                for p in payload_events(conn, rid, "phase_ended")
                if p.get("phase") == "collect"
            ),
            {},
        )
        findings_rows = count(conn, "SELECT COUNT(*) FROM findings WHERE run_id=?", (rid,))
        history_counts = {
            k: count(conn, "SELECT COUNT(*) FROM events WHERE run_id=? AND kind=?", (rid, k))
            for k in (
                "run_started",
                "run_ended",
                "run_closed",
                "phase_started",
                "phase_ended",
                "probe_started",
                "probe_result",
                "finding_created",
                "evidence_stored",
                "delegate_started",
                "delegate_finished",
                "error",
                "report_rendered",
                "retro_recorded",
                "classification_recorded",
            )
        }
        rows.append(
            {
                "run_id": rid,
                "target": one(conn, "SELECT target FROM runs WHERE run_id=?", (rid,)),
                "engine": one(conn, "SELECT engine FROM runs WHERE run_id=?", (rid,)),
                "scope": one(conn, "SELECT scope_name FROM runs WHERE run_id=?", (rid,)),
                "status": one(conn, "SELECT status FROM runs WHERE run_id=?", (rid,)),
                "outcome": one(conn, "SELECT outcome FROM runs WHERE run_id=?", (rid,)),
                "history_counts": history_counts,
                "elapsed_ms": ended.get("elapsed_ms"),
                "gates_failed": ended.get("gates_failed"),
                "gate_blocked": ended.get("gate_blocked"),
                # >2 events means a reset/rerun wrote duplicate closes on one ledger file.
                "duplicate_closes": (
                    history_counts["run_ended"] > 1 or history_counts["run_closed"] > 1
                ),
                "turns": count(
                    conn,
                    "SELECT COUNT(*) FROM events WHERE run_id=? AND kind='engine_event' "
                    "AND json_extract(payload,'$.stage')='agent_turn'",
                    (rid,),
                ),
                "stage_profile": {
                    stage: count(
                        conn,
                        "SELECT COUNT(*) FROM events WHERE run_id=? AND kind='engine_event' "
                        "AND json_extract(payload,'$.stage')=?",
                        (rid, stage),
                    )
                    for stage in ("agent_turn", "verify", "collect")
                },
                "tool_hist": [
                    {"tool": t, "n": c}
                    for t, c in conn.execute(
                        "SELECT json_extract(payload,'$.tool'), COUNT(*) FROM events "
                        "WHERE run_id=? AND kind='engine_event' "
                        "AND json_extract(payload,'$.tool') IS NOT NULL "
                        "GROUP BY 1 ORDER BY 2 DESC",
                        (rid,),
                    )
                ],
                "probes": {
                    "started": history_counts["probe_started"],
                    "results": history_counts["probe_result"],
                    "hits": count(
                        conn,
                        "SELECT COUNT(*) FROM events WHERE run_id=? AND kind='probe_result' "
                        "AND json_extract(payload,'$.hit')=1",
                        (rid,),
                    ),
                },
                "evidence_rows": count(
                    conn, "SELECT COUNT(*) FROM evidence WHERE run_id=?", (rid,)
                ),
                "finding_rows": findings_rows,
                "event_findings": ended.get("findings"),
                "event_verified": ended.get("verified"),
                # THE charge: event says zero, store says otherwise.
                "MISCOUNT": ended.get("findings") == 0 and findings_rows > 0,
                "collect_phase_findings": collect.get("findings"),
                "retro_lessons": [
                    lesson
                    for p in payload_events(conn, rid, "retro_recorded")
                    for lesson in p.get("lessons", []) or []
                ],
            }
        )
    return rows


def hist_line(row: dict, top: int = 8) -> str:
    return ", ".join(f"{t['tool']}={t['n']}" for t in row["tool_hist"][:top])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    conn = connect(args.db)
    rows = audit(conn, args.runs)

    print(f"=== last {len(rows)} runs — {args.db} (read-only) ===\n")
    for r in rows:
        print(f"{r['run_id']}  {r['target']}")
        print(
            f"  engine={r['engine']} scope={r['scope']} status={r['status']}"
            f" outcome={r['outcome']}"
        )
        print(
            f"  elapsed_ms={r['elapsed_ms']} turns={r['turns']}"
            f" stages={r['stage_profile']}"
        )
        print(
            f"  probes started/results/hits="
            f"{r['probes']['started']}/{r['probes']['results']}/{r['probes']['hits']}"
        )
        print(f"  evidence_rows={r['evidence_rows']}")
        print(
            f"  findings: store={r['finding_rows']}  run_ended={r['event_findings']}"
            f"  collect=={r['collect_phase_findings']}"
            f"  finding_created_events={r['history_counts']['finding_created']}"
        )
        if r["MISCOUNT"]:
            print(
                f"  ** MISCOUNT: run_ended says {r['event_findings']} but the store "
                f"holds {r['finding_rows']} — trust the store (skill section H)"
            )
        if r["duplicate_closes"]:
            print(
                "  ** DUPLICATE CLOSES: run_ended/run_closed appear >1x for one run_id"
            )
        print(f"  tools: {hist_line(r)}")
        if r["retro_lessons"]:
            for lesson in r["retro_lessons"]:
                flag = "" if not r["MISCOUNT"] else "   <- READ WITH CAUTION (§H)"
                print(f"  retro: {lesson}{flag}")
        print()

    print("--- cross-run detail ---")
    for r in rows:
        for f in conn.execute(
            "SELECT id, severity, status, klass, substr(title,1,72) FROM findings "
            "WHERE run_id=? ORDER BY id",
            (r["run_id"],),
        ):
            print(f"{r['run_id']} {f[0]} {f[1]:8} {f[2]:11} {f[3]:16} {f[4]}")

    mism = [r["run_id"] for r in rows if r["MISCOUNT"]]
    print()
    print(f"MISCOUNT runs: {mism or 'none'}")
    print(
        "Reminder: judge by SELECT COUNT(*) FROM findings WHERE run_id=?, "
        "never by run_ended.findings."
    )


if __name__ == "__main__":
    main()
