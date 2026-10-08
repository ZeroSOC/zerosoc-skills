#!/usr/bin/env python3
"""The notifications a confirmed Incident owes, and by when (Detection & Analysis §3.2, Incident Response
§6). Standard library only.

  regulatory_clock.py --awareness 2026-10-08T09:30:00Z [--severity High] [--regulation nis2 ...]
                      [--sent nis2-notification=2026-10-10T16:00:00Z ...] [--now TIME] [--json]

Times are ISO 8601 in UTC or milliseconds since the epoch. Deadlines run from awareness, which is at the
latest the Incident's confirmation.

Internal notification, by severity (reference response times, an organization policy knob), for every
confirmed Incident: High, the affected asset owners and the security lead within 30 minutes; Critical,
the CISO, legal counsel, risk management and executive leadership within 15 minutes; Low or Medium, an
incident ticket to the affected asset owners, with no deadline and no out-of-hours notification.

Regulatory notification, for a significant Incident of an organization in scope (`--regulation`):

- NIS2 (Article 23): early warning within 24 hours; incident notification within 72 hours; final report
  within one month of the incident notification.
- DORA (Article 19, deadlines from its technical standards, reference values): initial notification
  within 4 hours of the classification as major (here the confirmation); intermediate report within
  72 hours of the initial notification; final report within one month of the intermediate report.

A report that follows another is counted from the moment that one was sent, and from its deadline until
it is. A report already sent keeps the deadline it had. One month is one calendar month, on the month's
last day where it is shorter. The standards' outer bounds and a national transposition's shorter
deadlines are the organization's to apply. Which regulations apply is the organization's too: nothing on
a Case says whether it is in scope of either.

Output: one entry per report in the order each regulation sets them, with its deadline, when it was sent
and whether it is overdue at `--now`. Exit 1 when a report is overdue.
"""
import argparse, calendar, json, sys
from datetime import datetime, timezone

HOUR = 3_600_000

STEPS = (
    # kind, regulation, counted from (None: awareness), hours (None: one calendar month)
    ("nis2-early-warning", "nis2", None, 24),
    ("nis2-notification", "nis2", None, 72),
    ("nis2-final-report", "nis2", "nis2-notification", None),
    ("dora-initial", "dora", None, 4),
    ("dora-intermediate", "dora", "dora-initial", 72),
    ("dora-final", "dora", "dora-intermediate", None),
)
REGULATIONS = ("nis2", "dora")
SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
INTERNAL = {
    # severity: (minutes, recipients); None minutes: a ticket, with no deadline
    "High": (30, "the affected asset owners and the security lead"),
    "Critical": (15, "the CISO, legal counsel, risk management and executive leadership"),
    "Medium": (None, "the affected asset owners, as an incident ticket"),
    "Low": (None, "the affected asset owners, as an incident ticket"),
}


def millis(value):
    """A time as milliseconds since the epoch: an integer as it is, an ISO 8601 time read in UTC."""
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return int(value)
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def utc(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def month_after(ms):
    """The same moment one calendar month later, on the month's last day where it is shorter."""
    moment = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    year, month = (moment.year + 1, 1) if moment.month == 12 else (moment.year, moment.month + 1)
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return int(moment.replace(year=year, month=month, day=day).timestamp() * 1000)


def clock(awareness, regulations, sent=None, now=None, severity=None):
    """Every notification owed, each with its deadline: the internal one the severity sets first,
    then the reports the regulations require, in the order they are set."""
    sent = dict(sent or {})
    wanted = [r for r in REGULATIONS if r in set(regulations)]
    held = {}
    reports = []
    if severity in INTERNAL:
        minutes, recipient = INTERNAL[severity]
        deadline = awareness + minutes * 60_000 if minutes is not None else None
        reports.append({"kind": "internal", "regulation": None, "recipient": recipient,
                        "counted_from": "awareness", "deadline": deadline,
                        "deadline_utc": utc(deadline) if deadline is not None else None,
                        "sent_at": sent.get("internal"),
                        "overdue": deadline is not None and now is not None
                        and sent.get("internal") is None and now > deadline})
    for kind, regulation, after, hours in STEPS:
        if regulation not in wanted:
            continue
        if after is None:
            anchor, counted_from = awareness, "awareness"
        else:
            before = held[after]
            anchor = before["sent_at"] if before["sent_at"] is not None else before["deadline"]
            counted_from = f"{after} {'sent' if before['sent_at'] is not None else 'deadline'}"
        deadline = month_after(anchor) if hours is None else anchor + hours * HOUR
        report = {"kind": kind, "regulation": regulation, "counted_from": counted_from,
                  "deadline": deadline, "deadline_utc": utc(deadline),
                  "sent_at": sent.get(kind),
                  "overdue": now is not None and sent.get(kind) is None and now > deadline}
        held[kind] = report
        reports.append(report)
    return reports


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--awareness", required=True, help="when the organization became aware: at the latest the confirmation")
    ap.add_argument("--severity", choices=SEVERITIES, help="the Incident's severity: what the internal notification is")
    ap.add_argument("--regulation", action="append", choices=REGULATIONS, default=[],
                    help="a regulation the organization is in scope of; repeatable")
    ap.add_argument("--sent", action="append", default=[], metavar="KIND=TIME", help="a report already sent; repeatable")
    ap.add_argument("--now", help="the moment overdue is read at; omitted, nothing is overdue")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    known = {kind for kind, *_ in STEPS} | {"internal"}
    sent = {}
    for item in a.sent:
        kind, _, when = item.partition("=")
        if kind not in known or not when:
            ap.error(f"--sent {item}: expected one of {', '.join(sorted(known))} = a time")
        sent[kind] = millis(when)
    reports = clock(millis(a.awareness), a.regulation, sent, millis(a.now) if a.now else None, a.severity)
    if a.json:
        print(json.dumps(reports, indent=2))
    else:
        for r in reports:
            state = f"sent {utc(r['sent_at'])}" if r["sent_at"] is not None else ("OVERDUE" if r["overdue"] else "due")
            by = f"by {r['deadline_utc']} (from {r['counted_from']})" if r["deadline"] is not None else "no deadline"
            print(f"{r['kind']}: {by}, {state}" + (f" — to {r['recipient']}" if r.get("recipient") else ""))
        if not reports:
            print("no severity and no regulation named: no notification is owed")
    sys.exit(1 if any(r["overdue"] for r in reports) else 0)


if __name__ == "__main__":
    main()
