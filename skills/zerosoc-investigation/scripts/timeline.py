#!/usr/bin/env python3
"""The Case Timeline and T0, as the framework defines them. Standard library only.

  timeline.py ledger.json [--t0 <time>] [--json]

The timeline is a **reconstruction of the Case, not a listing of it** (Case Schema §5): its entries
are the ones flagged for the narrative, ordered by **when the thing happened** rather than when it
was recorded. T0 is the earliest Malicious event of the Case — its `start_time`, which only a
Malicious Finding moves: a benign precursor or a piece of context earlier than it is part of the
account and moves nothing. Exactly one entry carries T0: two detections of the same activity share
a time, and the first of them is the anchor while the rest are entries like any other. It is **T0**,
the anchor of the response metrics, only on a confirmed Incident (`recorded_verdict` True Positive):
until then the same moment is the Case's `start_time`, and the output gives it under both names with
`confirmed_incident` saying which it is.

Input: **the ledger** of triage_decide.py or resolve.py, whose findings say when the thing they
report happened and whether the narrative shows them:

{"now": "2026-09-14T15:12:00Z",                    when this gate ran
 "t0": null,                                        the Case's start_time if it states one; it is checked
 "findings": [{"id": "F1", "desc": "...", "side": "Malicious"|"Benign"|null, "retracted": false,
               "first_seen": "2026-09-14T14:55:41Z",   when it happened — never "at", when it was made
               "timeline": true,                      flagged for the narrative (the zerosoc:timeline tag)
               "event_refs": ["..."]}],
 "entries": [{"kind": "handover"|"action"|"note"|"investigation"|"detection", "desc": "...",
              "time": "..."}]}                        what is on the timeline and is not a finding

T0 is **derived**: the earliest `first_seen` among the Malicious findings that are not retracted,
flagged or not, and the `detection` entries. A `t0` the ledger states is the one the timeline must carry,
and it is compared with the derived one: they differ when the Case or the ledger is wrong. A time is
ISO 8601 with a date and a time of day (any offset, any fraction of a second) or milliseconds since the
epoch; both may meet in one ledger, and a time outside this century is not read — it is a slip, or seconds
given for milliseconds. A time written to the second holds the whole of that second.
An entry that is not a finding and has no time happened at this gate and is stamped `now`. A finding
has no such fallback: one flagged for the narrative with no `first_seen` cannot be placed, and says so.

Output: the entries in order, each with `time` (milliseconds), `time_utc` and `is_t0`; `t0`, `t0_utc`
and `t0_entry`; and `failures`, on any of which the script exits 1.
"""
import argparse, json, math, re, sys
from datetime import datetime, timezone

KINDS = ("detection", "finding", "investigation", "handover", "action", "note")
# a time of a Case is of this century; outside it, it is a typing slip or seconds given for milliseconds
EARLIEST, LATEST = 946684800000, 4102444800000  # 2000-01-01 and 2100-01-01, in milliseconds
TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(value):
    """(milliseconds since the epoch, milliseconds of precision), or None. A time without a zone is UTC.

    The precision is what lets a time written to the second meet the same moment written to the
    millisecond: they are one instant when they differ by less than the coarser of the two.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        found = (int(value), 1) if math.isfinite(value) else None
    else:
        m = TIME.match(str(value).strip())
        if not m:
            return None
        day, clock, frac, zone = m.groups()
        zone = "+00:00" if zone in (None, "Z") else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
        try:
            seconds = int(datetime.fromisoformat(f"{day}T{clock}{zone}").timestamp())
        except (ValueError, OverflowError):
            return None
        digits = (frac or "")[:3]
        found = seconds * 1000 + int(digits.ljust(3, "0") or 0), 10 ** (3 - len(digits))
    return found if found and EARLIEST <= found[0] < LATEST else None


def _same(a, b):
    """One instant: a time written to the second holds the whole of that second, from its start."""
    coarse, fine = (a, b) if a[1] >= b[1] else (b, a)
    return 0 <= fine[0] - coarse[0] < coarse[1]


def _utc(ms):
    stamp = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + (f".{ms % 1000:03d}" if ms % 1000 else "") + "Z"


def _malicious(finding):
    tag = finding.get("tag") if isinstance(finding.get("tag"), dict) else {}
    side = finding.get("side", tag.get("side"))
    return str(side or "").strip().lower() == "malicious" and finding.get("retracted") is not True


def _confirmed(ledger):
    """A confirmed Incident: the verdict the run recorded is True Positive."""
    return ledger.get("verdict_id") == 2 or "true positive" in str(ledger.get("recorded_verdict") or "").lower()


def build(ledger):
    """The Case Timeline: ordered, T0 derived and flagged exactly once, and what could not be placed."""
    problems, placed, unplaced, malicious = [], [], [], []
    if not isinstance(ledger, dict):
        return {"t0": None, "t0_utc": None, "t0_entry": None, "entries": [], "unplaced": [],
                "problems": [f"a ledger is an object; this is a {type(ledger).__name__}"]}
    now = parse_time(ledger.get("now"))
    if ledger.get("now") not in (None, "") and now is None:
        problems.append(f"now {ledger['now']!r} is not a time this can read")
    held = {}
    for name in ("findings", "entries"):
        listed = ledger.get(name) or []
        if not isinstance(listed, list):
            problems.append(f"{name} is a list; this is a {type(listed).__name__}")
            listed = []
        strangers = [x for x in listed if not isinstance(x, dict)]
        if strangers:
            problems.append(f"{name} holds {len(strangers)} item(s) that are not objects, e.g. {strangers[0]!r}")
        held[name] = [x for x in listed if isinstance(x, dict)]
    findings, others = held["findings"], held["entries"]

    for finding in findings:
        when = parse_time(finding.get("first_seen"))
        label = finding.get("id", "?")
        if finding.get("first_seen") not in (None, "") and when is None:
            problems.append(f"finding {label}: first_seen {finding['first_seen']!r} is not a time this can read")
        moves_t0 = _malicious(finding) and when is not None
        if moves_t0:
            malicious.append(when)
        if not finding.get("timeline"):
            continue
        if when is None:
            unplaced.append(dict(finding, why="a finding flagged for the narrative with no first_seen: it is placed "
                                              "by when the thing happened, never by when the finding was made"))
            continue
        placed.append(dict(finding, kind=finding.get("kind") or "finding", when=when, moves_t0=moves_t0))

    for entry in others:
        when = parse_time(entry.get("time"))
        if entry.get("time") not in (None, "") and when is None:
            problems.append(f"entry {entry.get('desc', '?')!r}: time {entry['time']!r} is not a time this can read")
            continue
        if when is None and entry.get("kind") != "detection":
            when = now  # a step of the work happened when this gate ran
        if when is None:
            unplaced.append(dict(entry, why="an entry with no time, and none could be given it"))
            continue
        moves_t0 = entry.get("kind") == "detection" and entry.get("time") not in (None, "")
        if moves_t0:
            malicious.append(when)  # an Alert is the first Malicious finding of its Case
        placed.append(dict(entry, when=when, moves_t0=moves_t0))

    # at one instant, what defines T0 comes first, so that it is the anchor and not what shares its time
    placed.sort(key=lambda e: (e["when"][0], not e["moves_t0"],
                               KINDS.index(e["kind"]) if e.get("kind") in KINDS else len(KINDS)))
    derived = min(malicious, key=lambda w: w[0]) if malicious else None
    stated = parse_time(ledger.get("t0"))
    if ledger.get("t0") not in (None, "") and stated is None:
        problems.append(f"t0 {ledger['t0']!r} is not a time this can read")
    t0 = stated or derived  # what the Case states is what its Note will state: the timeline must carry that one
    anchor = None
    for entry in placed:
        # only what can define T0 can carry it: a Benign finding, a piece of context or a handover at
        # the same instant is an entry like any other
        entry["is_t0"] = anchor is None and t0 is not None and entry["moves_t0"] and _same(t0, entry["when"])
        if entry["is_t0"]:
            anchor = entry
    for entry in placed:
        when = entry.pop("when")
        del entry["moves_t0"]
        entry["time"], entry["time_utc"] = when[0], _utc(when[0])
    return {
        "t0": t0[0] if t0 else None, "t0_utc": _utc(t0[0]) if t0 else None,
        "t0_entry": (anchor.get("desc") or anchor.get("id")) if anchor else None,
        # the same moment under the name the Case Schema gives it: it is T0, and anchors the metrics,
        # only once the Malicious hypothesis is proven
        "start_time": t0[0] if t0 else None, "start_time_utc": _utc(t0[0]) if t0 else None,
        "confirmed_incident": _confirmed(ledger),
        "stated_t0": stated[0] if stated else None, "derived_t0": derived[0] if derived else None,
        "stated_matches": None if not (stated and derived) else _same(stated, derived),
        "entries": placed, "unplaced": unplaced, "problems": problems,
    }


def check(built):
    """What the framework requires of a timeline, as failures a run can be held to."""
    failures = list(built.get("problems") or [])
    flagged = [e for e in built["entries"] if e.get("is_t0")]
    if built["t0"] is not None and not flagged:
        failures.append(f"T0 is {built['t0_utc']} and no entry carries it: the Note would state a first "
                        "malicious event the timeline does not show — flag the finding it comes from")
    if built.get("stated_matches") is False and built["derived_t0"] < built["stated_t0"]:
        failures.append(f"a Malicious entry at {_utc(built['derived_t0'])} happens before T0 ({_utc(built['stated_t0'])}): "
                        "T0 is the earliest Malicious event, so either T0 is wrong or the entry is not Malicious. "
                        "Context may come before T0; a Malicious finding may not")
    elif built.get("stated_t0") is not None and built.get("derived_t0") is None:
        failures.append(f"the Case states T0 {_utc(built['stated_t0'])} and nothing Malicious is known at any time: "
                        "T0 is the earliest Malicious event, so it rests on a finding the ledger does not hold")
    elif built.get("stated_matches") is False:
        failures.append(f"the Case states T0 {_utc(built['stated_t0'])} and its earliest Malicious finding is at "
                        f"{_utc(built['derived_t0'])}: nothing Malicious is known at T0, so one of the two is wrong")
    for entry in built["unplaced"]:
        failures.append(f"{entry.get('id') or entry.get('desc') or 'an entry'}: {entry.get('why')}")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ledger")
    ap.add_argument("--t0", default=None, help="the Case's stated start_time, instead of the ledger's own t0")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        with open(a.ledger, encoding="utf-8") as handle:
            ledger = json.load(handle)
    except (OSError, ValueError) as exc:
        ap.error(f"the ledger cannot be read: {exc}")
    if a.t0 is not None and isinstance(ledger, dict):
        ledger["t0"] = int(a.t0) if a.t0.isdigit() else a.t0
    built = build(ledger)
    built["failures"] = check(built)
    if a.json:
        print(json.dumps(built, indent=2, ensure_ascii=False))
    else:
        for entry in built["entries"]:
            print(f"{entry['time_utc']}  {'T0 ' if entry['is_t0'] else '   '}{entry.get('kind', '')}: "
                  f"{entry.get('desc') or entry.get('id') or ''}")
        for failure in built["failures"]:
            print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if built["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
