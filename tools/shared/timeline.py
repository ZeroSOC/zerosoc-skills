#!/usr/bin/env python3
"""The Case Timeline and T0, as the framework defines them. Standard library only.

  timeline.py timeline.json [--t0 <ms>] [--json]

The timeline is a **reconstruction of the Case, not a listing of it** (Case Schema §5): its entries
are the ones flagged for the narrative, ordered by **when the thing happened** rather than when it
was recorded. T0 is the earliest confirmed malicious event — the Case's `start_time` on a confirmed
Incident — and exactly one entry carries it: two detections of the same activity share a time, and
the first of them is the anchor while the rest are entries like any other.

Input (JSON):
{
  "t0": 1789397891000,                      the earliest confirmed malicious event, or null
  "now": 1789399500000,                     when this gate ran; what the investigation's own
                                            entries are stamped with
  "entries": [
    {"time": 1789397891000, "kind": "detection", "desc": "...", "executor": "automation",
     "related_events": [{"uid": "..."}]},
    {"kind": "investigation", "desc": "Q1: ... — 3 rows", "executor": "agent",
     "related_events": [{"uid": "EVT-…"}]},     no time: it happened at this gate
    {"kind": "handover", "desc": "assignee is a human (crown-jewel): ...", "executor": "automation"}
  ]
}

Output: the entries in `time` order, each with `is_t0`, and `t0` with the entry that anchors it.
An entry with no time of its own is stamped `now`, because a step of the investigation happened
when the investigation ran. An entry with no time and no `now` is dropped and reported: a timeline
entry that cannot be placed is not an entry.
"""
import argparse, json, sys

KINDS = ("detection", "investigation", "handover", "action", "note")


def build(document):
    """The Case Timeline: ordered, T0 flagged exactly once, and what could not be placed."""
    now = document.get("now")
    t0 = document.get("t0")
    placed, unplaced = [], []
    for entry in document.get("entries") or []:
        when = entry.get("time")
        if when is None:
            when = now if entry.get("kind") != "detection" else None
        if when is None:
            unplaced.append(entry)
            continue
        placed.append(dict(entry, time=when, is_t0=False))
    placed.sort(key=lambda e: (e["time"], KINDS.index(e["kind"]) if e.get("kind") in KINDS else len(KINDS)))
    anchor = next((e for e in placed if t0 is not None and e["time"] == t0), None)
    if anchor is not None:
        anchor["is_t0"] = True
    return {
        "t0": t0,
        "t0_entry": anchor["desc"] if anchor else None,
        "entries": placed,
        "unplaced": unplaced,
    }


def check(built):
    """What the framework requires of a timeline, as failures a run can be held to."""
    failures = []
    flagged = [e for e in built["entries"] if e.get("is_t0")]
    if built["t0"] is not None and not flagged:
        failures.append("T0 is set on the Case and no entry carries it: the Note would state a "
                        "first malicious event the timeline does not show")
    if len(flagged) > 1:
        failures.append(f"{len(flagged)} entries flagged T0; T0 is one moment and one anchor")
    if built["entries"] and built["t0"] is not None and built["entries"][0]["time"] < built["t0"]:
        failures.append("an entry happens before T0: T0 is the earliest confirmed malicious event, "
                        "so either the entry is not on the timeline or T0 is wrong")
    for entry in built["unplaced"]:
        failures.append(f"an entry has no time and none could be given it: {entry.get('desc')}")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("timeline")
    ap.add_argument("--t0", type=int, default=None, help="overrides the document's own t0")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    with open(a.timeline, encoding="utf-8") as handle:
        document = json.load(handle)
    if a.t0 is not None:
        document["t0"] = a.t0
    built = build(document)
    failures = check(built)
    built["failures"] = failures
    if a.json:
        print(json.dumps(built, indent=2, ensure_ascii=False))
    else:
        for entry in built["entries"]:
            print(f"{entry['time']}  {'T0 ' if entry['is_t0'] else '   '}{entry.get('kind','')}: {entry.get('desc','')}")
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
