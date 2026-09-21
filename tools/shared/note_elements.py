#!/usr/bin/env python3
"""The elements a conformant Note renders, in order, and the checks it must pass. Standard library only.

  note_elements.py --kind triage|investigation [--note note.json] [--json]

The framework says which elements a Note renders and in what order, and what makes one
non-conformant (Detection & Analysis §1.6 and §2.5). That is **structure and conformance**, and it
belongs with the method rather than in whatever host assembled the Note last.

What this script does **not** do is write the Note. The Summary, the Rationale, each Finding's
wording and the deployment's language are the executor's: a Note produced by a template would be a
form, and the framework asks for an account. The script renders the structure and runs the checks;
the model renders the content.

Without --note it prints the elements of that Note kind, in order, with what each must contain.
With --note it also checks an assembled Note and exits 1 on any failure.

note.json: the Note as the executor assembled it —
{"kind": "triage", "language": "en", "classification": {...}, "summary": "...",
 "findings": [{"n": 1, "finding": "...", "tag": {"side": "malicious|benign|context",
               "confidence_id": 1|2|3|null}, "event_refs": ["..."]}],
 "rationale": {"rationale": "..."}, "timeline": [...], "visibility_gaps": [{...}],
 "provenance": {...}, "detection_metadata": {...}}
"""
import argparse, json, re, sys

TECHNIQUE_BARE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b(?!\s*\()")

ELEMENTS = {
    "triage": [
        ("classification", "severity, confidence and impact, the candidate Incident Categories, and the decision: Close (with the verdict) or Promote"),
        ("summary", "a factual account current at this gate: what happened and when, which entities, who acted on whom, the root cause where it was found"),
        ("findings", "every Finding the Case holds, each with its side and confidence or marked context, with what produced it and the events it rests on"),
        ("rationale", "one or two sentences citing the Findings: why the decision follows"),
        ("timeline", "the Findings flagged for the narrative, in first_seen_time order; 'None.' when nothing is flagged"),
        ("visibility_gaps", "every required source unavailable and every §1.1 input the source did not supply, each with the check it prevented; 'None.' when none"),
        ("provenance", "the playbooks and their versions, the executor classes, the capability classes, the Case id"),
    ],
    "investigation": [
        ("classification", "severity, confidence, impact, the confirmed Incident Category and the verdict"),
        ("summary", "the account as it now stands, with what the queries established"),
        ("findings", "the Alerts, the triage Findings each verified or retracted with the reason, and the result of each validation query"),
        ("rationale", "why the verdict follows, citing the Findings"),
        ("reclassification_pivots", "every candidate category change, with the reason and the evidence"),
        ("timeline", "the Case Timeline, whose earliest confirmed malicious event is T0"),
        ("visibility_gaps", "the gaps of this phase, each with the check it prevented"),
        ("provenance", "as the Triage Note, plus the pointer to preserved evidence once there is one"),
    ],
}

SIDES = ("malicious", "benign", "context")


def elements(kind):
    """The elements of a conformant Note of this kind, in the order the framework renders them."""
    return [{"element": name, "renders": renders} for name, renders in ELEMENTS[kind]]


def check(note, kind=None):
    """What makes this Note non-conformant, in the framework's terms. Empty means conformant."""
    kind = kind or note.get("kind") or "triage"
    failures = []
    for name, _ in ELEMENTS[kind]:
        if name in ("timeline", "visibility_gaps", "reclassification_pivots"):
            continue  # an empty one renders "None."; absent is the same statement
        if not note.get(name):
            failures.append(f"the Note renders no {name}: the framework's {kind} Note requires it")

    for finding in note.get("findings") or []:
        where = f"finding {finding.get('n', '?')}"
        tag = finding.get("tag") or {}
        side = str(tag.get("side") or "").lower()
        if side not in SIDES:
            failures.append(f"{where}: side is {tag.get('side')!r}; the framework has Malicious, Benign, or context")
        elif side in ("malicious", "benign") and tag.get("confidence_id") is None:
            failures.append(f"{where}: {side} with no confidence; a side without one is not a finding")
        elif side == "context" and tag.get("confidence_id") is not None:
            failures.append(f"{where}: context carries a confidence; context bears on no hypothesis")
        if not finding.get("event_refs"):
            failures.append(f"{where}: cites no event; a Finding without a traceable reference is not conformant")
        for bare in TECHNIQUE_BARE.findall(str(finding.get("finding") or "")):
            failures.append(f"{where}: technique {bare} is written bare; the framework writes ID (Name)")

    for gap in note.get("visibility_gaps") or []:
        if not str(gap.get("check_prevented") or "").strip():
            failures.append(f"visibility gap {gap.get('data_source')!r} names no check it prevented")

    record = note.get("detection_metadata") or {}
    for alert in record.get("alerts") or []:
        for action in alert.get("recommended_actions") or []:
            state = str(action.get("disposition") or "").strip().lower().replace("_", " ")
            if state == "followed":
                continue
            if state in ("set aside", "setaside", "rejected") and str(action.get("reason") or "").strip():
                continue
            failures.append(
                f"recommended action {action.get('id')} of alert {alert.get('id')} is neither "
                "followed nor set aside with a stated reason")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kind", choices=sorted(ELEMENTS), required=True)
    ap.add_argument("--note")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = {"kind": a.kind, "elements": elements(a.kind)}
    if a.note:
        with open(a.note, encoding="utf-8") as handle:
            out["failures"] = check(json.load(handle), a.kind)
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        for n, element in enumerate(out["elements"], start=1):
            print(f"{n}. {element['element']} — {element['renders']}")
        for failure in out.get("failures", []):
            print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if out.get("failures") else 0


if __name__ == "__main__":
    sys.exit(main())
