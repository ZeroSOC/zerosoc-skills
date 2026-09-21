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
import argparse, json, os, re, sys

TECHNIQUE_BARE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b(?!\s*\()")
HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.normpath(os.path.join(HERE, "..", "references", "framework"))
METHOD = os.path.join("03-Processes", "02-detection_and_analysis.md")

SECTIONS = {"triage": "1.6 Triage Note", "investigation": "2.5 Investigation Note"}
"""Where the framework states the elements of each Note kind. The order and the words are read
from there — the skills execute the framework's method and never restate it."""

FIELDS = {
    "classification": "classification",
    "summary": "summary",
    "findings": "findings",
    "rationale": "rationale",
    "case timeline": "timeline",
    "re-classification pivots": "reclassification_pivots",
    "visibility gaps": "visibility_gaps",
    "provenance": "provenance",
}
"""The framework's name for an element, to the field a Note object carries it in. This binding is
the skill's — the framework writes for a reader, and a Note travels as data."""

OPTIONAL = ("timeline", "visibility_gaps", "reclassification_pivots")
"""Elements that render "None." when there is nothing: absent and empty are the same statement."""

ELEMENT = re.compile(r"^\s*\d+\.\s+\*\*(.+?)\*\*\s*[—-]\s*(.*)$")

SIDES = ("malicious", "benign", "context")


def _method(root):
    path = os.path.join(root, METHOD)
    if not os.path.isfile(path):
        raise SystemExit(f"{path} is missing: this skill's references/framework/ is not generated")
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _section(body, heading):
    """The lines of one numbered subsection of the method, up to the next heading of its level."""
    out, inside = [], False
    for line in body.splitlines():
        if line.startswith("### "):
            inside = line[4:].strip().startswith(heading)
            continue
        if inside and line.startswith("## "):
            break
        if inside:
            out.append(line)
    return out


def elements(kind, root=FRAMEWORK):
    """The elements of a conformant Note of this kind, in the order the framework renders them.

    Read from the framework itself, so the order and the words are the ones a human analyst reads
    in the method rather than a copy that has to be kept in step with it.
    """
    found = []
    for line in _section(_method(root), SECTIONS[kind]):
        matched = ELEMENT.match(line)
        if not matched:
            continue
        name = re.sub(r"[`*]", "", matched.group(1)).strip()
        field = FIELDS.get(name.lower())
        if field:
            found.append({"element": field, "name": name, "renders": matched.group(2).strip()})
    if not found:
        raise SystemExit(f"no elements found in the method's section {SECTIONS[kind]!r}")
    return found


def check(note, kind=None, root=FRAMEWORK):
    """What makes this Note non-conformant, in the framework's terms. Empty means conformant."""
    kind = kind or note.get("kind") or "triage"
    failures = []
    for element in elements(kind, root):
        if element["element"] in OPTIONAL:
            continue  # an empty one renders "None."; absent is the same statement
        if not note.get(element["element"]):
            failures.append(
                f"the Note renders no {element['name']}: the framework's {kind} Note requires it")

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
    ap.add_argument("--kind", choices=sorted(SECTIONS), required=True)
    ap.add_argument("--note")
    ap.add_argument("--root", default=FRAMEWORK)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = {"kind": a.kind, "elements": elements(a.kind, a.root)}
    if a.note:
        with open(a.note, encoding="utf-8") as handle:
            out["failures"] = check(json.load(handle), a.kind, a.root)
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        for n, element in enumerate(out["elements"], start=1):
            print(f"{n}. {element['name']} ({element['element']}) — {element['renders']}")
        for failure in out.get("failures", []):
            print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if out.get("failures") else 0


if __name__ == "__main__":
    sys.exit(main())
