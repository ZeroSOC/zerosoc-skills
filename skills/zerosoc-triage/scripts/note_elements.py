#!/usr/bin/env python3
"""The elements a conformant Note renders, in order, and the checks it must pass. Standard library only.

  note_elements.py --kind triage|investigation [--note note.json] [--json]

The framework says which elements a Note renders and in what order, and what makes one
non-conformant (Detection & Analysis §1.6 and §2.5). That is **structure and conformance**, and it
belongs with the method rather than with whatever assembled the Note last.

What this script does **not** do is write the Note. The Summary, the Rationale, each Finding's
wording and the deployment's language are the executor's: a Note produced by a template would be a
form, and the framework asks for an account. The script renders the structure and runs the checks;
the executor renders the content.

Without --note it prints the elements of that Note kind, in order, with what each must contain.
With --note it also checks an assembled Note and exits 1 on any failure.

note.json is **the ledger with the prose beside it** — the ledger of triage_decide.py or resolve.py, so
nothing is copied into a second shape, plus one field per element the framework names:

{"kind": "triage",
 "classification": {...}, "summary": "...", "rationale": "...", "provenance": {...},
 "findings": [{"id": "F1", "desc": "...", "side": "Malicious"|"Benign"|null,
               "confidence": "Low|Medium|High", "event_refs": ["<event id or link>"]}],
 "alerts": [...], "detection_metadata": {...}, "visibility_gaps": [{"data_source", "check_prevented"}],
 "timeline": [...], "reclassification_pivots": [...]}

An element's field is the framework's own name for it, lower-cased and joined with underscores —
"Visibility Gaps" is `visibility_gaps` — so an element the framework adds or renames is required under
its new name with no change here. Two are shorter by habit: "Case Timeline" is `timeline` and
"Re-classification Pivots" is `reclassification_pivots`. A finding with side null is context. A finding
written as {"n", "finding", "tag": {"side", "confidence_id"}} is read too.
"""
import argparse, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from alert_metadata import dispositions
except ImportError:  # the shared script is copied next to this one by tools/build_references.py
    dispositions = None

# a technique code that no "(Name)" follows. The code is taken whole — a sub-technique's ".003"
# and a bold or code mark around it included — before the name is looked for, so that
# "T1114.003 (Email Forwarding Rule)" is never read as a bare "T1114"
TECHNIQUE_BARE = re.compile(r"(?<![\w./])((?:AML\.)?T\d{4}(?:\.\d{3})?)(?![\d.]*\d)(?![*`_\]]*\s*\()")
ADDRESS = re.compile(r"\]\([^)\s]*\)|https?://\S+")  # a link's target and a bare URL: an address, not prose
HERE = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK = os.path.normpath(os.path.join(HERE, "..", "references", "framework"))
METHOD = os.path.join("03-Processes", "02-detection_and_analysis.md")

SECTIONS = {"triage": "1.6 Triage Note", "investigation": "2.5 Investigation Note"}
"""Where the framework states the elements of each Note kind. The order and the words are read
from there — the skills execute the framework's method and never restate it."""

SHORTER = {"case_timeline": "timeline", "re_classification_pivots": "reclassification_pivots"}
"""The two elements whose field is shorter than the framework's name for them."""

NUMBERED = re.compile(r"^(\s*)\d+\.\s+(.*)$")
RESERVED = ("kind", "alerts", "detection_metadata")  # fields of a Note that are not elements of it
ELEMENT = re.compile(r"^\*\*(.+?)\*\*\s*[—–-]\s*(.*)$")

# how the framework says an element may have nothing to render — in the element's own line, never in
# a paragraph under it that may quote the word about something else: it is told to render or write
# "None.", or it is "any" change, where there may be none
EMPTY = re.compile(r'(?:renders?|write)\s+["“]None\.["”]|^any\s', re.I)
CONFIDENCE = {"low": 1, "medium": 2, "high": 3, "1": 1, "2": 2, "3": 3}
PLACEHOLDER = "(state the check"  # what select_playbook.py prints where the executor states the check


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


def _field(name):
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return SHORTER.get(slug, slug)


def elements(kind, root=FRAMEWORK):
    """The elements of a conformant Note of this kind, in the order the framework renders them.

    Read from the framework itself, so the order, the names and the words are the ones an analyst
    reads in the method. `renders` is everything the framework says the element contains, the
    paragraphs under its numbered line included. The elements are the numbered lines at the depth of
    the first one: a list inside an element is part of that element, and prose at the margin between
    two elements does not end the list. A numbered line this cannot read as an element, a name that
    gives no field, or two names that give the same one, stops the script: an element that silently
    left the list would leave the check with it.
    """
    found, depth, after = [], None, []
    for line in _section(_method(root), SECTIONS[kind]):
        numbered = NUMBERED.match(line)
        if numbered and depth in (None, len(numbered.group(1))):
            depth = len(numbered.group(1))
            matched = ELEMENT.match(numbered.group(2).strip())
            if not matched:
                raise SystemExit(f"the method's section {SECTIONS[kind]!r} has a numbered line this script cannot "
                                 f"read as an element (**Name** — what it renders): {line.strip()[:80]!r}")
            name = re.sub(r"[`*]", "", matched.group(1)).strip()
            if after:  # what stood between two elements belongs to the one above it
                found[-1]["renders"] += " " + " ".join(after)
                after = []
            found.append({"element": _field(name), "name": name, "renders": matched.group(2).strip(),
                          "may_be_empty": bool(EMPTY.search(matched.group(2)))})
        elif found and line.strip():
            if line.startswith((" ", "\t")) and not after:
                found[-1]["renders"] += " " + line.strip()
            else:
                after.append(line.strip())  # the section's own prose, unless another element follows
    if not found:
        raise SystemExit(f"no elements found in the method's section {SECTIONS[kind]!r}")
    fields = [e["element"] for e in found]
    for element in found:
        if not element["element"] or element["element"] in RESERVED or fields.count(element["element"]) > 1:
            raise SystemExit(f"the element {element['name']!r} of {SECTIONS[kind]!r} gives the field "
                             f"{element['element']!r}, which is empty, taken by another element, or a field of the "
                             "ledger: name its field in SHORTER")
    return found


def _blank(value):
    """Nothing a reader can read: no text, and no list or object that holds any."""
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, dict):
        return all(_blank(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return all(_blank(v) for v in value)
    return True  # a number or a flag is not an element of a Note


def _texts(value, depth=0):
    if isinstance(value, str):
        yield value
    elif depth < 12 and isinstance(value, dict):
        for held in value.values():
            yield from _texts(held, depth + 1)
    elif depth < 12 and isinstance(value, (list, tuple)):
        for held in value:
            yield from _texts(held, depth + 1)


def _listed(value):
    """What a field that lists things holds, however it was written: one item is a list of one."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _bare(text):
    return TECHNIQUE_BARE.findall(ADDRESS.sub("]", str(text)))


def _read(finding):
    """One finding, from either shape: (label, text, side, confidence, event references)."""
    tag = finding.get("tag") if isinstance(finding.get("tag"), dict) else {}
    side = finding.get("side", tag.get("side"))
    side = None if side is None or str(side).strip().lower() in ("", "context") else str(side).strip().lower()
    stated = finding.get("confidence", tag.get("confidence_id"))
    if isinstance(stated, float) and stated.is_integer():
        stated = int(stated)
    confidence = None if stated in (None, "") or isinstance(stated, bool) else CONFIDENCE.get(str(stated).strip().lower(), 0)
    cited = [r for r in _listed(finding.get("event_refs")) if not isinstance(r, bool)
             and (r.get("uid") if isinstance(r, dict) else str(r if r is not None else "").strip())]
    label = finding.get("id", finding.get("n", "?"))
    return label, str(finding.get("desc") or finding.get("finding") or ""), side, confidence, cited


def check(note, kind=None, root=FRAMEWORK):
    """What makes this Note non-conformant, in the framework's terms. Empty means conformant."""
    if not isinstance(note, dict):
        return [f"a Note is an object with one field per element; this is a {type(note).__name__}"]
    kind = kind or note.get("kind") or "triage"
    if kind not in SECTIONS:
        return [f"the Note says it is a {kind!r} Note; the framework has {' and '.join(sorted(SECTIONS))} Notes"]
    failures = []
    if note.get("kind") and note["kind"] != kind:
        failures.append(f"the Note says it is a {note['kind']} Note and is checked as a {kind} Note")

    findings = note.get("findings") or []
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        return failures + ["findings is a list of findings, each an object with its side, confidence and events"]
    alerts = [a for a in _listed(note.get("alerts")) if isinstance(a, dict)]

    listed = elements(kind, root)
    for element in listed:
        held = note.get(element["element"])
        if element["element"] == "findings":
            held = findings or alerts  # the Alerts are the Case's first Findings, wherever the ledger keeps them
        if not element["may_be_empty"] and (_blank(held) or str(held).strip().rstrip(".").lower() == "none"):
            failures.append(f"the Note renders no {element['name']}: the framework's {kind} Note requires it")

    ids = set()
    for finding in findings:
        if isinstance(finding.get("tag"), str):
            failures.append(f"finding {finding.get('id', finding.get('n', '?'))}: the tag is the text "
                            f"{finding['tag']!r}; state \"side\" and \"confidence\" as the ledger does")
            continue
        label, text, side, confidence, cited = _read(finding)
        ids.add(str(label))
        where = f"finding {label}"
        if not text.strip():
            failures.append(f"{where} says nothing: a Finding is stated in accurate terms")
        if side not in (None, "malicious", "benign"):
            failures.append(f"{where}: side is {side!r}; the framework has Malicious, Benign, or neither for context")
        elif side and not confidence:
            failures.append(f"{where}: {side} with no confidence (Low, Medium or High); a side without one is not a finding")
        elif side is None and confidence is not None:
            failures.append(f"{where}: context carries a confidence; context bears on no hypothesis")
        if not cited:
            failures.append(f"{where}: cites no event; a Finding without a traceable reference is not conformant")

    # "whenever technique codes appear in a Note": every element's text. Of a finding, what the Note
    # renders — its text, what produced it, why it was retracted — and not the ledger's own data
    for element in listed:
        if element["element"] == "findings":
            texts = [t for f in findings for name in ("desc", "finding", "analytic", "retraction_reason")
                     for t in _texts(f.get(name))]
        else:
            texts = list(_texts(note.get(element["element"])))
        for bare in sorted({b for text in texts for b in _bare(text)}):
            failures.append(f"{element['name']}: technique {bare} is written bare; the framework writes ID (Name)")

    gaps = _listed(note.get("visibility_gaps"))
    for gap in gaps:
        if not isinstance(gap, dict):
            failures.append(f"visibility gap {gap!r} is not paired with the check it prevented: "
                            "{\"data_source\", \"check_prevented\"}")
            continue
        prevented = str(gap.get("check_prevented") or "").strip()
        if not prevented or prevented.startswith(PLACEHOLDER):
            failures.append(f"visibility gap {gap.get('data_source')!r} names no check it prevented")
    recorded = {str(g.get("data_source", "")).strip().lower() for g in gaps if isinstance(g, dict)}
    return failures + _asserted(note, alerts, findings, ids, recorded)


def _asserted(note, alerts, findings, finding_ids, recorded_gaps):
    """§1.6 item 3: each Alert Finding renders what its detection asserted, and the dispositions of
    the recommended actions render with the Findings. Triage keeps the Case's alerts in "alerts";
    investigation keeps them among its findings, each with its "alert_type"."""
    failures = []
    among = [f for f in findings if f.get("alert_type")]
    record = note.get("detection_metadata")
    if not isinstance(record, dict) or not isinstance(record.get("alerts", []), list) \
            or not all(isinstance(a, dict) for a in record.get("alerts", [])):
        if record is not None:
            failures.append("detection_metadata is the output of alert_metadata.py: {\"alerts\": [{\"id\", "
                            "\"techniques\", \"recommended_actions\", \"absent\", ...}], ...}")
        elif alerts or among:
            failures.append(f"the Note holds {len(alerts) + len(among)} Alert(s) and no detection_metadata: each Alert "
                            "Finding renders what its detection asserted (techniques, threat, source, remediation state)")
        return failures
    read = {str(a.get("id")) for a in record["alerts"]} if record.get("alerts") else set()
    # A deployment that declares no source profile reads nothing of §1.1 — there are no field names
    # to read it under — and alert_metadata.py answers with that as a visibility gap and no alerts.
    # The Note then renders no assertion because the run could gather none, and it says so where it
    # says what it could not check: a gap is the framework's answer to a source it cannot read, and
    # the Note is not less conformant for holding it. What a gap does not excuse is an assertion the
    # source supplied and the Note dropped, which is the case below.
    blind = any(gap.startswith("alert metadata") for gap in recorded_gaps)
    for alert in alerts:
        if str(alert.get("id")) not in read and not blind:
            failures.append(f"alert {alert.get('id')} renders nothing of what its detection asserted")
    if among and not read and not blind:
        failures.append(f"{len(among)} Alert Finding(s) and a detection_metadata that read no alert: each renders "
                        "what its detection asserted")
    actions = []
    for alert in record.get("alerts") or []:
        for technique in _listed(alert.get("techniques")):
            rendered = str((technique.get("rendered") or technique.get("id") or "") if isinstance(technique, dict) else technique)
            if _bare(rendered):
                failures.append(f"alert {alert.get('id')}: technique {rendered} is written bare; the framework writes "
                                "ID (Name) — a technique its tables do not hold is named as ATT&CK or ATLAS names it")
        for absent in _listed(alert.get("absent")):
            if f"alert metadata: {absent}".lower() not in recorded_gaps:
                failures.append(f"alert {alert.get('id')}: the source did not supply the {absent}, and no "
                                "Visibility Gap says so with the check it prevented")
        for action in _listed(alert.get("recommended_actions")):
            if isinstance(action, dict):
                actions.append(action)
            else:
                failures.append(f"alert {alert.get('id')}: the recommended action {action!r} carries no disposition")
    state = dispositions(actions) if dispositions else {"open": [a.get("id") for a in actions], "followed": []}
    for action in actions:
        if action.get("id") in state["open"]:
            failures.append(f"recommended action {action.get('id')} is neither followed nor set aside with a stated reason")
        elif action.get("id") in state["followed"] and str(action.get("finding") or "") not in finding_ids:
            failures.append(f"recommended action {action.get('id')} was followed and names no Finding it produced: "
                            "one followed renders as that Finding, naming the recommendation it came from")
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
        try:
            with open(a.note, encoding="utf-8") as handle:
                held = json.load(handle)
        except (OSError, ValueError) as exc:
            ap.error(f"the Note cannot be read: {exc}")
        out["failures"] = check(held, a.kind, a.root)
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
