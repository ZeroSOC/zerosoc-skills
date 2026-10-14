#!/usr/bin/env python3
"""Apply the triage decision rule of Detection & Analysis §1.5 to an observations ledger. Standard library only.

  triage_decide.py ledger.json [--close-as fp|benign] [--json]

Ledger (JSON):
{
  "case_uid": "CASE-1",
  "playbook": "04-Playbooks/01-Triage/endpoint.md", "playbook_version": "2026-09-16", "domain": "Endpoint",
  "alerts":   [{"id": "DF-1", "type": "Credential dumping", "entity": "host-1", "confidence": "High"|null,
                "severity": "High", "technique": "T1003"}],
  "detection_metadata": {...},   the output of scripts/alert_metadata.py: what each Alert's detection
                                 asserts (§1.1), the remediation the source already performed, and the
                                 assertions it did not supply
  "observations": [{"id": "O1", "desc": "...", "side": "Malicious"|"Benign"|null, "confidence": "Low|Medium|High",
                "about": ["<entity name or hash>"], "covers": ["DF-1"],
                "not_covering": [{"alert": "DF-2", "reason": "..."}],
                "condition": "false_positive"|"benign"|null, "artifact": "hash:...",
                "retracted": false, "event_refs": ["<event id or link>"], "first_seen": "2026-09-14T14:55:41Z",
                "timeline": false}],
  "evidence_inventory": {"extracted": 31, "source_count": 31, "source_count_basis": "source", "complete": true},
  "entities": [{"type": "file", "name": "...", "sha256": "...", "alert_ids": ["DF-1"], ...}],
                                 the inventory's entities, as scripts/evidence_inventory.py --json lists them
  "no_information_refs": ["<event id>"], "scoped_negative_refs": ["<event id>"],
  "visibility_gaps": [{"data_source": "...", "check_prevented": "..."}],
  "duplicate_of": null | "CASE-0"
}
Alerts are the first Malicious observations at the tool's confidence, or at the level their severity maps to.
The confidence leaving triage rises on independent alerts of different types **or techniques**, which are
the techniques the detections named. The coverage rule itself is unchanged: what the source already
neutralized is reported with the decision and never weighed into it — a block is a response, not an
explanation. What a source recommends is indicative (§1.5): a recommendation the run made nothing of
holds nothing up.
"event_refs" are the events an observation rests on: a Malicious observation that cites nothing but one alert
of the ledger (its own id and the ids merged into it) says of that alert what its detection asserted — it
**restates** it (§1.5), is set aside however it is tagged, and is reported under "restated_alerts". One that
cites a check's result, an item of the alert's own evidence it read further, or two or more alerts it
relates, stands beyond the alerts. "no_information_refs" are the results that carried no information (a
lookup that knows nothing of the indicator, a search that finds no approval, a lookup not answered) and
"scoped_negative_refs" the checks that covered the question and found nothing, which are cited like any
other result (§2.4). An observation is read without the first kind, on either side: one that rests on them
alone carries no weight, Benign or Malicious, covers nothing and is reported under "no_information", and a
Malicious one that rests on them and an alert restates the alert. A reference is one kind or the other,
never both. A ledger with no "scoped_negative_refs" key is read the same way, and "no_information_note" says
so (scripts/no_information.py). "first_seen" is when the thing it reports
happened (not when the observation was made) and "timeline" flags it for the Case Timeline: this rule reads
neither, and note_elements.py and timeline.py read them from this same ledger.
"condition" on a Benign observation is the kind of the playbook condition it named, read off the list the
condition belongs to (Playbook Architecture §4.1) — never a kind the executor labelled itself. The verdict a
Close carries is the rule's (§1.5): Benign (5) when the covering observation of the highest confidence names a
Benign condition, False Positive (1) otherwise — both kinds at that confidence, or no condition named at all.
--close-as is read only for a ledger whose observations carry no "condition" key, written before it existed.
Observations with side null are context and do not score.
Which alerts a Benign observation covers is read off the evidence, not chosen (#59): "about" names the
entities of "entities" it rests on, each by any value the inventory holds for it (its name, a hash, a sign-in
name, case aside), and the observation covers every alert that cites one of them, together with any alert
"covers" names. An alert it does not explain is left out only through "not_covering" with a reason; one
without a reason is ignored and reported under "coverage_note". A Benign observation with neither "about" nor
"covers" covers no alert. A ledger with no "entities" key, written before them, is read as it was — a Benign
observation with no "covers" covers every alert — and "coverage_note" says so.
Prints the decision, the coverage per alert, the confidence leaving triage and the verdict to record.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import no_information  # copied next to this script by tools/build_references.py
try:
    from evidence_inventory import note as inventory_note
except ImportError:  # the shared script is copied next to this one by tools/build_references.py
    inventory_note = None
try:
    from alert_metadata import decision_notes, neutralized, techniques_of
except ImportError:
    decision_notes = neutralized = techniques_of = None

W = {"Low": 1, "Medium": 2, "High": 3}
LEVELS = ["Low", "Medium", "High"]
SEV2CONF = {"Informational": "Low", "Low": "Low", "Medium": "Medium", "High": "High", "Critical": "High"}


def alert_confidence(a):
    return a.get("confidence") or SEV2CONF.get(a.get("severity", "Medium"), "Medium")


def dedupe_alerts(alerts):
    best = {}
    for a in alerts:
        key = (a.get("type", "").strip().lower(), a.get("entity", "").strip().lower())
        c = alert_confidence(a)
        if key not in best or W[c] > W[alert_confidence(best[key])]:
            best[key] = dict(a, confidence=c)
    return list(best.values())


def alert_ids(ledger):
    """Which alert of the ledger each id belongs to: its own id and the ones merged into it."""
    out = {}
    for n, a in enumerate(ledger.get("alerts", [])):
        for i in [a.get("id"), *(a.get("merged_ids") or [])]:
            if i:
                out[str(i)] = n
    return out


def restates_alerts(f, ids, empty=frozenset()):
    """A Malicious observation that cites one alert and nothing else says of it what its detection already
    asserted: the alert is weighed by the coverage rule and is not counted twice as evidence beyond itself.
    One that cites two alerts relates them, and one that cites an evidence item or a check's result read
    something the detection did not state — both stand beyond the alerts (§1.5)."""
    refs = no_information.informative(f, empty)
    return bool(refs) and all(r in ids for r in refs) and len({ids[r] for r in refs}) == 1


def close_verdict(covering):
    """§1.5: the verdict a Close carries, from the conditions the covering Benign observations named.

    The covering observation of the highest confidence decides: Benign (5) when it names a Benign
    condition and no False Positive one is named at that confidence; False Positive (1) otherwise —
    including when no covering observation names a condition of either list. None when the ledger
    predates the field: no observation carries a "condition" key at all."""
    if not any("condition" in f for f in covering):
        return None, None
    top = max((W[f["confidence"]] for f in covering), default=0)
    kinds = {f.get("condition") for f in covering if W[f["confidence"]] == top}
    if "benign" in kinds and "false_positive" not in kinds:
        return 5, "Benign Positive"
    return 1, "False Positive"


EMIT = {1: "tuning ticket to Phase 1", 5: "exception ticket: the Knowledge Base entry proposed for a person to confirm, unless the Knowledge Base already holds it"}


NAMES = ("name", "value", "sha256", "sha1", "md5", "upn", "account", "address")
"""The values an inventory entity can be named by in an observation's "about"."""


def _named(value):
    value = str(value or "").strip().lower()
    return value.split(":", 1)[1] if value.startswith(("sha256:", "sha1:", "md5:")) else value


def entity_alerts(ledger):
    """Each value an entity of the inventory is named by -> the alerts whose evidence cites that entity."""
    out = {}
    for entity in ledger.get("entities") or []:
        cited = {str(i) for i in entity.get("alert_ids") or []}
        for field in NAMES:
            if entity.get(field):
                out.setdefault(_named(entity[field]), set()).update(cited)
    return out


def covered_by(b, ledger, cites, notes):
    """The alerts a Benign observation covers (#59). None means every alert: a ledger written before
    "entities", where an observation with no "covers" covered everything."""
    if "entities" not in ledger and not b.get("covers") and not b.get("about"):
        return None
    alerts = {str(a) for a in b.get("covers") or []}
    for value in b.get("about") or []:
        alerts |= cites.get(_named(value), set())
    for left in b.get("not_covering") or []:
        alert = str(left.get("alert") if isinstance(left, dict) else left)
        if isinstance(left, dict) and str(left.get("reason") or "").strip():
            alerts.discard(alert)
        else:
            notes.append(f"{b['id']} leaves out {alert} without a reason, and still covers it")
    return alerts


def _decide(ledger):
    alerts = dedupe_alerts(ledger.get("alerts", []))
    active = [f for f in ledger.get("observations", []) if not f.get("retracted") and f.get("side") in ("Malicious", "Benign")]
    ids = alert_ids(ledger)
    empty, empty_note = no_information.refs(ledger)
    weightless = [f for f in active if no_information.carries_nothing(f, empty)]
    restated = [f for f in active if f["side"] == "Malicious" and f not in weightless and restates_alerts(f, ids, empty)]
    mal = [f for f in active if f["side"] == "Malicious" and f not in restated and f not in weightless]
    ben = [f for f in active if f["side"] == "Benign" and f not in weightless]
    coverage, notes = [], []
    cites = entity_alerts(ledger)
    covers = {b["id"]: covered_by(b, ledger, cites, notes) for b in ben}
    owners = alert_ids(ledger)
    for a in alerts:
        # an alert stands for every ledger alert of its type on its entity, and for the ids merged into it
        mine = {i for i, n in owners.items()
                if (ledger["alerts"][n].get("type", "").strip().lower(), ledger["alerts"][n].get("entity", "").strip().lower())
                == (a.get("type", "").strip().lower(), a.get("entity", "").strip().lower())}
        covering = [b for b in ben if covers[b["id"]] is None or covers[b["id"]] & (mine or {a["id"]})]
        if a["confidence"] == "High":
            covered = any(b["confidence"] == "High" for b in covering)
            rule = "High alert: needs a Benign (High) observation"
        else:
            total = sum(W[b["confidence"]] for b in covering)
            covered = total > W[a["confidence"]]
            rule = f"Benign weights {total} vs alert weight {W[a['confidence']]} (needs more)"
        coverage.append({"alert": a["id"], "confidence": a["confidence"], "covered": covered, "covering": [b["id"] for b in covering], "rule": rule})
    all_covered = bool(alerts) and all(c["covered"] for c in coverage)
    close_ok = not mal and all_covered
    result = {"case_uid": ledger.get("case_uid"), "alerts_considered": [a["id"] for a in alerts], "coverage": coverage,
              "malicious_beyond_alerts": [f["id"] for f in mal], "restated_alerts": [f["id"] for f in restated],
              "no_information": [f["id"] for f in weightless],
              "benign_observations": [f["id"] for f in ben]}
    if empty_note:
        result["no_information_note"] = empty_note
    if "entities" not in ledger and ben:
        notes.append("the ledger names no entities: a Benign observation with no covers is read as covering"
                     " every alert, as before #59")
    if notes:
        result["coverage_note"] = "; ".join(notes)
    if ledger.get("duplicate_of"):
        result.update(decision="Close", verdict_id=10, verdict="Duplicate", master_case_uid=ledger["duplicate_of"],
                      reminder="Duplicate only if all four §1.5 criteria were validated: matching core entities, overlapping timeline, active assignment, evidence merged.")
    elif close_ok:
        covering_ids = {i for c in coverage for i in c["covering"]}
        verdict_id, verdict = close_verdict([b for b in ben if b["id"] in covering_ids])
        if verdict_id is None:
            result.update(decision="Close", verdict_id=None, verdict="False Positive (1) if a False Positive condition explains the alerts; Benign (5) if a Benign condition does (use --close-as)")
        else:
            result.update(decision="Close", verdict_id=verdict_id, verdict=verdict, emit=EMIT[verdict_id],
                          verdict_rule="the covering observation of the highest confidence names a Benign condition" if verdict_id == 5
                          else "no Benign condition named by a covering observation of the highest confidence")
    else:
        why = []
        if mal: why.append("Malicious observations exist beyond the alerts: " + ", ".join(f["id"] for f in mal))
        if not all_covered: why.append("not every alert is covered: " + ", ".join(c["alert"] for c in coverage if not c["covered"]))
        if not alerts: why.append("no alert in the Case")
        result.update(decision="Promote", verdict_id=0, verdict="none (promoted Cases carry no verdict)", why=why)
    # confidence (§1.5): on a Close, the strongest Benign observation; on a Promote, the confidence leaving triage
    if alerts and close_ok and not ledger.get("duplicate_of"):
        level = max(W[b["confidence"]] for b in ben)
        notes = ["close: the highest confidence on the Benign side"]
        result.update(confidence_id=level, confidence=LEVELS[level - 1], confidence_notes=notes)
    elif alerts:
        level = max(W[a["confidence"]] for a in alerts)
        named = techniques_of(ledger.get("detection_metadata")) if techniques_of else {}
        kinds = set()
        for a in alerts:
            ids = [i for i in [a["id"], *(a.get("merged_ids") or [])] if named.get(i)]
            asserted = frozenset(str(t).strip().upper() for i in ids for t in named[i])
            # one shape for a kind, so the same kind named twice counts once: the techniques the
            # detection named, or, where it named none, the alert type itself
            kinds.add(asserted or frozenset({(a.get("technique") or a.get("type", "")).strip().lower()}))
        artifacts = {f.get("artifact") or f["id"] for f in mal}
        raised = len(kinds) >= 2 or len(artifacts) >= 2
        if raised: level += 1
        lowered = bool(ben) and not close_ok
        if lowered: level -= 1
        level = max(1, min(3, level))
        notes = []
        if raised: notes.append("+1: independent alerts of different types/techniques or two or more independent Malicious observations")
        if lowered: notes.append("-1: Benign observations exist but do not close the Case")
        result.update(confidence_id=level, confidence=LEVELS[level - 1], confidence_notes=notes)
    return result


def decide(ledger):
    """The §1.5 decision, with the evidence inventory and what the detection asserts read at the gate.

    The coverage rule is untouched by either: an incomplete inventory is reported beside the
    decision, and what the source recommends is indicative and holds nothing up.
    """
    r = _decide(ledger)
    inventory = inventory_note(ledger.get("evidence_inventory")) if inventory_note else None
    if inventory:
        r["evidence_inventory_note"] = inventory
    record = ledger.get("detection_metadata")
    if decision_notes:
        r["detection_notes"] = decision_notes(record, ledger)
    if record:
        r["neutralized_entities"] = neutralized(record)
        if record.get("candidate_incident_categories"):
            r["candidate_incident_categories"] = record["candidate_incident_categories"]
    return r


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    if not args:
        print(__doc__); sys.exit(2)
    ledger = json.load(open(args[0]))
    try:
        r = decide(ledger)
    except ValueError as exc:
        sys.exit(f"invalid ledger: {exc}")
    if "--close-as" in sys.argv and r["decision"] == "Close" and r.get("verdict_id") is None:
        # a ledger written before observations carried their condition: the caller says which kind
        kind = sys.argv[sys.argv.index("--close-as") + 1].lower()
        r["verdict_id"], r["verdict"] = (1, "False Positive") if kind == "fp" else (5, "Benign Positive")
        r["emit"] = EMIT[r["verdict_id"]]
    if "--json" in sys.argv:
        print(json.dumps(r, indent=2)); return
    print(f"Decision: {r['decision']}  verdict: {r.get('verdict')}")
    for c in r["coverage"]:
        print(f"  alert {c['alert']} ({c['confidence']}): {'covered' if c['covered'] else 'NOT covered'} by {c['covering'] or '-'} — {c['rule']}")
    if r.get("why"): print("  why: " + "; ".join(r["why"]))
    if "confidence" in r:
        print(f"Confidence leaving triage: {r['confidence']} ({r['confidence_id']})" + (" — " + "; ".join(r["confidence_notes"]) if r["confidence_notes"] else ""))
    if r.get("emit"): print("Emit: " + r["emit"])
    if r.get("reminder"): print(r["reminder"])
    if r.get("candidate_incident_categories"):
        print("Candidate Incident Categories from the techniques the detections named: " + ", ".join(r["candidate_incident_categories"]))
    if r.get("no_information"): print("Carry no information (not counted): " + ", ".join(r["no_information"]))
    for key in ("evidence_inventory_note", "no_information_note"):
        if r.get(key): print("Note: " + r[key])
    for note in r.get("detection_notes", []): print("Note: " + note)


if __name__ == "__main__":
    main()
