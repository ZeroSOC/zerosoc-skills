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
  "observations": [{"id": "F1", "desc": "...", "side": "Malicious"|"Benign"|null, "confidence": "Low|Medium|High",
                "covers": ["DF-1"], "condition": "false_positive"|"benign"|null, "artifact": "hash:...",
                "retracted": false, "event_refs": ["<event id or link>"], "first_seen": "2026-09-14T14:55:41Z",
                "timeline": false}],
  "evidence_inventory": {"extracted": 31, "source_count": 31, "complete": true},
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
relates, stands beyond the alerts. "first_seen" is when the thing it reports
happened (not when the observation was made) and "timeline" flags it for the Case Timeline: this rule reads
neither, and note_elements.py and timeline.py read them from this same ledger.
"condition" on a Benign observation is the kind of the playbook condition it named, read off the list the
condition belongs to (Playbook Architecture §4.1) — never a kind the executor labelled itself. The verdict a
Close carries is the rule's (§1.5): Benign (5) when the covering observation of the highest confidence names a
Benign condition, False Positive (1) otherwise — both kinds at that confidence, or no condition named at all.
--close-as is read only for a ledger whose observations carry no "condition" key, written before it existed.
Observations with side null are context and do not score. A Benign observation with no "covers" covers every alert.
Prints the decision, the coverage per alert, the confidence leaving triage and the verdict to record.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


def restates_alerts(f, ids):
    """A Malicious observation that cites one alert and nothing else says of it what its detection already
    asserted: the alert is weighed by the coverage rule and is not counted twice as evidence beyond itself.
    One that cites two alerts relates them, and one that cites an evidence item or a check's result read
    something the detection did not state — both stand beyond the alerts (§1.5)."""
    refs = [str(r) for r in (f.get("event_refs") or []) if r]
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


def _decide(ledger):
    alerts = dedupe_alerts(ledger.get("alerts", []))
    active = [f for f in ledger.get("observations", []) if not f.get("retracted") and f.get("side") in ("Malicious", "Benign")]
    ids = alert_ids(ledger)
    restated = [f for f in active if f["side"] == "Malicious" and restates_alerts(f, ids)]
    mal = [f for f in active if f["side"] == "Malicious" and f not in restated]
    ben = [f for f in active if f["side"] == "Benign"]
    coverage = []
    for a in alerts:
        covering = [b for b in ben if not b.get("covers") or a["id"] in b["covers"]]
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
              "benign_observations": [f["id"] for f in ben]}
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
    r = decide(ledger)
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
    if r.get("evidence_inventory_note"): print("Note: " + r["evidence_inventory_note"])
    for note in r.get("detection_notes", []): print("Note: " + note)


if __name__ == "__main__":
    main()
