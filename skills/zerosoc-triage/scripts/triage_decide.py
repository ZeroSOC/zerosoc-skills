#!/usr/bin/env python3
"""Apply the triage decision rule of Detection & Analysis §1.5 to a findings ledger. Standard library only.

  triage_decide.py ledger.json [--close-as fp|benign] [--json]

Ledger (JSON):
{
  "case_uid": "CASE-1",
  "alerts":   [{"id": "DF-1", "type": "Credential dumping", "entity": "host-1", "confidence": "High"|null,
                "severity": "High", "technique": "T1003"}],
  "findings": [{"id": "F1", "desc": "...", "side": "Malicious"|"Benign"|null, "confidence": "Low|Medium|High",
                "covers": ["DF-1"], "artifact": "hash:...", "retracted": false}],
  "evidence_inventory": {"extracted": 31, "source_count": 31, "complete": true},
  "visibility_gaps": [{"data_source": "...", "check_prevented": "..."}],
  "duplicate_of": null | "CASE-0"
}
Alerts are the first Malicious findings at the tool's confidence, or at the level their severity maps to.
Findings with side null are context and do not score. A Benign finding with no "covers" covers every alert.
Prints the decision, the coverage per alert, the confidence leaving triage and the verdict to record.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from evidence_inventory import note as inventory_note
except ImportError:  # the shared script is copied next to this one by tools/build_references.py
    inventory_note = None

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


def _decide(ledger):
    alerts = dedupe_alerts(ledger.get("alerts", []))
    active = [f for f in ledger.get("findings", []) if not f.get("retracted") and f.get("side") in ("Malicious", "Benign")]
    mal = [f for f in active if f["side"] == "Malicious"]
    ben = [f for f in active if f["side"] == "Benign"]
    coverage = []
    for a in alerts:
        covering = [b for b in ben if not b.get("covers") or a["id"] in b["covers"]]
        if a["confidence"] == "High":
            covered = any(b["confidence"] == "High" for b in covering)
            rule = "High alert: needs a Benign (High) finding"
        else:
            total = sum(W[b["confidence"]] for b in covering)
            covered = total > W[a["confidence"]]
            rule = f"Benign weights {total} vs alert weight {W[a['confidence']]} (needs more)"
        coverage.append({"alert": a["id"], "confidence": a["confidence"], "covered": covered, "covering": [b["id"] for b in covering], "rule": rule})
    all_covered = bool(alerts) and all(c["covered"] for c in coverage)
    close_ok = not mal and all_covered
    result = {"case_uid": ledger.get("case_uid"), "alerts_considered": [a["id"] for a in alerts], "coverage": coverage,
              "malicious_beyond_alerts": [f["id"] for f in mal], "benign_findings": [f["id"] for f in ben]}
    if ledger.get("duplicate_of"):
        result.update(decision="Close", verdict_id=10, verdict="Duplicate", master_case_uid=ledger["duplicate_of"],
                      reminder="Duplicate only if all four §1.5 criteria were validated: matching core entities, overlapping timeline, active assignment, evidence merged.")
    elif close_ok:
        result.update(decision="Close", verdict_id=None, verdict="False Positive (1) if a False Positive condition explains the alerts; Benign (5) if a Benign condition does (use --close-as)")
    else:
        why = []
        if mal: why.append("Malicious findings exist beyond the alerts: " + ", ".join(f["id"] for f in mal))
        if not all_covered: why.append("not every alert is covered: " + ", ".join(c["alert"] for c in coverage if not c["covered"]))
        if not alerts: why.append("no alert in the Case")
        result.update(decision="Promote", verdict_id=0, verdict="none (promoted Cases carry no verdict)", why=why)
    # confidence (§1.5): on a Close, the strongest Benign finding; on a Promote, the confidence leaving triage
    if alerts and close_ok and not ledger.get("duplicate_of"):
        level = max(W[b["confidence"]] for b in ben)
        notes = ["close: the highest confidence on the Benign side"]
        if ledger.get("visibility_gaps"):
            level = min(level, 2); notes.append("capped at Medium: visibility gap(s) recorded")
        result.update(confidence_id=level, confidence=LEVELS[level - 1], confidence_notes=notes)
    elif alerts:
        level = max(W[a["confidence"]] for a in alerts)
        kinds = {(a.get("technique") or a.get("type", "")).strip().lower() for a in alerts}
        artifacts = {f.get("artifact") or f["id"] for f in mal}
        raised = len(kinds) >= 2 or len(artifacts) >= 2
        if raised: level += 1
        lowered = bool(ben) and not close_ok
        if lowered: level -= 1
        level = max(1, min(3, level))
        notes = []
        if raised: notes.append("+1: independent alerts of different types/techniques or two or more independent Malicious findings")
        if lowered: notes.append("-1: Benign findings exist but do not close the Case")
        if ledger.get("visibility_gaps"):
            level = min(level, 2); notes.append("capped at Medium: visibility gap(s) recorded")
        result.update(confidence_id=level, confidence=LEVELS[level - 1], confidence_notes=notes)
    return result


def decide(ledger):
    """The §1.5 decision, plus a note when the evidence inventory is missing, unverified or incomplete."""
    r = _decide(ledger)
    if inventory_note and inventory_note(ledger.get("evidence_inventory")):
        r["evidence_inventory_note"] = inventory_note(ledger.get("evidence_inventory"))
    return r


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    if not args:
        print(__doc__); sys.exit(2)
    ledger = json.load(open(args[0]))
    r = decide(ledger)
    if "--close-as" in sys.argv and r["decision"] == "Close" and r.get("verdict_id") is None:
        kind = sys.argv[sys.argv.index("--close-as") + 1].lower()
        r["verdict_id"], r["verdict"] = (1, "False Positive") if kind == "fp" else (5, "Benign Positive")
        if kind == "fp": r["emit"] = "tuning ticket to Phase 1"
        else: r["emit"] = "SOC Knowledge Base entry if the exception was not recorded"
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
    if r.get("evidence_inventory_note"): print("Note: " + r["evidence_inventory_note"])


if __name__ == "__main__":
    main()
