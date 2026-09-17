#!/usr/bin/env python3
"""Apply the hypothesis resolution rule of Detection & Analysis §2.4 to a findings ledger. Standard library only.

  resolve.py ledger.json [--benign-kind fp|benign] [--now 2026-09-14T15:12:00Z] [--json]

Ledger (JSON):
{
  "case_uid": "CASE-1", "severity": "High" (or "severity_id": 4), "started_at": "2026-09-14T15:00:00Z",
  "findings": [{"id": "F1", "desc": "...", "side": "Malicious"|"Benign"|null, "confidence": "Low|Medium|High",
                "at": "2026-09-14T15:03:10Z", "artifact": "hash:...", "alert_type": "...", "entity": "...",
                "retracted": false, "retraction_reason": "", "covered": false}],
  "evidence_inventory": {"extracted": 31, "source_count": 31, "complete": true},
  "visibility_gaps": [], "duplicate_of": null, "budget_exhausted": false,
  "timebox_minutes": null, "resolved_at": null, "timebox_expired": false
}
"covered" on a Malicious finding means the Benign explanation accounts for it (§2.4 coverage). Findings
that share an "artifact" on the same side count once, and so do alert findings of the same "alert_type"
on the same "entity" (§1.1). The timebox is measured, not declared: elapsed time runs from "started_at"
to --now, else "resolved_at", else the current time, against 10 minutes at High or Critical severity and
20 otherwise ("timebox_minutes" may tighten the reference value, never extend it). Finding and step
timestamps ("at") are checked against "started_at". Without "started_at" the script falls back to the
self-reported "timebox_expired" and says so. Prints the score
of each side, which side is proven, the verdict and confidence to record, the residual observations, the
timebox, and the next step.
"""
import argparse, json, os, sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from evidence_inventory import note as inventory_note
except ImportError:  # the shared script is copied next to this one by tools/build_references.py
    inventory_note = None

W = {"Low": 1, "Medium": 2, "High": 3}
LEVELS = ["Low", "Medium", "High"]


SEVERITY = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


def _once_key(f):
    """What makes two findings the same observation: one alert type on one entity, or one artifact."""
    if f.get("alert_type") and f.get("entity"):
        return (f["side"], "alert", str(f["alert_type"]).strip().lower(), str(f["entity"]).strip().lower())
    if f.get("artifact"):
        return (f["side"], "artifact", f["artifact"])
    return None


def dedupe(findings):
    seen, out = {}, []
    for f in findings:
        key = _once_key(f)
        if key and key in seen:
            if W[f["confidence"]] > W[seen[key]["confidence"]]:
                seen[key].update(confidence=f["confidence"])
            continue
        g = dict(f); out.append(g)
        if key: seen[key] = g
    return out


def _utc(stamp):
    t = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def timebox(ledger, now=None):
    """The investigation timebox measured from the ledger's timestamps; (record, notes)."""
    severity = ledger.get("severity") or SEVERITY.get(ledger.get("severity_id"), "Medium")
    reference = 10 if str(severity).capitalize() in ("High", "Critical") else 20
    minutes, notes = reference, []
    override = ledger.get("timebox_minutes")
    if override:
        if override < reference:
            minutes = override
        elif override > reference:
            notes.append(f"timebox_minutes={override} ignored: an organization may tighten the reference value ({reference}), not extend it")
    reported = ledger.get("timebox_expired")
    if not ledger.get("started_at"):
        notes.append("timebox self-reported: the ledger has no started_at, so elapsed time cannot be checked")
        return {"minutes": minutes, "elapsed_minutes": None, "expired": bool(reported), "source": "self-reported"}, notes
    start = _utc(ledger["started_at"])
    end = _utc(now or ledger.get("resolved_at") or datetime.now(timezone.utc).isoformat())
    early = [x.get("id", "?") for x in ledger.get("findings", []) + ledger.get("steps", []) if x.get("at") and _utc(x["at"]) < start]
    if early:
        notes.append("timestamps precede started_at: " + ", ".join(map(str, early)))
    elapsed = round((end - start).total_seconds() / 60, 1)
    if elapsed < 0:
        notes.append("the end time precedes started_at: elapsed time counted as 0")
        elapsed = 0.0
    record = {"minutes": minutes, "elapsed_minutes": elapsed, "expired": elapsed >= minutes, "source": "computed"}
    if reported is not None and bool(reported) != record["expired"]:
        notes.append(f"timebox computed from the ledger timestamps; the self-reported timebox_expired={str(bool(reported)).lower()} was ignored")
    return record, notes


def resolve(ledger, now=None):
    active = dedupe([f for f in ledger.get("findings", []) if not f.get("retracted") and f.get("side") in ("Malicious", "Benign")])
    mal = [f for f in active if f["side"] == "Malicious"]
    ben = [f for f in active if f["side"] == "Benign"]
    mal_score = sum(W[f["confidence"]] for f in mal)
    ben_score = sum(W[f["confidence"]] for f in ben)
    uncovered_mh = [f for f in mal if f["confidence"] in ("Medium", "High") and not f.get("covered")]
    residual_low = [f for f in mal if f["confidence"] == "Low" and not f.get("covered")]
    malicious_proven = mal_score >= 3
    benign_proven = ben_score >= 3 and not uncovered_mh
    r = {"case_uid": ledger.get("case_uid"), "malicious_score": mal_score, "benign_score": ben_score,
         "malicious_findings": [f["id"] for f in mal], "benign_findings": [f["id"] for f in ben],
         "retracted": [f["id"] for f in ledger.get("findings", []) if f.get("retracted")],
         "uncovered_medium_high_malicious": [f["id"] for f in uncovered_mh], "residual_low_malicious": [f["id"] for f in residual_low]}
    box, box_notes = timebox(ledger, now)
    r["timebox"] = box
    if box_notes: r["timebox_note"] = "; ".join(box_notes)
    inventory = inventory_note(ledger.get("evidence_inventory")) if inventory_note else None
    if inventory: r["evidence_inventory_note"] = inventory
    if ledger.get("duplicate_of"):
        r.update(outcome="Duplicate", verdict_id=10, confidence_id=None, master_case_uid=ledger["duplicate_of"], next="close; merge evidence into the master Case")
    elif benign_proven:
        conf = max(W[f["confidence"]] for f in ben)
        if residual_low: conf -= 1
        conf = max(1, conf)
        r.update(outcome="Benign proven", verdict_id=None, confidence_id=conf, confidence=LEVELS[conf - 1],
                 verdict="False Positive (1) if the detection was wrong, Benign Positive (5) if the activity was authorized (use --benign-kind)",
                 next="close" + ("; Low-confidence close carries a monitoring watch and is flagged for QA sampling" if conf == 1 else ""))
    elif malicious_proven:
        conf = max(W[f["confidence"]] for f in mal)
        r.update(outcome="Malicious proven", verdict_id=2, verdict="True Positive", confidence_id=conf, confidence=LEVELS[conf - 1],
                 next="promote to Incident (§3.1): definitive category, T0 from the timeline, retrospective entity sweep, Investigation → Response contract" + ("; at Low confidence every containment action requires approval" if conf == 1 else ""))
    else:
        if box["expired"] or ledger.get("budget_exhausted"):
            r.update(outcome="Neither proven at timebox/budget expiry", verdict_id=7, verdict="Insufficient Data", confidence_id=None,
                     next="close as Insufficient Data with a monitoring watch (re-open on recurrence of the entities); emit a visibility or tuning ticket; record the state reached")
        else:
            r.update(outcome="Neither proven", verdict_id=None, next="run the remaining discriminating queries (listed or added); seek evidence against the favoured side")
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ledger")
    ap.add_argument("--benign-kind", choices=["fp", "benign"], type=str.lower)
    ap.add_argument("--now", help="UTC time to measure the timebox against (default: resolved_at, else the current time)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        r = resolve(json.load(open(a.ledger, encoding="utf-8")), now=a.now)
    except ValueError as exc:
        sys.exit(f"invalid ledger: {exc}")
    if a.benign_kind and r.get("outcome") == "Benign proven":
        r["verdict_id"], r["verdict"] = (1, "False Positive") if a.benign_kind == "fp" else (5, "Benign Positive")
        r["emit"] = "tuning ticket to Phase 1" if a.benign_kind == "fp" else "SOC Knowledge Base entry if the exception was not recorded"
    if a.json:
        print(json.dumps(r, indent=2)); return
    print(f"Malicious {r['malicious_score']} ({', '.join(r['malicious_findings']) or '-'})  |  Benign {r['benign_score']} ({', '.join(r['benign_findings']) or '-'})")
    if r["retracted"]: print("Retracted: " + ", ".join(r["retracted"]))
    print(f"Outcome: {r['outcome']}  verdict: {r.get('verdict', '-')} ({r.get('verdict_id')})  confidence: {r.get('confidence', '-')}")
    if r["uncovered_medium_high_malicious"]: print("Uncovered Medium/High Malicious findings (block a Benign verdict): " + ", ".join(r["uncovered_medium_high_malicious"]))
    if r["residual_low_malicious"]: print("Residual Low Malicious findings (listed in the Note, monitoring watch): " + ", ".join(r["residual_low_malicious"]))
    if r.get("confidence_note"): print(r["confidence_note"])
    box = r["timebox"]
    print(f"Timebox: {box['minutes']} min, elapsed {box['elapsed_minutes'] if box['elapsed_minutes'] is not None else '?'} min, {'EXPIRED' if box['expired'] else 'running'} ({box['source']})")
    for key in ("timebox_note", "evidence_inventory_note"):
        if r.get(key): print("Note: " + r[key])
    print("Next: " + r["next"])
    if r.get("emit"): print("Emit: " + r["emit"])


if __name__ == "__main__":
    main()
