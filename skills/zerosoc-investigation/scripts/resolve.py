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
to --now, else "resolved_at", else the latest finding or step timestamp, against 10 minutes at High or
Critical severity and 20 otherwise ("timebox_minutes" is the organization's override). Without
"started_at" the script falls back to the self-reported "timebox_expired" and says so. Prints the score
of each side, which side is proven, the verdict and confidence to record, the residual observations, the
timebox, and the next step.
"""
import json, os, sys
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
    """What makes two findings the same observation: one artifact, or one alert type on one entity."""
    if f.get("artifact"):
        return (f["side"], "artifact", f["artifact"])
    if f.get("alert_type") and f.get("entity"):
        return (f["side"], "alert", str(f["alert_type"]).strip().lower(), str(f["entity"]).strip().lower())
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
    """The investigation timebox measured from the ledger's timestamps; (record, note)."""
    severity = ledger.get("severity") or SEVERITY.get(ledger.get("severity_id"), "Medium")
    minutes = ledger.get("timebox_minutes") or (10 if str(severity).capitalize() in ("High", "Critical") else 20)
    reported = ledger.get("timebox_expired")
    if not ledger.get("started_at"):
        return {"minutes": minutes, "elapsed_minutes": None, "expired": bool(reported), "source": "self-reported"}, (
            "timebox self-reported: the ledger has no started_at, so elapsed time cannot be checked")
    stamps = [x["at"] for x in ledger.get("findings", []) + ledger.get("steps", []) if x.get("at")]
    end = now or ledger.get("resolved_at") or (max(stamps, key=_utc) if stamps else datetime.now(timezone.utc).isoformat())
    elapsed = round((_utc(end) - _utc(ledger["started_at"])).total_seconds() / 60, 1)
    record = {"minutes": minutes, "elapsed_minutes": elapsed, "expired": elapsed >= minutes, "source": "computed"}
    note = None
    if reported is not None and bool(reported) != record["expired"]:
        note = f"timebox computed from the ledger timestamps; the self-reported timebox_expired={str(bool(reported)).lower()} was ignored"
    return record, note


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
    box, box_note = timebox(ledger, now)
    r["timebox"] = box
    if box_note: r["timebox_note"] = box_note
    if inventory_note and inventory_note(ledger.get("evidence_inventory")):
        r["evidence_inventory_note"] = inventory_note(ledger.get("evidence_inventory"))
    cap = 2 if ledger.get("visibility_gaps") else 3
    if ledger.get("duplicate_of"):
        r.update(outcome="Duplicate", verdict_id=10, confidence_id=None, master_case_uid=ledger["duplicate_of"], next="close; merge evidence into the master Case")
    elif benign_proven:
        conf = max(W[f["confidence"]] for f in ben)
        if residual_low: conf -= 1
        conf = max(1, min(conf, cap))
        r.update(outcome="Benign proven", verdict_id=None, confidence_id=conf, confidence=LEVELS[conf - 1],
                 verdict="False Positive (1) if the detection was wrong, Benign Positive (5) if the activity was authorized (use --benign-kind)",
                 next="close" + ("; Low-confidence close carries a monitoring watch and is flagged for QA sampling" if conf == 1 else ""))
    elif malicious_proven:
        conf = min(max(W[f["confidence"]] for f in mal), cap)
        r.update(outcome="Malicious proven", verdict_id=2, verdict="True Positive", confidence_id=conf, confidence=LEVELS[conf - 1],
                 next="promote to Incident (§3.1): definitive category, T0 from the timeline, retrospective entity sweep, Investigation → Response contract" + ("; at Low confidence every containment action requires approval" if conf == 1 else ""))
    else:
        if box["expired"] or ledger.get("budget_exhausted"):
            r.update(outcome="Neither proven at timebox/budget expiry", verdict_id=7, verdict="Insufficient Data", confidence_id=None,
                     next="close as Insufficient Data with a monitoring watch (re-open on recurrence of the entities); emit a visibility or tuning ticket; record the state reached")
        else:
            r.update(outcome="Neither proven", verdict_id=None, next="run the remaining discriminating queries (listed or added); seek evidence against the favoured side")
    if r.get("confidence_id") and cap == 2 and r["confidence_id"] == 2 and ledger.get("visibility_gaps"):
        r["confidence_note"] = "capped at Medium: visibility gap(s) recorded"
    return r


def main():
    argv = sys.argv[1:]
    now = argv[argv.index("--now") + 1] if "--now" in argv else None
    valued = {argv.index(flag) + 1 for flag in ("--now", "--benign-kind") if flag in argv}
    args = [x for i, x in enumerate(argv) if not x.startswith("--") and i not in valued]
    if not args:
        print(__doc__); sys.exit(2)
    r = resolve(json.load(open(args[0])), now=now)
    if "--benign-kind" in sys.argv and r.get("outcome") == "Benign proven":
        kind = sys.argv[sys.argv.index("--benign-kind") + 1].lower()
        r["verdict_id"], r["verdict"] = (1, "False Positive") if kind == "fp" else (5, "Benign Positive")
        r["emit"] = "tuning ticket to Phase 1" if kind == "fp" else "SOC Knowledge Base entry if the exception was not recorded"
    if "--json" in sys.argv:
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
