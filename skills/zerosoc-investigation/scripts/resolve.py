#!/usr/bin/env python3
"""Apply the hypothesis resolution rule of Detection & Analysis §2.4 to a findings ledger. Standard library only.

  resolve.py ledger.json [--benign-kind fp|benign] [--json]

Ledger (JSON):
{
  "case_uid": "CASE-1",
  "findings": [{"id": "F1", "desc": "...", "side": "Malicious"|"Benign"|null, "confidence": "Low|Medium|High",
                "artifact": "hash:...", "retracted": false, "retraction_reason": "", "covered": false}],
  "visibility_gaps": [], "duplicate_of": null, "timebox_expired": false, "budget_exhausted": false
}
"covered" on a Malicious finding means the Benign explanation accounts for it (§2.4 coverage). Findings
that share an "artifact" on the same side count once. Prints the score of each side, which side is proven,
the verdict and confidence to record, the residual observations, and the next step.
"""
import json, sys

W = {"Low": 1, "Medium": 2, "High": 3}
LEVELS = ["Low", "Medium", "High"]


def dedupe(findings):
    seen, out = {}, []
    for f in findings:
        key = (f["side"], f.get("artifact"))
        if f.get("artifact") and key in seen:
            if W[f["confidence"]] > W[seen[key]["confidence"]]:
                seen[key].update(confidence=f["confidence"])
            continue
        g = dict(f); out.append(g)
        if f.get("artifact"): seen[key] = g
    return out


def resolve(ledger):
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
        if ledger.get("timebox_expired") or ledger.get("budget_exhausted"):
            r.update(outcome="Neither proven at timebox/budget expiry", verdict_id=7, verdict="Insufficient Data", confidence_id=None,
                     next="close as Insufficient Data with a monitoring watch (re-open on recurrence of the entities); emit a visibility or tuning ticket; record the state reached")
        else:
            r.update(outcome="Neither proven", verdict_id=None, next="run the remaining discriminating queries (listed or added); seek evidence against the favoured side")
    if r.get("confidence_id") and cap == 2 and r["confidence_id"] == 2 and ledger.get("visibility_gaps"):
        r["confidence_note"] = "capped at Medium: visibility gap(s) recorded"
    return r


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    if not args:
        print(__doc__); sys.exit(2)
    r = resolve(json.load(open(args[0])))
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
    print("Next: " + r["next"])
    if r.get("emit"): print("Emit: " + r["emit"])


if __name__ == "__main__":
    main()
