#!/usr/bin/env python3
"""Apply the hypothesis resolution rule of Detection & Analysis §2.4 to an observations ledger. Standard library only.

  resolve.py ledger.json [--benign-kind fp|benign] [--now 2026-09-14T15:12:00Z] [--json]

Ledger (JSON):
{
  "case_uid": "CASE-1", "severity": "High" (or "severity_id": 4), "started_at": "2026-09-14T15:00:00Z",
  "playbook": "04-Playbooks/02-Investigation-Response/02-malware.md", "playbook_version": "2026-09-16",
  "incident_category": "IC-02",
  "alerts": [{"id": "<alert id>", "confidence": "Low|Medium|High", "ids": ["<merged source alert ids>"]}],
  "observations": [{"id": "O1", "desc": "...", "side": "Malicious"|"Benign"|null, "confidence": "Low|Medium|High",
                "condition": "false_positive"|"benign"|null,
                "at": "2026-09-14T15:03:10Z", "artifact": "hash:...", "alert_type": "...", "entity": "...",
                "retracted": false, "retraction_reason": "", "covered": false,
                "event_refs": ["<event id or link>"], "first_seen": "2026-09-14T14:55:41Z", "timeline": false,
                "attacks": ["T1003.001"]}],
  "attacks": ["T1003.001"],     the Incident's techniques, recorded at confirmation (§2.5)
  "evidence_inventory": {"extracted": 31, "source_count": 31, "complete": true},
  "detection_metadata": {...},  what the detections asserted (§1.1), carried from triage and refreshed at
                                this gate: the remediation state as it now stands, and the disposition of
                                the source's recommended actions,
  "no_information_refs": ["<event id>"], "scoped_negative_refs": ["<event id>"],
  "visibility_gaps": [], "duplicate_of": null, "budget_exhausted": false,
  "timebox_minutes": null, "resolved_at": null, "timebox_expired": false
}
"at" is when the observation was made; "first_seen" is when the thing it reports happened, "event_refs" the
events it rests on and "timeline" whether the Case Timeline shows it; note_elements.py and timeline.py read
them from this same ledger. This rule reads "event_refs" with "alerts" (the Case's alerts and each one's own
confidence): a Malicious observation that cites one alert and nothing else counts as that alert, whatever it
is tagged — once, never above the alert's own confidence, in the score as in the proof — and Malicious is
proven at 3 only when an alert's own confidence is High or a Malicious observation stands beyond the alerts (§2.4). A ledger that names no alerts is resolved by the score alone, and says so.
"no_information_refs" are the references whose result carried no information: a lookup that knows nothing
of the indicator, a search that finds no approval, a query that was not answered. "scoped_negative_refs" are
the references whose query covered the question and found nothing, such as no child process on a covered
host in the window: something was learned, so they are cited like any other result (§2.4). An observation
is read without the first kind, on either side, and one resting on them alone carries no weight
("no_information"); on the Malicious side, one resting on them and one alert counts as that alert. A
reference is one kind or the other, never both. A ledger with no "scoped_negative_refs" key is read the same
way, and "no_information_note" says so (scripts/no_information.py).
"condition" on a Benign observation is the kind of the triage playbook condition it named, read off the list
the condition belongs to (Playbook Architecture §4.1), never a kind the executor labelled itself; on Benign
proven the verdict is Benign (5) when the Benign observation of the highest confidence names a Benign
condition and no False Positive one is named at that confidence, False Positive (1) otherwise — the rule of
Detection & Analysis §1.5, which §2.4 applies to the same two verdicts. --benign-kind is read only for a
ledger whose observations carry no "condition" key, written before it existed.
"covered" on a Malicious observation means the Benign explanation accounts for it (§2.4 coverage). Observations
that share an "artifact" on the same side count once, and so do alert observations of the same "alert_type"
on the same "entity" (§1.1). The timebox is measured, not declared: elapsed time runs from "started_at"
to --now, else "resolved_at", else the current time, against 10 minutes at High or Critical severity and
20 otherwise ("timebox_minutes" may tighten the reference value, never extend it). Observation and step
timestamps ("at") are checked against "started_at". Without "started_at" the script falls back to the
self-reported "timebox_expired" and says so. Prints the score
of each side, which side is proven, the verdict and confidence to record, the residual observations, the
timebox, and the next step; with --json also "counted": per side, the ids of the observations standing (not
retracted) and of those the score counts, once the ones that carry no information are set aside and one alert
type on one entity, or one artifact, counts once; a Note quotes it rather than recounting. "scoring" says how
each standing observation entered its side's score, in ledger order: "weight" and "confidence" where it is
counted (the weights of a side add up to its score; "capped_by_alert" where the alert it restates capped it,
"counts_for" the observations counted as this one), else "reason": "no-information", "same-evidence" or
"restates-alert", with "same_as" the observation it counts as and, for a restatement, its "alert".
"attacks" on an observation are the techniques it shows, as identifiers (`T1003.001`, or `T1003.001 (Name)`):
an alert's are the ones its detection asserted, and a Malicious observation's the ones it establishes. The
ledger's own "attacks" are the Incident's, recorded at confirmation from the observations that stand (§2.5).
On Malicious proven the script lists, under "attacks", the techniques the standing Malicious observations
show, each with the observations showing it, and names the recorded ones no standing observation shows
("untraced"); a technique is shown when an observation shows it or one of its sub-techniques. A retracted
observation shows nothing, so a retraction takes its techniques with it.
"""
import argparse, json, os, re, sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import no_information  # copied next to this script by tools/build_references.py
try:
    from evidence_inventory import note as inventory_note
except ImportError:  # the shared script is copied next to this one by tools/build_references.py
    inventory_note = None
try:
    from alert_metadata import decision_notes, neutralized
except ImportError:
    decision_notes = neutralized = None

W = {"Low": 1, "Medium": 2, "High": 3}
LEVELS = ["Low", "Medium", "High"]


SEVERITY = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

TECHNIQUE = re.compile(r"\b((?:AML\.)?T\d{4}(?:\.\d{3})?)\b")


def _ids(value, where):
    """The technique identifiers of an "attacks" list, each written bare or as `ID (Name)`."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f'{where}: "attacks" is a list of technique identifiers')
    out = []
    for entry in value:
        m = TECHNIQUE.search(str(entry))
        tid = m.group(1) if m else str(entry).strip()
        if tid and tid not in out:
            out.append(tid)
    return out


def techniques(ledger, standing):
    """The Incident's techniques as the observations that stand show them, and the recorded ones none shows."""
    shown = {}
    for f in standing:
        if f["side"] == "Malicious":
            for tid in _ids(f.get("attacks"), f"observation {f.get('id')}"):
                shown.setdefault(tid, []).append(f["id"])
    recorded = _ids(ledger.get("attacks"), "ledger")
    untraced = [t for t in recorded if t not in shown and not any(s.startswith(t + ".") for s in shown)]
    return {"shown": shown, "recorded": recorded, "untraced": untraced}


def _once_key(f):
    """What makes two observations the same observation: one alert type on one entity, or one artifact."""
    if f.get("alert_type") and f.get("entity"):
        return (f["side"], "alert", str(f["alert_type"]).strip().lower(), str(f["entity"]).strip().lower())
    if f.get("artifact"):
        return (f["side"], "artifact", f["artifact"])
    return None


def dedupe(observations, folded=None):
    """One observation per once-key, at the highest confidence of those it stands for; `folded`, when
    given, is filled with each observation set aside and the one it counts as."""
    seen, out = {}, []
    for f in observations:
        key = _once_key(f)
        if key and key in seen:
            if W[f["confidence"]] > W[seen[key]["confidence"]]:
                seen[key].update(confidence=f["confidence"])
            if folded is not None:
                folded[f["id"]] = seen[key]["id"]
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
    early = [x.get("id", "?") for x in ledger.get("observations", []) + ledger.get("steps", []) if x.get("at") and _utc(x["at"]) < start]
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


EMIT = {1: "tuning ticket to Phase 1", 5: "exception ticket: the Knowledge Base entry proposed for a person to confirm, unless the Knowledge Base already holds it"}


def benign_verdict(ben):
    """The verdict a Benign proof carries, from the conditions the Benign observations named: Benign (5)
    when the one of the highest confidence names a Benign condition and no False Positive one is named at
    that confidence, False Positive (1) otherwise. None for a ledger that predates the field."""
    if not any("condition" in f for f in ben):
        return None, None
    top = max((W[f["confidence"]] for f in ben), default=0)
    kinds = {f.get("condition") for f in ben if W[f["confidence"]] == top}
    if "benign" in kinds and "false_positive" not in kinds:
        return 5, "Benign Positive"
    return 1, "False Positive"


def alert_bound(f, owner, empty=frozenset()):
    """The alert a Malicious observation only restates: the one alert all its references belong to, or None
    when it cites anything else, two alerts, or nothing at all (§1.5). A reference whose result carried no
    information is not read."""
    refs = no_information.informative(f, empty)
    if f.get("alert_type"):
        return refs[0] if refs else f.get("id")
    alerts = {owner[r] for r in refs if r in owner}
    if refs and len(alerts) == 1 and all(r in owner for r in refs):
        return alerts.pop()
    return None


def alert_index(ledger):
    """Each alert id, merged source ids included, to the alert it belongs to; and each alert's own confidence."""
    alerts = ledger.get("alerts") or []
    # an alert that stands for several merged source alerts is one alert under each of its ids
    owner = {str(i): str(a["id"]) for a in alerts if a.get("id") for i in [a["id"], *(a.get("ids") or [])]}
    return owner, {str(a["id"]): a.get("confidence") for a in alerts if a.get("id")}


def as_alerts(observations, ledger, empty):
    """§2.4: an observation that only restates an alert counts as that alert, in the score as in the proof:
    the restatements of one alert are one observation, weighed no higher than the alert's own confidence however
    they are tagged, and the same one as the alert's typed observation where the ledger has one (§1.1). The
    cap never raises a tag: a High alert read at Low stays Low."""
    owner, own = alert_index(ledger)
    bound = {f["id"]: alert_bound(f, owner, empty) for f in observations if f["side"] == "Malicious"}
    typed = {}
    for f in observations:
        if bound.get(f["id"]) and f.get("alert_type") and f.get("entity"):
            typed.setdefault(bound[f["id"]], f)
    out = []
    for f in observations:
        alert = bound.get(f["id"])
        if alert not in own or f.get("alert_type"):
            out.append(f); continue
        cap = own[alert] if own[alert] in W else f["confidence"]
        # "_alert" names the alert it counts as, for the scoring record; nothing else reads it
        g = dict(f, confidence=min(f["confidence"], cap, key=W.__getitem__), _alert=alert)
        if alert in typed:
            g.update(alert_type=typed[alert]["alert_type"], entity=typed[alert]["entity"])
        else:
            g["artifact"] = "alert:" + alert
        out.append(g)
    return out


def proof_beyond(mal, ledger):
    """§2.4: why a Malicious score of 3 does not prove Malicious, or None when it does. The alerts at Medium
    or Low confidence, and every restatement of them, never prove it alone."""
    alerts = ledger.get("alerts")
    if not alerts:
        return None
    owner, own = alert_index(ledger)
    empty, _ = no_information.refs(ledger)
    bound = {f["id"]: alert_bound(f, owner, empty) for f in mal}
    if any(alert is None for alert in bound.values()):
        return None
    if any(own.get(alert) == "High" for alert in bound.values()):
        return None
    return ("the score rests on the alerts alone, none at High confidence: nothing stands beyond the alerts"
            " (Detection & Analysis §2.4)")


def scoring(standing, weightless, aligned, active, folded):
    """How each standing observation entered its side's score, in ledger order: its weight where it is
    counted, else why not. The weights of one side add up to its score. A counted one carries the
    confidence it was weighed at, which an alert it restates can cap and an observation counted as
    the same one can raise; one set aside names the observation it counts as, or the alert."""
    by_id = {g["id"]: g for g in aligned}
    kept = {g["id"]: g for g in active}
    aside = {f["id"] for f in weightless}
    out = []
    for f in standing:
        rec = {"id": f["id"], "side": f["side"]}
        g = by_id.get(f["id"])
        if f["id"] in aside or g is None:
            rec.update(weight=0, counted=False, reason="no-information")
        elif f["id"] in folded:
            rec.update(weight=0, counted=False, same_as=folded[f["id"]],
                       reason="restates-alert" if g.get("_alert") else "same-evidence")
            if g.get("_alert"):
                rec["alert"] = g["_alert"]
        else:
            held = kept[f["id"]]
            rec.update(weight=W[held["confidence"]], counted=True, confidence=held["confidence"])
            if W[g["confidence"]] < W[f["confidence"]]:
                rec["capped_by_alert"] = g["_alert"]
            others = [x for x, into in folded.items() if into == f["id"]]
            if others:
                rec["counts_for"] = others
        out.append(rec)
    return out


def resolve(ledger, now=None):
    standing = [f for f in ledger.get("observations", []) if not f.get("retracted") and f.get("side") in ("Malicious", "Benign")]
    attacks = techniques(ledger, standing)
    empty, empty_note = no_information.refs(ledger)
    # an observation resting on nothing but results that carried no information is none (§2.4); it is set
    # aside before the count-once rule, so it can neither stand in for a real observation nor lend it weight
    weightless = [f for f in standing if no_information.carries_nothing(f, empty)]
    aligned = as_alerts([f for f in standing if f not in weightless], ledger, empty)
    folded = {}
    active = dedupe(aligned, folded)
    mal = [f for f in active if f["side"] == "Malicious"]
    ben = [f for f in active if f["side"] == "Benign"]
    mal_score = sum(W[f["confidence"]] for f in mal)
    ben_score = sum(W[f["confidence"]] for f in ben)
    uncovered_mh = [f for f in mal if f["confidence"] in ("Medium", "High") and not f.get("covered")]
    residual_low = [f for f in mal if f["confidence"] == "Low" and not f.get("covered")]
    unproven = proof_beyond(mal, ledger) if mal_score >= 3 else None
    malicious_proven = mal_score >= 3 and unproven is None
    benign_proven = ben_score >= 3 and not uncovered_mh
    r = {"case_uid": ledger.get("case_uid"), "malicious_score": mal_score, "benign_score": ben_score,
         "malicious_observations": [f["id"] for f in mal], "benign_observations": [f["id"] for f in ben],
         "retracted": [f["id"] for f in ledger.get("observations", []) if f.get("retracted")],
         "uncovered_medium_high_malicious": [f["id"] for f in uncovered_mh], "residual_low_malicious": [f["id"] for f in residual_low],
         "counted": {side: {"standing": [f["id"] for f in standing if f["side"] == side], "counted": [f["id"] for f in kept]}
                     for side, kept in (("Malicious", mal), ("Benign", ben))},
         "scoring": scoring(standing, weightless, aligned, active, folded)}
    if unproven:
        r["malicious_not_proven"] = unproven
    if weightless:
        r["no_information"] = [f["id"] for f in weightless]
    if empty_note:
        r["no_information_note"] = empty_note
    if not ledger.get("alerts"):
        r["alerts_note"] = "the ledger names no alerts: Malicious is resolved by the score alone, without the §2.4 test of what stands beyond the alerts"
    box, box_notes = timebox(ledger, now)
    r["timebox"] = box
    if box_notes: r["timebox_note"] = "; ".join(box_notes)
    inventory = inventory_note(ledger.get("evidence_inventory")) if inventory_note else None
    if inventory: r["evidence_inventory_note"] = inventory
    record = ledger.get("detection_metadata")
    if decision_notes: r["detection_notes"] = decision_notes(record)
    if record:
        r["neutralized_entities"] = neutralized(record)
    if ledger.get("duplicate_of"):
        r.update(outcome="Duplicate", verdict_id=10, confidence_id=None, master_case_uid=ledger["duplicate_of"], next="close; merge evidence into the master Case")
    elif benign_proven:
        conf = max(W[f["confidence"]] for f in ben)
        if residual_low: conf -= 1
        conf = max(1, conf)
        verdict_id, verdict = benign_verdict(ben)
        r.update(outcome="Benign proven", verdict_id=verdict_id, confidence_id=conf, confidence=LEVELS[conf - 1],
                 verdict=verdict or "False Positive (1) if the detection was wrong, Benign Positive (5) if the activity was authorized (use --benign-kind)",
                 next="close" + ("; Low-confidence close carries a monitoring watch and is flagged for QA sampling" if conf == 1 else ""))
        if verdict_id: r["emit"] = EMIT[verdict_id]
    elif malicious_proven:
        conf = max(W[f["confidence"]] for f in mal)
        r.update(outcome="Malicious proven", verdict_id=2, verdict="True Positive", confidence_id=conf, confidence=LEVELS[conf - 1],
                 attacks=attacks,
                 next="confirm the Incident (§2.5): re-assess severity, confidence and category, estimate the impact, plan the initial response actions; then the definitive category, the Incident's techniques in \"attacks\" from the observations that stand, start_time carrying T0, the retrospective entity sweep (§3.1) and the Investigation → Response contract" + ("; at Low confidence every containment action requires approval" if conf == 1 else ""))
    else:
        if box["expired"] or ledger.get("budget_exhausted"):
            r.update(outcome="Neither proven at timebox/budget expiry", verdict_id=7, verdict="Insufficient Data", confidence_id=None,
                     next="close as Insufficient Data with a monitoring watch (re-open on recurrence of the entities); emit a visibility or tuning ticket; record the state reached")
        else:
            r.update(outcome="Neither proven", verdict_id=None, next="run the remaining discriminating queries (listed or added); seek evidence against the favoured side")
    if attacks["recorded"] and r.get("verdict_id") != 2:
        r["attacks_note"] = "the ledger records the Incident's techniques, but no Incident is confirmed: the Case's \"attacks\" stay empty"
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
    if a.benign_kind and r.get("outcome") == "Benign proven" and r.get("verdict_id") is None:
        # a ledger written before observations carried their condition: the caller says which kind
        r["verdict_id"], r["verdict"] = (1, "False Positive") if a.benign_kind == "fp" else (5, "Benign Positive")
        r["emit"] = EMIT[r["verdict_id"]]
    if a.json:
        print(json.dumps(r, indent=2)); return
    print(f"Malicious {r['malicious_score']} ({', '.join(r['malicious_observations']) or '-'})  |  Benign {r['benign_score']} ({', '.join(r['benign_observations']) or '-'})")
    if r["retracted"]: print("Retracted: " + ", ".join(r["retracted"]))
    print(f"Outcome: {r['outcome']}  verdict: {r.get('verdict', '-')} ({r.get('verdict_id')})  confidence: {r.get('confidence', '-')}")
    if r["uncovered_medium_high_malicious"]: print("Uncovered Medium/High Malicious observations (block a Benign verdict): " + ", ".join(r["uncovered_medium_high_malicious"]))
    if r["residual_low_malicious"]: print("Residual Low Malicious observations (listed in the Note, monitoring watch): " + ", ".join(r["residual_low_malicious"]))
    if r.get("confidence_note"): print(r["confidence_note"])
    if r.get("attacks"):
        shown = r["attacks"]["shown"]
        print("Techniques the standing Malicious observations show: "
              + (", ".join(f"{t} ({', '.join(ids)})" for t, ids in shown.items()) or "none recorded on them"))
        print("Recorded as the Incident's: " + (", ".join(r["attacks"]["recorded"]) or "none yet"))
        if r["attacks"]["untraced"]:
            print("Shown by no standing observation (record it on the observation that shows it, or leave it out): "
                  + ", ".join(r["attacks"]["untraced"]))
    box = r["timebox"]
    print(f"Timebox: {box['minutes']} min, elapsed {box['elapsed_minutes'] if box['elapsed_minutes'] is not None else '?'} min, {'EXPIRED' if box['expired'] else 'running'} ({box['source']})")
    if r.get("no_information"): print("Carry no information (not counted): " + ", ".join(r["no_information"]))
    for side in ("Malicious", "Benign"):
        held = [x for x in r["scoring"] if x["side"] == side]
        if held:
            print(f"{side} {r['malicious_score' if side == 'Malicious' else 'benign_score']} = "
                  + " + ".join(f"{x['id']} {x['weight']}" for x in held if x["counted"])
                  + "".join(f"; {x['id']} counts as {x['same_as']}" for x in held if x.get("same_as"))
                  + "".join(f"; {x['id']} carries no information" for x in held if x.get("reason") == "no-information"))
    for key in ("timebox_note", "evidence_inventory_note", "no_information_note", "attacks_note"):
        if r.get(key): print("Note: " + r[key])
    for note in r.get("detection_notes", []): print("Note: " + note)
    print("Next: " + r["next"])
    if r.get("emit"): print("Emit: " + r["emit"])


if __name__ == "__main__":
    main()
