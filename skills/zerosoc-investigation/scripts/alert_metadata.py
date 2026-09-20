#!/usr/bin/env python3
"""Read what the detection asserts about an Alert, before any enrichment. Standard library only.

  alert_metadata.py alerts.json --bindings zerosoc.capabilities.json [--evidence evidence.json] [--json]
  alert_metadata.py alerts.json --map alert_types.<source>.json [--evidence evidence.json] [--json]

Detection & Analysis §1.1: an Alert carries more than its entities and its type, and six of the things
it carries are required inputs of triage, read before enrichment and recorded on the Case — the
technique identifiers, the threat name and family, the detection source and detector, the remediation
state of each entity, the source's description of the detection, and its recommended actions. This
script extracts them, ledger-ready, and names what the source did not supply.

The script knows no source. The deployment's alert-type map (the file the binding names under
`alert_type_map`) declares, under `detection_metadata`, which of the source's fields carry each
assertion, how its detection sources map onto OCSF analytic types, and what its remediation states mean:

  "detection_metadata": {
    "fields": {"techniques": "...", "threat_name": "...", "threat_family": "...",
               "detection_source": "...", "detector_id": "...", "description": "...",
               "recommended_actions": "..."},
    "entity_fields": {"remediation_status": "...", "remediation_status_details": "..."},
    "analytic_types": {"<the source's detection source>": {"type_id": <OCSF analytic type>, "type": "<its name>"}},
    "remediation_states": {"<the source's state>": {"neutralized": true, "status": "Success", "activity": "Evict"}}
  }

A detection source the map does not list is OCSF analytic type Other (99), never guessed; a remediation
state it does not list is recorded as reported and treated as **not** neutralized, because a state
nobody declared is not evidence that anything was stopped.

Output (`--json`, or the same content printed): one object per alert under "alerts", the Case's
techniques and candidate Incident Categories, the per-entity remediation the evidence reports, and
"visibility_gaps" for every assertion an alert did not carry, naming the alerts that lack it. Record it in ledger.json: the
decision scripts read the alerts' assertions from there, and the Note renders them.

A remediation the source performed is **not** an explanation of the Alert (§1.5). It is recorded, it
carries no side and no confidence, and the questions the block does not answer — how the entity
arrived, what ran before it was stopped, whether the same thing is elsewhere — stay open.
"""
import argparse, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from select_playbook import ROOT as FRAMEWORK, candidates, technique_index
except ImportError:  # the shared scripts are copied next to each other by tools/build_references.py
    FRAMEWORK, candidates, technique_index = None, None, None

FIELDS = {"techniques": "techniques", "threat_name": "threat name", "threat_family": "threat family",
          "detection_source": "detection source", "detector_id": "detector id", "description": "description",
          "recommended_actions": "recommended actions"}
# What triage loses when the source supplies none of it (§1.1), as the check each gap prevented.
PREVENTS = {
    "techniques": "the technique identifiers the candidate Incident Categories and the playbook section start from",
    "threat name": "the threat or family name the Malicious hypothesis and the family-specific enrichment start from",
    "detection source": "how the Alert is weighed: a signature match and a model score are not the same evidence",
    "description": "what the detection fires on, which the False Positive conditions are judged against",
    "recommended actions": "the source's own procedure for this detection, which is followed or set aside on the record",
    "remediation state": "whether the source already blocked, quarantined or removed each entity",
}
OTHER = {"type_id": 99, "type": "Other"}


def spec_of(amap):
    return (amap or {}).get("detection_metadata") or {}


def field(record, spec, name, group="fields"):
    """The canonical field, or the source's own name for it as the map declares it."""
    value = record.get(name)
    if value not in (None, "", [], {}):
        return value
    alias = (spec.get(group) or {}).get(name)
    return record.get(alias) if alias else None


def _list(value):
    if value in (None, "", [], {}):
        return []
    if isinstance(value, str):
        return [line.strip(" -\t") for line in re.split(r"[\r\n]+|(?<=[.!?])\s{2,}", value) if line.strip(" -\t")]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value)]


def _actions(value):
    """The source's recommended actions, each undecided until triage follows it or sets it aside."""
    out = []
    for n, item in enumerate(_list(value), start=1):
        if isinstance(item, dict):
            out.append(dict({"id": f"RA{n}", "disposition": None}, **item))
        else:
            out.append({"id": f"RA{n}", "action": item, "disposition": None})
    return out


def actions_of(record):
    """Every recommended action the Case's detections published, across its alerts."""
    return [a for alert in (record or {}).get("alerts", []) for a in alert.get("recommended_actions", [])]


def neutralized(record):
    """The entities the source reports it blocked, quarantined or removed."""
    return [r.get("entity") for r in (record or {}).get("remediation", []) if r.get("neutralized")]


def dispositions(actions):
    """Which recommended actions were followed, which were set aside with a reason, which are still open.

    §1.5: each is followed, or set aside with a **stated reason**. Set aside without one is not a
    disposition, so it stays open and the Case is not decided on it.
    """
    followed, set_aside, open_ = [], [], []
    for action in actions or []:
        state = str(action.get("disposition") or "").strip().lower().replace("_", " ")
        if state == "followed":
            followed.append(action.get("id"))
        elif state in ("set aside", "setaside", "rejected") and str(action.get("reason") or "").strip():
            set_aside.append(action.get("id"))
        else:
            open_.append(action.get("id"))
    return {"followed": followed, "set_aside": set_aside, "open": open_}


def assertions(alert, amap, index=None):
    """What one Alert asserts: the six inputs of §1.1, plus what the source did not supply."""
    spec = spec_of(amap)
    techniques = [str(t).strip() for t in _list(field(alert, spec, "techniques"))]
    found = candidates(techniques, index) if (index is not None and candidates) else None
    name = field(alert, spec, "threat_name")
    family = field(alert, spec, "threat_family")
    source = field(alert, spec, "detection_source")
    analytic = (spec.get("analytic_types") or {}).get(str(source)) or OTHER if source else OTHER
    actions = _actions(field(alert, spec, "recommended_actions"))
    out = {
        "id": field(alert, {"fields": (amap or {}).get("fields") or {}}, "id"),
        "techniques": found["techniques"] if found else [{"id": t, "name": None, "rendered": t, "matched": None,
                                                          "categories": [], "alert_types": [], "domains": []}
                                                         for t in techniques],
        "candidate_incident_categories": found["categories"] if found else [],
        "techniques_not_in_the_catalog": found["unknown"] if found else techniques,
        "threat": {"name": str(name), "family": str(family) if family else None} if name or family else None,
        "detection": {"source": str(source) if source else None,
                      "detector_id": str(field(alert, spec, "detector_id") or "") or None,
                      "analytic_type_id": analytic["type_id"], "analytic_type": analytic["type"]},
        "description": str(field(alert, spec, "description") or "") or None,
        "recommended_actions": actions,
    }
    if out["threat"] and not out["threat"]["name"]:
        out["threat"]["name"] = out["threat"]["family"]
    out["absent"] = absent(out)
    return out


def absent(assertion):
    """The assertions this Alert does not carry, named as §1.1 names them."""
    missing = []
    if not assertion["techniques"]:
        missing.append(FIELDS["techniques"])
    if not assertion["threat"]:
        missing.append(FIELDS["threat_name"])
    if not assertion["detection"]["source"]:
        missing.append(FIELDS["detection_source"])
    if not assertion["description"]:
        missing.append(FIELDS["description"])
    if not assertion["recommended_actions"]:
        missing.append(FIELDS["recommended_actions"])
    return sorted(missing)


def remediation(rows, amap):
    """The remediation state the source reports per entity, one entry per entity it acted on.

    An entity the source left active carries no entry: §1.5 makes it the live part of the Case, and the
    absence of a remediation is not a state. A state the map does not declare is recorded as reported
    and is not treated as neutralized.
    """
    spec = spec_of(amap)
    states = spec.get("remediation_states") or {}
    out = []
    for row in rows or []:
        state = field(row, spec, "remediation_status", group="entity_fields")
        if state in (None, "", "unknown"):
            continue
        known = states.get(str(state)) or {}
        ids = row.get("alert_ids") or []
        out.append({
            "entity": row.get("name") or row.get("value"),
            "type": row.get("type"),
            "device": row.get("device"),
            "state": str(state),
            "neutralized": bool(known.get("neutralized")),
            "status": known.get("status", "Unknown"),
            "activity": known.get("activity"),
            "details": str(field(row, spec, "remediation_status_details", group="entity_fields") or "") or None,
            "alert_ids": [ids] if isinstance(ids, str) else list(ids),
            "declared": bool(known),
        })
    return out


def gaps(built, evidence_read=False):
    """Every assertion an Alert of the Case did not carry, as a gap with the check it prevented.

    One gap per assertion, naming the alerts that lack it: an assertion missing on one alert of twenty
    is a gap for that alert's triage, and the Case's other alerts do not make it up. The remediation
    state is a gap only once the evidence has been read — an executor that did not pass the evidence has
    not established that the source reports none, and a gap is a finding about the deployment, not about
    how the script was called.
    """
    missing = {}
    for alert in built["alerts"]:
        for name in alert["absent"]:
            missing.setdefault(name, []).append(alert["id"])
    out = []
    for name in sorted(missing):
        out.append({"data_source": f"alert metadata: {name}",
                    "check_prevented": PREVENTS.get(name, f"the {name} the source did not supply"),
                    "alerts": missing[name]})
    if built["alerts"] and evidence_read and not built["remediation"]:
        out.append({"data_source": "alert metadata: remediation state",
                    "check_prevented": PREVENTS["remediation state"],
                    "alerts": [a["id"] for a in built["alerts"]]})
    return out


def build(alerts, amap, evidence=None, index=None):
    """The Case's assertions, ledger-ready: per alert, then what they add up to for the Case."""
    built = {"alerts": [assertions(a, amap, index) for a in alerts],
             "remediation": remediation(evidence, amap)}
    seen, techniques = set(), []
    for alert in built["alerts"]:
        for t in alert["techniques"]:
            if t["id"] not in seen:
                seen.add(t["id"])
                techniques.append(t["id"])
    built["techniques"] = techniques
    built["candidate_incident_categories"] = sorted({c for a in built["alerts"] for c in a["candidate_incident_categories"]})
    built["recommended_actions"] = dispositions(actions_of(built))
    built["neutralized_entities"] = neutralized(built)
    built["visibility_gaps"] = gaps(built, evidence_read=evidence is not None)
    return built


def techniques_of(record):
    """Alert id -> the technique identifiers its detection named, for the decision rules."""
    out = {}
    for alert in (record or {}).get("alerts", []):
        out[str(alert.get("id"))] = [str(t.get("id")) for t in alert.get("techniques", []) if t.get("id")]
    return out


def decision_notes(record, ledger=None):
    """What a decision script says about the assertions: the lines a reader of the run must see.

    A Case decided without them is decided on less than the source supplied (§1.1), a recommendation
    left unread holds the decision (§1.5), and a remediated entity is recorded without ever explaining
    anything. Absences already recorded as visibility gaps are not repeated here.
    """
    if not record:
        return ["what the detection asserts was not extracted: run scripts/alert_metadata.py on the Case's "
                "alerts before deciding — its techniques, threat name, detection source, remediation state, "
                "description and recommended actions are required inputs of triage"]
    out = []
    recorded = {str(g.get("data_source", "")).lower() for g in
                list(record.get("visibility_gaps") or []) + list((ledger or {}).get("visibility_gaps") or [])}
    missing = sorted({a for alert in record.get("alerts", []) for a in alert.get("absent", [])
                      if f"alert metadata: {a}" not in recorded})
    if missing:
        out.append("the source supplied no " + ", ".join(missing) +
                   ": record each as a visibility gap with the check it prevented, and never infer one from the alert title")
    open_ = dispositions(actions_of(record))["open"]
    if open_:
        out.append("recommended actions still unread: " + ", ".join(str(i) for i in open_) +
                   " — follow each, or set it aside with a stated reason, before the Case is decided")
    neutralized = [r for r in record.get("remediation", []) if r.get("neutralized")]
    if neutralized:
        out.append("the source already neutralized " + ", ".join(str(r.get("entity")) for r in neutralized) +
                   ": recorded as an action of the Case and not an explanation of it — what remains open is how it "
                   "arrived, what ran before it was stopped, and whether the same thing is elsewhere")
    undeclared = sorted({str(r.get("state")) for r in record.get("remediation", []) if not r.get("declared")})
    if undeclared:
        out.append("remediation states the deployment's map does not declare: " + ", ".join(undeclared) +
                   " — add them to detection_metadata.remediation_states; until then they count as not neutralized")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("alerts")
    ap.add_argument("--map")
    ap.add_argument("--bindings", help="capability binding whose alert_type_map names the map, next to it")
    ap.add_argument("--evidence", help="the evidence rows, for the remediation state the source reports per entity")
    ap.add_argument("--root", default=FRAMEWORK)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    path = a.map
    if not path and a.bindings:
        named = json.load(open(a.bindings, encoding="utf-8")).get("alert_type_map")
        path = os.path.join(os.path.dirname(os.path.abspath(a.bindings)), named) if named else None
    if not path:
        ap.error("--map, or --bindings with an alert_type_map, is required")
    with open(path, encoding="utf-8") as handle:
        amap = json.load(handle)
    evidence = json.load(open(a.evidence, encoding="utf-8")) if a.evidence else None
    if isinstance(evidence, dict):  # the output of evidence_inventory.py
        evidence = evidence.get("entities") or evidence.get("rows") or []
    index = technique_index(a.root) if (technique_index and a.root and os.path.isdir(a.root)) else None
    built = build(json.load(open(a.alerts, encoding="utf-8")), amap, evidence, index)
    if a.json:
        print(json.dumps(built, indent=2, ensure_ascii=False))
        return 0  # the gaps are in the output; a caller reading JSON is not failed by them
    for alert in built["alerts"]:
        print(f"{alert['id']}")
        print("  techniques: " + (", ".join(t["rendered"] for t in alert["techniques"]) or "none asserted"))
        threat = alert["threat"]
        print("  threat: " + (f"{threat['name']}" + (f" (family {threat['family']})" if threat["family"] else "") if threat else "none named"))
        print(f"  detected by: {alert['detection']['source'] or 'not stated'}"
              f" (OCSF analytic type {alert['detection']['analytic_type_id']} {alert['detection']['analytic_type']})"
              + (f", detector {alert['detection']['detector_id']}" if alert["detection"]["detector_id"] else ""))
        for action in alert["recommended_actions"]:
            print(f"  recommended: {action['action']} — follow it, or set it aside with a reason")
        if alert["absent"]:
            print("  not supplied: " + ", ".join(alert["absent"]))
    if built["remediation"]:
        print("\nremediation the source already performed (an action of the Case, not an explanation of it):")
        for r in built["remediation"]:
            print(f"  {r['type']}\t{r['entity']}\t{r['state']}\t{'neutralized' if r['neutralized'] else 'still to be treated as live'}"
                  + ("" if r["declared"] else "\t(state not declared in the map: add it)"))
    print("\ncandidate_incident_categories: " + (", ".join(built["candidate_incident_categories"]) or "none from the techniques"))
    if built["techniques"]:
        unknown = sorted({t for a in built["alerts"] for t in a["techniques_not_in_the_catalog"]})
        if unknown:
            print("techniques the framework's tables do not hold; record them and name them in the Note: " + ", ".join(unknown))
    for gap in built["visibility_gaps"]:
        print(f"VISIBILITY GAP: {gap['data_source']} — {gap['check_prevented']}")
    return 3 if built["visibility_gaps"] else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
