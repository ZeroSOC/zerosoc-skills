#!/usr/bin/env python3
"""Map source alerts to the framework's alert types and build the ledger's alerts. Standard library only.

  alert_types.py alerts.json --profile <source_profile.json> [--json]

Detection & Analysis §1.1: the same alert type on the same entity counts once. That is only
deterministic when the alert type is: this script assigns it from the source profile (detector id first,
then title pattern) and collapses same type + same entity to the strongest alert, listing what it merged.

That counting, and an alert type that groups with the same behaviour under another vendor's name, are
what the type is for. Choosing a playbook is not: the executor identifies the telemetry domain, and
the techniques the detection asserts point at the candidate alert types (select_playbook.py
--technique), both before this runs. An alert left unmapped changes neither.

  alert_types.py alerts.json --bindings zerosoc.capabilities.json   (reads the binding's "source_profiles")

alerts.json: a list of {"id", "title", "detector_id"?, "entity", "severity"?, "confidence"?, "technique"?}.
The rules are the `alert_types` block of the technology's **source profile** (one versioned home for
what its records mean, validated against capabilities/source_profile.schema.json):
{"alert_types": {"fields": {"detector_id": "<the source's own field name>", ...},
                 "rules": [{"alert_type": "<framework alert type>", "domain": "<telemetry domain>",
                            "detector_ids": ["..."], "title_patterns": ["<regex, case-insensitive>"]},
                           {"unmapped": true, "reason": "<why no framework type is right>",
                            "title_patterns": ["..."]}]}}
"fields" lets the source's records be passed unrenamed; the script itself knows no source. An alert no
rule matches keeps its normalized title as its type and is flagged "unmapped": it still deduplicates,
and the flag tells the maintainer of the profile what to add. Some alerts should stay that way — a
source's correlation, attribution and containment records state a conclusion rather than a behaviour,
and no behaviour type is true of them. A rule declaring "unmapped" says so, with the reason, and the
alert is flagged exactly as before: the taxonomy is not bent to cover what it does not describe, and
the maintainer's list of what to add stops carrying what was already decided. Output: the "alerts"
array of ledger.json
(format in triage_decide.py). Each entry also carries "alert_type" and "side": "Malicious", so the same
entries seed the findings of resolve.py, where one type on one entity again counts once.
"""
import argparse, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import source_profile

W = {"Low": 1, "Medium": 2, "High": 3}
SEV2CONF = {"Informational": "Low", "Low": "Low", "Medium": "Medium", "High": "High", "Critical": "High"}


def load_map(path, override=None):
    """The alert-type rules of the technology at ``path``: its source profile's own block, with the
    deployment's local override laid over it where it names one."""
    return source_profile.alert_rules(source_profile.load(path, override))


def framework_alert_types(markdown):
    """Alert type -> telemetry domain, read from the framework's alert_types.md tables."""
    out, domain = {}, None
    for line in markdown.splitlines():
        h = re.match(r"^##\s+(.+?)\s*$", line)
        if h:
            domain = h.group(1)
            continue
        row = re.match(r"^\|\s*([^|]+?)\s*\|", line)
        if row and domain and row.group(1) not in ("Alert Type",) and not set(row.group(1)) <= set("-: "):
            out[row.group(1)] = domain
    return out


def _field(alert, amap, name):
    """The canonical field, or the source's own name for it as the profile declares under "fields"."""
    value = alert.get(name)
    alias = (amap.get("fields") or {}).get(name)
    return value if value not in (None, "") or not alias else alert.get(alias)


def _confidence(alert, amap):
    stated = str(_field(alert, amap, "confidence") or "").capitalize()
    if stated in W:
        return stated
    return SEV2CONF.get(str(_field(alert, amap, "severity") or "Medium").capitalize(), "Medium")


def classify(alert, amap):
    """The alert with its framework type: {"type", "domain", "unmapped", "matched_on", ...}.

    A rule that declares ``unmapped`` leaves the alert its own title, exactly as no rule at all would,
    and carries the reason on ``unmapped_reason``. The difference is ``matched_on``: a gap somebody
    decided says which rule decided it, and one nobody has looked at yet says nothing.
    """
    detector = _field(alert, amap, "detector_id")
    title = re.sub(r"\s+", " ", str(_field(alert, amap, "title") or "")).strip()
    hit, matched_on = None, None
    for rule in amap.get("rules", []):
        if detector and detector in rule.get("detector_ids", []):
            hit, matched_on = rule, "detector_id"
            break
    if hit is None:
        for rule in amap.get("rules", []):
            if any(re.search(p, title, re.IGNORECASE) for p in rule.get("title_patterns", [])):
                hit, matched_on = rule, "title"
                break
    decided = bool(hit and hit.get("unmapped"))
    mapped = hit is not None and not decided
    alert_type = hit["alert_type"] if mapped else title
    out = {"id": _field(alert, amap, "id"), "type": alert_type, "alert_type": alert_type, "side": "Malicious",
           "domain": hit["domain"] if mapped else None, "entity": str(_field(alert, amap, "entity") or ""),
           "confidence": _confidence(alert, amap), "source_title": title, "unmapped": not mapped,
           "matched_on": matched_on}
    if decided:
        out["unmapped_reason"] = hit["reason"]
    for key in ("severity", "technique"):
        if _field(alert, amap, key):
            out[key] = _field(alert, amap, key)
    if detector:
        out["detector_id"] = detector
    return out


def build_alerts(alerts, amap):
    """Classified alerts, same type on the same entity collapsed to the strongest, in first-seen order."""
    best, order = {}, []
    for alert in alerts:
        c = classify(alert, amap)
        key = (c["type"].strip().lower(), str(c["entity"]).strip().lower())
        if key not in best:
            best[key] = dict(c, merged_ids=[c["id"]])
            order.append(key)
            continue
        kept = best[key]
        merged = kept["merged_ids"] + [c["id"]]
        if W[c["confidence"]] > W[kept["confidence"]]:
            kept = dict(c)
        kept["merged_ids"] = merged
        best[key] = kept
    return [best[k] for k in order]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("alerts")
    source_profile.add_arguments(ap)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    profile = source_profile.from_arguments(ap, a)
    out = build_alerts(json.load(open(a.alerts, encoding="utf-8")), source_profile.alert_rules(profile))
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    for x in out:
        if x.get("unmapped_reason"):        # a gap the profile decided: there is nothing to add
            flag = f"  left unmapped on purpose: {x['unmapped_reason']}"
        elif x["unmapped"]:
            flag = "  UNMAPPED: add a rule to the source profile's alert_types"
        else:
            flag = ""
        merged = f"  (counts once for {', '.join(x['merged_ids'])})" if len(x["merged_ids"]) > 1 else ""
        print(f"{x['id']}\t{x['type']}\t{x['entity']}\t{x['confidence']}{merged}{flag}")
    if any(x["unmapped"] and not x.get("unmapped_reason") for x in out):
        sys.exit(3)


if __name__ == "__main__":
    main()
