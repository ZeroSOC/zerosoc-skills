#!/usr/bin/env python3
"""Map source alerts to the framework's alert types and build the ledger's alerts. Standard library only.

  alert_types.py alerts.json --map alert_types.<source>.json [--json]

Detection & Analysis §1.1: the same alert type on the same entity counts once. That is only
deterministic when the alert type is: this script assigns it from a deployment's map (detector id first,
then title pattern) and collapses same type + same entity to the strongest alert, listing what it merged.

alerts.json: a list of {"id", "title", "detector_id"?, "entity", "severity"?, "confidence"?, "technique"?}
(the source's own field names detectorId / detectionSource are accepted). The map is a JSON file shipped
with the capability binding of the deployment (see the repository's capabilities/ folder):
{"source": "...", "rules": [{"alert_type": "<framework alert type>", "domain": "<telemetry domain>",
                             "detector_ids": ["..."], "title_patterns": ["<regex, case-insensitive>"]}]}
An alert no rule matches keeps its normalized title as its type and is flagged "unmapped": it still
deduplicates, and the flag tells the maintainer of the map what to add. Output: the "alerts" array of
ledger.json (format in triage_decide.py), which resolve.py also accepts as seeded findings.
"""
import argparse, json, re, sys

W = {"Low": 1, "Medium": 2, "High": 3}
SEV2CONF = {"Informational": "Low", "Low": "Low", "Medium": "Medium", "High": "High", "Critical": "High"}


def load_map(path):
    m = json.load(open(path, encoding="utf-8"))
    for rule in m.get("rules", []):
        for pat in rule.get("title_patterns", []):
            re.compile(pat)  # fail at load, not at the first alert
    return m


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


def _confidence(alert):
    sev = str(alert.get("severity") or "Medium").capitalize()
    return alert.get("confidence") or SEV2CONF.get(sev, "Medium")


def classify(alert, amap):
    """The alert with its framework type: {"type", "domain", "unmapped", "matched_on", ...}."""
    detector = alert.get("detector_id") or alert.get("detectorId")
    title = re.sub(r"\s+", " ", str(alert.get("title") or "")).strip()
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
    out = {"id": alert.get("id"), "type": hit["alert_type"] if hit else title, "domain": hit["domain"] if hit else None,
           "entity": alert.get("entity", ""), "confidence": _confidence(alert), "source_title": title,
           "unmapped": hit is None, "matched_on": matched_on}
    for key in ("severity", "technique"):
        if alert.get(key):
            out[key] = alert[key]
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
    ap.add_argument("--map", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    out = build_alerts(json.load(open(a.alerts, encoding="utf-8")), load_map(a.map))
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    for x in out:
        flag = "  UNMAPPED: add a rule to the map" if x["unmapped"] else ""
        merged = f"  (counts once for {', '.join(x['merged_ids'])})" if len(x["merged_ids"]) > 1 else ""
        print(f"{x['id']}\t{x['type']}\t{x['entity']}\t{x['confidence']}{merged}{flag}")
    if any(x["unmapped"] for x in out):
        sys.exit(3)


if __name__ == "__main__":
    main()
