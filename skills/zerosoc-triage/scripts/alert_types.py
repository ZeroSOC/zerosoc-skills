#!/usr/bin/env python3
"""Build the ledger's alerts from the alert types the executor chose. Standard library only.

  alert_types.py alerts.json [--json]

Detection & Analysis §1.1: the same alert type on the same entity counts once. The executor chooses
each alert's type from the Alert Catalogs of the triage playbooks (select_playbook.py --catalogs), by
what the detection fires on: its description, its evidence, its techniques and what detected it. The
title is the source's name for the detection and decides nothing. This script checks each choice
against the framework's alert types and collapses the same type on the same entity to the strongest
alert, listing what it merged.

alerts.json: a list of {"id", "title", "entity", "alert_type"?, "no_type_reason"?, "severity"?,
"confidence"?, "threat_family"?, "technique"?, "detector_id"?}. "alert_type" is a row of the framework's alert types;
an alert no row fits carries "no_type_reason" in its place, keeps its title as its type, and is
flagged "unmapped" with that reason: the taxonomy is not bent to cover what it does not describe (a
source's correlation, attribution or containment record states a conclusion, not a behaviour). An
alert type the framework does not hold, or an alert with neither field, is refused: exit 2.

Output: the "alerts" array of ledger.json (format in triage_decide.py). Each entry also carries
"alert_type" and "side": "Malicious", so the same entries seed the observations of resolve.py, where
one type on one entity again counts once.
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "references", "framework"))
TAXONOMY = os.path.join("02-Taxonomy", "alert_types.md")

sys.path.insert(0, HERE)  # the shared scripts sit beside this one (copied by build_references)
from confidence import W, alert_confidence  # noqa: E402


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


def known_types(root=ROOT):
    with open(os.path.join(root, TAXONOMY), encoding="utf-8") as handle:
        return framework_alert_types(handle.read())


def typed(alert, known):
    """The alert as the ledger carries it: {"type", "domain", "unmapped", ...}.

    The type is the executor's choice, held to the framework's names: its domain is the one the
    taxonomy gives the type. An alert no type fits keeps its own title, with the reason.
    """
    title = re.sub(r"\s+", " ", str(alert.get("title") or "")).strip()
    chosen = str(alert.get("alert_type") or "").strip()
    reason = str(alert.get("no_type_reason") or "").strip()
    if chosen:
        domain = next((d for t, d in known.items() if t.casefold() == chosen.casefold()), None)
        if domain is None:
            raise ValueError(f"alert {alert.get('id')}: '{chosen}' is not an alert type of the framework;"
                             " choose a row of an Alert Catalog, or give no_type_reason")
        chosen = next(t for t in known if t.casefold() == chosen.casefold())
    elif not reason:
        raise ValueError(f"alert {alert.get('id')}: neither an alert_type nor a no_type_reason")
    out = {"id": alert.get("id"), "type": chosen or title, "alert_type": chosen or title, "side": "Malicious",
           "domain": domain if chosen else None, "entity": str(alert.get("entity") or ""),
           "confidence": alert_confidence(alert), "source_title": title, "unmapped": not chosen}
    if not chosen:
        out["unmapped_reason"] = reason
    for key in ("severity", "technique", "detector_id"):
        if alert.get(key):
            out[key] = alert[key]
    return out


def build_alerts(alerts, known):
    """Typed alerts, same type on the same entity collapsed to the strongest, in first-seen order."""
    best, order = {}, []
    for alert in alerts:
        c = typed(alert, known)
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
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        out = build_alerts(json.load(open(a.alerts, encoding="utf-8")), known_types(a.root))
    except ValueError as refused:
        print(refused, file=sys.stderr)
        sys.exit(2)
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    for x in out:
        flag = f"  no alert type fits: {x['unmapped_reason']}" if x["unmapped"] else ""
        merged = f"  (counts once for {', '.join(x['merged_ids'])})" if len(x["merged_ids"]) > 1 else ""
        print(f"{x['id']}\t{x['type']}\t{x['entity']}\t{x['confidence']}{merged}{flag}")


if __name__ == "__main__":
    main()
