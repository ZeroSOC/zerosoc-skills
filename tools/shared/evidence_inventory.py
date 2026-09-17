#!/usr/bin/env python3
"""Build the evidence inventory of a Case and record its completeness. Standard library only.

  evidence_inventory.py evidence.json [--source-count N] [--alert-devices devices.json] [--json]

Extraction is a step, not a side effect of reading: before the ledger is started, every entity the
source attaches to the Case's alerts is listed once, joined to its device, with the alerts that cite it,
and the count is compared with what the source itself shows (N). A mismatch is printed and recorded, so
a ledger is never silently built from part of the evidence.

evidence.json: a list of rows {"type": "process|file|device|user|ip|url|registry|mailbox|...", "name"|"value",
"device"?, "alert_ids": [...], ...any attributes (pid, created, sha256, path, command_line, verdict)}.
Rows the source leaves without a device are attached through the device row of the same alert;
devices.json ({"<alert id>": "<device name>"}) settles the alerts that cite several devices.
Record the printed "evidence_inventory" object in ledger.json; the decision scripts surface it.
"""
import argparse, json, sys

IDENTITY = ("sha256", "sha1", "pid", "created", "path", "key", "value", "name")


SCOPED = ("process", "file", "registry")  # the same name on two devices is two entities


def _identity(row):
    return (str(row.get("type", "")).lower(),) + tuple(str(row.get(k, "")).strip().lower() for k in IDENTITY)


def _same_place(entity, row, device):
    """Unscoped types match on identity alone; scoped ones unless both devices are known and differ."""
    if row.get("type") not in SCOPED or not entity.get("device") or not device:
        return True
    return str(entity["device"]).lower() == str(device).lower()


def _devices_by_alert(rows):
    """Alert id -> device, from the device rows themselves; an alert citing several devices joins nothing."""
    seen = {}
    for row in rows:
        if row.get("type") == "device" and row.get("name"):
            for alert_id in row.get("alert_ids") or []:
                seen.setdefault(alert_id, set()).add(row["name"])
    return {alert_id: next(iter(names)) for alert_id, names in seen.items() if len(names) == 1}


def build(rows, alert_devices=None):
    """De-duplicated entities, each joined to its device and listing the alerts that cite it."""
    alert_devices = dict(_devices_by_alert(rows), **(alert_devices or {}))
    by_identity, entities = {}, []
    for row in rows:
        ids = list(row.get("alert_ids") or [])
        device = row.get("device") or next((alert_devices[i] for i in ids if i in alert_devices), None)
        if row.get("type") == "device":
            device = row.get("name") or device
        candidates = by_identity.setdefault(_identity(row), [])
        entity = next((e for e in candidates if _same_place(e, row, device)), None)
        if entity is None:
            entity = dict(row, device=device, alert_ids=[])
            candidates.append(entity)
            entities.append(entity)
        entity["device"] = entity.get("device") or device
        entity["alert_ids"] = sorted(set(entity["alert_ids"]) | set(ids))
        for k, v in row.items():
            entity.setdefault(k, v)
    return {"count": len(entities), "entities": entities}


def completeness(inventory, source_count):
    """The object to record in the ledger: extracted vs what the source shows."""
    complete = None if source_count is None else inventory["count"] == source_count
    return {"extracted": inventory["count"], "source_count": source_count, "complete": complete}


def note(record):
    """One line for a decision script to print, or None when the inventory is complete."""
    if not record:
        return "evidence inventory not recorded: run scripts/evidence_inventory.py before starting the ledger"
    if record.get("complete") is None:
        return f"evidence inventory unverified: {record.get('extracted')} entities extracted, the source count was not recorded"
    if not record.get("complete"):
        return f"evidence inventory incomplete: {record.get('extracted')} of {record.get('source_count')} entities extracted; extract the rest before deciding"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence")
    ap.add_argument("--source-count", type=int)
    ap.add_argument("--alert-devices")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    devices = json.load(open(a.alert_devices, encoding="utf-8")) if a.alert_devices else None
    inventory = build(json.load(open(a.evidence, encoding="utf-8")), devices)
    record = completeness(inventory, a.source_count)
    if a.json:
        print(json.dumps({"evidence_inventory": record, **inventory}, indent=2, ensure_ascii=False))
    else:
        for e in inventory["entities"]:
            print(f"{e.get('type')}\t{e.get('name') or e.get('value')}\t{e.get('device') or '-'}\t{','.join(e['alert_ids'])}")
        print(f"evidence_inventory: {json.dumps(record)}")
        if note(record):
            print(note(record).upper() if record.get("complete") is False else note(record))
    sys.exit(4 if record["complete"] is False else 0)


if __name__ == "__main__":
    main()
