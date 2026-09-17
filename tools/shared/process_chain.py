#!/usr/bin/env python3
"""Reconstruct the process lineage of a Case from its evidence rows. Standard library only.

  process_chain.py evidence.json [--case] [--alerts alerts.json] [--json]

One chain per alert, the way a console shows an alert story: the processes the alert cites, each under its
ancestors, which are marked as context when they come from the Case's other alerts. `--case` prints the
Case-wide chain instead, every alert joined into one tree per device: the view an investigation scores on.

The chain is evidence-only: it holds the processes the source attached to the Case's alerts, never the
processes around them. A parent outside the evidence is printed as a lineage gap, to be filled from endpoint
telemetry when it is bound; it is never guessed. An alert whose evidence names no process has no chain here,
whatever the console draws from its own process telemetry.

evidence.json: the rows given to evidence_inventory.py (a list, or its --json output with "entities").
alerts.json (optional): {"<alert id>": {"title": ..., "severity": ...}}, to title the per-alert sections.
Process rows carry "pid", "created", "parent_pid", "parent_created", "parent_name" and "device", times in UTC.

- One node per process, not per row: rows with the same device, PID and creation time are one process,
  and the node keeps every row's name, verdict and alert.
- A child joins its parent on (device, parent PID, parent creation time), never on the PID alone: PIDs are
  reused. A parent reported without its creation time is a gap.
- Times match when they differ by less than one unit of the coarser precision: sources mix milliseconds and
  microseconds and drop trailing zeros. Device names are compared without case.
- A row without a device, PID or creation time is unplaced: listed, never linked.
- Conflicting parents for one process and a child created before its parent are reported as anomalies.
"""
import argparse, json, re, sys
from datetime import datetime

LABEL = "evidence-only chain"
TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(value):
    """(microseconds since the epoch, digits of precision up to 6), or None. A time without a zone is UTC."""
    m = TIME.match(str(value or "").strip())
    if not m:
        return None
    day, clock, frac, zone = m.groups()
    zone = "+00:00" if zone in (None, "Z") else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
    seconds = int(datetime.fromisoformat(f"{day}T{clock}{zone}").timestamp())
    frac = (frac or "")[:6]
    return seconds * 1_000_000 + int(frac.ljust(6, "0") or 0), len(frac)


def same_time(a, b):
    return abs(a[0] - b[0]) < 10 ** (6 - min(a[1], b[1]))


def _device(row):
    name = str(row.get("device") or "").strip()
    return None if name in ("", "?", "-") else name


def _pid(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ids(row):
    ids = row.get("alert_ids") or []
    return [ids] if isinstance(ids, str) else list(ids)


def _find(index, device, pid, time):
    return next((n for n in index.get((device.lower(), pid), []) if same_time(n["_t"], time)), None)


def _node(index, device, pid, created, time, in_evidence):
    node = {"device": device, "pid": pid, "created": created, "_t": time, "in_evidence": in_evidence,
            "names": [], "verdicts": [], "alert_ids": [], "command_lines": [], "rows": 0, "_parent": None, "children": []}
    index.setdefault((device.lower(), pid), []).append(node)
    return node


UNNAMED = ("", "(unnamed)")  # a source's placeholder for a process reported without its image file


def _add(values, value):
    if value is not None and value not in UNNAMED and value not in values:
        values.append(value)


def build(rows):
    """Nodes per device with their parent links, lineage gaps, unplaced rows and anomalies."""
    rows = rows.get("entities", []) if isinstance(rows, dict) else rows
    index, gap_index, nodes, gaps, unplaced, anomalies = {}, {}, [], [], [], []
    procs = [r for r in rows if str(r.get("type", "")).strip().lower() == "process"]
    for row in procs:
        device, pid, time = _device(row), _pid(row.get("pid")), parse_time(row.get("created"))
        missing = [k for k, v in (("device", device), ("pid", pid), ("created", time)) if v is None]
        if missing:
            unplaced.append({"name": row.get("name"), "pid": row.get("pid"), "created": row.get("created"),
                             "device": row.get("device"), "alert_ids": _ids(row), "missing": missing})
            continue
        node = _find(index, device, pid, time)
        if node is None:
            node = _node(index, device, pid, row.get("created"), time, True)
            nodes.append(node)
        elif time[1] > node["_t"][1]:
            node["created"], node["_t"] = row.get("created"), time
        node["rows"] += 1
        _add(node["names"], row.get("name"))
        _add(node["verdicts"], row.get("verdict"))
        _add(node["command_lines"], row.get("command_line"))
        node["alert_ids"] = sorted(set(node["alert_ids"]) | set(_ids(row)))
        ppid = _pid(row.get("parent_pid"))
        if ppid is None:
            continue
        ref = {"pid": ppid, "created": row.get("parent_created"), "name": row.get("parent_name")}
        known = node["_parent"]
        if known is None:
            node["_parent"] = ref
            continue
        a, b = parse_time(known["created"]), parse_time(ref["created"])
        if known["pid"] != ppid or (a and b and not same_time(a, b)):
            anomalies.append(f"{device} {node['names'][0] if node['names'] else '?'} {pid}: rows report different parents ({known['pid']} and {ppid})")
            continue
        known["created"] = known["created"] or ref["created"]
        known["name"] = known["name"] or ref["name"]

    for node in nodes:
        ref = node["_parent"]
        if ref is None:
            continue
        time = parse_time(ref["created"])
        parent = _find(index, node["device"], ref["pid"], time) if time else None
        if parent is node:
            anomalies.append(f"{node['device']} {node['pid']}: a process reported as its own parent")
            continue
        if parent is None:
            parent = _find(gap_index, node["device"], ref["pid"], time) if time else None
            if parent is None:
                parent = _node(gap_index, node["device"], ref["pid"], ref["created"], time, False)
                parent["gap"] = "outside the evidence" if time else "parent creation time not reported"
                gaps.append(parent)
            _add(parent["names"], ref["name"])
            parent["alert_ids"] = sorted(set(parent["alert_ids"]) | set(node["alert_ids"]))
        elif node["_t"][0] + 10 ** (6 - min(node["_t"][1], parent["_t"][1])) <= parent["_t"][0]:
            anomalies.append(f"{node['device']} {node['pid']}: created before its parent {parent['pid']}")
        node["parent"] = parent
        parent["children"].append(node)

    devices, reached = {}, set()
    for n in nodes + gaps:
        devices.setdefault(n["device"].lower(), {"device": n["device"], "roots": []})
        if "parent" not in n:
            devices[n["device"].lower()]["roots"].append(n)
            _reach(n, reached)
    for n in nodes:
        if id(n) not in reached:  # only a loop of parents leaves a process unreachable from every root
            anomalies.append(f"{n['device']} {n['pid']}: its parents form a loop")
            devices[n["device"].lower()]["roots"].append(n)
            _reach(n, reached)
    return {"nodes": nodes, "gaps": gaps, "devices": [devices[k] for k in sorted(devices)],
            "unplaced": unplaced, "anomalies": anomalies, "rows": len(procs)}


def _reach(node, reached):
    stack = [node]
    while stack:
        n = stack.pop()
        if id(n) not in reached:
            reached.add(id(n))
            stack.extend(n["children"])


def _key(n):
    return n["_t"][0] if n["_t"] else float("inf")


def _tree(node, seen, section=None):
    out = {k: node[k] for k in ("pid", "created", "in_evidence", "alert_ids")}
    if section is not None and node["in_evidence"]:
        out["cited_by_this_alert"] = id(node) in section["own"]
    out["name"] = node["names"][0] if node["names"] else None
    if len(node["names"]) > 1:
        out["names"] = node["names"]
    if node["in_evidence"]:
        out.update(verdicts=node["verdicts"], rows=node["rows"], command_lines=node["command_lines"])
    else:
        out["gap"] = node["gap"]
    seen.add(id(node))
    out["children"] = [_tree(c, seen, section) for c in sorted(node["children"], key=_key)
                       if id(c) not in seen and (section is None or id(c) in section["nodes"])]
    return out


def per_alert(chain):
    """One section per alert citing a process: its processes, closed upwards over their ancestors."""
    sections = {}
    for node in chain["nodes"]:
        for alert in node["alert_ids"]:
            own, nodes = sections.setdefault(alert, (set(), {}))
            own.add(id(node))
            walk = node
            while walk is not None and id(walk) not in nodes:
                nodes[id(walk)] = walk
                walk = walk.get("parent")
    out = []
    for alert in sorted(sections, key=lambda a: min(_key(n) for n in sections[a][1].values())):
        own, nodes = sections[alert]
        roots = [n for n in nodes.values() if n.get("parent") is None or id(n["parent"]) not in nodes]
        devices = {}
        for root in sorted(roots, key=_key):
            devices.setdefault(root["device"].lower(), {"device": root["device"], "roots": []})["roots"].append(root)
        out.append({"alert_id": alert, "own": own, "nodes": nodes, "devices": [devices[k] for k in sorted(devices)],
                    "processes": sum(1 for n in nodes.values() if n["in_evidence"]), "cited": len(own)})
    return out


def timeline(chain):
    """One entry per process in the evidence, oldest first, with its alerts as event references."""
    entries = []
    for n in sorted(chain["nodes"], key=_key):
        parent = n.get("parent")
        entries.append({"time": n["created"], "device": n["device"], "pid": n["pid"],
                        "process": n["names"][0] if n["names"] else None,
                        "parent_pid": parent["pid"] if parent else None,
                        "parent": (parent["names"][0] if parent["names"] else None) if parent else None,
                        "parent_in_evidence": parent["in_evidence"] if parent else None,
                        "event_refs": n["alert_ids"]})
    return entries


def summary(chain):
    return {"label": LABEL, "process_rows": chain["rows"], "processes": len(chain["nodes"]),
            "devices": len(chain["devices"]), "lineage_gaps": len(chain["gaps"]),
            "unplaced": len(chain["unplaced"]), "anomalies": len(chain["anomalies"])}


def as_json(chain):
    seen = set()
    sections = []
    for section in per_alert(chain):
        shown = set()
        sections.append({"alert_id": section["alert_id"], "processes_cited": section["cited"],
                         "ancestors_from_the_case": section["processes"] - section["cited"],
                         "devices": [{"device": d["device"], "tree": [_tree(r, shown, section) for r in sorted(d["roots"], key=_key)]}
                                     for d in section["devices"]]})
    return {"process_chain": dict(summary(chain), alerts_citing_a_process=len(sections)),
            "alerts": sections,
            "devices": [{"device": d["device"], "tree": [_tree(r, seen) for r in sorted(d["roots"], key=_key)]} for d in chain["devices"]],
            "lineage_gaps": [{"device": g["device"], "pid": g["pid"], "created": g["created"], "name": g["names"][0] if g["names"] else None,
                              "reason": g["gap"], "children": [c["pid"] for c in g["children"]]} for g in chain["gaps"]],
            "unplaced": chain["unplaced"], "anomalies": chain["anomalies"], "timeline": timeline(chain)}


def _lines(node, depth, seen, out, section=None):
    seen.add(id(node))
    name = node["names"][0] if node["names"] else "(unnamed)"
    if section is not None and node["in_evidence"] and id(node) not in section["own"]:
        out.append(f"{'  ' * depth}{name} {node['pid']} {node['created']} (context: another alert of the Case)")
    elif node["in_evidence"]:
        also = f" (also {', '.join(node['names'][1:])})" if len(node["names"]) > 1 else ""
        out.append(f"{'  ' * depth}{name}{also} {node['pid']} {node['created']} {'/'.join(node['verdicts']) or '-'} alerts={len(node['alert_ids'])}")
    else:
        out.append(f"{'  ' * depth}[gap] {name} {node['pid']} {node['created'] or '-'}: {node['gap']}")
    for child in sorted(node["children"], key=_key):
        if id(child) not in seen and (section is None or id(child) in section["nodes"]):
            _lines(child, depth + 1, seen, out, section)


def _titles(sections, alerts):
    for section in sections:
        meta = (alerts or {}).get(section["alert_id"]) or {}
        title = meta.get("title") or meta.get("displayName")
        yield section, f"alert {section['alert_id']}" + (f": {title}" if title else "")


def as_text(chain, alerts=None, case=False):
    s = summary(chain)
    head = (f"{LABEL}: {s['processes']} processes from {s['process_rows']} rows on {s['devices']} devices; "
            f"{s['lineage_gaps']} lineage gaps, {s['unplaced']} unplaced, {s['anomalies']} anomalies")
    out = [head if case else head + f"; {len(per_alert(chain))} of the Case's alerts cite a process"]
    if not case:
        for section, title in _titles(per_alert(chain), alerts):
            out.append(f"{title} — {section['cited']} processes cited, {section['processes'] - section['cited']} ancestors from the Case")
            seen = set()
            for d in section["devices"]:
                out.append(f"  {d['device']}")
                for root in sorted(d["roots"], key=_key):
                    _lines(root, 2, seen, out, section)
        out += [f"unplaced: {u.get('name') or '(unnamed)'} {u.get('pid')} missing {', '.join(u['missing'])}" for u in chain["unplaced"]]
        out += [f"anomaly: {a}" for a in chain["anomalies"]]
        return "\n".join(out)
    seen = set()
    for d in chain["devices"]:
        out.append(d["device"])
        for root in sorted(d["roots"], key=_key):
            _lines(root, 1, seen, out)
    out += [f"unplaced: {u.get('name') or '(unnamed)'} {u.get('pid')} missing {', '.join(u['missing'])}" for u in chain["unplaced"]]
    out += [f"anomaly: {a}" for a in chain["anomalies"]]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence")
    ap.add_argument("--case", action="store_true", help="the Case-wide chain instead of one per alert")
    ap.add_argument("--alerts", help="alert id -> {title, severity}, to title the sections")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    chain = build(json.load(open(a.evidence, encoding="utf-8")))
    alerts = json.load(open(a.alerts, encoding="utf-8")) if a.alerts else None
    print(json.dumps(as_json(chain), indent=2, ensure_ascii=False) if a.json else as_text(chain, alerts, a.case))
    sys.exit(0)


if __name__ == "__main__":
    main()
