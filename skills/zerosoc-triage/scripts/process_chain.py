#!/usr/bin/env python3
"""Reconstruct the process lineage of a Case from its evidence rows. Standard library only.

  process_chain.py evidence.json [--telemetry telemetry.json [--bindings zerosoc.capabilities.json]] [--case]
                   [--alerts alerts.json] [--width N] [--json]

One chain per alert, the way a console shows an alert story: the processes the alert cites, each under its
ancestors, which are marked as context when they come from the Case's other alerts. `--case` prints the
Case-wide chain instead, every alert joined into one tree per device: the view an investigation scores on.

Without telemetry the chain is evidence-only: it holds the processes the source attached to the Case's alerts,
never the processes around them, and a parent outside the evidence is printed as a lineage gap, never guessed.
An alert whose evidence names no process has no chain, whatever a console draws from its own telemetry.

With `--telemetry` the gaps are filled from process telemetry: each missing ancestor is looked up, named with
its command line and linked to its own parent, up to the root. Nodes that come from telemetry are marked, so a
Note can tell what the alerts asserted from what the chain reconstructed. Ancestors still missing (a process
created before the telemetry window, a device not onboarded) stay gaps. Telemetry is a Case-scoped query
through the bound endpoint class, never the whole tenant.

evidence.json: the rows given to evidence_inventory.py (a list, or its --json output with "entities").
alerts.json (optional): {"<alert id>": {"title": ..., "severity": ...}}, to title the per-alert sections.
telemetry.json (optional): process-creation rows for the Case's devices and window, as
{"device", "pid", "created", "name", "command_line", "parent_pid", "parent_created"} and, when the source
reports them on the same row, "parent_name", "parent_command_line", "parent_parent_pid",
"parent_parent_created". Column names are matched case-insensitively. This script knows no source: what a
source calls these columns is declared by its **source profile** (`fields.telemetry_rows.process_lineage`), read
with `--bindings zerosoc.capabilities.json` or `--profile`; without one, only the names above and a few generic
spellings of them are known.
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
import argparse, json, os, re, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import source_profile

WIDTH = 160  # where a command line is cut in the text view; --width 0 prints it whole
LABEL = "evidence-only chain"
LABEL_FULL = "chain from evidence and telemetry"
ATTRS = ("path", "sha1", "sha256", "account", "upn", "user_sid", "mde_device_id", "remediation_status",
         "detection_status", "decoded_command", "decode_rounds", "decode_capped", "elevation_token")
# the columns of a telemetry row the lineage is rebuilt from, under this script's own names
LINEAGE = ("device", "pid", "created", "name", "command_line", "parent_pid", "parent_created", "parent_name",
           "parent_command_line", "parent_parent_pid", "parent_parent_created")
ALIASES = {"process_id": "pid", "process_created": "created", "process_creation_time": "created",
           "parent_process_id": "parent_pid", "parent_process_created": "parent_created",
           "image": "name", "process_name": "name", "commandline": "command_line", "host": "device"}
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
            "names": [], "verdicts": [], "alert_ids": [], "command_lines": [], "attrs": {}, "rows": 0,
            "source": "evidence" if in_evidence else "missing", "_parent": None, "children": []}
    index.setdefault((device.lower(), pid), []).append(node)
    return node


UNNAMED = ("", "(unnamed)")  # a source's placeholder for a process reported without its image file


def _add(values, value):
    if value is not None and value not in UNNAMED and value not in values:
        values.append(value)


def columns_of(profile):
    """What this source calls the columns of LINEAGE, as its profile declares them: column -> name here."""
    named = source_profile.telemetry_rows(profile)["process_lineage"]
    return {str(column).strip().lower(): key for key, column in named.items() if key in LINEAGE}


def _normalize(row, columns=None):
    """A telemetry row under this script's field names; unknown columns are kept as they are."""
    known = dict(ALIASES, **(columns or {}))
    out = {}
    for key, value in row.items():
        out[known.get(str(key).strip().lower(), str(key).strip().lower())] = value
    return out


def _telemetry_index(rows, columns=None):
    """(device, pid) -> [(time, row)], from the processes themselves and from the parents rows report."""
    index = {}

    def add(device, pid, created, fields):
        time = parse_time(created)
        pid = _pid(pid)
        if device is None or pid is None or time is None:
            return
        entry = index.setdefault((str(device).strip().lower(), pid), [])
        for known_time, known in entry:
            if same_time(known_time, time):
                for k, v in fields.items():
                    if v not in (None, "") and known.get(k) in (None, ""):
                        known[k] = v
                return
        entry.append((time, dict(fields, device=device, pid=pid, created=created)))

    for raw in rows:
        row = _normalize(raw, columns)
        device = row.get("device")
        add(device, row.get("pid"), row.get("created"),
            {k: row.get(k) for k in ("name", "command_line", "parent_pid", "parent_created", "parent_name") + ATTRS
             if row.get(k) not in (None, "")})
        add(device, row.get("parent_pid"), row.get("parent_created"),
            {"name": row.get("parent_name"), "command_line": row.get("parent_command_line"),
             "parent_pid": row.get("parent_parent_pid"), "parent_created": row.get("parent_parent_created")})
    return index


def _from_telemetry(index, device, pid, time):
    for known_time, row in index.get((device.lower(), pid), []):
        if same_time(known_time, time):
            return row
    return None


def build(rows, telemetry=None, columns=None):
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
        for key in ATTRS:
            if row.get(key) not in (None, "") and key not in node["attrs"]:
                node["attrs"][key] = row[key]
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

    if telemetry:
        _fill(_telemetry_index(telemetry, columns), index, gap_index, nodes, gaps, anomalies)

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
            "unplaced": unplaced, "anomalies": anomalies, "rows": len(procs), "telemetry": bool(telemetry)}


def _fill(telemetry, index, gap_index, nodes, gaps, anomalies, limit=64):
    """Resolve each gap from the telemetry and keep walking up: the ancestors the alerts never cited."""
    queue, seen = list(gaps), set()
    while queue:
        gap = queue.pop(0)
        if id(gap) in seen or len(nodes) > limit * 64:
            continue
        seen.add(id(gap))
        row = _from_telemetry(telemetry, gap["device"], gap["pid"], gap["_t"]) if gap["_t"] else None
        if row is None:
            gap["gap"] = "outside the evidence and the telemetry" if gap.get("gap") == "outside the evidence" else gap["gap"]
            continue
        gap["source"], gap["in_evidence"] = "telemetry", False
        gap.pop("gap", None)
        gaps.remove(gap)
        nodes.append(gap)
        _add(gap["names"], row.get("name"))
        _add(gap["command_lines"], row.get("command_line"))
        for key in ATTRS:
            if row.get(key) not in (None, "") and key not in gap["attrs"]:
                gap["attrs"][key] = row[key]
        ppid, ptime = _pid(row.get("parent_pid")), parse_time(row.get("parent_created"))
        if ppid is None or ptime is None:
            continue
        parent = _find(index, gap["device"], ppid, ptime) or _find(gap_index, gap["device"], ppid, ptime)
        if parent is gap:
            anomalies.append(f"{gap['device']} {gap['pid']}: a process reported as its own parent")
            continue
        if parent is None:
            parent = _node(gap_index, gap["device"], ppid, row.get("parent_created"), ptime, False)
            parent["gap"] = "outside the evidence and the telemetry"
            _add(parent["names"], row.get("parent_name"))
            gaps.append(parent)
            queue.append(parent)
        gap["parent"] = parent
        parent["children"].append(gap)


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
    out = {k: node[k] for k in ("pid", "created", "in_evidence", "source", "alert_ids")}
    if section is not None and node["in_evidence"]:
        out["cited_by_this_alert"] = id(node) in section["own"]
    out["name"] = node["names"][0] if node["names"] else None
    if len(node["names"]) > 1:
        out["names"] = node["names"]
    out["command_lines"] = node["command_lines"]
    if node["attrs"]:
        out["attributes"] = node["attrs"]
    if node["in_evidence"]:
        out.update(verdicts=node["verdicts"], rows=node["rows"])
    elif node["source"] != "telemetry":
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
        entries.append({"time": n["created"], "device": n["device"], "pid": n["pid"], "source": n["source"],
                        "process": n["names"][0] if n["names"] else None,
                        "command_line": n["command_lines"][0] if n["command_lines"] else None,
                        "parent_pid": parent["pid"] if parent else None,
                        "parent": (parent["names"][0] if parent["names"] else None) if parent else None,
                        "parent_in_evidence": parent["in_evidence"] if parent else None,
                        "event_refs": n["alert_ids"]})
    return entries


def summary(chain):
    from_telemetry = sum(1 for n in chain["nodes"] if n["source"] == "telemetry")
    return {"label": LABEL_FULL if chain.get("telemetry") else LABEL, "process_rows": chain["rows"],
            "processes": len(chain["nodes"]), "from_the_evidence": len(chain["nodes"]) - from_telemetry,
            "from_telemetry": from_telemetry, "devices": len(chain["devices"]),
            "lineage_gaps": len(chain["gaps"]), "unplaced": len(chain["unplaced"]),
            "anomalies": len(chain["anomalies"])}


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
                              "command_line": g["command_lines"][0] if g["command_lines"] else None,
                              "reason": g["gap"], "children": [c["pid"] for c in g["children"]]} for g in chain["gaps"]],
            "unplaced": chain["unplaced"], "anomalies": chain["anomalies"], "timeline": timeline(chain)}


def _short(value, limit):
    """One line, cut to length: a chain stays readable, the JSON keeps the whole command."""
    text = " ".join(str(value).split())
    return text if not limit or len(text) <= limit else text[:limit - 1] + "…"


def _detail(node, depth, out, width=WIDTH):
    """The command line, its decoding and the remediation state: what a chain is read for.

    Every printed line is cut to `width` (0: never cut). A decoding keeps its own line structure, so a
    decoded script is read as a script; a decoding that is itself an encoded command is cut like any other."""
    pad = "  " * (depth + 1)
    for line in node["command_lines"][:2]:
        out.append(f"{pad}$ {_short(line, width)}")
    decoded = node["attrs"].get("decoded_command")
    if decoded:
        rounds = node["attrs"].get("decode_rounds")
        layers = f" ({rounds} layers of encoding{', still encoded' if node['attrs'].get('decode_capped') else ''})" if rounds else ""
        lines = [line for line in str(decoded).strip().splitlines() if line.strip()] or [""]
        out.append(f"{pad}decoded{layers}: {_short(lines[0], width)}")
        out += [f"{pad}         {_short(line, width)}" for line in lines[1:]]
    state = " ".join(str(node["attrs"][k]) for k in ("remediation_status", "detection_status") if node["attrs"].get(k))
    if state:
        out.append(f"{pad}state: {state}")


def _lines(node, depth, seen, out, section=None, width=WIDTH):
    seen.add(id(node))
    name = node["names"][0] if node["names"] else "(unnamed)"
    if section is not None and node["in_evidence"] and id(node) not in section["own"]:
        out.append(f"{'  ' * depth}{name} {node['pid']} {node['created']} (context: another alert of the Case)")
        _detail(node, depth, out, width)
    elif node["in_evidence"]:
        also = f" (also {', '.join(node['names'][1:])})" if len(node["names"]) > 1 else ""
        out.append(f"{'  ' * depth}{name}{also} {node['pid']} {node['created']} {'/'.join(node['verdicts']) or '-'} alerts={len(node['alert_ids'])}")
        _detail(node, depth, out, width)
    elif node["source"] == "telemetry":
        out.append(f"{'  ' * depth}[telemetry] {name} {node['pid']} {node['created']} (not cited by any alert)")
        _detail(node, depth, out, width)
    else:
        out.append(f"{'  ' * depth}[gap] {name} {node['pid']} {node['created'] or '-'}: {node['gap']}")
    for child in sorted(node["children"], key=_key):
        if id(child) not in seen and (section is None or id(child) in section["nodes"]):
            _lines(child, depth + 1, seen, out, section, width)


def _titles(sections, alerts):
    for section in sections:
        meta = (alerts or {}).get(section["alert_id"]) or {}
        title = meta.get("title") or meta.get("displayName")
        yield section, f"alert {section['alert_id']}" + (f": {title}" if title else "")


def as_text(chain, alerts=None, case=False, width=WIDTH):
    s = summary(chain)
    head = (f"{s['label']}: {s['processes']} processes on {s['devices']} devices "
            f"({s['from_the_evidence']} from {s['process_rows']} evidence rows"
            + (f", {s['from_telemetry']} from telemetry" if s["from_telemetry"] else "")
            + f"); {s['lineage_gaps']} lineage gaps, {s['unplaced']} unplaced, {s['anomalies']} anomalies")
    out = [head if case else head + f"; {len(per_alert(chain))} of the Case's alerts cite a process"]
    if not case:
        for section, title in _titles(per_alert(chain), alerts):
            out.append(f"{title} — {section['cited']} processes cited, {section['processes'] - section['cited']} ancestors from the Case")
            seen = set()
            for d in section["devices"]:
                out.append(f"  {d['device']}")
                for root in sorted(d["roots"], key=_key):
                    _lines(root, 2, seen, out, section, width)
        out += [f"unplaced: {u.get('name') or '(unnamed)'} {u.get('pid')} missing {', '.join(u['missing'])}" for u in chain["unplaced"]]
        out += [f"anomaly: {a}" for a in chain["anomalies"]]
        return "\n".join(out)
    seen = set()
    for d in chain["devices"]:
        out.append(d["device"])
        for root in sorted(d["roots"], key=_key):
            _lines(root, 1, seen, out, None, width)
    out += [f"unplaced: {u.get('name') or '(unnamed)'} {u.get('pid')} missing {', '.join(u['missing'])}" for u in chain["unplaced"]]
    out += [f"anomaly: {a}" for a in chain["anomalies"]]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence")
    ap.add_argument("--case", action="store_true", help="the Case-wide chain instead of one per alert")
    ap.add_argument("--telemetry", help="process-creation rows for the Case's devices, to fill the gaps")
    ap.add_argument("--alerts", help="alert id -> {title, severity}, to title the sections")
    ap.add_argument("--width", type=int, default=WIDTH, help="where a command line is cut; 0 prints it whole")
    ap.add_argument("--json", action="store_true")
    source_profile.add_arguments(ap)
    a = ap.parse_args()
    telemetry = json.load(open(a.telemetry, encoding="utf-8")) if a.telemetry else None
    # the profile says what this source calls the telemetry's columns; a run with no telemetry reads none
    columns = columns_of(source_profile.from_arguments(ap, a)) if telemetry and (a.profile or a.bindings) else None
    chain = build(json.load(open(a.evidence, encoding="utf-8")), telemetry, columns)
    if telemetry and not _telemetry_index(telemetry, columns):
        print(f"none of the {len(telemetry)} telemetry rows names a device, a process id and a creation time in "
              "a way this script knows, so the telemetry filled nothing: pass --bindings (or --profile), and the "
              "source profile says what this source calls its columns", file=sys.stderr)
    alerts = json.load(open(a.alerts, encoding="utf-8")) if a.alerts else None
    print(json.dumps(as_json(chain), indent=2, ensure_ascii=False) if a.json else as_text(chain, alerts, a.case, a.width))
    sys.exit(0)


if __name__ == "__main__":
    main()
