#!/usr/bin/env python3
"""Reconstruct the process lineage of a Case from its evidence rows. Standard library only.

  process_chain.py evidence.json [--telemetry telemetry.json [--bindings zerosoc.capabilities.json]]
                   [--alerts alerts.json] [--width N] [--json | --ocsf --bindings zerosoc.capabilities.json]
  process_chain.py --from-graph graph.json [--width N] [--ocsf [--bindings zerosoc.capabilities.json]]

One chain for the whole Case, one tree per device, every process once under its ancestors. The text is what an
executor reads: a legend labels the alerts that cite a process (A1, A2, …, each with its full id once), each
process names its alerts by label, so what is said about a process can cite them, and every decoded command is
printed in full, once, under "scripts:" (D1, D2, …), the command line pointing to it in place of its encoded
payload. The JSON (`--json`) is what a program reads: each process once, keyed as the evidence rows are
(`device|pid|created`), with its parent by key and each evidence row as its alerts reported it; the lineage
gaps; each decoded command once as a script the processes point to; a timeline oldest first. `--ocsf` prints the
chain as the Case keeps it (framework DD-30): a context Observation's `desc` and `related_events`, which cite the
OCSF events printed beside them in `events`. Each process is a Process Activity (Launch), its parentage in
`parent_process` and `ancestry` and the process that launched it as the `actor`; each decoded command a Script
Activity (Execute) its process ran; each alert that cites a process a Detection Finding naming them in its
`evidences`, with the source's verdict and state. The events name the product that reported them, which the
source profile says (`--bindings` or `--profile`). `--from-graph` prints the text of a graph or of an Observation
and its events written earlier, so the text can be shown again from what was kept; a chain kept before its events
were, with each process on its citation, is read as it was written.

Without telemetry the chain is evidence-only: it holds the processes the source attached to the Case's alerts,
never the processes around them, and a parent outside the evidence is printed as a lineage gap, never guessed.
An alert whose evidence names no process has no chain, whatever a console draws from its own telemetry.

With `--telemetry` the gaps are filled from process telemetry: each missing ancestor is looked up, named with
its command line and linked to its own parent, up to the root. Nodes that come from telemetry are marked, so a
Note can tell what the alerts asserted from what the chain reconstructed. Ancestors still missing (a process
created before the telemetry window, a device not onboarded) stay gaps. Telemetry is a Case-scoped query
through the bound endpoint class, never the whole tenant.

evidence.json: the rows given to evidence_inventory.py (a list, or its --json output with "entities").
alerts.json (optional): {"<alert id>": {"title": ..., "severity": ..., "created_time": ...}}, to title the alerts
in the legend, and to give each alert's Detection Finding its severity and the time it was created (OCSF
milliseconds), which OCSF requires of it.
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
            "evidence": [], "source": "evidence" if in_evidence else "missing", "_parent": None, "children": []}
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
                             "device": row.get("device"), "alert_ids": _ids(row), "missing": missing,
                             "cmd_line": row.get("command_line"),
                             **{k: row[k] for k in DECODING + SAID if row.get(k)}})
            continue
        node = _find(index, device, pid, time)
        if node is None:
            node = _node(index, device, pid, row.get("created"), time, True)
            nodes.append(node)
        elif time[1] > node["_t"][1]:
            node["created"], node["_t"] = row.get("created"), time
        node["rows"] += 1
        node["evidence"].append(_said(row))
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


def _uid(node):
    """A process's key, the one the evidence rows join on: device, PID and creation time."""
    return f"{node['device']}|{node['pid']}|{node['created'] or ''}"


def _ms(node):
    return node["_t"][0] // 1000 if node.get("_t") else None


def _walk(chain):
    """Every node once, devices in order and each tree depth first, children oldest first."""
    seen, out = set(), []

    def visit(node):
        if id(node) in seen:
            return
        seen.add(id(node))
        out.append(node)
        for child in sorted(node["children"], key=_key):
            visit(child)

    for d in chain["devices"]:
        for root in sorted(d["roots"], key=_key):
            visit(root)
    return out


SCRIPT_TYPES = (("powershell", 2, "PowerShell"), ("pwsh", 2, "PowerShell"), ("cmd", 1, "Windows Command Prompt"),
                ("python", 3, "Python"), ("bash", 6, "Unix Shell"), ("sh", 6, "Unix Shell"))
"""OCSF script type_id by the interpreter's image name; anything else is Unknown (0)."""


POWERSHELL_ENCODED = re.compile(r"(?i)(?:^|\s)[-/]e(?:c|nc|ncodedcommand)?\s")
"""PowerShell's encoded-command switch: what was decoded is a PowerShell script, whichever process's command
line carries it (cmd.exe running `powershell -enc …` included)."""


def _script_type(name, cmd_line=None):
    if cmd_line and POWERSHELL_ENCODED.search(str(cmd_line)):
        return 2, "PowerShell"
    base = os.path.basename(str(name or "")).lower().removesuffix(".exe")
    return next(((tid, cap) for key, tid, cap in SCRIPT_TYPES if base == key), (0, "Unknown"))


def legend(chain, alerts=None):
    """The alerts that cite a process, labelled A1, A2, … in the order their first process ran."""
    first = {}
    for node in chain["nodes"]:
        if not node["in_evidence"]:
            continue
        for alert in node["alert_ids"]:
            if alert not in first or _key(node) < first[alert]:
                first[alert] = _key(node)
    out = []
    for n, alert in enumerate(sorted(first, key=lambda a: (first[a], a)), 1):
        out.append({"label": f"A{n}", "alert_id": alert, **_alert_meta((alerts or {}).get(alert))})
    return out


SEVERITIES = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
"""OCSF's severity_id by a source's severity word; any other word is Unknown (0)."""


def _alert_meta(meta):
    """What alerts.json says of an alert that the chain carries: its title, and for its Detection Finding its
    severity and when it was created (OCSF milliseconds)."""
    if not isinstance(meta, dict):
        return {}
    title = meta.get("title") or meta.get("displayName")
    severity = meta.get("severity")
    created = meta.get("created_time")
    held = {"title": title,
            "severity_id": SEVERITIES.get(str(severity).strip().lower(), 0) if severity is not None else None,
            "created_time": created if isinstance(created, int) and not isinstance(created, bool) else None}
    return {k: v for k, v in held.items() if v is not None}


def timeline(chain):
    """One entry per process, oldest first, with its alerts as event references and its parent by key."""
    entries = []
    for n in sorted(chain["nodes"], key=_key):
        parent = n.get("parent")
        entries.append({"time": n["created"], "uid": _uid(n), "device": n["device"], "pid": n["pid"],
                        "source": n["source"], "process": n["names"][0] if n["names"] else None,
                        "parent_uid": _uid(parent) if parent else None,
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


DECODING = ("decoded_command", "decode_rounds", "decode_capped")
SAID = ("verdict", "remediation_status", "detection_status")
"""What an alert's evidence says of a process beyond the process itself: the source's verdict and state."""


def _said(row):
    """An evidence row as its alerts reported the process: which alerts, under what name and command line, and
    what the source said of it."""
    held = {"alert_ids": _ids(row), "name": row.get("name"), "cmd_line": row.get("command_line"),
            **{k: row.get(k) for k in SAID}}
    return {k: v for k, v in held.items() if v not in (None, "", [])}


def as_json(chain, alerts=None):
    """The chain as a graph, each process once: an OCSF-shaped process keyed as the evidence rows are, its
    parent by key, and each decoded command once as an OCSF-shaped script the processes point to."""
    labels = legend(chain, alerts)
    scripts, by_content, processes, gaps = [], {}, [], []
    for node in _walk(chain):
        if not node["in_evidence"] and node["source"] != "telemetry":
            gaps.append({"uid": _uid(node), "device": node["device"], "pid": node["pid"], "created": node["created"],
                         "created_time": _ms(node), "name": node["names"][0] if node["names"] else None,
                         "reason": node["gap"], "children": [_uid(c) for c in sorted(node["children"], key=_key)]})
            continue
        parent = node.get("parent")
        out = {"uid": _uid(node), "device": node["device"], "pid": node["pid"],
               "name": node["names"][0] if node["names"] else None, "created": node["created"],
               "created_time": _ms(node), "cmd_line": node["command_lines"][0] if node["command_lines"] else None,
               "parent_process": {"uid": _uid(parent), "pid": parent["pid"]} if parent else None,
               "source": node["source"], "alert_ids": node["alert_ids"]}
        if len(node["names"]) > 1:
            out["names"] = node["names"]
        if len(node["command_lines"]) > 1:
            out["cmd_lines"] = node["command_lines"]
        if node["in_evidence"]:
            out.update(verdicts=node["verdicts"], rows=node["rows"], evidence=node["evidence"])
        attrs = {k: v for k, v in node["attrs"].items() if k not in DECODING}
        if attrs:
            out["attributes"] = attrs
        decoded = node["attrs"].get("decoded_command")
        if decoded:
            content = str(decoded).strip()
            script = by_content.get(content)
            if script is None:
                type_id, caption = _script_type(out["name"], out["cmd_line"])
                script = {"uid": f"D{len(scripts) + 1}", "type_id": type_id, "type": caption,
                          "script_content": content, "process_uids": []}
                scripts.append(script)
                by_content[content] = script
            script["process_uids"].append(out["uid"])
            out["script_uid"] = script["uid"]
            if node["attrs"].get("decode_rounds"):
                out["decode_rounds"] = node["attrs"]["decode_rounds"]
            if node["attrs"].get("decode_capped"):
                out["decode_capped"] = True
        processes.append(out)
    unplaced = []
    for n, entry in enumerate(chain["unplaced"], 1):
        u = {k: v for k, v in entry.items() if k not in DECODING}
        decoded = entry.get("decoded_command")
        if decoded:
            content = str(decoded).strip()
            script = by_content.get(content)
            if script is None:
                type_id, caption = _script_type(u.get("name"), u.get("cmd_line"))
                script = {"uid": f"D{len(scripts) + 1}", "type_id": type_id, "type": caption,
                          "script_content": content, "process_uids": []}
                scripts.append(script)
                by_content[content] = script
            script["process_uids"].append(f"unplaced:{n}")
            u["script_uid"] = script["uid"]
            u.update({k: entry[k] for k in ("decode_rounds", "decode_capped") if entry.get(k)})
        unplaced.append(u)
    return {"process_chain": dict(summary(chain), alerts_citing_a_process=len(labels)),
            "alerts": labels,
            "devices": [{"device": d["device"], "roots": [_uid(r) for r in sorted(d["roots"], key=_key)]}
                        for d in chain["devices"]],
            "processes": processes, "gaps": gaps, "scripts": scripts,
            "unplaced": unplaced, "anomalies": chain["anomalies"], "timeline": timeline(chain)}


OCSF_VERSION = "1.9.0"
"""The OCSF release the events follow: the one the framework's Case Schema names (its `ocsf_version`)."""
LAUNCH = {"class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701,
          "type_name": "Process Activity: Launch"}
EXECUTE = {"class_uid": 1009, "category_uid": 1, "activity_id": 1, "type_uid": 100901,
           "type_name": "Script Activity: Execute"}
DETECTION = {"class_uid": 2004, "category_uid": 2, "activity_id": 1, "type_uid": 200401,
             "type_name": "Detection Finding: Create"}
UNRATED = 0
"""OCSF's Unknown severity, of a process launched or a script run: the source rates its alerts, not these."""
UNKNOWN_DEVICE = 0
"""OCSF's Unknown device type: the evidence names a device and not what kind it is."""
HASHES = (("sha1", 2, "SHA-1"), ("sha256", 3, "SHA-256"))
REGULAR_FILE = 1
"""OCSF's file type of a process's image."""
DECODED = "decoded command"
"""The type of the enrichment that says a command line was decoded into a script, and in how many layers."""
OTHER_VERDICT = 99
"""OCSF's verdict Other: the source's own word for what its evidence was, which the chain keeps as the source
said it and does not normalize, knowing no source's words."""


def _entity(p, full=True):
    """A process as another object names it: what is known of it as a parent, its name further up."""
    out = {"uid": p["uid"], "pid": p.get("pid"), "name": p.get("name")}
    if full:
        out.update(created_time=p.get("created_time"), created_time_dt=p.get("created"))
    return {k: v for k, v in out.items() if v is not None}


def _ocsf_process(p, known):
    attrs = p.get("attributes") or {}
    out = dict(_entity(p), cmd_line=p.get("cmd_line"))
    file = _image(p.get("name"), attrs)
    user = {k: v for k, v in (("name", attrs.get("account")), ("uid", attrs.get("user_sid")),
                              ("email_addr", attrs.get("upn"))) if v}
    # what OCSF's process has no attribute for: every name and command line the sources gave it, and the
    # elevation of its token
    extended = {k: v for k, v in (("names", p.get("names")), ("cmd_lines", p.get("cmd_lines")),
                                  ("token_elevation", attrs.get("elevation_token"))) if v}
    ancestry, parent = [], p.get("parent_process")
    while parent and parent["uid"] in known and len(ancestry) < 64:
        ancestry.append(_entity(known[parent["uid"]], full=not ancestry))
        parent = known[parent["uid"]].get("parent_process")
    out.update(file=file or None, user=user or None, parent_process=ancestry[0] if ancestry else None,
               ancestry=ancestry or None, xattributes=extended or None)
    return {k: v for k, v in out.items() if v is not None}


def _image(name, attrs):
    """The process's image as an OCSF file: its name, the folder the rows give as its `path`, the full path, and
    its hashes. None where the process is unnamed, since OCSF requires a file's name."""
    if not name:
        return None
    folder = attrs.get("path")
    separator = "\\" if "\\" in str(folder or "") else "/"
    hashes = [{"algorithm_id": aid, "algorithm": label, "value": attrs[key]} for key, aid, label in HASHES if attrs.get(key)]
    held = {"name": name, "type_id": REGULAR_FILE, "parent_folder": folder,
            "path": f"{str(folder).rstrip(separator)}{separator}{name}" if folder else None, "hashes": hashes or None}
    return {k: v for k, v in held.items() if v is not None}


def _ocsf_device(hostname, attrs=None):
    uid = (attrs or {}).get("mde_device_id")
    return {k: v for k, v in (("hostname", hostname), ("type_id", UNKNOWN_DEVICE), ("uid", uid)) if v is not None}


def _metadata(uid, product):
    return {"uid": uid, "product": product, "version": OCSF_VERSION}


def _cite(event, title=None):
    """The citation of an event: its uid is the event's `metadata.uid`, and it says what the event is and when
    it happened."""
    held = {"uid": event["metadata"]["uid"], "type_uid": event["type_uid"], "type_name": event["type_name"],
            "title": title, "first_seen_time": event.get("time")}
    return {k: v for k, v in held.items() if v is not None}


def _script(s):
    return {k: s[k] for k in ("uid", "type_id", "type", "script_content")}


def _decoding(p, cmd_line):
    """The enrichment that says the process's command line decodes to its script, and in how many layers."""
    data = {"script_uid": p["script_uid"], **{k: p[k] for k in ("decode_rounds", "decode_capped") if p.get(k)}}
    return [{"name": "process.cmd_line", "value": cmd_line or "", "type": DECODED, "data": data}]


def _evidence(uid, n, process, row):
    """An alert's evidence naming a process: the process as that alert's row reported it, with what the source
    said of it. Its uid is the row's, so a row two alerts cite is one row."""
    named = {k: v for k, v in (("uid", process.get("uid")), ("pid", process.get("pid")), ("name", row.get("name")),
                               ("cmd_line", row.get("cmd_line"))) if v is not None}
    out = {"name": "process", "uid": f"{uid}#{n}", "process": named}
    if row.get("verdict"):
        out.update(verdict_id=OTHER_VERDICT, verdict=row["verdict"])
    data = {k: row[k] for k in ("remediation_status", "detection_status") if row.get(k)}
    if data:
        out["data"] = data
    return out


def _launch(p, known, product):
    process = _ocsf_process(p, known)
    event = dict(metadata=_metadata(p["uid"], product), **LAUNCH, severity_id=UNRATED, time=p.get("created_time"),
                 device=_ocsf_device(p["device"], p.get("attributes")), process=process)
    if process.get("parent_process"):
        event["actor"] = {"process": process["parent_process"]}
    if p.get("script_uid"):
        event["enrichments"] = _decoding(p, p.get("cmd_line"))
    return {k: v for k, v in event.items() if v is not None}


def _execute(p, script, product, device):
    event = dict(metadata=_metadata(f"{p['uid']}#{script['uid']}", product), **EXECUTE, severity_id=UNRATED,
                 time=p.get("created_time"), device=device, actor={"process": _entity(p)}, script=_script(script))
    return {k: v for k, v in event.items() if v is not None}


def as_ocsf(graph, product):
    """The chain as the Case keeps it (Case Schema, *Processes and scripts*; framework DD-30): a context
    Observation's `desc` and `related_events`, and the OCSF events it cites in `events`. A Process Activity
    (Launch) per process, its parentage in `parent_process` and `ancestry` and the process that launched it as
    the `actor`; a Script Activity (Execute) per decoded command a process ran, that process its `actor`; a
    Detection Finding per alert that cites a process, naming in its `evidences` each process as the alert's
    row reported it, with the source's verdict and state. A citation's `uid` is its event's `metadata.uid`. A
    parent the evidence does not show is only named, as a parent, with what is known of it. `product` is the
    source's, as its profile names it: what reported the processes the events say were launched."""
    known = {g["uid"]: g for g in graph["gaps"]} | {p["uid"]: p for p in graph["processes"]}
    scripts = {s["uid"]: s for s in graph["scripts"]}
    events, found = [], {}
    for p in graph["processes"]:
        launch = _launch(p, known, product)
        events.append(launch)
        if p.get("script_uid"):
            events.append(_execute(p, scripts[p["script_uid"]], product, launch["device"]))
        # an alert cites what its evidence holds: a process telemetry filled in carries its descendants'
        # alerts in the graph, and no row of any of them names it
        for n, row in enumerate(p.get("evidence") or [], 1):
            for alert in row.get("alert_ids") or []:
                found.setdefault(alert, []).append(_evidence(p["uid"], n, launch["process"], row))
    for n, u in enumerate(graph["unplaced"], 1):
        uid = f"unplaced:{n}"
        created = parse_time(u.get("created"))
        process = {k: v for k, v in (("uid", uid), ("name", u.get("name")), ("pid", u.get("pid")),
                                     ("created_time_dt", u.get("created")), ("cmd_line", u.get("cmd_line"))) if v is not None}
        event = dict(metadata=_metadata(uid, product), **LAUNCH, severity_id=UNRATED,
                     time=created[0] // 1000 if created else None,
                     device=_ocsf_device(u["device"]) if u.get("device") else None,
                     process=process)
        if u.get("script_uid"):
            event["enrichments"] = _decoding(u, u.get("cmd_line"))
        events.append({k: v for k, v in event.items() if v is not None})
        if u.get("script_uid"):
            run = dict(metadata=_metadata(f"{uid}#{u['script_uid']}", product), **EXECUTE, severity_id=UNRATED,
                       time=event.get("time"), device=event.get("device"), actor={"process": process},
                       script=_script(scripts[u["script_uid"]]))
            events.append({k: v for k, v in run.items() if v is not None})
        for alert in u.get("alert_ids") or []:
            found.setdefault(alert, []).append(_evidence(uid, 1, process, u))
    legend = {a["alert_id"]: a for a in graph["alerts"]}
    # the alerts of the legend first, in its order, and then any that cites only a process it could not place
    order = [*legend, *(a for a in found if a not in legend)]
    alerts = []
    for alert in order:
        meta = legend.get(alert) or {}
        info = {k: v for k, v in (("uid", alert), ("title", meta.get("title"))) if v is not None}
        event = dict(metadata=_metadata(alert, product), **DETECTION, severity_id=meta.get("severity_id", 0),
                     time=meta.get("created_time"), finding_info=info, evidences=found.get(alert) or None)
        alerts.append({k: v for k, v in event.items() if v is not None})
    lines = [_header(graph["process_chain"])] + [f"anomaly: {a}" for a in graph["anomalies"]]
    titles = {a["metadata"]["uid"]: a["finding_info"].get("title") for a in alerts}
    return {"desc": "\n".join(lines),
            "related_events": [_cite(e, titles.get(e["metadata"]["uid"])) for e in alerts]
                              + [_cite(e) for e in events],
            "events": alerts + events}


def product_of(observation):
    """The product the events of a kept chain name, or None where it keeps none."""
    return next((e["metadata"]["product"] for e in observation.get("events") or []
                 if (e.get("metadata") or {}).get("product")), None)


def from_ocsf(observation):
    """The graph again from the Observation and events `as_ocsf` wrote, so its text can be shown from what the
    Case kept. A chain kept before its events were (framework DD-30) carries its processes on the citations,
    and is read as it was written."""
    if "events" not in observation:
        return _from_citations(observation)
    lines = str(observation.get("desc") or "").splitlines()
    label = lines[0].split(":")[0] if lines else LABEL
    held = {(e.get("metadata") or {}).get("uid"): e for e in observation.get("events") or []}
    events = [held[c["uid"]] for c in observation.get("related_events") or [] if c.get("uid") in held]
    rows, by_alert = {}, {}
    for e in (e for e in events if e.get("type_uid") == DETECTION["type_uid"]):
        alert = e["metadata"]["uid"]
        for artifact in e.get("evidences") or []:
            process_uid = (artifact.get("process") or {}).get("uid")
            row = rows.setdefault(process_uid, {}).setdefault(artifact.get("uid"), _row_of(artifact))
            row.setdefault("alert_ids", []).append(alert)
            by_alert.setdefault(alert, set()).add(process_uid)
    alerts = []
    for e in (e for e in events if e.get("type_uid") == DETECTION["type_uid"]):
        alert = e["metadata"]["uid"]
        if not any(not str(uid).startswith("unplaced:") for uid in by_alert.get(alert, ())):
            continue  # cites only processes it could not place: no label in the legend
        meta = {"title": (e.get("finding_info") or {}).get("title"), "severity_id": e.get("severity_id") or None,
                "created_time": e.get("time")}
        alerts.append({"label": f"A{len(alerts) + 1}", "alert_id": alert, **{k: v for k, v in meta.items() if v}})
    scripts, decoded = {}, {}
    for e in (e for e in events if e.get("type_uid") == EXECUTE["type_uid"]):
        s, runner = e.get("script") or {}, ((e.get("actor") or {}).get("process") or {}).get("uid")
        script = scripts.setdefault(s["uid"], {"uid": s["uid"], "type_id": s.get("type_id", 0),
                                               "type": s.get("type") or "Unknown",
                                               "script_content": s.get("script_content") or "", "process_uids": []})
        script["process_uids"].append(runner)
    for e in (e for e in events if e.get("type_uid") == LAUNCH["type_uid"]):
        for enrichment in e.get("enrichments") or []:
            if enrichment.get("type") == DECODED:
                decoded[e["metadata"]["uid"]] = enrichment.get("data") or {}
    processes, parents, unplaced = [], {}, []
    for e in (e for e in events if e.get("type_uid") == LAUNCH["type_uid"]):
        uid, proc = e["metadata"]["uid"], e.get("process") or {}
        device = (e.get("device") or {}).get("hostname")
        said = [rows[uid][k] for k in sorted(rows.get(uid, {}), key=_row_number)]
        decoding = decoded.get(uid) or {}
        if str(uid).startswith("unplaced:"):
            u = {"name": proc.get("name"), "pid": proc.get("pid"), "created": proc.get("created_time_dt"),
                 "device": device, "alert_ids": [a for r in said for a in r.get("alert_ids", [])],
                 "missing": [k for k, v in (("device", _device({"device": device})), ("pid", _pid(proc.get("pid"))),
                                            ("created", parse_time(proc.get("created_time_dt")))) if v is None],
                 "cmd_line": proc.get("cmd_line"),
                 **{k: said[0][k] for k in SAID if said and said[0].get(k)}}
            if decoding.get("script_uid"):
                u["script_uid"] = decoding["script_uid"]
                u.update({k: decoding[k] for k in ("decode_rounds", "decode_capped") if decoding.get(k)})
            unplaced.append(u)
            continue
        parent = proc.get("parent_process")
        extended = proc.get("xattributes") or {}
        out = {"uid": uid, "device": device, "pid": proc.get("pid"), "name": proc.get("name"),
               "created": proc.get("created_time_dt"), "created_time": proc.get("created_time"),
               "cmd_line": proc.get("cmd_line"),
               "parent_process": {"uid": parent["uid"], "pid": parent.get("pid")} if parent else None,
               "source": "evidence" if said else "telemetry",
               "alert_ids": sorted({a for r in said for a in r.get("alert_ids", [])})}
        for key in ("names", "cmd_lines"):
            if extended.get(key):
                out[key] = extended[key]
        if said:
            verdicts = []
            for r in said:
                _add(verdicts, r.get("verdict"))
            out.update(verdicts=verdicts, rows=len(said), evidence=said)
        file, user = proc.get("file") or {}, proc.get("user") or {}
        attrs = {k: v for k, v in (("path", file.get("parent_folder")), ("account", user.get("name")),
                                   ("upn", user.get("email_addr")), ("user_sid", user.get("uid")),
                                   ("mde_device_id", (e.get("device") or {}).get("uid")),
                                   ("elevation_token", extended.get("token_elevation"))) if v}
        for h in file.get("hashes") or []:
            attrs.update((key, h["value"]) for key, aid, _ in HASHES if aid == h.get("algorithm_id"))
        for key in ("remediation_status", "detection_status"):
            first = next((r[key] for r in said if r.get(key)), None)
            if first:
                attrs[key] = first
        if attrs:
            out["attributes"] = attrs
        if decoding.get("script_uid"):
            out["script_uid"] = decoding["script_uid"]
            out.update({k: decoding[k] for k in ("decode_rounds", "decode_capped") if decoding.get(k)})
        processes.append(out)
        if parent:
            parents.setdefault(parent["uid"], parent)
    return _graph(label, lines, alerts, processes, parents, list(scripts.values()), unplaced)


def _row_of(artifact):
    """An evidence row again from the alert evidence that named it."""
    proc = artifact.get("process") or {}
    held = {"name": proc.get("name"), "cmd_line": proc.get("cmd_line"), "verdict": artifact.get("verdict"),
            **(artifact.get("data") or {})}
    return {k: v for k, v in held.items() if v not in (None, "")}


def _row_number(uid):
    tail = str(uid).rsplit("#", 1)[-1]
    return int(tail) if tail.isdigit() else 0


def _graph(label, lines, alerts, processes, parents, scripts, unplaced):
    """The graph from what a kept chain holds: its gaps are the parents it names and does not hold."""
    known = {p["uid"] for p in processes}
    gaps = []
    for uid, g in parents.items():
        if uid in known:
            continue
        created = g.get("created_time_dt")
        reason = ("outside the evidence and the telemetry" if label == LABEL_FULL else "outside the evidence") \
            if created else "parent creation time not reported"
        gaps.append({"uid": uid, "device": uid.split("|")[0], "pid": g.get("pid"), "created": created,
                     "created_time": g.get("created_time"), "name": g.get("name"), "reason": reason, "children": []})

    def order(item):
        time = parse_time(item["created"]) if item.get("created") else None
        return time[0] if time else float("inf")

    nodes = {item["uid"]: item for item in processes + gaps}
    devices = {}
    for item in sorted(processes + gaps, key=order):
        devices.setdefault(item["device"].lower(), {"device": item["device"], "roots": []})
        parent = nodes.get((item.get("parent_process") or {}).get("uid"))
        if parent is None:
            devices[item["device"].lower()]["roots"].append(item["uid"])
        elif "reason" in parent:
            parent["children"].append(item["uid"])
    anomalies = [line.removeprefix("anomaly: ") for line in lines[1:] if line.startswith("anomaly: ")]
    from_telemetry = sum(1 for p in processes if p["source"] == "telemetry")
    summary = {"label": label, "process_rows": sum(p.get("rows") or 0 for p in processes) + len(unplaced),
               "processes": len(processes), "from_the_evidence": len(processes) - from_telemetry,
               "from_telemetry": from_telemetry, "devices": len(devices), "lineage_gaps": len(gaps),
               "unplaced": len(unplaced), "anomalies": len(anomalies), "alerts_citing_a_process": len(alerts)}
    return {"process_chain": summary, "alerts": alerts, "devices": [devices[k] for k in sorted(devices)],
            "processes": processes, "gaps": gaps, "scripts": scripts, "unplaced": unplaced,
            "anomalies": anomalies}


LEGACY_LAUNCH = 100701
LEGACY_DETECTION = 200401


def _from_citations(observation):
    """A chain kept before DD-30: each process an OCSF `process` on its citation, each decoded command a
    `script`, and the alerts' evidences on theirs."""
    lines = str(observation.get("desc") or "").splitlines()
    label = lines[0].split(":")[0] if lines else LABEL
    events = observation.get("related_events") or []
    alerts, cited = [], {}
    for e in (e for e in events if e.get("type_uid") == LEGACY_DETECTION):
        alerts.append({"label": f"A{len(alerts) + 1}", "alert_id": e["uid"], **({"title": e["title"]} if e.get("title") else {})})
        for artifact in e.get("evidences") or []:
            cited.setdefault(artifact.get("uid"), []).append(e["uid"])
    processes, parents, scripts, unplaced = [], {}, {}, []
    for e in (e for e in events if e.get("type_uid") == LEGACY_LAUNCH):
        proc = e.get("process") or {}
        state = dict(((e.get("evidences") or [{}])[0]).get("data") or {})
        device = (e.get("device") or {}).get("hostname")
        if str(e["uid"]).startswith("unplaced:"):
            u = {"name": proc.get("name"), "pid": proc.get("pid"), "created": proc.get("created_time_dt"),
                 "device": device, "alert_ids": [], "missing": state.get("missing") or [], "cmd_line": proc.get("cmd_line")}
            if e.get("script"):
                s = e["script"]
                script = scripts.setdefault(s["uid"], {"uid": s["uid"], "type_id": s.get("type_id", 0),
                                                       "type": s.get("type") or "Unknown",
                                                       "script_content": s.get("script_content") or "", "process_uids": []})
                script["process_uids"].append(e["uid"])
                u["script_uid"] = s["uid"]
                u.update({k: state[k] for k in ("decode_rounds", "decode_capped") if k in state})
            unplaced.append(u)
            continue
        parent = proc.get("parent_process")
        out = {"uid": e["uid"], "device": device, "pid": proc.get("pid"), "name": proc.get("name"),
               "created": proc.get("created_time_dt"), "created_time": proc.get("created_time"),
               "cmd_line": proc.get("cmd_line"),
               "parent_process": {"uid": parent["uid"], "pid": parent.get("pid")} if parent else None,
               "source": state.pop("source", "evidence"), "alert_ids": sorted(cited.get(e["uid"], []))}
        for key in ("names", "cmd_lines"):
            if key in state:
                out[key] = state.pop(key)
        verdicts = state.pop("verdicts", [])
        if out["source"] == "evidence":
            out.update(verdicts=verdicts, rows=e.get("count") or 0)
        decoding = {k: state.pop(k) for k in ("decode_rounds", "decode_capped") if k in state}
        file, user = proc.get("file") or {}, proc.get("user") or {}
        attrs = {k: v for k, v in (("path", file.get("path")), ("account", user.get("name")), ("user_sid", user.get("uid"))) if v}
        for h in file.get("hashes") or []:
            attrs.update((key, h["value"]) for key, aid, _ in HASHES if aid == h.get("algorithm_id"))
        attrs.update(state)
        if attrs:
            out["attributes"] = attrs
        if e.get("script"):
            s = e["script"]
            script = scripts.setdefault(s["uid"], {"uid": s["uid"], "type_id": s.get("type_id", 0),
                                                   "type": s.get("type") or "Unknown",
                                                   "script_content": s.get("script_content") or "", "process_uids": []})
            script["process_uids"].append(e["uid"])
            out.update(script_uid=s["uid"], **decoding)
        processes.append(out)
        if parent:
            parents.setdefault(parent["uid"], parent)
    return _graph(label, lines, alerts, processes, parents, list(scripts.values()), unplaced)

ENCODED = re.compile(r"^[A-Za-z0-9+/=]{40,}$")


def _short(value, limit):
    """One line, cut to length: a chain stays readable, the JSON keeps the whole command."""
    text = " ".join(str(value).split())
    return text if not limit or len(text) <= limit else text[:limit - 1] + "…"


def _command(line, script_uid):
    """A command line with its encoded payload replaced by the script it decodes to."""
    if not script_uid:
        return line
    return " ".join(f"‹encoded: {script_uid}›" if ENCODED.match(token) else token for token in str(line).split())


def _header(s):
    return (f"{s['label']}: {s['processes']} processes on {s['devices']} devices "
            f"({s['from_the_evidence']} from {s['process_rows']} evidence rows"
            + (f", {s['from_telemetry']} from telemetry" if s["from_telemetry"] else "")
            + f"); {s['lineage_gaps']} lineage gaps, {s['unplaced']} unplaced, {s['anomalies']} anomalies")


def render(graph, width=WIDTH):
    """The graph as text: the legend, one tree per device with every process once, each naming its alerts
    by label, and every decoded script in full, once. What an executor reads; the JSON is what a program reads."""
    out = [_header(graph["process_chain"])]
    label = {a["alert_id"]: a["label"] for a in graph["alerts"]}
    if graph["alerts"]:
        out.append("alerts:")
        out += [f"  {a['label']:<4} {a['alert_id']}" + (f"  {a['title']}" if a.get("title") else "") for a in graph["alerts"]]
    nodes = {p["uid"]: p for p in graph["processes"]}
    gaps = {g["uid"]: g for g in graph["gaps"]}
    children = {}
    for p in graph["processes"]:
        if p["parent_process"]:
            children.setdefault(p["parent_process"]["uid"], []).append(p["uid"])

    def line(uid, depth):
        pad = "  " * depth
        if uid in gaps:
            g = gaps[uid]
            out.append(f"{pad}[gap] {g['name'] or '(unnamed)'} {g['pid']} {_started(g['created'])}: {g['reason']}")
            kids = g["children"]
        else:
            p = nodes[uid]
            name = p["name"] or "(unnamed)"
            also = f" (also {', '.join(p['names'][1:])})" if len(p.get("names") or []) > 1 else ""
            if p["source"] == "telemetry":
                out.append(f"{pad}[telemetry] {name}{also} {p['pid']} {_started(p['created'])} (not cited by any alert)")
            else:
                cited = " ".join(label.get(a, a) for a in sorted(p["alert_ids"], key=lambda a: int(label.get(a, "A0")[1:])))
                out.append(f"{pad}{name}{also} {p['pid']} {_started(p['created'])} {'/'.join(p.get('verdicts') or []) or '-'}  alerts: {cited}")
            _ran(out, p, pad, width)
            attrs = p.get("attributes") or {}
            state = " ".join(str(attrs[k]) for k in ("remediation_status", "detection_status") if attrs.get(k))
            if state:
                out.append(f"{pad}  state: {state}")
            kids = children.get(uid, [])
        ordered = sorted(kids, key=lambda k: (nodes.get(k) or gaps.get(k) or {}).get("created_time") or 0)
        for kid in ordered:
            line(kid, depth + 1)

    for d in graph["devices"]:
        out.append(d["device"])
        for root in d["roots"]:
            line(root, 1)
    unplaced = {f"unplaced:{n}": u for n, u in enumerate(graph["unplaced"], 1)}
    if graph["scripts"]:
        out.append("scripts:")
        for script in graph["scripts"]:
            runs = ", ".join(f"{nodes[u]['name']} {nodes[u]['pid']}" if u in nodes else
                             f"{unplaced[u].get('name') or '(unnamed)'} {unplaced[u].get('pid')} (unplaced)"
                             for u in script["process_uids"] if u in nodes or u in unplaced)
            out.append(f"  {script['uid']}  {script['type']}, run by {runs}")
            out += [f"      {text}" for text in script["script_content"].splitlines()]
    for u in graph["unplaced"]:
        out.append(f"unplaced: {u.get('name') or '(unnamed)'} {u.get('pid')} missing {', '.join(u['missing'])}")
        _ran(out, u, "", width)
    out += [f"anomaly: {a}" for a in graph["anomalies"]]
    return "\n".join(out)


def _started(created):
    """A process's creation time, said to be one: a process can start long before the alert that cites
    it, and a bare time beside the alert's label was read as the alert's."""
    return f"started {created}" if created else "-"


def _ran(out, p, pad, width):
    """Every command line a process was seen with, its encoded payload replaced by the script it decodes to."""
    for cmd in p.get("cmd_lines") or ([p["cmd_line"]] if p.get("cmd_line") else []):
        out.append(f"{pad}  $ {_short(_command(cmd, p.get('script_uid')), width)}")
    if p.get("script_uid"):
        rounds = p.get("decode_rounds")
        layers = f" ({rounds} layers of encoding{', still encoded' if p.get('decode_capped') else ''})" if rounds else ""
        out.append(f"{pad}  decoded: {p['script_uid']}{layers}")


def as_text(chain, alerts=None, width=WIDTH):
    return render(as_json(chain, alerts), width)


def _product(ap, a):
    """The product the events name: the source's, as its profile says it, which reported the processes."""
    source = source_profile.from_arguments(ap, a)["source"]
    return {k: v for k, v in (("name", source.get("product")), ("vendor_name", source.get("vendor"))) if v}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence", nargs="?")
    ap.add_argument("--from-graph", help="print the text of a graph this script wrote with --json")
    ap.add_argument("--case", action="store_true", help=argparse.SUPPRESS)  # the Case-wide chain is the only view
    ap.add_argument("--telemetry", help="process-creation rows for the Case's devices, to fill the gaps")
    ap.add_argument("--alerts", help="alert id -> {title, severity}, to title the alerts")
    ap.add_argument("--width", type=int, default=WIDTH, help="where a command line is cut; 0 prints it whole")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ocsf", action="store_true", help="print the chain as a context Observation's desc and related_events")
    source_profile.add_arguments(ap)
    a = ap.parse_args()
    if a.from_graph:
        held = json.load(open(a.from_graph, encoding="utf-8"))
        graph = from_ocsf(held) if "related_events" in held else held
        if a.ocsf:
            product = product_of(held) or _product(ap, a)
            print(json.dumps(as_ocsf(graph, product), indent=2, ensure_ascii=False))
        else:
            print(render(graph, a.width))
        sys.exit(0)
    if not a.evidence:
        ap.error("evidence.json is required unless --from-graph is given")
    telemetry = json.load(open(a.telemetry, encoding="utf-8")) if a.telemetry else None
    # the profile says what this source calls the telemetry's columns; a run with no telemetry reads none
    columns = columns_of(source_profile.from_arguments(ap, a)) if telemetry and (a.profile or a.bindings) else None
    chain = build(json.load(open(a.evidence, encoding="utf-8")), telemetry, columns)
    if telemetry and not _telemetry_index(telemetry, columns):
        print(f"none of the {len(telemetry)} telemetry rows names a device, a process id and a creation time in "
              "a way this script knows, so the telemetry filled nothing: pass --bindings (or --profile), and the "
              "source profile says what this source calls its columns", file=sys.stderr)
    alerts = json.load(open(a.alerts, encoding="utf-8")) if a.alerts else None
    graph = as_json(chain, alerts)
    if a.json or a.ocsf:
        print(json.dumps(as_ocsf(graph, _product(ap, a)) if a.ocsf else graph, indent=2, ensure_ascii=False))
    else:
        print(render(graph, a.width))
    sys.exit(0)


if __name__ == "__main__":
    main()
