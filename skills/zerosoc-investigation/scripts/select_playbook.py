#!/usr/bin/env python3
"""Select a ZeroSOC playbook and report visibility gaps. Standard library only.

  select_playbook.py --domain Endpoint [--alert-type "Malware / loader execution"] [--bindings zerosoc.capabilities.json] [--json]
  select_playbook.py --category IC-01 [--section Investigation] [--bindings ...] [--json]
  select_playbook.py --technique T1003 --technique T1021.002 [--json]
  select_playbook.py --list

With --technique, the framework's own tables are read the other way round: the techniques a detection
named (Detection & Analysis §1.1) are looked up for what the framework calls them and for the Incident
Categories the alert types carrying them promote to, which is the first input to the candidate categories
(§1.4). A sub-technique the tables do not hold falls back to its parent; a technique they hold nowhere is
reported, never dropped, and never renamed.

Paths are relative to the skill directory (references/framework/...). Triage playbooks are matched on the
frontmatter `domain`; Investigation & Response playbooks on `incident_category`, with the catch-all
00-generic.md as fallback when present. Prints the playbook path and version (last_updated), the
required data sources with their availability from the binding file, then the requested section or the
whole body. With --json, prints a JSON object instead (path, version, required_data_sources,
visibility_gaps, section text).
"""
import argparse, glob, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "references", "framework"))


def parse_frontmatter(text):
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text
    fm, body = text[4:end], text[end + 5:]
    fields, key = {}, None
    for line in fm.splitlines():
        if re.match(r"^\s+-\s+", line) and key:
            item = re.sub(r"^\s+-\s+", "", line)
            item = re.sub(r"\s+#.*$", "", item).strip()
            fields.setdefault(key, [])
            if isinstance(fields[key], list):
                fields[key].append(item)
        else:
            m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
            if m:
                key = m.group(1)
                val = m.group(2).strip()
                fields[key] = [] if val == "" else val
    return fields, body


def load_playbooks(root):
    out = []
    for sub in ("04-Playbooks/01-Triage", "04-Playbooks/02-Investigation-Response"):
        for path in sorted(glob.glob(os.path.join(root, sub, "*.md"))):
            if os.path.basename(path).startswith("_"):
                continue
            fields, body = parse_frontmatter(open(path, encoding="utf-8").read())
            out.append({"path": path, "rel": os.path.relpath(path, root), "fields": fields, "body": body})
    return out


def section(body, heading, level):
    """Return the text of the section whose heading (any level >= level) matches, up to the next heading of the same or higher level."""
    lines = body.splitlines()
    pat = re.compile(r"^(#{%d,})\s+(.*)$" % level)
    start = None
    depth = None
    for i, line in enumerate(lines):
        m = re.match(r"^(#+)\s+(.*)$", line)
        if m:
            if start is None and len(m.group(1)) >= level and heading.lower() in m.group(2).strip().lower():
                start, depth = i, len(m.group(1))
                continue
            if start is not None and len(m.group(1)) <= depth:
                return "\n".join(lines[start:i]).strip()
    return "\n".join(lines[start:]).strip() if start is not None else ""


TECHNIQUE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b(?:\s*\(([^)]+)\))?")
CATEGORY = re.compile(r"\b(IC-\d{2})\b")
CANDIDATES = re.compile(r"\*\*Candidate Incident Categor(?:y|ies)[^*]*:\*\*([^\n]*)")


def candidate_categories(text):
    """The Incident Categories a playbook proposes for what was selected, in its own order.

    The playbook states them in a labelled element, and the order is the playbook's: the first is
    the one Investigation opens. A reader of the printed prose would have to scrape them out with
    a regular expression of their own, which is a rule of the framework living in whoever scraped
    it last; it is stated here once, beside the playbook that declares it.
    """
    out = []
    for element in CANDIDATES.findall(text or ""):
        for found in CATEGORY.findall(element):
            if found not in out:
                out.append(found)
    return out


def technique_index(root=ROOT):
    """Technique id -> {name, categories, alert_types, domains}, read from the framework's own tables.

    Every table row that names a technique is read: an alert catalog carries the technique and the
    candidate Incident Categories of an alert type in one row, and an Investigation & Response playbook
    carries its category in the frontmatter and its techniques under `mitre_ttps`. A name is recorded
    only where the framework writes one, so a technique it never names is never given a name here.
    """
    index = {}

    def entry(tid):
        return index.setdefault(tid, {"name": None, "categories": set(), "alert_types": set(), "domains": set()})

    for path in sorted(glob.glob(os.path.join(root, "**", "*.md"), recursive=True)):
        if os.path.basename(path).startswith("_"):
            continue
        with open(path, encoding="utf-8") as handle:
            fields, body = parse_frontmatter(handle.read())
        book_domain = fields.get("domain")
        book_category = fields.get("incident_category")
        heading = None
        for line in body.splitlines():
            head = re.match(r"^##\s+(.+?)\s*$", line)
            if head:
                heading = head.group(1)
                continue
            if not line.lstrip().startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            found = [(m.group(1), m.group(2)) for cell in cells for m in TECHNIQUE.finditer(cell)]
            if not found:
                continue
            categories = {m.group(1) for cell in cells for m in CATEGORY.finditer(cell)}
            alert_type = cells[0] if cells and cells[0] and not set(cells[0]) <= set("-: ") else None
            for tid, name in found:
                item = entry(tid)
                if name and not item["name"]:
                    item["name"] = name.strip()
                item["categories"] |= categories
                if alert_type:
                    item["alert_types"].add(alert_type)
                for domain in (book_domain, heading):
                    if isinstance(domain, str) and domain:
                        item["domains"].add(domain)
        if book_category:
            for tid in fields.get("mitre_ttps", []) or []:
                m = TECHNIQUE.match(str(tid))
                if m:
                    entry(m.group(1))["categories"].add(str(book_category))
    for item in index.values():
        item["categories"] = sorted(item["categories"])
        item["alert_types"] = sorted(item["alert_types"])
        item["domains"] = sorted(item["domains"])
    return index


def candidates(technique_ids, index):
    """What the framework knows of the techniques a detection named, and where they point.

    Each id keeps its own form: it is matched on itself, else on its parent technique, and rendered
    `ID (Name)` only where the framework names that exact id. An id nothing matches is listed under
    `unknown` — it widens nothing, and it is the signal that the catalog is incomplete.
    """
    out, categories, unknown = [], set(), []
    for raw in technique_ids:
        tid = str(raw).strip()
        matched, item = tid, index.get(tid)
        if item is None and "." in tid:
            matched = tid.split(".")[0]
            item = index.get(matched)
        if item is None:
            matched, item = None, {"categories": [], "alert_types": [], "domains": []}
            unknown.append(tid)
        name = (index.get(tid) or {}).get("name")
        categories |= set(item["categories"])
        out.append({"id": tid, "name": name, "rendered": f"{tid} ({name})" if name else tid, "matched": matched,
                    "categories": list(item["categories"]), "alert_types": list(item["alert_types"]),
                    "domains": list(item["domains"])})
    return {"techniques": out, "categories": sorted(categories), "unknown": unknown}


def gaps(fields, bindings):
    req = fields.get("required_data_sources", []) or []
    if isinstance(req, str):
        req = [req]
    ds = (bindings or {}).get("data_sources", {})
    why = (bindings or {}).get("data_source_notes", {})
    out = []
    for r in req:
        state = ds.get(r)
        item = {"data_source": r, "available": state, "status": "available" if state else ("unavailable" if state is False else "unbound")}
        if r in why:
            item["reason"] = why[r]
        out.append(item)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--domain")
    ap.add_argument("--category")
    ap.add_argument("--alert-type")
    ap.add_argument("--technique", action="append", default=[],
                    help="a technique the detection named; repeatable. Prints what the framework calls it and the categories it points at")
    ap.add_argument("--section")
    ap.add_argument("--bindings")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.technique:
        found = candidates(a.technique, technique_index(a.root))
        if a.json:
            print(json.dumps(found, indent=2, ensure_ascii=False))
            return
        for t in found["techniques"]:
            where = ", ".join(t["categories"]) or "no candidate category in the framework's tables"
            print(f"{t['rendered']}\t{where}" + (f"\t(matched on {t['matched']})" if t["matched"] and t["matched"] != t["id"] else ""))
        print("candidate_incident_categories: " + (", ".join(found["categories"]) or "none"))
        if found["unknown"]:
            print("not in the framework's tables; record them on the Case and name them in the Note: " + ", ".join(found["unknown"]))
        return
    books = load_playbooks(a.root)
    if a.list:
        for b in books:
            key = b["fields"].get("domain") or b["fields"].get("incident_category")
            print(f"{key}\t{b['rel']}\t{b['fields'].get('last_updated','')}\t{b['fields'].get('status','')}")
        return
    bindings = json.load(open(a.bindings)) if a.bindings else None
    chosen = None
    if a.domain:
        chosen = next((b for b in books if str(b["fields"].get("domain", "")).lower() == a.domain.lower()), None)
        if not chosen:
            print(f"no triage playbook for domain '{a.domain}' at this framework pin; use the domain's alert catalog in 02-Taxonomy/alert_types.md and the method of Detection & Analysis §1 directly", file=sys.stderr)
            sys.exit(2)
    elif a.category:
        chosen = next((b for b in books if str(b["fields"].get("incident_category", "")).upper() == a.category.upper()), None)
        if not chosen:
            chosen = next((b for b in books if b["rel"].endswith("00-generic.md")), None)
            if chosen:
                print(f"no playbook for {a.category}; using the catch-all", file=sys.stderr)
            else:
                print(f"no playbook for {a.category} and no catch-all at this framework pin; apply Detection & Analysis §2 directly with the category definition in 02-Taxonomy/incident_categories.md", file=sys.stderr)
                sys.exit(2)
    else:
        ap.error("one of --domain, --category, --technique or --list is required")
    text = chosen["body"]
    if a.alert_type:
        text = section(chosen["body"], a.alert_type, 3) or f"(alert type '{a.alert_type}' not found in {chosen['rel']}; see its Alert Catalog)"
    elif a.section:
        text = section(chosen["body"], a.section, 2) or f"(section '{a.section}' not found in {chosen['rel']})"
    g = gaps(chosen["fields"], bindings)
    result = {
        "path": chosen["rel"], "version": chosen["fields"].get("last_updated", ""), "status": chosen["fields"].get("status", ""),
        "candidate_incident_categories": candidate_categories(text),
        "required_data_sources": g,
        "visibility_gaps": [{"data_source": x["data_source"], "check_prevented": "(state the check this source would have supported)"} for x in g if x["status"] != "available"] if bindings else [],
        "text": text,
    }
    if a.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    print(f"# {chosen['rel']} (version {result['version']}, status {result['status']})")
    if result["candidate_incident_categories"]:
        print("candidate_incident_categories: " + ", ".join(result["candidate_incident_categories"]))
    print("required_data_sources:")
    for x in g:
        print(f"  - {x['data_source']}: {x['status']}" + (f" ({x['reason']})" if x.get("reason") else ""))
    if bindings and result["visibility_gaps"]:
        print("VISIBILITY GAPS: record each in the Note with the check it prevented.")
    print()
    print(text)


if __name__ == "__main__":
    main()
