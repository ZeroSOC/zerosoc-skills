#!/usr/bin/env python3
"""Select a ZeroSOC playbook and report visibility gaps. Standard library only.

  select_playbook.py --domain Endpoint [--alert-type "Malware / loader execution"] [--bindings zerosoc.capabilities.json] [--json]
  select_playbook.py --category IC-01 [--section Investigation] [--bindings ...] [--json]
  select_playbook.py --list

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
    ap.add_argument("--section")
    ap.add_argument("--bindings")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
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
        ap.error("one of --domain, --category or --list is required")
    text = chosen["body"]
    if a.alert_type:
        text = section(chosen["body"], a.alert_type, 3) or f"(alert type '{a.alert_type}' not found in {chosen['rel']}; see its Alert Catalog)"
    elif a.section:
        text = section(chosen["body"], a.section, 2) or f"(section '{a.section}' not found in {chosen['rel']})"
    g = gaps(chosen["fields"], bindings)
    result = {
        "path": chosen["rel"], "version": chosen["fields"].get("last_updated", ""), "status": chosen["fields"].get("status", ""),
        "required_data_sources": g,
        "visibility_gaps": [{"data_source": x["data_source"], "check_prevented": "(state the check this source would have supported)"} for x in g if x["status"] != "available"] if bindings else [],
        "text": text,
    }
    if a.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    print(f"# {chosen['rel']} (version {result['version']}, status {result['status']})")
    print("required_data_sources:")
    for x in g:
        print(f"  - {x['data_source']}: {x['status']}" + (f" ({x['reason']})" if x.get("reason") else ""))
    if bindings and result["visibility_gaps"]:
        print("VISIBILITY GAPS: record each in the Note with the check it prevented.")
    print()
    print(text)


if __name__ == "__main__":
    main()
