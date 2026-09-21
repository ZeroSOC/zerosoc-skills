#!/usr/bin/env python3
"""Validate every source profile against capabilities/source_profile.schema.json.

A profile is what one technology's records mean in the framework's terms. It is data, and data
that nothing validates drifts: two files declared what this source's remediation states mean, one
of them knew only the states that neutralize something, and a remediation the source attempted and
failed was silently nothing.

The validator covers the subset of JSON Schema the profile schema uses. A keyword it does not know
is an error rather than a pass, so the schema cannot quietly outgrow the check.

Standard library only. Exit 1 on any violation.

Usage:
  python3 tools/check_profiles.py            # every skills/*/source_profile.json
  python3 tools/check_profiles.py PATH ...   # these profiles
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "capabilities" / "source_profile.schema.json"

KNOWN = {
    "$schema", "$id", "$ref", "$defs", "title", "description",
    "type", "required", "properties", "additionalProperties", "items", "minItems", "enum",
}
TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)
}


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return isinstance(value, TYPES[expected])


def validate(value: Any, schema: dict[str, Any], root: dict[str, Any], where: str) -> list[str]:
    """The errors of one value against one schema, each naming where it is."""
    unknown = set(schema) - KNOWN
    if unknown:
        return [f"{where}: the schema uses keywords this validator does not know: {sorted(unknown)}"]
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            return [f"{where}: only #/$defs/ references are supported, not {ref!r}"]
        return validate(value, root["$defs"][ref.split("/")[-1]], root, where)

    problems: list[str] = []
    declared = schema.get("type")
    kinds = [declared] if isinstance(declared, str) else list(declared or [])
    for kind in kinds:
        if kind not in TYPES:
            return [f"{where}: unknown type {kind!r} in the schema"]
    if kinds and not any(_type_ok(value, k) for k in kinds):
        return [f"{where}: expected {' or '.join(kinds)}, found {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{where}: {value!r} is not one of {schema['enum']}")

    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                problems.append(f"{where}: missing required {name!r}")
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for name, held in value.items():
            if name in properties:
                problems += validate(held, properties[name], root, f"{where}.{name}")
            elif extra is False:
                problems.append(f"{where}.{name}: not declared, and the schema allows no others")
            elif isinstance(extra, dict):
                problems += validate(held, extra, root, f"{where}.{name}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            problems.append(f"{where}: {len(value)} items, fewer than the {schema['minItems']} required")
        if "items" in schema:
            for n, held in enumerate(value):
                problems += validate(held, schema["items"], root, f"{where}[{n}]")
    return problems


def coherent(profile: dict[str, Any], where: str) -> list[str]:
    """What the schema cannot say: the profile has to agree with itself."""
    problems: list[str] = []
    paths = {entry["path"] for entry in profile["case_map"]}
    for entry in profile["case_map"]:
        if "case" not in entry and "ignored" not in entry:
            problems.append(f"{where}: {entry['path']!r} is neither mapped nor ignored")
        if "ignored" in entry and not str(entry["ignored"]).strip():
            problems.append(f"{where}: {entry['path']!r} is ignored with no reason")
    for group, fields in profile["fields"].items():
        prefix = {"case": "", "alert": "alerts[].", "evidence": "alerts[].evidence[]."}[group]
        for name, path in fields.items():
            # a key of this source may itself contain a dot (@odata.type), so the whole path is
            # tried before its first segment
            if f"{prefix}{path}" not in paths and f"{prefix}{path.split('.')[0]}" not in paths:
                problems.append(
                    f"{where}: fields.{group}.{name} reads {path!r}, which the case_map does not name"
                )
    for rule in profile["alert_types"]["rules"]:
        for pattern in rule.get("title_patterns", []):
            try:
                re.compile(pattern)
            except re.error as exc:
                problems.append(f"{where}: alert type {rule['alert_type']!r} has a bad pattern {pattern!r}: {exc}")
    for name, held in profile["extension"]["properties"].items():
        if held["from"] not in paths:
            problems.append(f"{where}: extension.{name} reads {held['from']!r}, which the case_map does not name")
    return problems


def main(argv: list[str]) -> int:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    profiles = [Path(a) for a in argv] or sorted(ROOT.glob("skills/*/source_profile.json"))
    if not profiles:
        print("no source profile found", file=sys.stderr)
        return 1
    problems: list[str] = []
    for path in profiles:
        profile = json.loads(path.read_text(encoding="utf-8"))
        where = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        found = validate(profile, schema, schema, str(where))
        problems += found or coherent(profile, str(where))
        print(f"{where}: {'ok' if not found else 'invalid'} ({len(profile['case_map'])} mapped paths)")
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"{len(problems)} problem(s)", file=sys.stderr)
        return 1
    print("source profiles: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
