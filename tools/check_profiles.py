#!/usr/bin/env python3
"""Validate every source profile against capabilities/source_profile.schema.json.

A profile is what one technology's records mean in the framework's terms. It is data, and data
that nothing validates drifts: two files declared what this source's remediation states mean, one
of them knew only the states that neutralize something, and a remediation the source attempted and
failed was silently nothing.

The validator covers the subset of JSON Schema the profile schema uses. A keyword it does not know
is an error rather than a pass, so the schema cannot quietly outgrow the check.

Standard library only. Exit 1 on any violation.

A deployment that lays a local override over a shipped profile checks its binding: the override
against its own schema, and the profile that results against the same schema and the same coherence
as a shipped one, so an override cannot say less than the profile it stands in for.

Usage:
  python3 tools/check_profiles.py                   # every skills/*/source_profile.json
  python3 tools/check_profiles.py PATH ...          # these profiles
  python3 tools/check_profiles.py [PATH ...] --bindings PATH ...   # what a binding names, overrides laid over
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "capabilities" / "source_profile.schema.json"
OVERRIDE_SCHEMA = ROOT / "capabilities" / "source_profile_override.schema.json"

sys.path.insert(0, str(ROOT / "tools" / "shared"))
import source_profile  # noqa: E402

KNOWN = {
    "$schema", "$id", "$ref", "$defs", "title", "description",
    "type", "required", "properties", "additionalProperties", "items", "minItems", "enum",
    "oneOf", "const", "minLength",
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


def supported(schema: Any, where: str = "schema") -> list[str]:
    """Every keyword of the whole schema this validator does not know.

    Walked once, over the schema itself rather than over a profile: a keyword on a branch no
    profile happens to exercise would otherwise never be reached, and the guard would pass while
    the schema had already outgrown it.
    """
    problems: list[str] = []
    if isinstance(schema, dict):
        for name in sorted(set(schema) - KNOWN):
            problems.append(f"{where}: the schema uses {name!r}, which this validator does not know")
        declared = schema.get("type")
        for kind in [declared] if isinstance(declared, str) else list(declared or []):
            if kind not in TYPES:
                problems.append(f"{where}: the schema uses the type {kind!r}, which this validator cannot check")
        for name, held in schema.items():
            if name in ("properties", "$defs"):
                for key, sub in (held or {}).items():
                    problems += supported(sub, f"{where}.{name}.{key}")
            elif name in ("items", "additionalProperties"):
                problems += supported(held, f"{where}.{name}")
            elif name == "oneOf":
                for n, sub in enumerate(held or []):
                    problems += supported(sub, f"{where}.oneOf[{n}]")
    return problems


def validate(value: Any, schema: dict[str, Any], root: dict[str, Any], where: str) -> list[str]:
    """The errors of one value against one schema, each naming where it is."""
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
    if "const" in schema and value != schema["const"]:
        problems.append(f"{where}: expected {schema['const']!r}, found {value!r}")
    if "minLength" in schema and isinstance(value, str) and len(value) < schema["minLength"]:
        problems.append(f"{where}: {value!r} is shorter than the {schema['minLength']} characters required")
    if "oneOf" in schema:
        problems += _one_of(value, schema["oneOf"], root, where)

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


def _one_of(value: Any, branches: list[dict[str, Any]], root: dict[str, Any], where: str) -> list[str]:
    """One of several forms the same place may take, and exactly one of them.

    When none fits, the branch that came closest is the useful answer — a rule missing one key is
    reported against the form it was nearly, not against all of them at once — so the branch with
    the fewest problems is the one reported, named by its title where the schema gives one.
    """
    failures = [(sub, validate(value, sub, root, where)) for sub in branches]
    fitting = [sub for sub, problems in failures if not problems]
    if len(fitting) == 1:
        return []
    forms = " or ".join(sub.get("title", f"form {n + 1}") for n, sub in enumerate(branches))
    if not fitting:
        closest, problems = min(failures, key=lambda pair: len(pair[1]))
        named = closest.get("title", "one of the forms")
        return [f"{where}: fits none of {forms}; read as {named}: " + "; ".join(problems)]
    return [f"{where}: fits more than one of {forms}, so which was meant is ambiguous"]


def coherent(profile: dict[str, Any], where: str) -> list[str]:
    """What the schema cannot say: the profile has to agree with itself."""
    problems: list[str] = []
    listed = [entry["path"] for entry in profile["case_map"]]
    paths = set(listed)
    for path in sorted(paths):
        if listed.count(path) > 1:
            problems.append(f"{where}: {path!r} is in the case_map {listed.count(path)} times; "
                            "a path lands in one place")
    for entry in profile["case_map"]:
        if "case" not in entry and "ignored" not in entry:
            problems.append(f"{where}: {entry['path']!r} is neither mapped nor ignored")
        if "case" in entry and "ignored" in entry:
            problems.append(f"{where}: {entry['path']!r} is both mapped and ignored")
        if "ignored" in entry and not str(entry["ignored"]).strip():
            problems.append(f"{where}: {entry['path']!r} is ignored with no reason")
    # telemetry rows are not a path on the source's *record*: they are the shape of an answer to a
    # query, and the case_map describes the record. They are checked by their own shape instead.
    for group, fields in profile["fields"].items():
        if group == "telemetry_rows":
            for column, attribute in (fields.get("objects") or {}).items():
                if not attribute or not all(isinstance(step, str) and step for step in attribute):
                    problems.append(
                        f"{where}: telemetry column {column!r} maps to no attribute path")
            continue
        prefix = {"case": "", "alert": "alerts[].", "evidence": "alerts[].evidence[]."}[group]
        for name, path in fields.items():
            # the whole path, never its first step: the case_map names every nested key, and a
            # parent that is mapped says nothing about a child that is misspelt
            if f"{prefix}{path}" not in paths:
                problems.append(
                    f"{where}: fields.{group}.{name} reads {path!r}, which the case_map does not name"
                )
    for name, path in (profile["alert_types"].get("fields") or {}).items():
        if f"alerts[].{path}" not in paths:
            problems.append(
                f"{where}: alert_types.fields.{name} reads {path!r}, which the case_map does not name")
    for rule in profile["alert_types"]["rules"]:
        # a rule either names the framework type its alerts carry, or says they are deliberately
        # left unmapped; both forms match the same way, so both are reported by what they are
        named = (f"alert type {rule['alert_type']!r}" if "alert_type" in rule
                 else f"the non-mapping {rule.get('reason', '')!r}")
        if not rule.get("detector_ids") and not rule.get("title_patterns"):
            problems.append(f"{where}: {named} has no detector id and no "
                            "title pattern, so it matches nothing")
        for pattern in rule.get("title_patterns", []):
            if not pattern.strip():
                problems.append(f"{where}: {named} has an empty title "
                                "pattern, which matches every title")
                continue
            try:
                re.compile(pattern)
            except re.error as exc:
                problems.append(f"{where}: {named} has a bad pattern {pattern!r}: {exc}")
    for name, held in profile["extension"]["properties"].items():
        if held["from"] not in paths:
            problems.append(f"{where}: extension.{name} reads {held['from']!r}, which the case_map does not name")
    return problems


def _declared(target: str, schema: dict[str, Any], root: dict[str, Any]) -> bool:
    """Whether the Case Schema declares a dotted path. An open object is no excuse: an OCSF object
    takes any attribute, and a target nothing declares is a target nobody will read."""
    node: dict[str, Any] = schema
    for step in target.split("."):
        name, into_list = (step[:-2], True) if step.endswith("[]") else (step, False)
        while "$ref" in node:
            node = root["$defs"][node["$ref"].split("/")[-1]]
        node = (node.get("properties") or {}).get(name)
        if node is None:
            return False
        while "$ref" in node:
            node = root["$defs"][node["$ref"].split("/")[-1]]
        if into_list:
            node = node.get("items") or {}
    return True


def lands(profile: dict[str, Any], case_schema: dict[str, Any], where: str) -> list[str]:
    """Every mapped path lands on a field the pinned Case Schema declares, or on a property of the
    source's own extension object, which the profile itself declares."""
    problems: list[str] = []
    own = profile["extension"]["key"]
    for entry in profile["case_map"]:
        targets = entry.get("case") or []
        for target in [targets] if isinstance(targets, str) else targets:
            if target.startswith(f"{own}."):
                ok = target[len(own) + 1:] in profile["extension"]["properties"]
            else:
                ok = _declared(target, case_schema, case_schema)
            if not ok:
                problems.append(f"{where}: {entry['path']!r} lands on {target!r}, which the Case Schema does not declare")
    # a vocabulary turns the source's word into a value of the Case: it has to be one the Case has
    for name, field in (("severity", "severity_id"), ("status", "status_id"), ("verdict", "verdict_id")):
        allowed = (case_schema.get("properties") or {}).get(field, {}).get("enum")
        for word, held in (profile["vocabularies"].get(name) or {}).items():
            if allowed is not None and held["id"] not in allowed:
                problems.append(f"{where}: vocabularies.{name}.{word} is {held['id']}, which is no {field} "
                                f"of the Case Schema ({', '.join(map(str, allowed))})")
    problems += _determination(profile, case_schema, where)
    return problems


def _determination(profile: dict[str, Any], case_schema: dict[str, Any], where: str) -> list[str]:
    """The source's account of what the activity was: each word names the verdicts it may be
    written with, and a verdict that admits one word says so on that word alone.

    An executor closing a Case in the source reads this to know what it may write. Two words
    marked `only` for the same verdict, or one marked `only` beside others that offer themselves
    for it, is a vocabulary that answers a closure with two answers — which is the one thing an
    executor cannot do anything sensible with.
    """
    problems: list[str] = []
    allowed = (case_schema.get("properties") or {}).get("verdict_id", {}).get("enum")
    words = (profile["vocabularies"].get("determination") or {}).items()
    for word, held in words:
        for verdict in held["verdict_ids"]:
            if allowed is not None and verdict not in allowed:
                problems.append(f"{where}: vocabularies.determination.{word} names verdict {verdict}, which is "
                                f"no verdict_id of the Case Schema ({', '.join(map(str, allowed))})")
    for verdict in sorted({v for _w, held in words for v in held["verdict_ids"]}):
        offered = [w for w, held in words if verdict in held["verdict_ids"]]
        sole = [w for w in offered if (profile["vocabularies"]["determination"][w]).get("only")]
        if sole and offered != sole:
            problems.append(f"{where}: verdict {verdict} has vocabularies.determination.{sole[0]} marked `only` "
                            f"and is also offered {', '.join(w for w in offered if w not in sole)}: a verdict "
                            "admits one word or a choice of them, never both")
        if len(sole) > 1:
            problems.append(f"{where}: verdict {verdict} has {len(sole)} determinations marked `only` "
                            f"({', '.join(sole)}); `only` says there is nothing to choose")
    return problems


def case_schema_beside(path: Path) -> dict[str, Any] | None:
    """The Case Schema a tool skill carries in its generated references, at the pin it conforms to."""
    held = path.parent / "references" / "framework" / "02-Taxonomy" / "case_schema.json"
    return json.loads(held.read_text(encoding="utf-8")) if held.exists() else None


def shipped(profile: dict[str, Any], where: str) -> list[str]:
    """A profile on disk is a shipped one: the record of an override is written when a deployment
    reads through one, and a file that already carries it would pass for a run that did."""
    source = profile.get("source") if isinstance(profile, dict) else None
    if isinstance(source, dict) and "override" in source:
        return [f"{where}: source.override is written by the loader when a deployment reads through "
                "a local override; a profile file never carries one"]
    return []


def bound(binding: Path, schema: dict[str, Any], override_schema: dict[str, Any]) -> list[str]:
    """Every profile a binding names, as the deployment reads it: its override laid over it."""
    problems: list[str] = []
    try:
        named = json.loads(binding.read_text(encoding="utf-8")).get("source_profiles") or {}
        source_profile.resolved(str(binding), next(iter(named), None))  # an override with no profile
    except (OSError, ValueError) as exc:
        print(f"{binding.name}: cannot be read")
        return [f"{binding.name}: {exc}"]
    if not named:
        print(f"{binding.name}: names no source profile, which is a visibility gap and not an error")
    for source in sorted(named):
        where = f"{binding.name}: {source}"
        try:
            path, override = source_profile.resolved(str(binding), source)
            if override:
                document = json.loads(Path(override).read_text(encoding="utf-8"))
                found = validate(document, override_schema, override_schema, Path(override).name)
                if found:
                    problems += found
                    print(f"{where}: {len(found)} problem(s) in the override")
                    continue
            profile = source_profile.load(path, override)
        except (OSError, ValueError, re.error) as exc:
            problems.append(f"{where}: {exc}")
            print(f"{where}: cannot be read")
            continue
        found = validate(profile, schema, schema, where) or coherent(profile, where)
        case_schema = case_schema_beside(Path(path))
        if not found and case_schema is not None:
            found = lands(profile, case_schema, where)
        problems += found
        how = f"read through {Path(override).name}" if override else "as shipped"
        print(f"{where}: " + (f"{len(found)} problem(s), {how}" if found
                              else f"ok ({len(profile['case_map'])} mapped paths, {how})"))
        for note in source_profile.notes(profile):
            print(f"note: {note}")
    return problems


def main(argv: list[str]) -> int:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    override_schema = json.loads(OVERRIDE_SCHEMA.read_text(encoding="utf-8"))
    outgrown = supported(schema) + supported(override_schema, "override schema")
    for problem in outgrown:
        print(problem, file=sys.stderr)
    if outgrown:
        print("the schema has outgrown this validator; teach it the keyword or drop it", file=sys.stderr)
        return 1
    problems: list[str] = []
    split = argv.index("--bindings") if "--bindings" in argv else len(argv)
    bindings = [Path(a) for a in argv[split + 1:]]
    if split < len(argv) and not bindings:
        print("--bindings takes the path of a capability binding", file=sys.stderr)
        return 1
    for binding in bindings:
        problems += bound(binding, schema, override_schema)
    profiles = [Path(a) for a in argv[:split]]
    if not profiles and not bindings:
        profiles = sorted(ROOT.glob("skills/*/source_profile.json"))
        if not profiles:
            print("no source profile found", file=sys.stderr)
            return 1
    for path in profiles:
        profile = json.loads(path.read_text(encoding="utf-8"))
        where = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        found = (validate(profile, schema, schema, str(where)) or coherent(profile, str(where))) \
            + shipped(profile, str(where))
        case_schema = case_schema_beside(path)
        if not found and case_schema is not None:
            found = lands(profile, case_schema, str(where))
        problems += found
        state = "ok" if not found else f"{len(found)} problem(s)"
        print(f"{where}: {state}" + ("" if found else f" ({len(profile['case_map'])} mapped paths)"))
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"{len(problems)} problem(s)", file=sys.stderr)
        return 1
    print("source profiles: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
