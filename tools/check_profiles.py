#!/usr/bin/env python3
"""Validate every source profile against capabilities/source_profile.schema.json.

A profile is what one technology's records mean in the framework's terms. It is data, and data
that nothing validates drifts: two files declared what this source's remediation states mean, one
of them knew only the states that neutralize something, and a remediation the source attempted and
failed was silently nothing.

The validator covers the subset of JSON Schema the profile schema uses. A keyword it does not know
is an error rather than a pass, so the schema cannot quietly outgrow the check.

A mapped path lands on what the Case Schema declares or, where the framework leaves an attribute of the
OCSF class to OCSF (DD-23), on what that OCSF release declares, read from tools/ocsf_<version>.json.

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
OCSF_CLASS = "incident_finding"
"""The OCSF class a Case maps to: where a target the Case Schema does not state is looked up."""

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
    forms = " or ".join(_resolved(sub, root).get("title", f"form {n + 1}") for n, sub in enumerate(branches))
    if not fitting:
        # a form the value is not even the type of was never close: a list is read as the list form
        closest, problems = min(
            failures, key=lambda pair: (not _kind_fits(value, _resolved(pair[0], root)), len(pair[1]))
        )
        named = _resolved(closest, root).get("title", "one of the forms")
        return [f"{where}: fits none of {forms}; read as {named}: " + "; ".join(problems)]
    return [f"{where}: fits more than one of {forms}, so which was meant is ambiguous"]


def _resolved(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    """The schema a branch stands for: the definition it references, or itself."""
    ref = schema.get("$ref", "")
    return root.get("$defs", {}).get(ref.split("/")[-1], schema) if ref.startswith("#/$defs/") else schema


def _kind_fits(value: Any, schema: dict[str, Any]) -> bool:
    declared = schema.get("type")
    kinds = [declared] if isinstance(declared, str) else list(declared or [])
    return not kinds or any(_type_ok(value, k) for k in kinds)


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
    problems += _extension(profile["extension"]["properties"], "", paths, where)
    return problems


def _extension(properties: dict[str, Any], at: str, paths: set[str], where: str) -> list[str]:
    """The source's own object, property by property: each read from a path the case_map names, and
    an array, and only an array, saying what its items are."""
    problems: list[str] = []
    for name, held in properties.items():
        here = f"{at}.{name}"
        if held["from"] not in paths:
            problems.append(f"{where}: extension{here} reads {held['from']!r}, which the case_map does not name")
        items = held.get("items")
        if (held["type"] == "array") != (items is not None):
            problems.append(f"{where}: extension{here} is {'an array without' if items is None else 'no array, with'} "
                            "items; an array, and only an array, declares what its items are")
        elif items is not None and ("type" in items) == ("properties" in items):
            problems.append(f"{where}: extension{here}.items declares {'both' if 'type' in items else 'neither'} "
                            "a type and properties; its items are one or the other")
        elif items is not None and "properties" in items:
            problems += _extension(items["properties"], f"{here}[]", paths, where)
    return problems


def ocsf_for(case_schema: dict[str, Any]) -> dict[str, Any] | None:
    """The attributes of the OCSF release the Case Schema follows, as tools/ocsf_extract.py wrote
    them, or None where that release has not been extracted."""
    held = ROOT / "tools" / f"ocsf_{case_schema.get('ocsf_version')}.json"
    return json.loads(held.read_text(encoding="utf-8")) if held.exists() else None


def _in_ocsf(steps: list[str], kind: str, ocsf: dict[str, Any]) -> bool:
    """Whether OCSF declares the rest of a path, from its class or from an object of this kind."""
    for n, step in enumerate(steps):
        name, into_list = (step[:-2], True) if step.endswith("[]") else (step, False)
        declared = (ocsf["class"].get(kind) or ocsf["objects"].get(kind) or {}).get(name)
        if declared is None:
            return False
        many = declared.endswith("[]")
        # a [] step needs a list, and a list is passed through only by a [] step, unless it ends the path
        if (into_list and not many) or (many and not into_list and n < len(steps) - 1):
            return False
        kind = declared.removesuffix("[]")
    return True


def _declared(target: str, schema: dict[str, Any], root: dict[str, Any],
              ocsf: dict[str, Any] | None = None) -> bool:
    """Whether the Case Schema declares a dotted path, or OCSF does where the Case Schema stops at an
    OCSF object (its class at the root, `x-ocsf-object` below it) and states no more of it: the
    framework states only what OCSF leaves open, and any other attribute of the class is used as OCSF
    defines it (DD-23). An open object is no excuse: a target nothing declares is a target nobody
    will read."""
    node: dict[str, Any] = schema
    steps = target.split(".")
    for n, step in enumerate(steps):
        name, into_list = (step[:-2], True) if step.endswith("[]") else (step, False)
        while "$ref" in node:
            node = root["$defs"][node["$ref"].split("/")[-1]]
        kind = OCSF_CLASS if node is schema else node.get("x-ocsf-object")
        held = (node.get("properties") or {}).get(name)
        if held is None:
            return kind is not None and ocsf is not None and _in_ocsf(steps[n:], kind, ocsf)
        node = held
        while "$ref" in node:
            node = root["$defs"][node["$ref"].split("/")[-1]]
        if into_list:
            node = node.get("items") or {}
    return True


def _extension_declares(target: str, properties: dict[str, Any]) -> bool:
    """Whether the source's own object declares a dotted path: a property, an item of an array, or a
    property of an item. The keys of an object it keeps whole are the source's, and none is a target."""
    steps = target.split(".")
    for n, step in enumerate(steps):
        name, into_list = (step[:-2], True) if step.endswith("[]") else (step, False)
        held = properties.get(name)
        last = n == len(steps) - 1
        if held is None or (into_list and held["type"] != "array"):
            return False
        if last:
            return True
        properties = ((held.get("items") or {}).get("properties") or {}) if into_list else {}
    return False


def lands(profile: dict[str, Any], case_schema: dict[str, Any], where: str) -> list[str]:
    """Every mapped path lands on a field the pinned Case Schema declares, on an attribute of the
    OCSF class it maps the Case to, or on a property of the source's own object under unmapped,
    which the profile itself declares and fills from the paths that land there."""
    problems: list[str] = []
    version = case_schema.get("ocsf_version")
    ocsf = ocsf_for(case_schema)
    if ocsf is None:
        problems.append(f"{where}: the Case Schema follows OCSF {version}, and tools/ocsf_{version}.json is not "
                        f"there to read its attributes from: run python3 tools/ocsf_extract.py {version}")
    own = f"unmapped.{profile['extension']['key']}."
    landed: dict[str, list[str]] = {}
    for entry in profile["case_map"]:
        targets = entry.get("case") or []
        for target in [targets] if isinstance(targets, str) else targets:
            landed.setdefault(entry["path"], []).append(target)
            if target.startswith(own):
                if not _extension_declares(target[len(own):], profile["extension"]["properties"]):
                    problems.append(f"{where}: {entry['path']!r} lands on {target!r}, which the source's "
                                    "object (extension) does not declare")
            elif not _declared(target, case_schema, case_schema, ocsf):
                problems.append(f"{where}: {entry['path']!r} lands on {target!r}, which neither the Case Schema "
                                f"nor OCSF {version} declares")
    for at, held in _filled(profile["extension"]["properties"], ""):
        if not any(t in (own + at, own + at + "[]") for t in landed.get(held["from"], [])):
            problems.append(f"{where}: extension property {at!r} is read from {held['from']!r}, whose case_map "
                            f"entry does not land on {own + at!r}")
    if ocsf is not None:
        problems += _unmet(landed, ocsf, version, where)
    # a vocabulary turns the source's word into a value of the Case: it has to be one the Case has
    for name, field in (("severity", "severity_id"), ("status", "status_id"), ("verdict", "verdict_id")):
        allowed = (case_schema.get("properties") or {}).get(field, {}).get("enum")
        for word, held in (profile["vocabularies"].get(name) or {}).items():
            if allowed is not None and held["id"] not in allowed:
                problems.append(f"{where}: vocabularies.{name}.{word} is {held['id']}, which is no {field} "
                                f"of the Case Schema ({', '.join(map(str, allowed))})")
    problems += _determination(profile, case_schema, where)
    return problems


def _ocsf_kind(path: str, ocsf: dict[str, Any]) -> str | None:
    """The OCSF object a path of the Case holds, or None where OCSF does not declare the path."""
    kind = OCSF_CLASS
    for step in path.split("."):
        declared = (ocsf["class"].get(kind) or ocsf["objects"].get(kind) or {}).get(step.removesuffix("[]"))
        if declared is None:
            return None
        kind = declared.removesuffix("[]")
    return kind


def _unmet(landed: dict[str, list[str]], ocsf: dict[str, Any], version: Any, where: str) -> list[str]:
    """OCSF's rules on the objects the profile fills: each one it lands an attribute in needs, of each
    set OCSF names, at least one attribute some path lands there. A user named only by a display
    name, or a tag with a key and no value, is no OCSF object. The Case itself is left out: its
    assignee is the executor's, and no source fills it."""
    filled: dict[str, set[str]] = {}
    for targets in landed.values():
        for target in targets:
            steps = target.split(".")
            for n in range(1, len(steps)):
                filled.setdefault(".".join(steps[:n]), set()).add(steps[n].removesuffix("[]"))
    problems: list[str] = []
    for parent, names in sorted(filled.items()):
        kind = _ocsf_kind(parent, ocsf)
        group = (ocsf.get("constraints", {}).get(kind) or {}).get("at_least_one") if kind else None
        if group and not names & set(group):
            problems.append(f"{where}: {parent!r} is an OCSF {kind} and needs at least one of "
                            f"{', '.join(group)} (OCSF {version}); the case_map lands only {', '.join(sorted(names))}")
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


def _filled(properties: dict[str, Any], at: str) -> list[tuple[str, dict[str, Any]]]:
    """Each property of the source's object, at its path within it."""
    out: list[tuple[str, dict[str, Any]]] = []
    for name, held in properties.items():
        here = f"{at}.{name}" if at else name
        out.append((here, held))
        out += _filled(((held.get("items") or {}).get("properties") or {}), f"{here}[]")
    return out


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
