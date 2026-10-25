#!/usr/bin/env python3
"""Extract from an OCSF release the attributes a Case can carry: those of the Incident Finding
class and of every object they reach, with their types.

The Case Schema states only what OCSF leaves open (DD-23). Any other attribute of the OCSF class
is used as OCSF defines it, so a source profile may land a field on one the framework never names.
`tools/check_profiles.py` reads this file to tell such a target from a misspelt one.

Written to `tools/ocsf_<version>.json`; the checker reads the release the Case Schema declares as
its `ocsf_version`. An attribute's type is OCSF's scalar type (`string_t`, ...) or the name of the
object it holds, with `[]` when it is a list. Profile attributes are included: a Case that declares
the profile carries them. `constraints` keeps OCSF's own rules on an object's attributes, such as a
user that needs at least one of `account`, `name` or `uid`.

Standard library only. Reads the OCSF schema server's API.

Usage:
  python3 tools/ocsf_extract.py 1.9.0
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
API = "https://schema.ocsf.io/api/{version}/{kind}/{name}"
CLASS = "incident_finding"


def _fetch(version: str, kind: str, name: str) -> dict[str, Any]:
    url = API.format(version=version, kind=kind, name=name)
    with urllib.request.urlopen(url, timeout=60) as answer:  # noqa: S310 - a fixed https URL
        return json.load(answer)  # type: ignore[no-any-return]


def _types(definition: dict[str, Any]) -> dict[str, str]:
    out = {}
    for name, held in sorted(definition["attributes"].items()):
        kind = held.get("object_type") if held.get("type") == "object_t" else held["type"]
        out[name] = f"{kind}[]" if held.get("is_array") else kind
    return out


def extract(version: str) -> dict[str, Any]:
    case = _fetch(version, "classes", CLASS)
    attributes = _types(case)
    objects: dict[str, dict[str, str]] = {}
    constraints: dict[str, dict[str, list[str]]] = {CLASS: case["constraints"]} if case.get("constraints") else {}
    pending = sorted({t.removesuffix("[]") for t in attributes.values() if not t.endswith("_t") and not t.endswith("_t[]")})
    while pending:
        name = pending.pop()
        if name in objects:
            continue
        definition = _fetch(version, "objects", name)
        objects[name] = _types(definition)
        if definition.get("constraints"):
            constraints[name] = definition["constraints"]
        pending += [t.removesuffix("[]") for t in objects[name].values()
                    if not t.removesuffix("[]").endswith("_t") and t.removesuffix("[]") not in objects]
    return {
        "ocsf_version": version,
        "source": API.format(version=version, kind="classes", name=CLASS),
        "class": {CLASS: attributes},
        "objects": dict(sorted(objects.items())),
        "constraints": dict(sorted(constraints.items())),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    held = extract(argv[0])
    path = ROOT / "tools" / f"ocsf_{argv[0]}.json"
    path.write_text(json.dumps(held, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"{path.relative_to(ROOT)}: {len(held['class'][CLASS])} class attributes, {len(held['objects'])} objects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
