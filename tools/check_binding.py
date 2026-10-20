#!/usr/bin/env python3
"""Check a reference binding against the capabilities manifest of the server it describes.

A binding shipped as a reference shape describes what a server answers on one kind of deployment. The
server moves on, and a hand-kept binding does not follow it: tools change, classes gain an option, a
source becomes readable. Nothing notices, and the binding goes on telling every reader that a source is
missing when the server has read it for two releases.

So a reference binding names what it was derived from under "reference":

  "reference": {"manifest": "<URL of the server's capabilities.manifest.json at a release tag>",
                "provides": ["<every requirement the deployment meets: api:..., hunting:<table>, role:...>"]}

and this check derives from that manifest what a capability probe would bind on a deployment that meets
exactly those requirements, then compares it with the binding:

- each capability class the manifest knows is bound to the first option whose requirements are all met
  ("requires_all", and at least one of "requires_any" when it names any), and left unbound when none is;
  an "always:" requirement is met everywhere and is not listed;
- each data source the manifest knows is available when any requirement of its "any_of" is met, or every
  requirement of its "all_of".

Those are the rules of the server's own probe, which writes a binding from a live tenant the same way. A
class the manifest does not know (a knowledge base, a reputation service) is the deployment's own and is
left alone; a data source the manifest does not know is an error, because the binding then answers for a
source nobody declared. Notes are prose and are not compared.

A class may bind an ordered list of providers, each saying which observables it accepts. The manifest's
option is compared with the first of them; the others are the deployment's own and are left alone. Before
any of this the binding is held to its schema (capabilities/zerosoc.capabilities.schema.json), so a listed
provider that does not say what it accepts is refused here, not discovered by a host.

Standard library only. Exit 1 on any difference, 2 when the manifest cannot be read.

Usage:
  python3 tools/check_binding.py BINDING [--manifest PATH]   # PATH: a local copy, instead of the URL
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "capabilities" / "zerosoc.capabilities.schema.json"


def _validator() -> Any:
    """The standard-library schema check the profiles are held to, from its own file."""
    spec = importlib.util.spec_from_file_location("check_profiles", Path(__file__).with_name("check_profiles.py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate


def schema_problems(binding: dict[str, Any]) -> list[str]:
    """Every way the binding does not fit its schema, each naming where."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return _validator()(binding, schema, schema, "binding")


def first_tool(bound: Any) -> str | None:
    """The tool a class is bound to, or the first provider's when it binds several."""
    if isinstance(bound, list):
        bound = bound[0] if bound else None
    return (bound or {}).get("tool")


def _holds(requirement: str, provides: set[str]) -> bool:
    """An "always:" requirement holds on every deployment, as the probe answers it; any other only where
    the deployment provides it."""
    return requirement.startswith("always:") or requirement in provides


def _met(option: dict[str, Any], provides: set[str]) -> bool:
    every = option.get("requires_all") or []
    some = option.get("requires_any") or []
    return all(_holds(r, provides) for r in every) and (not some or any(_holds(r, provides) for r in some))


def _provided(rule: dict[str, Any], provides: set[str]) -> bool:
    any_of = rule.get("any_of") or []
    all_of = rule.get("all_of") or []
    return any(_holds(r, provides) for r in any_of) or bool(all_of and all(_holds(r, provides) for r in all_of))


def expected(manifest: dict[str, Any], provides: set[str]) -> tuple[dict[str, str | None], dict[str, bool]]:
    """What a probe of a deployment meeting ``provides`` binds: class -> tool or None, source -> bool."""
    classes = {
        klass: next((o["tool"] for o in options if _met(o, provides)), None)
        for klass, options in manifest.get("capabilities", {}).items()
    }
    sources = {name: _provided(rule, provides) for name, rule in manifest.get("data_sources", {}).items()}
    return classes, sources


def differences(binding: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    """Every way the binding differs from what the manifest derives for its declared requirements."""
    reference = binding.get("reference") or {}
    if not reference.get("provides"):
        return ["the binding declares no reference.provides: nothing to derive the expected binding from"]
    provides = set(reference["provides"])
    known = {
        r
        for options in manifest.get("capabilities", {}).values()
        for o in options
        for r in [*(o.get("requires_all") or []), *(o.get("requires_any") or [])]
    } | {
        r for rule in manifest.get("data_sources", {}).values()
        for r in [*(rule.get("any_of") or []), *(rule.get("all_of") or [])]
    }
    out = [f"reference.provides names {r}, which nothing in the manifest requires" for r in sorted(provides - known)]
    out += [f"reference.provides names {r}, which holds on every deployment and is not listed"
            for r in sorted(r for r in provides if r.startswith("always:"))]
    classes, sources = expected(manifest, provides)
    bound = {k: first_tool(v) for k, v in (binding.get("capabilities") or {}).items()}
    for klass, tool in sorted(classes.items()):
        have = bound.get(klass)
        if tool != have:
            out.append(f"capability {klass}: the manifest binds {tool or 'nothing'}, the binding {have or 'nothing'}")
    answered = binding.get("data_sources") or {}
    for name, available in sorted(sources.items()):
        if name not in answered:
            out.append(f"data source {name!r}: the manifest knows it, the binding does not answer it")
        elif answered[name] is not available:
            out.append(f"data source {name!r}: the manifest makes it {available}, the binding {answered[name]}")
    out += [f"data source {name!r}: the binding answers it, the manifest does not know it"
            for name in sorted(set(answered) - set(sources))]
    return out


def load_manifest(binding: dict[str, Any], path: str | None) -> dict[str, Any]:
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    url = (binding.get("reference") or {}).get("manifest")
    if not url:
        raise ValueError("the binding names no reference.manifest and no --manifest was given")
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - a URL the binding pins
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binding")
    ap.add_argument("--manifest", help="a local copy of the manifest, read instead of reference.manifest")
    a = ap.parse_args(argv)
    with open(a.binding, encoding="utf-8") as f:
        binding = json.load(f)
    unfit = schema_problems(binding)
    if unfit:
        for line in unfit:
            print(f"{a.binding}: {line}")
        return 1
    try:
        manifest = load_manifest(binding, a.manifest)
    except (OSError, ValueError) as exc:
        print(f"{a.binding}: cannot read the manifest: {exc}", file=sys.stderr)
        return 2
    found = differences(binding, manifest)
    for line in found:
        print(f"{a.binding}: {line}")
    if not found:
        server = f"{manifest.get('server', '?')} {manifest.get('version', '?')}"
        print(f"{a.binding}: ok (matches the manifest of {server})")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
