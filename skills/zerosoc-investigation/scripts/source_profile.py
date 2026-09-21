#!/usr/bin/env python3
"""The deployment's source profiles: what one technology's records mean, in one versioned place.

A profile says where each required input of Detection & Analysis §1.1 lives on this source's
records, what the source's own words mean, where every field of a record lands on the Case, and
which of the framework's questions the source answers. Its schema is
``capabilities/source_profile.schema.json`` and CI validates every profile against it.

What this module is for: the scripts of the method skills know no source. They take a profile —
named by the deployment's capability binding, exactly as the binding names its data sources — and
read the two views below out of it. There is one file per technology, so a field renamed by the
vendor is one edit, and nothing here has a second copy to drift from.

The shipped profile is the default. A deployment may lay a **local override** over it — the binding
names it under ``source_profile_overrides`` — so that a field the vendor renames is fixed where the
tenant is, in minutes, and the fix to the shipped profile follows at its own pace. An override holds
only what differs, so everything else keeps following the shipped profile, and a profile read through
one says so: ``record`` gives what the run writes on its ledger and on the Case's provenance.

  source_profile.py --bindings zerosoc.capabilities.json [--source ID] [--json]   the record
  source_profile.py --bindings zerosoc.capabilities.json --effective              the profile as read

Standard library only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys

# what an override may hold: every block of a profile but the one that says which source it is
BLOCKS = ("fields", "vocabularies", "alert_types", "case_map", "extension", "capability_coverage", "queries")
# a list of a profile whose entries have an identity: an override's entry replaces the shipped entry
# of the same identity. The rules are tried in order and have none: the deployment's are tried first
# and the shipped ones are left as they are. Any other list is replaced whole.
KEYED = {("case_map",): "path"}
FIRST = {("alert_types", "rules"): "alert_type"}


def _named_by(bindings_path):
    """What the binding names: its profiles and its local overrides, by source. An override named
    for a source the binding has no profile for is a mistake, and is refused."""
    with open(bindings_path, encoding="utf-8") as handle:
        binding = json.load(handle)
    profiles, overrides = binding.get("source_profiles") or {}, binding.get("source_profile_overrides") or {}
    orphans = sorted(set(overrides) - set(profiles))
    if orphans:
        raise ValueError(f"{os.path.basename(bindings_path)} overrides {', '.join(map(repr, orphans))}, "
                         "which it names no source profile for")
    return profiles, overrides


def resolved(bindings_path, source=None):
    """What the binding names for one source: the shipped profile and the local override, as paths
    beside the binding file.

    ``source_profiles`` maps a source identifier to a file, named from the tool skill that holds it
    (``_found`` says where it is looked for). With one profile and no source asked
    for, that profile is the deployment's; with several, the caller names which. A deployment that
    names none has no profile, which is a visibility gap and not an error. The override is None
    where the deployment names none, which is the default.
    """
    profiles, overrides = _named_by(bindings_path)
    if not profiles:
        return None, None
    if source is None:
        if len(profiles) > 1:
            raise ValueError(
                f"{os.path.basename(bindings_path)} names {len(profiles)} source profiles "
                f"({', '.join(sorted(profiles))}): say which one with --source"
            )
        source = next(iter(profiles))
    if source not in profiles:
        raise ValueError(f"no source profile named {source!r} in {os.path.basename(bindings_path)}")
    beside = os.path.dirname(os.path.abspath(bindings_path))
    return (_found(profiles[source], beside, os.path.basename(bindings_path)),
            os.path.join(beside, overrides[source]) if source in overrides else None)


def _skills_folder():
    """The folder the skills are installed in, side by side: the one that holds the skill this
    script runs from, or the repository's own when it runs from the shared sources."""
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(here) == "scripts":
        return os.path.dirname(os.path.dirname(here))
    return os.path.join(os.path.dirname(os.path.dirname(here)), "skills")


def _found(named, beside, binding_name):
    """Where the profile the binding names is. A profile lives with the tool skill of its
    technology, so a binding names it from there — ``<tool skill>/source_profile.json`` — and it is
    looked for beside the binding first, where a deployment's own copy wins, and then beside the
    skills, where it was installed. The override is the deployment's own and is only ever beside
    the binding."""
    places = [os.path.join(beside, named), os.path.join(_skills_folder(), named)]
    for place in places:
        if os.path.exists(place):
            return place
    raise ValueError(f"{binding_name} names the source profile {named!r}, which is neither beside the "
                     f"binding ({places[0]}) nor beside the skills ({places[1]})")


def named(bindings_path, source=None):
    """The profile the binding names, as a path beside the binding file."""
    return resolved(bindings_path, source)[0]


def _said(local):
    """An override's value as it is laid over nothing: null says "not this key" at any depth."""
    if isinstance(local, dict):
        return {key: _said(value) for key, value in local.items() if value is not None}
    return copy.deepcopy(local)


def _laid_over(shipped, local, where=()):
    """``local`` over ``shipped``: objects key by key, null removing a key; a list of entries that
    have an identity entry by entry; anything else replaced."""
    if isinstance(shipped, dict) and isinstance(local, dict):
        out = dict(shipped)
        for key, value in local.items():
            if value is None:
                out.pop(key, None)
            else:
                out[key] = _laid_over(shipped.get(key), value, where + (key,))
        return out
    identity = KEYED.get(where)
    if identity and isinstance(shipped, list) and isinstance(local, list):
        nameless = [entry for entry in local if not isinstance(entry, dict) or identity not in entry]
        if nameless:
            raise ValueError(f"an entry of {'.'.join(where)} in the override has no {identity!r}, "
                             "so it cannot be told which shipped entry it replaces")
        replaced = {entry[identity]: entry for entry in local}
        kept = [replaced.pop(entry[identity], entry) for entry in shipped]
        return _said(kept + list(replaced.values()))
    if where in FIRST and isinstance(shipped, list) and isinstance(local, list):
        return _said(local) + shipped
    return _said(local)


def _paths(local, where=()):
    """What an override sets, as the paths a reader of the record can find in the profile."""
    if isinstance(local, dict):
        return [p for key, value in local.items() for p in _paths(value, where + (key,))]
    named = KEYED.get(where) or FIRST.get(where)
    if named and isinstance(local, list):
        return [f"{'.'.join(where)}[{entry.get(named) if isinstance(entry, dict) else entry}]" for entry in local]
    return [".".join(where)]


def overridden(profile, override_path):
    """The shipped ``profile`` with the local override at ``override_path`` laid over it.

    The override names the source it is for and the version of the shipped profile it was written
    against. One written for another source is refused; one the shipped profile has since moved
    past is still read — a tenant must not break on a pin bump — and is marked stale, because the
    fix it stood in for may have landed. It may not restate who the source is: that block is the
    shipped profile's, and the override's own record is written into it here.
    """
    with open(override_path, "rb") as handle:
        raw = handle.read()
    document = json.loads(raw.decode("utf-8"))
    source = profile["source"]
    name = os.path.basename(override_path)
    if document.get("overrides") != source["id"]:
        raise ValueError(f"{name} overrides {document.get('overrides')!r}, not {source['id']!r}")
    local = document.get("profile")
    if not isinstance(local, dict) or not local:
        raise ValueError(f"{name} has no \"profile\": the blocks that differ from the shipped profile")
    if "source" in local:
        raise ValueError(f"{name} restates the source block: an override changes what the records "
                         "mean, never which source they come from or the version of its profile")
    unknown = sorted(set(local) - set(BLOCKS))
    if unknown:
        # a block the profile does not have would be laid over nothing, recorded, and change nothing
        raise ValueError(f"{name} overrides {', '.join(map(repr, unknown))}: a profile has no such block "
                         f"(it has {', '.join(BLOCKS)})")
    if not str(document.get("reason") or "").strip() or not document.get("base_profile_version"):
        raise ValueError(f"{name} must state its \"reason\" and the \"base_profile_version\" it was "
                         "written against: both are recorded with every run read through it")
    effective = _laid_over(profile, local)
    paths = sorted(_paths(local))
    against = document.get("base_profile_version")
    effective["source"] = dict(source, override={
        "file": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "reason": str(document.get("reason") or ""),
        "base_profile_version": against,
        "stale": against != source["profile_version"],
        "paths": paths,
    })
    return effective


def load(path, override=None):
    """The profile at ``path`` — with the local override laid over it, where the deployment names
    one — and its title patterns compiled: a bad pattern fails here rather than at the first alert
    that meets it."""
    with open(path, encoding="utf-8") as handle:
        profile = json.load(handle)
    if override:
        profile = overridden(profile, override)
    for rule in (profile.get("alert_types") or {}).get("rules", []):
        for pattern in rule.get("title_patterns", []):
            re.compile(pattern)
    return profile


def alert_rules(profile):
    """The view the alert-type assignment reads: the rules, and the source's own field names."""
    block = profile.get("alert_types") or {}
    return {"fields": block.get("fields") or {}, "rules": block.get("rules") or []}


def telemetry_rows(profile):
    """Where a row of this source's telemetry belongs in OCSF: the shape of a query's answer.

    It is not a path on the source's record — the case_map describes the record — so it is
    declared here beside the rest of what the source means, and a reader of an answer keeps a
    column this table does not name under its own name rather than dropping it.
    """
    rows = (profile.get("fields") or {}).get("telemetry_rows") or {}
    return {
        "objects": {k: tuple(v) for k, v in (rows.get("objects") or {}).items()},
        "times": tuple(rows.get("times") or ()),
        "uids": tuple(rows.get("uids") or ()),
        "process_lineage": dict(rows.get("process_lineage") or {}),
    }


def detection_spec(profile):
    """The view the §1.1 assertions read: where each input lives, and what the source's words mean.

    ``fields`` names them on an alert and ``entity_fields`` on an evidence item, under the
    canonical names the evidence inventory prints. The analytic types say which OCSF analytic type
    a detection source is — one not listed is Other (99) — and the remediation states say what the
    source did to an entity and whether it completed; a state not listed is recorded as reported
    and never treated as neutralized.
    """
    fields = profile.get("fields") or {}
    vocabularies = profile.get("vocabularies") or {}
    return {
        "fields": fields.get("alert") or {},
        "entity_fields": fields.get("evidence") or {},
        "analytic_types": vocabularies.get("analytic_types") or {},
        "remediation_states": vocabularies.get("remediation_states") or {},
    }


def record(profile):
    """What a run writes down about the profile it read its source through.

    ``source_profile`` goes on the ledger. ``product`` is the source's entry in the Case's
    ``provenance.products``, an OCSF product whose ``feature`` is the profile: its version is the
    shipped profile's, and under a local override it carries the override's digest, so two Cases
    read through different overrides never look alike.
    """
    source = profile["source"]
    override = source.get("override")
    held = {"source": source["id"], "profile_version": source["profile_version"]}
    feature = {"name": "source profile", "version": source["profile_version"]}
    if override:
        held["override"] = dict(override)
        feature["version"] += f"+local.{override['sha256'][:12]}"
        feature["uid"] = f"sha256:{override['sha256']}"
    product = {"name": source["product"], "vendor_name": source["vendor"], "uid": source["id"], "feature": feature}
    if source.get("api_version"):
        product["version"] = source["api_version"]
    return {"source_profile": held, "product": product}


def notes(profile):
    """What a reader of the run should be told about the profile, one line each."""
    override = (profile.get("source") or {}).get("override")
    if not override:
        return []
    source = profile["source"]
    out = [f"{source['id']}: read through the local override {override['file']} "
           f"({len(override['paths'])} path(s): {', '.join(override['paths'])}) — {override['reason']}"]
    if override["stale"]:
        out.append(f"{source['id']}: the override was written against the shipped profile of "
                   f"{override['base_profile_version']} and the shipped profile is now {source['profile_version']}: "
                   "check whether the fix it stands in for has landed, and drop the override if it has")
    return out


def add_arguments(ap):
    """The arguments by which a script is told which profile to read."""
    ap.add_argument("--profile", help="the source profile of the technology these records come from")
    ap.add_argument("--bindings", help="capability binding whose source_profiles names the profile, next to it")
    ap.add_argument("--source", help="which profile, where the binding names more than one")
    ap.add_argument("--override", help="with --profile: a local override to lay over it (a binding names its own)")


def from_arguments(ap, a):
    """The profile the arguments name, as the deployment reads it. A profile that is not there, or
    cannot be read, ends the script with what is wrong and where, not with a traceback."""
    try:
        path, override = ((a.profile, a.override) if a.profile
                          else resolved(a.bindings, a.source) if a.bindings else (None, None))
        if not path:
            ap.error("--profile, or --bindings with a source_profiles entry, is required")
        profile = load(path, override)
    except (OSError, ValueError, re.error) as exc:
        ap.error(f"the source profile cannot be read: {exc}")
    if not isinstance(profile.get("source"), dict) or "id" not in profile["source"]:
        ap.error(f"{path} is not a source profile: it has no source block "
                 "(capabilities/source_profile.schema.json declares one)")
    for note in notes(profile):
        print(note, file=sys.stderr)
    return profile


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--effective", action="store_true",
                    help="print the profile as the deployment reads it, the override laid over it: "
                         "what a host that reads the profile itself must be given")
    a = ap.parse_args(argv)
    profile = from_arguments(ap, a)
    if a.effective:
        print(json.dumps(profile, indent=2, ensure_ascii=False))
        return 0
    held = record(profile)
    if a.json:
        print(json.dumps(held, indent=2, ensure_ascii=False))
        return 0
    feature = held["product"]["feature"]
    print(f"{held['source_profile']['source']}\tsource profile {feature['version']}"
          + ("" if "override" in held["source_profile"] else "\tas shipped"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
