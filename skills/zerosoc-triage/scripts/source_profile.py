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

  source_profile.py --bindings zerosoc.capabilities.json [--source ID] [--json]

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

# the lists of a profile whose entries have an identity: an override's entry replaces the shipped
# entry of the same identity, and any other list is replaced whole
KEYED = {("case_map",): "path", ("alert_types", "rules"): "alert_type"}


def named(bindings_path, source=None):
    """The profile the binding names, as a path beside the binding file.

    ``source_profiles`` maps a source identifier to a file. With one profile and no source asked
    for, that profile is the deployment's; with several, the caller names which. A deployment that
    names none has no profile, which is a visibility gap and not an error.
    """
    with open(bindings_path, encoding="utf-8") as handle:
        binding = json.load(handle)
    profiles = binding.get("source_profiles") or {}
    if not profiles:
        return None
    if source is None:
        if len(profiles) > 1:
            raise ValueError(
                f"{os.path.basename(bindings_path)} names {len(profiles)} source profiles "
                f"({', '.join(sorted(profiles))}): say which one with --source"
            )
        source = next(iter(profiles))
    if source not in profiles:
        raise ValueError(f"no source profile named {source!r} in {os.path.basename(bindings_path)}")
    return os.path.join(os.path.dirname(os.path.abspath(bindings_path)), profiles[source])


def resolved(bindings_path, source=None):
    """What the binding names for one source: the shipped profile and the local override, as paths
    beside the binding file. The override is None where the deployment names none, which is the
    default; one named for a source the binding has no profile for is a mistake, and is refused."""
    path = named(bindings_path, source)
    with open(bindings_path, encoding="utf-8") as handle:
        binding = json.load(handle)
    profiles, overrides = binding.get("source_profiles") or {}, binding.get("source_profile_overrides") or {}
    orphans = sorted(set(overrides) - set(profiles))
    if orphans:
        raise ValueError(f"{os.path.basename(bindings_path)} overrides {', '.join(map(repr, orphans))}, "
                         "which it names no source profile for")
    if path is None:
        return None, None
    source = source if source is not None else next(iter(profiles))
    if source not in overrides:
        return path, None
    return path, os.path.join(os.path.dirname(os.path.abspath(bindings_path)), overrides[source])


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
        added = list(replaced.values())
        # a rule is tried in order, so the deployment's own is tried first; a mapped path has no order
        return added + kept if where == ("alert_types", "rules") else kept + added
    return copy.deepcopy(local)


def _paths(local, where=()):
    """What an override sets, as the paths a reader of the record can find in the profile."""
    if isinstance(local, dict):
        return [p for key, value in local.items() for p in _paths(value, where + (key,))]
    if where in KEYED and isinstance(local, list):
        return [f"{'.'.join(where)}[{entry[KEYED[where]]}]" for entry in local]
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
    local = document.get("profile") or {}
    if "source" in local:
        raise ValueError(f"{name} restates the source block: an override changes what the records "
                         "mean, never which source they come from or the version of its profile")
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


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bindings", required=True, help="the deployment's capability binding")
    ap.add_argument("--source", help="which profile, where the binding names more than one")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    path, override = resolved(a.bindings, a.source)
    if not path:
        print("the binding names no source profile: a visibility gap, and nothing to record", file=sys.stderr)
        return 3
    profile = load(path, override)
    held = record(profile)
    for note in notes(profile):
        print(note, file=sys.stderr)
    if a.json:
        print(json.dumps(held, indent=2, ensure_ascii=False))
        return 0
    feature = held["product"]["feature"]
    print(f"{held['source_profile']['source']}\tsource profile {feature['version']}"
          + ("" if override else "\tas shipped"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
