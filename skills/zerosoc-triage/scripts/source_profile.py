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

Standard library only.
"""
from __future__ import annotations

import json
import os
import re


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


def load(path):
    """The profile at ``path``, with its title patterns compiled: a bad pattern fails here rather
    than at the first alert that meets it."""
    with open(path, encoding="utf-8") as handle:
        profile = json.load(handle)
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
