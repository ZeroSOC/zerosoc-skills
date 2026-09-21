"""A deployment may lay a local override over the shipped source profile.

A field the vendor renames is otherwise fixed by a pull request here, a pin bump and a release of
whatever hosts the skills, while the tenant stays broken. The binding names a local override; it
holds only what differs, so the rest of the profile keeps following the shipped one; and the run
says on its record that it read the source through one.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_profiles  # noqa: E402


def load(rel: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


profiles = load("tools/shared/source_profile.py", "source_profile")
metadata = load("tools/shared/alert_metadata.py", "alert_metadata")
alert_types = load("tools/shared/alert_types.py", "alert_types")
checker = load("tools/check_run.py", "check_run")

SHIPPED = ROOT / "skills" / "zerosoc-defender-xdr" / "source_profile.json"
VERSION = json.loads(SHIPPED.read_text())["source"]["profile_version"]

# the vendor renamed the remediation state of an evidence item: the whole fix, and nothing else
RENAME = {
    "fields": {"evidence": {"remediation_status": "remediationState"}},
    "case_map": [{"path": "alerts[].evidence[].remediationState",
                  "case": "finding_info_list[].types[]"}],
}


class Deployment:
    """A binding in a directory of its own, as a deployment holds it."""

    def __init__(self, partial: dict[str, Any] | None = None, **envelope: Any) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.binding = self.base / "zerosoc.capabilities.json"
        binding: dict[str, Any] = {"capabilities": {}, "data_sources": {},
                                   "source_profiles": {"defender-xdr": str(SHIPPED)}}
        self.override = self.base / "defender-xdr.override.json"
        if partial is not None:
            document = {"overrides": "defender-xdr", "base_profile_version": VERSION,
                        "reason": "the vendor renamed remediationStatus; the upstream fix is pending",
                        "profile": partial}
            document.update(envelope)
            self.override.write_text(json.dumps(document))
            binding["source_profile_overrides"] = {"defender-xdr": self.override.name}
        self.binding.write_text(json.dumps(binding))

    def profile(self) -> dict[str, Any]:
        return profiles.load(*profiles.resolved(str(self.binding)))


class LocalOverride(unittest.TestCase):
    def test_the_shipped_profile_is_the_default(self) -> None:
        deployment = Deployment()
        self.assertEqual(deployment.profile(), json.loads(SHIPPED.read_text()))
        record = profiles.record(deployment.profile())
        self.assertEqual(record["source_profile"], {"source": "defender-xdr", "profile_version": VERSION})
        self.assertEqual(record["product"]["feature"], {"name": "source profile", "version": VERSION})

    def test_a_renamed_field_is_read_again_without_a_release(self) -> None:
        rows = [{"type": "file", "name": "x.exe", "alert_ids": ["A1"], "remediationState": "prevented"}]
        shipped = profiles.load(str(SHIPPED))
        self.assertEqual(metadata.remediation(rows, shipped), [], "the shipped profile does not know the new name")

        read = metadata.remediation(rows, Deployment(RENAME).profile())

        self.assertEqual([(r["entity"], r["state"], r["neutralized"]) for r in read], [("x.exe", "prevented", True)])

    def test_the_override_holds_only_what_differs(self) -> None:
        shipped, effective = json.loads(SHIPPED.read_text()), Deployment(RENAME).profile()
        self.assertEqual(effective["vocabularies"], shipped["vocabularies"])
        self.assertEqual(effective["fields"]["evidence"]["verdict"], shipped["fields"]["evidence"]["verdict"])
        self.assertEqual(len(effective["case_map"]), len(shipped["case_map"]) + 1)

    def test_a_case_map_entry_replaces_the_shipped_one_for_the_same_path(self) -> None:
        ignored = {"case_map": [{"path": "alerts[].evidence[].remediationStatus",
                                 "ignored": "this tenant's licence never fills it, so nothing reads it here"}]}
        shipped, effective = json.loads(SHIPPED.read_text()), Deployment(ignored).profile()
        self.assertEqual(len(effective["case_map"]), len(shipped["case_map"]))
        entry = next(e for e in effective["case_map"] if e["path"] == "alerts[].evidence[].remediationStatus")
        self.assertNotIn("case", entry)

    def test_a_local_alert_type_rule_is_tried_before_the_shipped_ones(self) -> None:
        shipped = alert_types.load_map(str(SHIPPED))
        taken = shipped["rules"][0]
        local = {"alert_types": {"rules": [{"alert_type": "Policy violation", "domain": "Endpoint",
                                             "detector_ids": list(taken.get("detector_ids", [])),
                                             "title_patterns": [".*"]}]}}
        deployment = Deployment(local)
        rules = alert_types.load_map(*profiles.resolved(str(deployment.binding)))
        built = alert_types.classify({"id": "A1", "title": "anything the shipped rules also match"}, rules)
        self.assertEqual(built["type"], "Policy violation")
        self.assertEqual(len(rules["rules"]), len(shipped["rules"]) + 1)

    def test_the_effective_profile_is_held_to_the_same_schema_and_coherence(self) -> None:
        schema = json.loads((ROOT / "capabilities" / "source_profile.schema.json").read_text())
        effective = Deployment(RENAME).profile()
        self.assertEqual(check_profiles.validate(effective, schema, schema, "p"), [])
        self.assertEqual(check_profiles.coherent(effective, "p"), [])

    def test_a_rename_the_case_map_does_not_follow_fails_the_check_of_the_binding(self) -> None:
        deployment = Deployment({"fields": RENAME["fields"]})
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = check_profiles.main(["--bindings", str(deployment.binding)])
        self.assertEqual(code, 1)
        self.assertIn("remediationState", err.getvalue())

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check_profiles.main(["--bindings", str(Deployment(RENAME).binding)]), 0)

    def test_the_override_is_on_the_record(self) -> None:
        deployment = Deployment(RENAME)
        digest = hashlib.sha256(deployment.override.read_bytes()).hexdigest()

        record = profiles.record(deployment.profile())

        held = record["source_profile"]["override"]
        self.assertEqual(held["sha256"], digest)
        self.assertEqual(held["file"], deployment.override.name)
        self.assertIn("renamed", held["reason"])
        self.assertEqual(held["paths"], ["case_map[alerts[].evidence[].remediationState]",
                                         "fields.evidence.remediation_status"])
        self.assertFalse(held["stale"])
        self.assertEqual(record["product"]["feature"],
                         {"name": "source profile", "version": f"{VERSION}+local.{digest[:12]}",
                          "uid": f"sha256:{digest}"})
        self.assertEqual(record["product"]["name"], "Microsoft Defender XDR")

    def test_an_override_the_shipped_profile_has_moved_past_is_flagged_and_still_read(self) -> None:
        deployment = Deployment(RENAME, base_profile_version="2026-01-01")
        record = profiles.record(deployment.profile())
        self.assertTrue(record["source_profile"]["override"]["stale"])
        self.assertTrue(any("2026-01-01" in note for note in profiles.notes(deployment.profile())))

    def test_an_override_written_for_another_source_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "another-source"):
            Deployment(RENAME, overrides="another-source").profile()

    def test_an_override_may_not_restate_who_the_source_is(self) -> None:
        with self.assertRaisesRegex(ValueError, "source"):
            Deployment({"source": {"profile_version": "2030-01-01"}}).profile()

    def test_an_override_for_a_source_the_binding_does_not_name_is_refused(self) -> None:
        deployment = Deployment(RENAME)
        binding = json.loads(deployment.binding.read_text())
        binding["source_profile_overrides"] = {"no-such-source": deployment.override.name}
        deployment.binding.write_text(json.dumps(binding))
        with self.assertRaisesRegex(ValueError, "no-such-source"):
            profiles.resolved(str(deployment.binding))

    def test_a_shipped_profile_never_carries_an_override(self) -> None:
        effective = Deployment(RENAME).profile()
        self.assertIn("override", effective["source"])
        self.assertTrue(check_profiles.shipped(effective, "p"))
        self.assertEqual(check_profiles.shipped(json.loads(SHIPPED.read_text()), "p"), [])


class TheRunRecordsIt(unittest.TestCase):
    """The acceptance harness: a run that read its source through an override says so."""

    def run_dir(self, recorded: dict[str, Any] | None) -> str:
        deployment = Deployment(RENAME)
        ledger: dict[str, Any] = {"case_uid": "CASE-1", "severity": "High"}
        if recorded is not None:
            ledger["source_profile"] = recorded
        (deployment.base / "ledger.triage.json").write_text(json.dumps(ledger))
        self.deployment = deployment
        return str(deployment.base)

    def check(self, run: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = checker.main_for_test(run)
        return code, out.getvalue()

    def test_an_override_the_ledger_does_not_record_fails_the_run(self) -> None:
        code, out = self.check(self.run_dir(None))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  triage: the source profile the run read is on the ledger", out)

    def test_the_recorded_override_is_the_one_the_binding_names(self) -> None:
        run = self.run_dir(None)
        record = profiles.record(self.deployment.profile())["source_profile"]
        (self.deployment.base / "ledger.triage.json").write_text(
            json.dumps({"case_uid": "CASE-1", "severity": "High", "source_profile": record}))
        code, out = self.check(run)
        self.assertIn("ok    triage: the source profile the run read is on the ledger", out)

        record["override"]["sha256"] = "0" * 64
        (self.deployment.base / "ledger.triage.json").write_text(
            json.dumps({"case_uid": "CASE-1", "severity": "High", "source_profile": record}))
        code, out = self.check(run)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  triage: the source profile the run read is on the ledger", out)


class CommandLine(unittest.TestCase):
    def test_the_record_is_printed_for_the_ledger_and_the_case(self) -> None:
        deployment = Deployment(RENAME)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = profiles.main(["--bindings", str(deployment.binding), "--json"])
        self.assertEqual(code, 0)
        printed = json.loads(out.getvalue())
        self.assertEqual(printed, profiles.record(deployment.profile()))


if __name__ == "__main__":
    unittest.main()
