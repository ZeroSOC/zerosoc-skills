"""The source profile: valid against its schema, and complete against sample documents.

The documents under fixtures/documents are **samples**: every key and every enum word is one the
source sends, and every value is invented. The case_map was measured against real records of a
tenant — 155 distinct paths, all of them in the map and none in the map that the records lack —
and those records are not published, because a tenant's incidents name its people and its
addresses. The samples carry every path of the map, so the guard below runs over the whole shape
of a record, and a real record dropped beside them is checked the same way.

The point of the case_map is that it is executable. Over one recorded incident, 15 of 49 distinct
keys of this source's records were read by nothing here — some read elsewhere, some deliberately
dropped, some simply unexamined, and nothing told the three apart. A key that is neither mapped nor
ignored with a reason now fails the build, so a field the vendor adds tomorrow arrives with a
noise instead of in silence.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_profiles  # noqa: E402

DOCUMENTS = ROOT / "tests" / "fixtures" / "documents"
PROFILES = sorted(ROOT.glob("skills/*/source_profile.json"))


def paths_of(node: Any, prefix: str = "", found: set[str] | None = None) -> set[str]:
    """Every path of a record, as the case_map writes them: dotted, [] for a step into a list."""
    found = set() if found is None else found
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{prefix}.{key}" if prefix else key
            found.add(here)
            paths_of(value, here, found)
    elif isinstance(node, list):
        for value in node:
            paths_of(value, prefix + "[]", found)
    return found


class SourceProfile(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(PROFILES, "no source profile to check")
        self.schema = json.loads((ROOT / "capabilities" / "source_profile.schema.json").read_text())
        self.profiles = {p: json.loads(p.read_text()) for p in PROFILES}

    def test_every_profile_validates_against_the_schema(self) -> None:
        for path, profile in self.profiles.items():
            with self.subTest(profile=path.name):
                self.assertEqual(check_profiles.validate(profile, self.schema, self.schema, "p"), [])

    def test_every_profile_agrees_with_itself(self) -> None:
        for path, profile in self.profiles.items():
            with self.subTest(profile=path.name):
                self.assertEqual(check_profiles.coherent(profile, "p"), [])

    def test_every_key_of_a_recorded_document_is_mapped_or_ignored(self) -> None:
        profile = json.loads((ROOT / "skills" / "zerosoc-defender-xdr" / "source_profile.json").read_text())
        known = {entry["path"] for entry in profile["case_map"]}
        documents = sorted(DOCUMENTS.glob("*.json"))
        self.assertTrue(documents, "no sample document to check the profile against")

        unexamined: dict[str, str] = {}
        for document in documents:
            for path in paths_of(json.loads(document.read_text())):
                if path not in known:
                    unexamined.setdefault(path, document.name)

        self.assertEqual(
            unexamined,
            {},
            "keys of the source's records that the profile neither maps nor ignores — "
            "add each to case_map with where it lands, or with the reason nothing reads it",
        )

    def test_every_mapped_path_is_shown_by_a_sample_document(self) -> None:
        """The other direction: a path enters the map only with a document that carries it, so the
        map cannot grow by a path nobody can show, and the documents stay the whole shape of a record."""
        profile = json.loads((ROOT / "skills" / "zerosoc-defender-xdr" / "source_profile.json").read_text())
        shown: set[str] = set()
        for document in DOCUMENTS.glob("*.json"):
            shown |= paths_of(json.loads(document.read_text()))
        self.assertEqual(sorted({entry["path"] for entry in profile["case_map"]} - shown), [])

    def test_every_data_source_a_profile_answers_is_one_a_playbook_asks_for(self) -> None:
        """The names join a profile to a playbook's required_data_sources, so a name no playbook
        writes joins nothing: it has to be the framework's own, letter for letter."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("select_playbook", ROOT / "tools" / "shared" / "select_playbook.py")
        selector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(selector)
        asked: set[str] = set()
        for skill in ("zerosoc-triage", "zerosoc-investigation", "zerosoc-response"):
            for book in selector.load_playbooks(str(ROOT / "skills" / skill / "references" / "framework")):
                required = book["fields"].get("required_data_sources") or []
                asked.update([required] if isinstance(required, str) else required)
        self.assertTrue(asked, "no playbook at this pin states a required data source")
        for path, profile in self.profiles.items():
            with self.subTest(profile=path.name):
                named = set(profile["capability_coverage"].get("data_sources") or {})
                self.assertTrue(named, "a profile that answers no data source joins no playbook")
                self.assertEqual(sorted(named - asked), [])

    def test_an_added_field_is_caught(self) -> None:
        """The guard itself, run: a document with a key the profile does not name fails the same
        comparison the test above passes, rather than a comparison written for this test."""
        profile = json.loads((ROOT / "skills" / "zerosoc-defender-xdr" / "source_profile.json").read_text())
        known = {entry["path"] for entry in profile["case_map"]}
        document = json.loads((DOCUMENTS / "incident_ransomware.json").read_text())
        document["alerts"][0]["newVendorFieldNobodyExamined"] = "surprise"

        unexamined = {path for path in paths_of(document) if path not in known}

        self.assertEqual(unexamined, {"alerts[].newVendorFieldNobodyExamined"})

        del document["alerts"][0]["newVendorFieldNobodyExamined"]
        self.assertEqual({p for p in paths_of(document) if p not in known}, set())

    def test_an_ignored_path_states_a_reason(self) -> None:
        for path, profile in self.profiles.items():
            for entry in profile["case_map"]:
                if "case" not in entry:
                    with self.subTest(profile=path.name, path=entry["path"]):
                        self.assertGreater(len(entry.get("ignored", "")), 20, entry["path"])


class Coherence(unittest.TestCase):
    """The shipped profile, broken one way at a time: each break has to be said, not passed."""

    def setUp(self) -> None:
        self.profile = json.loads((ROOT / "skills" / "zerosoc-defender-xdr" / "source_profile.json").read_text())

    def problems(self) -> str:
        return "\n".join(check_profiles.coherent(self.profile, "p"))

    def test_a_nested_field_path_is_checked_whole_not_by_its_first_step(self) -> None:
        self.profile["case_map"].append({"path": "alerts[].evidence[].userAccount", "case": "observables[]"})
        self.profile["fields"]["evidence"]["upn"] = "userAccount.userPrincipalNam"
        self.assertIn("userAccount.userPrincipalNam", self.problems())

    def test_the_alert_type_fields_are_paths_of_the_record_too(self) -> None:
        self.profile["alert_types"]["fields"]["detector_id"] = "detectorIdX"
        self.assertIn("detectorIdX", self.problems())

    def test_a_path_is_mapped_once(self) -> None:
        self.profile["case_map"].append({"path": "id", "ignored": "a second entry that contradicts the first"})
        self.assertIn("'id' is in the case_map 2 times", self.problems())

    def test_a_path_is_mapped_or_ignored_never_both(self) -> None:
        self.profile["case_map"][0]["ignored"] = "and yet it is mapped, so which is it"
        self.assertIn("both mapped and ignored", self.problems())

    def test_a_rule_that_can_match_nothing_or_everything_is_said(self) -> None:
        rules = self.profile["alert_types"]["rules"]
        rules[0]["detector_ids"], rules[0]["title_patterns"] = [], []
        rules[1]["title_patterns"] = [""]
        found = self.problems()
        self.assertIn("matches nothing", found)
        self.assertIn("matches every title", found)

    def test_a_profile_missing_a_block_is_reported_not_crashed_on(self) -> None:
        import contextlib, io, tempfile
        del self.profile["case_map"]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(self.profile, handle)
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = check_profiles.main([handle.name])
        self.assertEqual(code, 1)
        self.assertIn("missing required 'case_map'", err.getvalue())

    def test_a_schema_keyword_the_validator_does_not_know_is_an_error(self) -> None:
        schema = {"type": "object", "properties": {"deep": {"type": "array", "items": {"type": "string", "pattern": "^x"}}}}
        self.assertEqual(len(check_profiles.supported(schema)), 1)
        self.assertIn("'pattern'", check_profiles.supported(schema)[0])
        self.assertTrue(check_profiles.supported({"type": "number"}), "a type the validator cannot check")


if __name__ == "__main__":
    unittest.main()
