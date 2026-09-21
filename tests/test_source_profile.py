"""The source profile: valid against its schema, and complete against recorded documents.

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
        self.assertTrue(documents, "no recorded document to check the profile against")

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


if __name__ == "__main__":
    unittest.main()
