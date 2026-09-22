"""The method surface: the structure of a Note, the Case Timeline and T0, the candidate categories
and the normative rule text live in the skills, so a rule the framework changes is a skills release
and nothing else."""
import importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod


selector = load("tools/shared/select_playbook.py", "select_playbook")
timeline = load("tools/shared/timeline.py", "timeline")
note_elements = load("tools/shared/note_elements.py", "note_elements")
FRAMEWORK = os.path.join(ROOT, "skills", "zerosoc-investigation", "references", "framework")
T = 1789397741000  # 2026-09-14T14:55:41Z in milliseconds: the toy times below are offsets from a real day


class TheMethodSurface(unittest.TestCase):
    """A rule the framework changes is a skills release, not a host patch: the structure of a Note,
    the Case Timeline and T0, the candidate categories and the normative rule text are all here."""

    def test_the_playbook_returns_its_candidate_categories_rather_than_printing_them(self):
        """A host scraping them out of the printed prose with its own regular expression is the
        framework's rule living in whoever scraped it last."""
        found = selector.candidate_categories(
            "Something.\n**Candidate Incident Categories:** IC-03 (Ransomware), IC-05\nmore text"
        )

        self.assertEqual(found, ["IC-03", "IC-05"])

    def test_candidate_categories_keep_the_playbook_order_and_do_not_repeat(self):
        found = selector.candidate_categories(
            "**Candidate Incident Category:** IC-05\n**Candidate Incident Categories:** IC-03, IC-05"
        )

        self.assertEqual(found, ["IC-05", "IC-03"], "the first is the one Investigation opens")

    def test_a_section_with_no_candidates_proposes_none(self):
        self.assertEqual(selector.candidate_categories("no labelled element here IC-03"), [])

    def test_the_timeline_flags_exactly_one_t0(self):
        built = timeline.build({
            "t0": T + 100, "now": T + 500,
            "entries": [
                {"time": T + 100, "kind": "detection", "desc": "ransomware behaviour"},
                {"time": T + 100, "kind": "detection", "desc": "the same activity, seen twice"},
                {"kind": "investigation", "desc": "Q1: what ran before it?"},
            ],
        })

        self.assertEqual([e["is_t0"] for e in built["entries"]], [True, False, False])
        self.assertEqual(built["t0_entry"], "ransomware behaviour")
        self.assertEqual(timeline.check(built), [])

    def test_an_entry_without_a_time_happens_when_this_gate_ran(self):
        built = timeline.build({"t0": None, "now": T + 500, "entries": [
            {"kind": "investigation", "desc": "Q1"}, {"kind": "handover", "desc": "a human"}]})

        self.assertEqual([e["time"] for e in built["entries"]], [T + 500, T + 500])
        self.assertEqual(built["unplaced"], [])

    def test_a_detection_with_no_time_cannot_be_placed_and_says_so(self):
        built = timeline.build({"t0": None, "now": T + 500, "entries": [
            {"kind": "detection", "desc": "an alert with no time at all"}]})

        self.assertEqual(built["entries"], [])
        self.assertIn("no time", timeline.check(built)[0])

    def test_a_t0_no_entry_carries_is_a_failure(self):
        built = timeline.build({"t0": T + 90, "now": T + 500, "entries": [
            {"time": T + 100, "kind": "detection", "desc": "ransomware behaviour"}]})

        self.assertTrue(any("no entry carries it" in f for f in timeline.check(built)))

    def test_an_entry_before_t0_is_a_failure(self):
        built = timeline.build({"t0": T + 100, "now": T + 500, "entries": [
            {"time": T + 90, "kind": "detection", "desc": "something earlier"},
            {"time": T + 100, "kind": "detection", "desc": "ransomware behaviour"}]})

        self.assertTrue(any("happens before T0" in f for f in timeline.check(built)))

    ELEMENTS_ROOT = os.path.join(ROOT, "skills", "zerosoc-triage", "references", "framework")

    def elements(self, kind):
        return note_elements.elements(kind, self.ELEMENTS_ROOT)

    def test_the_note_elements_are_read_from_the_framework_in_its_own_order(self):
        """The order and the words are the framework's: a copy here would need keeping in step
        with the document it copies, which is the drift the references exist to remove."""
        found = self.elements("triage")
        names = [e["element"] for e in found]

        self.assertEqual(names[0], "summary", "the account before the measures (§1.6)")
        self.assertEqual(names[-1], "provenance")
        self.assertIn("findings", names)
        self.assertIn("what happened and when", found[0]["renders"], "the framework's own words")
        self.assertIn("reclassification_pivots", [e["element"] for e in self.elements("investigation")])

    def test_a_missing_reference_tree_is_an_error_not_an_empty_list(self):
        with self.assertRaises(SystemExit):
            note_elements.elements("triage", os.path.join(ROOT, "nowhere"))

    def test_a_conformant_note_passes(self):
        self.assertEqual(note_elements.check(self.note(), root=self.ELEMENTS_ROOT)[0], [])

    def test_a_finding_with_a_side_and_no_confidence_fails(self):
        note = self.note()
        note["findings"][0]["tag"] = {"side": "malicious", "confidence_id": None}

        self.assertTrue(any("no confidence" in f for f in note_elements.check(note, root=self.ELEMENTS_ROOT)[0]))

    def test_a_finding_that_cites_no_event_fails(self):
        note = self.note()
        note["findings"][0]["event_refs"] = []

        self.assertTrue(any("cites no event" in f for f in note_elements.check(note, root=self.ELEMENTS_ROOT)[0]))

    def test_a_bare_technique_code_is_nothing_this_script_reports(self):
        """`ID (Name)` is guidance given to whoever writes the Note, not a property read back off
        it. The check reported a bare code as an advisory and reported nothing else, which made an
        executor answer for a spelling in a run whose Note was otherwise conformant."""
        note = self.note()
        note["findings"][0]["finding"] = "T1486 was observed"
        failures, advisories = note_elements.check(note, root=self.ELEMENTS_ROOT)

        self.assertEqual(failures, [])
        self.assertEqual(advisories, [])

    def test_context_that_carries_a_confidence_fails(self):
        note = self.note()
        note["findings"][0]["tag"] = {"side": "context", "confidence_id": 2}

        self.assertTrue(any("context carries a confidence" in f for f in note_elements.check(note, root=self.ELEMENTS_ROOT)[0]))

    def test_a_recommended_action_nobody_acted_on_is_not_a_failure(self):
        """§1.5: what a source recommends is indicative. A Note used to be refused until every
        published action was answered — on a source that publishes its procedure per alert, which
        is how a Case of three alerts produced a Note of sixty-seven findings."""
        note = self.note()
        note["detection_metadata"] = {"alerts": [{"id": "A1", "recommended_actions": [
            {"id": "RA1", "action": "Run a full scan", "disposition": None}]}]}

        self.assertEqual(note_elements.check(note, root=self.ELEMENTS_ROOT)[0], [])

    def test_a_recommendation_set_aside_with_a_reason_passes(self):
        note = self.note()
        note["detection_metadata"] = {"alerts": [{"id": "A1", "recommended_actions": [
            {"id": "RA1", "action": "Run a full scan", "disposition": "set_aside",
             "reason": "the device was reimaged before triage opened"}]}]}

        self.assertEqual(note_elements.check(note, root=self.ELEMENTS_ROOT)[0], [])

    def test_a_gap_that_names_no_check_fails(self):
        note = self.note()
        note["visibility_gaps"] = [{"data_source": "EDR", "check_prevented": "  "}]

        self.assertTrue(any("names no check" in f for f in note_elements.check(note, root=self.ELEMENTS_ROOT)[0]))

    def test_the_rule_text_a_host_composes_lives_in_the_skill(self):
        for skill, names in (("zerosoc-triage", ("checks", "note-prose")),
                             ("zerosoc-investigation", ("verify", "tag", "note-prose"))):
            for name in names:
                path = os.path.join(ROOT, "skills", skill, "rules", f"{name}.md")
                with self.subTest(rule=f"{skill}/{name}"):
                    self.assertTrue(os.path.exists(path), path)
                    text = open(path, encoding="utf-8").read()
                    self.assertIn("$language", text, "a host substitutes the deployment's language")

    def note(self):
        return {
            "kind": "triage",
            "classification": {"kind": "promote", "severity_id": 4, "confidence_id": 3},
            "summary": "a factual account",
            "rationale": {"rationale": "the coverage rule promotes it"},
            "provenance": {"case_uid": "4711"},
            "findings": [
                {"n": 1, "finding": "T1486 (Data Encrypted for Impact) was observed",
                 "tag": {"side": "malicious", "confidence_id": 3}, "event_refs": ["A1"]},
                {"n": 2, "finding": "the device belongs to finance",
                 "tag": {"side": "context", "confidence_id": None}, "event_refs": ["EVT-1"]},
            ],
        }


def ledger_note(**changes):
    """A Note as the skills' own ledgers hold it: findings with side, confidence and the events they
    rest on, the prose beside them. Nothing here is a shape only one caller produces."""
    note = {
        "kind": "triage",
        "classification": {"decision": "promote", "severity_id": 4, "confidence_id": 3},
        "summary": "A loader ran on ws-01 at 14:55 UTC and T1486 (Data Encrypted for Impact) followed.",
        "rationale": "No Benign finding covers DF-1, so the coverage rule promotes the Case.",
        "provenance": {"case_uid": "4711", "playbook": "04-Playbooks/01-Triage/endpoint.md"},
        "alerts": [{"id": "DF-1", "type": "Malware / loader execution", "entity": "ws-01", "confidence": "High"}],
        "detection_metadata": {"alerts": [{"id": "DF-1", "absent": [],
                                           "techniques": [{"id": "T1114.003", "rendered": "T1114.003 (Email Forwarding Rule)"}],
                                           "recommended_actions": []}]},
        "findings": [
            {"id": "F1", "desc": "Forwarding rule created: T1114.003 (Email Forwarding Rule)", "side": "Malicious",
             "confidence": "High", "event_refs": ["EVT-1"], "first_seen": "2026-09-14T14:55:41Z", "timeline": True},
            {"id": "F2", "desc": "the device belongs to finance", "side": None, "event_refs": ["CMDB-7"]},
        ],
    }
    note.update(changes)
    return note


class TheNoteCheck(unittest.TestCase):
    def failures(self, note, kind="triage"):
        return note_elements.check(note, kind, FRAMEWORK)[0]

    def advisories(self, note, kind="triage"):
        return note_elements.check(note, kind, FRAMEWORK)[1]

    def test_a_note_in_the_ledgers_own_shape_is_conformant(self):
        self.assertEqual(self.failures(ledger_note()), [])

    def test_a_filename_that_carries_a_technique_code_does_not_discard_the_case(self):
        """What refused a Case on a live incident: `T1055.011_x86.exe`, a file an Atomic Red Team
        test drops on disk, read as a citation by a presentation rule that failed the Note. Read as
        a citation it still is, and it is advice now: the Case keeps its account of itself."""
        note = ledger_note(summary="ws-01 executed T1055.011_x86.exe from the user's Downloads folder")

        self.assertEqual(self.failures(note), [])

    def test_however_a_note_writes_a_technique_code_it_is_conformant(self):
        for where, note in (("finding", ledger_note()), ("summary", ledger_note(summary="T1486 was seen on ws-01")),
                            ("rationale", ledger_note(rationale="T1114.003 stands uncovered"))):
            if where == "finding":
                note["findings"][0]["desc"] = "T1114.003 observed"
            with self.subTest(where=where):
                self.assertEqual(self.failures(note), [], where)
                self.assertEqual(self.advisories(note), [], where)

    def test_a_side_needs_a_confidence_the_framework_has(self):
        for confidence in (None, 0, "Unknown", "certain"):
            note = ledger_note()
            note["findings"][0]["confidence"] = confidence
            with self.subTest(confidence=confidence):
                self.assertTrue(any("no confidence" in f for f in self.failures(note)))

    def test_context_is_a_finding_with_no_side_and_carries_no_confidence(self):
        note = ledger_note()
        note["findings"][1]["confidence"] = "Medium"
        self.assertTrue(any("context carries a confidence" in f for f in self.failures(note)))

    def test_a_blank_event_reference_is_no_reference(self):
        note = ledger_note()
        note["findings"][0]["event_refs"] = ["  "]
        self.assertTrue(any("cites no event" in f for f in self.failures(note)))

    def test_a_required_element_that_is_blank_is_missing(self):
        self.assertTrue(any("Rationale" in f for f in self.failures(ledger_note(rationale="  "))))
        self.assertTrue(any("Rationale" in f for f in self.failures(ledger_note(rationale={"rationale": ""}))))

    def test_a_note_of_one_kind_is_not_checked_as_the_other(self):
        self.assertTrue(any("triage" in f and "investigation" in f
                            for f in self.failures(ledger_note(), kind="investigation")))

    def test_the_placeholder_of_the_playbook_selection_is_not_a_check(self):
        gap = {"data_source": "EDR", "check_prevented": "(state the check this source would have supported)"}
        self.assertTrue(any("names no check" in f for f in self.failures(ledger_note(visibility_gaps=[gap]))))

    def test_a_followed_recommendation_names_the_finding_it_produced(self):
        note = ledger_note()
        actions = note["detection_metadata"]["alerts"][0]["recommended_actions"]
        actions.append({"id": "RA1", "action": "Run a full scan", "disposition": "followed"})
        self.assertTrue(any("RA1" in f and "Finding it produced" in f for f in self.failures(note)))
        actions[0]["finding"] = "F1"
        self.assertEqual(self.failures(note), [])

    def test_alerts_render_what_their_detection_asserted(self):
        note = ledger_note()
        del note["detection_metadata"]
        self.assertTrue(any("what its detection asserted" in f for f in self.failures(note)))
        note = ledger_note()
        note["detection_metadata"]["alerts"][0]["techniques"][0]["rendered"] = "T1114.003"
        self.assertEqual(self.failures(note), [], "an unnamed technique is still what the detection asserted")
        note = ledger_note()
        note["detection_metadata"]["alerts"][0]["absent"] = ["threat name"]
        self.assertTrue(any("threat name" in f and "Visibility Gap" in f for f in self.failures(note)))

    def test_a_source_the_deployment_cannot_read_is_a_gap_and_not_a_broken_note(self):
        """A deployment that declares no source profile reads nothing of §1.1: there are no field
        names to read it under. The run records that as the visibility gap it is, and the Note that
        holds the gap is conformant — a source nobody can read is not a Note nobody may write."""
        note = ledger_note(visibility_gaps=[{
            "data_source": "alert metadata: the deployment declares no field names",
            "check_prevented": "everything every detection of this Case asserted: its techniques, "
                               "the threat it named, what detected it and what it already remediated",
        }])
        note["detection_metadata"] = {"alerts": []}

        self.assertEqual(self.failures(note), [])

    def test_an_assertion_the_source_supplied_is_still_rendered_or_it_is_a_failure(self):
        """The gap excuses what could not be read, never what was read and dropped."""
        note = ledger_note(visibility_gaps=[{"data_source": "EDR", "check_prevented": "the process lineage"}])
        note["detection_metadata"] = {"alerts": []}

        self.assertTrue(any("renders nothing of what its detection asserted" in f
                            for f in self.failures(note)))

    def test_the_findings_element_says_what_an_alert_finding_renders(self):
        """The disposition of a recommended action is no longer among them: what the executor ran
        renders as the Finding it produced, and what it did not run renders nowhere."""
        findings = next(e for e in note_elements.elements("triage", FRAMEWORK) if e["element"] == "findings")
        for words in ("ID (Name)", "remediation state", "recommended action the executor ran"):
            self.assertIn(words, findings["renders"])
        self.assertNotIn("disposition of the recommended actions", findings["renders"])

    def test_something_that_is_not_a_note_is_a_failure_and_not_a_traceback(self):
        for broken in ([], {"findings": "F1"}, ledger_note(findings=[{"id": "F1", "tag": "Malicious (High)"}])):
            with self.subTest(note=str(broken)[:40]):
                self.assertTrue(note_elements.check(broken, "triage", FRAMEWORK)[0])

    def test_malformed_detection_metadata_is_a_failure_and_never_a_traceback(self):
        for name, held in (("techniques", ["T1486 (Data Encrypted for Impact)"]), ("recommended_actions", "Run a scan"),
                           ("absent", 3), ("absent", "threat name")):
            note = ledger_note()
            note["detection_metadata"]["alerts"][0][name] = held
            with self.subTest(field=name, value=str(held)[:20]):
                self.assertIsInstance(self.failures(note), list)
        for whole in (["DF-1"], {"id": "DF-1"}, 3):
            note = ledger_note()
            note["detection_metadata"]["alerts"] = whole
            with self.subTest(alerts=str(whole)):
                self.assertTrue(self.failures(note))
        self.assertTrue(self.failures(ledger_note(visibility_gaps=5)))
        self.assertTrue(self.failures(ledger_note(visibility_gaps=["EDR was down"])))
        note = ledger_note()
        note["findings"][0]["event_refs"] = 12345
        self.assertEqual(self.failures(note), [], "an event identifier may be a number")
        one_per_letter = ledger_note()
        one_per_letter["detection_metadata"]["alerts"][0]["absent"] = "threat name"
        self.assertEqual(len([f for f in self.failures(one_per_letter) if "did not supply" in f]), 1)

    def test_an_investigation_ledger_holds_its_alerts_among_its_findings(self):
        note = ledger_note(kind="investigation", timeline=[{"id": "F1"}])
        del note["alerts"], note["detection_metadata"]
        note["findings"][0].update(alert_type="Malware / loader execution", entity="ws-01")
        self.assertTrue(any("what its detection asserted" in f for f in self.failures(note, "investigation")))

    def test_a_hunt_opened_case_with_no_alert_asserts_nothing(self):
        note = ledger_note()
        del note["alerts"], note["detection_metadata"]
        self.assertEqual(self.failures(note), [])

    def test_a_case_closed_on_its_alerts_alone_renders_them_as_its_findings(self):
        self.assertEqual(self.failures(ledger_note(findings=[])), [], "the Alerts are the Case's first Findings")
        empty = ledger_note(findings=[], alerts=[])
        del empty["detection_metadata"]
        self.assertTrue(any("Findings" in f for f in self.failures(empty)))

    def test_a_required_element_holds_something_a_reader_can_read(self):
        for held in (True, 5, "None."):
            note = ledger_note(kind="investigation", timeline=held)
            with self.subTest(timeline=held):
                self.assertTrue(any("Case Timeline" in f for f in self.failures(note, "investigation")))
        self.assertTrue(any("Summary" in f for f in self.failures(ledger_note(summary=5))))
        note = ledger_note()
        del note["findings"][0]["desc"]
        self.assertTrue(any("F1" in f and "says nothing" in f for f in self.failures(note)))

    def test_a_kind_the_framework_does_not_have_is_said(self):
        self.assertTrue(note_elements.check(ledger_note(kind="bogus"), None, FRAMEWORK)[0])

    def test_the_older_tag_shape_is_still_read(self):
        note = ledger_note(findings=[{"n": 1, "finding": "T1486 (Data Encrypted for Impact) was observed",
                                      "tag": {"side": "malicious", "confidence_id": 3}, "event_refs": ["A1"]}])
        self.assertEqual(self.failures(note), [])


class AFrameworkChangeIsASkillsReleaseAndNothingElse(unittest.TestCase):
    """The third acceptance item, shown on one change: the framework renames an element of the Note,
    adds one, and the check follows with no edit to any script."""

    def served(self, rewrite):
        root = tempfile.mkdtemp()
        method = os.path.join("03-Processes", "02-detection_and_analysis.md")
        os.makedirs(os.path.join(root, "03-Processes"))
        with open(os.path.join(FRAMEWORK, method), encoding="utf-8") as f:
            text = f.read()
        with open(os.path.join(root, method), "w", encoding="utf-8") as f:
            f.write(rewrite(text))
        return root

    def test_a_renamed_and_an_added_element_are_required_with_no_script_change(self):
        def rewrite(text):
            head, rest = text.split("### 1.6 Triage Note", 1)
            rest = rest.replace("7.  **Provenance** —", "7.  **Provenance and Custody** —", 1)
            rest = rest.replace("\n**Two former elements", "8.  **Lessons** — what this Case teaches the next one.\n\n**Two former elements", 1)
            return head + "### 1.6 Triage Note" + rest
        root = self.served(rewrite)
        names = [e["element"] for e in note_elements.elements("triage", root)]
        self.assertEqual(names[-2:], ["provenance_and_custody", "lessons"])
        failures = note_elements.check(ledger_note(), "triage", root)[0]
        self.assertTrue(any("Provenance and Custody" in f for f in failures))
        self.assertTrue(any("Lessons" in f for f in failures))
        note = ledger_note(provenance_and_custody={"case_uid": "4711"}, lessons="Tune the loader rule.")
        self.assertEqual(note_elements.check(note, "triage", root)[0], [])

    def test_an_element_the_script_cannot_read_stops_it_rather_than_vanishing(self):
        root = self.served(lambda text: text.replace("3.  **Rationale** —", "3.  **Rationale:**", 1))
        with self.assertRaises(SystemExit) as stopped:
            note_elements.elements("triage", root)
        self.assertIn("Rationale", str(stopped.exception))

    def test_prose_between_two_elements_does_not_end_the_list(self):
        def rewrite(text):
            return text.replace("    Each **Alert** Finding also renders", "Each **Alert** Finding also renders", 1)
        names = [e["element"] for e in note_elements.elements("triage", self.served(rewrite))]
        self.assertEqual(names[-1], "provenance", "a paragraph at the margin is still inside the list")

    def test_a_list_inside_an_element_is_not_a_list_of_elements(self):
        def rewrite(text):
            return text.replace("4.  **Rationale** —", "    1. **Alerts** — first\n    2. **Checks** — then\n4.  **Rationale** —", 1)
        names = [e["element"] for e in note_elements.elements("triage", self.served(rewrite))]
        self.assertNotIn("alerts", names)
        self.assertIn("rationale", names)

    def test_two_elements_one_field_or_a_name_with_no_field_stops_the_script(self):
        for change in (("7.  **Provenance** —", "7.  **Summary** —"), ("7.  **Provenance** —", "7.  **来歴** —"),
                       ("7.  **Provenance** —", "7.  **Findings!** —")):
            with self.subTest(renamed=change[1]), self.assertRaises(SystemExit):
                note_elements.elements("triage", self.served(lambda text, c=change: text.replace(c[0], c[1], 1)))

    def test_which_elements_may_be_empty_is_the_frameworks_and_is_pinned(self):
        def optional(kind):
            return sorted(e["element"] for e in note_elements.elements(kind, FRAMEWORK) if e["may_be_empty"])
        self.assertEqual(optional("triage"), ["timeline", "visibility_gaps"])
        self.assertEqual(optional("investigation"), ["reclassification_pivots", "visibility_gaps"])

    def test_none_quoted_about_something_else_does_not_make_an_element_optional(self):
        def rewrite(text):
            return text.replace("    Each **Alert** Finding also renders", "    An Alert with no technique renders \"None.\" there. Each **Alert** Finding also renders", 1)
        findings = next(e for e in note_elements.elements("triage", self.served(rewrite)) if e["element"] == "findings")
        self.assertFalse(findings["may_be_empty"])

    def test_every_element_of_both_notes_is_read_at_this_pin(self):
        self.assertEqual([e["element"] for e in note_elements.elements("triage", FRAMEWORK)],
                         ["summary", "classification", "rationale", "findings", "timeline",
                          "visibility_gaps", "provenance"])
        self.assertEqual([e["element"] for e in note_elements.elements("investigation", FRAMEWORK)],
                         ["summary", "classification", "rationale", "findings", "reclassification_pivots",
                          "timeline", "visibility_gaps", "provenance"])


class TheCaseTimeline(unittest.TestCase):
    def ledger(self, *findings, **more):
        return dict({"now": "2026-09-14T15:12:00Z", "findings": list(findings)}, **more)

    def finding(self, fid, first_seen, side="Malicious", **more):
        return dict({"id": fid, "desc": f"finding {fid}", "side": side, "confidence": "High" if side else None,
                     "first_seen": first_seen, "timeline": True, "event_refs": [f"EVT-{fid}"]}, **more)

    def test_t0_is_derived_from_the_earliest_malicious_finding(self):
        built = timeline.build(self.ledger(
            self.finding("F2", "2026-09-14T14:58:00Z"), self.finding("F1", "2026-09-14T14:55:41Z"),
            self.finding("F0", "2026-09-14T14:40:00Z", side=None)))
        self.assertEqual([e["id"] for e in built["entries"]], ["F0", "F1", "F2"])
        self.assertEqual([e["is_t0"] for e in built["entries"]], [False, True, False])
        self.assertEqual(built["t0_utc"], "2026-09-14T14:55:41Z")
        self.assertEqual(timeline.check(built), [], "context before T0 is part of the account, not a failure")

    def test_only_the_findings_flagged_for_the_narrative_are_entries(self):
        built = timeline.build(self.ledger(self.finding("F1", "2026-09-14T14:55:41Z"),
                                           self.finding("F2", "2026-09-14T14:56:00Z", timeline=False)))
        self.assertEqual([e["id"] for e in built["entries"]], ["F1"])

    def test_a_retracted_finding_moves_nothing(self):
        built = timeline.build(self.ledger(self.finding("F0", "2026-09-14T13:00:00Z", retracted=True),
                                           self.finding("F1", "2026-09-14T14:55:41Z")))
        self.assertEqual(built["t0_utc"], "2026-09-14T14:55:41Z")

    def test_the_earliest_malicious_finding_left_off_the_timeline_is_a_failure(self):
        built = timeline.build(self.ledger(self.finding("F1", "2026-09-14T14:55:41Z", timeline=False),
                                           self.finding("F2", "2026-09-14T14:58:00Z")))
        self.assertTrue(any("no entry carries it" in f for f in timeline.check(built)))

    def test_a_stated_t0_that_is_not_the_earliest_malicious_finding_is_a_failure(self):
        built = timeline.build(self.ledger(self.finding("F1", "2026-09-14T14:55:41Z"), t0="2026-09-14T14:58:00Z"))
        self.assertTrue(any("earliest Malicious" in f for f in timeline.check(built)))

    def test_the_same_instant_is_the_same_instant_however_it_is_written(self):
        built = timeline.build(self.ledger(self.finding("F1", "2026-09-14T16:55:41+02:00"),
                                           self.finding("F2", "2026-09-14T14:55:41.5000000Z"),
                                           t0="2026-09-14T14:55:41Z"))
        self.assertEqual(timeline.check(built), [])
        self.assertEqual([e["id"] for e in built["entries"]], ["F1", "F2"])
        self.assertEqual([e["is_t0"] for e in built["entries"]], [True, False])

    def test_epoch_milliseconds_and_iso_times_may_meet_in_one_timeline(self):
        built = timeline.build({"t0": 1789397741000, "now": 1789399500000, "entries": [
            {"time": "2026-09-14T14:55:41Z", "kind": "detection", "desc": "as the source wrote it"},
            {"time": 1789397741000 + 60000, "kind": "action", "desc": "host isolated"}]})
        self.assertEqual(timeline.check(built), [])
        self.assertEqual(built["entries"][0]["is_t0"], True)

    def test_a_time_nobody_can_read_is_a_failure_and_not_a_traceback(self):
        built = timeline.build(self.ledger(self.finding("F1", "yesterday, around three")))
        self.assertTrue(any("F1" in f for f in timeline.check(built)))
        self.assertTrue(timeline.check(timeline.build({"entries": "F1"})))

    def test_a_finding_is_placed_by_when_the_thing_happened_never_by_when_it_was_made(self):
        found = self.finding("F1", None, at="2026-09-14T15:03:10Z")
        built = timeline.build(self.ledger(found))
        self.assertEqual(built["entries"], [])
        self.assertTrue(any("first_seen" in f for f in timeline.check(built)))

    def test_t0_is_carried_by_a_malicious_entry_never_by_whatever_shares_its_instant(self):
        at = "2026-09-14T14:55:41Z"
        for label, other in (("benign", self.finding("B1", at, side="Benign")),
                             ("context", self.finding("C1", "2026-09-14T14:55:40.500Z", side=None)),
                             ("retracted", self.finding("R1", at, retracted=True))):
            built = timeline.build(self.ledger(other, self.finding("M1", at)))
            with self.subTest(sharing=label):
                self.assertEqual([e["id"] for e in built["entries"] if e["is_t0"]], ["M1"])
        handover = timeline.build(self.ledger(self.finding("M1", "2026-09-14T15:12:00Z"),
                                              entries=[{"kind": "handover", "desc": "a human takes it"}]))
        self.assertEqual([e.get("id") for e in handover["entries"] if e["is_t0"]], ["M1"])

    def test_a_benign_entry_at_t0_does_not_hide_that_the_malicious_one_is_off_the_timeline(self):
        at = "2026-09-14T14:55:41Z"
        built = timeline.build(self.ledger(self.finding("M1", at, timeline=False), self.finding("B1", at, side="Benign")))
        self.assertTrue(any("no entry carries it" in f for f in timeline.check(built)))

    def test_a_stated_t0_with_nothing_malicious_known_is_a_failure(self):
        built = timeline.build(self.ledger(self.finding("B1", "2026-09-14T14:55:41Z", side="Benign"), t0="2026-09-14T14:55:41Z"))
        self.assertTrue(any("nothing Malicious" in f for f in timeline.check(built)))

    def test_a_malicious_finding_within_the_same_second_but_before_a_stated_t0_is_said(self):
        built = timeline.build(self.ledger(self.finding("M1", "2026-09-14T14:55:40.100Z"), t0="2026-09-14T14:55:41Z"))
        self.assertTrue(any("happens before T0" in f for f in timeline.check(built)))
        same_second = timeline.build(self.ledger(self.finding("M1", "2026-09-14T14:55:41.900Z"), t0="2026-09-14T14:55:41Z"))
        self.assertEqual(timeline.check(same_second), [], "a T0 written to the second holds the whole of that second")

    def test_a_time_out_of_any_case_is_unreadable_and_seconds_are_not_milliseconds(self):
        for bad in (1789397741, 1e400, float("nan"), 10 ** 18, "9999-12-31T23:59:59-05:00", -5):
            built = timeline.build(self.ledger(self.finding("F1", bad)))
            with self.subTest(first_seen=str(bad)):
                self.assertTrue(any("F1" in f for f in timeline.check(built)))

    def test_what_is_not_a_finding_or_a_readable_now_is_said(self):
        built = timeline.build({"now": "soon", "findings": ["F1", 3]})
        found = " | ".join(timeline.check(built))
        self.assertIn("now", found)
        self.assertIn("findings", found)

    def test_it_is_t0_only_on_a_confirmed_incident(self):
        """Until the Malicious hypothesis is proven the anchor is the Case's start_time, which is
        not a T0 and anchors no metric."""
        open_case = timeline.build(self.ledger(self.finding("M1", "2026-09-14T14:55:41Z")))
        self.assertEqual((open_case["start_time_utc"], open_case["confirmed_incident"]), ("2026-09-14T14:55:41Z", False))
        confirmed = timeline.build(self.ledger(self.finding("M1", "2026-09-14T14:55:41Z"), recorded_verdict="True Positive"))
        self.assertTrue(confirmed["confirmed_incident"])

    def test_the_older_tag_shape_moves_t0_too(self):
        built = timeline.build(self.ledger({"n": 1, "finding": "ransomware behaviour", "tag": {"side": "malicious", "confidence_id": 3},
                                            "first_seen": "2026-09-14T14:55:41Z", "timeline": True}))
        self.assertEqual(built["t0_utc"], "2026-09-14T14:55:41Z")

    def test_an_anchor_with_nothing_to_say_does_not_crash(self):
        built = timeline.build({"t0": T, "entries": [{"time": T, "kind": "detection"}]})
        self.assertEqual(timeline.check(built), [])


class CandidateCategoriesOfRealPlaybooks(unittest.TestCase):
    TRIAGE = os.path.join(ROOT, "skills", "zerosoc-triage", "references", "framework")

    def sections(self):
        import re
        for book in selector.load_playbooks(self.TRIAGE):
            if not book["fields"].get("domain"):
                continue
            for heading in re.findall(r"^### (.+)$", book["body"], re.M):
                text = selector.section(book["body"], heading.strip(), 3)
                if text and "Candidate Incident Categor" in text:
                    yield book, heading.strip(), text

    def test_every_alert_type_section_of_every_pinned_playbook_proposes_its_categories(self):
        seen = 0
        for book, heading, text in self.sections():
            seen += 1
            with self.subTest(playbook=book["rel"], alert_type=heading):
                self.assertTrue(selector.candidate_categories(text))
        self.assertGreater(seen, 40, "the pinned triage playbooks state their candidates per alert type")

    def test_a_wrapped_or_bulleted_element_is_read_whole(self):
        wrapped = "- **Candidate Incident Category(ies):** IC-05 (Commodity Malware);\n  IC-03 (Ransomware) if it follows.\n- **Next:** x IC-09"
        self.assertEqual(selector.candidate_categories(wrapped), ["IC-05", "IC-03"])
        bulleted = "- **Candidate Incident Categories:**\n  - IC-06 (Identity)\n  - IC-01\n\n#### Checks\nIC-09"
        self.assertEqual(selector.candidate_categories(bulleted), ["IC-06", "IC-01"])

    def test_a_whole_playbook_proposes_no_first_category(self):
        """Without an alert type there is no "first": the categories are given per alert type."""
        ran = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "shared", "select_playbook.py"),
                              "--root", self.TRIAGE, "--domain", "Endpoint", "--json"], capture_output=True, text=True)
        result = json.loads(ran.stdout)
        self.assertEqual(result["candidate_incident_categories"], [])
        by_type = result["candidate_incident_categories_by_alert_type"]
        self.assertEqual(by_type["Credential dumping"][0], "IC-06")


class TheRuleText(unittest.TestCase):
    FILES = [os.path.join(ROOT, "skills", skill, "rules", f"{name}.md")
             for skill, names in (("zerosoc-triage", ("checks", "note-prose")),
                                  ("zerosoc-investigation", ("verify", "tag", "note-prose"))) for name in names]

    def test_the_rules_name_nothing_the_skills_do_not_define(self):
        for path in self.FILES:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for foreign in ("if_malicious", "if_benign", "`false_positive`", "`benign`", "the host", "a host"):
                with self.subTest(rule=os.path.relpath(path, ROOT), foreign=foreign):
                    self.assertNotIn(foreign, text)

    def test_the_one_placeholder_is_said_to_be_one(self):
        import re
        for path in self.FILES:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            with self.subTest(rule=os.path.relpath(path, ROOT)):
                self.assertEqual(set(re.findall(r"\$[a-z_]+", text)), {"$language"})
        for skill in ("zerosoc-triage", "zerosoc-investigation"):
            with open(os.path.join(ROOT, "skills", skill, "SKILL.md"), encoding="utf-8") as f:
                self.assertIn("$language", f.read(), f"{skill} says what the placeholder of its rules stands for")

    def test_the_skill_lint_reads_the_rules_too(self):
        checker = load("tools/check_skills.py", "check_skills")
        base = tempfile.mkdtemp()
        skill = os.path.join(base, "zerosoc-triage")
        shutil.copytree(os.path.join(ROOT, "skills", "zerosoc-triage"), skill,
                        ignore=shutil.ignore_patterns("references", "__pycache__"))
        with open(os.path.join(skill, "SKILL.md"), "a", encoding="utf-8") as f:
            f.write("\nSee [rules/no-such-rule.md](rules/no-such-rule.md).\n")
        with open(os.path.join(skill, "rules", "checks.md"), "a", encoding="utf-8") as f:
            f.write("\nSee [the method](../references/framework/03-Processes/NOPE.md) and [a glossary](glossary.md).\n")
        with open(os.path.join(skill, "rules", "glossary.md"), "w", encoding="utf-8") as f:
            f.write("# Words\n")
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            problems = "\n".join(checker.check_skill(skill))
        self.assertIn("no-such-rule", problems)
        self.assertIn("NOPE.md", problems, "a link in a rule file is followed from the rule file")
        self.assertNotIn("glossary.md is linked from nowhere", problems, "a rule linked from a rule is linked")


class FromTheCommandLine(unittest.TestCase):
    """As an executor runs them: on the ledger the decision rule ran on, exit code and all."""

    def run_script(self, name, *args, document=None):
        base = tempfile.mkdtemp()
        if document is not None:
            with open(os.path.join(base, "ledger.json"), "w", encoding="utf-8") as f:
                json.dump(document, f)
        script = os.path.join(ROOT, "skills", "zerosoc-investigation", "scripts", name)
        return subprocess.run([sys.executable, script, *args], cwd=base, capture_output=True, text=True)

    def investigation(self):
        note = ledger_note(kind="investigation", started_at="2026-09-14T15:00:00Z", severity="High",
                           incident_category="IC-02", now="2026-09-14T15:12:00Z")
        note["findings"][0]["at"] = "2026-09-14T15:03:10Z"
        return note

    def test_one_ledger_serves_the_rule_the_note_check_and_the_timeline(self):
        document = self.investigation()
        resolved = self.run_script("resolve.py", "ledger.json", "--now", "2026-09-14T15:12:00Z", "--json", document=document)
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        built = self.run_script("timeline.py", "ledger.json", "--json", document=document)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.assertEqual(json.loads(built.stdout)["t0_utc"], "2026-09-14T14:55:41Z")
        unfinished = self.run_script("note_elements.py", "--kind", "investigation", "--note", "ledger.json", document=document)
        self.assertIn("renders no Case Timeline", unfinished.stderr,
                      "only a Triage Note may have nothing on its timeline: a Case under investigation has its alerts")
        document["timeline"] = json.loads(built.stdout)["entries"]
        checked = self.run_script("note_elements.py", "--kind", "investigation", "--note", "ledger.json", document=document)
        self.assertEqual((checked.returncode, checked.stderr), (0, ""))
        self.assertIn("5. Re-classification Pivots (reclassification_pivots)", checked.stdout)

    def test_a_note_that_is_not_conformant_exits_1_and_says_why(self):
        document = self.investigation()
        document["timeline"] = [{"id": "F1", "time_utc": "2026-09-14T14:55:41Z", "is_t0": True}]
        document["findings"][0]["event_refs"] = []
        ran = self.run_script("note_elements.py", "--kind", "investigation", "--note", "ledger.json", document=document)
        self.assertEqual(ran.returncode, 1)
        self.assertIn("FAIL: finding F1: cites no event", ran.stderr)

    def test_a_timeline_that_fails_exits_1_and_a_ledger_that_is_not_there_exits_2(self):
        document = self.investigation()
        document["t0"] = "2026-09-14T15:00:00Z"
        ran = self.run_script("timeline.py", "ledger.json", document=document)
        self.assertEqual(ran.returncode, 1)
        self.assertIn("happens before T0", ran.stderr)
        self.assertEqual(self.run_script("timeline.py", "no-such-ledger.json").returncode, 2)


if __name__ == "__main__":
    unittest.main()


class ARecommendationIsAnsweredWhereItWasPublished(unittest.TestCase):
    """A source numbers its procedure per alert, so "RA7" is one instruction on one alert and
    another on the next. The check reads them per alert for that reason."""

    def note(self, actions_by_alert):
        return ledger_note(
            alerts=[{"id": a, "type": "Malware / loader execution", "entity": "ws-01", "confidence": "High"}
                    for a in actions_by_alert],
            detection_metadata={"alerts": [
                {"id": a, "absent": [], "techniques": [], "recommended_actions": held}
                for a, held in actions_by_alert.items()
            ]},
        )

    def test_an_answer_for_one_alerts_action_is_not_an_answer_for_anothers(self):
        """Measured on a live 59-alert Case: the Note was refused for RA7 and RA11 while both had
        been answered on the alerts that published them."""
        note = self.note({
            "A1": [{"id": "RA7", "action": "Submit the files", "disposition": "followed", "finding": "F1"}],
            "A2": [{"id": "RA7", "action": "Check the timeline", "disposition": "set aside",
                    "reason": "no timeline in scope"}],
        })

        self.assertEqual(note_elements.check(note, root=FRAMEWORK)[0], [])

    def test_an_action_that_was_run_and_names_no_finding_says_which_alert(self):
        note = self.note({"A1": [{"id": "RA7", "action": "Submit the files", "disposition": "followed"}]})

        failures = note_elements.check(note, root=FRAMEWORK)[0]

        self.assertTrue(any("alert A1" in f and "RA7" in f for f in failures), failures)


class TheCheckAnswersWithBothLists(unittest.TestCase):
    """Two changes landed on the same function from two branches, and the merge left `_asserted`
    returning one list where `check()` unpacked two: every Note raised `ValueError` instead of
    being checked. A test that calls it through the command line would have caught it."""

    def test_every_path_through_the_check_answers_with_failures_and_advisories(self):
        for note in ([], {"kind": "nonesuch"}, ledger_note(), ledger_note(detection_metadata=None),
                     ledger_note(detection_metadata={"alerts": "not a list"})):
            with self.subTest(note=str(note)[:40]):
                failures, advisories = note_elements.check(note, root=FRAMEWORK)
                self.assertIsInstance(failures, list)
                self.assertIsInstance(advisories, list)
