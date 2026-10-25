import csv, importlib.util, json, os, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod


triage = load("skills/zerosoc-triage/scripts/triage_decide.py", "triage_decide")
inv = load("skills/zerosoc-investigation/scripts/resolve.py", "resolve")
auto = load("skills/zerosoc-response/scripts/autonomy.py", "autonomy")
alert_types = load("tools/shared/alert_types.py", "alert_types")
evidence = load("tools/shared/evidence_inventory.py", "evidence_inventory")
selector = load("tools/shared/select_playbook.py", "select_playbook")
chain = load("tools/shared/process_chain.py", "process_chain")
metadata = load("tools/shared/alert_metadata.py", "alert_metadata")
profiles = load("tools/shared/source_profile.py", "source_profile")
checker = load("tools/check_run.py", "check_run")

CAPABILITIES = os.path.join(ROOT, "capabilities")
XDR_PROFILE = os.path.join(ROOT, "skills", "zerosoc-defender-xdr", "source_profile.json")
DFB_PROFILE = os.path.join(CAPABILITIES, "zerosoc.capabilities.defender-for-business.json")
PLACEHOLDER_SOURCES = {"<telemetry source>"}
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
PRODUCT = {"name": "Microsoft Defender XDR", "vendor_name": "Microsoft"}
with open(os.path.join(ROOT, "tools", "ocsf_1.9.0.json"), encoding="utf-8") as _f:
    OCSF = json.load(_f)


def ocsf_lacks(node, kind, path):
    """What OCSF requires of `node` as a `kind` (a class or an object) that it lacks, and what it carries that
    OCSF does not declare, all the way down. OCSF's open `object` takes anything."""
    if kind == "object":
        return []
    out = [f"{path}.{name}" for name in OCSF["required"].get(kind, []) if node.get(name) in (None, "", [], {})]
    for names in (OCSF["constraints"].get(kind) or {}).values():
        if not any(node.get(n) not in (None, "", [], {}) for n in names):
            out.append(f"{path}: none of {', '.join(names)}")
    declared = OCSF["class"].get(kind) or OCSF["objects"].get(kind) or {}
    for name, value in node.items():
        kind_of = declared.get(name)
        if kind_of is None:
            out.append(f"{path}.{name}: not an attribute of {kind}")
        elif not kind_of.removesuffix("[]").endswith("_t"):
            many = kind_of.endswith("[]")
            for n, item in enumerate(value if many else [value]):
                if isinstance(item, dict):
                    out += ocsf_lacks(item, kind_of.removesuffix("[]"), f"{path}.{name}" + (f"[{n}]" if many else ""))
    return out


class TriageRule(unittest.TestCase):
    def test_oauth_consent_closes_as_benign_high(self):
        # Detection & Analysis §1.5, first example
        ledger = {"alerts": [{"id": "A", "type": "OAuth app consent", "entity": "u1", "confidence": "Medium"}],
                  "observations": [{"id": "O2", "side": "Benign", "confidence": "High"}, {"id": "O3", "side": "Benign", "confidence": "Medium"},
                               {"id": "O4", "side": "Benign", "confidence": "Low"}, {"id": "O1", "side": None}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Close"); self.assertEqual(r["confidence"], "High")

    def test_credential_dumping_promotes_at_high(self):
        # §1.5, second example: two techniques, a Malicious observation beyond the alerts
        ledger = {"alerts": [{"id": "A1", "type": "Credential dumping", "entity": "h", "confidence": "High", "technique": "T1003"},
                             {"id": "A2", "type": "Internal scan", "entity": "h", "severity": "Medium", "technique": "T1046"}],
                  "observations": [{"id": "B1", "side": "Benign", "confidence": "Low"}, {"id": "M1", "side": "Malicious", "confidence": "Medium"},
                               {"id": "M2", "side": "Malicious", "confidence": "Low"}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote"); self.assertEqual(r["confidence"], "High")

    def test_the_alerts_listed_as_o1_o2_are_the_alerts_and_not_more(self):
        # #226: the ledger lists each alert as an observation (O1, O2, ...) naming it in `alert`;
        # the rule reads the alerts once, from `alerts`, and decides as without them
        ledger = {"alerts": [{"id": "A", "type": "Antivirus detection", "entity": "h", "confidence": "Medium"}],
                  "observations": [{"id": "O2", "side": "Benign", "confidence": "High", "event_refs": ["EVT-1"],
                                    "covers": ["A"], "condition": "false_positive"}]}
        before = triage.decide(ledger)
        ledger["observations"].insert(0, {"id": "O1", "alert": "A", "side": "Malicious", "confidence": "Medium",
                                          "event_refs": ["A"]})
        after = triage.decide(ledger)
        self.assertEqual((after["decision"], after["confidence"]), (before["decision"], before["confidence"]))
        self.assertEqual((after["restated_alerts"], after["malicious_beyond_alerts"]), ([], []))
        # a Malicious observation naming an alert the ledger does not hold is read like any other
        ledger["observations"].insert(1, {"id": "O3", "alert": "Z", "side": "Malicious", "confidence": "Medium",
                                          "event_refs": ["EVT-2"]})
        self.assertEqual(triage.decide(ledger)["malicious_beyond_alerts"], ["O3"])

    def test_a_malicious_observation_resting_on_the_alerts_alone_restates_them(self):
        # §1.5: "beyond the alerts" — an observation that cites alert records alone is the alert restated
        ledger = {"alerts": [{"id": "A", "type": "Antivirus detection", "entity": "h", "confidence": "Medium"}],
                  "observations": [{"id": "M1", "side": "Malicious", "confidence": "Medium", "event_refs": ["A"]},
                                   {"id": "B1", "side": "Benign", "confidence": "High", "event_refs": ["EVT-1"], "covers": ["A"], "condition": "false_positive"}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Close"); self.assertEqual(r["restated_alerts"], ["M1"]); self.assertEqual(r["malicious_beyond_alerts"], [])
        # the same observation resting on a check's event stands beyond the alerts and promotes
        ledger["observations"][0]["event_refs"] = ["A", "EVT-2"]
        self.assertEqual(triage.decide(ledger)["decision"], "Promote")
        # a merged id is the alert's own
        ledger["alerts"][0]["merged_ids"] = ["A2"]; ledger["observations"][0]["event_refs"] = ["A", "A2"]
        self.assertEqual(triage.decide(ledger)["decision"], "Close")
        # two alerts related — the failures one reports and the success another does — is beyond either
        ledger["alerts"].append({"id": "B", "type": "Successful sign-in after failures", "entity": "h", "confidence": "Low"})
        ledger["observations"][0]["event_refs"] = ["A", "B"]
        ledger["observations"][1]["covers"] = ["A", "B"]
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote"); self.assertEqual(r["restated_alerts"], [])

    def test_the_verdict_a_close_carries_is_read_off_the_named_condition(self):
        # §1.5: Benign (5) when the highest-confidence covering observation names a Benign condition,
        # False Positive (1) otherwise — both kinds at that confidence, or no condition named at all
        def ledger(*obs):
            return {"alerts": [{"id": "A", "type": "x", "entity": "h", "confidence": "Medium"}],
                    "observations": [dict(o, side="Benign", covers=["A"], event_refs=["EVT"]) for o in obs]}
        self.assertEqual(triage.decide(ledger({"id": "B1", "confidence": "High", "condition": "benign"}))["verdict_id"], 5)
        self.assertEqual(triage.decide(ledger({"id": "B1", "confidence": "High", "condition": "false_positive"}))["verdict_id"], 1)
        r = triage.decide(ledger({"id": "B1", "confidence": "High", "condition": "false_positive"},
                                 {"id": "B2", "confidence": "Low", "condition": "benign"}))
        self.assertEqual(r["verdict_id"], 1, "the higher confidence decides")
        r = triage.decide(ledger({"id": "B1", "confidence": "High", "condition": "benign"},
                                 {"id": "B2", "confidence": "Low", "condition": "false_positive"}))
        self.assertEqual(r["verdict_id"], 5); self.assertTrue(r["emit"].startswith("exception ticket"))
        r = triage.decide(ledger({"id": "B1", "confidence": "High", "condition": "benign"},
                                 {"id": "B2", "confidence": "High", "condition": "false_positive"}))
        self.assertEqual(r["verdict_id"], 1, "both kinds at the same confidence: False Positive")
        r = triage.decide(ledger({"id": "B1", "confidence": "High", "condition": None}, {"id": "B2", "confidence": "Low", "condition": None}))
        self.assertEqual(r["verdict_id"], 1, "explained but no condition named: False Positive")
        self.assertEqual(r["emit"], "tuning ticket to Phase 1")
        r = triage.decide(ledger({"id": "B1", "confidence": "High", "condition": None}, {"id": "B2", "confidence": "High", "condition": "benign"}))
        self.assertEqual(r["verdict_id"], 5, "an unnamed observation beside a named Benign one names nothing against it")
        # a ledger from before the field is left to the caller, as it always was
        r = triage.decide(ledger({"id": "B1", "confidence": "High"}))
        self.assertIsNone(r["verdict_id"]); self.assertIn("--close-as", r["verdict"])

    def test_high_alert_needs_benign_high(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}],
                  "observations": [{"id": "B1", "side": "Benign", "confidence": "Medium"}, {"id": "B2", "side": "Benign", "confidence": "Medium"}]}
        self.assertEqual(triage.decide(ledger)["decision"], "Promote")

    def test_no_observation_promotes_and_a_gap_leaves_the_confidence_alone(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}], "observations": [], "visibility_gaps": [{"data_source": "EDR"}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote")
        self.assertEqual(r["confidence_id"], 3, "confidence follows the observations; the gap is recorded, not weighed in")
        self.assertEqual(triage.decide(dict(ledger, visibility_gaps=[]))["confidence_id"], 3)

    def test_same_type_same_entity_counts_once(self):
        ledger = {"alerts": [{"id": "A1", "type": "x", "entity": "e", "confidence": "Low"}, {"id": "A2", "type": "x", "entity": "e", "confidence": "Low"}],
                  "observations": [{"id": "B", "side": "Benign", "confidence": "Medium"}]}
        r = triage.decide(ledger)
        self.assertEqual(len(r["alerts_considered"]), 1); self.assertEqual(r["decision"], "Close")


SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _lab_case(*benign, entities=True):
    """Two alerts on one host naming the same test file (zerosoc-skills#59): an antivirus prevention at
    Low and a behavioural "human-operated activity" alert at High, whose evidence is the host and the file."""
    ledger = {"alerts": [{"id": "AV", "type": "Malware / loader execution", "entity": "host-1", "confidence": "Low"},
                         {"id": "HO", "type": "Potential human-operated malicious activity", "entity": "host-1",
                          "confidence": "High"}],
              "observations": [dict(b, side="Benign", event_refs=b.get("event_refs", ["EVT-1"])) for b in benign]}
    if entities:
        ledger["entities"] = [
            {"type": "file", "name": "eicar-scenario.com", "sha256": SHA, "device": "host-1", "alert_ids": ["AV", "HO"]},
            {"type": "device", "name": "host-1", "alert_ids": ["AV", "HO"]},
            {"type": "process", "name": "powershell.exe", "device": "host-1", "alert_ids": ["HO"]},
        ]
    return ledger


class CoverageReadOffTheEvidence(unittest.TestCase):
    """A Benign observation about an entity covers every alert whose evidence cites it (#59)."""

    def test_the_test_file_explains_both_alerts_that_name_it(self):
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "condition": "benign", "about": [SHA],
                                     "covers": ["AV"]}))
        self.assertEqual(r["decision"], "Close")
        self.assertEqual([c["covering"] for c in r["coverage"]], [["B1"], ["B1"]])
        self.assertEqual(r["verdict_id"], 5)

    def test_an_entity_is_named_by_any_value_the_inventory_holds_for_it(self):
        for about in ("eicar-scenario.com", "EICAR-SCENARIO.COM", f"sha256:{SHA}", SHA.upper()):
            r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "about": [about]}))
            self.assertEqual(r["decision"], "Close", about)

    def test_an_observation_about_nothing_covers_nothing(self):
        """Before, a Benign observation with no covers counted for every alert: a Medium note about anything
        on the host stood toward the High alert."""
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "condition": "benign"}))
        self.assertEqual(r["decision"], "Promote")
        self.assertEqual([c["covering"] for c in r["coverage"]], [[], []])

    def test_an_entity_only_one_alert_cites_covers_only_that_alert(self):
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "about": ["powershell.exe"]}))
        covered = {c["alert"]: c["covered"] for c in r["coverage"]}
        self.assertEqual(covered, {"AV": False, "HO": True})

    def test_an_alert_is_left_out_only_with_a_reason(self):
        reasoned = triage.decide(_lab_case({"id": "B1", "confidence": "High", "about": [SHA],
                                            "not_covering": [{"alert": "HO", "reason": "the alert rests on the"
                                                              " process tree, not on the file"}]}))
        self.assertEqual(reasoned["decision"], "Promote")
        self.assertEqual([c["covering"] for c in reasoned["coverage"]], [["B1"], []])
        unreasoned = triage.decide(_lab_case({"id": "B1", "confidence": "High", "about": [SHA],
                                              "not_covering": [{"alert": "HO"}]}))
        self.assertEqual(unreasoned["decision"], "Close", "an exclusion without a reason is not one")
        self.assertIn("B1", unreasoned["coverage_note"])

    def test_an_exclusion_reaches_every_id_of_the_alert(self):
        ledger = _lab_case({"id": "B1", "confidence": "High", "about": [SHA],
                            "not_covering": [{"alert": "HO", "reason": "the alert rests on the process tree"}]})
        ledger["alerts"][1]["merged_ids"] = ["HO-2"]
        ledger["entities"][0]["alert_ids"] = ["AV", "HO-2"]  # the evidence cites the merged id
        r = triage.decide(ledger)
        self.assertEqual({c["alert"]: c["covered"] for c in r["coverage"]}, {"AV": True, "HO": False})

    def test_the_artifact_names_what_the_observation_rests_on(self):
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "artifact": f"hash:{SHA}"}))
        self.assertEqual(r["decision"], "Close")

    def test_a_name_the_inventory_does_not_hold_is_reported(self):
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "about": ["eicar.com"]}))
        self.assertEqual(r["decision"], "Promote")
        self.assertIn("'eicar.com' names no entity", r["coverage_note"])

    def test_a_ledger_that_names_no_entities_is_read_as_before_and_says_so(self):
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High"}, entities=False))
        self.assertEqual(r["decision"], "Close", "no covers still covers every alert there")
        self.assertIn("names no entities", r["coverage_note"])
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High",
                                     "not_covering": [{"alert": "HO", "reason": "not the file"}]}, entities=False))
        self.assertEqual(r["decision"], "Promote", "an exclusion with a reason holds there too")
        r = triage.decide(_lab_case({"id": "B1", "confidence": "High", "covers": ["AV", "HO"]}, entities=False))
        self.assertNotIn("coverage_note", r, "nothing was read the old way")


class ResolutionRule(unittest.TestCase):
    def test_benign_proven_carries_the_verdict_of_the_named_condition(self):
        # §2.4 applies §1.5's rule to the same two verdicts
        def ledger(*obs):
            return {"observations": [dict(o, side="Benign", event_refs=["EVT"]) for o in obs]}
        self.assertEqual(inv.resolve(ledger({"id": "B1", "confidence": "High", "condition": "benign"}))["verdict_id"], 5)
        r = inv.resolve(ledger({"id": "B1", "confidence": "High", "condition": "false_positive"}, {"id": "B2", "confidence": "Low", "condition": "benign"}))
        self.assertEqual(r["verdict_id"], 1); self.assertEqual(r["emit"], "tuning ticket to Phase 1")
        self.assertEqual(inv.resolve(ledger({"id": "B1", "confidence": "High", "condition": None}))["verdict_id"], 1)
        r = inv.resolve(ledger({"id": "B1", "confidence": "High"}))
        self.assertEqual(r["outcome"], "Benign proven"); self.assertIsNone(r["verdict_id"])

    def test_retraction_flips_to_benign(self):
        # §2.4 example 1
        f = [{"id": "alert", "side": "Malicious", "confidence": "Medium", "covered": True},
             {"id": "domain", "side": "Malicious", "confidence": "Medium", "retracted": True},
             {"id": "page", "side": "Malicious", "confidence": "High", "retracted": True},
             {"id": "campaign", "side": "Benign", "confidence": "High"}]
        r = inv.resolve({"observations": f})
        self.assertEqual(r["outcome"], "Benign proven"); self.assertEqual(r["confidence"], "High")

    def test_coverage_decides(self):
        # §2.4 example 2: explanation covers the alert but not the later credential use
        f = [{"id": "alert", "side": "Malicious", "confidence": "High", "covered": True},
             {"id": "use", "side": "Malicious", "confidence": "High", "covered": False},
             {"id": "agent", "side": "Benign", "confidence": "High"}]
        r = inv.resolve({"observations": f})
        self.assertEqual(r["verdict_id"], 2); self.assertEqual(r["confidence"], "High")

    def test_strongest_not_average(self):
        f = [{"id": "a", "side": "Malicious", "confidence": "Medium"}, {"id": "feed", "side": "Malicious", "confidence": "High"},
             {"id": "l1", "side": "Malicious", "confidence": "Low"}, {"id": "l2", "side": "Malicious", "confidence": "Low"}, {"id": "l3", "side": "Malicious", "confidence": "Low"}]
        r = inv.resolve({"observations": f})
        self.assertEqual(r["malicious_score"], 8); self.assertEqual(r["confidence"], "High")

    def test_low_confidence_true_positive(self):
        f = [{"id": str(i), "side": "Malicious", "confidence": "Low"} for i in range(4)]
        r = inv.resolve({"observations": f})
        self.assertEqual(r["verdict_id"], 2); self.assertEqual(r["confidence"], "Low")

    def test_residual_low_lowers_benign_confidence(self):
        f = [{"id": "m", "side": "Malicious", "confidence": "Low"}, {"id": "b", "side": "Benign", "confidence": "High"}]
        r = inv.resolve({"observations": f})
        self.assertEqual(r["outcome"], "Benign proven"); self.assertEqual(r["confidence"], "Medium"); self.assertEqual(r["residual_low_malicious"], ["m"])

    def test_insufficient_data_at_timebox(self):
        f = [{"id": "m", "side": "Malicious", "confidence": "Medium"}, {"id": "b", "side": "Benign", "confidence": "Low"}]
        self.assertIsNone(inv.resolve({"observations": f})["verdict_id"])
        self.assertEqual(inv.resolve({"observations": f, "timebox_expired": True})["verdict_id"], 7)

    def test_same_artifact_counts_once(self):
        f = [{"id": "t", "side": "Malicious", "confidence": "Medium", "artifact": "hash:1"}, {"id": "i", "side": "Malicious", "confidence": "Medium", "artifact": "hash:1"}]
        self.assertEqual(inv.resolve({"observations": f})["malicious_score"], 2)


class TimeboxFromLedger(unittest.TestCase):
    # Guardrails §5: 10 minutes at High or Critical severity, 20 otherwise; an organization may tighten them
    F = [{"id": "m", "side": "Malicious", "confidence": "Medium", "at": "2026-09-14T15:04:00Z"},
         {"id": "b", "side": "Benign", "confidence": "Low", "at": "2026-09-14T15:09:00Z"}]
    START, AT_12 = "2026-09-14T15:00:00Z", "2026-09-14T15:12:00Z"

    def test_high_severity_expires_after_ten_minutes(self):
        r = inv.resolve({"observations": self.F, "started_at": self.START, "severity": "High"}, now=self.AT_12)
        self.assertEqual(r["timebox"], {"minutes": 10, "elapsed_minutes": 12.0, "expired": True, "source": "computed"})
        self.assertEqual(r["verdict_id"], 7)

    def test_medium_severity_has_twenty_minutes(self):
        r = inv.resolve({"observations": self.F, "started_at": self.START, "severity_id": 3}, now=self.AT_12)
        self.assertFalse(r["timebox"]["expired"]); self.assertEqual(r["timebox"]["minutes"], 20)
        self.assertIsNone(r["verdict_id"])

    def test_the_end_is_now_then_resolved_at_then_the_clock_never_the_last_observation(self):
        ledger = {"observations": self.F, "started_at": self.START, "severity": "Low", "resolved_at": "2026-09-14T15:25:00Z"}
        self.assertTrue(inv.resolve(ledger)["timebox"]["expired"])
        self.assertFalse(inv.resolve(ledger, now="2026-09-14T15:05:00Z")["timebox"]["expired"])
        del ledger["resolved_at"]  # a stalled run: the last observation is at +9 minutes, the clock is years later
        self.assertTrue(inv.resolve(ledger)["timebox"]["expired"])

    def test_computed_value_overrides_a_self_reported_flag(self):
        r = inv.resolve({"observations": self.F, "started_at": self.START, "severity": "Critical", "timebox_expired": False}, now=self.AT_12)
        self.assertTrue(r["timebox"]["expired"]); self.assertIn("self-reported", r["timebox_note"])

    def test_without_a_start_the_flag_is_used_and_marked_self_reported(self):
        r = inv.resolve({"observations": self.F, "timebox_expired": True})
        self.assertEqual(r["timebox"]["source"], "self-reported"); self.assertEqual(r["verdict_id"], 7)

    def test_an_organization_may_tighten_the_reference_value_not_extend_it(self):
        base = {"observations": self.F, "started_at": self.START, "severity": "High"}
        tight = inv.resolve(dict(base, timebox_minutes=5), now="2026-09-14T15:06:00Z")
        self.assertEqual(tight["timebox"]["minutes"], 5); self.assertTrue(tight["timebox"]["expired"])
        loose = inv.resolve(dict(base, timebox_minutes=30), now=self.AT_12)
        self.assertEqual(loose["timebox"]["minutes"], 10); self.assertTrue(loose["timebox"]["expired"])
        self.assertIn("ignored", loose["timebox_note"])

    def test_timestamps_out_of_order_are_reported(self):
        r = inv.resolve({"observations": self.F, "started_at": "2026-09-14T15:05:00Z", "severity": "High"}, now="2026-09-14T15:00:00Z")
        self.assertEqual(r["timebox"]["elapsed_minutes"], 0.0)
        self.assertIn("precedes started_at", r["timebox_note"]); self.assertIn("m", r["timebox_note"])

    def test_a_malformed_timestamp_is_a_value_error(self):
        with self.assertRaises(ValueError):
            inv.resolve({"observations": [], "started_at": "yesterday"})


class LedgerDedup(unittest.TestCase):
    def test_same_alert_type_on_the_same_entity_counts_once_in_resolution(self):
        # Detection & Analysis §1.1: same type on the same entity counts once
        f = [{"id": "a1", "side": "Malicious", "confidence": "Medium", "alert_type": "Credential dumping", "entity": "ws-04", "artifact": "alert:1"},
             {"id": "a2", "side": "Malicious", "confidence": "High", "alert_type": "credential dumping", "entity": "WS-04", "artifact": "alert:2"},
             {"id": "a3", "side": "Malicious", "confidence": "Medium", "alert_type": "Credential dumping", "entity": "ws-09"}]
        r = inv.resolve({"observations": f})
        self.assertEqual(r["malicious_score"], 5)  # High (3) for ws-04 once, Medium (2) for ws-09
        self.assertEqual(r["malicious_observations"], ["a1", "a3"])


class AlertTypeChoice(unittest.TestCase):
    """The executor chooses each alert's type; the script holds the choice to the framework's names
    and counts the same type on the same entity once."""

    def setUp(self):
        self.known = alert_types.known_types(os.path.join(ROOT, "framework"))

    def test_the_taxonomy_is_read_whole(self):
        self.assertGreater(len(self.known), 40)
        self.assertEqual(self.known["Credential dumping"], "Endpoint")
        self.assertEqual(self.known["Inbox forwarding / redirect or hide rule"], "Email")

    def test_a_chosen_type_carries_the_domain_the_taxonomy_gives_it(self):
        m = alert_types.typed({"id": "x", "title": "plink.exe", "alert_type": "ingress tool transfer to host",
                               "entity": "ws-04"}, self.known)
        self.assertEqual((m["type"], m["alert_type"], m["domain"], m["unmapped"]),
                         ("Ingress tool transfer to host", "Ingress tool transfer to host", "Endpoint", False),
                         "the framework's own spelling, whatever the case the executor wrote it in")
        self.assertEqual(m["source_title"], "plink.exe")

    def test_a_type_the_framework_does_not_hold_is_refused(self):
        with self.assertRaisesRegex(ValueError, "not an alert type of the framework"):
            alert_types.typed({"id": "x", "title": "t", "alert_type": "Lateral movement"}, self.known)

    def test_an_alert_no_type_describes_keeps_its_title_and_says_why(self):
        m = alert_types.typed({"id": "x", "title": "  Potential human-operated   malicious activity ",
                               "no_type_reason": "a correlation verdict, not a behaviour"}, self.known)
        self.assertEqual((m["type"], m["domain"], m["unmapped"]),
                         ("Potential human-operated malicious activity", None, True))
        self.assertEqual(m["unmapped_reason"], "a correlation verdict, not a behaviour")

    def test_an_alert_with_neither_a_type_nor_a_reason_is_refused(self):
        with self.assertRaisesRegex(ValueError, "neither an alert_type nor a no_type_reason"):
            alert_types.typed({"id": "x", "title": "t"}, self.known)

    def test_same_type_same_entity_collapses_to_the_strongest(self):
        alerts = [{"id": "A1", "title": "Sensitive credential memory read", "entity": "ws-04", "severity": "Medium",
                   "alert_type": "Credential dumping"},
                  {"id": "A2", "title": "Possible credential dumping (LSASS)", "entity": "WS-04", "severity": "High",
                   "alert_type": "Credential dumping"},
                  {"id": "A3", "title": "Possible credential dumping (LSASS)", "entity": "ws-09", "severity": "High",
                   "alert_type": "Credential dumping"}]
        out = alert_types.build_alerts(alerts, self.known)
        self.assertEqual([(a["id"], a["entity"], a["confidence"], a["merged_ids"]) for a in out],
                         [("A2", "WS-04", "High", ["A1", "A2"]), ("A3", "ws-09", "High", ["A3"])])
        # the triage rule sees the same thing it would after its own dedup
        self.assertEqual(len(triage.dedupe_alerts(out)), 2)

    def test_levels_are_case_insensitive_and_a_missing_entity_is_empty(self):
        m = alert_types.typed({"id": "x", "title": "t", "confidence": "high", "entity": None,
                               "no_type_reason": "r"}, self.known)
        self.assertEqual((m["confidence"], m["entity"]), ("High", ""))
        self.assertEqual(alert_types.typed({"id": "x", "title": "t", "severity": "critical", "no_type_reason": "r"},
                                           self.known)["confidence"], "High")

    def test_the_output_seeds_the_resolution_ledger_and_counts_once_there_too(self):
        alerts = [{"id": "A1", "title": "Sensitive credential memory read", "entity": "ws-04", "severity": "Medium",
                   "alert_type": "Credential dumping"},
                  {"id": "A2", "title": "Possible credential dumping (LSASS)", "entity": "ws-04", "severity": "Medium",
                   "alert_type": "Credential dumping"}]
        raw = [alert_types.typed(a, self.known) for a in alerts]  # not yet collapsed
        self.assertEqual(inv.resolve({"observations": raw})["malicious_score"], 2)
        self.assertEqual(inv.resolve({"observations": alert_types.build_alerts(alerts, self.known)})["malicious_score"], 2)

    def _ran(self, alerts):
        import subprocess, sys, tempfile, json as j
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            j.dump(alerts, f)
        ran = subprocess.run([sys.executable, os.path.join(ROOT, "tools/shared/alert_types.py"), f.name,
                              "--root", os.path.join(ROOT, "framework"), "--json"], capture_output=True, text=True)
        os.unlink(f.name)
        return ran

    def test_the_script_prints_the_ledger_alerts_and_refuses_an_invented_type(self):
        import json as j
        ran = self._ran([{"id": "A", "title": "Suspicious inbox forwarding rule", "entity": "u",
                          "alert_type": "Inbox forwarding / redirect or hide rule"}])
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(j.loads(ran.stdout)[0]["domain"], "Email")
        refused = self._ran([{"id": "B", "title": "t", "entity": "u", "alert_type": "Something new"}])
        self.assertEqual(refused.returncode, 2)
        self.assertIn("not an alert type of the framework", refused.stderr)

    def test_a_source_profile_types_no_alert(self):
        with open(XDR_PROFILE, encoding="utf-8") as f:
            self.assertNotIn("alert_types", json.load(f), "the executor chooses the type, not a map")


class DecisionReadsWhatTheDetectionAsserts(unittest.TestCase):
    """§1.1 and §1.5 at the decision: the assertions are on the ledger, the recommendations are
    dispositioned, and a remediated entity does not explain anything."""

    def ledger(self, **overrides):
        led = {"case_uid": "CASE-1",
               "alerts": [{"id": "A1", "type": "Malware / loader execution", "entity": "ws-04", "confidence": "High"}],
               "observations": [{"id": "B1", "side": "Benign", "confidence": "High"}],
               "evidence_inventory": {"extracted": 2, "source_count": 2, "complete": True},
               "detection_metadata": {
                   "alerts": [{"id": "A1", "techniques": [{"id": "T1204", "rendered": "T1204 (User Execution)"}],
                               "threat": {"name": "Trojan:Win32/Wacatac", "family": "Wacatac"},
                               "detection": {"source": "antivirus", "analytic_type_id": 5, "analytic_type": "Fingerprinting"},
                               "description": "d", "absent": [],
                               "recommended_actions": [{"id": "RA1", "action": "Run a full scan", "disposition": "followed"}]}],
                   "remediation": [{"entity": "loader.exe", "type": "file", "state": "quarantined", "neutralized": True,
                                    "alert_ids": ["A1"]}],
                   "neutralized_entities": ["loader.exe"],
                   "visibility_gaps": []}}
        led.update(overrides)
        return led

    def test_a_ledger_without_the_assertions_is_told_to_extract_them(self):
        r = triage.decide({"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "Low"}], "observations": []})
        self.assertIn("what the detection asserts", " ".join(r["detection_notes"]))
        self.assertIn("alert_metadata.py", " ".join(r["detection_notes"]))

    def test_a_recommendation_is_nothing_the_decision_accounts_for(self):
        """§1.5: what a source recommends is indicative. The decision once waited until every
        published action was followed or set aside with a reason, then reported what became of
        each. Both are a checklist on a source that publishes its procedure per alert — and the
        source publishes two kinds of instruction, checks and response actions, so accounting for
        every line made triage answer for containment it is not triage's to perform."""
        led = self.ledger()
        led["detection_metadata"]["alerts"][0]["recommended_actions"].append(
            {"id": "RA2", "action": "Isolate the device"})

        r = triage.decide(led)

        self.assertNotIn("decision_ready", r)
        self.assertNotIn("recommended_actions", r)
        self.assertEqual(r["decision"], "Close", "the coverage rule is unchanged")

    def test_a_neutralized_entity_is_recorded_and_never_taken_as_an_explanation(self):
        r = triage.decide(self.ledger())
        self.assertEqual(r["neutralized_entities"], ["loader.exe"])
        note = " ".join(r["detection_notes"])
        self.assertIn("loader.exe", note)
        self.assertIn("not an explanation", note)
        self.assertIn("how it arrived", note)

    def test_an_absent_assertion_asks_for_no_gap(self):
        led = self.ledger()
        led["detection_metadata"]["alerts"][0]["absent"] = ["techniques", "threat name"]
        r = triage.decide(led)
        self.assertNotIn("visibility gap", " ".join(r["detection_notes"]))

    def test_the_techniques_of_the_alerts_raise_the_confidence_the_rule_raises(self):
        # §1.5: independent alerts of different types or techniques raise the confidence one level
        led = self.ledger()
        led["alerts"].append({"id": "A2", "type": "Malware / loader execution", "entity": "ws-09", "confidence": "Medium"})
        led["detection_metadata"]["alerts"].append(dict(led["detection_metadata"]["alerts"][0], id="A2"))
        led["observations"] = []
        self.assertEqual(triage.decide(led)["confidence_id"], 3, "one technique on both alerts: no raise beyond High")
        led["alerts"][0]["confidence"] = "Low"
        led["alerts"][1]["confidence"] = "Low"
        same = triage.decide(led)
        self.assertEqual(same["confidence_id"], 1, "the same technique twice is not two techniques")
        led["detection_metadata"]["alerts"][1] = dict(led["detection_metadata"]["alerts"][1],
                                                      techniques=[{"id": "T1003", "rendered": "T1003 (OS Credential Dumping)"}])
        self.assertEqual(triage.decide(led)["confidence_id"], 2, "two techniques across two alerts raise it one level")

    def test_the_candidate_categories_of_the_case_come_back_with_the_decision(self):
        led = self.ledger()
        led["detection_metadata"]["candidate_incident_categories"] = ["IC-03", "IC-05"]
        self.assertEqual(triage.decide(led)["candidate_incident_categories"], ["IC-03", "IC-05"])

    def test_investigation_reads_the_same_record_at_its_own_gate(self):
        led = self.ledger()
        led["observations"] = [{"id": "O1", "side": "Malicious", "confidence": "High"}]
        r = inv.resolve(led)
        self.assertIn("loader.exe", " ".join(r["detection_notes"]))
        self.assertEqual(r["verdict_id"], 2, "the resolution rule is unchanged")


class TechniqueIndex(unittest.TestCase):
    """The techniques a detection names are looked up in the framework's own tables: what they are
    called, and which Incident Categories they point at (Detection & Analysis §1.4)."""

    @classmethod
    def setUpClass(cls):
        cls.index = selector.technique_index(os.path.join(ROOT, "framework"))

    def test_the_index_names_techniques_and_points_at_categories(self):
        self.assertEqual(self.index["T1003"]["name"], "OS Credential Dumping")
        self.assertIn("IC-06", self.index["T1003"]["categories"])
        self.assertIn("Endpoint", self.index["T1003"]["domains"])
        self.assertIn("Credential dumping", self.index["T1003"]["alert_types"])

    def test_a_sub_technique_falls_back_to_its_parent(self):
        found = selector.candidates(["T1003.001"], self.index)
        self.assertEqual(found["techniques"][0]["id"], "T1003.001")
        self.assertEqual(found["techniques"][0]["matched"], "T1003")
        self.assertIn("IC-06", found["categories"])

    def test_a_technique_the_catalog_does_not_hold_is_reported_not_dropped(self):
        found = selector.candidates(["T1003", "T9999"], self.index)
        self.assertIn("IC-06", found["categories"])
        self.assertEqual(found["unknown"], ["T9999"])
        self.assertIsNone(found["techniques"][1]["name"])

    def test_candidates_widen_over_every_technique_the_detection_names(self):
        found = selector.candidates(["T1003", "T1486"], self.index)
        self.assertIn("IC-06", found["categories"])
        self.assertIn("IC-03", found["categories"])
        self.assertEqual(found["categories"], sorted(found["categories"]))


class DetectionMetadata(unittest.TestCase):
    """What the detection asserts, read before enrichment (Detection & Analysis §1.1)."""

    ALERT = {"id": "A1", "title": "'Impacket' malware was detected", "severity": "high",
             "mitreTechniques": ["T1021.002", "T1047"], "threatDisplayName": "VirTool:Win32/Impacket.D",
             "threatFamilyName": "Impacket", "detectionSource": "antivirus", "detectorId": "det-7",
             "description": "Impacket is a collection of Python classes for working with network protocols.",
             "recommendedActions": "Run a full antivirus scan.\nCheck whether the file is present on other devices."}

    @classmethod
    def setUpClass(cls):
        cls.spec = profiles.load(XDR_PROFILE)
        cls.index = selector.technique_index(os.path.join(ROOT, "framework"))

    def one(self, alert=None, **kw):
        return metadata.assertions(alert or self.ALERT, self.spec, index=self.index, **kw)

    def test_every_assertion_is_read_under_the_source_own_field_names(self):
        a = self.one()
        self.assertEqual([t["id"] for t in a["techniques"]], ["T1021.002", "T1047"])
        self.assertEqual(a["threat"], {"name": "VirTool:Win32/Impacket.D", "family": "Impacket"})
        self.assertEqual(a["detection"]["source"], "antivirus")
        self.assertEqual(a["detection"]["detector_id"], "det-7")
        self.assertIn("Python classes", a["description"])
        self.assertEqual(len(a["recommended_actions"]), 2)
        self.assertEqual(a["absent"], [])

    def test_a_technique_is_rendered_only_with_the_name_the_framework_gives_it(self):
        a = self.one()
        self.assertEqual(a["techniques"][0]["rendered"], "T1021.002 (SMB/Windows Admin Shares)",
                         "a sub-technique the catalog names carries that name")
        self.assertEqual(a["techniques"][0]["matched"], "T1021.002",
                         "a sub-technique the catalog holds is matched on its own, not on its parent")
        self.assertEqual(a["techniques"][1]["rendered"], "T1047 (Windows Management Instrumentation)")
        bare = self.one({"id": "A2", "title": "t", "mitreTechniques": ["T1003.001"]})
        self.assertEqual(bare["techniques"][0]["rendered"], "T1003.001",
                         "the catalog names T1003, not the sub-technique: the id is not dressed in the parent's name")
        self.assertEqual(bare["techniques"][0]["matched"], "T1003",
                         "the parent is still what the categories come from")
        named = self.one({"id": "A3", "title": "t", "mitreTechniques": ["T1003"]})
        self.assertEqual(named["techniques"][0]["rendered"], "T1003 (OS Credential Dumping)")

    def test_the_detection_source_maps_to_an_ocsf_analytic_type(self):
        self.assertEqual(self.one()["detection"]["analytic_type_id"], 5)
        self.assertEqual(self.one()["detection"]["analytic_type"], "Fingerprinting")
        custom = self.one(dict(self.ALERT, detectionSource="customDetection"))
        self.assertEqual((custom["detection"]["analytic_type_id"], custom["detection"]["analytic_type"]), (1, "Rule"))
        unknown = self.one(dict(self.ALERT, detectionSource="somethingElse"))
        self.assertEqual(unknown["detection"]["analytic_type_id"], 99, "an unmapped source is Other, never guessed")

    def test_a_recommended_action_is_what_the_source_published_and_an_id_to_cite_it_by(self):
        """No disposition field: the executor is not asked what became of each one. What it ran is
        an Observation naming the recommendation in its `analytic`, checked as an Observation."""
        a = self.one()
        self.assertEqual([sorted(r) for r in a["recommended_actions"]], [["action", "id"], ["action", "id"]])
        self.assertFalse(hasattr(metadata, "dispositions"))

    def test_the_case_wide_list_names_the_alert_of_each_action(self):
        """Ids are numbered per alert: RA1 of A1 and RA1 of A2 are two actions, told apart by alert."""
        built = metadata.build([self.ALERT, dict(self.ALERT, id="A2")], self.spec, index=self.index)
        cited = [(a["alert"], a["id"]) for a in built["recommended_actions"]]
        self.assertEqual(cited, [("A1", "RA1"), ("A1", "RA2"), ("A2", "RA1"), ("A2", "RA2")])
        self.assertEqual(len(set(cited)), len(cited))

    def test_an_assertion_the_source_does_not_supply_is_named_not_assumed(self):
        bare = self.one({"id": "A2", "title": "Suspicious activity"})
        self.assertEqual(bare["techniques"], [])
        self.assertIsNone(bare["threat"])
        self.assertEqual(bare["absent"], ["description", "detection source", "recommended actions", "techniques", "threat name"])
        self.assertEqual(bare["candidate_incident_categories"], [])

    def test_what_an_alert_does_not_supply_is_listed_with_it_and_is_no_gap(self):
        # Detection & Analysis §1.1: an absent input is a gap only where a check needed it, which the
        # executor knows and the script does not
        rows = [{"type": "file", "name": "x.exe", "alert_ids": ["A1"]}]
        built = metadata.build([self.ALERT, {"id": "A2", "title": "t"}], self.spec, rows, index=self.index)
        self.assertEqual([a["absent"] for a in built["alerts"]],
                         [[], ["description", "detection source", "recommended actions", "techniques", "threat name"]])
        self.assertNotIn("visibility_gaps", built)

    def test_the_case_candidate_categories_come_from_the_techniques(self):
        built = metadata.build([self.ALERT], self.spec, index=self.index)
        self.assertIn("IC-08", built["candidate_incident_categories"])
        self.assertEqual(built["techniques"], ["T1021.002", "T1047"])

    def test_remediation_state_is_read_per_entity(self):
        rows = [{"type": "process", "name": "wmiprvse.exe", "device": "ws-04", "alert_ids": ["A1"],
                 "remediationStatus": "prevented", "remediationStatusDetails": "blocked at execution"},
                {"type": "process", "name": "rundll32.exe", "device": "ws-04", "alert_ids": ["A1"],
                 "remediation_status": "prevented"},
                {"type": "file", "name": "x.exe", "device": "ws-04", "alert_ids": ["A1"], "remediationStatus": "none"},
                {"type": "device", "name": "ws-04", "alert_ids": ["A1"]}]
        out = metadata.remediation(rows, self.spec)
        self.assertEqual([(r["entity"], r["state"], r["neutralized"]) for r in out],
                         [("wmiprvse.exe", "prevented", True), ("rundll32.exe", "prevented", True),
                          ("x.exe", "none", False)],
                         "a row that already carries the canonical name needs no alias: the inventory's rows do")
        self.assertEqual(out[0]["activity"], "Evict"); self.assertEqual(out[0]["status"], "Success")
        self.assertEqual(out[0]["alert_ids"], ["A1"])
        self.assertIn("blocked at execution", out[0]["details"])

    def test_a_remediation_the_source_did_not_complete_is_not_neutralized(self):
        rows = [{"type": "file", "name": "y.exe", "alert_ids": ["A1"], "remediationStatus": "notFound"},
                {"type": "file", "name": "z.exe", "alert_ids": ["A1"], "remediationStatus": "failed"}]
        out = metadata.remediation(rows, self.spec)
        self.assertEqual([(r["state"], r["neutralized"], r["status"]) for r in out],
                         [("notFound", False, "Does Not Exist"), ("failed", False, "Failure")])


class EvidenceInventory(unittest.TestCase):
    ROWS = [{"type": "device", "name": "ws-04", "alert_ids": ["A1"]},
            {"type": "process", "name": "cmd.exe", "pid": 5120, "created": "2026-09-14T14:55:41Z", "alert_ids": ["A1"]},
            {"type": "process", "name": "cmd.exe", "pid": 5120, "created": "2026-09-14T14:55:41Z", "device": "ws-04", "alert_ids": ["A2"]},
            {"type": "file", "name": "invoice.exe", "sha256": "ab" * 32, "alert_ids": ["A1"]},
            {"type": "user", "name": "m.rossi@lab.local", "alert_ids": ["A1", "A2"]}]

    def test_rows_are_deduplicated_and_joined_to_their_device(self):
        inv_ = evidence.build(self.ROWS, alert_devices={"A1": "ws-04", "A2": "ws-04"})
        self.assertEqual(inv_["count"], 4)
        proc = next(e for e in inv_["entities"] if e["type"] == "process")
        self.assertEqual(proc["device"], "ws-04"); self.assertEqual(proc["alert_ids"], ["A1", "A2"])

    def test_device_is_inferred_from_the_device_row_of_the_same_alert(self):
        built = evidence.build(self.ROWS)  # A2 has no device row: its process is the one A1 placed
        proc = [e for e in built["entities"] if e["type"] == "process"]
        self.assertEqual([(e["device"], e["alert_ids"]) for e in proc], [("ws-04", ["A1", "A2"])])
        self.assertEqual(built["count"], 4)
        two = self.ROWS + [{"type": "device", "name": "ws-09", "alert_ids": ["A1"]}]
        file_ = next(e for e in evidence.build(two)["entities"] if e["type"] == "file")
        self.assertIsNone(file_["device"], "an alert citing two devices cannot place the file; the map must")

    def test_the_same_process_on_two_devices_is_two_entities(self):
        rows = [{"type": "process", "name": "cmd.exe", "pid": 1, "device": d, "alert_ids": ["A"]} for d in ("ws-04", "ws-09")]
        self.assertEqual(evidence.build(rows)["count"], 2)

    def test_completeness_is_recorded_not_assumed(self):
        inv_ = evidence.build(self.ROWS, alert_devices={"A1": "ws-04", "A2": "ws-04"})
        self.assertEqual(evidence.completeness(inv_, 4), {"extracted": 4, "rows_read": 5, "source_count": 4, "source_count_basis": "source", "complete": True})
        self.assertFalse(evidence.completeness(inv_, 31)["complete"])
        self.assertIsNone(evidence.completeness(inv_, None)["complete"])
        self.assertIn("4 of 31", evidence.note(evidence.completeness(inv_, 31)))
        self.assertIn("listed twice", evidence.note(evidence.completeness(inv_, 3)))

    def test_rows_are_read_leniently(self):
        rows = [{"type": "Process", "name": "cmd.exe", "pid": 1, "device": "HOST1", "alert_ids": "A"},
                {"type": "process", "name": "cmd.exe", "pid": 1, "device": "HOST2", "alert_ids": ["B"]},
                {"type": "ip", "value": "198.51.100.23", "alert_ids": ["A"]},
                {"type": "ip", "name": "198.51.100.23", "alert_ids": ["B"]}]
        built = evidence.build(rows)
        self.assertEqual(built["count"], 3)  # two processes (two devices), one address
        self.assertEqual(built["entities"][0]["alert_ids"], ["A"])  # a string id is one id, not its characters
        self.assertEqual(built["entities"][2]["alert_ids"], ["A", "B"])

    def test_decisions_surface_a_missing_or_incomplete_inventory(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}], "observations": []}
        self.assertIn("not recorded", triage.decide(ledger)["evidence_inventory_note"])
        ledger["evidence_inventory"] = {"extracted": 28, "source_count": 31, "complete": False}
        self.assertIn("28 of 31", triage.decide(ledger)["evidence_inventory_note"])
        self.assertIn("28 of 31", inv.resolve({"observations": [], "evidence_inventory": ledger["evidence_inventory"]})["evidence_inventory_note"])
        ledger["evidence_inventory"] = {"extracted": 31, "source_count": 31, "complete": True}
        self.assertNotIn("evidence_inventory_note", triage.decide(ledger))


class ProcessChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES, "incident14_evidence.json"), encoding="utf-8") as f:
            cls.live = chain.build(json.load(f))

    def node(self, built, device, pid):
        return next(n for n in built["nodes"] + built["gaps"] if n["device"].lower().startswith(device) and n["pid"] == pid)

    def path(self, node):
        out = [node["pid"]]
        while node.get("parent"):
            node = node["parent"]; out.append(node["pid"])
        return out

    def test_live_incident_builds_one_node_per_process(self):
        s = chain.summary(self.live)
        self.assertEqual((s["process_rows"], s["processes"], s["devices"], s["anomalies"], s["unplaced"]), (20, 18, 5, 0, 0))

    def test_live_chain_links_parents_on_pid_and_creation_time(self):
        self.assertEqual(self.path(self.node(self.live, "enea", 4940)), [4940, 3972, 3308, 5064])
        self.assertEqual(self.path(self.node(self.live, "enea", 1892)), [1892, 3308, 5064])
        top = self.node(self.live, "enea", 5064)
        self.assertFalse(top["in_evidence"]); self.assertEqual(top["names"], ["cmd.exe"])
        # the parent's creation time is reported with a trailing zero dropped (…51.74649Z) and still joins
        self.assertEqual(self.path(self.node(self.live, "enea", 4184)), [4184, 640, 528])

    def test_children_of_one_missing_parent_share_one_gap(self):
        wininit = self.node(self.live, "enea", 528)
        self.assertFalse(wininit["in_evidence"])
        self.assertEqual(sorted(c["pid"] for c in wininit["children"]), [640, 660])

    def test_rows_of_one_process_keep_every_verdict(self):
        wmi = self.node(self.live, "ulisse", 3132)
        self.assertEqual((wmi["rows"], wmi["names"], sorted(wmi["verdicts"])), (2, ["WmiPrvSE.exe"], ["malicious", "suspicious"]))
        self.assertEqual(len(wmi["alert_ids"]), 2)

    def test_every_process_in_the_portal_export_is_a_node(self):
        with open(os.path.join(FIXTURES, "incident14_portal_processes.csv"), encoding="utf-8") as f:
            portal = {(r["Device"].lower(), int(r["Process ID"])) for r in csv.DictReader(f)}
        built = {(n["device"].lower().split(".")[0], n["pid"]) for n in self.live["nodes"]}
        self.assertEqual(built, portal)

    def test_timeline_cites_the_alerts_oldest_first(self):
        entries = chain.timeline(self.live)
        self.assertEqual(len(entries), 18)
        self.assertEqual([e["time"] for e in entries], sorted(e["time"] for e in entries))
        rundll = next(e for e in entries if e["pid"] == 4940)
        self.assertEqual((rundll["parent"], rundll["parent_in_evidence"]), ("cmd.exe", True))
        self.assertTrue(rundll["event_refs"])

    def row(self, pid, created, parent=None, parent_created=None, device="WS-01", **kw):
        return dict(type="process", name=kw.pop("name", f"p{pid}.exe"), pid=pid, created=created, device=device,
                    parent_pid=parent, parent_created=parent_created, alert_ids=kw.pop("alerts", ["A"]), **kw)

    def test_an_unplaced_process_keeps_its_command_line(self):
        # a process the evidence only partly describes reached the executor without what it ran
        built = chain.build([self.row(12, None, name="cmd.exe", command_line="cmd.exe /c vssadmin delete shadows /all")])
        text = chain.as_text(built)
        self.assertIn("unplaced: cmd.exe 12 missing created", text)
        self.assertIn("  $ cmd.exe /c vssadmin delete shadows /all", text)

    def test_an_unplaced_encoded_command_names_its_decoded_script(self):
        encoded = "powershell.exe -EncodedCommand " + "A" * 60
        built = chain.build([self.row(12, None, name="powershell.exe", command_line=encoded,
                                      decoded_command="Get-Process")])
        text = chain.as_text(built)
        self.assertIn("  $ powershell.exe -EncodedCommand \u2039encoded: D1\u203a", text)
        self.assertIn("  decoded: D1", text)
        self.assertIn("run by powershell.exe 12 (unplaced)", text)
        self.assertIn("Get-Process", text)

    def test_a_process_time_is_said_to_be_its_start(self):
        # a system process started at boot sat beside the alert that cited it with a bare time, which a
        # reader took for the alert's time
        built = chain.build([self.row(640, "2026-10-22T14:56:16Z", 528, "2026-10-22T14:56:15Z", name="services.exe")])
        text = chain.as_text(built)
        self.assertIn("services.exe 640 started 2026-10-22T14:56:16Z -  alerts: A1", text)
        self.assertIn("[gap] (unnamed) 528 started 2026-10-22T14:56:15Z: ", text)
        untimed = chain.as_text(chain.build([self.row(640, "2026-10-22T14:56:16Z", 528, name="services.exe")]))
        self.assertIn("[gap] (unnamed) 528 -: parent creation time not reported", untimed)

    def test_every_command_line_of_a_process_is_shown(self):
        rows = [self.row(10, "2026-09-13T12:00:00Z", command_line=f"p10.exe /run {n}") for n in range(3)]
        text = chain.as_text(chain.build(rows))
        for n in range(3):
            self.assertIn(f"$ p10.exe /run {n}", text)

    def test_an_unplaced_command_line_survives_the_ocsf_round_trip(self):
        # the Case keeps the chain in OCSF objects, and its text is rendered again from them
        encoded = "powershell.exe -EncodedCommand " + "A" * 60
        built = chain.build([self.row(12, None, name="cmd.exe", command_line="cmd.exe /c whoami"),
                             self.row(13, None, name="powershell.exe", command_line=encoded,
                                      decoded_command="Get-Process")])
        graph = chain.as_json(built)
        again = chain.render(chain.from_ocsf(chain.as_ocsf(graph, PRODUCT)))
        self.assertEqual(again, chain.render(graph))
        self.assertIn("  $ cmd.exe /c whoami", again)
        self.assertIn("  decoded: D1", again)

    def test_times_match_at_the_coarser_precision(self):
        built = chain.build([self.row(10, "2026-09-13T12:00:00.254123Z"),
                             self.row(11, "2026-09-13T12:00:01Z", 10, "2026-09-13T12:00:00.254Z", device="ws-01")])
        self.assertEqual(self.path(self.node(built, "ws-01", 11)), [11, 10])
        self.assertTrue(self.node(built, "ws-01", 10)["in_evidence"], "device names are compared without case")
        self.assertFalse(chain.same_time(chain.parse_time("2026-09-13T12:00:00.254Z"), chain.parse_time("2026-09-13T12:00:00.255001Z")))
        self.assertTrue(chain.same_time(chain.parse_time("2026-09-13T14:00:00+02:00"), chain.parse_time("2026-09-13T12:00:00Z")))

    def test_a_reused_pid_is_not_the_parent(self):
        built = chain.build([self.row(10, "2026-09-13T08:00:00Z"),  # earlier process with the same PID
                             self.row(11, "2026-09-13T12:00:01Z", 10, "2026-09-13T11:59:59Z")])
        parent = self.node(built, "ws-01", 11)["parent"]
        self.assertFalse(parent["in_evidence"]); self.assertEqual(parent["gap"], "outside the evidence")

    def test_a_parent_without_creation_time_is_a_gap_not_a_pid_match(self):
        built = chain.build([self.row(10, "2026-09-13T08:00:00Z"), self.row(11, "2026-09-13T12:00:01Z", 10)])
        self.assertEqual(self.node(built, "ws-01", 11)["parent"]["gap"], "parent creation time not reported")

    def test_the_same_pid_and_time_on_two_devices_are_two_processes(self):
        built = chain.build([self.row(10, "2026-09-13T08:00:00Z"), self.row(10, "2026-09-13T08:00:00Z", device="WS-02")])
        self.assertEqual(chain.summary(built)["processes"], 2)

    def test_rows_without_device_pid_or_time_are_unplaced(self):
        built = chain.build([self.row(10, "2026-09-13T08:00:00Z", device="?"), self.row(None, "2026-09-13T08:00:00Z"),
                             self.row(12, None)])
        self.assertEqual([u["missing"] for u in built["unplaced"]], [["device"], ["pid"], ["created"]])
        self.assertEqual(built["nodes"], [])

    def test_anomalies_are_reported(self):
        conflict = chain.build([self.row(11, "2026-09-13T12:00:01Z", 10, "2026-09-13T12:00:00Z"),
                                self.row(11, "2026-09-13T12:00:01Z", 9, "2026-09-13T12:00:00Z")])
        self.assertIn("different parents", conflict["anomalies"][0])
        early = chain.build([self.row(10, "2026-09-13T12:00:05Z"), self.row(11, "2026-09-13T12:00:01Z", 10, "2026-09-13T12:00:05Z")])
        self.assertIn("created before its parent", early["anomalies"][0])
        loop = chain.build([self.row(10, "2026-09-13T12:00:00Z", 11, "2026-09-13T12:00:00Z"),
                            self.row(11, "2026-09-13T12:00:00Z", 10, "2026-09-13T12:00:00Z")])
        self.assertTrue(any("loop" in a for a in loop["anomalies"]))
        self.assertEqual(len(chain.as_json(loop)["timeline"]), 2)

    def test_the_legend_labels_every_alert_citing_a_process_once(self):
        labels = chain.legend(self.live)
        self.assertEqual(len(labels), 28)  # of the incident's 32 alerts; the others cite no process
        self.assertEqual([a["label"] for a in labels], [f"A{n}" for n in range(1, 29)])
        cited = {a for n in self.live["nodes"] if n["in_evidence"] for a in n["alert_ids"]}
        self.assertEqual({a["alert_id"] for a in labels}, cited)

    def test_each_process_names_its_alerts_by_label(self):
        built = chain.build([self.row(10, "2026-09-13T12:00:00Z", alerts=["A"]),
                             self.row(11, "2026-09-13T12:00:01Z", 10, "2026-09-13T12:00:00Z", alerts=["A"]),
                             self.row(12, "2026-09-13T12:00:02Z", 11, "2026-09-13T12:00:01Z", alerts=["B", "A"])])
        text = chain.as_text(built, {"A": {"title": "Suspicious PowerShell"}, "B": {"title": "Credential theft"}})
        self.assertIn("A1   A  Suspicious PowerShell", text)
        self.assertIn("A2   B  Credential theft", text)
        self.assertIn("p12.exe 12 started 2026-09-13T12:00:02Z -  alerts: A1 A2", text)
        self.assertNotIn("context:", text, "no per-alert view: every process is in the one tree")
        self.assertEqual(text.count("p10.exe 10"), 1, "every process once")

    def test_the_text_is_one_tree_per_device(self):
        text = chain.as_text(self.live)
        self.assertEqual(text.count("[gap]"), len(self.live["gaps"]))
        for node in self.live["nodes"]:
            name = node["names"][0] if node["names"] else "(unnamed)"
            self.assertEqual(text.count(f"{name} {node['pid']} started {node['created']}"), 1, f"{name} {node['pid']}")

    def test_accepts_the_inventory_output_and_renders_the_label(self):
        inventory = evidence.build([self.row(10, "2026-09-13T08:00:00Z"), self.row(10, "2026-09-13T08:00:00Z", alerts=["B"])])
        built = chain.build(inventory)
        self.assertEqual(chain.summary(built)["processes"], 1)
        self.assertTrue(chain.as_text(built).startswith("evidence-only chain: 1 processes"))
        self.assertEqual(chain.as_json(self.live)["process_chain"]["label"], "evidence-only chain")


class ProcessChainTelemetry(unittest.TestCase):
    """The second binding: a deployment whose endpoint class carries process telemetry, so the
    ancestors the alerts never cited are reconstructed instead of left as gaps."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES, "winrm_case_evidence.json"), encoding="utf-8") as f:
            cls.evidence = json.load(f)
        with open(os.path.join(FIXTURES, "winrm_case_telemetry.json"), encoding="utf-8") as f:
            cls.telemetry = json.load(f)
        cls.without = chain.build(cls.evidence)
        cls.with_ = chain.build(cls.evidence, cls.telemetry)

    def node(self, built, pid):
        return next(n for n in built["nodes"] + built["gaps"] if n["pid"] == pid)

    def test_without_telemetry_the_ancestors_are_gaps(self):
        s = chain.summary(self.without)
        self.assertEqual((s["label"], s["processes"], s["from_telemetry"], s["lineage_gaps"]),
                         ("evidence-only chain", 33, 0, 9))

    def test_with_telemetry_the_gaps_are_filled_up_to_the_window(self):
        s = chain.summary(self.with_)
        self.assertEqual((s["label"], s["processes"], s["from_the_evidence"], s["from_telemetry"]),
                         ("chain from evidence and telemetry", 45, 33, 12))
        self.assertEqual(s["lineage_gaps"], 2, "a process created before the telemetry window stays a gap")
        self.assertEqual(self.node(self.with_, 676)["gap"], "outside the evidence and the telemetry")

    def test_a_filled_ancestor_carries_its_command_line_and_its_own_parent(self):
        winrs = self.node(self.with_, 2772)
        self.assertEqual((winrs["source"], winrs["in_evidence"], winrs["names"]), ("telemetry", False, ["winrshost.exe"]))
        self.assertEqual(winrs["command_lines"], ["WinrsHost.exe -Embedding"])
        self.assertEqual(winrs["parent"]["pid"], 948, "linked to the svchost the alerts did cite")
        self.assertEqual([c["pid"] for c in winrs["children"]], [5316])

    def test_the_lineage_of_an_alerted_process_reaches_the_service_host(self):
        path, node = [], self.node(self.with_, 3664)  # the alerted PowerShell
        while node:
            path.append((node["pid"], node["source"]))
            node = node.get("parent")
        self.assertEqual(path, [(3664, "evidence"), (3424, "telemetry"), (5316, "telemetry"),
                                (2772, "telemetry"), (948, "evidence"), (816, "telemetry"), (676, "missing")])

    def test_telemetry_of_unrelated_processes_is_not_pulled_into_the_chain(self):
        self.assertEqual(len(self.with_["nodes"]), 45, "only the ancestors of the Case's processes are added")

    def test_the_script_itself_names_no_column_of_any_source(self):
        with open(os.path.join(ROOT, "tools", "shared", "process_chain.py"), encoding="utf-8") as f:
            text = f.read()
        for spelling in ("InitiatingProcess", "ProcessCreationTime", "DeviceName", "initiatingprocess"):
            self.assertNotIn(spelling, text, "a method script knows no source: the profile names its columns")

    def test_without_a_profile_a_sources_own_column_names_are_not_known(self):
        rows = [{"DeviceName": "WS-01", "ProcessId": 10, "ProcessCreationTime": "2026-09-13T12:00:00Z",
                 "FileName": "parent.exe", "ProcessCommandLine": "parent.exe"}]
        evidence = [{"type": "process", "name": "child.exe", "pid": 11, "created": "2026-09-13T12:00:01Z",
                     "device": "ws-01", "parent_pid": 10, "parent_created": "2026-09-13T12:00:00Z",
                     "parent_name": "parent.exe", "alert_ids": ["A"]}]
        self.assertNotEqual(self.node(chain.build(evidence, rows), 10)["source"], "telemetry")
        named = chain.columns_of(profiles.load(XDR_PROFILE))
        self.assertEqual(self.node(chain.build(evidence, rows, named), 10)["source"], "telemetry")

    def test_telemetry_that_fills_nothing_says_so(self):
        import subprocess, sys, tempfile
        base = tempfile.mkdtemp()
        for name, document in (("evidence.json", [{"type": "process", "name": "c.exe", "pid": 11, "device": "ws-01",
                                                    "created": "2026-09-13T12:00:01Z", "alert_ids": ["A"]}]),
                               ("telemetry.json", [{"DeviceName": "WS-01", "ProcessId": 10,
                                                     "ProcessCreationTime": "2026-09-13T12:00:00Z"}])):
            with open(os.path.join(base, name), "w", encoding="utf-8") as f:
                json.dump(document, f)
        script = os.path.join(ROOT, "tools", "shared", "process_chain.py")
        ran = subprocess.run([sys.executable, script, "evidence.json", "--telemetry", "telemetry.json"],
                             cwd=base, capture_output=True, text=True)
        self.assertIn("filled nothing", ran.stderr)
        ran = subprocess.run([sys.executable, script, "evidence.json", "--telemetry", "telemetry.json",
                              "--profile", XDR_PROFILE], cwd=base, capture_output=True, text=True)
        self.assertNotIn("filled nothing", ran.stderr)

    def test_the_profile_names_every_column_the_lineage_is_rebuilt_from(self):
        lineage = profiles.telemetry_rows(profiles.load(XDR_PROFILE))["process_lineage"]
        self.assertEqual(set(lineage), set(chain.LINEAGE))

    def test_source_column_names_are_accepted(self):
        rows = [{"DeviceName": "WS-01", "ProcessId": 11, "ProcessCreationTime": "2026-09-13T12:00:01Z",
                 "FileName": "child.exe", "ProcessCommandLine": "child.exe -run",
                 "InitiatingProcessId": 10, "InitiatingProcessCreationTime": "2026-09-13T12:00:00Z",
                 "InitiatingProcessFileName": "parent.exe", "InitiatingProcessCommandLine": "parent.exe",
                 "InitiatingProcessParentId": 4, "InitiatingProcessParentCreationTime": "2026-09-13T11:00:00Z"}]
        evidence = [{"type": "process", "name": "child.exe", "pid": 11, "created": "2026-09-13T12:00:01Z",
                     "device": "ws-01", "parent_pid": 10, "parent_created": "2026-09-13T12:00:00Z",
                     "parent_name": "parent.exe", "alert_ids": ["A"]}]
        built = chain.build(evidence, rows, chain.columns_of(profiles.load(XDR_PROFILE)))
        parent = self.node(built, 10)
        self.assertEqual((parent["source"], parent["command_lines"]), ("telemetry", ["parent.exe"]))
        self.assertEqual(parent["parent"]["pid"], 4, "the row's grandparent columns add one more level")

    def test_the_text_view_points_an_encoded_command_to_its_script(self):
        text = chain.as_text(self.with_)
        self.assertIn("$ WinrsHost.exe -Embedding", text)
        self.assertIn("[telemetry]", text)
        self.assertRegex(text, r"\[telemetry\] \S+ \d+ started \d{4}-\d\d-\d\dT")
        self.assertIn("-EncodedCommand ‹encoded: D1›", text)
        self.assertNotIn("UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAg", text)
        commands = [line for line in text.splitlines() if line.strip().startswith("$ ")]
        self.assertTrue(all(len(line) < 200 for line in commands), "command lines are cut in the text view")
        whole = json.dumps(chain.as_json(self.with_))
        self.assertIn("EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAg", whole,
                      "the JSON keeps the whole command line")

    def test_width_controls_where_a_command_is_cut_and_scripts_stay_whole(self):
        whole = chain.as_text(self.with_, width=0)
        self.assertFalse([line for line in whole.splitlines() if line.strip().startswith("$ ") and line.endswith("…")])
        narrow = chain.as_text(self.with_, width=60)
        commands = [line.strip() for line in narrow.splitlines() if line.strip().startswith("$ ")]
        self.assertTrue(commands)
        self.assertTrue(all(len(line) <= 70 for line in commands), "only the commands answer to --width")
        self.assertEqual(narrow.split("scripts:")[1], whole.split("scripts:")[1], "a decoded script is never cut")

    def test_a_decoded_command_is_read_as_a_script_once(self):
        text = chain.as_text(self.with_)
        self.assertIn("decoded: D1", text)
        scripts = text.split("scripts:")[1]
        self.assertTrue(any(line.strip().startswith("if ($PSVersionTable") for line in scripts.splitlines()),
                        "the decoding keeps its own lines instead of being flattened")
        graph = chain.as_json(self.with_)
        contents = [s["script_content"] for s in graph["scripts"]]
        self.assertEqual(len(contents), len(set(contents)), "each decoded command once")
        self.assertTrue(all(s["type"] == "PowerShell" and s["type_id"] == 2 for s in graph["scripts"]))

    def test_layers_of_encoding_are_named_in_the_chain(self):
        rows = [{"type": "process", "name": "powershell.exe", "pid": 10, "created": "2026-09-13T12:00:00Z",
                 "device": "ws-01", "alert_ids": ["A"], "command_line": "powershell -enc AAAA",
                 "decoded_command": "whoami", "decode_rounds": 3, "decode_capped": True}]
        text = chain.as_text(chain.build(rows))
        self.assertIn("decoded: D1 (3 layers of encoding, still encoded)", text)
        self.assertIn("      whoami", text.split("scripts:")[1])
        plain = [dict(rows[0], decode_rounds=None, decode_capped=None)]
        self.assertIn("  decoded: D1\n", chain.as_text(chain.build(plain)) + "\n")

    def test_the_json_keeps_the_attributes_a_note_cites(self):
        document = chain.as_json(self.with_)
        alerted = [p for p in document["processes"] if p["source"] == "evidence" and p.get("attributes")]
        self.assertTrue(alerted)
        self.assertTrue(set().union(*(p["attributes"] for p in alerted)) >= {"sha256", "path", "account"})
        self.assertTrue(any(p["cmd_line"] for p in document["processes"]))
        self.assertTrue(all(e["uid"] for e in document["timeline"]))

    def test_the_json_holds_each_process_once_keyed_as_the_evidence_rows(self):
        document = chain.as_json(self.with_)
        uids = [p["uid"] for p in document["processes"]]
        self.assertEqual(len(uids), len(set(uids)), "each process once")
        rows = {f"{r['device']}|{r['pid']}|{r['created']}" for r in self.evidence if r.get("type") == "process"}
        cited = {p["uid"] for p in document["processes"] if p["source"] == "evidence"}
        self.assertLessEqual(cited, rows, "an evidence process joins its row on device, PID and creation time")
        known = set(uids) | {g["uid"] for g in document["gaps"]}
        parents = {p["parent_process"]["uid"] for p in document["processes"] if p["parent_process"]}
        self.assertLessEqual(parents, known, "a parent is a process or a gap of the graph")
        self.assertNotIn("tree", json.dumps(document["devices"]), "no nested copies")

    def test_the_text_renders_again_from_a_stored_graph(self):
        stored = json.loads(json.dumps(chain.as_json(self.with_)))
        self.assertEqual(chain.render(stored), chain.as_text(self.with_))

    def test_the_case_keeps_the_chain_as_ocsf_events(self):
        observation = chain.as_ocsf(chain.as_json(self.with_), PRODUCT)
        events = observation["events"]
        launches = {e["metadata"]["uid"]: e for e in events if e["type_uid"] == 100701}
        alerts = [e for e in events if e["type_uid"] == 200401]
        self.assertEqual(len(launches), 45, "a launch per process, the ones telemetry filled in included")
        self.assertEqual([a["metadata"]["uid"] for a in alerts], [a["alert_id"] for a in chain.legend(self.with_)])
        powershell = next(e for e in launches.values() if e["process"]["pid"] == 3664)
        self.assertEqual([p["pid"] for p in powershell["process"]["ancestry"]], [3424, 5316, 2772, 948, 816, 676],
                         "the extended parentage, the direct parent first")
        self.assertEqual(powershell["process"]["parent_process"]["pid"], 3424)
        self.assertEqual(powershell["actor"]["process"]["pid"], 3424, "the process that launched it")
        named = {a["process"]["uid"] for alert in alerts for a in alert["evidences"]}
        self.assertIn(powershell["metadata"]["uid"], named)
        filled = {uid for uid in launches if uid not in named}
        self.assertEqual(len(filled), 12, "the processes telemetry filled in: no alert's evidence names them")
        gap = self.node(self.with_, 676)
        self.assertNotIn(f"{gap['device']}|676|{gap['created']}", launches, "a gap is only named as a parent")
        scripts = [e for e in events if e["type_uid"] == 100901]
        self.assertTrue(scripts and all(e["script"]["type_id"] == 2 and e["script"]["script_content"] for e in scripts))
        self.assertTrue(all(e["actor"]["process"]["uid"] in launches for e in scripts), "run by a process the chain holds")
        self.assertEqual(observation["desc"].splitlines()[0], chain.as_text(self.with_).splitlines()[0])

    def test_the_text_renders_again_from_the_stored_observation(self):
        with open(os.path.join(FIXTURES, "incident14_evidence.json"), encoding="utf-8") as f:
            live = chain.build(json.load(f))
        odd = chain.build([{"type": "process", "name": "a.exe", "pid": 11, "created": "2026-09-13T12:00:01Z", "device": "ws-01",
                            "parent_pid": 10, "parent_created": "2026-09-13T12:00:00Z", "alert_ids": ["A"]},
                           {"type": "process", "name": "a.exe", "pid": 11, "created": "2026-09-13T12:00:01Z", "device": "ws-01",
                            "parent_pid": 9, "parent_created": "2026-09-13T12:00:00Z", "alert_ids": ["A"]},
                           {"type": "process", "name": "b.exe", "pid": 12, "device": "ws-01", "alert_ids": ["A"]}])
        self.assertTrue(odd["anomalies"] and odd["unplaced"])
        for built in (self.with_, self.without, live, odd):
            stored = json.loads(json.dumps(chain.as_ocsf(chain.as_json(built), PRODUCT)))
            self.assertEqual(chain.render(chain.from_ocsf(stored)), chain.as_text(built))
            self.assertEqual(chain.as_ocsf(chain.from_ocsf(stored), PRODUCT), stored, "what is kept is read back whole")

    def test_the_script_writes_and_reads_the_stored_observation(self):
        import subprocess, sys, tempfile
        base = tempfile.mkdtemp()
        with open(os.path.join(base, "evidence.json"), "w", encoding="utf-8") as f:
            json.dump(self.evidence, f)
        script = os.path.join(ROOT, "tools", "shared", "process_chain.py")

        def run(*args):
            return subprocess.run([sys.executable, script, *args], cwd=base, capture_output=True, text=True, check=True).stdout

        with open(os.path.join(base, "observation.json"), "w", encoding="utf-8") as f:
            f.write(run("evidence.json", "--ocsf", f"--profile={XDR_PROFILE}"))
        self.assertEqual(run("--from-graph", "observation.json"), run("evidence.json"))
        with open(os.path.join(base, "observation.json"), encoding="utf-8") as f:
            kept = json.load(f)
        # the kept events name their product, so reading them back needs no profile
        self.assertEqual(json.loads(run("--from-graph", "observation.json", "--ocsf")), kept)
        self.assertEqual({e["metadata"]["product"]["name"] for e in kept["events"]}, {"Microsoft Defender XDR"})
        refused = subprocess.run([sys.executable, script, "evidence.json", "--ocsf"], cwd=base, capture_output=True, text=True)
        self.assertEqual(refused.returncode, 2, "an event names the product that reported it, which only a profile says")
        self.assertIn("--profile", refused.stderr)

    def test_one_script_shared_by_two_processes_is_printed_once(self):
        rows = [{"type": "process", "name": "powershell.exe", "pid": pid, "created": created, "device": "ws-01",
                 "alert_ids": ["A"], "command_line": "powershell -enc " + "A" * 60, "decoded_command": "Get-Process"}
                for pid, created in ((10, "2026-09-13T12:00:00Z"), (11, "2026-09-13T12:00:05Z"))]
        text = chain.as_text(chain.build(rows))
        self.assertEqual(text.count("Get-Process"), 1)
        self.assertEqual(text.count("decoded: D1"), 2)
        self.assertIn("run by powershell.exe 10, powershell.exe 11", text)


class ChainKeptAsEvents(unittest.TestCase):
    """The chain as the Case keeps it (framework DD-30): the Observation cites, and the events are OCSF events of
    their own class. A small chain with every kind of entry: a root whose parent no row names, a process two
    alerts cite with different rows, a decoded command, a gap, an unplaced row and the source's state."""

    ALERTS = {"da-1": {"title": "Suspicious PowerShell", "severity": "high", "created_time": 1757761500000},
              "da-2": {"title": "Whoami run from a script", "severity": "medium", "created_time": 1757761560000}}

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES, "chain_small_evidence.json"), encoding="utf-8") as f:
            cls.rows = json.load(f)
        cls.built = chain.build(cls.rows)
        cls.kept = json.loads(json.dumps(chain.as_ocsf(chain.as_json(cls.built, cls.ALERTS), PRODUCT)))
        cls.events = {e["metadata"]["uid"]: e for e in cls.kept["events"]}

    def launch(self, pid):
        return next(e for e in self.kept["events"] if e["type_uid"] == 100701 and e["process"].get("pid") == pid)

    def test_every_event_is_what_ocsf_requires_of_its_class(self):
        classes = {1007: "process_activity", 1009: "script_activity", 2004: "detection_finding"}
        with open(os.path.join(FIXTURES, "winrm_case_evidence.json"), encoding="utf-8") as f:
            evidence = json.load(f)
        with open(os.path.join(FIXTURES, "winrm_case_telemetry.json"), encoding="utf-8") as f:
            larger = chain.as_ocsf(chain.as_json(chain.build(evidence, json.load(f))), PRODUCT)
        for kept in (self.kept, larger):
            for event in kept["events"]:
                uid = event["metadata"]["uid"]
                self.assertEqual(event["type_uid"], event["class_uid"] * 100 + event["activity_id"])
                self.assertEqual(event["metadata"]["version"], OCSF["ocsf_version"])
                # what the evidence does not say is not made up: a root no row names a parent of has no actor,
                # an unplaced row no time or device, and an alert alerts.json gives no time none either
                said = {f"{uid}.{k}" for k in ("actor", "time", "device")}
                lacks = ocsf_lacks(event, classes[event["class_uid"]], uid)
                self.assertEqual([gap for gap in lacks if gap not in said], [], uid)
        self.assertNotIn("actor", self.launch(100), "no row names explorer.exe's parent")
        timed = [e for e in self.kept["events"] if e["type_uid"] == 200401 and e["metadata"]["uid"] in self.ALERTS]
        self.assertTrue(timed and all("time" in e for e in timed), "an alert alerts.json gives a time to has it")

    def test_a_citation_names_an_event_and_says_what_and_when_it_was(self):
        citations = self.kept["related_events"]
        self.assertEqual(sorted(c["uid"] for c in citations), sorted(self.events), "each event cited once")
        for c in citations:
            event = self.events[c["uid"]]
            self.assertLessEqual(set(c), {"uid", "type_uid", "type_name", "title", "first_seen_time"})
            self.assertEqual((c["type_uid"], c["type_name"]), (event["type_uid"], event["type_name"]))
            self.assertEqual(c.get("first_seen_time"), event.get("time"))
            self.assertEqual(ocsf_lacks(c, "related_event", c["uid"]), [])

    def test_an_alert_names_each_process_as_its_rows_reported_it(self):
        whoami = self.events["da-2"]
        self.assertEqual((whoami["severity_id"], whoami["time"], whoami["finding_info"]),
                         (3, 1757761560000, {"uid": "da-2", "title": "Whoami run from a script"}))
        named = [(a["process"]["pid"], a.get("verdict"), a["process"].get("cmd_line", "")[:25], a.get("data"))
                 for a in whoami["evidences"]]
        self.assertEqual(named, [
            (200, "malicious", "powershell.exe -EncodedCo", {"remediation_status": "remediated", "detection_status": "detected"}),
            (200, "suspicious", "powershell.exe -NoProfile", None),
            (300, "unknown", "cmd.exe /c whoami", None),
        ])
        self.assertTrue(all(a["verdict_id"] == 99 for a in whoami["evidences"]), "the source's own word, as Other")
        shared = {a["uid"] for a in self.events["da-1"]["evidences"]} & {a["uid"] for a in whoami["evidences"]}
        self.assertEqual(len(shared), 1, "a row both alerts cite is one row")

    def test_a_decoded_command_is_a_script_activity_its_process_ran(self):
        powershell = self.launch(200)
        (run,) = [e for e in self.kept["events"] if e["type_uid"] == 100901]
        self.assertEqual(run["actor"]["process"]["uid"], powershell["metadata"]["uid"])
        self.assertEqual((run["script"]["type"], run["script"]["script_content"]), ("PowerShell", "Get-Process; whoami"))
        self.assertEqual(run["time"], powershell["time"])
        (decoded,) = powershell["enrichments"]
        self.assertEqual((decoded["name"], decoded["type"], decoded["data"]),
                         ("process.cmd_line", "decoded command", {"script_uid": run["script"]["uid"], "decode_rounds": 2}))

    def test_a_launch_names_the_process_that_launched_it(self):
        self.assertEqual(self.launch(200)["actor"]["process"]["name"], "explorer.exe")
        cmd = self.launch(300)
        self.assertEqual((cmd["actor"]["process"]["pid"], cmd["actor"]["process"]["name"]), (250, "conhost.exe"),
                         "a parent the evidence does not show, with what is known of it")
        self.assertNotIn("ws-02|250|2026-09-13T11:05:30Z", self.events, "a gap is no event of its own")

    def test_what_ocsf_s_process_has_no_attribute_for_is_in_its_extended_attributes(self):
        powershell = self.launch(200)
        process = powershell["process"]
        self.assertEqual(process["user"], {"name": "lab\\anna", "uid": "S-1-5-21-1001", "email_addr": "anna@lab.local"})
        self.assertEqual(powershell["device"], {"hostname": "ws-02", "type_id": 0, "uid": "2f7c0a"})
        self.assertEqual(process["xattributes"]["token_elevation"], "TokenElevationTypeFull")
        self.assertEqual(len(process["xattributes"]["cmd_lines"]), 2, "every command line the rows gave it")
        self.assertEqual(process["file"]["hashes"], [{"algorithm_id": 3, "algorithm": "SHA-256", "value": "ab" * 32}])

    def test_an_alert_that_cites_only_an_unplaced_process_has_no_label(self):
        unplaced = self.events["da-3"]
        self.assertEqual([a["process"]["uid"] for a in unplaced["evidences"]], ["unplaced:1"])
        again = chain.from_ocsf(self.kept)
        self.assertEqual([a["alert_id"] for a in again["alerts"]], ["da-1", "da-2"])
        self.assertEqual(again["unplaced"][0]["alert_ids"], ["da-3"])

    def test_the_kept_chain_renders_and_reads_back_whole(self):
        self.assertEqual(chain.render(chain.from_ocsf(self.kept)), chain.as_text(self.built, self.ALERTS))
        self.assertEqual(chain.as_ocsf(chain.from_ocsf(self.kept), PRODUCT), self.kept)

    def test_a_chain_kept_before_its_events_renders_as_it_did(self):
        # written by the script before framework DD-30: each process on its citation
        with open(os.path.join(FIXTURES, "chain_kept_before_dd30.json"), encoding="utf-8") as f:
            legacy = json.load(f)
        self.assertNotIn("events", legacy)
        alerts = {k: {"title": v["title"]} for k, v in self.ALERTS.items()}
        self.assertEqual(chain.render(chain.from_ocsf(legacy)), chain.as_text(self.built, alerts))

class RunCheck(unittest.TestCase):
    """The acceptance harness for a live run: it must catch a ledger that reports what it did not do."""

    def run_dir(self, **overrides):
        import tempfile
        base = tempfile.mkdtemp()
        rows = [{"type": "device", "name": "ws-01", "alert_ids": ["A1"]},
                {"type": "process", "name": "cmd.exe", "pid": 5120, "created": "2026-09-14T14:55:41Z",
                 "device": "ws-01", "alert_ids": ["A1"]}]
        ledger = {"case_uid": "CASE-1", "severity": "High", "started_at": "2026-09-14T15:00:00Z",
                  "resolved_at": "2026-09-14T15:06:00Z",
                  "evidence_inventory": {"extracted": 2, "source_count": 2, "complete": True},
                  "detection_metadata": {
                      "alerts": [{"id": "A1", "techniques": [{"id": "T1003", "rendered": "T1003 (OS Credential Dumping)"}],
                                  "threat": {"name": "HackTool:Win32/Mimikatz", "family": "Mimikatz"},
                                  "detection": {"source": "antivirus", "analytic_type_id": 5, "analytic_type": "Fingerprinting"},
                                  "description": "d", "absent": [],
                                  "recommended_actions": [{"id": "RA1", "action": "Run a full scan",
                                                           "disposition": "followed", "observation": "1"}]}],
                      "remediation": [], "visibility_gaps": []},
                  "observations": [{"id": "O1", "side": "Malicious", "confidence": "High", "at": "2026-09-14T15:01:00Z",
                                "alert_type": "Credential dumping", "entity": "ws-01"}]}
        ledger.update(overrides)
        alerts = [{"id": "A1", "title": "Possible credential dumping (LSASS)", "entity": "ws-01",
                   "alert_type": "Credential dumping", "mitreTechniques": ["T1003"], "threatDisplayName": "HackTool:Win32/Mimikatz",
                   "threatFamilyName": "Mimikatz", "detectionSource": "antivirus",
                   "description": "A process read credential material from LSASS.",
                   "recommendedActions": "Run a full scan"}]
        for name, document in (("evidence.json", rows), ("alerts.json", alerts),
                               ("ledger.triage.json", ledger), ("ledger.investigation.json", ledger)):
            with open(os.path.join(base, name), "w", encoding="utf-8") as f:
                json.dump(document, f)
        return base

    def check(self, base):
        import io, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = checker.main_for_test(base)
        return code, out.getvalue()

    def test_a_faithful_run_passes(self):
        code, out = self.check(self.run_dir())
        self.assertEqual(code, 0, out)
        self.assertIn("ok    triage: extracted count matches the evidence", out)

    def test_a_run_that_never_read_what_the_detection_asserts_fails(self):
        code, out = self.check(self.run_dir(detection_metadata=None))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  triage: what the detection asserts is on the ledger", out)

    def test_a_recommended_action_nobody_acted_on_is_reported_and_does_not_fail_the_run(self):
        """§1.5: what a source recommends is indicative. This once failed the run; on a source that
        publishes its procedure per alert that is a checklist rather than a check. What the run did
        with them is reported, so a reader can see it, and nothing is required of it."""
        base = self.run_dir()
        with open(os.path.join(base, "ledger.triage.json"), encoding="utf-8") as f:
            ledger = json.load(f)
        ledger["detection_metadata"]["alerts"][0]["recommended_actions"].append({"id": "RA2", "action": "Check other devices"})
        with open(os.path.join(base, "ledger.triage.json"), "w", encoding="utf-8") as f:
            json.dump(ledger, f)

        code, out = self.check(base)

        self.assertEqual(code, 0)
        self.assertIn("note  triage: recommended actions", out)
        self.assertIn("published across the Case's alerts", out)

    def test_a_ledger_claiming_an_assertion_its_alerts_do_not_carry_fails(self):
        """The assertions are recomputed from the run's own alerts: the ledger does not get to
        state a technique or a threat name the source never sent."""
        base = self.run_dir()
        with open(os.path.join(base, "ledger.triage.json"), encoding="utf-8") as f:
            ledger = json.load(f)
        ledger["detection_metadata"]["alerts"][0]["techniques"].append(
            {"id": "T1486", "rendered": "T1486 (Data Encrypted for Impact)"})
        with open(os.path.join(base, "ledger.triage.json"), "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        code, out = self.check(base)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  triage: the assertions are the ones the alerts carry", out)
        self.assertIn("T1486", out)

    def test_a_deployment_without_a_source_profile_degrades_and_is_not_failed(self):
        """§1.1 runs where the binding names no source profile: nothing declares where this
        source's assertions live, so they cannot be read at all, and the harness says so instead of
        failing the run for it."""
        base = self.run_dir(detection_metadata=None)
        with open(os.path.join(base, "zerosoc.capabilities.json"), "w", encoding="utf-8") as f:
            json.dump({"capabilities": {}, "data_sources": {}}, f)
        code, out = self.check(base)
        self.assertIn("skip  triage: what the detection asserts is on the ledger", out)
        self.assertNotIn("FAIL  triage: what the detection asserts is on the ledger", out)

    def test_an_absent_assertion_is_noted_and_fails_nothing(self):
        base = self.run_dir()
        with open(os.path.join(base, "ledger.triage.json"), encoding="utf-8") as f:
            ledger = json.load(f)
        ledger["detection_metadata"]["alerts"][0]["absent"] = ["recommended actions"]
        with open(os.path.join(base, "ledger.triage.json"), "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        _, out = self.check(base)
        self.assertIn("note  triage: assertions the source did not supply — recommended actions", out)
        self.assertFalse([line for line in out.splitlines() if line.startswith("FAIL") and "did not supply" in line])

    def test_an_invalid_ledger_is_a_failed_check(self):
        base = self.run_dir()
        for name in ("ledger.triage.json", "ledger.investigation.json"):
            with open(os.path.join(base, name), encoding="utf-8") as f:
                ledger = json.load(f)
            ledger.update(no_information_refs=["EVT-1"], scoped_negative_refs=["EVT-1"])
            ledger["evidence_inventory"]["source_count_basis"] = "reproduced"
            with open(os.path.join(base, name), "w", encoding="utf-8") as f:
                json.dump(ledger, f)
        code, out = self.check(base)
        self.assertEqual(code, 1)
        self.assertIn("invalid ledger: a reference is listed both", out)
        self.assertIn("unknown source count basis", out)

    def test_an_inventory_the_evidence_does_not_support_fails(self):
        code, out = self.check(self.run_dir(evidence_inventory={"extracted": 31, "source_count": 31, "complete": True}))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  triage: extracted count matches the evidence", out)

    def test_a_declared_timebox_fails(self):
        base = self.run_dir()
        with open(os.path.join(base, "ledger.investigation.json"), encoding="utf-8") as f:
            ledger = json.load(f)
        del ledger["started_at"]
        ledger["timebox_expired"] = False
        with open(os.path.join(base, "ledger.investigation.json"), "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        code, out = self.check(base)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  timebox: measured, not declared", out)

    def test_a_gap_the_binding_implies_but_the_run_does_not_record_fails(self):
        base = self.run_dir(domain="Endpoint", visibility_gaps=[
            {"data_source": "EDR / endpoint process telemetry", "check_prevented": "process lineage"}])
        with open(os.path.join(ROOT, "capabilities", "zerosoc.capabilities.defender-for-business.json"),
                  encoding="utf-8") as f:
            binding = json.load(f)
        with open(os.path.join(base, "zerosoc.capabilities.json"), "w", encoding="utf-8") as f:
            json.dump(binding, f)
        code, out = self.check(base)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  triage: every source the binding marks unavailable is a recorded gap", out)
        self.assertIn("file-integrity monitoring", out.lower())

    def test_a_visibility_gap_does_not_touch_the_confidence(self):
        gaps = [{"data_source": "EDR / endpoint process telemetry", "check_prevented": "process lineage"}]
        code, out = self.check(self.run_dir(visibility_gaps=gaps))
        self.assertEqual(code, 0, out)
        self.assertIn("ok    triage: visibility gaps recorded — 1 in the ledger", out)

    def test_one_observation_counted_twice_fails(self):
        doubled = [{"id": "O1", "side": "Malicious", "confidence": "High", "at": "2026-09-14T15:01:00Z",
                    "alert_type": "Credential dumping", "entity": "ws-01"},
                   {"id": "O2", "side": "Malicious", "confidence": "High", "at": "2026-09-14T15:02:00Z",
                    "alert_type": "credential dumping", "entity": "WS-01"}]
        code, out = self.check(self.run_dir(observations=doubled))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  investigation: no alert counted twice", out)

    def test_the_two_ledger_shapes_are_both_read(self):
        """Triage records the Case's alerts in "alerts"; investigation scores them among "observations"."""
        alerts = [{"id": "A1", "type": "Credential dumping", "entity": "ws-01", "confidence": "High"},
                  {"id": "A2", "type": "credential dumping", "entity": "WS-01", "confidence": "Low"}]
        code, out = self.check(self.run_dir(alerts=alerts, observations=[]))
        self.assertIn("FAIL  triage: no alert counted twice", out)
        self.assertEqual(code, 1)
        one = self.run_dir(alerts=alerts[:1], observations=[])
        code, out = self.check(one)
        self.assertIn("ok    triage: the Case's alerts carry type and entity", out)
        self.assertNotIn("skip  triage: the Case's alerts", out)


class BindingProfiles(unittest.TestCase):
    def setUp(self):
        import json
        with open(DFB_PROFILE, encoding="utf-8") as f:
            self.profile = json.load(f)

    def test_profile_has_the_binding_shape(self):
        self.assertTrue(all(isinstance(v, bool) for v in self.profile["data_sources"].values()))
        self.assertTrue(all("tool" in v for v in self.profile["capabilities"].values()))
        self.assertTrue(set(self.profile.get("data_source_notes", {})) <= set(self.profile["data_sources"]))

    def test_every_playbook_data_source_is_answered(self):
        required = set()
        for book in selector.load_playbooks(os.path.join(ROOT, "framework")):
            req = book["fields"].get("required_data_sources", []) or []
            required.update([req] if isinstance(req, str) else req)
        missing = sorted(r for r in required - PLACEHOLDER_SOURCES if r not in self.profile["data_sources"] and not r.startswith("Depends on"))
        self.assertEqual(missing, [])

    def test_endpoint_triage_reports_real_gaps_not_unbound(self):
        books = selector.load_playbooks(os.path.join(ROOT, "framework"))
        endpoint = next(b for b in books if str(b["fields"].get("domain", "")).lower() == "endpoint")
        g = {x["data_source"]: x for x in selector.gaps(endpoint["fields"], self.profile)}
        self.assertNotIn("unbound", {x["status"] for x in g.values()})
        self.assertEqual(g["EDR / endpoint process telemetry"]["status"], "unavailable")
        self.assertIn("alert evidence", g["EDR / endpoint process telemetry"]["reason"])
        self.assertEqual(g["Anti-virus / anti-malware"]["status"], "available")

    def test_open_search_is_not_bound_and_the_case_store_is(self):
        # hunting answers the identity table at this licence, but none of the activity tables a search runs over
        self.assertIn("cases.store", self.profile["capabilities"])
        self.assertNotIn("siem.search", self.profile["capabilities"])


class Procedures(unittest.TestCase):
    def read(self, skill):
        with open(os.path.join(ROOT, "skills", skill, "SKILL.md"), encoding="utf-8") as f:
            return f.read()

    def test_triage_extracts_the_evidence_inventory_and_the_chain_before_the_ledger(self):
        text = self.read("zerosoc-triage")
        self.assertIn("scripts/evidence_inventory.py", text)
        self.assertIn("scripts/process_chain.py", text)
        self.assertLess(text.index("evidence_inventory.py"), text.index("process_chain.py"))
        self.assertLess(text.index("process_chain.py"), text.index("Start the ledger"))

    def test_investigation_reads_what_triage_did_before_the_inventory_and_the_category(self):
        # what triage did is the first thing an investigation needs: the conflict it starts from, the
        # alert types and the candidate categories, before the evidence is extracted again
        text = self.read("zerosoc-investigation")
        procedure = text[text.index("## Procedure"):]
        ledger = procedure.index("1. **Start the ledger from the Triage Note")
        inventory = procedure.index("2. **Extract the evidence inventory**")
        category = procedure.index("3. **Choose the Incident Category")
        self.assertLess(ledger, inventory)
        self.assertLess(inventory, procedure.index("process_chain.py"))
        self.assertLess(procedure.index("process_chain.py"), category)
        self.assertLess(category, procedure.index("4. **Verify or retract**"))

    def test_both_procedures_choose_and_record_the_selected_playbook(self):
        triage = self.read("zerosoc-triage")
        self.assertIn("`playbook`", triage)
        self.assertIn("`domain`", triage)
        self.assertLess(triage.index("**Choose each alert's type"), triage.index("Start the ledger"))
        self.assertLess(triage.index("`playbook`"), triage.index("Start the ledger"))
        investigation = self.read("zerosoc-investigation")
        step = investigation[investigation.index("3. **Choose the Incident Category"):]
        self.assertIn("`playbook`", step)
        self.assertIn("`incident_category`", step)
        self.assertIn("re-run step 3", investigation, "a pivot chooses again")

    def test_the_retrospective_sweep_runs_through_the_case_store(self):
        text = self.read("zerosoc-investigation")
        sweep = text[text.index("retrospective"):]
        self.assertIn("`cases.store`", sweep[:700])

    def test_the_timebox_runs_from_when_the_case_is_taken_not_from_when_the_ledger_is_started(self):
        # Guardrails §5 gives an executor assigned a Case in Investigation ten or twenty minutes: the clock
        # starts at the assignment, so the procedure names `started_at` at its first step, before reading
        # the Triage Note, the extraction and the playbook selection, and the ledger carries that time
        text = self.read("zerosoc-investigation")
        procedure = text[text.index("## Procedure"):]
        first = procedure.index("`started_at`")
        self.assertLess(first, procedure.index("Read what triage did"))
        self.assertLess(first, procedure.index("2. **Extract the evidence inventory**"))
        step = procedure[procedure.index("1. **Start the ledger"):procedure.index("2. **Extract")]
        self.assertIn("`started_at` as noted here (never the time this file is created)", step)


class AutonomyMatrix(unittest.TestCase):
    def test_an_identity_action_on_a_hosts_own_identity_is_not_selected(self):
        # live: a confirmed Incident named the computer account a scheduled task ran under, and an executor
        # asked a person to approve disabling it (Incident Response §1, §2.1)
        for target in ("VWIN01$", "SYSTEM", "NT AUTHORITY\\NETWORK SERVICE", "Administrators"):
            for preset in auto.IDENTITY_ACTIONS:
                r = auto.classify(f"{preset} {target}", "High", "High", preset=preset, target=target)
                self.assertEqual(r["tier"], "not selected", (preset, target))
                self.assertIn("isolate", r["instead"])
                self.assertNotIn("presentation_payload", r, "never sent for approval")

    def test_a_stated_kind_wins_over_what_the_name_states(self):
        r = auto.classify("disable svc$", "High", "High", preset="disable-service-identity", target="svc$", target_kind="service")
        self.assertEqual(r["tier"], "requires approval")
        self.assertEqual(auto.classify("disable app01", "High", "High", preset="disable-user-identity", target="app01", target_kind="host")["tier"], "not selected")

    def test_a_persons_account_follows_the_matrix_and_the_payload_names_it(self):
        r = auto.classify("disable elena", "Low", "High", preset="disable-user-identity", target="elena@contoso.example", target_kind="person")
        self.assertEqual(r["tier"], "requires approval")
        self.assertIn("on elena@contoso.example (person)", r["presentation_payload"]["3_action_and_matrix_entry"])
        self.assertEqual(auto.classify("isolate VWIN01", "High", "High", preset="isolate-workstation", target="VWIN01$")["tier"], "pre-authorized",
                         "a host action on the host is unaffected")

    def test_workstation_isolation_preauthorized_immediate(self):
        r = auto.classify("isolate WS-07", "High", "High", preset="isolate-workstation")
        self.assertEqual(r["tier"], "pre-authorized"); self.assertIn("immediately", r["timing"])

    def test_low_confidence_requires_approval(self):
        r = auto.classify("revoke key", "Low", "Medium", preset="revoke-credential")
        self.assertEqual(r["tier"], "requires approval"); self.assertIn("presentation_payload", r)

    def test_domain_controller_isolation_requires_approval(self):
        self.assertEqual(auto.classify("isolate DC01", "High", "Critical", preset="isolate-domain-controller")["tier"], "requires approval")

    def test_disable_user_identity_on_crown_jewel_case_is_preauthorized(self):
        # §2.1 example: a personal admin account on a domain controller Incident
        self.assertEqual(auto.classify("disable admin account", "High", "High", preset="disable-user-identity")["tier"], "pre-authorized")


if __name__ == "__main__":
    unittest.main()


class AlertsAloneDoNotProve(unittest.TestCase):
    """Detection & Analysis §2.4 (#88 item 7): Malicious is proven at 3 only when an alert is at High
    confidence or an observation stands beyond the alerts; a restatement counts as its alert."""

    ALERTS = [{"id": "x1", "confidence": "Medium"}, {"id": "x2", "confidence": "Medium"}]

    def _obs(self, *extra):
        return [{"id": "O1", "side": "Malicious", "confidence": "Medium", "event_refs": ["x1"]},
                {"id": "O2", "side": "Malicious", "confidence": "Medium", "event_refs": ["x2"]}, *extra]

    def test_two_medium_alerts_nobody_could_check_are_neither_proven(self):
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs()})
        self.assertEqual(r["malicious_score"], 4)
        self.assertEqual(r["outcome"], "Neither proven")
        self.assertIn("beyond the alerts", r["malicious_not_proven"])

    def test_a_restatement_tagged_high_is_still_the_alert(self):
        restated = {"id": "O3", "side": "Malicious", "confidence": "High", "event_refs": ["x1"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(restated)})
        self.assertEqual(r["outcome"], "Neither proven")

    def test_one_observation_beyond_the_alerts_proves_it(self):
        found = {"id": "O3", "side": "Malicious", "confidence": "Low", "event_refs": ["EVT-1", "x1"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(found)})
        self.assertEqual(r["outcome"], "Malicious proven")

    def test_two_alerts_related_by_one_observation_stand_beyond_them(self):
        related = {"id": "O3", "side": "Malicious", "confidence": "Low", "event_refs": ["x1", "x2"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(related)})
        self.assertEqual(r["outcome"], "Malicious proven")

    def test_an_observation_citing_two_ids_of_one_merged_alert_restates_it(self):
        alerts = [{"id": "x1", "confidence": "Medium", "ids": ["x1", "x1b"]}, {"id": "x2", "confidence": "Medium"}]
        merged = {"id": "O3", "side": "Malicious", "confidence": "Low", "event_refs": ["x1", "x1b"]}
        r = inv.resolve({"alerts": alerts, "observations": self._obs(merged)})
        self.assertEqual(r["outcome"], "Neither proven")

    def test_a_restatement_scores_as_its_alert_once(self):
        """An observation that only restates an alert counts as that alert, in the score too (§2.4): a
        reputation lookup that knew nothing, cited beside the alert, adds no second alert."""
        lookup = {"id": "O3", "side": "Malicious", "confidence": "Medium", "event_refs": ["EVT-5", "x1"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(lookup), "no_information_refs": ["EVT-5"],
                         "scoped_negative_refs": []})
        self.assertEqual((r["malicious_score"], r["counted"]["Malicious"]["counted"]), (4, ["O1", "O2"]))

    def test_a_restatement_tagged_high_scores_at_its_alerts_confidence(self):
        restated = {"id": "O3", "side": "Malicious", "confidence": "High", "event_refs": ["x1"]}
        self.assertEqual(inv.resolve({"alerts": self.ALERTS, "observations": self._obs(restated)})["malicious_score"], 4)

    def test_a_restatement_tagged_below_its_alert_keeps_its_tag(self):
        """Counting a restatement as its alert caps its weight, never raises it: two High alerts read at Low
        stay undecided."""
        alerts = [{"id": "x1", "confidence": "High"}, {"id": "x2", "confidence": "High"}]
        low = [{"id": "O1", "side": "Malicious", "confidence": "Low", "event_refs": ["x1"]},
               {"id": "O2", "side": "Malicious", "confidence": "Low", "event_refs": ["x2"]}]
        r = inv.resolve({"alerts": alerts, "observations": low})
        self.assertEqual((r["malicious_score"], r["outcome"]), (2, "Neither proven"))

    def test_a_restatement_of_a_typed_alert_is_that_alert(self):
        typed = {"id": "O1", "side": "Malicious", "confidence": "Medium", "event_refs": ["x1"],
                 "alert_type": "C2 beaconing", "entity": "vwin02"}
        restated = {"id": "O3", "side": "Malicious", "confidence": "Medium", "event_refs": ["x1"]}
        r = inv.resolve({"alerts": self.ALERTS[:1], "observations": [typed, restated]})
        self.assertEqual((r["malicious_score"], r["counted"]["Malicious"]["counted"]), (2, ["O1"]))

    def test_an_alert_at_high_confidence_proves_it_alone(self):
        alerts = [{"id": "x1", "confidence": "High"}]
        f = [{"id": "O1", "side": "Malicious", "confidence": "High", "event_refs": ["x1"]}]
        self.assertEqual(inv.resolve({"alerts": alerts, "observations": f})["outcome"], "Malicious proven")

    def test_at_the_timebox_the_unchecked_alerts_close_as_insufficient_data(self):
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(), "timebox_expired": True})
        self.assertEqual((r["verdict_id"], r["outcome"]), (7, "Neither proven at timebox/budget expiry"))

    def test_a_ledger_that_names_no_alerts_is_resolved_as_before_and_says_so(self):
        r = inv.resolve({"observations": self._obs()})
        self.assertEqual(r["outcome"], "Malicious proven")
        self.assertIn("names no alerts", r["alerts_note"])


class NoInformationCarriesNoWeight(unittest.TestCase):
    """Detection & Analysis §2.4 (#88 item 2): a result that yields no information carries neither
    side. On the Malicious side, an observation resting only on such results and an alert counts as
    the alert; one resting on them alone counts for nothing."""

    ALERTS = [{"id": "x1", "confidence": "Medium"}, {"id": "x2", "confidence": "Medium"}]
    EMPTY = ["EVT-c-002"]

    def _obs(self, *extra):
        return [{"id": "O1", "side": "Malicious", "confidence": "Medium", "event_refs": ["x1"]},
                {"id": "O2", "side": "Malicious", "confidence": "Medium", "event_refs": ["x2"]}, *extra]

    def test_an_alert_and_a_lookup_that_found_nothing_is_the_alert(self):
        """The 2026-10-11 run: "no enrichment result supports a benign reading", tagged Malicious."""
        f8 = {"id": "O8", "side": "Malicious", "confidence": "Medium", "event_refs": ["x2", "EVT-c-002"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(f8), "no_information_refs": self.EMPTY})
        self.assertEqual(r["outcome"], "Neither proven")

    def test_an_observation_on_nothing_but_empty_results_carries_no_weight(self):
        empty = {"id": "O3", "side": "Malicious", "confidence": "High", "event_refs": ["EVT-c-002"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(empty), "no_information_refs": self.EMPTY})
        self.assertEqual(r["malicious_score"], 4)
        self.assertEqual(r["no_information"], ["O3"])

    def test_a_result_that_found_something_still_stands_beyond_the_alerts(self):
        found = {"id": "O3", "side": "Malicious", "confidence": "Low", "event_refs": ["x1", "EVT-c-003"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(found), "no_information_refs": self.EMPTY})
        self.assertEqual(r["outcome"], "Malicious proven")

    def test_a_benign_scoped_negative_keeps_its_weight(self):
        """A scoped negative (no child process on a covered host) is a real Benign observation."""
        scoped = {"id": "B1", "side": "Benign", "confidence": "Medium", "event_refs": ["EVT-c-002"]}
        r = inv.resolve({"alerts": self.ALERTS, "observations": self._obs(scoped), "no_information_refs": [],
                         "scoped_negative_refs": self.EMPTY})
        self.assertEqual(r["benign_score"], 2)

    def test_at_triage_it_does_not_stand_beyond_the_alerts(self):
        ledger = {"alerts": [{"id": "x1", "type": "Privileged role / group grant", "entity": "svc", "confidence": "Medium"}],
                  "observations": [{"id": "O2", "side": "Malicious", "confidence": "Medium", "event_refs": ["x1", "EVT-c-002"]},
                                   {"id": "O3", "side": "Benign", "confidence": "High", "event_refs": ["x1"], "covers": ["x1"], "condition": "false_positive"}],
                  "no_information_refs": self.EMPTY}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Close")


class ScopedNegativesAndNoInformation(unittest.TestCase):
    """Detection & Analysis §2.4: a result that yields no information carries neither side, and a scoped
    negative is a real observation. A ledger lists the two apart, and both decision scripts give
    "no_information_refs" no weight on either side. A ledger without "scoped_negative_refs" is read the same
    way, which can only cost a Benign observation its weight, and a note says so."""

    ALERTS = [{"id": "x1", "confidence": "Medium"}, {"id": "x2", "confidence": "Medium"}]
    NOTHING = ["EVT-ti-001"]   # a reputation lookup that knows nothing of the hash
    SCOPED = ["EVT-q-002"]     # no child process on the covered host in the window

    def ledger(self, *observations, scoped=True):
        out = {"alerts": self.ALERTS, "observations": list(observations), "no_information_refs": self.NOTHING}
        if scoped:
            out["scoped_negative_refs"] = self.SCOPED
        return out

    def test_a_benign_observation_on_nothing_but_no_information_carries_no_weight(self):
        b = {"id": "O3", "side": "Benign", "confidence": "Medium", "event_refs": self.NOTHING}
        r = inv.resolve(self.ledger(b))
        self.assertEqual(r["benign_score"], 0)
        self.assertEqual(r["no_information"], ["O3"])
        self.assertNotIn("no_information_note", r)

    def test_a_benign_scoped_negative_keeps_its_weight(self):
        b = {"id": "O3", "side": "Benign", "confidence": "Medium", "event_refs": self.SCOPED}
        self.assertEqual(inv.resolve(self.ledger(b))["benign_score"], 2)

    def test_a_malicious_observation_on_a_scoped_negative_stands_beyond_the_alerts(self):
        m = [{"id": "O1", "side": "Malicious", "confidence": "Medium", "event_refs": ["x1"]},
             {"id": "O2", "side": "Malicious", "confidence": "Low", "event_refs": ["x2", *self.SCOPED]}]
        self.assertEqual(inv.resolve(self.ledger(*m))["outcome"], "Malicious proven")

    def test_a_ledger_without_the_key_is_read_the_same_way_and_says_so(self):
        b = {"id": "O3", "side": "Benign", "confidence": "Medium", "event_refs": self.NOTHING}
        r = inv.resolve(self.ledger(b, scoped=False))
        self.assertEqual(r["benign_score"], 0)
        self.assertIn("scoped_negative_refs", r["no_information_note"])

    def test_no_information_is_set_aside_before_counting_once(self):
        """A weightless observation on the same artifact can neither stand in for a real one nor lend it weight."""
        weightless = {"id": "B1", "side": "Benign", "confidence": "High", "artifact": "hash:ab", "event_refs": self.NOTHING}
        real = {"id": "B2", "side": "Benign", "confidence": "Low", "artifact": "hash:ab", "event_refs": ["EVT-q-009"]}
        for order in ((weightless, real), (real, weightless)):
            r = inv.resolve(self.ledger(*order))
            self.assertEqual((r["benign_score"], r["benign_observations"], r["no_information"]), (1, ["B2"], ["B1"]))

    def test_an_empty_reference_reads_the_same_at_both_gates(self):
        b = {"id": "O3", "side": "Benign", "confidence": "Medium", "event_refs": ["", None, *self.NOTHING], "covers": ["x1"],
             "condition": "false_positive"}
        self.assertEqual(inv.resolve(self.ledger(b))["no_information"], ["O3"])
        tri = triage.decide(dict(self.ledger(b), alerts=[{"id": "x1", "type": "t", "entity": "e", "confidence": "Low"}]))
        self.assertEqual(tri["no_information"], ["O3"])

    def test_a_benign_observation_reading_the_alerts_own_evidence_keeps_its_weight(self):
        """The restatement rule is the Malicious side's (§1.5): a Benign reading of what the alert cites,
        a signed binary for instance, is an observation, whatever lookup sits beside it."""
        b = {"id": "O3", "side": "Benign", "confidence": "Medium", "event_refs": ["x1", *self.NOTHING]}
        self.assertEqual(inv.resolve(self.ledger(b))["benign_score"], 2)

    def test_one_reference_cannot_be_both(self):
        b = {"id": "O3", "side": "Benign", "confidence": "Medium", "event_refs": self.NOTHING}
        ledger = self.ledger(b)
        ledger["scoped_negative_refs"] = self.NOTHING
        with self.assertRaises(ValueError):
            inv.resolve(ledger)
        with self.assertRaises(ValueError):
            triage.decide(dict(ledger, alerts=[{"id": "x1", "type": "t", "entity": "e", "confidence": "Low"}]))

    def test_at_triage_a_lookup_that_knows_nothing_cannot_close(self):
        """An answered reputation lookup with no record, tagged Benign: under the old reading it closed."""
        ledger = {"alerts": [{"id": "x1", "type": "Suspicious script / interpreter execution", "entity": "h", "confidence": "Low"}],
                  "observations": [{"id": "O2", "side": "Benign", "confidence": "Medium", "event_refs": self.NOTHING,
                                    "covers": ["x1"], "condition": "false_positive"}],
                  "no_information_refs": self.NOTHING, "scoped_negative_refs": []}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote")
        self.assertEqual(r["no_information"], ["O2"])
        del ledger["scoped_negative_refs"]
        old = triage.decide(ledger)
        self.assertEqual(old["decision"], "Promote")
        self.assertIn("scoped_negative_refs", old["no_information_note"])

    def test_at_triage_a_scoped_negative_still_covers(self):
        ledger = {"alerts": [{"id": "x1", "type": "Suspicious script / interpreter execution", "entity": "h", "confidence": "Low"}],
                  "observations": [{"id": "O2", "side": "Benign", "confidence": "Medium", "event_refs": self.SCOPED,
                                    "covers": ["x1"], "condition": "false_positive"}],
                  "no_information_refs": self.NOTHING, "scoped_negative_refs": self.SCOPED}
        self.assertEqual(triage.decide(ledger)["decision"], "Close")


class ResolutionReportsWhatItCounted(unittest.TestCase):
    """A Note's Rationale quotes the rule's own count: the observations standing on each side, and how
    many they count as once one alert type on one entity and one artifact count once, and once the
    observations that carry no information are set aside."""

    def test_the_counts_follow_the_rule(self):
        ledger = {"observations": [
            {"id": "O1", "side": "Malicious", "confidence": "Medium", "alert_type": "Credential dumping", "entity": "h"},
            {"id": "O2", "side": "Malicious", "confidence": "High", "alert_type": "credential dumping", "entity": "H"},
            {"id": "O3", "side": "Malicious", "confidence": "Low", "event_refs": ["EVT-ti-001"]},
            {"id": "O4", "side": "Benign", "confidence": "Medium", "artifact": "hash:ab"},
            {"id": "O5", "side": "Benign", "confidence": "Low", "artifact": "hash:ab"},
            {"id": "O6", "side": "Benign", "confidence": "Low", "retracted": True},
            {"id": "O7", "side": None}],
            "no_information_refs": ["EVT-ti-001"], "scoped_negative_refs": []}
        r = inv.resolve(ledger)
        self.assertEqual(r["counted"], {"Malicious": {"standing": ["O1", "O2", "O3"], "counted": ["O1"]},
                                        "Benign": {"standing": ["O4", "O5"], "counted": ["O4"]}})
        self.assertEqual(r["malicious_score"], 3)


class IncidentTechniques(unittest.TestCase):
    """Techniques at two levels (DD-27): each observation carries the ones it shows, and the Incident's,
    recorded at confirmation, trace to the observations that stand."""

    def ledger(self, recorded=None, **extra):
        observations = [
            {"id": "O1", "side": "Malicious", "confidence": "High", "event_refs": ["A1"], "attacks": ["T1003.001 (LSASS Memory)"]},
            {"id": "O2", "side": "Malicious", "confidence": "Medium", "event_refs": ["E2"], "attacks": ["T1078", "T1078"]},
            {"id": "O3", "side": "Malicious", "confidence": "Low", "event_refs": ["E3"], "attacks": ["T1021.002"], "retracted": True},
            {"id": "O4", "side": "Benign", "confidence": "Low", "event_refs": ["E4"], "attacks": ["T1059"]}]
        return dict({"alerts": [{"id": "A1", "confidence": "High"}], "observations": observations, "attacks": recorded}, **extra)

    def test_the_standing_malicious_observations_show_the_techniques(self):
        r = inv.resolve(self.ledger())
        self.assertEqual(r["verdict_id"], 2)
        self.assertEqual(r["attacks"]["shown"], {"T1003.001": ["O1"], "T1078": ["O2"]},
                         "a retracted observation shows nothing, a Benign one is not read, a repeat counts once")

    def test_a_recorded_technique_no_standing_observation_shows_is_untraced(self):
        r = inv.resolve(self.ledger(["T1003", "T1078 (Valid Accounts)", "T1021.002"]))
        self.assertEqual(r["attacks"]["recorded"], ["T1003", "T1078", "T1021.002"])
        self.assertEqual(r["attacks"]["untraced"], ["T1021.002"],
                         "a parent of a shown sub-technique is shown; the retracted observation's technique is not")

    def test_no_incident_keeps_the_case_techniques_empty(self):
        ledger = {"observations": [{"id": "B1", "side": "Benign", "confidence": "High", "event_refs": ["E"]}],
                  "attacks": ["T1078"]}
        r = inv.resolve(ledger)
        self.assertNotIn("attacks", r)
        self.assertIn("no Incident is confirmed", r["attacks_note"])

    def test_attacks_must_be_a_list(self):
        with self.assertRaises(ValueError):
            inv.resolve(self.ledger("T1078"))

    def test_the_rules_ask_each_malicious_observation_for_its_techniques(self):
        for rel in ("skills/zerosoc-triage/rules/checks.md", "skills/zerosoc-investigation/rules/tag.md"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                self.assertIn("A Malicious observation names in `attacks` the techniques it shows", f.read(), rel)


class InventoryBasis(unittest.TestCase):
    """A count reproduced from the same evidence by the same identity rule always matches the extraction,
    so a complete inventory reads as verified only when the source supplied the count itself."""

    ROWS = EvidenceInventory.ROWS

    def built(self):
        return evidence.build(self.ROWS, alert_devices={"A1": "ws-04", "A2": "ws-04"})

    def test_the_basis_is_recorded(self):
        self.assertEqual(evidence.completeness(self.built(), 4)["source_count_basis"], "source")
        record = evidence.completeness(self.built(), 4, basis="reproduction")
        self.assertEqual(record["source_count_basis"], "reproduction")
        self.assertTrue(record["complete"])
        self.assertIsNone(evidence.completeness(self.built(), None)["source_count_basis"])

    def test_a_reproduced_count_that_matches_is_unverified(self):
        note = evidence.note(evidence.completeness(self.built(), 4, basis="reproduction"))
        self.assertIn("unverified", note)
        self.assertIsNone(evidence.note(evidence.completeness(self.built(), 4)))

    def test_a_reproduced_count_that_disagrees_is_still_reported(self):
        note = evidence.note(evidence.completeness(self.built(), 6, basis="reproduction"))
        self.assertIn("4 of 6", note)
        self.assertIn("reproduced", note)

    def test_the_decisions_carry_it(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}], "observations": [],
                  "evidence_inventory": {"extracted": 4, "source_count": 4, "source_count_basis": "reproduction", "complete": True}}
        self.assertIn("unverified", triage.decide(ledger)["evidence_inventory_note"])
        self.assertIn("unverified", inv.resolve({"observations": [], "evidence_inventory": ledger["evidence_inventory"]})["evidence_inventory_note"])

    def test_an_unknown_basis_is_refused(self):
        with self.assertRaises(ValueError):
            evidence.completeness(self.built(), 4, basis="guess")
        note = evidence.note({"extracted": 4, "source_count": 4, "source_count_basis": "reproduced", "complete": True})
        self.assertIn("unverified", note)
