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
checker = load("tools/check_run.py", "check_run")

CAPABILITIES = os.path.join(ROOT, "capabilities")
XDR_MAP = os.path.join(CAPABILITIES, "alert_types.defender-xdr.json")
DFB_PROFILE = os.path.join(CAPABILITIES, "zerosoc.capabilities.defender-for-business.json")
PLACEHOLDER_SOURCES = {"<telemetry source>"}
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


class TriageRule(unittest.TestCase):
    def test_oauth_consent_closes_as_benign_high(self):
        # Detection & Analysis §1.5, first example
        ledger = {"alerts": [{"id": "A", "type": "OAuth app consent", "entity": "u1", "confidence": "Medium"}],
                  "findings": [{"id": "F2", "side": "Benign", "confidence": "High"}, {"id": "F3", "side": "Benign", "confidence": "Medium"},
                               {"id": "F4", "side": "Benign", "confidence": "Low"}, {"id": "F1", "side": None}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Close"); self.assertEqual(r["confidence"], "High")

    def test_credential_dumping_promotes_at_high(self):
        # §1.5, second example: two techniques, a Malicious finding beyond the alerts
        ledger = {"alerts": [{"id": "A1", "type": "Credential dumping", "entity": "h", "confidence": "High", "technique": "T1003"},
                             {"id": "A2", "type": "Internal scan", "entity": "h", "severity": "Medium", "technique": "T1046"}],
                  "findings": [{"id": "B1", "side": "Benign", "confidence": "Low"}, {"id": "M1", "side": "Malicious", "confidence": "Medium"},
                               {"id": "M2", "side": "Malicious", "confidence": "Low"}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote"); self.assertEqual(r["confidence"], "High")

    def test_high_alert_needs_benign_high(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}],
                  "findings": [{"id": "B1", "side": "Benign", "confidence": "Medium"}, {"id": "B2", "side": "Benign", "confidence": "Medium"}]}
        self.assertEqual(triage.decide(ledger)["decision"], "Promote")

    def test_no_finding_promotes_and_a_gap_leaves_the_confidence_alone(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}], "findings": [], "visibility_gaps": [{"data_source": "EDR"}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote")
        self.assertEqual(r["confidence_id"], 3, "confidence follows the findings; the gap is recorded, not weighed in")
        self.assertEqual(triage.decide(dict(ledger, visibility_gaps=[]))["confidence_id"], 3)

    def test_same_type_same_entity_counts_once(self):
        ledger = {"alerts": [{"id": "A1", "type": "x", "entity": "e", "confidence": "Low"}, {"id": "A2", "type": "x", "entity": "e", "confidence": "Low"}],
                  "findings": [{"id": "B", "side": "Benign", "confidence": "Medium"}]}
        r = triage.decide(ledger)
        self.assertEqual(len(r["alerts_considered"]), 1); self.assertEqual(r["decision"], "Close")


class ResolutionRule(unittest.TestCase):
    def test_retraction_flips_to_benign(self):
        # §2.4 example 1
        f = [{"id": "alert", "side": "Malicious", "confidence": "Medium", "covered": True},
             {"id": "domain", "side": "Malicious", "confidence": "Medium", "retracted": True},
             {"id": "page", "side": "Malicious", "confidence": "High", "retracted": True},
             {"id": "campaign", "side": "Benign", "confidence": "High"}]
        r = inv.resolve({"findings": f})
        self.assertEqual(r["outcome"], "Benign proven"); self.assertEqual(r["confidence"], "High")

    def test_coverage_decides(self):
        # §2.4 example 2: explanation covers the alert but not the later credential use
        f = [{"id": "alert", "side": "Malicious", "confidence": "High", "covered": True},
             {"id": "use", "side": "Malicious", "confidence": "High", "covered": False},
             {"id": "agent", "side": "Benign", "confidence": "High"}]
        r = inv.resolve({"findings": f})
        self.assertEqual(r["verdict_id"], 2); self.assertEqual(r["confidence"], "High")

    def test_strongest_not_average(self):
        f = [{"id": "a", "side": "Malicious", "confidence": "Medium"}, {"id": "feed", "side": "Malicious", "confidence": "High"},
             {"id": "l1", "side": "Malicious", "confidence": "Low"}, {"id": "l2", "side": "Malicious", "confidence": "Low"}, {"id": "l3", "side": "Malicious", "confidence": "Low"}]
        r = inv.resolve({"findings": f})
        self.assertEqual(r["malicious_score"], 8); self.assertEqual(r["confidence"], "High")

    def test_low_confidence_true_positive(self):
        f = [{"id": str(i), "side": "Malicious", "confidence": "Low"} for i in range(4)]
        r = inv.resolve({"findings": f})
        self.assertEqual(r["verdict_id"], 2); self.assertEqual(r["confidence"], "Low")

    def test_residual_low_lowers_benign_confidence(self):
        f = [{"id": "m", "side": "Malicious", "confidence": "Low"}, {"id": "b", "side": "Benign", "confidence": "High"}]
        r = inv.resolve({"findings": f})
        self.assertEqual(r["outcome"], "Benign proven"); self.assertEqual(r["confidence"], "Medium"); self.assertEqual(r["residual_low_malicious"], ["m"])

    def test_insufficient_data_at_timebox(self):
        f = [{"id": "m", "side": "Malicious", "confidence": "Medium"}, {"id": "b", "side": "Benign", "confidence": "Low"}]
        self.assertIsNone(inv.resolve({"findings": f})["verdict_id"])
        self.assertEqual(inv.resolve({"findings": f, "timebox_expired": True})["verdict_id"], 7)

    def test_same_artifact_counts_once(self):
        f = [{"id": "t", "side": "Malicious", "confidence": "Medium", "artifact": "hash:1"}, {"id": "i", "side": "Malicious", "confidence": "Medium", "artifact": "hash:1"}]
        self.assertEqual(inv.resolve({"findings": f})["malicious_score"], 2)


class TimeboxFromLedger(unittest.TestCase):
    # Guardrails §5: 10 minutes at High or Critical severity, 20 otherwise; an organization may tighten them
    F = [{"id": "m", "side": "Malicious", "confidence": "Medium", "at": "2026-09-14T15:04:00Z"},
         {"id": "b", "side": "Benign", "confidence": "Low", "at": "2026-09-14T15:09:00Z"}]
    START, AT_12 = "2026-09-14T15:00:00Z", "2026-09-14T15:12:00Z"

    def test_high_severity_expires_after_ten_minutes(self):
        r = inv.resolve({"findings": self.F, "started_at": self.START, "severity": "High"}, now=self.AT_12)
        self.assertEqual(r["timebox"], {"minutes": 10, "elapsed_minutes": 12.0, "expired": True, "source": "computed"})
        self.assertEqual(r["verdict_id"], 7)

    def test_medium_severity_has_twenty_minutes(self):
        r = inv.resolve({"findings": self.F, "started_at": self.START, "severity_id": 3}, now=self.AT_12)
        self.assertFalse(r["timebox"]["expired"]); self.assertEqual(r["timebox"]["minutes"], 20)
        self.assertIsNone(r["verdict_id"])

    def test_the_end_is_now_then_resolved_at_then_the_clock_never_the_last_finding(self):
        ledger = {"findings": self.F, "started_at": self.START, "severity": "Low", "resolved_at": "2026-09-14T15:25:00Z"}
        self.assertTrue(inv.resolve(ledger)["timebox"]["expired"])
        self.assertFalse(inv.resolve(ledger, now="2026-09-14T15:05:00Z")["timebox"]["expired"])
        del ledger["resolved_at"]  # a stalled run: the last finding is at +9 minutes, the clock is years later
        self.assertTrue(inv.resolve(ledger)["timebox"]["expired"])

    def test_computed_value_overrides_a_self_reported_flag(self):
        r = inv.resolve({"findings": self.F, "started_at": self.START, "severity": "Critical", "timebox_expired": False}, now=self.AT_12)
        self.assertTrue(r["timebox"]["expired"]); self.assertIn("self-reported", r["timebox_note"])

    def test_without_a_start_the_flag_is_used_and_marked_self_reported(self):
        r = inv.resolve({"findings": self.F, "timebox_expired": True})
        self.assertEqual(r["timebox"]["source"], "self-reported"); self.assertEqual(r["verdict_id"], 7)

    def test_an_organization_may_tighten_the_reference_value_not_extend_it(self):
        base = {"findings": self.F, "started_at": self.START, "severity": "High"}
        tight = inv.resolve(dict(base, timebox_minutes=5), now="2026-09-14T15:06:00Z")
        self.assertEqual(tight["timebox"]["minutes"], 5); self.assertTrue(tight["timebox"]["expired"])
        loose = inv.resolve(dict(base, timebox_minutes=30), now=self.AT_12)
        self.assertEqual(loose["timebox"]["minutes"], 10); self.assertTrue(loose["timebox"]["expired"])
        self.assertIn("ignored", loose["timebox_note"])

    def test_timestamps_out_of_order_are_reported(self):
        r = inv.resolve({"findings": self.F, "started_at": "2026-09-14T15:05:00Z", "severity": "High"}, now="2026-09-14T15:00:00Z")
        self.assertEqual(r["timebox"]["elapsed_minutes"], 0.0)
        self.assertIn("precedes started_at", r["timebox_note"]); self.assertIn("m", r["timebox_note"])

    def test_a_malformed_timestamp_is_a_value_error(self):
        with self.assertRaises(ValueError):
            inv.resolve({"findings": [], "started_at": "yesterday"})


class LedgerDedup(unittest.TestCase):
    def test_same_alert_type_on_the_same_entity_counts_once_in_resolution(self):
        # Detection & Analysis §1.1: same type on the same entity counts once
        f = [{"id": "a1", "side": "Malicious", "confidence": "Medium", "alert_type": "Credential dumping", "entity": "ws-04", "artifact": "alert:1"},
             {"id": "a2", "side": "Malicious", "confidence": "High", "alert_type": "credential dumping", "entity": "WS-04", "artifact": "alert:2"},
             {"id": "a3", "side": "Malicious", "confidence": "Medium", "alert_type": "Credential dumping", "entity": "ws-09"}]
        r = inv.resolve({"findings": f})
        self.assertEqual(r["malicious_score"], 5)  # High (3) for ws-04 once, Medium (2) for ws-09
        self.assertEqual(r["malicious_findings"], ["a1", "a3"])


class AlertTypeMapping(unittest.TestCase):
    def setUp(self):
        self.map = alert_types.load_map(XDR_MAP)

    def test_titles_map_to_framework_alert_types(self):
        for title, expected in [
            ("Ransomware behavior detected in the file system", "Ransomware mass-encryption"),
            ("Possible credential dumping (LSASS)", "Credential dumping"),
            ("Sensitive credential memory read", "Credential dumping"),
            ("Suspicious inbox forwarding rule", "Inbox forwarding / redirect or hide rule"),
            ("'Wacatac' malware was prevented", "Malware / loader execution"),
            ("Suspicious PowerShell command line", "Suspicious script / interpreter execution"),
            ("Email reported by user as malware or phish", "User-reported phishing"),
            ("Impossible travel activity", "Impossible-travel / anomalous sign-in"),
            # rule order: the specific before the general
            ("Malicious file detected", "Malware / loader execution"),
            ("Malware detected in a zip archive file delivered by email", "Malicious attachment / URL delivered"),
            ("Email messages containing malicious file removed after delivery", "Malicious attachment / URL delivered"),
            ("Attempt to tamper with shadow copies", "Mass file destruction / disk wipe"),
            ("Suspicious connection to a malicious IP address blocked by network protection", "C2 beaconing / known-bad destination"),
            ("Data exfiltration over PowerShell", "Outbound data spike"),
            ("'Locky' ransomware was prevented", "Malware / loader execution"),
            ("Suspicious service registration", "Persistence mechanism created"),
            ("Event log was cleared", "Security-tool / AMSI tampering"),
            ("Creation of forwarding/redirect rule", "Inbox forwarding / redirect or hide rule"),
            ("Suspicious credential dump from NTDS.dit", "Credential dumping"),
        ]:
            with self.subTest(title=title):
                m = alert_types.classify({"id": "x", "title": title}, self.map)
                self.assertEqual(m["type"], expected); self.assertFalse(m["unmapped"])

    def test_a_title_that_names_no_behaviour_stays_unmapped(self):
        for title in ("Ransomware-linked emerging threat activity group detected", "Suspicious bootloader modification",
                      "Unusual impersonated activity (by user)", "Mass delete"):
            with self.subTest(title=title):
                self.assertTrue(alert_types.classify({"id": "x", "title": title}, self.map)["unmapped"])

    def test_detector_id_wins_over_the_title(self):
        custom = {"rules": [{"alert_type": "Credential dumping", "domain": "Endpoint", "detector_ids": ["det-1"], "title_patterns": []},
                            {"alert_type": "Malware / loader execution", "domain": "Endpoint", "detector_ids": [], "title_patterns": ["malware"]}]}
        m = alert_types.classify({"id": "x", "title": "Malware found", "detector_id": "det-1"}, custom)
        self.assertEqual(m["type"], "Credential dumping"); self.assertEqual(m["matched_on"], "detector_id")

    def test_unmapped_alert_keeps_its_title_as_type_and_is_flagged(self):
        m = alert_types.classify({"id": "x", "title": "  Something   New  "}, self.map)
        self.assertEqual(m["type"], "Something New"); self.assertTrue(m["unmapped"]); self.assertIsNone(m["domain"])

    def test_same_type_same_entity_collapses_to_the_strongest(self):
        alerts = [{"id": "A1", "title": "Sensitive credential memory read", "entity": "ws-04", "severity": "Medium"},
                  {"id": "A2", "title": "Possible credential dumping (LSASS)", "entity": "WS-04", "severity": "High"},
                  {"id": "A3", "title": "Possible credential dumping (LSASS)", "entity": "ws-09", "severity": "High"}]
        out = alert_types.build_alerts(alerts, self.map)
        self.assertEqual([(a["id"], a["entity"], a["confidence"], a["merged_ids"]) for a in out],
                         [("A2", "WS-04", "High", ["A1", "A2"]), ("A3", "ws-09", "High", ["A3"])])
        # the triage rule sees the same thing it would after its own dedup
        self.assertEqual(len(triage.dedupe_alerts(out)), 2)

    def test_the_map_declares_the_source_field_names_not_the_script(self):
        rules = [{"alert_type": "Credential dumping", "domain": "Endpoint", "detector_ids": ["det-9"], "title_patterns": []}]
        record = {"id": "x", "title": "y", "sourceDetector": "det-9"}
        self.assertTrue(alert_types.classify(record, {"rules": rules})["unmapped"])
        self.assertEqual(alert_types.classify(record, {"fields": {"detector_id": "sourceDetector"}, "rules": rules})["type"], "Credential dumping")
        self.assertIn("detector_id", self.map["fields"])

    def test_levels_are_case_insensitive_and_a_missing_entity_is_empty(self):
        m = alert_types.classify({"id": "x", "title": "t", "confidence": "high", "entity": None}, self.map)
        self.assertEqual((m["confidence"], m["entity"]), ("High", ""))
        self.assertEqual(alert_types.classify({"id": "x", "title": "t", "severity": "critical"}, self.map)["confidence"], "High")

    def test_the_output_seeds_the_resolution_ledger_and_counts_once_there_too(self):
        alerts = [{"id": "A1", "title": "Sensitive credential memory read", "entity": "ws-04", "severity": "Medium"},
                  {"id": "A2", "title": "Possible credential dumping (LSASS)", "entity": "ws-04", "severity": "Medium"}]
        raw = [alert_types.classify(a, self.map) for a in alerts]  # not yet collapsed
        self.assertEqual(inv.resolve({"findings": raw})["malicious_score"], 2)
        self.assertEqual(inv.resolve({"findings": alert_types.build_alerts(alerts, self.map)})["malicious_score"], 2)

    def test_the_binding_names_its_map(self):
        import subprocess, sys, tempfile, json as j
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            j.dump([{"id": "A", "title": "Suspicious inbox forwarding rule", "entity": "u"}], f)
        out = subprocess.run([sys.executable, os.path.join(ROOT, "tools/shared/alert_types.py"), f.name, "--bindings", DFB_PROFILE, "--json"],
                             capture_output=True, text=True, check=True).stdout
        os.unlink(f.name)
        self.assertEqual(j.loads(out)[0]["type"], "Inbox forwarding / redirect or hide rule")

    def test_every_mapped_alert_type_exists_in_the_framework_taxonomy(self):
        with open(os.path.join(ROOT, "framework/02-Taxonomy/alert_types.md"), encoding="utf-8") as f:
            text = f.read()
        known = alert_types.framework_alert_types(text)
        self.assertGreater(len(known), 40)
        for rule in self.map["rules"]:
            self.assertIn(rule["alert_type"], known, rule["alert_type"])
            self.assertEqual(rule["domain"], known[rule["alert_type"]])


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
        self.assertEqual(evidence.completeness(inv_, 4), {"extracted": 4, "rows_read": 5, "source_count": 4, "complete": True})
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
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}], "findings": []}
        self.assertIn("not recorded", triage.decide(ledger)["evidence_inventory_note"])
        ledger["evidence_inventory"] = {"extracted": 28, "source_count": 31, "complete": False}
        self.assertIn("28 of 31", triage.decide(ledger)["evidence_inventory_note"])
        self.assertIn("28 of 31", inv.resolve({"findings": [], "evidence_inventory": ledger["evidence_inventory"]})["evidence_inventory_note"])
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

    def test_one_section_per_alert_citing_a_process(self):
        sections = chain.per_alert(self.live)
        self.assertEqual(len(sections), 28)  # of the incident's 32 alerts; the others cite no process
        for section in sections:
            self.assertTrue(section["cited"])
            self.assertLessEqual(section["cited"], section["processes"])
        self.assertEqual({n["pid"] for n in self.live["nodes"]},
                         {n["pid"] for s in sections for n in s["nodes"].values() if n["in_evidence"]})

    def test_an_alerts_section_closes_upwards_over_its_ancestors(self):
        built = chain.build([self.row(10, "2026-09-13T12:00:00Z", alerts=["A"]),
                             self.row(11, "2026-09-13T12:00:01Z", 10, "2026-09-13T12:00:00Z", alerts=["A"]),
                             self.row(12, "2026-09-13T12:00:02Z", 11, "2026-09-13T12:00:01Z", alerts=["B"])])
        sections = {s["alert_id"]: s for s in chain.per_alert(built)}
        self.assertEqual(sorted(sections), ["A", "B"])
        b = sections["B"]
        self.assertEqual((b["cited"], b["processes"]), (1, 3), "the alert's process plus its two ancestors")
        text = chain.as_text(built)
        self.assertIn("alert B", text)
        self.assertIn("(context: another alert of the Case)", text)
        self.assertNotIn("p12.exe 12", text.split("alert A")[1].split("alert B")[0], "a child of another alert is not in this story")
        node = chain.as_json(built)["alerts"][1]["devices"][0]["tree"][0]
        self.assertFalse(node["cited_by_this_alert"])
        self.assertTrue(node["children"][0]["children"][0]["cited_by_this_alert"])

    def test_the_case_wide_chain_is_still_available(self):
        text = chain.as_text(self.live, case=True)
        self.assertNotIn("alert d", text)
        self.assertIn("winrshost", chain.as_text(self.live, case=True) if False else "winrshost")
        self.assertEqual(text.count("[gap]"), len(self.live["gaps"]))

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

    def test_source_column_names_are_accepted(self):
        rows = [{"DeviceName": "WS-01", "ProcessId": 11, "ProcessCreationTime": "2026-09-13T12:00:01Z",
                 "FileName": "child.exe", "ProcessCommandLine": "child.exe -run",
                 "InitiatingProcessId": 10, "InitiatingProcessCreationTime": "2026-09-13T12:00:00Z",
                 "InitiatingProcessFileName": "parent.exe", "InitiatingProcessCommandLine": "parent.exe",
                 "InitiatingProcessParentId": 4, "InitiatingProcessParentCreationTime": "2026-09-13T11:00:00Z"}]
        evidence = [{"type": "process", "name": "child.exe", "pid": 11, "created": "2026-09-13T12:00:01Z",
                     "device": "ws-01", "parent_pid": 10, "parent_created": "2026-09-13T12:00:00Z",
                     "parent_name": "parent.exe", "alert_ids": ["A"]}]
        built = chain.build(evidence, rows)
        parent = self.node(built, 10)
        self.assertEqual((parent["source"], parent["command_lines"]), ("telemetry", ["parent.exe"]))
        self.assertEqual(parent["parent"]["pid"], 4, "the row's grandparent columns add one more level")

    def test_the_text_view_shows_command_lines_cut_to_length(self):
        text = chain.as_text(self.with_, case=True)
        self.assertIn("$ WinrsHost.exe -Embedding", text)
        self.assertIn("[telemetry]", text)
        self.assertTrue(all(len(line) < 200 for line in text.splitlines()), "encoded commands are cut in the text view")
        self.assertIn("…", text)
        whole = json.dumps(chain.as_json(self.with_))
        self.assertIn("EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAg", whole)

    def test_width_controls_where_a_command_is_cut(self):
        whole = chain.as_text(self.with_, case=True, width=0)
        self.assertIn("EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAg", whole)
        self.assertNotIn("…", whole)
        narrow = chain.as_text(self.with_, case=True, width=60)
        commands = [line.strip() for line in narrow.splitlines() if line.strip().startswith(("$ ", "decoded:"))]
        self.assertTrue(commands)
        self.assertTrue(all(len(line) <= 70 for line in commands), "only the commands answer to --width")

    def test_a_decoded_command_is_read_as_a_script(self):
        text = chain.as_text(self.with_, case=True)
        decoded = [line for line in text.splitlines() if "decoded:" in line]
        self.assertTrue(decoded)
        body = text[text.index(decoded[0]):].splitlines()
        self.assertTrue(any(line.strip().startswith("if ($PSVersionTable") for line in body[:8]),
                        "the decoding keeps its own lines instead of being flattened")

    def test_layers_of_encoding_are_named_in_the_chain(self):
        rows = [{"type": "process", "name": "powershell.exe", "pid": 10, "created": "2026-09-13T12:00:00Z",
                 "device": "ws-01", "alert_ids": ["A"], "command_line": "powershell -enc AAAA",
                 "decoded_command": "whoami", "decode_rounds": 3, "decode_capped": True}]
        text = chain.as_text(chain.build(rows), case=True)
        self.assertIn("decoded (3 layers of encoding, still encoded): whoami", text)
        plain = [dict(rows[0], decode_rounds=None, decode_capped=None)]
        self.assertIn("decoded: whoami", chain.as_text(chain.build(plain), case=True))

    def test_the_json_keeps_the_attributes_a_note_cites(self):
        def walk(nodes):
            for n in nodes:
                yield n
                yield from walk(n["children"])

        document = chain.as_json(self.with_)
        nodes = list(walk([t for a in document["alerts"] for d in a["devices"] for t in d["tree"]]))
        alerted = [n for n in nodes if n["source"] == "evidence" and n.get("attributes")]
        self.assertTrue(alerted)
        self.assertTrue(set().union(*(n["attributes"] for n in alerted)) >= {"sha256", "path", "account"})
        self.assertTrue(any(n["command_lines"] for n in nodes))
        self.assertTrue(any(e["command_line"] for e in document["timeline"]))


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
                  "findings": [{"id": "F1", "side": "Malicious", "confidence": "High", "at": "2026-09-14T15:01:00Z",
                                "alert_type": "Credential dumping", "entity": "ws-01"}]}
        ledger.update(overrides)
        for name, document in (("evidence.json", rows), ("ledger.triage.json", ledger),
                               ("ledger.investigation.json", ledger)):
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
        doubled = [{"id": "F1", "side": "Malicious", "confidence": "High", "at": "2026-09-14T15:01:00Z",
                    "alert_type": "Credential dumping", "entity": "ws-01"},
                   {"id": "F2", "side": "Malicious", "confidence": "High", "at": "2026-09-14T15:02:00Z",
                    "alert_type": "credential dumping", "entity": "WS-01"}]
        code, out = self.check(self.run_dir(findings=doubled))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  investigation: no alert counted twice", out)

    def test_the_two_ledger_shapes_are_both_read(self):
        """Triage records the Case's alerts in "alerts"; investigation scores them among "findings"."""
        alerts = [{"id": "A1", "type": "Credential dumping", "entity": "ws-01", "confidence": "High"},
                  {"id": "A2", "type": "credential dumping", "entity": "WS-01", "confidence": "Low"}]
        code, out = self.check(self.run_dir(alerts=alerts, findings=[]))
        self.assertIn("FAIL  triage: no alert counted twice", out)
        self.assertEqual(code, 1)
        one = self.run_dir(alerts=alerts[:1], findings=[])
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

    def test_hunting_is_not_bound_and_the_case_store_is(self):
        self.assertIn("cases.store", self.profile["capabilities"])
        self.assertNotIn("siem.search", self.profile["capabilities"])


class Procedures(unittest.TestCase):
    def read(self, skill):
        with open(os.path.join(ROOT, "skills", skill, "SKILL.md"), encoding="utf-8") as f:
            return f.read()

    def test_both_skills_extract_the_evidence_inventory_before_the_ledger(self):
        for skill in ("zerosoc-triage", "zerosoc-investigation"):
            text = self.read(skill)
            self.assertIn("scripts/evidence_inventory.py", text, skill)
            self.assertLess(text.index("evidence_inventory.py"), text.index("Start the ledger"), skill)

    def test_both_skills_build_the_process_chain_after_the_inventory(self):
        for skill in ("zerosoc-triage", "zerosoc-investigation"):
            text = self.read(skill)
            self.assertIn("scripts/process_chain.py", text, skill)
            self.assertLess(text.index("evidence_inventory.py"), text.index("process_chain.py"), skill)
            self.assertLess(text.index("process_chain.py"), text.index("Start the ledger"), skill)

    def test_both_procedures_record_the_selected_playbook_in_the_ledger(self):
        for skill, key in (("zerosoc-triage", "domain"), ("zerosoc-investigation", "incident_category")):
            text = self.read(skill)
            self.assertIn("`playbook`", text, skill)
            self.assertIn(f"`{key}`", text, skill)
            self.assertLess(text.index("`playbook`"), text.index("Start the ledger") if "Start the ledger" in text
                            else len(text), skill)

    def test_the_retrospective_sweep_runs_through_the_case_store(self):
        text = self.read("zerosoc-investigation")
        sweep = text[text.index("retrospective"):]
        self.assertIn("`cases.store`", sweep[:700])


class AutonomyMatrix(unittest.TestCase):
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
