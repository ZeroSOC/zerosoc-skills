import importlib.util, os, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod


triage = load("skills/zerosoc-triage/scripts/triage_decide.py", "triage_decide")
inv = load("skills/zerosoc-investigation/scripts/resolve.py", "resolve")
auto = load("skills/zerosoc-response/scripts/autonomy.py", "autonomy")


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

    def test_no_finding_promotes_and_gap_caps(self):
        ledger = {"alerts": [{"id": "A", "type": "x", "entity": "e", "confidence": "High"}], "findings": [], "visibility_gaps": [{"data_source": "EDR"}]}
        r = triage.decide(ledger)
        self.assertEqual(r["decision"], "Promote"); self.assertEqual(r["confidence_id"], 2)

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
