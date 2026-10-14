"""tools/check_binding.py: a reference binding is checked against the manifest of the server it describes."""
import copy, importlib.util, io, json, os, tempfile, unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("check_binding", os.path.join(ROOT, "tools", "check_binding.py"))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)

MANIFEST = {
    "server": "example", "version": "1.0.0",
    "capabilities": {
        "telemetry.endpoint": [
            {"tool": "mcp:x/hunt", "requires_all": ["hunting:DeviceProcessEvents"], "requires_any": []},
            {"tool": "mcp:x/evidence", "requires_all": ["api:alerts"], "requires_any": []}],
        "siem.search": [{"tool": "mcp:x/hunt", "requires_all": [], "requires_any": ["hunting:DeviceProcessEvents", "hunting:EmailEvents"]}],
        "containment.isolate_host": [{"tool": "mcp:x/isolate", "requires_all": ["api:machines", "role:Isolate"], "requires_any": []}],
        "decode": [{"tool": "mcp:x/decode", "requires_all": ["always:local"], "requires_any": []}],
    },
    "data_sources": {
        "EDR": {"any_of": ["hunting:DeviceProcessEvents"], "fallback": "alert_evidence"},
        "Anti-virus": {"any_of": ["api:alerts"]},
        "Reputation": {"all_of": ["api:machines", "role:FileRead"]},
        "Firewall logs": {"any_of": []},
    },
}
BINDING = {
    "reference": {"manifest": "https://example.invalid/manifest.json",
                  "provides": ["api:alerts", "api:machines", "role:Isolate", "role:FileRead"]},
    "capabilities": {"telemetry.endpoint": {"tool": "mcp:x/evidence"}, "containment.isolate_host": {"tool": "mcp:x/isolate"},
                     "decode": {"tool": "mcp:x/decode"},
                     "soc.knowledge_base": {"tool": "file:./soc-kb/"}},
    "data_sources": {"EDR": False, "Anti-virus": True, "Reputation": True, "Firewall logs": False},
}


class ReferenceBinding(unittest.TestCase):
    def test_a_binding_the_manifest_derives_passes(self):
        self.assertEqual(check.differences(BINDING, MANIFEST), [])

    def test_the_first_option_whose_requirements_are_met_is_expected(self):
        b = copy.deepcopy(BINDING)
        b["reference"]["provides"].append("hunting:DeviceProcessEvents")
        found = check.differences(b, MANIFEST)
        self.assertIn("capability telemetry.endpoint: the manifest binds mcp:x/hunt, the binding mcp:x/evidence", found)
        self.assertIn("capability siem.search: the manifest binds mcp:x/hunt, the binding nothing", found)
        self.assertIn("data source 'EDR': the manifest makes it True, the binding False", found)

    def test_a_tool_the_server_no_longer_answers_with_is_reported(self):
        b = copy.deepcopy(BINDING)
        b["capabilities"]["telemetry.endpoint"]["tool"] = "mcp:x/alerts"
        self.assertEqual(check.differences(b, MANIFEST),
                         ["capability telemetry.endpoint: the manifest binds mcp:x/evidence, the binding mcp:x/alerts"])

    def test_a_source_the_server_reads_cannot_be_declared_missing(self):
        b = copy.deepcopy(BINDING)
        b["data_sources"]["Reputation"] = False
        self.assertEqual(check.differences(b, MANIFEST),
                         ["data source 'Reputation': the manifest makes it True, the binding False"])

    def test_all_of_needs_every_requirement(self):
        b = copy.deepcopy(BINDING)
        b["reference"]["provides"].remove("role:FileRead")
        self.assertIn("data source 'Reputation': the manifest makes it False, the binding True", check.differences(b, MANIFEST))

    def test_a_class_the_manifest_does_not_know_is_the_deployments_own(self):
        b = copy.deepcopy(BINDING)
        del b["capabilities"]["soc.knowledge_base"]
        self.assertEqual(check.differences(b, MANIFEST), [])

    def test_sources_must_be_the_same_set(self):
        b = copy.deepcopy(BINDING)
        del b["data_sources"]["Firewall logs"]
        b["data_sources"]["Proxy logs"] = False
        found = check.differences(b, MANIFEST)
        self.assertIn("data source 'Firewall logs': the manifest knows it, the binding does not answer it", found)
        self.assertIn("data source 'Proxy logs': the binding answers it, the manifest does not know it", found)

    def test_a_requirement_nothing_reads_is_a_typo(self):
        b = copy.deepcopy(BINDING)
        b["reference"]["provides"].append("api:alert")
        self.assertEqual(check.differences(b, MANIFEST),
                         ["reference.provides names api:alert, which nothing in the manifest requires"])

    def test_an_always_requirement_holds_without_being_listed(self):
        b = copy.deepcopy(BINDING)
        del b["capabilities"]["decode"]
        self.assertEqual(check.differences(b, MANIFEST), ["capability decode: the manifest binds mcp:x/decode, the binding nothing"])
        b = copy.deepcopy(BINDING)
        b["reference"]["provides"].append("always:local")
        self.assertEqual(check.differences(b, MANIFEST),
                         ["reference.provides names always:local, which holds on every deployment and is not listed"])

    def test_without_a_reference_there_is_nothing_to_check_against(self):
        b = copy.deepcopy(BINDING)
        del b["reference"]
        self.assertEqual(len(check.differences(b, MANIFEST)), 1)

    def test_the_command_reads_a_local_manifest_and_exits_on_a_difference(self):
        with tempfile.TemporaryDirectory() as d:
            m, good, bad = (os.path.join(d, n) for n in ("m.json", "good.json", "bad.json"))
            broken = copy.deepcopy(BINDING); broken["data_sources"]["Anti-virus"] = False
            for path, data in ((m, MANIFEST), (good, BINDING), (bad, broken)):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(check.main([good, "--manifest", m]), 0)
                self.assertEqual(check.main([bad, "--manifest", m]), 1)
            self.assertIn("matches the manifest of example 1.0.0", out.getvalue())
            self.assertIn("'Anti-virus'", out.getvalue())


class ShippedReferenceBinding(unittest.TestCase):
    """The Defender for Business example declares what it was derived from, so CI can check it."""

    def test_it_names_the_manifest_at_a_commit_of_a_release(self):
        """A commit cannot move under the check the way a tag can; the release names it for a reader."""
        with open(os.path.join(ROOT, "capabilities", "zerosoc.capabilities.defender-for-business.json"), encoding="utf-8") as f:
            reference = json.load(f)["reference"]
        self.assertRegex(reference["manifest"],
                         r"^https://raw\.githubusercontent\.com/ZeroSOC/zerosoc-mcp/[0-9a-f]{40}/servers/microsoft-security/capabilities\.manifest\.json$")
        self.assertRegex(reference["release"], r"^microsoft-security-v\d+\.\d+\.\d+$")
        self.assertIn("api:graph.alerts", reference["provides"])
        self.assertNotIn("hunting:DeviceProcessEvents", reference["provides"])


if __name__ == "__main__":
    unittest.main()
