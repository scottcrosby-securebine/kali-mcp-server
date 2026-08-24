import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ContainerIntegrationContractTests(unittest.TestCase):
    def test_release_workflow_runs_real_integration_gate_for_platform_matrix(self):
        workflow = (ROOT / ".github/workflows/container.yml").read_text(encoding="utf-8")
        self.assertIn("linux/amd64", workflow)
        self.assertIn("linux/arm64", workflow)
        self.assertIn("tests/integration/run_container_integration.py", workflow)
        self.assertIn('--platform "${{ matrix.platform }}"', workflow)

    def test_apple_silicon_evidence_schema_cannot_be_mistaken_for_ci_emulation(self):
        schema = json.loads(
            (ROOT / "tests/integration/apple-silicon-evidence.schema.json").read_text(encoding="utf-8")
        )
        properties = schema["properties"]
        self.assertEqual("Darwin", properties["host"]["properties"]["system"]["const"])
        self.assertEqual("arm64", properties["host"]["properties"]["architecture"]["const"])
        self.assertEqual({"passed", "failed", "not_run"}, set(
            properties["checks"]["items"]["properties"]["status"]["enum"]
        ))

    def test_fixture_registry_and_scan_targets_are_loopback_only(self):
        harness = (ROOT / "tests/integration/run_container_integration.py").read_text(encoding="utf-8")
        self.assertNotIn("example.com", harness)
        self.assertNotIn("scanme.nmap.org", harness)
        self.assertIn('"127.0.0.1"', harness)
        self.assertIn('f"{fixture_host}:{port}/kali-mcp-fixture:latest"', harness)
        self.assertRegex(harness, r'REGISTRY_IMAGE = "registry:2\.8\.3@sha256:[a-f0-9]{64}"')


if __name__ == "__main__":
    unittest.main()
