import json
from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ContainerIntegrationContractTests(unittest.TestCase):
    def test_release_workflow_runs_real_integration_gate_for_platform_matrix(self):
        workflow = (ROOT / ".github/workflows/container.yml").read_text(encoding="utf-8")
        self.assertIn("linux/amd64", workflow)
        self.assertIn("linux/arm64", workflow)
        self.assertIn("tests/integration/run_container_integration.py", workflow)
        self.assertIn('--platform "${{ matrix.platform }}"', workflow)
        self.assertIn("timeout-minutes:", workflow)

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
        self.assertIn("image_id", properties["image"]["required"])

        qualifier = (ROOT / "scripts/qualify-apple-silicon").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--image-digest", required=True)', qualifier)
        self.assertNotIn("hashlib", qualifier)

    def test_apple_qualification_binds_the_tested_reference_to_its_digest(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        validate = qualifier["validate_image_reference"]
        digest = "sha256:" + "a" * 64
        self.assertEqual(
            f"registry.invalid/kali-mcp@{digest}",
            validate(f"registry.invalid/kali-mcp@{digest}", digest),
        )
        with self.assertRaisesRegex(ValueError, "must end with"):
            validate("registry.invalid/kali-mcp:latest", digest)
        with self.assertRaisesRegex(ValueError, "must end with"):
            validate(
                f"registry.invalid/kali-mcp@{'sha256:' + 'b' * 64}",
                digest,
            )

    def test_fixture_registry_and_scan_targets_are_loopback_only(self):
        harness = (ROOT / "tests/integration/run_container_integration.py").read_text(encoding="utf-8")
        self.assertNotIn("example.com", harness)
        self.assertNotIn("scanme.nmap.org", harness)
        self.assertIn('"127.0.0.1"', harness)
        self.assertIn('registry_ref = "127.0.0.1:5000/kali-mcp-fixture:latest"', harness)
        self.assertRegex(harness, r'REGISTRY_IMAGE = "registry:2\.8\.3@sha256:[a-f0-9]{64}"')

    def test_harness_uses_launcher_and_an_isolated_container_network_namespace(self):
        harness = (ROOT / "tests/integration/run_container_integration.py").read_text(encoding="utf-8")
        self.assertIn("from kali_mcp_launcher import build_docker_command", harness)
        self.assertIn('f"--network=container:{registry_name}"', harness)
        self.assertIn('["docker", "network", "disconnect", "bridge", registry_name]', harness)
        self.assertNotIn("class TcpFixture", harness)
        self.assertNotRegex(harness, r"(?m)^\s*assert\s")

    def test_registry_is_seeded_by_host_http_without_daemon_registry_mutation(self):
        harness = (ROOT / "tests/integration/run_container_integration.py").read_text(encoding="utf-8")
        self.assertIn("publish_oci_fixture(endpoint, payloads)", harness)
        self.assertNotIn('"push"', harness)
        self.assertNotIn('"tag"', harness)
        self.assertNotIn("local_push_ref", harness)
        self.assertNotIn("insecure-registr", harness)


if __name__ == "__main__":
    unittest.main()
