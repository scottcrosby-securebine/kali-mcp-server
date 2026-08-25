from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from kali_mcp_launcher import Host


ROOT = Path(__file__).resolve().parent.parent
TEST_DIGEST = "sha256:" + "a" * 64


def qualification_run(command, **_kwargs):
    if command[:3] == ["docker", "offload", "status"]:
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "status": "STATUS_STOPPED",
            "engineStatus": "ENGINE_STATUS_STOPPED",
            "accountName": "",
            "engineWorkerID": "",
        }), stderr="")
    if command[:3] == ["docker", "desktop", "status"]:
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"Status": "running", "SessionID": "test-session"}),
            stderr="",
        )
    if command[:3] == ["docker", "context", "show"]:
        return SimpleNamespace(returncode=0, stdout="desktop-linux\n", stderr="")
    if command[:3] == ["docker", "context", "inspect"]:
        return SimpleNamespace(returncode=0, stdout=json.dumps([{
            "Name": "desktop-linux",
            "Metadata": {"Description": "Docker Desktop"},
            "Endpoints": {"docker": {
                "Host": f"unix://{Path.home()}/.docker/run/docker.sock",
            }},
        }]), stderr="")
    if command[:2] == ["docker", "info"]:
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "ID": "test-daemon-id",
            "Name": "docker-desktop",
            "OperatingSystem": "Docker Desktop",
            "Architecture": "aarch64",
            "ServerVersion": "29.2.1",
        }), stderr="")
    if command[:3] == ["docker", "image", "inspect"]:
        return SimpleNamespace(returncode=0, stdout=TEST_DIGEST + "\n", stderr="")
    return SimpleNamespace(returncode=0, stdout="PASS container integration\n", stderr="")


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
        self.assertEqual(2, properties["schema_version"]["const"])
        self.assertIn("v2", schema["$id"])
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

    def test_apple_qualification_uses_physical_host_detection(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        errors = io.StringIO()
        with (
            patch.object(sys, "argv", [
                "qualify-apple-silicon",
                "--image", "invalid",
                "--image-digest", "invalid",
                "--evidence", "/tmp/unused-apple-evidence.json",
            ]),
            redirect_stderr(errors),
            self.assertRaises(SystemExit),
        ):
            main()
        self.assertIn("--image-digest must be an immutable sha256 digest", errors.getvalue())
        self.assertNotIn("must run on a Darwin/arm64 host", errors.getvalue())

    def test_apple_qualification_records_local_arm64_docker_desktop(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        with tempfile.TemporaryDirectory() as root_text:
            evidence_path = Path(root_text) / "evidence.json"
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(evidence_path),
                ]),
                patch.object(main.__globals__["subprocess"], "run", side_effect=qualification_run),
            ):
                self.assertEqual(0, main())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(2, evidence["schema_version"])
        self.assertEqual("Docker Desktop", evidence["host"]["docker_platform"])
        self.assertEqual("arm64", evidence["host"]["docker_architecture"])
        self.assertEqual("desktop-linux", evidence["host"]["docker_context"])
        self.assertEqual("test-daemon-id", evidence["host"]["docker_daemon_id"])
        self.assertEqual("stopped-unconfigured", evidence["host"]["docker_offload"])
        self.assertEqual(
            f"unix://{Path.home()}/.docker/run/docker.sock",
            evidence["host"]["docker_endpoint"],
        )

    def test_apple_qualification_rejects_docker_host_override(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as root_text:
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(Path(root_text) / "evidence.json"),
                ]),
                patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote.invalid:2376"}),
                patch.object(main.__globals__["subprocess"], "run", side_effect=qualification_run),
                redirect_stderr(errors),
                self.assertRaises(SystemExit),
            ):
                main()
        self.assertIn("local Docker Desktop", errors.getvalue())

    def test_apple_qualification_rejects_docker_context_and_config_overrides(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        details = qualifier["docker_desktop_details"]
        for variable, value in (
            ("DOCKER_CONTEXT", "spoof"),
            ("DOCKER_CONFIG", "/tmp/spoof-docker-config"),
        ):
            with self.subTest(variable=variable), patch.dict(
                os.environ, {variable: value}, clear=True
            ), self.assertRaisesRegex(ValueError, "local Docker Desktop"):
                details()

    def test_apple_qualification_rejects_unix_socket_relay(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        details = qualifier["docker_desktop_details"]

        def relay_run(command, **kwargs):
            if command[:3] == ["docker", "context", "inspect"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{
                    "Name": "desktop-linux",
                    "Metadata": {"Description": "Docker Desktop"},
                    "Endpoints": {"docker": {"Host": "unix:///tmp/relay.sock"}},
                }]), stderr="")
            return qualification_run(command, **kwargs)

        with patch.object(
            details.__globals__["subprocess"], "run", side_effect=relay_run
        ), self.assertRaisesRegex(ValueError, "local Docker Desktop"):
            details()

    def test_apple_qualification_rejects_malformed_docker_desktop_status(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        details = qualifier["docker_desktop_details"]

        def malformed_status_run(command, **kwargs):
            if command[:3] == ["docker", "desktop", "status"]:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            return qualification_run(command, **kwargs)

        with patch.object(
            details.__globals__["subprocess"], "run", side_effect=malformed_status_run
        ), self.assertRaisesRegex(ValueError, "local Docker Desktop"):
            details()

    def test_apple_qualification_rejects_malformed_docker_version(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        details = qualifier["docker_desktop_details"]

        def malformed_version_run(command, **kwargs):
            if command[:2] == ["docker", "info"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps({
                    "ID": "test-daemon-id",
                    "OperatingSystem": "Docker Desktop",
                    "Architecture": "aarch64",
                    "ServerVersion": None,
                }), stderr="")
            return qualification_run(command, **kwargs)

        with patch.object(
            details.__globals__["subprocess"], "run", side_effect=malformed_version_run
        ), self.assertRaisesRegex(ValueError, "local Docker Desktop"):
            details()

    def test_apple_qualification_rejects_running_docker_offload(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        details = qualifier["docker_desktop_details"]

        def offload_running(command, **kwargs):
            if command[:3] == ["docker", "offload", "status"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps({
                    "status": "STATUS_RUNNING",
                    "engineStatus": "ENGINE_STATUS_RUNNING",
                    "accountName": "test@example.invalid",
                    "engineWorkerID": "cloud-worker",
                }), stderr="")
            return qualification_run(command, **kwargs)

        with patch.object(
            details.__globals__["subprocess"], "run", side_effect=offload_running
        ), self.assertRaisesRegex(ValueError, "local Docker Desktop"):
            details()

    def test_apple_qualification_rejects_configured_docker_offload(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        details = qualifier["docker_desktop_details"]

        def configured_offload(command, **kwargs):
            if command[:3] == ["docker", "offload", "status"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps({
                    "status": "STATUS_STOPPED",
                    "engineStatus": "ENGINE_STATUS_STOPPED",
                    "accountName": "test@example.invalid",
                    "engineWorkerID": "",
                }), stderr="")
            return qualification_run(command, **kwargs)

        with patch.object(
            details.__globals__["subprocess"], "run", side_effect=configured_offload
        ), self.assertRaisesRegex(ValueError, "local Docker Desktop"):
            details()

    def test_apple_qualification_pins_the_validated_daemon_for_all_work(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        calls = []

        def recording_run(command, **kwargs):
            calls.append((command, kwargs))
            return qualification_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as root_text:
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(Path(root_text) / "evidence.json"),
                ]),
                patch.object(main.__globals__["subprocess"], "run", side_effect=recording_run),
            ):
                self.assertEqual(0, main())

        expected = f"unix://{Path.home()}/.docker/run/docker.sock"
        integration = next(call for call in calls if call[0][0] == sys.executable)
        image_inspect = next(call for call in calls if call[0][:3] == [
            "docker", "image", "inspect",
        ])
        postflight = [call for call in calls if call[0][:2] == ["docker", "info"]][-1]
        postflight_offload = [
            call for call in calls if call[0][:3] == ["docker", "offload", "status"]
        ][-1]
        for _command, kwargs in (integration, image_inspect, postflight, postflight_offload):
            self.assertEqual(expected, kwargs["env"]["DOCKER_HOST"])
            self.assertNotIn("DOCKER_CONTEXT", kwargs["env"])
            self.assertNotIn("DOCKER_CONFIG", kwargs["env"])

    def test_apple_qualification_fails_if_daemon_identity_changes(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        info_calls = 0

        def changed_daemon_run(command, **kwargs):
            nonlocal info_calls
            result = qualification_run(command, **kwargs)
            if command[:2] == ["docker", "info"]:
                info_calls += 1
                if info_calls == 2:
                    payload = json.loads(result.stdout)
                    payload["ID"] = "different-daemon-id"
                    return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
            return result

        with tempfile.TemporaryDirectory() as root_text:
            evidence_path = Path(root_text) / "evidence.json"
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(evidence_path),
                ]),
                patch.object(
                    main.__globals__["subprocess"], "run", side_effect=changed_daemon_run
                ),
            ):
                self.assertEqual(1, main())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual("failed", evidence["result"])
        daemon_check = next(
            check for check in evidence["checks"] if check["name"] == "docker-daemon-identity"
        )
        self.assertEqual("failed", daemon_check["status"])

    def test_apple_qualification_fails_if_offload_starts_during_the_run(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        offload_calls = 0

        def changed_offload_run(command, **kwargs):
            nonlocal offload_calls
            result = qualification_run(command, **kwargs)
            if command[:3] == ["docker", "offload", "status"]:
                offload_calls += 1
                if offload_calls == 2:
                    return SimpleNamespace(returncode=0, stdout=json.dumps({
                        "status": "STATUS_RUNNING",
                        "engineStatus": "ENGINE_STATUS_RUNNING",
                        "accountName": "test@example.invalid",
                        "engineWorkerID": "cloud-worker",
                    }), stderr="")
            return result

        with tempfile.TemporaryDirectory() as root_text:
            evidence_path = Path(root_text) / "evidence.json"
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(evidence_path),
                ]),
                patch.object(
                    main.__globals__["subprocess"], "run", side_effect=changed_offload_run
                ),
            ):
                self.assertEqual(1, main())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual("failed", evidence["result"])
        self.assertEqual("docker-offload", evidence["checks"][-1]["name"])
        self.assertEqual("failed", evidence["checks"][-1]["status"])

    def test_offload_probe_failure_does_not_misreport_a_daemon_change(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        offload_calls = 0

        def failed_offload_probe(command, **kwargs):
            nonlocal offload_calls
            if command[:3] == ["docker", "offload", "status"]:
                offload_calls += 1
                if offload_calls == 2:
                    raise OSError("offload status unavailable")
            return qualification_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as root_text:
            evidence_path = Path(root_text) / "evidence.json"
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(evidence_path),
                ]),
                patch.object(
                    main.__globals__["subprocess"], "run", side_effect=failed_offload_probe
                ),
            ):
                self.assertEqual(1, main())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        checks = {check["name"]: check["status"] for check in evidence["checks"]}
        self.assertEqual("passed", checks["docker-daemon-identity"])
        self.assertEqual("not_run", checks["docker-offload"])
        offload_check = next(
            check for check in evidence["checks"] if check["name"] == "docker-offload"
        )
        self.assertIn("Could not verify", offload_check["detail"])

    def test_daemon_probe_failure_does_not_claim_identity_changed(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        info_calls = 0

        def failed_daemon_probe(command, **kwargs):
            nonlocal info_calls
            if command[:2] == ["docker", "info"]:
                info_calls += 1
                if info_calls == 2:
                    raise OSError("daemon info unavailable")
            return qualification_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as root_text:
            evidence_path = Path(root_text) / "evidence.json"
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(evidence_path),
                ]),
                patch.object(
                    main.__globals__["subprocess"], "run", side_effect=failed_daemon_probe
                ),
            ):
                self.assertEqual(1, main())
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        daemon_check = next(
            check for check in evidence["checks"] if check["name"] == "docker-daemon-identity"
        )
        self.assertEqual("not_run", daemon_check["status"])
        self.assertIn("Could not verify", daemon_check["detail"])

    def test_apple_qualification_rejects_remote_docker_context(self):
        qualifier = runpy.run_path(str(ROOT / "scripts/qualify-apple-silicon"))
        main = qualifier["main"]
        main.__globals__["detect_current_host"] = lambda: Host("darwin", "arm64")
        errors = io.StringIO()

        def remote_context_run(command, **kwargs):
            if command[:3] == ["docker", "context", "inspect"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps([{
                    "Name": "remote",
                    "Metadata": {"Description": "Docker Desktop"},
                    "Endpoints": {"docker": {"Host": "tcp://remote.invalid:2376"}},
                }]), stderr="")
            return qualification_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as root_text:
            with (
                patch.object(sys, "argv", [
                    "qualify-apple-silicon",
                    "--image", f"registry.invalid/kali-mcp@{TEST_DIGEST}",
                    "--image-digest", TEST_DIGEST,
                    "--evidence", str(Path(root_text) / "evidence.json"),
                ]),
                patch.object(main.__globals__["subprocess"], "run", side_effect=remote_context_run),
                redirect_stderr(errors),
                self.assertRaises(SystemExit),
            ):
                main()
        self.assertIn("local Docker Desktop", errors.getvalue())

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
        self.assertNotIn("/sys/class/net", harness)
        self.assertIn("/proc/net/route", harness)
        self.assertIn("/proc/net/ipv6_route", harness)
        self.assertIn("$NF", harness)
        self.assertNotIn("loopback-only network", harness)
        self.assertIn("no non-loopback routes", harness)
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
