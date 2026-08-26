import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scanners"


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class ScannerAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def invoke(self, name, *args, stdout=None, stderr="", returncode=0):
        completed = subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=fixture(name + "-success.json") if stdout is None else stdout, stderr=stderr
        )
        with tempfile.TemporaryDirectory() as results:
            with (
                patch.object(self.server, "RESULTS_ROOT", Path(results), create=True),
                patch.object(self.server.subprocess, "run", return_value=completed) as run,
            ):
                response = asyncio.run(getattr(self.server, name + ("_scan" if name == "trivy" else "_sbom"))(*args))
                files = [(path.name, path.read_text(encoding="utf-8")) for path in Path(results).iterdir()]
        return response, run, files

    def test_every_trivy_source_has_an_exact_daemonless_command(self):
        cases = (
            ("filesystem", "demo", ["trivy", "--cache-dir", "/tmp/trivy-cache", "filesystem", "--format", "json", "--no-progress", "--disable-telemetry", "/workspace/demo"]),
            ("sbom", "bom.json", ["trivy", "--cache-dir", "/tmp/trivy-cache", "sbom", "--format", "json", "--no-progress", "--disable-telemetry", "/workspace/bom.json"]),
            ("archive", "image.tar", ["trivy", "--cache-dir", "/tmp/trivy-cache", "image", "--input", "/artifacts/image.tar", "--format", "json", "--no-progress", "--disable-telemetry"]),
            ("registry", "registry.example/demo:1", ["trivy", "--cache-dir", "/tmp/trivy-cache", "image", "--image-src", "remote", "--format", "json", "--no-progress", "--disable-telemetry", "registry.example/demo:1"]),
        )
        for source, target, expected in cases:
            with self.subTest(source=source):
                _, run, _ = self.invoke("trivy", target, source)
                self.assertEqual(expected, run.call_args.args[0])
                self.assertNotIn("shell", run.call_args.kwargs)

    def test_every_syft_source_and_supported_format_is_explicit(self):
        sources = {
            "dir": "dir:/workspace/demo",
            "file": "file:/workspace/demo.lock",
            "docker-archive": "docker-archive:/artifacts/image.tar",
            "oci-archive": "oci-archive:/artifacts/image.tar",
            "oci-dir": "oci-dir:/workspace/layout",
            "registry": "registry:registry.example/demo:1",
        }
        targets = {"dir": "demo", "file": "demo.lock", "docker-archive": "image.tar", "oci-archive": "image.tar", "oci-dir": "layout", "registry": "registry.example/demo:1"}
        for source, selector in sources.items():
            with self.subTest(source=source):
                _, run, _ = self.invoke("syft", targets[source], source)
                self.assertEqual(["syft", selector, "-o", "cyclonedx-json"], run.call_args.args[0])
        for output_format in ("cyclonedx-json", "spdx-json", "syft-json"):
            with self.subTest(format=output_format):
                _, run, _ = self.invoke("syft", "demo", "dir", output_format)
                self.assertEqual(["syft", "dir:/workspace/demo", "-o", output_format], run.call_args.args[0])

    def test_invalid_values_fail_before_starting_a_process(self):
        cases = (
            ("trivy_scan", ("", "filesystem")),
            ("trivy_scan", ("demo", "docker")),
            ("syft_sbom", ("demo", "containerd", "cyclonedx-json")),
            ("syft_sbom", ("demo", "dir", "xml")),
            ("trivy_scan", ("registry-user:password@example.invalid/repo", "registry")),
            ("syft_sbom", ("docker://example.invalid/repo", "registry", "syft-json")),
        )
        for name, args in cases:
            with self.subTest(name=name, args=args), patch.object(self.server.subprocess, "run") as run:
                response = asyncio.run(getattr(self.server, name)(*args))
                self.assertIsInstance(response, str)
                self.assertIn("Error", response)
                run.assert_not_called()

    def test_filesystem_references_are_confined_before_execution(self):
        invalid = ("../etc/passwd", "nested/../../escape", "/etc/passwd", "/workspace-evil/file", "C:\\Windows\\secret")
        for target in invalid:
            with self.subTest(target=target), patch.object(self.server.subprocess, "run") as run:
                response = asyncio.run(self.server.trivy_scan(target, "filesystem"))
                self.assertIn("Error", response)
                run.assert_not_called()

    def test_symlink_escape_from_a_selected_mount_is_rejected(self):
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as outside:
            Path(workspace, "escape").symlink_to(Path(outside), target_is_directory=True)
            with (
                patch.object(self.server, "WORKSPACE_ROOT", Path(workspace), create=True),
                patch.object(self.server.subprocess, "run") as run,
            ):
                response = asyncio.run(self.server.trivy_scan("escape/secret", "filesystem"))
            self.assertIn("Error", response)
            run.assert_not_called()

    def test_success_persists_normalized_json_and_returns_opaque_id(self):
        response, _, files = self.invoke("trivy", "demo", "filesystem")
        self.assertEqual(1, len(files))
        name, text = files[0]
        result_id = name.removesuffix(".json")
        self.assertRegex(result_id, r"^[A-Za-z0-9_-]{16,}$")
        self.assertIn(result_id, response)
        normalized = json.loads(text)
        self.assertEqual("trivy", normalized["scanner"])
        self.assertEqual("success", normalized["status"])
        self.assertTrue(normalized["findings"])

    def test_syft_supported_output_shapes_normalize_findings(self):
        outputs = (
            {"artifacts": [{"name": "syft-package"}]},
            {"components": [{"name": "cyclonedx-package"}]},
            {"packages": [{"name": "spdx-package"}]},
        )
        for output in outputs:
            with self.subTest(keys=tuple(output)):
                _, _, files = self.invoke("syft", "demo", "dir", stdout=json.dumps(output))
                self.assertTrue(json.loads(files[0][1])["findings"])

    def test_failure_malformed_and_truncated_output_create_no_result(self):
        cases = (
            (fixture("trivy-success.json"), fixture("scanner-failure.txt"), 2),
            (fixture("malformed.json"), "", 0),
            (fixture("truncated.json"), "", 0),
        )
        for stdout, stderr, returncode in cases:
            with self.subTest(returncode=returncode, stdout=stdout[-20:]):
                response, _, files = self.invoke("trivy", "demo", "filesystem", stdout=stdout, stderr=stderr, returncode=returncode)
                self.assertIsInstance(response, str)
                self.assertFalse(files)
                self.assertNotIn("Traceback", response)

    def test_schema_invalid_json_creates_no_result(self):
        malformed_shapes = (
            {"Results": {}},
            {"Results": [{"Vulnerabilities": {"VulnerabilityID": "CVE-X"}}]},
            {"artifacts": {"name": "not-a-list"}},
        )
        calls = (("trivy", ("demo", "filesystem")), ("trivy", ("demo", "filesystem")), ("syft", ("demo", "dir")))
        for (scanner, args), output in zip(calls, malformed_shapes):
            with self.subTest(scanner=scanner, output=output):
                response, _, files = self.invoke(scanner, *args, stdout=json.dumps(output))
                self.assertIn("Error", response)
                self.assertFalse(files)

    def test_nested_secrets_are_redacted_without_discarding_findings(self):
        cases = (
            ("trivy", ("demo", "filesystem"), "secret-bearing-trivy.json", ("TrivyPass-6", "TrivyToken-6", "TrivyBearer-6", "TrivyPassword-6"), "keep-this-package"),
            ("syft", ("demo", "dir"), "secret-bearing-syft.json", ("SyftApiKey-6", "SyftPass-6", "SyftBearer-6"), "keep-this-syft-package"),
        )
        for scanner, args, fixture_name, sentinels, retained in cases:
            with self.subTest(scanner=scanner):
                response, _, files = self.invoke(scanner, *args, stdout=fixture(fixture_name))
                persisted = files[0][1]
                for sentinel in sentinels:
                    self.assertNotIn(sentinel, response)
                    self.assertNotIn(sentinel, persisted)
                self.assertIn(retained, persisted)

    def test_native_secret_match_and_colon_delimited_error_are_redacted(self):
        output = {"Results": [{"Secrets": [{"RuleID": "fixture-secret", "Match": "SUPERSECRET-RAW-VALUE"}]}]}
        response, _, files = self.invoke("trivy", "demo", "filesystem", stdout=json.dumps(output))
        self.assertNotIn("SUPERSECRET-RAW-VALUE", files[0][1])
        self.assertIn("fixture-secret", files[0][1])

        response, _, files = self.invoke(
            "trivy", "demo", "filesystem", stdout="", stderr="password: SUPERSECRET-COLON", returncode=2
        )
        self.assertNotIn("SUPERSECRET-COLON", response)

    def test_authorization_and_multiword_secrets_are_fully_redacted(self):
        output = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-FIXTURE",
                            "Title": "Authorization: Basic dXNlcjpTVVBFUlNFQ1JFVA==\nscan continued",
                        }
                    ]
                }
            ]
        }
        _, _, files = self.invoke("trivy", "demo", "filesystem", stdout=json.dumps(output))
        self.assertNotIn("dXNlcjpTVVBFUlNFQ1JFVA==", files[0][1])
        self.assertIn("CVE-FIXTURE", files[0][1])

        response, _, files = self.invoke(
            "trivy",
            "demo",
            "filesystem",
            stdout="",
            stderr="password: correct horse battery staple\nscanner aborted",
            returncode=2,
        )
        self.assertNotIn("correct horse battery staple", response)
        self.assertIn("scanner aborted", response)
        self.assertFalse(files)

    def test_existing_result_is_never_overwritten(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=fixture("trivy-success.json"), stderr="")
        with tempfile.TemporaryDirectory() as results:
            root = Path(results)
            existing = root / ("a" * 32 + ".json")
            existing.write_text("keep-me", encoding="utf-8")
            with patch.object(self.server, "RESULTS_ROOT", root, create=True), patch.object(self.server.subprocess, "run", return_value=completed):
                asyncio.run(self.server.trivy_scan("demo", "filesystem"))
            self.assertEqual("keep-me", existing.read_text(encoding="utf-8"))
            self.assertEqual(2, len(list(root.iterdir())))

    def test_trivy_database_provenance_is_pinned_when_the_scan_result_is_stored(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=fixture("trivy-success.json"), stderr="")
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            results.mkdir()
            db_metadata = root / "metadata.json"
            db_metadata.write_text(json.dumps({"Version": 2, "UpdatedAt": "scan-time"}), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "TRIVY_DB_METADATA_PATH", db_metadata),
                patch.object(self.server.subprocess, "run", return_value=completed),
            ):
                asyncio.run(self.server.trivy_scan("demo", "filesystem"))
            db_metadata.write_text(json.dumps({"Version": 3, "UpdatedAt": "later"}), encoding="utf-8")
            stored = json.loads(next(results.iterdir()).read_text(encoding="utf-8"))
            self.assertEqual(2, stored["metadata"]["database_Version"])
            self.assertEqual("scan-time", stored["metadata"]["database_UpdatedAt"])


class NmapCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    SAMPLE = (
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.18"/>'
        '<script id="http-title" output="Welcome"/></port>'
        '<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>'
        '<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/>'
        '<script id="smb-vuln-ms17-010" output="VULNERABLE: remote code execution"/></port>'
        '</ports></host></nmaprun>'
    )

    def test_parse_extracts_open_ports_and_scripts_with_severity(self):
        findings = self.server._parse_nmap_xml(self.SAMPLE)
        by_id = {f["id"]: f for f in findings}
        # open ports only (22 is closed -> excluded)
        self.assertIn("port-80-tcp", by_id)
        self.assertIn("port-445-tcp", by_id)
        self.assertNotIn("port-22-tcp", by_id)
        self.assertEqual("INFO", by_id["port-80-tcp"]["Severity"])
        self.assertEqual("nginx", by_id["port-80-tcp"]["product"])
        # VULNERABLE script -> HIGH; ordinary script -> INFO
        self.assertEqual("HIGH", by_id["smb-vuln-ms17-010"]["Severity"])
        self.assertEqual("INFO", by_id["http-title"]["Severity"])

    def test_parse_never_raises_on_hostile_or_empty_xml(self):
        for payload in (
            "", "<not xml", "not even close",
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><nmaprun>&x;</nmaprun>',
            '<!DOCTYPE lolz [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]><nmaprun><x>&b;</x></nmaprun>',
        ):
            with self.subTest(payload=payload[:20]):
                self.assertEqual([], self.server._parse_nmap_xml(payload))

    def test_tool_text_return_is_unchanged_and_result_is_captured(self):
        captured = {}

        def fake_run(cmd, timeout=None):
            self.assertNotIn("shell", cmd)
            oxi = cmd.index("-oX")
            # -oX path must precede the "--" separator
            self.assertLess(oxi, cmd.index("--"))
            Path(cmd[oxi + 1]).write_text(self.SAMPLE, encoding="utf-8")
            return "PORT STATE SERVICE\n80/tcp open http"

        def fake_write(document):
            captured["doc"] = document
            return "Z" * 32

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_write_scanner_result", fake_write),
        ):
            out = asyncio.run(self.server.nmap_scan("10.0.0.1"))
        self.assertEqual("PORT STATE SERVICE\n80/tcp open http", out)
        self.assertEqual("nmap", captured["doc"]["scanner"])
        self.assertEqual(1, captured["doc"]["schema_version"])
        self.assertEqual(2, len([f for f in captured["doc"]["findings"] if f["id"].startswith("port-")]))

    def test_single_id_report_accepts_a_captured_nmap_result(self):
        document = {
            "schema_version": 1, "scanner": "nmap", "source_type": "host",
            "target_ref": "10.0.0.1", "status": "success",
            "findings": [{"id": "port-80-tcp", "Severity": "INFO", "Title": "80/tcp http open"}],
            "metadata": {},
        }
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / f"{'A' * 32}.json").write_text(json.dumps(document), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="R" * 32),
            ):
                response = asyncio.run(self.server.generate_report("A" * 32))
            self.assertEqual(f"/reports/{'R' * 32}.html", response)
            self.assertNotIn("Error", response)

    def test_persist_failure_is_swallowed_and_scan_still_returns_text(self):
        def fake_run(cmd, timeout=None):
            Path(cmd[cmd.index("-oX") + 1]).write_text(self.SAMPLE, encoding="utf-8")
            return "nmap text output"

        def boom(_document):
            raise OSError("disk full")

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_write_scanner_result", boom),
        ):
            out = asyncio.run(self.server.nmap_port_scan("10.0.0.1", "80"))
        self.assertEqual("nmap text output", out)


if __name__ == "__main__":
    unittest.main()
