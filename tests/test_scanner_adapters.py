import asyncio
import inspect
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


def _xml(value):
    """Escape a probe secret for an XML attribute without changing its shape."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


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

        def fake_run(cmd, timeout=None, **kwargs):
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
        def fake_run(cmd, timeout=None, **kwargs):
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


class TlsCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    SSLSCAN_XML = (
        '<?xml version="1.0"?><document><ssltest host="h" port="443">'
        '<protocol type="ssl" version="3" enabled="1"/>'
        '<protocol type="tls" version="1.0" enabled="1"/>'
        '<protocol type="tls" version="1.2" enabled="1"/>'
        '<cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="ECDHE-RSA-RC4-SHA"/>'
        '<cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384"/>'
        '</ssltest></document>'
    )
    TESTSSL_JSON = (
        '[{"id":"BEAST","severity":"HIGH","finding":"vulnerable","cve":"CVE-2011-3389"},'
        '{"id":"cert_trust","severity":"OK","finding":"valid"}]'
    )
    SSLYZE_JSON = (
        '{"server_scan_results":[{"scan_result":{'
        '"ssl_3_0_cipher_suites":{"result":{"accepted_cipher_suites":[{"cipher_suite":{"name":"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}}]}},'
        '"tls_1_2_cipher_suites":{"result":{"accepted_cipher_suites":[{"cipher_suite":{"name":"TLS_AES_256_GCM_SHA384"}}]}}}}]}'
    )

    def test_sslscan_parser_grades_protocols_and_ciphers(self):
        by_id = {f["id"]: f for f in self.server._parse_sslscan_xml(self.SSLSCAN_XML)}
        self.assertEqual("HIGH", by_id["tls-proto-sslv3"]["Severity"])
        self.assertEqual("MEDIUM", by_id["tls-proto-tlsv1.0"]["Severity"])
        self.assertNotIn("tls-proto-tlsv1.2", by_id)  # strong protocol not flagged
        self.assertEqual("HIGH", by_id["tls-cipher-ECDHE-RSA-RC4-SHA"]["Severity"])
        self.assertEqual("INFO", by_id["tls-cipher-ECDHE-RSA-AES256-GCM-SHA384"]["Severity"])

    def test_testssl_parser_maps_severity_and_keeps_cve(self):
        by_id = {f["id"]: f for f in self.server._parse_testssl_json(self.TESTSSL_JSON)}
        self.assertEqual("HIGH", by_id["BEAST"]["Severity"])
        self.assertEqual("CVE-2011-3389", by_id["BEAST"]["cve"])
        self.assertEqual("INFO", by_id["cert_trust"]["Severity"])  # OK -> INFO

    def test_sslyze_parser_grades_weak_ciphers(self):
        findings = self.server._parse_sslyze_json(self.SSLYZE_JSON)
        self.assertTrue(any(f["Severity"] == "HIGH" and "3DES" in f["id"] for f in findings))

    def test_all_tls_parsers_never_raise_on_bad_input(self):
        for parser in (self.server._parse_sslscan_xml, self.server._parse_testssl_json, self.server._parse_sslyze_json):
            for payload in ("", "garbage", "<not xml", "{bad json", None, 42, "[]", "{}"):
                with self.subTest(parser=parser.__name__, payload=repr(payload)[:16]):
                    self.assertEqual([], parser(payload))
        # XXE / billion-laughs on the XML parser
        self.assertEqual([], self.server._parse_sslscan_xml(
            '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><document>&x;</document>'))

    def test_tls_tools_return_text_unchanged_and_capture(self):
        cases = [
            ("sslscan_scan", "sslscan", "--xml=", self.SSLSCAN_XML),
            ("testssl_scan", "testssl", "--jsonfile", self.TESTSSL_JSON),
            ("sslyze_scan", "sslyze", "--json_out=", self.SSLYZE_JSON),
        ]
        for tool, scanner, flag, sample in cases:
            with self.subTest(tool=tool):
                captured = {}

                def fake_run(cmd, timeout=None, _flag=flag, _sample=sample, **kwargs):
                    self.assertNotIn("shell", cmd)
                    path = None
                    for i, arg in enumerate(cmd):
                        if arg.startswith(_flag) and "=" in _flag:
                            path = arg.split("=", 1)[1]
                        elif arg == _flag.rstrip("="):
                            path = cmd[i + 1]
                    Path(path).write_text(_sample, encoding="utf-8")
                    return f"{scanner} TEXT"

                def fake_write(document, _c=captured):
                    _c["doc"] = document
                    return "Z" * 32

                with (
                    patch.object(self.server, "run_command", fake_run),
                    patch.object(self.server, "_write_scanner_result", fake_write),
                ):
                    out = asyncio.run(getattr(self.server, tool)("example.test"))
                self.assertEqual(f"{scanner} TEXT", out)
                self.assertEqual(scanner, captured["doc"]["scanner"])
                self.assertTrue(captured["doc"]["findings"])

    def test_tls_persist_failure_is_swallowed(self):
        def fake_run(cmd, timeout=None, **kwargs):
            for arg in cmd:
                if arg.startswith("--xml="):
                    Path(arg.split("=", 1)[1]).write_text(self.SSLSCAN_XML, encoding="utf-8")
            return "sslscan text"

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_write_scanner_result", lambda _d: (_ for _ in ()).throw(OSError("full"))),
        ):
            out = asyncio.run(self.server.sslscan_scan("example.test"))
        self.assertEqual("sslscan text", out)

    def test_deeply_nested_structured_output_does_not_fail_the_scan(self):
        # A JSON depth bomb raises RecursionError inside the parser; best-effort
        # capture must swallow it and still return the tool's text (B1).
        bomb = "[" * 100000 + "]" * 100000
        self.assertEqual([], self.server._parse_testssl_json(bomb))
        self.assertEqual([], self.server._parse_sslyze_json(bomb))

        def fake_run(cmd, timeout=None, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "--jsonfile":
                    Path(cmd[i + 1]).write_text(bomb, encoding="utf-8")
            return "testssl text"

        with patch.object(self.server, "run_command", fake_run):
            out = asyncio.run(self.server.testssl_scan("example.test"))
        self.assertEqual("testssl text", out)

    def test_target_beginning_with_dash_is_rejected(self):
        # Argument-injection guard: a leading '-' target must not reach the tool.
        with patch.object(self.server, "run_command") as run:
            for tool in ("sslscan_scan", "testssl_scan", "sslyze_scan"):
                with self.subTest(tool=tool):
                    response = asyncio.run(getattr(self.server, tool)("--xml=/etc/passwd"))
                    self.assertIn("Error", response)
            run.assert_not_called()

    def test_sslyze_weak_protocol_bumps_cipher_severity(self):
        sslyze = (
            '{"server_scan_results":[{"scan_result":{"ssl_3_0_cipher_suites":'
            '{"result":{"accepted_cipher_suites":[{"cipher_suite":{"name":"TLS_ECDHE_RSA_AES128"}}]}}}}]}'
        )
        findings = self.server._parse_sslyze_json(sslyze)
        self.assertTrue(findings)
        self.assertTrue(all(f["Severity"] == "HIGH" for f in findings))  # SSLv3 bump

    def test_single_id_report_accepts_tls_scanners(self):
        for scanner in ("sslscan", "testssl", "sslyze"):
            with self.subTest(scanner=scanner):
                document = {
                    "schema_version": 1, "scanner": scanner, "source_type": "host",
                    "target_ref": "h:443", "status": "success",
                    "findings": [{"id": "x", "Severity": "INFO", "Title": "x"}], "metadata": {},
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
                    self.assertNotIn("Error", response)
class WebCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_parsers_map_representative_samples(self):
        s = self.server
        ww = {f["id"]: f for f in s._parse_whatweb_json(json.dumps([{"plugins": {"nginx": {"version": ["1.18"]}, "jQuery": {}}}]))}
        self.assertIn("web-tech-nginx", ww)
        self.assertEqual("INFO", ww["web-tech-nginx"]["Severity"])
        nk = {f["id"]: f["Severity"] for f in s._parse_nikto_json(json.dumps({"vulnerabilities": [{"OSVDB": "3092", "msg": "x", "url": "/a"}, {"id": "0", "msg": "note"}]}))}
        self.assertEqual("MEDIUM", nk["3092"])
        self.assertEqual("INFO", nk["nikto-2"])
        ff = s._parse_ffuf_json(json.dumps({"results": [{"url": "http://x/admin", "status": 200, "length": 10}]}))
        self.assertEqual("INFO", ff[0]["Severity"])
        self.assertEqual("WAF detected: Cloudflare", s._parse_wafw00f_json(json.dumps([{"detected": True, "firewall": "Cloudflare"}]))[0]["Title"])
        self.assertEqual("No WAF detected", s._parse_wafw00f_json(json.dumps([{"detected": False}]))[0]["Title"])
        self.assertTrue(s._parse_paths_text("/admin (Status: 200)\nStarting gobuster"))
        self.assertTrue(s._parse_paths_text("+ http://x/admin (CODE:200|SIZE:10)\n==> DIRECTORY: /x/"))

    def test_redaction_is_not_catastrophic_on_long_scanner_strings(self):
        # Guard against ReDoS in the shared secret-redaction patterns: a long
        # alphanumeric run (as a hostile scanned target can reflect into a
        # finding) must redact in linear time, not O(n^2).
        import time
        big = "a" * (256 * 1024)
        start = time.monotonic()
        self.server._redact_scanner_data(big)
        self.assertLess(time.monotonic() - start, 5.0)
        # A real credential URL is still redacted after the pattern was bounded.
        self.assertNotIn("hunter2", self.server._redact_scanner_data("mongodb://a:hunter2@h/x"))

    def test_web_parsers_never_raise(self):
        s = self.server
        for parser in (s._parse_whatweb_json, s._parse_nikto_json,
                       s._parse_ffuf_json, s._parse_wafw00f_json, s._parse_paths_text):
            for payload in ("", "garbage", "{bad json", "[1,2,3]", None, 42, "[" * 50000 + "]" * 50000):
                with self.subTest(parser=parser.__name__, payload=repr(payload)[:12]):
                    self.assertEqual([], parser(payload))

    def test_web_tools_return_text_unchanged_and_capture(self):
        cases = [
            ("whatweb_scan", "whatweb", "--log-json=", json.dumps([{"plugins": {"nginx": {}}}])),
            ("nikto_scan", "nikto", "-o", json.dumps({"vulnerabilities": [{"OSVDB": "1", "msg": "m", "url": "/"}]})),
            ("ffuf_scan", "ffuf", "-o", json.dumps({"results": [{"url": "http://x/FUZZ", "status": 200}]})),
            ("gobuster_scan", "gobuster", "-o", "/admin (Status: 200)"),
            ("dirb_scan", "dirb", "-o", "+ http://x/admin (CODE:200|SIZE:1)"),
            ("wafw00f_scan", "wafw00f", "-o", json.dumps([{"detected": True, "firewall": "CF"}])),
        ]
        targets = {"ffuf_scan": "http://x/FUZZ"}
        for tool, scanner, flag, sample in cases:
            with self.subTest(tool=tool):
                captured = {}

                def fake_run(cmd, timeout=None, _flag=flag, _sample=sample, **kwargs):
                    self.assertNotIn("shell", cmd)
                    path = None
                    for i, arg in enumerate(cmd):
                        if _flag.endswith("=") and arg.startswith(_flag):
                            path = arg.split("=", 1)[1]
                        elif arg == _flag and not _flag.endswith("="):
                            path = cmd[i + 1]
                    Path(path).write_text(_sample, encoding="utf-8")
                    return f"{scanner} TEXT"

                def fake_write(document, _c=captured):
                    _c["doc"] = document
                    return "Z" * 32

                with (
                    patch.object(self.server, "run_command", fake_run),
                    patch.object(self.server, "_write_scanner_result", fake_write),
                ):
                    out = asyncio.run(getattr(self.server, tool)(targets.get(tool, "example.test")))
                self.assertEqual(f"{scanner} TEXT", out)
                self.assertEqual(scanner, captured["doc"]["scanner"])

    def test_single_id_report_accepts_web_scanners(self):
        for scanner in ("whatweb", "nikto", "ffuf", "gobuster", "dirb", "wafw00f"):
            with self.subTest(scanner=scanner):
                document = {"schema_version": 1, "scanner": scanner, "source_type": "host",
                           "target_ref": "http://x", "status": "success",
                           "findings": [{"id": "y", "Severity": "INFO", "Title": "y"}], "metadata": {}}
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
                    self.assertNotIn("Error", response)
class DnsReconCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_parsers_map_representative_samples(self):
        s = self.server
        dr = json.dumps([{"arguments": "-d x", "date": "now"},
                         {"type": "A", "name": "x.com", "address": "1.2.3.4"},
                         {"type": "MX", "name": "x.com", "exchange": "mail.x.com"}])
        f = {x["id"]: x for x in s._parse_dnsrecon_json(dr)}
        self.assertEqual(2, len(f))  # leading metadata record skipped
        self.assertIn("dns-A-x.com", f)
        self.assertEqual("INFO", f["dns-A-x.com"]["Severity"])
        # amass v5 prints assets under "<type>:" headers; headers, the
        # run_command status wrapper and error prose are all skipped.
        am = s._parse_amass_text("Scan completed successfully:\n\nFQDN:\n\na.x.com\nb.x.com\n")
        self.assertEqual(["a.x.com", "b.x.com"], [x["Title"] for x in am])
        self.assertEqual([], s._parse_amass_text("flag provided but not defined: -json\n"))
        sf = s._parse_subdomain_lines("a.x.com\nb.x.com\n\n")
        self.assertEqual(["a.x.com", "b.x.com"], [x["Title"] for x in sf])

    def test_parsers_never_raise(self):
        s = self.server
        # JSON parsers: bad input -> [].
        for parser in (s._parse_dnsrecon_json, s._parse_amass_text):
            for payload in ("", "garbage", "{bad", None, 42, "[" * 40000 + "]" * 40000):
                with self.subTest(parser=parser.__name__, payload=repr(payload)[:12]):
                    self.assertEqual([], parser(payload))
        # Plain-text parser: any non-empty line is a host, so it never raises and
        # returns a list; empty/None -> [].
        for payload in ("", None, 42):
            self.assertEqual([], s._parse_subdomain_lines(payload))
        self.assertIsInstance(s._parse_subdomain_lines("anything\ngoes"), list)

    def test_tools_return_text_unchanged_and_capture(self):
        # flag=None means the tool adds NO argument and capture parses the
        # tool's own text (amass v5 has no per-run structured output).
        cases = [
            ("dns_recon", "dns_recon", "-j", json.dumps([{"type": "A", "name": "x.com", "address": "1.1.1.1"}]), ("x.com",)),
            ("subfinder_scan", "subfinder", "-o", "a.x.com\nb.x.com", ("x.com",)),
            ("amass_enum", "amass", None, "FQDN:\n\na.x.com\n", ("x.com",)),
        ]
        for tool, scanner, flag, sample, args in cases:
            with self.subTest(tool=tool):
                captured = {}

                def fake_run(cmd, timeout=None, _flag=flag, _sample=sample, _c=captured, **kwargs):
                    self.assertNotIn("shell", cmd)
                    _c["argv"] = list(cmd)
                    if _flag is None:
                        return _sample  # capture reads the returned text
                    Path(cmd[cmd.index(_flag) + 1]).write_text(_sample, encoding="utf-8")
                    return f"{scanner} TEXT"

                def fake_write(document, _c=captured):
                    _c["doc"] = document
                    return "Z" * 32

                with (
                    patch.object(self.server, "run_command", fake_run),
                    patch.object(self.server, "_write_scanner_result", fake_write),
                ):
                    out = asyncio.run(getattr(self.server, tool)(*args))
                self.assertEqual(sample if flag is None else f"{scanner} TEXT", out)
                self.assertEqual(scanner, captured["doc"]["scanner"])
                self.assertTrue(captured["doc"]["findings"])

    # amass v5 has no structured-output flag: -json was removed and -oA is
    # registered but never read, so passing one turns every scan into a usage
    # error merged into the operator's text.
    def test_amass_adds_no_argument(self):
        captured = {}

        def fake_run(cmd, timeout=None, **kwargs):
            captured["argv"] = list(cmd)
            return "FQDN:\n\na.x.com\n"

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            asyncio.run(self.server.amass_enum("x.com"))
        # -timeout is amass_enum's own bounded-runtime arg (#76); the invariant
        # this test guards is that the CAPTURE path injects no output-file flag.
        self.assertEqual(["amass", "enum", "-passive", "-timeout", "8", "-d", "x.com"],
                         captured["argv"])
        for injected in ("-json", "-o", "-oA"):
            self.assertNotIn(injected, captured["argv"])

    # dnsrecon logs "Saving records to JSON file: <path>" to stderr, which
    # run_command merges. That line exists only because capture asked for it
    # and it discloses a server-internal path. Mock execute_command, NOT
    # run_command: the strip lives inside run_command and must happen before
    # its 200-line bound, so a run_command mock would prove nothing.
    def test_capture_path_never_reaches_operator_text(self):
        seen = {}

        def fake_exec(cmd, timeout=None, **kwargs):
            path = cmd[cmd.index("-j") + 1]
            seen["path"] = path
            Path(path).write_text(json.dumps([{"type": "A", "name": "x.com", "address": "1.1.1.1"}]), encoding="utf-8")
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="real record line\ntrailing line\n",
                stderr=f"2026-01-01 INFO Saving records to JSON file: {path}\n")

        with (
            patch.object(self.server, "execute_command", fake_exec),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            out = asyncio.run(self.server.dns_recon("x.com"))
        self.assertNotIn(seen["path"], out)
        self.assertNotIn("Saving records to JSON file", out)
        self.assertIn("real record line", out)

    # The strip must run BEFORE run_command's MAX_OUTPUT_LINES bound, or the
    # "(truncated N additional lines)" counter still reports the removed line
    # and the operator's text differs from an unflagged run.
    def test_stripped_line_does_not_shift_the_truncation_counter(self):
        body = "\n".join(f"record {index}" for index in range(self.server.MAX_OUTPUT_LINES + 59))

        def exec_for(flagged):
            def fake_exec(cmd, timeout=None, **kwargs):
                stderr = ""
                if flagged:
                    path = cmd[cmd.index("-j") + 1]
                    Path(path).write_text(json.dumps([{"type": "A", "name": "x.com"}]), encoding="utf-8")
                    stderr = f"2026-01-01 INFO Saving records to JSON file: {path}\n"
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=body, stderr=stderr)
            return fake_exec

        with (
            patch.object(self.server, "execute_command", exec_for(True)),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            captured = asyncio.run(self.server.dns_recon("x.com"))
        with patch.object(self.server, "execute_command", exec_for(False)):
            plain = self.server.run_command(["dnsrecon", "-d", "x.com"])
        self.assertEqual(plain, captured)

    # _redact_scanner_data only sees a secret-named key while the value is
    # still a dict, and only sees a pattern's trailing anchor while the value
    # is untruncated. Serializing or slicing first silently disables it.
    def test_secrets_redacted_before_serialization(self):
        s = self.server
        rec = {"type": "TXT", "name": "v.x.com", "password": "Hunter2LEAK", "api_key": "KEYLEAK"}
        dns = s._parse_dnsrecon_json(json.dumps([{"arguments": "meta"}, rec]))
        self.assertNotIn("Hunter2LEAK", json.dumps(dns))
        self.assertNotIn("KEYLEAK", json.dumps(dns))
        self.assertIn("[REDACTED]", dns[0]["evidence"])
        # A private key whose END anchor falls past the evidence cut.
        key = {"name": "k", "key": "-----BEGIN RSA PRIVATE KEY-----\n" + "LEAKBODY" * 40 + "\n-----END RSA PRIVATE KEY-----"}
        self.assertNotIn("LEAKBODY", json.dumps(s._parse_dnsrecon_json(json.dumps([{"arguments": "m"}, key]))))
        # id[:80] and Title[:200] must not disagree about one secret: the '@'
        # anchor lands exactly on the id cut at this password length.
        finding = s._parse_subdomain_lines("https://svcacct:" + "P" * 64 + "@h.x.com")[0]
        self.assertNotIn("PPPPPPPPPPPPPPPPPPPP", finding["id"])
        self.assertNotIn("PPPPPPPPPPPPPPPPPPPP", finding["Title"])

    # Uncapped id/Title let a hostile artifact stall the response while the
    # redactor walks megabytes, and store a multi-megabyte finding. Redaction
    # still runs first (it must), but on a bounded prefix.
    def test_json_parser_fields_are_bounded(self):
        s = self.server
        big = "n" * (2 * 1024 * 1024)
        cases = {
            "dnsrecon": s._parse_dnsrecon_json(json.dumps([{"arguments": "m"}, {"type": "A", "name": big}])),
            "amass": s._parse_amass_text(big + ".x.com"),
            "subfinder": s._parse_subdomain_lines(big),
        }
        for scanner, findings in cases.items():
            with self.subTest(scanner=scanner):
                self.assertTrue(findings)
                self.assertLessEqual(len(findings[0]["id"]), self.server.MAX_ID_CHARS)
                self.assertLessEqual(len(findings[0]["Title"]), self.server.MAX_TITLE_CHARS)

    # A truncation can cut a secret's CLOSING anchor out of reach, and the
    # attacker picks the distance, so no pre-slice bound is "far enough".
    # Every capped field goes through _clip, which redacts an orphaned opener.
    def test_secret_survives_no_truncation_distance(self):
        s = self.server
        for body in (8000, 8200, 200_000):
            with self.subTest(pem_body=body):
                record = {"name": "k", "strings": "-----BEGIN RSA PRIVATE KEY-----\n" + "LEAKBODY" * (body // 8) + "\n-----END RSA PRIVATE KEY-----"}
                parsed = s._parse_dnsrecon_json(json.dumps([{"arguments": "m"}, record]))
                self.assertNotIn("LEAKBODY", json.dumps(parsed))
        for password in (64, 8200, 100_000):
            with self.subTest(password=password):
                finding = s._parse_subdomain_lines("https://svcacct:" + "P" * password + "@h.x.com")[0]
                self.assertNotIn("P" * 20, finding["id"])
                self.assertNotIn("P" * 20, finding["Title"])

    # _clip must be correct on its own, not only after _redact_scanner_data has
    # already consumed the complete key pairs: only the LAST opener can be the
    # orphan, so the guard uses rfind.
    def test_clip_is_correct_without_prior_redaction(self):
        clip = self.server._clip
        complete = "-----BEGIN A PRIVATE KEY-----\nL1BODY-----END A PRIVATE KEY-----\n"
        self.assertNotIn("L2BODY", clip(complete + "-----BEGIN B PRIVATE KEY-----\nL2BODY" + "X" * 300, 300))
        self.assertEqual("[REDACTED]", clip("-----BEGIN RSA PRIVATE KEY-----\nLEAKBODY" + "X" * 400, 300))
        self.assertNotIn("LEAKBODY", clip("-----END RSA PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\nLEAKBODY" + "X" * 300, 300))
        self.assertNotIn("LEAKPW", clip("https://user:LEAKPW" + "X" * 500 + "@h.com", 300))
        # An unrelated later '@' must not be mistaken for the credential anchor.
        self.assertNotIn("LEAKPW", clip("https://user:LEAKPW" + "X" * 300 + " note@example.com", 300))
        # All THREE anchor-dependent patterns, not just PEM: the JWT needs its
        # signature segment and the URL credential needs its '@'.
        long_jwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJwYXNzd29yZCI6IkxFQUtQQVlMT0FEIn0" * 400 + ".sig"
        self.assertNotIn("eyJwYXNzd29yZCI", clip(long_jwt, 300))
        # ...and always the LAST opener, for every pattern, not only PEM.
        self.assertNotIn("LEAKPW", clip("https://a:goodpw@h1.com/https://b:LEAKPW" + "X" * 300, 300))
        self.assertNotIn("LEAKJWT", clip("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig eyJhbGciOiJIUzI1NiJ9.LEAKJWT" + "X" * 300, 300))
        # A complete, untruncated key is left for _redact_scanner_data.
        self.assertIn("-----END ", clip("-----BEGIN RSA PRIVATE KEY-----\nBODY-----END RSA PRIVATE KEY-----", 300))
        for value in (None, 42, 3.5, True):
            with self.subTest(value=value):
                self.assertIsInstance(clip(value, 50), str)

    # The web parsers carry the same defects and the same fixes as the DNS
    # ones. Only the dict-key half of _redact_scanner_data catches a cookie in
    # a whatweb plugin body: a Python dict repr puts a quote between the key
    # and the colon, so the value patterns cannot match it.
    def test_web_parsers_redact_before_serializing_and_bound_fields(self):
        s = self.server
        whatweb = s._parse_whatweb_json(json.dumps([{"target": "t", "plugins": {"p": {"Set-Cookie": "sid=SUPERSECRET"}}}]))
        self.assertNotIn("SUPERSECRET", json.dumps(whatweb))
        nikto = s._parse_nikto_json(json.dumps({"vulnerabilities": [
            {"OSVDB": "1", "msg": "b" * 5000, "url": "https://u:NIKTOLEAK@h.com"}]}))
        self.assertNotIn("NIKTOLEAK", json.dumps(nikto))
        self.assertLessEqual(len(nikto[0]["Title"]), self.server.MAX_TITLE_CHARS)
        ffuf = s._parse_ffuf_json(json.dumps({"results": [{"url": "https://u:FFUFLEAK@h.com/" + "c" * 5000, "status": 200}]}))
        self.assertNotIn("FFUFLEAK", json.dumps(ffuf))
        self.assertLessEqual(len(ffuf[0]["Title"]), self.server.MAX_TITLE_CHARS)

    # ffuf's banner prints an "Output file" line AND a "File format" line to
    # stderr whenever -o is set; stripping only the path leaves the second.
    def test_ffuf_capture_banner_is_fully_stripped(self):
        def exec_for(flagged):
            def fake_exec(cmd, timeout=None, **kwargs):
                stderr = ""
                if flagged:
                    path = cmd[cmd.index("-o") + 1]
                    Path(path).write_text(json.dumps({"results": []}), encoding="utf-8")
                    stderr = f" :: Output file       : {path}\n :: File format      : json\n"
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="banner\nresult line\n", stderr=stderr)
            return fake_exec

        with (
            patch.object(self.server, "execute_command", exec_for(True)),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            captured = asyncio.run(self.server.ffuf_scan("http://h/FUZZ"))
        with patch.object(self.server, "execute_command", exec_for(False)):
            plain = self.server.run_command(["ffuf", "-u", "http://h/FUZZ"])
        self.assertEqual(plain, captured)

    # sslyze writes '\n       Wrote JSON output to "<path>".\n' -- a blank line
    # AND a path line, both only because capture asked for the file. Stripping
    # the path line alone leaves the blank and shifts the truncation counter.
    def test_sslyze_capture_announcement_including_its_blank_line_is_stripped(self):
        for line_count in (3, self.server.MAX_OUTPUT_LINES + 50):
            with self.subTest(lines=line_count):
                body = "\n".join(f"L{index}" for index in range(line_count)) + "\n"

                def exec_for(flagged):
                    def fake_exec(cmd, timeout=None, **kwargs):
                        stderr = ""
                        if flagged:
                            path = [a.split("=", 1)[1] for a in cmd if a.startswith("--json_out=")][0]
                            Path(path).write_text("{}", encoding="utf-8")
                            stderr = f'\n       Wrote JSON output to "{path}".\n'
                        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=body, stderr=stderr)
                    return fake_exec

                with (
                    patch.object(self.server, "execute_command", exec_for(True)),
                    patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
                ):
                    captured = asyncio.run(self.server.sslyze_scan("h", "443"))
                with patch.object(self.server, "execute_command", exec_for(False)):
                    plain = self.server.run_command(["sslyze", "h:443"])
                self.assertEqual(plain, captured)

    # nikto treats -o as a PREFIX and appends ".$fmt" unless the path already
    # ends in it, so the capture suffix and the -Format value are coupled.
    def test_nikto_capture_suffix_matches_its_output_format(self):
        seen = {}

        def fake_exec(cmd, timeout=None, **kwargs):
            seen["argv"] = list(cmd)
            path = cmd[cmd.index("-o") + 1]
            Path(path).write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="nikto\n", stderr="")

        with (
            patch.object(self.server, "execute_command", fake_exec),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            asyncio.run(self.server.nikto_scan("h", "80"))
        argv = seen["argv"]
        self.assertEqual("json", argv[argv.index("-Format") + 1])
        self.assertTrue(argv[argv.index("-o") + 1].endswith(".json"))

    # Structural sweep. Every finding-producing function must redact and bound,
    # whatever wave it came from. An enumerated list is what let _parse_paths_text
    # and _parse_wafw00f_json keep leaking while six siblings were fixed, so this
    # DISCOVERS them instead of naming them. Each probe puts the secret in EVERY
    # scanner-controlled field, not one: probing a single field is what let
    # sslscan's `sslversion`/`bits` and sslyze's `label` slip through a green run.
    PARSER_PROBES = {
        "_parse_dnsrecon_json": lambda secret: json.dumps([{"arguments": "m"}, {"type": secret, "name": secret, "address": secret, "extra": [secret], "nested": {"k": secret}}]),
        "_parse_amass_text": lambda secret: secret + ".x.com",
        "_parse_subdomain_lines": lambda secret: secret + ".x.com",
        "_parse_paths_text": lambda secret: "/a?" + secret,
        "_parse_whatweb_json": lambda secret: json.dumps([{"target": secret, "plugins": {secret: {"k": secret, "nested": [secret]}}}]),
        "_parse_nikto_json": lambda secret: json.dumps({"vulnerabilities": [{"OSVDB": secret, "msg": secret, "url": secret, "nested": [secret]}]}),
        "_parse_ffuf_json": lambda secret: json.dumps({"results": [{"url": "http://h/?" + secret, "input": secret, "status": 200, "nested": [secret]}]}),
        "_parse_wafw00f_json": lambda secret: json.dumps([{"detected": True, "firewall": secret, "manufacturer": secret, "nested": [secret]}]),
        "_parse_sqlmap": lambda secret: f"Parameter: {secret} (GET)\n    Type: {secret}\n    Title: {secret}\n    Payload: {secret}\n---\nback-end DBMS: {secret}\n",
        "_parse_wpscan": lambda secret: json.dumps({"version": {"number": secret, "status": secret, "vulnerabilities": [{"title": secret, "fixed_in": secret, "references": {"cve": [secret], "url": [secret]}}]}, "plugins": {secret: {"vulnerabilities": [{"title": secret, "fixed_in": secret, "references": {"cve": [secret]}}]}}, "users": {secret: {}}}),
        "_parse_wfuzz": lambda secret: json.dumps([{"code": secret, "chars": secret, "words": secret, "lines": secret, "url": "http://h/" + secret, "description": secret, "payload": secret}]),
        "_parse_testssl_json": lambda secret: json.dumps([{"id": secret, "severity": "HIGH", "finding": secret, "cve": [secret]}]),
        "_parse_sslyze_json": lambda secret: json.dumps({"server_scan_results": [{"scan_result": {f"{secret}_cipher_suites": {"result": {"accepted_cipher_suites": [{"cipher_suite": {"name": secret}}]}}}}]}),
        "_parse_sslscan_xml": lambda secret: f'<document><ssltest><protocol type="ssl" version="{_xml(secret)}" enabled="1"/><cipher status="accepted" sslversion="{_xml(secret)}" bits="{_xml(secret)}" cipher="{_xml(secret)}"/></ssltest></document>',
        "_parse_nmap_xml": lambda secret: f'<nmaprun><host><ports><port portid="80" protocol="tcp"><state state="open"/><service name="{_xml(secret)}" product="{_xml(secret)}" version="{_xml(secret)}"/><script id="{_xml(secret)}" output="{_xml(secret)}"/></port></ports></host></nmaprun>',
    }
    # Reached through a probe above rather than called directly.
    # Reached through a probe above rather than called directly, or a factory
    # the uniform one-argument probe cannot build: `_raw_text_parser` takes
    # (scanner, target) and is covered by RawTextCaptureTests
    # .test_parser_redacts_and_bounds, which runs the same three secret shapes.
    PROBED_ELSEWHERE = {"_nmap_script_finding", "_run_nuclei_capture", "_raw_text_parser"}

    # nuclei is not a _parse_* function and was missed by the first version of
    # the discovery filter -- it was also the one leaking, via a nested list of
    # strings lifted straight out of the scanned target's response body.
    def test_nuclei_findings_are_redacted_at_every_depth(self):
        secrets = {
            "cert-closed key": "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * 80 + "-----END CERTIFICATE-----",
            "over-bound key": "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * 1500 + "-----END RSA PRIVATE KEY-----",
            "keyword": "password=Hunter2LEAK",
        }
        for label, secret in secrets.items():
            with self.subTest(secret=label):
                line = json.dumps({"template-id": "t", "host": "http://h",
                                   "extracted-results": [secret], "nested": {"k": [secret]},
                                   "info": {"severity": "critical", "name": secret}})

                def fake_exec(cmd, timeout=None, **kwargs):
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=line, stderr="")

                with tempfile.TemporaryDirectory() as root_text:
                    root = Path(root_text)
                    with (
                        patch.object(self.server, "execute_command", fake_exec),
                        patch.object(self.server, "RESULTS_ROOT", root),
                    ):
                        text = asyncio.run(self.server.nuclei_scan("http://h"))
                    stored = "".join(path.read_text(encoding="utf-8") for path in root.glob("*.json"))
                self.assertNotIn("LEAKBODY", text)
                self.assertNotIn("Hunter2LEAK", text)
                self.assertNotIn("LEAKBODY", stored)
                self.assertNotIn("Hunter2LEAK", stored)

    def test_every_finding_parser_is_covered_by_a_probe(self):
        produces = set()
        for name in dir(self.server):
            attribute = getattr(self.server, name)
            if name.startswith("_") and inspect.isfunction(attribute):
                source = inspect.getsource(attribute)
                if "findings.append" in source or "return _clip_finding" in source:
                    produces.add(name)
        self.assertEqual(set(), produces - set(self.PARSER_PROBES) - self.PROBED_ELSEWHERE,
                         "finding-producing function added with no redaction probe")

    def test_every_finding_parser_redacts_and_bounds(self):
        # A keyword secret, and a private key closed by a CERTIFICATE trailer
        # (which SECRET_VALUE_PATTERNS' private-key pattern does not match).
        secrets = {
            "keyword": "password=Hunter2LEAK",
            "cert-closed key": "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * 80 + "-----END CERTIFICATE-----",
            "fake end": "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * 20 + "-----END X-----" + "Z" * 9000,
            # Shapes wave 5 exposed. They leaked through EVERY parser here, not
            # just the new one, because the defect was in the shared helpers.
            # ONE line each: a multi-line probe fed to a line-per-host parser
            # (amass, subfinder) yields hostname-shaped fragments, which is that
            # parser working correctly on garbage rather than a leak.
            "lowercase orphan key": "-----begin private key-----LEAKBODY",
            "key opener on a keyword line":
                "password: -----BEGIN PRIVATE KEY-----LEAKBODY-----END PRIVATE KEY-----",
        }
        for name, build in self.PARSER_PROBES.items():
            for label, secret in secrets.items():
                with self.subTest(parser=name, secret=label):
                    rendered = json.dumps(getattr(self.server, name)(build(secret)))
                    self.assertNotIn("Hunter2LEAK", rendered)
                    self.assertNotIn("LEAKBODY", rendered)
        caps = {"id": self.server.MAX_ID_CHARS, "Title": self.server.MAX_TITLE_CHARS}
        for name, build in self.PARSER_PROBES.items():
            with self.subTest(parser=name, case="bounded"):
                for finding in getattr(self.server, name)(build("n" * 300_000)):
                    for key, value in finding.items():
                        if isinstance(value, str):
                            cap = caps.get(key, self.server.MAX_EVIDENCE_CHARS)
                            self.assertLessEqual(len(value), cap, f"{name}.{key} unbounded")

    # id is the combined report's dedupe key. It must clear a full 253-char
    # FQDN plus a prefix, or distinct findings silently merge into one.
    def test_long_but_legitimate_values_stay_distinct(self):
        s = self.server
        label = "a" * 63
        names = [f"{label}.{label}.x{n}.example.com" for n in (1, 2)]
        records = [{"type": "A", "name": n, "address": "1.1.1.1"} for n in names]
        findings = s._parse_dnsrecon_json(json.dumps([{"arguments": "m"}] + records))
        self.assertEqual(2, len({f["id"] for f in findings}))
        # A ported URL is an authority, not a credential: five ffuf hits on one
        # host:port must stay five findings, and the path must survive.
        hits = [{"url": f"http://target.local:8080/p{n}", "status": 200} for n in range(5)]
        ffuf = s._parse_ffuf_json(json.dumps({"results": hits}))
        self.assertEqual(5, len({f["id"] for f in ffuf}))
        self.assertIn("http://target.local:8080/p0", ffuf[0]["Title"])
        for url in ("http://example.com:8080/admin", "https://target.local:8443/", "http://10.0.0.5:8080/backup"):
            with self.subTest(url=url):
                self.assertEqual(url, s._clip(url, s.MAX_EVIDENCE_CHARS))
        # ...but a truncated credential is still redacted.
        self.assertNotIn("PWLEAK", s._clip("https://svcacct:PWLEAK" + "X" * 9000, 300))

    # NSE script output and testssl findings are the operator-facing substance
    # and were unbounded before capture; they must not be cut to a fifth of a page.
    def test_evidence_keeps_multi_kilobyte_tool_output(self):
        s = self.server
        nse = "| ssl-enum-ciphers:\n" + "|     TLS_RSA_WITH_AES_128_CBC_SHA - A\n" * 40
        self.assertGreater(len(nse), 1300)
        xml = f'<nmaprun><host><ports><port portid="443" protocol="tcp"><state state="open"/><script id="ssl-enum-ciphers" output="{nse}"/></port></ports></host></nmaprun>'
        evidence = [f for f in s._parse_nmap_xml(xml) if f["id"] == "ssl-enum-ciphers"][0]["evidence"]
        self.assertEqual(len(nse), len(evidence))
        finding = "x" * 1812
        self.assertEqual(1812, len(s._parse_testssl_json(json.dumps([{"id": "c", "severity": "LOW", "finding": finding}]))[0]["evidence"]))

    # Helper-level contracts. Each of these is currently also covered by a
    # parser path, but the recurring defect in this feature has been a helper
    # that is only safe because of what its caller happens to do next, so each
    # is pinned where it is defined.
    def test_bounded_for_redaction_never_emits_an_orphaned_anchor(self):
        bound = self.server.MAX_REDACT_CHARS
        key = "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * (bound // 4) + "-----END RSA PRIVATE KEY-----"
        for label, value in (("bare", key), ("nested", {"a": [{"b": key}]})):
            with self.subTest(shape=label):
                self.assertNotIn("LEAKBODY", json.dumps(self.server._bounded_for_redaction(value)))

    def test_truncation_guard_is_local_to_each_opener(self):
        clip = self.server._clip
        # A complete secret must not vouch for a later orphaned one...
        self.assertNotIn("L2BODY", clip(
            "-----BEGIN A PRIVATE KEY-----x-----END A PRIVATE KEY-----"
            "-----BEGIN B PRIVATE KEY-----L2BODY" + "X" * 300, 400))
        # ...nor a later complete one for an EARLIER orphan.
        self.assertNotIn("ORPHANPW", clip("https://a:ORPHANPW notes https://b:realpw@h.com", 400))
        self.assertNotIn("ORPHANJWT", clip(
            "eyJhbGciOiJIUzI1NiJ9.ORPHANJWT and eyJhbGciOiJIUzI1NiJ9.p.s", 400))
        # A ported URL is still not a credential, even beside a real one.
        self.assertIn("http://h:8080/x", clip("http://h:8080/x", 400))

    # dirb's OUTPUT_FILE line follows its banner's OWN trailing blank, so
    # collapsing a blank above every stripped line eats legitimate output.
    # sslyze's blank belongs to its announcement. Opposite handling, same code.
    def test_blank_collapse_is_opt_in_per_tool(self):
        banner = "\n-----------------\nDIRB v2.22\n-----------------\n\n"

        def exec_for(flagged):
            def fake_exec(cmd, timeout=None, **kwargs):
                stdout = banner + ("" if not flagged else f"OUTPUT_FILE: {cmd[cmd.index('-o') + 1]}\n") + "START_TIME: now\n"
                if flagged:
                    Path(cmd[cmd.index("-o") + 1]).write_text("/a\n", encoding="utf-8")
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=stdout, stderr="")
            return fake_exec

        with (
            patch.object(self.server, "execute_command", exec_for(True)),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            captured = asyncio.run(self.server.dirb_scan("http://h"))
        with patch.object(self.server, "execute_command", exec_for(False)):
            plain = self.server.run_command(["dirb", "http://h"])
        self.assertEqual(plain, captured)

    # amass v5 printScope lists one host under several asset types, and the id
    # is derived from the host alone.
    def test_amass_assets_are_deduped_and_paths_rejected(self):
        s = self.server
        self.assertEqual(["subdomain-x.com"], [f["id"] for f in s._parse_amass_text("DomainRecord:\n\nx.com\n\nFQDN:\n\nx.com\n")])
        for accepted in ("93.184.216.0/24", "*.dev.x.com", "_dmarc.x.com", "2606:2800:220:1::1"):
            with self.subTest(asset=accepted):
                self.assertTrue(s._parse_amass_text(accepted))
        for rejected in ("https://www.x.com/login", "/usr/share/wordlists/dirb/common.txt", "../../etc/passwd", "./"):
            with self.subTest(asset=rejected):
                self.assertEqual([], s._parse_amass_text(rejected))

    def test_single_id_report_accepts_dns_scanners(self):
        for scanner in ("dns_recon", "subfinder", "amass"):
            with self.subTest(scanner=scanner):
                document = {"schema_version": 1, "scanner": scanner, "source_type": "host",
                           "target_ref": "x.com", "status": "success",
                           "findings": [{"id": "y", "Severity": "INFO", "Title": "y"}], "metadata": {}}
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
                    self.assertNotIn("Error", response)


# === P2 wave 5: raw-text tail ===
# whois, nbtscan, smb_enum, metasploit search/info and fierce have no structured
# output of any kind, so capture parses the operator's own text through the
# out_args=None mode built for amass. responder_analyze is deliberately NOT
# wired: it spawns no subprocess and returns a constant.
class RawTextCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    # (tool, capture label, call args, the target the id/Title must carry)
    WIRED = [
        ("nbtscan_scan", "nbtscan", ("192.168.1.0/24",), "192.168.1.0/24"),
        ("smb_enum", "smbclient", ("10.0.0.5",), "10.0.0.5"),
        ("metasploit_search", "metasploit_search", ("eternalblue",), "eternalblue"),
        ("metasploit_info", "metasploit_info", ("exploit/windows/smb/ms17_010",), "exploit/windows/smb/ms17_010"),
        ("fierce_scan", "fierce", ("example.com",), "example.com"),
    ]

    def test_parser_maps_text_to_one_info_finding(self):
        parse = self.server._raw_text_parser("whois", "example.com")
        findings = parse("✅ Scan completed successfully:\n\nRegistrar: Example Inc\nStatus: ok")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("INFO", finding["Severity"])
        self.assertIn("example.com", finding["id"])
        self.assertIn("whois", finding["id"])
        self.assertIn("Registrar: Example Inc", finding["evidence"])

    def test_parser_never_raises_and_drops_failures(self):
        parse = self.server._raw_text_parser("whois", "x.com")
        # Nothing to capture: empty, whitespace, non-string, and the two hard
        # failure markers -- persisting an error string as an INFO finding would
        # put a bogus card in the report. Both markers are one-liners with no
        # body, which is what makes them nothing to capture (#31).
        for payload in ("", "   \n ", None, 42, [],
                        "❌ Error: Command not found. Tool may not be installed: whois",
                        "⏱️ Command timed out after 60 seconds. Try reducing scan scope."):
            with self.subTest(payload=repr(payload)[:24]):
                self.assertEqual([], parse(payload))
        # A run that exited non-zero WITH output is a real result: keep it.
        # Since #31 that arrives under ❌; the ⚠️ shape is kept alongside it
        # because the parser must stay banner-agnostic about substance.
        for payload in ("❌ Scan failed (exit code 1):\n\nNo match for domain",
                        "⚠️ Scan completed with warnings:\n\nNo match for domain"):
            with self.subTest(payload=payload[:24]):
                self.assertEqual(1, len(parse(payload)))

    def test_parser_redacts_and_bounds(self):
        parse = self.server._raw_text_parser("whois", "x.com")
        secrets = {
            "keyword": "password=Hunter2LEAK",
            "cert-closed key": "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * 80 + "-----END CERTIFICATE-----",
            "fake end": "-----BEGIN RSA PRIVATE KEY-----" + "LEAKBODY" * 20 + "-----END X-----" + "Z" * 9000,
        }
        for label, secret in secrets.items():
            with self.subTest(secret=label):
                rendered = json.dumps(parse("Contact: " + secret))
                self.assertNotIn("Hunter2LEAK", rendered)
                self.assertNotIn("LEAKBODY", rendered)
        # A hostile target reaches id and Title, so it is redacted there too.
        hostile = self.server._raw_text_parser("whois", "password=Hunter2LEAK")("body")
        self.assertNotIn("Hunter2LEAK", json.dumps(hostile))
        # Bounded at the same caps every other parser uses. The TARGET must be
        # long too: `Title` and `id` are built from it, so a short-target probe
        # leaves their caps untested (dropping the Title cap changed nothing).
        caps = {"id": self.server.MAX_ID_CHARS, "Title": self.server.MAX_TITLE_CHARS}
        long_target = self.server._raw_text_parser("whois", "t" * 300_000)
        for finding in long_target("body"):
            for key, value in finding.items():
                if isinstance(value, str):
                    self.assertLessEqual(len(value), caps.get(key, self.server.MAX_EVIDENCE_CHARS),
                                         f"raw parser .{key} unbounded for a long target")
        for finding in parse("n" * 300_000):
            for key, value in finding.items():
                if isinstance(value, str):
                    self.assertLessEqual(len(value), caps.get(key, self.server.MAX_EVIDENCE_CHARS),
                                         f"raw parser .{key} unbounded")

    # The whole point of the wave: the operator's text must be byte-identical to
    # a run without capture. Mock execute_command, not run_command -- the strip
    # and the 200-line bound both live inside run_command.
    def test_wired_tools_return_text_byte_unchanged_and_capture(self):
        body = "line one\nline two\n"
        for tool, scanner, args, target in self.WIRED:
            with self.subTest(tool=tool):
                seen = {}

                def fake_exec(cmd, timeout=None, **kwargs):
                    seen.setdefault("argv", []).append(list(cmd))
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=body, stderr="")

                captured = {}
                with (
                    patch.object(self.server, "execute_command", fake_exec),
                    patch.object(self.server, "_write_scanner_result", lambda d: captured.setdefault("doc", d) and "Z" * 32),
                ):
                    text = asyncio.run(getattr(self.server, tool)(*args))
                # The bare runner over the SAME argv the tool built.
                with patch.object(self.server, "execute_command", fake_exec):
                    plain = self.server.run_command(seen["argv"][0])
                self.assertEqual(plain, text)
                self.assertEqual(scanner, captured["doc"]["scanner"])
                self.assertEqual(1, len(captured["doc"]["findings"]))
                self.assertIn(target, captured["doc"]["findings"][0]["Title"])

    # whois left the raw-text family for a structured parser (#89 D3): capture
    # must still leave the operator text byte-identical and add no argument, but
    # now persists a structured registration finding with masked emails.
    def test_whois_capture_is_structured_and_text_unchanged(self):
        body = ("Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar Inc.\n"
                "Registrar Abuse Contact Email: abuse@example.com\n")
        seen = {}

        def fake_exec(cmd, timeout=None, **kwargs):
            seen.setdefault("argv", []).append(list(cmd))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=body, stderr="")

        captured = {}
        with (
            patch.object(self.server, "execute_command", fake_exec),
            patch.object(self.server, "_write_scanner_result",
                         lambda d: captured.setdefault("doc", d) and "Z" * 32),
        ):
            text = asyncio.run(self.server.whois_lookup("example.com"))
        with patch.object(self.server, "execute_command", fake_exec):
            plain = self.server.run_command(seen["argv"][0])
        self.assertEqual(plain, text)                              # text byte-unchanged
        self.assertEqual(["whois", "example.com"], seen["argv"][0])  # no argument added
        finding = captured["doc"]["findings"][0]
        self.assertEqual("whois", captured["doc"]["scanner"])
        self.assertEqual("Example Registrar Inc.", finding["registrar"])
        self.assertIn("a***@example.com", finding["emails"])       # masked at capture
        self.assertNotIn("abuse@example.com", json.dumps(captured["doc"]))

    # Capture must add NOTHING to argv in out_args=None mode, or the text
    # invariant is a claim rather than a property.
    def test_wired_tools_add_no_argument(self):
        expected = {
            "nbtscan_scan": ["nbtscan", "192.168.1.0/24"],
            "smb_enum": ["smbclient", "-L", "10.0.0.5", "-N"],
            "metasploit_search": ["msfconsole", "-q", "-x", "search eternalblue; exit"],
            "metasploit_info": ["msfconsole", "-q", "-x", "info exploit/windows/smb/ms17_010; exit"],
            "fierce_scan": ["fierce", "--domain", "example.com"],
        }
        for tool, _scanner, args, _target in self.WIRED:
            with self.subTest(tool=tool):
                seen = {}

                def fake_exec(cmd, timeout=None, **kwargs):
                    seen["argv"] = list(cmd)
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="x\n", stderr="")

                with (
                    patch.object(self.server, "execute_command", fake_exec),
                    patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
                ):
                    asyncio.run(getattr(self.server, tool)(*args))
                self.assertEqual(expected[tool], seen["argv"])

    # run_command has four no-substance returns, not two: the error and timeout
    # strings, and the two status lines a run with NO output produces. All four
    # would otherwise become an INFO card whose whole evidence is its own status.
    def test_runs_with_nothing_to_show_are_not_findings(self):
        parse = self.server._raw_text_parser("nbtscan", "10.0.0.1")
        for text in ("✅ Command completed successfully (no output)",
                     # #31 renamed the no-output non-zero line; the pre-#31
                     # shape stays covered because the rule is about substance,
                     # not about which banner run_command chose.
                     "❌ Command failed with exit code 1",
                     "⚠️ Command returned exit code 1",
                     "❌ Error: Command not found. Tool may not be installed: nbtscan",
                     "⏱️ Command timed out after 60 seconds."):
            with self.subTest(text=text[:28]):
                self.assertEqual([], parse(text))
        # A banner WITH a body below it is a real result and is kept -- ❌
        # included, or a failed scan would reach the report with no evidence of
        # WHY it found nothing.
        for text in ("✅ Scan completed successfully:\n\nDoing NBT name scan\n",
                     "❌ Scan failed (exit code 1):\n\nNo reply from 10.0.0.1\n",
                     "⚠️ Scan completed with warnings:\n\nNo reply from 10.0.0.1\n"):
            with self.subTest(text=text[:28]):
                self.assertEqual(1, len(parse(text)))

    # Credential leaks found by feeding WHOLE multi-line tool
    # text through the wave-4 redaction helper -- this is the first wave to do
    # that, so each was reachable but never reached. Every one is an end-to-end
    # check on the operator-visible evidence, not on the regex.
    def test_multiline_tool_text_does_not_leak_credentials(self):
        parse = self.server._raw_text_parser("whois", "example.com")
        cases = {
            # The keyword pattern's value is `[^\r\n]*`, so it ate a PEM opener
            # sharing its line and disarmed the private-key pattern behind it.
            "keyword pattern swallowing a PEM opener on its line":
                ("password: -----BEGIN PRIVATE KEY-----\n"
                 "MIIEvSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----", "SUPERSECRETKEYMATERIAL"),
            # The orphan guard's anchors were case-sensitive while the full
            # pattern was not, so a lowercase opener with no END matched neither.
            "lowercase PEM opener with no END":
                ("-----begin private key-----\nMIIEvLOWERCASELEAK\n", "LOWERCASELEAK"),
        }
        for label, (text, secret) in cases.items():
            with self.subTest(case=label):
                self.assertNotIn(secret, json.dumps(parse(text)))

    # PAIRED redaction table. Every redaction test in this file used to assert
    # only that a secret was ABSENT, never that legitimate content SURVIVED.
    # That asymmetry is why two regressions that amputated the tail of every
    # field carrying a well-formed credential passed a fully green suite. Both
    # halves are asserted here.
    REDACTION_MUST_REMOVE = (
        ("orphaned URL credential", "https://svc:PWLEAK", "PWLEAK"),
        ("orphaned JWT", "eyJhbGciOiJIUzI1NiJ9.PAYLOADLEAK", "PAYLOADLEAK"),
        ("orphaned key", "-----BEGIN RSA PRIVATE KEY-----\nKEYLEAK", "KEYLEAK"),
        ("orphaned lowercase key", "-----begin private key-----KEYLEAK", "KEYLEAK"),
        ("complete URL credential", "https://svc:PWLEAK@host/x", "PWLEAK"),
        ("complete key",
         "-----BEGIN RSA PRIVATE KEY-----\nKEYLEAK\n-----END RSA PRIVATE KEY-----", "KEYLEAK"),
        ("complete key then an orphaned one",
         "-----BEGIN RSA PRIVATE KEY-----\nA\n-----END RSA PRIVATE KEY-----\n"
         "-----BEGIN RSA PRIVATE KEY-----\nKEYLEAK", "KEYLEAK"),
        # Both orders of a complete/orphaned pair. What removes the orphan here
        # is `_redact_scanner_data`'s non-greedy private-key pattern, not the
        # orphan guard.
        ("orphaned key then a complete one",
         "-----BEGIN RSA PRIVATE KEY-----\nKEYLEAK\nfiller\n"
         "-----BEGIN RSA PRIVATE KEY-----\nB\n-----END RSA PRIVATE KEY-----", "KEYLEAK"),
        # --- #27. Every row below leaked on main. ---
        # H1: the closer was searched for anywhere in the region, so an
        # unrelated `@` on a later line vouched for the orphan above it. A
        # whois record carries an abuse address in nearly every case.
        ("orphan vouched for by a later unrelated @",
         "https://svc:PWLEAK\nRegistrar Abuse Contact Email: abuse@registrar.tld", "PWLEAK"),
        # H2: a keyword line ate the secret's OPENER, and the pattern that
        # would have caught the body needs an `-----END-----` a hostile server
        # simply omits. All four shapes the keyword pattern can swallow.
        ("keyword line eats an unpaired key opener",
         "password: -----BEGIN PRIVATE KEY-----\nMIIEvKEYLEAK", "MIIEvKEYLEAK"),
        ("keyword line eats a lowercase unpaired key opener",
         "secret=-----begin private key-----\nMIIEvKEYLEAK", "MIIEvKEYLEAK"),
        ("keyword line eats a split JWT opener",
         "authorization: eyJhbGciOiJIUzI1NiJ9.\neyJzdWIiPAYLOADLEAK", "PAYLOADLEAK"),
        ("keyword line eats a split URL credential opener",
         "token: https://svc:\nPWLEAK", "PWLEAK"),
        # X1: opener TYPES were tried in a fixed order with a return on the
        # first orphan, so a trailing bare key header made the guard cut THERE
        # and leave an orphaned JWT earlier in the value intact.
        ("a later key orphan must not preempt an earlier JWT orphan",
         "eyJhbGciOiJIUzI1NiJ9.PAYLOADLEAK -----BEGIN PRIVATE KEY-----", "PAYLOADLEAK"),
        # X2: the port tail was never range checked, so an all-numeric
        # password passed itself off as a port.
        ("an out-of-range numeric password is not a port", "https://svc:98765", "98765"),
        # C1/C2, both introduced by the first attempt at this fix and caught by
        # review, not by the suite. A keyword value that is an ordinary URL must
        # still be redacted whole -- stopping the value at any bare `scheme://`
        # left it in the clear -- and a bracket inside the userinfo must not let
        # a credential escape the pattern that exists to catch it.
        ("a keyword whose value is a plain URL",
         "password: http://svc.example/cb?k=SECRETVAL1", "SECRETVAL1"),
        ("a keyword whose value is a vault URL",
         "api_key: https://vault.example/s/SECRETVAL2", "SECRETVAL2"),
        ("a credential with a bracket in the userinfo",
         "https://us[er:PASSWORD1@host.example/x", "PASSWORD1"),
        ("a credential with a close bracket in the userinfo",
         "https://us]er:PASSWORD2@host.example/x", "PASSWORD2"),
        # A keyword has ALREADY said the value is a secret, so a numeric value
        # that merely looks like a port must not win over that.
        ("a keyword whose value is a port-shaped credential",
         "password: https://svc:12345", "12345"),
        ("a keyword whose port-shaped credential has a path",
         "token: https://svc:12345/path", "12345"),
        # An empty username is a real credential shape and used to pass every
        # matcher, because the userinfo was required to have a first character.
        ("a credential with an empty username",
         "prefix https://:PASSWORD1@db.internal/x suffix", "PASSWORD1"),
        # The orphan branch kept `scheme://user:` while the complete branch
        # already dropped the userinfo, so the username leaked out of one path.
        ("an orphaned credential does not disclose its username",
         "prefix https://dbadmin:hunter2", "dbadmin"),
        # D3. A URL parser removes tab, CR and LF before parsing, so each of
        # these is the single credential `user:PASSWORD` and stopping the cut at
        # the whitespace left the tail of the password in the report.
        ("a credential spanning a newline", "https://user:PASS\nWORDLEAKA@host/x", "WORDLEAKA"),
        ("a credential spanning a tab", "https://user:PASS\tWORDLEAKB@host/x", "WORDLEAKB"),
        ("a credential spanning a carriage return", "https://user:PASS\rWORDLEAKC@host/x", "WORDLEAKC"),
        # Every D3 row above carries a trailing `@host/x`, so all three pinned
        # only the branch where the closer is still reachable -- and the guard
        # exists for the case where it is NOT. With the `@` truncated away the
        # narrow whitespace run still applied and the tail leaked, on head but
        # not on base (#27 G1). The run-to-space is unconditional now.
        ("a newline-split credential with no trailing @",
         "https://user:PASS\nWORDLEAKD Name Server: NS1", "WORDLEAKD"),
        ("a tab-split credential with no trailing @",
         "https://user:PASS\tWORDLEAKE Name Server: NS1", "WORDLEAKE"),
        ("a CR-split credential with no trailing @",
         "https://user:PASS\rWORDLEAKF Name Server: NS1", "WORDLEAKF"),
    )
    REDACTION_MUST_KEEP = (
        ("a plain whois record",
         "Domain Name: EXAMPLE.COM\nRegistrar URL: https://www.markmonitor.com:443\n"
         "Registrar Abuse Contact Email: abuse@markmonitor.com\n"
         "Name Server: NS1.EXAMPLE.COM\n", "NS1.EXAMPLE.COM"),
        ("headers below a well-formed JWT",
         "HTTP/1.1 200 OK\nX-Auth: eyJhbGciOiJIUzI1NiJ9.eyJ1IjoiYSJ9.SIGSIG\n"
         "Server: nginx/1.18.0\n", "nginx/1.18.0"),
        # The two column-aligned shapes this family actually emits.
        ("an nbtscan name table",
         "10.0.0.5  ACME-DC1   <00> UNIQUE\n10.0.0.6  ACME-FS1   <20> UNIQUE\n", "ACME-FS1"),
        ("an msfconsole module list",
         "  exploit/windows/smb/ms17_010_eternalblue  2017-03-14  average\n", "ms17_010_eternalblue"),
        ("a URL with an empty port", "See https://example.com:/path and more", "and more"),
        # --- #27. Every row below was DESTROYED on main. ---
        # H3: the port tail accepted only `/ ? #` or end-of-string, so a
        # legitimate ported URL before any other character was read as an
        # orphan and everything from the URL onward was cut. One row per
        # terminator the pattern accepts, written out rather than generated:
        # the generated form drifted from the pattern immediately, leaving `}`
        # and the tab accepted by the code and pinned by nothing.
        ("a ported URL then a slash", "see https://host:8443/x then check log", "then check log"),
        ("a ported URL then a query", "see https://host:8443?a=1 then check log", "then check log"),
        ("a ported URL then a fragment", "see https://host:8443#top then check log", "then check log"),
        ("a ported URL then a double quote", 'see https://host:8443" then check log', "then check log"),
        ("a ported URL then a single quote", "see https://host:8443' then check log", "then check log"),
        ("a ported URL then a comma", "see https://host:8443, then check log", "then check log"),
        ("a ported URL then a semicolon", "see https://host:8443; then check log", "then check log"),
        ("a ported URL then a paren", "see https://host:8443) then check log", "then check log"),
        ("a ported URL then a bracket", "see https://host:8443] then check log", "then check log"),
        ("a ported URL then a brace", "see https://host:8443} then check log", "then check log"),
        ("a ported URL then a space", "see https://host:8443 then check log", "then check log"),
        ("a ported URL then a tab", "see https://host:8443\tthen check log", "then check log"),
        ("a ported URL then a serialized newline",
         "see https://host:8443\\n then check log", "then check log"),
        ("a ported URL then a real newline", "see https://host:8443\n then check log", "then check log"),
        ("an IPv6 URL with a port", "https://[2001:db8::1]:8443/status", "db8::1]:8443"),
        # H4/X3: redaction kept the secret's own opener as the `\\1` of
        # `\\1[REDACTED]`, the guard rematched it, found no closer, and
        # truncated the rest of the field. All three anchored patterns.
        ("content after a complete uppercase key",
         "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\nName Server: NS1", "NS1"),
        ("content after a complete lowercase key",
         "-----begin private key-----\nAAA\n-----end private key-----\nName Server: NS1", "NS1"),
        ("content after a complete URL credential",
         "https://dbadmin:hunter2@db.internal/x and more", "db.internal"),
        # H6: a JWT's own payload segment is itself a valid JWT opener, so a
        # well-formed three-segment token was judged an orphan.
        ("content after a complete JWT",
         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.SIGSIG Name Server: NS1", "NS1"),
        # D2/D3. An orphan is cut only to the end of its own run, not to the end
        # of the value. For a URL that run ends at a SPACE, not at any
        # whitespace, and only where no `@` is still reachable: a URL parser
        # strips tab, CR and LF before parsing, so a credential can span one.
        # There is deliberately NO row here for an abuse address on the line
        # BELOW an orphaned credential. It cannot survive, because under that
        # parser it may itself be part of the credential.
        ("text after a credential-shaped phrase",
         "ws://gateway:live contact ops@example.com", "contact ops@example.com"),
        ("text after an orphaned JWT",
         "eyJhbGciOiJIUzI1NiJ9.PAYLOADLEAK Name Server: NS1", "NS1"),
        ("text after a credential with an empty username",
         "prefix https://:PASSWORD1@db.internal/x suffix", "suffix"),
        # The paired half of the three G1 rows above, on the SAME strings: the
        # run-to-space must be unconditional AND must still stop at the space,
        # or the fix for the leak is just the end-of-value cut D2 removed.
        ("text after a newline-split credential",
         "https://user:PASS\nWORDLEAKD Name Server: NS1", "Name Server: NS1"),
        ("text after a tab-split credential",
         "https://user:PASS\tWORDLEAKE Name Server: NS1", "Name Server: NS1"),
        ("text after a CR-split credential",
         "https://user:PASS\rWORDLEAKF Name Server: NS1", "Name Server: NS1"),
    )

    def test_clip_never_exceeds_its_cap(self):
        """`_clip`'s one invariant: the result never exceeds `limit`. It has now
        broken three separate ways -- #27 H5 (the guard APPENDS its placeholder,
        so an opener landing near the boundary overshot; BOTH kept openers do it,
        and an earlier version of this test exercised only JWT pads), #27 R3 (a
        limit shorter than the placeholder made the slice negative and GREW the
        result), and #27 RT-B1 (R3's re-guard appends a placeholder of its own
        and the caller appended a second one). Each fix was scoped to the shape
        that had just broken, so this sweeps the space instead of that shape:
        both openers, limits -10 to 139 against 40 pad offsets, and a two-opener body
        that forces the re-guard to fire -- which is what RT-B1 needed and the
        single-opener rows above cannot produce."""
        cap = self.server.MAX_EVIDENCE_CHARS
        for opener in ("eyJabcdefgh.", "https://svc:"):
            # One opener, and TWO split by a space so the guard cuts twice.
            for name, tail in (("one-opener", "B" * 500),
                               ("two-opener", "B" + " " + opener + "C" * 500)):
                for offset in range(0, 40):
                    with self.subTest(opener=opener, tail=name, cap_offset=offset):
                        value = "A" * (cap - offset) + opener + tail
                        self.assertLessEqual(len(self.server._clip(value, cap)), cap)
                # Negative limits included: the invariant is max(limit, 0), and
                # dropping `limit = max(limit, 0)` from `_clip` only shows up here.
                for limit in range(-10, 140):
                    for offset in range(0, 40):
                        with self.subTest(opener=opener, tail=name, limit=limit, offset=offset):
                            value = "A" * max(0, limit - offset) + opener + tail
                            self.assertLessEqual(len(self.server._clip(value, limit)), max(limit, 0))

    def test_clip_reguard_keeps_the_redaction_marker_whole(self):
        """`_clip`'s re-guard branch, pinned. Deleting the whole
        `if len(clipped) > limit:` block left the suite green, because the cap
        invariant above is satisfied by the final `clipped[:limit]` on its own.
        What the branch actually buys is that the cut it has to make lands
        BEFORE the placeholder rather than through it: without it the output
        ends in `[REDA`, or in the bare opener with the marker sliced off
        entirely, and a redacted cut reads as the tool having stopped there.
        The re-redaction of the second slice is the other half and cannot be
        seen from outside, so this pins the half that shows."""
        for opener in ("eyJabcdefgh.", "https://svc:"):
            for limit in (30, 60, 120, self.server.MAX_EVIDENCE_CHARS):
                with self.subTest(opener=opener, limit=limit):
                    value = "A" * (limit - len(opener) - 1) + opener + "P" + "B" * 500
                    # The branch only fires when the guard's placeholder overshoots.
                    self.assertGreater(
                        len(self.server._redact_truncated_secret(value[:limit])), limit)
                    clipped = self.server._clip(value, limit)
                    self.assertTrue(clipped.endswith("[REDACTED]"), clipped[-20:])
                    self.assertEqual(limit, len(clipped))

    def test_paired_table_covers_every_terminator_the_pattern_accepts(self):
        """The terminator set was spelled three times and drifted three times:
        `}` and the tab ended up accepted by `URL_PORT_TAIL` and pinned by
        nothing. Hand-syncing copies is what failed, so this asserts the
        coverage instead -- add a terminator to the pattern and this fails until
        a row pins it.

        What pins the STRICT set today is the derivation
        `PORT_TERMINATORS = PORT_TERMINATORS_STRICT + ...`: while that holds,
        strict is a subset of wide and the strict loop below cannot fail on its
        own. The loop is here for the day someone un-derives them and spells
        strict separately again -- the fifth recurrence of this drift -- so that
        it fails instead of silently reopening it.

        A missing name must FAIL, not error and not pass. `getattr(..., "")`
        was the fifth recurrence's hiding place: renaming the set left the loop
        iterating an empty string and the suite green. An older revision that
        carries neither name is what the mutation gate replays against, and it
        accepts an assertion failure but rejects an AttributeError, so absence
        is asserted rather than raised."""
        pinned = "".join(text[len("see https://host:8443")] for _, text, _ in self.REDACTION_MUST_KEEP
                         if text.startswith("see https://host:8443"))
        for name in ("PORT_TERMINATORS", "PORT_TERMINATORS_STRICT"):
            terminators = getattr(self.server, name, None)
            self.assertIsNotNone(terminators, f"{name} must keep this name: the paired table iterates it")
            for terminator in terminators or "":
                with self.subTest(terminator_set=name, terminator=terminator):
                    self.assertIn(terminator, pinned)
        self.assertTrue({" ", "\t"} <= set(pinned), "whitespace terminators must be pinned too")

    def test_redaction_removes_secrets_and_keeps_everything_else(self):
        parse = self.server._raw_text_parser("whois", "example.com")
        for label, text, secret in self.REDACTION_MUST_REMOVE:
            with self.subTest(removes=label):
                self.assertNotIn(secret, json.dumps(parse(text)))
        for label, text, keep in self.REDACTION_MUST_KEEP:
            with self.subTest(keeps=label):
                self.assertIn(keep, parse(text)[0]["evidence"])

    # Redaction GROWS as well as shrinks: `token=x` (7) -> `token=[REDACTED]`
    # (16). A body under the cap before redaction can exceed it after, so
    # measuring the ORIGINAL text let a scan padded with short redactable lines
    # push its real output out of the report with no truncation marker.
    def test_redaction_growth_past_the_cap_is_still_marked(self):
        parse = self.server._raw_text_parser("whois", "example.com")
        text = "token=x\n" * 994 + "ZZZ_REAL_WHOIS_TAIL"
        self.assertLess(len(text), self.server.MAX_EVIDENCE_CHARS)  # under the cap...
        body = self.server._safe_scanner_value(text)
        self.assertGreater(len(body), self.server.MAX_EVIDENCE_CHARS)  # ...but over it after
        evidence = parse(text)[0]["evidence"]
        self.assertTrue(evidence.endswith("… [truncated]"), evidence[-40:])
        self.assertLessEqual(len(evidence), self.server.MAX_EVIDENCE_CHARS)

    # For this family the text IS the deliverable, so a cut must be visible
    # rather than reading as the tool having stopped there.
    def test_oversized_evidence_is_marked_not_silently_cut(self):
        parse = self.server._raw_text_parser("whois", "example.com")
        cap = self.server.MAX_EVIDENCE_CHARS
        evidence = parse("Registrar: " + "n" * (cap * 2))[0]["evidence"]
        self.assertTrue(evidence.endswith("… [truncated]"), evidence[-40:])
        self.assertLessEqual(len(evidence), cap)
        # A body that fits is untouched -- no spurious marker.
        short = parse("Registrar: Example Inc")[0]["evidence"]
        self.assertNotIn("truncated", short)
        self.assertIn("Registrar: Example Inc", short)

    # The shared runner rejects a target beginning with '-' because it would be
    # read as an option. That is right where the target IS a bare argv token,
    # and wrong for msfconsole, whose query is interpolated inside a single
    # `-x` string where a leading dash is msfconsole's own search syntax.
    def test_leading_dash_guard_applies_only_where_the_target_reaches_argv(self):
        seen = {}

        def fake_exec(cmd, timeout=None, **kwargs):
            seen["argv"] = list(cmd)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="x\n", stderr="")

        with (
            patch.object(self.server, "execute_command", fake_exec),
            patch.object(self.server, "_write_scanner_result", lambda d: "Z" * 32),
        ):
            # Positional-target tools keep the guard.
            for tool, argument in (("whois_lookup", "-h"), ("nbtscan_scan", "-v"),
                                   ("smb_enum", "-L"), ("fierce_scan", "--help")):
                with self.subTest(tool=tool):
                    seen.clear()
                    text = asyncio.run(getattr(self.server, tool)(argument))
                    self.assertIn("must not begin with", text)
                    self.assertEqual({}, seen)  # never executed
            # msfconsole is exempt from the PROCESS-argv dash guard
            # (guard_target=False: the value is one -x token), and this test's
            # name is about that. But #58 added a msfconsole-CONTENT guard: an
            # option-shaped token is a search/info OPTION, not a term, and
            # `search -o <path>` was a caller-named file write. So an option
            # token is now rejected there -- NOT by the process guard (the
            # distinction this test draws still holds), by the content guard.
            for tool, argument in (("metasploit_search", "-t exploit ms17_010"),
                                   ("metasploit_info", "-h")):
                with self.subTest(tool=tool):
                    seen.clear()
                    text = asyncio.run(getattr(self.server, tool)(argument))
                    self.assertNotIn("must not begin with", text)  # not the process guard
                    self.assertIn("option-like", text)             # the content guard
                    self.assertEqual({}, seen)                     # never executed
            # A legitimate search still reaches msfconsole unchanged.
            seen.clear()
            asyncio.run(self.server.metasploit_search("type:exploit ms17_010"))
            self.assertEqual(["msfconsole", "-q", "-x", "search type:exploit ms17_010; exit"], seen["argv"])

    # A capture failure must never fail a completed scan.
    def test_capture_failure_leaves_the_scan_text_intact(self):
        def fake_exec(cmd, timeout=None, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="whois body\n", stderr="")

        def boom(document):
            raise OSError("no space left on device")

        with (
            patch.object(self.server, "execute_command", fake_exec),
            patch.object(self.server, "_write_scanner_result", boom),
        ):
            text = asyncio.run(self.server.whois_lookup("example.com"))
        self.assertIn("whois body", text)
        self.assertNotIn("Error", text)

    # responder_analyze spawns no subprocess: there is no scan output to
    # capture, and wiring it would fabricate a finding out of a constant.
    def test_responder_is_not_wired_to_capture(self):
        calls = []

        with (
            patch.object(self.server, "execute_command", lambda *a, **k: calls.append(a)),
            patch.object(self.server, "_write_scanner_result", lambda d: calls.append(d)),
        ):
            text = asyncio.run(self.server.responder_analyze("eth0"))
        self.assertEqual([], calls)
        self.assertIn("Responder", text)

    def test_single_id_report_accepts_raw_scanners(self):
        for _tool, scanner, _args, _target in self.WIRED:
            with self.subTest(scanner=scanner):
                document = {"schema_version": 1, "scanner": scanner, "source_type": "host",
                            "target_ref": "x.com", "status": "success",
                            "findings": [{"id": "y", "Severity": "INFO", "Title": "y", "evidence": "raw"}],
                            "metadata": {}}
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
                    self.assertNotIn("Error", response)

    # Distinct targets must stay distinct findings: the combined report dedupes
    # on id, so a scanner-only id would merge two whois runs into one.
    def test_distinct_targets_stay_distinct(self):
        ids = {self.server._raw_text_parser("whois", host)("body")[0]["id"]
               for host in ("a.example.com", "b.example.com")}
        self.assertEqual(2, len(ids))

    # The raw finding renders through the existing finding article -- no
    # _render_report raw-card branch is needed.
    def test_raw_finding_renders_its_text(self):
        document = {"schema_version": 1, "scanner": "whois", "source_type": "host",
                    "target_ref": "example.com", "status": "success",
                    "findings": self.server._raw_text_parser("whois", "example.com")("Registrar: Example Inc"),
                    "metadata": {}}
        rendered = self.server._render_report(document)
        self.assertIn("Registrar: Example Inc", rendered)


class RedactionDifferentialExitCodeTests(unittest.TestCase):
    """`tests/redaction_differential.py` is a gate whose exit status IS its
    verdict, and the CI step maps each code to a different outcome. Nothing
    asserted what it returns, which is how "nothing to measure" shipped as 2 --
    a code CPython also returns when it cannot open the script file and argparse
    returns on any usage error, so the step passed with a false notice on a
    renamed gate path and on a renamed flag."""

    SCRIPT = Path(__file__).resolve().parent / "redaction_differential.py"

    def _status(self, *args):
        return subprocess.run([sys.executable, str(self.SCRIPT), *args],
                              cwd=self.SCRIPT.parent.parent,
                              capture_output=True, text=True).returncode

    def test_a_base_carrying_the_working_tree_file_exits_3(self):
        # A base byte-identical to the working tree, built without committing:
        # a blob of the current file and a dangling tree holding it. `git show
        # <tree>:<path>` reads that, which is all the script does with --base.
        repo = self.SCRIPT.parent.parent
        def git(*args, stdin=None):
            return subprocess.run(["git", *args], cwd=repo, input=stdin, check=True,
                                  capture_output=True, text=True).stdout.strip()
        blob = git("hash-object", "-w", "kali_pentest_server.py")
        tree = git("mktree", stdin=f"100644 blob {blob}\tkali_pentest_server.py\n")
        self.assertEqual(3, self._status("--base", tree))

    def test_usage_and_environment_errors_are_not_confusable_with_that(self):
        # Both are argparse's 2. The point is only that neither is 3, or the CI
        # step would report "nothing to measure" for a gate that never ran.
        self.assertEqual(2, self._status("--bogus-arg"))
        self.assertEqual(2, self._status("--base", "nosuchrev"))


if __name__ == "__main__":
    unittest.main()
