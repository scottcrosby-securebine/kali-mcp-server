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

                def fake_run(cmd, timeout=None, _flag=flag, _sample=sample):
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
        def fake_run(cmd, timeout=None):
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

        def fake_run(cmd, timeout=None):
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

                def fake_run(cmd, timeout=None, _flag=flag, _sample=sample):
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
        am = s._parse_amass_jsonl('{"name":"a.x.com","addresses":[{"ip":"1.1.1.1"}]}\n{"name":"b.x.com"}\nnot json\n')
        self.assertEqual(["a.x.com", "b.x.com"], [x["Title"] for x in am])  # bad line skipped
        sf = s._parse_subdomain_lines("a.x.com\nb.x.com\n\n")
        self.assertEqual(["a.x.com", "b.x.com"], [x["Title"] for x in sf])

    def test_parsers_never_raise(self):
        s = self.server
        # JSON parsers: bad input -> [].
        for parser in (s._parse_dnsrecon_json, s._parse_amass_jsonl):
            for payload in ("", "garbage", "{bad", None, 42, "[" * 40000 + "]" * 40000):
                with self.subTest(parser=parser.__name__, payload=repr(payload)[:12]):
                    self.assertEqual([], parser(payload))
        # Plain-text parser: any non-empty line is a host, so it never raises and
        # returns a list; empty/None -> [].
        for payload in ("", None, 42):
            self.assertEqual([], s._parse_subdomain_lines(payload))
        self.assertIsInstance(s._parse_subdomain_lines("anything\ngoes"), list)

    def test_tools_return_text_unchanged_and_capture(self):
        cases = [
            ("dns_recon", "dns_recon", "-j", json.dumps([{"type": "A", "name": "x.com", "address": "1.1.1.1"}]), ("x.com",)),
            ("subfinder_scan", "subfinder", "-o", "a.x.com\nb.x.com", ("x.com",)),
            ("amass_enum", "amass", "-json", '{"name":"a.x.com"}', ("x.com",)),
        ]
        for tool, scanner, flag, sample, args in cases:
            with self.subTest(tool=tool):
                captured = {}

                def fake_run(cmd, timeout=None, _flag=flag, _sample=sample):
                    self.assertNotIn("shell", cmd)
                    path = cmd[cmd.index(_flag) + 1]
                    Path(path).write_text(_sample, encoding="utf-8")
                    return f"{scanner} TEXT"

                def fake_write(document, _c=captured):
                    _c["doc"] = document
                    return "Z" * 32

                with (
                    patch.object(self.server, "run_command", fake_run),
                    patch.object(self.server, "_write_scanner_result", fake_write),
                ):
                    out = asyncio.run(getattr(self.server, tool)(*args))
                self.assertEqual(f"{scanner} TEXT", out)
                self.assertEqual(scanner, captured["doc"]["scanner"])
                self.assertTrue(captured["doc"]["findings"])

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


if __name__ == "__main__":
    unittest.main()
