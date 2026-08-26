import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from server_test_support import load_server


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_generate_report_validates_id_format_and_normalized_scanner(self):
        result_id = "A" * 32
        document = {
            "schema_version": 1,
            "scanner": "trivy",
            "source_type": "filesystem",
            "target_ref": "demo",
            "status": "success",
            "findings": [],
            "metadata": {},
        }
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / f"{result_id}.json").write_text(json.dumps(document), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="B" * 32),
            ):
                response = asyncio.run(self.server.generate_report(result_id, "html"))
                self.assertEqual(f"/reports/{'B' * 32}.html", response)
                self.assertEqual([f"{'B' * 32}.html"], [item.name for item in reports.iterdir()])
                self.assertIn(
                    "0.66.0-0kali1",
                    (reports / f"{'B' * 32}.html").read_text(encoding="utf-8"),
                )

                for invalid_ref, invalid_format in (
                    ("", "html"),
                    ("../result", "html"),
                    (f"/results/{result_id}.json", "html"),
                    (f"{result_id}.json", "html"),
                    ("short", "html"),
                    (f" {result_id}", "html"),
                    (result_id, "pdf"),
                    (result_id, "HTML"),
                ):
                    with self.subTest(result_ref=invalid_ref, format=invalid_format):
                        error = asyncio.run(self.server.generate_report(invalid_ref, invalid_format))
                        self.assertIn("Error", error)

                document["scanner"] = "nmap"
                (results / f"{result_id}.json").write_text(json.dumps(document), encoding="utf-8")
                error = asyncio.run(self.server.generate_report(result_id, "html"))
                self.assertIn("Error", error)

    def test_report_is_complete_self_contained_escaped_redacted_and_accessible(self):
        result_id = "C" * 32
        document = {
            "schema_version": 1,
            "scanner": "trivy",
            "source_type": "filesystem",
            "target_ref": "demo<&",
            "status": "partial",
            "findings": [
                {
                    "VulnerabilityID": "CVE-TEST-1",
                    "Title": '<script src="https://evil.invalid/x.js">attack</script>',
                    "Severity": "HIGH",
                    "Evidence": "Authorization: Bearer REPORT-SECRET",
                    "PrivateMaterial": "-----BEGIN PRIVATE KEY-----\nPEM-SECRET\n-----END PRIVATE KEY-----",
                    "Tokens": "Basic dXNlcjpwYXNz ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 xoxb-SLACKSECRET sk_live_STRIPESECRET glpat-GITLABSECRET",
                    "ObservedArtifact": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.JWT-SIGNATURE",
                    "Database": "mongodb://admin:DB-SECRET@example.test/app",
                    "SignedUrls": "https://s3.example/object?X-Amz-Credential=AKIAEXAMPLE12345678&X-Amz-Signature=AWS-SIGNATURE https://blob.example/item?sv=1&sig=AZURE-SIGNATURE https://storage.example/item?X-Goog-Credential=scope&X-Goog-Signature=GOOGLE-SIGNATURE",
                    "Remediation": "Upgrade package",
                },
                {"VulnerabilityID": "CVE-TEST-2", "Severity": "HIGH"},
                {"VulnerabilityID": "CVE-TEST-3", "Severity": "CRITICAL"},
            ],
            "metadata": {"tool_version": "0.66.0", "database_version": "2026-08-24"},
            "skipped_checks": ["license scan"],
            "failed_checks": ["database refresh"],
            "limitations": ["Offline database"],
        }
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / f"{result_id}.json").write_text(json.dumps(document), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="D" * 32),
            ):
                response = asyncio.run(self.server.generate_report(result_id))

            report = (reports / f"{'D' * 32}.html").read_text(encoding="utf-8")
            self.assertEqual(f"/reports/{'D' * 32}.html", response)
            for heading in (
                "Executive summary", "Scope", "Limitations", "Findings", "Evidence",
                "Severity", "Remediation", "Skipped/failed checks", "Tool/feed versions",
            ):
                self.assertIn(heading, report)
            for retained in ("demo&lt;&amp;", "CVE-TEST-1", "Upgrade package", "0.66.0", "2026-08-24"):
                self.assertIn(retained, report)
            for forbidden in ("<script", "REPORT-SECRET", "PEM-SECRET", "dXNlcjpwYXNz", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", "SLACKSECRET", "STRIPESECRET", "GITLABSECRET", "JWT-SIGNATURE", "AWS-SIGNATURE", "AZURE-SIGNATURE", "GOOGLE-SIGNATURE", "DB-SECRET", "<img", "<iframe"):
                self.assertNotIn(forbidden, report)
            self.assertNotIn("<script", report.lower())
            self.assertIn("Content-Security-Policy", report)
            self.assertIn('aria-label="Severity chart"', report)
            self.assertIn("Severity counts", report)
            self.assertIn("HIGH</th><td>2", report)
            self.assertIn("CRITICAL</th><td>1", report)
            self.assertIn("Status counts", report)

    def test_report_ids_are_independent_and_existing_files_are_never_overwritten(self):
        result_id = "E" * 32
        document = {
            "schema_version": 1, "scanner": "syft", "source_type": "dir",
            "target_ref": "demo", "status": "success", "findings": [], "metadata": {},
        }
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            reports.mkdir()
            (results / f"{result_id}.json").write_text(json.dumps(document), encoding="utf-8")
            collision = reports / f"{'F' * 32}.html"
            collision.write_bytes(b"keep-me")
            generated = iter(("F" * 32, "G" * 32, "H" * 32))
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", side_effect=lambda _=24: next(generated)),
            ):
                first = asyncio.run(self.server.generate_report(result_id))
                second = asyncio.run(self.server.generate_report(result_id))
            self.assertEqual(b"keep-me", collision.read_bytes())
            self.assertEqual(f"/reports/{'G' * 32}.html", first)
            self.assertEqual(f"/reports/{'H' * 32}.html", second)
            self.assertEqual(3, len(list(reports.iterdir())))

    def test_missing_malformed_and_schema_invalid_results_create_no_report(self):
        result_id = "M" * 32
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            cases = (
                None,
                "{broken",
                "[" * 1100 + "0" + "]" * 1100,
                json.dumps({"schema_version": 2, "scanner": "trivy", "findings": []}),
            )
            for content in cases:
                with self.subTest(content=content):
                    source = results / f"{result_id}.json"
                    source.unlink(missing_ok=True)
                    if content is not None:
                        source.write_text(content, encoding="utf-8")
                    with patch.object(self.server, "RESULTS_ROOT", results), patch.object(self.server, "REPORTS_ROOT", reports):
                        response = asyncio.run(self.server.generate_report(result_id))
                    self.assertIn("Error", response)
                    self.assertEqual([], list(reports.glob("*.html")) if reports.exists() else [])

    def test_full_recon_success_partial_and_total_failure_report_semantics(self):
        stages = ("nmap_service_scan", "dns_enum", "subfinder_scan", "whatweb_scan", "sslscan_scan")
        cases = (
            ("success", {name: f"✅ {name} ok" for name in stages}, True),
            ("partial", {**{name: f"✅ {name} ok" for name in stages}, "dns_enum": "❌ Error: dns failed"}, True),
            ("failed", {name: f"❌ Error: {name} failed" for name in stages}, False),
            ("failed", {name: "⚠️ Scan completed with warnings (return code: 2)" for name in stages}, False),
        )
        for status, outputs, expects_report in cases:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as root_text:
                reports = Path(root_text) / "reports"
                patches = [patch.object(self.server, name, AsyncMock(return_value=outputs[name])) for name in stages]
                with patch.object(self.server, "REPORTS_ROOT", reports), patch.object(
                    self.server.secrets, "token_urlsafe", return_value="R" * 32
                ):
                    for active in patches:
                        active.start()
                    try:
                        response = asyncio.run(self.server.full_recon("example.test"))
                    finally:
                        for active in reversed(patches):
                            active.stop()
                self.assertIsInstance(response, str)
                self.assertIn("COMPREHENSIVE RECONNAISSANCE", response)
                artifacts = list(reports.glob("*.html")) if reports.exists() else []
                self.assertEqual(1 if expects_report else 0, len(artifacts))
                if expects_report:
                    self.assertIn(f"report=/reports/{'R' * 32}.html", response)
                    report = artifacts[0].read_text(encoding="utf-8")
                    self.assertIn(status, report.lower())
                    self.assertIn("nmap_service_scan", report)
                    self.assertIn("1:9.20.26-1", report)
                    self.assertIn("2.1.5-1", report)
                    if status == "partial":
                        self.assertIn("dns failed", report)
                else:
                    self.assertNotIn("report=", response)
                    self.assertIn("failed", response.lower())

    def test_web_audit_writes_one_bounded_report_with_complete_nuclei_findings(self):
        findings = [{"template-id": f"finding-{index}", "name": "safe"} for index in range(250)]
        findings[-1]["name"] = "A" * 4000 + "beyond-public-bound"
        nuclei_result = self.server.NucleiScanText("\n".join(["✅ nuclei"] * 250), findings)
        with tempfile.TemporaryDirectory() as root_text:
            reports = Path(root_text) / "reports"
            with (
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="W" * 32),
                patch.object(self.server, "whatweb_scan", AsyncMock(return_value="✅ whatweb")),
                patch.object(self.server, "wafw00f_scan", AsyncMock(return_value="✅ waf")),
                patch.object(self.server, "web_headers", AsyncMock(return_value="✅ headers\nSet-Cookie: sessionid=COOKIE-SECRET; HttpOnly")),
                patch.object(self.server, "_deduplicate_url_inventory", AsyncMock(return_value=["https://example.test"])),
                patch.object(self.server, "nikto_scan", AsyncMock(return_value="✅ nikto")),
                patch.object(self.server, "nuclei_scan", AsyncMock(return_value=nuclei_result)),
                patch.object(self.server, "sslscan_scan", AsyncMock(return_value="❌ Error: tls failed")),
            ):
                response = asyncio.run(self.server.web_audit("https://example.test"))
            self.assertLessEqual(len(response.splitlines()), 200)
            self.assertTrue(response.endswith(f"report=/reports/{'W' * 32}.html"))
            artifacts = list(reports.glob("*.html"))
            self.assertEqual(1, len(artifacts))
            report = artifacts[0].read_text(encoding="utf-8")
            self.assertIn("partial", report.lower())
            self.assertIn("beyond-public-bound", report)
            self.assertNotIn("COOKIE-SECRET", report)

    def test_web_audit_total_failure_writes_no_report(self):
        with tempfile.TemporaryDirectory() as root_text:
            reports = Path(root_text) / "reports"
            failed = "❌ Error: check failed"
            with (
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server, "whatweb_scan", AsyncMock(return_value=failed)),
                patch.object(self.server, "wafw00f_scan", AsyncMock(return_value=failed)),
                patch.object(self.server, "web_headers", AsyncMock(return_value=failed)),
                patch.object(self.server, "_deduplicate_url_inventory", AsyncMock(return_value=["https://example.test"])),
                patch.object(self.server, "nikto_scan", AsyncMock(return_value=failed)),
                patch.object(self.server, "nuclei_scan", AsyncMock(return_value=failed)),
                patch.object(self.server, "sslscan_scan", AsyncMock(return_value=failed)),
            ):
                response = asyncio.run(self.server.web_audit("https://example.test"))
            self.assertIn("failed", response.lower())
            self.assertNotIn("report=", response)
            self.assertEqual([], list(reports.glob("*.html")) if reports.exists() else [])

    def test_report_applies_securebine_design_system(self):
        document = {
            "schema_version": 1, "scanner": "trivy", "source_type": "filesystem",
            "target_ref": "demo", "status": "success",
            "findings": [
                {"VulnerabilityID": "CVE-A", "Severity": "CRITICAL", "Title": "crit"},
                {"VulnerabilityID": "CVE-B", "Severity": "HIGH", "Title": "high"},
            ],
            "metadata": {},
        }
        report = self.server._render_report(document)
        # Scriptless + self-contained: no JS, no theme toggle, no external fetch.
        self.assertNotIn("<script", report.lower())
        self.assertNotIn("onclick", report.lower())
        # Theme via prefers-color-scheme, not a stamped attribute or a control.
        self.assertIn("@media (prefers-color-scheme: light)", report)
        # Brand token present (source of record: securebine-design/tokens.css).
        self.assertIn("#F5A701", report)
        # Logos embedded as CSS background data: URIs, never <img> tags; CSP allows data:.
        self.assertIn("data:image/png;base64,", report)
        self.assertNotIn("<img", report.lower())
        self.assertIn("img-src data:", report)
        self.assertTrue(self.server.REPORT_LOGO_DARK.startswith("data:image/png;base64,"))
        self.assertNotEqual(self.server.REPORT_LOGO_DARK, self.server.REPORT_LOGO_LIGHT)
        # STANDARD 6m: each severity mark carries its WORD, not colour alone.
        self.assertIn("CRITICAL</span>", report)
        self.assertIn('class="sev sev-critical"', report)
        self.assertIn('class="sev sev-high"', report)
        # h1 contract preserved for downstream tooling.
        self.assertIn("<h1>trivy report</h1>", report)

    def test_report_severity_word_survives_unknown_severity(self):
        document = {
            "schema_version": 1, "scanner": "syft", "source_type": "dir",
            "target_ref": "demo", "status": "success",
            "findings": [{"id": "X", "severity": "weird-value", "title": "t"}],
            "metadata": {},
        }
        report = self.server._render_report(document)
        # An unrecognised severity still prints its word in a mark, just without a colour class.
        self.assertIn('class="sev"', report)
        self.assertIn("weird-value", report)


if __name__ == "__main__":
    unittest.main()
