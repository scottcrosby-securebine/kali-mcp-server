"""P3a / #88 — web-application OWASP/WSTG report.

Covers the spec's Test seams: the three new parsers, `_owasp_classify`,
`render_webapp` via `_render_report`, and `web_app_report` aggregation.
"""

import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


SQLMAP_TRANSCRIPT = """\
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3061=3061

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71)
---
[10:00:00] [INFO] the back-end DBMS is MySQL
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
"""

WPSCAN_JSON = json.dumps({
    "version": {
        "number": "5.2",
        "status": "insecure",
        "vulnerabilities": [
            {"title": "WordPress core RCE", "fixed_in": "5.8",
             "references": {"cve": ["2021-1234"]}},
        ],
    },
    "plugins": {
        "contact-form": {
            "vulnerabilities": [
                {"title": "Stored XSS in contact-form", "fixed_in": "2.0",
                 "references": {"url": ["http://example/adv"]}},
            ],
        },
    },
    "users": {"admin": {}, "editor": {}},
})

WFUZZ_JSON = json.dumps([
    {"code": 200, "chars": 100, "words": 10, "lines": 3, "url": "http://h/admin", "payload": "admin"},
    {"code": 403, "chars": 20, "words": 2, "lines": 1, "url": "http://h/.git", "payload": ".git"},
])


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_parse_sqlmap_one_high_finding_per_parameter(self):
        findings = self.server._parse_sqlmap(SQLMAP_TRANSCRIPT)
        self.assertEqual(1, len(findings))
        f = findings[0]
        self.assertEqual("HIGH", f["Severity"])
        self.assertEqual("id", f["param"])
        self.assertEqual("GET", f["place"])
        self.assertEqual("MySQL >= 5.0.12", f["dbms"])
        self.assertIn("boolean-based blind", f["technique"])
        self.assertIn("UNION query", f["technique"])
        self.assertEqual("id=1 AND 3061=3061", f["payload"])
        self.assertEqual("SQL injection: parameter id (GET)", f["Title"])

    def test_parse_sqlmap_empty_when_no_injection(self):
        self.assertEqual([], self.server._parse_sqlmap("no injection found"))
        self.assertEqual([], self.server._parse_sqlmap(None))

    def test_parse_wpscan_vulns_version_and_users(self):
        findings = self.server._parse_wpscan(WPSCAN_JSON)
        by_title = {f["Title"]: f for f in findings}
        core = next(f for f in findings if "WordPress core RCE" in f["Title"])
        self.assertEqual("HIGH", core["Severity"])          # has a CVE reference
        self.assertIn("CVE-2021-1234", core["reference"])
        plugin = next(f for f in findings if "Stored XSS" in f["Title"])
        self.assertEqual("MEDIUM", plugin["Severity"])      # named vuln, no CVE
        self.assertTrue(any(f["Severity"] == "MEDIUM" and "5.2" in f["Title"]
                            and "insecure" in f["Title"] for f in findings))
        users = next(f for f in findings if f["id"] == "wpscan-users")
        self.assertEqual("INFO", users["Severity"])
        self.assertIn("admin", users["Title"])

    def test_parse_wpscan_non_dict_is_empty(self):
        self.assertEqual([], self.server._parse_wpscan("not json"))
        self.assertEqual([], self.server._parse_wpscan("[]"))

    def test_parse_wfuzz_discovered_paths_info(self):
        findings = self.server._parse_wfuzz(WFUZZ_JSON)
        self.assertEqual(2, len(findings))
        self.assertTrue(all(f["Severity"] == "INFO" for f in findings))
        self.assertIn("http://h/admin", findings[0]["Title"])
        self.assertIn("code=200", findings[0]["evidence"])

    def test_parse_wfuzz_non_list_is_empty(self):
        self.assertEqual([], self.server._parse_wfuzz("{}"))
        self.assertEqual([], self.server._parse_wfuzz("garbage"))


class OwaspClassifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_known_tokens_map_to_category_and_wstg(self):
        c = self.server._owasp_classify
        self.assertEqual(("A03", "WSTG-INPV-05"),
                         c({"Title": "SQL injection: parameter id (GET)"}))
        self.assertEqual(("A03", "WSTG-INPV-01"), c({"Title": "Stored XSS in form"}))
        self.assertEqual(("A05", "WSTG-CONF-07"),
                         c({"Title": "x-frame-options header missing"}))
        self.assertEqual(("A06", "WSTG-CONF-01"),
                         c({"evidence": "plugin=contact-form fixed_in=2.0"}))

    def test_unmapped_returns_none_for_manual_review(self):
        self.assertIsNone(self.server._owasp_classify({"Title": "200 /images/logo.png"}))
        self.assertIsNone(self.server._owasp_classify("not a dict"))

    def test_classification_never_uses_scanner_name(self):
        # A finding with no matching token is unmapped even though it came from a
        # web scanner: mapping is observed-text-only, never inferred from tool.
        self.assertIsNone(self.server._owasp_classify({"Title": "harmless note", "id": "nikto-1"}))


def _result(scanner, target, findings):
    return {
        "schema_version": 1, "scanner": scanner, "source_type": "host",
        "target_ref": target, "status": "success", "metadata": {}, "findings": findings,
    }


class RenderWebappTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _render(self, results):
        document = {
            "schema_version": 1, "report_type": "webapp", "scanner": "combined",
            "source_type": "host", "target_ref": "x", "status": "success",
            "metadata": {}, "results": results,
        }
        return self.server._render_report(document)

    def test_dirbust_path_never_forges_an_owasp_category(self):
        # B1 (red team): a discovered path whose name contains a vuln token
        # (/old-sqli-notes/, /ssrf-docs/) must NOT token-match A03/A10 and mark
        # the category exercised -- a filename is not evidence of the class.
        for scanner in ("dirb", "gobuster", "ffuf", "wfuzz"):
            out = self._render([_result(scanner, "http://t/", [
                {"id": "d1", "Title": "/old-sqli-notes/", "Severity": "INFO", "evidence": "code=200"},
                {"id": "d2", "Title": "/ssrf-docs/", "Severity": "INFO", "evidence": "code=200"},
            ])])
            # every OWASP category stays a miss -- none forged exercised from a path
            self.assertEqual(0, out.count("owasp-hit"), scanner)
            self.assertEqual(10, out.count("owasp-miss"), scanner)
            self.assertNotIn("A03 Injection</td><td>WSTG", out, scanner)

    def test_render_grid_endpoints_sqlmap_and_honesty(self):
        results = [
            _result("sqlmap", "http://t/", [{
                "id": "sqlmap-id-GET", "Title": "SQL injection: parameter id (GET)",
                "Severity": "HIGH", "param": "id", "place": "GET",
                "dbms": "MySQL >= 5.0.12", "technique": "boolean-based blind",
                "payload": "id=1 AND 1=1", "evidence": "parameter=id place=GET",
            }]),
            _result("nikto", "http://t/", [{
                "id": "n1", "Title": "x-frame-options header missing", "Severity": "MEDIUM",
                "evidence": "http://t/<script>alert(1)</script>",
            }]),
            _result("dirb", "http://t/", [{
                "id": "p1", "Title": "/admin (CODE:200)", "Severity": "INFO", "evidence": "/admin",
            }]),
            _result("nikto", "http://t/", [{
                "id": "idor1", "Title": "Insecure Direct Object Reference on /api/user",
                "Severity": "MEDIUM", "evidence": "/api/user?id=2",
            }]),
        ]
        html = self._render(results)

        # OWASP coverage grid, with all ten categories and honest empty verdict.
        self.assertIn("OWASP Top-10 (2021) coverage", html)
        self.assertIn("A03 Injection", html)
        self.assertIn("not exercised", html)          # A02/A04/... are untouched
        self.assertIn("exercised", html)

        # Per-endpoint rows with WSTG ids sourced from the classification table.
        self.assertIn("WSTG-INPV-05", html)           # sqlmap -> A03
        self.assertIn("WSTG-CONF-07", html)           # nikto missing header -> A05

        # sqlmap worked-injection block present when a sqlmap finding is present.
        self.assertIn("Repro payload", html)
        self.assertIn("MySQL &gt;= 5.0.12", html)

        # Discovered-content section with a risk flag.
        self.assertIn("/admin", html)

        # IDOR is unprovable by a detection-only scan -> manual confirmation.
        self.assertIn("requires manual confirmation", html)

        # Attacker-controlled markup stays escaped, never live.
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

        # Honesty: an empty category is never called "secure".
        self.assertNotIn("<td>secure</td>", html)

    def test_render_sqlmap_block_absent_without_sqlmap_finding(self):
        html = self._render([_result("nikto", "http://t/", [
            {"id": "n1", "Title": "x-frame-options header missing", "Severity": "MEDIUM"}])])
        self.assertIn("No SQL injection was confirmed", html)
        self.assertIn("not exercised", html)
        self.assertNotIn("<td>secure</td>", html)

    def test_render_empty_results_all_not_exercised(self):
        html = self._render([])
        # Every one of the ten categories renders "not exercised", none "secure".
        self.assertEqual(10, html.count("<td>not exercised</td>"))
        self.assertNotIn("<td>secure</td>", html)


class WebAppReportAggregationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_web_app_report_aggregates_web_results_only(self):
        sqlmap_doc = _result("sqlmap", "http://victim/", [{
            "id": "sqlmap-id-GET", "Title": "SQL injection: parameter id (GET)",
            "Severity": "HIGH", "param": "id", "place": "GET", "dbms": "MySQL",
            "technique": "boolean-based blind", "payload": "id=1 AND 1=1",
            "evidence": "parameter=id",
        }])
        # A non-web scanner must be excluded from the web-app report.
        nmap_doc = _result("nmap", "10.0.0.9", [{
            "id": "port-22-tcp", "Title": "22/tcp ssh open", "Severity": "INFO"}])
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / ("A" * 32 + ".json")).write_text(json.dumps(sqlmap_doc), encoding="utf-8")
            (results / ("B" * 32 + ".json")).write_text(json.dumps(nmap_doc), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="C" * 32),
            ):
                response = asyncio.run(self.server.web_app_report(""))
                self.assertEqual(f"/reports/{'C' * 32}.html", response)
                html = (reports / f"{'C' * 32}.html").read_text(encoding="utf-8")
        self.assertIn("OWASP Top-10 (2021) coverage", html)
        self.assertIn("WSTG-INPV-05", html)        # sqlmap classified
        self.assertNotIn("10.0.0.9", html)         # nmap result filtered out
        self.assertNotIn("<td>secure</td>", html)

    def test_web_app_report_empty_store(self):
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            results.mkdir()
            with patch.object(self.server, "RESULTS_ROOT", results):
                response = asyncio.run(self.server.web_app_report(""))
        self.assertIn("No captured web-scanner results", response)


if __name__ == "__main__":
    unittest.main()
