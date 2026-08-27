"""Renderer field fixes: #37 dedupe drops distinct findings, #38 trivy findings
are never normalized. Both live in `_render_report`; both assert on RENDERED
HTML, never on an internal helper."""

import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


# One nikto class of findings: nikto reuses test id 013587 for every
# missing-header result, so the id alone cannot identify a finding.
NIKTO_SHARED_ID_FINDINGS = [
    {"id": "013587", "Title": "/: Suggested security header missing: content-security-policy.",
     "Severity": "INFO", "evidence": "http://demo/"},
    {"id": "013587", "Title": "/: Suggested security header missing: referrer-policy.",
     "Severity": "INFO", "evidence": "http://demo/"},
    {"id": "013587", "Title": "/: Suggested security header missing: permissions-policy.",
     "Severity": "INFO", "evidence": "http://demo/"},
    {"id": "013587", "Title": "/: Suggested security header missing: strict-transport-security.",
     "Severity": "INFO", "evidence": "http://demo/"},
    {"id": "007342", "Title": "/: X-Frame-Options header is deprecated.",
     "Severity": "INFO", "evidence": "http://demo/"},
]

# Exactly the native shape trivy writes and earlier server versions persisted.
OLD_SHAPE_TRIVY_FINDING = {
    "VulnerabilityID": "CVE-2019-14234",
    "Title": "Django SQLi",
    "Severity": "CRITICAL",
    "PkgName": "django",
    "InstalledVersion": "2.2.0",
    "FixedVersion": "2.2.4",
    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-14234",
    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2019-14234",
                   "https://github.com/django/django/commit/deadbeef"],
    "CVSS": {"ghsa": {"V3Score": 9.8, "V3Vector": "CVSS:3.0/AV:N/AC:L"}},
    "DataSource": {"ID": "ghsa", "Name": "GitHub Security Advisory pip",
                   "URL": "https://github.com/advisories"},
}


def _articles(report):
    return report.count("<article>")


class DedupeKeepsDistinctFindingsTests(unittest.TestCase):
    """#37 — dedupe must remove true duplicates only."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _combined(self, findings):
        return self.server._render_report({
            "schema_version": 1, "scanner": "combined", "status": "success",
            "results": [{"schema_version": 1, "scanner": "nikto", "target_ref": "demo:80",
                         "status": "success", "findings": findings, "metadata": {}}],
        })

    def test_five_nikto_findings_sharing_a_test_id_render_five_articles(self):
        report = self._combined(NIKTO_SHARED_ID_FINDINGS)
        self.assertEqual(5, _articles(report))
        for finding in NIKTO_SHARED_ID_FINDINGS:
            self.assertIn(finding["Title"].replace("/:", "/:"), report)

    def test_genuine_exact_duplicate_still_collapses_to_one(self):
        duplicate = dict(NIKTO_SHARED_ID_FINDINGS[0])
        report = self._combined([NIKTO_SHARED_ID_FINDINGS[0], duplicate])
        self.assertEqual(1, _articles(report))

    def test_identical_findings_from_two_scans_of_one_target_collapse(self):
        finding = dict(NIKTO_SHARED_ID_FINDINGS[0])
        report = self.server._render_report({
            "schema_version": 1, "scanner": "combined", "status": "success",
            "results": [
                {"schema_version": 1, "scanner": "nikto", "target_ref": "demo:80",
                 "status": "success", "findings": [finding], "metadata": {}},
                {"schema_version": 1, "scanner": "nikto", "target_ref": "demo:80",
                 "status": "success", "findings": [dict(finding)], "metadata": {}},
            ],
        })
        self.assertEqual(1, _articles(report))

    def test_same_id_and_title_but_different_evidence_are_kept(self):
        first = dict(NIKTO_SHARED_ID_FINDINGS[0])
        second = dict(first, evidence="http://demo/admin")
        report = self._combined([first, second])
        self.assertEqual(2, _articles(report))


class TrivyNormalizationTests(unittest.TestCase):
    """#38 — trivy findings reach the report's slots, never as a Python repr."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _trivy_report(self, findings):
        return self.server._render_report({
            "schema_version": 1, "scanner": "trivy", "source_type": "filesystem",
            "target_ref": "/app", "status": "success", "findings": findings, "metadata": {},
        })

    def test_no_nested_value_renders_as_a_python_repr(self):
        report = self._trivy_report([OLD_SHAPE_TRIVY_FINDING])
        # Raw and HTML-escaped repr both: `escaped()` turns a repr's quotes into
        # &#x27;, so the bare "{'" check alone would pass on the broken renderer.
        self.assertNotIn("{'", report)
        self.assertNotIn("{&#x27;", report)
        self.assertNotIn("&#x27;:", report)

    def test_cvss_renders_as_a_formatted_score(self):
        report = self._trivy_report([OLD_SHAPE_TRIVY_FINDING])
        self.assertIn("9.8", report)
        self.assertIn("CVSS:3.0/AV:N/AC:L", report)

    def test_fixed_version_reaches_the_remediation_slot(self):
        report = self._trivy_report([OLD_SHAPE_TRIVY_FINDING])
        remediation = report.split("<strong>Remediation:</strong>")[1][:200]
        self.assertIn("2.2.4", remediation)
        self.assertIn("django", remediation)

    def test_explicit_remediation_still_wins_over_fixed_version(self):
        finding = dict(OLD_SHAPE_TRIVY_FINDING, Remediation="Rebuild the base image")
        report = self._trivy_report([finding])
        remediation = report.split("<strong>Remediation:</strong>")[1][:200]
        self.assertIn("Rebuild the base image", remediation)

    def test_primary_url_and_references_reach_the_reference_slot(self):
        report = self._trivy_report([OLD_SHAPE_TRIVY_FINDING])
        self.assertIn("<strong>References:</strong>", report)
        references = report.split("<strong>References:</strong>")[1][:600]
        self.assertIn("https://avd.aquasec.com/nvd/cve-2019-14234", references)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2019-14234", references)

    def test_a_finding_without_references_has_no_empty_reference_slot(self):
        report = self._trivy_report([{"VulnerabilityID": "CVE-X", "Severity": "LOW", "Title": "t"}])
        self.assertNotIn("<strong>References:</strong>", report)

    def test_reference_urls_are_inert_text_not_links(self):
        finding = dict(OLD_SHAPE_TRIVY_FINDING, PrimaryURL="javascript:alert(1)")
        report = self._trivy_report([finding])
        self.assertNotIn("<a ", report.lower())
        self.assertNotIn("href", report.lower())

    def test_hostile_nested_values_stay_escaped(self):
        finding = {
            "VulnerabilityID": "CVE-X", "Severity": "HIGH",
            "Title": '<script>alert(1)</script>',
            "CVSS": {"<img src=x>": {"V3Score": 1.0, "V3Vector": "<iframe>"}},
            "DataSource": {"Name": "<object>"},
            "References": ["<embed>"],
        }
        report = self._trivy_report([finding])
        for forbidden in ("<script", "<img", "<iframe", "<object", "<embed"):
            self.assertNotIn(forbidden, report.lower())

    def test_a_nested_value_from_any_scanner_is_flattened_too(self):
        """The repr problem is general, not trivy-specific: nuclei stores an
        `info` object on every finding."""
        report = self.server._render_report({
            "schema_version": 1, "scanner": "nuclei", "source_type": "url",
            "target_ref": "http://demo", "status": "success", "metadata": {},
            "findings": [{"id": "cve-x", "Title": "RCE", "Severity": "HIGH",
                          "info": {"name": "RCE", "tags": ["cve", "rce"]}}],
        })
        self.assertNotIn("{'", report)
        self.assertNotIn("{&#x27;", report)
        self.assertIn("cve, rce", report)


class OldShapePersistedResultTests(unittest.TestCase):
    """#38 regression: a result file written before the fix still renders."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_old_shape_trivy_result_on_disk_renders_normalized(self):
        result_id = "T" * 32
        document = {
            "schema_version": 1, "scanner": "trivy", "source_type": "filesystem",
            "target_ref": "/app", "status": "success",
            "findings": [OLD_SHAPE_TRIVY_FINDING], "metadata": {"tool_version": "0.66.0"},
        }
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results, reports = root / "results", root / "reports"
            results.mkdir()
            (results / f"{result_id}.json").write_text(json.dumps(document), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="U" * 32),
            ):
                response = asyncio.run(self.server.generate_report(result_id))
            self.assertEqual(f"/reports/{'U' * 32}.html", response)
            report = (reports / f"{'U' * 32}.html").read_text(encoding="utf-8")
        self.assertEqual(1, _articles(report))
        self.assertNotIn("{'", report)
        self.assertNotIn("{&#x27;", report)
        self.assertIn("CVE-2019-14234", report)
        self.assertIn("2.2.4", report.split("<strong>Remediation:</strong>")[1][:200])
        self.assertIn("https://avd.aquasec.com/nvd/cve-2019-14234", report)


if __name__ == "__main__":
    unittest.main()
