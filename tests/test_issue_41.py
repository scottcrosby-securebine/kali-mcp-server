"""Row 22 / #41: the combined report is a fix-first, package-grouped remediation
queue, not a flat severity list.

Structure/behaviour tests run through the combined `_render_report` path, which
exists on the base revision and renders the OLD flat layout there -- so they
carry the mutation signal by failing cleanly against base. Helper unit tests are
guarded to skip where the new helpers are absent.

Spec: docs/specs/2026-08-28-report-ia-41.md (approved).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


def _result(findings, scanner="nuclei", target="x"):
    return {"schema_version": 1, "scanner": scanner, "target_ref": target,
            "status": "success", "metadata": {}, "findings": findings}


def _combined(server, results):
    return server._render_report({
        "schema_version": 1, "scanner": "combined", "status": "success",
        "metadata": {}, "findings": [], "results": results})


class TheReportIsAFixFirstQueue(unittest.TestCase):
    """Through the combined path; fails cleanly on the old flat layout."""

    def setUp(self):
        self.server, _ = load_server()

    def test_the_new_sections_and_honest_ordering_label_are_present(self):
        report = _combined(self.server, [_result([{"VulnerabilityID": "CVE-2021-44228",
                                                   "Severity": "HIGH", "Title": "x"}])])
        for heading in ("Fix-first queue", "Package matrix", "CVE explorer",
                        "Web hardening", "Evidence appendix", "Methodology"):
            self.assertIn(heading, report)
        # Ordering is labelled by what was collected, never called "risk".
        self.assertIn("Prioritized by available signals", report)

    def test_same_package_cves_collapse_to_one_upgrade_work_unit(self):
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-2000-0001", "Severity": "HIGH", "PkgName": "openssl",
             "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "a"},
            {"VulnerabilityID": "CVE-2000-0002", "Severity": "CRITICAL", "PkgName": "openssl",
             "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "b"},
        ], scanner="trivy", target="img")])
        # One upgrade unit for two CVEs, not two rows.
        self.assertEqual(1, report.count("<article>"))
        self.assertIn("clears 2 CVE(s)", report)
        self.assertIn("openssl", report)

    def test_distinct_packages_are_distinct_work_units(self):
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-2000-0001", "Severity": "HIGH", "PkgName": "openssl",
             "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "a"},
            {"VulnerabilityID": "CVE-2000-0002", "Severity": "HIGH", "PkgName": "zlib",
             "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "b"},
        ], scanner="trivy", target="img")])
        self.assertEqual(2, report.count("<article>"))

    def test_a_fixable_finding_outranks_one_with_no_fix(self):
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-2000-0001", "Severity": "LOW", "Title": "nofix"},
            {"VulnerabilityID": "CVE-2000-0002", "Severity": "LOW", "Title": "hasfix",
             "remediation": "apply the patch"},
        ])])
        self.assertLess(report.index("CVE-2000-0002"), report.index("CVE-2000-0001"))

    def test_nikto_and_tls_are_a_separate_hardening_section_not_the_cve_queue(self):
        report = _combined(self.server, [
            _result([{"id": "013587", "Severity": "MEDIUM", "Title": "header missing"}], scanner="nikto"),
            _result([{"id": "tls-proto-sslv3", "Severity": "HIGH", "Title": "Weak protocol"}], scanner="sslscan"),
        ])
        # assertIn first so the base revision (no such heading) FAILS, not ERRORS.
        self.assertIn("Web hardening", report)
        head = report.index("Web hardening")
        self.assertLess(head, report.index("header missing"))
        self.assertLess(head, report.index("Weak protocol"))

    def test_informational_enumerations_land_in_the_appendix(self):
        report = _combined(self.server, [_result(
            [{"id": "dns-SOA-1", "Severity": "INFO", "Title": "SOA record"}], scanner="nmap", target="10.0.0.1")])
        self.assertIn("Evidence appendix", report)
        self.assertLess(report.index("Evidence appendix"), report.index("SOA record"))


class ClassificationHelper(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_classify_finding"):
            self.skipTest("classifier absent on this revision")

    def test_each_lane(self):
        c = self.server._classify_finding
        self.assertEqual("package", c("trivy", {"PkgName": "x", "FixedVersion": "1.1", "VulnerabilityID": "CVE-2000-0001"}))
        self.assertEqual("cve", c("trivy", {"VulnerabilityID": "CVE-2000-0001"}))  # CVE, no fix -> cve unit
        self.assertEqual("cve", c("nuclei", {"id": "CVE-2021-44228"}))
        self.assertEqual("hardening", c("nikto", {"id": "013587", "Severity": "INFO"}))
        self.assertEqual("hardening", c("sslscan", {"id": "tls-proto-sslv3", "Severity": "HIGH"}))
        self.assertEqual("enumeration", c("whatweb", {"id": "tech", "Severity": "INFO"}))


class OrderingSignals(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_finding_signals"):
            self.skipTest("signal reader absent on this revision")

    def test_kev_and_epss_are_read_back_from_the_enriched_slots(self):
        kev, epss, cvss, rank = self.server._finding_signals({
            "Severity": "HIGH", "KEV": "Actively exploited — fix now (KEV added 2021-12-10)",
            "EPSS": "0.975 probability (0.99 percentile)",
            "CVSS": {"nvd": {"V3Score": 9.8}}})
        self.assertTrue(kev)
        self.assertAlmostEqual(0.975, epss)
        self.assertAlmostEqual(9.8, cvss)
        self.assertGreater(rank, 0)

    def test_an_unenriched_finding_scores_no_signal(self):
        kev, epss, cvss, rank = self.server._finding_signals({
            "Severity": "LOW", "KEV": "Unknown — not enriched", "EPSS": "Not enriched"})
        self.assertFalse(kev)
        self.assertEqual(0.0, epss)
        self.assertEqual(0.0, cvss)


if __name__ == "__main__":
    unittest.main()
