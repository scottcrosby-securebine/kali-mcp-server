"""Regressions found by the wave-2 red team on the report renderer.

Each maps to a finding a green 172-test suite did not catch.
"""

import html
import math
import unittest

from server_test_support import load_server


def render(server, findings, scanner="nuclei"):
    return server._render_report({
        "schema_version": 1, "scanner": scanner, "source_type": "host",
        "target_ref": "x", "status": "success", "metadata": {}, "findings": findings,
    })


def combined(server, results):
    return server._render_report({
        "schema_version": 1, "scanner": "combined", "source_type": "host",
        "target_ref": "x", "status": "success", "metadata": {}, "findings": [], "results": results,
    })


def result(server, findings, scanner="nuclei"):
    return {"schema_version": 1, "scanner": scanner, "source_type": "host",
            "target_ref": "x", "status": "success", "metadata": {}, "findings": findings}


class EvidenceCompletenessTests(unittest.TestCase):
    """B-1: rows(evidence_map, None) re-armed the 4000-char value_limit."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_a_long_non_identity_field_is_not_truncated(self):
        # The existing "complete findings" test used `name`, which doubles as the
        # identity and renders through an UNCAPPED path, so it passed either way.
        # Capture bounds evidence at MAX_EVIDENCE_CHARS; the report must not
        # silently halve that.
        marker = "MARKER-BEYOND-FOUR-THOUSAND"
        body = "A" * (self.server.MAX_EVIDENCE_CHARS - len(marker) - 1) + marker
        out = render(self.server, [{"id": "t1", "Severity": "INFO", "Title": "t", "evidence": body}])
        self.assertIn(marker, out)

    def test_the_raw_text_family_keeps_its_whole_persisted_text(self):
        parser = self.server._raw_text_parser("whois", "example.com")
        marker = "REGISTRAR-LINE-AT-THE-END"
        findings = parser("Domain: example.com\n" + "x" * 6000 + "\n" + marker)
        self.assertTrue(findings)
        self.assertIn(marker, render(self.server, findings, scanner="whois"))


class DedupeVolatileKeyTests(unittest.TestCase):
    """B-2: whole-finding identity made dedupe a no-op for volatile fields."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_repeat_scans_collapse_despite_a_per_run_timestamp(self):
        # nuclei -jsonl stamps `timestamp` on every finding, so a fix-and-rescan
        # loop rendered one article per scan instead of one per finding.
        results = [result(self.server, [{"id": "CVE-1", "Severity": "HIGH", "Title": "v",
                                         "timestamp": f"2026-08-27T10:0{i}:00Z"}]) for i in range(6)]
        self.assertEqual(1, combined(self.server, results).count("<article>"))

    def test_distinct_findings_sharing_an_id_are_still_kept(self):
        # The #37 guarantee must survive the B-2 fix.
        findings = [{"id": "013587", "Severity": "LOW", "Title": name}
                    for name in ("csp", "referrer", "permissions", "hsts")]
        findings.append({"id": "007342", "Severity": "LOW", "Title": "xfo"})
        self.assertEqual(5, combined(self.server, [result(self.server, findings, "nikto")]).count("<article>"))

    def test_findings_differing_only_outside_the_volatile_set_are_kept(self):
        findings = [{"id": "013587", "Severity": "LOW", "Title": "missing header", "evidence": url}
                    for url in ("/a", "/b", "/c")]
        self.assertEqual(3, combined(self.server, [result(self.server, findings, "nikto")]).count("<article>"))


class NucleiMatchedAtTests(unittest.TestCase):
    """The volatile-key carve-out must not swallow a DISTINGUISHING field."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_hits_of_one_template_at_different_urls_are_all_kept(self):
        # `matched-at` is nuclei's matched URL and is often the only thing
        # separating two hits of one template. It was briefly in
        # VOLATILE_FINDING_KEYS, which collapsed these three to one and
        # reintroduced #37 for nuclei.
        findings = [{"template-id": "tech-detect", "id": "tech-detect", "Severity": "INFO",
                     "Title": "hit", "matched-at": url}
                    for url in ("http://h/a?q=1", "http://h/b?q=1", "http://h/c?q=1")]
        self.assertEqual(3, combined(self.server, [result(self.server, findings)]).count("<article>"))

    def test_only_keys_with_a_real_producer_are_treated_as_volatile(self):
        # A speculative denylist entry is how the bug above happened.
        self.assertEqual({"timestamp"}, set(self.server.VOLATILE_FINDING_KEYS))


class ReportSizeTests(unittest.TestCase):
    """B2 acceptance: report size for a realistic multi-CVE result drops."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_a_realistic_multi_cve_report_stays_under_its_measured_ceiling(self):
        # Measured against the pre-fix renderer on this exact fixture:
        # 151 CVEs rendered 520,715 bytes before and 390,823 after (-24.9%),
        # because Layer/PkgIdentifier/CVSS/DataSource no longer repr-dump.
        # The ceiling is the measured figure plus headroom, so this catches a
        # regression back toward repr-dumping without pinning exact bytes.
        findings = [{
            "VulnerabilityID": f"CVE-2024-{1000 + i}", "Title": f"Vulnerability {i}",
            "Severity": "HIGH", "PkgName": f"pkg{i}", "InstalledVersion": "1.0.0",
            "FixedVersion": "1.0.1", "Description": "D" * 1100,
            "PrimaryURL": f"https://avd.aquasec.com/nvd/cve-2024-{1000 + i}",
            "References": [f"https://ref{j}.example/{i}" for j in range(22)],
            "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L"}},
            "DataSource": {"ID": "ghsa", "Name": "GitHub Security Advisory pip"},
            "Layer": {"DiffID": "sha256:" + "a" * 64},
            "PkgIdentifier": {"PURL": f"pkg:pypi/pkg{i}@1.0.0"},
        } for i in range(151)]
        rendered = render(self.server, findings, scanner="trivy")
        self.assertEqual(151, rendered.count("<article>"))
        self.assertLess(len(rendered), 430_000)


class CvssSelectionTests(unittest.TestCase):
    """N-1, N-2, N-3."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def cell(self, cvss):
        out = html.unescape(render(self.server, [{"VulnerabilityID": "C", "Title": "t",
                                                  "Severity": "HIGH", "CVSS": cvss}], "trivy"))
        row = [part for part in out.split("<tr>") if "CVSS" in part][0]
        return row.split("<td>")[1].split("</td>")[0]

    def test_v3_is_preferred_over_a_numerically_higher_v2(self):
        # NVD rates Shellshock V2 10.0 / V3 9.8. Taking the larger made the
        # report contradict what trivy itself prints.
        self.assertEqual("9.8 (V3VEC, source: nvd)",
                         self.cell({"nvd": {"V2Score": 10.0, "V2Vector": "V2VEC",
                                            "V3Score": 9.8, "V3Vector": "V3VEC"}}))

    def test_v2_is_still_used_when_no_v3_exists(self):
        self.assertEqual("7.5 (V2VEC, source: nvd)",
                         self.cell({"nvd": {"V2Score": 7.5, "V2Vector": "V2VEC"}}))

    def test_a_nan_score_never_displaces_a_real_one(self):
        self.assertEqual("9.8 (VB, source: b)",
                         self.cell({"a": {"V3Score": float("nan"), "V3Vector": "VA"},
                                    "b": {"V3Score": 9.8, "V3Vector": "VB"}}))

    def test_an_unreadable_cvss_falls_back_instead_of_vanishing(self):
        # Deleting the row outright re-introduced the defect #38 fixed.
        for value in ("9.8", {"nvd": {"V3Score": "9.8"}}, {"nvd": [{"V3Score": 9.8}]}):
            with self.subTest(value=value):
                self.assertNotEqual("", self.cell(value))

    def test_the_highest_score_still_wins_across_feeds(self):
        self.assertEqual("9.8 (VB, source: b)",
                         self.cell({"a": {"V3Score": 5.0, "V3Vector": "VA"},
                                    "b": {"V3Score": 9.8, "V3Vector": "VB"}}))


class ProvenanceAndFlattenTests(unittest.TestCase):
    """N-4, N-5, N-6."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_the_advisory_source_survives_as_provenance(self):
        # DataSource varies per finding (debian for OS packages, ghsa for pip)
        # and nothing else in the report carries the advisory feed.
        out = html.unescape(render(self.server, [{"VulnerabilityID": "C", "Title": "t", "Severity": "HIGH",
                                                  "DataSource": {"ID": "ghsa", "Name": "GHSA pip"}}], "trivy"))
        self.assertIn("ghsa", out)
        self.assertNotIn("{'", out)

    def test_a_width_cut_says_so(self):
        out = html.unescape(render(self.server, [{"id": "a", "Severity": "INFO", "Title": "t",
                                                  "extracted": [f"i{n}" for n in range(25)]}]))
        self.assertIn("(+5 more)", out)

    def test_a_dict_remediation_is_flattened_not_repred(self):
        out = html.unescape(render(self.server, [{"VulnerabilityID": "C", "Title": "t", "Severity": "HIGH",
                                                  "Remediation": {"advice": "patch now"}}], "trivy"))
        self.assertIn("patch now", out)
        self.assertNotIn("{'", out)

    def test_markup_in_promoted_values_stays_escaped(self):
        out = render(self.server, [{"VulnerabilityID": "<script>alert(1)</script>", "Title": "t",
                                    "Severity": "HIGH", "DataSource": {"ID": "<img onerror=x>"},
                                    "Remediation": {"a": "<svg onload=y>"}}], "trivy")
        for tag in ("<script>", "<img onerror", "<svg onload"):
            self.assertNotIn(tag, out)


if __name__ == "__main__":
    unittest.main()
