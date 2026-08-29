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
        for heading in ("Risk model", "Fix-first queue", "Package matrix", "CVE explorer",
                        "Web hardening", "Evidence appendix", "Methodology"):
            self.assertIn(heading, report)
        # #86: ordering is now the auditable contextual-risk score. The honesty is
        # preserved differently -- the model, its weights, and the fact that
        # unknown inputs default conservative + flagged are all rendered.
        self.assertIn("contextual risk", report)
        self.assertIn("0.52", report)     # #86 phase-1 exploit weight is shown
        self.assertIn("Phase 2", report)  # reachability/asset_value deferred, stated honestly

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


class ContextualRiskSeam(unittest.TestCase):
    """#86 wave-1 Seams: pin the two teaching cases and the exposure join so a score
    regression is caught by mutation-check, not just the render-structure tests."""

    def setUp(self):
        self.server, _ = load_server()
        for name in ("_contextual_risk", "_exposure_for", "_risk_band_word", "_host_of"):
            if not hasattr(self.server, name):
                self.skipTest(f"{name} absent on this revision")

    def test_exploited_internet_facing_7_5_scores_89_high(self):
        # KEV -> exploit 1.0; nmap open host -> exposure 1.0; HIGH ceiling 89.
        f = {"VulnerabilityID": "CVE-2021-44228", "Severity": "HIGH",
             "KEV": "Actively exploited — fix now (KEV added 2021-12-10)",
             "EPSS": "0.975 probability (0.99 percentile)", "CVSS": {"nvd": {"V3Score": 7.5}}}
        r = self.server._contextual_risk(f, 1.0)
        self.assertEqual(89, r["score"])
        self.assertEqual("High", self.server._risk_band_word(r["score"]))

    def test_unexposed_internal_9_8_scores_50_medium(self):
        # unenriched -> exploit 0.5; unexposed -> exposure 0.5; CRITICAL ceiling 100.
        f = {"VulnerabilityID": "CVE-2022-0001", "Severity": "CRITICAL",
             "KEV": "Unknown — not enriched", "EPSS": "Not enriched", "CVSS": {"nvd": {"V3Score": 9.8}}}
        r = self.server._contextual_risk(f, 0.5)
        self.assertEqual(50, r["score"])
        self.assertEqual("Medium", self.server._risk_band_word(r["score"]))
        self.assertIn("exploit-unknown", r["assumed"])

    def test_weights_are_pinned_by_an_asymmetric_case(self):
        # #86 N5: the teaching cases use exploit==exposure, so a 0.52<->0.48 swap
        # passes them. This asymmetric case (exploit 1.0, exposure 0.5) pins which
        # weight is which: 100*(0.52*1.0 + 0.48*0.5) = 76; a swap yields 74.
        f = {"Severity": "CRITICAL", "KEV": "Actively exploited — now"}
        self.assertEqual(76, self.server._contextual_risk(f, 0.5)["score"])

    def test_teaching_invariant_facing_7_5_outranks_internal_9_8(self):
        facing = {"Severity": "HIGH", "KEV": "Actively exploited — now", "CVSS": {"nvd": {"V3Score": 7.5}}}
        internal = {"Severity": "CRITICAL", "KEV": "Unknown — not enriched",
                    "EPSS": "Not enriched", "CVSS": {"nvd": {"V3Score": 9.8}}}
        self.assertGreater(self.server._contextual_risk(facing, 1.0)["score"],
                           self.server._contextual_risk(internal, 0.5)["score"])

    def test_low_severity_never_renders_above_low(self):
        # #86 B3 regression: the old 0.42 constant floor made LOW render Medium.
        f = {"Severity": "LOW", "KEV": "Unknown — not enriched", "EPSS": "Not enriched"}
        r = self.server._contextual_risk(f, 0.5)
        self.assertLessEqual(r["score"], 39)
        self.assertIn(self.server._risk_band_word(r["score"]), ("Low", "Info"))

    def test_exposure_join_is_per_host(self):
        # #86 B1 regression: exposure must fire only for a finding on an open host.
        self.assertEqual(1.0, self.server._exposure_for("10.0.10.5", {"10.0.10.5"})[0])
        self.assertEqual(0.5, self.server._exposure_for("img:internal", {"10.0.10.5"})[0])
        self.assertEqual(0.5, self.server._exposure_for("", set())[0])

    def test_host_of_strips_scheme_port_userinfo(self):
        self.assertEqual("10.0.10.5", self.server._host_of("https://10.0.10.5:443/x"))
        self.assertEqual("10.0.10.5", self.server._host_of("10.0.10.5:22"))
        self.assertEqual("h", self.server._host_of("https://user:pass@h/p"))


class ExecLayerP1(unittest.TestCase):
    """Wave-2 P1: the bold exec layer (scope box + posture hero + traffic-lights)."""

    def setUp(self):
        self.server, _ = load_server()
        for name in ("_risk_bullet", "_posture"):
            if not hasattr(self.server, name):
                self.skipTest(f"{name} absent on this revision")

    def test_risk_bullet_is_scriptless_svg_with_score_and_label(self):
        svg = self.server._risk_bullet(84, "High")
        self.assertIn("<svg", svg)
        self.assertNotIn("<script", svg)
        self.assertIn("aria-label", svg)
        self.assertIn("84", svg)          # the datum survives as text (no tooltip)

    def test_posture_is_the_max_unit_risk(self):
        # work_units are (sort_key_tuple, ...) with risk at key[0].
        units = [((40, 1, False, 0, 0, 0, 1),), ((88, 1, False, 0, 0, 0, 1),)]
        self.assertEqual((88, "High"), self.server._posture(units))
        self.assertEqual((0, "Info"), self.server._posture([]))

    def test_exec_layer_renders_scope_box_hero_and_traffic_lights(self):
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "Title": "x"}])])
        # scope box: honesty + handling
        self.assertIn("detection-only", report)
        self.assertIn("TLP", report)
        # posture hero
        self.assertIn("hero", report)
        self.assertIn("indicative", report)
        # traffic-light KRI row
        self.assertIn("tl-row", report)
        self.assertIn("actively exploited", report)
        # A4: one value per fact — the hero posture equals the top fix-queue chip,
        # and the traffic-light critical count equals the severity tally.
        import re
        hero = re.search(r'hn-score band-\w+">(\d+)', report)
        chip = re.search(r'Risk (\d+) \u00b7', report)
        self.assertTrue(hero and chip, "hero score and a risk chip must both render")
        self.assertEqual(hero.group(1), chip.group(1))
        self.assertIn("1 critical", report)

    def test_no_scored_units_states_it_rather_than_zero(self):
        report = _combined(self.server, [_result(
            [{"id": "info-1", "Severity": "INFO", "Title": "banner"}], scanner="whatweb")])
        self.assertIn("No scored findings", report)


if __name__ == "__main__":
    unittest.main()
