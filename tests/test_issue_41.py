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


class ConfidenceSeamP2(unittest.TestCase):
    """Wave-2 P2: per-finding detection-confidence tiers, inverted allowlist model.
    OBSERVED IS AN ALLOWLIST, never a default (doctrine valve-4 ruling): only a vetted
    direct-target scanner renders Observed; everything else is inferred (CVE / package
    scanner) or heuristic (the default). An unvetted scanner can never overclaim."""

    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_confidence"):
            self.skipTest("_confidence absent on this revision")

    def c(self, finding, scanner=""):
        return self.server._confidence(finding, scanner)[0]

    # --- inference tier ---
    def test_cve_bearing_is_inferred(self):
        self.assertEqual("inferred", self.c({"VulnerabilityID": "CVE-2021-44228"}))

    def test_cve_beats_a_non_observed_scanner(self):
        # A CVE finding from a non-unwitnessed scanner is inferred regardless of id.
        self.assertEqual("inferred",
                         self.c({"id": "x", "VulnerabilityID": "CVE-2021-44228"}, "ffuf"))

    def test_trivy_ghsa_and_avd_are_inferred_not_observed(self):
        # red-team B-OVERCLAIM: trivy findings whose advisory id is GHSA/AVD (not a
        # CVE) are version matches, NOT live observations -> inferred, never observed.
        for vid in ("GHSA-jf85-cpcp-j695", "AVD-AWS-0088"):
            f = {"VulnerabilityID": vid, "Severity": "CRITICAL", "PkgName": "lodash"}
            self.assertEqual("inferred", self.c(f, "trivy"), vid)

    def test_trivy_cve_is_inferred(self):
        self.assertEqual("inferred", self.c({"VulnerabilityID": "CVE-2021-23337"}, "trivy"))

    # --- observed allowlist ---
    def test_observed_requires_an_allowlisted_scanner(self):
        # A TLS finding is Observed ONLY when the caller passes an allowlisted scanner;
        # scanner-blind it defaults to heuristic (the inversion: no overclaim on
        # unknown provenance).
        f = {"id": "tls-proto-tls1_0", "Severity": "MEDIUM"}
        self.assertEqual("observed", self.c(f, "testssl"))
        self.assertEqual("observed", self.c(f, "sslscan"))
        self.assertEqual("heuristic", self.c(f))          # no scanner -> default

    def test_nuclei_non_cve_and_dns_and_direct_target_are_observed(self):
        for scanner in ("nuclei", "dns_recon", "nbtscan", "smbclient"):
            self.assertEqual("observed", self.c({"id": "x", "Severity": "INFO"}, scanner), scanner)

    def test_nmap_open_port_is_observed_nse_is_heuristic(self):
        port = {"id": "port-443-tcp", "state": "open", "service": "https", "Severity": "INFO"}
        nse = {"id": "smb-vuln-ms17-010", "Severity": "HIGH", "evidence": "VULNERABLE"}
        self.assertEqual("observed", self.c(port, "nmap"))
        self.assertEqual("heuristic", self.c(nse, "nmap"))

    # --- heuristic default ---
    def test_unvetted_scanner_defaults_to_heuristic_never_observed(self):
        # The core inversion invariant: a scanner NOT on any allowlist can never
        # render Observed. A mutation making the final return "observed" is caught.
        for scanner in ("whatweb", "ffuf", "gobuster", "wafw00f", "subfinder",
                        "amass", "fierce", "syft", "olevba", "whois", "some-new-scanner", ""):
            self.assertEqual("heuristic", self.c({"id": "x", "Severity": "INFO"}, scanner), scanner)

    def test_whois_is_heuristic_not_observed(self):
        # red-team F1: whois queries a registry on TCP 43 and never touches the
        # target host, so it is not a direct-target observation -> heuristic.
        self.assertEqual("heuristic", self.c({"id": "whois-registrar", "Severity": "INFO"}, "whois"))

    def test_non_dict_finding_counts_toward_not_observed(self):
        # red-team F2: a structureless finding renders Heuristic and must be counted,
        # else the "not directly observed" disclosure over-reports observation.
        report = _combined(self.server, [{
            "schema_version": 1, "scanner": "customtool", "target_ref": "x",
            "status": "success", "metadata": {},
            "findings": ["a bare string finding",
                         {"id": "y", "Severity": "INFO", "Title": "dict finding"}]}])
        # both are heuristic (bare string + unvetted-scanner dict) -> 2 of 2
        self.assertIn("2 of 2", report)

    def test_nikto_and_metasploit_are_heuristic(self):
        f = {"id": "3268", "Title": "dir indexing", "Severity": "MEDIUM"}
        self.assertEqual("heuristic", self.c(f, "nikto"))
        self.assertEqual("heuristic", self.c({"id": "m"}, "metasploit_search"))
        self.assertEqual("heuristic", self.c({"id": "m"}, "metasploit_info"))

    def test_metasploit_cve_in_query_stays_heuristic(self):
        # red-team B1: a CVE named in a metasploit query lands in the id; unwitnessed
        # runs before the CVE branch, so it stays heuristic (not a host attribution).
        f = {"id": "metasploit_search-CVE-2021-44228", "Severity": "INFO"}
        self.assertEqual("heuristic", self.c(f, "metasploit_search"))

    def test_bare_string_finding_is_heuristic(self):
        # A structureless finding has no provenance -> heuristic (conservative), even
        # scanner-blind. Not Observed.
        self.assertEqual("heuristic", self.c("bare string"))

    def test_label_matches_key(self):
        self.assertEqual(("inferred", "Inferred"),
                         self.server._confidence({"VulnerabilityID": "CVE-2021-44228"}))

    # --- render integration ---
    def test_combined_report_renders_all_three_chips(self):
        report = _combined(self.server, [
            _result([{"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "Title": "log4shell"}], scanner="trivy"),
            _result([{"id": "tls-proto-tls1_0", "Severity": "MEDIUM", "Title": "weak tls"}], scanner="testssl"),
            _result([{"id": "3268", "Severity": "MEDIUM", "Title": "dir indexing"}], scanner="nikto")])
        self.assertIn("conf-inferred", report)   # trivy CVE
        self.assertIn("conf-observed", report)   # testssl
        self.assertIn("conf-heuristic", report)  # nikto

    def test_scope_box_not_observed_count_matches_scanner_aware_findings(self):
        # PA5, inverted: the count uses the SAME scanner-aware verdict the render does.
        results = [
            _result([{"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "Title": "a"}], scanner="trivy"),   # inferred
            _result([{"id": "3268", "Severity": "MEDIUM", "Title": "b"}], scanner="nikto"),                            # heuristic
            _result([{"id": "tls-proto-tls1_0", "Severity": "MEDIUM", "Title": "c"}], scanner="testssl")]              # observed
        report = _combined(self.server, results)
        # 2 not-observed (trivy inferred + nikto heuristic) of 3
        self.assertIn("Not directly observed", report)
        self.assertIn("2 of 3", report)

    def test_trivy_ghsa_critical_is_counted_not_observed_in_render(self):
        # red-team B-OVERCLAIM end to end: a GHSA CRITICAL must NOT render Observed
        # nor be excluded from the honesty count.
        import re
        report = _combined(self.server, [_result(
            [{"VulnerabilityID": "GHSA-jf85-cpcp-j695", "Severity": "CRITICAL",
              "PkgName": "lodash", "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
              "Title": "proto pollution"}], scanner="trivy")])
        art = [a for a in re.findall(r"<article>.*?</article>", report, re.S) if "lodash" in a][0]
        self.assertIn("conf-inferred", art)
        self.assertNotIn("conf-observed", art)
        self.assertIn("1 of 1", report)

    def test_metasploit_cve_finding_renders_heuristic_chip_not_inferred(self):
        # red-team B1 (chip path): the "_conf" stamp carries the scanner-aware
        # heuristic verdict through render_findings' re-enrich; the chip is not the
        # scanner-blind fallback.
        import re
        report = _combined(self.server, [_result(
            [{"id": "metasploit_search-CVE-2021-44228", "Title": "exploit modules",
              "Severity": "INFO"}], scanner="metasploit_search")])
        art = [a for a in re.findall(r"<article>.*?</article>", report, re.S)
               if "metasploit_search-CVE-2021-44228" in a][0]
        self.assertIn("conf-heuristic", art)
        self.assertNotIn("conf-inferred", art)
        self.assertNotIn("_conf", art)           # private stamp must not leak



class TlsGradeHeroP3a(unittest.TestCase):
    """Wave-2 P3a: SSL-Labs-style TLS letter-grade hero, computed downward from
    observed weaknesses and never overclaiming a top grade on a scanner's silence."""

    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_tls_grade"):
            self.skipTest("_tls_grade absent on this revision")

    def g(self, findings, scanner="testssl"):
        return self.server._tls_grade(findings, scanner)[0]

    def test_catastrophic_break_is_F(self):
        for f in ({"id": "heartbleed", "cve": "CVE-2014-0160", "Severity": "CRITICAL"},
                  {"id": "ROBOT", "Severity": "HIGH"},
                  {"id": "tls-proto-sslv2", "Severity": "HIGH", "Title": "Weak protocol enabled: SSLv2"}):
            self.assertEqual("F", self.g([f]), f)

    def test_sslv3_poodle_is_C(self):
        self.assertEqual("C", self.g([{"id": "tls-proto-sslv3", "Severity": "HIGH",
                                       "Title": "Weak protocol enabled: SSLv3"}]))

    def test_weak_cipher_is_B(self):
        self.assertEqual("B", self.g([{"id": "tls-cipher-RC4-MD5", "Severity": "HIGH",
                                       "Title": "Accepted cipher: RC4-MD5"}]))

    def test_legacy_protocol_is_B(self):
        self.assertEqual("B", self.g([{"id": "tls-proto-tlsv1.0", "Severity": "MEDIUM",
                                       "Title": "Weak protocol enabled: TLSv1.0"}]))

    def test_sslscan_clean_is_A(self):
        # sslscan/sslyze emit weak protocols/ciphers at ANY severity, so a clean scan
        # honestly grades A (no protocol/cipher weakness). testssl cannot (see below).
        grade, drivers, coverage = self.server._tls_grade([], "sslscan")
        self.assertEqual("A", grade)
        self.assertEqual([], drivers)
        self.assertIn("not an exhaustive SSL Labs assessment", coverage)

    def test_testssl_clean_is_B_coverage_capped(self):
        # red-team R6-B1: testssl runs --severity HIGH, so its JSON never carries the
        # LOW/MEDIUM tier (legacy TLS 1.0/1.1, SWEET32). It cannot certify A; a clean
        # testssl scan caps at B with a coverage-limit driver, never a false green A.
        grade, drivers, coverage = self.server._tls_grade([], "testssl")
        self.assertEqual("B", grade)
        self.assertIn("--severity HIGH", drivers[0])
        self.assertIn("does NOT surface LOW/MEDIUM", coverage)

    def test_testssl_negative_rows_do_not_cap_a_clean_server(self):
        # red-team B1: testssl emits "not offered"/"not vulnerable" rows (severity
        # OK->INFO) whose ids contain sslv2/heartbleed/etc. Only a COLOURED-severity
        # weakness may cap; a clean server must grade A, not F.
        clean = [
            {"id": "SSLv2", "Severity": "INFO", "Title": "SSLv2: not offered (OK)"},
            {"id": "heartbleed", "Severity": "INFO", "Title": "Heartbleed: not vulnerable (OK)"},
            {"id": "POODLE_SSL", "Severity": "INFO", "Title": "POODLE, SSL: not vulnerable (OK)"}]
        # negative rows must NOT cap to F; the residual testssl grade is the B coverage
        # cap (--severity HIGH), never F from a matched "not vulnerable" row.
        grade, drivers, _ = self.server._tls_grade(clean, "testssl")
        self.assertNotEqual("F", grade)
        self.assertEqual("B", grade)
        self.assertIn("--severity HIGH", drivers[0])

    def test_sslyze_legacy_tls_strong_cipher_is_B_not_A(self):
        # red-team B2: sslyze emits a tls-cipher-* finding titled "TLSv1.0 accepted
        # cipher" at MEDIUM for a strong cipher over a legacy protocol. The legacy
        # cap must fire off the TITLE, not a tls-proto id sslyze never emits.
        f = {"id": "tls-cipher-ECDHE-RSA-AES128-SHA", "Severity": "MEDIUM",
             "Title": "TLSv1.0 accepted cipher: ECDHE-RSA-AES128-SHA"}
        self.assertEqual("B", self.g([f], "sslyze"))

    def test_testssl_named_ids_are_graded(self):
        # red-team R2-F1 + Standards R2-S1: testssl uses its OWN id scheme (TLS1,
        # TLS1_1, RC4, FREAK...) not the tls-proto/tls-cipher prefixes. The caps must
        # read them, and must NOT false-cap the fine TLS1_2/TLS1_3 ids.
        self.assertEqual("B", self.g([{"id": "TLS1", "Severity": "LOW", "Title": "TLS1"}], "testssl"))
        self.assertEqual("B", self.g([{"id": "TLS1_1", "Severity": "LOW", "Title": "TLS1_1"}], "testssl"))
        self.assertEqual("B", self.g([{"id": "RC4", "Severity": "HIGH", "Title": "RC4"}], "testssl"))
        self.assertEqual("F", self.g([{"id": "FREAK", "Severity": "HIGH", "Title": "FREAK"}], "testssl"))
        # fine protocols must not hit the LEGACY weakness cap (TLS1 is a substring of
        # TLS1_2 — boundary guard). Under testssl the clean grade is B via the coverage
        # cap, so prove no false weakness-cap by the DRIVER, not the letter.
        _, drivers12, _ = self.server._tls_grade([{"id": "TLS1_2", "Severity": "LOW", "Title": "TLS1_2"}], "testssl")
        self.assertNotIn("legacy TLS 1.0/1.1 enabled", drivers12)   # not a weakness cap
        self.assertIn("--severity HIGH", drivers12[0])              # the coverage cap
        # TLS1_2 exact-id must not be in the legacy weakness set
        self.assertNotIn("tls1_2", self.server._TLS_B_LEGACY_IDS)
        self.assertIn("tls1", self.server._TLS_B_LEGACY_IDS)

    def test_critical_backstop_and_ccs_winshock_are_F(self):
        # red-team R3-F1: CCS/Winshock are CRITICAL testssl vulns that used to grade A.
        # Named tokens catch them, and a severity backstop catches any UNRECOGNISED
        # critical weakness so a future testssl vuln can never grade A.
        self.assertEqual("F", self.g([{"id": "CCS", "cve": "CVE-2014-0224", "Severity": "CRITICAL"}], "testssl"))
        self.assertEqual("F", self.g([{"id": "winshock", "cve": "CVE-2014-6321", "Severity": "CRITICAL"}], "testssl"))
        self.assertEqual("F", self.g([{"id": "SOME_FUTURE_VULN", "Severity": "CRITICAL",
                                       "Title": "unknown critical break"}], "testssl"))

    def test_testssl_cipherlist_weak_lists_cap(self):
        # Standards R3-S1: testssl reports accepted weak-cipher LISTS as cipherlist_*
        # ids. A coloured one is a bad list -> at least B; a CRITICAL NULL list -> F.
        self.assertEqual("F", self.g([{"id": "cipherlist_NULL", "Severity": "CRITICAL",
                                       "Title": "NULL ciphers offered"}], "testssl"))
        self.assertEqual("B", self.g([{"id": "cipherlist_LOW", "Severity": "MEDIUM"}], "testssl"))
        self.assertEqual("B", self.g([{"id": "cipherlist_EXPORT", "Severity": "HIGH"}], "testssl"))
        # a strong-cipher list is rated OK->INFO and gated out -> no WEAKNESS cap;
        # the residual testssl grade is the B coverage cap, not a weak-cipher B.
        grade, drivers, _ = self.server._tls_grade([{"id": "cipherlist_strongFS", "Severity": "INFO"}], "testssl")
        self.assertEqual("B", grade)
        self.assertIn("--severity HIGH", drivers[0])

    def test_renegotiation_crime_and_compression_families_cap(self):
        # red-team R4-F1 (Scott ruling: extend the allowlist): HIGH testssl weaknesses
        # in the renegotiation/compression families used to grade A. Now capped.
        self.assertEqual("F", self.g([{"id": "secure_renego", "cve": "CVE-2009-3555",
                                       "Severity": "HIGH", "Title": "Insecure renegotiation"}], "testssl"))
        self.assertEqual("C", self.g([{"id": "CRIME_TLS", "Severity": "HIGH", "Title": "CRIME, TLS"}], "testssl"))
        for vid in ("BREACH", "BEAST", "LUCKY13"):
            self.assertEqual("B", self.g([{"id": vid, "Severity": "MEDIUM", "Title": vid}], "testssl"), vid)

    def test_ccs_token_does_not_false_match_success(self):
        # Standards R4-S1: the bare "ccs" token was dropped (it substring-collides with
        # "success"); a coloured finding whose text contains "success" must NOT grade F.
        f = {"id": "some_check", "Severity": "MEDIUM", "Title": "handshake completed successfully"}
        self.assertNotEqual("F", self.g([f], "testssl"))
        # CCS is still F via its CVE / the CRITICAL backstop
        self.assertEqual("F", self.g([{"id": "CCS", "cve": "CVE-2014-0224", "Severity": "HIGH"}], "testssl"))

    def test_worst_cap_wins(self):
        # A catastrophic break plus a weak cipher grades F, not B.
        findings = [{"id": "tls-cipher-RC4-MD5", "Severity": "HIGH"},
                    {"id": "heartbleed", "cve": "CVE-2014-0160", "Severity": "CRITICAL"}]
        self.assertEqual("F", self.g(findings))

    def test_sparse_scanner_coverage_note_is_narrower(self):
        # sslscan tests protocols+ciphers only; the coverage note must say so and
        # NOT claim named-vuln coverage it did not perform.
        _, _, cov = self.server._tls_grade([], "sslscan")
        self.assertIn("weak protocols and accepted ciphers", cov)
        self.assertNotIn("named vulnerabilities", cov)

    def test_render_shows_grade_hero_for_tls_report(self):
        report = self.server._render_report({
            "schema_version": 1, "scanner": "testssl", "status": "success",
            "source_type": "url", "target_ref": "example.com", "metadata": {},
            "findings": [{"id": "tls-proto-sslv3", "Severity": "HIGH",
                          "Title": "Weak protocol enabled: SSLv3"}]})
        self.assertIn("tls-hero", report)
        self.assertIn("TLS grade", report)
        self.assertIn(">C<", report)                       # the graded letter
        self.assertIn("ceiling on posture", report)        # honesty qualifier
        # R8: the coverage note's QA2 tail must SURVIVE render (a 400-char escape() cap
        # used to sever it). Assert the last clause is present and not truncated.
        self.assertIn("verified A+", report)
        self.assertNotIn("[truncated]", report)
        self.assertNotIn("<script", report)

    def test_non_tls_report_has_no_grade_hero(self):
        report = self.server._render_report({
            "schema_version": 1, "scanner": "nikto", "status": "success",
            "source_type": "url", "target_ref": "example.com", "metadata": {},
            "findings": [{"id": "3268", "Severity": "MEDIUM", "Title": "dir indexing"}]})
        self.assertNotIn("tls-hero", report)


if __name__ == "__main__":
    unittest.main()
