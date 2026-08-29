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


class MacroVerdictHeroP3b(unittest.TestCase):
    """Wave-2 P3b: macro (olevba/msodde) verdict banner, computed downward from what
    STATIC analysis flagged. Never asserts detonation, never 'malicious'/'safe', and
    never tags an ATT&CK technique the scan text did not evidence (P2 overclaim rule)."""

    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_macro_verdict"):
            self.skipTest("_macro_verdict absent on this revision")

    def v(self, findings, scanner="olevba"):
        """(verdict, vclass)"""
        verdict, vclass, *_ = self.server._macro_verdict(findings, scanner)
        return verdict, vclass

    def tags(self, findings, scanner="olevba"):
        return [t[0] for t in self.server._macro_verdict(findings, scanner)[3]]

    def _macro_report(self, scanner, findings):
        return self.server._render_report({
            "schema_version": 1, "scanner": scanner, "status": "success",
            "source_type": "artifact", "target_ref": "sample.docm",
            "metadata": {}, "findings": findings})

    # --- verdict tiers (worst-tier-wins) --------------------------------------
    def test_autoexec_plus_distinct_suspicious_is_high_risk(self):
        # AutoOpen (auto-run hook) COMBINED WITH a distinct Shell behaviour is the
        # weaponised-document pattern -> HIGH RISK.
        verdict, vclass = self.v([
            {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
            {"type": "Suspicious", "keyword": "Shell", "description": "May run an executable"}])
        self.assertEqual("HIGH RISK", verdict)
        self.assertEqual("band-critical", vclass)

    def test_msodde_ddeauto_is_high_risk(self):
        # auto-executing DDE is inherently the classic weaponised pattern.
        verdict, vclass = self.v(
            [{"type": "dde", "field": "DDEAUTO cmd /c calc", "source": "word/document.xml"}],
            "msodde")
        self.assertEqual("HIGH RISK", verdict)
        self.assertEqual("band-critical", vclass)

    def test_autoexec_alone_is_suspicious_not_high_risk(self):
        # a bare auto-run hook with NO other flagged behaviour is SUSPICIOUS, not
        # HIGH RISK -- the combination is what earns the top tier.
        self.assertEqual(("SUSPICIOUS", "band-high"), self.v(
            [{"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"}]))

    def test_suspicious_without_autoexec_is_suspicious(self):
        self.assertEqual(("SUSPICIOUS", "band-high"), self.v(
            [{"type": "Suspicious", "keyword": "Chr", "description": "string obfuscation"}]))

    def test_no_findings_is_no_indicators_never_safe(self):
        verdict, vclass, drivers, tags, coverage = self.server._macro_verdict([], "olevba")
        self.assertEqual("NO INDICATORS", verdict)
        self.assertEqual("band-low", vclass)
        self.assertEqual([], tags)
        # honesty: absence of indicators is NOT proof of safety (it says so in a
        # negation), and the note states the macro was not executed. Never a bare
        # safety claim -- "safe" only ever appears inside "not proof ... is safe".
        low = coverage.lower()
        self.assertIn("not proof", low)
        self.assertIn("not executed", low)
        self.assertNotIn("is safe.", low)   # no standalone safety assertion

    def test_fixture_single_autoopen_typed_suspicious_is_suspicious(self):
        # the olevba-success fixture labels AutoOpen "Suspicious"; the keyword set
        # still recognises it as an auto-run hook, and with nothing else it is
        # SUSPICIOUS (auto-run alone), not HIGH RISK.
        self.assertEqual(("SUSPICIOUS", "band-high"), self.v(
            [{"type": "Suspicious", "keyword": "AutoOpen", "description": "Runs when opened"}]))

    # --- ATT&CK tags (observed-only, no overclaim) ----------------------------
    def test_any_indicator_tags_malicious_file(self):
        self.assertIn("T1204.002", self.tags(
            [{"type": "Suspicious", "keyword": "Chr", "description": "obfuscation"}]))

    def test_powershell_tags_t1059_001_not_command_shell(self):
        # "powershell" contains the substring "shell"; the command-shell tag must NOT
        # fire off that collision -- only PowerShell (T1059.001) is evidenced.
        tags = self.tags([{"type": "Suspicious", "keyword": "powershell",
                           "description": "downloads a payload"}])
        self.assertIn("T1059.001", tags)
        self.assertNotIn("T1059.003", tags)

    def test_msodde_dde_tags_t1559_002(self):
        self.assertIn("T1559.002", self.tags(
            [{"type": "dde", "field": "DDEAUTO powershell -enc AAAA", "source": "x"}], "msodde"))

    def test_bare_suspicious_tags_only_malicious_file(self):
        self.assertEqual(["T1204.002"], self.tags(
            [{"type": "Suspicious", "keyword": "Chr", "description": "string obfuscation"}]))

    def test_autoopen_does_not_tag_persistence(self):
        # "Runs when opened" contains "run"; T1547 persistence must NOT fire on it.
        # AutoOpen is auto-execution (T1204.002), not a Run-key/startup write.
        self.assertNotIn("T1547.001", self.tags(
            [{"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"}]))

    def test_registry_run_key_tags_persistence(self):
        self.assertIn("T1547.001", self.tags(
            [{"type": "Suspicious", "keyword": "RegWrite", "description": "writes an HKCU Run key"}]))

    def test_shell_keyword_tags_command_shell(self):
        # olevba emits the VBA function name "Shell" as a discrete keyword -> command
        # execution (T1059.003), matched keyword-exact.
        self.assertIn("T1059.003", self.tags(
            [{"type": "Suspicious", "keyword": "Shell", "description": "runs a program"}]))

    def test_no_indicators_tags_nothing(self):
        self.assertEqual([], self.tags([]))

    def test_autoexec_plus_encoded_payload_is_high_risk(self):
        # red-team B1: olevba emits obfuscated-payload findings under its OWN type
        # labels (Base64 String / Hex String / Dridex string / VBA obfuscated Strings),
        # none of which are "suspicious"/"ioc". auto-exec + a concealed payload is the
        # weaponised pattern and MUST be HIGH RISK, not SUSPICIOUS.
        for payload_type in ("Base64 String", "Hex String", "Dridex string",
                             "VBA obfuscated Strings"):
            verdict, _ = self.v([
                {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
                {"type": payload_type, "keyword": "TVqQAA", "description": "encoded payload"}])
            self.assertEqual("HIGH RISK", verdict, payload_type)

    def test_two_autoexec_hooks_without_payload_stay_suspicious(self):
        # broadening the indicator set must NOT tip two bare auto-run hooks (no payload)
        # into HIGH RISK -- there is no concerning behaviour beyond the hooks.
        self.assertEqual(("SUSPICIOUS", "band-high"), self.v([
            {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
            {"type": "AutoExec", "keyword": "AutoClose", "description": "Runs when closed"}]))

    def test_registry_read_does_not_tag_persistence(self):
        # red-team N1: a macro that only READS the registry is not autostart persistence.
        # bare "registry"/"hkcu"/"hklm" must not tag T1547.
        for f in ({"type": "Suspicious", "keyword": "RegRead",
                   "description": "May read system registry values"},
                  {"type": "IOC", "keyword": "HKCU\\Software\\Foo",
                   "description": "Reads a value under HKCU"}):
            self.assertNotIn("T1547.001", self.tags([f]), f)

    def test_non_dict_entry_does_not_manufacture_high_risk(self):
        # red-team N2: an unclassifiable non-dict entry keeps the report off NO
        # INDICATORS but must NOT combine with a lone AutoOpen to fabricate HIGH RISK.
        verdict, _ = self.v([
            {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
            "parser artifact string"])
        self.assertEqual("SUSPICIOUS", verdict)

    def test_autoexec_token_in_payload_value_does_not_suppress_high_risk(self):
        # red-team F1 (underclaim): the auto-run test must key off the entry's OWN
        # type/keyword, not a substring of attacker-controlled content. A Base64 payload
        # whose keyword embeds "autoopen" must NOT be misread as an auto-run hook and
        # thereby erase the concealed-payload half -> the doc stays HIGH RISK.
        verdict, _ = self.v([
            {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
            {"type": "Base64 String", "keyword": "ZZautoopenZZ", "description": "encoded payload"}])
        self.assertEqual("HIGH RISK", verdict)

    def test_autoexec_token_in_ioc_value_does_not_fabricate_high_risk(self):
        # red-team F1 (overclaim): an IOC filename containing "workbook_open" is a plain
        # indicator, NOT an auto-run trigger; it must not manufacture the auto-exec half.
        # Two weak indicators with no real auto-run hook -> SUSPICIOUS, not HIGH RISK.
        verdict, _ = self.v([
            {"type": "IOC", "keyword": "c:/logs/workbook_open.log", "description": "File name"},
            {"type": "Suspicious", "keyword": "Environ", "description": "May read environment variables"}])
        self.assertEqual("SUSPICIOUS", verdict)

    def test_attack_tags_do_not_fire_on_ioc_url_substrings(self):
        # red-team F3: a technique/persistence tag must not be derived from a token buried
        # in an attacker-controlled IOC value (a URL/domain), which is not behavioural
        # evidence the macro uses that technique.
        for f in ({"type": "IOC", "keyword": "http://powershell-cdn.example/p", "description": "URL"},
                  {"type": "IOC", "keyword": "http://comspec.example/x", "description": "URL"},
                  {"type": "IOC", "keyword": "http://autostart.example/y", "description": "URL"}):
            tags = self.tags([f])
            self.assertEqual(["T1204.002"], tags, f)

    def test_powershell_in_a_behavioural_description_still_tags(self):
        # the F3 fix must not suppress a REAL behavioural signal: powershell named in a
        # Suspicious entry's keyword/description is genuine execution evidence.
        self.assertIn("T1059.001", self.tags(
            [{"type": "Suspicious", "keyword": "powershell", "description": "invokes powershell"}]))

    def test_autorun_keyword_backstop_covers_real_olevba_triggers(self):
        # red-team NB4: the keyword backstop must not depend solely on olevba stamping
        # type=="AutoExec". A real auto-run trigger (AutoNew/Workbook_Activate/...) whose
        # entry is typed Suspicious must still be recognised as an auto-run hook, so
        # auto-run + a payload still grades HIGH RISK (underclaim is the dangerous way).
        for kw in ("AutoNew", "AutoExit", "Document_New", "Workbook_Activate",
                   "Workbook_BeforeClose", "Window_Activate"):
            verdict, _ = self.v([
                {"type": "Suspicious", "keyword": kw, "description": "auto-run handler"},
                {"type": "Base64 String", "keyword": "TVqQAA", "description": "encoded payload"}])
            self.assertEqual("HIGH RISK", verdict, kw)

    # --- render + scope -------------------------------------------------------
    def test_olevba_report_shows_macro_hero(self):
        report = self._macro_report("olevba", [
            {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
            {"type": "Suspicious", "keyword": "powershell", "description": "downloads a payload"}])
        self.assertIn("macro-hero", report)
        self.assertIn("HIGH RISK", report)
        self.assertIn("Macro verdict", report)
        self.assertIn("T1204.002", report)
        self.assertIn("T1059.001", report)
        self.assertIn("document not executed", report)      # honesty qualifier
        self.assertNotIn("[truncated]", report)
        self.assertNotIn("<script", report)

    def test_non_macro_report_has_no_verdict_hero(self):
        report = self._macro_report("nikto", [
            {"id": "3268", "Severity": "MEDIUM", "Title": "dir indexing"}])
        # nikto keeps its finding rows; no macro verdict hero is injected.
        self.assertNotIn("macro-hero", report)
        self.assertNotIn("Macro verdict", report)

    def test_tls_and_macro_heroes_are_mutually_exclusive(self):
        # the shared exec-hero slot must not render both; an olevba report shows the
        # macro hero and NOT the TLS grade hero.
        report = self._macro_report("olevba", [
            {"type": "Suspicious", "keyword": "Chr", "description": "obfuscation"}])
        self.assertIn("macro-hero", report)
        self.assertNotIn("tls-hero", report)



class MetasploitCardP3c(unittest.TestCase):
    """Wave-2 P3c: a metasploit_search/metasploit_info report is a CATALOG LOOKUP -- it
    strips the severity chrome and renders per-module reference cards with a NEUTRAL rank
    badge (Rapid7 reliability, never severity). Full parse (Scott 2026-08-30), best-effort
    with a raw-transcript fallback on any parse miss."""

    SEARCH_MINI = ("Matching Modules\n"
                   "   #  Name                              Rank    Description\n"
                   "   0  auxiliary/scanner/smb/smb_version  normal  SMB Version Detection")
    SEARCH_FULL = ("Matching Modules\n================\n\n"
                   "   #  Name                                      Disclosure Date  Rank     Check  Description\n"
                   "   -  ----                                      ---------------  ----     -----  -----------\n"
                   "   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue\n"
                   "   1  auxiliary/scanner/smb/smb_ms17_010        2017-03-14       normal   No     MS17-010 Detection\n")
    INFO = ("       Name: EternalBlue\n     Module: exploit/windows/smb/ms17_010_eternalblue\n"
            "   Platform: Windows\n       Rank: Average\n  Disclosed: 2017-03-14\n\n"
            "Available targets:\n  Id  Name\n  --  ----\n  0   Automatic Target\n\n"
            "Basic options:\n  Name    Current Setting  Required  Description\n  ----    -----\n"
            "  RHOSTS                   yes  host\n\n"
            "References:\n  https://nvd.nist.gov/vuln/detail/CVE-2017-0144\n")

    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_parse_msf_search"):
            self.skipTest("_parse_msf_search absent on this revision")

    def _report(self, scanner, transcript):
        return self.server._render_report({
            "schema_version": 1, "scanner": scanner, "status": "success",
            "source_type": "cli", "target_ref": "q", "metadata": {},
            "findings": [{"id": f"{scanner}-q", "Severity": "INFO", "Title": "t",
                          "evidence": transcript}]})

    # --- parsers --------------------------------------------------------------
    def test_search_minimal_and_full_layouts_parse(self):
        mini = self.server._parse_msf_search(self.SEARCH_MINI)
        self.assertEqual(1, len(mini))
        self.assertEqual("auxiliary/scanner/smb/smb_version", mini[0]["name"])
        self.assertEqual("Auxiliary", mini[0]["mtype"])
        self.assertEqual("normal", mini[0]["rank"])
        full = self.server._parse_msf_search(self.SEARCH_FULL)
        self.assertEqual(2, len(full))
        self.assertEqual("exploit/windows/smb/ms17_010_eternalblue", full[0]["name"])
        self.assertEqual("Exploit", full[0]["mtype"])
        self.assertEqual("2017-03-14", full[0]["disclosure"])
        self.assertEqual("average", full[0]["rank"])

    def test_search_no_table_returns_empty(self):
        self.assertEqual([], self.server._parse_msf_search("random text, no modules table"))
        self.assertEqual([], self.server._parse_msf_search(""))

    def test_info_parses_header_cves_targets_options(self):
        d = self.server._parse_msf_info(self.INFO)
        self.assertEqual("exploit/windows/smb/ms17_010_eternalblue", d["module"])
        self.assertEqual("Exploit", d["mtype"])
        self.assertEqual("Average", d["rank"])
        self.assertEqual("2017-03-14", d["disclosed"])
        self.assertIn("CVE-2017-0144", d["cves"])
        self.assertIn("Automatic Target", d["targets"])
        self.assertIn("RHOSTS", d["options"])

    def test_info_non_info_returns_none(self):
        self.assertIsNone(self.server._parse_msf_info("no key value pairs at all"))
        self.assertIsNone(self.server._parse_msf_info(""))

    def test_module_type_mapping(self):
        self.assertEqual("Post", self.server._msf_module_type("post/windows/gather/x"))
        self.assertEqual("Payload", self.server._msf_module_type("payload/generic/shell"))
        self.assertEqual("Module", self.server._msf_module_type("weird/thing"))

    # --- render: strip severity chrome, show catalog + cards ------------------
    def test_search_report_shows_catalog_and_cards_no_severity_chrome(self):
        h = self._report("metasploit_search", self.SEARCH_FULL)
        self.assertIn('class="hero msf-catalog"', h)      # catalog banner
        self.assertIn("not an assessment of any target", h)
        self.assertIn('<article class="msf-card"', h)     # per-module card
        self.assertIn("ms17_010_eternalblue", h)
        self.assertIn("rank: average", h)                 # neutral rank badge
        self.assertNotIn("Highest severity", h)           # severity tile stripped
        self.assertIn("no target severity", h)            # severity chart N/A
        # no per-card Severity mark or detection-confidence chip
        card = h.split('<article class="msf-card"', 1)[1]
        self.assertNotIn('class="sev', card)
        self.assertNotIn('class="conf ', card)
        self.assertNotIn("<script", h)

    def test_info_report_shows_detailed_card(self):
        h = self._report("metasploit_info", self.INFO)
        self.assertIn('<article class="msf-card"', h)
        self.assertIn("CVE-2017-0144", h)
        self.assertIn("Automatic Target", h)
        self.assertIn("RHOSTS", h)
        self.assertIn("Average", h)                        # rank word present

    def test_unparseable_transcript_falls_back_to_raw_without_severity_chrome(self):
        # MC2: a catalog lookup NEVER shows severity chrome, parsed or not. On a parse
        # miss the raw transcript is shown in a neutral card under the catalog banner,
        # with NO "Highest severity" tile, NO Severity chart, NO conf chip.
        h = self._report("metasploit_search", "No results from the module database.")
        self.assertIn('class="hero msf-catalog"', h)        # catalog framing still shown
        self.assertIn("could not be parsed", h)             # honest parse-miss wording
        self.assertIn("No results from the module database", h)  # raw transcript kept
        self.assertIn('class="msf-raw"', h)                 # raw card, not a fabricated one
        self.assertNotIn("Highest severity", h)             # severity tile stripped
        self.assertIn("no target severity", h)              # severity chart N/A
        self.assertNotIn('class="conf ', h)                 # no confidence chip
        self.assertNotIn('class="sev sev-', h)              # no coloured severity mark

    def test_ansi_colour_codes_do_not_misslice_columns(self):
        # red-team B1: msfconsole colorizes non-TTY `search` data rows (keyword highlight
        # + rank colour) but not the header, so header-relative column slicing shifts on
        # the zero-width ANSI bytes -> mangled name and a garbage rank badge. The parser
        # must strip ANSI before slicing.
        esc = "\x1b"
        row = (f"   0  auxiliary/scanner/{esc}[1m{esc}[43msmb{esc}[0m/"
               f"{esc}[1m{esc}[43msmb{esc}[0m_version  {esc}[32mnormal{esc}[0m  SMB Version Detection")
        tx = "Matching Modules\n   #  Name                              Rank    Description\n" + row
        mods = self.server._parse_msf_search(tx)
        self.assertEqual(1, len(mods))
        self.assertEqual("auxiliary/scanner/smb/smb_version", mods[0]["name"])
        self.assertEqual("normal", mods[0]["rank"])
        self.assertNotIn(esc, mods[0]["name"] + mods[0]["rank"])
        # info transcript ANSI stripped too
        info = f"       Name: {esc}[1mEB{esc}[0m\n     Module: exploit/windows/smb/eb\n       Rank: Average\n"
        self.assertEqual("exploit/windows/smb/eb", self.server._parse_msf_info(info)["module"])

    def test_wrapped_description_line_is_not_a_phantom_module(self):
        # red-team N3: a wrapped Description continuation line beginning with a digit
        # ("3.5 and later versions") must not parse as a module. A real row's Name is a
        # module path (contains "/"); the continuation has none, so it is dropped.
        tx = ("Matching Modules\n   #  Name                          Rank    Description\n"
              "   0  exploit/multi/http/foo         normal  Works on Apache\n"
              "   3.5 and later versions\n")
        mods = self.server._parse_msf_search(tx)
        self.assertEqual(1, len(mods))
        self.assertEqual("exploit/multi/http/foo", mods[0]["name"])

    def test_truncation_marker_does_not_misslice_into_rank(self):
        # red-team N2: the capture-time "… [truncated]" marker in the final table row
        # must not be sliced into the rank column (rank showing "uncated]").
        tx = ("Matching Modules\n"
              "   #  Name                              Rank    Description\n"
              "   0  auxiliary/scanner/smb/smb_version  normal  SMB Version Detection\n"
              "   1  auxiliary/scanner/smb/smb_ver\u2026 [truncated]")
        mods = self.server._parse_msf_search(tx)
        self.assertEqual(1, len(mods))                      # the partial row is dropped
        self.assertEqual("normal", mods[0]["rank"])
        self.assertTrue(all("truncated" not in m["rank"] for m in mods))

    def test_non_metasploit_report_has_no_catalog(self):
        h = self.server._render_report({
            "schema_version": 1, "scanner": "nikto", "status": "success",
            "source_type": "url", "target_ref": "x", "metadata": {},
            "findings": [{"id": "3268", "Severity": "MEDIUM", "Title": "dir indexing"}]})
        self.assertNotIn('class="hero msf-catalog"', h)


class ReconVulnHeroesP3d(unittest.TestCase):
    """Wave-2 P3d: a recon exposure hero (nmap) and a vuln severity hero (trivy/nuclei),
    each computed from findings, each honest — open ports are exposure not vulnerability,
    and vuln counts are detection-only, never a "secure" claim on a clean scan."""

    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_recon_exposure"):
            self.skipTest("_recon_exposure absent on this revision")

    def _report(self, scanner, findings):
        return self.server._render_report({
            "schema_version": 1, "scanner": scanner, "status": "success",
            "source_type": "host", "target_ref": "t", "metadata": {}, "findings": findings})

    # --- recon summary --------------------------------------------------------
    def test_recon_exposure_counts(self):
        f = [{"state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"},
             {"state": "open", "service": "http", "product": "nginx"},
             {"state": "open", "service": "http"},
             {"state": "closed", "service": "ftp"}, "junk"]
        open_ports, services, versioned = self.server._recon_exposure(f)
        self.assertEqual(3, open_ports)
        self.assertEqual({"ssh": 1, "http": 2}, services)
        self.assertEqual(2, versioned)

    def test_recon_no_open_ports(self):
        self.assertEqual((0, {}, 0), self.server._recon_exposure([{"state": "closed"}, "x"]))

    # --- vuln summary ---------------------------------------------------------
    def test_vuln_summary_counts_and_top_packages(self):
        f = [{"VulnerabilityID": "CVE-2021-1", "Severity": "CRITICAL", "PkgName": "log4j"},
             {"VulnerabilityID": "CVE-2021-2", "Severity": "HIGH", "PkgName": "log4j"},
             {"VulnerabilityID": "CVE-2020-9", "Severity": "MEDIUM", "PkgName": "openssl"},
             {"VulnerabilityID": "CVE-2019-9", "Severity": "INFO", "PkgName": "zlib"}]
        counts, total, top = self.server._vuln_summary(f)
        self.assertEqual({"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}, counts)   # INFO not counted
        self.assertEqual(3, total)
        self.assertEqual([("log4j", 2), ("openssl", 1)], top)

    def test_vuln_summary_package_tally_matches_headline_basis(self):
        # red-team N1: the per-package tally counts RAW coloured findings, the SAME basis
        # as the headline total, so the two never disagree. Two coloured findings on one
        # package -> headline 2 AND "log4j 2", not a deduped 1.
        f = [{"VulnerabilityID": "CVE-2021-1", "Severity": "HIGH", "PkgName": "log4j"},
             {"VulnerabilityID": "CVE-2021-2", "Severity": "HIGH", "PkgName": "log4j"}]
        counts, total, top = self.server._vuln_summary(f)
        self.assertEqual(2, total)
        self.assertEqual([("log4j", 2)], top)
        # the sum of per-package tallies equals the headline total when every finding
        # carries a PkgName (the consistency invariant N1 fixed).
        self.assertEqual(total, sum(n for _, n in top))

    def test_vuln_summary_clean(self):
        self.assertEqual(({}, 0, []), self.server._vuln_summary([]))

    def test_nuclei_severity_counted(self):
        counts, total, _ = self.server._vuln_summary(
            [{"id": "t", "Severity": "HIGH", "Title": "x"}])
        self.assertEqual({"HIGH": 1}, counts)

    def test_none_fields_are_robust(self):
        # red-team NB2: _render_report is generic over persisted documents; a None
        # PkgName/service/product/version must not crash or render the literal "None".
        counts, total, top = self.server._vuln_summary([
            {"Severity": "HIGH", "PkgName": "log4j"},
            {"Severity": "CRITICAL", "PkgName": None}])
        self.assertEqual({"HIGH": 1, "CRITICAL": 1}, counts)
        self.assertEqual([("log4j", 1)], top)                   # None PkgName not a package
        open_ports, services, versioned = self.server._recon_exposure(
            [{"state": "open", "service": None, "product": None, "version": None}])
        self.assertEqual(1, open_ports)
        self.assertEqual({"unknown": 1}, services)              # None service -> "unknown"
        self.assertEqual(0, versioned)                          # None product/version not a fingerprint

    # --- render ---------------------------------------------------------------
    def test_nmap_report_shows_recon_hero(self):
        h = self._report("nmap", [{"state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
        self.assertIn("recon-hero", h)
        self.assertIn("Open ports", h)
        self.assertIn("does NOT assess", h)          # exposure != vulnerability honesty
        self.assertNotIn("<script", h)

    def test_trivy_report_shows_vuln_hero(self):
        h = self._report("trivy", [
            {"VulnerabilityID": "CVE-2021-1", "Severity": "CRITICAL", "PkgName": "log4j"},
            {"VulnerabilityID": "CVE-2021-2", "Severity": "HIGH", "PkgName": "log4j"}])
        self.assertIn("vuln-hero", h)
        self.assertIn("sevbar", h)                    # stacked severity bar
        self.assertIn("log4j — 2 issue", h)           # top package
        self.assertIn("detection-only", h)            # honesty qualifier
        self.assertNotIn("<script", h)

    def test_clean_vuln_scan_never_says_secure(self):
        h = self._report("trivy", [])
        hero = h.split('class="hero vuln-hero"')[1].split("</div></div>")[0]
        self.assertIn("No vulnerabilities of coloured", hero)
        self.assertFalse(any(w in hero.lower() for w in ("secure", "safe", "clean")))

    def test_recon_hero_counts_multi_host_exposure_pre_dedup(self):
        # red-team B1: nmap findings carry no host id, so host-blind dedup collapses N
        # hosts with an identical open-port fingerprint to one finding. The recon hero
        # counts EXPOSURE from the pre-dedup list, so a multi-host scan is not undercounted
        # to "1 open port", and a note explains the findings table de-duplicates.
        dupe = {"id": "port-22-tcp", "Severity": "INFO", "state": "open", "service": "ssh",
                "product": "OpenSSH", "version": "8.9", "Title": "22/tcp ssh open"}
        h = self.server._render_report({
            "schema_version": 1, "scanner": "nmap", "status": "success",
            "source_type": "host", "target_ref": "10.0.0.0/24", "metadata": {},
            "findings": [dict(dupe), dict(dupe)]})
        self.assertIn("recon-hero", h)
        self.assertIn(">2<", h)                                  # exposure counted pre-dedup
        self.assertIn("ssh (2)", h)
        self.assertIn("de-duplicates identical host:port", h)    # honest about the table

    def test_recon_hero_single_host_has_no_dedup_note(self):
        # distinct fingerprints do not collapse, so exposure == distinct and no note fires.
        h = self.server._render_report({
            "schema_version": 1, "scanner": "nmap", "status": "success",
            "source_type": "host", "target_ref": "10.0.0.5", "metadata": {},
            "findings": [{"id": "port-22-tcp", "state": "open", "service": "ssh", "Severity": "INFO", "Title": "22/tcp ssh open"},
                         {"id": "port-80-tcp", "state": "open", "service": "http", "Severity": "INFO", "Title": "80/tcp http open"}]})
        self.assertIn(">2<", h)
        self.assertNotIn("de-duplicates identical host:port", h)

    def test_non_recon_vuln_report_has_neither_hero(self):
        h = self._report("nikto", [{"id": "1", "Severity": "MEDIUM", "Title": "x"}])
        self.assertNotIn("recon-hero", h)
        self.assertNotIn("vuln-hero", h)


class RemediationSlaP4(unittest.TestCase):
    """Wave-2 P4/M5: an auto remediation SLA benchmark from the severity band in the
    combined exec layer. The window is an ILLUSTRATIVE policy target, never a measured
    deadline or a compliance guarantee; KEV/regulatory dates override."""

    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_remediation_sla"):
            self.skipTest("_remediation_sla absent on this revision")

    def test_sla_days_per_band(self):
        self.assertEqual(15, self.server._remediation_sla("CRITICAL"))
        self.assertEqual(30, self.server._remediation_sla("HIGH"))
        self.assertEqual(90, self.server._remediation_sla("MEDIUM"))
        self.assertEqual(180, self.server._remediation_sla("LOW"))
        self.assertIsNone(self.server._remediation_sla("INFO"))
        self.assertIsNone(self.server._remediation_sla("UNKNOWN"))
        self.assertEqual(15, self.server._remediation_sla("critical"))   # case-insensitive

    def test_combined_report_shows_sla_block(self):
        # remediable package-upgrade findings become fix-queue work units, which the SLA
        # counts (B1: the SLA covers only remediable items, so it never contradicts the
        # "No remediable findings" line).
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "PkgName": "log4j", "InstalledVersion": "2.14", "FixedVersion": "2.16", "Title": "x"},
            {"VulnerabilityID": "CVE-2020-11111", "Severity": "HIGH", "PkgName": "openssl", "InstalledVersion": "1.1", "FixedVersion": "1.2", "Title": "y"},
            {"VulnerabilityID": "CVE-2019-22222", "Severity": "MEDIUM", "PkgName": "zlib", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "z"}], scanner="trivy")])
        self.assertIn('class="sla"', report)
        self.assertIn("15-day target", report)        # Critical, framed as a target
        self.assertIn("30-day target", report)        # High
        self.assertIn("90-day target", report)        # Medium
        # no Low findings -> no Low TABLE ROW (the note still names all four windows)
        sla_table = report.split('class="sla"', 1)[1].split("</table>", 1)[0]
        self.assertNotIn('sev-low">Low', sla_table)
        self.assertIn('sev-critical">Critical', sla_table)
        # at-a-glance honesty (red-team N1): the block heading itself says "illustrative",
        # so a skimmed/screenshotted table is not read as a committed deadline.
        self.assertIn("Fix-queue items", report)         # SLA counts remediation work units
        self.assertIn("illustrative benchmark", report)
        # full disclaimer: never a measured deadline or compliance guarantee; KEV overrides
        self.assertIn("NOT a measured deadline", report)
        self.assertIn("NOT a compliance", report)
        self.assertIn("KEV", report)
        self.assertNotIn("<script", report)

    def test_render_uses_the_sla_helper_single_source(self):
        # Standards F2 / red-team N2: the render path must use _remediation_sla (the single
        # source of truth), so a change to the helper flows to the report. Patch the helper
        # and confirm the rendered window follows it.
        original = self.server._remediation_sla
        self.server._remediation_sla = lambda band: 7 if str(band).upper() == "CRITICAL" else original(band)
        try:
            report = _combined(self.server, [_result([
                {"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "2", "Title": "x"}], scanner="trivy")])
            self.assertIn("7-day target", report)      # render followed the patched helper
        finally:
            self.server._remediation_sla = original

    def test_cve_lane_work_unit_counted_in_sla(self):
        # a valid-CVE finding with no package upgrade is a CVE-lane fix-queue work unit; the
        # SLA must count it by severity (its work-unit severity slot is populated, not None).
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-2021-44228", "Severity": "HIGH", "Title": "Log4Shell"}], scanner="trivy")])
        self.assertIn('class="sla"', report)
        self.assertIn("30-day target", report)           # High -> 30 days
        self.assertNotIn("15-day target", report)         # no Critical work unit

    def test_sla_does_not_contradict_no_remediable_findings(self):
        # red-team B1: a coloured hardening finding (weak cipher, no CVE / no fix) never
        # becomes a fix-queue work unit, so the report says "No remediable findings". The
        # SLA counts fix-queue items, so it must NOT assert a remediation target for it --
        # the two must never contradict in one exec layer.
        report = _combined(self.server, [_result([
            {"Severity": "HIGH", "Title": "Weak cipher RC4", "id": "tls-cipher-rc4"}], scanner="testssl")])
        self.assertIn("No remediable findings", report)
        self.assertNotIn('class="sla"', report)          # no SLA row -> no contradiction
        self.assertNotIn("30-day target", report)

    def test_info_only_combined_has_no_sla_rows(self):
        report = _combined(self.server, [_result([
            {"VulnerabilityID": "CVE-0", "Severity": "INFO", "PkgName": "p", "Title": "i"}], scanner="trivy")])
        # no coloured severity -> the SLA block is omitted entirely (no rows to show)
        self.assertNotIn('class="sla"', report)


if __name__ == "__main__":
    unittest.main()
