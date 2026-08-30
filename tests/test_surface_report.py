"""P3b / #89 — external attack-surface report.

Covers the spec's Test seams: `_mask_email`, `_parse_whois`, `_dns_hygiene`,
`render_surface` via `_render_report`, and `surface_report` aggregation. The
honesty rules (#89) are the point of the report, so several assertions have
"teeth" verified by mutation (see the module docstring in the report note).
"""

import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


WHOIS_TEXT = """% IANA WHOIS server comment line
Domain Name: EXAMPLE.COM
Registrar: Evil<script>alert(1)</script> Registrar Inc.
Creation Date: 1995-08-14T04:00:00Z
Updated Date: 2023-08-14T07:01:44Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientTransferProhibited
Registrar Abuse Contact Email: abuse@markmonitor.com
"""

DNS_JSON = json.dumps([
    {"type": "info", "name": "", "address": ""},               # metadata record, skipped
    {"type": "A", "name": "example.com", "address": "93.184.216.34"},
    {"type": "A", "name": "www.example.com", "address": "93.184.216.34"},
    {"type": "CNAME", "name": "shop.example.com",
     "target": "deleted-bucket.s3.amazonaws.com"},             # dangling: no A for target
    {"type": "TXT", "name": "example.com", "strings": "v=spf1 include:_spf.example.com ~all"},
    {"type": "TXT", "name": "_dmarc.example.com", "strings": "v=DMARC1; p=reject"},
])


def _result(scanner, target, findings):
    return {
        "schema_version": 1, "scanner": scanner, "source_type": "host",
        "target_ref": target, "status": "success", "metadata": {}, "findings": findings,
    }


class MaskEmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_masks_local_part_keeping_first_char(self):
        self.assertEqual("a***@example.com", self.server._mask_email("alice@example.com"))

    def test_single_char_local_part(self):
        self.assertEqual("*@x.com", self.server._mask_email("a@x.com"))

    def test_no_at_sign_returned_unchanged(self):
        self.assertEqual("not-an-email", self.server._mask_email("not-an-email"))

    def test_never_raises_on_non_string(self):
        self.assertEqual("123", self.server._mask_email(123))

    def test_masks_every_email_in_a_string(self):
        # red-team R-B2: masking must cover a free-text field, not only a lone
        # address -- so it renders safely over a whois line or an nmap banner.
        out = self.server._mask_email("primary alice@a.com and ops+abuse@b.io here")
        self.assertIn("a***@a.com", out)
        self.assertIn("o***@b.io", out)          # plus-tagged address still masked
        self.assertNotIn("alice@a.com", out)
        self.assertNotIn("ops+abuse@b.io", out)

    def test_scales_linearly_on_hostile_input(self):
        # red-team RT-F1: the old domain class `[A-Za-z0-9.\\-]+\\.` overlapped and
        # backtracked O(n^2). Gate on the SCALING RATIO, not wall-clock (memory:
        # wall-clock-perf-asserts-flake-on-ci). Linear ~2x; the bug was ~4x.
        import time

        def elapsed(n):
            s = "a" * n + "@" + "a." * n
            start = time.perf_counter()
            self.server._mask_email(s)
            return time.perf_counter() - start

        elapsed(2000)                       # warmup
        t1 = elapsed(4000)
        t2 = elapsed(8000)
        self.assertLess(t2, t1 * 3.0, f"_mask_email superlinear: {t1:.3f}s -> {t2:.3f}s")

    def test_masks_ip_literal_domain(self):
        # red-team RT-F4 (the part we close): IP-literal domains are covered.
        self.assertEqual("u***@[10.0.0.1]", self.server._mask_email("user@[10.0.0.1]"))


class ParseWhoisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_structured_fields_and_masked_email(self):
        findings = self.server._parse_whois(WHOIS_TEXT)
        self.assertEqual(1, len(findings))
        f = findings[0]
        self.assertEqual("INFO", f["Severity"])
        self.assertIn("Registrar Inc.", f["registrar"])
        self.assertEqual("1995-08-14T04:00:00Z", f["created"])
        self.assertEqual("2024-08-13T04:00:00Z", f["expires"])
        self.assertEqual(["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"], f["name_servers"])
        self.assertIn("clientTransferProhibited", f["status"])
        # Abuse email masked, raw never stored.
        self.assertIn("a***@markmonitor.com", f["emails"])
        self.assertNotIn("abuse@markmonitor.com", json.dumps(f))

    def test_empty_on_junk(self):
        self.assertEqual([], self.server._parse_whois("no structured lines here"))
        self.assertEqual([], self.server._parse_whois(""))
        self.assertEqual([], self.server._parse_whois(None))

    def test_scales_linearly_on_many_status_lines(self):
        # red-team R-N2: an `x not in growing_list` membership scan made a hostile
        # whois with thousands of unique Status lines quadratic. Gate on the SCALING
        # RATIO, not wall-clock, so a slow CI runner does not flake (memory:
        # wall-clock-perf-asserts-flake-on-ci). Linear ~2x; the O(n^2) bug was ~4x.
        import time

        def elapsed(n):
            text = "Registrar: r\n" + "".join(f"Domain Status: s{i}\n" for i in range(n))
            start = time.perf_counter()
            self.server._parse_whois(text)
            return time.perf_counter() - start

        elapsed(2000)                       # warmup
        t1 = elapsed(4000)
        t2 = elapsed(8000)
        self.assertLess(t2, t1 * 3.0, f"_parse_whois superlinear: {t1:.3f}s -> {t2:.3f}s")


class DnsHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _by_check(self, records):
        return {c["check"].split()[0]: c for c in self.server._dns_hygiene(records)}

    def test_present_verdicts_from_observed_records(self):
        records = [
            {"type": "TXT", "name": "example.com", "strings": "v=spf1 ~all"},
            {"type": "TXT", "name": "_dmarc.example.com", "strings": "v=DMARC1; p=none"},
        ]
        checks = self._by_check(records)
        self.assertTrue(checks["SPF"]["observed"])
        self.assertTrue(checks["DMARC"]["observed"])
        self.assertFalse(checks["Zone"]["observed"])

    def test_missing_check_reads_not_observed_never_pass(self):
        # No SPF/DMARC/AXFR records at all.
        checks = self._by_check([{"type": "A", "name": "example.com", "address": "1.2.3.4"}])
        for name in ("SPF", "DMARC", "Zone"):
            self.assertFalse(checks[name]["observed"])
            self.assertEqual("not observed in this scan", checks[name]["verdict"])
            self.assertNotIn("pass", checks[name]["verdict"].lower())
            self.assertNotIn("secure", checks[name]["verdict"].lower())

    def test_axfr_present_is_flagged(self):
        checks = self._by_check([{"type": "AXFR", "name": "example.com", "address": "1.2.3.4"}])
        self.assertTrue(checks["Zone"]["observed"])
        self.assertIn("FLAG", checks["Zone"]["verdict"])

    def test_never_raises_on_junk(self):
        self.assertEqual(3, len(self.server._dns_hygiene("garbage")))
        self.assertEqual(3, len(self.server._dns_hygiene([None, "x", 5])))

    def test_wrong_type_or_negative_statement_never_forges_a_verdict(self):
        # red-team R-B1: the match is TYPE- and VALUE-scoped. An A record whose
        # address happens to read `v=spf1`, and a TXT that merely SAYS "zone
        # transfer prohibited", must not forge SPF or AXFR.
        checks = self._by_check([
            {"type": "A", "name": "example.com", "address": "v=spf1 mail"},
            {"type": "TXT", "name": "example.com", "strings": "zone transfer prohibited"},
        ])
        self.assertFalse(checks["SPF"]["observed"])    # A-record address is not an SPF record
        self.assertFalse(checks["Zone"]["observed"])   # a TXT saying so is not a zone transfer

    def test_axfr_not_forged_by_a_failed_transfer_value(self):
        # red-team RT-F3: a captured zone_transfer field is Python-truthy even for
        # "failed"/"no"/"0", so a bare truthiness test forged AXFR from a FAILED
        # transfer. Only an explicit success marker (or an axfr-typed record) flags.
        for bad in ("failed", "no", "0", "false", ""):
            checks = self._by_check([{"type": "NS", "name": "example.com", "zone_transfer": bad}])
            self.assertFalse(checks["Zone"]["observed"], f"forged from {bad!r}")
        ok = self._by_check([{"type": "NS", "name": "example.com", "zone_transfer": "success"}])
        self.assertTrue(ok["Zone"]["observed"])

    def test_axfr_type_matched_exactly_not_by_substring(self):
        # R3 red-team note: `"axfr" in rtype` matched a crafted type "AXFR_FAILED";
        # exact match rejects it while a real axfr-typed record still flags.
        self.assertFalse(self._by_check([{"type": "AXFR_FAILED", "name": "x"}])["Zone"]["observed"])
        self.assertTrue(self._by_check([{"type": "AXFR", "name": "x"}])["Zone"]["observed"])


class RenderSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _render(self, results):
        document = {
            "schema_version": 1, "report_type": "surface", "scanner": "combined",
            "source_type": "host", "target_ref": "x", "status": "success",
            "metadata": {}, "results": results,
        }
        return self.server._render_report(document)

    def _full(self):
        dns_findings = self.server._parse_dnsrecon_json(DNS_JSON)
        whois_findings = self.server._parse_whois(WHOIS_TEXT)
        return self._render([
            _result("nmap", "example.com", [
                {"id": "port-80-tcp", "Severity": "INFO", "Title": "80/tcp http open",
                 "state": "open", "service": "http", "product": "nginx", "version": "1.18"},
                {"id": "port-3306-tcp", "Severity": "INFO", "Title": "3306/tcp mysql open",
                 "state": "open", "service": "mysql", "product": "MySQL", "version": "8.0"},
            ]),
            _result("whatweb", "http://example.com",
                    [{"id": "web-tech-nginx", "Severity": "INFO", "Title": "nginx detected",
                      "evidence": "x"}]),
            _result("dns_recon", "example.com", dns_findings),
            _result("subfinder", "example.com", [
                {"id": "s1", "Severity": "INFO", "Title": "www.example.com"},
                {"id": "s2", "Severity": "INFO", "Title": "shop.example.com"},
                {"id": "s3", "Severity": "INFO", "Title": "ghost.example.com"},
            ]),
            _result("whois", "example.com", whois_findings),
        ])

    def test_asset_inventory_joins_nmap_and_whatweb(self):
        html = self._full()
        self.assertIn("Asset inventory", html)
        self.assertIn("example.com", html)
        self.assertIn("93.184.216.34", html)          # IP joined from dns_recon A-record
        self.assertIn("mysql", html)                   # port service
        self.assertIn("nginx", html)                   # tech joined from whatweb

    def test_risky_port_highlighted(self):
        html = self._full()
        self.assertIn("Exposed services", html)
        self.assertIn("3306", html)
        self.assertIn("risky ports observed", html)

    def test_subdomain_resolve_live_split(self):
        html = self._full()
        # www has an A-record but no observed open port -> not "offline"/"dead".
        self.assertIn("resolved, no observed live service", html)
        # ghost has no A-record.
        self.assertIn("unresolved", html)
        self.assertNotIn("offline", html)
        self.assertNotIn("dead", html)

    def test_takeover_candidate_flagged_never_confirmed(self):
        html = self._full()
        self.assertIn("takeover candidate", html)
        self.assertIn("shop.example.com", html)
        self.assertNotIn("confirmed", html)
        self.assertNotIn("vulnerable", html)

    def test_hygiene_observed_only(self):
        html = self._full()
        self.assertIn("v=spf1 record observed", html)     # SPF present, observed
        self.assertIn("v=DMARC1 record observed", html)   # DMARC present, observed
        self.assertIn("not observed in this scan", html)  # AXFR not observed

    def test_emails_masked_in_output(self):
        html = self._full()
        self.assertIn("a***@markmonitor.com", html)
        self.assertNotIn("abuse@markmonitor.com", html)

    def test_attacker_markup_stays_escaped(self):
        html = self._full()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_theharvester_gap_flagged_not_fabricated(self):
        html = self._full()
        self.assertIn("OSINT footprint", html)
        self.assertIn("feed unavailable", html)

    def test_empty_results_render_without_error(self):
        html = self._render([])
        self.assertIn("External attack-surface report", html)
        self.assertIn("No nmap host captures", html)

    def test_dns_recon_only_subdomain_appears_in_table(self):
        # Spec P1: a host name only dnsrecon discovered (no subfinder/amass row)
        # must still reach the subdomain table.
        dns = self.server._parse_dnsrecon_json(json.dumps([
            {"type": "A", "name": "mail.corp.example.com", "address": "10.0.0.9"},
        ]))
        html = self._render([_result("dns_recon", "example.com", dns)])
        self.assertIn("mail.corp.example.com", html)

    def test_registrar_free_text_email_masked_in_render(self):
        # red-team R-B2: an email embedded in a whois FIELD value (not the separate
        # abuse-email line) must render masked.
        whois = self.server._parse_whois(
            "Registrar: Contact ops+abuse@registrar.example for issues\n"
            "Domain Status: ok\n")
        html = self._render([_result("whois", "example.com", whois)])
        self.assertNotIn("ops+abuse@registrar.example", html)
        self.assertIn("o***@registrar.example", html)

    def test_nmap_service_banner_email_masked_in_render(self):
        # red-team R-B2: an email in an nmap service/product banner must render masked.
        html = self._render([_result("nmap", "example.com", [
            {"id": "port-25-tcp", "Severity": "INFO", "Title": "25/tcp smtp open",
             "state": "open", "service": "smtp", "product": "postmaster root@mail.example"},
        ])])
        self.assertNotIn("root@mail.example", html)
        self.assertIn("r***@mail.example", html)

    def test_email_in_dns_name_cname_target_and_tech_masked(self):
        # red-team RT-F2: the R-B2 fix wrapped only a few fields. An email hidden in
        # a dnsrecon record NAME, a CNAME TARGET, or a whatweb tech label must also
        # render masked -- masking now runs at the single render chokepoint.
        dns = self.server._parse_dnsrecon_json(json.dumps([
            {"type": "A", "name": "ops@corp.example", "address": "1.2.3.4"},
            {"type": "CNAME", "name": "x.example.com", "target": "admin@stale.example"},
        ]))
        html = self._render([
            _result("nmap", "example.com", [
                {"id": "p80", "Severity": "INFO", "Title": "80/tcp http open",
                 "state": "open", "service": "http"}]),
            _result("dns_recon", "example.com", dns),
            _result("whatweb", "http://example.com",
                    [{"id": "t", "Severity": "INFO", "Title": "root@mail.example detected"}]),
        ])
        for raw in ("ops@corp.example", "admin@stale.example", "root@mail.example"):
            self.assertNotIn(raw, html)
        self.assertIn("o***@corp.example", html)     # dnsrecon A-record name
        self.assertIn("a***@stale.example", html)    # CNAME takeover target
        self.assertIn("r***@mail.example", html)     # whatweb tech label

    def test_provenance_target_ref_email_masked(self):
        # R3-F1: a URL scan target carrying userinfo renders in the provenance
        # table; it must be masked there too, consistent with the inventory cell.
        html = self._render([_result("nmap", "http://admin@example.com/", [
            {"id": "p", "Severity": "INFO", "Title": "80/tcp http open",
             "state": "open", "service": "http"}])])
        self.assertNotIn("admin@example.com", html)
        self.assertIn("a***@example.com", html)


class SurfaceReportAggregationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_aggregates_external_recon_only(self):
        nmap_doc = _result("nmap", "example.com", [
            {"id": "port-80-tcp", "Severity": "INFO", "Title": "80/tcp http open",
             "state": "open", "service": "http"}])
        # A web-app-only scanner must be excluded from the surface report.
        sqlmap_doc = _result("sqlmap", "http://victim/", [
            {"id": "sqlmap-id-GET", "Title": "SQL injection: parameter id (GET)",
             "Severity": "HIGH", "param": "id"}])
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            (results / ("A" * 32 + ".json")).write_text(json.dumps(nmap_doc), encoding="utf-8")
            (results / ("B" * 32 + ".json")).write_text(json.dumps(sqlmap_doc), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="C" * 32),
            ):
                response = asyncio.run(self.server.surface_report(""))
                self.assertEqual(f"/reports/{'C' * 32}.html", response)
                html = (reports / f"{'C' * 32}.html").read_text(encoding="utf-8")
        self.assertIn("External attack-surface report", html)
        self.assertIn("example.com", html)
        self.assertNotIn("SQL injection", html)     # sqlmap result filtered out

    def test_empty_store_message(self):
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            results.mkdir()
            with patch.object(self.server, "RESULTS_ROOT", results):
                response = asyncio.run(self.server.surface_report(""))
        self.assertIn("No captured external-recon results", response)


if __name__ == "__main__":
    unittest.main()
