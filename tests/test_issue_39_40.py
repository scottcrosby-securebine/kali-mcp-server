"""Row 21 / #39 (EPSS) + #40 (KEV): CVE findings are enriched at render time
with exploitation context joined from baked feed files, and the not-enriched
rule keeps an unchecked field from ever reading as 0 / not-exploited.

The feed FILES are baked into the image (the deferred half); this pins the
render-time engine: the join, the sentinels, staleness, and that a non-CVE
finding is left alone. The default feed paths do not exist off-image, so the
first class renders the not-enriched state with no patching -- which is also
what carries the mutation signal against a base that predates the feature.
"""
import asyncio
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


def _doc(findings):
    return {"schema_version": 1, "scanner": "trivy", "target_ref": "/app",
            "status": "success", "findings": findings, "metadata": {}}


class NotEnrichedWhenNoFeedIsPresent(unittest.TestCase):
    """No patching: the baked feed paths are absent off-image, so a CVE finding
    must degrade to the sentinels -- never 0, never a green 'not exploited'."""

    def setUp(self):
        self.server, _ = load_server()

    def test_a_cve_finding_reads_not_enriched(self):
        report = self.server._render_report(
            _doc([{"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "Title": "Log4Shell"}]))
        self.assertIn("Not enriched", report)
        self.assertIn("Unknown — not enriched", report)
        # The forbidden readings never appear for an unchecked field.
        self.assertNotIn("0% probability", report)
        self.assertNotIn("Not listed in KEV", report)


class EnrichmentJoinsTheFeeds(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_enrich_finding"):
            self.skipTest("enrichment engine absent on this revision")
        self._today = datetime.date.today()

    def _render(self, findings, epss_text=None, kev_obj=None):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            epss_path = root / "epss.csv"
            kev_path = root / "kev.json"
            if epss_text is not None:
                epss_path.write_text(epss_text, encoding="utf-8")
            if kev_obj is not None:
                kev_path.write_text(json.dumps(kev_obj), encoding="utf-8")
            with (patch.object(self.server, "EPSS_FEED_PATH", epss_path),
                  patch.object(self.server, "KEV_FEED_PATH", kev_path)):
                return self.server._render_report(_doc(findings))

    def _fresh_epss(self, *rows):
        head = f"#model_version:v2023,score_date:{self._today.isoformat()},x\ncve,epss,percentile\n"
        return head + "".join(rows)

    def _fresh_kev(self, *vulns):
        return {"dateReleased": self._today.isoformat() + "T00:00:00.000Z",
                "vulnerabilities": list(vulns)}

    def test_a_listed_cve_shows_its_epss_and_kev(self):
        report = self._render(
            [{"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "Title": "Log4Shell"}],
            self._fresh_epss("CVE-2021-44228,0.97564,0.99999\n"),
            self._fresh_kev({"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24"}))
        self.assertIn("0.97564 probability", report)
        self.assertIn("Actively exploited — fix now", report)
        self.assertIn("2021-12-10", report)

    def test_a_cve_absent_from_a_fresh_kev_is_a_real_negative(self):
        report = self._render(
            [{"VulnerabilityID": "CVE-2000-1111", "Severity": "HIGH", "Title": "x"}],
            self._fresh_epss("CVE-2021-44228,0.9,0.9\n"),
            self._fresh_kev({"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}))
        self.assertIn("Not listed in KEV", report)   # fresh feed, CVE not in it
        self.assertIn("Not enriched", report)         # not in EPSS dataset either

    def test_a_stale_feed_is_treated_as_absent(self):
        report = self._render(
            [{"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "Title": "x"}],
            "#score_date:2019-01-01,x\ncve,epss,percentile\nCVE-2021-44228,0.9,0.9\n",
            {"dateReleased": "2019-01-01T00:00:00Z",
             "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2019-01-01"}]})
        self.assertIn("Not enriched", report)
        self.assertIn("Unknown — not enriched", report)
        self.assertNotIn("Actively exploited", report)

    def test_a_non_cve_finding_is_left_alone(self):
        report = self._render(
            [{"id": "dns-SOA-1", "Severity": "INFO", "Title": "SOA record"}],
            self._fresh_epss("CVE-2021-44228,0.9,0.9\n"),
            self._fresh_kev({"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}))
        self.assertNotIn("EPSS", report)
        self.assertNotIn("KEV", report)


class FeedLoaders(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        if not hasattr(self.server, "_load_epss_feed"):
            self.skipTest("feed loaders absent on this revision")

    def test_epss_parses_score_date_and_rows(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "e.csv"
            path.write_text("#score_date:2026-08-01,x\ncve,epss,percentile\nCVE-1-2,0.5,0.7\n",
                            encoding="utf-8")
            with patch.object(self.server, "EPSS_FEED_PATH", path):
                mapping, date = self.server._load_epss_feed()
        self.assertEqual(("0.5", "0.7"), mapping["CVE-1-2"])
        self.assertEqual(datetime.date(2026, 8, 1), date)

    def test_absent_epss_file_is_empty_not_an_error(self):
        with patch.object(self.server, "EPSS_FEED_PATH", Path("/no/such/feed.csv")):
            self.assertEqual(({}, None), self.server._load_epss_feed())

    def test_freshness_boundary(self):
        today = datetime.date(2026, 8, 28)
        stale = today - datetime.timedelta(days=self.server.FEED_STALE_AFTER_DAYS + 1)
        edge = today - datetime.timedelta(days=self.server.FEED_STALE_AFTER_DAYS)
        self.assertTrue(self.server._feed_is_fresh(edge, today))
        self.assertFalse(self.server._feed_is_fresh(stale, today))
        self.assertFalse(self.server._feed_is_fresh(None, today))

    def test_finding_cve_extraction(self):
        self.assertEqual("CVE-2021-44228",
                         self.server._finding_cve({"VulnerabilityID": "CVE-2021-44228"}))
        self.assertEqual("CVE-2021-41773",
                         self.server._finding_cve({"template-id": "CVE-2021-41773"}))
        self.assertIsNone(self.server._finding_cve({"id": "dns-SOA-1"}))


if __name__ == "__main__":
    unittest.main()
