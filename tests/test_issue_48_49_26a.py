"""Row 18: #48 (transcript re-runs that differ are kept), #26a (scheme-variant
targets collapse to one section), #49 (single-ref dedupes like combined).

These share one dedupe helper, so they are tested together. The pre-existing
noise-collapse behaviour (#37/#38) is pinned in test_wave2_gate.py and must keep
passing; this file covers only what row 18 changed.
"""
import asyncio
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


def _result(scanner, target, findings, status="success"):
    return {
        "schema_version": 1, "scanner": scanner, "target_ref": target,
        "status": status, "findings": findings, "metadata": {},
    }


class TranscriptRunsThatGenuinelyDifferAreKept(unittest.TestCase):
    """#48: a fail then a success for the same (scanner, target) used to collapse
    to the OLDEST, telling the operator the successful run found nothing."""

    def setUp(self):
        self.server, _ = load_server()

    def _combined(self, docs):
        return self.server._render_report({
            "schema_version": 1, "scanner": "combined", "status": "success",
            "findings": [], "results": docs,
        })

    def _transcript(self, scanner, target, body):
        return self.server._raw_text_parser(scanner, target)(body)

    def test_a_failed_then_successful_run_both_survive(self):
        fail = self._transcript(
            "smbclient", "10.0.0.5",
            "❌ Scan failed (exit code 1):\n\ndo_connect: NT_STATUS_IO_TIMEOUT\n")
        ok = self._transcript(
            "smbclient", "10.0.0.5",
            "✅ Scan completed successfully:\n\nSharename  Type\nADMIN$  Disk\n")
        report = self._combined([
            _result("smbclient", "10.0.0.5", fail, status="failed"),
            _result("smbclient", "10.0.0.5", ok),
        ])
        self.assertEqual(2, report.count("<article>"))
        # The operator sees BOTH the timeout and the share list.
        self.assertIn("NT_STATUS_IO_TIMEOUT", report)
        self.assertIn("ADMIN$", report)

    def test_identical_reruns_still_collapse(self):
        # The immunity the carve-out was built for must survive the fix: six
        # whois lookups differing only by the update stamp render one card.
        bodies = [
            f"✅ Scan completed successfully:\n\nDomain: example.com\n"
            f">>> Last update of whois database: 2026-08-27T10:0{n}:00Z <<<\n"
            for n in range(6)
        ]
        docs = [_result("whois", "example.com", self._transcript("whois", "example.com", b))
                for b in bodies]
        self.assertEqual(1, self._combined(docs).count("<article>"))


class SchemeVariantTargetsCollapseToOneSection(unittest.TestCase):
    """#26a: http://host:80 and host:80 are one scan, one section."""

    def setUp(self):
        self.server, _ = load_server()

    def _render_no_ref(self, docs):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            for index, doc in enumerate(docs):
                path = results / f"{chr(65 + index) * 32}.json"
                path.write_text(json.dumps(doc), encoding="utf-8")
                os.utime(path, (1_700_000_000 + index, 1_700_000_000 + index))
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="R" * 32),
            ):
                asyncio.run(self.server.generate_report())
            return (reports / f"{'R' * 32}.html").read_text(encoding="utf-8")

    def test_a_scheme_prefixed_and_bare_target_render_one_section(self):
        report = self._render_no_ref([
            _result("nikto", "10.0.0.5:80", [{"id": "a", "Severity": "INFO", "Title": "T"}]),
            _result("nikto", "http://10.0.0.5:80", [{"id": "b", "Severity": "INFO", "Title": "NEW"}]),
        ])
        self.assertEqual(1, len(re.findall(r'class="scan-row"', report)))
        # Newest of the collapsed pair wins.
        self.assertIn("NEW", report)

    def test_genuinely_distinct_hosts_stay_separate(self):
        report = self._render_no_ref([
            _result("nikto", "http://a.example", [{"id": "1", "Severity": "INFO", "Title": "T"}]),
            _result("nikto", "http://b.example", [{"id": "2", "Severity": "INFO", "Title": "T"}]),
        ])
        self.assertEqual(2, len(re.findall(r'class="scan-row"', report)))


class SingleRefDedupesLikeCombined(unittest.TestCase):
    """#49: the same document rendered N on the single-ref path and 1 combined."""

    def setUp(self):
        self.server, _ = load_server()

    def _single(self, doc):
        return self.server._render_report(doc)

    def test_exact_duplicate_findings_collapse_on_the_single_ref_path(self):
        doc = _result("nuclei", "http://x", [
            {"VulnerabilityID": "CVE-9", "Severity": "HIGH", "Title": "RCE"},
            {"VulnerabilityID": "CVE-9", "Severity": "HIGH", "Title": "RCE"},
            {"VulnerabilityID": "CVE-9", "Severity": "HIGH", "Title": "RCE"},
        ])
        self.assertEqual(1, self._single(doc).count("<article>"))

    def test_findings_differing_only_by_timestamp_collapse(self):
        doc = _result("nuclei", "http://x", [
            {"id": "F", "Severity": "LOW", "Title": "T", "timestamp": f"2026-01-0{n}"}
            for n in range(1, 7)
        ])
        self.assertEqual(1, self._single(doc).count("<article>"))

    def test_genuinely_distinct_findings_are_not_collapsed(self):
        doc = _result("nuclei", "http://x", [
            {"id": "A", "Severity": "LOW", "Title": "one"},
            {"id": "B", "Severity": "LOW", "Title": "two"},
        ])
        self.assertEqual(2, self._single(doc).count("<article>"))


if __name__ == "__main__":
    unittest.main()
