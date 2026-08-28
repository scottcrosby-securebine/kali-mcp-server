"""#26 (entries dedupe): the no-ref combined report collapses re-runs of one scan.

Every tool persists a result on every call, including the nested calls web_audit
makes, so one (scanner, target) lands in /results several times. The combined
report rendered a section and summed findings for each. generate_report's no-ref
branch now keeps the newest result per (scanner, target_ref); a re-scan
supersedes.

This is the entries-level, exact-string half. Scheme-variant targets
(http://h vs h) are collapsed at the render layer (#26a / row 18), not here.
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


def _doc(scanner, target, findings, status="success"):
    return {
        "schema_version": 1, "scanner": scanner, "target_ref": target,
        "status": status, "findings": findings, "metadata": {},
    }


class NoRefReportCollapsesReRunsOfOneScan(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _render(self, docs):
        """Plant docs oldest-first (index 0 is oldest) and combine with no ref."""
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            results = root / "results"
            reports = root / "reports"
            results.mkdir()
            for index, doc in enumerate(docs):
                path = results / f"{chr(65 + index) * 32}.json"
                path.write_text(json.dumps(doc), encoding="utf-8")
                # Distinct, increasing mtimes: the dedupe compares mtime, so the
                # test must not depend on write order alone.
                os.utime(path, (1_700_000_000 + index, 1_700_000_000 + index))
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server.secrets, "token_urlsafe", return_value="R" * 32),
            ):
                response = asyncio.run(self.server.generate_report())
            return (reports / f"{'R' * 32}.html").read_text(encoding="utf-8")

    def test_a_duplicate_scanner_target_renders_one_section(self):
        report = self._render([
            _doc("whatweb", "http://h", [{"id": "a", "Severity": "INFO", "Title": "T"}]),
            _doc("whatweb", "http://h", [{"id": "a", "Severity": "INFO", "Title": "T"}]),
        ])
        # Two identical whatweb captures -> one section, not two.
        self.assertEqual(1, len(re.findall(r'class="scan-row"', report)))

    def test_findings_are_not_summed_across_the_duplicates(self):
        report = self._render([
            _doc("whatweb", "http://h", [{"id": "a", "Severity": "HIGH", "Title": "T"}]),
            _doc("whatweb", "http://h", [{"id": "a", "Severity": "HIGH", "Title": "T"}]),
        ])
        # One HIGH, not two: the second capture no longer inflates the total.
        self.assertIn("HIGH</th><td>1", report)

    def test_the_newest_capture_wins(self):
        report = self._render([
            _doc("whatweb", "http://h", [{"id": "old", "Severity": "INFO", "Title": "OLD"}]),
            _doc("whatweb", "http://h", [{"id": "new", "Severity": "INFO", "Title": "NEW"}]),
        ])
        self.assertIn("NEW", report)
        self.assertNotIn("OLD", report)

    def test_distinct_scanners_on_one_target_are_all_kept(self):
        report = self._render([
            _doc("whatweb", "http://h", [{"id": "a", "Severity": "INFO", "Title": "T"}]),
            _doc("nikto", "http://h", [{"id": "b", "Severity": "INFO", "Title": "T"}]),
            _doc("nuclei", "http://h", [{"id": "c", "Severity": "INFO", "Title": "T"}]),
        ])
        self.assertEqual(3, len(re.findall(r'class="scan-row"', report)))

    def test_one_scanner_on_distinct_targets_is_kept(self):
        report = self._render([
            _doc("whatweb", "http://a", [{"id": "1", "Severity": "INFO", "Title": "T"}]),
            _doc("whatweb", "http://b", [{"id": "2", "Severity": "INFO", "Title": "T"}]),
        ])
        self.assertEqual(2, len(re.findall(r'class="scan-row"', report)))


if __name__ == "__main__":
    unittest.main()
