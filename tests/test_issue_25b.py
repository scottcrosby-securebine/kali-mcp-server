"""Row 20 / #25b: nuclei surfaces its template coverage so a '0 findings'
result cannot be misread as 'the host is clean'.

A default nuclei scan runs the promoted detection-only set, which may be a
handful of templates. #25b (the surfacing half; #25a expands the set) puts the
count and promoted-set version in the tool output and the persisted metadata,
and cautions when the set that ran is trivially small.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


class CoverageSummaryLine(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        # These unit-test brand-new helpers; on a base revision that predates
        # them a direct call would ERROR and pollute the mutation gate, which
        # requires assertion failures with zero errors. The behavioural tests
        # below carry the mutation signal through nuclei_scan, which exists there.
        if not hasattr(self.server, "_nuclei_coverage_summary"):
            self.skipTest("coverage helpers absent on this revision")

    def test_trivially_small_set_with_no_findings_cautions(self):
        line = self.server._nuclei_coverage_summary((1, 1), "promoted set v10", 0)
        self.assertTrue(line.startswith("⚠️"))
        self.assertIn("1 detection-only template", line)
        self.assertIn("NOT that the target is free", line)

    def test_an_adequate_set_with_no_findings_does_not_caution(self):
        # At or above the meaningful floor, 0 findings is a real result, not a
        # near-empty scan; the line informs but does not warn.
        run = self.server.NUCLEI_MIN_MEANINGFUL_TEMPLATES
        line = self.server._nuclei_coverage_summary((run, run), "promoted set v10", 0)
        self.assertFalse(line.startswith("⚠️"))
        self.assertIn(f"{run} detection-only template", line)

    def test_findings_present_never_cautions(self):
        line = self.server._nuclei_coverage_summary((1, 1), "promoted set v10", 3)
        self.assertFalse(line.startswith("⚠️"))

    def test_undeterminable_count_cautions(self):
        line = self.server._nuclei_coverage_summary(None, "promoted set v10", 0)
        self.assertTrue(line.startswith("⚠️"))
        self.assertIn("undeterminable", line)

    def test_metadata_carries_the_counts(self):
        self.assertEqual(
            {"nuclei_templates_run": "2", "nuclei_templates_available": "7"},
            self.server._nuclei_coverage_metadata((2, 7)))
        self.assertEqual(
            {"nuclei_templates_run": "Not reported"},
            self.server._nuclei_coverage_metadata(None))


class NucleiScanSurfacesCoverage(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _run(self, counted, findings, versions=None):
        captured = {}
        outcome = {"summary": f"✅ Nuclei scan completed: {len(findings)} finding(s)",
                   "findings": findings}
        with (
            patch.object(self.server, "_nuclei_template_match", return_value=counted),
            patch.object(self.server, "_run_nuclei_capture", return_value=outcome),
            patch.object(self.server, "_nuclei_report_versions",
                         return_value=versions or {"nuclei_templates": "v10.4.7"}),
            patch.object(self.server, "_write_scanner_result",
                         side_effect=lambda d: captured.update(d) or "x"),
        ):
            out = asyncio.run(self.server.nuclei_scan("example.test"))
        return out, captured

    def test_output_leads_with_coverage_then_the_scan_headline(self):
        # No unsafe indexing: a base revision returns a single ✅ line, so the
        # assertions must FAIL cleanly there, never IndexError.
        out, _ = self._run((1, 1), [])
        self.assertTrue(out.startswith("Coverage:") or out.startswith("⚠️"), out[:80])
        self.assertIn("v10.4.7", out)
        self.assertIn("✅ Nuclei scan completed", out)

    def test_small_default_set_and_zero_findings_carries_the_caution(self):
        out, _ = self._run((1, 1), [])
        self.assertTrue(out.startswith("⚠️"), out[:80])

    def test_persisted_metadata_records_the_counts(self):
        # .get, not [], so a base revision without the keys FAILS, not ERRORS.
        _, captured = self._run((1, 4), [])
        meta = captured["metadata"]
        self.assertEqual("1", meta.get("nuclei_templates_run"))
        self.assertEqual("4", meta.get("nuclei_templates_available"))
        # The version rows survive the merge.
        self.assertEqual("v10.4.7", meta.get("nuclei_templates"))


if __name__ == "__main__":
    unittest.main()
