"""#55: report OUTPUT is bounded, and says so when it cuts.

`MAX_ARTIFACT_BYTES` bounds each input result file. Nothing bounded what the
renderer produced from one, and the amplification measured on the issue is ~5.4x:
a 22MB result rendered a 118MB HTML, and a combined report multiplies that by the
number of results in `/results`. Both `/results` and `/reports` are RAM-backed
tmpfs, so the report is charged straight to container memory.

Two caps, both disclosed: findings per section, and results per combined report.
The severity accounting deliberately covers EVERY finding, not just the rendered
ones, so a capped report still reports how many Criticals exist.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


def _finding(index, severity="HIGH"):
    return {
        "id": f"F-{index}",
        "title": f"Finding {index}",
        "severity": severity,
        "evidence": "E" * 200,
    }


def _render(server, findings, scanner="nuclei"):
    return server._render_report({
        "schema_version": 1, "scanner": scanner, "source_type": "host",
        "target_ref": "x", "status": "success", "metadata": {}, "findings": findings,
    })


def _combined(server, results):
    return server._render_report({
        "schema_version": 1, "scanner": "combined", "source_type": "host",
        "target_ref": "x", "status": "success", "metadata": {}, "findings": [],
        "results": results,
    })


def _result(server, findings, target="t", scanner="nuclei"):
    return {
        "schema_version": 1, "scanner": scanner, "source_type": "host",
        "target_ref": target, "status": "success", "metadata": {}, "findings": findings,
    }


class FindingsPerSectionAreBounded(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        self.cap = self.server.MAX_REPORT_FINDINGS

    def test_the_article_count_stops_at_the_cap(self):
        rendered = _render(self.server, [_finding(i) for i in range(self.cap + 250)])
        self.assertEqual(self.cap, rendered.count("<article>"))

    def test_the_cut_is_disclosed_with_its_size(self):
        # A silent cut reads as completeness. This is the same disclosure rule
        # the 200-line command output bound already follows.
        rendered = _render(self.server, [_finding(i) for i in range(self.cap + 250)])
        self.assertIn("250 further finding(s) omitted", rendered)

    def test_a_report_under_the_cap_is_untouched_and_says_nothing(self):
        rendered = _render(self.server, [_finding(i) for i in range(12)])
        self.assertEqual(12, rendered.count("<article>"))
        self.assertNotIn("omitted from this section", rendered)

    def test_severity_totals_count_every_finding_not_only_the_rendered_ones(self):
        # The point of counting before capping: an operator must still see that
        # 40 Criticals exist even when their articles were cut.
        findings = [_finding(i, "CRITICAL") for i in range(40)]
        findings += [_finding(i + 40, "LOW") for i in range(self.cap + 100)]
        rendered = _render(self.server, findings)
        self.assertEqual(self.cap, rendered.count("<article>"))
        # The severity chart carries the full tally, not the rendered subset.
        self.assertIn("40", rendered)
        self.assertIn("CRITICAL", rendered.upper())

    def test_output_stays_bounded_as_input_grows(self):
        # The defect in one line: input grew, output grew with it, without limit.
        small = _render(self.server, [_finding(i) for i in range(self.cap)])
        large = _render(self.server, [_finding(i) for i in range(self.cap * 20)])
        self.assertLess(
            len(large) - len(small),
            5_000,
            "output still scales with input past the cap",
        )


class CombinedResultsAreBounded(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()
        self.cap = self.server.MAX_REPORT_RESULTS

    def test_the_result_set_stops_at_the_cap_and_says_so(self):
        results = [
            _result(self.server, [_finding(i)], target=f"t{i}")
            for i in range(self.cap + 7)
        ]
        rendered = _combined(self.server, results)
        self.assertEqual(self.cap, rendered.count('class="scan-row"'))
        self.assertIn("7 older result(s) omitted", rendered)

    def test_the_newest_results_are_the_ones_kept(self):
        # `_load_normalized_results` sorts oldest first, so a head-slice would
        # keep the stalest scans and drop the ones just run.
        results = [
            _result(self.server, [_finding(i)], target=f"t{i}")
            for i in range(self.cap + 3)
        ]
        rendered = _combined(self.server, results)
        newest = f"t{self.cap + 2}"
        oldest = "t0"
        self.assertIn(newest, rendered)
        self.assertNotIn(f">{oldest} ", rendered)

    def test_a_session_under_the_cap_is_untouched_and_says_nothing(self):
        results = [_result(self.server, [_finding(i)], target=f"t{i}") for i in range(4)]
        rendered = _combined(self.server, results)
        self.assertEqual(4, rendered.count('class="scan-row"'))
        self.assertNotIn("older result(s) omitted", rendered)


class TheCapsAreNamedConstants(unittest.TestCase):
    """#41 rewrites `render_combined` wholesale. A cap spelled inline at its use
    site would go with it, silently. A module constant with this test behind it
    is a requirement that rewrite has to carry forward."""

    def setUp(self):
        self.server, _ = load_server()

    def test_both_caps_exist_as_module_level_ints(self):
        for name in ("MAX_REPORT_FINDINGS", "MAX_REPORT_RESULTS"):
            value = getattr(self.server, name, None)
            self.assertIsInstance(value, int, f"{name} must stay a module constant")
            self.assertGreater(value, 0)

    def test_the_findings_cap_leaves_room_for_a_real_trivy_image_scan(self):
        # A real image scan produced 151 findings; a cap under that would cut
        # ordinary output rather than the pathological case this bounds.
        self.assertGreaterEqual(self.server.MAX_REPORT_FINDINGS, 200)


if __name__ == "__main__":
    unittest.main()
