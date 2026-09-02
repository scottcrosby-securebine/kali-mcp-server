"""Phase 3 (#91 P3d): re-test classifier + comparability gate.

Pins the full verdict table and, above all, that a baseline finding's absence is
NEVER reported as fixed/closed — only NOT_OBSERVED_ON_RETEST on a comparable run,
else UNKNOWN (Option A, research C3/C4)."""
import unittest

from server_test_support import load_server

B_AT = "2020-01-01T00:00:00+00:00"
C_AT = "2020-02-01T00:00:00+00:00"
NMAP_ARGV = ["nmap", "--unprivileged", "-sT", "-Pn", "10.0.0.5"]


def _doc(scanner="nmap", target="10.0.0.5", findings=(), status="success",
         argv=NMAP_ARGV, captured_at=B_AT):
    return {"schema_version": 1, "scanner": scanner, "target_ref": target,
            "status": status, "findings": list(findings), "argv": argv,
            "captured_at": captured_at}


def _port(pid, sev="INFO", ev=""):
    return {"id": pid, "Title": f"{pid} open", "Severity": sev, "evidence": ev}


class RetestClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _verdicts(self, result):
        return {row["id"]: row["verdict"] for row in result["rows"]}

    def test_new_unchanged_not_observed_together(self):
        base = _doc(findings=[_port("port-80-tcp"), _port("port-443-tcp")], captured_at=B_AT)
        cur = _doc(findings=[_port("port-80-tcp"), _port("port-8080-tcp")], captured_at=C_AT)
        v = self._verdicts(self.server._retest_classify(base, cur))
        self.assertEqual("UNCHANGED", v["port-80-tcp"])
        self.assertEqual("NEW", v["port-8080-tcp"])
        self.assertEqual("NOT_OBSERVED_ON_RETEST", v["port-443-tcp"])

    def test_updated_on_state_drift(self):
        base = _doc(findings=[_port("port-80-tcp", sev="INFO", ev="a")], captured_at=B_AT)
        cur = _doc(findings=[_port("port-80-tcp", sev="HIGH", ev="b")], captured_at=C_AT)
        self.assertEqual("UPDATED", self._verdicts(self.server._retest_classify(base, cur))["port-80-tcp"])

    def test_absent_is_unknown_when_scope_differs(self):
        base = _doc(findings=[_port("port-443-tcp")], captured_at=B_AT)
        cur = _doc(findings=[_port("port-80-tcp")], argv=NMAP_ARGV + ["-p", "80"], captured_at=C_AT)
        self.assertEqual("UNKNOWN", self._verdicts(self.server._retest_classify(base, cur))["port-443-tcp"])

    def test_absent_is_unknown_for_pre_provenance_baseline(self):
        base = _doc(findings=[_port("port-443-tcp")], argv=None, captured_at=None)
        cur = _doc(findings=[_port("port-80-tcp")], captured_at=C_AT)
        self.assertEqual("UNKNOWN", self._verdicts(self.server._retest_classify(base, cur))["port-443-tcp"])

    def test_absent_is_unknown_when_scan_failed(self):
        base = _doc(findings=[_port("port-443-tcp")], captured_at=B_AT)
        cur = _doc(findings=[], status="failed", captured_at=C_AT)
        self.assertEqual("UNKNOWN", self._verdicts(self.server._retest_classify(base, cur))["port-443-tcp"])

    def test_absent_is_unknown_when_ordering_wrong(self):
        base = _doc(findings=[_port("port-443-tcp")], captured_at=C_AT)   # later
        cur = _doc(findings=[_port("port-80-tcp")], captured_at=B_AT)     # earlier
        self.assertEqual("UNKNOWN", self._verdicts(self.server._retest_classify(base, cur))["port-443-tcp"])

    def test_zero_yield_bucket(self):
        base = _doc(findings=[_port("port-80-tcp")], captured_at=B_AT)
        cur = _doc(findings=[], captured_at=C_AT)
        v = self._verdicts(self.server._retest_classify(base, cur))
        self.assertEqual("ZERO_YIELD", v["port-80-tcp"])

    def test_unvetted_scanner_is_advisory(self):
        base = _doc(scanner="ffuf", findings=[{"id": "web-path-200-/a", "Title": "t", "Severity": "INFO"}],
                    argv=["ffuf"], captured_at=B_AT)
        cur = _doc(scanner="ffuf", findings=[{"id": "web-path-200-/a", "Title": "t", "Severity": "INFO"}],
                   argv=["ffuf"], captured_at=C_AT)
        rows = self.server._retest_classify(base, cur)["rows"]
        self.assertTrue(rows and all(r["verdict"] == "ADVISORY" for r in rows))

    def test_nmap_multihost_target_is_advisory(self):
        base = _doc(target="10.0.0.0/24", findings=[_port("port-80-tcp")], captured_at=B_AT)
        cur = _doc(target="10.0.0.0/24", findings=[_port("port-80-tcp")], captured_at=C_AT)
        rows = self.server._retest_classify(base, cur)["rows"]
        self.assertTrue(all(r["verdict"] == "ADVISORY" for r in rows))

    def test_scanner_substitution_is_advisory(self):
        base = _doc(scanner="sslscan", findings=[{"id": "tls-cipher-x", "Severity": "HIGH"}],
                    argv=["sslscan"], captured_at=B_AT)
        cur = _doc(scanner="sslyze", findings=[{"id": "tls-cipher-x", "Severity": "HIGH"}],
                   argv=["sslyze"], captured_at=C_AT)
        rows = self.server._retest_classify(base, cur)["rows"]
        self.assertTrue(all(r["verdict"] == "ADVISORY" for r in rows))

    def test_never_emits_closure_vocabulary(self):
        base = _doc(findings=[_port("port-443-tcp")], captured_at=B_AT)
        cur = _doc(findings=[_port("port-80-tcp")], captured_at=C_AT)
        result = self.server._retest_classify(base, cur)
        blob = " ".join(r["verdict"] + " " + r["reason"] for r in result["rows"]).lower()
        for banned in ("fixed", "closed", "remediated", "verified closed"):
            self.assertNotIn(banned, blob)


class RetestReportToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _run(self, base, cur):
        import asyncio
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            reports = Path(root_text) / "reports"
            results.mkdir()
            bid, cid = "A" * 32, "B" * 32
            (results / f"{bid}.json").write_text(json.dumps(base), encoding="utf-8")
            (results / f"{cid}.json").write_text(json.dumps(cur), encoding="utf-8")
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports, create=True),
                patch.object(self.server.secrets, "token_urlsafe", return_value="C" * 32),
            ):
                response = asyncio.run(self.server.retest_report(bid, cid))
                html = ""
                report = reports / ("C" * 32 + ".html")
                if report.exists():
                    html = report.read_text(encoding="utf-8")
                return response, html

    def test_tool_renders_closure_free_html(self):
        base = _doc(findings=[_port("port-80-tcp"), _port("port-443-tcp")], captured_at=B_AT)
        cur = _doc(findings=[_port("port-80-tcp")], captured_at=C_AT)
        response, html = self._run(base, cur)
        self.assertEqual("/reports/" + "C" * 32 + ".html", response)
        low = html.lower()
        # honest phrasing present; explicit non-certification present
        self.assertIn("not observed on re-test", low)
        self.assertIn("does not certify remediation", low)
        # never an AFFIRMATIVE closure CLAIM (the disclaimer's negative use of
        # "fixed/closed/remediated" is required and allowed).
        for banned in ("verified closed", "confirmed fixed", "confirmed remediated",
                       "successfully remediated", "has been fixed", "now closed"):
            self.assertNotIn(banned, low)

    def test_empty_baseline_refuses(self):
        base = _doc(findings=[], captured_at=B_AT)
        cur = _doc(findings=[_port("port-80-tcp")], captured_at=C_AT)
        response, _ = self._run(base, cur)
        self.assertIn("No baseline findings", response)

    def test_missing_ref_errors(self):
        import asyncio
        self.assertTrue(asyncio.run(self.server.retest_report("", "")).startswith("❌"))


if __name__ == "__main__":
    unittest.main()
