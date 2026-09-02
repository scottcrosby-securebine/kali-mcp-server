"""Phase 1 (#91 P3d): provenance capture on persisted scan results.

The re-test/delta report's comparability gate needs, per captured result:
`captured_at` (ordering), `argv` (scope comparison). These tests pin that the
capture path records both, redacts argv, and stays backward-compatible and
failure-safe (capture must NEVER break a completed scan)."""
import asyncio
import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server_test_support import load_server


class ProvenanceCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _write(self, document):
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            results.mkdir()
            with patch.object(self.server, "RESULTS_ROOT", results):
                rid = self.server._write_scanner_result(document)
                return json.loads((results / f"{rid}.json").read_text(encoding="utf-8"))

    def test_write_injects_iso8601_utc_captured_at(self):
        doc = self._write({"schema_version": 1, "scanner": "nmap",
                            "status": "success", "findings": []})
        self.assertIn("captured_at", doc)
        parsed = datetime.datetime.fromisoformat(doc["captured_at"])
        self.assertIsNotNone(parsed.tzinfo, "captured_at must be timezone-aware")

    def test_write_respects_explicit_captured_at(self):
        stamp = "2020-01-02T03:04:05+00:00"
        doc = self._write({"schema_version": 1, "scanner": "nmap",
                            "status": "success", "findings": [],
                            "captured_at": stamp})
        self.assertEqual(stamp, doc["captured_at"])

    def test_capture_threads_redacted_argv(self):
        argv = ["nmap", "-sT", "-Pn", "https://user:s3cr3t@example.com/"]
        captured = {}
        with patch.object(self.server, "_write_scanner_result",
                          side_effect=lambda d: captured.update(d) or "R" * 32):
            self.server._capture_findings("nmap", "example.com",
                                          lambda _t: [], "output", "success",
                                          argv=argv)
        self.assertIn("argv", captured)
        expected = [self.server._redact_scanner_data(tok) for tok in argv]
        self.assertEqual(expected, captured["argv"])
        # the credential must not survive verbatim in stored argv
        self.assertNotIn("s3cr3t", json.dumps(captured["argv"]))

    def test_capture_without_argv_omits_or_nulls_it(self):
        captured = {}
        with patch.object(self.server, "_write_scanner_result",
                          side_effect=lambda d: captured.update(d) or "R" * 32):
            self.server._capture_findings("nmap", "example.com",
                                          lambda _t: [], "output", "success")
        self.assertIsNone(captured.get("argv"))

    def test_loader_tolerates_pre_provenance_documents(self):
        # A baseline captured before this change has no captured_at/argv; it must
        # still load (so the gate can down-rank it to UNKNOWN, not crash).
        legacy = {"schema_version": 1, "scanner": "nmap", "status": "success",
                  "findings": [], "target_ref": "h"}
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            results.mkdir()
            (results / f"{'C' * 32}.json").write_text(json.dumps(legacy), encoding="utf-8")
            with patch.object(self.server, "RESULTS_ROOT", results):
                loaded = self.server._load_normalized_results()
        self.assertEqual(1, len(loaded))
        self.assertNotIn("captured_at", loaded[0][1])

    def test_capture_still_swallows_on_parser_failure(self):
        def boom(_text):
            raise ValueError("parser blew up")
        with tempfile.TemporaryDirectory() as root_text:
            results = Path(root_text) / "results"
            results.mkdir()
            with patch.object(self.server, "RESULTS_ROOT", results):
                # must not raise
                self.server._capture_findings("nmap", "h", boom, "t", "success",
                                              argv=["nmap", "h"])
                self.assertEqual([], list(results.iterdir()))


if __name__ == "__main__":
    unittest.main()
