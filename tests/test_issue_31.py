"""#31: a non-zero exit must report as a failure, not as warnings.

Under D1 the operator-visible text is authorized to change for FAILING runs
only. Exit 0 stays byte-identical, so the exit-0 expectations below are the
literal strings the pre-change `run_command` produced, transcribed from
35d7a50 rather than recomputed from the new code.
"""

import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_test_support import load_server


class RunCommandStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_command(self, returncode=0, stdout="", stderr="", **kwargs):
        """Drive run_command at the execute_command seam, never a real binary."""
        completed = subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)
        with patch.object(self.server, "execute_command", return_value=completed):
            return self.server.run_command(["/bin/true"], **kwargs)

    def test_non_zero_exit_reports_a_failure_not_a_warning(self):
        # The three cases observed in the field. Every one of them reported as
        # "Scan completed with warnings", a success-adjacent state, while the
        # scan had in fact never run.
        cases = {
            "testssl": (245, "", "Fatal error: URI comes last"),
            "amass": (1, "", 'sudo: The "no new privileges" flag is set'),
            "smbclient": (1, "", "do_connect: Connection to 10.0.0.5 failed (NT_STATUS_IO_TIMEOUT)"),
        }
        for tool, (code, out, err) in cases.items():
            with self.subTest(tool=tool):
                response = self.run_command(returncode=code, stdout=out, stderr=err)
                self.assertTrue(response.startswith("❌"), response)
                self.assertNotIn("⚠️", response)
                self.assertNotIn("completed successfully", response)
                self.assertIn(str(code), response)
                self.assertIn(err, response)

    def test_non_zero_exit_with_no_output_names_the_exit_code(self):
        self.assertEqual("❌ Command failed with exit code 3", self.run_command(returncode=3))

    def test_exit_zero_output_is_byte_identical(self):
        body = "\n".join(f"line{index}" for index in range(250))
        cases = {
            # (stdout, stderr, kwargs) -> the exact 35d7a50 return value.
            "plain": (("Nmap scan report\n", "", {}), "✅ Scan completed successfully:\n\nNmap scan report\n"),
            # Exit 0 with stderr is a SUCCESS today and stays one: promoting it
            # to a warning banner would change exit-0 text (and _workflow_check
            # reads ⚠️ as a failed stage, so every noisy-but-clean scan would
            # start failing its combined report).
            "stderr on success": ((
                "Nmap scan report\n", "Warning: giving up on port\n", {}),
                "✅ Scan completed successfully:\n\nNmap scan report\nWarning: giving up on port\n"),
            "only stderr": (("", "Warning: giving up on port\n", {}),
                            "✅ Scan completed successfully:\n\nWarning: giving up on port\n"),
            "no output": (("", "", {}), "✅ Command completed successfully (no output)"),
            "whitespace only": ((" \n\t", "", {}), "✅ Command completed successfully (no output)"),
            "truncated": ((body, "", {}),
                          "✅ Scan completed successfully:\n\n"
                          + "\n".join(f"line{index}" for index in range(200))
                          + "\n\n... (truncated 50 additional lines)"),
            "stripped announcement": ((
                "Doing scan\n\nSaving records to JSON file: /tmp/x.json\ndone\n", "",
                {"strip_containing": ("/tmp/x.json",), "strip_leading_blank": True}),
                "✅ Scan completed successfully:\n\nDoing scan\ndone\n"),
        }
        for label, ((stdout, stderr, kwargs), expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(expected, self.run_command(stdout=stdout, stderr=stderr, **kwargs))


class CaptureStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def capture(self, returncode, stdout="", stderr=""):
        """Run the raw-text capture path and return (text, persisted document)."""
        completed = subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)
        written = []
        with (
            patch.object(self.server, "execute_command", return_value=completed),
            patch.object(self.server, "_write_scanner_result", lambda document: written.append(document) or "Z" * 32),
        ):
            text = self.server._run_with_capture(
                ["smbclient", "-L", "10.0.0.5"], "smbclient", "10.0.0.5", 60, None,
                self.server._raw_text_parser("smbclient", "10.0.0.5"))
        return text, (written[0] if written else None)

    def test_failed_run_is_persisted_as_failed_with_its_error_as_evidence(self):
        text, document = self.capture(1, stderr="do_connect: failed (NT_STATUS_IO_TIMEOUT)")
        self.assertTrue(text.startswith("❌"), text)
        self.assertEqual("failed", document["status"])
        # The reason the scan produced nothing is the whole value of the card:
        # a failed scanner with no findings and no evidence is what #31 is about.
        self.assertEqual(1, len(document["findings"]))
        self.assertIn("NT_STATUS_IO_TIMEOUT", document["findings"][0]["evidence"])

    def test_successful_run_is_still_persisted_as_success(self):
        text, document = self.capture(0, stdout="Sharename       Type\nADMIN$          Disk\n")
        self.assertTrue(text.startswith("✅"), text)
        self.assertEqual("success", document["status"])

    def test_raw_text_parser_keeps_a_failure_that_printed_and_drops_one_with_nothing(self):
        parse = self.server._raw_text_parser("smbclient", "10.0.0.5")
        # A non-zero exit that still printed is a real result; it used to arrive
        # under a ⚠️ banner and must not stop being captured now it arrives
        # under ❌.
        for text in ("❌ Scan failed (exit code 1):\n\ndo_connect: NT_STATUS_IO_TIMEOUT\n",
                     "⚠️ Scan completed with warnings:\n\nNo match for domain\n"):
            with self.subTest(kept=text[:24]):
                findings = parse(text)
                self.assertEqual(1, len(findings))
                self.assertIn(text.partition("\n\n")[2].strip(), findings[0]["evidence"])
        # A banner with nothing under it carries no evidence at all.
        for text in ("❌ Command failed with exit code 1",
                     "❌ Error: Command not found. Tool may not be installed: smbclient",
                     "✅ Command completed successfully (no output)",
                     "⏱️ Command timed out after 60 seconds."):
            with self.subTest(dropped=text[:24]):
                self.assertEqual([], parse(text))

    def test_report_does_not_count_a_failed_scan_as_successful_coverage(self):
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="do_connect: failed")
        with tempfile.TemporaryDirectory() as root:
            results, reports = Path(root) / "results", Path(root) / "reports"
            with (
                patch.object(self.server, "RESULTS_ROOT", results),
                patch.object(self.server, "REPORTS_ROOT", reports),
                patch.object(self.server, "execute_command", return_value=completed),
            ):
                self.server._run_with_capture(
                    ["smbclient", "-L", "10.0.0.5"], "smbclient", "10.0.0.5", 60, None,
                    self.server._raw_text_parser("smbclient", "10.0.0.5"))
                stored = json.loads(next(results.glob("*.json")).read_text(encoding="utf-8"))
                self.assertEqual("failed", stored["status"])
                asyncio.run(self.server.generate_report())
            html = next(reports.glob("*.html")).read_text(encoding="utf-8")
        # The combined report must not claim a clean run: the scan row reads
        # failed and the report status is no longer success.
        self.assertIn("<td>failed</td>", html)
        self.assertIn('<span class="v">partial</span>', html)


if __name__ == "__main__":
    unittest.main()
