"""Issue #34: a zero-template Nuclei selection must explain itself, not surface nuclei's FTL."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server_test_support import load_server


NUCLEI_BANNER = r"""
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.7

                projectdiscovery.io

[INF] Targets loaded for current scan: 1
[FTL] Could not run nuclei: no templates provided for scan
"""


class NucleiZeroTemplateSelectionTests(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def test_zero_template_selection_names_severity_and_set_size_without_running_nuclei(self):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            (root / "CVE-2021-41773.yaml").write_text(
                "id: CVE-2021-41773\ninfo:\n  severity: high\n", encoding="utf-8"
            )
            run = unittest.mock.MagicMock()
            with patch.object(self.server, "NUCLEI_PROMOTED_ROOT", root), patch.object(
                self.server, "execute_command", run
            ):
                result = asyncio.run(self.server.nuclei_scan("https://example.test", "", "info"))

        self.assertEqual(0, run.call_count)
        # Pin the whole clause: assertIn("1", result) passed on ANY digit
        # anywhere, so it stayed green with the count wrong.
        self.assertIn("severity 'info' matches 0 of the 1 promoted template(s)", result)
        self.assertNotIn("FTL", result)
        for art in ("/_/", "__,_", "projectdiscovery.io"):
            self.assertNotIn(art, result)

    def test_matching_severity_selection_is_unaffected(self):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            (root / "CVE-2021-41773.yaml").write_text(
                "id: CVE-2021-41773\ninfo:\n  severity: high\n", encoding="utf-8"
            )
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.object(self.server, "NUCLEI_PROMOTED_ROOT", root), patch.object(
                self.server, "execute_command", return_value=completed
            ) as run:
                result = asyncio.run(self.server.nuclei_scan("https://example.test", "", "high"))

        self.assertEqual(1, run.call_count)
        self.assertIn("completed", result)

    def test_undeterminable_template_severity_still_runs_the_scan(self):
        """A template whose severity cannot be read must not be guessed into a refusal."""
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            (root / "CVE-2021-41773.yaml").write_text("id: CVE-2021-41773\n", encoding="utf-8")
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.object(self.server, "NUCLEI_PROMOTED_ROOT", root), patch.object(
                self.server, "execute_command", return_value=completed
            ) as run:
                result = asyncio.run(self.server.nuclei_scan("https://example.test", "", "info"))

        self.assertEqual(1, run.call_count)
        self.assertIn("completed", result)

    def test_missing_promoted_root_still_runs_the_scan(self):
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(
            self.server, "NUCLEI_PROMOTED_ROOT", Path("/nonexistent/promoted")
        ), patch.object(self.server, "execute_command", return_value=completed) as run:
            result = asyncio.run(self.server.nuclei_scan("https://example.test", "", "info"))

        self.assertEqual(1, run.call_count)
        self.assertIn("completed", result)

    def test_banner_art_is_stripped_from_error_output(self):
        completed = SimpleNamespace(returncode=1, stdout="", stderr=NUCLEI_BANNER)
        with patch.object(self.server, "execute_command", return_value=completed):
            result = asyncio.run(self.server.nuclei_scan("https://example.test"))

        self.assertIn("Error", result)
        self.assertIn("no templates provided for scan", result)
        for art in ("/_/", "__,_", "____", "projectdiscovery.io"):
            self.assertNotIn(art, result)

    def test_nuclei_config_directory_is_created_before_the_run(self):
        with tempfile.TemporaryDirectory() as home_text:
            home = Path(home_text)
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.object(
                self.server, "_scanner_environment", return_value={"HOME": str(home)}
            ), patch.object(self.server, "execute_command", return_value=completed):
                asyncio.run(self.server.nuclei_scan("https://example.test"))

            self.assertTrue((home / ".config" / "nuclei").is_dir())


if __name__ == "__main__":
    unittest.main()
