"""Regressions found by the wave-1 red team and standards/spec review.

Each test here maps to a finding that a green 184-test suite did not catch.
"""

import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server_test_support import load_server


class WebHeadersSchemeGateTests(unittest.TestCase):
    """B-1: `"://" in target` let curl speak any protocol it supports."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def url_for(self, target):
        seen = []

        def fake_run(cmd, timeout=None, **kwargs):
            seen.append(list(cmd))
            return "text"

        with patch.object(self.server, "run_command", fake_run):
            asyncio.run(self.server.web_headers(target))
        return seen[0][-1]

    def test_a_non_http_scheme_never_reaches_curl_verbatim(self):
        # curl in this image speaks file, gopher, telnet, dict, smtp and more,
        # and the launcher runs --network=host. A header audit must not become
        # a file-metadata oracle or a raw-TCP write primitive.
        for target in ("file:///etc/shadow", "gopher://127.0.0.1:11211/_x",
                       "telnet://10.0.0.1:23", "dict://127.0.0.1:2628/x",
                       "ftp://10.0.0.1/", "scp://10.0.0.1/etc/passwd"):
            with self.subTest(target=target):
                url = self.url_for(target)
                self.assertTrue(url.startswith(("http://", "https://")), url)
                self.assertNotEqual(target, url)

    def test_a_scheme_inside_a_path_does_not_skip_the_scheme_logic(self):
        self.assertEqual("https://example.com/r?u=https://x",
                         self.url_for("example.com/r?u=https://x"))

    def test_an_explicit_http_prefix_is_still_honoured_unchanged(self):
        for target in ("http://example.com", "https://example.com",
                       "http://example.com:8443/p"):
            with self.subTest(target=target):
                self.assertEqual(target, self.url_for(target))


class FuzzTargetPlacementTests(unittest.TestCase):
    """F1: /FUZZ was appended after the query, so ffuf fuzzed the query value."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_fuzz_lands_in_the_path_not_after_the_query(self):
        cases = {
            "http://x/app?q=1": "http://x/app/FUZZ?q=1",
            "http://x?q=1": "http://x/FUZZ?q=1",
            "x?q=1": "http://x/FUZZ?q=1",
            "http://x/app#frag": "http://x/app/FUZZ#frag",
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(expected, self.server._fuzz_target(target))

    def test_ordinary_targets_are_unchanged_by_the_fix(self):
        cases = {
            "example.com": "http://example.com/FUZZ",
            "http://x/app/": "http://x/app/FUZZ",
            "https://x/a/b": "https://x/a/b/FUZZ",
            "http://x/s?q=FUZZ": "http://x/s?q=FUZZ",
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(expected, self.server._fuzz_target(target))


class NucleiCounterAndBannerTests(unittest.TestCase):
    """N-1 and N-2: a false refusal, and a stripper that ate real errors."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def count(self, body, severities):
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            (root / "t.yaml").write_text(body, encoding="utf-8")
            return self.server._nuclei_template_match(root, severities)

    def test_an_ambiguous_severity_is_undeterminable_not_a_refusal(self):
        # A `severity:` inside a description block matched first and produced a
        # WRONG count, refusing a scan the promoted set actually covers.
        ambiguous = ("info:\n  description: |\n    Upstream severity:\n"
                     "    severity: critical\n  severity: low\n")
        self.assertIsNone(self.count(ambiguous, "low"))

    def test_the_severity_pattern_does_not_match_across_a_newline(self):
        # `\s` matches newlines, so `\s{1,4}` reached a column-0 key below.
        self.assertIsNone(self.count("id: b\n\nseverity: critical\n", "critical"))

    def test_an_unambiguous_template_still_counts(self):
        self.assertEqual((1, 1), self.count("id: a\ninfo:\n  severity: high\n", "critical,high"))
        self.assertEqual((0, 1), self.count("id: a\ninfo:\n  severity: high\n", "info"))

    def test_a_real_error_ending_in_the_vendor_domain_survives(self):
        message = "[FTL] Invalid API key, get one at https://cloud.projectdiscovery.io"
        self.assertIn("Invalid API key", self.server._strip_nuclei_banner(message))

    def test_the_bare_banner_domain_line_is_still_dropped(self):
        self.assertEqual("", self.server._strip_nuclei_banner("                projectdiscovery.io"))

    def test_a_real_message_on_stdout_survives_a_banner_only_stderr(self):
        banner = "   ____  __  _______/ /__  (_)\n                projectdiscovery.io\n"
        completed = SimpleNamespace(returncode=1, stdout="[FTL] real failure here", stderr=banner)
        with patch.object(self.server, "execute_command", return_value=completed):
            outcome = self.server._run_nuclei_capture(["nuclei"])
        self.assertIn("real failure here", outcome["error"])


if __name__ == "__main__":
    unittest.main()
