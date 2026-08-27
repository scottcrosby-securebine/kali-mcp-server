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


class FuzzTargetRobustnessTests(unittest.TestCase):
    """B2-1: the F1 repair made urlsplit reachable, and it raises."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_a_bracket_malformed_target_returns_a_string_and_does_not_raise(self):
        # urlsplit raises ValueError('Invalid IPv6 URL') on these. Every tool in
        # this file returns a str, and dirb/gobuster hand such a target to the
        # scanner to reject rather than blowing up.
        for target in ("http://[::1/", "x[y]z", "192.168.1.1[", "[", "http://]["):
            with self.subTest(target=target):
                self.assertIsInstance(self.server._fuzz_target(target), str)

    def test_a_malformed_target_is_handed_over_unchanged_not_rebuilt(self):
        # The fallback must NOT append /FUZZ: that was the pre-F1 shape and put
        # the placeholder after any query. ffuf's Go parser accepts a bracketed
        # host, so it would run and fuzz the query value.
        for target in ("http://[127.0.0.1]/app?q=1", "http://x[y]z.com/app?q=1"):
            with self.subTest(target=target):
                self.assertEqual(target, self.server._fuzz_target(target))

    def test_both_fuzzers_survive_a_malformed_target(self):
        import asyncio
        for tool in ("ffuf_scan", "wfuzz_scan"):
            for target in ("http://[::1/", "x[y]z"):
                with self.subTest(tool=tool, target=target):
                    with patch.object(self.server, "run_command", lambda *a, **k: "text"):
                        self.assertIsInstance(asyncio.run(getattr(self.server, tool)(target)), str)


class CurlProtocolPinningTests(unittest.TestCase):
    """N2-1/N2-2: the scheme gate only governs the FIRST request."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def argv_for(self, target):
        seen = []

        def fake_run(cmd, timeout=None, **kwargs):
            seen.append(list(cmd))
            return "text"

        with patch.object(self.server, "run_command", fake_run):
            asyncio.run(self.server.web_headers(target))
        return seen[0]

    def test_redirects_cannot_leave_http(self):
        # With -L an attacker-controlled 302 sends curl wherever libcurl can go;
        # an ftp:// redirect was observed attempting the connect, and the
        # launcher runs --network=host.
        argv = self.argv_for("example.com")
        self.assertIn("--proto", argv)
        self.assertIn("--proto-redir", argv)
        self.assertEqual("=http,https", argv[argv.index("--proto") + 1])
        self.assertEqual("=http,https", argv[argv.index("--proto-redir") + 1])

    def test_url_globbing_cannot_turn_one_audit_into_a_port_sweep(self):
        # "127.0.0.1:[1-65535]" is a curl RANGE without -g; one call fanned out
        # into separate connects, bounded only by TIMEOUT_SHORT, under
        # --network=host.
        self.assertIn("-g", self.argv_for("127.0.0.1:[18098-18100]"))

    def test_a_legal_uppercase_scheme_is_honoured_not_mangled(self):
        # RFC 3986 schemes are case-insensitive; HTTP://example.com is a legal
        # URL and used to become https://HTTP://example.com.
        for target in ("HTTP://example.com", "HtTpS://example.com", "HTTPS://example.com"):
            with self.subTest(target=target):
                self.assertEqual(target, self.argv_for(target)[-1])

    def test_a_smuggled_scheme_is_still_defanged(self):
        for target in ("file:///etc/shadow", "FILE:///etc/shadow", "gopher://127.0.0.1/x"):
            with self.subTest(target=target):
                self.assertTrue(self.argv_for(target)[-1].startswith("https://"))


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

    def test_an_empty_detail_names_the_exit_code(self):
        # Banner-only output strips to nothing, leaving "Nuclei scan failed: "
        # with nothing after the colon.
        completed = SimpleNamespace(returncode=7, stdout="", stderr="")
        with patch.object(self.server, "execute_command", return_value=completed):
            outcome = self.server._run_nuclei_capture(["nuclei"])
        self.assertIn("exit code 7", outcome["error"])

    def test_a_real_message_on_stdout_survives_a_banner_only_stderr(self):
        banner = "   ____  __  _______/ /__  (_)\n                projectdiscovery.io\n"
        completed = SimpleNamespace(returncode=1, stdout="[FTL] real failure here", stderr=banner)
        with patch.object(self.server, "execute_command", return_value=completed):
            outcome = self.server._run_nuclei_capture(["nuclei"])
        self.assertIn("real failure here", outcome["error"])


if __name__ == "__main__":
    unittest.main()
