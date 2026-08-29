"""Phase 2 QA batch: #80 (ANSI/control-byte strip), #81 (false-success demotion),
#82 (SSL host:port parsing), #83 (web_audit host extraction), #73 (nmap bound)."""

import asyncio
import subprocess
import unittest
from unittest.mock import patch

from server_test_support import load_server


def _capture(returncode=0, stdout="", stderr=""):
    calls = []

    def fake(cmd, timeout=None, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=returncode,
                                           stdout=stdout, stderr=stderr)

    return calls, fake


class ControlByteStripTests(unittest.TestCase):
    """#80: terminal escape / C0-C1 bytes must not reach output or the report."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_output(self, stdout):
        _, fake = _capture(stdout=stdout)
        with patch.object(self.server, "execute_command", fake):
            return self.server.run_command(["tool"])

    def test_ansi_and_control_bytes_removed_from_output(self):
        out = self.run_output("Server: Apache\x1b[2J\x1b]0;PWNED\x07 end\n")
        self.assertIn("Apache", out)
        self.assertIn("end", out)
        for bad in ("\x1b", "\x07", "PWNED", "[2J"):
            self.assertNotIn(bad, out)

    def test_osc8_hyperlink_escape_removed(self):
        out = self.run_output("link \x1b]8;;http://evil/\x07click\x1b]8;;\x07 here\n")
        self.assertNotIn("\x1b", out)
        self.assertIn("here", out)

    def test_tab_newline_preserved(self):
        out = self.run_output("a\tb\nc\n")
        self.assertIn("a\tb", out)

    def test_escape_split_secret_is_redacted_not_reassembled(self):
        # red-team: a secret split by an injected ESC must be reassembled and
        # redacted, never stripped back into plaintext (strip runs BEFORE redact).
        out = self.run_output("token is Bea\x1b[0mrer SECRETLEAK123 here\n")
        self.assertNotIn("SECRETLEAK123", out)

    def test_report_escape_strips_control_bytes(self):
        escaped = self.server._escape_report_data("x\x1b[31my\x07z")
        self.assertNotIn("\x1b", escaped)
        self.assertNotIn("\x07", escaped)
        self.assertIn("x", escaped)
        self.assertIn("z", escaped)


class FalseSuccessDemotionTests(unittest.TestCase):
    """#81: a tool that exits 0 but could not connect must read ❌, not ✅."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_with(self, returncode, stdout, failure_markers=()):
        _, fake = _capture(returncode=returncode, stdout=stdout)
        with patch.object(self.server, "execute_command", fake):
            return self.server.run_command(["tool"], failure_markers=failure_markers)

    def test_exit0_with_failure_marker_is_failure(self):
        out = self.run_with(0, "ERROR Opening: http://127.0.0.1:1 - Connection refused",
                            failure_markers=self.server._CONNECT_FAILURE_MARKERS)
        self.assertTrue(out.startswith("❌"), out)

    def test_exit0_clean_stays_success(self):
        out = self.run_with(0, "WordPress 6.4 detected on the target",
                            failure_markers=self.server._CONNECT_FAILURE_MARKERS)
        self.assertTrue(out.startswith("✅"), out)

    def test_whatweb_connection_refused_is_failure(self):
        _, fake = _capture(returncode=0, stdout="ERROR Opening: http://127.0.0.1:1 - Connection refused")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.whatweb_scan(target="http://127.0.0.1:1/"))
        self.assertTrue(out.startswith("❌"), out)

    def test_sslyze_rejected_connection_is_failure(self):
        _, fake = _capture(returncode=0, stdout="Server rejected the connection; discarding")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.sslyze_scan(target="127.0.0.1", port="1"))
        self.assertTrue(out.startswith("❌"), out)

    def test_marker_matching_is_case_insensitive(self):
        # whatweb's real error format, upper-cased.
        out = self.run_with(0, "ERROR OPENING: http://x/ - Connection refused",
                            failure_markers=self.server._CONNECT_FAILURE_MARKERS)
        self.assertTrue(out.startswith("❌"), out)

    def test_discarding_alone_no_longer_over_demotes(self):
        out = self.run_with(0, "discarding duplicate finding for host",
                            failure_markers=self.server._CONNECT_FAILURE_MARKERS)
        self.assertTrue(out.startswith("✅"), out)

    # Real captured failure lines (in-container) for the 5 wired tools.
    def test_real_tool_failure_lines_demote(self):
        cases = {
            "whatweb": "ERROR Opening: http://127.0.0.1:1/ - Connection refused - connect(2)",
            "wafw00f": "ERROR:wafw00f:Site 127.0.0.1 appears to be down",
            "nikto": "+ [FAIL] Unable to connect to 127.0.0.1:1.",
            "sslscan": "ERROR: Could not open a connection to host 127.0.0.1 (127.0.0.1) on port 1",
            "sslyze": "   127.0.0.1:1  => ERROR: Server rejected the connection; discarding scan.",
        }
        for tool, line in cases.items():
            with self.subTest(tool=tool):
                out = self.run_with(0, line, failure_markers=self.server._CONNECT_FAILURE_MARKERS)
                self.assertTrue(out.startswith("❌"), f"{tool}: {out}")

    def test_target_content_echoing_failure_phrase_stays_success(self):
        # RT2-B2 / RT3-B1: target-controlled page titles echoing a failure phrase
        # OR the tool's own error prefix must NOT demote a successful (200 OK) scan.
        for title in ("Connection refused", "ERROR Opening", "usage: help"):
            with self.subTest(title=title):
                _, fake = _capture(returncode=0,
                                   stdout=f"http://host [200 OK] Title[{title}], Country[US]")
                with patch.object(self.server, "execute_command", fake):
                    out = asyncio.run(self.server.whatweb_scan(target="http://host/"))
                self.assertTrue(out.startswith("✅"), out)

    def test_sslscan_usage_banner_is_failure(self):
        # F8 guard: an exit-0 usage/help banner reads ❌.
        _, fake = _capture(returncode=0,
                           stdout="Usage: sslscan [Options] [host:port | host]\n  --help  Display the help text you are now reading")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.sslscan_scan(target="127.0.0.1"))
        self.assertTrue(out.startswith("❌"), out)


class TargetHostPortTests(unittest.TestCase):
    """#82: build host:port once, never double-append a port."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_parsing(self):
        cases = [
            ("127.0.0.1", "443", "127.0.0.1:443"),
            ("127.0.0.1:8099", "443", "127.0.0.1:8099"),   # embedded port wins
            ("[::1]:80", "443", "[::1]:80"),
            ("::1", "443", "[::1]:443"),                    # bare IPv6 bracketed
            ("2001:db8::1", "443", "[2001:db8::1]:443"),    # full bare IPv6 (red-team)
            ("https://host/path", "443", "host:443"),        # scheme + path dropped
            ("https://user:pass@host:8443/x", "443", "host:8443"),  # userinfo dropped
            ("host", "22", "host:22"),
        ]
        for target, default, expected in cases:
            with self.subTest(target=target):
                self.assertEqual(expected, self.server._target_host_port(target, default))

    def test_sslscan_does_not_double_append_port(self):
        calls, fake = _capture(stdout="Testing SSL server")
        with patch.object(self.server, "execute_command", fake):
            asyncio.run(self.server.sslscan_scan(target="127.0.0.1:8099"))
        argv = calls[0]
        self.assertIn("127.0.0.1:8099", argv)
        self.assertNotIn("127.0.0.1:8099:443", argv)
        # #72: options must precede the target or sslscan prints usage and exits 0.
        self.assertEqual("127.0.0.1:8099", argv[-1])
        self.assertTrue(any(a.startswith("--xml=") for a in argv[:-1]))


class WebAuditHostExtractionTests(unittest.TestCase):
    """#83: web_audit's TLS stage must scan the real host, not the userinfo."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_userinfo_url_scans_the_host_not_the_username(self):
        seen = {}

        async def noop(*a, **k):
            return "✅ ok"

        async def record_sslscan(host, port="443", *a, **k):
            seen["host"] = host
            seen["port"] = port
            return "✅ ok"

        async def dedup(urls):
            return list(urls)

        with (
            patch.object(self.server, "whatweb_scan", noop),
            patch.object(self.server, "wafw00f_scan", noop),
            patch.object(self.server, "web_headers", noop),
            patch.object(self.server, "nuclei_scan", noop),
            patch.object(self.server, "nikto_scan", noop),
            patch.object(self.server, "_deduplicate_url_inventory", dedup),
            patch.object(self.server, "sslscan_scan", record_sslscan),
        ):
            asyncio.run(self.server.web_audit(target="https://user:pass@127.0.0.1/"))
        self.assertEqual("127.0.0.1", seen.get("host"))


class NmapHostTimeoutTests(unittest.TestCase):
    """#73: nmap_service_scan must bound its own runtime."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_host_timeout_present_and_bounded(self):
        calls, fake = _capture(stdout="80/tcp open http\n")
        with patch.object(self.server, "execute_command", fake):
            asyncio.run(self.server.nmap_service_scan(target="127.0.0.1"))
        argv = calls[0]
        self.assertIn("--host-timeout", argv)
        value = argv[argv.index("--host-timeout") + 1]
        self.assertTrue(value.endswith("s"), value)
        self.assertLess(int(value[:-1]), self.server.TIMEOUT_LONG)


if __name__ == "__main__":
    unittest.main()
