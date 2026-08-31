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

    def test_invisible_unicode_split_secret_is_redacted_not_leaked(self):
        # red-team: a secret keyword split by an INVISIBLE unicode char (not just
        # an ESC/C0/C1 byte) must be reassembled and redacted. ZWSP/ZWNJ/word-
        # joiner/BOM/soft-hyphen/NBSP all split a keyword so SECRET_KEY misses.
        # cover the whole invisible/format CLASS, not just an enum: Cf (ZW*, bidi
        # incl. U+061C, word-joiner, BOM, soft-hyphen, TAG) + default-ignorable
        # non-Cf strays (NBSP, combining grapheme joiner, variation selectors).
        for name, sep in [("ZWSP", "\u200b"), ("ZWNJ", "\u200c"),
                          ("word-joiner", "\u2060"), ("BOM", "\ufeff"),
                          ("soft-hyphen", "\u00ad"), ("NBSP", "\u00a0"),
                          ("ALM-U+061C", "\u061c"), ("TAG-r", "\U000e0072"),
                          ("var-selector", "\ufe0f"), ("CGJ", "\u034f"),
                          # non-Cf default-ignorables (DI, not category Cf)
                          ("Hangul-filler", "\u115f"), ("Mongolian-FVS", "\u180b"),
                          ("reserved-2065", "\u2065"), ("Khmer", "\u17b4")]:
            with self.subTest(sep=name):
                payload = f"authorization: Bea{sep}rer SECRETLEAK123"
                out = self.server._redact_scanner_data(payload)
                self.assertNotIn("SECRETLEAK123", out, f"{name} split leaked")
        # a keyword split by an INVISIBLE (zero-width) char still reassembles and
        # redacts. (A keyword split by NBSP renders as a visible space -> that is the
        # out-of-scope visible-split class; NBSP is folded to a space, not deleted.)
        self.assertNotIn("SECRETLEAK123",
                         self.server._redact_scanner_data("pass\u200bword: SECRETLEAK123"))

    def test_nikto_pattern_no_quadratic_redos(self):
        # red-team: an unbounded gap before 'contents' made SECRET_VALUE_PATTERNS'
        # nikto rule O(n^2) on target-reflected content (many quoted secret keywords,
        # no colon). The gap is bounded {0,120} now -> linear. A 200KB pathological
        # input finished in ~19s before the bound, ~0.2s after; 2s guards regression.
        import time
        # Two O(n^2) sources lived in this one pattern; each shape pins a different
        # bound, and each is sized so the UNBOUNDED version blows past 2s (verified
        # by reverting each bound: many-quotes/200KB -> ~19s on an unbounded gap;
        # unterminated/820KB -> ~13s on unbounded quoted-name spans), while the
        # bounded version stays <1s. Undersizing is why the first cut of this test
        # passed on the vulnerable code (green-gate-is-not-a-proving-gate).
        #   many-quotes (closing quote every 8 chars) pins the name->contents gap {0,120}
        #   unterminated / keyword-dense pins the quoted-name spans {0,200}
        for label, payload in (
            ("gap {0,120}", "'token' " * (200 * 1024 // 8)),
            ("span {0,200}", "'" + "authorization" * (820 * 1024 // 13)),
        ):
            with self.subTest(shape=label):
                start = time.time()
                self.server._redact_scanner_data(payload)
                self.assertLess(time.time() - start, 2.0, f"nikto pattern quadratic: {label}")

    def test_whitespace_separator_folded_not_deleted(self):
        # red-team B1: a keyword/value separator that is NBSP/NEL/a C0-C1 control /
        # a unicode space must be FOLDED to a space, not deleted -- deleting it fused
        # 'Bearer<sep>token' so bearer\\s+ matched nothing and the token leaked.
        for sep in ("\u00a0", "\x85", "\x1c", "\u2028", "\u202f", "\x0b"):
            with self.subTest(sep=hex(ord(sep))):
                out = self.server._redact_scanner_data(f"Bearer{sep}AKIALEAK123")
                self.assertNotIn("AKIALEAK123", out, f"sep U+{ord(sep):04X} leaked")
        self.assertNotIn("YWxhZGRpbjpvcGVu",
                         self.server._redact_scanner_data("Basic\u00a0YWxhZGRpbjpvcGVu"))

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

    def test_colon_heavy_non_ipv6_target_does_not_raise(self):
        # red-team regression: bracketing any >=2-colon token sent a malformed
        # host (ex.com:22:99) into a urlsplit ValueError. Only a real IPv6 literal
        # is bracketed now, so a bad host degrades gracefully instead of crashing.
        for t in ("ex.com:22:99", "a:b:c:d", "host:1:2:3:4"):
            with self.subTest(target=t):
                self.assertIsInstance(self.server._target_host_port(t, "443"), str)

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


class PemRedosTests(unittest.TestCase):
    """#96: the PEM private-key redaction pattern must be linear on unpaired openers."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_unpaired_pem_openers_stay_linear(self):
        import time
        # unbounded [\s\S]*? was O(n^2); bounded {0,20000} -> linear. Gate on the
        # SCALING RATIO, not an absolute wall-clock: a wall-clock bound is machine-
        # dependent and flaked on a slow CI runner (3.2s vs a 2.5s bound) while the
        # pattern was provably linear. Doubling the openers ~doubles a linear run
        # (ratio ~2) and ~quadruples a quadratic one (ratio ~4); 3.0 sits between.
        def elapsed(n):
            payload = "-----BEGIN PRIVATE KEY-----\n" * n
            self.server._redact_scanner_data(payload[:1])  # warm the regex cache
            start = time.time()
            self.server._redact_scanner_data(payload)
            return time.time() - start
        t1 = elapsed(2000)
        t2 = elapsed(4000)
        self.assertLess(t2, t1 * 3.0,
                        f"PEM pattern went superlinear: {t1:.3f}s -> {t2:.3f}s")

    def test_real_key_still_redacted(self):
        key = ("-----BEGIN PRIVATE KEY-----\n" + "MIIBVAIBADANBg" * 40
               + "\n-----END PRIVATE KEY-----")
        self.assertNotIn("MIIBVAIBADANBg", self.server._redact_scanner_data(key))


class SslDashTargetGuardTests(unittest.TestCase):
    """#97: SSL wrappers must reject a dash-flag target before it becomes a tool argv."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_dash_target_rejected(self):
        for fn in ("sslscan_scan", "sslyze_scan", "testssl_scan"):
            with self.subTest(tool=fn):
                out = asyncio.run(getattr(self.server, fn)(target="--xml=/tmp/x"))
                self.assertTrue(out.startswith("❌"), out)
                self.assertIn("must not begin with", out)

    def test_normal_target_not_rejected(self):
        # a legitimate host must still reach the tool across all three wrappers
        for fn in ("sslscan_scan", "sslyze_scan", "testssl_scan"):
            with self.subTest(tool=fn):
                calls, fake = _capture(stdout="Testing SSL")
                with patch.object(self.server, "execute_command", fake):
                    asyncio.run(getattr(self.server, fn)(target="example.com"))
                self.assertTrue(calls, f"{fn} guard wrongly rejected a normal target")

    def test_bracketed_non_ipv6_target_does_not_crash(self):
        # red-team: a bracketed non-IPv6 target ([foo]) crashed _target_host_port
        # with an uncaught ValueError; it must degrade to a string, not raise.
        for t in ("[foo]", "[example.com]", "[::g]"):
            with self.subTest(target=t):
                self.assertIsInstance(self.server._target_host_port(t, "443"), str)


if __name__ == "__main__":
    unittest.main()
