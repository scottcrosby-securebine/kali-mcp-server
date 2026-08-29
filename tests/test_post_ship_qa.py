"""Post-ship QA batch: argv/status/arch seams for #75, #76, #77, #13.

Each argv test patches `execute_command` (the single subprocess seam) and
inspects the argument list the wrapper built. Status tests drive the real
`run_command`/`_run_with_capture` over a faked exit code.
"""

import asyncio
import platform
import subprocess
import unittest
from unittest.mock import patch

from server_test_support import load_server


def _capture(returncode=0, stdout="", stderr=""):
    """Return (calls, fake_execute_command). fake records every argv it saw."""
    calls = []

    def fake(cmd, timeout=None, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=returncode,
                                           stdout=stdout, stderr=stderr)

    return calls, fake


class TheHarvesterSourceTests(unittest.TestCase):
    """#75: the wrapper must not request the dropped google engine and must
    honor the source arg."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def argv_for(self, **kwargs):
        calls, fake = _capture(stdout="[*] Target: example.com\n")
        with patch.object(self.server, "execute_command", fake):
            asyncio.run(self.server.theharvester_scan(**kwargs))
        self.assertEqual(1, len(calls))
        return calls[0]

    def test_default_source_is_not_google(self):
        argv = self.argv_for(domain="example.com")
        self.assertNotIn("google", argv)
        self.assertIn("-b", argv)
        self.assertEqual("crtsh", argv[argv.index("-b") + 1])

    def test_source_arg_is_wired_through(self):
        argv = self.argv_for(domain="example.com", source="bing")
        self.assertEqual("bing", argv[argv.index("-b") + 1])

    def test_unsupported_source_falls_back_to_supported_default(self):
        for bad in ("all", "google", "linkedin", ""):
            with self.subTest(source=bad):
                argv = self.argv_for(domain="example.com", source=bad)
                self.assertEqual("crtsh", argv[argv.index("-b") + 1])


class AmassTimeoutTests(unittest.TestCase):
    """#76: amass must carry a bounded -timeout so it flushes before the wrapper
    cutoff, in both modes."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def argv_for(self, mode):
        calls, fake = _capture(stdout="www.example.com\n")
        with patch.object(self.server, "execute_command", fake):
            asyncio.run(self.server.amass_enum(domain="example.com", mode=mode))
        self.assertEqual(1, len(calls))
        return calls[0]

    def test_passive_has_bounded_timeout(self):
        argv = self.argv_for("passive")
        self.assertIn("-passive", argv)
        self.assertIn("-timeout", argv)
        minutes = int(argv[argv.index("-timeout") + 1])
        self.assertGreater(minutes, 0)
        self.assertLess(minutes * 60, self.server.TIMEOUT_LONG)

    def test_active_has_bounded_timeout(self):
        argv = self.argv_for("active")
        self.assertIn("-active", argv)
        self.assertIn("-timeout", argv)


class ExitCodeClassificationTests(unittest.TestCase):
    """#77: a tool's documented non-error exit code is a success; an arbitrary
    nonzero from a tool with no allowlist is still a failure."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_command_with(self, returncode, stdout, success_markers=()):
        _, fake = _capture(returncode=returncode, stdout=stdout)
        with patch.object(self.server, "execute_command", fake):
            return self.server.run_command(["tool"], success_markers=success_markers)

    WP_MARKER = ((4, "does not seem to be running WordPress"),)

    def test_nonzero_exit_with_its_marker_is_success(self):
        out = self.run_command_with(4, "the site does not seem to be running WordPress",
                                    success_markers=self.WP_MARKER)
        self.assertTrue(out.startswith("✅"), out)

    def test_nonzero_exit_without_its_marker_still_fails(self):
        # R1: exit 4 without the not-WP marker is a REAL wpscan failure, not a
        # valid negative -- content-gating must not relabel it success.
        out = self.run_command_with(4, "Fatal: could not resolve host",
                                    success_markers=self.WP_MARKER)
        self.assertTrue(out.startswith("❌"), out)

    def test_unmarked_nonzero_exit_still_fails(self):
        out = self.run_command_with(4, "real crash", success_markers=())
        self.assertTrue(out.startswith("❌"), out)

    def test_wpscan_not_wordpress_is_success(self):
        _, fake = _capture(returncode=4,
                           stdout="Scan Aborted: The remote website is up, but does not seem to be running WordPress")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.wpscan_scan(target="http://127.0.0.1/"))
        self.assertTrue(out.startswith("✅"), out)

    def test_wpscan_real_error_is_failure(self):
        # R1: a genuine wpscan exit-4 error (no not-WP marker) stays ❌.
        _, fake = _capture(returncode=4, stdout="The target seems to be down")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.wpscan_scan(target="http://127.0.0.1/"))
        self.assertTrue(out.startswith("❌"), out)

    def test_sslyze_cert_verdict_is_success(self):
        _, fake = _capture(returncode=1,
                           stdout="Compliance against TLS configuration\n ... FAILED")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.sslyze_scan(target="127.0.0.1", port="443"))
        self.assertTrue(out.startswith("✅"), out)

    def test_sslyze_incomplete_scan_is_failure(self):
        # R2: exit 1 from ServerScanResultIncomplete (no compliance banner) is a
        # real failure, not a verdict.
        _, fake = _capture(returncode=1, stdout="Could not connect to the server")
        with patch.object(self.server, "execute_command", fake):
            out = asyncio.run(self.server.sslyze_scan(target="127.0.0.1", port="443"))
        self.assertTrue(out.startswith("❌"), out)


class RuntimeArchTests(unittest.TestCase):
    """#13: report the real architecture, never a hard-coded Apple Silicon."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def test_arch_reports_real_machine(self):
        self.assertIn(platform.machine(), self.server._runtime_arch())

    def test_arch_never_claims_apple_silicon(self):
        self.assertNotIn("Apple", self.server._runtime_arch())
        self.assertNotIn("ARM64", self.server._runtime_arch())


if __name__ == "__main__":
    unittest.main()


class CombinedTrailerTests(unittest.TestCase):
    """#87: quick_recon / network_sweep must classify child status, not append a
    hard-coded ✅. Mirrors full_recon's ✅/⚠️/❌ tiers."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def _run(self, coro):
        return asyncio.run(coro)

    @staticmethod
    async def _fail(*a, **k):
        return "❌ Error: connection refused"

    @staticmethod
    async def _ok(*a, **k):
        return "✅ done"

    def _trailer(self, text):
        return text.strip().splitlines()[-2]

    def test_quick_recon_all_fail_is_error(self):
        s = self.server
        with patch.object(s, "nmap_scan", self._fail), \
             patch.object(s, "whatweb_scan", self._fail):
            out = self._run(s.quick_recon("10.0.0.1"))
        self.assertTrue(self._trailer(out).startswith("❌"), out)

    def test_quick_recon_mixed_is_warning(self):
        s = self.server
        with patch.object(s, "nmap_scan", self._fail), \
             patch.object(s, "whatweb_scan", self._ok), \
             patch.object(s, "whois_lookup", self._ok):
            out = self._run(s.quick_recon("example.com"))
        self.assertTrue(self._trailer(out).startswith("⚠️"), out)

    def test_quick_recon_all_pass_is_success(self):
        s = self.server
        with patch.object(s, "nmap_scan", self._ok), \
             patch.object(s, "whatweb_scan", self._ok), \
             patch.object(s, "whois_lookup", self._ok):
            out = self._run(s.quick_recon("example.com"))
        self.assertTrue(self._trailer(out).startswith("✅"), out)

    def test_network_sweep_all_fail_is_error(self):
        s = self.server
        with patch.object(s, "nmap_scan", self._fail), \
             patch.object(s, "nbtscan_scan", self._fail):
            out = self._run(s.network_sweep("10.0.0.0/24"))
        self.assertTrue(self._trailer(out).startswith("❌"), out)

    def test_network_sweep_mixed_is_warning(self):
        s = self.server
        with patch.object(s, "nmap_scan", self._ok), \
             patch.object(s, "nbtscan_scan", self._fail):
            out = self._run(s.network_sweep("10.0.0.0/24"))
        self.assertTrue(self._trailer(out).startswith("⚠️"), out)

    def test_network_sweep_all_pass_is_success(self):
        s = self.server
        with patch.object(s, "nmap_scan", self._ok), \
             patch.object(s, "nbtscan_scan", self._ok):
            out = self._run(s.network_sweep("10.0.0.0/24"))
        self.assertTrue(self._trailer(out).startswith("✅"), out)


class CompoundKeyRedactionTests(unittest.TestCase):
    """#98: the flat `key:value` path reuses the SECRET_KEY guard, so a key token
    that CONTAINS a secret keyword anywhere (compound key) redacts its value, exactly
    as the structured dict-key path already does. MUST_REMOVE = key contains a secret
    keyword (incl. the compound-key class the issue names); MUST_KEEP = key has no
    secret keyword. Paired corpus (issue asks for one)."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    MUST_REMOVE = (
        # compound-key class the issue names (keyword is a mid/prefix segment)
        "aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
        "AWS_SECRET_ACCESS_KEY=UPPERVAL1234567890",
        "api_key_value=abcdef123456",
        "secret_access_key=topsecretval",
        "app.secret.key=deadbeefcafe",
        "SECRET_KEY_BASE=abc123railssigningsecret",   # Rails master secret (red-team F1)
        "secret_id=b1c2d3e4-role-secret",             # Vault AppRole SecretID (red-team F1)
        "secret_hash=BASE64HASHVALUE==",              # AWS Cognito SecretHash (red-team F1)
        "api_key_prefix=live_abc",
        "db_password_hash=argon2hash",
        # red-team round 2 F1: a secret keyword >64 chars deep in a dotted/namespaced
        # key must still redact (no prefix-length ceiling -- keyword matched anywhere)
        "spring.datasource.hikari.data-source-properties.deep.nested.path.secret=hunter2SECRETVAL",
        "com.example.service.integration.thirdparty.oauth.client.credentials.token=SECRETTOKENVAL",
        # keyword already adjacent to the separator (regressions)
        "db_password=hunter2",
        "admin_password=p@ssw0rd",
        "session=abc123def456",
    )
    MUST_KEEP = (
        # no secret keyword anywhere in the key token -> value intact
        "content_length=1234",
        "retry_count=2",
        "max_connections=10",
        "status_code=200",
        "request_id=abc-123",
        "build_number=42",
        "error_code=500",
        "access_key_id=AKIAIOSFODNN7EXAMPLE",   # public AWS key id: no 'secret'/'api_key' substring
    )

    def test_must_remove(self):
        red = self.server._redact_scanner_data
        for payload in self.MUST_REMOVE:
            with self.subTest(payload=payload):
                self.assertIn("[REDACTED]", red(payload))

    def test_must_keep(self):
        red = self.server._redact_scanner_data
        for payload in self.MUST_KEEP:
            with self.subTest(payload=payload):
                self.assertNotIn("[REDACTED]", red(payload))
