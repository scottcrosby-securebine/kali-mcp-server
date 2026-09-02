"""N1 (red-team, 2026-09-02): the #73 unbounded-runtime fix landed on
nmap_service_scan ONLY. The other three -sV scanners run NSE scripts (slower,
so MORE exposed to the same failure) with no --host-timeout, so on a slow or
filtered target nmap is SIGKILLed by the wrapper before it flushes XML and the
capture persists zero findings.

Class fix: every -sV builder carries --host-timeout, sized under its wrapper
timeout so nmap self-terminates and emits partial XML first.
"""

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


class NmapServiceVersionHostTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def argv_for(self, coro):
        calls, fake = _capture(stdout="<nmaprun></nmaprun>")
        with patch.object(self.server, "execute_command", fake):
            asyncio.run(coro)
        self.assertEqual(1, len(calls))
        return calls[0]

    def _assert_bounded(self, argv):
        self.assertIn("-sV", argv)
        self.assertIn("--host-timeout", argv, f"-sV scan missing --host-timeout: {argv}")
        value = argv[argv.index("--host-timeout") + 1]
        self.assertTrue(value.endswith("s"), value)
        self.assertGreater(int(value[:-1]), 0)
        # Bound must sit under the wrapper timeout so nmap flushes first.
        self.assertLess(int(value[:-1]), self.server.TIMEOUT_EXTRA_LONG)

    def test_vuln_scan_bounded(self):
        self._assert_bounded(self.argv_for(self.server.nmap_vuln_scan(target="scanme.example")))

    def test_comprehensive_scan_bounded(self):
        self._assert_bounded(self.argv_for(self.server.nmap_comprehensive_scan(target="scanme.example")))

    def test_script_scan_bounded(self):
        self._assert_bounded(self.argv_for(self.server.nmap_script_scan(target="scanme.example")))

    def test_service_scan_still_bounded(self):
        # The originally-fixed #73 tool must stay bounded.
        argv = self.argv_for(self.server.nmap_service_scan(target="scanme.example"))
        self.assertIn("--host-timeout", argv)


if __name__ == "__main__":
    unittest.main()
