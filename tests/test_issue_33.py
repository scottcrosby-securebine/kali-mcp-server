"""#33 secondary: nmap_port_scan must accept a bare target (no ports)."""

import asyncio
import unittest
from unittest.mock import patch

from server_test_support import load_server


class NmapPortScanBareTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def scan(self, *args):
        """Run nmap_port_scan with the process and capture seams stubbed out."""
        seen = []

        def fake_run(cmd, timeout=None, **kwargs):
            seen.append(list(cmd))
            return "nmap text output"

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_capture_findings", lambda *a, **k: None),
        ):
            output = asyncio.run(self.server.nmap_port_scan(*args))
        return output, (seen[0] if seen else [])

    def test_bare_target_scans_the_top_100_ports_like_its_siblings(self):
        for ports in ((), ("",), ("   ",)):
            with self.subTest(ports=ports):
                output, cmd = self.scan("10.0.0.1", *ports)
                self.assertEqual("nmap text output", output)
                self.assertNotIn("❌", output)
                self.assertEqual(["nmap", "--unprivileged", "-sT", "-Pn", "--top-ports=100"], cmd[:5])
                self.assertNotIn("-p", cmd)
                self.assertEqual(["-oX", cmd[6], "--", "10.0.0.1"], cmd[5:])

    def test_explicit_ports_are_unchanged(self):
        output, cmd = self.scan("10.0.0.1", " 22,80,443 ")
        self.assertEqual("nmap text output", output)
        self.assertEqual(["nmap", "--unprivileged", "-sT", "-Pn", "-p", "22,80,443"], cmd[:6])
        self.assertNotIn("--top-ports=100", cmd)
        self.assertEqual(["-oX", cmd[7], "--", "10.0.0.1"], cmd[6:])

    def test_an_empty_target_is_still_rejected_without_running_anything(self):
        output, cmd = self.scan("", "80")
        self.assertEqual([], cmd)
        self.assertIn("❌", output)
