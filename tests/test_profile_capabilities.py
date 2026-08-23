import asyncio
import os
import unittest
from unittest.mock import patch

from server_test_support import load_server


server, _mcp = load_server()


class ProfileCapabilityTests(unittest.TestCase):
    def test_fixed_category_nmap_wrappers_exclude_broadcast_scripts(self):
        cases = (
            (server.nmap_vuln_scan, "(vuln)"),
            (server.nmap_comprehensive_scan, "(default)"),
        )
        for wrapper, requested_selector in cases:
            with self.subTest(wrapper=wrapper.__name__), patch.object(server, "run_command", return_value="ok") as run_command:
                result = asyncio.run(wrapper("192.0.2.1"))
                self.assertEqual("ok", result)
                selector = next(value for value in run_command.call_args.args[0] if value.startswith("--script="))
                self.assertIn(requested_selector, selector)
                self.assertIn("not broadcast", selector)
                self.assertIn("--unprivileged", run_command.call_args.args[0])

    def test_broadcast_nse_category_fails_before_command_execution(self):
        for profile in ("linux-full", "linux-hardened", "mac-hardened"):
            with (
                self.subTest(profile=profile),
                patch.dict(os.environ, {"KALI_MCP_PROFILE": profile}),
                patch.object(server, "run_command") as run_command,
            ):
                result = asyncio.run(server.nmap_script_scan("192.0.2.1", "safe,broadcast"))
                self.assertEqual(
                    f"capability_missing: nmap_script_scan requires raw/link-layer networking in profile '{profile}'",
                    result,
                )
                run_command.assert_not_called()

    def test_broadcast_selector_bypasses_are_rejected_before_execution(self):
        selectors = (
            "broadcast*",
            "broadcast or safe",
            "broadcast and safe",
            "broadcast-dhcp-discover",
            "/usr/share/nmap/scripts/broadcast-dhcp-discover.nse",
        )
        for selector in selectors:
            with self.subTest(selector=selector), patch.object(server, "run_command") as run_command:
                result = asyncio.run(server.nmap_script_scan("192.0.2.1", selector))
                self.assertTrue(result.startswith("❌ Error: Unsupported NSE script category"))
                run_command.assert_not_called()

    def test_documented_comma_separated_categories_still_execute(self):
        with patch.object(server, "run_command", return_value="ok") as run_command:
            result = asyncio.run(server.nmap_script_scan("192.0.2.1", "safe,discovery"))
            self.assertEqual("ok", result)
            selector = next(value for value in run_command.call_args.args[0] if value.startswith("--script="))
            self.assertIn("--script=(safe or discovery) and not broadcast", selector)
            self.assertIn("--unprivileged", run_command.call_args.args[0])

    def test_every_allowed_category_excludes_overlapping_broadcast_scripts(self):
        allowed = ("default", "safe", "discovery", "auth", "vuln", "exploit", "intrusive", "malware")
        for category in allowed:
            with self.subTest(category=category), patch.object(server, "run_command", return_value="ok") as run_command:
                asyncio.run(server.nmap_script_scan("192.0.2.1", category))
                command = run_command.call_args.args[0]
                selector = next(value for value in command if value.startswith("--script="))
                self.assertIn(f"--script=({category}) and not broadcast", selector)
                self.assertIn("--unprivileged", command)

    def test_every_nmap_wrapper_forces_unprivileged_mode(self):
        cases = (
            (server.nmap_scan, ("192.0.2.1",)),
            (server.nmap_service_scan, ("192.0.2.1",)),
            (server.nmap_vuln_scan, ("192.0.2.1",)),
            (server.nmap_comprehensive_scan, ("192.0.2.1",)),
            (server.nmap_port_scan, ("192.0.2.1", "443")),
            (server.nmap_script_scan, ("192.0.2.1", "safe")),
        )
        for wrapper, arguments in cases:
            with self.subTest(wrapper=wrapper.__name__), patch.object(server, "run_command", return_value="ok") as run_command:
                asyncio.run(wrapper(*arguments))
                command = run_command.call_args.args[0]
                self.assertIn("--unprivileged", command)
                self.assertEqual("--", command[-2])
                self.assertEqual("192.0.2.1", command[-1])


if __name__ == "__main__":
    unittest.main()
