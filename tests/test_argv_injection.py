"""#50, #42, #52: untrusted input must not reach a tool's argv as an option.

Every case patches the run_command / execute_command seam and asserts on the
built argv or the returned error. No binary is ever spawned.
"""

import asyncio
import os
import unittest
from unittest.mock import patch

from server_test_support import load_server


class LeadingDashGuardTests(unittest.TestCase):
    """#50 / #42: a positional target beginning with '-' is CWE-88 injection."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def call(self, tool, *args):
        """Run a tool with the process seam blocked; a spawn is a test failure."""
        spawned = []

        def fake_run(cmd, timeout=None, **kwargs):
            spawned.append(list(cmd))
            return "text"

        def fake_exec(cmd, timeout=None, **kwargs):
            spawned.append(list(cmd))
            raise AssertionError("execute_command must not run for a rejected input")

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "execute_command", fake_exec),
            patch.object(self.server, "_capture_findings", lambda *a, **k: None),
        ):
            out = asyncio.run(getattr(self.server, tool)(*args))
        return out, spawned

    # (tool, dash-leading args that must be rejected)
    DASH_CASES = [
        ("enum4linux_scan", ("--version",)),
        ("crackmapexec_scan", ("-U",)),
        ("searchsploit_search", ("-h",)),
        ("wfuzz_scan", ("-x/FUZZ",)),           # FUZZ present, still dash-led
        ("hydra_attack", ("-U", "ssh", "admin", "/etc/hostname")),
        ("dns_enum", ("-f/etc/hostname",)),   # dig -f<path> is batch-file mode
    ]

    def test_a_dash_leading_positional_is_rejected_and_spawns_nothing(self):
        for tool, args in self.DASH_CASES:
            with self.subTest(tool=tool):
                out, spawned = self.call(tool, *args)
                self.assertIn("must not begin with '-'", out)
                self.assertEqual([], spawned, f"{tool} spawned on a rejected input")

    def test_hash_file_tools_reject_a_dash_leading_path(self):
        # john/hashcat existence-check the file, but the guard makes the
        # rejection explicit rather than incidental. Patch exists True so the
        # guard, not the existence check, is what fires.
        with patch.object(self.server.os.path, "exists", return_value=True):
            for tool in ("john_crack", "hashcat_crack"):
                with self.subTest(tool=tool):
                    out, spawned = self.call(tool, "-config=/evil")
                    self.assertIn("must not begin with '-'", out)
                    self.assertEqual([], spawned)

    def test_a_normal_target_still_runs(self):
        for tool, args in [("enum4linux_scan", ("10.0.0.1",)),
                           ("crackmapexec_scan", ("10.0.0.1",)),
                           ("searchsploit_search", ("apache struts",))]:
            with self.subTest(tool=tool):
                out, spawned = self.call(tool, *args)
                self.assertEqual("text", out)
                self.assertEqual(1, len(spawned))
                self.assertEqual(args[0], spawned[0][-1])

    def test_metasploit_search_keeps_its_documented_dash_exemption(self):
        # A leading dash is msfconsole search syntax, not a process option; wave
        # 5 exempted it via guard_target=False. Centralizing the guard must not
        # regress that.
        captured = {}

        def fake_run(cmd, timeout=None, **kwargs):
            captured["cmd"] = list(cmd)
            return "text"

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_capture_findings", lambda *a, **k: None),
        ):
            out = asyncio.run(self.server.metasploit_search("-x type:exploit"))
        self.assertNotIn("must not begin with", out)
        self.assertIn("-x type:exploit", " ".join(captured["cmd"]))


class HydraServiceAllowlistTests(unittest.TestCase):
    """#52A: hydra's `service` positional accepts arbitrary options."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_hydra(self, service):
        spawned = []

        def fake_run(cmd, timeout=None, **kwargs):
            spawned.append(list(cmd))
            return "text"

        with (
            patch.object(self.server.os.path, "isfile", return_value=True),
            patch.object(self.server, "run_command", fake_run),
        ):
            out = asyncio.run(self.server.hydra_attack("10.0.0.1", service, "admin", "/tmp/wl"))
        return out, spawned

    def test_each_documented_service_builds_argv_with_that_service(self):
        for service in self.server.HYDRA_SERVICES:
            with self.subTest(service=service):
                out, spawned = self.run_hydra(service)
                self.assertEqual("text", out)
                self.assertIn(service, spawned[0])

    def test_an_option_shaped_service_is_rejected(self):
        for service in ("-U", "-S", "-6", "-x"):
            with self.subTest(service=service):
                out, spawned = self.run_hydra(service)
                self.assertIn("unsupported hydra service", out)
                self.assertEqual([], spawned)

    def test_an_unknown_service_is_rejected_not_coerced_to_ssh(self):
        # Coercing a typo to ssh would attack port 22 instead of the intended
        # service.
        out, spawned = self.run_hydra("sssh")
        self.assertIn("unsupported hydra service", out)
        self.assertEqual([], spawned)
        self.assertIn("ssh", out)  # the accepted set is named

    def test_the_error_names_the_accepted_set(self):
        out, _ = self.run_hydra("telnet")
        for service in self.server.HYDRA_SERVICES:
            self.assertIn(service, out)


class HydraWordlistTests(unittest.TestCase):
    """#52B / D2: an empty or missing wordlist must error, never substitute."""

    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_hydra(self, password_list, path_exists=True):
        spawned = []

        def fake_run(cmd, timeout=None, **kwargs):
            spawned.append(list(cmd))
            return "text"

        with (
            patch.object(self.server.os.path, "isfile", return_value=path_exists),
            patch.object(self.server, "run_command", fake_run),
        ):
            out = asyncio.run(self.server.hydra_attack("10.0.0.1", "ssh", "admin", password_list))
        return out, spawned

    def test_empty_wordlist_errors_instead_of_running_rockyou(self):
        out, spawned = self.run_hydra("")
        self.assertIn("password_list is required", out)
        self.assertEqual([], spawned)

    def test_a_missing_wordlist_errors_and_names_no_substitute(self):
        out, spawned = self.run_hydra("/mnt/typo.txt", path_exists=False)
        self.assertIn("password_list not found", out)
        self.assertIn("/mnt/typo.txt", out)
        self.assertNotIn("rockyou", out)
        self.assertNotIn("dirb", out)
        self.assertEqual([], spawned)

    def test_a_directory_or_device_wordlist_is_rejected(self):
        # os.path.exists accepted /tmp (a directory) and /dev/zero (an infinite
        # stream); the guard now requires a regular file.
        import os.path
        real_isfile = os.path.isfile
        for path, isfile in (("/tmp", False), ("/dev/zero", False)):
            with self.subTest(path=path):
                spawned = []
                with (
                    patch.object(self.server.os.path, "isfile", lambda p, _f=isfile: _f),
                    patch.object(self.server, "run_command",
                                 lambda cmd, timeout=None, **k: spawned.append(list(cmd)) or "text"),
                ):
                    out = asyncio.run(self.server.hydra_attack("10.0.0.1", "ssh", "admin", path))
                self.assertIn("not found or not a file", out)
                self.assertEqual([], spawned)

    def test_an_existing_wordlist_is_used_verbatim(self):
        out, spawned = self.run_hydra("/mnt/custom.txt", path_exists=True)
        self.assertEqual("text", out)
        cmd = spawned[0]
        self.assertEqual("/mnt/custom.txt", cmd[cmd.index("-P") + 1])


if __name__ == "__main__":
    unittest.main()
