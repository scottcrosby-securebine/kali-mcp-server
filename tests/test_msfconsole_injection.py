"""#58: metasploit_search/metasploit_info must not let a caller inject
msfconsole commands via ';' or a newline in the -x string.
"""

import asyncio
import unittest
from unittest.mock import patch

from server_test_support import load_server


class MsfConsoleInjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_tool(self, tool, value):
        """Drive the tool with both process seams blocked; a spawn is failure."""
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
            out = asyncio.run(getattr(self.server, tool)(value))
        return out, spawned

    INJECTIONS = [
        "x; irb -e 'puts 1'",           # RCE via arbitrary Ruby
        "x; spool /tmp/o",              # attacker-named file write
        "x; resource /tmp/evil.rc",     # run a script file
        "x;exit;irb",                   # no spaces around the separator
        "x\nirb -e 'puts 1'",           # newline as a separator
        "x\r\nload foo",                # CRLF
        ";irb",                         # leading separator
    ]

    def test_search_rejects_every_injection_and_spawns_nothing(self):
        for value in self.INJECTIONS:
            with self.subTest(value=value):
                out, spawned = self.run_tool("metasploit_search", value)
                self.assertIn("must not contain", out)
                self.assertEqual([], spawned)

    def test_info_rejects_every_injection_and_spawns_nothing(self):
        for value in self.INJECTIONS:
            with self.subTest(value=value):
                out, spawned = self.run_tool("metasploit_info", value)
                self.assertIn("must not contain", out)
                self.assertEqual([], spawned)

    def test_a_legitimate_search_still_reaches_msfconsole(self):
        for value in ("type:exploit platform:windows cve:2021-44228",
                      "eternalblue", "apache 2.4.49 path traversal",
                      "author:hdm rank:excellent"):
            with self.subTest(value=value):
                out, spawned = self.run_tool("metasploit_search", value)
                self.assertEqual("text", out)
                self.assertEqual(1, len(spawned))
                x = spawned[0][-1]
                self.assertEqual(f"search {value}; exit", x)

    def test_a_legitimate_module_path_still_reaches_msfconsole(self):
        value = "exploit/windows/smb/ms17_010_eternalblue"
        out, spawned = self.run_tool("metasploit_info", value)
        self.assertEqual("text", out)
        self.assertEqual(f"info {value}; exit", spawned[0][-1])

    def test_the_leading_dash_exemption_is_intact(self):
        # A leading dash is msfconsole search syntax, not a separator; #58 must
        # not regress the guard_target=False exemption.
        for tool, value in [("metasploit_search", "-x type:exploit"),
                            ("metasploit_info", "-x")]:
            with self.subTest(tool=tool):
                out, spawned = self.run_tool(tool, value)
                self.assertNotIn("must not contain", out)
                self.assertEqual(1, len(spawned))
                self.assertIn(value, spawned[0][-1])


if __name__ == "__main__":
    unittest.main()
