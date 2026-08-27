"""#32: ffuf_scan/wfuzz_scan accept a plain target like their gobuster/dirb siblings."""

import asyncio
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from server_test_support import load_server


# (input target, the URL the fuzzer must end up running)
TARGET_CASES = (
    ("example.test", "http://example.test/FUZZ"),
    ("http://example.test/app/", "http://example.test/app/FUZZ"),
    ("https://example.test/app", "https://example.test/app/FUZZ"),
    ("http://h/s?q=FUZZ", "http://h/s?q=FUZZ"),
    ("http://h/FUZZ", "http://h/FUZZ"),
)


class FuzzTargetDefaultingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_tool(self, tool, target):
        """Invoke a fuzzer with the process seam faked and return its argv."""
        seen = {}

        def fake_run(cmd, timeout=None, **kwargs):
            seen["cmd"] = cmd
            if "-o" in cmd:
                Path(cmd[cmd.index("-o") + 1]).write_text(
                    json.dumps({"results": []}), encoding="utf-8")
            return "TEXT"

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_write_scanner_result", lambda document: "Z" * 32),
        ):
            response = asyncio.run(getattr(self.server, tool)(target))
        self.assertNotIn("❌", response)
        self.assertNotIn("shell", seen["cmd"])
        return seen["cmd"]

    def test_ffuf_fuzzes_a_plain_target_and_leaves_an_explicit_FUZZ_alone(self):
        for target, expected in TARGET_CASES:
            with self.subTest(target=target):
                cmd = self.run_tool("ffuf_scan", target)
                self.assertEqual(expected, cmd[cmd.index("-u") + 1])

    def test_wfuzz_fuzzes_a_plain_target_and_leaves_an_explicit_FUZZ_alone(self):
        for target, expected in TARGET_CASES:
            with self.subTest(target=target):
                cmd = self.run_tool("wfuzz_scan", target)
                self.assertEqual(expected, cmd[-1])

    def test_neither_tool_appends_a_second_FUZZ(self):
        for tool, index in (("ffuf_scan", None), ("wfuzz_scan", -1)):
            for target in ("http://h/FUZZ", "http://h/s?q=FUZZ", "http://FUZZ.h/"):
                with self.subTest(tool=tool, target=target):
                    cmd = self.run_tool(tool, target)
                    url = cmd[-1] if index == -1 else cmd[cmd.index("-u") + 1]
                    self.assertEqual(1, url.count("FUZZ"))

    def test_docstrings_no_longer_demand_a_FUZZ_placeholder(self):
        for tool in ("ffuf_scan", "wfuzz_scan"):
            with self.subTest(tool=tool):
                doc = getattr(self.server, tool).__doc__
                self.assertEqual(1, len(doc.strip().splitlines()))
                self.assertNotIn("must contain FUZZ", doc)

    def test_an_empty_target_is_still_rejected(self):
        for tool in ("ffuf_scan", "wfuzz_scan"):
            with self.subTest(tool=tool):
                self.assertIn("❌", asyncio.run(getattr(self.server, tool)("   ")))


if __name__ == "__main__":
    unittest.main()
