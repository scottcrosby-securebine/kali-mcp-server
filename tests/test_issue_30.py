"""#30: testssl.sh aborts unless the connect URI is the final argv element."""

import asyncio
from pathlib import Path
import unittest
from unittest.mock import patch

from server_test_support import load_server


TESTSSL_JSON = '[{"id":"BEAST","severity":"HIGH","finding":"vulnerable","cve":"CVE-2011-3389"}]'


class TestsslUriLastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, _ = load_server()

    def run_testssl(self, *args, json_text=TESTSSL_JSON):
        """Invoke testssl_scan with the subprocess seam replaced; return argv and capture."""
        seen = {}

        def fake_run(cmd, timeout=None, **kwargs):
            seen["cmd"] = list(cmd)
            for index, arg in enumerate(cmd):
                if arg == "--jsonfile":
                    Path(cmd[index + 1]).write_text(json_text, encoding="utf-8")
            return "testssl TEXT"

        def fake_write(document):
            seen["doc"] = document
            return "Z" * 32

        with (
            patch.object(self.server, "run_command", fake_run),
            patch.object(self.server, "_write_scanner_result", fake_write),
        ):
            seen["out"] = asyncio.run(self.server.testssl_scan(*args))
        return seen

    def test_uri_is_the_final_argv_element_with_jsonfile_before_it(self):
        for args, uri in ((("example.test",), "example.test:443"), (("example.test", "8443"), "example.test:8443")):
            with self.subTest(args=args):
                seen = self.run_testssl(*args)
                cmd = seen["cmd"]
                self.assertEqual(uri, cmd[-1])
                self.assertEqual([uri], [arg for arg in cmd if arg == uri])
                self.assertIn("--jsonfile", cmd)
                self.assertLess(cmd.index("--jsonfile") + 1, len(cmd) - 1)
                self.assertEqual(["testssl", "--fast", "--severity", "HIGH"], cmd[:4])
                self.assertNotIn("shell", cmd)

    def test_capture_still_produces_a_normalized_result(self):
        seen = self.run_testssl("example.test")
        self.assertEqual("testssl TEXT", seen["out"])
        self.assertEqual("testssl", seen["doc"]["scanner"])
        self.assertEqual("example.test:443", seen["doc"]["target_ref"])
        self.assertEqual("HIGH", seen["doc"]["findings"][0]["Severity"])

    def test_capture_failure_never_fails_the_scan(self):
        seen = self.run_testssl("example.test", json_text="{bad json")
        self.assertEqual("testssl TEXT", seen["out"])


if __name__ == "__main__":
    unittest.main()
