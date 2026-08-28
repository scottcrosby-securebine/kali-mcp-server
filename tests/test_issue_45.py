"""#45 (server half): hashcat must skip the self-test that aborts every run.

PoCL's CPU kernel self-test fails on this host and hashcat aborts before trying
a single hash, so the tool never cracks anything. `--force` was already set and
does not cover a self-test failure. The server lever is `--self-test-disable`;
it is added to the argument list, not a replacement for `--force`.

The image half of #45 (an OpenCL runtime that could pass the self-test) is a
Dockerfile change tracked separately as row 13 and is not exercised here.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


class HashcatSkipsTheFailingSelfTest(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _command(self):
        with (
            patch.object(self.server.os.path, "exists", return_value=True),
            patch.object(self.server.os.path, "isfile", return_value=True),
            patch.object(self.server, "run_command", return_value="ran") as rc,
        ):
            asyncio.run(self.server.hashcat_crack(
                "/workspace/md5.hash", "0", "/workspace/pw.txt"))
        return rc.call_args.args[0]

    def test_the_self_test_is_disabled(self):
        self.assertIn("--self-test-disable", self._command())

    def test_force_is_still_present(self):
        # --self-test-disable is an addition. --force still suppresses the
        # unrelated "insecure environment" refusal the hardened container trips.
        self.assertIn("--force", self._command())


if __name__ == "__main__":
    unittest.main()
