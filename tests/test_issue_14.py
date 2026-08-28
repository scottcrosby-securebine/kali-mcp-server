"""#14: the fuzzers' default wordlist must resolve to a path present in the image.

ffuf_scan, gobuster_scan and wfuzz_scan defaulted to
/usr/share/wordlists/dirb/common.txt, the path Kali's apt package uses. This
image builds dirb from source, so the file is at /usr/share/dirb/wordlists/
instead, and every default call failed before scanning. The three now share one
constant, DEFAULT_WEB_WORDLIST, which is the path dirb_scan already resolves.

The real-container half of #14's acceptance (the file actually exists in the
built image) is a container-integration check, not exercised here; this pins the
source side: the correct path, one spelling, and custom wordlists still passing
through. hashcat_crack's copy of the broken literal was #56's, already removed.
"""
import asyncio
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


class DefaultWordlistResolvesToTheImagePath(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _cmd_for(self, tool, *args):
        with patch.object(self.server, "run_command", return_value="ran") as rc:
            asyncio.run(getattr(self.server, tool)(*args))
        return rc.call_args.args[0]

    def test_each_fuzzer_defaults_to_the_dirb_source_path(self):
        expected = "/usr/share/dirb/wordlists/common.txt"
        self.assertEqual(expected, self.server.DEFAULT_WEB_WORDLIST)
        for tool, target in (
            ("ffuf_scan", "example.test"),
            ("gobuster_scan", "example.test"),
            ("wfuzz_scan", "example.test/FUZZ"),
        ):
            with self.subTest(tool=tool):
                cmd = self._cmd_for(tool, target)
                self.assertIn(expected, cmd)
                self.assertNotIn("/usr/share/wordlists/dirb/common.txt", cmd)

    def test_the_default_is_the_path_dirb_scan_already_uses(self):
        # dirb works in the image, so its "common" mapping is proof the file is
        # present. The fuzzers' default must equal it, not diverge.
        cmd = self._cmd_for("dirb_scan", "example.test", "common")
        self.assertIn(self.server.DEFAULT_WEB_WORDLIST, cmd)

    def test_a_custom_wordlist_is_still_honoured(self):
        cmd = self._cmd_for("ffuf_scan", "example.test", "/workspace/custom.txt")
        self.assertIn("/workspace/custom.txt", cmd)
        self.assertNotIn(self.server.DEFAULT_WEB_WORDLIST, cmd)


class NoBrokenAptWordlistPathRemains(unittest.TestCase):
    """The drift guard. Three copies of the literal drifted from dirb_scan's
    correct one; a fourth would drift again. Read the source, not a copy."""

    def test_the_apt_path_appears_only_in_the_constants_explanatory_comment(self):
        offenders = []
        for number, line in enumerate(
            (REPO / "kali_pentest_server.py").read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if "/usr/share/wordlists/dirb/" in line and not line.lstrip().startswith("#"):
                offenders.append(f"{number}: {line.strip()}")
        self.assertEqual([], offenders, "the broken apt wordlist path is back in code")


if __name__ == "__main__":
    unittest.main()
