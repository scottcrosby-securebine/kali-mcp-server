"""#56: hashcat_crack must not silently substitute a wordlist.

The old code defaulted an empty wordlist to rockyou (~14M) and then swapped a
missing path to dirb's common.txt. So an operator who named a wordlist that was
not present got a DIFFERENT attack than the one they asked for, with no signal
at all -- and rockyou is not in this image (#14), so the "default" aborted
anyway. Same defect and same fix as hydra_attack (#52B): require an explicit,
existing wordlist, error otherwise.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server_test_support import load_server


class HashcatRequiresAnExplicitExistingWordlist(unittest.TestCase):
    def setUp(self):
        self.server, _ = load_server()

    def _call(self, *args, isfile=True, run_return="ran"):
        with (
            patch.object(self.server.os.path, "exists", return_value=True),
            patch.object(self.server.os.path, "isfile", return_value=isfile),
            patch.object(self.server, "run_command", return_value=run_return) as rc,
        ):
            result = asyncio.run(self.server.hashcat_crack(*args))
        return result, rc

    def test_an_empty_wordlist_is_rejected_not_defaulted_to_rockyou(self):
        result, rc = self._call("/workspace/hashes.txt", "0", "")
        self.assertIn("❌", result)
        self.assertIn("wordlist is required", result)
        rc.assert_not_called()

    def test_a_missing_wordlist_is_rejected_not_swapped_to_dirb(self):
        result, rc = self._call("/workspace/hashes.txt", "0", "/nope/list.txt", isfile=False)
        self.assertIn("❌", result)
        self.assertIn("not found", result)
        rc.assert_not_called()

    def test_an_explicit_existing_wordlist_runs(self):
        result, rc = self._call("/workspace/hashes.txt", "0", "/workspace/list.txt")
        self.assertEqual("ran", result)
        rc.assert_called_once()
        # The named wordlist reaches the command verbatim; nothing was swapped.
        cmd = rc.call_args.args[0]
        self.assertIn("/workspace/list.txt", cmd)
        self.assertNotIn("/usr/share/wordlists/dirb/common.txt", cmd)
        self.assertNotIn("/usr/share/wordlists/rockyou.txt", cmd)

    def test_no_default_wordlist_literal_remains_in_the_function(self):
        # The broken paths are gone from the source, so #14's repo-wide audit of
        # the dirb literal has nothing left to do in this tool (the two issues
        # share that string; #56 owns hashcat_crack's copies).
        source = (Path(__file__).resolve().parent.parent / "kali_pentest_server.py").read_text()
        start = source.index("async def hashcat_crack")
        end = source.index("async def searchsploit_search")
        # Code only: the fix's own comment names the paths it removed, and that
        # prose is not a substitution. Drop comment lines before scanning.
        body = "\n".join(
            line for line in source[start:end].splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn("rockyou", body)
        self.assertNotIn("/usr/share/wordlists/dirb/common.txt", body)


if __name__ == "__main__":
    unittest.main()
