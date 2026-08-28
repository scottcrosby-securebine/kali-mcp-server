"""The mutation check's verdict must reject every run that proves nothing.

The check exists to prove an assertion pins behaviour. It only does that when
tests were collected, an ASSERTION failed, and nothing errored. Its previous two
versions read the runner's text (`grep -c '^FAILED ('`), which cannot separate
`FAILED (errors=1)` from `FAILED (failures=1)`, so an import error in the
mutated source was accepted as proof. These cases pin the separation.
"""
import importlib.util
import subprocess
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mutation-check"
_spec = importlib.util.spec_from_loader("mutation_check", SourceFileLoader("mutation_check", str(SCRIPT)))
mutation_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mutation_check)

CAUGHT, SUITE_PASSED, INCONCLUSIVE = 0, 1, 2


class VerdictTests(unittest.TestCase):
    def verdict(self, tests_run, failures, errors):
        return mutation_check.verdict(tests_run, failures, errors, "BASE")

    def test_genuine_assertion_failure_is_the_only_accepted_proof(self):
        code, message = self.verdict(12, 3, 0)
        self.assertEqual(CAUGHT, code)
        self.assertIn("OK", message)

    def test_errors_only_run_is_rejected(self):
        # An unimportable mutated source: `Ran 1 test` + `FAILED (errors=1)`,
        # which is exactly what the old text-parsing gate accepted.
        code, message = self.verdict(1, 0, 1)
        self.assertEqual(INCONCLUSIVE, code)
        self.assertIn("ERROR(s)", message)

    def test_errors_alongside_failures_are_still_rejected(self):
        code, message = self.verdict(12, 3, 1)
        self.assertEqual(INCONCLUSIVE, code)
        self.assertIn("ERROR(s)", message)

    def test_zero_collected_run_is_rejected(self):
        code, message = self.verdict(0, 0, 0)
        self.assertEqual(INCONCLUSIVE, code)
        self.assertIn("collected 0 tests", message)

    def test_clean_run_is_rejected_as_a_failed_check(self):
        code, message = self.verdict(12, 0, 0)
        self.assertEqual(SUITE_PASSED, code)
        self.assertIn("pin nothing", message)

    def test_each_rejection_carries_a_distinguishable_message(self):
        messages = {self.verdict(*counts)[1] for counts in [(1, 0, 1), (0, 0, 0), (12, 0, 0)]}
        self.assertEqual(3, len(messages))


NOISY_TEST = '''
import sys, unittest

class Noisy(unittest.TestCase):
    def test_noisy(self):
        print('docker run --rm -i kali-mcp-server:test')
        print('{"testsRun": 281, "failures": 0, "errors": 0}')
        print('{"testsRun": 99, "failures": 0, "errors": 0}', file=sys.stderr)
        self.assertEqual(1, 2)
'''


class PayloadChannelTests(unittest.TestCase):
    """The counts must survive a collected test printing anything, JSON included.

    The real suite collects a launcher test that prints a docker command line to
    stdout. When the payload shared stdout, that line destroyed every verdict
    under the documented `test_*.py` pattern.
    """

    def test_counts_survive_arbitrary_child_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite_dir = Path(tmp) / "tests"
            suite_dir.mkdir()
            (suite_dir / "test_noisy.py").write_text(NOISY_TEST)
            # DEVNULL keeps the noise out of the parent suite's log: a stray
            # `Ran 1 test` / `FAILED (failures=1)` above a green summary is the
            # same confusion this check exists to prevent, and CI's
            # zero-collection guard greps for that `Ran N tests` line. The child
            # still writes it through sys.stdout/sys.stderr on fds 1 and 2, so
            # what the pipe has to survive is unchanged.
            _, counts = mutation_check.run_suite(
                "test_noisy.py", cwd=tmp,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual({"testsRun": 1, "failures": 1, "errors": 0}, counts)


if __name__ == "__main__":
    unittest.main()
