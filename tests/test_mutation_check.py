"""The mutation check's verdict must reject every run that proves nothing.

The check exists to prove an assertion pins behaviour. It only does that when
tests were collected, an ASSERTION failed, and nothing errored. Its previous two
versions read the runner's text (`grep -c '^FAILED ('`), which cannot separate
`FAILED (errors=1)` from `FAILED (failures=1)`, so an import error in the
mutated source was accepted as proof. These cases pin the separation.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mutation-check"
_spec = importlib.util.spec_from_loader("mutation_check", SourceFileLoader("mutation_check", str(SCRIPT)))
mutation_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mutation_check)

CAUGHT, SUITE_PASSED, INCONCLUSIVE, NOTHING_TO_MEASURE = 0, 1, 2, 3


def next_pipe():
    """The lowest free descriptor pair. It moves up if a call leaked one."""
    fds = os.pipe()
    for fd in fds:
        os.close(fd)
    return fds


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


# A runner that reports its counts and exits while a forked child still holds
# the inherited write end: reading to EOF would wait for that child.
REPORTING_FORKER = '''
import os, time, unittest

class Forker(unittest.TestCase):
    def test_forks_a_child_that_outlives_the_runner(self):
        if os.fork() == 0:
            time.sleep(15)
            os._exit(0)
        self.assertEqual(1, 2)
'''

# The same, except the runner dies before writing anything. Nothing will ever
# arrive, and the pipe stays open, so a blocking read waits forever.
DYING_FORKER = '''
import os, time, unittest

class Forker(unittest.TestCase):
    def test_dies_before_reporting(self):
        if os.fork() == 0:
            time.sleep(15)
            os._exit(0)
        os._exit(1)
'''

# run_suite driven from a separate process so a blocking read shows up here as a
# TimeoutExpired FAILURE instead of hanging this suite.
DRIVER = '''
import importlib.util, json, subprocess, sys
from importlib.machinery import SourceFileLoader
spec = importlib.util.spec_from_loader("mc", SourceFileLoader("mc", sys.argv[1]))
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)
_, counts = mc.run_suite(sys.argv[3], cwd=sys.argv[2],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(json.dumps(counts))
'''


class PipeLifetimeTests(unittest.TestCase):
    """The payload pipe must not hang the gate, and must not leak either end.

    A gate whose failure mode is a hang is worse than one that fails: CI reports
    it as an infrastructure timeout, not a defect. Both cases here fail.
    """

    def test_a_forked_grandchild_cannot_hang_the_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "tests").mkdir()
            (Path(tmp) / "tests" / "test_reporting_forker.py").write_text(REPORTING_FORKER)
            (Path(tmp) / "tests" / "test_dying_forker.py").write_text(DYING_FORKER)
            for pattern, expected in [
                    ("test_reporting_forker.py", '{"testsRun": 1, "failures": 1, "errors": 0}'),
                    ("test_dying_forker.py", "null")]:
                with self.subTest(pattern=pattern):
                    driver = subprocess.run(
                        [sys.executable, "-c", DRIVER, str(SCRIPT), tmp, pattern],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(expected, driver.stdout.strip(), driver.stderr)

    def test_both_pipe_ends_are_closed_on_success_and_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "tests").mkdir()
            (Path(tmp) / "tests" / "test_noisy.py").write_text(NOISY_TEST)
            before = next_pipe()
            mutation_check.run_suite("test_noisy.py", cwd=tmp,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(before, next_pipe(), "a descriptor leaked on the success path")
            with self.assertRaises(OSError):        # no such cwd: run() raises
                mutation_check.run_suite("test_noisy.py", cwd=str(Path(tmp) / "absent"))
            self.assertEqual(before, next_pipe(), "a descriptor leaked on the error path")


class NothingToMeasureTests(unittest.TestCase):
    def test_an_unmutated_base_is_not_an_accusation(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "HEAD"],
                             capture_output=True, text=True, cwd=SCRIPT.parent.parent)
        if run.returncode == INCONCLUSIVE:
            self.skipTest(f"precondition not met: {run.stderr.strip()}")
        self.assertEqual(NOTHING_TO_MEASURE, run.returncode, run.stderr)
        self.assertIn("NOTHING TO MEASURE", run.stderr)


if __name__ == "__main__":
    unittest.main()
